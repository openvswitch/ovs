/*
 * Copyright (c) 2008-2019 Nicira, Inc.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "command-line.h"
#include "compiler.h"
#include "ct-dpif.h"
#include "dirs.h"
#include "dpctl.h"
#include "dpif.h"
#include "dpif-provider.h"
#include "openvswitch/dynamic-string.h"
#include "flow.h"
#include "openvswitch/match.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-util.h"
#include "openvswitch/ofpbuf.h"
#include "packets.h"
#include "openvswitch/shash.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-port.h"

enum {
    DPCTL_FLOWS_ADD = 0,
    DPCTL_FLOWS_DEL,
    DPCTL_FLOWS_MOD
};

typedef int dpctl_command_handler(int argc, const char *argv[],
                                  struct dpctl_params *);
struct dpctl_command {
    const char *name;
    const char *usage;
    int min_args;
    int max_args;
    dpctl_command_handler *handler;
    enum { DP_RO, DP_RW} mode;
};
static const struct dpctl_command *get_all_dpctl_commands(void);
static void dpctl_print(struct dpctl_params *dpctl_p, const char *fmt, ...)
    OVS_PRINTF_FORMAT(2, 3);
static void dpctl_error(struct dpctl_params* dpctl_p, int err_no,
                        const char *fmt, ...)
    OVS_PRINTF_FORMAT(3, 4);

static void
dpctl_puts(struct dpctl_params *dpctl_p, bool error, const char *string)
{
    dpctl_p->output(dpctl_p->aux, error, string);
}

static void
dpctl_print(struct dpctl_params *dpctl_p, const char *fmt, ...)
{
    char *string;
    va_list args;

    va_start(args, fmt);
    string = xvasprintf(fmt, args);
    va_end(args);

    dpctl_puts(dpctl_p, false, string);
    free(string);
}

static void
dpctl_error(struct dpctl_params* dpctl_p, int err_no, const char *fmt, ...)
{
    const char *subprogram_name = get_subprogram_name();
    struct ds ds = DS_EMPTY_INITIALIZER;
    int save_errno = errno;
    va_list args;


    if (subprogram_name[0]) {
        ds_put_format(&ds, "%s(%s): ", program_name,subprogram_name);
    } else {
        ds_put_format(&ds, "%s: ", program_name);
    }

    va_start(args, fmt);
    ds_put_format_valist(&ds, fmt, args);
    va_end(args);

    if (err_no != 0) {
        ds_put_format(&ds, " (%s)", ovs_retval_to_string(err_no));
    }
    ds_put_cstr(&ds, "\n");

    dpctl_puts(dpctl_p, true, ds_cstr(&ds));

    ds_destroy(&ds);

    errno = save_errno;
}

static int dpctl_add_if(int argc, const char *argv[], struct dpctl_params *);

static int
if_up(struct netdev *netdev)
{
    return netdev_turn_flags_on(netdev, NETDEV_UP, NULL);
}

/* Retrieve the name of the datapath if exactly one exists.  The caller
 * is responsible for freeing the returned string.  If a single datapath
 * name cannot be determined, returns NULL. */
static char *
get_one_dp(struct dpctl_params *dpctl_p)
{
    struct sset types;
    const char *type;
    char *dp_name = NULL;
    size_t count = 0;

    sset_init(&types);
    dp_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        struct sset names;

        sset_init(&names);
        if (!dp_enumerate_names(type, &names)) {
            count += sset_count(&names);
            if (!dp_name && count == 1) {
                dp_name = xasprintf("%s@%s", type, SSET_FIRST(&names));
            }
        }
        sset_destroy(&names);
    }
    sset_destroy(&types);

    if (!count) {
        dpctl_error(dpctl_p, 0, "no datapaths exist");
    } else if (count > 1) {
        dpctl_error(dpctl_p, 0, "multiple datapaths, specify one");
        free(dp_name);
        dp_name = NULL;
    }

    return dp_name;
}

static int
parsed_dpif_open(const char *arg_, bool create, struct dpif **dpifp)
{
    int result;
    char *name, *type;

    dp_parse_name(arg_, &name, &type);

    if (create) {
        result = dpif_create(name, type, dpifp);
    } else {
        result = dpif_open(name, type, dpifp);
    }

    free(name);
    free(type);
    return result;
}

static bool
dp_exists(const char *queried_dp)
{
    char *queried_name, *queried_type;
    dp_parse_name(queried_dp, &queried_name, &queried_type);
    struct sset dpif_names = SSET_INITIALIZER(&dpif_names),
                dpif_types = SSET_INITIALIZER(&dpif_types);
    dp_enumerate_types(&dpif_types);

    bool found = (sset_contains(&dpif_types, queried_type) &&
                  !dp_enumerate_names(queried_type, &dpif_names) &&
                  sset_contains(&dpif_names, queried_name));

    sset_destroy(&dpif_names);
    sset_destroy(&dpif_types);
    free(queried_name);
    free(queried_type);
    return found;
}

static bool
dp_arg_exists(int argc, const char *argv[])
{
    return argc > 1 && dp_exists(argv[1]);
}

/* Open a dpif with an optional name argument.
 *
 * The datapath name is not a mandatory parameter for this command.  If it is
 * not specified, we retrieve it from the current setup, assuming only one
 * exists.  On success stores the opened dpif in '*dpifp'.  */
static int
opt_dpif_open(int argc, const char *argv[], struct dpctl_params *dpctl_p,
              int max_args, struct dpif **dpifp)
{
    char *dpname;

    if (dp_arg_exists(argc, argv)) {
        dpname = xstrdup(argv[1]);
    } else if (argc != max_args) {
        dpname = get_one_dp(dpctl_p);
    } else {
        /* If the arguments are the maximum possible number and there is no
         * valid datapath argument, then we fall into the case of dpname is
         * NULL, since this is an error. */
        dpname = NULL;
    }

    int error = 0;
    if (!dpname) {
        error = EINVAL;
        dpctl_error(dpctl_p, error, "datapath not found");
    } else {
        error = parsed_dpif_open(dpname, false, dpifp);
        free(dpname);
        if (error) {
            dpctl_error(dpctl_p, error, "opening datapath");
        }
    }
    return error;
}

static int
dpctl_add_dp(int argc, const char *argv[],
             struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error;

    error = parsed_dpif_open(argv[1], true, &dpif);
    if (error) {
        dpctl_error(dpctl_p, error, "add_dp");
        return error;
    }
    dpif_close(dpif);
    if (argc > 2) {
        error = dpctl_add_if(argc, argv, dpctl_p);
    }
    return error;
}

static int
dpctl_del_dp(int argc OVS_UNUSED, const char *argv[],
             struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error;

    error = parsed_dpif_open(argv[1], false, &dpif);
    if (error) {
        dpctl_error(dpctl_p, error, "opening datapath");
        return error;
    }
    error = dpif_delete(dpif);
    if (error) {
        dpctl_error(dpctl_p, error, "del_dp");
    }

    dpif_close(dpif);
    return error;
}

static int
dpctl_add_if(int argc OVS_UNUSED, const char *argv[],
             struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int i, error, lasterror = 0;

    error = parsed_dpif_open(argv[1], false, &dpif);
    if (error) {
        dpctl_error(dpctl_p, error, "opening datapath");
        return error;
    }
    for (i = 2; i < argc; i++) {
        const char *name, *type;
        char *save_ptr = NULL, *argcopy;
        struct netdev *netdev = NULL;
        struct smap args;
        odp_port_t port_no = ODPP_NONE;
        char *option;

        argcopy = xstrdup(argv[i]);
        name = strtok_r(argcopy, ",", &save_ptr);
        type = "system";

        if (!name) {
            dpctl_error(dpctl_p, 0, "%s is not a valid network device name",
                        argv[i]);
            error = EINVAL;
            goto next;
        }

        smap_init(&args);
        while ((option = strtok_r(NULL, ",", &save_ptr)) != NULL) {
            char *save_ptr_2 = NULL;
            char *key, *value;

            key = strtok_r(option, "=", &save_ptr_2);
            value = strtok_r(NULL, "", &save_ptr_2);
            if (!value) {
                value = "";
            }

            if (!strcmp(key, "type")) {
                type = value;
            } else if (!strcmp(key, "port_no")) {
                port_no = u32_to_odp(atoi(value));
            } else if (!smap_add_once(&args, key, value)) {
                dpctl_error(dpctl_p, 0, "duplicate \"%s\" option", key);
            }
        }

        error = netdev_open(name, type, &netdev);
        if (error) {
            dpctl_error(dpctl_p, error, "%s: failed to open network device",
                        name);
            goto next_destroy_args;
        }

        error = netdev_set_config(netdev, &args, NULL);
        if (error) {
            goto next_destroy_args;
        }

        error = dpif_port_add(dpif, netdev, &port_no);
        if (error) {
            dpctl_error(dpctl_p, error, "adding %s to %s failed", name,
                        argv[1]);
            goto next_destroy_args;
        }

        error = if_up(netdev);
        if (error) {
            dpctl_error(dpctl_p, error, "%s: failed bringing interface up",
                        name);
        }

next_destroy_args:
        netdev_close(netdev);
        smap_destroy(&args);
next:
        free(argcopy);
        if (error) {
            lasterror = error;
        }
    }
    dpif_close(dpif);

    return lasterror;
}

static int
dpctl_set_if(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int i, error, lasterror = 0;

    error = parsed_dpif_open(argv[1], false, &dpif);
    if (error) {
        dpctl_error(dpctl_p, error, "opening datapath");
        return error;
    }
    for (i = 2; i < argc; i++) {
        struct netdev *netdev = NULL;
        struct dpif_port dpif_port;
        char *save_ptr = NULL;
        char *type = NULL;
        char *argcopy;
        const char *name;
        struct smap args;
        odp_port_t port_no;
        char *option;

        error = 0;

        argcopy = xstrdup(argv[i]);
        name = strtok_r(argcopy, ",", &save_ptr);
        if (!name) {
            dpctl_error(dpctl_p, 0, "%s is not a valid network device name",
                        argv[i]);
            goto next;
        }

        /* Get the port's type from the datapath. */
        error = dpif_port_query_by_name(dpif, name, &dpif_port);
        if (error) {
            dpctl_error(dpctl_p, error, "%s: failed to query port in %s", name,
                        argv[1]);
            goto next;
        }
        type = xstrdup(dpif_port.type);
        port_no = dpif_port.port_no;
        dpif_port_destroy(&dpif_port);

        /* Retrieve its existing configuration. */
        error = netdev_open(name, type, &netdev);
        if (error) {
            dpctl_error(dpctl_p, error, "%s: failed to open network device",
                        name);
            goto next;
        }

        smap_init(&args);
        error = netdev_get_config(netdev, &args);
        if (error) {
            dpctl_error(dpctl_p, error, "%s: failed to fetch configuration",
                        name);
            goto next_destroy_args;
        }

        /* Parse changes to configuration. */
        while ((option = strtok_r(NULL, ",", &save_ptr)) != NULL) {
            char *save_ptr_2 = NULL;
            char *key, *value;

            key = strtok_r(option, "=", &save_ptr_2);
            value = strtok_r(NULL, "", &save_ptr_2);
            if (!value) {
                value = "";
            }

            if (!strcmp(key, "type")) {
                if (strcmp(value, type)) {
                    dpctl_error(dpctl_p, 0,
                                "%s: can't change type from %s to %s",
                                 name, type, value);
                    error = EINVAL;
                    goto next_destroy_args;
                }
            } else if (!strcmp(key, "port_no")) {
                if (port_no != u32_to_odp(atoi(value))) {
                    dpctl_error(dpctl_p, 0, "%s: can't change port number from"
                              " %"PRIu32" to %d", name, port_no, atoi(value));
                    error = EINVAL;
                    goto next_destroy_args;
                }
            } else if (value[0] == '\0') {
                smap_remove(&args, key);
            } else {
                smap_replace(&args, key, value);
            }
        }

        /* Update configuration. */
        char *err_s = NULL;
        error = netdev_set_config(netdev, &args, &err_s);
        if (err_s || error) {
            dpctl_error(dpctl_p, error, "%s",
                        err_s ? err_s : "Error updating configuration");
            free(err_s);
        }
        if (error) {
            goto next_destroy_args;
        }

next_destroy_args:
        smap_destroy(&args);
next:
        netdev_close(netdev);
        free(type);
        free(argcopy);
        if (error) {
            lasterror = error;
        }
    }
    dpif_close(dpif);

    return lasterror;
}

static bool
get_port_number(struct dpif *dpif, const char *name, odp_port_t *port,
                struct dpctl_params *dpctl_p)
{
    struct dpif_port dpif_port;

    if (!dpif_port_query_by_name(dpif, name, &dpif_port)) {
        *port = dpif_port.port_no;
        dpif_port_destroy(&dpif_port);
        return true;
    } else {
        dpctl_error(dpctl_p, 0, "no port named %s", name);
        return false;
    }
}

static int
dpctl_del_if(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int i, error, lasterror = 0;

    error = parsed_dpif_open(argv[1], false, &dpif);
    if (error) {
        dpctl_error(dpctl_p, error, "opening datapath");
        return error;
    }
    for (i = 2; i < argc; i++) {
        const char *name = argv[i];
        odp_port_t port;

        if (!name[strspn(name, "0123456789")]) {
            port = u32_to_odp(atoi(name));
        } else if (!get_port_number(dpif, name, &port, dpctl_p)) {
            lasterror = ENOENT;
            continue;
        }

        error = dpif_port_del(dpif, port, false);
        if (error) {
            dpctl_error(dpctl_p, error, "deleting port %s from %s failed",
                        name, argv[1]);
            lasterror = error;
        }
    }
    dpif_close(dpif);
    return lasterror;
}

static void
print_stat(struct dpctl_params *dpctl_p, const char *leader, uint64_t value)
{
    dpctl_print(dpctl_p, "%s", leader);
    if (value != UINT64_MAX) {
        dpctl_print(dpctl_p, "%"PRIu64, value);
    } else {
        dpctl_print(dpctl_p, "?");
    }
}

static void
print_human_size(struct dpctl_params *dpctl_p, uint64_t value)
{
    if (value == UINT64_MAX) {
        /* Nothing to do. */
    } else if (value >= 1024ULL * 1024 * 1024 * 1024) {
        dpctl_print(dpctl_p, " (%.1f TiB)",
                    value / (1024.0 * 1024 * 1024 * 1024));
    } else if (value >= 1024ULL * 1024 * 1024) {
        dpctl_print(dpctl_p, " (%.1f GiB)", value / (1024.0 * 1024 * 1024));
    } else if (value >= 1024ULL * 1024) {
        dpctl_print(dpctl_p, " (%.1f MiB)", value / (1024.0 * 1024));
    } else if (value >= 1024) {
        dpctl_print(dpctl_p, " (%.1f KiB)", value / 1024.0);
    }
}

/* qsort comparison function. */
static int
compare_port_nos(const void *a_, const void *b_)
{
    const odp_port_t *ap = a_;
    const odp_port_t *bp = b_;
    uint32_t a = odp_to_u32(*ap);
    uint32_t b = odp_to_u32(*bp);

    return a < b ? -1 : a > b;
}

static void
show_dpif(struct dpif *dpif, struct dpctl_params *dpctl_p)
{
    struct dpif_port_dump dump;
    struct dpif_port dpif_port;
    struct dpif_dp_stats stats;
    struct netdev *netdev;

    dpctl_print(dpctl_p, "%s:\n", dpif_name(dpif));
    if (!dpif_get_dp_stats(dpif, &stats)) {
        dpctl_print(dpctl_p, "  lookups: hit:%"PRIu64" missed:%"PRIu64
                             " lost:%"PRIu64"\n  flows: %"PRIu64"\n",
                    stats.n_hit, stats.n_missed, stats.n_lost, stats.n_flows);
        if (stats.n_masks != UINT32_MAX) {
            uint64_t n_pkts = stats.n_hit + stats.n_missed;
            double avg = n_pkts ? (double) stats.n_mask_hit / n_pkts : 0.0;

            dpctl_print(dpctl_p, "  masks: hit:%"PRIu64" total:%"PRIu32
                                 " hit/pkt:%.2f\n",
                        stats.n_mask_hit, stats.n_masks, avg);
        }
    }

    odp_port_t *port_nos = NULL;
    size_t allocated_port_nos = 0, n_port_nos = 0;
    DPIF_PORT_FOR_EACH (&dpif_port, &dump, dpif) {
        if (n_port_nos >= allocated_port_nos) {
            port_nos = x2nrealloc(port_nos, &allocated_port_nos,
                                  sizeof *port_nos);
        }

        port_nos[n_port_nos] = dpif_port.port_no;
        n_port_nos++;
    }

    if (port_nos) {
        qsort(port_nos, n_port_nos, sizeof *port_nos, compare_port_nos);
    }

    for (int i = 0; i < n_port_nos; i++) {
        if (dpif_port_query_by_number(dpif, port_nos[i], &dpif_port)) {
            continue;
        }

        dpctl_print(dpctl_p, "  port %u: %s",
                    dpif_port.port_no, dpif_port.name);

        if (strcmp(dpif_port.type, "system")) {
            int error;

            dpctl_print(dpctl_p, " (%s", dpif_port.type);

            error = netdev_open(dpif_port.name, dpif_port.type, &netdev);
            if (!error) {
                struct smap config;

                smap_init(&config);
                error = netdev_get_config(netdev, &config);
                if (!error) {
                    const struct smap_node **nodes = smap_sort(&config);
                    for (size_t j = 0; j < smap_count(&config); j++) {
                        const struct smap_node *node = nodes[j];
                        dpctl_print(dpctl_p, "%c %s=%s", j ? ',' : ':',
                                    node->key, node->value);
                    }
                    free(nodes);
                } else {
                    dpctl_print(dpctl_p, ", could not retrieve configuration "
                                         "(%s)",  ovs_strerror(error));
                }
                smap_destroy(&config);

                netdev_close(netdev);
            } else {
                dpctl_print(dpctl_p, ": open failed (%s)",
                            ovs_strerror(error));
            }
            dpctl_print(dpctl_p, ")");
        }
        dpctl_print(dpctl_p, "\n");

        if (dpctl_p->print_statistics) {
            struct netdev_stats s;
            int error;

            error = netdev_open(dpif_port.name, dpif_port.type, &netdev);
            if (error) {
                dpctl_print(dpctl_p, ", open failed (%s)",
                            ovs_strerror(error));
                dpif_port_destroy(&dpif_port);
                continue;
            }
            error = netdev_get_stats(netdev, &s);
            if (!error) {
                netdev_close(netdev);
                print_stat(dpctl_p, "    RX packets:", s.rx_packets);
                print_stat(dpctl_p, " errors:", s.rx_errors);
                print_stat(dpctl_p, " dropped:", s.rx_dropped);
                print_stat(dpctl_p, " overruns:", s.rx_over_errors);
                print_stat(dpctl_p, " frame:", s.rx_frame_errors);
                dpctl_print(dpctl_p, "\n");

                print_stat(dpctl_p, "    TX packets:", s.tx_packets);
                print_stat(dpctl_p, " errors:", s.tx_errors);
                print_stat(dpctl_p, " dropped:", s.tx_dropped);
                print_stat(dpctl_p, " aborted:", s.tx_aborted_errors);
                print_stat(dpctl_p, " carrier:", s.tx_carrier_errors);
                dpctl_print(dpctl_p, "\n");

                print_stat(dpctl_p, "    collisions:", s.collisions);
                dpctl_print(dpctl_p, "\n");

                print_stat(dpctl_p, "    RX bytes:", s.rx_bytes);
                print_human_size(dpctl_p, s.rx_bytes);
                print_stat(dpctl_p, "  TX bytes:", s.tx_bytes);
                print_human_size(dpctl_p, s.tx_bytes);
                dpctl_print(dpctl_p, "\n");
            } else {
                dpctl_print(dpctl_p, ", could not retrieve stats (%s)",
                            ovs_strerror(error));
            }
        }
        dpif_port_destroy(&dpif_port);
    }

    free(port_nos);
}

typedef void (*dps_for_each_cb)(struct dpif *, struct dpctl_params *);

static int
dps_for_each(struct dpctl_params *dpctl_p, dps_for_each_cb cb)
{
    struct sset dpif_names = SSET_INITIALIZER(&dpif_names),
                dpif_types = SSET_INITIALIZER(&dpif_types);
    int error, openerror = 0, enumerror = 0;
    const char *type, *name;
    bool at_least_one = false;

    dp_enumerate_types(&dpif_types);

    SSET_FOR_EACH (type, &dpif_types) {
        error = dp_enumerate_names(type, &dpif_names);
        if (error) {
            enumerror = error;
        }

        SSET_FOR_EACH (name, &dpif_names) {
            struct dpif *dpif;

            at_least_one = true;
            error = dpif_open(name, type, &dpif);
            if (!error) {
                cb(dpif, dpctl_p);
                dpif_close(dpif);
            } else {
                openerror = error;
                dpctl_error(dpctl_p, error, "opening datapath %s failed",
                            name);
            }
        }
    }

    sset_destroy(&dpif_names);
    sset_destroy(&dpif_types);

    /* If there has been an error while opening a datapath it should be
     * reported.  Otherwise, we want to ignore the errors generated by
     * dp_enumerate_names() if at least one datapath has been discovered,
     * because they're not interesting for the user.  This happens, for
     * example, if OVS is using a userspace datapath and the kernel module
     * is not loaded. */
    if (openerror) {
        return openerror;
    } else {
        return at_least_one ? 0 : enumerror;
    }
}

static int
dpctl_show(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    int error, lasterror = 0;
    if (argc > 1) {
        int i;
        for (i = 1; i < argc; i++) {
            const char *name = argv[i];
            struct dpif *dpif;

            error = parsed_dpif_open(name, false, &dpif);
            if (!error) {
                show_dpif(dpif, dpctl_p);
                dpif_close(dpif);
            } else {
                dpctl_error(dpctl_p, error, "opening datapath %s failed",
                            name);
                lasterror = error;
            }
        }
    } else {
        lasterror = dps_for_each(dpctl_p, show_dpif);
    }

    return lasterror;
}

static void
dump_cb(struct dpif *dpif, struct dpctl_params *dpctl_p)
{
    dpctl_print(dpctl_p, "%s\n", dpif_name(dpif));
}

static int
dpctl_dump_dps(int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
               struct dpctl_params *dpctl_p)
{
    return dps_for_each(dpctl_p, dump_cb);
}

static void
format_dpif_flow(struct ds *ds, const struct dpif_flow *f, struct hmap *ports,
                 struct dpctl_params *dpctl_p)
{
    if (dpctl_p->verbosity && f->ufid_present) {
        odp_format_ufid(&f->ufid, ds);
        ds_put_cstr(ds, ", ");
    }
    odp_flow_format(f->key, f->key_len, f->mask, f->mask_len, ports, ds,
                    dpctl_p->verbosity);
    ds_put_cstr(ds, ", ");

    dpif_flow_stats_format(&f->stats, ds);
    if (dpctl_p->verbosity && f->attrs.offloaded) {
        if (f->attrs.dp_layer && !strcmp(f->attrs.dp_layer, "ovs")) {
            ds_put_cstr(ds, ", offloaded:partial");
        } else {
            ds_put_cstr(ds, ", offloaded:yes");
        }
    }
    if (dpctl_p->verbosity && f->attrs.dp_layer) {
        ds_put_format(ds, ", dp:%s", f->attrs.dp_layer);
    }
    ds_put_cstr(ds, ", actions:");
    format_odp_actions(ds, f->actions, f->actions_len, ports);
    if (dpctl_p->verbosity && f->attrs.dp_extra_info) {
        ds_put_format(ds, ", dp-extra-info:%s", f->attrs.dp_extra_info);
    }
}

struct dump_types {
    bool ovs;
    bool tc;
    bool dpdk;
    bool offloaded;
    bool non_offloaded;
    bool partially_offloaded;
};

static void
enable_all_dump_types(struct dump_types *dump_types)
{
    dump_types->ovs = true;
    dump_types->tc = true;
    dump_types->dpdk = true;
    dump_types->offloaded = true;
    dump_types->non_offloaded = true;
    dump_types->partially_offloaded = true;
}

static int
populate_dump_types(char *types_list, struct dump_types *dump_types,
                    struct dpctl_params *dpctl_p)
{
    if (!types_list) {
        enable_all_dump_types(dump_types);
        return 0;
    }

    char *current_type;

    while (types_list && types_list[0] != '\0') {
        current_type = types_list;
        size_t type_len = strcspn(current_type, ",");

        types_list += type_len + (types_list[type_len] != '\0');
        current_type[type_len] = '\0';

        if (!strcmp(current_type, "ovs")) {
            dump_types->ovs = true;
        } else if (!strcmp(current_type, "tc")) {
            dump_types->tc = true;
        } else if (!strcmp(current_type, "dpdk")) {
            dump_types->dpdk = true;
        } else if (!strcmp(current_type, "offloaded")) {
            dump_types->offloaded = true;
        } else if (!strcmp(current_type, "non-offloaded")) {
            dump_types->non_offloaded = true;
        } else if (!strcmp(current_type, "partially-offloaded")) {
            dump_types->partially_offloaded = true;
        } else if (!strcmp(current_type, "all")) {
            enable_all_dump_types(dump_types);
        } else {
            dpctl_error(dpctl_p, EINVAL, "Failed to parse type (%s)",
                        current_type);
            return EINVAL;
        }
    }
    return 0;
}

static void
determine_dpif_flow_dump_types(struct dump_types *dump_types,
                               struct dpif_flow_dump_types *dpif_dump_types)
{
    dpif_dump_types->ovs_flows = dump_types->ovs || dump_types->non_offloaded;
    dpif_dump_types->netdev_flows = dump_types->tc || dump_types->offloaded
                                    || dump_types->non_offloaded
                                    || dump_types->dpdk
                                    || dump_types->partially_offloaded;
}

static bool
flow_passes_type_filter(const struct dpif_flow *f,
                        struct dump_types *dump_types)
{
    if (dump_types->ovs && !strcmp(f->attrs.dp_layer, "ovs")) {
        return true;
    }
    if (dump_types->tc && !strcmp(f->attrs.dp_layer, "tc")) {
        return true;
    }
    if (dump_types->dpdk && !strcmp(f->attrs.dp_layer, "dpdk")) {
        return true;
    }
    if (dump_types->offloaded && f->attrs.offloaded &&
        strcmp(f->attrs.dp_layer, "ovs")) {
        return true;
    }
    if (dump_types->partially_offloaded && f->attrs.offloaded &&
        !strcmp(f->attrs.dp_layer, "ovs")) {
        return true;
    }
    if (dump_types->non_offloaded && !(f->attrs.offloaded)) {
        return true;
    }
    return false;
}

static struct hmap *
dpctl_get_portno_names(struct dpif *dpif, const struct dpctl_params *dpctl_p)
{
    if (dpctl_p->names) {
        struct hmap *portno_names = xmalloc(sizeof *portno_names);
        hmap_init(portno_names);

        struct dpif_port_dump port_dump;
        struct dpif_port dpif_port;
        DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
            odp_portno_names_set(portno_names, dpif_port.port_no,
                                 dpif_port.name);
        }

        return portno_names;
    } else {
        return NULL;
    }
}

static void
dpctl_free_portno_names(struct hmap *portno_names)
{
    if (portno_names) {
        odp_portno_names_destroy(portno_names);
        hmap_destroy(portno_names);
        free(portno_names);
    }
}

static int
dpctl_dump_flows(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    struct ds ds;

    char *filter = NULL;
    struct flow flow_filter;
    struct flow_wildcards wc_filter;
    char *types_list = NULL;
    struct dump_types dump_types;
    struct dpif_flow_dump_types dpif_dump_types;

    struct dpif_flow_dump_thread *flow_dump_thread;
    struct dpif_flow_dump *flow_dump;
    struct dpif_flow f;
    int pmd_id = PMD_ID_NULL;
    bool pmd_id_filter = false;
    int lastargc = 0;
    int error;

    while (argc > 1 && lastargc != argc) {
        lastargc = argc;
        if (!strncmp(argv[argc - 1], "filter=", 7) && !filter) {
            filter = xstrdup(argv[--argc] + 7);
        } else if (!strncmp(argv[argc - 1], "type=", 5) && !types_list) {
            if (!dpctl_p->is_appctl) {
                dpctl_error(dpctl_p, 0,
                            "Invalid argument 'type'. "
                            "Use 'ovs-appctl dpctl/dump-flows' instead.");
                error = EINVAL;
                goto out_free;
            }
            types_list = xstrdup(argv[--argc] + 5);
        } else if (!strncmp(argv[argc - 1], "pmd=", 4)) {
            if (!ovs_scan(argv[--argc], "pmd=%d", &pmd_id)) {
                error = EINVAL;
                goto out_free;
            }

            if (pmd_id == -1) {
                pmd_id = NON_PMD_CORE_ID;
            }
            pmd_id_filter = true;
        }
    }

    error = opt_dpif_open(argc, argv, dpctl_p, 2, &dpif);
    if (error) {
        goto out_free;
    }

    struct hmap *portno_names = dpctl_get_portno_names(dpif, dpctl_p);

    if (filter) {
        struct ofputil_port_map port_map;
        ofputil_port_map_init(&port_map);

        struct dpif_port_dump port_dump;
        struct dpif_port dpif_port;
        DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
            ofputil_port_map_put(&port_map,
                                 u16_to_ofp(odp_to_u32(dpif_port.port_no)),
                                 dpif_port.name);
        }
        char *err = parse_ofp_exact_flow(&flow_filter, &wc_filter, NULL,
                                         filter, &port_map);
        ofputil_port_map_destroy(&port_map);
        if (err) {
            dpctl_error(dpctl_p, 0, "Failed to parse filter (%s)", err);
            free(err);
            error = EINVAL;
            goto out_dpifclose;
        }
    }

    memset(&dump_types, 0, sizeof dump_types);
    error = populate_dump_types(types_list, &dump_types, dpctl_p);
    if (error) {
        goto out_dpifclose;
    }
    determine_dpif_flow_dump_types(&dump_types, &dpif_dump_types);

    /* Make sure that these values are different. PMD_ID_NULL means that the
     * pmd is unspecified (e.g. because the datapath doesn't have different
     * pmd threads), while NON_PMD_CORE_ID refers to every non pmd threads
     * in the userspace datapath */
    BUILD_ASSERT(PMD_ID_NULL != NON_PMD_CORE_ID);

    ds_init(&ds);
    memset(&f, 0, sizeof f);
    flow_dump = dpif_flow_dump_create(dpif, false, &dpif_dump_types);
    flow_dump_thread = dpif_flow_dump_thread_create(flow_dump);
    while (dpif_flow_dump_next(flow_dump_thread, &f, 1)) {
        if (filter) {
            struct flow flow;
            struct flow_wildcards wc;
            struct match match, match_filter;
            struct minimatch minimatch;

            odp_flow_key_to_flow(f.key, f.key_len, &flow, NULL);
            odp_flow_key_to_mask(f.mask, f.mask_len, &wc, &flow, NULL);
            match_init(&match, &flow, &wc);

            match_init(&match_filter, &flow_filter, &wc);
            match_init(&match_filter, &match_filter.flow, &wc_filter);
            minimatch_init(&minimatch, &match_filter);

            if (!minimatch_matches_flow(&minimatch, &match.flow)) {
                minimatch_destroy(&minimatch);
                continue;
            }
            minimatch_destroy(&minimatch);
        }
        ds_clear(&ds);
        /* If 'pmd_id' is specified, overlapping flows could be dumped from
         * different pmd threads.  So, separates dumps from different pmds
         * by printing a title line. */
        if (!pmd_id_filter && pmd_id != f.pmd_id) {
            if (f.pmd_id == NON_PMD_CORE_ID) {
                ds_put_format(&ds, "flow-dump from the main thread:\n");
            } else {
                ds_put_format(&ds, "flow-dump from pmd on cpu core: %d\n",
                              f.pmd_id);
            }
            pmd_id = f.pmd_id;
        }
        if (pmd_id == f.pmd_id &&
            flow_passes_type_filter(&f, &dump_types)) {
            format_dpif_flow(&ds, &f, portno_names, dpctl_p);
            dpctl_print(dpctl_p, "%s\n", ds_cstr(&ds));
        }
    }
    dpif_flow_dump_thread_destroy(flow_dump_thread);
    error = dpif_flow_dump_destroy(flow_dump);

    if (error) {
        dpctl_error(dpctl_p, error, "Failed to dump flows from datapath");
    }
    ds_destroy(&ds);

out_dpifclose:
    dpctl_free_portno_names(portno_names);
    dpif_close(dpif);
out_free:
    free(filter);
    free(types_list);
    return error;
}

static int
dpctl_put_flow_dpif(struct dpif *dpif, const char *key_s,
                    const char *actions_s,
                    enum dpif_flow_put_flags flags,
                    struct dpctl_params *dpctl_p)
{
    struct dpif_flow_stats stats;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct ofpbuf actions;
    struct ofpbuf key;
    struct ofpbuf mask;
    ovs_u128 ufid;
    bool ufid_present;
    struct simap port_names;
    int n, error;

    ufid_present = false;
    n = odp_ufid_from_string(key_s, &ufid);
    if (n < 0) {
        dpctl_error(dpctl_p, -n, "parsing flow ufid");
        return -n;
    } else if (n) {
        key_s += n;
        ufid_present = true;
    }

    simap_init(&port_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        simap_put(&port_names, dpif_port.name, odp_to_u32(dpif_port.port_no));
    }

    ofpbuf_init(&key, 0);
    ofpbuf_init(&mask, 0);
    char *error_s;
    error = odp_flow_from_string(key_s, &port_names, &key, &mask, &error_s);
    simap_destroy(&port_names);
    if (error) {
        dpctl_error(dpctl_p, error, "parsing flow key (%s)", error_s);
        free(error_s);
        goto out_freekeymask;
    }

    ofpbuf_init(&actions, 0);
    error = odp_actions_from_string(actions_s, NULL, &actions);
    if (error) {
        dpctl_error(dpctl_p, error, "parsing actions");
        goto out_freeactions;
    }

    if (!ufid_present && dpctl_p->is_appctl) {
        /* Generating UFID for this flow so it could be offloaded to HW.  We're
         * not doing that if invoked from ovs-dpctl utility because
         * odp_flow_key_hash() uses randomly generated base for flow hashes
         * that will be different for each invocation.  And, anyway, offloading
         * is only available via appctl. */
        odp_flow_key_hash(key.data, key.size, &ufid);
        ufid_present = true;
    }

    /* The flow will be added on all pmds currently in the datapath. */
    error = dpif_flow_put(dpif, flags,
                          key.data, key.size,
                          mask.size == 0 ? NULL : mask.data,
                          mask.size, actions.data,
                          actions.size, ufid_present ? &ufid : NULL,
                          PMD_ID_NULL,
                          dpctl_p->print_statistics ? &stats : NULL);

    if (error) {
        dpctl_error(dpctl_p, error, "updating flow table");
        goto out_freeactions;
    }

    if (dpctl_p->print_statistics) {
        struct ds s;

        ds_init(&s);
        dpif_flow_stats_format(&stats, &s);
        dpctl_print(dpctl_p, "%s\n", ds_cstr(&s));
        ds_destroy(&s);
    }

out_freeactions:
    ofpbuf_uninit(&actions);
out_freekeymask:
    ofpbuf_uninit(&mask);
    ofpbuf_uninit(&key);
    return error;
}

static int
dpctl_put_flow(int argc, const char *argv[], enum dpif_flow_put_flags flags,
               struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error;

    error = opt_dpif_open(argc, argv, dpctl_p, 4, &dpif);
    if (error) {
        return error;
    }

    error = dpctl_put_flow_dpif(dpif, argv[argc - 2], argv[argc - 1], flags,
                                dpctl_p);

    dpif_close(dpif);
    return error;
}

static int
dpctl_add_flow(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    return dpctl_put_flow(argc, argv, DPIF_FP_CREATE, dpctl_p);
}

static int
dpctl_mod_flow(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    enum dpif_flow_put_flags flags;

    flags = DPIF_FP_MODIFY;
    if (dpctl_p->may_create) {
        flags |= DPIF_FP_CREATE;
    }
    if (dpctl_p->zero_statistics) {
        flags |= DPIF_FP_ZERO_STATS;
    }

    return dpctl_put_flow(argc, argv, flags, dpctl_p);
}

static int
dpctl_get_flow(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    const char *key_s = argv[argc - 1];
    struct dpif_flow flow;
    struct dpif *dpif;
    ovs_u128 ufid;
    struct ofpbuf buf;
    uint64_t stub[DPIF_FLOW_BUFSIZE / 8];
    struct ds ds;
    int n, error;

    error = opt_dpif_open(argc, argv, dpctl_p, 3, &dpif);
    if (error) {
        return error;
    }

    ofpbuf_use_stub(&buf, &stub, sizeof stub);

    struct hmap *portno_names = dpctl_get_portno_names(dpif, dpctl_p);

    n = odp_ufid_from_string(key_s, &ufid);
    if (n <= 0) {
        dpctl_error(dpctl_p, -n, "parsing flow ufid");
        goto out;
    }

    /* In case of PMD will be returned flow from first PMD thread with match. */
    error = dpif_flow_get(dpif, NULL, 0, &ufid, PMD_ID_NULL, &buf, &flow);
    if (error) {
        dpctl_error(dpctl_p, error, "getting flow");
        goto out;
    }

    ds_init(&ds);
    format_dpif_flow(&ds, &flow, portno_names, dpctl_p);
    dpctl_print(dpctl_p, "%s\n", ds_cstr(&ds));
    ds_destroy(&ds);

out:
    dpctl_free_portno_names(portno_names);
    ofpbuf_uninit(&buf);
    dpif_close(dpif);
    return error;
}

static int
dpctl_del_flow_dpif(struct dpif *dpif, const char *key_s,
                    struct dpctl_params *dpctl_p)
{
    struct dpif_flow_stats stats;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct ofpbuf key;
    struct ofpbuf mask; /* To be ignored. */

    ovs_u128 ufid;
    bool ufid_generated;
    bool ufid_present;
    struct simap port_names;
    int n, error;

    ufid_present = false;
    n = odp_ufid_from_string(key_s, &ufid);
    if (n < 0) {
        dpctl_error(dpctl_p, -n, "parsing flow ufid");
        return -n;
    } else if (n) {
        key_s += n;
        ufid_present = true;
    }

    simap_init(&port_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        simap_put(&port_names, dpif_port.name, odp_to_u32(dpif_port.port_no));
    }

    ofpbuf_init(&key, 0);
    ofpbuf_init(&mask, 0);

    char *error_s;
    error = odp_flow_from_string(key_s, &port_names, &key, &mask, &error_s);
    if (error) {
        dpctl_error(dpctl_p, error, "%s", error_s);
        free(error_s);
        goto out;
    }

    if (!ufid_present && dpctl_p->is_appctl) {
        /* While adding flow via appctl we're generating UFID to make HW
         * offloading possible.  Generating UFID here to be sure that such
         * flows could be removed the same way they were added. */
        odp_flow_key_hash(key.data, key.size, &ufid);
        ufid_present = ufid_generated = true;
    }

    /* The flow will be deleted from all pmds currently in the datapath. */
    error = dpif_flow_del(dpif, key.data, key.size,
                          ufid_present ? &ufid : NULL, PMD_ID_NULL,
                          dpctl_p->print_statistics ? &stats : NULL);

    if (error) {
        dpctl_error(dpctl_p, error, "deleting flow");
        if (error == ENOENT && (!ufid_present || ufid_generated)) {
            struct ds s;

            ds_init(&s);
            ds_put_format(&s, "Perhaps you need to specify a UFID?");
            dpctl_print(dpctl_p, "%s\n", ds_cstr(&s));
            ds_destroy(&s);
        }
        goto out;
    }

    if (dpctl_p->print_statistics) {
        struct ds s;

        ds_init(&s);
        dpif_flow_stats_format(&stats, &s);
        dpctl_print(dpctl_p, "%s\n", ds_cstr(&s));
        ds_destroy(&s);
    }

out:
    ofpbuf_uninit(&mask);
    ofpbuf_uninit(&key);
    simap_destroy(&port_names);
    return error;
}

static int
dpctl_del_flow(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    const char *key_s = argv[argc - 1];
    struct dpif *dpif;
    int error;

    error = opt_dpif_open(argc, argv, dpctl_p, 3, &dpif);
    if (error) {
        return error;
    }

    error = dpctl_del_flow_dpif(dpif, key_s, dpctl_p);

    dpif_close(dpif);
    return error;
}

static int
dpctl_parse_flow_line(int command, struct ds *s, char **flow, char **action)
{
    const char *line = ds_cstr(s);
    size_t len;

    /* First figure out the command, or fallback to FLOWS_ADD. */
    line += strspn(line, " \t\r\n");
    len = strcspn(line, ", \t\r\n");

    if (!strncmp(line, "add", len)) {
         command = DPCTL_FLOWS_ADD;
    } else if (!strncmp(line, "delete", len)) {
        command = DPCTL_FLOWS_DEL;
    } else if (!strncmp(line, "modify", len)) {
        command = DPCTL_FLOWS_MOD;
    } else {
        len = 0;
    }
    line += len;

    /* Isolate flow and action (for add/modify). */
    line += strspn(line, " \t\r\n");
    len = strcspn(line, " \t\r\n");

    if (len == 0) {
        *flow = NULL;
        *action = NULL;
        return command;
    }

    *flow = xzalloc(len + 1);
    ovs_strlcpy(*flow, line, len + 1);

    line += len;
    line += strspn(line, " \t\r\n");
    if (strlen(line)) {
        *action = xstrdup(line);
    } else {
        *action = NULL;
    }

    return command;
}

static int
dpctl_process_flows(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    const char *file_name = argv[argc - 1];
    int line_number = 0;
    struct dpif *dpif;
    struct ds line;
    FILE *stream;
    int error;
    int def_cmd = DPCTL_FLOWS_ADD;

    if (strstr(argv[0], "mod-flows")) {
        def_cmd = DPCTL_FLOWS_MOD;
    } else if (strstr(argv[0], "del-flows")) {
        def_cmd = DPCTL_FLOWS_DEL;
    }

    error = opt_dpif_open(argc, argv, dpctl_p, 4, &dpif);
    if (error) {
        return error;
    }

    stream = !strcmp(file_name, "-") ? stdin : fopen(file_name, "r");
    if (!stream) {
        error = errno;
        dpctl_error(dpctl_p, error, "Opening file \"%s\" failed", file_name);
        goto out_close_dpif;
    }

    ds_init(&line);
    while (!ds_get_preprocessed_line(&line, stream, &line_number)) {
        /* We do not process all the lines first and then execute the actions
         * as we would like to take commands as a continuous stream of
         * commands from stdin.
         */
        char *flow = NULL;
        char *action = NULL;
        int cmd = dpctl_parse_flow_line(def_cmd, &line, &flow, &action);

        if ((!flow && !action)
            || ((cmd == DPCTL_FLOWS_ADD || cmd == DPCTL_FLOWS_MOD) && !action)
            || (cmd == DPCTL_FLOWS_DEL && action)) {
            dpctl_error(dpctl_p, 0,
                        "Failed parsing line number %u, skipped!",
                        line_number);
        } else {
            switch (cmd) {
            case DPCTL_FLOWS_ADD:
                dpctl_put_flow_dpif(dpif, flow, action,
                                    DPIF_FP_CREATE, dpctl_p);
                break;
            case DPCTL_FLOWS_MOD:
                dpctl_put_flow_dpif(dpif, flow, action,
                                    DPIF_FP_MODIFY, dpctl_p);
                break;
            case DPCTL_FLOWS_DEL:
                dpctl_del_flow_dpif(dpif, flow, dpctl_p);
                break;
            }
        }

        free(flow);
        free(action);
    }

    ds_destroy(&line);
    if (stream != stdin) {
        fclose(stream);
    }
out_close_dpif:
    dpif_close(dpif);
    return 0;
}

static int
dpctl_del_flows(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error;

    if ((!dp_arg_exists(argc, argv) && argc == 2) || argc > 2) {
        return dpctl_process_flows(argc, argv, dpctl_p);
    }

    error = opt_dpif_open(argc, argv, dpctl_p, 2, &dpif);
    if (error) {
        return error;
    }

    error = dpif_flow_flush(dpif);
    if (error) {
        dpctl_error(dpctl_p, error, "deleting all flows");
    }
    dpif_close(dpif);
    return error;
}

static int
dpctl_help(int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
           struct dpctl_params *dpctl_p)
{
    if (dpctl_p->usage) {
        dpctl_p->usage(dpctl_p->aux);
    }

    return 0;
}

static int
dpctl_list_commands(int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                    struct dpctl_params *dpctl_p)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct dpctl_command *commands = get_all_dpctl_commands();

    ds_put_cstr(&ds, "The available commands are:\n");
    for (; commands->name; commands++) {
        const struct dpctl_command *c = commands;

        if (dpctl_p->is_appctl && !strcmp(c->name, "help")) {
            continue;
        }

        ds_put_format(&ds, "  %s%-23s %s\n", dpctl_p->is_appctl ? "dpctl/" : "",
                      c->name, c->usage);
    }
    dpctl_puts(dpctl_p, false, ds.string);
    ds_destroy(&ds);

    return 0;
}


static int
dpctl_dump_conntrack(int argc, const char *argv[],
                     struct dpctl_params *dpctl_p)
{
    struct ct_dpif_dump_state *dump;
    struct ct_dpif_entry cte;
    uint16_t zone, *pzone = NULL;
    int tot_bkts;
    struct dpif *dpif;
    int error;

    if (argc > 1 && ovs_scan(argv[argc - 1], "zone=%"SCNu16, &zone)) {
        pzone = &zone;
        argc--;
    }

    error = opt_dpif_open(argc, argv, dpctl_p, 2, &dpif);
    if (error) {
        return error;
    }

    error = ct_dpif_dump_start(dpif, &dump, pzone, &tot_bkts);
    if (error) {
        dpctl_error(dpctl_p, error, "starting conntrack dump");
        dpif_close(dpif);
        return error;
    }

    while (!(error = ct_dpif_dump_next(dump, &cte))) {
        struct ds s = DS_EMPTY_INITIALIZER;

        ct_dpif_format_entry(&cte, &s, dpctl_p->verbosity,
                             dpctl_p->print_statistics);
        ct_dpif_entry_uninit(&cte);

        dpctl_print(dpctl_p, "%s\n", ds_cstr(&s));
        ds_destroy(&s);
    }
    if (error == EOF) {
        /* Any CT entry was dumped with no issue. */
        error = 0;
    } else if (error) {
        dpctl_error(dpctl_p, error, "dumping conntrack entry");
    }

    ct_dpif_dump_done(dump);
    dpif_close(dpif);
    return error;
}

static int
dpctl_flush_conntrack(int argc, const char *argv[],
                      struct dpctl_params *dpctl_p)
{
    struct dpif *dpif = NULL;
    struct ct_dpif_tuple tuple, *ptuple = NULL;
    struct ds ds = DS_EMPTY_INITIALIZER;
    uint16_t zone, *pzone = NULL;
    int error;
    int args = argc - 1;

    /* Parse ct tuple */
    if (args && ct_dpif_parse_tuple(&tuple, argv[args], &ds)) {
        ptuple = &tuple;
        args--;
    }

    /* Parse zone */
    if (args && ovs_scan(argv[args], "zone=%"SCNu16, &zone)) {
        pzone = &zone;
        args--;
    }

    /* Report error if there are more than one unparsed argument. */
    if (args > 1) {
        ds_put_cstr(&ds, "invalid arguments");
        error = EINVAL;
        goto error;
    }

    error = opt_dpif_open(argc, argv, dpctl_p, 4, &dpif);
    if (error) {
        return error;
    }

    error = ct_dpif_flush(dpif, pzone, ptuple);
    if (!error) {
        dpif_close(dpif);
        return 0;
    } else {
        ds_put_cstr(&ds, "failed to flush conntrack");
    }

error:
    dpctl_error(dpctl_p, error, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
    dpif_close(dpif);
    return error;
}

static int
dpctl_ct_stats_show(int argc, const char *argv[],
                     struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    struct ct_dpif_dump_state *dump;
    struct ct_dpif_entry cte;
    uint16_t zone, *pzone = NULL;
    int tot_bkts;
    int lastargc = 0;

    int proto_stats[CT_STATS_MAX];
    int tcp_conn_per_states[CT_DPIF_TCPS_MAX_NUM];
    int error;

    bool verbose = dpctl_p->verbosity;

    while (argc > 1 && lastargc != argc) {
        lastargc = argc;
        if (!strncmp(argv[argc - 1], "verbose", 7)) {
            /* Support "verbose" argument for backwards compatibility. */
            verbose = true;
            argc--;
        } else if (!strncmp(argv[argc - 1], "zone=", 5)) {
            if (ovs_scan(argv[argc - 1], "zone=%"SCNu16, &zone)) {
                pzone = &zone;
                argc--;
            }
        }
    }

    error = opt_dpif_open(argc, argv, dpctl_p, 2, &dpif);
    if (error) {
        return error;
    }

    memset(proto_stats, 0, sizeof(proto_stats));
    memset(tcp_conn_per_states, 0, sizeof(tcp_conn_per_states));
    error = ct_dpif_dump_start(dpif, &dump, pzone, &tot_bkts);
    if (error) {
        dpctl_error(dpctl_p, error, "starting conntrack dump");
        dpif_close(dpif);
        return error;
    }

    int tot_conn = 0;
    while (!(error = ct_dpif_dump_next(dump, &cte))) {
        ct_dpif_entry_uninit(&cte);
        tot_conn++;
        switch (cte.tuple_orig.ip_proto) {
        case IPPROTO_ICMP:
            proto_stats[CT_STATS_ICMP]++;
            break;
        case IPPROTO_ICMPV6:
            proto_stats[CT_STATS_ICMPV6]++;
            break;
        case IPPROTO_TCP:
            proto_stats[CT_STATS_TCP]++;
            uint8_t tcp_state;
            /* We keep two separate tcp states, but we print just one. The
             * Linux kernel connection tracker internally keeps only one state,
             * so 'state_orig' and 'state_reply', will be the same. */
            tcp_state = MAX(cte.protoinfo.tcp.state_orig,
                            cte.protoinfo.tcp.state_reply);
            tcp_state = ct_dpif_coalesce_tcp_state(tcp_state);
            tcp_conn_per_states[tcp_state]++;
            break;
        case IPPROTO_UDP:
            proto_stats[CT_STATS_UDP]++;
            break;
        case IPPROTO_SCTP:
            proto_stats[CT_STATS_SCTP]++;
            break;
        case IPPROTO_UDPLITE:
            proto_stats[CT_STATS_UDPLITE]++;
            break;
        case IPPROTO_DCCP:
            proto_stats[CT_STATS_DCCP]++;
            break;
        case IPPROTO_IGMP:
            proto_stats[CT_STATS_IGMP]++;
            break;
        default:
            proto_stats[CT_STATS_OTHER]++;
            break;
        }
    }
    if (error == EOF) {
        /* All CT entries were dumped with no issue.  */
        error = 0;
    } else if (error) {
        dpctl_error(dpctl_p, error, "dumping conntrack entry");
        /* Fall through to show any other info we collected. */
    }

    dpctl_print(dpctl_p, "Connections Stats:\n    Total: %d\n", tot_conn);
    if (proto_stats[CT_STATS_TCP]) {
        dpctl_print(dpctl_p, "  TCP: %d\n", proto_stats[CT_STATS_TCP]);
        if (verbose) {
            dpctl_print(dpctl_p, "    Conn per TCP states:\n");
            for (int i = 0; i < CT_DPIF_TCPS_MAX_NUM; i++) {
                if (tcp_conn_per_states[i]) {
                    struct ds s = DS_EMPTY_INITIALIZER;
                    ct_dpif_format_tcp_stat(&s, i, tcp_conn_per_states[i]);
                    dpctl_print(dpctl_p, "%s\n", ds_cstr(&s));
                    ds_destroy(&s);
                }
            }
        }
    }
    if (proto_stats[CT_STATS_UDP]) {
        dpctl_print(dpctl_p, "  UDP: %d\n", proto_stats[CT_STATS_UDP]);
    }
    if (proto_stats[CT_STATS_UDPLITE]) {
        dpctl_print(dpctl_p, "  UDPLITE: %d\n", proto_stats[CT_STATS_UDPLITE]);
    }
    if (proto_stats[CT_STATS_SCTP]) {
        dpctl_print(dpctl_p, "  SCTP: %d\n", proto_stats[CT_STATS_SCTP]);
    }
    if (proto_stats[CT_STATS_ICMP]) {
        dpctl_print(dpctl_p, "  ICMP: %d\n", proto_stats[CT_STATS_ICMP]);
    }
    if (proto_stats[CT_STATS_DCCP]) {
        dpctl_print(dpctl_p, "  DCCP: %d\n", proto_stats[CT_STATS_DCCP]);
    }
    if (proto_stats[CT_STATS_IGMP]) {
        dpctl_print(dpctl_p, "  IGMP: %d\n", proto_stats[CT_STATS_IGMP]);
    }
    if (proto_stats[CT_STATS_OTHER]) {
        dpctl_print(dpctl_p, "  Other: %d\n", proto_stats[CT_STATS_OTHER]);
    }

    ct_dpif_dump_done(dump);
    dpif_close(dpif);
    return error;
}

#define CT_BKTS_GT "gt="
static int
dpctl_ct_bkts(int argc, const char *argv[],
                     struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    struct ct_dpif_dump_state *dump;
    struct ct_dpif_entry cte;
    uint16_t gt = 0; /* Threshold: display value when greater than gt. */
    uint16_t *pzone = NULL;
    int tot_bkts = 0;
    int error;

    if (argc > 1 && !strncmp(argv[argc - 1], CT_BKTS_GT, strlen(CT_BKTS_GT))) {
        if (ovs_scan(argv[argc - 1], CT_BKTS_GT"%"SCNu16, &gt)) {
            argc--;
        }
    }

    error = opt_dpif_open(argc, argv, dpctl_p, 2, &dpif);
    if (error) {
        return error;
    }

    error = ct_dpif_dump_start(dpif, &dump, pzone, &tot_bkts);
    if (error) {
        dpctl_error(dpctl_p, error, "starting conntrack dump");
        dpif_close(dpif);
        return error;
    }
    if (tot_bkts == -1) {
         /* Command not available when called by kernel OvS. */
         dpctl_print(dpctl_p,
             "Command is available for UserSpace ConnTracker only.\n");
         ct_dpif_dump_done(dump);
         dpif_close(dpif);
         return 0;
    }

    dpctl_print(dpctl_p, "Total Buckets: %d\n", tot_bkts);

    int tot_conn = 0;
    uint32_t *conn_per_bkts = xzalloc(tot_bkts * sizeof(uint32_t));

    while (!(error = ct_dpif_dump_next(dump, &cte))) {
        ct_dpif_entry_uninit(&cte);
        tot_conn++;
        if (tot_bkts > 0) {
            if (cte.bkt < tot_bkts) {
                conn_per_bkts[cte.bkt]++;
            } else {
                dpctl_print(dpctl_p, "Bucket nr out of range: %d >= %d\n",
                        cte.bkt, tot_bkts);
            }
        }
    }
    if (error == EOF) {
        /* All CT entries were dumped with no issue.  */
        error = 0;
    } else if (error) {
        dpctl_error(dpctl_p, error, "dumping conntrack entry");
        /* Fall through and display all the collected info.  */
    }

    dpctl_print(dpctl_p, "Current Connections: %d\n", tot_conn);
    dpctl_print(dpctl_p, "\n");
    if (tot_bkts && tot_conn) {
        dpctl_print(dpctl_p, "+-----------+"
                "-----------------------------------------+\n");
        dpctl_print(dpctl_p, "|  Buckets  |"
                "         Connections per Buckets         |\n");
        dpctl_print(dpctl_p, "+-----------+"
                "-----------------------------------------+");
#define NUM_BKTS_DIPLAYED_PER_ROW 8
        for (int i = 0; i < tot_bkts; i++) {
            if (i % NUM_BKTS_DIPLAYED_PER_ROW == 0) {
                 dpctl_print(dpctl_p, "\n %3d..%3d   | ",
                         i, i + NUM_BKTS_DIPLAYED_PER_ROW - 1);
            }
            if (conn_per_bkts[i] > gt) {
                dpctl_print(dpctl_p, "%5d", conn_per_bkts[i]);
            } else {
                dpctl_print(dpctl_p, "%5s", ".");
            }
        }
        dpctl_print(dpctl_p, "\n\n");
    }

    ct_dpif_dump_done(dump);
    dpif_close(dpif);
    free(conn_per_bkts);
    return error;
}

static int
dpctl_ct_set_maxconns(int argc, const char *argv[],
                      struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error = opt_dpif_open(argc, argv, dpctl_p, 3, &dpif);
    if (!error) {
        uint32_t maxconns;
        if (ovs_scan(argv[argc - 1], "%"SCNu32, &maxconns)) {
            error = ct_dpif_set_maxconns(dpif, maxconns);

            if (!error) {
                dpctl_print(dpctl_p, "setting maxconns successful");
            } else {
                dpctl_error(dpctl_p, error, "ct set maxconns failed");
            }
        } else {
            error = EINVAL;
            dpctl_error(dpctl_p, error, "maxconns missing or malformed");
        }
        dpif_close(dpif);
    }

    return error;
}

static int
dpctl_ct_get_maxconns(int argc, const char *argv[],
                    struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error = opt_dpif_open(argc, argv, dpctl_p, 2, &dpif);
    if (!error) {
        uint32_t maxconns;
        error = ct_dpif_get_maxconns(dpif, &maxconns);

        if (!error) {
            dpctl_print(dpctl_p, "%u\n", maxconns);
        } else {
            dpctl_error(dpctl_p, error, "maxconns could not be retrieved");
        }
        dpif_close(dpif);
    }

    return error;
}

static int
dpctl_ct_get_nconns(int argc, const char *argv[],
                    struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error = opt_dpif_open(argc, argv, dpctl_p, 2, &dpif);
    if (!error) {
        uint32_t nconns;
        error = ct_dpif_get_nconns(dpif, &nconns);

        if (!error) {
            dpctl_print(dpctl_p, "%u\n", nconns);
        } else {
            dpctl_error(dpctl_p, error, "nconns could not be retrieved");
        }
        dpif_close(dpif);
    }

    return error;
}

static int
dpctl_ct_set_tcp_seq_chk__(int argc, const char *argv[],
                           struct dpctl_params *dpctl_p, bool enabled)
{
    struct dpif *dpif;
    int error = opt_dpif_open(argc, argv, dpctl_p, 3, &dpif);
    if (!error) {
        error = ct_dpif_set_tcp_seq_chk(dpif, enabled);
        if (!error) {
            dpctl_print(dpctl_p,
                        "%s TCP sequence checking successful",
                        enabled ? "enabling" : "disabling");
        } else {
            dpctl_error(dpctl_p, error,
                        "%s TCP sequence checking failed",
                        enabled ? "enabling" : "disabling");
        }
        dpif_close(dpif);
    }
    return error;
}

static int
dpctl_ct_enable_tcp_seq_chk(int argc, const char *argv[],
                            struct dpctl_params *dpctl_p)
{
    return dpctl_ct_set_tcp_seq_chk__(argc, argv, dpctl_p, true);
}

static int
dpctl_ct_disable_tcp_seq_chk(int argc, const char *argv[],
                             struct dpctl_params *dpctl_p)
{
    return dpctl_ct_set_tcp_seq_chk__(argc, argv, dpctl_p, false);
}

static int
dpctl_ct_get_tcp_seq_chk(int argc, const char *argv[],
                         struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error = opt_dpif_open(argc, argv, dpctl_p, 2, &dpif);
    if (!error) {
        bool enabled;
        error = ct_dpif_get_tcp_seq_chk(dpif, &enabled);
        if (!error) {
            dpctl_print(dpctl_p, "TCP sequence checking: %s\n",
                        enabled ? "enabled" : "disabled");
        } else {
            dpctl_error(dpctl_p, error, "TCP sequence checking query failed");
        }
        dpif_close(dpif);
    }
    return error;
}

static int
dpctl_ct_set_limits(int argc, const char *argv[],
                    struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    struct ds ds = DS_EMPTY_INITIALIZER;
    int i =  dp_arg_exists(argc, argv) ? 2 : 1;
    uint32_t default_limit, *p_default_limit = NULL;
    struct ovs_list zone_limits = OVS_LIST_INITIALIZER(&zone_limits);

    int error = opt_dpif_open(argc, argv, dpctl_p, INT_MAX, &dpif);
    if (error) {
        return error;
    }

    /* Parse default limit */
    if (!strncmp(argv[i], "default=", 8)) {
        if (ovs_scan(argv[i], "default=%"SCNu32, &default_limit)) {
            p_default_limit = &default_limit;
            i++;
        } else {
            ds_put_cstr(&ds, "invalid default limit");
            error = EINVAL;
            goto error;
        }
    }

    /* Parse ct zone limit tuples */
    while (i < argc) {
        uint16_t zone;
        uint32_t limit;
        if (!ct_dpif_parse_zone_limit_tuple(argv[i++], &zone, &limit, &ds)) {
            error = EINVAL;
            goto error;
        }
        ct_dpif_push_zone_limit(&zone_limits, zone, limit, 0);
    }

    error = ct_dpif_set_limits(dpif, p_default_limit, &zone_limits);
    if (!error) {
        ct_dpif_free_zone_limits(&zone_limits);
        dpif_close(dpif);
        return 0;
    } else {
        ds_put_cstr(&ds, "failed to set conntrack limit");
    }

error:
    dpctl_error(dpctl_p, error, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
    ct_dpif_free_zone_limits(&zone_limits);
    dpif_close(dpif);
    return error;
}

static int
parse_ct_limit_zones(const char *argv, struct ovs_list *zone_limits,
                     struct ds *ds)
{
    char *save_ptr = NULL, *argcopy, *next_zone;
    uint16_t zone;

    if (strncmp(argv, "zone=", 5)) {
        ds_put_format(ds, "invalid argument %s", argv);
        return EINVAL;
    }

    argcopy = xstrdup(argv + 5);
    next_zone = strtok_r(argcopy, ",", &save_ptr);

    do {
        if (ovs_scan(next_zone, "%"SCNu16, &zone)) {
            ct_dpif_push_zone_limit(zone_limits, zone, 0, 0);
        } else {
            ds_put_cstr(ds, "invalid zone");
            free(argcopy);
            return EINVAL;
        }
    } while ((next_zone = strtok_r(NULL, ",", &save_ptr)) != NULL);

    free(argcopy);
    return 0;
}

static int
dpctl_ct_del_limits(int argc, const char *argv[],
                    struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    struct ds ds = DS_EMPTY_INITIALIZER;
    int error;
    int i =  dp_arg_exists(argc, argv) ? 2 : 1;
    struct ovs_list zone_limits = OVS_LIST_INITIALIZER(&zone_limits);

    error = opt_dpif_open(argc, argv, dpctl_p, 3, &dpif);
    if (error) {
        return error;
    }

    error = parse_ct_limit_zones(argv[i], &zone_limits, &ds);
    if (error) {
        goto error;
    }

    error = ct_dpif_del_limits(dpif, &zone_limits);
    if (!error) {
        goto out;
    } else {
        ds_put_cstr(&ds, "failed to delete conntrack limit");
    }

error:
    dpctl_error(dpctl_p, error, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
out:
    ct_dpif_free_zone_limits(&zone_limits);
    dpif_close(dpif);
    return error;
}

static int
dpctl_ct_get_limits(int argc, const char *argv[],
                    struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    struct ds ds = DS_EMPTY_INITIALIZER;
    uint32_t default_limit;
    int i =  dp_arg_exists(argc, argv) ? 2 : 1;
    struct ovs_list list_query = OVS_LIST_INITIALIZER(&list_query);
    struct ovs_list list_reply = OVS_LIST_INITIALIZER(&list_reply);

    int error = opt_dpif_open(argc, argv, dpctl_p, 3, &dpif);
    if (error) {
        return error;
    }

    if (argc > i) {
        error = parse_ct_limit_zones(argv[i], &list_query, &ds);
        if (error) {
            goto error;
        }
    }

    error = ct_dpif_get_limits(dpif, &default_limit, &list_query,
                               &list_reply);
    if (!error) {
        ct_dpif_format_zone_limits(default_limit, &list_reply, &ds);
        dpctl_print(dpctl_p, "%s\n", ds_cstr(&ds));
        goto out;
    } else {
        ds_put_format(&ds, "failed to get conntrack limit %s",
                      ovs_strerror(error));
    }

error:
    dpctl_error(dpctl_p, error, "%s", ds_cstr(&ds));
out:
    ds_destroy(&ds);
    ct_dpif_free_zone_limits(&list_query);
    ct_dpif_free_zone_limits(&list_reply);
    dpif_close(dpif);
    return error;
}

static int
ipf_set_enabled__(int argc, const char *argv[], struct dpctl_params *dpctl_p,
                  bool enabled)
{
    struct dpif *dpif;
    int error = opt_dpif_open(argc, argv, dpctl_p, 4, &dpif);
    if (!error) {
        char v4_or_v6[3] = {0};
        if (ovs_scan(argv[argc - 1], "%2s", v4_or_v6) &&
            (!strncmp(v4_or_v6, "v4", 2) || !strncmp(v4_or_v6, "v6", 2))) {
            error = ct_dpif_ipf_set_enabled(
                        dpif, !strncmp(v4_or_v6, "v6", 2), enabled);
            if (!error) {
                dpctl_print(dpctl_p,
                            "%s fragmentation reassembly successful",
                            enabled ? "enabling" : "disabling");
            } else {
                dpctl_error(dpctl_p, error,
                            "%s fragmentation reassembly failed",
                            enabled ? "enabling" : "disabling");
            }
        } else {
            error = EINVAL;
            dpctl_error(dpctl_p, error,
                        "parameter missing: 'v4' for IPv4 or 'v6' for IPv6");
        }
        dpif_close(dpif);
    }
    return error;
}

static int
dpctl_ipf_set_enabled(int argc, const char *argv[],
                      struct dpctl_params *dpctl_p)
{
    return ipf_set_enabled__(argc, argv, dpctl_p, true);
}

static int
dpctl_ipf_set_disabled(int argc, const char *argv[],
                       struct dpctl_params *dpctl_p)
{
    return ipf_set_enabled__(argc, argv, dpctl_p, false);
}

static int
dpctl_ipf_set_min_frag(int argc, const char *argv[],
                       struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error = opt_dpif_open(argc, argv, dpctl_p, 4, &dpif);
    if (!error) {
        char v4_or_v6[3] = {0};
        if (ovs_scan(argv[argc - 2], "%2s", v4_or_v6) &&
            (!strncmp(v4_or_v6, "v4", 2) || !strncmp(v4_or_v6, "v6", 2))) {
            uint32_t min_fragment;
            if (ovs_scan(argv[argc - 1], "%"SCNu32, &min_fragment)) {
                error = ct_dpif_ipf_set_min_frag(
                            dpif, !strncmp(v4_or_v6, "v6", 2), min_fragment);
                if (!error) {
                    dpctl_print(dpctl_p,
                                "setting minimum fragment size successful");
                } else {
                    dpctl_error(dpctl_p, error,
                                "requested minimum fragment size too small;"
                                " see documentation");
                }
            } else {
                error = EINVAL;
                dpctl_error(dpctl_p, error,
                            "parameter missing for minimum fragment size");
            }
        } else {
            error = EINVAL;
            dpctl_error(dpctl_p, error,
                        "parameter missing: v4 for IPv4 or v6 for IPv6");
        }
        dpif_close(dpif);
    }

    return error;
}

static int
dpctl_ipf_set_max_nfrags(int argc, const char *argv[],
                         struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error = opt_dpif_open(argc, argv, dpctl_p, 3, &dpif);
    if (!error) {
        uint32_t nfrags_max;
        if (ovs_scan(argv[argc - 1], "%"SCNu32, &nfrags_max)) {
            error = ct_dpif_ipf_set_max_nfrags(dpif, nfrags_max);
            if (!error) {
                dpctl_print(dpctl_p,
                            "setting maximum fragments successful");
            } else {
                dpctl_error(dpctl_p, error,
                            "setting maximum fragments failed");
            }
        } else {
            error = EINVAL;
            dpctl_error(dpctl_p, error,
                        "parameter missing for maximum fragments");
        }
        dpif_close(dpif);
    }

    return error;
}

static void
dpctl_dump_ipf(struct dpif *dpif, struct dpctl_params *dpctl_p)
{
    struct ipf_dump_ctx *dump_ctx;
    char *dump;

    int error = ct_dpif_ipf_dump_start(dpif, &dump_ctx);
    if (error) {
        dpctl_error(dpctl_p, error, "starting ipf list dump");
        /* Nothing to clean up, just return. */
        return;
    }

    dpctl_print(dpctl_p, "\n        Fragment Lists:\n\n");
    while (!(error = ct_dpif_ipf_dump_next(dpif, dump_ctx, &dump))) {
        dpctl_print(dpctl_p, "%s\n", dump);
        free(dump);
    }

    if (error && error != EOF) {
        dpctl_error(dpctl_p, error, "dumping ipf lists failed");
    }

    ct_dpif_ipf_dump_done(dpif, dump_ctx);
}

static int
dpctl_ct_ipf_get_status(int argc, const char *argv[],
                        struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    int error = opt_dpif_open(argc, argv, dpctl_p, 2, &dpif);

    if (!error) {
        struct dpif_ipf_status dpif_ipf_status;
        error = ct_dpif_ipf_get_status(dpif, &dpif_ipf_status);

        if (!error) {
            dpctl_print(dpctl_p, "        Fragmentation Module Status\n");
            dpctl_print(dpctl_p, "        ---------------------------\n");
            dpctl_print(dpctl_p, "        v4 enabled: %u\n",
                        dpif_ipf_status.v4.enabled);
            dpctl_print(dpctl_p, "        v6 enabled: %u\n",
                        dpif_ipf_status.v6.enabled);
            dpctl_print(dpctl_p, "        max num frags (v4/v6): %u\n",
                        dpif_ipf_status.nfrag_max);
            dpctl_print(dpctl_p, "        num frag: %u\n",
                        dpif_ipf_status.nfrag);
            dpctl_print(dpctl_p, "        min v4 frag size: %u\n",
                        dpif_ipf_status.v4.min_frag_size);
            dpctl_print(dpctl_p, "        v4 frags accepted: %"PRIu64"\n",
                        dpif_ipf_status.v4.nfrag_accepted);
            dpctl_print(dpctl_p, "        v4 frags completed: %"PRIu64"\n",
                        dpif_ipf_status.v4.nfrag_completed_sent);
            dpctl_print(dpctl_p, "        v4 frags expired: %"PRIu64"\n",
                        dpif_ipf_status.v4.nfrag_expired_sent);
            dpctl_print(dpctl_p, "        v4 frags too small: %"PRIu64"\n",
                        dpif_ipf_status.v4.nfrag_too_small);
            dpctl_print(dpctl_p, "        v4 frags overlapped: %"PRIu64"\n",
                        dpif_ipf_status.v4.nfrag_overlap);
            dpctl_print(dpctl_p, "        v4 frags purged: %"PRIu64"\n",
                        dpif_ipf_status.v4.nfrag_purged);

            dpctl_print(dpctl_p, "        min v6 frag size: %u\n",
                        dpif_ipf_status.v6.min_frag_size);
            dpctl_print(dpctl_p, "        v6 frags accepted: %"PRIu64"\n",
                        dpif_ipf_status.v6.nfrag_accepted);
            dpctl_print(dpctl_p, "        v6 frags completed: %"PRIu64"\n",
                        dpif_ipf_status.v6.nfrag_completed_sent);
            dpctl_print(dpctl_p, "        v6 frags expired: %"PRIu64"\n",
                        dpif_ipf_status.v6.nfrag_expired_sent);
            dpctl_print(dpctl_p, "        v6 frags too small: %"PRIu64"\n",
                        dpif_ipf_status.v6.nfrag_too_small);
            dpctl_print(dpctl_p, "        v6 frags overlapped: %"PRIu64"\n",
                        dpif_ipf_status.v6.nfrag_overlap);
            dpctl_print(dpctl_p, "        v6 frags purged: %"PRIu64"\n",
                        dpif_ipf_status.v6.nfrag_purged);
        } else {
            dpctl_error(dpctl_p, error,
                        "ipf status could not be retrieved");
            return error;
        }

        if (dpctl_p->verbosity) {
            dpctl_dump_ipf(dpif, dpctl_p);
        }

        dpif_close(dpif);
    }

    return error;
}

/* Undocumented commands for unit testing. */

static int
dpctl_parse_actions(int argc, const char *argv[], struct dpctl_params* dpctl_p)
{
    int i, error = 0;

    for (i = 1; i < argc; i++) {
        struct ofpbuf actions;
        struct ds s;

        ofpbuf_init(&actions, 0);
        error = odp_actions_from_string(argv[i], NULL, &actions);

        if (error) {
            ofpbuf_uninit(&actions);
            dpctl_error(dpctl_p, error, "odp_actions_from_string");
            return error;
        }

        ds_init(&s);
        format_odp_actions(&s, actions.data, actions.size, NULL);
        dpctl_print(dpctl_p, "%s\n", ds_cstr(&s));
        ds_destroy(&s);

        ofpbuf_uninit(&actions);
    }

    return error;
}

struct actions_for_flow {
    struct hmap_node hmap_node;
    struct flow flow;
    struct ofpbuf actions;
};

static struct actions_for_flow *
get_actions_for_flow(struct hmap *actions_per_flow, const struct flow *flow)
{
    uint32_t hash = flow_hash(flow, 0);
    struct actions_for_flow *af;

    HMAP_FOR_EACH_WITH_HASH (af, hmap_node, hash, actions_per_flow) {
        if (flow_equal(&af->flow, flow)) {
            return af;
        }
    }

    af = xmalloc(sizeof *af);
    af->flow = *flow;
    ofpbuf_init(&af->actions, 0);
    hmap_insert(actions_per_flow, &af->hmap_node, hash);
    return af;
}

static int
compare_actions_for_flow(const void *a_, const void *b_)
{
    struct actions_for_flow *const *a = a_;
    struct actions_for_flow *const *b = b_;

    return flow_compare_3way(&(*a)->flow, &(*b)->flow);
}

static int
compare_output_actions(const void *a_, const void *b_)
{
    const struct nlattr *a = a_;
    const struct nlattr *b = b_;
    uint32_t a_port = nl_attr_get_u32(a);
    uint32_t b_port = nl_attr_get_u32(b);

    return a_port < b_port ? -1 : a_port > b_port;
}

static void
sort_output_actions__(struct nlattr *first, struct nlattr *end)
{
    size_t bytes = (uint8_t *) end - (uint8_t *) first;
    size_t n = bytes / NL_A_U32_SIZE;

    ovs_assert(bytes % NL_A_U32_SIZE == 0);
    qsort(first, n, NL_A_U32_SIZE, compare_output_actions);
}

static void
sort_output_actions(struct nlattr *actions, size_t length)
{
    struct nlattr *first_output = NULL;
    struct nlattr *a;
    int left;

    NL_ATTR_FOR_EACH (a, left, actions, length) {
        if (nl_attr_type(a) == OVS_ACTION_ATTR_OUTPUT) {
            if (!first_output) {
                first_output = a;
            }
        } else {
            if (first_output) {
                sort_output_actions__(first_output, a);
                first_output = NULL;
            }
        }
    }
    if (first_output) {
        uint8_t *end = (uint8_t *) actions + length;
        sort_output_actions__(first_output,
                              ALIGNED_CAST(struct nlattr *, end));
    }
}

/* usage: "ovs-dpctl normalize-actions FLOW ACTIONS" where FLOW and ACTIONS
 * have the syntax used by "ovs-dpctl dump-flows".
 *
 * This command prints ACTIONS in a format that shows what happens for each
 * VLAN, independent of the order of the ACTIONS.  For example, there is more
 * than one way to output a packet on VLANs 9 and 11, but this command will
 * print the same output for any form.
 *
 * The idea here generalizes beyond VLANs (e.g. to setting other fields) but
 * so far the implementation only covers VLANs. */
static int
dpctl_normalize_actions(int argc, const char *argv[],
                        struct dpctl_params *dpctl_p)
{
    struct simap port_names;
    struct ofpbuf keybuf;
    struct flow flow;
    struct ofpbuf odp_actions;
    struct hmap actions_per_flow;
    struct actions_for_flow **afs;
    struct actions_for_flow *af;
    struct nlattr *a;
    size_t n_afs;
    struct ds s;
    int left;
    int i, error;
    int encaps = 0;

    ds_init(&s);

    simap_init(&port_names);
    for (i = 3; i < argc; i++) {
        char name[16];
        int number;

        if (ovs_scan(argv[i], "%15[^=]=%d", name, &number)) {
            uintptr_t n = number;
            simap_put(&port_names, name, n);
        } else {
            dpctl_error(dpctl_p, 0, "%s: expected NAME=NUMBER", argv[i]);
            error = EINVAL;
            goto out;
        }
    }

    /* Parse flow key. */
    ofpbuf_init(&keybuf, 0);
    char *error_s;
    error = odp_flow_from_string(argv[1], &port_names, &keybuf, NULL,
                                 &error_s);
    if (error) {
        dpctl_error(dpctl_p, error, "odp_flow_key_from_string (%s)", error_s);
        free(error_s);
        goto out_freekeybuf;
    }

    ds_clear(&s);
    odp_flow_format(keybuf.data, keybuf.size, NULL, 0, NULL,
                    &s, dpctl_p->verbosity);
    dpctl_print(dpctl_p, "input flow: %s\n", ds_cstr(&s));

    error = odp_flow_key_to_flow(keybuf.data, keybuf.size, &flow, &error_s);
    if (error) {
        dpctl_error(dpctl_p, error, "odp_flow_key_to_flow failed (%s)",
                    error_s ? error_s : "reason unknown");
        free(error_s);
        goto out_freekeybuf;
    }

    /* Parse actions. */
    ofpbuf_init(&odp_actions, 0);
    error = odp_actions_from_string(argv[2], &port_names, &odp_actions);
    if (error) {
        dpctl_error(dpctl_p, error, "odp_actions_from_string");
        goto out_freeactions;
    }

    if (dpctl_p->verbosity) {
        ds_clear(&s);
        format_odp_actions(&s, odp_actions.data, odp_actions.size, NULL);
        dpctl_print(dpctl_p, "input actions: %s\n", ds_cstr(&s));
    }

    hmap_init(&actions_per_flow);
    NL_ATTR_FOR_EACH (a, left, odp_actions.data, odp_actions.size) {
        const struct ovs_action_push_vlan *push;
        switch(nl_attr_type(a)) {
        case OVS_ACTION_ATTR_POP_VLAN:
            flow_pop_vlan(&flow, NULL);
            continue;

        case OVS_ACTION_ATTR_PUSH_VLAN:
            flow_push_vlan_uninit(&flow, NULL);
            push = nl_attr_get_unspec(a, sizeof *push);
            flow.vlans[0].tpid = push->vlan_tpid;
            flow.vlans[0].tci = push->vlan_tci;
            continue;
        }

        af = get_actions_for_flow(&actions_per_flow, &flow);
        nl_msg_put_unspec(&af->actions, nl_attr_type(a),
                          nl_attr_get(a), nl_attr_get_size(a));
    }

    n_afs = hmap_count(&actions_per_flow);
    afs = xmalloc(n_afs * sizeof *afs);
    i = 0;
    HMAP_FOR_EACH (af, hmap_node, &actions_per_flow) {
        afs[i++] = af;
    }

    ovs_assert(i == n_afs);
    hmap_destroy(&actions_per_flow);

    qsort(afs, n_afs, sizeof *afs, compare_actions_for_flow);

    for (i = 0; i < n_afs; i++) {
        af = afs[i];
        sort_output_actions(af->actions.data, af->actions.size);

        for (encaps = 0; encaps < FLOW_MAX_VLAN_HEADERS; encaps ++) {
            union flow_vlan_hdr *vlan = &af->flow.vlans[encaps];
            if (vlan->tci != htons(0)) {
                dpctl_print(dpctl_p, "vlan(");
                if (vlan->tpid != htons(ETH_TYPE_VLAN)) {
                    dpctl_print(dpctl_p, "tpid=0x%04"PRIx16",", vlan->tpid);
                }
                dpctl_print(dpctl_p, "vid=%"PRIu16",pcp=%d): ",
                            vlan_tci_to_vid(vlan->tci),
                            vlan_tci_to_pcp(vlan->tci));
            } else {
                if (encaps == 0) {
                    dpctl_print(dpctl_p, "no vlan: ");
                }
                break;
            }
        }

        if (eth_type_mpls(af->flow.dl_type)) {
            dpctl_print(dpctl_p, "mpls(label=%"PRIu32",tc=%d,ttl=%d): ",
                        mpls_lse_to_label(af->flow.mpls_lse[0]),
                        mpls_lse_to_tc(af->flow.mpls_lse[0]),
                        mpls_lse_to_ttl(af->flow.mpls_lse[0]));
        } else {
            dpctl_print(dpctl_p, "no mpls: ");
        }

        ds_clear(&s);
        format_odp_actions(&s, af->actions.data, af->actions.size, NULL);
        dpctl_puts(dpctl_p, false, ds_cstr(&s));

        ofpbuf_uninit(&af->actions);
        free(af);
    }
    free(afs);


out_freeactions:
    ofpbuf_uninit(&odp_actions);
out_freekeybuf:
    ofpbuf_uninit(&keybuf);
out:
    simap_destroy(&port_names);
    ds_destroy(&s);

    return error;
}

static const struct dpctl_command all_commands[] = {
    { "add-dp", "dp [iface...]", 1, INT_MAX, dpctl_add_dp, DP_RW },
    { "del-dp", "dp", 1, 1, dpctl_del_dp, DP_RW },
    { "add-if", "dp iface...", 2, INT_MAX, dpctl_add_if, DP_RW },
    { "del-if", "dp iface...", 2, INT_MAX, dpctl_del_if, DP_RW },
    { "set-if", "dp iface...", 2, INT_MAX, dpctl_set_if, DP_RW },
    { "dump-dps", "", 0, 0, dpctl_dump_dps, DP_RO },
    { "show", "[-s] [dp...]", 0, INT_MAX, dpctl_show, DP_RO },
    { "dump-flows", "[-m] [--names] [dp] [filter=..] [type=..] [pmd=..]",
      0, 6, dpctl_dump_flows, DP_RO },
    { "add-flow", "[dp] flow actions", 2, 3, dpctl_add_flow, DP_RW },
    { "mod-flow", "[dp] flow actions", 2, 3, dpctl_mod_flow, DP_RW },
    { "get-flow", "[dp] ufid", 1, 2, dpctl_get_flow, DP_RO },
    { "del-flow", "[dp] flow", 1, 2, dpctl_del_flow, DP_RW },
    { "add-flows", "[dp] file", 1, 2, dpctl_process_flows, DP_RW },
    { "mod-flows", "[dp] file", 1, 2, dpctl_process_flows, DP_RW },
    { "del-flows", "[dp] [file]", 0, 2, dpctl_del_flows, DP_RW },
    { "dump-conntrack", "[-m] [-s] [dp] [zone=N]",
      0, 4, dpctl_dump_conntrack, DP_RO },
    { "flush-conntrack", "[dp] [zone=N] [ct-tuple]", 0, 3,
      dpctl_flush_conntrack, DP_RW },
    { "ct-stats-show", "[dp] [zone=N]",
      0, 3, dpctl_ct_stats_show, DP_RO },
    { "ct-bkts", "[dp] [gt=N]", 0, 2, dpctl_ct_bkts, DP_RO },
    { "ct-set-maxconns", "[dp] maxconns", 1, 2, dpctl_ct_set_maxconns,
       DP_RW },
    { "ct-get-maxconns", "[dp]", 0, 1, dpctl_ct_get_maxconns, DP_RO },
    { "ct-get-nconns", "[dp]", 0, 1, dpctl_ct_get_nconns, DP_RO },
    { "ct-enable-tcp-seq-chk", "[dp]", 0, 1, dpctl_ct_enable_tcp_seq_chk,
       DP_RW },
    { "ct-disable-tcp-seq-chk", "[dp]", 0, 1, dpctl_ct_disable_tcp_seq_chk,
       DP_RW },
    { "ct-get-tcp-seq-chk", "[dp]", 0, 1, dpctl_ct_get_tcp_seq_chk, DP_RO },
    { "ct-set-limits", "[dp] [default=L] [zone=N,limit=L]...", 1, INT_MAX,
        dpctl_ct_set_limits, DP_RO },
    { "ct-del-limits", "[dp] zone=N1[,N2]...", 1, 2, dpctl_ct_del_limits,
        DP_RO },
    { "ct-get-limits", "[dp] [zone=N1[,N2]...]", 0, 2, dpctl_ct_get_limits,
        DP_RO },
    { "ipf-set-enabled", "[dp] v4|v6", 1, 2, dpctl_ipf_set_enabled, DP_RW },
    { "ipf-set-disabled", "[dp] v4|v6", 1, 2, dpctl_ipf_set_disabled, DP_RW },
    { "ipf-set-min-frag", "[dp] v4|v6 minfragment", 2, 3,
       dpctl_ipf_set_min_frag, DP_RW },
    { "ipf-set-max-nfrags", "[dp] maxfrags", 1, 2,
       dpctl_ipf_set_max_nfrags, DP_RW },
    { "ipf-get-status", "[dp]", 0, 1, dpctl_ct_ipf_get_status,
       DP_RO },
    { "help", "", 0, INT_MAX, dpctl_help, DP_RO },
    { "list-commands", "", 0, INT_MAX, dpctl_list_commands, DP_RO },

    /* Undocumented commands for testing. */
    { "parse-actions", "actions", 1, INT_MAX, dpctl_parse_actions, DP_RO },
    { "normalize-actions", "actions",
      2, INT_MAX, dpctl_normalize_actions, DP_RO },

    { NULL, NULL, 0, 0, NULL, DP_RO },
};

static const struct dpctl_command *get_all_dpctl_commands(void)
{
    return all_commands;
}

/* Runs the command designated by argv[0] within the command table specified by
 * 'commands', which must be terminated by a command whose 'name' member is a
 * null pointer. */
int
dpctl_run_command(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    const struct dpctl_command *p;
    if (argc < 1) {
        dpctl_error(dpctl_p, 0, "missing command name; use --help for help");
        return EINVAL;
    }

    for (p = all_commands; p->name != NULL; p++) {
        if (!strcmp(p->name, argv[0])) {
            int n_arg = argc - 1;
            if (n_arg < p->min_args) {
                dpctl_error(dpctl_p, 0,
                            "'%s' command requires at least %d arguments",
                            p->name, p->min_args);
                return EINVAL;
            } else if (n_arg > p->max_args) {
                dpctl_error(dpctl_p, 0,
                            "'%s' command takes at most %d arguments",
                            p->name, p->max_args);
                return EINVAL;
            } else {
                if (p->mode == DP_RW && dpctl_p->read_only) {
                    dpctl_error(dpctl_p, 0,
                                "'%s' command does not work in read only mode",
                                p->name);
                    return EINVAL;
                }
                return p->handler(argc, argv, dpctl_p);
            }
        }
    }

    dpctl_error(dpctl_p, 0, "unknown command '%s'; use --help for help",
                argv[0]);
    return EINVAL;
}

static void
dpctl_unixctl_print(void *userdata, bool error OVS_UNUSED, const char *msg)
{
    struct ds *ds = userdata;
    ds_put_cstr(ds, msg);
}

static void
dpctl_unixctl_handler(struct unixctl_conn *conn, int argc, const char *argv[],
                      void *aux)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    bool error = false;

    struct dpctl_params dpctl_p = {
        .is_appctl = true,
        .output = dpctl_unixctl_print,
        .aux = &ds,
    };

    /* Parse options (like getopt). Unfortunately it does
     * not seem a good idea to call getopt_long() here, since it uses global
     * variables */
    bool set_names = false;
    while (argc > 1 && !error) {
        const char *arg = argv[1];
        if (!strncmp(arg, "--", 2)) {
            /* Long option */
            if (!strcmp(arg, "--statistics")) {
                dpctl_p.print_statistics = true;
            } else if (!strcmp(arg, "--clear")) {
                dpctl_p.zero_statistics = true;
            } else if (!strcmp(arg, "--may-create")) {
                dpctl_p.may_create = true;
            } else if (!strcmp(arg, "--more")) {
                dpctl_p.verbosity++;
            } else if (!strcmp(arg, "--names")) {
                dpctl_p.names = true;
                set_names = true;
            } else if (!strcmp(arg, "--no-names")) {
                dpctl_p.names = false;
                set_names = true;
            } else {
                ds_put_format(&ds, "Unrecognized option %s", argv[1]);
                error = true;
            }
        } else if (arg[0] == '-' && arg[1] != '\0') {
            /* Short option[s] */
            const char *opt = &arg[1];

            while (*opt && !error) {
                switch (*opt) {
                case 'm':
                    dpctl_p.verbosity++;
                    break;
                case 's':
                    dpctl_p.print_statistics = true;
                    break;
                default:
                    ds_put_format(&ds, "Unrecognized option -%c", *opt);
                    error = true;
                    break;
                }
                opt++;
            }
        } else {
            /* Doesn't start with -, not an option */
            break;
        }

        if (error) {
            break;
        }
        argv++;
        argc--;
    }
    if (!set_names) {
        dpctl_p.names = dpctl_p.verbosity > 0;
    }

    if (!error) {
        dpctl_command_handler *handler = (dpctl_command_handler *) aux;
        error = handler(argc, argv, &dpctl_p) != 0;
    }

    if (error) {
        unixctl_command_reply_error(conn, ds_cstr(&ds));
    } else {
        unixctl_command_reply(conn, ds_cstr(&ds));
    }

    ds_destroy(&ds);
}

void
dpctl_unixctl_register(void)
{
    const struct dpctl_command *p;

    for (p = all_commands; p->name != NULL; p++) {
        if (strcmp(p->name, "help")) {
            char *cmd_name = xasprintf("dpctl/%s", p->name);
            unixctl_command_register(cmd_name,
                                     p->usage,
                                     p->min_args,
                                     p->max_args,
                                     dpctl_unixctl_handler,
                                     p->handler);
            free(cmd_name);
        }
    }
}
