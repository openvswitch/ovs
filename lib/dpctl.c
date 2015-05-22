/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "dpctl.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "flow.h"
#include "match.h"
#include "netdev.h"
#include "netdev-dpdk.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofp-parse.h"
#include "ofpbuf.h"
#include "ovs-numa.h"
#include "packets.h"
#include "shash.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

typedef int dpctl_command_handler(int argc, const char *argv[],
                                  struct dpctl_params *);
struct dpctl_command {
    const char *name;
    const char *usage;
    int min_args;
    int max_args;
    dpctl_command_handler *handler;
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
 * is responsible for freeing the returned string.  If there is not one
 * datapath, aborts with an error message. */
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
        int error = 0;

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

        error = dpif_port_del(dpif, port);
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

static void
show_dpif(struct dpif *dpif, struct dpctl_params *dpctl_p)
{
    struct dpif_port_dump dump;
    struct dpif_port dpif_port;
    struct dpif_dp_stats stats;
    struct netdev *netdev;

    dpctl_print(dpctl_p, "%s:\n", dpif_name(dpif));
    if (!dpif_get_dp_stats(dpif, &stats)) {
        dpctl_print(dpctl_p, "\tlookups: hit:%"PRIu64" missed:%"PRIu64
                             " lost:%"PRIu64"\n\tflows: %"PRIu64"\n",
                    stats.n_hit, stats.n_missed, stats.n_lost, stats.n_flows);
        if (stats.n_masks != UINT32_MAX) {
            uint64_t n_pkts = stats.n_hit + stats.n_missed;
            double avg = n_pkts ? (double) stats.n_mask_hit / n_pkts : 0.0;

            dpctl_print(dpctl_p, "\tmasks: hit:%"PRIu64" total:%"PRIu32
                                 " hit/pkt:%.2f\n",
                        stats.n_mask_hit, stats.n_masks, avg);
        }
    }

    DPIF_PORT_FOR_EACH (&dpif_port, &dump, dpif) {
        dpctl_print(dpctl_p, "\tport %u: %s",
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
                    const struct smap_node **nodes;
                    size_t i;

                    nodes = smap_sort(&config);
                    for (i = 0; i < smap_count(&config); i++) {
                        const struct smap_node *node = nodes[i];
                        dpctl_print(dpctl_p, "%c %s=%s", i ? ',' : ':',
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
                continue;
            }
            error = netdev_get_stats(netdev, &s);
            if (!error) {
                netdev_close(netdev);
                print_stat(dpctl_p, "\t\tRX packets:", s.rx_packets);
                print_stat(dpctl_p, " errors:", s.rx_errors);
                print_stat(dpctl_p, " dropped:", s.rx_dropped);
                print_stat(dpctl_p, " overruns:", s.rx_over_errors);
                print_stat(dpctl_p, " frame:", s.rx_frame_errors);
                dpctl_print(dpctl_p, "\n");

                print_stat(dpctl_p, "\t\tTX packets:", s.tx_packets);
                print_stat(dpctl_p, " errors:", s.tx_errors);
                print_stat(dpctl_p, " dropped:", s.tx_dropped);
                print_stat(dpctl_p, " aborted:", s.tx_aborted_errors);
                print_stat(dpctl_p, " carrier:", s.tx_carrier_errors);
                dpctl_print(dpctl_p, "\n");

                print_stat(dpctl_p, "\t\tcollisions:", s.collisions);
                dpctl_print(dpctl_p, "\n");

                print_stat(dpctl_p, "\t\tRX bytes:", s.rx_bytes);
                print_human_size(dpctl_p, s.rx_bytes);
                print_stat(dpctl_p, "  TX bytes:", s.tx_bytes);
                print_human_size(dpctl_p, s.tx_bytes);
                dpctl_print(dpctl_p, "\n");
            } else {
                dpctl_print(dpctl_p, ", could not retrieve stats (%s)",
                            ovs_strerror(error));
            }
        }
    }
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
    ds_put_cstr(ds, ", actions:");
    format_odp_actions(ds, f->actions, f->actions_len);
}

static int
dpctl_dump_flows(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    struct ds ds;
    char *name;

    char *filter = NULL;
    struct flow flow_filter;
    struct flow_wildcards wc_filter;

    struct dpif_port_dump port_dump;
    struct dpif_port dpif_port;
    struct hmap portno_names;
    struct simap names_portno;

    struct dpif_flow_dump_thread *flow_dump_thread;
    struct dpif_flow_dump *flow_dump;
    struct dpif_flow f;
    int pmd_id = PMD_ID_NULL;
    int error;

    if (argc > 1 && !strncmp(argv[argc - 1], "filter=", 7)) {
        filter = xstrdup(argv[--argc] + 7);
    }
    name = (argc == 2) ? xstrdup(argv[1]) : get_one_dp(dpctl_p);
    if (!name) {
        error = EINVAL;
        goto out_freefilter;
    }

    error = parsed_dpif_open(name, false, &dpif);
    free(name);
    if (error) {
        dpctl_error(dpctl_p, error, "opening datapath");
        goto out_freefilter;
    }


    hmap_init(&portno_names);
    simap_init(&names_portno);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        odp_portno_names_set(&portno_names, dpif_port.port_no, dpif_port.name);
        simap_put(&names_portno, dpif_port.name,
                  odp_to_u32(dpif_port.port_no));
    }

    if (filter) {
        char *err = parse_ofp_exact_flow(&flow_filter, &wc_filter.masks,
                                         filter, &names_portno);
        if (err) {
            dpctl_error(dpctl_p, 0, "Failed to parse filter (%s)", err);
            error = EINVAL;
            goto out_dpifclose;
        }
    }

    /* Make sure that these values are different. PMD_ID_NULL means that the
     * pmd is unspecified (e.g. because the datapath doesn't have different
     * pmd threads), while NON_PMD_CORE_ID refers to every non pmd threads
     * in the userspace datapath */
    BUILD_ASSERT(PMD_ID_NULL != NON_PMD_CORE_ID);

    ds_init(&ds);
    flow_dump = dpif_flow_dump_create(dpif, false);
    flow_dump_thread = dpif_flow_dump_thread_create(flow_dump);
    while (dpif_flow_dump_next(flow_dump_thread, &f, 1)) {
        if (filter) {
            struct flow flow;
            struct flow_wildcards wc;
            struct match match, match_filter;
            struct minimatch minimatch;

            odp_flow_key_to_flow(f.key, f.key_len, &flow);
            odp_flow_key_to_mask(f.mask, f.mask_len, &wc.masks, &flow);
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
        if (pmd_id != f.pmd_id) {
            if (f.pmd_id == NON_PMD_CORE_ID) {
                ds_put_format(&ds, "flow-dump from non-dpdk interfaces:\n");
            } else {
                ds_put_format(&ds, "flow-dump from pmd on cpu core: %d\n",
                              f.pmd_id);
            }
            pmd_id = f.pmd_id;
        }
        format_dpif_flow(&ds, &f, &portno_names, dpctl_p);
        dpctl_print(dpctl_p, "%s\n", ds_cstr(&ds));
    }
    dpif_flow_dump_thread_destroy(flow_dump_thread);
    error = dpif_flow_dump_destroy(flow_dump);

    if (error) {
        dpctl_error(dpctl_p, error, "Failed to dump flows from datapath");
    }
    ds_destroy(&ds);

out_dpifclose:
    odp_portno_names_destroy(&portno_names);
    simap_destroy(&names_portno);
    hmap_destroy(&portno_names);
    dpif_close(dpif);
out_freefilter:
    free(filter);
    return error;
}

/* Extracts the in_port from the parsed keys, and returns the reference
 * to the 'struct netdev *' of the dpif port.  On error, returns NULL.
 * Users must call 'netdev_close()' after finish using the returned
 * reference. */
static struct netdev *
get_in_port_netdev_from_key(struct dpif *dpif, const struct ofpbuf *key)
{
    const struct nlattr *in_port_nla;
    struct netdev *dev = NULL;

    in_port_nla = nl_attr_find(key, 0, OVS_KEY_ATTR_IN_PORT);
    if (in_port_nla) {
        struct dpif_port dpif_port;
        odp_port_t port_no;
        int error;

        port_no = ODP_PORT_C(nl_attr_get_u32(in_port_nla));
        error = dpif_port_query_by_number(dpif, port_no, &dpif_port);
        if (error) {
            goto out;
        }

        netdev_open(dpif_port.name, dpif_port.type, &dev);
        dpif_port_destroy(&dpif_port);
    }

out:
    return dev;
}

static int
dpctl_put_flow(int argc, const char *argv[], enum dpif_flow_put_flags flags,
               struct dpctl_params *dpctl_p)
{
    const char *key_s = argv[argc - 2];
    const char *actions_s = argv[argc - 1];
    struct netdev *in_port_netdev = NULL;
    struct dpif_flow_stats stats;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct ofpbuf actions;
    struct ofpbuf key;
    struct ofpbuf mask;
    struct dpif *dpif;
    ovs_u128 ufid;
    bool ufid_present;
    char *dp_name;
    struct simap port_names;
    int n, error;

    dp_name = argc == 4 ? xstrdup(argv[1]) : get_one_dp(dpctl_p);
    if (!dp_name) {
        return EINVAL;
    }
    error = parsed_dpif_open(dp_name, false, &dpif);
    free(dp_name);
    if (error) {
        dpctl_error(dpctl_p, error, "opening datapath");
        return error;
    }

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
    error = odp_flow_from_string(key_s, &port_names, &key, &mask);
    simap_destroy(&port_names);
    if (error) {
        dpctl_error(dpctl_p, error, "parsing flow key");
        goto out_freekeymask;
    }

    ofpbuf_init(&actions, 0);
    error = odp_actions_from_string(actions_s, NULL, &actions);
    if (error) {
        dpctl_error(dpctl_p, error, "parsing actions");
        goto out_freeactions;
    }

    /* For DPDK interface, applies the operation to all pmd threads
     * on the same numa node. */
    in_port_netdev = get_in_port_netdev_from_key(dpif, &key);
    if (in_port_netdev && netdev_is_pmd(in_port_netdev)) {
        int numa_id;

        numa_id = netdev_get_numa_id(in_port_netdev);
        if (ovs_numa_numa_id_is_valid(numa_id)) {
            struct ovs_numa_dump *dump = ovs_numa_dump_cores_on_numa(numa_id);
            struct ovs_numa_info *iter;

            FOR_EACH_CORE_ON_NUMA (iter, dump) {
                if (ovs_numa_core_is_pinned(iter->core_id)) {
                    error = dpif_flow_put(dpif, flags,
                                          key.data, key.size,
                                          mask.size == 0 ? NULL : mask.data,
                                          mask.size, actions.data,
                                          actions.size, ufid_present ? &ufid : NULL,
                                          iter->core_id, dpctl_p->print_statistics ? &stats : NULL);
                }
            }
            ovs_numa_dump_destroy(dump);
        } else {
            error = EINVAL;
        }
    } else {
        error = dpif_flow_put(dpif, flags,
                              key.data, key.size,
                              mask.size == 0 ? NULL : mask.data,
                              mask.size, actions.data,
                              actions.size, ufid_present ? &ufid : NULL,
                              PMD_ID_NULL, dpctl_p->print_statistics ? &stats : NULL);
    }
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
    dpif_close(dpif);
    netdev_close(in_port_netdev);
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
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct dpif *dpif;
    char *dp_name;
    struct hmap portno_names;
    ovs_u128 ufid;
    struct ofpbuf buf;
    uint64_t stub[DPIF_FLOW_BUFSIZE / 8];
    struct ds ds;
    int n, error;

    dp_name = argc == 3 ? xstrdup(argv[1]) : get_one_dp(dpctl_p);
    if (!dp_name) {
        return EINVAL;
    }
    error = parsed_dpif_open(dp_name, false, &dpif);
    free(dp_name);
    if (error) {
        dpctl_error(dpctl_p, error, "opening datapath");
        return error;
    }

    ofpbuf_use_stub(&buf, &stub, sizeof stub);
    hmap_init(&portno_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        odp_portno_names_set(&portno_names, dpif_port.port_no, dpif_port.name);
    }

    n = odp_ufid_from_string(key_s, &ufid);
    if (n <= 0) {
        dpctl_error(dpctl_p, -n, "parsing flow ufid");
        goto out;
    }

    /* Does not work for DPDK, since do not know which 'pmd' to apply the
     * operation.  So, just uses PMD_ID_NULL. */
    error = dpif_flow_get(dpif, NULL, 0, &ufid, PMD_ID_NULL, &buf, &flow);
    if (error) {
        dpctl_error(dpctl_p, error, "getting flow");
        goto out;
    }

    ds_init(&ds);
    format_dpif_flow(&ds, &flow, &portno_names, dpctl_p);
    dpctl_print(dpctl_p, "%s\n", ds_cstr(&ds));
    ds_destroy(&ds);

out:
    odp_portno_names_destroy(&portno_names);
    hmap_destroy(&portno_names);
    ofpbuf_uninit(&buf);
    dpif_close(dpif);
    return error;
}

static int
dpctl_del_flow(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    const char *key_s = argv[argc - 1];
    struct netdev *in_port_netdev = NULL;
    struct dpif_flow_stats stats;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct ofpbuf key;
    struct ofpbuf mask; /* To be ignored. */
    struct dpif *dpif;
    ovs_u128 ufid;
    bool ufid_present;
    char *dp_name;
    struct simap port_names;
    int n, error;

    dp_name = argc == 3 ? xstrdup(argv[1]) : get_one_dp(dpctl_p);
    if (!dp_name) {
        return EINVAL;
    }
    error = parsed_dpif_open(dp_name, false, &dpif);
    free(dp_name);
    if (error) {
        dpctl_error(dpctl_p, error, "opening datapath");
        return error;
    }

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

    error = odp_flow_from_string(key_s, &port_names, &key, &mask);
    if (error) {
        dpctl_error(dpctl_p, error, "parsing flow key");
        goto out;
    }

    /* For DPDK interface, applies the operation to all pmd threads
     * on the same numa node. */
    in_port_netdev = get_in_port_netdev_from_key(dpif, &key);
    if (in_port_netdev && netdev_is_pmd(in_port_netdev)) {
        int numa_id;

        numa_id = netdev_get_numa_id(in_port_netdev);
        if (ovs_numa_numa_id_is_valid(numa_id)) {
            struct ovs_numa_dump *dump = ovs_numa_dump_cores_on_numa(numa_id);
            struct ovs_numa_info *iter;

            FOR_EACH_CORE_ON_NUMA (iter, dump) {
                if (ovs_numa_core_is_pinned(iter->core_id)) {
                    error = dpif_flow_del(dpif, key.data,
                                          key.size, ufid_present ? &ufid : NULL,
                                          iter->core_id, dpctl_p->print_statistics ? &stats : NULL);
                }
            }
            ovs_numa_dump_destroy(dump);
        } else {
            error = EINVAL;
        }
    } else {
        error = dpif_flow_del(dpif, key.data, key.size,
                              ufid_present ? &ufid : NULL, PMD_ID_NULL,
                              dpctl_p->print_statistics ? &stats : NULL);
    }
    if (error) {
        dpctl_error(dpctl_p, error, "deleting flow");
        if (error == ENOENT && !ufid_present) {
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
    dpif_close(dpif);
    netdev_close(in_port_netdev);
    return error;
}

static int
dpctl_del_flows(int argc, const char *argv[], struct dpctl_params *dpctl_p)
{
    struct dpif *dpif;
    char *name;
    int error;

    name = (argc == 2) ? xstrdup(argv[1]) : get_one_dp(dpctl_p);
    if (!name) {
        return EINVAL;
    }
    error = parsed_dpif_open(name, false, &dpif);
    free(name);
    if (error) {
        dpctl_error(dpctl_p, error, "opening datapath");
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

        ds_put_format(&ds, "  %s%-23s %s\n", dpctl_p->is_appctl ? "dpctl/" : "",
                      c->name, c->usage);
    }
    dpctl_puts(dpctl_p, false, ds.string);
    ds_destroy(&ds);

    return 0;
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
        format_odp_actions(&s, actions.data, actions.size);
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
    error = odp_flow_from_string(argv[1], &port_names, &keybuf, NULL);
    if (error) {
        dpctl_error(dpctl_p, error, "odp_flow_key_from_string");
        goto out_freekeybuf;
    }

    ds_clear(&s);
    odp_flow_format(keybuf.data, keybuf.size, NULL, 0, NULL,
                    &s, dpctl_p->verbosity);
    dpctl_print(dpctl_p, "input flow: %s\n", ds_cstr(&s));

    error = odp_flow_key_to_flow(keybuf.data, keybuf.size, &flow);
    if (error) {
        dpctl_error(dpctl_p, error, "odp_flow_key_to_flow");
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
        format_odp_actions(&s, odp_actions.data, odp_actions.size);
        dpctl_print(dpctl_p, "input actions: %s\n", ds_cstr(&s));
    }

    hmap_init(&actions_per_flow);
    NL_ATTR_FOR_EACH (a, left, odp_actions.data, odp_actions.size) {
        const struct ovs_action_push_vlan *push;
        switch(nl_attr_type(a)) {
        case OVS_ACTION_ATTR_POP_VLAN:
            flow.vlan_tci = htons(0);
            continue;

        case OVS_ACTION_ATTR_PUSH_VLAN:
            push = nl_attr_get_unspec(a, sizeof *push);
            flow.vlan_tci = push->vlan_tci;
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
        struct actions_for_flow *af = afs[i];

        sort_output_actions(af->actions.data, af->actions.size);

        if (af->flow.vlan_tci != htons(0)) {
            dpctl_print(dpctl_p, "vlan(vid=%"PRIu16",pcp=%d): ",
                        vlan_tci_to_vid(af->flow.vlan_tci),
                        vlan_tci_to_pcp(af->flow.vlan_tci));
        } else {
            dpctl_print(dpctl_p, "no vlan: ");
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
        format_odp_actions(&s, af->actions.data, af->actions.size);
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
    { "add-dp", "add-dp dp [iface...]", 1, INT_MAX, dpctl_add_dp },
    { "del-dp", "del-dp dp", 1, 1, dpctl_del_dp },
    { "add-if", "add-if dp iface...", 2, INT_MAX, dpctl_add_if },
    { "del-if", "del-if dp iface...", 2, INT_MAX, dpctl_del_if },
    { "set-if", "set-if dp iface...", 2, INT_MAX, dpctl_set_if },
    { "dump-dps", "", 0, 0, dpctl_dump_dps },
    { "show", "[dp...]", 0, INT_MAX, dpctl_show },
    { "dump-flows", "[dp]", 0, 2, dpctl_dump_flows },
    { "add-flow", "add-flow [dp] flow actions", 2, 3, dpctl_add_flow },
    { "mod-flow", "mod-flow [dp] flow actions", 2, 3, dpctl_mod_flow },
    { "get-flow", "get-flow [dp] ufid", 1, 2, dpctl_get_flow },
    { "del-flow", "del-flow [dp] flow", 1, 2, dpctl_del_flow },
    { "del-flows", "[dp]", 0, 1, dpctl_del_flows },
    { "help", "", 0, INT_MAX, dpctl_help },
    { "list-commands", "", 0, INT_MAX, dpctl_list_commands },

    /* Undocumented commands for testing. */
    { "parse-actions", "actions", 1, INT_MAX, dpctl_parse_actions },
    { "normalize-actions", "actions", 2, INT_MAX, dpctl_normalize_actions },

    { NULL, NULL, 0, 0, NULL },
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
    struct dpctl_params dpctl_p;
    bool error = false;

    dpctl_command_handler *handler = (dpctl_command_handler *) aux;

    dpctl_p.print_statistics = false;
    dpctl_p.zero_statistics = false;
    dpctl_p.may_create = false;
    dpctl_p.verbosity = 0;

    /* Parse options (like getopt). Unfortunately it does
     * not seem a good idea to call getopt_long() here, since it uses global
     * variables */
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

    if (!error) {
        dpctl_p.is_appctl = true;
        dpctl_p.output = dpctl_unixctl_print;
        dpctl_p.aux = &ds;

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
        char *cmd_name = xasprintf("dpctl/%s", p->name);
        unixctl_command_register(cmd_name, "", p->min_args, p->max_args,
                                 dpctl_unixctl_handler, p->handler);
        free(cmd_name);
    }
}
