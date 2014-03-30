/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include <getopt.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "flow.h"
#include "match.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofp-parse.h"
#include "ofpbuf.h"
#include "packets.h"
#include "shash.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

/* -s, --statistics: Print port/flow statistics? */
static bool print_statistics;

/* --clear: Reset existing statistics to zero when modifying a flow? */
static bool zero_statistics;

/* --may-create: Allow mod-flows command to create a new flow? */
static bool may_create;

/* -m, --more: Increase output verbosity. */
static int verbosity;

static const struct command *get_all_commands(void);

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();
    run_command(argc - optind, argv + optind, get_all_commands());
    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_CLEAR = UCHAR_MAX + 1,
        OPT_MAY_CREATE,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"statistics", no_argument, NULL, 's'},
        {"clear", no_argument, NULL, OPT_CLEAR},
        {"may-create", no_argument, NULL, OPT_MAY_CREATE},
        {"more", no_argument, NULL, 'm'},
        {"timeout", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 's':
            print_statistics = true;
            break;

        case OPT_CLEAR:
            zero_statistics = true;
            break;

        case OPT_MAY_CREATE:
            may_create = true;
            break;

        case 'm':
            verbosity++;
            break;

        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ovs_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: Open vSwitch datapath management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "  add-dp DP [IFACE...]     add new datapath DP (with IFACEs)\n"
           "  del-dp DP                delete local datapath DP\n"
           "  add-if DP IFACE...       add each IFACE as a port on DP\n"
           "  set-if DP IFACE...       reconfigure each IFACE within DP\n"
           "  del-if DP IFACE...       delete each IFACE from DP\n"
           "  dump-dps                 display names of all datapaths\n"
           "  show                     show basic info on all datapaths\n"
           "  show DP...               show basic info on each DP\n"
           "  dump-flows [DP]          display flows in DP\n"
           "  add-flow [DP] FLOW ACTIONS add FLOW with ACTIONS to DP\n"
           "  mod-flow [DP] FLOW ACTIONS change FLOW actions to ACTIONS in DP\n"
           "  del-flow [DP] FLOW         delete FLOW from DP\n"
           "  del-flows [DP]             delete all flows from DP\n"
           "Each IFACE on add-dp, add-if, and set-if may be followed by\n"
           "comma-separated options.  See ovs-dpctl(8) for syntax, or the\n"
           "Interface table in ovs-vswitchd.conf.db(5) for an options list.\n"
           "For COMMAND dump-flows, add-flow, mod-flow, del-flow and\n"
           "del-flows, DP is optional if there is only one datapath.\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOptions for show and mod-flow:\n"
           "  -s,  --statistics           print statistics for port or flow\n"
           "\nOptions for dump-flows:\n"
           "  -m, --more                  increase verbosity of output\n"
           "\nOptions for mod-flow:\n"
           "  --may-create                create flow if it doesn't exist\n"
           "  --clear                     reset existing stats to zero\n"
           "\nOther options:\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static void run(int retval, const char *message, ...)
    PRINTF_FORMAT(2, 3);

static void run(int retval, const char *message, ...)
{
    if (retval) {
        va_list args;

        va_start(args, message);
        ovs_fatal_valist(retval, message, args);
    }
}

static void dpctl_add_if(int argc, char *argv[]);

static int if_up(const char *netdev_name)
{
    struct netdev *netdev;
    int retval;

    retval = netdev_open(netdev_name, "system", &netdev);
    if (!retval) {
        retval = netdev_turn_flags_on(netdev, NETDEV_UP, NULL);
        netdev_close(netdev);
    }
    return retval;
}

/* Retrieve the name of the datapath if exactly one exists.  The caller
 * is responsible for freeing the returned string.  If there is not one
 * datapath, aborts with an error message. */
static char *
get_one_dp(void)
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
        ovs_fatal(0, "no datapaths exist");
    } else if (count > 1) {
        ovs_fatal(0, "multiple datapaths, specify one");
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

static void
dpctl_add_dp(int argc OVS_UNUSED, char *argv[])
{
    struct dpif *dpif;
    run(parsed_dpif_open(argv[1], true, &dpif), "add_dp");
    dpif_close(dpif);
    if (argc > 2) {
        dpctl_add_if(argc, argv);
    }
}

static void
dpctl_del_dp(int argc OVS_UNUSED, char *argv[])
{
    struct dpif *dpif;
    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");
    run(dpif_delete(dpif), "del_dp");
    dpif_close(dpif);
}

static void
dpctl_add_if(int argc OVS_UNUSED, char *argv[])
{
    bool failure = false;
    struct dpif *dpif;
    int i;

    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");
    for (i = 2; i < argc; i++) {
        const char *name, *type;
        char *save_ptr = NULL;
        struct netdev *netdev = NULL;
        struct smap args;
        odp_port_t port_no = ODPP_NONE;
        char *option;
        int error;

        name = strtok_r(argv[i], ",", &save_ptr);
        type = "system";

        if (!name) {
            ovs_error(0, "%s is not a valid network device name", argv[i]);
            failure = true;
            continue;
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
                ovs_error(0, "duplicate \"%s\" option", key);
            }
        }

        error = netdev_open(name, type, &netdev);
        if (error) {
            ovs_error(error, "%s: failed to open network device", name);
            goto next;
        }

        error = netdev_set_config(netdev, &args);
        if (error) {
            goto next;
        }

        error = dpif_port_add(dpif, netdev, &port_no);
        if (error) {
            ovs_error(error, "adding %s to %s failed", name, argv[1]);
            goto next;
        }

        error = if_up(name);

next:
        netdev_close(netdev);
        if (error) {
            failure = true;
        }
    }
    dpif_close(dpif);
    if (failure) {
        exit(EXIT_FAILURE);
    }
}

static void
dpctl_set_if(int argc, char *argv[])
{
    bool failure = false;
    struct dpif *dpif;
    int i;

    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");
    for (i = 2; i < argc; i++) {
        struct netdev *netdev = NULL;
        struct dpif_port dpif_port;
        char *save_ptr = NULL;
        char *type = NULL;
        const char *name;
        struct smap args;
        odp_port_t port_no;
        char *option;
        int error;

        name = strtok_r(argv[i], ",", &save_ptr);
        if (!name) {
            ovs_error(0, "%s is not a valid network device name", argv[i]);
            failure = true;
            continue;
        }

        /* Get the port's type from the datapath. */
        error = dpif_port_query_by_name(dpif, name, &dpif_port);
        if (error) {
            ovs_error(error, "%s: failed to query port in %s", name, argv[1]);
            goto next;
        }
        type = xstrdup(dpif_port.type);
        port_no = dpif_port.port_no;
        dpif_port_destroy(&dpif_port);

        /* Retrieve its existing configuration. */
        error = netdev_open(name, type, &netdev);
        if (error) {
            ovs_error(error, "%s: failed to open network device", name);
            goto next;
        }

        smap_init(&args);
        error = netdev_get_config(netdev, &args);
        if (error) {
            ovs_error(error, "%s: failed to fetch configuration", name);
            goto next;
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
                    ovs_error(0, "%s: can't change type from %s to %s",
                              name, type, value);
                    failure = true;
                }
            } else if (!strcmp(key, "port_no")) {
                if (port_no != u32_to_odp(atoi(value))) {
                    ovs_error(0, "%s: can't change port number from "
                              "%"PRIu32" to %d",
                              name, port_no, atoi(value));
                    failure = true;
                }
            } else if (value[0] == '\0') {
                smap_remove(&args, key);
            } else {
                smap_replace(&args, key, value);
            }
        }

        /* Update configuration. */
        error = netdev_set_config(netdev, &args);
        smap_destroy(&args);
        if (error) {
            goto next;
        }

next:
        free(type);
        netdev_close(netdev);
        if (error) {
            failure = true;
        }
    }
    dpif_close(dpif);
    if (failure) {
        exit(EXIT_FAILURE);
    }
}

static bool
get_port_number(struct dpif *dpif, const char *name, odp_port_t *port)
{
    struct dpif_port dpif_port;

    if (!dpif_port_query_by_name(dpif, name, &dpif_port)) {
        *port = dpif_port.port_no;
        dpif_port_destroy(&dpif_port);
        return true;
    } else {
        ovs_error(0, "no port named %s", name);
        return false;
    }
}

static void
dpctl_del_if(int argc OVS_UNUSED, char *argv[])
{
    bool failure = false;
    struct dpif *dpif;
    int i;

    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");
    for (i = 2; i < argc; i++) {
        const char *name = argv[i];
        odp_port_t port;
        int error;

        if (!name[strspn(name, "0123456789")]) {
            port = u32_to_odp(atoi(name));
        } else if (!get_port_number(dpif, name, &port)) {
            failure = true;
            continue;
        }

        error = dpif_port_del(dpif, port);
        if (error) {
            ovs_error(error, "deleting port %s from %s failed", name, argv[1]);
            failure = true;
        }
    }
    dpif_close(dpif);
    if (failure) {
        exit(EXIT_FAILURE);
    }
}

static void
print_stat(const char *leader, uint64_t value)
{
    fputs(leader, stdout);
    if (value != UINT64_MAX) {
        printf("%"PRIu64, value);
    } else {
        putchar('?');
    }
}

static void
print_human_size(uint64_t value)
{
    if (value == UINT64_MAX) {
        /* Nothing to do. */
    } else if (value >= 1024ULL * 1024 * 1024 * 1024) {
        printf(" (%.1f TiB)", value / (1024.0 * 1024 * 1024 * 1024));
    } else if (value >= 1024ULL * 1024 * 1024) {
        printf(" (%.1f GiB)", value / (1024.0 * 1024 * 1024));
    } else if (value >= 1024ULL * 1024) {
        printf(" (%.1f MiB)", value / (1024.0 * 1024));
    } else if (value >= 1024) {
        printf(" (%.1f KiB)", value / 1024.0);
    }
}

static void
show_dpif(struct dpif *dpif)
{
    struct dpif_port_dump dump;
    struct dpif_port dpif_port;
    struct dpif_dp_stats stats;
    struct netdev *netdev;

    printf("%s:\n", dpif_name(dpif));
    if (!dpif_get_dp_stats(dpif, &stats)) {
        printf("\tlookups: hit:%"PRIu64" missed:%"PRIu64" lost:%"PRIu64"\n"
               "\tflows: %"PRIu64"\n",
               stats.n_hit, stats.n_missed, stats.n_lost, stats.n_flows);
        if (stats.n_masks != UINT32_MAX) {
            uint64_t n_pkts = stats.n_hit + stats.n_missed;
            double avg = n_pkts ? (double) stats.n_mask_hit / n_pkts : 0.0;

            printf("\tmasks: hit:%"PRIu64" total:%"PRIu32" hit/pkt:%.2f\n",
                   stats.n_mask_hit, stats.n_masks, avg);
        }
    }

    DPIF_PORT_FOR_EACH (&dpif_port, &dump, dpif) {
        printf("\tport %u: %s", dpif_port.port_no, dpif_port.name);

        if (strcmp(dpif_port.type, "system")) {
            int error;

            printf (" (%s", dpif_port.type);

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
                        printf("%c %s=%s", i ? ',' : ':', node->key,
                               node->value);
                    }
                    free(nodes);
                } else {
                    printf(", could not retrieve configuration (%s)",
                           ovs_strerror(error));
                }
                smap_destroy(&config);

                netdev_close(netdev);
            } else {
                printf(": open failed (%s)", ovs_strerror(error));
            }
            putchar(')');
        }
        putchar('\n');

        if (print_statistics) {
            struct netdev_stats s;
            int error;

            error = netdev_open(dpif_port.name, dpif_port.type, &netdev);
            if (error) {
                printf(", open failed (%s)", ovs_strerror(error));
                continue;
            }
            error = netdev_get_stats(netdev, &s);
            if (error) {
                printf(", could not retrieve stats (%s)", ovs_strerror(error));
                continue;
            }

            netdev_close(netdev);
            print_stat("\t\tRX packets:", s.rx_packets);
            print_stat(" errors:", s.rx_errors);
            print_stat(" dropped:", s.rx_dropped);
            print_stat(" overruns:", s.rx_over_errors);
            print_stat(" frame:", s.rx_frame_errors);
            printf("\n");

            print_stat("\t\tTX packets:", s.tx_packets);
            print_stat(" errors:", s.tx_errors);
            print_stat(" dropped:", s.tx_dropped);
            print_stat(" aborted:", s.tx_aborted_errors);
            print_stat(" carrier:", s.tx_carrier_errors);
            printf("\n");

            print_stat("\t\tcollisions:", s.collisions);
            printf("\n");

            print_stat("\t\tRX bytes:", s.rx_bytes);
            print_human_size(s.rx_bytes);
            print_stat("  TX bytes:", s.tx_bytes);
            print_human_size(s.tx_bytes);
            printf("\n");
        }
    }
    dpif_close(dpif);
}

static void
dpctl_show(int argc, char *argv[])
{
    bool failure = false;
    if (argc > 1) {
        int i;
        for (i = 1; i < argc; i++) {
            const char *name = argv[i];
            struct dpif *dpif;
            int error;

            error = parsed_dpif_open(name, false, &dpif);
            if (!error) {
                show_dpif(dpif);
            } else {
                ovs_error(error, "opening datapath %s failed", name);
                failure = true;
            }
        }
    } else {
        struct sset types;
        const char *type;

        sset_init(&types);
        dp_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            struct sset names;
            const char *name;

            sset_init(&names);
            if (dp_enumerate_names(type, &names)) {
                failure = true;
                continue;
            }
            SSET_FOR_EACH (name, &names) {
                struct dpif *dpif;
                int error;

                error = dpif_open(name, type, &dpif);
                if (!error) {
                    show_dpif(dpif);
                } else {
                    ovs_error(error, "opening datapath %s failed", name);
                    failure = true;
                }
            }
            sset_destroy(&names);
        }
        sset_destroy(&types);
    }
    if (failure) {
        exit(EXIT_FAILURE);
    }
}

static void
dpctl_dump_dps(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct sset dpif_names, dpif_types;
    const char *type;
    int error = 0;

    sset_init(&dpif_names);
    sset_init(&dpif_types);
    dp_enumerate_types(&dpif_types);

    SSET_FOR_EACH (type, &dpif_types) {
        const char *name;
        int retval;

        retval = dp_enumerate_names(type, &dpif_names);
        if (retval) {
            error = retval;
        }

        SSET_FOR_EACH (name, &dpif_names) {
            struct dpif *dpif;
            if (!dpif_open(name, type, &dpif)) {
                printf("%s\n", dpif_name(dpif));
                dpif_close(dpif);
            }
        }
    }

    sset_destroy(&dpif_names);
    sset_destroy(&dpif_types);
    if (error) {
        exit(EXIT_FAILURE);
    }
}

static void
dpctl_dump_flows(int argc, char *argv[])
{
    const struct dpif_flow_stats *stats;
    const struct nlattr *actions;
    struct dpif_flow_dump flow_dump;
    const struct nlattr *key;
    const struct nlattr *mask;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct hmap portno_names;
    struct simap names_portno;
    size_t actions_len;
    struct dpif *dpif;
    size_t key_len;
    size_t mask_len;
    struct ds ds;
    char *name, *filter = NULL;
    struct flow flow_filter;
    struct flow_wildcards wc_filter;
    void *state = NULL;
    int error;

    if (argc > 1 && !strncmp(argv[argc - 1], "filter=", 7)) {
        filter = xstrdup(argv[--argc] + 7);
    }
    name = (argc == 2) ? xstrdup(argv[1]) : get_one_dp();

    run(parsed_dpif_open(name, false, &dpif), "opening datapath");
    free(name);

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
            ovs_fatal(0, "Failed to parse filter (%s)", err);
        }
    }

    ds_init(&ds);
    error = dpif_flow_dump_start(&flow_dump, dpif);
    if (error) {
        goto exit;
    }
    dpif_flow_dump_state_init(dpif, &state);
    while (dpif_flow_dump_next(&flow_dump, state, &key, &key_len,
                               &mask, &mask_len, &actions, &actions_len,
                               &stats)) {
        if (filter) {
            struct flow flow;
            struct flow_wildcards wc;
            struct match match, match_filter;
            struct minimatch minimatch;

            odp_flow_key_to_flow(key, key_len, &flow);
            odp_flow_key_to_mask(mask, mask_len, &wc.masks, &flow);
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
        odp_flow_format(key, key_len, mask, mask_len, &portno_names, &ds,
                        verbosity);
        ds_put_cstr(&ds, ", ");

        dpif_flow_stats_format(stats, &ds);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len);
        printf("%s\n", ds_cstr(&ds));
    }
    dpif_flow_dump_state_uninit(dpif, state);
    error = dpif_flow_dump_done(&flow_dump);

exit:
    if (error) {
        ovs_fatal(error, "Failed to dump flows from datapath");
    }
    free(filter);
    odp_portno_names_destroy(&portno_names);
    hmap_destroy(&portno_names);
    simap_destroy(&names_portno);
    ds_destroy(&ds);
    dpif_close(dpif);
}

static void
dpctl_put_flow(int argc, char *argv[], enum dpif_flow_put_flags flags)
{
    const char *key_s = argv[argc - 2];
    const char *actions_s = argv[argc - 1];
    struct dpif_flow_stats stats;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct ofpbuf actions;
    struct ofpbuf key;
    struct ofpbuf mask;
    struct dpif *dpif;
    struct ds s;
    char *dp_name;
    struct simap port_names;

    dp_name = argc == 4 ? xstrdup(argv[1]) : get_one_dp();
    run(parsed_dpif_open(dp_name, false, &dpif), "opening datapath");
    free(dp_name);


    simap_init(&port_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        simap_put(&port_names, dpif_port.name, odp_to_u32(dpif_port.port_no));
    }

    ds_init(&s);
    ofpbuf_init(&key, 0);
    ofpbuf_init(&mask, 0);
    run(odp_flow_from_string(key_s, &port_names, &key, &mask),
        "parsing flow key");

    simap_destroy(&port_names);

    ofpbuf_init(&actions, 0);
    run(odp_actions_from_string(actions_s, NULL, &actions), "parsing actions");

    run(dpif_flow_put(dpif, flags,
                      ofpbuf_data(&key), ofpbuf_size(&key),
                      ofpbuf_size(&mask) == 0 ? NULL : ofpbuf_data(&mask),
                      ofpbuf_size(&mask),
                      ofpbuf_data(&actions), ofpbuf_size(&actions),
                      print_statistics ? &stats : NULL),
        "updating flow table");

    ofpbuf_uninit(&key);
    ofpbuf_uninit(&mask);
    ofpbuf_uninit(&actions);

    if (print_statistics) {
        struct ds s;

        ds_init(&s);
        dpif_flow_stats_format(&stats, &s);
        puts(ds_cstr(&s));
        ds_destroy(&s);
    }
}

static void
dpctl_add_flow(int argc, char *argv[])
{
    dpctl_put_flow(argc, argv, DPIF_FP_CREATE);
}

static void
dpctl_mod_flow(int argc OVS_UNUSED, char *argv[])
{
    enum dpif_flow_put_flags flags;

    flags = DPIF_FP_MODIFY;
    if (may_create) {
        flags |= DPIF_FP_CREATE;
    }
    if (zero_statistics) {
        flags |= DPIF_FP_ZERO_STATS;
    }

    dpctl_put_flow(argc, argv, flags);
}

static void
dpctl_del_flow(int argc, char *argv[])
{
    const char *key_s = argv[argc - 1];
    struct dpif_flow_stats stats;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct ofpbuf key;
    struct ofpbuf mask; /* To be ignored. */
    struct dpif *dpif;
    char *dp_name;
    struct simap port_names;

    dp_name = argc == 3 ? xstrdup(argv[1]) : get_one_dp();
    run(parsed_dpif_open(dp_name, false, &dpif), "opening datapath");
    free(dp_name);

    simap_init(&port_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        simap_put(&port_names, dpif_port.name, odp_to_u32(dpif_port.port_no));
    }

    ofpbuf_init(&key, 0);
    ofpbuf_init(&mask, 0);
    run(odp_flow_from_string(key_s, &port_names, &key, &mask), "parsing flow key");

    run(dpif_flow_del(dpif,
                      ofpbuf_data(&key), ofpbuf_size(&key),
                      print_statistics ? &stats : NULL), "deleting flow");

    simap_destroy(&port_names);
    ofpbuf_uninit(&key);
    ofpbuf_uninit(&mask);

    if (print_statistics) {
        struct ds s;

        ds_init(&s);
        dpif_flow_stats_format(&stats, &s);
        puts(ds_cstr(&s));
        ds_destroy(&s);
    }
}

static void
dpctl_del_flows(int argc, char *argv[])
{
    struct dpif *dpif;
    char *name;

    name = (argc == 2) ? xstrdup(argv[1]) : get_one_dp();
    run(parsed_dpif_open(name, false, &dpif), "opening datapath");
    free(name);

    run(dpif_flow_flush(dpif), "deleting all flows");
    dpif_close(dpif);
}

static void
dpctl_help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
}

/* Undocumented commands for unit testing. */

static void
dpctl_parse_actions(int argc, char *argv[])
{
    int i;

    for (i = 1; i < argc; i++) {
        struct ofpbuf actions;
        struct ds s;

        ofpbuf_init(&actions, 0);
        run(odp_actions_from_string(argv[i], NULL, &actions),
            "odp_actions_from_string");

        ds_init(&s);
        format_odp_actions(&s, ofpbuf_data(&actions), ofpbuf_size(&actions));
        puts(ds_cstr(&s));
        ds_destroy(&s);

        ofpbuf_uninit(&actions);
    }
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
static void
dpctl_normalize_actions(int argc, char *argv[])
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
    int i;

    ds_init(&s);

    simap_init(&port_names);
    for (i = 3; i < argc; i++) {
        char name[16];
        int number;

        if (ovs_scan(argv[i], "%15[^=]=%d", name, &number)) {
            uintptr_t n = number;
            simap_put(&port_names, name, n);
        } else {
            ovs_fatal(0, "%s: expected NAME=NUMBER", argv[i]);
        }
    }

    /* Parse flow key. */
    ofpbuf_init(&keybuf, 0);
    run(odp_flow_from_string(argv[1], &port_names, &keybuf, NULL),
        "odp_flow_key_from_string");

    ds_clear(&s);
    odp_flow_format(ofpbuf_data(&keybuf), ofpbuf_size(&keybuf), NULL, 0, NULL, &s, verbosity);
    printf("input flow: %s\n", ds_cstr(&s));

    run(odp_flow_key_to_flow(ofpbuf_data(&keybuf), ofpbuf_size(&keybuf), &flow),
        "odp_flow_key_to_flow");
    ofpbuf_uninit(&keybuf);

    /* Parse actions. */
    ofpbuf_init(&odp_actions, 0);
    run(odp_actions_from_string(argv[2], &port_names, &odp_actions),
        "odp_actions_from_string");
    simap_destroy(&port_names);

    if (verbosity) {
        ds_clear(&s);
        format_odp_actions(&s, ofpbuf_data(&odp_actions), ofpbuf_size(&odp_actions));
        printf("input actions: %s\n", ds_cstr(&s));
    }

    hmap_init(&actions_per_flow);
    NL_ATTR_FOR_EACH (a, left, ofpbuf_data(&odp_actions), ofpbuf_size(&odp_actions)) {
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

    qsort(afs, n_afs, sizeof *afs, compare_actions_for_flow);

    for (i = 0; i < n_afs; i++) {
        const struct actions_for_flow *af = afs[i];

        sort_output_actions(ofpbuf_data(&af->actions), ofpbuf_size(&af->actions));

        if (af->flow.vlan_tci != htons(0)) {
            printf("vlan(vid=%"PRIu16",pcp=%d): ",
                   vlan_tci_to_vid(af->flow.vlan_tci),
                   vlan_tci_to_pcp(af->flow.vlan_tci));
        } else {
            printf("no vlan: ");
        }

        if (eth_type_mpls(af->flow.dl_type)) {
            printf("mpls(label=%"PRIu32",tc=%d,ttl=%d): ",
                   mpls_lse_to_label(af->flow.mpls_lse[0]),
                   mpls_lse_to_tc(af->flow.mpls_lse[0]),
                   mpls_lse_to_ttl(af->flow.mpls_lse[0]));
        } else {
            printf("no mpls: ");
        }

        ds_clear(&s);
        format_odp_actions(&s, ofpbuf_data(&af->actions), ofpbuf_size(&af->actions));
        puts(ds_cstr(&s));
    }
    ds_destroy(&s);
}

static const struct command all_commands[] = {
    { "add-dp", 1, INT_MAX, dpctl_add_dp },
    { "del-dp", 1, 1, dpctl_del_dp },
    { "add-if", 2, INT_MAX, dpctl_add_if },
    { "del-if", 2, INT_MAX, dpctl_del_if },
    { "set-if", 2, INT_MAX, dpctl_set_if },
    { "dump-dps", 0, 0, dpctl_dump_dps },
    { "show", 0, INT_MAX, dpctl_show },
    { "dump-flows", 0, 2, dpctl_dump_flows },
    { "add-flow", 2, 3, dpctl_add_flow },
    { "mod-flow", 2, 3, dpctl_mod_flow },
    { "del-flow", 1, 2, dpctl_del_flow },
    { "del-flows", 0, 1, dpctl_del_flows },
    { "help", 0, INT_MAX, dpctl_help },

    /* Undocumented commands for testing. */
    { "parse-actions", 1, INT_MAX, dpctl_parse_actions },
    { "normalize-actions", 2, INT_MAX, dpctl_normalize_actions },

    { NULL, 0, 0, NULL },
};

static const struct command *get_all_commands(void)
{
    return all_commands;
}
