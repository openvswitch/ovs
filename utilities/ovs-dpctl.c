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
#include "netdev.h"
#include "odp-util.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpctl);

/* -s, --statistics: Print port statistics? */
static bool print_statistics;

static const struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    run_command(argc - optind, argv + optind, all_commands);
    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_DUMMY = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"statistics", no_argument, NULL, 's'},
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
            OVS_PRINT_VERSION(0, 0);
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
           "  del-if DP IFACE...       delete each IFACE from DP\n"
           "  dump-dps                 display names of all datapaths\n"
           "  show                     show basic info on all datapaths\n"
           "  show DP...               show basic info on each DP\n"
           "  dump-flows DP            display flows in DP\n"
           "  del-flows DP             delete all flows from DP\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOther options:\n"
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

static void do_add_if(int argc, char *argv[]);

static int if_up(const char *netdev_name)
{
    struct netdev *netdev;
    int retval;

    retval = netdev_open_default(netdev_name, &netdev);
    if (!retval) {
        retval = netdev_turn_flags_on(netdev, NETDEV_UP, true);
        netdev_close(netdev);
    }
    return retval;
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
do_add_dp(int argc OVS_UNUSED, char *argv[])
{
    struct dpif *dpif;
    run(parsed_dpif_open(argv[1], true, &dpif), "add_dp");
    dpif_close(dpif);
    if (argc > 2) {
        do_add_if(argc, argv);
    }
}

static void
do_del_dp(int argc OVS_UNUSED, char *argv[])
{
    struct dpif *dpif;
    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");
    run(dpif_delete(dpif), "del_dp");
    dpif_close(dpif);
}

static void
do_add_if(int argc OVS_UNUSED, char *argv[])
{
    bool failure = false;
    struct dpif *dpif;
    int i;

    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");
    for (i = 2; i < argc; i++) {
        char *save_ptr = NULL;
        struct netdev_options options;
        struct netdev *netdev;
        struct shash args;
        char *option;
        int error;

        options.name = strtok_r(argv[i], ",", &save_ptr);
        options.type = "system";
        options.args = &args;
        options.ethertype = NETDEV_ETH_TYPE_NONE;

        if (!options.name) {
            ovs_error(0, "%s is not a valid network device name", argv[i]);
            continue;
        }

        shash_init(&args);
        while ((option = strtok_r(NULL, ",", &save_ptr)) != NULL) {
            char *save_ptr_2 = NULL;
            char *key, *value;

            key = strtok_r(option, "=", &save_ptr_2);
            value = strtok_r(NULL, "", &save_ptr_2);
            if (!value) {
                value = "";
            }

            if (!strcmp(key, "type")) {
                options.type = value;
            } else if (!shash_add_once(&args, key, value)) {
                ovs_error(0, "duplicate \"%s\" option", key);
            }
        }

        error = netdev_open(&options, &netdev);
        if (error) {
            ovs_error(error, "%s: failed to open network device",
                      options.name);
        } else {
            error = dpif_port_add(dpif, netdev, NULL);
            if (error) {
                ovs_error(error, "adding %s to %s failed",
                          options.name, argv[1]);
            } else {
                error = if_up(options.name);
            }
            netdev_close(netdev);
        }
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
get_port_number(struct dpif *dpif, const char *name, uint16_t *port)
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
do_del_if(int argc OVS_UNUSED, char *argv[])
{
    bool failure = false;
    struct dpif *dpif;
    int i;

    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");
    for (i = 2; i < argc; i++) {
        const char *name = argv[i];
        uint16_t port;
        int error;

        if (!name[strspn(name, "0123456789")]) {
            port = atoi(name);
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
    struct odp_stats stats;

    printf("%s:\n", dpif_name(dpif));
    if (!dpif_get_dp_stats(dpif, &stats)) {
        printf("\tlookups: frags:%llu, hit:%llu, missed:%llu, lost:%llu\n",
               (unsigned long long int) stats.n_frags,
               (unsigned long long int) stats.n_hit,
               (unsigned long long int) stats.n_missed,
               (unsigned long long int) stats.n_lost);
    }
    DPIF_PORT_FOR_EACH (&dpif_port, &dump, dpif) {
        printf("\tport %u: %s", dpif_port.port_no, dpif_port.name);

        if (strcmp(dpif_port.type, "system")) {
            struct netdev_options netdev_options;
            struct netdev *netdev;
            int error;

            printf (" (%s", dpif_port.type);

            netdev_options.name = dpif_port.name;
            netdev_options.type = dpif_port.type;
            netdev_options.args = NULL;
            netdev_options.ethertype = NETDEV_ETH_TYPE_NONE;
            error = netdev_open(&netdev_options, &netdev);
            if (!error) {
                const struct shash_node **nodes;
                const struct shash *config;
                size_t i;

                config = netdev_get_config(netdev);
                nodes = shash_sort(config);
                for (i = 0; i < shash_count(config); i++) {
                    const struct shash_node *node = nodes[i];
                    printf("%c %s=%s", i ? ',' : ':',
                           node->name, (char *) node->data);
                }
                free(nodes);

                netdev_close(netdev);
            } else {
                printf(": open failed (%s)", strerror(error));
            }
            putchar(')');
        }
        putchar('\n');

        if (print_statistics) {
            const struct netdev_stats *s = &dpif_port.stats;

            print_stat("\t\tRX packets:", s->rx_packets);
            print_stat(" errors:", s->rx_errors);
            print_stat(" dropped:", s->rx_dropped);
            print_stat(" overruns:", s->rx_over_errors);
            print_stat(" frame:", s->rx_frame_errors);
            printf("\n");

            print_stat("\t\tTX packets:", s->tx_packets);
            print_stat(" errors:", s->tx_errors);
            print_stat(" dropped:", s->tx_dropped);
            print_stat(" aborted:", s->tx_aborted_errors);
            print_stat(" carrier:", s->tx_carrier_errors);
            printf("\n");

            print_stat("\t\tcollisions:", s->collisions);
            printf("\n");

            print_stat("\t\tRX bytes:", s->rx_bytes);
            print_human_size(s->rx_bytes);
            print_stat("  TX bytes:", s->tx_bytes);
            print_human_size(s->tx_bytes);
            printf("\n");
        }
    }
    dpif_close(dpif);
}

static void
do_show(int argc, char *argv[])
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
do_dump_dps(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
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
do_dump_flows(int argc OVS_UNUSED, char *argv[])
{
    const struct dpif_flow_stats *stats;
    const struct nlattr *actions;
    struct dpif_flow_dump dump;
    const struct nlattr *key;
    size_t actions_len;
    struct dpif *dpif;
    size_t key_len;
    struct ds ds;

    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");

    ds_init(&ds);
    dpif_flow_dump_start(&dump, dpif);
    while (dpif_flow_dump_next(&dump, &key, &key_len,
                               &actions, &actions_len, &stats)) {
        ds_clear(&ds);
        odp_flow_key_format(key, key_len, &ds);
        ds_put_cstr(&ds, ", ");
        dpif_flow_stats_format(stats, &ds);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len);
        printf("%s\n", ds_cstr(&ds));
    }
    dpif_flow_dump_done(&dump);
    ds_destroy(&ds);
    dpif_close(dpif);
}

static void
do_del_flows(int argc OVS_UNUSED, char *argv[])
{
    struct dpif *dpif;

    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");
    run(dpif_flow_flush(dpif), "deleting all flows");
    dpif_close(dpif);
}

static void
do_help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
}

static const struct command all_commands[] = {
    { "add-dp", 1, INT_MAX, do_add_dp },
    { "del-dp", 1, 1, do_del_dp },
    { "add-if", 2, INT_MAX, do_add_if },
    { "del-if", 2, INT_MAX, do_del_if },
    { "dump-dps", 0, 0, do_dump_dps },
    { "show", 0, INT_MAX, do_show },
    { "dump-flows", 1, 1, do_dump_flows },
    { "del-flows", 1, 1, do_del_flows },
    { "help", 0, INT_MAX, do_help },
    { NULL, 0, 0, NULL },
};
