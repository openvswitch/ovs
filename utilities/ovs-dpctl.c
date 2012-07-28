/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <assert.h>
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
#include "flow.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "shash.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpctl);

/* -s, --statistics: Print port statistics? */
static bool print_statistics;

/* -m, --more: Output verbosity.
 *
 * So far only undocumented commands honor this option, so we don't document
 * the option itself. */
static int verbosity;

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
           "  dump-flows DP            display flows in DP\n"
           "  del-flows DP             delete all flows from DP\n"
           "Each IFACE on add-dp, add-if, and set-if may be followed by\n"
           "comma-separated options.  See ovs-dpctl(8) for syntax, or the\n"
           "Interface table in ovs-vswitchd.conf.db(5) for an options list.\n",
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

static void dpctl_add_if(int argc, char *argv[]);

static int if_up(const char *netdev_name)
{
    struct netdev *netdev;
    int retval;

    retval = netdev_open(netdev_name, "system", &netdev);
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
        uint16_t port_no = UINT16_MAX;
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
                port_no = atoi(value);
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
            ovs_error(error, "%s: failed to configure network device", name);
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
        uint32_t port_no;
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
                if (port_no != atoi(value)) {
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
            ovs_error(error, "%s: failed to configure network device", name);
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
dpctl_del_if(int argc OVS_UNUSED, char *argv[])
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
    struct dpif_dp_stats stats;
    struct netdev *netdev;

    printf("%s:\n", dpif_name(dpif));
    if (!dpif_get_dp_stats(dpif, &stats)) {
        printf("\tlookups: hit:%"PRIu64" missed:%"PRIu64" lost:%"PRIu64"\n"
               "\tflows: %"PRIu64"\n",
               stats.n_hit, stats.n_missed, stats.n_lost, stats.n_flows);
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
                           strerror(error));
                }
                smap_destroy(&config);

                netdev_close(netdev);
            } else {
                printf(": open failed (%s)", strerror(error));
            }
            putchar(')');
        }
        putchar('\n');

        if (print_statistics) {
            struct netdev_stats s;
            int error;

            error = netdev_open(dpif_port.name, dpif_port.type, &netdev);
            if (error) {
                printf(", open failed (%s)", strerror(error));
                continue;
            }
            error = netdev_get_stats(netdev, &s);
            if (error) {
                printf(", could not retrieve stats (%s)", strerror(error));
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
dpctl_dump_flows(int argc OVS_UNUSED, char *argv[])
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
dpctl_del_flows(int argc OVS_UNUSED, char *argv[])
{
    struct dpif *dpif;

    run(parsed_dpif_open(argv[1], false, &dpif), "opening datapath");
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
        format_odp_actions(&s, actions.data, actions.size);
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

    assert(bytes % NL_A_U32_SIZE == 0);
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
        sort_output_actions__(first_output, (struct nlattr *) end);
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
        int n = -1;

        if (sscanf(argv[i], "%15[^=]=%d%n", name, &number, &n) > 0 && n > 0) {
            uintptr_t n = number;
            simap_put(&port_names, name, n);
        } else {
            ovs_fatal(0, "%s: expected NAME=NUMBER", argv[i]);
        }
    }

    /* Parse flow key. */
    ofpbuf_init(&keybuf, 0);
    run(odp_flow_key_from_string(argv[1], &port_names, &keybuf),
        "odp_flow_key_from_string");

    ds_clear(&s);
    odp_flow_key_format(keybuf.data, keybuf.size, &s);
    printf("input flow: %s\n", ds_cstr(&s));

    run(odp_flow_key_to_flow(keybuf.data, keybuf.size, &flow),
        "odp_flow_key_to_flow");
    ofpbuf_uninit(&keybuf);

    /* Parse actions. */
    ofpbuf_init(&odp_actions, 0);
    run(odp_actions_from_string(argv[2], &port_names, &odp_actions),
        "odp_actions_from_string");

    if (verbosity) {
        ds_clear(&s);
        format_odp_actions(&s, odp_actions.data, odp_actions.size);
        printf("input actions: %s\n", ds_cstr(&s));
    }

    hmap_init(&actions_per_flow);
    NL_ATTR_FOR_EACH (a, left, odp_actions.data, odp_actions.size) {
        if (nl_attr_type(a) == OVS_ACTION_ATTR_POP_VLAN) {
            flow.vlan_tci = htons(0);
            continue;
        }

        if (nl_attr_type(a) == OVS_ACTION_ATTR_PUSH_VLAN) {
            const struct ovs_action_push_vlan *push;

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
    assert(i == n_afs);

    qsort(afs, n_afs, sizeof *afs, compare_actions_for_flow);

    for (i = 0; i < n_afs; i++) {
        const struct actions_for_flow *af = afs[i];

        sort_output_actions(af->actions.data, af->actions.size);

        if (af->flow.vlan_tci != htons(0)) {
            printf("vlan(vid=%"PRIu16",pcp=%d): ",
                   vlan_tci_to_vid(af->flow.vlan_tci),
                   vlan_tci_to_pcp(af->flow.vlan_tci));
        } else {
            printf("no vlan: ");
        }

        ds_clear(&s);
        format_odp_actions(&s, af->actions.data, af->actions.size);
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
    { "dump-flows", 1, 1, dpctl_dump_flows },
    { "del-flows", 1, 1, dpctl_del_flows },
    { "help", 0, INT_MAX, dpctl_help },

    /* Undocumented commands for testing. */
    { "parse-actions", 1, INT_MAX, dpctl_parse_actions },
    { "normalize-actions", 2, INT_MAX, dpctl_normalize_actions },

    { NULL, 0, 0, NULL },
};
