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
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
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
#include "dynamic-string.h"
#include "netdev.h"
#include "xflow-util.h"
#include "svec.h"
#include "timeval.h"
#include "util.h"
#include "xfif.h"

#include "vlog.h"
#define THIS_MODULE VLM_dpctl

static const struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    time_init();
    vlog_init();
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
        {"timeout", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        VLOG_LONG_OPTIONS,
        {0, 0, 0, 0},
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
           "  del-flows DP             delete all flows from DP\n"
           "  dump-groups DP           display port groups in DP\n",
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

        fprintf(stderr, "%s: ", program_name);
        va_start(args, message);
        vfprintf(stderr, message, args);
        va_end(args);
        if (retval == EOF) {
            fputs(": unexpected end of file\n", stderr);
        } else {
            fprintf(stderr, ": %s\n", strerror(retval));
        }

        exit(EXIT_FAILURE);
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
parsed_xfif_open(const char *arg_, bool create, struct xfif **xfifp)
{
    int result;
    char *name, *type;

    xf_parse_name(arg_, &name, &type);

    if (create) {
        result = xfif_create(name, type, xfifp);
    } else {
        result = xfif_open(name, type, xfifp);
    }

    free(name);
    free(type);
    return result;
}

static void
do_add_dp(int argc OVS_UNUSED, char *argv[])
{
    struct xfif *xfif;
    run(parsed_xfif_open(argv[1], true, &xfif), "add_dp");
    xfif_close(xfif);
    if (argc > 2) {
        do_add_if(argc, argv);
    }
}

static void
do_del_dp(int argc OVS_UNUSED, char *argv[])
{
    struct xfif *xfif;
    run(parsed_xfif_open(argv[1], false, &xfif), "opening datapath");
    run(xfif_delete(xfif), "del_dp");
    xfif_close(xfif);
}

static int
compare_ports(const void *a_, const void *b_)
{
    const struct xflow_port *a = a_;
    const struct xflow_port *b = b_;
    return a->port < b->port ? -1 : a->port > b->port;
}

static void
query_ports(struct xfif *xfif, struct xflow_port **ports, size_t *n_ports)
{
    run(xfif_port_list(xfif, ports, n_ports), "listing ports");
    qsort(*ports, *n_ports, sizeof **ports, compare_ports);
}

static void
do_add_if(int argc OVS_UNUSED, char *argv[])
{
    bool failure = false;
    struct xfif *xfif;
    int i;

    run(parsed_xfif_open(argv[1], false, &xfif), "opening datapath");
    for (i = 2; i < argc; i++) {
        char *save_ptr = NULL;
        char *devname, *suboptions;
        int flags = 0;
        int error;

        devname = strtok_r(argv[i], ",", &save_ptr);
        if (!devname) {
            ovs_error(0, "%s is not a valid network device name", argv[i]);
            continue;
        }

        suboptions = strtok_r(NULL, "", &save_ptr);
        if (suboptions) {
            enum {
                AP_INTERNAL
            };
            static char *options[] = {
                "internal"
            };

            while (*suboptions != '\0') {
                char *value;

                switch (getsubopt(&suboptions, options, &value)) {
                case AP_INTERNAL:
                    flags |= XFLOW_PORT_INTERNAL;
                    break;

                default:
                    ovs_error(0, "unknown suboption '%s'", value);
                    break;
                }
            }
        }

        error = xfif_port_add(xfif, devname, flags, NULL);
        if (error) {
            ovs_error(error, "adding %s to %s failed", devname, argv[1]);
            failure = true;
        } else if (if_up(devname)) {
            failure = true;
        }
    }
    xfif_close(xfif);
    if (failure) {
        exit(EXIT_FAILURE);
    }
}

static bool
get_port_number(struct xfif *xfif, const char *name, uint16_t *port)
{
    struct xflow_port *ports;
    size_t n_ports;
    size_t i;

    query_ports(xfif, &ports, &n_ports);
    for (i = 0; i < n_ports; i++) {
        if (!strcmp(name, ports[i].devname)) {
            *port = ports[i].port;
            free(ports);
            return true;
        }
    }
    free(ports);
    ovs_error(0, "no port named %s", name);
    return false;
}

static void
do_del_if(int argc OVS_UNUSED, char *argv[])
{
    bool failure = false;
    struct xfif *xfif;
    int i;

    run(parsed_xfif_open(argv[1], false, &xfif), "opening datapath");
    for (i = 2; i < argc; i++) {
        const char *name = argv[i];
        uint16_t port;
        int error;

        if (!name[strspn(name, "0123456789")]) {
            port = atoi(name);
        } else if (!get_port_number(xfif, name, &port)) {
            failure = true;
            continue;
        }

        error = xfif_port_del(xfif, port);
        if (error) {
            ovs_error(error, "deleting port %s from %s failed", name, argv[1]);
            failure = true;
        }
    }
    xfif_close(xfif);
    if (failure) {
        exit(EXIT_FAILURE);
    }
}

static void
show_xfif(struct xfif *xfif)
{
    struct xflow_port *ports;
    struct xflow_stats stats;
    size_t n_ports;
    size_t i;

    printf("%s:\n", xfif_name(xfif));
    if (!xfif_get_xf_stats(xfif, &stats)) {
        printf("\tflows: cur:%"PRIu32", soft-max:%"PRIu32", "
               "hard-max:%"PRIu32"\n",
               stats.n_flows, stats.cur_capacity, stats.max_capacity);
        printf("\tports: cur:%"PRIu32", max:%"PRIu32"\n",
               stats.n_ports, stats.max_ports);
        printf("\tgroups: max:%"PRIu16"\n", stats.max_groups);
        printf("\tlookups: frags:%llu, hit:%llu, missed:%llu, lost:%llu\n",
               (unsigned long long int) stats.n_frags,
               (unsigned long long int) stats.n_hit,
               (unsigned long long int) stats.n_missed,
               (unsigned long long int) stats.n_lost);
        printf("\tqueues: max-miss:%"PRIu16", max-action:%"PRIu16"\n",
               stats.max_miss_queue, stats.max_action_queue);
    }
    query_ports(xfif, &ports, &n_ports);
    for (i = 0; i < n_ports; i++) {
        printf("\tport %u: %s", ports[i].port, ports[i].devname);
        if (ports[i].flags & XFLOW_PORT_INTERNAL) {
            printf(" (internal)");
        }
        printf("\n");
    }
    free(ports);
    xfif_close(xfif);
}

static void
do_show(int argc, char *argv[])
{
    bool failure = false;
    if (argc > 1) {
        int i;
        for (i = 1; i < argc; i++) {
            const char *name = argv[i];
            struct xfif *xfif;
            int error;

            error = parsed_xfif_open(name, false, &xfif);
            if (!error) {
                show_xfif(xfif);
            } else {
                ovs_error(error, "opening datapath %s failed", name);
                failure = true;
            }
        }
    } else {
        unsigned int i;
        for (i = 0; i < XFLOW_MAX; i++) {
            char name[128];
            struct xfif *xfif;
            int error;

            sprintf(name, "dp%u", i);
            error = parsed_xfif_open(name, false, &xfif);
            if (!error) {
                show_xfif(xfif);
            } else if (error != ENODEV) {
                ovs_error(error, "opening datapath %s failed", name);
                failure = true;
            }
        }
    }
    if (failure) {
        exit(EXIT_FAILURE);
    }
}

static void
do_dump_dps(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct svec xfif_names, xfif_types;
    unsigned int i;
    int error = 0;

    svec_init(&xfif_names);
    svec_init(&xfif_types);
    xf_enumerate_types(&xfif_types);

    for (i = 0; i < xfif_types.n; i++) {
        unsigned int j;
        int retval;

        retval = xf_enumerate_names(xfif_types.names[i], &xfif_names);
        if (retval) {
            error = retval;
        }

        for (j = 0; j < xfif_names.n; j++) {
            struct xfif *xfif;
            if (!xfif_open(xfif_names.names[j], xfif_types.names[i], &xfif)) {
                printf("%s\n", xfif_name(xfif));
                xfif_close(xfif);
            }
        }
    }

    svec_destroy(&xfif_names);
    svec_destroy(&xfif_types);
    if (error) {
        exit(EXIT_FAILURE);
    }
}

static void
do_dump_flows(int argc OVS_UNUSED, char *argv[])
{
    struct xflow_flow *flows;
    struct xfif *xfif;
    size_t n_flows;
    struct ds ds;
    size_t i;

    run(parsed_xfif_open(argv[1], false, &xfif), "opening datapath");
    run(xfif_flow_list_all(xfif, &flows, &n_flows), "listing all flows");

    ds_init(&ds);
    for (i = 0; i < n_flows; i++) {
        struct xflow_flow *f = &flows[i];
        enum { MAX_ACTIONS = 4096 / sizeof(union xflow_action) };
        union xflow_action actions[MAX_ACTIONS];

        f->actions = actions;
        f->n_actions = MAX_ACTIONS;
        xfif_flow_get(xfif, f);

        ds_clear(&ds);
        format_xflow_flow(&ds, f);
        printf("%s\n", ds_cstr(&ds));
    }
    ds_destroy(&ds);
    xfif_close(xfif);
}

static void
do_del_flows(int argc OVS_UNUSED, char *argv[])
{
    struct xfif *xfif;

    run(parsed_xfif_open(argv[1], false, &xfif), "opening datapath");
    run(xfif_flow_flush(xfif), "deleting all flows");
    xfif_close(xfif);
}

static void
do_dump_groups(int argc OVS_UNUSED, char *argv[])
{
    struct xflow_stats stats;
    struct xfif *xfif;
    unsigned int i;

    run(parsed_xfif_open(argv[1], false, &xfif), "opening datapath");
    run(xfif_get_xf_stats(xfif, &stats), "get datapath stats");
    for (i = 0; i < stats.max_groups; i++) {
        uint16_t *ports;
        size_t n_ports;

        if (!xfif_port_group_get(xfif, i, &ports, &n_ports) && n_ports) {
            size_t j;

            printf("group %u:", i);
            for (j = 0; j < n_ports; j++) {
                printf(" %"PRIu16, ports[j]);
            }
            printf("\n");
        }
        free(ports);
    }
    xfif_close(xfif);
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
    { "dump-groups", 1, 1, do_dump_groups },
    { "help", 0, INT_MAX, do_help },
    { NULL, 0, 0, NULL },
};
