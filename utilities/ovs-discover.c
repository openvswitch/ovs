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
#include <getopt.h>
#include <limits.h>
#include <regex.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "command-line.h"
#include "daemon.h"
#include "dhcp-client.h"
#include "dhcp.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "netdev.h"
#include "poll-loop.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_discover)

struct iface {
    const char *name;
    struct dhclient *dhcp;
};

/* The interfaces that we serve. */
static struct iface *ifaces;
static int n_ifaces;

/* --accept-vconn: Regular expression specifying the class of controller vconns
 * that we will accept during autodiscovery. */
static const char *accept_controller_re = "tcp:.*";
static regex_t accept_controller_regex;

/* --exit-without-bind: Exit after discovering the controller, without binding
 * the network device to an IP address? */
static bool exit_without_bind;

/* --exit-after-bind: Exit after discovering the controller, after binding the
 * network device to an IP address? */
static bool exit_after_bind;

static bool iface_init(struct iface *, const char *netdev_name);
static void release_ifaces(void *aux OVS_UNUSED);

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static void modify_dhcp_request(struct dhcp_msg *, void *aux);
static bool validate_dhcp_offer(const struct dhcp_msg *, void *aux);

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    int retval;
    int i;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    parse_options(argc, argv);

    argc -= optind;
    argv += optind;
    if (argc < 1) {
        ovs_fatal(0, "need at least one non-option argument; "
                  "use --help for usage");
    }

    ifaces = xmalloc(argc * sizeof *ifaces);
    n_ifaces = 0;
    for (i = 0; i < argc; i++) {
        if (iface_init(&ifaces[n_ifaces], argv[i])) {
            n_ifaces++;
        }
    }
    if (!n_ifaces) {
        ovs_fatal(0, "failed to initialize any DHCP clients");
    }

    for (i = 0; i < n_ifaces; i++) {
        struct iface *iface = &ifaces[i];
        dhclient_init(iface->dhcp, 0);
    }
    fatal_signal_add_hook(release_ifaces, NULL, NULL, true);

    retval = regcomp(&accept_controller_regex, accept_controller_re,
                     REG_NOSUB | REG_EXTENDED);
    if (retval) {
        size_t length = regerror(retval, &accept_controller_regex, NULL, 0);
        char *buffer = xmalloc(length);
        regerror(retval, &accept_controller_regex, buffer, length);
        ovs_fatal(0, "%s: %s", accept_controller_re, buffer);
    }

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    die_if_already_running();

    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        for (i = 0; i < n_ifaces; i++) {
            struct iface *iface = &ifaces[i];
            dhclient_run(iface->dhcp);
            if (dhclient_changed(iface->dhcp)) {
                bool is_bound = dhclient_is_bound(iface->dhcp);
                int j;

                /* Configure network device. */
                if (!exit_without_bind) {
                    dhclient_configure_netdev(iface->dhcp);
                    dhclient_update_resolv_conf(iface->dhcp);
                }

                if (is_bound) {
                    static bool detached = false;
                    struct ds ds;

                    /* Disable timeout, since discovery was successful. */
                    time_alarm(0);

                    /* Print discovered parameters. */
                    ds_init(&ds);
                    dhcp_msg_to_string(dhclient_get_config(iface->dhcp),
                                       true, &ds);
                    fputs(ds_cstr(&ds), stdout);
                    putchar('\n');
                    fflush(stdout);
                    ds_destroy(&ds);

                    /* Exit if the user requested it. */
                    if (exit_without_bind) {
                        VLOG_DBG("exiting because of successful binding on %s "
                                 "and --exit-without-bind specified",
                                 iface->name);
                        exit(0);
                    }
                    if (exit_after_bind) {
                        VLOG_DBG("exiting because of successful binding on %s "
                                 "and --exit-after-bind specified",
                                 iface->name);
                        exit(0);
                    }

                    /* Detach into background, if we haven't already. */
                    if (!detached) {
                        detached = true;
                        daemonize();
                    }
                }

                /* We only want an address on a single one of our interfaces.
                 * So: if we have an address on this interface, stop looking
                 * for one on the others; if we don't have an address on this
                 * interface, start looking everywhere. */
                for (j = 0; j < n_ifaces; j++) {
                    struct iface *if2 = &ifaces[j];
                    if (iface != if2) {
                        if (is_bound) {
                            dhclient_release(if2->dhcp);
                        } else {
                            dhclient_init(if2->dhcp, 0);
                        }
                    }
                }
            }
        }
        unixctl_server_run(unixctl);
        for (i = 0; i < n_ifaces; i++) {
            struct iface *iface = &ifaces[i];
            dhclient_wait(iface->dhcp);
        }
        unixctl_server_wait(unixctl);
        poll_block();
    }

    return 0;
}

static bool
iface_init(struct iface *iface, const char *netdev_name)
{
    int retval;

    iface->name = netdev_name;
    iface->dhcp = NULL;

    if (exit_after_bind) {
        /* Bring this interface up permanently, so that the bound address
         * persists past program termination. */
        struct netdev *netdev;

        retval = netdev_open_default(iface->name, &netdev);
        if (retval) {
            ovs_error(retval, "Could not open %s device", iface->name);
            return false;
        }
        retval = netdev_turn_flags_on(netdev, NETDEV_UP, true);
        if (retval) {
            ovs_error(retval, "Could not bring %s device up", iface->name);
            return false;
        }
        netdev_close(netdev);
    }

    retval = dhclient_create(iface->name, modify_dhcp_request,
                             validate_dhcp_offer, NULL, &iface->dhcp);
    if (retval) {
        ovs_error(retval, "%s: failed to initialize DHCP client", iface->name);
        return false;
    }

    return true;
}

static void
release_ifaces(void *aux OVS_UNUSED)
{
    int i;

    for (i = 0; i < n_ifaces; i++) {
        struct dhclient *dhcp = ifaces[i].dhcp;
        dhclient_release(dhcp);
        if (dhclient_changed(dhcp)) {
            dhclient_configure_netdev(dhcp);
        }
    }
}

static void
modify_dhcp_request(struct dhcp_msg *msg, void *aux OVS_UNUSED)
{
    dhcp_msg_put_string(msg, DHCP_CODE_VENDOR_CLASS, "OpenFlow");
}

static bool
validate_dhcp_offer(const struct dhcp_msg *msg, void *aux OVS_UNUSED)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);
    char *vconn_name;
    bool accept;

    vconn_name = dhcp_msg_get_string(msg, DHCP_CODE_OFP_CONTROLLER_VCONN);
    if (!vconn_name) {
        VLOG_WARN_RL(&rl, "rejecting DHCP offer missing controller vconn");
        return false;
    }
    accept = !regexec(&accept_controller_regex, vconn_name, 0, NULL, 0);
    free(vconn_name);
    return accept;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_ACCEPT_VCONN = UCHAR_MAX + 1,
        OPT_EXIT_WITHOUT_BIND,
        OPT_EXIT_AFTER_BIND,
        OPT_NO_DETACH,
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"accept-vconn", required_argument, 0, OPT_ACCEPT_VCONN},
        {"exit-without-bind", no_argument, 0, OPT_EXIT_WITHOUT_BIND},
        {"exit-after-bind", no_argument, 0, OPT_EXIT_AFTER_BIND},
        {"no-detach",   no_argument, 0, OPT_NO_DETACH},
        {"timeout",     required_argument, 0, 't'},
        {"pidfile",     optional_argument, 0, OPT_PIDFILE},
        {"overwrite-pidfile", no_argument, 0, OPT_OVERWRITE_PIDFILE},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        VLOG_LONG_OPTIONS,
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);
    bool detach_after_bind = true;

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_ACCEPT_VCONN:
            accept_controller_re = (optarg[0] == '^'
                                    ? optarg
                                    : xasprintf("^%s", optarg));
            break;

        case OPT_EXIT_WITHOUT_BIND:
            exit_without_bind = true;
            break;

        case OPT_EXIT_AFTER_BIND:
            exit_after_bind = true;
            break;

        case OPT_NO_DETACH:
            detach_after_bind = false;
            break;

        case OPT_PIDFILE:
            set_pidfile(optarg);
            break;

        case OPT_OVERWRITE_PIDFILE:
            ignore_existing_pidfile();
            break;

        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ovs_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            signal(SIGALRM, SIG_DFL);
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

    if ((exit_without_bind + exit_after_bind + !detach_after_bind) > 1) {
        ovs_fatal(0, "--exit-without-bind, --exit-after-bind, and --no-detach "
                  "are mutually exclusive");
    }
    if (detach_after_bind) {
        set_detach();
    }
}

static void
usage(void)
{
    printf("%s: a tool for discovering OpenFlow controllers.\n"
           "usage: %s [OPTIONS] NETDEV [NETDEV...]\n"
           "where each NETDEV is a network device on which to perform\n"
           "controller discovery.\n"
           "\nOrdinarily, ovs-discover runs in the foreground until it\n"
           "obtains an IP address and discovers an OpenFlow controller via\n"
           "DHCP, then it prints information about the controller to stdout\n"
           "and detaches to the background to maintain the IP address lease.\n"
           "\nNetworking options:\n"
           "  --accept-vconn=REGEX    accept matching discovered controllers\n"
           "  --exit-without-bind     exit after discovery, without binding\n"
           "  --exit-after-bind       exit after discovery, after binding\n"
           "  --no-detach             do not detach after discovery\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOther options:\n"
           "  -t, --timeout=SECS      give up discovery after SECS seconds\n"
           "  --pidfile[=FILE]        create pidfile (default: %s/%s.pid)\n"
           "  --overwrite-pidfile     with --pidfile, start even if already "
                                      "running\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n",
           ovs_rundir, program_name);
    exit(EXIT_SUCCESS);
}
