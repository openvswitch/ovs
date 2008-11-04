/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
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
#include "util.h"
#include "vlog-socket.h"

#include "vlog.h"
#define THIS_MODULE VLM_ofp_discover

struct iface {
    const char *name;
    struct dhclient *dhcp;
};

/* The interfaces that we serve. */
static struct iface *ifaces;
static int n_ifaces;

/* --accept-vconn: Regular expression specifying the class of controller vconns
 * that we will accept during autodiscovery. */
static const char *accept_controller_re = ".*";
static regex_t accept_controller_regex;

/* --exit-without-bind: Exit after discovering the controller, without binding
 * the network device to an IP address? */
static bool exit_without_bind;

/* --exit-after-bind: Exit after discovering the controller, after binding the
 * network device to an IP address? */
static bool exit_after_bind;

static bool iface_init(struct iface *, const char *netdev_name);
static void release_ifaces(void *aux UNUSED);

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static void modify_dhcp_request(struct dhcp_msg *, void *aux);
static bool validate_dhcp_offer(const struct dhcp_msg *, void *aux);

int
main(int argc, char *argv[])
{
    int retval;
    int i;

    set_program_name(argv[0]);
    time_init();
    vlog_init();
    parse_options(argc, argv);

    argc -= optind;
    argv += optind;
    if (argc < 1) {
        ofp_fatal(0, "need at least one non-option argument; "
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
        ofp_fatal(0, "failed to initialize any DHCP clients");
    }

    for (i = 0; i < n_ifaces; i++) {
        struct iface *iface = &ifaces[i];
        dhclient_init(iface->dhcp, 0);
    }
    fatal_signal_add_hook(release_ifaces, NULL, true);

    retval = regcomp(&accept_controller_regex, accept_controller_re,
                     REG_NOSUB | REG_EXTENDED);
    if (retval) {
        size_t length = regerror(retval, &accept_controller_regex, NULL, 0);
        char *buffer = xmalloc(length);
        regerror(retval, &accept_controller_regex, buffer, length);
        ofp_fatal(0, "%s: %s", accept_controller_re, buffer);
    }

    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        ofp_fatal(retval, "Could not listen for vlog connections");
    }

    die_if_already_running();

    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        fatal_signal_block();
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
        for (i = 0; i < n_ifaces; i++) {
            struct iface *iface = &ifaces[i];
            dhclient_wait(iface->dhcp);
        }
        fatal_signal_unblock();
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

        retval = netdev_open(iface->name, NETDEV_ETH_TYPE_NONE, &netdev);
        if (retval) {
            ofp_error(retval, "Could not open %s device", iface->name);
            return false;
        }
        retval = netdev_turn_flags_on(netdev, NETDEV_UP, true);
        if (retval) {
            ofp_error(retval, "Could not bring %s device up", iface->name);
            return false;
        }
        netdev_close(netdev);
    }

    retval = dhclient_create(iface->name, modify_dhcp_request,
                             validate_dhcp_offer, NULL, &iface->dhcp);
    if (retval) {
        ofp_error(retval, "%s: failed to initialize DHCP client", iface->name);
        return false;
    }

    return true;
}

static void
release_ifaces(void *aux UNUSED)
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
modify_dhcp_request(struct dhcp_msg *msg, void *aux)
{
    dhcp_msg_put_string(msg, DHCP_CODE_VENDOR_CLASS, "OpenFlow");
}

static bool
validate_dhcp_offer(const struct dhcp_msg *msg, void *aux)
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
    };
    static struct option long_options[] = {
        {"accept-vconn", required_argument, 0, OPT_ACCEPT_VCONN},
        {"exit-without-bind", no_argument, 0, OPT_EXIT_WITHOUT_BIND},
        {"exit-after-bind", no_argument, 0, OPT_EXIT_AFTER_BIND},
        {"no-detach",   no_argument, 0, OPT_NO_DETACH},
        {"timeout",     required_argument, 0, 't'},
        {"pidfile",     optional_argument, 0, 'P'},
        {"force",       no_argument, 0, 'f'},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
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

        case 'P':
            set_pidfile(optarg);
            break;

        case 'f':
            ignore_existing_pidfile();
            break;

        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ofp_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            signal(SIGALRM, SIG_DFL);
            break;

        case 'h':
            usage();

        case 'V':
            printf("%s %s compiled "__DATE__" "__TIME__"\n",
                   program_name, VERSION BUILDNR);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    if ((exit_without_bind + exit_after_bind + !detach_after_bind) > 1) {
        ofp_fatal(0, "--exit-without-bind, --exit-after-bind, and --no-detach "
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
           "\nOrdinarily, ofp-discover runs in the foreground until it\n"
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
           "  -P, --pidfile[=FILE]    create pidfile (default: %s/%s.pid)\n"
           "  -f, --force             with -P, start even if already running\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n",
           ofp_rundir, program_name);
    exit(EXIT_SUCCESS);
}
