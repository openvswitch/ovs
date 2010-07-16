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
#include "dhcp-client.h"
#include <arpa/inet.h>
#include <getopt.h>
#include <stdlib.h>
#include <limits.h>
#include "command-line.h"
#include "dhcp.h"
#include "fatal-signal.h"
#include "poll-loop.h"
#include "util.h"
#include "vlog.h"

/* --request-ip: IP address to request from server.  If zero, then do not
 * request a specific IP address. */
static struct in_addr request_ip;

/* --vendor-class: Vendor class string to include in request.  If null, no
 * vendor class string is included. */
static const char *vendor_class;

/* --no-resolv-conf: Update /etc/resolv.conf to match DHCP reply? */
static bool update_resolv_conf = true;

static void parse_options(int argc, char *argv[]);
static void usage(void);
static void release(void *cli_);
static void modify_dhcp_request(struct dhcp_msg *, void *aux);

int
main(int argc, char *argv[])
{
    struct dhclient *cli;
    int error;

    set_program_name(argv[0]);
    parse_options(argc, argv);

    argc -= optind;
    argv += optind;
    if (argc != 1) {
        ovs_fatal(0, "exactly one non-option argument required; "
                  "use --help for help");
    }

    error = dhclient_create(argv[0], modify_dhcp_request, NULL, NULL, &cli);
    if (error) {
        ovs_fatal(error, "dhclient_create failed");
    }
    dhclient_init(cli, request_ip.s_addr);
    fatal_signal_add_hook(release, NULL, cli, true);

    for (;;) {
        dhclient_run(cli);
        if (dhclient_changed(cli)) {
            dhclient_configure_netdev(cli);
            if (update_resolv_conf) {
                dhclient_update_resolv_conf(cli);
            }
        }
        dhclient_wait(cli);
        poll_block();
    }
}

static void
release(void *cli_)
{
    struct dhclient *cli = cli_;
    dhclient_release(cli);
    if (dhclient_changed(cli)) {
        dhclient_configure_netdev(cli);
    }
}

static void
modify_dhcp_request(struct dhcp_msg *msg, void *aux OVS_UNUSED)
{
    if (vendor_class) {
        dhcp_msg_put_string(msg, DHCP_CODE_VENDOR_CLASS, vendor_class);
    }
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_REQUEST_IP = UCHAR_MAX + 1,
        OPT_VENDOR_CLASS,
        OPT_NO_RESOLV_CONF
    };
    static struct option long_options[] = {
        {"request-ip",  required_argument, 0, OPT_REQUEST_IP },
        {"vendor-class", required_argument, 0, OPT_VENDOR_CLASS },
        {"no-resolv-conf", no_argument, 0, OPT_NO_RESOLV_CONF},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_REQUEST_IP:
            if (!inet_aton(optarg, &request_ip)) {
                ovs_fatal(0,
                          "--request-ip argument is not a valid IP address");
            }
            break;

        case OPT_VENDOR_CLASS:
            vendor_class = optarg;
            break;

        case OPT_NO_RESOLV_CONF:
            update_resolv_conf = false;
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
}

static void
usage(void)
{
    printf("%s: standalone program for testing Open vSwitch DHCP client.\n"
           "usage: %s [OPTIONS] NETDEV\n"
           "where NETDEV is a network device (e.g. eth0).\n"
           "\nDHCP options:\n"
           "  --request-ip=IP         request specified IP address (default:\n"
           "                          do not request a specific IP)\n"
           "  --vendor-class=STRING   use STRING as vendor class; use\n"
           "                          OpenFlow to imitate ovs-openflowd\n"
           "  --no-resolv-conf        do not update /etc/resolv.conf\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

