/*
 * Copyright (c) 2011 Nicira, Inc.
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

#include <errno.h>
#include <getopt.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "command-line.h"
#include "util.h"

#define ADD_ALL_VLANS_CMD 10
#define DEL_ALL_VLANS_CMD 11

static void usage(void);
static void parse_options(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    struct vlan_ioctl_args vlan_args;
    const char *netdev, *setting;
    int fd;

    set_program_name(argv[0]);

    parse_options(argc, argv);
    if (argc - optind != 2) {
        ovs_fatal(0, "exactly two non-option arguments are required "
                  "(use --help for help)");
    }

    memset(&vlan_args, 0, sizeof vlan_args);

    /* Get command. */
    setting = argv[optind + 1];
    if (!strcmp(setting, "on")) {
        vlan_args.cmd = ADD_ALL_VLANS_CMD;
    } else if (!strcmp(setting, "off")) {
        vlan_args.cmd = DEL_ALL_VLANS_CMD;
    } else {
        ovs_fatal(0, "second command line argument must be \"on\" or \"off\" "
                  "(not \"%s\")", setting);
    }

    /* Get network device name. */
    netdev = argv[optind];
    if (strlen(netdev) >= IFNAMSIZ) {
        ovs_fatal(0, "%s: network device name too long", netdev);
    }
    strcpy(vlan_args.device1, netdev);

    /* Execute operation. */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ovs_fatal(errno, "socket creation failed");
    }
    if (ioctl(fd, SIOCSIFVLAN, &vlan_args) < 0) {
        if (errno == ENOPKG) {
            ovs_fatal(0, "operation failed (8021q module not loaded)");
        } else if (errno == EOPNOTSUPP) {
            ovs_fatal(0, "operation failed (kernel does not support the "
                      "VLAN bug workaround)");
        } else {
            ovs_fatal(errno, "operation failed");
        }
    }
    close(fd);

    return 0;
}

static void
usage(void)
{
    printf("\
%s, for enabling or disabling the kernel VLAN bug workaround\n\
usage: %s NETDEV SETTING\n\
where NETDEV is a network device (e.g. \"eth0\")\n\
  and SETTING is \"on\" to enable the workaround or \"off\" to disable it.\n\
\n\
Options:\n\
  -h, --help         Print this helpful information\n\
  -V, --version      Display version information\n",
           program_name, program_name);
    exit(EXIT_SUCCESS);
}

static void
parse_options(int argc, char *argv[])
{
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int option;

        option = getopt_long(argc, argv, "+t:hVe", long_options, NULL);
        if (option == -1) {
            break;
        }
        switch (option) {
        case 'h':
            usage();
            break;

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        case '?':
            exit(EXIT_FAILURE);

        default:
            OVS_NOT_REACHED();
        }
    }
    free(short_options);
}
