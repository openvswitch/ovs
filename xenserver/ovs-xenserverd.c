/* Copyright (c) 2010 Nicira Networks
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
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "poll-loop.h"
#include "process.h"
#include "socket-util.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

#define THIS_MODULE VLM_xenserverd
#include "vlog.h"

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static void network_uuid_refresh_run(void);
static void network_uuid_refresh_wait(void);

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    int retval;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    process_init();

    die_if_already_running();
    daemonize_start();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    daemonize_complete();

    for (;;) {
        network_uuid_refresh_run();
        unixctl_server_run(unixctl);

        network_uuid_refresh_wait();
        unixctl_server_wait(unixctl);

        poll_block();
    }

    return 0;
}


static void
parse_options(int argc, char *argv[])
{
    enum {
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
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
        case 'H':
        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    if (optind != argc) {
        ovs_fatal(0, "no non-option arguments accepted");
    }
}

static void
usage(void)
{
    printf("%s: Open vSwitch daemon for XenServer-specific functionality\n"
           "usage: %s [OPTIONS]\n", program_name, program_name);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

/* Network UUID refreshing.
 *
 * The vswitch database is supposed to maintain an up-to-date UUID for the
 * system's networks in the Bridge table as external-ids:network-uuids.  On
 * XenServer systems, /opt/xensource/libexec/interface-reconfigure updates
 * these fields as bridges are brought up and down.  Most of the time, that is
 * sufficient.  However, this is one exception: when a XenServer host enters or
 * leaves a pool, interface-reconfigure is not invoked, and neither is any
 * other script.  So we need to monitor the XenServer's pool membership status
 * and refresh the network UUIDs (by invoking the refresh-network-uuids script)
 * if it changes.
 *
 * This functionality should be harmless on non-XenServer systems, since they
 * will have neither /etc/xensource/pool.conf nor refresh-network-uuids.
 */

/* Timestamp of /etc/xensource/pool.conf, or zeros if it does not exist. */
static struct timespec pool_conf_mtime;

/* The executing instance of refresh-network-uuids, or NULL if none. */
static struct process *refresh_script;

/* Time at which to start the refresh script. */
static long long int next_refresh = LLONG_MAX;

static void
network_uuid_refresh_run(void)
{
    struct timespec new_mtime;

    /* If a script is running, don't do anything until it finishes. */
    if (refresh_script) {
        char *s;

        if (!process_exited(refresh_script)) {
            return;
        }

        s = process_status_msg(process_status(refresh_script));
        VLOG_INFO("refresh-network-uuids exited, %s", s);
        free(s);

        process_destroy(refresh_script);
        refresh_script = NULL;
    }

    /* Otherwise, schedule a refresh in a few seconds if the timestamp has
     * changed.  Refreshing immediately doesn't work because XAPI takes a while
     * to switch over to new UUIDs.
     *
     * (We will always detect a change in timestamp when we start up.  That's
     * good, since it means that the refresh-network-uuids script gets
     * thoroughly tested and we can't miss pool changes that happen when
     * ovs-vswitchd isn't running.)  */
    get_mtime("/etc/xensource/pool.conf", &new_mtime);
    if (new_mtime.tv_sec != pool_conf_mtime.tv_sec
        || new_mtime.tv_nsec != pool_conf_mtime.tv_nsec) {
        next_refresh = time_msec() + 10 * 1000;
        return;
    }

    /* Otherwise, if our timer expired then start the refresh. */
    if (time_msec() >= next_refresh) {
        struct stat s;
        char *argv[2];

        next_refresh = LLONG_MAX;

        argv[0] = xasprintf("%s/scripts/refresh-network-uuids",
                            ovs_pkgdatadir);
        argv[1] = NULL;

        if (!stat(argv[0], &s)) {
            int error = process_start(argv, NULL, 0, NULL, 0, &refresh_script);
            if (error) {
                VLOG_ERR("failed to refresh network UUIDs: %s could "
                         "not be started (%s)", argv[0], strerror(error));
            } else {
                VLOG_INFO("refreshing network UUIDs: started %s", argv[0]);
            }
        } else {
            VLOG_ERR("failed to refresh network UUIDs: could not stat %s (%s)",
                     argv[0], strerror(errno));
        }

        pool_conf_mtime = new_mtime;
        free(argv[0]);
    }
}

void
network_uuid_refresh_wait(void)
{
    if (refresh_script) {
        process_wait(refresh_script);
    } else {
        if (pool_conf_mtime.tv_sec) {
            poll_timer_wait(1000);
        }
        if (next_refresh != LLONG_MAX) {
            poll_timer_wait(next_refresh - time_msec());
        }
    }
}
