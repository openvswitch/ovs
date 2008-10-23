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
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "command-line.h"
#include "daemon.h"
#include "datapath.h"
#include "fault.h"
#include "openflow.h"
#include "poll-loop.h"
#include "queue.h"
#include "util.h"
#include "rconn.h"
#include "timeval.h"
#include "vconn.h"
#include "vconn-ssl.h"
#include "vlog-socket.h"

#define THIS_MODULE VLM_switch
#include "vlog.h"


/* Strings to describe the manufacturer, hardware, and software.  This data 
 * is queriable through the switch description stats message. */
char mfr_desc[DESC_STR_LEN] = "Nicira Networks";
char hw_desc[DESC_STR_LEN] = "Reference User-Space Switch";
char sw_desc[DESC_STR_LEN] = VERSION;
char serial_num[SERIAL_NUM_LEN] = "None";

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static const char *listen_pvconn_name;
static struct datapath *dp;
static uint64_t dpid = UINT64_MAX;
static char *port_list;

/* --max-backoff: Maximum interval between controller connection attempts, in
 * seconds. */
static int max_backoff = 15;

static void add_ports(struct datapath *dp, char *port_list);

int
main(int argc, char *argv[])
{
    struct rconn *rconn;
    int error;

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);

    if (argc - optind != 1) {
        ofp_fatal(0, "missing controller argument; use --help for usage");
    }

    rconn = rconn_create(60, max_backoff);
    error = rconn_connect(rconn, argv[optind]);
    if (error == EAFNOSUPPORT) {
        ofp_fatal(0, "no support for %s vconn", argv[optind]);
    }
    error = dp_new(&dp, dpid, rconn);
    if (listen_pvconn_name) {
        struct pvconn *listen_pvconn;
        int retval;

        retval = pvconn_open(listen_pvconn_name, &listen_pvconn);
        if (retval && retval != EAGAIN) {
            ofp_fatal(retval, "opening %s", listen_pvconn_name);
        }
        dp_add_listen_pvconn(dp, listen_pvconn);
    }
    if (error) {
        ofp_fatal(error, "could not create datapath");
    }
    if (port_list) {
        add_ports(dp, port_list); 
    }

    error = vlog_server_listen(NULL, NULL);
    if (error) {
        ofp_fatal(error, "could not listen for vlog connections");
    }

    die_if_already_running();
    daemonize();

    for (;;) {
        dp_run(dp);
        dp_wait(dp);
        poll_block();
    }

    return 0;
}

static void
add_ports(struct datapath *dp, char *port_list)
{
    char *port, *save_ptr;

    /* Glibc 2.7 has a bug in strtok_r when compiling with optimization that
     * can cause segfaults here:
     * http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
     * Using ",," instead of the obvious "," works around it. */
    for (port = strtok_r(port_list, ",,", &save_ptr); port;
         port = strtok_r(NULL, ",,", &save_ptr)) {
        int error = dp_add_port(dp, port);
        if (error) {
            ofp_fatal(error, "failed to add port %s", port);
        }
    }
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_MAX_BACKOFF = UCHAR_MAX + 1,
        OPT_MFR_DESC,
        OPT_HW_DESC,
        OPT_SW_DESC,
        OPT_SERIAL_NUM,
        OPT_BOOTSTRAP_CA_CERT
    };

    static struct option long_options[] = {
        {"interfaces",  required_argument, 0, 'i'},
        {"datapath-id", required_argument, 0, 'd'},
        {"max-backoff", required_argument, 0, OPT_MAX_BACKOFF},
        {"listen",      required_argument, 0, 'l'},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        {"mfr-desc",    required_argument, 0, OPT_MFR_DESC},
        {"hw-desc",     required_argument, 0, OPT_HW_DESC},
        {"sw-desc",     required_argument, 0, OPT_SW_DESC},
        {"serial_num",  required_argument, 0, OPT_SERIAL_NUM},
        DAEMON_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        VCONN_SSL_LONG_OPTIONS
        {"bootstrap-ca-cert", required_argument, 0, OPT_BOOTSTRAP_CA_CERT},
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int indexptr;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, &indexptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'd':
            if (strlen(optarg) != 12
                || strspn(optarg, "0123456789abcdefABCDEF") != 12) {
                ofp_fatal(0, "argument to -d or --datapath-id must be "
                          "exactly 12 hex digits");
            }
            dpid = strtoll(optarg, NULL, 16);
            if (!dpid) {
                ofp_fatal(0, "argument to -d or --datapath-id must "
                          "be nonzero");
            }
            break;

        case 'h':
            usage();

        case 'V':
            printf("%s "VERSION" compiled "__DATE__" "__TIME__"\n", argv[0]);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case 'i':
            if (!port_list) {
                port_list = optarg;
            } else {
                port_list = xasprintf("%s,%s", port_list, optarg);
            }
            break;

        case OPT_MAX_BACKOFF:
            max_backoff = atoi(optarg);
            if (max_backoff < 1) {
                ofp_fatal(0, "--max-backoff argument must be at least 1");
            } else if (max_backoff > 3600) {
                max_backoff = 3600;
            }
            break;

        case OPT_MFR_DESC:
            strncpy(mfr_desc, optarg, sizeof mfr_desc);
            break;

        case OPT_HW_DESC:
            strncpy(hw_desc, optarg, sizeof hw_desc);
            break;

        case OPT_SW_DESC:
            strncpy(sw_desc, optarg, sizeof sw_desc);
            break;

        case OPT_SERIAL_NUM:
            strncpy(serial_num, optarg, sizeof serial_num);
            break;

        case 'l':
            if (listen_pvconn_name) {
                ofp_fatal(0, "-l or --listen may be only specified once");
            }
            listen_pvconn_name = optarg;
            break;

        DAEMON_OPTION_HANDLERS

#ifdef HAVE_OPENSSL
        VCONN_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            vconn_ssl_set_ca_cert_file(optarg, true);
            break;
#endif

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
    printf("%s: userspace OpenFlow switch\n"
           "usage: %s [OPTIONS] CONTROLLER\n"
           "where CONTROLLER is an active OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, true, true);
    printf("\nConfiguration options:\n"
           "  -i, --interfaces=NETDEV[,NETDEV]...\n"
           "                          add specified initial switch ports\n"
           "  -d, --datapath-id=ID    Use ID as the OpenFlow switch ID\n"
           "                          (ID must consist of 12 hex digits)\n"
           "  --max-backoff=SECS      max time between controller connection\n"
           "                          attempts (default: 15 seconds)\n"
           "  -l, --listen=METHOD     allow management connections on METHOD\n"
           "                          (a passive OpenFlow connection method)\n");
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
