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

#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "command-line.h"
#include "controller.h"
#include "datapath.h"
#include "fault.h"
#include "forward.h"
#include "openflow.h"
#include "poll-loop.h"
#include "queue.h"
#include "util.h"
#include "vconn.h"
#include "vconn-ssl.h"
#include "vlog-socket.h"

#define THIS_MODULE VLM_switch
#include "vlog.h"

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static bool reliable = true;
static struct datapath *dp;
static uint64_t dpid = UINT64_MAX;
static char *port_list;

static void add_ports(struct datapath *dp, char *port_list);

int
main(int argc, char *argv[])
{
    struct controller_connection cc;
    int error;

    set_program_name(argv[0]);
    register_fault_handlers();
    vlog_init();
    parse_options(argc, argv);

    if (argc - optind != 1) {
        fatal(0, "missing controller argument; use --help for usage");
    }

    controller_init(&cc, argv[optind], reliable);
    error = dp_new(&dp, dpid, &cc);
    if (error) {
        fatal(error, "could not create datapath");
    }
    if (port_list) {
        add_ports(dp, port_list); 
    }

    error = vlog_server_listen(NULL, NULL);
    if (error) {
        fatal(error, "could not listen for vlog connections");
    }

    for (;;) {
        dp_run(dp);
        fwd_run(dp);
        controller_run(&cc);
        
        dp_wait(dp);
        fwd_run_wait(dp);
        controller_run_wait(&cc);
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
            fatal(error, "failed to add port %s", port);
        }
    }
}

static void
parse_options(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"interfaces",  required_argument, 0, 'i'},
        {"unreliable",  no_argument, 0, 'u'},
        {"datapath-id", required_argument, 0, 'd'},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
#ifdef HAVE_OPENSSL
        {"private-key", required_argument, 0, 'p'},
        {"certificate", required_argument, 0, 'c'},
        {"ca-cert",     required_argument, 0, 'C'},
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
        case 'u':
            reliable = false;
            break;

        case 'd':
            if (strlen(optarg) != 12
                || strspn(optarg, "0123456789abcdefABCDEF") != 12) {
                fatal(0, "argument to -d or --datapath-id must be "
                      "exactly 12 hex digits");
            }
            dpid = strtoll(optarg, NULL, 16);
            if (!dpid) {
                fatal(0, "argument to -d or --datapath-id must be nonzero");
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

#ifdef HAVE_OPENSSL
        case 'p':
            vconn_ssl_set_private_key_file(optarg);
            break;

        case 'c':
            vconn_ssl_set_certificate_file(optarg);
            break;

        case 'C':
            vconn_ssl_set_ca_cert_file(optarg);
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
           "CONTROLLER must be one of the following:\n"
           "  tcp:HOST[:PORT]         PORT (default: %d) on remote TCP HOST\n",
           program_name, program_name, OFP_TCP_PORT);
#ifdef HAVE_OPENSSL
    printf("  ssl:HOST[:PORT]         SSL PORT (default: %d) on remote HOST\n"
           "\nPKI configuration (required to use SSL):\n"
           "  -p, --private-key=FILE  file with private key\n"
           "  -c, --certificate=FILE  file with certificate for private key\n"
           "  -C, --ca-cert=FILE      file with peer CA certificate\n",
           OFP_SSL_PORT);
#endif
    printf("Options:\n"
           "  -i, --interfaces=NETDEV[,NETDEV]...\n"
           "                          add specified initial switch ports\n"
           "  -d, --datapath-id=ID    Use ID as the OpenFlow switch ID\n"
           "                          (ID must consist of 12 hex digits)\n"
           "  -u, --unreliable        do not reconnect to controller\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
