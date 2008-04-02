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
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "buffer.h"
#include "command-line.h"
#include "compiler.h"
#include "fault.h"
#include "util.h"
#include "rconn.h"
#include "vconn-ssl.h"
#include "vlog-socket.h"
#include "openflow.h"
#include "poll-loop.h"

#include "vlog.h"
#define THIS_MODULE VLM_secchan

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static bool reliable = true;

int
main(int argc, char *argv[])
{
    struct half {
        struct rconn *rconn;
        struct buffer *rxbuf;
    };

    struct half halves[2];
    int retval;
    int i;

    set_program_name(argv[0]);
    register_fault_handlers();
    vlog_init();
    parse_options(argc, argv);

    if (argc - optind != 2) {
        fatal(0, "exactly two peer arguments required; use --help for usage");
    }

    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        fatal(retval, "Could not listen for vlog connections");
    }

    for (i = 0; i < 2; i++) {
        halves[i].rconn = rconn_new(argv[optind + i], 1);
        halves[i].rxbuf = NULL;
    }
    for (;;) {
        /* Do some work.  Limit the number of iterations so that callbacks
         * registered with the poll loop don't starve. */
        int iteration;

        for (i = 0; i < 2; i++) {
            rconn_run(halves[i].rconn);
        }

        for (iteration = 0; iteration < 50; iteration++) {
            bool progress = false;
            for (i = 0; i < 2; i++) {
                struct half *this = &halves[i];
                struct half *peer = &halves[!i];

                if (!this->rxbuf) {
                    this->rxbuf = rconn_recv(this->rconn);
                }

                if (this->rxbuf) {
                    retval = rconn_send(peer->rconn, this->rxbuf);
                    if (retval != EAGAIN) {
                        this->rxbuf = NULL;
                        if (!retval) {
                            progress = true;
                        }
                    }
                }
            }
            if (!progress) {
                break;
            }
        }

        /* Wait for something to happen. */
        for (i = 0; i < 2; i++) {
            struct half *this = &halves[i];

            rconn_run_wait(this->rconn);
            if (!this->rxbuf) {
                rconn_recv_wait(this->rconn);
            }
        }
        poll_block();
    }

    return 0;
}

static void
parse_options(int argc, char *argv[]) 
{
    static struct option long_options[] = {
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
        case 'h':
            usage();

        case 'V':
            printf("%s "VERSION" compiled "__DATE__" "__TIME__"\n", argv[0]);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
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
    printf("%s: Secure Channel\n"
           "usage: %s [OPTIONS] LOCAL REMOTE\n"
           "\nRelays OpenFlow message between LOCAL and REMOTE datapaths.\n"
           "LOCAL and REMOTE must each be one of the following:\n"
           "  tcp:HOST[:PORT]         PORT (default: %d) on remote TCP HOST\n",
           program_name, program_name, OFP_TCP_PORT);
#ifdef HAVE_NETLINK
    printf("  nl:DP_IDX               local datapath DP_IDX\n");
#endif
#ifdef HAVE_OPENSSL
    printf("  ssl:HOST[:PORT]         SSL PORT (default: %d) on remote HOST\n"
           "\nPKI configuration (required to use SSL):\n"
           "  -p, --private-key=FILE  file with private key\n"
           "  -c, --certificate=FILE  file with certificate for private key\n"
           "  -C, --ca-cert=FILE      file with peer CA certificate\n",
           OFP_SSL_PORT);
#endif
    printf("\nOther options:\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
