/* Copyright (C) 2007 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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
#include "vconn-ssl.h"
#include "vconn.h"
#include "vlog-socket.h"
#include "openflow.h"
#include "poll-loop.h"

#include "vlog.h"
#define THIS_MODULE VLM_secchan

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static bool reliable = true;

struct half {
    const char *name;
    struct vconn *vconn;
    struct buffer *rxbuf;
    time_t backoff_deadline;
    int backoff;
};

static void reconnect(struct half *);

int
main(int argc, char *argv[])
{
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
        halves[i].name = argv[optind + i];
        halves[i].vconn = NULL;
        halves[i].rxbuf = NULL;
        halves[i].backoff_deadline = 0;
        halves[i].backoff = 1;
        reconnect(&halves[i]);
    }
    for (;;) {
        /* Do some work.  Limit the number of iterations so that callbacks
         * registered with the poll loop don't starve. */
        int iteration;
        for (iteration = 0; iteration < 50; iteration++) {
            bool progress = false;
            for (i = 0; i < 2; i++) {
                struct half *this = &halves[i];
                struct half *peer = &halves[!i];

                if (!this->rxbuf) {
                    retval = vconn_recv(this->vconn, &this->rxbuf);
                    if (retval && retval != EAGAIN) {
                        if (retval == EOF) {
                            VLOG_DBG("%s: connection closed by remote host",
                                     this->name); 
                        } else {
                            VLOG_DBG("%s: recv: closing connection: %s",
                                     this->name, strerror(retval));
                        }
                        reconnect(this);
                        break;
                    }
                }

                if (this->rxbuf) {
                    retval = vconn_send(peer->vconn, this->rxbuf);
                    if (!retval) {
                        this->rxbuf = NULL;
                        progress = true;
                    } else if (retval != EAGAIN) {
                        VLOG_DBG("%s: send: closing connection: %s",
                                 peer->name, strerror(retval));
                        reconnect(peer);
                        break;
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
            struct half *peer = &halves[!i];
            if (!this->rxbuf) {
                vconn_recv_wait(this->vconn);
            } else {
                vconn_send_wait(peer->vconn);
            }
        }
        poll_block();
    }

    return 0;
}

static void
reconnect(struct half *this) 
{
    if (this->vconn != NULL) {
        if (!reliable) {
            fatal(0, "%s: connection dropped", this->name);
        }

        VLOG_WARN("%s: connection dropped, reconnecting", this->name);
        vconn_close(this->vconn);
        this->vconn = NULL;
        buffer_delete(this->rxbuf);
        this->rxbuf = NULL;
    }

    for (;;) {
        time_t now = time(0);
        int retval;

        if (now >= this->backoff_deadline) {
            this->backoff = 1;
        } else {
            this->backoff *= 2;
            if (this->backoff > 60) {
                this->backoff = 60;
            }
            VLOG_WARN("%s: waiting %d seconds before reconnect\n",
                      this->name, (int) (this->backoff_deadline - now));
            poll_timer_wait((this->backoff_deadline - now) * 1000);
            poll_block();
        }

        retval = vconn_open_block(this->name, &this->vconn);
        if (!retval) {
            VLOG_WARN("%s: connected", this->name);
            if (vconn_is_passive(this->vconn)) {
                fatal(0, "%s: passive vconn not supported in control path",
                      this->name);
            }
            this->backoff_deadline = now + this->backoff;
            return;
        }

        if (!reliable) {
            fatal(0, "%s: connection failed", this->name);
        }
        VLOG_WARN("%s: connection failed (%s)", this->name, strerror(retval));
        this->backoff_deadline = time(0) + this->backoff;
    }
}

static void
parse_options(int argc, char *argv[]) 
{
    static struct option long_options[] = {
        {"unreliable",  no_argument, 0, 'u'},
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
    printf("\nNetworking options:\n"
           "  -u, --unreliable        do not reconnect after connections drop\n"
           "\nOther options:\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
