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
#include "list.h"
#include "util.h"
#include "rconn.h"
#include "vconn-ssl.h"
#include "vlog-socket.h"
#include "openflow.h"
#include "poll-loop.h"
#include "vconn.h"

#include "vlog.h"
#define THIS_MODULE VLM_secchan

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static struct vconn *listen_vconn = NULL;

struct half {
    struct rconn *rconn;
    struct buffer *rxbuf;
};

struct relay {
    struct list node;
    struct half halves[2];
};

static struct list relays = LIST_INITIALIZER(&relays);

static void new_management_connection(const char *nl_name, struct vconn *new_remote);
static void relay_create(struct rconn *, struct rconn *);
static void relay_run(struct relay *);
static void relay_wait(struct relay *);
static void relay_destroy(struct relay *);

int
main(int argc, char *argv[])
{
    const char *nl_name;
    int retval;

    set_program_name(argv[0]);
    register_fault_handlers();
    vlog_init();
    parse_options(argc, argv);

    if (argc - optind != 2) {
        fatal(0,
              "need exactly two non-option arguments; use --help for usage");
    }
    nl_name = argv[optind];
    if (strncmp(nl_name, "nl:", 3)
        || strlen(nl_name) < 4
        || nl_name[strspn(nl_name + 3, "0123456789") + 3]) {
        fatal(0, "%s: argument is not of the form \"nl:DP_ID\"", nl_name);
    }

    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        fatal(retval, "Could not listen for vlog connections");
    }

    relay_create(rconn_new(argv[optind], 1), rconn_new(argv[optind + 1], 1));
    for (;;) {
        struct relay *r, *n;

        /* Do work. */
        LIST_FOR_EACH_SAFE (r, n, struct relay, node, &relays) {
            relay_run(r);
        }
        if (listen_vconn) {
            struct vconn *new_remote;
            for (;;) {
                retval = vconn_accept(listen_vconn, &new_remote);
                if (retval) {
                    if (retval != EAGAIN) {
                        VLOG_WARN("accept failed (%s)", strerror(retval));
                    }
                    break;
                }

                new_management_connection(nl_name, new_remote);
            }
        }

        /* Wait for something to happen. */
        LIST_FOR_EACH (r, struct relay, node, &relays) {
            relay_wait(r);
        }
        if (listen_vconn) {
            vconn_accept_wait(listen_vconn);
        }
        poll_block();
    }

    return 0;
}

static void
new_management_connection(const char *nl_name, struct vconn *new_remote)
{
    char *nl_name_without_subscription;
    struct vconn *new_local;
    struct rconn *r1, *r2;
    int retval;

    /* nl:123 or nl:123:1 opens a netlink connection to local datapath 123.  We
     * only accept the former syntax in main().
     *
     * nl:123:0 opens a netlink connection to local datapath 123 without
     * obtaining a subscription for ofp_packet_in or ofp_flow_expired
     * messages.*/
    nl_name_without_subscription = xasprintf("%s:0", nl_name);
    retval = vconn_open(nl_name_without_subscription, &new_local);
    if (retval) {
        VLOG_ERR("could not connect to %s (%s)",
                 nl_name_without_subscription, strerror(retval));
        vconn_close(new_remote);
        return;
    }
    free(nl_name_without_subscription);

    /* Add it to the relay list. */
    r1 = rconn_new_from_vconn(nl_name_without_subscription, 1, new_local);
    r2 = rconn_new_from_vconn("passive", 1, new_remote);
    relay_create(r1, r2);
}

static void
relay_create(struct rconn *a, struct rconn *b)
{
    struct relay *r;
    int i;

    r = xmalloc(sizeof *r);
    for (i = 0; i < 2; i++) {
        r->halves[i].rconn = i ? b : a;
        r->halves[i].rxbuf = NULL;
    }
    list_push_back(&relays, &r->node);
}

static void
relay_run(struct relay *r)
{
    int iteration;
    int i;

    for (i = 0; i < 2; i++) {
        rconn_run(r->halves[i].rconn);
    }

    /* Limit the number of iterations to prevent other tasks from starving. */
    for (iteration = 0; iteration < 50; iteration++) {
        bool progress = false;
        for (i = 0; i < 2; i++) {
            struct half *this = &r->halves[i];
            struct half *peer = &r->halves[!i];

            if (!this->rxbuf) {
                this->rxbuf = rconn_recv(this->rconn);
            }

            if (this->rxbuf) {
                int retval = rconn_send(peer->rconn, this->rxbuf);
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

    for (i = 0; i < 2; i++) {
        struct half *this = &r->halves[i];
        if (!rconn_is_alive(this->rconn)) {
            relay_destroy(r);
            return;
        }
    }
}

static void
relay_wait(struct relay *r)
{
    int i;

    for (i = 0; i < 2; i++) {
        struct half *this = &r->halves[i];

        rconn_run_wait(this->rconn);
        if (!this->rxbuf) {
            rconn_recv_wait(this->rconn);
        }
    }
}

static void
relay_destroy(struct relay *r)
{
    int i;

    list_remove(&r->node);
    for (i = 0; i < 2; i++) {
        struct half *this = &r->halves[i];
        rconn_destroy(this->rconn);
        buffer_delete(this->rxbuf);
    }
    free(r);
}

static void
parse_options(int argc, char *argv[]) 
{
    static struct option long_options[] = {
        {"listen",      required_argument, 0, 'l'},
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
        int retval;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'l':
            if (listen_vconn) {
                fatal(0, "-l or --listen may be only specified once");
            }
            retval = vconn_open(optarg, &listen_vconn);
            if (retval && retval != EAGAIN) {
                fatal(retval, "opening %s", optarg);
            }
            if (!vconn_is_passive(listen_vconn)) {
                fatal(0, "%s is not a passive vconn", optarg);
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
    printf("%s: Secure Channel, a relay for OpenFlow messages.\n"
           "usage: %s [OPTIONS] LOCAL REMOTE\n"
           "where LOCAL and REMOTE are active OpenFlow connection methods.\n",
           program_name, program_name);
    vconn_usage(true, true);
    printf("\nNetworking options:\n"
           "  -l, --listen=METHOD     allow management connections on METHOD\n"
           "                          (a passive OpenFlow connection method)\n"
           "\nOther options:\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
