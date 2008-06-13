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
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "buffer.h"
#include "command-line.h"
#include "compiler.h"
#include "fault.h"
#include "flow.h"
#include "learning-switch.h"
#include "list.h"
#include "mac-learning.h"
#include "netdev.h"
#include "openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "rconn.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "vlog-socket.h"

#include "vlog.h"
#define THIS_MODULE VLM_secchan

#include "ofp-print.h"

static const char *listen_vconn_name;

struct half {
    struct rconn *rconn;
    struct buffer *rxbuf;
};

/* Behavior when the connection to the controller fails. */
enum fail_mode {
    FAIL_OPEN,                  /* Act as learning switch. */
    FAIL_CLOSED                 /* Drop all packets. */
};

struct relay {
    struct list node;

#define HALF_LOCAL 0
#define HALF_REMOTE 1
    struct half halves[2];

    bool is_mgmt_conn;
    struct lswitch *lswitch;
};

static struct list relays = LIST_INITIALIZER(&relays);

/* Enable the local port? */
static int local_port;

/* MAC address of local port. */
static uint8_t local_mac[ETH_ADDR_LEN];

/* MAC learning table for local port. */
static struct mac_learning *local_ml;

/* -f, --fail: Behavior when the connection to the controller fails. */
static enum fail_mode fail_mode = FAIL_OPEN;

/* -d, --fail-open-delay: Number of seconds after which to fail open, when
 * fail_mode is FAIL_OPEN. */
static int fail_open_delay = 30;

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static void new_management_connection(const char *nl_name, struct vconn *new_remote);
static struct relay *relay_create(struct rconn *local, struct rconn *remote,
                                  bool is_mgmt_conn);
static void relay_run(struct relay *);
static void relay_wait(struct relay *);
static void relay_destroy(struct relay *);

static bool local_hook(struct relay *r);
static bool fail_open_hook(struct relay *r);

int
main(int argc, char *argv[])
{
    struct vconn *listen_vconn;
    struct netdev *of_device;
    const char *nl_name;
    char of_name[16];
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

    if (listen_vconn_name) {
        retval = vconn_open(listen_vconn_name, &listen_vconn);
        if (retval && retval != EAGAIN) {
            fatal(retval, "opening %s", listen_vconn_name);
        }
        if (!vconn_is_passive(listen_vconn)) {
            fatal(0, "%s is not a passive vconn", listen_vconn_name);
        }
    } else {
        listen_vconn = NULL;
    }

    snprintf(of_name, sizeof of_name, "of%s", nl_name + 3);
    retval = netdev_open(of_name, &of_device);
    if (!retval) {
        enum netdev_flags flags;
        retval = netdev_get_flags(of_device, &flags);
        if (!retval) {
            if (flags & NETDEV_UP) {
                struct in6_addr in6;

                local_port = true;
                memcpy(local_mac, netdev_get_etheraddr(of_device),
                       ETH_ADDR_LEN);
                if (netdev_get_in6(of_device, &in6)) {
                    VLOG_WARN("Ignoring IPv6 address on %s device: "
                              "IPv6 not supported", of_name);
                }
                local_ml = mac_learning_create();
            }
        } else {
            error(retval, "Could not get flags for %s device", of_name);
        }
        netdev_close(of_device);
    } else {
        error(retval, "Could not open %s device", of_name);
    }

    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        fatal(retval, "Could not listen for vlog connections");
    }

    relay_create(rconn_new(argv[optind], 1), rconn_new(argv[optind + 1], 1),
                 false);
    for (;;) {
        struct relay *r, *n;

        /* Do work. */
        LIST_FOR_EACH_SAFE (r, n, struct relay, node, &relays) {
            relay_run(r);
        }
        if (listen_vconn) {
            for (;;) {
                struct vconn *new_remote;
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
        free(nl_name_without_subscription);
        return;
    }

    /* Add it to the relay list. */
    r1 = rconn_new_from_vconn(nl_name_without_subscription, 1, new_local);
    r2 = rconn_new_from_vconn("passive", 1, new_remote);
    relay_create(r1, r2, true);

    free(nl_name_without_subscription);
}

static struct relay *
relay_create(struct rconn *local, struct rconn *remote, bool is_mgmt_conn)
{
    struct relay *r;
    int i;

    r = xmalloc(sizeof *r);
    r->halves[HALF_LOCAL].rconn = local;
    r->halves[HALF_REMOTE].rconn = remote;
    for (i = 0; i < 2; i++) {
        r->halves[i].rxbuf = NULL;
    }
    r->is_mgmt_conn = is_mgmt_conn;
    r->lswitch = NULL;
    list_push_back(&relays, &r->node);
    return r;
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
                if (this->rxbuf && !r->is_mgmt_conn && i == HALF_LOCAL
                    && (local_hook(r) || fail_open_hook(r))) {
                    buffer_delete(this->rxbuf);
                    this->rxbuf = NULL;
                }
            }

            if (this->rxbuf) {
                int retval = rconn_send(peer->rconn, this->rxbuf);
                if (retval != EAGAIN) {
                    if (!retval) {
                        progress = true;
                    } else {
                        buffer_delete(this->rxbuf);
                    }
                    this->rxbuf = NULL;
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

static bool
local_hook(struct relay *r)
{
    struct rconn *rc = r->halves[HALF_LOCAL].rconn;
    struct buffer *msg = r->halves[HALF_LOCAL].rxbuf;
    struct ofp_packet_in *opi;
    struct ofp_header *oh;
    size_t pkt_ofs, pkt_len;
    struct buffer pkt, *b;
    struct flow flow;
    uint16_t in_port, out_port;

    if (!local_port) {
        return false;
    }

    oh = msg->data;
    if (oh->type != OFPT_PACKET_IN) {
        return false;
    }
    if (msg->size < offsetof (struct ofp_packet_in, data)) {
        VLOG_WARN("packet too short (%zu bytes) for packet_in", msg->size);
        return false;
    }

    /* Extract flow data from 'opi' into 'flow'. */
    opi = msg->data;
    in_port = ntohs(opi->in_port);
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    pkt.data = opi->data;
    pkt.size = pkt_len;
    flow_extract(&pkt, in_port, &flow);

    /* Deal with local stuff. */
    if (!rconn_is_connected(r->halves[HALF_REMOTE].rconn)
        && eth_addr_is_broadcast(flow.dl_dst)) {
        out_port = OFPP_FLOOD;
    } else if (in_port == OFPP_LOCAL) {
        out_port = mac_learning_lookup(local_ml, flow.dl_dst);
    } else if (eth_addr_equals(flow.dl_dst, local_mac)) {
        out_port = OFPP_LOCAL;
        if (mac_learning_learn(local_ml, flow.dl_src, in_port)) {
            VLOG_DBG("learned that "ETH_ADDR_FMT" is on port %"PRIu16,
                     ETH_ADDR_ARGS(flow.dl_src), in_port);
        }
    } else {
        return false;
    }

    /* Add new flow. */
    if (out_port != OFPP_FLOOD) {
        b = make_add_simple_flow(&flow, ntohl(opi->buffer_id), out_port);
        if (rconn_force_send(rc, b)) {
            buffer_delete(b);
        }
    }

    /* If the switch didn't buffer the packet, we need to send a copy. */
    if (out_port == OFPP_FLOOD || ntohl(opi->buffer_id) == UINT32_MAX) {
        b = make_unbuffered_packet_out(&pkt, in_port, out_port);
        if (rconn_force_send(rc, b)) {
            buffer_delete(b);
        }
    }
    return true;
}

static bool
fail_open_hook(struct relay *r)
{
    struct buffer *msg = r->halves[HALF_LOCAL].rxbuf;
    struct rconn *local = r->halves[HALF_LOCAL].rconn;
    struct rconn *remote = r->halves[HALF_REMOTE].rconn;
    int disconnected_duration;

    if (fail_mode == FAIL_CLOSED) {
        /* We fail closed, so there's never anything to do. */
        return false;
    }

    disconnected_duration = rconn_disconnected_duration(remote);
    if (disconnected_duration < fail_open_delay) {
        /* It's not time to fail open yet. */
        if (r->lswitch && rconn_is_connected(remote)) {
            /* We're connected, so drop the learning switch. */
            VLOG_WARN("No longer in fail-open mode");
            lswitch_destroy(r->lswitch);
            r->lswitch = NULL;
        }
        return false;
    }

    if (!r->lswitch) {
        VLOG_WARN("Could not connect to controller for %d seconds, "
                  "failing open", disconnected_duration);
        r->lswitch = lswitch_create(local, true, true);
    }

    /* Do switching. */
    lswitch_process_packet(r->lswitch, local, msg);
    rconn_run(local);
    return true;
}

static void
parse_options(int argc, char *argv[]) 
{
    static struct option long_options[] = {
        {"fail",        required_argument, 0, 'f'},
        {"fail-open-delay", required_argument, 0, 'd'},
        {"listen",      required_argument, 0, 'l'},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        VCONN_SSL_LONG_OPTIONS
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
        case 'f':
            if (!strcmp(optarg, "open")) {
                fail_mode = FAIL_OPEN;
            } else if (!strcmp(optarg, "closed")) {
                fail_mode = FAIL_CLOSED;
            } else {
                fatal(0,
                      "-f or --fail argument must be \"open\" or \"closed\"");
            }
            break;

        case 'd':
            fail_open_delay = atoi(optarg);
            if (fail_open_delay < 1) {
                fatal(0,
                      "-d or --fail-open-delay argument must be at least 1");
            }
            break;

        case 'l':
            if (listen_vconn_name) {
                fatal(0, "-l or --listen may be only specified once");
            }
            listen_vconn_name = optarg;
            break;

        case 'h':
            usage();

        case 'V':
            printf("%s "VERSION" compiled "__DATE__" "__TIME__"\n", argv[0]);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        VCONN_SSL_OPTION_HANDLERS

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
           "  -f, --fail=open|closed  when controller connection fails:\n"
           "                            closed: drop all packets\n"
           "                            open (default): act as learning switch\n"
           "  -d, --fail-open-delay=SECS  number of seconds after which to\n"
           "                          fail open if --fail=open (default: 30)\n"
           "  -l, --listen=METHOD     allow management connections on METHOD\n"
           "                          (a passive OpenFlow connection method)\n"
           "\nOther options:\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
