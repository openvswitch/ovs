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

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "buffer.h"
#include "command-line.h"
#include "compiler.h"
#include "fault.h"
#include "flow.h"
#include "hash.h"
#include "list.h"
#include "ofp-print.h"
#include "mac-learning.h"
#include "openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "queue.h"
#include "time.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "vlog-socket.h"
#include "xtoxll.h"

#include "vlog.h"
#define THIS_MODULE VLM_controller

#define MAX_SWITCHES 16
#define MAX_TXQ 128

struct switch_ {
    char *name;
    struct vconn *vconn;

    uint64_t datapath_id;
    time_t last_features_request;

    struct queue txq;
    struct mac_learning *ml;
};

/* Learn the ports on which MAC addresses appear? */
static bool learn_macs = true;

/* Set up flows?  (If not, every packet is processed at the controller.) */
static bool setup_flows = true;

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static struct switch_ *connect_switch(const char *name);
static struct switch_ *new_switch(const char *name, struct vconn *);
static void close_switch(struct switch_ *);

static void queue_tx(struct switch_ *, struct buffer *);

static void send_features_request(struct switch_ *);

static int do_switch_recv(struct switch_ *this);
static int do_switch_send(struct switch_ *this);

static void process_packet(struct switch_ *, struct buffer *);
static void process_packet_in(struct switch_ *, struct ofp_packet_in *);

int
main(int argc, char *argv[])
{
    struct switch_ *switches[MAX_SWITCHES];
    int n_switches;
    int retval;
    int i;

    set_program_name(argv[0]);
    register_fault_handlers();
    vlog_init();
    parse_options(argc, argv);

    if (argc - optind < 1) {
        fatal(0, "at least one vconn argument required; use --help for usage");
    }

    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        fatal(retval, "Could not listen for vlog connections");
    }

    n_switches = 0;
    for (i = 0; i < argc - optind; i++) {
        struct switch_ *this = connect_switch(argv[optind + i]);
        if (this) {
            if (n_switches >= MAX_SWITCHES) {
                fatal(0, "max %d switch connections", n_switches);
            }
            switches[n_switches++] = this;
        }
    }
    if (n_switches == 0) {
        fatal(0, "could not connect to any switches");
    }

    while (n_switches > 0) {
        /* Do some work.  Limit the number of iterations so that callbacks
         * registered with the poll loop don't starve. */
        int iteration;
        int i;
        for (iteration = 0; iteration < 50; iteration++) {
            bool progress = false;
            for (i = 0; i < n_switches; ) {
                struct switch_ *this = switches[i];
                int retval;

                if (vconn_is_passive(this->vconn)) {
                    retval = 0;
                    while (n_switches < MAX_SWITCHES) {
                        struct vconn *new_vconn;
                        retval = vconn_accept(this->vconn, &new_vconn);
                        if (retval) {
                            break;
                        }
                        switches[n_switches++] = new_switch("tcp", new_vconn);
                    }
                } else {
                    retval = do_switch_recv(this);
                    if (!retval || retval == EAGAIN) {
                        do {
                            retval = do_switch_send(this);
                            if (!retval) {
                                progress = true;
                            }
                        } while (!retval);
                    }
                }

                if (retval && retval != EAGAIN) {
                    close_switch(this);
                    switches[i] = switches[--n_switches];
                } else {
                    i++;
                }
            }
            if (!progress) {
                break;
            }
        }

        /* Wait for something to happen. */
        for (i = 0; i < n_switches; i++) {
            struct switch_ *this = switches[i];
            if (vconn_is_passive(this->vconn)) {
                if (n_switches < MAX_SWITCHES) {
                    vconn_accept_wait(this->vconn);
                }
            } else {
                vconn_recv_wait(this->vconn);
                if (this->txq.n) {
                    vconn_send_wait(this->vconn);
                }
            }
        }
        poll_block();
    }

    return 0;
}

static int
do_switch_recv(struct switch_ *this) 
{
    struct buffer *msg;
    int retval;

    retval = vconn_recv(this->vconn, &msg);
    if (!retval) {
        process_packet(this, msg);
        buffer_delete(msg);
    }
    return retval;
}

static int
do_switch_send(struct switch_ *this) 
{
    int retval = 0;
    if (this->txq.n) {
        struct buffer *next = this->txq.head->next;
        retval = vconn_send(this->vconn, this->txq.head);
        if (retval) {
            return retval;
        }
        queue_advance_head(&this->txq, next);
        return 0;
    }
    return EAGAIN;
}

struct switch_ *
connect_switch(const char *name) 
{
    struct vconn *vconn;
    int retval;

    retval = vconn_open(name, &vconn);
    if (retval) {
        VLOG_ERR("%s: connect: %s", name, strerror(retval));
        return NULL;
    }

    return new_switch(name, vconn);
}

static struct switch_ *
new_switch(const char *name, struct vconn *vconn) 
{
    struct switch_ *this = xmalloc(sizeof *this);
    memset(this, 0, sizeof *this);
    this->name = xstrdup(name);
    this->vconn = vconn;
    queue_init(&this->txq);
    this->last_features_request = 0;
    if (!vconn_is_passive(vconn)) {
        send_features_request(this);
    }
    if (learn_macs) {
        this->ml = mac_learning_create(); 
    }
    return this;
}

static void
close_switch(struct switch_ *this) 
{
    if (this) {
        free(this->name);
        vconn_close(this->vconn);
        queue_destroy(&this->txq);
        mac_learning_destroy(this->ml);
        free(this);
    }
}

static void
send_features_request(struct switch_ *this)
{
    time_t now = time(0);
    if (now >= this->last_features_request + 1) {
        struct buffer *b;
        struct ofp_header *ofr;
        struct ofp_switch_config *osc;

        /* Send OFPT_FEATURES_REQUEST. */
        b = buffer_new(0);
        ofr = buffer_put_uninit(b, sizeof *ofr);
        memset(ofr, 0, sizeof *ofr);
        ofr->type = OFPT_FEATURES_REQUEST;
        ofr->version = OFP_VERSION;
        ofr->length = htons(sizeof *ofr);
        queue_tx(this, b);

        /* Send OFPT_SET_CONFIG. */
        b = buffer_new(0);
        osc = buffer_put_uninit(b, sizeof *osc);
        memset(osc, 0, sizeof *osc);
        osc->header.type = OFPT_SET_CONFIG;
        osc->header.version = OFP_VERSION;
        osc->header.length = htons(sizeof *osc);
        osc->flags = htons(OFPC_SEND_FLOW_EXP);
        osc->miss_send_len = htons(OFP_DEFAULT_MISS_SEND_LEN);
        queue_tx(this, b);

        this->last_features_request = now;
    }
}

static void
queue_tx(struct switch_ *this, struct buffer *b) 
{
    queue_push_tail(&this->txq, b);
}

static void
process_packet(struct switch_ *sw, struct buffer *msg) 
{
    static const size_t min_size[UINT8_MAX + 1] = {
        [0 ... UINT8_MAX] = sizeof (struct ofp_header),
        [OFPT_FEATURES_REPLY] = sizeof (struct ofp_switch_features),
        [OFPT_PACKET_IN] = offsetof (struct ofp_packet_in, data),
    };
    struct ofp_header *oh;

    oh = msg->data;
    if (msg->size < min_size[oh->type]) {
        VLOG_WARN("%s: too short (%zu bytes) for type %"PRIu8" (min %zu)",
                  sw->name, msg->size, oh->type, min_size[oh->type]);
        return;
    }

    if (oh->type == OFPT_FEATURES_REPLY) {
        struct ofp_switch_features *osf = msg->data;
        sw->datapath_id = osf->datapath_id;
    } else if (sw->datapath_id == 0) {
        send_features_request(sw);
    } else if (oh->type == OFPT_PACKET_IN) {
        struct ofp_packet_in *opi = msg->data;
        if (sw->txq.n >= MAX_TXQ) {
            /* FIXME: ratelimit. */
            VLOG_WARN("%s: tx queue overflow", sw->name);
        } else {
            process_packet_in(sw, opi);
        }
    } else {
        ofp_print(stdout, msg->data, msg->size, 2); 
    }
}

static void
process_packet_in(struct switch_ *sw, struct ofp_packet_in *opi) 
{
    uint16_t in_port = ntohs(opi->in_port);
    uint16_t out_port = OFPP_FLOOD;

    size_t pkt_ofs, pkt_len;
    struct buffer pkt;
    struct flow flow;

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    pkt.data = opi->data;
    pkt.size = pkt_len;
    flow_extract(&pkt, in_port, &flow);

    if (learn_macs) {
        if (mac_learning_learn(sw->ml, flow.dl_src, in_port)) {
            VLOG_DBG("learned that "ETH_ADDR_FMT" is on datapath %"
                     PRIx64" port %"PRIu16, ETH_ADDR_ARGS(flow.dl_src),
                     ntohll(sw->datapath_id), in_port);
        }
        out_port = mac_learning_lookup(sw->ml, flow.dl_dst);
    }

    if (setup_flows && (!learn_macs || out_port != OFPP_FLOOD)) {
        /* The output port is known, or we always flood everything, so add a
         * new flow. */
        queue_tx(sw, make_add_simple_flow(&flow, ntohl(opi->buffer_id),
                                          out_port));

        /* If the switch didn't buffer the packet, we need to send a copy. */
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            queue_tx(sw, make_unbuffered_packet_out(&pkt, in_port, out_port));
        }
    } else {
        /* We don't know that MAC, or we don't set up flows.  Send along the
         * packet without setting up a flow. */
        struct buffer *b;
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            b = make_unbuffered_packet_out(&pkt, in_port, out_port);
        } else {
            b = make_buffered_packet_out(ntohl(opi->buffer_id),
                                         in_port, out_port);
        }
        queue_tx(sw, b);
    }
}

static void
parse_options(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"hub",         no_argument, 0, 'H'},
        {"noflow",      no_argument, 0, 'n'},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        VCONN_SSL_LONG_OPTIONS
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
        case 'H':
            learn_macs = false;
            break;

        case 'n':
            setup_flows = false;
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
    printf("%s: OpenFlow controller\n"
           "usage: %s [OPTIONS] METHOD\n"
           "where METHOD is any OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, true);
    printf("\nOther options:\n"
           "  -H, --hub               act as hub instead of learning switch\n"
           "  -n, --noflow            pass traffic, but don't add flows\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
