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
#include "mac.h"
#include "ofp-print.h"
#include "openflow.h"
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
    struct pollfd *pollfd;

    uint64_t datapath_id;
    time_t last_control_hello;

    int n_txq;
    struct buffer *txq, *tx_tail;
};

/* -H, --hub: Use dumb hub instead of learning switch? */
static bool hub = false;

/* -n, --noflow: Pass traffic, but don't setup flows in switch */
static bool noflow = false;

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static struct switch_ *connect_switch(const char *name);
static struct switch_ *new_switch(const char *name, struct vconn *);
static void close_switch(struct switch_ *);

static void queue_tx(struct switch_ *, struct buffer *);

static void send_control_hello(struct switch_ *);

static int do_switch_recv(struct switch_ *this);
static int do_switch_send(struct switch_ *this);

static void process_packet(struct switch_ *, struct buffer *);
static void process_hub(struct switch_ *, struct ofp_packet_in *);
static void process_noflow(struct switch_ *, struct ofp_packet_in *);

static void switch_init(void);
static void process_switch(struct switch_ *, struct ofp_packet_in *);

int
main(int argc, char *argv[])
{
    struct switch_ *switches[MAX_SWITCHES];
    struct pollfd pollfds[MAX_SWITCHES + 1];
    struct vlog_server *vlog_server;
    int n_switches;
    int retval;
    int i;

    set_program_name(argv[0]);
    register_fault_handlers();
    vlog_init();
    parse_options(argc, argv);

    if (!hub && !noflow) {
        switch_init();
    }

    if (argc - optind < 1) {
        fatal(0, "at least one vconn argument required; use --help for usage");
    }

    retval = vlog_server_listen(NULL, &vlog_server);
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
        size_t n_ready;
        int retval;

        /* Wait until there's something to do. */
        n_ready = 0;
        for (i = 0; i < n_switches; i++) {
            struct switch_ *this = switches[i];
            int want;

            if (vconn_is_passive(this->vconn)) {
                want = n_switches < MAX_SWITCHES ? WANT_ACCEPT : 0;
            } else {
                want = WANT_RECV;
                if (this->n_txq) {
                    want |= WANT_SEND;
                }
            }

            this->pollfd = &pollfds[i];
            this->pollfd->fd = -1;
            this->pollfd->events = 0;
            n_ready += vconn_prepoll(this->vconn, want, this->pollfd);
        }
        if (vlog_server) {
            pollfds[n_switches].fd = vlog_server_get_fd(vlog_server);
            pollfds[n_switches].events = POLLIN;
        }
        do {
            retval = poll(pollfds, n_switches + (vlog_server != NULL),
                          n_ready ? 0 : -1);
        } while (retval < 0 && errno == EINTR);
        if (retval < 0 || (retval == 0 && !n_ready)) {
            fatal(retval < 0 ? errno : 0, "poll");
        }

        /* Let each connection deal with any pending operations. */
        for (i = 0; i < n_switches; i++) {
            struct switch_ *this = switches[i];
            vconn_postpoll(this->vconn, &this->pollfd->revents);
            if (this->pollfd->revents & POLLERR) {
                this->pollfd->revents |= POLLIN | POLLOUT;
            }
        }
        if (vlog_server && pollfds[n_switches].revents) {
            vlog_server_poll(vlog_server);
        }

        for (i = 0; i < n_switches; ) {
            struct switch_ *this = switches[i];

            if (this->pollfd) {
                retval = 0;
                if (vconn_is_passive(this->vconn)) {
                    if (this->pollfd->revents & POLLIN) {
                        struct vconn *new_vconn;
                        while (n_switches < MAX_SWITCHES 
                               && (retval = vconn_accept(this->vconn,
                                                         &new_vconn)) == 0) {
                            switches[n_switches++] = new_switch("tcp",
                                                                new_vconn);
                        }
                    }
                } else {
                    bool may_read = this->pollfd->revents & POLLIN;
                    bool may_write = this->pollfd->revents & POLLOUT;
                    if (may_read) {
                        retval = do_switch_recv(this);
                        if (!retval || retval == EAGAIN) {
                            retval = 0;

                            /* Enable writing to avoid round trip through poll
                             * in common case. */
                            may_write = true;
                        }
                    }
                    while ((!retval || retval == EAGAIN) && may_write) {
                        retval = do_switch_send(this);
                        may_write = !retval;
                    }
                }

                if (retval && retval != EAGAIN) {
                    close_switch(this);
                    switches[i] = switches[--n_switches];
                    continue;
                }
            } else {
                /* New switch that hasn't been polled yet. */
            }
            i++;
        }
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
    if (this->n_txq) {
        struct buffer *next = this->txq->next;

        retval = vconn_send(this->vconn, this->txq);
        if (retval) {
            return retval;
        }

        this->txq = next;
        if (this->txq == NULL) {
            this->tx_tail = NULL;
        }
        this->n_txq--;
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
    this->pollfd = NULL;
    this->n_txq = 0;
    this->txq = NULL;
    this->tx_tail = NULL;
    this->last_control_hello = 0;
    if (!vconn_is_passive(vconn)) {
        send_control_hello(this);
    }
    return this;
}

static void
close_switch(struct switch_ *this) 
{
    if (this) {
        struct buffer *cur, *next;

        free(this->name);
        vconn_close(this->vconn);
        for (cur = this->txq; cur != NULL; cur = next) {
            next = cur->next;
            buffer_delete(cur);
        }
        free(this);
    }
}

static void
send_control_hello(struct switch_ *this)
{
    time_t now = time(0);
    if (now >= this->last_control_hello + 1) {
        struct buffer *b;
        struct ofp_control_hello *och;

        b = buffer_new(0);
        och = buffer_put_uninit(b, sizeof *och);
        memset(och, 0, sizeof *och);
        och->header.version = OFP_VERSION;
        och->header.length = htons(sizeof *och);

        och->version = htonl(OFP_VERSION);
        och->flags = htons(OFP_CHELLO_SEND_FLOW_EXP);
        och->miss_send_len = htons(OFP_DEFAULT_MISS_SEND_LEN);
        queue_tx(this, b);

        this->last_control_hello = now;
    }
}

static void
check_txq(struct switch_ *this UNUSED)
{
#if 0
    struct buffer *iter;
    size_t n;

    assert(this->n_txq == 0
           ? this->txq == NULL && this->tx_tail == NULL
           : this->txq != NULL && this->tx_tail != NULL);

    n = 0;
    for (iter = this->txq; iter != NULL; iter = iter->next) {
        n++;
        assert((iter->next != NULL) == (iter != this->tx_tail));
    }
    assert(n == this->n_txq);
#endif
}

static void
queue_tx(struct switch_ *this, struct buffer *b) 
{
    check_txq(this);

    b->next = NULL;
    if (this->n_txq++) {
        this->tx_tail->next = b;
    } else {
        this->txq = b;
    }
    this->tx_tail = b;

    check_txq(this);
}

static void
process_packet(struct switch_ *sw, struct buffer *msg) 
{
    static const size_t min_size[UINT8_MAX + 1] = {
        [0 ... UINT8_MAX] = SIZE_MAX,
        [OFPT_CONTROL_HELLO] = sizeof (struct ofp_control_hello),
        [OFPT_DATA_HELLO] = sizeof (struct ofp_data_hello),
        [OFPT_PACKET_IN] = offsetof (struct ofp_packet_in, data),
        [OFPT_PACKET_OUT] = sizeof (struct ofp_packet_out),
        [OFPT_FLOW_MOD] = sizeof (struct ofp_flow_mod),
        [OFPT_FLOW_EXPIRED] = sizeof (struct ofp_flow_expired),
        [OFPT_TABLE] = sizeof (struct ofp_table),
        [OFPT_PORT_MOD] = sizeof (struct ofp_port_mod),
        [OFPT_PORT_STATUS] = sizeof (struct ofp_port_status),
        [OFPT_FLOW_STAT_REQUEST] = sizeof (struct ofp_flow_stat_request),
        [OFPT_FLOW_STAT_REPLY] = sizeof (struct ofp_flow_stat_reply),
    };
    struct ofp_header *oh;

    oh = msg->data;
    if (msg->size < min_size[oh->type]) {
        VLOG_WARN("%s: too short (%zu bytes) for type %"PRIu8" (min %zu)",
                  sw->name, msg->size, oh->type, min_size[oh->type]);
        return;
    }

    if (oh->type == OFPT_DATA_HELLO) {
        struct ofp_data_hello *odh = msg->data;
        sw->datapath_id = odh->datapath_id;
    } else if (sw->datapath_id == 0) {
        send_control_hello(sw);
        return;
    }

    if (oh->type == OFPT_PACKET_IN) {
        if (sw->n_txq >= MAX_TXQ) {
            VLOG_WARN("%s: tx queue overflow", sw->name);
        } else if (noflow) {
            process_noflow(sw, msg->data);
        } else if (hub) {
            process_hub(sw, msg->data);
        } else {
            process_switch(sw, msg->data);
        }
        return;
    }

    ofp_print(stdout, msg->data, msg->size, 2);
}

static void
process_hub(struct switch_ *sw, struct ofp_packet_in *opi)
{
    size_t pkt_ofs, pkt_len;
    struct buffer pkt;
    struct flow flow;

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    pkt.data = opi->data;
    pkt.size = pkt_len;
    flow_extract(&pkt, ntohs(opi->in_port), &flow);

    /* Add new flow. */
    queue_tx(sw, make_add_simple_flow(&flow, ntohl(opi->buffer_id),
                                      OFPP_FLOOD));

    /* If the switch didn't buffer the packet, we need to send a copy. */
    if (ntohl(opi->buffer_id) == UINT32_MAX) {
        queue_tx(sw, make_unbuffered_packet_out(&pkt, ntohs(flow.in_port),
                                                OFPP_FLOOD));
    }
}

static void
process_noflow(struct switch_ *sw, struct ofp_packet_in *opi)
{
    /* If the switch didn't buffer the packet, we need to send a copy. */
    if (ntohl(opi->buffer_id) == UINT32_MAX) {
        size_t pkt_ofs, pkt_len;
        struct buffer pkt;

        /* Extract flow data from 'opi' into 'flow'. */
        pkt_ofs = offsetof(struct ofp_packet_in, data);
        pkt_len = ntohs(opi->header.length) - pkt_ofs;
        pkt.data = opi->data;
        pkt.size = pkt_len;

        queue_tx(sw, make_unbuffered_packet_out(&pkt, ntohs(opi->in_port),
                    OFPP_FLOOD));
    } else {
        queue_tx(sw, make_buffered_packet_out(ntohl(opi->buffer_id), 
                    ntohs(opi->in_port), OFPP_FLOOD));
    }
}


#define MAC_HASH_BITS 10
#define MAC_HASH_MASK (MAC_HASH_SIZE - 1)
#define MAC_HASH_SIZE (1u << MAC_HASH_BITS)

#define MAC_MAX 1024

struct mac_source {
    struct list hash_list;
    struct list lru_list;
    uint64_t datapath_id;
    uint8_t mac[ETH_ADDR_LEN];
    uint16_t port;
};

static struct list mac_table[MAC_HASH_SIZE];
static struct list lrus;
static size_t mac_count;

static void
switch_init(void)
{
    int i;

    list_init(&lrus);
    for (i = 0; i < MAC_HASH_SIZE; i++) {
        list_init(&mac_table[i]);
    }
}

static struct list *
mac_table_bucket(uint64_t datapath_id, const uint8_t mac[ETH_ADDR_LEN]) 
{
    uint32_t hash;
    hash = hash_fnv(&datapath_id, sizeof datapath_id, HASH_FNV_BASIS);
    hash = hash_fnv(mac, ETH_ADDR_LEN, hash);
    return &mac_table[hash & MAC_HASH_BITS];
}

static void
process_switch(struct switch_ *sw, struct ofp_packet_in *opi)
{
    size_t pkt_ofs, pkt_len;
    struct buffer pkt;
    struct flow flow;

    uint16_t out_port;

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    pkt.data = opi->data;
    pkt.size = pkt_len;
    flow_extract(&pkt, ntohs(opi->in_port), &flow);

    /* Learn the source. */
    if (!mac_is_multicast(flow.dl_src)) {
        struct mac_source *src;
        struct list *bucket;
        bool found;

        bucket = mac_table_bucket(sw->datapath_id, flow.dl_src);
        found = false;
        LIST_FOR_EACH (src, struct mac_source, hash_list, bucket) {
            if (src->datapath_id == sw->datapath_id
                && mac_equals(src->mac, flow.dl_src)) {
                found = true;
                break;
            }
        }

        if (!found) {
            /* Learn a new address. */

            if (mac_count >= MAC_MAX) {
                /* Drop the least recently used mac source. */
                struct mac_source *lru;
                lru = CONTAINER_OF(lrus.next, struct mac_source, lru_list);
                list_remove(&lru->hash_list);
                list_remove(&lru->lru_list);
                free(lru);
            } else {
                mac_count++;
            }

            /* Create new mac source */
            src = xmalloc(sizeof *src);
            src->datapath_id = sw->datapath_id;
            memcpy(src->mac, flow.dl_src, ETH_ADDR_LEN);
            src->port = -1;
            list_push_front(bucket, &src->hash_list);
            list_push_back(&lrus, &src->lru_list);
        } else {
            /* Make 'src' most-recently-used.  */
            list_remove(&src->lru_list);
            list_push_back(&lrus, &src->lru_list);
        }

        if (ntohs(flow.in_port) != src->port) {
            src->port = ntohs(flow.in_port);
            VLOG_DBG("learned that "MAC_FMT" is on datapath %"PRIx64" port %d",
                     MAC_ARGS(src->mac), ntohll(src->datapath_id),
                     src->port);
        }
    } else {
        VLOG_DBG("multicast packet source "MAC_FMT, MAC_ARGS(flow.dl_src));
    }

    /* Figure out the destination. */
    out_port = OFPP_FLOOD;
    if (!mac_is_multicast(flow.dl_dst)) {
        struct mac_source *dst;
        struct list *bucket;

        bucket = mac_table_bucket(sw->datapath_id, flow.dl_dst);
        LIST_FOR_EACH (dst, struct mac_source, hash_list, bucket) {
            if (dst->datapath_id == sw->datapath_id
                && mac_equals(dst->mac, flow.dl_dst)) {
                out_port = dst->port;
                break;
            }
        }
    }

    if (out_port != OFPP_FLOOD) {
        /* The output port is known, so add a new flow. */
        queue_tx(sw, make_add_simple_flow(&flow, ntohl(opi->buffer_id), 
                    out_port));

        /* If the switch didn't buffer the packet, we need to send a copy. */
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            queue_tx(sw, make_unbuffered_packet_out(&pkt, ntohs(flow.in_port),
                                                    out_port));
        }
    } else {
        /* We don't know that MAC.  Flood the packet. */
        struct buffer *b;
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            b = make_unbuffered_packet_out(&pkt, ntohs(flow.in_port), out_port);
        } else {
            b = make_buffered_packet_out(ntohl(opi->buffer_id), 
                        ntohs(flow.in_port), out_port);
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
        case 'H':
            hub = true;
            break;

        case 'n':
            noflow = true;
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
    printf("%s: OpenFlow controller\n"
           "usage: %s [OPTIONS] VCONN\n"
           "where VCONN is one of the following:\n"
           "  ptcp:[PORT]             listen to TCP PORT (default: %d)\n",
           program_name, program_name, OFP_TCP_PORT);
#ifdef HAVE_NETLINK
    printf("  nl:DP_IDX               via netlink to local datapath DP_IDX\n");
#endif
#ifdef HAVE_OPENSSL
    printf("  pssl:[PORT]             listen for SSL on PORT (default: %d)\n"
           "\nPKI configuration (required to use SSL):\n"
           "  -p, --private-key=FILE  file with private key\n"
           "  -c, --certificate=FILE  file with certificate for private key\n"
           "  -C, --ca-cert=FILE      file with peer CA certificate\n",
           OFP_SSL_PORT);
#endif
    printf("\nOther options:\n"
           "  -H, --hub               act as hub instead of learning switch\n"
           "  -n, --noflow            pass traffic, but don't add flows\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
