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

#include "datapath.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "chain.h"
#include "csum.h"
#include "flow.h"
#include "netdev.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "poll-loop.h"
#include "rconn.h"
#include "stp.h"
#include "switch-flow.h"
#include "table.h"
#include "vconn.h"
#include "xtoxll.h"
#include "nx_msg.h"
#include "dp_act.h"

#define THIS_MODULE VLM_datapath
#include "vlog.h"

extern char mfr_desc;
extern char hw_desc;
extern char sw_desc;
extern char serial_num;

/* Capabilities supported by this implementation. */
#define OFP_SUPPORTED_CAPABILITIES ( OFPC_FLOW_STATS \
        | OFPC_TABLE_STATS \
        | OFPC_PORT_STATS \
        | OFPC_MULTI_PHY_TX )

/* Actions supported by this implementation. */
#define OFP_SUPPORTED_ACTIONS ( (1 << OFPAT_OUTPUT)         \
                                | (1 << OFPAT_SET_VLAN_VID) \
                                | (1 << OFPAT_SET_VLAN_PCP) \
                                | (1 << OFPAT_STRIP_VLAN)   \
                                | (1 << OFPAT_SET_DL_SRC)   \
                                | (1 << OFPAT_SET_DL_DST)   \
                                | (1 << OFPAT_SET_NW_SRC)   \
                                | (1 << OFPAT_SET_NW_DST)   \
                                | (1 << OFPAT_SET_TP_SRC)   \
                                | (1 << OFPAT_SET_TP_DST) )

/* The origin of a received OpenFlow message, to enable sending a reply. */
struct sender {
    struct remote *remote;      /* The device that sent the message. */
    uint32_t xid;               /* The OpenFlow transaction ID. */
};

/* A connection to a secure channel. */
struct remote {
    struct list node;
    struct rconn *rconn;
#define TXQ_LIMIT 128           /* Max number of packets to queue for tx. */
    int n_txq;                  /* Number of packets queued for tx on rconn. */

    /* Support for reliable, multi-message replies to requests.
     *
     * If an incoming request needs to have a reliable reply that might
     * require multiple messages, it can use remote_start_dump() to set up
     * a callback that will be called as buffer space for replies. */
    int (*cb_dump)(struct datapath *, void *aux);
    void (*cb_done)(void *aux);
    void *cb_aux;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static struct remote *remote_create(struct datapath *, struct rconn *);
static void remote_run(struct datapath *, struct remote *);
static void remote_wait(struct remote *);
static void remote_destroy(struct remote *);

static void update_port_flags(struct datapath *, const struct ofp_port_mod *);
static int update_port_status(struct sw_port *p);
static void send_port_status(struct sw_port *p, uint8_t status);
static void del_switch_port(struct sw_port *p);

/* Buffers are identified by a 31-bit opaque ID.  We divide the ID
 * into a buffer number (low bits) and a cookie (high bits).  The buffer number
 * is an index into an array of buffers.  The cookie distinguishes between
 * different packets that have occupied a single buffer.  Thus, the more
 * buffers we have, the lower-quality the cookie... */
#define PKT_BUFFER_BITS 8
#define N_PKT_BUFFERS (1 << PKT_BUFFER_BITS)
#define PKT_BUFFER_MASK (N_PKT_BUFFERS - 1)

#define PKT_COOKIE_BITS (32 - PKT_BUFFER_BITS)

int run_flow_through_tables(struct datapath *, struct ofpbuf *,
                            struct sw_port *);
void fwd_port_input(struct datapath *, struct ofpbuf *, struct sw_port *);
int fwd_control_input(struct datapath *, const struct sender *,
                      const void *, size_t);

uint32_t save_buffer(struct ofpbuf *);
static struct ofpbuf *retrieve_buffer(uint32_t id);
static void discard_buffer(uint32_t id);

static struct sw_port *
lookup_port(struct datapath *dp, uint16_t port_no) 
{
    return (port_no < DP_MAX_PORTS ? &dp->ports[port_no]
            : port_no == OFPP_LOCAL ? dp->local_port
            : NULL);
}

/* Generates and returns a random datapath id. */
static uint64_t
gen_datapath_id(void)
{
    uint8_t ea[ETH_ADDR_LEN];
    eth_addr_random(ea);
    ea[0] = 0x00;               /* Set Nicira OUI. */
    ea[1] = 0x23;
    ea[2] = 0x20;
    return eth_addr_to_uint64(ea);
}

int
dp_new(struct datapath **dp_, uint64_t dpid)
{
    struct datapath *dp;

    dp = calloc(1, sizeof *dp);
    if (!dp) {
        return ENOMEM;
    }

    dp->last_timeout = time_now();
    list_init(&dp->remotes);
    dp->listeners = NULL;
    dp->n_listeners = 0;
    dp->id = dpid <= UINT64_C(0xffffffffffff) ? dpid : gen_datapath_id();
    dp->chain = chain_create(dp);
    if (!dp->chain) {
        VLOG_ERR("could not create chain");
        free(dp);
        return ENOMEM;
    }

    list_init(&dp->port_list);
    dp->flags = 0;
    dp->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;
    *dp_ = dp;
    return 0;
}

static int
new_port(struct datapath *dp, struct sw_port *port, uint16_t port_no,
         const char *netdev_name, const uint8_t *new_mac)
{
    struct netdev *netdev;
    struct in6_addr in6;
    struct in_addr in4;
    int error;

    error = netdev_open(netdev_name, NETDEV_ETH_TYPE_ANY, &netdev);
    if (error) {
        return error;
    }
    if (new_mac && !eth_addr_equals(netdev_get_etheraddr(netdev), new_mac)) {
        /* Generally the device has to be down before we change its hardware
         * address.  Don't bother to check for an error because it's really
         * the netdev_set_etheraddr() call below that we care about. */
        netdev_set_flags(netdev, 0, false);
        error = netdev_set_etheraddr(netdev, new_mac);
        if (error) {
            VLOG_WARN("failed to change %s Ethernet address "
                      "to "ETH_ADDR_FMT": %s",
                      netdev_name, ETH_ADDR_ARGS(new_mac), strerror(error));
        }
    }
    error = netdev_set_flags(netdev, NETDEV_UP | NETDEV_PROMISC, false);
    if (error) {
        VLOG_ERR("failed to set promiscuous mode on %s device", netdev_name);
        netdev_close(netdev);
        return error;
    }
    if (netdev_get_in4(netdev, &in4)) {
        VLOG_ERR("%s device has assigned IP address %s",
                 netdev_name, inet_ntoa(in4));
    }
    if (netdev_get_in6(netdev, &in6)) {
        char in6_name[INET6_ADDRSTRLEN + 1];
        inet_ntop(AF_INET6, &in6, in6_name, sizeof in6_name);
        VLOG_ERR("%s device has assigned IPv6 address %s",
                 netdev_name, in6_name);
    }

    memset(port, '\0', sizeof *port);

    port->dp = dp;
    port->netdev = netdev;
    port->port_no = port_no;
    list_push_back(&dp->port_list, &port->node);

    /* Notify the ctlpath that this port has been added */
    send_port_status(port, OFPPR_ADD);

    return 0;
}

int
dp_add_port(struct datapath *dp, const char *netdev)
{
    int port_no;
    for (port_no = 0; port_no < DP_MAX_PORTS; port_no++) {
        struct sw_port *port = &dp->ports[port_no];
        if (!port->netdev) {
            return new_port(dp, port, port_no, netdev, NULL);
        }
    }
    return EXFULL;
}

int
dp_add_local_port(struct datapath *dp, const char *netdev) 
{
    if (!dp->local_port) {
        uint8_t ea[ETH_ADDR_LEN];
        struct sw_port *port;
        int error;

        port = xcalloc(1, sizeof *port);
        eth_addr_from_uint64(dp->id, ea);
        error = new_port(dp, port, OFPP_LOCAL, netdev, ea);
        if (!error) {
            dp->local_port = port;
        } else {
            free(port);
        }
        return error;
    } else {
        return EXFULL;
    }
}

void
dp_add_pvconn(struct datapath *dp, struct pvconn *pvconn)
{
    dp->listeners = xrealloc(dp->listeners,
                             sizeof *dp->listeners * (dp->n_listeners + 1));
    dp->listeners[dp->n_listeners++] = pvconn;
}

void
dp_run(struct datapath *dp)
{
    time_t now = time_now();
    struct sw_port *p, *pn;
    struct remote *r, *rn;
    struct ofpbuf *buffer = NULL;
    size_t i;

    if (now != dp->last_timeout) {
        struct list deleted = LIST_INITIALIZER(&deleted);
        struct sw_flow *f, *n;

        LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
            if (update_port_status(p)) {
                send_port_status(p, OFPPR_MODIFY);
            }
        }

        chain_timeout(dp->chain, &deleted);
        LIST_FOR_EACH_SAFE (f, n, struct sw_flow, node, &deleted) {
            dp_send_flow_end(dp, f, f->reason);
            list_remove(&f->node);
            flow_free(f);
        }
        dp->last_timeout = now;
    }
    poll_timer_wait(1000);
    
    LIST_FOR_EACH_SAFE (p, pn, struct sw_port, node, &dp->port_list) {
        int error;

        if (!buffer) {
            /* Allocate buffer with some headroom to add headers in forwarding
             * to the controller or adding a vlan tag, plus an extra 2 bytes to
             * allow IP headers to be aligned on a 4-byte boundary.  */
            const int headroom = 128 + 2;
            const int hard_header = VLAN_ETH_HEADER_LEN;
            const int mtu = netdev_get_mtu(p->netdev);
            buffer = ofpbuf_new(headroom + hard_header + mtu);
            buffer->data = (char*)buffer->data + headroom;
        }
        error = netdev_recv(p->netdev, buffer);
        if (!error) {
            p->rx_packets++;
            p->rx_bytes += buffer->size;
            fwd_port_input(dp, buffer, p);
            buffer = NULL;
        } else if (error != EAGAIN) {
            VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                        netdev_get_name(p->netdev), strerror(error));
        }
    }
    ofpbuf_delete(buffer);

    /* Talk to remotes. */
    LIST_FOR_EACH_SAFE (r, rn, struct remote, node, &dp->remotes) {
        remote_run(dp, r);
    }

    for (i = 0; i < dp->n_listeners; ) {
        struct pvconn *pvconn = dp->listeners[i];
        struct vconn *new_vconn;
        int retval = pvconn_accept(pvconn, OFP_VERSION, &new_vconn);
        if (!retval) {
            remote_create(dp, rconn_new_from_vconn("passive", new_vconn));
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", strerror(retval));
            dp->listeners[i] = dp->listeners[--dp->n_listeners];
            continue;
        }
        i++;
    }
}

static void
remote_run(struct datapath *dp, struct remote *r)
{
    int i;

    rconn_run(r->rconn);

    /* Do some remote processing, but cap it at a reasonable amount so that
     * other processing doesn't starve. */
    for (i = 0; i < 50; i++) {
        if (!r->cb_dump) {
            struct ofpbuf *buffer;
            struct ofp_header *oh;

            buffer = rconn_recv(r->rconn);
            if (!buffer) {
                break;
            }

            if (buffer->size >= sizeof *oh) {
                struct sender sender;

                oh = buffer->data;
                sender.remote = r;
                sender.xid = oh->xid;
                fwd_control_input(dp, &sender, buffer->data, buffer->size);
            } else {
                VLOG_WARN_RL(&rl, "received too-short OpenFlow message");
            }
            ofpbuf_delete(buffer); 
        } else {
            if (r->n_txq < TXQ_LIMIT) {
                int error = r->cb_dump(dp, r->cb_aux);
                if (error <= 0) {
                    if (error) {
                        VLOG_WARN_RL(&rl, "dump callback error: %s",
                                     strerror(-error));
                    }
                    r->cb_done(r->cb_aux);
                    r->cb_dump = NULL;
                }
            } else {
                break;
            }
        }
    }

    if (!rconn_is_alive(r->rconn)) {
        remote_destroy(r);
    }
}

static void
remote_wait(struct remote *r) 
{
    rconn_run_wait(r->rconn);
    rconn_recv_wait(r->rconn);
}

static void
remote_destroy(struct remote *r)
{
    if (r) {
        if (r->cb_dump && r->cb_done) {
            r->cb_done(r->cb_aux);
        }
        list_remove(&r->node);
        rconn_destroy(r->rconn);
        free(r);
    }
}

static struct remote *
remote_create(struct datapath *dp, struct rconn *rconn) 
{
    struct remote *remote = xmalloc(sizeof *remote);
    list_push_back(&dp->remotes, &remote->node);
    remote->rconn = rconn;
    remote->cb_dump = NULL;
    remote->n_txq = 0;
    return remote;
}

/* Starts a callback-based, reliable, possibly multi-message reply to a
 * request made by 'remote'.
 *
 * 'dump' designates a function that will be called when the 'remote' send
 * queue has an empty slot.  It should compose a message and send it on
 * 'remote'.  On success, it should return 1 if it should be called again when
 * another send queue slot opens up, 0 if its transmissions are complete, or a
 * negative errno value on failure.
 *
 * 'done' designates a function to clean up any resources allocated for the
 * dump.  It must handle being called before the dump is complete (which will
 * happen if 'remote' is closed unexpectedly).
 *
 * 'aux' is passed to 'dump' and 'done'. */
static void
remote_start_dump(struct remote *remote,
                  int (*dump)(struct datapath *, void *),
                  void (*done)(void *),
                  void *aux) 
{
    assert(!remote->cb_dump);
    remote->cb_dump = dump;
    remote->cb_done = done;
    remote->cb_aux = aux;
}

void
dp_wait(struct datapath *dp) 
{
    struct sw_port *p;
    struct remote *r;
    size_t i;

    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        netdev_recv_wait(p->netdev);
    }
    LIST_FOR_EACH (r, struct remote, node, &dp->remotes) {
        remote_wait(r);
    }
    for (i = 0; i < dp->n_listeners; i++) {
        pvconn_wait(dp->listeners[i]);
    }
}

/* Delete 'p' from switch. */
static void
del_switch_port(struct sw_port *p)
{
    send_port_status(p, OFPPR_DELETE);
    netdev_close(p->netdev);
    p->netdev = NULL;
    list_remove(&p->node);
}

void
dp_destroy(struct datapath *dp)
{
    struct sw_port *p, *n;

    if (!dp) {
        return;
    }

    LIST_FOR_EACH_SAFE (p, n, struct sw_port, node, &dp->port_list) {
        del_switch_port(p); 
    }
    chain_destroy(dp->chain);
    free(dp);
}

/* Send packets out all the ports except the originating one.  If the
 * "flood" argument is set, don't send out ports with flooding disabled.
 */
static int
output_all(struct datapath *dp, struct ofpbuf *buffer, int in_port, int flood)
{
    struct sw_port *p;
    int prev_port;

    prev_port = -1;
    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        if (p->port_no == in_port) {
            continue;
        }
        if (flood && p->config & OFPPC_NO_FLOOD) {
            continue;
        }
        if (prev_port != -1) {
            dp_output_port(dp, ofpbuf_clone(buffer), in_port, prev_port,
                           false);
        }
        prev_port = p->port_no;
    }
    if (prev_port != -1)
        dp_output_port(dp, buffer, in_port, prev_port, false);
    else
        ofpbuf_delete(buffer);

    return 0;
}

void
output_packet(struct datapath *dp, struct ofpbuf *buffer, uint16_t out_port) 
{
    struct sw_port *p = lookup_port(dp, out_port);
    if (p && p->netdev != NULL) {
        if (!(p->config & OFPPC_PORT_DOWN)) {
            if (!netdev_send(p->netdev, buffer)) {
                p->tx_packets++;
                p->tx_bytes += buffer->size;
            } else {
                p->tx_dropped++;
            }
        }
        ofpbuf_delete(buffer);
        return;
    }

    ofpbuf_delete(buffer);
    VLOG_DBG_RL(&rl, "can't forward to bad port %d\n", out_port);
}

/* Takes ownership of 'buffer' and transmits it to 'out_port' on 'dp'.
 */
void
dp_output_port(struct datapath *dp, struct ofpbuf *buffer,
               int in_port, int out_port, bool ignore_no_fwd)
{

    assert(buffer);
    switch (out_port) {
    case OFPP_IN_PORT:
        output_packet(dp, buffer, in_port);
        break;

    case OFPP_TABLE: {
        struct sw_port *p = lookup_port(dp, in_port);
		if (run_flow_through_tables(dp, buffer, p)) {
			ofpbuf_delete(buffer);
        }
        break;
    }

    case OFPP_FLOOD:
        output_all(dp, buffer, in_port, 1);
        break;

    case OFPP_ALL:
        output_all(dp, buffer, in_port, 0);
        break;

    case OFPP_CONTROLLER:
        dp_output_control(dp, buffer, in_port, 0, OFPR_ACTION);
        break;

    case OFPP_LOCAL:
    default:
        if (in_port == out_port) {
            VLOG_DBG_RL(&rl, "can't directly forward to input port");
            return;
        }
        output_packet(dp, buffer, out_port);
        break;
    }
}

static void *
make_openflow_reply(size_t openflow_len, uint8_t type,
                    const struct sender *sender, struct ofpbuf **bufferp)
{
    return make_openflow_xid(openflow_len, type, sender ? sender->xid : 0,
                             bufferp);
}

static int
send_openflow_buffer_to_remote(struct ofpbuf *buffer, struct remote *remote)
{
    int retval = rconn_send_with_limit(remote->rconn, buffer, &remote->n_txq,
                                       TXQ_LIMIT);
    if (retval) {
        VLOG_WARN_RL(&rl, "send to %s failed: %s",
                     rconn_get_name(remote->rconn), strerror(retval));
    }
    return retval;
}

static int
send_openflow_buffer(struct datapath *dp, struct ofpbuf *buffer,
                     const struct sender *sender)
{
    update_openflow_length(buffer);
    if (sender) {
        /* Send back to the sender. */
        return send_openflow_buffer_to_remote(buffer, sender->remote);
    } else {
        /* Broadcast to all remotes. */
        struct remote *r, *prev = NULL;
        LIST_FOR_EACH (r, struct remote, node, &dp->remotes) {
            if (prev) {
                send_openflow_buffer_to_remote(ofpbuf_clone(buffer), prev);
            }
            prev = r;
        }
        if (prev) {
            send_openflow_buffer_to_remote(buffer, prev);
        } else {
            ofpbuf_delete(buffer);
        }
        return 0;
    }
}

/* Takes ownership of 'buffer' and transmits it to 'dp''s controller.  If the
 * packet can be saved in a buffer, then only the first max_len bytes of
 * 'buffer' are sent; otherwise, all of 'buffer' is sent.  'reason' indicates
 * why 'buffer' is being sent. 'max_len' sets the maximum number of bytes that
 * the caller wants to be sent; a value of 0 indicates the entire packet should
 * be sent. */
void
dp_output_control(struct datapath *dp, struct ofpbuf *buffer, int in_port,
                  size_t max_len, int reason)
{
    struct ofp_packet_in *opi;
    size_t total_len;
    uint32_t buffer_id;

    buffer_id = save_buffer(buffer);
    total_len = buffer->size;
    if (buffer_id != UINT32_MAX && max_len && buffer->size > max_len) {
        buffer->size = max_len;
    }

    opi = ofpbuf_push_uninit(buffer, offsetof(struct ofp_packet_in, data));
    opi->header.version = OFP_VERSION;
    opi->header.type    = OFPT_PACKET_IN;
    opi->header.length  = htons(buffer->size);
    opi->header.xid     = htonl(0);
    opi->buffer_id      = htonl(buffer_id);
    opi->total_len      = htons(total_len);
    opi->in_port        = htons(in_port);
    opi->reason         = reason;
    opi->pad            = 0;
    send_openflow_buffer(dp, buffer, NULL);
}

static void fill_port_desc(struct datapath *dp, struct sw_port *p,
                           struct ofp_phy_port *desc)
{
    desc->port_no = htons(p->port_no);
    strncpy((char *) desc->name, netdev_get_name(p->netdev),
            sizeof desc->name);
    desc->name[sizeof desc->name - 1] = '\0';
    memcpy(desc->hw_addr, netdev_get_etheraddr(p->netdev), ETH_ADDR_LEN);
    desc->config = htonl(p->config);
    desc->state = htonl(p->state);
    desc->curr = htonl(netdev_get_features(p->netdev, NETDEV_FEAT_CURRENT));
    desc->supported = htonl(netdev_get_features(p->netdev, 
                NETDEV_FEAT_SUPPORTED));
    desc->advertised = htonl(netdev_get_features(p->netdev, 
                NETDEV_FEAT_ADVERTISED));
    desc->peer = htonl(netdev_get_features(p->netdev, NETDEV_FEAT_PEER));
}

static void
dp_send_features_reply(struct datapath *dp, const struct sender *sender)
{
    struct ofpbuf *buffer;
    struct ofp_switch_features *ofr;
    struct sw_port *p;

    ofr = make_openflow_reply(sizeof *ofr, OFPT_FEATURES_REPLY,
                               sender, &buffer);
    ofr->datapath_id  = htonll(dp->id); 
    ofr->n_tables     = dp->chain->n_tables;
    ofr->n_buffers    = htonl(N_PKT_BUFFERS);
    ofr->capabilities = htonl(OFP_SUPPORTED_CAPABILITIES);
    ofr->actions      = htonl(OFP_SUPPORTED_ACTIONS);
    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        struct ofp_phy_port *opp = ofpbuf_put_uninit(buffer, sizeof *opp);
        memset(opp, 0, sizeof *opp);
        fill_port_desc(dp, p, opp);
    }
    send_openflow_buffer(dp, buffer, sender);
}

void
update_port_flags(struct datapath *dp, const struct ofp_port_mod *opm)
{
    struct sw_port *p = lookup_port(dp, ntohs(opm->port_no));

    /* Make sure the port id hasn't changed since this was sent */
    if (!p || memcmp(opm->hw_addr, netdev_get_etheraddr(p->netdev),
                     ETH_ADDR_LEN) != 0) {
        return;
    }


    if (opm->mask) {
        uint32_t config_mask = ntohl(opm->mask);
        p->config &= ~config_mask;
        p->config |= ntohl(opm->config) & config_mask;
    }

    if (opm->mask & htonl(OFPPC_PORT_DOWN)) {
        if ((opm->config & htonl(OFPPC_PORT_DOWN))
            && (p->config & OFPPC_PORT_DOWN) == 0) {
            p->config |= OFPPC_PORT_DOWN;
            netdev_turn_flags_off(p->netdev, NETDEV_UP, true);
        } else if ((opm->config & htonl(OFPPC_PORT_DOWN)) == 0
                   && (p->config & OFPPC_PORT_DOWN)) {
            p->config &= ~OFPPC_PORT_DOWN;
            netdev_turn_flags_on(p->netdev, NETDEV_UP, true);
        }
    }
}

/* Update the port status field of the bridge port.  A non-zero return
 * value indicates some field has changed. 
 *
 * NB: Callers of this function may hold the RCU read lock, so any
 * additional checks must not sleep.
 */
static int
update_port_status(struct sw_port *p)
{
    int retval;
    enum netdev_flags flags;
    uint32_t orig_config = p->config;
    uint32_t orig_state = p->state;

    if (netdev_get_flags(p->netdev, &flags) < 0) {
        VLOG_WARN_RL(&rl, "could not get netdev flags for %s", 
                     netdev_get_name(p->netdev));
        return 0;
    } else {
        if (flags & NETDEV_UP) {
            p->config &= ~OFPPC_PORT_DOWN;
        } else {
            p->config |= OFPPC_PORT_DOWN;
        } 
    }

    /* Not all cards support this getting link status, so don't warn on
     * error. */
    retval = netdev_get_link_status(p->netdev);
    if (retval == 1) {
        p->state &= ~OFPPS_LINK_DOWN;
    } else if (retval == 0) {
        p->state |= OFPPS_LINK_DOWN;
    } 

    return ((orig_config != p->config) || (orig_state != p->state));
}

static void
send_port_status(struct sw_port *p, uint8_t status) 
{
    struct ofpbuf *buffer;
    struct ofp_port_status *ops;
    ops = make_openflow_xid(sizeof *ops, OFPT_PORT_STATUS, 0, &buffer);
    ops->reason = status;
    memset(ops->pad, 0, sizeof ops->pad);
    fill_port_desc(p->dp, p, &ops->desc);

    send_openflow_buffer(p->dp, buffer, NULL);
}

void
dp_send_flow_end(struct datapath *dp, struct sw_flow *flow,
              enum nx_flow_end_reason reason)
{
    struct ofpbuf *buffer;
    struct nx_flow_end *nfe;

    if (!dp->send_flow_end) {
        return;
    }

    nfe = make_openflow_xid(sizeof *nfe, OFPT_VENDOR, 0, &buffer);
    if (!nfe) {
        return;
    }
    nfe->header.vendor = htonl(NX_VENDOR_ID);
    nfe->header.subtype = htonl(NXT_FLOW_END);

    flow_fill_match(&nfe->match, &flow->key);

    nfe->priority = htons(flow->priority);
    nfe->reason = reason;

    nfe->tcp_flags = flow->tcp_flags;
    nfe->ip_tos = flow->ip_tos;

    memset(nfe->pad, 0, sizeof nfe->pad);

    nfe->init_time = htonll(flow->created);
    nfe->used_time = htonll(flow->used);
    nfe->end_time = htonll(time_msec());

    nfe->packet_count = htonll(flow->packet_count);
    nfe->byte_count   = htonll(flow->byte_count);

    send_openflow_buffer(dp, buffer, NULL);
}

void
dp_send_error_msg(struct datapath *dp, const struct sender *sender,
                  uint16_t type, uint16_t code, const void *data, size_t len)
{
    struct ofpbuf *buffer;
    struct ofp_error_msg *oem;
    oem = make_openflow_reply(sizeof(*oem)+len, OFPT_ERROR, sender, &buffer);
    oem->type = htons(type);
    oem->code = htons(code);
    memcpy(oem->data, data, len);
    send_openflow_buffer(dp, buffer, sender);
}

static void
fill_flow_stats(struct ofpbuf *buffer, struct sw_flow *flow,
                int table_idx, uint64_t now)
{
    struct ofp_flow_stats *ofs;
    int length = sizeof *ofs + flow->sf_acts->actions_len;
    ofs = ofpbuf_put_uninit(buffer, length);
    ofs->length          = htons(length);
    ofs->table_id        = table_idx;
    ofs->pad             = 0;
    ofs->match.wildcards = htonl(flow->key.wildcards);
    ofs->match.in_port   = flow->key.flow.in_port;
    memcpy(ofs->match.dl_src, flow->key.flow.dl_src, ETH_ADDR_LEN);
    memcpy(ofs->match.dl_dst, flow->key.flow.dl_dst, ETH_ADDR_LEN);
    ofs->match.dl_vlan   = flow->key.flow.dl_vlan;
    ofs->match.dl_type   = flow->key.flow.dl_type;
    ofs->match.nw_src    = flow->key.flow.nw_src;
    ofs->match.nw_dst    = flow->key.flow.nw_dst;
    ofs->match.nw_proto  = flow->key.flow.nw_proto;
    ofs->match.pad       = 0;
    ofs->match.tp_src    = flow->key.flow.tp_src;
    ofs->match.tp_dst    = flow->key.flow.tp_dst;
    ofs->duration        = htonl((now - flow->created) / 1000);
    ofs->priority        = htons(flow->priority);
    ofs->idle_timeout    = htons(flow->idle_timeout);
    ofs->hard_timeout    = htons(flow->hard_timeout);
    memset(ofs->pad2, 0, sizeof ofs->pad2);
    ofs->packet_count    = htonll(flow->packet_count);
    ofs->byte_count      = htonll(flow->byte_count);
    memcpy(ofs->actions, flow->sf_acts->actions, flow->sf_acts->actions_len);
}


/* 'buffer' was received on 'p', which may be a a physical switch port or a
 * null pointer.  Process it according to 'dp''s flow table.  Returns 0 if
 * successful, in which case 'buffer' is destroyed, or -ESRCH if there is no
 * matching flow, in which case 'buffer' still belongs to the caller. */
int run_flow_through_tables(struct datapath *dp, struct ofpbuf *buffer,
                            struct sw_port *p)
{
    struct sw_flow_key key;
    struct sw_flow *flow;

    key.wildcards = 0;
    if (flow_extract(buffer, p ? p->port_no : OFPP_NONE, &key.flow)
        && (dp->flags & OFPC_FRAG_MASK) == OFPC_FRAG_DROP) {
        /* Drop fragment. */
        ofpbuf_delete(buffer);
        return 0;
    }
	if (p && p->config & (OFPPC_NO_RECV | OFPPC_NO_RECV_STP)
        && p->config & (!eth_addr_equals(key.flow.dl_dst, stp_eth_addr)
                       ? OFPPC_NO_RECV : OFPPC_NO_RECV_STP)) {
		ofpbuf_delete(buffer);
		return 0;
	}

    flow = chain_lookup(dp->chain, &key);
    if (flow != NULL) {
        flow_used(flow, buffer);
        execute_actions(dp, buffer, &key, flow->sf_acts->actions, 
                        flow->sf_acts->actions_len, false);
        return 0;
    } else {
        return -ESRCH;
    }
}

/* 'buffer' was received on 'p', which may be a a physical switch port or a
 * null pointer.  Process it according to 'dp''s flow table, sending it up to
 * the controller if no flow matches.  Takes ownership of 'buffer'. */
void fwd_port_input(struct datapath *dp, struct ofpbuf *buffer,
                    struct sw_port *p)
{
    if (run_flow_through_tables(dp, buffer, p)) {
        dp_output_control(dp, buffer, p->port_no,
                          dp->miss_send_len, OFPR_NO_MATCH);
    }
}

static int
recv_features_request(struct datapath *dp, const struct sender *sender,
                      const void *msg) 
{
    dp_send_features_reply(dp, sender);
    return 0;
}

static int
recv_get_config_request(struct datapath *dp, const struct sender *sender,
                        const void *msg) 
{
    struct ofpbuf *buffer;
    struct ofp_switch_config *osc;

    osc = make_openflow_reply(sizeof *osc, OFPT_GET_CONFIG_REPLY,
                              sender, &buffer);

    osc->flags = htons(dp->flags);
    osc->miss_send_len = htons(dp->miss_send_len);

    return send_openflow_buffer(dp, buffer, sender);
}

static int
recv_set_config(struct datapath *dp, const struct sender *sender UNUSED,
                const void *msg)
{
    const struct ofp_switch_config *osc = msg;
    int flags;

    flags = ntohs(osc->flags) & (OFPC_SEND_FLOW_EXP | OFPC_FRAG_MASK);
    if ((flags & OFPC_FRAG_MASK) != OFPC_FRAG_NORMAL
        && (flags & OFPC_FRAG_MASK) != OFPC_FRAG_DROP) {
        flags = (flags & ~OFPC_FRAG_MASK) | OFPC_FRAG_DROP;
    }
    dp->flags = flags;
    dp->miss_send_len = ntohs(osc->miss_send_len);
    return 0;
}

static int
recv_packet_out(struct datapath *dp, const struct sender *sender,
                const void *msg)
{
    const struct ofp_packet_out *opo = msg;
    struct sw_flow_key key;
    uint16_t v_code;
    struct ofpbuf *buffer;
    size_t actions_len = ntohs(opo->actions_len);

    if (actions_len > (ntohs(opo->header.length) - sizeof *opo)) {
        VLOG_DBG_RL(&rl, "message too short for number of actions");
        return -EINVAL;
    }

    if (ntohl(opo->buffer_id) == (uint32_t) -1) {
        /* FIXME: can we avoid copying data here? */
        int data_len = ntohs(opo->header.length) - sizeof *opo - actions_len;
        buffer = ofpbuf_new(data_len);
        ofpbuf_put(buffer, (uint8_t *)opo->actions + actions_len, data_len);
    } else {
        buffer = retrieve_buffer(ntohl(opo->buffer_id));
        if (!buffer) {
            return -ESRCH; 
        }
    }
 
    flow_extract(buffer, ntohs(opo->in_port), &key.flow);

    v_code = validate_actions(dp, &key, opo->actions, actions_len);
    if (v_code != ACT_VALIDATION_OK) {
        dp_send_error_msg(dp, sender, OFPET_BAD_ACTION, v_code,
                  msg, ntohs(opo->header.length));
        goto error;
    }

    execute_actions(dp, buffer, &key, opo->actions, actions_len, true);

    return 0;

error:
    ofpbuf_delete(buffer);
    return -EINVAL;
}

static int
recv_port_mod(struct datapath *dp, const struct sender *sender UNUSED,
              const void *msg)
{
    const struct ofp_port_mod *opm = msg;

    update_port_flags(dp, opm);

    return 0;
}

static int
add_flow(struct datapath *dp, const struct sender *sender,
        const struct ofp_flow_mod *ofm)
{
    int error = -ENOMEM;
    uint16_t v_code;
    struct sw_flow *flow; 
    size_t actions_len = ntohs(ofm->header.length) - sizeof *ofm;

    /* Allocate memory. */
    flow = flow_alloc(actions_len);
    if (flow == NULL)
        goto error;

    flow_extract_match(&flow->key, &ofm->match);

    v_code = validate_actions(dp, &flow->key, ofm->actions, actions_len);
    if (v_code != ACT_VALIDATION_OK) {
        dp_send_error_msg(dp, sender, OFPET_BAD_ACTION, v_code,
                  ofm, ntohs(ofm->header.length));
        goto error_free_flow;
    }

    /* Fill out flow. */
    flow->priority = flow->key.wildcards ? ntohs(ofm->priority) : -1;
    flow->idle_timeout = ntohs(ofm->idle_timeout);
    flow->hard_timeout = ntohs(ofm->hard_timeout);
    flow->used = flow->created = time_msec();
    flow->sf_acts->actions_len = actions_len;
    flow->byte_count = 0;
    flow->packet_count = 0;
    flow->tcp_flags = 0;
    flow->ip_tos = 0;
    memcpy(flow->sf_acts->actions, ofm->actions, actions_len);

    /* Act. */
    error = chain_insert(dp->chain, flow);
    if (error == -ENOBUFS) {
        dp_send_error_msg(dp, sender, OFPET_FLOW_MOD_FAILED, 
                OFPFMFC_ALL_TABLES_FULL, ofm, ntohs(ofm->header.length));
        goto error_free_flow;
    } else if (error) {
        goto error_free_flow; 
    }
    error = 0;
    if (ntohl(ofm->buffer_id) != UINT32_MAX) {
        struct ofpbuf *buffer = retrieve_buffer(ntohl(ofm->buffer_id));
        if (buffer) {
            struct sw_flow_key key;
            uint16_t in_port = ntohs(ofm->match.in_port);
            flow_extract(buffer, in_port, &key.flow);
            flow_used(flow, buffer);
            execute_actions(dp, buffer, &key, 
                    ofm->actions, actions_len, false);
        } else {
            error = -ESRCH; 
        }
    }
    return error;

error_free_flow:
    flow_free(flow);
error:
    if (ntohl(ofm->buffer_id) != (uint32_t) -1)
        discard_buffer(ntohl(ofm->buffer_id));
    return error;
}

static int
mod_flow(struct datapath *dp, const struct sender *sender,
        const struct ofp_flow_mod *ofm)
{
    int error = -ENOMEM;
    uint16_t v_code;
    size_t actions_len;
    struct sw_flow_key key;
    uint16_t priority;
    int strict;

    flow_extract_match(&key, &ofm->match);
 
    actions_len = ntohs(ofm->header.length) - sizeof *ofm;
 
    v_code = validate_actions(dp, &key, ofm->actions, actions_len);
    if (v_code != ACT_VALIDATION_OK) {
        dp_send_error_msg(dp, sender, OFPET_BAD_ACTION, v_code,
                  ofm, ntohs(ofm->header.length));
        goto error;
    }

    priority = key.wildcards ? ntohs(ofm->priority) : -1;
    strict = (ofm->command == htons(OFPFC_MODIFY_STRICT)) ? 1 : 0;
    chain_modify(dp->chain, &key, priority, strict, ofm->actions, actions_len);

    if (ntohl(ofm->buffer_id) != UINT32_MAX) {
        struct ofpbuf *buffer = retrieve_buffer(ntohl(ofm->buffer_id));
        if (buffer) {
            struct sw_flow_key skb_key;
            uint16_t in_port = ntohs(ofm->match.in_port);
            flow_extract(buffer, in_port, &skb_key.flow);
            execute_actions(dp, buffer, &skb_key,
                            ofm->actions, actions_len, false);
        } else {
            error = -ESRCH; 
        }
    }
    return error;

error:
    if (ntohl(ofm->buffer_id) != (uint32_t) -1)
        discard_buffer(ntohl(ofm->buffer_id));
    return error;
}

static int
recv_flow(struct datapath *dp, const struct sender *sender,
          const void *msg)
{
    const struct ofp_flow_mod *ofm = msg;
    uint16_t command = ntohs(ofm->command);

    if (command == OFPFC_ADD) {
        return add_flow(dp, sender, ofm);
    } else if ((command == OFPFC_MODIFY) || (command == OFPFC_MODIFY_STRICT)) {
        return mod_flow(dp, sender, ofm);
    }  else if (command == OFPFC_DELETE) {
        struct sw_flow_key key;
        flow_extract_match(&key, &ofm->match);
        return chain_delete(dp->chain, &key, ofm->out_port, 0, 0) ? 0 : -ESRCH;
    } else if (command == OFPFC_DELETE_STRICT) {
        struct sw_flow_key key;
        uint16_t priority;
        flow_extract_match(&key, &ofm->match);
        priority = key.wildcards ? ntohs(ofm->priority) : -1;
        return chain_delete(dp->chain, &key, ofm->out_port, 
                priority, 1) ? 0 : -ESRCH;
    } else {
        return -ENODEV;
    }
}

static int desc_stats_dump(struct datapath *dp, void *state,
                              struct ofpbuf *buffer)
{
    struct ofp_desc_stats *ods = ofpbuf_put_uninit(buffer, sizeof *ods);

    strncpy(ods->mfr_desc, &mfr_desc, sizeof ods->mfr_desc);
    strncpy(ods->hw_desc, &hw_desc, sizeof ods->hw_desc);
    strncpy(ods->sw_desc, &sw_desc, sizeof ods->sw_desc);
    strncpy(ods->serial_num, &serial_num, sizeof ods->serial_num);

    return 0;
}

struct flow_stats_state {
    int table_idx;
    struct sw_table_position position;
    struct ofp_flow_stats_request rq;
    uint64_t now;                  /* Current time in milliseconds */

    struct ofpbuf *buffer;
};

#define MAX_FLOW_STATS_BYTES 4096

static int flow_stats_init(struct datapath *dp, const void *body, int body_len,
                           void **state)
{
    const struct ofp_flow_stats_request *fsr = body;
    struct flow_stats_state *s = xmalloc(sizeof *s);
    s->table_idx = fsr->table_id == 0xff ? 0 : fsr->table_id;
    memset(&s->position, 0, sizeof s->position);
    s->rq = *fsr;
    *state = s;
    return 0;
}

static int flow_stats_dump_callback(struct sw_flow *flow, void *private)
{
    struct flow_stats_state *s = private;
    fill_flow_stats(s->buffer, flow, s->table_idx, s->now);
    return s->buffer->size >= MAX_FLOW_STATS_BYTES;
}

static int flow_stats_dump(struct datapath *dp, void *state,
                           struct ofpbuf *buffer)
{
    struct flow_stats_state *s = state;
    struct sw_flow_key match_key;

    flow_extract_match(&match_key, &s->rq.match);
    s->buffer = buffer;
    s->now = time_msec();
    while (s->table_idx < dp->chain->n_tables
           && (s->rq.table_id == 0xff || s->rq.table_id == s->table_idx))
    {
        struct sw_table *table = dp->chain->tables[s->table_idx];

        if (table->iterate(table, &match_key, s->rq.out_port, 
                    &s->position, flow_stats_dump_callback, s))
            break;

        s->table_idx++;
        memset(&s->position, 0, sizeof s->position);
    }
    return s->buffer->size >= MAX_FLOW_STATS_BYTES;
}

static void flow_stats_done(void *state)
{
    free(state);
}

struct aggregate_stats_state {
    struct ofp_aggregate_stats_request rq;
};

static int aggregate_stats_init(struct datapath *dp,
                                const void *body, int body_len,
                                void **state)
{
    const struct ofp_aggregate_stats_request *rq = body;
    struct aggregate_stats_state *s = xmalloc(sizeof *s);
    s->rq = *rq;
    *state = s;
    return 0;
}

static int aggregate_stats_dump_callback(struct sw_flow *flow, void *private)
{
    struct ofp_aggregate_stats_reply *rpy = private;
    rpy->packet_count += flow->packet_count;
    rpy->byte_count += flow->byte_count;
    rpy->flow_count++;
    return 0;
}

static int aggregate_stats_dump(struct datapath *dp, void *state,
                                struct ofpbuf *buffer)
{
    struct aggregate_stats_state *s = state;
    struct ofp_aggregate_stats_request *rq = &s->rq;
    struct ofp_aggregate_stats_reply *rpy;
    struct sw_table_position position;
    struct sw_flow_key match_key;
    int table_idx;

    rpy = ofpbuf_put_uninit(buffer, sizeof *rpy);
    memset(rpy, 0, sizeof *rpy);

    flow_extract_match(&match_key, &rq->match);
    table_idx = rq->table_id == 0xff ? 0 : rq->table_id;
    memset(&position, 0, sizeof position);
    while (table_idx < dp->chain->n_tables
           && (rq->table_id == 0xff || rq->table_id == table_idx))
    {
        struct sw_table *table = dp->chain->tables[table_idx];
        int error;

        error = table->iterate(table, &match_key, rq->out_port, &position, 
                               aggregate_stats_dump_callback, rpy);
        if (error)
            return error;

        table_idx++;
        memset(&position, 0, sizeof position);
    }

    rpy->packet_count = htonll(rpy->packet_count);
    rpy->byte_count = htonll(rpy->byte_count);
    rpy->flow_count = htonl(rpy->flow_count);
    return 0;
}

static void aggregate_stats_done(void *state) 
{
    free(state);
}

static int table_stats_dump(struct datapath *dp, void *state,
                            struct ofpbuf *buffer)
{
    int i;
    for (i = 0; i < dp->chain->n_tables; i++) {
        struct ofp_table_stats *ots = ofpbuf_put_uninit(buffer, sizeof *ots);
        struct sw_table_stats stats;
        dp->chain->tables[i]->stats(dp->chain->tables[i], &stats);
        strncpy(ots->name, stats.name, sizeof ots->name);
        ots->table_id = i;
        ots->wildcards = htonl(stats.wildcards);
        memset(ots->pad, 0, sizeof ots->pad);
        ots->max_entries = htonl(stats.max_flows);
        ots->active_count = htonl(stats.n_flows);
        ots->lookup_count = htonll(stats.n_lookup);
        ots->matched_count = htonll(stats.n_matched);
    }
    return 0;
}

struct port_stats_state {
    int port;
};

static int port_stats_init(struct datapath *dp, const void *body, int body_len,
               void **state)
{
    struct port_stats_state *s = xmalloc(sizeof *s);
    s->port = 0;
    *state = s;
    return 0;
}

static void
dump_port_stats(struct sw_port *port, struct ofpbuf *buffer)
{
    struct ofp_port_stats *ops = ofpbuf_put_uninit(buffer, sizeof *ops);
    ops->port_no = htons(port->port_no);
    memset(ops->pad, 0, sizeof ops->pad);
    ops->rx_packets   = htonll(port->rx_packets);
    ops->tx_packets   = htonll(port->tx_packets);
    ops->rx_bytes     = htonll(port->rx_bytes);
    ops->tx_bytes     = htonll(port->tx_bytes);
    ops->rx_dropped   = htonll(-1);
    ops->tx_dropped   = htonll(port->tx_dropped);
    ops->rx_errors    = htonll(-1);
    ops->tx_errors    = htonll(-1);
    ops->rx_frame_err = htonll(-1);
    ops->rx_over_err  = htonll(-1);
    ops->rx_crc_err   = htonll(-1);
    ops->collisions   = htonll(-1);
}

static int port_stats_dump(struct datapath *dp, void *state,
                           struct ofpbuf *buffer)
{
    struct port_stats_state *s = state;
    int i;

    for (i = s->port; i < DP_MAX_PORTS; i++) {
        struct sw_port *p = &dp->ports[i];
        if (p->netdev) {
            dump_port_stats(p, buffer);
        }
    }
    s->port = i;

    if (dp->local_port) {
        dump_port_stats(dp->local_port, buffer);
        s->port = OFPP_LOCAL + 1;
    }
    return 0;
}

static void port_stats_done(void *state)
{
    free(state);
}

struct stats_type {
    /* Value for 'type' member of struct ofp_stats_request. */
    int type;

    /* Minimum and maximum acceptable number of bytes in body member of
     * struct ofp_stats_request. */
    size_t min_body, max_body;

    /* Prepares to dump some kind of statistics on 'dp'.  'body' and
     * 'body_len' are the 'body' member of the struct ofp_stats_request.
     * Returns zero if successful, otherwise a negative error code.
     * May initialize '*state' to state information.  May be null if no
     * initialization is required.*/
    int (*init)(struct datapath *dp, const void *body, int body_len,
            void **state);

    /* Appends statistics for 'dp' to 'buffer', which initially contains a
     * struct ofp_stats_reply.  On success, it should return 1 if it should be
     * called again later with another buffer, 0 if it is done, or a negative
     * errno value on failure. */
    int (*dump)(struct datapath *dp, void *state, struct ofpbuf *buffer);

    /* Cleans any state created by the init or dump functions.  May be null
     * if no cleanup is required. */
    void (*done)(void *state);
};

static const struct stats_type stats[] = {
    {
        OFPST_DESC,
        0,
        0,
        NULL,
        desc_stats_dump,
        NULL
    },
    {
        OFPST_FLOW,
        sizeof(struct ofp_flow_stats_request),
        sizeof(struct ofp_flow_stats_request),
        flow_stats_init,
        flow_stats_dump,
        flow_stats_done
    },
    {
        OFPST_AGGREGATE,
        sizeof(struct ofp_aggregate_stats_request),
        sizeof(struct ofp_aggregate_stats_request),
        aggregate_stats_init,
        aggregate_stats_dump,
        aggregate_stats_done
    },
    {
        OFPST_TABLE,
        0,
        0,
        NULL,
        table_stats_dump,
        NULL
    },
    {
        OFPST_PORT,
        0,
        0,
        port_stats_init,
        port_stats_dump,
        port_stats_done
    },
};

struct stats_dump_cb {
    bool done;
    struct ofp_stats_request *rq;
    struct sender sender;
    const struct stats_type *s;
    void *state;
};

static int
stats_dump(struct datapath *dp, void *cb_)
{
    struct stats_dump_cb *cb = cb_;
    struct ofp_stats_reply *osr;
    struct ofpbuf *buffer;
    int err;

    if (cb->done) {
        return 0;
    }

    osr = make_openflow_reply(sizeof *osr, OFPT_STATS_REPLY, &cb->sender,
                              &buffer);
    osr->type = htons(cb->s->type);
    osr->flags = 0;

    err = cb->s->dump(dp, cb->state, buffer);
    if (err >= 0) {
        int err2;
        if (!err) {
            cb->done = true;
        } else {
            /* Buffer might have been reallocated, so find our data again. */
            osr = ofpbuf_at_assert(buffer, 0, sizeof *osr);
            osr->flags = ntohs(OFPSF_REPLY_MORE);
        }
        err2 = send_openflow_buffer(dp, buffer, &cb->sender);
        if (err2) {
            err = err2;
        }
    }

    return err;
}

static void
stats_done(void *cb_)
{
    struct stats_dump_cb *cb = cb_;
    if (cb) {
        if (cb->s->done) {
            cb->s->done(cb->state);
        }
        free(cb);
    }
}

static int
recv_stats_request(struct datapath *dp, const struct sender *sender,
                   const void *oh)
{
    const struct ofp_stats_request *rq = oh;
    size_t rq_len = ntohs(rq->header.length);
    const struct stats_type *st;
    struct stats_dump_cb *cb;
    int type, body_len;
    int err;

    type = ntohs(rq->type);
    for (st = stats; ; st++) {
        if (st >= &stats[ARRAY_SIZE(stats)]) {
            VLOG_WARN_RL(&rl, "received stats request of unknown type %d",
                         type);
            return -EINVAL;
        } else if (type == st->type) {
            break;
        }
    }

    cb = xmalloc(sizeof *cb);
    cb->done = false;
    cb->rq = xmemdup(rq, rq_len);
    cb->sender = *sender;
    cb->s = st;
    cb->state = NULL;
    
    body_len = rq_len - offsetof(struct ofp_stats_request, body);
    if (body_len < cb->s->min_body || body_len > cb->s->max_body) {
        VLOG_WARN_RL(&rl, "stats request type %d with bad body length %d",
                     type, body_len);
        err = -EINVAL;
        goto error;
    }

    if (cb->s->init) {
        err = cb->s->init(dp, rq->body, body_len, &cb->state);
        if (err) {
            VLOG_WARN_RL(&rl,
                         "failed initialization of stats request type %d: %s",
                         type, strerror(-err));
            goto error;
        }
    }

    remote_start_dump(sender->remote, stats_dump, stats_done, cb);
    return 0;

error:
    free(cb->rq);
    free(cb);
    return err;
}

static int
recv_echo_request(struct datapath *dp, const struct sender *sender,
                  const void *oh)
{
    return send_openflow_buffer(dp, make_echo_reply(oh), sender);
}

static int
recv_echo_reply(struct datapath *dp UNUSED, const struct sender *sender UNUSED,
                  const void *oh UNUSED)
{
    return 0;
}

static int
recv_vendor(struct datapath *dp, const struct sender *sender,
                  const void *oh)
{
    const struct ofp_vendor_header *ovh = oh;

    switch (ntohl(ovh->vendor)) 
    {
    case NX_VENDOR_ID:
        return nx_recv_msg(dp, sender, oh);

    default:
        VLOG_WARN_RL(&rl, "unknown vendor: 0x%x\n", ntohl(ovh->vendor));
        dp_send_error_msg(dp, sender, OFPET_BAD_REQUEST,
                OFPBRC_BAD_VENDOR, oh, ntohs(ovh->header.length));
        return -EINVAL;
    }
}

/* 'msg', which is 'length' bytes long, was received from the control path.
 * Apply it to 'chain'. */
int
fwd_control_input(struct datapath *dp, const struct sender *sender,
                  const void *msg, size_t length)
{
    int (*handler)(struct datapath *, const struct sender *, const void *);
    struct ofp_header *oh;
    size_t min_size;

    /* Check encapsulated length. */
    oh = (struct ofp_header *) msg;
    if (ntohs(oh->length) > length) {
        return -EINVAL;
    }
    assert(oh->version == OFP_VERSION);

    /* Figure out how to handle it. */
    switch (oh->type) {
    case OFPT_FEATURES_REQUEST:
        min_size = sizeof(struct ofp_header);
        handler = recv_features_request;
        break;
    case OFPT_GET_CONFIG_REQUEST:
        min_size = sizeof(struct ofp_header);
        handler = recv_get_config_request;
        break;
    case OFPT_SET_CONFIG:
        min_size = sizeof(struct ofp_switch_config);
        handler = recv_set_config;
        break;
    case OFPT_PACKET_OUT:
        min_size = sizeof(struct ofp_packet_out);
        handler = recv_packet_out;
        break;
    case OFPT_FLOW_MOD:
        min_size = sizeof(struct ofp_flow_mod);
        handler = recv_flow;
        break;
    case OFPT_PORT_MOD:
        min_size = sizeof(struct ofp_port_mod);
        handler = recv_port_mod;
        break;
    case OFPT_STATS_REQUEST:
        min_size = sizeof(struct ofp_stats_request);
        handler = recv_stats_request;
        break;
    case OFPT_ECHO_REQUEST:
        min_size = sizeof(struct ofp_header);
        handler = recv_echo_request;
        break;
    case OFPT_ECHO_REPLY:
        min_size = sizeof(struct ofp_header);
        handler = recv_echo_reply;
        break;
    case OFPT_VENDOR:
        min_size = sizeof(struct ofp_vendor_header);
        handler = recv_vendor;
        break;
    default:
        dp_send_error_msg(dp, sender, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE,
                          msg, length);
        return -EINVAL;
    }

    /* Handle it. */
    if (length < min_size)
        return -EFAULT;
    return handler(dp, sender, msg);
}

/* Packet buffering. */

#define OVERWRITE_SECS  1

struct packet_buffer {
    struct ofpbuf *buffer;
    uint32_t cookie;
    time_t timeout;
};

static struct packet_buffer buffers[N_PKT_BUFFERS];
static unsigned int buffer_idx;

uint32_t save_buffer(struct ofpbuf *buffer)
{
    struct packet_buffer *p;
    uint32_t id;

    buffer_idx = (buffer_idx + 1) & PKT_BUFFER_MASK;
    p = &buffers[buffer_idx];
    if (p->buffer) {
        /* Don't buffer packet if existing entry is less than
         * OVERWRITE_SECS old. */
        if (time_now() < p->timeout) { /* FIXME */
            return -1;
        } else {
            ofpbuf_delete(p->buffer); 
        }
    }
    /* Don't use maximum cookie value since the all-bits-1 id is
     * special. */
    if (++p->cookie >= (1u << PKT_COOKIE_BITS) - 1)
        p->cookie = 0;
    p->buffer = ofpbuf_clone(buffer);      /* FIXME */
    p->timeout = time_now() + OVERWRITE_SECS; /* FIXME */
    id = buffer_idx | (p->cookie << PKT_BUFFER_BITS);

    return id;
}

static struct ofpbuf *retrieve_buffer(uint32_t id)
{
    struct ofpbuf *buffer = NULL;
    struct packet_buffer *p;

    p = &buffers[id & PKT_BUFFER_MASK];
    if (p->cookie == id >> PKT_BUFFER_BITS) {
        buffer = p->buffer;
        p->buffer = NULL;
    } else {
        printf("cookie mismatch: %x != %x\n",
               id >> PKT_BUFFER_BITS, p->cookie);
    }

    return buffer;
}

static void discard_buffer(uint32_t id)
{
    struct packet_buffer *p;

    p = &buffers[id & PKT_BUFFER_MASK];
    if (p->cookie == id >> PKT_BUFFER_BITS) {
        ofpbuf_delete(p->buffer);
        p->buffer = NULL;
    }
}
