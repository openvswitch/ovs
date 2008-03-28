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
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "chain.h"
#include "controller.h"
#include "flow.h"
#include "forward.h"
#include "netdev.h"
#include "packets.h"
#include "poll-loop.h"
#include "table.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_datapath
#include "vlog.h"

#define BRIDGE_PORT_NO_FLOOD    0x00000001

static void send_port_status(struct sw_port *p, uint8_t status);
static void del_switch_port(struct sw_port *p);
static int port_no(struct datapath *dp, struct sw_port *p) 
{
    assert(p >= dp->ports && p < &dp->ports[ARRAY_SIZE(dp->ports)]);
    return p - dp->ports;
}

/* Generates a unique datapath id.  It incorporates the datapath index
 * and a hardware address, if available.  If not, it generates a random
 * one.
 */
static uint64_t
gen_datapath_id(void)
{
    /* Choose a random datapath id. */
    uint64_t id = 0;
    int i;

    srand(time(0));

    for (i = 0; i < ETH_ADDR_LEN; i++) {
        id |= (uint64_t)(rand() & 0xff) << (8*(ETH_ADDR_LEN-1 - i));
    }

    return id;
}

int
dp_new(struct datapath **dp_, uint64_t dpid, struct controller_connection *cc)
{
    struct datapath *dp;

    dp = calloc(1, sizeof *dp);
    if (!dp) {
        return ENOMEM;
    }

    dp->last_timeout = time(0);
    dp->cc = cc;
    dp->id = dpid <= UINT64_C(0xffffffffffff) ? dpid : gen_datapath_id();
    dp->chain = chain_create();
    if (!dp->chain) {
        VLOG_ERR("could not create chain");
        free(dp);
        return ENOMEM;
    }

    list_init(&dp->port_list);
    dp->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;
    *dp_ = dp;
    return 0;
}

int
dp_add_port(struct datapath *dp, const char *name)
{
    struct netdev *netdev;
    struct sw_port *p;
    int error;

    error = netdev_open(name, &netdev);
    if (error) {
        return error;
    }

    for (p = dp->ports; ; p++) {
        if (p >= &dp->ports[ARRAY_SIZE(dp->ports)]) {
            return EXFULL;
        } else if (!p->netdev) {
            break;
        }
    }

    p->dp = dp;
    p->netdev = netdev;
    list_push_back(&dp->port_list, &p->node);

    /* Notify the ctlpath that this port has been added */
    send_port_status(p, OFPPR_ADD);

    return 0;
}

void
dp_run(struct datapath *dp) 
{
    time_t now = time(0);
    struct sw_port *p, *n;
    struct buffer *buffer = NULL;

    if (now != dp->last_timeout) {
        chain_timeout(dp->chain, dp);
        dp->last_timeout = now;
    }
    poll_timer_wait(1000);
    
    LIST_FOR_EACH_SAFE (p, n, struct sw_port, node, &dp->port_list) {
        int error;

        if (!buffer) {
            /* Allocate buffer with some headroom to add headers in forwarding
             * to the controller or adding a vlan tag, plus an extra 2 bytes to
             * allow IP headers to be aligned on a 4-byte boundary.  */
            const int headroom = 128 + 2;
            const int hard_header = VLAN_ETH_HEADER_LEN;
            const int mtu = netdev_get_mtu(p->netdev);
            buffer = buffer_new(headroom + hard_header + mtu);
            buffer->data += headroom;
        }
        error = netdev_recv(p->netdev, buffer, false);
        if (!error) {
            fwd_port_input(dp, buffer, port_no(dp, p));
            buffer = NULL;
        } else if (error != EAGAIN) {
            VLOG_ERR("Error receiving data from %s: %s",
                     netdev_get_name(p->netdev), strerror(error));
            del_switch_port(p);
        }
    }
    buffer_delete(buffer);
}

void
dp_wait(struct datapath *dp) 
{
    struct sw_port *p;

    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        poll_fd_wait(netdev_get_fd(p->netdev), POLLIN, NULL);
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

static int
flood(struct datapath *dp, struct buffer *buffer, int in_port)
{
    struct sw_port *p;
    struct sw_port *prev_port;

    prev_port = NULL;
    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        if (port_no(dp, p) == in_port || p->flags & BRIDGE_PORT_NO_FLOOD) {
            continue;
        }
        if (prev_port) {
            struct buffer *clone = buffer_clone(buffer);
            if (!clone) {
                buffer_delete(buffer);
                return -ENOMEM;
            }
            dp_output_port(dp, clone, in_port, port_no(dp, prev_port)); 
        }
        prev_port = p;
    }
    if (prev_port)
        dp_output_port(dp, buffer, in_port, port_no(dp, prev_port));
    else
        buffer_delete(buffer);

    return 0;
}

void
output_packet(struct datapath *dp, struct buffer *buffer, int out_port) 
{
    if (out_port >= 0 && out_port < OFPP_MAX) { 
        struct sw_port *p = &dp->ports[out_port];
        if (p->netdev != NULL) {
            /* FIXME: queue packets. */
            netdev_send(p->netdev, buffer, false);
            return;
        }
    }

    buffer_delete(buffer);
    /* FIXME: ratelimit */
    VLOG_DBG("can't forward to bad port %d\n", out_port);
}

/* Takes ownership of 'buffer' and transmits it to 'out_port' on 'dp'.
 */
void
dp_output_port(struct datapath *dp, struct buffer *buffer,
               int in_port, int out_port)
{

    assert(buffer);
    if (out_port == OFPP_FLOOD) {
        flood(dp, buffer, in_port); 
    } else if (out_port == OFPP_CONTROLLER) {
        dp_output_control(dp, buffer, in_port, fwd_save_buffer(buffer), 0,
                          OFPR_ACTION); 
    } else {
        output_packet(dp, buffer, out_port);
    }
}

/* Takes ownership of 'buffer' and transmits it to 'dp''s controller.  If
 * 'buffer_id' != -1, then only the first 64 bytes of 'buffer' are sent;
 * otherwise, all of 'buffer' is sent.  'reason' indicates why 'buffer' is
 * being sent. 'max_len' sets the maximum number of bytes that the caller wants
 * to be sent; a value of 0 indicates the entire packet should be sent. */
void
dp_output_control(struct datapath *dp, struct buffer *buffer, int in_port,
                  uint32_t buffer_id, size_t max_len, int reason)
{
    struct ofp_packet_in *opi;
    size_t total_len;

    total_len = buffer->size;
    if (buffer_id != UINT32_MAX && max_len > buffer->size) {
        buffer->size = max_len;
    }

    opi = buffer_push_uninit(buffer, offsetof(struct ofp_packet_in, data));
    opi->header.version = OFP_VERSION;
    opi->header.type    = OFPT_PACKET_IN;
    opi->header.length  = htons(buffer->size);
    opi->header.xid     = htonl(0);
    opi->buffer_id      = htonl(buffer_id);
    opi->total_len      = htons(total_len);
    opi->in_port        = htons(in_port);
    opi->reason         = reason;
    opi->pad            = 0;
    controller_send(dp->cc, buffer);
}

static void fill_port_desc(struct datapath *dp, struct sw_port *p,
                           struct ofp_phy_port *desc)
{
    desc->port_no = htons(port_no(dp, p));
    strncpy((char *) desc->name, netdev_get_name(p->netdev),
            sizeof desc->name);
    desc->name[sizeof desc->name - 1] = '\0';
    memcpy(desc->hw_addr, netdev_get_etheraddr(p->netdev), ETH_ADDR_LEN);
    desc->flags = htonl(p->flags);
    desc->features = htonl(netdev_get_features(p->netdev));
    desc->speed = htonl(netdev_get_speed(p->netdev));
}

void
dp_send_hello(struct datapath *dp)
{
    struct buffer *buffer;
    struct ofp_data_hello *odh;
    struct sw_port *p;

    buffer = buffer_new(sizeof *odh);
    odh = buffer_put_uninit(buffer, sizeof *odh);
    memset(odh, 0, sizeof *odh);
    odh->header.version = OFP_VERSION;
    odh->header.type    = OFPT_DATA_HELLO;
    odh->header.xid     = htonl(0);
    odh->datapath_id    = htonll(dp->id); 
    odh->n_exact        = htonl(2 * TABLE_HASH_MAX_FLOWS);
    odh->n_mac_only     = htonl(TABLE_MAC_MAX_FLOWS);
    odh->n_compression  = 0;                                           /* Not supported */
    odh->n_general      = htonl(TABLE_LINEAR_MAX_FLOWS);
    odh->buffer_mb      = htonl(UINT32_MAX);
    odh->n_buffers      = htonl(N_PKT_BUFFERS);
    odh->capabilities   = htonl(OFP_SUPPORTED_CAPABILITIES);
    odh->actions        = htonl(OFP_SUPPORTED_ACTIONS);
    odh->miss_send_len  = htons(dp->miss_send_len); 
    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        struct ofp_phy_port *opp = buffer_put_uninit(buffer, sizeof *opp);
        memset(opp, 0, sizeof *opp);
        fill_port_desc(dp, p, opp);
    }
    odh = buffer_at_assert(buffer, 0, sizeof *odh);
    odh->header.length = htons(buffer->size);
    controller_send(dp->cc, buffer);
}

void
dp_update_port_flags(struct datapath *dp, const struct ofp_phy_port *opp)
{
    struct sw_port *p;

    p = &dp->ports[htons(opp->port_no)];

    /* Make sure the port id hasn't changed since this was sent */
    if (!p || memcmp(opp->hw_addr, netdev_get_etheraddr(p->netdev),
                     ETH_ADDR_LEN) != 0) 
        return;
        
    p->flags = htonl(opp->flags);
}

static void
send_port_status(struct sw_port *p, uint8_t status) 
{
    struct buffer *buffer;
    struct ofp_port_status *ops;
    buffer = buffer_new(sizeof *ops);
    ops = buffer_put_uninit(buffer, sizeof *ops);
    ops->header.version = OFP_VERSION;
    ops->header.type    = OFPT_PORT_STATUS;
    ops->header.length  = htons(sizeof(*ops));
    ops->header.xid     = htonl(0);
    ops->reason         = status;
    fill_port_desc(p->dp, p, &ops->desc);
    controller_send(p->dp->cc, buffer);
}

void
dp_send_flow_expired(struct datapath *dp, struct sw_flow *flow)
{
    struct buffer *buffer;
    struct ofp_flow_expired *ofe;
    buffer = buffer_new(sizeof *ofe);
    ofe = buffer_put_uninit(buffer, sizeof *ofe);
    ofe->header.version = OFP_VERSION;
    ofe->header.type    = OFPT_FLOW_EXPIRED;
    ofe->header.length  = htons(sizeof(*ofe));
    ofe->header.xid     = htonl(0);
    flow_fill_match(&ofe->match, &flow->key);
    ofe->duration   = htonl(flow->timeout - flow->max_idle - flow->created);
    ofe->packet_count   = htonll(flow->packet_count);
    ofe->byte_count     = htonll(flow->byte_count);
    controller_send(dp->cc, buffer);
}
