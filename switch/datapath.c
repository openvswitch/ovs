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
#include "netdev.h"
#include "packets.h"
#include "poll-loop.h"
#include "table.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_datapath
#include "vlog.h"

#define BRIDGE_PORT_NO_FLOOD    0x00000001

/* Capabilities supported by this implementation. */
#define OFP_SUPPORTED_CAPABILITIES (OFPC_MULTI_PHY_TX)

/* Actions supported by this implementation. */
#define OFP_SUPPORTED_ACTIONS ( (1 << OFPAT_OUTPUT)         \
                                | (1 << OFPAT_SET_DL_VLAN)  \
                                | (1 << OFPAT_SET_DL_SRC)   \
                                | (1 << OFPAT_SET_DL_DST)   \
                                | (1 << OFPAT_SET_NW_SRC)   \
                                | (1 << OFPAT_SET_NW_DST)   \
                                | (1 << OFPAT_SET_TP_SRC)   \
                                | (1 << OFPAT_SET_TP_DST) )

struct sw_port {
    uint32_t flags;
    struct datapath *dp;
    struct netdev *netdev;
    struct list node; /* Element in datapath.ports. */
};

struct datapath {
    struct controller_connection *cc;

    time_t last_timeout;

    /* Unique identifier for this datapath */
    uint64_t  id;

    struct sw_chain *chain;  /* Forwarding rules. */

    /* Flags from the control hello message */
    uint16_t hello_flags;

    /* Maximum number of bytes that should be sent for flow misses */
    uint16_t miss_send_len;

    /* Switch ports. */
    struct sw_port ports[OFPP_MAX];
    struct list port_list; /* List of ports, for flooding. */
};

void dp_output_port(struct datapath *, struct buffer *,
                    int in_port, int out_port);
void dp_send_hello(struct datapath *);
void dp_update_port_flags(struct datapath *dp, const struct ofp_phy_port *opp);
void dp_output_control(struct datapath *, struct buffer *, int in_port,
                       size_t max_len, int reason);
static void send_port_status(struct sw_port *p, uint8_t status);
static void del_switch_port(struct sw_port *p);
static void execute_actions(struct datapath *, struct buffer *,
                            int in_port, const struct sw_flow_key *,
                            const struct ofp_action *, int n_actions);
static void modify_vlan(struct buffer *buffer, const struct sw_flow_key *key,
                        const struct ofp_action *a);
static void modify_nh(struct buffer *buffer, uint16_t eth_proto,
                      uint8_t nw_proto, const struct ofp_action *a);
static void modify_th(struct buffer *buffer, uint16_t eth_proto,
                          uint8_t nw_proto, const struct ofp_action *a);

/* Buffers are identified to userspace by a 31-bit opaque ID.  We divide the ID
 * into a buffer number (low bits) and a cookie (high bits).  The buffer number
 * is an index into an array of buffers.  The cookie distinguishes between
 * different packets that have occupied a single buffer.  Thus, the more
 * buffers we have, the lower-quality the cookie... */
#define PKT_BUFFER_BITS 8
#define N_PKT_BUFFERS (1 << PKT_BUFFER_BITS)
#define PKT_BUFFER_MASK (N_PKT_BUFFERS - 1)

#define PKT_COOKIE_BITS (32 - PKT_BUFFER_BITS)

void fwd_port_input(struct datapath *, struct buffer *, int in_port);
int fwd_control_input(struct datapath *, const void *, size_t);

uint32_t save_buffer(struct buffer *);
static struct buffer *retrieve_buffer(uint32_t id);
static void discard_buffer(uint32_t id);

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
    int i;

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
        error = netdev_recv(p->netdev, buffer);
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

    for (i = 0; i < 50; i++) {
        struct buffer *buffer = controller_recv(dp->cc);
        if (!buffer) {
            break;
        }
        fwd_control_input(dp, buffer->data, buffer->size);
        buffer_delete(buffer);
    }

    controller_run(dp->cc);
}

void
dp_wait(struct datapath *dp) 
{
    struct sw_port *p;

    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        netdev_recv_wait(p->netdev);
    }
    controller_recv_wait(dp->cc);
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
    int prev_port;

    prev_port = -1;
    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        if (port_no(dp, p) == in_port || p->flags & BRIDGE_PORT_NO_FLOOD) {
            continue;
        }
        if (prev_port != -1) {
            dp_output_port(dp, buffer_clone(buffer), in_port, prev_port);
        }
        prev_port = port_no(dp, p);
    }
    if (prev_port != -1)
        dp_output_port(dp, buffer, in_port, prev_port);
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
            netdev_send(p->netdev, buffer);
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
        dp_output_control(dp, buffer, in_port, 0, OFPR_ACTION); 
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
                  size_t max_len, int reason)
{
    struct ofp_packet_in *opi;
    size_t total_len;
    uint32_t buffer_id;

    buffer_id = save_buffer(buffer);
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

/* 'buffer' was received on 'in_port', a physical switch port between 0 and
 * OFPP_MAX.  Process it according to 'chain'. */
void fwd_port_input(struct datapath *dp, struct buffer *buffer, int in_port)
{
    struct sw_flow_key key;
    struct sw_flow *flow;

    key.wildcards = 0;
    flow_extract(buffer, in_port, &key.flow);
    flow = chain_lookup(dp->chain, &key);
    if (flow != NULL) {
        flow_used(flow, buffer);
        execute_actions(dp, buffer, in_port, &key,
                        flow->actions, flow->n_actions);
    } else {
        dp_output_control(dp, buffer, in_port, dp->miss_send_len,
                          OFPR_NO_MATCH);
    }
}

static void
do_output(struct datapath *dp, struct buffer *buffer, int in_port,
          size_t max_len, int out_port)
{
    if (out_port != OFPP_CONTROLLER) {
        dp_output_port(dp, buffer, in_port, out_port);
    } else {
        dp_output_control(dp, buffer, in_port, max_len, OFPR_ACTION);
    }
}

static void
execute_actions(struct datapath *dp, struct buffer *buffer,
                int in_port, const struct sw_flow_key *key,
                const struct ofp_action *actions, int n_actions)
{
    /* Every output action needs a separate clone of 'buffer', but the common
     * case is just a single output action, so that doing a clone and then
     * freeing the original buffer is wasteful.  So the following code is
     * slightly obscure just to avoid that. */
    int prev_port;
    size_t max_len=0;        /* Initialze to make compiler happy */
    uint16_t eth_proto;
    int i;

    prev_port = -1;
    eth_proto = ntohs(key->flow.dl_type);

    for (i = 0; i < n_actions; i++) {
        const struct ofp_action *a = &actions[i];
        struct eth_header *eh = buffer->l2;

        if (prev_port != -1) {
            do_output(dp, buffer_clone(buffer), in_port, max_len, prev_port);
            prev_port = -1;
        }

        switch (ntohs(a->type)) {
        case OFPAT_OUTPUT:
            prev_port = ntohs(a->arg.output.port);
            max_len = ntohs(a->arg.output.max_len);
            break;

        case OFPAT_SET_DL_VLAN:
            modify_vlan(buffer, key, a);
            break;

        case OFPAT_SET_DL_SRC:
            memcpy(eh->eth_src, a->arg.dl_addr, sizeof eh->eth_src);
            break;

        case OFPAT_SET_DL_DST:
            memcpy(eh->eth_dst, a->arg.dl_addr, sizeof eh->eth_dst);
            break;

        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST:
            modify_nh(buffer, eth_proto, key->flow.nw_proto, a);
            break;

        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST:
            modify_th(buffer, eth_proto, key->flow.nw_proto, a);
            break;

        default:
            NOT_REACHED();
        }
    }
    if (prev_port != -1)
        do_output(dp, buffer, in_port, max_len, prev_port);
    else
        buffer_delete(buffer);
}

/* Returns the new checksum for a packet in which the checksum field previously
 * contained 'old_csum' and in which a field that contained 'old_u16' was
 * changed to contain 'new_u16'. */
static uint16_t
recalc_csum16(uint16_t old_csum, uint16_t old_u16, uint16_t new_u16)
{
    /* Ones-complement arithmetic is endian-independent, so this code does not
     * use htons() or ntohs().
     *
     * See RFC 1624 for formula and explanation. */
    uint16_t hc_complement = ~old_csum;
    uint16_t m_complement = ~old_u16;
    uint16_t m_prime = new_u16;
    uint32_t sum = hc_complement + m_complement + m_prime;
    uint16_t hc_prime_complement = sum + (sum >> 16);
    return ~hc_prime_complement;
}

/* Returns the new checksum for a packet in which the checksum field previously
 * contained 'old_csum' and in which a field that contained 'old_u32' was
 * changed to contain 'new_u32'. */
static uint16_t
recalc_csum32(uint16_t old_csum, uint32_t old_u32, uint32_t new_u32)
{
    return recalc_csum16(recalc_csum16(old_csum, old_u32, new_u32),
                         old_u32 >> 16, new_u32 >> 16);
}

static void modify_nh(struct buffer *buffer, uint16_t eth_proto,
                      uint8_t nw_proto, const struct ofp_action *a)
{
    if (eth_proto == ETH_TYPE_IP) {
        struct ip_header *nh = buffer->l3;
        uint32_t new, *field;

        new = a->arg.nw_addr;
        field = a->type == OFPAT_SET_NW_SRC ? &nh->ip_src : &nh->ip_dst;
        if (nw_proto == IP_TYPE_TCP) {
            struct tcp_header *th = buffer->l4;
            th->tcp_csum = recalc_csum32(th->tcp_csum, *field, new);
        } else if (nw_proto == IP_TYPE_UDP) {
            struct udp_header *th = buffer->l4;
            if (th->udp_csum) {
                th->udp_csum = recalc_csum32(th->udp_csum, *field, new);
                if (!th->udp_csum) {
                    th->udp_csum = 0xffff;
                }
            }
        }
        nh->ip_csum = recalc_csum32(nh->ip_csum, *field, new);
        *field = new;
    }
}

static void modify_th(struct buffer *buffer, uint16_t eth_proto,
                      uint8_t nw_proto, const struct ofp_action *a)
{
    if (eth_proto == ETH_TYPE_IP) {
        uint16_t new, *field;

        new = a->arg.tp;

        if (nw_proto == IP_TYPE_TCP) {
            struct tcp_header *th = buffer->l4;
            field = a->type == OFPAT_SET_TP_SRC ? &th->tcp_src : &th->tcp_dst;
            th->tcp_csum = recalc_csum16(th->tcp_csum, *field, new);
            *field = new;
        } else if (nw_proto == IP_TYPE_UDP) {
            struct udp_header *th = buffer->l4;
            field = a->type == OFPAT_SET_TP_SRC ? &th->udp_src : &th->udp_dst;
            th->udp_csum = recalc_csum16(th->udp_csum, *field, new);
            *field = new;
        }
    }
}

static void
modify_vlan(struct buffer *buffer,
            const struct sw_flow_key *key, const struct ofp_action *a)
{
    uint16_t new_id = a->arg.vlan_id;
    struct vlan_eth_header *veh;

    if (new_id != OFP_VLAN_NONE) {
        if (key->flow.dl_vlan != htons(OFP_VLAN_NONE)) {
            /* Modify vlan id, but maintain other TCI values */
            veh = buffer->l2;
            veh->veth_tci &= ~htons(VLAN_VID);
            veh->veth_tci |= htons(new_id);
        } else {
            /* Insert new vlan id. */
            struct eth_header *eh = buffer->l2;
            struct vlan_eth_header tmp;
            memcpy(tmp.veth_dst, eh->eth_dst, ETH_ADDR_LEN);
            memcpy(tmp.veth_src, eh->eth_src, ETH_ADDR_LEN);
            tmp.veth_type = htons(ETH_TYPE_VLAN);
            tmp.veth_tci = new_id;
            tmp.veth_next_type = eh->eth_type;
            
            veh = buffer_push_uninit(buffer, VLAN_HEADER_LEN);
            memcpy(veh, &tmp, sizeof tmp);
            buffer->l2 -= VLAN_HEADER_LEN;
        }
    } else  {
        /* Remove an existing vlan header if it exists */
        veh = buffer->l2;
        if (veh->veth_type == htons(ETH_TYPE_VLAN)) {
            struct eth_header tmp;
            
            memcpy(tmp.eth_dst, veh->veth_dst, ETH_ADDR_LEN);
            memcpy(tmp.eth_src, veh->veth_src, ETH_ADDR_LEN);
            tmp.eth_type = veh->veth_next_type;
            
            buffer->size -= VLAN_HEADER_LEN;
            buffer->data += VLAN_HEADER_LEN;
            buffer->l2 += VLAN_HEADER_LEN;
            memcpy(buffer->data, &tmp, sizeof tmp);
        }
    }
}

static int
recv_control_hello(struct datapath *dp, const void *msg)
{
    const struct ofp_control_hello *och = msg;

    printf("control_hello(version=%d)\n", ntohl(och->version));

    if (ntohs(och->miss_send_len) != OFP_MISS_SEND_LEN_UNCHANGED) {
        dp->miss_send_len = ntohs(och->miss_send_len);
    }

    dp->hello_flags = ntohs(och->flags);

    dp_send_hello(dp);

    return 0;
}

static int
recv_packet_out(struct datapath *dp, const void *msg)
{
    const struct ofp_packet_out *opo = msg;

    if (ntohl(opo->buffer_id) == (uint32_t) -1) {
        /* FIXME: can we avoid copying data here? */
        int data_len = ntohs(opo->header.length) - sizeof *opo;
        struct buffer *buffer = buffer_new(data_len);
        buffer_put(buffer, opo->u.data, data_len);
        dp_output_port(dp, buffer,
                       ntohs(opo->in_port), ntohs(opo->out_port));
    } else {
        struct sw_flow_key key;
        struct buffer *buffer;
        int n_acts;

        buffer = retrieve_buffer(ntohl(opo->buffer_id));
        if (!buffer) {
            return -ESRCH; 
        }

        n_acts = (ntohs(opo->header.length) - sizeof *opo) 
            / sizeof *opo->u.actions;
        flow_extract(buffer, ntohs(opo->in_port), &key.flow);
        execute_actions(dp, buffer, ntohs(opo->in_port),
                        &key, opo->u.actions, n_acts);
    }
    return 0;
}

static int
recv_port_mod(struct datapath *dp, const void *msg)
{
    const struct ofp_port_mod *opm = msg;

    dp_update_port_flags(dp, &opm->desc);

    return 0;
}

static int
add_flow(struct datapath *dp, const struct ofp_flow_mod *ofm)
{
    int error = -ENOMEM;
    int n_acts;
    struct sw_flow *flow;


    /* Check number of actions. */
    n_acts = (ntohs(ofm->header.length) - sizeof *ofm) / sizeof *ofm->actions;
    if (n_acts > MAX_ACTIONS) {
        error = -E2BIG;
        goto error;
    }

    /* Allocate memory. */
    flow = flow_alloc(n_acts);
    if (flow == NULL)
        goto error;

    /* Fill out flow. */
    flow_extract_match(&flow->key, &ofm->match);
    flow->group_id = ntohl(ofm->group_id);
    flow->max_idle = ntohs(ofm->max_idle);
    flow->timeout = time(0) + flow->max_idle; /* FIXME */
    flow->n_actions = n_acts;
    flow->created = time(0);    /* FIXME */
    flow->byte_count = 0;
    flow->packet_count = 0;
    memcpy(flow->actions, ofm->actions, n_acts * sizeof *flow->actions);

    /* Act. */
    error = chain_insert(dp->chain, flow);
    if (error) {
        goto error_free_flow; 
    }
    error = 0;
    if (ntohl(ofm->buffer_id) != UINT32_MAX) {
        struct buffer *buffer = retrieve_buffer(ntohl(ofm->buffer_id));
        if (buffer) {
            struct sw_flow_key key;
            uint16_t in_port = ntohs(ofm->match.in_port);
            flow_used(flow, buffer);
            flow_extract(buffer, in_port, &key.flow);
            execute_actions(dp, buffer, in_port, &key, ofm->actions, n_acts);
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
recv_flow(struct datapath *dp, const void *msg)
{
    const struct ofp_flow_mod *ofm = msg;
    uint16_t command = ntohs(ofm->command);

    if (command == OFPFC_ADD) {
        return add_flow(dp, ofm);
    }  else if (command == OFPFC_DELETE) {
        struct sw_flow_key key;
        flow_extract_match(&key, &ofm->match);
        return chain_delete(dp->chain, &key, 0) ? 0 : -ESRCH;
    } else if (command == OFPFC_DELETE_STRICT) {
        struct sw_flow_key key;
        flow_extract_match(&key, &ofm->match);
        return chain_delete(dp->chain, &key, 1) ? 0 : -ESRCH;
    } else {
        return -ENODEV;
    }
}

/* 'msg', which is 'length' bytes long, was received from the control path.
 * Apply it to 'chain'. */
int
fwd_control_input(struct datapath *dp, const void *msg, size_t length)
{

    struct openflow_packet {
        size_t min_size;
        int (*handler)(struct datapath *, const void *);
    };

    static const struct openflow_packet packets[] = {
        [OFPT_CONTROL_HELLO] = {
            sizeof (struct ofp_control_hello),
            recv_control_hello,
        },
        [OFPT_PACKET_OUT] = {
            sizeof (struct ofp_packet_out),
            recv_packet_out,
        },
        [OFPT_FLOW_MOD] = {
            sizeof (struct ofp_flow_mod),
            recv_flow,
        },
        [OFPT_PORT_MOD] = {
            sizeof (struct ofp_port_mod),
            recv_port_mod,
        },
    };

    const struct openflow_packet *pkt;
    struct ofp_header *oh;

    if (length < sizeof(struct ofp_header))
        return -EINVAL;

    oh = (struct ofp_header *) msg;
    if (oh->version != 1 || oh->type >= ARRAY_SIZE(packets)
        || ntohs(oh->length) > length)
        return -EINVAL;

    pkt = &packets[oh->type];
    if (!pkt->handler)
        return -ENOSYS;
    if (length < pkt->min_size)
        return -EFAULT;

    return pkt->handler(dp, msg);
}

/* Packet buffering. */

#define OVERWRITE_SECS  1

struct packet_buffer {
    struct buffer *buffer;
    uint32_t cookie;
    time_t timeout;
};

static struct packet_buffer buffers[N_PKT_BUFFERS];
static unsigned int buffer_idx;

uint32_t save_buffer(struct buffer *buffer)
{
    struct packet_buffer *p;
    uint32_t id;

    buffer_idx = (buffer_idx + 1) & PKT_BUFFER_MASK;
    p = &buffers[buffer_idx];
    if (p->buffer) {
        /* Don't buffer packet if existing entry is less than
         * OVERWRITE_SECS old. */
        if (time(0) < p->timeout) { /* FIXME */
            return -1;
        } else {
            buffer_delete(p->buffer); 
        }
    }
    /* Don't use maximum cookie value since the all-bits-1 id is
     * special. */
    if (++p->cookie >= (1u << PKT_COOKIE_BITS) - 1)
        p->cookie = 0;
    p->buffer = buffer_clone(buffer);      /* FIXME */
    p->timeout = time(0) + OVERWRITE_SECS; /* FIXME */
    id = buffer_idx | (p->cookie << PKT_BUFFER_BITS);

    return id;
}

static struct buffer *retrieve_buffer(uint32_t id)
{
    struct buffer *buffer = NULL;
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
        buffer_delete(p->buffer);
        p->buffer = NULL;
    }
}
