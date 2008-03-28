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

#include "forward.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "datapath.h"
#include "chain.h"
#include "flow.h"
#include "packets.h"

static void execute_actions(struct datapath *, struct buffer *,
                            int in_port, const struct sw_flow_key *,
                            const struct ofp_action *, int n_actions);

static struct buffer *retrieve_buffer(uint32_t id);
static void discard_buffer(uint32_t id);

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
        dp_output_control(dp, buffer, in_port, fwd_save_buffer(buffer),
                          dp->miss_send_len, OFPR_NO_MATCH);
    }
}

static void
do_output(struct datapath *dp, struct buffer *buffer, int in_port,
          size_t max_len, int out_port)
{
    if (out_port != OFPP_CONTROLLER) {
        dp_output_port(dp, buffer, in_port, out_port);
    } else {
        dp_output_control(dp, buffer, in_port, fwd_save_buffer(buffer),
                          max_len, OFPR_ACTION);
    }
}

static void execute_actions(struct datapath *dp, struct buffer *buffer,
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

        if (prev_port != -1) {
            do_output(dp, buffer_clone(buffer), in_port, max_len, prev_port);
            prev_port = -1;
        }

        if (a->type == ntohs(OFPAT_OUTPUT)) {
            prev_port = ntohs(a->arg.output.port);
            max_len = ntohs(a->arg.output.max_len);
        } else {
            buffer = execute_setter(buffer, eth_proto, key, a);
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

static struct buffer *
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

    return buffer;
}

struct buffer *execute_setter(struct buffer *buffer, uint16_t eth_proto,
                              const struct sw_flow_key *key, const struct ofp_action *a)
{
    switch (a->type) {
    case OFPAT_SET_DL_VLAN:
        buffer = modify_vlan(buffer, key, a);
        break;

    case OFPAT_SET_DL_SRC: {
        struct eth_header *eh = buffer->l2;
        memcpy(eh->eth_src, a->arg.dl_addr, sizeof eh->eth_src);
        break;
    }
    case OFPAT_SET_DL_DST: {
        struct eth_header *eh = buffer->l2;
        memcpy(eh->eth_dst, a->arg.dl_addr, sizeof eh->eth_dst);
        break;
    }

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

    return buffer;
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
            execute_actions(dp, buffer, in_port,
                            &key, ofm->actions, n_acts);
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

uint32_t fwd_save_buffer(struct buffer *buffer)
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

void fwd_exit(void)
{
    int i;

    for (i = 0; i < N_PKT_BUFFERS; i++)
        buffer_delete(buffers[i].buffer);
}
