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

/* Functions for executing OpenFlow actions. */

#include <arpa/inet.h>
#include "csum.h"
#include "packets.h"
#include "dp_act.h"
#include "openflow/nicira-ext.h"
#include "nx_act.h"


static uint16_t
validate_output(struct datapath *dp, const struct sw_flow_key *key, 
        const struct ofp_action_header *ah) 
{
    struct ofp_action_output *oa = (struct ofp_action_output *)ah;

    /* To prevent loops, make sure there's no action to send to the
     * OFP_TABLE virtual port.
     */
    if (oa->port == htons(OFPP_NONE) || oa->port == key->flow.in_port) {
        return OFPBAC_BAD_OUT_PORT;
    }
    return ACT_VALIDATION_OK;
}

static void
do_output(struct datapath *dp, struct ofpbuf *buffer, int in_port,
          size_t max_len, int out_port, bool ignore_no_fwd)
{
    if (out_port != OFPP_CONTROLLER) {
        dp_output_port(dp, buffer, in_port, out_port, ignore_no_fwd);
    } else {
        dp_output_control(dp, buffer, in_port, max_len, OFPR_ACTION);
    }
}

/* Modify vlan tag control information (TCI).  Only sets the TCI bits
 * indicated by 'mask'.  If no vlan tag is present, one is added.
 */
static void
modify_vlan_tci(struct ofpbuf *buffer, struct sw_flow_key *key,
        uint16_t tci, uint16_t mask)
{
    struct vlan_eth_header *veh;

    if (key->flow.dl_vlan != htons(OFP_VLAN_NONE)) {
        /* Modify vlan id, but maintain other TCI values */
        veh = buffer->l2;
        veh->veth_tci &= ~htons(mask);
        veh->veth_tci |= htons(tci);
    } else {
        /* Insert new vlan id. */
        struct eth_header *eh = buffer->l2;
        struct vlan_eth_header tmp;
        memcpy(tmp.veth_dst, eh->eth_dst, ETH_ADDR_LEN);
        memcpy(tmp.veth_src, eh->eth_src, ETH_ADDR_LEN);
        tmp.veth_type = htons(ETH_TYPE_VLAN);
        tmp.veth_tci = htons(tci);
        tmp.veth_next_type = eh->eth_type;

        veh = ofpbuf_push_uninit(buffer, VLAN_HEADER_LEN);
        memcpy(veh, &tmp, sizeof tmp);
        buffer->l2 = (char*)buffer->l2 - VLAN_HEADER_LEN;
    }

    key->flow.dl_vlan = veh->veth_tci & htons(VLAN_VID_MASK);
}


/* Remove an existing vlan header if it exists. */
static void
vlan_pull_tag(struct ofpbuf *buffer)
{
    struct vlan_eth_header *veh = buffer->l2;

    if (veh->veth_type == htons(ETH_TYPE_VLAN)) {
        struct eth_header tmp;

        memcpy(tmp.eth_dst, veh->veth_dst, ETH_ADDR_LEN);
        memcpy(tmp.eth_src, veh->veth_src, ETH_ADDR_LEN);
        tmp.eth_type = veh->veth_next_type;

        buffer->size -= VLAN_HEADER_LEN;
        buffer->data = (char*)buffer->data + VLAN_HEADER_LEN;
        buffer->l2 = (char*)buffer->l2 + VLAN_HEADER_LEN;
        memcpy(buffer->data, &tmp, sizeof tmp);
    }
}

static void
set_vlan_vid(struct ofpbuf *buffer, struct sw_flow_key *key, 
        const struct ofp_action_header *ah)
{
    struct ofp_action_vlan_vid *va = (struct ofp_action_vlan_vid *)ah;
    uint16_t tci = ntohs(va->vlan_vid);

    modify_vlan_tci(buffer, key, tci, VLAN_VID_MASK);
}

static void
set_vlan_pcp(struct ofpbuf *buffer, struct sw_flow_key *key, 
        const struct ofp_action_header *ah)
{
    struct ofp_action_vlan_pcp *va = (struct ofp_action_vlan_pcp *)ah;
    uint16_t tci = (uint16_t)va->vlan_pcp << 13;

    modify_vlan_tci(buffer, key, tci, VLAN_PCP_MASK);
}

static void
strip_vlan(struct ofpbuf *buffer, struct sw_flow_key *key, 
        const struct ofp_action_header *ah)
{
    vlan_pull_tag(buffer);
    key->flow.dl_vlan = htons(OFP_VLAN_NONE);
}

static void
set_dl_addr(struct ofpbuf *buffer, struct sw_flow_key *key, 
        const struct ofp_action_header *ah)
{
    struct ofp_action_dl_addr *da = (struct ofp_action_dl_addr *)ah;
    struct eth_header *eh = buffer->l2;

    if (da->type == htons(OFPAT_SET_DL_SRC)) {
        memcpy(eh->eth_src, da->dl_addr, sizeof eh->eth_src);
    } else {
        memcpy(eh->eth_dst, da->dl_addr, sizeof eh->eth_dst);
    }
}

static void
set_nw_addr(struct ofpbuf *buffer, struct sw_flow_key *key, 
        const struct ofp_action_header *ah)
{
    struct ofp_action_nw_addr *na = (struct ofp_action_nw_addr *)ah;
    uint16_t eth_proto = ntohs(key->flow.dl_type);

    if (eth_proto == ETH_TYPE_IP) {
        struct ip_header *nh = buffer->l3;
        uint8_t nw_proto = key->flow.nw_proto;
        uint32_t new, *field;

        new = na->nw_addr;
        field = na->type == OFPAT_SET_NW_SRC ? &nh->ip_src : &nh->ip_dst;
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

static void
set_tp_port(struct ofpbuf *buffer, struct sw_flow_key *key, 
        const struct ofp_action_header *ah)
{
    struct ofp_action_tp_port *ta = (struct ofp_action_tp_port *)ah;
    uint16_t eth_proto = ntohs(key->flow.dl_type);

    if (eth_proto == ETH_TYPE_IP) {
        uint8_t nw_proto = key->flow.nw_proto;
        uint16_t new, *field;

        new = ta->tp_port;
        if (nw_proto == IP_TYPE_TCP) {
            struct tcp_header *th = buffer->l4;
            field = ta->type == OFPAT_SET_TP_SRC ? &th->tcp_src : &th->tcp_dst;
            th->tcp_csum = recalc_csum16(th->tcp_csum, *field, new);
            *field = new;
        } else if (nw_proto == IP_TYPE_UDP) {
            struct udp_header *th = buffer->l4;
            field = ta->type == OFPAT_SET_TP_SRC ? &th->udp_src : &th->udp_dst;
            th->udp_csum = recalc_csum16(th->udp_csum, *field, new);
            *field = new;
        }
    }
}

struct openflow_action {
    size_t min_size;
    size_t max_size;
    uint16_t (*validate)(struct datapath *dp, 
            const struct sw_flow_key *key,
            const struct ofp_action_header *ah);
    void (*execute)(struct ofpbuf *buffer,
            struct sw_flow_key *key, 
            const struct ofp_action_header *ah);
};

static const struct openflow_action of_actions[] = {
    [OFPAT_OUTPUT] = {
        sizeof(struct ofp_action_output),
        sizeof(struct ofp_action_output),
        validate_output,
        NULL                   /* This is optimized into execute_actions */
    },
    [OFPAT_SET_VLAN_VID] = {
        sizeof(struct ofp_action_vlan_vid),
        sizeof(struct ofp_action_vlan_vid),
        NULL,
        set_vlan_vid
    },
    [OFPAT_SET_VLAN_PCP] = {
        sizeof(struct ofp_action_vlan_pcp),
        sizeof(struct ofp_action_vlan_pcp),
        NULL,
        set_vlan_pcp
    },
    [OFPAT_STRIP_VLAN] = {
        sizeof(struct ofp_action_header),
        sizeof(struct ofp_action_header),
        NULL,
        strip_vlan
    },
    [OFPAT_SET_DL_SRC] = {
        sizeof(struct ofp_action_dl_addr),
        sizeof(struct ofp_action_dl_addr),
        NULL,
        set_dl_addr
    },
    [OFPAT_SET_DL_DST] = {
        sizeof(struct ofp_action_dl_addr),
        sizeof(struct ofp_action_dl_addr),
        NULL,
        set_dl_addr
    },
    [OFPAT_SET_NW_SRC] = {
        sizeof(struct ofp_action_nw_addr),
        sizeof(struct ofp_action_nw_addr),
        NULL,
        set_nw_addr
    },
    [OFPAT_SET_NW_DST] = {
        sizeof(struct ofp_action_nw_addr),
        sizeof(struct ofp_action_nw_addr),
        NULL,
        set_nw_addr
    },
    [OFPAT_SET_TP_SRC] = {
        sizeof(struct ofp_action_tp_port),
        sizeof(struct ofp_action_tp_port),
        NULL,
        set_tp_port
    },
    [OFPAT_SET_TP_DST] = {
        sizeof(struct ofp_action_tp_port),
        sizeof(struct ofp_action_tp_port),
        NULL,
        set_tp_port
    }
    /* OFPAT_VENDOR is not here, since it would blow up the array size. */
};

/* Validate built-in OpenFlow actions.  Either returns ACT_VALIDATION_OK
 * or an OFPET_BAD_ACTION error code. */
static uint16_t 
validate_ofpat(struct datapath *dp, const struct sw_flow_key *key, 
        const struct ofp_action_header *ah, uint16_t type, uint16_t len)
{
    int ret = ACT_VALIDATION_OK;
    const struct openflow_action *act = &of_actions[type];

    if ((len < act->min_size) || (len > act->max_size)) {
        return OFPBAC_BAD_LEN;
    }

    if (act->validate) {
        ret = act->validate(dp, key, ah);
    }

    return ret;
}

/* Validate vendor-defined actions.  Either returns ACT_VALIDATION_OK
 * or an OFPET_BAD_ACTION error code. */
static uint16_t 
validate_vendor(struct datapath *dp, const struct sw_flow_key *key, 
        const struct ofp_action_header *ah, uint16_t len)
{
    struct ofp_action_vendor_header *avh;
    int ret = ACT_VALIDATION_OK;

    if (len < sizeof(struct ofp_action_vendor_header)) {
        return OFPBAC_BAD_LEN;
    }

    avh = (struct ofp_action_vendor_header *)ah;

    switch(ntohl(avh->vendor)) {
    case NX_VENDOR_ID: 
        ret = nx_validate_act(dp, key, avh, len);
        break;

    default:
        return OFPBAC_BAD_VENDOR;
    }

    return ret;
}

/* Validates a list of actions.  If a problem is found, a code for the
 * OFPET_BAD_ACTION error type is returned.  If the action list validates, 
 * ACT_VALIDATION_OK is returned. */
uint16_t 
validate_actions(struct datapath *dp, const struct sw_flow_key *key,
        const struct ofp_action_header *actions, size_t actions_len)
{
    uint8_t *p = (uint8_t *)actions;
    int err;

    while (actions_len >= sizeof(struct ofp_action_header)) {
        struct ofp_action_header *ah = (struct ofp_action_header *)p;
        size_t len = ntohs(ah->len);
        uint16_t type;

        /* Make there's enough remaining data for the specified length
         * and that the action length is a multiple of 64 bits. */
        if ((actions_len < len) || (len % 8) != 0) {
            return OFPBAC_BAD_LEN;
        }

        type = ntohs(ah->type);
        if (type < ARRAY_SIZE(of_actions)) {
            err = validate_ofpat(dp, key, ah, type, len);
            if (err != ACT_VALIDATION_OK) {
                return err;
            }
        } else if (type == OFPAT_VENDOR) {
            err = validate_vendor(dp, key, ah, len);
            if (err != ACT_VALIDATION_OK) {
                return err;
            }
        } else {
            return OFPBAC_BAD_TYPE;
        }

        p += len;
        actions_len -= len;
    }

    /* Check if there's any trailing garbage. */
    if (actions_len != 0) {
        return OFPBAC_BAD_LEN;
    }

    return ACT_VALIDATION_OK;
}

/* Execute a built-in OpenFlow action against 'buffer'. */
static void
execute_ofpat(struct ofpbuf *buffer, struct sw_flow_key *key, 
        const struct ofp_action_header *ah, uint16_t type)
{
    const struct openflow_action *act = &of_actions[type];

    if (act->execute) {
        act->execute(buffer, key, ah);
    }
}

/* Execute a vendor-defined action against 'buffer'. */
static void
execute_vendor(struct ofpbuf *buffer, const struct sw_flow_key *key, 
        const struct ofp_action_header *ah)
{
    struct ofp_action_vendor_header *avh 
            = (struct ofp_action_vendor_header *)ah;

    switch(ntohl(avh->vendor)) {
    case NX_VENDOR_ID: 
        nx_execute_act(buffer, key, avh);
        break;

    default:
        /* This should not be possible due to prior validation. */
        printf("attempt to execute action with unknown vendor: %#x\n", 
                ntohl(avh->vendor));
        break;
    }
}

/* Execute a list of actions against 'buffer'. */
void execute_actions(struct datapath *dp, struct ofpbuf *buffer,
             struct sw_flow_key *key,
             const struct ofp_action_header *actions, size_t actions_len,
             int ignore_no_fwd)
{
    /* Every output action needs a separate clone of 'buffer', but the common
     * case is just a single output action, so that doing a clone and then
     * freeing the original buffer is wasteful.  So the following code is
     * slightly obscure just to avoid that. */
    int prev_port;
    size_t max_len=0;     /* Initialze to make compiler happy */
    uint16_t in_port = ntohs(key->flow.in_port);
    uint8_t *p = (uint8_t *)actions;

    prev_port = -1;

    /* The action list was already validated, so we can be a bit looser
     * in our sanity-checking. */
    while (actions_len > 0) {
        struct ofp_action_header *ah = (struct ofp_action_header *)p;
        size_t len = htons(ah->len);

        if (prev_port != -1) {
            do_output(dp, ofpbuf_clone(buffer), in_port, max_len, 
                    prev_port, ignore_no_fwd);
            prev_port = -1;
        }

        if (ah->type == htons(OFPAT_OUTPUT)) {
            struct ofp_action_output *oa = (struct ofp_action_output *)p;
            prev_port = ntohs(oa->port);
            max_len = ntohs(oa->max_len);
        } else {
            uint16_t type = ntohs(ah->type);

            if (type < ARRAY_SIZE(of_actions)) {
                execute_ofpat(buffer, key, ah, type);
            } else if (type == OFPAT_VENDOR) {
                execute_vendor(buffer, key, ah);
            }
        }

        p += len;
        actions_len -= len;
    }
    if (prev_port != -1) {
        do_output(dp, buffer, in_port, max_len, prev_port, ignore_no_fwd);
    } else {
        ofpbuf_delete(buffer);
    }
}
