/* Copyright (C) 2008 Board of Trustees, Leland Stanford Jr. University.
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

/* Interface exported by OpenFlow module. */

#ifndef DATAPATH_H
#define DATAPATH_H 1

#include <time.h>
#include "openflow.h"
#include "switch-flow.h"
#include "buffer.h"
#include "list.h"

#define NL_FLOWS_PER_MESSAGE 100

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

int dp_new(struct datapath **, uint64_t dpid, struct controller_connection *);
int dp_add_port(struct datapath *, const char *netdev);
void dp_run(struct datapath *);
void dp_wait(struct datapath *);

void dp_output_port(struct datapath *, struct buffer *,
                    int in_port, int out_port);
void dp_output_control(struct datapath *, struct buffer *, int in_port,
                       uint32_t buffer_id, size_t max_len, int reason);
void dp_send_hello(struct datapath *);
void dp_send_flow_expired(struct datapath *, struct sw_flow *);
void dp_update_port_flags(struct datapath *dp, const struct ofp_phy_port *opp);

#endif /* datapath.h */
