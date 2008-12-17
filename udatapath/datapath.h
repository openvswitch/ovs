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

/* Interface exported by OpenFlow module. */

#ifndef DATAPATH_H
#define DATAPATH_H 1

#include <stdbool.h>
#include <stdint.h>
#include "openflow/nicira-ext.h"
#include "ofpbuf.h"
#include "timeval.h"
#include "list.h"

struct rconn;
struct pvconn;
struct sw_flow;
struct sender;

struct sw_port {
    uint32_t config;            /* Some subset of OFPPC_* flags. */
    uint32_t state;             /* Some subset of OFPPS_* flags. */
    struct datapath *dp;
    struct netdev *netdev;
    struct list node; /* Element in datapath.ports. */
    unsigned long long int rx_packets, tx_packets;
    unsigned long long int rx_bytes, tx_bytes;
    unsigned long long int tx_dropped;
    uint16_t port_no;
};

#define DP_MAX_PORTS 255
BUILD_ASSERT_DECL(DP_MAX_PORTS <= OFPP_MAX);

struct datapath {
    /* Remote connections. */
    struct list remotes;        /* All connections (including controller). */

    /* Listeners. */
    struct pvconn **listeners;
    size_t n_listeners;

    time_t last_timeout;

    /* Unique identifier for this datapath */
    uint64_t  id;

    struct sw_chain *chain;  /* Forwarding rules. */

    /* Configuration set from controller. */
    uint16_t flags;
    uint16_t miss_send_len;

    /* Flag controlling whether Flow End messages are generated. */
    uint8_t send_flow_end;

    /* Switch ports. */
    struct sw_port ports[DP_MAX_PORTS];
    struct sw_port *local_port;  /* OFPP_LOCAL port, if any. */
    struct list port_list; /* All ports, including local_port. */
};

int dp_new(struct datapath **, uint64_t dpid);
int dp_add_port(struct datapath *, const char *netdev);
int dp_add_local_port(struct datapath *, const char *netdev);
void dp_add_pvconn(struct datapath *, struct pvconn *);
void dp_run(struct datapath *);
void dp_wait(struct datapath *);
void dp_send_error_msg(struct datapath *, const struct sender *,
                  uint16_t, uint16_t, const void *, size_t);
void dp_send_flow_end(struct datapath *, struct sw_flow *,
                      enum nx_flow_end_reason);
void dp_output_port(struct datapath *, struct ofpbuf *, int in_port, 
        int out_port, bool ignore_no_fwd);
void dp_output_control(struct datapath *, struct ofpbuf *, int in_port,
        size_t max_len, int reason);

#endif /* datapath.h */
