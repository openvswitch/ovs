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

#include <config.h>
#include "in-band.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include "flow.h"
#include "mac-learning.h"
#include "netdev.h"
#include "ofpbuf.h"
#include "openflow.h"
#include "packets.h"
#include "port-watcher.h"
#include "rconn.h"
#include "secchan.h"
#include "status.h"
#include "timeval.h"
#include "vconn.h"

#define THIS_MODULE VLM_in_band
#include "vlog.h"

struct in_band_data {
    const struct settings *s;
    struct mac_learning *ml;
    struct netdev *of_device;
    struct rconn *controller;
    int n_queued;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static void
queue_tx(struct rconn *rc, struct in_band_data *in_band, struct ofpbuf *b)
{
    rconn_send_with_limit(rc, b, &in_band->n_queued, 10);
}

static const uint8_t *
get_controller_mac(struct in_band_data *in_band)
{
    static uint32_t ip, last_nonzero_ip;
    static uint8_t mac[ETH_ADDR_LEN], last_nonzero_mac[ETH_ADDR_LEN];
    static time_t next_refresh = 0;

    uint32_t last_ip = ip;

    time_t now = time_now();

    ip = rconn_get_ip(in_band->controller);
    if (last_ip != ip || !next_refresh || now >= next_refresh) {
        bool have_mac;

        /* Look up MAC address. */
        memset(mac, 0, sizeof mac);
        if (ip && in_band->of_device) {
            int retval = netdev_arp_lookup(in_band->of_device, ip, mac);
            if (retval) {
                VLOG_DBG_RL(&rl, "cannot look up controller hw address "
                            "("IP_FMT"): %s", IP_ARGS(&ip), strerror(retval));
            }
        }
        have_mac = !eth_addr_is_zero(mac);

        /* Log changes in IP, MAC addresses. */
        if (ip && ip != last_nonzero_ip) {
            VLOG_DBG("controller IP address changed from "IP_FMT
                     " to "IP_FMT, IP_ARGS(&last_nonzero_ip), IP_ARGS(&ip));
            last_nonzero_ip = ip;
        }
        if (have_mac && memcmp(last_nonzero_mac, mac, ETH_ADDR_LEN)) {
            VLOG_DBG("controller MAC address changed from "ETH_ADDR_FMT" to "
                     ETH_ADDR_FMT,
                     ETH_ADDR_ARGS(last_nonzero_mac), ETH_ADDR_ARGS(mac));
            memcpy(last_nonzero_mac, mac, ETH_ADDR_LEN);
        }

        /* Schedule next refresh.
         *
         * If we have an IP address but not a MAC address, then refresh
         * quickly, since we probably will get a MAC address soon (via ARP).
         * Otherwise, we can afford to wait a little while. */
        next_refresh = now + (!ip || have_mac ? 10 : 1);
    }
    return !eth_addr_is_zero(mac) ? mac : NULL;
}

static bool
is_controller_mac(const uint8_t dl_addr[ETH_ADDR_LEN],
                  struct in_band_data *in_band)
{
    const uint8_t *mac = get_controller_mac(in_band);
    return mac && eth_addr_equals(mac, dl_addr);
}

static void
in_band_learn_mac(struct in_band_data *in_band,
                  uint16_t in_port, const uint8_t src_mac[ETH_ADDR_LEN])
{
    if (mac_learning_learn(in_band->ml, src_mac, in_port)) {
        VLOG_DBG_RL(&rl, "learned that "ETH_ADDR_FMT" is on port %"PRIu16,
                    ETH_ADDR_ARGS(src_mac), in_port);
    }
}

static bool
in_band_local_packet_cb(struct relay *r, void *in_band_)
{
    struct in_band_data *in_band = in_band_;
    struct rconn *rc = r->halves[HALF_LOCAL].rconn;
    struct ofp_packet_in *opi;
    struct eth_header *eth;
    struct ofpbuf payload;
    struct flow flow;
    uint16_t in_port;
    int out_port;

    if (!get_ofp_packet_eth_header(r, &opi, &eth) || !in_band->of_device) {
        return false;
    }
    in_port = ntohs(opi->in_port);

    /* Deal with local stuff. */
    if (in_port == OFPP_LOCAL) {
        /* Sent by secure channel. */
        out_port = mac_learning_lookup(in_band->ml, eth->eth_dst);
    } else if (eth_addr_equals(eth->eth_dst,
                               netdev_get_etheraddr(in_band->of_device))) {
        /* Sent to secure channel. */
        out_port = OFPP_LOCAL;
        in_band_learn_mac(in_band, in_port, eth->eth_src);
    } else if (eth->eth_type == htons(ETH_TYPE_ARP)
               && eth_addr_is_broadcast(eth->eth_dst)
               && is_controller_mac(eth->eth_src, in_band)) {
        /* ARP sent by controller. */
        out_port = OFPP_FLOOD;
    } else if (is_controller_mac(eth->eth_dst, in_band)
               || is_controller_mac(eth->eth_src, in_band)) {
        /* Traffic to or from controller.  Switch it by hand. */
        in_band_learn_mac(in_band, in_port, eth->eth_src);
        out_port = mac_learning_lookup(in_band->ml, eth->eth_dst);
    } else {
        const uint8_t *controller_mac;
        controller_mac = get_controller_mac(in_band);
        if (eth->eth_type == htons(ETH_TYPE_ARP)
            && eth_addr_is_broadcast(eth->eth_dst)
            && is_controller_mac(eth->eth_src, in_band)) {
            /* ARP sent by controller. */
            out_port = OFPP_FLOOD;
        } else if (is_controller_mac(eth->eth_dst, in_band)
                   && in_port == mac_learning_lookup(in_band->ml,
                                                     controller_mac)) {
            /* Drop controller traffic that arrives on the controller port. */
            out_port = -1;
        } else {
            return false;
        }
    }

    get_ofp_packet_payload(opi, &payload);
    flow_extract(&payload, in_port, &flow);
    if (in_port == out_port) {
        /* The input and output port match.  Set up a flow to drop packets. */
        queue_tx(rc, in_band, make_add_flow(&flow, ntohl(opi->buffer_id),
                                          in_band->s->max_idle, 0));
    } else if (out_port != OFPP_FLOOD) {
        /* The output port is known, so add a new flow. */
        queue_tx(rc, in_band,
                 make_add_simple_flow(&flow, ntohl(opi->buffer_id),
                                      out_port, in_band->s->max_idle));

        /* If the switch didn't buffer the packet, we need to send a copy. */
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            queue_tx(rc, in_band,
                     make_unbuffered_packet_out(&payload, in_port, out_port));
        }
    } else {
        /* We don't know that MAC.  Send along the packet without setting up a
         * flow. */
        struct ofpbuf *b;
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            b = make_unbuffered_packet_out(&payload, in_port, out_port);
        } else {
            b = make_buffered_packet_out(ntohl(opi->buffer_id),
                                         in_port, out_port);
        }
        queue_tx(rc, in_band, b);
    }
    return true;
}

static void
in_band_status_cb(struct status_reply *sr, void *in_band_)
{
    struct in_band_data *in_band = in_band_;
    struct in_addr local_ip;
    uint32_t controller_ip;
    const uint8_t *controller_mac;

    if (in_band->of_device) {
        const uint8_t *mac = netdev_get_etheraddr(in_band->of_device);
        if (netdev_get_in4(in_band->of_device, &local_ip)) {
            status_reply_put(sr, "local-ip="IP_FMT, IP_ARGS(&local_ip.s_addr));
        }
        status_reply_put(sr, "local-mac="ETH_ADDR_FMT, ETH_ADDR_ARGS(mac));

        controller_ip = rconn_get_ip(in_band->controller);
        if (controller_ip) {
            status_reply_put(sr, "controller-ip="IP_FMT,
                             IP_ARGS(&controller_ip));
        }
        controller_mac = get_controller_mac(in_band);
        if (controller_mac) {
            status_reply_put(sr, "controller-mac="ETH_ADDR_FMT,
                             ETH_ADDR_ARGS(controller_mac));
        }
    }
}

void
get_ofp_packet_payload(struct ofp_packet_in *opi, struct ofpbuf *payload)
{
    payload->data = opi->data;
    payload->size = ntohs(opi->header.length) - offsetof(struct ofp_packet_in,
                                                         data);
}

static void
in_band_local_port_cb(const struct ofp_phy_port *port, void *in_band_)
{
    struct in_band_data *in_band = in_band_;
    if (port) {
        char name[sizeof port->name + 1];
        get_port_name(port, name, sizeof name);

        if (!in_band->of_device
            || strcmp(netdev_get_name(in_band->of_device), name))
        {
            int error;
            netdev_close(in_band->of_device);
            error = netdev_open(name, NETDEV_ETH_TYPE_NONE,
                                &in_band->of_device);
            if (error) {
                VLOG_ERR("failed to open in-band control network device "
                         "\"%s\": %s", name, strerror(errno));
            }
        }
    } else {
        netdev_close(in_band->of_device);
        in_band->of_device = NULL;
    }
}

struct hook
in_band_hook_create(const struct settings *s, struct switch_status *ss,
                    struct port_watcher *pw, struct rconn *remote)
{
    struct in_band_data *in_band;

    in_band = xcalloc(1, sizeof *in_band);
    in_band->s = s;
    in_band->ml = mac_learning_create();
    in_band->of_device = NULL;
    in_band->controller = remote;
    switch_status_register_category(ss, "in-band", in_band_status_cb, in_band);
    port_watcher_register_local_port_callback(pw, in_band_local_port_cb,
                                              in_band);
    return make_hook(in_band_local_packet_cb, NULL, NULL, NULL, in_band);
}
