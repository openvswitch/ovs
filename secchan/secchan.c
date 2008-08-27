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
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <regex.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "buffer.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dhcp.h"
#include "dhcp-client.h"
#include "dynamic-string.h"
#include "fault.h"
#include "flow.h"
#include "learning-switch.h"
#include "list.h"
#include "mac-learning.h"
#include "netdev.h"
#include "openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "rconn.h"
#include "timeval.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "vlog-socket.h"

#include "vlog.h"
#define THIS_MODULE VLM_secchan

/* Behavior when the connection to the controller fails. */
enum fail_mode {
    FAIL_OPEN,                  /* Act as learning switch. */
    FAIL_CLOSED                 /* Drop all packets. */
};

/* Maximum number of management connection listeners. */
#define MAX_MGMT 8

/* Settings that may be configured by the user. */
struct settings {
    /* Overall mode of operation. */
    bool discovery;           /* Discover the controller automatically? */
    bool in_band;             /* Connect to controller in-band? */

    /* Related vconns and network devices. */
    const char *nl_name;        /* Local datapath (must be "nl:" vconn). */
    char *of_name;              /* ofX network device name. */
    const char *controller_name; /* Controller (if not discovery mode). */
    const char *listener_names[MAX_MGMT]; /* Listen for mgmt connections. */
    size_t n_listeners;          /* Number of mgmt connection listeners. */

    /* Failure behavior. */
    enum fail_mode fail_mode; /* Act as learning switch if no controller? */
    int max_idle;             /* Idle time for flows in fail-open mode. */
    int probe_interval;       /* # seconds idle before sending echo request. */
    int max_backoff;          /* Max # seconds between connection attempts. */

    /* Packet-in rate-limiting. */
    int rate_limit;           /* Tokens added to bucket per second. */
    int burst_limit;          /* Maximum number token bucket size. */

    /* Discovery behavior. */
    regex_t accept_controller_regex;  /* Controller vconns to accept. */
    const char *accept_controller_re; /* String version of regex. */
    bool update_resolv_conf;          /* Update /etc/resolv.conf? */
};

struct half {
    struct rconn *rconn;
    struct buffer *rxbuf;
    int n_txq;                  /* No. of packets queued for tx on 'rconn'. */
};

struct relay {
    struct list node;

#define HALF_LOCAL 0
#define HALF_REMOTE 1
    struct half halves[2];

    bool is_mgmt_conn;
};

struct hook {
    bool (*packet_cb)(struct relay *, int half, void *aux);
    void (*periodic_cb)(void *aux);
    void (*wait_cb)(void *aux);
    void *aux;
};

static struct vlog_rate_limit vrl = VLOG_RATE_LIMIT_INIT(60, 60);

static void parse_options(int argc, char *argv[], struct settings *);
static void usage(void) NO_RETURN;

static struct relay *relay_create(struct rconn *local, struct rconn *remote,
                                  bool is_mgmt_conn);
static struct relay *relay_accept(const struct settings *, struct vconn *);
static void relay_run(struct relay *, const struct hook[], size_t n_hooks);
static void relay_wait(struct relay *);
static void relay_destroy(struct relay *);

static struct hook make_hook(bool (*packet_cb)(struct relay *, int, void *),
                             void (*periodic_cb)(void *),
                             void (*wait_cb)(void *),
                             void *aux);

struct switch_status;
struct status_reply;
static struct hook switch_status_hook_create(const struct settings *,
                                             struct switch_status **);
static void switch_status_register_category(struct switch_status *,
                                            const char *category,
                                            void (*cb)(struct status_reply *,
                                                       void *aux),
                                            void *aux);
static void status_reply_put(struct status_reply *, const char *, ...)
    PRINTF_FORMAT(2, 3);

static void rconn_status_cb(struct status_reply *, void *rconn_);

static struct discovery *discovery_init(const struct settings *,
                                        struct switch_status *);
static void discovery_question_connectivity(struct discovery *);
static bool discovery_run(struct discovery *, char **controller_name);
static void discovery_wait(struct discovery *);

static struct hook in_band_hook_create(const struct settings *,
                                       struct switch_status *,
                                       struct rconn *remote);
static struct hook fail_open_hook_create(const struct settings *,
                                         struct switch_status *,
                                         struct rconn *local,
                                         struct rconn *remote);
static struct hook rate_limit_hook_create(const struct settings *,
                                          struct switch_status *,
                                          struct rconn *local,
                                          struct rconn *remote);


static void modify_dhcp_request(struct dhcp_msg *, void *aux);
static bool validate_dhcp_offer(const struct dhcp_msg *, void *aux);

int
main(int argc, char *argv[])
{
    struct settings s;

    struct list relays = LIST_INITIALIZER(&relays);

    struct hook hooks[8];
    size_t n_hooks = 0;

    struct vconn *listeners[MAX_MGMT];
    size_t n_listeners;

    struct rconn *local_rconn, *remote_rconn;
    struct relay *controller_relay;
    struct discovery *discovery;
    struct switch_status *switch_status;
    int i;
    int retval;

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    parse_options(argc, argv, &s);
    signal(SIGPIPE, SIG_IGN);

    /* Start listening for management connections. */
    n_listeners = 0;
    for (i = 0; i < s.n_listeners; i++) {
        const char *name = s.listener_names[i];
        struct vconn *listener;
        retval = vconn_open(name, &listener);
        if (retval && retval != EAGAIN) {
            fatal(retval, "opening %s", name);
        }
        if (!vconn_is_passive(listener)) {
            fatal(0, "%s is not a passive vconn", name);
        }
        listeners[n_listeners++] = listener;
    }

    /* Initialize switch status hook. */
    hooks[n_hooks++] = switch_status_hook_create(&s, &switch_status);

    /* Start controller discovery. */
    discovery = s.discovery ? discovery_init(&s, switch_status) : NULL;

    /* Start listening for vlogconf requests. */
    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        fatal(retval, "Could not listen for vlog connections");
    }

    daemonize();

    VLOG_WARN("OpenFlow reference implementation version %s", VERSION);
    VLOG_WARN("OpenFlow protocol version 0x%02x", OFP_VERSION);

    /* Connect to datapath. */
    local_rconn = rconn_create(0, s.max_backoff);
    rconn_connect(local_rconn, s.nl_name);
    switch_status_register_category(switch_status, "local",
                                    rconn_status_cb, local_rconn);

    /* Connect to controller. */
    remote_rconn = rconn_create(s.probe_interval, s.max_backoff);
    if (s.controller_name) {
        retval = rconn_connect(remote_rconn, s.controller_name);
        if (retval == EAFNOSUPPORT) {
            fatal(0, "No support for %s vconn", s.controller_name);
        }
    }
    switch_status_register_category(switch_status, "remote",
                                    rconn_status_cb, remote_rconn);

    /* Start relaying. */
    controller_relay = relay_create(local_rconn, remote_rconn, false);
    list_push_back(&relays, &controller_relay->node);

    /* Set up hooks. */
    if (s.in_band) {
        hooks[n_hooks++] = in_band_hook_create(&s, switch_status,
                                               remote_rconn);
    }
    if (s.fail_mode == FAIL_OPEN) {
        hooks[n_hooks++] = fail_open_hook_create(&s, switch_status,
                                                 local_rconn, remote_rconn);
    }
    if (s.rate_limit) {
        hooks[n_hooks++] = rate_limit_hook_create(&s, switch_status,
                                                  local_rconn, remote_rconn);
    }
    assert(n_hooks <= ARRAY_SIZE(hooks));

    for (;;) {
        struct relay *r, *n;
        size_t i;

        /* Do work. */
        LIST_FOR_EACH_SAFE (r, n, struct relay, node, &relays) {
            relay_run(r, hooks, n_hooks);
        }
        for (i = 0; i < n_listeners; i++) {
            for (;;) {
                struct relay *r = relay_accept(&s, listeners[i]);
                if (!r) {
                    break;
                }
                list_push_back(&relays, &r->node);
            }
        }
        for (i = 0; i < n_hooks; i++) {
            if (hooks[i].periodic_cb) {
                hooks[i].periodic_cb(hooks[i].aux);
            }
        }
        if (s.discovery) {
            char *controller_name;
            if (rconn_is_connectivity_questionable(remote_rconn)) {
                discovery_question_connectivity(discovery);
            }
            if (discovery_run(discovery, &controller_name)) {
                if (controller_name) {
                    rconn_connect(remote_rconn, controller_name);
                } else {
                    rconn_disconnect(remote_rconn);
                }
            }
        }

        /* Wait for something to happen. */
        LIST_FOR_EACH (r, struct relay, node, &relays) {
            relay_wait(r);
        }
        for (i = 0; i < n_listeners; i++) {
            vconn_accept_wait(listeners[i]);
        }
        for (i = 0; i < n_hooks; i++) {
            if (hooks[i].wait_cb) {
                hooks[i].wait_cb(hooks[i].aux);
            }
        }
        if (discovery) {
            discovery_wait(discovery);
        }
        poll_block();
    }

    return 0;
}

static struct hook
make_hook(bool (*packet_cb)(struct relay *, int half, void *aux),
          void (*periodic_cb)(void *aux),
          void (*wait_cb)(void *aux),
          void *aux)
{
    struct hook h;
    h.packet_cb = packet_cb;
    h.periodic_cb = periodic_cb;
    h.wait_cb = wait_cb;
    h.aux = aux;
    return h;
}

/* OpenFlow message relaying. */

static struct relay *
relay_accept(const struct settings *s, struct vconn *listen_vconn)
{
    struct vconn *new_remote, *new_local;
    char *nl_name_without_subscription;
    struct rconn *r1, *r2;
    int retval;

    retval = vconn_accept(listen_vconn, &new_remote);
    if (retval) {
        if (retval != EAGAIN) {
            VLOG_WARN_RL(&vrl, "accept failed (%s)", strerror(retval));
        }
        return NULL;
    }

    /* nl:123 or nl:123:1 opens a netlink connection to local datapath 123.  We
     * only accept the former syntax in main().
     *
     * nl:123:0 opens a netlink connection to local datapath 123 without
     * obtaining a subscription for ofp_packet_in or ofp_flow_expired
     * messages.*/
    nl_name_without_subscription = xasprintf("%s:0", s->nl_name);
    retval = vconn_open(nl_name_without_subscription, &new_local);
    if (retval) {
        VLOG_ERR_RL(&vrl, "could not connect to %s (%s)",
                    nl_name_without_subscription, strerror(retval));
        vconn_close(new_remote);
        free(nl_name_without_subscription);
        return NULL;
    }

    /* Create and return relay. */
    r1 = rconn_create(0, 0);
    rconn_connect_unreliably(r1, nl_name_without_subscription, new_local);
    free(nl_name_without_subscription);

    r2 = rconn_create(0, 0);
    rconn_connect_unreliably(r2, "passive", new_remote);

    return relay_create(r1, r2, true);
}

static struct relay *
relay_create(struct rconn *local, struct rconn *remote, bool is_mgmt_conn)
{
    struct relay *r = xcalloc(1, sizeof *r);
    r->halves[HALF_LOCAL].rconn = local;
    r->halves[HALF_REMOTE].rconn = remote;
    r->is_mgmt_conn = is_mgmt_conn;
    return r;
}

static void
relay_run(struct relay *r, const struct hook hooks[], size_t n_hooks)
{
    int iteration;
    int i;

    for (i = 0; i < 2; i++) {
        rconn_run(r->halves[i].rconn);
    }

    /* Limit the number of iterations to prevent other tasks from starving. */
    for (iteration = 0; iteration < 50; iteration++) {
        bool progress = false;
        for (i = 0; i < 2; i++) {
            struct half *this = &r->halves[i];
            struct half *peer = &r->halves[!i];

            if (!this->rxbuf) {
                this->rxbuf = rconn_recv(this->rconn);
                if (this->rxbuf) {
                    const struct hook *h;
                    for (h = hooks; h < &hooks[n_hooks]; h++) {
                        if (h->packet_cb(r, i, h->aux)) {
                            buffer_delete(this->rxbuf);
                            this->rxbuf = NULL;
                            progress = true;
                            break;
                        }
                    }
                }
            }

            if (this->rxbuf && !this->n_txq) {
                int retval = rconn_send(peer->rconn, this->rxbuf,
                                        &this->n_txq);
                if (retval != EAGAIN) {
                    if (!retval) {
                        progress = true;
                    } else {
                        buffer_delete(this->rxbuf);
                    }
                    this->rxbuf = NULL;
                }
            }
        }
        if (!progress) {
            break;
        }
    }

    if (r->is_mgmt_conn) {
        for (i = 0; i < 2; i++) {
            struct half *this = &r->halves[i];
            if (!rconn_is_alive(this->rconn)) {
                relay_destroy(r);
                return;
            }
        }
    }
}

static void
relay_wait(struct relay *r)
{
    int i;

    for (i = 0; i < 2; i++) {
        struct half *this = &r->halves[i];

        rconn_run_wait(this->rconn);
        if (!this->rxbuf) {
            rconn_recv_wait(this->rconn);
        }
    }
}

static void
relay_destroy(struct relay *r)
{
    int i;

    list_remove(&r->node);
    for (i = 0; i < 2; i++) {
        struct half *this = &r->halves[i];
        rconn_destroy(this->rconn);
        buffer_delete(this->rxbuf);
    }
    free(r);
}

/* In-band control. */

struct in_band_data {
    const struct settings *s;
    struct mac_learning *ml;
    struct netdev *of_device;
    struct rconn *controller;
    uint8_t mac[ETH_ADDR_LEN];
    int n_queued;
};

static void
queue_tx(struct rconn *rc, struct in_band_data *in_band, struct buffer *b)
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
        if (ip) {
            int retval = netdev_arp_lookup(in_band->of_device, ip, mac);
            if (retval) {
                VLOG_DBG("cannot look up controller hw address ("IP_FMT"): %s",
                         IP_ARGS(&ip), strerror(retval));
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

static bool
in_band_packet_cb(struct relay *r, int half, void *in_band_)
{
    struct in_band_data *in_band = in_band_;
    struct rconn *rc = r->halves[HALF_LOCAL].rconn;
    struct buffer *msg = r->halves[HALF_LOCAL].rxbuf;
    struct ofp_packet_in *opi;
    struct ofp_header *oh;
    size_t pkt_ofs, pkt_len;
    struct buffer pkt;
    struct flow flow;
    uint16_t in_port, out_port;
    const uint8_t *controller_mac;

    if (half != HALF_LOCAL || r->is_mgmt_conn) {
        return false;
    }

    oh = msg->data;
    if (oh->type != OFPT_PACKET_IN) {
        return false;
    }
    if (msg->size < offsetof(struct ofp_packet_in, data)) {
        VLOG_WARN_RL(&vrl, "packet too short (%zu bytes) for packet_in",
                     msg->size);
        return false;
    }

    /* Extract flow data from 'opi' into 'flow'. */
    opi = msg->data;
    in_port = ntohs(opi->in_port);
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    pkt.data = opi->data;
    pkt.size = pkt_len;
    flow_extract(&pkt, in_port, &flow);

    /* Deal with local stuff. */
    controller_mac = get_controller_mac(in_band);
    if (in_port == OFPP_LOCAL) {
        /* Sent by secure channel. */
        out_port = mac_learning_lookup(in_band->ml, flow.dl_dst);
    } else if (eth_addr_equals(flow.dl_dst, in_band->mac)) {
        /* Sent to secure channel. */
        out_port = OFPP_LOCAL;
        if (mac_learning_learn(in_band->ml, flow.dl_src, in_port)) {
            VLOG_DBG_RL(&vrl, "learned that "ETH_ADDR_FMT" is on port %"PRIu16,
                        ETH_ADDR_ARGS(flow.dl_src), in_port);
        }
    } else if (flow.dl_type == htons(ETH_TYPE_ARP)
               && eth_addr_is_broadcast(flow.dl_dst)
               && is_controller_mac(flow.dl_src, in_band)) {
        /* ARP sent by controller. */
        out_port = OFPP_FLOOD;
    } else if (is_controller_mac(flow.dl_dst, in_band)
               && in_port == mac_learning_lookup(in_band->ml,
                                                 controller_mac)) {
        /* Drop controller traffic that arrives on the controller port. */
        queue_tx(rc, in_band, make_add_flow(&flow, ntohl(opi->buffer_id),
                                            in_band->s->max_idle, 0));
        return true;
    } else {
        return false;
    }

    if (out_port != OFPP_FLOOD) {
        /* The output port is known, so add a new flow. */
        queue_tx(rc, in_band,
                 make_add_simple_flow(&flow, ntohl(opi->buffer_id),
                                      out_port, in_band->s->max_idle));

        /* If the switch didn't buffer the packet, we need to send a copy. */
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            queue_tx(rc, in_band,
                     make_unbuffered_packet_out(&pkt, in_port, out_port));
        }
    } else {
        /* We don't know that MAC.  Send along the packet without setting up a
         * flow. */
        struct buffer *b;
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            b = make_unbuffered_packet_out(&pkt, in_port, out_port);
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

    if (netdev_get_in4(in_band->of_device, &local_ip)) {
        status_reply_put(sr, "local-ip="IP_FMT, IP_ARGS(&local_ip.s_addr));
    }
    status_reply_put(sr, "local-mac="ETH_ADDR_FMT,
                     ETH_ADDR_ARGS(in_band->mac));

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

static struct hook
in_band_hook_create(const struct settings *s, struct switch_status *ss,
                    struct rconn *remote)
{
    struct in_band_data *in_band;
    int retval;

    in_band = xcalloc(1, sizeof *in_band);
    in_band->s = s;
    in_band->ml = mac_learning_create();
    retval = netdev_open(s->of_name, NETDEV_ETH_TYPE_NONE,
                         &in_band->of_device);
    if (retval) {
        fatal(retval, "Could not open %s device", s->of_name);
    }
    memcpy(in_band->mac, netdev_get_etheraddr(in_band->of_device),
           ETH_ADDR_LEN);
    in_band->controller = remote;
    switch_status_register_category(ss, "in-band", in_band_status_cb, in_band);
    return make_hook(in_band_packet_cb, NULL, NULL, in_band);
}

/* Fail open support. */

struct fail_open_data {
    const struct settings *s;
    struct rconn *local_rconn;
    struct rconn *remote_rconn;
    struct lswitch *lswitch;
    int last_disconn_secs;
};

/* Causes 'r' to enter or leave fail-open mode, if appropriate. */
static void
fail_open_periodic_cb(void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    int disconn_secs;
    bool open;

    disconn_secs = rconn_disconnected_duration(fail_open->remote_rconn);
    open = disconn_secs >= fail_open->s->probe_interval * 3;
    if (open != (fail_open->lswitch != NULL)) {
        if (!open) {
            VLOG_WARN("No longer in fail-open mode");
            lswitch_destroy(fail_open->lswitch);
            fail_open->lswitch = NULL;
        } else {
            VLOG_WARN("Could not connect to controller for %d seconds, "
                      "failing open", disconn_secs);
            fail_open->lswitch = lswitch_create(fail_open->local_rconn, true,
                                                fail_open->s->max_idle);
            fail_open->last_disconn_secs = disconn_secs;
        }
    } else if (open && disconn_secs > fail_open->last_disconn_secs + 60) {
        VLOG_WARN("Still in fail-open mode after %d seconds disconnected "
                  "from controller", disconn_secs);
        fail_open->last_disconn_secs = disconn_secs;
    }
}

static bool
fail_open_packet_cb(struct relay *r, int half, void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    if (half != HALF_LOCAL || r->is_mgmt_conn || !fail_open->lswitch) {
        return false;
    } else {
        lswitch_process_packet(fail_open->lswitch, fail_open->local_rconn,
                               r->halves[HALF_LOCAL].rxbuf);
        rconn_run(fail_open->local_rconn);
        return true;
    }
}

static void
fail_open_status_cb(struct status_reply *sr, void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    const struct settings *s = fail_open->s;
    int trigger_duration = s->probe_interval * 3;
    int cur_duration = rconn_disconnected_duration(fail_open->remote_rconn);

    status_reply_put(sr, "trigger-duration=%d", trigger_duration);
    status_reply_put(sr, "current-duration=%d", cur_duration);
    status_reply_put(sr, "triggered=%s",
                     cur_duration >= trigger_duration ? "true" : "false");
    status_reply_put(sr, "max-idle=%d", s->max_idle);
}

static struct hook
fail_open_hook_create(const struct settings *s, struct switch_status *ss,
                      struct rconn *local_rconn, struct rconn *remote_rconn)
{
    struct fail_open_data *fail_open = xmalloc(sizeof *fail_open);
    fail_open->s = s;
    fail_open->local_rconn = local_rconn;
    fail_open->remote_rconn = remote_rconn;
    fail_open->lswitch = NULL;
    switch_status_register_category(ss, "fail-open",
                                    fail_open_status_cb, fail_open);
    return make_hook(fail_open_packet_cb, fail_open_periodic_cb, NULL,
                     fail_open);
}

struct rate_limiter {
    const struct settings *s;
    struct rconn *remote_rconn;

    /* One queue per physical port. */
    struct queue queues[OFPP_MAX];
    int n_queued;               /* Sum over queues[*].n. */
    int next_tx_port;           /* Next port to check in round-robin. */

    /* Token bucket.
     *
     * It costs 1000 tokens to send a single packet_in message.  A single token
     * per message would be more straightforward, but this choice lets us avoid
     * round-off error in refill_bucket()'s calculation of how many tokens to
     * add to the bucket, since no division step is needed. */
    long long int last_fill;    /* Time at which we last added tokens. */
    int tokens;                 /* Current number of tokens. */

    /* Transmission queue. */
    int n_txq;                  /* No. of packets waiting in rconn for tx. */

    /* Statistics reporting. */
    unsigned long long n_normal;        /* # txed w/o rate limit queuing. */
    unsigned long long n_limited;       /* # queued for rate limiting. */
    unsigned long long n_queue_dropped; /* # dropped due to queue overflow. */
    unsigned long long n_tx_dropped;    /* # dropped due to tx overflow. */
};

/* Drop a packet from the longest queue in 'rl'. */
static void
drop_packet(struct rate_limiter *rl)
{
    struct queue *longest;      /* Queue currently selected as longest. */
    int n_longest;              /* # of queues of same length as 'longest'. */
    struct queue *q;

    longest = &rl->queues[0];
    n_longest = 1;
    for (q = &rl->queues[0]; q < &rl->queues[OFPP_MAX]; q++) {
        if (longest->n < q->n) {
            longest = q;
            n_longest = 1;
        } else if (longest->n == q->n) {
            n_longest++;

            /* Randomly select one of the longest queues, with a uniform
             * distribution (Knuth algorithm 3.4.2R). */
            if (!random_range(n_longest)) {
                longest = q;
            }
        }
    }

    /* FIXME: do we want to pop the tail instead? */
    buffer_delete(queue_pop_head(longest));
    rl->n_queued--;
}

/* Remove and return the next packet to transmit (in round-robin order). */
static struct buffer *
dequeue_packet(struct rate_limiter *rl)
{
    unsigned int i;

    for (i = 0; i < OFPP_MAX; i++) {
        unsigned int port = (rl->next_tx_port + i) % OFPP_MAX;
        struct queue *q = &rl->queues[port];
        if (q->n) {
            rl->next_tx_port = (port + 1) % OFPP_MAX;
            rl->n_queued--;
            return queue_pop_head(q);
        }
    }
    NOT_REACHED();
}

/* Add tokens to the bucket based on elapsed time. */
static void
refill_bucket(struct rate_limiter *rl)
{
    const struct settings *s = rl->s;
    long long int now = time_msec();
    long long int tokens = (now - rl->last_fill) * s->rate_limit + rl->tokens;
    if (tokens >= 1000) {
        rl->last_fill = now;
        rl->tokens = MIN(tokens, s->burst_limit * 1000);
    }
}

/* Attempts to remove enough tokens from 'rl' to transmit a packet.  Returns
 * true if successful, false otherwise.  (In the latter case no tokens are
 * removed.) */
static bool
get_token(struct rate_limiter *rl)
{
    if (rl->tokens >= 1000) {
        rl->tokens -= 1000;
        return true;
    } else {
        return false;
    }
}

static bool
rate_limit_packet_cb(struct relay *r, int half, void *rl_)
{
    struct rate_limiter *rl = rl_;
    const struct settings *s = rl->s;
    struct buffer *msg = r->halves[HALF_LOCAL].rxbuf;
    struct ofp_header *oh;

    if (half == HALF_REMOTE) {
        return false;
    }

    oh = msg->data;
    if (oh->type != OFPT_PACKET_IN) {
        return false;
    }
    if (msg->size < offsetof(struct ofp_packet_in, data)) {
        VLOG_WARN_RL(&vrl, "packet too short (%zu bytes) for packet_in",
                     msg->size);
        return false;
    }

    if (!rl->n_queued && get_token(rl)) {
        /* In the common case where we are not constrained by the rate limit,
         * let the packet take the normal path. */
        rl->n_normal++;
        return false;
    } else {
        /* Otherwise queue it up for the periodic callback to drain out. */
        struct ofp_packet_in *opi = msg->data;
        int port = ntohs(opi->in_port) % OFPP_MAX;
        if (rl->n_queued >= s->burst_limit) {
            drop_packet(rl);
        }
        queue_push_tail(&rl->queues[port], buffer_clone(msg));
        rl->n_queued++;
        rl->n_limited++;
        return true;
    }
}

static void
rate_limit_status_cb(struct status_reply *sr, void *rl_)
{
    struct rate_limiter *rl = rl_;

    status_reply_put(sr, "normal=%llu", rl->n_normal);
    status_reply_put(sr, "limited=%llu", rl->n_limited);
    status_reply_put(sr, "queue-dropped=%llu", rl->n_queue_dropped);
    status_reply_put(sr, "tx-dropped=%llu", rl->n_tx_dropped);
}

static void
rate_limit_periodic_cb(void *rl_)
{
    struct rate_limiter *rl = rl_;
    int i;

    /* Drain some packets out of the bucket if possible, but limit the number
     * of iterations to allow other code to get work done too. */
    refill_bucket(rl);
    for (i = 0; rl->n_queued && get_token(rl) && i < 50; i++) {
        /* Use a small, arbitrary limit for the amount of queuing to do here,
         * because the TCP connection is responsible for buffering and there is
         * no point in trying to transmit faster than the TCP connection can
         * handle. */
        struct buffer *b = dequeue_packet(rl);
        if (rconn_send_with_limit(rl->remote_rconn, b, &rl->n_txq, 10)) {
            rl->n_tx_dropped++;
        }
    }
}

static void
rate_limit_wait_cb(void *rl_)
{
    struct rate_limiter *rl = rl_;
    if (rl->n_queued) {
        if (rl->tokens >= 1000) {
            /* We can transmit more packets as soon as we're called again. */
            poll_immediate_wake();
        } else {
            /* We have to wait for the bucket to re-fill.  We could calculate
             * the exact amount of time here for increased smoothness. */
            poll_timer_wait(TIME_UPDATE_INTERVAL / 2);
        }
    }
}

static struct hook
rate_limit_hook_create(const struct settings *s, struct switch_status *ss,
                       struct rconn *local, struct rconn *remote)
{
    struct rate_limiter *rl;
    size_t i;

    rl = xcalloc(1, sizeof *rl);
    rl->s = s;
    rl->remote_rconn = remote;
    for (i = 0; i < ARRAY_SIZE(rl->queues); i++) {
        queue_init(&rl->queues[i]);
    }
    rl->last_fill = time_msec();
    rl->tokens = s->rate_limit * 100;
    switch_status_register_category(ss, "rate-limit",
                                    rate_limit_status_cb, rl);
    return make_hook(rate_limit_packet_cb, rate_limit_periodic_cb,
                     rate_limit_wait_cb, rl);
}

/* OFPST_SWITCH statistics. */

struct switch_status_category {
    char *name;
    void (*cb)(struct status_reply *, void *aux);
    void *aux;
};

struct switch_status {
    const struct settings *s;
    time_t booted;
    struct switch_status_category categories[8];
    int n_categories;
};

struct status_reply {
    struct switch_status_category *category;
    struct ds request;
    struct ds output;
};

static bool
switch_status_packet_cb(struct relay *r, int half, void *ss_)
{
    struct switch_status *ss = ss_;
    struct rconn *rc = r->halves[HALF_REMOTE].rconn;
    struct buffer *msg = r->halves[HALF_REMOTE].rxbuf;
    struct switch_status_category *c;
    struct ofp_stats_request *osr;
    struct ofp_stats_reply *reply;
    struct status_reply sr;
    struct ofp_header *oh;
    struct buffer *b;
    int retval;

    if (half == HALF_LOCAL) {
        return false;
    }

    oh = msg->data;
    if (oh->type != OFPT_STATS_REQUEST) {
        return false;
    }
    if (msg->size < sizeof(struct ofp_stats_request)) {
        VLOG_WARN_RL(&vrl, "packet too short (%zu bytes) for stats_request",
                     msg->size);
        return false;
    }

    osr = msg->data;
    if (osr->type != htons(OFPST_SWITCH)) {
        return false;
    }

    sr.request.string = (void *) (osr + 1);
    sr.request.length = msg->size - sizeof *osr;
    ds_init(&sr.output);
    for (c = ss->categories; c < &ss->categories[ss->n_categories]; c++) {
        if (!memcmp(c->name, sr.request.string,
                    MIN(strlen(c->name), sr.request.length))) {
            sr.category = c;
            c->cb(&sr, c->aux);
        }
    }
    reply = make_openflow_xid((offsetof(struct ofp_stats_reply, body)
                               + sr.output.length),
                              OFPT_STATS_REPLY, osr->header.xid, &b);
    reply->type = htons(OFPST_SWITCH);
    reply->flags = 0;
    memcpy(reply->body, sr.output.string, sr.output.length);
    retval = rconn_send(rc, b, NULL);
    if (retval && retval != EAGAIN) {
        VLOG_WARN("send failed (%s)", strerror(retval));
    }
    ds_destroy(&sr.output);
    return true;
}

static void
rconn_status_cb(struct status_reply *sr, void *rconn_)
{
    struct rconn *rconn = rconn_;
    time_t now = time_now();

    status_reply_put(sr, "name=%s", rconn_get_name(rconn));
    status_reply_put(sr, "state=%s", rconn_get_state(rconn));
    status_reply_put(sr, "is-connected=%s",
                     rconn_is_connected(rconn) ? "true" : "false");
    status_reply_put(sr, "sent-msgs=%u", rconn_packets_sent(rconn));
    status_reply_put(sr, "received-msgs=%u", rconn_packets_received(rconn));
    status_reply_put(sr, "attempted-connections=%u",
                     rconn_get_attempted_connections(rconn));
    status_reply_put(sr, "successful-connections=%u",
                     rconn_get_successful_connections(rconn));
    status_reply_put(sr, "last-connection=%ld",
                     (long int) (now - rconn_get_last_connection(rconn)));
    status_reply_put(sr, "time-connected=%lu",
                     rconn_get_total_time_connected(rconn));
}

static void
config_status_cb(struct status_reply *sr, void *s_)
{
    const struct settings *s = s_;
    size_t i;

    for (i = 0; i < s->n_listeners; i++) {
        status_reply_put(sr, "management%zu=%s", i, s->listener_names[i]);
    }
    if (s->probe_interval) {
        status_reply_put(sr, "probe-interval=%d", s->probe_interval);
    }
    if (s->max_backoff) {
        status_reply_put(sr, "max-backoff=%d", s->max_backoff);
    }
}

static void
switch_status_cb(struct status_reply *sr, void *ss_)
{
    struct switch_status *ss = ss_;
    time_t now = time_now();

    status_reply_put(sr, "now=%ld", (long int) now);
    status_reply_put(sr, "uptime=%ld", (long int) (now - ss->booted));
    status_reply_put(sr, "pid=%ld", (long int) getpid());
}

static struct hook
switch_status_hook_create(const struct settings *s, struct switch_status **ssp)
{
    struct switch_status *ss = xcalloc(1, sizeof *ss);
    ss->s = s;
    ss->booted = time_now();
    switch_status_register_category(ss, "config",
                                    config_status_cb, (void *) s);
    switch_status_register_category(ss, "switch", switch_status_cb, ss);
    *ssp = ss;
    return make_hook(switch_status_packet_cb, NULL, NULL, ss);
}

static void
switch_status_register_category(struct switch_status *ss,
                                const char *category,
                                void (*cb)(struct status_reply *,
                                           void *aux),
                                void *aux)
{
    struct switch_status_category *c;
    assert(ss->n_categories < ARRAY_SIZE(ss->categories));
    c = &ss->categories[ss->n_categories++];
    c->cb = cb;
    c->aux = aux;
    c->name = xstrdup(category);
}

static void
status_reply_put(struct status_reply *sr, const char *content, ...)
{
    size_t old_length = sr->output.length;
    size_t added;
    va_list args;

    /* Append the status reply to the output. */
    ds_put_format(&sr->output, "%s.", sr->category->name);
    va_start(args, content);
    ds_put_format_valist(&sr->output, content, args);
    va_end(args);
    if (ds_last(&sr->output) != '\n') {
        ds_put_char(&sr->output, '\n');
    }

    /* Drop what we just added if it doesn't match the request. */
    added = sr->output.length - old_length;
    if (added < sr->request.length
        || memcmp(&sr->output.string[old_length],
                  sr->request.string, sr->request.length)) {
        ds_truncate(&sr->output, old_length);
    }
}


/* Controller discovery. */

struct discovery
{
    const struct settings *s;
    struct dhclient *dhcp;
    int n_changes;
};

static void
discovery_status_cb(struct status_reply *sr, void *d_)
{
    struct discovery *d = d_;

    status_reply_put(sr, "discovery.accept-remote=%s",
                     d->s->accept_controller_re);
    status_reply_put(sr, "discovery.n-changes=%d", d->n_changes);
    status_reply_put(sr, "discovery.state=%s", dhclient_get_state(d->dhcp));
    status_reply_put(sr, "discovery.state-elapsed=%u",
                     dhclient_get_state_elapsed(d->dhcp));
    if (dhclient_is_bound(d->dhcp)) {
        uint32_t ip = dhclient_get_ip(d->dhcp);
        uint32_t netmask = dhclient_get_netmask(d->dhcp);
        uint32_t router = dhclient_get_router(d->dhcp);

        const struct dhcp_msg *cfg = dhclient_get_config(d->dhcp);
        uint32_t dns_server;
        char *domain_name;
        int i;

        status_reply_put(sr, "discovery.ip="IP_FMT, IP_ARGS(&ip));
        status_reply_put(sr, "discovery.netmask="IP_FMT, IP_ARGS(&netmask));
        if (router) {
            status_reply_put(sr, "discovery.router="IP_FMT, IP_ARGS(&router));
        }

        for (i = 0; dhcp_msg_get_ip(cfg, DHCP_CODE_DNS_SERVER, i, &dns_server);
             i++) {
            status_reply_put(sr, "discovery.dns%d="IP_FMT,
                             i, IP_ARGS(&dns_server));
        }

        domain_name = dhcp_msg_get_string(cfg, DHCP_CODE_DOMAIN_NAME);
        if (domain_name) {
            status_reply_put(sr, "discovery.domain=%s", domain_name);
            free(domain_name);
        }

        status_reply_put(sr, "discovery.lease-remaining=%u",
                         dhclient_get_lease_remaining(d->dhcp));
    }
}

static struct discovery *
discovery_init(const struct settings *s, struct switch_status *ss)
{
    struct netdev *netdev;
    struct discovery *d;
    struct dhclient *dhcp;
    int retval;

    /* Bring ofX network device up. */
    retval = netdev_open(s->of_name, NETDEV_ETH_TYPE_NONE, &netdev);
    if (retval) {
        fatal(retval, "Could not open %s device", s->of_name);
    }
    retval = netdev_turn_flags_on(netdev, NETDEV_UP, true);
    if (retval) {
        fatal(retval, "Could not bring %s device up", s->of_name);
    }
    netdev_close(netdev);

    /* Initialize DHCP client. */
    retval = dhclient_create(s->of_name, modify_dhcp_request,
                             validate_dhcp_offer, (void *) s, &dhcp);
    if (retval) {
        fatal(retval, "Failed to initialize DHCP client");
    }
    dhclient_init(dhcp, 0);

    d = xmalloc(sizeof *d);
    d->s = s;
    d->dhcp = dhcp;
    d->n_changes = 0;

    switch_status_register_category(ss, "discovery", discovery_status_cb, d);

    return d;
}

static void
discovery_question_connectivity(struct discovery *d)
{
    dhclient_force_renew(d->dhcp, 15);
}

static bool
discovery_run(struct discovery *d, char **controller_name)
{
    dhclient_run(d->dhcp);
    if (!dhclient_changed(d->dhcp)) {
        return false;
    }

    dhclient_configure_netdev(d->dhcp);
    if (d->s->update_resolv_conf) {
        dhclient_update_resolv_conf(d->dhcp);
    }

    if (dhclient_is_bound(d->dhcp)) {
        *controller_name = dhcp_msg_get_string(dhclient_get_config(d->dhcp),
                                               DHCP_CODE_OFP_CONTROLLER_VCONN);
        VLOG_WARN("%s: discovered controller", *controller_name);
        d->n_changes++;
    } else {
        *controller_name = NULL;
        if (d->n_changes) {
            VLOG_WARN("discovered controller no longer available");
            d->n_changes++;
        }
    }
    return true;
}

static void
discovery_wait(struct discovery *d)
{
    dhclient_wait(d->dhcp);
}

static void
modify_dhcp_request(struct dhcp_msg *msg, void *aux)
{
    dhcp_msg_put_string(msg, DHCP_CODE_VENDOR_CLASS, "OpenFlow");
}

static bool
validate_dhcp_offer(const struct dhcp_msg *msg, void *s_)
{
    const struct settings *s = s_;
    char *vconn_name;
    bool accept;

    vconn_name = dhcp_msg_get_string(msg, DHCP_CODE_OFP_CONTROLLER_VCONN);
    if (!vconn_name) {
        VLOG_WARN_RL(&vrl, "rejecting DHCP offer missing controller vconn");
        return false;
    }
    accept = !regexec(&s->accept_controller_regex, vconn_name, 0, NULL, 0);
    if (!accept) {
        VLOG_WARN_RL(&vrl, "rejecting controller vconn that fails to match %s",
                     s->accept_controller_re);
    }
    free(vconn_name);
    return accept;
}

/* User interface. */

static void
parse_options(int argc, char *argv[], struct settings *s)
{
    enum {
        OPT_ACCEPT_VCONN = UCHAR_MAX + 1,
        OPT_NO_RESOLV_CONF,
        OPT_INACTIVITY_PROBE,
        OPT_MAX_IDLE,
        OPT_MAX_BACKOFF,
        OPT_RATE_LIMIT,
        OPT_BURST_LIMIT
    };
    static struct option long_options[] = {
        {"accept-vconn", required_argument, 0, OPT_ACCEPT_VCONN},
        {"no-resolv-conf", no_argument, 0, OPT_NO_RESOLV_CONF},
        {"fail",        required_argument, 0, 'f'},
        {"inactivity-probe", required_argument, 0, OPT_INACTIVITY_PROBE},
        {"max-idle",    required_argument, 0, OPT_MAX_IDLE},
        {"max-backoff", required_argument, 0, OPT_MAX_BACKOFF},
        {"listen",      required_argument, 0, 'l'},
        {"rate-limit",  optional_argument, 0, OPT_RATE_LIMIT},
        {"burst-limit", required_argument, 0, OPT_BURST_LIMIT},
        {"detach",      no_argument, 0, 'D'},
        {"pidfile",     optional_argument, 0, 'P'},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        VCONN_SSL_LONG_OPTIONS
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);
    char *accept_re = NULL;
    int retval;

    /* Set defaults that we can figure out before parsing options. */
    s->n_listeners = 0;
    s->fail_mode = FAIL_OPEN;
    s->max_idle = 15;
    s->probe_interval = 15;
    s->max_backoff = 15;
    s->update_resolv_conf = true;
    s->rate_limit = 0;
    s->burst_limit = 0;
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_ACCEPT_VCONN:
            accept_re = optarg[0] == '^' ? optarg : xasprintf("^%s", optarg);
            break;

        case OPT_NO_RESOLV_CONF:
            s->update_resolv_conf = false;
            break;

        case 'f':
            if (!strcmp(optarg, "open")) {
                s->fail_mode = FAIL_OPEN;
            } else if (!strcmp(optarg, "closed")) {
                s->fail_mode = FAIL_CLOSED;
            } else {
                fatal(0,
                      "-f or --fail argument must be \"open\" or \"closed\"");
            }
            break;

        case OPT_INACTIVITY_PROBE:
            s->probe_interval = atoi(optarg);
            if (s->probe_interval < 5) {
                fatal(0, "--inactivity-probe argument must be at least 5");
            }
            break;

        case OPT_MAX_IDLE:
            if (!strcmp(optarg, "permanent")) {
                s->max_idle = OFP_FLOW_PERMANENT;
            } else {
                s->max_idle = atoi(optarg);
                if (s->max_idle < 1 || s->max_idle > 65535) {
                    fatal(0, "--max-idle argument must be between 1 and "
                          "65535 or the word 'permanent'");
                }
            }
            break;

        case OPT_MAX_BACKOFF:
            s->max_backoff = atoi(optarg);
            if (s->max_backoff < 1) {
                fatal(0, "--max-backoff argument must be at least 1");
            } else if (s->max_backoff > 3600) {
                s->max_backoff = 3600;
            }
            break;

        case OPT_RATE_LIMIT:
            if (optarg) {
                s->rate_limit = atoi(optarg);
                if (s->rate_limit < 1) {
                    fatal(0, "--rate-limit argument must be at least 1");
                }
            } else {
                s->rate_limit = 1000;
            }
            break;

        case OPT_BURST_LIMIT:
            s->burst_limit = atoi(optarg);
            if (s->burst_limit < 1) {
                fatal(0, "--burst-limit argument must be at least 1");
            }
            break;

        case 'D':
            set_detach();
            break;

        case 'P':
            set_pidfile(optarg);
            break;

        case 'l':
            if (s->n_listeners >= MAX_MGMT) {
                fatal(0, "-l or --listen may be specified at most %d times",
                      MAX_MGMT);
            }
            s->listener_names[s->n_listeners++] = optarg;
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

    argc -= optind;
    argv += optind;
    if (argc < 1 || argc > 2) {
        fatal(0, "need one or two non-option arguments; use --help for usage");
    }

    /* Local and remote vconns. */
    s->nl_name = argv[0];
    if (strncmp(s->nl_name, "nl:", 3)
        || strlen(s->nl_name) < 4
        || s->nl_name[strspn(s->nl_name + 3, "0123456789") + 3]) {
        fatal(0, "%s: argument is not of the form \"nl:DP_IDX\"", s->nl_name);
    }
    s->of_name = xasprintf("of%s", s->nl_name + 3);
    s->controller_name = argc > 1 ? xstrdup(argv[1]) : NULL;

    /* Set accept_controller_regex. */
    if (!accept_re) {
        accept_re = vconn_ssl_is_configured() ? "^ssl:.*" : ".*";
    }
    retval = regcomp(&s->accept_controller_regex, accept_re,
                     REG_NOSUB | REG_EXTENDED);
    if (retval) {
        size_t length = regerror(retval, &s->accept_controller_regex, NULL, 0);
        char *buffer = xmalloc(length);
        regerror(retval, &s->accept_controller_regex, buffer, length);
        fatal(0, "%s: %s", accept_re, buffer);
    }
    s->accept_controller_re = accept_re;

    /* Mode of operation. */
    s->discovery = s->controller_name == NULL;
    if (s->discovery) {
        s->in_band = true;
    } else {
        enum netdev_flags flags;
        struct netdev *netdev;

        retval = netdev_open(s->of_name, NETDEV_ETH_TYPE_NONE, &netdev);
        if (retval) {
            fatal(retval, "Could not open %s device", s->of_name);
        }

        retval = netdev_get_flags(netdev, &flags);
        if (retval) {
            fatal(retval, "Could not get flags for %s device", s->of_name);
        }

        s->in_band = (flags & NETDEV_UP) != 0;
        if (s->in_band && netdev_get_in6(netdev, NULL)) {
            VLOG_WARN("Ignoring IPv6 address on %s device: IPv6 not supported",
                      s->of_name);
        }

        netdev_close(netdev);
    }

    /* Rate limiting. */
    if (s->rate_limit) {
        if (s->rate_limit < 100) {
            VLOG_WARN("Rate limit set to unusually low value %d",
                      s->rate_limit);
        }
        if (!s->burst_limit) {
            s->burst_limit = s->rate_limit / 4;
        }
        s->burst_limit = MAX(s->burst_limit, 1);
        s->burst_limit = MIN(s->burst_limit, INT_MAX / 1000);
    }
}

static void
usage(void)
{
    printf("%s: secure channel, a relay for OpenFlow messages.\n"
           "usage: %s [OPTIONS] nl:DP_IDX [CONTROLLER]\n"
           "where nl:DP_IDX is a datapath that has been added with dpctl.\n"
           "CONTROLLER is an active OpenFlow connection method; if it is\n"
           "omitted, then secchan performs controller discovery.\n",
           program_name, program_name);
    vconn_usage(true, true);
    printf("\nController discovery options:\n"
           "  --accept-vconn=REGEX    accept matching discovered controllers\n"
           "  --no-resolv-conf        do not update /etc/resolv.conf\n"
           "\nNetworking options:\n"
           "  -f, --fail=open|closed  when controller connection fails:\n"
           "                            closed: drop all packets\n"
           "                            open (default): act as learning switch\n"
           "  --inactivity-probe=SECS time between inactivity probes\n"
           "  --max-idle=SECS         max idle for flows set up by secchan\n"
           "  --max-backoff=SECS      max time between controller connection\n"
           "                          attempts (default: 15 seconds)\n"
           "  -l, --listen=METHOD     allow management connections on METHOD\n"
           "                          (a passive OpenFlow connection method)\n"
           "\nRate-limiting of \"packet-in\" messages to the controller:\n"
           "  --rate-limit[=PACKETS]  max rate, in packets/s (default: 1000)\n"
           "  --burst-limit=BURST     limit on packet credit for idle time\n"
           "\nOther options:\n"
           "  -D, --detach            run in background as daemon\n"
           "  -P, --pidfile[=FILE]    create pidfile (default: %s/secchan.pid)\n"
           "  -v, --verbose=MODULE[:FACILITY[:LEVEL]]  set logging levels\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n",
           RUNDIR);
    exit(EXIT_SUCCESS);
}
