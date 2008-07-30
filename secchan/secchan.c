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

/* Settings that may be configured by the user. */
struct settings {
    /* Overall mode of operation. */
    bool discovery;           /* Discover the controller automatically? */
    bool in_band;             /* Connect to controller in-band? */

    /* Related vconns and network devices. */
    const char *nl_name;        /* Local datapath (must be "nl:" vconn). */
    char *of_name;              /* ofX network device name. */
    const char *controller_name; /* Controller (if not discovery mode). */
    const char *listen_vconn_name; /* Listens for mgmt connections. */

    /* Failure behavior. */
    enum fail_mode fail_mode; /* Act as learning switch if no controller? */
    int max_idle;             /* Idle time for flows in fail-open mode. */
    int probe_interval;       /* # seconds idle before sending echo request. */
    int max_backoff;          /* Max # seconds between connection attempts. */

    /* Discovery behavior. */
    regex_t accept_controller_regex;  /* Controller vconns to accept. */
    const char *accept_controller_re; /* String version of regex. */
    bool update_resolv_conf;          /* Update /etc/resolv.conf? */
};

struct half {
    struct rconn *rconn;
    struct buffer *rxbuf;
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
    void *aux;
};

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
                             void *aux);

static struct discovery *discovery_init(const struct settings *);
static void discovery_question_connectivity(struct discovery *);
static bool discovery_run(struct discovery *, char **controller_name);
static void discovery_wait(struct discovery *);

static struct hook in_band_hook_create(const struct settings *);
static struct hook fail_open_hook_create(const struct settings *,
                                         struct rconn *local,
                                         struct rconn *remote);

static void modify_dhcp_request(struct dhcp_msg *, void *aux);
static bool validate_dhcp_offer(const struct dhcp_msg *, void *aux);

int
main(int argc, char *argv[])
{
    struct settings s;

    struct list relays = LIST_INITIALIZER(&relays);

    struct hook hooks[3];
    size_t n_hooks;

    struct rconn *local_rconn, *remote_rconn;
    struct vconn *listen_vconn;
    struct relay *controller_relay;
    struct discovery *discovery;
    int retval;

    set_program_name(argv[0]);
    register_fault_handlers();
    vlog_init();
    parse_options(argc, argv, &s);

    /* Start listening for management connections. */
    if (s.listen_vconn_name) {
        retval = vconn_open(s.listen_vconn_name, &listen_vconn);
        if (retval && retval != EAGAIN) {
            fatal(retval, "opening %s", s.listen_vconn_name);
        }
        if (!vconn_is_passive(listen_vconn)) {
            fatal(0, "%s is not a passive vconn", s.listen_vconn_name);
        }
    } else {
        listen_vconn = NULL;
    }

    /* Start controller discovery. */
    discovery = s.discovery ? discovery_init(&s) : NULL;

    /* Start listening for vlogconf requests. */
    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        fatal(retval, "Could not listen for vlog connections");
    }

    daemonize();

    /* Connect to datapath. */
    local_rconn = rconn_create(1, 0, s.max_backoff);
    rconn_connect(local_rconn, s.nl_name);

    /* Connect to controller. */
    remote_rconn = rconn_create(1, s.probe_interval, s.max_backoff);
    if (s.controller_name) {
        retval = rconn_connect(remote_rconn, s.controller_name);
        if (retval == EAFNOSUPPORT) {
            fatal(0, "No support for %s vconn", s.controller_name);
        }
    }

    /* Start relaying. */
    controller_relay = relay_create(local_rconn, remote_rconn, false);
    list_push_back(&relays, &controller_relay->node);

    /* Set up hooks. */
    n_hooks = 0;
    if (s.in_band) {
        hooks[n_hooks++] = in_band_hook_create(&s);
    }
    if (s.fail_mode == FAIL_OPEN) {
        hooks[n_hooks++] = fail_open_hook_create(&s,
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
        if (listen_vconn) {
            for (;;) {
                struct relay *r = relay_accept(&s, listen_vconn);
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
        if (listen_vconn) {
            vconn_accept_wait(listen_vconn);
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
          void *aux)
{
    struct hook h;
    h.packet_cb = packet_cb;
    h.periodic_cb = periodic_cb;
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
            VLOG_WARN("accept failed (%s)", strerror(retval));
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
        VLOG_ERR("could not connect to %s (%s)",
                 nl_name_without_subscription, strerror(retval));
        vconn_close(new_remote);
        free(nl_name_without_subscription);
        return NULL;
    }

    /* Create and return relay. */
    r1 = rconn_create(1, 0, 0);
    rconn_connect_unreliably(r1, nl_name_without_subscription, new_local);
    free(nl_name_without_subscription);

    r2 = rconn_create(1, 0, 0);
    rconn_connect_unreliably(r2, "passive", new_remote);

    return relay_create(r1, r2, true);
}

static struct relay *
relay_create(struct rconn *local, struct rconn *remote, bool is_mgmt_conn)
{
    struct relay *r;
    int i;

    r = xmalloc(sizeof *r);
    r->halves[HALF_LOCAL].rconn = local;
    r->halves[HALF_REMOTE].rconn = remote;
    for (i = 0; i < 2; i++) {
        r->halves[i].rxbuf = NULL;
    }
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

            if (this->rxbuf) {
                int retval = rconn_send(peer->rconn, this->rxbuf);
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
    uint8_t mac[ETH_ADDR_LEN];
};

static void
queue_tx(struct rconn *rc, struct buffer *b)
{
    if (rconn_force_send(rc, b)) {
        buffer_delete(b);
    }
}

static bool
is_controller_mac(const uint8_t dl_addr[ETH_ADDR_LEN], struct netdev *netdev,
                  struct rconn *controller)
{
    static uint32_t ip, last_nonzero_ip;
    static uint8_t mac[ETH_ADDR_LEN], last_nonzero_mac[ETH_ADDR_LEN];
    static time_t next_refresh = 0;

    uint32_t last_ip = ip;

    time_t now = time(0);

    ip = rconn_get_ip(controller);
    if (last_ip != ip || !next_refresh || now >= next_refresh) {
        bool have_mac;

        /* Look up MAC address. */
        memset(mac, 0, sizeof mac);
        if (ip) {
            int retval = netdev_arp_lookup(netdev, ip, mac);
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
    return !eth_addr_is_zero(mac) && eth_addr_equals(mac, dl_addr);
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

    if (half != HALF_LOCAL || r->is_mgmt_conn) {
        return false;
    }

    oh = msg->data;
    if (oh->type != OFPT_PACKET_IN) {
        return false;
    }
    if (msg->size < offsetof (struct ofp_packet_in, data)) {
        VLOG_WARN("packet too short (%zu bytes) for packet_in", msg->size);
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
    if (in_port == OFPP_LOCAL) {
        out_port = mac_learning_lookup(in_band->ml, flow.dl_dst);
    } else if (eth_addr_equals(flow.dl_dst, in_band->mac)) {
        out_port = OFPP_LOCAL;
        if (mac_learning_learn(in_band->ml, flow.dl_src, in_port)) {
            VLOG_DBG("learned that "ETH_ADDR_FMT" is on port %"PRIu16,
                     ETH_ADDR_ARGS(flow.dl_src), in_port);
        }
    } else if (flow.dl_type == htons(ETH_TYPE_ARP)
               && eth_addr_is_broadcast(flow.dl_dst)
               && is_controller_mac(flow.dl_src, in_band->of_device,
                                    r->halves[HALF_REMOTE].rconn)) {
        out_port = OFPP_FLOOD;
    } else {
        return false;
    }

    if (out_port != OFPP_FLOOD) {
        /* The output port is known, so add a new flow. */
        queue_tx(rc, make_add_simple_flow(&flow, ntohl(opi->buffer_id),
                                          out_port, in_band->s->max_idle));

        /* If the switch didn't buffer the packet, we need to send a copy. */
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            queue_tx(rc, make_unbuffered_packet_out(&pkt, in_port, out_port));
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
        queue_tx(rc, b);
    }
    return true;
}

static struct hook
in_band_hook_create(const struct settings *s)
{
    struct in_band_data *in_band;
    int retval;

    in_band = xmalloc(sizeof *in_band);
    in_band->s = s;
    in_band->ml = mac_learning_create();
    retval = netdev_open(s->of_name, NETDEV_ETH_TYPE_NONE,
                         &in_band->of_device);
    if (retval) {
        fatal(retval, "Could not open %s device", s->of_name);
    }
    memcpy(in_band->mac, netdev_get_etheraddr(in_band->of_device),
           ETH_ADDR_LEN);

    return make_hook(in_band_packet_cb, NULL, in_band);
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

static struct hook
fail_open_hook_create(const struct settings *s, struct rconn *local_rconn,
                      struct rconn *remote_rconn)
{
    struct fail_open_data *fail_open = xmalloc(sizeof *fail_open);
    fail_open->s = s;
    fail_open->local_rconn = local_rconn;
    fail_open->remote_rconn = remote_rconn;
    fail_open->lswitch = NULL;
    return make_hook(fail_open_packet_cb, fail_open_periodic_cb, fail_open);
}

/* Controller discovery. */

struct discovery
{
    const struct settings *s;
    struct dhclient *dhcp;
    bool ever_successful;
};

static struct discovery *
discovery_init(const struct settings *s)
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
    d->ever_successful = false;
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
        d->ever_successful = true;
    } else if (controller_name) {
        *controller_name = NULL;
        if (d->ever_successful) {
            VLOG_WARN("discovered controller no longer available");
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
        VLOG_WARN("rejecting DHCP offer missing controller vconn");
        return false;
    }
    accept = !regexec(&s->accept_controller_regex, vconn_name, 0, NULL, 0);
    if (!accept) {
        VLOG_WARN("rejecting controller vconn that fails to match %s",
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
        OPT_MAX_BACKOFF
    };
    static struct option long_options[] = {
        {"accept-vconn", required_argument, 0, OPT_ACCEPT_VCONN},
        {"no-resolv-conf", no_argument, 0, OPT_NO_RESOLV_CONF},
        {"fail",        required_argument, 0, 'f'},
        {"inactivity-probe", required_argument, 0, OPT_INACTIVITY_PROBE},
        {"max-idle",    required_argument, 0, OPT_MAX_IDLE},
        {"max-backoff", required_argument, 0, OPT_MAX_BACKOFF},
        {"listen",      required_argument, 0, 'l'},
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
    s->listen_vconn_name = NULL;
    s->fail_mode = FAIL_OPEN;
    s->max_idle = 15;
    s->probe_interval = 15;
    s->max_backoff = 15;
    s->update_resolv_conf = true;
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

        case 'D':
            set_detach();
            break;

        case 'P':
            set_pidfile(optarg);
            break;

        case 'l':
            if (s->listen_vconn_name) {
                fatal(0, "-l or --listen may be only specified once");
            }
            s->listen_vconn_name = optarg;
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
