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

static const char *listen_vconn_name;

struct half {
    struct rconn *rconn;
    struct buffer *rxbuf;
};

/* Behavior when the connection to the controller fails. */
enum fail_mode {
    FAIL_OPEN,                  /* Act as learning switch. */
    FAIL_CLOSED                 /* Drop all packets. */
};

struct relay {
    struct list node;

#define HALF_LOCAL 0
#define HALF_REMOTE 1
    struct half halves[2];

    bool is_mgmt_conn;
    struct lswitch *lswitch;
};

static struct list relays = LIST_INITIALIZER(&relays);

/* Mode of operation.  Note that autodiscovery implies in-band
 * communication. */
static bool autodiscovery;      /* Discover the controller automatically? */
static bool in_band;            /* Connect to controller in-band? */

/* MAC address of local port. */
static uint8_t local_mac[ETH_ADDR_LEN];

/* MAC learning table for local port. */
static struct mac_learning *local_ml;

/* Controller vconn name, or null to perform controller autodiscovery. */
static char *controller_name = NULL;

/* -f, --fail: Behavior when the connection to the controller fails. */
static enum fail_mode fail_mode = FAIL_OPEN;

/* The OpenFlow virtual network device ofX. */
static struct netdev *of_device;

/* --inactivity-probe: Number of seconds without receiving a message from the
   controller before sending an inactivity probe. */
static int probe_interval = 15;

/* --max-idle: Idle time to assign to flows created by learning switch when in
 * fail-open mode. */
static int max_idle = 15;

/* --max-backoff: Maximum interval between controller connection attempts, in
 * seconds. */
static int max_backoff = 15;

/* DHCP client, for controller autodiscovery. */
static struct dhclient *dhcp;

/* --accept-vconn: Regular expression specifying the class of controller vconns
 * that we will accept during autodiscovery. */
static const char *accept_controller_re;
static regex_t accept_controller_regex;

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static void new_management_connection(const char *nl_name, struct vconn *new_remote);
static struct relay *relay_create(struct rconn *local, struct rconn *remote,
                                  bool is_mgmt_conn);
static void relay_run(struct relay *);
static void relay_wait(struct relay *);
static void relay_destroy(struct relay *);

static bool local_hook(struct relay *r);
static bool failing_open(struct relay *r);
static bool fail_open_hook(struct relay *r);

static void modify_dhcp_request(struct dhcp_msg *, void *aux);
static bool validate_dhcp_offer(const struct dhcp_msg *, void *aux);

int
main(int argc, char *argv[])
{
    struct rconn *local_rconn, *remote_rconn;
    struct vconn *listen_vconn;
    struct relay *controller_relay;
    const char *nl_name;
    char of_name[16];
    int retval;

    set_program_name(argv[0]);
    register_fault_handlers();
    vlog_init();
    parse_options(argc, argv);

    argc -= optind;
    argv += optind;
    if (argc < 1 || argc > 2) {
        fatal(0, "need one or two non-option arguments; use --help for usage");
    }
    nl_name = argv[0];
    if (strncmp(nl_name, "nl:", 3)
        || strlen(nl_name) < 4
        || nl_name[strspn(nl_name + 3, "0123456789") + 3]) {
        fatal(0, "%s: argument is not of the form \"nl:DP_IDX\"", nl_name);
    }
    controller_name = argc > 1 ? xstrdup(argv[1]) : NULL;
    autodiscovery = controller_name == NULL;

    if (!accept_controller_re) {
        accept_controller_re = vconn_ssl_is_configured() ? "^ssl:.*" : ".*";
    }
    retval = regcomp(&accept_controller_regex, accept_controller_re,
                     REG_NOSUB | REG_EXTENDED);
    if (retval) {
        size_t length = regerror(retval, &accept_controller_regex, NULL, 0);
        char *buffer = xmalloc(length);
        regerror(retval, &accept_controller_regex, buffer, length);
        fatal(0, "%s: %s", accept_controller_re, buffer);
    }

    if (listen_vconn_name) {
        retval = vconn_open(listen_vconn_name, &listen_vconn);
        if (retval && retval != EAGAIN) {
            fatal(retval, "opening %s", listen_vconn_name);
        }
        if (!vconn_is_passive(listen_vconn)) {
            fatal(0, "%s is not a passive vconn", listen_vconn_name);
        }
    } else {
        listen_vconn = NULL;
    }

    snprintf(of_name, sizeof of_name, "of%s", nl_name + 3);
    retval = netdev_open(of_name, NETDEV_ETH_TYPE_NONE, &of_device);
    if (!retval) {
        enum netdev_flags flags;

        if (autodiscovery) {
            retval = netdev_turn_flags_on(of_device, NETDEV_UP, true);
            if (retval) {
                fatal(retval, "Could not bring %s device up", of_name);
            }
        }

        retval = netdev_get_flags(of_device, &flags);
        if (!retval) {
            if (flags & NETDEV_UP) {
                struct in6_addr in6;

                in_band = true;
                memcpy(local_mac, netdev_get_etheraddr(of_device),
                       ETH_ADDR_LEN);
                if (netdev_get_in6(of_device, &in6)) {
                    VLOG_WARN("Ignoring IPv6 address on %s device: "
                              "IPv6 not supported", of_name);
                }
                local_ml = mac_learning_create();
            } 
        } else {
            error(retval, "Could not get flags for %s device", of_name);
        }
    } else {
        error(retval, "Could not open %s device", of_name);
    }
    if (autodiscovery && !in_band) {
        fatal(retval, "In autodiscovery mode but failed to configure "
              "in-band control");
    }

    if (autodiscovery) {
        retval = dhclient_create(of_name, modify_dhcp_request,
                                 validate_dhcp_offer, NULL, &dhcp);
        if (retval) {
            fatal(retval, "Failed to initialize DHCP client");
        }
        dhclient_init(dhcp, 0);
    }

    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        fatal(retval, "Could not listen for vlog connections");
    }

    daemonize();

    local_rconn = rconn_create(1, 0, max_backoff);
    rconn_connect(local_rconn, nl_name);

    remote_rconn = rconn_create(1, probe_interval, max_backoff);
    if (controller_name) {
        retval = rconn_connect(remote_rconn, controller_name);
        if (retval == EAFNOSUPPORT) {
            fatal(0, "No support for %s vconn", controller_name);
        }
    }
    controller_relay = relay_create(local_rconn, remote_rconn, false);
    for (;;) {
        struct relay *r, *n;

        /* Do work. */
        LIST_FOR_EACH_SAFE (r, n, struct relay, node, &relays) {
            relay_run(r);
        }
        if (listen_vconn) {
            for (;;) {
                struct vconn *new_remote;
                retval = vconn_accept(listen_vconn, &new_remote);
                if (retval) {
                    if (retval != EAGAIN) {
                        VLOG_WARN("accept failed (%s)", strerror(retval));
                    }
                    break;
                }
                new_management_connection(nl_name, new_remote);
            }
        }
        if (controller_relay) {
            /* FIXME: should also fail open when controller_relay is NULL. */
            failing_open(controller_relay); 
        }
        if (dhcp) {
            if (rconn_is_connectivity_questionable(remote_rconn)) {
                dhclient_force_renew(dhcp, 15);
            }
            dhclient_run(dhcp);
            if (dhclient_changed(dhcp)) {
                free(controller_name);
                if (dhclient_is_bound(dhcp)) {
                    controller_name = dhcp_msg_get_string(
                        dhclient_get_config(dhcp),
                        DHCP_CODE_OFP_CONTROLLER_VCONN);
                    VLOG_WARN("%s: discovered controller",
                              controller_name);
                    rconn_connect(remote_rconn, controller_name);
                } else if (controller_name) {
                    VLOG_WARN("%s: discover controller no longer available",
                              controller_name);
                    controller_name = NULL;
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
        if (dhcp) {
            dhclient_wait(dhcp);
        }
        poll_block();
    }

    return 0;
}

static void
new_management_connection(const char *nl_name, struct vconn *new_remote)
{
    char *nl_name_without_subscription;
    struct vconn *new_local;
    struct rconn *r1, *r2;
    int retval;

    /* nl:123 or nl:123:1 opens a netlink connection to local datapath 123.  We
     * only accept the former syntax in main().
     *
     * nl:123:0 opens a netlink connection to local datapath 123 without
     * obtaining a subscription for ofp_packet_in or ofp_flow_expired
     * messages.*/
    nl_name_without_subscription = xasprintf("%s:0", nl_name);
    retval = vconn_open(nl_name_without_subscription, &new_local);
    if (retval) {
        VLOG_ERR("could not connect to %s (%s)",
                 nl_name_without_subscription, strerror(retval));
        vconn_close(new_remote);
        free(nl_name_without_subscription);
        return;
    }

    /* Add it to the relay list. */
    r1 = rconn_create(1, 0, 0);
    rconn_connect_unreliably(r1, nl_name_without_subscription, new_local);
    r2 = rconn_create(1, 0, 0);
    rconn_connect_unreliably(r2, "passive", new_remote);
    relay_create(r1, r2, true);

    free(nl_name_without_subscription);
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
    r->lswitch = NULL;
    list_push_back(&relays, &r->node);
    return r;
}

static void
relay_run(struct relay *r)
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
                if (this->rxbuf && !r->is_mgmt_conn && i == HALF_LOCAL
                    && (local_hook(r) || fail_open_hook(r))) {
                    buffer_delete(this->rxbuf);
                    this->rxbuf = NULL;
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

static void
queue_tx(struct rconn *rc, struct buffer *b)
{
    if (rconn_force_send(rc, b)) {
        buffer_delete(b);
    }
}

static bool
is_controller_mac(const uint8_t dl_addr[ETH_ADDR_LEN],
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
            int retval = netdev_arp_lookup(of_device, ip, mac);
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
local_hook(struct relay *r)
{
    struct rconn *rc = r->halves[HALF_LOCAL].rconn;
    struct buffer *msg = r->halves[HALF_LOCAL].rxbuf;
    struct ofp_packet_in *opi;
    struct ofp_header *oh;
    size_t pkt_ofs, pkt_len;
    struct buffer pkt;
    struct flow flow;
    uint16_t in_port, out_port;

    if (!in_band) {
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
        out_port = mac_learning_lookup(local_ml, flow.dl_dst);
    } else if (eth_addr_equals(flow.dl_dst, local_mac)) {
        out_port = OFPP_LOCAL;
        if (mac_learning_learn(local_ml, flow.dl_src, in_port)) {
            VLOG_DBG("learned that "ETH_ADDR_FMT" is on port %"PRIu16,
                     ETH_ADDR_ARGS(flow.dl_src), in_port);
        }
    } else if (flow.dl_type == htons(ETH_TYPE_ARP)
               && eth_addr_is_broadcast(flow.dl_dst)
               && is_controller_mac(flow.dl_src,
                                    r->halves[HALF_REMOTE].rconn)) {
        out_port = OFPP_FLOOD;
    } else {
        return false;
    }

    if (out_port != OFPP_FLOOD) {
        /* The output port is known, so add a new flow. */
        queue_tx(rc, make_add_simple_flow(&flow, ntohl(opi->buffer_id),
                                          out_port, max_idle));

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

/* Causess 'r' to enter or leave fail-open mode, if appropriate.  Returns true
 * if 'r' is in fail-open fail, false otherwise. */
static bool
failing_open(struct relay *r)
{
    struct rconn *local = r->halves[HALF_LOCAL].rconn;
    struct rconn *remote = r->halves[HALF_REMOTE].rconn;
    int disconnected_duration;

    if (fail_mode == FAIL_CLOSED) {
        /* We fail closed, so there's never anything to do. */
        return false;
    }

    disconnected_duration = rconn_disconnected_duration(remote);
    if (disconnected_duration < probe_interval * 3) {
        /* It's not time to fail open yet. */
        if (r->lswitch && rconn_is_connected(remote)) {
            /* We're connected, so drop the learning switch. */
            VLOG_WARN("No longer in fail-open mode");
            lswitch_destroy(r->lswitch);
            r->lswitch = NULL;
        }
        return false;
    }

    if (!r->lswitch) {
        VLOG_WARN("Could not connect to controller for %d seconds, "
                  "failing open", disconnected_duration);
        r->lswitch = lswitch_create(local, true, max_idle);
    }
    return true;
}

static bool
fail_open_hook(struct relay *r)
{
    if (!failing_open(r)) {
        return false;
    } else {
        struct buffer *msg = r->halves[HALF_LOCAL].rxbuf;
        struct rconn *local = r->halves[HALF_LOCAL].rconn;
        lswitch_process_packet(r->lswitch, local, msg);
        rconn_run(local);
        return true;
    }
}

static void
modify_dhcp_request(struct dhcp_msg *msg, void *aux)
{
    dhcp_msg_put_string(msg, DHCP_CODE_VENDOR_CLASS, "OpenFlow");
}

static bool
validate_dhcp_offer(const struct dhcp_msg *msg, void *aux)
{
    char *vconn_name;
    bool accept;

    vconn_name = dhcp_msg_get_string(msg, DHCP_CODE_OFP_CONTROLLER_VCONN);
    if (!vconn_name) {
        VLOG_WARN("rejecting DHCP offer missing controller vconn");
        return false;
    }
    accept = !regexec(&accept_controller_regex, vconn_name, 0, NULL, 0);
    free(vconn_name);
    return accept;
}

static void
parse_options(int argc, char *argv[]) 
{
    enum {
        OPT_ACCEPT_VCONN = UCHAR_MAX + 1,
        OPT_INACTIVITY_PROBE,
        OPT_MAX_IDLE,
        OPT_MAX_BACKOFF
    };
    static struct option long_options[] = {
        {"accept-vconn", required_argument, 0, OPT_ACCEPT_VCONN},
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
    
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_ACCEPT_VCONN:
            accept_controller_re = (optarg[0] == '^'
                                    ? optarg
                                    : xasprintf("^%s", optarg));
            break;

        case 'f':
            if (!strcmp(optarg, "open")) {
                fail_mode = FAIL_OPEN;
            } else if (!strcmp(optarg, "closed")) {
                fail_mode = FAIL_CLOSED;
            } else {
                fatal(0,
                      "-f or --fail argument must be \"open\" or \"closed\"");
            }
            break;

        case OPT_INACTIVITY_PROBE:
            probe_interval = atoi(optarg);
            if (probe_interval < 5) {
                fatal(0, "--inactivity-probe argument must be at least 5");
            }
            break;

        case OPT_MAX_IDLE:
            if (!strcmp(optarg, "permanent")) {
                max_idle = OFP_FLOW_PERMANENT;
            } else {
                max_idle = atoi(optarg);
                if (max_idle < 1 || max_idle > 65535) {
                    fatal(0, "--max-idle argument must be between 1 and "
                          "65535 or the word 'permanent'");
                }
            }
            break;

        case OPT_MAX_BACKOFF:
            max_backoff = atoi(optarg);
            if (max_backoff < 1) {
                fatal(0, "--max-backoff argument must be at least 1");
            } else if (max_backoff > 3600) {
                max_backoff = 3600;
            }
            break;

        case 'D':
            set_detach();
            break;

        case 'P':
            set_pidfile(optarg ? optarg : "secchan.pid");
            break;

        case 'l':
            if (listen_vconn_name) {
                fatal(0, "-l or --listen may be only specified once");
            }
            listen_vconn_name = optarg;
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
}

static void
usage(void)
{
    printf("%s: secure channel, a relay for OpenFlow messages.\n"
           "usage: %s [OPTIONS] nl:DP_IDX [CONTROLLER]\n"
           "where nl:DP_IDX is a datapath that has been added with dpctl.\n"
           "CONTROLLER is an active OpenFlow connection method; if it is\n"
           "omitted, then secchan performs controller autodiscovery.\n",
           program_name, program_name);
    vconn_usage(true, true);
    printf("\nNetworking options:\n"
           "  --accept-vconn=REGEX    accept matching discovered controllers\n"
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
