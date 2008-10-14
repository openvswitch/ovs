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

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dhcp-client.h"
#include "dhcp.h"
#include "dynamic-string.h"
#include "fault.h"
#include "flow.h"
#include "learning-switch.h"
#include "list.h"
#include "mac-learning.h"
#include "netdev.h"
#include "nicira-ext.h"
#include "ofpbuf.h"
#include "openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "port-array.h"
#include "rconn.h"
#include "stp.h"
#include "timeval.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "vlog-socket.h"
#include "xtoxll.h"

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
    const char *dp_name;        /* Local datapath. */
    const char *controller_name; /* Controller (if not discovery mode). */
    const char *listener_names[MAX_MGMT]; /* Listen for mgmt connections. */
    size_t n_listeners;          /* Number of mgmt connection listeners. */
    const char *monitor_name;   /* Listen for traffic monitor connections. */

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

    /* Spanning tree protocol. */
    bool enable_stp;
};

struct half {
    struct rconn *rconn;
    struct ofpbuf *rxbuf;
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
    bool (*packet_cb[2])(struct relay *, void *aux);
    void (*periodic_cb)(void *aux);
    void (*wait_cb)(void *aux);
    void *aux;
};

static struct vlog_rate_limit vrl = VLOG_RATE_LIMIT_INIT(60, 60);

static void parse_options(int argc, char *argv[], struct settings *);
static void usage(void) NO_RETURN;

static struct pvconn *open_passive_vconn(const char *name);
static struct vconn *accept_vconn(struct pvconn *pvconn);

static struct relay *relay_create(struct rconn *local, struct rconn *remote,
                                  bool is_mgmt_conn);
static struct relay *relay_accept(const struct settings *, struct pvconn *);
static void relay_run(struct relay *, const struct hook[], size_t n_hooks);
static void relay_wait(struct relay *);
static void relay_destroy(struct relay *);

static struct hook make_hook(bool (*local_packet_cb)(struct relay *, void *),
                             bool (*remote_packet_cb)(struct relay *, void *),
                             void (*periodic_cb)(void *),
                             void (*wait_cb)(void *),
                             void *aux);
static struct ofp_packet_in *get_ofp_packet_in(struct relay *);
static bool get_ofp_packet_eth_header(struct relay *, struct ofp_packet_in **,
                                      struct eth_header **);
static void get_ofp_packet_payload(struct ofp_packet_in *, struct ofpbuf *);

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

struct port_watcher;
static struct discovery *discovery_init(const struct settings *,
                                        struct port_watcher *,
                                        struct switch_status *);
static void discovery_question_connectivity(struct discovery *);
static bool discovery_run(struct discovery *, char **controller_name);
static void discovery_wait(struct discovery *);

static struct hook in_band_hook_create(const struct settings *,
                                       struct switch_status *,
                                       struct port_watcher *,
                                       struct rconn *remote);

static struct hook port_watcher_create(struct rconn *local,
                                       struct rconn *remote,
                                       struct port_watcher **);
static uint32_t port_watcher_get_config(const struct port_watcher *,
                                        uint16_t port_no);
static const char *port_watcher_get_name(const struct port_watcher *,
                                         uint16_t port_no) UNUSED;
static const uint8_t *port_watcher_get_hwaddr(const struct port_watcher *,
                                              uint16_t port_no);
static void port_watcher_set_flags(struct port_watcher *, uint16_t port_no, 
                                   uint32_t config, uint32_t c_mask,
                                   uint32_t state, uint32_t s_mask);

#ifdef SUPPORT_SNAT
static struct hook snat_hook_create(struct port_watcher *pw);
#endif

static struct hook stp_hook_create(const struct settings *,
                                   struct port_watcher *,
                                   struct rconn *local, struct rconn *remote);

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

    struct pvconn *monitor;

    struct pvconn *listeners[MAX_MGMT];
    size_t n_listeners;

    struct rconn *local_rconn, *remote_rconn;
    struct relay *controller_relay;
    struct discovery *discovery;
    struct switch_status *switch_status;
    struct port_watcher *pw;
    int i;
    int retval;

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    parse_options(argc, argv, &s);
    signal(SIGPIPE, SIG_IGN);

    /* Start listening for management and monitoring connections. */
    n_listeners = 0;
    for (i = 0; i < s.n_listeners; i++) {
        listeners[n_listeners++] = open_passive_vconn(s.listener_names[i]);
    }
    monitor = s.monitor_name ? open_passive_vconn(s.monitor_name) : NULL;

    /* Initialize switch status hook. */
    hooks[n_hooks++] = switch_status_hook_create(&s, &switch_status);

    /* Start listening for vlogconf requests. */
    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        ofp_fatal(retval, "Could not listen for vlog connections");
    }

    die_if_already_running();
    daemonize();

    VLOG_WARN("OpenFlow reference implementation version %s", VERSION);
    VLOG_WARN("OpenFlow protocol version 0x%02x", OFP_VERSION);

    /* Connect to datapath. */
    local_rconn = rconn_create(0, s.max_backoff);
    rconn_connect(local_rconn, s.dp_name);
    switch_status_register_category(switch_status, "local",
                                    rconn_status_cb, local_rconn);

    /* Connect to controller. */
    remote_rconn = rconn_create(s.probe_interval, s.max_backoff);
    if (s.controller_name) {
        retval = rconn_connect(remote_rconn, s.controller_name);
        if (retval == EAFNOSUPPORT) {
            ofp_fatal(0, "No support for %s vconn", s.controller_name);
        }
    }
    switch_status_register_category(switch_status, "remote",
                                    rconn_status_cb, remote_rconn);

    /* Start relaying. */
    controller_relay = relay_create(local_rconn, remote_rconn, false);
    list_push_back(&relays, &controller_relay->node);

    /* Set up hooks. */
    hooks[n_hooks++] = port_watcher_create(local_rconn, remote_rconn, &pw);
    discovery = s.discovery ? discovery_init(&s, pw, switch_status) : NULL;
#ifdef SUPPORT_SNAT
    hooks[n_hooks++] = snat_hook_create(pw);
#endif
    if (s.enable_stp) {
        hooks[n_hooks++] = stp_hook_create(&s, pw, local_rconn, remote_rconn);
    }
    if (s.in_band) {
        hooks[n_hooks++] = in_band_hook_create(&s, switch_status, pw,
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
        if (monitor) {
            struct vconn *new = accept_vconn(monitor);
            if (new) {
                rconn_add_monitor(local_rconn, new);
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
            pvconn_wait(listeners[i]);
        }
        if (monitor) {
            pvconn_wait(monitor);
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

static struct pvconn *
open_passive_vconn(const char *name)
{
    struct pvconn *pvconn;
    int retval;

    retval = pvconn_open(name, &pvconn);
    if (retval && retval != EAGAIN) {
        ofp_fatal(retval, "opening %s", name);
    }
    return pvconn;
}

static struct vconn *
accept_vconn(struct pvconn *pvconn)
{
    struct vconn *new;
    int retval;

    retval = pvconn_accept(pvconn, OFP_VERSION, &new);
    if (retval && retval != EAGAIN) {
        VLOG_WARN_RL(&vrl, "accept failed (%s)", strerror(retval));
    }
    return new;
}

static struct hook
make_hook(bool (*local_packet_cb)(struct relay *, void *aux),
          bool (*remote_packet_cb)(struct relay *, void *aux),
          void (*periodic_cb)(void *aux),
          void (*wait_cb)(void *aux),
          void *aux)
{
    struct hook h;
    h.packet_cb[HALF_LOCAL] = local_packet_cb;
    h.packet_cb[HALF_REMOTE] = remote_packet_cb;
    h.periodic_cb = periodic_cb;
    h.wait_cb = wait_cb;
    h.aux = aux;
    return h;
}

static struct ofp_packet_in *
get_ofp_packet_in(struct relay *r)
{
    struct ofpbuf *msg = r->halves[HALF_LOCAL].rxbuf;
    struct ofp_header *oh = msg->data;
    if (oh->type == OFPT_PACKET_IN) {
        if (msg->size >= offsetof (struct ofp_packet_in, data)) {
            return msg->data;
        } else {
            VLOG_WARN("packet too short (%zu bytes) for packet_in",
                      msg->size);
        }
    }
    return NULL;
}

static bool
get_ofp_packet_eth_header(struct relay *r, struct ofp_packet_in **opip,
                          struct eth_header **ethp)
{
    const int min_len = offsetof(struct ofp_packet_in, data) + ETH_HEADER_LEN;
    struct ofp_packet_in *opi = get_ofp_packet_in(r);
    if (opi && ntohs(opi->header.length) >= min_len) {
        *opip = opi;
        *ethp = (void *) opi->data;
        return true;
    }
    return false;
}


/* OpenFlow message relaying. */

static struct relay *
relay_accept(const struct settings *s, struct pvconn *pvconn)
{
    struct vconn *new_remote, *new_local;
    struct rconn *r1, *r2;
    char *vconn_name;
    int nl_index;
    int retval;

    new_remote = accept_vconn(pvconn);
    if (!new_remote) {
        return NULL;
    }

    if (sscanf(s->dp_name, "nl:%d", &nl_index) == 1) {
        /* nl:123 or nl:123:1 opens a netlink connection to local datapath 123.
         * nl:123:0 opens a netlink connection to local datapath 123 without
         * obtaining a subscription for ofp_packet_in or ofp_flow_expired
         * messages.  That's what we want here; management connections should
         * not receive those messages, at least by default. */
        vconn_name = xasprintf("nl:%d:0", nl_index);
    } else {
        /* We don't have a way to specify not to subscribe to those messages
         * for other transports.  (That's a defect: really this should be in
         * the OpenFlow protocol, not the Netlink transport). */
        VLOG_WARN_RL(&vrl, "new management connection will receive "
                     "asynchronous messages");
        vconn_name = xstrdup(s->dp_name);
    }

    retval = vconn_open(vconn_name, OFP_VERSION, &new_local);
    if (retval) {
        VLOG_ERR_RL(&vrl, "could not connect to %s (%s)",
                    vconn_name, strerror(retval));
        vconn_close(new_remote);
        free(vconn_name);
        return NULL;
    }

    /* Create and return relay. */
    r1 = rconn_create(0, 0);
    rconn_connect_unreliably(r1, vconn_name, new_local);
    free(vconn_name);

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
                if (this->rxbuf && (i == HALF_REMOTE || !r->is_mgmt_conn)) {
                    const struct hook *h;
                    for (h = hooks; h < &hooks[n_hooks]; h++) {
                        if (h->packet_cb[i] && h->packet_cb[i](r, h->aux)) {
                            ofpbuf_delete(this->rxbuf);
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
                        ofpbuf_delete(this->rxbuf);
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
        ofpbuf_delete(this->rxbuf);
    }
    free(r);
}

/* Port status watcher. */

typedef void port_changed_cb_func(uint16_t port_no,
                                  const struct ofp_phy_port *old,
                                  const struct ofp_phy_port *new,
                                  void *aux);

struct port_watcher_cb {
    port_changed_cb_func *port_changed;
    void *aux;
};

typedef void local_port_changed_cb_func(const struct ofp_phy_port *new,
                                        void *aux);

struct port_watcher_local_cb {
    local_port_changed_cb_func *local_port_changed;
    void *aux;
};

struct port_watcher {
    struct rconn *local_rconn;
    struct rconn *remote_rconn;
    struct port_array ports;
    time_t last_feature_request;
    bool got_feature_reply;
    uint64_t datapath_id;
    int n_txq;
    struct port_watcher_cb cbs[2];
    int n_cbs;
    struct port_watcher_local_cb local_cbs[4];
    int n_local_cbs;
    char local_port_name[OFP_MAX_PORT_NAME_LEN + 1];
};

/* Returns the number of fields that differ from 'a' to 'b'. */
static int
opp_differs(const struct ofp_phy_port *a, const struct ofp_phy_port *b)
{
    BUILD_ASSERT_DECL(sizeof *a == 48); /* Trips when we add or remove fields. */
    return ((a->port_no != b->port_no)
            + (memcmp(a->hw_addr, b->hw_addr, sizeof a->hw_addr) != 0)
            + (memcmp(a->name, b->name, sizeof a->name) != 0)
            + (a->config != b->config)
            + (a->state != b->state)
            + (a->curr != b->curr)
            + (a->advertised != b->advertised)
            + (a->supported != b->supported)
            + (a->peer != b->peer));
}

static void
sanitize_opp(struct ofp_phy_port *opp)
{
    size_t i;

    for (i = 0; i < sizeof opp->name; i++) {
        char c = opp->name[i];
        if (c && (c < 0x20 || c > 0x7e)) {
            opp->name[i] = '.';
        }
    }
    opp->name[sizeof opp->name - 1] = '\0';
}

static void
call_port_changed_callbacks(struct port_watcher *pw, int port_no,
                            const struct ofp_phy_port *old,
                            const struct ofp_phy_port *new)
{
    int i;
    for (i = 0; i < pw->n_cbs; i++) {
        port_changed_cb_func *port_changed = pw->cbs[i].port_changed;
        (port_changed)(port_no, old, new, pw->cbs[i].aux);
    }
}

static void
get_port_name(const struct ofp_phy_port *port, char *name, size_t name_size)
{
    char *p;

    memcpy(name, port->name, MIN(name_size, sizeof port->name));
    name[name_size - 1] = '\0';
    for (p = name; *p != '\0'; p++) {
        if (*p < 32 || *p > 126) {
            *p = '.';
        }
    }
}

static struct ofp_phy_port *
lookup_port(const struct port_watcher *pw, uint16_t port_no)
{
    return port_array_get(&pw->ports, port_no);
}

static void
call_local_port_changed_callbacks(struct port_watcher *pw)
{
    char name[OFP_MAX_PORT_NAME_LEN + 1];
    const struct ofp_phy_port *port;
    int i;

    /* Pass the local port to the callbacks, if it exists.
       Pass a null pointer if there is no local port. */
    port = lookup_port(pw, OFPP_LOCAL);

    /* Log the name of the local port. */
    if (port) {
        get_port_name(port, name, sizeof name);
    } else {
        name[0] = '\0';
    }
    if (strcmp(pw->local_port_name, name)) {
        if (name[0]) {
            VLOG_WARN("Identified data path local port as \"%s\".", name);
        } else {
            VLOG_WARN("Data path has no local port.");
        }
        strcpy(pw->local_port_name, name);
    }

    /* Invoke callbacks. */
    for (i = 0; i < pw->n_local_cbs; i++) {
        local_port_changed_cb_func *cb = pw->local_cbs[i].local_port_changed;
        (cb)(port, pw->local_cbs[i].aux);
    }
}

static void
update_phy_port(struct port_watcher *pw, struct ofp_phy_port *opp,
                uint8_t reason)
{
    struct ofp_phy_port *old;
    uint16_t port_no;

    port_no = ntohs(opp->port_no);
    old = lookup_port(pw, port_no);

    if (reason == OFPPR_DELETE && old) {
        call_port_changed_callbacks(pw, port_no, old, NULL);
        free(old);
        port_array_set(&pw->ports, port_no, NULL);
    } else if (reason == OFPPR_MODIFY || reason == OFPPR_ADD) {
        if (old) {
            uint32_t s_mask = htonl(OFPPS_STP_MASK);
            opp->state = (opp->state & ~s_mask) | (old->state & s_mask);
        }
        if (!old || opp_differs(opp, old)) {
            struct ofp_phy_port new = *opp;
            sanitize_opp(&new);
            call_port_changed_callbacks(pw, port_no, old, &new);
            if (old) {
                *old = new;
            } else {
                port_array_set(&pw->ports, port_no, xmemdup(&new, sizeof new));
            }
        }
    }
}

static bool
port_watcher_local_packet_cb(struct relay *r, void *pw_)
{
    struct port_watcher *pw = pw_;
    struct ofpbuf *msg = r->halves[HALF_LOCAL].rxbuf;
    struct ofp_header *oh = msg->data;

    if (oh->type == OFPT_FEATURES_REPLY
        && msg->size >= offsetof(struct ofp_switch_features, ports)) {
        struct ofp_switch_features *osf = msg->data;
        bool seen[PORT_ARRAY_SIZE];
        struct ofp_phy_port *p;
        unsigned int port_no;
        size_t n_ports;
        size_t i;

        pw->got_feature_reply = true;
        if (pw->datapath_id != osf->datapath_id) {
            pw->datapath_id = osf->datapath_id;
            VLOG_WARN("Datapath id is %012"PRIx64, ntohll(pw->datapath_id));
        }

        /* Update each port included in the message. */
        memset(seen, false, sizeof seen);
        n_ports = ((msg->size - offsetof(struct ofp_switch_features, ports))
                   / sizeof *osf->ports);
        for (i = 0; i < n_ports; i++) {
            struct ofp_phy_port *opp = &osf->ports[i];
            update_phy_port(pw, opp, OFPPR_MODIFY);
            seen[ntohs(opp->port_no)] = true;
        }

        /* Delete all the ports not included in the message. */
        for (p = port_array_first(&pw->ports, &port_no); p;
             p = port_array_next(&pw->ports, &port_no)) {
            if (!seen[port_no]) {
                update_phy_port(pw, p, OFPPR_DELETE);
            }
        }

        call_local_port_changed_callbacks(pw);
    } else if (oh->type == OFPT_PORT_STATUS
               && msg->size >= sizeof(struct ofp_port_status)) {
        struct ofp_port_status *ops = msg->data;
        update_phy_port(pw, &ops->desc, ops->reason);
        if (ops->desc.port_no == htons(OFPP_LOCAL)) {
            call_local_port_changed_callbacks(pw);
        }
    }
    return false;
}

static bool
port_watcher_remote_packet_cb(struct relay *r, void *pw_)
{
    struct port_watcher *pw = pw_;
    struct ofpbuf *msg = r->halves[HALF_REMOTE].rxbuf;
    struct ofp_header *oh = msg->data;

    if (oh->type == OFPT_PORT_MOD
        && msg->size >= sizeof(struct ofp_port_mod)) {
        struct ofp_port_mod *opm = msg->data;
        uint16_t port_no = ntohs(opm->port_no);
        struct ofp_phy_port *pw_opp = lookup_port(pw, port_no);
        if (pw_opp->port_no != htons(OFPP_NONE)) {
            struct ofp_phy_port old = *pw_opp;
            pw_opp->config = ((pw_opp->config & ~opm->mask)
                              | (opm->config & opm->mask));
            call_port_changed_callbacks(pw, port_no, &old, pw_opp);
            if (pw_opp->port_no == htons(OFPP_LOCAL)) {
                call_local_port_changed_callbacks(pw);
            }
        }
    }
    return false;
}

static void
port_watcher_periodic_cb(void *pw_)
{
    struct port_watcher *pw = pw_;

    if (!pw->got_feature_reply
        && time_now() >= pw->last_feature_request + 5
        && rconn_is_connected(pw->local_rconn)) {
        struct ofpbuf *b;
        make_openflow(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, &b);
        rconn_send_with_limit(pw->local_rconn, b, &pw->n_txq, 1);
        pw->last_feature_request = time_now();
    }
}

static void
port_watcher_wait_cb(void *pw_)
{
    struct port_watcher *pw = pw_;
    if (!pw->got_feature_reply && rconn_is_connected(pw->local_rconn)) {
        if (pw->last_feature_request != TIME_MIN) {
            poll_timer_wait(pw->last_feature_request + 5 - time_now());
        } else {
            poll_immediate_wake();
        }
    }
}

static void
put_duplexes(struct ds *ds, const char *name, uint32_t features,
             uint32_t hd_bit, uint32_t fd_bit)
{
    if (features & (hd_bit | fd_bit)) {
        ds_put_format(ds, " %s", name);
        if (features & hd_bit) {
            ds_put_cstr(ds, "(HD)");
        }
        if (features & fd_bit) {
            ds_put_cstr(ds, "(FD)");
        }
    }
}

static void
put_features(struct ds *ds, const char *name, uint32_t features)
{
    if (features & (OFPPF_10MB_HD | OFPPF_10MB_FD
                    | OFPPF_100MB_HD | OFPPF_100MB_FD
                    | OFPPF_1GB_HD | OFPPF_1GB_FD | OFPPF_10GB_FD)) {
        ds_put_cstr(ds, name);
        put_duplexes(ds, "10M", features, OFPPF_10MB_HD, OFPPF_10MB_FD);
        put_duplexes(ds, "100M", features,
                     OFPPF_100MB_HD, OFPPF_100MB_FD);
        put_duplexes(ds, "1G", features, OFPPF_100MB_HD, OFPPF_100MB_FD);
        if (features & OFPPF_10GB_FD) {
            ds_put_cstr(ds, " 10G");
        }
        if (features & OFPPF_AUTONEG) {
            ds_put_cstr(ds, " AUTO_NEG");
        }
        if (features & OFPPF_PAUSE) {
            ds_put_cstr(ds, " PAUSE");
        }
        if (features & OFPPF_PAUSE_ASYM) {
            ds_put_cstr(ds, " PAUSE_ASYM");
        }
    }
}

static void
log_port_status(uint16_t port_no,
                const struct ofp_phy_port *old,
                const struct ofp_phy_port *new,
                void *aux)
{
    if (VLOG_IS_DBG_ENABLED()) {
        if (old && new && (opp_differs(old, new)
                           == ((old->config != new->config)
                               + (old->state != new->state))))
        {
            /* Don't care if only state or config changed. */
        } else if (!new) {
            if (old) {
                VLOG_DBG("Port %d deleted", port_no);
            }
        } else {
            struct ds ds = DS_EMPTY_INITIALIZER;
            uint32_t curr = ntohl(new->curr);
            uint32_t supported = ntohl(new->supported);
            ds_put_format(&ds, "\"%s\", "ETH_ADDR_FMT, new->name,
                          ETH_ADDR_ARGS(new->hw_addr));
            if (curr) {
                put_features(&ds, ", current", curr);
            }
            if (supported) {
                put_features(&ds, ", supports", supported);
            }
            VLOG_DBG("Port %d %s: %s",
                     port_no, old ? "changed" : "added", ds_cstr(&ds));
            ds_destroy(&ds);
        }
    }
}

static void
port_watcher_register_callback(struct port_watcher *pw,
                               port_changed_cb_func *port_changed,
                               void *aux)
{
    assert(pw->n_cbs < ARRAY_SIZE(pw->cbs));
    pw->cbs[pw->n_cbs].port_changed = port_changed;
    pw->cbs[pw->n_cbs].aux = aux;
    pw->n_cbs++;
}

static void
port_watcher_register_local_port_callback(struct port_watcher *pw,
                                          local_port_changed_cb_func *cb,
                                          void *aux)
{
    assert(pw->n_local_cbs < ARRAY_SIZE(pw->local_cbs));
    pw->local_cbs[pw->n_local_cbs].local_port_changed = cb;
    pw->local_cbs[pw->n_local_cbs].aux = aux;
    pw->n_local_cbs++;
}

static uint32_t
port_watcher_get_config(const struct port_watcher *pw, uint16_t port_no)
{
    struct ofp_phy_port *p = lookup_port(pw, port_no);
    return p ? ntohl(p->config) : 0;
}

static const char *
port_watcher_get_name(const struct port_watcher *pw, uint16_t port_no)
{
    struct ofp_phy_port *p = lookup_port(pw, port_no);
    return p ? (const char *) p->name : NULL;
}

static const uint8_t *
port_watcher_get_hwaddr(const struct port_watcher *pw, uint16_t port_no) 
{
    struct ofp_phy_port *p = lookup_port(pw, port_no);
    return p ? p->hw_addr : NULL;
}

static void
port_watcher_set_flags(struct port_watcher *pw, uint16_t port_no, 
                       uint32_t config, uint32_t c_mask,
                       uint32_t state, uint32_t s_mask)
{
    struct ofp_phy_port old;
    struct ofp_phy_port *p;
    struct ofp_port_mod *opm;
    struct ofp_port_status *ops;
    struct ofpbuf *b;

    p = lookup_port(pw, port_no);
    if (!p) {
        return;
    }

    if (!((ntohl(p->state) ^ state) & s_mask) 
            && (!((ntohl(p->config) ^ config) & c_mask))) {
        return;
    }
    old = *p;

    /* Update our idea of the flags. */
    p->config = htonl((ntohl(p->config) & ~c_mask) | (config & c_mask));
    p->state = htonl((ntohl(p->state) & ~s_mask) | (state & s_mask));
    call_port_changed_callbacks(pw, port_no, &old, p);

    /* Change the flags in the datapath. */
    opm = make_openflow(sizeof *opm, OFPT_PORT_MOD, &b);
    opm->port_no = p->port_no;
    memcpy(opm->hw_addr, p->hw_addr, OFP_ETH_ALEN);
    opm->config = p->config;
    opm->mask = htonl(c_mask);
    opm->advertise = htonl(0);
    rconn_send(pw->local_rconn, b, NULL);

    /* Notify the controller that the flags changed. */
    ops = make_openflow(sizeof *ops, OFPT_PORT_STATUS, &b);
    ops->reason = OFPPR_MODIFY;
    ops->desc = *p;
    rconn_send(pw->remote_rconn, b, NULL);
}

static bool
port_watcher_is_ready(const struct port_watcher *pw)
{
    return pw->got_feature_reply;
}

static struct hook
port_watcher_create(struct rconn *local_rconn, struct rconn *remote_rconn,
                    struct port_watcher **pwp)
{
    struct port_watcher *pw;

    pw = *pwp = xcalloc(1, sizeof *pw);
    pw->local_rconn = local_rconn;
    pw->remote_rconn = remote_rconn;
    pw->last_feature_request = TIME_MIN;
    port_array_init(&pw->ports);
    pw->local_port_name[0] = '\0';
    port_watcher_register_callback(pw, log_port_status, NULL);
    return make_hook(port_watcher_local_packet_cb,
                     port_watcher_remote_packet_cb,
                     port_watcher_periodic_cb,
                     port_watcher_wait_cb, pw);
}

#ifdef SUPPORT_SNAT
struct snat_port_conf {
    struct list node;
    struct nx_snat_config config;
};

struct snat_data {
    struct port_watcher *pw;
    struct list port_list;
};


/* Source-NAT configuration monitor. */
#define SNAT_CMD_LEN 1024

/* Commands to configure iptables.  There is no programmatic interface
 * to iptables from the kernel, so we're stuck making command-line calls
 * in user-space. */
#define SNAT_FLUSH_ALL_CMD "/sbin/iptables -t nat -F"
#define SNAT_FLUSH_CHAIN_CMD "/sbin/iptables -t nat -F of-snat-%s"

#define SNAT_ADD_CHAIN_CMD "/sbin/iptables -t nat -N of-snat-%s"
#define SNAT_CONF_CHAIN_CMD "/sbin/iptables -t nat -A POSTROUTING -o %s -j of-snat-%s"

#define SNAT_ADD_IP_CMD "/sbin/iptables -t nat -A of-snat-%s -j SNAT --to %s-%s"
#define SNAT_ADD_TCP_CMD "/sbin/iptables -t nat -A of-snat-%s -j SNAT -p TCP --to %s-%s:%d-%d"
#define SNAT_ADD_UDP_CMD "/sbin/iptables -t nat -A of-snat-%s -j SNAT -p UDP --to %s-%s:%d-%d"

#define SNAT_UNSET_CHAIN_CMD "/sbin/iptables -t nat -D POSTROUTING -o %s -j of-snat-%s"
#define SNAT_DEL_CHAIN_CMD "/sbin/iptables -t nat -X of-snat-%s"

static void 
snat_add_rules(const struct nx_snat_config *sc, const uint8_t *dev_name)
{
    char command[SNAT_CMD_LEN];
    char ip_str_start[16];
    char ip_str_end[16];


    snprintf(ip_str_start, sizeof ip_str_start, IP_FMT, 
            IP_ARGS(&sc->ip_addr_start));
    snprintf(ip_str_end, sizeof ip_str_end, IP_FMT, 
            IP_ARGS(&sc->ip_addr_end));

    /* We always attempt to remove existing entries, so that we know
     * there's a pristine state for SNAT on the interface.  We just ignore 
     * the results of these calls, since iptables will complain about 
     * any non-existent entries. */

    /* Flush the chain that does the SNAT. */
    snprintf(command, sizeof(command), SNAT_FLUSH_CHAIN_CMD, dev_name);
    system(command);

    /* We always try to create the a new chain. */
    snprintf(command, sizeof(command), SNAT_ADD_CHAIN_CMD, dev_name);
    system(command);

    /* Disassociate any old SNAT chain from the POSTROUTING chain. */
    snprintf(command, sizeof(command), SNAT_UNSET_CHAIN_CMD, dev_name, 
            dev_name);
    system(command);

    /* Associate the new chain with the POSTROUTING hook. */
    snprintf(command, sizeof(command), SNAT_CONF_CHAIN_CMD, dev_name, 
            dev_name);
    if (system(command) != 0) {
        VLOG_ERR("SNAT: problem flushing chain for add");
        return;
    }

    /* If configured, restrict TCP source port ranges. */
    if ((sc->tcp_start != 0) && (sc->tcp_end != 0)) {
        snprintf(command, sizeof(command), SNAT_ADD_TCP_CMD, 
                dev_name, ip_str_start, ip_str_end,
                ntohs(sc->tcp_start), ntohs(sc->tcp_end));
        if (system(command) != 0) {
            VLOG_ERR("SNAT: problem adding TCP rule");
            return;
        }
    }

    /* If configured, restrict UDP source port ranges. */
    if ((sc->udp_start != 0) && (sc->udp_end != 0)) {
        snprintf(command, sizeof(command), SNAT_ADD_UDP_CMD, 
                dev_name, ip_str_start, ip_str_end,
                ntohs(sc->udp_start), ntohs(sc->udp_end));
        if (system(command) != 0) {
            VLOG_ERR("SNAT: problem adding UDP rule");
            return;
        }
    }

    /* Add a rule that covers all IP traffic that would not be covered
     * by the prior TCP or UDP ranges. */
    snprintf(command, sizeof(command), SNAT_ADD_IP_CMD, 
            dev_name, ip_str_start, ip_str_end);
    if (system(command) != 0) {
        VLOG_ERR("SNAT: problem adding base rule");
        return;
    }
}

static void 
snat_del_rules(const uint8_t *dev_name)
{
    char command[SNAT_CMD_LEN];

    /* Flush the chain that does the SNAT. */
    snprintf(command, sizeof(command), SNAT_FLUSH_CHAIN_CMD, dev_name);
    if (system(command) != 0) {
        VLOG_ERR("SNAT: problem flushing chain for deletion");
        return;
    }

    /* Disassociate the SNAT chain from the POSTROUTING chain. */
    snprintf(command, sizeof(command), SNAT_UNSET_CHAIN_CMD, dev_name, 
            dev_name);
    if (system(command) != 0) {
        VLOG_ERR("SNAT: problem unsetting chain");
        return;
    }

    /* Now we can finally delete our SNAT chain. */
    snprintf(command, sizeof(command), SNAT_DEL_CHAIN_CMD, dev_name);
    if (system(command) != 0) {
        VLOG_ERR("SNAT: problem deleting chain");
        return;
    }
}

static void 
snat_config(const struct nx_snat_config *sc, struct snat_data *snat)
{
    struct snat_port_conf *c, *spc=NULL;
    const uint8_t *netdev_name;

    netdev_name = (const uint8_t *) port_watcher_get_name(snat->pw,
                                                          ntohs(sc->port));
    if (!netdev_name) {
        return;
    }

    LIST_FOR_EACH(c, struct snat_port_conf, node, &snat->port_list) {
        if (c->config.port == sc->port) {
            spc = c;
            break;
        }
    }

    if (sc->command == NXSC_ADD) {
        if (!spc) {
            spc = xmalloc(sizeof(*c));
            if (!spc) {
                VLOG_ERR("SNAT: no memory for new entry");
                return;
            }
            list_push_back(&snat->port_list, &spc->node);
        }
        memcpy(&spc->config, sc, sizeof(spc->config));
        snat_add_rules(sc, netdev_name);
    } else if (spc) {
        snat_del_rules(netdev_name);
        list_remove(&spc->node);
    }
}

static bool
snat_remote_packet_cb(struct relay *r, void *snat_)
{
    struct snat_data *snat = snat_;
    struct ofpbuf *msg = r->halves[HALF_REMOTE].rxbuf;
    struct nicira_header *request = msg->data;
    struct nx_act_config *nac = msg->data;
    int n_configs, i;


    if (msg->size < sizeof(struct nx_act_config)) {
        return false;
    }
    request = msg->data;
    if (request->header.type != OFPT_VENDOR
        || request->vendor != htonl(NX_VENDOR_ID)
        || request->subtype != htonl(NXT_ACT_SET_CONFIG)) {
        return false;
    }

    /* We're only interested in attempts to configure SNAT */
    if (nac->type != htons(NXAST_SNAT)) {
        return false;
    }

    n_configs = (msg->size - sizeof *nac) / sizeof *nac->snat;
    for (i=0; i<n_configs; i++) {
        snat_config(&nac->snat[i], snat);
    }

    return false;
}

static void
snat_port_changed_cb(uint16_t port_no,
                    const struct ofp_phy_port *old,
                    const struct ofp_phy_port *new,
                    void *snat_)
{
    struct snat_data *snat = snat_;
    struct snat_port_conf *c;

    /* We're only interested in ports that went away */
    if (old && !new) {
        return;
    }

    LIST_FOR_EACH(c, struct snat_port_conf, node, &snat->port_list) {
        if (c->config.port == old->port_no) {
            snat_del_rules(old->name);
            list_remove(&c->node);
            return;
        }
    }
}

static struct hook
snat_hook_create(struct port_watcher *pw)
{
    int ret;
    struct snat_data *snat;

    ret = system(SNAT_FLUSH_ALL_CMD); 
    if (ret != 0) {
        VLOG_ERR("SNAT: problem flushing tables");
    }

    snat = xcalloc(1, sizeof *snat);
    snat->pw = pw;
    list_init(&snat->port_list);

    port_watcher_register_callback(pw, snat_port_changed_cb, snat);
    return make_hook(NULL, snat_remote_packet_cb, NULL, NULL, snat);
}
#endif /* SUPPORT_SNAT */

/* Spanning tree protocol. */

/* Extra time, in seconds, at boot before going into fail-open, to give the
 * spanning tree protocol time to figure out the network layout. */
#define STP_EXTRA_BOOT_TIME 30

struct stp_data {
    struct stp *stp;
    struct port_watcher *pw;
    struct rconn *local_rconn;
    struct rconn *remote_rconn;
    long long int last_tick_256ths;
    int n_txq;
};

static bool
stp_local_packet_cb(struct relay *r, void *stp_)
{
    struct ofpbuf *msg = r->halves[HALF_LOCAL].rxbuf;
    struct ofp_header *oh;
    struct stp_data *stp = stp_;
    struct ofp_packet_in *opi;
    struct eth_header *eth;
    struct llc_header *llc;
    struct ofpbuf payload;
    uint16_t port_no;
    struct flow flow;

    oh = msg->data;
    if (oh->type == OFPT_FEATURES_REPLY
        && msg->size >= offsetof(struct ofp_switch_features, ports)) {
        struct ofp_switch_features *osf = msg->data;
        osf->capabilities |= htonl(OFPC_STP);
        return false;
    }

    if (!get_ofp_packet_eth_header(r, &opi, &eth)
        || !eth_addr_equals(eth->eth_dst, stp_eth_addr)) {
        return false;
    }

    port_no = ntohs(opi->in_port);
    if (port_no >= STP_MAX_PORTS) {
        /* STP only supports 255 ports. */
        return false;
    }
    if (port_watcher_get_config(stp->pw, port_no) & OFPPC_NO_STP) {
        /* We're not doing STP on this port. */
        return false;
    }

    if (opi->reason == OFPR_ACTION) {
        /* The controller set up a flow for this, so we won't intercept it. */
        return false;
    }

    get_ofp_packet_payload(opi, &payload);
    flow_extract(&payload, port_no, &flow);
    if (flow.dl_type != htons(OFP_DL_TYPE_NOT_ETH_TYPE)) {
        VLOG_DBG("non-LLC frame received on STP multicast address");
        return false;
    }
    llc = ofpbuf_at_assert(&payload, sizeof *eth, sizeof *llc);
    if (llc->llc_dsap != STP_LLC_DSAP) {
        VLOG_DBG("bad DSAP 0x%02"PRIx8" received on STP multicast address",
                 llc->llc_dsap);
        return false;
    }

    /* Trim off padding on payload. */
    if (payload.size > ntohs(eth->eth_type) + ETH_HEADER_LEN) {
        payload.size = ntohs(eth->eth_type) + ETH_HEADER_LEN;
    }
    if (ofpbuf_try_pull(&payload, ETH_HEADER_LEN + LLC_HEADER_LEN)) {
        struct stp_port *p = stp_get_port(stp->stp, port_no);
        stp_received_bpdu(p, payload.data, payload.size);
    }

    return true;
}

static long long int
time_256ths(void)
{
    return time_msec() * 256 / 1000;
}

static void
stp_periodic_cb(void *stp_)
{
    struct stp_data *stp = stp_;
    long long int now_256ths = time_256ths();
    long long int elapsed_256ths = now_256ths - stp->last_tick_256ths;
    struct stp_port *p;

    if (!port_watcher_is_ready(stp->pw)) {
        /* Can't start STP until we know port flags, because port flags can
         * disable STP. */
        return;
    }
    if (elapsed_256ths <= 0) {
        return;
    }

    stp_tick(stp->stp, MIN(INT_MAX, elapsed_256ths));
    stp->last_tick_256ths = now_256ths;

    while (stp_get_changed_port(stp->stp, &p)) {
        int port_no = stp_port_no(p);
        enum stp_state s_state = stp_port_get_state(p);

        if (s_state != STP_DISABLED) {
            VLOG_WARN("STP: Port %d entered %s state",
                      port_no, stp_state_name(s_state));
        }
        if (!(port_watcher_get_config(stp->pw, port_no) & OFPPC_NO_STP)) {
            uint32_t p_config = 0;
            uint32_t p_state;
            switch (s_state) {
            case STP_LISTENING:
                p_state = OFPPS_STP_LISTEN;
                break;
            case STP_LEARNING:
                p_state = OFPPS_STP_LEARN;
                break;
            case STP_DISABLED:
            case STP_FORWARDING:
                p_state = OFPPS_STP_FORWARD;
                break;
            case STP_BLOCKING:
                p_state = OFPPS_STP_BLOCK;
                break;
            default:
                VLOG_DBG_RL(&vrl, "STP: Port %d has bad state %x",
                            port_no, s_state);
                p_state = OFPPS_STP_FORWARD;
                break;
            }
            if (!stp_forward_in_state(s_state)) {
                p_config = OFPPC_NO_FLOOD;
            }
            port_watcher_set_flags(stp->pw, port_no, 
                                   p_config, OFPPC_NO_FLOOD,
                                   p_state, OFPPS_STP_MASK);
        } else {
            /* We don't own those flags. */
        }
    }
}

static void
stp_wait_cb(void *stp_ UNUSED)
{
    poll_timer_wait(1000);
}

static void
send_bpdu(const void *bpdu, size_t bpdu_size, int port_no, void *stp_)
{
    struct stp_data *stp = stp_;
    const uint8_t *port_mac;
    struct eth_header *eth;
    struct llc_header *llc;
    struct ofpbuf pkt, *opo;

    port_mac = port_watcher_get_hwaddr(stp->pw, port_no);
    if (!port_mac) {
        VLOG_WARN_RL(&vrl, "cannot send BPDU on missing port %d", port_no);
        return;
    }

    /* Packet skeleton. */
    ofpbuf_init(&pkt, ETH_HEADER_LEN + LLC_HEADER_LEN + bpdu_size);
    eth = ofpbuf_put_uninit(&pkt, sizeof *eth);
    llc = ofpbuf_put_uninit(&pkt, sizeof *llc);
    ofpbuf_put(&pkt, bpdu, bpdu_size);

    /* 802.2 header. */
    memcpy(eth->eth_dst, stp_eth_addr, ETH_ADDR_LEN);
    memcpy(eth->eth_src, port_mac, ETH_ADDR_LEN);
    eth->eth_type = htons(pkt.size - ETH_HEADER_LEN);

    /* LLC header. */
    llc->llc_dsap = STP_LLC_DSAP;
    llc->llc_ssap = STP_LLC_SSAP;
    llc->llc_cntl = STP_LLC_CNTL;

    opo = make_unbuffered_packet_out(&pkt, OFPP_NONE, port_no);
    ofpbuf_uninit(&pkt);
    rconn_send_with_limit(stp->local_rconn, opo, &stp->n_txq, OFPP_MAX);
}

static bool
stp_is_port_supported(uint16_t port_no)
{
    return port_no < STP_MAX_PORTS;
}

static void
stp_port_changed_cb(uint16_t port_no,
                    const struct ofp_phy_port *old,
                    const struct ofp_phy_port *new,
                    void *stp_)
{
    struct stp_data *stp = stp_;
    struct stp_port *p;

    if (!stp_is_port_supported(port_no)) {
        return;
    }

    p = stp_get_port(stp->stp, port_no);
    if (!new
        || new->config & htonl(OFPPC_NO_STP | OFPPC_PORT_DOWN)
        || new->state & htonl(OFPPS_LINK_DOWN)) {
        stp_port_disable(p);
    } else {
        int speed = 0;
        stp_port_enable(p);
        if (new->curr & (OFPPF_10MB_HD | OFPPF_10MB_FD)) {
            speed = 10;
        } else if (new->curr & (OFPPF_100MB_HD | OFPPF_100MB_FD)) {
            speed = 100;
        } else if (new->curr & (OFPPF_1GB_HD | OFPPF_1GB_FD)) {
            speed = 1000;
        } else if (new->curr & OFPPF_100MB_FD) {
            speed = 10000;
        }
        stp_port_set_speed(p, speed);
    }
}

static void
stp_local_port_changed_cb(const struct ofp_phy_port *port, void *stp_)
{
    struct stp_data *stp = stp_;
    if (port) {
        stp_set_bridge_id(stp->stp, eth_addr_to_uint64(port->hw_addr));
    }
}

static struct hook
stp_hook_create(const struct settings *s, struct port_watcher *pw,
                struct rconn *local, struct rconn *remote)
{
    uint8_t dpid[ETH_ADDR_LEN];
    struct stp_data *stp;

    stp = xcalloc(1, sizeof *stp);
    eth_addr_random(dpid);
    stp->stp = stp_create("stp", eth_addr_to_uint64(dpid), send_bpdu, stp);
    stp->pw = pw;
    stp->local_rconn = local;
    stp->remote_rconn = remote;
    stp->last_tick_256ths = time_256ths();

    port_watcher_register_callback(pw, stp_port_changed_cb, stp);
    port_watcher_register_local_port_callback(pw, stp_local_port_changed_cb,
                                              stp);
    return make_hook(stp_local_packet_cb, NULL,
                     stp_periodic_cb, stp_wait_cb, stp);
}

/* In-band control. */

struct in_band_data {
    const struct settings *s;
    struct mac_learning *ml;
    struct netdev *of_device;
    struct rconn *controller;
    int n_queued;
};

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
                VLOG_DBG_RL(&vrl, "cannot look up controller hw address "
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
        VLOG_DBG_RL(&vrl, "learned that "ETH_ADDR_FMT" is on port %"PRIu16,
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

static void
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

static struct hook
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

/* Fail open support. */

struct fail_open_data {
    const struct settings *s;
    struct rconn *local_rconn;
    struct rconn *remote_rconn;
    struct lswitch *lswitch;
    int last_disconn_secs;
    time_t boot_deadline;
};

/* Causes 'r' to enter or leave fail-open mode, if appropriate. */
static void
fail_open_periodic_cb(void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    int disconn_secs;
    bool open;

    if (time_now() < fail_open->boot_deadline) {
        return;
    }
    disconn_secs = rconn_failure_duration(fail_open->remote_rconn);
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
    if (fail_open->lswitch) {
        lswitch_run(fail_open->lswitch, fail_open->local_rconn);
    }
}

static void
fail_open_wait_cb(void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    if (fail_open->lswitch) {
        lswitch_wait(fail_open->lswitch);
    }
}

static bool
fail_open_local_packet_cb(struct relay *r, void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    if (!fail_open->lswitch) {
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
    int cur_duration = rconn_failure_duration(fail_open->remote_rconn);

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
    fail_open->boot_deadline = time_now() + s->probe_interval * 3;
    if (s->enable_stp) {
        fail_open->boot_deadline += STP_EXTRA_BOOT_TIME;
    }
    switch_status_register_category(ss, "fail-open",
                                    fail_open_status_cb, fail_open);
    return make_hook(fail_open_local_packet_cb, NULL,
                     fail_open_periodic_cb, fail_open_wait_cb, fail_open);
}

struct rate_limiter {
    const struct settings *s;
    struct rconn *remote_rconn;

    /* One queue per physical port. */
    struct ofp_queue queues[OFPP_MAX];
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
    struct ofp_queue *longest;  /* Queue currently selected as longest. */
    int n_longest;              /* # of queues of same length as 'longest'. */
    struct ofp_queue *q;

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
    ofpbuf_delete(queue_pop_head(longest));
    rl->n_queued--;
}

/* Remove and return the next packet to transmit (in round-robin order). */
static struct ofpbuf *
dequeue_packet(struct rate_limiter *rl)
{
    unsigned int i;

    for (i = 0; i < OFPP_MAX; i++) {
        unsigned int port = (rl->next_tx_port + i) % OFPP_MAX;
        struct ofp_queue *q = &rl->queues[port];
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
rate_limit_local_packet_cb(struct relay *r, void *rl_)
{
    struct rate_limiter *rl = rl_;
    const struct settings *s = rl->s;
    struct ofp_packet_in *opi;

    opi = get_ofp_packet_in(r);
    if (!opi) {
        return false;
    }

    if (!rl->n_queued && get_token(rl)) {
        /* In the common case where we are not constrained by the rate limit,
         * let the packet take the normal path. */
        rl->n_normal++;
        return false;
    } else {
        /* Otherwise queue it up for the periodic callback to drain out. */
        struct ofpbuf *msg = r->halves[HALF_LOCAL].rxbuf;
        int port = ntohs(opi->in_port) % OFPP_MAX;
        if (rl->n_queued >= s->burst_limit) {
            drop_packet(rl);
        }
        queue_push_tail(&rl->queues[port], ofpbuf_clone(msg));
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
        struct ofpbuf *b = dequeue_packet(rl);
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
    return make_hook(rate_limit_local_packet_cb, NULL, rate_limit_periodic_cb,
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
switch_status_remote_packet_cb(struct relay *r, void *ss_)
{
    struct switch_status *ss = ss_;
    struct rconn *rc = r->halves[HALF_REMOTE].rconn;
    struct ofpbuf *msg = r->halves[HALF_REMOTE].rxbuf;
    struct switch_status_category *c;
    struct nicira_header *request;
    struct nicira_header *reply;
    struct status_reply sr;
    struct ofpbuf *b;
    int retval;

    if (msg->size < sizeof(struct nicira_header)) {
        return false;
    }
    request = msg->data;
    if (request->header.type != OFPT_VENDOR
        || request->vendor != htonl(NX_VENDOR_ID)
        || request->subtype != htonl(NXT_STATUS_REQUEST)) {
        return false;
    }

    sr.request.string = (void *) (request + 1);
    sr.request.length = msg->size - sizeof *request;
    ds_init(&sr.output);
    for (c = ss->categories; c < &ss->categories[ss->n_categories]; c++) {
        if (!memcmp(c->name, sr.request.string,
                    MIN(strlen(c->name), sr.request.length))) {
            sr.category = c;
            c->cb(&sr, c->aux);
        }
    }
    reply = make_openflow_xid(sizeof *reply + sr.output.length,
                              OFPT_VENDOR, request->header.xid, &b);
    reply->vendor = htonl(NX_VENDOR_ID);
    reply->subtype = htonl(NXT_STATUS_REPLY);
    memcpy(reply + 1, sr.output.string, sr.output.length);
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
    status_reply_put(sr, "backoff=%d", rconn_get_backoff(rconn));
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
    status_reply_put(sr, "state-elapsed=%u", rconn_get_state_elapsed(rconn));
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
    return make_hook(NULL, switch_status_remote_packet_cb, NULL, NULL, ss);
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

    status_reply_put(sr, "accept-remote=%s", d->s->accept_controller_re);
    status_reply_put(sr, "n-changes=%d", d->n_changes);
    if (d->dhcp) {
        status_reply_put(sr, "state=%s", dhclient_get_state(d->dhcp));
        status_reply_put(sr, "state-elapsed=%u",
                         dhclient_get_state_elapsed(d->dhcp)); 
        if (dhclient_is_bound(d->dhcp)) {
            uint32_t ip = dhclient_get_ip(d->dhcp);
            uint32_t netmask = dhclient_get_netmask(d->dhcp);
            uint32_t router = dhclient_get_router(d->dhcp);

            const struct dhcp_msg *cfg = dhclient_get_config(d->dhcp);
            uint32_t dns_server;
            char *domain_name;
            int i;

            status_reply_put(sr, "ip="IP_FMT, IP_ARGS(&ip));
            status_reply_put(sr, "netmask="IP_FMT, IP_ARGS(&netmask));
            if (router) {
                status_reply_put(sr, "router="IP_FMT, IP_ARGS(&router));
            }

            for (i = 0; dhcp_msg_get_ip(cfg, DHCP_CODE_DNS_SERVER, i,
                                        &dns_server);
                 i++) {
                status_reply_put(sr, "dns%d="IP_FMT, i, IP_ARGS(&dns_server));
            }

            domain_name = dhcp_msg_get_string(cfg, DHCP_CODE_DOMAIN_NAME);
            if (domain_name) {
                status_reply_put(sr, "domain=%s", domain_name);
                free(domain_name);
            }

            status_reply_put(sr, "lease-remaining=%u",
                             dhclient_get_lease_remaining(d->dhcp));
        }
    }
}

static void
discovery_local_port_cb(const struct ofp_phy_port *port, void *d_) 
{
    struct discovery *d = d_;
    if (port) {
        char name[OFP_MAX_PORT_NAME_LEN + 1];
        struct netdev *netdev;
        int retval;

        /* Check that this was really a change. */
        get_port_name(port, name, sizeof name);
        if (d->dhcp && !strcmp(netdev_get_name(dhclient_get_netdev(d->dhcp)),
                               name)) {
            return;
        }

        /* Destroy current DHCP client. */
        dhclient_destroy(d->dhcp);
        d->dhcp = NULL;

        /* Bring local network device up. */
        retval = netdev_open(name, NETDEV_ETH_TYPE_NONE, &netdev);
        if (retval) {
            VLOG_ERR("Could not open %s device, discovery disabled: %s",
                     name, strerror(retval));
            return;
        }
        retval = netdev_turn_flags_on(netdev, NETDEV_UP, true);
        if (retval) {
            VLOG_ERR("Could not bring %s device up, discovery disabled: %s",
                     name, strerror(retval));
            return;
        }
        netdev_close(netdev);

        /* Initialize DHCP client. */
        retval = dhclient_create(name, modify_dhcp_request,
                                 validate_dhcp_offer, (void *) d->s, &d->dhcp);
        if (retval) {
            VLOG_ERR("Failed to initialize DHCP client, "
                     "discovery disabled: %s", strerror(retval));
            return;
        }
        dhclient_set_max_timeout(d->dhcp, 3);
        dhclient_init(d->dhcp, 0);
    } else {
        dhclient_destroy(d->dhcp);
        d->dhcp = NULL;
    }
}


static struct discovery *
discovery_init(const struct settings *s, struct port_watcher *pw,
               struct switch_status *ss)
{
    struct discovery *d;

    d = xmalloc(sizeof *d);
    d->s = s;
    d->dhcp = NULL;
    d->n_changes = 0;

    switch_status_register_category(ss, "discovery", discovery_status_cb, d);
    port_watcher_register_local_port_callback(pw, discovery_local_port_cb, d);

    return d;
}

static void
discovery_question_connectivity(struct discovery *d)
{
    if (d->dhcp) {
        dhclient_force_renew(d->dhcp, 15); 
    }
}

static bool
discovery_run(struct discovery *d, char **controller_name)
{
    if (!d->dhcp) {
        *controller_name = NULL;
        return true;
    }

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
    if (d->dhcp) {
        dhclient_wait(d->dhcp); 
    }
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
        OPT_BURST_LIMIT,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_STP,
        OPT_NO_STP,
        OPT_OUT_OF_BAND,
        OPT_IN_BAND
    };
    static struct option long_options[] = {
        {"accept-vconn", required_argument, 0, OPT_ACCEPT_VCONN},
        {"no-resolv-conf", no_argument, 0, OPT_NO_RESOLV_CONF},
        {"fail",        required_argument, 0, 'F'},
        {"inactivity-probe", required_argument, 0, OPT_INACTIVITY_PROBE},
        {"max-idle",    required_argument, 0, OPT_MAX_IDLE},
        {"max-backoff", required_argument, 0, OPT_MAX_BACKOFF},
        {"listen",      required_argument, 0, 'l'},
        {"monitor",     required_argument, 0, 'm'},
        {"rate-limit",  optional_argument, 0, OPT_RATE_LIMIT},
        {"burst-limit", required_argument, 0, OPT_BURST_LIMIT},
        {"stp",         no_argument, 0, OPT_STP},
        {"no-stp",      no_argument, 0, OPT_NO_STP},
        {"out-of-band", no_argument, 0, OPT_OUT_OF_BAND},
        {"in-band",     no_argument, 0, OPT_IN_BAND},
        {"detach",      no_argument, 0, 'D'},
        {"force",       no_argument, 0, 'f'},
        {"pidfile",     optional_argument, 0, 'P'},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
#ifdef HAVE_OPENSSL
        VCONN_SSL_LONG_OPTIONS
        {"bootstrap-ca-cert", required_argument, 0, OPT_BOOTSTRAP_CA_CERT},
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);
    char *accept_re = NULL;
    int retval;

    /* Set defaults that we can figure out before parsing options. */
    s->n_listeners = 0;
    s->monitor_name = NULL;
    s->fail_mode = FAIL_OPEN;
    s->max_idle = 15;
    s->probe_interval = 15;
    s->max_backoff = 15;
    s->update_resolv_conf = true;
    s->rate_limit = 0;
    s->burst_limit = 0;
    s->enable_stp = false;
    s->in_band = true;
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

        case 'F':
            if (!strcmp(optarg, "open")) {
                s->fail_mode = FAIL_OPEN;
            } else if (!strcmp(optarg, "closed")) {
                s->fail_mode = FAIL_CLOSED;
            } else {
                ofp_fatal(0, "-f or --fail argument must be \"open\" "
                          "or \"closed\"");
            }
            break;

        case OPT_INACTIVITY_PROBE:
            s->probe_interval = atoi(optarg);
            if (s->probe_interval < 5) {
                ofp_fatal(0, "--inactivity-probe argument must be at least 5");
            }
            break;

        case OPT_MAX_IDLE:
            if (!strcmp(optarg, "permanent")) {
                s->max_idle = OFP_FLOW_PERMANENT;
            } else {
                s->max_idle = atoi(optarg);
                if (s->max_idle < 1 || s->max_idle > 65535) {
                    ofp_fatal(0, "--max-idle argument must be between 1 and "
                              "65535 or the word 'permanent'");
                }
            }
            break;

        case OPT_MAX_BACKOFF:
            s->max_backoff = atoi(optarg);
            if (s->max_backoff < 1) {
                ofp_fatal(0, "--max-backoff argument must be at least 1");
            } else if (s->max_backoff > 3600) {
                s->max_backoff = 3600;
            }
            break;

        case OPT_RATE_LIMIT:
            if (optarg) {
                s->rate_limit = atoi(optarg);
                if (s->rate_limit < 1) {
                    ofp_fatal(0, "--rate-limit argument must be at least 1");
                }
            } else {
                s->rate_limit = 1000;
            }
            break;

        case OPT_BURST_LIMIT:
            s->burst_limit = atoi(optarg);
            if (s->burst_limit < 1) {
                ofp_fatal(0, "--burst-limit argument must be at least 1");
            }
            break;

        case OPT_STP:
            s->enable_stp = true;
            break;

        case OPT_NO_STP:
            s->enable_stp = false;
            break;

        case OPT_OUT_OF_BAND:
            s->in_band = false;
            break;

        case OPT_IN_BAND:
            s->in_band = true;
            break;

        case 'D':
            set_detach();
            break;

        case 'P':
            set_pidfile(optarg);
            break;

        case 'f':
            ignore_existing_pidfile();
            break;

        case 'l':
            if (s->n_listeners >= MAX_MGMT) {
                ofp_fatal(0,
                          "-l or --listen may be specified at most %d times",
                          MAX_MGMT);
            }
            s->listener_names[s->n_listeners++] = optarg;
            break;

        case 'm':
            if (s->monitor_name) {
                ofp_fatal(0, "-m or --monitor may only be specified once");
            }
            s->monitor_name = optarg;
            break;

        case 'h':
            usage();

        case 'V':
            printf("%s "VERSION" compiled "__DATE__" "__TIME__"\n", argv[0]);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

#ifdef HAVE_OPENSSL
        VCONN_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            vconn_ssl_set_ca_cert_file(optarg, true);
            break;
#endif

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
        ofp_fatal(0, "need one or two non-option arguments; "
                  "use --help for usage");
    }

    /* Local and remote vconns. */
    s->dp_name = argv[0];
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
        ofp_fatal(0, "%s: %s", accept_re, buffer);
    }
    s->accept_controller_re = accept_re;

    /* Mode of operation. */
    s->discovery = s->controller_name == NULL;
    if (s->discovery && !s->in_band) {
        ofp_fatal(0, "Cannot perform discovery with out-of-band control");
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
    vconn_usage(true, true, true);
    printf("\nController discovery options:\n"
           "  --accept-vconn=REGEX    accept matching discovered controllers\n"
           "  --no-resolv-conf        do not update /etc/resolv.conf\n"
           "\nNetworking options:\n"
           "  -F, --fail=open|closed  when controller connection fails:\n"
           "                            closed: drop all packets\n"
           "                            open (default): act as learning switch\n"
           "  --inactivity-probe=SECS time between inactivity probes\n"
           "  --max-idle=SECS         max idle for flows set up by secchan\n"
           "  --max-backoff=SECS      max time between controller connection\n"
           "                          attempts (default: 15 seconds)\n"
           "  -l, --listen=METHOD     allow management connections on METHOD\n"
           "                          (a passive OpenFlow connection method)\n"
           "  -m, --monitor=METHOD    copy traffic to/from kernel to METHOD\n"
           "                          (a passive OpenFlow connection method)\n"
           "  --out-of-band           controller connection is out-of-band\n"
           "  --stp                   enable 802.1D Spanning Tree Protocol\n"
           "  --no-stp                disable 802.1D Spanning Tree Protocol\n"
           "\nRate-limiting of \"packet-in\" messages to the controller:\n"
           "  --rate-limit[=PACKETS]  max rate, in packets/s (default: 1000)\n"
           "  --burst-limit=BURST     limit on packet credit for idle time\n"
           "\nOther options:\n"
           "  -D, --detach            run in background as daemon\n"
           "  -P, --pidfile[=FILE]    create pidfile (default: %s/secchan.pid)\n"
           "  -f, --force             with -P, start even if already running\n"
           "  -v, --verbose=MODULE[:FACILITY[:LEVEL]]  set logging levels\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n",
           RUNDIR);
    exit(EXIT_SUCCESS);
}
