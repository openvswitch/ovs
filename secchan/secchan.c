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
#include "secchan.h"
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "discovery.h"
#include "executer.h"
#include "fail-open.h"
#include "fault.h"
#include "in-band.h"
#include "list.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "port-watcher.h"
#include "poll-loop.h"
#include "ratelimit.h"
#include "rconn.h"
#ifdef SUPPORT_SNAT
#include "snat.h"
#endif
#include "flow-end.h"
#include "stp-secchan.h"
#include "status.h"
#include "timeval.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "vlog-socket.h"

#include "vlog.h"
#define THIS_MODULE VLM_secchan

struct hook {
    const struct hook_class *class;
    void *aux;
};

struct secchan {
    struct hook *hooks;
    size_t n_hooks, allocated_hooks;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static void parse_options(int argc, char *argv[], struct settings *);
static void usage(void) NO_RETURN;

static char *vconn_name_without_subscription(const char *);
static struct pvconn *open_passive_vconn(const char *name);
static struct vconn *accept_vconn(struct pvconn *pvconn);

static struct relay *relay_create(struct rconn *async,
                                  struct rconn *local, struct rconn *remote,
                                  bool is_mgmt_conn);
static struct relay *relay_accept(const struct settings *, struct pvconn *);
static void relay_run(struct relay *, struct secchan *);
static void relay_wait(struct relay *);
static void relay_destroy(struct relay *);

int
main(int argc, char *argv[])
{
    struct settings s;

    struct list relays = LIST_INITIALIZER(&relays);

    struct secchan secchan;

    struct pvconn *monitor;

    struct pvconn *listeners[MAX_MGMT];
    size_t n_listeners;

    char *local_rconn_name;
    struct rconn *async_rconn, *local_rconn, *remote_rconn;
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

    secchan.hooks = NULL;
    secchan.n_hooks = 0;
    secchan.allocated_hooks = 0;

    /* Start listening for management and monitoring connections. */
    n_listeners = 0;
    for (i = 0; i < s.n_listeners; i++) {
        listeners[n_listeners++] = open_passive_vconn(s.listener_names[i]);
    }
    monitor = s.monitor_name ? open_passive_vconn(s.monitor_name) : NULL;

    /* Initialize switch status hook. */
    switch_status_start(&secchan, &s, &switch_status);

    die_if_already_running();
    daemonize();

    /* Start listening for vlogconf requests. */
    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        ofp_fatal(retval, "Could not listen for vlog connections");
    }

    VLOG_WARN("OpenFlow reference implementation version %s", VERSION BUILDNR);
    VLOG_WARN("OpenFlow protocol version 0x%02x", OFP_VERSION);

    /* Check datapath name, to try to catch command-line invocation errors. */
    if (strncmp(s.dp_name, "nl:", 3) && strncmp(s.dp_name, "unix:", 5)
        && !s.controller_name) {
        VLOG_WARN("Controller not specified and datapath is not nl: or "
                  "unix:.  (Did you forget to specify the datapath?)");
    }

    if (!strncmp(s.dp_name, "nl:", 3)) {
        /* Connect to datapath with a subscription for asynchronous events.  By
         * separating the connection for asynchronous events from that for
         * request and replies we prevent the socket receive buffer from being
         * filled up by received packet data, which in turn would prevent
         * getting replies to any Netlink messages we send to the kernel. */
        async_rconn = rconn_create(0, s.max_backoff);
        rconn_connect(async_rconn, s.dp_name);
        switch_status_register_category(switch_status, "async",
                                        rconn_status_cb, async_rconn);
    } else {
        /* No need for a separate asynchronous connection: we must be connected
         * to the user datapath, which is smart enough to discard packet events
         * instead of message replies.  In fact, having a second connection
         * would work against us since we'd get double copies of asynchronous
         * event messages (the user datapath provides no way to turn off
         * asynchronous events). */
        async_rconn = NULL;
    }

    /* Connect to datapath without a subscription, for requests and replies. */
    local_rconn_name = vconn_name_without_subscription(s.dp_name);
    local_rconn = rconn_create(0, s.max_backoff);
    rconn_connect(local_rconn, local_rconn_name);
    free(local_rconn_name);
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
    controller_relay = relay_create(async_rconn, local_rconn, remote_rconn,
                                    false);
    list_push_back(&relays, &controller_relay->node);

    /* Set up hooks. */
    port_watcher_start(&secchan, local_rconn, remote_rconn, &pw);
    discovery = s.discovery ? discovery_init(&s, pw, switch_status) : NULL;
#ifdef SUPPORT_SNAT
    snat_start(&secchan, pw);
#endif
    flow_end_start(&secchan, s.netflow_dst, local_rconn, remote_rconn);
    if (s.enable_stp) {
        stp_start(&secchan, &s, pw, local_rconn, remote_rconn);
    }
    if (s.in_band) {
        in_band_start(&secchan, &s, switch_status, pw, remote_rconn);
    }
    if (s.fail_mode == FAIL_OPEN) {
        fail_open_start(&secchan, &s, switch_status,
                        local_rconn, remote_rconn);
    }
    if (s.rate_limit) {
        rate_limit_start(&secchan, &s, switch_status, remote_rconn);
    }
    if (s.command_acl[0]) {
        executer_start(&secchan, &s);
    }

    for (;;) {
        struct relay *r, *n;
        size_t i;

        /* Do work. */
        LIST_FOR_EACH_SAFE (r, n, struct relay, node, &relays) {
            relay_run(r, &secchan);
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
                /* XXX should monitor async_rconn too but rconn_add_monitor()
                 * takes ownership of the vconn passed in. */
                rconn_add_monitor(local_rconn, new);
            }
        }
        for (i = 0; i < secchan.n_hooks; i++) {
            if (secchan.hooks[i].class->periodic_cb) {
                secchan.hooks[i].class->periodic_cb(secchan.hooks[i].aux);
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
        for (i = 0; i < secchan.n_hooks; i++) {
            if (secchan.hooks[i].class->wait_cb) {
                secchan.hooks[i].class->wait_cb(secchan.hooks[i].aux);
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
        VLOG_WARN_RL(&rl, "accept failed (%s)", strerror(retval));
    }
    return new;
}

void
add_hook(struct secchan *secchan, const struct hook_class *class, void *aux)
{
    struct hook *hook;

    if (secchan->n_hooks >= secchan->allocated_hooks) {
        secchan->allocated_hooks = secchan->allocated_hooks * 2 + 1;
        secchan->hooks = xrealloc(secchan->hooks,
                                  (sizeof *secchan->hooks
                                   * secchan->allocated_hooks));
    }
    hook = &secchan->hooks[secchan->n_hooks++];
    hook->class = class;
    hook->aux = aux;
}

struct ofp_packet_in *
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

bool
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

/* Returns a malloc'd string containing a copy of 'vconn_name' modified not to
 * subscribe to asynchronous messages such as 'ofp_packet_in' events (if
 * possible). */
static char *
vconn_name_without_subscription(const char *vconn_name)
{
    int nl_index;
    if (sscanf(vconn_name, "nl:%d", &nl_index) == 1) {
        /* nl:123 or nl:123:1 opens a netlink connection to local datapath 123.
         * nl:123:0 opens a netlink connection to local datapath 123 without
         * obtaining a subscription for ofp_packet_in or ofp_flow_expired
         * messages. */
        return xasprintf("nl:%d:0", nl_index);
    } else {
        /* We don't have a way to specify not to subscribe to those messages
         * for other transports.  (That's a defect: really this should be in
         * the OpenFlow protocol, not the Netlink transport). */
        VLOG_WARN_RL(&rl, "new management connection will receive "
                     "asynchronous messages");
        return xstrdup(vconn_name);
    }
}

static struct relay *
relay_accept(const struct settings *s, struct pvconn *pvconn)
{
    struct vconn *new_remote, *new_local;
    struct rconn *r1, *r2;
    char *vconn_name;
    int retval;

    new_remote = accept_vconn(pvconn);
    if (!new_remote) {
        return NULL;
    }

    vconn_name = vconn_name_without_subscription(s->dp_name);
    retval = vconn_open(vconn_name, OFP_VERSION, &new_local);
    if (retval) {
        VLOG_ERR_RL(&rl, "could not connect to %s (%s)",
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

    return relay_create(NULL, r1, r2, true);
}

static struct relay *
relay_create(struct rconn *async, struct rconn *local, struct rconn *remote,
             bool is_mgmt_conn)
{
    struct relay *r = xcalloc(1, sizeof *r);
    r->halves[HALF_LOCAL].rconn = local;
    r->halves[HALF_REMOTE].rconn = remote;
    r->is_mgmt_conn = is_mgmt_conn;
    r->async_rconn = async;
    return r;
}

static bool
call_local_packet_cbs(struct secchan *secchan, struct relay *r)
{
    const struct hook *h;
    for (h = secchan->hooks; h < &secchan->hooks[secchan->n_hooks]; h++) {
        bool (*cb)(struct relay *, void *aux) = h->class->local_packet_cb;
        if (cb && (cb)(r, h->aux)) {
            return true;
        }
    }
    return false;
}

static bool
call_remote_packet_cbs(struct secchan *secchan, struct relay *r)
{
    const struct hook *h;
    for (h = secchan->hooks; h < &secchan->hooks[secchan->n_hooks]; h++) {
        bool (*cb)(struct relay *, void *aux) = h->class->remote_packet_cb;
        if (cb && (cb)(r, h->aux)) {
            return true;
        }
    }
    return false;
}

static void
relay_run(struct relay *r, struct secchan *secchan)
{
    int iteration;
    int i;

    if (r->async_rconn) {
        rconn_run(r->async_rconn);
    }
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
                if (!this->rxbuf && i == HALF_LOCAL && r->async_rconn) {
                    this->rxbuf = rconn_recv(r->async_rconn);
                }
                if (this->rxbuf && (i == HALF_REMOTE || !r->is_mgmt_conn)) {
                    if (i == HALF_LOCAL
                        ? call_local_packet_cbs(secchan, r)
                        : call_remote_packet_cbs(secchan, r))
                    {
                        ofpbuf_delete(this->rxbuf);
                        this->rxbuf = NULL;
                        progress = true;
                        break;
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

    if (r->async_rconn) {
        rconn_run_wait(r->async_rconn);
    }
    for (i = 0; i < 2; i++) {
        struct half *this = &r->halves[i];

        rconn_run_wait(this->rconn);
        if (!this->rxbuf) {
            rconn_recv_wait(this->rconn);
            if (i == HALF_LOCAL && r->async_rconn) {
                rconn_recv_wait(r->async_rconn);
            }
        }
    }
}

static void
relay_destroy(struct relay *r)
{
    int i;

    list_remove(&r->node);
    rconn_destroy(r->async_rconn);
    for (i = 0; i < 2; i++) {
        struct half *this = &r->halves[i];
        rconn_destroy(this->rconn);
        ofpbuf_delete(this->rxbuf);
    }
    free(r);
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
        OPT_IN_BAND,
        OPT_COMMAND_ACL,
        OPT_COMMAND_DIR,
        OPT_NETFLOW,
        VLOG_OPTION_ENUMS
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
        {"command-acl", required_argument, 0, OPT_COMMAND_ACL},
        {"command-dir", required_argument, 0, OPT_COMMAND_DIR},
        {"netflow",     required_argument, 0, OPT_NETFLOW},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
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
    s->command_acl = "";
    s->command_dir = xasprintf("%s/commands", ofp_pkgdatadir);
    s->netflow_dst = NULL;
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

        case OPT_COMMAND_ACL:
            s->command_acl = (s->command_acl[0]
                              ? xasprintf("%s,%s", s->command_acl, optarg)
                              : optarg);
            break;

        case OPT_COMMAND_DIR:
            s->command_dir = optarg;
            break;

        case OPT_NETFLOW:
            if (s->netflow_dst) {
                ofp_fatal(0, "--netflow may only be specified once");
            }
            s->netflow_dst = optarg;
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
            printf("%s %s compiled "__DATE__" "__TIME__"\n",
                   program_name, VERSION BUILDNR);
            exit(EXIT_SUCCESS);

        DAEMON_OPTION_HANDLERS

        VLOG_OPTION_HANDLERS

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
           "usage: %s [OPTIONS] DATAPATH [CONTROLLER]\n"
           "DATAPATH is an active connection method to a local datapath.\n"
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
           "  --netflow=HOST:PORT     send NetFlow v5 messages when flows end\n"
           "\nRate-limiting of \"packet-in\" messages to the controller:\n"
           "  --rate-limit[=PACKETS]  max rate, in packets/s (default: 1000)\n"
           "  --burst-limit=BURST     limit on packet credit for idle time\n"
           "\nRemote command execution options:\n"
           "  --command-acl=[!]GLOB[,[!]GLOB...] set allowed/denied commands\n"
           "  --command-dir=DIR       set command dir (default: %s/commands)\n",
           ofp_pkgdatadir);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
