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
#include "port-watcher.h"
#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include "dynamic-string.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "port-array.h"
#include "rconn.h"
#include "timeval.h"
#include "vconn.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_port_watcher
#include "vlog.h"

struct port_watcher_cb {
    port_changed_cb_func *port_changed;
    void *aux;
};

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

void
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

void
port_watcher_register_callback(struct port_watcher *pw,
                               port_changed_cb_func *port_changed,
                               void *aux)
{
    assert(pw->n_cbs < ARRAY_SIZE(pw->cbs));
    pw->cbs[pw->n_cbs].port_changed = port_changed;
    pw->cbs[pw->n_cbs].aux = aux;
    pw->n_cbs++;
}

void
port_watcher_register_local_port_callback(struct port_watcher *pw,
                                          local_port_changed_cb_func *cb,
                                          void *aux)
{
    assert(pw->n_local_cbs < ARRAY_SIZE(pw->local_cbs));
    pw->local_cbs[pw->n_local_cbs].local_port_changed = cb;
    pw->local_cbs[pw->n_local_cbs].aux = aux;
    pw->n_local_cbs++;
}

uint32_t
port_watcher_get_config(const struct port_watcher *pw, uint16_t port_no)
{
    struct ofp_phy_port *p = lookup_port(pw, port_no);
    return p ? ntohl(p->config) : 0;
}

const char *
port_watcher_get_name(const struct port_watcher *pw, uint16_t port_no)
{
    struct ofp_phy_port *p = lookup_port(pw, port_no);
    return p ? (const char *) p->name : NULL;
}

const uint8_t *
port_watcher_get_hwaddr(const struct port_watcher *pw, uint16_t port_no) 
{
    struct ofp_phy_port *p = lookup_port(pw, port_no);
    return p ? p->hw_addr : NULL;
}

void
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

bool
port_watcher_is_ready(const struct port_watcher *pw)
{
    return pw->got_feature_reply;
}

static struct hook_class port_watcher_hook_class = { 
    port_watcher_local_packet_cb,                        /* local_packet_cb */
    port_watcher_remote_packet_cb,                       /* remote_packet_cb */
    port_watcher_periodic_cb,                            /* periodic_cb */
    port_watcher_wait_cb,                                /* wait_cb */
    NULL,                                                /* closing_cb */
};

void
port_watcher_start(struct secchan *secchan,
                   struct rconn *local_rconn, struct rconn *remote_rconn,
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
    add_hook(secchan, &port_watcher_hook_class, pw);
}
