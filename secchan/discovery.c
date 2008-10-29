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
#include "discovery.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "dhcp-client.h"
#include "dhcp.h"
#include "netdev.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "port-watcher.h"
#include "secchan.h"
#include "status.h"

#define THIS_MODULE VLM_discovery
#include "vlog.h"

struct discovery
{
    const struct settings *s;
    struct dhclient *dhcp;
    int n_changes;
};

static void modify_dhcp_request(struct dhcp_msg *, void *aux);
static bool validate_dhcp_offer(const struct dhcp_msg *, void *aux);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

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


struct discovery *
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

void
discovery_question_connectivity(struct discovery *d)
{
    if (d->dhcp) {
        dhclient_force_renew(d->dhcp, 15); 
    }
}

bool
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

void
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
        VLOG_WARN_RL(&rl, "rejecting DHCP offer missing controller vconn");
        return false;
    }
    accept = !regexec(&s->accept_controller_regex, vconn_name, 0, NULL, 0);
    if (!accept) {
        VLOG_WARN_RL(&rl, "rejecting controller vconn that fails to match %s",
                     s->accept_controller_re);
    }
    free(vconn_name);
    return accept;
}
