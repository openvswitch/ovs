/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "discovery.h"
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include "dhcp-client.h"
#include "dhcp.h"
#include "dpif.h"
#include "netdev.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "status.h"
#include "stream-ssl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(discovery)

struct discovery {
    char *dpif_name;
    char *re;
    bool update_resolv_conf;
    regex_t *regex;
    struct dhclient *dhcp;
    int n_changes;
    struct status_category *ss_cat;
};

static void modify_dhcp_request(struct dhcp_msg *, void *aux);
static bool validate_dhcp_offer(const struct dhcp_msg *, void *aux);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static void
discovery_status_cb(struct status_reply *sr, void *d_)
{
    struct discovery *d = d_;

    status_reply_put(sr, "accept-remote=%s", d->re);
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

int
discovery_create(const char *re, bool update_resolv_conf,
                 struct dpif *dpif, struct switch_status *ss,
                 struct discovery **discoveryp)
{
    struct discovery *d;
    char local_name[IF_NAMESIZE];
    int error;

    d = xzalloc(sizeof *d);

    d->dpif_name = xstrdup(dpif_base_name(dpif));

    /* Controller regular expression. */
    error = discovery_set_accept_controller_re(d, re);
    if (error) {
        goto error_free;
    }
    d->update_resolv_conf = update_resolv_conf;

    /* Initialize DHCP client. */
    error = dpif_port_get_name(dpif, ODPP_LOCAL,
                               local_name, sizeof local_name);
    if (error) {
        VLOG_ERR("%s: failed to query datapath local port: %s",
                 d->dpif_name, strerror(error));
        goto error_regfree;
    }
    error = dhclient_create(local_name, modify_dhcp_request,
                            validate_dhcp_offer, d, &d->dhcp);
    if (error) {
        VLOG_ERR("%s: failed to initialize DHCP client: %s",
                 d->dpif_name, strerror(error));
        goto error_regfree;
    }
    dhclient_set_max_timeout(d->dhcp, 3);
    dhclient_init(d->dhcp, 0);

    d->ss_cat = switch_status_register(ss, "discovery",
                                       discovery_status_cb, d);

    *discoveryp = d;
    return 0;

error_regfree:
    regfree(d->regex);
    free(d->regex);
error_free:
    free(d->dpif_name);
    free(d);
    *discoveryp = 0;
    return error;
}

void
discovery_destroy(struct discovery *d)
{
    if (d) {
        free(d->re);
        regfree(d->regex);
        free(d->regex);
        dhclient_destroy(d->dhcp);
        switch_status_unregister(d->ss_cat);
        free(d->dpif_name);
        free(d);
    }
}

bool
discovery_get_update_resolv_conf(const struct discovery *d)
{
    return d->update_resolv_conf;
}

void
discovery_set_update_resolv_conf(struct discovery *d,
                                 bool update_resolv_conf)
{
    d->update_resolv_conf = update_resolv_conf;
}

const char *
discovery_get_accept_controller_re(const struct discovery *d)
{
    return d->re;
}

int
discovery_set_accept_controller_re(struct discovery *d, const char *re_)
{
    regex_t *regex;
    int error;
    char *re;

    re = (!re_ ? xstrdup(stream_ssl_is_configured() ? "^ssl:.*" : "^tcp:.*")
          : re_[0] == '^' ? xstrdup(re_) : xasprintf("^%s", re_));
    regex = xmalloc(sizeof *regex);
    error = regcomp(regex, re, REG_NOSUB | REG_EXTENDED);
    if (error) {
        size_t length = regerror(error, regex, NULL, 0);
        char *buffer = xmalloc(length);
        regerror(error, regex, buffer, length);
        VLOG_WARN("%s: %s: %s", d->dpif_name, re, buffer);
        free(regex);
        free(re);
        return EINVAL;
    } else {
        if (d->regex) {
            regfree(d->regex);
            free(d->regex);
        }
        free(d->re);

        d->regex = regex;
        d->re = re;
        return 0;
    }
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
    if (d->update_resolv_conf) {
        dhclient_update_resolv_conf(d->dhcp);
    }

    if (dhclient_is_bound(d->dhcp)) {
        *controller_name = dhcp_msg_get_string(dhclient_get_config(d->dhcp),
                                               DHCP_CODE_OFP_CONTROLLER_VCONN);
        VLOG_INFO("%s: discovered controller %s",
                  d->dpif_name, *controller_name);
        d->n_changes++;
    } else {
        *controller_name = NULL;
        if (d->n_changes) {
            VLOG_INFO("%s: discovered controller no longer available",
                      d->dpif_name);
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
modify_dhcp_request(struct dhcp_msg *msg, void *aux OVS_UNUSED)
{
    dhcp_msg_put_string(msg, DHCP_CODE_VENDOR_CLASS, "OpenFlow");
}

static bool
validate_dhcp_offer(const struct dhcp_msg *msg, void *d_)
{
    const struct discovery *d = d_;
    char *vconn_name;
    bool accept;

    vconn_name = dhcp_msg_get_string(msg, DHCP_CODE_OFP_CONTROLLER_VCONN);
    if (!vconn_name) {
        VLOG_WARN_RL(&rl, "%s: rejecting DHCP offer missing controller vconn",
                     d->dpif_name);
        return false;
    }
    accept = !regexec(d->regex, vconn_name, 0, NULL, 0);
    if (!accept) {
        VLOG_WARN_RL(&rl, "%s: rejecting controller vconn that fails to "
                     "match %s", d->dpif_name, d->re);
    }
    free(vconn_name);
    return accept;
}
