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
#include "snat.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include "openflow/nicira-ext.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "port-watcher.h"

#define THIS_MODULE VLM_snat
#include "vlog.h"

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

static struct hook_class snat_hook_class = {
    NULL,                       /* local_packet_cb */
    snat_remote_packet_cb,      /* remote_packet_cb */
    NULL,                       /* periodic_cb */
    NULL,                       /* wait_cb */
    NULL,                       /* closing_cb */
};

void
snat_start(struct secchan *secchan, struct port_watcher *pw)
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
    add_hook(secchan, &snat_hook_class, snat);
}
