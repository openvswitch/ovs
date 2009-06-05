/* Copyright (c) 2009 Nicira Networks
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, Nicira Networks gives permission
 * to link the code of its release of vswitchd with the OpenSSL project's
 * "OpenSSL" library (or with modified versions of it that use the same
 * license as the "OpenSSL" library), and distribute the linked
 * executables.  You must obey the GNU General Public License in all
 * respects for all of the code used other than "OpenSSL".  If you modify
 * this file, you may extend this exception to your version of the file,
 * but you are not obligated to do so.  If you do not wish to do so,
 * delete this exception statement from your version.
 *
 */

#include <config.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "bridge.h"
#include "cfg.h"
#include "coverage.h"
#include "list.h"
#include "mgmt.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openflow/openflow-mgmt.h"
#include "ofpbuf.h"
#include "ovs-vswitchd.h"
#include "packets.h"
#include "rconn.h"
#include "svec.h"
#include "vconn.h"
#include "vconn-ssl.h"
#include "xenserver.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_mgmt
#include "vlog.h"

#define MAX_BACKOFF_DEFAULT 15
#define INACTIVITY_PROBE_DEFAULT 15

static struct svec mgmt_cfg;
static uint8_t cfg_cookie[CFG_COOKIE_LEN];
static struct rconn *mgmt_rconn;
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);
static struct svec capabilities;
uint64_t mgmt_id;


#define TXQ_LIMIT 128         /* Max number of packets to queue for tx. */
struct rconn_packet_counter *txqlen; /* # pkts queued for tx on mgmt_rconn. */

static uint64_t pick_fallback_mgmt_id(void);
static void send_config_update(uint32_t xid, bool use_xid);
static void send_resources_update(uint32_t xid, bool use_xid);

void
mgmt_init(void)
{
    txqlen = rconn_packet_counter_create();

    svec_init(&mgmt_cfg);
    svec_init(&capabilities);
    svec_add_nocopy(&capabilities, 
            xasprintf("com.nicira.mgmt.manager=true\n"));

    mgmt_id = cfg_get_dpid(0, "mgmt.id");
    if (!mgmt_id) {
        /* Randomly generate a mgmt id */
        mgmt_id = pick_fallback_mgmt_id();
    }
}

#ifdef HAVE_OPENSSL
static bool
config_string_change(const char *key, char **valuep)
{
    const char *value = cfg_get_string(0, "%s", key);
    if (value && (!*valuep || strcmp(value, *valuep))) {
        free(*valuep);
        *valuep = xstrdup(value);
        return true;
    } else {
        return false;
    }
}

static void
mgmt_configure_ssl(void)
{
    static char *private_key_file;
    static char *certificate_file;
    static char *cacert_file;

    /* XXX SSL should be configurable separate from the bridges.
     * XXX should be possible to de-configure SSL. */
    if (config_string_change("ssl.private-key", &private_key_file)) {
        vconn_ssl_set_private_key_file(private_key_file);
    }

    if (config_string_change("ssl.certificate", &certificate_file)) {
        vconn_ssl_set_certificate_file(certificate_file);
    }

    if (config_string_change("ssl.ca-cert", &cacert_file)) {
        vconn_ssl_set_ca_cert_file(cacert_file,
                cfg_get_bool(0, "ssl.bootstrap-ca-cert"));
    }
}
#endif

void
mgmt_reconfigure(void)
{
    struct svec new_cfg;
    uint8_t new_cookie[CFG_COOKIE_LEN];
    bool cfg_updated = false;
    const char *controller_name;
    int max_backoff;
    int inactivity_probe;
    int retval;

    if (!cfg_has_section("mgmt")) {
        if (mgmt_rconn) {
            rconn_destroy(mgmt_rconn);
            mgmt_rconn = NULL;
        }
        return;
    }

    /* If this is an established connection, send a resources update. */
    /* xxx This is wasteful if there were no resource changes!!! */
    if (mgmt_rconn) {
        send_resources_update(0, false);
    }

    cfg_get_cookie(new_cookie);
    if (memcmp(cfg_cookie, new_cookie, sizeof(cfg_cookie))) {
        memcpy(cfg_cookie, new_cookie, sizeof(cfg_cookie));
        cfg_updated = true;
    }

    svec_init(&new_cfg);
    cfg_get_section(&new_cfg, "mgmt");
    if (svec_equal(&mgmt_cfg, &new_cfg)) {
        /* Reconnecting to the controller causes the config file to be
         * resent automatically.  If we're not reconnecting and the
         * config file has changed, we need to notify the controller of
         * changes. */
        if (cfg_updated && mgmt_rconn) {
            send_config_update(0, false);
        }
        svec_destroy(&new_cfg);
        return;
    }

    controller_name = cfg_get_string(0, "mgmt.controller");
    if (!controller_name) {
        VLOG_ERR("no controller specified for managment");
        svec_destroy(&new_cfg);
        return;
    }

    max_backoff = cfg_get_int(0, "mgmt.max-backoff");
    if (max_backoff < 1) {
        max_backoff = MAX_BACKOFF_DEFAULT;
    } else if (max_backoff > 3600) {
        max_backoff = 3600;
    }

    inactivity_probe = cfg_get_int(0, "mgmt.inactivity-probe");
    if (inactivity_probe < 5) {
        inactivity_probe = INACTIVITY_PROBE_DEFAULT;
    }

    /* xxx If this changes, we need to restart bridges to use new id,
     * xxx but they need the id before the connect to controller, but we
     * xxx need their dpids. */
    /* Check if a different mgmt id has been assigned. */
    if (cfg_has("mgmt.id")) {
        uint64_t cfg_mgmt_id = cfg_get_dpid(0, "mgmt.id");
        if (cfg_mgmt_id != mgmt_id) {
            mgmt_id = cfg_mgmt_id;
        }
    }

    svec_swap(&new_cfg, &mgmt_cfg);
    svec_destroy(&new_cfg);

#ifdef HAVE_OPENSSL
    /* Configure SSL. */
    mgmt_configure_ssl();
#endif

    if (mgmt_rconn) {
        rconn_destroy(mgmt_rconn);
        mgmt_rconn = NULL;
    }
    mgmt_rconn = rconn_create(inactivity_probe, max_backoff);
    retval = rconn_connect(mgmt_rconn, controller_name);
    if (retval == EAFNOSUPPORT) {
        VLOG_ERR("no support for %s vconn", controller_name);
    }
}

static int
send_openflow_buffer(struct ofpbuf *buffer)
{               
    int retval;

    if (!mgmt_rconn) {
        VLOG_ERR("attempt to send openflow packet with no rconn\n");
        return EINVAL;
    }

    update_openflow_length(buffer);
    retval = rconn_send_with_limit(mgmt_rconn, buffer, txqlen, TXQ_LIMIT);
    if (retval) {
        VLOG_WARN_RL(&rl, "send to %s failed: %s",
                     rconn_get_name(mgmt_rconn), strerror(retval));
    }   
    return retval;
}   
    
static void
send_features_reply(uint32_t xid)
{
    struct ofpbuf *buffer;
    struct ofp_switch_features *ofr;

    ofr = make_openflow_xid(sizeof *ofr, OFPT_FEATURES_REPLY, xid, &buffer);
    ofr->datapath_id  = 0;
    ofr->n_tables     = 0;
    ofr->n_buffers    = 0;
    ofr->capabilities = 0;
    ofr->actions      = 0;
    send_openflow_buffer(buffer);
}

static void *
make_ofmp_xid(size_t ofmp_len, uint16_t type, uint32_t xid,
        struct ofpbuf **bufferp)
{
    struct ofmp_header *oh;

    oh = make_openflow_xid(ofmp_len, OFPT_VENDOR, xid, bufferp);
    oh->header.vendor = htonl(NX_VENDOR_ID);
    oh->header.subtype = htonl(NXT_MGMT);
    oh->type = htons(type);

    return oh;
}

static void *
make_ofmp(size_t ofmp_len, uint16_t type, struct ofpbuf **bufferp)
{
    struct ofmp_header *oh;

    oh = make_openflow(ofmp_len, OFPT_VENDOR, bufferp);
    oh->header.vendor = htonl(NX_VENDOR_ID);
    oh->header.subtype = htonl(NXT_MGMT);
    oh->type = htons(type);

    return oh;
}

static void 
send_capability_reply(uint32_t xid)
{
    int i;
    struct ofpbuf *buffer;
    struct ofmp_capability_reply *ofmpcr;

    ofmpcr = make_ofmp_xid(sizeof *ofmpcr, OFMPT_CAPABILITY_REPLY, 
            xid, &buffer);
    ofmpcr->format = htonl(OFMPCOF_SIMPLE);
    ofmpcr->mgmt_id = htonll(mgmt_id);
    for (i=0; i<capabilities.n; i++) {
        ofpbuf_put(buffer, capabilities.names[i], 
                strlen(capabilities.names[i]));
    }
    send_openflow_buffer(buffer);
}

static void 
send_resources_update(uint32_t xid, bool use_xid)
{
    struct ofpbuf *buffer;
    struct ofmp_resources_update *ofmpru;
    struct ofmp_tlv *tlv;
    struct svec br_list;
    const char *host_uuid;
    int i;

    if (use_xid) {
        ofmpru = make_ofmp_xid(sizeof *ofmpru, OFMPT_RESOURCES_UPDATE, 
                xid, &buffer);
    } else {
        ofmpru = make_ofmp(sizeof *ofmpru, OFMPT_RESOURCES_UPDATE, &buffer);
    }

    /* On XenServer systems, each host has its own UUID, which we provide
     * to the controller. 
     */ 
    host_uuid = xenserver_get_host_uuid();
    if (host_uuid) {
        struct ofmptsr_mgmt_uuid *mgmt_uuid_tlv;

        mgmt_uuid_tlv = ofpbuf_put_zeros(buffer, sizeof(*mgmt_uuid_tlv));
        mgmt_uuid_tlv->type = htons(OFMPTSR_MGMT_UUID);
        mgmt_uuid_tlv->len = htons(sizeof(*mgmt_uuid_tlv));
        mgmt_uuid_tlv->mgmt_id = htonll(mgmt_id);
        memcpy(mgmt_uuid_tlv->uuid, host_uuid, OFMP_UUID_LEN);
    }

    svec_init(&br_list);
    cfg_get_subsections(&br_list, "bridge");
    for (i=0; i < br_list.n; i++) {
        struct ofmptsr_dp *dp_tlv;
        uint64_t dp_id;
        int n_uuid;

        dp_id = bridge_get_datapathid(br_list.names[i]);
        if (!dp_id) {
            VLOG_WARN_RL(&rl, "bridge %s doesn't seem to exist", 
                    br_list.names[i]);
            continue;
        }
        dp_tlv = ofpbuf_put_zeros(buffer, sizeof(*dp_tlv));
        dp_tlv->type = htons(OFMPTSR_DP);
        dp_tlv->len = htons(sizeof(*dp_tlv));

        dp_tlv->dp_id = htonll(dp_id);
        memcpy(dp_tlv->name, br_list.names[i], strlen(br_list.names[i])+1);

        /* On XenServer systems, each network has one or more UUIDs
         * associated with it, which we provide to the controller. 
         */
        n_uuid = cfg_count("bridge.%s.xs-network-uuids", br_list.names[i]);
        if (n_uuid) {
            struct ofmptsr_dp_uuid *dp_uuid_tlv;
            size_t tlv_len = sizeof(*dp_uuid_tlv) + n_uuid * OFMP_UUID_LEN;
            int j;

            dp_uuid_tlv = ofpbuf_put_zeros(buffer, sizeof(*dp_uuid_tlv));
            dp_uuid_tlv->type = htons(OFMPTSR_DP_UUID);
            dp_uuid_tlv->len = htons(tlv_len);
            dp_uuid_tlv->dp_id = htonll(dp_id);

            for (j=0; j<n_uuid; j++) {
                const char *dp_uuid = cfg_get_string(j, 
                        "bridge.%s.xs-network-uuids", br_list.names[i]);

                /* The UUID list could change underneath us, so just
                 * fill with zeros in that case.  Another update will be
                 * initiated shortly, which should contain corrected data.
                 */
                if (dp_uuid) {
                    ofpbuf_put(buffer, dp_uuid, OFMP_UUID_LEN);
                } else {
                    ofpbuf_put_zeros(buffer, OFMP_UUID_LEN);
                }
            }
        }
    }

    /* Put end marker. */
    tlv = ofpbuf_put_zeros(buffer, sizeof(*tlv));
    tlv->type = htons(OFMPTSR_END);
    tlv->len = htons(sizeof(*tlv));
    send_openflow_buffer(buffer);
}

static void 
send_config_update(uint32_t xid, bool use_xid)
{
    struct ofpbuf *buffer;
    struct ofmp_config_update *ofmpcu;

    if (use_xid) {
        ofmpcu = make_ofmp_xid(sizeof *ofmpcu, OFMPT_CONFIG_UPDATE, 
                xid, &buffer);
    } else {
        ofmpcu = make_ofmp(sizeof *ofmpcu, OFMPT_CONFIG_UPDATE, &buffer);
    }

    ofmpcu->format = htonl(OFMPCOF_SIMPLE);
    memcpy(ofmpcu->cookie, cfg_cookie, sizeof(ofmpcu->cookie));
    cfg_buf_put(buffer);
    send_openflow_buffer(buffer);
}

static void 
send_config_update_ack(uint32_t xid, bool success)
{
    struct ofpbuf *buffer;
    struct ofmp_config_update_ack *ofmpcua;

    ofmpcua = make_ofmp_xid(sizeof *ofmpcua, OFMPT_CONFIG_UPDATE_ACK, 
            xid, &buffer);

    ofmpcua->format = htonl(OFMPCOF_SIMPLE);
    if (success) {
        ofmpcua->flags = htonl(OFMPCUAF_SUCCESS);
    }
    cfg_get_cookie(ofmpcua->cookie);
    send_openflow_buffer(buffer);
}

static void
send_ofmp_error_msg(uint32_t xid, uint16_t type, uint16_t code, 
            const void *data, size_t len)
{
    struct ofpbuf *buffer;
    struct ofmp_error_msg *oem;

    oem = make_ofmp_xid(sizeof(*oem)+len, OFMPT_ERROR, xid, &buffer);
    oem->type = htons(type);
    oem->code = htons(code);
    memcpy(oem->data, data, len);
    send_openflow_buffer(buffer);
}

static void
send_error_msg(uint32_t xid, uint16_t type, uint16_t code, 
            const void *data, size_t len)
{
    struct ofpbuf *buffer;
    struct ofp_error_msg *oem;

    oem = make_openflow_xid(sizeof(*oem)+len, OFPT_ERROR, xid, &buffer);
    oem->type = htons(type);
    oem->code = htons(code);
    memcpy(oem->data, data, len);
    send_openflow_buffer(buffer);
}

static int
recv_echo_request(uint32_t xid UNUSED, const void *msg)
{
    const struct ofp_header *rq = msg;
    send_openflow_buffer(make_echo_reply(rq));
    return 0;
}

static int
recv_features_request(uint32_t xid, const void *msg UNUSED)
{
    send_features_reply(xid);
    return 0;
}

static int
recv_set_config(uint32_t xid UNUSED, const void *msg UNUSED)
{
    /* Nothing to configure! */
    return 0;
}

static int
recv_ofmp_capability_request(uint32_t xid, const struct ofmp_header *ofmph)
{
    struct ofmp_capability_request *ofmpcr;

    if (htons(ofmph->header.header.length) != sizeof(*ofmpcr)) {
        /* xxx Send error */
        return -EINVAL;
    }

    ofmpcr = (struct ofmp_capability_request *)ofmph;
    if (ofmpcr->format != htonl(OFMPCAF_SIMPLE)) {
        /* xxx Send error */
        return -EINVAL;
    }

    send_capability_reply(xid);

    return 0;
}

static int
recv_ofmp_resources_request(uint32_t xid, const void *msg UNUSED)
{
    send_resources_update(xid, true);
    return 0;
}

static int
recv_ofmp_config_request(uint32_t xid, const struct ofmp_header *ofmph)
{
    struct ofmp_config_request *ofmpcr;

    if (htons(ofmph->header.header.length) != sizeof(*ofmpcr)) {
        /* xxx Send error */
        return -EINVAL;
    }

    ofmpcr = (struct ofmp_config_request *)ofmph;
    if (ofmpcr->format != htonl(OFMPCOF_SIMPLE)) {
        /* xxx Send error */
        return -EINVAL;
    }

    send_config_update(xid, true);

    return 0;
}

static int
recv_ofmp_config_update(uint32_t xid, const struct ofmp_header *ofmph)
{
    struct ofmp_config_update *ofmpcu;
    int data_len;

    data_len = htons(ofmph->header.header.length) - sizeof(*ofmpcu);
    if (data_len <= sizeof(*ofmpcu)) {
        /* xxx Send error. */
        return -EINVAL;
    }

    ofmpcu = (struct ofmp_config_update *)ofmph;
    if (ofmpcu->format != htonl(OFMPCOF_SIMPLE)) {
        /* xxx Send error */
        return -EINVAL;
    }

    /* Check if the supplied cookie matches our current understanding of
     * it.  If they don't match, tell the controller and let it sort
     * things out. */
    if (cfg_lock(ofmpcu->cookie, 0)) {  
        /* xxx cfg_lock can fail for other reasons, such as being
         * xxx locked... */
        VLOG_WARN_RL(&rl, "config update failed due to bad cookie\n");
        send_config_update_ack(xid, false);
        return 0;
    }

    /* xxx We should probably do more sanity checking than this. */

    cfg_write_data(ofmpcu->data, data_len);
    cfg_unlock();

    /* Send the ACK before running reconfigure, since our management
     * connection settings may have changed. */
    send_config_update_ack(xid, true);

    reconfigure();


    return 0;
}

static
int recv_ofmp(uint32_t xid, struct ofmp_header *ofmph)
{
    /* xxx Should sanity-check for min/max length */
    switch (ntohs(ofmph->type)) 
    {
        case OFMPT_CAPABILITY_REQUEST:
            return recv_ofmp_capability_request(xid, ofmph);
        case OFMPT_RESOURCES_REQUEST:
            return recv_ofmp_resources_request(xid, ofmph);
        case OFMPT_CONFIG_REQUEST:
            return recv_ofmp_config_request(xid, ofmph);
        case OFMPT_CONFIG_UPDATE:
            return recv_ofmp_config_update(xid, ofmph);
        default:
            VLOG_WARN_RL(&rl, "unknown mgmt message: %d", 
                    ntohs(ofmph->type));
            return -EINVAL;
    }
}

static int 
recv_nx_msg(uint32_t xid, const void *oh)
{
    const struct nicira_header *nh = oh;

    switch (ntohl(nh->subtype)) {

    case NXT_MGMT:
        return recv_ofmp(xid, (struct ofmp_header *)oh);

    default:
        send_error_msg(xid, OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE, 
                oh, htons(nh->header.length));
        return -EINVAL;
    }
}

static int
recv_vendor(uint32_t xid, const void *oh)
{
    const struct ofp_vendor_header *ovh = oh;

    switch (ntohl(ovh->vendor))
    {
    case NX_VENDOR_ID:
        return recv_nx_msg(xid, oh);

    default:
        VLOG_WARN_RL(&rl, "unknown vendor: 0x%x", ntohl(ovh->vendor));
        send_error_msg(xid, OFPET_BAD_REQUEST, OFPBRC_BAD_VENDOR, 
                oh, ntohs(ovh->header.length));
        return -EINVAL; 
    }
}

static int
handle_msg(uint32_t xid, const void *msg, size_t length)
{
    int (*handler)(uint32_t, const void *);
    struct ofp_header *oh;
    size_t min_size;

    COVERAGE_INC(mgmt_received);

    /* Check encapsulated length. */
    oh = (struct ofp_header *) msg;
    if (ntohs(oh->length) > length) {
        return -EINVAL;
    }
    assert(oh->version == OFP_VERSION);

    /* Figure out how to handle it. */
    switch (oh->type) {
    case OFPT_ECHO_REQUEST:
        min_size = sizeof(struct ofp_header);
        handler = recv_echo_request;
        break;
    case OFPT_ECHO_REPLY:
        return 0;
    case OFPT_FEATURES_REQUEST:
        min_size = sizeof(struct ofp_header);
        handler = recv_features_request;
        break;
    case OFPT_SET_CONFIG:
        min_size = sizeof(struct ofp_switch_config);
        handler = recv_set_config;
        break;
    case OFPT_VENDOR:
        min_size = sizeof(struct ofp_vendor_header);
        handler = recv_vendor;
        break;
    default:
        VLOG_WARN_RL(&rl, "unknown openflow type: %d", oh->type);
        send_error_msg(xid, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE,
                msg, length);
        return -EINVAL;
    }

    /* Handle it. */
    if (length < min_size) {
        return -EFAULT;
    }
    return handler(xid, msg);
}

void 
mgmt_run(void)
{
    int i;

    if (!mgmt_rconn) {
        return;
    }

    rconn_run(mgmt_rconn);

    /* Do some processing, but cap it at a reasonable amount so that
     * other processing doesn't starve. */
    for (i=0; i<50; i++) {
        struct ofpbuf *buffer;
        struct ofp_header *oh;

        buffer = rconn_recv(mgmt_rconn);
        if (!buffer) {
            break;
        }

        if (buffer->size >= sizeof *oh) {
            oh = buffer->data;
            handle_msg(oh->xid, buffer->data, buffer->size);
            ofpbuf_delete(buffer);
        } else {
            VLOG_WARN_RL(&rl, "received too-short OpenFlow message");
        }
    }
}

void
mgmt_wait(void)
{
    if (!mgmt_rconn) {
        return;
    }

    rconn_run_wait(mgmt_rconn);
    rconn_recv_wait(mgmt_rconn);
}

static uint64_t
pick_fallback_mgmt_id(void)
{
    uint8_t ea[ETH_ADDR_LEN];
    eth_addr_random(ea);
    ea[0] = 0x00;               /* Set Nicira OUI. */
    ea[1] = 0x23;
    ea[2] = 0x20;
    return eth_addr_to_uint64(ea);
}
