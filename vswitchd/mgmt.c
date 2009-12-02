/* Copyright (c) 2009 Nicira Networks
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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

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
static bool need_reconfigure = false;
static struct rconn *mgmt_rconn;
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);
static struct svec capabilities;
static struct ofpbuf ext_data_buffer;
static uint32_t ext_data_xid = UINT32_MAX;
uint64_t mgmt_id;


#define TXQ_LIMIT 128         /* Max number of packets to queue for tx. */
struct rconn_packet_counter *txqlen; /* # pkts queued for tx on mgmt_rconn. */

static uint64_t pick_fallback_mgmt_id(void);
static void send_config_update(uint32_t xid, bool use_xid);
static void send_resources_update(uint32_t xid, bool use_xid);
static int recv_ofmp(uint32_t xid, struct ofmp_header *ofmph, size_t len);

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

    ofpbuf_init(&ext_data_buffer, 0);
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
    struct stat s;

    /* XXX SSL should be configurable separate from the bridges.
     * XXX should be possible to de-configure SSL. */
    if (config_string_change("ssl.private-key", &private_key_file)) {
        vconn_ssl_set_private_key_file(private_key_file);
    }

    if (config_string_change("ssl.certificate", &certificate_file)) {
        vconn_ssl_set_certificate_file(certificate_file);
    }

    /* We assume that even if the filename hasn't changed, if the CA cert 
     * file has been removed, that we want to move back into
     * boot-strapping mode.  This opens a small security hole, because
     * the old certificate will still be trusted until vSwitch is
     * restarted.  We may want to address this in vconn's SSL library. */
    if (config_string_change("ssl.ca-cert", &cacert_file) 
            || (stat(cacert_file, &s) && errno == ENOENT)) {
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
        svec_clear(&mgmt_cfg);
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

    /* Reset the extended message buffer when we create a new
     * management connection. */
    ofpbuf_clear(&ext_data_buffer);
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

static int
send_openflow_buffer(struct ofpbuf *buffer)
{               
    int retval;

    if (!mgmt_rconn) {
        VLOG_ERR("attempt to send openflow packet with no rconn\n");
        return EINVAL;
    }

    /* Make sure there's room to transmit the data.  We don't want to
     * fail part way through a send. */
    if (rconn_packet_counter_read(txqlen) >= TXQ_LIMIT) {
        return EAGAIN;
    }

    /* OpenFlow messages use a 16-bit length field, so messages over 64K
     * must be broken into multiple pieces. 
     */
    if (buffer->size <= 65535) {
        update_openflow_length(buffer);
        retval = rconn_send(mgmt_rconn, buffer, txqlen);
        if (retval) {
            VLOG_WARN_RL(&rl, "send to %s failed: %s",
                         rconn_get_name(mgmt_rconn), strerror(retval));
        }   
        return retval;
    } else {
        struct ofmp_header *header = (struct ofmp_header *)buffer->data;
        uint32_t xid = header->header.header.xid;
        size_t remain = buffer->size;
        uint8_t *ptr = buffer->data;
        
        /* Mark the OpenFlow header with a zero length to indicate some
         * funkiness. 
         */
        header->header.header.length = 0;

        while (remain > 0) {
            struct ofpbuf *new_buffer;
            struct ofmp_extended_data *oed;
            size_t new_len = MIN(65535 - sizeof *oed, remain);

            oed = make_ofmp_xid(sizeof *oed, OFMPT_EXTENDED_DATA, xid, 
                    &new_buffer);
            oed->type = header->type;

            if (remain > new_len) {
                oed->flags |= OFMPEDF_MORE_DATA;
            }

            /* Copy the entire original message, including the OpenFlow
             * header, since management protocol structure definitions
             * include these headers.
             */
            ofpbuf_put(new_buffer, ptr, new_len);

            update_openflow_length(new_buffer);
            retval = rconn_send(mgmt_rconn, new_buffer, txqlen);
            if (retval) {
                VLOG_WARN_RL(&rl, "send to %s failed: %s",
                             rconn_get_name(mgmt_rconn), strerror(retval));
                ofpbuf_delete(buffer);
                return retval;
            }   

            remain -= new_len;
            ptr += new_len;
        }

        ofpbuf_delete(buffer);
        return 0;
    }
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
    struct svec port_list;
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
    svec_destroy(&br_list);

    /* On XenServer systems, extended information about virtual interfaces 
     * (VIFs) is available, which is needed by the controller. 
     */ 
    svec_init(&port_list);
    bridge_get_ifaces(&port_list);
    for (i=0; i < port_list.n; i++) {
        const char *vif_uuid, *vm_uuid, *net_uuid;
        uint64_t vif_mac;
        struct ofmptsr_vif *vif_tlv;

        vif_uuid = cfg_get_string(0, "port.%s.vif-uuid", port_list.names[i]);
        if (!vif_uuid) {
            continue;
        }

        vif_tlv = ofpbuf_put_zeros(buffer, sizeof(*vif_tlv));
        vif_tlv->type = htons(OFMPTSR_VIF);
        vif_tlv->len = htons(sizeof(*vif_tlv));

        memcpy(vif_tlv->name, port_list.names[i], strlen(port_list.names[i])+1);
        memcpy(vif_tlv->vif_uuid, vif_uuid, sizeof(vif_tlv->vif_uuid));

        vm_uuid = cfg_get_string(0, "port.%s.vm-uuid", port_list.names[i]);
        if (vm_uuid) {
            memcpy(vif_tlv->vm_uuid, vm_uuid, sizeof(vif_tlv->vm_uuid));
        } else {
            /* In case the vif disappeared underneath us. */
            memset(vif_tlv->vm_uuid, '\0', sizeof(vif_tlv->vm_uuid));
        }

        net_uuid = cfg_get_string(0, "port.%s.net-uuid", port_list.names[i]);
        if (net_uuid) {
            memcpy(vif_tlv->net_uuid, net_uuid, sizeof(vif_tlv->net_uuid));
        } else {
            /* In case the vif disappeared underneath us. */
            memset(vif_tlv->net_uuid, '\0', sizeof(vif_tlv->net_uuid));
        }

        vif_mac = cfg_get_mac(0, "port.%s.vif-mac", port_list.names[i]);
        vif_tlv->vif_mac = htonll(vif_mac);
    }
    svec_destroy(&port_list);

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
recv_ofmp_capability_request(uint32_t xid, const struct ofmp_header *ofmph,
        size_t len)
{
    struct ofmp_capability_request *ofmpcr;

    if (len != sizeof(*ofmpcr)) {
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
recv_ofmp_resources_request(uint32_t xid, const void *msg UNUSED, 
        size_t len UNUSED)
{
    send_resources_update(xid, true);
    return 0;
}

static int
recv_ofmp_config_request(uint32_t xid, const struct ofmp_header *ofmph, 
        size_t len)
{
    struct ofmp_config_request *ofmpcr;

    if (len != sizeof(*ofmpcr)) {
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
recv_ofmp_config_update(uint32_t xid, const struct ofmp_header *ofmph,
        size_t len)
{
    struct ofmp_config_update *ofmpcu;
    int data_len;

    data_len = len - sizeof(*ofmpcu);
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

        /* Check if our local view matches the controller, in which
         * case, it is likely that there were local modifications
         * without our being told to reread the config file. */
        if (!memcmp(cfg_cookie, ofmpcu->cookie, sizeof cfg_cookie)) {
            VLOG_WARN_RL(&rl, "config appears to have been locally modified "
                              "without having told ovs-vswitchd to reload");
        }
        send_config_update_ack(xid, false);
        return 0;
    }

    /* xxx We should probably do more sanity checking than this. */

    cfg_write_data(ofmpcu->data, data_len);
    cfg_unlock();

    /* Send the ACK before running reconfigure, since our management
     * connection settings may have changed. */
    send_config_update_ack(xid, true);

    need_reconfigure = true;

    return 0;
}

static int
recv_ofmp_extended_data(uint32_t xid, const struct ofmp_header *ofmph,
        size_t len)
{
    int data_len;
    struct ofmp_extended_data *ofmped;

    if (len <= sizeof(*ofmped)) {
        /* xxx Send error. */
        return -EINVAL;
    }

    ext_data_xid = xid;
    ofmped = (struct ofmp_extended_data *)ofmph;

    data_len = len - sizeof(*ofmped);
    ofpbuf_put(&ext_data_buffer, ofmped->data, data_len);

    if (!(ofmped->flags & OFMPEDF_MORE_DATA)) {
        struct ofmp_header *new_oh;
        int error;

        /* An embedded message must be greater than the size of an
         * OpenFlow message. */
        new_oh = ofpbuf_at(&ext_data_buffer, 0, 65536);
        if (!new_oh) {
            VLOG_WARN_RL(&rl, "received short embedded message: %zu\n",
                    ext_data_buffer.size);
            return -EINVAL;
        }

        /* Make sure that this is a management message and that there's
         * not an embedded extended data message. */
        if ((new_oh->header.vendor != htonl(NX_VENDOR_ID))
                || (new_oh->header.subtype != htonl(NXT_MGMT))
                || (new_oh->type == htonl(OFMPT_EXTENDED_DATA))) {
            VLOG_WARN_RL(&rl, "received bad embedded message\n");
            return -EINVAL;
        }
        new_oh->header.header.xid = ext_data_xid;
        new_oh->header.header.length = 0;

        error = recv_ofmp(xid, ext_data_buffer.data, ext_data_buffer.size);
        ofpbuf_clear(&ext_data_buffer);

        return error;
    }

    return 0;
}

/* Handles receiving a management message.  Generally, this function
 * will be called 'len' set to zero, and the length will be derived by
 * the OpenFlow header.  With the extended data message, management
 * messages are not constrained by OpenFlow's 64K message length limit.  
 * The extended data handler calls this function with the 'len' set to
 * the total message length and the OpenFlow header's length field is 
 * ignored.
 */
static
int recv_ofmp(uint32_t xid, struct ofmp_header *ofmph, size_t len)
{
    if (!len) {
        len = ntohs(ofmph->header.header.length);
    }

    /* Reset the extended data buffer if this isn't a continuation of an 
     * existing extended data message. */
    if (ext_data_xid != xid) {
        ofpbuf_clear(&ext_data_buffer);
    }

    /* xxx Should sanity-check for min/max length */
    switch (ntohs(ofmph->type)) 
    {
        case OFMPT_CAPABILITY_REQUEST:
            return recv_ofmp_capability_request(xid, ofmph, len);
        case OFMPT_RESOURCES_REQUEST:
            return recv_ofmp_resources_request(xid, ofmph, len);
        case OFMPT_CONFIG_REQUEST:
            return recv_ofmp_config_request(xid, ofmph, len);
        case OFMPT_CONFIG_UPDATE:
            return recv_ofmp_config_update(xid, ofmph, len);
        case OFMPT_EXTENDED_DATA:
            return recv_ofmp_extended_data(xid, ofmph, len);
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
        return recv_ofmp(xid, (struct ofmp_header *)oh, 0);

    default:
        send_error_msg(xid, OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE, 
                oh, ntohs(nh->header.length));
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

bool 
mgmt_run(void)
{
    int i;

    if (!mgmt_rconn) {
        return false;
    }

    need_reconfigure = false;
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

    return need_reconfigure;
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
