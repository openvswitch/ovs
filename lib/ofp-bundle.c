/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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
#include "openvswitch/ofp-bundle.h"
#include <errno.h>
#include <stdlib.h>
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofp_bundle);

/* Destroys 'bms'. */
void
ofputil_free_bundle_msgs(struct ofputil_bundle_msg *bms, size_t n_bms)
{
    for (size_t i = 0; i < n_bms; i++) {
        switch ((int)bms[i].type) {
        case OFPTYPE_FLOW_MOD:
            free(CONST_CAST(struct ofpact *, bms[i].fm.ofpacts));
            minimatch_destroy(&bms[i].fm.match);
            break;
        case OFPTYPE_GROUP_MOD:
            ofputil_uninit_group_mod(&bms[i].gm);
            break;
        case OFPTYPE_PACKET_OUT:
            free(bms[i].po.ofpacts);
            free(CONST_CAST(void *, bms[i].po.packet));
            break;
        default:
            break;
        }
    }
    free(bms);
}

void
ofputil_encode_bundle_msgs(const struct ofputil_bundle_msg *bms,
                           size_t n_bms, struct ovs_list *requests,
                           enum ofputil_protocol protocol)
{
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);

    for (size_t i = 0; i < n_bms; i++) {
        struct ofpbuf *request = NULL;

        switch ((int)bms[i].type) {
        case OFPTYPE_FLOW_MOD:
            request = ofputil_encode_flow_mod(&bms[i].fm, protocol);
            break;
        case OFPTYPE_GROUP_MOD:
            request = ofputil_encode_group_mod(version, &bms[i].gm);
            break;
        case OFPTYPE_PACKET_OUT:
            request = ofputil_encode_packet_out(&bms[i].po, protocol);
            break;
        default:
            break;
        }
        if (request) {
            ovs_list_push_back(requests, &request->list_node);
        }
    }
}

enum ofperr
ofputil_decode_bundle_ctrl(const struct ofp_header *oh,
                           struct ofputil_bundle_ctrl_msg *msg)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    ovs_assert(raw == OFPRAW_OFPT14_BUNDLE_CONTROL
               || raw == OFPRAW_ONFT13_BUNDLE_CONTROL);

    const struct ofp14_bundle_ctrl_msg *m = b.msg;
    msg->bundle_id = ntohl(m->bundle_id);
    msg->type = ntohs(m->type);
    msg->flags = ntohs(m->flags);

    return 0;
}

struct ofpbuf *
ofputil_encode_bundle_ctrl_request(enum ofp_version ofp_version,
                                   struct ofputil_bundle_ctrl_msg *bc)
{
    struct ofpbuf *request;
    struct ofp14_bundle_ctrl_msg *m;

    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
    case OFP12_VERSION:
        ovs_fatal(0, "bundles need OpenFlow 1.3 or later "
                     "(\'-O OpenFlow14\')");
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        request = ofpraw_alloc(ofp_version == OFP13_VERSION
                               ? OFPRAW_ONFT13_BUNDLE_CONTROL
                               : OFPRAW_OFPT14_BUNDLE_CONTROL, ofp_version, 0);
        m = ofpbuf_put_zeros(request, sizeof *m);

        m->bundle_id = htonl(bc->bundle_id);
        m->type = htons(bc->type);
        m->flags = htons(bc->flags);
        break;
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

static const char *
bundle_flags_to_name(uint32_t bit)
{
    switch (bit) {
    case OFPBF_ATOMIC:
        return "atomic";
    case OFPBF_ORDERED:
        return "ordered";
    default:
        return NULL;
    }
}

void
ofputil_format_bundle_ctrl_request(struct ds *s,
                                   const struct ofputil_bundle_ctrl_msg *bctrl)
{
    ds_put_char(s, '\n');
    ds_put_format(s, " bundle_id=%#"PRIx32" type=",  bctrl->bundle_id);
    switch (bctrl->type) {
    case OFPBCT_OPEN_REQUEST:
        ds_put_cstr(s, "OPEN_REQUEST");
        break;
    case OFPBCT_OPEN_REPLY:
        ds_put_cstr(s, "OPEN_REPLY");
        break;
    case OFPBCT_CLOSE_REQUEST:
        ds_put_cstr(s, "CLOSE_REQUEST");
        break;
    case OFPBCT_CLOSE_REPLY:
        ds_put_cstr(s, "CLOSE_REPLY");
        break;
    case OFPBCT_COMMIT_REQUEST:
        ds_put_cstr(s, "COMMIT_REQUEST");
        break;
    case OFPBCT_COMMIT_REPLY:
        ds_put_cstr(s, "COMMIT_REPLY");
        break;
    case OFPBCT_DISCARD_REQUEST:
        ds_put_cstr(s, "DISCARD_REQUEST");
        break;
    case OFPBCT_DISCARD_REPLY:
        ds_put_cstr(s, "DISCARD_REPLY");
        break;
    }

    ds_put_cstr(s, " flags=");
    ofp_print_bit_names(s, bctrl->flags, bundle_flags_to_name, ' ');
}


struct ofpbuf *
ofputil_encode_bundle_ctrl_reply(const struct ofp_header *oh,
                                 struct ofputil_bundle_ctrl_msg *msg)
{
    struct ofpbuf *buf;
    struct ofp14_bundle_ctrl_msg *m;

    buf = ofpraw_alloc_reply(oh->version == OFP13_VERSION
                             ? OFPRAW_ONFT13_BUNDLE_CONTROL
                             : OFPRAW_OFPT14_BUNDLE_CONTROL, oh, 0);
    m = ofpbuf_put_zeros(buf, sizeof *m);

    m->bundle_id = htonl(msg->bundle_id);
    m->type = htons(msg->type);
    m->flags = htons(msg->flags);

    return buf;
}

/* Return true for bundlable state change requests, false for other messages.
 */
static bool
ofputil_is_bundlable(enum ofptype type)
{
    switch (type) {
        /* Minimum required by OpenFlow 1.4. */
    case OFPTYPE_PORT_MOD:
    case OFPTYPE_FLOW_MOD:
        /* Other supported types. */
    case OFPTYPE_GROUP_MOD:
    case OFPTYPE_PACKET_OUT:
        return true;

        /* Nice to have later. */
    case OFPTYPE_FLOW_MOD_TABLE_ID:
    case OFPTYPE_TABLE_MOD:
    case OFPTYPE_METER_MOD:
    case OFPTYPE_NXT_TLV_TABLE_MOD:

        /* Not to be bundlable. */
    case OFPTYPE_ECHO_REQUEST:
    case OFPTYPE_FEATURES_REQUEST:
    case OFPTYPE_GET_CONFIG_REQUEST:
    case OFPTYPE_SET_CONFIG:
    case OFPTYPE_BARRIER_REQUEST:
    case OFPTYPE_ROLE_REQUEST:
    case OFPTYPE_ECHO_REPLY:
    case OFPTYPE_SET_FLOW_FORMAT:
    case OFPTYPE_SET_PACKET_IN_FORMAT:
    case OFPTYPE_SET_CONTROLLER_ID:
    case OFPTYPE_FLOW_AGE:
    case OFPTYPE_FLOW_MONITOR_CANCEL:
    case OFPTYPE_SET_ASYNC_CONFIG:
    case OFPTYPE_GET_ASYNC_REQUEST:
    case OFPTYPE_DESC_STATS_REQUEST:
    case OFPTYPE_FLOW_STATS_REQUEST:
    case OFPTYPE_AGGREGATE_STATS_REQUEST:
    case OFPTYPE_TABLE_STATS_REQUEST:
    case OFPTYPE_TABLE_FEATURES_STATS_REQUEST:
    case OFPTYPE_TABLE_DESC_REQUEST:
    case OFPTYPE_PORT_STATS_REQUEST:
    case OFPTYPE_QUEUE_STATS_REQUEST:
    case OFPTYPE_PORT_DESC_STATS_REQUEST:
    case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
    case OFPTYPE_METER_STATS_REQUEST:
    case OFPTYPE_METER_CONFIG_STATS_REQUEST:
    case OFPTYPE_METER_FEATURES_STATS_REQUEST:
    case OFPTYPE_GROUP_STATS_REQUEST:
    case OFPTYPE_GROUP_DESC_STATS_REQUEST:
    case OFPTYPE_GROUP_FEATURES_STATS_REQUEST:
    case OFPTYPE_QUEUE_GET_CONFIG_REQUEST:
    case OFPTYPE_BUNDLE_CONTROL:
    case OFPTYPE_BUNDLE_ADD_MESSAGE:
    case OFPTYPE_HELLO:
    case OFPTYPE_ERROR:
    case OFPTYPE_FEATURES_REPLY:
    case OFPTYPE_GET_CONFIG_REPLY:
    case OFPTYPE_PACKET_IN:
    case OFPTYPE_FLOW_REMOVED:
    case OFPTYPE_PORT_STATUS:
    case OFPTYPE_BARRIER_REPLY:
    case OFPTYPE_QUEUE_GET_CONFIG_REPLY:
    case OFPTYPE_DESC_STATS_REPLY:
    case OFPTYPE_FLOW_STATS_REPLY:
    case OFPTYPE_QUEUE_STATS_REPLY:
    case OFPTYPE_PORT_STATS_REPLY:
    case OFPTYPE_TABLE_STATS_REPLY:
    case OFPTYPE_AGGREGATE_STATS_REPLY:
    case OFPTYPE_PORT_DESC_STATS_REPLY:
    case OFPTYPE_ROLE_REPLY:
    case OFPTYPE_FLOW_MONITOR_PAUSED:
    case OFPTYPE_FLOW_MONITOR_RESUMED:
    case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
    case OFPTYPE_GET_ASYNC_REPLY:
    case OFPTYPE_GROUP_STATS_REPLY:
    case OFPTYPE_GROUP_DESC_STATS_REPLY:
    case OFPTYPE_GROUP_FEATURES_STATS_REPLY:
    case OFPTYPE_METER_STATS_REPLY:
    case OFPTYPE_METER_CONFIG_STATS_REPLY:
    case OFPTYPE_METER_FEATURES_STATS_REPLY:
    case OFPTYPE_TABLE_FEATURES_STATS_REPLY:
    case OFPTYPE_TABLE_DESC_REPLY:
    case OFPTYPE_ROLE_STATUS:
    case OFPTYPE_REQUESTFORWARD:
    case OFPTYPE_TABLE_STATUS:
    case OFPTYPE_NXT_TLV_TABLE_REQUEST:
    case OFPTYPE_NXT_TLV_TABLE_REPLY:
    case OFPTYPE_NXT_RESUME:
    case OFPTYPE_IPFIX_BRIDGE_STATS_REQUEST:
    case OFPTYPE_IPFIX_BRIDGE_STATS_REPLY:
    case OFPTYPE_IPFIX_FLOW_STATS_REQUEST:
    case OFPTYPE_IPFIX_FLOW_STATS_REPLY:
    case OFPTYPE_CT_FLUSH_ZONE:
        break;
    }

    return false;
}

enum ofperr
ofputil_decode_bundle_add(const struct ofp_header *oh,
                          struct ofputil_bundle_add_msg *msg,
                          enum ofptype *typep)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));

    /* Pull the outer ofp_header. */
    enum ofpraw raw = ofpraw_pull_assert(&b);
    ovs_assert(raw == OFPRAW_OFPT14_BUNDLE_ADD_MESSAGE
               || raw == OFPRAW_ONFT13_BUNDLE_ADD_MESSAGE);

    /* Pull the bundle_ctrl header. */
    const struct ofp14_bundle_ctrl_msg *m = ofpbuf_pull(&b, sizeof *m);
    msg->bundle_id = ntohl(m->bundle_id);
    msg->flags = ntohs(m->flags);

    /* Pull the inner ofp_header. */
    if (b.size < sizeof(struct ofp_header)) {
        return OFPERR_OFPBFC_MSG_BAD_LEN;
    }
    msg->msg = b.data;
    if (msg->msg->version != oh->version) {
        return OFPERR_OFPBFC_BAD_VERSION;
    }
    size_t inner_len = ntohs(msg->msg->length);
    if (inner_len < sizeof(struct ofp_header) || inner_len > b.size) {
        return OFPERR_OFPBFC_MSG_BAD_LEN;
    }
    if (msg->msg->xid != oh->xid) {
        return OFPERR_OFPBFC_MSG_BAD_XID;
    }

    /* Reject unbundlable messages. */
    enum ofptype type;
    enum ofperr error = ofptype_decode(&type, msg->msg);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "OFPT14_BUNDLE_ADD_MESSAGE contained "
                     "message is unparsable (%s)", ofperr_get_name(error));
        return OFPERR_OFPBFC_MSG_UNSUP; /* 'error' would be confusing. */
    }

    if (!ofputil_is_bundlable(type)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "%s message not allowed inside "
                     "OFPT14_BUNDLE_ADD_MESSAGE", ofptype_get_name(type));
        return OFPERR_OFPBFC_MSG_UNSUP;
    }
    if (typep) {
        *typep = type;
    }

    return 0;
}

struct ofpbuf *
ofputil_encode_bundle_add(enum ofp_version ofp_version,
                          struct ofputil_bundle_add_msg *msg)
{
    struct ofpbuf *request;
    struct ofp14_bundle_ctrl_msg *m;

    /* Must use the same xid as the embedded message. */
    request = ofpraw_alloc_xid(ofp_version == OFP13_VERSION
                               ? OFPRAW_ONFT13_BUNDLE_ADD_MESSAGE
                               : OFPRAW_OFPT14_BUNDLE_ADD_MESSAGE, ofp_version,
                               msg->msg->xid, ntohs(msg->msg->length));
    m = ofpbuf_put_zeros(request, sizeof *m);

    m->bundle_id = htonl(msg->bundle_id);
    m->flags = htons(msg->flags);
    ofpbuf_put(request, msg->msg, ntohs(msg->msg->length));

    ofpmsg_update_length(request);
    return request;
}

/* Opens file 'file_name' and reads each line as a flow_mod or a group_mod,
 * depending on the first keyword on each line.  Stores each flow and group
 * mods in '*bms', an array allocated on the caller's behalf, and the number of
 * messages in '*n_bms'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_bundle_file(const char *file_name,
                      const struct ofputil_port_map *port_map,
                      const struct ofputil_table_map *table_map,
                      struct ofputil_bundle_msg **bms, size_t *n_bms,
                      enum ofputil_protocol *usable_protocols)
{
    size_t allocated_bms;
    char *error = NULL;
    int line_number;
    FILE *stream;
    struct ds ds;

    *usable_protocols = OFPUTIL_P_ANY;

    *bms = NULL;
    *n_bms = 0;

    stream = !strcmp(file_name, "-") ? stdin : fopen(file_name, "r");
    if (stream == NULL) {
        return xasprintf("%s: open failed (%s)",
                         file_name, ovs_strerror(errno));
    }

    allocated_bms = *n_bms;
    ds_init(&ds);
    line_number = 0;
    while (!ds_get_preprocessed_line(&ds, stream, &line_number)) {
        enum ofputil_protocol usable;
        char *s = ds_cstr(&ds);
        size_t len;

        if (*n_bms >= allocated_bms) {
            struct ofputil_bundle_msg *new_bms;

            new_bms = x2nrealloc(*bms, &allocated_bms, sizeof **bms);
            for (size_t i = 0; i < *n_bms; i++) {
                if (new_bms[i].type == OFPTYPE_GROUP_MOD) {
                    ovs_list_moved(&new_bms[i].gm.buckets,
                                   &(*bms)[i].gm.buckets);
                }
            }
            *bms = new_bms;
        }

        s += strspn(s, " \t\r\n");   /* Skip white space. */
        len = strcspn(s, ", \t\r\n"); /* Get length of the first token. */

        if (!strncmp(s, "flow", len)) {
            s += len;
            error = parse_ofp_flow_mod_str(&(*bms)[*n_bms].fm, s, port_map,
                                           table_map, -2, &usable);
            if (error) {
                break;
            }
            (*bms)[*n_bms].type = OFPTYPE_FLOW_MOD;
        } else if (!strncmp(s, "group", len)) {
            s += len;
            error = parse_ofp_group_mod_str(&(*bms)[*n_bms].gm, -2, s,
                                            port_map, table_map, &usable);
            if (error) {
                break;
            }
            (*bms)[*n_bms].type = OFPTYPE_GROUP_MOD;
        } else if (!strncmp(s, "packet-out", len)) {
            s += len;
            error = parse_ofp_packet_out_str(&(*bms)[*n_bms].po, s, port_map,
                                             table_map, &usable);
            if (error) {
                break;
            }
            (*bms)[*n_bms].type = OFPTYPE_PACKET_OUT;
        } else {
            error = xasprintf("Unsupported bundle message type: %.*s",
                              (int)len, s);
            break;
        }

        *usable_protocols &= usable; /* Each line can narrow the set. */
        *n_bms += 1;
    }

    ds_destroy(&ds);
    if (stream != stdin) {
        fclose(stream);
    }

    if (error) {
        char *err_msg = xasprintf("%s:%d: %s", file_name, line_number, error);
        free(error);

        ofputil_free_bundle_msgs(*bms, *n_bms);
        *bms = NULL;
        *n_bms = 0;
        return err_msg;
    }
    return NULL;
}

void
ofputil_format_bundle_add(struct ds *s,
                          const struct ofputil_bundle_add_msg *badd,
                          const struct ofputil_port_map *port_map,
                          const struct ofputil_table_map *table_map,
                          int verbosity)
{
    ds_put_char(s, '\n');
    ds_put_format(s, " bundle_id=%#"PRIx32, badd->bundle_id);
    ds_put_cstr(s, " flags=");
    ofp_print_bit_names(s, badd->flags, bundle_flags_to_name, ' ');

    ds_put_char(s, '\n');
    char *msg = ofp_to_string(badd->msg, ntohs(badd->msg->length), port_map,
                              table_map, verbosity);
    ds_put_and_free_cstr(s, msg);
}
