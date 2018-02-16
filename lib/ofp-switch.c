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
#include "openvswitch/ofp-switch.h"
#include "byte-order.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/ofp-print.h"
#include "util.h"

/* ofputil_switch_features */

#define OFPC_COMMON (OFPC_FLOW_STATS | OFPC_TABLE_STATS | OFPC_PORT_STATS | \
                     OFPC_IP_REASM | OFPC_QUEUE_STATS)
BUILD_ASSERT_DECL((int) OFPUTIL_C_FLOW_STATS == OFPC_FLOW_STATS);
BUILD_ASSERT_DECL((int) OFPUTIL_C_TABLE_STATS == OFPC_TABLE_STATS);
BUILD_ASSERT_DECL((int) OFPUTIL_C_PORT_STATS == OFPC_PORT_STATS);
BUILD_ASSERT_DECL((int) OFPUTIL_C_IP_REASM == OFPC_IP_REASM);
BUILD_ASSERT_DECL((int) OFPUTIL_C_QUEUE_STATS == OFPC_QUEUE_STATS);
BUILD_ASSERT_DECL((int) OFPUTIL_C_ARP_MATCH_IP == OFPC_ARP_MATCH_IP);
BUILD_ASSERT_DECL((int) OFPUTIL_C_PORT_BLOCKED == OFPC12_PORT_BLOCKED);
BUILD_ASSERT_DECL((int) OFPUTIL_C_BUNDLES == OFPC14_BUNDLES);
BUILD_ASSERT_DECL((int) OFPUTIL_C_FLOW_MONITORING == OFPC14_FLOW_MONITORING);

static uint32_t
ofputil_capabilities_mask(enum ofp_version ofp_version)
{
    /* Handle capabilities whose bit is unique for all OpenFlow versions */
    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
        return OFPC_COMMON | OFPC_ARP_MATCH_IP;
    case OFP12_VERSION:
    case OFP13_VERSION:
        return OFPC_COMMON | OFPC12_PORT_BLOCKED;
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        return OFPC_COMMON | OFPC12_PORT_BLOCKED | OFPC14_BUNDLES
            | OFPC14_FLOW_MONITORING;
    default:
        /* Caller needs to check osf->header.version itself */
        return 0;
    }
}

/* Pulls an OpenFlow "switch_features" structure from 'b' and decodes it into
 * an abstract representation in '*features', readying 'b' to iterate over the
 * OpenFlow port structures following 'osf' with later calls to
 * ofputil_pull_phy_port().  Returns 0 if successful, otherwise an OFPERR_*
 * value.  */
enum ofperr
ofputil_pull_switch_features(struct ofpbuf *b,
                             struct ofputil_switch_features *features)
{
    const struct ofp_header *oh = b->data;
    enum ofpraw raw = ofpraw_pull_assert(b);
    const struct ofp_switch_features *osf = ofpbuf_pull(b, sizeof *osf);
    features->datapath_id = ntohll(osf->datapath_id);
    features->n_buffers = ntohl(osf->n_buffers);
    features->n_tables = osf->n_tables;
    features->auxiliary_id = 0;

    features->capabilities = ntohl(osf->capabilities) &
        ofputil_capabilities_mask(oh->version);

    if (raw == OFPRAW_OFPT10_FEATURES_REPLY) {
        if (osf->capabilities & htonl(OFPC10_STP)) {
            features->capabilities |= OFPUTIL_C_STP;
        }
        features->ofpacts = ofpact_bitmap_from_openflow(osf->actions,
                                                        OFP10_VERSION);
    } else if (raw == OFPRAW_OFPT11_FEATURES_REPLY
               || raw == OFPRAW_OFPT13_FEATURES_REPLY) {
        if (osf->capabilities & htonl(OFPC11_GROUP_STATS)) {
            features->capabilities |= OFPUTIL_C_GROUP_STATS;
        }
        features->ofpacts = 0;
        if (raw == OFPRAW_OFPT13_FEATURES_REPLY) {
            features->auxiliary_id = osf->auxiliary_id;
        }
    } else {
        return OFPERR_OFPBRC_BAD_VERSION;
    }

    return 0;
}

/* In OpenFlow 1.0, 1.1, and 1.2, an OFPT_FEATURES_REPLY message lists all the
 * switch's ports, unless there are too many to fit.  In OpenFlow 1.3 and
 * later, an OFPT_FEATURES_REPLY does not list ports at all.
 *
 * Given a buffer 'b' that contains a Features Reply message, this message
 * checks if it contains a complete list of the switch's ports.  Returns true,
 * if so.  Returns false if the list is missing (OF1.3+) or incomplete
 * (OF1.0/1.1/1.2), and in the latter case removes all of the ports from the
 * message.
 *
 * When this function returns false, the caller should send an OFPST_PORT_DESC
 * stats request to get the ports. */
bool
ofputil_switch_features_has_ports(struct ofpbuf *b)
{
    struct ofp_header *oh = b->data;
    size_t phy_port_size;

    if (oh->version >= OFP13_VERSION) {
        /* OpenFlow 1.3+ never has ports in the feature reply. */
        return false;
    }

    phy_port_size = (oh->version == OFP10_VERSION
                     ? sizeof(struct ofp10_phy_port)
                     : sizeof(struct ofp11_port));
    if (ntohs(oh->length) + phy_port_size <= UINT16_MAX) {
        /* There's room for additional ports in the feature reply.
         * Assume that the list is complete. */
        return true;
    }

    /* The feature reply has no room for more ports.  Probably the list is
     * truncated.  Drop the ports and tell the caller to retrieve them with
     * OFPST_PORT_DESC. */
    b->size = sizeof *oh + sizeof(struct ofp_switch_features);
    ofpmsg_update_length(b);
    return false;
}

/* Returns a buffer owned by the caller that encodes 'features' in the format
 * required by 'protocol' with the given 'xid'.  The caller should append port
 * information to the buffer with subsequent calls to
 * ofputil_put_switch_features_port(). */
struct ofpbuf *
ofputil_encode_switch_features(const struct ofputil_switch_features *features,
                               enum ofputil_protocol protocol, ovs_be32 xid)
{
    struct ofp_switch_features *osf;
    struct ofpbuf *b;
    enum ofp_version version;
    enum ofpraw raw;

    version = ofputil_protocol_to_ofp_version(protocol);
    switch (version) {
    case OFP10_VERSION:
        raw = OFPRAW_OFPT10_FEATURES_REPLY;
        break;
    case OFP11_VERSION:
    case OFP12_VERSION:
        raw = OFPRAW_OFPT11_FEATURES_REPLY;
        break;
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        raw = OFPRAW_OFPT13_FEATURES_REPLY;
        break;
    default:
        OVS_NOT_REACHED();
    }
    b = ofpraw_alloc_xid(raw, version, xid, 0);
    osf = ofpbuf_put_zeros(b, sizeof *osf);
    osf->datapath_id = htonll(features->datapath_id);
    osf->n_buffers = htonl(features->n_buffers);
    osf->n_tables = features->n_tables;

    osf->capabilities = htonl(features->capabilities &
                              ofputil_capabilities_mask(version));
    switch (version) {
    case OFP10_VERSION:
        if (features->capabilities & OFPUTIL_C_STP) {
            osf->capabilities |= htonl(OFPC10_STP);
        }
        osf->actions = ofpact_bitmap_to_openflow(features->ofpacts,
                                                 OFP10_VERSION);
        break;
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        osf->auxiliary_id = features->auxiliary_id;
        /* fall through */
    case OFP11_VERSION:
    case OFP12_VERSION:
        if (features->capabilities & OFPUTIL_C_GROUP_STATS) {
            osf->capabilities |= htonl(OFPC11_GROUP_STATS);
        }
        break;
    default:
        OVS_NOT_REACHED();
    }

    return b;
}

/* Encodes 'pp' into the format required by the switch_features message already
 * in 'b', which should have been returned by ofputil_encode_switch_features(),
 * and appends the encoded version to 'b'. */
void
ofputil_put_switch_features_port(const struct ofputil_phy_port *pp,
                                 struct ofpbuf *b)
{
    const struct ofp_header *oh = b->data;

    if (oh->version < OFP13_VERSION) {
        /* Try adding a port description to the message, but drop it again if
         * the buffer overflows.  (This possibility for overflow is why
         * OpenFlow 1.3+ moved port descriptions into a multipart message.)  */
        size_t start_ofs = b->size;
        ofputil_put_phy_port(oh->version, pp, b);
        if (b->size > UINT16_MAX) {
            b->size = start_ofs;
        }
    }
}

static const char *
ofputil_capabilities_to_name(uint32_t bit)
{
    enum ofputil_capabilities capabilities = bit;

    switch (capabilities) {
    case OFPUTIL_C_FLOW_STATS:   return "FLOW_STATS";
    case OFPUTIL_C_TABLE_STATS:  return "TABLE_STATS";
    case OFPUTIL_C_PORT_STATS:   return "PORT_STATS";
    case OFPUTIL_C_IP_REASM:     return "IP_REASM";
    case OFPUTIL_C_QUEUE_STATS:  return "QUEUE_STATS";
    case OFPUTIL_C_ARP_MATCH_IP: return "ARP_MATCH_IP";
    case OFPUTIL_C_STP:          return "STP";
    case OFPUTIL_C_GROUP_STATS:  return "GROUP_STATS";
    case OFPUTIL_C_PORT_BLOCKED: return "PORT_BLOCKED";
    case OFPUTIL_C_BUNDLES:      return "BUNDLES";
    case OFPUTIL_C_FLOW_MONITORING: return "FLOW_MONITORING";
    }

    return NULL;
}

void
ofputil_switch_features_format(struct ds *s,
                               const struct ofputil_switch_features *features)
{
    ds_put_format(s, " dpid:%016"PRIx64"\n", features->datapath_id);

    ds_put_format(s, "n_tables:%"PRIu8", n_buffers:%"PRIu32,
                  features->n_tables, features->n_buffers);
    if (features->auxiliary_id) {
        ds_put_format(s, ", auxiliary_id:%"PRIu8, features->auxiliary_id);
    }
    ds_put_char(s, '\n');

    ds_put_cstr(s, "capabilities: ");
    ofp_print_bit_names(s, features->capabilities,
                        ofputil_capabilities_to_name, ' ');
    ds_put_char(s, '\n');

    if (features->ofpacts) {
        ds_put_cstr(s, "actions: ");
        ofpact_bitmap_format(features->ofpacts, s);
        ds_put_char(s, '\n');
    }
}

const char *
ofputil_frag_handling_to_string(enum ofputil_frag_handling frag)
{
    switch (frag) {
    case OFPUTIL_FRAG_NORMAL:   return "normal";
    case OFPUTIL_FRAG_DROP:     return "drop";
    case OFPUTIL_FRAG_REASM:    return "reassemble";
    case OFPUTIL_FRAG_NX_MATCH: return "nx-match";
    }

    OVS_NOT_REACHED();
}

bool
ofputil_frag_handling_from_string(const char *s,
                                  enum ofputil_frag_handling *frag)
{
    if (!strcasecmp(s, "normal")) {
        *frag = OFPUTIL_FRAG_NORMAL;
    } else if (!strcasecmp(s, "drop")) {
        *frag = OFPUTIL_FRAG_DROP;
    } else if (!strcasecmp(s, "reassemble")) {
        *frag = OFPUTIL_FRAG_REASM;
    } else if (!strcasecmp(s, "nx-match")) {
        *frag = OFPUTIL_FRAG_NX_MATCH;
    } else {
        return false;
    }
    return true;
}

/* ofputil_switch_config */

/* Decodes 'oh', which must be an OFPT_GET_CONFIG_REPLY or OFPT_SET_CONFIG
 * message, into 'config'.  Returns false if 'oh' contained any flags that
 * aren't specified in its version of OpenFlow, true otherwise. */
static bool
ofputil_decode_switch_config(const struct ofp_header *oh,
                             struct ofputil_switch_config *config)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    const struct ofp_switch_config *osc = ofpbuf_pull(&b, sizeof *osc);
    config->frag = ntohs(osc->flags) & OFPC_FRAG_MASK;
    config->miss_send_len = ntohs(osc->miss_send_len);

    ovs_be16 valid_mask = htons(OFPC_FRAG_MASK);
    if (oh->version < OFP13_VERSION) {
        const ovs_be16 ttl_bit = htons(OFPC_INVALID_TTL_TO_CONTROLLER);
        valid_mask |= ttl_bit;
        config->invalid_ttl_to_controller = (osc->flags & ttl_bit) != 0;
    } else {
        config->invalid_ttl_to_controller = -1;
    }

    return !(osc->flags & ~valid_mask);
}

void
ofputil_decode_get_config_reply(const struct ofp_header *oh,
                                struct ofputil_switch_config *config)
{
    ofputil_decode_switch_config(oh, config);
}

enum ofperr
ofputil_decode_set_config(const struct ofp_header *oh,
                          struct ofputil_switch_config *config)
{
    return (ofputil_decode_switch_config(oh, config)
            ? 0
            : OFPERR_OFPSCFC_BAD_FLAGS);
}

static struct ofpbuf *
ofputil_put_switch_config(const struct ofputil_switch_config *config,
                          struct ofpbuf *b)
{
    const struct ofp_header *oh = b->data;
    struct ofp_switch_config *osc = ofpbuf_put_zeros(b, sizeof *osc);
    osc->flags = htons(config->frag);
    if (config->invalid_ttl_to_controller > 0 && oh->version < OFP13_VERSION) {
        osc->flags |= htons(OFPC_INVALID_TTL_TO_CONTROLLER);
    }
    osc->miss_send_len = htons(config->miss_send_len);
    return b;
}

struct ofpbuf *
ofputil_encode_get_config_reply(const struct ofp_header *request,
                                const struct ofputil_switch_config *config)
{
    struct ofpbuf *b = ofpraw_alloc_reply(OFPRAW_OFPT_GET_CONFIG_REPLY,
                                          request, 0);
    return ofputil_put_switch_config(config, b);
}

struct ofpbuf *
ofputil_encode_set_config(const struct ofputil_switch_config *config,
                          enum ofp_version version)
{
    struct ofpbuf *b = ofpraw_alloc(OFPRAW_OFPT_SET_CONFIG, version, 0);
    return ofputil_put_switch_config(config, b);
}

void
ofputil_switch_config_format(struct ds *s,
                             const struct ofputil_switch_config *config)
{
    ds_put_format(s, " frags=%s",
                  ofputil_frag_handling_to_string(config->frag));

    if (config->invalid_ttl_to_controller > 0) {
        ds_put_format(s, " invalid_ttl_to_controller");
    }

    ds_put_format(s, " miss_send_len=%"PRIu16"\n", config->miss_send_len);
}
