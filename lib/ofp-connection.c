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
#include "openvswitch/ofp-connection.h"
#include "byte-order.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-monitor.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofp-table.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/type-props.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofp_connection);

/* ofputil_role_request */

/* Decodes the OpenFlow "role request" or "role reply" message in '*oh' into
 * an abstract form in '*rr'.  Returns 0 if successful, otherwise an
 * OFPERR_* value. */
enum ofperr
ofputil_decode_role_message(const struct ofp_header *oh,
                            struct ofputil_role_request *rr)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT12_ROLE_REQUEST ||
        raw == OFPRAW_OFPT12_ROLE_REPLY) {
        const struct ofp12_role_request *orr = b.msg;

        if (orr->role != htonl(OFPCR12_ROLE_NOCHANGE) &&
            orr->role != htonl(OFPCR12_ROLE_EQUAL) &&
            orr->role != htonl(OFPCR12_ROLE_PRIMARY) &&
            orr->role != htonl(OFPCR12_ROLE_SECONDARY)) {
            return OFPERR_OFPRRFC_BAD_ROLE;
        }

        rr->role = ntohl(orr->role);
        if (raw == OFPRAW_OFPT12_ROLE_REQUEST
            ? orr->role == htonl(OFPCR12_ROLE_NOCHANGE)
            : orr->generation_id == OVS_BE64_MAX) {
            rr->have_generation_id = false;
            rr->generation_id = 0;
        } else {
            rr->have_generation_id = true;
            rr->generation_id = ntohll(orr->generation_id);
        }
    } else if (raw == OFPRAW_NXT_ROLE_REQUEST ||
               raw == OFPRAW_NXT_ROLE_REPLY) {
        const struct nx_role_request *nrr = b.msg;

        BUILD_ASSERT(NX_ROLE_OTHER + 1 == OFPCR12_ROLE_EQUAL);
        BUILD_ASSERT(NX_ROLE_PRIMARY + 1 == OFPCR12_ROLE_PRIMARY);
        BUILD_ASSERT(NX_ROLE_SECONDARY + 1 == OFPCR12_ROLE_SECONDARY);

        if (nrr->role != htonl(NX_ROLE_OTHER) &&
            nrr->role != htonl(NX_ROLE_PRIMARY) &&
            nrr->role != htonl(NX_ROLE_SECONDARY)) {
            return OFPERR_OFPRRFC_BAD_ROLE;
        }

        rr->role = ntohl(nrr->role) + 1;
        rr->have_generation_id = false;
        rr->generation_id = 0;
    } else {
        OVS_NOT_REACHED();
    }

    return 0;
}

static void
format_role_generic(struct ds *string, enum ofp12_controller_role role,
                    uint64_t generation_id)
{
    ds_put_cstr(string, " role=");

    switch (role) {
    case OFPCR12_ROLE_NOCHANGE:
        ds_put_cstr(string, "nochange");
        break;
    case OFPCR12_ROLE_EQUAL:
        ds_put_cstr(string, "equal"); /* OF 1.2 wording */
        break;
    case OFPCR12_ROLE_PRIMARY:
        ds_put_cstr(string, "primary");
        break;
    case OFPCR12_ROLE_SECONDARY:
        ds_put_cstr(string, "secondary");
        break;
    default:
        OVS_NOT_REACHED();
    }

    if (generation_id != UINT64_MAX) {
        ds_put_format(string, " generation_id=%"PRIu64, generation_id);
    }
}

void
ofputil_format_role_message(struct ds *string,
                            const struct ofputil_role_request *rr)
{
    format_role_generic(string, rr->role, (rr->have_generation_id
                                           ? rr->generation_id
                                           : UINT64_MAX));
}

/* Returns an encoded form of a role reply suitable for the "request" in a
 * buffer owned by the caller. */
struct ofpbuf *
ofputil_encode_role_reply(const struct ofp_header *request,
                          const struct ofputil_role_request *rr)
{
    struct ofpbuf *buf;
    enum ofpraw raw;

    raw = ofpraw_decode_assert(request);
    if (raw == OFPRAW_OFPT12_ROLE_REQUEST) {
        struct ofp12_role_request *orr;

        buf = ofpraw_alloc_reply(OFPRAW_OFPT12_ROLE_REPLY, request, 0);
        orr = ofpbuf_put_zeros(buf, sizeof *orr);

        orr->role = htonl(rr->role);
        orr->generation_id = htonll(rr->have_generation_id
                                    ? rr->generation_id
                                    : UINT64_MAX);
    } else if (raw == OFPRAW_NXT_ROLE_REQUEST) {
        struct nx_role_request *nrr;

        BUILD_ASSERT(NX_ROLE_OTHER == OFPCR12_ROLE_EQUAL - 1);
        BUILD_ASSERT(NX_ROLE_PRIMARY == OFPCR12_ROLE_PRIMARY - 1);
        BUILD_ASSERT(NX_ROLE_SECONDARY == OFPCR12_ROLE_SECONDARY - 1);

        buf = ofpraw_alloc_reply(OFPRAW_NXT_ROLE_REPLY, request, 0);
        nrr = ofpbuf_put_zeros(buf, sizeof *nrr);
        nrr->role = htonl(rr->role - 1);
    } else {
        OVS_NOT_REACHED();
    }

    return buf;
}

/* Encodes "role status" message 'status' for sending in the given
 * 'protocol'.  Returns the role status message, if 'protocol' supports them,
 * otherwise a null pointer. */
struct ofpbuf *
ofputil_encode_role_status(const struct ofputil_role_status *status,
                           enum ofputil_protocol protocol)
{
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);
    if (version < OFP13_VERSION) {
        return NULL;
    }

    enum ofpraw raw = (version >= OFP14_VERSION
                       ? OFPRAW_OFPT14_ROLE_STATUS
                       : OFPRAW_ONFT13_ROLE_STATUS);
    struct ofpbuf *buf = ofpraw_alloc_xid(raw, version, htonl(0), 0);
    struct ofp14_role_status *rstatus = ofpbuf_put_zeros(buf, sizeof *rstatus);
    rstatus->role = htonl(status->role);
    rstatus->reason = status->reason;
    rstatus->generation_id = htonll(status->generation_id);

    return buf;
}

enum ofperr
ofputil_decode_role_status(const struct ofp_header *oh,
                           struct ofputil_role_status *rs)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    ovs_assert(raw == OFPRAW_OFPT14_ROLE_STATUS ||
               raw == OFPRAW_ONFT13_ROLE_STATUS);

    const struct ofp14_role_status *r = b.msg;
    if (r->role != htonl(OFPCR12_ROLE_NOCHANGE) &&
        r->role != htonl(OFPCR12_ROLE_EQUAL) &&
        r->role != htonl(OFPCR12_ROLE_PRIMARY) &&
        r->role != htonl(OFPCR12_ROLE_SECONDARY)) {
        return OFPERR_OFPRRFC_BAD_ROLE;
    }

    rs->role = ntohl(r->role);
    rs->generation_id = ntohll(r->generation_id);
    rs->reason = r->reason;

    return 0;
}

void
ofputil_format_role_status(struct ds *string,
                           const struct ofputil_role_status *rs)
{
    format_role_generic(string, rs->role, rs->generation_id);

    ds_put_cstr(string, " reason=");

    switch (rs->reason) {
    case OFPCRR_PRIMARY_REQUEST:
        ds_put_cstr(string, "primary_request");
        break;
    case OFPCRR_CONFIG:
        ds_put_cstr(string, "configuration_changed");
        break;
    case OFPCRR_EXPERIMENTER:
        ds_put_cstr(string, "experimenter_data_changed");
        break;
    case OFPCRR_N_REASONS:
    default:
        ds_put_cstr(string, "(unknown)");
        break;
    }
}

const char *
ofputil_async_msg_type_to_string(enum ofputil_async_msg_type type)
{
    switch (type) {
    case OAM_PACKET_IN:      return "PACKET_IN";
    case OAM_PORT_STATUS:    return "PORT_STATUS";
    case OAM_FLOW_REMOVED:   return "FLOW_REMOVED";
    case OAM_ROLE_STATUS:    return "ROLE_STATUS";
    case OAM_TABLE_STATUS:   return "TABLE_STATUS";
    case OAM_REQUESTFORWARD: return "REQUESTFORWARD";

    case OAM_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

struct ofp14_async_prop {
    uint64_t prop_type;
    enum ofputil_async_msg_type oam;
    bool primary;
    uint32_t allowed10, allowed14;
};

#define AP_PAIR(SECONDARY_PROP_TYPE, OAM, A10, A14) \
    { SECONDARY_PROP_TYPE,       OAM, false, A10, (A14) ? (A14) : (A10) },  \
    { (SECONDARY_PROP_TYPE + 1), OAM, true,  A10, (A14) ? (A14) : (A10) }

static const struct ofp14_async_prop async_props[] = {
    AP_PAIR( 0, OAM_PACKET_IN,      OFPR10_BITS, OFPR14_BITS),
    AP_PAIR( 2, OAM_PORT_STATUS,    (1 << OFPPR_N_REASONS) - 1, 0),
    AP_PAIR( 4, OAM_FLOW_REMOVED,   (1 << OVS_OFPRR_NONE) - 1, 0),
    AP_PAIR( 6, OAM_ROLE_STATUS,    (1 << OFPCRR_N_REASONS) - 1, 0),
    AP_PAIR( 8, OAM_TABLE_STATUS,   OFPTR_BITS, 0),
    AP_PAIR(10, OAM_REQUESTFORWARD, (1 << OFPRFR_N_REASONS) - 1, 0),
};

#define FOR_EACH_ASYNC_PROP(VAR)                                \
    for (const struct ofp14_async_prop *VAR = async_props;      \
         VAR < &async_props[ARRAY_SIZE(async_props)]; VAR++)

static const struct ofp14_async_prop *
get_ofp14_async_config_prop_by_prop_type(uint64_t prop_type)
{
    FOR_EACH_ASYNC_PROP (ap) {
        if (prop_type == ap->prop_type) {
            return ap;
        }
    }
    return NULL;
}

static const struct ofp14_async_prop *
get_ofp14_async_config_prop_by_oam(enum ofputil_async_msg_type oam,
                                   bool primary)
{
    FOR_EACH_ASYNC_PROP (ap) {
        if (ap->oam == oam && ap->primary == primary) {
            return ap;
        }
    }
    return NULL;
}

static uint32_t
ofp14_async_prop_allowed(const struct ofp14_async_prop *prop,
                         enum ofp_version version)
{
    return version >= OFP14_VERSION ? prop->allowed14 : prop->allowed10;
}

static ovs_be32
encode_async_mask(const struct ofputil_async_cfg *src,
                  const struct ofp14_async_prop *ap,
                  enum ofp_version version)
{
    uint32_t mask = (ap->primary
                     ? src->primary[ap->oam]
                     : src->secondary[ap->oam]);
    return htonl(mask & ofp14_async_prop_allowed(ap, version));
}

static enum ofperr
decode_async_mask(ovs_be32 src,
                  const struct ofp14_async_prop *ap, enum ofp_version version,
                  bool loose, struct ofputil_async_cfg *dst)
{
    uint32_t mask = ntohl(src);
    uint32_t allowed = ofp14_async_prop_allowed(ap, version);
    if (mask & ~allowed) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        OFPPROP_LOG(&rl, loose,
                    "bad value %#x for %s (allowed mask %#x)",
                    mask, ofputil_async_msg_type_to_string(ap->oam),
                    allowed);
        mask &= allowed;
        if (!loose) {
            return OFPERR_OFPACFC_INVALID;
        }
    }

    if (ap->oam == OAM_PACKET_IN) {
        if (mask & (1u << OFPR_NO_MATCH)) {
            mask |= 1u << OFPR_EXPLICIT_MISS;
            if (version < OFP13_VERSION) {
                mask |= 1u << OFPR_IMPLICIT_MISS;
            }
        }
    }

    uint32_t *array = ap->primary ? dst->primary : dst->secondary;
    array[ap->oam] = mask;
    return 0;
}

static enum ofperr
parse_async_tlv(const struct ofpbuf *property,
                const struct ofp14_async_prop *ap,
                struct ofputil_async_cfg *ac,
                enum ofp_version version, bool loose)
{
    enum ofperr error;
    ovs_be32 mask;

    error  = ofpprop_parse_be32(property, &mask);
    if (error) {
        return error;
    }

    if (ofpprop_is_experimenter(ap->prop_type)) {
        /* For experimenter properties, whether a property is for the primary or
         * secondary role is indicated by both 'type' and 'exp_type' in struct
         * ofp_prop_experimenter.  Check that these are consistent. */
        const struct ofp_prop_experimenter *ope = property->data;
        bool should_be_primary = ope->type == htons(0xffff);
        if (should_be_primary != ap->primary) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "async property type %#"PRIx16" "
                         "indicates %s role but exp_type %"PRIu32" indicates "
                         "%s role",
                         ntohs(ope->type),
                         should_be_primary ? "primary" : "secondary",
                         ntohl(ope->exp_type),
                         ap->primary ? "primary" : "secondary");
            return OFPERR_OFPBPC_BAD_EXP_TYPE;
        }
    }

    return decode_async_mask(mask, ap, version, loose, ac);
}

static void
decode_legacy_async_masks(const ovs_be32 masks[2],
                          enum ofputil_async_msg_type oam,
                          enum ofp_version version,
                          struct ofputil_async_cfg *dst)
{
    for (int i = 0; i < 2; i++) {
        bool primary = i == 0;
        const struct ofp14_async_prop *ap
            = get_ofp14_async_config_prop_by_oam(oam, primary);
        decode_async_mask(masks[i], ap, version, true, dst);
    }
}

/* Decodes the OpenFlow "set async config" request and "get async config
 * reply" message in '*oh' into an abstract form in 'ac'.
 *
 * Some versions of the "set async config" request change only some of the
 * settings and leave the others alone.  This function uses 'basis' as the
 * initial state for decoding these.  Other versions of the request change all
 * the settings; this function ignores 'basis' when decoding these.
 *
 * If 'loose' is true, this function ignores properties and values that it does
 * not understand, as a controller would want to do when interpreting
 * capabilities provided by a switch.  If 'loose' is false, this function
 * treats unknown properties and values as an error, as a switch would want to
 * do when interpreting a configuration request made by a controller.
 *
 * Returns 0 if successful, otherwise an OFPERR_* value.
 *
 * Returns error code OFPERR_OFPACFC_INVALID if the value of mask is not in
 * the valid range of mask.
 *
 * Returns error code OFPERR_OFPACFC_UNSUPPORTED if the configuration is not
 * supported.*/
enum ofperr
ofputil_decode_set_async_config(const struct ofp_header *oh, bool loose,
                                const struct ofputil_async_cfg *basis,
                                struct ofputil_async_cfg *ac)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);

    if (raw == OFPRAW_OFPT13_SET_ASYNC ||
        raw == OFPRAW_NXT_SET_ASYNC_CONFIG ||
        raw == OFPRAW_OFPT13_GET_ASYNC_REPLY) {
        const struct nx_async_config *msg = ofpmsg_body(oh);

        *ac = OFPUTIL_ASYNC_CFG_INIT;
        decode_legacy_async_masks(msg->packet_in_mask, OAM_PACKET_IN,
                                  oh->version, ac);
        decode_legacy_async_masks(msg->port_status_mask, OAM_PORT_STATUS,
                                  oh->version, ac);
        decode_legacy_async_masks(msg->flow_removed_mask, OAM_FLOW_REMOVED,
                                  oh->version, ac);
    } else if (raw == OFPRAW_OFPT14_SET_ASYNC ||
               raw == OFPRAW_OFPT14_GET_ASYNC_REPLY ||
               raw == OFPRAW_NXT_SET_ASYNC_CONFIG2) {
        *ac = *basis;
        while (b.size > 0) {
            struct ofpbuf property;
            enum ofperr error;
            uint64_t type;

            error = ofpprop_pull__(&b, &property, 8, 0xfffe, &type);
            if (error) {
                return error;
            }

            const struct ofp14_async_prop *ap
                = get_ofp14_async_config_prop_by_prop_type(type);
            error = (ap
                     ? parse_async_tlv(&property, ap, ac, oh->version, loose)
                     : OFPPROP_UNKNOWN(loose, "async config", type));
            if (error) {
                /* Most messages use OFPBPC_BAD_TYPE but async has its own (who
                 * knows why, it's OpenFlow. */
                if (error == OFPERR_OFPBPC_BAD_TYPE) {
                    error = OFPERR_OFPACFC_UNSUPPORTED;
                }
                return error;
            }
        }
    } else {
        return OFPERR_OFPBRC_BAD_VERSION;
    }
    return 0;
}

static void
encode_legacy_async_masks(const struct ofputil_async_cfg *ac,
                          enum ofputil_async_msg_type oam,
                          enum ofp_version version,
                          ovs_be32 masks[2])
{
    for (int i = 0; i < 2; i++) {
        bool primary = i == 0;
        const struct ofp14_async_prop *ap
            = get_ofp14_async_config_prop_by_oam(oam, primary);
        masks[i] = encode_async_mask(ac, ap, version);
    }
}

static void
ofputil_put_async_config__(const struct ofputil_async_cfg *ac,
                           struct ofpbuf *buf, bool tlv,
                           enum ofp_version version, uint32_t oams)
{
    if (!tlv) {
        struct nx_async_config *msg = ofpbuf_put_zeros(buf, sizeof *msg);
        encode_legacy_async_masks(ac, OAM_PACKET_IN, version,
                                  msg->packet_in_mask);
        encode_legacy_async_masks(ac, OAM_PORT_STATUS, version,
                                  msg->port_status_mask);
        encode_legacy_async_masks(ac, OAM_FLOW_REMOVED, version,
                                  msg->flow_removed_mask);
    } else {
        FOR_EACH_ASYNC_PROP (ap) {
            if (oams & (1u << ap->oam)) {
                size_t ofs = buf->size;
                ofpprop_put_be32(buf, ap->prop_type,
                                 encode_async_mask(ac, ap, version));

                /* For experimenter properties, we need to use type 0xfffe for
                 * primary and 0xffff for secondaries. */
                if (ofpprop_is_experimenter(ap->prop_type)) {
                    struct ofp_prop_experimenter *ope
                        = ofpbuf_at_assert(buf, ofs, sizeof *ope);
                    ope->type = ap->primary ? htons(0xffff) : htons(0xfffe);
                }
            }
        }
    }
}

/* Encodes and returns a reply to the OFPT_GET_ASYNC_REQUEST in 'oh' that
 * states that the asynchronous message configuration is 'ac'. */
struct ofpbuf *
ofputil_encode_get_async_reply(const struct ofp_header *oh,
                               const struct ofputil_async_cfg *ac)
{
    enum ofpraw raw = (oh->version < OFP14_VERSION
                       ? OFPRAW_OFPT13_GET_ASYNC_REPLY
                       : OFPRAW_OFPT14_GET_ASYNC_REPLY);
    struct ofpbuf *reply = ofpraw_alloc_reply(raw, oh, 0);
    ofputil_put_async_config__(ac, reply,
                               raw == OFPRAW_OFPT14_GET_ASYNC_REPLY,
                               oh->version, UINT32_MAX);
    return reply;
}

/* Encodes and returns a message, in a format appropriate for OpenFlow version
 * 'ofp_version', that sets the asynchronous message configuration to 'ac'.
 *
 * Specify 'oams' as a bitmap of OAM_* that indicate the asynchronous messages
 * to configure.  OF1.0 through OF1.3 can't natively configure a subset of
 * messages, so more messages than requested may be configured.  OF1.0 through
 * OF1.3 also can't configure OVS extension OAM_* values, so if 'oam' includes
 * any extensions then this function encodes an Open vSwitch extension message
 * that does support configuring OVS extension OAM_*. */
struct ofpbuf *
ofputil_encode_set_async_config(const struct ofputil_async_cfg *ac,
                                uint32_t oams, enum ofp_version ofp_version)
{
    enum ofpraw raw = (ofp_version >= OFP14_VERSION ? OFPRAW_OFPT14_SET_ASYNC
                       : oams & OAM_EXTENSIONS ? OFPRAW_NXT_SET_ASYNC_CONFIG2
                       : ofp_version >= OFP13_VERSION ? OFPRAW_OFPT13_SET_ASYNC
                       : OFPRAW_NXT_SET_ASYNC_CONFIG);
    struct ofpbuf *request = ofpraw_alloc(raw, ofp_version, 0);
    ofputil_put_async_config__(ac, request,
                               (raw == OFPRAW_OFPT14_SET_ASYNC ||
                                raw == OFPRAW_NXT_SET_ASYNC_CONFIG2),
                               ofp_version, oams);
    return request;
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFP_PORT_REASON_BUFSIZE. */
#define OFP_PORT_REASON_BUFSIZE (INT_STRLEN(int) + 1)
static const char *
ofp_port_reason_to_string(enum ofp_port_reason reason,
                          char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPPR_ADD:
        return "add";

    case OFPPR_DELETE:
        return "delete";

    case OFPPR_MODIFY:
        return "modify";

    case OFPPR_N_REASONS:
    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFP_ASYNC_CONFIG_REASON_BUFSIZE. */
static const char*
ofp_role_reason_to_string(enum ofp14_controller_role_reason reason,
                          char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPCRR_PRIMARY_REQUEST:
        return "primary_request";

    case OFPCRR_CONFIG:
        return "configuration_changed";

    case OFPCRR_EXPERIMENTER:
        return "experimenter_data_changed";

    case OFPCRR_N_REASONS:
    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFP_ASYNC_CONFIG_REASON_BUFSIZE. */
static const char*
ofp_requestforward_reason_to_string(enum ofp14_requestforward_reason reason,
                                    char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPRFR_GROUP_MOD:
        return "group_mod_request";

    case OFPRFR_METER_MOD:
        return "meter_mod_request";

    case OFPRFR_N_REASONS:
    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

static const char *
ofp_async_config_reason_to_string(uint32_t reason,
                                  enum ofputil_async_msg_type type,
                                  char *reasonbuf, size_t bufsize)
{
    switch (type) {
    case OAM_PACKET_IN:
        return ofputil_packet_in_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_PORT_STATUS:
        return ofp_port_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_FLOW_REMOVED:
        return ofp_flow_removed_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_ROLE_STATUS:
        return ofp_role_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_TABLE_STATUS:
        return ofp_table_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_REQUESTFORWARD:
        return ofp_requestforward_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_N_TYPES:
    default:
        return "Unknown asynchronous configuration message type";
    }
}

void
ofputil_format_set_async_config(struct ds *string,
                                const struct ofputil_async_cfg *ac)
{
    for (int i = 0; i < 2; i++) {
        ds_put_format(string, "\n %s:\n", i == 0 ? "primary" : "secondary");
        for (uint32_t type = 0; type < OAM_N_TYPES; type++) {
            ds_put_format(string, "%16s:",
                          ofputil_async_msg_type_to_string(type));

            uint32_t role = i == 0 ? ac->primary[type] : ac->secondary[type];
            for (int j = 0; j < 32; j++) {
                if (role & (1u << j)) {
                    char reasonbuf[INT_STRLEN(int) + 1];
                    const char *reason;

                    reason = ofp_async_config_reason_to_string(
                        j, type, reasonbuf, sizeof reasonbuf);
                    if (reason[0]) {
                        ds_put_format(string, " %s", reason);
                    }
                }
            }
            if (!role) {
                ds_put_cstr(string, " (off)");
            }
            ds_put_char(string, '\n');
        }
    }
}

struct ofputil_async_cfg
ofputil_async_cfg_default(enum ofp_version version)
{
    /* We enable all of the OF1.4 reasons regardless of 'version' because the
     * reasons added in OF1.4 just are just refinements of the OFPR_ACTION
     * introduced in OF1.0, breaking it into more specific categories.  When we
     * encode these for earlier OpenFlow versions, we translate them into
     * OFPR_ACTION.  */
    uint32_t pin = OFPR14_BITS & ~(1u << OFPR_INVALID_TTL);
    pin |= 1u << OFPR_EXPLICIT_MISS;
    if (version <= OFP12_VERSION) {
        pin |= 1u << OFPR_IMPLICIT_MISS;
    }

    struct ofputil_async_cfg oac = {
        .primary[OAM_PACKET_IN] = pin,
        .primary[OAM_PORT_STATUS] = OFPPR_BITS,
        .secondary[OAM_PORT_STATUS] = OFPPR_BITS
    };

    if (version >= OFP14_VERSION) {
        oac.primary[OAM_FLOW_REMOVED] = OFPRR14_BITS;
    } else if (version == OFP13_VERSION) {
        oac.primary[OAM_FLOW_REMOVED] = OFPRR13_BITS;
    } else {
        oac.primary[OAM_FLOW_REMOVED] = OFPRR10_BITS;
    }

    return oac;
}
