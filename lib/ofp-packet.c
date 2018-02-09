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
#include "openvswitch/ofp-packet.h"
#include <string.h>
#include "dp-packet.h"
#include "nx-match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(ofp_packet);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

bool
ofputil_packet_in_format_is_valid(enum nx_packet_in_format packet_in_format)
{
    switch (packet_in_format) {
    case NXPIF_STANDARD:
    case NXPIF_NXT_PACKET_IN:
    case NXPIF_NXT_PACKET_IN2:
        return true;
    }

    return false;
}

const char *
ofputil_packet_in_format_to_string(enum nx_packet_in_format packet_in_format)
{
    switch (packet_in_format) {
    case NXPIF_STANDARD:
        return "standard";
    case NXPIF_NXT_PACKET_IN:
        return "nxt_packet_in";
    case NXPIF_NXT_PACKET_IN2:
        return "nxt_packet_in2";
    default:
        OVS_NOT_REACHED();
    }
}

int
ofputil_packet_in_format_from_string(const char *s)
{
    return (!strcmp(s, "standard") || !strcmp(s, "openflow10")
            ? NXPIF_STANDARD
            : !strcmp(s, "nxt_packet_in") || !strcmp(s, "nxm")
            ? NXPIF_NXT_PACKET_IN
            : !strcmp(s, "nxt_packet_in2")
            ? NXPIF_NXT_PACKET_IN2
            : -1);
}

struct ofpbuf *
ofputil_make_set_packet_in_format(enum ofp_version ofp_version,
                                  enum nx_packet_in_format packet_in_format)
{
    struct nx_set_packet_in_format *spif;
    struct ofpbuf *msg;

    msg = ofpraw_alloc(OFPRAW_NXT_SET_PACKET_IN_FORMAT, ofp_version, 0);
    spif = ofpbuf_put_zeros(msg, sizeof *spif);
    spif->format = htonl(packet_in_format);

    return msg;
}

/* The caller has done basic initialization of '*pin'; the other output
 * arguments needs to be initialized. */
static enum ofperr
decode_nx_packet_in2(const struct ofp_header *oh, bool loose,
                     const struct tun_table *tun_table,
                     const struct vl_mff_map *vl_mff_map,
                     struct ofputil_packet_in *pin,
                     size_t *total_len, uint32_t *buffer_id,
                     struct ofpbuf *continuation)
{
    *total_len = 0;
    *buffer_id = UINT32_MAX;

    struct ofpbuf properties;
    ofpbuf_use_const(&properties, oh, ntohs(oh->length));
    ofpraw_pull_assert(&properties);

    while (properties.size > 0) {
        struct ofpbuf payload;
        uint64_t type;

        enum ofperr error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case NXPINT_PACKET:
            pin->packet = payload.msg;
            pin->packet_len = ofpbuf_msgsize(&payload);
            break;

        case NXPINT_FULL_LEN: {
            uint32_t u32;
            error = ofpprop_parse_u32(&payload, &u32);
            *total_len = u32;
            break;
        }

        case NXPINT_BUFFER_ID:
            error = ofpprop_parse_u32(&payload, buffer_id);
            break;

        case NXPINT_TABLE_ID:
            error = ofpprop_parse_u8(&payload, &pin->table_id);
            break;

        case NXPINT_COOKIE:
            error = ofpprop_parse_be64(&payload, &pin->cookie);
            break;

        case NXPINT_REASON: {
            uint8_t reason;
            error = ofpprop_parse_u8(&payload, &reason);
            pin->reason = reason;
            break;
        }

        case NXPINT_METADATA:
            error = oxm_decode_match(payload.msg, ofpbuf_msgsize(&payload),
                                     loose, tun_table, vl_mff_map,
                                     &pin->flow_metadata);
            break;

        case NXPINT_USERDATA:
            pin->userdata = payload.msg;
            pin->userdata_len = ofpbuf_msgsize(&payload);
            break;

        case NXPINT_CONTINUATION:
            if (continuation) {
                error = ofpprop_parse_nested(&payload, continuation);
            }
            break;

        default:
            error = OFPPROP_UNKNOWN(loose, "NX_PACKET_IN2", type);
            break;
        }
        if (error) {
            return error;
        }
    }

    if (!pin->packet_len) {
        VLOG_WARN_RL(&rl, "NXT_PACKET_IN2 lacks packet");
        return OFPERR_OFPBRC_BAD_LEN;
    } else if (!*total_len) {
        *total_len = pin->packet_len;
    } else if (*total_len < pin->packet_len) {
        VLOG_WARN_RL(&rl, "NXT_PACKET_IN2 claimed full_len < len");
        return OFPERR_OFPBRC_BAD_LEN;
    }

    return 0;
}

/* Decodes the packet-in message starting at 'oh' into '*pin'.  Populates
 * 'pin->packet' and 'pin->packet_len' with the part of the packet actually
 * included in the message.  If 'total_lenp' is nonnull, populates
 * '*total_lenp' with the original length of the packet (which is larger than
 * 'packet->len' if only part of the packet was included).  If 'buffer_idp' is
 * nonnull, stores the packet's buffer ID in '*buffer_idp' (UINT32_MAX if it
 * was not buffered).
 *
 * Populates 'continuation', if nonnull, with the continuation data from the
 * packet-in (an empty buffer, if 'oh' did not contain continuation data).  The
 * format of this data is supposed to be opaque to anything other than
 * ovs-vswitchd, so that in any other process the only reasonable use of this
 * data is to be copied into an NXT_RESUME message via ofputil_encode_resume().
 *
 * This function points 'pin->packet' into 'oh', so the caller should not free
 * it separately from the original OpenFlow message.  This is also true for
 * 'pin->userdata' (which could also end up NULL if there is no userdata).
 *
 * 'vl_mff_map' is an optional parameter that is used to validate the length
 * of variable length mf_fields in 'match'. If it is not provided, the
 * default mf_fields with maximum length will be used.
 *
 * Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
ofputil_decode_packet_in(const struct ofp_header *oh, bool loose,
                         const struct tun_table *tun_table,
                         const struct vl_mff_map *vl_mff_map,
                         struct ofputil_packet_in *pin,
                         size_t *total_lenp, uint32_t *buffer_idp,
                         struct ofpbuf *continuation)
{
    uint32_t buffer_id;
    size_t total_len;

    memset(pin, 0, sizeof *pin);
    pin->cookie = OVS_BE64_MAX;
    if (continuation) {
        ofpbuf_use_const(continuation, NULL, 0);
    }

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT13_PACKET_IN || raw == OFPRAW_OFPT12_PACKET_IN) {
        const struct ofp12_packet_in *opi = ofpbuf_pull(&b, sizeof *opi);
        const ovs_be64 *cookie = (raw == OFPRAW_OFPT13_PACKET_IN
                                  ? ofpbuf_pull(&b, sizeof *cookie)
                                  : NULL);
        enum ofperr error = oxm_pull_match_loose(&b, false, tun_table,
                                                 &pin->flow_metadata);
        if (error) {
            return error;
        }

        if (!ofpbuf_try_pull(&b, 2)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        pin->reason = opi->reason;
        pin->table_id = opi->table_id;
        buffer_id = ntohl(opi->buffer_id);
        total_len = ntohs(opi->total_len);
        if (cookie) {
            pin->cookie = *cookie;
        }

        pin->packet = b.data;
        pin->packet_len = b.size;
    } else if (raw == OFPRAW_OFPT10_PACKET_IN) {
        const struct ofp10_packet_in *opi;

        opi = ofpbuf_pull(&b, offsetof(struct ofp10_packet_in, data));

        pin->packet = CONST_CAST(uint8_t *, opi->data);
        pin->packet_len = b.size;

        match_init_catchall(&pin->flow_metadata);
        match_set_in_port(&pin->flow_metadata,
                          u16_to_ofp(ntohs(opi->in_port)));
        pin->reason = opi->reason;
        buffer_id = ntohl(opi->buffer_id);
        total_len = ntohs(opi->total_len);
    } else if (raw == OFPRAW_OFPT11_PACKET_IN) {
        const struct ofp11_packet_in *opi;
        ofp_port_t in_port;
        enum ofperr error;

        opi = ofpbuf_pull(&b, sizeof *opi);

        pin->packet = b.data;
        pin->packet_len = b.size;

        buffer_id = ntohl(opi->buffer_id);
        error = ofputil_port_from_ofp11(opi->in_port, &in_port);
        if (error) {
            return error;
        }
        match_init_catchall(&pin->flow_metadata);
        match_set_in_port(&pin->flow_metadata, in_port);
        total_len = ntohs(opi->total_len);
        pin->reason = opi->reason;
        pin->table_id = opi->table_id;
    } else if (raw == OFPRAW_NXT_PACKET_IN) {
        const struct nx_packet_in *npi;
        int error;

        npi = ofpbuf_pull(&b, sizeof *npi);
        error = nx_pull_match_loose(&b, ntohs(npi->match_len),
                                    &pin->flow_metadata, NULL, NULL, false,
                                    NULL);
        if (error) {
            return error;
        }

        if (!ofpbuf_try_pull(&b, 2)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        pin->reason = npi->reason;
        pin->table_id = npi->table_id;
        pin->cookie = npi->cookie;

        buffer_id = ntohl(npi->buffer_id);
        total_len = ntohs(npi->total_len);

        pin->packet = b.data;
        pin->packet_len = b.size;
    } else if (raw == OFPRAW_NXT_PACKET_IN2 || raw == OFPRAW_NXT_RESUME) {
        enum ofperr error = decode_nx_packet_in2(oh, loose, tun_table,
                                                 vl_mff_map, pin, &total_len,
                                                 &buffer_id, continuation);
        if (error) {
            return error;
        }
    } else {
        OVS_NOT_REACHED();
    }

    if (total_lenp) {
        *total_lenp = total_len;
    }
    if (buffer_idp) {
        *buffer_idp = buffer_id;
    }

    return 0;
}

static int
encode_packet_in_reason(enum ofp_packet_in_reason reason,
                        enum ofp_version version)
{
    switch (reason) {
    case OFPR_NO_MATCH:
    case OFPR_ACTION:
    case OFPR_INVALID_TTL:
        return reason;

    case OFPR_ACTION_SET:
    case OFPR_GROUP:
    case OFPR_PACKET_OUT:
        return version < OFP14_VERSION ? OFPR_ACTION : reason;

    case OFPR_EXPLICIT_MISS:
        return version < OFP13_VERSION ? OFPR_ACTION : OFPR_NO_MATCH;

    case OFPR_IMPLICIT_MISS:
        return OFPR_NO_MATCH;

    case OFPR_N_REASONS:
    default:
        OVS_NOT_REACHED();
    }
}

/* Only NXT_PACKET_IN2 (not NXT_RESUME) should include NXCPT_USERDATA, so this
 * function omits it.  The caller can add it itself if desired. */
static void
ofputil_put_packet_in(const struct ofputil_packet_in *pin,
                      enum ofp_version version, size_t include_bytes,
                      struct ofpbuf *msg)
{
    /* Add packet properties. */
    ofpprop_put(msg, NXPINT_PACKET, pin->packet, include_bytes);
    if (include_bytes != pin->packet_len) {
        ofpprop_put_u32(msg, NXPINT_FULL_LEN, pin->packet_len);
    }

    /* Add flow properties. */
    ofpprop_put_u8(msg, NXPINT_TABLE_ID, pin->table_id);
    if (pin->cookie != OVS_BE64_MAX) {
        ofpprop_put_be64(msg, NXPINT_COOKIE, pin->cookie);
    }

    /* Add other properties. */
    ofpprop_put_u8(msg, NXPINT_REASON,
                   encode_packet_in_reason(pin->reason, version));

    size_t start = ofpprop_start(msg, NXPINT_METADATA);
    oxm_put_raw(msg, &pin->flow_metadata, version);
    ofpprop_end(msg, start);
}

static void
put_actions_property(struct ofpbuf *msg, uint64_t prop_type,
                     enum ofp_version version,
                     const struct ofpact *actions, size_t actions_len)
{
    if (actions_len) {
        size_t start = ofpprop_start_nested(msg, prop_type);
        ofpacts_put_openflow_actions(actions, actions_len, msg, version);
        ofpprop_end(msg, start);
    }
}

enum nx_continuation_prop_type {
    NXCPT_BRIDGE = 0x8000,
    NXCPT_STACK,
    NXCPT_MIRRORS,
    NXCPT_CONNTRACKED,
    NXCPT_TABLE_ID,
    NXCPT_COOKIE,
    NXCPT_ACTIONS,
    NXCPT_ACTION_SET,
};

/* Only NXT_PACKET_IN2 (not NXT_RESUME) should include NXCPT_USERDATA, so this
 * function omits it.  The caller can add it itself if desired. */
static void
ofputil_put_packet_in_private(const struct ofputil_packet_in_private *pin,
                              enum ofp_version version, size_t include_bytes,
                              struct ofpbuf *msg)
{
    ofputil_put_packet_in(&pin->base, version, include_bytes, msg);

    size_t continuation_ofs = ofpprop_start_nested(msg, NXPINT_CONTINUATION);
    size_t inner_ofs = msg->size;

    if (!uuid_is_zero(&pin->bridge)) {
        ofpprop_put_uuid(msg, NXCPT_BRIDGE, &pin->bridge);
    }

    struct ofpbuf pin_stack;
    ofpbuf_use_const(&pin_stack, pin->stack, pin->stack_size);

    while (pin_stack.size) {
        uint8_t len;
        uint8_t *val = nx_stack_pop(&pin_stack, &len);
        ofpprop_put(msg, NXCPT_STACK, val, len);
    }

    if (pin->mirrors) {
        ofpprop_put_u32(msg, NXCPT_MIRRORS, pin->mirrors);
    }

    if (pin->conntracked) {
        ofpprop_put_flag(msg, NXCPT_CONNTRACKED);
    }

    if (pin->actions_len) {
        /* Divide 'pin->actions' into groups that begins with an
         * unroll_xlate action.  For each group, emit a NXCPT_TABLE_ID and
         * NXCPT_COOKIE property (if either has changed; each is initially
         * assumed 0), then a NXCPT_ACTIONS property with the grouped
         * actions.
         *
         * The alternative is to make OFPACT_UNROLL_XLATE public.  We can
         * always do that later, since this is a private property. */
        const struct ofpact *const end = ofpact_end(pin->actions,
                                                    pin->actions_len);
        const struct ofpact_unroll_xlate *unroll = NULL;
        uint8_t table_id = 0;
        ovs_be64 cookie = 0;

        const struct ofpact *a;
        for (a = pin->actions; ; a = ofpact_next(a)) {
            if (a == end || a->type == OFPACT_UNROLL_XLATE) {
                if (unroll) {
                    if (table_id != unroll->rule_table_id) {
                        ofpprop_put_u8(msg, NXCPT_TABLE_ID,
                                       unroll->rule_table_id);
                        table_id = unroll->rule_table_id;
                    }
                    if (cookie != unroll->rule_cookie) {
                        ofpprop_put_be64(msg, NXCPT_COOKIE,
                                         unroll->rule_cookie);
                        cookie = unroll->rule_cookie;
                    }
                }

                const struct ofpact *start
                    = unroll ? ofpact_next(&unroll->ofpact) : pin->actions;
                put_actions_property(msg, NXCPT_ACTIONS, version,
                                     start, (a - start) * sizeof *a);

                if (a == end) {
                    break;
                }
                unroll = ofpact_get_UNROLL_XLATE(a);
            }
        }
    }

    if (pin->action_set_len) {
        size_t start = ofpprop_start_nested(msg, NXCPT_ACTION_SET);
        ofpacts_put_openflow_actions(pin->action_set,
                                     pin->action_set_len, msg, version);
        ofpprop_end(msg, start);
    }

    if (msg->size > inner_ofs) {
        ofpprop_end(msg, continuation_ofs);
    } else {
        msg->size = continuation_ofs;
    }
}

static struct ofpbuf *
ofputil_encode_ofp10_packet_in(const struct ofputil_packet_in *pin)
{
    struct ofp10_packet_in *opi;
    struct ofpbuf *msg;

    msg = ofpraw_alloc_xid(OFPRAW_OFPT10_PACKET_IN, OFP10_VERSION,
                           htonl(0), pin->packet_len);
    opi = ofpbuf_put_zeros(msg, offsetof(struct ofp10_packet_in, data));
    opi->total_len = htons(pin->packet_len);
    opi->in_port = htons(ofp_to_u16(pin->flow_metadata.flow.in_port.ofp_port));
    opi->reason = encode_packet_in_reason(pin->reason, OFP10_VERSION);
    opi->buffer_id = htonl(UINT32_MAX);

    return msg;
}

static struct ofpbuf *
ofputil_encode_nx_packet_in(const struct ofputil_packet_in *pin,
                            enum ofp_version version)
{
    struct nx_packet_in *npi;
    struct ofpbuf *msg;
    size_t match_len;

    /* The final argument is just an estimate of the space required. */
    msg = ofpraw_alloc_xid(OFPRAW_NXT_PACKET_IN, version,
                           htonl(0), NXM_TYPICAL_LEN + 2 + pin->packet_len);
    ofpbuf_put_zeros(msg, sizeof *npi);
    match_len = nx_put_match(msg, &pin->flow_metadata, 0, 0);
    ofpbuf_put_zeros(msg, 2);

    npi = msg->msg;
    npi->buffer_id = htonl(UINT32_MAX);
    npi->total_len = htons(pin->packet_len);
    npi->reason = encode_packet_in_reason(pin->reason, version);
    npi->table_id = pin->table_id;
    npi->cookie = pin->cookie;
    npi->match_len = htons(match_len);

    return msg;
}

static struct ofpbuf *
ofputil_encode_nx_packet_in2(const struct ofputil_packet_in_private *pin,
                             enum ofp_version version, size_t include_bytes)
{
    /* 'extra' is just an estimate of the space required. */
    size_t extra = (pin->base.packet_len
                    + NXM_TYPICAL_LEN   /* flow_metadata */
                    + pin->stack_size * 4
                    + pin->actions_len
                    + pin->action_set_len
                    + 256);     /* fudge factor */
    struct ofpbuf *msg = ofpraw_alloc_xid(OFPRAW_NXT_PACKET_IN2, version,
                                          htonl(0), extra);

    ofputil_put_packet_in_private(pin, version, include_bytes, msg);
    if (pin->base.userdata_len) {
        ofpprop_put(msg, NXPINT_USERDATA, pin->base.userdata,
                    pin->base.userdata_len);
    }

    ofpmsg_update_length(msg);
    return msg;
}

static struct ofpbuf *
ofputil_encode_ofp11_packet_in(const struct ofputil_packet_in *pin)
{
    struct ofp11_packet_in *opi;
    struct ofpbuf *msg;

    msg = ofpraw_alloc_xid(OFPRAW_OFPT11_PACKET_IN, OFP11_VERSION,
                           htonl(0), pin->packet_len);
    opi = ofpbuf_put_zeros(msg, sizeof *opi);
    opi->buffer_id = htonl(UINT32_MAX);
    opi->in_port = ofputil_port_to_ofp11(
        pin->flow_metadata.flow.in_port.ofp_port);
    opi->in_phy_port = opi->in_port;
    opi->total_len = htons(pin->packet_len);
    opi->reason = encode_packet_in_reason(pin->reason, OFP11_VERSION);
    opi->table_id = pin->table_id;

    return msg;
}

static struct ofpbuf *
ofputil_encode_ofp12_packet_in(const struct ofputil_packet_in *pin,
                               enum ofp_version version)
{
    enum ofpraw raw = (version >= OFP13_VERSION
                       ? OFPRAW_OFPT13_PACKET_IN
                       : OFPRAW_OFPT12_PACKET_IN);
    struct ofpbuf *msg;

    /* The final argument is just an estimate of the space required. */
    msg = ofpraw_alloc_xid(raw, version,
                           htonl(0), NXM_TYPICAL_LEN + 2 + pin->packet_len);

    struct ofp12_packet_in *opi = ofpbuf_put_zeros(msg, sizeof *opi);
    opi->buffer_id = htonl(UINT32_MAX);
    opi->total_len = htons(pin->packet_len);
    opi->reason = encode_packet_in_reason(pin->reason, version);
    opi->table_id = pin->table_id;

    if (version >= OFP13_VERSION) {
        ovs_be64 cookie = pin->cookie;
        ofpbuf_put(msg, &cookie, sizeof cookie);
    }

    oxm_put_match(msg, &pin->flow_metadata, version);
    ofpbuf_put_zeros(msg, 2);

    return msg;
}

/* Converts abstract ofputil_packet_in_private 'pin' into a PACKET_IN message
 * for 'protocol', using the packet-in format specified by 'packet_in_format'.
 *
 * This function is really meant only for use by ovs-vswitchd.  To any other
 * code, the "continuation" data, i.e. the data that is in struct
 * ofputil_packet_in_private but not in struct ofputil_packet_in, is supposed
 * to be opaque (and it might change from one OVS version to another).  Thus,
 * if any other code wants to encode a packet-in, it should use a non-"private"
 * version of this function.  (Such a version doesn't currently exist because
 * only ovs-vswitchd currently wants to encode packet-ins.  If you need one,
 * write it...) */
struct ofpbuf *
ofputil_encode_packet_in_private(const struct ofputil_packet_in_private *pin,
                                 enum ofputil_protocol protocol,
                                 enum nx_packet_in_format packet_in_format)
{
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);

    struct ofpbuf *msg;
    switch (packet_in_format) {
    case NXPIF_STANDARD:
        switch (protocol) {
        case OFPUTIL_P_OF10_STD:
        case OFPUTIL_P_OF10_STD_TID:
        case OFPUTIL_P_OF10_NXM:
        case OFPUTIL_P_OF10_NXM_TID:
            msg = ofputil_encode_ofp10_packet_in(&pin->base);
            break;

        case OFPUTIL_P_OF11_STD:
            msg = ofputil_encode_ofp11_packet_in(&pin->base);
            break;

        case OFPUTIL_P_OF12_OXM:
        case OFPUTIL_P_OF13_OXM:
        case OFPUTIL_P_OF14_OXM:
        case OFPUTIL_P_OF15_OXM:
        case OFPUTIL_P_OF16_OXM:
            msg = ofputil_encode_ofp12_packet_in(&pin->base, version);
            break;

        default:
            OVS_NOT_REACHED();
        }
        break;

    case NXPIF_NXT_PACKET_IN:
        msg = ofputil_encode_nx_packet_in(&pin->base, version);
        break;

    case NXPIF_NXT_PACKET_IN2:
        return ofputil_encode_nx_packet_in2(pin, version,
                                            pin->base.packet_len);

    default:
        OVS_NOT_REACHED();
    }

    ofpbuf_put(msg, pin->base.packet, pin->base.packet_len);
    ofpmsg_update_length(msg);
    return msg;
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFPUTIL_PACKET_IN_REASON_BUFSIZE. */
const char *
ofputil_packet_in_reason_to_string(enum ofp_packet_in_reason reason,
                                   char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPR_NO_MATCH:
        return "no_match";
    case OFPR_ACTION:
        return "action";
    case OFPR_INVALID_TTL:
        return "invalid_ttl";
    case OFPR_ACTION_SET:
        return "action_set";
    case OFPR_GROUP:
        return "group";
    case OFPR_PACKET_OUT:
        return "packet_out";
    case OFPR_EXPLICIT_MISS:
    case OFPR_IMPLICIT_MISS:
        return "";

    case OFPR_N_REASONS:
    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

bool
ofputil_packet_in_reason_from_string(const char *s,
                                     enum ofp_packet_in_reason *reason)
{
    int i;

    for (i = 0; i < OFPR_N_REASONS; i++) {
        char reasonbuf[OFPUTIL_PACKET_IN_REASON_BUFSIZE];
        const char *reason_s;

        reason_s = ofputil_packet_in_reason_to_string(i, reasonbuf,
                                                      sizeof reasonbuf);
        if (!strcasecmp(s, reason_s)) {
            *reason = i;
            return true;
        }
    }
    return false;
}

/* Returns a newly allocated NXT_RESUME message for 'pin', with the given
 * 'continuation', for 'protocol'.  This message is suitable for resuming the
 * pipeline traveral of the packet represented by 'pin', if sent to the switch
 * from which 'pin' was received. */
struct ofpbuf *
ofputil_encode_resume(const struct ofputil_packet_in *pin,
                      const struct ofpbuf *continuation,
                      enum ofputil_protocol protocol)
{
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);
    size_t extra = pin->packet_len + NXM_TYPICAL_LEN + continuation->size;
    struct ofpbuf *msg = ofpraw_alloc_xid(OFPRAW_NXT_RESUME, version,
                                          0, extra);
    ofputil_put_packet_in(pin, version, pin->packet_len, msg);
    ofpprop_put_nested(msg, NXPINT_CONTINUATION, continuation);
    ofpmsg_update_length(msg);
    return msg;
}

static enum ofperr
parse_stack_prop(const struct ofpbuf *property, struct ofpbuf *stack)
{
    unsigned int len = ofpbuf_msgsize(property);
    if (len > sizeof(union mf_subvalue)) {
        VLOG_WARN_RL(&rl, "NXCPT_STACK property has bad length %u",
                     len);
        return OFPERR_OFPBPC_BAD_LEN;
    }
    nx_stack_push_bottom(stack, property->msg, len);
    return 0;
}

static enum ofperr
parse_actions_property(struct ofpbuf *property, enum ofp_version version,
                       struct ofpbuf *ofpacts)
{
    if (!ofpbuf_try_pull(property, ROUND_UP(ofpbuf_headersize(property), 8))) {
        VLOG_WARN_RL(&rl, "actions property has bad length %"PRIu32,
                     property->size);
        return OFPERR_OFPBPC_BAD_LEN;
    }

    return ofpacts_pull_openflow_actions(property, property->size,
                                         version, NULL, NULL, ofpacts);
}

/* This is like ofputil_decode_packet_in(), except that it decodes the
 * continuation data into 'pin'.  The format of this data is supposed to be
 * opaque to any process other than ovs-vswitchd, so this function should not
 * be used outside ovs-vswitchd.
 *
 * 'vl_mff_map' is an optional parameter that is used to validate the length
 * of variable length mf_fields in 'match'. If it is not provided, the
 * default mf_fields with maximum length will be used.
 *
 * When successful, 'pin' contains some dynamically allocated data.  Call
 * ofputil_packet_in_private_destroy() to free this data. */
enum ofperr
ofputil_decode_packet_in_private(const struct ofp_header *oh, bool loose,
                                 const struct tun_table *tun_table,
                                 const struct vl_mff_map *vl_mff_map,
                                 struct ofputil_packet_in_private *pin,
                                 size_t *total_len, uint32_t *buffer_id)
{
    memset(pin, 0, sizeof *pin);

    struct ofpbuf continuation;
    enum ofperr error;
    error = ofputil_decode_packet_in(oh, loose, tun_table, vl_mff_map,
                                     &pin->base, total_len, buffer_id,
                                     &continuation);
    if (error) {
        return error;
    }

    struct ofpbuf actions, action_set;
    ofpbuf_init(&actions, 0);
    ofpbuf_init(&action_set, 0);

    uint8_t table_id = 0;
    ovs_be64 cookie = 0;

    struct ofpbuf stack;
    ofpbuf_init(&stack, 0);

    while (continuation.size > 0) {
        struct ofpbuf payload;
        uint64_t type;

        error = ofpprop_pull(&continuation, &payload, &type);
        if (error) {
            break;
        }

        switch (type) {
        case NXCPT_BRIDGE:
            error = ofpprop_parse_uuid(&payload, &pin->bridge);
            break;

        case NXCPT_STACK:
            error = parse_stack_prop(&payload, &stack);
            break;

        case NXCPT_MIRRORS:
            error = ofpprop_parse_u32(&payload, &pin->mirrors);
            break;

        case NXCPT_CONNTRACKED:
            pin->conntracked = true;
            break;

        case NXCPT_TABLE_ID:
            error = ofpprop_parse_u8(&payload, &table_id);
            break;

        case NXCPT_COOKIE:
            error = ofpprop_parse_be64(&payload, &cookie);
            break;

        case NXCPT_ACTIONS: {
            struct ofpact_unroll_xlate *unroll
                = ofpact_put_UNROLL_XLATE(&actions);
            unroll->rule_table_id = table_id;
            unroll->rule_cookie = cookie;
            error = parse_actions_property(&payload, oh->version, &actions);
            break;
        }

        case NXCPT_ACTION_SET:
            error = parse_actions_property(&payload, oh->version, &action_set);
            break;

        default:
            error = OFPPROP_UNKNOWN(loose, "continuation", type);
            break;
        }
        if (error) {
            break;
        }
    }

    pin->actions_len = actions.size;
    pin->actions = ofpbuf_steal_data(&actions);
    pin->action_set_len = action_set.size;
    pin->action_set = ofpbuf_steal_data(&action_set);
    pin->stack_size = stack.size;
    pin->stack = ofpbuf_steal_data(&stack);

    if (error) {
        ofputil_packet_in_private_destroy(pin);
    }

    return error;
}

/* Frees data in 'pin' that is dynamically allocated by
 * ofputil_decode_packet_in_private().
 *
 * 'pin->base' contains some pointer members that
 * ofputil_decode_packet_in_private() doesn't initialize to newly allocated
 * data, so this function doesn't free those. */
void
ofputil_packet_in_private_destroy(struct ofputil_packet_in_private *pin)
{
    if (pin) {
        free(pin->stack);
        free(pin->actions);
        free(pin->action_set);
    }
}

/* Converts an OFPT_PACKET_OUT in 'opo' into an abstract ofputil_packet_out in
 * 'po'.
 *
 * Uses 'ofpacts' to store the abstract OFPACT_* version of the packet out
 * message's actions.  The caller must initialize 'ofpacts' and retains
 * ownership of it.  'po->ofpacts' will point into the 'ofpacts' buffer.
 *
 * 'po->packet' refers to the packet data in 'oh', so the buffer containing
 * 'oh' must not be destroyed while 'po' is being used.
 *
 * Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_packet_out(struct ofputil_packet_out *po,
                          const struct ofp_header *oh,
                          const struct tun_table *tun_table,
                          struct ofpbuf *ofpacts)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);

    ofpbuf_clear(ofpacts);
    match_init_catchall(&po->flow_metadata);
    if (raw == OFPRAW_OFPT15_PACKET_OUT) {
        enum ofperr error;
        const struct ofp15_packet_out *opo = ofpbuf_pull(&b, sizeof *opo);

        po->buffer_id = ntohl(opo->buffer_id);
        error = oxm_pull_match_loose(&b, true, tun_table, &po->flow_metadata);
        if (error) {
            return error;
        }

        if (!po->flow_metadata.wc.masks.in_port.ofp_port) {
            return OFPERR_OFPBRC_BAD_PORT;
        }

        error = ofpacts_pull_openflow_actions(&b, ntohs(opo->actions_len),
                                              oh->version, NULL, NULL,
                                              ofpacts);
        if (error) {
            return error;
        }
    } else if (raw == OFPRAW_OFPT11_PACKET_OUT) {
        enum ofperr error;
        ofp_port_t in_port;
        const struct ofp11_packet_out *opo = ofpbuf_pull(&b, sizeof *opo);

        po->buffer_id = ntohl(opo->buffer_id);
        error = ofputil_port_from_ofp11(opo->in_port, &in_port);
        if (error) {
            return error;
        }
        match_set_packet_type(&po->flow_metadata, htonl(PT_ETH));
        match_set_in_port(&po->flow_metadata, in_port);

        error = ofpacts_pull_openflow_actions(&b, ntohs(opo->actions_len),
                                              oh->version, NULL, NULL,
                                              ofpacts);
        if (error) {
            return error;
        }
    } else if (raw == OFPRAW_OFPT10_PACKET_OUT) {
        enum ofperr error;
        const struct ofp10_packet_out *opo = ofpbuf_pull(&b, sizeof *opo);

        po->buffer_id = ntohl(opo->buffer_id);
        match_set_packet_type(&po->flow_metadata, htonl(PT_ETH));
        match_set_in_port(&po->flow_metadata, u16_to_ofp(ntohs(opo->in_port)));

        error = ofpacts_pull_openflow_actions(&b, ntohs(opo->actions_len),
                                              oh->version, NULL, NULL,
                                              ofpacts);
        if (error) {
            return error;
        }
    } else {
        OVS_NOT_REACHED();
    }

    ofp_port_t in_port = po->flow_metadata.flow.in_port.ofp_port;
    if (ofp_to_u16(in_port) >= ofp_to_u16(OFPP_MAX)
        && in_port != OFPP_LOCAL
        && in_port != OFPP_NONE
        && in_port != OFPP_CONTROLLER) {
        VLOG_WARN_RL(&rl, "packet-out has bad input port %#"PRIx32,
                     po->flow_metadata.flow.in_port.ofp_port);
        return OFPERR_OFPBRC_BAD_PORT;
    }

    po->ofpacts = ofpacts->data;
    po->ofpacts_len = ofpacts->size;

    if (po->buffer_id == UINT32_MAX) {
        po->packet = b.data;
        po->packet_len = b.size;
    } else {
        po->packet = NULL;
        po->packet_len = 0;
    }

    return 0;
}

struct ofpbuf *
ofputil_encode_packet_out(const struct ofputil_packet_out *po,
                          enum ofputil_protocol protocol)
{
    enum ofp_version ofp_version = ofputil_protocol_to_ofp_version(protocol);
    struct ofpbuf *msg;
    size_t size;

    size = po->ofpacts_len;
    if (po->buffer_id == UINT32_MAX) {
        size += po->packet_len;
    }

    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_packet_out *opo;
        size_t actions_ofs;

        msg = ofpraw_alloc(OFPRAW_OFPT10_PACKET_OUT, OFP10_VERSION, size);
        ofpbuf_put_zeros(msg, sizeof *opo);
        actions_ofs = msg->size;
        ofpacts_put_openflow_actions(po->ofpacts, po->ofpacts_len, msg,
                                     ofp_version);

        opo = msg->msg;
        opo->buffer_id = htonl(po->buffer_id);
        opo->in_port =htons(ofp_to_u16(
                                po->flow_metadata.flow.in_port.ofp_port));
        opo->actions_len = htons(msg->size - actions_ofs);
        break;
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION: {
        struct ofp11_packet_out *opo;
        size_t len;

        msg = ofpraw_alloc(OFPRAW_OFPT11_PACKET_OUT, ofp_version, size);
        ofpbuf_put_zeros(msg, sizeof *opo);
        len = ofpacts_put_openflow_actions(po->ofpacts, po->ofpacts_len, msg,
                                           ofp_version);
        opo = msg->msg;
        opo->buffer_id = htonl(po->buffer_id);
        opo->in_port =
            ofputil_port_to_ofp11(po->flow_metadata.flow.in_port.ofp_port);
        opo->actions_len = htons(len);
        break;
    }

    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp15_packet_out *opo;
        size_t len;

        /* The final argument is just an estimate of the space required. */
        msg = ofpraw_alloc(OFPRAW_OFPT15_PACKET_OUT, ofp_version,
                           size + NXM_TYPICAL_LEN);
        ofpbuf_put_zeros(msg, sizeof *opo);
        oxm_put_match(msg, &po->flow_metadata, ofp_version);
        len = ofpacts_put_openflow_actions(po->ofpacts, po->ofpacts_len, msg,
                                           ofp_version);
        opo = msg->msg;
        opo->buffer_id = htonl(po->buffer_id);
        opo->actions_len = htons(len);
        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    if (po->buffer_id == UINT32_MAX) {
        ofpbuf_put(msg, po->packet, po->packet_len);
    }

    ofpmsg_update_length(msg);

    return msg;
}

/* Parse a string representation of a OFPT_PACKET_OUT to '*po'.  If successful,
 * both 'po->ofpacts' and 'po->packet' must be free()d by the caller. */
static char * OVS_WARN_UNUSED_RESULT
parse_ofp_packet_out_str__(struct ofputil_packet_out *po, char *string,
                           const struct ofputil_port_map *port_map,
                           const struct ofputil_table_map *table_map,
                           enum ofputil_protocol *usable_protocols)
{
    enum ofputil_protocol action_usable_protocols;
    uint64_t stub[256 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    struct dp_packet *packet = NULL;
    char *act_str = NULL;
    char *name, *value;
    char *error = NULL;

    *usable_protocols = OFPUTIL_P_ANY;

    *po = (struct ofputil_packet_out) {
        .buffer_id = UINT32_MAX,
    };
    match_init_catchall(&po->flow_metadata);
    match_set_in_port(&po->flow_metadata, OFPP_CONTROLLER);

    act_str = ofp_extract_actions(string);

    while (ofputil_parse_key_value(&string, &name, &value)) {
        if (!*value) {
            error = xasprintf("field %s missing value", name);
            goto out;
        }

        if (!strcmp(name, "in_port")) {
            ofp_port_t in_port;
            if (!ofputil_port_from_string(value, port_map, &in_port)) {
                error = xasprintf("%s is not a valid OpenFlow port", value);
                goto out;
            }
            if (ofp_to_u16(in_port) > ofp_to_u16(OFPP_MAX)
                && in_port != OFPP_LOCAL
                && in_port != OFPP_NONE
                && in_port != OFPP_CONTROLLER) {
                error = xasprintf(
                              "%s is not a valid OpenFlow port for PACKET_OUT",
                              value);
                goto out;
            }
            match_set_in_port(&po->flow_metadata, in_port);
        } else if (!strcmp(name, "packet_type")) {
            char *ns = value;
            char *ns_type = strstr(value, ",");
            if (ns_type) {
                ovs_be32 packet_type;
                *ns_type = '\0';
                packet_type = PACKET_TYPE_BE(strtoul(ns, NULL, 0),
                                             strtoul(++ns_type, NULL, 0));
                match_set_packet_type(&po->flow_metadata, packet_type);
            } else {
                error = xasprintf("%s(%s) can't be interpreted", name, value);
                goto out;
            }
        } else if (!strcmp(name, "packet")) {
            const char *error_msg = eth_from_hex(value, &packet);
            if (error_msg) {
                error = xasprintf("%s: %s", name, error_msg);
                goto out;
            }
        } else {
            const struct mf_field *mf = mf_from_name(name);
            if (!mf) {
                error = xasprintf("unknown keyword %s", name);
                goto out;
            }

            error = ofp_parse_field(mf, value, port_map, &po->flow_metadata,
                                    usable_protocols);
            if (error) {
                goto out;
            }
            if (!mf_is_pipeline_field(mf)) {
                error = xasprintf("%s is not a valid pipeline field "
                                  "for PACKET_OUT", name);
                goto out;
            }
        }
    }

    if (!packet || !dp_packet_size(packet)) {
        error = xstrdup("must specify packet");
        goto out;
    }

    if (act_str) {
        struct ofpact_parse_params pp = {
            .port_map = port_map,
            .table_map = table_map,
            .ofpacts = &ofpacts,
            .usable_protocols = &action_usable_protocols,
        };
        error = ofpacts_parse_actions(act_str, &pp);
        *usable_protocols &= action_usable_protocols;
        if (error) {
            goto out;
        }
    }
    po->ofpacts_len = ofpacts.size;
    po->ofpacts = ofpbuf_steal_data(&ofpacts);

    po->packet_len = dp_packet_size(packet);
    po->packet = dp_packet_steal_data(packet);
out:
    ofpbuf_uninit(&ofpacts);
    dp_packet_delete(packet);
    return error;
}

/* Convert 'str_' (as described in the Packet-Out Syntax section of the
 * ovs-ofctl man page) into 'po' for sending a OFPT_PACKET_OUT message to a
 * switch.  Returns the set of usable protocols in '*usable_protocols'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string.
 * If successful, both 'po->ofpacts' and 'po->packet' must be free()d by
 * the caller. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_packet_out_str(struct ofputil_packet_out *po, const char *str_,
                         const struct ofputil_port_map *port_map,
                         const struct ofputil_table_map *table_map,
                         enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error;

    error = parse_ofp_packet_out_str__(po, string, port_map, table_map,
                                       usable_protocols);
    if (error) {
        po->ofpacts = NULL;
        po->ofpacts_len = 0;
    }

    free(string);
    return error;
}
