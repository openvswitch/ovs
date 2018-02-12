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
#include "openvswitch/ofp-flow.h"
#include <errno.h>
#include "byte-order.h"
#include "flow.h"
#include "nx-match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-group.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/ofp-table.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofp_flow);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Returns an NXT_SET_FLOW_FORMAT message that can be used to set the flow
 * format to 'nxff'.  */
struct ofpbuf *
ofputil_encode_nx_set_flow_format(enum nx_flow_format nxff)
{
    struct nx_set_flow_format *sff;
    struct ofpbuf *msg;

    ovs_assert(ofputil_nx_flow_format_is_valid(nxff));

    msg = ofpraw_alloc(OFPRAW_NXT_SET_FLOW_FORMAT, OFP10_VERSION, 0);
    sff = ofpbuf_put_zeros(msg, sizeof *sff);
    sff->format = htonl(nxff);

    return msg;
}

/* Returns the base protocol if 'flow_format' is a valid NXFF_* value, false
 * otherwise. */
enum ofputil_protocol
ofputil_nx_flow_format_to_protocol(enum nx_flow_format flow_format)
{
    switch (flow_format) {
    case NXFF_OPENFLOW10:
        return OFPUTIL_P_OF10_STD;

    case NXFF_NXM:
        return OFPUTIL_P_OF10_NXM;

    default:
        return 0;
    }
}

/* Returns true if 'flow_format' is a valid NXFF_* value, false otherwise. */
bool
ofputil_nx_flow_format_is_valid(enum nx_flow_format flow_format)
{
    return ofputil_nx_flow_format_to_protocol(flow_format) != 0;
}

/* Returns a string version of 'flow_format', which must be a valid NXFF_*
 * value. */
const char *
ofputil_nx_flow_format_to_string(enum nx_flow_format flow_format)
{
    switch (flow_format) {
    case NXFF_OPENFLOW10:
        return "openflow10";
    case NXFF_NXM:
        return "nxm";
    default:
        OVS_NOT_REACHED();
    }
}

/* Returns an OpenFlow message that can be used to turn the flow_mod_table_id
 * extension on or off (according to 'flow_mod_table_id'). */
struct ofpbuf *
ofputil_make_flow_mod_table_id(bool flow_mod_table_id)
{
    struct nx_flow_mod_table_id *nfmti;
    struct ofpbuf *msg;

    msg = ofpraw_alloc(OFPRAW_NXT_FLOW_MOD_TABLE_ID, OFP10_VERSION, 0);
    nfmti = ofpbuf_put_zeros(msg, sizeof *nfmti);
    nfmti->set = flow_mod_table_id;
    return msg;
}

struct ofputil_flow_mod_flag {
    uint16_t raw_flag;
    enum ofp_version min_version, max_version;
    enum ofputil_flow_mod_flags flag;
};

static const struct ofputil_flow_mod_flag ofputil_flow_mod_flags[] = {
    { OFPFF_SEND_FLOW_REM,   OFP10_VERSION, 0, OFPUTIL_FF_SEND_FLOW_REM },
    { OFPFF_CHECK_OVERLAP,   OFP10_VERSION, 0, OFPUTIL_FF_CHECK_OVERLAP },
    { OFPFF10_EMERG,         OFP10_VERSION, OFP10_VERSION,
      OFPUTIL_FF_EMERG },
    { OFPFF12_RESET_COUNTS,  OFP12_VERSION, 0, OFPUTIL_FF_RESET_COUNTS },
    { OFPFF13_NO_PKT_COUNTS, OFP13_VERSION, 0, OFPUTIL_FF_NO_PKT_COUNTS },
    { OFPFF13_NO_BYT_COUNTS, OFP13_VERSION, 0, OFPUTIL_FF_NO_BYT_COUNTS },
    { 0, 0, 0, 0 },
};

static enum ofperr
ofputil_decode_flow_mod_flags(ovs_be16 raw_flags_,
                              enum ofp_flow_mod_command command,
                              enum ofp_version version,
                              enum ofputil_flow_mod_flags *flagsp)
{
    uint16_t raw_flags = ntohs(raw_flags_);
    const struct ofputil_flow_mod_flag *f;

    *flagsp = 0;
    for (f = ofputil_flow_mod_flags; f->raw_flag; f++) {
        if (raw_flags & f->raw_flag
            && version >= f->min_version
            && (!f->max_version || version <= f->max_version)) {
            raw_flags &= ~f->raw_flag;
            *flagsp |= f->flag;
        }
    }

    /* In OF1.0 and OF1.1, "add" always resets counters, and other commands
     * never do.
     *
     * In OF1.2 and later, OFPFF12_RESET_COUNTS controls whether each command
     * resets counters. */
    if ((version == OFP10_VERSION || version == OFP11_VERSION)
        && command == OFPFC_ADD) {
        *flagsp |= OFPUTIL_FF_RESET_COUNTS;
    }

    return raw_flags ? OFPERR_OFPFMFC_BAD_FLAGS : 0;
}

static ovs_be16
ofputil_encode_flow_mod_flags(enum ofputil_flow_mod_flags flags,
                              enum ofp_version version)
{
    const struct ofputil_flow_mod_flag *f;
    uint16_t raw_flags;

    raw_flags = 0;
    for (f = ofputil_flow_mod_flags; f->raw_flag; f++) {
        if (f->flag & flags
            && version >= f->min_version
            && (!f->max_version || version <= f->max_version)) {
            raw_flags |= f->raw_flag;
        }
    }

    return htons(raw_flags);
}

/* Converts an OFPT_FLOW_MOD or NXT_FLOW_MOD message 'oh' into an abstract
 * flow_mod in 'fm'.  Returns 0 if successful, otherwise an OpenFlow error
 * code.
 *
 * Uses 'ofpacts' to store the abstract OFPACT_* version of 'oh''s actions.
 * The caller must initialize 'ofpacts' and retains ownership of it.
 * 'fm->ofpacts' will point into the 'ofpacts' buffer.
 *
 * Does not validate the flow_mod actions.  The caller should do that, with
 * ofpacts_check(). */
enum ofperr
ofputil_decode_flow_mod(struct ofputil_flow_mod *fm,
                        const struct ofp_header *oh,
                        enum ofputil_protocol protocol,
                        const struct tun_table *tun_table,
                        const struct vl_mff_map *vl_mff_map,
                        struct ofpbuf *ofpacts,
                        ofp_port_t max_port, uint8_t max_table)
{
    ovs_be16 raw_flags;
    enum ofperr error;
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT11_FLOW_MOD) {
        /* Standard OpenFlow 1.1+ flow_mod. */
        const struct ofp11_flow_mod *ofm;

        ofm = ofpbuf_pull(&b, sizeof *ofm);

        error = ofputil_pull_ofp11_match(&b, tun_table, vl_mff_map, &fm->match,
                                         NULL);
        if (error) {
            return error;
        }

        /* Translate the message. */
        fm->priority = ntohs(ofm->priority);
        if (ofm->command == OFPFC_ADD
            || (oh->version == OFP11_VERSION
                && (ofm->command == OFPFC_MODIFY ||
                    ofm->command == OFPFC_MODIFY_STRICT)
                && ofm->cookie_mask == htonll(0))) {
            /* In OpenFlow 1.1 only, a "modify" or "modify-strict" that does
             * not match on the cookie is treated as an "add" if there is no
             * match. */
            fm->cookie = htonll(0);
            fm->cookie_mask = htonll(0);
            fm->new_cookie = ofm->cookie;
        } else {
            fm->cookie = ofm->cookie;
            fm->cookie_mask = ofm->cookie_mask;
            fm->new_cookie = OVS_BE64_MAX;
        }
        fm->modify_cookie = false;
        fm->command = ofm->command;

        /* Get table ID.
         *
         * OF1.1 entirely forbids table_id == OFPTT_ALL.
         * OF1.2+ allows table_id == OFPTT_ALL only for deletes. */
        fm->table_id = ofm->table_id;
        if (fm->table_id == OFPTT_ALL
            && (oh->version == OFP11_VERSION
                || (ofm->command != OFPFC_DELETE &&
                    ofm->command != OFPFC_DELETE_STRICT))) {
            return OFPERR_OFPFMFC_BAD_TABLE_ID;
        }

        fm->idle_timeout = ntohs(ofm->idle_timeout);
        fm->hard_timeout = ntohs(ofm->hard_timeout);
        if (oh->version >= OFP14_VERSION && ofm->command == OFPFC_ADD) {
            fm->importance = ntohs(ofm->importance);
        } else {
            fm->importance = 0;
        }
        fm->buffer_id = ntohl(ofm->buffer_id);
        error = ofputil_port_from_ofp11(ofm->out_port, &fm->out_port);
        if (error) {
            return error;
        }

        fm->out_group = (ofm->command == OFPFC_DELETE ||
                         ofm->command == OFPFC_DELETE_STRICT
                         ? ntohl(ofm->out_group)
                         : OFPG_ANY);
        raw_flags = ofm->flags;
    } else {
        uint16_t command;

        if (raw == OFPRAW_OFPT10_FLOW_MOD) {
            /* Standard OpenFlow 1.0 flow_mod. */
            const struct ofp10_flow_mod *ofm;

            /* Get the ofp10_flow_mod. */
            ofm = ofpbuf_pull(&b, sizeof *ofm);

            /* Translate the rule. */
            ofputil_match_from_ofp10_match(&ofm->match, &fm->match);
            ofputil_normalize_match(&fm->match);

            /* OpenFlow 1.0 says that exact-match rules have to have the
             * highest possible priority. */
            fm->priority = (ofm->match.wildcards & htonl(OFPFW10_ALL)
                            ? ntohs(ofm->priority)
                            : UINT16_MAX);

            /* Translate the message. */
            command = ntohs(ofm->command);
            fm->cookie = htonll(0);
            fm->cookie_mask = htonll(0);
            fm->new_cookie = ofm->cookie;
            fm->idle_timeout = ntohs(ofm->idle_timeout);
            fm->hard_timeout = ntohs(ofm->hard_timeout);
            fm->importance = 0;
            fm->buffer_id = ntohl(ofm->buffer_id);
            fm->out_port = u16_to_ofp(ntohs(ofm->out_port));
            fm->out_group = OFPG_ANY;
            raw_flags = ofm->flags;
        } else if (raw == OFPRAW_NXT_FLOW_MOD) {
            /* Nicira extended flow_mod. */
            const struct nx_flow_mod *nfm;

            /* Dissect the message. */
            nfm = ofpbuf_pull(&b, sizeof *nfm);
            error = nx_pull_match(&b, ntohs(nfm->match_len),
                                  &fm->match, &fm->cookie, &fm->cookie_mask,
                                  false, tun_table, vl_mff_map);
            if (error) {
                return error;
            }

            /* Translate the message. */
            command = ntohs(nfm->command);
            if ((command & 0xff) == OFPFC_ADD && fm->cookie_mask) {
                /* Flow additions may only set a new cookie, not match an
                 * existing cookie. */
                return OFPERR_NXBRC_NXM_INVALID;
            }
            fm->priority = ntohs(nfm->priority);
            fm->new_cookie = nfm->cookie;
            fm->idle_timeout = ntohs(nfm->idle_timeout);
            fm->hard_timeout = ntohs(nfm->hard_timeout);
            fm->importance = 0;
            fm->buffer_id = ntohl(nfm->buffer_id);
            fm->out_port = u16_to_ofp(ntohs(nfm->out_port));
            fm->out_group = OFPG_ANY;
            raw_flags = nfm->flags;
        } else {
            OVS_NOT_REACHED();
        }

        fm->modify_cookie = fm->new_cookie != OVS_BE64_MAX;
        if (protocol & OFPUTIL_P_TID) {
            fm->command = command & 0xff;
            fm->table_id = command >> 8;
        } else {
            if (command > 0xff) {
                VLOG_WARN_RL(&rl, "flow_mod has explicit table_id "
                             "but flow_mod_table_id extension is not enabled");
            }
            fm->command = command;
            fm->table_id = 0xff;
        }
    }

    /* Check for mismatched conntrack original direction tuple address fields
     * w.r.t. the IP version of the match. */
    if (((fm->match.wc.masks.ct_nw_src || fm->match.wc.masks.ct_nw_dst)
         && fm->match.flow.dl_type != htons(ETH_TYPE_IP))
        || ((ipv6_addr_is_set(&fm->match.wc.masks.ct_ipv6_src)
             || ipv6_addr_is_set(&fm->match.wc.masks.ct_ipv6_dst))
            && fm->match.flow.dl_type != htons(ETH_TYPE_IPV6))) {
        return OFPERR_OFPBAC_MATCH_INCONSISTENT;
    }

    if (fm->command > OFPFC_DELETE_STRICT) {
        return OFPERR_OFPFMFC_BAD_COMMAND;
    }

    fm->ofpacts_tlv_bitmap = 0;
    error = ofpacts_pull_openflow_instructions(&b, b.size, oh->version,
                                               vl_mff_map,
                                               &fm->ofpacts_tlv_bitmap,
                                               ofpacts);
    if (error) {
        return error;
    }
    fm->ofpacts = ofpacts->data;
    fm->ofpacts_len = ofpacts->size;

    error = ofputil_decode_flow_mod_flags(raw_flags, fm->command,
                                          oh->version, &fm->flags);
    if (error) {
        return error;
    }

    if (fm->flags & OFPUTIL_FF_EMERG) {
        /* We do not support the OpenFlow 1.0 emergency flow cache, which
         * is not required in OpenFlow 1.0.1 and removed from OpenFlow 1.1.
         *
         * OpenFlow 1.0 specifies the error code to use when idle_timeout
         * or hard_timeout is nonzero.  Otherwise, there is no good error
         * code, so just state that the flow table is full. */
        return (fm->hard_timeout || fm->idle_timeout
                ? OFPERR_OFPFMFC_BAD_EMERG_TIMEOUT
                : OFPERR_OFPFMFC_TABLE_FULL);
    }

    return ofpacts_check_consistency(fm->ofpacts, fm->ofpacts_len,
                                     &fm->match, max_port,
                                     fm->table_id, max_table, protocol);
}

static ovs_be16
ofputil_tid_command(const struct ofputil_flow_mod *fm,
                    enum ofputil_protocol protocol)
{
    return htons(protocol & OFPUTIL_P_TID
                 ? (fm->command & 0xff) | (fm->table_id << 8)
                 : fm->command);
}

/* Converts 'fm' into an OFPT_FLOW_MOD or NXT_FLOW_MOD message according to
 * 'protocol' and returns the message. */
struct ofpbuf *
ofputil_encode_flow_mod(const struct ofputil_flow_mod *fm,
                        enum ofputil_protocol protocol)
{
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);
    ovs_be16 raw_flags = ofputil_encode_flow_mod_flags(fm->flags, version);
    struct ofpbuf *msg;

    switch (protocol) {
    case OFPUTIL_P_OF11_STD:
    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM:
    case OFPUTIL_P_OF14_OXM:
    case OFPUTIL_P_OF15_OXM:
    case OFPUTIL_P_OF16_OXM: {
        struct ofp11_flow_mod *ofm;
        int tailroom;

        tailroom = ofputil_match_typical_len(protocol) + fm->ofpacts_len;
        msg = ofpraw_alloc(OFPRAW_OFPT11_FLOW_MOD, version, tailroom);
        ofm = ofpbuf_put_zeros(msg, sizeof *ofm);
        if ((protocol == OFPUTIL_P_OF11_STD
             && (fm->command == OFPFC_MODIFY ||
                 fm->command == OFPFC_MODIFY_STRICT)
             && fm->cookie_mask == htonll(0))
            || fm->command == OFPFC_ADD) {
            ofm->cookie = fm->new_cookie;
        } else {
            ofm->cookie = fm->cookie & fm->cookie_mask;
        }
        ofm->cookie_mask = fm->cookie_mask;
        if (fm->table_id != OFPTT_ALL
            || (protocol != OFPUTIL_P_OF11_STD
                && (fm->command == OFPFC_DELETE ||
                    fm->command == OFPFC_DELETE_STRICT))) {
            ofm->table_id = fm->table_id;
        } else {
            ofm->table_id = 0;
        }
        ofm->command = fm->command;
        ofm->idle_timeout = htons(fm->idle_timeout);
        ofm->hard_timeout = htons(fm->hard_timeout);
        ofm->priority = htons(fm->priority);
        ofm->buffer_id = htonl(fm->buffer_id);
        ofm->out_port = ofputil_port_to_ofp11(fm->out_port);
        ofm->out_group = htonl(fm->out_group);
        ofm->flags = raw_flags;
        if (version >= OFP14_VERSION && fm->command == OFPFC_ADD) {
            ofm->importance = htons(fm->importance);
        } else {
            ofm->importance = 0;
        }
        ofputil_put_ofp11_match(msg, &fm->match, protocol);
        ofpacts_put_openflow_instructions(fm->ofpacts, fm->ofpacts_len, msg,
                                          version);
        break;
    }

    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID: {
        struct ofp10_flow_mod *ofm;

        msg = ofpraw_alloc(OFPRAW_OFPT10_FLOW_MOD, OFP10_VERSION,
                           fm->ofpacts_len);
        ofm = ofpbuf_put_zeros(msg, sizeof *ofm);
        ofputil_match_to_ofp10_match(&fm->match, &ofm->match);
        ofm->cookie = fm->new_cookie;
        ofm->command = ofputil_tid_command(fm, protocol);
        ofm->idle_timeout = htons(fm->idle_timeout);
        ofm->hard_timeout = htons(fm->hard_timeout);
        ofm->priority = htons(fm->priority);
        ofm->buffer_id = htonl(fm->buffer_id);
        ofm->out_port = htons(ofp_to_u16(fm->out_port));
        ofm->flags = raw_flags;
        ofpacts_put_openflow_actions(fm->ofpacts, fm->ofpacts_len, msg,
                                     version);
        break;
    }

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID: {
        struct nx_flow_mod *nfm;
        int match_len;

        msg = ofpraw_alloc(OFPRAW_NXT_FLOW_MOD, OFP10_VERSION,
                           NXM_TYPICAL_LEN + fm->ofpacts_len);
        nfm = ofpbuf_put_zeros(msg, sizeof *nfm);
        nfm->command = ofputil_tid_command(fm, protocol);
        nfm->cookie = fm->new_cookie;
        match_len = nx_put_match(msg, &fm->match, fm->cookie, fm->cookie_mask);
        nfm = msg->msg;
        nfm->idle_timeout = htons(fm->idle_timeout);
        nfm->hard_timeout = htons(fm->hard_timeout);
        nfm->priority = htons(fm->priority);
        nfm->buffer_id = htonl(fm->buffer_id);
        nfm->out_port = htons(ofp_to_u16(fm->out_port));
        nfm->flags = raw_flags;
        nfm->match_len = htons(match_len);
        ofpacts_put_openflow_actions(fm->ofpacts, fm->ofpacts_len, msg,
                                     version);
        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    ofpmsg_update_length(msg);
    return msg;
}

static enum ofperr
ofputil_decode_ofpst10_flow_request(struct ofputil_flow_stats_request *fsr,
                                    const struct ofp10_flow_stats_request *ofsr,
                                    bool aggregate)
{
    fsr->aggregate = aggregate;
    ofputil_match_from_ofp10_match(&ofsr->match, &fsr->match);
    fsr->out_port = u16_to_ofp(ntohs(ofsr->out_port));
    fsr->out_group = OFPG_ANY;
    fsr->table_id = ofsr->table_id;
    fsr->cookie = fsr->cookie_mask = htonll(0);

    return 0;
}

static enum ofperr
ofputil_decode_ofpst11_flow_request(struct ofputil_flow_stats_request *fsr,
                                    struct ofpbuf *b, bool aggregate,
                                    const struct tun_table *tun_table,
                                    const struct vl_mff_map *vl_mff_map)
{
    const struct ofp11_flow_stats_request *ofsr;
    enum ofperr error;

    ofsr = ofpbuf_pull(b, sizeof *ofsr);
    fsr->aggregate = aggregate;
    fsr->table_id = ofsr->table_id;
    error = ofputil_port_from_ofp11(ofsr->out_port, &fsr->out_port);
    if (error) {
        return error;
    }
    fsr->out_group = ntohl(ofsr->out_group);
    fsr->cookie = ofsr->cookie;
    fsr->cookie_mask = ofsr->cookie_mask;
    error = ofputil_pull_ofp11_match(b, tun_table, vl_mff_map, &fsr->match,
                                     NULL);
    if (error) {
        return error;
    }

    return 0;
}

static enum ofperr
ofputil_decode_nxst_flow_request(struct ofputil_flow_stats_request *fsr,
                                 struct ofpbuf *b, bool aggregate,
                                 const struct tun_table *tun_table,
                                 const struct vl_mff_map *vl_mff_map)
{
    const struct nx_flow_stats_request *nfsr;
    enum ofperr error;

    nfsr = ofpbuf_pull(b, sizeof *nfsr);
    error = nx_pull_match(b, ntohs(nfsr->match_len), &fsr->match,
                          &fsr->cookie, &fsr->cookie_mask, false, tun_table,
                          vl_mff_map);
    if (error) {
        return error;
    }
    if (b->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    fsr->aggregate = aggregate;
    fsr->out_port = u16_to_ofp(ntohs(nfsr->out_port));
    fsr->out_group = OFPG_ANY;
    fsr->table_id = nfsr->table_id;

    return 0;
}

/* Converts an OFPST_FLOW, OFPST_AGGREGATE, NXST_FLOW, or NXST_AGGREGATE
 * request 'oh', into an abstract flow_stats_request in 'fsr'.  Returns 0 if
 * successful, otherwise an OpenFlow error code.
 *
 * 'vl_mff_map' is an optional parameter that is used to validate the length
 * of variable length mf_fields in 'match'. If it is not provided, the
 * default mf_fields with maximum length will be used. */
enum ofperr
ofputil_decode_flow_stats_request(struct ofputil_flow_stats_request *fsr,
                                  const struct ofp_header *oh,
                                  const struct tun_table *tun_table,
                                  const struct vl_mff_map *vl_mff_map)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    switch ((int) raw) {
    case OFPRAW_OFPST10_FLOW_REQUEST:
        return ofputil_decode_ofpst10_flow_request(fsr, b.data, false);

    case OFPRAW_OFPST10_AGGREGATE_REQUEST:
        return ofputil_decode_ofpst10_flow_request(fsr, b.data, true);

    case OFPRAW_OFPST11_FLOW_REQUEST:
        return ofputil_decode_ofpst11_flow_request(fsr, &b, false, tun_table,
                                                   vl_mff_map);

    case OFPRAW_OFPST11_AGGREGATE_REQUEST:
        return ofputil_decode_ofpst11_flow_request(fsr, &b, true, tun_table,
                                                   vl_mff_map);

    case OFPRAW_NXST_FLOW_REQUEST:
        return ofputil_decode_nxst_flow_request(fsr, &b, false, tun_table,
                                                vl_mff_map);

    case OFPRAW_NXST_AGGREGATE_REQUEST:
        return ofputil_decode_nxst_flow_request(fsr, &b, true, tun_table,
                                                vl_mff_map);

    default:
        /* Hey, the caller lied. */
        OVS_NOT_REACHED();
    }
}

/* Converts abstract flow_stats_request 'fsr' into an OFPST_FLOW,
 * OFPST_AGGREGATE, NXST_FLOW, or NXST_AGGREGATE request 'oh' according to
 * 'protocol', and returns the message. */
struct ofpbuf *
ofputil_encode_flow_stats_request(const struct ofputil_flow_stats_request *fsr,
                                  enum ofputil_protocol protocol)
{
    struct ofpbuf *msg;
    enum ofpraw raw;

    switch (protocol) {
    case OFPUTIL_P_OF11_STD:
    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM:
    case OFPUTIL_P_OF14_OXM:
    case OFPUTIL_P_OF15_OXM:
    case OFPUTIL_P_OF16_OXM: {
        struct ofp11_flow_stats_request *ofsr;

        raw = (fsr->aggregate
               ? OFPRAW_OFPST11_AGGREGATE_REQUEST
               : OFPRAW_OFPST11_FLOW_REQUEST);
        msg = ofpraw_alloc(raw, ofputil_protocol_to_ofp_version(protocol),
                           ofputil_match_typical_len(protocol));
        ofsr = ofpbuf_put_zeros(msg, sizeof *ofsr);
        ofsr->table_id = fsr->table_id;
        ofsr->out_port = ofputil_port_to_ofp11(fsr->out_port);
        ofsr->out_group = htonl(fsr->out_group);
        ofsr->cookie = fsr->cookie;
        ofsr->cookie_mask = fsr->cookie_mask;
        ofputil_put_ofp11_match(msg, &fsr->match, protocol);
        break;
    }

    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID: {
        struct ofp10_flow_stats_request *ofsr;

        raw = (fsr->aggregate
               ? OFPRAW_OFPST10_AGGREGATE_REQUEST
               : OFPRAW_OFPST10_FLOW_REQUEST);
        msg = ofpraw_alloc(raw, OFP10_VERSION, 0);
        ofsr = ofpbuf_put_zeros(msg, sizeof *ofsr);
        ofputil_match_to_ofp10_match(&fsr->match, &ofsr->match);
        ofsr->table_id = fsr->table_id;
        ofsr->out_port = htons(ofp_to_u16(fsr->out_port));
        break;
    }

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID: {
        struct nx_flow_stats_request *nfsr;
        int match_len;

        raw = (fsr->aggregate
               ? OFPRAW_NXST_AGGREGATE_REQUEST
               : OFPRAW_NXST_FLOW_REQUEST);
        msg = ofpraw_alloc(raw, OFP10_VERSION, NXM_TYPICAL_LEN);
        ofpbuf_put_zeros(msg, sizeof *nfsr);
        match_len = nx_put_match(msg, &fsr->match,
                                 fsr->cookie, fsr->cookie_mask);

        nfsr = msg->msg;
        nfsr->out_port = htons(ofp_to_u16(fsr->out_port));
        nfsr->match_len = htons(match_len);
        nfsr->table_id = fsr->table_id;
        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    return msg;
}

char * OVS_WARN_UNUSED_RESULT
parse_ofp_flow_stats_request_str(struct ofputil_flow_stats_request *fsr,
                                 bool aggregate, const char *string,
                                 const struct ofputil_port_map *port_map,
                                 const struct ofputil_table_map *table_map,
                                 enum ofputil_protocol *usable_protocols)
{
    struct ofputil_flow_mod fm;
    char *error;

    error = parse_ofp_str(&fm, -1, string, port_map, table_map,
                          usable_protocols);
    if (error) {
        return error;
    }

    /* Special table ID support not required for stats requests. */
    if (*usable_protocols & OFPUTIL_P_OF10_STD_TID) {
        *usable_protocols |= OFPUTIL_P_OF10_STD;
    }
    if (*usable_protocols & OFPUTIL_P_OF10_NXM_TID) {
        *usable_protocols |= OFPUTIL_P_OF10_NXM;
    }

    fsr->aggregate = aggregate;
    fsr->cookie = fm.cookie;
    fsr->cookie_mask = fm.cookie_mask;
    fsr->match = fm.match;
    fsr->out_port = fm.out_port;
    fsr->out_group = fm.out_group;
    fsr->table_id = fm.table_id;
    return NULL;
}

/* Converts an OFPST_FLOW or NXST_FLOW reply in 'msg' into an abstract
 * ofputil_flow_stats in 'fs'.
 *
 * Multiple OFPST_FLOW or NXST_FLOW replies can be packed into a single
 * OpenFlow message.  Calling this function multiple times for a single 'msg'
 * iterates through the replies.  The caller must initially leave 'msg''s layer
 * pointers null and not modify them between calls.
 *
 * Most switches don't send the values needed to populate fs->idle_age and
 * fs->hard_age, so those members will usually be set to 0.  If the switch from
 * which 'msg' originated is known to implement NXT_FLOW_AGE, then pass
 * 'flow_age_extension' as true so that the contents of 'msg' determine the
 * 'idle_age' and 'hard_age' members in 'fs'.
 *
 * Uses 'ofpacts' to store the abstract OFPACT_* version of the flow stats
 * reply's actions.  The caller must initialize 'ofpacts' and retains ownership
 * of it.  'fs->ofpacts' will point into the 'ofpacts' buffer.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise an OFPERR_* value. */
int
ofputil_decode_flow_stats_reply(struct ofputil_flow_stats *fs,
                                struct ofpbuf *msg,
                                bool flow_age_extension,
                                struct ofpbuf *ofpacts)
{
    const struct ofp_header *oh;
    size_t instructions_len;
    enum ofperr error;
    enum ofpraw raw;

    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }
    oh = msg->header;

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_OFPST11_FLOW_REPLY
               || raw == OFPRAW_OFPST13_FLOW_REPLY) {
        const struct ofp11_flow_stats *ofs;
        size_t length;
        uint16_t padded_match_len;

        ofs = ofpbuf_try_pull(msg, sizeof *ofs);
        if (!ofs) {
            VLOG_WARN_RL(&rl, "OFPST_FLOW reply has %"PRIu32" leftover "
                         "bytes at end", msg->size);
            return OFPERR_OFPBRC_BAD_LEN;
        }

        length = ntohs(ofs->length);
        if (length < sizeof *ofs) {
            VLOG_WARN_RL(&rl, "OFPST_FLOW reply claims invalid "
                         "length %"PRIuSIZE, length);
            return OFPERR_OFPBRC_BAD_LEN;
        }

        error = ofputil_pull_ofp11_match(msg, NULL, NULL, &fs->match,
                                         &padded_match_len);
        if (error) {
            VLOG_WARN_RL(&rl, "OFPST_FLOW reply bad match");
            return error;
        }
        instructions_len = length - sizeof *ofs - padded_match_len;

        fs->priority = ntohs(ofs->priority);
        fs->table_id = ofs->table_id;
        fs->duration_sec = ntohl(ofs->duration_sec);
        fs->duration_nsec = ntohl(ofs->duration_nsec);
        fs->idle_timeout = ntohs(ofs->idle_timeout);
        fs->hard_timeout = ntohs(ofs->hard_timeout);
        if (oh->version >= OFP14_VERSION) {
            fs->importance = ntohs(ofs->importance);
        } else {
            fs->importance = 0;
        }
        if (raw == OFPRAW_OFPST13_FLOW_REPLY) {
            error = ofputil_decode_flow_mod_flags(ofs->flags, -1, oh->version,
                                                  &fs->flags);
            if (error) {
                return error;
            }
        } else {
            fs->flags = 0;
        }
        fs->idle_age = -1;
        fs->hard_age = -1;
        fs->cookie = ofs->cookie;
        fs->packet_count = ntohll(ofs->packet_count);
        fs->byte_count = ntohll(ofs->byte_count);
    } else if (raw == OFPRAW_OFPST10_FLOW_REPLY) {
        const struct ofp10_flow_stats *ofs;
        size_t length;

        ofs = ofpbuf_try_pull(msg, sizeof *ofs);
        if (!ofs) {
            VLOG_WARN_RL(&rl, "OFPST_FLOW reply has %"PRIu32" leftover "
                         "bytes at end", msg->size);
            return OFPERR_OFPBRC_BAD_LEN;
        }

        length = ntohs(ofs->length);
        if (length < sizeof *ofs) {
            VLOG_WARN_RL(&rl, "OFPST_FLOW reply claims invalid "
                         "length %"PRIuSIZE, length);
            return OFPERR_OFPBRC_BAD_LEN;
        }
        instructions_len = length - sizeof *ofs;

        fs->cookie = get_32aligned_be64(&ofs->cookie);
        ofputil_match_from_ofp10_match(&ofs->match, &fs->match);
        fs->priority = ntohs(ofs->priority);
        fs->table_id = ofs->table_id;
        fs->duration_sec = ntohl(ofs->duration_sec);
        fs->duration_nsec = ntohl(ofs->duration_nsec);
        fs->idle_timeout = ntohs(ofs->idle_timeout);
        fs->hard_timeout = ntohs(ofs->hard_timeout);
        fs->importance = 0;
        fs->idle_age = -1;
        fs->hard_age = -1;
        fs->packet_count = ntohll(get_32aligned_be64(&ofs->packet_count));
        fs->byte_count = ntohll(get_32aligned_be64(&ofs->byte_count));
        fs->flags = 0;
    } else if (raw == OFPRAW_NXST_FLOW_REPLY) {
        const struct nx_flow_stats *nfs;
        size_t match_len, length;

        nfs = ofpbuf_try_pull(msg, sizeof *nfs);
        if (!nfs) {
            VLOG_WARN_RL(&rl, "NXST_FLOW reply has %"PRIu32" leftover "
                         "bytes at end", msg->size);
            return OFPERR_OFPBRC_BAD_LEN;
        }

        length = ntohs(nfs->length);
        match_len = ntohs(nfs->match_len);
        if (length < sizeof *nfs + ROUND_UP(match_len, 8)) {
            VLOG_WARN_RL(&rl, "NXST_FLOW reply with match_len=%"PRIuSIZE" "
                         "claims invalid length %"PRIuSIZE, match_len, length);
            return OFPERR_OFPBRC_BAD_LEN;
        }
        error = nx_pull_match(msg, match_len, &fs->match, NULL, NULL, false,
                              NULL, NULL);
        if (error) {
            return error;
        }
        instructions_len = length - sizeof *nfs - ROUND_UP(match_len, 8);

        fs->cookie = nfs->cookie;
        fs->table_id = nfs->table_id;
        fs->duration_sec = ntohl(nfs->duration_sec);
        fs->duration_nsec = ntohl(nfs->duration_nsec);
        fs->priority = ntohs(nfs->priority);
        fs->idle_timeout = ntohs(nfs->idle_timeout);
        fs->hard_timeout = ntohs(nfs->hard_timeout);
        fs->importance = 0;
        fs->idle_age = -1;
        fs->hard_age = -1;
        if (flow_age_extension) {
            if (nfs->idle_age) {
                fs->idle_age = ntohs(nfs->idle_age) - 1;
            }
            if (nfs->hard_age) {
                fs->hard_age = ntohs(nfs->hard_age) - 1;
            }
        }
        fs->packet_count = ntohll(nfs->packet_count);
        fs->byte_count = ntohll(nfs->byte_count);
        fs->flags = 0;
    } else {
        OVS_NOT_REACHED();
    }

    error = ofpacts_pull_openflow_instructions(msg, instructions_len,
                                               oh->version, NULL, NULL,
                                               ofpacts);
    if (error) {
        VLOG_WARN_RL(&rl, "OFPST_FLOW reply bad instructions");
        return error;
    }
    fs->ofpacts = ofpacts->data;
    fs->ofpacts_len = ofpacts->size;

    return 0;
}

/* Returns 'count' unchanged except that UINT64_MAX becomes 0.
 *
 * We use this in situations where OVS internally uses UINT64_MAX to mean
 * "value unknown" but OpenFlow 1.0 does not define any unknown value. */
static uint64_t
unknown_to_zero(uint64_t count)
{
    return count != UINT64_MAX ? count : 0;
}

/* Appends an OFPST_FLOW or NXST_FLOW reply that contains the data in 'fs' to
 * those already present in the list of ofpbufs in 'replies'.  'replies' should
 * have been initialized with ofpmp_init(). */
void
ofputil_append_flow_stats_reply(const struct ofputil_flow_stats *fs,
                                struct ovs_list *replies,
                                const struct tun_table *tun_table)
{
    struct ofputil_flow_stats *fs_ = CONST_CAST(struct ofputil_flow_stats *,
                                                fs);
    const struct tun_table *orig_tun_table;
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_ofs = reply->size;
    enum ofp_version version = ofpmp_version(replies);
    enum ofpraw raw = ofpmp_decode_raw(replies);

    orig_tun_table = fs->match.flow.tunnel.metadata.tab;
    fs_->match.flow.tunnel.metadata.tab = tun_table;

    if (raw == OFPRAW_OFPST11_FLOW_REPLY || raw == OFPRAW_OFPST13_FLOW_REPLY) {
        struct ofp11_flow_stats *ofs;

        ofpbuf_put_uninit(reply, sizeof *ofs);
        oxm_put_match(reply, &fs->match, version);
        ofpacts_put_openflow_instructions(fs->ofpacts, fs->ofpacts_len, reply,
                                          version);

        ofs = ofpbuf_at_assert(reply, start_ofs, sizeof *ofs);
        ofs->length = htons(reply->size - start_ofs);
        ofs->table_id = fs->table_id;
        ofs->pad = 0;
        ofs->duration_sec = htonl(fs->duration_sec);
        ofs->duration_nsec = htonl(fs->duration_nsec);
        ofs->priority = htons(fs->priority);
        ofs->idle_timeout = htons(fs->idle_timeout);
        ofs->hard_timeout = htons(fs->hard_timeout);
        if (version >= OFP14_VERSION) {
            ofs->importance = htons(fs->importance);
        } else {
            ofs->importance = 0;
        }
        if (raw == OFPRAW_OFPST13_FLOW_REPLY) {
            ofs->flags = ofputil_encode_flow_mod_flags(fs->flags, version);
        } else {
            ofs->flags = 0;
        }
        memset(ofs->pad2, 0, sizeof ofs->pad2);
        ofs->cookie = fs->cookie;
        ofs->packet_count = htonll(unknown_to_zero(fs->packet_count));
        ofs->byte_count = htonll(unknown_to_zero(fs->byte_count));
    } else if (raw == OFPRAW_OFPST10_FLOW_REPLY) {
        struct ofp10_flow_stats *ofs;

        ofpbuf_put_uninit(reply, sizeof *ofs);
        ofpacts_put_openflow_actions(fs->ofpacts, fs->ofpacts_len, reply,
                                     version);
        ofs = ofpbuf_at_assert(reply, start_ofs, sizeof *ofs);
        ofs->length = htons(reply->size - start_ofs);
        ofs->table_id = fs->table_id;
        ofs->pad = 0;
        ofputil_match_to_ofp10_match(&fs->match, &ofs->match);
        ofs->duration_sec = htonl(fs->duration_sec);
        ofs->duration_nsec = htonl(fs->duration_nsec);
        ofs->priority = htons(fs->priority);
        ofs->idle_timeout = htons(fs->idle_timeout);
        ofs->hard_timeout = htons(fs->hard_timeout);
        memset(ofs->pad2, 0, sizeof ofs->pad2);
        put_32aligned_be64(&ofs->cookie, fs->cookie);
        put_32aligned_be64(&ofs->packet_count,
                           htonll(unknown_to_zero(fs->packet_count)));
        put_32aligned_be64(&ofs->byte_count,
                           htonll(unknown_to_zero(fs->byte_count)));
    } else if (raw == OFPRAW_NXST_FLOW_REPLY) {
        struct nx_flow_stats *nfs;
        int match_len;

        ofpbuf_put_uninit(reply, sizeof *nfs);
        match_len = nx_put_match(reply, &fs->match, 0, 0);
        ofpacts_put_openflow_actions(fs->ofpacts, fs->ofpacts_len, reply,
                                     version);
        nfs = ofpbuf_at_assert(reply, start_ofs, sizeof *nfs);
        nfs->length = htons(reply->size - start_ofs);
        nfs->table_id = fs->table_id;
        nfs->pad = 0;
        nfs->duration_sec = htonl(fs->duration_sec);
        nfs->duration_nsec = htonl(fs->duration_nsec);
        nfs->priority = htons(fs->priority);
        nfs->idle_timeout = htons(fs->idle_timeout);
        nfs->hard_timeout = htons(fs->hard_timeout);
        nfs->idle_age = htons(fs->idle_age < 0 ? 0
                              : fs->idle_age < UINT16_MAX ? fs->idle_age + 1
                              : UINT16_MAX);
        nfs->hard_age = htons(fs->hard_age < 0 ? 0
                              : fs->hard_age < UINT16_MAX ? fs->hard_age + 1
                              : UINT16_MAX);
        nfs->match_len = htons(match_len);
        nfs->cookie = fs->cookie;
        nfs->packet_count = htonll(fs->packet_count);
        nfs->byte_count = htonll(fs->byte_count);
    } else {
        OVS_NOT_REACHED();
    }

    ofpmp_postappend(replies, start_ofs);
    fs_->match.flow.tunnel.metadata.tab = orig_tun_table;
}

/* Converts abstract ofputil_aggregate_stats 'stats' into an OFPST_AGGREGATE or
 * NXST_AGGREGATE reply matching 'request', and returns the message. */
struct ofpbuf *
ofputil_encode_aggregate_stats_reply(
    const struct ofputil_aggregate_stats *stats,
    const struct ofp_header *request)
{
    struct ofp_aggregate_stats_reply *asr;
    uint64_t packet_count;
    uint64_t byte_count;
    struct ofpbuf *msg;
    enum ofpraw raw;

    ofpraw_decode(&raw, request);
    if (raw == OFPRAW_OFPST10_AGGREGATE_REQUEST) {
        packet_count = unknown_to_zero(stats->packet_count);
        byte_count = unknown_to_zero(stats->byte_count);
    } else {
        packet_count = stats->packet_count;
        byte_count = stats->byte_count;
    }

    msg = ofpraw_alloc_stats_reply(request, 0);
    asr = ofpbuf_put_zeros(msg, sizeof *asr);
    put_32aligned_be64(&asr->packet_count, htonll(packet_count));
    put_32aligned_be64(&asr->byte_count, htonll(byte_count));
    asr->flow_count = htonl(stats->flow_count);

    return msg;
}

enum ofperr
ofputil_decode_aggregate_stats_reply(struct ofputil_aggregate_stats *stats,
                                     const struct ofp_header *reply)
{
    struct ofpbuf msg = ofpbuf_const_initializer(reply, ntohs(reply->length));
    ofpraw_pull_assert(&msg);

    struct ofp_aggregate_stats_reply *asr = msg.msg;
    stats->packet_count = ntohll(get_32aligned_be64(&asr->packet_count));
    stats->byte_count = ntohll(get_32aligned_be64(&asr->byte_count));
    stats->flow_count = ntohl(asr->flow_count);

    return 0;
}


/* Parses 'str_value' as the value of subfield 'name', and updates
 * 'match' appropriately.  Restricts the set of usable protocols to ones
 * supporting the parsed field.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
parse_subfield(const char *name, const char *str_value, struct match *match,
               enum ofputil_protocol *usable_protocols)
{
    struct mf_subfield sf;
    char *error;

    error = mf_parse_subfield(&sf, name);
    if (!error) {
        union mf_value val;
        char *tail;
        if (parse_int_string(str_value, (uint8_t *)&val, sf.field->n_bytes,
                             &tail) || *tail != 0) {
            return xasprintf("%s: cannot parse integer value: %s", name,
                             str_value);
        }
        if (!bitwise_is_all_zeros(&val, sf.field->n_bytes, sf.n_bits,
                                  sf.field->n_bytes * 8 - sf.n_bits)) {
            struct ds ds;

            ds_init(&ds);
            mf_format(sf.field, &val, NULL, NULL, &ds);
            error = xasprintf("%s: value %s does not fit into %d bits",
                              name, ds_cstr(&ds), sf.n_bits);
            ds_destroy(&ds);
            return error;
        }

        const struct mf_field *field = sf.field;
        union mf_value value, mask;
        unsigned int size = field->n_bytes;

        mf_get(field, match, &value, &mask);
        bitwise_copy(&val, size, 0, &value, size, sf.ofs, sf.n_bits);
        bitwise_one (               &mask,  size, sf.ofs, sf.n_bits);
        *usable_protocols &= mf_set(field, &value, &mask, match, &error);

        match_add_ethernet_prereq(match, sf.field);
    }
    return error;
}

static char * OVS_WARN_UNUSED_RESULT
parse_ofp_str__(struct ofputil_flow_mod *fm, int command, char *string,
                const struct ofputil_port_map *port_map,
                const struct ofputil_table_map *table_map,
                enum ofputil_protocol *usable_protocols)
{
    enum {
        F_OUT_PORT = 1 << 0,
        F_ACTIONS = 1 << 1,
        F_IMPORTANCE = 1 << 2,
        F_TIMEOUT = 1 << 3,
        F_PRIORITY = 1 << 4,
        F_FLAGS = 1 << 5,
    } fields;
    char *act_str = NULL;
    char *name, *value;

    *usable_protocols = OFPUTIL_P_ANY;

    if (command == -2) {
        size_t len;

        string += strspn(string, " \t\r\n");   /* Skip white space. */
        len = strcspn(string, ", \t\r\n"); /* Get length of the first token. */

        if (!strncmp(string, "add", len)) {
            command = OFPFC_ADD;
        } else if (!strncmp(string, "delete", len)) {
            command = OFPFC_DELETE;
        } else if (!strncmp(string, "delete_strict", len)) {
            command = OFPFC_DELETE_STRICT;
        } else if (!strncmp(string, "modify", len)) {
            command = OFPFC_MODIFY;
        } else if (!strncmp(string, "modify_strict", len)) {
            command = OFPFC_MODIFY_STRICT;
        } else {
            len = 0;
            command = OFPFC_ADD;
        }
        string += len;
    }

    switch (command) {
    case -1:
        fields = F_OUT_PORT;
        break;

    case OFPFC_ADD:
        fields = F_ACTIONS | F_TIMEOUT | F_PRIORITY | F_FLAGS | F_IMPORTANCE;
        break;

    case OFPFC_DELETE:
        fields = F_OUT_PORT;
        break;

    case OFPFC_DELETE_STRICT:
        fields = F_OUT_PORT | F_PRIORITY;
        break;

    case OFPFC_MODIFY:
        fields = F_ACTIONS | F_TIMEOUT | F_PRIORITY | F_FLAGS;
        break;

    case OFPFC_MODIFY_STRICT:
        fields = F_ACTIONS | F_TIMEOUT | F_PRIORITY | F_FLAGS;
        break;

    default:
        OVS_NOT_REACHED();
    }

    *fm = (struct ofputil_flow_mod) {
        .match = MATCH_CATCHALL_INITIALIZER,
        .priority = OFP_DEFAULT_PRIORITY,
        .table_id = 0xff,
        .command = command,
        .buffer_id = UINT32_MAX,
        .out_port = OFPP_ANY,
        .out_group = OFPG_ANY,
    };
    /* For modify, by default, don't update the cookie. */
    if (command == OFPFC_MODIFY || command == OFPFC_MODIFY_STRICT) {
        fm->new_cookie = OVS_BE64_MAX;
    }

    if (fields & F_ACTIONS) {
        act_str = ofp_extract_actions(string);
        if (!act_str) {
            return xstrdup("must specify an action");
        }
    }

    while (ofputil_parse_key_value(&string, &name, &value)) {
        const struct ofp_protocol *p;
        const struct mf_field *mf;
        char *error = NULL;

        if (ofp_parse_protocol(name, &p)) {
            match_set_dl_type(&fm->match, htons(p->dl_type));
            if (p->nw_proto) {
                match_set_nw_proto(&fm->match, p->nw_proto);
            }
            match_set_default_packet_type(&fm->match);
        } else if (!strcmp(name, "eth")) {
            match_set_packet_type(&fm->match, htonl(PT_ETH));
        } else if (fields & F_FLAGS && !strcmp(name, "send_flow_rem")) {
            fm->flags |= OFPUTIL_FF_SEND_FLOW_REM;
        } else if (fields & F_FLAGS && !strcmp(name, "check_overlap")) {
            fm->flags |= OFPUTIL_FF_CHECK_OVERLAP;
        } else if (fields & F_FLAGS && !strcmp(name, "reset_counts")) {
            fm->flags |= OFPUTIL_FF_RESET_COUNTS;
            *usable_protocols &= OFPUTIL_P_OF12_UP;
        } else if (fields & F_FLAGS && !strcmp(name, "no_packet_counts")) {
            fm->flags |= OFPUTIL_FF_NO_PKT_COUNTS;
            *usable_protocols &= OFPUTIL_P_OF13_UP;
        } else if (fields & F_FLAGS && !strcmp(name, "no_byte_counts")) {
            fm->flags |= OFPUTIL_FF_NO_BYT_COUNTS;
            *usable_protocols &= OFPUTIL_P_OF13_UP;
        } else if (!strcmp(name, "no_readonly_table")
                   || !strcmp(name, "allow_hidden_fields")) {
             /* ignore these fields. */
        } else if ((mf = mf_from_name(name)) != NULL) {
            error = ofp_parse_field(mf, value, port_map,
                                    &fm->match, usable_protocols);
        } else if (strchr(name, '[')) {
            error = parse_subfield(name, value, &fm->match, usable_protocols);
        } else {
            if (!*value) {
                return xasprintf("field %s missing value", name);
            }

            if (!strcmp(name, "table")) {
                if (!ofputil_table_from_string(value, table_map,
                                               &fm->table_id)) {
                    return xasprintf("unknown table \"%s\"", value);
                }
                if (fm->table_id != 0xff) {
                    *usable_protocols &= OFPUTIL_P_TID;
                }
            } else if (fields & F_OUT_PORT && !strcmp(name, "out_port")) {
                if (!ofputil_port_from_string(value, port_map,
                                              &fm->out_port)) {
                    error = xasprintf("%s is not a valid OpenFlow port",
                                      value);
                }
            } else if (fields & F_OUT_PORT && !strcmp(name, "out_group")) {
                *usable_protocols &= OFPUTIL_P_OF11_UP;
                if (!ofputil_group_from_string(value, &fm->out_group)) {
                    error = xasprintf("%s is not a valid OpenFlow group",
                                      value);
                }
            } else if (fields & F_PRIORITY && !strcmp(name, "priority")) {
                uint16_t priority = 0;

                error = str_to_u16(value, name, &priority);
                fm->priority = priority;
            } else if (fields & F_TIMEOUT && !strcmp(name, "idle_timeout")) {
                error = str_to_u16(value, name, &fm->idle_timeout);
            } else if (fields & F_TIMEOUT && !strcmp(name, "hard_timeout")) {
                error = str_to_u16(value, name, &fm->hard_timeout);
            } else if (fields & F_IMPORTANCE && !strcmp(name, "importance")) {
                error = str_to_u16(value, name, &fm->importance);
            } else if (!strcmp(name, "cookie")) {
                char *mask = strchr(value, '/');

                if (mask) {
                    /* A mask means we're searching for a cookie. */
                    if (command == OFPFC_ADD) {
                        return xstrdup("flow additions cannot use "
                                       "a cookie mask");
                    }
                    *mask = '\0';
                    error = str_to_be64(value, &fm->cookie);
                    if (error) {
                        return error;
                    }
                    error = str_to_be64(mask + 1, &fm->cookie_mask);

                    /* Matching of the cookie is only supported through NXM or
                     * OF1.1+. */
                    if (fm->cookie_mask != htonll(0)) {
                        *usable_protocols &= OFPUTIL_P_NXM_OF11_UP;
                    }
                } else {
                    /* No mask means that the cookie is being set. */
                    if (command != OFPFC_ADD && command != OFPFC_MODIFY
                        && command != OFPFC_MODIFY_STRICT) {
                        return xstrdup("cannot set cookie");
                    }
                    error = str_to_be64(value, &fm->new_cookie);
                    fm->modify_cookie = true;
                }
            } else if (!strcmp(name, "duration")
                       || !strcmp(name, "n_packets")
                       || !strcmp(name, "n_bytes")
                       || !strcmp(name, "idle_age")
                       || !strcmp(name, "hard_age")) {
                /* Ignore these, so that users can feed the output of
                 * "ovs-ofctl dump-flows" back into commands that parse
                 * flows. */
            } else {
                error = xasprintf("unknown keyword %s", name);
            }
        }

        if (error) {
            return error;
        }
    }
    /* Copy ethertype to flow->dl_type for matches on packet_type
     * (OFPHTN_ETHERTYPE, ethertype). */
    if (fm->match.wc.masks.packet_type == OVS_BE32_MAX &&
            pt_ns(fm->match.flow.packet_type) == OFPHTN_ETHERTYPE) {
        fm->match.flow.dl_type = pt_ns_type_be(fm->match.flow.packet_type);
    }
    /* Check for usable protocol interdependencies between match fields. */
    if (fm->match.flow.dl_type == htons(ETH_TYPE_IPV6)) {
        const struct flow_wildcards *wc = &fm->match.wc;
        /* Only NXM and OXM support matching L3 and L4 fields within IPv6.
         *
         * (IPv6 specific fields as well as arp_sha, arp_tha, nw_frag, and
         *  nw_ttl are covered elsewhere so they don't need to be included in
         *  this test too.)
         */
        if (wc->masks.nw_proto || wc->masks.nw_tos
            || wc->masks.tp_src || wc->masks.tp_dst) {
            *usable_protocols &= OFPUTIL_P_NXM_OXM_ANY;
        }
    }
    if (!fm->cookie_mask && fm->new_cookie == OVS_BE64_MAX
        && (command == OFPFC_MODIFY || command == OFPFC_MODIFY_STRICT)) {
        /* On modifies without a mask, we are supposed to add a flow if
         * one does not exist.  If a cookie wasn't been specified, use a
         * default of zero. */
        fm->new_cookie = htonll(0);
    }
    if (fields & F_ACTIONS) {
        enum ofputil_protocol action_usable_protocols;
        struct ofpbuf ofpacts;
        char *error;

        ofpbuf_init(&ofpacts, 32);
        struct ofpact_parse_params pp = {
            .port_map = port_map,
            .table_map = table_map,
            .ofpacts = &ofpacts,
            .usable_protocols = &action_usable_protocols
        };
        error = ofpacts_parse_instructions(act_str, &pp);
        *usable_protocols &= action_usable_protocols;
        if (!error) {
            enum ofperr err;

            err = ofpacts_check(ofpacts.data, ofpacts.size, &fm->match,
                                OFPP_MAX, fm->table_id, 255, usable_protocols);
            if (!err && !*usable_protocols) {
                err = OFPERR_OFPBAC_MATCH_INCONSISTENT;
            }
            if (err) {
                error = xasprintf("actions are invalid with specified match "
                                  "(%s)", ofperr_to_string(err));
            }

        }
        if (error) {
            ofpbuf_uninit(&ofpacts);
            return error;
        }

        fm->ofpacts_len = ofpacts.size;
        fm->ofpacts = ofpbuf_steal_data(&ofpacts);
    } else {
        fm->ofpacts_len = 0;
        fm->ofpacts = NULL;
    }

    return NULL;
}

/* Convert 'str_' (as described in the Flow Syntax section of the ovs-ofctl man
 * page) into 'fm' for sending the specified flow_mod 'command' to a switch.
 * Returns the set of usable protocols in '*usable_protocols'.
 *
 * To parse syntax for an OFPT_FLOW_MOD (or NXT_FLOW_MOD), use an OFPFC_*
 * constant for 'command'.  To parse syntax for an OFPST_FLOW or
 * OFPST_AGGREGATE (or NXST_FLOW or NXST_AGGREGATE), use -1 for 'command'.
 *
 * If 'command' is given as -2, 'str_' may begin with a command name ("add",
 * "modify", "delete", "modify_strict", or "delete_strict").  A missing command
 * name is treated as "add".
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_str(struct ofputil_flow_mod *fm, int command, const char *str_,
              const struct ofputil_port_map *port_map,
              const struct ofputil_table_map *table_map,
              enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error;

    error = parse_ofp_str__(fm, command, string, port_map, table_map,
                            usable_protocols);
    if (error) {
        fm->ofpacts = NULL;
        fm->ofpacts_len = 0;
    }

    free(string);
    return error;
}

/* Opens file 'file_name' and reads each line as a flow_mod of the specified
 * type (one of OFPFC_*).  Stores each flow_mod in '*fm', an array allocated
 * on the caller's behalf, and the number of flow_mods in '*n_fms'.
 *
 * If 'command' is given as -2, each line may start with a command name
 * ("add", "modify", "delete", "modify_strict", or "delete_strict").  A missing
 * command name is treated as "add".
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_flow_mod_file(const char *file_name,
                        const struct ofputil_port_map *port_map,
                        const struct ofputil_table_map *table_map,
                        int command,
                        struct ofputil_flow_mod **fms, size_t *n_fms,
                        enum ofputil_protocol *usable_protocols)
{
    size_t allocated_fms;
    int line_number;
    FILE *stream;
    struct ds s;

    *usable_protocols = OFPUTIL_P_ANY;

    *fms = NULL;
    *n_fms = 0;

    stream = !strcmp(file_name, "-") ? stdin : fopen(file_name, "r");
    if (stream == NULL) {
        return xasprintf("%s: open failed (%s)",
                         file_name, ovs_strerror(errno));
    }

    allocated_fms = *n_fms;
    ds_init(&s);
    line_number = 0;
    while (!ds_get_preprocessed_line(&s, stream, &line_number)) {
        char *error;
        enum ofputil_protocol usable;

        if (*n_fms >= allocated_fms) {
            *fms = x2nrealloc(*fms, &allocated_fms, sizeof **fms);
        }
        error = parse_ofp_flow_mod_str(&(*fms)[*n_fms], ds_cstr(&s), port_map,
                                       table_map, command, &usable);
        if (error) {
            char *err_msg;
            size_t i;

            for (i = 0; i < *n_fms; i++) {
                free(CONST_CAST(struct ofpact *, (*fms)[i].ofpacts));
            }
            free(*fms);
            *fms = NULL;
            *n_fms = 0;

            ds_destroy(&s);
            if (stream != stdin) {
                fclose(stream);
            }

            err_msg = xasprintf("%s:%d: %s", file_name, line_number, error);
            free(error);
            return err_msg;
        }
        *usable_protocols &= usable; /* Each line can narrow the set. */
        *n_fms += 1;
    }

    ds_destroy(&s);
    if (stream != stdin) {
        fclose(stream);
    }
    return NULL;
}

/* Parses a specification of a flow from 's' into 'flow'.  's' must take the
 * form FIELD=VALUE[,FIELD=VALUE]... where each FIELD is the name of a
 * mf_field.  Fields must be specified in a natural order for satisfying
 * prerequisites. If 'wc' is specified, masks the field in 'wc' for each of the
 * field specified in flow. If the map, 'names_portno' is specfied, converts
 * the in_port name into port no while setting the 'flow'.
 *
 * Returns NULL on success, otherwise a malloc()'d string that explains the
 * problem. */
char *
parse_ofp_exact_flow(struct flow *flow, struct flow_wildcards *wc,
                     const struct tun_table *tun_table, const char *s,
                     const struct ofputil_port_map *port_map)
{
    char *pos, *key, *value_s;
    char *error = NULL;
    char *copy;

    memset(flow, 0, sizeof *flow);
    if (wc) {
        memset(wc, 0, sizeof *wc);
    }
    flow->tunnel.metadata.tab = tun_table;

    pos = copy = xstrdup(s);
    while (ofputil_parse_key_value(&pos, &key, &value_s)) {
        const struct ofp_protocol *p;
        if (ofp_parse_protocol(key, &p)) {
            if (flow->dl_type) {
                error = xasprintf("%s: Ethernet type set multiple times", s);
                goto exit;
            }
            flow->dl_type = htons(p->dl_type);
            if (wc) {
                wc->masks.dl_type = OVS_BE16_MAX;
            }

            if (p->nw_proto) {
                if (flow->nw_proto) {
                    error = xasprintf("%s: network protocol set "
                                      "multiple times", s);
                    goto exit;
                }
                flow->nw_proto = p->nw_proto;
                if (wc) {
                    wc->masks.nw_proto = UINT8_MAX;
                }
            }
        } else {
            const struct mf_field *mf;
            union mf_value value;
            char *field_error;

            mf = mf_from_name(key);
            if (!mf) {
                error = xasprintf("%s: unknown field %s", s, key);
                goto exit;
            }

            if (!mf_are_prereqs_ok(mf, flow, NULL)) {
                error = xasprintf("%s: prerequisites not met for setting %s",
                                  s, key);
                goto exit;
            }

            if (mf_is_set(mf, flow)) {
                error = xasprintf("%s: field %s set multiple times", s, key);
                goto exit;
            }

            field_error = mf_parse_value(mf, value_s, port_map, &value);
            if (field_error) {
                error = xasprintf("%s: bad value for %s (%s)",
                                  s, key, field_error);
                free(field_error);
                goto exit;
            }

            mf_set_flow_value(mf, &value, flow);
            if (wc) {
                mf_mask_field(mf, wc);
            }
        }
    }

    if (!flow->in_port.ofp_port) {
        flow->in_port.ofp_port = OFPP_NONE;
    }

exit:
    free(copy);

    if (error) {
        memset(flow, 0, sizeof *flow);
        if (wc) {
            memset(wc, 0, sizeof *wc);
        }
    }
    return error;
}
