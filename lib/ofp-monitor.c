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
#include "openvswitch/ofp-monitor.h"
#include "byte-order.h"
#include "nx-match.h"
#include "ovs-atomic.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-group.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-meter.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-table.h"
#include "openvswitch/vlog.h"
#include "ox-stat.h"

VLOG_DEFINE_THIS_MODULE(ofp_monitor);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFP_FLOW_REMOVED_REASON_BUFSIZE. */
const char *
ofp_flow_removed_reason_to_string(enum ofp_flow_removed_reason reason,
                                  char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPRR_IDLE_TIMEOUT:
        return "idle";
    case OFPRR_HARD_TIMEOUT:
        return "hard";
    case OFPRR_DELETE:
        return "delete";
    case OFPRR_GROUP_DELETE:
        return "group_delete";
    case OFPRR_EVICTION:
        return "eviction";
    case OFPRR_METER_DELETE:
        return "meter_delete";
    case OVS_OFPRR_NONE:
    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

/* Converts an OFPT_FLOW_REMOVED or NXT_FLOW_REMOVED message 'oh' into an
 * abstract ofputil_flow_removed in 'fr'.  Returns 0 if successful, otherwise
 * an OpenFlow error code. */
enum ofperr
ofputil_decode_flow_removed(struct ofputil_flow_removed *fr,
                            const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT15_FLOW_REMOVED) {
        const struct ofp15_flow_removed *ofr;
        enum ofperr error;

        ofr = ofpbuf_pull(&b, sizeof *ofr);

        error = ofputil_pull_ofp11_match(&b, NULL, NULL,  &fr->match, NULL);
        if (error) {
            return error;
        }

        struct oxs_stats stats;
        uint16_t statlen;
        uint8_t oxs_field_set;
        error = oxs_pull_stat(&b, &stats, &statlen, &oxs_field_set);
        if (error) {
            return error;
        }

        fr->cookie = ofr->cookie;
        fr->priority = ntohs(ofr->priority);
        fr->reason = ofr->reason;
        fr->table_id = ofr->table_id;
        fr->duration_sec = stats.duration_sec;
        fr->duration_nsec = stats.duration_nsec;
        fr->idle_timeout = ntohs(ofr->idle_timeout);
        fr->hard_timeout = ntohs(ofr->hard_timeout);
        fr->packet_count = stats.packet_count;
        fr->byte_count = stats.byte_count;
    } else if (raw == OFPRAW_OFPT11_FLOW_REMOVED) {
        const struct ofp12_flow_removed *ofr;
        enum ofperr error;

        ofr = ofpbuf_pull(&b, sizeof *ofr);

        error = ofputil_pull_ofp11_match(&b, NULL, NULL, &fr->match, NULL);
        if (error) {
            return error;
        }

        fr->priority = ntohs(ofr->priority);
        fr->cookie = ofr->cookie;
        fr->reason = ofr->reason;
        fr->table_id = ofr->table_id;
        fr->duration_sec = ntohl(ofr->duration_sec);
        fr->duration_nsec = ntohl(ofr->duration_nsec);
        fr->idle_timeout = ntohs(ofr->idle_timeout);
        fr->hard_timeout = ntohs(ofr->hard_timeout);
        fr->packet_count = ntohll(ofr->packet_count);
        fr->byte_count = ntohll(ofr->byte_count);
    } else if (raw == OFPRAW_OFPT10_FLOW_REMOVED) {
        const struct ofp10_flow_removed *ofr;

        ofr = ofpbuf_pull(&b, sizeof *ofr);

        ofputil_match_from_ofp10_match(&ofr->match, &fr->match);
        fr->priority = ntohs(ofr->priority);
        fr->cookie = ofr->cookie;
        fr->reason = ofr->reason;
        fr->table_id = 255;
        fr->duration_sec = ntohl(ofr->duration_sec);
        fr->duration_nsec = ntohl(ofr->duration_nsec);
        fr->idle_timeout = ntohs(ofr->idle_timeout);
        fr->hard_timeout = 0;
        fr->packet_count = ntohll(ofr->packet_count);
        fr->byte_count = ntohll(ofr->byte_count);
    } else if (raw == OFPRAW_NXT_FLOW_REMOVED) {
        struct nx_flow_removed *nfr;
        enum ofperr error;

        nfr = ofpbuf_pull(&b, sizeof *nfr);
        error = nx_pull_match(&b, ntohs(nfr->match_len), &fr->match, NULL,
                              NULL, false, NULL, NULL);
        if (error) {
            return error;
        }
        if (b.size) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        fr->priority = ntohs(nfr->priority);
        fr->cookie = nfr->cookie;
        fr->reason = nfr->reason;
        fr->table_id = nfr->table_id ? nfr->table_id - 1 : 255;
        fr->duration_sec = ntohl(nfr->duration_sec);
        fr->duration_nsec = ntohl(nfr->duration_nsec);
        fr->idle_timeout = ntohs(nfr->idle_timeout);
        fr->hard_timeout = 0;
        fr->packet_count = ntohll(nfr->packet_count);
        fr->byte_count = ntohll(nfr->byte_count);
    } else {
        OVS_NOT_REACHED();
    }

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

/* Converts abstract ofputil_flow_removed 'fr' into an OFPT_FLOW_REMOVED or
 * NXT_FLOW_REMOVED message 'oh' according to 'protocol', and returns the
 * message. */
struct ofpbuf *
ofputil_encode_flow_removed(const struct ofputil_flow_removed *fr,
                            enum ofputil_protocol protocol)
{
    struct ofpbuf *msg;
    enum ofp_flow_removed_reason reason = fr->reason;

    if (reason == OFPRR_METER_DELETE && !(protocol & OFPUTIL_P_OF14_UP)) {
        reason = OFPRR_DELETE;
    }

    switch (protocol) {
    case OFPUTIL_P_OF11_STD:
    case OFPUTIL_P_OF12_OXM:
    case OFPUTIL_P_OF13_OXM:
    case OFPUTIL_P_OF14_OXM: {
        struct ofp12_flow_removed *ofr;

        msg = ofpraw_alloc_xid(OFPRAW_OFPT11_FLOW_REMOVED,
                               ofputil_protocol_to_ofp_version(protocol),
                               htonl(0),
                               ofputil_match_typical_len(protocol));
        ofr = ofpbuf_put_zeros(msg, sizeof *ofr);
        ofr->cookie = fr->cookie;
        ofr->priority = htons(fr->priority);
        ofr->reason = reason;
        ofr->table_id = fr->table_id;
        ofr->duration_sec = htonl(fr->duration_sec);
        ofr->duration_nsec = htonl(fr->duration_nsec);
        ofr->idle_timeout = htons(fr->idle_timeout);
        ofr->hard_timeout = htons(fr->hard_timeout);
        ofr->packet_count = htonll(fr->packet_count);
        ofr->byte_count = htonll(fr->byte_count);
        ofputil_put_ofp11_match(msg, &fr->match, protocol);
        break;
    }
    case OFPUTIL_P_OF15_OXM: {
        struct ofp15_flow_removed *ofr;

        msg = ofpraw_alloc_xid(OFPRAW_OFPT15_FLOW_REMOVED,
                               ofputil_protocol_to_ofp_version(protocol),
                               htonl(0),
                               ofputil_match_typical_len(protocol));
        ofr = ofpbuf_put_zeros(msg, sizeof *ofr);
        ofr->cookie = fr->cookie;
        ofr->priority = htons(fr->priority);
        ofr->reason = reason;
        ofr->table_id = fr->table_id;
        ofr->idle_timeout = htons(fr->idle_timeout);
        ofr->hard_timeout = htons(fr->hard_timeout);
        ofputil_put_ofp11_match(msg, &fr->match, protocol);

        const struct oxs_stats oxs = {
            .duration_sec = fr->duration_sec,
            .duration_nsec = fr->duration_nsec,
            .idle_age = UINT32_MAX,
            .packet_count = fr->packet_count,
            .byte_count = fr->byte_count,
            .flow_count = UINT32_MAX,
        };
        oxs_put_stats(msg, &oxs);
        break;
    }
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID: {
        struct ofp10_flow_removed *ofr;

        msg = ofpraw_alloc_xid(OFPRAW_OFPT10_FLOW_REMOVED, OFP10_VERSION,
                               htonl(0), 0);
        ofr = ofpbuf_put_zeros(msg, sizeof *ofr);
        ofputil_match_to_ofp10_match(&fr->match, &ofr->match);
        ofr->cookie = fr->cookie;
        ofr->priority = htons(fr->priority);
        ofr->reason = reason;
        ofr->duration_sec = htonl(fr->duration_sec);
        ofr->duration_nsec = htonl(fr->duration_nsec);
        ofr->idle_timeout = htons(fr->idle_timeout);
        ofr->packet_count = htonll(unknown_to_zero(fr->packet_count));
        ofr->byte_count = htonll(unknown_to_zero(fr->byte_count));
        break;
    }

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID: {
        struct nx_flow_removed *nfr;
        int match_len;

        msg = ofpraw_alloc_xid(OFPRAW_NXT_FLOW_REMOVED, OFP10_VERSION,
                               htonl(0), NXM_TYPICAL_LEN);
        ofpbuf_put_zeros(msg, sizeof *nfr);
        match_len = nx_put_match(msg, &fr->match, 0, 0);

        nfr = msg->msg;
        nfr->cookie = fr->cookie;
        nfr->priority = htons(fr->priority);
        nfr->reason = reason;
        nfr->table_id = fr->table_id + 1;
        nfr->duration_sec = htonl(fr->duration_sec);
        nfr->duration_nsec = htonl(fr->duration_nsec);
        nfr->idle_timeout = htons(fr->idle_timeout);
        nfr->match_len = htons(match_len);
        nfr->packet_count = htonll(fr->packet_count);
        nfr->byte_count = htonll(fr->byte_count);
        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    return msg;
}

void
ofputil_flow_removed_format(struct ds *s,
                            const struct ofputil_flow_removed *fr,
                            const struct ofputil_port_map *port_map,
                            const struct ofputil_table_map *table_map)
{
    char reasonbuf[OFP_FLOW_REMOVED_REASON_BUFSIZE];

    ds_put_char(s, ' ');
    match_format(&fr->match, port_map, s, fr->priority);

    ds_put_format(s, " reason=%s",
                  ofp_flow_removed_reason_to_string(fr->reason, reasonbuf,
                                                    sizeof reasonbuf));

    if (fr->table_id != 255) {
        ds_put_format(s, " table_id=");
        ofputil_format_table(fr->table_id, table_map, s);
    }

    if (fr->cookie != htonll(0)) {
        ds_put_format(s, " cookie:0x%"PRIx64, ntohll(fr->cookie));
    }
    ds_put_cstr(s, " duration");
    ofp_print_duration(s, fr->duration_sec, fr->duration_nsec);
    ds_put_format(s, " idle%"PRIu16, fr->idle_timeout);
    if (fr->hard_timeout) {
        /* The hard timeout was only added in OF1.2, so only print it if it is
         * actually in use to avoid gratuitous change to the formatting. */
        ds_put_format(s, " hard%"PRIu16, fr->hard_timeout);
    }
    ds_put_format(s, " pkts%"PRIu64" bytes%"PRIu64"\n",
                  fr->packet_count, fr->byte_count);
}

/* ofputil_flow_monitor_request */

/* Converts an NXST_FLOW_MONITOR request in 'msg' into an abstract
 * ofputil_flow_monitor_request in 'rq'.
 *
 * Multiple NXST_FLOW_MONITOR requests can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the requests.  The caller must initially leave 'msg''s layer
 * pointers null and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no requests were left in this 'msg',
 * otherwise an OFPERR_* value. */
int
ofputil_decode_flow_monitor_request(struct ofputil_flow_monitor_request *rq,
                                    struct ofpbuf *msg)
{
    struct nx_flow_monitor_request *nfmr;
    uint16_t flags;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    nfmr = ofpbuf_try_pull(msg, sizeof *nfmr);
    if (!nfmr) {
        VLOG_WARN_RL(&rl, "NXST_FLOW_MONITOR request has %"PRIu32" "
                     "leftover bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    flags = ntohs(nfmr->flags);
    if (!(flags & (NXFMF_ADD | NXFMF_DELETE | NXFMF_MODIFY))
        || flags & ~(NXFMF_INITIAL | NXFMF_ADD | NXFMF_DELETE
                     | NXFMF_MODIFY | NXFMF_ACTIONS | NXFMF_OWN)) {
        VLOG_WARN_RL(&rl, "NXST_FLOW_MONITOR has bad flags %#"PRIx16, flags);
        return OFPERR_OFPMOFC_BAD_FLAGS;
    }

    if (!is_all_zeros(nfmr->zeros, sizeof nfmr->zeros)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    rq->id = ntohl(nfmr->id);
    rq->flags = flags;
    rq->out_port = u16_to_ofp(ntohs(nfmr->out_port));
    rq->table_id = nfmr->table_id;

    return nx_pull_match(msg, ntohs(nfmr->match_len), &rq->match, NULL,
                         NULL, false, NULL, NULL);
}

void
ofputil_append_flow_monitor_request(
    const struct ofputil_flow_monitor_request *rq, struct ofpbuf *msg)
{
    struct nx_flow_monitor_request *nfmr;
    size_t start_ofs;
    int match_len;

    if (!msg->size) {
        ofpraw_put(OFPRAW_NXST_FLOW_MONITOR_REQUEST, OFP10_VERSION, msg);
    }

    start_ofs = msg->size;
    ofpbuf_put_zeros(msg, sizeof *nfmr);
    match_len = nx_put_match(msg, &rq->match, htonll(0), htonll(0));

    nfmr = ofpbuf_at_assert(msg, start_ofs, sizeof *nfmr);
    nfmr->id = htonl(rq->id);
    nfmr->flags = htons(rq->flags);
    nfmr->out_port = htons(ofp_to_u16(rq->out_port));
    nfmr->match_len = htons(match_len);
    nfmr->table_id = rq->table_id;
}

static const char *
nx_flow_monitor_flags_to_name(uint32_t bit)
{
    enum nx_flow_monitor_flags fmf = bit;

    switch (fmf) {
    case NXFMF_INITIAL: return "initial";
    case NXFMF_ADD: return "add";
    case NXFMF_DELETE: return "delete";
    case NXFMF_MODIFY: return "modify";
    case NXFMF_ACTIONS: return "actions";
    case NXFMF_OWN: return "own";
    }

    return NULL;
}

void
ofputil_flow_monitor_request_format(
    struct ds *s, const struct ofputil_flow_monitor_request *request,
    const struct ofputil_port_map *port_map,
    const struct ofputil_table_map *table_map)
{
    ds_put_format(s, "\n id=%"PRIu32" flags=", request->id);
    ofp_print_bit_names(s, request->flags, nx_flow_monitor_flags_to_name, ',');

    if (request->out_port != OFPP_NONE) {
        ds_put_cstr(s, " out_port=");
        ofputil_format_port(request->out_port, port_map, s);
    }

    if (request->table_id != 0xff) {
        ds_put_format(s, " table=");
        ofputil_format_table(request->table_id, table_map, s);
    }

    ds_put_char(s, ' ');
    match_format(&request->match, port_map, s, OFP_DEFAULT_PRIORITY);
    ds_chomp(s, ' ');
}

static char * OVS_WARN_UNUSED_RESULT
parse_flow_monitor_request__(struct ofputil_flow_monitor_request *fmr,
                             const char *str_,
                             const struct ofputil_port_map *port_map,
                             const struct ofputil_table_map *table_map,
                             char *string,
                             enum ofputil_protocol *usable_protocols)
{
    static atomic_count id = ATOMIC_COUNT_INIT(0);
    char *name, *value;

    fmr->id = atomic_count_inc(&id);

    fmr->flags = (NXFMF_INITIAL | NXFMF_ADD | NXFMF_DELETE | NXFMF_MODIFY
                  | NXFMF_OWN | NXFMF_ACTIONS);
    fmr->out_port = OFPP_NONE;
    fmr->table_id = 0xff;
    match_init_catchall(&fmr->match);

    *usable_protocols = OFPUTIL_P_ANY;
    while (ofputil_parse_key_value(&string, &name, &value)) {
        const struct ofp_protocol *p;
        char *error = NULL;

        if (!strcmp(name, "!initial")) {
            fmr->flags &= ~NXFMF_INITIAL;
        } else if (!strcmp(name, "!add")) {
            fmr->flags &= ~NXFMF_ADD;
        } else if (!strcmp(name, "!delete")) {
            fmr->flags &= ~NXFMF_DELETE;
        } else if (!strcmp(name, "!modify")) {
            fmr->flags &= ~NXFMF_MODIFY;
        } else if (!strcmp(name, "!actions")) {
            fmr->flags &= ~NXFMF_ACTIONS;
        } else if (!strcmp(name, "!own")) {
            fmr->flags &= ~NXFMF_OWN;
        } else if (ofp_parse_protocol(name, &p)) {
            match_set_dl_type(&fmr->match, htons(p->dl_type));
            if (p->nw_proto) {
                match_set_nw_proto(&fmr->match, p->nw_proto);
            }
        } else if (mf_from_name(name)) {
            error = ofp_parse_field(mf_from_name(name), value, port_map,
                                    &fmr->match, usable_protocols);
            if (!error && !(*usable_protocols & OFPUTIL_P_OF10_ANY)) {
                return xasprintf("%s: match field is not supported for "
                                 "flow monitor", name);
            }
        } else {
            if (!*value) {
                return xasprintf("%s: field %s missing value", str_, name);
            }

            if (!strcmp(name, "table")) {
                if (!ofputil_table_from_string(value, table_map,
                                               &fmr->table_id)) {
                    error = xasprintf("unknown table \"%s\"", value);
                }
            } else if (!strcmp(name, "out_port")) {
                fmr->out_port = u16_to_ofp(atoi(value));
            } else {
                return xasprintf("%s: unknown keyword %s", str_, name);
            }
        }

        if (error) {
            return error;
        }
        /* Flow Monitor is supported in OpenFlow 1.0 or can be further reduced
         * to a few 1.0 flavors by a match field. */
        *usable_protocols &= OFPUTIL_P_OF10_ANY;
    }
    return NULL;
}

/* Convert 'str_' (as described in the documentation for the "monitor" command
 * in the ovs-ofctl man page) into 'fmr'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_flow_monitor_request(struct ofputil_flow_monitor_request *fmr,
                           const char *str_,
                           const struct ofputil_port_map *port_map,
                           const struct ofputil_table_map *table_map,
                           enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error = parse_flow_monitor_request__(fmr, str_, port_map, table_map,
                                               string, usable_protocols);
    free(string);
    return error;
}

/* Converts an NXST_FLOW_MONITOR reply (also known as a flow update) in 'msg'
 * into an abstract ofputil_flow_update in 'update'.  The caller must have
 * initialized update->match to point to space allocated for a match.
 *
 * Uses 'ofpacts' to store the abstract OFPACT_* version of the update's
 * actions (except for NXFME_ABBREV, which never includes actions).  The caller
 * must initialize 'ofpacts' and retains ownership of it.  'update->ofpacts'
 * will point into the 'ofpacts' buffer.
 *
 * Multiple flow updates can be packed into a single OpenFlow message.  Calling
 * this function multiple times for a single 'msg' iterates through the
 * updates.  The caller must initially leave 'msg''s layer pointers null and
 * not modify them between calls.
 *
 * Returns 0 if successful, EOF if no updates were left in this 'msg',
 * otherwise an OFPERR_* value. */
int
ofputil_decode_flow_update(struct ofputil_flow_update *update,
                           struct ofpbuf *msg, struct ofpbuf *ofpacts)
{
    struct nx_flow_update_header *nfuh;
    unsigned int length;
    struct ofp_header *oh;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    ofpbuf_clear(ofpacts);
    if (!msg->size) {
        return EOF;
    }

    if (msg->size < sizeof(struct nx_flow_update_header)) {
        goto bad_len;
    }

    oh = msg->header;

    nfuh = msg->data;
    update->event = ntohs(nfuh->event);
    length = ntohs(nfuh->length);
    if (length > msg->size || length % 8) {
        goto bad_len;
    }

    if (update->event == NXFME_ABBREV) {
        struct nx_flow_update_abbrev *nfua;

        if (length != sizeof *nfua) {
            goto bad_len;
        }

        nfua = ofpbuf_pull(msg, sizeof *nfua);
        update->xid = nfua->xid;
        return 0;
    } else if (update->event == NXFME_ADDED
               || update->event == NXFME_DELETED
               || update->event == NXFME_MODIFIED) {
        struct nx_flow_update_full *nfuf;
        unsigned int actions_len;
        unsigned int match_len;
        enum ofperr error;

        if (length < sizeof *nfuf) {
            goto bad_len;
        }

        nfuf = ofpbuf_pull(msg, sizeof *nfuf);
        match_len = ntohs(nfuf->match_len);
        if (sizeof *nfuf + match_len > length) {
            goto bad_len;
        }

        update->reason = ntohs(nfuf->reason);
        update->idle_timeout = ntohs(nfuf->idle_timeout);
        update->hard_timeout = ntohs(nfuf->hard_timeout);
        update->table_id = nfuf->table_id;
        update->cookie = nfuf->cookie;
        update->priority = ntohs(nfuf->priority);

        error = nx_pull_match(msg, match_len, &update->match, NULL, NULL,
                              false, NULL, NULL);
        if (error) {
            return error;
        }

        actions_len = length - sizeof *nfuf - ROUND_UP(match_len, 8);
        error = ofpacts_pull_openflow_actions(msg, actions_len, oh->version,
                                              NULL, NULL, ofpacts);
        if (error) {
            return error;
        }

        update->ofpacts = ofpacts->data;
        update->ofpacts_len = ofpacts->size;
        return 0;
    } else {
        VLOG_WARN_RL(&rl, "NXST_FLOW_MONITOR reply has bad event %"PRIu16,
                     ntohs(nfuh->event));
        return OFPERR_NXBRC_FM_BAD_EVENT;
    }

bad_len:
    VLOG_WARN_RL(&rl, "NXST_FLOW_MONITOR reply has %"PRIu32" "
                 "leftover bytes at end", msg->size);
    return OFPERR_OFPBRC_BAD_LEN;
}

uint32_t
ofputil_decode_flow_monitor_cancel(const struct ofp_header *oh)
{
    const struct nx_flow_monitor_cancel *cancel = ofpmsg_body(oh);

    return ntohl(cancel->id);
}

struct ofpbuf *
ofputil_encode_flow_monitor_cancel(uint32_t id)
{
    struct nx_flow_monitor_cancel *nfmc;
    struct ofpbuf *msg;

    msg = ofpraw_alloc(OFPRAW_NXT_FLOW_MONITOR_CANCEL, OFP10_VERSION, 0);
    nfmc = ofpbuf_put_uninit(msg, sizeof *nfmc);
    nfmc->id = htonl(id);
    return msg;
}

void
ofputil_start_flow_update(struct ovs_list *replies)
{
    struct ofpbuf *msg;

    msg = ofpraw_alloc_xid(OFPRAW_NXST_FLOW_MONITOR_REPLY, OFP10_VERSION,
                           htonl(0), 1024);

    ovs_list_init(replies);
    ovs_list_push_back(replies, &msg->list_node);
}

void
ofputil_append_flow_update(const struct ofputil_flow_update *update,
                           struct ovs_list *replies,
                           const struct tun_table *tun_table)
{
    struct ofputil_flow_update *update_ =
        CONST_CAST(struct ofputil_flow_update *, update);
    const struct tun_table *orig_tun_table;
    enum ofp_version version = ofpmp_version(replies);
    struct nx_flow_update_header *nfuh;
    struct ofpbuf *msg;
    size_t start_ofs;

    orig_tun_table = update->match.flow.tunnel.metadata.tab;
    update_->match.flow.tunnel.metadata.tab = tun_table;

    msg = ofpbuf_from_list(ovs_list_back(replies));
    start_ofs = msg->size;

    if (update->event == NXFME_ABBREV) {
        struct nx_flow_update_abbrev *nfua;

        nfua = ofpbuf_put_zeros(msg, sizeof *nfua);
        nfua->xid = update->xid;
    } else {
        struct nx_flow_update_full *nfuf;
        int match_len;

        ofpbuf_put_zeros(msg, sizeof *nfuf);
        match_len = nx_put_match(msg, &update->match, htonll(0), htonll(0));
        ofpacts_put_openflow_actions(update->ofpacts, update->ofpacts_len, msg,
                                     version);
        nfuf = ofpbuf_at_assert(msg, start_ofs, sizeof *nfuf);
        nfuf->reason = htons(update->reason);
        nfuf->priority = htons(update->priority);
        nfuf->idle_timeout = htons(update->idle_timeout);
        nfuf->hard_timeout = htons(update->hard_timeout);
        nfuf->match_len = htons(match_len);
        nfuf->table_id = update->table_id;
        nfuf->cookie = update->cookie;
    }

    nfuh = ofpbuf_at_assert(msg, start_ofs, sizeof *nfuh);
    nfuh->length = htons(msg->size - start_ofs);
    nfuh->event = htons(update->event);

    ofpmp_postappend(replies, start_ofs);
    update_->match.flow.tunnel.metadata.tab = orig_tun_table;
}

void
ofputil_flow_update_format(struct ds *s,
                           const struct ofputil_flow_update *update,
                           const struct ofputil_port_map *port_map,
                           const struct ofputil_table_map *table_map)
{
    char reasonbuf[OFP_FLOW_REMOVED_REASON_BUFSIZE];

    ds_put_cstr(s, "\n event=");
    switch (update->event) {
    case NXFME_ADDED:
        ds_put_cstr(s, "ADDED");
        break;

    case NXFME_DELETED:
        ds_put_format(s, "DELETED reason=%s",
                      ofp_flow_removed_reason_to_string(update->reason,
                                                        reasonbuf,
                                                        sizeof reasonbuf));
        break;

    case NXFME_MODIFIED:
        ds_put_cstr(s, "MODIFIED");
        break;

    case NXFME_ABBREV:
        ds_put_format(s, "ABBREV xid=0x%"PRIx32, ntohl(update->xid));
        return;
    }

    ds_put_format(s, " table=");
    ofputil_format_table(update->table_id, table_map, s);
    if (update->idle_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, " idle_timeout=%"PRIu16, update->idle_timeout);
    }
    if (update->hard_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, " hard_timeout=%"PRIu16, update->hard_timeout);
    }
    ds_put_format(s, " cookie=%#"PRIx64, ntohll(update->cookie));

    ds_put_char(s, ' ');
    match_format(&update->match, port_map, s, OFP_DEFAULT_PRIORITY);

    if (update->ofpacts_len) {
        if (s->string[s->length - 1] != ' ') {
            ds_put_char(s, ' ');
        }
        ds_put_cstr(s, "actions=");
        struct ofpact_format_params fp = {
            .port_map = port_map,
            .table_map = table_map,
            .s = s,
        };
        ofpacts_format(update->ofpacts, update->ofpacts_len, &fp);
    }
}

/* Encodes 'rf' according to 'protocol', and returns the encoded message. */
struct ofpbuf *
ofputil_encode_requestforward(const struct ofputil_requestforward *rf,
                              enum ofputil_protocol protocol)
{
    enum ofp_version ofp_version = ofputil_protocol_to_ofp_version(protocol);
    enum ofpraw raw_msg_type;
    struct ofpbuf *inner;

    switch (rf->reason) {
    case OFPRFR_GROUP_MOD:
        inner = ofputil_encode_group_mod(ofp_version, rf->group_mod,
                                         rf->new_buckets, rf->group_existed);
        break;

    case OFPRFR_METER_MOD:
        inner = ofputil_encode_meter_mod(ofp_version, rf->meter_mod);
        break;

    case OFPRFR_N_REASONS:
    default:
        OVS_NOT_REACHED();
    }

    struct ofp_header *inner_oh = inner->data;
    inner_oh->xid = rf->xid;
    inner_oh->length = htons(inner->size);

    if (ofp_version < OFP13_VERSION) {
        raw_msg_type = OFPRAW_NXT_REQUESTFORWARD;
    } else if (ofp_version == OFP13_VERSION) {
        raw_msg_type = OFPRAW_ONFT13_REQUESTFORWARD;
    } else {
        raw_msg_type = OFPRAW_OFPT14_REQUESTFORWARD;
    }

    struct ofpbuf *outer = ofpraw_alloc_xid(raw_msg_type, ofp_version,
                                            htonl(0), inner->size);
    ofpbuf_put(outer, inner->data, inner->size);
    ofpbuf_delete(inner);

    return outer;
}

/* Decodes OFPT_REQUESTFORWARD message 'outer'.  On success, puts the decoded
 * form into '*rf' and returns 0, and the caller is later responsible for
 * freeing the content of 'rf', with ofputil_destroy_requestforward(rf).  On
 * failure, returns an ofperr and '*rf' is indeterminate. */
enum ofperr
ofputil_decode_requestforward(const struct ofp_header *outer,
                              struct ofputil_requestforward *rf)
{
    rf->new_buckets = NULL;
    rf->group_existed = -1;

    struct ofpbuf b = ofpbuf_const_initializer(outer, ntohs(outer->length));

    /* Skip past outer message. */
    enum ofpraw raw_msg_type = ofpraw_pull_assert(&b);
    ovs_assert(raw_msg_type == OFPRAW_OFPT14_REQUESTFORWARD ||
               raw_msg_type == OFPRAW_ONFT13_REQUESTFORWARD ||
               raw_msg_type == OFPRAW_NXT_REQUESTFORWARD);

    /* Validate inner message. */
    if (b.size < sizeof(struct ofp_header)) {
        return OFPERR_OFPBFC_MSG_BAD_LEN;
    }
    const struct ofp_header *inner = b.data;
    unsigned int inner_len = ntohs(inner->length);
    if (inner_len < sizeof(struct ofp_header) || inner_len > b.size) {
        return OFPERR_OFPBFC_MSG_BAD_LEN;
    }
    if (inner->version != outer->version) {
        return OFPERR_OFPBRC_BAD_VERSION;
    }

    /* Parse inner message. */
    enum ofptype type;
    enum ofperr error = ofptype_decode(&type, inner);
    if (error) {
        return error;
    }

    rf->xid = inner->xid;
    if (type == OFPTYPE_GROUP_MOD) {
        rf->reason = OFPRFR_GROUP_MOD;
        rf->group_mod = xmalloc(sizeof *rf->group_mod);
        error = ofputil_decode_group_mod(inner, rf->group_mod);
        if (error) {
            free(rf->group_mod);
            return error;
        }
    } else if (type == OFPTYPE_METER_MOD) {
        rf->reason = OFPRFR_METER_MOD;
        rf->meter_mod = xmalloc(sizeof *rf->meter_mod);
        ofpbuf_init(&rf->bands, 64);
        error = ofputil_decode_meter_mod(inner, rf->meter_mod, &rf->bands);
        if (error) {
            free(rf->meter_mod);
            ofpbuf_uninit(&rf->bands);
            return error;
        }
    } else {
        return OFPERR_OFPBFC_MSG_UNSUP;
    }

    return 0;
}

void
ofputil_format_requestforward(struct ds *string,
                              enum ofp_version ofp_version,
                              const struct ofputil_requestforward *rf,
                              const struct ofputil_port_map *port_map,
                              const struct ofputil_table_map *table_map)
{
    ds_put_cstr(string, " reason=");

    switch (rf->reason) {
    case OFPRFR_GROUP_MOD:
        ds_put_cstr(string, "group_mod");
        ofputil_group_mod_format__(string, ofp_version, rf->group_mod,
                                   port_map, table_map);
        break;

    case OFPRFR_METER_MOD:
        ds_put_cstr(string, "meter_mod");
        ofputil_format_meter_mod(string, rf->meter_mod);
        break;

    case OFPRFR_N_REASONS:
        OVS_NOT_REACHED();
    }
}


/* Frees the content of 'rf', which should have been initialized through a
 * successful call to ofputil_decode_requestforward(). */
void
ofputil_destroy_requestforward(struct ofputil_requestforward *rf)
{
    if (!rf) {
        return;
    }

    switch (rf->reason) {
    case OFPRFR_GROUP_MOD:
        ofputil_uninit_group_mod(rf->group_mod);
        free(rf->group_mod);
        /* 'rf' does not own rf->new_buckets. */
        break;

    case OFPRFR_METER_MOD:
        ofpbuf_uninit(&rf->bands);
        free(rf->meter_mod);
        break;

    case OFPRFR_N_REASONS:
        OVS_NOT_REACHED();
    }
}
