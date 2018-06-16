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
#include "openvswitch/ofp-meter.h"
#include "byte-order.h"
#include "nx-match.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_meter);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

void
ofputil_format_meter_id(struct ds *s, uint32_t meter_id, char separator)
{
    if (meter_id <= OFPM13_MAX) {
        ds_put_format(s, "meter%c%"PRIu32, separator, meter_id);
    } else {
        const char *name;
        switch (meter_id) {
        case OFPM13_SLOWPATH:
            name = "slowpath";
            break;
        case OFPM13_CONTROLLER:
            name = "controller";
            break;
        case OFPM13_ALL:
            name = "all";
            break;
        default:
            name = "unknown";
        }
        ds_put_format(s, "meter%c%s", separator, name);
    }
}

void
ofputil_format_meter_band(struct ds *s, enum ofp13_meter_flags flags,
                          const struct ofputil_meter_band *mb)
{
    ds_put_cstr(s, "\ntype=");
    switch (mb->type) {
    case OFPMBT13_DROP:
        ds_put_cstr(s, "drop");
        break;
    case OFPMBT13_DSCP_REMARK:
        ds_put_cstr(s, "dscp_remark");
        break;
    default:
        ds_put_format(s, "%u", mb->type);
    }

    ds_put_format(s, " rate=%"PRIu32, mb->rate);

    if (flags & OFPMF13_BURST) {
        ds_put_format(s, " burst_size=%"PRIu32, mb->burst_size);
    }
    if (mb->type == OFPMBT13_DSCP_REMARK) {
        ds_put_format(s, " prec_level=%"PRIu8, mb->prec_level);
    }
}

static enum ofperr
ofputil_pull_bands(struct ofpbuf *msg, size_t len, uint16_t *n_bands,
                   struct ofpbuf *bands)
{
    const struct ofp13_meter_band_header *ombh;
    struct ofputil_meter_band *mb;
    uint16_t n = 0;

    ombh = ofpbuf_try_pull(msg, len);
    if (!ombh) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    while (len >= sizeof (struct ofp13_meter_band_drop)) {
        size_t ombh_len = ntohs(ombh->len);
        /* All supported band types have the same length. */
        if (ombh_len != sizeof (struct ofp13_meter_band_drop)) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        mb = ofpbuf_put_uninit(bands, sizeof *mb);
        mb->type = ntohs(ombh->type);
        if (mb->type != OFPMBT13_DROP && mb->type != OFPMBT13_DSCP_REMARK) {
            return OFPERR_OFPMMFC_BAD_BAND;
        }
        mb->rate = ntohl(ombh->rate);
        mb->burst_size = ntohl(ombh->burst_size);
        mb->prec_level = (mb->type == OFPMBT13_DSCP_REMARK) ?
            ((struct ofp13_meter_band_dscp_remark *)ombh)->prec_level : 0;
        n++;
        len -= ombh_len;
        ombh = ALIGNED_CAST(struct ofp13_meter_band_header *,
                            (char *) ombh + ombh_len);
    }
    if (len) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    *n_bands = n;
    return 0;
}

enum ofperr
ofputil_decode_meter_mod(const struct ofp_header *oh,
                         struct ofputil_meter_mod *mm,
                         struct ofpbuf *bands)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);
    const struct ofp13_meter_mod *omm = ofpbuf_pull(&b, sizeof *omm);

    /* Translate the message. */
    mm->command = ntohs(omm->command);
    if (mm->command != OFPMC13_ADD &&
        mm->command != OFPMC13_MODIFY &&
        mm->command != OFPMC13_DELETE) {
        return OFPERR_OFPMMFC_BAD_COMMAND;
    }
    mm->meter.meter_id = ntohl(omm->meter_id);

    if (mm->command == OFPMC13_DELETE) {
        mm->meter.flags = 0;
        mm->meter.n_bands = 0;
        mm->meter.bands = NULL;
    } else {
        enum ofperr error;

        mm->meter.flags = ntohs(omm->flags);
        if (mm->meter.flags & OFPMF13_KBPS &&
            mm->meter.flags & OFPMF13_PKTPS) {
            return OFPERR_OFPMMFC_BAD_FLAGS;
        }

        error = ofputil_pull_bands(&b, b.size, &mm->meter.n_bands, bands);
        if (error) {
            return error;
        }
        mm->meter.bands = bands->data;
    }
    return 0;
}

void
ofputil_decode_meter_request(const struct ofp_header *oh, uint32_t *meter_id)
{
    const struct ofp13_meter_multipart_request *omr = ofpmsg_body(oh);
    *meter_id = ntohl(omr->meter_id);
}

struct ofpbuf *
ofputil_encode_meter_request(enum ofp_version ofp_version,
                             enum ofputil_meter_request_type type,
                             uint32_t meter_id)
{
    struct ofpbuf *msg;

    enum ofpraw raw;

    switch (type) {
    case OFPUTIL_METER_CONFIG:
        raw = OFPRAW_OFPST13_METER_CONFIG_REQUEST;
        break;
    case OFPUTIL_METER_STATS:
        raw = OFPRAW_OFPST13_METER_REQUEST;
        break;
    default:
    case OFPUTIL_METER_FEATURES:
        raw = OFPRAW_OFPST13_METER_FEATURES_REQUEST;
        break;
    }

    msg = ofpraw_alloc(raw, ofp_version, 0);

    if (type != OFPUTIL_METER_FEATURES) {
        struct ofp13_meter_multipart_request *omr;
        omr = ofpbuf_put_zeros(msg, sizeof *omr);
        omr->meter_id = htonl(meter_id);
    }
    return msg;
}

static void
ofputil_put_bands(uint16_t n_bands, const struct ofputil_meter_band *mb,
                  struct ofpbuf *msg)
{
    uint16_t n = 0;

    for (n = 0; n < n_bands; ++n) {
        /* Currently all band types have same size. */
        struct ofp13_meter_band_dscp_remark *ombh;
        size_t ombh_len = sizeof *ombh;

        ombh = ofpbuf_put_zeros(msg, ombh_len);

        ombh->type = htons(mb->type);
        ombh->len = htons(ombh_len);
        ombh->rate = htonl(mb->rate);
        ombh->burst_size = htonl(mb->burst_size);
        ombh->prec_level = mb->prec_level;

        mb++;
    }
}

/* Encode a meter stat for 'mc' and append it to 'replies'. */
void
ofputil_append_meter_config(struct ovs_list *replies,
                            const struct ofputil_meter_config *mc)
{
    struct ofpbuf *msg = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_ofs = msg->size;
    struct ofp13_meter_config *reply;

    ofpbuf_put_uninit(msg, sizeof *reply);
    ofputil_put_bands(mc->n_bands, mc->bands, msg);

    reply = ofpbuf_at_assert(msg, start_ofs, sizeof *reply);
    reply->flags = htons(mc->flags);
    reply->meter_id = htonl(mc->meter_id);
    reply->length = htons(msg->size - start_ofs);

    ofpmp_postappend(replies, start_ofs);
}

/* Encode a meter stat for 'ms' and append it to 'replies'. */
void
ofputil_append_meter_stats(struct ovs_list *replies,
                           const struct ofputil_meter_stats *ms)
{
    struct ofp13_meter_stats *reply;
    uint16_t n = 0;
    uint16_t len;

    len = sizeof *reply + ms->n_bands * sizeof(struct ofp13_meter_band_stats);
    reply = ofpmp_append(replies, len);

    reply->meter_id = htonl(ms->meter_id);
    reply->len = htons(len);
    memset(reply->pad, 0, sizeof reply->pad);
    reply->flow_count = htonl(ms->flow_count);
    reply->packet_in_count = htonll(ms->packet_in_count);
    reply->byte_in_count = htonll(ms->byte_in_count);
    reply->duration_sec = htonl(ms->duration_sec);
    reply->duration_nsec = htonl(ms->duration_nsec);

    for (n = 0; n < ms->n_bands; ++n) {
        const struct ofputil_meter_band_stats *src = &ms->bands[n];
        struct ofp13_meter_band_stats *dst = &reply->band_stats[n];

        dst->packet_band_count = htonll(src->packet_count);
        dst->byte_band_count = htonll(src->byte_count);
    }
}

/* Converts an OFPMP_METER_CONFIG reply in 'msg' into an abstract
 * ofputil_meter_config in 'mc', with mc->bands pointing to bands decoded into
 * 'bands'.  The caller must have initialized 'bands' and retains ownership of
 * it across the call.
 *
 * Multiple OFPST13_METER_CONFIG replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  'bands' is cleared for each reply.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_meter_config(struct ofpbuf *msg,
                            struct ofputil_meter_config *mc,
                            struct ofpbuf *bands)
{
    const struct ofp13_meter_config *omc;
    enum ofperr err;

    /* Pull OpenFlow headers for the first call. */
    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    omc = ofpbuf_try_pull(msg, sizeof *omc);
    if (!omc) {
        VLOG_WARN_RL(&rl, "OFPMP_METER_CONFIG reply has %"PRIu32" leftover "
                     "bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    ofpbuf_clear(bands);
    err = ofputil_pull_bands(msg, ntohs(omc->length) - sizeof *omc,
                             &mc->n_bands, bands);
    if (err) {
        return err;
    }
    mc->meter_id = ntohl(omc->meter_id);
    mc->flags = ntohs(omc->flags);
    mc->bands = bands->data;

    return 0;
}

static void
ofp_print_meter_flags(struct ds *s, enum ofp13_meter_flags flags)
{
    if (flags & OFPMF13_KBPS) {
        ds_put_cstr(s, "kbps ");
    }
    if (flags & OFPMF13_PKTPS) {
        ds_put_cstr(s, "pktps ");
    }
    if (flags & OFPMF13_BURST) {
        ds_put_cstr(s, "burst ");
    }
    if (flags & OFPMF13_STATS) {
        ds_put_cstr(s, "stats ");
    }

    flags &= ~(OFPMF13_KBPS | OFPMF13_PKTPS | OFPMF13_BURST | OFPMF13_STATS);
    if (flags) {
        ds_put_format(s, "flags:0x%"PRIx16" ", flags);
    }
}

void
ofputil_format_meter_config(struct ds *s,
                            const struct ofputil_meter_config *mc)
{
    uint16_t i;

    ofputil_format_meter_id(s, mc->meter_id, '=');
    ds_put_char(s, ' ');

    ofp_print_meter_flags(s, mc->flags);

    ds_put_cstr(s, "bands=");
    for (i = 0; i < mc->n_bands; ++i) {
        ofputil_format_meter_band(s, mc->flags, &mc->bands[i]);
    }
    ds_put_char(s, '\n');
}

static enum ofperr
ofputil_pull_band_stats(struct ofpbuf *msg, size_t len, uint16_t *n_bands,
                        struct ofpbuf *bands)
{
    const struct ofp13_meter_band_stats *ombs;
    struct ofputil_meter_band_stats *mbs;
    uint16_t n, i;

    ombs = ofpbuf_try_pull(msg, len);
    if (!ombs) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    n = len / sizeof *ombs;
    if (len != n * sizeof *ombs) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    mbs = ofpbuf_put_uninit(bands, len);

    for (i = 0; i < n; ++i) {
        mbs[i].packet_count = ntohll(ombs[i].packet_band_count);
        mbs[i].byte_count = ntohll(ombs[i].byte_band_count);
    }
    *n_bands = n;
    return 0;
}

/* Converts an OFPMP_METER reply in 'msg' into an abstract
 * ofputil_meter_stats in 'ms', with ms->bands pointing to band stats
 * decoded into 'bands'.
 *
 * Multiple OFPMP_METER replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  'bands' is cleared for each reply.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_meter_stats(struct ofpbuf *msg,
                           struct ofputil_meter_stats *ms,
                           struct ofpbuf *bands)
{
    const struct ofp13_meter_stats *oms;
    enum ofperr err;

    /* Pull OpenFlow headers for the first call. */
    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    oms = ofpbuf_try_pull(msg, sizeof *oms);
    if (!oms) {
        VLOG_WARN_RL(&rl, "OFPMP_METER reply has %"PRIu32" leftover bytes "
                     "at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    ofpbuf_clear(bands);
    err = ofputil_pull_band_stats(msg, ntohs(oms->len) - sizeof *oms,
                                  &ms->n_bands, bands);
    if (err) {
        return err;
    }
    ms->meter_id = ntohl(oms->meter_id);
    ms->flow_count = ntohl(oms->flow_count);
    ms->packet_in_count = ntohll(oms->packet_in_count);
    ms->byte_in_count = ntohll(oms->byte_in_count);
    ms->duration_sec = ntohl(oms->duration_sec);
    ms->duration_nsec = ntohl(oms->duration_nsec);
    ms->bands = bands->data;

    return 0;
}

void
ofputil_format_meter_stats(struct ds *s, const struct ofputil_meter_stats *ms)
{
    uint16_t i;

    ofputil_format_meter_id(s, ms->meter_id, ':');
    ds_put_char(s, ' ');
    ds_put_format(s, "flow_count:%"PRIu32" ", ms->flow_count);
    ds_put_format(s, "packet_in_count:%"PRIu64" ", ms->packet_in_count);
    ds_put_format(s, "byte_in_count:%"PRIu64" ", ms->byte_in_count);
    ds_put_cstr(s, "duration:");
    ofp_print_duration(s, ms->duration_sec, ms->duration_nsec);
    ds_put_char(s, ' ');

    ds_put_cstr(s, "bands:\n");
    for (i = 0; i < ms->n_bands; ++i) {
        ds_put_format(s, "%d: ", i);
        ds_put_format(s, "packet_count:%"PRIu64" ", ms->bands[i].packet_count);
        ds_put_format(s, "byte_count:%"PRIu64"\n", ms->bands[i].byte_count);
    }
}

void
ofputil_decode_meter_features(const struct ofp_header *oh,
                              struct ofputil_meter_features *mf)
{
    const struct ofp13_meter_features *omf = ofpmsg_body(oh);

    mf->max_meters = ntohl(omf->max_meter);
    mf->band_types = ntohl(omf->band_types);
    mf->capabilities = ntohl(omf->capabilities);
    mf->max_bands = omf->max_bands;
    mf->max_color = omf->max_color;
}

struct ofpbuf *
ofputil_encode_meter_features_reply(const struct ofputil_meter_features *mf,
                                    const struct ofp_header *request)
{
    struct ofpbuf *reply;
    struct ofp13_meter_features *omf;

    reply = ofpraw_alloc_stats_reply(request, 0);
    omf = ofpbuf_put_zeros(reply, sizeof *omf);

    omf->max_meter = htonl(mf->max_meters);
    omf->band_types = htonl(mf->band_types);
    omf->capabilities = htonl(mf->capabilities);
    omf->max_bands = mf->max_bands;
    omf->max_color = mf->max_color;

    return reply;
}

static const char *
ofputil_meter_band_types_to_name(uint32_t bit)
{
    switch (bit) {
    case 1 << OFPMBT13_DROP:          return "drop";
    case 1 << OFPMBT13_DSCP_REMARK:   return "dscp_remark";
    }

    return NULL;
}

static const char *
ofputil_meter_capabilities_to_name(uint32_t bit)
{
    enum ofp13_meter_flags flag = bit;

    switch (flag) {
    case OFPMF13_KBPS:    return "kbps";
    case OFPMF13_PKTPS:   return "pktps";
    case OFPMF13_BURST:   return "burst";
    case OFPMF13_STATS:   return "stats";
    }

    return NULL;
}

void
ofputil_format_meter_features(struct ds *s,
                              const struct ofputil_meter_features *mf)
{
    ds_put_format(s, "\nmax_meter:%"PRIu32, mf->max_meters);
    ds_put_format(s, " max_bands:%"PRIu8, mf->max_bands);
    ds_put_format(s, " max_color:%"PRIu8"\n", mf->max_color);

    ds_put_cstr(s, "band_types: ");
    ofp_print_bit_names(s, mf->band_types,
                        ofputil_meter_band_types_to_name, ' ');
    ds_put_char(s, '\n');

    ds_put_cstr(s, "capabilities: ");
    ofp_print_bit_names(s, mf->capabilities,
                        ofputil_meter_capabilities_to_name, ' ');
    ds_put_char(s, '\n');
}

struct ofpbuf *
ofputil_encode_meter_mod(enum ofp_version ofp_version,
                         const struct ofputil_meter_mod *mm)
{
    struct ofpbuf *msg;

    struct ofp13_meter_mod *omm;

    msg = ofpraw_alloc(OFPRAW_OFPT13_METER_MOD, ofp_version,
                       NXM_TYPICAL_LEN + mm->meter.n_bands * 16);
    omm = ofpbuf_put_zeros(msg, sizeof *omm);
    omm->command = htons(mm->command);
    if (mm->command != OFPMC13_DELETE) {
        omm->flags = htons(mm->meter.flags);
    }
    omm->meter_id = htonl(mm->meter.meter_id);

    ofputil_put_bands(mm->meter.n_bands, mm->meter.bands, msg);

    ofpmsg_update_length(msg);
    return msg;
}

/* Parse a string representation of a meter modification message to '*mm'.
 * If successful, 'mm->meter.bands' must be free()d by the caller. */
static char * OVS_WARN_UNUSED_RESULT
parse_ofp_meter_mod_str__(struct ofputil_meter_mod *mm, char *string,
                          struct ofpbuf *bands, int command,
                          enum ofputil_protocol *usable_protocols)
{
    enum {
        F_METER = 1 << 0,
        F_FLAGS = 1 << 1,
        F_BANDS = 1 << 2,
    } fields;
    char *save_ptr = NULL;
    char *band_str = NULL;
    char *name;

    /* Meters require at least OF 1.3. */
    *usable_protocols = OFPUTIL_P_OF13_UP;

    switch (command) {
    case -1:
        fields = F_METER;
        break;

    case OFPMC13_ADD:
        fields = F_METER | F_FLAGS | F_BANDS;
        break;

    case OFPMC13_DELETE:
        fields = F_METER;
        break;

    case OFPMC13_MODIFY:
        fields = F_METER | F_FLAGS | F_BANDS;
        break;

    default:
        OVS_NOT_REACHED();
    }

    mm->command = command;
    mm->meter.meter_id = 0;
    mm->meter.flags = 0;
    mm->meter.n_bands = 0;
    mm->meter.bands = NULL;

    if (fields & F_BANDS) {
        band_str = strstr(string, "band");
        if (!band_str) {
            return xstrdup("must specify bands");
        }
        *band_str = '\0';

        band_str = strchr(band_str + 1, '=');
        if (!band_str) {
            return xstrdup("must specify bands");
        }

        band_str++;
    }
    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {

        if (fields & F_FLAGS && !strcmp(name, "kbps")) {
            mm->meter.flags |= OFPMF13_KBPS;
        } else if (fields & F_FLAGS && !strcmp(name, "pktps")) {
            mm->meter.flags |= OFPMF13_PKTPS;
        } else if (fields & F_FLAGS && !strcmp(name, "burst")) {
            mm->meter.flags |= OFPMF13_BURST;
        } else if (fields & F_FLAGS && !strcmp(name, "stats")) {
            mm->meter.flags |= OFPMF13_STATS;
        } else {
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                return xasprintf("field %s missing value", name);
            }

            if (!strcmp(name, "meter")) {
                if (!strcmp(value, "all")) {
                    mm->meter.meter_id = OFPM13_ALL;
                } else if (!strcmp(value, "controller")) {
                    mm->meter.meter_id = OFPM13_CONTROLLER;
                } else if (!strcmp(value, "slowpath")) {
                    mm->meter.meter_id = OFPM13_SLOWPATH;
                } else {
                    char *error = str_to_u32(value, &mm->meter.meter_id);
                    if (error) {
                        return error;
                    }
                    if (mm->meter.meter_id > OFPM13_MAX
                        || !mm->meter.meter_id) {
                        return xasprintf("invalid value for %s", name);
                    }
                }
            } else {
                return xasprintf("unknown keyword %s", name);
            }
        }
    }
    if (fields & F_METER && !mm->meter.meter_id) {
        return xstrdup("must specify 'meter'");
    }
    if (fields & F_FLAGS && !mm->meter.flags) {
        return xstrdup("meter must specify either 'kbps' or 'pktps'");
    }

    if (fields & F_BANDS) {
        uint16_t n_bands = 0;
        struct ofputil_meter_band *band = NULL;
        int i;

        for (name = strtok_r(band_str, "=, \t\r\n", &save_ptr); name;
             name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {

            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                return xasprintf("field %s missing value", name);
            }

            if (!strcmp(name, "type")) {
                /* Start a new band */
                band = ofpbuf_put_zeros(bands, sizeof *band);
                n_bands++;

                if (!strcmp(value, "drop")) {
                    band->type = OFPMBT13_DROP;
                } else if (!strcmp(value, "dscp_remark")) {
                    band->type = OFPMBT13_DSCP_REMARK;
                } else {
                    return xasprintf("field %s unknown value %s", name, value);
                }
            } else if (!band || !band->type) {
                return xstrdup("band must start with the 'type' keyword");
            } else if (!strcmp(name, "rate")) {
                char *error = str_to_u32(value, &band->rate);
                if (error) {
                    return error;
                }
            } else if (!strcmp(name, "burst_size")) {
                char *error = str_to_u32(value, &band->burst_size);
                if (error) {
                    return error;
                }
            } else if (!strcmp(name, "prec_level")) {
                char *error = str_to_u8(value, name, &band->prec_level);
                if (error) {
                    return error;
                }
            } else {
                return xasprintf("unknown keyword %s", name);
            }
        }
        /* validate bands */
        if (!n_bands) {
            return xstrdup("meter must have bands");
        }

        mm->meter.n_bands = n_bands;
        mm->meter.bands = ofpbuf_steal_data(bands);

        for (i = 0; i < n_bands; ++i) {
            band = &mm->meter.bands[i];

            if (!band->type) {
                return xstrdup("band must have 'type'");
            }
            if (band->type == OFPMBT13_DSCP_REMARK) {
                if (!band->prec_level) {
                    return xstrdup("'dscp_remark' band must have"
                                   " 'prec_level'");
                }
            } else {
                if (band->prec_level) {
                    return xstrdup("Only 'dscp_remark' band may have"
                                   " 'prec_level'");
                }
            }
            if (!band->rate) {
                return xstrdup("band must have 'rate'");
            }
            if (mm->meter.flags & OFPMF13_BURST) {
                if (!band->burst_size) {
                    return xstrdup("band must have 'burst_size' "
                                   "when 'burst' flag is set");
                }
            } else {
                if (band->burst_size) {
                    return xstrdup("band may have 'burst_size' only "
                                   "when 'burst' flag is set");
                }
            }
        }
    }

    return NULL;
}

/* Convert 'str_' (as described in the Meter Syntax section of the
 * ovs-ofctl man page) into 'mm' for sending the specified meter_mod
 * 'command' to a switch.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string.
 * If successful, 'mm->meter.bands' must be free()'d by the caller. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_meter_mod_str(struct ofputil_meter_mod *mm, const char *str_,
                        int command, enum ofputil_protocol *usable_protocols)
{
    struct ofpbuf bands;
    char *string;
    char *error;

    ofpbuf_init(&bands, 64);
    string = xstrdup(str_);

    error = parse_ofp_meter_mod_str__(mm, string, &bands, command,
                                      usable_protocols);

    free(string);
    ofpbuf_uninit(&bands);

    return error;
}

void
ofputil_format_meter_mod(struct ds *s, const struct ofputil_meter_mod *mm)
{
    switch (mm->command) {
    case OFPMC13_ADD:
        ds_put_cstr(s, " ADD ");
        break;
    case OFPMC13_MODIFY:
        ds_put_cstr(s, " MOD ");
        break;
    case OFPMC13_DELETE:
        ds_put_cstr(s, " DEL ");
        break;
    default:
        ds_put_format(s, " cmd:%d ", mm->command);
    }

    ofputil_format_meter_config(s, &mm->meter);
}
