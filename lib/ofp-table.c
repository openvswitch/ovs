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
#include "openvswitch/ofp-table.h"
#include "bitmap.h"
#include "nx-match.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofp_table);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static ovs_be32 ofputil_encode_table_config(enum ofputil_table_miss,
                                            enum ofputil_table_eviction,
                                            enum ofputil_table_vacancy,
                                            enum ofp_version);
static enum ofputil_table_vacancy ofputil_decode_table_vacancy(
    ovs_be32 config, enum ofp_version);
static enum ofputil_table_eviction ofputil_decode_table_eviction(
    ovs_be32 config, enum ofp_version);

const char *
ofputil_table_miss_to_string(enum ofputil_table_miss miss)
{
    switch (miss) {
    case OFPUTIL_TABLE_MISS_DEFAULT: return "default";
    case OFPUTIL_TABLE_MISS_CONTROLLER: return "controller";
    case OFPUTIL_TABLE_MISS_CONTINUE: return "continue";
    case OFPUTIL_TABLE_MISS_DROP: return "drop";
    default: return "***error***";
    }
}

const char *
ofputil_table_eviction_to_string(enum ofputil_table_eviction eviction)
{
    switch (eviction) {
    case OFPUTIL_TABLE_EVICTION_DEFAULT: return "default";
    case OFPUTIL_TABLE_EVICTION_ON: return "on";
    case OFPUTIL_TABLE_EVICTION_OFF: return "off";
    default: return "***error***";
    }
}

const char *
ofputil_table_vacancy_to_string(enum ofputil_table_vacancy vacancy)
{
    switch (vacancy) {
    case OFPUTIL_TABLE_VACANCY_DEFAULT: return "default";
    case OFPUTIL_TABLE_VACANCY_ON: return "on";
    case OFPUTIL_TABLE_VACANCY_OFF: return "off";
    default: return "***error***";
    }
}

/* ofputil_table_map.  */

void
ofputil_table_map_init(struct ofputil_table_map *map)
{
    namemap_init(&map->map);
}

void
ofputil_table_map_put(struct ofputil_table_map *map,
                      uint8_t table_id, const char *name)
{
    namemap_put(&map->map, table_id, name);
}

const char *
ofputil_table_map_get_name(const struct ofputil_table_map *map,
                           uint8_t table_id)
{
    struct namemap_node *node
        = map ? namemap_find_by_number(&map->map, table_id) : NULL;
    return node && !node->duplicate ? node->name : NULL;
}

uint8_t
ofputil_table_map_get_number(const struct ofputil_table_map *map,
                             const char *name)
{
    struct namemap_node *node
        = map ? namemap_find_by_name(&map->map, name) : NULL;
    return node && !node->duplicate ? node->number : UINT8_MAX;
}

void
ofputil_table_map_destroy(struct ofputil_table_map *map)
{
    namemap_destroy(&map->map);
}

/* Table numbers. */

/* Stores the table number represented by 's' into '*tablep'.  's' may be an
 * integer or, if 'table_map' is nonnull, a name (quoted or unquoted).
 *
 * Returns true if successful, false if 's' is not a valid OpenFlow table
 * number or name.  The caller should issue an error message in this case,
 * because this function usually does not.  (This gives the caller an
 * opportunity to look up the table name another way, e.g. by contacting the
 * switch and listing the names of all its tables). */
bool
ofputil_table_from_string(const char *s,
                          const struct ofputil_table_map *table_map,
                          uint8_t *tablep)
{
    *tablep = 0;
    if (*s == '-') {
        VLOG_WARN("Negative value %s is not a valid table number.", s);
        return false;
    }

    unsigned int table;
    if (str_to_uint(s, 10, &table)) {
        if (table > 255) {
            VLOG_WARN("table %u is outside the supported range 0 through 255",
                      table);
            return false;
        }
        *tablep = table;
        return true;
    } else {
        if (s[0] != '"') {
            table = ofputil_table_map_get_number(table_map, s);
        } else {
            size_t length = strlen(s);
            char *name = NULL;
            if (length > 1
                && s[length - 1] == '"'
                && json_string_unescape(s + 1, length - 2, &name)) {
                table = ofputil_table_map_get_number(table_map, name);
            }
            free(name);
        }
        if (table != UINT8_MAX) {
            *tablep = table;
            return true;
        }

        return false;
    }
}

/* Appends to 's' a string representation of the OpenFlow table number 'table',
 * either the table number or a name drawn from 'table_map'. */
void
ofputil_format_table(uint8_t table, const struct ofputil_table_map *table_map,
                     struct ds *s)
{
    const char *table_name = ofputil_table_map_get_name(table_map, table);
    if (table_name) {
        namemap_put_name(table_name, s);
    } else {
        ds_put_format(s, "%"PRIu8, table);
    }
}

/* Puts in the 'bufsize' byte in 'namebuf' a null-terminated string
 * representation of OpenFlow table number 'table', either the table's number
 * or a name drawn from 'table_map'. */
void
ofputil_table_to_string(uint8_t table,
                        const struct ofputil_table_map *table_map,
                        char *namebuf, size_t bufsize)
{
    const char *table_name = ofputil_table_map_get_name(table_map, table);
    if (table_name) {
        struct ds s = DS_EMPTY_INITIALIZER;
        namemap_put_name(table_name, &s);
        ovs_strlcpy(namebuf, ds_cstr(&s), bufsize);
        ds_destroy(&s);
        return;
    }

    snprintf(namebuf, bufsize, "%"PRIu8, table);
}

/* Table features. */

static enum ofperr
pull_table_feature_property(struct ofpbuf *msg, struct ofpbuf *payload,
                            uint64_t *typep)
{
    enum ofperr error;

    error = ofpprop_pull(msg, payload, typep);
    if (payload && !error) {
        ofpbuf_pull(payload, (char *)payload->msg - (char *)payload->header);
    }
    return error;
}

static enum ofperr
parse_action_bitmap(struct ofpbuf *payload, enum ofp_version ofp_version,
                    uint64_t *ofpacts)
{
    uint32_t types = 0;

    while (payload->size > 0) {
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull__(payload, NULL, 1, 0x10000, &type);
        if (error) {
            return error;
        }
        if (type < CHAR_BIT * sizeof types) {
            types |= 1u << type;
        }
    }

    *ofpacts = ofpact_bitmap_from_openflow(htonl(types), ofp_version);
    return 0;
}

static enum ofperr
parse_instruction_ids(struct ofpbuf *payload, bool loose, uint32_t *insts)
{
    *insts = 0;
    while (payload->size > 0) {
        enum ovs_instruction_type inst;
        enum ofperr error;
        uint64_t ofpit;

        /* OF1.3 and OF1.4 aren't clear about padding in the instruction IDs.
         * It seems clear that they aren't padded to 8 bytes, though, because
         * both standards say that "non-experimenter instructions are 4 bytes"
         * and do not mention any padding before the first instruction ID.
         * (There wouldn't be any point in padding to 8 bytes if the IDs were
         * aligned on an odd 4-byte boundary.)
         *
         * Anyway, we just assume they're all glommed together on byte
         * boundaries. */
        error = ofpprop_pull__(payload, NULL, 1, 0x10000, &ofpit);
        if (error) {
            return error;
        }

        error = ovs_instruction_type_from_inst_type(&inst, ofpit);
        if (!error) {
            *insts |= 1u << inst;
        } else if (!loose) {
            return error;
        }
    }
    return 0;
}

static enum ofperr
parse_table_features_next_table(struct ofpbuf *payload,
                                unsigned long int *next_tables)
{
    size_t i;

    memset(next_tables, 0, bitmap_n_bytes(255));
    for (i = 0; i < payload->size; i++) {
        uint8_t id = ((const uint8_t *) payload->data)[i];
        if (id >= 255) {
            return OFPERR_OFPBPC_BAD_VALUE;
        }
        bitmap_set1(next_tables, id);
    }
    return 0;
}

static enum ofperr
parse_oxms(struct ofpbuf *payload, bool loose,
           struct mf_bitmap *exactp, struct mf_bitmap *maskedp)
{
    struct mf_bitmap exact = MF_BITMAP_INITIALIZER;
    struct mf_bitmap masked = MF_BITMAP_INITIALIZER;

    while (payload->size > 0) {
        const struct mf_field *field;
        enum ofperr error;
        bool hasmask;

        error = nx_pull_header(payload, NULL, &field, &hasmask);
        if (!error) {
            bitmap_set1(hasmask ? masked.bm : exact.bm, field->id);
        } else if (error != OFPERR_OFPBMC_BAD_FIELD || !loose) {
            return error;
        }
    }
    if (exactp) {
        *exactp = exact;
    } else if (!bitmap_is_all_zeros(exact.bm, MFF_N_IDS)) {
        return OFPERR_OFPBMC_BAD_MASK;
    }
    if (maskedp) {
        *maskedp = masked;
    } else if (!bitmap_is_all_zeros(masked.bm, MFF_N_IDS)) {
        return OFPERR_OFPBMC_BAD_MASK;
    }
    return 0;
}

/* Converts an OFPMP_TABLE_FEATURES request or reply in 'msg' into an abstract
 * ofputil_table_features in 'tf'.
 *
 * If 'loose' is true, this function ignores properties and values that it does
 * not understand, as a controller would want to do when interpreting
 * capabilities provided by a switch.  If 'loose' is false, this function
 * treats unknown properties and values as an error, as a switch would want to
 * do when interpreting a configuration request made by a controller.
 *
 * A single OpenFlow message can specify features for multiple tables.  Calling
 * this function multiple times for a single 'msg' iterates through the tables
 * in the message.  The caller must initially leave 'msg''s layer pointers null
 * and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no tables were left in this 'msg', otherwise
 * a positive "enum ofperr" value. */
int
ofputil_decode_table_features(struct ofpbuf *msg,
                              struct ofputil_table_features *tf, bool loose)
{
    memset(tf, 0, sizeof *tf);

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    const struct ofp_header *oh = msg->header;
    struct ofp13_table_features *otf = msg->data;
    if (msg->size < sizeof *otf) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    unsigned int len = ntohs(otf->length);
    if (len < sizeof *otf || len % 8 || len > msg->size) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    tf->table_id = otf->table_id;
    if (tf->table_id == OFPTT_ALL) {
        return OFPERR_OFPTFFC_BAD_TABLE;
    }

    ovs_strlcpy_arrays(tf->name, otf->name);
    tf->metadata_match = otf->metadata_match;
    tf->metadata_write = otf->metadata_write;
    tf->miss_config = OFPUTIL_TABLE_MISS_DEFAULT;
    if (oh->version >= OFP14_VERSION) {
        uint32_t caps = ntohl(otf->capabilities);
        tf->supports_eviction = (caps & OFPTC14_EVICTION) != 0;
        tf->supports_vacancy_events = (caps & OFPTC14_VACANCY_EVENTS) != 0;
    } else {
        tf->supports_eviction = -1;
        tf->supports_vacancy_events = -1;
    }
    tf->max_entries = ntohl(otf->max_entries);

    struct ofpbuf properties = ofpbuf_const_initializer(ofpbuf_pull(msg, len),
                                                        len);
    ofpbuf_pull(&properties, sizeof *otf);
    while (properties.size > 0) {
        struct ofpbuf payload;
        enum ofperr error;
        uint64_t type;

        error = pull_table_feature_property(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch ((enum ofp13_table_feature_prop_type) type) {
        case OFPTFPT13_INSTRUCTIONS:
            error = parse_instruction_ids(&payload, loose,
                                          &tf->nonmiss.instructions);
            break;
        case OFPTFPT13_INSTRUCTIONS_MISS:
            error = parse_instruction_ids(&payload, loose,
                                          &tf->miss.instructions);
            break;

        case OFPTFPT13_NEXT_TABLES:
            error = parse_table_features_next_table(&payload,
                                                    tf->nonmiss.next);
            break;
        case OFPTFPT13_NEXT_TABLES_MISS:
            error = parse_table_features_next_table(&payload, tf->miss.next);
            break;

        case OFPTFPT13_WRITE_ACTIONS:
            error = parse_action_bitmap(&payload, oh->version,
                                        &tf->nonmiss.write.ofpacts);
            break;
        case OFPTFPT13_WRITE_ACTIONS_MISS:
            error = parse_action_bitmap(&payload, oh->version,
                                        &tf->miss.write.ofpacts);
            break;

        case OFPTFPT13_APPLY_ACTIONS:
            error = parse_action_bitmap(&payload, oh->version,
                                        &tf->nonmiss.apply.ofpacts);
            break;
        case OFPTFPT13_APPLY_ACTIONS_MISS:
            error = parse_action_bitmap(&payload, oh->version,
                                        &tf->miss.apply.ofpacts);
            break;

        case OFPTFPT13_MATCH:
            error = parse_oxms(&payload, loose, &tf->match, &tf->mask);
            break;
        case OFPTFPT13_WILDCARDS:
            error = parse_oxms(&payload, loose, &tf->wildcard, NULL);
            break;

        case OFPTFPT13_WRITE_SETFIELD:
            error = parse_oxms(&payload, loose,
                               &tf->nonmiss.write.set_fields, NULL);
            break;
        case OFPTFPT13_WRITE_SETFIELD_MISS:
            error = parse_oxms(&payload, loose,
                               &tf->miss.write.set_fields, NULL);
            break;
        case OFPTFPT13_APPLY_SETFIELD:
            error = parse_oxms(&payload, loose,
                               &tf->nonmiss.apply.set_fields, NULL);
            break;
        case OFPTFPT13_APPLY_SETFIELD_MISS:
            error = parse_oxms(&payload, loose,
                               &tf->miss.apply.set_fields, NULL);
            break;

        case OFPTFPT13_EXPERIMENTER:
        case OFPTFPT13_EXPERIMENTER_MISS:
        default:
            error = OFPPROP_UNKNOWN(loose, "table features", type);
            break;
        }
        if (error) {
            return error;
        }
    }

    /* Fix inconsistencies:
     *
     *     - Turn on 'match' bits that are set in 'mask', because maskable
     *       fields are matchable.
     *
     *     - Turn on 'wildcard' bits that are set in 'mask', because a field
     *       that is arbitrarily maskable can be wildcarded entirely.
     *
     *     - Turn off 'wildcard' bits that are not in 'match', because a field
     *       must be matchable for it to be meaningfully wildcarded. */
    bitmap_or(tf->match.bm, tf->mask.bm, MFF_N_IDS);
    bitmap_or(tf->wildcard.bm, tf->mask.bm, MFF_N_IDS);
    bitmap_and(tf->wildcard.bm, tf->match.bm, MFF_N_IDS);

    return 0;
}

/* Encodes and returns a request to obtain the table features of a switch.
 * The message is encoded for OpenFlow version 'ofp_version'. */
struct ofpbuf *
ofputil_encode_table_features_request(enum ofp_version ofp_version)
{
    struct ofpbuf *request = NULL;

    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
    case OFP12_VERSION:
        ovs_fatal(0, "dump-table-features needs OpenFlow 1.3 or later "
                     "(\'-O OpenFlow13\')");
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        request = ofpraw_alloc(OFPRAW_OFPST13_TABLE_FEATURES_REQUEST,
                               ofp_version, 0);
        break;
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

static void
put_fields_property(struct ofpbuf *reply,
                    const struct mf_bitmap *fields,
                    const struct mf_bitmap *masks,
                    enum ofp13_table_feature_prop_type property,
                    enum ofp_version version)
{
    size_t start_ofs;
    int field;

    start_ofs = ofpprop_start(reply, property);
    BITMAP_FOR_EACH_1 (field, MFF_N_IDS, fields->bm) {
        nx_put_header(reply, field, version,
                      masks && bitmap_is_set(masks->bm, field));
    }
    ofpprop_end(reply, start_ofs);
}

static void
put_table_action_features(struct ofpbuf *reply,
                          const struct ofputil_table_action_features *taf,
                          enum ofp13_table_feature_prop_type actions_type,
                          enum ofp13_table_feature_prop_type set_fields_type,
                          int miss_offset, enum ofp_version version)
{
    ofpprop_put_bitmap(reply, actions_type + miss_offset,
                       ntohl(ofpact_bitmap_to_openflow(taf->ofpacts,
                                                       version)));
    put_fields_property(reply, &taf->set_fields, NULL,
                        set_fields_type + miss_offset, version);
}

static void
put_table_instruction_features(
    struct ofpbuf *reply, const struct ofputil_table_instruction_features *tif,
    int miss_offset, enum ofp_version version)
{
    size_t start_ofs;
    uint8_t table_id;

    ofpprop_put_bitmap(reply, OFPTFPT13_INSTRUCTIONS + miss_offset,
                       ntohl(ovsinst_bitmap_to_openflow(tif->instructions,
                                                        version)));

    start_ofs = ofpprop_start(reply, OFPTFPT13_NEXT_TABLES + miss_offset);
    BITMAP_FOR_EACH_1 (table_id, 255, tif->next) {
        ofpbuf_put(reply, &table_id, 1);
    }
    ofpprop_end(reply, start_ofs);

    put_table_action_features(reply, &tif->write,
                              OFPTFPT13_WRITE_ACTIONS,
                              OFPTFPT13_WRITE_SETFIELD, miss_offset, version);
    put_table_action_features(reply, &tif->apply,
                              OFPTFPT13_APPLY_ACTIONS,
                              OFPTFPT13_APPLY_SETFIELD, miss_offset, version);
}

void
ofputil_append_table_features_reply(const struct ofputil_table_features *tf,
                                    struct ovs_list *replies)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    enum ofp_version version = ofpmp_version(replies);
    size_t start_ofs = reply->size;
    struct ofp13_table_features *otf;

    otf = ofpbuf_put_zeros(reply, sizeof *otf);
    otf->table_id = tf->table_id;
    ovs_strlcpy_arrays(otf->name, tf->name);
    otf->metadata_match = tf->metadata_match;
    otf->metadata_write = tf->metadata_write;
    if (version >= OFP14_VERSION) {
        if (tf->supports_eviction) {
            otf->capabilities |= htonl(OFPTC14_EVICTION);
        }
        if (tf->supports_vacancy_events) {
            otf->capabilities |= htonl(OFPTC14_VACANCY_EVENTS);
        }
    }
    otf->max_entries = htonl(tf->max_entries);

    put_table_instruction_features(reply, &tf->nonmiss, 0, version);
    put_table_instruction_features(reply, &tf->miss, 1, version);

    put_fields_property(reply, &tf->match, &tf->mask,
                        OFPTFPT13_MATCH, version);
    put_fields_property(reply, &tf->wildcard, NULL,
                        OFPTFPT13_WILDCARDS, version);

    otf = ofpbuf_at_assert(reply, start_ofs, sizeof *otf);
    otf->length = htons(reply->size - start_ofs);
    ofpmp_postappend(replies, start_ofs);
}

static enum ofperr
parse_table_desc_vacancy_property(struct ofpbuf *property,
                                  struct ofputil_table_desc *td)
{
    struct ofp14_table_mod_prop_vacancy *otv = property->data;

    if (property->size != sizeof *otv) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    td->table_vacancy.vacancy_down = otv->vacancy_down;
    td->table_vacancy.vacancy_up = otv->vacancy_up;
    td->table_vacancy.vacancy = otv->vacancy;
    return 0;
}

/* Decodes the next OpenFlow "table desc" message (of possibly several) from
 * 'msg' into an abstract form in '*td'.  Returns 0 if successful, EOF if the
 * last "table desc" in 'msg' was already decoded, otherwise an OFPERR_*
 * value. */
int
ofputil_decode_table_desc(struct ofpbuf *msg,
                          struct ofputil_table_desc *td,
                          enum ofp_version version)
{
    memset(td, 0, sizeof *td);

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    struct ofp14_table_desc *otd = ofpbuf_try_pull(msg, sizeof *otd);
    if (!otd) {
        VLOG_WARN_RL(&rl, "OFP14_TABLE_DESC reply has %"PRIu32" "
                     "leftover bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    td->table_id = otd->table_id;
    size_t length = ntohs(otd->length);
    if (length < sizeof *otd || length - sizeof *otd > msg->size) {
        VLOG_WARN_RL(&rl, "OFP14_TABLE_DESC reply claims invalid "
                     "length %"PRIuSIZE, length);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    length -= sizeof *otd;

    td->eviction = ofputil_decode_table_eviction(otd->config, version);
    td->vacancy = ofputil_decode_table_vacancy(otd->config, version);
    td->eviction_flags = UINT32_MAX;

    struct ofpbuf properties = ofpbuf_const_initializer(
        ofpbuf_pull(msg, length), length);
    while (properties.size > 0) {
        struct ofpbuf payload;
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPTMPT14_EVICTION:
            error = ofpprop_parse_u32(&payload, &td->eviction_flags);
            break;

        case OFPTMPT14_VACANCY:
            error = parse_table_desc_vacancy_property(&payload, td);
            break;

        default:
            error = OFPPROP_UNKNOWN(true, "table_desc", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

/* Encodes and returns a request to obtain description of tables of a switch.
 * The message is encoded for OpenFlow version 'ofp_version'. */
struct ofpbuf *
ofputil_encode_table_desc_request(enum ofp_version ofp_version)
{
    struct ofpbuf *request = NULL;

    if (ofp_version >= OFP14_VERSION) {
        request = ofpraw_alloc(OFPRAW_OFPST14_TABLE_DESC_REQUEST,
                               ofp_version, 0);
    } else {
        ovs_fatal(0, "dump-table-desc needs OpenFlow 1.4 or later "
                  "(\'-O OpenFlow14\')");
    }

    return request;
}

/* Function to append Table desc information in a reply list. */
void
ofputil_append_table_desc_reply(const struct ofputil_table_desc *td,
                                struct ovs_list *replies,
                                enum ofp_version version)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_otd;
    struct ofp14_table_desc *otd;

    start_otd = reply->size;
    ofpbuf_put_zeros(reply, sizeof *otd);
    if (td->eviction_flags != UINT32_MAX) {
        ofpprop_put_u32(reply, OFPTMPT14_EVICTION, td->eviction_flags);
    }
    if (td->vacancy == OFPUTIL_TABLE_VACANCY_ON) {
        struct ofp14_table_mod_prop_vacancy *otv;

        otv = ofpprop_put_zeros(reply, OFPTMPT14_VACANCY, sizeof *otv);
        otv->vacancy_down = td->table_vacancy.vacancy_down;
        otv->vacancy_up = td->table_vacancy.vacancy_up;
        otv->vacancy = td->table_vacancy.vacancy;
    }

    otd = ofpbuf_at_assert(reply, start_otd, sizeof *otd);
    otd->length = htons(reply->size - start_otd);
    otd->table_id = td->table_id;
    otd->config = ofputil_encode_table_config(OFPUTIL_TABLE_MISS_DEFAULT,
                                              td->eviction, td->vacancy,
                                              version);
    ofpmp_postappend(replies, start_otd);
}

static const char *
ofputil_eviction_flag_to_string(uint32_t bit)
{
    enum ofp14_table_mod_prop_eviction_flag eviction_flag = bit;

    switch (eviction_flag) {
    case OFPTMPEF14_OTHER:      return "OTHER";
    case OFPTMPEF14_IMPORTANCE: return "IMPORTANCE";
    case OFPTMPEF14_LIFETIME:   return "LIFETIME";
    }

    return NULL;
}

/* Appends to 'string' a description of the bitmap of OFPTMPEF14_* values in
 * 'eviction_flags'. */
static void
ofputil_put_eviction_flags(struct ds *string, uint32_t eviction_flags)
{
    if (eviction_flags != UINT32_MAX) {
        ofp_print_bit_names(string, eviction_flags,
                            ofputil_eviction_flag_to_string, '|');
    } else {
        ds_put_cstr(string, "(default)");
    }
}

void
ofputil_table_desc_format(struct ds *s, const struct ofputil_table_desc *td,
                          const struct ofputil_table_map *table_map)
{
    ds_put_format(s, "\n  table ");
    ofputil_format_table(td->table_id, table_map, s);
    ds_put_cstr(s, ":\n");
    ds_put_format(s, "   eviction=%s eviction_flags=",
                  ofputil_table_eviction_to_string(td->eviction));
    ofputil_put_eviction_flags(s, td->eviction_flags);
    ds_put_char(s, '\n');
    ds_put_format(s, "   vacancy=%s",
                  ofputil_table_vacancy_to_string(td->vacancy));
    if (td->vacancy == OFPUTIL_TABLE_VACANCY_ON) {
        ds_put_format(s, " vacancy_down=%"PRIu8"%%",
                      td->table_vacancy.vacancy_down);
        ds_put_format(s, " vacancy_up=%"PRIu8"%%",
                      td->table_vacancy.vacancy_up);
        ds_put_format(s, " vacancy=%"PRIu8"%%",
                      td->table_vacancy.vacancy);
    }
    ds_put_char(s, '\n');
}

/* This function parses Vacancy property, and decodes the
 * ofp14_table_mod_prop_vacancy in ofputil_table_mod.
 * Returns OFPERR_OFPBPC_BAD_VALUE error code when vacancy_down is
 * greater than vacancy_up and also when current vacancy has non-zero
 * value. Returns 0 on success. */
static enum ofperr
parse_table_mod_vacancy_property(struct ofpbuf *property,
                                 struct ofputil_table_mod *tm)
{
    struct ofp14_table_mod_prop_vacancy *otv = property->data;

    if (property->size != sizeof *otv) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    tm->table_vacancy.vacancy_down = otv->vacancy_down;
    tm->table_vacancy.vacancy_up = otv->vacancy_up;
    if (tm->table_vacancy.vacancy_down > tm->table_vacancy.vacancy_up) {
        OFPPROP_LOG(&rl, false,
                    "Value of vacancy_down is greater than vacancy_up");
        return OFPERR_OFPBPC_BAD_VALUE;
    }
    if (tm->table_vacancy.vacancy_down > 100 ||
        tm->table_vacancy.vacancy_up > 100) {
        OFPPROP_LOG(&rl, false, "Vacancy threshold percentage "
                    "should not be greater than 100");
        return OFPERR_OFPBPC_BAD_VALUE;
    }
    tm->table_vacancy.vacancy = otv->vacancy;
    if (tm->table_vacancy.vacancy) {
        OFPPROP_LOG(&rl, false,
                    "Vacancy value should be zero for table-mod messages");
        return OFPERR_OFPBPC_BAD_VALUE;
    }
    return 0;
}

/* Given 'config', taken from an OpenFlow 'version' message that specifies
 * table configuration (a table mod, table stats, or table features message),
 * returns the table vacancy configuration that it specifies.
 *
 * Only OpenFlow 1.4 and later specify table vacancy configuration this way,
 * so for other 'version' this function always returns
 * OFPUTIL_TABLE_VACANCY_DEFAULT. */
static enum ofputil_table_vacancy
ofputil_decode_table_vacancy(ovs_be32 config, enum ofp_version version)
{
    return (version < OFP14_VERSION ? OFPUTIL_TABLE_VACANCY_DEFAULT
            : config & htonl(OFPTC14_VACANCY_EVENTS) ? OFPUTIL_TABLE_VACANCY_ON
            : OFPUTIL_TABLE_VACANCY_OFF);
}

/* Given 'config', taken from an OpenFlow 'version' message that specifies
 * table configuration (a table mod, table stats, or table features message),
 * returns the table eviction configuration that it specifies.
 *
 * Only OpenFlow 1.4 and later specify table eviction configuration this way,
 * so for other 'version' values this function always returns
 * OFPUTIL_TABLE_EVICTION_DEFAULT. */
static enum ofputil_table_eviction
ofputil_decode_table_eviction(ovs_be32 config, enum ofp_version version)
{
    return (version < OFP14_VERSION ? OFPUTIL_TABLE_EVICTION_DEFAULT
            : config & htonl(OFPTC14_EVICTION) ? OFPUTIL_TABLE_EVICTION_ON
            : OFPUTIL_TABLE_EVICTION_OFF);
}

/* Returns a bitmap of OFPTC* values suitable for 'config' fields in various
 * OpenFlow messages of the given 'version', based on the provided 'miss' and
 * 'eviction' values. */
static ovs_be32
ofputil_encode_table_config(enum ofputil_table_miss miss,
                            enum ofputil_table_eviction eviction,
                            enum ofputil_table_vacancy vacancy,
                            enum ofp_version version)
{
    uint32_t config = 0;
    /* Search for "OFPTC_* Table Configuration" in the documentation for more
     * information on the crazy evolution of this field. */
    switch (version) {
    case OFP10_VERSION:
        /* OpenFlow 1.0 didn't have such a field, any value ought to do. */
        return htonl(0);

    case OFP11_VERSION:
    case OFP12_VERSION:
        /* OpenFlow 1.1 and 1.2 define only OFPTC11_TABLE_MISS_*. */
        switch (miss) {
        case OFPUTIL_TABLE_MISS_DEFAULT:
            /* Really this shouldn't be used for encoding (the caller should
             * provide a specific value) but I can't imagine that defaulting to
             * the fall-through case here will hurt. */
        case OFPUTIL_TABLE_MISS_CONTROLLER:
        default:
            return htonl(OFPTC11_TABLE_MISS_CONTROLLER);
        case OFPUTIL_TABLE_MISS_CONTINUE:
            return htonl(OFPTC11_TABLE_MISS_CONTINUE);
        case OFPUTIL_TABLE_MISS_DROP:
            return htonl(OFPTC11_TABLE_MISS_DROP);
        }
        OVS_NOT_REACHED();

    case OFP13_VERSION:
        /* OpenFlow 1.3 removed OFPTC11_TABLE_MISS_* and didn't define any new
         * flags, so this is correct. */
        return htonl(0);

    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        /* OpenFlow 1.4 introduced OFPTC14_EVICTION and
         * OFPTC14_VACANCY_EVENTS. */
        if (eviction == OFPUTIL_TABLE_EVICTION_ON) {
            config |= OFPTC14_EVICTION;
        }
        if (vacancy == OFPUTIL_TABLE_VACANCY_ON) {
            config |= OFPTC14_VACANCY_EVENTS;
        }
        return htonl(config);
    }

    OVS_NOT_REACHED();
}

/* Given 'config', taken from an OpenFlow 'version' message that specifies
 * table configuration (a table mod, table stats, or table features message),
 * returns the table miss configuration that it specifies.
 *
 * Only OpenFlow 1.1 and 1.2 specify table miss configurations this way, so for
 * other 'version' values this function always returns
 * OFPUTIL_TABLE_MISS_DEFAULT. */
static enum ofputil_table_miss
ofputil_decode_table_miss(ovs_be32 config_, enum ofp_version version)
{
    uint32_t config = ntohl(config_);

    if (version == OFP11_VERSION || version == OFP12_VERSION) {
        switch (config & OFPTC11_TABLE_MISS_MASK) {
        case OFPTC11_TABLE_MISS_CONTROLLER:
            return OFPUTIL_TABLE_MISS_CONTROLLER;

        case OFPTC11_TABLE_MISS_CONTINUE:
            return OFPUTIL_TABLE_MISS_CONTINUE;

        case OFPTC11_TABLE_MISS_DROP:
            return OFPUTIL_TABLE_MISS_DROP;

        default:
            VLOG_WARN_RL(&rl, "bad table miss config %d", config);
            return OFPUTIL_TABLE_MISS_CONTROLLER;
        }
    } else {
        return OFPUTIL_TABLE_MISS_DEFAULT;
    }
}

/* Decodes the OpenFlow "table mod" message in '*oh' into an abstract form in
 * '*pm'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_table_mod(const struct ofp_header *oh,
                         struct ofputil_table_mod *pm)
{
    memset(pm, 0, sizeof *pm);
    pm->miss = OFPUTIL_TABLE_MISS_DEFAULT;
    pm->eviction = OFPUTIL_TABLE_EVICTION_DEFAULT;
    pm->eviction_flags = UINT32_MAX;
    pm->vacancy = OFPUTIL_TABLE_VACANCY_DEFAULT;

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT11_TABLE_MOD) {
        const struct ofp11_table_mod *otm = b.data;

        pm->table_id = otm->table_id;
        pm->miss = ofputil_decode_table_miss(otm->config, oh->version);
    } else if (raw == OFPRAW_OFPT14_TABLE_MOD) {
        const struct ofp14_table_mod *otm = ofpbuf_pull(&b, sizeof *otm);

        pm->table_id = otm->table_id;
        pm->miss = ofputil_decode_table_miss(otm->config, oh->version);
        pm->eviction = ofputil_decode_table_eviction(otm->config, oh->version);
        pm->vacancy = ofputil_decode_table_vacancy(otm->config, oh->version);
        while (b.size > 0) {
            struct ofpbuf property;
            enum ofperr error;
            uint64_t type;

            error = ofpprop_pull(&b, &property, &type);
            if (error) {
                return error;
            }

            switch (type) {
            case OFPTMPT14_EVICTION:
                error = ofpprop_parse_u32(&property, &pm->eviction);
                break;

            case OFPTMPT14_VACANCY:
                error = parse_table_mod_vacancy_property(&property, pm);
                break;

            default:
                error = OFPERR_OFPBRC_BAD_TYPE;
                break;
            }

            if (error) {
                return error;
            }
        }
    } else {
        return OFPERR_OFPBRC_BAD_TYPE;
    }

    return 0;
}

/* Converts the abstract form of a "table mod" message in '*tm' into an
 * OpenFlow message suitable for 'protocol', and returns that encoded form in a
 * buffer owned by the caller. */
struct ofpbuf *
ofputil_encode_table_mod(const struct ofputil_table_mod *tm,
                        enum ofputil_protocol protocol)
{
    enum ofp_version ofp_version = ofputil_protocol_to_ofp_version(protocol);
    struct ofpbuf *b;

    switch (ofp_version) {
    case OFP10_VERSION: {
        ovs_fatal(0, "table mod needs OpenFlow 1.1 or later "
                     "(\'-O OpenFlow11\')");
        break;
    }
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        struct ofp11_table_mod *otm;

        b = ofpraw_alloc(OFPRAW_OFPT11_TABLE_MOD, ofp_version, 0);
        otm = ofpbuf_put_zeros(b, sizeof *otm);
        otm->table_id = tm->table_id;
        otm->config = ofputil_encode_table_config(tm->miss, tm->eviction,
                                                  tm->vacancy, ofp_version);
        break;
    }
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp14_table_mod *otm;

        b = ofpraw_alloc(OFPRAW_OFPT14_TABLE_MOD, ofp_version, 0);
        otm = ofpbuf_put_zeros(b, sizeof *otm);
        otm->table_id = tm->table_id;
        otm->config = ofputil_encode_table_config(tm->miss, tm->eviction,
                                                  tm->vacancy, ofp_version);

        if (tm->eviction_flags != UINT32_MAX) {
            ofpprop_put_u32(b, OFPTMPT14_EVICTION, tm->eviction_flags);
        }
        if (tm->vacancy == OFPUTIL_TABLE_VACANCY_ON) {
            struct ofp14_table_mod_prop_vacancy *otv;

            otv = ofpprop_put_zeros(b, OFPTMPT14_VACANCY, sizeof *otv);
            otv->vacancy_down = tm->table_vacancy.vacancy_down;
            otv->vacancy_up = tm->table_vacancy.vacancy_up;
        }
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return b;
}

void
ofputil_table_mod_format(struct ds *s, const struct ofputil_table_mod *tm,
                         const struct ofputil_table_map *table_map)
{
    if (tm->table_id == 0xff) {
        ds_put_cstr(s, " table_id: ALL_TABLES");
    } else {
        ds_put_format(s, " table_id=");
        ofputil_format_table(tm->table_id, table_map, s);
    }

    if (tm->miss != OFPUTIL_TABLE_MISS_DEFAULT) {
        ds_put_format(s, ", flow_miss_config=%s",
                      ofputil_table_miss_to_string(tm->miss));
    }
    if (tm->eviction != OFPUTIL_TABLE_EVICTION_DEFAULT) {
        ds_put_format(s, ", eviction=%s",
                      ofputil_table_eviction_to_string(tm->eviction));
    }
    if (tm->eviction_flags != UINT32_MAX) {
        ds_put_cstr(s, "eviction_flags=");
        ofputil_put_eviction_flags(s, tm->eviction_flags);
    }
    if (tm->vacancy != OFPUTIL_TABLE_VACANCY_DEFAULT) {
        ds_put_format(s, ", vacancy=%s",
                      ofputil_table_vacancy_to_string(tm->vacancy));
        if (tm->vacancy == OFPUTIL_TABLE_VACANCY_ON) {
            ds_put_format(s, " vacancy:%"PRIu8""
                          ",%"PRIu8"", tm->table_vacancy.vacancy_down,
                          tm->table_vacancy.vacancy_up);
        }
    }
}

/* Convert 'setting' (as described for the "mod-table" command
 * in ovs-ofctl man page) into 'tm->table_vacancy->vacancy_up' and
 * 'tm->table_vacancy->vacancy_down' threshold values.
 * For the two threshold values, value of vacancy_up is always greater
 * than value of vacancy_down.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
parse_ofp_table_vacancy(struct ofputil_table_mod *tm, const char *setting)
{
    char *save_ptr = NULL;
    char *vac_up, *vac_down;
    char *value = xstrdup(setting);
    char *ret_msg;
    int vacancy_up, vacancy_down;

    strtok_r(value, ":", &save_ptr);
    vac_down = strtok_r(NULL, ",", &save_ptr);
    if (!vac_down) {
        ret_msg = xasprintf("Vacancy down value missing");
        goto exit;
    }
    if (!str_to_int(vac_down, 0, &vacancy_down) ||
        vacancy_down < 0 || vacancy_down > 100) {
        ret_msg = xasprintf("Invalid vacancy down value \"%s\"", vac_down);
        goto exit;
    }
    vac_up = strtok_r(NULL, ",", &save_ptr);
    if (!vac_up) {
        ret_msg = xasprintf("Vacancy up value missing");
        goto exit;
    }
    if (!str_to_int(vac_up, 0, &vacancy_up) ||
        vacancy_up < 0 || vacancy_up > 100) {
        ret_msg = xasprintf("Invalid vacancy up value \"%s\"", vac_up);
        goto exit;
    }
    if (vacancy_down > vacancy_up) {
        ret_msg = xasprintf("Invalid vacancy range, vacancy up should be "
                            "greater than vacancy down (%s)",
                            ofperr_to_string(OFPERR_OFPBPC_BAD_VALUE));
        goto exit;
    }

    free(value);
    tm->table_vacancy.vacancy_down = vacancy_down;
    tm->table_vacancy.vacancy_up = vacancy_up;
    return NULL;

exit:
    free(value);
    return ret_msg;
}

/* Convert 'table_id' and 'setting' (as described for the "mod-table" command
 * in the ovs-ofctl man page) into 'tm' for sending a table_mod command to a
 * switch.
 *
 * Stores a bitmap of the OpenFlow versions that are usable for 'tm' into
 * '*usable_versions'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_table_mod(struct ofputil_table_mod *tm, const char *table_id,
                    const char *setting,
                    const struct ofputil_table_map *table_map,
                    uint32_t *usable_versions)
{
    *usable_versions = 0;
    if (!strcasecmp(table_id, "all")) {
        tm->table_id = OFPTT_ALL;
    } else if (!ofputil_table_from_string(table_id, table_map,
                                          &tm->table_id)) {
        return xasprintf("unknown table \"%s\"", table_id);
    }

    tm->miss = OFPUTIL_TABLE_MISS_DEFAULT;
    tm->eviction = OFPUTIL_TABLE_EVICTION_DEFAULT;
    tm->eviction_flags = UINT32_MAX;
    tm->vacancy = OFPUTIL_TABLE_VACANCY_DEFAULT;
    tm->table_vacancy.vacancy_down = 0;
    tm->table_vacancy.vacancy_up = 0;
    tm->table_vacancy.vacancy = 0;
    /* Only OpenFlow 1.1 and 1.2 can configure table-miss via table_mod.
     * Only OpenFlow 1.4+ can configure eviction and vacancy events
     * via table_mod.
     */
    if (!strcmp(setting, "controller")) {
        tm->miss = OFPUTIL_TABLE_MISS_CONTROLLER;
        *usable_versions = (1u << OFP11_VERSION) | (1u << OFP12_VERSION);
    } else if (!strcmp(setting, "continue")) {
        tm->miss = OFPUTIL_TABLE_MISS_CONTINUE;
        *usable_versions = (1u << OFP11_VERSION) | (1u << OFP12_VERSION);
    } else if (!strcmp(setting, "drop")) {
        tm->miss = OFPUTIL_TABLE_MISS_DROP;
        *usable_versions = (1u << OFP11_VERSION) | (1u << OFP12_VERSION);
    } else if (!strcmp(setting, "evict")) {
        tm->eviction = OFPUTIL_TABLE_EVICTION_ON;
        *usable_versions = (1 << OFP14_VERSION) | (1u << OFP15_VERSION);
    } else if (!strcmp(setting, "noevict")) {
        tm->eviction = OFPUTIL_TABLE_EVICTION_OFF;
        *usable_versions = (1 << OFP14_VERSION) | (1u << OFP15_VERSION);
    } else if (!strncmp(setting, "vacancy", strcspn(setting, ":"))) {
        tm->vacancy = OFPUTIL_TABLE_VACANCY_ON;
        *usable_versions = (1 << OFP14_VERSION) | (1u << OFP15_VERSION);
        char *error = parse_ofp_table_vacancy(tm, setting);
        if (error) {
            return error;
        }
    } else if (!strcmp(setting, "novacancy")) {
        tm->vacancy = OFPUTIL_TABLE_VACANCY_OFF;
        *usable_versions = (1 << OFP14_VERSION) | (1u << OFP15_VERSION);
    } else {
        return xasprintf("invalid table_mod setting %s", setting);
    }

    if (tm->table_id == 0xfe
        && tm->miss == OFPUTIL_TABLE_MISS_CONTINUE) {
        return xstrdup("last table's flow miss handling can not be continue");
    }

    return NULL;
}

static void
print_table_action_features(struct ds *s,
                            const struct ofputil_table_action_features *taf)
{
    if (taf->ofpacts) {
        ds_put_cstr(s, "        actions: ");
        ofpact_bitmap_format(taf->ofpacts, s);
        ds_put_char(s, '\n');
    }

    if (!bitmap_is_all_zeros(taf->set_fields.bm, MFF_N_IDS)) {
        int i;

        ds_put_cstr(s, "        supported on Set-Field:");
        BITMAP_FOR_EACH_1 (i, MFF_N_IDS, taf->set_fields.bm) {
            ds_put_format(s, " %s", mf_from_id(i)->name);
        }
        ds_put_char(s, '\n');
    }
}

static bool
table_action_features_equal(const struct ofputil_table_action_features *a,
                            const struct ofputil_table_action_features *b)
{
    return (a->ofpacts == b->ofpacts
            && bitmap_equal(a->set_fields.bm, b->set_fields.bm, MFF_N_IDS));
}

static bool
table_action_features_empty(const struct ofputil_table_action_features *taf)
{
    return !taf->ofpacts && bitmap_is_all_zeros(taf->set_fields.bm, MFF_N_IDS);
}

static void
print_table_instruction_features(
    struct ds *s,
    const struct ofputil_table_instruction_features *tif,
    const struct ofputil_table_instruction_features *prev_tif)
{
    int start, end;

    if (!bitmap_is_all_zeros(tif->next, 255)) {
        ds_put_cstr(s, "      next tables: ");
        for (start = bitmap_scan(tif->next, 1, 0, 255); start < 255;
             start = bitmap_scan(tif->next, 1, end, 255)) {
            end = bitmap_scan(tif->next, 0, start + 1, 255);
            if (end == start + 1) {
                ds_put_format(s, "%d,", start);
            } else {
                ds_put_format(s, "%d-%d,", start, end - 1);
            }
        }
        ds_chomp(s, ',');
        if (ds_last(s) == ' ') {
            ds_put_cstr(s, "none");
        }
        ds_put_char(s, '\n');
    }

    if (tif->instructions) {
        if (prev_tif && tif->instructions == prev_tif->instructions) {
            ds_put_cstr(s, "      (same instructions)\n");
        } else {
            ds_put_cstr(s, "      instructions: ");
            int i;

            for (i = 0; i < 32; i++) {
                if (tif->instructions & (1u << i)) {
                    const char *name = ovs_instruction_name_from_type(i);
                    if (name) {
                        ds_put_cstr(s, name);
                    } else {
                        ds_put_format(s, "%d", i);
                    }
                    ds_put_char(s, ',');
                }
            }
            ds_chomp(s, ',');
            ds_put_char(s, '\n');
        }
    }

    if (prev_tif
        && table_action_features_equal(&tif->write, &prev_tif->write)
        && table_action_features_equal(&tif->apply, &prev_tif->apply)
        && !bitmap_is_all_zeros(tif->write.set_fields.bm, MFF_N_IDS)) {
        ds_put_cstr(s, "      (same actions)\n");
    } else if (!table_action_features_equal(&tif->write, &tif->apply)) {
        ds_put_cstr(s, "      Write-Actions features:\n");
        print_table_action_features(s, &tif->write);
        ds_put_cstr(s, "      Apply-Actions features:\n");
        print_table_action_features(s, &tif->apply);
    } else if (tif->write.ofpacts
               || !bitmap_is_all_zeros(tif->write.set_fields.bm, MFF_N_IDS)) {
        ds_put_cstr(s, "      Write-Actions and Apply-Actions features:\n");
        print_table_action_features(s, &tif->write);
    }
}

/* Compares bitmaps of next tables 'a' and 'b', for tables 'a_table_id' and
 * 'b_table_id', respectively.  Returns true if the bitmaps are equal.
 *
 * The bitmaps are considered equal if b_table_id == a_table_id + 1 and the bit
 * for 'b_table_id' is set in 'a' but not in 'b'.  This is because OpenFlow
 * requires that a table not be able to do a goto_table back to its own table
 * or an earlier one.  Without considering these equivalent, every table will
 * be different from every one in some way, which just isn't useful in printing
 * table features. */
static bool
table_instruction_features_next_equal(const unsigned long *a, int a_table_id,
                                      const unsigned long *b, int b_table_id)
{
    if (b_table_id == a_table_id + 1
        && bitmap_is_set(a, b_table_id)
        && !bitmap_is_set(b, b_table_id)) {
        for (size_t i = 0; i < BITMAP_N_LONGS(255); i++) {
            unsigned long diff = a[i] ^ b[i];
            if (i == b_table_id / BITMAP_ULONG_BITS) {
                diff &= ~bitmap_bit__(b_table_id);
            }
            if (diff) {
                return false;
            }
        }
        return true;
    } else if (a_table_id == b_table_id + 1) {
        return table_instruction_features_next_equal(b, b_table_id,
                                                     a, a_table_id);
    } else {
        return bitmap_equal(a, b, 255);
    }
}

static bool
table_instruction_features_equal(
    const struct ofputil_table_instruction_features *a, int a_table_id,
    const struct ofputil_table_instruction_features *b, int b_table_id)
{
    return (table_instruction_features_next_equal(a->next, a_table_id,
                                                  b->next, b_table_id)
            && a->instructions == b->instructions
            && table_action_features_equal(&a->write, &b->write)
            && table_action_features_equal(&a->apply, &b->apply));
}

static bool
table_instruction_features_empty(
    const struct ofputil_table_instruction_features *tif)
{
    return (bitmap_is_all_zeros(tif->next, 255)
            && !tif->instructions
            && table_action_features_empty(&tif->write)
            && table_action_features_empty(&tif->apply));
}

static bool
table_features_equal(const struct ofputil_table_features *a,
                     const struct ofputil_table_features *b)
{
    return (a->metadata_match == b->metadata_match
            && a->metadata_write == b->metadata_write
            && a->miss_config == b->miss_config
            && a->supports_eviction == b->supports_eviction
            && a->supports_vacancy_events == b->supports_vacancy_events
            && a->max_entries == b->max_entries
            && table_instruction_features_equal(&a->nonmiss, a->table_id,
                                                &b->nonmiss, b->table_id)
            && table_instruction_features_equal(&a->miss, a->table_id,
                                                &b->miss, b->table_id)
            && bitmap_equal(a->match.bm, b->match.bm, MFF_N_IDS));
}

static bool
table_features_empty(const struct ofputil_table_features *tf)
{
    return (!tf->metadata_match
            && !tf->metadata_write
            && tf->miss_config == OFPUTIL_TABLE_MISS_DEFAULT
            && tf->supports_eviction < 0
            && tf->supports_vacancy_events < 0
            && !tf->max_entries
            && table_instruction_features_empty(&tf->nonmiss)
            && table_instruction_features_empty(&tf->miss)
            && bitmap_is_all_zeros(tf->match.bm, MFF_N_IDS));
}

static bool
table_stats_equal(const struct ofputil_table_stats *a,
                  const struct ofputil_table_stats *b)
{
    return (a->active_count == b->active_count
            && a->lookup_count == b->lookup_count
            && a->matched_count == b->matched_count);
}

void
ofputil_table_features_format(
    struct ds *s,
    const struct ofputil_table_features *features,
    const struct ofputil_table_features *prev_features,
    const struct ofputil_table_stats *stats,
    const struct ofputil_table_stats *prev_stats,
    int *first_ditto, int *last_ditto)
{
    int table = features->table_id;
    int prev_table = prev_features ? prev_features->table_id : 0;

    bool same_stats = !stats || (prev_stats
                                 && table_stats_equal(stats, prev_stats));
    bool same_features = prev_features && table_features_equal(features,
                                                               prev_features);
    if (same_stats && same_features && !features->name[0]) {
        if (*first_ditto < 0) {
            *first_ditto = table;
        }
        *last_ditto = table;
        return;
    }
    ofputil_table_features_format_finish(s, *first_ditto, *last_ditto);
    *first_ditto = -1;

    ds_put_format(s, "\n  table %d", table);
    if (features->name[0]) {
        ds_put_format(s, " (\"%s\")", features->name);
    }
    ds_put_char(s, ':');

    if (same_stats && same_features) {
        ds_put_cstr(s, " ditto");
        return;
    }
    ds_put_char(s, '\n');
    if (stats) {
        ds_put_format(s, "    active=%"PRIu32", ", stats->active_count);
        ds_put_format(s, "lookup=%"PRIu64", ", stats->lookup_count);
        ds_put_format(s, "matched=%"PRIu64"\n", stats->matched_count);
    }
    if (same_features) {
        if (!table_features_empty(features)) {
            ds_put_cstr(s, "    (same features)\n");
        }
        return;
    }
    if (features->metadata_match || features->metadata_write) {
        ds_put_format(s, "    metadata: match=%#"PRIx64" write=%#"PRIx64"\n",
                      ntohll(features->metadata_match),
                      ntohll(features->metadata_write));
    }

    if (features->miss_config != OFPUTIL_TABLE_MISS_DEFAULT) {
        ds_put_format(s, "    config=%s\n",
                      ofputil_table_miss_to_string(features->miss_config));
    }

    if (features->supports_eviction >= 0) {
        ds_put_format(s, "    eviction: %ssupported\n",
                      features->supports_eviction ? "" : "not ");

    }
    if (features->supports_vacancy_events >= 0) {
        ds_put_format(s, "    vacancy events: %ssupported\n",
                      features->supports_vacancy_events ? "" : "not ");

    }

    if (features->max_entries) {
        ds_put_format(s, "    max_entries=%"PRIu32"\n", features->max_entries);
    }

    const struct ofputil_table_instruction_features *prev_nonmiss
        = prev_features ? &prev_features->nonmiss : NULL;
    const struct ofputil_table_instruction_features *prev_miss
        = prev_features ? &prev_features->miss : NULL;
    if (prev_features
        && table_instruction_features_equal(&features->nonmiss, table,
                                            prev_nonmiss, prev_table)
        && table_instruction_features_equal(&features->miss, table,
                                            prev_miss, prev_table)) {
        if (!table_instruction_features_empty(&features->nonmiss)) {
            ds_put_cstr(s, "    (same instructions)\n");
        }
    } else if (!table_instruction_features_equal(&features->nonmiss, table,
                                                 &features->miss, table)) {
        ds_put_cstr(s, "    instructions (other than table miss):\n");
        print_table_instruction_features(s, &features->nonmiss, prev_nonmiss);
        ds_put_cstr(s, "    instructions (table miss):\n");
        print_table_instruction_features(s, &features->miss, prev_miss);
    } else if (!table_instruction_features_empty(&features->nonmiss)) {
        ds_put_cstr(s, "    instructions (table miss and others):\n");
        print_table_instruction_features(s, &features->nonmiss, prev_nonmiss);
    }

    if (!bitmap_is_all_zeros(features->match.bm, MFF_N_IDS)) {
        if (prev_features
            && bitmap_equal(features->match.bm, prev_features->match.bm,
                            MFF_N_IDS)) {
            ds_put_cstr(s, "    (same matching)\n");
        } else {
            ds_put_cstr(s, "    matching:\n");

            int i;
            BITMAP_FOR_EACH_1 (i, MFF_N_IDS, features->match.bm) {
                const struct mf_field *f = mf_from_id(i);
                bool mask = bitmap_is_set(features->mask.bm, i);
                bool wildcard = bitmap_is_set(features->wildcard.bm, i);

                ds_put_format(s, "      %s: %s\n",
                              f->name,
                              (mask ? "arbitrary mask"
                               : wildcard ? "exact match or wildcard"
                               : "must exact match"));
            }
        }
    }
}

void
ofputil_table_features_format_finish(struct ds *s,
                                     int first_ditto, int last_ditto)
{
    if (first_ditto < 0) {
        return;
    }

    ds_put_char(s, '\n');
    if (first_ditto == last_ditto) {
        ds_put_format(s, "  table %d: ditto\n", first_ditto);
    } else {
        ds_put_format(s, "  tables %d...%d: ditto\n", first_ditto, last_ditto);
    }
}

/* Table stats. */

/* OpenFlow 1.0 and 1.1 don't distinguish between a field that cannot be
 * matched and a field that must be wildcarded.  This function returns a bitmap
 * that contains both kinds of fields. */
static struct mf_bitmap
wild_or_nonmatchable_fields(const struct ofputil_table_features *features)
{
    struct mf_bitmap wc = features->match;
    bitmap_not(wc.bm, MFF_N_IDS);
    bitmap_or(wc.bm, features->wildcard.bm, MFF_N_IDS);
    return wc;
}

struct ofp10_wc_map {
    enum ofp10_flow_wildcards wc10;
    enum mf_field_id mf;
};

static const struct ofp10_wc_map ofp10_wc_map[] = {
    { OFPFW10_IN_PORT,     MFF_IN_PORT },
    { OFPFW10_DL_VLAN,     MFF_VLAN_VID },
    { OFPFW10_DL_SRC,      MFF_ETH_SRC },
    { OFPFW10_DL_DST,      MFF_ETH_DST},
    { OFPFW10_DL_TYPE,     MFF_ETH_TYPE },
    { OFPFW10_NW_PROTO,    MFF_IP_PROTO },
    { OFPFW10_TP_SRC,      MFF_TCP_SRC },
    { OFPFW10_TP_DST,      MFF_TCP_DST },
    { OFPFW10_NW_SRC_MASK, MFF_IPV4_SRC },
    { OFPFW10_NW_DST_MASK, MFF_IPV4_DST },
    { OFPFW10_DL_VLAN_PCP, MFF_VLAN_PCP },
    { OFPFW10_NW_TOS,      MFF_IP_DSCP },
};

static ovs_be32
mf_bitmap_to_of10(const struct mf_bitmap *fields)
{
    const struct ofp10_wc_map *p;
    uint32_t wc10 = 0;

    for (p = ofp10_wc_map; p < &ofp10_wc_map[ARRAY_SIZE(ofp10_wc_map)]; p++) {
        if (bitmap_is_set(fields->bm, p->mf)) {
            wc10 |= p->wc10;
        }
    }
    return htonl(wc10);
}

static struct mf_bitmap
mf_bitmap_from_of10(ovs_be32 wc10_)
{
    struct mf_bitmap fields = MF_BITMAP_INITIALIZER;
    const struct ofp10_wc_map *p;
    uint32_t wc10 = ntohl(wc10_);

    for (p = ofp10_wc_map; p < &ofp10_wc_map[ARRAY_SIZE(ofp10_wc_map)]; p++) {
        if (wc10 & p->wc10) {
            bitmap_set1(fields.bm, p->mf);
        }
    }
    return fields;
}

static void
ofputil_put_ofp10_table_stats(const struct ofputil_table_stats *stats,
                              const struct ofputil_table_features *features,
                              struct ofpbuf *buf)
{
    struct mf_bitmap wc = wild_or_nonmatchable_fields(features);
    struct ofp10_table_stats *out;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = features->table_id;
    ovs_strlcpy_arrays(out->name, features->name);
    out->wildcards = mf_bitmap_to_of10(&wc);
    out->max_entries = htonl(features->max_entries);
    out->active_count = htonl(stats->active_count);
    put_32aligned_be64(&out->lookup_count, htonll(stats->lookup_count));
    put_32aligned_be64(&out->matched_count, htonll(stats->matched_count));
}

struct ofp11_wc_map {
    enum ofp11_flow_match_fields wc11;
    enum mf_field_id mf;
};

static const struct ofp11_wc_map ofp11_wc_map[] = {
    { OFPFMF11_IN_PORT,     MFF_IN_PORT },
    { OFPFMF11_DL_VLAN,     MFF_VLAN_VID },
    { OFPFMF11_DL_VLAN_PCP, MFF_VLAN_PCP },
    { OFPFMF11_DL_TYPE,     MFF_ETH_TYPE },
    { OFPFMF11_NW_TOS,      MFF_IP_DSCP },
    { OFPFMF11_NW_PROTO,    MFF_IP_PROTO },
    { OFPFMF11_TP_SRC,      MFF_TCP_SRC },
    { OFPFMF11_TP_DST,      MFF_TCP_DST },
    { OFPFMF11_MPLS_LABEL,  MFF_MPLS_LABEL },
    { OFPFMF11_MPLS_TC,     MFF_MPLS_TC },
    /* I don't know what OFPFMF11_TYPE means. */
    { OFPFMF11_DL_SRC,      MFF_ETH_SRC },
    { OFPFMF11_DL_DST,      MFF_ETH_DST },
    { OFPFMF11_NW_SRC,      MFF_IPV4_SRC },
    { OFPFMF11_NW_DST,      MFF_IPV4_DST },
    { OFPFMF11_METADATA,    MFF_METADATA },
};

static ovs_be32
mf_bitmap_to_of11(const struct mf_bitmap *fields)
{
    const struct ofp11_wc_map *p;
    uint32_t wc11 = 0;

    for (p = ofp11_wc_map; p < &ofp11_wc_map[ARRAY_SIZE(ofp11_wc_map)]; p++) {
        if (bitmap_is_set(fields->bm, p->mf)) {
            wc11 |= p->wc11;
        }
    }
    return htonl(wc11);
}

static struct mf_bitmap
mf_bitmap_from_of11(ovs_be32 wc11_)
{
    struct mf_bitmap fields = MF_BITMAP_INITIALIZER;
    const struct ofp11_wc_map *p;
    uint32_t wc11 = ntohl(wc11_);

    for (p = ofp11_wc_map; p < &ofp11_wc_map[ARRAY_SIZE(ofp11_wc_map)]; p++) {
        if (wc11 & p->wc11) {
            bitmap_set1(fields.bm, p->mf);
        }
    }
    return fields;
}

static void
ofputil_put_ofp11_table_stats(const struct ofputil_table_stats *stats,
                              const struct ofputil_table_features *features,
                              struct ofpbuf *buf)
{
    struct mf_bitmap wc = wild_or_nonmatchable_fields(features);
    struct ofp11_table_stats *out;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = features->table_id;
    ovs_strlcpy_arrays(out->name, features->name);
    out->wildcards = mf_bitmap_to_of11(&wc);
    out->match = mf_bitmap_to_of11(&features->match);
    out->instructions = ovsinst_bitmap_to_openflow(
        features->nonmiss.instructions, OFP11_VERSION);
    out->write_actions = ofpact_bitmap_to_openflow(
        features->nonmiss.write.ofpacts, OFP11_VERSION);
    out->apply_actions = ofpact_bitmap_to_openflow(
        features->nonmiss.apply.ofpacts, OFP11_VERSION);
    out->config = htonl(features->miss_config);
    out->max_entries = htonl(features->max_entries);
    out->active_count = htonl(stats->active_count);
    out->lookup_count = htonll(stats->lookup_count);
    out->matched_count = htonll(stats->matched_count);
}

static void
ofputil_put_ofp12_table_stats(const struct ofputil_table_stats *stats,
                              const struct ofputil_table_features *features,
                              struct ofpbuf *buf)
{
    struct ofp12_table_stats *out;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = features->table_id;
    ovs_strlcpy_arrays(out->name, features->name);
    out->match = oxm_bitmap_from_mf_bitmap(&features->match, OFP12_VERSION);
    out->wildcards = oxm_bitmap_from_mf_bitmap(&features->wildcard,
                                             OFP12_VERSION);
    out->write_actions = ofpact_bitmap_to_openflow(
        features->nonmiss.write.ofpacts, OFP12_VERSION);
    out->apply_actions = ofpact_bitmap_to_openflow(
        features->nonmiss.apply.ofpacts, OFP12_VERSION);
    out->write_setfields = oxm_bitmap_from_mf_bitmap(
        &features->nonmiss.write.set_fields, OFP12_VERSION);
    out->apply_setfields = oxm_bitmap_from_mf_bitmap(
        &features->nonmiss.apply.set_fields, OFP12_VERSION);
    out->metadata_match = features->metadata_match;
    out->metadata_write = features->metadata_write;
    out->instructions = ovsinst_bitmap_to_openflow(
        features->nonmiss.instructions, OFP12_VERSION);
    out->config = ofputil_encode_table_config(features->miss_config,
                                              OFPUTIL_TABLE_EVICTION_DEFAULT,
                                              OFPUTIL_TABLE_VACANCY_DEFAULT,
                                              OFP12_VERSION);
    out->max_entries = htonl(features->max_entries);
    out->active_count = htonl(stats->active_count);
    out->lookup_count = htonll(stats->lookup_count);
    out->matched_count = htonll(stats->matched_count);
}

static void
ofputil_put_ofp13_table_stats(const struct ofputil_table_stats *stats,
                              struct ofpbuf *buf)
{
    struct ofp13_table_stats *out;

    out = ofpbuf_put_zeros(buf, sizeof *out);
    out->table_id = stats->table_id;
    out->active_count = htonl(stats->active_count);
    out->lookup_count = htonll(stats->lookup_count);
    out->matched_count = htonll(stats->matched_count);
}

struct ofpbuf *
ofputil_encode_table_stats_reply(const struct ofp_header *request)
{
    return ofpraw_alloc_stats_reply(request, 0);
}

void
ofputil_append_table_stats_reply(struct ofpbuf *reply,
                                 const struct ofputil_table_stats *stats,
                                 const struct ofputil_table_features *features)
{
    struct ofp_header *oh = reply->header;

    ovs_assert(stats->table_id == features->table_id);

    switch ((enum ofp_version) oh->version) {
    case OFP10_VERSION:
        ofputil_put_ofp10_table_stats(stats, features, reply);
        break;

    case OFP11_VERSION:
        ofputil_put_ofp11_table_stats(stats, features, reply);
        break;

    case OFP12_VERSION:
        ofputil_put_ofp12_table_stats(stats, features, reply);
        break;

    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        ofputil_put_ofp13_table_stats(stats, reply);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static int
ofputil_decode_ofp10_table_stats(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    struct ofp10_table_stats *ots;

    ots = ofpbuf_try_pull(msg, sizeof *ots);
    if (!ots) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    features->table_id = ots->table_id;
    ovs_strlcpy_arrays(features->name, ots->name);
    features->max_entries = ntohl(ots->max_entries);
    features->match = features->wildcard = mf_bitmap_from_of10(ots->wildcards);

    stats->table_id = ots->table_id;
    stats->active_count = ntohl(ots->active_count);
    stats->lookup_count = ntohll(get_32aligned_be64(&ots->lookup_count));
    stats->matched_count = ntohll(get_32aligned_be64(&ots->matched_count));

    return 0;
}

static int
ofputil_decode_ofp11_table_stats(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    struct ofp11_table_stats *ots;

    ots = ofpbuf_try_pull(msg, sizeof *ots);
    if (!ots) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    features->table_id = ots->table_id;
    ovs_strlcpy_arrays(features->name, ots->name);
    features->max_entries = ntohl(ots->max_entries);
    features->nonmiss.instructions = ovsinst_bitmap_from_openflow(
        ots->instructions, OFP11_VERSION);
    features->nonmiss.write.ofpacts = ofpact_bitmap_from_openflow(
        ots->write_actions, OFP11_VERSION);
    features->nonmiss.apply.ofpacts = ofpact_bitmap_from_openflow(
        ots->write_actions, OFP11_VERSION);
    features->miss = features->nonmiss;
    features->miss_config = ofputil_decode_table_miss(ots->config,
                                                      OFP11_VERSION);
    features->match = mf_bitmap_from_of11(ots->match);
    features->wildcard = mf_bitmap_from_of11(ots->wildcards);
    bitmap_or(features->match.bm, features->wildcard.bm, MFF_N_IDS);

    stats->table_id = ots->table_id;
    stats->active_count = ntohl(ots->active_count);
    stats->lookup_count = ntohll(ots->lookup_count);
    stats->matched_count = ntohll(ots->matched_count);

    return 0;
}

static int
ofputil_decode_ofp12_table_stats(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    struct ofp12_table_stats *ots;

    ots = ofpbuf_try_pull(msg, sizeof *ots);
    if (!ots) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    features->table_id = ots->table_id;
    ovs_strlcpy_arrays(features->name, ots->name);
    features->metadata_match = ots->metadata_match;
    features->metadata_write = ots->metadata_write;
    features->miss_config = ofputil_decode_table_miss(ots->config,
                                                      OFP12_VERSION);
    features->max_entries = ntohl(ots->max_entries);

    features->nonmiss.instructions = ovsinst_bitmap_from_openflow(
        ots->instructions, OFP12_VERSION);
    features->nonmiss.write.ofpacts = ofpact_bitmap_from_openflow(
        ots->write_actions, OFP12_VERSION);
    features->nonmiss.apply.ofpacts = ofpact_bitmap_from_openflow(
        ots->apply_actions, OFP12_VERSION);
    features->nonmiss.write.set_fields = oxm_bitmap_to_mf_bitmap(
        ots->write_setfields, OFP12_VERSION);
    features->nonmiss.apply.set_fields = oxm_bitmap_to_mf_bitmap(
        ots->apply_setfields, OFP12_VERSION);
    features->miss = features->nonmiss;

    features->match = oxm_bitmap_to_mf_bitmap(ots->match, OFP12_VERSION);
    features->wildcard = oxm_bitmap_to_mf_bitmap(ots->wildcards,
                                                 OFP12_VERSION);
    bitmap_or(features->match.bm, features->wildcard.bm, MFF_N_IDS);

    stats->table_id = ots->table_id;
    stats->active_count = ntohl(ots->active_count);
    stats->lookup_count = ntohll(ots->lookup_count);
    stats->matched_count = ntohll(ots->matched_count);

    return 0;
}

static int
ofputil_decode_ofp13_table_stats(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    struct ofp13_table_stats *ots;

    ots = ofpbuf_try_pull(msg, sizeof *ots);
    if (!ots) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    features->table_id = ots->table_id;

    stats->table_id = ots->table_id;
    stats->active_count = ntohl(ots->active_count);
    stats->lookup_count = ntohll(ots->lookup_count);
    stats->matched_count = ntohll(ots->matched_count);

    return 0;
}

int
ofputil_decode_table_stats_reply(struct ofpbuf *msg,
                                 struct ofputil_table_stats *stats,
                                 struct ofputil_table_features *features)
{
    const struct ofp_header *oh;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }
    oh = msg->header;

    if (!msg->size) {
        return EOF;
    }

    memset(stats, 0, sizeof *stats);
    memset(features, 0, sizeof *features);
    features->supports_eviction = -1;
    features->supports_vacancy_events = -1;

    switch ((enum ofp_version) oh->version) {
    case OFP10_VERSION:
        return ofputil_decode_ofp10_table_stats(msg, stats, features);

    case OFP11_VERSION:
        return ofputil_decode_ofp11_table_stats(msg, stats, features);

    case OFP12_VERSION:
        return ofputil_decode_ofp12_table_stats(msg, stats, features);

    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        return ofputil_decode_ofp13_table_stats(msg, stats, features);

    default:
        OVS_NOT_REACHED();
    }
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFP_ASYNC_CONFIG_REASON_BUFSIZE. */
const char *
ofp_table_reason_to_string(enum ofp14_table_reason reason,
                           char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPTR_VACANCY_DOWN:
        return "vacancy_down";

    case OFPTR_VACANCY_UP:
        return "vacancy_up";

    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

static void
ofputil_put_ofp14_table_desc(const struct ofputil_table_desc *td,
                             struct ofpbuf *b, enum ofp_version version)
{
    struct ofp14_table_desc *otd;
    struct ofp14_table_mod_prop_vacancy *otv;
    size_t start_otd;

    start_otd = b->size;
    ofpbuf_put_zeros(b, sizeof *otd);

    ofpprop_put_u32(b, OFPTMPT14_EVICTION, td->eviction_flags);

    otv = ofpbuf_put_zeros(b, sizeof *otv);
    otv->type = htons(OFPTMPT14_VACANCY);
    otv->length = htons(sizeof *otv);
    otv->vacancy_down = td->table_vacancy.vacancy_down;
    otv->vacancy_up = td->table_vacancy.vacancy_up;
    otv->vacancy = td->table_vacancy.vacancy;

    otd = ofpbuf_at_assert(b, start_otd, sizeof *otd);
    otd->length = htons(b->size - start_otd);
    otd->table_id = td->table_id;
    otd->config = ofputil_encode_table_config(OFPUTIL_TABLE_MISS_DEFAULT,
                                              td->eviction, td->vacancy,
                                              version);
}

/* Converts the abstract form of a "table status" message in '*ts' into an
 * OpenFlow message suitable for 'protocol', and returns that encoded form in
 * a buffer owned by the caller. */
struct ofpbuf *
ofputil_encode_table_status(const struct ofputil_table_status *ts,
                            enum ofputil_protocol protocol)
{
    enum ofp_version version;
    struct ofpbuf *b;

    version = ofputil_protocol_to_ofp_version(protocol);
    if (version >= OFP14_VERSION) {
        enum ofpraw raw;
        struct ofp14_table_status *ots;

        raw = OFPRAW_OFPT14_TABLE_STATUS;
        b = ofpraw_alloc_xid(raw, version, htonl(0), 0);
        ots = ofpbuf_put_zeros(b, sizeof *ots);
        ots->reason = ts->reason;
        ofputil_put_ofp14_table_desc(&ts->desc, b, version);
        ofpmsg_update_length(b);
        return b;
    } else {
        return NULL;
    }
}

/* Decodes the OpenFlow "table status" message in '*ots' into an abstract form
 * in '*ts'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_table_status(const struct ofp_header *oh,
                            struct ofputil_table_status *ts)
{
    const struct ofp14_table_status *ots;
    struct ofpbuf b;
    enum ofperr error;
    enum ofpraw raw;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);
    ots = ofpbuf_pull(&b, sizeof *ots);

    if (raw == OFPRAW_OFPT14_TABLE_STATUS) {
        if (ots->reason != OFPTR_VACANCY_DOWN
            && ots->reason != OFPTR_VACANCY_UP) {
            return OFPERR_OFPBPC_BAD_VALUE;
        }
        ts->reason = ots->reason;

        error = ofputil_decode_table_desc(&b, &ts->desc, oh->version);
        return error;
    } else {
        return OFPERR_OFPBRC_BAD_VERSION;
    }

    return 0;
}

void
ofputil_format_table_status(struct ds *string,
                            const struct ofputil_table_status *ts,
                            const struct ofputil_table_map *table_map)
{
    if (ts->reason == OFPTR_VACANCY_DOWN) {
        ds_put_format(string, " reason=VACANCY_DOWN");
    } else if (ts->reason == OFPTR_VACANCY_UP) {
        ds_put_format(string, " reason=VACANCY_UP");
    }

    ds_put_format(string, "\ntable_desc:-");
    ofputil_table_desc_format(string, &ts->desc, table_map);
}
