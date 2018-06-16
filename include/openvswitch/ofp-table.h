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

#ifndef OPENVSWITCH_OFP_TABLE_H
#define OPENVSWITCH_OFP_TABLE_H 1

#include <limits.h>
#include "openflow/openflow.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-port.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ofputil_table_stats;

/* Abstract version of OFPTC11_TABLE_MISS_*.
 *
 * OpenFlow 1.0 always sends packets that miss to the next flow table, or to
 * the controller if they miss in the last flow table.
 *
 * OpenFlow 1.1 and 1.2 can configure table miss behavior via a "table-mod"
 * that specifies "send to controller", "miss", or "drop".
 *
 * OpenFlow 1.3 and later never sends packets that miss to the controller.
 */
enum ofputil_table_miss {
    /* Protocol-specific default behavior.  On OpenFlow 1.0 through 1.2
     * connections, the packet is sent to the controller, and on OpenFlow 1.3
     * and later connections, the packet is dropped.
     *
     * This is also used as a result of decoding OpenFlow 1.3+ "config" values
     * in table-mods, to indicate that no table-miss was specified. */
    OFPUTIL_TABLE_MISS_DEFAULT,    /* Protocol default behavior. */

    /* These constants have the same meanings as those in OpenFlow with the
     * same names. */
    OFPUTIL_TABLE_MISS_CONTROLLER, /* Send to controller. */
    OFPUTIL_TABLE_MISS_CONTINUE,   /* Go to next table. */
    OFPUTIL_TABLE_MISS_DROP,       /* Drop the packet. */
};

const char *ofputil_table_miss_to_string(enum ofputil_table_miss);

/* Abstract version of OFPTC14_EVICTION.
 *
 * OpenFlow 1.0 through 1.3 don't know anything about eviction, so decoding a
 * message for one of these protocols always yields
 * OFPUTIL_TABLE_EVICTION_DEFAULT. */
enum ofputil_table_eviction {
    OFPUTIL_TABLE_EVICTION_DEFAULT, /* No value. */
    OFPUTIL_TABLE_EVICTION_ON,      /* Enable eviction. */
    OFPUTIL_TABLE_EVICTION_OFF      /* Disable eviction. */
};

const char *ofputil_table_eviction_to_string(enum ofputil_table_eviction);

/* Abstract version of OFPTC14_VACANCY_EVENTS.
 *
 * OpenFlow 1.0 through 1.3 don't know anything about vacancy events, so
 * decoding a message for one of these protocols always yields
 * OFPUTIL_TABLE_VACANCY_DEFAULT. */
enum ofputil_table_vacancy {
    OFPUTIL_TABLE_VACANCY_DEFAULT, /* No value. */
    OFPUTIL_TABLE_VACANCY_ON,      /* Enable vacancy events. */
    OFPUTIL_TABLE_VACANCY_OFF      /* Disable vacancy events. */
};

const char *ofputil_table_vacancy_to_string(enum ofputil_table_vacancy);

/* Abstract version of OFPTMPT_VACANCY.
 *
 * Openflow 1.4+ defines vacancy events.
 * The fields vacancy_down and vacancy_up are the threshold for generating
 * vacancy events that should be configured on the flow table, expressed as
 * a percent.
 * The vacancy field is only used when this property in included in a
 * OFPMP_TABLE_DESC multipart reply or a OFPT_TABLE_STATUS message and
 * represent the current vacancy of the table, expressed as a percent. In
 * OFP_TABLE_MOD requests, this field must be set to 0 */
struct ofputil_table_mod_prop_vacancy {
    uint8_t vacancy_down;    /* Vacancy threshold when space decreases (%). */
    uint8_t vacancy_up;      /* Vacancy threshold when space increases (%). */
    uint8_t vacancy;         /* Current vacancy (%). */
};

/* Mapping between table numbers and names. */
struct ofputil_table_map {
    struct namemap map;
};
#define OFPUTIL_TABLE_MAP_INITIALIZER(MAP) { NAMEMAP_INITIALIZER((MAP).map) }

void ofputil_table_map_init(struct ofputil_table_map *);
const char *ofputil_table_map_get_name(const struct ofputil_table_map *,
                                       uint8_t);
uint8_t ofputil_table_map_get_number(const struct ofputil_table_map *,
                                     const char *name);
void ofputil_table_map_put(struct ofputil_table_map *,
                           uint8_t, const char *name);
void ofputil_table_map_destroy(struct ofputil_table_map *);

/* Table numbers. */
bool ofputil_table_from_string(const char *, const struct ofputil_table_map *,
                               uint8_t *tablep);
void ofputil_format_table(uint8_t table, const struct ofputil_table_map *,
                         struct ds *);
void ofputil_table_to_string(uint8_t, const struct ofputil_table_map *,
                            char *namebuf, size_t bufsize);

/* Abstract ofp_table_mod. */
struct ofputil_table_mod {
    uint8_t table_id;         /* ID of the table, 0xff indicates all tables. */

    /* OpenFlow 1.1 and 1.2 only.  For other versions, ignored on encoding,
     * decoded to OFPUTIL_TABLE_MISS_DEFAULT. */
    enum ofputil_table_miss miss;

    /* OpenFlow 1.4+ only.  For other versions, ignored on encoding, decoded to
     * OFPUTIL_TABLE_EVICTION_DEFAULT. */
    enum ofputil_table_eviction eviction;

    /* OpenFlow 1.4+ only and optional even there; UINT32_MAX indicates
     * absence.  For other versions, ignored on encoding, decoded to
     * UINT32_MAX.*/
    uint32_t eviction_flags;    /* OFPTMPEF14_*. */

    /* OpenFlow 1.4+ only. For other versions, ignored on encoding, decoded to
     * OFPUTIL_TABLE_VACANCY_DEFAULT. */
    enum ofputil_table_vacancy vacancy;

    /* Openflow 1.4+ only. Defines threshold values of vacancy expressed as
     * percent, value of current vacancy is set to zero for table-mod.
     * For other versions, ignored on encoding, all values decoded to
     * zero. */
    struct ofputil_table_mod_prop_vacancy table_vacancy;
};

enum ofperr ofputil_decode_table_mod(const struct ofp_header *,
                                    struct ofputil_table_mod *);
struct ofpbuf *ofputil_encode_table_mod(const struct ofputil_table_mod *,
                                       enum ofputil_protocol);
void ofputil_table_mod_format(struct ds *, const struct ofputil_table_mod *,
                              const struct ofputil_table_map *);
char *parse_ofp_table_mod(struct ofputil_table_mod *,
                          const char *table_id, const char *flow_miss_handling,
                          const struct ofputil_table_map *,
                          uint32_t *usable_versions)
    OVS_WARN_UNUSED_RESULT;

/* Abstract ofp14_table_desc. */
struct ofputil_table_desc {
    uint8_t table_id;         /* ID of the table. */
    enum ofputil_table_eviction eviction;
    uint32_t eviction_flags;    /* UINT32_MAX if not present. */
    enum ofputil_table_vacancy vacancy;
    struct ofputil_table_mod_prop_vacancy table_vacancy;
};

int ofputil_decode_table_desc(struct ofpbuf *,
                              struct ofputil_table_desc *,
                              enum ofp_version);
void ofputil_append_table_desc_reply(const struct ofputil_table_desc *td,
                                     struct ovs_list *replies,
                                     enum ofp_version);
void ofputil_table_desc_format(struct ds *,
                               const struct ofputil_table_desc *,
                               const struct ofputil_table_map *);

/* Abstract ofp_table_features.
 *
 * This is used for all versions of OpenFlow, even though ofp_table_features
 * was only introduced in OpenFlow 1.3, because earlier versions of OpenFlow
 * include support for a subset of ofp_table_features through OFPST_TABLE (aka
 * OFPMP_TABLE). */
struct ofputil_table_features {
    uint8_t table_id;         /* Identifier of table. Lower numbered tables
                                 are consulted first. */
    char name[OFP_MAX_TABLE_NAME_LEN];
    ovs_be64 metadata_match;  /* Bits of metadata table can match. */
    ovs_be64 metadata_write;  /* Bits of metadata table can write. */
    uint32_t max_entries;     /* Max number of entries supported. */

    /* Flags.
     *
     * 'miss_config' is relevant for OpenFlow 1.1 and 1.2 only, because those
     * versions include OFPTC_MISS_* flags in OFPST_TABLE.  For other versions,
     * it is decoded to OFPUTIL_TABLE_MISS_DEFAULT and ignored for encoding.
     *
     * 'supports_eviction' and 'supports_vacancy_events' are relevant only for
     * OpenFlow 1.4 and later only.  For OF1.4, they are boolean: 1 if
     * supported, otherwise 0.  For other versions, they are decoded as -1 and
     * ignored for encoding.
     *
     * Search for "OFPTC_* Table Configuration" in the documentation for more
     * details of how OpenFlow has changed in this area.
     */
    enum ofputil_table_miss miss_config; /* OF1.1 and 1.2 only. */
    int supports_eviction;               /* OF1.4+ only. */
    int supports_vacancy_events;         /* OF1.4+ only. */

    /* Table features related to instructions.  There are two instances:
     *
     *   - 'miss' reports features available in the table miss flow.
     *
     *   - 'nonmiss' reports features available in other flows. */
    struct ofputil_table_instruction_features {
        /* Tables that "goto-table" may jump to. */
        unsigned long int next[BITMAP_N_LONGS(255)];

        /* Bitmap of OVSINST_* for supported instructions. */
        uint32_t instructions;

        /* Table features related to actions.  There are two instances:
         *
         *    - 'write' reports features available in a "write_actions"
         *      instruction.
         *
         *    - 'apply' reports features available in an "apply_actions"
         *      instruction. */
        struct ofputil_table_action_features {
            uint64_t ofpacts;     /* Bitmap of supported OFPACT_*. */
            struct mf_bitmap set_fields; /* Fields for "set-field". */
        } write, apply;
    } nonmiss, miss;

    /* MFF_* bitmaps.
     *
     * For any given field the following combinations are valid:
     *
     *    - match=0, wildcard=0, mask=0: Flows in this table cannot match on
     *      this field.
     *
     *    - match=1, wildcard=0, mask=0: Flows in this table must match on all
     *      the bits in this field.
     *
     *    - match=1, wildcard=1, mask=0: Flows in this table must either match
     *      on all the bits in the field or wildcard the field entirely.
     *
     *    - match=1, wildcard=1, mask=1: Flows in this table may arbitrarily
     *      mask this field (as special cases, they may match on all the bits
     *      or wildcard it entirely).
     *
     * Other combinations do not make sense.
     */
    struct mf_bitmap match;     /* Fields that may be matched. */
    struct mf_bitmap mask;      /* Subset of 'match' that may have masks. */
    struct mf_bitmap wildcard;  /* Subset of 'match' that may be wildcarded. */
};

int ofputil_decode_table_features(struct ofpbuf *,
                                  struct ofputil_table_features *, bool loose);

struct ofpbuf *ofputil_encode_table_features_request(enum ofp_version);

struct ofpbuf *ofputil_encode_table_desc_request(enum ofp_version);

void ofputil_append_table_features_reply(
    const struct ofputil_table_features *tf, struct ovs_list *replies);

void ofputil_table_features_format(
    struct ds *, const struct ofputil_table_features *features,
    const struct ofputil_table_features *prev_features,
    const struct ofputil_table_stats *stats,
    const struct ofputil_table_stats *prev_stats,
    const struct ofputil_table_map *table_map);

/* Abstract table stats.
 *
 * This corresponds to the OpenFlow 1.3 table statistics structure, which only
 * includes actual statistics.  In earlier versions of OpenFlow, several
 * members describe table features, so this structure has to be paired with
 * struct ofputil_table_features to get all information. */
struct ofputil_table_stats {
    uint8_t table_id;           /* Identifier of table. */
    uint32_t active_count;      /* Number of active entries. */
    uint64_t lookup_count;      /* Number of packets looked up in table. */
    uint64_t matched_count;     /* Number of packets that hit table. */
};

struct ofpbuf *ofputil_encode_table_stats_reply(const struct ofp_header *rq);

struct ofpbuf *ofputil_encode_table_desc_reply(const struct ofp_header *rq);

void ofputil_append_table_stats_reply(struct ofpbuf *reply,
                                      const struct ofputil_table_stats *,
                                      const struct ofputil_table_features *);

int ofputil_decode_table_stats_reply(struct ofpbuf *reply,
                                     struct ofputil_table_stats *,
                                     struct ofputil_table_features *);

/* Abstract ofp14_table_status. */
struct ofputil_table_status {
    enum ofp14_table_reason reason;     /* One of OFPTR_*. */
    struct ofputil_table_desc desc;   /* New table config. */
};

const char *ofp_table_reason_to_string(enum ofp14_table_reason,
                                       char *reasonbuf, size_t bufsize);

enum ofperr ofputil_decode_table_status(const struct ofp_header *,
                                        struct ofputil_table_status *);
struct ofpbuf *ofputil_encode_table_status(const struct ofputil_table_status *,
                                           enum ofputil_protocol);
void ofputil_format_table_status(struct ds *,
                                 const struct ofputil_table_status *,
                                 const struct ofputil_table_map *);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-table.h */
