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
#include "openvswitch/ofp-group.h"
#include <errno.h>
#include "byte-order.h"
#include "id-pool.h"
#include "nx-match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofp_group);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Stores the group id represented by 's' into '*group_idp'.  's' may be an
 * integer or, for reserved group IDs, the standard OpenFlow name for the group
 * (either "ANY" or "ALL").
 *
 * Returns true if successful, false if 's' is not a valid OpenFlow group ID or
 * name. */
bool
ofputil_group_from_string(const char *s, uint32_t *group_idp)
{
    if (!strcasecmp(s, "any")) {
        *group_idp = OFPG_ANY;
    } else if (!strcasecmp(s, "all")) {
        *group_idp = OFPG_ALL;
    } else if (!str_to_uint(s, 10, group_idp)) {
        VLOG_WARN("%s is not a valid group ID.  (Valid group IDs are "
                  "32-bit nonnegative integers or the keywords ANY or "
                  "ALL.)", s);
        return false;
    }

    return true;
}

/* Appends to 's' a string representation of the OpenFlow group ID 'group_id'.
 * Most groups' string representation is just the number, but for special
 * groups, e.g. OFPG_ALL, it is the name, e.g. "ALL". */
void
ofputil_format_group(uint32_t group_id, struct ds *s)
{
    char name[MAX_GROUP_NAME_LEN];

    ofputil_group_to_string(group_id, name, sizeof name);
    ds_put_cstr(s, name);
}


/* Puts in the 'bufsize' byte in 'namebuf' a null-terminated string
 * representation of OpenFlow group ID 'group_id'.  Most group are represented
 * as just their number, but special groups, e.g. OFPG_ALL, are represented
 * by name, e.g. "ALL". */
void
ofputil_group_to_string(uint32_t group_id,
                        char namebuf[MAX_GROUP_NAME_LEN + 1], size_t bufsize)
{
    switch (group_id) {
    case OFPG_ALL:
        ovs_strlcpy(namebuf, "ALL", bufsize);
        break;

    case OFPG_ANY:
        ovs_strlcpy(namebuf, "ANY", bufsize);
        break;

    default:
        snprintf(namebuf, bufsize, "%"PRIu32, group_id);
        break;
    }
}

/* Frees all of the "struct ofputil_bucket"s in the 'buckets' list. */
void
ofputil_bucket_list_destroy(struct ovs_list *buckets)
{
    struct ofputil_bucket *bucket;

    LIST_FOR_EACH_POP (bucket, list_node, buckets) {
        free(bucket->ofpacts);
        free(bucket);
    }
}

/* Clones 'bucket' and its ofpacts data */
static struct ofputil_bucket *
ofputil_bucket_clone_data(const struct ofputil_bucket *bucket)
{
    struct ofputil_bucket *new;

    new = xmemdup(bucket, sizeof *bucket);
    new->ofpacts = xmemdup(bucket->ofpacts, bucket->ofpacts_len);

    return new;
}

/* Clones each of the buckets in the list 'src' appending them
 * in turn to 'dest' which should be an initialised list.
 * An exception is that if the pointer value of a bucket in 'src'
 * matches 'skip' then it is not cloned or appended to 'dest'.
 * This allows all of 'src' or 'all of 'src' except 'skip' to
 * be cloned and appended to 'dest'. */
void
ofputil_bucket_clone_list(struct ovs_list *dest, const struct ovs_list *src,
                          const struct ofputil_bucket *skip)
{
    struct ofputil_bucket *bucket;

    LIST_FOR_EACH (bucket, list_node, src) {
        struct ofputil_bucket *new_bucket;

        if (bucket == skip) {
            continue;
        }

        new_bucket = ofputil_bucket_clone_data(bucket);
        ovs_list_push_back(dest, &new_bucket->list_node);
    }
}

/* Find a bucket in the list 'buckets' whose bucket id is 'bucket_id'
 * Returns the first bucket found or NULL if no buckets are found. */
struct ofputil_bucket *
ofputil_bucket_find(const struct ovs_list *buckets, uint32_t bucket_id)
{
    struct ofputil_bucket *bucket;

    if (bucket_id > OFPG15_BUCKET_MAX) {
        return NULL;
    }

    LIST_FOR_EACH (bucket, list_node, buckets) {
        if (bucket->bucket_id == bucket_id) {
            return bucket;
        }
    }

    return NULL;
}

/* Returns true if more than one bucket in the list 'buckets'
 * have the same bucket id. Returns false otherwise. */
bool
ofputil_bucket_check_duplicate_id(const struct ovs_list *buckets)
{
    struct ofputil_bucket *i, *j;

    LIST_FOR_EACH (i, list_node, buckets) {
        LIST_FOR_EACH_REVERSE (j, list_node, buckets) {
            if (i == j) {
                break;
            }
            if (i->bucket_id == j->bucket_id) {
                return true;
            }
        }
    }

    return false;
}

/* Returns the bucket at the front of the list 'buckets'.
 * Undefined if 'buckets is empty. */
struct ofputil_bucket *
ofputil_bucket_list_front(const struct ovs_list *buckets)
{
    static struct ofputil_bucket *bucket;

    ASSIGN_CONTAINER(bucket, ovs_list_front(buckets), list_node);

    return bucket;
}

/* Returns the bucket at the back of the list 'buckets'.
 * Undefined if 'buckets is empty. */
struct ofputil_bucket *
ofputil_bucket_list_back(const struct ovs_list *buckets)
{
    static struct ofputil_bucket *bucket;

    ASSIGN_CONTAINER(bucket, ovs_list_back(buckets), list_node);

    return bucket;
}

/* Returns an OpenFlow group stats request for OpenFlow version 'ofp_version',
 * that requests stats for group 'group_id'.  (Use OFPG_ALL to request stats
 * for all groups.)
 *
 * Group statistics include packet and byte counts for each group. */
struct ofpbuf *
ofputil_encode_group_stats_request(enum ofp_version ofp_version,
                                   uint32_t group_id)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP10_VERSION:
        ovs_fatal(0, "dump-group-stats needs OpenFlow 1.1 or later "
                     "(\'-O OpenFlow11\')");
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp11_group_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST11_GROUP_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->group_id = htonl(group_id);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

void
ofputil_uninit_group_desc(struct ofputil_group_desc *gd)
{
    ofputil_bucket_list_destroy(&gd->buckets);
    ofputil_group_properties_destroy(&gd->props);
}

/* Decodes the OpenFlow group description request in 'oh', returning the group
 * whose description is requested, or OFPG_ALL if stats for all groups was
 * requested. */
uint32_t
ofputil_decode_group_desc_request(const struct ofp_header *oh)
{
    struct ofpbuf request = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&request);
    if (raw == OFPRAW_OFPST11_GROUP_DESC_REQUEST) {
        return OFPG_ALL;
    } else if (raw == OFPRAW_OFPST15_GROUP_DESC_REQUEST) {
        ovs_be32 *group_id = ofpbuf_pull(&request, sizeof *group_id);
        return ntohl(*group_id);
    } else {
        OVS_NOT_REACHED();
    }
}

/* Returns an OpenFlow group description request for OpenFlow version
 * 'ofp_version', that requests stats for group 'group_id'.  Use OFPG_ALL to
 * request stats for all groups (OpenFlow 1.4 and earlier always request all
 * groups).
 *
 * Group descriptions include the bucket and action configuration for each
 * group. */
struct ofpbuf *
ofputil_encode_group_desc_request(enum ofp_version ofp_version,
                                  uint32_t group_id)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP10_VERSION:
        ovs_fatal(0, "dump-groups needs OpenFlow 1.1 or later "
                     "(\'-O OpenFlow11\')");
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        request = ofpraw_alloc(OFPRAW_OFPST11_GROUP_DESC_REQUEST,
                               ofp_version, 0);
        break;
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp15_group_desc_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST15_GROUP_DESC_REQUEST,
                               ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->group_id = htonl(group_id);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

static void
ofputil_group_bucket_counters_to_ofp11(const struct ofputil_group_stats *gs,
                                    struct ofp11_bucket_counter bucket_cnts[])
{
    int i;

    for (i = 0; i < gs->n_buckets; i++) {
       bucket_cnts[i].packet_count = htonll(gs->bucket_stats[i].packet_count);
       bucket_cnts[i].byte_count = htonll(gs->bucket_stats[i].byte_count);
    }
}

static void
ofputil_group_stats_to_ofp11(const struct ofputil_group_stats *gs,
                             struct ofp11_group_stats *gs11, size_t length,
                             struct ofp11_bucket_counter bucket_cnts[])
{
    memset(gs11, 0, sizeof *gs11);
    gs11->length = htons(length);
    gs11->group_id = htonl(gs->group_id);
    gs11->ref_count = htonl(gs->ref_count);
    gs11->packet_count = htonll(gs->packet_count);
    gs11->byte_count = htonll(gs->byte_count);
    ofputil_group_bucket_counters_to_ofp11(gs, bucket_cnts);
}

static void
ofputil_group_stats_to_ofp13(const struct ofputil_group_stats *gs,
                             struct ofp13_group_stats *gs13, size_t length,
                             struct ofp11_bucket_counter bucket_cnts[])
{
    ofputil_group_stats_to_ofp11(gs, &gs13->gs, length, bucket_cnts);
    gs13->duration_sec = htonl(gs->duration_sec);
    gs13->duration_nsec = htonl(gs->duration_nsec);

}

/* Encodes 'gs' properly for the format of the list of group statistics
 * replies already begun in 'replies' and appends it to the list.  'replies'
 * must have originally been initialized with ofpmp_init(). */
void
ofputil_append_group_stats(struct ovs_list *replies,
                           const struct ofputil_group_stats *gs)
{
    size_t bucket_counter_size;
    struct ofp11_bucket_counter *bucket_counters;
    size_t length;

    bucket_counter_size = gs->n_buckets * sizeof(struct ofp11_bucket_counter);

    switch (ofpmp_version(replies)) {
    case OFP11_VERSION:
    case OFP12_VERSION:{
            struct ofp11_group_stats *gs11;

            length = sizeof *gs11 + bucket_counter_size;
            gs11 = ofpmp_append(replies, length);
            bucket_counters = (struct ofp11_bucket_counter *)(gs11 + 1);
            ofputil_group_stats_to_ofp11(gs, gs11, length, bucket_counters);
            break;
        }

    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
            struct ofp13_group_stats *gs13;

            length = sizeof *gs13 + bucket_counter_size;
            gs13 = ofpmp_append(replies, length);
            bucket_counters = (struct ofp11_bucket_counter *)(gs13 + 1);
            ofputil_group_stats_to_ofp13(gs, gs13, length, bucket_counters);
            break;
        }

    case OFP10_VERSION:
    default:
        OVS_NOT_REACHED();
    }
}
/* Returns an OpenFlow group features request for OpenFlow version
 * 'ofp_version'. */
struct ofpbuf *
ofputil_encode_group_features_request(enum ofp_version ofp_version)
{
    struct ofpbuf *request = NULL;

    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
        ovs_fatal(0, "dump-group-features needs OpenFlow 1.2 or later "
                     "(\'-O OpenFlow12\')");
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        request = ofpraw_alloc(OFPRAW_OFPST12_GROUP_FEATURES_REQUEST,
                               ofp_version, 0);
        break;
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

/* Returns a OpenFlow message that encodes 'features' properly as a reply to
 * group features request 'request'. */
struct ofpbuf *
ofputil_encode_group_features_reply(
    const struct ofputil_group_features *features,
    const struct ofp_header *request)
{
    struct ofp12_group_features_stats *ogf;
    struct ofpbuf *reply;
    int i;

    reply = ofpraw_alloc_xid(OFPRAW_OFPST12_GROUP_FEATURES_REPLY,
                             request->version, request->xid, 0);
    ogf = ofpbuf_put_zeros(reply, sizeof *ogf);
    ogf->types = htonl(features->types);
    ogf->capabilities = htonl(features->capabilities);
    for (i = 0; i < OFPGT12_N_TYPES; i++) {
        ogf->max_groups[i] = htonl(features->max_groups[i]);
        ogf->actions[i] = ofpact_bitmap_to_openflow(features->ofpacts[i],
                                                    request->version);
    }

    return reply;
}

/* Decodes group features reply 'oh' into 'features'. */
void
ofputil_decode_group_features_reply(const struct ofp_header *oh,
                                    struct ofputil_group_features *features)
{
    const struct ofp12_group_features_stats *ogf = ofpmsg_body(oh);
    int i;

    features->types = ntohl(ogf->types);
    features->capabilities = ntohl(ogf->capabilities);
    for (i = 0; i < OFPGT12_N_TYPES; i++) {
        features->max_groups[i] = ntohl(ogf->max_groups[i]);
        features->ofpacts[i] = ofpact_bitmap_from_openflow(
            ogf->actions[i], oh->version);
    }
}

/* Parse a group status request message into a 32 bit OpenFlow 1.1
 * group ID and stores the latter in '*group_id'.
 * Returns 0 if successful, otherwise an OFPERR_* number. */
enum ofperr
ofputil_decode_group_stats_request(const struct ofp_header *request,
                                   uint32_t *group_id)
{
    const struct ofp11_group_stats_request *gsr11 = ofpmsg_body(request);
    *group_id = ntohl(gsr11->group_id);
    return 0;
}

/* Converts a group stats reply in 'msg' into an abstract ofputil_group_stats
 * in 'gs'.  Assigns freshly allocated memory to gs->bucket_stats for the
 * caller to eventually free.
 *
 * Multiple group stats replies can be packed into a single OpenFlow message.
 * Calling this function multiple times for a single 'msg' iterates through the
 * replies.  The caller must initially leave 'msg''s layer pointers null and
 * not modify them between calls.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_group_stats_reply(struct ofpbuf *msg,
                                 struct ofputil_group_stats *gs)
{
    struct ofp11_bucket_counter *obc;
    struct ofp11_group_stats *ogs11;
    enum ofpraw raw;
    enum ofperr error;
    size_t base_len;
    size_t length;
    size_t i;

    gs->bucket_stats = NULL;
    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
    }

    if (raw == OFPRAW_OFPST11_GROUP_REPLY) {
        base_len = sizeof *ogs11;
        ogs11 = ofpbuf_try_pull(msg, sizeof *ogs11);
        gs->duration_sec = gs->duration_nsec = UINT32_MAX;
    } else if (raw == OFPRAW_OFPST13_GROUP_REPLY) {
        struct ofp13_group_stats *ogs13;

        base_len = sizeof *ogs13;
        ogs13 = ofpbuf_try_pull(msg, sizeof *ogs13);
        if (ogs13) {
            ogs11 = &ogs13->gs;
            gs->duration_sec = ntohl(ogs13->duration_sec);
            gs->duration_nsec = ntohl(ogs13->duration_nsec);
        } else {
            ogs11 = NULL;
        }
    } else {
        OVS_NOT_REACHED();
    }

    if (!ogs11) {
        VLOG_WARN_RL(&rl, "%s reply has %"PRIu32" leftover bytes at end",
                     ofpraw_get_name(raw), msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    length = ntohs(ogs11->length);
    if (length < sizeof base_len) {
        VLOG_WARN_RL(&rl, "%s reply claims invalid length %"PRIuSIZE,
                     ofpraw_get_name(raw), length);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    gs->group_id = ntohl(ogs11->group_id);
    gs->ref_count = ntohl(ogs11->ref_count);
    gs->packet_count = ntohll(ogs11->packet_count);
    gs->byte_count = ntohll(ogs11->byte_count);

    gs->n_buckets = (length - base_len) / sizeof *obc;
    obc = ofpbuf_try_pull(msg, gs->n_buckets * sizeof *obc);
    if (!obc) {
        VLOG_WARN_RL(&rl, "%s reply has %"PRIu32" leftover bytes at end",
                     ofpraw_get_name(raw), msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    gs->bucket_stats = xmalloc(gs->n_buckets * sizeof *gs->bucket_stats);
    for (i = 0; i < gs->n_buckets; i++) {
        gs->bucket_stats[i].packet_count = ntohll(obc[i].packet_count);
        gs->bucket_stats[i].byte_count = ntohll(obc[i].byte_count);
    }

    return 0;
}

static char * OVS_WARN_UNUSED_RESULT
parse_bucket_str(struct ofputil_bucket *bucket, char *str_,
                 const struct ofputil_port_map *port_map,
                 const struct ofputil_table_map *table_map,
                 uint8_t group_type, enum ofputil_protocol *usable_protocols)
{
    char *pos, *key, *value;
    struct ofpbuf ofpacts;
    struct ds actions;
    char *error;

    bucket->weight = group_type == OFPGT11_SELECT ? 1 : 0;
    bucket->bucket_id = OFPG15_BUCKET_ALL;
    bucket->watch_port = OFPP_ANY;
    bucket->watch_group = OFPG_ANY;

    ds_init(&actions);

    pos = str_;
    error = NULL;
    while (ofputil_parse_key_value(&pos, &key, &value)) {
        if (!strcasecmp(key, "weight")) {
            error = str_to_u16(value, "weight", &bucket->weight);
        } else if (!strcasecmp(key, "watch_port")) {
            if (!ofputil_port_from_string(value, port_map, &bucket->watch_port)
                || (ofp_to_u16(bucket->watch_port) >= ofp_to_u16(OFPP_MAX)
                    && bucket->watch_port != OFPP_ANY)) {
                error = xasprintf("%s: invalid watch_port", value);
            }
        } else if (!strcasecmp(key, "watch_group")) {
            error = str_to_u32(value, &bucket->watch_group);
            if (!error && bucket->watch_group > OFPG_MAX) {
                error = xasprintf("invalid watch_group id %"PRIu32,
                                  bucket->watch_group);
            }
        } else if (!strcasecmp(key, "bucket_id")) {
            error = str_to_u32(value, &bucket->bucket_id);
            if (!error && bucket->bucket_id > OFPG15_BUCKET_MAX) {
                error = xasprintf("invalid bucket_id id %"PRIu32,
                                  bucket->bucket_id);
            }
            *usable_protocols &= OFPUTIL_P_OF15_UP;
        } else if (!strcasecmp(key, "action") || !strcasecmp(key, "actions")) {
            ds_put_format(&actions, "%s,", value);
        } else {
            ds_put_format(&actions, "%s(%s),", key, value);
        }

        if (error) {
            ds_destroy(&actions);
            return error;
        }
    }

    if (!actions.length) {
        return xstrdup("bucket must specify actions");
    }
    ds_chomp(&actions, ',');

    ofpbuf_init(&ofpacts, 0);
    struct ofpact_parse_params pp = {
        .port_map = port_map,
        .table_map = table_map,
        .ofpacts = &ofpacts,
        .usable_protocols = usable_protocols,
    };
    error = ofpacts_parse_actions(ds_cstr(&actions), &pp);
    ds_destroy(&actions);
    if (error) {
        ofpbuf_uninit(&ofpacts);
        return error;
    }
    bucket->ofpacts = ofpacts.data;
    bucket->ofpacts_len = ofpacts.size;

    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_select_group_field(char *s, const struct ofputil_port_map *port_map,
                         struct field_array *fa,
                         enum ofputil_protocol *usable_protocols)
{
    char *name, *value_str;

    while (ofputil_parse_key_value(&s, &name, &value_str)) {
        const struct mf_field *mf = mf_from_name(name);

        if (mf) {
            char *error;
            union mf_value value;

            if (bitmap_is_set(fa->used.bm, mf->id)) {
                return xasprintf("%s: duplicate field", name);
            }

            if (*value_str) {
                error = mf_parse_value(mf, value_str, port_map, &value);
                if (error) {
                    return error;
                }

                /* The mask cannot be all-zeros */
                if (!mf_is_tun_metadata(mf) &&
                    is_all_zeros(&value, mf->n_bytes)) {
                    return xasprintf("%s: values are wildcards here "
                                     "and must not be all-zeros", s);
                }

                /* The values parsed are masks for fields used
                 * by the selection method */
                if (!mf_is_mask_valid(mf, &value)) {
                    return xasprintf("%s: invalid mask for field %s",
                                     value_str, mf->name);
                }
            } else {
                memset(&value, 0xff, mf->n_bytes);
            }

            field_array_set(mf->id, &value, fa);

            if (is_all_ones(&value, mf->n_bytes)) {
                *usable_protocols &= mf->usable_protocols_exact;
            } else if (mf->usable_protocols_bitwise == mf->usable_protocols_cidr
                       || ip_is_cidr(value.be32)) {
                *usable_protocols &= mf->usable_protocols_cidr;
            } else {
                *usable_protocols &= mf->usable_protocols_bitwise;
            }
        } else {
            return xasprintf("%s: unknown field %s", s, name);
        }
    }

    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_ofp_group_mod_str__(struct ofputil_group_mod *gm, int command,
                          char *string,
                          const struct ofputil_port_map *port_map,
                          const struct ofputil_table_map *table_map,
                          enum ofputil_protocol *usable_protocols)
{
    enum {
        F_GROUP_TYPE            = 1 << 0,
        F_BUCKETS               = 1 << 1,
        F_COMMAND_BUCKET_ID     = 1 << 2,
        F_COMMAND_BUCKET_ID_ALL = 1 << 3,
    } fields;
    bool had_type = false;
    bool had_command_bucket_id = false;
    struct ofputil_bucket *bucket;
    char *error = NULL;

    *usable_protocols = OFPUTIL_P_OF11_UP;

    if (command == -2) {
        size_t len;

        string += strspn(string, " \t\r\n");   /* Skip white space. */
        len = strcspn(string, ", \t\r\n"); /* Get length of the first token. */

        if (!strncmp(string, "add", len)) {
            command = OFPGC11_ADD;
        } else if (!strncmp(string, "delete", len)) {
            command = OFPGC11_DELETE;
        } else if (!strncmp(string, "modify", len)) {
            command = OFPGC11_MODIFY;
        } else if (!strncmp(string, "add_or_mod", len)) {
            command = OFPGC11_ADD_OR_MOD;
        } else if (!strncmp(string, "insert_bucket", len)) {
            command = OFPGC15_INSERT_BUCKET;
        } else if (!strncmp(string, "remove_bucket", len)) {
            command = OFPGC15_REMOVE_BUCKET;
        } else {
            len = 0;
            command = OFPGC11_ADD;
        }
        string += len;
    }

    switch (command) {
    case OFPGC11_ADD:
        fields = F_GROUP_TYPE | F_BUCKETS;
        break;

    case OFPGC11_DELETE:
        fields = 0;
        break;

    case OFPGC11_MODIFY:
        fields = F_GROUP_TYPE | F_BUCKETS;
        break;

    case OFPGC11_ADD_OR_MOD:
        fields = F_GROUP_TYPE | F_BUCKETS;
        break;

    case OFPGC15_INSERT_BUCKET:
        fields = F_BUCKETS | F_COMMAND_BUCKET_ID;
        *usable_protocols &= OFPUTIL_P_OF15_UP;
        break;

    case OFPGC15_REMOVE_BUCKET:
        fields = F_COMMAND_BUCKET_ID | F_COMMAND_BUCKET_ID_ALL;
        *usable_protocols &= OFPUTIL_P_OF15_UP;
        break;

    default:
        OVS_NOT_REACHED();
    }

    memset(gm, 0, sizeof *gm);
    gm->command = command;
    gm->group_id = OFPG_ANY;
    gm->command_bucket_id = OFPG15_BUCKET_ALL;
    ovs_list_init(&gm->buckets);
    if (command == OFPGC11_DELETE && string[0] == '\0') {
        gm->group_id = OFPG_ALL;
        return NULL;
    }

    *usable_protocols = OFPUTIL_P_OF11_UP;

    /* Strip the buckets off the end of 'string', if there are any, saving a
     * pointer for later.  We want to parse the buckets last because the bucket
     * type influences bucket defaults. */
    char *bkt_str = strstr(string, "bucket=");
    if (bkt_str) {
        if (!(fields & F_BUCKETS)) {
            error = xstrdup("bucket is not needed");
            goto out;
        }
        *bkt_str = '\0';
    }

    /* Parse everything before the buckets. */
    char *pos = string;
    char *name, *value;
    while (ofputil_parse_key_value(&pos, &name, &value)) {
        if (!strcmp(name, "command_bucket_id")) {
            if (!(fields & F_COMMAND_BUCKET_ID)) {
                error = xstrdup("command bucket id is not needed");
                goto out;
            }
            if (!strcmp(value, "all")) {
                gm->command_bucket_id = OFPG15_BUCKET_ALL;
            } else if (!strcmp(value, "first")) {
                gm->command_bucket_id = OFPG15_BUCKET_FIRST;
            } else if (!strcmp(value, "last")) {
                gm->command_bucket_id = OFPG15_BUCKET_LAST;
            } else {
                error = str_to_u32(value, &gm->command_bucket_id);
                if (error) {
                    goto out;
                }
                if (gm->command_bucket_id > OFPG15_BUCKET_MAX
                    && (gm->command_bucket_id != OFPG15_BUCKET_FIRST
                        && gm->command_bucket_id != OFPG15_BUCKET_LAST
                        && gm->command_bucket_id != OFPG15_BUCKET_ALL)) {
                    error = xasprintf("invalid command bucket id %"PRIu32,
                                      gm->command_bucket_id);
                    goto out;
                }
            }
            if (gm->command_bucket_id == OFPG15_BUCKET_ALL
                && !(fields & F_COMMAND_BUCKET_ID_ALL)) {
                error = xstrdup("command_bucket_id=all is not permitted");
                goto out;
            }
            had_command_bucket_id = true;
        } else if (!strcmp(name, "group_id")) {
            if(!strcmp(value, "all")) {
                gm->group_id = OFPG_ALL;
            } else {
                error = str_to_u32(value, &gm->group_id);
                if (error) {
                    goto out;
                }
                if (gm->group_id != OFPG_ALL && gm->group_id > OFPG_MAX) {
                    error = xasprintf("invalid group id %"PRIu32,
                                      gm->group_id);
                    goto out;
                }
            }
        } else if (!strcmp(name, "type")){
            if (!(fields & F_GROUP_TYPE)) {
                error = xstrdup("type is not needed");
                goto out;
            }
            if (!strcmp(value, "all")) {
                gm->type = OFPGT11_ALL;
            } else if (!strcmp(value, "select")) {
                gm->type = OFPGT11_SELECT;
            } else if (!strcmp(value, "indirect")) {
                gm->type = OFPGT11_INDIRECT;
            } else if (!strcmp(value, "ff") ||
                       !strcmp(value, "fast_failover")) {
                gm->type = OFPGT11_FF;
            } else {
                error = xasprintf("invalid group type %s", value);
                goto out;
            }
            had_type = true;
        } else if (!strcmp(name, "selection_method")) {
            if (!(fields & F_GROUP_TYPE)) {
                error = xstrdup("selection method is not needed");
                goto out;
            }
            if (strlen(value) >= NTR_MAX_SELECTION_METHOD_LEN) {
                error = xasprintf("selection method is longer than %u"
                                  " bytes long",
                                  NTR_MAX_SELECTION_METHOD_LEN - 1);
                goto out;
            }
            memset(gm->props.selection_method, '\0',
                   NTR_MAX_SELECTION_METHOD_LEN);
            strcpy(gm->props.selection_method, value);
            *usable_protocols &= OFPUTIL_P_OF15_UP;
        } else if (!strcmp(name, "selection_method_param")) {
            if (!(fields & F_GROUP_TYPE)) {
                error = xstrdup("selection method param is not needed");
                goto out;
            }
            error = str_to_u64(value, &gm->props.selection_method_param);
            if (error) {
                goto out;
            }
            *usable_protocols &= OFPUTIL_P_OF15_UP;
        } else if (!strcmp(name, "fields")) {
            if (!(fields & F_GROUP_TYPE)) {
                error = xstrdup("fields are not needed");
                goto out;
            }
            error = parse_select_group_field(value, port_map,
                                             &gm->props.fields,
                                             usable_protocols);
            if (error) {
                goto out;
            }
            *usable_protocols &= OFPUTIL_P_OF15_UP;
        } else {
            error = xasprintf("unknown keyword %s", name);
            goto out;
        }
    }
    if (gm->group_id == OFPG_ANY) {
        error = xstrdup("must specify a group_id");
        goto out;
    }
    if (fields & F_GROUP_TYPE && !had_type) {
        error = xstrdup("must specify a type");
        goto out;
    }

    /* Exclude fields for non "hash" selection method. */
    if (strcmp(gm->props.selection_method, "hash") &&
        gm->props.fields.values_size) {
        error = xstrdup("fields may only be specified with "
                        "\"selection_method=hash\"");
        goto out;
    }
    /* Exclude selection_method_param if no selection_method is given. */
    if (gm->props.selection_method[0] == 0
        && gm->props.selection_method_param != 0) {
        error = xstrdup("selection_method_param is only allowed with "
                        "\"selection_method\"");
        goto out;
    }
    if (fields & F_COMMAND_BUCKET_ID) {
        if (!(fields & F_COMMAND_BUCKET_ID_ALL || had_command_bucket_id)) {
            error = xstrdup("must specify a command bucket id");
            goto out;
        }
    } else if (had_command_bucket_id) {
        error = xstrdup("command bucket id is not needed");
        goto out;
    }

    /* Now parse the buckets, if any. */
    while (bkt_str) {
        char *next_bkt_str;

        bkt_str = strchr(bkt_str + 1, '=');
        if (!bkt_str) {
            error = xstrdup("must specify bucket content");
            goto out;
        }
        bkt_str++;

        next_bkt_str = strstr(bkt_str, "bucket=");
        if (next_bkt_str) {
            *next_bkt_str = '\0';
        }

        bucket = xzalloc(sizeof(struct ofputil_bucket));
        error = parse_bucket_str(bucket, bkt_str, port_map, table_map,
                                 gm->type, usable_protocols);
        if (error) {
            free(bucket);
            goto out;
        }
        ovs_list_push_back(&gm->buckets, &bucket->list_node);

        if (gm->type != OFPGT11_SELECT && bucket->weight) {
            error = xstrdup("Only select groups can have bucket weights.");
            goto out;
        }

        bkt_str = next_bkt_str;
    }
    if (gm->type == OFPGT11_INDIRECT && !ovs_list_is_short(&gm->buckets)) {
        error = xstrdup("Indirect groups can have at most one bucket.");
        goto out;
    }

    return NULL;
 out:
    ofputil_uninit_group_mod(gm);
    return error;
}

/* If 'command' is given as -2, each line may start with a command name ("add",
 * "modify", "add_or_mod", "delete", "insert_bucket", or "remove_bucket").  A
 * missing command name is treated as "add".
 */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_group_mod_str(struct ofputil_group_mod *gm, int command,
                        const char *str_,
                        const struct ofputil_port_map *port_map,
                        const struct ofputil_table_map *table_map,
                        enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error = parse_ofp_group_mod_str__(gm, command, string, port_map,
                                            table_map, usable_protocols);
    free(string);
    return error;
}

/* If 'command' is given as -2, each line may start with a command name ("add",
 * "modify", "add_or_mod", "delete", "insert_bucket", or "remove_bucket").  A
 * missing command name is treated as "add".
 */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_group_mod_file(const char *file_name,
                         const struct ofputil_port_map *port_map,
                         const struct ofputil_table_map *table_map,
                         int command,
                         struct ofputil_group_mod **gms, size_t *n_gms,
                         enum ofputil_protocol *usable_protocols)
{
    size_t allocated_gms;
    int line_number;
    FILE *stream;
    struct ds s;

    *gms = NULL;
    *n_gms = 0;

    stream = !strcmp(file_name, "-") ? stdin : fopen(file_name, "r");
    if (stream == NULL) {
        return xasprintf("%s: open failed (%s)",
                         file_name, ovs_strerror(errno));
    }

    allocated_gms = *n_gms;
    ds_init(&s);
    line_number = 0;
    *usable_protocols = OFPUTIL_P_OF11_UP;
    while (!ds_get_preprocessed_line(&s, stream, &line_number)) {
        enum ofputil_protocol usable;
        char *error;

        if (*n_gms >= allocated_gms) {
            struct ofputil_group_mod *new_gms;
            size_t i;

            new_gms = x2nrealloc(*gms, &allocated_gms, sizeof **gms);
            for (i = 0; i < *n_gms; i++) {
                ovs_list_moved(&new_gms[i].buckets, &(*gms)[i].buckets);
            }
            *gms = new_gms;
        }
        error = parse_ofp_group_mod_str(&(*gms)[*n_gms], command, ds_cstr(&s),
                                        port_map, table_map, &usable);
        if (error) {
            size_t i;

            for (i = 0; i < *n_gms; i++) {
                ofputil_uninit_group_mod(&(*gms)[i]);
            }
            free(*gms);
            *gms = NULL;
            *n_gms = 0;

            ds_destroy(&s);
            if (stream != stdin) {
                fclose(stream);
            }

            char *ret = xasprintf("%s:%d: %s", file_name, line_number, error);
            free(error);
            return ret;
        }
        *usable_protocols &= usable;
        *n_gms += 1;
    }

    ds_destroy(&s);
    if (stream != stdin) {
        fclose(stream);
    }
    return NULL;
}

static void
ofputil_put_ofp11_bucket(const struct ofputil_bucket *bucket,
                         struct ofpbuf *openflow, enum ofp_version ofp_version)
{
    struct ofp11_bucket *ob;
    size_t start;

    start = openflow->size;
    ofpbuf_put_zeros(openflow, sizeof *ob);
    ofpacts_put_openflow_actions(bucket->ofpacts, bucket->ofpacts_len,
                                openflow, ofp_version);
    ob = ofpbuf_at_assert(openflow, start, sizeof *ob);
    ob->len = htons(openflow->size - start);
    ob->weight = htons(bucket->weight);
    ob->watch_port = ofputil_port_to_ofp11(bucket->watch_port);
    ob->watch_group = htonl(bucket->watch_group);
}

static void
ofputil_put_ofp15_bucket(const struct ofputil_bucket *bucket,
                         uint32_t bucket_id, enum ofp11_group_type group_type,
                         struct ofpbuf *openflow, enum ofp_version ofp_version)
{
    struct ofp15_bucket *ob;
    size_t start, actions_start, actions_len;

    start = openflow->size;
    ofpbuf_put_zeros(openflow, sizeof *ob);

    actions_start = openflow->size;
    ofpacts_put_openflow_actions(bucket->ofpacts, bucket->ofpacts_len,
                                 openflow, ofp_version);
    actions_len = openflow->size - actions_start;

    if (group_type == OFPGT11_SELECT) {
        ofpprop_put_u16(openflow, OFPGBPT15_WEIGHT, bucket->weight);
    }
    if (bucket->watch_port != OFPP_ANY) {
        ofpprop_put_be32(openflow, OFPGBPT15_WATCH_PORT,
                         ofputil_port_to_ofp11(bucket->watch_port));
    }
    if (bucket->watch_group != OFPG_ANY) {
        ofpprop_put_u32(openflow, OFPGBPT15_WATCH_GROUP, bucket->watch_group);
    }

    ob = ofpbuf_at_assert(openflow, start, sizeof *ob);
    ob->len = htons(openflow->size - start);
    ob->action_array_len = htons(actions_len);
    ob->bucket_id = htonl(bucket_id);
}

static void
ofputil_put_group_prop_ntr_selection_method(enum ofp_version ofp_version,
                                            const struct ofputil_group_props *gp,
                                            struct ofpbuf *openflow)
{
    struct ntr_group_prop_selection_method *prop;
    size_t start;

    start = openflow->size;
    ofpbuf_put_zeros(openflow, sizeof *prop);
    oxm_put_field_array(openflow, &gp->fields, ofp_version);
    prop = ofpbuf_at_assert(openflow, start, sizeof *prop);
    prop->type = htons(OFPGPT15_EXPERIMENTER);
    prop->experimenter = htonl(NTR_VENDOR_ID);
    prop->exp_type = htonl(NTRT_SELECTION_METHOD);
    strcpy(prop->selection_method, gp->selection_method);
    prop->selection_method_param = htonll(gp->selection_method_param);
    ofpprop_end(openflow, start);
}

static void
ofputil_append_ofp11_group_desc_reply(const struct ofputil_group_desc *gds,
                                      const struct ovs_list *buckets,
                                      struct ovs_list *replies,
                                      enum ofp_version version)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    struct ofp11_group_desc_stats *ogds;
    struct ofputil_bucket *bucket;
    size_t start_ogds;

    start_ogds = reply->size;
    ofpbuf_put_zeros(reply, sizeof *ogds);
    LIST_FOR_EACH (bucket, list_node, buckets) {
        ofputil_put_ofp11_bucket(bucket, reply, version);
    }
    ogds = ofpbuf_at_assert(reply, start_ogds, sizeof *ogds);
    ogds->length = htons(reply->size - start_ogds);
    ogds->type = gds->type;
    ogds->group_id = htonl(gds->group_id);

    ofpmp_postappend(replies, start_ogds);
}

static void
ofputil_append_ofp15_group_desc_reply(const struct ofputil_group_desc *gds,
                                      const struct ovs_list *buckets,
                                      struct ovs_list *replies,
                                      enum ofp_version version)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    struct ofp15_group_desc_stats *ogds;
    struct ofputil_bucket *bucket;
    size_t start_ogds, start_buckets;

    start_ogds = reply->size;
    ofpbuf_put_zeros(reply, sizeof *ogds);
    start_buckets = reply->size;
    LIST_FOR_EACH (bucket, list_node, buckets) {
        ofputil_put_ofp15_bucket(bucket, bucket->bucket_id,
                                 gds->type, reply, version);
    }
    ogds = ofpbuf_at_assert(reply, start_ogds, sizeof *ogds);
    ogds->type = gds->type;
    ogds->group_id = htonl(gds->group_id);
    ogds->bucket_list_len =  htons(reply->size - start_buckets);

    /* Add group properties */
    if (gds->props.selection_method[0]) {
        ofputil_put_group_prop_ntr_selection_method(version, &gds->props,
                                                    reply);
    }
    ogds = ofpbuf_at_assert(reply, start_ogds, sizeof *ogds);
    ogds->length = htons(reply->size - start_ogds);

    ofpmp_postappend(replies, start_ogds);
}

/* Appends a group stats reply that contains the data in 'gds' to those already
 * present in the list of ofpbufs in 'replies'.  'replies' should have been
 * initialized with ofpmp_init(). */
void
ofputil_append_group_desc_reply(const struct ofputil_group_desc *gds,
                                const struct ovs_list *buckets,
                                struct ovs_list *replies)
{
    enum ofp_version version = ofpmp_version(replies);

    switch (version)
    {
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        ofputil_append_ofp11_group_desc_reply(gds, buckets, replies, version);
        break;

    case OFP15_VERSION:
    case OFP16_VERSION:
        ofputil_append_ofp15_group_desc_reply(gds, buckets, replies, version);
        break;

    case OFP10_VERSION:
    default:
        OVS_NOT_REACHED();
    }
}

static enum ofperr
ofputil_pull_ofp11_buckets(struct ofpbuf *msg, size_t buckets_length,
                           enum ofp_version version, struct ovs_list *buckets)
{
    struct ofp11_bucket *ob;
    uint32_t bucket_id = 0;

    ovs_list_init(buckets);
    while (buckets_length > 0) {
        struct ofputil_bucket *bucket;
        struct ofpbuf ofpacts;
        enum ofperr error;
        size_t ob_len;

        ob = (buckets_length >= sizeof *ob
              ? ofpbuf_try_pull(msg, sizeof *ob)
              : NULL);
        if (!ob) {
            VLOG_WARN_RL(&rl, "buckets end with %"PRIuSIZE" leftover bytes",
                         buckets_length);
            ofputil_bucket_list_destroy(buckets);
            return OFPERR_OFPGMFC_BAD_BUCKET;
        }

        ob_len = ntohs(ob->len);
        if (ob_len < sizeof *ob) {
            VLOG_WARN_RL(&rl, "OpenFlow message bucket length "
                         "%"PRIuSIZE" is not valid", ob_len);
            ofputil_bucket_list_destroy(buckets);
            return OFPERR_OFPGMFC_BAD_BUCKET;
        } else if (ob_len > buckets_length) {
            VLOG_WARN_RL(&rl, "OpenFlow message bucket length %"PRIuSIZE" "
                         "exceeds remaining buckets data size %"PRIuSIZE,
                         ob_len, buckets_length);
            ofputil_bucket_list_destroy(buckets);
            return OFPERR_OFPGMFC_BAD_BUCKET;
        }
        buckets_length -= ob_len;

        ofpbuf_init(&ofpacts, 0);
        error = ofpacts_pull_openflow_actions(msg, ob_len - sizeof *ob,
                                              version, NULL, NULL, &ofpacts);
        if (error) {
            ofpbuf_uninit(&ofpacts);
            ofputil_bucket_list_destroy(buckets);
            return error;
        }

        bucket = xzalloc(sizeof *bucket);
        bucket->weight = ntohs(ob->weight);
        error = ofputil_port_from_ofp11(ob->watch_port, &bucket->watch_port);
        if (error) {
            ofpbuf_uninit(&ofpacts);
            ofputil_bucket_list_destroy(buckets);
            free(bucket);
            return OFPERR_OFPGMFC_BAD_WATCH;
        }
        bucket->watch_group = ntohl(ob->watch_group);
        bucket->bucket_id = bucket_id++;

        bucket->ofpacts = ofpbuf_steal_data(&ofpacts);
        bucket->ofpacts_len = ofpacts.size;
        ovs_list_push_back(buckets, &bucket->list_node);
    }

    return 0;
}

static enum ofperr
ofputil_pull_ofp15_buckets(struct ofpbuf *msg, size_t buckets_length,
                           enum ofp_version version, uint8_t group_type,
                           struct ovs_list *buckets)
{
    struct ofp15_bucket *ob;

    ovs_list_init(buckets);
    while (buckets_length > 0) {
        struct ofputil_bucket *bucket = NULL;
        struct ofpbuf ofpacts;
        enum ofperr err = OFPERR_OFPGMFC_BAD_BUCKET;
        size_t ob_len, actions_len, properties_len;
        ovs_be32 watch_port = ofputil_port_to_ofp11(OFPP_ANY);
        ovs_be32 watch_group = htonl(OFPG_ANY);
        ovs_be16 weight = htons(group_type == OFPGT11_SELECT ? 1 : 0);

        ofpbuf_init(&ofpacts, 0);

        ob = ofpbuf_try_pull(msg, sizeof *ob);
        if (!ob) {
            VLOG_WARN_RL(&rl, "buckets end with %"PRIuSIZE
                         " leftover bytes", buckets_length);
            goto err;
        }

        ob_len = ntohs(ob->len);
        actions_len = ntohs(ob->action_array_len);

        if (ob_len < sizeof *ob) {
            VLOG_WARN_RL(&rl, "OpenFlow message bucket length "
                         "%"PRIuSIZE" is not valid", ob_len);
            goto err;
        } else if (ob_len > buckets_length) {
            VLOG_WARN_RL(&rl, "OpenFlow message bucket length "
                         "%"PRIuSIZE" exceeds remaining buckets data size %"
                         PRIuSIZE, ob_len, buckets_length);
            goto err;
        } else if (actions_len > ob_len - sizeof *ob) {
            VLOG_WARN_RL(&rl, "OpenFlow message bucket actions "
                         "length %"PRIuSIZE" exceeds remaining bucket "
                         "data size %"PRIuSIZE, actions_len,
                         ob_len - sizeof *ob);
            goto err;
        }
        buckets_length -= ob_len;

        err = ofpacts_pull_openflow_actions(msg, actions_len, version,
                                            NULL, NULL, &ofpacts);
        if (err) {
            goto err;
        }

        properties_len = ob_len - sizeof *ob - actions_len;
        struct ofpbuf properties = ofpbuf_const_initializer(
            ofpbuf_pull(msg, properties_len), properties_len);
        while (properties.size > 0) {
            struct ofpbuf payload;
            uint64_t type;

            err = ofpprop_pull(&properties, &payload, &type);
            if (err) {
                goto err;
            }

            switch (type) {
            case OFPGBPT15_WEIGHT:
                err = ofpprop_parse_be16(&payload, &weight);
                break;

            case OFPGBPT15_WATCH_PORT:
                err = ofpprop_parse_be32(&payload, &watch_port);
                break;

            case OFPGBPT15_WATCH_GROUP:
                err = ofpprop_parse_be32(&payload, &watch_group);
                break;

            default:
                err = OFPPROP_UNKNOWN(false, "group bucket", type);
                break;
            }

            if (err) {
                goto err;
            }
        }

        bucket = xzalloc(sizeof *bucket);

        bucket->weight = ntohs(weight);
        err = ofputil_port_from_ofp11(watch_port, &bucket->watch_port);
        if (err) {
            err = OFPERR_OFPGMFC_BAD_WATCH;
            goto err;
        }
        bucket->watch_group = ntohl(watch_group);
        bucket->bucket_id = ntohl(ob->bucket_id);
        if (bucket->bucket_id > OFPG15_BUCKET_MAX) {
            VLOG_WARN_RL(&rl, "bucket id (%u) is out of range",
                         bucket->bucket_id);
            err = OFPERR_OFPGMFC_BAD_BUCKET;
            goto err;
        }

        bucket->ofpacts = ofpbuf_steal_data(&ofpacts);
        bucket->ofpacts_len = ofpacts.size;
        ovs_list_push_back(buckets, &bucket->list_node);

        continue;

    err:
        free(bucket);
        ofpbuf_uninit(&ofpacts);
        ofputil_bucket_list_destroy(buckets);
        return err;
    }

    if (ofputil_bucket_check_duplicate_id(buckets)) {
        VLOG_WARN_RL(&rl, "Duplicate bucket id");
        ofputil_bucket_list_destroy(buckets);
        return OFPERR_OFPGMFC_BAD_BUCKET;
    }

    return 0;
}

static void
ofputil_init_group_properties(struct ofputil_group_props *gp)
{
    memset(gp, 0, sizeof *gp);
}

void
ofputil_group_properties_copy(struct ofputil_group_props *to,
                              const struct ofputil_group_props *from)
{
    *to = *from;
    to->fields.values = xmemdup(from->fields.values, from->fields.values_size);
}

void
ofputil_group_properties_destroy(struct ofputil_group_props *gp)
{
    free(gp->fields.values);
}

static enum ofperr
parse_group_prop_ntr_selection_method(struct ofpbuf *payload,
                                      enum ofp11_group_type group_type,
                                      enum ofp15_group_mod_command group_cmd,
                                      struct ofputil_group_props *gp)
{
    struct ntr_group_prop_selection_method *prop = payload->data;
    size_t fields_len, method_len;
    enum ofperr error;

    switch (group_type) {
    case OFPGT11_SELECT:
        break;
    case OFPGT11_ALL:
    case OFPGT11_INDIRECT:
    case OFPGT11_FF:
        OFPPROP_LOG(&rl, false, "ntr selection method property is "
                    "only allowed for select groups");
        return OFPERR_OFPBPC_BAD_VALUE;
    default:
        OVS_NOT_REACHED();
    }

    switch (group_cmd) {
    case OFPGC15_ADD:
    case OFPGC15_MODIFY:
    case OFPGC15_ADD_OR_MOD:
        break;
    case OFPGC15_DELETE:
    case OFPGC15_INSERT_BUCKET:
    case OFPGC15_REMOVE_BUCKET:
        OFPPROP_LOG(&rl, false, "ntr selection method property is "
                    "only allowed for add and delete group modifications");
        return OFPERR_OFPBPC_BAD_VALUE;
    default:
        OVS_NOT_REACHED();
    }

    if (payload->size < sizeof *prop) {
        OFPPROP_LOG(&rl, false, "ntr selection method property "
                    "length %u is not valid", payload->size);
        return OFPERR_OFPBPC_BAD_LEN;
    }

    method_len = strnlen(prop->selection_method, NTR_MAX_SELECTION_METHOD_LEN);

    if (method_len == NTR_MAX_SELECTION_METHOD_LEN) {
        OFPPROP_LOG(&rl, false,
                    "ntr selection method is not null terminated");
        return OFPERR_OFPBPC_BAD_VALUE;
    }

    if (strcmp("hash", prop->selection_method)
        && strcmp("dp_hash", prop->selection_method)) {
        OFPPROP_LOG(&rl, false,
                    "ntr selection method '%s' is not supported",
                    prop->selection_method);
        return OFPERR_OFPBPC_BAD_VALUE;
    }
    /* 'method_len' is now non-zero. */

    strcpy(gp->selection_method, prop->selection_method);
    gp->selection_method_param = ntohll(prop->selection_method_param);

    ofpbuf_pull(payload, sizeof *prop);

    fields_len = ntohs(prop->length) - sizeof *prop;
    if (fields_len && strcmp("hash", gp->selection_method)) {
        OFPPROP_LOG(&rl, false, "ntr selection method %s "
                    "does not support fields", gp->selection_method);
        return OFPERR_OFPBPC_BAD_VALUE;
    }

    error = oxm_pull_field_array(payload->data, fields_len,
                                 &gp->fields);
    if (error) {
        OFPPROP_LOG(&rl, false,
                    "ntr selection method fields are invalid");
        return error;
    }

    return 0;
}

static enum ofperr
parse_ofp15_group_properties(struct ofpbuf *msg,
                             enum ofp11_group_type group_type,
                             enum ofp15_group_mod_command group_cmd,
                             struct ofputil_group_props *gp,
                             size_t properties_len)
{
    struct ofpbuf properties = ofpbuf_const_initializer(
        ofpbuf_pull(msg, properties_len), properties_len);
    while (properties.size > 0) {
        struct ofpbuf payload;
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPPROP_EXP(NTR_VENDOR_ID, NTRT_SELECTION_METHOD):
        case OFPPROP_EXP(NTR_COMPAT_VENDOR_ID, NTRT_SELECTION_METHOD):
            error = parse_group_prop_ntr_selection_method(&payload, group_type,
                                                          group_cmd, gp);
            break;

        default:
            error = OFPPROP_UNKNOWN(false, "group", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

static int
ofputil_decode_ofp11_group_desc_reply(struct ofputil_group_desc *gd,
                                      struct ofpbuf *msg,
                                      enum ofp_version version)
{
    struct ofp11_group_desc_stats *ogds;
    size_t length;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    ogds = ofpbuf_try_pull(msg, sizeof *ogds);
    if (!ogds) {
        VLOG_WARN_RL(&rl, "OFPST11_GROUP_DESC reply has %"PRIu32" "
                     "leftover bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    gd->type = ogds->type;
    gd->group_id = ntohl(ogds->group_id);

    length = ntohs(ogds->length);
    if (length < sizeof *ogds || length - sizeof *ogds > msg->size) {
        VLOG_WARN_RL(&rl, "OFPST11_GROUP_DESC reply claims invalid "
                     "length %"PRIuSIZE, length);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    return ofputil_pull_ofp11_buckets(msg, length - sizeof *ogds, version,
                                      &gd->buckets);
}

static int
ofputil_decode_ofp15_group_desc_reply(struct ofputil_group_desc *gd,
                                      struct ofpbuf *msg,
                                      enum ofp_version version)
{
    struct ofp15_group_desc_stats *ogds;
    uint16_t length, bucket_list_len;
    int error;

    if (!msg->header) {
        ofpraw_pull_assert(msg);
    }

    if (!msg->size) {
        return EOF;
    }

    ogds = ofpbuf_try_pull(msg, sizeof *ogds);
    if (!ogds) {
        VLOG_WARN_RL(&rl, "OFPST11_GROUP_DESC reply has %"PRIu32" "
                     "leftover bytes at end", msg->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    gd->type = ogds->type;
    gd->group_id = ntohl(ogds->group_id);

    length = ntohs(ogds->length);
    if (length < sizeof *ogds || length - sizeof *ogds > msg->size) {
        VLOG_WARN_RL(&rl, "OFPST11_GROUP_DESC reply claims invalid "
                     "length %u", length);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    bucket_list_len = ntohs(ogds->bucket_list_len);
    if (length < bucket_list_len + sizeof *ogds) {
        VLOG_WARN_RL(&rl, "OFPST11_GROUP_DESC reply claims invalid "
                     "bucket list length %u", bucket_list_len);
        return OFPERR_OFPBRC_BAD_LEN;
    }
    error = ofputil_pull_ofp15_buckets(msg, bucket_list_len, version, gd->type,
                                       &gd->buckets);
    if (error) {
        return error;
    }

    /* By definition group desc messages don't have a group mod command.
     * However, parse_group_prop_ntr_selection_method() checks to make sure
     * that the command is OFPGC15_ADD or OFPGC15_DELETE to guard
     * against group mod messages with other commands supplying
     * a NTR selection method group experimenter property.
     * Such properties are valid for group desc replies so
     * claim that the group mod command is OFPGC15_ADD to
     * satisfy the check in parse_group_prop_ntr_selection_method() */
    error = parse_ofp15_group_properties(
        msg, gd->type, OFPGC15_ADD, &gd->props,
        length - sizeof *ogds - bucket_list_len);
    if (error) {
        ofputil_bucket_list_destroy(&gd->buckets);
    }
    return error;
}

/* Converts a group description reply in 'msg' into an abstract
 * ofputil_group_desc in 'gd'.
 *
 * Multiple group description replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  The caller must initially leave 'msg''s layer pointers
 * null and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_group_desc_reply(struct ofputil_group_desc *gd,
                                struct ofpbuf *msg, enum ofp_version version)
{
    ofputil_init_group_properties(&gd->props);

    switch (version)
    {
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        return ofputil_decode_ofp11_group_desc_reply(gd, msg, version);

    case OFP15_VERSION:
    case OFP16_VERSION:
        return ofputil_decode_ofp15_group_desc_reply(gd, msg, version);

    case OFP10_VERSION:
    default:
        OVS_NOT_REACHED();
    }
}

void
ofputil_uninit_group_mod(struct ofputil_group_mod *gm)
{
    ofputil_bucket_list_destroy(&gm->buckets);
    ofputil_group_properties_destroy(&gm->props);
}

static struct ofpbuf *
ofputil_encode_ofp11_group_mod(enum ofp_version ofp_version,
                               const struct ofputil_group_mod *gm)
{
    struct ofpbuf *b;
    struct ofp11_group_mod *ogm;
    size_t start_ogm;
    struct ofputil_bucket *bucket;

    b = ofpraw_alloc(OFPRAW_OFPT11_GROUP_MOD, ofp_version, 0);
    start_ogm = b->size;
    ofpbuf_put_zeros(b, sizeof *ogm);

    LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
        ofputil_put_ofp11_bucket(bucket, b, ofp_version);
    }
    ogm = ofpbuf_at_assert(b, start_ogm, sizeof *ogm);
    ogm->command = htons(gm->command);
    ogm->type = gm->type;
    ogm->group_id = htonl(gm->group_id);

    return b;
}

static struct ofpbuf *
ofputil_encode_ofp15_group_mod(enum ofp_version ofp_version,
                               const struct ofputil_group_mod *gm)
{
    struct ofpbuf *b;
    struct ofp15_group_mod *ogm;
    size_t start_ogm;
    struct ofputil_bucket *bucket;
    struct id_pool *bucket_ids = NULL;

    b = ofpraw_alloc(OFPRAW_OFPT15_GROUP_MOD, ofp_version, 0);
    start_ogm = b->size;
    ofpbuf_put_zeros(b, sizeof *ogm);

    LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
        uint32_t bucket_id;

        /* Generate a bucket id if none was supplied */
        if (bucket->bucket_id > OFPG15_BUCKET_MAX) {
            if (!bucket_ids) {
                const struct ofputil_bucket *bkt;

                bucket_ids = id_pool_create(0, OFPG15_BUCKET_MAX + 1);

                /* Mark all bucket_ids that are present in gm
                 * as used in the pool. */
                LIST_FOR_EACH_REVERSE (bkt, list_node, &gm->buckets) {
                    if (bkt == bucket) {
                        break;
                    }
                    if (bkt->bucket_id <= OFPG15_BUCKET_MAX) {
                        id_pool_add(bucket_ids, bkt->bucket_id);
                    }
                }
            }

            if (!id_pool_alloc_id(bucket_ids, &bucket_id)) {
                OVS_NOT_REACHED();
            }
        } else {
            bucket_id = bucket->bucket_id;
        }

        ofputil_put_ofp15_bucket(bucket, bucket_id, gm->type, b, ofp_version);
    }
    ogm = ofpbuf_at_assert(b, start_ogm, sizeof *ogm);
    ogm->command = htons(gm->command);
    ogm->type = gm->type;
    ogm->group_id = htonl(gm->group_id);
    ogm->command_bucket_id = htonl(gm->command_bucket_id);
    ogm->bucket_array_len = htons(b->size - start_ogm - sizeof *ogm);

    /* Add group properties */
    if (gm->props.selection_method[0]) {
        ofputil_put_group_prop_ntr_selection_method(ofp_version, &gm->props, b);
    }

    id_pool_destroy(bucket_ids);
    return b;
}

static void
bad_group_cmd(enum ofp15_group_mod_command cmd)
{
    const char *opt_version;
    const char *version;
    const char *cmd_str;

    switch (cmd) {
    case OFPGC15_ADD:
    case OFPGC15_MODIFY:
    case OFPGC15_ADD_OR_MOD:
    case OFPGC15_DELETE:
        version = "1.1";
        opt_version = "11";
        break;

    case OFPGC15_INSERT_BUCKET:
    case OFPGC15_REMOVE_BUCKET:
        version = "1.5";
        opt_version = "15";
        break;

    default:
        OVS_NOT_REACHED();
    }

    switch (cmd) {
    case OFPGC15_ADD:
        cmd_str = "add-group";
        break;

    case OFPGC15_MODIFY:
    case OFPGC15_ADD_OR_MOD:
        cmd_str = "mod-group";
        break;

    case OFPGC15_DELETE:
        cmd_str = "del-group";
        break;

    case OFPGC15_INSERT_BUCKET:
        cmd_str = "insert-bucket";
        break;

    case OFPGC15_REMOVE_BUCKET:
        cmd_str = "remove-bucket";
        break;

    default:
        OVS_NOT_REACHED();
    }

    ovs_fatal(0, "%s needs OpenFlow %s or later (\'-O OpenFlow%s\')",
              cmd_str, version, opt_version);

}

/* Converts abstract group mod 'gm' into a message for OpenFlow version
 * 'ofp_version' and returns the message. */
struct ofpbuf *
ofputil_encode_group_mod(enum ofp_version ofp_version,
                         const struct ofputil_group_mod *gm)
{

    switch (ofp_version) {
    case OFP10_VERSION:
        bad_group_cmd(gm->command);
        /* fall through */

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        if (gm->command > OFPGC11_DELETE && gm->command != OFPGC11_ADD_OR_MOD) {
            bad_group_cmd(gm->command);
        }
        return ofputil_encode_ofp11_group_mod(ofp_version, gm);

    case OFP15_VERSION:
    case OFP16_VERSION:
        return ofputil_encode_ofp15_group_mod(ofp_version, gm);

    default:
        OVS_NOT_REACHED();
    }
}

static enum ofperr
ofputil_pull_ofp11_group_mod(struct ofpbuf *msg, enum ofp_version ofp_version,
                             struct ofputil_group_mod *gm)
{
    const struct ofp11_group_mod *ogm;
    enum ofperr error;

    ogm = ofpbuf_pull(msg, sizeof *ogm);
    gm->command = ntohs(ogm->command);
    gm->type = ogm->type;
    gm->group_id = ntohl(ogm->group_id);
    gm->command_bucket_id = OFPG15_BUCKET_ALL;

    error = ofputil_pull_ofp11_buckets(msg, msg->size, ofp_version,
                                       &gm->buckets);

    /* OF1.3.5+ prescribes an error when an OFPGC_DELETE includes buckets. */
    if (!error
        && ofp_version >= OFP13_VERSION
        && gm->command == OFPGC11_DELETE
        && !ovs_list_is_empty(&gm->buckets)) {
        error = OFPERR_OFPGMFC_INVALID_GROUP;
        ofputil_bucket_list_destroy(&gm->buckets);
    }

    return error;
}

static enum ofperr
ofputil_pull_ofp15_group_mod(struct ofpbuf *msg, enum ofp_version ofp_version,
                             struct ofputil_group_mod *gm)
{
    const struct ofp15_group_mod *ogm;
    uint16_t bucket_list_len;
    enum ofperr error = OFPERR_OFPGMFC_BAD_BUCKET;

    ogm = ofpbuf_pull(msg, sizeof *ogm);
    gm->command = ntohs(ogm->command);
    gm->type = ogm->type;
    gm->group_id = ntohl(ogm->group_id);

    gm->command_bucket_id = ntohl(ogm->command_bucket_id);
    switch (gm->command) {
    case OFPGC15_REMOVE_BUCKET:
        if (gm->command_bucket_id == OFPG15_BUCKET_ALL) {
            error = 0;
        }
        /* Fall through */
    case OFPGC15_INSERT_BUCKET:
        if (gm->command_bucket_id <= OFPG15_BUCKET_MAX ||
            gm->command_bucket_id == OFPG15_BUCKET_FIRST
            || gm->command_bucket_id == OFPG15_BUCKET_LAST) {
            error = 0;
        }
        break;

    case OFPGC11_ADD:
    case OFPGC11_MODIFY:
    case OFPGC11_ADD_OR_MOD:
    case OFPGC11_DELETE:
    default:
        if (gm->command_bucket_id == OFPG15_BUCKET_ALL) {
            error = 0;
        }
        break;
    }
    if (error) {
        VLOG_WARN_RL(&rl,
                     "group command bucket id (%u) is out of range",
                     gm->command_bucket_id);
        return OFPERR_OFPGMFC_BAD_BUCKET;
    }

    bucket_list_len = ntohs(ogm->bucket_array_len);
    if (bucket_list_len > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    error = ofputil_pull_ofp15_buckets(msg, bucket_list_len, ofp_version,
                                       gm->type, &gm->buckets);
    if (error) {
        return error;
    }

    error = parse_ofp15_group_properties(msg, gm->type, gm->command,
                                         &gm->props, msg->size);
    if (error) {
        ofputil_bucket_list_destroy(&gm->buckets);
    }
    return error;
}

static enum ofperr
ofputil_check_group_mod(const struct ofputil_group_mod *gm)
{
    switch (gm->type) {
    case OFPGT11_INDIRECT:
        if (gm->command != OFPGC11_DELETE
            && !ovs_list_is_singleton(&gm->buckets) ) {
            return OFPERR_OFPGMFC_INVALID_GROUP;
        }
        break;
    case OFPGT11_ALL:
    case OFPGT11_SELECT:
    case OFPGT11_FF:
        break;
    default:
        return OFPERR_OFPGMFC_BAD_TYPE;
    }

    switch (gm->command) {
    case OFPGC11_ADD:
    case OFPGC11_MODIFY:
    case OFPGC11_ADD_OR_MOD:
    case OFPGC11_DELETE:
    case OFPGC15_INSERT_BUCKET:
        break;
    case OFPGC15_REMOVE_BUCKET:
        if (!ovs_list_is_empty(&gm->buckets)) {
            return OFPERR_OFPGMFC_BAD_BUCKET;
        }
        break;
    default:
        return OFPERR_OFPGMFC_BAD_COMMAND;
    }

    struct ofputil_bucket *bucket;
    LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
        if (bucket->weight && gm->type != OFPGT11_SELECT) {
            return OFPERR_OFPGMFC_INVALID_GROUP;
        }

        switch (gm->type) {
        case OFPGT11_ALL:
        case OFPGT11_INDIRECT:
            if (ofputil_bucket_has_liveness(bucket)) {
                return OFPERR_OFPGMFC_WATCH_UNSUPPORTED;
            }
            break;
        case OFPGT11_SELECT:
            break;
        case OFPGT11_FF:
            if (!ofputil_bucket_has_liveness(bucket)) {
                return OFPERR_OFPGMFC_INVALID_GROUP;
            }
            break;
        default:
            /* Returning BAD TYPE to be consistent
             * though gm->type has been checked already. */
            return OFPERR_OFPGMFC_BAD_TYPE;
        }
    }

    return 0;
}

/* Converts OpenFlow group mod message 'oh' into an abstract group mod in
 * 'gm'.  Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
ofputil_decode_group_mod(const struct ofp_header *oh,
                         struct ofputil_group_mod *gm)
{
    ofputil_init_group_properties(&gm->props);

    enum ofp_version ofp_version = oh->version;
    struct ofpbuf msg = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&msg);

    enum ofperr err;
    switch (ofp_version) {
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        err = ofputil_pull_ofp11_group_mod(&msg, ofp_version, gm);
        break;

    case OFP15_VERSION:
    case OFP16_VERSION:
        err = ofputil_pull_ofp15_group_mod(&msg, ofp_version, gm);
        break;

    case OFP10_VERSION:
    default:
        OVS_NOT_REACHED();
    }
    if (err) {
        return err;
    }

    err = ofputil_check_group_mod(gm);
    if (err) {
        ofputil_uninit_group_mod(gm);
    }
    return err;
}
