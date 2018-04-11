/*
 * Copyright (c) 2017, 2018 Nicira, Inc.
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

#include "raft-private.h"

#include "openvswitch/dynamic-string.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "socket-util.h"
#include "sset.h"

/* Addresses of Raft servers. */

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_address_validate(const char *address)
{
    if (!strncmp(address, "unix:", 5)) {
        return NULL;
    } else if (!strncmp(address, "ssl:", 4) || !strncmp(address, "tcp:", 4)) {
        struct sockaddr_storage ss;
        if (!inet_parse_active(address + 4, -1, &ss)) {
            return ovsdb_error(NULL, "%s: syntax error in address", address);
        }
        return NULL;
    } else {
        return ovsdb_error(NULL, "%s: expected \"tcp\" or \"ssl\" address",
                           address);
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_address_validate_json(const struct json *address)
{
    if (address->type != JSON_STRING) {
        return ovsdb_syntax_error(address, NULL,
                                  "server address is not string");
    }
    return raft_address_validate(json_string(address));
}

/* Constructs and returns a "nickname" for a Raft server based on its 'address'
 * and server ID 'sid'.  The nickname is just a short name for the server to
 * use in log messages, to make them more readable.
 *
 * The caller must eventually free the returned string. */
char *
raft_address_to_nickname(const char *address, const struct uuid *sid)
{
    if (!strncmp(address, "unix:", 5)) {
        const char *p = address + 5;

        const char *slash = strrchr(p, '/');
        if (slash) {
            p = slash + 1;
        }

        int len = strcspn(p, ".");
        if (len) {
            return xmemdup0(p, len);
        }
    }

    return xasprintf(SID_FMT, SID_ARGS(sid));
}

/* Sets of Raft server addresses. */

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_addresses_from_json(const struct json *json, struct sset *addresses)
{
    sset_init(addresses);

    const struct json_array *array = json_array(json);
    if (!array->n) {
        return ovsdb_syntax_error(json, NULL,
                                  "at least one remote address is required");
    }
    for (size_t i = 0; i < array->n; i++) {
        const struct json *address = array->elems[i];
        struct ovsdb_error *error = raft_address_validate_json(address);
        if (error) {
            sset_destroy(addresses);
            sset_init(addresses);
            return error;
        }
        sset_add(addresses, json_string(address));
    }
    return NULL;
}

struct json *
raft_addresses_to_json(const struct sset *sset)
{
    struct json *array;
    const char *s;

    array = json_array_create_empty();
    SSET_FOR_EACH (s, sset) {
        json_array_add(array, json_string_create(s));
    }
    return array;
}

/* raft_server. */

const char *
raft_server_phase_to_string(enum raft_server_phase phase)
{
    switch (phase) {
    case RAFT_PHASE_STABLE: return "stable";
    case RAFT_PHASE_CATCHUP: return "adding: catchup";
    case RAFT_PHASE_CAUGHT_UP: return "adding: caught up";
    case RAFT_PHASE_COMMITTING: return "adding: committing";
    case RAFT_PHASE_REMOVE: return "removing";
    default: return "<error>";
    }
}

void
raft_server_destroy(struct raft_server *s)
{
    if (s) {
        free(s->address);
        free(s->nickname);
        free(s);
    }
}

void
raft_servers_destroy(struct hmap *servers)
{
    struct raft_server *s, *next;
    HMAP_FOR_EACH_SAFE (s, next, hmap_node, servers) {
        hmap_remove(servers, &s->hmap_node);
        raft_server_destroy(s);
    }
    hmap_destroy(servers);
}

struct raft_server *
raft_server_add(struct hmap *servers, const struct uuid *sid,
                const char *address)
{
    struct raft_server *s = xzalloc(sizeof *s);
    s->sid = *sid;
    s->address = xstrdup(address);
    s->nickname = raft_address_to_nickname(address, sid);
    s->phase = RAFT_PHASE_STABLE;
    hmap_insert(servers, &s->hmap_node, uuid_hash(sid));
    return s;
}


struct raft_server *
raft_server_find(const struct hmap *servers, const struct uuid *sid)
{
    struct raft_server *s;
    HMAP_FOR_EACH_IN_BUCKET (s, hmap_node, uuid_hash(sid), servers) {
        if (uuid_equals(sid, &s->sid)) {
            return s;
        }
    }
    return NULL;
}

const char *
raft_servers_get_nickname__(const struct hmap *servers, const struct uuid *sid)
{
    const struct raft_server *s = raft_server_find(servers, sid);
    return s ? s->nickname : NULL;
}

const char *
raft_servers_get_nickname(const struct hmap *servers,
                          const struct uuid *sid,
                          char buf[SID_LEN + 1], size_t bufsize)
{
    const char *s = raft_servers_get_nickname__(servers, sid);
    if (s) {
        return s;
    }
    snprintf(buf, bufsize, SID_FMT, SID_ARGS(sid));
    return buf;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_servers_from_json__(const struct json *json, struct hmap *servers)
{
    if (!json || json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "servers must be JSON object");
    } else if (shash_is_empty(json_object(json))) {
        return ovsdb_syntax_error(json, NULL, "must have at least one server");
    }

    /* Parse new servers. */
    struct shash_node *node;
    SHASH_FOR_EACH (node, json_object(json)) {
        /* Parse server UUID. */
        struct uuid sid;
        if (!uuid_from_string(&sid, node->name)) {
            return ovsdb_syntax_error(json, NULL, "%s is not a UUID",
                                      node->name);
        }

        const struct json *address = node->data;
        struct ovsdb_error *error = raft_address_validate_json(address);
        if (error) {
            return error;
        }

        raft_server_add(servers, &sid, json_string(address));
    }

    return NULL;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_servers_from_json(const struct json *json, struct hmap *servers)
{
    hmap_init(servers);
    struct ovsdb_error *error = raft_servers_from_json__(json, servers);
    if (error) {
        raft_servers_destroy(servers);
    }
    return error;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_servers_validate_json(const struct json *json)
{
    struct hmap servers = HMAP_INITIALIZER(&servers);
    struct ovsdb_error *error = raft_servers_from_json__(json, &servers);
    raft_servers_destroy(&servers);
    return error;
}

struct json *
raft_servers_to_json(const struct hmap *servers)
{
    struct json *json = json_object_create();
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, servers) {
        char sid_s[UUID_LEN + 1];
        sprintf(sid_s, UUID_FMT, UUID_ARGS(&s->sid));
        json_object_put_string(json, sid_s, s->address);
    }
    return json;
}

void
raft_servers_format(const struct hmap *servers, struct ds *ds)
{
    int i = 0;
    const struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, servers) {
        if (i++) {
            ds_put_cstr(ds, ", ");
        }
        ds_put_format(ds, SID_FMT"(%s)", SID_ARGS(&s->sid), s->address);
    }
}

/* Raft log entries. */

void
raft_entry_clone(struct raft_entry *dst, const struct raft_entry *src)
{
    dst->term = src->term;
    dst->data = json_nullable_clone(src->data);
    dst->eid = src->eid;
    dst->servers = json_nullable_clone(src->servers);
}

void
raft_entry_uninit(struct raft_entry *e)
{
    if (e) {
        json_destroy(e->data);
        json_destroy(e->servers);
    }
}

struct json *
raft_entry_to_json(const struct raft_entry *e)
{
    struct json *json = json_object_create();
    raft_put_uint64(json, "term", e->term);
    if (e->data) {
        json_object_put(json, "data", json_clone(e->data));
        json_object_put_format(json, "eid", UUID_FMT, UUID_ARGS(&e->eid));
    }
    if (e->servers) {
        json_object_put(json, "servers", json_clone(e->servers));
    }
    return json;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_entry_from_json(struct json *json, struct raft_entry *e)
{
    memset(e, 0, sizeof *e);

    struct ovsdb_parser p;
    ovsdb_parser_init(&p, json, "raft log entry");
    e->term = raft_parse_required_uint64(&p, "term");
    e->data = json_nullable_clone(
        ovsdb_parser_member(&p, "data", OP_OBJECT | OP_ARRAY | OP_OPTIONAL));
    e->eid = e->data ? raft_parse_required_uuid(&p, "eid") : UUID_ZERO;
    e->servers = json_nullable_clone(
        ovsdb_parser_member(&p, "servers", OP_OBJECT | OP_OPTIONAL));
    if (e->servers) {
        ovsdb_parser_put_error(&p, raft_servers_validate_json(e->servers));
    }

    struct ovsdb_error *error = ovsdb_parser_finish(&p);
    if (error) {
        raft_entry_uninit(e);
    }
    return error;
}

bool
raft_entry_equals(const struct raft_entry *a, const struct raft_entry *b)
{
    return (a->term == b->term
            && json_equal(a->data, b->data)
            && uuid_equals(&a->eid, &b->eid)
            && json_equal(a->servers, b->servers));
}

void
raft_header_uninit(struct raft_header *h)
{
    if (!h) {
        return;
    }

    free(h->name);
    free(h->local_address);
    sset_destroy(&h->remote_addresses);
    raft_entry_uninit(&h->snap);
}

static void
raft_header_from_json__(struct raft_header *h, struct ovsdb_parser *p)
{
    /* Parse always-required fields. */
    h->sid = raft_parse_required_uuid(p, "server_id");
    h->name = nullable_xstrdup(raft_parse_required_string(p, "name"));
    h->local_address = nullable_xstrdup(
        raft_parse_required_string(p, "local_address"));

    /* Parse "remote_addresses", if present.
     *
     * If this is present, then this database file is for the special case of a
     * server that was created with "ovsdb-tool join-cluster" and has not yet
     * joined its cluster, */
    const struct json *remote_addresses
        = ovsdb_parser_member(p, "remote_addresses", OP_ARRAY | OP_OPTIONAL);
    h->joining = remote_addresses != NULL;
    if (h->joining) {
        struct ovsdb_error *error = raft_addresses_from_json(
            remote_addresses, &h->remote_addresses);
        if (error) {
            ovsdb_parser_put_error(p, error);
        } else if (sset_find_and_delete(&h->remote_addresses, h->local_address)
                   && sset_is_empty(&h->remote_addresses)) {
            ovsdb_parser_raise_error(p, "at least one remote address (other "
                                     "than the local address) is required");
        }
    } else {
        /* The set of servers is mandatory. */
        h->snap.servers = json_nullable_clone(
            ovsdb_parser_member(p, "prev_servers", OP_OBJECT));
        if (h->snap.servers) {
            ovsdb_parser_put_error(p, raft_servers_validate_json(
                                       h->snap.servers));
        }

        /* Term, index, and snapshot are optional, but if any of them is
         * present, all of them must be. */
        h->snap_index = raft_parse_optional_uint64(p, "prev_index");
        if (h->snap_index) {
            h->snap.data = json_nullable_clone(
                ovsdb_parser_member(p, "prev_data", OP_ANY));
            h->snap.eid = raft_parse_required_uuid(p, "prev_eid");
            h->snap.term = raft_parse_required_uint64(p, "prev_term");
        }
    }

    /* Parse cluster ID.  If we're joining a cluster, this is optional,
     * otherwise it is mandatory. */
    raft_parse_uuid(p, "cluster_id", h->joining, &h->cid);
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_header_from_json(struct raft_header *h, const struct json *json)
{
    struct ovsdb_parser p;
    ovsdb_parser_init(&p, json, "raft header");
    memset(h, 0, sizeof *h);
    sset_init(&h->remote_addresses);
    raft_header_from_json__(h, &p);
    struct ovsdb_error *error = ovsdb_parser_finish(&p);
    if (error) {
        raft_header_uninit(h);
    }
    return error;
}

struct json *
raft_header_to_json(const struct raft_header *h)
{
    struct json *json = json_object_create();

    json_object_put_format(json, "server_id", UUID_FMT, UUID_ARGS(&h->sid));
    if (!uuid_is_zero(&h->cid)) {
        json_object_put_format(json, "cluster_id",
                               UUID_FMT, UUID_ARGS(&h->cid));
    }
    json_object_put_string(json, "local_address", h->local_address);
    json_object_put_string(json, "name", h->name);

    if (!sset_is_empty(&h->remote_addresses)) {
        json_object_put(json, "remote_addresses",
                        raft_addresses_to_json(&h->remote_addresses));
    }

    if (h->snap.servers) {
        json_object_put(json, "prev_servers", json_clone(h->snap.servers));
    }
    if (h->snap_index) {
        raft_put_uint64(json, "prev_index", h->snap_index);
        raft_put_uint64(json, "prev_term", h->snap.term);
        if (h->snap.data) {
            json_object_put(json, "prev_data", json_clone(h->snap.data));
        }
        json_object_put_format(json, "prev_eid",
                               UUID_FMT, UUID_ARGS(&h->snap.eid));
    }

    return json;
}

void
raft_record_uninit(struct raft_record *r)
{
    if (!r) {
        return;
    }

    free(r->comment);

    switch (r->type) {
    case RAFT_REC_ENTRY:
        json_destroy(r->entry.data);
        json_destroy(r->entry.servers);
        break;

    case RAFT_REC_NOTE:
        free(r->note);
        break;

    case RAFT_REC_TERM:
    case RAFT_REC_VOTE:
    case RAFT_REC_COMMIT_INDEX:
    case RAFT_REC_LEADER:
        break;
    }
}

static void
raft_record_from_json__(struct raft_record *r, struct ovsdb_parser *p)
{
    r->comment = nullable_xstrdup(raft_parse_optional_string(p, "comment"));

    /* Parse "note". */
    const char *note = raft_parse_optional_string(p, "note");
    if (note) {
        r->type = RAFT_REC_NOTE;
        r->term = 0;
        r->note = xstrdup(note);
        return;
    }

    /* Parse "commit_index". */
    r->commit_index = raft_parse_optional_uint64(p, "commit_index");
    if (r->commit_index) {
        r->type = RAFT_REC_COMMIT_INDEX;
        r->term = 0;
        return;
    }

    /* All remaining types of log records include "term", plus at most one of:
     *
     *     - "index" plus zero or more of "data", "eid", and "servers".  "data"
     *       and "eid" must be both present or both absent.
     *
     *     - "vote".
     *
     *     - "leader".
     */

    /* Parse "term".
     *
     * A Raft leader can replicate entries from previous terms to the other
     * servers in the cluster, retaining the original terms on those entries
     * (see section 3.6.2 "Committing entries from previous terms" for more
     * information), so it's OK for the term in a log record to precede the
     * current term. */
    r->term = raft_parse_required_uint64(p, "term");

    /* Parse "leader". */
    if (raft_parse_optional_uuid(p, "leader", &r->sid)) {
        r->type = RAFT_REC_LEADER;
        if (uuid_is_zero(&r->sid)) {
            ovsdb_parser_raise_error(p, "record says leader is all-zeros SID");
        }
        return;
    }

    /* Parse "vote". */
    if (raft_parse_optional_uuid(p, "vote", &r->sid)) {
        r->type = RAFT_REC_VOTE;
        if (uuid_is_zero(&r->sid)) {
            ovsdb_parser_raise_error(p, "record votes for all-zeros SID");
        }
        return;
    }

    /* If "index" is present parse the rest of the entry, otherwise it's just a
     * term update. */
    r->entry.index = raft_parse_optional_uint64(p, "index");
    if (!r->entry.index) {
        r->type = RAFT_REC_TERM;
    } else {
        r->type = RAFT_REC_ENTRY;
        r->entry.servers = json_nullable_clone(
            ovsdb_parser_member(p, "servers", OP_OBJECT | OP_OPTIONAL));
        if (r->entry.servers) {
            ovsdb_parser_put_error(
                p, raft_servers_validate_json(r->entry.servers));
        }
        r->entry.data = json_nullable_clone(
            ovsdb_parser_member(p, "data",
                                OP_OBJECT | OP_ARRAY | OP_OPTIONAL));
        r->entry.eid = (r->entry.data
                        ? raft_parse_required_uuid(p, "eid")
                        : UUID_ZERO);
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_record_from_json(struct raft_record *r, const struct json *json)
{
    struct ovsdb_parser p;
    ovsdb_parser_init(&p, json, "raft log record");
    raft_record_from_json__(r, &p);
    struct ovsdb_error *error = ovsdb_parser_finish(&p);
    if (error) {
        raft_record_uninit(r);
    }
    return error;
}

struct json *
raft_record_to_json(const struct raft_record *r)
{
    struct json *json = json_object_create();

    if (r->comment && *r->comment) {
        json_object_put_string(json, "comment", r->comment);
    }

    switch (r->type) {
    case RAFT_REC_ENTRY:
        raft_put_uint64(json, "term", r->term);
        raft_put_uint64(json, "index", r->entry.index);
        if (r->entry.data) {
            json_object_put(json, "data", json_clone(r->entry.data));
        }
        if (r->entry.servers) {
            json_object_put(json, "servers", json_clone(r->entry.servers));
        }
        if (!uuid_is_zero(&r->entry.eid)) {
            json_object_put_format(json, "eid",
                                   UUID_FMT, UUID_ARGS(&r->entry.eid));
        }
        break;

    case RAFT_REC_TERM:
        raft_put_uint64(json, "term", r->term);
        break;

    case RAFT_REC_VOTE:
        raft_put_uint64(json, "term", r->term);
        json_object_put_format(json, "vote", UUID_FMT, UUID_ARGS(&r->sid));
        break;

    case RAFT_REC_NOTE:
        json_object_put(json, "note", json_string_create(r->note));
        break;

    case RAFT_REC_COMMIT_INDEX:
        raft_put_uint64(json, "commit_index", r->commit_index);
        break;

    case RAFT_REC_LEADER:
        raft_put_uint64(json, "term", r->term);
        json_object_put_format(json, "leader", UUID_FMT, UUID_ARGS(&r->sid));
        break;

    default:
        OVS_NOT_REACHED();
    }
    return json;
}

/* Puts 'integer' into JSON 'object' with the given 'name'.
 *
 * The OVS JSON implementation only supports integers in the range
 * INT64_MIN...INT64_MAX, which causes trouble for values from INT64_MAX+1 to
 * UINT64_MAX.  We map those into the negative range. */
void
raft_put_uint64(struct json *object, const char *name, uint64_t integer)
{
    json_object_put(object, name, json_integer_create(integer));
}

/* Parses an integer from parser 'p' with the given 'name'.
 *
 * The OVS JSON implementation only supports integers in the range
 * INT64_MIN...INT64_MAX, which causes trouble for values from INT64_MAX+1 to
 * UINT64_MAX.  We map the negative range back into positive numbers. */
static uint64_t
raft_parse_uint64__(struct ovsdb_parser *p, const char *name, bool optional)
{
    enum ovsdb_parser_types types = OP_INTEGER | (optional ? OP_OPTIONAL : 0);
    const struct json *json = ovsdb_parser_member(p, name, types);
    return json ? json_integer(json) : 0;
}

uint64_t
raft_parse_optional_uint64(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_uint64__(p, name, true);
}

uint64_t
raft_parse_required_uint64(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_uint64__(p, name, false);
}

static int
raft_parse_boolean__(struct ovsdb_parser *p, const char *name, bool optional)
{
    enum ovsdb_parser_types types = OP_BOOLEAN | (optional ? OP_OPTIONAL : 0);
    const struct json *json = ovsdb_parser_member(p, name, types);
    return json ? json_boolean(json) : -1;
}

bool
raft_parse_required_boolean(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_boolean__(p, name, false);
}

/* Returns true or false if present, -1 if absent. */
int
raft_parse_optional_boolean(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_boolean__(p, name, true);
}

static const char *
raft_parse_string__(struct ovsdb_parser *p, const char *name, bool optional)
{
    enum ovsdb_parser_types types = OP_STRING | (optional ? OP_OPTIONAL : 0);
    const struct json *json = ovsdb_parser_member(p, name, types);
    return json ? json_string(json) : NULL;
}

const char *
raft_parse_required_string(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_string__(p, name, false);
}

const char *
raft_parse_optional_string(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_string__(p, name, true);
}

bool
raft_parse_uuid(struct ovsdb_parser *p, const char *name, bool optional,
                struct uuid *uuid)
{
    const char *s = raft_parse_string__(p, name, optional);
    if (s) {
        if (uuid_from_string(uuid, s)) {
            return true;
        }
        ovsdb_parser_raise_error(p, "%s is not a valid UUID", name);
    }
    *uuid = UUID_ZERO;
    return false;
}

struct uuid
raft_parse_required_uuid(struct ovsdb_parser *p, const char *name)
{
    struct uuid uuid;
    raft_parse_uuid(p, name, false, &uuid);
    return uuid;
}

bool
raft_parse_optional_uuid(struct ovsdb_parser *p, const char *name,
                    struct uuid *uuid)
{
    return raft_parse_uuid(p, name, true, uuid);
}

