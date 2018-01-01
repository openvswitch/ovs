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

#include "raft-rpc.h"
#include <stdlib.h>
#include <string.h>
#include "compiler.h"
#include "jsonrpc.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/vlog.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(raft_rpc);

#define RAFT_RPC(ENUM, NAME)                                            \
    static void raft_##NAME##_uninit(struct raft_##NAME *);             \
    static void raft_##NAME##_clone(struct raft_##NAME *,               \
                                    const struct raft_##NAME *);        \
    static void raft_##NAME##_to_jsonrpc(const struct raft_##NAME *,    \
                                         struct json *);                \
    static void raft_##NAME##_from_jsonrpc(struct ovsdb_parser *,       \
                                           struct raft_##NAME *);       \
    static void raft_format_##NAME(const struct raft_##NAME *, struct ds *);
RAFT_RPC_TYPES
#undef RAFT_RPC

/* raft_rpc_type. */
const char *
raft_rpc_type_to_string(enum raft_rpc_type status)
{
    switch (status) {
#define RAFT_RPC(ENUM, NAME) case ENUM: return #NAME;
        RAFT_RPC_TYPES
#undef RAFT_RPC
            }
    return "<unknown>";
}

bool
raft_rpc_type_from_string(const char *s, enum raft_rpc_type *status)
{
#define RAFT_RPC(ENUM, NAME)                    \
    if (!strcmp(s, #NAME)) {                    \
        *status = ENUM;                         \
        return true;                            \
    }
    RAFT_RPC_TYPES
#undef RAFT_RPC
        return false;
}

/* raft_hello_request. */

static void
raft_hello_request_uninit(struct raft_hello_request *rq)
{
    free(rq->address);
}

static void
raft_hello_request_clone(struct raft_hello_request *dst,
                         const struct raft_hello_request *src)
{
    dst->address = nullable_xstrdup(src->address);
}

static void
raft_hello_request_to_jsonrpc(const struct raft_hello_request *rq,
                              struct json *args)
{
    json_object_put_string(args, "address", rq->address);
}

static void
raft_hello_request_from_jsonrpc(struct ovsdb_parser *p,
                                struct raft_hello_request *rq)
{
    rq->address = nullable_xstrdup(raft_parse_required_string(p, "address"));
}

static void
raft_format_hello_request(const struct raft_hello_request *rq,
                          struct ds *s)
{
    ds_put_format(s, " address=\"%s\"", rq->address);
}

/* raft_append_request. */

static void
raft_append_request_uninit(struct raft_append_request *rq)
{
    for (size_t i = 0; i < rq->n_entries; i++) {
        raft_entry_uninit(&rq->entries[i]);
    }
    free(rq->entries);
}

static void
raft_append_request_clone(struct raft_append_request *dst,
                          const struct raft_append_request *src)
{
    dst->entries = xmalloc(src->n_entries * sizeof *dst->entries);
    for (size_t i = 0; i < src->n_entries; i++) {
        raft_entry_clone(&dst->entries[i], &src->entries[i]);
    }
}

static void
raft_append_request_to_jsonrpc(const struct raft_append_request *rq,
                               struct json *args)
{
    raft_put_uint64(args, "term", rq->term);
    raft_put_uint64(args, "prev_log_index", rq->prev_log_index);
    raft_put_uint64(args, "prev_log_term", rq->prev_log_term);
    raft_put_uint64(args, "leader_commit", rq->leader_commit);

    struct json **entries = xmalloc(rq->n_entries * sizeof *entries);
    for (size_t i = 0; i < rq->n_entries; i++) {
        entries[i] = raft_entry_to_json(&rq->entries[i]);
    }
    json_object_put(args, "log", json_array_create(entries, rq->n_entries));
}

static void
raft_append_request_from_jsonrpc(struct ovsdb_parser *p,
                                 struct raft_append_request *rq)
{
    rq->term = raft_parse_required_uint64(p, "term");
    rq->prev_log_index = raft_parse_required_uint64(p, "prev_log_index");
    rq->prev_log_term = raft_parse_required_uint64(p, "prev_log_term");
    rq->leader_commit = raft_parse_required_uint64(p, "leader_commit");

    const struct json *log = ovsdb_parser_member(p, "log", OP_ARRAY);
    if (!log) {
        return;
    }
    const struct json_array *entries = json_array(log);
    rq->entries = xmalloc(entries->n * sizeof *rq->entries);
    rq->n_entries = 0;
    for (size_t i = 0; i < entries->n; i++) {
        struct ovsdb_error *error = raft_entry_from_json(entries->elems[i],
                                                         &rq->entries[i]);
        if (error) {
            ovsdb_parser_put_error(p, error);
            break;
        }
        rq->n_entries++;
    }
}

static void
raft_format_append_request(const struct raft_append_request *rq,
                           struct ds *s)
{
    ds_put_format(s, " term=%"PRIu64, rq->term);
    ds_put_format(s, " prev_log_index=%"PRIu64, rq->prev_log_index);
    ds_put_format(s, " prev_log_term=%"PRIu64, rq->prev_log_term);
    ds_put_format(s, " leader_commit=%"PRIu64, rq->leader_commit);
    ds_put_format(s, " n_entries=%u", rq->n_entries);
}

/* raft_append_reply. */

const char *
raft_append_result_to_string(enum raft_append_result result)
{
    switch (result) {
    case RAFT_APPEND_OK:
        return "OK";
    case RAFT_APPEND_INCONSISTENCY:
        return "inconsistency";
    case RAFT_APPEND_IO_ERROR:
        return "I/O error";
    default:
        return NULL;
    }
}

bool
raft_append_result_from_string(const char *s, enum raft_append_result *resultp)
{
    for (enum raft_append_result result = 0; ; result++) {
        const char *s2 = raft_append_result_to_string(result);
        if (!s2) {
            *resultp = 0;
            return false;
        } else if (!strcmp(s, s2)) {
            *resultp = result;
            return true;
        }
    }
}

static void
raft_append_reply_uninit(struct raft_append_reply *rpy OVS_UNUSED)
{
}

static void
raft_append_reply_clone(struct raft_append_reply *dst OVS_UNUSED,
                        const struct raft_append_reply *src OVS_UNUSED)
{
}

static void
raft_append_reply_to_jsonrpc(const struct raft_append_reply *rpy,
                             struct json *args)
{
    raft_put_uint64(args, "term", rpy->term);
    raft_put_uint64(args, "log_end", rpy->log_end);
    raft_put_uint64(args, "prev_log_index", rpy->prev_log_index);
    raft_put_uint64(args, "prev_log_term", rpy->prev_log_term);
    raft_put_uint64(args, "n_entries", rpy->n_entries);
    json_object_put_string(args, "result",
                           raft_append_result_to_string(rpy->result));
}

static void
raft_append_reply_from_jsonrpc(struct ovsdb_parser *p,
                               struct raft_append_reply *rpy)
{
    rpy->term = raft_parse_required_uint64(p, "term");
    rpy->log_end = raft_parse_required_uint64(p, "log_end");
    rpy->prev_log_index = raft_parse_required_uint64(p, "prev_log_index");
    rpy->prev_log_term = raft_parse_required_uint64(p, "prev_log_term");
    rpy->n_entries = raft_parse_required_uint64(p, "n_entries");

    const char *result = raft_parse_required_string(p, "result");
    if (result && !raft_append_result_from_string(result, &rpy->result)) {
        ovsdb_parser_raise_error(p, "unknown result \"%s\"", result);
    }
}

static void
raft_format_append_reply(const struct raft_append_reply *rpy, struct ds *s)
{
    ds_put_format(s, " term=%"PRIu64, rpy->term);
    ds_put_format(s, " log_end=%"PRIu64, rpy->log_end);
    ds_put_format(s, " result=\"%s\"",
                  raft_append_result_to_string(rpy->result));
}

/* raft_vote_request. */

static void
raft_vote_request_uninit(struct raft_vote_request *rq OVS_UNUSED)
{
}

static void
raft_vote_request_clone(struct raft_vote_request *dst OVS_UNUSED,
                        const struct raft_vote_request *src OVS_UNUSED)
{
}

static void
raft_vote_request_to_jsonrpc(const struct raft_vote_request *rq,
                             struct json *args)
{
    raft_put_uint64(args, "term", rq->term);
    raft_put_uint64(args, "last_log_index", rq->last_log_index);
    raft_put_uint64(args, "last_log_term", rq->last_log_term);
    if (rq->leadership_transfer) {
        json_object_put(args, "leadership_transfer",
                        json_boolean_create(true));
    }
}

static void
raft_vote_request_from_jsonrpc(struct ovsdb_parser *p,
                               struct raft_vote_request *rq)
{
    rq->term = raft_parse_required_uint64(p, "term");
    rq->last_log_index = raft_parse_required_uint64(p, "last_log_index");
    rq->last_log_term = raft_parse_required_uint64(p, "last_log_term");
    rq->leadership_transfer
        = raft_parse_optional_boolean(p, "leadership_transfer") == 1;
}

static void
raft_format_vote_request(const struct raft_vote_request *rq, struct ds *s)
{
    ds_put_format(s, " term=%"PRIu64, rq->term);
    ds_put_format(s, " last_log_index=%"PRIu64, rq->last_log_index);
    ds_put_format(s, " last_log_term=%"PRIu64, rq->last_log_term);
    if (rq->leadership_transfer) {
        ds_put_cstr(s, " leadership_transfer=true");
    }
}

/* raft_vote_reply. */

static void
raft_vote_reply_uninit(struct raft_vote_reply *rpy OVS_UNUSED)
{
}

static void
raft_vote_reply_clone(struct raft_vote_reply *dst OVS_UNUSED,
                      const struct raft_vote_reply *src OVS_UNUSED)
{
}

static void
raft_vote_reply_to_jsonrpc(const struct raft_vote_reply *rpy,
                           struct json *args)
{
    raft_put_uint64(args, "term", rpy->term);
    json_object_put_format(args, "vote", UUID_FMT, UUID_ARGS(&rpy->vote));
}

static void
raft_vote_reply_from_jsonrpc(struct ovsdb_parser *p,
                             struct raft_vote_reply *rpy)
{
    rpy->term = raft_parse_required_uint64(p, "term");
    rpy->vote = raft_parse_required_uuid(p, "vote");
}

static void
raft_format_vote_reply(const struct raft_vote_reply *rpy, struct ds *s)
{
    ds_put_format(s, " term=%"PRIu64, rpy->term);
    ds_put_format(s, " vote="SID_FMT, SID_ARGS(&rpy->vote));
}

/* raft_add_server_request */

static void
raft_add_server_request_uninit(struct raft_add_server_request *rq)
{
    free(rq->address);
}

static void
raft_add_server_request_clone(struct raft_add_server_request *dst,
                               const struct raft_add_server_request *src)
{
    dst->address = nullable_xstrdup(src->address);
}

static void
raft_add_server_request_to_jsonrpc(const struct raft_add_server_request *rq,
                                   struct json *args)
{
    json_object_put_string(args, "address", rq->address);
}

static void
raft_add_server_request_from_jsonrpc(struct ovsdb_parser *p,
                                     struct raft_add_server_request *rq)
{
    rq->address = nullable_xstrdup(raft_parse_required_string(p, "address"));
}

static void
raft_format_add_server_request(const struct raft_add_server_request *rq,
                               struct ds *s)
{
    ds_put_format(s, " address=\"%s\"", rq->address);
}

/* raft_add_server_reply. */

static void
raft_add_server_reply_uninit(struct raft_add_server_reply *rpy)
{
    sset_destroy(&rpy->remote_addresses);
}

static void
raft_add_server_reply_clone(struct raft_add_server_reply *dst,
                            const struct raft_add_server_reply *src)
{
    sset_clone(&dst->remote_addresses, &src->remote_addresses);
}

static void
raft_add_server_reply_to_jsonrpc(const struct raft_add_server_reply *rpy,
                                 struct json *args)
{
    json_object_put(args, "success", json_boolean_create(rpy->success));
    if (!sset_is_empty(&rpy->remote_addresses)) {
        json_object_put(args, "remote_addresses",
                        raft_addresses_to_json(&rpy->remote_addresses));
    }
}

static void
raft_add_server_reply_from_jsonrpc(struct ovsdb_parser *p,
                                   struct raft_add_server_reply *rpy)
{
    rpy->success = raft_parse_required_boolean(p, "success");

    const struct json *json = ovsdb_parser_member(p, "remote_addresses",
                                                  OP_ARRAY | OP_OPTIONAL);
    if (json) {
        ovsdb_parser_put_error(p, raft_addresses_from_json(
                                   json, &rpy->remote_addresses));
    } else {
        sset_init(&rpy->remote_addresses);
    }
}

static void
raft_format_add_server_reply(const struct raft_add_server_reply *rpy,
                             struct ds *s)
{
    ds_put_format(s, " success=%s", rpy->success ? "true" : "false");
    if (!sset_is_empty(&rpy->remote_addresses)) {
        ds_put_cstr(s, " remote_addresses=[");

        const char *address;
        int i = 0;
        SSET_FOR_EACH (address, &rpy->remote_addresses) {
            if (i++ > 0) {
                ds_put_cstr(s, ", ");
            }
            ds_put_cstr(s, address);
        }
        ds_put_char(s, ']');
    }
}

/* raft_remove_server_reply. */

static void
raft_remove_server_reply_uninit(
    struct raft_remove_server_reply *rpy OVS_UNUSED)
{
}

static void
raft_remove_server_reply_clone(
    struct raft_remove_server_reply *dst OVS_UNUSED,
    const struct raft_remove_server_reply *src OVS_UNUSED)
{
}

static void
raft_remove_server_reply_to_jsonrpc(const struct raft_remove_server_reply *rpy,
                                    struct json *args)
{
    json_object_put(args, "success", json_boolean_create(rpy->success));
}

static void
raft_remove_server_reply_from_jsonrpc(struct ovsdb_parser *p,
                                      struct raft_remove_server_reply *rpy)
{
    rpy->success = raft_parse_required_boolean(p, "success");
}

static void
raft_format_remove_server_reply(const struct raft_remove_server_reply *rpy,
                                struct ds *s)
{
    ds_put_format(s, " success=%s", rpy->success ? "true" : "false");
}

/* raft_install_snapshot_request. */

static void
raft_install_snapshot_request_uninit(
    struct raft_install_snapshot_request *rq)
{
    json_destroy(rq->last_servers);
    json_destroy(rq->data);
}

static void
raft_install_snapshot_request_clone(
    struct raft_install_snapshot_request *dst,
    const struct raft_install_snapshot_request *src)
{
    dst->last_servers = json_clone(src->last_servers);
    dst->data = json_clone(src->data);
}

static void
raft_install_snapshot_request_to_jsonrpc(
    const struct raft_install_snapshot_request *rq, struct json *args)
{
    raft_put_uint64(args, "term", rq->term);
    raft_put_uint64(args, "last_index", rq->last_index);
    raft_put_uint64(args, "last_term", rq->last_term);
    json_object_put(args, "last_servers", json_clone(rq->last_servers));
    json_object_put_format(args, "last_eid",
                           UUID_FMT, UUID_ARGS(&rq->last_eid));

    json_object_put(args, "data", json_clone(rq->data));
}

static void
raft_install_snapshot_request_from_jsonrpc(
    struct ovsdb_parser *p, struct raft_install_snapshot_request *rq)
{
    rq->last_servers = json_nullable_clone(
        ovsdb_parser_member(p, "last_servers", OP_OBJECT));
    ovsdb_parser_put_error(p, raft_servers_validate_json(rq->last_servers));

    rq->term = raft_parse_required_uint64(p, "term");
    rq->last_index = raft_parse_required_uint64(p, "last_index");
    rq->last_term = raft_parse_required_uint64(p, "last_term");
    rq->last_eid = raft_parse_required_uuid(p, "last_eid");

    rq->data = json_nullable_clone(
        ovsdb_parser_member(p, "data", OP_OBJECT | OP_ARRAY));
}

static void
raft_format_install_snapshot_request(
    const struct raft_install_snapshot_request *rq, struct ds *s)
{
    ds_put_format(s, " term=%"PRIu64, rq->term);
    ds_put_format(s, " last_index=%"PRIu64, rq->last_index);
    ds_put_format(s, " last_term=%"PRIu64, rq->last_term);
    ds_put_format(s, " last_eid="UUID_FMT, UUID_ARGS(&rq->last_eid));
    ds_put_cstr(s, " last_servers=");

    struct hmap servers;
    struct ovsdb_error *error =
        raft_servers_from_json(rq->last_servers, &servers);
    if (!error) {
        raft_servers_format(&servers, s);
        raft_servers_destroy(&servers);
    } else {
        ds_put_cstr(s, "***error***");
        ovsdb_error_destroy(error);
    }
}

/* raft_install_snapshot_reply. */

static void
raft_install_snapshot_reply_uninit(
    struct raft_install_snapshot_reply *rpy OVS_UNUSED)
{
}

static void
raft_install_snapshot_reply_clone(
    struct raft_install_snapshot_reply *dst OVS_UNUSED,
    const struct raft_install_snapshot_reply *src OVS_UNUSED)
{
}

static void
raft_install_snapshot_reply_to_jsonrpc(
    const struct raft_install_snapshot_reply *rpy, struct json *args)
{
    raft_put_uint64(args, "term", rpy->term);
    raft_put_uint64(args, "last_index", rpy->last_index);
    raft_put_uint64(args, "last_term", rpy->last_term);
}

static void
raft_install_snapshot_reply_from_jsonrpc(
    struct ovsdb_parser *p,
    struct raft_install_snapshot_reply *rpy)
{
    rpy->term = raft_parse_required_uint64(p, "term");
    rpy->last_index = raft_parse_required_uint64(p, "last_index");
    rpy->last_term = raft_parse_required_uint64(p, "last_term");
}

static void
raft_format_install_snapshot_reply(
    const struct raft_install_snapshot_reply *rpy, struct ds *s)
{
    ds_put_format(s, " term=%"PRIu64, rpy->term);
    ds_put_format(s, " last_index=%"PRIu64, rpy->last_index);
    ds_put_format(s, " last_term=%"PRIu64, rpy->last_term);
}

/* raft_remove_server_request. */

static void
raft_remove_server_request_uninit(
    struct raft_remove_server_request *rq OVS_UNUSED)
{
}

static void
raft_remove_server_request_clone(
    struct raft_remove_server_request *dst OVS_UNUSED,
    const struct raft_remove_server_request *src OVS_UNUSED)
{
}

static void
raft_remove_server_request_to_jsonrpc(
    const struct raft_remove_server_request *rq, struct json *args)
{
    json_object_put_format(args, "server_id", UUID_FMT, UUID_ARGS(&rq->sid));
}

static void
raft_remove_server_request_from_jsonrpc(struct ovsdb_parser *p,
                                        struct raft_remove_server_request *rq)
{
    rq->sid = raft_parse_required_uuid(p, "server_id");
}

static void
raft_format_remove_server_request(const struct raft_remove_server_request *rq,
                                  struct ds *s)
{
    ds_put_format(s, " server="SID_FMT, SID_ARGS(&rq->sid));
}

/* raft_become_leader. */

static void
raft_become_leader_uninit(struct raft_become_leader *rpc OVS_UNUSED)
{
}

static void
raft_become_leader_clone(struct raft_become_leader *dst OVS_UNUSED,
                         const struct raft_become_leader *src OVS_UNUSED)
{
}

static void
raft_become_leader_to_jsonrpc(const struct raft_become_leader *rpc,
                              struct json *args)
{
    raft_put_uint64(args, "term", rpc->term);
}

static void
raft_become_leader_from_jsonrpc(struct ovsdb_parser *p,
                                struct raft_become_leader *rpc)
{
    rpc->term = raft_parse_required_uint64(p, "term");
}

static void
raft_format_become_leader(const struct raft_become_leader *rq, struct ds *s)
{
    ds_put_format(s, " term=%"PRIu64, rq->term);
}

/* raft_execute_command_request. */

static void
raft_execute_command_request_uninit(
    struct raft_execute_command_request *rq)
{
    json_destroy(rq->data);
}

static void
raft_execute_command_request_clone(
    struct raft_execute_command_request *dst,
    const struct raft_execute_command_request *src)
{
    dst->data = json_clone(src->data);
}

static void
raft_execute_command_request_to_jsonrpc(
    const struct raft_execute_command_request *rq, struct json *args)
{
    json_object_put(args, "data", json_clone(rq->data));
    json_object_put_format(args, "prereq", UUID_FMT, UUID_ARGS(&rq->prereq));
    json_object_put_format(args, "result", UUID_FMT, UUID_ARGS(&rq->result));
}

static void
raft_execute_command_request_from_jsonrpc(
    struct ovsdb_parser *p, struct raft_execute_command_request *rq)
{
    rq->data = json_nullable_clone(ovsdb_parser_member(p, "data",
                                                       OP_OBJECT | OP_ARRAY));
    rq->prereq = raft_parse_required_uuid(p, "prereq");
    rq->result = raft_parse_required_uuid(p, "result");
}

static void
raft_format_execute_command_request(
    const struct raft_execute_command_request *rq, struct ds *s)
{
    ds_put_format(s, " prereq="UUID_FMT, UUID_ARGS(&rq->prereq));
    ds_put_format(s, " result="UUID_FMT, UUID_ARGS(&rq->result));
    ds_put_format(s, " data=");
    json_to_ds(rq->data, JSSF_SORT, s);
}

/* raft_execute_command_reply. */

static void
raft_execute_command_reply_uninit(
    struct raft_execute_command_reply *rpy OVS_UNUSED)
{
}

static void
raft_execute_command_reply_clone(
    struct raft_execute_command_reply *dst OVS_UNUSED,
    const struct raft_execute_command_reply *src OVS_UNUSED)
{
}

static void
raft_execute_command_reply_to_jsonrpc(
    const struct raft_execute_command_reply *rpy, struct json *args)
{
    json_object_put_format(args, "result", UUID_FMT, UUID_ARGS(&rpy->result));
    json_object_put_string(args, "status",
                           raft_command_status_to_string(rpy->status));
    if (rpy->commit_index) {
        raft_put_uint64(args, "commit_index", rpy->commit_index);
    }
}

static void
raft_execute_command_reply_from_jsonrpc(
    struct ovsdb_parser *p, struct raft_execute_command_reply *rpy)
{
    rpy->result = raft_parse_required_uuid(p, "result");

    const char *status = raft_parse_required_string(p, "status");
    if (status && !raft_command_status_from_string(status, &rpy->status)) {
        ovsdb_parser_raise_error(p, "unknown status \"%s\"", status);
    }

    rpy->commit_index = raft_parse_optional_uint64(p, "commit_index");
}

static void
raft_format_execute_command_reply(
    const struct raft_execute_command_reply *rpy, struct ds *s)
{
    ds_put_format(s, " result="UUID_FMT, UUID_ARGS(&rpy->result));
    ds_put_format(s, " status=\"%s\"",
                  raft_command_status_to_string(rpy->status));
    if (rpy->commit_index) {
        ds_put_format(s, " commit_index=%"PRIu64, rpy->commit_index);
    }
}

void
raft_rpc_uninit(union raft_rpc *rpc)
{
    if (rpc) {
        free(rpc->common.comment);

        switch (rpc->type) {
#define RAFT_RPC(ENUM, NAME)                        \
            case ENUM:                              \
                raft_##NAME##_uninit(&rpc->NAME);   \
                break;
            RAFT_RPC_TYPES
#undef RAFT_RPC
        }
    }
}

union raft_rpc *
raft_rpc_clone(const union raft_rpc *src)
{
    union raft_rpc *dst = xmemdup(src, sizeof *src);
    dst->common.comment = nullable_xstrdup(src->common.comment);

    switch (src->type) {
#define RAFT_RPC(ENUM, NAME)                                \
        case ENUM:                                          \
            raft_##NAME##_clone(&dst->NAME, &src->NAME);    \
            break;
    RAFT_RPC_TYPES
#undef RAFT_RPC
    }

    return dst;
}

/* Returns 'rpc' converted to a jsonrpc_msg.  The caller must eventually free
 * the returned message.
 *
 * 'rpc->common.sid' should be the destination server ID; it is omitted if
 * all-zeros.  'sid' is the source.  'cid' should be the cluster ID; it is
 * omitted if all-zeros. */
struct jsonrpc_msg *
raft_rpc_to_jsonrpc(const struct uuid *cid,
                    const struct uuid *sid,
                    const union raft_rpc *rpc)
{
    struct json *args = json_object_create();
    if (!uuid_is_zero(cid)) {
        json_object_put_format(args, "cluster", UUID_FMT, UUID_ARGS(cid));
    }
    if (!uuid_is_zero(&rpc->common.sid)) {
        json_object_put_format(args, "to", UUID_FMT,
                               UUID_ARGS(&rpc->common.sid));
    }
    json_object_put_format(args, "from", UUID_FMT, UUID_ARGS(sid));
    if (rpc->common.comment) {
        json_object_put_string(args, "comment", rpc->common.comment);
    }

    switch (rpc->type) {
#define RAFT_RPC(ENUM, NAME)                        \
    case ENUM:                                      \
        raft_##NAME##_to_jsonrpc(&rpc->NAME, args); \
        break;
    RAFT_RPC_TYPES
#undef RAFT_RPC
    default:
        OVS_NOT_REACHED();
    }

    return jsonrpc_create_notify(raft_rpc_type_to_string(rpc->type),
                                 json_array_create_1(args));
}

/* Parses 'msg' as a Raft message directed to 'sid' and initializes 'rpc'
 * appropriately.  On success, returns NULL and the caller owns the contents of
 * 'rpc' and must eventually uninitialize it with raft_rpc_uninit().  On
 * failure, returns an error that the caller must eventually free.
 *
 * 'cidp' must point to the Raft cluster's ID.  If the cluster ID isn't yet
 * known, then '*cidp' must be UUID_ZERO and this function will attempt to
 * initialize it based on 'msg'. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_rpc_from_jsonrpc(struct uuid *cidp, const struct uuid *sid,
                      const struct jsonrpc_msg *msg, union raft_rpc *rpc)
{
    memset(rpc, 0, sizeof *rpc);
    if (msg->type != JSONRPC_NOTIFY) {
        return ovsdb_error(NULL, "expecting notify RPC but received %s",
                           jsonrpc_msg_type_to_string(msg->type));
    }

    if (!raft_rpc_type_from_string(msg->method, &rpc->type)) {
        return ovsdb_error(NULL, "unknown method %s", msg->method);
    }

    if (json_array(msg->params)->n != 1) {
        return ovsdb_error(NULL,
                           "%s RPC has %"PRIuSIZE" parameters (expected 1)",
                           msg->method, json_array(msg->params)->n);
    }

    struct ovsdb_parser p;
    ovsdb_parser_init(&p, json_array(msg->params)->elems[0],
                      "raft %s RPC", msg->method);

    bool is_hello = rpc->type == RAFT_RPC_HELLO_REQUEST;
    bool is_add = rpc->type == RAFT_RPC_ADD_SERVER_REQUEST;

    struct uuid cid;
    if (raft_parse_uuid(&p, "cluster", is_add, &cid)
        && !uuid_equals(&cid, cidp)) {
        if (uuid_is_zero(cidp)) {
            *cidp = cid;
            VLOG_INFO("learned cluster ID "CID_FMT, CID_ARGS(&cid));
        } else {
            ovsdb_parser_raise_error(&p, "wrong cluster "CID_FMT" "
                                     "(expected "CID_FMT")",
                                     CID_ARGS(&cid), CID_ARGS(cidp));
        }
    }

    struct uuid to_sid;
    if (raft_parse_uuid(&p, "to", is_add || is_hello, &to_sid)
        && !uuid_equals(&to_sid, sid)) {
        ovsdb_parser_raise_error(&p, "misrouted message (addressed to "
                                 SID_FMT" but we're "SID_FMT")",
                                 SID_ARGS(&to_sid), SID_ARGS(sid));
    }

    rpc->common.sid = raft_parse_required_uuid(&p, "from");
    rpc->common.comment = nullable_xstrdup(
        raft_parse_optional_string(&p, "comment"));

    switch (rpc->type) {
#define RAFT_RPC(ENUM, NAME)                            \
        case ENUM:                                      \
            raft_##NAME##_from_jsonrpc(&p, &rpc->NAME); \
            break;
    RAFT_RPC_TYPES
#undef RAFT_RPC

    default:
        OVS_NOT_REACHED();
    }

    struct ovsdb_error *error = ovsdb_parser_finish(&p);
    if (error) {
        raft_rpc_uninit(rpc);
    }
    return error;
}

/* Appends a formatted representation of 'rpc' to 's'.
 *
 * Does not include the RPC's server ID in the formatted representation, since
 * the caller usually has more context that allows for a more human friendly
 * name. */
void
raft_rpc_format(const union raft_rpc *rpc, struct ds *s)
{
    ds_put_cstr(s, raft_rpc_type_to_string(rpc->type));
    if (rpc->common.comment) {
        ds_put_format(s, " \"%s\"", rpc->common.comment);
    }
    ds_put_char(s, ':');

    switch (rpc->type) {
#define RAFT_RPC(ENUM, NAME)                    \
    case ENUM:                                  \
        raft_format_##NAME(&rpc->NAME, s);      \
        break;
    RAFT_RPC_TYPES
#undef RAFT_RPC
    default:
        OVS_NOT_REACHED();
    }
}

uint64_t
raft_rpc_get_term(const union raft_rpc *rpc)
{
    switch (rpc->type) {
    case RAFT_RPC_HELLO_REQUEST:
    case RAFT_RPC_ADD_SERVER_REQUEST:
    case RAFT_RPC_ADD_SERVER_REPLY:
    case RAFT_RPC_REMOVE_SERVER_REQUEST:
    case RAFT_RPC_REMOVE_SERVER_REPLY:
    case RAFT_RPC_EXECUTE_COMMAND_REQUEST:
    case RAFT_RPC_EXECUTE_COMMAND_REPLY:
        return 0;

    case RAFT_RPC_APPEND_REQUEST:
        return rpc->append_request.term;

    case RAFT_RPC_APPEND_REPLY:
        return rpc->append_reply.term;

    case RAFT_RPC_VOTE_REQUEST:
        return rpc->vote_request.term;

    case RAFT_RPC_VOTE_REPLY:
        return rpc->vote_reply.term;

    case RAFT_RPC_INSTALL_SNAPSHOT_REQUEST:
        return rpc->install_snapshot_request.term;

    case RAFT_RPC_INSTALL_SNAPSHOT_REPLY:
        return rpc->install_snapshot_reply.term;

    case RAFT_RPC_BECOME_LEADER:
        return rpc->become_leader.term;

    default:
        OVS_NOT_REACHED();
    }
}

const struct uuid *
raft_rpc_get_vote(const union raft_rpc *rpc)
{
    switch (rpc->type) {
    case RAFT_RPC_HELLO_REQUEST:
    case RAFT_RPC_ADD_SERVER_REQUEST:
    case RAFT_RPC_ADD_SERVER_REPLY:
    case RAFT_RPC_REMOVE_SERVER_REQUEST:
    case RAFT_RPC_REMOVE_SERVER_REPLY:
    case RAFT_RPC_EXECUTE_COMMAND_REQUEST:
    case RAFT_RPC_EXECUTE_COMMAND_REPLY:
    case RAFT_RPC_APPEND_REQUEST:
    case RAFT_RPC_APPEND_REPLY:
    case RAFT_RPC_VOTE_REQUEST:
    case RAFT_RPC_INSTALL_SNAPSHOT_REQUEST:
    case RAFT_RPC_INSTALL_SNAPSHOT_REPLY:
    case RAFT_RPC_BECOME_LEADER:
        return NULL;

    case RAFT_RPC_VOTE_REPLY:
        return &raft_vote_reply_cast(rpc)->vote;

    default:
        OVS_NOT_REACHED();
    }
}

/* Returns the minimum log index that must be synced to disk if 'rpc' is to be
 * sent.  (This is generally the biggest log index in the message but some
 * messages, e.g. RAFT_RPC_APPEND_REQUEST, don't need their entries synced.) */
uint64_t
raft_rpc_get_min_sync_index(const union raft_rpc *rpc)
{
    switch (rpc->type) {
    case RAFT_RPC_HELLO_REQUEST:
    case RAFT_RPC_ADD_SERVER_REQUEST:
    case RAFT_RPC_ADD_SERVER_REPLY:
    case RAFT_RPC_REMOVE_SERVER_REQUEST:
    case RAFT_RPC_REMOVE_SERVER_REPLY:
    case RAFT_RPC_EXECUTE_COMMAND_REQUEST:
    case RAFT_RPC_EXECUTE_COMMAND_REPLY:
    case RAFT_RPC_APPEND_REQUEST:
    case RAFT_RPC_BECOME_LEADER:
    case RAFT_RPC_VOTE_REPLY:
        return 0;

    case RAFT_RPC_APPEND_REPLY:
        return raft_append_reply_cast(rpc)->log_end - 1;

    case RAFT_RPC_VOTE_REQUEST:
        return raft_vote_request_cast(rpc)->last_log_index;

    case RAFT_RPC_INSTALL_SNAPSHOT_REQUEST:
        return raft_install_snapshot_request_cast(rpc)->last_index;

    case RAFT_RPC_INSTALL_SNAPSHOT_REPLY:
        /* This will need to change if install_snapshot_reply becomes able to
         * report an error */
        return raft_install_snapshot_reply_cast(rpc)->last_index;

    default:
        OVS_NOT_REACHED();
    }
}
