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

#ifndef RAFT_PRIVATE_H
#define RAFT_PRIVATE_H 1

/* Data structures for use internally within the Raft implementation. */

#include "raft.h"
#include <stdint.h>
#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include "sset.h"

struct ds;
struct ovsdb_parser;

/* Formatting server IDs and cluster IDs for use in human-readable logs.  Do
 * not use these in cases where the whole server or cluster ID is needed; use
 * UUID_FMT and UUID_ARGS in that case.*/

#define SID_FMT "%04x"
#define SID_ARGS(SID) uuid_prefix(SID, 4)
#define SID_LEN 4

#define CID_FMT "%04x"
#define CID_ARGS(CID) uuid_prefix(CID, 4)
#define CID_LEN 4

struct ovsdb_error *raft_address_validate(const char *address)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *raft_addresses_from_json(const struct json *,
                                             struct sset *addresses)
    OVS_WARN_UNUSED_RESULT;
struct json *raft_addresses_to_json(const struct sset *addresses);

char *raft_address_to_nickname(const char *address, const struct uuid *sid);

enum raft_server_phase {
    RAFT_PHASE_STABLE,          /* Not being changed. */

    /* Phases for servers being added. */
    RAFT_PHASE_CATCHUP,         /* Populating new server's log. */
    RAFT_PHASE_CAUGHT_UP,       /* Waiting for prev configuration to commit. */
    RAFT_PHASE_COMMITTING,      /* Waiting for new configuration to commit. */

    /* Phases for servers to be removed. */
    RAFT_PHASE_REMOVE,          /* To be removed. */
};

const char *raft_server_phase_to_string(enum raft_server_phase);

/* Information about a server in a Raft cluster.
 *
 * Often within struct raft's 'servers' or 'add_servers' hmap. */
struct raft_server {
    struct hmap_node hmap_node; /* Hashed based on 'sid'. */

    struct uuid sid;            /* Unique Server ID. */
    char *address;              /* "(tcp|ssl):1.2.3.4:5678" */
    char *nickname;             /* "1ab3(s3)" */

    /* Volatile state on candidates.  Reinitialized at start of election. */
    struct uuid vote;           /* Server ID of vote, or all-zeros. */

    /* Volatile state on leaders.  Reinitialized after election. */
    uint64_t next_index;     /* Index of next log entry to send this server. */
    uint64_t match_index;    /* Index of max log entry server known to have. */
    enum raft_server_phase phase;
    /* For use in adding and removing servers: */
    struct uuid requester_sid;  /* Nonzero if requested via RPC. */
    struct unixctl_conn *requester_conn; /* Only if requested via unixctl. */
};

void raft_server_destroy(struct raft_server *);
void raft_servers_destroy(struct hmap *servers);
struct raft_server *raft_server_add(struct hmap *servers,
                                    const struct uuid *sid,
                                    const char *address);
struct raft_server *raft_server_find(const struct hmap *servers,
                                     const struct uuid *sid);
const char *raft_servers_get_nickname__(const struct hmap *servers,
                                        const struct uuid *sid);
const char *raft_servers_get_nickname(const struct hmap *servers,
                                      const struct uuid *sid,
                                      char buf[SID_LEN + 1], size_t bufsize);
struct ovsdb_error *raft_servers_from_json(const struct json *,
                                           struct hmap *servers)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *raft_servers_validate_json(const struct json *);
    OVS_WARN_UNUSED_RESULT
struct json *raft_servers_to_json(const struct hmap *servers);
void raft_servers_format(const struct hmap *servers, struct ds *ds);

/* A raft_entry is an in-memory data structure that represents a Raft log
 * entry.  */
struct raft_entry {
    uint64_t term;
    struct json *data;
    struct uuid eid;
    struct json *servers;
};

void raft_entry_clone(struct raft_entry *, const struct raft_entry *);
void raft_entry_uninit(struct raft_entry *);
struct json *raft_entry_to_json(const struct raft_entry *);
struct ovsdb_error *raft_entry_from_json(struct json *, struct raft_entry *)
    OVS_WARN_UNUSED_RESULT;
bool raft_entry_equals(const struct raft_entry *, const struct raft_entry *);

/* On disk data serialization and deserialization. */

/* First record in a Raft log. */
struct raft_header {
    /* All servers. */
    struct uuid sid;            /* Server ID. */
    struct uuid cid;            /* Cluster ID.  May be zero if 'joining'. */
    char *name;                 /* Database name. */
    char *local_address;        /* Address for Raft server to listen. */
    bool joining;               /* True iff cluster not joined yet. */

    /* Only for servers that haven't joined the cluster yet. */
    struct sset remote_addresses; /* Address of other Raft servers. */

    /* Only for servers that have joined the cluster. */
    uint64_t snap_index;        /* Snapshot's index. */
    struct raft_entry snap;     /* Snapshot. */
};

void raft_header_uninit(struct raft_header *);
struct ovsdb_error *raft_header_from_json(struct raft_header *,
                                          const struct json *)
    OVS_WARN_UNUSED_RESULT;
struct json *raft_header_to_json(const struct raft_header *);

enum raft_record_type {
    /* Record types that match those in the Raft specification. */
    RAFT_REC_ENTRY,             /* A log entry. */
    RAFT_REC_TERM,              /* A new term. */
    RAFT_REC_VOTE,              /* A vote. */

    /* Extensions. */
    RAFT_REC_NOTE,              /* A note about some significant event. */
    RAFT_REC_COMMIT_INDEX,      /* An update to the local commit_index. */
    RAFT_REC_LEADER,            /* A server has become leader for this term. */
};

/* Type used for the second and subsequent records in a Raft log. */
struct raft_record {
    enum raft_record_type type;
    char *comment;

    /* Valid in RAFT_REC_ENTRY, RAFT_REC_TERM, RAFT_REC_LEADER, and
     * RAFT_REC_VOTE, and otherwise 0. */
    uint64_t term;

    union {
        char *note;             /* RAFT_REC_NOTE. */

        uint64_t commit_index;  /* RAFT_REC_COMMIT_INDEX. */

        struct uuid sid;        /* RAFT_REC_VOTE, RAFT_REC_LEADER. */

        struct {                /* RAFT_REC_ENTRY. */
            uint64_t index;
            struct json *data;
            struct json *servers;
            struct uuid eid;
        } entry;
    };
};

void raft_record_uninit(struct raft_record *);
struct ovsdb_error *raft_record_from_json(struct raft_record *,
                                          const struct json *)
    OVS_WARN_UNUSED_RESULT;
struct json *raft_record_to_json(const struct raft_record *);

void raft_put_uint64(struct json *object, const char *name, uint64_t integer);
uint64_t raft_parse_optional_uint64(struct ovsdb_parser *, const char *name);
uint64_t raft_parse_required_uint64(struct ovsdb_parser *, const char *name);

bool raft_parse_required_boolean(struct ovsdb_parser *, const char *name);
int raft_parse_optional_boolean(struct ovsdb_parser *, const char *name);
const char *raft_parse_required_string(struct ovsdb_parser *,
                                           const char *name);
const char *raft_parse_optional_string(struct ovsdb_parser *,
                                           const char *name);
bool raft_parse_uuid(struct ovsdb_parser *, const char *name, bool optional,
                     struct uuid *);
struct uuid raft_parse_required_uuid(struct ovsdb_parser *, const char *name);
bool raft_parse_optional_uuid(struct ovsdb_parser *, const char *name,
                         struct uuid *);

#endif /* raft-private.h */
