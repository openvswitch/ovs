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

#ifndef RAFT_RPC_H
#define RAFT_RPC_H 1

/* Data structures used internally by Raft implementation for JSON-RPC. */

#include <stdbool.h>
#include <stdint.h>
#include "openvswitch/uuid.h"
#include "raft.h"
#include "raft-private.h"
#include "sset.h"

struct ds;

#define RAFT_RPC_TYPES                                                  \
    /* Hello RPC. */                                                    \
    RAFT_RPC(RAFT_RPC_HELLO_REQUEST, hello_request)                     \
                                                                        \
    /* AppendEntries RPC. */                                            \
    RAFT_RPC(RAFT_RPC_APPEND_REQUEST, append_request)                   \
    RAFT_RPC(RAFT_RPC_APPEND_REPLY, append_reply)                       \
                                                                        \
    /* RequestVote RPC. */                                              \
    RAFT_RPC(RAFT_RPC_VOTE_REQUEST, vote_request)                       \
    RAFT_RPC(RAFT_RPC_VOTE_REPLY, vote_reply)                           \
                                                                        \
    /* AddServer RPC. */                                                \
    RAFT_RPC(RAFT_RPC_ADD_SERVER_REQUEST, add_server_request)           \
    RAFT_RPC(RAFT_RPC_ADD_SERVER_REPLY, add_server_reply)               \
                                                                        \
    /* RemoveServer RPC. */                                             \
    RAFT_RPC(RAFT_RPC_REMOVE_SERVER_REQUEST, remove_server_request)     \
    RAFT_RPC(RAFT_RPC_REMOVE_SERVER_REPLY, remove_server_reply)         \
                                                                        \
    /* InstallSnapshot RPC. */                                          \
    RAFT_RPC(RAFT_RPC_INSTALL_SNAPSHOT_REQUEST, install_snapshot_request) \
    RAFT_RPC(RAFT_RPC_INSTALL_SNAPSHOT_REPLY, install_snapshot_reply)   \
                                                                        \
    /* BecomeLeader RPC. */                                             \
    RAFT_RPC(RAFT_RPC_BECOME_LEADER, become_leader)                     \
                                                                        \
    /* ExecuteCommand RPC. */                                           \
    RAFT_RPC(RAFT_RPC_EXECUTE_COMMAND_REQUEST, execute_command_request) \
    RAFT_RPC(RAFT_RPC_EXECUTE_COMMAND_REPLY, execute_command_reply)

enum raft_rpc_type {
#define RAFT_RPC(ENUM, NAME) ENUM,
    RAFT_RPC_TYPES
#undef RAFT_RPC
};

const char *raft_rpc_type_to_string(enum raft_rpc_type);
bool raft_rpc_type_from_string(const char *, enum raft_rpc_type *);

struct raft_rpc_common {
    enum raft_rpc_type type;    /* Message type. */
    struct uuid sid;            /* Peer server (source or destination). */
    char *comment;              /* Human-friendly additional text. */
};

struct raft_hello_request {
    struct raft_rpc_common common;
    char *address;              /* Sender's address. */
};

struct raft_append_request {
    struct raft_rpc_common common;
    uint64_t term;              /* Leader's term. */
    uint64_t prev_log_index;    /* Log entry just before new ones. */
    uint64_t prev_log_term;     /* Term of prev_log_index entry. */
    uint64_t leader_commit;     /* Leader's commit_index. */

    /* The append request includes 0 or more log entries.  entries[0] is for
     * log entry 'prev_log_index + 1', and so on.
     *
     * A heartbeat append_request has no terms. */
    struct raft_entry *entries;
    unsigned int n_entries;
};

enum raft_append_result {
    RAFT_APPEND_OK,             /* Success. */
    RAFT_APPEND_INCONSISTENCY,  /* Failure due to log inconsistency. */
    RAFT_APPEND_IO_ERROR,       /* Failure due to I/O error. */
};

const char *raft_append_result_to_string(enum raft_append_result);
bool raft_append_result_from_string(const char *, enum raft_append_result *);

struct raft_append_reply {
    struct raft_rpc_common common;

    /* Copied from the state machine of the reply's sender. */
    uint64_t term;             /* Current term, for leader to update itself. */
    uint64_t log_end;          /* To allow capping next_index, see 4.2.1. */

    /* Copied from request. */
    uint64_t prev_log_index;   /* Log entry just before new ones. */
    uint64_t prev_log_term;    /* Term of prev_log_index entry. */
    unsigned int n_entries;

    /* Result. */
    enum raft_append_result result;
};

struct raft_vote_request {
    struct raft_rpc_common common;
    uint64_t term;           /* Candidate's term. */
    uint64_t last_log_index; /* Index of candidate's last log entry. */
    uint64_t last_log_term;  /* Term of candidate's last log entry. */
    bool leadership_transfer;  /* True to override minimum election timeout. */
};

struct raft_vote_reply {
    struct raft_rpc_common common;
    uint64_t term;          /* Current term, for candidate to update itself. */
    struct uuid vote;       /* Server ID of vote. */
};

struct raft_add_server_request {
    struct raft_rpc_common common;
    char *address;              /* Address of new server. */
};

struct raft_remove_server_request {
    struct raft_rpc_common common;
    struct uuid sid;            /* Server to remove. */

    /* Nonnull if request was received via unixctl. */
    struct unixctl_conn *requester_conn;
};

/* The operation committed and is now complete. */
#define RAFT_SERVER_COMPLETED "completed"

/* The operation could not be initiated because this server is not the current
 * leader.  Only the leader can add or remove servers. */
#define RAFT_SERVER_NOT_LEADER "not leader"

/* An operation to add a server succeeded without any change because the server
 * was already part of the cluster. */
#define RAFT_SERVER_ALREADY_PRESENT "already in cluster"

/* An operation to remove a server succeeded without any change because the
 * server was not part of the cluster. */
#define RAFT_SERVER_ALREADY_GONE "already not in cluster"

/* The operation could not be initiated because an identical
 * operation was already in progress. */
#define RAFT_SERVER_IN_PROGRESS "in progress"

/* Adding a server failed because of a timeout.  This could mean that the
 * server was entirely unreachable, or that it became unreachable partway
 * through populating it with an initial copy of the log.  In the latter case,
 * retrying the operation should resume where it left off. */
#define RAFT_SERVER_TIMEOUT "timeout"

/* The operation was initiated but it later failed because this server lost
 * cluster leadership.  The operation may be retried against the new cluster
 * leader.  For adding a server, if the log was already partially copied to the
 * new server, retrying the operation should resume where it left off. */
#define RAFT_SERVER_LOST_LEADERSHIP "lost leadership"

/* Adding a server was canceled by submission of an operation to remove the
 * same server, or removing a server was canceled by submission of an operation
 * to add the same server. */
#define RAFT_SERVER_CANCELED "canceled"

/* Adding or removing a server could not be initiated because the operation to
 * remove or add the server, respectively, has been logged but not committed.
 * The new operation may be retried once the former operation commits. */
#define RAFT_SERVER_COMMITTING "committing"

/* Adding or removing a server was canceled because the leader shut down. */
#define RAFT_SERVER_SHUTDOWN "shutdown"

/* Removing a server could not be initiated because, taken together with any
 * other scheduled server removals, the cluster would be empty.  (This
 * calculation ignores scheduled or uncommitted add server operations because
 * of the possibility that they could fail.)  */
#define RAFT_SERVER_EMPTY "empty"

struct raft_add_server_reply {
    struct raft_rpc_common common;
    bool success;
    struct sset remote_addresses;
};

struct raft_remove_server_reply {
    struct raft_rpc_common common;
    bool success;
};

struct raft_install_snapshot_request {
    struct raft_rpc_common common;

    uint64_t term;              /* Leader's term. */

    uint64_t last_index;        /* Covers everything up & including this. */
    uint64_t last_term;         /* Term of last_index. */
    struct uuid last_eid;       /* Last entry ID. */
    struct json *last_servers;

    /* Data. */
    struct json *data;
};

struct raft_install_snapshot_reply {
    struct raft_rpc_common common;

    uint64_t term;              /* For leader to update itself. */

    /* Repeated from the install_snapshot request. */
    uint64_t last_index;
    uint64_t last_term;
};

struct raft_become_leader {
    struct raft_rpc_common common;

    uint64_t term;              /* Leader's term. */
};

struct raft_execute_command_request {
    struct raft_rpc_common common;

    struct json *data;
    struct uuid prereq;
    struct uuid result;
};

struct raft_execute_command_reply {
    struct raft_rpc_common common;

    struct uuid result;
    enum raft_command_status status;
    uint64_t commit_index;
};

union raft_rpc {
    enum raft_rpc_type type;
    struct raft_rpc_common common;
#define RAFT_RPC(ENUM, NAME) struct raft_##NAME NAME;
    RAFT_RPC_TYPES
#undef RAFT_RPC
};

#define RAFT_RPC(ENUM, NAME)                        \
    static inline const struct raft_##NAME *        \
    raft_##NAME##_cast(const union raft_rpc *rpc)   \
    {                                               \
        ovs_assert(rpc->type == ENUM);              \
        return &rpc->NAME;                          \
    }
RAFT_RPC_TYPES
#undef RAFT_RPC

void raft_rpc_uninit(union raft_rpc *);
union raft_rpc *raft_rpc_clone(const union raft_rpc *);

struct jsonrpc_msg *raft_rpc_to_jsonrpc(const struct uuid *cid,
                                        const struct uuid *sid,
                                        const union raft_rpc *);
struct ovsdb_error *raft_rpc_from_jsonrpc(struct uuid *cid,
                                          const struct uuid *sid,
                                          const struct jsonrpc_msg *,
                                          union raft_rpc *)
    OVS_WARN_UNUSED_RESULT;

void raft_rpc_format(const union raft_rpc *, struct ds *);

uint64_t raft_rpc_get_term(const union raft_rpc *);
const struct uuid *raft_rpc_get_vote(const union raft_rpc *);
uint64_t raft_rpc_get_min_sync_index(const union raft_rpc *);

#endif /* lib/raft-rpc.h */
