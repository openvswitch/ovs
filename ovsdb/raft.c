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

#include "raft.h"
#include "raft-private.h"

#include <errno.h>
#include <unistd.h>

#include "hash.h"
#include "jsonrpc.h"
#include "lockfile.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb/log.h"
#include "raft-rpc.h"
#include "random.h"
#include "socket-util.h"
#include "stream.h"
#include "timeval.h"
#include "unicode.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(raft);

/* Roles for a Raft server:
 *
 *    - Followers: Servers in touch with the current leader.
 *
 *    - Candidate: Servers unaware of a current leader and seeking election to
 *      leader.
 *
 *    - Leader: Handles all client requests.  At most one at a time.
 *
 * In normal operation there is exactly one leader and all of the other servers
 * are followers. */
enum raft_role {
    RAFT_FOLLOWER,
    RAFT_CANDIDATE,
    RAFT_LEADER
};

/* A connection between this Raft server and another one. */
struct raft_conn {
    struct ovs_list list_node;  /* In struct raft's 'conns' list. */
    struct jsonrpc_session *js; /* JSON-RPC connection. */
    struct uuid sid;            /* This server's unique ID. */
    char *nickname;             /* Short name for use in log messages. */
    bool incoming;              /* True if incoming, false if outgoing. */
    unsigned int js_seqno;      /* Seqno for noticing (re)connections. */
};

static void raft_conn_close(struct raft_conn *);

/* A "command", that is, a request to append an entry to the log.
 *
 * The Raft specification only allows clients to issue commands to the leader.
 * With this implementation, clients may issue a command on any server, which
 * then relays the command to the leader if necessary.
 *
 * This structure is thus used in three cases:
 *
 *     1. We are the leader and the command was issued to us directly.
 *
 *     2. We are a follower and relayed the command to the leader.
 *
 *     3. We are the leader and a follower relayed the command to us.
 */
struct raft_command {
    /* All cases. */
    struct hmap_node hmap_node; /* In struct raft's 'commands' hmap. */
    unsigned int n_refs;        /* Reference count.  */
    enum raft_command_status status; /* Execution status. */

    /* Case 1 only. */
    uint64_t index;             /* Index in log (0 if being relayed). */

    /* Cases 2 and 3. */
    struct uuid eid;            /* Entry ID of result. */

    /* Case 2 only. */
    long long int timestamp;    /* Issue or last ping time, for expiration. */

    /* Case 3 only. */
    struct uuid sid;            /* The follower (otherwise UUID_ZERO). */
};

static void raft_command_complete(struct raft *, struct raft_command *,
                                  enum raft_command_status);

static void raft_complete_all_commands(struct raft *,
                                       enum raft_command_status);

/* Type of deferred action, see struct raft_waiter. */
enum raft_waiter_type {
    RAFT_W_ENTRY,
    RAFT_W_TERM,
    RAFT_W_RPC,
};

/* An action deferred until a log write commits to disk. */
struct raft_waiter {
    struct ovs_list list_node;
    uint64_t commit_ticket;

    enum raft_waiter_type type;
    union {
        /* RAFT_W_ENTRY.
         *
         * Waits for a RAFT_REC_ENTRY write to our local log to commit.  Upon
         * completion, updates 'log_synced' to indicate that the new log entry
         * or entries are committed and, if we are leader, also updates our
         * local 'match_index'. */
        struct {
            uint64_t index;
        } entry;

        /* RAFT_W_TERM.
         *
         * Waits for a RAFT_REC_TERM or RAFT_REC_VOTE record write to commit.
         * Upon completion, updates 'synced_term' and 'synced_vote', which
         * triggers sending RPCs deferred by the uncommitted 'term' and
         * 'vote'. */
        struct {
            uint64_t term;
            struct uuid vote;
        } term;

        /* RAFT_W_RPC.
         *
         * Sometimes, sending an RPC to a peer must be delayed until an entry,
         * a term, or a vote mentioned in the RPC is synced to disk.  This
         * waiter keeps a copy of such an RPC until the previous waiters have
         * committed. */
        union raft_rpc *rpc;
    };
};

static struct raft_waiter *raft_waiter_create(struct raft *,
                                              enum raft_waiter_type,
                                              bool start_commit);
static void raft_waiters_destroy(struct raft *);

/* The Raft state machine. */
struct raft {
    struct hmap_node hmap_node; /* In 'all_rafts'. */
    struct ovsdb_log *log;

/* Persistent derived state.
 *
 * This must be updated on stable storage before responding to RPCs.  It can be
 * derived from the header, snapshot, and log in 'log'. */

    struct uuid cid;            /* Cluster ID (immutable for the cluster). */
    struct uuid sid;            /* Server ID (immutable for the server). */
    char *local_address;        /* Local address (immutable for the server). */
    char *local_nickname;       /* Used for local server in log messages. */
    char *name;                 /* Schema name (immutable for the cluster). */

    /* Contains "struct raft_server"s and represents the server configuration
     * most recently added to 'log'. */
    struct hmap servers;

/* Persistent state on all servers.
 *
 * Must be updated on stable storage before responding to RPCs. */

    /* Current term and the vote for that term.  These might be on the way to
     * disk now. */
    uint64_t term;              /* Initialized to 0 and only increases. */
    struct uuid vote;           /* All-zeros if no vote yet in 'term'. */

    /* The term and vote that have been synced to disk. */
    uint64_t synced_term;
    struct uuid synced_vote;

    /* The log.
     *
     * A log entry with index 1 never really exists; the initial snapshot for a
     * Raft is considered to include this index.  The first real log entry has
     * index 2.
     *
     * A new Raft instance contains an empty log:  log_start=2, log_end=2.
     * Over time, the log grows:                   log_start=2, log_end=N.
     * At some point, the server takes a snapshot: log_start=N, log_end=N.
     * The log continues to grow:                  log_start=N, log_end=N+1...
     *
     * Must be updated on stable storage before responding to RPCs. */
    struct raft_entry *entries; /* Log entry i is in log[i - log_start]. */
    uint64_t log_start;         /* Index of first entry in log. */
    uint64_t log_end;           /* Index of last entry in log, plus 1. */
    uint64_t log_synced;        /* Index of last synced entry. */
    size_t allocated_log;       /* Allocated entries in 'log'. */

    /* Snapshot state (see Figure 5.1)
     *
     * This is the state of the cluster as of the last discarded log entry,
     * that is, at log index 'log_start - 1' (called prevIndex in Figure 5.1).
     * Only committed log entries can be included in a snapshot. */
    struct raft_entry snap;

/* Volatile state.
 *
 * The snapshot is always committed, but the rest of the log might not be yet.
 * 'last_applied' tracks what entries have been passed to the client.  If the
 * client hasn't yet read the latest snapshot, then even the snapshot isn't
 * applied yet.  Thus, the invariants are different for these members:
 *
 *     log_start - 2 <= last_applied <= commit_index < log_end.
 *     log_start - 1                 <= commit_index < log_end.
 */

    enum raft_role role;        /* Current role. */
    uint64_t commit_index;      /* Max log index known to be committed. */
    uint64_t last_applied;      /* Max log index applied to state machine. */
    struct uuid leader_sid;     /* Server ID of leader (zero, if unknown). */

    /* Followers and candidates only. */
#define ELECTION_BASE_MSEC 1024
#define ELECTION_RANGE_MSEC 1024
    long long int election_base;    /* Time of last heartbeat from leader. */
    long long int election_timeout; /* Time at which we start an election. */

    /* Used for joining a cluster. */
    bool joining;                 /* Attempting to join the cluster? */
    struct sset remote_addresses; /* Addresses to try to find other servers. */
    long long int join_timeout;   /* Time to re-send add server request. */

    /* Used for leaving a cluster. */
    bool leaving;               /* True if we are leaving the cluster. */
    bool left;                  /* True if we have finished leaving. */
    long long int leave_timeout; /* Time to re-send remove server request. */

    /* Failure. */
    bool failed;                /* True if unrecoverable error has occurred. */

    /* File synchronization. */
    struct ovs_list waiters;    /* Contains "struct raft_waiter"s. */

    /* Network connections. */
    struct pstream *listener;   /* For connections from other Raft servers. */
    long long int listen_backoff; /* For retrying creating 'listener'. */
    struct ovs_list conns;      /* Contains struct raft_conns. */

    /* Leaders only.  Reinitialized after becoming leader. */
    struct hmap add_servers;    /* Contains "struct raft_server"s to add. */
    struct raft_server *remove_server; /* Server being removed. */
    struct hmap commands;       /* Contains "struct raft_command"s. */
#define PING_TIME_MSEC (ELECTION_BASE_MSEC / 3)
    long long int ping_timeout; /* Time at which to send a heartbeat */

    /* Candidates only.  Reinitialized at start of election. */
    int n_votes;                /* Number of votes for me. */
};

/* All Raft structures. */
static struct hmap all_rafts = HMAP_INITIALIZER(&all_rafts);

static void raft_init(void);

static struct ovsdb_error *raft_read_header(struct raft *)
    OVS_WARN_UNUSED_RESULT;

static void raft_send_execute_command_reply(struct raft *,
                                            const struct uuid *sid,
                                            const struct uuid *eid,
                                            enum raft_command_status,
                                            uint64_t commit_index);

static void raft_update_our_match_index(struct raft *, uint64_t min_index);

static void raft_send_remove_server_reply__(
    struct raft *, const struct uuid *target_sid,
    const struct uuid *requester_sid, struct unixctl_conn *requester_conn,
    bool success, const char *comment);

static void raft_server_init_leader(struct raft *, struct raft_server *);

static bool raft_rpc_is_heartbeat(const union raft_rpc *);
static bool raft_is_rpc_synced(const struct raft *, const union raft_rpc *);

static void raft_handle_rpc(struct raft *, const union raft_rpc *);
static bool raft_send(struct raft *, const union raft_rpc *);
static bool raft_send__(struct raft *, const union raft_rpc *,
                        struct raft_conn *);
static void raft_send_append_request(struct raft *,
                                     struct raft_server *, unsigned int n,
                                     const char *comment);

static void raft_become_leader(struct raft *);
static void raft_become_follower(struct raft *);
static void raft_reset_timer(struct raft *);
static void raft_send_heartbeats(struct raft *);
static void raft_start_election(struct raft *, bool leadership_transfer);
static bool raft_truncate(struct raft *, uint64_t new_end);
static void raft_get_servers_from_log(struct raft *, enum vlog_level);

static bool raft_handle_write_error(struct raft *, struct ovsdb_error *);

static void raft_run_reconfigure(struct raft *);

static struct raft_server *
raft_find_server(const struct raft *raft, const struct uuid *sid)
{
    return raft_server_find(&raft->servers, sid);
}

static char *
raft_make_address_passive(const char *address_)
{
    if (!strncmp(address_, "unix:", 5)) {
        return xasprintf("p%s", address_);
    } else {
        char *address = xstrdup(address_);
        char *p = strchr(address, ':') + 1;
        char *host = inet_parse_token(&p);
        char *port = inet_parse_token(&p);

        struct ds paddr = DS_EMPTY_INITIALIZER;
        ds_put_format(&paddr, "p%.3s:%s:", address, port);
        if (strchr(host, ':')) {
            ds_put_format(&paddr, "[%s]", host);
        } else {
            ds_put_cstr(&paddr, host);
        }
        free(address);
        return ds_steal_cstr(&paddr);
    }
}

static struct raft *
raft_alloc(void)
{
    raft_init();

    struct raft *raft = xzalloc(sizeof *raft);
    hmap_node_nullify(&raft->hmap_node);
    hmap_init(&raft->servers);
    raft->log_start = raft->log_end = 1;
    raft->role = RAFT_FOLLOWER;
    sset_init(&raft->remote_addresses);
    raft->join_timeout = LLONG_MAX;
    ovs_list_init(&raft->waiters);
    raft->listen_backoff = LLONG_MIN;
    ovs_list_init(&raft->conns);
    hmap_init(&raft->add_servers);
    hmap_init(&raft->commands);

    raft->ping_timeout = time_msec() + PING_TIME_MSEC;
    raft_reset_timer(raft);

    return raft;
}

/* Creates an on-disk file that represents a new Raft cluster and initializes
 * it to consist of a single server, the one on which this function is called.
 *
 * Creates the local copy of the cluster's log in 'file_name', which must not
 * already exist.  Gives it the name 'name', which should be the database
 * schema name and which is used only to match up this database with the server
 * added to the cluster later if the cluster ID is unavailable.
 *
 * The new server is located at 'local_address', which must take one of the
 * forms "tcp:IP:PORT" or "ssl:IP:PORT", where IP is an IPv4 address or a
 * square bracket enclosed IPv6 address and PORT is a TCP port number.
 *
 * This only creates the on-disk file.  Use raft_open() to start operating the
 * new server.
 *
 * Returns null if successful, otherwise an ovsdb_error describing the
 * problem. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_create_cluster(const char *file_name, const char *name,
                    const char *local_address, const struct json *data)
{
    /* Parse and verify validity of the local address. */
    struct ovsdb_error *error = raft_address_validate(local_address);
    if (error) {
        return error;
    }

    /* Create log file. */
    struct ovsdb_log *log;
    error = ovsdb_log_open(file_name, RAFT_MAGIC, OVSDB_LOG_CREATE_EXCL,
                           -1, &log);
    if (error) {
        return error;
    }

    /* Write log file. */
    struct raft_header h = {
        .sid = uuid_random(),
        .cid = uuid_random(),
        .name = xstrdup(name),
        .local_address = xstrdup(local_address),
        .joining = false,
        .remote_addresses = SSET_INITIALIZER(&h.remote_addresses),
        .snap_index = 1,
        .snap = {
            .term = 1,
            .data = json_nullable_clone(data),
            .eid = uuid_random(),
            .servers = json_object_create(),
        },
    };
    shash_add_nocopy(json_object(h.snap.servers),
                     xasprintf(UUID_FMT, UUID_ARGS(&h.sid)),
                     json_string_create(local_address));
    error = ovsdb_log_write_and_free(log, raft_header_to_json(&h));
    raft_header_uninit(&h);
    if (!error) {
        error = ovsdb_log_commit_block(log);
    }
    ovsdb_log_close(log);

    return error;
}

/* Creates a database file that represents a new server in an existing Raft
 * cluster.
 *
 * Creates the local copy of the cluster's log in 'file_name', which must not
 * already exist.  Gives it the name 'name', which must be the same name
 * passed in to raft_create_cluster() earlier.
 *
 * 'cid' is optional.  If specified, the new server will join only the cluster
 * with the given cluster ID.
 *
 * The new server is located at 'local_address', which must take one of the
 * forms "tcp:IP:PORT" or "ssl:IP:PORT", where IP is an IPv4 address or a
 * square bracket enclosed IPv6 address and PORT is a TCP port number.
 *
 * Joining the cluster requires contacting it.  Thus, 'remote_addresses'
 * specifies the addresses of existing servers in the cluster.  One server out
 * of the existing cluster is sufficient, as long as that server is reachable
 * and not partitioned from the current cluster leader.  If multiple servers
 * from the cluster are specified, then it is sufficient for any of them to
 * meet this criterion.
 *
 * This only creates the on-disk file and does no network access.  Use
 * raft_open() to start operating the new server.  (Until this happens, the
 * new server has not joined the cluster.)
 *
 * Returns null if successful, otherwise an ovsdb_error describing the
 * problem. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_join_cluster(const char *file_name,
                  const char *name, const char *local_address,
                  const struct sset *remote_addresses,
                  const struct uuid *cid)
{
    ovs_assert(!sset_is_empty(remote_addresses));

    /* Parse and verify validity of the addresses. */
    struct ovsdb_error *error = raft_address_validate(local_address);
    if (error) {
        return error;
    }
    const char *addr;
    SSET_FOR_EACH (addr, remote_addresses) {
        error = raft_address_validate(addr);
        if (error) {
            return error;
        }
        if (!strcmp(addr, local_address)) {
            return ovsdb_error(NULL, "remote addresses cannot be the same "
                               "as the local address");
        }
    }

    /* Verify validity of the cluster ID (if provided). */
    if (cid && uuid_is_zero(cid)) {
        return ovsdb_error(NULL, "all-zero UUID is not valid cluster ID");
    }

    /* Create log file. */
    struct ovsdb_log *log;
    error = ovsdb_log_open(file_name, RAFT_MAGIC, OVSDB_LOG_CREATE_EXCL,
                           -1, &log);
    if (error) {
        return error;
    }

    /* Write log file. */
    struct raft_header h = {
        .sid = uuid_random(),
        .cid = cid ? *cid : UUID_ZERO,
        .name = xstrdup(name),
        .local_address = xstrdup(local_address),
        .joining = true,
        /* No snapshot yet. */
    };
    sset_clone(&h.remote_addresses, remote_addresses);
    error = ovsdb_log_write_and_free(log, raft_header_to_json(&h));
    raft_header_uninit(&h);
    if (!error) {
        error = ovsdb_log_commit_block(log);
    }
    ovsdb_log_close(log);

    return error;
}

/* Reads the initial header record from 'log', which must be a Raft clustered
 * database log, and populates '*md' with the information read from it.  The
 * caller must eventually destroy 'md' with raft_metadata_destroy().
 *
 * On success, returns NULL.  On failure, returns an error that the caller must
 * eventually destroy and zeros '*md'. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_read_metadata(struct ovsdb_log *log, struct raft_metadata *md)
{
    struct raft *raft = raft_alloc();
    raft->log = log;

    struct ovsdb_error *error = raft_read_header(raft);
    if (!error) {
        md->sid = raft->sid;
        md->name = xstrdup(raft->name);
        md->local = xstrdup(raft->local_address);
        md->cid = raft->cid;
    } else {
        memset(md, 0, sizeof *md);
    }

    raft->log = NULL;
    raft_close(raft);
    return error;
}

/* Frees the metadata in 'md'. */
void
raft_metadata_destroy(struct raft_metadata *md)
{
    if (md) {
        free(md->name);
        free(md->local);
    }
}

static const struct raft_entry *
raft_get_entry(const struct raft *raft, uint64_t index)
{
    ovs_assert(index >= raft->log_start);
    ovs_assert(index < raft->log_end);
    return &raft->entries[index - raft->log_start];
}

static uint64_t
raft_get_term(const struct raft *raft, uint64_t index)
{
    return (index == raft->log_start - 1
            ? raft->snap.term
            : raft_get_entry(raft, index)->term);
}

static const struct json *
raft_servers_for_index(const struct raft *raft, uint64_t index)
{
    ovs_assert(index >= raft->log_start - 1);
    ovs_assert(index < raft->log_end);

    const struct json *servers = raft->snap.servers;
    for (uint64_t i = raft->log_start; i <= index; i++) {
        const struct raft_entry *e = raft_get_entry(raft, i);
        if (e->servers) {
            servers = e->servers;
        }
    }
    return servers;
}

static void
raft_set_servers(struct raft *raft, const struct hmap *new_servers,
                 enum vlog_level level)
{
    struct raft_server *s, *next;
    HMAP_FOR_EACH_SAFE (s, next, hmap_node, &raft->servers) {
        if (!raft_server_find(new_servers, &s->sid)) {
            ovs_assert(s != raft->remove_server);

            hmap_remove(&raft->servers, &s->hmap_node);
            VLOG(level, "server %s removed from configuration", s->nickname);
            raft_server_destroy(s);
        }
    }

    HMAP_FOR_EACH_SAFE (s, next, hmap_node, new_servers) {
        if (!raft_find_server(raft, &s->sid)) {
            VLOG(level, "server %s added to configuration", s->nickname);

            struct raft_server *new
                = raft_server_add(&raft->servers, &s->sid, s->address);
            raft_server_init_leader(raft, new);
        }
    }
}

static uint64_t
raft_add_entry(struct raft *raft,
               uint64_t term, struct json *data, const struct uuid *eid,
               struct json *servers)
{
    if (raft->log_end - raft->log_start >= raft->allocated_log) {
        raft->entries = x2nrealloc(raft->entries, &raft->allocated_log,
                                   sizeof *raft->entries);
    }

    uint64_t index = raft->log_end++;
    struct raft_entry *entry = &raft->entries[index - raft->log_start];
    entry->term = term;
    entry->data = data;
    entry->eid = eid ? *eid : UUID_ZERO;
    entry->servers = servers;
    return index;
}

/* Writes a RAFT_REC_ENTRY record for 'term', 'data', 'eid', 'servers' to
 * 'raft''s log and returns an error indication. */
static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_write_entry(struct raft *raft, uint64_t term, struct json *data,
                 const struct uuid *eid, struct json *servers)
{
    struct raft_record r = {
        .type = RAFT_REC_ENTRY,
        .term = term,
        .entry = {
            .index = raft_add_entry(raft, term, data, eid, servers),
            .data = data,
            .servers = servers,
            .eid = eid ? *eid : UUID_ZERO,
        },
    };
    return ovsdb_log_write_and_free(raft->log, raft_record_to_json(&r));
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_write_state(struct ovsdb_log *log,
                 uint64_t term, const struct uuid *vote)
{
    struct raft_record r = { .term = term };
    if (vote && !uuid_is_zero(vote)) {
        r.type = RAFT_REC_VOTE;
        r.sid = *vote;
    } else {
        r.type = RAFT_REC_TERM;
    }
    return ovsdb_log_write_and_free(log, raft_record_to_json(&r));
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_apply_record(struct raft *raft, unsigned long long int rec_idx,
                  const struct raft_record *r)
{
    /* Apply "term", which is present in most kinds of records (and otherwise
     * 0).
     *
     * A Raft leader can replicate entries from previous terms to the other
     * servers in the cluster, retaining the original terms on those entries
     * (see section 3.6.2 "Committing entries from previous terms" for more
     * information), so it's OK for the term in a log record to precede the
     * current term. */
    if (r->term > raft->term) {
        raft->term = raft->synced_term = r->term;
        raft->vote = raft->synced_vote = UUID_ZERO;
    }

    switch (r->type) {
    case RAFT_REC_ENTRY:
        if (r->entry.index < raft->commit_index) {
            return ovsdb_error(NULL, "record %llu attempts to truncate log "
                               "from %"PRIu64" to %"PRIu64" entries, but "
                               "commit index is already %"PRIu64,
                               rec_idx, raft->log_end, r->entry.index,
                               raft->commit_index);
        } else if (r->entry.index > raft->log_end) {
            return ovsdb_error(NULL, "record %llu with index %"PRIu64" skips "
                               "past expected index %"PRIu64,
                               rec_idx, r->entry.index, raft->log_end);
        }

        if (r->entry.index < raft->log_end) {
            /* This can happen, but it is notable. */
            VLOG_DBG("record %llu truncates log from %"PRIu64" to %"PRIu64
                     " entries", rec_idx, raft->log_end, r->entry.index);
            raft_truncate(raft, r->entry.index);
        }

        uint64_t prev_term = (raft->log_end > raft->log_start
                              ? raft->entries[raft->log_end
                                              - raft->log_start - 1].term
                              : raft->snap.term);
        if (r->term < prev_term) {
            return ovsdb_error(NULL, "record %llu with index %"PRIu64" term "
                               "%"PRIu64" precedes previous entry's term "
                               "%"PRIu64,
                               rec_idx, r->entry.index, r->term, prev_term);
        }

        raft->log_synced = raft_add_entry(
            raft, r->term,
            json_nullable_clone(r->entry.data), &r->entry.eid,
            json_nullable_clone(r->entry.servers));
        return NULL;

    case RAFT_REC_TERM:
        return NULL;

    case RAFT_REC_VOTE:
        if (r->term < raft->term) {
            return ovsdb_error(NULL, "record %llu votes for term %"PRIu64" "
                               "but current term is %"PRIu64,
                               rec_idx, r->term, raft->term);
        } else if (!uuid_is_zero(&raft->vote)
                   && !uuid_equals(&raft->vote, &r->sid)) {
            return ovsdb_error(NULL, "record %llu votes for "SID_FMT" in term "
                               "%"PRIu64" but a previous record for the "
                               "same term voted for "SID_FMT, rec_idx,
                               SID_ARGS(&raft->vote), r->term,
                               SID_ARGS(&r->sid));
        } else {
            raft->vote = raft->synced_vote = r->sid;
            return NULL;
        }
        break;

    case RAFT_REC_NOTE:
        if (!strcmp(r->note, "left")) {
            return ovsdb_error(NULL, "record %llu indicates server has left "
                               "the cluster; it cannot be added back (use "
                               "\"ovsdb-tool join-cluster\" to add a new "
                               "server)", rec_idx);
        }
        return NULL;

    case RAFT_REC_COMMIT_INDEX:
        if (r->commit_index < raft->commit_index) {
            return ovsdb_error(NULL, "record %llu regresses commit index "
                               "from %"PRIu64 " to %"PRIu64,
                               rec_idx, raft->commit_index, r->commit_index);
        } else if (r->commit_index >= raft->log_end) {
            return ovsdb_error(NULL, "record %llu advances commit index to "
                               "%"PRIu64 " but last log index is %"PRIu64,
                               rec_idx, r->commit_index, raft->log_end - 1);
        } else {
            raft->commit_index = r->commit_index;
            return NULL;
        }
        break;

    case RAFT_REC_LEADER:
        /* XXX we could use this to take back leadership for quick restart */
        return NULL;

    default:
        OVS_NOT_REACHED();
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_read_header(struct raft *raft)
{
    /* Read header record. */
    struct json *json;
    struct ovsdb_error *error = ovsdb_log_read(raft->log, &json);
    if (error || !json) {
        /* Report error or end-of-file. */
        return error;
    }
    ovsdb_log_mark_base(raft->log);

    struct raft_header h;
    error = raft_header_from_json(&h, json);
    json_destroy(json);
    if (error) {
        return error;
    }

    raft->sid = h.sid;
    raft->cid = h.cid;
    raft->name = xstrdup(h.name);
    raft->local_address = xstrdup(h.local_address);
    raft->local_nickname = raft_address_to_nickname(h.local_address, &h.sid);
    raft->joining = h.joining;

    if (h.joining) {
        sset_clone(&raft->remote_addresses, &h.remote_addresses);
    } else {
        raft_entry_clone(&raft->snap, &h.snap);
        raft->log_start = raft->log_end = h.snap_index + 1;
        raft->commit_index = h.snap_index;
        raft->last_applied = h.snap_index - 1;
    }

    raft_header_uninit(&h);

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_read_log(struct raft *raft)
{
    for (unsigned long long int i = 1; ; i++) {
        struct json *json;
        struct ovsdb_error *error = ovsdb_log_read(raft->log, &json);
        if (!json) {
            if (error) {
                /* We assume that the error is due to a partial write while
                 * appending to the file before a crash, so log it and
                 * continue. */
                char *error_string = ovsdb_error_to_string_free(error);
                VLOG_WARN("%s", error_string);
                free(error_string);
                error = NULL;
            }
            break;
        }

        struct raft_record r;
        error = raft_record_from_json(&r, json);
        if (!error) {
            error = raft_apply_record(raft, i, &r);
            raft_record_uninit(&r);
        }
        if (error) {
            return ovsdb_wrap_error(error, "error reading record %llu from "
                                    "%s log", i, raft->name);
        }
    }

    /* Set the most recent servers. */
    raft_get_servers_from_log(raft, VLL_DBG);

    return NULL;
}

static void
raft_reset_timer(struct raft *raft)
{
    unsigned int duration = (ELECTION_BASE_MSEC
                             + random_range(ELECTION_RANGE_MSEC));
    raft->election_base = time_msec();
    raft->election_timeout = raft->election_base + duration;
}

static void
raft_add_conn(struct raft *raft, struct jsonrpc_session *js,
              const struct uuid *sid, bool incoming)
{
    struct raft_conn *conn = xzalloc(sizeof *conn);
    ovs_list_push_back(&raft->conns, &conn->list_node);
    conn->js = js;
    if (sid) {
        conn->sid = *sid;
    }
    conn->nickname = raft_address_to_nickname(jsonrpc_session_get_name(js),
                                              &conn->sid);
    conn->incoming = incoming;
    conn->js_seqno = jsonrpc_session_get_seqno(conn->js);
}

/* Starts the local server in an existing Raft cluster, using the local copy of
 * the cluster's log in 'file_name'.  Takes ownership of 'log', whether
 * successful or not. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_open(struct ovsdb_log *log, struct raft **raftp)
{
    struct raft *raft = raft_alloc();
    raft->log = log;

    struct ovsdb_error *error = raft_read_header(raft);
    if (error) {
        goto error;
    }

    if (!raft->joining) {
        error = raft_read_log(raft);
        if (error) {
            goto error;
        }

        /* Find our own server. */
        if (!raft_find_server(raft, &raft->sid)) {
            error = ovsdb_error(NULL, "server does not belong to cluster");
            goto error;
        }

        /* If there's only one server, start an election right away so that the
         * cluster bootstraps quickly. */
        if (hmap_count(&raft->servers) == 1) {
            raft_start_election(raft, false);
        }
    } else {
        raft->join_timeout = time_msec() + 1000;
    }

    *raftp = raft;
    hmap_insert(&all_rafts, &raft->hmap_node, hash_string(raft->name, 0));
    return NULL;

error:
    raft_close(raft);
    *raftp = NULL;
    return error;
}

/* Returns the name of 'raft', which in OVSDB is the database schema name. */
const char *
raft_get_name(const struct raft *raft)
{
    return raft->name;
}

/* Returns the cluster ID of 'raft'.  If 'raft' has not yet completed joining
 * its cluster, then 'cid' will be all-zeros (unless the administrator
 * specified a cluster ID running "ovsdb-tool join-cluster").
 *
 * Each cluster has a unique cluster ID. */
const struct uuid *
raft_get_cid(const struct raft *raft)
{
    return &raft->cid;
}

/* Returns the server ID of 'raft'.  Each server has a unique server ID. */
const struct uuid *
raft_get_sid(const struct raft *raft)
{
    return &raft->sid;
}

/* Returns true if 'raft' has completed joining its cluster, has not left or
 * initiated leaving the cluster, does not have failed disk storage, and is
 * apparently connected to the leader in a healthy way (or is itself the
 * leader).*/
bool
raft_is_connected(const struct raft *raft)
{
    return (raft->role != RAFT_CANDIDATE
            && !raft->joining
            && !raft->leaving
            && !raft->left
            && !raft->failed);
}

/* Returns true if 'raft' is the cluster leader. */
bool
raft_is_leader(const struct raft *raft)
{
    return raft->role == RAFT_LEADER;
}

/* Returns true if 'raft' is the process of joining its cluster. */
bool
raft_is_joining(const struct raft *raft)
{
    return raft->joining;
}

/* Only returns *connected* connections. */
static struct raft_conn *
raft_find_conn_by_sid(struct raft *raft, const struct uuid *sid)
{
    if (!uuid_is_zero(sid)) {
        struct raft_conn *conn;
        LIST_FOR_EACH (conn, list_node, &raft->conns) {
            if (uuid_equals(sid, &conn->sid)
                && jsonrpc_session_is_connected(conn->js)) {
                return conn;
            }
        }
    }
    return NULL;
}

static struct raft_conn *
raft_find_conn_by_address(struct raft *raft, const char *address)
{
    struct raft_conn *conn;
    LIST_FOR_EACH (conn, list_node, &raft->conns) {
        if (!strcmp(jsonrpc_session_get_name(conn->js), address)) {
            return conn;
        }
    }
    return NULL;
}

static void OVS_PRINTF_FORMAT(3, 4)
raft_record_note(struct raft *raft, const char *note,
                 const char *comment_format, ...)
{
    va_list args;
    va_start(args, comment_format);
    char *comment = xvasprintf(comment_format, args);
    va_end(args);

    struct raft_record r = {
        .type = RAFT_REC_NOTE,
        .comment = comment,
        .note = CONST_CAST(char *, note),
    };
    ignore(ovsdb_log_write_and_free(raft->log, raft_record_to_json(&r)));

    free(comment);
}

/* If we're leader, try to transfer leadership to another server, logging
 * 'reason' as the human-readable reason (it should be a phrase suitable for
 * following "because") . */
void
raft_transfer_leadership(struct raft *raft, const char *reason)
{
    if (raft->role != RAFT_LEADER) {
        return;
    }

    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (!uuid_equals(&raft->sid, &s->sid)
            && s->phase == RAFT_PHASE_STABLE) {
            struct raft_conn *conn = raft_find_conn_by_sid(raft, &s->sid);
            if (!conn) {
                continue;
            }

            union raft_rpc rpc = {
                .become_leader = {
                    .common = {
                        .comment = CONST_CAST(char *, reason),
                        .type = RAFT_RPC_BECOME_LEADER,
                        .sid = s->sid,
                    },
                    .term = raft->term,
                }
            };
            raft_send__(raft, &rpc, conn);

            raft_record_note(raft, "transfer leadership",
                             "transferring leadership to %s because %s",
                             s->nickname, reason);
            break;
        }
    }
}

/* Send a RemoveServerRequest to the rest of the servers in the cluster.
 *
 * If we know which server is the leader, we can just send the request to it.
 * However, we might not know which server is the leader, and we might never
 * find out if the remove request was actually previously committed by a
 * majority of the servers (because in that case the new leader will not send
 * AppendRequests or heartbeats to us).  Therefore, we instead send
 * RemoveRequests to every server.  This theoretically has the same problem, if
 * the current cluster leader was not previously a member of the cluster, but
 * it seems likely to be more robust in practice.  */
static void
raft_send_remove_server_requests(struct raft *raft)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    VLOG_INFO_RL(&rl, "sending remove request (joining=%s, leaving=%s)",
                 raft->joining ? "true" : "false",
                 raft->leaving ? "true" : "false");
    const struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (!uuid_equals(&s->sid, &raft->sid)) {
            union raft_rpc rpc = (union raft_rpc) {
                .remove_server_request = {
                    .common = {
                        .type = RAFT_RPC_REMOVE_SERVER_REQUEST,
                        .sid = s->sid,
                    },
                    .sid = raft->sid,
                },
            };
            raft_send(raft, &rpc);
        }
    }

    raft->leave_timeout = time_msec() + ELECTION_BASE_MSEC;
}

/* Attempts to start 'raft' leaving its cluster.  The caller can check progress
 * using raft_is_leaving() and raft_left(). */
void
raft_leave(struct raft *raft)
{
    if (raft->joining || raft->failed || raft->leaving || raft->left) {
        return;
    }
    VLOG_INFO(SID_FMT": starting to leave cluster "CID_FMT,
              SID_ARGS(&raft->sid), CID_ARGS(&raft->cid));
    raft->leaving = true;
    raft_transfer_leadership(raft, "this server is leaving the cluster");
    raft_become_follower(raft);
    raft_send_remove_server_requests(raft);
    raft->leave_timeout = time_msec() + ELECTION_BASE_MSEC;
}

/* Returns true if 'raft' is currently attempting to leave its cluster. */
bool
raft_is_leaving(const struct raft *raft)
{
    return raft->leaving;
}

/* Returns true if 'raft' successfully left its cluster. */
bool
raft_left(const struct raft *raft)
{
    return raft->left;
}

/* Returns true if 'raft' has experienced a disk I/O failure.  When this
 * returns true, only closing and reopening 'raft' allows for recovery. */
bool
raft_failed(const struct raft *raft)
{
    return raft->failed;
}

/* Forces 'raft' to attempt to take leadership of the cluster by deposing the
 * current cluster. */
void
raft_take_leadership(struct raft *raft)
{
    if (raft->role != RAFT_LEADER) {
        raft_start_election(raft, true);
    }
}

/* Closes everything owned by 'raft' that might be visible outside the process:
 * network connections, commands, etc.  This is part of closing 'raft'; it is
 * also used if 'raft' has failed in an unrecoverable way. */
static void
raft_close__(struct raft *raft)
{
    if (!hmap_node_is_null(&raft->hmap_node)) {
        hmap_remove(&all_rafts, &raft->hmap_node);
        hmap_node_nullify(&raft->hmap_node);
    }

    raft_complete_all_commands(raft, RAFT_CMD_SHUTDOWN);

    struct raft_server *rs = raft->remove_server;
    if (rs) {
        raft_send_remove_server_reply__(raft, &rs->sid, &rs->requester_sid,
                                        rs->requester_conn, false,
                                        RAFT_SERVER_SHUTDOWN);
        raft_server_destroy(raft->remove_server);
        raft->remove_server = NULL;
    }

    struct raft_conn *conn, *next;
    LIST_FOR_EACH_SAFE (conn, next, list_node, &raft->conns) {
        raft_conn_close(conn);
    }
}

/* Closes and frees 'raft'.
 *
 * A server's cluster membership is independent of whether the server is
 * actually running.  When a server that is a member of a cluster closes, the
 * cluster treats this as a server failure. */
void
raft_close(struct raft *raft)
{
    if (!raft) {
        return;
    }

    raft_transfer_leadership(raft, "this server is shutting down");

    raft_close__(raft);

    ovsdb_log_close(raft->log);

    raft_servers_destroy(&raft->servers);

    for (uint64_t index = raft->log_start; index < raft->log_end; index++) {
        struct raft_entry *e = &raft->entries[index - raft->log_start];
        raft_entry_uninit(e);
    }
    free(raft->entries);

    raft_entry_uninit(&raft->snap);

    raft_waiters_destroy(raft);

    raft_servers_destroy(&raft->add_servers);

    hmap_destroy(&raft->commands);

    pstream_close(raft->listener);

    sset_destroy(&raft->remote_addresses);
    free(raft->local_address);
    free(raft->local_nickname);
    free(raft->name);

    free(raft);
}

static bool
raft_conn_receive(struct raft *raft, struct raft_conn *conn,
                  union raft_rpc *rpc)
{
    struct jsonrpc_msg *msg = jsonrpc_session_recv(conn->js);
    if (!msg) {
        return false;
    }

    struct ovsdb_error *error = raft_rpc_from_jsonrpc(&raft->cid, &raft->sid,
                                                      msg, rpc);
    jsonrpc_msg_destroy(msg);
    if (error) {
        char *s = ovsdb_error_to_string_free(error);
        VLOG_INFO("%s: %s", jsonrpc_session_get_name(conn->js), s);
        free(s);
        return false;
    }

    if (uuid_is_zero(&conn->sid)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(50, 50);
        conn->sid = rpc->common.sid;
        VLOG_INFO_RL(&rl, "%s: learned server ID "SID_FMT,
                     jsonrpc_session_get_name(conn->js), SID_ARGS(&conn->sid));
    } else if (!uuid_equals(&conn->sid, &rpc->common.sid)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "%s: ignoring message with unexpected server ID "
                     SID_FMT" (expected "SID_FMT")",
                     jsonrpc_session_get_name(conn->js),
                     SID_ARGS(&rpc->common.sid), SID_ARGS(&conn->sid));
        raft_rpc_uninit(rpc);
        return false;
    }

    const char *address = (rpc->type == RAFT_RPC_HELLO_REQUEST
                           ? rpc->hello_request.address
                           : rpc->type == RAFT_RPC_ADD_SERVER_REQUEST
                           ? rpc->add_server_request.address
                           : NULL);
    if (address) {
        char *new_nickname = raft_address_to_nickname(address, &conn->sid);
        if (strcmp(conn->nickname, new_nickname)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(50, 50);
            VLOG_INFO_RL(&rl, "%s: learned remote address %s",
                         jsonrpc_session_get_name(conn->js), address);

            free(conn->nickname);
            conn->nickname = new_nickname;
        } else {
            free(new_nickname);
        }
    }

    return true;
}

static const char *
raft_get_nickname(const struct raft *raft, const struct uuid *sid,
                  char buf[SID_LEN + 1], size_t bufsize)
{
    if (uuid_equals(sid, &raft->sid)) {
        return raft->local_nickname;
    }

    const char *s = raft_servers_get_nickname__(&raft->servers, sid);
    if (s) {
        return s;
    }

    return raft_servers_get_nickname(&raft->add_servers, sid, buf, bufsize);
}

static void
log_rpc(const union raft_rpc *rpc,
        const char *direction, const struct raft_conn *conn)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);
    if (!raft_rpc_is_heartbeat(rpc) && !VLOG_DROP_DBG(&rl)) {
        struct ds s = DS_EMPTY_INITIALIZER;
        raft_rpc_format(rpc, &s);
        VLOG_DBG("%s%s %s", direction, conn->nickname, ds_cstr(&s));
        ds_destroy(&s);
    }
}

static void
raft_send_add_server_request(struct raft *raft, struct raft_conn *conn)
{
    union raft_rpc rq = {
        .add_server_request = {
            .common = {
                .type = RAFT_RPC_ADD_SERVER_REQUEST,
                .sid = UUID_ZERO,
                .comment = NULL,
            },
            .address = raft->local_address,
        },
    };
    raft_send__(raft, &rq, conn);
}

static void
raft_conn_run(struct raft *raft, struct raft_conn *conn)
{
    jsonrpc_session_run(conn->js);

    unsigned int new_seqno = jsonrpc_session_get_seqno(conn->js);
    bool just_connected = (new_seqno != conn->js_seqno
                           && jsonrpc_session_is_connected(conn->js));
    conn->js_seqno = new_seqno;
    if (just_connected) {
        if (raft->joining) {
            raft_send_add_server_request(raft, conn);
        } else if (raft->leaving) {
            union raft_rpc rq = {
                .remove_server_request = {
                    .common = {
                        .type = RAFT_RPC_REMOVE_SERVER_REQUEST,
                        .sid = conn->sid,
                    },
                    .sid = raft->sid,
                },
            };
            raft_send__(raft, &rq, conn);
        } else {
            union raft_rpc rq = (union raft_rpc) {
                .hello_request = {
                    .common = {
                        .type = RAFT_RPC_HELLO_REQUEST,
                        .sid = conn->sid,
                    },
                    .address = raft->local_address,
                },
            };
            raft_send__(raft, &rq, conn);
        }
    }

    for (size_t i = 0; i < 50; i++) {
        union raft_rpc rpc;
        if (!raft_conn_receive(raft, conn, &rpc)) {
            break;
        }

        log_rpc(&rpc, "<--", conn);
        raft_handle_rpc(raft, &rpc);
        raft_rpc_uninit(&rpc);
    }
}

static void
raft_waiter_complete_rpc(struct raft *raft, const union raft_rpc *rpc)
{
    uint64_t term = raft_rpc_get_term(rpc);
    if (term && term < raft->term) {
        /* Drop the message because it's for an expired term. */
        return;
    }

    if (!raft_is_rpc_synced(raft, rpc)) {
        /* This is a bug.  A reply message is deferred because some state in
         * the message, such as a term or index, has not been committed to
         * disk, and they should only be completed when that commit is done.
         * But this message is being completed before the commit is finished.
         * Complain, and hope that someone reports the bug. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        if (VLOG_DROP_ERR(&rl)) {
            return;
        }

        struct ds s = DS_EMPTY_INITIALIZER;

        if (term > raft->synced_term) {
            ds_put_format(&s, " because message term %"PRIu64" is "
                          "past synced term %"PRIu64,
                          term, raft->synced_term);
        }

        uint64_t index = raft_rpc_get_min_sync_index(rpc);
        if (index > raft->log_synced) {
            ds_put_format(&s, " %s message index %"PRIu64" is past last "
                          "synced index %"PRIu64,
                          s.length ? "and" : "because",
                          index, raft->log_synced);
        }

        const struct uuid *vote = raft_rpc_get_vote(rpc);
        if (vote && !uuid_equals(vote, &raft->synced_vote)) {
            char buf1[SID_LEN + 1];
            char buf2[SID_LEN + 1];
            ds_put_format(&s, " %s vote %s differs from synced vote %s",
                          s.length ? "and" : "because",
                          raft_get_nickname(raft, vote, buf1, sizeof buf1),
                          raft_get_nickname(raft, &raft->synced_vote,
                                            buf2, sizeof buf2));
        }

        char buf[SID_LEN + 1];
        ds_put_format(&s, ": %s ",
                      raft_get_nickname(raft, &rpc->common.sid,
                                        buf, sizeof buf));
        raft_rpc_format(rpc, &s);
        VLOG_ERR("internal error: deferred %s message completed "
                 "but not ready to send%s",
                 raft_rpc_type_to_string(rpc->type), ds_cstr(&s));
        ds_destroy(&s);

        return;
    }

    struct raft_conn *dst = raft_find_conn_by_sid(raft, &rpc->common.sid);
    if (dst) {
        raft_send__(raft, rpc, dst);
    }
}

static void
raft_waiter_complete(struct raft *raft, struct raft_waiter *w)
{
    switch (w->type) {
    case RAFT_W_ENTRY:
        if (raft->role == RAFT_LEADER) {
            raft_update_our_match_index(raft, w->entry.index);
        }
        raft->log_synced = w->entry.index;
        break;

    case RAFT_W_TERM:
        raft->synced_term = w->term.term;
        raft->synced_vote = w->term.vote;
        break;

    case RAFT_W_RPC:
        raft_waiter_complete_rpc(raft, w->rpc);
        break;
    }
}

static void
raft_waiter_destroy(struct raft_waiter *w)
{
    if (!w) {
        return;
    }

    ovs_list_remove(&w->list_node);

    switch (w->type) {
    case RAFT_W_ENTRY:
    case RAFT_W_TERM:
        break;

    case RAFT_W_RPC:
        raft_rpc_uninit(w->rpc);
        free(w->rpc);
        break;
    }
    free(w);
}

static void
raft_waiters_run(struct raft *raft)
{
    if (ovs_list_is_empty(&raft->waiters)) {
        return;
    }

    uint64_t cur = ovsdb_log_commit_progress(raft->log);
    struct raft_waiter *w, *next;
    LIST_FOR_EACH_SAFE (w, next, list_node, &raft->waiters) {
        if (cur < w->commit_ticket) {
            break;
        }
        raft_waiter_complete(raft, w);
        raft_waiter_destroy(w);
    }
}

static void
raft_waiters_wait(struct raft *raft)
{
    struct raft_waiter *w;
    LIST_FOR_EACH (w, list_node, &raft->waiters) {
        ovsdb_log_commit_wait(raft->log, w->commit_ticket);
        break;
    }
}

static void
raft_waiters_destroy(struct raft *raft)
{
    struct raft_waiter *w, *next;
    LIST_FOR_EACH_SAFE (w, next, list_node, &raft->waiters) {
        raft_waiter_destroy(w);
    }
}

static bool OVS_WARN_UNUSED_RESULT
raft_set_term(struct raft *raft, uint64_t term, const struct uuid *vote)
{
    struct ovsdb_error *error = raft_write_state(raft->log, term, vote);
    if (!raft_handle_write_error(raft, error)) {
        return false;
    }

    struct raft_waiter *w = raft_waiter_create(raft, RAFT_W_TERM, true);
    raft->term = w->term.term = term;
    raft->vote = w->term.vote = vote ? *vote : UUID_ZERO;
    return true;
}

static void
raft_accept_vote(struct raft *raft, struct raft_server *s,
                 const struct uuid *vote)
{
    if (uuid_equals(&s->vote, vote)) {
        return;
    }
    if (!uuid_is_zero(&s->vote)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        char buf1[SID_LEN + 1];
        char buf2[SID_LEN + 1];
        VLOG_WARN_RL(&rl, "server %s changed its vote from %s to %s",
                     s->nickname,
                     raft_get_nickname(raft, &s->vote, buf1, sizeof buf1),
                     raft_get_nickname(raft, vote, buf2, sizeof buf2));
    }
    s->vote = *vote;
    if (uuid_equals(vote, &raft->sid)
        && ++raft->n_votes > hmap_count(&raft->servers) / 2) {
        raft_become_leader(raft);
    }
}

static void
raft_start_election(struct raft *raft, bool leadership_transfer)
{
    if (raft->leaving) {
        return;
    }

    struct raft_server *me = raft_find_server(raft, &raft->sid);
    if (!me) {
        return;
    }

    if (!raft_set_term(raft, raft->term + 1, &raft->sid)) {
        return;
    }

    raft_complete_all_commands(raft, RAFT_CMD_LOST_LEADERSHIP);

    ovs_assert(raft->role != RAFT_LEADER);
    ovs_assert(hmap_is_empty(&raft->commands));
    raft->role = RAFT_CANDIDATE;

    raft->n_votes = 0;

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    if (!VLOG_DROP_INFO(&rl)) {
        long long int now = time_msec();
        if (now >= raft->election_timeout) {
            VLOG_INFO("term %"PRIu64": %lld ms timeout expired, "
                      "starting election",
                      raft->term, now - raft->election_base);
        } else {
            VLOG_INFO("term %"PRIu64": starting election", raft->term);
        }
    }
    raft_reset_timer(raft);

    struct raft_server *peer;
    HMAP_FOR_EACH (peer, hmap_node, &raft->servers) {
        peer->vote = UUID_ZERO;
        if (uuid_equals(&raft->sid, &peer->sid)) {
            continue;
        }

        union raft_rpc rq = {
            .vote_request = {
                .common = {
                    .type = RAFT_RPC_VOTE_REQUEST,
                    .sid = peer->sid,
                },
                .term = raft->term,
                .last_log_index = raft->log_end - 1,
                .last_log_term = (
                    raft->log_end > raft->log_start
                    ? raft->entries[raft->log_end - raft->log_start - 1].term
                    : raft->snap.term),
                .leadership_transfer = leadership_transfer,
            },
        };
        raft_send(raft, &rq);
    }

    /* Vote for ourselves. */
    raft_accept_vote(raft, me, &raft->sid);
}

static void
raft_open_conn(struct raft *raft, const char *address, const struct uuid *sid)
{
    if (strcmp(address, raft->local_address)
        && !raft_find_conn_by_address(raft, address)) {
        raft_add_conn(raft, jsonrpc_session_open(address, true), sid, false);
    }
}

static void
raft_conn_close(struct raft_conn *conn)
{
    jsonrpc_session_close(conn->js);
    ovs_list_remove(&conn->list_node);
    free(conn->nickname);
    free(conn);
}

/* Returns true if 'conn' should stay open, false if it should be closed. */
static bool
raft_conn_should_stay_open(struct raft *raft, struct raft_conn *conn)
{
    /* Close the connection if it's actually dead.  If necessary, we'll
     * initiate a new session later. */
    if (!jsonrpc_session_is_alive(conn->js)) {
        return false;
    }

    /* Keep incoming sessions.  We trust the originator to decide to drop
     * it. */
    if (conn->incoming) {
        return true;
    }

    /* If we are joining the cluster, keep sessions to the remote addresses
     * that are supposed to be part of the cluster we're joining. */
    if (raft->joining && sset_contains(&raft->remote_addresses,
                                       jsonrpc_session_get_name(conn->js))) {
        return true;
    }

    /* We have joined the cluster.  If we did that "recently", then there is a
     * chance that we do not have the most recent server configuration log
     * entry.  If so, it's a waste to disconnect from the servers that were in
     * remote_addresses and that will probably appear in the configuration,
     * just to reconnect to them a moment later when we do get the
     * configuration update.  If we are not ourselves in the configuration,
     * then we know that there must be a new configuration coming up, so in
     * that case keep the connection. */
    if (!raft_find_server(raft, &raft->sid)) {
        return true;
    }

    /* Keep the connection only if the server is part of the configuration. */
    return raft_find_server(raft, &conn->sid);
}

/* Allows 'raft' to maintain the distributed log.  Call this function as part
 * of the process's main loop. */
void
raft_run(struct raft *raft)
{
    if (raft->left || raft->failed) {
        return;
    }

    raft_waiters_run(raft);

    if (!raft->listener && time_msec() >= raft->listen_backoff) {
        char *paddr = raft_make_address_passive(raft->local_address);
        int error = pstream_open(paddr, &raft->listener, DSCP_DEFAULT);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "%s: listen failed (%s)",
                         paddr, ovs_strerror(error));
            raft->listen_backoff = time_msec() + 1000;
        }
        free(paddr);
    }

    if (raft->listener) {
        struct stream *stream;
        int error = pstream_accept(raft->listener, &stream);
        if (!error) {
            raft_add_conn(raft, jsonrpc_session_open_unreliably(
                              jsonrpc_open(stream), DSCP_DEFAULT), NULL,
                          true);
        } else if (error != EAGAIN) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "%s: accept failed: %s",
                         pstream_get_name(raft->listener),
                         ovs_strerror(error));
        }
    }

    /* Run RPCs for all open sessions. */
    struct raft_conn *conn;
    LIST_FOR_EACH (conn, list_node, &raft->conns) {
        raft_conn_run(raft, conn);
    }

    /* Close unneeded sessions. */
    struct raft_conn *next;
    LIST_FOR_EACH_SAFE (conn, next, list_node, &raft->conns) {
        if (!raft_conn_should_stay_open(raft, conn)) {
            raft_conn_close(conn);
        }
    }

    /* Open needed sessions. */
    struct raft_server *server;
    HMAP_FOR_EACH (server, hmap_node, &raft->servers) {
        raft_open_conn(raft, server->address, &server->sid);
    }
    if (raft->joining) {
        const char *address;
        SSET_FOR_EACH (address, &raft->remote_addresses) {
            raft_open_conn(raft, address, NULL);
        }
    }

    if (!raft->joining && time_msec() >= raft->election_timeout) {
        raft_start_election(raft, false);
    }

    if (raft->leaving && time_msec() >= raft->leave_timeout) {
        raft_send_remove_server_requests(raft);
    }

    if (raft->joining && time_msec() >= raft->join_timeout) {
        raft->join_timeout = time_msec() + 1000;
        LIST_FOR_EACH (conn, list_node, &raft->conns) {
            raft_send_add_server_request(raft, conn);
        }
    }

    if (time_msec() >= raft->ping_timeout) {
        if (raft->role == RAFT_LEADER) {
            raft_send_heartbeats(raft);
        } else {
            long long int now = time_msec();
            struct raft_command *cmd, *next_cmd;
            HMAP_FOR_EACH_SAFE (cmd, next_cmd, hmap_node, &raft->commands) {
                if (cmd->timestamp
                    && now - cmd->timestamp > ELECTION_BASE_MSEC) {
                    raft_command_complete(raft, cmd, RAFT_CMD_TIMEOUT);
                }
            }
        }
        raft->ping_timeout = time_msec() + PING_TIME_MSEC;
    }

    /* Do this only at the end; if we did it as soon as we set raft->left or
     * raft->failed in handling the RemoveServerReply, then it could easily
     * cause references to freed memory in RPC sessions, etc. */
    if (raft->left || raft->failed) {
        raft_close__(raft);
    }
}

static void
raft_wait_session(struct jsonrpc_session *js)
{
    if (js) {
        jsonrpc_session_wait(js);
        jsonrpc_session_recv_wait(js);
    }
}

/* Causes the next call to poll_block() to wake up when 'raft' needs to do
 * something. */
void
raft_wait(struct raft *raft)
{
    if (raft->left || raft->failed) {
        return;
    }

    raft_waiters_wait(raft);

    if (raft->listener) {
        pstream_wait(raft->listener);
    } else {
        poll_timer_wait_until(raft->listen_backoff);
    }

    struct raft_conn *conn;
    LIST_FOR_EACH (conn, list_node, &raft->conns) {
        raft_wait_session(conn->js);
    }

    if (!raft->joining) {
        poll_timer_wait_until(raft->election_timeout);
    } else {
        poll_timer_wait_until(raft->join_timeout);
    }
    if (raft->leaving) {
        poll_timer_wait_until(raft->leave_timeout);
    }
    if (raft->role == RAFT_LEADER || !hmap_is_empty(&raft->commands)) {
        poll_timer_wait_until(raft->ping_timeout);
    }
}

static struct raft_waiter *
raft_waiter_create(struct raft *raft, enum raft_waiter_type type,
                   bool start_commit)
{
    struct raft_waiter *w = xzalloc(sizeof *w);
    ovs_list_push_back(&raft->waiters, &w->list_node);
    w->commit_ticket = start_commit ? ovsdb_log_commit_start(raft->log) : 0;
    w->type = type;
    return w;
}

/* Returns a human-readable representation of 'status' (or NULL if 'status' is
 * invalid). */
const char *
raft_command_status_to_string(enum raft_command_status status)
{
    switch (status) {
    case RAFT_CMD_INCOMPLETE:
        return "operation still in progress";
    case RAFT_CMD_SUCCESS:
        return "success";
    case RAFT_CMD_NOT_LEADER:
        return "not leader";
    case RAFT_CMD_BAD_PREREQ:
        return "prerequisite check failed";
    case RAFT_CMD_LOST_LEADERSHIP:
        return "lost leadership";
    case RAFT_CMD_SHUTDOWN:
        return "server shutdown";
    case RAFT_CMD_IO_ERROR:
        return "I/O error";
    case RAFT_CMD_TIMEOUT:
        return "timeout";
    default:
        return NULL;
    }
}

/* Converts human-readable status in 's' into status code in '*statusp'.
 * Returns true if successful, false if 's' is unknown. */
bool
raft_command_status_from_string(const char *s,
                                enum raft_command_status *statusp)
{
    for (enum raft_command_status status = 0; ; status++) {
        const char *s2 = raft_command_status_to_string(status);
        if (!s2) {
            *statusp = 0;
            return false;
        } else if (!strcmp(s, s2)) {
            *statusp = status;
            return true;
        }
    }
}

static const struct uuid *
raft_get_eid(const struct raft *raft, uint64_t index)
{
    for (; index >= raft->log_start; index--) {
        const struct raft_entry *e = raft_get_entry(raft, index);
        if (e->data) {
            return &e->eid;
        }
    }
    return &raft->snap.eid;
}

static const struct uuid *
raft_current_eid(const struct raft *raft)
{
    return raft_get_eid(raft, raft->log_end - 1);
}

static struct raft_command *
raft_command_create_completed(enum raft_command_status status)
{
    ovs_assert(status != RAFT_CMD_INCOMPLETE);

    struct raft_command *cmd = xzalloc(sizeof *cmd);
    cmd->n_refs = 1;
    cmd->status = status;
    return cmd;
}

static struct raft_command *
raft_command_create_incomplete(struct raft *raft, uint64_t index)
{
    struct raft_command *cmd = xzalloc(sizeof *cmd);
    cmd->n_refs = 2;            /* One for client, one for raft->commands. */
    cmd->index = index;
    cmd->status = RAFT_CMD_INCOMPLETE;
    hmap_insert(&raft->commands, &cmd->hmap_node, cmd->index);
    return cmd;
}

static struct raft_command * OVS_WARN_UNUSED_RESULT
raft_command_initiate(struct raft *raft,
                      const struct json *data, const struct json *servers,
                      const struct uuid *eid)
{
    /* Write to local log. */
    uint64_t index = raft->log_end;
    if (!raft_handle_write_error(
            raft, raft_write_entry(
                raft, raft->term, json_nullable_clone(data), eid,
                json_nullable_clone(servers)))) {
        return raft_command_create_completed(RAFT_CMD_IO_ERROR);
    }

    struct raft_command *cmd = raft_command_create_incomplete(raft, index);
    if (eid) {
        cmd->eid = *eid;
    }

    raft_waiter_create(raft, RAFT_W_ENTRY, true)->entry.index = cmd->index;

    /* Write to remote logs. */
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (!uuid_equals(&s->sid, &raft->sid) && s->next_index == index) {
            raft_send_append_request(raft, s, 1, "execute command");
            s->next_index++;
        }
    }

    return cmd;
}

static struct raft_command * OVS_WARN_UNUSED_RESULT
raft_command_execute__(struct raft *raft,
                       const struct json *data, const struct json *servers,
                       const struct uuid *prereq, struct uuid *result)
{
    if (raft->joining || raft->leaving || raft->left || raft->failed) {
        return raft_command_create_completed(RAFT_CMD_SHUTDOWN);
    }

    if (raft->role != RAFT_LEADER) {
        /* Consider proxying the command to the leader.  We can only do that if
         * we know the leader and the command does not change the set of
         * servers.  We do not proxy commands without prerequisites, even
         * though we could, because in an OVSDB context a log entry doesn't
         * make sense without context. */
        if (servers || !data
            || raft->role != RAFT_FOLLOWER || uuid_is_zero(&raft->leader_sid)
            || !prereq) {
            return raft_command_create_completed(RAFT_CMD_NOT_LEADER);
        }
    }

    struct uuid eid = data ? uuid_random() : UUID_ZERO;
    if (result) {
        *result = eid;
    }

    if (raft->role != RAFT_LEADER) {
        const union raft_rpc rpc = {
            .execute_command_request = {
                .common = {
                    .type = RAFT_RPC_EXECUTE_COMMAND_REQUEST,
                    .sid = raft->leader_sid,
                },
                .data = CONST_CAST(struct json *, data),
                .prereq = *prereq,
                .result = eid,
            }
        };
        if (!raft_send(raft, &rpc)) {
            /* Couldn't send command, so it definitely failed. */
            return raft_command_create_completed(RAFT_CMD_NOT_LEADER);
        }

        struct raft_command *cmd = raft_command_create_incomplete(raft, 0);
        cmd->timestamp = time_msec();
        cmd->eid = eid;
        return cmd;
    }

    const struct uuid *current_eid = raft_current_eid(raft);
    if (prereq && !uuid_equals(prereq, current_eid)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_INFO_RL(&rl, "current entry eid "UUID_FMT" does not match "
                     "prerequisite "UUID_FMT,
                     UUID_ARGS(current_eid), UUID_ARGS(prereq));
        return raft_command_create_completed(RAFT_CMD_BAD_PREREQ);
    }

    return raft_command_initiate(raft, data, servers, &eid);
}

/* Initiates appending a log entry to 'raft'.  The log entry consists of 'data'
 * and, if 'prereq' is nonnull, it is only added to the log if the previous
 * entry in the log has entry ID 'prereq'.  If 'result' is nonnull, it is
 * populated with the entry ID for the new log entry.
 *
 * Returns a "struct raft_command" that may be used to track progress adding
 * the log entry.  The caller must eventually free the returned structure, with
 * raft_command_unref(). */
struct raft_command * OVS_WARN_UNUSED_RESULT
raft_command_execute(struct raft *raft, const struct json *data,
                     const struct uuid *prereq, struct uuid *result)
{
    return raft_command_execute__(raft, data, NULL, prereq, result);
}

/* Returns the status of 'cmd'. */
enum raft_command_status
raft_command_get_status(const struct raft_command *cmd)
{
    ovs_assert(cmd->n_refs > 0);
    return cmd->status;
}

/* Returns the index of the log entry at which 'cmd' was committed.
 *
 * This function works only with successful commands. */
uint64_t
raft_command_get_commit_index(const struct raft_command *cmd)
{
    ovs_assert(cmd->n_refs > 0);
    ovs_assert(cmd->status == RAFT_CMD_SUCCESS);
    return cmd->index;
}

/* Frees 'cmd'. */
void
raft_command_unref(struct raft_command *cmd)
{
    if (cmd) {
        ovs_assert(cmd->n_refs > 0);
        if (!--cmd->n_refs) {
            free(cmd);
        }
    }
}

/* Causes poll_block() to wake up when 'cmd' has status to report. */
void
raft_command_wait(const struct raft_command *cmd)
{
    if (cmd->status != RAFT_CMD_INCOMPLETE) {
        poll_immediate_wake();
    }
}

static void
raft_command_complete(struct raft *raft,
                      struct raft_command *cmd,
                      enum raft_command_status status)
{
    if (!uuid_is_zero(&cmd->sid)) {
        uint64_t commit_index = status == RAFT_CMD_SUCCESS ? cmd->index : 0;
        raft_send_execute_command_reply(raft, &cmd->sid, &cmd->eid, status,
                                        commit_index);
    }

    ovs_assert(cmd->status == RAFT_CMD_INCOMPLETE);
    ovs_assert(cmd->n_refs > 0);
    hmap_remove(&raft->commands, &cmd->hmap_node);
    cmd->status = status;
    raft_command_unref(cmd);
}

static void
raft_complete_all_commands(struct raft *raft, enum raft_command_status status)
{
    struct raft_command *cmd, *next;
    HMAP_FOR_EACH_SAFE (cmd, next, hmap_node, &raft->commands) {
        raft_command_complete(raft, cmd, status);
    }
}

static struct raft_command *
raft_find_command_by_index(struct raft *raft, uint64_t index)
{
    struct raft_command *cmd;

    HMAP_FOR_EACH_IN_BUCKET (cmd, hmap_node, index, &raft->commands) {
        if (cmd->index == index) {
            return cmd;
        }
    }
    return NULL;
}

static struct raft_command *
raft_find_command_by_eid(struct raft *raft, const struct uuid *eid)
{
    struct raft_command *cmd;

    HMAP_FOR_EACH (cmd, hmap_node, &raft->commands) {
        if (uuid_equals(&cmd->eid, eid)) {
            return cmd;
        }
    }
    return NULL;
}

#define RAFT_RPC(ENUM, NAME) \
    static void raft_handle_##NAME(struct raft *, const struct raft_##NAME *);
RAFT_RPC_TYPES
#undef RAFT_RPC

static void
raft_handle_hello_request(struct raft *raft OVS_UNUSED,
                          const struct raft_hello_request *hello OVS_UNUSED)
{
}

/* 'sid' is the server being added. */
static void
raft_send_add_server_reply__(struct raft *raft, const struct uuid *sid,
                             const char *address,
                             bool success, const char *comment)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    if (!VLOG_DROP_INFO(&rl)) {
        struct ds s = DS_EMPTY_INITIALIZER;
        char buf[SID_LEN + 1];
        ds_put_format(&s, "adding %s ("SID_FMT" at %s) "
                      "to cluster "CID_FMT" %s",
                      raft_get_nickname(raft, sid, buf, sizeof buf),
                      SID_ARGS(sid), address, CID_ARGS(&raft->cid),
                      success ? "succeeded" : "failed");
        if (comment) {
            ds_put_format(&s, " (%s)", comment);
        }
        VLOG_INFO("%s", ds_cstr(&s));
        ds_destroy(&s);
    }

    union raft_rpc rpy = {
        .add_server_reply = {
            .common = {
                .type = RAFT_RPC_ADD_SERVER_REPLY,
                .sid = *sid,
                .comment = CONST_CAST(char *, comment),
            },
            .success = success,
        }
    };

    struct sset *remote_addresses = &rpy.add_server_reply.remote_addresses;
    sset_init(remote_addresses);
    if (!raft->joining) {
        struct raft_server *s;
        HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
            if (!uuid_equals(&s->sid, &raft->sid)) {
                sset_add(remote_addresses, s->address);
            }
        }
    }

    raft_send(raft, &rpy);

    sset_destroy(remote_addresses);
}

static void
raft_send_remove_server_reply_rpc(struct raft *raft, const struct uuid *sid,
                                  bool success, const char *comment)
{
    const union raft_rpc rpy = {
        .remove_server_reply = {
            .common = {
                .type = RAFT_RPC_REMOVE_SERVER_REPLY,
                .sid = *sid,
                .comment = CONST_CAST(char *, comment),
            },
            .success = success,
        }
    };
    raft_send(raft, &rpy);
}

static void
raft_send_remove_server_reply__(struct raft *raft,
                                const struct uuid *target_sid,
                                const struct uuid *requester_sid,
                                struct unixctl_conn *requester_conn,
                                bool success, const char *comment)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "request ");
    if (!uuid_is_zero(requester_sid)) {
        char buf[SID_LEN + 1];
        ds_put_format(&s, "by %s",
                      raft_get_nickname(raft, requester_sid, buf, sizeof buf));
    } else {
        ds_put_cstr(&s, "via unixctl");
    }
    ds_put_cstr(&s, " to remove ");
    if (!requester_conn && uuid_equals(target_sid, requester_sid)) {
        ds_put_cstr(&s, "itself");
    } else {
        char buf[SID_LEN + 1];
        ds_put_cstr(&s, raft_get_nickname(raft, target_sid, buf, sizeof buf));
    }
    ds_put_format(&s, " from cluster "CID_FMT" %s",
                  CID_ARGS(&raft->cid),
                  success ? "succeeded" : "failed");
    if (comment) {
        ds_put_format(&s, " (%s)", comment);
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    VLOG_INFO_RL(&rl, "%s", ds_cstr(&s));

    /* Send RemoveServerReply to the requester (which could be a server or a
     * unixctl connection.  Also always send it to the removed server; this
     * allows it to be sure that it's really removed and update its log and
     * disconnect permanently.  */
    if (!uuid_is_zero(requester_sid)) {
        raft_send_remove_server_reply_rpc(raft, requester_sid,
                                          success, comment);
    }
    if (!uuid_equals(requester_sid, target_sid)) {
        raft_send_remove_server_reply_rpc(raft, target_sid, success, comment);
    }
    if (requester_conn) {
        if (success) {
            unixctl_command_reply(requester_conn, ds_cstr(&s));
        } else {
            unixctl_command_reply_error(requester_conn, ds_cstr(&s));
        }
    }

    ds_destroy(&s);
}

static void
raft_send_add_server_reply(struct raft *raft,
                           const struct raft_add_server_request *rq,
                           bool success, const char *comment)
{
    return raft_send_add_server_reply__(raft, &rq->common.sid, rq->address,
                                        success, comment);
}

static void
raft_send_remove_server_reply(struct raft *raft,
                              const struct raft_remove_server_request *rq,
                              bool success, const char *comment)
{
    return raft_send_remove_server_reply__(raft, &rq->sid, &rq->common.sid,
                                           rq->requester_conn, success,
                                           comment);
}

static void
raft_become_follower(struct raft *raft)
{
    raft->leader_sid = UUID_ZERO;
    if (raft->role == RAFT_FOLLOWER) {
        return;
    }

    raft->role = RAFT_FOLLOWER;
    raft_reset_timer(raft);

    /* Notify clients about lost leadership.
     *
     * We do not reverse our changes to 'raft->servers' because the new
     * configuration is already part of the log.  Possibly the configuration
     * log entry will not be committed, but until we know that we must use the
     * new configuration.  Our AppendEntries processing will properly update
     * the server configuration later, if necessary. */
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->add_servers) {
        raft_send_add_server_reply__(raft, &s->sid, s->address, false,
                                     RAFT_SERVER_LOST_LEADERSHIP);
    }
    if (raft->remove_server) {
        raft_send_remove_server_reply__(raft, &raft->remove_server->sid,
                                        &raft->remove_server->requester_sid,
                                        raft->remove_server->requester_conn,
                                        false, RAFT_SERVER_LOST_LEADERSHIP);
        raft_server_destroy(raft->remove_server);
        raft->remove_server = NULL;
    }

    raft_complete_all_commands(raft, RAFT_CMD_LOST_LEADERSHIP);
}

static void
raft_send_append_request(struct raft *raft,
                         struct raft_server *peer, unsigned int n,
                         const char *comment)
{
    ovs_assert(raft->role == RAFT_LEADER);

    const union raft_rpc rq = {
        .append_request = {
            .common = {
                .type = RAFT_RPC_APPEND_REQUEST,
                .sid = peer->sid,
                .comment = CONST_CAST(char *, comment),
            },
            .term = raft->term,
            .prev_log_index = peer->next_index - 1,
            .prev_log_term = (peer->next_index - 1 >= raft->log_start
                              ? raft->entries[peer->next_index - 1
                                              - raft->log_start].term
                              : raft->snap.term),
            .leader_commit = raft->commit_index,
            .entries = &raft->entries[peer->next_index - raft->log_start],
            .n_entries = n,
        },
    };
    raft_send(raft, &rq);
}

static void
raft_send_heartbeats(struct raft *raft)
{
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (!uuid_equals(&raft->sid, &s->sid)) {
            raft_send_append_request(raft, s, 0, "heartbeat");
        }
    }

    /* Send anyone waiting for a command to complete a ping to let them
     * know we're still working on it. */
    struct raft_command *cmd;
    HMAP_FOR_EACH (cmd, hmap_node, &raft->commands) {
        if (!uuid_is_zero(&cmd->sid)) {
            raft_send_execute_command_reply(raft, &cmd->sid,
                                            &cmd->eid,
                                            RAFT_CMD_INCOMPLETE, 0);
        }
    }
}

/* Initializes the fields in 's' that represent the leader's view of the
 * server. */
static void
raft_server_init_leader(struct raft *raft, struct raft_server *s)
{
    s->next_index = raft->log_end;
    s->match_index = 0;
    s->phase = RAFT_PHASE_STABLE;
}

static void
raft_become_leader(struct raft *raft)
{
    raft_complete_all_commands(raft, RAFT_CMD_LOST_LEADERSHIP);

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    VLOG_INFO_RL(&rl, "term %"PRIu64": elected leader by %d+ of "
                 "%"PRIuSIZE" servers", raft->term,
                 raft->n_votes, hmap_count(&raft->servers));

    ovs_assert(raft->role != RAFT_LEADER);
    raft->role = RAFT_LEADER;
    raft->leader_sid = raft->sid;
    raft->election_timeout = LLONG_MAX;
    raft->ping_timeout = time_msec() + PING_TIME_MSEC;

    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        raft_server_init_leader(raft, s);
    }

    raft_update_our_match_index(raft, raft->log_end - 1);
    raft_send_heartbeats(raft);

    /* Write the fact that we are leader to the log.  This is not used by the
     * algorithm (although it could be, for quick restart), but it is used for
     * offline analysis to check for conformance with the properties that Raft
     * guarantees. */
    struct raft_record r = {
        .type = RAFT_REC_LEADER,
        .term = raft->term,
        .sid = raft->sid,
    };
    ignore(ovsdb_log_write_and_free(raft->log, raft_record_to_json(&r)));

    /* Initiate a no-op commit.  Otherwise we might never find out what's in
     * the log.  See section 6.4 item 1:
     *
     *     The Leader Completeness Property guarantees that a leader has all
     *     committed entries, but at the start of its term, it may not know
     *     which those are.  To find out, it needs to commit an entry from its
     *     term.  Raft handles this by having each leader commit a blank no-op
     *     entry into the log at the start of its term.  As soon as this no-op
     *     entry is committed, the leader’s commit index will be at least as
     *     large as any other servers’ during its term.
     */
    raft_command_unref(raft_command_execute__(raft, NULL, NULL, NULL, NULL));
}

/* Processes term 'term' received as part of RPC 'common'.  Returns true if the
 * caller should continue processing the RPC, false if the caller should reject
 * it due to a stale term. */
static bool
raft_receive_term__(struct raft *raft, const struct raft_rpc_common *common,
                    uint64_t term)
{
    /* Section 3.3 says:
     *
     *     Current terms are exchanged whenever servers communicate; if one
     *     server’s current term is smaller than the other’s, then it updates
     *     its current term to the larger value.  If a candidate or leader
     *     discovers that its term is out of date, it immediately reverts to
     *     follower state.  If a server receives a request with a stale term
     *     number, it rejects the request.
     */
    if (term > raft->term) {
        if (!raft_set_term(raft, term, NULL)) {
            /* Failed to update the term to 'term'. */
            return false;
        }
        raft_become_follower(raft);
    } else if (term < raft->term) {
        char buf[SID_LEN + 1];
        VLOG_INFO("rejecting term %"PRIu64" < current term %"PRIu64" received "
                  "in %s message from server %s",
                  term, raft->term,
                  raft_rpc_type_to_string(common->type),
                  raft_get_nickname(raft, &common->sid, buf, sizeof buf));
        return false;
    }
    return true;
}

static void
raft_get_servers_from_log(struct raft *raft, enum vlog_level level)
{
    const struct json *servers_json = raft->snap.servers;
    for (uint64_t index = raft->log_end - 1; index >= raft->log_start;
         index--) {
        struct raft_entry *e = &raft->entries[index - raft->log_start];
        if (e->servers) {
            servers_json = e->servers;
            break;
        }
    }

    struct hmap servers;
    struct ovsdb_error *error = raft_servers_from_json(servers_json, &servers);
    ovs_assert(!error);
    raft_set_servers(raft, &servers, level);
    raft_servers_destroy(&servers);
}

/* Truncates the log, so that raft->log_end becomes 'new_end'.
 *
 * Doesn't write anything to disk.  In theory, we could truncate the on-disk
 * log file, but we don't have the right information to know how long it should
 * be.  What we actually do is to append entries for older indexes to the
 * on-disk log; when we re-read it later, these entries truncate the log.
 *
 * Returns true if any of the removed log entries were server configuration
 * entries, false otherwise. */
static bool
raft_truncate(struct raft *raft, uint64_t new_end)
{
    ovs_assert(new_end >= raft->log_start);
    if (raft->log_end > new_end) {
        char buf[SID_LEN + 1];
        VLOG_INFO("%s truncating %"PRIu64 " entries from end of log",
                  raft_get_nickname(raft, &raft->sid, buf, sizeof buf),
                  raft->log_end - new_end);
    }

    bool servers_changed = false;
    while (raft->log_end > new_end) {
        struct raft_entry *entry = &raft->entries[--raft->log_end
                                                  - raft->log_start];
        if (entry->servers) {
            servers_changed = true;
        }
        raft_entry_uninit(entry);
    }
    return servers_changed;
}

static const struct json *
raft_peek_next_entry(struct raft *raft, struct uuid *eid)
{
    /* Invariant: log_start - 2 <= last_applied <= commit_index < log_end. */
    ovs_assert(raft->log_start <= raft->last_applied + 2);
    ovs_assert(raft->last_applied <= raft->commit_index);
    ovs_assert(raft->commit_index < raft->log_end);

    if (raft->joining || raft->failed) {
        return NULL;
    }

    if (raft->log_start == raft->last_applied + 2) {
        *eid = raft->snap.eid;
        return raft->snap.data;
    }

    while (raft->last_applied < raft->commit_index) {
        const struct raft_entry *e = raft_get_entry(raft,
                                                    raft->last_applied + 1);
        if (e->data) {
            *eid = e->eid;
            return e->data;
        }
        raft->last_applied++;
    }
    return NULL;
}

static const struct json *
raft_get_next_entry(struct raft *raft, struct uuid *eid)
{
    const struct json *data = raft_peek_next_entry(raft, eid);
    if (data) {
        raft->last_applied++;
    }
    return data;
}

static void
raft_update_commit_index(struct raft *raft, uint64_t new_commit_index)
{
    if (new_commit_index <= raft->commit_index) {
        return;
    }

    if (raft->role == RAFT_LEADER) {
        while (raft->commit_index < new_commit_index) {
            uint64_t index = ++raft->commit_index;
            const struct raft_entry *e = raft_get_entry(raft, index);
            if (e->servers) {
                raft_run_reconfigure(raft);
            }
            if (e->data) {
                struct raft_command *cmd
                    = raft_find_command_by_index(raft, index);
                if (cmd) {
                    raft_command_complete(raft, cmd, RAFT_CMD_SUCCESS);
                }
            }
        }
    } else {
        raft->commit_index = new_commit_index;
    }

    /* Write the commit index to the log.  The next time we restart, this
     * allows us to start exporting a reasonably fresh log, instead of a log
     * that only contains the snapshot. */
    struct raft_record r = {
        .type = RAFT_REC_COMMIT_INDEX,
        .commit_index = raft->commit_index,
    };
    ignore(ovsdb_log_write_and_free(raft->log, raft_record_to_json(&r)));
}

/* This doesn't use rq->entries (but it does use rq->n_entries). */
static void
raft_send_append_reply(struct raft *raft, const struct raft_append_request *rq,
                       enum raft_append_result result, const char *comment)
{
    /* Figure 3.1: "If leaderCommit > commitIndex, set commitIndex =
     * min(leaderCommit, index of last new entry)" */
    if (result == RAFT_APPEND_OK && rq->leader_commit > raft->commit_index) {
        raft_update_commit_index(
            raft, MIN(rq->leader_commit, rq->prev_log_index + rq->n_entries));
    }

    /* Send reply. */
    union raft_rpc reply = {
        .append_reply = {
            .common = {
                .type = RAFT_RPC_APPEND_REPLY,
                .sid = rq->common.sid,
                .comment = CONST_CAST(char *, comment),
            },
            .term = raft->term,
            .log_end = raft->log_end,
            .prev_log_index = rq->prev_log_index,
            .prev_log_term = rq->prev_log_term,
            .n_entries = rq->n_entries,
            .result = result,
        }
    };
    raft_send(raft, &reply);
}

/* If 'prev_log_index' exists in 'raft''s log, in term 'prev_log_term', returns
 * NULL.  Otherwise, returns an explanation for the mismatch.  */
static const char *
match_index_and_term(const struct raft *raft,
                     uint64_t prev_log_index, uint64_t prev_log_term)
{
    if (prev_log_index < raft->log_start - 1) {
        return "mismatch before start of log";
    } else if (prev_log_index == raft->log_start - 1) {
        if (prev_log_term != raft->snap.term) {
            return "prev_term mismatch";
        }
    } else if (prev_log_index < raft->log_end) {
        if (raft->entries[prev_log_index - raft->log_start].term
            != prev_log_term) {
            return "term mismatch";
        }
    } else {
        /* prev_log_index >= raft->log_end */
        return "mismatch past end of log";
    }
    return NULL;
}

static void
raft_handle_append_entries(struct raft *raft,
                           const struct raft_append_request *rq,
                           uint64_t prev_log_index, uint64_t prev_log_term,
                           const struct raft_entry *entries,
                           unsigned int n_entries)
{
    /* Section 3.5: "When sending an AppendEntries RPC, the leader includes
     * the index and term of the entry in its log that immediately precedes
     * the new entries. If the follower does not find an entry in its log
     * with the same index and term, then it refuses the new entries." */
    const char *mismatch = match_index_and_term(raft, prev_log_index,
                                                prev_log_term);
    if (mismatch) {
        VLOG_INFO("rejecting append_request because previous entry "
                  "%"PRIu64",%"PRIu64" not in local log (%s)",
                  prev_log_term, prev_log_index, mismatch);
        raft_send_append_reply(raft, rq, RAFT_APPEND_INCONSISTENCY, mismatch);
        return;
    }

    /* Figure 3.1: "If an existing entry conflicts with a new one (same
     * index but different terms), delete the existing entry and all that
     * follow it." */
    unsigned int i;
    bool servers_changed = false;
    for (i = 0; ; i++) {
        if (i >= n_entries) {
            /* No change. */
            if (rq->common.comment
                && !strcmp(rq->common.comment, "heartbeat")) {
                raft_send_append_reply(raft, rq, RAFT_APPEND_OK, "heartbeat");
            } else {
                raft_send_append_reply(raft, rq, RAFT_APPEND_OK, "no change");
            }
            return;
        }

        uint64_t log_index = (prev_log_index + 1) + i;
        if (log_index >= raft->log_end) {
            break;
        }
        if (raft->entries[log_index - raft->log_start].term
            != entries[i].term) {
            if (raft_truncate(raft, log_index)) {
                servers_changed = true;
            }
            break;
        }
    }

    /* Figure 3.1: "Append any entries not already in the log." */
    struct ovsdb_error *error = NULL;
    bool any_written = false;
    for (; i < n_entries; i++) {
        const struct raft_entry *e = &entries[i];
        error = raft_write_entry(raft, e->term,
                                 json_nullable_clone(e->data), &e->eid,
                                 json_nullable_clone(e->servers));
        if (error) {
            break;
        }
        any_written = true;
        if (e->servers) {
            servers_changed = true;
        }
    }

    if (any_written) {
        raft_waiter_create(raft, RAFT_W_ENTRY, true)->entry.index
            = raft->log_end - 1;
    }
    if (servers_changed) {
        /* The set of servers might have changed; check. */
        raft_get_servers_from_log(raft, VLL_INFO);
    }

    if (error) {
        char *s = ovsdb_error_to_string_free(error);
        VLOG_ERR("%s", s);
        free(s);
        raft_send_append_reply(raft, rq, RAFT_APPEND_IO_ERROR, "I/O error");
        return;
    }

    raft_send_append_reply(raft, rq, RAFT_APPEND_OK, "log updated");
}

static bool
raft_update_leader(struct raft *raft, const struct uuid *sid)
{
    if (raft->role == RAFT_LEADER) {
        char buf[SID_LEN + 1];
        VLOG_ERR("this server is leader but server %s claims to be",
                 raft_get_nickname(raft, sid, buf, sizeof buf));
        return false;
    } else if (!uuid_equals(sid, &raft->leader_sid)) {
        if (!uuid_is_zero(&raft->leader_sid)) {
            char buf1[SID_LEN + 1];
            char buf2[SID_LEN + 1];
            VLOG_ERR("leader for term %"PRIu64" changed from %s to %s",
                     raft->term,
                     raft_get_nickname(raft, &raft->leader_sid,
                                       buf1, sizeof buf1),
                     raft_get_nickname(raft, sid, buf2, sizeof buf2));
        } else {
            char buf[SID_LEN + 1];
            VLOG_INFO("server %s is leader for term %"PRIu64,
                      raft_get_nickname(raft, sid, buf, sizeof buf),
                      raft->term);
        }
        raft->leader_sid = *sid;

        /* Record the leader to the log.  This is not used by the algorithm
         * (although it could be, for quick restart), but it is used for
         * offline analysis to check for conformance with the properties
         * that Raft guarantees. */
        struct raft_record r = {
            .type = RAFT_REC_LEADER,
            .term = raft->term,
            .sid = *sid,
        };
        ignore(ovsdb_log_write_and_free(raft->log, raft_record_to_json(&r)));
    }
    return true;
}

static void
raft_handle_append_request(struct raft *raft,
                           const struct raft_append_request *rq)
{
    /* We do not check whether the server that sent the request is part of the
     * cluster.  As section 4.1 says, "A server accepts AppendEntries requests
     * from a leader that is not part of the server’s latest configuration.
     * Otherwise, a new server could never be added to the cluster (it would
     * never accept any log entries preceding the configuration entry that adds
     * the server)." */
    if (!raft_update_leader(raft, &rq->common.sid)) {
        raft_send_append_reply(raft, rq, RAFT_APPEND_INCONSISTENCY,
                               "usurped leadership");
        return;
    }
    raft_reset_timer(raft);

    /* First check for the common case, where the AppendEntries request is
     * entirely for indexes covered by 'log_start' ... 'log_end - 1', something
     * like this:
     *
     *     rq->prev_log_index
     *       | first_entry_index
     *       |   |         nth_entry_index
     *       |   |           |
     *       v   v           v
     *         +---+---+---+---+
     *       T | T | T | T | T |
     *         +---+-------+---+
     *     +---+---+---+---+
     *   T | T | T | T | T |
     *     +---+---+---+---+
     *       ^               ^
     *       |               |
     *   log_start        log_end
     * */
    uint64_t first_entry_index = rq->prev_log_index + 1;
    uint64_t nth_entry_index = rq->prev_log_index + rq->n_entries;
    if (OVS_LIKELY(first_entry_index >= raft->log_start)) {
        raft_handle_append_entries(raft, rq,
                                   rq->prev_log_index, rq->prev_log_term,
                                   rq->entries, rq->n_entries);
        return;
    }

    /* Now a series of checks for odd cases, where the AppendEntries request
     * extends earlier than the beginning of our log, into the log entries
     * discarded by the most recent snapshot. */

    /*
     * Handle the case where the indexes covered by rq->entries[] are entirely
     * disjoint with 'log_start - 1' ... 'log_end - 1', as shown below.  So,
     * everything in the AppendEntries request must already have been
     * committed, and we might as well return true.
     *
     *     rq->prev_log_index
     *       | first_entry_index
     *       |   |         nth_entry_index
     *       |   |           |
     *       v   v           v
     *         +---+---+---+---+
     *       T | T | T | T | T |
     *         +---+-------+---+
     *                             +---+---+---+---+
     *                           T | T | T | T | T |
     *                             +---+---+---+---+
     *                               ^               ^
     *                               |               |
     *                           log_start        log_end
     */
    if (nth_entry_index < raft->log_start - 1) {
        raft_send_append_reply(raft, rq, RAFT_APPEND_OK,
                               "append before log start");
        return;
    }

    /*
     * Handle the case where the last entry in rq->entries[] has the same index
     * as 'log_start - 1', so we can compare their terms:
     *
     *     rq->prev_log_index
     *       | first_entry_index
     *       |   |         nth_entry_index
     *       |   |           |
     *       v   v           v
     *         +---+---+---+---+
     *       T | T | T | T | T |
     *         +---+-------+---+
     *                         +---+---+---+---+
     *                       T | T | T | T | T |
     *                         +---+---+---+---+
     *                           ^               ^
     *                           |               |
     *                       log_start        log_end
     *
     * There's actually a sub-case where rq->n_entries == 0, in which we
     * compare rq->prev_term:
     *
     *     rq->prev_log_index
     *       |
     *       |
     *       |
     *       v
     *       T
     *
     *         +---+---+---+---+
     *       T | T | T | T | T |
     *         +---+---+---+---+
     *           ^               ^
     *           |               |
     *       log_start        log_end
     */
    if (nth_entry_index == raft->log_start - 1) {
        if (rq->n_entries
            ? raft->snap.term == rq->entries[rq->n_entries - 1].term
            : raft->snap.term == rq->prev_log_term) {
            raft_send_append_reply(raft, rq, RAFT_APPEND_OK, "no change");
        } else {
            raft_send_append_reply(raft, rq, RAFT_APPEND_INCONSISTENCY,
                                   "term mismatch");
        }
        return;
    }

    /*
     * We now know that the data in rq->entries[] overlaps the data in
     * raft->entries[], as shown below, with some positive 'ofs':
     *
     *     rq->prev_log_index
     *       | first_entry_index
     *       |   |             nth_entry_index
     *       |   |               |
     *       v   v               v
     *         +---+---+---+---+---+
     *       T | T | T | T | T | T |
     *         +---+-------+---+---+
     *                     +---+---+---+---+
     *                   T | T | T | T | T |
     *                     +---+---+---+---+
     *                       ^               ^
     *                       |               |
     *                   log_start        log_end
     *
     *         |<-- ofs -->|
     *
     * We transform this into the following by trimming the first 'ofs'
     * elements off of rq->entries[], ending up with the following.  Notice how
     * we retain the term but not the data for rq->entries[ofs - 1]:
     *
     *                  first_entry_index + ofs - 1
     *                   | first_entry_index + ofs
     *                   |   |  nth_entry_index + ofs
     *                   |   |   |
     *                   v   v   v
     *                     +---+---+
     *                   T | T | T |
     *                     +---+---+
     *                     +---+---+---+---+
     *                   T | T | T | T | T |
     *                     +---+---+---+---+
     *                       ^               ^
     *                       |               |
     *                   log_start        log_end
     */
    uint64_t ofs = raft->log_start - first_entry_index;
    raft_handle_append_entries(raft, rq,
                               raft->log_start - 1, rq->entries[ofs - 1].term,
                               &rq->entries[ofs], rq->n_entries - ofs);
}

/* Returns true if 'raft' has another log entry or snapshot to read. */
bool
raft_has_next_entry(const struct raft *raft_)
{
    struct raft *raft = CONST_CAST(struct raft *, raft_);
    struct uuid eid;
    return raft_peek_next_entry(raft, &eid) != NULL;
}

/* Returns the next log entry or snapshot from 'raft', or NULL if there are
 * none left to read.  Stores the entry ID of the log entry in '*eid'.  Stores
 * true in '*is_snapshot' if the returned data is a snapshot, false if it is a
 * log entry. */
const struct json *
raft_next_entry(struct raft *raft, struct uuid *eid, bool *is_snapshot)
{
    const struct json *data = raft_get_next_entry(raft, eid);
    *is_snapshot = data == raft->snap.data;
    return data;
}

/* Returns the log index of the last-read snapshot or log entry. */
uint64_t
raft_get_applied_index(const struct raft *raft)
{
    return raft->last_applied;
}

/* Returns the log index of the last snapshot or log entry that is available to
 * be read. */
uint64_t
raft_get_commit_index(const struct raft *raft)
{
    return raft->commit_index;
}

static struct raft_server *
raft_find_peer(struct raft *raft, const struct uuid *uuid)
{
    struct raft_server *s = raft_find_server(raft, uuid);
    return s && !uuid_equals(&raft->sid, &s->sid) ? s : NULL;
}

static struct raft_server *
raft_find_new_server(struct raft *raft, const struct uuid *uuid)
{
    return raft_server_find(&raft->add_servers, uuid);
}

/* Figure 3.1: "If there exists an N such that N > commitIndex, a
 * majority of matchIndex[i] >= N, and log[N].term == currentTerm, set
 * commitIndex = N (sections 3.5 and 3.6)." */
static void
raft_consider_updating_commit_index(struct raft *raft)
{
    /* This loop cannot just bail out when it comes across a log entry that
     * does not match the criteria.  For example, Figure 3.7(d2) shows a
     * case where the log entry for term 2 cannot be committed directly
     * (because it is not for the current term) but it can be committed as
     * a side effect of commit the entry for term 4 (the current term).
     * XXX Is there a more efficient way to do this? */
    ovs_assert(raft->role == RAFT_LEADER);

    uint64_t new_commit_index = raft->commit_index;
    for (uint64_t idx = MAX(raft->commit_index + 1, raft->log_start);
         idx < raft->log_end; idx++) {
        if (raft->entries[idx - raft->log_start].term == raft->term) {
            size_t count = 0;
            struct raft_server *s2;
            HMAP_FOR_EACH (s2, hmap_node, &raft->servers) {
                if (s2->match_index >= idx) {
                    count++;
                }
            }
            if (count > hmap_count(&raft->servers) / 2) {
                VLOG_DBG("index %"PRIu64" committed to %"PRIuSIZE" servers, "
                          "applying", idx, count);
                new_commit_index = idx;
            }
        }
    }
    raft_update_commit_index(raft, new_commit_index);
}

static void
raft_update_match_index(struct raft *raft, struct raft_server *s,
                        uint64_t min_index)
{
    ovs_assert(raft->role == RAFT_LEADER);
    if (min_index > s->match_index) {
        s->match_index = min_index;
        raft_consider_updating_commit_index(raft);
    }
}

static void
raft_update_our_match_index(struct raft *raft, uint64_t min_index)
{
    raft_update_match_index(raft, raft_find_server(raft, &raft->sid),
                            min_index);
}

static void
raft_send_install_snapshot_request(struct raft *raft,
                                   const struct raft_server *s,
                                   const char *comment)
{
    union raft_rpc rpc = {
        .install_snapshot_request = {
            .common = {
                .type = RAFT_RPC_INSTALL_SNAPSHOT_REQUEST,
                .sid = s->sid,
                .comment = CONST_CAST(char *, comment),
            },
            .term = raft->term,
            .last_index = raft->log_start - 1,
            .last_term = raft->snap.term,
            .last_servers = raft->snap.servers,
            .last_eid = raft->snap.eid,
            .data = raft->snap.data,
        }
    };
    raft_send(raft, &rpc);
}

static void
raft_handle_append_reply(struct raft *raft,
                         const struct raft_append_reply *rpy)
{
    if (raft->role != RAFT_LEADER) {
        VLOG_INFO("rejected append_reply (not leader)");
        return;
    }

    /* Most commonly we'd be getting an AppendEntries reply from a configured
     * server (e.g. a peer), but we can also get them from servers in the
     * process of being added. */
    struct raft_server *s = raft_find_peer(raft, &rpy->common.sid);
    if (!s) {
        s = raft_find_new_server(raft, &rpy->common.sid);
        if (!s) {
            VLOG_INFO("rejected append_reply from unknown server "SID_FMT,
                      SID_ARGS(&rpy->common.sid));
            return;
        }
    }

    if (rpy->result == RAFT_APPEND_OK) {
        /* Figure 3.1: "If successful, update nextIndex and matchIndex for
         * follower (section 3.5)." */
        uint64_t min_index = rpy->prev_log_index + rpy->n_entries + 1;
        if (s->next_index < min_index) {
            s->next_index = min_index;
        }
        raft_update_match_index(raft, s, min_index - 1);
    } else {
        /* Figure 3.1: "If AppendEntries fails because of log inconsistency,
         * decrement nextIndex and retry (section 3.5)."
         *
         * We also implement the optimization suggested in section 4.2.1:
         * "Various approaches can make nextIndex converge to its correct value
         * more quickly, including those described in Chapter 3. The simplest
         * approach to solving this particular problem of adding a new server,
         * however, is to have followers return the length of their logs in the
         * AppendEntries response; this allows the leader to cap the follower’s
         * nextIndex accordingly." */
        s->next_index = (s->next_index > 0
                         ? MIN(s->next_index - 1, rpy->log_end)
                         : 0);

        if (rpy->result == RAFT_APPEND_IO_ERROR) {
            /* Append failed but not because of a log inconsistency.  Because
             * of the I/O error, there's no point in re-sending the append
             * immediately. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_INFO_RL(&rl, "%s reported I/O error", s->nickname);
            return;
        }
    }

    /*
     * Our behavior here must depend on the value of next_index relative to
     * log_start and log_end.  There are three cases:
     *
     *        Case 1       |    Case 2     |      Case 3
     *   <---------------->|<------------->|<------------------>
     *                     |               |
     *
     *                     +---+---+---+---+
     *                   T | T | T | T | T |
     *                     +---+---+---+---+
     *                       ^               ^
     *                       |               |
     *                   log_start        log_end
     */
    if (s->next_index < raft->log_start) {
        /* Case 1. */
        raft_send_install_snapshot_request(raft, s, NULL);
    } else if (s->next_index < raft->log_end) {
        /* Case 2. */
        raft_send_append_request(raft, s, 1, NULL);
    } else {
        /* Case 3. */
        if (s->phase == RAFT_PHASE_CATCHUP) {
            s->phase = RAFT_PHASE_CAUGHT_UP;
            raft_run_reconfigure(raft);
        }
    }
}

static bool
raft_should_suppress_disruptive_server(struct raft *raft,
                                       const union raft_rpc *rpc)
{
    if (rpc->type != RAFT_RPC_VOTE_REQUEST) {
        return false;
    }

    /* Section 4.2.3 "Disruptive Servers" says:
     *
     *    ...if a server receives a RequestVote request within the minimum
     *    election timeout of hearing from a current leader, it does not update
     *    its term or grant its vote...
     *
     *    ...This change conflicts with the leadership transfer mechanism as
     *    described in Chapter 3, in which a server legitimately starts an
     *    election without waiting an election timeout.  In that case,
     *    RequestVote messages should be processed by other servers even when
     *    they believe a current cluster leader exists.  Those RequestVote
     *    requests can include a special flag to indicate this behavior (“I
     *    have permission to disrupt the leader--it told me to!”).
     *
     * This clearly describes how the followers should act, but not the leader.
     * We just ignore vote requests that arrive at a current leader.  This
     * seems to be fairly safe, since a majority other than the current leader
     * can still elect a new leader and the first AppendEntries from that new
     * leader will depose the current leader. */
    const struct raft_vote_request *rq = raft_vote_request_cast(rpc);
    if (rq->leadership_transfer) {
        return false;
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    long long int now = time_msec();
    switch (raft->role) {
    case RAFT_LEADER:
        VLOG_WARN_RL(&rl, "ignoring vote request received as leader");
        return true;

    case RAFT_FOLLOWER:
        if (now < raft->election_base + ELECTION_BASE_MSEC) {
            VLOG_WARN_RL(&rl, "ignoring vote request received after only "
                         "%lld ms (minimum election time is %d ms)",
                         now - raft->election_base, ELECTION_BASE_MSEC);
            return true;
        }
        return false;

    case RAFT_CANDIDATE:
        return false;

    default:
        OVS_NOT_REACHED();
    }
}

/* Returns true if a reply should be sent. */
static bool
raft_handle_vote_request__(struct raft *raft,
                           const struct raft_vote_request *rq)
{
    /* Figure 3.1: "If votedFor is null or candidateId, and candidate's vote is
     * at least as up-to-date as receiver's log, grant vote (sections 3.4,
     * 3.6)." */
    if (uuid_equals(&raft->vote, &rq->common.sid)) {
        /* Already voted for this candidate in this term.  Resend vote. */
        return true;
    } else if (!uuid_is_zero(&raft->vote)) {
        /* Already voted for different candidate in this term.  Send a reply
         * saying what candidate we did vote for.  This isn't a necessary part
         * of the Raft protocol but it can make debugging easier. */
        return true;
    }

    /* Section 3.6.1: "The RequestVote RPC implements this restriction: the RPC
     * includes information about the candidate’s log, and the voter denies its
     * vote if its own log is more up-to-date than that of the candidate.  Raft
     * determines which of two logs is more up-to-date by comparing the index
     * and term of the last entries in the logs.  If the logs have last entries
     * with different terms, then the log with the later term is more
     * up-to-date.  If the logs end with the same term, then whichever log is
     * longer is more up-to-date." */
    uint64_t last_term = (raft->log_end > raft->log_start
                          ? raft->entries[raft->log_end - 1
                                          - raft->log_start].term
                          : raft->snap.term);
    if (last_term > rq->last_log_term
        || (last_term == rq->last_log_term
            && raft->log_end - 1 > rq->last_log_index)) {
        /* Our log is more up-to-date than the peer's.   Withhold vote. */
        return false;
    }

    /* Record a vote for the peer. */
    if (!raft_set_term(raft, raft->term, &rq->common.sid)) {
        return false;
    }

    raft_reset_timer(raft);

    return true;
}

static void
raft_send_vote_reply(struct raft *raft, const struct uuid *dst,
                     const struct uuid *vote)
{
    union raft_rpc rpy = {
        .vote_reply = {
            .common = {
                .type = RAFT_RPC_VOTE_REPLY,
                .sid = *dst,
            },
            .term = raft->term,
            .vote = *vote,
        },
    };
    raft_send(raft, &rpy);
}

static void
raft_handle_vote_request(struct raft *raft,
                         const struct raft_vote_request *rq)
{
    if (raft_handle_vote_request__(raft, rq)) {
        raft_send_vote_reply(raft, &rq->common.sid, &raft->vote);
    }
}

static void
raft_handle_vote_reply(struct raft *raft,
                       const struct raft_vote_reply *rpy)
{
    if (!raft_receive_term__(raft, &rpy->common, rpy->term)) {
        return;
    }

    if (raft->role != RAFT_CANDIDATE) {
        return;
    }

    struct raft_server *s = raft_find_peer(raft, &rpy->common.sid);
    if (s) {
        raft_accept_vote(raft, s, &rpy->vote);
    }
}

/* Returns true if 'raft''s log contains reconfiguration entries that have not
 * yet been committed. */
static bool
raft_has_uncommitted_configuration(const struct raft *raft)
{
    for (uint64_t i = raft->commit_index + 1; i < raft->log_end; i++) {
        ovs_assert(i >= raft->log_start);
        const struct raft_entry *e = &raft->entries[i - raft->log_start];
        if (e->servers) {
            return true;
        }
    }
    return false;
}

static void
raft_log_reconfiguration(struct raft *raft)
{
    struct json *servers_json = raft_servers_to_json(&raft->servers);
    raft_command_unref(raft_command_execute__(
                           raft, NULL, servers_json, NULL, NULL));
    json_destroy(servers_json);
}

static void
raft_run_reconfigure(struct raft *raft)
{
    ovs_assert(raft->role == RAFT_LEADER);

    /* Reconfiguration only progresses when configuration changes commit. */
    if (raft_has_uncommitted_configuration(raft)) {
        return;
    }

    /* If we were waiting for a configuration change to commit, it's done. */
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (s->phase == RAFT_PHASE_COMMITTING) {
            raft_send_add_server_reply__(raft, &s->sid, s->address,
                                         true, RAFT_SERVER_COMPLETED);
            s->phase = RAFT_PHASE_STABLE;
        }
    }
    if (raft->remove_server) {
        raft_send_remove_server_reply__(raft, &raft->remove_server->sid,
                                        &raft->remove_server->requester_sid,
                                        raft->remove_server->requester_conn,
                                        true, RAFT_SERVER_COMPLETED);
        raft_server_destroy(raft->remove_server);
        raft->remove_server = NULL;
    }

    /* If a new server is caught up, add it to the configuration.  */
    HMAP_FOR_EACH (s, hmap_node, &raft->add_servers) {
        if (s->phase == RAFT_PHASE_CAUGHT_UP) {
            /* Move 's' from 'raft->add_servers' to 'raft->servers'. */
            hmap_remove(&raft->add_servers, &s->hmap_node);
            hmap_insert(&raft->servers, &s->hmap_node, uuid_hash(&s->sid));

            /* Mark 's' as waiting for commit. */
            s->phase = RAFT_PHASE_COMMITTING;

            raft_log_reconfiguration(raft);

            /* When commit completes we'll transition to RAFT_PHASE_STABLE and
             * send a RAFT_SERVER_OK reply. */

            return;
        }
    }

    /* Remove a server, if one is scheduled for removal. */
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (s->phase == RAFT_PHASE_REMOVE) {
            hmap_remove(&raft->servers, &s->hmap_node);
            raft->remove_server = s;

            raft_log_reconfiguration(raft);

            return;
        }
    }
}

static void
raft_handle_add_server_request(struct raft *raft,
                               const struct raft_add_server_request *rq)
{
    /* Figure 4.1: "1. Reply NOT_LEADER if not leader (section 6.2)." */
    if (raft->role != RAFT_LEADER) {
        raft_send_add_server_reply(raft, rq, false, RAFT_SERVER_NOT_LEADER);
        return;
    }

    /* Check for an existing server. */
    struct raft_server *s = raft_find_server(raft, &rq->common.sid);
    if (s) {
        /* If the server is scheduled to be removed, cancel it. */
        if (s->phase == RAFT_PHASE_REMOVE) {
            s->phase = RAFT_PHASE_STABLE;
            raft_send_add_server_reply(raft, rq, false, RAFT_SERVER_CANCELED);
            return;
        }

        /* If the server is being added, then it's in progress. */
        if (s->phase != RAFT_PHASE_STABLE) {
            raft_send_add_server_reply(raft, rq,
                                       false, RAFT_SERVER_IN_PROGRESS);
        }

        /* Nothing to do--server is already part of the configuration. */
        raft_send_add_server_reply(raft, rq,
                                   true, RAFT_SERVER_ALREADY_PRESENT);
        return;
    }

    /* Check for a server being removed. */
    if (raft->remove_server
        && uuid_equals(&rq->common.sid, &raft->remove_server->sid)) {
        raft_send_add_server_reply(raft, rq, false, RAFT_SERVER_COMMITTING);
        return;
    }

    /* Check for a server already being added. */
    if (raft_find_new_server(raft, &rq->common.sid)) {
        raft_send_add_server_reply(raft, rq, false, RAFT_SERVER_IN_PROGRESS);
        return;
    }

    /* Add server to 'add_servers'. */
    s = raft_server_add(&raft->add_servers, &rq->common.sid, rq->address);
    raft_server_init_leader(raft, s);
    s->requester_sid = rq->common.sid;
    s->requester_conn = NULL;
    s->phase = RAFT_PHASE_CATCHUP;

    /* Start sending the log.  If this is the first time we've tried to add
     * this server, then this will quickly degenerate into an InstallSnapshot
     * followed by a series of AddEntries, but if it's a retry of an earlier
     * AddRequest that was interrupted (e.g. by a timeout or a loss of
     * leadership) then it will gracefully resume populating the log.
     *
     * See the last few paragraphs of section 4.2.1 for further insight. */
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    VLOG_INFO_RL(&rl,
                 "starting to add server %s ("SID_FMT" at %s) "
                 "to cluster "CID_FMT, s->nickname, SID_ARGS(&s->sid),
                 rq->address, CID_ARGS(&raft->cid));
    raft_send_append_request(raft, s, 0, "initialize new server");
}

static void
raft_handle_add_server_reply(struct raft *raft,
                             const struct raft_add_server_reply *rpy)
{
    if (!raft->joining) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "received add_server_reply even though we're "
                     "already part of the cluster");
        return;
    }

    if (rpy->success) {
        raft->joining = false;

        /* It is tempting, at this point, to check that this server is part of
         * the current configuration.  However, this is not necessarily the
         * case, because the log entry that added this server to the cluster
         * might have been committed by a majority of the cluster that does not
         * include this one.  This actually happens in testing. */
    } else {
        const char *address;
        SSET_FOR_EACH (address, &rpy->remote_addresses) {
            if (sset_add(&raft->remote_addresses, address)) {
                VLOG_INFO("%s: learned new server address for joining cluster",
                          address);
            }
        }
    }
}

/* This is called by raft_unixctl_kick() as well as via RPC. */
static void
raft_handle_remove_server_request(struct raft *raft,
                                  const struct raft_remove_server_request *rq)
{
    /* Figure 4.1: "1. Reply NOT_LEADER if not leader (section 6.2)." */
    if (raft->role != RAFT_LEADER) {
        raft_send_remove_server_reply(raft, rq, false, RAFT_SERVER_NOT_LEADER);
        return;
    }

    /* If the server to remove is currently waiting to be added, cancel it. */
    struct raft_server *target = raft_find_new_server(raft, &rq->sid);
    if (target) {
        raft_send_add_server_reply__(raft, &target->sid, target->address,
                                     false, RAFT_SERVER_CANCELED);
        hmap_remove(&raft->add_servers, &target->hmap_node);
        raft_server_destroy(target);
        return;
    }

    /* If the server isn't configured, report that. */
    target = raft_find_server(raft, &rq->sid);
    if (!target) {
        raft_send_remove_server_reply(raft, rq,
                                      true, RAFT_SERVER_ALREADY_GONE);
        return;
    }

    /* Check whether we're waiting for the addition of the server to commit. */
    if (target->phase == RAFT_PHASE_COMMITTING) {
        raft_send_remove_server_reply(raft, rq, false, RAFT_SERVER_COMMITTING);
        return;
    }

    /* Check whether the server is already scheduled for removal. */
    if (target->phase == RAFT_PHASE_REMOVE) {
        raft_send_remove_server_reply(raft, rq,
                                      false, RAFT_SERVER_IN_PROGRESS);
        return;
    }

    /* Make sure that if we remove this server then that at least one other
     * server will be left.  We don't count servers currently being added (in
     * 'add_servers') since those could fail. */
    struct raft_server *s;
    int n = 0;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (s != target && s->phase != RAFT_PHASE_REMOVE) {
            n++;
        }
    }
    if (!n) {
        raft_send_remove_server_reply(raft, rq, false, RAFT_SERVER_EMPTY);
        return;
    }

    /* Mark the server for removal. */
    target->phase = RAFT_PHASE_REMOVE;
    if (rq->requester_conn) {
        target->requester_sid = UUID_ZERO;
        unixctl_command_reply(rq->requester_conn, "started removal");
    } else {
        target->requester_sid = rq->common.sid;
        target->requester_conn = NULL;
    }

    raft_run_reconfigure(raft);
    /* Operation in progress, reply will be sent later. */
}

static void
raft_handle_remove_server_reply(struct raft *raft,
                                const struct raft_remove_server_reply *rpc)
{
    if (rpc->success) {
        VLOG_INFO(SID_FMT": finished leaving cluster "CID_FMT,
                  SID_ARGS(&raft->sid), CID_ARGS(&raft->cid));

        raft_record_note(raft, "left", "this server left the cluster");

        raft->leaving = false;
        raft->left = true;
    }
}

static bool
raft_handle_write_error(struct raft *raft, struct ovsdb_error *error)
{
    if (error && !raft->failed) {
        raft->failed = true;

        char *s = ovsdb_error_to_string_free(error);
        VLOG_WARN("%s: entering failure mode due to I/O error (%s)",
                  raft->name, s);
        free(s);
    }
    return !raft->failed;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_write_snapshot(struct raft *raft, struct ovsdb_log *log,
                    uint64_t new_log_start,
                    const struct raft_entry *new_snapshot)
{
    struct raft_header h = {
        .sid = raft->sid,
        .cid = raft->cid,
        .name = raft->name,
        .local_address = raft->local_address,
        .snap_index = new_log_start - 1,
        .snap = *new_snapshot,
    };
    struct ovsdb_error *error = ovsdb_log_write_and_free(
        log, raft_header_to_json(&h));
    if (error) {
        return error;
    }
    ovsdb_log_mark_base(raft->log);

    /* Write log records. */
    for (uint64_t index = new_log_start; index < raft->log_end; index++) {
        const struct raft_entry *e = &raft->entries[index - raft->log_start];
        struct raft_record r = {
            .type = RAFT_REC_ENTRY,
            .term = e->term,
            .entry = {
                .index = index,
                .data = e->data,
                .servers = e->servers,
                .eid = e->eid,
            },
        };
        error = ovsdb_log_write_and_free(log, raft_record_to_json(&r));
        if (error) {
            return error;
        }
    }

    /* Write term and vote (if any).
     *
     * The term is redundant if we wrote a log record for that term above.  The
     * vote, if any, is never redundant.
     */
    error = raft_write_state(log, raft->term, &raft->vote);
    if (error) {
        return error;
    }

    /* Write commit_index if it's beyond the new start of the log. */
    if (raft->commit_index >= new_log_start) {
        struct raft_record r = {
            .type = RAFT_REC_COMMIT_INDEX,
            .commit_index = raft->commit_index,
        };
        return ovsdb_log_write_and_free(log, raft_record_to_json(&r));
    }
    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_save_snapshot(struct raft *raft,
                   uint64_t new_start, const struct raft_entry *new_snapshot)

{
    struct ovsdb_log *new_log;
    struct ovsdb_error *error;
    error = ovsdb_log_replace_start(raft->log, &new_log);
    if (error) {
        return error;
    }

    error = raft_write_snapshot(raft, new_log, new_start, new_snapshot);
    if (error) {
        ovsdb_log_replace_abort(new_log);
        return error;
    }

    return ovsdb_log_replace_commit(raft->log, new_log);
}

static bool
raft_handle_install_snapshot_request__(
    struct raft *raft, const struct raft_install_snapshot_request *rq)
{
    raft_reset_timer(raft);

    /*
     * Our behavior here depend on new_log_start in the snapshot compared to
     * log_start and log_end.  There are three cases:
     *
     *        Case 1       |    Case 2     |      Case 3
     *   <---------------->|<------------->|<------------------>
     *                     |               |
     *
     *                     +---+---+---+---+
     *                   T | T | T | T | T |
     *                     +---+---+---+---+
     *                       ^               ^
     *                       |               |
     *                   log_start        log_end
     */
    uint64_t new_log_start = rq->last_index + 1;
    if (new_log_start < raft->log_start) {
        /* Case 1: The new snapshot covers less than our current one.  Nothing
         * to do. */
        return true;
    } else if (new_log_start < raft->log_end) {
        /* Case 2: The new snapshot starts in the middle of our log.  We could
         * discard the first 'new_log_start - raft->log_start' entries in the
         * log.  But there's not much value in that, since snapshotting is
         * supposed to be a local decision.  Just skip it. */
        return true;
    }

    /* Case 3: The new snapshot starts past the end of our current log, so
     * discard all of our current log. */
    const struct raft_entry new_snapshot = {
        .term = rq->last_term,
        .data = rq->data,
        .eid = rq->last_eid,
        .servers = rq->last_servers,
    };
    struct ovsdb_error *error = raft_save_snapshot(raft, new_log_start,
                                                   &new_snapshot);
    if (error) {
        char *error_s = ovsdb_error_to_string(error);
        VLOG_WARN("could not save snapshot: %s", error_s);
        free(error_s);
        return false;
    }

    for (size_t i = 0; i < raft->log_end - raft->log_start; i++) {
        raft_entry_uninit(&raft->entries[i]);
    }
    raft->log_start = raft->log_end = new_log_start;
    raft->log_synced = raft->log_end - 1;
    raft->commit_index = raft->log_start - 1;
    if (raft->last_applied < raft->commit_index) {
        raft->last_applied = raft->log_start - 2;
    }

    raft_entry_uninit(&raft->snap);
    raft_entry_clone(&raft->snap, &new_snapshot);

    raft_get_servers_from_log(raft, VLL_INFO);

    return true;
}

static void
raft_handle_install_snapshot_request(
    struct raft *raft, const struct raft_install_snapshot_request *rq)
{
    if (raft_handle_install_snapshot_request__(raft, rq)) {
        union raft_rpc rpy = {
            .install_snapshot_reply = {
                .common = {
                    .type = RAFT_RPC_INSTALL_SNAPSHOT_REPLY,
                    .sid = rq->common.sid,
                },
                .term = raft->term,
                .last_index = rq->last_index,
                .last_term = rq->last_term,
            },
        };
        raft_send(raft, &rpy);
    }
}

static void
raft_handle_install_snapshot_reply(
    struct raft *raft, const struct raft_install_snapshot_reply *rpy)
{
    /* We might get an InstallSnapshot reply from a configured server (e.g. a
     * peer) or a server in the process of being added. */
    struct raft_server *s = raft_find_peer(raft, &rpy->common.sid);
    if (!s) {
        s = raft_find_new_server(raft, &rpy->common.sid);
        if (!s) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_INFO_RL(&rl, "cluster "CID_FMT": received %s from "
                         "unknown server "SID_FMT, CID_ARGS(&raft->cid),
                         raft_rpc_type_to_string(rpy->common.type),
                         SID_ARGS(&rpy->common.sid));
            return;
        }
    }

    if (rpy->last_index != raft->log_start - 1 ||
        rpy->last_term != raft->snap.term) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_INFO_RL(&rl, "cluster "CID_FMT": server %s installed "
                     "out-of-date snapshot, starting over",
                     CID_ARGS(&raft->cid), s->nickname);
        raft_send_install_snapshot_request(raft, s,
                                           "installed obsolete snapshot");
        return;
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    VLOG_INFO_RL(&rl, "cluster "CID_FMT": installed snapshot on server %s "
                 " up to %"PRIu64":%"PRIu64, CID_ARGS(&raft->cid),
                 s->nickname, rpy->last_term, rpy->last_index);
    s->next_index = raft->log_end;
    raft_send_append_request(raft, s, 0, "snapshot installed");
}

/* Returns true if 'raft' has grown enough since the last snapshot that
 * reducing the log to a snapshot would be valuable, false otherwise.  */
bool
raft_grew_lots(const struct raft *raft)
{
    return ovsdb_log_grew_lots(raft->log);
}

/* Returns the number of log entries that could be trimmed off the on-disk log
 * by snapshotting. */
uint64_t
raft_get_log_length(const struct raft *raft)
{
    return (raft->last_applied < raft->log_start
            ? 0
            : raft->last_applied - raft->log_start + 1);
}

/* Returns true if taking a snapshot of 'raft', with raft_store_snapshot(), is
 * possible. */
bool
raft_may_snapshot(const struct raft *raft)
{
    return (!raft->joining
            && !raft->leaving
            && !raft->left
            && !raft->failed
            && raft->last_applied >= raft->log_start);
}

/* Replaces the log for 'raft', up to the last log entry read, by
 * 'new_snapshot_data'.  Returns NULL if successful, otherwise an error that
 * the caller must eventually free.
 *
 * This function can only succeed if raft_may_snapshot() returns true.  It is
 * only valuable to call it if raft_get_log_length() is significant and
 * especially if raft_grew_lots() returns true. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_store_snapshot(struct raft *raft, const struct json *new_snapshot_data)
{
    if (raft->joining) {
        return ovsdb_error(NULL,
                           "cannot store a snapshot while joining cluster");
    } else if (raft->leaving) {
        return ovsdb_error(NULL,
                           "cannot store a snapshot while leaving cluster");
    } else if (raft->left) {
        return ovsdb_error(NULL,
                           "cannot store a snapshot after leaving cluster");
    } else if (raft->failed) {
        return ovsdb_error(NULL,
                           "cannot store a snapshot following failure");
    }

    if (raft->last_applied < raft->log_start) {
        return ovsdb_error(NULL, "not storing a duplicate snapshot");
    }

    uint64_t new_log_start = raft->last_applied + 1;
    const struct raft_entry new_snapshot = {
        .term = raft_get_term(raft, new_log_start - 1),
        .data = CONST_CAST(struct json *, new_snapshot_data),
        .eid = *raft_get_eid(raft, new_log_start - 1),
        .servers = CONST_CAST(struct json *,
                              raft_servers_for_index(raft, new_log_start - 1)),
    };
    struct ovsdb_error *error = raft_save_snapshot(raft, new_log_start,
                                                   &new_snapshot);
    if (error) {
        return error;
    }

    raft->log_synced = raft->log_end - 1;
    raft_entry_uninit(&raft->snap);
    raft_entry_clone(&raft->snap, &new_snapshot);
    for (size_t i = 0; i < new_log_start - raft->log_start; i++) {
        raft_entry_uninit(&raft->entries[i]);
    }
    memmove(&raft->entries[0], &raft->entries[new_log_start - raft->log_start],
            (raft->log_end - new_log_start) * sizeof *raft->entries);
    raft->log_start = new_log_start;
    return NULL;
}

static void
raft_handle_become_leader(struct raft *raft,
                          const struct raft_become_leader *rq)
{
    if (raft->role == RAFT_FOLLOWER) {
        char buf[SID_LEN + 1];
        VLOG_INFO("received leadership transfer from %s in term %"PRIu64,
                  raft_get_nickname(raft, &rq->common.sid, buf, sizeof buf),
                  rq->term);
        raft_start_election(raft, true);
    }
}

static void
raft_send_execute_command_reply(struct raft *raft,
                                const struct uuid *sid,
                                const struct uuid *eid,
                                enum raft_command_status status,
                                uint64_t commit_index)
{
    union raft_rpc rpc = {
        .execute_command_reply = {
            .common = {
                .type = RAFT_RPC_EXECUTE_COMMAND_REPLY,
                .sid = *sid,
            },
            .result = *eid,
            .status = status,
            .commit_index = commit_index,
        },
    };
    raft_send(raft, &rpc);
}

static enum raft_command_status
raft_handle_execute_command_request__(
    struct raft *raft, const struct raft_execute_command_request *rq)
{
    if (raft->role != RAFT_LEADER) {
        return RAFT_CMD_NOT_LEADER;
    }

    const struct uuid *current_eid = raft_current_eid(raft);
    if (!uuid_equals(&rq->prereq, current_eid)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_INFO_RL(&rl, "current entry eid "UUID_FMT" does not match "
                     "prerequisite "UUID_FMT" in execute_command_request",
                     UUID_ARGS(current_eid), UUID_ARGS(&rq->prereq));
        return RAFT_CMD_BAD_PREREQ;
    }

    struct raft_command *cmd = raft_command_initiate(raft, rq->data,
                                                     NULL, &rq->result);
    cmd->sid = rq->common.sid;

    enum raft_command_status status = cmd->status;
    if (status != RAFT_CMD_INCOMPLETE) {
        raft_command_unref(cmd);
    }
    return status;
}

static void
raft_handle_execute_command_request(
    struct raft *raft, const struct raft_execute_command_request *rq)
{
    enum raft_command_status status
        = raft_handle_execute_command_request__(raft, rq);
    if (status != RAFT_CMD_INCOMPLETE) {
        raft_send_execute_command_reply(raft, &rq->common.sid, &rq->result,
                                        status, 0);
    }
}

static void
raft_handle_execute_command_reply(
    struct raft *raft, const struct raft_execute_command_reply *rpy)
{
    struct raft_command *cmd = raft_find_command_by_eid(raft, &rpy->result);
    if (!cmd) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        char buf[SID_LEN + 1];
        VLOG_INFO_RL(&rl,
                     "%s received \"%s\" reply from %s for unknown command",
                     raft->local_nickname,
                     raft_command_status_to_string(rpy->status),
                     raft_get_nickname(raft, &rpy->common.sid,
                                       buf, sizeof buf));
        return;
    }

    if (rpy->status == RAFT_CMD_INCOMPLETE) {
        cmd->timestamp = time_msec();
    } else {
        cmd->index = rpy->commit_index;
        raft_command_complete(raft, cmd, rpy->status);
    }
}

static void
raft_handle_rpc(struct raft *raft, const union raft_rpc *rpc)
{
    uint64_t term = raft_rpc_get_term(rpc);
    if (term
        && !raft_should_suppress_disruptive_server(raft, rpc)
        && !raft_receive_term__(raft, &rpc->common, term)) {
        if (rpc->type == RAFT_RPC_APPEND_REQUEST) {
            /* Section 3.3: "If a server receives a request with a stale term
             * number, it rejects the request." */
            raft_send_append_reply(raft, raft_append_request_cast(rpc),
                                   RAFT_APPEND_INCONSISTENCY, "stale term");
        }
        return;
    }

    switch (rpc->type) {
#define RAFT_RPC(ENUM, NAME)                        \
        case ENUM:                                  \
            raft_handle_##NAME(raft, &rpc->NAME);   \
            break;
    RAFT_RPC_TYPES
#undef RAFT_RPC
    default:
        OVS_NOT_REACHED();
    }
}

static bool
raft_rpc_is_heartbeat(const union raft_rpc *rpc)
{
    return ((rpc->type == RAFT_RPC_APPEND_REQUEST
             || rpc->type == RAFT_RPC_APPEND_REPLY)
             && rpc->common.comment
             && !strcmp(rpc->common.comment, "heartbeat"));
}


static bool
raft_send__(struct raft *raft, const union raft_rpc *rpc,
            struct raft_conn *conn)
{
    log_rpc(rpc, "-->", conn);
    return !jsonrpc_session_send(
        conn->js, raft_rpc_to_jsonrpc(&raft->cid, &raft->sid, rpc));
}

static bool
raft_is_rpc_synced(const struct raft *raft, const union raft_rpc *rpc)
{
    uint64_t term = raft_rpc_get_term(rpc);
    uint64_t index = raft_rpc_get_min_sync_index(rpc);
    const struct uuid *vote = raft_rpc_get_vote(rpc);

    return (term <= raft->synced_term
            && index <= raft->log_synced
            && (!vote || uuid_equals(vote, &raft->synced_vote)));
}

static bool
raft_send(struct raft *raft, const union raft_rpc *rpc)
{
    const struct uuid *dst = &rpc->common.sid;
    if (uuid_equals(dst, &raft->sid)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "attempting to send RPC to self");
        return false;
    }

    struct raft_conn *conn = raft_find_conn_by_sid(raft, dst);
    if (!conn) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        char buf[SID_LEN + 1];
        VLOG_DBG_RL(&rl, "%s: no connection to %s, cannot send RPC",
                    raft->local_nickname,
                    raft_get_nickname(raft, dst, buf, sizeof buf));
        return false;
    }

    if (!raft_is_rpc_synced(raft, rpc)) {
        raft_waiter_create(raft, RAFT_W_RPC, false)->rpc = raft_rpc_clone(rpc);
        return true;
    }

    return raft_send__(raft, rpc, conn);
}

static struct raft *
raft_lookup_by_name(const char *name)
{
    struct raft *raft;

    HMAP_FOR_EACH_WITH_HASH (raft, hmap_node, hash_string(name, 0),
                             &all_rafts) {
        if (!strcmp(raft->name, name)) {
            return raft;
        }
    }
    return NULL;
}

static void
raft_unixctl_cid(struct unixctl_conn *conn,
                 int argc OVS_UNUSED, const char *argv[],
                 void *aux OVS_UNUSED)
{
    struct raft *raft = raft_lookup_by_name(argv[1]);
    if (!raft) {
        unixctl_command_reply_error(conn, "unknown cluster");
    } else if (uuid_is_zero(&raft->cid)) {
        unixctl_command_reply_error(conn, "cluster id not yet known");
    } else {
        char *uuid = xasprintf(UUID_FMT, UUID_ARGS(&raft->cid));
        unixctl_command_reply(conn, uuid);
        free(uuid);
    }
}

static void
raft_unixctl_sid(struct unixctl_conn *conn,
                 int argc OVS_UNUSED, const char *argv[],
                 void *aux OVS_UNUSED)
{
    struct raft *raft = raft_lookup_by_name(argv[1]);
    if (!raft) {
        unixctl_command_reply_error(conn, "unknown cluster");
    } else {
        char *uuid = xasprintf(UUID_FMT, UUID_ARGS(&raft->sid));
        unixctl_command_reply(conn, uuid);
        free(uuid);
    }
}

static void
raft_put_sid(const char *title, const struct uuid *sid,
             const struct raft *raft, struct ds *s)
{
    ds_put_format(s, "%s: ", title);
    if (uuid_equals(sid, &raft->sid)) {
        ds_put_cstr(s, "self");
    } else if (uuid_is_zero(sid)) {
        ds_put_cstr(s, "unknown");
    } else {
        char buf[SID_LEN + 1];
        ds_put_cstr(s, raft_get_nickname(raft, sid, buf, sizeof buf));
    }
    ds_put_char(s, '\n');
}

static void
raft_unixctl_status(struct unixctl_conn *conn,
                    int argc OVS_UNUSED, const char *argv[],
                    void *aux OVS_UNUSED)
{
    struct raft *raft = raft_lookup_by_name(argv[1]);
    if (!raft) {
        unixctl_command_reply_error(conn, "unknown cluster");
        return;
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "%s\n", raft->local_nickname);
    ds_put_format(&s, "Name: %s\n", raft->name);
    ds_put_format(&s, "Cluster ID: ");
    if (!uuid_is_zero(&raft->cid)) {
        ds_put_format(&s, CID_FMT" ("UUID_FMT")\n",
                      CID_ARGS(&raft->cid), UUID_ARGS(&raft->cid));
    } else {
        ds_put_format(&s, "not yet known\n");
    }
    ds_put_format(&s, "Server ID: "SID_FMT" ("UUID_FMT")\n",
                  SID_ARGS(&raft->sid), UUID_ARGS(&raft->sid));
    ds_put_format(&s, "Address: %s\n", raft->local_address);
    ds_put_format(&s, "Status: %s\n",
                  raft->joining ? "joining cluster"
                  : raft->leaving ? "leaving cluster"
                  : raft->left ? "left cluster"
                  : raft->failed ? "failed"
                  : "cluster member");
    if (raft->joining) {
        ds_put_format(&s, "Remotes for joining:");
        const char *address;
        SSET_FOR_EACH (address, &raft->remote_addresses) {
            ds_put_format(&s, " %s", address);
        }
        ds_put_char(&s, '\n');
    }
    if (raft->role == RAFT_LEADER) {
        struct raft_server *as;
        HMAP_FOR_EACH (as, hmap_node, &raft->add_servers) {
            ds_put_format(&s, "Adding server %s ("SID_FMT" at %s) (%s)\n",
                          as->nickname, SID_ARGS(&as->sid), as->address,
                          raft_server_phase_to_string(as->phase));
        }

        struct raft_server *rs = raft->remove_server;
        if (rs) {
            ds_put_format(&s, "Removing server %s ("SID_FMT" at %s) (%s)\n",
                          rs->nickname, SID_ARGS(&rs->sid), rs->address,
                          raft_server_phase_to_string(rs->phase));
        }
    }

    ds_put_format(&s, "Role: %s\n",
                  raft->role == RAFT_LEADER ? "leader"
                  : raft->role == RAFT_CANDIDATE ? "candidate"
                  : raft->role == RAFT_FOLLOWER ? "follower"
                  : "<error>");
    ds_put_format(&s, "Term: %"PRIu64"\n", raft->term);
    raft_put_sid("Leader", &raft->leader_sid, raft, &s);
    raft_put_sid("Vote", &raft->vote, raft, &s);
    ds_put_char(&s, '\n');

    ds_put_format(&s, "Log: [%"PRIu64", %"PRIu64"]\n",
                  raft->log_start, raft->log_end);

    uint64_t n_uncommitted = raft->log_end - raft->commit_index - 1;
    ds_put_format(&s, "Entries not yet committed: %"PRIu64"\n", n_uncommitted);

    uint64_t n_unapplied = raft->log_end - raft->last_applied - 1;
    ds_put_format(&s, "Entries not yet applied: %"PRIu64"\n", n_unapplied);

    const struct raft_conn *c;
    ds_put_cstr(&s, "Connections:");
    LIST_FOR_EACH (c, list_node, &raft->conns) {
        bool connected = jsonrpc_session_is_connected(c->js);
        ds_put_format(&s, " %s%s%s%s",
                      connected ? "" : "(",
                      c->incoming ? "<-" : "->", c->nickname,
                      connected ? "" : ")");
    }
    ds_put_char(&s, '\n');

    ds_put_cstr(&s, "Servers:\n");
    struct raft_server *server;
    HMAP_FOR_EACH (server, hmap_node, &raft->servers) {
        ds_put_format(&s, "    %s ("SID_FMT" at %s)",
                      server->nickname,
                      SID_ARGS(&server->sid), server->address);
        if (uuid_equals(&server->sid, &raft->sid)) {
            ds_put_cstr(&s, " (self)");
        }
        if (server->phase != RAFT_PHASE_STABLE) {
            ds_put_format (&s, " (%s)",
                           raft_server_phase_to_string(server->phase));
        }
        if (raft->role == RAFT_CANDIDATE) {
            if (!uuid_is_zero(&server->vote)) {
                char buf[SID_LEN + 1];
                ds_put_format(&s, " (voted for %s)",
                              raft_get_nickname(raft, &server->vote,
                                                buf, sizeof buf));
            }
        } else if (raft->role == RAFT_LEADER) {
            ds_put_format(&s, " next_index=%"PRIu64" match_index=%"PRIu64,
                          server->next_index, server->match_index);
        }
        ds_put_char(&s, '\n');
    }

    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}

static void
raft_unixctl_leave__(struct unixctl_conn *conn, struct raft *raft)
{
    if (raft_is_leaving(raft)) {
        unixctl_command_reply_error(conn,
                                    "already in progress leaving cluster");
    } else if (raft_is_joining(raft)) {
        unixctl_command_reply_error(conn,
                                    "can't leave while join in progress");
    } else if (raft_failed(raft)) {
        unixctl_command_reply_error(conn,
                                    "can't leave after failure");
    } else {
        raft_leave(raft);
        unixctl_command_reply(conn, NULL);
    }
}

static void
raft_unixctl_leave(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct raft *raft = raft_lookup_by_name(argv[1]);
    if (!raft) {
        unixctl_command_reply_error(conn, "unknown cluster");
        return;
    }

    raft_unixctl_leave__(conn, raft);
}

static struct raft_server *
raft_lookup_server_best_match(struct raft *raft, const char *id)
{
    struct raft_server *best = NULL;
    int best_score = -1;
    int n_best = 0;

    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        int score = (!strcmp(id, s->address)
                     ? INT_MAX
                     : uuid_is_partial_match(&s->sid, id));
        if (score > best_score) {
            best = s;
            best_score = score;
            n_best = 1;
        } else if (score == best_score) {
            n_best++;
        }
    }
    return n_best == 1 ? best : NULL;
}

static void
raft_unixctl_kick(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[], void *aux OVS_UNUSED)
{
    const char *cluster_name = argv[1];
    const char *server_name = argv[2];

    struct raft *raft = raft_lookup_by_name(cluster_name);
    if (!raft) {
        unixctl_command_reply_error(conn, "unknown cluster");
        return;
    }

    struct raft_server *server = raft_lookup_server_best_match(raft,
                                                               server_name);
    if (!server) {
        unixctl_command_reply_error(conn, "unknown server");
        return;
    }

    if (uuid_equals(&server->sid, &raft->sid)) {
        raft_unixctl_leave__(conn, raft);
    } else if (raft->role == RAFT_LEADER) {
        const struct raft_remove_server_request rq = {
            .sid = server->sid,
            .requester_conn = conn,
        };
        raft_handle_remove_server_request(raft, &rq);
    } else {
        const union raft_rpc rpc = {
            .remove_server_request = {
                .common = {
                    .type = RAFT_RPC_REMOVE_SERVER_REQUEST,
                    .sid = raft->leader_sid,
                    .comment = "via unixctl"
                },
                .sid = server->sid,
            }
        };
        if (raft_send(raft, &rpc)) {
            unixctl_command_reply(conn, "sent removal request to leader");
        } else {
            unixctl_command_reply_error(conn,
                                        "failed to send removal request");
        }
    }
}

static void
raft_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    if (!ovsthread_once_start(&once)) {
        return;
    }
    unixctl_command_register("cluster/cid", "DB", 1, 1,
                             raft_unixctl_cid, NULL);
    unixctl_command_register("cluster/sid", "DB", 1, 1,
                             raft_unixctl_sid, NULL);
    unixctl_command_register("cluster/status", "DB", 1, 1,
                             raft_unixctl_status, NULL);
    unixctl_command_register("cluster/leave", "DB", 1, 1,
                             raft_unixctl_leave, NULL);
    unixctl_command_register("cluster/kick", "DB SERVER", 2, 2,
                             raft_unixctl_kick, NULL);
    ovsthread_once_done(&once);
}
