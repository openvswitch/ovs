/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITION OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "ovsdb-cs.h"

#include <errno.h>

#include "hash.h"
#include "jsonrpc.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb-session.h"
#include "ovsdb-types.h"
#include "sset.h"
#include "svec.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_cs);

/* Connection state machine.
 *
 * When a JSON-RPC session connects, the CS layer sends a "monitor_cond"
 * request for the Database table in the _Server database and transitions to
 * the CS_S_SERVER_MONITOR_REQUESTED state.  If the session drops and
 * reconnects, or if the CS receives a "monitor_canceled" notification for a
 * table it is monitoring, the CS starts over again in the same way. */
#define OVSDB_CS_STATES                                                 \
    /* Waits for "get_schema" reply, then sends "monitor_cond"          \
     * request for the Database table in the _Server database, whose    \
     * details are informed by the schema, and transitions to           \
     * CS_S_SERVER_MONITOR_REQUESTED. */                                \
    OVSDB_CS_STATE(SERVER_SCHEMA_REQUESTED)                             \
                                                                        \
    /* Waits for "monitor_cond" reply for the Database table:           \
     *                                                                  \
     * - If the reply indicates success, and the Database table has a   \
     *   row for the CS database:                                       \
     *                                                                  \
     *   * If the row indicates that this is a clustered database       \
     *     that is not connected to the cluster, closes the             \
     *     connection.  The next connection attempt has a chance at     \
     *     picking a connected server.                                  \
     *                                                                  \
     *   * Otherwise, sends a monitoring request for the CS             \
     *     database whose details are informed by the schema            \
     *     (obtained from the row), and transitions to                  \
     *     CS_S_DATA_MONITOR_(COND_(SINCE_))REQUESTED.                  \
     *                                                                  \
     * - If the reply indicates success, but the Database table does    \
     *   not have a row for the CS database, transitions to             \
     *   CS_S_ERROR.                                                    \
     *                                                                  \
     * - If the reply indicates failure, sends a "get_schema" request   \
     *   for the CS database and transitions to                         \
     *   CS_S_DATA_SCHEMA_REQUESTED. */                                 \
    OVSDB_CS_STATE(SERVER_MONITOR_REQUESTED)                            \
                                                                        \
    /* Waits for "get_schema" reply, then sends "monitor_cond"          \
     * request whose details are informed by the schema, and            \
     * transitions to CS_S_DATA_MONITOR_COND_REQUESTED. */              \
    OVSDB_CS_STATE(DATA_SCHEMA_REQUESTED)                               \
                                                                        \
    /* Waits for "monitor_cond_since" reply.  If successful, replaces   \
     * the CS contents by the data carried in the reply and             \
     * transitions to CS_S_MONITORING.  On failure, sends a             \
     * "monitor_cond" request and transitions to                        \
     * CS_S_DATA_MONITOR_COND_REQUESTED. */                             \
    OVSDB_CS_STATE(DATA_MONITOR_COND_SINCE_REQUESTED)                   \
                                                                        \
    /* Waits for "monitor_cond" reply.  If successful, replaces the     \
     * CS contents by the data carried in the reply and transitions     \
     * to CS_S_MONITORING.  On failure, sends a "monitor" request       \
     * and transitions to CS_S_DATA_MONITOR_REQUESTED. */               \
    OVSDB_CS_STATE(DATA_MONITOR_COND_REQUESTED)                         \
                                                                        \
    /* Waits for "monitor" reply.  If successful, replaces the CS       \
     * contents by the data carried in the reply and transitions to     \
     * CS_S_MONITORING.  On failure, transitions to CS_S_ERROR. */      \
    OVSDB_CS_STATE(DATA_MONITOR_REQUESTED)                              \
                                                                        \
    /* State that processes "update", "update2" or "update3"            \
     * notifications for the main database (and the Database table      \
     * in _Server if available).                                        \
     *                                                                  \
     * If we're monitoring the Database table and we get notified       \
     * that the CS database has been deleted, we close the              \
     * connection (which will restart the state machine). */            \
    OVSDB_CS_STATE(MONITORING)                                          \
                                                                        \
    /* Terminal error state that indicates that nothing useful can be   \
     * done, for example because the database server doesn't actually   \
     * have the desired database.  We maintain the session with the     \
     * database server anyway.  If it starts serving the database       \
     * that we want, or if someone fixes and restarts the database,     \
     * then it will kill the session and we will automatically          \
     * reconnect and try again. */                                      \
    OVSDB_CS_STATE(ERROR)                                               \
                                                                        \
    /* Terminal state that indicates we connected to a useless server   \
     * in a cluster, e.g. one that is partitioned from the rest of      \
     * the cluster. We're waiting to retry. */                          \
    OVSDB_CS_STATE(RETRY)

enum ovsdb_cs_state {
#define OVSDB_CS_STATE(NAME) CS_S_##NAME,
    OVSDB_CS_STATES
#undef OVSDB_CS_STATE
};

static const char *
ovsdb_cs_state_to_string(enum ovsdb_cs_state state)
{
    switch (state) {
#define OVSDB_CS_STATE(NAME) case CS_S_##NAME: return #NAME;
        OVSDB_CS_STATES
#undef OVSDB_CS_STATE
    default: return "<unknown>";
    }
}

/* A database being monitored.
 *
 * There are two instances of this data structure for each CS instance, one for
 * the _Server database used for working with clusters, and the other one for
 * the actual database that the client is interested in.  */
struct ovsdb_cs_db {
    struct ovsdb_cs *cs;

    /* Data. */
    const char *db_name;        /* Database's name. */
    struct hmap tables;         /* Contains "struct ovsdb_cs_db_table *"s.*/
    struct json *monitor_id;
    struct json *schema;

    /* Monitor version. */
    int max_version;            /* Maximum version of monitor request to use. */
    int monitor_version;        /* 0 if not monitoring, 1=monitor,
                                 * 2=monitor_cond, 3=monitor_cond_since. */

    /* Condition changes. */
    bool cond_changed;          /* Change not yet sent to server? */
    unsigned int cond_seqno;    /* Increments when condition changes. */

    /* Database locking. */
    char *lock_name;            /* Name of lock we need, NULL if none. */
    bool has_lock;              /* Has db server told us we have the lock? */
    bool is_lock_contended;     /* Has db server told us we can't get lock? */
    struct json *lock_request_id; /* JSON-RPC ID of in-flight lock request. */

    /* Last db txn id, used for fast resync through monitor_cond_since */
    struct uuid last_id;

    /* Client interface. */
    struct ovs_list events;
    const struct ovsdb_cs_ops *ops;
    void *ops_aux;
};

static const struct ovsdb_cs_ops ovsdb_cs_server_ops;

static void ovsdb_cs_db_destroy_tables(struct ovsdb_cs_db *);
static unsigned int ovsdb_cs_db_set_condition(
    struct ovsdb_cs_db *, const char *db_name, const struct json *condition);

static void ovsdb_cs_send_schema_request(struct ovsdb_cs *,
                                          struct ovsdb_cs_db *);
static void ovsdb_cs_send_db_change_aware(struct ovsdb_cs *);
static bool ovsdb_cs_check_server_db(struct ovsdb_cs *);
static void ovsdb_cs_clear_server_rows(struct ovsdb_cs *);
static void ovsdb_cs_send_monitor_request(struct ovsdb_cs *,
                                          struct ovsdb_cs_db *, int version);
static void ovsdb_cs_db_ack_condition(struct ovsdb_cs_db *db);
static void ovsdb_cs_db_sync_condition(struct ovsdb_cs_db *db);

struct ovsdb_cs {
    struct ovsdb_cs_db server;
    struct ovsdb_cs_db data;

    /* Session state.
     *
     * 'state_seqno' is a snapshot of the session's sequence number as returned
     * jsonrpc_session_get_seqno(session), so if it differs from the value that
     * function currently returns then the session has reconnected and the
     * state machine must restart.  */
    struct jsonrpc_session *session; /* Connection to the server. */
    char *remote;                    /* 'session' remote name. */
    enum ovsdb_cs_state state;       /* Current session state. */
    unsigned int state_seqno;        /* See above. */
    struct json *request_id;         /* JSON ID for request awaiting reply. */

    /* IDs of outstanding transactions. */
    struct json **txns;
    size_t n_txns, allocated_txns;

    /* Info for the _Server database. */
    struct uuid cid;
    struct hmap server_rows;

    /* Clustered servers. */
    uint64_t min_index;      /* Minimum allowed index, to avoid regression. */
    bool leader_only;        /* If true, do not connect to Raft followers. */
    bool shuffle_remotes;    /* If true, connect to servers in random order. */
};

static void ovsdb_cs_transition_at(struct ovsdb_cs *, enum ovsdb_cs_state,
                                    const char *where);
#define ovsdb_cs_transition(CS, STATE) \
    ovsdb_cs_transition_at(CS, STATE, OVS_SOURCE_LOCATOR)

static void ovsdb_cs_retry_at(struct ovsdb_cs *, const char *where);
#define ovsdb_cs_retry(CS) ovsdb_cs_retry_at(CS, OVS_SOURCE_LOCATOR)

static struct vlog_rate_limit syntax_rl = VLOG_RATE_LIMIT_INIT(1, 5);

static void ovsdb_cs_db_parse_monitor_reply(struct ovsdb_cs_db *,
                                            const struct json *result,
                                            int version);
static bool ovsdb_cs_db_parse_update_rpc(struct ovsdb_cs_db *,
                                         const struct jsonrpc_msg *);
static bool ovsdb_cs_handle_monitor_canceled(struct ovsdb_cs *,
                                              struct ovsdb_cs_db *,
                                              const struct jsonrpc_msg *);

static bool ovsdb_cs_db_process_lock_replies(struct ovsdb_cs_db *,
                                              const struct jsonrpc_msg *);
static struct jsonrpc_msg *ovsdb_cs_db_compose_lock_request(
    struct ovsdb_cs_db *);
static struct jsonrpc_msg *ovsdb_cs_db_compose_unlock_request(
    struct ovsdb_cs_db *);
static void ovsdb_cs_db_parse_lock_reply(struct ovsdb_cs_db *,
                                          const struct json *);
static bool ovsdb_cs_db_parse_lock_notify(struct ovsdb_cs_db *,
                                           const struct json *params,
                                           bool new_has_lock);
static void ovsdb_cs_send_cond_change(struct ovsdb_cs *);

static bool ovsdb_cs_db_txn_process_reply(struct ovsdb_cs *,
                                          const struct jsonrpc_msg *reply);

/* Events. */

void
ovsdb_cs_event_destroy(struct ovsdb_cs_event *event)
{
    if (event) {
        switch (event->type) {
        case OVSDB_CS_EVENT_TYPE_RECONNECT:
        case OVSDB_CS_EVENT_TYPE_LOCKED:
            break;

        case OVSDB_CS_EVENT_TYPE_UPDATE:
            json_destroy(event->update.table_updates);
            break;

        case OVSDB_CS_EVENT_TYPE_TXN_REPLY:
            jsonrpc_msg_destroy(event->txn_reply);
            break;
        }
        free(event);
    }
}

/* Lifecycle. */

static void
ovsdb_cs_db_init(struct ovsdb_cs_db *db, const char *db_name,
                 struct ovsdb_cs *parent, int max_version,
                 const struct ovsdb_cs_ops *ops, void *ops_aux)
{
    *db = (struct ovsdb_cs_db) {
        .cs = parent,
        .db_name = db_name,
        .tables = HMAP_INITIALIZER(&db->tables),
        .max_version = max_version,
        .monitor_id = json_array_create_2(json_string_create("monid"),
                                          json_string_create(db_name)),
        .events = OVS_LIST_INITIALIZER(&db->events),
        .ops = ops,
        .ops_aux = ops_aux,
    };
}

/* Creates and returns a new client synchronization object.  The connection
 * will monitor remote database 'db_name'.  If 'retry' is true, then also
 * reconnect if the connection fails.
 *
 * XXX 'max_version' should ordinarily be 3, to allow use of the most efficient
 * "monitor_cond_since" method with the database.  Currently there's some kind
 * of bug in the DDlog Rust code that interfaces to that, so instead
 * ovn-northd-ddlog passes 1 to use plain 'monitor' instead.  Once the DDlog
 * Rust code gets fixed, we might as well just delete 'max_version'
 * entirely.
 *
 * 'ops' is a struct for northd_cs_run() to use, and 'ops_aux' is a pointer
 * that gets passed into each call.
 *
 * Use ovsdb_cs_set_remote() to configure the database to which to connect.
 * Until a remote is configured, no data can be retrieved.
 */
struct ovsdb_cs *
ovsdb_cs_create(const char *db_name, int max_version,
                const struct ovsdb_cs_ops *ops, void *ops_aux)
{
    struct ovsdb_cs *cs = xzalloc(sizeof *cs);
    ovsdb_cs_db_init(&cs->server, "_Server", cs, 2, &ovsdb_cs_server_ops, cs);
    ovsdb_cs_db_init(&cs->data, db_name, cs, max_version, ops, ops_aux);
    cs->state_seqno = UINT_MAX;
    cs->request_id = NULL;
    cs->leader_only = true;
    cs->shuffle_remotes = true;
    hmap_init(&cs->server_rows);

    return cs;
}

static void
ovsdb_cs_db_destroy(struct ovsdb_cs_db *db)
{
    ovsdb_cs_db_destroy_tables(db);

    json_destroy(db->monitor_id);
    json_destroy(db->schema);

    free(db->lock_name);

    json_destroy(db->lock_request_id);

    /* This list always gets flushed out at the end of ovsdb_cs_run(). */
    ovs_assert(ovs_list_is_empty(&db->events));
}

/* Destroys 'cs' and all of the data structures that it manages. */
void
ovsdb_cs_destroy(struct ovsdb_cs *cs)
{
    if (cs) {
        ovsdb_cs_db_destroy(&cs->server);
        ovsdb_cs_db_destroy(&cs->data);
        jsonrpc_session_close(cs->session);
        free(cs->remote);
        json_destroy(cs->request_id);

        for (size_t i = 0; i < cs->n_txns; i++) {
            json_destroy(cs->txns[i]);
        }
        free(cs->txns);

        ovsdb_cs_clear_server_rows(cs);
        hmap_destroy(&cs->server_rows);

        free(cs);
    }
}

static void
ovsdb_cs_transition_at(struct ovsdb_cs *cs, enum ovsdb_cs_state new_state,
                        const char *where)
{
    VLOG_DBG("%s: %s -> %s at %s",
             cs->session ? jsonrpc_session_get_name(cs->session) : "void",
             ovsdb_cs_state_to_string(cs->state),
             ovsdb_cs_state_to_string(new_state),
             where);
    cs->state = new_state;
}

static void
ovsdb_cs_send_request(struct ovsdb_cs *cs, struct jsonrpc_msg *request)
{
    json_destroy(cs->request_id);
    cs->request_id = json_clone(request->id);
    if (cs->session) {
        jsonrpc_session_send(cs->session, request);
    } else {
        jsonrpc_msg_destroy(request);
    }
}

static void
ovsdb_cs_retry_at(struct ovsdb_cs *cs, const char *where)
{
    ovsdb_cs_force_reconnect(cs);
    ovsdb_cs_transition_at(cs, CS_S_RETRY, where);
}

static void
ovsdb_cs_restart_fsm(struct ovsdb_cs *cs)
{
    /* Resync data DB table conditions to avoid missing updates due to
     * conditions that were in flight or changed locally while the connection
     * was down.
     */
    ovsdb_cs_db_sync_condition(&cs->data);

    ovsdb_cs_send_schema_request(cs, &cs->server);
    ovsdb_cs_transition(cs, CS_S_SERVER_SCHEMA_REQUESTED);
    cs->data.monitor_version = 0;
    cs->server.monitor_version = 0;
}

static void
ovsdb_cs_process_response(struct ovsdb_cs *cs, struct jsonrpc_msg *msg)
{
    bool ok = msg->type == JSONRPC_REPLY;
    if (!ok
        && cs->state != CS_S_SERVER_SCHEMA_REQUESTED
        && cs->state != CS_S_SERVER_MONITOR_REQUESTED
        && cs->state != CS_S_DATA_MONITOR_COND_REQUESTED
        && cs->state != CS_S_DATA_MONITOR_COND_SINCE_REQUESTED) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        char *s = jsonrpc_msg_to_string(msg);
        VLOG_INFO_RL(&rl, "%s: received unexpected %s response in "
                     "%s state: %s", jsonrpc_session_get_name(cs->session),
                     jsonrpc_msg_type_to_string(msg->type),
                     ovsdb_cs_state_to_string(cs->state),
                     s);
        free(s);
        ovsdb_cs_retry(cs);
        return;
    }

    switch (cs->state) {
    case CS_S_SERVER_SCHEMA_REQUESTED:
        if (ok) {
            json_destroy(cs->server.schema);
            cs->server.schema = json_clone(msg->result);
            ovsdb_cs_send_monitor_request(cs, &cs->server,
                                          cs->server.max_version);
            ovsdb_cs_transition(cs, CS_S_SERVER_MONITOR_REQUESTED);
        } else {
            ovsdb_cs_send_schema_request(cs, &cs->data);
            ovsdb_cs_transition(cs, CS_S_DATA_SCHEMA_REQUESTED);
        }
        break;

    case CS_S_SERVER_MONITOR_REQUESTED:
        if (ok) {
            cs->server.monitor_version = cs->server.max_version;
            ovsdb_cs_db_parse_monitor_reply(&cs->server, msg->result,
                                            cs->server.monitor_version);
            if (ovsdb_cs_check_server_db(cs)) {
                ovsdb_cs_send_db_change_aware(cs);
            }
        } else {
            ovsdb_cs_send_schema_request(cs, &cs->data);
            ovsdb_cs_transition(cs, CS_S_DATA_SCHEMA_REQUESTED);
        }
        break;

    case CS_S_DATA_SCHEMA_REQUESTED:
        json_destroy(cs->data.schema);
        cs->data.schema = json_clone(msg->result);
        if (cs->data.max_version >= 2) {
            ovsdb_cs_send_monitor_request(cs, &cs->data, 2);
            ovsdb_cs_transition(cs, CS_S_DATA_MONITOR_COND_REQUESTED);
        } else {
            ovsdb_cs_send_monitor_request(cs, &cs->data, 1);
            ovsdb_cs_transition(cs, CS_S_DATA_MONITOR_REQUESTED);
        }
        break;

    case CS_S_DATA_MONITOR_COND_SINCE_REQUESTED:
        if (!ok) {
            /* "monitor_cond_since" not supported.  Try "monitor_cond". */
            ovsdb_cs_send_monitor_request(cs, &cs->data, 2);
            ovsdb_cs_transition(cs, CS_S_DATA_MONITOR_COND_REQUESTED);
        } else {
            cs->data.monitor_version = 3;
            ovsdb_cs_transition(cs, CS_S_MONITORING);
            ovsdb_cs_db_parse_monitor_reply(&cs->data, msg->result, 3);
        }
        break;

    case CS_S_DATA_MONITOR_COND_REQUESTED:
        if (!ok) {
            /* "monitor_cond" not supported.  Try "monitor". */
            ovsdb_cs_send_monitor_request(cs, &cs->data, 1);
            ovsdb_cs_transition(cs, CS_S_DATA_MONITOR_REQUESTED);
        } else {
            cs->data.monitor_version = 2;
            ovsdb_cs_transition(cs, CS_S_MONITORING);
            ovsdb_cs_db_parse_monitor_reply(&cs->data, msg->result, 2);
        }
        break;

    case CS_S_DATA_MONITOR_REQUESTED:
        cs->data.monitor_version = 1;
        ovsdb_cs_transition(cs, CS_S_MONITORING);
        ovsdb_cs_db_parse_monitor_reply(&cs->data, msg->result, 1);
        break;

    case CS_S_MONITORING:
        /* We don't normally have a request outstanding in this state.  If we
         * do, it's a "monitor_cond_change", which means that the conditional
         * monitor clauses were updated.
         *
         * Mark the last requested conditions as acked and if further
         * condition changes were pending, send them now. */
        ovsdb_cs_db_ack_condition(&cs->data);
        ovsdb_cs_send_cond_change(cs);
        cs->data.cond_seqno++;
        break;

    case CS_S_ERROR:
    case CS_S_RETRY:
        /* Nothing to do in this state. */
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static void
ovsdb_cs_process_msg(struct ovsdb_cs *cs, struct jsonrpc_msg *msg)
{
    bool is_response = (msg->type == JSONRPC_REPLY ||
                        msg->type == JSONRPC_ERROR);

    /* Process a reply to an outstanding request. */
    if (is_response
        && cs->request_id && json_equal(cs->request_id, msg->id)) {
        json_destroy(cs->request_id);
        cs->request_id = NULL;
        ovsdb_cs_process_response(cs, msg);
        return;
    }

    /* Process database contents updates. */
    if (ovsdb_cs_db_parse_update_rpc(&cs->data, msg)) {
        return;
    }
    if (cs->server.monitor_version
        && ovsdb_cs_db_parse_update_rpc(&cs->server, msg)) {
        ovsdb_cs_check_server_db(cs);
        return;
    }

    if (ovsdb_cs_handle_monitor_canceled(cs, &cs->data, msg)
        || (cs->server.monitor_version
            && ovsdb_cs_handle_monitor_canceled(cs, &cs->server, msg))) {
        return;
    }

    /* Process "lock" replies and related notifications. */
    if (ovsdb_cs_db_process_lock_replies(&cs->data, msg)) {
        return;
    }

    /* Process response to a database transaction we submitted. */
    if (is_response && ovsdb_cs_db_txn_process_reply(cs, msg)) {
        return;
    }

    /* Unknown message.  Log at a low level because this can happen if
     * ovsdb_cs_txn_destroy() is called to destroy a transaction
     * before we receive the reply.
     *
     * (We could sort those out from other kinds of unknown messages by
     * using distinctive IDs for transactions, if it seems valuable to
     * do so, and then it would be possible to use different log
     * levels. XXX?) */
    char *s = jsonrpc_msg_to_string(msg);
    VLOG_DBG("%s: received unexpected %s message: %s",
             jsonrpc_session_get_name(cs->session),
             jsonrpc_msg_type_to_string(msg->type), s);
    free(s);
}

static struct ovsdb_cs_event *
ovsdb_cs_db_add_event(struct ovsdb_cs_db *db, enum ovsdb_cs_event_type type)
{
    struct ovsdb_cs_event *event = xmalloc(sizeof *event);
    event->type = type;
    ovs_list_push_back(&db->events, &event->list_node);
    return event;
}

/* Processes a batch of messages from the database server on 'cs'.  This may
 * cause the CS's contents to change.
 *
 * Initializes 'events' with a list of events that occurred on 'cs'.  The
 * caller must process and destroy all of the events. */
void
ovsdb_cs_run(struct ovsdb_cs *cs, struct ovs_list *events)
{
    ovs_list_init(events);
    if (!cs->session) {
        return;
    }

    ovsdb_cs_send_cond_change(cs);

    jsonrpc_session_run(cs->session);

    unsigned int seqno = jsonrpc_session_get_seqno(cs->session);
    if (cs->state_seqno != seqno) {
        cs->state_seqno = seqno;
        ovsdb_cs_restart_fsm(cs);

        for (size_t i = 0; i < cs->n_txns; i++) {
            json_destroy(cs->txns[i]);
        }
        cs->n_txns = 0;

        ovsdb_cs_db_add_event(&cs->data, OVSDB_CS_EVENT_TYPE_RECONNECT);

        if (cs->data.lock_name) {
            jsonrpc_session_send(
                cs->session,
                ovsdb_cs_db_compose_lock_request(&cs->data));
        }
    }

    for (int i = 0; i < 50; i++) {
        struct jsonrpc_msg *msg = jsonrpc_session_recv(cs->session);
        if (!msg) {
            break;
        }
        ovsdb_cs_process_msg(cs, msg);
        jsonrpc_msg_destroy(msg);
    }
    ovs_list_push_back_all(events, &cs->data.events);
}

/* Arranges for poll_block() to wake up when ovsdb_cs_run() has something to
 * do or when activity occurs on a transaction on 'cs'. */
void
ovsdb_cs_wait(struct ovsdb_cs *cs)
{
    if (!cs->session) {
        return;
    }
    jsonrpc_session_wait(cs->session);
    jsonrpc_session_recv_wait(cs->session);
}

/* Network connection. */

/* Changes the remote and creates a new session.
 *
 * If 'retry' is true, the connection to the remote will automatically retry
 * when it fails.  If 'retry' is false, the connection is one-time. */
void
ovsdb_cs_set_remote(struct ovsdb_cs *cs, const char *remote, bool retry)
{
    if (cs
        && ((remote != NULL) != (cs->remote != NULL)
            || (remote && cs->remote && strcmp(remote, cs->remote)))) {
        /* Close the old session, if any. */
        if (cs->session) {
            jsonrpc_session_close(cs->session);
            cs->session = NULL;

            free(cs->remote);
            cs->remote = NULL;
        }

        /* Open new session, if any. */
        if (remote) {
            struct svec remotes = SVEC_EMPTY_INITIALIZER;
            ovsdb_session_parse_remote(remote, &remotes, &cs->cid);
            if (cs->shuffle_remotes) {
                svec_shuffle(&remotes);
            }
            cs->session = jsonrpc_session_open_multiple(&remotes, retry);
            svec_destroy(&remotes);

            cs->state_seqno = UINT_MAX;

            cs->remote = xstrdup(remote);
        }
    }
}

/* Reconfigures 'cs' so that it would reconnect to the database, if
 * connection was dropped. */
void
ovsdb_cs_enable_reconnect(struct ovsdb_cs *cs)
{
    if (cs->session) {
        jsonrpc_session_enable_reconnect(cs->session);
    }
}

/* Forces 'cs' to drop its connection to the database and reconnect.  In the
 * meantime, the contents of 'cs' will not change. */
void
ovsdb_cs_force_reconnect(struct ovsdb_cs *cs)
{
    if (cs->session) {
        jsonrpc_session_force_reconnect(cs->session);
    }
}

/* Drops 'cs''s current connection and the cached session.  This is useful if
 * the client notices some kind of inconsistency. */
void
ovsdb_cs_flag_inconsistency(struct ovsdb_cs *cs)
{
    cs->data.last_id = UUID_ZERO;
    ovsdb_cs_retry(cs);
}

/* Returns true if 'cs' is currently connected or will eventually try to
 * reconnect. */
bool
ovsdb_cs_is_alive(const struct ovsdb_cs *cs)
{
    return (cs->session
            && jsonrpc_session_is_alive(cs->session)
            && cs->state != CS_S_ERROR);
}

/* Returns true if 'cs' is currently connected to a server. */
bool
ovsdb_cs_is_connected(const struct ovsdb_cs *cs)
{
    return cs->session && jsonrpc_session_is_connected(cs->session);
}

/* Returns the last error reported on a connection by 'cs'.  The return value
 * is 0 only if no connection made by 'cs' has ever encountered an error and
 * a negative response to a schema request has never been received. See
 * jsonrpc_get_status() for jsonrpc_session_get_last_error() return value
 * interpretation. */
int
ovsdb_cs_get_last_error(const struct ovsdb_cs *cs)
{
    int err = cs->session ? jsonrpc_session_get_last_error(cs->session) : 0;
    if (err) {
        return err;
    } else if (cs->state == CS_S_ERROR) {
        return ENOENT;
    } else {
        return 0;
    }
}

/* Sets the "probe interval" for 'cs''s current session to 'probe_interval', in
 * milliseconds. */
void
ovsdb_cs_set_probe_interval(const struct ovsdb_cs *cs, int probe_interval)
{
    if (cs->session) {
        jsonrpc_session_set_probe_interval(cs->session, probe_interval);
    }
}

/* Conditional monitoring. */

/* A table being monitored.
 *
 * At the CS layer, the only thing we care about, table-wise, is the conditions
 * we're using for monitoring them, so there's little here.  We only create
 * these table structures at all for tables that have conditions. */
struct ovsdb_cs_db_table {
    struct hmap_node hmap_node; /* Indexed by 'name'. */
    char *name;                 /* Table name. */

    /* Each of these is a null pointer if it is empty, or JSON [<condition>*]
     * or [true] or [false] otherwise.  [true] could be represented as a null
     * pointer, but we want to distinguish "empty slot" from "a condition that
     * is always true" in a slot. */
    struct json *ack_cond; /* Last condition acked by the server. */
    struct json *req_cond; /* Last condition requested to the server. */
    struct json *new_cond; /* Latest condition set by the IDL client. */
};

/* A kind of condition, so that we can treat equivalent JSON as equivalent. */
enum condition_type {
    COND_FALSE,                 /* [] or [false] */
    COND_TRUE,                  /* Null pointer or [true] */
    COND_OTHER                  /* Anything else. */
};

/* Returns the condition_type for 'condition'. */
static enum condition_type
condition_classify(const struct json *condition)
{
    if (condition) {
        const struct json_array *a = json_array(condition);
        switch (a->n) {
        case 0:
            return COND_FALSE;

        case 1:
            return (a->elems[0]->type == JSON_FALSE ? COND_FALSE
                    : a->elems[0]->type == JSON_TRUE ? COND_TRUE
                    : COND_OTHER);

        default:
            return COND_OTHER;
        }
    } else {
        return COND_TRUE;
    }
}

/* Returns true if 'a' and 'b' are the same condition (in an obvious way; we're
 * not going to compare for boolean equivalence or anything). */
static bool
condition_equal(const struct json *a, const struct json *b)
{
    enum condition_type type = condition_classify(a);
    return (type == condition_classify(b)
            && (type != COND_OTHER || json_equal(a, b)));
}

/* Returns a clone of 'condition', translating always-true and always-false to
 * [true] and [false], respectively. */
static struct json *
condition_clone(const struct json *condition)
{
    switch (condition_classify(condition)) {
    case COND_TRUE:
        return json_array_create_1(json_boolean_create(true));

    case COND_FALSE:
        return json_array_create_1(json_boolean_create(false));

    case COND_OTHER:
        return json_clone(condition);
    }

    OVS_NOT_REACHED();
}

/* Returns the ovsdb_cs_db_table associated with 'table' in 'db', creating an
 * empty one if necessary. */
static struct ovsdb_cs_db_table *
ovsdb_cs_db_get_table(struct ovsdb_cs_db *db, const char *table)
{
    uint32_t hash = hash_string(table, 0);
    struct ovsdb_cs_db_table *t;

    HMAP_FOR_EACH_WITH_HASH (t, hmap_node, hash, &db->tables) {
        if (!strcmp(t->name, table)) {
            return t;
        }
    }

    t = xzalloc(sizeof *t);
    t->name = xstrdup(table);
    t->new_cond = json_array_create_1(json_boolean_create(true));
    hmap_insert(&db->tables, &t->hmap_node, hash);
    return t;
}

static void
ovsdb_cs_db_destroy_tables(struct ovsdb_cs_db *db)
{
    struct ovsdb_cs_db_table *table, *next;
    HMAP_FOR_EACH_SAFE (table, next, hmap_node, &db->tables) {
        json_destroy(table->ack_cond);
        json_destroy(table->req_cond);
        json_destroy(table->new_cond);
        hmap_remove(&db->tables, &table->hmap_node);
        free(table->name);
        free(table);
    }
    hmap_destroy(&db->tables);
}

static unsigned int
ovsdb_cs_db_set_condition(struct ovsdb_cs_db *db, const char *table,
                          const struct json *condition)
{
    /* Compare the new condition to the last known condition which can be
     * either "new" (not sent yet), "requested" or "acked", in this order. */
    struct ovsdb_cs_db_table *t = ovsdb_cs_db_get_table(db, table);
    const struct json *table_cond = (t->new_cond ? t->new_cond
                                     : t->req_cond ? t->req_cond
                                     : t->ack_cond);
    if (!condition_equal(condition, table_cond)) {
        json_destroy(t->new_cond);
        t->new_cond = condition_clone(condition);
        db->cond_changed = true;
        poll_immediate_wake();
    }

    /* Conditions will be up to date when we receive replies for already
     * requested and new conditions, if any.  This includes condition change
     * requests for other tables too.
     */
    if (t->new_cond) {
        /* New condition will be sent out after all already requested ones
         * are acked.
         */
        bool any_req_cond = false;
        HMAP_FOR_EACH (t, hmap_node, &db->tables) {
            if (t->req_cond) {
                any_req_cond = true;
                break;
            }
        }
        return db->cond_seqno + any_req_cond + 1;
    } else {
        /* Already requested conditions should be up to date at
         * db->cond_seqno + 1 while acked conditions are already up to date.
         */
        return db->cond_seqno + !!t->req_cond;
    }
}

/* Sets the replication condition for 'tc' in 'cs' to 'condition' and arranges
 * to send the new condition to the database server.
 *
 * Return the next conditional update sequence number.  When this value and
 * ovsdb_cs_get_condition_seqno() matches, 'cs' contains rows that match the
 * 'condition'. */
unsigned int
ovsdb_cs_set_condition(struct ovsdb_cs *cs, const char *table,
                       const struct json *condition)
{
    return ovsdb_cs_db_set_condition(&cs->data, table, condition);
}

/* Returns a "sequence number" that represents the number of conditional
 * monitoring updates successfully received by the OVSDB server of a CS
 * connection.
 *
 * ovsdb_cs_set_condition() sets a new condition that is different from the
 * current condtion, the next expected "sequence number" is returned.
 *
 * Whenever ovsdb_cs_get_condition_seqno() returns a value that matches the
 * return value of ovsdb_cs_set_condition(), the client is assured that:
 *
 *   - The ovsdb_cs_set_condition() changes has been acknowledged by the OVSDB
 *     server.
 *
 *   -  'cs' now contains the content matches the new conditions.   */
unsigned int
ovsdb_cs_get_condition_seqno(const struct ovsdb_cs *cs)
{
    return cs->data.cond_seqno;
}

static struct json *
ovsdb_cs_create_cond_change_req(const struct json *cond)
{
    struct json *monitor_cond_change_request = json_object_create();
    json_object_put(monitor_cond_change_request, "where", json_clone(cond));
    return monitor_cond_change_request;
}

static struct jsonrpc_msg *
ovsdb_cs_db_compose_cond_change(struct ovsdb_cs_db *db)
{
    if (!db->cond_changed) {
        return NULL;
    }

    struct json *monitor_cond_change_requests = NULL;
    struct ovsdb_cs_db_table *table;
    HMAP_FOR_EACH (table, hmap_node, &db->tables) {
        /* Always use the most recent conditions set by the CS client when
         * requesting monitor_cond_change, i.e., table->new_cond.
         */
        if (table->new_cond) {
            struct json *req =
                ovsdb_cs_create_cond_change_req(table->new_cond);
            if (req) {
                if (!monitor_cond_change_requests) {
                    monitor_cond_change_requests = json_object_create();
                }
                json_object_put(monitor_cond_change_requests,
                                table->name,
                                json_array_create_1(req));
            }
            /* Mark the new condition as requested by moving it to req_cond.
             * If there's already requested condition that's a bug.
             */
            ovs_assert(table->req_cond == NULL);
            table->req_cond = table->new_cond;
            table->new_cond = NULL;
        }
    }

    if (!monitor_cond_change_requests) {
        return NULL;
    }

    db->cond_changed = false;
    struct json *params = json_array_create_3(json_clone(db->monitor_id),
                                              json_clone(db->monitor_id),
                                              monitor_cond_change_requests);
    return jsonrpc_create_request("monitor_cond_change", params, NULL);
}

/* Marks all requested table conditions in 'db' as acked by the server.
 * It should be called when the server replies to monitor_cond_change
 * requests.
 */
static void
ovsdb_cs_db_ack_condition(struct ovsdb_cs_db *db)
{
    struct ovsdb_cs_db_table *table;
    HMAP_FOR_EACH (table, hmap_node, &db->tables) {
        if (table->req_cond) {
            json_destroy(table->ack_cond);
            table->ack_cond = table->req_cond;
            table->req_cond = NULL;
        }
    }
}

/* Should be called when the CS fsm is restarted and resyncs table conditions
 * based on the state the DB is in:
 * - if a non-zero last_id is available for the DB then upon reconnect
 *   the CS should first request acked conditions to avoid missing updates
 *   about records that were added before the transaction with
 *   txn-id == last_id. If there were requested condition changes in flight
 *   (i.e., req_cond not NULL) and the CS client didn't set new conditions
 *   (i.e., new_cond is NULL) then move req_cond to new_cond to trigger a
 *   follow up monitor_cond_change request.
 * - if there's no last_id available for the DB then it's safe to use the
 *   latest conditions set by the CS client even if they weren't acked yet.
 */
static void
ovsdb_cs_db_sync_condition(struct ovsdb_cs_db *db)
{
    bool ack_all = uuid_is_zero(&db->last_id);
    if (ack_all) {
        db->cond_changed = false;
    }

    struct ovsdb_cs_db_table *table;
    HMAP_FOR_EACH (table, hmap_node, &db->tables) {
        /* When monitor_cond_since requests will be issued, the
         * table->ack_cond condition will be added to the "where" clause".
         * Follow up monitor_cond_change requests will use table->new_cond.
         */
        if (ack_all) {
            if (table->new_cond) {
                json_destroy(table->req_cond);
                table->req_cond = table->new_cond;
                table->new_cond = NULL;
            }

            if (table->req_cond) {
                json_destroy(table->ack_cond);
                table->ack_cond = table->req_cond;
                table->req_cond = NULL;
            }
        } else {
            if (table->req_cond) {
                /* There was an in-flight monitor_cond_change request.  It's no
                 * longer relevant in the restarted FSM, so clear it. */
                if (table->new_cond) {
                    /* We will send a new monitor_cond_change with the new
                     * condition.  The previously in-flight condition is
                     * irrelevant and we can just forget about it. */
                    json_destroy(table->req_cond);
                } else {
                    /* The restarted FSM needs to again send a request for the
                     * previously in-flight condition. */
                    table->new_cond = table->req_cond;
                }
                table->req_cond = NULL;
                db->cond_changed = true;
            }
        }
    }
}

static void
ovsdb_cs_send_cond_change(struct ovsdb_cs *cs)
{
    /* When 'cs->request_id' is not NULL, there is an outstanding
     * conditional monitoring update request that we have not heard
     * from the server yet. Don't generate another request in this case. */
    if (!jsonrpc_session_is_connected(cs->session)
        || cs->data.monitor_version == 1
        || cs->request_id) {
        return;
    }

    struct jsonrpc_msg *msg = ovsdb_cs_db_compose_cond_change(&cs->data);
    if (msg) {
        cs->request_id = json_clone(msg->id);
        jsonrpc_session_send(cs->session, msg);
    }
}

/* Clustered servers. */

/* By default, or if 'leader_only' is true, when 'cs' connects to a clustered
 * database, the CS layer will avoid servers other than the cluster
 * leader. This ensures that any data that it reads and reports is up-to-date.
 * If 'leader_only' is false, the CS layer will accept any server in the
 * cluster, which means that for read-only transactions it can report and act
 * on stale data (transactions that modify the database are always serialized
 * even with false 'leader_only').  Refer to Understanding Cluster Consistency
 * in ovsdb(7) for more information. */
void
ovsdb_cs_set_leader_only(struct ovsdb_cs *cs, bool leader_only)
{
    cs->leader_only = leader_only;
    if (leader_only && cs->server.monitor_version) {
        ovsdb_cs_check_server_db(cs);
    }
}

/* Set whether the order of remotes should be shuffled, when there is more than
 * one remote.  The setting doesn't take effect until the next time when
 * ovsdb_cs_set_remote() is called. */
void
ovsdb_cs_set_shuffle_remotes(struct ovsdb_cs *cs, bool shuffle)
{
    cs->shuffle_remotes = shuffle;
}

/* Reset min_index to 0. This prevents a situation where the client
 * thinks all databases have stale data, when they actually have all
 * been destroyed and rebuilt from scratch.
 */
void
ovsdb_cs_reset_min_index(struct ovsdb_cs *cs)
{
    cs->min_index = 0;
}

/* Database locks. */

static struct jsonrpc_msg *
ovsdb_cs_db_set_lock(struct ovsdb_cs_db *db, const char *lock_name)
{
    if (db->lock_name
        && (!lock_name || strcmp(lock_name, db->lock_name))) {
        /* Release previous lock. */
        struct jsonrpc_msg *msg = ovsdb_cs_db_compose_unlock_request(db);
        free(db->lock_name);
        db->lock_name = NULL;
        db->is_lock_contended = false;
        return msg;
    }

    if (lock_name && !db->lock_name) {
        /* Acquire new lock. */
        db->lock_name = xstrdup(lock_name);
        return ovsdb_cs_db_compose_lock_request(db);
    }

    return NULL;
}

/* If 'lock_name' is nonnull, configures 'cs' to obtain the named lock from the
 * database server and to prevent modifying the database when the lock cannot
 * be acquired (that is, when another client has the same lock).
 *
 * If 'lock_name' is NULL, drops the locking requirement and releases the
 * lock. */
void
ovsdb_cs_set_lock(struct ovsdb_cs *cs, const char *lock_name)
{
    for (;;) {
        struct jsonrpc_msg *msg = ovsdb_cs_db_set_lock(&cs->data, lock_name);
        if (!msg) {
            break;
        }
        if (cs->session) {
            jsonrpc_session_send(cs->session, msg);
        } else {
            jsonrpc_msg_destroy(msg);
        }
    }
}

/* Returns the name of the lock that 'cs' is trying to obtain, or NULL if none
 * is configured. */
const char *
ovsdb_cs_get_lock(const struct ovsdb_cs *cs)
{
    return cs->data.lock_name;
}

/* Returns true if 'cs' is configured to obtain a lock and owns that lock,
 * false if it doesn't own the lock or isn't configured to obtain one.
 *
 * Locking and unlocking happens asynchronously from the database client's
 * point of view, so the information is only useful for optimization (e.g. if
 * the client doesn't have the lock then there's no point in trying to write to
 * the database). */
bool
ovsdb_cs_has_lock(const struct ovsdb_cs *cs)
{
    return cs->data.has_lock;
}

/* Returns true if 'cs' is configured to obtain a lock but the database server
 * has indicated that some other client already owns the requested lock. */
bool
ovsdb_cs_is_lock_contended(const struct ovsdb_cs *cs)
{
    return cs->data.is_lock_contended;
}

static void
ovsdb_cs_db_update_has_lock(struct ovsdb_cs_db *db, bool new_has_lock)
{
    if (new_has_lock && !db->has_lock) {
        ovsdb_cs_db_add_event(db, OVSDB_CS_EVENT_TYPE_LOCKED);
        db->is_lock_contended = false;
    }
    db->has_lock = new_has_lock;
}

static bool
ovsdb_cs_db_process_lock_replies(struct ovsdb_cs_db *db,
                                  const struct jsonrpc_msg *msg)
{
    if (msg->type == JSONRPC_REPLY
        && db->lock_request_id
        && json_equal(db->lock_request_id, msg->id)) {
        /* Reply to our "lock" request. */
        ovsdb_cs_db_parse_lock_reply(db, msg->result);
        return true;
    }

    if (msg->type == JSONRPC_NOTIFY) {
        if (!strcmp(msg->method, "locked")) {
            /* We got our lock. */
            return ovsdb_cs_db_parse_lock_notify(db, msg->params, true);
        } else if (!strcmp(msg->method, "stolen")) {
            /* Someone else stole our lock. */
            return ovsdb_cs_db_parse_lock_notify(db, msg->params, false);
        }
    }

    return false;
}

static struct jsonrpc_msg *
ovsdb_cs_db_compose_lock_request__(struct ovsdb_cs_db *db,
                                    const char *method)
{
    ovsdb_cs_db_update_has_lock(db, false);

    json_destroy(db->lock_request_id);
    db->lock_request_id = NULL;

    struct json *params = json_array_create_1(json_string_create(
                                                  db->lock_name));
    return jsonrpc_create_request(method, params, NULL);
}

static struct jsonrpc_msg *
ovsdb_cs_db_compose_lock_request(struct ovsdb_cs_db *db)
{
    struct jsonrpc_msg *msg = ovsdb_cs_db_compose_lock_request__(db, "lock");
    db->lock_request_id = json_clone(msg->id);
    return msg;
}

static struct jsonrpc_msg *
ovsdb_cs_db_compose_unlock_request(struct ovsdb_cs_db *db)
{
    return ovsdb_cs_db_compose_lock_request__(db, "unlock");
}

static void
ovsdb_cs_db_parse_lock_reply(struct ovsdb_cs_db *db,
                              const struct json *result)
{
    bool got_lock;

    json_destroy(db->lock_request_id);
    db->lock_request_id = NULL;

    if (result->type == JSON_OBJECT) {
        const struct json *locked;

        locked = shash_find_data(json_object(result), "locked");
        got_lock = locked && locked->type == JSON_TRUE;
    } else {
        got_lock = false;
    }

    ovsdb_cs_db_update_has_lock(db, got_lock);
    if (!got_lock) {
        db->is_lock_contended = true;
    }
}

static bool
ovsdb_cs_db_parse_lock_notify(struct ovsdb_cs_db *db,
                               const struct json *params,
                               bool new_has_lock)
{
    if (db->lock_name
        && params->type == JSON_ARRAY
        && json_array(params)->n > 0
        && json_array(params)->elems[0]->type == JSON_STRING) {
        const char *lock_name = json_string(json_array(params)->elems[0]);

        if (!strcmp(db->lock_name, lock_name)) {
            ovsdb_cs_db_update_has_lock(db, new_has_lock);
            if (!new_has_lock) {
                db->is_lock_contended = true;
            }
            return true;
        }
    }
    return false;
}

/* Transactions. */

static bool
ovsdb_cs_db_txn_process_reply(struct ovsdb_cs *cs,
                              const struct jsonrpc_msg *reply)
{
    bool found = ovsdb_cs_forget_transaction(cs, reply->id);
    if (found) {
        struct ovsdb_cs_event *event
            = ovsdb_cs_db_add_event(&cs->data, OVSDB_CS_EVENT_TYPE_TXN_REPLY);
        event->txn_reply = jsonrpc_msg_clone(reply);
    }
    return found;
}

/* Returns true if 'cs' can be sent a transaction now, false otherwise.  This
 * is useful for optimization: there is no point in composing and sending a
 * transaction if it returns false. */
bool
ovsdb_cs_may_send_transaction(const struct ovsdb_cs *cs)
{
    return (cs->session != NULL
            && cs->state == CS_S_MONITORING
            && (!cs->data.lock_name || ovsdb_cs_has_lock(cs)));
}

/* Attempts to send a transaction with the specified 'operations' to 'cs''s
 * server.  On success, returns the request ID; the caller must eventually free
 * it.  On failure, returns NULL. */
struct json * OVS_WARN_UNUSED_RESULT
ovsdb_cs_send_transaction(struct ovsdb_cs *cs, struct json *operations)
{
    if (!ovsdb_cs_may_send_transaction(cs)) {
        json_destroy(operations);
        return NULL;
    }

    if (cs->data.lock_name) {
        struct json *assertion = json_object_create();
        json_object_put_string(assertion, "op", "assert");
        json_object_put_string(assertion, "lock", cs->data.lock_name);
        json_array_add(operations, assertion);
    }

    struct json *request_id;
    struct jsonrpc_msg *request = jsonrpc_create_request(
        "transact", operations, &request_id);
    int error = jsonrpc_session_send(cs->session, request);
    if (error) {
        json_destroy(request_id);
        return NULL;
    }

    if (cs->n_txns >= cs->allocated_txns) {
        cs->txns = x2nrealloc(cs->txns, &cs->allocated_txns,
                              sizeof *cs->txns);
    }
    cs->txns[cs->n_txns++] = request_id;
    return json_clone(request_id);
}

/* Makes 'cs' drop its record of transaction 'request_id'.  If a reply arrives
 * for it later (which it will, unless the connection drops in the meantime),
 * it won't be reported through an event.
 *
 * Returns true if 'request_id' was known, false otherwise. */
bool
ovsdb_cs_forget_transaction(struct ovsdb_cs *cs, const struct json *request_id)
{
    for (size_t i = 0; i < cs->n_txns; i++) {
        if (json_equal(request_id, cs->txns[i])) {
            json_destroy(cs->txns[i]);
            cs->txns[i] = cs->txns[--cs->n_txns];
            return true;
        }
    }
    return false;
}

static void
ovsdb_cs_send_schema_request(struct ovsdb_cs *cs,
                              struct ovsdb_cs_db *db)
{
    ovsdb_cs_send_request(cs, jsonrpc_create_request(
                               "get_schema",
                               json_array_create_1(json_string_create(
                                                       db->db_name)),
                               NULL));
}

static void
ovsdb_cs_send_db_change_aware(struct ovsdb_cs *cs)
{
    struct jsonrpc_msg *msg = jsonrpc_create_request(
        "set_db_change_aware", json_array_create_1(json_boolean_create(true)),
        NULL);
    jsonrpc_session_send(cs->session, msg);
}

static void
ovsdb_cs_send_monitor_request(struct ovsdb_cs *cs, struct ovsdb_cs_db *db,
                              int version)
{
    struct json *mrs = db->ops->compose_monitor_requests(
        db->schema, db->ops_aux);
    /* XXX handle failure */
    ovs_assert(mrs->type == JSON_OBJECT);

    if (version > 1) {
        struct ovsdb_cs_db_table *table;
        HMAP_FOR_EACH (table, hmap_node, &db->tables) {
            if (table->ack_cond) {
                struct json *mr = shash_find_data(json_object(mrs),
                                                  table->name);
                if (!mr) {
                    mr = json_array_create_empty();
                    json_object_put(mrs, table->name, mr);
                }
                ovs_assert(mr->type == JSON_ARRAY);

                struct json *mr0;
                if (json_array(mr)->n == 0) {
                    mr0 = json_object_create();
                    json_object_put(mr0, "columns", json_array_create_empty());
                    json_array_add(mr, mr0);
                } else {
                    mr0 = json_array(mr)->elems[0];
                }
                ovs_assert(mr0->type == JSON_OBJECT);

                json_object_put(mr0, "where",
                                json_clone(table->ack_cond));
            }
        }
    }

    const char *method = (version == 1 ? "monitor"
                          : version == 2 ? "monitor_cond"
                          : "monitor_cond_since");
    struct json *params = json_array_create_3(
                              json_string_create(db->db_name),
                              json_clone(db->monitor_id),
                              mrs);
    if (version == 3) {
        struct json *json_last_id = json_string_create_nocopy(
            xasprintf(UUID_FMT, UUID_ARGS(&db->last_id)));
        json_array_add(params, json_last_id);
    }
    ovsdb_cs_send_request(cs, jsonrpc_create_request(method, params, NULL));
}

static void
log_parse_update_error(struct ovsdb_error *error)
{
    if (!VLOG_DROP_WARN(&syntax_rl)) {
        char *s = ovsdb_error_to_string(error);
        VLOG_WARN_RL(&syntax_rl, "%s", s);
        free(s);
    }
    ovsdb_error_destroy(error);
}

static void
ovsdb_cs_db_add_update(struct ovsdb_cs_db *db,
                       const struct json *table_updates, int version,
                       bool clear, bool monitor_reply)
{
    struct ovsdb_cs_event *event = ovsdb_cs_db_add_event(
        db, OVSDB_CS_EVENT_TYPE_UPDATE);
    event->update = (struct ovsdb_cs_update_event) {
        .table_updates = json_clone(table_updates),
        .clear = clear,
        .monitor_reply = monitor_reply,
        .version = version,
    };
}

static void
ovsdb_cs_db_parse_monitor_reply(struct ovsdb_cs_db *db,
                                const struct json *result, int version)
{
    const struct json *table_updates;
    bool clear;
    if (version == 3) {
        struct uuid last_id;
        if (result->type != JSON_ARRAY || result->array.n != 3
            || (result->array.elems[0]->type != JSON_TRUE &&
                result->array.elems[0]->type != JSON_FALSE)
            || result->array.elems[1]->type != JSON_STRING
            || !uuid_from_string(&last_id,
                                 json_string(result->array.elems[1]))) {
            struct ovsdb_error *error = ovsdb_syntax_error(
                result, NULL, "bad monitor_cond_since reply format");
            log_parse_update_error(error);
            return;
        }

        bool found = json_boolean(result->array.elems[0]);
        clear = !found;
        table_updates = result->array.elems[2];
    } else {
        clear = true;
        table_updates = result;
    }

    ovsdb_cs_db_add_update(db, table_updates, version, clear, true);
}

static bool
ovsdb_cs_db_parse_update_rpc(struct ovsdb_cs_db *db,
                             const struct jsonrpc_msg *msg)
{
    if (msg->type != JSONRPC_NOTIFY) {
        return false;
    }

    int version = (!strcmp(msg->method, "update") ? 1
                   : !strcmp(msg->method, "update2") ? 2
                   : !strcmp(msg->method, "update3") ? 3
                   : 0);
    if (!version) {
        return false;
    }

    struct json *params = msg->params;
    int n = version == 3 ? 3 : 2;
    if (params->type != JSON_ARRAY || params->array.n != n) {
        struct ovsdb_error *error = ovsdb_syntax_error(
            params, NULL, "%s must be an array with %u elements.",
            msg->method, n);
        log_parse_update_error(error);
        return false;
    }

    if (!json_equal(params->array.elems[0], db->monitor_id)) {
        return false;
    }

    if (version == 3) {
        const char *last_id = json_string(params->array.elems[1]);
        if (!uuid_from_string(&db->last_id, last_id)) {
            struct ovsdb_error *error = ovsdb_syntax_error(
                params, NULL, "Last-id %s is not in UUID format.", last_id);
            log_parse_update_error(error);
            return false;
        }
    }

    struct json *table_updates = params->array.elems[version == 3 ? 2 : 1];
    ovsdb_cs_db_add_update(db, table_updates, version, false, false);
    return true;
}

static bool
ovsdb_cs_handle_monitor_canceled(struct ovsdb_cs *cs,
                                 struct ovsdb_cs_db *db,
                                 const struct jsonrpc_msg *msg)
{
    if (msg->type != JSONRPC_NOTIFY
        || strcmp(msg->method, "monitor_canceled")
        || msg->params->type != JSON_ARRAY
        || msg->params->array.n != 1
        || !json_equal(msg->params->array.elems[0], db->monitor_id)) {
        return false;
    }

    db->monitor_version = 0;

    /* Cancel the other monitor and restart the FSM from the top.
     *
     * Maybe a more sophisticated response would be better in some cases, but
     * it doesn't seem worth optimizing yet.  (Although this is already more
     * sophisticated than just dropping the connection and reconnecting.) */
    struct ovsdb_cs_db *other_db
        = db == &cs->data ? &cs->server : &cs->data;
    if (other_db->monitor_version) {
        jsonrpc_session_send(
            cs->session,
            jsonrpc_create_request(
                "monitor_cancel",
                json_array_create_1(json_clone(other_db->monitor_id)), NULL));
        other_db->monitor_version = 0;
    }
    ovsdb_cs_restart_fsm(cs);

    return true;
}

/* The _Server database.
 *
 * We replicate the Database table in the _Server database because this is the
 * only way to find out properties we need to know for clustering, such as
 * whether a database is clustered at all and whether this server is the
 * leader.
 *
 * This code implements a kind of simple IDL-like layer. */

struct server_column {
    const char *name;
    struct ovsdb_type type;
};
enum server_column_index {
    COL_NAME,
    COL_MODEL,
    COL_CONNECTED,
    COL_LEADER,
    COL_SCHEMA,
    COL_CID,
    COL_INDEX,
};
#define OPTIONAL_COLUMN(TYPE) \
    {                                           \
        .key = OVSDB_BASE_##TYPE##_INIT,        \
        .value = OVSDB_BASE_VOID_INIT,          \
        .n_min = 0,                             \
        .n_max = 1                              \
    }
static const struct server_column server_columns[] = {
    [COL_NAME] = {"name",  OPTIONAL_COLUMN(STRING) },
    [COL_MODEL] = {"model", OPTIONAL_COLUMN(STRING) },
    [COL_CONNECTED] = {"connected", OPTIONAL_COLUMN(BOOLEAN) },
    [COL_LEADER] = {"leader", OPTIONAL_COLUMN(BOOLEAN) },
    [COL_SCHEMA] = {"schema", OPTIONAL_COLUMN(STRING) },
    [COL_CID] = {"cid", OPTIONAL_COLUMN(UUID) },
    [COL_INDEX] = {"index", OPTIONAL_COLUMN(INTEGER) },
};
#define N_SERVER_COLUMNS ARRAY_SIZE(server_columns)
struct server_row {
    struct hmap_node hmap_node;
    struct uuid uuid;
    struct ovsdb_datum data[N_SERVER_COLUMNS];
};

static void
server_row_destroy(struct server_row *row)
{
    if (row) {
        for (size_t i = 0; i < N_SERVER_COLUMNS; i++) {
            ovsdb_datum_destroy(&row->data[i], &server_columns[i].type);
        }
        free(row);
    }
}

static struct server_row *
ovsdb_cs_find_server_row(struct ovsdb_cs *cs, const struct uuid *uuid)
{
    struct server_row *row;
    HMAP_FOR_EACH (row, hmap_node, &cs->server_rows) {
        if (uuid_equals(uuid, &row->uuid)) {
            return row;
        }
    }
    return NULL;
}

static void
ovsdb_cs_delete_server_row(struct ovsdb_cs *cs, struct server_row *row)
{
    hmap_remove(&cs->server_rows, &row->hmap_node);
    server_row_destroy(row);
}

static struct server_row *
ovsdb_cs_insert_server_row(struct ovsdb_cs *cs, const struct uuid *uuid)
{
    struct server_row *row = xmalloc(sizeof *row);
    hmap_insert(&cs->server_rows, &row->hmap_node, uuid_hash(uuid));
    row->uuid = *uuid;
    for (size_t i = 0; i < N_SERVER_COLUMNS; i++) {
        ovsdb_datum_init_default(&row->data[i], &server_columns[i].type);
    }
    return row;
}

static void
ovsdb_cs_update_server_row(struct server_row *row,
                           const struct shash *update, bool xor)
{
    for (size_t i = 0; i < N_SERVER_COLUMNS; i++) {
        const struct server_column *column = &server_columns[i];
        struct shash_node *node = shash_find(update, column->name);
        if (!node) {
            continue;
        }
        const struct json *json = node->data;

        struct ovsdb_datum *old = &row->data[i];
        struct ovsdb_datum new;
        if (!xor) {
            struct ovsdb_error *error = ovsdb_datum_from_json(
                &new, &column->type, json, NULL);
            if (error) {
                ovsdb_error_destroy(error);
                continue;
            }
        } else {
            struct ovsdb_datum diff;
            struct ovsdb_error *error = ovsdb_transient_datum_from_json(
                &diff, &column->type, json);
            if (error) {
                ovsdb_error_destroy(error);
                continue;
            }

            error = ovsdb_datum_apply_diff(&new, old, &diff, &column->type);
            if (error) {
                ovsdb_error_destroy(error);
                ovsdb_datum_destroy(&new, &column->type);
                continue;
            }
            ovsdb_datum_destroy(&diff, &column->type);
        }

        ovsdb_datum_destroy(&row->data[i], &column->type);
        row->data[i] = new;
    }
}

static void
ovsdb_cs_clear_server_rows(struct ovsdb_cs *cs)
{
    struct server_row *row, *next;
    HMAP_FOR_EACH_SAFE (row, next, hmap_node, &cs->server_rows) {
        ovsdb_cs_delete_server_row(cs, row);
    }
}

static void log_parse_update_error(struct ovsdb_error *);

static void
ovsdb_cs_process_server_event(struct ovsdb_cs *cs,
                              const struct ovsdb_cs_event *event)
{
    ovs_assert(event->type == OVSDB_CS_EVENT_TYPE_UPDATE);

    const struct ovsdb_cs_update_event *update = &event->update;
    struct ovsdb_cs_db_update *du;
    struct ovsdb_error *error = ovsdb_cs_parse_db_update(
        update->table_updates, update->version, &du);
    if (error) {
        log_parse_update_error(error);
        return;
    }

    if (update->clear) {
        ovsdb_cs_clear_server_rows(cs);
    }

    const struct ovsdb_cs_table_update *tu = ovsdb_cs_db_update_find_table(
        du, "Database");
    if (tu) {
        for (size_t i = 0; i < tu->n; i++) {
            const struct ovsdb_cs_row_update *ru = &tu->row_updates[i];
            struct server_row *row
                = ovsdb_cs_find_server_row(cs, &ru->row_uuid);
            if (ru->type == OVSDB_CS_ROW_DELETE) {
                ovsdb_cs_delete_server_row(cs, row);
            } else {
                if (!row) {
                    row = ovsdb_cs_insert_server_row(cs, &ru->row_uuid);
                }
                ovsdb_cs_update_server_row(row, ru->columns,
                                           ru->type == OVSDB_CS_ROW_XOR);
            }
        }
    }

    ovsdb_cs_db_update_destroy(du);
}

static const char *
server_column_get_string(const struct server_row *row,
                         enum server_column_index index,
                         const char *default_value)
{
    ovs_assert(server_columns[index].type.key.type == OVSDB_TYPE_STRING);
    const struct ovsdb_datum *d = &row->data[index];
    return d->n == 1 ? d->keys[0].string : default_value;
}

static bool
server_column_get_bool(const struct server_row *row,
                       enum server_column_index index,
                       bool default_value)
{
    ovs_assert(server_columns[index].type.key.type == OVSDB_TYPE_BOOLEAN);
    const struct ovsdb_datum *d = &row->data[index];
    return d->n == 1 ? d->keys[0].boolean : default_value;
}

static uint64_t
server_column_get_int(const struct server_row *row,
                      enum server_column_index index,
                      uint64_t default_value)
{
    ovs_assert(server_columns[index].type.key.type == OVSDB_TYPE_INTEGER);
    const struct ovsdb_datum *d = &row->data[index];
    return d->n == 1 ? d->keys[0].integer : default_value;
}

static const struct uuid *
server_column_get_uuid(const struct server_row *row,
                       enum server_column_index index,
                       const struct uuid *default_value)
{
    ovs_assert(server_columns[index].type.key.type == OVSDB_TYPE_UUID);
    const struct ovsdb_datum *d = &row->data[index];
    return d->n == 1 ? &d->keys[0].uuid : default_value;
}

static const struct server_row *
ovsdb_find_server_row(struct ovsdb_cs *cs)
{
    const struct server_row *row;
    HMAP_FOR_EACH (row, hmap_node, &cs->server_rows) {
        const struct uuid *cid = server_column_get_uuid(row, COL_CID, NULL);
        const char *name = server_column_get_string(row, COL_NAME, NULL);
        if (uuid_is_zero(&cs->cid)
            ? (name && !strcmp(cs->data.db_name, name))
            : (cid && uuid_equals(cid, &cs->cid))) {
            return row;
        }
    }
    return NULL;
}

static void OVS_UNUSED
ovsdb_log_server_rows(const struct ovsdb_cs *cs)
{
    int row_num = 0;
    const struct server_row *row;
    HMAP_FOR_EACH (row, hmap_node, &cs->server_rows) {
        struct ds s = DS_EMPTY_INITIALIZER;
        for (size_t i = 0; i < N_SERVER_COLUMNS; i++) {
            ds_put_format(&s, " %s=", server_columns[i].name);
            if (i == COL_SCHEMA) {
                ds_put_format(&s, "...");
            } else {
                ovsdb_datum_to_string(&row->data[i], &server_columns[i].type,
                                      &s);
            }
        }
        VLOG_INFO("row %d:%s", row_num++, ds_cstr(&s));
        ds_destroy(&s);
    }
}

static bool
ovsdb_cs_check_server_db__(struct ovsdb_cs *cs)
{
    struct ovsdb_cs_event *event;
    LIST_FOR_EACH_POP (event, list_node, &cs->server.events) {
        ovsdb_cs_process_server_event(cs, event);
        ovsdb_cs_event_destroy(event);
    }

    const struct server_row *db_row = ovsdb_find_server_row(cs);
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    const char *server_name = jsonrpc_session_get_name(cs->session);
    if (!db_row) {
        VLOG_INFO_RL(&rl, "%s: server does not have %s database",
                     server_name, cs->data.db_name);
        return false;
    }

    bool ok = false;
    const char *model = server_column_get_string(db_row, COL_MODEL, "");
    const char *schema = server_column_get_string(db_row, COL_SCHEMA, NULL);
    if (!strcmp(model, "clustered")) {
        bool connected = server_column_get_bool(db_row, COL_CONNECTED, false);
        bool leader = server_column_get_bool(db_row, COL_LEADER, false);
        uint64_t index = server_column_get_int(db_row, COL_INDEX, 0);

        if (!schema) {
            VLOG_INFO("%s: clustered database server has not yet joined "
                      "cluster; trying another server", server_name);
        } else if (!connected) {
            VLOG_INFO("%s: clustered database server is disconnected "
                      "from cluster; trying another server", server_name);
        } else if (cs->leader_only && !leader) {
            VLOG_INFO("%s: clustered database server is not cluster "
                      "leader; trying another server", server_name);
        } else if (index < cs->min_index) {
            VLOG_WARN("%s: clustered database server has stale data; "
                      "trying another server", server_name);
        } else {
            cs->min_index = index;
            ok = true;
        }
    } else {
        if (!schema) {
            VLOG_INFO("%s: missing database schema", server_name);
        } else {
            ok = true;
        }
    }
    if (!ok) {
        return false;
    }

    if (cs->state == CS_S_SERVER_MONITOR_REQUESTED) {
        json_destroy(cs->data.schema);
        cs->data.schema = json_from_string(schema);
        if (cs->data.max_version >= 3) {
            ovsdb_cs_send_monitor_request(cs, &cs->data, 3);
            ovsdb_cs_transition(cs, CS_S_DATA_MONITOR_COND_SINCE_REQUESTED);
        } else if (cs->data.max_version >= 2) {
            ovsdb_cs_send_monitor_request(cs, &cs->data, 2);
            ovsdb_cs_transition(cs, CS_S_DATA_MONITOR_COND_REQUESTED);
        } else {
            ovsdb_cs_send_monitor_request(cs, &cs->data, 1);
            ovsdb_cs_transition(cs, CS_S_DATA_MONITOR_REQUESTED);
        }
    }
    return true;
}

static bool
ovsdb_cs_check_server_db(struct ovsdb_cs *cs)
{
    bool ok = ovsdb_cs_check_server_db__(cs);
    if (!ok) {
        ovsdb_cs_retry(cs);
    }
    return ok;
}

static struct json *
ovsdb_cs_compose_server_monitor_request(const struct json *schema_json,
                                        void *cs_)
{
    struct ovsdb_cs *cs = cs_;
    struct shash *schema = ovsdb_cs_parse_schema(schema_json);
    struct json *monitor_requests = json_object_create();

    const char *table_name = "Database";
    const struct sset *table_schema
        = schema ? shash_find_data(schema, table_name) : NULL;
    if (!table_schema) {
        VLOG_WARN("%s database lacks %s table "
                  "(database needs upgrade?)",
                  cs->server.db_name, table_name);
        /* XXX return failure? */
    } else {
        struct json *columns = json_array_create_empty();
        for (size_t j = 0; j < N_SERVER_COLUMNS; j++) {
            const struct server_column *column = &server_columns[j];
            bool db_has_column = (table_schema &&
                                  sset_contains(table_schema, column->name));
            if (table_schema && !db_has_column) {
                VLOG_WARN("%s table in %s database lacks %s column "
                          "(database needs upgrade?)",
                          table_name, cs->server.db_name, column->name);
                continue;
            }
            json_array_add(columns, json_string_create(column->name));
        }

        struct json *monitor_request = json_object_create();
        json_object_put(monitor_request, "columns", columns);
        json_object_put(monitor_requests, table_name,
                        json_array_create_1(monitor_request));
    }
    ovsdb_cs_free_schema(schema);

    return monitor_requests;
}

static const struct ovsdb_cs_ops ovsdb_cs_server_ops = {
    ovsdb_cs_compose_server_monitor_request
};

static void
log_error(struct ovsdb_error *error)
{
    char *s = ovsdb_error_to_string_free(error);
    VLOG_WARN("error parsing database schema: %s", s);
    free(s);
}

/* Parses 'schema_json', an OVSDB schema in JSON format as described in RFC
 * 7047, to obtain the names of its rows and columns.  If successful, returns
 * an shash whose keys are table names and whose values are ssets, where each
 * sset contains the names of its table's columns.  On failure (due to a parse
 * error), returns NULL.
 *
 * It would also be possible to use the general-purpose OVSDB schema parser in
 * ovsdb-server, but that's overkill, possibly too strict for the current use
 * case, and would require restructuring ovsdb-server to separate the schema
 * code from the rest. */
struct shash *
ovsdb_cs_parse_schema(const struct json *schema_json)
{
    struct ovsdb_parser parser;
    const struct json *tables_json;
    struct ovsdb_error *error;
    struct shash_node *node;
    struct shash *schema;

    ovsdb_parser_init(&parser, schema_json, "database schema");
    tables_json = ovsdb_parser_member(&parser, "tables", OP_OBJECT);
    error = ovsdb_parser_destroy(&parser);
    if (error) {
        log_error(error);
        return NULL;
    }

    schema = xmalloc(sizeof *schema);
    shash_init(schema);
    SHASH_FOR_EACH (node, json_object(tables_json)) {
        const char *table_name = node->name;
        const struct json *json = node->data;
        const struct json *columns_json;

        ovsdb_parser_init(&parser, json, "table schema for table %s",
                          table_name);
        columns_json = ovsdb_parser_member(&parser, "columns", OP_OBJECT);
        error = ovsdb_parser_destroy(&parser);
        if (error) {
            log_error(error);
            ovsdb_cs_free_schema(schema);
            return NULL;
        }

        struct sset *columns = xmalloc(sizeof *columns);
        sset_init(columns);

        struct shash_node *node2;
        SHASH_FOR_EACH (node2, json_object(columns_json)) {
            const char *column_name = node2->name;
            sset_add(columns, column_name);
        }
        shash_add(schema, table_name, columns);
    }
    return schema;
}

/* Frees 'schema', which is in the format returned by
 * ovsdb_cs_parse_schema(). */
void
ovsdb_cs_free_schema(struct shash *schema)
{
    if (schema) {
        struct shash_node *node, *next;

        SHASH_FOR_EACH_SAFE (node, next, schema) {
            struct sset *sset = node->data;
            sset_destroy(sset);
            free(sset);
            shash_delete(schema, node);
        }
        shash_destroy(schema);
        free(schema);
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_row_update1(const struct json *in,
                           struct ovsdb_cs_row_update *out)
{
    const struct json *old_json, *new_json;

    old_json = shash_find_data(json_object(in), "old");
    new_json = shash_find_data(json_object(in), "new");
    if (old_json && old_json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(old_json, NULL,
                                  "\"old\" <row> is not object");
    } else if (new_json && new_json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(new_json, NULL,
                                  "\"new\" <row> is not object");
    } else if ((old_json != NULL) + (new_json != NULL)
               != shash_count(json_object(in))) {
        return ovsdb_syntax_error(in, NULL,
                                  "<row-update> contains "
                                  "unexpected member");
    } else if (!old_json && !new_json) {
        return ovsdb_syntax_error(in, NULL,
                                  "<row-update> missing \"old\" "
                                  "and \"new\" members");
    }

    if (!new_json) {
        out->type = OVSDB_CS_ROW_DELETE;
        out->columns = json_object(old_json);
    } else if (!old_json) {
        out->type = OVSDB_CS_ROW_INSERT;
        out->columns = json_object(new_json);
    } else {
        out->type = OVSDB_CS_ROW_UPDATE;
        out->columns = json_object(new_json);
    }
    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_row_update2(const struct json *in,
                           struct ovsdb_cs_row_update *out)
{
    const struct shash *object = json_object(in);
    if (shash_count(object) != 1) {
        return ovsdb_syntax_error(
            in, NULL, "<row-update2> has %"PRIuSIZE" members "
            "instead of expected 1", shash_count(object));
    }

    struct shash_node *node = shash_first(object);
    const struct json *columns = node->data;
    if (!strcmp(node->name, "insert") || !strcmp(node->name, "initial")) {
        out->type = OVSDB_CS_ROW_INSERT;
    } else if (!strcmp(node->name, "modify")) {
        out->type = OVSDB_CS_ROW_XOR;
    } else if (!strcmp(node->name, "delete")) {
        out->type = OVSDB_CS_ROW_DELETE;
        if (columns->type != JSON_NULL) {
            return ovsdb_syntax_error(
                in, NULL,
                "<row-update2> delete operation has unexpected value");
        }
        return NULL;
    } else {
        return ovsdb_syntax_error(in, NULL,
                                  "<row-update2> has unknown member \"%s\"",
                                  node->name);
    }

    if (columns->type != JSON_OBJECT) {
        return ovsdb_syntax_error(
            in, NULL,
            "<row-update2> \"%s\" operation has unexpected value",
            node->name);
    }
    out->columns = json_object(columns);

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_row_update(const char *table_name,
                          const struct json *in, int version,
                          struct ovsdb_cs_row_update *out)
{
    if (in->type != JSON_OBJECT) {
        const char *suffix = version > 1 ? "2" : "";
        return ovsdb_syntax_error(
            in, NULL,
            "<table-update%s> for table \"%s\" contains <row-update%s> "
            "that is not an object",
            suffix, table_name, suffix);
    }

    return (version == 1
            ? ovsdb_cs_parse_row_update1(in, out)
            : ovsdb_cs_parse_row_update2(in, out));
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_table_update(const char *table_name,
                            const struct json *in, int version,
                            struct ovsdb_cs_table_update *out)
{
    const char *suffix = version > 1 ? "2" : "";

    if (in->type != JSON_OBJECT) {
        return ovsdb_syntax_error(
            in, NULL, "<table-update%s> for table \"%s\" is not an object",
            suffix, table_name);
    }
    struct shash *in_rows = json_object(in);

    out->row_updates = xmalloc(shash_count(in_rows) * sizeof *out->row_updates);

    const struct shash_node *node;
    SHASH_FOR_EACH (node, in_rows) {
        const char *row_uuid_string = node->name;
        struct uuid row_uuid;
        if (!uuid_from_string(&row_uuid, row_uuid_string)) {
            return ovsdb_syntax_error(
                in, NULL,
                "<table-update%s> for table \"%s\" contains "
                "bad UUID \"%s\" as member name",
                suffix, table_name, row_uuid_string);
        }

        const struct json *in_ru = node->data;
        struct ovsdb_cs_row_update *out_ru = &out->row_updates[out->n++];
        *out_ru = (struct ovsdb_cs_row_update) { .row_uuid = row_uuid };

        struct ovsdb_error *error = ovsdb_cs_parse_row_update(
            table_name, in_ru, version, out_ru);
        if (error) {
            return error;
        }
    }

    return NULL;
}

/* Parses OVSDB <table-updates> or <table-updates2> object 'in' into '*outp'.
 * If successful, sets '*outp' to the new object and returns NULL.  On failure,
 * returns the error and sets '*outp' to NULL.
 *
 * On success, the caller must eventually free '*outp', with
 * ovsdb_cs_db_update_destroy().
 *
 * 'version' should be 1 if 'in' is a <table-updates>, 2 or 3 if it is a
 * <table-updates2>. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_db_update(const struct json *in, int version,
                         struct ovsdb_cs_db_update **outp)
{
    const char *suffix = version > 1 ? "2" : "";

    *outp = NULL;
    if (in->type != JSON_OBJECT) {
        return ovsdb_syntax_error(in, NULL,
                                  "<table-updates%s> is not an object", suffix);
    }

    struct ovsdb_cs_db_update *out = xzalloc(sizeof *out);
    out->table_updates = xmalloc(shash_count(json_object(in))
                                 * sizeof *out->table_updates);
    const struct shash_node *node;
    SHASH_FOR_EACH (node, json_object(in)) {
        const char *table_name = node->name;
        const struct json *in_tu = node->data;

        struct ovsdb_cs_table_update *out_tu = &out->table_updates[out->n++];
        *out_tu = (struct ovsdb_cs_table_update) { .table_name = table_name };

        struct ovsdb_error *error = ovsdb_cs_parse_table_update(
            table_name, in_tu, version, out_tu);
        if (error) {
            ovsdb_cs_db_update_destroy(out);
            return error;
        }
    }

    *outp = out;
    return NULL;
}

/* Frees 'du', which was presumably allocated by ovsdb_cs_parse_db_update(). */
void
ovsdb_cs_db_update_destroy(struct ovsdb_cs_db_update *du)
{
    if (!du) {
        return;
    }

    for (size_t i = 0; i < du->n; i++) {
        struct ovsdb_cs_table_update *tu = &du->table_updates[i];
        free(tu->row_updates);
    }
    free(du->table_updates);
    free(du);
}

const struct ovsdb_cs_table_update *
ovsdb_cs_db_update_find_table(const struct ovsdb_cs_db_update *du,
                              const char *table_name)
{
    for (size_t i = 0; i < du->n; i++) {
        const struct ovsdb_cs_table_update *tu = &du->table_updates[i];
        if (!strcmp(tu->table_name, table_name)) {
            return tu;
        }
    }
    return NULL;
}

