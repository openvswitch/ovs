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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "ovsdb-idl.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

#include "bitmap.h"
#include "coverage.h"
#include "hash.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "ovsdb/ovsdb.h"
#include "ovsdb/table.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-idl-provider.h"
#include "ovsdb-parser.h"
#include "ovsdb-server-idl.h"
#include "ovsdb-session.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "skiplist.h"
#include "sset.h"
#include "svec.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_idl);

COVERAGE_DEFINE(txn_uncommitted);
COVERAGE_DEFINE(txn_unchanged);
COVERAGE_DEFINE(txn_incomplete);
COVERAGE_DEFINE(txn_aborted);
COVERAGE_DEFINE(txn_success);
COVERAGE_DEFINE(txn_try_again);
COVERAGE_DEFINE(txn_not_locked);
COVERAGE_DEFINE(txn_error);

/* An arc from one idl_row to another.  When row A contains a UUID that
 * references row B, this is represented by an arc from A (the source) to B
 * (the destination).
 *
 * Arcs from a row to itself are omitted, that is, src and dst are always
 * different.
 *
 * Arcs are never duplicated, that is, even if there are multiple references
 * from A to B, there is only a single arc from A to B.
 *
 * Arcs are directed: an arc from A to B is the converse of an an arc from B to
 * A.  Both an arc and its converse may both be present, if each row refers
 * to the other circularly.
 *
 * The source and destination row may be in the same table or in different
 * tables.
 */
struct ovsdb_idl_arc {
    struct ovs_list src_node;   /* In src->src_arcs list. */
    struct ovs_list dst_node;   /* In dst->dst_arcs list. */
    struct ovsdb_idl_row *src;  /* Source row. */
    struct ovsdb_idl_row *dst;  /* Destination row. */
};

/* Connection state machine.
 *
 * When a JSON-RPC session connects, the IDL sends a "monitor_cond" request for
 * the Database table in the _Server database and transitions to the
 * IDL_S_SERVER_MONITOR_COND_REQUESTED state.  If the session drops and
 * reconnects, or if the IDL receives a "monitor_canceled" notification for a
 * table it is monitoring, the IDL starts over again in the same way. */
#define OVSDB_IDL_STATES                                                \
    /* Waits for "get_schema" reply, then sends "monitor_cond"          \
     * request for the Database table in the _Server database, whose    \
     * details are informed by the schema, and transitions to           \
     * IDL_S_SERVER_MONITOR_COND_REQUESTED. */                          \
    OVSDB_IDL_STATE(SERVER_SCHEMA_REQUESTED)                            \
                                                                        \
    /* Waits for "monitor_cond" reply for the Database table:           \
     *                                                                  \
     * - If the reply indicates success, and the Database table has a   \
     *   row for the IDL database:                                      \
     *                                                                  \
     *   * If the row indicates that this is a clustered database       \
     *     that is not connected to the cluster, closes the             \
     *     connection.  The next connection attempt has a chance at     \
     *     picking a connected server.                                  \
     *                                                                  \
     *   * Otherwise, sends a "monitor_cond" request for the IDL        \
     *     database whose details are informed by the schema            \
     *     (obtained from the row), and transitions to                  \
     *     IDL_S_DATA_MONITOR_COND_REQUESTED.                           \
     *                                                                  \
     * - If the reply indicates success, but the Database table does    \
     *   not have a row for the IDL database, transitions to            \
     *   IDL_S_ERROR.                                                   \
     *                                                                  \
     * - If the reply indicates failure, sends a "get_schema" request   \
     *   for the IDL database and transitions to                        \
     *   IDL_S_DATA_SCHEMA_REQUESTED. */                                \
    OVSDB_IDL_STATE(SERVER_MONITOR_COND_REQUESTED)                      \
                                                                        \
    /* Waits for "get_schema" reply, then sends "monitor_cond"          \
     * request whose details are informed by the schema, and            \
     * transitions to IDL_S_DATA_MONITOR_COND_REQUESTED. */             \
    OVSDB_IDL_STATE(DATA_SCHEMA_REQUESTED)                              \
                                                                        \
    /* Waits for "monitor_cond" reply.  If successful, replaces the     \
     * IDL contents by the data carried in the reply and transitions    \
     * to IDL_S_MONITORING.  On failure, sends a "monitor" request      \
     * and transitions to IDL_S_DATA_MONITOR_REQUESTED. */              \
    OVSDB_IDL_STATE(DATA_MONITOR_COND_REQUESTED)                        \
                                                                        \
    /* Waits for "monitor" reply.  If successful, replaces the IDL      \
     * contents by the data carried in the reply and transitions to     \
     * IDL_S_MONITORING.  On failure, transitions to IDL_S_ERROR. */    \
    OVSDB_IDL_STATE(DATA_MONITOR_REQUESTED)                             \
                                                                        \
    /* State that processes "update" or "update2" notifications for     \
     * the main database (and the Database table in _Server if          \
     * available).                                                      \
     *                                                                  \
     * If we're monitoring the Database table and we get notified       \
     * that the IDL database has been deleted, we close the             \
     * connection (which will restart the state machine). */            \
    OVSDB_IDL_STATE(MONITORING)                                         \
                                                                        \
    /* Terminal error state that indicates that nothing useful can be   \
     * done, for example because the database server doesn't actually   \
     * have the desired database.  We maintain the session with the     \
     * database server anyway.  If it starts serving the database       \
     * that we want, or if someone fixes and restarts the database,     \
     * then it will kill the session and we will automatically          \
     * reconnect and try again. */                                      \
    OVSDB_IDL_STATE(ERROR)                                              \
                                                                        \
    /* Terminal state that indicates we connected to a useless server   \
     * in a cluster, e.g. one that is partitioned from the rest of      \
     * the cluster. We're waiting to retry. */                          \
    OVSDB_IDL_STATE(RETRY)

enum ovsdb_idl_state {
#define OVSDB_IDL_STATE(NAME) IDL_S_##NAME,
    OVSDB_IDL_STATES
#undef OVSDB_IDL_STATE
};

static const char *ovsdb_idl_state_to_string(enum ovsdb_idl_state);

enum ovsdb_idl_monitoring {
    OVSDB_IDL_NOT_MONITORING,   /* Database is not being monitored. */
    OVSDB_IDL_MONITORING,       /* Database has "monitor" outstanding. */
    OVSDB_IDL_MONITORING_COND,  /* Database has "monitor_cond" outstanding. */
};

struct ovsdb_idl_db {
    struct ovsdb_idl *idl;

    /* Data. */
    const struct ovsdb_idl_class *class_;
    struct shash table_by_name; /* Contains "struct ovsdb_idl_table *"s.*/
    struct ovsdb_idl_table *tables; /* Array of ->class_->n_tables elements. */
    struct json *monitor_id;
    unsigned int change_seqno;
    struct ovsdb_idl_txn *txn;
    struct hmap outstanding_txns;
    bool verify_write_only;
    struct json *schema;
    enum ovsdb_idl_monitoring monitoring;

    /* True if any of the tables' monitoring conditions has changed. */
    bool cond_changed;

    unsigned int cond_seqno;   /* Keep track of condition clauses changes
                                  over a single conditional monitoring session.
                                  Reverts to zero when idl session
                                  reconnects.  */

    /* Database locking. */
    char *lock_name;            /* Name of lock we need, NULL if none. */
    bool has_lock;              /* Has db server told us we have the lock? */
    bool is_lock_contended;     /* Has db server told us we can't get lock? */
    struct json *lock_request_id; /* JSON-RPC ID of in-flight lock request. */
};

static void ovsdb_idl_db_track_clear(struct ovsdb_idl_db *);
static void ovsdb_idl_db_add_column(struct ovsdb_idl_db *,
                                    const struct ovsdb_idl_column *);
static void ovsdb_idl_db_omit(struct ovsdb_idl_db *,
                              const struct ovsdb_idl_column *);
static void ovsdb_idl_db_omit_alert(struct ovsdb_idl_db *,
                                    const struct ovsdb_idl_column *);
static unsigned int ovsdb_idl_db_set_condition(
    struct ovsdb_idl_db *, const struct ovsdb_idl_table_class *,
    const struct ovsdb_idl_condition *);

static void ovsdb_idl_send_schema_request(struct ovsdb_idl *,
                                          struct ovsdb_idl_db *);
static void ovsdb_idl_send_db_change_aware(struct ovsdb_idl *);
static bool ovsdb_idl_check_server_db(struct ovsdb_idl *);
static void ovsdb_idl_send_monitor_request(struct ovsdb_idl *,
                                           struct ovsdb_idl_db *,
                                           bool use_monitor_cond);

struct ovsdb_idl {
    struct ovsdb_idl_db server;
    struct ovsdb_idl_db data;

    /* Session state.
     *
     *'state_seqno' is a snapshot of the session's sequence number as returned
     * jsonrpc_session_get_seqno(session), so if it differs from the value that
     * function currently returns then the session has reconnected and the
     * state machine must restart.  */
    struct jsonrpc_session *session; /* Connection to the server. */
    enum ovsdb_idl_state state;      /* Current session state. */
    unsigned int state_seqno;        /* See above. */
    struct json *request_id;         /* JSON ID for request awaiting reply. */

    struct uuid cid;

    uint64_t min_index;
    bool leader_only;
};

static void ovsdb_idl_transition_at(struct ovsdb_idl *, enum ovsdb_idl_state,
                                    const char *where);
#define ovsdb_idl_transition(IDL, STATE) \
    ovsdb_idl_transition_at(IDL, STATE, OVS_SOURCE_LOCATOR)

static void ovsdb_idl_retry_at(struct ovsdb_idl *, const char *where);
#define ovsdb_idl_retry(IDL) ovsdb_idl_retry_at(IDL, OVS_SOURCE_LOCATOR)

struct ovsdb_idl_txn {
    struct hmap_node hmap_node;
    struct json *request_id;
    struct ovsdb_idl_db *db;
    struct hmap txn_rows;
    enum ovsdb_idl_txn_status status;
    char *error;
    bool dry_run;
    struct ds comment;

    /* Increments. */
    const char *inc_table;
    const char *inc_column;
    struct uuid inc_row;
    bool inc_force;
    unsigned int inc_index;
    int64_t inc_new_value;

    /* Inserted rows. */
    struct hmap inserted_rows;  /* Contains "struct ovsdb_idl_txn_insert"s. */
};

struct ovsdb_idl_txn_insert {
    struct hmap_node hmap_node; /* In struct ovsdb_idl_txn's inserted_rows. */
    struct uuid dummy;          /* Dummy UUID used locally. */
    int op_index;               /* Index into transaction's operation array. */
    struct uuid real;           /* Real UUID used by database server. */
};

static struct vlog_rate_limit syntax_rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct vlog_rate_limit semantic_rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct vlog_rate_limit other_rl = VLOG_RATE_LIMIT_INIT(1, 5);

static void ovsdb_idl_clear(struct ovsdb_idl *);
static void ovsdb_idl_db_parse_monitor_reply(struct ovsdb_idl_db *,
                                             const struct json *result,
                                             bool is_monitor_cond);
static bool ovsdb_idl_db_parse_update_rpc(struct ovsdb_idl_db *,
                                          const struct jsonrpc_msg *);
static bool ovsdb_idl_handle_monitor_canceled(struct ovsdb_idl *,
                                              struct ovsdb_idl_db *,
                                              const struct jsonrpc_msg *);
static void ovsdb_idl_db_parse_update(struct ovsdb_idl_db *,
                                      const struct json *table_updates,
                                      bool is_monitor_cond);
static bool ovsdb_idl_process_update(struct ovsdb_idl_table *,
                                     const struct uuid *,
                                     const struct json *old,
                                     const struct json *new);
static bool ovsdb_idl_process_update2(struct ovsdb_idl_table *,
                                      const struct uuid *,
                                      const char *operation,
                                      const struct json *row);
static void ovsdb_idl_insert_row(struct ovsdb_idl_row *, const struct json *);
static void ovsdb_idl_delete_row(struct ovsdb_idl_row *);
static bool ovsdb_idl_modify_row(struct ovsdb_idl_row *, const struct json *);
static bool ovsdb_idl_modify_row_by_diff(struct ovsdb_idl_row *,
                                         const struct json *);

static bool ovsdb_idl_row_is_orphan(const struct ovsdb_idl_row *);
static struct ovsdb_idl_row *ovsdb_idl_row_create__(
    const struct ovsdb_idl_table_class *);
static struct ovsdb_idl_row *ovsdb_idl_row_create(struct ovsdb_idl_table *,
                                                  const struct uuid *);
static void ovsdb_idl_row_destroy(struct ovsdb_idl_row *);
static void ovsdb_idl_row_destroy_postprocess(struct ovsdb_idl_db *);
static void ovsdb_idl_destroy_all_map_op_lists(struct ovsdb_idl_row *);
static void ovsdb_idl_destroy_all_set_op_lists(struct ovsdb_idl_row *);

static void ovsdb_idl_row_parse(struct ovsdb_idl_row *);
static void ovsdb_idl_row_unparse(struct ovsdb_idl_row *);
static void ovsdb_idl_row_clear_old(struct ovsdb_idl_row *);
static void ovsdb_idl_row_clear_new(struct ovsdb_idl_row *);
static void ovsdb_idl_row_clear_arcs(struct ovsdb_idl_row *, bool destroy_dsts);

static void ovsdb_idl_db_txn_abort_all(struct ovsdb_idl_db *);
static void ovsdb_idl_txn_abort_all(struct ovsdb_idl *);
static bool ovsdb_idl_db_txn_process_reply(struct ovsdb_idl_db *,
                                           const struct jsonrpc_msg *msg);
static bool ovsdb_idl_txn_extract_mutations(struct ovsdb_idl_row *,
                                            struct json *);
static void ovsdb_idl_txn_add_map_op(struct ovsdb_idl_row *,
                                     const struct ovsdb_idl_column *,
                                     struct ovsdb_datum *,
                                     enum map_op_type);
static void ovsdb_idl_txn_add_set_op(struct ovsdb_idl_row *,
                                     const struct ovsdb_idl_column *,
                                     struct ovsdb_datum *,
                                     enum set_op_type);

static bool ovsdb_idl_db_process_lock_replies(struct ovsdb_idl_db *,
                                              const struct jsonrpc_msg *);
static struct jsonrpc_msg *ovsdb_idl_db_compose_lock_request(
    struct ovsdb_idl_db *);
static struct jsonrpc_msg *ovsdb_idl_db_compose_unlock_request(
    struct ovsdb_idl_db *);
static void ovsdb_idl_db_parse_lock_reply(struct ovsdb_idl_db *,
                                          const struct json *);
static bool ovsdb_idl_db_parse_lock_notify(struct ovsdb_idl_db *,
                                           const struct json *params,
                                           bool new_has_lock);
static struct ovsdb_idl_table *
ovsdb_idl_db_table_from_class(const struct ovsdb_idl_db *,
                              const struct ovsdb_idl_table_class *);
static struct ovsdb_idl_table *
ovsdb_idl_table_from_class(const struct ovsdb_idl *,
                           const struct ovsdb_idl_table_class *);
static bool ovsdb_idl_track_is_set(struct ovsdb_idl_table *table);
static void ovsdb_idl_send_cond_change(struct ovsdb_idl *idl);

static void ovsdb_idl_destroy_indexes(struct ovsdb_idl_table *);
static void ovsdb_idl_add_to_indexes(const struct ovsdb_idl_row *);
static void ovsdb_idl_remove_from_indexes(const struct ovsdb_idl_row *);

static void
ovsdb_idl_open_session(struct ovsdb_idl *idl, const char *remote, bool retry)
{
    ovs_assert(!idl->data.txn);
    jsonrpc_session_close(idl->session);

    struct svec remotes = SVEC_EMPTY_INITIALIZER;
    ovsdb_session_parse_remote(remote, &remotes, &idl->cid);
    idl->session = jsonrpc_session_open_multiple(&remotes, retry);
    svec_destroy(&remotes);
}

static void
ovsdb_idl_db_init(struct ovsdb_idl_db *db, const struct ovsdb_idl_class *class,
                  struct ovsdb_idl *parent, bool monitor_everything_by_default)
{
    memset(db, 0, sizeof *db);

    uint8_t default_mode = (monitor_everything_by_default
                            ? OVSDB_IDL_MONITOR | OVSDB_IDL_ALERT
                            : 0);

    db->idl = parent;
    db->class_ = class;
    shash_init(&db->table_by_name);
    db->tables = xmalloc(class->n_tables * sizeof *db->tables);
    for (size_t i = 0; i < class->n_tables; i++) {
        const struct ovsdb_idl_table_class *tc = &class->tables[i];
        struct ovsdb_idl_table *table = &db->tables[i];

        shash_add_assert(&db->table_by_name, tc->name, table);
        table->class_ = tc;
        table->modes = xmalloc(tc->n_columns);
        memset(table->modes, default_mode, tc->n_columns);
        table->need_table = false;
        shash_init(&table->columns);
        ovs_list_init(&table->indexes);
        for (size_t j = 0; j < tc->n_columns; j++) {
            const struct ovsdb_idl_column *column = &tc->columns[j];

            shash_add_assert(&table->columns, column->name, column);
        }
        hmap_init(&table->rows);
        ovs_list_init(&table->track_list);
        table->change_seqno[OVSDB_IDL_CHANGE_INSERT]
            = table->change_seqno[OVSDB_IDL_CHANGE_MODIFY]
            = table->change_seqno[OVSDB_IDL_CHANGE_DELETE] = 0;
        table->db = db;
        ovsdb_idl_condition_init(&table->condition);
        ovsdb_idl_condition_add_clause_true(&table->condition);
        table->cond_changed = false;
    }
    db->monitor_id = json_array_create_2(json_string_create("monid"),
                                         json_string_create(class->database));
    hmap_init(&db->outstanding_txns);
}

/* Creates and returns a connection to database 'remote', which should be in a
 * form acceptable to jsonrpc_session_open().  The connection will maintain an
 * in-memory replica of the remote database whose schema is described by
 * 'class'.  (Ordinarily 'class' is compiled from an OVSDB schema automatically
 * by ovsdb-idlc.)
 *
 * Passes 'retry' to jsonrpc_session_open().  See that function for
 * documentation.
 *
 * If 'monitor_everything_by_default' is true, then everything in the remote
 * database will be replicated by default.  ovsdb_idl_omit() and
 * ovsdb_idl_omit_alert() may be used to selectively drop some columns from
 * monitoring.
 *
 * If 'monitor_everything_by_default' is false, then no columns or tables will
 * be replicated by default.  ovsdb_idl_add_column() and ovsdb_idl_add_table()
 * must be used to choose some columns or tables to replicate.
 */
struct ovsdb_idl *
ovsdb_idl_create(const char *remote, const struct ovsdb_idl_class *class,
                 bool monitor_everything_by_default, bool retry)
{
    struct ovsdb_idl *idl;

    idl = xzalloc(sizeof *idl);
    ovsdb_idl_db_init(&idl->server, &serverrec_idl_class, idl, true);
    ovsdb_idl_db_init(&idl->data, class, idl, monitor_everything_by_default);
    ovsdb_idl_open_session(idl, remote, retry);
    idl->state_seqno = UINT_MAX;
    idl->request_id = NULL;
    idl->leader_only = true;

    /* Monitor the Database table in the _Server database.
     *
     * We monitor only the row for 'class', or the row that has the
     * desired 'cid'. */
    struct ovsdb_idl_condition cond;
    ovsdb_idl_condition_init(&cond);
    if (!uuid_is_zero(&idl->cid)) {
        serverrec_database_add_clause_cid(&cond, OVSDB_F_EQ, &idl->cid, 1);
    } else {
        serverrec_database_add_clause_name(&cond, OVSDB_F_EQ, class->database);
    }
    ovsdb_idl_db_set_condition(&idl->server, &serverrec_table_database, &cond);
    ovsdb_idl_condition_destroy(&cond);

    return idl;
}

/* Changes the remote and creates a new session. */
void
ovsdb_idl_set_remote(struct ovsdb_idl *idl, const char *remote,
                     bool retry)
{
    if (idl) {
        ovsdb_idl_open_session(idl, remote, retry);
        idl->state_seqno = UINT_MAX;
    }
}

static void
ovsdb_idl_db_destroy(struct ovsdb_idl_db *db)
{
    ovs_assert(!db->txn);
    ovsdb_idl_db_txn_abort_all(db);
    for (size_t i = 0; i < db->class_->n_tables; i++) {
        struct ovsdb_idl_table *table = &db->tables[i];
        ovsdb_idl_condition_destroy(&table->condition);
        ovsdb_idl_destroy_indexes(table);
        shash_destroy(&table->columns);
        hmap_destroy(&table->rows);
        free(table->modes);
    }
    shash_destroy(&db->table_by_name);
    free(db->tables);
    json_destroy(db->schema);
    hmap_destroy(&db->outstanding_txns);
    free(db->lock_name);
    json_destroy(db->lock_request_id);
    json_destroy(db->monitor_id);
}

/* Destroys 'idl' and all of the data structures that it manages. */
void
ovsdb_idl_destroy(struct ovsdb_idl *idl)
{
    if (idl) {
        ovsdb_idl_clear(idl);
        jsonrpc_session_close(idl->session);

        ovsdb_idl_db_destroy(&idl->server);
        ovsdb_idl_db_destroy(&idl->data);
        json_destroy(idl->request_id);
        free(idl);
    }
}

void
ovsdb_idl_set_leader_only(struct ovsdb_idl *idl, bool leader_only)
{
    idl->leader_only = leader_only;
    if (leader_only && idl->server.monitoring) {
        ovsdb_idl_check_server_db(idl);
    }
}

static void
ovsdb_idl_db_clear(struct ovsdb_idl_db *db)
{
    bool changed = false;
    size_t i;

    for (i = 0; i < db->class_->n_tables; i++) {
        struct ovsdb_idl_table *table = &db->tables[i];
        struct ovsdb_idl_row *row, *next_row;

        table->cond_changed = false;
        if (hmap_is_empty(&table->rows)) {
            continue;
        }

        changed = true;
        HMAP_FOR_EACH_SAFE (row, next_row, hmap_node, &table->rows) {
            struct ovsdb_idl_arc *arc, *next_arc;

            if (!ovsdb_idl_row_is_orphan(row)) {
                ovsdb_idl_remove_from_indexes(row);
                ovsdb_idl_row_unparse(row);
            }
            LIST_FOR_EACH_SAFE (arc, next_arc, src_node, &row->src_arcs) {
                free(arc);
            }
            /* No need to do anything with dst_arcs: some node has those arcs
             * as forward arcs and will destroy them itself. */

            if (!ovs_list_is_empty(&row->track_node)) {
                ovs_list_remove(&row->track_node);
            }

            ovsdb_idl_row_destroy(row);
        }
    }

    db->cond_changed = false;
    db->cond_seqno = 0;
    ovsdb_idl_db_track_clear(db);

    if (changed) {
        db->change_seqno++;
    }
}

static const char *
ovsdb_idl_state_to_string(enum ovsdb_idl_state state)
{
    switch (state) {
#define OVSDB_IDL_STATE(NAME) case IDL_S_##NAME: return #NAME;
        OVSDB_IDL_STATES
#undef OVSDB_IDL_STATE
    default: return "<unknown>";
    }
}

static void
ovsdb_idl_retry_at(struct ovsdb_idl *idl, const char *where)
{
    if (jsonrpc_session_get_n_remotes(idl->session) > 1) {
        ovsdb_idl_force_reconnect(idl);
        ovsdb_idl_transition_at(idl, IDL_S_RETRY, where);
    } else {
        ovsdb_idl_transition_at(idl, IDL_S_ERROR, where);
    }
}

static void
ovsdb_idl_transition_at(struct ovsdb_idl *idl, enum ovsdb_idl_state new_state,
                        const char *where)
{
    VLOG_DBG("%s: %s -> %s at %s",
             jsonrpc_session_get_name(idl->session),
             ovsdb_idl_state_to_string(idl->state),
             ovsdb_idl_state_to_string(new_state),
             where);
    idl->state = new_state;
}

static void
ovsdb_idl_clear(struct ovsdb_idl *idl)
{
    ovsdb_idl_db_clear(&idl->data);
}

static void
ovsdb_idl_send_request(struct ovsdb_idl *idl, struct jsonrpc_msg *request)
{
    json_destroy(idl->request_id);
    idl->request_id = json_clone(request->id);
    jsonrpc_session_send(idl->session, request);
}

static void
ovsdb_idl_restart_fsm(struct ovsdb_idl *idl)
{
    ovsdb_idl_send_schema_request(idl, &idl->server);
    ovsdb_idl_transition(idl, IDL_S_SERVER_SCHEMA_REQUESTED);
    idl->data.monitoring = OVSDB_IDL_NOT_MONITORING;
    idl->server.monitoring = OVSDB_IDL_NOT_MONITORING;
}

static void
ovsdb_idl_process_response(struct ovsdb_idl *idl, struct jsonrpc_msg *msg)
{
    bool ok = msg->type == JSONRPC_REPLY;
    if (!ok
        && idl->state != IDL_S_SERVER_SCHEMA_REQUESTED
        && idl->state != IDL_S_SERVER_MONITOR_COND_REQUESTED
        && idl->state != IDL_S_DATA_MONITOR_COND_REQUESTED) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        char *s = jsonrpc_msg_to_string(msg);
        VLOG_INFO_RL(&rl, "%s: received unexpected %s response in "
                     "%s state: %s", jsonrpc_session_get_name(idl->session),
                     jsonrpc_msg_type_to_string(msg->type),
                     ovsdb_idl_state_to_string(idl->state),
                     s);
        free(s);
        ovsdb_idl_retry(idl);
        return;
    }

    switch (idl->state) {
    case IDL_S_SERVER_SCHEMA_REQUESTED:
        if (ok) {
            json_destroy(idl->server.schema);
            idl->server.schema = json_clone(msg->result);
            ovsdb_idl_send_monitor_request(idl, &idl->server, true);
            ovsdb_idl_transition(idl, IDL_S_SERVER_MONITOR_COND_REQUESTED);
        } else {
            ovsdb_idl_send_schema_request(idl, &idl->data);
            ovsdb_idl_transition(idl, IDL_S_DATA_SCHEMA_REQUESTED);
        }
        break;

    case IDL_S_SERVER_MONITOR_COND_REQUESTED:
        if (ok) {
            idl->server.monitoring = OVSDB_IDL_MONITORING_COND;
            ovsdb_idl_db_parse_monitor_reply(&idl->server, msg->result, true);
            if (ovsdb_idl_check_server_db(idl)) {
                ovsdb_idl_send_db_change_aware(idl);
            }
        } else {
            ovsdb_idl_send_schema_request(idl, &idl->data);
            ovsdb_idl_transition(idl, IDL_S_DATA_SCHEMA_REQUESTED);
        }
        break;

    case IDL_S_DATA_SCHEMA_REQUESTED:
        json_destroy(idl->data.schema);
        idl->data.schema = json_clone(msg->result);
        ovsdb_idl_send_monitor_request(idl, &idl->data, true);
        ovsdb_idl_transition(idl, IDL_S_DATA_MONITOR_COND_REQUESTED);
        break;

    case IDL_S_DATA_MONITOR_COND_REQUESTED:
        if (!ok) {
            /* "monitor_cond" not supported.  Try "monitor". */
            ovsdb_idl_send_monitor_request(idl, &idl->data, false);
            ovsdb_idl_transition(idl, IDL_S_DATA_MONITOR_REQUESTED);
        } else {
            idl->data.monitoring = OVSDB_IDL_MONITORING_COND;
            ovsdb_idl_transition(idl, IDL_S_MONITORING);
            ovsdb_idl_db_parse_monitor_reply(&idl->data, msg->result, true);
        }
        break;

    case IDL_S_DATA_MONITOR_REQUESTED:
        idl->data.monitoring = OVSDB_IDL_MONITORING;
        ovsdb_idl_transition(idl, IDL_S_MONITORING);
        ovsdb_idl_db_parse_monitor_reply(&idl->data, msg->result, false);
        idl->data.change_seqno++;
        ovsdb_idl_clear(idl);
        ovsdb_idl_db_parse_update(&idl->data, msg->result, false);
        break;

    case IDL_S_MONITORING:
        /* We don't normally have a request outstanding in this state.  If we
         * do, it's a "monitor_cond_change", which means that the conditional
         * monitor clauses were updated.
         *
         * If further condition changes were pending, send them now. */
        ovsdb_idl_send_cond_change(idl);
        idl->data.cond_seqno++;
        break;

    case IDL_S_ERROR:
    case IDL_S_RETRY:
        /* Nothing to do in this state. */
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static void
ovsdb_idl_process_msg(struct ovsdb_idl *idl, struct jsonrpc_msg *msg)
{
    bool is_response = (msg->type == JSONRPC_REPLY ||
                        msg->type == JSONRPC_ERROR);

    /* Process a reply to an outstanding request. */
    if (is_response
        && idl->request_id && json_equal(idl->request_id, msg->id)) {
        json_destroy(idl->request_id);
        idl->request_id = NULL;
        ovsdb_idl_process_response(idl, msg);
        return;
    }

    /* Process database contents updates. */
    if (ovsdb_idl_db_parse_update_rpc(&idl->data, msg)) {
        return;
    }
    if (idl->server.monitoring
        && ovsdb_idl_db_parse_update_rpc(&idl->server, msg)) {
        ovsdb_idl_check_server_db(idl);
        return;
    }

    if (ovsdb_idl_handle_monitor_canceled(idl, &idl->data, msg)
        || (idl->server.monitoring
            && ovsdb_idl_handle_monitor_canceled(idl, &idl->server, msg))) {
        return;
    }

    /* Process "lock" replies and related notifications. */
    if (ovsdb_idl_db_process_lock_replies(&idl->data, msg)) {
        return;
    }

    /* Process response to a database transaction we submitted. */
    if (is_response && ovsdb_idl_db_txn_process_reply(&idl->data, msg)) {
        return;
    }

    /* Unknown message.  Log at a low level because this can happen if
     * ovsdb_idl_txn_destroy() is called to destroy a transaction
     * before we receive the reply.
     *
     * (We could sort those out from other kinds of unknown messages by
     * using distinctive IDs for transactions, if it seems valuable to
     * do so, and then it would be possible to use different log
     * levels. XXX?) */
    char *s = jsonrpc_msg_to_string(msg);
    VLOG_DBG("%s: received unexpected %s message: %s",
             jsonrpc_session_get_name(idl->session),
             jsonrpc_msg_type_to_string(msg->type), s);
    free(s);
}

/* Processes a batch of messages from the database server on 'idl'.  This may
 * cause the IDL's contents to change.  The client may check for that with
 * ovsdb_idl_get_seqno(). */
void
ovsdb_idl_run(struct ovsdb_idl *idl)
{
    int i;

    ovs_assert(!idl->data.txn);

    ovsdb_idl_send_cond_change(idl);

    jsonrpc_session_run(idl->session);
    for (i = 0; jsonrpc_session_is_connected(idl->session) && i < 50; i++) {
        struct jsonrpc_msg *msg;
        unsigned int seqno;

        seqno = jsonrpc_session_get_seqno(idl->session);
        if (idl->state_seqno != seqno) {
            idl->state_seqno = seqno;
            ovsdb_idl_txn_abort_all(idl);
            ovsdb_idl_restart_fsm(idl);

            if (idl->data.lock_name) {
                jsonrpc_session_send(
                    idl->session,
                    ovsdb_idl_db_compose_lock_request(&idl->data));
            }
        }

        msg = jsonrpc_session_recv(idl->session);
        if (!msg) {
            break;
        }
        ovsdb_idl_process_msg(idl, msg);
        jsonrpc_msg_destroy(msg);
    }
    ovsdb_idl_row_destroy_postprocess(&idl->data);
}

/* Arranges for poll_block() to wake up when ovsdb_idl_run() has something to
 * do or when activity occurs on a transaction on 'idl'. */
void
ovsdb_idl_wait(struct ovsdb_idl *idl)
{
    jsonrpc_session_wait(idl->session);
    jsonrpc_session_recv_wait(idl->session);
}

/* Returns a "sequence number" that represents the state of 'idl'.  When
 * ovsdb_idl_run() changes the database, the sequence number changes.  The
 * initial fetch of the entire contents of the remote database is considered to
 * be one kind of change.  Successfully acquiring a lock, if one has been
 * configured with ovsdb_idl_set_lock(), is also considered to be a change.
 *
 * As long as the sequence number does not change, the client may continue to
 * use any data structures it obtains from 'idl'.  But when it changes, the
 * client must not access any of these data structures again, because they
 * could have freed or reused for other purposes.
 *
 * The sequence number can occasionally change even if the database does not.
 * This happens if the connection to the database drops and reconnects, which
 * causes the database contents to be reloaded even if they didn't change.  (It
 * could also happen if the database server sends out a "change" that reflects
 * what the IDL already thought was in the database.  The database server is
 * not supposed to do that, but bugs could in theory cause it to do so.) */
unsigned int
ovsdb_idl_get_seqno(const struct ovsdb_idl *idl)
{
    return idl->data.change_seqno;
}

/* Returns a "sequence number" that represents the number of conditional
 * monitoring updates successfully received by the OVSDB server of an IDL
 * connection.
 *
 * ovsdb_idl_set_condition() sets a new condition that is different from
 * the current condtion, the next expected "sequence number" is returned.
 *
 * Whenever ovsdb_idl_get_cond_seqno() returns a value that matches
 * the return value of ovsdb_idl_set_condition(),  The client is
 * assured that:
 *   -  The ovsdb_idl_set_condition() changes has been acknowledged by
 *      the OVSDB sever.
 *
 *   -  'idl' now contains the content matches the new conditions.   */
unsigned int
ovsdb_idl_get_condition_seqno(const struct ovsdb_idl *idl)
{
    return idl->data.cond_seqno;
}

/* Returns true if 'idl' successfully connected to the remote database and
 * retrieved its contents (even if the connection subsequently dropped and is
 * in the process of reconnecting).  If so, then 'idl' contains an atomic
 * snapshot of the database's contents (but it might be arbitrarily old if the
 * connection dropped).
 *
 * Returns false if 'idl' has never connected or retrieved the database's
 * contents.  If so, 'idl' is empty. */
bool
ovsdb_idl_has_ever_connected(const struct ovsdb_idl *idl)
{
    return ovsdb_idl_get_seqno(idl) != 0;
}

/* Reconfigures 'idl' so that it would reconnect to the database, if
 * connection was dropped. */
void
ovsdb_idl_enable_reconnect(struct ovsdb_idl *idl)
{
    jsonrpc_session_enable_reconnect(idl->session);
}

/* Forces 'idl' to drop its connection to the database and reconnect.  In the
 * meantime, the contents of 'idl' will not change. */
void
ovsdb_idl_force_reconnect(struct ovsdb_idl *idl)
{
    jsonrpc_session_force_reconnect(idl->session);
}

/* Some IDL users should only write to write-only columns.  Furthermore,
 * writing to a column which is not write-only can cause serious performance
 * degradations for these users.  This function causes 'idl' to reject writes
 * to columns which are not marked write only using ovsdb_idl_omit_alert(). */
void
ovsdb_idl_verify_write_only(struct ovsdb_idl *idl)
{
    idl->data.verify_write_only = true;
}

/* Returns true if 'idl' is currently connected or trying to connect
 * and a negative response to a schema request has not been received */
bool
ovsdb_idl_is_alive(const struct ovsdb_idl *idl)
{
    return jsonrpc_session_is_alive(idl->session) &&
           idl->state != IDL_S_ERROR;
}

/* Returns the last error reported on a connection by 'idl'.  The return value
 * is 0 only if no connection made by 'idl' has ever encountered an error and
 * a negative response to a schema request has never been received. See
 * jsonrpc_get_status() for jsonrpc_session_get_last_error() return value
 * interpretation. */
int
ovsdb_idl_get_last_error(const struct ovsdb_idl *idl)
{
    int err;

    err = jsonrpc_session_get_last_error(idl->session);

    if (err) {
        return err;
    } else if (idl->state == IDL_S_ERROR) {
        return ENOENT;
    } else {
        return 0;
    }
}

/* Sets the "probe interval" for 'idl->session' to 'probe_interval', in
 * milliseconds.
 */
void
ovsdb_idl_set_probe_interval(const struct ovsdb_idl *idl, int probe_interval)
{
    jsonrpc_session_set_probe_interval(idl->session, probe_interval);
}

static size_t
find_uuid_in_array(const struct uuid *target,
                   const struct uuid *array, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (uuid_equals(&array[i], target)) {
            return i;
        }
    }
    return SIZE_MAX;
}

static size_t
array_contains_uuid(const struct uuid *target,
                    const struct uuid *array, size_t n)
{
    return find_uuid_in_array(target, array, n) != SIZE_MAX;
}

static bool
remove_uuid_from_array(const struct uuid *target,
                       struct uuid *array, size_t *n)
{
    size_t i = find_uuid_in_array(target, array, *n);
    if (i != SIZE_MAX) {
        array[i] = array[--*n];
        return true;
    } else {
        return false;
    }
}

static void
add_row_references(const struct ovsdb_base_type *type,
                   const union ovsdb_atom *atoms, size_t n_atoms,
                   const struct uuid *exclude_uuid,
                   struct uuid **dstsp, size_t *n_dstsp,
                   size_t *allocated_dstsp)
{
    if (type->type != OVSDB_TYPE_UUID || !type->uuid.refTableName) {
        return;
    }

    for (size_t i = 0; i < n_atoms; i++) {
        const struct uuid *uuid = &atoms[i].uuid;
        if (!uuid_equals(uuid, exclude_uuid)
            && !array_contains_uuid(uuid, *dstsp, *n_dstsp)) {
            if (*n_dstsp >= *allocated_dstsp) {
                *dstsp = x2nrealloc(*dstsp, allocated_dstsp,
                                    sizeof **dstsp);

            }
            (*dstsp)[*n_dstsp] = *uuid;
            ++*n_dstsp;
        }
    }
}

/* Checks for consistency in 'idl''s graph of arcs between database rows.  Each
 * reference from one row to a different row should be reflected as a "struct
 * ovsdb_idl_arc" between those rows.
 *
 * This function is slow, big-O wise, and aborts if it finds an inconsistency,
 * thus it is only for use in test programs. */
void
ovsdb_idl_check_consistency(const struct ovsdb_idl *idl)
{
    /* Consistency is broken while a transaction is in progress. */
    if (!idl->data.txn) {
        return;
    }

    bool ok = true;

    struct uuid *dsts = NULL;
    size_t allocated_dsts = 0;

    for (size_t i = 0; i < idl->data.class_->n_tables; i++) {
        const struct ovsdb_idl_table *table = &idl->data.tables[i];
        const struct ovsdb_idl_table_class *class = table->class_;

        const struct ovsdb_idl_row *row;
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            size_t n_dsts = 0;
            if (row->new_datum) {
                size_t n_columns = shash_count(&row->table->columns);
                for (size_t j = 0; j < n_columns; j++) {
                    const struct ovsdb_type *type = &class->columns[j].type;
                    const struct ovsdb_datum *datum = &row->new_datum[j];
                    add_row_references(&type->key,
                                       datum->keys, datum->n, &row->uuid,
                                       &dsts, &n_dsts, &allocated_dsts);
                    add_row_references(&type->value,
                                       datum->values, datum->n, &row->uuid,
                                       &dsts, &n_dsts, &allocated_dsts);
                }
            }
            const struct ovsdb_idl_arc *arc;
            LIST_FOR_EACH (arc, src_node, &row->src_arcs) {
                if (!remove_uuid_from_array(&arc->dst->uuid,
                                            dsts, &n_dsts)) {
                    VLOG_ERR("unexpected arc from %s row "UUID_FMT" to %s "
                             "row "UUID_FMT,
                             table->class_->name,
                             UUID_ARGS(&row->uuid),
                             arc->dst->table->class_->name,
                             UUID_ARGS(&arc->dst->uuid));
                    ok = false;
                }
            }
            for (size_t j = 0; j < n_dsts; j++) {
                VLOG_ERR("%s row "UUID_FMT" missing arc to row "UUID_FMT,
                         table->class_->name, UUID_ARGS(&row->uuid),
                         UUID_ARGS(&dsts[j]));
                ok = false;
            }
        }
    }
    free(dsts);
    ovs_assert(ok);
}

const struct ovsdb_idl_class *
ovsdb_idl_get_class(const struct ovsdb_idl *idl)
{
    return idl->data.class_;
}

/* Given 'column' in some table in 'class', returns the table's class. */
const struct ovsdb_idl_table_class *
ovsdb_idl_table_class_from_column(const struct ovsdb_idl_class *class,
                                  const struct ovsdb_idl_column *column)
{
    for (size_t i = 0; i < class->n_tables; i++) {
        const struct ovsdb_idl_table_class *tc = &class->tables[i];
        if (column >= tc->columns && column < &tc->columns[tc->n_columns]) {
            return tc;
        }
    }

    OVS_NOT_REACHED();
}

/* Given 'column' in some table in 'db', returns the table. */
static struct ovsdb_idl_table *
ovsdb_idl_table_from_column(struct ovsdb_idl_db *db,
                            const struct ovsdb_idl_column *column)
{
    const struct ovsdb_idl_table_class *tc =
        ovsdb_idl_table_class_from_column(db->class_, column);
    return &db->tables[tc - db->class_->tables];
}

static unsigned char *
ovsdb_idl_db_get_mode(struct ovsdb_idl_db *db,
                      const struct ovsdb_idl_column *column)
{
    ovs_assert(!db->change_seqno);

    const struct ovsdb_idl_table *table = ovsdb_idl_table_from_column(db,
                                                                      column);
    return &table->modes[column - table->class_->columns];
}

static void
add_ref_table(struct ovsdb_idl_db *db, const struct ovsdb_base_type *base)
{
    if (base->type == OVSDB_TYPE_UUID && base->uuid.refTableName) {
        struct ovsdb_idl_table *table;

        table = shash_find_data(&db->table_by_name, base->uuid.refTableName);
        if (table) {
            table->need_table = true;
        } else {
            VLOG_WARN("%s IDL class missing referenced table %s",
                      db->class_->database, base->uuid.refTableName);
        }
    }
}

static void
ovsdb_idl_db_add_column(struct ovsdb_idl_db *db,
                        const struct ovsdb_idl_column *column)
{
    *ovsdb_idl_db_get_mode(db, column) = OVSDB_IDL_MONITOR | OVSDB_IDL_ALERT;
    add_ref_table(db, &column->type.key);
    add_ref_table(db, &column->type.value);
}

/* Turns on OVSDB_IDL_MONITOR and OVSDB_IDL_ALERT for 'column' in 'idl'.  Also
 * ensures that any tables referenced by 'column' will be replicated, even if
 * no columns in that table are selected for replication (see
 * ovsdb_idl_add_table() for more information).
 *
 * This function is only useful if 'monitor_everything_by_default' was false in
 * the call to ovsdb_idl_create().  This function should be called between
 * ovsdb_idl_create() and the first call to ovsdb_idl_run().
 */
void
ovsdb_idl_add_column(struct ovsdb_idl *idl,
                     const struct ovsdb_idl_column *column)
{
    ovsdb_idl_db_add_column(&idl->data, column);
}

static void
ovsdb_idl_db_add_table(struct ovsdb_idl_db *db,
                       const struct ovsdb_idl_table_class *tc)
{
    size_t i;

    for (i = 0; i < db->class_->n_tables; i++) {
        struct ovsdb_idl_table *table = &db->tables[i];

        if (table->class_ == tc) {
            table->need_table = true;
            return;
        }
    }

    OVS_NOT_REACHED();
}

/* Ensures that the table with class 'tc' will be replicated on 'idl' even if
 * no columns are selected for replication. Just the necessary data for table
 * references will be replicated (the UUID of the rows, for instance), any
 * columns not selected for replication will remain unreplicated.
 * This can be useful because it allows 'idl' to keep track of what rows in the
 * table actually exist, which in turn allows columns that reference the table
 * to have accurate contents. (The IDL presents the database with references to
 * rows that do not exist removed.)
 *
 * This function is only useful if 'monitor_everything_by_default' was false in
 * the call to ovsdb_idl_create().  This function should be called between
 * ovsdb_idl_create() and the first call to ovsdb_idl_run().
 */
void
ovsdb_idl_add_table(struct ovsdb_idl *idl,
                    const struct ovsdb_idl_table_class *tc)
{
    ovsdb_idl_db_add_table(&idl->data, tc);
}

/* A single clause within an ovsdb_idl_condition. */
struct ovsdb_idl_clause {
    struct hmap_node hmap_node;   /* In struct ovsdb_idl_condition. */
    enum ovsdb_function function; /* Never OVSDB_F_TRUE or OVSDB_F_FALSE. */
    const struct ovsdb_idl_column *column; /* Must be nonnull. */
    struct ovsdb_datum arg;       /* Has ovsdb_type ->column->type. */
};

static uint32_t
ovsdb_idl_clause_hash(const struct ovsdb_idl_clause *clause)
{
    uint32_t hash = hash_pointer(clause->column, clause->function);
    return ovsdb_datum_hash(&clause->arg, &clause->column->type, hash);
}

static int
ovsdb_idl_clause_equals(const struct ovsdb_idl_clause *a,
                        const struct ovsdb_idl_clause *b)
{
    return (a->function == b->function
            && a->column == b->column
            && ovsdb_datum_equals(&a->arg, &b->arg, &a->column->type));
}

static struct json *
ovsdb_idl_clause_to_json(const struct ovsdb_idl_clause *clause)
{
    const char *function = ovsdb_function_to_string(clause->function);
    return json_array_create_3(json_string_create(clause->column->name),
                               json_string_create(function),
                               ovsdb_datum_to_json(&clause->arg,
                                                   &clause->column->type));
}

static void
ovsdb_idl_clause_destroy(struct ovsdb_idl_clause *clause)
{
    if (clause) {
        ovsdb_datum_destroy(&clause->arg, &clause->column->type);
        free(clause);
    }
}

/* ovsdb_idl_condition. */

void
ovsdb_idl_condition_init(struct ovsdb_idl_condition *cnd)
{
    hmap_init(&cnd->clauses);
    cnd->is_true = false;
}

void
ovsdb_idl_condition_destroy(struct ovsdb_idl_condition *cond)
{
    if (cond) {
        ovsdb_idl_condition_clear(cond);
        hmap_destroy(&cond->clauses);
    }
}

void
ovsdb_idl_condition_clear(struct ovsdb_idl_condition *cond)
{
    struct ovsdb_idl_clause *clause, *next;
    HMAP_FOR_EACH_SAFE (clause, next, hmap_node, &cond->clauses) {
        hmap_remove(&cond->clauses, &clause->hmap_node);
        ovsdb_idl_clause_destroy(clause);
    }
    cond->is_true = false;
}

bool
ovsdb_idl_condition_is_true(const struct ovsdb_idl_condition *condition)
{
    return condition->is_true;
}

static struct ovsdb_idl_clause *
ovsdb_idl_condition_find_clause(const struct ovsdb_idl_condition *condition,
                                const struct ovsdb_idl_clause *target,
                                uint32_t hash)
{
    struct ovsdb_idl_clause *clause;
    HMAP_FOR_EACH_WITH_HASH (clause, hmap_node, hash, &condition->clauses) {
        if (ovsdb_idl_clause_equals(clause, target)) {
            return clause;
        }
    }
    return NULL;
}

static void
ovsdb_idl_condition_add_clause__(struct ovsdb_idl_condition *condition,
                                 const struct ovsdb_idl_clause *src,
                                 uint32_t hash)
{
    struct ovsdb_idl_clause *clause = xmalloc(sizeof *clause);
    clause->function = src->function;
    clause->column = src->column;
    ovsdb_datum_clone(&clause->arg, &src->arg, &src->column->type);
    hmap_insert(&condition->clauses, &clause->hmap_node, hash);
}

/* Adds a clause to the condition for replicating the table with class 'tc' in
 * 'idl'.
 *
 * The IDL replicates only rows in a table that satisfy at least one clause in
 * the table's condition.  The default condition for a table has a single
 * clause with function OVSDB_F_TRUE, so that the IDL replicates all rows in
 * the table.  When the IDL client replaces the default condition by one of its
 * own, the condition can have any number of clauses.  If it has no conditions,
 * then no rows are replicated.
 *
 * Two distinct of clauses can usefully be added:
 *
 *    - A 'function' of OVSDB_F_TRUE.  A "true" clause causes every row to be
 *      replicated, regardless of whether other clauses exist.  'column' and
 *      'arg' are ignored.
 *
 *    - Binary 'functions' add a clause of the form "<column> <function>
 *      <arg>", e.g. "column == 5" or "column <= 10".  In this case, 'arg' must
 *      have a type that is compatible with 'column'.
 */
void
ovsdb_idl_condition_add_clause(struct ovsdb_idl_condition *condition,
                               enum ovsdb_function function,
                               const struct ovsdb_idl_column *column,
                               const struct ovsdb_datum *arg)
{
    if (condition->is_true) {
        /* Adding a clause to an always-true condition has no effect.  */
    } else if (function == OVSDB_F_TRUE) {
        ovsdb_idl_condition_add_clause_true(condition);
    } else if (function == OVSDB_F_FALSE) {
        /* Adding a "false" clause never has any effect. */
    } else {
        struct ovsdb_idl_clause clause = {
            .function = function,
            .column = column,
            .arg = *arg,
        };
        uint32_t hash = ovsdb_idl_clause_hash(&clause);
        if (!ovsdb_idl_condition_find_clause(condition, &clause, hash)) {
            ovsdb_idl_condition_add_clause__(condition, &clause, hash);
        }
    }
}

void
ovsdb_idl_condition_add_clause_true(struct ovsdb_idl_condition *condition)
{
    if (!condition->is_true) {
        ovsdb_idl_condition_clear(condition);
        condition->is_true = true;
    }
}

static bool
ovsdb_idl_condition_equals(const struct ovsdb_idl_condition *a,
                           const struct ovsdb_idl_condition *b)
{
    if (hmap_count(&a->clauses) != hmap_count(&b->clauses)) {
        return false;
    }
    if (a->is_true != b->is_true) {
        return false;
    }

    const struct ovsdb_idl_clause *clause;
    HMAP_FOR_EACH (clause, hmap_node, &a->clauses) {
        if (!ovsdb_idl_condition_find_clause(b, clause,
                                             clause->hmap_node.hash)) {
            return false;
        }
    }
    return true;
}

static void
ovsdb_idl_condition_clone(struct ovsdb_idl_condition *dst,
                          const struct ovsdb_idl_condition *src)
{
    ovsdb_idl_condition_init(dst);

    dst->is_true = src->is_true;

    const struct ovsdb_idl_clause *clause;
    HMAP_FOR_EACH (clause, hmap_node, &src->clauses) {
        ovsdb_idl_condition_add_clause__(dst, clause, clause->hmap_node.hash);
    }
}

static unsigned int
ovsdb_idl_db_set_condition(struct ovsdb_idl_db *db,
                           const struct ovsdb_idl_table_class *tc,
                           const struct ovsdb_idl_condition *condition)
{
    struct ovsdb_idl_table *table = ovsdb_idl_db_table_from_class(db, tc);
    unsigned int seqno = db->cond_seqno;
    if (!ovsdb_idl_condition_equals(condition, &table->condition)) {
        ovsdb_idl_condition_destroy(&table->condition);
        ovsdb_idl_condition_clone(&table->condition, condition);
        db->cond_changed = table->cond_changed = true;
        poll_immediate_wake();
        return seqno + 1;
    }

    return seqno;
}

/* Sets the replication condition for 'tc' in 'idl' to 'condition' and
 * arranges to send the new condition to the database server.
 *
 * Return the next conditional update sequence number.  When this
 * value and ovsdb_idl_get_condition_seqno() matches, the 'idl'
 * contains rows that match the 'condition'. */
unsigned int
ovsdb_idl_set_condition(struct ovsdb_idl *idl,
                        const struct ovsdb_idl_table_class *tc,
                        const struct ovsdb_idl_condition *condition)
{
    return ovsdb_idl_db_set_condition(&idl->data, tc, condition);
}

static struct json *
ovsdb_idl_condition_to_json(const struct ovsdb_idl_condition *cnd)
{
    if (cnd->is_true) {
        return json_array_create_empty();
    }

    size_t n = hmap_count(&cnd->clauses);
    if (!n) {
        return json_array_create_1(json_boolean_create(false));
    }

    struct json **clauses = xmalloc(n * sizeof *clauses);
    const struct ovsdb_idl_clause *clause;
    size_t i = 0;
    HMAP_FOR_EACH (clause, hmap_node, &cnd->clauses) {
        clauses[i++] = ovsdb_idl_clause_to_json(clause);
    }
    ovs_assert(i == n);
    return json_array_create(clauses, n);
}

static struct json *
ovsdb_idl_create_cond_change_req(struct ovsdb_idl_table *table)
{
    const struct ovsdb_idl_condition *cond = &table->condition;
    struct json *monitor_cond_change_request = json_object_create();
    struct json *cond_json = ovsdb_idl_condition_to_json(cond);

    json_object_put(monitor_cond_change_request, "where", cond_json);

    return monitor_cond_change_request;
}

static struct jsonrpc_msg *
ovsdb_idl_db_compose_cond_change(struct ovsdb_idl_db *db)
{
    if (!db->cond_changed) {
        return NULL;
    }

    struct json *monitor_cond_change_requests = NULL;
    for (size_t i = 0; i < db->class_->n_tables; i++) {
        struct ovsdb_idl_table *table = &db->tables[i];

        if (table->cond_changed) {
            struct json *req = ovsdb_idl_create_cond_change_req(table);
            if (req) {
                if (!monitor_cond_change_requests) {
                    monitor_cond_change_requests = json_object_create();
                }
                json_object_put(monitor_cond_change_requests,
                             table->class_->name,
                             json_array_create_1(req));
            }
            table->cond_changed = false;
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

static void
ovsdb_idl_send_cond_change(struct ovsdb_idl *idl)
{
    /* When 'idl->request_id' is not NULL, there is an outstanding
     * conditional monitoring update request that we have not heard
     * from the server yet. Don't generate another request in this case. */
    if (!jsonrpc_session_is_connected(idl->session)
        || idl->data.monitoring != OVSDB_IDL_MONITORING_COND
        || idl->request_id) {
        return;
    }

    struct jsonrpc_msg *msg = ovsdb_idl_db_compose_cond_change(&idl->data);
    if (msg) {
        idl->request_id = json_clone(msg->id);
        jsonrpc_session_send(idl->session, msg);
    }
}

/* Turns off OVSDB_IDL_ALERT and OVSDB_IDL_TRACK for 'column' in 'db'.
 *
 * This function should be called between ovsdb_idl_create() and the first call
 * to ovsdb_idl_run().
 */
static void
ovsdb_idl_db_omit_alert(struct ovsdb_idl_db *db,
                        const struct ovsdb_idl_column *column)
{
    *ovsdb_idl_db_get_mode(db, column) &= ~(OVSDB_IDL_ALERT | OVSDB_IDL_TRACK);
}

/* Turns off OVSDB_IDL_ALERT and OVSDB_IDL_TRACK for 'column' in 'idl'.
 *
 * This function should be called between ovsdb_idl_create() and the first call
 * to ovsdb_idl_run().
 */
void
ovsdb_idl_omit_alert(struct ovsdb_idl *idl,
                     const struct ovsdb_idl_column *column)
{
    ovsdb_idl_db_omit_alert(&idl->data, column);
}

static void
ovsdb_idl_db_omit(struct ovsdb_idl_db *db,
                  const struct ovsdb_idl_column *column)
{
    *ovsdb_idl_db_get_mode(db, column) = 0;
}

/* Sets the mode for 'column' in 'idl' to 0.  See the big comment above
 * OVSDB_IDL_MONITOR for details.
 *
 * This function should be called between ovsdb_idl_create() and the first call
 * to ovsdb_idl_run().
 */
void
ovsdb_idl_omit(struct ovsdb_idl *idl, const struct ovsdb_idl_column *column)
{
    ovsdb_idl_db_omit(&idl->data, column);
}

/* Returns the most recent IDL change sequence number that caused a
 * insert, modify or delete update to the table with class 'table_class'.
 */
unsigned int
ovsdb_idl_table_get_seqno(const struct ovsdb_idl *idl,
                          const struct ovsdb_idl_table_class *table_class)
{
    struct ovsdb_idl_table *table
        = ovsdb_idl_db_table_from_class(&idl->data, table_class);
    unsigned int max_seqno = table->change_seqno[OVSDB_IDL_CHANGE_INSERT];

    if (max_seqno < table->change_seqno[OVSDB_IDL_CHANGE_MODIFY]) {
        max_seqno = table->change_seqno[OVSDB_IDL_CHANGE_MODIFY];
    }
    if (max_seqno < table->change_seqno[OVSDB_IDL_CHANGE_DELETE]) {
        max_seqno = table->change_seqno[OVSDB_IDL_CHANGE_DELETE];
    }
    return max_seqno;
}

/* For each row that contains tracked columns, IDL stores the most
 * recent IDL change sequence numbers associateed with insert, modify
 * and delete updates to the table.
 */
unsigned int
ovsdb_idl_row_get_seqno(const struct ovsdb_idl_row *row,
                        enum ovsdb_idl_change change)
{
    return row->change_seqno[change];
}

/* Turns on OVSDB_IDL_TRACK for 'column' in 'idl', ensuring that
 * all rows whose 'column' is modified are traced. Similarly, insert
 * or delete of rows having 'column' are tracked. Clients are able
 * to retrive the tracked rows with the ovsdb_idl_track_get_*()
 * functions.
 *
 * This function should be called between ovsdb_idl_create() and
 * the first call to ovsdb_idl_run(). The column to be tracked
 * should have OVSDB_IDL_ALERT turned on.
 */
void
ovsdb_idl_track_add_column(struct ovsdb_idl *idl,
                           const struct ovsdb_idl_column *column)
{
    if (!(*ovsdb_idl_db_get_mode(&idl->data, column) & OVSDB_IDL_ALERT)) {
        ovsdb_idl_add_column(idl, column);
    }
    *ovsdb_idl_db_get_mode(&idl->data, column) |= OVSDB_IDL_TRACK;
}

void
ovsdb_idl_track_add_all(struct ovsdb_idl *idl)
{
    size_t i, j;

    for (i = 0; i < idl->data.class_->n_tables; i++) {
        const struct ovsdb_idl_table_class *tc = &idl->data.class_->tables[i];

        for (j = 0; j < tc->n_columns; j++) {
            const struct ovsdb_idl_column *column = &tc->columns[j];
            ovsdb_idl_track_add_column(idl, column);
        }
    }
}

/* Returns true if 'table' has any tracked column. */
static bool
ovsdb_idl_track_is_set(struct ovsdb_idl_table *table)
{
    size_t i;

    for (i = 0; i < table->class_->n_columns; i++) {
        if (table->modes[i] & OVSDB_IDL_TRACK) {
            return true;
        }
    }
   return false;
}

/* Returns the first tracked row in table with class 'table_class'
 * for the specified 'idl'. Returns NULL if there are no tracked rows */
const struct ovsdb_idl_row *
ovsdb_idl_track_get_first(const struct ovsdb_idl *idl,
                          const struct ovsdb_idl_table_class *table_class)
{
    struct ovsdb_idl_table *table
        = ovsdb_idl_db_table_from_class(&idl->data, table_class);

    if (!ovs_list_is_empty(&table->track_list)) {
        return CONTAINER_OF(ovs_list_front(&table->track_list), struct ovsdb_idl_row, track_node);
    }
    return NULL;
}

/* Returns the next tracked row in table after the specified 'row'
 * (in no particular order). Returns NULL if there are no tracked rows */
const struct ovsdb_idl_row *
ovsdb_idl_track_get_next(const struct ovsdb_idl_row *row)
{
    if (row->track_node.next != &row->table->track_list) {
        return CONTAINER_OF(row->track_node.next, struct ovsdb_idl_row, track_node);
    }

    return NULL;
}

/* Returns true if a tracked 'column' in 'row' was updated by IDL, false
 * otherwise. The tracking data is cleared by ovsdb_idl_track_clear()
 *
 * Function returns false if 'column' is not tracked (see
 * ovsdb_idl_track_add_column()).
 */
bool
ovsdb_idl_track_is_updated(const struct ovsdb_idl_row *row,
                           const struct ovsdb_idl_column *column)
{
    const struct ovsdb_idl_table_class *class;
    size_t column_idx;

    class = row->table->class_;
    column_idx = column - class->columns;

    if (row->updated && bitmap_is_set(row->updated, column_idx)) {
        return true;
    } else {
        return false;
    }
}

/* Flushes the tracked rows. Client calls this function after calling
 * ovsdb_idl_run() and read all tracked rows with the ovsdb_idl_track_get_*()
 * functions. This is usually done at the end of the client's processing
 * loop when it is ready to do ovsdb_idl_run() again.
 */
static void
ovsdb_idl_db_track_clear(struct ovsdb_idl_db *db)
{
    size_t i;

    for (i = 0; i < db->class_->n_tables; i++) {
        struct ovsdb_idl_table *table = &db->tables[i];

        if (!ovs_list_is_empty(&table->track_list)) {
            struct ovsdb_idl_row *row, *next;

            LIST_FOR_EACH_SAFE(row, next, track_node, &table->track_list) {
                if (row->updated) {
                    free(row->updated);
                    row->updated = NULL;
                }
                ovs_list_remove(&row->track_node);
                ovs_list_init(&row->track_node);
                if (ovsdb_idl_row_is_orphan(row)) {
                    ovsdb_idl_row_clear_old(row);
                    free(row);
                }
            }
        }
    }
}

/* Flushes the tracked rows. Client calls this function after calling
 * ovsdb_idl_run() and read all tracked rows with the ovsdb_idl_track_get_*()
 * functions. This is usually done at the end of the client's processing
 * loop when it is ready to do ovsdb_idl_run() again.
 */
void
ovsdb_idl_track_clear(struct ovsdb_idl *idl)
{
    ovsdb_idl_db_track_clear(&idl->data);
}

static void
ovsdb_idl_send_schema_request(struct ovsdb_idl *idl,
                              struct ovsdb_idl_db *db)
{
    ovsdb_idl_send_request(idl, jsonrpc_create_request(
                               "get_schema",
                               json_array_create_1(json_string_create(
                                                       db->class_->database)),
                               NULL));
}

static void
ovsdb_idl_send_db_change_aware(struct ovsdb_idl *idl)
{
    struct jsonrpc_msg *msg = jsonrpc_create_request(
        "set_db_change_aware", json_array_create_1(json_boolean_create(true)),
        NULL);
    jsonrpc_session_send(idl->session, msg);
}

static bool
ovsdb_idl_check_server_db(struct ovsdb_idl *idl)
{
    const struct serverrec_database *database;
    SERVERREC_DATABASE_FOR_EACH (database, idl) {
        if (uuid_is_zero(&idl->cid)
            ? !strcmp(database->name, idl->data.class_->database)
            : database->n_cid && uuid_equals(database->cid, &idl->cid)) {
            break;
        }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    const char *server_name = jsonrpc_session_get_name(idl->session);
    bool ok = false;
    if (!database) {
        VLOG_INFO_RL(&rl, "%s: server does not have %s database",
                     server_name, idl->data.class_->database);
    } else if (!strcmp(database->model, "clustered")
               && jsonrpc_session_get_n_remotes(idl->session) > 1) {
        uint64_t index = database->n_index ? *database->index : 0;

        if (!database->schema) {
            VLOG_INFO("%s: clustered database server has not yet joined "
                      "cluster; trying another server", server_name);
        } else if (!database->connected) {
            VLOG_INFO("%s: clustered database server is disconnected "
                      "from cluster; trying another server", server_name);
        } else if (idl->leader_only && !database->leader) {
            VLOG_INFO("%s: clustered database server is not cluster "
                      "leader; trying another server", server_name);
        } else if (index < idl->min_index) {
            VLOG_WARN("%s: clustered database server has stale data; "
                      "trying another server", server_name);
        } else {
            idl->min_index = MAX(idl->min_index, index);
            ok = true;
        }
    } else {
        ok = true;
    }
    if (!ok) {
        ovsdb_idl_retry(idl);
        return false;
    }

    if (idl->state == IDL_S_SERVER_MONITOR_COND_REQUESTED) {
        json_destroy(idl->data.schema);
        idl->data.schema = json_from_string(database->schema);
        ovsdb_idl_send_monitor_request(idl, &idl->data, true);
        ovsdb_idl_transition(idl, IDL_S_DATA_MONITOR_COND_REQUESTED);
    }
    return true;
}

static void
log_error(struct ovsdb_error *error)
{
    char *s = ovsdb_error_to_string_free(error);
    VLOG_WARN("error parsing database schema: %s", s);
    free(s);
}

/* Frees 'schema', which is in the format returned by parse_schema(). */
static void
free_schema(struct shash *schema)
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
static struct shash *
parse_schema(const struct json *schema_json)
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
            free_schema(schema);
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

static void
ovsdb_idl_send_monitor_request(struct ovsdb_idl *idl, struct ovsdb_idl_db *db,
                               bool use_monitor_cond)
{
    struct shash *schema = parse_schema(db->schema);
    struct json *monitor_requests = json_object_create();

    for (size_t i = 0; i < db->class_->n_tables; i++) {
        struct ovsdb_idl_table *table = &db->tables[i];
        const struct ovsdb_idl_table_class *tc = table->class_;
        struct json *monitor_request;
        const struct sset *table_schema
            = schema ? shash_find_data(schema, table->class_->name) : NULL;

        struct json *columns
            = table->need_table ? json_array_create_empty() : NULL;
        for (size_t j = 0; j < tc->n_columns; j++) {
            const struct ovsdb_idl_column *column = &tc->columns[j];
            bool db_has_column = (table_schema &&
                                  sset_contains(table_schema, column->name));
            if (column->is_synthetic) {
                if (db_has_column) {
                    VLOG_WARN("%s table in %s database has synthetic "
                              "column %s", table->class_->name,
                              db->class_->database, column->name);
                }
            } else if (table->modes[j] & OVSDB_IDL_MONITOR) {
                if (table_schema && !db_has_column) {
                    VLOG_WARN("%s table in %s database lacks %s column "
                              "(database needs upgrade?)",
                              table->class_->name, db->class_->database,
                              column->name);
                    continue;
                }
                if (!columns) {
                    columns = json_array_create_empty();
                }
                json_array_add(columns, json_string_create(column->name));
            }
        }

        if (columns) {
            if (schema && !table_schema) {
                VLOG_WARN("%s database lacks %s table "
                          "(database needs upgrade?)",
                          db->class_->database, table->class_->name);
                json_destroy(columns);
                continue;
            }

            monitor_request = json_object_create();
            json_object_put(monitor_request, "columns", columns);

            const struct ovsdb_idl_condition *cond = &table->condition;
            if (use_monitor_cond && !ovsdb_idl_condition_is_true(cond)) {
                json_object_put(monitor_request, "where",
                                ovsdb_idl_condition_to_json(cond));
                table->cond_changed = false;
            }
            json_object_put(monitor_requests, tc->name,
                            json_array_create_1(monitor_request));
        }
    }
    free_schema(schema);

    db->cond_changed = false;

    ovsdb_idl_send_request(
        idl,
        jsonrpc_create_request(
            use_monitor_cond ? "monitor_cond" : "monitor",
            json_array_create_3(json_string_create(db->class_->database),
                                json_clone(db->monitor_id), monitor_requests),
            NULL));
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
ovsdb_idl_db_parse_monitor_reply(struct ovsdb_idl_db *db,
                                 const struct json *result,
                                 bool is_monitor_cond)
{
    db->change_seqno++;
    ovsdb_idl_db_clear(db);
    ovsdb_idl_db_parse_update(db, result, is_monitor_cond);
}

static bool
ovsdb_idl_db_parse_update_rpc(struct ovsdb_idl_db *db,
                              const struct jsonrpc_msg *msg)
{
    if (msg->type == JSONRPC_NOTIFY) {
        bool is_update = !strcmp(msg->method, "update");
        bool is_update2 = !strcmp(msg->method, "update2");
        if ((is_update || is_update2)
            && msg->params->type == JSON_ARRAY
            && msg->params->array.n == 2
            && json_equal(msg->params->array.elems[0], db->monitor_id)) {
            ovsdb_idl_db_parse_update(db, msg->params->array.elems[1],
                                      is_update2);
            return true;
        }
    }
    return false;
}

static bool
ovsdb_idl_handle_monitor_canceled(struct ovsdb_idl *idl,
                                  struct ovsdb_idl_db *db,
                                  const struct jsonrpc_msg *msg)
{
    if (msg->type != JSONRPC_NOTIFY
        || strcmp(msg->method, "monitor_canceled")
        || msg->params->type != JSON_ARRAY
        || msg->params->array.n != 1
        || !json_equal(msg->params->array.elems[0], db->monitor_id)) {
        return false;
    }

    db->monitoring = OVSDB_IDL_NOT_MONITORING;

    /* Cancel the other monitor and restart the FSM from the top.
     *
     * Maybe a more sophisticated response would be better in some cases, but
     * it doesn't seem worth optimizing yet.  (Although this is already more
     * sophisticated than just dropping the connection and reconnecting.) */
    struct ovsdb_idl_db *other_db
        = db == &idl->data ? &idl->server : &idl->data;
    if (other_db->monitoring) {
        jsonrpc_session_send(
            idl->session,
            jsonrpc_create_request(
                "monitor_cancel",
                json_array_create_1(json_clone(other_db->monitor_id)), NULL));
        other_db->monitoring = OVSDB_IDL_NOT_MONITORING;
    }
    ovsdb_idl_restart_fsm(idl);

    return true;
}

static struct ovsdb_error *
ovsdb_idl_db_parse_update__(struct ovsdb_idl_db *db,
                            const struct json *table_updates,
                            bool is_monitor_cond)
{
    const struct shash_node *tables_node;
    const char *version_suffix = is_monitor_cond ? "2" : "";

    if (table_updates->type != JSON_OBJECT) {
        return ovsdb_syntax_error(table_updates, NULL,
                                  "<table_updates%s> is not an object",
                                  version_suffix);
    }

    SHASH_FOR_EACH (tables_node, json_object(table_updates)) {
        const struct json *table_update = tables_node->data;
        const struct shash_node *table_node;
        struct ovsdb_idl_table *table;

        table = shash_find_data(&db->table_by_name, tables_node->name);
        if (!table) {
            return ovsdb_syntax_error(
                table_updates, NULL,
                "<table_updates%s> includes unknown table \"%s\"",
                version_suffix, tables_node->name);
        }

        if (table_update->type != JSON_OBJECT) {
            return ovsdb_syntax_error(table_update, NULL,
                                      "<table_update%s> for table \"%s\" is "
                                      "not an object",
                                      version_suffix, table->class_->name);
        }
        SHASH_FOR_EACH (table_node, json_object(table_update)) {
            const struct json *row_update = table_node->data;
            struct uuid uuid;

            if (!uuid_from_string(&uuid, table_node->name)) {
                return ovsdb_syntax_error(table_update, NULL,
                                          "<table_update%s> for table \"%s\" "
                                          "contains bad UUID "
                                          "\"%s\" as member name",
                                          version_suffix,
                                          table->class_->name,
                                          table_node->name);
            }
            if (row_update->type != JSON_OBJECT) {
                return ovsdb_syntax_error(row_update, NULL,
                                          "<table_update%s> for table \"%s\" "
                                          "contains <row_update%s> for %s "
                                          "that is not an object",
                                          version_suffix, table->class_->name,
                                          version_suffix, table_node->name);
            }

            if (is_monitor_cond) {
                const char *ops[] = {"modify", "insert", "delete", "initial"};
                const char *operation;
                const struct json *row;
                int i;

                for (i = 0; i < ARRAY_SIZE(ops); i++) {
                    operation = ops[i];
                    row = shash_find_data(json_object(row_update), operation);

                    if (row)  {
                        if (ovsdb_idl_process_update2(table, &uuid, operation,
                                                      row)) {
                            db->change_seqno++;
                        }
                        break;
                    }
                }

                /* row_update2 should contain one of the objects */
                if (i == ARRAY_SIZE(ops)) {
                    return ovsdb_syntax_error(row_update, NULL,
                                              "<row_update2> includes unknown "
                                              "object");
                }
            } else {
                const struct json *old_json, *new_json;

                old_json = shash_find_data(json_object(row_update), "old");
                new_json = shash_find_data(json_object(row_update), "new");
                if (old_json && old_json->type != JSON_OBJECT) {
                    return ovsdb_syntax_error(old_json, NULL,
                                              "\"old\" <row> is not object");
                } else if (new_json && new_json->type != JSON_OBJECT) {
                    return ovsdb_syntax_error(new_json, NULL,
                                              "\"new\" <row> is not object");
                } else if ((old_json != NULL) + (new_json != NULL)
                           != shash_count(json_object(row_update))) {
                    return ovsdb_syntax_error(row_update, NULL,
                                              "<row-update> contains "
                                              "unexpected member");
                } else if (!old_json && !new_json) {
                    return ovsdb_syntax_error(row_update, NULL,
                                              "<row-update> missing \"old\" "
                                              "and \"new\" members");
                }

                if (ovsdb_idl_process_update(table, &uuid, old_json,
                                             new_json)) {
                    db->change_seqno++;
                }
            }
        }
    }

    return NULL;
}

static void
ovsdb_idl_db_parse_update(struct ovsdb_idl_db *db,
                          const struct json *table_updates,
                          bool is_monitor_cond)
{
    struct ovsdb_error *error = ovsdb_idl_db_parse_update__(db, table_updates,
                                                            is_monitor_cond);
    if (error) {
        log_parse_update_error(error);
    }
}

static struct ovsdb_idl_row *
ovsdb_idl_get_row(struct ovsdb_idl_table *table, const struct uuid *uuid)
{
    struct ovsdb_idl_row *row;

    HMAP_FOR_EACH_WITH_HASH (row, hmap_node, uuid_hash(uuid), &table->rows) {
        if (uuid_equals(&row->uuid, uuid)) {
            return row;
        }
    }
    return NULL;
}

/* Returns true if a column with mode OVSDB_IDL_MODE_RW changed, false
 * otherwise. */
static bool
ovsdb_idl_process_update(struct ovsdb_idl_table *table,
                         const struct uuid *uuid, const struct json *old,
                         const struct json *new)
{
    struct ovsdb_idl_row *row;

    row = ovsdb_idl_get_row(table, uuid);
    if (!new) {
        /* Delete row. */
        if (row && !ovsdb_idl_row_is_orphan(row)) {
            /* XXX perhaps we should check the 'old' values? */
            ovsdb_idl_delete_row(row);
        } else {
            VLOG_WARN_RL(&semantic_rl, "cannot delete missing row "UUID_FMT" "
                         "from table %s",
                         UUID_ARGS(uuid), table->class_->name);
            return false;
        }
    } else if (!old) {
        /* Insert row. */
        if (!row) {
            ovsdb_idl_insert_row(ovsdb_idl_row_create(table, uuid), new);
        } else if (ovsdb_idl_row_is_orphan(row)) {
            ovsdb_idl_insert_row(row, new);
        } else {
            VLOG_WARN_RL(&semantic_rl, "cannot add existing row "UUID_FMT" to "
                         "table %s", UUID_ARGS(uuid), table->class_->name);
            return ovsdb_idl_modify_row(row, new);
        }
    } else {
        /* Modify row. */
        if (row) {
            /* XXX perhaps we should check the 'old' values? */
            if (!ovsdb_idl_row_is_orphan(row)) {
                return ovsdb_idl_modify_row(row, new);
            } else {
                VLOG_WARN_RL(&semantic_rl, "cannot modify missing but "
                             "referenced row "UUID_FMT" in table %s",
                             UUID_ARGS(uuid), table->class_->name);
                ovsdb_idl_insert_row(row, new);
            }
        } else {
            VLOG_WARN_RL(&semantic_rl, "cannot modify missing row "UUID_FMT" "
                         "in table %s", UUID_ARGS(uuid), table->class_->name);
            ovsdb_idl_insert_row(ovsdb_idl_row_create(table, uuid), new);
        }
    }

    return true;
}

/* Returns true if a column with mode OVSDB_IDL_MODE_RW changed, false
 * otherwise. */
static bool
ovsdb_idl_process_update2(struct ovsdb_idl_table *table,
                          const struct uuid *uuid,
                          const char *operation,
                          const struct json *json_row)
{
    struct ovsdb_idl_row *row;

    row = ovsdb_idl_get_row(table, uuid);
    if (!strcmp(operation, "delete")) {
        /* Delete row. */
        if (row && !ovsdb_idl_row_is_orphan(row)) {
            ovsdb_idl_delete_row(row);
        } else {
            VLOG_WARN_RL(&semantic_rl, "cannot delete missing row "UUID_FMT" "
                         "from table %s",
                         UUID_ARGS(uuid), table->class_->name);
            return false;
        }
    } else if (!strcmp(operation, "insert") || !strcmp(operation, "initial")) {
        /* Insert row. */
        if (!row) {
            ovsdb_idl_insert_row(ovsdb_idl_row_create(table, uuid), json_row);
        } else if (ovsdb_idl_row_is_orphan(row)) {
            ovsdb_idl_insert_row(row, json_row);
        } else {
            VLOG_WARN_RL(&semantic_rl, "cannot add existing row "UUID_FMT" to "
                         "table %s", UUID_ARGS(uuid), table->class_->name);
            ovsdb_idl_delete_row(row);
            ovsdb_idl_insert_row(row, json_row);
        }
    } else if (!strcmp(operation, "modify")) {
        /* Modify row. */
        if (row) {
            if (!ovsdb_idl_row_is_orphan(row)) {
                return ovsdb_idl_modify_row_by_diff(row, json_row);
            } else {
                VLOG_WARN_RL(&semantic_rl, "cannot modify missing but "
                             "referenced row "UUID_FMT" in table %s",
                             UUID_ARGS(uuid), table->class_->name);
                return false;
            }
        } else {
            VLOG_WARN_RL(&semantic_rl, "cannot modify missing row "UUID_FMT" "
                         "in table %s", UUID_ARGS(uuid), table->class_->name);
            return false;
        }
    } else {
        VLOG_WARN_RL(&semantic_rl, "unknown operation %s to "
                     "table %s", operation, table->class_->name);
        return false;
    }

    return true;
}

/* Returns true if a column with mode OVSDB_IDL_MODE_RW changed, false
 * otherwise.
 *
 * Change 'row' either with the content of 'row_json' or by apply 'diff'.
 * Caller needs to provide either valid 'row_json' or 'diff', but not
 * both.  */
static bool
ovsdb_idl_row_change__(struct ovsdb_idl_row *row, const struct json *row_json,
                       const struct json *diff_json,
                       enum ovsdb_idl_change change)
{
    struct ovsdb_idl_table *table = row->table;
    const struct ovsdb_idl_table_class *class = table->class_;
    struct shash_node *node;
    bool changed = false;
    bool apply_diff = diff_json != NULL;
    const struct json *json = apply_diff ? diff_json : row_json;

    SHASH_FOR_EACH (node, json_object(json)) {
        const char *column_name = node->name;
        const struct ovsdb_idl_column *column;
        struct ovsdb_datum datum;
        struct ovsdb_error *error;
        unsigned int column_idx;
        struct ovsdb_datum *old;

        column = shash_find_data(&table->columns, column_name);
        if (!column) {
            VLOG_WARN_RL(&syntax_rl, "unknown column %s updating row "UUID_FMT,
                         column_name, UUID_ARGS(&row->uuid));
            continue;
        }

        column_idx = column - table->class_->columns;
        old = &row->old_datum[column_idx];

        error = NULL;
        if (apply_diff) {
            struct ovsdb_datum diff;

            ovs_assert(!row_json);
            error = ovsdb_transient_datum_from_json(&diff, &column->type,
                                                    node->data);
            if (!error) {
                error = ovsdb_datum_apply_diff(&datum, old, &diff,
                                               &column->type);
                ovsdb_datum_destroy(&diff, &column->type);
            }
        } else {
            ovs_assert(!diff_json);
            error = ovsdb_datum_from_json(&datum, &column->type, node->data,
                                          NULL);
        }

        if (!error) {
            if (!ovsdb_datum_equals(old, &datum, &column->type)) {
                ovsdb_datum_swap(old, &datum);
                if (table->modes[column_idx] & OVSDB_IDL_ALERT) {
                    changed = true;
                    row->change_seqno[change]
                        = row->table->change_seqno[change]
                        = row->table->db->change_seqno + 1;
                    if (table->modes[column_idx] & OVSDB_IDL_TRACK) {
                        if (!ovs_list_is_empty(&row->track_node)) {
                            ovs_list_remove(&row->track_node);
                        }
                        ovs_list_push_back(&row->table->track_list,
                                       &row->track_node);
                        if (!row->updated) {
                            row->updated = bitmap_allocate(class->n_columns);
                        }
                        bitmap_set1(row->updated, column_idx);
                    }
                }
            } else {
                /* Didn't really change but the OVSDB monitor protocol always
                 * includes every value in a row. */
            }

            ovsdb_datum_destroy(&datum, &column->type);
        } else {
            char *s = ovsdb_error_to_string_free(error);
            VLOG_WARN_RL(&syntax_rl, "error parsing column %s in row "UUID_FMT
                         " in table %s: %s", column_name,
                         UUID_ARGS(&row->uuid), table->class_->name, s);
            free(s);
        }
    }
    return changed;
}

static bool
ovsdb_idl_row_update(struct ovsdb_idl_row *row, const struct json *row_json,
                     enum ovsdb_idl_change change)
{
    return ovsdb_idl_row_change__(row, row_json, NULL, change);
}

static bool
ovsdb_idl_row_apply_diff(struct ovsdb_idl_row *row,
                         const struct json *diff_json,
                         enum ovsdb_idl_change change)
{
    return ovsdb_idl_row_change__(row, NULL, diff_json, change);
}

/* When a row A refers to row B through a column with a "refTable" constraint,
 * but row B does not exist, row B is called an "orphan row".  Orphan rows
 * should not persist, because the database enforces referential integrity, but
 * they can appear transiently as changes from the database are received (the
 * database doesn't try to topologically sort them and circular references mean
 * it isn't always possible anyhow).
 *
 * This function returns true if 'row' is an orphan row, otherwise false.
 */
static bool
ovsdb_idl_row_is_orphan(const struct ovsdb_idl_row *row)
{
    return !row->old_datum && !row->new_datum;
}

/* Returns true if 'row' is conceptually part of the database as modified by
 * the current transaction (if any), false otherwise.
 *
 * This function will return true if 'row' is not an orphan (see the comment on
 * ovsdb_idl_row_is_orphan()) and:
 *
 *   - 'row' exists in the database and has not been deleted within the
 *     current transaction (if any).
 *
 *   - 'row' was inserted within the current transaction and has not been
 *     deleted.  (In the latter case you should not have passed 'row' in at
 *     all, because ovsdb_idl_txn_delete() freed it.)
 *
 * This function will return false if 'row' is an orphan or if 'row' was
 * deleted within the current transaction.
 */
static bool
ovsdb_idl_row_exists(const struct ovsdb_idl_row *row)
{
    return row->new_datum != NULL;
}

static void
ovsdb_idl_row_parse(struct ovsdb_idl_row *row)
{
    const struct ovsdb_idl_table_class *class = row->table->class_;
    size_t i;

    for (i = 0; i < class->n_columns; i++) {
        const struct ovsdb_idl_column *c = &class->columns[i];
        (c->parse)(row, &row->old_datum[i]);
    }
}

static void
ovsdb_idl_row_unparse(struct ovsdb_idl_row *row)
{
    const struct ovsdb_idl_table_class *class = row->table->class_;
    size_t i;

    for (i = 0; i < class->n_columns; i++) {
        const struct ovsdb_idl_column *c = &class->columns[i];
        (c->unparse)(row);
    }
}

/* The OVSDB-IDL Compound Indexes feature allows for the creation of custom
 * table indexes over one or more columns in the IDL. These indexes provide
 * the ability to retrieve rows matching a particular search criteria and to
 * iterate over a subset of rows in a defined order.
 */

/* Generic comparator that can compare each index, using the custom
 * configuration (an struct ovsdb_idl_index) passed to it.
 * Not intended for direct usage.
 */
static int
ovsdb_idl_index_generic_comparer(const void *a,
                                 const void *b, const void *conf)
{
    const struct ovsdb_idl_column *column;
    const struct ovsdb_idl_index *index;
    size_t i;

    index = CONST_CAST(struct ovsdb_idl_index *, conf);

    if (a == b) {
        return 0;
    }

    for (i = 0; i < index->n_columns; i++) {
        int val;
        if (index->columns[i].comparer) {
            val = index->columns[i].comparer(a, b);
        } else {
            column = index->columns[i].column;
            const struct ovsdb_idl_row *row_a, *row_b;
            row_a = CONST_CAST(struct ovsdb_idl_row *, a);
            row_b = CONST_CAST(struct ovsdb_idl_row *, b);
            const struct ovsdb_datum *datum_a, *datum_b;
            datum_a = ovsdb_idl_read(row_a, column);
            datum_b = ovsdb_idl_read(row_b, column);
            val = ovsdb_datum_compare_3way(datum_a, datum_b, &column->type);
        }

        if (val) {
            return index->columns[i].order == OVSDB_INDEX_ASC ? val : -val;
        }
    }

    /* If ins_del is true then a row is being inserted into or deleted from
     * the index list. In this case, we augment the search key with
     * additional values (row UUID and memory address) to create a unique
     * search key in order to locate the correct entry efficiently and to
     * ensure that the correct entry is deleted in the case of a "delete"
     * operation.
     */
    if (index->ins_del) {
        const struct ovsdb_idl_row *row_a, *row_b;

        row_a = (const struct ovsdb_idl_row *) a;
        row_b = (const struct ovsdb_idl_row *) b;
        int value = uuid_compare_3way(&row_a->uuid, &row_b->uuid);

        return value ? value : (a < b) - (a > b);
    } else {
        return 0;
    }
}

static struct ovsdb_idl_index *
ovsdb_idl_db_index_create(struct ovsdb_idl_db *db,
                          const struct ovsdb_idl_index_column *columns,
                          size_t n)
{
    ovs_assert(n > 0);

    struct ovsdb_idl_index *index = xzalloc(sizeof *index);

    index->table = ovsdb_idl_table_from_column(db, columns[0].column);
    for (size_t i = 0; i < n; i++) {
        const struct ovsdb_idl_index_column *c = &columns[i];
        ovs_assert(ovsdb_idl_table_from_column(db, c->column) == index->table);
        ovs_assert(*ovsdb_idl_db_get_mode(db, c->column) & OVSDB_IDL_MONITOR);
    }

    index->columns = xmemdup(columns, n * sizeof *columns);
    index->n_columns = n;
    index->skiplist = skiplist_create(ovsdb_idl_index_generic_comparer, index);

    ovs_list_push_back(&index->table->indexes, &index->node);

    return index;
}

/* Creates a new index for the given 'idl' and with the 'n' specified
 * 'columns'.
 *
 * All indexes must be created before the first call to ovsdb_idl_run(). */
struct ovsdb_idl_index *
ovsdb_idl_index_create(struct ovsdb_idl *idl,
                       const struct ovsdb_idl_index_column *columns,
                       size_t n)
{
    return ovsdb_idl_db_index_create(&idl->data, columns, n);
}

struct ovsdb_idl_index *
ovsdb_idl_index_create1(struct ovsdb_idl *idl,
                        const struct ovsdb_idl_column *column1)
{
    const struct ovsdb_idl_index_column columns[] = {
        { .column = column1 },
    };
    return ovsdb_idl_index_create(idl, columns, ARRAY_SIZE(columns));
}

struct ovsdb_idl_index *
ovsdb_idl_index_create2(struct ovsdb_idl *idl,
                        const struct ovsdb_idl_column *column1,
                        const struct ovsdb_idl_column *column2)
{
    const struct ovsdb_idl_index_column columns[] = {
        { .column = column1 },
        { .column = column2 },
    };
    return ovsdb_idl_index_create(idl, columns, ARRAY_SIZE(columns));
}

static void
ovsdb_idl_destroy_indexes(struct ovsdb_idl_table *table)
{
    struct ovsdb_idl_index *index, *next;
    LIST_FOR_EACH_SAFE (index, next, node, &table->indexes) {
        skiplist_destroy(index->skiplist, NULL);
        free(index->columns);
        free(index);
    }
}

static void
ovsdb_idl_add_to_indexes(const struct ovsdb_idl_row *row)
{
    struct ovsdb_idl_table *table = row->table;
    struct ovsdb_idl_index *index;
    LIST_FOR_EACH (index, node, &table->indexes) {
        index->ins_del = true;
        skiplist_insert(index->skiplist, row);
        index->ins_del = false;
    }
}

static void
ovsdb_idl_remove_from_indexes(const struct ovsdb_idl_row *row)
{
    struct ovsdb_idl_table *table = row->table;
    struct ovsdb_idl_index *index;
    LIST_FOR_EACH (index, node, &table->indexes) {
        index->ins_del = true;
        skiplist_delete(index->skiplist, row);
        index->ins_del = false;
    }
}

/* Writes a datum in an ovsdb_idl_row, and updates the corresponding field in
 * the table record.  Not intended for direct usage. */
void
ovsdb_idl_index_write(struct ovsdb_idl_row *const_row,
                       const struct ovsdb_idl_column *column,
                       struct ovsdb_datum *datum,
                       const struct ovsdb_idl_table_class *class)
{
    struct ovsdb_idl_row *row = CONST_CAST(struct ovsdb_idl_row *, const_row);
    size_t column_idx = column - class->columns;

    if (bitmap_is_set(row->written, column_idx)) {
        free(row->new_datum[column_idx].values);
        free(row->new_datum[column_idx].keys);
    } else {
        bitmap_set1(row->written, column_idx);
     }
    row->new_datum[column_idx] = *datum;
    (column->unparse)(row);
    (column->parse)(row, &row->new_datum[column_idx]);
}

/* Magic UUID for index rows */
static const struct uuid index_row_uuid = {
        .parts = {0xdeadbeef,
                  0xdeadbeef,
                  0xdeadbeef,
                  0xdeadbeef}};

/* Check if a row is an index row */
static bool
is_index_row(const struct ovsdb_idl_row *row)
{
    return uuid_equals(&row->uuid, &index_row_uuid);
}

/* Initializes a row for use in an indexed query.
 * Not intended for direct usage.
 */
struct ovsdb_idl_row *
ovsdb_idl_index_init_row(struct ovsdb_idl_index *index)
{
    const struct ovsdb_idl_table_class *class = index->table->class_;
    struct ovsdb_idl_row *row = xzalloc(class->allocation_size);
    class->row_init(row);
    row->uuid = index_row_uuid;
    row->new_datum = xmalloc(class->n_columns * sizeof *row->new_datum);
    row->written = bitmap_allocate(class->n_columns);
    row->table = index->table;
    /* arcs are not used for index row, but it doesn't harm to initialize */
    ovs_list_init(&row->src_arcs);
    ovs_list_init(&row->dst_arcs);
    return row;
}

/* Destroys 'row_' and frees all associated memory. This function is intended
 * to be used indirectly through one of the "index_destroy_row" functions
 * generated by ovsdb-idlc.
 */
void
ovsdb_idl_index_destroy_row(const struct ovsdb_idl_row *row_)
{
    struct ovsdb_idl_row *row = CONST_CAST(struct ovsdb_idl_row *, row_);
    const struct ovsdb_idl_table_class *class = row->table->class_;
    const struct ovsdb_idl_column *c;
    size_t i;

    ovs_assert(is_index_row(row_));
    ovs_assert(ovs_list_is_empty(&row_->src_arcs));
    ovs_assert(ovs_list_is_empty(&row_->dst_arcs));
    BITMAP_FOR_EACH_1 (i, class->n_columns, row->written) {
        c = &class->columns[i];
        (c->unparse) (row);
        free(row->new_datum[i].values);
        free(row->new_datum[i].keys);
    }
    free(row->new_datum);
    free(row->written);
    free(row);
}

struct ovsdb_idl_row *
ovsdb_idl_index_find(struct ovsdb_idl_index *index,
                     const struct ovsdb_idl_row *target)
{
    return skiplist_get_data(skiplist_find(index->skiplist, target));
}

struct ovsdb_idl_cursor
ovsdb_idl_cursor_first(struct ovsdb_idl_index *index)
{
    struct skiplist_node *node = skiplist_first(index->skiplist);
    return (struct ovsdb_idl_cursor) { index, node };
}

struct ovsdb_idl_cursor
ovsdb_idl_cursor_first_eq(struct ovsdb_idl_index *index,
                          const struct ovsdb_idl_row *target)
{
    struct skiplist_node *node = skiplist_find(index->skiplist, target);
    return (struct ovsdb_idl_cursor) { index, node };
}

struct ovsdb_idl_cursor
ovsdb_idl_cursor_first_ge(struct ovsdb_idl_index *index,
                          const struct ovsdb_idl_row *target)
{
    struct skiplist_node *node = (target
                                  ? skiplist_forward_to(index->skiplist,
                                                        target)
                                  : skiplist_first(index->skiplist));
    return (struct ovsdb_idl_cursor) { index, node };
}

void
ovsdb_idl_cursor_next(struct ovsdb_idl_cursor *cursor)
{
    cursor->position = skiplist_next(cursor->position);
}

void
ovsdb_idl_cursor_next_eq(struct ovsdb_idl_cursor *cursor)
{
    struct ovsdb_idl_row *data = skiplist_get_data(cursor->position);
    struct skiplist_node *next_position = skiplist_next(cursor->position);
    struct ovsdb_idl_row *next_data = skiplist_get_data(next_position);
    cursor->position = (!ovsdb_idl_index_compare(cursor->index,
                                                 data, next_data)
                        ? next_position : NULL);
}

struct ovsdb_idl_row *
ovsdb_idl_cursor_data(struct ovsdb_idl_cursor *cursor)
{
    return skiplist_get_data(cursor->position);
}

/* Returns the result of comparing two rows using the comparison function
 * for this index.
 * Returns:
 * < 0 if a < b
 * 0 if a == b
 * > 0 if a > b
 * When the pointer to either row is NULL, this function considers NULL to be
 * greater than any other value, and NULL == NULL.
 */
int
ovsdb_idl_index_compare(struct ovsdb_idl_index *index,
                        const struct ovsdb_idl_row *a,
                        const struct ovsdb_idl_row *b)
{
    if (a && b) {
        return ovsdb_idl_index_generic_comparer(a, b, index);
    } else if (!a && !b) {
        return 0;
    } else if (a) {
        return -1;
    } else {
        return 1;
    }
}

static void
ovsdb_idl_row_clear_old(struct ovsdb_idl_row *row)
{
    ovs_assert(row->old_datum == row->new_datum);
    if (!ovsdb_idl_row_is_orphan(row)) {
        const struct ovsdb_idl_table_class *class = row->table->class_;
        size_t i;

        for (i = 0; i < class->n_columns; i++) {
            ovsdb_datum_destroy(&row->old_datum[i], &class->columns[i].type);
        }
        free(row->old_datum);
        row->old_datum = row->new_datum = NULL;
    }
}

static void
ovsdb_idl_row_clear_new(struct ovsdb_idl_row *row)
{
    if (row->old_datum != row->new_datum) {
        if (row->new_datum) {
            const struct ovsdb_idl_table_class *class = row->table->class_;
            size_t i;

            if (row->written) {
                BITMAP_FOR_EACH_1 (i, class->n_columns, row->written) {
                    ovsdb_datum_destroy(&row->new_datum[i],
                                        &class->columns[i].type);
                }
            }
            free(row->new_datum);
            free(row->written);
            row->written = NULL;
        }
        row->new_datum = row->old_datum;
    }
}

static void
ovsdb_idl_row_clear_arcs(struct ovsdb_idl_row *row, bool destroy_dsts)
{
    struct ovsdb_idl_arc *arc, *next;

    /* Delete all forward arcs.  If 'destroy_dsts', destroy any orphaned rows
     * that this causes to be unreferenced, if tracking is not enabled.
     * If tracking is enabled, orphaned nodes are removed from hmap but not
     * freed.
     */
    LIST_FOR_EACH_SAFE (arc, next, src_node, &row->src_arcs) {
        ovs_list_remove(&arc->dst_node);
        if (destroy_dsts
            && ovsdb_idl_row_is_orphan(arc->dst)
            && ovs_list_is_empty(&arc->dst->dst_arcs)) {
            ovsdb_idl_row_destroy(arc->dst);
        }
        free(arc);
    }
    ovs_list_init(&row->src_arcs);
}

/* Force nodes that reference 'row' to reparse. */
static void
ovsdb_idl_row_reparse_backrefs(struct ovsdb_idl_row *row)
{
    struct ovsdb_idl_arc *arc, *next;

    /* This is trickier than it looks.  ovsdb_idl_row_clear_arcs() will destroy
     * 'arc', so we need to use the "safe" variant of list traversal.  However,
     * calling an ovsdb_idl_column's 'parse' function will add an arc
     * equivalent to 'arc' to row->arcs.  That could be a problem for
     * traversal, but it adds it at the beginning of the list to prevent us
     * from stumbling upon it again.
     *
     * (If duplicate arcs were possible then we would need to make sure that
     * 'next' didn't also point into 'arc''s destination, but we forbid
     * duplicate arcs.) */
    LIST_FOR_EACH_SAFE (arc, next, dst_node, &row->dst_arcs) {
        struct ovsdb_idl_row *ref = arc->src;

        ovsdb_idl_row_unparse(ref);
        ovsdb_idl_row_clear_arcs(ref, false);
        ovsdb_idl_row_parse(ref);
    }
}

static struct ovsdb_idl_row *
ovsdb_idl_row_create__(const struct ovsdb_idl_table_class *class)
{
    struct ovsdb_idl_row *row = xzalloc(class->allocation_size);
    class->row_init(row);
    ovs_list_init(&row->src_arcs);
    ovs_list_init(&row->dst_arcs);
    hmap_node_nullify(&row->txn_node);
    ovs_list_init(&row->track_node);
    return row;
}

static struct ovsdb_idl_row *
ovsdb_idl_row_create(struct ovsdb_idl_table *table, const struct uuid *uuid)
{
    struct ovsdb_idl_row *row = ovsdb_idl_row_create__(table->class_);
    hmap_insert(&table->rows, &row->hmap_node, uuid_hash(uuid));
    row->uuid = *uuid;
    row->table = table;
    row->map_op_written = NULL;
    row->map_op_lists = NULL;
    row->set_op_written = NULL;
    row->set_op_lists = NULL;
    return row;
}

static void
ovsdb_idl_row_destroy(struct ovsdb_idl_row *row)
{
    if (row) {
        ovsdb_idl_row_clear_old(row);
        hmap_remove(&row->table->rows, &row->hmap_node);
        ovsdb_idl_destroy_all_map_op_lists(row);
        ovsdb_idl_destroy_all_set_op_lists(row);
        if (ovsdb_idl_track_is_set(row->table)) {
            row->change_seqno[OVSDB_IDL_CHANGE_DELETE]
                = row->table->change_seqno[OVSDB_IDL_CHANGE_DELETE]
                = row->table->db->change_seqno + 1;
        }
        if (!ovs_list_is_empty(&row->track_node)) {
            ovs_list_remove(&row->track_node);
        }
        ovs_list_push_back(&row->table->track_list, &row->track_node);
    }
}

static void
ovsdb_idl_destroy_all_map_op_lists(struct ovsdb_idl_row *row)
{
    if (row->map_op_written) {
        /* Clear Map Operation Lists */
        size_t idx, n_columns;
        const struct ovsdb_idl_column *columns;
        const struct ovsdb_type *type;
        n_columns = row->table->class_->n_columns;
        columns = row->table->class_->columns;
        BITMAP_FOR_EACH_1 (idx, n_columns, row->map_op_written) {
            type = &columns[idx].type;
            map_op_list_destroy(row->map_op_lists[idx], type);
        }
        free(row->map_op_lists);
        bitmap_free(row->map_op_written);
        row->map_op_lists = NULL;
        row->map_op_written = NULL;
    }
}

static void
ovsdb_idl_destroy_all_set_op_lists(struct ovsdb_idl_row *row)
{
    if (row->set_op_written) {
        /* Clear Set Operation Lists */
        size_t idx, n_columns;
        const struct ovsdb_idl_column *columns;
        const struct ovsdb_type *type;
        n_columns = row->table->class_->n_columns;
        columns = row->table->class_->columns;
        BITMAP_FOR_EACH_1 (idx, n_columns, row->set_op_written) {
            type = &columns[idx].type;
            set_op_list_destroy(row->set_op_lists[idx], type);
        }
        free(row->set_op_lists);
        bitmap_free(row->set_op_written);
        row->set_op_lists = NULL;
        row->set_op_written = NULL;
    }
}

static void
ovsdb_idl_row_destroy_postprocess(struct ovsdb_idl_db *db)
{
    size_t i;

    for (i = 0; i < db->class_->n_tables; i++) {
        struct ovsdb_idl_table *table = &db->tables[i];

        if (!ovs_list_is_empty(&table->track_list)) {
            struct ovsdb_idl_row *row, *next;

            LIST_FOR_EACH_SAFE(row, next, track_node, &table->track_list) {
                if (!ovsdb_idl_track_is_set(row->table)) {
                    ovs_list_remove(&row->track_node);
                    free(row);
                }
            }
        }
    }
}

static void
ovsdb_idl_insert_row(struct ovsdb_idl_row *row, const struct json *row_json)
{
    const struct ovsdb_idl_table_class *class = row->table->class_;
    size_t i, datum_size;

    ovs_assert(!row->old_datum && !row->new_datum);
    datum_size = class->n_columns * sizeof *row->old_datum;
    row->old_datum = row->new_datum = xmalloc(datum_size);
    for (i = 0; i < class->n_columns; i++) {
        ovsdb_datum_init_default(&row->old_datum[i], &class->columns[i].type);
    }
    ovsdb_idl_row_update(row, row_json, OVSDB_IDL_CHANGE_INSERT);
    ovsdb_idl_row_parse(row);

    ovsdb_idl_row_reparse_backrefs(row);
    ovsdb_idl_add_to_indexes(row);
}

static void
ovsdb_idl_delete_row(struct ovsdb_idl_row *row)
{
    ovsdb_idl_remove_from_indexes(row);
    ovsdb_idl_row_unparse(row);
    ovsdb_idl_row_clear_arcs(row, true);
    ovsdb_idl_row_clear_old(row);
    if (ovs_list_is_empty(&row->dst_arcs)) {
        ovsdb_idl_row_destroy(row);
    } else {
        ovsdb_idl_row_reparse_backrefs(row);
    }
}

/* Returns true if a column with mode OVSDB_IDL_MODE_RW changed, false
 * otherwise. */
static bool
ovsdb_idl_modify_row(struct ovsdb_idl_row *row, const struct json *row_json)
{
    bool changed;

    ovsdb_idl_remove_from_indexes(row);
    ovsdb_idl_row_unparse(row);
    ovsdb_idl_row_clear_arcs(row, true);
    changed = ovsdb_idl_row_update(row, row_json, OVSDB_IDL_CHANGE_MODIFY);
    ovsdb_idl_row_parse(row);
    ovsdb_idl_add_to_indexes(row);

    return changed;
}

static bool
ovsdb_idl_modify_row_by_diff(struct ovsdb_idl_row *row,
                             const struct json *diff_json)
{
    bool changed;

    ovsdb_idl_row_unparse(row);
    ovsdb_idl_row_clear_arcs(row, true);
    changed = ovsdb_idl_row_apply_diff(row, diff_json,
                                       OVSDB_IDL_CHANGE_MODIFY);
    ovsdb_idl_row_parse(row);

    return changed;
}

static bool
may_add_arc(const struct ovsdb_idl_row *src, const struct ovsdb_idl_row *dst)
{
    const struct ovsdb_idl_arc *arc;

    /* No self-arcs. */
    if (src == dst) {
        return false;
    }

    /* No duplicate arcs.
     *
     * We only need to test whether the first arc in dst->dst_arcs originates
     * at 'src', since we add all of the arcs from a given source in a clump
     * (in a single call to ovsdb_idl_row_parse()) and new arcs are always
     * added at the front of the dst_arcs list. */
    if (ovs_list_is_empty(&dst->dst_arcs)) {
        return true;
    }
    arc = CONTAINER_OF(dst->dst_arcs.next, struct ovsdb_idl_arc, dst_node);
    return arc->src != src;
}

static struct ovsdb_idl_table *
ovsdb_idl_db_table_from_class(const struct ovsdb_idl_db *db,
                              const struct ovsdb_idl_table_class *table_class)
{
    ptrdiff_t idx = table_class - db->class_->tables;
    return idx >= 0 && idx < db->class_->n_tables ? &db->tables[idx] : NULL;
}

static struct ovsdb_idl_table *
ovsdb_idl_table_from_class(const struct ovsdb_idl *idl,
                           const struct ovsdb_idl_table_class *table_class)
{
    struct ovsdb_idl_table *table;

    table = ovsdb_idl_db_table_from_class(&idl->data, table_class);
    if (!table) {
         table = ovsdb_idl_db_table_from_class(&idl->server, table_class);
    }

    return table;
}

/* Called by ovsdb-idlc generated code. */
struct ovsdb_idl_row *
ovsdb_idl_get_row_arc(struct ovsdb_idl_row *src,
                      const struct ovsdb_idl_table_class *dst_table_class,
                      const struct uuid *dst_uuid)
{
    struct ovsdb_idl_db *db = src->table->db;
    struct ovsdb_idl_table *dst_table;
    struct ovsdb_idl_arc *arc;
    struct ovsdb_idl_row *dst;

    dst_table = ovsdb_idl_db_table_from_class(db, dst_table_class);
    dst = ovsdb_idl_get_row(dst_table, dst_uuid);
    if (db->txn || is_index_row(src)) {
        /* There are two cases we should not update any arcs:
         *
         * 1. We're being called from ovsdb_idl_txn_write(). We must not update
         * any arcs, because the transaction will be backed out at commit or
         * abort time and we don't want our graph screwed up.
         *
         * 2. The row is used as an index for querying purpose only.
         *
         * In these cases, just return the destination row, if there is one and
         * it has not been deleted. */
        if (dst && (hmap_node_is_null(&dst->txn_node) || dst->new_datum)) {
            return dst;
        }
        return NULL;
    } else {
        /* We're being called from some other context.  Update the graph. */
        if (!dst) {
            dst = ovsdb_idl_row_create(dst_table, dst_uuid);
        }

        /* Add a new arc, if it wouldn't be a self-arc or a duplicate arc. */
        if (may_add_arc(src, dst)) {
            /* The arc *must* be added at the front of the dst_arcs list.  See
             * ovsdb_idl_row_reparse_backrefs() for details. */
            arc = xmalloc(sizeof *arc);
            ovs_list_push_front(&src->src_arcs, &arc->src_node);
            ovs_list_push_front(&dst->dst_arcs, &arc->dst_node);
            arc->src = src;
            arc->dst = dst;
        }

        return !ovsdb_idl_row_is_orphan(dst) ? dst : NULL;
    }
}

/* Searches 'tc''s table in 'idl' for a row with UUID 'uuid'.  Returns a
 * pointer to the row if there is one, otherwise a null pointer.  */
const struct ovsdb_idl_row *
ovsdb_idl_get_row_for_uuid(const struct ovsdb_idl *idl,
                           const struct ovsdb_idl_table_class *tc,
                           const struct uuid *uuid)
{
    return ovsdb_idl_get_row(ovsdb_idl_table_from_class(idl, tc), uuid);
}

static struct ovsdb_idl_row *
next_real_row(struct ovsdb_idl_table *table, struct hmap_node *node)
{
    for (; node; node = hmap_next(&table->rows, node)) {
        struct ovsdb_idl_row *row;

        row = CONTAINER_OF(node, struct ovsdb_idl_row, hmap_node);
        if (ovsdb_idl_row_exists(row)) {
            return row;
        }
    }
    return NULL;
}

/* Returns a row in 'table_class''s table in 'idl', or a null pointer if that
 * table is empty.
 *
 * Database tables are internally maintained as hash tables, so adding or
 * removing rows while traversing the same table can cause some rows to be
 * visited twice or not at apply. */
const struct ovsdb_idl_row *
ovsdb_idl_first_row(const struct ovsdb_idl *idl,
                    const struct ovsdb_idl_table_class *table_class)
{
    struct ovsdb_idl_table *table = ovsdb_idl_table_from_class(idl,
                                                               table_class);
    return next_real_row(table, hmap_first(&table->rows));
}

/* Returns a row following 'row' within its table, or a null pointer if 'row'
 * is the last row in its table. */
const struct ovsdb_idl_row *
ovsdb_idl_next_row(const struct ovsdb_idl_row *row)
{
    struct ovsdb_idl_table *table = row->table;

    return next_real_row(table, hmap_next(&table->rows, &row->hmap_node));
}

/* Reads and returns the value of 'column' within 'row'.  If an ongoing
 * transaction has changed 'column''s value, the modified value is returned.
 *
 * The caller must not modify or free the returned value.
 *
 * Various kinds of changes can invalidate the returned value: writing to the
 * same 'column' in 'row' (e.g. with ovsdb_idl_txn_write()), deleting 'row'
 * (e.g. with ovsdb_idl_txn_delete()), or completing an ongoing transaction
 * (e.g. with ovsdb_idl_txn_commit() or ovsdb_idl_txn_abort()).  If the
 * returned value is needed for a long time, it is best to make a copy of it
 * with ovsdb_datum_clone(). */
const struct ovsdb_datum *
ovsdb_idl_read(const struct ovsdb_idl_row *row,
               const struct ovsdb_idl_column *column)
{
    const struct ovsdb_idl_table_class *class;
    size_t column_idx;

    ovs_assert(!ovsdb_idl_row_is_synthetic(row));

    class = row->table->class_;
    column_idx = column - class->columns;

    ovs_assert(row->new_datum != NULL);
    ovs_assert(column_idx < class->n_columns);

    if (row->written && bitmap_is_set(row->written, column_idx)) {
        return &row->new_datum[column_idx];
    } else if (row->old_datum) {
        return &row->old_datum[column_idx];
    } else {
        return ovsdb_datum_default(&column->type);
    }
}

/* Same as ovsdb_idl_read(), except that it also asserts that 'column' has key
 * type 'key_type' and value type 'value_type'.  (Scalar and set types will
 * have a value type of OVSDB_TYPE_VOID.)
 *
 * This is useful in code that "knows" that a particular column has a given
 * type, so that it will abort if someone changes the column's type without
 * updating the code that uses it. */
const struct ovsdb_datum *
ovsdb_idl_get(const struct ovsdb_idl_row *row,
              const struct ovsdb_idl_column *column,
              enum ovsdb_atomic_type key_type OVS_UNUSED,
              enum ovsdb_atomic_type value_type OVS_UNUSED)
{
    ovs_assert(column->type.key.type == key_type);
    ovs_assert(column->type.value.type == value_type);

    return ovsdb_idl_read(row, column);
}

/* Returns true if the field represented by 'column' in 'row' may be modified,
 * false if it is immutable.
 *
 * Normally, whether a field is mutable is controlled by its column's schema.
 * However, an immutable column can be set to any initial value at the time of
 * insertion, so if 'row' is a new row (one that is being added as part of the
 * current transaction, supposing that a transaction is in progress) then even
 * its "immutable" fields are actually mutable. */
bool
ovsdb_idl_is_mutable(const struct ovsdb_idl_row *row,
                     const struct ovsdb_idl_column *column)
{
    return column->is_mutable || (row->new_datum && !row->old_datum);
}

/* Returns false if 'row' was obtained from the IDL, true if it was initialized
 * to all-zero-bits by some other entity.  If 'row' was set up some other way
 * then the return value is indeterminate. */
bool
ovsdb_idl_row_is_synthetic(const struct ovsdb_idl_row *row)
{
    return row->table == NULL;
}

/* Transactions. */

static void ovsdb_idl_txn_complete(struct ovsdb_idl_txn *txn,
                                   enum ovsdb_idl_txn_status);

/* Returns a string representation of 'status'.  The caller must not modify or
 * free the returned string.
 *
 * The return value is probably useful only for debug log messages and unit
 * tests. */
const char *
ovsdb_idl_txn_status_to_string(enum ovsdb_idl_txn_status status)
{
    switch (status) {
    case TXN_UNCOMMITTED:
        return "uncommitted";
    case TXN_UNCHANGED:
        return "unchanged";
    case TXN_INCOMPLETE:
        return "incomplete";
    case TXN_ABORTED:
        return "aborted";
    case TXN_SUCCESS:
        return "success";
    case TXN_TRY_AGAIN:
        return "try again";
    case TXN_NOT_LOCKED:
        return "not locked";
    case TXN_ERROR:
        return "error";
    }
    return "<unknown>";
}

/* Starts a new transaction on 'idl'.  A given ovsdb_idl may only have a single
 * active transaction at a time.  See the large comment in ovsdb-idl.h for
 * general information on transactions. */
struct ovsdb_idl_txn *
ovsdb_idl_txn_create(struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;

    ovs_assert(!idl->data.txn);
    idl->data.txn = txn = xmalloc(sizeof *txn);
    txn->request_id = NULL;
    txn->db = &idl->data;
    hmap_init(&txn->txn_rows);
    txn->status = TXN_UNCOMMITTED;
    txn->error = NULL;
    txn->dry_run = false;
    ds_init(&txn->comment);

    txn->inc_table = NULL;
    txn->inc_column = NULL;

    hmap_init(&txn->inserted_rows);

    return txn;
}

/* Appends 's', which is treated as a printf()-type format string, to the
 * comments that will be passed to the OVSDB server when 'txn' is committed.
 * (The comment will be committed to the OVSDB log, which "ovsdb-tool
 * show-log" can print in a relatively human-readable form.) */
void
ovsdb_idl_txn_add_comment(struct ovsdb_idl_txn *txn, const char *s, ...)
{
    va_list args;

    if (txn->comment.length) {
        ds_put_char(&txn->comment, '\n');
    }

    va_start(args, s);
    ds_put_format_valist(&txn->comment, s, args);
    va_end(args);
}

/* Marks 'txn' as a transaction that will not actually modify the database.  In
 * almost every way, the transaction is treated like other transactions.  It
 * must be committed or aborted like other transactions, it will be sent to the
 * database server like other transactions, and so on.  The only difference is
 * that the operations sent to the database server will include, as the last
 * step, an "abort" operation, so that any changes made by the transaction will
 * not actually take effect. */
void
ovsdb_idl_txn_set_dry_run(struct ovsdb_idl_txn *txn)
{
    txn->dry_run = true;
}

/* Causes 'txn', when committed, to increment the value of 'column' within
 * 'row' by 1.  'column' must have an integer type.  After 'txn' commits
 * successfully, the client may retrieve the final (incremented) value of
 * 'column' with ovsdb_idl_txn_get_increment_new_value().
 *
 * If at time of commit the transaction is otherwise empty, that is, it doesn't
 * change the database, then 'force' is important.  If 'force' is false in this
 * case, the IDL suppresses the increment and skips a round trip to the
 * database server.  If 'force' is true, the IDL will still increment the
 * column.
 *
 * The client could accomplish something similar with ovsdb_idl_read(),
 * ovsdb_idl_txn_verify() and ovsdb_idl_txn_write(), or with ovsdb-idlc
 * generated wrappers for these functions.  However, ovsdb_idl_txn_increment()
 * will never (by itself) fail because of a verify error.
 *
 * The intended use is for incrementing the "next_cfg" column in the
 * Open_vSwitch table. */
void
ovsdb_idl_txn_increment(struct ovsdb_idl_txn *txn,
                        const struct ovsdb_idl_row *row,
                        const struct ovsdb_idl_column *column,
                        bool force)
{
    ovs_assert(!txn->inc_table);
    ovs_assert(column->type.key.type == OVSDB_TYPE_INTEGER);
    ovs_assert(column->type.value.type == OVSDB_TYPE_VOID);

    txn->inc_table = row->table->class_->name;
    txn->inc_column = column->name;
    txn->inc_row = row->uuid;
    txn->inc_force = force;
}

/* Destroys 'txn' and frees all associated memory.  If ovsdb_idl_txn_commit()
 * has been called for 'txn' but the commit is still incomplete (that is, the
 * last call returned TXN_INCOMPLETE) then the transaction may or may not still
 * end up committing at the database server, but the client will not be able to
 * get any further status information back. */
void
ovsdb_idl_txn_destroy(struct ovsdb_idl_txn *txn)
{
    struct ovsdb_idl_txn_insert *insert, *next;

    json_destroy(txn->request_id);
    if (txn->status == TXN_INCOMPLETE) {
        hmap_remove(&txn->db->outstanding_txns, &txn->hmap_node);
    }
    ovsdb_idl_txn_abort(txn);
    ds_destroy(&txn->comment);
    free(txn->error);
    HMAP_FOR_EACH_SAFE (insert, next, hmap_node, &txn->inserted_rows) {
        free(insert);
    }
    hmap_destroy(&txn->inserted_rows);
    free(txn);
}

/* Causes poll_block() to wake up if 'txn' has completed committing. */
void
ovsdb_idl_txn_wait(const struct ovsdb_idl_txn *txn)
{
    if (txn->status != TXN_UNCOMMITTED && txn->status != TXN_INCOMPLETE) {
        poll_immediate_wake();
    }
}

static struct json *
where_uuid_equals(const struct uuid *uuid)
{
    return
        json_array_create_1(
            json_array_create_3(
                json_string_create("_uuid"),
                json_string_create("=="),
                json_array_create_2(
                    json_string_create("uuid"),
                    json_string_create_nocopy(
                        xasprintf(UUID_FMT, UUID_ARGS(uuid))))));
}

static const struct ovsdb_idl_row *
ovsdb_idl_txn_get_row(const struct ovsdb_idl_txn *txn, const struct uuid *uuid)
{
    const struct ovsdb_idl_row *row;

    HMAP_FOR_EACH_WITH_HASH (row, txn_node, uuid_hash(uuid), &txn->txn_rows) {
        if (uuid_equals(&row->uuid, uuid)) {
            return row;
        }
    }
    return NULL;
}

/* XXX there must be a cleaner way to do this */
static struct json *
substitute_uuids(struct json *json, const struct ovsdb_idl_txn *txn)
{
    if (json->type == JSON_ARRAY) {
        struct uuid uuid;
        size_t i;

        if (json->array.n == 2
            && json->array.elems[0]->type == JSON_STRING
            && json->array.elems[1]->type == JSON_STRING
            && !strcmp(json->array.elems[0]->string, "uuid")
            && uuid_from_string(&uuid, json->array.elems[1]->string)) {
            const struct ovsdb_idl_row *row;

            row = ovsdb_idl_txn_get_row(txn, &uuid);
            if (row && !row->old_datum && row->new_datum) {
                json_destroy(json);

                return json_array_create_2(
                    json_string_create("named-uuid"),
                    json_string_create_nocopy(ovsdb_data_row_name(&uuid)));
            }
        }

        for (i = 0; i < json->array.n; i++) {
            json->array.elems[i] = substitute_uuids(json->array.elems[i],
                                                      txn);
        }
    } else if (json->type == JSON_OBJECT) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, json_object(json)) {
            node->data = substitute_uuids(node->data, txn);
        }
    }
    return json;
}

static void
ovsdb_idl_txn_disassemble(struct ovsdb_idl_txn *txn)
{
    struct ovsdb_idl_row *row, *next;

    /* This must happen early.  Otherwise, ovsdb_idl_row_parse() will call an
     * ovsdb_idl_column's 'parse' function, which will call
     * ovsdb_idl_get_row_arc(), which will seen that the IDL is in a
     * transaction and fail to update the graph.  */
    txn->db->txn = NULL;

    HMAP_FOR_EACH_SAFE (row, next, txn_node, &txn->txn_rows) {
        ovsdb_idl_destroy_all_map_op_lists(row);
        ovsdb_idl_destroy_all_set_op_lists(row);
        if (row->old_datum) {
            if (row->written) {
                ovsdb_idl_row_unparse(row);
                ovsdb_idl_row_clear_arcs(row, false);
                ovsdb_idl_row_parse(row);
            }
        } else {
            ovsdb_idl_row_unparse(row);
        }
        ovsdb_idl_row_clear_new(row);

        free(row->prereqs);
        row->prereqs = NULL;

        free(row->written);
        row->written = NULL;

        hmap_remove(&txn->txn_rows, &row->txn_node);
        hmap_node_nullify(&row->txn_node);
        if (!row->old_datum) {
            hmap_remove(&row->table->rows, &row->hmap_node);
            free(row);
        }
    }
    hmap_destroy(&txn->txn_rows);
    hmap_init(&txn->txn_rows);
}

static bool
ovsdb_idl_txn_extract_mutations(struct ovsdb_idl_row *row,
                                struct json *mutations)
{
    const struct ovsdb_idl_table_class *class = row->table->class_;
    size_t idx;
    bool any_mutations = false;

    if (row->map_op_written) {
        BITMAP_FOR_EACH_1(idx, class->n_columns, row->map_op_written) {
            struct map_op_list *map_op_list;
            const struct ovsdb_idl_column *column;
            const struct ovsdb_datum *old_datum;
            enum ovsdb_atomic_type key_type, value_type;
            struct json *mutation, *map, *col_name, *mutator;
            struct json *del_set, *ins_map;
            bool any_del, any_ins;

            map_op_list = row->map_op_lists[idx];
            column = &class->columns[idx];
            key_type = column->type.key.type;
            value_type = column->type.value.type;

            /* Get the value to be changed */
            if (row->new_datum && row->written
                && bitmap_is_set(row->written,idx)) {
                old_datum = &row->new_datum[idx];
            } else if (row->old_datum != NULL) {
                old_datum = &row->old_datum[idx];
            } else {
                old_datum = ovsdb_datum_default(&column->type);
            }

            del_set = json_array_create_empty();
            ins_map = json_array_create_empty();
            any_del = false;
            any_ins = false;

            for (struct map_op *map_op = map_op_list_first(map_op_list); map_op;
                 map_op = map_op_list_next(map_op_list, map_op)) {

                if (map_op_type(map_op) == MAP_OP_UPDATE) {
                    /* Find out if value really changed. */
                    struct ovsdb_datum *new_datum;
                    unsigned int pos;
                    new_datum = map_op_datum(map_op);
                    pos = ovsdb_datum_find_key(old_datum,
                                               &new_datum->keys[0],
                                               key_type);
                    if (ovsdb_atom_equals(&new_datum->values[0],
                                          &old_datum->values[pos],
                                          value_type)) {
                        /* No change in value. Move on to next update. */
                        continue;
                    }
                } else if (map_op_type(map_op) == MAP_OP_DELETE){
                    /* Verify that there is a key to delete. */
                    unsigned int pos;
                    pos = ovsdb_datum_find_key(old_datum,
                                               &map_op_datum(map_op)->keys[0],
                                               key_type);
                    if (pos == UINT_MAX) {
                        /* No key to delete.  Move on to next update. */
                        VLOG_WARN("Trying to delete a key that doesn't "
                                  "exist in the map.");
                        continue;
                    }
                }

                if (map_op_type(map_op) == MAP_OP_INSERT) {
                    map = json_array_create_2(
                        ovsdb_atom_to_json(&map_op_datum(map_op)->keys[0],
                                           key_type),
                        ovsdb_atom_to_json(&map_op_datum(map_op)->values[0],
                                           value_type));
                    json_array_add(ins_map, map);
                    any_ins = true;
                } else { /* MAP_OP_UPDATE or MAP_OP_DELETE */
                    map = ovsdb_atom_to_json(&map_op_datum(map_op)->keys[0],
                                             key_type);
                    json_array_add(del_set, map);
                    any_del = true;
                }

                /* Generate an additional insert mutate for updates. */
                if (map_op_type(map_op) == MAP_OP_UPDATE) {
                    map = json_array_create_2(
                        ovsdb_atom_to_json(&map_op_datum(map_op)->keys[0],
                                           key_type),
                        ovsdb_atom_to_json(&map_op_datum(map_op)->values[0],
                                           value_type));
                    json_array_add(ins_map, map);
                    any_ins = true;
                }
            }

            if (any_del) {
                col_name = json_string_create(column->name);
                mutator = json_string_create("delete");
                map = json_array_create_2(json_string_create("set"), del_set);
                mutation = json_array_create_3(col_name, mutator, map);
                json_array_add(mutations, mutation);
                any_mutations = true;
            } else {
                json_destroy(del_set);
            }
            if (any_ins) {
                col_name = json_string_create(column->name);
                mutator = json_string_create("insert");
                map = json_array_create_2(json_string_create("map"), ins_map);
                mutation = json_array_create_3(col_name, mutator, map);
                json_array_add(mutations, mutation);
                any_mutations = true;
            } else {
                json_destroy(ins_map);
            }
        }
    }
    if (row->set_op_written) {
        BITMAP_FOR_EACH_1(idx, class->n_columns, row->set_op_written) {
            struct set_op_list *set_op_list;
            const struct ovsdb_idl_column *column;
            const struct ovsdb_datum *old_datum;
            enum ovsdb_atomic_type key_type;
            struct json *mutation, *set, *col_name, *mutator;
            struct json *del_set, *ins_set;
            bool any_del, any_ins;

            set_op_list = row->set_op_lists[idx];
            column = &class->columns[idx];
            key_type = column->type.key.type;

            /* Get the value to be changed */
            if (row->new_datum && row->written
                && bitmap_is_set(row->written,idx)) {
                old_datum = &row->new_datum[idx];
            } else if (row->old_datum != NULL) {
                old_datum = &row->old_datum[idx];
            } else {
                old_datum = ovsdb_datum_default(&column->type);
            }

            del_set = json_array_create_empty();
            ins_set = json_array_create_empty();
            any_del = false;
            any_ins = false;

            for (struct set_op *set_op = set_op_list_first(set_op_list); set_op;
                 set_op = set_op_list_next(set_op_list, set_op)) {
                if (set_op_type(set_op) == SET_OP_INSERT) {
                    set = ovsdb_atom_to_json(&set_op_datum(set_op)->keys[0],
                                             key_type);
                    json_array_add(ins_set, set);
                    any_ins = true;
                } else { /* SETP_OP_DELETE */
                    /* Verify that there is a key to delete. */
                    unsigned int pos;
                    pos = ovsdb_datum_find_key(old_datum,
                                               &set_op_datum(set_op)->keys[0],
                                               key_type);
                    if (pos == UINT_MAX) {
                        /* No key to delete.  Move on to next update. */
                        VLOG_WARN("Trying to delete a key that doesn't "
                                  "exist in the set.");
                        continue;
                    }
                    set = ovsdb_atom_to_json(&set_op_datum(set_op)->keys[0],
                                             key_type);
                    json_array_add(del_set, set);
                    any_del = true;
                }
            }
            if (any_del) {
                col_name = json_string_create(column->name);
                mutator = json_string_create("delete");
                set = json_array_create_2(json_string_create("set"), del_set);
                mutation = json_array_create_3(col_name, mutator, set);
                json_array_add(mutations, mutation);
                any_mutations = true;
            } else {
                json_destroy(del_set);
            }
            if (any_ins) {
                col_name = json_string_create(column->name);
                mutator = json_string_create("insert");
                set = json_array_create_2(json_string_create("set"), ins_set);
                mutation = json_array_create_3(col_name, mutator, set);
                json_array_add(mutations, mutation);
                any_mutations = true;
            } else {
                json_destroy(ins_set);
            }
        }
    }
    return any_mutations;
}

/* Attempts to commit 'txn'.  Returns the status of the commit operation, one
 * of the following TXN_* constants:
 *
 *   TXN_INCOMPLETE:
 *
 *       The transaction is in progress, but not yet complete.  The caller
 *       should call again later, after calling ovsdb_idl_run() to let the IDL
 *       do OVSDB protocol processing.
 *
 *   TXN_UNCHANGED:
 *
 *       The transaction is complete.  (It didn't actually change the database,
 *       so the IDL didn't send any request to the database server.)
 *
 *   TXN_ABORTED:
 *
 *       The caller previously called ovsdb_idl_txn_abort().
 *
 *   TXN_SUCCESS:
 *
 *       The transaction was successful.  The update made by the transaction
 *       (and possibly other changes made by other database clients) should
 *       already be visible in the IDL.
 *
 *   TXN_TRY_AGAIN:
 *
 *       The transaction failed for some transient reason, e.g. because a
 *       "verify" operation reported an inconsistency or due to a network
 *       problem.  The caller should wait for a change to the database, then
 *       compose a new transaction, and commit the new transaction.
 *
 *       Use the return value of ovsdb_idl_get_seqno() to wait for a change in
 *       the database.  It is important to use its return value *before* the
 *       initial call to ovsdb_idl_txn_commit() as the baseline for this
 *       purpose, because the change that one should wait for can happen after
 *       the initial call but before the call that returns TXN_TRY_AGAIN, and
 *       using some other baseline value in that situation could cause an
 *       indefinite wait if the database rarely changes.
 *
 *   TXN_NOT_LOCKED:
 *
 *       The transaction failed because the IDL has been configured to require
 *       a database lock (with ovsdb_idl_set_lock()) but didn't get it yet or
 *       has already lost it.
 *
 * Committing a transaction rolls back all of the changes that it made to the
 * IDL's copy of the database.  If the transaction commits successfully, then
 * the database server will send an update and, thus, the IDL will be updated
 * with the committed changes. */
enum ovsdb_idl_txn_status
ovsdb_idl_txn_commit(struct ovsdb_idl_txn *txn)
{
    struct ovsdb_idl_row *row;
    struct json *operations;
    bool any_updates;

    if (txn != txn->db->txn) {
        goto coverage_out;
    }

    /* If we need a lock but don't have it, give up quickly. */
    if (txn->db->lock_name && !txn->db->has_lock) {
        txn->status = TXN_NOT_LOCKED;
        goto disassemble_out;
    }

    operations = json_array_create_1(
        json_string_create(txn->db->class_->database));

    /* Assert that we have the required lock (avoiding a race). */
    if (txn->db->lock_name) {
        struct json *op = json_object_create();
        json_array_add(operations, op);
        json_object_put_string(op, "op", "assert");
        json_object_put_string(op, "lock", txn->db->lock_name);
    }

    /* Add prerequisites and declarations of new rows. */
    HMAP_FOR_EACH (row, txn_node, &txn->txn_rows) {
        /* XXX check that deleted rows exist even if no prereqs? */
        if (row->prereqs) {
            const struct ovsdb_idl_table_class *class = row->table->class_;
            size_t n_columns = class->n_columns;
            struct json *op, *columns, *row_json;
            size_t idx;

            op = json_object_create();
            json_array_add(operations, op);
            json_object_put_string(op, "op", "wait");
            json_object_put_string(op, "table", class->name);
            json_object_put(op, "timeout", json_integer_create(0));
            json_object_put(op, "where", where_uuid_equals(&row->uuid));
            json_object_put_string(op, "until", "==");
            columns = json_array_create_empty();
            json_object_put(op, "columns", columns);
            row_json = json_object_create();
            json_object_put(op, "rows", json_array_create_1(row_json));

            BITMAP_FOR_EACH_1 (idx, n_columns, row->prereqs) {
                const struct ovsdb_idl_column *column = &class->columns[idx];
                json_array_add(columns, json_string_create(column->name));
                json_object_put(row_json, column->name,
                                ovsdb_datum_to_json(&row->old_datum[idx],
                                                    &column->type));
            }
        }
    }

    /* Add updates. */
    any_updates = false;

    /* For tables constrained to have only a single row (a fairly common OVSDB
     * pattern for storing global data), identify whether we're inserting a
     * row.  If so, then verify that the table is empty before inserting the
     * row.  This gives us a clear verification-related failure if there was an
     * insertion race with another client. */
    for (size_t i = 0; i < txn->db->class_->n_tables; i++) {
        struct ovsdb_idl_table *table = &txn->db->tables[i];
        if (table->class_->is_singleton) {
            /* Count the number of rows in the table before and after our
             * transaction commits.  This is O(n) in the number of rows in the
             * table, but that's OK since we know that the table should only
             * have one row. */
            size_t initial_rows = 0;
            size_t final_rows = 0;
            HMAP_FOR_EACH (row, hmap_node, &table->rows) {
                initial_rows += row->old_datum != NULL;
                final_rows += row->new_datum != NULL;
            }

            if (initial_rows == 0 && final_rows == 1) {
                struct json *op = json_object_create();
                json_array_add(operations, op);
                json_object_put_string(op, "op", "wait");
                json_object_put_string(op, "table", table->class_->name);
                json_object_put(op, "where", json_array_create_empty());
                json_object_put(op, "timeout", json_integer_create(0));
                json_object_put_string(op, "until", "==");
                json_object_put(op, "rows", json_array_create_empty());
            }
        }
    }

    HMAP_FOR_EACH (row, txn_node, &txn->txn_rows) {
        const struct ovsdb_idl_table_class *class = row->table->class_;

        if (!row->new_datum) {
            if (class->is_root) {
                struct json *op = json_object_create();
                json_object_put_string(op, "op", "delete");
                json_object_put_string(op, "table", class->name);
                json_object_put(op, "where", where_uuid_equals(&row->uuid));
                json_array_add(operations, op);
                any_updates = true;
            } else {
                /* Let ovsdb-server decide whether to really delete it. */
            }
        } else if (row->old_datum != row->new_datum) {
            struct json *row_json;
            size_t idx;

            struct json *op = json_object_create();
            json_object_put_string(op, "op",
                                   row->old_datum ? "update" : "insert");
            json_object_put_string(op, "table", class->name);
            if (row->old_datum) {
                json_object_put(op, "where", where_uuid_equals(&row->uuid));
            } else {
                struct ovsdb_idl_txn_insert *insert;

                any_updates = true;

                json_object_put(op, "uuid-name",
                                json_string_create_nocopy(
                                    ovsdb_data_row_name(&row->uuid)));

                insert = xmalloc(sizeof *insert);
                insert->dummy = row->uuid;
                insert->op_index = operations->array.n - 1;
                uuid_zero(&insert->real);
                hmap_insert(&txn->inserted_rows, &insert->hmap_node,
                            uuid_hash(&insert->dummy));
            }
            row_json = json_object_create();
            json_object_put(op, "row", row_json);

            if (row->written) {
                BITMAP_FOR_EACH_1 (idx, class->n_columns, row->written) {
                    const struct ovsdb_idl_column *column =
                                                        &class->columns[idx];

                    if (row->old_datum
                        || !ovsdb_datum_is_default(&row->new_datum[idx],
                                                  &column->type)) {
                        struct json *value;

                        value = ovsdb_datum_to_json(&row->new_datum[idx],
                                                    &column->type);
                        json_object_put(row_json, column->name,
                                        substitute_uuids(value, txn));

                        /* If anything really changed, consider it an update.
                         * We can't suppress not-really-changed values earlier
                         * or transactions would become nonatomic (see the big
                         * comment inside ovsdb_idl_txn_write()). */
                        if (!any_updates && row->old_datum &&
                            !ovsdb_datum_equals(&row->old_datum[idx],
                                                &row->new_datum[idx],
                                                &column->type)) {
                            any_updates = true;
                        }
                    }
                }
            }

            if (!row->old_datum || !shash_is_empty(json_object(row_json))) {
                json_array_add(operations, op);
            } else {
                json_destroy(op);
            }
        }

        /* Add mutate operation, for partial map or partial set updates. */
        if (row->map_op_written || row->set_op_written) {
            struct json *op, *mutations;
            bool any_mutations;

            op = json_object_create();
            json_object_put_string(op, "op", "mutate");
            json_object_put_string(op, "table", class->name);
            json_object_put(op, "where", where_uuid_equals(&row->uuid));
            mutations = json_array_create_empty();
            any_mutations = ovsdb_idl_txn_extract_mutations(row, mutations);
            json_object_put(op, "mutations", mutations);

            if (any_mutations) {
                op = substitute_uuids(op, txn);
                json_array_add(operations, op);
                any_updates = true;
            } else {
                json_destroy(op);
            }
        }
    }

    /* Add increment. */
    if (txn->inc_table && (any_updates || txn->inc_force)) {
        any_updates = true;
        txn->inc_index = operations->array.n - 1;

        struct json *op = json_object_create();
        json_object_put_string(op, "op", "mutate");
        json_object_put_string(op, "table", txn->inc_table);
        json_object_put(op, "where",
                        substitute_uuids(where_uuid_equals(&txn->inc_row),
                                         txn));
        json_object_put(op, "mutations",
                        json_array_create_1(
                            json_array_create_3(
                                json_string_create(txn->inc_column),
                                json_string_create("+="),
                                json_integer_create(1))));
        json_array_add(operations, op);

        op = json_object_create();
        json_object_put_string(op, "op", "select");
        json_object_put_string(op, "table", txn->inc_table);
        json_object_put(op, "where",
                        substitute_uuids(where_uuid_equals(&txn->inc_row),
                                         txn));
        json_object_put(op, "columns",
                        json_array_create_1(json_string_create(
                                                txn->inc_column)));
        json_array_add(operations, op);
    }

    if (txn->comment.length) {
        struct json *op = json_object_create();
        json_object_put_string(op, "op", "comment");
        json_object_put_string(op, "comment", ds_cstr(&txn->comment));
        json_array_add(operations, op);
    }

    if (txn->dry_run) {
        struct json *op = json_object_create();
        json_object_put_string(op, "op", "abort");
        json_array_add(operations, op);
    }

    if (!any_updates) {
        txn->status = TXN_UNCHANGED;
        json_destroy(operations);
    } else if (!jsonrpc_session_send(
                   txn->db->idl->session,
                   jsonrpc_create_request(
                       "transact", operations, &txn->request_id))) {
        hmap_insert(&txn->db->outstanding_txns, &txn->hmap_node,
                    json_hash(txn->request_id, 0));
        txn->status = TXN_INCOMPLETE;
    } else {
        txn->status = TXN_TRY_AGAIN;
    }

disassemble_out:
    ovsdb_idl_txn_disassemble(txn);
coverage_out:
    switch (txn->status) {
    case TXN_UNCOMMITTED:   COVERAGE_INC(txn_uncommitted);    break;
    case TXN_UNCHANGED:     COVERAGE_INC(txn_unchanged);      break;
    case TXN_INCOMPLETE:    COVERAGE_INC(txn_incomplete);     break;
    case TXN_ABORTED:       COVERAGE_INC(txn_aborted);        break;
    case TXN_SUCCESS:       COVERAGE_INC(txn_success);        break;
    case TXN_TRY_AGAIN:     COVERAGE_INC(txn_try_again);      break;
    case TXN_NOT_LOCKED:    COVERAGE_INC(txn_not_locked);     break;
    case TXN_ERROR:         COVERAGE_INC(txn_error);          break;
    }

    return txn->status;
}

/* Attempts to commit 'txn', blocking until the commit either succeeds or
 * fails.  Returns the final commit status, which may be any TXN_* value other
 * than TXN_INCOMPLETE.
 *
 * This function calls ovsdb_idl_run() on 'txn''s IDL, so it may cause the
 * return value of ovsdb_idl_get_seqno() to change. */
enum ovsdb_idl_txn_status
ovsdb_idl_txn_commit_block(struct ovsdb_idl_txn *txn)
{
    enum ovsdb_idl_txn_status status;

    fatal_signal_run();
    while ((status = ovsdb_idl_txn_commit(txn)) == TXN_INCOMPLETE) {
        ovsdb_idl_run(txn->db->idl);
        ovsdb_idl_wait(txn->db->idl);
        ovsdb_idl_txn_wait(txn);
        poll_block();
    }
    return status;
}

/* Returns the final (incremented) value of the column in 'txn' that was set to
 * be incremented by ovsdb_idl_txn_increment().  'txn' must have committed
 * successfully. */
int64_t
ovsdb_idl_txn_get_increment_new_value(const struct ovsdb_idl_txn *txn)
{
    ovs_assert(txn->status == TXN_SUCCESS);
    return txn->inc_new_value;
}

/* Aborts 'txn' without sending it to the database server.  This is effective
 * only if ovsdb_idl_txn_commit() has not yet been called for 'txn'.
 * Otherwise, it has no effect.
 *
 * Aborting a transaction doesn't free its memory.  Use
 * ovsdb_idl_txn_destroy() to do that. */
void
ovsdb_idl_txn_abort(struct ovsdb_idl_txn *txn)
{
    ovsdb_idl_txn_disassemble(txn);
    if (txn->status == TXN_UNCOMMITTED || txn->status == TXN_INCOMPLETE) {
        txn->status = TXN_ABORTED;
    }
}

/* Returns a string that reports the error status for 'txn'.  The caller must
 * not modify or free the returned string.  A call to ovsdb_idl_txn_destroy()
 * for 'txn' may free the returned string.
 *
 * The return value is ordinarily one of the strings that
 * ovsdb_idl_txn_status_to_string() would return, but if the transaction failed
 * due to an error reported by the database server, the return value is that
 * error. */
const char *
ovsdb_idl_txn_get_error(const struct ovsdb_idl_txn *txn)
{
    if (txn->status != TXN_ERROR) {
        return ovsdb_idl_txn_status_to_string(txn->status);
    } else if (txn->error) {
        return txn->error;
    } else {
        return "no error details available";
    }
}

static void
ovsdb_idl_txn_set_error_json(struct ovsdb_idl_txn *txn,
                             const struct json *json)
{
    if (json && txn->error == NULL) {
        txn->error = json_to_string(json, JSSF_SORT);
    }
}

/* For transaction 'txn' that completed successfully, finds and returns the
 * permanent UUID that the database assigned to a newly inserted row, given the
 * 'uuid' that ovsdb_idl_txn_insert() assigned locally to that row.
 *
 * Returns NULL if 'uuid' is not a UUID assigned by ovsdb_idl_txn_insert() or
 * if it was assigned by that function and then deleted by
 * ovsdb_idl_txn_delete() within the same transaction.  (Rows that are inserted
 * and then deleted within a single transaction are never sent to the database
 * server, so it never assigns them a permanent UUID.) */
const struct uuid *
ovsdb_idl_txn_get_insert_uuid(const struct ovsdb_idl_txn *txn,
                              const struct uuid *uuid)
{
    const struct ovsdb_idl_txn_insert *insert;

    ovs_assert(txn->status == TXN_SUCCESS || txn->status == TXN_UNCHANGED);
    HMAP_FOR_EACH_IN_BUCKET (insert, hmap_node,
                             uuid_hash(uuid), &txn->inserted_rows) {
        if (uuid_equals(uuid, &insert->dummy)) {
            return &insert->real;
        }
    }
    return NULL;
}

static void
ovsdb_idl_txn_complete(struct ovsdb_idl_txn *txn,
                       enum ovsdb_idl_txn_status status)
{
    txn->status = status;
    hmap_remove(&txn->db->outstanding_txns, &txn->hmap_node);
}

static void
ovsdb_idl_txn_write__(const struct ovsdb_idl_row *row_,
                      const struct ovsdb_idl_column *column,
                      struct ovsdb_datum *datum, bool owns_datum)
{
    struct ovsdb_idl_row *row = CONST_CAST(struct ovsdb_idl_row *, row_);
    const struct ovsdb_idl_table_class *class;
    size_t column_idx;
    bool write_only;

    ovs_assert(!column->is_synthetic);
    if (ovsdb_idl_row_is_synthetic(row)) {
        goto discard_datum;
    }

    class = row->table->class_;
    column_idx = column - class->columns;
    write_only = row->table->modes[column_idx] == OVSDB_IDL_MONITOR;

    ovs_assert(row->new_datum != NULL);
    ovs_assert(column_idx < class->n_columns);
    ovs_assert(row->old_datum == NULL ||
               row->table->modes[column_idx] & OVSDB_IDL_MONITOR);

    if (row->table->db->verify_write_only && !write_only) {
        VLOG_ERR("Bug: Attempt to write to a read/write column (%s:%s) when"
                 " explicitly configured not to.", class->name, column->name);
        goto discard_datum;
    }

    /* If this is a write-only column and the datum being written is the same
     * as the one already there, just skip the update entirely.  This is worth
     * optimizing because we have a lot of columns that get periodically
     * refreshed into the database but don't actually change that often.
     *
     * We don't do this for read/write columns because that would break
     * atomicity of transactions--some other client might have written a
     * different value in that column since we read it.  (But if a whole
     * transaction only does writes of existing values, without making any real
     * changes, we will drop the whole transaction later in
     * ovsdb_idl_txn_commit().) */
    if (write_only && ovsdb_datum_equals(ovsdb_idl_read(row, column),
                                         datum, &column->type)) {
        goto discard_datum;
    }

    if (hmap_node_is_null(&row->txn_node)) {
        hmap_insert(&row->table->db->txn->txn_rows, &row->txn_node,
                    uuid_hash(&row->uuid));
    }
    if (row->old_datum == row->new_datum) {
        row->new_datum = xmalloc(class->n_columns * sizeof *row->new_datum);
    }
    if (!row->written) {
        row->written = bitmap_allocate(class->n_columns);
    }
    if (bitmap_is_set(row->written, column_idx)) {
        ovsdb_datum_destroy(&row->new_datum[column_idx], &column->type);
    } else {
        bitmap_set1(row->written, column_idx);
    }
    if (owns_datum) {
        row->new_datum[column_idx] = *datum;
    } else {
        ovsdb_datum_clone(&row->new_datum[column_idx], datum, &column->type);
    }
    (column->unparse)(row);
    (column->parse)(row, &row->new_datum[column_idx]);
    return;

discard_datum:
    if (owns_datum) {
        ovsdb_datum_destroy(datum, &column->type);
    }
}

/* Writes 'datum' to the specified 'column' in 'row_'.  Updates both 'row_'
 * itself and the structs derived from it (e.g. the "struct ovsrec_*", for
 * ovs-vswitchd).
 *
 * 'datum' must have the correct type for its column, but it needs not be
 * sorted or unique because this function will take care of that.  The IDL does
 * not check that it meets schema constraints, but ovsdb-server will do so at
 * commit time so it had better be correct.
 *
 * A transaction must be in progress.  Replication of 'column' must not have
 * been disabled (by calling ovsdb_idl_omit()).
 *
 * Usually this function is used indirectly through one of the "set" functions
 * generated by ovsdb-idlc.
 *
 * Takes ownership of what 'datum' points to (and in some cases destroys that
 * data before returning) but makes a copy of 'datum' itself.  (Commonly
 * 'datum' is on the caller's stack.) */
void
ovsdb_idl_txn_write(const struct ovsdb_idl_row *row,
                    const struct ovsdb_idl_column *column,
                    struct ovsdb_datum *datum)
{
    ovsdb_datum_sort_unique(datum,
                            column->type.key.type, column->type.value.type);
    ovsdb_idl_txn_write__(row, column, datum, true);
}

/* Similar to ovsdb_idl_txn_write(), except:
 *
 *     - The caller retains ownership of 'datum' and what it points to.
 *
 *     - The caller must ensure that 'datum' is sorted and unique (e.g. via
 *       ovsdb_datum_sort_unique().) */
void
ovsdb_idl_txn_write_clone(const struct ovsdb_idl_row *row,
                          const struct ovsdb_idl_column *column,
                          const struct ovsdb_datum *datum)
{
    ovsdb_idl_txn_write__(row, column,
                          CONST_CAST(struct ovsdb_datum *, datum), false);
}

/* Causes the original contents of 'column' in 'row_' to be verified as a
 * prerequisite to completing the transaction.  That is, if 'column' in 'row_'
 * changed (or if 'row_' was deleted) between the time that the IDL originally
 * read its contents and the time that the transaction commits, then the
 * transaction aborts and ovsdb_idl_txn_commit() returns TXN_TRY_AGAIN.
 *
 * The intention is that, to ensure that no transaction commits based on dirty
 * reads, an application should call ovsdb_idl_txn_verify() on each data item
 * read as part of a read-modify-write operation.
 *
 * In some cases ovsdb_idl_txn_verify() reduces to a no-op, because the current
 * value of 'column' is already known:
 *
 *   - If 'row_' is a row created by the current transaction (returned by
 *     ovsdb_idl_txn_insert()).
 *
 *   - If 'column' has already been modified (with ovsdb_idl_txn_write())
 *     within the current transaction.
 *
 * Because of the latter property, always call ovsdb_idl_txn_verify() *before*
 * ovsdb_idl_txn_write() for a given read-modify-write.
 *
 * A transaction must be in progress.
 *
 * Usually this function is used indirectly through one of the "verify"
 * functions generated by ovsdb-idlc. */
void
ovsdb_idl_txn_verify(const struct ovsdb_idl_row *row_,
                     const struct ovsdb_idl_column *column)
{
    struct ovsdb_idl_row *row = CONST_CAST(struct ovsdb_idl_row *, row_);
    const struct ovsdb_idl_table_class *class;
    size_t column_idx;

    if (ovsdb_idl_row_is_synthetic(row)) {
        return;
    }

    class = row->table->class_;
    column_idx = column - class->columns;

    ovs_assert(row->new_datum != NULL);
    ovs_assert(row->old_datum == NULL ||
               row->table->modes[column_idx] & OVSDB_IDL_MONITOR);
    if (!row->old_datum
        || (row->written && bitmap_is_set(row->written, column_idx))) {
        return;
    }

    if (hmap_node_is_null(&row->txn_node)) {
        hmap_insert(&row->table->db->txn->txn_rows, &row->txn_node,
                    uuid_hash(&row->uuid));
    }
    if (!row->prereqs) {
        row->prereqs = bitmap_allocate(class->n_columns);
    }
    bitmap_set1(row->prereqs, column_idx);
}

/* Deletes 'row_' from its table.  May free 'row_', so it must not be
 * accessed afterward.
 *
 * A transaction must be in progress.
 *
 * Usually this function is used indirectly through one of the "delete"
 * functions generated by ovsdb-idlc. */
void
ovsdb_idl_txn_delete(const struct ovsdb_idl_row *row_)
{
    struct ovsdb_idl_row *row = CONST_CAST(struct ovsdb_idl_row *, row_);

    if (ovsdb_idl_row_is_synthetic(row)) {
        return;
    }

    ovs_assert(row->new_datum != NULL);
    if (!row->old_datum) {
        ovsdb_idl_row_unparse(row);
        ovsdb_idl_row_clear_new(row);
        ovs_assert(!row->prereqs);
        hmap_remove(&row->table->rows, &row->hmap_node);
        hmap_remove(&row->table->db->txn->txn_rows, &row->txn_node);
        free(row);
        return;
    }
    if (hmap_node_is_null(&row->txn_node)) {
        hmap_insert(&row->table->db->txn->txn_rows, &row->txn_node,
                    uuid_hash(&row->uuid));
    }
    ovsdb_idl_row_clear_new(row);
    row->new_datum = NULL;
}

/* Inserts and returns a new row in the table with the specified 'class' in the
 * database with open transaction 'txn'.
 *
 * The new row is assigned a provisional UUID.  If 'uuid' is null then one is
 * randomly generated; otherwise 'uuid' should specify a randomly generated
 * UUID not otherwise in use.  ovsdb-server will assign a different UUID when
 * 'txn' is committed, but the IDL will replace any uses of the provisional
 * UUID in the data to be to be committed by the UUID assigned by
 * ovsdb-server.
 *
 * Usually this function is used indirectly through one of the "insert"
 * functions generated by ovsdb-idlc. */
const struct ovsdb_idl_row *
ovsdb_idl_txn_insert(struct ovsdb_idl_txn *txn,
                     const struct ovsdb_idl_table_class *class,
                     const struct uuid *uuid)
{
    struct ovsdb_idl_row *row = ovsdb_idl_row_create__(class);

    if (uuid) {
        ovs_assert(!ovsdb_idl_txn_get_row(txn, uuid));
        row->uuid = *uuid;
    } else {
        uuid_generate(&row->uuid);
    }

    row->table = ovsdb_idl_db_table_from_class(txn->db, class);
    row->new_datum = xmalloc(class->n_columns * sizeof *row->new_datum);
    hmap_insert(&row->table->rows, &row->hmap_node, uuid_hash(&row->uuid));
    hmap_insert(&txn->txn_rows, &row->txn_node, uuid_hash(&row->uuid));
    return row;
}

static void
ovsdb_idl_db_txn_abort_all(struct ovsdb_idl_db *db)
{
    struct ovsdb_idl_txn *txn;

    HMAP_FOR_EACH (txn, hmap_node, &db->outstanding_txns) {
        ovsdb_idl_txn_complete(txn, TXN_TRY_AGAIN);
    }
}

static void
ovsdb_idl_txn_abort_all(struct ovsdb_idl *idl)
{
    ovsdb_idl_db_txn_abort_all(&idl->server);
    ovsdb_idl_db_txn_abort_all(&idl->data);
}

static struct ovsdb_idl_txn *
ovsdb_idl_db_txn_find(struct ovsdb_idl_db *db, const struct json *id)
{
    struct ovsdb_idl_txn *txn;

    HMAP_FOR_EACH_WITH_HASH (txn, hmap_node,
                             json_hash(id, 0), &db->outstanding_txns) {
        if (json_equal(id, txn->request_id)) {
            return txn;
        }
    }
    return NULL;
}

static bool
check_json_type(const struct json *json, enum json_type type, const char *name)
{
    if (!json) {
        VLOG_WARN_RL(&syntax_rl, "%s is missing", name);
        return false;
    } else if (json->type != type) {
        VLOG_WARN_RL(&syntax_rl, "%s is %s instead of %s",
                     name, json_type_to_string(json->type),
                     json_type_to_string(type));
        return false;
    } else {
        return true;
    }
}

static bool
ovsdb_idl_txn_process_inc_reply(struct ovsdb_idl_txn *txn,
                                const struct json_array *results)
{
    struct json *count, *rows, *row, *column;
    struct shash *mutate, *select;

    if (txn->inc_index + 2 > results->n) {
        VLOG_WARN_RL(&syntax_rl, "reply does not contain enough operations "
                     "for increment (has %"PRIuSIZE", needs %u)",
                     results->n, txn->inc_index + 2);
        return false;
    }

    /* We know that this is a JSON object because the loop in
     * ovsdb_idl_db_txn_process_reply() checked. */
    mutate = json_object(results->elems[txn->inc_index]);
    count = shash_find_data(mutate, "count");
    if (!check_json_type(count, JSON_INTEGER, "\"mutate\" reply \"count\"")) {
        return false;
    }
    if (count->integer != 1) {
        VLOG_WARN_RL(&syntax_rl,
                     "\"mutate\" reply \"count\" is %lld instead of 1",
                     count->integer);
        return false;
    }

    select = json_object(results->elems[txn->inc_index + 1]);
    rows = shash_find_data(select, "rows");
    if (!check_json_type(rows, JSON_ARRAY, "\"select\" reply \"rows\"")) {
        return false;
    }
    if (rows->array.n != 1) {
        VLOG_WARN_RL(&syntax_rl, "\"select\" reply \"rows\" has %"PRIuSIZE" elements "
                     "instead of 1",
                     rows->array.n);
        return false;
    }
    row = rows->array.elems[0];
    if (!check_json_type(row, JSON_OBJECT, "\"select\" reply row")) {
        return false;
    }
    column = shash_find_data(json_object(row), txn->inc_column);
    if (!check_json_type(column, JSON_INTEGER,
                         "\"select\" reply inc column")) {
        return false;
    }
    txn->inc_new_value = column->integer;
    return true;
}

static bool
ovsdb_idl_txn_process_insert_reply(struct ovsdb_idl_txn_insert *insert,
                                   const struct json_array *results)
{
    static const struct ovsdb_base_type uuid_type = OVSDB_BASE_UUID_INIT;
    struct ovsdb_error *error;
    struct json *json_uuid;
    union ovsdb_atom uuid;
    struct shash *reply;

    if (insert->op_index >= results->n) {
        VLOG_WARN_RL(&syntax_rl, "reply does not contain enough operations "
                     "for insert (has %"PRIuSIZE", needs %u)",
                     results->n, insert->op_index);
        return false;
    }

    /* We know that this is a JSON object because the loop in
     * ovsdb_idl_txn_process_reply() checked. */
    reply = json_object(results->elems[insert->op_index]);
    json_uuid = shash_find_data(reply, "uuid");
    if (!check_json_type(json_uuid, JSON_ARRAY, "\"insert\" reply \"uuid\"")) {
        return false;
    }

    error = ovsdb_atom_from_json(&uuid, &uuid_type, json_uuid, NULL);
    if (error) {
        char *s = ovsdb_error_to_string_free(error);
        VLOG_WARN_RL(&syntax_rl, "\"insert\" reply \"uuid\" is not a JSON "
                     "UUID: %s", s);
        free(s);
        return false;
    }

    insert->real = uuid.uuid;

    return true;
}

static bool
ovsdb_idl_db_txn_process_reply(struct ovsdb_idl_db *db,
                               const struct jsonrpc_msg *msg)
{
    struct ovsdb_idl_txn *txn;
    enum ovsdb_idl_txn_status status;

    txn = ovsdb_idl_db_txn_find(db, msg->id);
    if (!txn) {
        return false;
    }

    if (msg->type == JSONRPC_ERROR) {
        if (msg->error
            && msg->error->type == JSON_STRING
            && !strcmp(json_string(msg->error), "canceled")) {
            /* ovsdb-server uses this error message to indicate that the
            * transaction was canceled because the database in question was
            * removed, converted, etc. */
            status = TXN_TRY_AGAIN;
        } else {
            status = TXN_ERROR;
            ovsdb_idl_txn_set_error_json(txn, msg->error);
        }
    } else if (msg->result->type != JSON_ARRAY) {
        VLOG_WARN_RL(&syntax_rl, "reply to \"transact\" is not JSON array");
        status = TXN_ERROR;
        ovsdb_idl_txn_set_error_json(txn, msg->result);
    } else {
        struct json_array *ops = &msg->result->array;
        int hard_errors = 0;
        int soft_errors = 0;
        int lock_errors = 0;
        size_t i;

        for (i = 0; i < ops->n; i++) {
            struct json *op = ops->elems[i];

            if (op->type == JSON_NULL) {
                /* This isn't an error in itself but indicates that some prior
                 * operation failed, so make sure that we know about it. */
                soft_errors++;
            } else if (op->type == JSON_OBJECT) {
                struct json *error;

                error = shash_find_data(json_object(op), "error");
                if (error) {
                    if (error->type == JSON_STRING) {
                        if (!strcmp(error->string, "timed out")) {
                            soft_errors++;
                        } else if (!strcmp(error->string, "not owner")) {
                            lock_errors++;
                        } else if (!strcmp(error->string, "not allowed")) {
                            hard_errors++;
                            ovsdb_idl_txn_set_error_json(txn, op);
                        } else if (strcmp(error->string, "aborted")) {
                            hard_errors++;
                            ovsdb_idl_txn_set_error_json(txn, op);
                            VLOG_WARN_RL(&other_rl,
                                         "transaction error: %s", txn->error);
                        }
                    } else {
                        hard_errors++;
                        ovsdb_idl_txn_set_error_json(txn, op);
                        VLOG_WARN_RL(&syntax_rl,
                                     "\"error\" in reply is not JSON string");
                    }
                }
            } else {
                hard_errors++;
                ovsdb_idl_txn_set_error_json(txn, op);
                VLOG_WARN_RL(&syntax_rl,
                             "operation reply is not JSON null or object");
            }
        }

        if (!soft_errors && !hard_errors && !lock_errors) {
            struct ovsdb_idl_txn_insert *insert;

            if (txn->inc_table && !ovsdb_idl_txn_process_inc_reply(txn, ops)) {
                hard_errors++;
            }

            HMAP_FOR_EACH (insert, hmap_node, &txn->inserted_rows) {
                if (!ovsdb_idl_txn_process_insert_reply(insert, ops)) {
                    hard_errors++;
                }
            }
        }

        status = (hard_errors ? TXN_ERROR
                  : lock_errors ? TXN_NOT_LOCKED
                  : soft_errors ? TXN_TRY_AGAIN
                  : TXN_SUCCESS);
    }

    ovsdb_idl_txn_complete(txn, status);
    return true;
}

/* Returns the transaction currently active for 'row''s IDL.  A transaction
 * must currently be active. */
struct ovsdb_idl_txn *
ovsdb_idl_txn_get(const struct ovsdb_idl_row *row)
{
    struct ovsdb_idl_txn *txn = row->table->db->txn;
    ovs_assert(txn != NULL);
    return txn;
}

/* Returns the IDL on which 'txn' acts. */
struct ovsdb_idl *
ovsdb_idl_txn_get_idl (struct ovsdb_idl_txn *txn)
{
    return txn->db->idl;
}

/* Blocks until 'idl' successfully connects to the remote database and
 * retrieves its contents. */
void
ovsdb_idl_get_initial_snapshot(struct ovsdb_idl *idl)
{
    while (1) {
        ovsdb_idl_run(idl);
        if (ovsdb_idl_has_ever_connected(idl)) {
            return;
        }
        ovsdb_idl_wait(idl);
        poll_block();
    }
}

static struct jsonrpc_msg *
ovsdb_idl_db_set_lock(struct ovsdb_idl_db *db, const char *lock_name)
{
    ovs_assert(!db->txn);
    ovs_assert(hmap_is_empty(&db->outstanding_txns));

    if (db->lock_name
        && (!lock_name || strcmp(lock_name, db->lock_name))) {
        /* Release previous lock. */
        struct jsonrpc_msg *msg = ovsdb_idl_db_compose_unlock_request(db);
        free(db->lock_name);
        db->lock_name = NULL;
        db->is_lock_contended = false;
        return msg;
    }

    if (lock_name && !db->lock_name) {
        /* Acquire new lock. */
        db->lock_name = xstrdup(lock_name);
        return ovsdb_idl_db_compose_lock_request(db);
    }

    return NULL;
}

/* If 'lock_name' is nonnull, configures 'idl' to obtain the named lock from
 * the database server and to avoid modifying the database when the lock cannot
 * be acquired (that is, when another client has the same lock).
 *
 * If 'lock_name' is NULL, drops the locking requirement and releases the
 * lock. */
void
ovsdb_idl_set_lock(struct ovsdb_idl *idl, const char *lock_name)
{
    for (;;) {
        struct jsonrpc_msg *msg = ovsdb_idl_db_set_lock(&idl->data, lock_name);
        if (!msg) {
            break;
        }
        jsonrpc_session_send(idl->session, msg);
    }
}

/* Returns true if 'idl' is configured to obtain a lock and owns that lock.
 *
 * Locking and unlocking happens asynchronously from the database client's
 * point of view, so the information is only useful for optimization (e.g. if
 * the client doesn't have the lock then there's no point in trying to write to
 * the database). */
bool
ovsdb_idl_has_lock(const struct ovsdb_idl *idl)
{
    return idl->data.has_lock;
}

/* Returns true if 'idl' is configured to obtain a lock but the database server
 * has indicated that some other client already owns the requested lock. */
bool
ovsdb_idl_is_lock_contended(const struct ovsdb_idl *idl)
{
    return idl->data.is_lock_contended;
}

static void
ovsdb_idl_db_update_has_lock(struct ovsdb_idl_db *db, bool new_has_lock)
{
    if (new_has_lock && !db->has_lock) {
        if (db->idl->state == IDL_S_MONITORING) {
            db->change_seqno++;
        } else {
            /* We're setting up a session, so don't signal that the database
             * changed.  Finalizing the session will increment change_seqno
             * anyhow. */
        }
        db->is_lock_contended = false;
    }
    db->has_lock = new_has_lock;
}

static bool
ovsdb_idl_db_process_lock_replies(struct ovsdb_idl_db *db,
                                  const struct jsonrpc_msg *msg)
{
    if (msg->type == JSONRPC_REPLY
        && db->lock_request_id
        && json_equal(db->lock_request_id, msg->id)) {
        /* Reply to our "lock" request. */
        ovsdb_idl_db_parse_lock_reply(db, msg->result);
        return true;
    }

    if (msg->type == JSONRPC_NOTIFY) {
        if (!strcmp(msg->method, "locked")) {
            /* We got our lock. */
            return ovsdb_idl_db_parse_lock_notify(db, msg->params, true);
        } else if (!strcmp(msg->method, "stolen")) {
            /* Someone else stole our lock. */
            return ovsdb_idl_db_parse_lock_notify(db, msg->params, false);
        }
    }

    return false;
}

static struct jsonrpc_msg *
ovsdb_idl_db_compose_lock_request__(struct ovsdb_idl_db *db,
                                    const char *method)
{
    ovsdb_idl_db_update_has_lock(db, false);

    json_destroy(db->lock_request_id);
    db->lock_request_id = NULL;

    struct json *params = json_array_create_1(json_string_create(
                                                  db->lock_name));
    return jsonrpc_create_request(method, params, NULL);
}

static struct jsonrpc_msg *
ovsdb_idl_db_compose_lock_request(struct ovsdb_idl_db *db)
{
    struct jsonrpc_msg *msg = ovsdb_idl_db_compose_lock_request__(db, "lock");
    db->lock_request_id = json_clone(msg->id);
    return msg;
}

static struct jsonrpc_msg *
ovsdb_idl_db_compose_unlock_request(struct ovsdb_idl_db *db)
{
    return ovsdb_idl_db_compose_lock_request__(db, "unlock");
}

static void
ovsdb_idl_db_parse_lock_reply(struct ovsdb_idl_db *db,
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

    ovsdb_idl_db_update_has_lock(db, got_lock);
    if (!got_lock) {
        db->is_lock_contended = true;
    }
}

static bool
ovsdb_idl_db_parse_lock_notify(struct ovsdb_idl_db *db,
                               const struct json *params,
                               bool new_has_lock)
{
    if (db->lock_name
        && params->type == JSON_ARRAY
        && json_array(params)->n > 0
        && json_array(params)->elems[0]->type == JSON_STRING) {
        const char *lock_name = json_string(json_array(params)->elems[0]);

        if (!strcmp(db->lock_name, lock_name)) {
            ovsdb_idl_db_update_has_lock(db, new_has_lock);
            if (!new_has_lock) {
                db->is_lock_contended = true;
            }
            return true;
        }
    }
    return false;
}

/* Inserts a new Map Operation into current transaction. */
static void
ovsdb_idl_txn_add_map_op(struct ovsdb_idl_row *row,
                         const struct ovsdb_idl_column *column,
                         struct ovsdb_datum *datum,
                         enum map_op_type op_type)
{
    const struct ovsdb_idl_table_class *class;
    size_t column_idx;
    struct map_op *map_op;

    class = row->table->class_;
    column_idx = column - class->columns;

    /* Check if a map operation list exists for this column. */
    if (!row->map_op_written) {
        row->map_op_written = bitmap_allocate(class->n_columns);
        row->map_op_lists = xzalloc(class->n_columns *
                                    sizeof *row->map_op_lists);
    }
    if (!row->map_op_lists[column_idx]) {
        row->map_op_lists[column_idx] = map_op_list_create();
    }

    /* Add a map operation to the corresponding list. */
    map_op = map_op_create(datum, op_type);
    bitmap_set1(row->map_op_written, column_idx);
    map_op_list_add(row->map_op_lists[column_idx], map_op, &column->type);

    /* Add this row to transaction's list of rows. */
    if (hmap_node_is_null(&row->txn_node)) {
        hmap_insert(&row->table->db->txn->txn_rows, &row->txn_node,
                    uuid_hash(&row->uuid));
    }
}

/* Inserts a new Set Operation into current transaction. */
static void
ovsdb_idl_txn_add_set_op(struct ovsdb_idl_row *row,
                         const struct ovsdb_idl_column *column,
                         struct ovsdb_datum *datum,
                         enum set_op_type op_type)
{
    const struct ovsdb_idl_table_class *class;
    size_t column_idx;
    struct set_op *set_op;

    class = row->table->class_;
    column_idx = column - class->columns;

    /* Check if a set operation list exists for this column. */
    if (!row->set_op_written) {
        row->set_op_written = bitmap_allocate(class->n_columns);
        row->set_op_lists = xzalloc(class->n_columns *
                                    sizeof *row->set_op_lists);
    }
    if (!row->set_op_lists[column_idx]) {
        row->set_op_lists[column_idx] = set_op_list_create();
    }

    /* Add a set operation to the corresponding list. */
    set_op = set_op_create(datum, op_type);
    bitmap_set1(row->set_op_written, column_idx);
    set_op_list_add(row->set_op_lists[column_idx], set_op, &column->type);

    /* Add this row to the transactions's list of rows. */
    if (hmap_node_is_null(&row->txn_node)) {
        hmap_insert(&row->table->db->txn->txn_rows, &row->txn_node,
                    uuid_hash(&row->uuid));
    }
}

static bool
is_valid_partial_update(const struct ovsdb_idl_row *row,
                        const struct ovsdb_idl_column *column,
                        struct ovsdb_datum *datum)
{
    /* Verify that this column is being monitored. */
    unsigned int column_idx = column - row->table->class_->columns;
    if (!(row->table->modes[column_idx] & OVSDB_IDL_MONITOR)) {
        VLOG_WARN("cannot partially update non-monitored column");
        return false;
    }

    /* Verify that the update affects a single element. */
    if (datum->n != 1) {
        VLOG_WARN("invalid datum for partial update");
        return false;
    }

    return true;
}

/* Inserts the value described in 'datum' into the map in 'column' in
 * 'row_'. If the value doesn't already exist in 'column' then it's value
 * is added.  The value in 'datum' must be of the same type as the values
 * in 'column'.  This function takes ownership of 'datum'.
 *
 * Usually this function is used indirectly through one of the "update"
 * functions generated by vswitch-idl. */
void
ovsdb_idl_txn_write_partial_set(const struct ovsdb_idl_row *row_,
                                const struct ovsdb_idl_column *column,
                                struct ovsdb_datum *datum)
{
    struct ovsdb_idl_row *row = CONST_CAST(struct ovsdb_idl_row *, row_);
    enum set_op_type op_type;

    if (!is_valid_partial_update(row, column, datum)) {
        ovsdb_datum_destroy(datum, &column->type);
        free(datum);
        return;
    }

    op_type = SET_OP_INSERT;

    ovsdb_idl_txn_add_set_op(row, column, datum, op_type);
}

/* Deletes the value specified in 'datum' from the set in 'column' in 'row_'.
 * The value in 'datum' must be of the same type as the keys in 'column'.
 * This function takes ownership of 'datum'.
 *
 * Usually this function is used indirectly through one of the "update"
 * functions generated by vswitch-idl. */
void
ovsdb_idl_txn_delete_partial_set(const struct ovsdb_idl_row *row_,
                                 const struct ovsdb_idl_column *column,
                                 struct ovsdb_datum *datum)
{
    struct ovsdb_idl_row *row = CONST_CAST(struct ovsdb_idl_row *, row_);

    if (!is_valid_partial_update(row, column, datum)) {
        struct ovsdb_type type_ = column->type;
        type_.value.type = OVSDB_TYPE_VOID;
        ovsdb_datum_destroy(datum, &type_);
        free(datum);
        return;
    }
    ovsdb_idl_txn_add_set_op(row, column, datum, SET_OP_DELETE);
}

/* Inserts the key-value specified in 'datum' into the map in 'column' in
 * 'row_'. If the key already exist in 'column', then it's value is updated
 * with the value in 'datum'. The key-value in 'datum' must be of the same type
 * as the keys-values in 'column'. This function takes ownership of 'datum'.
 *
 * Usually this function is used indirectly through one of the "update"
 * functions generated by vswitch-idl. */
void
ovsdb_idl_txn_write_partial_map(const struct ovsdb_idl_row *row_,
                                const struct ovsdb_idl_column *column,
                                struct ovsdb_datum *datum)
{
    struct ovsdb_idl_row *row = CONST_CAST(struct ovsdb_idl_row *, row_);
    enum ovsdb_atomic_type key_type;
    enum map_op_type op_type;
    unsigned int pos;
    const struct ovsdb_datum *old_datum;

    if (!is_valid_partial_update(row, column, datum)) {
        ovsdb_datum_destroy(datum, &column->type);
        free(datum);
        return;
    }

    /* Find out if this is an insert or an update. */
    key_type = column->type.key.type;
    old_datum = ovsdb_idl_read(row, column);
    pos = ovsdb_datum_find_key(old_datum, &datum->keys[0], key_type);
    op_type = pos == UINT_MAX ? MAP_OP_INSERT : MAP_OP_UPDATE;

    ovsdb_idl_txn_add_map_op(row, column, datum, op_type);
}

/* Deletes the key specified in 'datum' from the map in 'column' in 'row_'.
 * The key in 'datum' must be of the same type as the keys in 'column'.
 * The value in 'datum' must be NULL. This function takes ownership of
 * 'datum'.
 *
 * Usually this function is used indirectly through one of the "update"
 * functions generated by vswitch-idl. */
void
ovsdb_idl_txn_delete_partial_map(const struct ovsdb_idl_row *row_,
                                 const struct ovsdb_idl_column *column,
                                 struct ovsdb_datum *datum)
{
    struct ovsdb_idl_row *row = CONST_CAST(struct ovsdb_idl_row *, row_);

    if (!is_valid_partial_update(row, column, datum)) {
        struct ovsdb_type type_ = column->type;
        type_.value.type = OVSDB_TYPE_VOID;
        ovsdb_datum_destroy(datum, &type_);
        free(datum);
        return;
    }
    ovsdb_idl_txn_add_map_op(row, column, datum, MAP_OP_DELETE);
}

void
ovsdb_idl_loop_destroy(struct ovsdb_idl_loop *loop)
{
    if (loop) {
        ovsdb_idl_destroy(loop->idl);
    }
}

struct ovsdb_idl_txn *
ovsdb_idl_loop_run(struct ovsdb_idl_loop *loop)
{
    ovsdb_idl_run(loop->idl);
    loop->open_txn = (loop->committing_txn
                      || ovsdb_idl_get_seqno(loop->idl) == loop->skip_seqno
                      ? NULL
                      : ovsdb_idl_txn_create(loop->idl));
    return loop->open_txn;
}

/* Attempts to commit the current transaction, if one is open, and sets up the
 * poll loop to wake up when some more work might be needed.
 *
 * If a transaction was open, in this or a previous iteration of the main loop,
 * and had not before finished committing (successfully or unsuccessfully), the
 * return value is one of:
 *
 *  1: The transaction committed successfully (or it did not change anything in
 *     the database).
 *  0: The transaction failed.
 * -1: The commit is still in progress.
 *
 * Thus, the return value is -1 if the transaction is in progress and otherwise
 * true for success, false for failure.
 *
 * (In the corner case where the IDL sends a transaction to the database and
 * the database commits it, and the connection between the IDL and the database
 * drops before the IDL receives the message confirming the commit, this
 * function can return 0 even though the transaction succeeded.)
 */
int
ovsdb_idl_loop_commit_and_wait(struct ovsdb_idl_loop *loop)
{
    if (loop->open_txn) {
        loop->committing_txn = loop->open_txn;
        loop->open_txn = NULL;

        loop->precommit_seqno = ovsdb_idl_get_seqno(loop->idl);
    }

    struct ovsdb_idl_txn *txn = loop->committing_txn;
    int retval;
    if (txn) {
        enum ovsdb_idl_txn_status status = ovsdb_idl_txn_commit(txn);
        if (status != TXN_INCOMPLETE) {
            switch (status) {
            case TXN_TRY_AGAIN:
                /* We want to re-evaluate the database when it's changed from
                 * the contents that it had when we started the commit.  (That
                 * might have already happened.) */
                loop->skip_seqno = loop->precommit_seqno;
                if (ovsdb_idl_get_seqno(loop->idl) != loop->skip_seqno) {
                    poll_immediate_wake();
                }
                retval = 0;
                break;

            case TXN_SUCCESS:
                /* Possibly some work on the database was deferred because no
                 * further transaction could proceed.  Wake up again. */
                retval = 1;
                loop->cur_cfg = loop->next_cfg;
                poll_immediate_wake();
                break;

            case TXN_UNCHANGED:
                retval = 1;
                loop->cur_cfg = loop->next_cfg;
                break;

            case TXN_ABORTED:
            case TXN_NOT_LOCKED:
            case TXN_ERROR:
                retval = 0;
                break;

            case TXN_UNCOMMITTED:
            case TXN_INCOMPLETE:
            default:
                OVS_NOT_REACHED();
            }
            ovsdb_idl_txn_destroy(txn);
            loop->committing_txn = NULL;
        } else {
            retval = -1;
        }
    } else {
        /* Not a meaningful return value: no transaction was in progress. */
        retval = 1;
    }

    ovsdb_idl_wait(loop->idl);

    return retval;
}
