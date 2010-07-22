/* Copyright (c) 2009, 2010 Nicira Networks
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

#include "jsonrpc-server.h"

#include <assert.h>
#include <errno.h>

#include "bitmap.h"
#include "column.h"
#include "json.h"
#include "jsonrpc.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb.h"
#include "reconnect.h"
#include "row.h"
#include "stream.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "trigger.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_jsonrpc_server)

struct ovsdb_jsonrpc_remote;
struct ovsdb_jsonrpc_session;

/* Message rate-limiting. */
struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Sessions. */
static struct ovsdb_jsonrpc_session *ovsdb_jsonrpc_session_create(
    struct ovsdb_jsonrpc_remote *, struct jsonrpc_session *);
static void ovsdb_jsonrpc_session_run_all(struct ovsdb_jsonrpc_remote *);
static void ovsdb_jsonrpc_session_wait_all(struct ovsdb_jsonrpc_remote *);
static void ovsdb_jsonrpc_session_close_all(struct ovsdb_jsonrpc_remote *);
static void ovsdb_jsonrpc_session_reconnect_all(struct ovsdb_jsonrpc_remote *);

/* Triggers. */
static void ovsdb_jsonrpc_trigger_create(struct ovsdb_jsonrpc_session *,
                                         struct json *id, struct json *params);
static struct ovsdb_jsonrpc_trigger *ovsdb_jsonrpc_trigger_find(
    struct ovsdb_jsonrpc_session *, const struct json *id, size_t hash);
static void ovsdb_jsonrpc_trigger_complete(struct ovsdb_jsonrpc_trigger *);
static void ovsdb_jsonrpc_trigger_complete_all(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_trigger_complete_done(
    struct ovsdb_jsonrpc_session *);

/* Monitors. */
static struct json *ovsdb_jsonrpc_monitor_create(
    struct ovsdb_jsonrpc_session *, struct json *params);
static struct jsonrpc_msg *ovsdb_jsonrpc_monitor_cancel(
    struct ovsdb_jsonrpc_session *,
    struct json_array *params,
    const struct json *request_id);
static void ovsdb_jsonrpc_monitor_remove_all(struct ovsdb_jsonrpc_session *);

/* JSON-RPC database server. */

struct ovsdb_jsonrpc_server {
    struct ovsdb *db;
    unsigned int n_sessions, max_sessions;
    struct shash remotes;      /* Contains "struct ovsdb_jsonrpc_remote *"s. */
};

/* A configured remote.  This is either a passive stream listener plus a list
 * of the currently connected sessions, or a list of exactly one active
 * session. */
struct ovsdb_jsonrpc_remote {
    struct ovsdb_jsonrpc_server *server;
    struct pstream *listener;   /* Listener, if passive. */
    struct list sessions;       /* List of "struct ovsdb_jsonrpc_session"s. */
};

static void ovsdb_jsonrpc_server_add_remote(struct ovsdb_jsonrpc_server *,
                                            const char *name);
static void ovsdb_jsonrpc_server_del_remote(struct shash_node *);

struct ovsdb_jsonrpc_server *
ovsdb_jsonrpc_server_create(struct ovsdb *db)
{
    struct ovsdb_jsonrpc_server *server = xzalloc(sizeof *server);
    server->db = db;
    server->max_sessions = 64;
    shash_init(&server->remotes);
    return server;
}

void
ovsdb_jsonrpc_server_destroy(struct ovsdb_jsonrpc_server *svr)
{
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, &svr->remotes) {
        ovsdb_jsonrpc_server_del_remote(node);
    }
    shash_destroy(&svr->remotes);
    free(svr);
}

/* Sets 'svr''s current set of remotes to the names in 'new_remotes'.  The data
 * values in 'new_remotes' are ignored.
 *
 * A remote is an active or passive stream connection method, e.g. "pssl:" or
 * "tcp:1.2.3.4". */
void
ovsdb_jsonrpc_server_set_remotes(struct ovsdb_jsonrpc_server *svr,
                                 const struct shash *new_remotes)
{
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, &svr->remotes) {
        if (!shash_find(new_remotes, node->name)) {
            ovsdb_jsonrpc_server_del_remote(node);
        }
    }
    SHASH_FOR_EACH (node, new_remotes) {
        if (!shash_find(&svr->remotes, node->name)) {
            ovsdb_jsonrpc_server_add_remote(svr, node->name);
        }
    }
}

static void
ovsdb_jsonrpc_server_add_remote(struct ovsdb_jsonrpc_server *svr,
                                const char *name)
{
    struct ovsdb_jsonrpc_remote *remote;
    struct pstream *listener;
    int error;

    error = jsonrpc_pstream_open(name, &listener);
    if (error && error != EAFNOSUPPORT) {
        VLOG_ERR_RL(&rl, "%s: listen failed: %s", name, strerror(error));
        return;
    }

    remote = xmalloc(sizeof *remote);
    remote->server = svr;
    remote->listener = listener;
    list_init(&remote->sessions);
    shash_add(&svr->remotes, name, remote);

    if (!listener) {
        ovsdb_jsonrpc_session_create(remote, jsonrpc_session_open(name));
    }
}

static void
ovsdb_jsonrpc_server_del_remote(struct shash_node *node)
{
    struct ovsdb_jsonrpc_remote *remote = node->data;

    ovsdb_jsonrpc_session_close_all(remote);
    pstream_close(remote->listener);
    shash_delete(&remote->server->remotes, node);
    free(remote);
}

/* Forces all of the JSON-RPC sessions managed by 'svr' to disconnect and
 * reconnect. */
void
ovsdb_jsonrpc_server_reconnect(struct ovsdb_jsonrpc_server *svr)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &svr->remotes) {
        struct ovsdb_jsonrpc_remote *remote = node->data;

        ovsdb_jsonrpc_session_reconnect_all(remote);
    }
}

void
ovsdb_jsonrpc_server_run(struct ovsdb_jsonrpc_server *svr)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &svr->remotes) {
        struct ovsdb_jsonrpc_remote *remote = node->data;

        if (remote->listener && svr->n_sessions < svr->max_sessions) {
            struct stream *stream;
            int error;

            error = pstream_accept(remote->listener, &stream);
            if (!error) {
                struct jsonrpc_session *js;
                js = jsonrpc_session_open_unreliably(jsonrpc_open(stream));
                ovsdb_jsonrpc_session_create(remote, js);
            } else if (error != EAGAIN) {
                VLOG_WARN_RL(&rl, "%s: accept failed: %s",
                             pstream_get_name(remote->listener),
                             strerror(error));
            }
        }

        ovsdb_jsonrpc_session_run_all(remote);
    }
}

void
ovsdb_jsonrpc_server_wait(struct ovsdb_jsonrpc_server *svr)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &svr->remotes) {
        struct ovsdb_jsonrpc_remote *remote = node->data;

        if (remote->listener && svr->n_sessions < svr->max_sessions) {
            pstream_wait(remote->listener);
        }

        ovsdb_jsonrpc_session_wait_all(remote);
    }
}

/* JSON-RPC database server session. */

struct ovsdb_jsonrpc_session {
    struct ovsdb_jsonrpc_remote *remote;
    struct list node;           /* Element in remote's sessions list. */

    /* Triggers. */
    struct hmap triggers;       /* Hmap of "struct ovsdb_jsonrpc_trigger"s. */
    struct list completions;    /* Completed triggers. */

    /* Monitors. */
    struct hmap monitors;       /* Hmap of "struct ovsdb_jsonrpc_monitor"s. */

    /* Network connectivity. */
    struct jsonrpc_session *js;  /* JSON-RPC session. */
    unsigned int js_seqno;       /* Last jsonrpc_session_get_seqno() value. */
};

static void ovsdb_jsonrpc_session_close(struct ovsdb_jsonrpc_session *);
static int ovsdb_jsonrpc_session_run(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_session_wait(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_session_got_request(struct ovsdb_jsonrpc_session *,
                                             struct jsonrpc_msg *);
static void ovsdb_jsonrpc_session_got_notify(struct ovsdb_jsonrpc_session *,
                                             struct jsonrpc_msg *);

static struct ovsdb_jsonrpc_session *
ovsdb_jsonrpc_session_create(struct ovsdb_jsonrpc_remote *remote,
                             struct jsonrpc_session *js)
{
    struct ovsdb_jsonrpc_session *s;

    s = xzalloc(sizeof *s);
    s->remote = remote;
    list_push_back(&remote->sessions, &s->node);
    hmap_init(&s->triggers);
    hmap_init(&s->monitors);
    list_init(&s->completions);
    s->js = js;
    s->js_seqno = jsonrpc_session_get_seqno(js);

    remote->server->n_sessions++;

    return s;
}

static void
ovsdb_jsonrpc_session_close(struct ovsdb_jsonrpc_session *s)
{
    ovsdb_jsonrpc_monitor_remove_all(s);
    jsonrpc_session_close(s->js);
    list_remove(&s->node);
    s->remote->server->n_sessions--;
    free(s);
}

static int
ovsdb_jsonrpc_session_run(struct ovsdb_jsonrpc_session *s)
{
    jsonrpc_session_run(s->js);
    if (s->js_seqno != jsonrpc_session_get_seqno(s->js)) {
        s->js_seqno = jsonrpc_session_get_seqno(s->js);
        ovsdb_jsonrpc_trigger_complete_all(s);
        ovsdb_jsonrpc_monitor_remove_all(s);
    }

    ovsdb_jsonrpc_trigger_complete_done(s);

    if (!jsonrpc_session_get_backlog(s->js)) {
        struct jsonrpc_msg *msg = jsonrpc_session_recv(s->js);
        if (msg) {
            if (msg->type == JSONRPC_REQUEST) {
                ovsdb_jsonrpc_session_got_request(s, msg);
            } else if (msg->type == JSONRPC_NOTIFY) {
                ovsdb_jsonrpc_session_got_notify(s, msg);
            } else {
                VLOG_WARN("%s: received unexpected %s message",
                          jsonrpc_session_get_name(s->js),
                          jsonrpc_msg_type_to_string(msg->type));
                jsonrpc_session_force_reconnect(s->js);
                jsonrpc_msg_destroy(msg);
            }
        }
    }
    return jsonrpc_session_is_alive(s->js) ? 0 : ETIMEDOUT;
}

static void
ovsdb_jsonrpc_session_run_all(struct ovsdb_jsonrpc_remote *remote)
{
    struct ovsdb_jsonrpc_session *s, *next;

    LIST_FOR_EACH_SAFE (s, next, struct ovsdb_jsonrpc_session, node,
                        &remote->sessions) {
        int error = ovsdb_jsonrpc_session_run(s);
        if (error) {
            ovsdb_jsonrpc_session_close(s);
        }
    }
}

static void
ovsdb_jsonrpc_session_wait(struct ovsdb_jsonrpc_session *s)
{
    jsonrpc_session_wait(s->js);
    if (!jsonrpc_session_get_backlog(s->js)) {
        jsonrpc_session_recv_wait(s->js);
    }
}

static void
ovsdb_jsonrpc_session_wait_all(struct ovsdb_jsonrpc_remote *remote)
{
    struct ovsdb_jsonrpc_session *s;

    LIST_FOR_EACH (s, struct ovsdb_jsonrpc_session, node, &remote->sessions) {
        ovsdb_jsonrpc_session_wait(s);
    }
}

static void
ovsdb_jsonrpc_session_close_all(struct ovsdb_jsonrpc_remote *remote)
{
    struct ovsdb_jsonrpc_session *s, *next;

    LIST_FOR_EACH_SAFE (s, next, struct ovsdb_jsonrpc_session, node,
                        &remote->sessions) {
        ovsdb_jsonrpc_session_close(s);
    }
}

/* Forces all of the JSON-RPC sessions managed by 'remote' to disconnect and
 * reconnect. */
static void
ovsdb_jsonrpc_session_reconnect_all(struct ovsdb_jsonrpc_remote *remote)
{
    struct ovsdb_jsonrpc_session *s, *next;

    LIST_FOR_EACH_SAFE (s, next, struct ovsdb_jsonrpc_session, node,
                        &remote->sessions) {
        jsonrpc_session_force_reconnect(s->js);
        if (!jsonrpc_session_is_alive(s->js)) {
            ovsdb_jsonrpc_session_close(s);
        }
    }
}

static const char *
get_db_name(const struct ovsdb_jsonrpc_session *s)
{
    return s->remote->server->db->schema->name;
}

static struct jsonrpc_msg *
ovsdb_jsonrpc_check_db_name(const struct ovsdb_jsonrpc_session *s,
                            const struct jsonrpc_msg *request)
{
    struct json_array *params;
    const char *want_db_name;
    const char *have_db_name;
    struct ovsdb_error *error;
    struct jsonrpc_msg *reply;

    params = json_array(request->params);
    if (!params->n || params->elems[0]->type != JSON_STRING) {
        error = ovsdb_syntax_error(
            request->params, NULL,
            "%s request params must begin with <db-name>", request->method);
        goto error;
    }

    want_db_name = params->elems[0]->u.string;
    have_db_name = get_db_name(s);
    if (strcmp(want_db_name, have_db_name)) {
        error = ovsdb_syntax_error(
            request->params, "unknown database",
            "%s request specifies unknown database %s",
            request->method, want_db_name);
        goto error;
    }

    return NULL;

error:
    reply = jsonrpc_create_reply(ovsdb_error_to_json(error), request->id);
    ovsdb_error_destroy(error);
    return reply;
}

static struct jsonrpc_msg *
execute_transaction(struct ovsdb_jsonrpc_session *s,
                    struct jsonrpc_msg *request)
{
    ovsdb_jsonrpc_trigger_create(s, request->id, request->params);
    request->id = NULL;
    request->params = NULL;
    jsonrpc_msg_destroy(request);
    return NULL;
}

static void
ovsdb_jsonrpc_session_got_request(struct ovsdb_jsonrpc_session *s,
                                  struct jsonrpc_msg *request)
{
    struct jsonrpc_msg *reply;

    if (!strcmp(request->method, "transact")) {
        reply = ovsdb_jsonrpc_check_db_name(s, request);
        if (!reply) {
            reply = execute_transaction(s, request);
        }
    } else if (!strcmp(request->method, "monitor")) {
        reply = ovsdb_jsonrpc_check_db_name(s, request);
        if (!reply) {
            reply = jsonrpc_create_reply(
                ovsdb_jsonrpc_monitor_create(s, request->params), request->id);
        }
    } else if (!strcmp(request->method, "monitor_cancel")) {
        reply = ovsdb_jsonrpc_monitor_cancel(s, json_array(request->params),
                                             request->id);
    } else if (!strcmp(request->method, "get_schema")) {
        reply = ovsdb_jsonrpc_check_db_name(s, request);
        if (!reply) {
            reply = jsonrpc_create_reply(
                ovsdb_schema_to_json(s->remote->server->db->schema),
                request->id);
        }
    } else if (!strcmp(request->method, "list_dbs")) {
        reply = jsonrpc_create_reply(
            json_array_create_1(json_string_create(get_db_name(s))),
            request->id);
    } else if (!strcmp(request->method, "echo")) {
        reply = jsonrpc_create_reply(json_clone(request->params), request->id);
    } else {
        reply = jsonrpc_create_error(json_string_create("unknown method"),
                                     request->id);
    }

    if (reply) {
        jsonrpc_msg_destroy(request);
        jsonrpc_session_send(s->js, reply);
    }
}

static void
execute_cancel(struct ovsdb_jsonrpc_session *s, struct jsonrpc_msg *request)
{
    if (json_array(request->params)->n == 1) {
        struct ovsdb_jsonrpc_trigger *t;
        struct json *id;

        id = request->params->u.array.elems[0];
        t = ovsdb_jsonrpc_trigger_find(s, id, json_hash(id, 0));
        if (t) {
            ovsdb_jsonrpc_trigger_complete(t);
        }
    }
}

static void
ovsdb_jsonrpc_session_got_notify(struct ovsdb_jsonrpc_session *s,
                                 struct jsonrpc_msg *request)
{
    if (!strcmp(request->method, "cancel")) {
        execute_cancel(s, request);
    }
    jsonrpc_msg_destroy(request);
}

/* JSON-RPC database server triggers.
 *
 * (Every transaction is treated as a trigger even if it doesn't actually have
 * any "wait" operations.) */

struct ovsdb_jsonrpc_trigger {
    struct ovsdb_trigger trigger;
    struct ovsdb_jsonrpc_session *session;
    struct hmap_node hmap_node; /* In session's "triggers" hmap. */
    struct json *id;
};

static void
ovsdb_jsonrpc_trigger_create(struct ovsdb_jsonrpc_session *s,
                             struct json *id, struct json *params)
{
    struct ovsdb_jsonrpc_trigger *t;
    size_t hash;

    /* Check for duplicate ID. */
    hash = json_hash(id, 0);
    t = ovsdb_jsonrpc_trigger_find(s, id, hash);
    if (t) {
        struct jsonrpc_msg *msg;

        msg = jsonrpc_create_error(json_string_create("duplicate request ID"),
                                   id);
        jsonrpc_session_send(s->js, msg);
        json_destroy(id);
        json_destroy(params);
        return;
    }

    /* Insert into trigger table. */
    t = xmalloc(sizeof *t);
    ovsdb_trigger_init(s->remote->server->db,
                       &t->trigger, params, &s->completions,
                       time_msec());
    t->session = s;
    t->id = id;
    hmap_insert(&s->triggers, &t->hmap_node, hash);

    /* Complete early if possible. */
    if (ovsdb_trigger_is_complete(&t->trigger)) {
        ovsdb_jsonrpc_trigger_complete(t);
    }
}

static struct ovsdb_jsonrpc_trigger *
ovsdb_jsonrpc_trigger_find(struct ovsdb_jsonrpc_session *s,
                           const struct json *id, size_t hash)
{
    struct ovsdb_jsonrpc_trigger *t;

    HMAP_FOR_EACH_WITH_HASH (t, struct ovsdb_jsonrpc_trigger, hmap_node, hash,
                             &s->triggers) {
        if (json_equal(t->id, id)) {
            return t;
        }
    }

    return NULL;
}

static void
ovsdb_jsonrpc_trigger_complete(struct ovsdb_jsonrpc_trigger *t)
{
    struct ovsdb_jsonrpc_session *s = t->session;

    if (jsonrpc_session_is_connected(s->js)) {
        struct jsonrpc_msg *reply;
        struct json *result;

        result = ovsdb_trigger_steal_result(&t->trigger);
        if (result) {
            reply = jsonrpc_create_reply(result, t->id);
        } else {
            reply = jsonrpc_create_error(json_string_create("canceled"),
                                         t->id);
        }
        jsonrpc_session_send(s->js, reply);
    }

    json_destroy(t->id);
    ovsdb_trigger_destroy(&t->trigger);
    hmap_remove(&s->triggers, &t->hmap_node);
    free(t);
}

static void
ovsdb_jsonrpc_trigger_complete_all(struct ovsdb_jsonrpc_session *s)
{
    struct ovsdb_jsonrpc_trigger *t, *next;
    HMAP_FOR_EACH_SAFE (t, next, struct ovsdb_jsonrpc_trigger, hmap_node,
                        &s->triggers) {
        ovsdb_jsonrpc_trigger_complete(t);
    }
}

static void
ovsdb_jsonrpc_trigger_complete_done(struct ovsdb_jsonrpc_session *s)
{
    while (!list_is_empty(&s->completions)) {
        struct ovsdb_jsonrpc_trigger *t
            = CONTAINER_OF(s->completions.next,
                           struct ovsdb_jsonrpc_trigger, trigger.node);
        ovsdb_jsonrpc_trigger_complete(t);
    }
}

/* JSON-RPC database table monitors. */

enum ovsdb_jsonrpc_monitor_selection {
    OJMS_INITIAL = 1 << 0,      /* All rows when monitor is created. */
    OJMS_INSERT = 1 << 1,       /* New rows. */
    OJMS_DELETE = 1 << 2,       /* Deleted rows. */
    OJMS_MODIFY = 1 << 3        /* Modified rows. */
};

/* A particular column being monitored. */
struct ovsdb_jsonrpc_monitor_column {
    const struct ovsdb_column *column;
    enum ovsdb_jsonrpc_monitor_selection select;
};

/* A particular table being monitored. */
struct ovsdb_jsonrpc_monitor_table {
    const struct ovsdb_table *table;

    /* This is the union (bitwise-OR) of the 'select' values in all of the
     * members of 'columns' below. */
    enum ovsdb_jsonrpc_monitor_selection select;

    /* Columns being monitored. */
    struct ovsdb_jsonrpc_monitor_column *columns;
    size_t n_columns;
};

/* A collection of tables being monitored. */
struct ovsdb_jsonrpc_monitor {
    struct ovsdb_replica replica;
    struct ovsdb_jsonrpc_session *session;
    struct hmap_node node;      /* In ovsdb_jsonrpc_session's "monitors". */

    struct json *monitor_id;
    struct shash tables;     /* Holds "struct ovsdb_jsonrpc_monitor_table"s. */
};

static const struct ovsdb_replica_class ovsdb_jsonrpc_replica_class;

struct ovsdb_jsonrpc_monitor *ovsdb_jsonrpc_monitor_find(
    struct ovsdb_jsonrpc_session *, const struct json *monitor_id);
static void ovsdb_jsonrpc_monitor_destroy(struct ovsdb_replica *);
static struct json *ovsdb_jsonrpc_monitor_get_initial(
    const struct ovsdb_jsonrpc_monitor *);

static bool
parse_bool(struct ovsdb_parser *parser, const char *name, bool default_value)
{
    const struct json *json;

    json = ovsdb_parser_member(parser, name, OP_BOOLEAN | OP_OPTIONAL);
    return json ? json_boolean(json) : default_value;
}

struct ovsdb_jsonrpc_monitor *
ovsdb_jsonrpc_monitor_find(struct ovsdb_jsonrpc_session *s,
                           const struct json *monitor_id)
{
    struct ovsdb_jsonrpc_monitor *m;

    HMAP_FOR_EACH_WITH_HASH (m, struct ovsdb_jsonrpc_monitor, node,
                             json_hash(monitor_id, 0), &s->monitors) {
        if (json_equal(m->monitor_id, monitor_id)) {
            return m;
        }
    }

    return NULL;
}

static void
ovsdb_jsonrpc_add_monitor_column(struct ovsdb_jsonrpc_monitor_table *mt,
                                 const struct ovsdb_column *column,
                                 enum ovsdb_jsonrpc_monitor_selection select,
                                 size_t *allocated_columns)
{
    struct ovsdb_jsonrpc_monitor_column *c;

    if (mt->n_columns >= *allocated_columns) {
        mt->columns = x2nrealloc(mt->columns, allocated_columns,
                                 sizeof *mt->columns);
    }

    c = &mt->columns[mt->n_columns++];
    c->column = column;
    c->select = select;
}

static int
compare_ovsdb_jsonrpc_monitor_column(const void *a_, const void *b_)
{
    const struct ovsdb_jsonrpc_monitor_column *a = a_;
    const struct ovsdb_jsonrpc_monitor_column *b = b_;

    return a->column < b->column ? -1 : a->column > b->column;
}

static struct ovsdb_error * WARN_UNUSED_RESULT
ovsdb_jsonrpc_parse_monitor_request(struct ovsdb_jsonrpc_monitor_table *mt,
                                    const struct json *monitor_request,
                                    size_t *allocated_columns)
{
    const struct ovsdb_table_schema *ts = mt->table->schema;
    enum ovsdb_jsonrpc_monitor_selection select;
    const struct json *columns, *select_json;
    struct ovsdb_parser parser;
    struct ovsdb_error *error;

    ovsdb_parser_init(&parser, monitor_request, "table %s", ts->name);
    columns = ovsdb_parser_member(&parser, "columns", OP_ARRAY | OP_OPTIONAL);
    select_json = ovsdb_parser_member(&parser, "select",
                                      OP_OBJECT | OP_OPTIONAL);
    error = ovsdb_parser_finish(&parser);
    if (error) {
        return error;
    }

    if (select_json) {
        select = 0;
        ovsdb_parser_init(&parser, select_json, "table %s select", ts->name);
        if (parse_bool(&parser, "initial", true)) {
            select |= OJMS_INITIAL;
        }
        if (parse_bool(&parser, "insert", true)) {
            select |= OJMS_INSERT;
        }
        if (parse_bool(&parser, "delete", true)) {
            select |= OJMS_DELETE;
        }
        if (parse_bool(&parser, "modify", true)) {
            select |= OJMS_MODIFY;
        }
        error = ovsdb_parser_finish(&parser);
        if (error) {
            return error;
        }
    } else {
        select = OJMS_INITIAL | OJMS_INSERT | OJMS_DELETE | OJMS_MODIFY;
    }
    mt->select |= select;

    if (columns) {
        size_t i;

        if (columns->type != JSON_ARRAY) {
            return ovsdb_syntax_error(columns, NULL,
                                      "array of column names expected");
        }

        for (i = 0; i < columns->u.array.n; i++) {
            const struct ovsdb_column *column;
            const char *s;

            if (columns->u.array.elems[i]->type != JSON_STRING) {
                return ovsdb_syntax_error(columns, NULL,
                                          "array of column names expected");
            }

            s = columns->u.array.elems[i]->u.string;
            column = shash_find_data(&mt->table->schema->columns, s);
            if (!column) {
                return ovsdb_syntax_error(columns, NULL, "%s is not a valid "
                                          "column name", s);
            }
            ovsdb_jsonrpc_add_monitor_column(mt, column, select,
                                             allocated_columns);
        }
    } else {
        struct shash_node *node;

        SHASH_FOR_EACH (node, &ts->columns) {
            const struct ovsdb_column *column = node->data;
            if (column->index != OVSDB_COL_UUID) {
                ovsdb_jsonrpc_add_monitor_column(mt, column, select,
                                                 allocated_columns);
            }
        }
    }

    return NULL;
}

static struct json *
ovsdb_jsonrpc_monitor_create(struct ovsdb_jsonrpc_session *s,
                             struct json *params)
{
    struct ovsdb_jsonrpc_monitor *m = NULL;
    struct json *monitor_id, *monitor_requests;
    struct ovsdb_error *error = NULL;
    struct shash_node *node;
    struct json *json;

    if (json_array(params)->n != 3) {
        error = ovsdb_syntax_error(params, NULL, "invalid parameters");
        goto error;
    }
    monitor_id = params->u.array.elems[1];
    monitor_requests = params->u.array.elems[2];
    if (monitor_requests->type != JSON_OBJECT) {
        error = ovsdb_syntax_error(monitor_requests, NULL,
                                   "monitor-requests must be object");
        goto error;
    }

    if (ovsdb_jsonrpc_monitor_find(s, monitor_id)) {
        error = ovsdb_syntax_error(monitor_id, NULL, "duplicate monitor ID");
        goto error;
    }

    m = xzalloc(sizeof *m);
    ovsdb_replica_init(&m->replica, &ovsdb_jsonrpc_replica_class);
    ovsdb_add_replica(s->remote->server->db, &m->replica);
    m->session = s;
    hmap_insert(&s->monitors, &m->node, json_hash(monitor_id, 0));
    m->monitor_id = json_clone(monitor_id);
    shash_init(&m->tables);

    SHASH_FOR_EACH (node, json_object(monitor_requests)) {
        const struct ovsdb_table *table;
        struct ovsdb_jsonrpc_monitor_table *mt;
        size_t allocated_columns;
        const struct json *mr_value;
        size_t i;

        table = ovsdb_get_table(s->remote->server->db, node->name);
        if (!table) {
            error = ovsdb_syntax_error(NULL, NULL,
                                       "no table named %s", node->name);
            goto error;
        }

        mt = xzalloc(sizeof *mt);
        mt->table = table;
        shash_add(&m->tables, table->schema->name, mt);

        /* Parse columns. */
        mr_value = node->data;
        allocated_columns = 0;
        if (mr_value->type == JSON_ARRAY) {
            const struct json_array *array = &mr_value->u.array;

            for (i = 0; i < array->n; i++) {
                error = ovsdb_jsonrpc_parse_monitor_request(
                    mt, array->elems[i], &allocated_columns);
                if (error) {
                    goto error;
                }
            }
        } else {
            error = ovsdb_jsonrpc_parse_monitor_request(
                mt, mr_value, &allocated_columns);
            if (error) {
                goto error;
            }
        }

        /* Check for duplicate columns. */
        qsort(mt->columns, mt->n_columns, sizeof *mt->columns,
              compare_ovsdb_jsonrpc_monitor_column);
        for (i = 1; i < mt->n_columns; i++) {
            if (mt->columns[i].column == mt->columns[i - 1].column) {
                error = ovsdb_syntax_error(mr_value, NULL, "column %s "
                                           "mentioned more than once",
                                           mt->columns[i].column->name);
                goto error;
            }
        }
    }

    return ovsdb_jsonrpc_monitor_get_initial(m);

error:
    if (m) {
        ovsdb_remove_replica(s->remote->server->db, &m->replica);
    }

    json = ovsdb_error_to_json(error);
    ovsdb_error_destroy(error);
    return json;
}

static struct jsonrpc_msg *
ovsdb_jsonrpc_monitor_cancel(struct ovsdb_jsonrpc_session *s,
                             struct json_array *params,
                             const struct json *request_id)
{
    if (params->n != 1) {
        return jsonrpc_create_error(json_string_create("invalid parameters"),
                                    request_id);
    } else {
        struct ovsdb_jsonrpc_monitor *m;

        m = ovsdb_jsonrpc_monitor_find(s, params->elems[0]);
        if (!m) {
            return jsonrpc_create_error(json_string_create("unknown monitor"),
                                        request_id);
        } else {
            ovsdb_remove_replica(s->remote->server->db, &m->replica);
            return jsonrpc_create_reply(json_object_create(), request_id);
        }
    }
}

static void
ovsdb_jsonrpc_monitor_remove_all(struct ovsdb_jsonrpc_session *s)
{
    struct ovsdb_jsonrpc_monitor *m, *next;

    HMAP_FOR_EACH_SAFE (m, next,
                        struct ovsdb_jsonrpc_monitor, node, &s->monitors) {
        ovsdb_remove_replica(s->remote->server->db, &m->replica);
    }
}

static struct ovsdb_jsonrpc_monitor *
ovsdb_jsonrpc_monitor_cast(struct ovsdb_replica *replica)
{
    assert(replica->class == &ovsdb_jsonrpc_replica_class);
    return CONTAINER_OF(replica, struct ovsdb_jsonrpc_monitor, replica);
}

struct ovsdb_jsonrpc_monitor_aux {
    bool initial;               /* Sending initial contents of table? */
    const struct ovsdb_jsonrpc_monitor *monitor;
    struct json *json;          /* JSON for the whole transaction. */

    /* Current table.  */
    struct ovsdb_jsonrpc_monitor_table *mt;
    struct json *table_json;    /* JSON for table's transaction. */
};

static bool
ovsdb_jsonrpc_monitor_change_cb(const struct ovsdb_row *old,
                                const struct ovsdb_row *new,
                                const unsigned long int *changed,
                                void *aux_)
{
    struct ovsdb_jsonrpc_monitor_aux *aux = aux_;
    const struct ovsdb_jsonrpc_monitor *m = aux->monitor;
    struct ovsdb_table *table = new ? new->table : old->table;
    enum ovsdb_jsonrpc_monitor_selection type;
    struct json *old_json, *new_json;
    struct json *row_json;
    char uuid[UUID_LEN + 1];
    int n_changed;
    size_t i;

    if (!aux->mt || table != aux->mt->table) {
        aux->mt = shash_find_data(&m->tables, table->schema->name);
        aux->table_json = NULL;
        if (!aux->mt) {
            /* We don't care about rows in this table at all.  Tell the caller
             * to skip it.  */
            return false;
        }
    }

    type = (aux->initial ? OJMS_INITIAL
            : !old ? OJMS_INSERT
            : !new ? OJMS_DELETE
            : OJMS_MODIFY);
    if (!(aux->mt->select & type)) {
        /* We don't care about this type of change (but do want to be called
         * back for changes to other rows in the same table). */
        return true;
    }

    old_json = new_json = NULL;
    n_changed = 0;
    for (i = 0; i < aux->mt->n_columns; i++) {
        const struct ovsdb_jsonrpc_monitor_column *c = &aux->mt->columns[i];
        const struct ovsdb_column *column = c->column;
        unsigned int idx = c->column->index;
        bool column_changed = false;

        if (!(type & c->select)) {
            /* We don't care about this type of change for this particular
             * column (but we will care about it for some other column). */
            continue;
        }

        if (type == OJMS_MODIFY) {
            column_changed = bitmap_is_set(changed, idx);
            n_changed += column_changed;
        }
        if (column_changed || type == OJMS_DELETE) {
            if (!old_json) {
                old_json = json_object_create();
            }
            json_object_put(old_json, column->name,
                            ovsdb_datum_to_json(&old->fields[idx],
                                                &column->type));
        }
        if (type & (OJMS_INITIAL | OJMS_INSERT | OJMS_MODIFY)) {
            if (!new_json) {
                new_json = json_object_create();
            }
            json_object_put(new_json, column->name,
                            ovsdb_datum_to_json(&new->fields[idx],
                                                &column->type));
        }
    }
    if ((type == OJMS_MODIFY && !n_changed) || (!old_json && !new_json)) {
        /* No reportable changes. */
        json_destroy(old_json);
        json_destroy(new_json);
        return true;
    }

    /* Create JSON object for transaction overall. */
    if (!aux->json) {
        aux->json = json_object_create();
    }

    /* Create JSON object for transaction on this table. */
    if (!aux->table_json) {
        aux->table_json = json_object_create();
        json_object_put(aux->json, aux->mt->table->schema->name,
                        aux->table_json);
    }

    /* Create JSON object for transaction on this row. */
    row_json = json_object_create();
    if (old_json) {
        json_object_put(row_json, "old", old_json);
    }
    if (new_json) {
        json_object_put(row_json, "new", new_json);
    }

    /* Add JSON row to JSON table. */
    snprintf(uuid, sizeof uuid,
             UUID_FMT, UUID_ARGS(ovsdb_row_get_uuid(new ? new : old)));
    json_object_put(aux->table_json, uuid, row_json);

    return true;
}

static void
ovsdb_jsonrpc_monitor_init_aux(struct ovsdb_jsonrpc_monitor_aux *aux,
                               const struct ovsdb_jsonrpc_monitor *m,
                               bool initial)
{
    aux->initial = initial;
    aux->monitor = m;
    aux->json = NULL;
    aux->mt = NULL;
    aux->table_json = NULL;
}

static struct ovsdb_error *
ovsdb_jsonrpc_monitor_commit(struct ovsdb_replica *replica,
                             const struct ovsdb_txn *txn,
                             bool durable OVS_UNUSED)
{
    struct ovsdb_jsonrpc_monitor *m = ovsdb_jsonrpc_monitor_cast(replica);
    struct ovsdb_jsonrpc_monitor_aux aux;

    ovsdb_jsonrpc_monitor_init_aux(&aux, m, false);
    ovsdb_txn_for_each_change(txn, ovsdb_jsonrpc_monitor_change_cb, &aux);
    if (aux.json) {
        struct jsonrpc_msg *msg;
        struct json *params;

        params = json_array_create_2(json_clone(aux.monitor->monitor_id),
                                     aux.json);
        msg = jsonrpc_create_notify("update", params);
        jsonrpc_session_send(aux.monitor->session->js, msg);
    }

    return NULL;
}

static struct json *
ovsdb_jsonrpc_monitor_get_initial(const struct ovsdb_jsonrpc_monitor *m)
{
    struct ovsdb_jsonrpc_monitor_aux aux;
    struct shash_node *node;

    ovsdb_jsonrpc_monitor_init_aux(&aux, m, true);
    SHASH_FOR_EACH (node, &m->tables) {
        struct ovsdb_jsonrpc_monitor_table *mt = node->data;

        if (mt->select & OJMS_INITIAL) {
            struct ovsdb_row *row;

            HMAP_FOR_EACH (row, struct ovsdb_row, hmap_node,
                           &mt->table->rows) {
                ovsdb_jsonrpc_monitor_change_cb(NULL, row, NULL, &aux);
            }
        }
    }
    return aux.json ? aux.json : json_object_create();
}

static void
ovsdb_jsonrpc_monitor_destroy(struct ovsdb_replica *replica)
{
    struct ovsdb_jsonrpc_monitor *m = ovsdb_jsonrpc_monitor_cast(replica);
    struct shash_node *node;

    json_destroy(m->monitor_id);
    SHASH_FOR_EACH (node, &m->tables) {
        struct ovsdb_jsonrpc_monitor_table *mt = node->data;
        free(mt->columns);
        free(mt);
    }
    shash_destroy(&m->tables);
    hmap_remove(&m->session->monitors, &m->node);
    free(m);
}

static const struct ovsdb_replica_class ovsdb_jsonrpc_replica_class = {
    ovsdb_jsonrpc_monitor_commit,
    ovsdb_jsonrpc_monitor_destroy
};
