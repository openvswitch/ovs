/* Copyright (c) 2009 Nicira Networks
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

#include <errno.h>

#include "json.h"
#include "jsonrpc.h"
#include "ovsdb.h"
#include "reconnect.h"
#include "stream.h"
#include "svec.h"
#include "timeval.h"
#include "trigger.h"

#define THIS_MODULE VLM_ovsdb_jsonrpc_server
#include "vlog.h"

struct ovsdb_jsonrpc_trigger {
    struct ovsdb_trigger trigger;
    struct ovsdb_jsonrpc_session *session;
    struct hmap_node hmap_node; /* Element in session's trigger table. */
    struct json *id;
};

static struct ovsdb_jsonrpc_trigger *ovsdb_jsonrpc_trigger_find(
    struct ovsdb_jsonrpc_session *, const struct json *id, size_t hash);
static void ovsdb_jsonrpc_trigger_complete(struct ovsdb_jsonrpc_trigger *);

struct ovsdb_jsonrpc_session {
    struct ovsdb_jsonrpc_server *server;
    struct list node;           /* Element in server's sessions list. */
    struct hmap triggers;
    struct list completions;    /* Completed triggers. */

    struct reconnect *reconnect; /* For back-off. */
    bool active;                /* Active or passive connection? */
    struct jsonrpc *rpc;
    struct stream *stream;      /* Only if active == false and rpc == NULL. */
};

static void ovsdb_jsonrpc_session_create_active(struct ovsdb_jsonrpc_server *,
                                                const char *name);
static void ovsdb_jsonrpc_session_create_passive(struct ovsdb_jsonrpc_server *,
                                                 struct stream *);
static void ovsdb_jsonrpc_session_close(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_session_disconnect(struct ovsdb_jsonrpc_session *s);
static int ovsdb_jsonrpc_session_run(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_session_wait(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_session_got_request(struct ovsdb_jsonrpc_session *,
                                             struct jsonrpc_msg *);
static void ovsdb_jsonrpc_session_got_notify(struct ovsdb_jsonrpc_session *,
                                             struct jsonrpc_msg *);

struct ovsdb_jsonrpc_server {
    struct ovsdb *db;

    struct list sessions;       /* List of "struct ovsdb_jsonrpc_session"s. */
    unsigned int n_sessions, max_sessions;
    unsigned int max_triggers;

    struct pstream **listeners;
    size_t n_listeners, allocated_listeners;
};

static void ovsdb_jsonrpc_server_listen(struct ovsdb_jsonrpc_server *,
                                        struct pstream *);

int
ovsdb_jsonrpc_server_create(struct ovsdb *db, const struct svec *active,
                            const struct svec *passive,
                            struct ovsdb_jsonrpc_server **serverp)
{
    struct ovsdb_jsonrpc_server *server;
    const char *name;
    int retval = 0;
    size_t i;

    server = xzalloc(sizeof *server);
    server->db = db;
    server->max_sessions = 64;
    server->max_triggers = 64;
    list_init(&server->sessions);

    SVEC_FOR_EACH (i, name, active) {
        ovsdb_jsonrpc_session_create_active(server, name);
    }

    SVEC_FOR_EACH (i, name, passive) {
        struct pstream *pstream;
        int error;

        error = pstream_open(name, &pstream);
        if (!error) {
            ovsdb_jsonrpc_server_listen(server, pstream);
        } else {
            ovs_error(error, "failed to listen on %s", name);
            retval = error;
        }
    }

    *serverp = server;
    return retval;
}

void
ovsdb_jsonrpc_server_run(struct ovsdb_jsonrpc_server *svr)
{
    struct ovsdb_jsonrpc_session *s, *next;
    size_t i;

    /* Accept new connections. */
    for (i = 0; i < svr->n_listeners && svr->n_sessions < svr->max_sessions;) {
        struct pstream *listener = svr->listeners[i];
        struct stream *stream;
        int error;

        error = pstream_accept(listener, &stream);
        if (!error) {
            ovsdb_jsonrpc_session_create_passive(svr, stream);
        } else if (error == EAGAIN) {
            i++;
        } else if (error) {
            VLOG_WARN("%s: accept failed: %s",
                      pstream_get_name(listener), strerror(error));
            pstream_close(listener);
            svr->listeners[i] = svr->listeners[--svr->n_listeners];
        }
    }

    /* Handle each session. */
    LIST_FOR_EACH_SAFE (s, next, struct ovsdb_jsonrpc_session, node,
                        &svr->sessions) {
        int error = ovsdb_jsonrpc_session_run(s);
        if (error) {
            ovsdb_jsonrpc_session_close(s);
        }
    }
}

void
ovsdb_jsonrpc_server_wait(struct ovsdb_jsonrpc_server *svr)
{
    struct ovsdb_jsonrpc_session *s;

    if (svr->n_sessions < svr->max_sessions) {
        size_t i;

        for (i = 0; i < svr->n_listeners; i++) {
            pstream_wait(svr->listeners[i]);
        }
    }

    LIST_FOR_EACH (s, struct ovsdb_jsonrpc_session, node, &svr->sessions) {
        ovsdb_jsonrpc_session_wait(s);
    }
}

static void
ovsdb_jsonrpc_server_listen(struct ovsdb_jsonrpc_server *svr,
                            struct pstream *pstream)
{
    if (svr->n_listeners >= svr->allocated_listeners) {
        svr->listeners = x2nrealloc(svr->listeners, &svr->allocated_listeners,
                                    sizeof *svr->listeners);
    }
    svr->listeners[svr->n_listeners++] = pstream;
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

    if (s->rpc && !jsonrpc_get_status(s->rpc)) {
        struct jsonrpc_msg *reply;
        struct json *result;

        result = ovsdb_trigger_steal_result(&t->trigger);
        if (result) {
            reply = jsonrpc_create_reply(result, t->id);
        } else {
            reply = jsonrpc_create_error(json_string_create("canceled"),
                                         t->id);
        }
        jsonrpc_send(s->rpc, reply);
    }

    json_destroy(t->id);
    ovsdb_trigger_destroy(&t->trigger);
    hmap_remove(&s->triggers, &t->hmap_node);
    free(t);
}

static struct ovsdb_jsonrpc_session *
ovsdb_jsonrpc_session_create(struct ovsdb_jsonrpc_server *svr,
                             const char *name, bool active)
{
    struct ovsdb_jsonrpc_session *s;

    s = xzalloc(sizeof *s);
    s->server = svr;
    list_push_back(&svr->sessions, &s->node);
    hmap_init(&s->triggers);
    list_init(&s->completions);
    s->reconnect = reconnect_create(time_msec());
    reconnect_set_name(s->reconnect, name);
    reconnect_enable(s->reconnect, time_msec());
    s->active = active;

    svr->n_sessions++;

    return s;
}

static void
ovsdb_jsonrpc_session_create_active(struct ovsdb_jsonrpc_server *svr,
                                    const char *name)
{
    ovsdb_jsonrpc_session_create(svr, name, true);
}

static void
ovsdb_jsonrpc_session_create_passive(struct ovsdb_jsonrpc_server *svr,
                                     struct stream *stream)
{
    struct ovsdb_jsonrpc_session *s;

    s = ovsdb_jsonrpc_session_create(svr, stream_get_name(stream), false);
    reconnect_connected(s->reconnect, time_msec());
    s->rpc = jsonrpc_open(stream);
}

static void
ovsdb_jsonrpc_session_close(struct ovsdb_jsonrpc_session *s)
{
    ovsdb_jsonrpc_session_disconnect(s);
    list_remove(&s->node);
    s->server->n_sessions--;
}

static void
ovsdb_jsonrpc_session_disconnect(struct ovsdb_jsonrpc_session *s)
{
    reconnect_disconnected(s->reconnect, time_msec(), 0);
    if (s->rpc) {
        struct ovsdb_jsonrpc_trigger *t, *next;

        jsonrpc_error(s->rpc, EOF);
        HMAP_FOR_EACH_SAFE (t, next, struct ovsdb_jsonrpc_trigger, hmap_node,
                            &s->triggers) {
            ovsdb_jsonrpc_trigger_complete(t);
        }

        jsonrpc_close(s->rpc);
        s->rpc = NULL;
    } else if (s->stream) {
        stream_close(s->stream);
        s->stream = NULL;
    }
}

static void
ovsdb_jsonrpc_session_connect(struct ovsdb_jsonrpc_session *s)
{
    ovsdb_jsonrpc_session_disconnect(s);
    if (s->active) {
        int error = stream_open(reconnect_get_name(s->reconnect), &s->stream);
        if (error) {
            reconnect_connect_failed(s->reconnect, time_msec(), error);
        } else {
            reconnect_connecting(s->reconnect, time_msec());
        }
    }
}

static int
ovsdb_jsonrpc_session_run(struct ovsdb_jsonrpc_session *s)
{
    if (s->rpc) {
        struct jsonrpc_msg *msg;
        int error;

        jsonrpc_run(s->rpc);

        while (!list_is_empty(&s->completions)) {
            struct ovsdb_jsonrpc_trigger *t
                = CONTAINER_OF(s->completions.next,
                               struct ovsdb_jsonrpc_trigger, trigger.node);
            ovsdb_jsonrpc_trigger_complete(t);
        }

        if (!jsonrpc_get_backlog(s->rpc) && !jsonrpc_recv(s->rpc, &msg)) {
            reconnect_received(s->reconnect, time_msec());
            if (msg->type == JSONRPC_REQUEST) {
                ovsdb_jsonrpc_session_got_request(s, msg);
            } else if (msg->type == JSONRPC_NOTIFY) {
                ovsdb_jsonrpc_session_got_notify(s, msg);
            } else {
                VLOG_WARN("%s: received unexpected %s message",
                          jsonrpc_get_name(s->rpc),
                          jsonrpc_msg_type_to_string(msg->type));
                jsonrpc_error(s->rpc, EPROTO);
                jsonrpc_msg_destroy(msg);
            }
        }

        error = jsonrpc_get_status(s->rpc);
        if (error) {
            if (s->active) {
                ovsdb_jsonrpc_session_disconnect(s);
            } else {
                return error;
            }
        }
    } else if (s->stream) {
        int error = stream_connect(s->stream);
        if (!error) {
            reconnect_connected(s->reconnect, time_msec());
            s->rpc = jsonrpc_open(s->stream);
            s->stream = NULL;
        } else if (error != EAGAIN) {
            reconnect_connect_failed(s->reconnect, time_msec(), error);
            stream_close(s->stream);
            s->stream = NULL;
        }
    }

    switch (reconnect_run(s->reconnect, time_msec())) {
    case RECONNECT_CONNECT:
        ovsdb_jsonrpc_session_connect(s);
        break;

    case RECONNECT_DISCONNECT:
        ovsdb_jsonrpc_session_disconnect(s);
        break;

    case RECONNECT_PROBE:
        if (s->rpc) {
            struct json *params = json_integer_create(0);
            jsonrpc_send(s->rpc, jsonrpc_create_request("echo", params));
        }
        break;
    }
    return s->active || s->rpc ? 0 : ETIMEDOUT;

}

static void
ovsdb_jsonrpc_session_wait(struct ovsdb_jsonrpc_session *s)
{
    if (s->rpc) {
        jsonrpc_wait(s->rpc);
        if (!jsonrpc_get_backlog(s->rpc)) {
            jsonrpc_recv_wait(s->rpc);
        }
    } else if (s->stream) {
        stream_connect_wait(s->stream);
    }
    reconnect_wait(s->reconnect, time_msec());
}

static struct jsonrpc_msg *
execute_transaction(struct ovsdb_jsonrpc_session *s,
                    struct jsonrpc_msg *request)
{
    struct ovsdb_jsonrpc_trigger *t;
    size_t hash;

    /* Check for duplicate ID. */
    hash = json_hash(request->id, 0);
    t = ovsdb_jsonrpc_trigger_find(s, request->id, hash);
    if (t) {
        return jsonrpc_create_error(
            json_string_create("duplicate request ID"), request->id);
    }

    /* Insert into trigger table. */
    t = xmalloc(sizeof *t);
    ovsdb_trigger_init(s->server->db,
                       &t->trigger, request->params, &s->completions,
                       time_msec());
    t->session = s;
    t->id = request->id;
    hmap_insert(&s->triggers, &t->hmap_node, hash);

    request->id = NULL;
    request->params = NULL;

    /* Complete early if possible. */
    if (ovsdb_trigger_is_complete(&t->trigger)) {
        ovsdb_jsonrpc_trigger_complete(t);
    }

    return NULL;
}

static void
ovsdb_jsonrpc_session_got_request(struct ovsdb_jsonrpc_session *s,
                                  struct jsonrpc_msg *request)
{
    struct jsonrpc_msg *reply;

    if (!strcmp(request->method, "transact")) {
        reply = execute_transaction(s, request);
    } else if (!strcmp(request->method, "get_schema")) {
        reply = jsonrpc_create_reply(
            ovsdb_schema_to_json(s->server->db->schema), request->id);
    } else if (!strcmp(request->method, "echo")) {
        reply = jsonrpc_create_reply(json_clone(request->params), request->id);
    } else {
        reply = jsonrpc_create_error(json_string_create("unknown method"),
                                     request->id);
    }

    if (reply) {
        jsonrpc_msg_destroy(request);
        jsonrpc_send(s->rpc, reply);
    }
}

static void
execute_cancel(struct ovsdb_jsonrpc_session *s, struct jsonrpc_msg *request)
{
    size_t hash = json_hash(request->id, 0);
    struct ovsdb_jsonrpc_trigger *t;

    t = ovsdb_jsonrpc_trigger_find(s, request->params, hash);
    if (t) {
        ovsdb_jsonrpc_trigger_complete(t);
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
