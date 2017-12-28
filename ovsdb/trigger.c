/* Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

#include "trigger.h"

#include <limits.h>

#include "file.h"
#include "log.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "openvswitch/poll-loop.h"
#include "server.h"
#include "util.h"


static bool ovsdb_trigger_try(struct ovsdb_trigger *, long long int now);
static void trigger_error(struct ovsdb_trigger *, struct ovsdb_error *);
static void trigger_success(struct ovsdb_trigger *, struct json *result);

bool
ovsdb_trigger_init(struct ovsdb_session *session, struct ovsdb *db,
                   struct ovsdb_trigger *trigger,
                   struct jsonrpc_msg *request, long long int now,
                   bool read_only, const char *role, const char *id)
{
    ovs_assert(!strcmp(request->method, "transact") ||
               !strcmp(request->method, "convert"));
    trigger->session = session;
    trigger->db = db;
    ovs_list_push_back(&trigger->db->triggers, &trigger->node);
    trigger->request = request;
    trigger->reply = NULL;
    trigger->created = now;
    trigger->timeout_msec = LLONG_MAX;
    trigger->read_only = read_only;
    trigger->role = nullable_xstrdup(role);
    trigger->id = nullable_xstrdup(id);
    return ovsdb_trigger_try(trigger, now);
}

void
ovsdb_trigger_destroy(struct ovsdb_trigger *trigger)
{
    ovs_list_remove(&trigger->node);
    jsonrpc_msg_destroy(trigger->request);
    jsonrpc_msg_destroy(trigger->reply);
    free(trigger->role);
    free(trigger->id);
}

bool
ovsdb_trigger_is_complete(const struct ovsdb_trigger *trigger)
{
    return trigger->reply != NULL;
}

struct jsonrpc_msg *
ovsdb_trigger_steal_reply(struct ovsdb_trigger *trigger)
{
    struct jsonrpc_msg *reply = trigger->reply;
    trigger->reply = NULL;
    return reply;
}

void
ovsdb_trigger_prereplace_db(struct ovsdb_trigger *trigger)
{
    if (!strcmp(trigger->request->method, "transact")) {
        trigger_error(trigger, ovsdb_error("canceled", NULL));
    } else if (!strcmp(trigger->request->method, "convert")) {
        /* We don't cancel "convert" requests when a database is being replaced
         * for two reasons.  First, we expect the administrator to do some kind
         * of sensible synchronization on conversion requests, that is, it only
         * really makes sense for the admin to do a single conversion at a time
         * at a scheduled point.  Second, if we did then every "convert"
         * request would end up getting canceled since "convert" itself causes
         * the database to be replaced. */
    } else {
        OVS_NOT_REACHED();
    }
}

bool
ovsdb_trigger_run(struct ovsdb *db, long long int now)
{
    struct ovsdb_trigger *t, *next;

    bool run_triggers = db->run_triggers;
    db->run_triggers = false;

    bool disconnect_all = false;

    LIST_FOR_EACH_SAFE (t, next, node, &db->triggers) {
        if (run_triggers || now - t->created >= t->timeout_msec) {
            if (ovsdb_trigger_try(t, now)) {
                disconnect_all = true;
            }
        }
    }
    return disconnect_all;
}

void
ovsdb_trigger_wait(struct ovsdb *db, long long int now)
{
    if (db->run_triggers) {
        poll_immediate_wake();
    } else {
        long long int deadline = LLONG_MAX;
        struct ovsdb_trigger *t;

        LIST_FOR_EACH (t, node, &db->triggers) {
            if (t->created < LLONG_MAX - t->timeout_msec) {
                long long int t_deadline = t->created + t->timeout_msec;
                if (deadline > t_deadline) {
                    deadline = t_deadline;
                    if (now >= deadline) {
                        break;
                    }
                }
            }
        }

        if (deadline < LLONG_MAX) {
            poll_timer_wait_until(deadline);
        }
    }
}

static bool
ovsdb_trigger_try(struct ovsdb_trigger *t, long long int now)
{
    if (!strcmp(t->request->method, "transact")) {
        struct json *result = ovsdb_execute(t->db, t->session,
                                            t->request->params, t->read_only,
                                            t->role, t->id, now - t->created,
                                            &t->timeout_msec);
        if (result) {
            trigger_success(t, result);
        }
        return false;
    } else if (!strcmp(t->request->method, "convert")) {
        /* Permission check. */
        if (t->role && *t->role) {
            trigger_error(t, ovsdb_perm_error(
                              "RBAC rules for client \"%s\" role \"%s\" "
                              "prohibit \"convert\" of database %s "
                              "(only the root role may convert databases)",
                              t->id, t->role, t->db->schema->name));
            return false;
        }

        /* Validate parameters. */
        const struct json *params = t->request->params;
        if (params->type != JSON_ARRAY || params->u.array.n != 2) {
            trigger_error(t, ovsdb_syntax_error(params, NULL,
                                                "array expected"));
            return false;
        }

        /* Parse new schema and make a converted copy. */
        const struct json *new_schema_json = params->u.array.elems[1];
        struct ovsdb_schema *new_schema;
        struct ovsdb_error *error = ovsdb_schema_from_json(new_schema_json,
                                                           &new_schema);
        if (!error && strcmp(new_schema->name, t->db->schema->name)) {
            error = ovsdb_error(
                "invalid parameters",
                "new schema name (%s) does not match database name (%s)",
                new_schema->name, t->db->schema->name);
        }
        if (!error) {
            error = ovsdb_file_convert(t->db->file, new_schema);
        }
        ovsdb_schema_destroy(new_schema);
        if (error) {
            trigger_error(t, error);
            return false;
        }

        trigger_success(t, json_object_create());
        return true;
    } else {
        OVS_NOT_REACHED();
    }
}

static void
ovsdb_trigger_complete(struct ovsdb_trigger *t, struct jsonrpc_msg *reply)
{
    ovs_assert(reply && !t->reply);
    t->reply = reply;
    ovs_list_remove(&t->node);
    ovs_list_push_back(&t->session->completions, &t->node);
}

static void
trigger_error(struct ovsdb_trigger *t, struct ovsdb_error *error)
{
    struct jsonrpc_msg *reply = jsonrpc_create_error(
        ovsdb_error_to_json_free(error), t->request->id);
    ovsdb_trigger_complete(t, reply);
}

static void
trigger_success(struct ovsdb_trigger *t, struct json *result)
{
    struct jsonrpc_msg *reply = jsonrpc_create_reply(result, t->request->id);
    ovsdb_trigger_complete(t, reply);
}
