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
#include <string.h>

#include "file.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "openvswitch/poll-loop.h"
#include "server.h"
#include "transaction.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(trigger);

static bool ovsdb_trigger_try(struct ovsdb_trigger *, long long int now);
static void ovsdb_trigger_complete(struct ovsdb_trigger *);
static void trigger_convert_error(struct ovsdb_trigger *,
                                  struct ovsdb_error *);
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
    trigger->progress = NULL;
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
    ovsdb_txn_progress_destroy(trigger->progress);
    ovs_list_remove(&trigger->node);
    jsonrpc_msg_destroy(trigger->request);
    jsonrpc_msg_destroy(trigger->reply);
    free(trigger->role);
    free(trigger->id);
}

bool
ovsdb_trigger_is_complete(const struct ovsdb_trigger *trigger)
{
    return trigger->reply && !trigger->progress;
}

struct jsonrpc_msg *
ovsdb_trigger_steal_reply(struct ovsdb_trigger *trigger)
{
    struct jsonrpc_msg *reply = trigger->reply;
    trigger->reply = NULL;
    return reply;
}

/* Cancels 'trigger'.  'reason' should be a human-readable reason for log
 * messages etc.  */
void
ovsdb_trigger_cancel(struct ovsdb_trigger *trigger, const char *reason)
{
    if (trigger->progress) {
        /* The transaction still might complete asynchronously, but we can stop
         * tracking it. */
        ovsdb_txn_progress_destroy(trigger->progress);
        trigger->progress = NULL;
    }

    jsonrpc_msg_destroy(trigger->reply);
    trigger->reply = NULL;

    if (!strcmp(trigger->request->method, "transact")) {
        /* There's no place to stick 'reason' into the error reply because RFC
         * 7047 prescribes a fix form for these messages, see section 4.1.4. */
        trigger->reply = jsonrpc_create_error(json_string_create("canceled"),
                                              trigger->request->id);
        ovsdb_trigger_complete(trigger);
    } else if (!strcmp(trigger->request->method, "convert")) {
        trigger_convert_error(
            trigger,
            ovsdb_error("canceled", "database conversion canceled because %s",
                        reason));
    }
}

void
ovsdb_trigger_prereplace_db(struct ovsdb_trigger *trigger)
{
    if (!ovsdb_trigger_is_complete(trigger)) {
        if (!strcmp(trigger->request->method, "transact")) {
            ovsdb_trigger_cancel(trigger, "database schema is changing");
        } else if (!strcmp(trigger->request->method, "convert")) {
            /* We don't cancel "convert" requests when a database is being
             * replaced for two reasons.  First, we expect the administrator to
             * do some kind of sensible synchronization on conversion requests,
             * that is, it only really makes sense for the admin to do a single
             * conversion at a time at a scheduled point.  Second, if we did
             * then every "convert" request would end up getting canceled since
             * "convert" itself causes the database to be replaced. */
        } else {
            OVS_NOT_REACHED();
        }
    }
}

bool
ovsdb_trigger_run(struct ovsdb *db, long long int now)
{
    struct ovsdb_trigger *t, *next;

    bool run_triggers = db->run_triggers;
    db->run_triggers_now = db->run_triggers = false;

    bool disconnect_all = false;

    LIST_FOR_EACH_SAFE (t, next, node, &db->triggers) {
        if (run_triggers
            || now - t->created >= t->timeout_msec
            || t->progress) {
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
    if (db->run_triggers_now) {
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
    /* Handle "initialized" state. */
    if (!t->reply) {
        ovs_assert(!t->progress);

        struct ovsdb_txn *txn = NULL;
        struct ovsdb *newdb = NULL;
        if (!strcmp(t->request->method, "transact")) {
            if (!ovsdb_txn_precheck_prereq(t->db)) {
                return false;
            }

            bool durable;

            struct json *result;
            txn = ovsdb_execute_compose(
                t->db, t->session, t->request->params, t->read_only,
                t->role, t->id, now - t->created, &t->timeout_msec,
                &durable, &result);
            if (!txn) {
                if (result) {
                    /* Complete.  There was an error but we still represent it
                     * in JSON-RPC as a successful result. */
                    trigger_success(t, result);
                } else {
                    /* Unsatisfied "wait" condition.  Take no action now, retry
                     * later. */
                }
                return false;
            }

            /* Transition to "committing" state. */
            t->reply = jsonrpc_create_reply(result, t->request->id);
            t->progress = ovsdb_txn_propose_commit(txn, durable);
        } else if (!strcmp(t->request->method, "convert")) {
            /* Permission check. */
            if (t->role && *t->role) {
                trigger_convert_error(
                    t, ovsdb_perm_error(
                        "RBAC rules for client \"%s\" role \"%s\" prohibit "
                        "\"convert\" of database %s "
                        "(only the root role may convert databases)",
                        t->id, t->role, t->db->schema->name));
                return false;
            }

            /* Validate parameters. */
            const struct json *params = t->request->params;
            if (params->type != JSON_ARRAY || params->array.n != 2) {
                trigger_convert_error(t, ovsdb_syntax_error(params, NULL,
                                                            "array expected"));
                return false;
            }

            /* Parse new schema and make a converted copy. */
            const struct json *new_schema_json = params->array.elems[1];
            struct ovsdb_schema *new_schema;
            struct ovsdb_error *error
                = ovsdb_schema_from_json(new_schema_json, &new_schema);
            if (!error && strcmp(new_schema->name, t->db->schema->name)) {
                error = ovsdb_error("invalid parameters",
                                    "new schema name (%s) does not match "
                                    "database name (%s)",
                                    new_schema->name, t->db->schema->name);
            }
            if (!error) {
                error = ovsdb_convert(t->db, new_schema, &newdb);
            }
            ovsdb_schema_destroy(new_schema);
            if (error) {
                trigger_convert_error(t, error);
                return false;
            }

            /* Make the new copy into a transaction log record. */
            struct json *txn_json = ovsdb_to_txn_json(
                newdb, "converted by ovsdb-server");

            /* Propose the change. */
            t->progress = ovsdb_txn_propose_schema_change(
                t->db, new_schema_json, txn_json);
            json_destroy(txn_json);
            t->reply = jsonrpc_create_reply(json_object_create(),
                                            t->request->id);
        } else {
            OVS_NOT_REACHED();
        }

        /* If the transaction committed synchronously, complete it and
         * transition to "complete".  This is more than an optimization because
         * the file-based storage isn't implemented to read back the
         * transactions that we write (which is an ugly broken abstraction but
         * it's what we have). */
        if (ovsdb_txn_progress_is_complete(t->progress)
            && !ovsdb_txn_progress_get_error(t->progress)) {
            if (txn) {
                ovsdb_txn_complete(txn);
            }
            ovsdb_txn_progress_destroy(t->progress);
            t->progress = NULL;
            ovsdb_trigger_complete(t);
            if (newdb) {
                ovsdb_replace(t->db, newdb);
                return true;
            }
            return false;
        }
        ovsdb_destroy(newdb);

        /* Fall through to the general handling for the "committing" state.  We
         * abort the transaction--if and when it eventually commits, we'll read
         * it back from storage and replay it locally. */
        if (txn) {
            ovsdb_txn_abort(txn);
        }
    }

    /* Handle "committing" state. */
    if (t->progress) {
        if (!ovsdb_txn_progress_is_complete(t->progress)) {
            return false;
        }

        /* Transition to "complete". */
        struct ovsdb_error *error
            = ovsdb_error_clone(ovsdb_txn_progress_get_error(t->progress));
        ovsdb_txn_progress_destroy(t->progress);
        t->progress = NULL;

        if (error) {
            if (!strcmp(ovsdb_error_get_tag(error), "cluster error")) {
                /* Temporary error.  Transition back to "initialized" state to
                 * try again. */
                char *err_s = ovsdb_error_to_string(error);
                VLOG_DBG("cluster error %s", err_s);

                jsonrpc_msg_destroy(t->reply);
                t->reply = NULL;
                t->db->run_triggers = true;
                if (!strstr(err_s, "not leader")) {
                    t->db->run_triggers_now = true;
                }
                free(err_s);
                ovsdb_error_destroy(error);
            } else {
                /* Permanent error.  Transition to "completed" state to report
                 * it. */
                if (!strcmp(t->request->method, "transact")) {
                    json_array_add(t->reply->result,
                                   ovsdb_error_to_json_free(error));
                    ovsdb_trigger_complete(t);
                } else if (!strcmp(t->request->method, "convert")) {
                    jsonrpc_msg_destroy(t->reply);
                    t->reply = NULL;
                    trigger_convert_error(t, error);
                }
            }
        } else {
            /* Success. */
            ovsdb_trigger_complete(t);
        }

        return false;
    }

    OVS_NOT_REACHED();
}

static void
ovsdb_trigger_complete(struct ovsdb_trigger *t)
{
    ovs_assert(t->reply);
    ovs_list_remove(&t->node);
    ovs_list_push_back(&t->session->completions, &t->node);
}

/* Makes a "convert" request into an error.
 *
 * This is not suitable for "transact" requests because their replies should
 * never be bare ovsdb_errors: RFC 7047 says that their replies must either be
 * a JSON-RPC reply that contains an array of operation replies (which can be
 * errors), or a JSON-RPC error whose "error" member is simply "canceled". */
static void
trigger_convert_error(struct ovsdb_trigger *t, struct ovsdb_error *error)
{
    ovs_assert(!strcmp(t->request->method, "convert"));
    ovs_assert(error && !t->reply);
    t->reply = jsonrpc_create_error(
        ovsdb_error_to_json_free(error), t->request->id);
    ovsdb_trigger_complete(t);
}

static void
trigger_success(struct ovsdb_trigger *t, struct json *result)
{
    ovs_assert(result && !t->reply);
    t->reply = jsonrpc_create_reply(result, t->request->id);
    ovsdb_trigger_complete(t);
}
