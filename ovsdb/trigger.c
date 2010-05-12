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

#include "trigger.h"

#include <assert.h>
#include <limits.h>

#include "json.h"
#include "jsonrpc.h"
#include "ovsdb.h"
#include "poll-loop.h"

static bool ovsdb_trigger_try(struct ovsdb *db, struct ovsdb_trigger *,
                              long long int now);
static void ovsdb_trigger_complete(struct ovsdb_trigger *);

void
ovsdb_trigger_init(struct ovsdb *db, struct ovsdb_trigger *trigger,
                   struct json *request, struct list *completion,
                   long long int now)
{
    list_push_back(&db->triggers, &trigger->node);
    trigger->completion = completion;
    trigger->request = request;
    trigger->result = NULL;
    trigger->created = now;
    trigger->timeout_msec = LLONG_MAX;
    ovsdb_trigger_try(db, trigger, now);
}

void
ovsdb_trigger_destroy(struct ovsdb_trigger *trigger)
{
    list_remove(&trigger->node);
    json_destroy(trigger->request);
    json_destroy(trigger->result);
}

bool
ovsdb_trigger_is_complete(const struct ovsdb_trigger *trigger)
{
    return trigger->result != NULL;
}

struct json *
ovsdb_trigger_steal_result(struct ovsdb_trigger *trigger)
{
    struct json *result = trigger->result;
    trigger->result = NULL;
    return result;
}

void
ovsdb_trigger_run(struct ovsdb *db, long long int now)
{
    struct ovsdb_trigger *t, *next;
    bool run_triggers;

    run_triggers = db->run_triggers;
    db->run_triggers = false;
    LIST_FOR_EACH_SAFE (t, next, struct ovsdb_trigger, node, &db->triggers) {
        if (run_triggers || now - t->created >= t->timeout_msec) {
            ovsdb_trigger_try(db, t, now);
        }
    }
}

void
ovsdb_trigger_wait(struct ovsdb *db, long long int now)
{
    if (db->run_triggers) {
        poll_immediate_wake();
    } else {
        long long int deadline = LLONG_MAX;
        struct ovsdb_trigger *t;

        LIST_FOR_EACH (t, struct ovsdb_trigger, node, &db->triggers) {
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
ovsdb_trigger_try(struct ovsdb *db, struct ovsdb_trigger *t, long long int now)
{
    t->result = ovsdb_execute(db, t->request, now - t->created,
                              &t->timeout_msec);
    if (t->result) {
        ovsdb_trigger_complete(t);
        return true;
    } else {
        return false;
    }
}

static void
ovsdb_trigger_complete(struct ovsdb_trigger *t)
{
    assert(t->result != NULL);
    list_remove(&t->node);
    list_push_back(t->completion, &t->node);
}
