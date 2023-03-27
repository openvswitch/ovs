/* Copyright (c) 2009, 2011, 2012 Nicira, Inc.
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

#ifndef OVSDB_TRIGGER_H
#define OVSDB_TRIGGER_H 1

#include "openvswitch/list.h"
#include "openvswitch/uuid.h"

struct ovsdb;

/* Triggers have the following states:
 *
 *    - Initialized (reply == NULL, progress == NULL, txn_forward == NULL):
 *      Executing the trigger can keep it in the initialized state, if it has a
 *      "wait" condition that isn't met.  Executing the trigger can also yield
 *      an error, in which case it transitions to "complete".  Otherwise,
 *      execution yields a transaction, which the database attempts to commit.
 *      If the transaction completes immediately and synchronously, then the
 *      trigger transitions to the "complete" state.  If the transaction
 *      requires some time to complete, it transitions to the "committing"
 *      state.  If the transaction can not be completed locally due to
 *      read-only restrictions and transaction forwarding is enabled, starts
 *      forwarding and transitions to the "forwarding" state.
 *
 *    - Committing (reply != NULL, progress != NULL, txn_forward == NULL):
 *      The transaction is committing.  If it succeeds, or if it fails
 *      permanently, then the trigger transitions to "complete".  If it fails
 *      temporarily (e.g. because someone else committed to cluster-based
 *      storage before we did), then we transition back to "initialized" to
 *      try again.
 *
 *    - Forwarding (reply == NULL, progress == NULL, txn_forward != NULL):
 *      Transaction is forwarded.  Either it succeeds or it fails, the trigger
 *      transitions to "complete".
 *
 *    - Complete (reply != NULL, progress == NULL, txn_forward == NULL):
 *      The transaction is done and either succeeded or failed.
 */
struct ovsdb_trigger {
    /* In "initialized", "committing" or "forwarding" state, in db->triggers.
     * In "complete", in session->completions. */
    struct ovs_list node;
    struct ovsdb_session *session; /* Session that owns this trigger. */
    struct ovsdb *db;           /* Database on which trigger acts. */
    struct ovsdb *converted_db;   /* Result of the 'convert' request. */
    struct uuid conversion_txnid; /* txnid of the conversion request. */
    struct jsonrpc_msg *request; /* Database request. */
    struct jsonrpc_msg *reply;   /* Result (null if none yet). */
    struct ovsdb_txn_progress *progress;
    struct ovsdb_txn_forward *txn_forward; /* Tracks transaction forwarding. */
    long long int created;      /* Time created. */
    long long int timeout_msec; /* Max wait duration. */
    bool read_only;             /* Database is in read only mode. */
    char *role;                 /* Role, for role-based access controls. */
    char *id;                   /* ID, for role-based access controls. */
};

bool ovsdb_trigger_init(struct ovsdb_session *, struct ovsdb *,
                        struct ovsdb_trigger *,
                        struct jsonrpc_msg *request, long long int now,
                        bool read_only, const char *role, const char *id);
void ovsdb_trigger_destroy(struct ovsdb_trigger *);

bool ovsdb_trigger_is_complete(const struct ovsdb_trigger *);
struct jsonrpc_msg *ovsdb_trigger_steal_reply(struct ovsdb_trigger *);
void ovsdb_trigger_cancel(struct ovsdb_trigger *, const char *reason);

void ovsdb_trigger_prereplace_db(struct ovsdb_trigger *);

struct ovsdb *ovsdb_trigger_find_and_steal_converted_db(
        const struct ovsdb *, const struct uuid *)
    OVS_WARN_UNUSED_RESULT;

bool ovsdb_trigger_run(struct ovsdb *, long long int now);
void ovsdb_trigger_wait(struct ovsdb *, long long int now);

#endif /* ovsdb/trigger.h */
