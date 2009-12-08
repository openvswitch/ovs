/* Copyright (c) 2009 Nicira Networks.
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

#ifndef OVSDB_IDL_H
#define OVSDB_IDL_H 1

struct ovsdb_idl_class;

struct ovsdb_idl *ovsdb_idl_create(const char *remote,
                                   const struct ovsdb_idl_class *);
void ovsdb_idl_destroy(struct ovsdb_idl *);

void ovsdb_idl_run(struct ovsdb_idl *);
void ovsdb_idl_wait(struct ovsdb_idl *);

unsigned int ovsdb_idl_get_seqno(const struct ovsdb_idl *);
void ovsdb_idl_force_reconnect(struct ovsdb_idl *);

enum ovsdb_idl_txn_status {
    TXN_INCOMPLETE,             /* Commit in progress, please wait. */
    TXN_ABORTED,                /* ovsdb_idl_txn_abort() called. */
    TXN_SUCCESS,                /* Commit successful. */
    TXN_TRY_AGAIN,              /* Commit failed because a "verify" operation
                                 * reported an inconsistency, due to a network
                                 * problem, or other transient failure. */
    TXN_ERROR                   /* Commit failed due to a hard error. */
};

const char *ovsdb_idl_txn_status_to_string(enum ovsdb_idl_txn_status);

struct ovsdb_idl_txn *ovsdb_idl_txn_create(struct ovsdb_idl *);
void ovsdb_idl_txn_destroy(struct ovsdb_idl_txn *);
enum ovsdb_idl_txn_status ovsdb_idl_txn_commit(struct ovsdb_idl_txn *);
void ovsdb_idl_txn_abort(struct ovsdb_idl_txn *);

#endif /* ovsdb-idl.h */
