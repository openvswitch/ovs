/* Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

/* Open vSwitch Database Interface Definition Language (OVSDB IDL).
 *
 * The OVSDB IDL maintains an in-memory replica of a database.  It issues RPC
 * requests to an OVSDB database server and parses the responses, converting
 * raw JSON into data structures that are easier for clients to digest.  Most
 * notably, references to rows via UUID become C pointers.
 *
 * The IDL also assists with issuing database transactions.  The client creates
 * a transaction, manipulates the IDL data structures, and commits or aborts
 * the transaction.  The IDL then composes and issues the necessary JSON-RPC
 * requests and reports to the client whether the transaction completed
 * successfully.
 */

#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"
#include "ovsdb-types.h"

struct json;
struct ovsdb_datum;
struct ovsdb_idl_class;
struct ovsdb_idl_column;
struct ovsdb_idl_table_class;
struct uuid;

struct ovsdb_idl *ovsdb_idl_create(const char *remote,
                                   const struct ovsdb_idl_class *,
                                   bool monitor_everything_by_default);
void ovsdb_idl_destroy(struct ovsdb_idl *);

bool ovsdb_idl_run(struct ovsdb_idl *);
void ovsdb_idl_wait(struct ovsdb_idl *);

void ovsdb_idl_set_lock(struct ovsdb_idl *, const char *lock_name);
bool ovsdb_idl_has_lock(const struct ovsdb_idl *);
bool ovsdb_idl_is_lock_contended(const struct ovsdb_idl *);

unsigned int ovsdb_idl_get_seqno(const struct ovsdb_idl *);
bool ovsdb_idl_has_ever_connected(const struct ovsdb_idl *);
void ovsdb_idl_force_reconnect(struct ovsdb_idl *);

/* Choosing columns and tables to replicate. */

/* Modes with which the IDL can monitor a column.
 *
 * If no bits are set, the column is not monitored at all.  Its value will
 * always appear to the client to be the default value for its type.
 *
 * If OVSDB_IDL_MONITOR is set, then the column is replicated.  Its value will
 * reflect the value in the database.  If OVSDB_IDL_ALERT is also set, then
 * ovsdb_idl_run() will return "true", and the value returned by
 * ovsdb_idl_get_seqno() will change, when the column's value changes.
 *
 * The possible mode combinations are:
 *
 *   - 0, for a column that a client doesn't care about.
 *
 *   - (OVSDB_IDL_MONITOR | OVSDB_IDL_ALERT), for a column that a client wants
 *     to track and possibly update.
 *
 *   - OVSDB_IDL_MONITOR, for columns that a client treats as "write-only",
 *     that is, it updates them but doesn't want to get alerted about its own
 *     updates.  It also won't be alerted about other clients' updates, so this
 *     is suitable only for use by a client that "owns" a particular column.
 *
 *   - OVDSB_IDL_ALERT without OVSDB_IDL_MONITOR is not valid.
 */
#define OVSDB_IDL_MONITOR (1 << 0) /* Monitor this column? */
#define OVSDB_IDL_ALERT   (1 << 1) /* Alert client when column updated? */

void ovsdb_idl_add_column(struct ovsdb_idl *, const struct ovsdb_idl_column *);
void ovsdb_idl_add_table(struct ovsdb_idl *,
                         const struct ovsdb_idl_table_class *);

void ovsdb_idl_omit(struct ovsdb_idl *, const struct ovsdb_idl_column *);
void ovsdb_idl_omit_alert(struct ovsdb_idl *, const struct ovsdb_idl_column *);

/* Reading the database replica. */

const struct ovsdb_idl_row *ovsdb_idl_get_row_for_uuid(
    const struct ovsdb_idl *, const struct ovsdb_idl_table_class *,
    const struct uuid *);
const struct ovsdb_idl_row *ovsdb_idl_first_row(
    const struct ovsdb_idl *, const struct ovsdb_idl_table_class *);
const struct ovsdb_idl_row *ovsdb_idl_next_row(const struct ovsdb_idl_row *);

const struct ovsdb_datum *ovsdb_idl_read(const struct ovsdb_idl_row *,
                                         const struct ovsdb_idl_column *);
const struct ovsdb_datum *ovsdb_idl_get(const struct ovsdb_idl_row *,
                                        const struct ovsdb_idl_column *,
                                        enum ovsdb_atomic_type key_type,
                                        enum ovsdb_atomic_type value_type);

bool ovsdb_idl_row_is_synthetic(const struct ovsdb_idl_row *);

/* Transactions. */

enum ovsdb_idl_txn_status {
    TXN_UNCOMMITTED,            /* Not yet committed or aborted. */
    TXN_UNCHANGED,              /* Transaction didn't include any changes. */
    TXN_INCOMPLETE,             /* Commit in progress, please wait. */
    TXN_ABORTED,                /* ovsdb_idl_txn_abort() called. */
    TXN_SUCCESS,                /* Commit successful. */
    TXN_TRY_AGAIN,              /* Commit failed because a "verify" operation
                                 * reported an inconsistency, due to a network
                                 * problem, or other transient failure. */
    TXN_NOT_LOCKED,             /* Server hasn't given us the lock yet. */
    TXN_ERROR                   /* Commit failed due to a hard error. */
};

const char *ovsdb_idl_txn_status_to_string(enum ovsdb_idl_txn_status);

struct ovsdb_idl_txn *ovsdb_idl_txn_create(struct ovsdb_idl *);
void ovsdb_idl_txn_add_comment(struct ovsdb_idl_txn *, const char *, ...)
    PRINTF_FORMAT (2, 3);
void ovsdb_idl_txn_set_dry_run(struct ovsdb_idl_txn *);
void ovsdb_idl_txn_increment(struct ovsdb_idl_txn *, const char *table,
                             const char *column, const struct json *where);
void ovsdb_idl_txn_destroy(struct ovsdb_idl_txn *);
void ovsdb_idl_txn_wait(const struct ovsdb_idl_txn *);
enum ovsdb_idl_txn_status ovsdb_idl_txn_commit(struct ovsdb_idl_txn *);
enum ovsdb_idl_txn_status ovsdb_idl_txn_commit_block(struct ovsdb_idl_txn *);
void ovsdb_idl_txn_abort(struct ovsdb_idl_txn *);

const char *ovsdb_idl_txn_get_error(const struct ovsdb_idl_txn *);

int64_t ovsdb_idl_txn_get_increment_new_value(const struct ovsdb_idl_txn *);
const struct uuid *ovsdb_idl_txn_get_insert_uuid(const struct ovsdb_idl_txn *,
                                                 const struct uuid *);

void ovsdb_idl_txn_write(const struct ovsdb_idl_row *,
                         const struct ovsdb_idl_column *,
                         struct ovsdb_datum *);
void ovsdb_idl_txn_delete(const struct ovsdb_idl_row *);
const struct ovsdb_idl_row *ovsdb_idl_txn_insert(
    struct ovsdb_idl_txn *, const struct ovsdb_idl_table_class *,
    const struct uuid *);

struct ovsdb_idl *ovsdb_idl_txn_get_idl (struct ovsdb_idl_txn *);

#endif /* ovsdb-idl.h */
