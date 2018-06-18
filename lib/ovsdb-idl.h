/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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

#ifndef OVSDB_IDL_H
#define OVSDB_IDL_H 1

/* Open vSwitch Database Interface Definition Language (OVSDB IDL).
 *
 * The OVSDB IDL maintains an in-memory replica of a database.  It issues RPC
 * requests to an OVSDB database server and parses the responses, converting
 * raw JSON into data structures that are easier for clients to digest.  Most
 * notably, references to rows via UUID become C pointers.
 *
 * The IDL always presents a consistent snapshot of the database to its client,
 * that is, it won't present the effects of some part of a transaction applied
 * at the database server without presenting all of its effects.
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
#include "ovsdb-data.h"
#include "openvswitch/list.h"
#include "ovsdb-condition.h"
#include "skiplist.h"

#ifdef __cplusplus
extern "C" {
#endif

struct json;
struct ovsdb_datum;
struct ovsdb_idl_class;
struct ovsdb_idl_row;
struct ovsdb_idl_column;
struct ovsdb_idl_table_class;
struct uuid;

struct ovsdb_idl *ovsdb_idl_create(const char *remote,
                                   const struct ovsdb_idl_class *,
                                   bool monitor_everything_by_default,
                                   bool retry);
struct ovsdb_idl *ovsdb_idl_create_unconnected(
    const struct ovsdb_idl_class *, bool monitor_everything_by_default);
void ovsdb_idl_set_remote(struct ovsdb_idl *, const char *, bool);
void ovsdb_idl_destroy(struct ovsdb_idl *);

void ovsdb_idl_set_leader_only(struct ovsdb_idl *, bool leader_only);

void ovsdb_idl_run(struct ovsdb_idl *);
void ovsdb_idl_wait(struct ovsdb_idl *);

void ovsdb_idl_set_lock(struct ovsdb_idl *, const char *lock_name);
bool ovsdb_idl_has_lock(const struct ovsdb_idl *);
bool ovsdb_idl_is_lock_contended(const struct ovsdb_idl *);

const struct uuid  * ovsdb_idl_get_monitor_id(const struct ovsdb_idl *);
unsigned int ovsdb_idl_get_seqno(const struct ovsdb_idl *);
bool ovsdb_idl_has_ever_connected(const struct ovsdb_idl *);
void ovsdb_idl_enable_reconnect(struct ovsdb_idl *);
void ovsdb_idl_force_reconnect(struct ovsdb_idl *);
void ovsdb_idl_verify_write_only(struct ovsdb_idl *);

bool ovsdb_idl_is_alive(const struct ovsdb_idl *);
bool ovsdb_idl_is_connected(const struct ovsdb_idl *idl);
int ovsdb_idl_get_last_error(const struct ovsdb_idl *);

void ovsdb_idl_set_probe_interval(const struct ovsdb_idl *, int probe_interval);

void ovsdb_idl_check_consistency(const struct ovsdb_idl *);

const struct ovsdb_idl_class *ovsdb_idl_get_class(const struct ovsdb_idl *);
const struct ovsdb_idl_table_class *ovsdb_idl_table_class_from_column(
    const struct ovsdb_idl_class *, const struct ovsdb_idl_column *);

/* Choosing columns and tables to replicate. */

/* Modes with which the IDL can monitor a column.
 *
 * If no bits are set, the column is not monitored at all.  Its value will
 * always appear to the client to be the default value for its type.
 *
 * If OVSDB_IDL_MONITOR is set, then the column is replicated.  Its value will
 * reflect the value in the database.  If OVSDB_IDL_ALERT is also set, then the
 * value returned by ovsdb_idl_get_seqno() will change when the column's value
 * changes.
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
 *
 *   - (OVSDB_IDL_MONITOR | OVSDB_IDL_ALERT | OVSDB_IDL_TRACK), for a column
 *     that a client wants to track using the change tracking
 *     ovsdb_idl_track_get_*() functions.
 */
#define OVSDB_IDL_MONITOR (1 << 0) /* Monitor this column? */
#define OVSDB_IDL_ALERT   (1 << 1) /* Alert client when column updated? */
#define OVSDB_IDL_TRACK   (1 << 2)

void ovsdb_idl_add_column(struct ovsdb_idl *, const struct ovsdb_idl_column *);
void ovsdb_idl_add_table(struct ovsdb_idl *,
                         const struct ovsdb_idl_table_class *);

void ovsdb_idl_omit(struct ovsdb_idl *, const struct ovsdb_idl_column *);
void ovsdb_idl_omit_alert(struct ovsdb_idl *, const struct ovsdb_idl_column *);

/* Change tracking.
 *
 * In OVSDB, change tracking is applied at each client in the IDL layer.  This
 * means that when a client makes a request to track changes on a particular
 * table, they are essentially requesting information about the incremental
 * changes to that table from the point in time that the request is made.  Once
 * the client clears tracked changes, that information will no longer be
 * available.
 *
 * The implication of the above is that if a client requires replaying
 * untracked history, it faces the choice of either trying to remember changes
 * itself (which translates into a memory leak) or of being structured with a
 * path for processing the full untracked table as well as a path that
 * processes incremental changes. */
enum ovsdb_idl_change {
    OVSDB_IDL_CHANGE_INSERT,
    OVSDB_IDL_CHANGE_MODIFY,
    OVSDB_IDL_CHANGE_DELETE,
    OVSDB_IDL_CHANGE_MAX
};

/* Row, table sequence numbers */
unsigned int ovsdb_idl_table_get_seqno(
    const struct ovsdb_idl *idl,
    const struct ovsdb_idl_table_class *table_class);
unsigned int ovsdb_idl_row_get_seqno(
    const struct ovsdb_idl_row *row,
    enum ovsdb_idl_change change);

void ovsdb_idl_track_add_column(struct ovsdb_idl *idl,
                                const struct ovsdb_idl_column *column);
void ovsdb_idl_track_add_all(struct ovsdb_idl *idl);
const struct ovsdb_idl_row *ovsdb_idl_track_get_first(
    const struct ovsdb_idl *, const struct ovsdb_idl_table_class *);
const struct ovsdb_idl_row *ovsdb_idl_track_get_next(const struct ovsdb_idl_row *);
bool ovsdb_idl_track_is_updated(const struct ovsdb_idl_row *row,
                                const struct ovsdb_idl_column *column);
void ovsdb_idl_track_clear(struct ovsdb_idl *);


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
bool ovsdb_idl_is_mutable(const struct ovsdb_idl_row *,
                          const struct ovsdb_idl_column *);

bool ovsdb_idl_row_is_synthetic(const struct ovsdb_idl_row *);

/* Transactions.
 *
 * A transaction may modify the contents of a database by modifying the values
 * of columns, deleting rows, inserting rows, or adding checks that columns in
 * the database have not changed ("verify" operations), through
 * ovsdb_idl_txn_*() functions.  (The OVSDB IDL code generator produces helper
 * functions that internally call the ovsdb_idl_txn_*() functions.  These are
 * likely to be more convenient.)
 *
 * Reading and writing columns and inserting and deleting rows are all
 * straightforward.  The reasons to verify columns are less obvious.
 * Verification is the key to maintaining transactional integrity.  Because
 * OVSDB handles multiple clients, it can happen that between the time that
 * OVSDB client A reads a column and writes a new value, OVSDB client B has
 * written that column.  Client A's write should not ordinarily overwrite
 * client B's, especially if the column in question is a "map" column that
 * contains several more or less independent data items.  If client A adds a
 * "verify" operation before it writes the column, then the transaction fails
 * in case client B modifies it first.  Client A will then see the new value of
 * the column and compose a new transaction based on the new contents written
 * by client B.
 *
 * When a transaction is complete, which must be before the next call to
 * ovsdb_idl_run() on 'idl', call ovsdb_idl_txn_commit() or
 * ovsdb_idl_txn_abort().
 *
 * The life-cycle of a transaction looks like this:
 *
 * 1. Create the transaction and record the initial sequence number:
 *
 *     seqno = ovsdb_idl_get_seqno(idl);
 *     txn = ovsdb_idl_txn_create(idl);
 *
 * 2. Modify the database with ovsdb_idl_txn_*() functions directly or
 *    indirectly.
 *
 * 3. Commit the transaction by calling ovsdb_idl_txn_commit().  The first call
 *    to this function probably returns TXN_INCOMPLETE.  The client must keep
 *    calling again along as this remains true, calling ovsdb_idl_run() in
 *    between to let the IDL do protocol processing.  (If the client doesn't
 *    have anything else to do in the meantime, it can use
 *    ovsdb_idl_txn_commit_block() to avoid having to loop itself.)
 *
 * 4. If the final status is TXN_TRY_AGAIN, wait for ovsdb_idl_get_seqno() to
 *    change from the saved 'seqno' (it's possible that it's already changed,
 *    in which case the client should not wait at all), then start over from
 *    step 1.  Only a call to ovsdb_idl_run() will change the return value of
 *    ovsdb_idl_get_seqno().  (ovsdb_idl_txn_commit_block() calls
 *    ovsdb_idl_run().)
 */

enum ovsdb_idl_txn_status {
    TXN_UNCOMMITTED,            /* Not yet committed or aborted. */
    TXN_UNCHANGED,              /* Transaction didn't include any changes. */
    TXN_INCOMPLETE,             /* Commit in progress, please wait. */
    TXN_ABORTED,                /* ovsdb_idl_txn_abort() called. */
    TXN_SUCCESS,                /* Commit successful. */
    TXN_TRY_AGAIN,              /* Commit failed because a "verify" operation
                                 * reported an inconsistency, due to a network
                                 * problem, or other transient failure.  Wait
                                 * for a change, then try again. */
    TXN_NOT_LOCKED,             /* Server hasn't given us the lock yet. */
    TXN_ERROR                   /* Commit failed due to a hard error. */
};

const char *ovsdb_idl_txn_status_to_string(enum ovsdb_idl_txn_status);

struct ovsdb_idl_txn *ovsdb_idl_txn_create(struct ovsdb_idl *);
void ovsdb_idl_txn_add_comment(struct ovsdb_idl_txn *, const char *, ...)
    OVS_PRINTF_FORMAT (2, 3);
void ovsdb_idl_txn_set_dry_run(struct ovsdb_idl_txn *);
void ovsdb_idl_txn_increment(struct ovsdb_idl_txn *,
                             const struct ovsdb_idl_row *,
                             const struct ovsdb_idl_column *,
                             bool force);
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
void ovsdb_idl_txn_write_clone(const struct ovsdb_idl_row *,
                               const struct ovsdb_idl_column *,
                               const struct ovsdb_datum *);
void ovsdb_idl_txn_write_partial_map(const struct ovsdb_idl_row *,
                                     const struct ovsdb_idl_column *,
                                     struct ovsdb_datum *);
void ovsdb_idl_txn_delete_partial_map(const struct ovsdb_idl_row *,
                                      const struct ovsdb_idl_column *,
                                      struct ovsdb_datum *);
void ovsdb_idl_txn_write_partial_set(const struct ovsdb_idl_row *,
                                     const struct ovsdb_idl_column *,
                                     struct ovsdb_datum *);
void ovsdb_idl_txn_delete_partial_set(const struct ovsdb_idl_row *,
                                      const struct ovsdb_idl_column *,
                                      struct ovsdb_datum *);
void ovsdb_idl_txn_delete(const struct ovsdb_idl_row *);
const struct ovsdb_idl_row *ovsdb_idl_txn_insert(
    struct ovsdb_idl_txn *, const struct ovsdb_idl_table_class *,
    const struct uuid *);

struct ovsdb_idl *ovsdb_idl_txn_get_idl (struct ovsdb_idl_txn *);
void ovsdb_idl_get_initial_snapshot(struct ovsdb_idl *);


/* ovsdb_idl_loop provides an easy way to manage the transactions related
 * to 'idl' and to cope with different status during transaction. */
struct ovsdb_idl_loop {
    struct ovsdb_idl *idl;
    unsigned int skip_seqno;

    struct ovsdb_idl_txn *committing_txn;
    unsigned int precommit_seqno;

    struct ovsdb_idl_txn *open_txn;

    /* These members allow a client a simple, stateless way to keep track of
     * transactions that commit: when a transaction commits successfully,
     * ovsdb_idl_loop_commit_and_wait() copies 'next_cfg' to 'cur_cfg'.  Thus,
     * the client can set 'next_cfg' to a value that indicates a successful
     * commit and check 'cur_cfg' on each iteration. */
    int64_t cur_cfg;
    int64_t next_cfg;
};

#define OVSDB_IDL_LOOP_INITIALIZER(IDL) { .idl = (IDL) }

void ovsdb_idl_loop_destroy(struct ovsdb_idl_loop *);
struct ovsdb_idl_txn *ovsdb_idl_loop_run(struct ovsdb_idl_loop *);
int ovsdb_idl_loop_commit_and_wait(struct ovsdb_idl_loop *);

/* Conditional Replication
 * =======================
 *
 * By default, when the IDL replicates a particular table in the database, it
 * replicates every row in the table.  These functions allow the client to
 * specify that only selected rows should be replicated, by constructing a
 * per-table condition that specifies the rows to replicate.
 *
 * A condition is a disjunction of clauses.  The condition is true, and thus a
 * row is replicated, if any of the clauses evaluates to true for a given row.
 * (Thus, a condition with no clauses is always false.)
 */

struct ovsdb_idl_condition {
    struct hmap clauses;        /* Contains "struct ovsdb_idl_clause"s. */
    bool is_true;               /* Is the condition unconditionally true? */
};
#define OVSDB_IDL_CONDITION_INIT(CONDITION) \
    { HMAP_INITIALIZER(&(CONDITION)->clauses), false }

void ovsdb_idl_condition_init(struct ovsdb_idl_condition *);
void ovsdb_idl_condition_clear(struct ovsdb_idl_condition *);
void ovsdb_idl_condition_destroy(struct ovsdb_idl_condition *);
void ovsdb_idl_condition_add_clause(struct ovsdb_idl_condition *,
                                    enum ovsdb_function function,
                                    const struct ovsdb_idl_column *column,
                                    const struct ovsdb_datum *arg);
void ovsdb_idl_condition_add_clause_true(struct ovsdb_idl_condition *);
bool ovsdb_idl_condition_is_true(const struct ovsdb_idl_condition *);

unsigned int ovsdb_idl_set_condition(struct ovsdb_idl *,
                                     const struct ovsdb_idl_table_class *,
                                     const struct ovsdb_idl_condition *);

unsigned int ovsdb_idl_get_condition_seqno(const struct ovsdb_idl *);

/* Indexes over one or more columns in the IDL, to retrieve rows matching
 * particular search criteria and to iterate over a subset of rows in a defined
 * order. */

enum ovsdb_index_order {
    OVSDB_INDEX_ASC,            /* 0, 1, 2, ... */
    OVSDB_INDEX_DESC            /* 2, 1, 0, ... */
};

typedef int column_comparator_func(const void *a, const void *b);

struct ovsdb_idl_index_column {
    const struct ovsdb_idl_column *column;
    column_comparator_func *comparer;
    enum ovsdb_index_order order;
};

/* Creating an index. */
struct ovsdb_idl_index *ovsdb_idl_index_create(
    struct ovsdb_idl *, const struct ovsdb_idl_index_column *, size_t n);
struct ovsdb_idl_index *ovsdb_idl_index_create1(
    struct ovsdb_idl *, const struct ovsdb_idl_column *);
struct ovsdb_idl_index *ovsdb_idl_index_create2(
    struct ovsdb_idl *, const struct ovsdb_idl_column *,
    const struct ovsdb_idl_column *);

/* Searching an index. */
struct ovsdb_idl_row *ovsdb_idl_index_find(struct ovsdb_idl_index *,
                                           const struct ovsdb_idl_row *);

/* Iteration over an index.
 *
 * Usually these would be invoked through table-specific wrappers generated
 * by the IDL. */

struct ovsdb_idl_cursor {
    struct ovsdb_idl_index *index;  /* Index being iterated. */
    struct skiplist_node *position; /* Current position in 'index'. */
};

struct ovsdb_idl_cursor ovsdb_idl_cursor_first(struct ovsdb_idl_index *);
struct ovsdb_idl_cursor ovsdb_idl_cursor_first_eq(
    struct ovsdb_idl_index *, const struct ovsdb_idl_row *);
struct ovsdb_idl_cursor ovsdb_idl_cursor_first_ge(
    struct ovsdb_idl_index *, const struct ovsdb_idl_row *);

void ovsdb_idl_cursor_next(struct ovsdb_idl_cursor *);
void ovsdb_idl_cursor_next_eq(struct ovsdb_idl_cursor *);

struct ovsdb_idl_row *ovsdb_idl_cursor_data(struct ovsdb_idl_cursor *);

#ifdef __cplusplus
}
#endif

#endif /* ovsdb-idl.h */
