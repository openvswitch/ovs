/* Copyright (c) 2009, 2010 Nicira Networks.
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

#include <stdbool.h>
#include <stdint.h>

struct json;
struct ovsdb_datum;
struct ovsdb_idl_class;
struct ovsdb_idl_column;
struct ovsdb_idl_table_class;
struct uuid;

struct ovsdb_idl *ovsdb_idl_create(const char *remote,
                                   const struct ovsdb_idl_class *);
void ovsdb_idl_destroy(struct ovsdb_idl *);

void ovsdb_idl_run(struct ovsdb_idl *);
void ovsdb_idl_wait(struct ovsdb_idl *);

unsigned int ovsdb_idl_get_seqno(const struct ovsdb_idl *);
bool ovsdb_idl_has_ever_connected(const struct ovsdb_idl *);
void ovsdb_idl_force_reconnect(struct ovsdb_idl *);

const struct ovsdb_idl_row *ovsdb_idl_get_row_for_uuid(
    const struct ovsdb_idl *, const struct ovsdb_idl_table_class *,
    const struct uuid *);
const struct ovsdb_idl_row *ovsdb_idl_first_row(
    const struct ovsdb_idl *, const struct ovsdb_idl_table_class *);
const struct ovsdb_idl_row *ovsdb_idl_next_row(const struct ovsdb_idl_row *);

enum ovsdb_idl_txn_status {
    TXN_UNCHANGED,              /* Transaction didn't include any changes. */
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
void ovsdb_idl_txn_add_comment(struct ovsdb_idl_txn *, const char *);
void ovsdb_idl_txn_set_dry_run(struct ovsdb_idl_txn *);
void ovsdb_idl_txn_increment(struct ovsdb_idl_txn *, const char *table,
                             const char *column, const struct json *where);
void ovsdb_idl_txn_destroy(struct ovsdb_idl_txn *);
void ovsdb_idl_txn_wait(const struct ovsdb_idl_txn *);
enum ovsdb_idl_txn_status ovsdb_idl_txn_commit(struct ovsdb_idl_txn *);
void ovsdb_idl_txn_abort(struct ovsdb_idl_txn *);

int64_t ovsdb_idl_txn_get_increment_new_value(const struct ovsdb_idl_txn *);
const struct uuid *ovsdb_idl_txn_get_insert_uuid(const struct ovsdb_idl_txn *,
                                                 const struct uuid *);

void ovsdb_idl_txn_read(const struct ovsdb_idl_row *,
                        const struct ovsdb_idl_column *,
                        struct ovsdb_datum *);
void ovsdb_idl_txn_write(const struct ovsdb_idl_row *,
                         const struct ovsdb_idl_column *,
                         struct ovsdb_datum *);
void ovsdb_idl_txn_delete(const struct ovsdb_idl_row *);
const struct ovsdb_idl_row *ovsdb_idl_txn_insert(
    struct ovsdb_idl_txn *, const struct ovsdb_idl_table_class *);

#endif /* ovsdb-idl.h */
