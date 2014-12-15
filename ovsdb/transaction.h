/* Copyright (c) 2009, 2010 Nicira, Inc.
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

#ifndef OVSDB_TRANSACTION_H
#define OVSDB_TRANSACTION_H 1

#include <stdbool.h>
#include "compiler.h"

struct json;
struct ovsdb;
struct ovsdb_table;
struct uuid;

struct ovsdb_txn *ovsdb_txn_create(struct ovsdb *);
void ovsdb_txn_abort(struct ovsdb_txn *);
struct ovsdb_error *ovsdb_txn_commit(struct ovsdb_txn *, bool durable)
    OVS_WARN_UNUSED_RESULT;

struct ovsdb_row *ovsdb_txn_row_modify(struct ovsdb_txn *,
                                       const struct ovsdb_row *);
void ovsdb_txn_row_insert(struct ovsdb_txn *, struct ovsdb_row *);
void ovsdb_txn_row_delete(struct ovsdb_txn *, const struct ovsdb_row *);

typedef bool ovsdb_txn_row_cb_func(const struct ovsdb_row *old,
                                   const struct ovsdb_row *new,
                                   const unsigned long int *changed,
                                   void *aux);
void ovsdb_txn_for_each_change(const struct ovsdb_txn *,
                               ovsdb_txn_row_cb_func *, void *aux);

void ovsdb_txn_add_comment(struct ovsdb_txn *, const char *);
const char *ovsdb_txn_get_comment(const struct ovsdb_txn *);

#endif /* ovsdb/transaction.h */
