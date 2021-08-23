/*
 * Copyright (c) 2021, Red Hat, Inc.
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

#ifndef OVSDB_TXN_FORWARD_H
#define OVSDB_TXN_FORWARD_H 1

#include <stdbool.h>

struct ovsdb;
struct ovsdb_cs;
struct ovsdb_txn_forward;
struct jsonrpc_session;
struct jsonrpc_msg;

struct ovsdb_txn_forward *ovsdb_txn_forward_create(
    struct ovsdb *, const struct jsonrpc_msg *request);
void ovsdb_txn_forward_destroy(struct ovsdb *, struct ovsdb_txn_forward *);

bool ovsdb_txn_forward_is_complete(const struct ovsdb_txn_forward *);
void ovsdb_txn_forward_complete(struct ovsdb *,
                                const struct jsonrpc_msg *reply);

struct jsonrpc_msg *ovsdb_txn_forward_steal_reply(struct ovsdb_txn_forward *);

void ovsdb_txn_forward_run(struct ovsdb *, struct ovsdb_cs *);
void ovsdb_txn_forward_wait(struct ovsdb *, struct ovsdb_cs *);

void ovsdb_txn_forward_cancel(struct ovsdb *, struct ovsdb_txn_forward *);
void ovsdb_txn_forward_cancel_all(struct ovsdb *, bool sent_only);

#endif /* OVSDB_TXN_FORWARD_H */
