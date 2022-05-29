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

#include <config.h>

#include "transaction-forward.h"

#include "coverage.h"
#include "jsonrpc.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovsdb.h"
#include "ovsdb-cs.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(transaction_forward);

COVERAGE_DEFINE(txn_forward_cancel);
COVERAGE_DEFINE(txn_forward_complete);
COVERAGE_DEFINE(txn_forward_create);
COVERAGE_DEFINE(txn_forward_sent);

struct ovsdb_txn_forward {
    struct ovs_list new_node;    /* In 'txn_forward_new' of struct ovsdb. */
    struct hmap_node sent_node;  /* In 'txn_forward_sent' of struct ovsdb. */
    struct json *id;             /* 'id' of the forwarded transaction. */
    struct jsonrpc_msg *request; /* Original request. */
    struct jsonrpc_msg *reply;   /* Reply from the server. */
};

struct ovsdb_txn_forward *
ovsdb_txn_forward_create(struct ovsdb *db, const struct jsonrpc_msg *request)
{
    struct ovsdb_txn_forward *txn_fwd = xzalloc(sizeof *txn_fwd);

    COVERAGE_INC(txn_forward_create);
    txn_fwd->request = jsonrpc_msg_clone(request);
    ovs_list_push_back(&db->txn_forward_new, &txn_fwd->new_node);
    hmap_node_nullify(&txn_fwd->sent_node);

    return txn_fwd;
}

static void
ovsdb_txn_forward_unlist(struct ovsdb *db, struct ovsdb_txn_forward *txn_fwd)
{
    if (!ovs_list_is_empty(&txn_fwd->new_node)) {
        ovs_list_remove(&txn_fwd->new_node);
        ovs_list_init(&txn_fwd->new_node);
    }
    if (!hmap_node_is_null(&txn_fwd->sent_node)) {
        hmap_remove(&db->txn_forward_sent, &txn_fwd->sent_node);
        hmap_node_nullify(&txn_fwd->sent_node);
    }
}

void
ovsdb_txn_forward_destroy(struct ovsdb *db, struct ovsdb_txn_forward *txn_fwd)
{
    if (!txn_fwd) {
        return;
    }

    ovsdb_txn_forward_unlist(db, txn_fwd);
    json_destroy(txn_fwd->id);
    jsonrpc_msg_destroy(txn_fwd->request);
    jsonrpc_msg_destroy(txn_fwd->reply);
    free(txn_fwd);
}

bool
ovsdb_txn_forward_is_complete(const struct ovsdb_txn_forward *txn_fwd)
{
    return txn_fwd->reply != NULL;
}

void
ovsdb_txn_forward_complete(struct ovsdb *db, const struct jsonrpc_msg *reply)
{
    struct ovsdb_txn_forward *t;
    size_t hash = json_hash(reply->id, 0);

    HMAP_FOR_EACH_WITH_HASH (t, sent_node, hash, &db->txn_forward_sent) {
        if (json_equal(reply->id, t->id)) {
            COVERAGE_INC(txn_forward_complete);
            t->reply = jsonrpc_msg_clone(reply);

            /* Replacing id with the id of the original request. */
            json_destroy(t->reply->id);
            t->reply->id = json_clone(t->request->id);

            hmap_remove(&db->txn_forward_sent, &t->sent_node);
            hmap_node_nullify(&t->sent_node);

            db->run_triggers_now = db->run_triggers = true;
            return;
        }
    }
}

struct jsonrpc_msg *
ovsdb_txn_forward_steal_reply(struct ovsdb_txn_forward *txn_fwd)
{
    struct jsonrpc_msg *reply = txn_fwd->reply;

    txn_fwd->reply = NULL;
    return reply;
}

void
ovsdb_txn_forward_run(struct ovsdb *db, struct ovsdb_cs *cs)
{
    struct ovsdb_txn_forward *t;

    /* Send all transactions that needs to be forwarded. */
    LIST_FOR_EACH_SAFE (t, new_node, &db->txn_forward_new) {
        if (!ovsdb_cs_may_send_transaction(cs)) {
            break;
        }
        ovs_assert(!strcmp(t->request->method, "transact"));
        t->id = ovsdb_cs_send_transaction(cs, json_clone(t->request->params));
        if (t->id) {
            COVERAGE_INC(txn_forward_sent);
            ovs_list_remove(&t->new_node);
            ovs_list_init(&t->new_node);
            hmap_insert(&db->txn_forward_sent, &t->sent_node,
                        json_hash(t->id, 0));
        }
    }
}

void
ovsdb_txn_forward_wait(struct ovsdb *db, struct ovsdb_cs *cs)
{
    if (ovsdb_cs_may_send_transaction(cs)
        && !ovs_list_is_empty(&db->txn_forward_new)) {
        poll_immediate_wake();
    }
}

void
ovsdb_txn_forward_cancel(struct ovsdb *db, struct ovsdb_txn_forward *txn_fwd)
{
    COVERAGE_INC(txn_forward_cancel);
    jsonrpc_msg_destroy(txn_fwd->reply);
    txn_fwd->reply = jsonrpc_create_error(json_string_create("canceled"),
                                          txn_fwd->request->id);
    ovsdb_txn_forward_unlist(db, txn_fwd);
}

void
ovsdb_txn_forward_cancel_all(struct ovsdb *db, bool sent_only)
{
    struct ovsdb_txn_forward *t;

    HMAP_FOR_EACH_SAFE (t, sent_node, &db->txn_forward_sent) {
        ovsdb_txn_forward_cancel(db, t);
    }

    if (sent_only) {
        return;
    }

    LIST_FOR_EACH_SAFE (t, new_node, &db->txn_forward_new) {
        ovsdb_txn_forward_cancel(db, t);
    }
}
