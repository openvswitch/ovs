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

#include "relay.h"

#include "coverage.h"
#include "jsonrpc.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovsdb.h"
#include "ovsdb-cs.h"
#include "ovsdb-error.h"
#include "row.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "transaction-forward.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(relay);

static struct shash relay_dbs = SHASH_INITIALIZER(&relay_dbs);

struct relay_ctx {
    struct ovsdb *db;
    struct ovsdb_cs *cs;

    /* Schema updates. */
    struct ovsdb_schema *new_schema;
    schema_change_callback schema_change_cb;
    void *schema_change_aux;

    long long int last_connected;
};

#define RELAY_MAX_RECONNECTION_MS 30000

/* Reports if the database is connected to the relay source and functional,
 * i.e. it actively monitors the source and is able to forward transactions. */
bool
ovsdb_relay_is_connected(struct ovsdb *db)
{
    struct relay_ctx *ctx = shash_find_data(&relay_dbs, db->name);

    if (!ctx || !ovsdb_cs_is_alive(ctx->cs)) {
        return false;
    }

    if (ovsdb_cs_may_send_transaction(ctx->cs)) {
        return true;
    }

    /* Trying to avoid connection state flapping by delaying report for
     * upper layer and giving ovsdb-cs some time to reconnect. */
    if (time_msec() - ctx->last_connected < RELAY_MAX_RECONNECTION_MS) {
        return true;
    }

    return false;
}

static struct json *
ovsdb_relay_compose_monitor_request(const struct json *schema_json, void *ctx_)
{
    struct json *monitor_request = json_object_create();
    struct relay_ctx *ctx = ctx_;
    struct ovsdb_schema *schema;
    struct ovsdb *db = ctx->db;
    struct ovsdb_error *error;

    error = ovsdb_schema_from_json(schema_json, &schema);
    if (error) {
        char *msg = ovsdb_error_to_string_free(error);
        VLOG_WARN("%s: Failed to parse db schema: %s", db->name, msg);
        free(msg);
        /* There is nothing we can really do here. */
        return monitor_request;
    }

    const struct shash_node *node;
    SHASH_FOR_EACH (node, &schema->tables) {
        struct json *monitor_request_array = json_array_create_empty();
        struct ovsdb_table_schema *table = node->data;

        json_array_add(monitor_request_array, json_object_create());
        json_object_put(monitor_request, table->name, monitor_request_array);
    }

    if (!db->schema || !ovsdb_schema_equal(schema, db->schema)) {
        VLOG_DBG("database %s schema changed.", db->name);
        if (ctx->new_schema) {
            ovsdb_schema_destroy(ctx->new_schema);
        }
        /* We will update the schema later when we will receive actual data
         * from the mointor in order to avoid sitting with an empty database
         * until the monitor reply. */
        ctx->new_schema = schema;
    } else {
        ovsdb_schema_destroy(schema);
    }
    return monitor_request;
}

static struct ovsdb_cs_ops relay_cs_ops = {
    .compose_monitor_requests = ovsdb_relay_compose_monitor_request,
};

void
ovsdb_relay_add_db(struct ovsdb *db, const char *remote,
                   schema_change_callback schema_change_cb,
                   void *schema_change_aux)
{
    struct relay_ctx *ctx;

    if (!db || !remote) {
        return;
    }

    ctx = shash_find_data(&relay_dbs, db->name);
    if (ctx) {
        ovsdb_cs_set_remote(ctx->cs, remote, true);
        VLOG_DBG("%s: relay source set to '%s'", db->name, remote);
        return;
    }

    db->is_relay = true;
    ctx = xzalloc(sizeof *ctx);
    ctx->schema_change_cb = schema_change_cb;
    ctx->schema_change_aux = schema_change_aux;
    ctx->db = db;
    ctx->cs = ovsdb_cs_create(db->name, 3, &relay_cs_ops, ctx);
    ctx->last_connected = 0;
    shash_add(&relay_dbs, db->name, ctx);
    ovsdb_cs_set_leader_only(ctx->cs, false);
    ovsdb_cs_set_remote(ctx->cs, remote, true);

    VLOG_DBG("added database: %s, %s", db->name, remote);
}

void
ovsdb_relay_del_db(struct ovsdb *db)
{
    struct relay_ctx *ctx;

    if (!db) {
        return;
    }

    ctx = shash_find_and_delete(&relay_dbs, db->name);
    if (!ctx) {
        VLOG_WARN("Failed to remove relay database %s: not found.", db->name);
        return;
    }

    VLOG_DBG("removed database: %s", db->name);

    db->is_relay = false;
    ovsdb_cs_destroy(ctx->cs);
    free(ctx);
}

static struct ovsdb_error *
ovsdb_relay_process_row_update(struct ovsdb_table *table,
                               const struct ovsdb_cs_row_update *ru,
                               struct ovsdb_txn *txn)
{
    const struct uuid *uuid = &ru->row_uuid;
    struct ovsdb_error * error = NULL;

    /* XXX: ovsdb-cs module returns shash which was previously part of a json
     *      structure and we need json row format in order to use ovsdb_row*
     *      functions.  Creating a json object out of shash. */
    struct json *json_row = json_object_create();
    struct shash *obj = json_row->object;
    json_row->object = CONST_CAST(struct shash *, ru->columns);

    switch (ru->type) {
    case OVSDB_CS_ROW_DELETE:
        error = ovsdb_table_execute_delete(txn, uuid, table);
        break;

    case OVSDB_CS_ROW_INSERT:
        error = ovsdb_table_execute_insert(txn, uuid, table, json_row);
        break;

    case OVSDB_CS_ROW_UPDATE:
        error = ovsdb_table_execute_update(txn, uuid, table, json_row, false);
        break;

    case OVSDB_CS_ROW_XOR:
        error = ovsdb_table_execute_update(txn, uuid, table, json_row, true);
        break;

    default:
        OVS_NOT_REACHED();
    }

    json_row->object = obj;
    json_destroy(json_row);

    return error;
}

static struct ovsdb_error *
ovsdb_relay_parse_update__(struct ovsdb *db,
                           const struct ovsdb_cs_db_update *du,
                           const struct uuid *last_id)
{
    struct ovsdb_error *error = NULL;
    struct ovsdb_txn *txn;

    txn = ovsdb_txn_create(db);

    for (size_t i = 0; i < du->n; i++) {
        const struct ovsdb_cs_table_update *tu = &du->table_updates[i];
        struct ovsdb_table *table = ovsdb_get_table(db, tu->table_name);

        if (!table) {
            error = ovsdb_error("unknown table", "unknown table %s",
                                tu->table_name);
            goto exit;
        }

        for (size_t j = 0; j < tu->n; j++) {
            const struct ovsdb_cs_row_update *ru = &tu->row_updates[j];

            error = ovsdb_relay_process_row_update(table, ru, txn);
            if (error) {
                goto exit;
            }
        }
    }

exit:
    if (error) {
        ovsdb_txn_abort(txn);
        return error;
    } else {
        if (uuid_is_zero(last_id)) {
            /* The relay source doesn't support unique transaction ids,
             * disabling transaction history for relay. */
            ovsdb_txn_history_destroy(db);
            ovsdb_txn_history_init(db, false);
        } else {
            ovsdb_txn_set_txnid(last_id, txn);
        }
        /* Commit transaction.
         * There is no storage, so ovsdb_txn_replay_commit() can be used. */
        error = ovsdb_txn_replay_commit(txn);
    }

    return error;
}

static struct ovsdb_error *
ovsdb_relay_clear(struct ovsdb *db)
{
    struct ovsdb_txn *txn = ovsdb_txn_create(db);
    struct shash_node *table_node;
    struct ovsdb_error *error;

    SHASH_FOR_EACH (table_node, &db->tables) {
        struct ovsdb_table *table = table_node->data;
        struct ovsdb_row *row;

        HMAP_FOR_EACH_SAFE (row, hmap_node, &table->rows) {
            ovsdb_txn_row_delete(txn, row);
        }
    }

    /* There is no storage, so ovsdb_txn_replay_commit() can be used. */
    error = ovsdb_txn_replay_commit(txn);

    /* Clearing the transaction history, and re-enabling it. */
    ovsdb_txn_history_destroy(db);
    ovsdb_txn_history_init(db, true);

    return error;
}

static void
ovsdb_relay_parse_update(struct relay_ctx *ctx,
                         const struct ovsdb_cs_update_event *update)
{
    struct ovsdb_error *error = NULL;

    if (!ctx->db) {
        return;
    }

    if (update->monitor_reply && ctx->new_schema) {
        /* There was a schema change.  Updating a database with a new schema
         * before processing monitor reply with the new data. */
        error = ctx->schema_change_cb(ctx->db, ctx->new_schema, false,
                                      ctx->schema_change_aux);
        if (error) {
            /* Should never happen, but handle this case anyway. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            char *s = ovsdb_error_to_string_free(error);

            VLOG_ERR_RL(&rl, "%s", s);
            free(s);

            ovsdb_cs_flag_inconsistency(ctx->cs);
            return;
        }
        ovsdb_schema_destroy(ctx->new_schema);
        ctx->new_schema = NULL;
    }

    struct ovsdb_cs_db_update *du;

    error = ovsdb_cs_parse_db_update(update->table_updates,
                                     update->version, &du);
    if (!error) {
        if (update->clear) {
            error = ovsdb_relay_clear(ctx->db);
        }
        if (!error) {
            error = ovsdb_relay_parse_update__(ctx->db, du, &update->last_id);
        }
    }
    ovsdb_cs_db_update_destroy(du);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        if (!VLOG_DROP_WARN(&rl)) {
            char *s = ovsdb_error_to_string(error);
            VLOG_WARN_RL(&rl, "%s", s);
            free(s);
        }
        /* Something bad happened.  Try to recover. */
        if (!strcmp(ovsdb_error_get_tag(error), "consistency violation")) {
            ovsdb_cs_flag_inconsistency(ctx->cs);
        } else {
            ovsdb_cs_force_reconnect(ctx->cs);
        }
        ovsdb_error_destroy(error);
    }
}

void
ovsdb_relay_run(void)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, &relay_dbs) {
        struct relay_ctx *ctx = node->data;
        struct ovs_list events;

        ovsdb_txn_forward_run(ctx->db, ctx->cs);
        ovsdb_cs_run(ctx->cs, &events);

        if (ovsdb_cs_may_send_transaction(ctx->cs)) {
            ctx->last_connected = time_msec();
        }

        struct ovsdb_cs_event *event;
        LIST_FOR_EACH_POP (event, list_node, &events) {
            if (!ctx->db) {
                ovsdb_cs_event_destroy(event);
                continue;
            }

            switch (event->type) {
            case OVSDB_CS_EVENT_TYPE_RECONNECT:
                /* Cancelling all the transactions that were already sent but
                 * not replied yet as they might be lost. */
                ovsdb_txn_forward_cancel_all(ctx->db, true);
                break;

            case OVSDB_CS_EVENT_TYPE_UPDATE:
                ovsdb_relay_parse_update(ctx, &event->update);
                break;

            case OVSDB_CS_EVENT_TYPE_TXN_REPLY:
                ovsdb_txn_forward_complete(ctx->db, event->txn_reply);
                break;

            case OVSDB_CS_EVENT_TYPE_LOCKED:
                VLOG_WARN("%s: Unexpected LOCKED event.", ctx->db->name);
                break;
            }
            ovsdb_cs_event_destroy(event);
        }
        ovsdb_txn_history_run(ctx->db);
    }
}

void
ovsdb_relay_wait(void)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &relay_dbs) {
        struct relay_ctx *ctx = node->data;

        ovsdb_cs_wait(ctx->cs);
        ovsdb_txn_forward_wait(ctx->db, ctx->cs);
    }
}
