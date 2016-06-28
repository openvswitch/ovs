/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#include "replication.h"

#include "condition.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "query.h"
#include "row.h"
#include "stream.h"
#include "sset.h"
#include "svec.h"
#include "table.h"
#include "transaction.h"

static char *remote_ovsdb_server;
static struct jsonrpc *rpc;
static struct sset monitored_tables = SSET_INITIALIZER(&monitored_tables);
static struct sset tables_blacklist = SSET_INITIALIZER(&tables_blacklist);
static bool reset_dbs = true;

static struct jsonrpc *open_jsonrpc(const char *server);
static struct ovsdb_error *check_jsonrpc_error(int error,
                                               struct jsonrpc_msg **reply_);
static void fetch_dbs(struct jsonrpc *rpc, struct svec *dbs);
static struct ovsdb_schema *fetch_schema(struct jsonrpc *rpc,
                                         const char *database);

static void send_monitor_requests(struct shash *all_dbs);
static void add_monitored_table(struct ovsdb_table_schema *table,
                                struct json *monitor_requests);

static void get_initial_db_state(const struct db *database);
static void reset_database(struct ovsdb *db, struct ovsdb_txn *txn);
static struct ovsdb_error *reset_databases(struct shash *all_dbs);

static void check_for_notifications(struct shash *all_dbs);
static void process_notification(struct json *table_updates,
                                 struct ovsdb *database);
static struct ovsdb_error *process_table_update(struct json *table_update,
                                                const char *table_name,
                                                struct ovsdb *database,
                                                struct ovsdb_txn *txn);

static struct ovsdb_error *execute_insert(struct ovsdb_txn *txn,
                                          const char *uuid,
                                          struct ovsdb_table *table,
                                          struct json *new);
static struct ovsdb_error *execute_delete(struct ovsdb_txn *txn,
                                          const char *uuid,
                                          struct ovsdb_table *table);
static struct ovsdb_error *execute_update(struct ovsdb_txn *txn,
                                          const char *uuid,
                                          struct ovsdb_table *table,
                                          struct json *new);

void
replication_init(void)
{
    sset_init(&monitored_tables);
    sset_init(&tables_blacklist);
    reset_dbs = true;
}

void
replication_run(struct shash *all_dbs)
{
    if (sset_is_empty(&monitored_tables) && remote_ovsdb_server) {
        /* Reset local databases. */
        if (reset_dbs) {
            struct ovsdb_error *error = reset_databases(all_dbs);
            if (!error) {
                reset_dbs = false;
            }
            /* In case of success reseting the databases,
             * return in order to notify monitors. */
            return;
        }

        /* Open JSON-RPC. */
        jsonrpc_close(rpc);
        rpc = open_jsonrpc(remote_ovsdb_server);
        if (!rpc) {
            return;
        }

        /* Send monitor requests. */
        send_monitor_requests(all_dbs);
    }
    if (!sset_is_empty(&monitored_tables)) {
        check_for_notifications(all_dbs);
    }
}

void
set_remote_ovsdb_server(const char *remote_server)
{
    remote_ovsdb_server = nullable_xstrdup(remote_server);
}

const char *
get_remote_ovsdb_server(void)
{
    return remote_ovsdb_server;
}

void
set_tables_blacklist(const char *blacklist)
{
    replication_init();
    if (blacklist) {
        sset_from_delimited_string(&tables_blacklist, blacklist, ",");
    }
}

struct sset
get_tables_blacklist(void)
{
    return tables_blacklist;
}

void
disconnect_remote_server(void)
{
    jsonrpc_close(rpc);
    sset_clear(&monitored_tables);
    sset_clear(&tables_blacklist);
}

void
destroy_remote_server(void)
{
    jsonrpc_close(rpc);
    sset_destroy(&monitored_tables);
    sset_destroy(&tables_blacklist);

    if (remote_ovsdb_server) {
        free(remote_ovsdb_server);
        remote_ovsdb_server = NULL;
    }
}

const struct db *
find_db(const struct shash *all_dbs, const char *db_name)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, all_dbs) {
        struct db *db = node->data;
        if (!strcmp(db->db->schema->name, db_name)) {
            return db;
        }
    }

    return NULL;
}

static struct ovsdb_error *
reset_databases(struct shash *all_dbs)
{
    struct shash_node *db_node;
    struct ovsdb_error *error = NULL;

    SHASH_FOR_EACH (db_node, all_dbs) {
        struct db *db = db_node->data;
        struct ovsdb_txn *txn = ovsdb_txn_create(db->db);
        reset_database(db->db, txn);
        error = ovsdb_txn_commit(txn, false);
    }

    return error;
}

static void
reset_database(struct ovsdb *db, struct ovsdb_txn *txn)
{
    struct shash_node *table_node;

    SHASH_FOR_EACH (table_node, &db->tables) {
        struct ovsdb_table *table = table_node->data;
        struct ovsdb_row *row;

        /* Do not reset if table is blacklisted. */
        char *blacklist_item = xasprintf(
            "%s%s%s", db->schema->name, ":", table_node->name);
        if (!sset_contains(&tables_blacklist, blacklist_item)) {
            HMAP_FOR_EACH (row, hmap_node, &table->rows) {
                ovsdb_txn_row_delete(txn, row);
            }
        }
        free(blacklist_item);
    }
}

static struct jsonrpc *
open_jsonrpc(const char *server)
{
    struct stream *stream;
    int error;

    error = jsonrpc_stream_open(server, &stream, DSCP_DEFAULT);

    return error ? NULL : jsonrpc_open(stream);
}

static struct ovsdb_error *
check_jsonrpc_error(int error, struct jsonrpc_msg **reply_)
{
    struct jsonrpc_msg *reply = *reply_;

    if (error) {
        return ovsdb_error("transaction failed",
                           "transaction returned error %d",
                           error);
    }

    if (reply->error) {
        return ovsdb_error("transaction failed",
                           "transaction returned error: %s",
                           json_to_string(reply->error, 0));
    }
    return NULL;
}

static void
fetch_dbs(struct jsonrpc *rpc, struct svec *dbs)
{
    struct jsonrpc_msg *request, *reply;
    struct ovsdb_error *error;
    size_t i;

    request = jsonrpc_create_request("list_dbs", json_array_create_empty(),
                                     NULL);

    error = check_jsonrpc_error(jsonrpc_transact_block(rpc, request, &reply),
                                &reply);
    if (error) {
        ovsdb_error_assert(error);
        return;
    }

    if (reply->result->type != JSON_ARRAY) {
        ovsdb_error_assert(ovsdb_error("list-dbs failed",
                                       "list_dbs response is not array"));
        return;
    }

    for (i = 0; i < reply->result->u.array.n; i++) {
        const struct json *name = reply->result->u.array.elems[i];

        if (name->type != JSON_STRING) {
            ovsdb_error_assert(ovsdb_error(
                                   "list_dbs failed",
                                   "list_dbs response %"PRIuSIZE" is not string",
                                   i));
        }
        svec_add(dbs, name->u.string);
    }
    jsonrpc_msg_destroy(reply);
    svec_sort(dbs);
}

static struct ovsdb_schema *
fetch_schema(struct jsonrpc *rpc, const char *database)
{
    struct jsonrpc_msg *request, *reply;
    struct ovsdb_schema *schema;
    struct ovsdb_error *error;

    request = jsonrpc_create_request("get_schema",
                                     json_array_create_1(
                                         json_string_create(database)),
                                     NULL);
    error = check_jsonrpc_error(jsonrpc_transact_block(rpc, request, &reply),
                                &reply);
    if (error) {
        jsonrpc_msg_destroy(reply);
        ovsdb_error_assert(error);
        return NULL;
    }

    error = ovsdb_schema_from_json(reply->result, &schema);
    if (error) {
        jsonrpc_msg_destroy(reply);
        ovsdb_error_assert(error);
        return NULL;
    }
    jsonrpc_msg_destroy(reply);

    return schema;
}

static void
send_monitor_requests(struct shash *all_dbs)
{
    const char *db_name;
    struct svec dbs;
    size_t i;

    svec_init(&dbs);
    fetch_dbs(rpc, &dbs);
    SVEC_FOR_EACH (i, db_name, &dbs) {
        const struct db *database = find_db(all_dbs, db_name);

        if (database) {
            struct ovsdb_schema *local_schema, *remote_schema;

            local_schema = database->db->schema;
            remote_schema = fetch_schema(rpc, db_name);
            if (ovsdb_schema_equal(local_schema, remote_schema)) {
                struct jsonrpc_msg *request;
                struct json *monitor, *monitor_request;

                monitor_request = json_object_create();
                size_t n = shash_count(&local_schema->tables);
                const struct shash_node **nodes = shash_sort(
                    &local_schema->tables);

                for (int j = 0; j < n; j++) {
                    struct ovsdb_table_schema *table = nodes[j]->data;

                    /* Check if table is not blacklisted. */
                    char *blacklist_item = xasprintf(
                        "%s%s%s", db_name, ":", table->name);
                    if (!sset_contains(&tables_blacklist, blacklist_item)) {
                        add_monitored_table(table, monitor_request);
                    }
                    free(blacklist_item);
                }
                free(nodes);

                /* Send monitor request. */
                monitor = json_array_create_3(
                    json_string_create(db_name),
                    json_string_create(db_name),
                    monitor_request);
                request = jsonrpc_create_request("monitor", monitor, NULL);
                jsonrpc_send(rpc, request);
                get_initial_db_state(database);
            }
            ovsdb_schema_destroy(remote_schema);
        }
    }
    svec_destroy(&dbs);
}

static void
get_initial_db_state(const struct db *database)
{
    struct jsonrpc_msg *msg;

    jsonrpc_recv_block(rpc, &msg);

    if (msg->type == JSONRPC_REPLY) {
        process_notification(msg->result, database->db);
    }

    jsonrpc_msg_destroy(msg);
}

static void
add_monitored_table(struct ovsdb_table_schema *table,
                    struct json *monitor_request)
{
    struct json *monitor_request_array;

    sset_add(&monitored_tables, table->name);

    monitor_request_array = json_array_create_empty();
    json_array_add(monitor_request_array, json_object_create());

    json_object_put(monitor_request, table->name, monitor_request_array);
}

static void
check_for_notifications(struct shash *all_dbs)
{
    struct jsonrpc_msg *msg;
    int error;

    error = jsonrpc_recv(rpc, &msg);
    if (error == EAGAIN) {
        return;
    } else if (error) {
        jsonrpc_close(rpc);
        rpc = open_jsonrpc(remote_ovsdb_server);
        if (!rpc) {
            /* Remote server went down. */
            disconnect_remote_server();
        }
        jsonrpc_msg_destroy(msg);
        return;
    }
    if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
        jsonrpc_send(rpc, jsonrpc_create_reply(json_clone(msg->params),
                                               msg->id));
    } else if (msg->type == JSONRPC_NOTIFY
               && !strcmp(msg->method, "update")) {
        struct json *params = msg->params;
        if (params->type == JSON_ARRAY
            && params->u.array.n == 2) {
            char *db_name = params->u.array.elems[0]->u.string;
            const struct db *database = find_db(all_dbs, db_name);
            if (database) {
                process_notification(params->u.array.elems[1], database->db);
            }
        }
    }
    jsonrpc_msg_destroy(msg);
    jsonrpc_run(rpc);
}

static void
process_notification(struct json *table_updates, struct ovsdb *database)
{
    struct ovsdb_error *error;
    struct ovsdb_txn *txn;

    if (table_updates->type != JSON_OBJECT) {
        sset_clear(&monitored_tables);
        return;
    }

    txn = ovsdb_txn_create(database);
    error = NULL;

    /* Process each table update. */
    struct shash_node *node;
    SHASH_FOR_EACH (node, json_object(table_updates)) {
        struct json *table_update = node->data;
        if (table_update) {
            error = process_table_update(table_update, node->name, database, txn);
            if (error) {
                break;
            }
        }
    }

    if (error) {
        ovsdb_txn_abort(txn);
        goto error;
    }

    /* Commit transaction. */
    error = ovsdb_txn_commit(txn, false);

error:
    if (error) {
        ovsdb_error_assert(error);
        disconnect_remote_server();
    }
}

static struct ovsdb_error *
process_table_update(struct json *table_update, const char *table_name,
                     struct ovsdb *database, struct ovsdb_txn *txn)
{
    struct shash_node *node;
    struct ovsdb_table *table;
    struct ovsdb_error *error;

    if (table_update->type != JSON_OBJECT) {
        return ovsdb_error("Not a JSON object",
                           "<table-update> for table is not object");
    }

    table = ovsdb_get_table(database, table_name);
    error = NULL;

    SHASH_FOR_EACH (node, json_object(table_update)) {
        struct json *row_update = node->data;
        struct json *old, *new;

        if (row_update->type != JSON_OBJECT) {
            error = ovsdb_error("NOt a JSON object",
                                "<row-update> is not object");
            break;
        }
        old = shash_find_data(json_object(row_update), "old");
        new = shash_find_data(json_object(row_update), "new");

        if (!old) {
            error = execute_insert(txn, node->name, table, new);
        } else{
            if (!new) {
                error = execute_delete(txn, node->name, table);
            } else {
                error = execute_update(txn, node->name, table, new);
            }
        }
        if (error) {
            break;
        }
    }
    return error;
}

static struct ovsdb_error *
execute_insert(struct ovsdb_txn *txn, const char *uuid,
               struct ovsdb_table *table, struct json *json_row)
{
    struct ovsdb_row *row = NULL;
    struct uuid row_uuid;
    struct ovsdb_error *error;

    row = ovsdb_row_create(table);
    error = ovsdb_row_from_json(row, json_row, NULL, NULL);
    if (!error) {
        /* Add UUID to row. */
        uuid_from_string(&row_uuid, uuid);
        *ovsdb_row_get_uuid_rw(row) = row_uuid;
        ovsdb_txn_row_insert(txn, row);
    } else {
        ovsdb_row_destroy(row);
    }

    return error;
}

struct delete_row_cbdata {
    size_t n_matches;
    const struct ovsdb_table *table;
    struct ovsdb_txn *txn;
};

static bool
delete_row_cb(const struct ovsdb_row *row, void *dr_)
{
    struct delete_row_cbdata *dr = dr_;

    dr->n_matches++;
    ovsdb_txn_row_delete(dr->txn, row);

    return true;
}

static struct ovsdb_error *
execute_delete(struct ovsdb_txn *txn, const char *uuid,
               struct ovsdb_table *table)
{
    const struct json *where;
    struct ovsdb_error *error;
    struct ovsdb_condition condition = OVSDB_CONDITION_INITIALIZER(&condition);
    char where_string[UUID_LEN+29];

    if (!table) {
        return OVSDB_BUG("null table");
    }

    snprintf(where_string, sizeof where_string, "%s%s%s",
             "[[\"_uuid\",\"==\",[\"uuid\",\"",uuid,"\"]]]");

    where = json_from_string(where_string);
    error = ovsdb_condition_from_json(table->schema, where, NULL, &condition);
    if (!error) {
        struct delete_row_cbdata dr;

        dr.n_matches = 0;
        dr.table = table;
        dr.txn = txn;
        ovsdb_query(table, &condition, delete_row_cb, &dr);
    }

    ovsdb_condition_destroy(&condition);
    return error;
}

struct update_row_cbdata {
    size_t n_matches;
    struct ovsdb_txn *txn;
    const struct ovsdb_row *row;
    const struct ovsdb_column_set *columns;
};

static bool
update_row_cb(const struct ovsdb_row *row, void *ur_)
{
    struct update_row_cbdata *ur = ur_;

    ur->n_matches++;
    if (!ovsdb_row_equal_columns(row, ur->row, ur->columns)) {
        ovsdb_row_update_columns(ovsdb_txn_row_modify(ur->txn, row),
                                 ur->row, ur->columns);
    }

    return true;
}

static struct ovsdb_error *
execute_update(struct ovsdb_txn *txn, const char *uuid,
               struct ovsdb_table *table, struct json *json_row)
{
    struct ovsdb_column_set columns = OVSDB_COLUMN_SET_INITIALIZER;
    struct ovsdb_condition condition = OVSDB_CONDITION_INITIALIZER(&condition);
    struct update_row_cbdata ur;
    struct ovsdb_row *row;
    struct ovsdb_error *error;
    const struct json *where;
    char where_string[UUID_LEN+29];

    snprintf(where_string, sizeof where_string, "%s%s%s",
             "[[\"_uuid\",\"==\",[\"uuid\",\"",uuid,"\"]]]");
    where = json_from_string(where_string);

    row = ovsdb_row_create(table);
    error = ovsdb_row_from_json(row, json_row, NULL, &columns);
    if (!error) {
        error = ovsdb_condition_from_json(table->schema, where, NULL,
                                          &condition);
    }
    if (!error) {
        ur.n_matches = 0;
        ur.txn = txn;
        ur.row = row;
        ur.columns = &columns;
        ovsdb_query(table, &condition, update_row_cb, &ur);
    }

    ovsdb_row_destroy(row);
    ovsdb_column_set_destroy(&columns);
    ovsdb_condition_destroy(&condition);

    return error;
}

void
replication_usage(void)
{
    printf("\n\
Syncing options:\n\
  --sync-from=SERVER      sync DATABASE from remote SERVER\n\
  --sync-exclude-tables=DB:TABLE,...\n\
                          exclude the TABLE in DB from syncing\n");
}
