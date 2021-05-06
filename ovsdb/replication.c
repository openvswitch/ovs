/*
 * (c) Copyright 2016, 2017 Hewlett Packard Enterprise Development LP
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
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


#include "condition.h"
#include "jsonrpc.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/vlog.h"
#include "ovsdb-error.h"
#include "ovsdb.h"
#include "query.h"
#include "replication.h"
#include "row.h"
#include "sset.h"
#include "stream.h"
#include "svec.h"
#include "table.h"
#include "transaction.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(replication);

static char *sync_from;
static struct uuid server_uuid;
static struct jsonrpc_session *session;
static unsigned int session_seqno = UINT_MAX;

static struct jsonrpc_msg *create_monitor_request(struct ovsdb_schema *);
static void add_monitored_table(struct ovsdb_table_schema *table,
                                struct json *monitor_requests);

static struct ovsdb_error *reset_database(struct ovsdb *db);

static struct ovsdb_error *process_notification(struct json *, struct ovsdb *);
static struct ovsdb_error *process_table_update(struct json *table_update,
                                                const char *table_name,
                                                struct ovsdb *database,
                                                struct ovsdb_txn *txn);

static struct ovsdb_error *execute_insert(struct ovsdb_txn *txn,
                                          const struct uuid *row_uuid,
                                          struct ovsdb_table *table,
                                          struct json *new);
static struct ovsdb_error *execute_delete(struct ovsdb_txn *txn,
                                          const struct uuid *row_uuid,
                                          struct ovsdb_table *table);
static struct ovsdb_error *execute_update(struct ovsdb_txn *txn,
                                          const struct uuid *row_uuid,
                                          struct ovsdb_table *table,
                                          struct json *new);

/* Maps from db name to sset of table names. */
static struct shash excluded_tables = SHASH_INITIALIZER(&excluded_tables);

static void excluded_tables_clear(void);
static void excluded_tables_add(const char *database, const char *table);
static bool excluded_tables_find(const char *database, const char *table);


/* Keep track of request IDs of all outstanding OVSDB requests. */
static struct hmap request_ids = HMAP_INITIALIZER(&request_ids);

struct request_ids_hmap_node {
    struct hmap_node hmap;
    struct json *request_id;
    struct ovsdb *db;          /* associated database */
};
void request_ids_add(const struct json *id, struct ovsdb *db);
bool request_ids_lookup_and_free(const struct json *id, struct ovsdb **db);
static void request_ids_destroy(void);
void request_ids_clear(void);

enum ovsdb_replication_state {
    RPL_S_INIT,
    RPL_S_SERVER_ID_REQUESTED,
    RPL_S_DB_REQUESTED,
    RPL_S_SCHEMA_REQUESTED,
    RPL_S_MONITOR_REQUESTED,
    RPL_S_REPLICATING,
    RPL_S_ERR /* Error, no longer replicating. */
};
static enum ovsdb_replication_state state;


struct replication_db {
    struct ovsdb *db;
    bool schema_version_higher;
     /* Points to the schema received from the active server if
      * the local db schema version is higher. NULL otherwise. */
    struct ovsdb_schema *active_db_schema;
};

static bool is_replication_possible(struct ovsdb_schema *local_db_schema,
                                    struct ovsdb_schema *active_db_schema);

/* All DBs known to ovsdb-server.  The actual replication dbs are stored
 * in 'replication dbs', which is a subset of all dbs and remote dbs whose
 * schema matches.  */
static struct shash local_dbs = SHASH_INITIALIZER(&local_dbs);
static struct shash *replication_dbs;

static struct shash *replication_dbs_create(void);
static void replication_dbs_destroy(void);
/* Find 'struct ovsdb' by name within 'replication_dbs' */
static struct replication_db *find_db(const char *db_name);


void
replication_init(const char *sync_from_, const char *exclude_tables,
                 const struct uuid *server, int probe_interval)
{
    free(sync_from);
    sync_from = xstrdup(sync_from_);
    /* Caller should have verified that the 'exclude_tables' is
     * parseable. An error here is unexpected. */
    ovs_assert(!set_excluded_tables(exclude_tables, false));

    replication_dbs_destroy();

    shash_clear(&local_dbs);
    if (session) {
        jsonrpc_session_close(session);
    }

    session = jsonrpc_session_open(sync_from, true);
    session_seqno = UINT_MAX;

    jsonrpc_session_set_probe_interval(session, probe_interval);

    /* Keep a copy of local server uuid.  */
    server_uuid = *server;

    state = RPL_S_INIT;
}

void
replication_add_local_db(const char *database, struct ovsdb *db)
{
    shash_add_assert(&local_dbs, database, db);
}

static void
send_schema_requests(const struct json *result)
{
    for (size_t i = 0; i < result->array.n; i++) {
        const struct json *name = result->array.elems[i];
        if (name->type == JSON_STRING) {
            /* Send one schema request for each remote DB. */
            const char *db_name = json_string(name);
            struct replication_db *rdb = find_db(db_name);
            if (rdb) {
                struct jsonrpc_msg *request =
                    jsonrpc_create_request(
                        "get_schema",
                        json_array_create_1(
                            json_string_create(db_name)),
                        NULL);

                request_ids_add(request->id, rdb->db);
                jsonrpc_session_send(session, request);
            }
        }
    }
}

void
replication_run(void)
{
    if (!session) {
        return;
    }

    jsonrpc_session_run(session);

    for (int i = 0; jsonrpc_session_is_connected(session) && i < 50; i++) {
        struct jsonrpc_msg *msg;
        unsigned int seqno;

        seqno = jsonrpc_session_get_seqno(session);
        if (seqno != session_seqno || state == RPL_S_INIT) {
            session_seqno = seqno;
            request_ids_clear();
            struct jsonrpc_msg *request;
            request = jsonrpc_create_request("get_server_id",
                                             json_array_create_empty(), NULL);
            request_ids_add(request->id, NULL);
            jsonrpc_session_send(session, request);

            state = RPL_S_SERVER_ID_REQUESTED;
            VLOG_DBG("send server ID request.");
        }

        msg = jsonrpc_session_recv(session);
        if (!msg) {
            continue;
        }

        if (msg->type == JSONRPC_NOTIFY && state != RPL_S_ERR
            && !strcmp(msg->method, "update")) {
            if (msg->params->type == JSON_ARRAY
                && msg->params->array.n == 2
                && msg->params->array.elems[0]->type == JSON_STRING) {
                char *db_name = msg->params->array.elems[0]->string;
                struct replication_db *rdb = find_db(db_name);
                if (rdb) {
                    struct ovsdb_error *error;
                    error = process_notification(msg->params->array.elems[1],
                                                 rdb->db);
                    if (error) {
                        ovsdb_error_assert(error);
                        state = RPL_S_ERR;
                    }
                }
            }
        } else if (msg->type == JSONRPC_REPLY) {
            struct replication_db *rdb;
            struct ovsdb *db;
            if (!request_ids_lookup_and_free(msg->id, &db)) {
                VLOG_WARN("received unexpected reply");
                goto next;
            }

            switch (state) {
            case RPL_S_SERVER_ID_REQUESTED: {
                struct uuid uuid;
                if (msg->result->type != JSON_STRING ||
                    !uuid_from_string(&uuid, json_string(msg->result))) {
                    struct ovsdb_error *error;
                    error = ovsdb_error("get_server_id failed",
                                        "Server ID is not valid UUID");

                    ovsdb_error_assert(error);
                    state = RPL_S_ERR;
                    break;
                }

                if (uuid_equals(&uuid, &server_uuid)) {
                    struct ovsdb_error *error;
                    error = ovsdb_error("Server ID check failed",
                                        "Self replicating is not allowed");

                    ovsdb_error_assert(error);
                    state = RPL_S_ERR;
                    break;
                }

                struct jsonrpc_msg *request;
                request = jsonrpc_create_request("list_dbs",
                                                 json_array_create_empty(),
                                                 NULL);
                request_ids_add(request->id, NULL);
                jsonrpc_session_send(session, request);

                replication_dbs_destroy();
                replication_dbs = replication_dbs_create();
                state = RPL_S_DB_REQUESTED;
                break;
            }
            case RPL_S_DB_REQUESTED:
                if (msg->result->type != JSON_ARRAY) {
                    struct ovsdb_error *error;
                    error = ovsdb_error("list_dbs failed",
                                        "list_dbs response is not array");
                    ovsdb_error_assert(error);
                    state = RPL_S_ERR;
                } else {
                    send_schema_requests(msg->result);
                    VLOG_DBG("Send schema requests");
                    state = RPL_S_SCHEMA_REQUESTED;
                }
                break;

            case RPL_S_SCHEMA_REQUESTED: {
                struct ovsdb_schema *schema;
                struct ovsdb_error *error;

                error = ovsdb_schema_from_json(msg->result, &schema);
                if (error) {
                    ovsdb_error_assert(error);
                    state = RPL_S_ERR;
                }

                rdb = find_db(schema->name);
                if (!rdb) {
                    /* Unexpected schema. */
                    VLOG_WARN("unexpected schema %s", schema->name);
                    state = RPL_S_ERR;
                } else if (!ovsdb_schema_equal(schema, rdb->db->schema)) {
                    /* Schmea version mismatch. */
                    VLOG_INFO("Schema version mismatch, checking if %s can "
                              "still be replicated or not.",
                              schema->name);
                    if (is_replication_possible(rdb->db->schema, schema)) {
                        VLOG_INFO("%s can be replicated.", schema->name);
                        rdb->schema_version_higher = true;
                        if (rdb->active_db_schema) {
                            ovsdb_schema_destroy(rdb->active_db_schema);
                        }
                        rdb->active_db_schema = schema;
                    } else {
                        VLOG_INFO("%s cannot be replicated.", schema->name);
                        struct replication_db *r =
                            shash_find_and_delete(replication_dbs,
                                                  schema->name);
                        if (r->active_db_schema) {
                            ovsdb_schema_destroy(r->active_db_schema);
                        }
                        free(r);
                        ovsdb_schema_destroy(schema);
                    }
                } else {
                    ovsdb_schema_destroy(schema);
                }

                /* After receiving schemas, reset the local databases that
                 * will be monitored and send out monitor requests for them. */
                if (hmap_is_empty(&request_ids)) {
                    struct shash_node *node;

                    if (shash_is_empty(replication_dbs)) {
                        VLOG_WARN("Nothing to replicate.");
                        state = RPL_S_ERR;
                    } else {
                        SHASH_FOR_EACH (node, replication_dbs) {
                            rdb = node->data;
                            struct jsonrpc_msg *request =
                                create_monitor_request(
                                    rdb->schema_version_higher ?
                                    rdb->active_db_schema : rdb->db->schema);

                            request_ids_add(request->id, rdb->db);
                            jsonrpc_session_send(session, request);
                            VLOG_DBG("Send monitor requests");
                            state = RPL_S_MONITOR_REQUESTED;
                        }
                    }
                }
                break;
            }

            case RPL_S_MONITOR_REQUESTED: {
                /* Reply to monitor requests. */
                struct ovsdb_error *error;
                VLOG_INFO("Monitor request received. Resetting the database");
                /* Resetting the database here has few risks. If the
                 * process_notification() fails, the database is completely
                 * lost locally. In case that node becomes active, then
                 * there is a chance of complete data loss in the active/standy
                 * cluster. */
                error = reset_database(db);
                if (!error) {
                    error = process_notification(msg->result, db);
                }
                if (error) {
                    ovsdb_error_assert(error);
                    state = RPL_S_ERR;
                } else {
                    /* Transition to replicating state after receiving
                     * all replies of "monitor" requests. */
                    if (hmap_is_empty(&request_ids)) {
                        VLOG_DBG("Listening to monitor updates");
                        state = RPL_S_REPLICATING;
                    }
                }
                break;
            }

            case RPL_S_ERR:
                /* Ignore all messages */
                break;

            case RPL_S_INIT:
            case RPL_S_REPLICATING:
            default:
                OVS_NOT_REACHED();
            }
        }
    next:
        jsonrpc_msg_destroy(msg);
    }
}

void
replication_wait(void)
{
    if (session) {
        jsonrpc_session_wait(session);
        jsonrpc_session_recv_wait(session);
    }
}

/* Parse 'excluded' to rebuild 'excluded_tables'.  If 'dryrun' is false, the
 * current set of excluded tables will be wiped out, regardless of whether
 * 'excluded' can be parsed.  If 'dryrun' is true, only parses 'excluded' and
 * reports any errors, without modifying the list of exclusions.
 *
 * On error, returns the error string, which the caller is
 * responsible for freeing. Returns NULL otherwise. */
char * OVS_WARN_UNUSED_RESULT
set_excluded_tables(const char *excluded, bool dryrun)
{
    struct sset set = SSET_INITIALIZER(&set);
    char *err = NULL;

    if (excluded) {
        const char *longname;

        if (!dryrun) {
            /* Can only add to an empty shash. */
            excluded_tables_clear();
        }

        sset_from_delimited_string(&set, excluded, " ,");
        SSET_FOR_EACH (longname, &set) {
            char *database = xstrdup(longname), *table = NULL;
            strtok_r(database, ":", &table);
            if (table && !dryrun) {
                excluded_tables_add(database, table);
            }

            free(database);
            if (!table) {
                err = xasprintf("Can't parse excluded table: %s", longname);
                goto done;
            }
        }
    }

done:
    sset_destroy(&set);
    if (err && !dryrun) {
        /* On error, destroy the partially built 'excluded_tables'. */
        excluded_tables_clear();
    }
    return err;
}

char * OVS_WARN_UNUSED_RESULT
get_excluded_tables(void)
{
    struct shash_node *node;
    struct sset set = SSET_INITIALIZER(&set);

    SHASH_FOR_EACH (node, &excluded_tables) {
        const char *database = node->name;
        const char *table;
        struct sset *tables = node->data;

        SSET_FOR_EACH (table, tables) {
            sset_add_and_free(&set, xasprintf("%s:%s", database, table));
        }
    }

    /* Output the table list in an sorted order, so that
     * the output string will not depend on the hash function
     * that used to implement the hmap data structure. This is
     * only useful for writting unit tests.  */
    const char **sorted = sset_sort(&set);
    struct ds ds = DS_EMPTY_INITIALIZER;
    size_t i;
    for (i = 0; i < sset_count(&set); i++) {
        ds_put_format(&ds, "%s,", sorted[i]);
    }

    ds_chomp(&ds, ',');

    free(sorted);
    sset_destroy(&set);

    return ds_steal_cstr(&ds);
}

static void
excluded_tables_clear(void)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, &excluded_tables) {
        struct sset *tables = node->data;
        sset_destroy(tables);
    }

    shash_clear_free_data(&excluded_tables);
}

static void
excluded_tables_add(const char *database, const char *table)
{
    struct sset *tables = shash_find_data(&excluded_tables, database);

    if (!tables) {
        tables = xmalloc(sizeof *tables);
        sset_init(tables);
        shash_add(&excluded_tables, database, tables);
    }

    sset_add(tables, table);
}

static bool
excluded_tables_find(const char *database, const char *table)
{
    struct sset *tables = shash_find_data(&excluded_tables, database);
    return tables && sset_contains(tables, table);
}

void
disconnect_active_server(void)
{
    jsonrpc_session_close(session);
    session = NULL;
}

void
replication_destroy(void)
{
    excluded_tables_clear();
    shash_destroy(&excluded_tables);

    if (sync_from) {
        free(sync_from);
        sync_from = NULL;
    }

    request_ids_destroy();
    replication_dbs_destroy();

    shash_destroy(&local_dbs);
}

static struct replication_db *
find_db(const char *db_name)
{
    return shash_find_data(replication_dbs, db_name);
}

static struct ovsdb_error *
reset_database(struct ovsdb *db)
{
    struct ovsdb_txn *txn = ovsdb_txn_create(db);
    struct shash_node *table_node;

    SHASH_FOR_EACH (table_node, &db->tables) {
        /* Delete all rows if the table is not excluded. */
        if (!excluded_tables_find(db->schema->name, table_node->name)) {
            struct ovsdb_table *table = table_node->data;
            struct ovsdb_row *row, *next;
            HMAP_FOR_EACH_SAFE (row, next, hmap_node, &table->rows) {
                ovsdb_txn_row_delete(txn, row);
            }
        }
    }

    return ovsdb_txn_propose_commit_block(txn, false);
}

/* Create a monitor request for 'db'. The monitor request will include
 * any tables from 'excluded_tables'
 *
 * Caller is responsible for disposing 'request'.
 */
static struct jsonrpc_msg *
create_monitor_request(struct ovsdb_schema *schema)
{
    struct jsonrpc_msg *request;
    struct json *monitor;
    const char *db_name = schema->name;

    struct json *monitor_request = json_object_create();
    size_t n = shash_count(&schema->tables);
    const struct shash_node **nodes = shash_sort(&schema->tables);

    for (int j = 0; j < n; j++) {
        struct ovsdb_table_schema *table = nodes[j]->data;

        /* Monitor all tables not excluded. */
        if (!excluded_tables_find(db_name, table->name)) {
            add_monitored_table(table, monitor_request);
        }
    }
    free(nodes);

    /* Create a monitor request. */
    monitor = json_array_create_3(
        json_string_create(db_name),
        json_string_create(db_name),
        monitor_request);
    request = jsonrpc_create_request("monitor", monitor, NULL);

    return request;
}

static void
add_monitored_table(struct ovsdb_table_schema *table,
                    struct json *monitor_request)
{
    struct json *monitor_request_array;

    monitor_request_array = json_array_create_empty();
    json_array_add(monitor_request_array, json_object_create());

    json_object_put(monitor_request, table->name, monitor_request_array);
}


static struct ovsdb_error *
process_notification(struct json *table_updates, struct ovsdb *db)
{
    struct ovsdb_error *error = NULL;
    struct ovsdb_txn *txn;

    if (table_updates->type == JSON_OBJECT) {
        txn = ovsdb_txn_create(db);

        /* Process each table update. */
        struct shash_node *node;
        SHASH_FOR_EACH (node, json_object(table_updates)) {
            struct json *table_update = node->data;
            if (table_update) {
                error = process_table_update(table_update, node->name, db, txn);
                if (error) {
                    break;
                }
            }
        }

        if (error) {
            ovsdb_txn_abort(txn);
            return error;
        } else {
            /* Commit transaction. */
            error = ovsdb_txn_propose_commit_block(txn, false);
        }
    }

    return error;
}

static struct ovsdb_error *
process_table_update(struct json *table_update, const char *table_name,
                     struct ovsdb *database, struct ovsdb_txn *txn)
{
    struct ovsdb_table *table = ovsdb_get_table(database, table_name);
    if (!table) {
        return ovsdb_error("unknown table", "unknown table %s", table_name);
    }

    if (table_update->type != JSON_OBJECT) {
        return ovsdb_error("Not a JSON object",
                           "<table-update> for table is not object");
    }

    struct shash_node *node;
    SHASH_FOR_EACH (node, json_object(table_update)) {
        struct json *row_update = node->data;
        struct json *old, *new;

        if (row_update->type != JSON_OBJECT) {
            return ovsdb_error("Not a JSON object",
                               "<row-update> is not object");
        }

        struct uuid uuid;
        if (!uuid_from_string(&uuid, node->name)) {
            return ovsdb_syntax_error(table_update, "bad row UUID",
                                      "<table-update> names must be UUIDs");
        }

        old = shash_find_data(json_object(row_update), "old");
        new = shash_find_data(json_object(row_update), "new");

        struct ovsdb_error *error;
        error = (!new ? execute_delete(txn, &uuid, table)
                 : !old ? execute_insert(txn, &uuid, table, new)
                 : execute_update(txn, &uuid, table, new));
        if (error) {
            return error;
        }
    }
    return NULL;
}

static struct ovsdb_error *
execute_insert(struct ovsdb_txn *txn, const struct uuid *row_uuid,
               struct ovsdb_table *table, struct json *json_row)
{
    struct ovsdb_row *row = ovsdb_row_create(table);
    struct ovsdb_error *error = ovsdb_row_from_json(row, json_row, NULL, NULL);
    if (!error) {
        *ovsdb_row_get_uuid_rw(row) = *row_uuid;
        ovsdb_txn_row_insert(txn, row);
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "cannot add existing row "UUID_FMT" to table %s",
                     UUID_ARGS(row_uuid), table->schema->name);
        ovsdb_row_destroy(row);
    }

    return error;
}

static struct ovsdb_error *
execute_delete(struct ovsdb_txn *txn, const struct uuid *row_uuid,
               struct ovsdb_table *table)
{
    const struct ovsdb_row *row = ovsdb_table_get_row(table, row_uuid);
    if (row) {
        ovsdb_txn_row_delete(txn, row);
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "cannot delete missing row "UUID_FMT" from table %s",
                     UUID_ARGS(row_uuid), table->schema->name);
    }
    return NULL;
}

static struct ovsdb_error *
execute_update(struct ovsdb_txn *txn, const struct uuid *row_uuid,
               struct ovsdb_table *table, struct json *json_row)
{
    const struct ovsdb_row *row = ovsdb_table_get_row(table, row_uuid);
    if (!row) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "cannot modify missing row "UUID_FMT" in table %s",
                     UUID_ARGS(row_uuid), table->schema->name);
        return NULL;
    }

    struct ovsdb_column_set columns = OVSDB_COLUMN_SET_INITIALIZER;
    struct ovsdb_row *update = ovsdb_row_create(table);
    struct ovsdb_error *error = ovsdb_row_from_json(update, json_row,
                                                    NULL, &columns);

    if (!error && !ovsdb_row_equal_columns(row, update, &columns)) {
        ovsdb_row_update_columns(ovsdb_txn_row_modify(txn, row),
                                 update, &columns);
    }

    ovsdb_column_set_destroy(&columns);
    ovsdb_row_destroy(update);
    return error;
}

void
request_ids_add(const struct json *id, struct ovsdb *db)
{
    struct request_ids_hmap_node *node = xmalloc(sizeof *node);

    node->request_id = json_clone(id);
    node->db = db;
    hmap_insert(&request_ids, &node->hmap, json_hash(id, 0));
}

/* Look up 'id' from 'request_ids', if found, remove the found id from
 * 'request_ids' and free its memory. If not found, 'request_ids' does
 * not change.  Sets '*db' to the database for the request (NULL if not
 * found).
 *
 * Return true if 'id' is found, false otherwise.
 */
bool
request_ids_lookup_and_free(const struct json *id, struct ovsdb **db)
{
    struct request_ids_hmap_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, hmap, json_hash(id, 0), &request_ids) {
        if (json_equal(id, node->request_id)) {
            hmap_remove(&request_ids, &node->hmap);
            *db = node->db;
            json_destroy(node->request_id);
            free(node);
            return true;
        }
    }

    *db = NULL;
    return false;
}

static void
request_ids_destroy(void)
{
    struct request_ids_hmap_node *node;

    HMAP_FOR_EACH_POP (node, hmap, &request_ids) {
        json_destroy(node->request_id);
        free(node);
    }
    hmap_destroy(&request_ids);
}

void
request_ids_clear(void)
{
    request_ids_destroy();
    hmap_init(&request_ids);
}

static struct shash *
replication_dbs_create(void)
{
    struct shash *new = xmalloc(sizeof *new);
    shash_init(new);

    struct shash_node *node;
    SHASH_FOR_EACH (node, &local_dbs) {
        struct replication_db *repl_db = xmalloc(sizeof *repl_db);
        repl_db->db = node->data;
        repl_db->schema_version_higher = false;
        repl_db->active_db_schema = NULL;
        shash_add(new, node->name, repl_db);
    }

    return new;
}

static void
replication_dbs_destroy(void)
{
    if (!replication_dbs) {
        return;
    }

    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, replication_dbs) {
        hmap_remove(&replication_dbs->map, &node->node);
        struct replication_db *rdb = node->data;
        if (rdb->active_db_schema) {
            ovsdb_schema_destroy(rdb->active_db_schema);
        }
        free(rdb);
        free(node->name);
        free(node);
    }

    hmap_destroy(&replication_dbs->map);
    free(replication_dbs);
    replication_dbs = NULL;
}

/* Return true if replication just started or is ongoing.
 * Return false if the connection failed, or the replication
 * was not able to start. */
bool
replication_is_alive(void)
{
    if (session) {
        return jsonrpc_session_is_alive(session) && state != RPL_S_ERR;
    }
    return false;
}

/* Return the last error reported on a connection by 'session'. The
 * return value is 0 if replication is not currently running, or
 * if replication session has not encountered any error.
 *
 * Return a negative value if replication session has error, or the
 * replication was not able to start.  */
int
replication_get_last_error(void)
{
    int err = 0;

    if (session) {
        err = jsonrpc_session_get_last_error(session);
        if (!err) {
            err = (state == RPL_S_ERR) ? ENOENT : 0;
        }
    }

    return err;
}

char *
replication_status(void)
{
    bool alive = session && jsonrpc_session_is_alive(session);
    struct ds ds = DS_EMPTY_INITIALIZER;

    if (alive) {
        switch(state) {
        case RPL_S_INIT:
        case RPL_S_SERVER_ID_REQUESTED:
        case RPL_S_DB_REQUESTED:
        case RPL_S_SCHEMA_REQUESTED:
        case RPL_S_MONITOR_REQUESTED:
            ds_put_format(&ds, "connecting: %s", sync_from);
            break;
        case RPL_S_REPLICATING: {
            struct shash_node *node;

            ds_put_format(&ds, "replicating: %s\n", sync_from);
            ds_put_cstr(&ds, "database:");
            SHASH_FOR_EACH (node, replication_dbs) {
                ds_put_format(&ds, " %s,", node->name);
            }
            ds_chomp(&ds, ',');

            if (!shash_is_empty(&excluded_tables)) {
                ds_put_char(&ds, '\n');
                ds_put_cstr(&ds, "exclude: ");
                ds_put_and_free_cstr(&ds, get_excluded_tables());
            }
            break;
        }
        case RPL_S_ERR:
            ds_put_format(&ds, "Replication to (%s) failed\n", sync_from);
            break;
        default:
            OVS_NOT_REACHED();
        }
    } else {
        ds_put_format(&ds, "not connected to %s", sync_from);
    }
    return ds_steal_cstr(&ds);
}

/* Checks if it's possible to replicate to the local db from the active db
 * schema.  Returns true, if 'local_db_schema' has all the tables and columns
 * of 'active_db_schema', false otherwise.
 */
static bool
is_replication_possible(struct ovsdb_schema *local_db_schema,
                        struct ovsdb_schema *active_db_schema)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, &active_db_schema->tables) {
        struct ovsdb_table_schema *ldb_table_schema =
            shash_find_data(&local_db_schema->tables, node->name);
        if (!ldb_table_schema) {
            VLOG_INFO("Table %s not present in the local db schema",
                      node->name);
            return false;
        }

        /* Local schema table should have all the columns
         * of active schema table. */
        struct ovsdb_table_schema *adb_table_schema = node->data;
        struct shash_node *n;
        SHASH_FOR_EACH (n, &adb_table_schema->columns) {
            struct ovsdb_column *ldb_col =
                shash_find_data(&ldb_table_schema->columns, n->name);
            if (!ldb_col) {
                VLOG_INFO("Column %s not present in the local "
                          "db schema table %s.", n->name, node->name);
                return false;
            }

            struct json *ldb_col_json = ovsdb_column_to_json(ldb_col);
            struct json *adb_col_json = ovsdb_column_to_json(n->data);
            bool cols_equal = json_equal(ldb_col_json, adb_col_json);
            json_destroy(ldb_col_json);
            json_destroy(adb_col_json);

            if (!cols_equal) {
                VLOG_INFO("Column %s mismatch in local "
                          "db schema table %s.", n->name, node->name);
                return false;
            }
        }
    }

    return true;
}

void
replication_set_probe_interval(int probe_interval)
{
    if (session) {
        jsonrpc_session_set_probe_interval(session, probe_interval);
    }
}

void
replication_usage(void)
{
    printf("\n\
Syncing options:\n\
  --sync-from=SERVER      sync DATABASE from active SERVER and start in\n\
                          backup mode (except with --active)\n\
  --sync-exclude-tables=DB:TABLE,...\n\
                          exclude the TABLE in DB from syncing\n\
  --active                with --sync-from, start in active mode\n");
}
