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

static struct uuid server_uuid;

static struct ovsdb_error *process_notification(const struct json *,
                                                struct ovsdb *);
static struct ovsdb_error *process_table_update(
    const struct json *table_update, const char *table_name,
    struct ovsdb *database, struct ovsdb_txn *txn);

enum ovsdb_replication_state {
    RPL_S_INIT,
    RPL_S_SERVER_ID_REQUESTED,
    RPL_S_DB_REQUESTED,
    RPL_S_SCHEMA_REQUESTED,
    RPL_S_MONITOR_REQUESTED,
    RPL_S_REPLICATING,
    RPL_S_ERR /* Error, no longer replicating. */
};

struct replication_db {
    struct ovsdb *db;

    bool schema_version_higher;
     /* Points to the schema received from the active server if
      * the local db schema version is higher. NULL otherwise. */
    struct ovsdb_schema *active_db_schema;

    char *sync_from;
    char *excluded_tables_str;
    struct sset excluded_tables;

    struct json *request_id;  /* Id of the outstanding OVSDB request. */

    struct jsonrpc_session *session;
    unsigned int session_seqno;

    enum ovsdb_replication_state state;
};

static bool is_replication_possible(struct ovsdb_schema *local_db_schema,
                                    struct ovsdb_schema *active_db_schema);

static struct jsonrpc_msg *create_monitor_request(struct replication_db *,
                                                  struct ovsdb_schema *);
static void add_monitored_table(struct ovsdb_table_schema *table,
                                struct json *monitor_requests);


/* All DBs known to ovsdb-server.  The actual replication dbs are stored
 * in 'replication dbs', which is a subset of all dbs and remote dbs whose
 * schema matches.  */
static struct shash replication_dbs = SHASH_INITIALIZER(&replication_dbs);

static void replication_db_destroy(struct replication_db *);
static struct ovsdb_error *reset_database(struct replication_db *);

/* Find 'struct ovsdb' by name within 'replication_dbs' */
static struct replication_db *find_db(const char *db_name);

static char *set_excluded_tables(struct replication_db *, const char *excluded)
    OVS_WARN_UNUSED_RESULT;

static void request_id_set(struct replication_db *, const struct json *id);
static void request_id_clear(struct replication_db *);
static bool request_id_compare_and_free(struct replication_db *,
                                        const struct json *id);


void
replication_set_db(struct ovsdb *db, const char *sync_from,
                   const char *exclude_tables, const struct uuid *server,
                   const struct jsonrpc_session_options *options)
{
    struct replication_db *rdb = find_db(db->name);

    if (uuid_is_zero(&server_uuid)) {
        /* Keep a copy of local server uuid.  */
        server_uuid = *server;
    } else {
        ovs_assert(uuid_equals(&server_uuid, server));
    }

    ovs_assert(sync_from);

    if (rdb
        && nullable_string_is_equal(rdb->excluded_tables_str, exclude_tables)
        && nullable_string_is_equal(rdb->sync_from, sync_from)) {
        jsonrpc_session_set_options(rdb->session, options);
        return;
    }

    if (!rdb) {
        rdb = xzalloc(sizeof *rdb);
        rdb->db = db;
        sset_init(&rdb->excluded_tables);
        rdb->schema_version_higher = false;
        shash_add(&replication_dbs, db->name, rdb);
    } else {
        replication_db_destroy(rdb);
    }

    rdb->sync_from = xstrdup(sync_from);
    rdb->excluded_tables_str = nullable_xstrdup(exclude_tables);
    /* Caller should have verified that the 'exclude_tables' is
     * parseable. An error here is unexpected. */
    ovs_assert(!set_excluded_tables(rdb, exclude_tables));

    rdb->session = jsonrpc_session_open(rdb->sync_from, true);
    rdb->session_seqno = UINT_MAX;

    jsonrpc_session_set_options(rdb->session, options);

    rdb->state = RPL_S_INIT;
    rdb->db->read_only = true;
}

void
replication_remove_db(const struct ovsdb *db)
{
    struct replication_db *rdb;

    rdb = shash_find_and_delete(&replication_dbs, db->name);
    if (rdb) {
        replication_db_destroy(rdb);
        free(rdb);
    }
}

static void
send_schema_request(struct replication_db *rdb)
{
    struct jsonrpc_msg *request =
        jsonrpc_create_request(
                "get_schema",
                json_array_create_1(json_string_create(rdb->db->name)),
                NULL);

    request_id_set(rdb, request->id);
    jsonrpc_session_send(rdb->session, request);
}

static void
replication_run_db(struct replication_db *rdb)
{
    if (!rdb->session) {
        return;
    }

    jsonrpc_session_run(rdb->session);

    for (int i = 0; i < 50; i++) {
        struct jsonrpc_msg *msg;
        unsigned int seqno;

        if (!jsonrpc_session_is_connected(rdb->session)) {
            break;
        }

        seqno = jsonrpc_session_get_seqno(rdb->session);
        if (seqno != rdb->session_seqno || rdb->state == RPL_S_INIT) {
            rdb->session_seqno = seqno;
            request_id_clear(rdb);

            struct jsonrpc_msg *request;
            request = jsonrpc_create_request("get_server_id",
                                             json_array_create_empty(), NULL);
            request_id_set(rdb, request->id);
            jsonrpc_session_send(rdb->session, request);

            rdb->state = RPL_S_SERVER_ID_REQUESTED;
            VLOG_DBG("%s: send server ID request.", rdb->db->name);
        }

        msg = jsonrpc_session_recv(rdb->session);
        if (!msg) {
            continue;
        }

        if (msg->type == JSONRPC_NOTIFY && rdb->state != RPL_S_ERR
            && !strcmp(msg->method, "update")) {
            if (msg->params->type == JSON_ARRAY
                && json_array_size(msg->params) == 2
                && json_array_at(msg->params, 0)->type == JSON_STRING) {
                const char *db_name = json_string(
                                        json_array_at(msg->params, 0));

                if (!strcmp(db_name, rdb->db->name)) {
                    struct ovsdb_error *error;
                    error = process_notification(json_array_at(msg->params, 1),
                                                 rdb->db);
                    if (error) {
                        ovsdb_error_assert(error);
                        rdb->state = RPL_S_ERR;
                    }
                } else {
                    VLOG_WARN("%s: received update for unexpected database %s",
                              rdb->db->name, db_name);
                    rdb->state = RPL_S_ERR;
                }
            }
        } else if (msg->type == JSONRPC_REPLY) {
            if (!request_id_compare_and_free(rdb, msg->id)) {
                VLOG_WARN("%s: received unexpected reply.", rdb->db->name);
                goto next;
            }

            switch (rdb->state) {
            case RPL_S_SERVER_ID_REQUESTED: {
                struct uuid uuid;
                if (msg->result->type != JSON_STRING ||
                    !uuid_from_string(&uuid, json_string(msg->result))) {
                    struct ovsdb_error *error;
                    error = ovsdb_error("get_server_id failed",
                                        "%s: Server ID is not valid UUID",
                                        rdb->db->name);

                    ovsdb_error_assert(error);
                    rdb->state = RPL_S_ERR;
                    break;
                }

                if (uuid_equals(&uuid, &server_uuid)) {
                    struct ovsdb_error *error;
                    error = ovsdb_error("Server ID check failed",
                                        "%s: Self replicating is not allowed",
                                        rdb->db->name);

                    ovsdb_error_assert(error);
                    rdb->state = RPL_S_ERR;
                    break;
                }

                struct jsonrpc_msg *request;
                request = jsonrpc_create_request("list_dbs",
                                                 json_array_create_empty(),
                                                 NULL);
                request_id_set(rdb, request->id);
                jsonrpc_session_send(rdb->session, request);

                rdb->state = RPL_S_DB_REQUESTED;
                break;
            }
            case RPL_S_DB_REQUESTED:
                if (msg->result->type != JSON_ARRAY) {
                    struct ovsdb_error *error;
                    error = ovsdb_error("list_dbs failed",
                                        "%s: list_dbs response is not array",
                                        rdb->db->name);
                    ovsdb_error_assert(error);
                    rdb->state = RPL_S_ERR;
                } else if (!json_array_contains_string(msg->result,
                                                       rdb->db->name)) {
                    struct ovsdb_error *error;
                    error = ovsdb_error("list_dbs failed",
                                        "%s: database name is not in the list",
                                        rdb->db->name);
                    ovsdb_error_assert(error);
                    rdb->state = RPL_S_ERR;
                } else {
                    send_schema_request(rdb);
                    VLOG_DBG("%s: send schema request.", rdb->db->name);
                    rdb->state = RPL_S_SCHEMA_REQUESTED;
                }
                break;

            case RPL_S_SCHEMA_REQUESTED: {
                struct ovsdb_schema *schema;
                struct ovsdb_error *error;

                error = ovsdb_schema_from_json(msg->result, &schema);
                if (error) {
                    ovsdb_error_assert(error);
                    rdb->state = RPL_S_ERR;
                    break;
                }

                if (strcmp(rdb->db->name, schema->name)) {
                    /* Unexpected schema. */
                    VLOG_WARN("%s: unexpected schema %s.",
                              rdb->db->name, schema->name);
                    rdb->state = RPL_S_ERR;
                    ovsdb_schema_destroy(schema);
                    break;
                } else if (!ovsdb_schema_equal(schema, rdb->db->schema)) {
                    /* Schmea version mismatch. */
                    VLOG_INFO("%s: Schema version mismatch, checking if %s can"
                              " still be replicated or not.",
                              rdb->db->name, schema->name);
                    if (is_replication_possible(rdb->db->schema, schema)) {
                        VLOG_INFO("%s can be replicated.", schema->name);
                        rdb->schema_version_higher = true;
                        if (rdb->active_db_schema) {
                            ovsdb_schema_destroy(rdb->active_db_schema);
                        }
                        rdb->active_db_schema = schema;
                    } else {
                        VLOG_INFO("%s cannot be replicated.", schema->name);
                        rdb->state = RPL_S_ERR;
                        ovsdb_schema_destroy(schema);
                        break;
                    }
                } else {
                    ovsdb_schema_destroy(schema);
                }

                /* Send out a monitor request. */
                struct jsonrpc_msg *request =
                    create_monitor_request(rdb, rdb->schema_version_higher
                                                ? rdb->active_db_schema
                                                : rdb->db->schema);

                request_id_set(rdb, request->id);
                jsonrpc_session_send(rdb->session, request);
                VLOG_DBG("%s: send monitor request.", rdb->db->name);
                rdb->state = RPL_S_MONITOR_REQUESTED;
                break;
            }

            case RPL_S_MONITOR_REQUESTED: {
                /* Reply to monitor requests. */
                struct ovsdb_error *error;
                VLOG_INFO("%s: Monitor reply received. "
                          "Resetting the database.", rdb->db->name);
                /* Resetting the database here has few risks. If the
                 * process_notification() fails, the database is completely
                 * lost locally. In case that node becomes active, then
                 * there is a chance of complete data loss in the active/standy
                 * cluster. */
                error = reset_database(rdb);
                if (!error) {
                    error = process_notification(msg->result, rdb->db);
                }
                if (error) {
                    ovsdb_error_assert(error);
                    rdb->state = RPL_S_ERR;
                } else {
                    VLOG_DBG("%s: Listening to monitor updates.",
                             rdb->db->name);
                    rdb->state = RPL_S_REPLICATING;
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
replication_run(void)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &replication_dbs) {
        replication_run_db(node->data);
    }
}

void
replication_wait(void)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &replication_dbs) {
        struct replication_db *rdb = node->data;

        if (rdb->session) {
            jsonrpc_session_wait(rdb->session);
            jsonrpc_session_recv_wait(rdb->session);
        }
    }
}

/* Parse 'excluded' to rebuild 'rdb->excluded_tables'.  If 'rdb' is not NULL,
 * the current set of excluded tables will be wiped out, regardless of whether
 * 'excluded' can be parsed.  If 'rdb' is NULL, only parses 'excluded' and
 * reports any errors, without modifying the list of exclusions.
 *
 * On error, returns the error string, which the caller is responsible for
 * freeing.  Returns NULL otherwise. */
static char * OVS_WARN_UNUSED_RESULT
set_excluded_tables__(struct replication_db *rdb, const char *excluded)
{
    struct sset set = SSET_INITIALIZER(&set);
    char *err = NULL;

    if (excluded) {
        const char *longname;

        if (rdb) {
            /* Can only add to an empty set. */
            sset_clear(&rdb->excluded_tables);
        }

        sset_from_delimited_string(&set, excluded, " ,");
        SSET_FOR_EACH (longname, &set) {
            if (rdb && !strchr(longname, ':')) {
                sset_add(&rdb->excluded_tables, longname);
                continue;
            }

            char *database = xstrdup(longname), *table = NULL;
            strtok_r(database, ":", &table);
            if (table && rdb && !strcmp(rdb->db->name, database)) {
                sset_add(&rdb->excluded_tables, table);
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
    if (err && rdb) {
        /* On error, destroy the partially built 'excluded_tables'. */
        sset_clear(&rdb->excluded_tables);
    }
    return err;
}

char * OVS_WARN_UNUSED_RESULT
parse_excluded_tables(const char *excluded)
{
    return set_excluded_tables__(NULL, excluded);
}

static char * OVS_WARN_UNUSED_RESULT
set_excluded_tables(struct replication_db *rdb, const char *excluded)
{
    return set_excluded_tables__(rdb, excluded);
}

char * OVS_WARN_UNUSED_RESULT
get_excluded_tables(const struct ovsdb *db)
{
    const struct replication_db *rdb = find_db(db->name);

    if (!rdb) {
        return xstrdup("");
    }

    struct sset set = SSET_INITIALIZER(&set);
    const char *table;
    char *result;

    SSET_FOR_EACH (table, &rdb->excluded_tables) {
        sset_add_and_free(&set, xasprintf("%s:%s", rdb->db->name, table));
    }

    result = sset_join(&set, ",", "");
    sset_destroy(&set);

    return result;
}

void
replication_destroy(void)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &replication_dbs) {
        replication_db_destroy(node->data);
    }
    shash_destroy_free_data(&replication_dbs);
}

static struct replication_db *
find_db(const char *db_name)
{
    return shash_find_data(&replication_dbs, db_name);
}

static struct ovsdb_error *
reset_database(struct replication_db *rdb)
{
    struct ovsdb_txn *txn = ovsdb_txn_create(rdb->db);
    struct shash_node *table_node;

    SHASH_FOR_EACH (table_node, &rdb->db->tables) {
        /* Delete all rows if the table is not excluded. */
        if (!sset_contains(&rdb->excluded_tables, table_node->name)) {
            struct ovsdb_table *table = table_node->data;
            struct ovsdb_row *row;
            HMAP_FOR_EACH_SAFE (row, hmap_node, &table->rows) {
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
create_monitor_request(struct replication_db *rdb, struct ovsdb_schema *schema)
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
        if (!sset_contains(&rdb->excluded_tables, table->name)) {
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
process_notification(const struct json *table_updates, struct ovsdb *db)
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
process_table_update(const struct json *table_update, const char *table_name,
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
        error = (!new ? ovsdb_table_execute_delete(txn, &uuid, table)
                 : !old ? ovsdb_table_execute_insert(txn, &uuid, table, new)
                 : ovsdb_table_execute_update(txn, &uuid, table, new, false));
        if (error) {
            if (!strcmp(ovsdb_error_get_tag(error), "consistency violation")) {
                ovsdb_error_assert(error);
                error = NULL;
            }
            return error;
        }
    }
    return NULL;
}

static void
request_id_set(struct replication_db *rdb, const struct json *id)
{
    ovs_assert(!rdb->request_id);
    rdb->request_id = json_clone(id);
}

static void
request_id_clear(struct replication_db *rdb)
{
    json_destroy(rdb->request_id);
    rdb->request_id = NULL;
}

/* Compare 'id' with sent 'request_id'.  If it matches, clear the current
 * 'request_id'.  If it doesn't match, 'request_id' does not change.
 *
 * Return true if 'id' matches, false otherwise.
 */
static bool
request_id_compare_and_free(struct replication_db *rdb, const struct json *id)
{
    if (rdb->request_id && json_equal(id, rdb->request_id)) {
        request_id_clear(rdb);
        return true;
    }
    return false;
}

static void
replication_db_destroy(struct replication_db *rdb)
{
    if (!rdb) {
        return;
    }

    free(rdb->sync_from);
    rdb->sync_from = NULL;

    free(rdb->excluded_tables_str);
    rdb->excluded_tables_str = NULL;
    sset_destroy(&rdb->excluded_tables);

    request_id_clear(rdb);

    if (rdb->session) {
        jsonrpc_session_close(rdb->session);
        rdb->session = NULL;
    }

    if (rdb->active_db_schema) {
        ovsdb_schema_destroy(rdb->active_db_schema);
        rdb->active_db_schema = NULL;
    }

    rdb->schema_version_higher = false;
    rdb->db->read_only = false;
}

/* Return true if replication just started or is ongoing.
 * Return false if the connection failed, or the replication
 * was not able to start. */
bool
replication_is_alive(const struct ovsdb *db)
{
    const struct replication_db *rdb = find_db(db->name);

    if (!rdb || !rdb->session) {
        return false;
    }
    return jsonrpc_session_is_alive(rdb->session) && rdb->state != RPL_S_ERR;
}

/* Return the last error reported on a connection by 'session'. The
 * return value is 0 if replication is not currently running, or
 * if replication session has not encountered any error.
 *
 * Return a negative value if replication session has error, or the
 * replication was not able to start.  */
int
replication_get_last_error(const struct ovsdb *db)
{
    const struct replication_db *rdb = find_db(db->name);
    int err = 0;

    if (rdb && rdb->session) {
        err = jsonrpc_session_get_last_error(rdb->session);
        if (!err) {
            err = (rdb->state == RPL_S_ERR) ? ENOENT : 0;
        }
    }

    return err;
}

char * OVS_WARN_UNUSED_RESULT
replication_status(const struct ovsdb *db)
{
    const struct replication_db *rdb = find_db(db->name);

    if (!rdb) {
        return xasprintf("%s is not configured for replication", db->name);
    }

    bool alive = rdb->session && jsonrpc_session_is_alive(rdb->session);
    struct ds ds = DS_EMPTY_INITIALIZER;

    if (alive) {
        switch (rdb->state) {
        case RPL_S_INIT:
        case RPL_S_SERVER_ID_REQUESTED:
        case RPL_S_DB_REQUESTED:
        case RPL_S_SCHEMA_REQUESTED:
        case RPL_S_MONITOR_REQUESTED:
            ds_put_format(&ds, "connecting: %s", rdb->sync_from);
            break;
        case RPL_S_REPLICATING: {
            ds_put_format(&ds, "replicating: %s\n", rdb->sync_from);

            if (!sset_is_empty(&rdb->excluded_tables)) {
                ds_put_cstr(&ds, "exclude: ");
                ds_put_and_free_cstr(&ds, get_excluded_tables(db));
            }
            break;
        }
        case RPL_S_ERR:
            ds_put_format(&ds, "Replication to (%s) failed", rdb->sync_from);
            break;
        default:
            OVS_NOT_REACHED();
        }
    } else {
        ds_put_format(&ds, "not connected to %s", rdb->sync_from);
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
replication_set_probe_interval(const struct ovsdb *db, int probe_interval)
{
    const struct replication_db *rdb = find_db(db->name);

    if (rdb && rdb->session) {
        jsonrpc_session_set_probe_interval(rdb->session, probe_interval);
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
