/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2017 Nicira, Inc.
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

#include "ovsdb.h"

#if HAVE_DECL_MALLOC_TRIM
#include <malloc.h>
#endif

#include "column.h"
#include "file.h"
#include "monitor.h"
#include "openvswitch/json.h"
#include "openvswitch/poll-loop.h"
#include "ovs-thread.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb-types.h"
#include "row.h"
#include "seq.h"
#include "simap.h"
#include "storage.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "transaction-forward.h"
#include "trigger.h"
#include "unixctl.h"

#include "openvswitch/vlog.h"
VLOG_DEFINE_THIS_MODULE(ovsdb);

size_t n_weak_refs = 0;

struct ovsdb_schema *
ovsdb_schema_create(const char *name, const char *version, const char *cksum)
{
    struct ovsdb_schema *schema;

    schema = xzalloc(sizeof *schema);
    schema->name = xstrdup(name);
    schema->version = xstrdup(version);
    schema->cksum = xstrdup(cksum);
    shash_init(&schema->tables);

    return schema;
}

struct ovsdb_schema *
ovsdb_schema_clone(const struct ovsdb_schema *old)
{
    struct ovsdb_schema *new;
    struct shash_node *node;

    new = ovsdb_schema_create(old->name, old->version, old->cksum);
    SHASH_FOR_EACH (node, &old->tables) {
        const struct ovsdb_table_schema *ts = node->data;

        shash_add(&new->tables, node->name, ovsdb_table_schema_clone(ts));
    }
    return new;
}

void
ovsdb_schema_destroy(struct ovsdb_schema *schema)
{
    struct shash_node *node;

    if (!schema) {
        return;
    }

    SHASH_FOR_EACH (node, &schema->tables) {
        ovsdb_table_schema_destroy(node->data);
    }
    shash_destroy(&schema->tables);
    free(schema->name);
    free(schema->version);
    free(schema->cksum);
    free(schema);
}

struct ovsdb_error *
ovsdb_schema_from_file(const char *file_name, struct ovsdb_schema **schemap)
{
    struct ovsdb_schema *schema;
    struct ovsdb_error *error;
    struct json *json;

    *schemap = NULL;
    json = json_from_file(file_name);
    if (json->type == JSON_STRING) {
        error = ovsdb_error("failed to read schema",
                           "\"%s\" could not be read as JSON (%s)",
                           file_name, json_string(json));
        json_destroy(json);
        return error;
    }

    error = ovsdb_schema_from_json(json, &schema);
    json_destroy(json);
    if (error) {
        return ovsdb_wrap_error(error,
                                "failed to parse \"%s\" as ovsdb schema",
                                file_name);
    }

    *schemap = schema;
    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_schema_check_ref_table(struct ovsdb_column *column,
                             const struct shash *tables,
                             const struct ovsdb_base_type *base,
                             const char *base_name)
{
    struct ovsdb_table_schema *refTable;

    if (base->type != OVSDB_TYPE_UUID || !base->uuid.refTableName) {
        return NULL;
    }

    refTable = shash_find_data(tables, base->uuid.refTableName);
    if (!refTable) {
        return ovsdb_syntax_error(NULL, NULL,
                                  "column %s %s refers to undefined table %s",
                                  column->name, base_name,
                                  base->uuid.refTableName);
    }

    if (ovsdb_base_type_is_strong_ref(base) && !refTable->is_root) {
        /* We cannot allow a strong reference to a non-root table to be
         * ephemeral: if it is the only reference to a row, then replaying the
         * database log from disk will cause the referenced row to be deleted,
         * even though it did exist in memory.  If there are references to that
         * row later in the log (to modify it, to delete it, or just to point
         * to it), then this will yield a transaction error. */
        column->persistent = true;
    }

    return NULL;
}

/* Attempts to parse 's' as a version string in the format "<x>.<y>.<z>".  If
 * successful, stores each part of the version into 'version->x', 'version->y',
 * and 'version->z', respectively, and returns true.  On failure, returns
 * false. */
bool
ovsdb_parse_version(const char *s, struct ovsdb_version *version)
{
    int n = -1;
    return (ovs_scan(s, "%u.%u.%u%n", &version->x, &version->y, &version->z,
                     &n)
            && n != -1 && s[n] == '\0');
}

/* Returns true if 's' is a version string in the format "<x>.<y>.<z>",
 * otherwie false. */
bool
ovsdb_is_valid_version(const char *s)
{
    struct ovsdb_version version;
    return ovsdb_parse_version(s, &version);
}

/* If set to 'true', database schema conversion operations in the storage
 * may not contain the converted data, only the schema.  Currently affects
 * only the clustered storage. */
static bool use_no_data_conversion = true;

static void
ovsdb_no_data_conversion_enable(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                const char *argv[] OVS_UNUSED,
                                void *arg OVS_UNUSED)
{
    use_no_data_conversion = true;
    unixctl_command_reply(conn, NULL);
}

void
ovsdb_no_data_conversion_disable(void)
{
    if (!use_no_data_conversion) {
        return;
    }
    use_no_data_conversion = false;
    unixctl_command_register("ovsdb/file/no-data-conversion-enable", "",
                             0, 0, ovsdb_no_data_conversion_enable, NULL);
}

/* Returns true if the database storage allows conversion records without
 * data specified. */
bool
ovsdb_conversion_with_no_data_supported(const struct ovsdb *db)
{
    return use_no_data_conversion && ovsdb_storage_is_clustered(db->storage);
}

/* Returns the number of tables in 'schema''s root set. */
static size_t
root_set_size(const struct ovsdb_schema *schema)
{
    struct shash_node *node;
    size_t n_root = 0;

    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;

        n_root += table->is_root;
    }
    return n_root;
}

struct ovsdb_error *
ovsdb_schema_from_json(const struct json *json, struct ovsdb_schema **schemap)
{
    struct ovsdb_schema *schema;
    const struct json *name, *tables, *version_json, *cksum;
    struct ovsdb_error *error;
    struct shash_node *node;
    struct ovsdb_parser parser;
    const char *version;

    *schemap = NULL;

    ovsdb_parser_init(&parser, json, "database schema");
    name = ovsdb_parser_member(&parser, "name", OP_ID);
    version_json = ovsdb_parser_member(&parser, "version",
                                       OP_STRING | OP_OPTIONAL);
    cksum = ovsdb_parser_member(&parser, "cksum", OP_STRING | OP_OPTIONAL);
    tables = ovsdb_parser_member(&parser, "tables", OP_OBJECT);
    error = ovsdb_parser_finish(&parser);
    if (error) {
        return error;
    }

    if (version_json) {
        version = json_string(version_json);
        if (!ovsdb_is_valid_version(version)) {
            return ovsdb_syntax_error(json, NULL, "schema version \"%s\" not "
                                      "in format x.y.z", version);
        }
    } else {
        /* Backward compatibility with old databases. */
        version = "";
    }

    schema = ovsdb_schema_create(json_string(name), version,
                                 cksum ? json_string(cksum) : "");
    SHASH_FOR_EACH (node, json_object(tables)) {
        struct ovsdb_table_schema *table;

        if (node->name[0] == '_') {
            error = ovsdb_syntax_error(json, NULL, "names beginning with "
                                       "\"_\" are reserved");
        } else if (!ovsdb_parser_is_id(node->name)) {
            error = ovsdb_syntax_error(json, NULL, "name must be a valid id");
        } else {
            error = ovsdb_table_schema_from_json(node->data, node->name,
                                                 &table);
        }
        if (error) {
            ovsdb_schema_destroy(schema);
            return error;
        }

        shash_add(&schema->tables, table->name, table);
    }

    /* "isRoot" was not part of the original schema definition.  Before it was
     * added, there was no support for garbage collection.  So, for backward
     * compatibility, if the root set is empty then assume that every table is
     * in the root set. */
    if (root_set_size(schema) == 0) {
        SHASH_FOR_EACH (node, &schema->tables) {
            struct ovsdb_table_schema *table = node->data;

            table->is_root = true;
        }
    }

    /* Validate that all refTables refer to the names of tables that exist.
     *
     * Also force certain columns to be persistent, as explained in
     * ovsdb_schema_check_ref_table().  This requires 'is_root' to be known, so
     * this must follow the loop updating 'is_root' above. */
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;
        struct shash_node *node2;

        SHASH_FOR_EACH (node2, &table->columns) {
            struct ovsdb_column *column = node2->data;

            error = ovsdb_schema_check_ref_table(column, &schema->tables,
                                                 &column->type.key, "key");
            if (!error) {
                error = ovsdb_schema_check_ref_table(column, &schema->tables,
                                                     &column->type.value,
                                                     "value");
            }
            if (error) {
                ovsdb_schema_destroy(schema);
                return error;
            }
        }
    }

    *schemap = schema;
    return NULL;
}

struct json *
ovsdb_schema_to_json(const struct ovsdb_schema *schema)
{
    struct json *json, *tables;
    struct shash_node *node;
    bool default_is_root;

    json = json_object_create();
    json_object_put_string(json, "name", schema->name);
    if (schema->version[0]) {
        json_object_put_string(json, "version", schema->version);
    }
    if (schema->cksum[0]) {
        json_object_put_string(json, "cksum", schema->cksum);
    }

    /* "isRoot" was not part of the original schema definition.  Before it was
     * added, there was no support for garbage collection.  So, for backward
     * compatibility, if every table is in the root set then do not output
     * "isRoot" in table schemas. */
    default_is_root = root_set_size(schema) == shash_count(&schema->tables);

    tables = json_object_create();

    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;
        json_object_put(tables, table->name,
                        ovsdb_table_schema_to_json(table, default_is_root));
    }
    json_object_put(json, "tables", tables);

    return json;
}

/* Returns true if 'a' and 'b' specify equivalent schemas, false if they
 * differ. */
bool
ovsdb_schema_equal(const struct ovsdb_schema *a,
                   const struct ovsdb_schema *b)
{
    /* This implementation is simple, stupid, and slow, but I doubt that it
     * will ever require much maintenance. */
    struct json *ja = ovsdb_schema_to_json(a);
    struct json *jb = ovsdb_schema_to_json(b);
    bool equals = json_equal(ja, jb);
    json_destroy(ja);
    json_destroy(jb);

    return equals;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_schema_check_for_ephemeral_columns(const struct ovsdb_schema *schema)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;
        struct shash_node *node2;

        SHASH_FOR_EACH (node2, &table->columns) {
            struct ovsdb_column *column = node2->data;

            if (column->index >= OVSDB_N_STD_COLUMNS && !column->persistent) {
                return ovsdb_syntax_error(
                    NULL, NULL, "Table %s column %s is ephemeral but "
                    "clustered databases do not support ephemeral columns.",
                    table->name, column->name);
            }
        }
    }
    return NULL;
}

void
ovsdb_schema_persist_ephemeral_columns(struct ovsdb_schema *schema,
                                       const char *filename)
{
    int n = 0;
    const char *example_table = NULL;
    const char *example_column = NULL;

    struct shash_node *node;
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;
        struct shash_node *node2;

        SHASH_FOR_EACH (node2, &table->columns) {
            struct ovsdb_column *column = node2->data;

            if (column->index >= OVSDB_N_STD_COLUMNS && !column->persistent) {
                column->persistent = true;
                example_table = table->name;
                example_column = column->name;
                n++;
            }
        }
    }

    if (n) {
        VLOG_WARN("%s: changed %d columns in '%s' database from ephemeral to "
                  "persistent, including '%s' column in '%s' table, because "
                  "clusters do not support ephemeral columns",
                  filename, n, schema->name, example_column, example_table);
    }
}

static void
ovsdb_set_ref_table(const struct shash *tables,
                    struct ovsdb_base_type *base)
{
    if (base->type == OVSDB_TYPE_UUID && base->uuid.refTableName) {
        struct ovsdb_table *table;

        table = shash_find_data(tables, base->uuid.refTableName);
        base->uuid.refTable = table;
    }
}

/* Creates and returns a new ovsdb based on 'schema' and 'storage' and takes
 * ownership of both.
 *
 * At least one of the arguments must be nonnull. */
struct ovsdb *
ovsdb_create(struct ovsdb_schema *schema, struct ovsdb_storage *storage)
{
    struct shash_node *node;
    struct ovsdb *db;

    db = xzalloc(sizeof *db);
    db->name = xstrdup(schema
                       ? schema->name
                       : ovsdb_storage_get_name(storage));
    db->schema = schema;
    db->storage = storage;
    ovs_list_init(&db->monitors);
    ovs_list_init(&db->triggers);
    db->run_triggers_now = db->run_triggers = false;

    db->n_atoms = 0;

    db->is_relay = false;
    ovs_list_init(&db->txn_forward_new);
    hmap_init(&db->txn_forward_sent);

    shash_init(&db->tables);
    if (schema) {
        SHASH_FOR_EACH (node, &schema->tables) {
            struct ovsdb_table_schema *ts = node->data;
            shash_add(&db->tables, node->name, ovsdb_table_create(ts));
        }

        /* Set all the refTables. */
        SHASH_FOR_EACH (node, &schema->tables) {
            struct ovsdb_table_schema *table = node->data;
            struct shash_node *node2;

            SHASH_FOR_EACH (node2, &table->columns) {
                struct ovsdb_column *column = node2->data;

                ovsdb_set_ref_table(&db->tables, &column->type.key);
                ovsdb_set_ref_table(&db->tables, &column->type.value);
            }
        }
    }

    /* Use RBAC roles table if present. */
    db->rbac_role = ovsdb_get_table(db, "RBAC_Role");

    return db;
}

void
ovsdb_destroy(struct ovsdb *db)
{
    if (db) {
        struct shash_node *node;

        /* Need to wait for compaction thread to finish the work. */
        while (ovsdb_snapshot_in_progress(db)) {
            ovsdb_snapshot_wait(db);
            poll_block();
        }
        if (ovsdb_snapshot_ready(db)) {
            struct ovsdb_error *error = ovsdb_snapshot(db, false);

            if (error) {
                char *s = ovsdb_error_to_string_free(error);
                VLOG_INFO("%s: %s", db->name, s);
                free(s);
            }
        }

        /* Close the log. */
        ovsdb_storage_close(db->storage);

        /* Remove all the monitors. */
        ovsdb_monitors_remove(db);

        /* Destroy txn history. */
        ovsdb_txn_history_destroy(db);

        /* Cancell all the forwarded transactions.  There should not be
         * any as all triggers should be already cancelled. */
        ovsdb_txn_forward_cancel_all(db, false);
        ovs_assert(hmap_is_empty(&db->txn_forward_sent));
        hmap_destroy(&db->txn_forward_sent);

        /* The caller must ensure that no triggers remain. */
        ovs_assert(ovs_list_is_empty(&db->triggers));

        /* Delete all the tables.  This also deletes their schemas. */
        SHASH_FOR_EACH (node, &db->tables) {
            struct ovsdb_table *table = node->data;
            ovsdb_table_destroy(table);
        }
        shash_destroy(&db->tables);

        /* The schemas, but not the table that points to them, were deleted in
         * the previous step, so we need to clear out the table.  We can't
         * destroy the table, because ovsdb_schema_destroy() will do that. */
        if (db->schema) {
            shash_clear(&db->schema->tables);
            ovsdb_schema_destroy(db->schema);
        }

        free(db->name);
        free(db);
    }
}

/* Adds some memory usage statistics for 'db' into 'usage', for use with
 * memory_report(). */
void
ovsdb_get_memory_usage(const struct ovsdb *db, struct simap *usage)
{
    if (!db->schema) {
        return;
    }

    const struct shash_node *node;
    unsigned int cells = 0;

    SHASH_FOR_EACH (node, &db->tables) {
        const struct ovsdb_table *table = node->data;
        unsigned int n_columns = shash_count(&table->schema->columns);
        unsigned int n_rows = hmap_count(&table->rows);

        cells += n_rows * n_columns;
    }

    simap_increase(usage, "cells", cells);
    simap_increase(usage, "atoms", db->n_atoms);
    simap_increase(usage, "txn-history", db->n_txn_history);
    simap_increase(usage, "txn-history-atoms", db->n_txn_history_atoms);

    if (db->storage) {
        ovsdb_storage_get_memory_usage(db->storage, usage);
    }

    simap_put(usage, "n-weak-refs", n_weak_refs);
}

struct ovsdb_table *
ovsdb_get_table(const struct ovsdb *db, const char *name)
{
    return shash_find_data(&db->tables, name);
}

static struct ovsdb *
ovsdb_clone_data(const struct ovsdb *db)
{
    struct ovsdb *new = ovsdb_create(ovsdb_schema_clone(db->schema), NULL);

    struct shash_node *node;
    SHASH_FOR_EACH (node, &db->tables) {
        struct ovsdb_table *table = node->data;
        struct ovsdb_table *new_table = shash_find_data(&new->tables,
                                                        node->name);
        struct ovsdb_row *row, *new_row;

        hmap_reserve(&new_table->rows, hmap_count(&table->rows));
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            new_row = ovsdb_row_datum_clone(row);
            hmap_insert(&new_table->rows, &new_row->hmap_node,
                        ovsdb_row_hash(new_row));
        }
    }

    return new;
}

static void *
compaction_thread(void *aux)
{
    struct ovsdb_compaction_state *state = aux;
    uint64_t start_time = time_msec();
    struct json *data;

    VLOG_DBG("%s: Compaction thread started.", state->db->name);
    data = ovsdb_to_txn_json(state->db, "compacting database online",
                             /* Do not allow shallow copies to avoid races. */
                             false);
    state->data = json_serialized_object_create(data);
    json_destroy(data);

    state->thread_time = time_msec() - start_time;

    VLOG_DBG("%s: Compaction thread finished in %"PRIu64" ms.",
             state->db->name, state->thread_time);
    seq_change(state->done);
    return NULL;
}

void
ovsdb_snapshot_wait(struct ovsdb *db)
{
    if (db->snap_state) {
        seq_wait(db->snap_state->done, db->snap_state->seqno);
    }
}

bool
ovsdb_snapshot_in_progress(struct ovsdb *db)
{
    return db->snap_state &&
           seq_read(db->snap_state->done) == db->snap_state->seqno;
}

bool
ovsdb_snapshot_ready(struct ovsdb *db)
{
    return db->snap_state &&
           seq_read(db->snap_state->done) != db->snap_state->seqno;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_snapshot(struct ovsdb *db, bool trim_memory OVS_UNUSED)
{
    if (!db->storage || ovsdb_snapshot_in_progress(db)) {
        return NULL;
    }

    uint64_t applied_index = ovsdb_storage_get_applied_index(db->storage);
    uint64_t elapsed, start_time = time_msec();
    struct ovsdb_compaction_state *state;

    if (!applied_index) {
        /* Parallel compaction is not supported for standalone databases. */
        state = xzalloc(sizeof *state);
        state->data = ovsdb_to_txn_json(db,
                                        "compacting database online", true);
        state->schema = ovsdb_schema_to_json(db->schema);
    } else if (ovsdb_snapshot_ready(db)) {
        xpthread_join(db->snap_state->thread, NULL);

        state = db->snap_state;
        db->snap_state = NULL;

        ovsdb_destroy(state->db);
        seq_destroy(state->done);
    } else {
        /* Creating a thread. */
        ovs_assert(!db->snap_state);
        state = xzalloc(sizeof *state);

        state->db = ovsdb_clone_data(db);
        state->schema = ovsdb_schema_to_json(db->schema);
        state->applied_index = applied_index;
        state->done = seq_create();
        state->seqno = seq_read(state->done);
        state->thread = ovs_thread_create("compaction",
                                          compaction_thread, state);
        state->init_time = time_msec() - start_time;

        db->snap_state = state;
        return NULL;
    }

    struct ovsdb_error *error;

    error = ovsdb_storage_store_snapshot(db->storage, state->schema,
                                         state->data, state->applied_index);
    json_destroy(state->schema);
    json_destroy(state->data);

#if HAVE_DECL_MALLOC_TRIM
    if (!error && trim_memory) {
        malloc_trim(0);
    }
#endif

    elapsed = time_msec() - start_time;
    VLOG(elapsed > 1000 ? VLL_INFO : VLL_DBG,
         "%s: Database compaction took %"PRIu64"ms "
         "(init: %"PRIu64"ms, write: %"PRIu64"ms, thread: %"PRIu64"ms)",
         db->name, elapsed + state->init_time,
         state->init_time, elapsed, state->thread_time);

    free(state);
    return error;
}

void
ovsdb_replace(struct ovsdb *dst, struct ovsdb *src)
{
    /* Cancel monitors. */
    ovsdb_monitor_prereplace_db(dst);

    /* Cancel triggers. */
    struct ovsdb_trigger *trigger;
    LIST_FOR_EACH_SAFE (trigger, node, &dst->triggers) {
        ovsdb_trigger_prereplace_db(trigger);
    }

    /* Destroy txn history. */
    ovsdb_txn_history_destroy(dst);

    struct ovsdb_schema *tmp_schema = dst->schema;
    dst->schema = src->schema;
    src->schema = tmp_schema;

    shash_swap(&dst->tables, &src->tables);

    dst->rbac_role = ovsdb_get_table(dst, "RBAC_Role");

    /* Get statistics from the new database. */
    dst->n_atoms = src->n_atoms;

    ovsdb_destroy(src);
}
