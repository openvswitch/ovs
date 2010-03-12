/* Copyright (c) 2009, 2010 Nicira Networks
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

#include "file.h"

#include <assert.h>
#include <fcntl.h>

#include "bitmap.h"
#include "column.h"
#include "log.h"
#include "json.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "row.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "uuid.h"
#include "util.h"

#define THIS_MODULE VLM_ovsdb_file
#include "vlog.h"

/* A transaction being converted to JSON for writing to a file. */
struct ovsdb_file_txn {
    struct json *json;          /* JSON for the whole transaction. */
    struct json *table_json;    /* JSON for 'table''s transaction. */
    struct ovsdb_table *table;  /* Table described in 'table_json'.  */
};

static void ovsdb_file_txn_init(struct ovsdb_file_txn *);
static void ovsdb_file_txn_add_row(struct ovsdb_file_txn *,
                                   const struct ovsdb_row *old,
                                   const struct ovsdb_row *new,
                                   const unsigned long int *changed);
static struct ovsdb_error *ovsdb_file_txn_commit(struct json *,
                                                 const char *comment,
                                                 bool durable,
                                                 struct ovsdb_log *);

static struct ovsdb_error *ovsdb_file_open__(const char *file_name,
                                             const struct ovsdb_schema *,
                                             bool read_only, struct ovsdb **);
static struct ovsdb_error *ovsdb_file_txn_from_json(struct ovsdb *,
                                                    const struct json *,
                                                    bool converting,
                                                    struct ovsdb_txn **);
static void ovsdb_file_replica_create(struct ovsdb *, struct ovsdb_log *);

/* Opens database 'file_name' and stores a pointer to the new database in
 * '*dbp'.  If 'read_only' is false, then the database will be locked and
 * changes to the database will be written to disk.  If 'read_only' is true,
 * the database will not be locked and changes to the database will persist
 * only as long as the "struct ovsdb".
 *
 * On success, returns NULL.  On failure, returns an ovsdb_error (which the
 * caller must destroy) and sets '*dbp' to NULL. */
struct ovsdb_error *
ovsdb_file_open(const char *file_name, bool read_only, struct ovsdb **dbp)
{
    return ovsdb_file_open__(file_name, NULL, read_only, dbp);
}

/* Opens database 'file_name' with an alternate schema.  The specified 'schema'
 * is used to interpret the data in 'file_name', ignoring the schema actually
 * stored in the file.  Data in the file for tables or columns that do not
 * exist in 'schema' are ignored, but the ovsdb file format must otherwise be
 * observed, including column constraints.
 *
 * This function can be useful for upgrading or downgrading databases to
 * "almost-compatible" formats.
 *
 * The database will not be locked.  Changes to the database will persist only
 * as long as the "struct ovsdb".
 *
 * On success, stores a pointer to the new database in '*dbp' and returns a
 * null pointer.  On failure, returns an ovsdb_error (which the caller must
 * destroy) and sets '*dbp' to NULL. */
struct ovsdb_error *
ovsdb_file_open_as_schema(const char *file_name,
                          const struct ovsdb_schema *schema,
                          struct ovsdb **dbp)
{
    return ovsdb_file_open__(file_name, schema, true, dbp);
}

static struct ovsdb_error *
ovsdb_file_open__(const char *file_name,
                  const struct ovsdb_schema *alternate_schema,
                  bool read_only, struct ovsdb **dbp)
{
    enum ovsdb_log_open_mode open_mode;
    struct ovsdb_schema *schema;
    struct ovsdb_error *error;
    struct ovsdb_log *log;
    struct json *json;
    struct ovsdb *db;

    open_mode = read_only ? OVSDB_LOG_READ_ONLY : OVSDB_LOG_READ_WRITE;
    error = ovsdb_log_open(file_name, open_mode, -1, &log);
    if (error) {
        return error;
    }

    error = ovsdb_log_read(log, &json);
    if (error) {
        return error;
    } else if (!json) {
        return ovsdb_io_error(EOF, "%s: database file contains no schema",
                              file_name);
    }

    if (alternate_schema) {
        schema = ovsdb_schema_clone(alternate_schema);
    } else {
        error = ovsdb_schema_from_json(json, &schema);
        if (error) {
            json_destroy(json);
            return ovsdb_wrap_error(error,
                                    "failed to parse \"%s\" as ovsdb schema",
                                    file_name);
        }
    }
    json_destroy(json);

    db = ovsdb_create(schema);
    while ((error = ovsdb_log_read(log, &json)) == NULL && json) {
        struct ovsdb_txn *txn;

        error = ovsdb_file_txn_from_json(db, json, alternate_schema != NULL,
                                         &txn);
        json_destroy(json);
        if (error) {
            break;
        }

        ovsdb_txn_commit(txn, false);
    }
    if (error) {
        char *msg = ovsdb_error_to_string(error);
        VLOG_WARN("%s", msg);
        free(msg);

        ovsdb_error_destroy(error);
    }

    if (!read_only) {
        ovsdb_file_replica_create(db, log);
    } else {
        ovsdb_log_close(log);
    }

    *dbp = db;
    return NULL;
}

static struct ovsdb_error *
ovsdb_file_update_row_from_json(struct ovsdb_row *row, bool converting,
                                const struct json *json)
{
    struct ovsdb_table_schema *schema = row->table->schema;
    struct ovsdb_error *error;
    struct shash_node *node;

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "row must be JSON object");
    }

    SHASH_FOR_EACH (node, json_object(json)) {
        const char *column_name = node->name;
        const struct ovsdb_column *column;
        struct ovsdb_datum datum;

        column = ovsdb_table_schema_get_column(schema, column_name);
        if (!column) {
            if (converting) {
                continue;
            }
            return ovsdb_syntax_error(json, "unknown column",
                                      "No column %s in table %s.",
                                      column_name, schema->name);
        }

        error = ovsdb_datum_from_json(&datum, &column->type, node->data, NULL);
        if (error) {
            return error;
        }
        ovsdb_datum_swap(&row->fields[column->index], &datum);
        ovsdb_datum_destroy(&datum, &column->type);
    }

    return NULL;
}

static struct ovsdb_error *
ovsdb_file_txn_row_from_json(struct ovsdb_txn *txn, struct ovsdb_table *table,
                             bool converting,
                             const struct uuid *row_uuid, struct json *json)
{
    const struct ovsdb_row *row = ovsdb_table_get_row(table, row_uuid);
    if (json->type == JSON_NULL) {
        if (!row) {
            return ovsdb_syntax_error(NULL, NULL, "transaction deletes "
                                      "row "UUID_FMT" that does not exist",
                                      UUID_ARGS(row_uuid));
        }
        ovsdb_txn_row_delete(txn, row);
        return NULL;
    } else if (row) {
        return ovsdb_file_update_row_from_json(ovsdb_txn_row_modify(txn, row),
                                               converting, json);
    } else {
        struct ovsdb_error *error;
        struct ovsdb_row *new;

        new = ovsdb_row_create(table);
        *ovsdb_row_get_uuid_rw(new) = *row_uuid;
        error = ovsdb_file_update_row_from_json(new, converting, json);
        if (error) {
            ovsdb_row_destroy(new);
        }

        ovsdb_txn_row_insert(txn, new);

        return error;
    }
}

static struct ovsdb_error *
ovsdb_file_txn_table_from_json(struct ovsdb_txn *txn,
                               struct ovsdb_table *table,
                               bool converting, struct json *json)
{
    struct shash_node *node;

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "object expected");
    }

    SHASH_FOR_EACH (node, json->u.object) {
        const char *uuid_string = node->name;
        struct json *txn_row_json = node->data;
        struct ovsdb_error *error;
        struct uuid row_uuid;

        if (!uuid_from_string(&row_uuid, uuid_string)) {
            return ovsdb_syntax_error(json, NULL, "\"%s\" is not a valid UUID",
                                      uuid_string);
        }

        error = ovsdb_file_txn_row_from_json(txn, table, converting,
                                             &row_uuid, txn_row_json);
        if (error) {
            return error;
        }
    }

    return NULL;
}

static struct ovsdb_error *
ovsdb_file_txn_from_json(struct ovsdb *db, const struct json *json,
                         bool converting, struct ovsdb_txn **txnp)
{
    struct ovsdb_error *error;
    struct shash_node *node;
    struct ovsdb_txn *txn;

    *txnp = NULL;
    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "object expected");
    }

    txn = ovsdb_txn_create(db);
    SHASH_FOR_EACH (node, json->u.object) {
        const char *table_name = node->name;
        struct json *txn_table_json = node->data;
        struct ovsdb_table *table;

        table = shash_find_data(&db->tables, table_name);
        if (!table) {
            if (!strcmp(table_name, "_date")
                || !strcmp(table_name, "_comment")
                || converting) {
                continue;
            }

            error = ovsdb_syntax_error(json, "unknown table",
                                       "No table named %s.", table_name);
            goto error;
        }

        error = ovsdb_file_txn_table_from_json(txn, table, converting,
                                               txn_table_json);
        if (error) {
            goto error;
        }
    }
    *txnp = txn;
    return NULL;

error:
    ovsdb_txn_abort(txn);
    return error;
}

/* Saves a snapshot of 'db''s current contents as 'file_name'.  If 'comment' is
 * nonnull, then it is added along with the data contents and can be viewed
 * with "ovsdb-tool show-log".
 *
 * 'locking' is passed along to ovsdb_log_open() untouched. */
struct ovsdb_error *
ovsdb_file_save_copy(const char *file_name, int locking,
                     const char *comment, const struct ovsdb *db)
{
    const struct shash_node *node;
    struct ovsdb_file_txn ftxn;
    struct ovsdb_error *error;
    struct ovsdb_log *log;
    struct json *json;

    error = ovsdb_log_open(file_name, OVSDB_LOG_CREATE, locking, &log);
    if (error) {
        return error;
    }

    /* Write schema. */
    json = ovsdb_schema_to_json(db->schema);
    error = ovsdb_log_write(log, json);
    json_destroy(json);
    if (error) {
        goto exit;
    }

    /* Write data. */
    ovsdb_file_txn_init(&ftxn);
    SHASH_FOR_EACH (node, &db->tables) {
        const struct ovsdb_table *table = node->data;
        const struct ovsdb_row *row;

        HMAP_FOR_EACH (row, struct ovsdb_row, hmap_node, &table->rows) {
            ovsdb_file_txn_add_row(&ftxn, NULL, row, NULL);
        }
    }
    error = ovsdb_file_txn_commit(ftxn.json, comment, true, log);

exit:
    ovsdb_log_close(log);
    if (error) {
        remove(file_name);
    }
    return error;
}

/* Replica implementation. */

struct ovsdb_file_replica {
    struct ovsdb_replica replica;
    struct ovsdb_log *log;
};

static const struct ovsdb_replica_class ovsdb_file_replica_class;

static void
ovsdb_file_replica_create(struct ovsdb *db, struct ovsdb_log *log)
{
    struct ovsdb_file_replica *r = xmalloc(sizeof *r);
    ovsdb_replica_init(&r->replica, &ovsdb_file_replica_class);
    r->log = log;
    ovsdb_add_replica(db, &r->replica);

}

static struct ovsdb_file_replica *
ovsdb_file_replica_cast(struct ovsdb_replica *replica)
{
    assert(replica->class == &ovsdb_file_replica_class);
    return CONTAINER_OF(replica, struct ovsdb_file_replica, replica);
}

static bool
ovsdb_file_replica_change_cb(const struct ovsdb_row *old,
                             const struct ovsdb_row *new,
                             const unsigned long int *changed,
                             void *ftxn_)
{
    struct ovsdb_file_txn *ftxn = ftxn_;
    ovsdb_file_txn_add_row(ftxn, old, new, changed);
    return true;
}

static struct ovsdb_error *
ovsdb_file_replica_commit(struct ovsdb_replica *r_,
                          const struct ovsdb_txn *txn, bool durable)
{
    struct ovsdb_file_replica *r = ovsdb_file_replica_cast(r_);
    struct ovsdb_file_txn ftxn;

    ovsdb_file_txn_init(&ftxn);
    ovsdb_txn_for_each_change(txn, ovsdb_file_replica_change_cb, &ftxn);
    if (!ftxn.json) {
        /* Nothing to commit. */
        return NULL;
    }

    return ovsdb_file_txn_commit(ftxn.json, ovsdb_txn_get_comment(txn),
                                 durable, r->log);
}

static void
ovsdb_file_replica_destroy(struct ovsdb_replica *r_)
{
    struct ovsdb_file_replica *r = ovsdb_file_replica_cast(r_);

    ovsdb_log_close(r->log);
    free(r);
}

static const struct ovsdb_replica_class ovsdb_file_replica_class = {
    ovsdb_file_replica_commit,
    ovsdb_file_replica_destroy
};

static void
ovsdb_file_txn_init(struct ovsdb_file_txn *ftxn)
{
    ftxn->json = NULL;
    ftxn->table_json = NULL;
    ftxn->table = NULL;
}

static void
ovsdb_file_txn_add_row(struct ovsdb_file_txn *ftxn,
                       const struct ovsdb_row *old,
                       const struct ovsdb_row *new,
                       const unsigned long int *changed)
{
    struct json *row;

    if (!new) {
        row = json_null_create();
    } else {
        struct shash_node *node;

        row = old ? NULL : json_object_create();
        SHASH_FOR_EACH (node, &new->table->schema->columns) {
            const struct ovsdb_column *column = node->data;
            const struct ovsdb_type *type = &column->type;
            unsigned int idx = column->index;

            if (idx != OVSDB_COL_UUID && column->persistent
                && (old
                    ? bitmap_is_set(changed, idx)
                    : !ovsdb_datum_is_default(&new->fields[idx], type)))
            {
                if (!row) {
                    row = json_object_create();
                }
                json_object_put(row, column->name,
                                ovsdb_datum_to_json(&new->fields[idx], type));
            }
        }
    }

    if (row) {
        struct ovsdb_table *table = new ? new->table : old->table;
        char uuid[UUID_LEN + 1];

        if (table != ftxn->table) {
            /* Create JSON object for transaction overall. */
            if (!ftxn->json) {
                ftxn->json = json_object_create();
            }

            /* Create JSON object for transaction on this table. */
            ftxn->table_json = json_object_create();
            ftxn->table = table;
            json_object_put(ftxn->json, table->schema->name, ftxn->table_json);
        }

        /* Add row to transaction for this table. */
        snprintf(uuid, sizeof uuid,
                 UUID_FMT, UUID_ARGS(ovsdb_row_get_uuid(new ? new : old)));
        json_object_put(ftxn->table_json, uuid, row);
    }
}

static struct ovsdb_error *
ovsdb_file_txn_commit(struct json *json, const char *comment,
                      bool durable, struct ovsdb_log *log)
{
    struct ovsdb_error *error;

    if (!json) {
        json = json_object_create();
    }
    if (comment) {
        json_object_put_string(json, "_comment", comment);
    }
    json_object_put(json, "_date", json_integer_create(time_now()));

    error = ovsdb_log_write(log, json);
    json_destroy(json);
    if (error) {
        return ovsdb_wrap_error(error, "writing transaction failed");
    }

    if (durable) {
        error = ovsdb_log_commit(log);
        if (error) {
            return ovsdb_wrap_error(error, "committing transaction failed");
        }
    }

    return NULL;
}
