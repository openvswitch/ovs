/* Copyright (c) 2009 Nicira Networks
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

#include <fcntl.h>

#include "file.h"
#include "json.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "table.h"
#include "transaction.h"

#define THIS_MODULE VLM_ovsdb
#include "vlog.h"

struct ovsdb_schema *
ovsdb_schema_create(const char *name, const char *comment)
{
    struct ovsdb_schema *schema;

    schema = xzalloc(sizeof *schema);
    schema->name = xstrdup(name);
    schema->comment = comment ? xstrdup(comment) : NULL;
    shash_init(&schema->tables);

    return schema;
}

void
ovsdb_schema_destroy(struct ovsdb_schema *schema)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &schema->tables) {
        ovsdb_table_schema_destroy(node->data);
    }
    shash_destroy(&schema->tables);
    free(schema->comment);
    free(schema->name);
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
    if (error) {
        json_destroy(json);
        return ovsdb_wrap_error(error,
                                "failed to parse \"%s\" as ovsdb schema",
                                file_name);
    }

    *schemap = schema;
    return NULL;
}

struct ovsdb_error *
ovsdb_schema_from_json(struct json *json, struct ovsdb_schema **schemap)
{
    struct ovsdb_schema *schema;
    const struct json *name, *comment, *tables;
    struct ovsdb_error *error;
    struct shash_node *node;
    struct ovsdb_parser parser;

    *schemap = NULL;

    ovsdb_parser_init(&parser, json, "database schema");
    name = ovsdb_parser_member(&parser, "name", OP_ID);
    comment = ovsdb_parser_member(&parser, "comment", OP_STRING | OP_OPTIONAL);
    tables = ovsdb_parser_member(&parser, "tables", OP_OBJECT);
    error = ovsdb_parser_finish(&parser);
    if (error) {
        return error;
    }

    schema = ovsdb_schema_create(json_string(name),
                                 comment ? json_string(comment) : NULL);
    SHASH_FOR_EACH (node, json_object(tables)) {
        struct ovsdb_table_schema *table;

        if (node->name[0] == '_') {
            error = ovsdb_syntax_error(json, NULL, "names beginning with "
                                       "\"_\" are reserved");
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
    *schemap = schema;
    return 0;
}

struct json *
ovsdb_schema_to_json(const struct ovsdb_schema *schema)
{
    struct json *json, *tables;
    struct shash_node *node;

    json = json_object_create();
    json_object_put_string(json, "name", schema->name);
    if (schema->comment) {
        json_object_put_string(json, "comment", schema->comment);
    }

    tables = json_object_create();

    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;
        json_object_put(tables, table->name,
                        ovsdb_table_schema_to_json(table));
    }
    json_object_put(json, "tables", tables);

    return json;
}

struct ovsdb *
ovsdb_create(struct ovsdb_file *file, struct ovsdb_schema *schema)
{
    struct shash_node *node;
    struct ovsdb *db;

    db = xmalloc(sizeof *db);
    db->schema = schema;
    db->file = file;
    list_init(&db->triggers);
    db->run_triggers = false;

    shash_init(&db->tables);
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *ts = node->data;
        shash_add(&db->tables, node->name, ovsdb_table_create(ts));
    }

    return db;
}

struct ovsdb_error *
ovsdb_open(const char *file_name, bool read_only, struct ovsdb **dbp)
{
    struct ovsdb_schema *schema;
    struct ovsdb_error *error;
    struct ovsdb_file *file;
    struct json *json;
    struct ovsdb *db;

    error = ovsdb_file_open(file_name, read_only ? O_RDONLY : O_RDWR, &file);
    if (error) {
        return error;
    }

    error = ovsdb_file_read(file, &json);
    if (error) {
        return error;
    } else if (!json) {
        return ovsdb_io_error(EOF, "%s: database file contains no schema",
                              file_name);
    }

    error = ovsdb_schema_from_json(json, &schema);
    if (error) {
        json_destroy(json);
        return ovsdb_wrap_error(error,
                                "failed to parse \"%s\" as ovsdb schema",
                                file_name);
    }
    json_destroy(json);

    db = ovsdb_create(read_only ? file : NULL, schema);
    while ((error = ovsdb_file_read(file, &json)) == NULL && json) {
        struct ovsdb_txn *txn;

        error = ovsdb_txn_from_json(db, json, &txn);
        json_destroy(json);
        if (error) {
            break;
        }

        ovsdb_txn_commit(txn);
    }
    if (error) {
        char *msg = ovsdb_error_to_string(error);
        VLOG_WARN("%s", msg);
        free(msg);

        ovsdb_error_destroy(error);
    }

    if (read_only) {
        ovsdb_file_close(file);
    }

    *dbp = db;
    return NULL;
}

void
ovsdb_destroy(struct ovsdb *db)
{
    if (db) {
        struct shash_node *node;

        /* Delete all the tables.  This also deletes their schemas. */
        SHASH_FOR_EACH (node, &db->tables) {
            struct ovsdb_table *table = node->data;
            ovsdb_table_destroy(table);
        }
        shash_destroy(&db->tables);

        /* The schemas, but not the table that points to them, were deleted in
         * the previous step, so we need to clear out the table.  We can't
         * destroy the table, because ovsdb_schema_destroy() will do that. */
        shash_clear(&db->schema->tables);

        ovsdb_schema_destroy(db->schema);
        ovsdb_file_close(db->file);
        free(db);
    }
}

struct ovsdb_table *
ovsdb_get_table(const struct ovsdb *db, const char *name)
{
    return shash_find_data(&db->tables, name);
}
