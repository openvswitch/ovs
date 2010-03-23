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

#include "ovsdb.h"

#include "column.h"
#include "json.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb-types.h"
#include "table.h"
#include "transaction.h"

struct ovsdb_schema *
ovsdb_schema_create(const char *name)
{
    struct ovsdb_schema *schema;

    schema = xzalloc(sizeof *schema);
    schema->name = xstrdup(name);
    shash_init(&schema->tables);

    return schema;
}

struct ovsdb_schema *
ovsdb_schema_clone(const struct ovsdb_schema *old)
{
    struct ovsdb_schema *new;
    struct shash_node *node;

    new = ovsdb_schema_create(old->name);
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

static struct ovsdb_error * WARN_UNUSED_RESULT
ovsdb_schema_check_ref_table(const struct ovsdb_column *column,
                             const struct shash *tables,
                             const struct ovsdb_base_type *base,
                             const char *base_name)
{
    if (base->type == OVSDB_TYPE_UUID && base->u.uuid.refTableName
        && !shash_find(tables, base->u.uuid.refTableName)) {
        return ovsdb_syntax_error(NULL, NULL,
                                  "column %s %s refers to undefined table %s",
                                  column->name, base_name,
                                  base->u.uuid.refTableName);
    } else {
        return NULL;
    }
}

struct ovsdb_error *
ovsdb_schema_from_json(struct json *json, struct ovsdb_schema **schemap)
{
    struct ovsdb_schema *schema;
    const struct json *name, *tables;
    struct ovsdb_error *error;
    struct shash_node *node;
    struct ovsdb_parser parser;

    *schemap = NULL;

    ovsdb_parser_init(&parser, json, "database schema");
    name = ovsdb_parser_member(&parser, "name", OP_ID);
    tables = ovsdb_parser_member(&parser, "tables", OP_OBJECT);
    error = ovsdb_parser_finish(&parser);
    if (error) {
        return error;
    }

    schema = ovsdb_schema_create(json_string(name));
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

    /* Validate that all refTables refer to the names of tables that exist. */
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
    return 0;
}

struct json *
ovsdb_schema_to_json(const struct ovsdb_schema *schema)
{
    struct json *json, *tables;
    struct shash_node *node;

    json = json_object_create();
    json_object_put_string(json, "name", schema->name);

    tables = json_object_create();

    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;
        json_object_put(tables, table->name,
                        ovsdb_table_schema_to_json(table));
    }
    json_object_put(json, "tables", tables);

    return json;
}

static void
ovsdb_set_ref_table(const struct shash *tables,
                    struct ovsdb_base_type *base)
{
    if (base->type == OVSDB_TYPE_UUID && base->u.uuid.refTableName) {
        struct ovsdb_table *table;

        table = shash_find_data(tables, base->u.uuid.refTableName);
        base->u.uuid.refTable = table;
    }
}

struct ovsdb *
ovsdb_create(struct ovsdb_schema *schema)
{
    struct shash_node *node;
    struct ovsdb *db;

    db = xmalloc(sizeof *db);
    db->schema = schema;
    list_init(&db->replicas);
    list_init(&db->triggers);
    db->run_triggers = false;

    shash_init(&db->tables);
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

    return db;
}

void
ovsdb_destroy(struct ovsdb *db)
{
    if (db) {
        struct shash_node *node;

        /* Remove all the replicas. */
        while (!list_is_empty(&db->replicas)) {
            struct ovsdb_replica *r
                = CONTAINER_OF(list_pop_back(&db->replicas),
                               struct ovsdb_replica, node);
            ovsdb_remove_replica(db, r);
        }

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
        free(db);
    }
}

struct ovsdb_table *
ovsdb_get_table(const struct ovsdb *db, const char *name)
{
    return shash_find_data(&db->tables, name);
}

void
ovsdb_replica_init(struct ovsdb_replica *r,
                   const struct ovsdb_replica_class *class)
{
    r->class = class;
}

void
ovsdb_add_replica(struct ovsdb *db, struct ovsdb_replica *r)
{
    list_push_back(&db->replicas, &r->node);
}

void
ovsdb_remove_replica(struct ovsdb *db OVS_UNUSED, struct ovsdb_replica *r)
{
    list_remove(&r->node);
    (r->class->destroy)(r);
}
