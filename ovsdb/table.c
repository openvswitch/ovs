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

#include "table.h"

#include <assert.h>
#include <limits.h>

#include "json.h"
#include "column.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb-types.h"
#include "row.h"

static void
add_column(struct ovsdb_table_schema *ts, struct ovsdb_column *column)
{
    assert(!shash_find(&ts->columns, column->name));
    column->index = shash_count(&ts->columns);
    shash_add(&ts->columns, column->name, column);
}

struct ovsdb_table_schema *
ovsdb_table_schema_create(const char *name, bool mutable,
                          unsigned int max_rows)
{
    struct ovsdb_column *uuid, *version;
    struct ovsdb_table_schema *ts;

    ts = xzalloc(sizeof *ts);
    ts->name = xstrdup(name);
    ts->mutable = mutable;
    shash_init(&ts->columns);
    ts->max_rows = max_rows;

    uuid = ovsdb_column_create("_uuid", false, true, &ovsdb_type_uuid);
    add_column(ts, uuid);
    assert(uuid->index == OVSDB_COL_UUID);

    version = ovsdb_column_create("_version", false, false, &ovsdb_type_uuid);
    add_column(ts, version);
    assert(version->index == OVSDB_COL_VERSION);

    return ts;
}

struct ovsdb_table_schema *
ovsdb_table_schema_clone(const struct ovsdb_table_schema *old)
{
    struct ovsdb_table_schema *new;
    struct shash_node *node;

    new = ovsdb_table_schema_create(old->name, old->mutable, old->max_rows);
    SHASH_FOR_EACH (node, &old->columns) {
        const struct ovsdb_column *column = node->data;

        if (column->name[0] == '_') {
            /* Added automatically by ovsdb_table_schema_create(). */
            continue;
        }

        add_column(new, ovsdb_column_clone(column));
    }
    return new;
}

void
ovsdb_table_schema_destroy(struct ovsdb_table_schema *ts)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &ts->columns) {
        ovsdb_column_destroy(node->data);
    }
    shash_destroy(&ts->columns);
    free(ts->name);
    free(ts);
}

struct ovsdb_error *
ovsdb_table_schema_from_json(const struct json *json, const char *name,
                             struct ovsdb_table_schema **tsp)
{
    struct ovsdb_table_schema *ts;
    const struct json *columns, *mutable, *max_rows;
    struct shash_node *node;
    struct ovsdb_parser parser;
    struct ovsdb_error *error;
    long long int n_max_rows;

    *tsp = NULL;

    ovsdb_parser_init(&parser, json, "table schema for table %s", name);
    columns = ovsdb_parser_member(&parser, "columns", OP_OBJECT);
    mutable = ovsdb_parser_member(&parser, "mutable",
                                  OP_TRUE | OP_FALSE | OP_OPTIONAL);
    max_rows = ovsdb_parser_member(&parser, "maxRows",
                                   OP_INTEGER | OP_OPTIONAL);
    error = ovsdb_parser_finish(&parser);
    if (error) {
        return error;
    }

    if (max_rows) {
        if (json_integer(max_rows) <= 0) {
            return ovsdb_syntax_error(json, NULL,
                                      "maxRows must be at least 1");
        }
        n_max_rows = max_rows->u.integer;
    } else {
        n_max_rows = UINT_MAX;
    }

    if (shash_is_empty(json_object(columns))) {
        return ovsdb_syntax_error(json, NULL,
                                  "table must have at least one column");
    }

    ts = ovsdb_table_schema_create(name,
                                   mutable ? json_boolean(mutable) : true,
                                   MIN(n_max_rows, UINT_MAX));
    SHASH_FOR_EACH (node, json_object(columns)) {
        struct ovsdb_column *column;

        if (node->name[0] == '_') {
            error = ovsdb_syntax_error(json, NULL, "names beginning with "
                                       "\"_\" are reserved");
        } else if (!ovsdb_parser_is_id(node->name)) {
            error = ovsdb_syntax_error(json, NULL, "name must be a valid id");
        } else {
            error = ovsdb_column_from_json(node->data, node->name, &column);
        }
        if (error) {
            ovsdb_table_schema_destroy(ts);
            return error;
        }

        add_column(ts, column);
    }
    *tsp = ts;
    return 0;
}

struct json *
ovsdb_table_schema_to_json(const struct ovsdb_table_schema *ts)
{
    struct json *json, *columns;
    struct shash_node *node;

    json = json_object_create();
    if (!ts->mutable) {
        json_object_put(json, "mutable", json_boolean_create(false));
    }

    columns = json_object_create();

    SHASH_FOR_EACH (node, &ts->columns) {
        const struct ovsdb_column *column = node->data;
        if (node->name[0] != '_') {
            json_object_put(columns, column->name,
                            ovsdb_column_to_json(column));
        }
    }
    json_object_put(json, "columns", columns);
    if (ts->max_rows != UINT_MAX) {
        json_object_put(json, "maxRows", json_integer_create(ts->max_rows));
    }

    return json;
}

const struct ovsdb_column *
ovsdb_table_schema_get_column(const struct ovsdb_table_schema *ts,
                              const char *name)
{
    return shash_find_data(&ts->columns, name);
}

struct ovsdb_table *
ovsdb_table_create(struct ovsdb_table_schema *ts)
{
    struct ovsdb_table *table;

    table = xmalloc(sizeof *table);
    table->schema = ts;
    table->txn_table = NULL;
    hmap_init(&table->rows);

    return table;
}

void
ovsdb_table_destroy(struct ovsdb_table *table)
{
    if (table) {
        struct ovsdb_row *row, *next;

        HMAP_FOR_EACH_SAFE (row, next, struct ovsdb_row, hmap_node,
                            &table->rows) {
            ovsdb_row_destroy(row);
        }
        hmap_destroy(&table->rows);

        ovsdb_table_schema_destroy(table->schema);
        free(table);
    }
}

const struct ovsdb_row *
ovsdb_table_get_row(const struct ovsdb_table *table, const struct uuid *uuid)
{
    struct ovsdb_row *row;

    HMAP_FOR_EACH_WITH_HASH (row, struct ovsdb_row, hmap_node, uuid_hash(uuid),
                             &table->rows) {
        if (uuid_equals(ovsdb_row_get_uuid(row), uuid)) {
            return row;
        }
    }

    return NULL;
}

/* This is probably not the function you want.  Use ovsdb_txn_row_modify()
 * instead. */
bool
ovsdb_table_put_row(struct ovsdb_table *table, struct ovsdb_row *row)
{
    const struct uuid *uuid = ovsdb_row_get_uuid(row);
    if (!ovsdb_table_get_row(table, uuid)) {
        hmap_insert(&table->rows, &row->hmap_node, uuid_hash(uuid));
        return true;
    } else {
        return false;
    }
}
