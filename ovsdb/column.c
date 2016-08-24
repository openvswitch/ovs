/* Copyright (c) 2009, 2010, 2011, 2016 Nicira, Inc.
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

#include "ovsdb/column.h"

#include <stdlib.h>

#include "column.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "table.h"
#include "util.h"

struct ovsdb_column *
ovsdb_column_create(const char *name,
                    bool mutable, bool persistent,
                    const struct ovsdb_type *type)
{
    /* Doesn't set the new column's 'index': the caller must do that. */
    struct ovsdb_column *column;

    column = xzalloc(sizeof *column);
    column->name = xstrdup(name);
    column->mutable = mutable;
    column->persistent = persistent;
    ovsdb_type_clone(&column->type, type);

    return column;
}

struct ovsdb_column *
ovsdb_column_clone(const struct ovsdb_column *old)
{
    /* Doesn't copy the column's 'index': the caller must do that. */
    return ovsdb_column_create(old->name,
                               old->mutable, old->persistent,
                               &old->type);
}

void
ovsdb_column_destroy(struct ovsdb_column *column)
{
    ovsdb_type_destroy(&column->type);
    free(column->name);
    free(column);
}

struct ovsdb_error *
ovsdb_column_from_json(const struct json *json, const char *name,
                       struct ovsdb_column **columnp)
{
    const struct json *mutable_json, *ephemeral, *type_json;
    struct ovsdb_error *error;
    struct ovsdb_type type;
    struct ovsdb_parser parser;

    *columnp = NULL;

    ovsdb_parser_init(&parser, json, "schema for column %s", name);
    mutable_json = ovsdb_parser_member(&parser, "mutable",
                                       OP_TRUE | OP_FALSE | OP_OPTIONAL);
    ephemeral = ovsdb_parser_member(&parser, "ephemeral",
                                    OP_TRUE | OP_FALSE | OP_OPTIONAL);
    type_json = ovsdb_parser_member(&parser, "type", OP_STRING | OP_OBJECT);
    error = ovsdb_parser_finish(&parser);
    if (error) {
        return error;
    }

    error = ovsdb_type_from_json(&type, type_json);
    if (error) {
        return error;
    }

    bool mutable = !mutable_json || json_boolean(mutable_json);
    if (!mutable
        && (ovsdb_base_type_is_weak_ref(&type.key) ||
            ovsdb_base_type_is_weak_ref(&type.value))) {
        /* We cannot allow a weak reference to be immutable: if referenced rows
         * are deleted, then the weak reference needs to change. */
        mutable = true;
    }

    bool persistent = ephemeral ? !json_boolean(ephemeral) : true;
    *columnp = ovsdb_column_create(name, mutable, persistent, &type);

    ovsdb_type_destroy(&type);

    return NULL;
}

struct json *
ovsdb_column_to_json(const struct ovsdb_column *column)
{
    struct json *json = json_object_create();
    if (!column->mutable) {
        json_object_put(json, "mutable", json_boolean_create(false));
    }
    if (!column->persistent) {
        json_object_put(json, "ephemeral", json_boolean_create(true));
    }
    json_object_put(json, "type", ovsdb_type_to_json(&column->type));
    return json;
}

void
ovsdb_column_set_init(struct ovsdb_column_set *set)
{
    set->columns = NULL;
    set->n_columns = set->allocated_columns = 0;
}

void
ovsdb_column_set_destroy(struct ovsdb_column_set *set)
{
    free(set->columns);
}

void
ovsdb_column_set_clone(struct ovsdb_column_set *new,
                       const struct ovsdb_column_set *old)
{
    new->columns = xmemdup(old->columns,
                           old->n_columns * sizeof *old->columns);
    new->n_columns = new->allocated_columns = old->n_columns;
}

struct ovsdb_error *
ovsdb_column_set_from_json(const struct json *json,
                           const struct ovsdb_table_schema *schema,
                           struct ovsdb_column_set *set)
{
    ovsdb_column_set_init(set);
    if (!json) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, &schema->columns) {
            const struct ovsdb_column *column = node->data;
            ovsdb_column_set_add(set, column);
        }

        return NULL;
    } else {
        struct ovsdb_error *error = NULL;
        size_t i;

        if (json->type != JSON_ARRAY) {
            goto error;
        }

        /* XXX this is O(n**2) */
        for (i = 0; i < json->u.array.n; i++) {
            const struct ovsdb_column *column;
            const char *s;

            if (json->u.array.elems[i]->type != JSON_STRING) {
                goto error;
            }

            s = json->u.array.elems[i]->u.string;
            column = shash_find_data(&schema->columns, s);
            if (!column) {
                error = ovsdb_syntax_error(json, NULL, "%s is not a valid "
                                           "column name", s);
                goto error;
            } else if (ovsdb_column_set_contains(set, column->index)) {
                goto error;
            }
            ovsdb_column_set_add(set, column);
        }
        return NULL;

    error:
        ovsdb_column_set_destroy(set);
        ovsdb_column_set_init(set);
        if (!error) {
            error = ovsdb_syntax_error(json, NULL, "array of distinct column "
                                       "names expected");
        }
        return error;
    }
}

struct json *
ovsdb_column_set_to_json(const struct ovsdb_column_set *set)
{
    struct json *json;
    size_t i;

    json = json_array_create_empty();
    for (i = 0; i < set->n_columns; i++) {
        json_array_add(json, json_string_create(set->columns[i]->name));
    }
    return json;
}

/* Returns an English string listing the contents of 'set', e.g. "columns
 * \"a\", \"b\", and \"c\"".  The caller must free the string. */
char *
ovsdb_column_set_to_string(const struct ovsdb_column_set *set)
{
    if (!set->n_columns) {
        return xstrdup("no columns");
    } else {
        struct ds s;
        size_t i;

        ds_init(&s);
        ds_put_format(&s, "column%s ", set->n_columns > 1 ? "s" : "");
        for (i = 0; i < set->n_columns; i++) {
            const char *delimiter = english_list_delimiter(i, set->n_columns);
            ds_put_format(&s, "%s\"%s\"", delimiter, set->columns[i]->name);
        }
        return ds_steal_cstr(&s);
    }
}

void
ovsdb_column_set_add(struct ovsdb_column_set *set,
                     const struct ovsdb_column *column)
{
    if (set->n_columns >= set->allocated_columns) {
        set->columns = x2nrealloc(set->columns, &set->allocated_columns,
                                  sizeof *set->columns);
    }
    set->columns[set->n_columns++] = column;
}

void
ovsdb_column_set_add_all(struct ovsdb_column_set *set,
                         const struct ovsdb_table *table)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &table->schema->columns) {
        const struct ovsdb_column *column = node->data;
        ovsdb_column_set_add(set, column);
    }
}

bool
ovsdb_column_set_contains(const struct ovsdb_column_set *set,
                          unsigned int column_index)
{
    size_t i;

    for (i = 0; i < set->n_columns; i++) {
        if (set->columns[i]->index == column_index) {
            return true;
        }
    }
    return false;
}

/* This comparison is sensitive to ordering of columns within a set, but that's
 * good: the only existing caller wants to make sure that hash values are
 * comparable, which is only true if column ordering is the same. */
bool
ovsdb_column_set_equals(const struct ovsdb_column_set *a,
                        const struct ovsdb_column_set *b)
{
    size_t i;

    if (a->n_columns != b->n_columns) {
        return false;
    }
    for (i = 0; i < a->n_columns; i++) {
        if (a->columns[i] != b->columns[i]) {
            return false;
        }
    }
    return true;
}
