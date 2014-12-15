/* Copyright (c) 2009, 2010, 2011 Nicira, Inc.
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

#include <limits.h>

#include "column.h"
#include "json.h"
#include "ovsdb-error.h"
#include "row.h"
#include "table.h"

struct ovsdb_error *
ovsdb_function_from_string(const char *name, enum ovsdb_function *function)
{
#define OVSDB_FUNCTION(ENUM, NAME)              \
    if (!strcmp(name, NAME)) {                  \
        *function = ENUM;                       \
        return NULL;                            \
    }
    OVSDB_FUNCTIONS;
#undef OVSDB_FUNCTION

    return ovsdb_syntax_error(NULL, "unknown function",
                              "No function named %s.", name);
}

const char *
ovsdb_function_to_string(enum ovsdb_function function)
{
    switch (function) {
#define OVSDB_FUNCTION(ENUM, NAME) case ENUM: return NAME;
        OVSDB_FUNCTIONS;
#undef OVSDB_FUNCTION
    }

    return NULL;
}

static OVS_WARN_UNUSED_RESULT struct ovsdb_error *
ovsdb_clause_from_json(const struct ovsdb_table_schema *ts,
                       const struct json *json,
                       struct ovsdb_symbol_table *symtab,
                       struct ovsdb_clause *clause)
{
    const struct json_array *array;
    struct ovsdb_error *error;
    const char *function_name;
    const char *column_name;
    struct ovsdb_type type;

    if (json->type != JSON_ARRAY
        || json->u.array.n != 3
        || json->u.array.elems[0]->type != JSON_STRING
        || json->u.array.elems[1]->type != JSON_STRING) {
        return ovsdb_syntax_error(json, NULL, "Parse error in condition.");
    }
    array = json_array(json);

    column_name = json_string(array->elems[0]);
    clause->column = ovsdb_table_schema_get_column(ts, column_name);
    if (!clause->column) {
        return ovsdb_syntax_error(json, "unknown column",
                                  "No column %s in table %s.",
                                  column_name, ts->name);
    }
    type = clause->column->type;

    function_name = json_string(array->elems[1]);
    error = ovsdb_function_from_string(function_name, &clause->function);
    if (error) {
        return error;
    }

    /* Type-check and relax restrictions on 'type' if appropriate.  */
    switch (clause->function) {
    case OVSDB_F_LT:
    case OVSDB_F_LE:
    case OVSDB_F_GT:
    case OVSDB_F_GE:
        /* Allow these operators for types with n_min == 0, n_max == 1.
         * (They will always be "false" if the value is missing.) */
        if (!(ovsdb_type_is_scalar(&type)
            || ovsdb_type_is_optional_scalar(&type))
            || (type.key.type != OVSDB_TYPE_INTEGER
                && type.key.type != OVSDB_TYPE_REAL)) {
            char *s = ovsdb_type_to_english(&type);
            error = ovsdb_syntax_error(
                json, NULL, "Type mismatch: \"%s\" operator may not be "
                "applied to column %s of type %s.",
                ovsdb_function_to_string(clause->function),
                clause->column->name, s);
            free(s);
            return error;
        }
        break;

    case OVSDB_F_EQ:
    case OVSDB_F_NE:
        break;

    case OVSDB_F_EXCLUDES:
        if (!ovsdb_type_is_scalar(&type)) {
            type.n_min = 0;
            type.n_max = UINT_MAX;
        }
        break;

    case OVSDB_F_INCLUDES:
        if (!ovsdb_type_is_scalar(&type)) {
            type.n_min = 0;
        }
        break;
    }
    return ovsdb_datum_from_json(&clause->arg, &type, array->elems[2], symtab);
}

static void
ovsdb_clause_free(struct ovsdb_clause *clause)
{
    ovsdb_datum_destroy(&clause->arg, &clause->column->type);
}

static int
compare_clauses_3way(const void *a_, const void *b_)
{
    const struct ovsdb_clause *a = a_;
    const struct ovsdb_clause *b = b_;

    if (a->function != b->function) {
        /* Bring functions to the front based on the fraction of table rows
         * that they are (heuristically) expected to leave in the query
         * results.  Note that "enum ovsdb_function" is intentionally ordered
         * to make this trivial. */
        return a->function < b->function ? -1 : 1;
    } else if (a->column->index != b->column->index) {
        if (a->column->index < OVSDB_N_STD_COLUMNS
            || b->column->index < OVSDB_N_STD_COLUMNS) {
            /* Bring the standard columns and in particular the UUID column
             * (since OVSDB_COL_UUID has value 0) to the front.  We have an
             * index on the UUID column, so that makes our queries cheaper. */
            return a->column->index < b->column->index ? -1 : 1;
        } else {
            /* Order clauses predictably to make testing easier. */
            return strcmp(a->column->name, b->column->name);
        }
    } else {
        return 0;
    }
}

struct ovsdb_error *
ovsdb_condition_from_json(const struct ovsdb_table_schema *ts,
                          const struct json *json,
                          struct ovsdb_symbol_table *symtab,
                          struct ovsdb_condition *cnd)
{
    const struct json_array *array = json_array(json);
    size_t i;

    cnd->clauses = xmalloc(array->n * sizeof *cnd->clauses);
    cnd->n_clauses = 0;
    for (i = 0; i < array->n; i++) {
        struct ovsdb_error *error;
        error = ovsdb_clause_from_json(ts, array->elems[i], symtab,
                                       &cnd->clauses[i]);
        if (error) {
            ovsdb_condition_destroy(cnd);
            cnd->clauses = NULL;
            cnd->n_clauses = 0;
            return error;
        }
        cnd->n_clauses++;
    }

    /* A real database would have a query optimizer here. */
    qsort(cnd->clauses, cnd->n_clauses, sizeof *cnd->clauses,
          compare_clauses_3way);

    return NULL;
}

static struct json *
ovsdb_clause_to_json(const struct ovsdb_clause *clause)
{
    return json_array_create_3(
        json_string_create(clause->column->name),
        json_string_create(ovsdb_function_to_string(clause->function)),
        ovsdb_datum_to_json(&clause->arg, &clause->column->type));
}

struct json *
ovsdb_condition_to_json(const struct ovsdb_condition *cnd)
{
    struct json **clauses;
    size_t i;

    clauses = xmalloc(cnd->n_clauses * sizeof *clauses);
    for (i = 0; i < cnd->n_clauses; i++) {
        clauses[i] = ovsdb_clause_to_json(&cnd->clauses[i]);
    }
    return json_array_create(clauses, cnd->n_clauses);
}

static bool
ovsdb_clause_evaluate(const struct ovsdb_row *row,
                      const struct ovsdb_clause *c)
{
    const struct ovsdb_datum *field = &row->fields[c->column->index];
    const struct ovsdb_datum *arg = &c->arg;
    const struct ovsdb_type *type = &c->column->type;

    if (ovsdb_type_is_optional_scalar(type) && field->n == 0) {
        switch (c->function) {
            case OVSDB_F_LT:
            case OVSDB_F_LE:
            case OVSDB_F_EQ:
            case OVSDB_F_GE:
            case OVSDB_F_GT:
            case OVSDB_F_INCLUDES:
                return false;
            case OVSDB_F_NE:
            case OVSDB_F_EXCLUDES:
                return true;
        }
    } else if (ovsdb_type_is_scalar(type)
               || ovsdb_type_is_optional_scalar(type)) {
        int cmp = ovsdb_atom_compare_3way(&field->keys[0], &arg->keys[0],
                                          type->key.type);
        switch (c->function) {
        case OVSDB_F_LT:
            return cmp < 0;
        case OVSDB_F_LE:
            return cmp <= 0;
        case OVSDB_F_EQ:
        case OVSDB_F_INCLUDES:
            return cmp == 0;
        case OVSDB_F_NE:
        case OVSDB_F_EXCLUDES:
            return cmp != 0;
        case OVSDB_F_GE:
            return cmp >= 0;
        case OVSDB_F_GT:
            return cmp > 0;
        }
    } else {
        switch (c->function) {
        case OVSDB_F_EQ:
            return ovsdb_datum_equals(field, arg, type);
        case OVSDB_F_NE:
            return !ovsdb_datum_equals(field, arg, type);
        case OVSDB_F_INCLUDES:
            return ovsdb_datum_includes_all(arg, field, type);
        case OVSDB_F_EXCLUDES:
            return ovsdb_datum_excludes_all(arg, field, type);
        case OVSDB_F_LT:
        case OVSDB_F_LE:
        case OVSDB_F_GE:
        case OVSDB_F_GT:
            OVS_NOT_REACHED();
        }
    }

    OVS_NOT_REACHED();
}

bool
ovsdb_condition_evaluate(const struct ovsdb_row *row,
                         const struct ovsdb_condition *cnd)
{
    size_t i;

    for (i = 0; i < cnd->n_clauses; i++) {
        if (!ovsdb_clause_evaluate(row, &cnd->clauses[i])) {
            return false;
        }
    }

    return true;
}

void
ovsdb_condition_destroy(struct ovsdb_condition *cnd)
{
    size_t i;

    for (i = 0; i < cnd->n_clauses; i++) {
        ovsdb_clause_free(&cnd->clauses[i]);
    }
    free(cnd->clauses);
}
