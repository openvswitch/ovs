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
#include "openvswitch/json.h"
#include "ovsdb-error.h"
#include "row.h"

#include <string.h>

#include "table.h"
#include "util.h"

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

static struct ovsdb_error *
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

    if (json->type == JSON_TRUE || json->type == JSON_FALSE) {
        clause->function =
            json->type == JSON_TRUE ? OVSDB_F_TRUE : OVSDB_F_FALSE;

        /* Column and arg fields are not being used with boolean functions.
         * Use dummy values */
        clause->column = ovsdb_table_schema_get_column(ts, "_uuid");
        clause->index = clause->column->index;
        ovsdb_datum_init_default(&clause->arg, &clause->column->type);
        return NULL;
    }

    if (json->type != JSON_ARRAY
        || json->array.n != 3
        || json->array.elems[0]->type != JSON_STRING
        || json->array.elems[1]->type != JSON_STRING) {
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
    clause->index = clause->column->index;
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
    case OVSDB_F_TRUE:
    case OVSDB_F_FALSE:
        OVS_NOT_REACHED();
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

static int
compare_clauses_3way_with_data(const void *a_, const void *b_)
{
    const struct ovsdb_clause *a = a_;
    const struct ovsdb_clause *b = b_;
    int res;

    res = compare_clauses_3way(a, b);
    return res ? res : ovsdb_datum_compare_3way(&a->arg,
                                                &b->arg,
                                                &a->column->type);
 }

struct ovsdb_o_column {
    const struct ovsdb_column *column;
    struct hmap o_clauses;
};

struct ovsdb_o_clause {
    struct ovsdb_datum *arg;
    struct hmap_node hmap_node;
};

static void
ovsdb_condition_optimize(struct ovsdb_condition *cnd)
{
    size_t i;
    uint32_t hash;

    if (!cnd->optimized) {
        return;
    }

    for(i = 0; i < cnd->n_clauses; i++) {
        struct ovsdb_clause *clause = &cnd->clauses[i];

        if (clause->function != OVSDB_F_EQ) {
            continue;
        }

        struct ovsdb_o_clause *o_clause = xzalloc(sizeof *o_clause);
        struct ovsdb_o_column *o_column =
            shash_find_data(&cnd->o_columns, clause->column->name);

        if (!o_column) {
            o_column = xzalloc(sizeof *o_column);
            o_column->column = clause->column;
            hmap_init(&o_column->o_clauses);
            shash_add(&cnd->o_columns, clause->column->name, o_column);
        }
        o_clause->arg = &clause->arg;
        hash = ovsdb_datum_hash(&clause->arg, &clause->column->type, 0);
        hmap_insert(&o_column->o_clauses, &o_clause->hmap_node, hash);
    }
}

static void
ovsdb_condition_optimize_destroy(struct ovsdb_condition *cnd)
{
     struct shash_node *node, *next;

     SHASH_FOR_EACH_SAFE (node, next, &cnd->o_columns) {
         struct ovsdb_o_column *o_column = node->data;
         struct ovsdb_o_clause *c, *c_next;

         HMAP_FOR_EACH_SAFE(c, c_next, hmap_node, &o_column->o_clauses) {
             hmap_remove(&o_column->o_clauses, &c->hmap_node);
             free(c);
         }
         hmap_destroy(&o_column->o_clauses);
         shash_delete(&cnd->o_columns, node);
         free(o_column);
     }
     shash_destroy(&cnd->o_columns);
}

struct ovsdb_error *
ovsdb_condition_from_json(const struct ovsdb_table_schema *ts,
                          const struct json *json,
                          struct ovsdb_symbol_table *symtab,
                          struct ovsdb_condition *cnd)
{
    const struct json_array *array = json_array(json);
    size_t i;

    ovsdb_condition_init(cnd);
    cnd->clauses = xmalloc(array->n * sizeof *cnd->clauses);

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
        if (cnd->clauses[i].function > OVSDB_F_EQ) {
            cnd->optimized = false;
        }
    }

    /* A real database would have a query optimizer here. */
    qsort(cnd->clauses, cnd->n_clauses, sizeof *cnd->clauses,
          compare_clauses_3way_with_data);

    ovsdb_condition_optimize(cnd);

    return NULL;
}

static struct json *
ovsdb_clause_to_json(const struct ovsdb_clause *clause)
{
    if (clause->function != OVSDB_F_TRUE &&
        clause->function != OVSDB_F_FALSE) {
        return json_array_create_3(
                json_string_create(clause->column->name),
                json_string_create(ovsdb_function_to_string(clause->function)),
                ovsdb_datum_to_json(&clause->arg, &clause->column->type));
    }

    return json_boolean_create(clause->function == OVSDB_F_TRUE);
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
ovsdb_clause_evaluate(const struct ovsdb_datum *fields,
                      const struct ovsdb_clause *c,
                      unsigned int index_map[])
{
    const struct ovsdb_datum *field = &fields[index_map ?
                                              index_map[c->column->index] :
                                              c->column->index];
    const struct ovsdb_datum *arg = &c->arg;
    const struct ovsdb_type *type = &c->column->type;

    if (c->function == OVSDB_F_TRUE ||
        c->function == OVSDB_F_FALSE) {
        return c->function == OVSDB_F_TRUE;
    }
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
            case OVSDB_F_TRUE:
            case OVSDB_F_FALSE:
                OVS_NOT_REACHED();
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
        case OVSDB_F_TRUE:
        case OVSDB_F_FALSE:
            OVS_NOT_REACHED();
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
        case OVSDB_F_TRUE:
        case OVSDB_F_FALSE:
            OVS_NOT_REACHED();
        }
    }

    OVS_NOT_REACHED();
}

static void
ovsdb_clause_clone(struct ovsdb_clause *new, struct ovsdb_clause *old)
{
    new->function = old->function;
    new->column = old->column;
    ovsdb_datum_clone(&new->arg,
                      &old->arg,
                      &old->column->type);
}

bool
ovsdb_condition_match_every_clause(const struct ovsdb_row *row,
                                   const struct ovsdb_condition *cnd)
{
    size_t i;

    for (i = 0; i < cnd->n_clauses; i++) {
        if (!ovsdb_clause_evaluate(row->fields, &cnd->clauses[i], NULL)) {
            return false;
        }
    }

    return true;
}

static bool
ovsdb_condition_match_any_clause_optimized(const struct ovsdb_datum *row_datum,
                                           const struct ovsdb_condition *cnd,
                                           unsigned int index_map[])
{
    if (ovsdb_condition_is_true(cnd)) {
        return true;
    }

    struct shash_node *node;
    SHASH_FOR_EACH (node, &cnd->o_columns) {
        struct ovsdb_o_column *o_column = node->data;
        const struct ovsdb_column *column = o_column->column;
        const struct ovsdb_datum *arg = &row_datum[index_map ?
                                                   index_map[column->index] :
                                                   column->index];
        uint32_t hash = ovsdb_datum_hash(arg, &column->type, 0);
        struct ovsdb_o_clause *o_clause;

        HMAP_FOR_EACH_WITH_HASH(o_clause, hmap_node, hash, &o_column->o_clauses) {
            if (ovsdb_datum_equals(arg, o_clause->arg, &column->type)) {
                return true;
            }
        }
    }
    return false;
}

/* Returns true if condition evaluation of one of the clauses is
 * true. index_map[] is an optional array that if exists indicates a mapping
 * between indexing row_datum to the indexes in ovsdb_column */
bool
ovsdb_condition_match_any_clause(const struct ovsdb_datum *row_datum,
                                 const struct ovsdb_condition *cnd,
                                 unsigned int index_map[])
{
    size_t i;

    if (cnd->optimized) {
        return ovsdb_condition_match_any_clause_optimized(row_datum, cnd,
                                                          index_map);
    }

    for (i = 0; i < cnd->n_clauses; i++) {
        if (ovsdb_clause_evaluate(row_datum, &cnd->clauses[i], index_map)) {
            return true;
        }
    }

    return false;
}

void
ovsdb_condition_destroy(struct ovsdb_condition *cnd)
{
    size_t i;

    for (i = 0; i < cnd->n_clauses; i++) {
        ovsdb_clause_free(&cnd->clauses[i]);
    }
    free(cnd->clauses);
    cnd->n_clauses = 0;

    ovsdb_condition_optimize_destroy(cnd);
}

void
ovsdb_condition_init(struct ovsdb_condition *cnd)
{
    cnd->clauses = NULL;
    cnd->n_clauses = 0;
    cnd->optimized = true;
    shash_init(&cnd->o_columns);
}

bool
ovsdb_condition_empty(const struct ovsdb_condition *cnd)
{
    return cnd->n_clauses == 0;
}

int
ovsdb_condition_cmp_3way(const struct ovsdb_condition *a,
                         const struct ovsdb_condition *b)
{
    size_t i;
    int res;

    if (a->n_clauses != b->n_clauses) {
        return a->n_clauses < b->n_clauses ? -1 : 1;
    }

    /* We assume clauses are sorted */
    for (i = 0; i < a->n_clauses; i++) {
        res = (compare_clauses_3way_with_data(&a->clauses[i], &b->clauses[i]));
        if (res != 0) {
            return res;
        }
    }

    return 0;
}

void
ovsdb_condition_clone(struct ovsdb_condition *to,
                      const struct ovsdb_condition *from)
{
    size_t i;

    ovsdb_condition_init(to);

    to->clauses = xzalloc(from->n_clauses * sizeof *to->clauses);

    for (i = 0; i < from->n_clauses; i++) {
        ovsdb_clause_clone(&to->clauses[i], &from->clauses[i]);
    }
    to->n_clauses = from->n_clauses;
    to->optimized = from->optimized;
    if (to->optimized) {
        ovsdb_condition_optimize(to);
    }
}

/* Return true if ovsdb_condition_match_any_clause() will return true on
 * any row */
bool
ovsdb_condition_is_true(const struct ovsdb_condition *cond)
{
    return (!cond->n_clauses ||
       (cond->n_clauses >= 1 && (cond->clauses[0].function == OVSDB_F_TRUE)) ||
       (cond->n_clauses >= 2 && (cond->clauses[1].function == OVSDB_F_TRUE)));
}

bool
ovsdb_condition_is_false(const struct ovsdb_condition *cond)
{
    return ((cond->n_clauses == 1) &&
            (cond->clauses[0].function == OVSDB_F_FALSE));
 }

const struct ovsdb_column **
ovsdb_condition_get_columns(const struct ovsdb_condition *cond,
                            size_t *n_columns)
{
    const struct ovsdb_column **columns;
    size_t i;

    columns = xmalloc(cond->n_clauses * sizeof *columns);
    for (i = 0; i < cond->n_clauses; i++) {
        columns[i] = cond->clauses[i].column;
    }
    *n_columns = i;

    return columns;
}
