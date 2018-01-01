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

#include <limits.h>

#include "column.h"
#include "condition.h"
#include "file.h"
#include "openvswitch/json.h"
#include "mutation.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "query.h"
#include "rbac.h"
#include "row.h"
#include "server.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"

struct ovsdb_execution {
    struct ovsdb *db;
    const struct ovsdb_session *session;
    struct ovsdb_txn *txn;
    struct ovsdb_symbol_table *symtab;
    bool durable;
    const char *role;
    const char *id;

    /* Triggers. */
    long long int elapsed_msec;
    long long int timeout_msec;
};

typedef struct ovsdb_error *ovsdb_operation_executor(struct ovsdb_execution *,
                                                     struct ovsdb_parser *,
                                                     struct json *result);

static ovsdb_operation_executor ovsdb_execute_insert;
static ovsdb_operation_executor ovsdb_execute_select;
static ovsdb_operation_executor ovsdb_execute_update;
static ovsdb_operation_executor ovsdb_execute_mutate;
static ovsdb_operation_executor ovsdb_execute_delete;
static ovsdb_operation_executor ovsdb_execute_wait;
static ovsdb_operation_executor ovsdb_execute_commit;
static ovsdb_operation_executor ovsdb_execute_abort;
static ovsdb_operation_executor ovsdb_execute_comment;
static ovsdb_operation_executor ovsdb_execute_assert;

static ovsdb_operation_executor *
lookup_executor(const char *name, bool *read_only)
{
    struct ovsdb_operation {
        const char *name;
        bool read_only;
        ovsdb_operation_executor *executor;
    };

    static const struct ovsdb_operation operations[] = {
        { "insert", false, ovsdb_execute_insert },
        { "select", true, ovsdb_execute_select },
        { "update", false, ovsdb_execute_update },
        { "mutate", false, ovsdb_execute_mutate },
        { "delete", false, ovsdb_execute_delete },
        { "wait", true, ovsdb_execute_wait },
        { "commit", false, ovsdb_execute_commit },
        { "abort", true, ovsdb_execute_abort },
        { "comment", true, ovsdb_execute_comment },
        { "assert", true, ovsdb_execute_assert },
    };

    size_t i;

    for (i = 0; i < ARRAY_SIZE(operations); i++) {
        const struct ovsdb_operation *c = &operations[i];
        if (!strcmp(c->name, name)) {
            *read_only = c->read_only;
            return c->executor;
        }
    }
    return NULL;
}

/* On success, returns a transaction and stores the results to return to the
 * client in '*resultsp'.
 *
 * On failure, returns NULL.  If '*resultsp' is nonnull, then it is the results
 * to return to the client.  If '*resultsp' is null, then the execution failed
 * due to an unsatisfied "wait" operation and '*timeout_msec' is the time at
 * which the transaction will time out.  (If 'timeout_msec' is null, this case
 * never occurs--instead, an unsatisfied "wait" unconditionally fails.) */
struct ovsdb_txn *
ovsdb_execute_compose(struct ovsdb *db, const struct ovsdb_session *session,
                      const struct json *params, bool read_only,
                      const char *role, const char *id,
                      long long int elapsed_msec, long long int *timeout_msec,
                      bool *durable, struct json **resultsp)
{
    struct ovsdb_execution x;
    struct ovsdb_error *error;
    struct json *results;
    size_t n_operations;
    size_t i;

    *durable = false;
    if (params->type != JSON_ARRAY
        || !params->u.array.n
        || params->u.array.elems[0]->type != JSON_STRING
        || strcmp(params->u.array.elems[0]->u.string, db->schema->name)) {
        if (params->type != JSON_ARRAY) {
            error = ovsdb_syntax_error(params, NULL, "array expected");
        } else {
            error = ovsdb_syntax_error(params, NULL, "database name expected "
                                       "as first parameter");
        }

        *resultsp = ovsdb_error_to_json_free(error);
        return NULL;
    }

    x.db = db;
    x.session = session;
    x.txn = ovsdb_txn_create(db);
    x.symtab = ovsdb_symbol_table_create();
    x.durable = false;
    x.role = role;
    x.id = id;
    x.elapsed_msec = elapsed_msec;
    x.timeout_msec = LLONG_MAX;
    results = NULL;

    results = json_array_create_empty();
    n_operations = params->u.array.n - 1;
    error = NULL;
    for (i = 1; i <= n_operations; i++) {
        struct json *operation = params->u.array.elems[i];
        struct ovsdb_error *parse_error;
        struct ovsdb_parser parser;
        struct json *result;
        const struct json *op;
        const char *op_name = NULL;
        bool ro = false;

        /* Parse and execute operation. */
        ovsdb_parser_init(&parser, operation,
                          "ovsdb operation %"PRIuSIZE" of %"PRIuSIZE, i,
                          n_operations);
        op = ovsdb_parser_member(&parser, "op", OP_ID);
        result = json_object_create();
        if (op) {
            op_name = json_string(op);
            ovsdb_operation_executor *executor = lookup_executor(op_name, &ro);
            if (executor) {
                error = executor(&x, &parser, result);
            } else {
                ovsdb_parser_raise_error(&parser, "No operation \"%s\"",
                                         op_name);
            }
        } else {
            ovs_assert(ovsdb_parser_has_error(&parser));
        }

        /* A parse error overrides any other error.
         * An error overrides any other result. */
        parse_error = ovsdb_parser_finish(&parser);
        if (parse_error) {
            ovsdb_error_destroy(error);
            error = parse_error;
        }
        /* Create read-only violation error if there is one. */
        if (!ro && !error) {
            if (read_only) {
                error = ovsdb_error("not allowed",
                                    "%s operation not allowed when "
                                    "database server is in read only mode",
                                    op_name);
            } else if (db->schema->name[0] == '_') {
                error = ovsdb_error("not allowed",
                                    "%s operation not allowed on "
                                    "table in reserved database %s",
                                    op_name, db->schema->name);
            }
        }
        if (error) {
            json_destroy(result);
            json_array_add(results, ovsdb_error_to_json(error));
            if (!strcmp(ovsdb_error_get_tag(error), "not supported")
                && timeout_msec) {
                *timeout_msec = x.timeout_msec;
                json_destroy(results);
                results = NULL;
                goto exit;
            }
            break;
        }
        json_array_add(results, result);
    }
    while (json_array(results)->n < n_operations) {
        json_array_add(results, json_null_create());
    }

exit:
    if (error) {
        ovsdb_txn_abort(x.txn);
        x.txn = NULL;

        ovsdb_error_destroy(error);
    }
    *resultsp = results;
    *durable = x.durable;
    ovsdb_symbol_table_destroy(x.symtab);

    return x.txn;
}

struct json *
ovsdb_execute(struct ovsdb *db, const struct ovsdb_session *session,
              const struct json *params, bool read_only,
              const char *role, const char *id,
              long long int elapsed_msec, long long int *timeout_msec)
{
    bool durable;
    struct json *results;
    struct ovsdb_txn *txn = ovsdb_execute_compose(
        db, session, params, read_only, role, id, elapsed_msec, timeout_msec,
        &durable, &results);
    if (!txn) {
        return results;
    }

    struct ovsdb_error *error = ovsdb_txn_propose_commit_block(txn, durable);
    if (error) {
        json_array_add(results, ovsdb_error_to_json(error));
        ovsdb_error_destroy(error);
    }
    return results;
}

static struct ovsdb_error *
ovsdb_execute_commit(struct ovsdb_execution *x, struct ovsdb_parser *parser,
                     struct json *result OVS_UNUSED)
{
    const struct json *durable;

    durable = ovsdb_parser_member(parser, "durable", OP_BOOLEAN);
    if (durable && json_boolean(durable)) {
        x->durable = true;
    }
    return NULL;
}

static struct ovsdb_error *
ovsdb_execute_abort(struct ovsdb_execution *x OVS_UNUSED,
                    struct ovsdb_parser *parser OVS_UNUSED,
                    struct json *result OVS_UNUSED)
{
    return ovsdb_error("aborted", "aborted by request");
}

static struct ovsdb_table *
parse_table(struct ovsdb_execution *x,
            struct ovsdb_parser *parser, const char *member)
{
    struct ovsdb_table *table;
    const char *table_name;
    const struct json *json;

    json = ovsdb_parser_member(parser, member, OP_ID);
    if (!json) {
        return NULL;
    }
    table_name = json_string(json);

    table = shash_find_data(&x->db->tables, table_name);
    if (!table) {
        ovsdb_parser_raise_error(parser, "No table named %s.", table_name);
    }
    return table;
}

static OVS_WARN_UNUSED_RESULT struct ovsdb_error *
parse_row(const struct json *json, const struct ovsdb_table *table,
          struct ovsdb_symbol_table *symtab,
          struct ovsdb_row **rowp, struct ovsdb_column_set *columns)
{
    struct ovsdb_error *error;
    struct ovsdb_row *row;

    *rowp = NULL;

    if (!table) {
        return OVSDB_BUG("null table");
    }
    if (!json) {
        return OVSDB_BUG("null row");
    }

    row = ovsdb_row_create(table);
    error = ovsdb_row_from_json(row, json, symtab, columns);
    if (error) {
        ovsdb_row_destroy(row);
        return error;
    } else {
        *rowp = row;
        return NULL;
    }
}

static struct ovsdb_error *
ovsdb_execute_insert(struct ovsdb_execution *x, struct ovsdb_parser *parser,
                     struct json *result)
{
    struct ovsdb_table *table;
    struct ovsdb_row *row = NULL;
    const struct json *uuid_name, *row_json;
    struct ovsdb_error *error;
    struct uuid row_uuid;

    table = parse_table(x, parser, "table");
    uuid_name = ovsdb_parser_member(parser, "uuid-name", OP_ID | OP_OPTIONAL);
    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    error = ovsdb_parser_get_error(parser);
    if (error) {
        return error;
    }

    if (uuid_name) {
        struct ovsdb_symbol *symbol;

        symbol = ovsdb_symbol_table_insert(x->symtab, json_string(uuid_name));
        if (symbol->created) {
            return ovsdb_syntax_error(uuid_name, "duplicate uuid-name",
                                      "This \"uuid-name\" appeared on an "
                                      "earlier \"insert\" operation.");
        }
        row_uuid = symbol->uuid;
        symbol->created = true;
    } else {
        uuid_generate(&row_uuid);
    }

    if (!error) {
        error = parse_row(row_json, table, x->symtab, &row, NULL);
    }
    if (!error) {
        /* Check constraints for columns not included in "row", in case the
         * default values do not satisfy the constraints.  We could check only
         * the columns that have their default values by supplying an
         * ovsdb_column_set to parse_row() above, but I suspect that this is
         * cheaper.  */
        const struct shash_node *node;

        SHASH_FOR_EACH (node, &table->schema->columns) {
            const struct ovsdb_column *column = node->data;
            const struct ovsdb_datum *datum = &row->fields[column->index];

            /* If there are 0 keys or pairs, there's nothing to check.
             * If there is 1, it might be a default value.
             * If there are more, it can't be a default value, so the value has
             * already been checked. */
            if (datum->n == 1) {
                error = ovsdb_datum_check_constraints(datum, &column->type);
                if (error) {
                    break;
                }
            }
        }
    }

    if (!error && !ovsdb_rbac_insert(x->db, table, row, x->role, x->id)) {
        error = ovsdb_perm_error("RBAC rules for client \"%s\" role \"%s\" "
                                 "prohibit row insertion into table \"%s\".",
                                 x->id, x->role, table->schema->name);
    }

    if (!error) {
        *ovsdb_row_get_uuid_rw(row) = row_uuid;
        ovsdb_txn_row_insert(x->txn, row);
        json_object_put(result, "uuid",
                        ovsdb_datum_to_json(&row->fields[OVSDB_COL_UUID],
                                            &ovsdb_type_uuid));
    } else {
        ovsdb_row_destroy(row);
    }
    return error;
}

static struct ovsdb_error *
ovsdb_execute_select(struct ovsdb_execution *x, struct ovsdb_parser *parser,
                     struct json *result)
{
    struct ovsdb_table *table;
    const struct json *where, *columns_json, *sort_json;
    struct ovsdb_condition condition = OVSDB_CONDITION_INITIALIZER(&condition);
    struct ovsdb_column_set columns = OVSDB_COLUMN_SET_INITIALIZER;
    struct ovsdb_column_set sort = OVSDB_COLUMN_SET_INITIALIZER;
    struct ovsdb_error *error;

    table = parse_table(x, parser, "table");
    where = ovsdb_parser_member(parser, "where", OP_ARRAY);
    columns_json = ovsdb_parser_member(parser, "columns",
                                       OP_ARRAY | OP_OPTIONAL);
    sort_json = ovsdb_parser_member(parser, "sort", OP_ARRAY | OP_OPTIONAL);

    error = ovsdb_parser_get_error(parser);
    if (!error) {
        error = ovsdb_condition_from_json(table->schema, where, x->symtab,
                                          &condition);
    }
    if (!error) {
        error = ovsdb_column_set_from_json(columns_json, table->schema,
                                           &columns);
    }
    if (!error) {
        error = ovsdb_column_set_from_json(sort_json, table->schema, &sort);
    }
    if (!error) {
        struct ovsdb_row_set rows = OVSDB_ROW_SET_INITIALIZER;

        ovsdb_query_distinct(table, &condition, &columns, &rows);
        ovsdb_row_set_sort(&rows, &sort);
        json_object_put(result, "rows",
                        ovsdb_row_set_to_json(&rows, &columns));

        ovsdb_row_set_destroy(&rows);
    }

    ovsdb_column_set_destroy(&columns);
    ovsdb_column_set_destroy(&sort);
    ovsdb_condition_destroy(&condition);

    return error;
}

struct update_row_cbdata {
    size_t n_matches;
    struct ovsdb_txn *txn;
    const struct ovsdb_row *row;
    const struct ovsdb_column_set *columns;
    const char *role;
    const char *id;
};

static bool
update_row_cb(const struct ovsdb_row *row, void *ur_)
{
    struct update_row_cbdata *ur = ur_;

    ur->n_matches++;
    if (!ovsdb_row_equal_columns(row, ur->row, ur->columns)) {
        ovsdb_row_update_columns(ovsdb_txn_row_modify(ur->txn, row),
                                 ur->row, ur->columns);
    }

    return true;
}

static struct ovsdb_error *
ovsdb_execute_update(struct ovsdb_execution *x, struct ovsdb_parser *parser,
                     struct json *result)
{
    struct ovsdb_table *table;
    const struct json *where, *row_json;
    struct ovsdb_condition condition = OVSDB_CONDITION_INITIALIZER(&condition);
    struct ovsdb_column_set columns = OVSDB_COLUMN_SET_INITIALIZER;
    struct ovsdb_row *row = NULL;
    struct update_row_cbdata ur;
    struct ovsdb_error *error;

    table = parse_table(x, parser, "table");
    where = ovsdb_parser_member(parser, "where", OP_ARRAY);
    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    error = ovsdb_parser_get_error(parser);
    if (!error) {
        error = parse_row(row_json, table, x->symtab, &row, &columns);
    }
    if (!error) {
        size_t i;

        for (i = 0; i < columns.n_columns; i++) {
            const struct ovsdb_column *column = columns.columns[i];

            if (!column->mutable) {
                error = ovsdb_syntax_error(parser->json,
                                           "constraint violation",
                                           "Cannot update immutable column %s "
                                           "in table %s.",
                                           column->name, table->schema->name);
                break;
            }
        }
    }
    if (!error) {
        error = ovsdb_condition_from_json(table->schema, where, x->symtab,
                                          &condition);
    }
    if (!error) {
        ur.n_matches = 0;
        ur.txn = x->txn;
        ur.row = row;
        ur.columns = &columns;
        if (ovsdb_rbac_update(x->db, table, &columns, &condition, x->role,
                              x->id)) {
            ovsdb_query(table, &condition, update_row_cb, &ur);
        } else {
            error = ovsdb_perm_error("RBAC rules for client \"%s\" role "
                                     "\"%s\" prohibit modification of "
                                     "table \"%s\".",
                                     x->id, x->role, table->schema->name);
        }
        json_object_put(result, "count", json_integer_create(ur.n_matches));
    }

    ovsdb_row_destroy(row);
    ovsdb_column_set_destroy(&columns);
    ovsdb_condition_destroy(&condition);

    return error;
}

struct mutate_row_cbdata {
    size_t n_matches;
    struct ovsdb_txn *txn;
    const struct ovsdb_mutation_set *mutations;
    struct ovsdb_error **error;
};

static bool
mutate_row_cb(const struct ovsdb_row *row, void *mr_)
{
    struct mutate_row_cbdata *mr = mr_;

    mr->n_matches++;
    *mr->error = ovsdb_mutation_set_execute(ovsdb_txn_row_modify(mr->txn, row),
                                            mr->mutations);
    return *mr->error == NULL;
}

static struct ovsdb_error *
ovsdb_execute_mutate(struct ovsdb_execution *x, struct ovsdb_parser *parser,
                     struct json *result)
{
    struct ovsdb_table *table;
    const struct json *where;
    const struct json *mutations_json;
    struct ovsdb_condition condition = OVSDB_CONDITION_INITIALIZER(&condition);
    struct ovsdb_mutation_set mutations = OVSDB_MUTATION_SET_INITIALIZER;
    struct ovsdb_row *row = NULL;
    struct mutate_row_cbdata mr;
    struct ovsdb_error *error;

    table = parse_table(x, parser, "table");
    where = ovsdb_parser_member(parser, "where", OP_ARRAY);
    mutations_json = ovsdb_parser_member(parser, "mutations", OP_ARRAY);
    error = ovsdb_parser_get_error(parser);
    if (!error) {
        error = ovsdb_mutation_set_from_json(table->schema, mutations_json,
                                             x->symtab, &mutations);
    }
    if (!error) {
        error = ovsdb_condition_from_json(table->schema, where, x->symtab,
                                          &condition);
    }
    if (!error) {
        mr.n_matches = 0;
        mr.txn = x->txn;
        mr.mutations = &mutations;
        mr.error = &error;
        if (ovsdb_rbac_mutate(x->db, table, &mutations, &condition, x->role,
                              x->id)) {
            ovsdb_query(table, &condition, mutate_row_cb, &mr);
        } else {
            error = ovsdb_perm_error("RBAC rules for client \"%s\" role "
                                     "\"%s\" prohibit mutate operation on "
                                     "table \"%s\".",
                                     x->id, x->role, table->schema->name);
        }
        json_object_put(result, "count", json_integer_create(mr.n_matches));
    }

    ovsdb_row_destroy(row);
    ovsdb_mutation_set_destroy(&mutations);
    ovsdb_condition_destroy(&condition);

    return error;
}

struct delete_row_cbdata {
    size_t n_matches;
    const struct ovsdb_table *table;
    struct ovsdb_txn *txn;
};

static bool
delete_row_cb(const struct ovsdb_row *row, void *dr_)
{
    struct delete_row_cbdata *dr = dr_;

    dr->n_matches++;
    ovsdb_txn_row_delete(dr->txn, row);

    return true;
}

static struct ovsdb_error *
ovsdb_execute_delete(struct ovsdb_execution *x, struct ovsdb_parser *parser,
                     struct json *result)
{
    struct ovsdb_table *table;
    const struct json *where;
    struct ovsdb_condition condition = OVSDB_CONDITION_INITIALIZER(&condition);
    struct ovsdb_error *error;

    where = ovsdb_parser_member(parser, "where", OP_ARRAY);
    table = parse_table(x, parser, "table");
    error = ovsdb_parser_get_error(parser);
    if (!error) {
        error = ovsdb_condition_from_json(table->schema, where, x->symtab,
                                          &condition);
    }
    if (!error) {
        struct delete_row_cbdata dr;

        dr.n_matches = 0;
        dr.table = table;
        dr.txn = x->txn;

        if (ovsdb_rbac_delete(x->db, table, &condition, x->role, x->id)) {
            ovsdb_query(table, &condition, delete_row_cb, &dr);
        } else {
            error = ovsdb_perm_error("RBAC rules for client \"%s\" role "
                                     "\"%s\" prohibit row deletion from "
                                     "table \"%s\".",
                                     x->id, x->role, table->schema->name);
        }
        json_object_put(result, "count", json_integer_create(dr.n_matches));
    }

    ovsdb_condition_destroy(&condition);

    return error;
}

struct wait_auxdata {
    struct ovsdb_row_hash *actual;
    struct ovsdb_row_hash *expected;
    bool *equal;
};

static bool
ovsdb_execute_wait_query_cb(const struct ovsdb_row *row, void *aux_)
{
    struct wait_auxdata *aux = aux_;

    if (ovsdb_row_hash_contains(aux->expected, row)) {
        ovsdb_row_hash_insert(aux->actual, row);
        return true;
    } else {
        /* The query row isn't in the expected result set, so the actual and
         * expected results sets definitely differ and we can short-circuit the
         * rest of the query. */
        *aux->equal = false;
        return false;
    }
}

static struct ovsdb_error *
ovsdb_execute_wait(struct ovsdb_execution *x, struct ovsdb_parser *parser,
                   struct json *result OVS_UNUSED)
{
    struct ovsdb_table *table;
    const struct json *timeout, *where, *columns_json, *until, *rows;
    struct ovsdb_condition condition = OVSDB_CONDITION_INITIALIZER(&condition);
    struct ovsdb_column_set columns = OVSDB_COLUMN_SET_INITIALIZER;
    struct ovsdb_row_hash expected = OVSDB_ROW_HASH_INITIALIZER(expected);
    struct ovsdb_row_hash actual = OVSDB_ROW_HASH_INITIALIZER(actual);
    struct ovsdb_error *error;
    struct wait_auxdata aux;
    long long int timeout_msec = 0;
    size_t i;

    timeout = ovsdb_parser_member(parser, "timeout", OP_NUMBER | OP_OPTIONAL);
    where = ovsdb_parser_member(parser, "where", OP_ARRAY);
    columns_json = ovsdb_parser_member(parser, "columns",
                                       OP_ARRAY | OP_OPTIONAL);
    until = ovsdb_parser_member(parser, "until", OP_STRING);
    rows = ovsdb_parser_member(parser, "rows", OP_ARRAY);
    table = parse_table(x, parser, "table");
    error = ovsdb_parser_get_error(parser);
    if (!error) {
        error = ovsdb_condition_from_json(table->schema, where, x->symtab,
                                          &condition);
    }
    if (!error) {
        error = ovsdb_column_set_from_json(columns_json, table->schema,
                                           &columns);
    }
    if (!error) {
        if (timeout) {
            timeout_msec = MIN(LLONG_MAX, json_real(timeout));
            if (timeout_msec < 0) {
                error = ovsdb_syntax_error(timeout, NULL,
                                           "timeout must be nonnegative");
            } else if (timeout_msec < x->timeout_msec) {
                x->timeout_msec = timeout_msec;
            }
        } else {
            timeout_msec = LLONG_MAX;
        }
    }
    if (!error) {
        if (strcmp(json_string(until), "==")
            && strcmp(json_string(until), "!=")) {
            error = ovsdb_syntax_error(until, NULL,
                                       "\"until\" must be \"==\" or \"!=\"");
        }
    }
    if (!error) {
        /* Parse "rows" into 'expected'. */
        ovsdb_row_hash_init(&expected, &columns);
        for (i = 0; i < rows->u.array.n; i++) {
            struct ovsdb_row *row;

            row = ovsdb_row_create(table);
            error = ovsdb_row_from_json(row, rows->u.array.elems[i], x->symtab,
                                        NULL);
            if (error) {
                ovsdb_row_destroy(row);
                break;
            }

            if (!ovsdb_row_hash_insert(&expected, row)) {
                /* XXX Perhaps we should abort with an error or log a
                 * warning. */
                ovsdb_row_destroy(row);
            }
        }
    }
    if (!error) {
        /* Execute query. */
        bool equal = true;
        ovsdb_row_hash_init(&actual, &columns);
        aux.actual = &actual;
        aux.expected = &expected;
        aux.equal = &equal;
        ovsdb_query(table, &condition, ovsdb_execute_wait_query_cb, &aux);
        if (equal) {
            /* We know that every row in 'actual' is also in 'expected'.  We
             * also know that all of the rows in 'actual' are distinct and that
             * all of the rows in 'expected' are distinct.  Therefore, if
             * 'actual' and 'expected' have the same number of rows, then they
             * have the same content. */
            size_t n_actual = ovsdb_row_hash_count(&actual);
            size_t n_expected = ovsdb_row_hash_count(&expected);
            equal = n_actual == n_expected;
        }
        if (!strcmp(json_string(until), "==") != equal) {
            if (timeout && x->elapsed_msec >= timeout_msec) {
                if (x->elapsed_msec) {
                    error = ovsdb_error("timed out",
                                        "\"wait\" timed out after %lld ms",
                                        x->elapsed_msec);
                } else {
                    error = ovsdb_error("timed out",
                                        "\"where\" clause test failed");
                }
            } else {
                /* ovsdb_execute() will change this, if triggers really are
                 * supported. */
                error = ovsdb_error("not supported", "triggers not supported");
            }
        }
    }


    ovsdb_row_hash_destroy(&expected, true);
    ovsdb_row_hash_destroy(&actual, false);
    ovsdb_column_set_destroy(&columns);
    ovsdb_condition_destroy(&condition);

    return error;
}

static struct ovsdb_error *
ovsdb_execute_comment(struct ovsdb_execution *x, struct ovsdb_parser *parser,
                      struct json *result OVS_UNUSED)
{
    const struct json *comment;

    comment = ovsdb_parser_member(parser, "comment", OP_STRING);
    if (!comment) {
        return NULL;
    }
    ovsdb_txn_add_comment(x->txn, json_string(comment));

    return NULL;
}

static struct ovsdb_error *
ovsdb_execute_assert(struct ovsdb_execution *x, struct ovsdb_parser *parser,
                     struct json *result OVS_UNUSED)
{
    const struct json *lock_name;

    lock_name = ovsdb_parser_member(parser, "lock", OP_ID);
    if (!lock_name) {
        return NULL;
    }

    if (x->session) {
        const struct ovsdb_lock_waiter *waiter;

        waiter = ovsdb_session_get_lock_waiter(x->session,
                                               json_string(lock_name));
        if (waiter && ovsdb_lock_waiter_is_owner(waiter)) {
            return NULL;
        }
    }

    return ovsdb_error("not owner", "Asserted lock %s not held.",
                       json_string(lock_name));
}
