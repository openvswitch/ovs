/*
 * Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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

#include <ctype.h>
#include <getopt.h>
#include <unistd.h>

#include "db-ctl-base.h"

#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/json.h"
#include "openvswitch/vlog.h"
#include "ovsdb-data.h"
#include "ovsdb-idl.h"
#include "ovsdb-idl-provider.h"
#include "openvswitch/shash.h"
#include "sset.h"
#include "svec.h"
#include "string.h"
#include "table.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(db_ctl_base);

/* This array defines the 'show' command output format.  User can check the
 * definition in utilities/ovs-vsctl.c as reference.
 *
 * Particularly, if an element in 'columns[]' represents a reference to
 * another table, the referred table must also be defined as an entry in
 * in 'cmd_show_tables[]'.
 *
 * The definition must end with an all-NULL entry.  It is initalized once
 * when ctl_init() is called.
 *
 * */
static const struct cmd_show_table *cmd_show_tables;

/* ctl_exit() is called by ctl_fatal(). User can optionally supply an exit
 * function ctl_exit_func() via ctl_init. If supplied, this function will
 * be called by ctl_exit()
 */
static void (*ctl_exit_func)(int status) = NULL;
OVS_NO_RETURN static void ctl_exit(int status);

/* IDL class. */
static const struct ovsdb_idl_class *idl_class;

/* Two arrays with 'n_classes' elements, which represent the tables in this
 * database and how the user can refer to their rows. */
static const struct ctl_table_class *ctl_classes;
static const struct ovsdb_idl_table_class *idl_classes;
static size_t n_classes;

static struct shash all_commands = SHASH_INITIALIZER(&all_commands);
static char *get_table(const char *, const struct ovsdb_idl_table_class **);
static char *set_column(const struct ovsdb_idl_table_class *,
                        const struct ovsdb_idl_row *, const char *,
                        struct ovsdb_symbol_table *);


static struct option *
find_option(const char *name, struct option *options, size_t n_options)
{
    size_t i;

    for (i = 0; i < n_options; i++) {
        if (!strcmp(options[i].name, name)) {
            return &options[i];
        }
    }
    return NULL;
}

static struct option *
add_option(struct option **optionsp, size_t *n_optionsp,
           size_t *allocated_optionsp)
{
    if (*n_optionsp >= *allocated_optionsp) {
        *optionsp = x2nrealloc(*optionsp, allocated_optionsp,
                               sizeof **optionsp);
    }
    return &(*optionsp)[(*n_optionsp)++];
}

/* Converts the command arguments into format that can be parsed by
 * bash completion script.
 *
 * Therein, arguments will be attached with following prefixes:
 *
 *    !argument :: The argument is required
 *    ?argument :: The argument is optional
 *    *argument :: The argument may appear any number (0 or more) times
 *    +argument :: The argument may appear one or more times
 *
 */
static void
print_command_arguments(const struct ctl_command_syntax *command)
{
    /*
     * The argument string is parsed in reverse.  We use a stack 'oew_stack' to
     * keep track of nested optionals.  Whenever a ']' is encountered, we push
     * a bit to 'oew_stack'.  The bit is set to 1 if the ']' is not nested.
     * Subsequently, we pop an entry everytime '[' is met.
     *
     * We use 'whole_word_is_optional' value to decide whether or not a ! or +
     * should be added on encountering a space: if the optional surrounds the
     * whole word then it shouldn't be, but if it is only a part of the word
     * (i.e. [key=]value), it should be.
     */
    uint32_t oew_stack = 0;

    const char *arguments = command->arguments;
    int length = strlen(arguments);
    if (!length) {
        return;
    }

    /* Output buffer, written backward from end. */
    char *output = xmalloc(2 * length);
    char *outp = output + 2 * length;
    *--outp = '\0';

    bool in_repeated = false;
    bool whole_word_is_optional = false;

    for (const char *inp = arguments + length; inp > arguments; ) {
        switch (*--inp) {
        case ']':
            oew_stack <<= 1;
            if (inp[1] == '\0' || inp[1] == ' ' || inp[1] == '.') {
                oew_stack |= 1;
            }
            break;
        case '[':
            /* Checks if the whole word is optional, and sets the
             * 'whole_word_is_optional' accordingly. */
            if ((inp == arguments || inp[-1] == ' ') && oew_stack & 1) {
                *--outp = in_repeated ? '*' : '?';
                whole_word_is_optional = true;
            } else {
                *--outp = '?';
                whole_word_is_optional = false;
            }
            oew_stack >>= 1;
            break;
        case ' ':
            if (!whole_word_is_optional) {
                *--outp = in_repeated ? '+' : '!';
            }
            *--outp = ' ';
            in_repeated = false;
            whole_word_is_optional = false;
            break;
        case '.':
            in_repeated = true;
            break;
        default:
            *--outp = *inp;
            break;
        }
    }
    if (arguments[0] != '[' && outp != output + 2 * length - 1) {
        *--outp = in_repeated ? '+' : '!';
    }
    printf("%s", outp);
    free(output);
}

static int
to_lower_and_underscores(unsigned c)
{
    return c == '-' ? '_' : tolower(c);
}

/* Returns a score representing how well 's' matches 'name'.  Higher return
 * values indicate a better match.  The order of the arguments is important:
 * 'name' is the name of an entity such as a table or a column, and 's' is user
 * input. */
static unsigned int
score_partial_match(const char *name, const char *s)
{
    int score;

    if (!strcmp(name, s)) {
        return UINT_MAX;
    }
    for (score = 0; ; score++, name++, s++) {
        if (to_lower_and_underscores(*name) != to_lower_and_underscores(*s)) {
            break;
        } else if (*name == '\0') {
            return UINT_MAX - 1;
        }
    }
    return *s == '\0' ? score : 0;
}

/* Returns NULL and sets 'symbolp' and 'newp' if symbol was created
 * successfully. Otherwise returns a malloc()'ed error message on failure. */
static char * OVS_WARN_UNUSED_RESULT
create_symbol(struct ovsdb_symbol_table *symtab, const char *id,
              struct ovsdb_symbol **symbolp, bool *newp)
{
    struct ovsdb_symbol *symbol;

    ovs_assert(symbolp);

    if (id[0] != '@') {
        return xasprintf("row id \"%s\" does not begin with \"@\"", id);
    }

    if (newp) {
        *newp = ovsdb_symbol_table_get(symtab, id) == NULL;
    }

    symbol = ovsdb_symbol_table_insert(symtab, id);
    if (symbol->created) {
        return xasprintf("row id \"%s\" may only be specified on one --id "
                         "option", id);
    }
    symbol->created = true;
    *symbolp = symbol;
    return NULL;
}

static bool
record_id_equals(const union ovsdb_atom *name, enum ovsdb_atomic_type type,
                 const char *record_id)
{
    if (type == OVSDB_TYPE_STRING) {
        if (!strcmp(name->string, record_id)) {
            return true;
        }

        struct uuid uuid;
        size_t len = strlen(record_id);
        if (len >= 4
            && uuid_from_string(&uuid, name->string)
            && !strncmp(name->string, record_id, len)) {
            return true;
        }

        return false;
    } else {
        ovs_assert(type == OVSDB_TYPE_INTEGER);
        return name->integer == strtoll(record_id, NULL, 10);
    }
}

static const struct ovsdb_idl_row *
get_row_by_id(struct ctl_context *ctx,
              const struct ovsdb_idl_table_class *table,
              const struct ctl_row_id *id, const char *record_id,
              bool *multiple_matches)
{
    ovs_assert(multiple_matches);
    *multiple_matches = false;

    if (!id->name_column) {
        return NULL;
    }

    const struct ovsdb_idl_row *referrer = NULL;

    /* Figure out the 'key' and 'value' types for the column that we're going
     * to look at.  One of these ('name_type') is the type of the name we're
     * going to compare against 'record_id'.  */
    enum ovsdb_atomic_type key, value, name_type;
    if (!id->key) {
        name_type = key = id->name_column->type.key.type;
        value = OVSDB_TYPE_VOID;
    } else {
        key = OVSDB_TYPE_STRING;
        name_type = value = id->name_column->type.value.type;
    }

    /* We only support integer and string names (so far). */
    if (name_type == OVSDB_TYPE_INTEGER) {
        if (!record_id[0] || record_id[strspn(record_id, "0123456789")]) {
            return NULL;
        }
    } else {
        ovs_assert(name_type == OVSDB_TYPE_STRING);
    }

    const struct ovsdb_idl_class *class = ovsdb_idl_get_class(ctx->idl);
    const struct ovsdb_idl_table_class *id_table
        = ovsdb_idl_table_class_from_column(class, id->name_column);
    for (const struct ovsdb_idl_row *row = ovsdb_idl_first_row(ctx->idl,
                                                               id_table);
         row != NULL;
         row = ovsdb_idl_next_row(row)) {
        /* Pick out the name column's data. */
        const struct ovsdb_datum *datum = ovsdb_idl_get(
            row, id->name_column, key, value);

        /* Extract the name from the column. */
        const union ovsdb_atom *name;
        if (!id->key) {
            name = datum->n == 1 ? &datum->keys[0] : NULL;
        } else {
            const union ovsdb_atom key_atom
                = { .string = CONST_CAST(char *, id->key) };
            unsigned int i = ovsdb_datum_find_key(datum, &key_atom,
                                                  OVSDB_TYPE_STRING);
            name = i == UINT_MAX ? NULL : &datum->values[i];
        }
        if (!name) {
            continue;
        }

        /* If the name equals 'record_id', take it. */
        if (record_id_equals(name, name_type, record_id)) {
            if (referrer) {
                *multiple_matches = true;
                return NULL;
            }
            referrer = row;
        }
    }
    if (!referrer) {
        return NULL;
    }

    const struct ovsdb_idl_row *final = referrer;
    if (id->uuid_column) {
        const struct ovsdb_datum *uuid;

        ovsdb_idl_txn_verify(referrer, id->uuid_column);
        uuid = ovsdb_idl_get(referrer, id->uuid_column,
                             OVSDB_TYPE_UUID, OVSDB_TYPE_VOID);
        if (uuid->n == 1) {
            final = ovsdb_idl_get_row_for_uuid(ctx->idl, table,
                                               &uuid->keys[0].uuid);
        } else {
            final = NULL;
        }
    }
    return final;
}

char * OVS_WARN_UNUSED_RESULT
ctl_get_row(struct ctl_context *ctx,
            const struct ovsdb_idl_table_class *table, const char *record_id,
            bool must_exist, const struct ovsdb_idl_row **rowp)
{
    const struct ovsdb_idl_row *row = NULL;
    struct uuid uuid;

    ovs_assert(rowp);

    if (uuid_from_string(&uuid, record_id)) {
        row = ovsdb_idl_get_row_for_uuid(ctx->idl, table, &uuid);
    }
    if (!row) {
        if (!strcmp(record_id, ".")) {
            row = ovsdb_idl_first_row(ctx->idl, table);
            if (row && ovsdb_idl_next_row(row)) {
                row = NULL;
            }
        }
    }
    if (!row) {
        const struct ctl_table_class *ctl_class
            = &ctl_classes[table - idl_classes];
        for (int i = 0; i < ARRAY_SIZE(ctl_class->row_ids); i++) {
            const struct ctl_row_id *id = &ctl_class->row_ids[i];
            bool multiple_matches;

            row = get_row_by_id(ctx, table, id, record_id, &multiple_matches);
            if (multiple_matches) {
                const struct ovsdb_idl_class *class =
                    ovsdb_idl_get_class(ctx->idl);
                const struct ovsdb_idl_table_class *table_class =
                    ovsdb_idl_table_class_from_column(class, id->name_column);
                return xasprintf("multiple rows in %s match \"%s\"",
                                 table_class->name, record_id);
            }
            if (row) {
                break;
            }
        }
    }
    if (!row && uuid_is_partial_string(record_id) >= 4) {
        for (const struct ovsdb_idl_row *r = ovsdb_idl_first_row(ctx->idl,
                                                                 table);
             r != NULL;
             r = ovsdb_idl_next_row(r)) {
            if (uuid_is_partial_match(&r->uuid, record_id)) {
                if (!row) {
                    row = r;
                } else {
                    return xasprintf("%s contains 2 or more rows whose UUIDs "
                                     "begin with %s: at least "UUID_FMT" "
                                     "and "UUID_FMT, table->name, record_id,
                                     UUID_ARGS(&row->uuid),
                                     UUID_ARGS(&r->uuid));
                }
            }
        }
    }
    if (must_exist && !row) {
        return xasprintf("no row \"%s\" in table %s", record_id, table->name);
    }

    *rowp = row;
    return NULL;
}

static char *
get_column(const struct ovsdb_idl_table_class *table, const char *column_name,
           const struct ovsdb_idl_column **columnp)
{
    struct sset best_matches = SSET_INITIALIZER(&best_matches);
    const struct ovsdb_idl_column *best_match = NULL;
    unsigned int best_score = 0;

    for (size_t i = 0; i < table->n_columns; i++) {
        const struct ovsdb_idl_column *column = &table->columns[i];
        unsigned int score = score_partial_match(column->name, column_name);
        if (score && score >= best_score) {
            if (score > best_score) {
                sset_clear(&best_matches);
            }
            sset_add(&best_matches, column->name);
            best_match = column;
            best_score = score;
        }
    }

    char *error = NULL;
    *columnp = NULL;
    if (!best_match) {
        error = xasprintf("%s does not contain a column whose name matches "
                          "\"%s\"", table->name, column_name);
    } else if (sset_count(&best_matches) == 1) {
        *columnp = best_match;
    } else {
        char *matches = sset_join(&best_matches, ", ", "");
        error = xasprintf("%s contains more than one column "
                          "whose name matches \"%s\": %s",
                          table->name, column_name, matches);
        free(matches);
    }
    sset_destroy(&best_matches);
    return error;
}

static char * OVS_WARN_UNUSED_RESULT
pre_get_column(struct ctl_context *ctx,
               const struct ovsdb_idl_table_class *table,
               const char *column_name,
               const struct ovsdb_idl_column **columnp)
{
    char *error = get_column(table, column_name, columnp);
    if (error) {
        return error;
    }
    ovsdb_idl_add_column(ctx->idl, *columnp);
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
pre_get_table(struct ctl_context *ctx, const char *table_name,
              const struct ovsdb_idl_table_class **tablep)
{
    const struct ovsdb_idl_table_class *table;
    char *error = get_table(table_name, &table);
    if (error) {
        return error;
    }
    ovsdb_idl_add_table(ctx->idl, table);

    const struct ctl_table_class *ctl = &ctl_classes[table - idl_classes];
    for (int i = 0; i < ARRAY_SIZE(ctl->row_ids); i++) {
        const struct ctl_row_id *id = &ctl->row_ids[i];
        if (id->name_column) {
            ovsdb_idl_add_column(ctx->idl, id->name_column);
        }
        if (id->uuid_column) {
            ovsdb_idl_add_column(ctx->idl, id->uuid_column);
        }
    }

    if (tablep) {
        *tablep = table;
    }
    return NULL;
}

static char *
missing_operator_error(const char *arg, const char **allowed_operators,
                       size_t n_allowed)
{
    struct ds s;

    ds_init(&s);
    ds_put_format(&s, "%s: argument does not end in ", arg);
    ds_put_format(&s, "\"%s\"", allowed_operators[0]);
    if (n_allowed == 2) {
        ds_put_format(&s, " or \"%s\"", allowed_operators[1]);
    } else if (n_allowed > 2) {
        size_t i;

        for (i = 1; i < n_allowed - 1; i++) {
            ds_put_format(&s, ", \"%s\"", allowed_operators[i]);
        }
        ds_put_format(&s, ", or \"%s\"", allowed_operators[i]);
    }
    ds_put_format(&s, " followed by a value.");

    return ds_steal_cstr(&s);
}

/* Breaks 'arg' apart into a number of fields in the following order:
 *
 *      - The name of a column in 'table', stored into '*columnp'.  The column
 *        name may be abbreviated.
 *
 *      - Optionally ':' followed by a key string.  The key is stored as a
 *        malloc()'d string into '*keyp', or NULL if no key is present in
 *        'arg'.
 *
 *      - If 'valuep' is nonnull, an operator followed by a value string.  The
 *        allowed operators are the 'n_allowed' string in 'allowed_operators',
 *        or just "=" if 'n_allowed' is 0.  If 'operatorp' is nonnull, then the
 *        index of the operator within 'allowed_operators' is stored into
 *        '*operatorp'.  The value is stored as a malloc()'d string into
 *        '*valuep', or NULL if no value is present in 'arg'.
 *
 * On success, returns NULL.  On failure, returned a malloc()'d string error
 * message and stores NULL into all of the nonnull output arguments. */
static char * OVS_WARN_UNUSED_RESULT
parse_column_key_value(const char *arg,
                       const struct ovsdb_idl_table_class *table,
                       const struct ovsdb_idl_column **columnp, char **keyp,
                       int *operatorp,
                       const char **allowed_operators, size_t n_allowed,
                       char **valuep)
{
    const char *p = arg;
    char *column_name;
    char *error;

    ovs_assert(!(operatorp && !valuep));
    *keyp = NULL;
    if (valuep) {
        *valuep = NULL;
    }

    /* Parse column name. */
    error = ovsdb_token_parse(&p, &column_name);
    if (error) {
        goto error;
    }
    if (column_name[0] == '\0') {
        free(column_name);
        error = xasprintf("%s: missing column name", arg);
        goto error;
    }
    error = get_column(table, column_name, columnp);
    free(column_name);
    if (error) {
        goto error;
    }

    /* Parse key string. */
    if (*p == ':') {
        p++;
        error = ovsdb_token_parse(&p, keyp);
        if (error) {
            goto error;
        }
    }

    /* Parse value string. */
    if (valuep) {
        size_t best_len;
        size_t i;
        int best;

        if (!allowed_operators) {
            static const char *equals = "=";
            allowed_operators = &equals;
            n_allowed = 1;
        }

        best = -1;
        best_len = 0;
        for (i = 0; i < n_allowed; i++) {
            const char *op = allowed_operators[i];
            size_t op_len = strlen(op);

            if (op_len > best_len && !strncmp(op, p, op_len) && p[op_len]) {
                best_len = op_len;
                best = i;
            }
        }
        if (best < 0) {
            error = missing_operator_error(arg, allowed_operators, n_allowed);
            goto error;
        }

        if (operatorp) {
            *operatorp = best;
        }
        *valuep = xstrdup(p + best_len);
    } else {
        if (*p != '\0') {
            error = xasprintf("%s: trailing garbage \"%s\" in argument",
                              arg, p);
            goto error;
        }
    }
    return NULL;

 error:
    *columnp = NULL;
    free(*keyp);
    *keyp = NULL;
    if (valuep) {
        free(*valuep);
        *valuep = NULL;
        if (operatorp) {
            *operatorp = -1;
        }
    }
    return error;
}

static char * OVS_WARN_UNUSED_RESULT
pre_parse_column_key_value(struct ctl_context *ctx, const char *arg,
                           const struct ovsdb_idl_table_class *table)
{
    const struct ovsdb_idl_column *column;
    const char *p;
    char *column_name = NULL;
    char *error;

    p = arg;
    error = ovsdb_token_parse(&p, &column_name);
    if (error) {
        goto out;
    }
    if (column_name[0] == '\0') {
        error = xasprintf("%s: missing column name", arg);
        goto out;
    }

    error = pre_get_column(ctx, table, column_name, &column);
out:
    free(column_name);

    return error;
}

/* Checks if the 'column' is mutable. Returns NULL if it is mutable, or a
 * malloc()'ed error message otherwise. */
static char * OVS_WARN_UNUSED_RESULT
check_mutable(const struct ovsdb_idl_row *row,
              const struct ovsdb_idl_column *column)
{
    if (!ovsdb_idl_is_mutable(row, column)) {
        return xasprintf("cannot modify read-only column %s in table %s",
                         column->name, row->table->class_->name);
    }
    return NULL;
}

#define RELOPS                                  \
    RELOP(RELOP_EQ,     "=")                    \
    RELOP(RELOP_NE,     "!=")                   \
    RELOP(RELOP_LT,     "<")                    \
    RELOP(RELOP_GT,     ">")                    \
    RELOP(RELOP_LE,     "<=")                   \
    RELOP(RELOP_GE,     ">=")                   \
    RELOP(RELOP_SET_EQ, "{=}")                  \
    RELOP(RELOP_SET_NE, "{!=}")                 \
    RELOP(RELOP_SET_LT, "{<}")                  \
    RELOP(RELOP_SET_GT, "{>}")                  \
    RELOP(RELOP_SET_LE, "{<=}")                 \
    RELOP(RELOP_SET_GE, "{>=}")                 \
    RELOP(RELOP_SET_IN, "{in}")                 \
    RELOP(RELOP_SET_NOT_IN, "{not-in}")

enum relop {
#define RELOP(ENUM, STRING) ENUM,
    RELOPS
#undef RELOP
};

static bool
is_set_operator(enum relop op)
{
    return (op == RELOP_SET_EQ || op == RELOP_SET_NE ||
            op == RELOP_SET_LT || op == RELOP_SET_GT ||
            op == RELOP_SET_LE || op == RELOP_SET_GE ||
            op == RELOP_SET_IN || op == RELOP_SET_NOT_IN);
}

static bool
evaluate_relop(const struct ovsdb_datum *a, const struct ovsdb_datum *b,
               const struct ovsdb_type *type, enum relop op)
{
    switch (op) {
    case RELOP_EQ:
    case RELOP_SET_EQ:
        return ovsdb_datum_compare_3way(a, b, type) == 0;
    case RELOP_NE:
    case RELOP_SET_NE:
        return ovsdb_datum_compare_3way(a, b, type) != 0;
    case RELOP_LT:
        return ovsdb_datum_compare_3way(a, b, type) < 0;
    case RELOP_GT:
        return ovsdb_datum_compare_3way(a, b, type) > 0;
    case RELOP_LE:
        return ovsdb_datum_compare_3way(a, b, type) <= 0;
    case RELOP_GE:
        return ovsdb_datum_compare_3way(a, b, type) >= 0;

    case RELOP_SET_LT:
        return b->n > a->n && ovsdb_datum_includes_all(a, b, type);
    case RELOP_SET_GT:
        return a->n > b->n && ovsdb_datum_includes_all(b, a, type);
    case RELOP_SET_LE:
    case RELOP_SET_IN:
        return ovsdb_datum_includes_all(a, b, type);
    case RELOP_SET_GE:
        return ovsdb_datum_includes_all(b, a, type);
    case RELOP_SET_NOT_IN:
        return ovsdb_datum_excludes_all(a, b, type);

    default:
        OVS_NOT_REACHED();
    }
}

/* Checks if given row satisfies the specified condition. Returns the result of
 * evaluating the condition in 'satisfied' flag and NULL as a return value on
 * success. On failure returns a malloc()'ed error message and 'satisfied'
 * value is not modified. */
static char * OVS_WARN_UNUSED_RESULT
check_condition(const struct ovsdb_idl_table_class *table,
                const struct ovsdb_idl_row *row, const char *arg,
                struct ovsdb_symbol_table *symtab, bool *satisfied)
{
    static const char *operators[] = {
#define RELOP(ENUM, STRING) STRING,
        RELOPS
#undef RELOP
    };

    const struct ovsdb_idl_column *column;
    const struct ovsdb_datum *have_datum;
    char *key_string = NULL;
    char *value_string = NULL;
    struct ovsdb_type type;
    int operator;
    bool retval;
    char *error;

    ovs_assert(satisfied);

    error = parse_column_key_value(arg, table, &column, &key_string,
                                   &operator, operators, ARRAY_SIZE(operators),
                                   &value_string);
    if (error) {
        goto out;
    }
    if (!value_string) {
        error = xasprintf("%s: missing value", arg);
        goto out;
    }

    type = column->type;
    type.n_max = UINT_MAX;

    have_datum = ovsdb_idl_read(row, column);
    if (key_string) {
        union ovsdb_atom want_key;
        struct ovsdb_datum b;
        unsigned int idx;

        if (column->type.value.type == OVSDB_TYPE_VOID) {
            error = xasprintf("cannot specify key to check for non-map column "
                              "%s", column->name);
            goto out;
        }

        error = ovsdb_atom_from_string(&want_key, NULL, &column->type.key,
                                       key_string, symtab);
        if (error) {
            goto out;
        }

        type.key = type.value;
        type.value.type = OVSDB_TYPE_VOID;
        error = ovsdb_datum_from_string(&b, &type, value_string, symtab);
        if (error) {
            goto out;
        }

        idx = ovsdb_datum_find_key(have_datum,
                                   &want_key, column->type.key.type);
        if (idx == UINT_MAX && !is_set_operator(operator)) {
            retval = false;
        } else {
            struct ovsdb_datum a;

            if (idx != UINT_MAX) {
                a.n = 1;
                a.keys = &have_datum->values[idx];
                a.values = NULL;
            } else {
                a.n = 0;
                a.keys = NULL;
                a.values = NULL;
            }

            retval = evaluate_relop(&a, &b, &type, operator);
        }

        ovsdb_atom_destroy(&want_key, column->type.key.type);
        ovsdb_datum_destroy(&b, &type);
    } else {
        struct ovsdb_datum want_datum;

        error = ovsdb_datum_from_string(&want_datum, &column->type,
                                        value_string, symtab);
        if (error) {
            goto out;
        }
        retval = evaluate_relop(have_datum, &want_datum, &type, operator);
        ovsdb_datum_destroy(&want_datum, &column->type);
    }

    *satisfied = retval;
out:
    free(key_string);
    free(value_string);

    return error;
}

static void
invalidate_cache(struct ctl_context *ctx)
{
    if (ctx->invalidate_cache_cb) {
        (ctx->invalidate_cache_cb)(ctx);
    }
}

static void
pre_cmd_get(struct ctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;
    int i;

    /* Using "get" without --id or a column name could possibly make sense.
     * Maybe, for example, a *ctl command run wants to assert that a row
     * exists.  But it is unlikely that an interactive user would want to do
     * that, so issue a warning if we're running on a terminal. */
    if (!id && ctx->argc <= 3 && isatty(STDOUT_FILENO)) {
        VLOG_WARN("\"get\" command without row arguments or \"--id\" is "
                  "possibly erroneous");
    }

    ctx->error = pre_get_table(ctx, table_name, &table);
    if (ctx->error) {
        return;
    }
    for (i = 3; i < ctx->argc; i++) {
        if (!strcasecmp(ctx->argv[i], "_uuid")
            || !strcasecmp(ctx->argv[i], "-uuid")) {
            continue;
        }

        ctx->error = pre_parse_column_key_value(ctx, ctx->argv[i], table);
        if (ctx->error) {
            return;
        }
    }
}

static void
cmd_get(struct ctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_row *row;
    struct ds *out = &ctx->output;
    int i;

    if (id && !must_exist) {
        ctl_error(ctx, "--if-exists and --id may not be specified together");
        return;
    }

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = ctl_get_row(ctx, table, record_id, must_exist, &row);
    if (ctx->error) {
        return;
    }
    if (!row) {
        return;
    }

    if (id) {
        struct ovsdb_symbol *symbol = NULL;
        bool new = false;

        ctx->error = create_symbol(ctx->symtab, id, &symbol, &new);
        if (ctx->error) {
            return;
        }
        if (!new) {
            ctl_error(ctx, "row id \"%s\" specified on \"get\" command was "
                      "used before it was defined", id);
            return;
        }
        symbol->uuid = row->uuid;

        /* This symbol refers to a row that already exists, so disable warnings
         * about it being unreferenced. */
        symbol->strong_ref = true;
    }
    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;
        const struct ovsdb_datum *datum;
        char *key_string;

        /* Special case for obtaining the UUID of a row.  We can't just do this
         * through parse_column_key_value() below since it returns a "struct
         * ovsdb_idl_column" and the UUID column doesn't have one. */
        if (!strcasecmp(ctx->argv[i], "_uuid")
            || !strcasecmp(ctx->argv[i], "-uuid")) {
            ds_put_format(out, UUID_FMT"\n", UUID_ARGS(&row->uuid));
            continue;
        }

        ctx->error = parse_column_key_value(ctx->argv[i], table, &column,
                                            &key_string, NULL, NULL, 0, NULL);
        if (ctx->error) {
            return;
        }

        ovsdb_idl_txn_verify(row, column);
        datum = ovsdb_idl_read(row, column);
        if (key_string) {
            union ovsdb_atom key;
            unsigned int idx;

            if (column->type.value.type == OVSDB_TYPE_VOID) {
                ctl_error(ctx,
                          "cannot specify key to get for non-map column %s",
                          column->name);
                free(key_string);
                return;
            }

            ctx->error = ovsdb_atom_from_string(&key, NULL, &column->type.key,
                                                key_string, ctx->symtab);
            if (ctx->error) {
                free(key_string);
                return;
            }

            idx = ovsdb_datum_find_key(datum, &key,
                                       column->type.key.type);
            if (idx == UINT_MAX) {
                if (must_exist) {
                    ctl_error(
                        ctx, "no key \"%s\" in %s record \"%s\" column %s",
                        key_string, table->name, record_id, column->name);
                    free(key_string);
                    ovsdb_atom_destroy(&key, column->type.key.type);
                    return;
                }
            } else {
                ovsdb_atom_to_string(&datum->values[idx],
                                     column->type.value.type, out);
            }
            ovsdb_atom_destroy(&key, column->type.key.type);
        } else {
            ovsdb_datum_to_string(datum, &column->type, out);
        }
        ds_put_char(out, '\n');

        free(key_string);
    }
}

/* Returns NULL on success or malloc()'ed error message on failure. */
static char * OVS_WARN_UNUSED_RESULT
parse_column_names(const char *column_names,
                   const struct ovsdb_idl_table_class *table,
                   const struct ovsdb_idl_column ***columnsp,
                   size_t *n_columnsp)
{
    const struct ovsdb_idl_column **columns;
    size_t n_columns;

    if (!column_names) {
        size_t i;

        n_columns = table->n_columns + 1;
        columns = xmalloc(n_columns * sizeof *columns);
        columns[0] = NULL;
        for (i = 0; i < table->n_columns; i++) {
            columns[i + 1] = &table->columns[i];
        }
    } else {
        char *s = xstrdup(column_names);
        size_t allocated_columns;
        char *save_ptr = NULL;
        char *column_name;

        columns = NULL;
        allocated_columns = n_columns = 0;
        for (column_name = strtok_r(s, ", ", &save_ptr); column_name;
             column_name = strtok_r(NULL, ", ", &save_ptr)) {
            const struct ovsdb_idl_column *column;

            if (!strcasecmp(column_name, "_uuid")) {
                column = NULL;
            } else {
                char *error = get_column(table, column_name, &column);
                if (error) {
                    free(columns);
                    free(s);
                    return error;
                }
            }
            if (n_columns >= allocated_columns) {
                columns = x2nrealloc(columns, &allocated_columns,
                                     sizeof *columns);
            }
            columns[n_columns++] = column;
        }
        free(s);

        if (!n_columns) {
            return xstrdup("must specify at least one column name");
        }
    }
    *columnsp = columns;
    *n_columnsp = n_columns;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
pre_list_columns(struct ctl_context *ctx,
                 const struct ovsdb_idl_table_class *table,
                 const char *column_names)
{
    const struct ovsdb_idl_column **columns;
    size_t n_columns;
    size_t i;
    char *error;

    error = parse_column_names(column_names, table, &columns, &n_columns);
    if (error) {
        return error;
    }
    for (i = 0; i < n_columns; i++) {
        if (columns[i]) {
            ovsdb_idl_add_column(ctx->idl, columns[i]);
        }
    }
    free(columns);
    return NULL;
}

static void
pre_cmd_list(struct ctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;

    ctx->error = pre_get_table(ctx, table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = pre_list_columns(ctx, table, column_names);
    if (ctx->error) {
        return;
    }
}

static struct table *
list_make_table(const struct ovsdb_idl_column **columns, size_t n_columns)
{
    struct table *out;
    size_t i;

    out = xmalloc(sizeof *out);
    table_init(out);

    for (i = 0; i < n_columns; i++) {
        const struct ovsdb_idl_column *column = columns[i];
        const char *column_name = column ? column->name : "_uuid";

        table_add_column(out, "%s", column_name);
    }

    return out;
}

static void
list_record(const struct ovsdb_idl_row *row,
            const struct ovsdb_idl_column **columns, size_t n_columns,
            struct table *out)
{
    size_t i;

    if (!row) {
        return;
    }

    table_add_row(out);
    for (i = 0; i < n_columns; i++) {
        const struct ovsdb_idl_column *column = columns[i];
        struct cell *cell = table_add_cell(out);

        if (!column) {
            struct ovsdb_datum datum;
            union ovsdb_atom atom;

            atom.uuid = row->uuid;

            datum.keys = &atom;
            datum.values = NULL;
            datum.n = 1;

            cell->json = ovsdb_datum_to_json(&datum, &ovsdb_type_uuid);
            cell->type = &ovsdb_type_uuid;
        } else {
            const struct ovsdb_datum *datum = ovsdb_idl_read(row, column);

            cell->json = ovsdb_datum_to_json(datum, &column->type);
            cell->type = &column->type;
        }
    }
}

static void
cmd_list(struct ctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct ovsdb_idl_column **columns;
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;
    struct table *out;
    size_t n_columns;
    int i;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = parse_column_names(column_names, table, &columns, &n_columns);
    if (ctx->error) {
        return;
    }
    out = ctx->table = list_make_table(columns, n_columns);
    if (ctx->argc > 2) {
        for (i = 2; i < ctx->argc; i++) {
            const struct ovsdb_idl_row *row;

            ctx->error = ctl_get_row(ctx, table, ctx->argv[i], must_exist,
                                     &row);
            if (ctx->error) {
                free(columns);
                return;
            }
            list_record(row, columns, n_columns, out);
        }
    } else {
        const struct ovsdb_idl_row *row;

        for (row = ovsdb_idl_first_row(ctx->idl, table); row != NULL;
             row = ovsdb_idl_next_row(row)) {
            list_record(row, columns, n_columns, out);
        }
    }
    free(columns);
}

/* Finds the "struct ovsdb_idl_table_class *" with 'table_name' by searching
 * the tables in these schema. Returns NULL and sets 'tablep' on success, or a
 * malloc()'ed error message on failure. */
static char * OVS_WARN_UNUSED_RESULT
get_table(const char *table_name, const struct ovsdb_idl_table_class **tablep)
{
    struct sset best_matches = SSET_INITIALIZER(&best_matches);
    const struct ovsdb_idl_table_class *best_match = NULL;
    unsigned int best_score = 0;

    for (const struct ovsdb_idl_table_class *table = idl_classes;
         table < &idl_classes[n_classes]; table++) {
        unsigned int score = score_partial_match(table->name, table_name);
        if (score && score >= best_score) {
            if (score > best_score) {
                sset_clear(&best_matches);
            }
            sset_add(&best_matches, table->name);
            best_match = table;
            best_score = score;
        }
    }

    char *error = NULL;
    if (!best_match) {
        error = xasprintf("unknown table \"%s\"", table_name);
    } else if (sset_count(&best_matches) == 1) {
        *tablep = best_match;
    } else {
        char *matches = sset_join(&best_matches, ", ", "");
        error = xasprintf("\"%s\" matches multiple table names: %s",
                          table_name, matches);
        free(matches);
    }
    sset_destroy(&best_matches);
    return error;
}

static void
pre_cmd_find(struct ctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;
    int i;

    ctx->error = pre_get_table(ctx, table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = pre_list_columns(ctx, table, column_names);
    if (ctx->error) {
        return;
    }
    for (i = 2; i < ctx->argc; i++) {
        ctx->error = pre_parse_column_key_value(ctx, ctx->argv[i], table);
        if (ctx->error) {
            return;
        }
    }
}

static void
cmd_find(struct ctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const struct ovsdb_idl_column **columns;
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_row *row;
    struct table *out;
    size_t n_columns;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = parse_column_names(column_names, table, &columns, &n_columns);
    if (ctx->error) {
        return;
    }
    out = ctx->table = list_make_table(columns, n_columns);
    for (row = ovsdb_idl_first_row(ctx->idl, table); row;
         row = ovsdb_idl_next_row(row)) {
        int i;

        for (i = 2; i < ctx->argc; i++) {
            bool satisfied = false;

            ctx->error = check_condition(table, row, ctx->argv[i],
                                         ctx->symtab, &satisfied);
            if (ctx->error) {
                free(columns);
                return;
            }
            if (!satisfied) {
                goto next_row;
            }
        }
        list_record(row, columns, n_columns, out);

    next_row: ;
    }
    free(columns);
}

/* Sets the column of 'row' in 'table'. Returns NULL on success or a
 * malloc()'ed error message on failure. */
static char * OVS_WARN_UNUSED_RESULT
set_column(const struct ovsdb_idl_table_class *table,
           const struct ovsdb_idl_row *row, const char *arg,
           struct ovsdb_symbol_table *symtab)
{
    const struct ovsdb_idl_column *column;
    char *key_string = NULL;
    char *value_string = NULL;
    char *error;

    error = parse_column_key_value(arg, table, &column, &key_string,
                                   NULL, NULL, 0, &value_string);
    if (error) {
        goto out;
    }
    if (!value_string) {
        error = xasprintf("%s: missing value", arg);
        goto out;
    }
    error = check_mutable(row, column);
    if (error) {
        goto out;
    }

    if (key_string) {
        union ovsdb_atom key, value;
        struct ovsdb_datum datum;

        if (column->type.value.type == OVSDB_TYPE_VOID) {
            error = xasprintf("cannot specify key to set for non-map column "
                              "%s", column->name);
            goto out;
        }

        error = ovsdb_atom_from_string(&key, NULL, &column->type.key,
                                       key_string, symtab);
        if (error) {
            goto out;
        }
        error = ovsdb_atom_from_string(&value, NULL, &column->type.value,
                                       value_string, symtab);
        if (error) {
            goto out;
        }

        ovsdb_datum_init_empty(&datum);
        ovsdb_datum_add_unsafe(&datum, &key, &value, &column->type, NULL);

        ovsdb_atom_destroy(&key, column->type.key.type);
        ovsdb_atom_destroy(&value, column->type.value.type);

        ovsdb_datum_union(&datum, ovsdb_idl_read(row, column),
                          &column->type, false);
        ovsdb_idl_txn_verify(row, column);
        ovsdb_idl_txn_write(row, column, &datum);
    } else {
        struct ovsdb_datum datum;

        error = ovsdb_datum_from_string(&datum, &column->type,
                                        value_string, symtab);
        if (error) {
            goto out;
        }
        ovsdb_idl_txn_write(row, column, &datum);
    }

out:
    free(key_string);
    free(value_string);

    return error;
}

static void
pre_cmd_set(struct ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;
    int i;

    ctx->error = pre_get_table(ctx, table_name, &table);
    if (ctx->error) {
        return;
    }
    for (i = 3; i < ctx->argc; i++) {
        ctx->error = pre_parse_column_key_value(ctx, ctx->argv[i], table);
        if (ctx->error) {
            return;
        }
    }
}

static void
cmd_set(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_row *row;
    int i;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = ctl_get_row(ctx, table, record_id, must_exist, &row);
    if (ctx->error) {
        return;
    }
    if (!row) {
        return;
    }

    for (i = 3; i < ctx->argc; i++) {
        ctx->error = set_column(table, row, ctx->argv[i], ctx->symtab);
        if (ctx->error) {
            return;
        }
    }

    invalidate_cache(ctx);
}

static void
pre_cmd_add(struct ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *column_name = ctx->argv[3];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *column;

    ctx->error = pre_get_table(ctx, table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = pre_get_column(ctx, table, column_name, &column);
    if (ctx->error) {
        return;
    }
}

static void
cmd_add(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const char *column_name = ctx->argv[3];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *column;
    const struct ovsdb_idl_row *row;
    const struct ovsdb_type *type;
    struct ovsdb_datum old;
    int i;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = get_column(table, column_name, &column);
    if (ctx->error) {
        return;
    }
    ctx->error = ctl_get_row(ctx, table, record_id, must_exist, &row);
    if (ctx->error) {
        return;
    }
    if (!row) {
        return;
    }
    ctx->error = check_mutable(row, column);
    if (ctx->error) {
        return;
    }

    type = &column->type;
    ovsdb_datum_clone(&old, ovsdb_idl_read(row, column), &column->type);
    for (i = 4; i < ctx->argc; i++) {
        struct ovsdb_type add_type;
        struct ovsdb_datum add;

        add_type = *type;
        add_type.n_min = 1;
        add_type.n_max = UINT_MAX;
        ctx->error = ovsdb_datum_from_string(&add, &add_type, ctx->argv[i],
                                             ctx->symtab);
        if (ctx->error) {
            ovsdb_datum_destroy(&old, &column->type);
            return;
        }
        ovsdb_datum_union(&old, &add, type, false);
        ovsdb_datum_destroy(&add, type);
    }
    if (old.n > type->n_max) {
        ctl_error(ctx, "\"add\" operation would put %u %s in column %s of "
                  "table %s but the maximum number is %u",
                  old.n,
                  type->value.type == OVSDB_TYPE_VOID ? "values" : "pairs",
                  column->name, table->name, type->n_max);
        ovsdb_datum_destroy(&old, &column->type);
        return;
    }
    ovsdb_idl_txn_verify(row, column);
    ovsdb_idl_txn_write(row, column, &old);

    invalidate_cache(ctx);
}

static void
pre_cmd_remove(struct ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *column_name = ctx->argv[3];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *column;

    ctx->error = pre_get_table(ctx, table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = pre_get_column(ctx, table, column_name, &column);
    if (ctx->error) {
        return;
    }
}

static void
cmd_remove(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const char *column_name = ctx->argv[3];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *column;
    const struct ovsdb_idl_row *row;
    const struct ovsdb_type *type;
    struct ovsdb_datum old;
    int i;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = get_column(table, column_name, &column);
    if (ctx->error) {
        return;
    }
    ctx->error = ctl_get_row(ctx, table, record_id, must_exist, &row);
    if (ctx->error) {
        return;
    }
    if (!row) {
        return;
    }
    ctx->error = check_mutable(row, column);
    if (ctx->error) {
        return;
    }

    type = &column->type;
    ovsdb_datum_clone(&old, ovsdb_idl_read(row, column), &column->type);
    for (i = 4; i < ctx->argc; i++) {
        struct ovsdb_type rm_type;
        struct ovsdb_datum rm;
        char *error;

        rm_type = *type;
        rm_type.n_min = 1;
        rm_type.n_max = UINT_MAX;
        error = ovsdb_datum_from_string(&rm, &rm_type,
                                        ctx->argv[i], ctx->symtab);

        if (error) {
            if (ovsdb_type_is_map(&rm_type)) {
                rm_type.value.type = OVSDB_TYPE_VOID;
                free(error);
                ctx->error = ovsdb_datum_from_string(&rm, &rm_type,
                                                     ctx->argv[i],
                                                     ctx->symtab);
                if (ctx->error) {
                    ovsdb_datum_destroy(&old, &column->type);
                    return;
                }
            } else {
                ctx->error = error;
                ovsdb_datum_destroy(&old, &column->type);
                return;
            }
        }
        ovsdb_datum_subtract(&old, type, &rm, &rm_type);
        ovsdb_datum_destroy(&rm, &rm_type);
    }
    if (old.n < type->n_min) {
        ctl_error(ctx, "\"remove\" operation would put %u %s in column %s of "
                  "table %s but the minimum number is %u", old.n,
                  type->value.type == OVSDB_TYPE_VOID ? "values" : "pairs",
                  column->name, table->name, type->n_min);
        ovsdb_datum_destroy(&old, &column->type);
        return;
    }
    ovsdb_idl_txn_verify(row, column);
    ovsdb_idl_txn_write(row, column, &old);

    invalidate_cache(ctx);
}

static void
pre_cmd_clear(struct ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;
    int i;

    ctx->error = pre_get_table(ctx, table_name, &table);
    if (ctx->error) {
        return;
    }
    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;

        ctx->error = pre_get_column(ctx, table, ctx->argv[i], &column);
        if (ctx->error) {
            return;
        }
    }
}

static void
cmd_clear(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_row *row;
    int i;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = ctl_get_row(ctx, table, record_id, must_exist, &row);
    if (ctx->error) {
        return;
    }
    if (!row) {
        return;
    }

    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;
        const struct ovsdb_type *type;
        struct ovsdb_datum datum;

        ctx->error = get_column(table, ctx->argv[i], &column);
        if (ctx->error) {
            return;
        }
        ctx->error = check_mutable(row, column);
        if (ctx->error) {
            return;
        }

        type = &column->type;
        if (type->n_min > 0) {
            ctl_error(ctx, "\"clear\" operation cannot be applied to column "
                      "%s of table %s, which is not allowed to be empty",
                      column->name, table->name);
            return;
        }

        ovsdb_datum_init_empty(&datum);
        ovsdb_idl_txn_write(row, column, &datum);
    }

    invalidate_cache(ctx);
}

static void
pre_create(struct ctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    if (!id && !table->is_root) {
        VLOG_WARN("applying \"create\" command to table %s without --id "
                  "option will have no effect", table->name);
    }
}

static void
cmd_create(struct ctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_row *row;
    const struct uuid *uuid = NULL;
    int i;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    if (id) {
        struct ovsdb_symbol *symbol = NULL;

        ctx->error = create_symbol(ctx->symtab, id, &symbol, NULL);
        if (ctx->error) {
            return;
        }
        if (table->is_root) {
            /* This table is in the root set, meaning that rows created in it
             * won't disappear even if they are unreferenced, so disable
             * warnings about that by pretending that there is a reference. */
            symbol->strong_ref = true;
        }
        uuid = &symbol->uuid;
    }

    row = ovsdb_idl_txn_insert(ctx->txn, table, uuid);
    for (i = 2; i < ctx->argc; i++) {
        ctx->error = set_column(table, row, ctx->argv[i], ctx->symtab);
        if (ctx->error) {
            return;
        }
    }
    ds_put_format(&ctx->output, UUID_FMT, UUID_ARGS(&row->uuid));
}

/* This function may be used as the 'postprocess' function for commands that
 * insert new rows into the database.  It expects that the command's 'run'
 * function prints the UUID reported by ovsdb_idl_txn_insert() as the command's
 * sole output.  It replaces that output by the row's permanent UUID assigned
 * by the database server and appends a new-line.
 *
 * Currently we use this only for "create", because the higher-level commands
 * are supposed to be independent of the actual structure of the vswitch
 * configuration. */
static void
post_create(struct ctl_context *ctx)
{
    const struct uuid *real;
    struct uuid dummy;

    if (!uuid_from_string(&dummy, ds_cstr(&ctx->output))) {
        OVS_NOT_REACHED();
    }
    real = ovsdb_idl_txn_get_insert_uuid(ctx->txn, &dummy);
    if (real) {
        ds_clear(&ctx->output);
        ds_put_format(&ctx->output, UUID_FMT, UUID_ARGS(real));
    }
    ds_put_char(&ctx->output, '\n');
}

static void
pre_cmd_destroy(struct ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];

    ctx->error = pre_get_table(ctx, table_name, NULL);
    if (ctx->error) {
        return;
    }
}

static void
cmd_destroy(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    bool delete_all = shash_find(&ctx->options, "--all");
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;
    int i;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }

    if (delete_all && ctx->argc > 2) {
        ctl_error(ctx, "--all and records argument should not be specified "
                  "together");
        return;
    }

    if (delete_all && !must_exist) {
        ctl_error(ctx, "--all and --if-exists should not be specified "
                  "together");
        return;
    }

    if (!delete_all && ctx->argc == 2) {
        VLOG_WARN("either --all or records argument should be specified");
        return;
    }

    if (delete_all) {
        const struct ovsdb_idl_row *row;
        const struct ovsdb_idl_row *next_row;

        for (row = ovsdb_idl_first_row(ctx->idl, table);
             row;) {
            next_row = ovsdb_idl_next_row(row);
            ovsdb_idl_txn_delete(row);
            row = next_row;
        }
    } else {
        for (i = 2; i < ctx->argc; i++) {
            const struct ovsdb_idl_row *row;

            ctx->error = ctl_get_row(ctx, table, ctx->argv[i], must_exist,
                                     &row);
            if (ctx->error) {
                return;
            }
            if (row) {
                ovsdb_idl_txn_delete(row);
            }
        }
    }
    invalidate_cache(ctx);
}

static void
pre_cmd_wait_until(struct ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const struct ovsdb_idl_table_class *table;
    int i;

    ctx->error = pre_get_table(ctx, table_name, &table);
    if (ctx->error) {
        return;
    }

    for (i = 3; i < ctx->argc; i++) {
        ctx->error = pre_parse_column_key_value(ctx, ctx->argv[i], table);
        if (ctx->error) {
            return;
        }
    }
}

static void
cmd_wait_until(struct ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_row *row;
    int i;

    ctx->error = get_table(table_name, &table);
    if (ctx->error) {
        return;
    }
    ctx->error = ctl_get_row(ctx, table, record_id, false, &row);
    if (ctx->error) {
        return;
    }
    if (!row) {
        ctx->try_again = true;
        return;
    }

    for (i = 3; i < ctx->argc; i++) {
        bool satisfied;

        ctx->error = check_condition(table, row, ctx->argv[i], ctx->symtab,
                                     &satisfied);
        if (ctx->error) {
            return;
        }
        if (!satisfied) {
            ctx->try_again = true;
            return;
        }
    }
}

/* Parses one command. */
static char * OVS_WARN_UNUSED_RESULT
parse_command(int argc, char *argv[], struct shash *local_options,
              struct ctl_command *command)
{
    const struct ctl_command_syntax *p;
    struct shash_node *node;
    int n_arg;
    int i;
    char *error;

    shash_init(&command->options);
    shash_swap(local_options, &command->options);
    for (i = 0; i < argc; i++) {
        const char *option = argv[i];
        const char *equals;
        char *key, *value;

        if (option[0] != '-') {
            break;
        }

        equals = strchr(option, '=');
        if (equals) {
            key = xmemdup0(option, equals - option);
            value = xstrdup(equals + 1);
        } else {
            key = xstrdup(option);
            value = NULL;
        }

        if (shash_find(&command->options, key)) {
            free(key);
            free(value);
            error = xasprintf("'%s' option specified multiple times", argv[i]);
            goto error;
        }
        shash_add_nocopy(&command->options, key, value);
    }
    if (i == argc) {
        error = xstrdup("missing command name (use --help for help)");
        goto error;
    }

    p = shash_find_data(&all_commands, argv[i]);
    if (!p) {
        error = xasprintf("unknown command '%s'; use --help for help",
                          argv[i]);
        goto error;
    }

    SHASH_FOR_EACH (node, &command->options) {
        const char *s = strstr(p->options, node->name);
        int end = s ? s[strlen(node->name)] : EOF;

        if (!strchr("=,? ", end)) {
            error = xasprintf("'%s' command has no '%s' option",
                              argv[i], node->name);
            goto error;
        }
        if (end != '?' && (end == '=') != (node->data != NULL)) {
            if (end == '=') {
                error = xasprintf("missing argument to '%s' option on '%s' "
                                  "command", node->name, argv[i]);
                goto error;
            } else {
                error = xasprintf("'%s' option on '%s' does not accept an "
                                  "argument", node->name, argv[i]);
                goto error;
            }
        }
    }

    n_arg = argc - i - 1;
    if (n_arg < p->min_args) {
        error = xasprintf("'%s' command requires at least %d arguments",
                          p->name, p->min_args);
        goto error;
    } else if (n_arg > p->max_args) {
        int j;

        for (j = i + 1; j < argc; j++) {
            if (argv[j][0] == '-') {
                error = xasprintf("'%s' command takes at most %d arguments "
                                  "(note that options must precede command "
                                  "names and follow a \"--\" argument)",
                                  p->name, p->max_args);
                goto error;
            }
        }

        error = xasprintf("'%s' command takes at most %d arguments",
                          p->name, p->max_args);
        goto error;
    }

    command->syntax = p;
    command->argc = n_arg + 1;
    command->argv = &argv[i];
    return NULL;

error:
    shash_destroy_free_data(&command->options);
    return error;
}

static void
pre_cmd_show(struct ctl_context *ctx)
{
    const struct cmd_show_table *show;

    for (show = cmd_show_tables; show->table; show++) {
        size_t i;

        ovsdb_idl_add_table(ctx->idl, show->table);
        if (show->name_column) {
            ovsdb_idl_add_column(ctx->idl, show->name_column);
        }
        for (i = 0; i < ARRAY_SIZE(show->columns); i++) {
            const struct ovsdb_idl_column *column = show->columns[i];
            if (column) {
                ovsdb_idl_add_column(ctx->idl, column);
            }
        }
        if (show->wref_table.table) {
            ovsdb_idl_add_table(ctx->idl, show->wref_table.table);
        }
        if (show->wref_table.name_column) {
            ovsdb_idl_add_column(ctx->idl, show->wref_table.name_column);
        }
        if (show->wref_table.wref_column) {
            ovsdb_idl_add_column(ctx->idl, show->wref_table.wref_column);
        }
    }
}

static const struct cmd_show_table *
cmd_show_find_table_by_row(const struct ovsdb_idl_row *row)
{
    const struct cmd_show_table *show;

    for (show = cmd_show_tables; show->table; show++) {
        if (show->table == row->table->class_) {
            return show;
        }
    }
    return NULL;
}

static const struct cmd_show_table *
cmd_show_find_table_by_name(const char *name)
{
    const struct cmd_show_table *show;

    for (show = cmd_show_tables; show->table; show++) {
        if (!strcmp(show->table->name, name)) {
            return show;
        }
    }
    return NULL;
}

/*  Prints table entries that weak reference the 'cur_row'. */
static void
cmd_show_weak_ref(struct ctl_context *ctx, const struct cmd_show_table *show,
                  const struct ovsdb_idl_row *cur_row, int level)
{
    const struct ovsdb_idl_row *row_wref;
    const struct ovsdb_idl_table_class *table = show->wref_table.table;
    const struct ovsdb_idl_column *name_column
        = show->wref_table.name_column;
    const struct ovsdb_idl_column *wref_column
        = show->wref_table.wref_column;

    if (!table || !name_column || !wref_column) {
        return;
    }

    for (row_wref = ovsdb_idl_first_row(ctx->idl, table); row_wref;
         row_wref = ovsdb_idl_next_row(row_wref)) {
        const struct ovsdb_datum *wref_datum
            = ovsdb_idl_read(row_wref, wref_column);
        /* If weak reference refers to the 'cur_row', prints it. */
        if (wref_datum->n
            && uuid_equals(&cur_row->uuid, &wref_datum->keys[0].uuid)) {
            const struct ovsdb_datum *name_datum
                = ovsdb_idl_read(row_wref, name_column);
            ds_put_char_multiple(&ctx->output, ' ', (level + 1) * 4);
            ds_put_format(&ctx->output, "%s ", table->name);
            ovsdb_datum_to_string(name_datum, &name_column->type, &ctx->output);
            ds_put_char(&ctx->output, '\n');
        }
    }
}

/* 'shown' records the tables that has been displayed by the current
 * command to avoid duplicated prints.
 */
static void
cmd_show_row(struct ctl_context *ctx, const struct ovsdb_idl_row *row,
             int level, struct sset *shown)
{
    const struct cmd_show_table *show = cmd_show_find_table_by_row(row);
    size_t i;

    ds_put_char_multiple(&ctx->output, ' ', level * 4);
    if (show && show->name_column) {
        const struct ovsdb_datum *datum;

        ds_put_format(&ctx->output, "%s ", show->table->name);
        datum = ovsdb_idl_read(row, show->name_column);
        ovsdb_datum_to_string(datum, &show->name_column->type, &ctx->output);
    } else {
        ds_put_format(&ctx->output, UUID_FMT, UUID_ARGS(&row->uuid));
    }
    ds_put_char(&ctx->output, '\n');

    if (!show || sset_find(shown, show->table->name)) {
        return;
    }

    sset_add(shown, show->table->name);
    for (i = 0; i < ARRAY_SIZE(show->columns); i++) {
        const struct ovsdb_idl_column *column = show->columns[i];
        const struct ovsdb_datum *datum;

        if (!column) {
            break;
        }

        datum = ovsdb_idl_read(row, column);
        if (column->type.key.type == OVSDB_TYPE_UUID &&
            column->type.key.uuid.refTableName) {
            const struct cmd_show_table *ref_show;
            size_t j;

            ref_show = cmd_show_find_table_by_name(
                column->type.key.uuid.refTableName);
            if (ref_show) {
                for (j = 0; j < datum->n; j++) {
                    const struct ovsdb_idl_row *ref_row;

                    ref_row = ovsdb_idl_get_row_for_uuid(ctx->idl,
                                                         ref_show->table,
                                                         &datum->keys[j].uuid);
                    if (ref_row) {
                        cmd_show_row(ctx, ref_row, level + 1, shown);
                    }
                }
                continue;
            }
        } else if (ovsdb_type_is_map(&column->type) &&
                   column->type.value.type == OVSDB_TYPE_UUID &&
                   column->type.value.uuid.refTableName) {
            const struct cmd_show_table *ref_show;
            size_t j;

            /* Prints the key to ref'ed table name map if the ref'ed table
             * is also defined in 'cmd_show_tables'.  */
            ref_show = cmd_show_find_table_by_name(
                column->type.value.uuid.refTableName);
            if (ref_show && ref_show->name_column) {
                ds_put_char_multiple(&ctx->output, ' ', (level + 1) * 4);
                ds_put_format(&ctx->output, "%s:\n", column->name);
                for (j = 0; j < datum->n; j++) {
                    const struct ovsdb_idl_row *ref_row;

                    ref_row = ovsdb_idl_get_row_for_uuid(ctx->idl,
                                                         ref_show->table,
                                                         &datum->values[j].uuid);

                    ds_put_char_multiple(&ctx->output, ' ', (level + 2) * 4);
                    ovsdb_atom_to_string(&datum->keys[j], column->type.key.type,
                                         &ctx->output);
                    ds_put_char(&ctx->output, '=');
                    if (ref_row) {
                        const struct ovsdb_datum *ref_datum;

                        ref_datum = ovsdb_idl_read(ref_row,
                                                   ref_show->name_column);
                        ovsdb_datum_to_string(ref_datum,
                                              &ref_show->name_column->type,
                                              &ctx->output);
                    } else {
                        ds_put_cstr(&ctx->output, "\"<null>\"");
                    }
                    ds_put_char(&ctx->output, '\n');
                }
                continue;
            }
        }

        if (!ovsdb_datum_is_default(datum, &column->type)) {
            ds_put_char_multiple(&ctx->output, ' ', (level + 1) * 4);
            ds_put_format(&ctx->output, "%s: ", column->name);
            ovsdb_datum_to_string(datum, &column->type, &ctx->output);
            ds_put_char(&ctx->output, '\n');
        }
    }
    cmd_show_weak_ref(ctx, show, row, level);
    sset_find_and_delete_assert(shown, show->table->name);
}

static void
cmd_show(struct ctl_context *ctx)
{
    const struct ovsdb_idl_row *row;
    struct sset shown = SSET_INITIALIZER(&shown);

    for (row = ovsdb_idl_first_row(ctx->idl, cmd_show_tables[0].table);
         row; row = ovsdb_idl_next_row(row)) {
        cmd_show_row(ctx, row, 0, &shown);
    }

    ovs_assert(sset_is_empty(&shown));
    sset_destroy(&shown);
}


/* Given pointer to dynamic array 'options_p',  array's current size
 * 'allocated_options_p' and number of added options 'n_options_p',
 * adds all command options to the array.  Enlarges the array if
 * necessary. */
void
ctl_add_cmd_options(struct option **options_p, size_t *n_options_p,
                    size_t *allocated_options_p, int opt_val)
{
    struct option *o;
    const struct shash_node *node;
    size_t n_existing_options = *n_options_p;

    SHASH_FOR_EACH (node, &all_commands) {
        const struct ctl_command_syntax *p = node->data;

        if (p->options[0]) {
            char *save_ptr = NULL;
            char *name;
            char *s;

            s = xstrdup(p->options);
            for (name = strtok_r(s, ",", &save_ptr); name != NULL;
                 name = strtok_r(NULL, ",", &save_ptr)) {
                ovs_assert(name[0] == '-' && name[1] == '-' && name[2]);
                name += 2;

                size_t n = strcspn(name, "=?");
                int has_arg = (name[n] == '\0' ? no_argument
                               : name[n] == '=' ? required_argument
                               : optional_argument);
                name[n] = '\0';

                o = find_option(name, *options_p, *n_options_p);
                if (o) {
                    ovs_assert(o - *options_p >= n_existing_options);
                    ovs_assert(o->has_arg == has_arg);
                } else {
                    o = add_option(options_p, n_options_p, allocated_options_p);
                    o->name = xstrdup(name);
                    o->has_arg = has_arg;
                    o->flag = NULL;
                    o->val = opt_val;
                }
            }

            free(s);
        }
    }
    o = add_option(options_p, n_options_p, allocated_options_p);
    memset(o, 0, sizeof *o);
}

/* Parses command-line input for commands. */
char *
ctl_parse_commands(int argc, char *argv[], struct shash *local_options,
                   struct ctl_command **commandsp, size_t *n_commandsp)
{
    struct ctl_command *commands;
    size_t n_commands, allocated_commands;
    int i, start;
    char *error;

    commands = NULL;
    n_commands = allocated_commands = 0;

    *commandsp = NULL;
    *n_commandsp = 0;

    for (start = i = 0; i <= argc; i++) {
        if (i == argc || !strcmp(argv[i], "--")) {
            if (i > start) {
                if (n_commands >= allocated_commands) {
                    struct ctl_command *c;

                    commands = x2nrealloc(commands, &allocated_commands,
                                          sizeof *commands);
                    for (c = commands; c < &commands[n_commands]; c++) {
                        shash_moved(&c->options);
                    }
                }
                error = parse_command(i - start, &argv[start], local_options,
                                      &commands[n_commands]);
                if (error) {
                    struct ctl_command *c;

                    for (c = commands; c < &commands[n_commands]; c++) {
                        shash_destroy_free_data(&c->options);
                    }
                    free(commands);

                    return error;
                }

                n_commands++;
            } else if (!shash_is_empty(local_options)) {
                return xstrdup("missing command name (use --help for help)");
            }
            start = i + 1;
        }
    }
    if (!n_commands) {
        return xstrdup("missing command name (use --help for help)");
    }
    *commandsp = commands;
    *n_commandsp = n_commands;
    return NULL;
}

/* Prints all registered commands. */
void
ctl_print_commands(void)
{
    const struct shash_node *node;

    SHASH_FOR_EACH (node, &all_commands) {
        const struct ctl_command_syntax *p = node->data;
        char *options = xstrdup(p->options);
        char *options_begin = options;
        char *item;

        for (item = strsep(&options, ","); item != NULL;
             item = strsep(&options, ",")) {
            if (item[0] != '\0') {
                printf("[%s] ", item);
            }
        }
        printf(",%s,", p->name);
        print_command_arguments(p);
        printf("\n");

        free(options_begin);
    }

    exit(EXIT_SUCCESS);
}

/* Given array of options 'options', prints them. */
void
ctl_print_options(const struct option *options)
{
    for (; options->name; options++) {
        const struct option *o = options;

        printf("--%s%s\n", o->name, o->has_arg ? "=ARG" : "");
        if (o->flag == NULL && o->val > 0 && o->val <= UCHAR_MAX) {
            printf("-%c%s\n", o->val, o->has_arg ? " ARG" : "");
        }
    }

    exit(EXIT_SUCCESS);
}

/* Returns the default local database path. */
char *
ctl_default_db(void)
{
    static char *def;
    if (!def) {
        def = xasprintf("unix:%s/db.sock", ovs_rundir());
    }
    return def;
}

/* Returns true if it looks like this set of arguments might modify the
 * database, otherwise false.  (Not very smart, so it's prone to false
 * positives.) */
bool
ctl_might_write_to_db(const struct ctl_command *commands, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (commands[i].syntax->mode == RW) {
            return true;
        }
    }
    return false;
}

/* Report an error while running in the command context. Caller should return
 * to its caller immediately after reporting the error. */
void
ctl_error(struct ctl_context *ctx, const char *format, ...)
{
    va_list args;

    ovs_assert(ctx);

    if (ctx->error) {
        VLOG_ERR("Discarding unhandled error: %s", ctx->error);
        free(ctx->error);
    }

    va_start(args, format);
    ctx->error = xvasprintf(format, args);
    va_end(args);
}

void
ctl_fatal(const char *format, ...)
{
    char *message;
    va_list args;

    va_start(args, format);
    message = xvasprintf(format, args);
    va_end(args);

    vlog_set_levels(&this_module, VLF_CONSOLE, VLL_OFF);
    VLOG_ERR("%s", message);
    ovs_error(0, "%s", message);
    ctl_exit(EXIT_FAILURE);
}

/* Frees the current transaction and the underlying IDL and then calls
 * exit(status).
 *
 * Freeing the transaction and the IDL is not strictly necessary, but it makes
 * for a clean memory leak report from valgrind in the normal case.  That makes
 * it easier to notice real memory leaks. */
static void
ctl_exit(int status)
{
    if (ctl_exit_func) {
        ctl_exit_func(status);
    }
    exit(status);
}

/* Comman database commands to be registered. */
static const struct ctl_command_syntax db_ctl_commands[] = {
    {"comment", 0, INT_MAX, "[ARG]...", NULL, NULL, NULL, "", RO},
    {"get", 2, INT_MAX, "TABLE RECORD [COLUMN[:KEY]]...",pre_cmd_get, cmd_get,
     NULL, "--if-exists,--id=", RO},
    {"list", 1, INT_MAX, "TABLE [RECORD]...", pre_cmd_list, cmd_list, NULL,
     "--if-exists,--columns=", RO},
    {"find", 1, INT_MAX, "TABLE [COLUMN[:KEY]=VALUE]...", pre_cmd_find,
     cmd_find, NULL, "--columns=", RO},
    {"set", 3, INT_MAX, "TABLE RECORD COLUMN[:KEY]=VALUE...", pre_cmd_set,
     cmd_set, NULL, "--if-exists", RW},
    {"add", 4, INT_MAX, "TABLE RECORD COLUMN [KEY=]VALUE...", pre_cmd_add,
     cmd_add, NULL, "--if-exists", RW},
    {"remove", 4, INT_MAX, "TABLE RECORD COLUMN KEY|VALUE|KEY=VALUE...",
     pre_cmd_remove, cmd_remove, NULL, "--if-exists", RW},
    {"clear", 3, INT_MAX, "TABLE RECORD COLUMN...", pre_cmd_clear, cmd_clear,
     NULL, "--if-exists", RW},
    {"create", 2, INT_MAX, "TABLE COLUMN[:KEY]=VALUE...", pre_create,
     cmd_create, post_create, "--id=", RW},
    {"destroy", 1, INT_MAX, "TABLE [RECORD]...", pre_cmd_destroy, cmd_destroy,
     NULL, "--if-exists,--all", RW},
    {"wait-until", 2, INT_MAX, "TABLE RECORD [COLUMN[:KEY]=VALUE]...",
     pre_cmd_wait_until, cmd_wait_until, NULL, "", RO},
    {NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, RO},
};

static void
ctl_register_command(const struct ctl_command_syntax *command)
{
    shash_add_assert(&all_commands, command->name, command);
}

/* Registers commands represented by 'struct ctl_command_syntax's to
 * 'all_commands'.  The last element of 'commands' must be an all-NULL
 * element. */
void
ctl_register_commands(const struct ctl_command_syntax *commands)
{
    const struct ctl_command_syntax *p;

    for (p = commands; p->name; p++) {
        ctl_register_command(p);
    }
}

/* Registers the 'db_ctl_commands' to 'all_commands'. */
void
ctl_init__(const struct ovsdb_idl_class *idl_class_,
           const struct ctl_table_class *ctl_classes_,
           const struct cmd_show_table cmd_show_tables_[],
           void (*ctl_exit_func_)(int status))
{
    idl_class = idl_class_;
    idl_classes = idl_class_->tables;
    ctl_classes = ctl_classes_;
    n_classes = idl_class->n_tables;
    ctl_exit_func = ctl_exit_func_;
    ctl_register_commands(db_ctl_commands);

    cmd_show_tables = cmd_show_tables_;
    if (cmd_show_tables) {
        static const struct ctl_command_syntax show =
            {"show", 0, 0, "", pre_cmd_show, cmd_show, NULL, "", RO};
        ctl_register_command(&show);
    }
}

/* Returns the text for the database commands usage.  */
const char *
ctl_get_db_cmd_usage(void)
{
    return "Database commands:\n\
  list TBL [REC]              list RECord (or all records) in TBL\n\
  find TBL CONDITION...       list records satisfying CONDITION in TBL\n\
  get TBL REC COL[:KEY]       print values of COLumns in RECord in TBL\n\
  set TBL REC COL[:KEY]=VALUE set COLumn values in RECord in TBL\n\
  add TBL REC COL [KEY=]VALUE add (KEY=)VALUE to COLumn in RECord in TBL\n\
  remove TBL REC COL [KEY=]VALUE  remove (KEY=)VALUE from COLumn\n\
  clear TBL REC COL           clear values from COLumn in RECord in TBL\n\
  create TBL COL[:KEY]=VALUE  create and initialize new record\n\
  destroy TBL REC             delete RECord from TBL\n\
  wait-until TBL REC [COL[:KEY]=VALUE]  wait until condition is true\n\
Potentially unsafe database commands require --force option.\n";
}

const char *
ctl_list_db_tables_usage(void)
{
    static struct ds s = DS_EMPTY_INITIALIZER;
    if (s.length) {
        return ds_cstr(&s);
    }

    ds_put_cstr(&s, "Database commands may reference a row in each table in the following ways:\n");
    for (int i = 0; i < n_classes; i++) {
        struct svec options = SVEC_EMPTY_INITIALIZER;

        svec_add(&options, "by UUID");
        if (idl_classes[i].is_singleton) {
            svec_add(&options, "as \".\"");
        }

        for (int j = 0; j < ARRAY_SIZE(ctl_classes[i].row_ids); j++) {
            const struct ctl_row_id *id = &ctl_classes[i].row_ids[j];
            if (!id->name_column) {
                continue;
            }

            struct ds o = DS_EMPTY_INITIALIZER;
            if (id->uuid_column) {
                ds_put_format(&o, "via \"%s\"", id->uuid_column->name);
                const struct ovsdb_idl_table_class *referrer
                    = ovsdb_idl_table_class_from_column(idl_class,
                                                        id->uuid_column);
                if (referrer != &idl_classes[i]) {
                    ds_put_format(&o, " of %s", referrer->name);
                }
                if (id->key) {
                    ds_put_format(&o, " with matching \"%s:%s\"",
                                  id->name_column->name, id->key);
                } else {
                    ds_put_format(&o, " with matching \"%s\"", id->name_column->name);
                }
            } else if (id->key) {
                ds_put_format(&o, "by \"%s:%s\"", id->name_column->name, id->key);
            } else {
                ds_put_format(&o, "by \"%s\"", id->name_column->name);
            }
            svec_add_nocopy(&options, ds_steal_cstr(&o));
        }

        ds_put_format(&s, "  %s:", idl_classes[i].name);
        for (int j = 0; j < options.n; j++) {
            ds_put_format(&s, "\n    %s", options.names[j]);
        }
        ds_put_char(&s, '\n');
        svec_destroy(&options);
    }

    return ds_cstr(&s);
}

/* Initializes 'ctx' from 'command'. */
void
ctl_context_init_command(struct ctl_context *ctx,
                         struct ctl_command *command)
{
    ctx->argc = command->argc;
    ctx->argv = command->argv;
    ctx->options = command->options;

    ds_swap(&ctx->output, &command->output);
    ctx->table = command->table;
    ctx->try_again = false;
    ctx->error = NULL;
}

/* Initializes the entire 'ctx'. */
void
ctl_context_init(struct ctl_context *ctx, struct ctl_command *command,
                 struct ovsdb_idl *idl, struct ovsdb_idl_txn *txn,
                 struct ovsdb_symbol_table *symtab,
                 void (*invalidate_cache_cb)(struct ctl_context *))
{
    if (command) {
        ctl_context_init_command(ctx, command);
    }
    ctx->idl = idl;
    ctx->txn = txn;
    ctx->symtab = symtab;
    ctx->invalidate_cache_cb = invalidate_cache_cb;
}

/* Completes processing of 'command' within 'ctx'. */
void
ctl_context_done_command(struct ctl_context *ctx,
                         struct ctl_command *command)
{
    ds_swap(&ctx->output, &command->output);
    command->table = ctx->table;
    free(ctx->error);
    ctx->error = NULL;
}

/* Finishes up with 'ctx'.
 *
 * If command is nonnull, first calls ctl_context_done_command() to complete
 * processing that command within 'ctx'. */
void
ctl_context_done(struct ctl_context *ctx,
                 struct ctl_command *command)
{
    if (command) {
        ctl_context_done_command(ctx, command);
    }
    invalidate_cache(ctx);
}

char * OVS_WARN_UNUSED_RESULT
ctl_set_column(const char *table_name, const struct ovsdb_idl_row *row,
               const char *arg, struct ovsdb_symbol_table *symtab)
{
    const struct ovsdb_idl_table_class *table;
    char *error;

    error = get_table(table_name, &table);
    if (error) {
        return error;
    }
    error = set_column(table, row, arg, symtab);
    if (error) {
        return error;
    }

    return NULL;
}
