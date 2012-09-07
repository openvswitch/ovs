/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "command-line.h"
#include "dynamic-string.h"
#include "json.h"
#include "jsonrpc.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-idl.h"
#include "ovsdb-types.h"
#include "ovsdb/column.h"
#include "ovsdb/condition.h"
#include "ovsdb/file.h"
#include "ovsdb/log.h"
#include "ovsdb/mutation.h"
#include "ovsdb/ovsdb.h"
#include "ovsdb/query.h"
#include "ovsdb/row.h"
#include "ovsdb/server.h"
#include "ovsdb/table.h"
#include "ovsdb/transaction.h"
#include "ovsdb/trigger.h"
#include "poll-loop.h"
#include "stream.h"
#include "svec.h"
#include "tests/idltest.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

static struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    parse_options(argc, argv);
    run_command(argc - optind, argv + optind, all_commands);
    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"timeout", required_argument, NULL, 't'},
        {"verbose", optional_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ovs_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            break;

        case 'h':
            usage();

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: Open vSwitch database test utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n\n"
           "  log-io FILE FLAGS COMMAND...\n"
           "    open FILE with FLAGS, run COMMANDs\n"
           "  default-atoms\n"
           "    test ovsdb_atom_default()\n"
           "  default-data\n"
           "    test ovsdb_datum_default()\n"
           "  parse-atomic-type TYPE\n"
           "    parse TYPE as OVSDB atomic type, and re-serialize\n"
           "  parse-base-type TYPE\n"
           "    parse TYPE as OVSDB base type, and re-serialize\n"
           "  parse-type JSON\n"
           "    parse JSON as OVSDB type, and re-serialize\n"
           "  parse-atoms TYPE ATOM...\n"
           "    parse JSON ATOMs as atoms of TYPE, and re-serialize\n"
           "  parse-atom-strings TYPE ATOM...\n"
           "    parse string ATOMs as atoms of given TYPE, and re-serialize\n"
           "  sort-atoms TYPE ATOM...\n"
           "    print JSON ATOMs in sorted order\n"
           "  parse-data TYPE DATUM...\n"
           "    parse JSON DATUMs as data of given TYPE, and re-serialize\n"
           "  parse-data-strings TYPE DATUM...\n"
           "    parse string DATUMs as data of given TYPE, and re-serialize\n"
           "  parse-column NAME OBJECT\n"
           "    parse column NAME with info OBJECT, and re-serialize\n"
           "  parse-table NAME OBJECT [DEFAULT-IS-ROOT]\n"
           "    parse table NAME with info OBJECT\n"
           "  parse-row TABLE ROW..., and re-serialize\n"
           "    parse each ROW of defined TABLE\n"
           "  compare-row TABLE ROW...\n"
           "    mutually compare all of the ROWs, print those that are equal\n"
           "  parse-conditions TABLE CONDITION...\n"
           "    parse each CONDITION on TABLE, and re-serialize\n"
           "  evaluate-conditions TABLE [CONDITION,...] [ROW,...]\n"
           "    test CONDITIONS on TABLE against each ROW, print results\n"
           "  parse-mutations TABLE MUTATION...\n"
           "    parse each MUTATION on TABLE, and re-serialize\n"
           "  execute-mutations TABLE [MUTATION,...] [ROW,...]\n"
           "    execute MUTATIONS on TABLE on each ROW, print results\n"
           "  query TABLE [ROW,...] [CONDITION,...]\n"
           "    add each ROW to TABLE, then query and print the rows that\n"
           "    satisfy each CONDITION.\n"
           "  query-distinct TABLE [ROW,...] [CONDITION,...] COLUMNS\n"
           "    add each ROW to TABLE, then query and print the rows that\n"
           "    satisfy each CONDITION and have distinct COLUMNS.\n"
           "  parse-schema JSON\n"
           "    parse JSON as an OVSDB schema, and re-serialize\n"
           "  transact COMMAND\n"
           "    execute each specified transactional COMMAND:\n"
           "      commit\n"
           "      abort\n"
           "      insert UUID I J\n"
           "      delete UUID\n"
           "      modify UUID I J\n"
           "      print\n"
           "  execute SCHEMA TRANSACTION...\n"
           "    executes each TRANSACTION on an initially empty database\n"
           "    the specified SCHEMA\n"
           "  trigger SCHEMA TRANSACTION...\n"
           "    executes each TRANSACTION on an initially empty database\n"
           "    the specified SCHEMA.   A TRANSACTION of the form\n"
           "    [\"advance\", NUMBER] advances NUMBER milliseconds in\n"
           "    simulated time, for causing triggers to time out.\n"
           "  idl SERVER [TRANSACTION...]\n"
           "    connect to SERVER and dump the contents of the database\n"
           "    as seen initially by the IDL implementation and after\n"
           "    executing each TRANSACTION.  (Each TRANSACTION must modify\n"
           "    the database or this command will hang.)\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOther options:\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  -h, --help                  display this help message\n");
    exit(EXIT_SUCCESS);
}

/* Command helper functions. */

static struct json *
parse_json(const char *s)
{
    struct json *json = json_from_string(s);
    if (json->type == JSON_STRING) {
        ovs_fatal(0, "\"%s\": %s", s, json->u.string);
    }
    return json;
}

static struct json *
unbox_json(struct json *json)
{
    if (json->type == JSON_ARRAY && json->u.array.n == 1) {
        struct json *inner = json->u.array.elems[0];
        json->u.array.elems[0] = NULL;
        json_destroy(json);
        return inner;
    } else {
        return json;
    }
}

static void
print_and_free_json(struct json *json)
{
    char *string = json_to_string(json, JSSF_SORT);
    json_destroy(json);
    puts(string);
    free(string);
}

static void
print_and_free_ovsdb_error(struct ovsdb_error *error)
{
    char *string = ovsdb_error_to_string(error);
    ovsdb_error_destroy(error);
    puts(string);
    free(string);
}

static void
check_ovsdb_error(struct ovsdb_error *error)
{
    if (error) {
        char *s = ovsdb_error_to_string(error);
        ovsdb_error_destroy(error);
        ovs_fatal(0, "%s", s);
    }
}

static void
die_if_error(char *error)
{
    if (error) {
        ovs_fatal(0, "%s", error);
    }
}

/* Command implementations. */

static void
do_log_io(int argc, char *argv[])
{
    const char *name = argv[1];
    char *mode_string = argv[2];

    struct ovsdb_error *error;
    enum ovsdb_log_open_mode mode;
    struct ovsdb_log *log;
    int i;

    if (!strcmp(mode_string, "read-only")) {
        mode = OVSDB_LOG_READ_ONLY;
    } else if (!strcmp(mode_string, "read/write")) {
        mode = OVSDB_LOG_READ_WRITE;
    } else if (!strcmp(mode_string, "create")) {
        mode = OVSDB_LOG_CREATE;
    } else {
        ovs_fatal(0, "unknown log-io open mode \"%s\"", mode_string);
    }

    check_ovsdb_error(ovsdb_log_open(name, mode, -1, &log));
    printf("%s: open successful\n", name);

    for (i = 3; i < argc; i++) {
        const char *command = argv[i];
        if (!strcmp(command, "read")) {
            struct json *json;

            error = ovsdb_log_read(log, &json);
            if (!error) {
                printf("%s: read: ", name);
                if (json) {
                    print_and_free_json(json);
                } else {
                    printf("end of log\n");
                }
                continue;
            }
        } else if (!strncmp(command, "write:", 6)) {
            struct json *json = parse_json(command + 6);
            error = ovsdb_log_write(log, json);
            json_destroy(json);
        } else if (!strcmp(command, "commit")) {
            error = ovsdb_log_commit(log);
        } else {
            ovs_fatal(0, "unknown log-io command \"%s\"", command);
        }
        if (error) {
            char *s = ovsdb_error_to_string(error);
            printf("%s: %s failed: %s\n", name, command, s);
            free(s);
            ovsdb_error_destroy(error);
        } else {
            printf("%s: %s successful\n", name, command);
        }
    }

    ovsdb_log_close(log);
}

static void
do_default_atoms(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    int type;

    for (type = 0; type < OVSDB_N_TYPES; type++) {
        union ovsdb_atom atom;

        if (type == OVSDB_TYPE_VOID) {
            continue;
        }

        printf("%s: ", ovsdb_atomic_type_to_string(type));

        ovsdb_atom_init_default(&atom, type);
        if (!ovsdb_atom_equals(&atom, ovsdb_atom_default(type), type)) {
            printf("wrong\n");
            exit(1);
        }
        ovsdb_atom_destroy(&atom, type);

        printf("OK\n");
    }
}

static void
do_default_data(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned int n_min;
    int key, value;

    for (n_min = 0; n_min <= 1; n_min++) {
        for (key = 0; key < OVSDB_N_TYPES; key++) {
            if (key == OVSDB_TYPE_VOID) {
                continue;
            }
            for (value = 0; value < OVSDB_N_TYPES; value++) {
                struct ovsdb_datum datum;
                struct ovsdb_type type;

                ovsdb_base_type_init(&type.key, key);
                ovsdb_base_type_init(&type.value, value);
                type.n_min = n_min;
                type.n_max = 1;
                assert(ovsdb_type_is_valid(&type));

                printf("key %s, value %s, n_min %u: ",
                       ovsdb_atomic_type_to_string(key),
                       ovsdb_atomic_type_to_string(value), n_min);

                ovsdb_datum_init_default(&datum, &type);
                if (!ovsdb_datum_equals(&datum, ovsdb_datum_default(&type),
                                        &type)) {
                    printf("wrong\n");
                    exit(1);
                }
                ovsdb_datum_destroy(&datum, &type);
                ovsdb_type_destroy(&type);

                printf("OK\n");
            }
        }
    }
}

static void
do_parse_atomic_type(int argc OVS_UNUSED, char *argv[])
{
    enum ovsdb_atomic_type type;
    struct json *json;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_atomic_type_from_json(&type, json));
    json_destroy(json);
    print_and_free_json(ovsdb_atomic_type_to_json(type));
}

static void
do_parse_base_type(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_base_type base;
    struct json *json;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_base_type_from_json(&base, json));
    json_destroy(json);
    print_and_free_json(ovsdb_base_type_to_json(&base));
    ovsdb_base_type_destroy(&base);
}

static void
do_parse_type(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_type type;
    struct json *json;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_type_from_json(&type, json));
    json_destroy(json);
    print_and_free_json(ovsdb_type_to_json(&type));
    ovsdb_type_destroy(&type);
}

static void
do_parse_atoms(int argc, char *argv[])
{
    struct ovsdb_base_type base;
    struct json *json;
    int i;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_base_type_from_json(&base, json));
    json_destroy(json);

    for (i = 2; i < argc; i++) {
        struct ovsdb_error *error;
        union ovsdb_atom atom;

        json = unbox_json(parse_json(argv[i]));
        error = ovsdb_atom_from_json(&atom, &base, json, NULL);
        json_destroy(json);

        if (error) {
            print_and_free_ovsdb_error(error);
        } else {
            print_and_free_json(ovsdb_atom_to_json(&atom, base.type));
            ovsdb_atom_destroy(&atom, base.type);
        }
    }
    ovsdb_base_type_destroy(&base);
}

static void
do_parse_atom_strings(int argc, char *argv[])
{
    struct ovsdb_base_type base;
    struct json *json;
    int i;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_base_type_from_json(&base, json));
    json_destroy(json);

    for (i = 2; i < argc; i++) {
        union ovsdb_atom atom;
        struct ds out;

        die_if_error(ovsdb_atom_from_string(&atom, &base, argv[i], NULL));

        ds_init(&out);
        ovsdb_atom_to_string(&atom, base.type, &out);
        puts(ds_cstr(&out));
        ds_destroy(&out);

        ovsdb_atom_destroy(&atom, base.type);
    }
    ovsdb_base_type_destroy(&base);
}

static void
do_parse_data__(int argc, char *argv[],
                struct ovsdb_error *
                (*parse)(struct ovsdb_datum *datum,
                         const struct ovsdb_type *type,
                         const struct json *json,
                         struct ovsdb_symbol_table *symtab))
{
    struct ovsdb_type type;
    struct json *json;
    int i;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_type_from_json(&type, json));
    json_destroy(json);

    for (i = 2; i < argc; i++) {
        struct ovsdb_datum datum;

        json = unbox_json(parse_json(argv[i]));
        check_ovsdb_error(parse(&datum, &type, json, NULL));
        json_destroy(json);

        print_and_free_json(ovsdb_datum_to_json(&datum, &type));

        ovsdb_datum_destroy(&datum, &type);
    }
    ovsdb_type_destroy(&type);
}

static void
do_parse_data(int argc, char *argv[])
{
    do_parse_data__(argc, argv, ovsdb_datum_from_json);
}

static void
do_parse_data_strings(int argc, char *argv[])
{
    struct ovsdb_type type;
    struct json *json;
    int i;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_type_from_json(&type, json));
    json_destroy(json);

    for (i = 2; i < argc; i++) {
        struct ovsdb_datum datum;
        struct ds out;

        die_if_error(ovsdb_datum_from_string(&datum, &type, argv[i], NULL));

        ds_init(&out);
        ovsdb_datum_to_string(&datum, &type, &out);
        puts(ds_cstr(&out));
        ds_destroy(&out);

        ovsdb_datum_destroy(&datum, &type);
    }
    ovsdb_type_destroy(&type);
}

static enum ovsdb_atomic_type compare_atoms_atomic_type;

static int
compare_atoms(const void *a_, const void *b_)
{
    const union ovsdb_atom *a = a_;
    const union ovsdb_atom *b = b_;

    return ovsdb_atom_compare_3way(a, b, compare_atoms_atomic_type);
}

static void
do_sort_atoms(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_base_type base;
    union ovsdb_atom *atoms;
    struct json *json, **json_atoms;
    size_t n_atoms;
    int i;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_base_type_from_json(&base, json));
    json_destroy(json);

    json = unbox_json(parse_json(argv[2]));
    if (json->type != JSON_ARRAY) {
        ovs_fatal(0, "second argument must be array");
    }

    /* Convert JSON atoms to internal representation. */
    n_atoms = json->u.array.n;
    atoms = xmalloc(n_atoms * sizeof *atoms);
    for (i = 0; i < n_atoms; i++) {
        check_ovsdb_error(ovsdb_atom_from_json(&atoms[i], &base,
                                               json->u.array.elems[i], NULL));
    }
    json_destroy(json);

    /* Sort atoms. */
    compare_atoms_atomic_type = base.type;
    qsort(atoms, n_atoms, sizeof *atoms, compare_atoms);

    /* Convert internal representation back to JSON. */
    json_atoms = xmalloc(n_atoms * sizeof *json_atoms);
    for (i = 0; i < n_atoms; i++) {
        json_atoms[i] = ovsdb_atom_to_json(&atoms[i], base.type);
        ovsdb_atom_destroy(&atoms[i], base.type);
    }
    print_and_free_json(json_array_create(json_atoms, n_atoms));
    free(atoms);
    ovsdb_base_type_destroy(&base);
}

static void
do_parse_column(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_column *column;
    struct json *json;

    json = parse_json(argv[2]);
    check_ovsdb_error(ovsdb_column_from_json(json, argv[1], &column));
    json_destroy(json);
    print_and_free_json(ovsdb_column_to_json(column));
    ovsdb_column_destroy(column);
}

static void
do_parse_table(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_table_schema *ts;
    bool default_is_root;
    struct json *json;

    default_is_root = argc > 3 && !strcmp(argv[3], "true");

    json = parse_json(argv[2]);
    check_ovsdb_error(ovsdb_table_schema_from_json(json, argv[1], &ts));
    json_destroy(json);
    print_and_free_json(ovsdb_table_schema_to_json(ts, default_is_root));
    ovsdb_table_schema_destroy(ts);
}

static void
do_parse_rows(int argc, char *argv[])
{
    struct ovsdb_column_set all_columns;
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct json *json;
    int i;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);
    ovsdb_column_set_init(&all_columns);
    ovsdb_column_set_add_all(&all_columns, table);

    for (i = 2; i < argc; i++) {
        struct ovsdb_column_set columns;
        struct ovsdb_row *row;

        ovsdb_column_set_init(&columns);
        row = ovsdb_row_create(table);

        json = unbox_json(parse_json(argv[i]));
        check_ovsdb_error(ovsdb_row_from_json(row, json, NULL, &columns));
        json_destroy(json);

        print_and_free_json(ovsdb_row_to_json(row, &all_columns));

        if (columns.n_columns) {
            struct svec names;
            size_t j;
            char *s;

            svec_init(&names);
            for (j = 0; j < columns.n_columns; j++) {
                svec_add(&names, columns.columns[j]->name);
            }
            svec_sort(&names);
            s = svec_join(&names, ", ", "");
            puts(s);
            free(s);
            svec_destroy(&names);
        } else {
            printf("<none>\n");
        }

        ovsdb_column_set_destroy(&columns);
        ovsdb_row_destroy(row);
    }

    ovsdb_column_set_destroy(&all_columns);
    ovsdb_table_destroy(table); /* Also destroys 'ts'. */
}

static void
do_compare_rows(int argc, char *argv[])
{
    struct ovsdb_column_set all_columns;
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct ovsdb_row **rows;
    struct json *json;
    char **names;
    int n_rows;
    int i, j;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);
    ovsdb_column_set_init(&all_columns);
    ovsdb_column_set_add_all(&all_columns, table);

    n_rows = argc - 2;
    rows = xmalloc(sizeof *rows * n_rows);
    names = xmalloc(sizeof *names * n_rows);
    for (i = 0; i < n_rows; i++) {
        rows[i] = ovsdb_row_create(table);

        json = parse_json(argv[i + 2]);
        if (json->type != JSON_ARRAY || json->u.array.n != 2
            || json->u.array.elems[0]->type != JSON_STRING) {
            ovs_fatal(0, "\"%s\" does not have expected form "
                      "[\"name\", {data}]", argv[i]);
        }
        names[i] = xstrdup(json->u.array.elems[0]->u.string);
        check_ovsdb_error(ovsdb_row_from_json(rows[i], json->u.array.elems[1],
                                              NULL, NULL));
        json_destroy(json);
    }
    for (i = 0; i < n_rows; i++) {
        uint32_t i_hash = ovsdb_row_hash_columns(rows[i], &all_columns, 0);
        for (j = i + 1; j < n_rows; j++) {
            uint32_t j_hash = ovsdb_row_hash_columns(rows[j], &all_columns, 0);
            if (ovsdb_row_equal_columns(rows[i], rows[j], &all_columns)) {
                printf("%s == %s\n", names[i], names[j]);
                if (i_hash != j_hash) {
                    printf("but hash(%s) != hash(%s)\n", names[i], names[j]);
                    abort();
                }
            } else if (i_hash == j_hash) {
                printf("hash(%s) == hash(%s)\n", names[i], names[j]);
            }
        }
    }
    for (i = 0; i < n_rows; i++) {
        ovsdb_row_destroy(rows[i]);
        free(names[i]);
    }
    free(rows);
    free(names);

    ovsdb_column_set_destroy(&all_columns);
    ovsdb_table_destroy(table); /* Also destroys 'ts'. */
}

static void
do_parse_conditions(int argc, char *argv[])
{
    struct ovsdb_table_schema *ts;
    struct json *json;
    int exit_code = 0;
    int i;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    for (i = 2; i < argc; i++) {
        struct ovsdb_condition cnd;
        struct ovsdb_error *error;

        json = parse_json(argv[i]);
        error = ovsdb_condition_from_json(ts, json, NULL, &cnd);
        if (!error) {
            print_and_free_json(ovsdb_condition_to_json(&cnd));
        } else {
            char *s = ovsdb_error_to_string(error);
            ovs_error(0, "%s", s);
            free(s);
            ovsdb_error_destroy(error);
            exit_code = 1;
        }
        json_destroy(json);

        ovsdb_condition_destroy(&cnd);
    }
    ovsdb_table_schema_destroy(ts);

    exit(exit_code);
}

static void
do_evaluate_conditions(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct ovsdb_condition *conditions;
    size_t n_conditions;
    struct ovsdb_row **rows;
    size_t n_rows;
    struct json *json;
    size_t i, j;

    /* Parse table schema, create table. */
    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);

    /* Parse conditions. */
    json = parse_json(argv[2]);
    if (json->type != JSON_ARRAY) {
        ovs_fatal(0, "CONDITION argument is not JSON array");
    }
    n_conditions = json->u.array.n;
    conditions = xmalloc(n_conditions * sizeof *conditions);
    for (i = 0; i < n_conditions; i++) {
        check_ovsdb_error(ovsdb_condition_from_json(ts, json->u.array.elems[i],
                                                    NULL, &conditions[i]));
    }
    json_destroy(json);

    /* Parse rows. */
    json = parse_json(argv[3]);
    if (json->type != JSON_ARRAY) {
        ovs_fatal(0, "ROW argument is not JSON array");
    }
    n_rows = json->u.array.n;
    rows = xmalloc(n_rows * sizeof *rows);
    for (i = 0; i < n_rows; i++) {
        rows[i] = ovsdb_row_create(table);
        check_ovsdb_error(ovsdb_row_from_json(rows[i], json->u.array.elems[i],
                                              NULL, NULL));
    }
    json_destroy(json);

    for (i = 0; i < n_conditions; i++) {
        printf("condition %2zu:", i);
        for (j = 0; j < n_rows; j++) {
            bool result = ovsdb_condition_evaluate(rows[j], &conditions[i]);
            if (j % 5 == 0) {
                putchar(' ');
            }
            putchar(result ? 'T' : '-');
        }
        printf("\n");
    }

    for (i = 0; i < n_conditions; i++) {
        ovsdb_condition_destroy(&conditions[i]);
    }
    free(conditions);
    for (i = 0; i < n_rows; i++) {
        ovsdb_row_destroy(rows[i]);
    }
    free(rows);
    ovsdb_table_destroy(table); /* Also destroys 'ts'. */
}

static void
do_parse_mutations(int argc, char *argv[])
{
    struct ovsdb_table_schema *ts;
    struct json *json;
    int exit_code = 0;
    int i;

    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    for (i = 2; i < argc; i++) {
        struct ovsdb_mutation_set set;
        struct ovsdb_error *error;

        json = parse_json(argv[i]);
        error = ovsdb_mutation_set_from_json(ts, json, NULL, &set);
        if (!error) {
            print_and_free_json(ovsdb_mutation_set_to_json(&set));
        } else {
            char *s = ovsdb_error_to_string(error);
            ovs_error(0, "%s", s);
            free(s);
            ovsdb_error_destroy(error);
            exit_code = 1;
        }
        json_destroy(json);

        ovsdb_mutation_set_destroy(&set);
    }
    ovsdb_table_schema_destroy(ts);

    exit(exit_code);
}

static void
do_execute_mutations(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct ovsdb_mutation_set *sets;
    size_t n_sets;
    struct ovsdb_row **rows;
    size_t n_rows;
    struct json *json;
    size_t i, j;

    /* Parse table schema, create table. */
    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);

    /* Parse mutations. */
    json = parse_json(argv[2]);
    if (json->type != JSON_ARRAY) {
        ovs_fatal(0, "MUTATION argument is not JSON array");
    }
    n_sets = json->u.array.n;
    sets = xmalloc(n_sets * sizeof *sets);
    for (i = 0; i < n_sets; i++) {
        check_ovsdb_error(ovsdb_mutation_set_from_json(ts,
                                                       json->u.array.elems[i],
                                                       NULL, &sets[i]));
    }
    json_destroy(json);

    /* Parse rows. */
    json = parse_json(argv[3]);
    if (json->type != JSON_ARRAY) {
        ovs_fatal(0, "ROW argument is not JSON array");
    }
    n_rows = json->u.array.n;
    rows = xmalloc(n_rows * sizeof *rows);
    for (i = 0; i < n_rows; i++) {
        rows[i] = ovsdb_row_create(table);
        check_ovsdb_error(ovsdb_row_from_json(rows[i], json->u.array.elems[i],
                                              NULL, NULL));
    }
    json_destroy(json);

    for (i = 0; i < n_sets; i++) {
        printf("mutation %2zu:\n", i);
        for (j = 0; j < n_rows; j++) {
            struct ovsdb_error *error;
            struct ovsdb_row *row;

            row = ovsdb_row_clone(rows[j]);
            error = ovsdb_mutation_set_execute(row, &sets[i]);

            printf("row %zu: ", j);
            if (error) {
                print_and_free_ovsdb_error(error);
            } else {
                struct ovsdb_column_set columns;
                struct shash_node *node;

                ovsdb_column_set_init(&columns);
                SHASH_FOR_EACH (node, &ts->columns) {
                    struct ovsdb_column *c = node->data;
                    if (!ovsdb_datum_equals(&row->fields[c->index],
                                            &rows[j]->fields[c->index],
                                            &c->type)) {
                        ovsdb_column_set_add(&columns, c);
                    }
                }
                if (columns.n_columns) {
                    print_and_free_json(ovsdb_row_to_json(row, &columns));
                } else {
                    printf("no change\n");
                }
                ovsdb_column_set_destroy(&columns);
            }
            ovsdb_row_destroy(row);
        }
        printf("\n");
    }

    for (i = 0; i < n_sets; i++) {
        ovsdb_mutation_set_destroy(&sets[i]);
    }
    free(sets);
    for (i = 0; i < n_rows; i++) {
        ovsdb_row_destroy(rows[i]);
    }
    free(rows);
    ovsdb_table_destroy(table); /* Also destroys 'ts'. */
}

/* Inserts a row, without bothering to update metadata such as refcounts. */
static void
put_row(struct ovsdb_table *table, struct ovsdb_row *row)
{
    const struct uuid *uuid = ovsdb_row_get_uuid(row);
    if (!ovsdb_table_get_row(table, uuid)) {
        hmap_insert(&table->rows, &row->hmap_node, uuid_hash(uuid));
    }
}

struct do_query_cbdata {
    struct uuid *row_uuids;
    int *counts;
    size_t n_rows;
};

static bool
do_query_cb(const struct ovsdb_row *row, void *cbdata_)
{
    struct do_query_cbdata *cbdata = cbdata_;
    size_t i;

    for (i = 0; i < cbdata->n_rows; i++) {
        if (uuid_equals(ovsdb_row_get_uuid(row), &cbdata->row_uuids[i])) {
            cbdata->counts[i]++;
        }
    }

    return true;
}

static void
do_query(int argc OVS_UNUSED, char *argv[])
{
    struct do_query_cbdata cbdata;
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct json *json;
    int exit_code = 0;
    size_t i;

    /* Parse table schema, create table. */
    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);

    /* Parse rows, add to table. */
    json = parse_json(argv[2]);
    if (json->type != JSON_ARRAY) {
        ovs_fatal(0, "ROW argument is not JSON array");
    }
    cbdata.n_rows = json->u.array.n;
    cbdata.row_uuids = xmalloc(cbdata.n_rows * sizeof *cbdata.row_uuids);
    cbdata.counts = xmalloc(cbdata.n_rows * sizeof *cbdata.counts);
    for (i = 0; i < cbdata.n_rows; i++) {
        struct ovsdb_row *row = ovsdb_row_create(table);
        uuid_generate(ovsdb_row_get_uuid_rw(row));
        check_ovsdb_error(ovsdb_row_from_json(row, json->u.array.elems[i],
                                              NULL, NULL));
        if (ovsdb_table_get_row(table, ovsdb_row_get_uuid(row))) {
            ovs_fatal(0, "duplicate UUID "UUID_FMT" in table",
                      UUID_ARGS(ovsdb_row_get_uuid(row)));
        }
        cbdata.row_uuids[i] = *ovsdb_row_get_uuid(row);
        put_row(table, row);
    }
    json_destroy(json);

    /* Parse conditions and execute queries. */
    json = parse_json(argv[3]);
    if (json->type != JSON_ARRAY) {
        ovs_fatal(0, "CONDITION argument is not JSON array");
    }
    for (i = 0; i < json->u.array.n; i++) {
        struct ovsdb_condition cnd;
        size_t j;

        check_ovsdb_error(ovsdb_condition_from_json(ts, json->u.array.elems[i],
                                                    NULL, &cnd));

        memset(cbdata.counts, 0, cbdata.n_rows * sizeof *cbdata.counts);
        ovsdb_query(table, &cnd, do_query_cb, &cbdata);

        printf("query %2zu:", i);
        for (j = 0; j < cbdata.n_rows; j++) {
            if (j % 5 == 0) {
                putchar(' ');
            }
            if (cbdata.counts[j]) {
                printf("%d", cbdata.counts[j]);
                if (cbdata.counts[j] > 1) {
                    /* Dup! */
                    exit_code = 1;
                }
            } else {
                putchar('-');
            }
        }
        putchar('\n');

        ovsdb_condition_destroy(&cnd);
    }
    json_destroy(json);

    ovsdb_table_destroy(table); /* Also destroys 'ts'. */

    exit(exit_code);
}

struct do_query_distinct_class {
    struct ovsdb_row *example;
    int count;
};

struct do_query_distinct_row {
    struct uuid uuid;
    struct do_query_distinct_class *class;
};

static void
do_query_distinct(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_column_set columns;
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct do_query_distinct_row *rows;
    size_t n_rows;
    struct do_query_distinct_class *classes;
    size_t n_classes;
    struct json *json;
    int exit_code = 0;
    size_t i;

    /* Parse table schema, create table. */
    json = unbox_json(parse_json(argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);

    /* Parse column set. */
    json = parse_json(argv[4]);
    check_ovsdb_error(ovsdb_column_set_from_json(json, table->schema,
                                                 &columns));
    json_destroy(json);

    /* Parse rows, add to table. */
    json = parse_json(argv[2]);
    if (json->type != JSON_ARRAY) {
        ovs_fatal(0, "ROW argument is not JSON array");
    }
    n_rows = json->u.array.n;
    rows = xmalloc(n_rows * sizeof *rows);
    classes = xmalloc(n_rows * sizeof *classes);
    n_classes = 0;
    for (i = 0; i < n_rows; i++) {
        struct ovsdb_row *row;
        size_t j;

        /* Parse row. */
        row = ovsdb_row_create(table);
        uuid_generate(ovsdb_row_get_uuid_rw(row));
        check_ovsdb_error(ovsdb_row_from_json(row, json->u.array.elems[i],
                                              NULL, NULL));

        /* Initialize row and find equivalence class. */
        rows[i].uuid = *ovsdb_row_get_uuid(row);
        rows[i].class = NULL;
        for (j = 0; j < n_classes; j++) {
            if (ovsdb_row_equal_columns(row, classes[j].example, &columns)) {
                rows[i].class = &classes[j];
                break;
            }
        }
        if (!rows[i].class) {
            rows[i].class = &classes[n_classes];
            classes[n_classes].example = ovsdb_row_clone(row);
            n_classes++;
        }

        /* Add row to table. */
        if (ovsdb_table_get_row(table, ovsdb_row_get_uuid(row))) {
            ovs_fatal(0, "duplicate UUID "UUID_FMT" in table",
                      UUID_ARGS(ovsdb_row_get_uuid(row)));
        }
        put_row(table, row);

    }
    json_destroy(json);

    /* Parse conditions and execute queries. */
    json = parse_json(argv[3]);
    if (json->type != JSON_ARRAY) {
        ovs_fatal(0, "CONDITION argument is not JSON array");
    }
    for (i = 0; i < json->u.array.n; i++) {
        struct ovsdb_row_set results;
        struct ovsdb_condition cnd;
        size_t j;

        check_ovsdb_error(ovsdb_condition_from_json(ts, json->u.array.elems[i],
                                                    NULL, &cnd));

        for (j = 0; j < n_classes; j++) {
            classes[j].count = 0;
        }
        ovsdb_row_set_init(&results);
        ovsdb_query_distinct(table, &cnd, &columns, &results);
        for (j = 0; j < results.n_rows; j++) {
            size_t k;

            for (k = 0; k < n_rows; k++) {
                if (uuid_equals(ovsdb_row_get_uuid(results.rows[j]),
                                &rows[k].uuid)) {
                    rows[k].class->count++;
                }
            }
        }
        ovsdb_row_set_destroy(&results);

        printf("query %2zu:", i);
        for (j = 0; j < n_rows; j++) {
            int count = rows[j].class->count;

            if (j % 5 == 0) {
                putchar(' ');
            }
            if (count > 1) {
                /* Dup! */
                printf("%d", count);
                exit_code = 1;
            } else if (count == 1) {
                putchar("abcdefghijklmnopqrstuvwxyz"[rows[j].class - classes]);
            } else {
                putchar('-');
            }
        }
        putchar('\n');

        ovsdb_condition_destroy(&cnd);
    }
    json_destroy(json);

    ovsdb_table_destroy(table); /* Also destroys 'ts'. */

    exit(exit_code);
}

static void
do_parse_schema(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_schema *schema;
    struct json *json;

    json = parse_json(argv[1]);
    check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
    json_destroy(json);
    print_and_free_json(ovsdb_schema_to_json(schema));
    ovsdb_schema_destroy(schema);
}

static void
do_execute(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_schema *schema;
    struct json *json;
    struct ovsdb *db;
    int i;

    /* Create database. */
    json = parse_json(argv[1]);
    check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
    json_destroy(json);
    db = ovsdb_create(schema);

    for (i = 2; i < argc; i++) {
        struct json *params, *result;
        char *s;

        params = parse_json(argv[i]);
        result = ovsdb_execute(db, NULL, params, 0, NULL);
        s = json_to_string(result, JSSF_SORT);
        printf("%s\n", s);
        free(s);
        json_destroy(params);
        json_destroy(result);
    }

    ovsdb_destroy(db);
}

struct test_trigger {
    struct ovsdb_trigger trigger;
    int number;
};

static void
do_trigger_dump(struct test_trigger *t, long long int now, const char *title)
{
    struct json *result;
    char *s;

    result = ovsdb_trigger_steal_result(&t->trigger);
    s = json_to_string(result, JSSF_SORT);
    printf("t=%lld: trigger %d (%s): %s\n", now, t->number, title, s);
    free(s);
    json_destroy(result);
    ovsdb_trigger_destroy(&t->trigger);
    free(t);
}

static void
do_trigger(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_schema *schema;
    struct ovsdb_session session;
    struct ovsdb_server server;
    struct json *json;
    struct ovsdb *db;
    long long int now;
    int number;
    int i;

    /* Create database. */
    json = parse_json(argv[1]);
    check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
    json_destroy(json);
    db = ovsdb_create(schema);

    ovsdb_server_init(&server);
    ovsdb_server_add_db(&server, db);
    ovsdb_session_init(&session, &server);

    now = 0;
    number = 0;
    for (i = 2; i < argc; i++) {
        struct json *params = parse_json(argv[i]);
        if (params->type == JSON_ARRAY
            && json_array(params)->n == 2
            && json_array(params)->elems[0]->type == JSON_STRING
            && !strcmp(json_string(json_array(params)->elems[0]), "advance")
            && json_array(params)->elems[1]->type == JSON_INTEGER) {
            now += json_integer(json_array(params)->elems[1]);
            json_destroy(params);
        } else {
            struct test_trigger *t = xmalloc(sizeof *t);
            ovsdb_trigger_init(&session, db, &t->trigger, params, now);
            t->number = number++;
            if (ovsdb_trigger_is_complete(&t->trigger)) {
                do_trigger_dump(t, now, "immediate");
            } else {
                printf("t=%lld: new trigger %d\n", now, t->number);
            }
        }

        ovsdb_trigger_run(db, now);
        while (!list_is_empty(&session.completions)) {
            do_trigger_dump(CONTAINER_OF(list_pop_front(&session.completions),
                                         struct test_trigger, trigger.node),
                            now, "delayed");
        }

        ovsdb_trigger_wait(db, now);
        poll_immediate_wake();
        poll_block();
    }

    ovsdb_server_destroy(&server);
    ovsdb_destroy(db);
}

static void
do_help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
}

/* "transact" command. */

static struct ovsdb *do_transact_db;
static struct ovsdb_txn *do_transact_txn;
static struct ovsdb_table *do_transact_table;

static void
do_transact_commit(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    ovsdb_error_destroy(ovsdb_txn_commit(do_transact_txn, false));
    do_transact_txn = NULL;
}

static void
do_transact_abort(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    ovsdb_txn_abort(do_transact_txn);
    do_transact_txn = NULL;
}

static void
uuid_from_integer(int integer, struct uuid *uuid)
{
    uuid_zero(uuid);
    uuid->parts[3] = integer;
}

static const struct ovsdb_row *
do_transact_find_row(const char *uuid_string)
{
    const struct ovsdb_row *row;
    struct uuid uuid;

    uuid_from_integer(atoi(uuid_string), &uuid);
    row = ovsdb_table_get_row(do_transact_table, &uuid);
    if (!row) {
        ovs_fatal(0, "table does not contain row with UUID "UUID_FMT,
                  UUID_ARGS(&uuid));
    }
    return row;
}

static void
do_transact_set_integer(struct ovsdb_row *row, const char *column_name,
                        int integer)
{
    if (integer != -1) {
        const struct ovsdb_column *column;

        column = ovsdb_table_schema_get_column(do_transact_table->schema,
                                               column_name);
        row->fields[column->index].keys[0].integer = integer;
    }
}

static int
do_transact_get_integer(const struct ovsdb_row *row, const char *column_name)
{
    const struct ovsdb_column *column;

    column = ovsdb_table_schema_get_column(do_transact_table->schema,
                                           column_name);
    return row->fields[column->index].keys[0].integer;
}

static void
do_transact_set_i_j(struct ovsdb_row *row,
                    const char *i_string, const char *j_string)
{
    do_transact_set_integer(row, "i", atoi(i_string));
    do_transact_set_integer(row, "j", atoi(j_string));
}

static void
do_transact_insert(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ovsdb_row *row;
    struct uuid *uuid;

    row = ovsdb_row_create(do_transact_table);

    /* Set UUID. */
    uuid = ovsdb_row_get_uuid_rw(row);
    uuid_from_integer(atoi(argv[1]), uuid);
    if (ovsdb_table_get_row(do_transact_table, uuid)) {
        ovs_fatal(0, "table already contains row with UUID "UUID_FMT,
                  UUID_ARGS(uuid));
    }

    do_transact_set_i_j(row, argv[2], argv[3]);

    /* Insert row. */
    ovsdb_txn_row_insert(do_transact_txn, row);
}

static void
do_transact_delete(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    const struct ovsdb_row *row = do_transact_find_row(argv[1]);
    ovsdb_txn_row_delete(do_transact_txn, row);
}

static void
do_transact_modify(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    const struct ovsdb_row *row_ro;
    struct ovsdb_row *row_rw;

    row_ro = do_transact_find_row(argv[1]);
    row_rw = ovsdb_txn_row_modify(do_transact_txn, row_ro);
    do_transact_set_i_j(row_rw, argv[2], argv[3]);
}

static int
compare_rows_by_uuid(const void *a_, const void *b_)
{
    struct ovsdb_row *const *ap = a_;
    struct ovsdb_row *const *bp = b_;

    return uuid_compare_3way(ovsdb_row_get_uuid(*ap), ovsdb_row_get_uuid(*bp));
}

static void
do_transact_print(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    const struct ovsdb_row **rows;
    const struct ovsdb_row *row;
    size_t n_rows;
    size_t i;

    n_rows = hmap_count(&do_transact_table->rows);
    rows = xmalloc(n_rows * sizeof *rows);
    i = 0;
    HMAP_FOR_EACH (row, hmap_node, &do_transact_table->rows) {
        rows[i++] = row;
    }
    assert(i == n_rows);

    qsort(rows, n_rows, sizeof *rows, compare_rows_by_uuid);

    for (i = 0; i < n_rows; i++) {
        printf("\n%"PRId32": i=%d, j=%d",
               ovsdb_row_get_uuid(rows[i])->parts[3],
               do_transact_get_integer(rows[i], "i"),
               do_transact_get_integer(rows[i], "j"));
    }

    free(rows);
}

static void
do_transact(int argc, char *argv[])
{
    static const struct command do_transact_commands[] = {
        { "commit", 0, 0, do_transact_commit },
        { "abort", 0, 0, do_transact_abort },
        { "insert", 2, 3, do_transact_insert },
        { "delete", 1, 1, do_transact_delete },
        { "modify", 2, 3, do_transact_modify },
        { "print", 0, 0, do_transact_print },
        { NULL, 0, 0, NULL },
    };

    struct ovsdb_schema *schema;
    struct json *json;
    int i;

    /* Create table. */
    json = parse_json("{\"name\": \"testdb\", "
                      " \"tables\": "
                      "  {\"mytable\": "
                      "    {\"columns\": "
                      "      {\"i\": {\"type\": \"integer\"}, "
                      "       \"j\": {\"type\": \"integer\"}}}}}");
    check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
    json_destroy(json);
    do_transact_db = ovsdb_create(schema);
    do_transact_table = ovsdb_get_table(do_transact_db, "mytable");
    assert(do_transact_table != NULL);

    for (i = 1; i < argc; i++) {
        struct json *command;
        size_t n_args;
        char **args;
        int j;

        command = parse_json(argv[i]);
        if (command->type != JSON_ARRAY) {
            ovs_fatal(0, "transaction %d must be JSON array "
                      "with at least 1 element", i);
        }

        n_args = command->u.array.n;
        args = xmalloc((n_args + 1) * sizeof *args);
        for (j = 0; j < n_args; j++) {
            struct json *s = command->u.array.elems[j];
            if (s->type != JSON_STRING) {
                ovs_fatal(0, "transaction %d argument %d must be JSON string",
                          i, j);
            }
            args[j] = xstrdup(json_string(s));
        }
        args[n_args] = NULL;

        if (!do_transact_txn) {
            do_transact_txn = ovsdb_txn_create(do_transact_db);
        }

        for (j = 0; j < n_args; j++) {
            if (j) {
                putchar(' ');
            }
            fputs(args[j], stdout);
        }
        fputs(":", stdout);
        run_command(n_args, args, do_transact_commands);
        putchar('\n');

        for (j = 0; j < n_args; j++) {
            free(args[j]);
        }
        free(args);
        json_destroy(command);
    }
    ovsdb_txn_abort(do_transact_txn);
    ovsdb_destroy(do_transact_db); /* Also destroys 'schema'. */
}

static int
compare_link1(const void *a_, const void *b_)
{
    const struct idltest_link1 *const *ap = a_;
    const struct idltest_link1 *const *bp = b_;
    const struct idltest_link1 *a = *ap;
    const struct idltest_link1 *b = *bp;

    return a->i < b->i ? -1 : a->i > b->i;
}

static void
print_idl(struct ovsdb_idl *idl, int step)
{
    const struct idltest_simple *s;
    const struct idltest_link1 *l1;
    const struct idltest_link2 *l2;
    int n = 0;

    IDLTEST_SIMPLE_FOR_EACH (s, idl) {
        size_t i;

        printf("%03d: i=%"PRId64" r=%g b=%s s=%s u="UUID_FMT" ia=[",
               step, s->i, s->r, s->b ? "true" : "false",
               s->s, UUID_ARGS(&s->u));
        for (i = 0; i < s->n_ia; i++) {
            printf("%s%"PRId64, i ? " " : "", s->ia[i]);
        }
        printf("] ra=[");
        for (i = 0; i < s->n_ra; i++) {
            printf("%s%g", i ? " " : "", s->ra[i]);
        }
        printf("] ba=[");
        for (i = 0; i < s->n_ba; i++) {
            printf("%s%s", i ? " " : "", s->ba[i] ? "true" : "false");
        }
        printf("] sa=[");
        for (i = 0; i < s->n_sa; i++) {
            printf("%s%s", i ? " " : "", s->sa[i]);
        }
        printf("] ua=[");
        for (i = 0; i < s->n_ua; i++) {
            printf("%s"UUID_FMT, i ? " " : "", UUID_ARGS(&s->ua[i]));
        }
        printf("] uuid="UUID_FMT"\n", UUID_ARGS(&s->header_.uuid));
        n++;
    }
    IDLTEST_LINK1_FOR_EACH (l1, idl) {
        struct idltest_link1 **links;
        size_t i;

        printf("%03d: i=%"PRId64" k=", step, l1->i);
        if (l1->k) {
            printf("%"PRId64, l1->k->i);
        }
        printf(" ka=[");
        links = xmemdup(l1->ka, l1->n_ka * sizeof *l1->ka);
        qsort(links, l1->n_ka, sizeof *links, compare_link1);
        for (i = 0; i < l1->n_ka; i++) {
            printf("%s%"PRId64, i ? " " : "", links[i]->i);
        }
        free(links);
        printf("] l2=");
        if (l1->l2) {
            printf("%"PRId64, l1->l2->i);
        }
        printf(" uuid="UUID_FMT"\n", UUID_ARGS(&l1->header_.uuid));
        n++;
    }
    IDLTEST_LINK2_FOR_EACH (l2, idl) {
        printf("%03d: i=%"PRId64" l1=", step, l2->i);
        if (l2->l1) {
            printf("%"PRId64, l2->l1->i);
        }
        printf(" uuid="UUID_FMT"\n", UUID_ARGS(&l2->header_.uuid));
        n++;
    }
    if (!n) {
        printf("%03d: empty\n", step);
    }
}

static void
parse_uuids(const struct json *json, struct ovsdb_symbol_table *symtab,
            size_t *n)
{
    struct uuid uuid;

    if (json->type == JSON_STRING && uuid_from_string(&uuid, json->u.string)) {
        char *name = xasprintf("#%zu#", *n);
        fprintf(stderr, "%s = "UUID_FMT"\n", name, UUID_ARGS(&uuid));
        ovsdb_symbol_table_put(symtab, name, &uuid, false);
        free(name);
        *n += 1;
    } else if (json->type == JSON_ARRAY) {
        size_t i;

        for (i = 0; i < json->u.array.n; i++) {
            parse_uuids(json->u.array.elems[i], symtab, n);
        }
    } else if (json->type == JSON_OBJECT) {
        const struct shash_node *node;

        SHASH_FOR_EACH (node, json_object(json)) {
            parse_uuids(node->data, symtab, n);
        }
    }
}

static void
substitute_uuids(struct json *json, const struct ovsdb_symbol_table *symtab)
{
    if (json->type == JSON_STRING) {
        const struct ovsdb_symbol *symbol;

        symbol = ovsdb_symbol_table_get(symtab, json->u.string);
        if (symbol) {
            free(json->u.string);
            json->u.string = xasprintf(UUID_FMT, UUID_ARGS(&symbol->uuid));
        }
    } else if (json->type == JSON_ARRAY) {
        size_t i;

        for (i = 0; i < json->u.array.n; i++) {
            substitute_uuids(json->u.array.elems[i], symtab);
        }
    } else if (json->type == JSON_OBJECT) {
        const struct shash_node *node;

        SHASH_FOR_EACH (node, json_object(json)) {
            substitute_uuids(node->data, symtab);
        }
    }
}

static const struct idltest_simple *
idltest_find_simple(struct ovsdb_idl *idl, int i)
{
    const struct idltest_simple *s;

    IDLTEST_SIMPLE_FOR_EACH (s, idl) {
        if (s->i == i) {
            return s;
        }
    }
    return NULL;
}

static void
idl_set(struct ovsdb_idl *idl, char *commands, int step)
{
    char *cmd, *save_ptr1 = NULL;
    struct ovsdb_idl_txn *txn;
    enum ovsdb_idl_txn_status status;
    bool increment = false;

    txn = ovsdb_idl_txn_create(idl);
    for (cmd = strtok_r(commands, ",", &save_ptr1); cmd;
         cmd = strtok_r(NULL, ",", &save_ptr1)) {
        char *save_ptr2 = NULL;
        char *name, *arg1, *arg2, *arg3;

        name = strtok_r(cmd, " ", &save_ptr2);
        arg1 = strtok_r(NULL, " ", &save_ptr2);
        arg2 = strtok_r(NULL, " ", &save_ptr2);
        arg3 = strtok_r(NULL, " ", &save_ptr2);

        if (!strcmp(name, "set")) {
            const struct idltest_simple *s;

            if (!arg3) {
                ovs_fatal(0, "\"set\" command requires 3 arguments");
            }

            s = idltest_find_simple(idl, atoi(arg1));
            if (!s) {
                ovs_fatal(0, "\"set\" command asks for nonexistent "
                          "i=%d", atoi(arg1));
            }

            if (!strcmp(arg2, "b")) {
                idltest_simple_set_b(s, atoi(arg3));
            } else if (!strcmp(arg2, "s")) {
                idltest_simple_set_s(s, arg3);
            } else if (!strcmp(arg2, "u")) {
                struct uuid uuid;
                if (!uuid_from_string(&uuid, arg3)) {
                    ovs_fatal(0, "\"%s\" is not a valid UUID", arg3);
                }
                idltest_simple_set_u(s, uuid);
            } else if (!strcmp(arg2, "r")) {
                idltest_simple_set_r(s, atof(arg3));
            } else {
                ovs_fatal(0, "\"set\" command asks for unknown column %s",
                          arg2);
            }
        } else if (!strcmp(name, "insert")) {
            struct idltest_simple *s;

            if (!arg1 || arg2) {
                ovs_fatal(0, "\"insert\" command requires 1 argument");
            }

            s = idltest_simple_insert(txn);
            idltest_simple_set_i(s, atoi(arg1));
        } else if (!strcmp(name, "delete")) {
            const struct idltest_simple *s;

            if (!arg1 || arg2) {
                ovs_fatal(0, "\"delete\" command requires 1 argument");
            }

            s = idltest_find_simple(idl, atoi(arg1));
            if (!s) {
                ovs_fatal(0, "\"delete\" command asks for nonexistent "
                          "i=%d", atoi(arg1));
            }
            idltest_simple_delete(s);
        } else if (!strcmp(name, "verify")) {
            const struct idltest_simple *s;

            if (!arg2 || arg3) {
                ovs_fatal(0, "\"verify\" command requires 2 arguments");
            }

            s = idltest_find_simple(idl, atoi(arg1));
            if (!s) {
                ovs_fatal(0, "\"verify\" command asks for nonexistent "
                          "i=%d", atoi(arg1));
            }

            if (!strcmp(arg2, "i")) {
                idltest_simple_verify_i(s);
            } else if (!strcmp(arg2, "b")) {
                idltest_simple_verify_b(s);
            } else if (!strcmp(arg2, "s")) {
                idltest_simple_verify_s(s);
            } else if (!strcmp(arg2, "u")) {
                idltest_simple_verify_s(s);
            } else if (!strcmp(arg2, "r")) {
                idltest_simple_verify_r(s);
            } else {
                ovs_fatal(0, "\"verify\" command asks for unknown column %s",
                          arg2);
            }
        } else if (!strcmp(name, "increment")) {
            const struct idltest_simple *s;

            if (!arg1 || arg2) {
                ovs_fatal(0, "\"increment\" command requires 1 argument");
            }

            s = idltest_find_simple(idl, atoi(arg1));
            if (!s) {
                ovs_fatal(0, "\"set\" command asks for nonexistent "
                          "i=%d", atoi(arg1));
            }

            ovsdb_idl_txn_increment(txn, &s->header_, &idltest_simple_col_i);
            increment = true;
        } else if (!strcmp(name, "abort")) {
            ovsdb_idl_txn_abort(txn);
            break;
        } else if (!strcmp(name, "destroy")) {
            printf("%03d: destroy\n", step);
            ovsdb_idl_txn_destroy(txn);
            return;
        } else {
            ovs_fatal(0, "unknown command %s", name);
        }
    }

    status = ovsdb_idl_txn_commit_block(txn);
    printf("%03d: commit, status=%s",
           step, ovsdb_idl_txn_status_to_string(status));
    if (increment) {
        printf(", increment=%"PRId64,
               ovsdb_idl_txn_get_increment_new_value(txn));
    }
    putchar('\n');
    ovsdb_idl_txn_destroy(txn);
}

static void
do_idl(int argc, char *argv[])
{
    struct jsonrpc *rpc;
    struct ovsdb_idl *idl;
    unsigned int seqno = 0;
    struct ovsdb_symbol_table *symtab;
    size_t n_uuids = 0;
    int step = 0;
    int error;
    int i;

    idltest_init();

    idl = ovsdb_idl_create(argv[1], &idltest_idl_class, true);
    if (argc > 2) {
        struct stream *stream;

        error = stream_open_block(jsonrpc_stream_open(argv[1], &stream,
                                  DSCP_DEFAULT), &stream);
        if (error) {
            ovs_fatal(error, "failed to connect to \"%s\"", argv[1]);
        }
        rpc = jsonrpc_open(stream);
    } else {
        rpc = NULL;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    symtab = ovsdb_symbol_table_create();
    for (i = 2; i < argc; i++) {
        char *arg = argv[i];
        struct jsonrpc_msg *request, *reply;

        if (*arg == '+') {
            /* The previous transaction didn't change anything. */
            arg++;
        } else {
            /* Wait for update. */
            for (;;) {
                ovsdb_idl_run(idl);
                if (ovsdb_idl_get_seqno(idl) != seqno) {
                    break;
                }
                jsonrpc_run(rpc);

                ovsdb_idl_wait(idl);
                jsonrpc_wait(rpc);
                poll_block();
            }

            /* Print update. */
            print_idl(idl, step++);
        }
        seqno = ovsdb_idl_get_seqno(idl);

        if (!strcmp(arg, "reconnect")) {
            printf("%03d: reconnect\n", step++);
            ovsdb_idl_force_reconnect(idl);
        } else if (arg[0] != '[') {
            idl_set(idl, arg, step++);
        } else {
            struct json *json = parse_json(arg);
            substitute_uuids(json, symtab);
            request = jsonrpc_create_request("transact", json, NULL);
            error = jsonrpc_transact_block(rpc, request, &reply);
            if (error || reply->error) {
                ovs_fatal(error, "jsonrpc transaction failed");
            }
            printf("%03d: ", step++);
            if (reply->result) {
                parse_uuids(reply->result, symtab, &n_uuids);
            }
            json_destroy(reply->id);
            reply->id = NULL;
            print_and_free_json(jsonrpc_msg_to_json(reply));
        }
    }
    ovsdb_symbol_table_destroy(symtab);

    if (rpc) {
        jsonrpc_close(rpc);
    }
    for (;;) {
        ovsdb_idl_run(idl);
        if (ovsdb_idl_get_seqno(idl) != seqno) {
            break;
        }
        ovsdb_idl_wait(idl);
        poll_block();
    }
    print_idl(idl, step++);
    ovsdb_idl_destroy(idl);
    printf("%03d: done\n", step);
}

static struct command all_commands[] = {
    { "log-io", 2, INT_MAX, do_log_io },
    { "default-atoms", 0, 0, do_default_atoms },
    { "default-data", 0, 0, do_default_data },
    { "parse-atomic-type", 1, 1, do_parse_atomic_type },
    { "parse-base-type", 1, 1, do_parse_base_type },
    { "parse-type", 1, 1, do_parse_type },
    { "parse-atoms", 2, INT_MAX, do_parse_atoms },
    { "parse-atom-strings", 2, INT_MAX, do_parse_atom_strings },
    { "parse-data", 2, INT_MAX, do_parse_data },
    { "parse-data-strings", 2, INT_MAX, do_parse_data_strings },
    { "sort-atoms", 2, 2, do_sort_atoms },
    { "parse-column", 2, 2, do_parse_column },
    { "parse-table", 2, 3, do_parse_table },
    { "parse-rows", 2, INT_MAX, do_parse_rows },
    { "compare-rows", 2, INT_MAX, do_compare_rows },
    { "parse-conditions", 2, INT_MAX, do_parse_conditions },
    { "evaluate-conditions", 3, 3, do_evaluate_conditions },
    { "parse-mutations", 2, INT_MAX, do_parse_mutations },
    { "execute-mutations", 3, 3, do_execute_mutations },
    { "query", 3, 3, do_query },
    { "query-distinct", 4, 4, do_query_distinct },
    { "transact", 1, INT_MAX, do_transact },
    { "parse-schema", 1, 1, do_parse_schema },
    { "execute", 2, INT_MAX, do_execute },
    { "trigger", 2, INT_MAX, do_trigger },
    { "idl", 1, INT_MAX, do_idl },
    { "help", 0, INT_MAX, do_help },
    { NULL, 0, 0, NULL },
};
