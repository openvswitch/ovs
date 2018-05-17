/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2015, 2016, 2017 Nicira, Inc.
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

#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "byte-order.h"
#include "command-line.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
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
#include "ovsdb/storage.h"
#include "ovsdb/table.h"
#include "ovsdb/transaction.h"
#include "ovsdb/trigger.h"
#include "openvswitch/poll-loop.h"
#include "stream.h"
#include "svec.h"
#include "tests/idltest.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

struct test_ovsdb_pvt_context {
    bool track;
};

/* Magic to pass to ovsdb_log_open(). */
static const char *magic = OVSDB_MAGIC;

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[],
    struct test_ovsdb_pvt_context *pvt);
static struct ovs_cmdl_command *get_all_commands(void);

int
main(int argc, char *argv[])
{
    struct test_ovsdb_pvt_context pvt = {.track = false};
    struct ovs_cmdl_context ctx = { .argc = 0, .pvt = &pvt};
    set_program_name(argv[0]);
    parse_options(argc, argv, &pvt);
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, get_all_commands());
    return 0;
}

static void
parse_options(int argc, char *argv[], struct test_ovsdb_pvt_context *pvt)
{
    enum {
        OPT_MAGIC = CHAR_MAX + 1,
        OPT_NO_RENAME_OPEN_FILES
    };
    static const struct option long_options[] = {
        {"timeout", required_argument, NULL, 't'},
        {"verbose", optional_argument, NULL, 'v'},
        {"change-track", optional_argument, NULL, 'c'},
        {"magic", required_argument, NULL, OPT_MAGIC},
        {"no-rename-open-files", no_argument, NULL, OPT_NO_RENAME_OPEN_FILES},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

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

        case 'c':
            pvt->track = true;
            break;

        case OPT_MAGIC:
            magic = optarg;
            break;

        case OPT_NO_RENAME_OPEN_FILES:
            ovsdb_log_disable_renaming_open_files();
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
           "  [--magic=MAGIC] [--no-rename-open-files] "
           " log-io FILE FLAGS COMMAND...\n"
           "    open FILE with FLAGS (and MAGIC), run COMMANDs\n"
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
           "  evaluate-conditions-any TABLE [CONDITION,...] [ROW,...]\n"
           "    test CONDITIONS to match any of the CONDITONS on TABLE\n"
           "    against each ROW, print results\n"
           "  compare-conditions TABLE [CONDITION,...]\n"
           "    mutually compare all of the CONDITION, print results for\n"
           "    each pair\n"
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
           "  execute-readonly SCHEMA TRANSACTION...\n"
           "    same as execute, except the TRANSACTION will be executed\n"
           "    against the database server that is in read only mode\n"
           "  trigger SCHEMA TRANSACTION...\n"
           "    executes each TRANSACTION on an initially empty database\n"
           "    the specified SCHEMA.   A TRANSACTION of the form\n"
           "    [\"advance\", NUMBER] advances NUMBER milliseconds in\n"
           "    simulated time, for causing triggers to time out.\n"
           "  idl SERVER [TRANSACTION...]\n"
           "    connect to SERVER and dump the contents of the database\n"
           "    as seen initially by the IDL implementation and after\n"
           "    executing each TRANSACTION.  (Each TRANSACTION must modify\n"
           "    the database or this command will hang.)\n"
           "  idl-partial-update-map-column SERVER \n"
           "    connect to SERVER and executes different operations to\n"
           "    test the capacity of updating elements inside a map column\n"
           "    displaying the table information after each operation.\n"
           "  idl-partial-update-set-column SERVER \n"
           "    connect to SERVER and executes different operations to\n"
           "    test the capacity of updating elements inside a set column\n"
           "    displaying the table information after each operation.\n"
           "  idl-compound-index TEST_TO_EXECUTE\n"
           "    Execute the tests to verify compound-index feature.\n"
           "    The TEST_TO_EXECUTE are:\n"
           "        idl_compound_index_single_column:\n"
           "          test for indexes using one column.\n"
           "        idl_compound_index_double_column:\n"
           "            test for indexes using two columns.\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOther options:\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  -h, --help                  display this help message\n"
           "  -c, --change-track          used with the 'idl' command to\n"
           "                              enable tracking of IDL changes\n");
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
    char *string = ovsdb_error_to_string_free(error);
    puts(string);
    free(string);
}

static void
check_ovsdb_error(struct ovsdb_error *error)
{
    if (error) {
        char *s = ovsdb_error_to_string_free(error);
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
do_log_io(struct ovs_cmdl_context *ctx)
{
    const char *name = ctx->argv[1];
    char *mode_string = ctx->argv[2];

    struct ovsdb_error *error;
    enum ovsdb_log_open_mode mode;
    int i;

    if (!strcmp(mode_string, "read-only")) {
        mode = OVSDB_LOG_READ_ONLY;
    } else if (!strcmp(mode_string, "read/write")) {
        mode = OVSDB_LOG_READ_WRITE;
    } else if (!strcmp(mode_string, "create")) {
        mode = OVSDB_LOG_CREATE;
    } else if (!strcmp(mode_string, "create-excl")) {
        mode = OVSDB_LOG_CREATE_EXCL;
    } else {
        ovs_fatal(0, "unknown log-io open mode \"%s\"", mode_string);
    }

    struct ovsdb_log *log;
    check_ovsdb_error(ovsdb_log_open(name, magic, mode, -1, &log));
    printf("%s: open successful\n", name);

    struct ovsdb_log *replacement = NULL;

    for (i = 3; i < ctx->argc; i++) {
        const char *command = ctx->argv[i];

        struct ovsdb_log *target;
        const char *target_name;
        if (!strncmp(command, "old-", 4)) {
            command += 4;
            target = log;
            target_name = name;
        } else if (!strncmp(command, "new-", 4)) {
            if (!replacement) {
                ovs_fatal(0, "%s: can't execute command without "
                          "replacement log", command);
            }

            command += 4;
            target = replacement;
            target_name = "(temp)";
        } else {
            target = log;
            target_name = name;
        }

        if (!strcmp(command, "read")) {
            struct json *json;

            error = ovsdb_log_read(target, &json);
            if (!error) {
                printf("%s: read: ", target_name);
                if (json) {
                    print_and_free_json(json);
                } else {
                    printf("end of log\n");
                }
                continue;
            }
        } else if (!strncmp(command, "write:", 6)) {
            struct json *json = parse_json(command + 6);
            error = ovsdb_log_write_and_free(target, json);
        } else if (!strcmp(command, "commit")) {
            error = ovsdb_log_commit_block(target);
        } else if (!strcmp(command, "replace_start")) {
            ovs_assert(!replacement);
            error = ovsdb_log_replace_start(log, &replacement);
        } else if (!strcmp(command, "replace_commit")) {
            ovs_assert(replacement);
            error = ovsdb_log_replace_commit(log, replacement);
            replacement = NULL;
        } else if (!strcmp(command, "replace_abort")) {
            ovs_assert(replacement);
            ovsdb_log_replace_abort(replacement);
            replacement = NULL;
            error = NULL;
        } else {
            ovs_fatal(0, "unknown log-io command \"%s\"", command);
        }
        if (error) {
            char *s = ovsdb_error_to_string_free(error);
            printf("%s: %s failed: %s\n", target_name, command, s);
            free(s);
        } else {
            printf("%s: %s successful\n", target_name, command);
        }
    }

    ovsdb_log_close(log);
}

static void
do_default_atoms(struct ovs_cmdl_context *ctx OVS_UNUSED)
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
do_default_data(struct ovs_cmdl_context *ctx OVS_UNUSED)
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
                ovs_assert(ovsdb_type_is_valid(&type));

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
do_diff_data(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_type type;
    struct json *json;
    struct ovsdb_datum new, old, diff, reincarnation;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_type_from_json(&type, json));
    json_destroy(json);

    /* Arguments in pairs of 'old' and 'new'. */
    for (int i = 2; i < ctx->argc - 1; i+=2) {
        struct ovsdb_error *error;

        json = unbox_json(parse_json(ctx->argv[i]));
        check_ovsdb_error(ovsdb_datum_from_json(&old, &type, json, NULL));
        json_destroy(json);

        json = unbox_json(parse_json(ctx->argv[i+1]));
        check_ovsdb_error(ovsdb_transient_datum_from_json(&new, &type, json));
        json_destroy(json);

        /* Generate the diff.  */
        ovsdb_datum_diff(&diff, &old, &new, &type);

        /* Apply diff to 'old' to create'reincarnation'. */
        error = ovsdb_datum_apply_diff(&reincarnation, &old, &diff, &type);
        if (error) {
            char *string = ovsdb_error_to_string_free(error);
            ovs_fatal(0, "%s", string);
        }

        /* Test to make sure 'new' equals 'reincarnation'.  */
        if (!ovsdb_datum_equals(&new, &reincarnation, &type)) {
            ovs_fatal(0, "failed to apply diff");
        }

        /* Print diff */
        json = ovsdb_datum_to_json(&diff, &type);
        printf ("diff: ");
        print_and_free_json(json);

        /* Print reincarnation */
        json = ovsdb_datum_to_json(&reincarnation, &type);
        printf ("apply diff: ");
        print_and_free_json(json);

        ovsdb_datum_destroy(&new, &type);
        ovsdb_datum_destroy(&old, &type);
        ovsdb_datum_destroy(&diff, &type);
        ovsdb_datum_destroy(&reincarnation, &type);

        printf("OK\n");
    }

    ovsdb_type_destroy(&type);
}

static void
do_parse_atomic_type(struct ovs_cmdl_context *ctx)
{
    enum ovsdb_atomic_type type;
    struct json *json;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_atomic_type_from_json(&type, json));
    json_destroy(json);
    print_and_free_json(ovsdb_atomic_type_to_json(type));
}

static void
do_parse_base_type(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_base_type base;
    struct json *json;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_base_type_from_json(&base, json));
    json_destroy(json);
    print_and_free_json(ovsdb_base_type_to_json(&base));
    ovsdb_base_type_destroy(&base);
}

static void
do_parse_type(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_type type;
    struct json *json;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_type_from_json(&type, json));
    json_destroy(json);
    print_and_free_json(ovsdb_type_to_json(&type));
    ovsdb_type_destroy(&type);
}

static void
do_parse_atoms(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_base_type base;
    struct json *json;
    int i;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_base_type_from_json(&base, json));
    json_destroy(json);

    for (i = 2; i < ctx->argc; i++) {
        struct ovsdb_error *error;
        union ovsdb_atom atom;

        json = unbox_json(parse_json(ctx->argv[i]));
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
do_parse_atom_strings(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_base_type base;
    struct json *json;
    int i;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_base_type_from_json(&base, json));
    json_destroy(json);

    for (i = 2; i < ctx->argc; i++) {
        union ovsdb_atom atom, *range_end_atom = NULL;
        struct ds out;

        die_if_error(ovsdb_atom_from_string(&atom, &range_end_atom, &base,
                                            ctx->argv[i], NULL));

        ds_init(&out);
        ovsdb_atom_to_string(&atom, base.type, &out);
        if (range_end_atom) {
            struct ds range_end_ds;
            ds_init(&range_end_ds);
            ovsdb_atom_to_string(range_end_atom, base.type, &range_end_ds);
            ds_put_char(&out, '-');
            ds_put_cstr(&out, ds_cstr(&range_end_ds));;
            ds_destroy(&range_end_ds);
        }
        puts(ds_cstr(&out));
        ds_destroy(&out);

        ovsdb_atom_destroy(&atom, base.type);
        if (range_end_atom) {
            ovsdb_atom_destroy(range_end_atom, base.type);
            free(range_end_atom);
        }
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
do_parse_data(struct ovs_cmdl_context *ctx)
{
    do_parse_data__(ctx->argc, ctx->argv, ovsdb_datum_from_json);
}

static void
do_parse_data_strings(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_type type;
    struct json *json;
    int i;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_type_from_json(&type, json));
    json_destroy(json);

    for (i = 2; i < ctx->argc; i++) {
        struct ovsdb_datum datum;
        struct ds out;

        die_if_error(ovsdb_datum_from_string(&datum, &type, ctx->argv[i], NULL));

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
do_sort_atoms(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_base_type base;
    union ovsdb_atom *atoms;
    struct json *json, **json_atoms;
    size_t n_atoms;
    int i;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_base_type_from_json(&base, json));
    json_destroy(json);

    json = unbox_json(parse_json(ctx->argv[2]));
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
do_parse_column(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_column *column;
    struct json *json;

    json = parse_json(ctx->argv[2]);
    check_ovsdb_error(ovsdb_column_from_json(json, ctx->argv[1], &column));
    json_destroy(json);
    print_and_free_json(ovsdb_column_to_json(column));
    ovsdb_column_destroy(column);
}

static void
do_parse_table(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_table_schema *ts;
    bool default_is_root;
    struct json *json;

    default_is_root = ctx->argc > 3 && !strcmp(ctx->argv[3], "true");

    json = parse_json(ctx->argv[2]);
    check_ovsdb_error(ovsdb_table_schema_from_json(json, ctx->argv[1], &ts));
    json_destroy(json);
    print_and_free_json(ovsdb_table_schema_to_json(ts, default_is_root));
    ovsdb_table_schema_destroy(ts);
}

static void
do_parse_rows(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_column_set all_columns;
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct json *json;
    int i;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);
    ovsdb_column_set_init(&all_columns);
    ovsdb_column_set_add_all(&all_columns, table);

    for (i = 2; i < ctx->argc; i++) {
        struct ovsdb_column_set columns;
        struct ovsdb_row *row;

        ovsdb_column_set_init(&columns);
        row = ovsdb_row_create(table);

        json = unbox_json(parse_json(ctx->argv[i]));
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
do_compare_rows(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_column_set all_columns;
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct ovsdb_row **rows;
    struct json *json;
    char **names;
    int n_rows;
    int i, j;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);
    ovsdb_column_set_init(&all_columns);
    ovsdb_column_set_add_all(&all_columns, table);

    n_rows = ctx->argc - 2;
    rows = xmalloc(sizeof *rows * n_rows);
    names = xmalloc(sizeof *names * n_rows);
    for (i = 0; i < n_rows; i++) {
        rows[i] = ovsdb_row_create(table);

        json = parse_json(ctx->argv[i + 2]);
        if (json->type != JSON_ARRAY || json->u.array.n != 2
            || json->u.array.elems[0]->type != JSON_STRING) {
            ovs_fatal(0, "\"%s\" does not have expected form "
                      "[\"name\", {data}]", ctx->argv[i]);
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
do_parse_conditions(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_table_schema *ts;
    struct json *json;
    int exit_code = 0;
    int i;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    for (i = 2; i < ctx->argc; i++) {
        struct ovsdb_condition cnd;
        struct ovsdb_error *error;

        json = parse_json(ctx->argv[i]);
        error = ovsdb_condition_from_json(ts, json, NULL, &cnd);
        if (!error) {
            print_and_free_json(ovsdb_condition_to_json(&cnd));
        } else {
            char *s = ovsdb_error_to_string_free(error);
            ovs_error(0, "%s", s);
            free(s);
            exit_code = 1;
        }
        json_destroy(json);

        ovsdb_condition_destroy(&cnd);
    }
    ovsdb_table_schema_destroy(ts);

    exit(exit_code);
}

#define OVSDB_CONDITION_EVERY 0
#define OVSDB_CONDITION_ANY 1

static void
do_evaluate_condition__(struct ovs_cmdl_context *ctx, int mode)
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
    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);

    /* Parse conditions. */
    json = parse_json(ctx->argv[2]);
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
    json = parse_json(ctx->argv[3]);
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
        printf("condition %2"PRIuSIZE":", i);
        for (j = 0; j < n_rows; j++) {
            bool result;
            if (mode == OVSDB_CONDITION_EVERY) {
                result = ovsdb_condition_match_every_clause(rows[j],
                                                  &conditions[i]);
            } else {
                result = ovsdb_condition_match_any_clause(rows[j]->fields,
                                                          &conditions[i],
                                                          NULL);
            }
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
do_evaluate_conditions(struct ovs_cmdl_context *ctx)
{
    do_evaluate_condition__(ctx, OVSDB_CONDITION_EVERY);
}

static void
do_evaluate_conditions_any(struct ovs_cmdl_context *ctx)
{
    do_evaluate_condition__(ctx, OVSDB_CONDITION_ANY);
}

static void
do_compare_conditions(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct ovsdb_condition *conditions;
    size_t n_conditions;
    struct json *json;
    size_t i;

    /* Parse table schema, create table. */
    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);

    /* Parse conditions. */
    json = parse_json(ctx->argv[2]);
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

    for (i = 0; i < n_conditions - 1; i++) {
        int res = ovsdb_condition_cmp_3way(&conditions[i], &conditions[i + 1]);
        printf("condition %"PRIuSIZE"-%"PRIuSIZE": %d\n", i, i + 1, res);
    }

    for (i = 0; i < n_conditions; i++) {
        ovsdb_condition_destroy(&conditions[i]);
    }
    free(conditions);
    ovsdb_table_destroy(table); /* Also destroys 'ts'. */
}

static void
do_parse_mutations(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_table_schema *ts;
    struct json *json;
    int exit_code = 0;
    int i;

    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    for (i = 2; i < ctx->argc; i++) {
        struct ovsdb_mutation_set set;
        struct ovsdb_error *error;

        json = parse_json(ctx->argv[i]);
        error = ovsdb_mutation_set_from_json(ts, json, NULL, &set);
        if (!error) {
            print_and_free_json(ovsdb_mutation_set_to_json(&set));
        } else {
            char *s = ovsdb_error_to_string_free(error);
            ovs_error(0, "%s", s);
            free(s);
            exit_code = 1;
        }
        json_destroy(json);

        ovsdb_mutation_set_destroy(&set);
    }
    ovsdb_table_schema_destroy(ts);

    exit(exit_code);
}

static void
do_execute_mutations(struct ovs_cmdl_context *ctx)
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
    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);

    /* Parse mutations. */
    json = parse_json(ctx->argv[2]);
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
    json = parse_json(ctx->argv[3]);
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
        printf("mutation %2"PRIuSIZE":\n", i);
        for (j = 0; j < n_rows; j++) {
            struct ovsdb_error *error;
            struct ovsdb_row *row;

            row = ovsdb_row_clone(rows[j]);
            error = ovsdb_mutation_set_execute(row, &sets[i]);

            printf("row %"PRIuSIZE": ", j);
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
do_query(struct ovs_cmdl_context *ctx)
{
    struct do_query_cbdata cbdata;
    struct ovsdb_table_schema *ts;
    struct ovsdb_table *table;
    struct json *json;
    int exit_code = 0;
    size_t i;

    /* Parse table schema, create table. */
    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);

    /* Parse rows, add to table. */
    json = parse_json(ctx->argv[2]);
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
    json = parse_json(ctx->argv[3]);
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

        printf("query %2"PRIuSIZE":", i);
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
do_query_distinct(struct ovs_cmdl_context *ctx)
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
    json = unbox_json(parse_json(ctx->argv[1]));
    check_ovsdb_error(ovsdb_table_schema_from_json(json, "mytable", &ts));
    json_destroy(json);

    table = ovsdb_table_create(ts);

    /* Parse column set. */
    json = parse_json(ctx->argv[4]);
    check_ovsdb_error(ovsdb_column_set_from_json(json, table->schema,
                                                 &columns));
    json_destroy(json);

    /* Parse rows, add to table. */
    json = parse_json(ctx->argv[2]);
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
    json = parse_json(ctx->argv[3]);
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

        printf("query %2"PRIuSIZE":", i);
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

    for (i = 0; i < n_classes; i++) {
        ovsdb_row_destroy(classes[i].example);
    }

    ovsdb_table_destroy(table); /* Also destroys 'ts'. */

    free(rows);
    free(classes);
    exit(exit_code);
}

static void
do_parse_schema(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_schema *schema;
    struct json *json;

    json = parse_json(ctx->argv[1]);
    check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
    json_destroy(json);
    print_and_free_json(ovsdb_schema_to_json(schema));
    ovsdb_schema_destroy(schema);
}

static void
do_execute__(struct ovs_cmdl_context *ctx, bool ro)
{
    struct ovsdb_schema *schema;
    struct json *json;
    struct ovsdb *db;
    int i;

    /* Create database. */
    json = parse_json(ctx->argv[1]);
    check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
    json_destroy(json);
    db = ovsdb_create(schema, ovsdb_storage_create_unbacked());

    for (i = 2; i < ctx->argc; i++) {
        struct json *params, *result;
        char *s;

        params = parse_json(ctx->argv[i]);
        result = ovsdb_execute(db, NULL, params, ro,  NULL, NULL, 0, NULL);
        s = json_to_string(result, JSSF_SORT);
        printf("%s\n", s);
        free(s);
        json_destroy(params);
        json_destroy(result);
    }

    ovsdb_destroy(db);
}

static void
do_execute_ro(struct ovs_cmdl_context *ctx)
{
    do_execute__(ctx, true);
}

static void
do_execute(struct ovs_cmdl_context *ctx)
{
    do_execute__(ctx, false);
}

struct test_trigger {
    struct ovsdb_trigger trigger;
    int number;
};

static void
do_trigger_dump(struct test_trigger *t, long long int now, const char *title)
{
    struct jsonrpc_msg *reply;
    char *s;

    reply = ovsdb_trigger_steal_reply(&t->trigger);
    s = json_to_string(reply->result, JSSF_SORT);
    printf("t=%lld: trigger %d (%s): %s\n", now, t->number, title, s);
    free(s);
    jsonrpc_msg_destroy(reply);
    ovsdb_trigger_destroy(&t->trigger);
    free(t);
}

static void
do_trigger(struct ovs_cmdl_context *ctx)
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
    json = parse_json(ctx->argv[1]);
    check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
    json_destroy(json);
    db = ovsdb_create(schema, ovsdb_storage_create_unbacked());

    ovsdb_server_init(&server);
    ovsdb_server_add_db(&server, db);
    ovsdb_session_init(&session, &server);

    now = 0;
    number = 0;
    for (i = 2; i < ctx->argc; i++) {
        struct json *params = parse_json(ctx->argv[i]);
        if (params->type == JSON_ARRAY
            && json_array(params)->n == 2
            && json_array(params)->elems[0]->type == JSON_STRING
            && !strcmp(json_string(json_array(params)->elems[0]), "advance")
            && json_array(params)->elems[1]->type == JSON_INTEGER) {
            now += json_integer(json_array(params)->elems[1]);
            json_destroy(params);
        } else {
            struct test_trigger *t = xmalloc(sizeof *t);
            ovsdb_trigger_init(&session, db, &t->trigger,
                               jsonrpc_create_request("transact", params,
                                                      NULL),
                               now, false, NULL, NULL);
            t->number = number++;
            if (ovsdb_trigger_is_complete(&t->trigger)) {
                do_trigger_dump(t, now, "immediate");
            } else {
                printf("t=%lld: new trigger %d\n", now, t->number);
            }
        }

        ovsdb_trigger_run(db, now);

        struct test_trigger *t;
        LIST_FOR_EACH_POP (t, trigger.node, &session.completions) {
            do_trigger_dump(t, now, "delayed");
            ovsdb_trigger_run(db, now);
        }

        ovsdb_trigger_wait(db, now);
        poll_immediate_wake();
        poll_block();
    }

    ovsdb_server_destroy(&server);
    ovsdb_destroy(db);
}

static void
do_help(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    usage();
}

/* "transact" command. */

static struct ovsdb *do_transact_db;
static struct ovsdb_txn *do_transact_txn;
static struct ovsdb_table *do_transact_table;

static void
do_transact_commit(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ovsdb_error_destroy(ovsdb_txn_replay_commit(do_transact_txn));
    do_transact_txn = NULL;
}

static void
do_transact_abort(struct ovs_cmdl_context *ctx OVS_UNUSED)
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
do_transact_insert(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_row *row;
    struct uuid *uuid;

    row = ovsdb_row_create(do_transact_table);

    /* Set UUID. */
    uuid = ovsdb_row_get_uuid_rw(row);
    uuid_from_integer(atoi(ctx->argv[1]), uuid);
    if (ovsdb_table_get_row(do_transact_table, uuid)) {
        ovs_fatal(0, "table already contains row with UUID "UUID_FMT,
                  UUID_ARGS(uuid));
    }

    do_transact_set_i_j(row, ctx->argv[2], ctx->argv[3]);

    /* Insert row. */
    ovsdb_txn_row_insert(do_transact_txn, row);
}

static void
do_transact_delete(struct ovs_cmdl_context *ctx)
{
    const struct ovsdb_row *row = do_transact_find_row(ctx->argv[1]);
    ovsdb_txn_row_delete(do_transact_txn, row);
}

static void
do_transact_modify(struct ovs_cmdl_context *ctx)
{
    const struct ovsdb_row *row_ro;
    struct ovsdb_row *row_rw;

    row_ro = do_transact_find_row(ctx->argv[1]);
    row_rw = ovsdb_txn_row_modify(do_transact_txn, row_ro);
    do_transact_set_i_j(row_rw, ctx->argv[2], ctx->argv[3]);
}

static int
compare_rows_by_uuid(const void *a_, const void *b_)
{
    struct ovsdb_row *const *ap = a_;
    struct ovsdb_row *const *bp = b_;

    return uuid_compare_3way(ovsdb_row_get_uuid(*ap), ovsdb_row_get_uuid(*bp));
}

static void
do_transact_print(struct ovs_cmdl_context *ctx OVS_UNUSED)
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
    ovs_assert(i == n_rows);

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
do_transact(struct ovs_cmdl_context *ctx)
{
    static const struct ovs_cmdl_command do_transact_commands[] = {
        { "commit", NULL, 0, 0, do_transact_commit, OVS_RO },
        { "abort", NULL, 0, 0, do_transact_abort, OVS_RO },
        { "insert", NULL, 2, 3, do_transact_insert, OVS_RO },
        { "delete", NULL, 1, 1, do_transact_delete, OVS_RO },
        { "modify", NULL, 2, 3, do_transact_modify, OVS_RO },
        { "print", NULL, 0, 0, do_transact_print, OVS_RO },
        { NULL, NULL, 0, 0, NULL, OVS_RO },
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
    do_transact_db = ovsdb_create(schema, ovsdb_storage_create_unbacked());
    do_transact_table = ovsdb_get_table(do_transact_db, "mytable");
    ovs_assert(do_transact_table != NULL);

    for (i = 1; i < ctx->argc; i++) {
        struct json *command;
        size_t n_args;
        char **args;
        int j;
        struct ovs_cmdl_context transact_ctx = { .argc = 0, };

        command = parse_json(ctx->argv[i]);
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
        transact_ctx.argc = n_args;
        transact_ctx.argv = args;
        ovs_cmdl_run_command(&transact_ctx, do_transact_commands);
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
print_idl_row_updated_simple(const struct idltest_simple *s, int step)
{
    size_t i;
    bool updated = false;

    for (i = 0; i < IDLTEST_SIMPLE_N_COLUMNS; i++) {
        if (idltest_simple_is_updated(s, i)) {
            if (!updated) {
                printf("%03d: updated columns:", step);
                updated = true;
            }
            printf(" %s", idltest_simple_columns[i].name);
        }
    }
    if (updated) {
        printf("\n");
    }
}

static void
print_idl_row_updated_link1(const struct idltest_link1 *l1, int step)
{
    size_t i;
    bool updated = false;

    for (i = 0; i < IDLTEST_LINK1_N_COLUMNS; i++) {
        if (idltest_link1_is_updated(l1, i)) {
            if (!updated) {
                printf("%03d: updated columns:", step);
                updated = true;
            }
            printf(" %s", idltest_link1_columns[i].name);
        }
    }
    if (updated) {
        printf("\n");
    }
}

static void
print_idl_row_updated_link2(const struct idltest_link2 *l2, int step)
{
    size_t i;
    bool updated = false;

    for (i = 0; i < IDLTEST_LINK2_N_COLUMNS; i++) {
        if (idltest_link2_is_updated(l2, i)) {
            if (!updated) {
                printf("%03d: updated columns:", step);
                updated = true;
            }
            printf(" %s", idltest_link2_columns[i].name);
        }
    }
    if (updated) {
        printf("\n");
    }
}

static void
print_idl_row_simple(const struct idltest_simple *s, int step)
{
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
    print_idl_row_updated_simple(s, step);
}

static void
print_idl_row_link1(const struct idltest_link1 *l1, int step)
{
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
    print_idl_row_updated_link1(l1, step);
}

static void
print_idl_row_link2(const struct idltest_link2 *l2, int step)
{
    printf("%03d: i=%"PRId64" l1=", step, l2->i);
    if (l2->l1) {
        printf("%"PRId64, l2->l1->i);
    }
    printf(" uuid="UUID_FMT"\n", UUID_ARGS(&l2->header_.uuid));
    print_idl_row_updated_link2(l2, step);
}

static void
print_idl(struct ovsdb_idl *idl, int step)
{
    const struct idltest_simple *s;
    const struct idltest_link1 *l1;
    const struct idltest_link2 *l2;
    int n = 0;

    IDLTEST_SIMPLE_FOR_EACH (s, idl) {
        print_idl_row_simple(s, step);
        n++;
    }
    IDLTEST_LINK1_FOR_EACH (l1, idl) {
        print_idl_row_link1(l1, step);
        n++;
    }
    IDLTEST_LINK2_FOR_EACH (l2, idl) {
        print_idl_row_link2(l2, step);
        n++;
    }
    if (!n) {
        printf("%03d: empty\n", step);
    }
}

static void
print_idl_track(struct ovsdb_idl *idl, int step, unsigned int seqno)
{
    const struct idltest_simple *s;
    const struct idltest_link1 *l1;
    const struct idltest_link2 *l2;
    int n = 0;

    IDLTEST_SIMPLE_FOR_EACH_TRACKED (s, idl) {
        if (idltest_simple_row_get_seqno(s, OVSDB_IDL_CHANGE_DELETE) >= seqno) {
            printf("%03d: ##deleted## uuid="UUID_FMT"\n", step, UUID_ARGS(&s->header_.uuid));
        } else {
            print_idl_row_simple(s, step);
        }
        n++;
    }
    IDLTEST_LINK1_FOR_EACH_TRACKED (l1, idl) {
        if (idltest_simple_row_get_seqno(s, OVSDB_IDL_CHANGE_DELETE) >= seqno) {
            printf("%03d: ##deleted## uuid="UUID_FMT"\n", step, UUID_ARGS(&s->header_.uuid));
        } else {
            print_idl_row_link1(l1, step);
        }
        n++;
    }
    IDLTEST_LINK2_FOR_EACH_TRACKED (l2, idl) {
        if (idltest_simple_row_get_seqno(s, OVSDB_IDL_CHANGE_DELETE) >= seqno) {
            printf("%03d: ##deleted## uuid="UUID_FMT"\n", step, UUID_ARGS(&s->header_.uuid));
        } else {
            print_idl_row_link2(l2, step);
        }
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
        char *name = xasprintf("#%"PRIuSIZE"#", *n);
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
    ovsdb_idl_check_consistency(idl);
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

            ovsdb_idl_txn_increment(txn, &s->header_, &idltest_simple_col_i,
                                    false);
            increment = true;
        } else if (!strcmp(name, "abort")) {
            ovsdb_idl_txn_abort(txn);
            ovsdb_idl_check_consistency(idl);
            break;
        } else if (!strcmp(name, "destroy")) {
            printf("%03d: destroy\n", step);
            ovsdb_idl_txn_destroy(txn);
            ovsdb_idl_check_consistency(idl);
            return;
        } else {
            ovs_fatal(0, "unknown command %s", name);
        }
        ovsdb_idl_check_consistency(idl);
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
    ovsdb_idl_check_consistency(idl);
}

static const struct ovsdb_idl_table_class *
find_table_class(const char *name)
{
    if (!strcmp(name, "simple")) {
        return &idltest_table_simple;
    } else if (!strcmp(name, "link1")) {
        return &idltest_table_link1;
    } else if (!strcmp(name, "link2")) {
        return &idltest_table_link2;
    }
    return NULL;
}

static void
parse_simple_json_clause(struct ovsdb_idl_condition *cond,
                         enum ovsdb_function function,
                         const char *column, const struct json *arg)
{
    if (!strcmp(column, "b")) {
        idltest_simple_add_clause_b(cond, function, json_boolean(arg));
    } else if (!strcmp(column, "i")) {
         idltest_simple_add_clause_i(cond, function, json_integer(arg));
    } else if (!strcmp(column, "s")) {
        idltest_simple_add_clause_s(cond, function, json_string(arg));
    } else if (!strcmp(column, "u")) {
        struct uuid uuid;
        if (!uuid_from_string(&uuid, json_string(arg))) {
            ovs_fatal(0, "\"%s\" is not a valid UUID", json_string(arg));
        }
        idltest_simple_add_clause_u(cond, function, uuid);
    } else if (!strcmp(column, "r")) {
        idltest_simple_add_clause_r(cond, function, json_real(arg));
    } else {
        ovs_fatal(0, "Unsupported columns name %s", column);
    }
}

static void
parse_link1_json_clause(struct ovsdb_idl_condition *cond,
                        enum ovsdb_function function,
                        const char *column, const struct json *arg)
{
    if (!strcmp(column, "i")) {
        idltest_link1_add_clause_i(cond, function, json_integer(arg));
    } else {
        ovs_fatal(0, "Unsupported columns name %s", column);
    }
}

static void
parse_link2_json_clause(struct ovsdb_idl_condition *cond,
                        enum ovsdb_function function,
                        const char *column, const struct json *arg)
{
    if (!strcmp(column, "i")) {
        idltest_link2_add_clause_i(cond, function, json_integer(arg));
    } else {
        ovs_fatal(0, "Unsupported columns name %s", column);
    }
}

static void
update_conditions(struct ovsdb_idl *idl, char *commands)
{
    char *cmd, *save_ptr1 = NULL;
    const struct ovsdb_idl_table_class *tc;

    for (cmd = strtok_r(commands, ";", &save_ptr1); cmd;
         cmd = strtok_r(NULL, ";", &save_ptr1)) {
        char *save_ptr2 = NULL;
        char *table_name = strtok_r(cmd, " ", &save_ptr2);
        struct json *json = parse_json(save_ptr2);
        int i;

        if (json->type != JSON_ARRAY) {
            ovs_fatal(0, "condition should be an array");
        }

        tc = find_table_class(table_name);
        if (!tc) {
            ovs_fatal(0, "Table %s does not exist", table_name);
        }

        struct ovsdb_idl_condition cond = OVSDB_IDL_CONDITION_INIT(&cond);
        for (i = 0; i < json->u.array.n; i++) {
            const struct json *clause = json->u.array.elems[i];
            if (clause->type == JSON_TRUE) {
                ovsdb_idl_condition_add_clause_true(&cond);
            } else if (clause->type != JSON_ARRAY || clause->u.array.n != 3
                       || clause->u.array.elems[0]->type != JSON_STRING
                       || clause->u.array.elems[1]->type != JSON_STRING) {
                ovs_fatal(0, "Error parsing condition");
            } else {
                enum ovsdb_function function;
                const char *function_s = json_string(clause->u.array.elems[1]);
                struct ovsdb_error *error = ovsdb_function_from_string(
                    function_s, &function);
                if (error) {
                    ovs_fatal(0, "unknown clause function %s", function_s);
                }

                const char *column = json_string(clause->u.array.elems[0]);
                const struct json *arg = clause->u.array.elems[2];
                if (!strcmp(table_name, "simple")) {
                    parse_simple_json_clause(&cond, function, column, arg);
                } else if (!strcmp(table_name, "link1")) {
                    parse_link1_json_clause(&cond, function, column, arg);
                } else if (!strcmp(table_name, "link2")) {
                    parse_link2_json_clause(&cond, function, column, arg);
                }
            }
        }

        unsigned int seqno = ovsdb_idl_get_condition_seqno(idl);
        unsigned int next_seqno = ovsdb_idl_set_condition(idl, tc, &cond);
        if (seqno == next_seqno ) {
            ovs_fatal(0, "condition unchanged");
        }
        ovsdb_idl_condition_destroy(&cond);
        json_destroy(json);
    }
}

static void
do_idl(struct ovs_cmdl_context *ctx)
{
    struct jsonrpc *rpc;
    struct ovsdb_idl *idl;
    unsigned int seqno = 0;
    struct ovsdb_symbol_table *symtab;
    size_t n_uuids = 0;
    int step = 0;
    int error;
    int i;
    bool track;

    track = ((struct test_ovsdb_pvt_context *)(ctx->pvt))->track;

    idl = ovsdb_idl_create(ctx->argv[1], &idltest_idl_class, true, true);
    if (ctx->argc > 2) {
        struct stream *stream;

        error = stream_open_block(jsonrpc_stream_open(ctx->argv[1], &stream,
                                  DSCP_DEFAULT), &stream);
        if (error) {
            ovs_fatal(error, "failed to connect to \"%s\"", ctx->argv[1]);
        }
        rpc = jsonrpc_open(stream);
    } else {
        rpc = NULL;
    }

    if (track) {
        ovsdb_idl_track_add_all(idl);
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    symtab = ovsdb_symbol_table_create();
    const char cond_s[] = "condition ";
    if (ctx->argc > 2 && strstr(ctx->argv[2], cond_s)) {
        update_conditions(idl, ctx->argv[2] + strlen(cond_s));
        printf("%03d: change conditions\n", step++);
        i = 3;
    } else {
        i = 2;
    }
    for (; i < ctx->argc; i++) {
        char *arg = ctx->argv[i];
        struct jsonrpc_msg *request, *reply;

        if (*arg == '+') {
            /* The previous transaction didn't change anything. */
            arg++;
        } else {
            /* Wait for update. */
            for (;;) {
                ovsdb_idl_run(idl);
                ovsdb_idl_check_consistency(idl);
                if (ovsdb_idl_get_seqno(idl) != seqno) {
                    break;
                }
                jsonrpc_run(rpc);

                ovsdb_idl_wait(idl);
                jsonrpc_wait(rpc);
                poll_block();
            }

            /* Print update. */
            if (track) {
                print_idl_track(idl, step++, ovsdb_idl_get_seqno(idl));
                ovsdb_idl_track_clear(idl);
            } else {
                print_idl(idl, step++);
            }
        }
        seqno = ovsdb_idl_get_seqno(idl);

        if (!strcmp(arg, "reconnect")) {
            printf("%03d: reconnect\n", step++);
            ovsdb_idl_force_reconnect(idl);
        }  else if (!strncmp(arg, cond_s, strlen(cond_s))) {
            update_conditions(idl, arg + strlen(cond_s));
            printf("%03d: change conditions\n", step++);
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
        ovsdb_idl_check_consistency(idl);
        if (ovsdb_idl_get_seqno(idl) != seqno) {
            break;
        }
        ovsdb_idl_wait(idl);
        poll_block();
    }
    print_idl(idl, step++);
    ovsdb_idl_track_clear(idl);
    ovsdb_idl_destroy(idl);
    printf("%03d: done\n", step);
}

static void
print_idl_row_simple2(const struct idltest_simple2 *s, int step)
{
    size_t i;
    const struct ovsdb_datum *smap, *imap;

    smap = idltest_simple2_get_smap(s, OVSDB_TYPE_STRING, OVSDB_TYPE_STRING);
    imap = idltest_simple2_get_imap(s, OVSDB_TYPE_INTEGER, OVSDB_TYPE_STRING);
    printf("%03d: name=%s smap=[",
           step, s->name);
    for (i = 0; i < smap->n; i++) {
        printf("[%s : %s]%s", smap->keys[i].string, smap->values[i].string,
                i < smap->n-1? ",": "");
    }
    printf("] imap=[");
    for (i = 0; i < imap->n; i++) {
        printf("[%"PRId64" : %s]%s", imap->keys[i].integer, imap->values[i].string,
                i < imap->n-1? ",":"");
    }
    printf("]\n");
}

static void
dump_simple2(struct ovsdb_idl *idl,
             const struct idltest_simple2 *myRow,
             int step)
{
    IDLTEST_SIMPLE2_FOR_EACH(myRow, idl) {
        print_idl_row_simple2(myRow, step);
    }
}

static void
do_idl_partial_update_map_column(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_idl *idl;
    struct ovsdb_idl_txn *myTxn;
    const struct idltest_simple2 *myRow;
    const struct ovsdb_datum *smap, *imap OVS_UNUSED;
    int step = 0;
    char key_to_delete[100];

    idl = ovsdb_idl_create(ctx->argv[1], &idltest_idl_class, false, true);
    ovsdb_idl_add_table(idl, &idltest_table_simple2);
    ovsdb_idl_add_column(idl, &idltest_simple2_col_name);
    ovsdb_idl_add_column(idl, &idltest_simple2_col_smap);
    ovsdb_idl_add_column(idl, &idltest_simple2_col_imap);
    ovsdb_idl_get_initial_snapshot(idl);
    setvbuf(stdout, NULL, _IONBF, 0);
    ovsdb_idl_run(idl);

    /* Display original data in table. */
    myRow = NULL;
    printf("%03d: Getting records\n", step++);
    dump_simple2(idl, myRow, step++);

    /* Insert new elements in different map columns. */
    myRow = idltest_simple2_first(idl);
    myTxn = ovsdb_idl_txn_create(idl);
    idltest_simple2_get_smap(myRow, OVSDB_TYPE_STRING,
                                    OVSDB_TYPE_STRING);
    idltest_simple2_update_smap_setkey(myRow, "key1", "myList1");
    imap = idltest_simple2_get_imap(myRow, OVSDB_TYPE_INTEGER,
                                    OVSDB_TYPE_STRING);
    idltest_simple2_update_imap_setkey(myRow, 3, "myids2");
    idltest_simple2_set_name(myRow, "String2");
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After insert element\n", step++);
    dump_simple2(idl, myRow, step++);

    /* Insert duplicate element. */
    myTxn = ovsdb_idl_txn_create(idl);
    idltest_simple2_update_smap_setkey(myRow, "key1", "myList1");
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After insert duplicated element\n", step++);
    dump_simple2(idl, myRow, step++);

    /* Deletes an element of a map column. */
    myRow = idltest_simple2_first(idl);
    myTxn = ovsdb_idl_txn_create(idl);
    smap = idltest_simple2_get_smap(myRow, OVSDB_TYPE_STRING,
                                    OVSDB_TYPE_STRING);
    strcpy(key_to_delete, smap->keys[0].string);
    idltest_simple2_update_smap_delkey(myRow, smap->keys[0].string);
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After delete element\n", step++);
    dump_simple2(idl, myRow, step++);

    /* Try to delete a deleted element of a map column. */
    myTxn = ovsdb_idl_txn_create(idl);
    idltest_simple2_update_smap_delkey(myRow, key_to_delete);
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After trying to delete a deleted element\n", step++);
    dump_simple2(idl, myRow, step++);

    ovsdb_idl_destroy(idl);
    printf("%03d: End test\n", step);
    return;
}

static void
print_idl_row_simple3(const struct idltest_simple3 *s, int step)
{
    size_t i;
    const struct ovsdb_datum *uset;
    const struct ovsdb_datum *uref;

    uset = idltest_simple3_get_uset(s, OVSDB_TYPE_UUID);
    printf("%03d: name=%s uset=[",
           step, s->name);
    for (i = 0; i < uset->n; i++) {
        printf("["UUID_FMT"]%s", UUID_ARGS(&(uset->keys[i].uuid)), i < uset->n-1? ",": "");
    }
    uref = idltest_simple3_get_uref(s, OVSDB_TYPE_UUID);
    printf("] uref=[");
    for (i = 0; i < uref->n; i++) {
        printf("["UUID_FMT"]%s", UUID_ARGS(&(uref->keys[i].uuid)), i < uref->n-1? ",": "");
    }
    printf("]\n");
}

static void
dump_simple3(struct ovsdb_idl *idl,
             const struct idltest_simple3 *myRow,
             int step)
{
    IDLTEST_SIMPLE3_FOR_EACH(myRow, idl) {
        print_idl_row_simple3(myRow, step);
    }
}

static void
do_idl_partial_update_set_column(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_idl *idl;
    struct ovsdb_idl_txn *myTxn;
    const struct idltest_simple3 *myRow;
    struct idltest_simple4 *myRow2;
    const struct ovsdb_datum *uset OVS_UNUSED;
    const struct ovsdb_datum *uref OVS_UNUSED;
    int step = 0;

    idl = ovsdb_idl_create(ctx->argv[1], &idltest_idl_class, false, true);
    ovsdb_idl_add_table(idl, &idltest_table_simple3);
    ovsdb_idl_add_column(idl, &idltest_simple3_col_name);
    ovsdb_idl_add_column(idl, &idltest_simple3_col_uset);
    ovsdb_idl_add_column(idl, &idltest_simple3_col_uref);
    ovsdb_idl_add_table(idl, &idltest_table_simple4);
    ovsdb_idl_add_column(idl, &idltest_simple4_col_name);
    ovsdb_idl_get_initial_snapshot(idl);
    setvbuf(stdout, NULL, _IONBF, 0);
    ovsdb_idl_run(idl);

    /* Display original data in table. */
    myRow = NULL;
    printf("%03d: Getting records\n", step++);
    dump_simple3(idl, myRow, step++);

    /* Insert new elements in different map columns. */
    myRow = idltest_simple3_first(idl);
    myTxn = ovsdb_idl_txn_create(idl);
    idltest_simple3_get_uset(myRow, OVSDB_TYPE_UUID);
    struct uuid uuid_to_add;
    uuid_from_string(&uuid_to_add, "001e43d2-dd3f-4616-ab6a-83a490bb0991");
    idltest_simple3_update_uset_addvalue(myRow, uuid_to_add);
    idltest_simple3_set_name(myRow, "String2");
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After rename+add new value\n", step++);
    dump_simple3(idl, myRow, step++);

    /* Insert duplicate element. */
    myTxn = ovsdb_idl_txn_create(idl);
    struct uuid uuid_to_add2;
    uuid_from_string(&uuid_to_add2, "0026b3ba-571b-4729-8227-d860a5210ab8");
    idltest_simple3_update_uset_addvalue(myRow, uuid_to_add2);
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After add new value\n", step++);
    dump_simple3(idl, myRow, step++);

    /* Deletes an element of a set column. */
    myRow = idltest_simple3_first(idl);
    myTxn = ovsdb_idl_txn_create(idl);
    uset = idltest_simple3_get_uset(myRow, OVSDB_TYPE_UUID);
    idltest_simple3_update_uset_delvalue(myRow, uuid_to_add);
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After delete value\n", step++);
    dump_simple3(idl, myRow, step++);

    /* Try to delete a deleted element of a map column.  */
    myRow = idltest_simple3_first(idl);
    myTxn = ovsdb_idl_txn_create(idl);
    idltest_simple3_update_uset_delvalue(myRow, uuid_to_add);
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After trying to delete a deleted value\n", step++);
    dump_simple3(idl, myRow, step++);

    /* Adds to a table and update a strong reference in another table. */
    myRow = idltest_simple3_first(idl);
    myTxn = ovsdb_idl_txn_create(idl);
    myRow2 = idltest_simple4_insert(myTxn);
    idltest_simple4_set_name(myRow2, "test");
    idltest_simple3_update_uref_addvalue(myRow, myRow2);
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After add to other table + set of strong ref\n", step++);
    dump_simple3(idl, myRow, step++);
    ovsdb_idl_destroy(idl);
    printf("%03d: End test\n", step);
    return;
}

static void
do_idl_compound_index_with_ref(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_idl *idl;
    struct ovsdb_idl_txn *myTxn;
    const struct idltest_simple3 *myRow;
    struct idltest_simple4 *myRow2;
    const struct ovsdb_datum *uset OVS_UNUSED;
    const struct ovsdb_datum *uref OVS_UNUSED;
    struct ovsdb_idl_index_cursor cursor;
    int step = 0;

    idl = ovsdb_idl_create(ctx->argv[1], &idltest_idl_class, false, true);
    ovsdb_idl_add_table(idl, &idltest_table_simple3);
    ovsdb_idl_add_column(idl, &idltest_simple3_col_name);
    ovsdb_idl_add_column(idl, &idltest_simple3_col_uset);
    ovsdb_idl_add_column(idl, &idltest_simple3_col_uref);
    ovsdb_idl_add_table(idl, &idltest_table_simple4);
    ovsdb_idl_add_column(idl, &idltest_simple4_col_name);

    struct ovsdb_idl_index *index;
    index = ovsdb_idl_create_index(idl, &idltest_table_simple3, "uref");
    ovsdb_idl_index_add_column(index, &idltest_simple3_col_uref,
                               OVSDB_INDEX_ASC, NULL);

    ovsdb_idl_get_initial_snapshot(idl);

    ovsdb_idl_initialize_cursor(idl, &idltest_table_simple3, "uref",
                                &cursor);

    setvbuf(stdout, NULL, _IONBF, 0);
    ovsdb_idl_run(idl);

    /* Adds to a table and update a strong reference in another table. */
    myTxn = ovsdb_idl_txn_create(idl);
    myRow = idltest_simple3_insert(myTxn);
    myRow2 = idltest_simple4_insert(myTxn);
    idltest_simple4_set_name(myRow2, "test");
    idltest_simple3_update_uref_addvalue(myRow, myRow2);
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After add to other table + set of strong ref\n", step++);
    dump_simple3(idl, myRow, step++);

    myRow2 = (struct idltest_simple4 *) idltest_simple4_first(idl);
    printf("%03d: check simple4: %s\n", step++,
           myRow2 ? "not empty" : "empty");

    /* Use index to query the row with reference */

    struct idltest_simple3 *equal;
    equal = idltest_simple3_index_init_row(idl, &idltest_table_simple3);
    myRow2 = (struct idltest_simple4 *) idltest_simple4_first(idl);
    idltest_simple3_index_set_uref(equal, &myRow2, 1);
    printf("%03d: Query using index with reference\n", step++);
    IDLTEST_SIMPLE3_FOR_EACH_EQUAL (myRow, &cursor, equal) {
        print_idl_row_simple3(myRow, step++);
    }
    idltest_simple3_index_destroy_row(equal);

    /* Delete the row with reference */
    myTxn = ovsdb_idl_txn_create(idl);
    myRow = idltest_simple3_first(idl);
    idltest_simple3_delete(myRow);
    ovsdb_idl_txn_commit_block(myTxn);
    ovsdb_idl_txn_destroy(myTxn);
    ovsdb_idl_get_initial_snapshot(idl);
    printf("%03d: After delete\n", step++);
    dump_simple3(idl, myRow, step++);

    myRow2 = (struct idltest_simple4 *) idltest_simple4_first(idl);
    printf("%03d: check simple4: %s\n", step++,
           myRow2 ? "not empty" : "empty");

    ovsdb_idl_destroy(idl);
    printf("%03d: End test\n", step);
    return;
}


static int
test_idl_compound_index_single_column(struct ovsdb_idl *idl,
        struct ovsdb_idl_index_cursor *sCursor,
        struct ovsdb_idl_index_cursor *iCursor)
{
    const struct idltest_simple *myRow;
    struct ovsdb_idl_txn *txn;
    int step = 0;

     /* Display records by string index -> sCursor */
     ++step;
     IDLTEST_SIMPLE_FOR_EACH_BYINDEX (myRow, sCursor) {
         printf("%03d: s=%s i=%"PRId64" b=%s r=%f\n", step, myRow->s,
                myRow->i, myRow->b?"True":"False", myRow->r);
     }
     /* Display records by integer index -> iCursor */
     ++step;
     IDLTEST_SIMPLE_FOR_EACH_BYINDEX (myRow, iCursor) {
         printf("%03d: i=%"PRId64" s=%s b=%s r=%f\n", step,  myRow->i,
                myRow->s, myRow->b?"True":"False", myRow->r);
     }
     /* Display records by string index -> sCursor with filtering
      * where s=\"List001\
      */
     ++step;
     struct idltest_simple *equal;
     equal = idltest_simple_index_init_row(idl, &idltest_table_simple);
     idltest_simple_index_set_s(equal, "List001");
     ovs_assert(strcmp(equal->s, "List001") == 0);
     IDLTEST_SIMPLE_FOR_EACH_EQUAL (myRow, sCursor, equal) {
         printf("%03d: s=%s i=%"PRId64" b=%s r=%f\n", step, myRow->s,
                myRow->i, myRow->b?"True":"False", myRow->r);
     }
     /* Display records by integer index -> iCursor with filtering where i=5 */
     ++step;
     idltest_simple_index_set_i(equal, 5);
     ovs_assert(equal->i == 5);
     IDLTEST_SIMPLE_FOR_EACH_EQUAL (myRow, iCursor, equal) {
         printf("%03d: i=%"PRId64" s=%s b=%s r=%f\n", step,  myRow->i,
                myRow->s, myRow->b?"True":"False", myRow->r);
     }
     /* Display records by integer index -> iCursor in range i=[3,7] */
     ++step;
     struct idltest_simple *from, *to;
     from = idltest_simple_index_init_row(idl, &idltest_table_simple);
     idltest_simple_index_set_i(from, 3);
     ovs_assert(from->i == 3);
     to = idltest_simple_index_init_row(idl, &idltest_table_simple);
     idltest_simple_index_set_i(to, 7);
     ovs_assert(to->i == 7);
     IDLTEST_SIMPLE_FOR_EACH_RANGE (myRow, iCursor, from, to) {
         printf("%03d: i=%"PRId64" s=%s b=%s r=%f\n", step,  myRow->i,
                myRow->s, myRow->b?"True":"False", myRow->r);
     }
     /* Delete record i=4 and insert i=54 by integer index -> iCursor */
     ++step;
     struct idltest_simple *toDelete, *toInsert;
     toDelete = idltest_simple_index_init_row(idl, &idltest_table_simple);
     idltest_simple_index_set_i(toDelete, 4);
     ovs_assert(toDelete->i == 4);
     myRow = idltest_simple_index_find(iCursor, toDelete);
     ovs_assert(myRow);
     ovs_assert(myRow->i == 4);
     txn = ovsdb_idl_txn_create(idl);
     idltest_simple_delete(myRow);
     toInsert = idltest_simple_insert(txn);
     idltest_simple_set_i(toInsert, 54);
     idltest_simple_set_s(toInsert, "Lista054");
     ovsdb_idl_txn_commit_block(txn);
     ovsdb_idl_txn_destroy(txn);
     idltest_simple_index_set_i(to, 60);
     printf("Expected 60, stored %"PRId64"\n", to->i);
     ovs_assert(to->i == 60);
     IDLTEST_SIMPLE_FOR_EACH_RANGE (myRow, iCursor, from, to) {
         printf("%03d: i=%"PRId64" s=%s b=%s r=%f\n", step,  myRow->i,
                myRow->s, myRow->b?"True":"False", myRow->r);
     }

     /* Test special-case range, "from" and "to" are both NULL,
      * which is interpreted as the range from -infinity to +infinity. */
     ++step;
     IDLTEST_SIMPLE_FOR_EACH_RANGE (myRow, iCursor, NULL, NULL) {
         printf("%03d: i=%"PRId64" s=%s b=%s r=%f\n", step,  myRow->i,
                myRow->s, myRow->b?"True":"False", myRow->r);
     }

     /* Free the temporal rows */
     idltest_simple_index_destroy_row(from);
     idltest_simple_index_destroy_row(to);
     idltest_simple_index_destroy_row(equal);
     return step;
}

static int
test_idl_compound_index_double_column(struct ovsdb_idl *idl,
        struct ovsdb_idl_index_cursor *siCursor,
        struct ovsdb_idl_index_cursor *sidCursor,
        struct ovsdb_idl_index_cursor *isCursor,
        struct ovsdb_idl_index_cursor *idsCursor)
{
    const struct idltest_simple *myRow;
    int step = 0;

    /* Display records by string-integer index -> siCursor */
    step++;
    IDLTEST_SIMPLE_FOR_EACH_BYINDEX (myRow, siCursor) {
        printf("%03d: s=%s i=%"PRId64" b=%s r=%f\n", step, myRow->s, myRow->i,
               myRow->b?"True":"False", myRow->r);
    }
    /* Display records by string-integer(down order) index -> sidCursor */
    step++;
    IDLTEST_SIMPLE_FOR_EACH_BYINDEX (myRow, sidCursor) {
        printf("%03d: s=%s i=%"PRId64" b=%s r=%f\n", step, myRow->s, myRow->i,
               myRow->b?"True":"False", myRow->r);
    }
    /* Display records by string-integer index -> siCursor with filtering
     * where s="List000" and i=10
     */
    step++;
    struct idltest_simple *equal;
    equal = idltest_simple_index_init_row(idl, &idltest_table_simple);
    idltest_simple_index_set_s(equal, "List000");
    ovs_assert(strcmp(equal->s, "List000") == 0);
    idltest_simple_index_set_i(equal, 10);
    ovs_assert(equal->i == 10);
    IDLTEST_SIMPLE_FOR_EACH_EQUAL (myRow, siCursor, equal) {
        printf("%03d: s=%s i=%"PRId64" b=%s r=%f\n", step, myRow->s, myRow->i,
               myRow->b?"True":"False", myRow->r);
    }
    /* Display records by string-integer index -> siCursor in range i=[0,100]
     * and s=[\"List002\",\"List003\"]
     */
    step++;
    struct idltest_simple *from, *to;
    from =  idltest_simple_index_init_row(idl, &idltest_table_simple);
    to = idltest_simple_index_init_row(idl, &idltest_table_simple);
    idltest_simple_index_set_i(from, 0);
    ovs_assert(from->i == 0);
    idltest_simple_index_set_s(from, "List001");
    ovs_assert(strcmp(from->s, "List001") == 0);
    idltest_simple_index_set_i(to, 100);
    ovs_assert(to->i == 100);
    idltest_simple_index_set_s(to, "List005");
    ovs_assert(strcmp(to->s, "List005")==0);
    IDLTEST_SIMPLE_FOR_EACH_RANGE (myRow, siCursor, from, to) {
        printf("%03d: s=%s i=%"PRId64" b=%s r=%f\n", step, myRow->s, myRow->i,
               myRow->b?"True":"False", myRow->r);
    }
    /* Display records using integer-string index. */
    step++;
    IDLTEST_SIMPLE_FOR_EACH_BYINDEX (myRow, isCursor) {
        printf("%03d: i=%"PRId64" s=%s b=%s r=%f\n", step, myRow->i, myRow->s,
               myRow->b?"True":"False", myRow->r);
    }
    /* Display records using integer(descend)-string index. */
    step++;
    IDLTEST_SIMPLE_FOR_EACH_BYINDEX (myRow, idsCursor) {
        printf("%03d: i=%"PRId64" s=%s b=%s r=%f\n", step, myRow->i, myRow->s,
               myRow->b?"True":"False", myRow->r);
    }

    idltest_simple_index_destroy_row(to);
    idltest_simple_index_destroy_row(from);
    idltest_simple_index_destroy_row(equal);
    return step;
}

static void
do_idl_compound_index(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_idl *idl;
    struct ovsdb_idl_index_cursor sCursor, iCursor, siCursor, sidCursor,
                    isCursor, idsCursor;
    enum TESTS { IDL_COMPOUND_INDEX_WITH_SINGLE_COLUMN,
            IDL_COMPOUND_INDEX_WITH_DOUBLE_COLUMN
    };
    int step = 0;
    int i;

    idl = ovsdb_idl_create(ctx->argv[1], &idltest_idl_class, false, true);

    /* Add tables/columns and initialize index data needed for tests */
    ovsdb_idl_add_table(idl, &idltest_table_simple);
    ovsdb_idl_add_column(idl, &idltest_simple_col_s);
    ovsdb_idl_add_column(idl, &idltest_simple_col_i);
    ovsdb_idl_add_column(idl, &idltest_simple_col_r);
    ovsdb_idl_add_column(idl, &idltest_simple_col_b);

    struct ovsdb_idl_index *index;
    index = ovsdb_idl_create_index(idl, &idltest_table_simple, "string");
    ovsdb_idl_index_add_column(index, &idltest_simple_col_s, OVSDB_INDEX_ASC,
                               NULL);

    index = ovsdb_idl_create_index(idl, &idltest_table_simple, "integer");
    ovsdb_idl_index_add_column(index, &idltest_simple_col_i, OVSDB_INDEX_ASC,
                               NULL);

    index = ovsdb_idl_create_index(idl, &idltest_table_simple,
                                   "string-integer");
    ovsdb_idl_index_add_column(index, &idltest_simple_col_s, OVSDB_INDEX_ASC,
                               NULL);
    ovsdb_idl_index_add_column(index, &idltest_simple_col_i, OVSDB_INDEX_ASC,
                               NULL);

    index = ovsdb_idl_create_index(idl, &idltest_table_simple,
                                   "string-integerd");
    ovsdb_idl_index_add_column(index, &idltest_simple_col_s, OVSDB_INDEX_ASC,
                               NULL);
    ovsdb_idl_index_add_column(index, &idltest_simple_col_i, OVSDB_INDEX_DESC,
                               NULL);

    index = ovsdb_idl_create_index(idl, &idltest_table_simple,
                                   "integer-string");
    ovsdb_idl_index_add_column(index, &idltest_simple_col_i, OVSDB_INDEX_ASC,
                               NULL);
    ovsdb_idl_index_add_column(index, &idltest_simple_col_s, OVSDB_INDEX_ASC,
                               NULL);

    index = ovsdb_idl_create_index(idl, &idltest_table_simple,
                                   "integerd-string");
    ovsdb_idl_index_add_column(index, &idltest_simple_col_i, OVSDB_INDEX_DESC,
                               NULL);
    ovsdb_idl_index_add_column(index, &idltest_simple_col_s, OVSDB_INDEX_ASC,
                               NULL);

    /* wait for replica to be updated */
    ovsdb_idl_get_initial_snapshot(idl);

    /* Initialize cursors to be used by indexes */
    ovsdb_idl_initialize_cursor(idl, &idltest_table_simple, "string",
                                &sCursor);
    ovsdb_idl_initialize_cursor(idl, &idltest_table_simple, "integer",
                                &iCursor);
    ovsdb_idl_initialize_cursor(idl, &idltest_table_simple, "string-integer",
                                &siCursor);
    ovsdb_idl_initialize_cursor(idl, &idltest_table_simple, "string-integerd",
                                &sidCursor);
    ovsdb_idl_initialize_cursor(idl, &idltest_table_simple, "integer-string",
                                &isCursor);
    ovsdb_idl_initialize_cursor(idl, &idltest_table_simple, "integerd-string",
                                &idsCursor);

    setvbuf(stdout, NULL, _IONBF, 0);
    int test_to_run = -1;
    for (i = 2; i < ctx->argc; i++) {
        char *arg = ctx->argv[i];

        if (strcmp(arg,"idl_compound_index_single_column") == 0) {
            test_to_run = IDL_COMPOUND_INDEX_WITH_SINGLE_COLUMN;
        } else if (strcmp(arg, "idl_compound_index_double_column") == 0) {
            test_to_run = IDL_COMPOUND_INDEX_WITH_DOUBLE_COLUMN;
        }

        switch (test_to_run) {
            case IDL_COMPOUND_INDEX_WITH_SINGLE_COLUMN:
                test_idl_compound_index_single_column(idl, &sCursor, &iCursor);
                break;
            case IDL_COMPOUND_INDEX_WITH_DOUBLE_COLUMN:
                test_idl_compound_index_double_column(idl, &siCursor,
                        &sidCursor, &isCursor, &idsCursor);
                break;
            default:
                printf("%03d: Test %s not implemented.\n", step++, arg);
        }
    }
    ovsdb_idl_destroy(idl);
    printf("%03d: done\n", step);
}

static struct ovs_cmdl_command all_commands[] = {
    { "log-io", NULL, 2, INT_MAX, do_log_io, OVS_RO },
    { "default-atoms", NULL, 0, 0, do_default_atoms, OVS_RO },
    { "default-data", NULL, 0, 0, do_default_data, OVS_RO },
    { "diff-data", NULL, 3, INT_MAX, do_diff_data, OVS_RO },
    { "parse-atomic-type", NULL, 1, 1, do_parse_atomic_type, OVS_RO },
    { "parse-base-type", NULL, 1, 1, do_parse_base_type, OVS_RO },
    { "parse-type", NULL, 1, 1, do_parse_type, OVS_RO },
    { "parse-atoms", NULL, 2, INT_MAX, do_parse_atoms, OVS_RO },
    { "parse-atom-strings", NULL, 2, INT_MAX, do_parse_atom_strings, OVS_RO },
    { "parse-data", NULL, 2, INT_MAX, do_parse_data, OVS_RO },
    { "parse-data-strings", NULL, 2, INT_MAX, do_parse_data_strings, OVS_RO },
    { "sort-atoms", NULL, 2, 2, do_sort_atoms, OVS_RO },
    { "parse-column", NULL, 2, 2, do_parse_column, OVS_RO },
    { "parse-table", NULL, 2, 3, do_parse_table, OVS_RO },
    { "parse-rows", NULL, 2, INT_MAX, do_parse_rows, OVS_RO },
    { "compare-rows", NULL, 2, INT_MAX, do_compare_rows, OVS_RO },
    { "parse-conditions", NULL, 2, INT_MAX, do_parse_conditions, OVS_RO },
    { "evaluate-conditions", NULL, 3, 3, do_evaluate_conditions, OVS_RO },
    { "evaluate-conditions-any", NULL, 3, 3, do_evaluate_conditions_any, OVS_RO },
    { "compare-conditions", NULL, 2, 2, do_compare_conditions, OVS_RO },
    { "parse-mutations", NULL, 2, INT_MAX, do_parse_mutations, OVS_RO },
    { "execute-mutations", NULL, 3, 3, do_execute_mutations, OVS_RO },
    { "query", NULL, 3, 3, do_query, OVS_RO },
    { "query-distinct", NULL, 4, 4, do_query_distinct, OVS_RO },
    { "transact", NULL, 1, INT_MAX, do_transact, OVS_RO },
    { "parse-schema", NULL, 1, 1, do_parse_schema, OVS_RO },
    { "execute", NULL, 2, INT_MAX, do_execute, OVS_RO },
    { "execute-readonly", NULL, 2, INT_MAX, do_execute_ro, OVS_RO },
    { "trigger", NULL, 2, INT_MAX, do_trigger, OVS_RO },
    { "idl", NULL, 1, INT_MAX, do_idl, OVS_RO },
    { "idl-compound-index", NULL, 2, 2, do_idl_compound_index, OVS_RW },
    { "idl-compound-index-with-ref", NULL, 1, INT_MAX,
        do_idl_compound_index_with_ref, OVS_RO },
    { "idl-partial-update-map-column", NULL, 1, INT_MAX,
        do_idl_partial_update_map_column, OVS_RO },
    { "idl-partial-update-set-column", NULL, 1, INT_MAX,
        do_idl_partial_update_set_column, OVS_RO },
    { "help", NULL, 0, INT_MAX, do_help, OVS_RO },
    { NULL, NULL, 0, 0, NULL, OVS_RO },
};

static struct ovs_cmdl_command *
get_all_commands(void)
{
    return all_commands;
}
