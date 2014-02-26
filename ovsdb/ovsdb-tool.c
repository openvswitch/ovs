/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "column.h"
#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "file.h"
#include "lockfile.h"
#include "log.h"
#include "json.h"
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "socket-util.h"
#include "table.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

/* -m, --more: Verbosity level for "show-log" command output. */
static int show_log_verbosity;

static const struct command *get_all_commands(void);

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

static const char *default_db(void);
static const char *default_schema(void);

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();
    run_command(argc - optind, argv + optind, get_all_commands());
    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    static const struct option long_options[] = {
        {"more", no_argument, NULL, 'm'},
        {"verbose", optional_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'm':
            show_log_verbosity++;
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

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
    printf("%s: Open vSwitch database management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "  create [DB [SCHEMA]]    create DB with the given SCHEMA\n"
           "  compact [DB [DST]]      compact DB in-place (or to DST)\n"
           "  convert [DB [SCHEMA [DST]]]   convert DB to SCHEMA (to DST)\n"
           "  db-version [DB]         report version of schema used by DB\n"
           "  db-cksum [DB]           report checksum of schema used by DB\n"
           "  schema-version [SCHEMA] report SCHEMA's schema version\n"
           "  schema-cksum [SCHEMA]   report SCHEMA's checksum\n"
           "  query [DB] TRNS         execute read-only transaction on DB\n"
           "  transact [DB] TRNS      execute read/write transaction on DB\n"
           "  [-m]... show-log [DB]   print DB's log entries\n"
           "The default DB is %s.\n"
           "The default SCHEMA is %s.\n",
           program_name, program_name, default_db(), default_schema());
    vlog_usage();
    printf("\nOther options:\n"
           "  -m, --more                  increase show-log verbosity\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static const char *
default_db(void)
{
    static char *db;
    if (!db) {
        db = xasprintf("%s/conf.db", ovs_dbdir());
    }
    return db;
}

static const char *
default_schema(void)
{
    static char *schema;
    if (!schema) {
        schema = xasprintf("%s/vswitch.ovsschema", ovs_pkgdatadir());
    }
    return schema;
}

static struct json *
parse_json(const char *s)
{
    struct json *json = json_from_string(s);
    if (json->type == JSON_STRING) {
        ovs_fatal(0, "\"%s\": %s", s, json->u.string);
    }
    return json;
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
check_ovsdb_error(struct ovsdb_error *error)
{
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string(error));
    }
}

static void
do_create(int argc, char *argv[])
{
    const char *db_file_name = argc >= 2 ? argv[1] : default_db();
    const char *schema_file_name = argc >= 3 ? argv[2] : default_schema();
    struct ovsdb_schema *schema;
    struct ovsdb_log *log;
    struct json *json;

    /* Read schema from file and convert to JSON. */
    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    json = ovsdb_schema_to_json(schema);
    ovsdb_schema_destroy(schema);

    /* Create database file. */
    check_ovsdb_error(ovsdb_log_open(db_file_name, OVSDB_LOG_CREATE,
                                     -1, &log));
    check_ovsdb_error(ovsdb_log_write(log, json));
    check_ovsdb_error(ovsdb_log_commit(log));
    ovsdb_log_close(log);

    json_destroy(json);
}

static void
compact_or_convert(const char *src_name_, const char *dst_name_,
                   const struct ovsdb_schema *new_schema,
                   const char *comment)
{
    char *src_name, *dst_name;
    struct lockfile *src_lock;
    struct lockfile *dst_lock;
    bool in_place = dst_name_ == NULL;
    struct ovsdb *db;
    int retval;

    /* Dereference symlinks for source and destination names.  In the in-place
     * case this ensures that, if the source name is a symlink, we replace its
     * target instead of replacing the symlink by a regular file.  In the
     * non-in-place, this has the same effect for the destination name. */
    src_name = follow_symlinks(src_name_);
    dst_name = (in_place
                ? xasprintf("%s.tmp", src_name)
                : follow_symlinks(dst_name_));

    /* Lock the source, if we will be replacing it. */
    if (in_place) {
        retval = lockfile_lock(src_name, &src_lock);
        if (retval) {
            ovs_fatal(retval, "%s: failed to lock lockfile", src_name);
        }
    }

    /* Get (temporary) destination and lock it. */
    retval = lockfile_lock(dst_name, &dst_lock);
    if (retval) {
        ovs_fatal(retval, "%s: failed to lock lockfile", dst_name);
    }

    /* Save a copy. */
    check_ovsdb_error(new_schema
                      ? ovsdb_file_open_as_schema(src_name, new_schema, &db)
                      : ovsdb_file_open(src_name, true, &db, NULL));
    check_ovsdb_error(ovsdb_file_save_copy(dst_name, false, comment, db));
    ovsdb_destroy(db);

    /* Replace source. */
    if (in_place) {
        if (rename(dst_name, src_name)) {
            ovs_fatal(errno, "failed to rename \"%s\" to \"%s\"",
                      dst_name, src_name);
        }
        fsync_parent_dir(dst_name);
        lockfile_unlock(src_lock);
    }

    lockfile_unlock(dst_lock);

    free(src_name);
    free(dst_name);
}

static void
do_compact(int argc, char *argv[])
{
    const char *db = argc >= 2 ? argv[1] : default_db();
    const char *target = argc >= 3 ? argv[2] : NULL;

    compact_or_convert(db, target, NULL, "compacted by ovsdb-tool "VERSION);
}

static void
do_convert(int argc, char *argv[])
{
    const char *db = argc >= 2 ? argv[1] : default_db();
    const char *schema = argc >= 3 ? argv[2] : default_schema();
    const char *target = argc >= 4 ? argv[3] : NULL;
    struct ovsdb_schema *new_schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema, &new_schema));
    compact_or_convert(db, target, new_schema,
                       "converted by ovsdb-tool "VERSION);
    ovsdb_schema_destroy(new_schema);
}

static void
do_needs_conversion(int argc, char *argv[])
{
    const char *db_file_name = argc >= 2 ? argv[1] : default_db();
    const char *schema_file_name = argc >= 3 ? argv[2] : default_schema();
    struct ovsdb_schema *schema1, *schema2;

    check_ovsdb_error(ovsdb_file_read_schema(db_file_name, &schema1));
    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema2));
    puts(ovsdb_schema_equal(schema1, schema2) ? "no" : "yes");
    ovsdb_schema_destroy(schema1);
    ovsdb_schema_destroy(schema2);
}

static void
do_db_version(int argc, char *argv[])
{
    const char *db_file_name = argc >= 2 ? argv[1] : default_db();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_file_read_schema(db_file_name, &schema));
    puts(schema->version);
    ovsdb_schema_destroy(schema);
}

static void
do_db_cksum(int argc OVS_UNUSED, char *argv[])
{
    const char *db_file_name = argc >= 2 ? argv[1] : default_db();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_file_read_schema(db_file_name, &schema));
    puts(schema->cksum);
    ovsdb_schema_destroy(schema);
}

static void
do_schema_version(int argc, char *argv[])
{
    const char *schema_file_name = argc >= 2 ? argv[1] : default_schema();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    puts(schema->version);
    ovsdb_schema_destroy(schema);
}

static void
do_schema_cksum(int argc, char *argv[])
{
    const char *schema_file_name = argc >= 2 ? argv[1] : default_schema();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    puts(schema->cksum);
    ovsdb_schema_destroy(schema);
}

static void
transact(bool read_only, int argc, char *argv[])
{
    const char *db_file_name = argc >= 3 ? argv[1] : default_db();
    const char *transaction = argv[argc - 1];
    struct json *request, *result;
    struct ovsdb *db;

    check_ovsdb_error(ovsdb_file_open(db_file_name, read_only, &db, NULL));

    request = parse_json(transaction);
    result = ovsdb_execute(db, NULL, request, 0, NULL);
    json_destroy(request);

    print_and_free_json(result);
    ovsdb_destroy(db);
}

static void
do_query(int argc, char *argv[])
{
    transact(true, argc, argv);
}

static void
do_transact(int argc, char *argv[])
{
    transact(false, argc, argv);
}

static void
print_db_changes(struct shash *tables, struct shash *names,
                 const struct ovsdb_schema *schema)
{
    struct shash_node *n1;

    SHASH_FOR_EACH (n1, tables) {
        const char *table = n1->name;
        struct ovsdb_table_schema *table_schema;
        struct json *rows = n1->data;
        struct shash_node *n2;

        if (n1->name[0] == '_' || rows->type != JSON_OBJECT) {
            continue;
        }

        table_schema = shash_find_data(&schema->tables, table);
        SHASH_FOR_EACH (n2, json_object(rows)) {
            const char *row_uuid = n2->name;
            struct json *columns = n2->data;
            struct shash_node *n3;
            char *old_name, *new_name;
            bool free_new_name = false;

            old_name = new_name = shash_find_data(names, row_uuid);
            if (columns->type == JSON_OBJECT) {
                struct json *new_name_json;

                new_name_json = shash_find_data(json_object(columns), "name");
                if (new_name_json) {
                    new_name = json_to_string(new_name_json, JSSF_SORT);
                    free_new_name = true;
                }
            }

            printf("\ttable %s", table);

            if (!old_name) {
                if (new_name) {
                    printf(" insert row %s (%.8s):\n", new_name, row_uuid);
                } else {
                    printf(" insert row %.8s:\n", row_uuid);
                }
            } else {
                printf(" row %s (%.8s):\n", old_name, row_uuid);
            }

            if (columns->type == JSON_OBJECT) {
                if (show_log_verbosity > 1) {
                    SHASH_FOR_EACH (n3, json_object(columns)) {
                        const char *column = n3->name;
                        const struct ovsdb_column *column_schema;
                        struct json *value = n3->data;
                        char *value_string = NULL;

                        column_schema =
                            (table_schema
                             ? shash_find_data(&table_schema->columns, column)
                             : NULL);
                        if (column_schema) {
                            const struct ovsdb_type *type;
                            struct ovsdb_error *error;
                            struct ovsdb_datum datum;

                            type = &column_schema->type;
                            error = ovsdb_datum_from_json(&datum, type,
                                                          value, NULL);
                            if (!error) {
                                struct ds s;

                                ds_init(&s);
                                ovsdb_datum_to_string(&datum, type, &s);
                                value_string = ds_steal_cstr(&s);
                            } else {
                                ovsdb_error_destroy(error);
                            }
                        }
                        if (!value_string) {
                            value_string = json_to_string(value, JSSF_SORT);
                        }
                        printf("\t\t%s=%s\n", column, value_string);
                        free(value_string);
                    }
                }
                if (!old_name
                    || (new_name != old_name && strcmp(old_name, new_name))) {
                    if (old_name) {
                        shash_delete(names, shash_find(names, row_uuid));
                        free(old_name);
                    }
                    shash_add(names, row_uuid, (new_name
                                                ? xstrdup(new_name)
                                                : xmemdup0(row_uuid, 8)));
                }
            } else if (columns->type == JSON_NULL) {
                struct shash_node *node;

                printf("\t\tdelete row\n");
                node = shash_find(names, row_uuid);
                if (node) {
                    shash_delete(names, node);
                }
                free(old_name);
            }

            if (free_new_name) {
                free(new_name);
            }
        }
    }
}

static void
do_show_log(int argc, char *argv[])
{
    const char *db_file_name = argc >= 2 ? argv[1] : default_db();
    struct shash names;
    struct ovsdb_log *log;
    struct ovsdb_schema *schema;
    unsigned int i;

    check_ovsdb_error(ovsdb_log_open(db_file_name, OVSDB_LOG_READ_ONLY,
                                     -1, &log));
    shash_init(&names);
    schema = NULL;
    for (i = 0; ; i++) {
        struct json *json;

        check_ovsdb_error(ovsdb_log_read(log, &json));
        if (!json) {
            break;
        }

        printf("record %u:", i);
        if (i == 0) {
            check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
            printf(" \"%s\" schema, version=\"%s\", cksum=\"%s\"\n",
                   schema->name, schema->version, schema->cksum);
        } else if (json->type == JSON_OBJECT) {
            struct json *date, *comment;

            date = shash_find_data(json_object(json), "_date");
            if (date && date->type == JSON_INTEGER) {
                long long int t = json_integer(date);
                char *s;

                if (t < INT32_MAX) {
                    /* Older versions of ovsdb wrote timestamps in seconds. */
                    t *= 1000;
                }

                s = xastrftime_msec(" %Y-%m-%d %H:%M:%S.###", t, true);
                fputs(s, stdout);
                free(s);
            }

            comment = shash_find_data(json_object(json), "_comment");
            if (comment && comment->type == JSON_STRING) {
                printf(" \"%s\"", json_string(comment));
            }

            if (i > 0 && show_log_verbosity > 0) {
                putchar('\n');
                print_db_changes(json_object(json), &names, schema);
            }
        }
        json_destroy(json);
        putchar('\n');
    }

    ovsdb_log_close(log);
    ovsdb_schema_destroy(schema);
    /* XXX free 'names'. */
}

static void
do_help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
}

static const struct command all_commands[] = {
    { "create", 0, 2, do_create },
    { "compact", 0, 2, do_compact },
    { "convert", 0, 3, do_convert },
    { "needs-conversion", 0, 2, do_needs_conversion },
    { "db-version", 0, 1, do_db_version },
    { "db-cksum", 0, 1, do_db_cksum },
    { "schema-version", 0, 1, do_schema_version },
    { "schema-cksum", 0, 1, do_schema_cksum },
    { "query", 1, 2, do_query },
    { "transact", 1, 2, do_transact },
    { "show-log", 0, 1, do_show_log },
    { "help", 0, INT_MAX, do_help },
    { NULL, 0, 0, NULL },
};

static const struct command *get_all_commands(void)
{
    return all_commands;
}
