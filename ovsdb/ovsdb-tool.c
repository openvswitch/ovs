/*
 * Copyright (c) 2009 Nicira Networks.
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

#include "command-line.h"
#include "compiler.h"
#include "file.h"
#include "log.h"
#include "json.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "table.h"
#include "timeval.h"
#include "util.h"

#include "vlog.h"
#define THIS_MODULE VLM_ovsdb_tool

static const struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    run_command(argc - optind, argv + optind, all_commands);
    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"verbose", optional_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(0, 0);
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
           "  create DB SCHEMA   create DB with the given SCHEMA\n"
           "  compact DB [DST]   compact DB in-place (or to DST)\n"
           "  extract-schema DB  print DB's schema on stdout\n"
           "  query DB TRNS      execute read-only transaction on DB\n"
           "  transact DB TRNS   execute read/write transaction on DB\n"
           "  show-log DB        prints information about DB's log entries\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
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
do_create(int argc UNUSED, char *argv[])
{
    const char *db_file_name = argv[1];
    const char *schema_file_name = argv[2];
    struct ovsdb_schema *schema;
    struct ovsdb_log *log;
    struct json *json;

    /* Read schema from file and convert to JSON. */
    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    json = ovsdb_schema_to_json(schema);

    /* Create database file. */
    check_ovsdb_error(ovsdb_log_open(db_file_name, O_RDWR | O_CREAT | O_EXCL,
                                     &log));
    check_ovsdb_error(ovsdb_log_write(log, json));
    check_ovsdb_error(ovsdb_log_commit(log));
    ovsdb_log_close(log);

    json_destroy(json);
}

static void
transact(bool read_only, const char *db_file_name, const char *transaction)
{
    struct json *request, *result;
    struct ovsdb *db;

    check_ovsdb_error(ovsdb_file_open(db_file_name, read_only, &db));

    request = parse_json(transaction);
    result = ovsdb_execute(db, request, 0, NULL);
    json_destroy(request);

    print_and_free_json(result);
    ovsdb_destroy(db);
}

static void
do_query(int argc UNUSED, char *argv[])
{
    transact(true, argv[1], argv[2]);
}

static void
do_transact(int argc UNUSED, char *argv[])
{
    transact(false, argv[1], argv[2]);
}

static void
do_show_log(int argc UNUSED, char *argv[])
{
    const char *db_file_name = argv[1];
    struct ovsdb_log *log;
    unsigned int i;

    check_ovsdb_error(ovsdb_log_open(db_file_name, O_RDONLY, &log));
    for (i = 0; ; i++) {
        struct json *json;

        check_ovsdb_error(ovsdb_log_read(log, &json));
        if (!json) {
            break;
        }

        printf("record %u:", i);
        if (json->type == JSON_OBJECT) {
            struct json *date, *comment;

            date = shash_find_data(json_object(json), "_date");
            if (date && date->type == JSON_INTEGER) {
                time_t t = json_integer(date);
                char s[128];

                strftime(s, sizeof s, "%Y-%m-%d %H:%M:%S", localtime(&t));
                printf(" %s", s);
            }

            comment = shash_find_data(json_object(json), "_comment");
            if (comment && comment->type == JSON_STRING) {
                printf(" \"%s\"", json_string(comment));
            }
        }
        json_destroy(json);
        putchar('\n');
    }
}

static void
do_help(int argc UNUSED, char *argv[] UNUSED)
{
    usage();
}

static const struct command all_commands[] = {
    { "create", 2, 2, do_create },
    { "query", 2, 2, do_query },
    { "transact", 2, 2, do_transact },
    { "show-log", 1, 1, do_show_log },
    { "help", 0, INT_MAX, do_help },
    { NULL, 0, 0, NULL },
};
