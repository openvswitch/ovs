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

#include "ovsdb.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include "column.h"
#include "command-line.h"
#include "daemon.h"
#include "file.h"
#include "json.h"
#include "jsonrpc.h"
#include "jsonrpc-server.h"
#include "leak-checker.h"
#include "list.h"
#include "ovsdb-data.h"
#include "ovsdb-types.h"
#include "ovsdb-error.h"
#include "poll-loop.h"
#include "process.h"
#include "row.h"
#include "stream-ssl.h"
#include "stream.h"
#include "svec.h"
#include "table.h"
#include "timeval.h"
#include "trigger.h"
#include "util.h"
#include "unixctl.h"

#include "vlog.h"
#define THIS_MODULE VLM_ovsdb_server

static unixctl_cb_func ovsdb_server_exit;

static void parse_options(int argc, char *argv[], char **file_namep,
                          struct shash *remotes, char **unixctl_pathp,
                          char **run_command);
static void usage(void) NO_RETURN;

static void set_remotes(struct ovsdb_jsonrpc_server *jsonrpc,
                        const struct ovsdb *db, struct shash *remotes);

int
main(int argc, char *argv[])
{
    char *unixctl_path = NULL;
    char *run_command = NULL;
    struct unixctl_server *unixctl;
    struct ovsdb_jsonrpc_server *jsonrpc;
    struct shash remotes;
    struct ovsdb_error *error;
    struct ovsdb *db;
    struct process *run_process;
    char *file_name;
    bool exiting;
    int retval;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    time_init();
    vlog_init();
    signal(SIGPIPE, SIG_IGN);
    process_init();

    parse_options(argc, argv, &file_name, &remotes, &unixctl_path,
                  &run_command);

    die_if_already_running();
    daemonize_start();

    error = ovsdb_file_open(file_name, false, &db);
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string(error));
    }

    jsonrpc = ovsdb_jsonrpc_server_create(db);
    set_remotes(jsonrpc, db, &remotes);

    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    if (run_command) {
        char *run_argv[4];

        run_argv[0] = "/bin/sh";
        run_argv[1] = "-c";
        run_argv[2] = run_command;
        run_argv[3] = NULL;

        retval = process_start(run_argv, NULL, 0, NULL, 0, &run_process);
        if (retval) {
            ovs_fatal(retval, "%s: process failed to start", run_command);
        }
    } else {
        run_process = NULL;
    }

    daemonize_complete();

    unixctl_command_register("exit", ovsdb_server_exit, &exiting);

    exiting = false;
    while (!exiting) {
        set_remotes(jsonrpc, db, &remotes);
        ovsdb_jsonrpc_server_run(jsonrpc);
        unixctl_server_run(unixctl);
        ovsdb_trigger_run(db, time_msec());
        if (run_process && process_exited(run_process)) {
            exiting = true;
        }

        ovsdb_jsonrpc_server_wait(jsonrpc);
        unixctl_server_wait(unixctl);
        ovsdb_trigger_wait(db, time_msec());
        if (run_process) {
            process_wait(run_process);
        }
        poll_block();
    }
    ovsdb_jsonrpc_server_destroy(jsonrpc);
    ovsdb_destroy(db);
    shash_destroy(&remotes);
    unixctl_server_destroy(unixctl);

    if (run_process && process_exited(run_process)) {
        int status = process_status(run_process);
        if (status) {
            ovs_fatal(0, "%s: child exited, %s",
                      run_command, process_status_msg(status));
        }
    }

    return 0;
}

static void
query_db_remotes(const char *name_, const struct ovsdb *db,
                 struct shash *remotes)
{
    char *name, *table_name, *column_name;
    const struct ovsdb_column *column;
    const struct ovsdb_table *table;
    const struct ovsdb_row *row;
    char *save_ptr = NULL;

    name = xstrdup(name_);
    strtok_r(name, ":", &save_ptr); /* "db:" */
    table_name = strtok_r(NULL, ",", &save_ptr);
    column_name = strtok_r(NULL, ",", &save_ptr);
    if (!table_name || !column_name) {
        ovs_fatal(0, "remote \"%s\": invalid syntax", name_);
    }

    table = ovsdb_get_table(db, table_name);
    if (!table) {
        ovs_fatal(0, "remote \"%s\": no table named %s", name_, table_name);
    }

    column = ovsdb_table_schema_get_column(table->schema, column_name);
    if (!column) {
        ovs_fatal(0, "remote \"%s\": table \"%s\" has no column \"%s\"",
                  name_, table_name, column_name);
    }

    if (column->type.key.type != OVSDB_TYPE_STRING
        || column->type.value.type != OVSDB_TYPE_VOID) {
        ovs_fatal(0, "remote \"%s\": type of table \"%s\" column \"%s\" is "
                  "not string or set of strings",
                  name_, table_name, column_name);
    }

    HMAP_FOR_EACH (row, struct ovsdb_row, hmap_node, &table->rows) {
        const struct ovsdb_datum *datum;
        size_t i;

        datum = &row->fields[column->index];
        for (i = 0; i < datum->n; i++) {
            shash_add_once(remotes, datum->keys[i].string, NULL);
        }
    }

    free(name);
}

static void
set_remotes(struct ovsdb_jsonrpc_server *jsonrpc,
            const struct ovsdb *db, struct shash *remotes)
{
    struct shash resolved_remotes;
    struct shash_node *node;

    shash_init(&resolved_remotes);
    SHASH_FOR_EACH (node, remotes) {
        const char *name = node->name;

        if (!strncmp(name, "db:", 3)) {
            query_db_remotes(name, db, &resolved_remotes);
        } else {
            shash_add_once(&resolved_remotes, name, NULL);
        }
    }
    ovsdb_jsonrpc_server_set_remotes(jsonrpc, &resolved_remotes);
    shash_destroy(&resolved_remotes);
}


static void
ovsdb_server_exit(struct unixctl_conn *conn, const char *args OVS_UNUSED,
                  void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, 200, NULL);
}

static void
parse_options(int argc, char *argv[], char **file_namep,
              struct shash *remotes, char **unixctl_pathp,
              char **run_command)
{
    enum {
        OPT_DUMMY = UCHAR_MAX + 1,
        OPT_REMOTE,
        OPT_UNIXCTL,
        OPT_RUN,
        OPT_BOOTSTRAP_CA_CERT,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"remote",      required_argument, 0, OPT_REMOTE},
        {"unixctl",     required_argument, 0, OPT_UNIXCTL},
        {"run",         required_argument, 0, OPT_RUN},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        {"bootstrap-ca-cert", required_argument, 0, OPT_BOOTSTRAP_CA_CERT},
        STREAM_SSL_LONG_OPTIONS
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    shash_init(remotes);
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_REMOTE:
            shash_add_once(remotes, optarg, NULL);
            break;

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        case OPT_RUN:
            *run_command = optarg;
            break;

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        LEAK_CHECKER_OPTION_HANDLERS

#ifdef HAVE_OPENSSL
        STREAM_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;
#endif


        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    if (argc > 1) {
        ovs_fatal(0, "database file is only non-option argument; "
                "use --help for usage");
    } else if (argc < 1) {
        ovs_fatal(0, "missing database file argument; use --help for usage");
    }

    *file_namep = argv[0];
}

static void
usage(void)
{
    printf("%s: Open vSwitch database server\n"
           "usage: %s [OPTIONS] DATABASE\n"
           "where DATABASE is a database file in ovsdb format.\n",
           program_name, program_name);
    printf("\nJSON-RPC options (may be specified any number of times):\n"
           "  --remote=REMOTE         connect or listen to REMOTE\n");
    stream_usage("JSON-RPC", true, true, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  --run COMMAND           run COMMAND as subprocess then exit\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    leak_checker_usage();
    exit(EXIT_SUCCESS);
}
