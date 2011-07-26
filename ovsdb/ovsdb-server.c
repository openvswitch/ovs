/* Copyright (c) 2009, 2010, 2011 Nicira Networks
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
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include "column.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "file.h"
#include "hash.h"
#include "json.h"
#include "jsonrpc.h"
#include "jsonrpc-server.h"
#include "leak-checker.h"
#include "list.h"
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-types.h"
#include "ovsdb-error.h"
#include "poll-loop.h"
#include "process.h"
#include "row.h"
#include "stream-ssl.h"
#include "stream.h"
#include "stress.h"
#include "sset.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "trigger.h"
#include "util.h"
#include "unixctl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_server);

/* SSL configuration. */
static char *private_key_file;
static char *certificate_file;
static char *ca_cert_file;
static bool bootstrap_ca_cert;

static unixctl_cb_func ovsdb_server_exit;
static unixctl_cb_func ovsdb_server_compact;
static unixctl_cb_func ovsdb_server_reconnect;

static void parse_options(int argc, char *argv[], char **file_namep,
                          struct sset *remotes, char **unixctl_pathp,
                          char **run_command);
static void usage(void) NO_RETURN;

static void reconfigure_from_db(struct ovsdb_jsonrpc_server *jsonrpc,
                                const struct ovsdb *db, struct sset *remotes);

static void update_remote_status(const struct ovsdb_jsonrpc_server *jsonrpc,
                                 const struct sset *remotes,
                                 struct ovsdb *db);

int
main(int argc, char *argv[])
{
    char *unixctl_path = NULL;
    char *run_command = NULL;
    struct unixctl_server *unixctl;
    struct ovsdb_jsonrpc_server *jsonrpc;
    struct sset remotes;
    struct ovsdb_error *error;
    struct ovsdb_file *file;
    struct ovsdb *db;
    struct process *run_process;
    char *file_name;
    bool exiting;
    int retval;
    long long int status_timer = LLONG_MIN;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    stress_init_command();
    signal(SIGPIPE, SIG_IGN);
    process_init();

    parse_options(argc, argv, &file_name, &remotes, &unixctl_path,
                  &run_command);

    daemonize_start();

    error = ovsdb_file_open(file_name, false, &db, &file);
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string(error));
    }
    free(file_name);

    jsonrpc = ovsdb_jsonrpc_server_create(db);
    reconfigure_from_db(jsonrpc, db, &remotes);

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
    unixctl_command_register("ovsdb-server/compact", ovsdb_server_compact,
                             file);
    unixctl_command_register("ovsdb-server/reconnect", ovsdb_server_reconnect,
                             jsonrpc);

    exiting = false;
    while (!exiting) {
        reconfigure_from_db(jsonrpc, db, &remotes);
        ovsdb_jsonrpc_server_run(jsonrpc);
        unixctl_server_run(unixctl);
        ovsdb_trigger_run(db, time_msec());
        if (run_process && process_exited(run_process)) {
            exiting = true;
        }

        /* update Manager status(es) every 5 seconds */
        if (time_msec() >= status_timer) {
            status_timer = time_msec() + 5000;
            update_remote_status(jsonrpc, &remotes, db);
        }

        ovsdb_jsonrpc_server_wait(jsonrpc);
        unixctl_server_wait(unixctl);
        ovsdb_trigger_wait(db, time_msec());
        if (run_process) {
            process_wait(run_process);
        }
        if (exiting) {
            poll_immediate_wake();
        }
        poll_timer_wait_until(status_timer);
        poll_block();
    }
    ovsdb_jsonrpc_server_destroy(jsonrpc);
    ovsdb_destroy(db);
    sset_destroy(&remotes);
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
parse_db_column(const struct ovsdb *db,
                const char *name_,
                const struct ovsdb_table **tablep,
                const struct ovsdb_column **columnp)
{
    char *name, *table_name, *column_name;
    const struct ovsdb_column *column;
    const struct ovsdb_table *table;
    char *save_ptr = NULL;

    name = xstrdup(name_);
    strtok_r(name, ":", &save_ptr); /* "db:" */
    table_name = strtok_r(NULL, ",", &save_ptr);
    column_name = strtok_r(NULL, ",", &save_ptr);
    if (!table_name || !column_name) {
        ovs_fatal(0, "\"%s\": invalid syntax", name_);
    }

    table = ovsdb_get_table(db, table_name);
    if (!table) {
        ovs_fatal(0, "\"%s\": no table named %s", name_, table_name);
    }

    column = ovsdb_table_schema_get_column(table->schema, column_name);
    if (!column) {
        ovs_fatal(0, "\"%s\": table \"%s\" has no column \"%s\"",
                  name_, table_name, column_name);
    }
    free(name);

    *columnp = column;
    *tablep = table;
}

static void
parse_db_string_column(const struct ovsdb *db,
                       const char *name,
                       const struct ovsdb_table **tablep,
                       const struct ovsdb_column **columnp)
{
    const struct ovsdb_column *column;
    const struct ovsdb_table *table;

    parse_db_column(db, name, &table, &column);

    if (column->type.key.type != OVSDB_TYPE_STRING
        || column->type.value.type != OVSDB_TYPE_VOID) {
        ovs_fatal(0, "\"%s\": table \"%s\" column \"%s\" is "
                  "not string or set of strings",
                  name, table->schema->name, column->name);
    }

    *columnp = column;
    *tablep = table;
}

static OVS_UNUSED const char *
query_db_string(const struct ovsdb *db, const char *name)
{
    if (!name || strncmp(name, "db:", 3)) {
        return name;
    } else {
        const struct ovsdb_column *column;
        const struct ovsdb_table *table;
        const struct ovsdb_row *row;

        parse_db_string_column(db, name, &table, &column);

        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum;
            size_t i;

            datum = &row->fields[column->index];
            for (i = 0; i < datum->n; i++) {
                if (datum->keys[i].string[0]) {
                    return datum->keys[i].string;
                }
            }
        }
        return NULL;
    }
}

static struct ovsdb_jsonrpc_options *
add_remote(struct shash *remotes, const char *target)
{
    struct ovsdb_jsonrpc_options *options;

    options = shash_find_data(remotes, target);
    if (!options) {
        options = ovsdb_jsonrpc_default_options();
        shash_add(remotes, target, options);
    }

    return options;
}

static struct ovsdb_datum *
get_datum(struct ovsdb_row *row, const char *column_name,
          const enum ovsdb_atomic_type key_type,
          const enum ovsdb_atomic_type value_type,
          const size_t n_max)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    const struct ovsdb_table_schema *schema = row->table->schema;
    const struct ovsdb_column *column;

    column = ovsdb_table_schema_get_column(schema, column_name);
    if (!column) {
        VLOG_DBG_RL(&rl, "Table `%s' has no `%s' column",
                    schema->name, column_name);
        return NULL;
    }

    if (column->type.key.type != key_type
        || column->type.value.type != value_type
        || column->type.n_max != n_max) {
        if (!VLOG_DROP_DBG(&rl)) {
            char *type_name = ovsdb_type_to_english(&column->type);
            VLOG_DBG("Table `%s' column `%s' has type %s, not expected "
                     "key type %s, value type %s, max elements %zd.",
                     schema->name, column_name, type_name,
                     ovsdb_atomic_type_to_string(key_type),
                     ovsdb_atomic_type_to_string(value_type),
                     n_max);
            free(type_name);
        }
        return NULL;
    }

    return &row->fields[column->index];
}

static const union ovsdb_atom *
read_column(const struct ovsdb_row *row, const char *column_name,
            enum ovsdb_atomic_type type)
{
    const struct ovsdb_datum *datum;

    datum = get_datum((struct ovsdb_row *) row, column_name, type, OVSDB_TYPE_VOID, 1);
    return datum && datum->n ? datum->keys : NULL;
}

static bool
read_integer_column(const struct ovsdb_row *row, const char *column_name,
                    long long int *integerp)
{
    const union ovsdb_atom *atom;

    atom = read_column(row, column_name, OVSDB_TYPE_INTEGER);
    *integerp = atom ? atom->integer : 0;
    return atom != NULL;
}

static bool
read_string_column(const struct ovsdb_row *row, const char *column_name,
                   const char **stringp)
{
    const union ovsdb_atom *atom;

    atom = read_column(row, column_name, OVSDB_TYPE_STRING);
    *stringp = atom ? atom->string : NULL;
    return atom != NULL;
}

static void
write_bool_column(struct ovsdb_row *row, const char *column_name, bool value)
{
    struct ovsdb_datum *datum = get_datum(row, column_name, OVSDB_TYPE_BOOLEAN,
                                          OVSDB_TYPE_VOID, 1);

    if (!datum) {
        return;
    }
    datum->keys[0].boolean = value;
}

static void
write_string_string_column(struct ovsdb_row *row, const char *column_name,
                           char **keys, char **values, size_t n)
{
    const struct ovsdb_column *column;
    struct ovsdb_datum *datum;
    size_t i;

    column = ovsdb_table_schema_get_column(row->table->schema, column_name);
    datum = get_datum(row, column_name, OVSDB_TYPE_STRING, OVSDB_TYPE_STRING,
                      UINT_MAX);
    if (!datum) {
        return;
    }

    /* Free existing data. */
    ovsdb_datum_destroy(datum, &column->type);

    /* Allocate space for new values. */
    datum->n = n;
    datum->keys = xmalloc(n * sizeof *datum->keys);
    datum->values = xmalloc(n * sizeof *datum->values);

    for (i = 0; i < n; ++i) {
        datum->keys[i].string = keys[i];
        datum->values[i].string = values[i];
    }

    /* Sort and check constraints. */
    ovsdb_datum_sort_assert(datum, column->type.key.type);
}

/* Adds a remote and options to 'remotes', based on the Manager table row in
 * 'row'. */
static void
add_manager_options(struct shash *remotes, const struct ovsdb_row *row)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    struct ovsdb_jsonrpc_options *options;
    long long int max_backoff, probe_interval;
    const char *target;

    if (!read_string_column(row, "target", &target) || !target) {
        VLOG_INFO_RL(&rl, "Table `%s' has missing or invalid `target' column",
                     row->table->schema->name);
        return;
    }

    options = add_remote(remotes, target);
    if (read_integer_column(row, "max_backoff", &max_backoff)) {
        options->max_backoff = max_backoff;
    }
    if (read_integer_column(row, "inactivity_probe", &probe_interval)) {
        options->probe_interval = probe_interval;
    }
}

static void
query_db_remotes(const char *name, const struct ovsdb *db,
                 struct shash *remotes)
{
    const struct ovsdb_column *column;
    const struct ovsdb_table *table;
    const struct ovsdb_row *row;

    parse_db_column(db, name, &table, &column);

    if (column->type.key.type == OVSDB_TYPE_STRING
        && column->type.value.type == OVSDB_TYPE_VOID) {
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum;
            size_t i;

            datum = &row->fields[column->index];
            for (i = 0; i < datum->n; i++) {
                add_remote(remotes, datum->keys[i].string);
            }
        }
    } else if (column->type.key.type == OVSDB_TYPE_UUID
               && column->type.key.u.uuid.refTable
               && column->type.value.type == OVSDB_TYPE_VOID) {
        const struct ovsdb_table *ref_table = column->type.key.u.uuid.refTable;
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum;
            size_t i;

            datum = &row->fields[column->index];
            for (i = 0; i < datum->n; i++) {
                const struct ovsdb_row *ref_row;

                ref_row = ovsdb_table_get_row(ref_table, &datum->keys[i].uuid);
                if (ref_row) {
                    add_manager_options(remotes, ref_row);
                }
            }
        }
    }
}

static void
update_remote_row(const struct ovsdb_row *row, struct ovsdb_txn *txn,
                  const struct ovsdb_jsonrpc_server *jsonrpc)
{
    struct ovsdb_jsonrpc_remote_status status;
    struct ovsdb_row *rw_row;
    const char *target;
    char *keys[8], *values[8];
    size_t n = 0;

    /* Get the "target" (protocol/host/port) spec. */
    if (!read_string_column(row, "target", &target)) {
        /* Bad remote spec or incorrect schema. */
        return;
    }
    rw_row = ovsdb_txn_row_modify(txn, row);
    ovsdb_jsonrpc_server_get_remote_status(jsonrpc, target, &status);

    /* Update status information columns. */
    write_bool_column(rw_row, "is_connected", status.is_connected);

    if (status.state) {
        keys[n] = xstrdup("state");
        values[n++] = xstrdup(status.state);
    }
    if (status.sec_since_connect != UINT_MAX) {
        keys[n] = xstrdup("sec_since_connect");
        values[n++] = xasprintf("%u", status.sec_since_connect);
    }
    if (status.sec_since_disconnect != UINT_MAX) {
        keys[n] = xstrdup("sec_since_disconnect");
        values[n++] = xasprintf("%u", status.sec_since_disconnect);
    }
    if (status.last_error) {
        keys[n] = xstrdup("last_error");
        values[n++] =
            xstrdup(ovs_retval_to_string(status.last_error));
    }
    if (status.locks_held && status.locks_held[0]) {
        keys[n] = xstrdup("locks_held");
        values[n++] = xstrdup(status.locks_held);
    }
    if (status.locks_waiting && status.locks_waiting[0]) {
        keys[n] = xstrdup("locks_waiting");
        values[n++] = xstrdup(status.locks_waiting);
    }
    if (status.locks_lost && status.locks_lost[0]) {
        keys[n] = xstrdup("locks_lost");
        values[n++] = xstrdup(status.locks_lost);
    }
    if (status.n_connections > 1) {
        keys[n] = xstrdup("n_connections");
        values[n++] = xasprintf("%d", status.n_connections);
    }
    write_string_string_column(rw_row, "status", keys, values, n);

    ovsdb_jsonrpc_server_free_remote_status(&status);
}

static void
update_remote_rows(const struct ovsdb *db, struct ovsdb_txn *txn,
                   const char *remote_name,
                   const struct ovsdb_jsonrpc_server *jsonrpc)
{
    const struct ovsdb_table *table, *ref_table;
    const struct ovsdb_column *column;
    const struct ovsdb_row *row;

    if (strncmp("db:", remote_name, 3)) {
        return;
    }

    parse_db_column(db, remote_name, &table, &column);

    if (column->type.key.type != OVSDB_TYPE_UUID
        || !column->type.key.u.uuid.refTable
        || column->type.value.type != OVSDB_TYPE_VOID) {
        return;
    }

    ref_table = column->type.key.u.uuid.refTable;

    HMAP_FOR_EACH (row, hmap_node, &table->rows) {
        const struct ovsdb_datum *datum;
        size_t i;

        datum = &row->fields[column->index];
        for (i = 0; i < datum->n; i++) {
            const struct ovsdb_row *ref_row;

            ref_row = ovsdb_table_get_row(ref_table, &datum->keys[i].uuid);
            if (ref_row) {
                update_remote_row(ref_row, txn, jsonrpc);
            }
        }
    }
}

static void
update_remote_status(const struct ovsdb_jsonrpc_server *jsonrpc,
                     const struct sset *remotes, struct ovsdb *db)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    struct ovsdb_txn *txn;
    const bool durable_txn = false;
    struct ovsdb_error *error;
    const char *remote;

    txn = ovsdb_txn_create(db);

    /* Iterate over --remote arguments given on command line. */
    SSET_FOR_EACH (remote, remotes) {
        update_remote_rows(db, txn, remote, jsonrpc);
    }

    error = ovsdb_txn_commit(txn, durable_txn);
    if (error) {
        VLOG_ERR_RL(&rl, "Failed to update remote status: %s",
                    ovsdb_error_to_string(error));
    }
}

/* Reconfigures ovsdb-server based on information in the database. */
static void
reconfigure_from_db(struct ovsdb_jsonrpc_server *jsonrpc,
                    const struct ovsdb *db, struct sset *remotes)
{
    struct shash resolved_remotes;
    const char *name;

    /* Configure remotes. */
    shash_init(&resolved_remotes);
    SSET_FOR_EACH (name, remotes) {
        if (!strncmp(name, "db:", 3)) {
            query_db_remotes(name, db, &resolved_remotes);
        } else {
            add_remote(&resolved_remotes, name);
        }
    }
    ovsdb_jsonrpc_server_set_remotes(jsonrpc, &resolved_remotes);
    shash_destroy_free_data(&resolved_remotes);

    /* Configure SSL. */
    stream_ssl_set_key_and_cert(query_db_string(db, private_key_file),
                                query_db_string(db, certificate_file));
    stream_ssl_set_ca_cert_file(query_db_string(db, ca_cert_file),
                                bootstrap_ca_cert);
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
ovsdb_server_compact(struct unixctl_conn *conn, const char *args OVS_UNUSED,
                     void *file_)
{
    struct ovsdb_file *file = file_;
    struct ovsdb_error *error;

    VLOG_INFO("compacting database by user request");
    error = ovsdb_file_compact(file);
    if (!error) {
        unixctl_command_reply(conn, 200, NULL);
    } else {
        char *s = ovsdb_error_to_string(error);
        ovsdb_error_destroy(error);
        unixctl_command_reply(conn, 503, s);
        free(s);
    }
}

/* "ovsdb-server/reconnect": makes ovsdb-server drop all of its JSON-RPC
 * connections and reconnect. */
static void
ovsdb_server_reconnect(struct unixctl_conn *conn, const char *args OVS_UNUSED,
                       void *jsonrpc_)
{
    struct ovsdb_jsonrpc_server *jsonrpc = jsonrpc_;

    ovsdb_jsonrpc_server_reconnect(jsonrpc);
    unixctl_command_reply(conn, 200, NULL);
}

static void
parse_options(int argc, char *argv[], char **file_namep,
              struct sset *remotes, char **unixctl_pathp,
              char **run_command)
{
    enum {
        OPT_DUMMY = UCHAR_MAX + 1,
        OPT_REMOTE,
        OPT_UNIXCTL,
        OPT_RUN,
        OPT_BOOTSTRAP_CA_CERT,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"remote",      required_argument, NULL, OPT_REMOTE},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        {"run",         required_argument, NULL, OPT_RUN},
        {"help",        no_argument, NULL, 'h'},
        {"version",     no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {"private-key", required_argument, NULL, 'p'},
        {"certificate", required_argument, NULL, 'c'},
        {"ca-cert",     required_argument, NULL, 'C'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    sset_init(remotes);
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_REMOTE:
            sset_add(remotes, optarg);
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

        case 'p':
            private_key_file = optarg;
            break;

        case 'c':
            certificate_file = optarg;
            break;

        case 'C':
            ca_cert_file = optarg;
            bootstrap_ca_cert = false;
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            ca_cert_file = optarg;
            bootstrap_ca_cert = true;
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {
    case 0:
        *file_namep = xasprintf("%s/openvswitch/conf.db", ovs_sysconfdir());
        break;

    case 1:
        *file_namep = xstrdup(argv[0]);
        break;

    default:
        ovs_fatal(0, "database file is only non-option argument; "
                "use --help for usage");
    }
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
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    leak_checker_usage();
    exit(EXIT_SUCCESS);
}
