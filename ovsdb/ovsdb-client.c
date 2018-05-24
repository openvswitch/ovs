/*
 * Copyright (c) 2009-2017 Nicira, Inc.
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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "command-line.h"
#include "column.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "file.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "lib/table.h"
#include "log.h"
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-session.h"
#include "openvswitch/poll-loop.h"
#include "row.h"
#include "sort.h"
#include "svec.h"
#include "storage.h"
#include "stream.h"
#include "stream-ssl.h"
#include "table.h"
#include "transaction.h"
#include "monitor.h"
#include "condition.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_client);

enum args_needed {
    NEED_NONE,            /* No JSON-RPC connection or database name needed. */
    NEED_RPC,             /* JSON-RPC connection needed. */
    NEED_DATABASE         /* JSON-RPC connection and database name needed. */
};

struct ovsdb_client_command {
    const char *name;
    enum args_needed need;
    int min_args;
    int max_args;
    void (*handler)(struct jsonrpc *rpc, const char *database,
                    int argc, char *argv[]);
};

/* --timestamp: Print a timestamp before each update on "monitor" command? */
static bool timestamp;

/* --db-change-aware, --no-db-change-aware: Enable db_change_aware feature for
 * "monitor" command?
 *
 * -1 (default): Use db_change_aware if available.
 * 0: Disable db_change_aware.
 * 1: Require db_change_aware.
 *
 * (This option is undocumented because anything other than the default is
 * expected to be useful only for testing that the db_change_aware feature
 * actually works.) */
static int db_change_aware = -1;

/* --force: Ignore schema differences for "restore" command? */
static bool force;

/* --leader-only, --no-leader-only: Only accept the leader in a cluster. */
static bool leader_only = true;

/* Format for table output. */
static struct table_style table_style = TABLE_STYLE_DEFAULT;

static const struct ovsdb_client_command *get_all_commands(void);

static struct json *parse_json(const char *);

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);
static struct jsonrpc *open_jsonrpc(const char *server);
static void fetch_dbs(struct jsonrpc *, struct svec *dbs);
static bool should_stay_connected(const char *server, const char *database,
                                  const struct uuid *cid,
                                  const struct jsonrpc_msg *reply);
struct jsonrpc_msg *create_database_info_request(const char *database);

static char *
default_remote(void)
{
    return xasprintf("unix:%s/db.sock", ovs_rundir());
}

static int
open_rpc(int min_args, enum args_needed need,
         int argc, char *argv[], struct jsonrpc **rpcp, char **databasep)
{
    struct svec remotes = SVEC_EMPTY_INITIALIZER;
    struct uuid cid = UUID_ZERO;

    /* First figure out the remote(s).  If the first command-line argument has
     * the form of a remote, use it, otherwise use the default. */
    int argidx = 0;
    if (argc > min_args && (isalpha((unsigned char) argv[0][0])
                            && strchr(argv[0], ':'))) {
        ovsdb_session_parse_remote(argv[argidx++], &remotes, &cid);
    } else {
        svec_add_nocopy(&remotes, default_remote());
    }

    /* Handle the case where there's one remote.  In this case, if we need a
     * database name, we try to figure out a default if none was specified
     * explicitly. */
    char *database = *databasep;
    if (remotes.n == 1) {
        struct jsonrpc *rpc = open_jsonrpc(remotes.names[0]);
        svec_destroy(&remotes);

        if (need == NEED_DATABASE && !database) {
            struct svec dbs;

            svec_init(&dbs);
            fetch_dbs(rpc, &dbs);
            if (argc - argidx > min_args
                && svec_contains(&dbs, argv[argidx])) {
                database = xstrdup(argv[argidx++]);
            } else if (svec_contains(&dbs, "Open_vSwitch")) {
                database = xstrdup("Open_vSwitch");
            } else {
                size_t n = 0;
                const char *best = NULL;
                for (size_t i = 0; i < dbs.n; i++) {
                    if (dbs.names[i][0] != '_') {
                        best = dbs.names[i];
                        n++;
                    }
                }
                if (n != 1) {
                    jsonrpc_close(rpc);
                    ovs_fatal(0, "could not find a default database, "
                              "please specify a database name");
                }
                database = xstrdup(best);
            }
            svec_destroy(&dbs);
        }
        *rpcp = rpc;
        *databasep = database;

        return argidx;
    }

    /* If there's more than one remote, and we need a database name, then it
     * must be specified explicitly.  It's too likely to cause surprising
     * behavior if we try to pick a default across several servers. */
    if (!database && need == NEED_DATABASE) {
        if (argc - argidx > min_args) {
            database = xstrdup(argv[argidx++]);
        } else {
            ovs_fatal(0, "database name is required with multiple remotes");
        }
    }

    /* We have multiple remotes.  Connect to them in a random order and choose
     * the first one that is up and hosts the database we want (if any) in an
     * acceptable state. */
    struct jsonrpc_session *js = jsonrpc_session_open_multiple(
        &remotes, false);
    svec_destroy(&remotes);

    unsigned int seqno = 0;
    struct json *id = NULL;
    for (;;) {
        jsonrpc_session_run(js);
        if (!jsonrpc_session_is_alive(js)) {
            ovs_fatal(0, "no servers were available");
        }

        if (seqno != jsonrpc_session_get_seqno(js)
            && jsonrpc_session_is_connected(js)) {
            if (!database) {
                break;
            }

            seqno = jsonrpc_session_get_seqno(js);
            struct jsonrpc_msg *txn = create_database_info_request(database);
            json_destroy(id);
            id = json_clone(txn->id);
            jsonrpc_session_send(js, txn);
        }

        struct jsonrpc_msg *reply = jsonrpc_session_recv(js);
        if (reply && id && reply->id && json_equal(id, reply->id)) {
            if (reply->type == JSONRPC_REPLY
                && should_stay_connected(jsonrpc_session_get_name(js),
                                         database, &cid, reply)) {
                jsonrpc_msg_destroy(reply);
                break;
            }
            jsonrpc_session_force_reconnect(js);
        }
        jsonrpc_msg_destroy(reply);

        jsonrpc_session_recv_wait(js);
        jsonrpc_session_wait(js);
        poll_block();
    }
    json_destroy(id);

    *rpcp = jsonrpc_session_steal(js);
    *databasep = database;
    return argidx;
}

int
main(int argc, char *argv[])
{
    const struct ovsdb_client_command *command;
    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemon_become_new_user(false);
    if (optind >= argc) {
        ovs_fatal(0, "missing command name; use --help for help");
    }

    for (command = get_all_commands(); ; command++) {
        if (!command->name) {
            VLOG_FATAL("unknown command '%s'; use --help for help",
                       argv[optind]);
        } else if (!strcmp(command->name, argv[optind])) {
            break;
        }
    }
    optind++;

    char *database = NULL;
    struct jsonrpc *rpc = NULL;
    if (command->need != NEED_NONE) {
        optind += open_rpc(command->min_args, command->need,
                           argc - optind, argv + optind, &rpc, &database);
    }


    if (argc - optind < command->min_args ||
        argc - optind > command->max_args) {
        free(database);
        VLOG_FATAL("invalid syntax for '%s' (use --help for help)",
                    command->name);
    }

    command->handler(rpc, database, argc - optind, argv + optind);

    free(database);
    jsonrpc_close(rpc);

    if (ferror(stdout)) {
        VLOG_FATAL("write to stdout failed");
    }
    if (ferror(stderr)) {
        VLOG_FATAL("write to stderr failed");
    }

    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_BOOTSTRAP_CA_CERT = UCHAR_MAX + 1,
        OPT_TIMESTAMP,
        OPT_FORCE,
        OPT_LEADER_ONLY,
        OPT_NO_LEADER_ONLY,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        TABLE_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {"timestamp", no_argument, NULL, OPT_TIMESTAMP},
        {"force", no_argument, NULL, OPT_FORCE},
        {"timeout", required_argument, NULL, 't'},
        {"db-change-aware", no_argument, &db_change_aware, 1},
        {"no-db-change-aware", no_argument, &db_change_aware, 0},
        {"leader-only", no_argument, NULL, OPT_LEADER_ONLY},
        {"no-leader-only", no_argument, NULL, OPT_NO_LEADER_ONLY},
        VLOG_LONG_OPTIONS,
        DAEMON_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        STREAM_SSL_LONG_OPTIONS,
#endif
        TABLE_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    table_style.format = TF_TABLE;

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)
        STREAM_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case OPT_TIMESTAMP:
            timestamp = true;
            break;

        case OPT_FORCE:
            force = true;
            break;

        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ovs_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            break;

        case OPT_LEADER_ONLY:
            leader_only = true;
            break;

        case OPT_NO_LEADER_ONLY:
            leader_only = false;
            break;

        case '?':
            exit(EXIT_FAILURE);

        case 0:
            /* getopt_long() already set the value for us. */
            break;

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: Open vSwitch database JSON-RPC client\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "\nValid commands are:\n"
           "\n  list-dbs [SERVER]\n"
           "    list databases available on SERVER\n"
           "\n  get-schema [SERVER] [DATABASE]\n"
           "    retrieve schema for DATABASE from SERVER\n"
           "\n  get-schema-version [SERVER] [DATABASE]\n"
           "    retrieve schema for DATABASE from SERVER and report only its\n"
           "    version number on stdout\n"
           "\n  get-schema-cksum [SERVER] [DATABASE]\n"
           "    retrieve schema for DATABASE from SERVER and report only its\n"
           "    checksum on stdout\n"
           "\n  list-tables [SERVER] [DATABASE]\n"
           "    list tables for DATABASE on SERVER\n"
           "\n  list-columns [SERVER] [DATABASE] [TABLE]\n"
           "    list columns in TABLE (or all tables) in DATABASE on SERVER\n"
           "\n  transact [SERVER] TRANSACTION\n"
           "    run TRANSACTION (params for \"transact\" request) on SERVER\n"
           "    and print the results as JSON on stdout\n"
           "\n  query [SERVER] TRANSACTION\n"
           "    run TRANSACTION (params for \"transact\" request) on SERVER,\n"
           "    as read-only, and print the results as JSON on stdout\n"
           "\n  monitor [SERVER] [DATABASE] TABLE [COLUMN,...]...\n"
           "    monitor contents of COLUMNs in TABLE in DATABASE on SERVER.\n"
           "    COLUMNs may include !initial, !insert, !delete, !modify\n"
           "    to avoid seeing the specified kinds of changes.\n"
           "\n  monitor-cond [SERVER] [DATABASE] CONDITION TABLE [COLUMN,...]...\n"
           "    monitor contents that match CONDITION of COLUMNs in TABLE in\n"
           "    DATABASE on SERVER.\n"
           "    COLUMNs may include !initial, !insert, !delete, !modify\n"
           "    to avoid seeing the specified kinds of changes.\n"
           "\n  convert [SERVER] SCHEMA\n"
           "    convert database on SERVER named in SCHEMA to SCHEMA.\n"
           "\n  needs-conversion [SERVER] SCHEMA\n"
           "    tests whether SCHEMA's db on SERVER needs conversion.\n"
           "\n  monitor [SERVER] [DATABASE] ALL\n"
           "    monitor all changes to all columns in all tables\n"
           "\n  wait [SERVER] DATABASE STATE\n"
           "    wait until DATABASE reaches STATE "
           "(\"added\" or \"connected\" or \"removed\")\n"
           "    in DATBASE on SERVER.\n"
           "\n  dump [SERVER] [DATABASE]\n"
           "    dump contents of DATABASE on SERVER to stdout\n"
           "\n  backup [SERVER] [DATABASE] > SNAPSHOT\n"
           "    dump database contents in the form of a database file\n"
           "\n  [--force] restore [SERVER] [DATABASE] < SNAPSHOT\n"
           "    restore database contents from a database file\n"
           "\n  lock [SERVER] LOCK\n"
           "    create or wait for LOCK in SERVER\n"
           "\n  steal [SERVER] LOCK\n"
           "    steal LOCK from SERVER\n"
           "\n  unlock [SERVER] LOCK\n"
           "    unlock LOCK from SERVER\n"
           "\nThe default SERVER is unix:%s/db.sock.\n"
           "The default DATABASE is Open_vSwitch.\n",
           program_name, program_name, ovs_rundir());
    stream_usage("SERVER", true, true, true);
    table_usage();
    printf("  --timestamp                 timestamp \"monitor\" output");
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static void
check_txn(int error, struct jsonrpc_msg **reply_)
{
    struct jsonrpc_msg *reply = *reply_;

    if (error) {
        ovs_fatal(error, "transaction failed");
    }

    if (reply->error) {
        ovs_fatal(error, "transaction returned error: %s",
                  json_to_string(reply->error, table_style.json_flags));
    }
}

static struct json *
parse_json(const char *s)
{
    struct json *json = json_from_string(s);
    if (json->type == JSON_STRING) {
        ovs_fatal(0, "\"%s\": %s", s, json->string);
    }
    return json;
}

static struct jsonrpc *
open_jsonrpc(const char *server)
{
    struct stream *stream;
    int error;

    error = stream_open_block(jsonrpc_stream_open(server, &stream,
                              DSCP_DEFAULT), &stream);
    if (error == EAFNOSUPPORT) {
        struct pstream *pstream;

        error = jsonrpc_pstream_open(server, &pstream, DSCP_DEFAULT);
        if (error) {
            ovs_fatal(error, "failed to connect or listen to \"%s\"", server);
        }

        VLOG_INFO("%s: waiting for connection...", server);
        error = pstream_accept_block(pstream, &stream);
        if (error) {
            ovs_fatal(error, "failed to accept connection on \"%s\"", server);
        }

        pstream_close(pstream);
    } else if (error) {
        ovs_fatal(error, "failed to connect to \"%s\"", server);
    }

    return jsonrpc_open(stream);
}

static void
print_json(struct json *json)
{
    char *string = json_to_string(json, table_style.json_flags);
    puts(string);
    free(string);
}

static void
print_and_free_json(struct json *json)
{
    print_json(json);
    json_destroy(json);
}

static void
check_ovsdb_error(struct ovsdb_error *error)
{
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string(error));
    }
}

static struct ovsdb_schema *
fetch_schema(struct jsonrpc *rpc, const char *database)
{
    struct jsonrpc_msg *request, *reply;
    struct ovsdb_schema *schema;

    request = jsonrpc_create_request("get_schema",
                                     json_array_create_1(
                                         json_string_create(database)),
                                     NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    check_ovsdb_error(ovsdb_schema_from_json(reply->result, &schema));
    jsonrpc_msg_destroy(reply);

    return schema;
}

static void
fetch_dbs(struct jsonrpc *rpc, struct svec *dbs)
{
    struct jsonrpc_msg *request, *reply;
    size_t i;

    request = jsonrpc_create_request("list_dbs", json_array_create_empty(),
                                     NULL);

    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    if (reply->result->type != JSON_ARRAY) {
        ovs_fatal(0, "list_dbs response is not array");
    }

    for (i = 0; i < reply->result->array.n; i++) {
        const struct json *name = reply->result->array.elems[i];

        if (name->type != JSON_STRING) {
            ovs_fatal(0, "list_dbs response %"PRIuSIZE" is not string", i);
        }
        svec_add(dbs, name->string);
    }
    jsonrpc_msg_destroy(reply);
    svec_sort(dbs);
}

static const char *
parse_string_column(const struct json *row, const char *column_name)
{
    const struct json *column = shash_find_data(json_object(row), column_name);
    return column && column->type == JSON_STRING ? json_string(column) : "";
}

static int
parse_boolean_column(const struct json *row, const char *column_name)
{
    const struct json *column = shash_find_data(json_object(row), column_name);
    return (!column ? -1
            : column->type == JSON_TRUE ? true
            : column->type == JSON_FALSE ? false
            : -1);
}

static struct uuid
parse_uuid_column(const struct json *row, const char *column_name)
{
    const struct json *column = shash_find_data(json_object(row), column_name);
    if (!column) {
        return UUID_ZERO;
    }

    struct ovsdb_type type = { OVSDB_BASE_UUID_INIT, OVSDB_BASE_VOID_INIT,
                               0, 1 };
    struct ovsdb_datum datum;
    struct ovsdb_error *error = ovsdb_datum_from_json(&datum, &type, column,
                                                      NULL);
    if (error) {
        ovsdb_error_destroy(error);
        return UUID_ZERO;
    }
    struct uuid uuid = datum.n > 0 ? datum.keys[0].uuid : UUID_ZERO;
    ovsdb_datum_destroy(&datum, &type);
    return uuid;
}

struct jsonrpc_msg *
create_database_info_request(const char *database)
{
    struct json *op = json_object_create();
    json_object_put_string(op, "op", "select");
    json_object_put_string(op, "table", "Database");
    struct json *condition = json_array_create_3(
        json_string_create("name"),
        json_string_create("=="),
        json_string_create(database));
    json_object_put(op, "where", json_array_create_1(condition));
    struct json *txn = json_array_create_2(
        json_string_create("_Server"), op);
    return jsonrpc_create_request("transact", txn, NULL);
}

static const struct json *
parse_database_info_reply(const struct jsonrpc_msg *reply, const char *server,
                          const char *database, const struct uuid *cid)
{
    const struct json *result = reply->result;
    if (result->type != JSON_ARRAY
        || result->array.n != 1
        || result->array.elems[0]->type != JSON_OBJECT) {
        VLOG_WARN("%s: unexpected reply to _Server request for %s",
                  server, database);
        return NULL;
    }

    const struct json *op_result = result->array.elems[0];
    const struct json *rows = shash_find_data(json_object(op_result), "rows");
    if (!rows || rows->type != JSON_ARRAY) {
        VLOG_WARN("%s: missing \"rows\" member in  _Server reply for %s",
                  server, database);
        return NULL;
    }

    for (size_t i = 0; i < rows->array.n; i++) {
        const struct json *row = rows->array.elems[i];
        if (row->type != JSON_OBJECT) {
            VLOG_WARN("%s: bad row in  _Server reply for %s",
                      server, database);
            continue;
        }

        if (strcmp(parse_string_column(row, "name"), database)) {
            continue;
        }

        if (cid && !uuid_is_zero(cid)) {
            struct uuid cid2 = parse_uuid_column(row, "cid");
            if (!uuid_equals(cid, &cid2)) {
                continue;
            }
        }

        return row;
    }

    /* No such database. */
    return NULL;
}

/* Parses 'reply', a JSON-RPC reply to our request asking for the status of
 * 'database' on 'server'.  Determines whether this server is acceptable for
 * the transaction we want to make and returns true if so or false to
 * disconnect and try a different server. */
static bool
should_stay_connected(const char *server, const char *database,
                      const struct uuid *cid, const struct jsonrpc_msg *reply)
{
    const struct json *row = parse_database_info_reply(reply, server,
                                                       database, cid);
    if (!row) {
        /* No such database. */
        return false;
    }

    if (strcmp(parse_string_column(row, "model"), "clustered")) {
        /* Always accept standalone databases. */
        return true;
    }

    if (!parse_boolean_column(row, "connected")) {
        /* Reject disconnected servers. */
        return false;
    }

    if (leader_only && !parse_boolean_column(row, "leader")) {
        /* Reject if not leader.. */
        return false;
    }

    return true;
}

static void
do_list_dbs(struct jsonrpc *rpc, const char *database OVS_UNUSED,
            int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    const char *db_name;
    struct svec dbs;
    size_t i;

    svec_init(&dbs);
    fetch_dbs(rpc, &dbs);
    SVEC_FOR_EACH (i, db_name, &dbs) {
        puts(db_name);
    }
    svec_destroy(&dbs);
}

static void
do_get_schema(struct jsonrpc *rpc, const char *database,
              int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ovsdb_schema *schema = fetch_schema(rpc, database);
    print_and_free_json(ovsdb_schema_to_json(schema));
    ovsdb_schema_destroy(schema);
}

static void
do_get_schema_version(struct jsonrpc *rpc, const char *database,
                      int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ovsdb_schema *schema = fetch_schema(rpc, database);
    puts(schema->version);
    ovsdb_schema_destroy(schema);
}

static void
do_get_schema_cksum(struct jsonrpc *rpc, const char *database,
                      int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ovsdb_schema *schema = fetch_schema(rpc, database);
    puts(schema->cksum);
    ovsdb_schema_destroy(schema);
}

static void
do_list_tables(struct jsonrpc *rpc, const char *database,
               int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ovsdb_schema *schema;
    struct shash_node *node;
    struct table t;

    schema = fetch_schema(rpc, database);
    table_init(&t);
    table_add_column(&t, "Table");
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *ts = node->data;

        table_add_row(&t);
        table_add_cell(&t)->text = xstrdup(ts->name);
    }
    ovsdb_schema_destroy(schema);
    table_print(&t, &table_style);
    table_destroy(&t);
}

static void
do_list_columns(struct jsonrpc *rpc, const char *database,
                int argc OVS_UNUSED, char *argv[])
{
    const char *table_name = argv[0];
    struct ovsdb_schema *schema;
    struct shash_node *table_node;
    struct table t;

    schema = fetch_schema(rpc, database);
    table_init(&t);
    if (!table_name) {
        table_add_column(&t, "Table");
    }
    table_add_column(&t, "Column");
    table_add_column(&t, "Type");
    SHASH_FOR_EACH (table_node, &schema->tables) {
        struct ovsdb_table_schema *ts = table_node->data;

        if (!table_name || !strcmp(table_name, ts->name)) {
            struct shash_node *column_node;

            SHASH_FOR_EACH (column_node, &ts->columns) {
                const struct ovsdb_column *column = column_node->data;

                table_add_row(&t);
                if (!table_name) {
                    table_add_cell(&t)->text = xstrdup(ts->name);
                }
                table_add_cell(&t)->text = xstrdup(column->name);
                table_add_cell(&t)->json = ovsdb_type_to_json(&column->type);
            }
        }
    }
    ovsdb_schema_destroy(schema);
    table_print(&t, &table_style);
    table_destroy(&t);
}

static void
send_db_change_aware(struct jsonrpc *rpc)
{
    if (db_change_aware != 0) {
        struct jsonrpc_msg *request = jsonrpc_create_request(
            "set_db_change_aware",
            json_array_create_1(json_boolean_create(true)),
            NULL);
        struct jsonrpc_msg *reply;
        int error = jsonrpc_transact_block(rpc, request, &reply);
        if (error) {
            ovs_fatal(error, "%s: error setting db_change_aware",
                      jsonrpc_get_name(rpc));
        }
        if (reply->type == JSONRPC_ERROR && db_change_aware == 1) {
            ovs_fatal(0, "%s: set_db_change_aware failed (%s)",
                      jsonrpc_get_name(rpc), json_to_string(reply->error, 0));
        }
        jsonrpc_msg_destroy(reply);
    }
}

static struct json *
do_transact__(int argc, char *argv[], struct json *transaction)
{
    struct jsonrpc_msg *request, *reply;
    if (transaction->type != JSON_ARRAY
        || !transaction->array.n
        || transaction->array.elems[0]->type != JSON_STRING) {
        ovs_fatal(0, "not a valid OVSDB query");
    }
    const char *db_name = json_string(transaction->array.elems[0]);

    struct jsonrpc *rpc;
    char *database = CONST_CAST(char *, db_name);
    open_rpc(1, NEED_DATABASE, argc, argv, &rpc, &database);

    if (db_change_aware == 1) {
        send_db_change_aware(rpc);
    }
    daemon_save_fd(STDOUT_FILENO);
    daemon_save_fd(STDERR_FILENO);
    daemonize();

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    struct json *result = json_clone(reply->result);
    jsonrpc_msg_destroy(reply);
    jsonrpc_close(rpc);

    return result;
}

static void
do_transact(struct jsonrpc *rpc OVS_UNUSED, const char *database OVS_UNUSED,
            int argc, char *argv[])
{
    print_and_free_json(do_transact__(argc, argv, parse_json(argv[argc - 1])));
}

static void
do_query(struct jsonrpc *rpc OVS_UNUSED, const char *database OVS_UNUSED,
         int argc, char *argv[])
{
    struct json *transaction = parse_json(argv[argc - 1]);

    if (transaction->type != JSON_ARRAY) {
        ovs_fatal(0, "not a valid OVSDB query");
    }

    /* Append an "abort" operation to the query. */
    struct json *abort_op = json_object_create();
    json_object_put_string(abort_op, "op", "abort");
    json_array_add(transaction, abort_op);
    size_t abort_idx = transaction->array.n - 2;

    /* Run query. */
    struct json *result = do_transact__(argc, argv, transaction);

    /* If the "abort" operation ended the transaction, remove its result. */
    if (result->type == JSON_ARRAY
        && result->array.n == abort_idx + 1
        && result->array.elems[abort_idx]->type == JSON_OBJECT) {
        struct json *op_result = result->array.elems[abort_idx];
        struct json *error = shash_find_data(json_object(op_result), "error");
        if (error
            && error->type == JSON_STRING
            && !strcmp(json_string(error), "aborted")) {
            result->array.n--;
            json_destroy(op_result);
        }
    }

    /* Print the result. */
    print_and_free_json(result);
}

/* "monitor" command. */

struct monitored_table {
    struct ovsdb_table_schema *table;
    struct ovsdb_column_set columns;
};

static void
monitor_print_row(struct json *row, const char *type, const char *uuid,
                  const struct ovsdb_column_set *columns, struct table *t)
{
    size_t i;

    if (!row) {
        ovs_error(0, "missing %s row", type);
        return;
    } else if (row->type != JSON_OBJECT) {
        ovs_error(0, "<row> is not object");
        return;
    }

    table_add_row(t);
    table_add_cell(t)->text = xstrdup(uuid);
    table_add_cell(t)->text = xstrdup(type);
    for (i = 0; i < columns->n_columns; i++) {
        const struct ovsdb_column *column = columns->columns[i];
        struct json *value = shash_find_data(json_object(row), column->name);
        struct cell *cell = table_add_cell(t);
        if (value) {
            cell->json = json_clone(value);
            cell->type = &column->type;
        }
    }
}

static void
monitor_print_table(struct json *table_update,
                    const struct monitored_table *mt, char *caption,
                    bool initial)
{
    const struct ovsdb_table_schema *table = mt->table;
    const struct ovsdb_column_set *columns = &mt->columns;
    struct shash_node *node;
    struct table t;
    size_t i;

    if (table_update->type != JSON_OBJECT) {
        ovs_error(0, "<table-update> for table %s is not object", table->name);
        return;
    }

    table_init(&t);
    table_set_timestamp(&t, timestamp);
    table_set_caption(&t, caption);

    table_add_column(&t, "row");
    table_add_column(&t, "action");
    for (i = 0; i < columns->n_columns; i++) {
        table_add_column(&t, "%s", columns->columns[i]->name);
    }
    SHASH_FOR_EACH (node, json_object(table_update)) {
        struct json *row_update = node->data;
        struct json *old, *new;

        if (row_update->type != JSON_OBJECT) {
            ovs_error(0, "<row-update> is not object");
            continue;
        }
        old = shash_find_data(json_object(row_update), "old");
        new = shash_find_data(json_object(row_update), "new");
        if (initial) {
            monitor_print_row(new, "initial", node->name, columns, &t);
        } else if (!old) {
            monitor_print_row(new, "insert", node->name, columns, &t);
        } else if (!new) {
            monitor_print_row(old, "delete", node->name, columns, &t);
        } else {
            monitor_print_row(old, "old", node->name, columns, &t);
            monitor_print_row(new, "new", "", columns, &t);
        }
    }
    table_print(&t, &table_style);
    table_destroy(&t);
}

static void
monitor_print(struct json *table_updates,
              const struct monitored_table *mts, size_t n_mts,
              bool initial)
{
    size_t i;

    if (table_updates->type != JSON_OBJECT) {
        ovs_error(0, "<table-updates> is not object");
        return;
    }

    for (i = 0; i < n_mts; i++) {
        const struct monitored_table *mt = &mts[i];
        struct json *table_update = shash_find_data(json_object(table_updates),
                                                    mt->table->name);
        if (table_update) {
            monitor_print_table(table_update, mt,
                                n_mts > 1 ? xstrdup(mt->table->name) : NULL,
                                initial);
        }
    }
}

static void
monitor2_print_row(struct json *row, const char *type, const char *uuid,
                   const struct ovsdb_column_set *columns, struct table *t)
{
    if (!strcmp(type, "delete")) {
        if (row->type != JSON_NULL) {
            ovs_error(0, "delete method does not expect <row>");
            return;
        }

        table_add_row(t);
        table_add_cell(t)->text = xstrdup(uuid);
        table_add_cell(t)->text = xstrdup(type);
    } else {
        if (!row || row->type != JSON_OBJECT) {
            ovs_error(0, "<row> is not object");
            return;
        }
        monitor_print_row(row, type, uuid, columns, t);
    }
}

static void
monitor2_print_table(struct json *table_update2,
                    const struct monitored_table *mt, char *caption)
{
    const struct ovsdb_table_schema *table = mt->table;
    const struct ovsdb_column_set *columns = &mt->columns;
    struct shash_node *node;
    struct table t;

    if (table_update2->type != JSON_OBJECT) {
        ovs_error(0, "<table-update> for table %s is not object", table->name);
        return;
    }

    table_init(&t);
    table_set_timestamp(&t, timestamp);
    table_set_caption(&t, caption);

    table_add_column(&t, "row");
    table_add_column(&t, "action");
    for (size_t i = 0; i < columns->n_columns; i++) {
        table_add_column(&t, "%s", columns->columns[i]->name);
    }
    SHASH_FOR_EACH (node, json_object(table_update2)) {
        struct json *row_update2 = node->data;
        const char *operation;
        struct json *row;
        const char *ops[] = {"delete", "initial", "modify", "insert"};

        if (row_update2->type != JSON_OBJECT) {
            ovs_error(0, "<row-update2> is not object");
            continue;
        }

        /* row_update2 contains one of objects indexed by ops[] */
        for (int i = 0; i < ARRAY_SIZE(ops); i++) {
            operation = ops[i];
            row = shash_find_data(json_object(row_update2), operation);

            if (row) {
                monitor2_print_row(row, operation, node->name, columns, &t);
                break;
            }
        }
    }
    table_print(&t, &table_style);
    table_destroy(&t);
}

static void
monitor2_print(struct json *table_updates2,
               const struct monitored_table *mts, size_t n_mts)
{
    size_t i;

    if (table_updates2->type != JSON_OBJECT) {
        ovs_error(0, "<table-updates2> is not object");
        return;
    }

    for (i = 0; i < n_mts; i++) {
        const struct monitored_table *mt = &mts[i];
        struct json *table_update = shash_find_data(
                                        json_object(table_updates2),
                                        mt->table->name);
        if (table_update) {
            monitor2_print_table(table_update, mt,
                                n_mts > 1 ? xstrdup(mt->table->name) : NULL);
        }
    }
}

static void
add_column(const char *server, const struct ovsdb_column *column,
           struct ovsdb_column_set *columns, struct json *columns_json)
{
    if (ovsdb_column_set_contains(columns, column->index)) {
        ovs_fatal(0, "%s: column \"%s\" mentioned multiple times",
                  server, column->name);
    }
    ovsdb_column_set_add(columns, column);
    json_array_add(columns_json, json_string_create(column->name));
}

static struct json *
parse_monitor_columns(char *arg, const char *server, const char *database,
                      const struct ovsdb_table_schema *table,
                      struct ovsdb_column_set *columns)
{
    bool initial, insert, delete, modify;
    struct json *mr, *columns_json;
    char *save_ptr = NULL;
    char *token;

    mr = json_object_create();
    columns_json = json_array_create_empty();
    json_object_put(mr, "columns", columns_json);

    initial = insert = delete = modify = true;
    for (token = strtok_r(arg, ",", &save_ptr); token != NULL;
         token = strtok_r(NULL, ",", &save_ptr)) {
        if (!strcmp(token, "!initial")) {
            initial = false;
        } else if (!strcmp(token, "!insert")) {
            insert = false;
        } else if (!strcmp(token, "!delete")) {
            delete = false;
        } else if (!strcmp(token, "!modify")) {
            modify = false;
        } else {
            const struct ovsdb_column *column;

            column = ovsdb_table_schema_get_column(table, token);
            if (!column) {
                ovs_fatal(0, "%s: table \"%s\" in %s does not have a "
                          "column named \"%s\"",
                          server, table->name, database, token);
            }
            add_column(server, column, columns, columns_json);
        }
    }

    if (columns_json->array.n == 0) {
        const struct shash_node **nodes;
        size_t i, n;

        n = shash_count(&table->columns);
        nodes = shash_sort(&table->columns);
        for (i = 0; i < n; i++) {
            const struct ovsdb_column *column = nodes[i]->data;
            if (column->index != OVSDB_COL_UUID
                && column->index != OVSDB_COL_VERSION) {
                add_column(server, column, columns, columns_json);
            }
        }
        free(nodes);

        add_column(server, ovsdb_table_schema_get_column(table, "_version"),
                   columns, columns_json);
    }

    if (!initial || !insert || !delete || !modify) {
        struct json *select = json_object_create();
        json_object_put(select, "initial", json_boolean_create(initial));
        json_object_put(select, "insert", json_boolean_create(insert));
        json_object_put(select, "delete", json_boolean_create(delete));
        json_object_put(select, "modify", json_boolean_create(modify));
        json_object_put(mr, "select", select);
    }

    return mr;
}

static void
ovsdb_client_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_client_block(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *blocked_)
{
    bool *blocked = blocked_;

    if (!*blocked) {
        *blocked = true;
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply(conn, "already blocking");
    }
}

static void
ovsdb_client_unblock(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *blocked_)
{
    bool *blocked = blocked_;

    if (*blocked) {
        *blocked = false;
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply(conn, "already unblocked");
    }
}

static void
ovsdb_client_cond_change(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[], void *rpc_)
{
    struct jsonrpc *rpc = rpc_;
    struct json *monitor_cond_update_requests = json_object_create();
    struct json *monitor_cond_update_request = json_object_create();
    struct json *params;
    struct jsonrpc_msg *request;

    json_object_put(monitor_cond_update_request, "where",
                    json_from_string(argv[2]));
    json_object_put(monitor_cond_update_requests,
                    argv[1],
                    json_array_create_1(monitor_cond_update_request));

    params = json_array_create_3(json_null_create(),json_null_create(),
                                 monitor_cond_update_requests);

    request = jsonrpc_create_request("monitor_cond_change", params, NULL);
    jsonrpc_send(rpc, request);

    VLOG_DBG("cond change %s %s", argv[1], argv[2]);
    unixctl_command_reply(conn, "condiiton changed");
}

static void
add_monitored_table(int argc, char *argv[],
                    const char *server, const char *database,
                    struct json *condition,
                    struct ovsdb_table_schema *table,
                    struct json *monitor_requests,
                    struct monitored_table **mts,
                    size_t *n_mts, size_t *allocated_mts)
{
    struct json *monitor_request_array, *mr;
    struct monitored_table *mt;

    if (*n_mts >= *allocated_mts) {
        *mts = x2nrealloc(*mts, allocated_mts, sizeof **mts);
    }
    mt = &(*mts)[(*n_mts)++];
    mt->table = table;
    ovsdb_column_set_init(&mt->columns);

    monitor_request_array = json_array_create_empty();
    if (argc > 1) {
        int i;

        for (i = 1; i < argc; i++) {
            mr = parse_monitor_columns(argv[i], server, database, table,
                                       &mt->columns);
            if (i == 1 && condition) {
                json_object_put(mr, "where", condition);
            }
            json_array_add(monitor_request_array, mr);
        }
    } else {
        /* Allocate a writable empty string since parse_monitor_columns()
         * is going to strtok() it and that's risky with literal "". */
        char empty[] = "";

        mr = parse_monitor_columns(empty, server, database,
                                   table, &mt->columns);
        if (condition) {
            json_object_put(mr, "where", condition);
        }
        json_array_add(monitor_request_array, mr);
    }

    json_object_put(monitor_requests, table->name, monitor_request_array);
}

static void
destroy_monitored_table(struct monitored_table *mts, size_t n)
{
    int i;

    for (i = 0; i < n; i++) {
        struct monitored_table *mt = &mts[i];
        ovsdb_column_set_destroy(&mt->columns);
    }

    free(mts);
}

static void
do_monitor__(struct jsonrpc *rpc, const char *database,
             enum ovsdb_monitor_version version,
             int argc, char *argv[], struct json *condition)
{
    const char *server = jsonrpc_get_name(rpc);
    const char *table_name = argv[0];
    struct unixctl_server *unixctl;
    struct ovsdb_schema *schema;
    struct json *monitor, *monitor_requests, *request_id;
    bool exiting = false;
    bool blocked = false;

    struct monitored_table *mts;
    size_t n_mts, allocated_mts;

    ovs_assert(version < OVSDB_MONITOR_VERSION_MAX);

    daemon_save_fd(STDOUT_FILENO);
    daemon_save_fd(STDERR_FILENO);
    daemonize_start(false);
    if (get_detach()) {
        int error;

        error = unixctl_server_create(NULL, &unixctl);
        if (error) {
            ovs_fatal(error, "failed to create unixctl server");
        }

        unixctl_command_register("exit", "", 0, 0,
                                 ovsdb_client_exit, &exiting);
        unixctl_command_register("ovsdb-client/block", "", 0, 0,
                                 ovsdb_client_block, &blocked);
        unixctl_command_register("ovsdb-client/unblock", "", 0, 0,
                                 ovsdb_client_unblock, &blocked);
        unixctl_command_register("ovsdb-client/cond_change", "TABLE COND", 2, 2,
                                 ovsdb_client_cond_change, rpc);
    } else {
        unixctl = NULL;
    }

    schema = fetch_schema(rpc, database);

    monitor_requests = json_object_create();

    mts = NULL;
    n_mts = allocated_mts = 0;
    if (strcmp(table_name, "ALL")) {
        struct ovsdb_table_schema *table;

        table = shash_find_data(&schema->tables, table_name);
        if (!table) {
            ovs_fatal(0, "%s: %s does not have a table named \"%s\"",
                      server, database, table_name);
        }

        add_monitored_table(argc, argv, server, database, condition, table,
                            monitor_requests, &mts, &n_mts, &allocated_mts);
    } else {
        size_t n = shash_count(&schema->tables);
        const struct shash_node **nodes = shash_sort(&schema->tables);
        size_t i;

        if (condition) {
            ovs_fatal(0, "ALL tables are not allowed with condition");
        }

        for (i = 0; i < n; i++) {
            struct ovsdb_table_schema *table = nodes[i]->data;

            add_monitored_table(argc, argv, server, database, NULL, table,
                                monitor_requests,
                                &mts, &n_mts, &allocated_mts);
        }
        free(nodes);
    }

    send_db_change_aware(rpc);

    monitor = json_array_create_3(json_string_create(database),
                                  json_null_create(), monitor_requests);
    const char *method = version == OVSDB_MONITOR_V2 ? "monitor_cond"
                                                     : "monitor";

    struct jsonrpc_msg *request;
    request = jsonrpc_create_request(method, monitor, NULL);
    request_id = json_clone(request->id);
    jsonrpc_send(rpc, request);

    for (;;) {
        unixctl_server_run(unixctl);
        while (!blocked) {
            struct jsonrpc_msg *msg;
            int error;

            error = jsonrpc_recv(rpc, &msg);
            if (error == EAGAIN) {
                break;
            } else if (error) {
                ovs_fatal(error, "%s: receive failed", server);
            }

            if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
                jsonrpc_send(rpc, jsonrpc_create_reply(json_clone(msg->params),
                                                       msg->id));
            } else if (msg->type == JSONRPC_REPLY
                       && json_equal(msg->id, request_id)) {
                switch(version) {
                case OVSDB_MONITOR_V1:
                    monitor_print(msg->result, mts, n_mts, true);
                    break;
                case OVSDB_MONITOR_V2:
                    monitor2_print(msg->result, mts, n_mts);
                    break;
                case OVSDB_MONITOR_VERSION_MAX:
                default:
                    OVS_NOT_REACHED();
                }
                fflush(stdout);
                daemonize_complete();
            } else if (msg->type == JSONRPC_NOTIFY
                       && !strcmp(msg->method, "update")) {
                struct json *params = msg->params;
                if (params->type == JSON_ARRAY
                    && params->array.n == 2
                    && params->array.elems[0]->type == JSON_NULL) {
                    monitor_print(params->array.elems[1], mts, n_mts, false);
                    fflush(stdout);
                }
            } else if (msg->type == JSONRPC_NOTIFY
                       && version == OVSDB_MONITOR_V2
                       && !strcmp(msg->method, "update2")) {
                struct json *params = msg->params;
                if (params->type == JSON_ARRAY
                    && params->array.n == 2
                    && params->array.elems[0]->type == JSON_NULL) {
                    monitor2_print(params->array.elems[1], mts, n_mts);
                    fflush(stdout);
                }
            } else if (msg->type == JSONRPC_NOTIFY
                       && !strcmp(msg->method, "monitor_canceled")) {
                ovs_fatal(0, "%s: %s database was removed",
                          server, database);
            }
            jsonrpc_msg_destroy(msg);
        }

        if (exiting) {
            break;
        }

        jsonrpc_run(rpc);
        jsonrpc_wait(rpc);
        if (!blocked) {
            jsonrpc_recv_wait(rpc);
        }
        unixctl_server_wait(unixctl);
        poll_block();
    }

    json_destroy(request_id);
    unixctl_server_destroy(unixctl);
    ovsdb_schema_destroy(schema);
    destroy_monitored_table(mts, n_mts);
}

static void
do_monitor(struct jsonrpc *rpc, const char *database,
           int argc, char *argv[])
{
    do_monitor__(rpc, database, OVSDB_MONITOR_V1, argc, argv, NULL);
}

static void
do_monitor_cond(struct jsonrpc *rpc, const char *database,
           int argc, char *argv[])
{
    struct ovsdb_condition cnd;
    struct json *condition = NULL;
    struct ovsdb_schema *schema;
    struct ovsdb_table_schema *table;
    const char *table_name = argv[1];

    ovs_assert(argc > 1);
    schema = fetch_schema(rpc, database);
    table = shash_find_data(&schema->tables, table_name);
    if (!table) {
        ovs_fatal(0, "%s does not have a table named \"%s\"",
                  database, table_name);
    }
    condition = parse_json(argv[0]);
    check_ovsdb_error(ovsdb_condition_from_json(table, condition,
                                                    NULL, &cnd));
    ovsdb_condition_destroy(&cnd);
    do_monitor__(rpc, database, OVSDB_MONITOR_V2, --argc, ++argv, condition);
    ovsdb_schema_destroy(schema);
}

static bool
is_database_clustered(struct jsonrpc *rpc, const char *database)
{
    struct jsonrpc_msg *reply;
    check_txn(jsonrpc_transact_block(rpc,
                                     create_database_info_request(database),
                                     &reply), &reply);

    const struct json *row = parse_database_info_reply(
        reply, jsonrpc_get_name(rpc), database, NULL);
    return !strcmp(parse_string_column(row, "model"), "clustered");
}

static void
do_convert(struct jsonrpc *rpc, const char *database_ OVS_UNUSED,
           int argc, char *argv[])
{
    const char *schema_file_name = argv[argc - 1];
    struct ovsdb_schema *new_schema;
    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &new_schema));

    char *database = new_schema->name;
    open_rpc(1, NEED_DATABASE, argc, argv, &rpc, &database);

    if (is_database_clustered(rpc, database)) {
        ovsdb_schema_persist_ephemeral_columns(new_schema, schema_file_name);
    }

    send_db_change_aware(rpc);

    struct jsonrpc_msg *request, *reply;
    request = jsonrpc_create_request(
        "convert",
        json_array_create_2(json_string_create(new_schema->name),
                            ovsdb_schema_to_json(new_schema)), NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    jsonrpc_msg_destroy(reply);
}

static void
do_needs_conversion(struct jsonrpc *rpc, const char *database_ OVS_UNUSED,
                    int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_schema *schema1;
    check_ovsdb_error(ovsdb_schema_from_file(argv[0], &schema1));

    char *database = schema1->name;
    open_rpc(1, NEED_DATABASE, argc, argv, &rpc, &database);

    if (is_database_clustered(rpc, database)) {
        ovsdb_schema_persist_ephemeral_columns(schema1, argv[0]);
    }

    struct ovsdb_schema *schema2 = fetch_schema(rpc, schema1->name);
    puts(ovsdb_schema_equal(schema1, schema2) ? "no" : "yes");
    ovsdb_schema_destroy(schema1);
    ovsdb_schema_destroy(schema2);
}

struct dump_table_aux {
    struct ovsdb_datum **data;
    const struct ovsdb_column **columns;
    size_t n_columns;
};

static int
compare_data(size_t a_y, size_t b_y, size_t x,
             const struct dump_table_aux *aux)
{
    return ovsdb_datum_compare_3way(&aux->data[a_y][x],
                                    &aux->data[b_y][x],
                                    &aux->columns[x]->type);
}

static int
compare_rows(size_t a_y, size_t b_y, void *aux_)
{
    struct dump_table_aux *aux = aux_;
    size_t x;

    /* Skip UUID columns on the first pass, since their values tend to be
     * random and make our results less reproducible. */
    for (x = 0; x < aux->n_columns; x++) {
        if (aux->columns[x]->type.key.type != OVSDB_TYPE_UUID) {
            int cmp = compare_data(a_y, b_y, x, aux);
            if (cmp) {
                return cmp;
            }
        }
    }

    /* Use UUID columns as tie-breakers. */
    for (x = 0; x < aux->n_columns; x++) {
        if (aux->columns[x]->type.key.type == OVSDB_TYPE_UUID) {
            int cmp = compare_data(a_y, b_y, x, aux);
            if (cmp) {
                return cmp;
            }
        }
    }

    return 0;
}

static void
swap_rows(size_t a_y, size_t b_y, void *aux_)
{
    struct dump_table_aux *aux = aux_;
    struct ovsdb_datum *tmp = aux->data[a_y];
    aux->data[a_y] = aux->data[b_y];
    aux->data[b_y] = tmp;
}

static int
compare_columns(const void *a_, const void *b_)
{
    const struct ovsdb_column *const *ap = a_;
    const struct ovsdb_column *const *bp = b_;
    const struct ovsdb_column *a = *ap;
    const struct ovsdb_column *b = *bp;

    return strcmp(a->name, b->name);
}

static void
dump_table(const char *table_name, const struct shash *cols,
           struct json_array *rows)
{
    const struct ovsdb_column **columns;
    size_t n_columns;

    struct ovsdb_datum **data;

    struct dump_table_aux aux;
    struct shash_node *node;
    struct table t;
    size_t x, y;

    /* Sort columns by name, for reproducibility. */
    columns = xmalloc(shash_count(cols) * sizeof *columns);
    n_columns = 0;
    SHASH_FOR_EACH (node, cols) {
        struct ovsdb_column *column = node->data;
        if (strcmp(column->name, "_version")) {
            columns[n_columns++] = column;
        }
    }
    qsort(columns, n_columns, sizeof *columns, compare_columns);

    /* Extract data from table. */
    data = xmalloc(rows->n * sizeof *data);
    for (y = 0; y < rows->n; y++) {
        struct shash *row;

        if (rows->elems[y]->type != JSON_OBJECT) {
            ovs_fatal(0,  "row %"PRIuSIZE" in table %s response is not a JSON object: "
                      "%s", y, table_name, json_to_string(rows->elems[y], 0));
        }
        row = json_object(rows->elems[y]);

        data[y] = xmalloc(n_columns * sizeof **data);
        for (x = 0; x < n_columns; x++) {
            const struct json *json = shash_find_data(row, columns[x]->name);
            if (!json) {
                ovs_fatal(0, "row %"PRIuSIZE" in table %s response lacks %s column",
                          y, table_name, columns[x]->name);
            }

            check_ovsdb_error(ovsdb_unconstrained_datum_from_json(
                                  &data[y][x], &columns[x]->type, json));
        }
    }

    /* Sort rows by column values, for reproducibility. */
    aux.data = data;
    aux.columns = columns;
    aux.n_columns = n_columns;
    sort(rows->n, compare_rows, swap_rows, &aux);

    /* Add column headings. */
    table_init(&t);
    table_set_caption(&t, xasprintf("%s table", table_name));
    for (x = 0; x < n_columns; x++) {
        table_add_column(&t, "%s", columns[x]->name);
    }

    /* Print rows. */
    for (y = 0; y < rows->n; y++) {
        table_add_row(&t);
        for (x = 0; x < n_columns; x++) {
            struct cell *cell = table_add_cell(&t);
            cell->json = ovsdb_datum_to_json(&data[y][x], &columns[x]->type);
            cell->type = &columns[x]->type;
            ovsdb_datum_destroy(&data[y][x], &columns[x]->type);
        }
        free(data[y]);
    }
    table_print(&t, &table_style);
    table_destroy(&t);

    free(data);
    free(columns);
}

static void
do_dump(struct jsonrpc *rpc, const char *database,
        int argc, char *argv[])
{
    struct jsonrpc_msg *request, *reply;
    struct ovsdb_schema *schema;
    struct json *transaction;

    const struct shash_node *node, **tables;
    size_t n_tables;
    struct ovsdb_table_schema *tschema;
    const struct shash *columns;
    struct shash custom_columns;

    size_t i;

    shash_init(&custom_columns);
    schema = fetch_schema(rpc, database);
    if (argc) {
        node = shash_find(&schema->tables, argv[0]);
        if (!node) {
            ovs_fatal(0, "No table \"%s\" found.", argv[0]);
        }
        tables = xmemdup(&node, sizeof node);
        n_tables = 1;
        tschema = tables[0]->data;
        for (i = 1; i < argc; i++) {
            node = shash_find(&tschema->columns, argv[i]);
            if (!node) {
                ovs_fatal(0, "Table \"%s\" has no column %s.", argv[0], argv[1]);
            }
            shash_add(&custom_columns, argv[1], node->data);
        }
    } else {
        tables = shash_sort(&schema->tables);
        n_tables = shash_count(&schema->tables);
    }

    /* Construct transaction to retrieve entire database. */
    transaction = json_array_create_1(json_string_create(database));
    for (i = 0; i < n_tables; i++) {
        const struct ovsdb_table_schema *ts = tables[i]->data;
        struct json *op, *jcolumns;

        if (argc > 1) {
            columns = &custom_columns;
        } else {
            columns = &ts->columns;
        }
        jcolumns = json_array_create_empty();
        SHASH_FOR_EACH (node, columns) {
            const struct ovsdb_column *column = node->data;

            if (strcmp(column->name, "_version")) {
                json_array_add(jcolumns, json_string_create(column->name));
            }
        }

        op = json_object_create();
        json_object_put_string(op, "op", "select");
        json_object_put_string(op, "table", tables[i]->name);
        json_object_put(op, "where", json_array_create_empty());
        json_object_put(op, "columns", jcolumns);
        json_array_add(transaction, op);
    }

    /* Send request, get reply. */
    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);

    /* Print database contents. */
    if (reply->result->type != JSON_ARRAY
        || reply->result->array.n != n_tables) {
        ovs_fatal(0, "reply is not array of %"PRIuSIZE" elements: %s",
                  n_tables, json_to_string(reply->result, 0));
    }
    for (i = 0; i < n_tables; i++) {
        const struct ovsdb_table_schema *ts = tables[i]->data;
        const struct json *op_result = reply->result->array.elems[i];
        struct json *rows;

        if (op_result->type != JSON_OBJECT
            || !(rows = shash_find_data(json_object(op_result), "rows"))
            || rows->type != JSON_ARRAY) {
            ovs_fatal(0, "%s table reply is not an object with a \"rows\" "
                      "member array: %s",
                      ts->name, json_to_string(op_result, 0));
        }

        if (argc > 1) {
            dump_table(tables[i]->name, &custom_columns, &rows->array);
        } else {
            dump_table(tables[i]->name, &ts->columns, &rows->array);
        }
    }

    jsonrpc_msg_destroy(reply);
    shash_destroy(&custom_columns);
    free(tables);
    ovsdb_schema_destroy(schema);
}

static void
print_and_free_log_record(struct json *record)
{
    struct ds header = DS_EMPTY_INITIALIZER;
    struct ds data = DS_EMPTY_INITIALIZER;
    ovsdb_log_compose_record(record, OVSDB_MAGIC, &header, &data);
    fwrite(header.string, header.length, 1, stdout);
    fwrite(data.string, data.length, 1, stdout);
    ds_destroy(&data);
    ds_destroy(&header);
    json_destroy(record);
}

static void
set_binary_mode(FILE *stream OVS_UNUSED)
{
#ifdef _WIN32
    fflush(stream);
    /* On Windows set binary mode on the file descriptor to avoid
     * translation (i.e. CRLF line endings). */
    if (_setmode(_fileno(stream), O_BINARY) == -1) {
        ovs_fatal(errno, "could not set binary mode on fd %d",
                  _fileno(stream));
    }
#endif
}

static void
do_backup(struct jsonrpc *rpc, const char *database,
          int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    if (isatty(STDOUT_FILENO)) {
        ovs_fatal(0, "not writing backup to a terminal; "
                  "please redirect stdout to a file");
    }
    set_binary_mode(stdout);

    /* Get schema. */
    struct ovsdb_schema *schema = fetch_schema(rpc, database);

    /* Construct transaction to retrieve all tables. */
    struct json *txn = json_array_create_1(json_string_create(database));
    struct shash_node *node;
    SHASH_FOR_EACH (node, &schema->tables) {
        const char *table_name = node->name;
        const struct ovsdb_table_schema *table = node->data;

        /* Get all the columns except _version and the ephemeral ones.
         *
         * We don't omit tables that only have ephemeral columns because of the
         * possibility that other tables references rows in those tables; that
         * is, even if all the columns are ephemeral, the rows themselves are
         * not. */
        struct json *columns = json_array_create_empty();
        struct shash_node *node2;
        SHASH_FOR_EACH (node2, &table->columns) {
            const struct ovsdb_column *column = node2->data;

            if (column->persistent) {
                if (!columns) {
                    columns = json_array_create_empty();
                }
                json_array_add(columns, json_string_create(column->name));
            }
        }

        struct json *op = json_object_create();
        json_object_put_string(op, "op", "select");
        json_object_put_string(op, "table", table_name);
        json_object_put(op, "where", json_array_create_empty());
        json_object_put(op, "columns", columns);
        json_array_add(txn, op);
    }

    /* Send request, get reply. */
    struct jsonrpc_msg *rq = jsonrpc_create_request("transact", txn, NULL);
    struct jsonrpc_msg *reply;
    check_txn(jsonrpc_transact_block(rpc, rq, &reply), &reply);

    /* Print schema record. */
    print_and_free_log_record(ovsdb_schema_to_json(schema));

    /* Print database transaction record. */
    if (reply->result->type != JSON_ARRAY
        || reply->result->array.n != shash_count(&schema->tables)) {
        ovs_fatal(0, "reply is not array of %"PRIuSIZE" elements: %s",
                  shash_count(&schema->tables),
                  json_to_string(reply->result, 0));
    }
    struct json *output_txn = json_object_create();

    size_t i = 0;
    SHASH_FOR_EACH (node, &schema->tables) {
        const char *table_name = node->name;
        const struct ovsdb_table_schema *table = node->data;
        const struct json *op_result = reply->result->array.elems[i++];
        struct json *rows;

        if (op_result->type != JSON_OBJECT
            || !(rows = shash_find_data(json_object(op_result), "rows"))
            || rows->type != JSON_ARRAY) {
            ovs_fatal(0, "%s table reply is not an object with a \"rows\" "
                      "member array: %s",
                      table->name, json_to_string(op_result, 0));
        }

        if (!rows->array.n) {
            continue;
        }

        struct json *output_rows = json_object_create();
        for (size_t j = 0; j < rows->array.n; j++) {
            struct json *row = rows->array.elems[j];
            if (row->type != JSON_OBJECT) {
                ovs_fatal(0, "%s table reply row is not an object: %s",
                          table_name, json_to_string(row, 0));
            }

            struct json *uuid_json = shash_find_and_delete(json_object(row),
                                                           "_uuid");
            if (!uuid_json) {
                ovs_fatal(0, "%s table reply row lacks _uuid member: %s",
                          table_name, json_to_string(row, 0));
            }

            const struct ovsdb_base_type uuid_base = OVSDB_BASE_UUID_INIT;
            union ovsdb_atom atom;
            check_ovsdb_error(ovsdb_atom_from_json(&atom, &uuid_base,
                                                   uuid_json, NULL));

            char uuid_s[UUID_LEN + 1];
            snprintf(uuid_s, sizeof uuid_s, UUID_FMT, UUID_ARGS(&atom.uuid));
            json_object_put(output_rows, uuid_s, json_clone(row));
        }
        json_object_put(output_txn, table_name, output_rows);
    }
    output_txn = ovsdb_file_txn_annotate(
        output_txn, "produced by \"ovsdb-client backup\"");
    print_and_free_log_record(output_txn);

    ovsdb_schema_destroy(schema);
    jsonrpc_msg_destroy(reply);
}

static void
check_transaction_reply(struct jsonrpc_msg *reply)
{
    if (reply->result->type != JSON_ARRAY) {
        ovs_fatal(0, "result is not array");
    }
    for (size_t i = 0; i < json_array(reply->result)->n; i++) {
        struct json *json = json_array(reply->result)->elems[i];
        if (json->type != JSON_OBJECT) {
            ovs_fatal(0, "result array element is not object");
        }
        struct shash *object = json_object(json);
        if (shash_find(object, "error")) {
            ovs_fatal(0, "server returned error reply: %s",
                      json_to_string(json, JSSF_SORT));
        }
    }
}

static void
do_restore(struct jsonrpc *rpc, const char *database,
           int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    if (isatty(STDIN_FILENO)) {
        ovs_fatal(0, "not reading backup from a terminal; "
                  "please redirect stdin from a file");
    }
    set_binary_mode(stdin);

    struct ovsdb *backup = ovsdb_file_read("/dev/stdin", false);
    ovsdb_storage_close(backup->storage);
    backup->storage = NULL;

    struct ovsdb_schema *online_schema = fetch_schema(rpc, database);
    if (!ovsdb_schema_equal(backup->schema, online_schema)) {
        struct ds s = DS_EMPTY_INITIALIZER;
        if (strcmp(backup->schema->version, online_schema->version)) {
            ds_put_format(&s, "backup schema has version \"%s\" but "
                          "database schema has version \"%s\"",
                          backup->schema->version, online_schema->version);
        } else {
            ds_put_format(&s, "backup schema and database schema are "
                          "both version %s but still differ",
                          backup->schema->version);
        }
        if (!force) {
            ovs_fatal(0, "%s (use --force to override differences, or "
                      "\"ovsdb-client convert\" to change the schema)",
                      ds_cstr(&s));
        }
        VLOG_INFO("%s", ds_cstr(&s));
        ds_destroy(&s);
    }
    ovsdb_schema_destroy(online_schema);

    struct json *txn = json_array_create_empty();
    json_array_add(txn, json_string_create(backup->schema->name));
    struct shash_node *node;
    SHASH_FOR_EACH (node, &backup->tables) {
        const char *table_name = node->name;
        struct ovsdb_table *table = node->data;

        struct json *del_op = json_object_create();
        json_object_put_string(del_op, "op", "delete");
        json_object_put_string(del_op, "table", table_name);
        json_object_put(del_op, "where", json_array_create_empty());
        json_array_add(txn, del_op);

        const struct ovsdb_row *row;
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            struct json *ins_op = json_object_create();
            json_object_put_string(ins_op, "op", "insert");
            json_object_put_string(ins_op, "table", table_name);
            json_object_put(ins_op, "uuid-name",
                            json_string_create_nocopy(
                                ovsdb_data_row_name(ovsdb_row_get_uuid(row))));
            struct json *row_json = json_object_create();
            json_object_put(ins_op, "row", row_json);

            struct shash_node *node2;
            SHASH_FOR_EACH (node2, &table->schema->columns) {
                const struct ovsdb_column *column = node2->data;
                const struct ovsdb_datum *datum = &row->fields[column->index];
                const struct ovsdb_type *type = &column->type;
                if (column->persistent
                    && column->index >= OVSDB_N_STD_COLUMNS
                    && !ovsdb_datum_is_default(datum, type)) {
                    struct json *value = ovsdb_datum_to_json_with_row_names(
                        datum, type);
                    json_object_put(row_json, column->name, value);
                }
            }
            json_array_add(txn, ins_op);
        }
    }
    ovsdb_destroy(backup);
    struct jsonrpc_msg *rq = jsonrpc_create_request("transact", txn, NULL);
    struct jsonrpc_msg *reply;
    check_txn(jsonrpc_transact_block(rpc, rq, &reply), &reply);
    check_transaction_reply(reply);
    jsonrpc_msg_destroy(reply);
}


static void
do_help(struct jsonrpc *rpc OVS_UNUSED, const char *database OVS_UNUSED,
        int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
}


/* "lock" command. */

struct ovsdb_client_lock_req {
    const char *method;
    char *lock;
};

static void
lock_req_init(struct ovsdb_client_lock_req *lock_req,
              const char *method, const char *lock_name)
{
    if (lock_req->method || lock_req->lock) {
        return;
    }
    lock_req->method = method;
    lock_req->lock = xstrdup(lock_name);
}

static bool
lock_req_is_set(struct ovsdb_client_lock_req *lock_req)
{
    return lock_req->method;
}

static void
lock_req_destroy(struct ovsdb_client_lock_req *lock_req)
{
    free(lock_req->lock);
    lock_req->method = NULL;
    lock_req->lock = NULL;
}

/* Create a lock class request. Caller is responsible for free
 * the 'request' message. */
static struct jsonrpc_msg *
create_lock_request(struct ovsdb_client_lock_req *lock_req)
{
    struct json *locks, *lock;

    locks = json_array_create_empty();
    lock = json_string_create(lock_req->lock);
    json_array_add(locks, lock);

    return jsonrpc_create_request(lock_req->method, locks, NULL);
}

static void
ovsdb_client_lock(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[], void *lock_req_)
{
    struct ovsdb_client_lock_req *lock_req = lock_req_;
    lock_req_init(lock_req, "lock", argv[1]);
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_client_unlock(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[], void *lock_req_)
{
    struct ovsdb_client_lock_req *lock_req = lock_req_;
    lock_req_init(lock_req, "unlock", argv[1]);
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_client_steal(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[], void *lock_req_)
{
    struct ovsdb_client_lock_req *lock_req = lock_req_;
    lock_req_init(lock_req, "steal", argv[1]);
    unixctl_command_reply(conn, NULL);
}

static void
do_lock(struct jsonrpc *rpc, const char *method, const char *lock)
{
    struct ovsdb_client_lock_req lock_req = {NULL, NULL};
    struct unixctl_server *unixctl;
    struct jsonrpc_msg *request;
    struct json *request_id = NULL;
    bool exiting = false;
    bool enable_lock_request = true; /* Don't send another request before
                                        getting a reply of the previous
                                        request. */
    daemon_save_fd(STDOUT_FILENO);
    daemonize_start(false);
    lock_req_init(&lock_req, method, lock);

    if (get_detach()) {
        int error;

        error = unixctl_server_create(NULL, &unixctl);
        if (error) {
            ovs_fatal(error, "failed to create unixctl server");
        }

        unixctl_command_register("unlock", "LOCK", 1, 1,
                                  ovsdb_client_unlock, &lock_req);
        unixctl_command_register("steal", "LOCK", 1, 1,
                                  ovsdb_client_steal, &lock_req);
        unixctl_command_register("lock", "LOCK", 1, 1,
                                  ovsdb_client_lock, &lock_req);
        unixctl_command_register("exit", "", 0, 0,
                                 ovsdb_client_exit, &exiting);
    } else {
        unixctl = NULL;
    }

    for (;;) {
        struct jsonrpc_msg *msg;
        int error;

        unixctl_server_run(unixctl);
        if (enable_lock_request && lock_req_is_set(&lock_req)) {
            request = create_lock_request(&lock_req);
            request_id = json_clone(request->id);
            jsonrpc_send(rpc, request);
            lock_req_destroy(&lock_req);
        }

        error = jsonrpc_recv(rpc, &msg);
        if (error == EAGAIN) {
            goto no_msg;
        } else if (error) {
            ovs_fatal(error, "%s: receive failed", jsonrpc_get_name(rpc));
        }

        if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
            jsonrpc_send(rpc, jsonrpc_create_reply(json_clone(msg->params),
                                                   msg->id));
        } else if (msg->type == JSONRPC_REPLY
                   && json_equal(msg->id, request_id)) {
            print_json(msg->result);
            fflush(stdout);
            enable_lock_request = true;
            json_destroy(request_id);
            request_id = NULL;
            daemonize_complete();
        } else if (msg->type == JSONRPC_NOTIFY) {
            puts(msg->method);
            print_json(msg->params);
            fflush(stdout);
        }

        jsonrpc_msg_destroy(msg);

no_msg:
        if (exiting) {
            break;
        }

        jsonrpc_run(rpc);
        jsonrpc_wait(rpc);
        jsonrpc_recv_wait(rpc);

        unixctl_server_wait(unixctl);
        poll_block();
    }

    json_destroy(request_id);
    unixctl_server_destroy(unixctl);
}

static void
do_lock_create(struct jsonrpc *rpc, const char *database OVS_UNUSED,
               int argc OVS_UNUSED, char *argv[])
{
    do_lock(rpc, "lock", argv[0]);
}

static void
do_lock_steal(struct jsonrpc *rpc, const char *database OVS_UNUSED,
              int argc OVS_UNUSED, char *argv[])
{
    do_lock(rpc, "steal", argv[0]);
}

static void
do_lock_unlock(struct jsonrpc *rpc, const char *database OVS_UNUSED,
               int argc OVS_UNUSED, char *argv[])
{
    do_lock(rpc, "unlock", argv[0]);
}

enum ovsdb_client_wait_type {
    WAIT_CONNECTED,
    WAIT_ADDED,
    WAIT_REMOVED
};

static struct jsonrpc_msg *
compose_wait_transaction(enum ovsdb_client_wait_type type,
                         const char *database)
{
    struct json *txn = json_array_create_empty();
    json_array_add(txn, json_string_create("_Server"));

    struct json *op = json_object_create();
    json_array_add(txn, op);
    json_object_put_string(op, "op", "wait");
    json_object_put_string(op, "table", "Database");
    json_object_put(op, "where",
                    json_array_create_1(
                        json_array_create_3(
                            json_string_create("name"),
                            json_string_create("=="),
                            json_string_create(database))));

    if (type == WAIT_CONNECTED) {
        /* Wait until connected == true. */
        json_object_put(op, "columns",
                        json_array_create_1(json_string_create("connected")));
        json_object_put_string(op, "until", "==");

        struct json *row = json_object_create();
        json_object_put(row, "connected", json_boolean_create(true));
        json_object_put(op, "rows", json_array_create_1(row));
    } else {
        ovs_assert(type == WAIT_ADDED || type == WAIT_REMOVED);

        /* Wait until such a row exists, or not, respectively.  */
        json_object_put(op, "columns", json_array_create_empty());
        json_object_put_string(op, "until", "==");
        json_object_put(op, "rows",
                        (type == WAIT_ADDED
                         ? json_array_create_1(json_object_create())
                         : json_array_create_empty()));
    }
    return jsonrpc_create_request("transact", txn, NULL);
}

static void
do_wait(struct jsonrpc *rpc_unused OVS_UNUSED,
        const char *database_unused OVS_UNUSED,
        int argc, char *argv[])
{
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels_from_string_assert("reconnect:err");
    vlog_set_levels_from_string_assert("jsonrpc:err");

    const char *database = argv[argc - 2];
    const char *state = argv[argc - 1];

    enum ovsdb_client_wait_type type;
    if (!strcmp(state, "connected")) {
        type = WAIT_CONNECTED;
    } else if (!strcmp(state, "added")) {
        type = WAIT_ADDED;
    } else if (!strcmp(state, "removed")) {
        type = WAIT_REMOVED;
    } else {
        ovs_fatal(0, "%s: unknown state", state);
    }

    char *remote = argc > 2 ? xstrdup(argv[0]) : default_remote();
    struct jsonrpc_session *js = jsonrpc_session_open(remote, true);
    free(remote);

    unsigned int seqno = 0;
    struct json *sdca_id = NULL;
    struct json *txn_id = NULL;
    for (;;) {
        jsonrpc_session_run(js);

        if (seqno != jsonrpc_session_get_seqno(js)
            && jsonrpc_session_is_connected(js)) {
            seqno = jsonrpc_session_get_seqno(js);

            /* Send set_db_change_aware request. */
            struct jsonrpc_msg *rq = jsonrpc_create_request(
                "set_db_change_aware",
                json_array_create_1(json_boolean_create(true)),
                NULL);
            json_destroy(sdca_id);
            sdca_id = json_clone(rq->id);
            jsonrpc_session_send(js, rq);

            /* Send transaction. */
            rq = compose_wait_transaction(type, database);
            json_destroy(txn_id);
            txn_id = json_clone(rq->id);
            jsonrpc_session_send(js, rq);
        }

        struct jsonrpc_msg *reply = jsonrpc_session_recv(js);
        if (reply && reply->id) {
            if (sdca_id && json_equal(sdca_id, reply->id)) {
                if (reply->type == JSONRPC_ERROR) {
                    ovs_fatal(0, "%s: set_db_change_aware failed (%s)",
                              jsonrpc_session_get_name(js),
                              json_to_string(reply->error, 0));
                }
            } else if (txn_id && json_equal(txn_id, reply->id)) {
                check_transaction_reply(reply);
                exit(0);
            }
        }
        jsonrpc_msg_destroy(reply);

        jsonrpc_session_recv_wait(js);
        jsonrpc_session_wait(js);
        poll_block();
    }
}

/* Command handlers may take an optional server socket name (e.g. "unix:...")
 * and an optional database name (e.g. Open_vSwitch) as their initial
 * arguments.  The NEED_* element indicates what a particular command needs.
 * These optional arguments should not be included in min_args or max_args, and
 * they are not included in the argc and argv arguments passed to the handler:
 * the argv[0] passed to the handler is the first argument after the optional
 * server socket name. */
static const struct ovsdb_client_command all_commands[] = {
    { "list-dbs",           NEED_RPC,      0, 0,       do_list_dbs },
    { "get-schema",         NEED_DATABASE, 0, 0,       do_get_schema },
    { "get-schema-version", NEED_DATABASE, 0, 0,       do_get_schema_version },
    { "get-schema-cksum",   NEED_DATABASE, 0, 0,       do_get_schema_cksum },
    { "list-tables",        NEED_DATABASE, 0, 0,       do_list_tables },
    { "list-columns",       NEED_DATABASE, 0, 1,       do_list_columns },
    { "transact",           NEED_NONE,     1, 2,       do_transact },
    { "query",              NEED_NONE,     1, 2,       do_query },
    { "monitor",            NEED_DATABASE, 1, INT_MAX, do_monitor },
    { "monitor-cond",       NEED_DATABASE, 2, 3,       do_monitor_cond },
    { "wait",               NEED_NONE,     2, 3,       do_wait },
    { "convert",            NEED_NONE,     1, 2,       do_convert },
    { "needs-conversion",   NEED_NONE,     1, 2,       do_needs_conversion },
    { "dump",               NEED_DATABASE, 0, INT_MAX, do_dump },
    { "backup",             NEED_DATABASE, 0, 0,       do_backup },
    { "restore",            NEED_DATABASE, 0, 0,       do_restore },
    { "lock",               NEED_RPC,      1, 1,       do_lock_create },
    { "steal",              NEED_RPC,      1, 1,       do_lock_steal },
    { "unlock",             NEED_RPC,      1, 1,       do_lock_unlock },
    { "help",               NEED_NONE,     0, INT_MAX, do_help },

    { NULL,                 0,             0, 0,       NULL },
};

static const struct ovsdb_client_command *get_all_commands(void)
{
    return all_commands;
}
