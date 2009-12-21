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
#include "dynamic-string.h"
#include "json.h"
#include "jsonrpc.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "stream.h"
#include "stream-ssl.h"
#include "table.h"
#include "timeval.h"
#include "util.h"

#include "vlog.h"
#define THIS_MODULE VLM_ovsdb_client

/* --format: Output formatting. */
static enum {
    FMT_TABLE,                  /* Textual table. */
    FMT_HTML,                   /* HTML table. */
    FMT_CSV                     /* Comma-separated lines. */
} output_format;

/* --wide: For --format=table, the maximum output width. */
static int output_width;

/* --no-headings: Whether table output should include headings. */
static int output_headings = true;

/* --pretty: Flags to pass to json_to_string(). */
static int json_flags = JSSF_SORT;

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
    enum {
        OPT_BOOTSTRAP_CA_CERT = UCHAR_MAX + 1
    };
    static struct option long_options[] = {
        {"wide", no_argument, &output_width, INT_MAX},
        {"format", required_argument, 0, 'f'},
	    {"no-headings", no_argument, &output_headings, 0},
        {"pretty", no_argument, &json_flags, JSSF_PRETTY | JSSF_SORT},
        {"verbose", optional_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        {"bootstrap-ca-cert", required_argument, 0, OPT_BOOTSTRAP_CA_CERT},
        STREAM_SSL_LONG_OPTIONS
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    output_width = isatty(fileno(stdout)) ? 79 : INT_MAX;
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'f':
            if (!strcmp(optarg, "table")) {
                output_format = FMT_TABLE;
            } else if (!strcmp(optarg, "html")) {
                output_format = FMT_HTML;
            } else if (!strcmp(optarg, "csv")) {
                output_format = FMT_CSV;
            } else {
                ovs_fatal(0, "unknown output format \"%s\"", optarg);
            }
            break;

        case 'w':
            output_width = INT_MAX;
            break;

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(0, 0);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        DAEMON_OPTION_HANDLERS

#ifdef HAVE_OPENSSL
        STREAM_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;
#endif

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
           "\n  get-schema SERVER\n"
           "    retrieve schema from SERVER\n"
           "\n  list-tables SERVER\n"
           "    list SERVER's tables\n"
           "\n  list-columns SERVER [TABLE]\n"
           "    list columns in TABLE (or all tables) on SERVER\n"
           "\n  transact SERVER TRANSACTION\n"
           "    run TRANSACTION (a JSON array of operations) on SERVER\n"
           "    and print the results as JSON on stdout\n"
           "\n  monitor SERVER TABLE [COLUMN,...] [SELECT,...]\n"
           "    monitor contents of (COLUMNs in) TABLE on SERVER\n"
           "    Valid SELECTs are: initial, insert, delete, modify\n",
           program_name, program_name);
    stream_usage("SERVER", true, true, true);
    printf("\nOutput formatting options:\n"
           "  -f, --format=FORMAT         set output formatting to FORMAT\n"
           "                              (\"table\", \"html\", or \"csv\"\n"
           "  --wide                      don't limit TTY lines to 79 bytes\n"
           "  --no-headings               omit table heading row\n"
           "  --pretty                    pretty-print JSON in output");
    daemon_usage();
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

static struct jsonrpc *
open_jsonrpc(const char *server)
{
    struct stream *stream;
    int error;

    error = stream_open_block(server, &stream);
    if (error == EAFNOSUPPORT) {
        struct pstream *pstream;

        error = pstream_open(server, &pstream);
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
    char *string = json_to_string(json, json_flags);
    fputs(string, stdout);
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
fetch_schema_from_rpc(struct jsonrpc *rpc)
{
    struct jsonrpc_msg *request, *reply;
    struct ovsdb_schema *schema;
    int error;

    request = jsonrpc_create_request("get_schema", json_array_create_empty(),
                                     NULL);
    error = jsonrpc_transact_block(rpc, request, &reply);
    if (error) {
        ovs_fatal(error, "transaction failed");
    }
    check_ovsdb_error(ovsdb_schema_from_json(reply->result, &schema));
    jsonrpc_msg_destroy(reply);

    return schema;
}

static struct ovsdb_schema *
fetch_schema(const char *server)
{
    struct ovsdb_schema *schema;
    struct jsonrpc *rpc;

    rpc = open_jsonrpc(server);
    schema = fetch_schema_from_rpc(rpc);
    jsonrpc_close(rpc);

    return schema;
}

struct column {
    char *heading;
    int width;
};

struct table {
    char **cells;
    struct column *columns;
    size_t n_columns, allocated_columns;
    size_t n_rows, allocated_rows;
    size_t current_column;
};

static void
table_init(struct table *table)
{
    memset(table, 0, sizeof *table);
}

static void
table_destroy(struct table *table)
{
    size_t i;

    for (i = 0; i < table->n_columns; i++) {
        free(table->columns[i].heading);
    }
    free(table->columns);

    for (i = 0; i < table->n_columns * table->n_rows; i++) {
        free(table->cells[i]);
    }
    free(table->cells);
}

static void
table_add_column(struct table *table, const char *heading, ...)
    PRINTF_FORMAT(2, 3);

static void
table_add_column(struct table *table, const char *heading, ...)
{
    struct column *column;
    va_list args;

    assert(!table->n_rows);
    if (table->n_columns >= table->allocated_columns) {
        table->columns = x2nrealloc(table->columns, &table->allocated_columns,
                                    sizeof *table->columns);
    }
    column = &table->columns[table->n_columns++];

    va_start(args, heading);
    column->heading = xvasprintf(heading, args);
    column->width = strlen(column->heading);
    va_end(args);
}

static char **
table_cell__(const struct table *table, size_t row, size_t column)
{
    return &table->cells[column + row * table->n_columns];
}

static void
table_add_row(struct table *table)
{
    size_t x, y;

    if (table->n_rows >= table->allocated_rows) {
        table->cells = x2nrealloc(table->cells, &table->allocated_rows,
                                  table->n_columns * sizeof *table->cells);
    }

    y = table->n_rows++;
    table->current_column = 0;
    for (x = 0; x < table->n_columns; x++) {
        *table_cell__(table, y, x) = NULL;
    }
}

static void
table_add_cell_nocopy(struct table *table, char *s)
{
    size_t x, y;
    int length;

    assert(table->n_rows > 0);
    assert(table->current_column < table->n_columns);

    x = table->current_column++;
    y = table->n_rows - 1;
    *table_cell__(table, y, x) = s;

    length = strlen(s);
    if (length > table->columns[x].width) {
        table->columns[x].width = length;
    }
}

static void
table_add_cell(struct table *table, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    table_add_cell_nocopy(table, xvasprintf(format, args));
    va_end(args);
}

static void
table_print_table_line__(struct ds *line, size_t max_width)
{
    ds_truncate(line, max_width);
    puts(ds_cstr(line));
    ds_clear(line);
}

static void
table_print_table__(const struct table *table)
{
    struct ds line = DS_EMPTY_INITIALIZER;
    size_t x, y;

    if (output_headings) {
        for (x = 0; x < table->n_columns; x++) {
            const struct column *column = &table->columns[x];
            if (x) {
                ds_put_char(&line, ' ');
            }
            ds_put_format(&line, "%-*s", column->width, column->heading);
        }
        table_print_table_line__(&line, output_width);

        for (x = 0; x < table->n_columns; x++) {
            const struct column *column = &table->columns[x];
            int i;

            if (x) {
                ds_put_char(&line, ' ');
            }
            for (i = 0; i < column->width; i++) {
                ds_put_char(&line, '-');
            }
        }
        table_print_table_line__(&line, output_width);
    }

    for (y = 0; y < table->n_rows; y++) {
        for (x = 0; x < table->n_columns; x++) {
            const char *cell = *table_cell__(table, y, x);
            if (x) {
                ds_put_char(&line, ' ');
            }
            ds_put_format(&line, "%-*s", table->columns[x].width, cell);
        }
        table_print_table_line__(&line, output_width);
    }

    ds_destroy(&line);
}

static void
table_print_html_cell__(const char *element, const char *content)
{
    const char *p;

    printf("    <%s>", element);
    for (p = content; *p != '\0'; p++) {
        switch (*p) {
        case '&':
            fputs("&amp;", stdout);
            break;
        case '<':
            fputs("&lt;", stdout);
            break;
        case '>':
            fputs("&gt;", stdout);
            break;
        default:
            putchar(*p);
            break;
        }
    }
    printf("</%s>\n", element);
}

static void
table_print_html__(const struct table *table)
{
    size_t x, y;

    fputs("<table>\n", stdout);

    if (output_headings) {
        fputs("  <tr>\n", stdout);
        for (x = 0; x < table->n_columns; x++) {
            const struct column *column = &table->columns[x];
            table_print_html_cell__("th", column->heading);
        }
        fputs("  </tr>\n", stdout);
    }

    for (y = 0; y < table->n_rows; y++) {
        fputs("  <tr>\n", stdout);
        for (x = 0; x < table->n_columns; x++) {
            table_print_html_cell__("td", *table_cell__(table, y, x));
        }
        fputs("  </tr>\n", stdout);
    }

    fputs("</table>\n", stdout);
}

static void
table_print_csv_cell__(const char *content)
{
    const char *p;

    if (!strpbrk(content, "\n\",")) {
        fputs(content, stdout);
    } else {
        putchar('"');
        for (p = content; *p != '\0'; p++) {
            switch (*p) {
            case '"':
                fputs("\"\"", stdout);
                break;
            default:
                putchar(*p);
                break;
            }
        }
        putchar('"');
    }
}

static void
table_print_csv__(const struct table *table)
{
    size_t x, y;

    if (output_headings) {
        for (x = 0; x < table->n_columns; x++) {
            const struct column *column = &table->columns[x];
            if (x) {
                putchar(',');
            }
            table_print_csv_cell__(column->heading);
        }
        putchar('\n');
    }

    for (y = 0; y < table->n_rows; y++) {
        for (x = 0; x < table->n_columns; x++) {
            if (x) {
                putchar(',');
            }
            table_print_csv_cell__(*table_cell__(table, y, x));
        }
        putchar('\n');
    }
}

static void
table_print(const struct table *table)
{
    switch (output_format) {
    case FMT_TABLE:
        table_print_table__(table);
        break;

    case FMT_HTML:
        table_print_html__(table);
        break;

    case FMT_CSV:
        table_print_csv__(table);
        break;
    }
}

static void
do_get_schema(int argc UNUSED, char *argv[])
{
    struct ovsdb_schema *schema = fetch_schema(argv[1]);
    print_and_free_json(ovsdb_schema_to_json(schema));
    ovsdb_schema_destroy(schema);
}

static void
do_list_tables(int argc UNUSED, char *argv[])
{
    struct ovsdb_schema *schema;
    struct shash_node *node;
    struct table t;

    schema = fetch_schema(argv[1]);
    table_init(&t);
    table_add_column(&t, "Table");
    table_add_column(&t, "Comment");
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *ts = node->data;

        table_add_row(&t);
        table_add_cell(&t, ts->name);
        if (ts->comment) {
            table_add_cell(&t, ts->comment);
        }
    }
    ovsdb_schema_destroy(schema);
    table_print(&t);
}

static void
do_list_columns(int argc UNUSED, char *argv[])
{
    const char *table_name = argv[2];
    struct ovsdb_schema *schema;
    struct shash_node *table_node;
    struct table t;

    schema = fetch_schema(argv[1]);
    table_init(&t);
    if (!table_name) {
        table_add_column(&t, "Table");
    }
    table_add_column(&t, "Column");
    table_add_column(&t, "Type");
    table_add_column(&t, "Comment");
    SHASH_FOR_EACH (table_node, &schema->tables) {
        struct ovsdb_table_schema *ts = table_node->data;

        if (!table_name || !strcmp(table_name, ts->name)) {
            struct shash_node *column_node;

            SHASH_FOR_EACH (column_node, &ts->columns) {
                struct ovsdb_column *column = column_node->data;
                struct json *type = ovsdb_type_to_json(&column->type);

                table_add_row(&t);
                if (!table_name) {
                    table_add_cell(&t, ts->name);
                }
                table_add_cell(&t, column->name);
                table_add_cell_nocopy(&t, json_to_string(type, JSSF_SORT));
                if (column->comment) {
                    table_add_cell(&t, column->comment);
                }

                json_destroy(type);
            }
        }
    }
    ovsdb_schema_destroy(schema);
    table_print(&t);
}

static void
do_transact(int argc UNUSED, char *argv[])
{
    struct jsonrpc_msg *request, *reply;
    struct json *transaction;
    struct jsonrpc *rpc;
    int error;

    transaction = parse_json(argv[2]);

    rpc = open_jsonrpc(argv[1]);
    request = jsonrpc_create_request("transact", transaction, NULL);
    error = jsonrpc_transact_block(rpc, request, &reply);
    if (error) {
        ovs_fatal(error, "transaction failed");
    }
    if (reply->error) {
        ovs_fatal(error, "transaction returned error: %s",
                  json_to_string(reply->error, json_flags));
    }
    print_json(reply->result);
    putchar('\n');
    jsonrpc_msg_destroy(reply);
    jsonrpc_close(rpc);
}

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
    table_add_cell(t, uuid);
    table_add_cell(t, type);
    for (i = 0; i < columns->n_columns; i++) {
        const struct ovsdb_column *column = columns->columns[i];
        struct json *value = shash_find_data(json_object(row), column->name);
        if (value) {
            table_add_cell_nocopy(t, json_to_string(value, JSSF_SORT));
        } else {
            table_add_cell(t, "");
        }
    }
}

static void
monitor_print(struct json *table_updates,
              const struct ovsdb_table_schema *table,
              const struct ovsdb_column_set *columns, bool initial)
{
    struct json *table_update;
    struct shash_node *node;
    struct table t;
    size_t i;

    table_init(&t);

    if (table_updates->type != JSON_OBJECT) {
        ovs_error(0, "<table-updates> is not object");
        return;
    }
    table_update = shash_find_data(json_object(table_updates), table->name);
    if (!table_update) {
        return;
    }
    if (table_update->type != JSON_OBJECT) {
        ovs_error(0, "<table-update> is not object");
        return;
    }

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
    table_print(&t);
    table_destroy(&t);
}

static void
do_monitor(int argc, char *argv[])
{
    struct ovsdb_column_set columns = OVSDB_COLUMN_SET_INITIALIZER;
    struct ovsdb_table_schema *table;
    struct ovsdb_schema *schema;
    struct jsonrpc_msg *request;
    struct jsonrpc *rpc;
    struct json *select, *monitor, *monitor_request, *monitor_requests,
        *request_id;

    rpc = open_jsonrpc(argv[1]);

    schema = fetch_schema_from_rpc(rpc);
    table = shash_find_data(&schema->tables, argv[2]);
    if (!table) {
        ovs_fatal(0, "%s: no table named \"%s\"", argv[1], argv[2]);
    }

    if (argc >= 4 && *argv[3] != '\0') {
        char *save_ptr = NULL;
        char *token;

        for (token = strtok_r(argv[3], ",", &save_ptr); token != NULL;
             token = strtok_r(NULL, ",", &save_ptr)) {
            const struct ovsdb_column *column;
            column = ovsdb_table_schema_get_column(table, token);
            if (!column) {
                ovs_fatal(0, "%s: table \"%s\" does not have a "
                          "column named \"%s\"", argv[1], argv[2], token);
            }
            ovsdb_column_set_add(&columns, column);
        }
    } else {
        struct shash_node *node;

        SHASH_FOR_EACH (node, &table->columns) {
            const struct ovsdb_column *column = node->data;
            if (column->index != OVSDB_COL_UUID) {
                ovsdb_column_set_add(&columns, column);
            }
        }
    }

    if (argc >= 5 && *argv[4] != '\0') {
        char *save_ptr = NULL;
        char *token;

        select = json_object_create();
        for (token = strtok_r(argv[4], ",", &save_ptr); token != NULL;
             token = strtok_r(NULL, ",", &save_ptr)) {
            json_object_put(select, token, json_boolean_create(true));
        }
    } else {
        select = NULL;
    }

    monitor_request = json_object_create();
    json_object_put(monitor_request,
                    "columns", ovsdb_column_set_to_json(&columns));
    if (select) {
        json_object_put(monitor_request, "select", select);
    }

    monitor_requests = json_object_create();
    json_object_put(monitor_requests, argv[2], monitor_request);

    monitor = json_array_create_2(json_null_create(), monitor_requests);
    request = jsonrpc_create_request("monitor", monitor, NULL);
    request_id = json_clone(request->id);
    jsonrpc_send(rpc, request);
    for (;;) {
        struct jsonrpc_msg *msg;
        int error;

        error = jsonrpc_recv_block(rpc, &msg);
        if (error) {
            ovs_fatal(error, "%s: receive failed", argv[1]);
        }

        if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
            jsonrpc_send(rpc, jsonrpc_create_reply(json_clone(msg->params),
                                                   msg->id));
        } else if (msg->type == JSONRPC_REPLY
                   && json_equal(msg->id, request_id)) {
            monitor_print(msg->result, table, &columns, true);
            fflush(stdout);
            daemonize();
        } else if (msg->type == JSONRPC_NOTIFY
                   && !strcmp(msg->method, "update")) {
            struct json *params = msg->params;
            if (params->type == JSON_ARRAY
                && params->u.array.n == 2
                && params->u.array.elems[0]->type == JSON_NULL) {
                monitor_print(params->u.array.elems[1],
                              table, &columns, false);
                fflush(stdout);
            }
        }
    }
}

static void
do_help(int argc UNUSED, char *argv[] UNUSED)
{
    usage();
}

static const struct command all_commands[] = {
    { "get-schema", 1, 1, do_get_schema },
    { "list-tables", 1, 1, do_list_tables },
    { "list-columns", 1, 2, do_list_columns },
    { "transact", 2, 2, do_transact },
    { "monitor", 2, 4, do_monitor },
    { "help", 0, INT_MAX, do_help },
    { NULL, 0, 0, NULL },
};
