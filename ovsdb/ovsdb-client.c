/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "sort.h"
#include "stream.h"
#include "stream-ssl.h"
#include "table.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_client)

/* --format: Output formatting. */
static enum {
    FMT_TABLE,                  /* Textual table. */
    FMT_HTML,                   /* HTML table. */
    FMT_CSV                     /* Comma-separated lines. */
} output_format;

/* --no-headings: Whether table output should include headings. */
static int output_headings = true;

/* --pretty: Flags to pass to json_to_string(). */
static int json_flags = JSSF_SORT;

/* --data: Format of data in output tables. */
static enum {
    DF_STRING,                  /* String format. */
    DF_JSON,                    /* JSON. */
} data_format;

static const struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    proctitle_init(argc, argv);
    set_program_name(argv[0]);
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
        {"format", required_argument, 0, 'f'},
        {"data", required_argument, 0, 'd'},
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

        case 'd':
            if (!strcmp(optarg, "string")) {
                data_format = DF_STRING;
            } else if (!strcmp(optarg, "json")) {
                data_format = DF_JSON;
            } else {
                ovs_fatal(0, "unknown data format \"%s\"", optarg);
            }
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
           "\n  list-dbs SERVER\n"
           "    list databases available on SERVER\n"
           "\n  get-schema SERVER DATABASE\n"
           "    retrieve schema for DATABASE from SERVER\n"
           "\n  list-tables SERVER DATABASE\n"
           "    list tables for DATABASE on SERVER\n"
           "\n  list-columns SERVER DATABASE [TABLE]\n"
           "    list columns in TABLE (or all tables) in DATABASE on SERVER\n"
           "\n  transact SERVER TRANSACTION\n"
           "    run TRANSACTION (a JSON array of operations) on SERVER\n"
           "    and print the results as JSON on stdout\n"
           "\n  monitor SERVER DATABASE TABLE [COLUMN,...]...\n"
           "    monitor contents of COLUMNs in TABLE in DATABASE on SERVER.\n"
           "    COLUMNs may include !initial, !insert, !delete, !modify\n"
           "    to avoid seeing the specified kinds of changes.\n"
           "\n  dump SERVER DATABASE\n"
           "    dump contents of DATABASE on SERVER to stdout\n",
           program_name, program_name);
    stream_usage("SERVER", true, true, true);
    printf("\nOutput formatting options:\n"
           "  -f, --format=FORMAT         set output formatting to FORMAT\n"
           "                              (\"table\", \"html\", or \"csv\"\n"
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

    error = stream_open_block(jsonrpc_stream_open(server, &stream), &stream);
    if (error == EAFNOSUPPORT) {
        struct pstream *pstream;

        error = jsonrpc_pstream_open(server, &pstream);
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
fetch_schema_from_rpc(struct jsonrpc *rpc, const char *database)
{
    struct jsonrpc_msg *request, *reply;
    struct ovsdb_schema *schema;
    int error;

    request = jsonrpc_create_request("get_schema",
                                     json_array_create_1(
                                         json_string_create(database)),
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
fetch_schema(const char *server, const char *database)
{
    struct ovsdb_schema *schema;
    struct jsonrpc *rpc;

    rpc = open_jsonrpc(server);
    schema = fetch_schema_from_rpc(rpc, database);
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
    char *caption;
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

    free(table->caption);
}

static void
table_set_caption(struct table *table, char *caption)
{
    free(table->caption);
    table->caption = caption;
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
table_print_table_line__(struct ds *line)
{
    puts(ds_cstr(line));
    ds_clear(line);
}

static void
table_print_table__(const struct table *table)
{
    static int n = 0;
    struct ds line = DS_EMPTY_INITIALIZER;
    size_t x, y;

    if (n++ > 0) {
        putchar('\n');
    }

    if (output_headings) {
        for (x = 0; x < table->n_columns; x++) {
            const struct column *column = &table->columns[x];
            if (x) {
                ds_put_char(&line, ' ');
            }
            ds_put_format(&line, "%-*s", column->width, column->heading);
        }
        table_print_table_line__(&line);

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
        table_print_table_line__(&line);
    }

    for (y = 0; y < table->n_rows; y++) {
        for (x = 0; x < table->n_columns; x++) {
            const char *cell = *table_cell__(table, y, x);
            if (x) {
                ds_put_char(&line, ' ');
            }
            ds_put_format(&line, "%-*s", table->columns[x].width, cell);
        }
        table_print_table_line__(&line);
    }

    ds_destroy(&line);
}

static void
table_escape_html_text__(const char *s, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        char c = s[i];

        switch (c) {
        case '&':
            fputs("&amp;", stdout);
            break;
        case '<':
            fputs("&lt;", stdout);
            break;
        case '>':
            fputs("&gt;", stdout);
            break;
        case '"':
            fputs("&quot;", stdout);
            break;
        default:
            putchar(c);
            break;
        }
    }
}

static void
table_print_html_cell__(const char *element, const char *content)
{
    const char *p;

    printf("    <%s>", element);
    for (p = content; *p; ) {
        struct uuid uuid;

        if (uuid_from_string_prefix(&uuid, p)) {
            printf("<a href=\"#%.*s\">%.*s</a>", UUID_LEN, p, 8, p);
            p += UUID_LEN;
        } else {
            table_escape_html_text__(p, 1);
            p++;
        }
    }
    printf("</%s>\n", element);
}

static void
table_print_html__(const struct table *table)
{
    size_t x, y;

    fputs("<table border=1>\n", stdout);

    if (table->caption) {
        table_print_html_cell__("caption", table->caption);
    }

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
            const char *content = *table_cell__(table, y, x);

            if (!strcmp(table->columns[x].heading, "_uuid")) {
                fputs("    <td><a name=\"", stdout);
                table_escape_html_text__(content, strlen(content));
                fputs("\">", stdout);
                table_escape_html_text__(content, 8);
                fputs("</a></td>\n", stdout);
            } else {
                table_print_html_cell__("td", content);
            }
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
    static int n = 0;
    size_t x, y;

    if (n++ > 0) {
        putchar('\n');
    }

    if (table->caption) {
        puts(table->caption);
    }

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
do_list_dbs(int argc OVS_UNUSED, char *argv[])
{
    struct jsonrpc_msg *request, *reply;
    struct jsonrpc *rpc;
    int error;
    size_t i;

    rpc = open_jsonrpc(argv[1]);
    request = jsonrpc_create_request("list_dbs", json_array_create_empty(),
                                     NULL);
    error = jsonrpc_transact_block(rpc, request, &reply);
    if (error) {
        ovs_fatal(error, "transaction failed");
    }

    if (reply->result->type != JSON_ARRAY) {
        ovs_fatal(0, "list_dbs response is not array");
    }

    for (i = 0; i < reply->result->u.array.n; i++) {
        const struct json *name = reply->result->u.array.elems[i];

        if (name->type != JSON_STRING) {
            ovs_fatal(0, "list_dbs response %zu is not string", i);
        }
        puts(name->u.string);
    }
    jsonrpc_msg_destroy(reply);
}

static void
do_get_schema(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_schema *schema = fetch_schema(argv[1], argv[2]);
    print_and_free_json(ovsdb_schema_to_json(schema));
    ovsdb_schema_destroy(schema);
}

static void
do_list_tables(int argc OVS_UNUSED, char *argv[])
{
    struct ovsdb_schema *schema;
    struct shash_node *node;
    struct table t;

    schema = fetch_schema(argv[1], argv[2]);
    table_init(&t);
    table_add_column(&t, "Table");
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *ts = node->data;

        table_add_row(&t);
        table_add_cell(&t, ts->name);
    }
    ovsdb_schema_destroy(schema);
    table_print(&t);
}

static void
do_list_columns(int argc OVS_UNUSED, char *argv[])
{
    const char *table_name = argv[3];
    struct ovsdb_schema *schema;
    struct shash_node *table_node;
    struct table t;

    schema = fetch_schema(argv[1], argv[2]);
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
                struct json *type = ovsdb_type_to_json(&column->type);

                table_add_row(&t);
                if (!table_name) {
                    table_add_cell(&t, ts->name);
                }
                table_add_cell(&t, column->name);
                table_add_cell_nocopy(&t, json_to_string(type, JSSF_SORT));

                json_destroy(type);
            }
        }
    }
    ovsdb_schema_destroy(schema);
    table_print(&t);
}

static void
do_transact(int argc OVS_UNUSED, char *argv[])
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

static char *
format_json(const struct json *json, const struct ovsdb_type *type)
{
    if (data_format == DF_JSON) {
        return json_to_string(json, JSSF_SORT);
    } else if (data_format == DF_STRING) {
        struct ovsdb_datum datum;
        struct ovsdb_error *error;
        struct ds s;

        error = ovsdb_datum_from_json(&datum, type, json, NULL);
        if (error) {
            return json_to_string(json, JSSF_SORT);
        }

        ds_init(&s);
        ovsdb_datum_to_string(&datum, type, &s);
        ovsdb_datum_destroy(&datum, type);
        return ds_steal_cstr(&s);
    } else {
        NOT_REACHED();
    }
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
            table_add_cell_nocopy(t, format_json(value, &column->type));
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

    if (columns_json->u.array.n == 0) {
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

        add_column(server, ovsdb_table_schema_get_column(table,"_version"),
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
do_monitor(int argc, char *argv[])
{
    const char *server = argv[1];
    const char *database = argv[2];
    const char *table_name = argv[3];
    struct ovsdb_column_set columns = OVSDB_COLUMN_SET_INITIALIZER;
    struct ovsdb_table_schema *table;
    struct ovsdb_schema *schema;
    struct jsonrpc_msg *request;
    struct jsonrpc *rpc;
    struct json *monitor, *monitor_request_array,
        *monitor_requests, *request_id;

    rpc = open_jsonrpc(server);

    schema = fetch_schema_from_rpc(rpc, database);
    table = shash_find_data(&schema->tables, table_name);
    if (!table) {
        ovs_fatal(0, "%s: %s does not have a table named \"%s\"",
                  server, database, table_name);
    }

    monitor_request_array = json_array_create_empty();
    if (argc > 4) {
        int i;

        for (i = 4; i < argc; i++) {
            json_array_add(
                monitor_request_array,
                parse_monitor_columns(argv[i], server, database, table,
                                      &columns));
        }
    } else {
        /* Allocate a writable empty string since parse_monitor_columns() is
         * going to strtok() it and that's risky with literal "". */
        char empty[] = "";
        json_array_add(
            monitor_request_array,
            parse_monitor_columns(empty, server, database, table, &columns));
    }

    monitor_requests = json_object_create();
    json_object_put(monitor_requests, table_name, monitor_request_array);

    monitor = json_array_create_3(json_string_create(database),
                                  json_null_create(), monitor_requests);
    request = jsonrpc_create_request("monitor", monitor, NULL);
    request_id = json_clone(request->id);
    jsonrpc_send(rpc, request);
    for (;;) {
        struct jsonrpc_msg *msg;
        int error;

        error = jsonrpc_recv_block(rpc, &msg);
        if (error) {
            ovsdb_schema_destroy(schema);
            ovs_fatal(error, "%s: receive failed", server);
        }

        if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
            jsonrpc_send(rpc, jsonrpc_create_reply(json_clone(msg->params),
                                                   msg->id));
        } else if (msg->type == JSONRPC_REPLY
                   && json_equal(msg->id, request_id)) {
            monitor_print(msg->result, table, &columns, true);
            fflush(stdout);
            if (get_detach()) {
                /* daemonize() closes the standard file descriptors.  We output
                 * to stdout, so we need to save and restore STDOUT_FILENO. */
                int fd = dup(STDOUT_FILENO);
                daemonize();
                dup2(fd, STDOUT_FILENO);
                close(fd);
            }
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
        jsonrpc_msg_destroy(msg);
    }
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

static char *
format_data(const struct ovsdb_datum *datum, const struct ovsdb_type *type)
{
    if (data_format == DF_JSON) {
        struct json *json = ovsdb_datum_to_json(datum, type);
        char *s = json_to_string(json, JSSF_SORT);
        json_destroy(json);
        return s;
    } else if (data_format == DF_STRING) {
        struct ds s;

        ds_init(&s);
        ovsdb_datum_to_string(datum, type, &s);
        return ds_steal_cstr(&s);
    } else {
        NOT_REACHED();
    }
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
dump_table(const struct ovsdb_table_schema *ts, struct json_array *rows)
{
    const struct ovsdb_column **columns;
    size_t n_columns;

    struct ovsdb_datum **data;

    struct dump_table_aux aux;
    struct shash_node *node;
    struct table t;
    size_t x, y;

    /* Sort columns by name, for reproducibility. */
    columns = xmalloc(shash_count(&ts->columns) * sizeof *columns);
    n_columns = 0;
    SHASH_FOR_EACH (node, &ts->columns) {
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
            ovs_fatal(0,  "row %zu in table %s response is not a JSON object: "
                      "%s", y, ts->name, json_to_string(rows->elems[y], 0));
        }
        row = json_object(rows->elems[y]);

        data[y] = xmalloc(n_columns * sizeof **data);
        for (x = 0; x < n_columns; x++) {
            const struct json *json = shash_find_data(row, columns[x]->name);
            if (!json) {
                ovs_fatal(0, "row %zu in table %s response lacks %s column",
                          y, ts->name, columns[x]->name);
            }

            check_ovsdb_error(ovsdb_datum_from_json(&data[y][x],
                                                    &columns[x]->type,
                                                    json, NULL));
        }
    }

    /* Sort rows by column values, for reproducibility. */
    aux.data = data;
    aux.columns = columns;
    aux.n_columns = n_columns;
    sort(rows->n, compare_rows, swap_rows, &aux);

    /* Add column headings. */
    table_init(&t);
    table_set_caption(&t, xasprintf("%s table", ts->name));
    for (x = 0; x < n_columns; x++) {
        table_add_column(&t, "%s", columns[x]->name);
    }

    /* Print rows. */
    for (y = 0; y < rows->n; y++) {
        table_add_row(&t);
        for (x = 0; x < n_columns; x++) {
            table_add_cell_nocopy(&t, format_data(&data[y][x],
                                                  &columns[x]->type));
        }
    }
    table_print(&t);
    table_destroy(&t);
}

static void
do_dump(int argc OVS_UNUSED, char *argv[])
{
    const char *server = argv[1];
    const char *database = argv[2];

    struct jsonrpc_msg *request, *reply;
    struct ovsdb_schema *schema;
    struct json *transaction;
    struct jsonrpc *rpc;
    int error;

    const struct shash_node **tables;
    size_t n_tables;

    size_t i;

    rpc = open_jsonrpc(server);

    schema = fetch_schema_from_rpc(rpc, database);
    tables = shash_sort(&schema->tables);
    n_tables = shash_count(&schema->tables);

    /* Construct transaction to retrieve entire database. */
    transaction = json_array_create_1(json_string_create(database));
    for (i = 0; i < n_tables; i++) {
        const struct ovsdb_table_schema *ts = tables[i]->data;
        struct json *op, *columns;
        struct shash_node *node;

        columns = json_array_create_empty();
        SHASH_FOR_EACH (node, &ts->columns) {
            const struct ovsdb_column *column = node->data;

            if (strcmp(column->name, "_version")) {
                json_array_add(columns, json_string_create(column->name));
            }
        }

        op = json_object_create();
        json_object_put_string(op, "op", "select");
        json_object_put_string(op, "table", tables[i]->name);
        json_object_put(op, "where", json_array_create_empty());
        json_object_put(op, "columns", columns);
        json_array_add(transaction, op);
    }

    /* Send request, get reply. */
    request = jsonrpc_create_request("transact", transaction, NULL);
    error = jsonrpc_transact_block(rpc, request, &reply);
    if (error) {
        ovs_fatal(error, "transaction failed");
    }

    /* Print database contents. */
    if (reply->result->type != JSON_ARRAY
        || reply->result->u.array.n != n_tables) {
        ovs_fatal(0, "reply is not array of %zu elements: %s",
                  n_tables, json_to_string(reply->result, 0));
    }
    for (i = 0; i < n_tables; i++) {
        const struct ovsdb_table_schema *ts = tables[i]->data;
        const struct json *op_result = reply->result->u.array.elems[i];
        struct json *rows;

        if (op_result->type != JSON_OBJECT
            || !(rows = shash_find_data(json_object(op_result), "rows"))
            || rows->type != JSON_ARRAY) {
            ovs_fatal(0, "%s table reply is not an object with a \"rows\" "
                      "member array: %s",
                      ts->name, json_to_string(op_result, 0));
        }

        dump_table(ts, &rows->u.array);
    }
}

static void
do_help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
}

static const struct command all_commands[] = {
    { "list-dbs", 1, 1, do_list_dbs },
    { "get-schema", 2, 2, do_get_schema },
    { "list-tables", 2, 2, do_list_tables },
    { "list-columns", 2, 3, do_list_columns },
    { "transact", 2, 2, do_transact },
    { "monitor", 3, INT_MAX, do_monitor },
    { "dump", 2, 2, do_dump },
    { "help", 0, INT_MAX, do_help },
    { NULL, 0, 0, NULL },
};
