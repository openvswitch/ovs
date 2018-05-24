/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#undef NDEBUG
#include "jsonrpc.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "command-line.h"
#include "daemon.h"
#include "openvswitch/json.h"
#include "ovstest.h"
#include "openvswitch/poll-loop.h"
#include "stream-ssl.h"
#include "stream.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);
static struct ovs_cmdl_command *get_all_commands(void);

static void
test_jsonrpc_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = { .argc = 0, };
    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, get_all_commands());
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_BOOTSTRAP_CA_CERT = UCHAR_MAX + 1,
        DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"verbose", optional_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        DAEMON_LONG_OPTIONS,
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        DAEMON_OPTION_HANDLERS

        STREAM_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
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
    printf("%s: JSON-RPC test utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "  listen LOCAL             listen for connections on LOCAL\n"
           "  request REMOTE METHOD PARAMS   send request, print reply\n"
           "  notify REMOTE METHOD PARAMS  send notification and exit\n",
           program_name, program_name);
    stream_usage("JSON-RPC", true, true, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help                  display this help message\n");
    exit(EXIT_SUCCESS);
}

/* Command helper functions. */

static struct json *
parse_json(const char *s)
{
    struct json *json = json_from_string(s);
    if (json->type == JSON_STRING) {
        ovs_fatal(0, "\"%s\": %s", s, json->string);
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

/* Command implementations. */

static int
handle_rpc(struct jsonrpc *rpc, struct jsonrpc_msg *msg, bool *done)
{
    if (msg->type == JSONRPC_REQUEST) {
        struct jsonrpc_msg *reply = NULL;
        if (!strcmp(msg->method, "echo")) {
            reply = jsonrpc_create_reply(json_clone(msg->params), msg->id);
        } else {
            struct json *error = json_object_create();
            json_object_put_string(error, "error", "unknown method");
            reply = jsonrpc_create_error(error, msg->id);
            ovs_error(0, "unknown request %s", msg->method);
        }
        jsonrpc_send(rpc, reply);
        return 0;
    } else if (msg->type == JSONRPC_NOTIFY) {
        if (!strcmp(msg->method, "shutdown")) {
            *done = true;
            return 0;
        } else {
            ovs_error(0, "unknown notification %s", msg->method);
            return ENOTTY;
        }
    } else {
        ovs_error(0, "unsolicited JSON-RPC reply or error");
        return EPROTO;
    }
}

static void
do_listen(struct ovs_cmdl_context *ctx)
{
    struct pstream *pstream;
    struct jsonrpc **rpcs;
    size_t n_rpcs, allocated_rpcs;
    bool done;
    int error;

    error = jsonrpc_pstream_open(ctx->argv[1], &pstream, DSCP_DEFAULT);
    if (error) {
        ovs_fatal(error, "could not listen on \"%s\"", ctx->argv[1]);
    }

    daemonize();

    rpcs = NULL;
    n_rpcs = allocated_rpcs = 0;
    done = false;
    for (;;) {
        struct stream *stream;
        size_t i;

        /* Accept new connections. */
        error = pstream_accept(pstream, &stream);
        if (!error) {
            if (n_rpcs >= allocated_rpcs) {
                rpcs = x2nrealloc(rpcs, &allocated_rpcs, sizeof *rpcs);
            }
            rpcs[n_rpcs++] = jsonrpc_open(stream);
        } else if (error != EAGAIN) {
            ovs_fatal(error, "pstream_accept failed");
        }

        /* Service existing connections. */
        for (i = 0; i < n_rpcs; ) {
            struct jsonrpc *rpc = rpcs[i];
            struct jsonrpc_msg *msg;

            jsonrpc_run(rpc);
            if (!jsonrpc_get_backlog(rpc)) {
                error = jsonrpc_recv(rpc, &msg);
                if (!error) {
                    error = handle_rpc(rpc, msg, &done);
                    jsonrpc_msg_destroy(msg);
                } else if (error == EAGAIN) {
                    error = 0;
                }
            }

            if (!error) {
                error = jsonrpc_get_status(rpc);
            }
            if (error) {
                jsonrpc_close(rpc);
                ovs_error(error, "connection closed");
                memmove(&rpcs[i], &rpcs[i + 1],
                        (n_rpcs - i - 1) * sizeof *rpcs);
                n_rpcs--;
            } else {
                i++;
            }
        }

        /* Wait for something to do. */
        if (done && !n_rpcs) {
            break;
        }
        pstream_wait(pstream);
        for (i = 0; i < n_rpcs; i++) {
            struct jsonrpc *rpc = rpcs[i];

            jsonrpc_wait(rpc);
            if (!jsonrpc_get_backlog(rpc)) {
                jsonrpc_recv_wait(rpc);
            }
        }
        poll_block();
    }
    free(rpcs);
    pstream_close(pstream);
}

static void
do_request(struct ovs_cmdl_context *ctx)
{
    struct jsonrpc_msg *msg;
    struct jsonrpc *rpc;
    struct json *params;
    struct stream *stream;
    const char *method;
    char *string;
    int error;

    method = ctx->argv[2];
    params = parse_json(ctx->argv[3]);
    msg = jsonrpc_create_request(method, params, NULL);
    string = jsonrpc_msg_is_valid(msg);
    if (string) {
        ovs_fatal(0, "not a valid JSON-RPC request: %s", string);
    }

    error = stream_open_block(jsonrpc_stream_open(ctx->argv[1], &stream,
                              DSCP_DEFAULT), &stream);
    if (error) {
        ovs_fatal(error, "could not open \"%s\"", ctx->argv[1]);
    }
    rpc = jsonrpc_open(stream);

    error = jsonrpc_send(rpc, msg);
    if (error) {
        ovs_fatal(error, "could not send request");
    }

    error = jsonrpc_recv_block(rpc, &msg);
    if (error) {
        ovs_fatal(error, "error waiting for reply");
    }
    print_and_free_json(jsonrpc_msg_to_json(msg));

    jsonrpc_close(rpc);
}

static void
do_notify(struct ovs_cmdl_context *ctx)
{
    struct jsonrpc_msg *msg;
    struct jsonrpc *rpc;
    struct json *params;
    struct stream *stream;
    const char *method;
    char *string;
    int error;

    method = ctx->argv[2];
    params = parse_json(ctx->argv[3]);
    msg = jsonrpc_create_notify(method, params);
    string = jsonrpc_msg_is_valid(msg);
    if (string) {
        ovs_fatal(0, "not a JSON RPC-valid notification: %s", string);
    }

    error = stream_open_block(jsonrpc_stream_open(ctx->argv[1], &stream,
                              DSCP_DEFAULT), &stream);
    if (error) {
        ovs_fatal(error, "could not open \"%s\"", ctx->argv[1]);
    }
    rpc = jsonrpc_open(stream);

    error = jsonrpc_send_block(rpc, msg);
    if (error) {
        ovs_fatal(error, "could not send notification");
    }
    jsonrpc_close(rpc);
}

static void
do_help(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    usage();
}

static struct ovs_cmdl_command all_commands[] = {
    { "listen", NULL, 1, 1, do_listen, OVS_RO },
    { "request", NULL, 3, 3, do_request, OVS_RO },
    { "notify", NULL, 3, 3, do_notify, OVS_RO },
    { "help", NULL, 0, INT_MAX, do_help, OVS_RO },
    { NULL, NULL, 0, 0, NULL, OVS_RO },
};

static struct ovs_cmdl_command *
get_all_commands(void)
{
    return all_commands;
}

OVSTEST_REGISTER("test-jsonrpc", test_jsonrpc_main);
