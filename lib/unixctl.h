/*
 * Copyright (c) 2008, 2009, 2011 Nicira, Inc.
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

#ifndef UNIXCTL_H
#define UNIXCTL_H 1

#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct json;
enum unixctl_output_fmt {
    UNIXCTL_OUTPUT_FMT_TEXT = 1 << 0,
    UNIXCTL_OUTPUT_FMT_JSON = 1 << 1,
};

const char *unixctl_output_fmt_to_string(enum unixctl_output_fmt);
bool unixctl_output_fmt_from_string(const char *, enum unixctl_output_fmt *);

/* Server for Unix domain socket control connection. */
struct unixctl_server;
int unixctl_server_create(const char *path, struct unixctl_server **);
void unixctl_server_run(struct unixctl_server *);
void unixctl_server_wait(struct unixctl_server *);
void unixctl_server_destroy(struct unixctl_server *);

const char *unixctl_server_get_path(const struct unixctl_server *);

/* Client for Unix domain socket control connection. */
struct jsonrpc;
int unixctl_client_create(const char *path, struct jsonrpc **client);
int unixctl_client_transact(struct jsonrpc *client,
                            const char *command,
                            int argc, char *argv[],
                            struct json **result, struct json **error);

/* Command registration. */
struct unixctl_conn;
typedef void unixctl_cb_func(struct unixctl_conn *,
                             int argc, const char *argv[], void *aux);
void unixctl_command_register(const char *name, const char *usage,
                              int min_args, int max_args,
                              unixctl_cb_func *cb, void *aux);
enum unixctl_output_fmt unixctl_command_get_output_format(
    struct unixctl_conn *);
void unixctl_command_reply_error(struct unixctl_conn *, const char *error);
void unixctl_command_reply(struct unixctl_conn *, const char *body);
void unixctl_command_reply_json(struct unixctl_conn *,
                                struct json *body);

#ifdef  __cplusplus
}
#endif

#endif /* unixctl.h */
