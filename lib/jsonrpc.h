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

#ifndef JSONRPC_H
#define JSONRPC_H 1

/* This is an implementation of the JSON-RPC 1.0 specification defined at
 * http://json-rpc.org/wiki/specification. */

#include <stdbool.h>
#include <stddef.h>

struct json;
struct jsonrpc_msg;
struct stream;

/* API for a JSON-RPC stream. */

struct jsonrpc *jsonrpc_open(struct stream *);
void jsonrpc_close(struct jsonrpc *);

void jsonrpc_run(struct jsonrpc *);
void jsonrpc_wait(struct jsonrpc *);

void jsonrpc_error(struct jsonrpc *, int error);
int jsonrpc_get_status(const struct jsonrpc *);
size_t jsonrpc_get_backlog(const struct jsonrpc *);
const char *jsonrpc_get_name(const struct jsonrpc *);

int jsonrpc_send(struct jsonrpc *, struct jsonrpc_msg *);
int jsonrpc_recv(struct jsonrpc *, struct jsonrpc_msg **);
void jsonrpc_recv_wait(struct jsonrpc *);

int jsonrpc_send_block(struct jsonrpc *, struct jsonrpc_msg *);
int jsonrpc_recv_block(struct jsonrpc *, struct jsonrpc_msg **);

/* Messages. */
enum jsonrpc_msg_type {
    JSONRPC_REQUEST,           /* Request. */
    JSONRPC_NOTIFY,            /* Notification. */
    JSONRPC_REPLY,             /* Successful reply. */
    JSONRPC_ERROR              /* Error reply. */
};

struct jsonrpc_msg {
    enum jsonrpc_msg_type type;
    char *method;               /* Request or notification only. */
    struct json *params;        /* Request or notification only. */
    struct json *result;        /* Successful reply only. */
    struct json *error;         /* Error reply only. */
    struct json *id;            /* Request or reply only. */
};

struct jsonrpc_msg *jsonrpc_create_request(const char *method,
                                           struct json *params);
struct jsonrpc_msg *jsonrpc_create_notify(const char *method,
                                          struct json *params);
struct jsonrpc_msg *jsonrpc_create_reply(struct json *result,
                                         const struct json *id);
struct jsonrpc_msg *jsonrpc_create_error(struct json *error,
                                         const struct json *id);

const char *jsonrpc_msg_type_to_string(enum jsonrpc_msg_type);
char *jsonrpc_msg_is_valid(const struct jsonrpc_msg *);
void jsonrpc_msg_destroy(struct jsonrpc_msg *);

char *jsonrpc_msg_from_json(struct json *, struct jsonrpc_msg **);
struct json *jsonrpc_msg_to_json(struct jsonrpc_msg *);

#endif /* jsonrpc.h */
