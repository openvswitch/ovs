/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#ifdef  __cplusplus
extern "C" {
#endif

/* Server for Unix domain socket control connection. */
struct unixctl_server;
int unixctl_server_create(const char *path, struct unixctl_server **);
void unixctl_server_run(struct unixctl_server *);
void unixctl_server_wait(struct unixctl_server *);
void unixctl_server_destroy(struct unixctl_server *);

/* Client for Unix domain socket control connection. */
struct unixctl_client;
int unixctl_client_create(const char *path, struct unixctl_client **);
void unixctl_client_destroy(struct unixctl_client *);
int unixctl_client_transact(struct unixctl_client *,
                            const char *request,
                            int *reply_code, char **reply_body);
const char *unixctl_client_target(const struct unixctl_client *);

/* Command registration. */
struct unixctl_conn;
typedef void unixctl_cb_func(struct unixctl_conn *,
                             const char *args, void *aux);
void unixctl_command_register(const char *name,
                              unixctl_cb_func *cb, void *aux);
void unixctl_command_reply(struct unixctl_conn *, int code,
                           const char *body);

#ifdef  __cplusplus
}
#endif

#endif /* unixctl.h */
