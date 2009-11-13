/* Copyright (c) 2009 Nicira Networks
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

#ifndef OVSDB_JSONRPC_SERVER_H
#define OVSDB_JSONRPC_SERVER_H 1

struct ovsdb;

struct ovsdb_jsonrpc_server *ovsdb_jsonrpc_server_create(struct ovsdb *);

int ovsdb_jsonrpc_server_listen(struct ovsdb_jsonrpc_server *,
                                const char *name);
void ovsdb_jsonrpc_server_connect(struct ovsdb_jsonrpc_server *,
                                  const char *name);

void ovsdb_jsonrpc_server_run(struct ovsdb_jsonrpc_server *);
void ovsdb_jsonrpc_server_wait(struct ovsdb_jsonrpc_server *);

#endif /* ovsdb/jsonrpc-server.h */
