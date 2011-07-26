/* Copyright (c) 2011 Nicira Networks
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

#ifndef SERVER_H
#define SERVER_H 1

#include "hmap.h"
#include "list.h"

/* Abstract representation of an OVSDB client connection, not tied to any
 * particular network protocol.  Protocol implementations
 * (e.g. jsonrpc-server.c) embed this in a larger data structure.  */
struct ovsdb_session {
    struct ovsdb *db;
    struct list completions;    /* Completed triggers. */
};

void ovsdb_session_init(struct ovsdb_session *, struct ovsdb *);
void ovsdb_session_destroy(struct ovsdb_session *);

/* Abstract representation of an OVSDB server not tied to any particular
 * network protocol.  Protocol implementations (e.g. jsonrpc-server.c) embed
 * this in a larger data structure.  */
struct ovsdb_server {
    struct ovsdb *db;
};

void ovsdb_server_init(struct ovsdb_server *, struct ovsdb *);
void ovsdb_server_destroy(struct ovsdb_server *);

#endif /* ovsdb/server.h */
