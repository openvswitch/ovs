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

#include <config.h>

#include "server.h"

/* Initializes 'session' as a session that operates on 'db'. */
void
ovsdb_session_init(struct ovsdb_session *session, struct ovsdb *db)
{
    session->db = db;
    list_init(&session->completions);
}

/* Destroys 'session'. */
void
ovsdb_session_destroy(struct ovsdb_session *session OVS_UNUSED)
{
}

/* Initializes 'server' as a server that operates on 'db'. */
void
ovsdb_server_init(struct ovsdb_server *server, struct ovsdb *db)
{
    server->db = db;
}

/* Destroys 'server'. */
void
ovsdb_server_destroy(struct ovsdb_server *server OVS_UNUSED)
{
}
