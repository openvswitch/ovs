/* Copyright (c) 2011, 2012 Nicira, Inc.
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
#include "shash.h"

struct ovsdb;
struct ovsdb_server;

/* Abstract representation of an OVSDB client connection, not tied to any
 * particular network protocol.  Protocol implementations
 * (e.g. jsonrpc-server.c) embed this in a larger data structure.  */
struct ovsdb_session {
    struct ovsdb_server *server;
    struct list completions;    /* Completed triggers. */
    struct hmap waiters;        /* "ovsdb_lock_waiter *"s by lock name. */
};

void ovsdb_session_init(struct ovsdb_session *, struct ovsdb_server *);
void ovsdb_session_destroy(struct ovsdb_session *);

struct ovsdb_lock_waiter *ovsdb_session_get_lock_waiter(
    const struct ovsdb_session *, const char *lock_name);

/* A database lock.
 *
 * A lock always has one or more "lock waiters" kept on a list.  The waiter at
 * the head of the list owns the lock. */
struct ovsdb_lock {
    struct hmap_node hmap_node;  /* In ovsdb_server's "locks" hmap. */
    struct ovsdb_server *server; /* The containing server. */
    char *name;                  /* Unique name. */
    struct list waiters;         /* Contains "struct ovsdb_lock_waiter"s. */
};

struct ovsdb_lock_waiter *ovsdb_lock_get_owner(const struct ovsdb_lock *);

/* How to obtain a lock. */
enum ovsdb_lock_mode {
    OVSDB_LOCK_WAIT,            /* By waiting for it to become available. */
    OVSDB_LOCK_STEAL            /* By stealing it from the owner. */
};

/* A session's request for a database lock. */
struct ovsdb_lock_waiter {
    struct hmap_node session_node; /* In ->session->locks's hmap. */
    struct ovsdb_lock *lock;    /* The lock being waited for. */

    enum ovsdb_lock_mode mode;
    char *lock_name;

    struct ovsdb_session *session;
    struct list lock_node;      /* In ->lock->waiters's list. */
};

struct ovsdb_session *ovsdb_lock_waiter_remove(struct ovsdb_lock_waiter *);
void ovsdb_lock_waiter_destroy(struct ovsdb_lock_waiter *);
bool ovsdb_lock_waiter_is_owner(const struct ovsdb_lock_waiter *);

/* Abstract representation of an OVSDB server not tied to any particular
 * network protocol.  Protocol implementations (e.g. jsonrpc-server.c) embed
 * this in a larger data structure.  */
struct ovsdb_server {
    struct shash dbs;      /* Maps from a db name to a "struct ovsdb *". */
    struct hmap locks;     /* Contains "struct ovsdb_lock"s indexed by name. */
};

void ovsdb_server_init(struct ovsdb_server *);
bool ovsdb_server_add_db(struct ovsdb_server *, struct ovsdb *);
void ovsdb_server_destroy(struct ovsdb_server *);

struct ovsdb_lock_waiter *ovsdb_server_lock(struct ovsdb_server *,
                                            struct ovsdb_session *,
                                            const char *lock_name,
                                            enum ovsdb_lock_mode,
                                            struct ovsdb_session **victimp);

#endif /* ovsdb/server.h */
