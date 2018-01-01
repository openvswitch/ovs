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

#include <config.h>

#include "server.h"

#include "hash.h"
#include "ovsdb.h"
#include "uuid.h"

/* Initializes 'session' as a session within 'server'. */
void
ovsdb_session_init(struct ovsdb_session *session, struct ovsdb_server *server)
{
    session->server = server;
    ovs_list_init(&session->completions);
    hmap_init(&session->waiters);
}

/* Destroys 'session'. */
void
ovsdb_session_destroy(struct ovsdb_session *session)
{
    ovs_assert(hmap_is_empty(&session->waiters));
    hmap_destroy(&session->waiters);
}

/* Searches 'session' for an ovsdb_lock_waiter named 'lock_name' and returns
 * it if it finds one, otherwise NULL. */
struct ovsdb_lock_waiter *
ovsdb_session_get_lock_waiter(const struct ovsdb_session *session,
                              const char *lock_name)
{
    struct ovsdb_lock_waiter *waiter;

    HMAP_FOR_EACH_WITH_HASH (waiter, session_node, hash_string(lock_name, 0),
                             &session->waiters) {
        if (!strcmp(lock_name, waiter->lock_name)) {
            return waiter;
        }
    }
    return NULL;
}

/* Returns the waiter that owns 'lock'.
 *
 * A lock always has an owner, so this function will never return NULL. */
struct ovsdb_lock_waiter *
ovsdb_lock_get_owner(const struct ovsdb_lock *lock)
{
    return CONTAINER_OF(ovs_list_front(&lock->waiters),
                        struct ovsdb_lock_waiter, lock_node);
}

/* Removes 'waiter' from its lock's list.  This means that, if 'waiter' was
 * formerly the owner of its lock, then it no longer owns it.
 *
 * Returns the session that now owns 'waiter'.  This is NULL if 'waiter' was
 * the lock's owner and no other sessions were waiting for the lock.  In this
 * case, the lock has been destroyed, so the caller must be sure not to refer
 * to it again.  A nonnull return value reflects a change in the lock's
 * ownership if and only if 'waiter' formerly owned the lock. */
struct ovsdb_session *
ovsdb_lock_waiter_remove(struct ovsdb_lock_waiter *waiter)
{
    struct ovsdb_lock *lock = waiter->lock;

    ovs_list_remove(&waiter->lock_node);
    waiter->lock = NULL;

    if (ovs_list_is_empty(&lock->waiters)) {
        hmap_remove(&lock->server->locks, &lock->hmap_node);
        free(lock->name);
        free(lock);
        return NULL;
    }

    return ovsdb_lock_get_owner(lock)->session;
}

/* Destroys 'waiter', which must have already been removed from its lock's
 * waiting list with ovsdb_lock_waiter_remove().
 *
 * Removing and destroying locks are decoupled because a lock initially created
 * by the "steal" request, that is later stolen by another client, remains in
 * the database session until the database client sends an "unlock" request. */
void
ovsdb_lock_waiter_destroy(struct ovsdb_lock_waiter *waiter)
{
    ovs_assert(!waiter->lock);
    hmap_remove(&waiter->session->waiters, &waiter->session_node);
    free(waiter->lock_name);
    free(waiter);
}

/* Returns true if 'waiter' owns its associated lock. */
bool
ovsdb_lock_waiter_is_owner(const struct ovsdb_lock_waiter *waiter)
{
    return waiter->lock && waiter == ovsdb_lock_get_owner(waiter->lock);
}

/* Initializes 'server'.
 *
 * The caller must call ovsdb_server_add_db() for each database to which
 * 'server' should provide access. */
void
ovsdb_server_init(struct ovsdb_server *server)
{
    shash_init(&server->dbs);
    hmap_init(&server->locks);
    uuid_generate(&server->uuid);
}

/* Adds 'db' to the set of databases served out by 'server'.  Returns true if
 * successful, false if 'db''s name is the same as some database already in
 * 'server'. */
bool
ovsdb_server_add_db(struct ovsdb_server *server, struct ovsdb *db)
{
    return shash_add_once(&server->dbs, db->name, db);
}

/* Removes 'db' from the set of databases served out by 'server'. */
void
ovsdb_server_remove_db(struct ovsdb_server *server, struct ovsdb *db)
{
    shash_find_and_delete_assert(&server->dbs, db->name);
}

/* Destroys 'server'. */
void
ovsdb_server_destroy(struct ovsdb_server *server)
{
    shash_destroy(&server->dbs);
    hmap_destroy(&server->locks);
}

static struct ovsdb_lock *
ovsdb_server_create_lock__(struct ovsdb_server *server, const char *lock_name,
                           uint32_t hash)
{
    struct ovsdb_lock *lock;

    HMAP_FOR_EACH_WITH_HASH (lock, hmap_node, hash, &server->locks) {
        if (!strcmp(lock->name, lock_name)) {
            return lock;
        }
    }

    lock = xzalloc(sizeof *lock);
    lock->server = server;
    lock->name = xstrdup(lock_name);
    hmap_insert(&server->locks, &lock->hmap_node, hash);
    ovs_list_init(&lock->waiters);

    return lock;
}

/* Attempts to acquire the lock named 'lock_name' for 'session' within
 * 'server'.  Returns the new lock waiter.
 *
 * If 'mode' is OVSDB_LOCK_STEAL, then the new lock waiter is always the owner
 * of the lock.  '*victimp' receives the session of the previous owner or NULL
 * if the lock was previously unowned.  (If the victim itself originally
 * obtained the lock through a "steal" operation, then this function also
 * removes the victim from the lock's waiting list.)
 *
 * If 'mode' is OVSDB_LOCK_WAIT, then the new lock waiter is the owner of the
 * lock only if this lock had no existing owner.  '*victimp' is set to NULL. */
struct ovsdb_lock_waiter *
ovsdb_server_lock(struct ovsdb_server *server,
                  struct ovsdb_session *session,
                  const char *lock_name,
                  enum ovsdb_lock_mode mode,
                  struct ovsdb_session **victimp)
{
    uint32_t hash = hash_string(lock_name, 0);
    struct ovsdb_lock_waiter *waiter, *victim;
    struct ovsdb_lock *lock;

    lock = ovsdb_server_create_lock__(server, lock_name, hash);
    victim = (mode == OVSDB_LOCK_STEAL && !ovs_list_is_empty(&lock->waiters)
              ? ovsdb_lock_get_owner(lock)
              : NULL);

    waiter = xmalloc(sizeof *waiter);
    waiter->mode = mode;
    waiter->lock_name = xstrdup(lock_name);
    waiter->lock = lock;
    if (mode == OVSDB_LOCK_STEAL) {
        ovs_list_push_front(&lock->waiters, &waiter->lock_node);
    } else {
        ovs_list_push_back(&lock->waiters, &waiter->lock_node);
    }
    waiter->session = session;
    hmap_insert(&waiter->session->waiters, &waiter->session_node, hash);

    if (victim && victim->mode == OVSDB_LOCK_STEAL) {
        ovsdb_lock_waiter_remove(victim);
    }
    *victimp = victim ? victim->session : NULL;

    return waiter;
}
