/*
 * Copyright (c) 2021 NVIDIA Corporation.
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

#include "openvswitch/list.h"
#include "openvswitch/thread.h"
#include "openvswitch/util.h"
#include "ovs-atomic.h"
#include "id-fpool.h"

#ifdef HAVE_PTHREAD_SPIN_LOCK
#define id_fpool_lock_type ovs_spin
#define id_fpool_lock_init(l) do { ovs_spin_init(l); } while (0)
#define id_fpool_lock_destroy(l) do { ovs_spin_destroy(l); } while (0)
#define id_fpool_lock(l) do { ovs_spin_lock(l); } while (0)
#define id_fpool_unlock(l) do { ovs_spin_unlock(l); } while (0)
#else
#define id_fpool_lock_type ovs_mutex
#define id_fpool_lock_init(l) do { ovs_mutex_init(l); } while (0)
#define id_fpool_lock_destroy(l) do { ovs_mutex_destroy(l); } while (0)
#define id_fpool_lock(l) do { ovs_mutex_lock(l); } while (0)
#define id_fpool_unlock(l) do { ovs_mutex_unlock(l); } while (0)
#endif

struct id_slab {
    struct ovs_list node;
    uint32_t pos;
    uint32_t ids[ID_FPOOL_CACHE_SIZE];
};

struct per_user {
PADDED_MEMBERS(CACHE_LINE_SIZE,
    struct id_fpool_lock_type user_lock;
    struct id_slab *slab;
);};

struct id_fpool {
    /* Constants */
    uint32_t floor; /* IDs are in the range of [floor, ceiling). */
    uint32_t ceiling;
    size_t nb_user; /* Number of concurrent users. */

    /* Shared mutable data protected by global lock. */
    struct id_fpool_lock_type pool_lock;
    struct ovs_list free_slabs;
    uint32_t next_id;

    /* Per-user mutable data protected by user locks. */
    struct per_user per_users[0];
};

/* Lock precedence is
 * 1: per_users.user_lock
 * 2: pool_lock
 */

static struct id_slab *
id_slab_create(uint32_t *next_id, uint32_t max)
{
    struct id_slab *slab;
    size_t n_ids;
    size_t pos;

    if (next_id[0] == max) {
        return NULL;
    }

    n_ids = max - next_id[0];
    slab = xmalloc(sizeof *slab);
    ovs_list_init(&slab->node);
    slab->pos = 0;

    for (pos = MIN(n_ids, ARRAY_SIZE(slab->ids)); pos > 0; pos--) {
        slab->ids[pos - 1] = next_id[0];
        next_id[0]++;
        slab->pos++;
    }

    return slab;
}

static bool
id_slab_insert(struct id_slab *slab, uint32_t id)
{
    if (slab == NULL) {
        return false;
    }
    if (slab->pos >= ARRAY_SIZE(slab->ids)) {
        return false;
    }
    slab->ids[slab->pos++] = id;
    return true;
}

static bool
id_slab_remove(struct id_slab *slab, uint32_t *id)
{
    if (slab == NULL) {
        return false;
    }
    if (slab->pos == 0) {
        return false;
    }
    *id = slab->ids[--slab->pos];
    return true;
}

static void
per_user_init(struct per_user *pu, uint32_t *next_id, uint32_t max)
{
    id_fpool_lock_init(&pu->user_lock);
    pu->slab = id_slab_create(next_id, max);
}

static void
per_user_destroy(struct per_user *pu)
{
    id_fpool_lock(&pu->user_lock);
    free(pu->slab);
    pu->slab = NULL;
    id_fpool_unlock(&pu->user_lock);
    id_fpool_lock_destroy(&pu->user_lock);
}

struct id_fpool *
id_fpool_create(unsigned int nb_user, uint32_t floor, uint32_t n_ids)
{
    struct id_fpool *pool;
    size_t i;

    ovs_assert(nb_user != 0);
    ovs_assert(floor <= UINT32_MAX - n_ids);

    pool = xmalloc(sizeof *pool + nb_user * sizeof(struct per_user));
    pool->next_id = floor;
    pool->floor = floor;
    pool->ceiling = floor + n_ids;

    for (i = 0; i < nb_user; i++) {
        per_user_init(&pool->per_users[i],
                      &pool->next_id, pool->ceiling);
    }
    pool->nb_user = nb_user;

    id_fpool_lock_init(&pool->pool_lock);
    ovs_list_init(&pool->free_slabs);

    return pool;
}

void
id_fpool_destroy(struct id_fpool *pool)
{
    struct id_slab *slab;
    size_t i;

    id_fpool_lock(&pool->pool_lock);
    LIST_FOR_EACH_SAFE (slab, node, &pool->free_slabs) {
        free(slab);
    }
    ovs_list_poison(&pool->free_slabs);
    id_fpool_unlock(&pool->pool_lock);
    id_fpool_lock_destroy(&pool->pool_lock);

    for (i = 0; i < pool->nb_user; i++) {
        per_user_destroy(&pool->per_users[i]);
    }
    free(pool);
}

bool
id_fpool_new_id(struct id_fpool *pool, unsigned int uid, uint32_t *id)
{
    struct per_user *pu;
    unsigned int uid2;
    bool res = false;

    ovs_assert(uid < pool->nb_user);
    pu = &pool->per_users[uid];

    id_fpool_lock(&pu->user_lock);

    if (id_slab_remove(pu->slab, id)) {
        res = true;
        goto unlock_and_ret;
    }
    free(pu->slab);

    id_fpool_lock(&pool->pool_lock);
    if (!ovs_list_is_empty(&pool->free_slabs)) {
        pu->slab = CONTAINER_OF(ovs_list_pop_front(&pool->free_slabs),
                                struct id_slab, node);
    } else {
        pu->slab = id_slab_create(&pool->next_id, pool->ceiling);
    }
    id_fpool_unlock(&pool->pool_lock);

    if (pu->slab != NULL) {
        res = id_slab_remove(pu->slab, id);
        goto unlock_and_ret;
    }

    id_fpool_unlock(&pu->user_lock);

    /* No ID available in local slab, no slab available in shared list.
     * The shared counter is maxed out. Attempt to steal an ID from another
     * user slab. */

    for (uid2 = 0; uid2 < pool->nb_user; uid2++) {
        struct per_user *pu2 = &pool->per_users[uid2];

        if (uid == uid2) {
            continue;
        }
        id_fpool_lock(&pu2->user_lock);;
        res = id_slab_remove(pu2->slab, id);
        id_fpool_unlock(&pu2->user_lock);;
        if (res) {
            break;
        }
    }

    goto out;

unlock_and_ret:
    id_fpool_unlock(&pu->user_lock);
out:
    return res;
}

void
id_fpool_free_id(struct id_fpool *pool, unsigned int uid, uint32_t id)
{
    struct per_user *pu;

    if (id < pool->floor || id >= pool->ceiling) {
        return;
    }

    ovs_assert(uid < pool->nb_user);
    pu = &pool->per_users[uid];

    id_fpool_lock(&pu->user_lock);

    if (pu->slab == NULL) {
        /* Create local slab with a single ID. */
        pu->slab = id_slab_create(&id, id + 1);
        goto unlock;
    }

    if (id_slab_insert(pu->slab, id)) {
        goto unlock;
    }

    id_fpool_lock(&pool->pool_lock);
    ovs_list_push_back(&pool->free_slabs, &pu->slab->node);
    id_fpool_unlock(&pool->pool_lock);

    /* Create local slab with a single ID. */
    pu->slab = id_slab_create(&id, id + 1);

unlock:
    id_fpool_unlock(&pu->user_lock);
}
