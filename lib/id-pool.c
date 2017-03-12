/*
 * Copyright (c) 2014 Nicira, Inc.
 * Copyright (c) 2014 Netronome.
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
#include "id-pool.h"
#include "openvswitch/hmap.h"
#include "hash.h"

struct id_node {
    struct hmap_node node;
    uint32_t id;
};

struct id_pool {
    struct hmap map;
    uint32_t base;         /* IDs in the range of [base, base + n_ids). */
    uint32_t n_ids;        /* Total number of ids in the pool. */
    uint32_t next_free_id; /* Possible next free id. */
};

static void id_pool_init(struct id_pool *pool,
                         uint32_t base, uint32_t n_ids);
static void id_pool_uninit(struct id_pool *pool);
static struct id_node *id_pool_find(struct id_pool *pool, uint32_t id);

struct id_pool *
id_pool_create(uint32_t base, uint32_t n_ids)
{
    struct id_pool *pool;

    pool = xmalloc(sizeof *pool);
    id_pool_init(pool, base, n_ids);

    return pool;
}

void
id_pool_destroy(struct id_pool *pool)
{
    if (pool) {
        id_pool_uninit(pool);
        free(pool);
    }
}

static void
id_pool_init(struct id_pool *pool, uint32_t base, uint32_t n_ids)
{
    pool->base = base;
    pool->n_ids = n_ids;
    pool->next_free_id = base;
    hmap_init(&pool->map);
}

static void
id_pool_uninit(struct id_pool *pool)
{
    struct id_node *id_node;

    HMAP_FOR_EACH_POP(id_node, node, &pool->map) {
        free(id_node);
    }

    hmap_destroy(&pool->map);
}

static struct id_node *
id_pool_find(struct id_pool *pool, uint32_t id)
{
    size_t hash;
    struct id_node *id_node;

    hash = hash_int(id, 0);
    HMAP_FOR_EACH_WITH_HASH(id_node, node, hash, &pool->map) {
        if (id == id_node->id) {
            return id_node;
        }
    }
    return NULL;
}

void
id_pool_add(struct id_pool *pool, uint32_t id)
{
    struct id_node *id_node = xmalloc(sizeof *id_node);
    size_t hash;

    id_node->id = id;
    hash = hash_int(id, 0);
    hmap_insert(&pool->map, &id_node->node, hash);
}

bool
id_pool_alloc_id(struct id_pool *pool, uint32_t *id_)
{
    uint32_t id;

    if (pool->n_ids == 0) {
        return false;
    }

    if (!(id_pool_find(pool, pool->next_free_id))) {
        id = pool->next_free_id;
        goto found_free_id;
    }

    for(id = pool->base; id < pool->base + pool->n_ids; id++) {
        if (!id_pool_find(pool, id)) {
            goto found_free_id;
        }
    }

    /* Not available. */
    return false;

found_free_id:
    id_pool_add(pool, id);

    if (id + 1 < pool->base + pool->n_ids) {
        pool->next_free_id = id + 1;
    } else {
        pool->next_free_id = pool->base;
    }

    *id_ = id;
    return true;
}

void
id_pool_free_id(struct id_pool *pool, uint32_t id)
{
    struct id_node *id_node;
    if (id >= pool->base && (id < pool->base + pool->n_ids)) {
        id_node = id_pool_find(pool, id);
        if (id_node) {
            hmap_remove(&pool->map, &id_node->node);
            if (id < pool->next_free_id) {
                pool->next_free_id = id;
            }
            free(id_node);
        }
    }
}
