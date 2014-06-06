/*
 * Copyright (c) 2014 Nicira, Inc.
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

#include "hmap.h"
#include "hash.h"
#include "ovs-thread.h"
#include "ofproto-dpif-rid.h"

struct rid_map {
    struct hmap map;
};

struct rid_node {
    struct hmap_node node;
    uint32_t recirc_id;
};

struct rid_pool {
    struct rid_map ridmap;
    uint32_t base;         /* IDs in the range of [base, base + n_ids). */
    uint32_t n_ids;        /* Total number of ids in the pool. */
    uint32_t next_free_id; /* Possible next free id. */
};

struct recirc_id_pool {
    struct ovs_mutex lock;
    struct rid_pool rids;
};

#define RECIRC_ID_BASE  300
#define RECIRC_ID_N_IDS  1024

static void rid_pool_init(struct rid_pool *rids,
                         uint32_t base, uint32_t n_ids);
static void rid_pool_uninit(struct rid_pool *pool);
static uint32_t rid_pool_alloc_id(struct rid_pool *pool);
static void rid_pool_free_id(struct rid_pool *rids, uint32_t rid);
static struct rid_node *rid_pool_find(struct rid_pool *rids, uint32_t id);
static struct rid_node *rid_pool_add(struct rid_pool *rids, uint32_t id);

struct recirc_id_pool *
recirc_id_pool_create(void)
{
    struct recirc_id_pool *pool;

    pool = xmalloc(sizeof *pool);
    rid_pool_init(&pool->rids, RECIRC_ID_BASE, RECIRC_ID_N_IDS);
    ovs_mutex_init(&pool->lock);

    return pool;
}

void
recirc_id_pool_destroy(struct recirc_id_pool *pool)
{
    rid_pool_uninit(&pool->rids);
    ovs_mutex_destroy(&pool->lock);
    free(pool);
}

uint32_t
recirc_id_alloc(struct recirc_id_pool *pool)
{
    uint32_t id;

    ovs_mutex_lock(&pool->lock);
    id = rid_pool_alloc_id(&pool->rids);
    ovs_mutex_unlock(&pool->lock);

    return id;
}

void
recirc_id_free(struct recirc_id_pool *pool, uint32_t id)
{
    ovs_mutex_lock(&pool->lock);
    rid_pool_free_id(&pool->rids, id);
    ovs_mutex_unlock(&pool->lock);
}

static void
rid_pool_init(struct rid_pool *rids, uint32_t base, uint32_t n_ids)
{
    rids->base = base;
    rids->n_ids = n_ids;
    rids->next_free_id = base;
    hmap_init(&rids->ridmap.map);
}

static void
rid_pool_uninit(struct rid_pool *rids)
{
    struct rid_node *rid, *next;

    HMAP_FOR_EACH_SAFE(rid, next, node, &rids->ridmap.map) {
        hmap_remove(&rids->ridmap.map, &rid->node);
        free(rid);
    }

    hmap_destroy(&rids->ridmap.map);
}

static struct rid_node *
rid_pool_find(struct rid_pool *rids, uint32_t id)
{
    size_t hash;
    struct rid_node *rid;

    hash = hash_int(id, 0);
    HMAP_FOR_EACH_WITH_HASH(rid, node, hash, &rids->ridmap.map) {
        if (id == rid->recirc_id) {
            return rid;
        }
    }
    return NULL;
}

static struct rid_node *
rid_pool_add(struct rid_pool *rids, uint32_t id)
{
    struct rid_node *rid = xmalloc(sizeof *rid);
    size_t hash;

    rid->recirc_id = id;
    hash = hash_int(id, 0);
    hmap_insert(&rids->ridmap.map, &rid->node, hash);
    return rid;
}

static uint32_t
rid_pool_alloc_id(struct rid_pool *rids)
{
    uint32_t id;

    if (rids->n_ids == 0) {
        return 0;
    }

    if (!(rid_pool_find(rids, rids->next_free_id))) {
        id = rids->next_free_id;
        goto found_free_id;
    }

    for(id = rids->base; id < rids->base + rids->n_ids; id++) {
        if (rid_pool_find(rids, id)) {
            goto found_free_id;
        }
    }

    /* Not available. */
    return 0;

found_free_id:
    rid_pool_add(rids, id);

    if (id < rids->base + rids->n_ids) {
        rids->next_free_id = id + 1;
    } else {
        rids->next_free_id = rids->base;
    }

    return id;
}

static void
rid_pool_free_id(struct rid_pool *rids, uint32_t id)
{
    struct rid_node *rid;
    if (id > rids->base && (id <= rids->base + rids->n_ids)) {
        rid = rid_pool_find(rids, id);
        if (rid) {
            hmap_remove(&rids->ridmap.map, &rid->node);
        }
    }
}
