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

#include "id-pool.h"
#include "ovs-thread.h"
#include "ofproto-dpif-rid.h"

struct recirc_id_pool {
    struct ovs_mutex lock;
    struct id_pool *rids;
};

#define RECIRC_ID_BASE  300
#define RECIRC_ID_N_IDS  1024

struct recirc_id_pool *
recirc_id_pool_create(void)
{
    struct recirc_id_pool *pool;

    pool = xmalloc(sizeof *pool);
    pool->rids = id_pool_create(RECIRC_ID_BASE, RECIRC_ID_N_IDS);
    ovs_mutex_init(&pool->lock);

    return pool;
}

void
recirc_id_pool_destroy(struct recirc_id_pool *pool)
{
    id_pool_destroy(pool->rids);
    ovs_mutex_destroy(&pool->lock);
    free(pool);
}

uint32_t
recirc_id_alloc(struct recirc_id_pool *pool)
{
    uint32_t id;
    bool ret;

    ovs_mutex_lock(&pool->lock);
    ret = id_pool_alloc_id(pool->rids, &id);
    ovs_mutex_unlock(&pool->lock);

    if (!ret) {
        return 0;
    }

    return id;
}

void
recirc_id_free(struct recirc_id_pool *pool, uint32_t id)
{
    ovs_mutex_lock(&pool->lock);
    id_pool_free_id(pool->rids, id);
    ovs_mutex_unlock(&pool->lock);
}
