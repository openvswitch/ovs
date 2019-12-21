/*
 * Copyright (c) 2017 DtDream Technology Co.,Ltd.
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
#include <string.h>

#include "bitmap.h"
#include "hash.h"
#include "lib/uuid.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/extend-table.h"

VLOG_DEFINE_THIS_MODULE(extend_table);

void
ovn_extend_table_init(struct ovn_extend_table *table)
{
    table->table_ids = bitmap_allocate(MAX_EXT_TABLE_ID);
    bitmap_set1(table->table_ids, 0); /* table id 0 is invalid. */
    hmap_init(&table->desired);
    hmap_init(&table->lflow_to_desired);
    hmap_init(&table->existing);
}

static struct ovn_extend_table_info *
ovn_extend_table_info_alloc(const char *name, uint32_t id, bool is_new_id,
                            uint32_t hash)
{
    struct ovn_extend_table_info *e = xmalloc(sizeof *e);
    e->name = xstrdup(name);
    e->table_id = id;
    e->new_table_id = is_new_id;
    e->hmap_node.hash = hash;
    hmap_init(&e->references);
    return e;
}

static void
ovn_extend_table_info_destroy(struct ovn_extend_table_info *e)
{
    free(e->name);
    struct ovn_extend_table_lflow_ref *r, *r_next;
    HMAP_FOR_EACH_SAFE (r, r_next, hmap_node, &e->references) {
        hmap_remove(&e->references, &r->hmap_node);
        ovs_list_remove(&r->list_node);
        free(r);
    }
    hmap_destroy(&e->references);
    free(e);
}

/* Finds and returns a group_info in 'existing' whose key is identical
 * to 'target''s key, or NULL if there is none. */
struct ovn_extend_table_info *
ovn_extend_table_lookup(struct hmap *exisiting,
                        const struct ovn_extend_table_info *target)
{
    struct ovn_extend_table_info *e;

    HMAP_FOR_EACH_WITH_HASH (e, hmap_node, target->hmap_node.hash,
                             exisiting) {
        if (e->table_id == target->table_id) {
            return e;
        }
   }
    return NULL;
}

static struct ovn_extend_table_lflow_to_desired *
ovn_extend_table_find_desired_by_lflow(struct ovn_extend_table *table,
                                       const struct uuid *lflow_uuid)
{
    struct ovn_extend_table_lflow_to_desired *l;
    HMAP_FOR_EACH_WITH_HASH (l, hmap_node, uuid_hash(lflow_uuid),
                             &table->lflow_to_desired) {
        if (uuid_equals(&l->lflow_uuid, lflow_uuid)) {
            return l;
        }
    }
    return NULL;
}

/* Add a reference to the list of items that <lflow_uuid> uses.
 * If the <lflow_uuid> entry doesn't exist in lflow_to_desired mapping, add
 * the <lflow_uuid> entry first. */
static void
ovn_extend_table_add_desired_to_lflow(struct ovn_extend_table *table,
                                      const struct uuid *lflow_uuid,
                                      struct ovn_extend_table_lflow_ref *r)
{
    struct ovn_extend_table_lflow_to_desired *l =
        ovn_extend_table_find_desired_by_lflow(table, lflow_uuid);
    if (!l) {
        l = xmalloc(sizeof *l);
        l->lflow_uuid = *lflow_uuid;
        ovs_list_init(&l->desired);
        hmap_insert(&table->lflow_to_desired, &l->hmap_node,
                    uuid_hash(lflow_uuid));
        VLOG_DBG("%s: add new lflow_to_desired entry "UUID_FMT,
                 __func__, UUID_ARGS(lflow_uuid));
    }

    ovs_list_insert(&l->desired, &r->list_node);
    VLOG_DBG("%s: lflow "UUID_FMT" use new item %s, id %"PRIu32,
             __func__, UUID_ARGS(lflow_uuid), r->desired->name,
             r->desired->table_id);
}

static struct ovn_extend_table_lflow_ref *
ovn_extend_info_find_lflow_ref(struct ovn_extend_table_info *e,
                               const struct uuid *lflow_uuid)
{
    struct ovn_extend_table_lflow_ref *r;
    HMAP_FOR_EACH_WITH_HASH (r, hmap_node, uuid_hash(lflow_uuid),
                             &e->references) {
        if (uuid_equals(&r->lflow_uuid, lflow_uuid)) {
            return r;
        }
    }
    return NULL;
}

/* Create the cross reference between <e> and <lflow_uuid> */
static void
ovn_extend_info_add_lflow_ref(struct ovn_extend_table *table,
                              struct ovn_extend_table_info *e,
                              const struct uuid *lflow_uuid)
{
    struct ovn_extend_table_lflow_ref *r =
        ovn_extend_info_find_lflow_ref(e, lflow_uuid);
    if (!r) {
        r = xmalloc(sizeof *r);
        r->lflow_uuid = *lflow_uuid;
        r->desired = e;
        hmap_insert(&e->references, &r->hmap_node, uuid_hash(lflow_uuid));

        ovn_extend_table_add_desired_to_lflow(table, lflow_uuid, r);
    }
}

static void
ovn_extend_info_del_lflow_ref(struct ovn_extend_table_lflow_ref *r)
{
    VLOG_DBG("%s: name %s, lflow "UUID_FMT" n %"PRIuSIZE, __func__,
             r->desired->name, UUID_ARGS(&r->lflow_uuid),
             hmap_count(&r->desired->references));
    hmap_remove(&r->desired->references, &r->hmap_node);
    ovs_list_remove(&r->list_node);
    free(r);
}

/* Clear either desired or existing in ovn_extend_table. */
void
ovn_extend_table_clear(struct ovn_extend_table *table, bool existing)
{
    struct ovn_extend_table_info *g, *next;
    struct hmap *target = existing ? &table->existing : &table->desired;

    /* Clear lflow_to_desired index, if the target is desired table. */
    if (!existing) {
        struct ovn_extend_table_lflow_to_desired *l, *l_next;
        HMAP_FOR_EACH_SAFE (l, l_next, hmap_node, &table->lflow_to_desired) {
            hmap_remove(&table->lflow_to_desired, &l->hmap_node);
            free(l);
        }
    }

    /* Clear the target table. */
    HMAP_FOR_EACH_SAFE (g, next, hmap_node, target) {
        hmap_remove(target, &g->hmap_node);
        /* Don't unset bitmap for desired group_info if the group_id
         * was not freshly reserved. */
        if (existing || g->new_table_id) {
            bitmap_set0(table->table_ids, g->table_id);
        }
        ovn_extend_table_info_destroy(g);
    }
}

void
ovn_extend_table_destroy(struct ovn_extend_table *table)
{
    ovn_extend_table_clear(table, false);
    hmap_destroy(&table->desired);
    hmap_destroy(&table->lflow_to_desired);
    ovn_extend_table_clear(table, true);
    hmap_destroy(&table->existing);
    bitmap_free(table->table_ids);
}

/* Remove an entry from existing table */
void
ovn_extend_table_remove_existing(struct ovn_extend_table *table,
                                 struct ovn_extend_table_info *existing)
{
    /* Remove 'existing' from 'groups->existing' */
    hmap_remove(&table->existing, &existing->hmap_node);

    /* Dealloc group_id. */
    bitmap_set0(table->table_ids, existing->table_id);
    ovn_extend_table_info_destroy(existing);
}

/* Remove entries in desired table that are created by the lflow_uuid */
void
ovn_extend_table_remove_desired(struct ovn_extend_table *table,
                                const struct uuid *lflow_uuid)
{
    struct ovn_extend_table_lflow_to_desired *l =
        ovn_extend_table_find_desired_by_lflow(table, lflow_uuid);

    if (!l) {
        return;
    }

    hmap_remove(&table->lflow_to_desired, &l->hmap_node);
    struct ovn_extend_table_lflow_ref *r, *next_r;
    LIST_FOR_EACH_SAFE (r, next_r, list_node, &l->desired) {
        struct ovn_extend_table_info *e = r->desired;
        ovn_extend_info_del_lflow_ref(r);
        if (hmap_is_empty(&e->references)) {
            VLOG_DBG("%s: %s, "UUID_FMT, __func__,
                     e->name, UUID_ARGS(lflow_uuid));
            hmap_remove(&table->desired, &e->hmap_node);
            if (e->new_table_id) {
                bitmap_set0(table->table_ids, e->table_id);
            }
            ovn_extend_table_info_destroy(e);
        }
    }
    free(l);
}

static struct ovn_extend_table_info*
ovn_extend_info_clone(struct ovn_extend_table_info *source)
{
    struct ovn_extend_table_info *clone =
        ovn_extend_table_info_alloc(source->name,
                                    source->table_id,
                                    source->new_table_id,
                                    source->hmap_node.hash);
    return clone;
}

void
ovn_extend_table_sync(struct ovn_extend_table *table)
{
    struct ovn_extend_table_info *desired, *next;

    /* Copy the contents of desired to existing. */
    HMAP_FOR_EACH_SAFE (desired, next, hmap_node, &table->desired) {
        if (!ovn_extend_table_lookup(&table->existing, desired)) {
            desired->new_table_id = false;
            struct ovn_extend_table_info *clone =
                ovn_extend_info_clone(desired);
            hmap_insert(&table->existing, &clone->hmap_node,
                        clone->hmap_node.hash);
        }
    }
}

/* Assign a new table ID for the table information from the bitmap.
 * If it already exists, return the old ID. */
uint32_t
ovn_extend_table_assign_id(struct ovn_extend_table *table, const char *name,
                           struct uuid lflow_uuid)
{
    uint32_t table_id = 0, hash;
    struct ovn_extend_table_info *table_info;

    hash = hash_string(name, 0);

    /* Check whether we have non installed but allocated group_id. */
    HMAP_FOR_EACH_WITH_HASH (table_info, hmap_node, hash, &table->desired) {
        if (!strcmp(table_info->name, name)) {
            VLOG_DBG("ovn_externd_table_assign_id: reuse old id %"PRIu32
                     " for %s, used by lflow "UUID_FMT,
                     table_info->table_id, table_info->name,
                     UUID_ARGS(&lflow_uuid));
            ovn_extend_info_add_lflow_ref(table, table_info, &lflow_uuid);
            return table_info->table_id;
        }
    }

    /* Check whether we already have an installed entry for this
     * combination. */
    HMAP_FOR_EACH_WITH_HASH (table_info, hmap_node, hash, &table->existing) {
        if (!strcmp(table_info->name, name)) {
            table_id = table_info->table_id;
        }
    }

    bool new_table_id = false;
    if (!table_id) {
        /* Reserve a new group_id. */
        table_id = bitmap_scan(table->table_ids, 0, 1, MAX_EXT_TABLE_ID + 1);
        new_table_id = true;
    }

    if (table_id == MAX_EXT_TABLE_ID + 1) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_ERR_RL(&rl, "%"PRIu32" out of table ids.", table_id);
        return EXT_TABLE_ID_INVALID;
    }
    bitmap_set1(table->table_ids, table_id);

    table_info = ovn_extend_table_info_alloc(name, table_id, new_table_id,
                                             hash);

    hmap_insert(&table->desired,
                &table_info->hmap_node, table_info->hmap_node.hash);

    ovn_extend_info_add_lflow_ref(table, table_info, &lflow_uuid);

    return table_id;
}
