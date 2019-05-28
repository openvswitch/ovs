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
    hmap_init(&table->existing);
}

static void
ovn_extend_table_info_destroy(struct hmap *target)
{
    struct ovn_extend_table_info *e, *next;
    HMAP_FOR_EACH_SAFE (e, next, hmap_node, target) {
        hmap_remove(target, &e->hmap_node);
        free(e->name);
        free(e);
    }
    hmap_destroy(target);
}

void
ovn_extend_table_destroy(struct ovn_extend_table *table)
{
    bitmap_free(table->table_ids);

    ovn_extend_table_info_destroy(&table->desired);
    ovn_extend_table_info_destroy(&table->existing);
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

/* Clear either desired or existing in ovn_extend_table. */
void
ovn_extend_table_clear(struct ovn_extend_table *table, bool existing)
{
    struct ovn_extend_table_info *g, *next;
    struct hmap *target = existing ? &table->existing : &table->desired;

    HMAP_FOR_EACH_SAFE (g, next, hmap_node, target) {
        hmap_remove(target, &g->hmap_node);
        /* Don't unset bitmap for desired group_info if the group_id
         * was not freshly reserved. */
        if (existing || g->new_table_id) {
            bitmap_set0(table->table_ids, g->table_id);
        }
        free(g->name);
        free(g);
    }
}

/* Remove an entry from existing table */
void
ovn_extend_table_remove_existing(struct ovn_extend_table *table,
                                 struct ovn_extend_table_info *existing)
{
    /* Remove 'existing' from 'groups->existing' */
    hmap_remove(&table->existing, &existing->hmap_node);
    free(existing->name);

    /* Dealloc group_id. */
    bitmap_set0(table->table_ids, existing->table_id);
    free(existing);
}

/* Remove entries in desired table that are created by the lflow_uuid */
void
ovn_extend_table_remove_desired(struct ovn_extend_table *table,
                                const struct uuid *lflow_uuid)
{
    struct ovn_extend_table_info *e, *next_e;
    HMAP_FOR_EACH_SAFE (e, next_e, hmap_node, &table->desired) {
        if (uuid_equals(&e->lflow_uuid, lflow_uuid)) {
            hmap_remove(&table->desired, &e->hmap_node);
            free(e->name);
            if (e->new_table_id) {
                bitmap_set0(table->table_ids, e->table_id);
            }
            free(e);
        }
    }

}

static struct ovn_extend_table_info*
ovn_extend_info_clone(struct ovn_extend_table_info *source)
{
    struct ovn_extend_table_info *clone = xmalloc(sizeof *clone);
    clone->name = xstrdup(source->name);
    clone->table_id = source->table_id;
    clone->new_table_id = source->new_table_id;
    clone->hmap_node.hash = source->hmap_node.hash;
    clone->lflow_uuid = source->lflow_uuid;
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
        if (!strcmp(table_info->name, name) &&
            table_info->new_table_id) {
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

    table_info = xmalloc(sizeof *table_info);
    table_info->name = xstrdup(name);
    table_info->table_id = table_id;
    table_info->hmap_node.hash = hash;
    table_info->new_table_id = new_table_id;
    table_info->lflow_uuid = lflow_uuid;

    hmap_insert(&table->desired,
                &table_info->hmap_node, table_info->hmap_node.hash);

    return table_id;
}
