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

#ifndef EXTEND_TABLE_H
#define EXTEND_TABLE_H 1

#define MAX_EXT_TABLE_ID 65535
#define EXT_TABLE_ID_INVALID 0

#include "openvswitch/hmap.h"
#include "openvswitch/list.h"

/* Used to manage expansion tables associated with Flow table,
 * such as the Group Table or Meter Table. */
struct ovn_extend_table {
    unsigned long *table_ids;  /* Used as a bitmap with value set
                                * for allocated group ids in either
                                * desired or existing. */
    struct hmap desired;
    struct hmap existing;
};

struct ovn_extend_table_info {
    struct hmap_node hmap_node;
    char *name;         /* Name for the table entity. */
    uint32_t table_id;
    bool new_table_id;  /* 'True' if 'table_id' was reserved from
                         * ovn_extend_table's 'table_ids' bitmap. */
};

void ovn_extend_table_init(struct ovn_extend_table *);

void ovn_extend_table_destroy(struct ovn_extend_table *);

struct ovn_extend_table_info *ovn_extend_table_lookup(
    struct hmap *, const struct ovn_extend_table_info *);

void ovn_extend_table_clear(struct ovn_extend_table *, bool);

void ovn_extend_table_remove(struct ovn_extend_table *,
                             struct ovn_extend_table_info *);

/* Move the contents of desired to existing. */
void ovn_extend_table_move(struct ovn_extend_table *);

uint32_t ovn_extend_table_assign_id(struct ovn_extend_table *,
                                    const char *name);

/* Iterates 'DESIRED' through all of the 'ovn_extend_table_info's in
 * 'TABLE'->desired that are not in 'TABLE'->existing.  (The loop body
 * presumably adds them.) */
#define EXTEND_TABLE_FOR_EACH_UNINSTALLED(DESIRED, TABLE) \
    HMAP_FOR_EACH (DESIRED, hmap_node, &(TABLE)->desired) \
        if (!ovn_extend_table_lookup(&(TABLE)->existing, DESIRED))

/* Iterates 'EXISTING' through all of the 'ovn_extend_table_info's in
 * 'TABLE'->existing that are not in 'TABLE'->desired.  (The loop body
 * presumably removes them.) */
#define EXTEND_TABLE_FOR_EACH_INSTALLED(EXISTING, NEXT, TABLE)         \
    HMAP_FOR_EACH_SAFE (EXISTING, NEXT, hmap_node, &(TABLE)->existing) \
        if (!ovn_extend_table_lookup(&(TABLE)->desired, EXISTING))

#endif /* ovn/lib/extend-table.h */
