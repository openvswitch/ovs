/* Copyright (c) 2016, 2017 Red Hat, Inc.
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

#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovn/actions.h"
#include "ovn/lib/chassis-index.h"
#include "ovn/lib/ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(chassis_index);

struct chassis {
    struct hmap_node name_node;
    const struct sbrec_chassis *db;
};

const struct sbrec_chassis *
chassis_lookup_by_name(const struct chassis_index *chassis_index,
                       const char *name)
{
    const struct chassis *chassis;
    HMAP_FOR_EACH_WITH_HASH (chassis, name_node, hash_string(name, 0),
                             &chassis_index->by_name) {
        if (!strcmp(chassis->db->name, name)) {
            return chassis->db;
        }
    }
    return NULL;
}

void
chassis_index_init(const struct sbrec_chassis_table *chassis_table,
                   struct chassis_index *chassis_index)
{
    hmap_init(&chassis_index->by_name);

    const struct sbrec_chassis *chassis;
    SBREC_CHASSIS_TABLE_FOR_EACH (chassis, chassis_table) {
        if (!chassis->name) {
            continue;
        }
        struct chassis *c = xmalloc(sizeof *c);
        hmap_insert(&chassis_index->by_name, &c->name_node,
                    hash_string(chassis->name, 0));
        c->db = chassis;
    }
}

void
chassis_index_destroy(struct chassis_index *chassis_index)
{
    if (!chassis_index) {
        return;
    }

    /* Destroy all of the "struct chassis"s. */
    struct chassis *chassis, *next;
    HMAP_FOR_EACH_SAFE (chassis, next, name_node, &chassis_index->by_name) {
        hmap_remove(&chassis_index->by_name, &chassis->name_node);
        free(chassis);
    }

    hmap_destroy(&chassis_index->by_name);
}
