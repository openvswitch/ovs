/* Copyright (c) 2017, Red Hat, Inc.
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

#ifndef OVN_CHASSIS_INDEX_H
#define OVN_CHASSIS_INDEX_H 1

#include "openvswitch/hmap.h"

struct chassis_index {
    struct hmap by_name;
};

struct sbrec_chassis_table;

/* Finds and returns the chassis with the given 'name', or NULL if no such
 * chassis exists. */
const struct sbrec_chassis *
chassis_lookup_by_name(const struct chassis_index *chassis_index,
                       const char *name);

/* Initializes the chassis index out of the ovsdb_idl to SBDB */
void chassis_index_init(const struct sbrec_chassis_table *,
                        struct chassis_index *chassis_index);

/* Free a chassis index from memory */
void chassis_index_destroy(struct chassis_index *chassis_index);

#endif /* ovn/lib/chassis-index.h */
