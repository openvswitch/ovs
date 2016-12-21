/* Copyright (c) 2015, 2016 Nicira, Inc.
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

#ifndef OVN_LPORT_H
#define OVN_LPORT_H 1

#include <stdint.h>
#include "openvswitch/hmap.h"

struct ovsdb_idl;
struct sbrec_datapath_binding;

/* Database indexes.
 * =================
 *
 * If the database IDL were a little smarter, it would allow us to directly
 * look up data based on values of its fields.  It's not that smart (yet), so
 * instead we define our own indexes.
 */

/* Logical datapath index
 * ======================
 */

struct ldatapath {
    struct hmap_node by_key_node; /* Index by tunnel key. */
    const struct sbrec_datapath_binding *db;
    const struct sbrec_port_binding **lports;
    size_t n_lports, allocated_lports;
};

struct ldatapath_index {
    struct hmap by_key;
};

void ldatapath_index_init(struct ldatapath_index *, struct ovsdb_idl *);
void ldatapath_index_destroy(struct ldatapath_index *);

const struct ldatapath *ldatapath_lookup_by_key(
    const struct ldatapath_index *, uint32_t dp_key);

/* Logical port index
 * ==================
 *
 * This data structure holds multiple indexes over logical ports, to allow for
 * efficient searching for logical ports by name or number.
 */

struct lport_index {
    struct hmap by_name;
    struct hmap by_key;
};

void lport_index_init(struct lport_index *, struct ovsdb_idl *);
void lport_index_destroy(struct lport_index *);

const struct sbrec_port_binding *lport_lookup_by_name(
    const struct lport_index *, const char *name);
const struct sbrec_port_binding *lport_lookup_by_key(
    const struct lport_index *, uint32_t dp_key, uint16_t port_key);

/* Multicast group index
 * =====================
 *
 * This is separate from the logical port index because of namespace issues:
 * logical port names are globally unique, but multicast group names are only
 * unique within the scope of a logical datapath.
 *
 * Multicast groups could be indexed by number also, but so far the clients do
 * not need this index. */

struct mcgroup_index {
    struct hmap by_dp_name;
};

void mcgroup_index_init(struct mcgroup_index *, struct ovsdb_idl *);
void mcgroup_index_destroy(struct mcgroup_index *);

const struct sbrec_multicast_group *mcgroup_lookup_by_dp_name(
    const struct mcgroup_index *,
    const struct sbrec_datapath_binding *,
    const char *name);

#endif /* ovn/lport.h */
