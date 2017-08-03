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
#include "lib/uuid.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"

struct ovsdb_idl;
struct sbrec_chassis;
struct sbrec_datapath_binding;
struct sbrec_port_binding;


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


const struct sbrec_port_binding *lport_lookup_by_name(
    struct ovsdb_idl *, const char *name);
const struct sbrec_port_binding *lport_lookup_by_key(
    struct ovsdb_idl *, uint64_t dp_key, uint64_t port_key);


const struct sbrec_multicast_group *mcgroup_lookup_by_dp_name(
    struct ovsdb_idl *idl,
    const struct sbrec_datapath_binding *,
    const char *name);

void lport_init(struct ovsdb_idl *idl);

#endif /* ovn/lport.h */
