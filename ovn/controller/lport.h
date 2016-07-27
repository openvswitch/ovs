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
#include "uuid.h"

struct ovsdb_idl;
struct sbrec_datapath_binding;

/* Logical port and multicast group indexes
 * ========================================
 *
 * This data structure holds multiple indexes over logical ports, to allow for
 * efficient searching for logical ports by name or number.
 */

struct lport_index {
    struct hmap by_name;
    struct hmap by_key;
    struct hmap by_uuid;
};

void lport_index_reset(void);
void lport_index_init(struct lport_index *);
void lport_index_fill(struct lport_index *, struct ovsdb_idl *);
bool lport_index_remove(struct lport_index *, const struct uuid *);
void lport_index_clear(struct lport_index *);
void lport_index_destroy(struct lport_index *);
void lport_index_rebuild(void);

const struct sbrec_port_binding *lport_lookup_by_name(
    const struct lport_index *, const char *name);
const struct sbrec_port_binding *lport_lookup_by_key(
    const struct lport_index *, uint32_t dp_key, uint16_t port_key);

const struct lport *lport_lookup_by_uuid(
    const struct lport_index *, const struct uuid *uuid);


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
    struct hmap by_uuid;
};

void mcgroup_index_reset(void);
void mcgroup_index_init(struct mcgroup_index *);
void mcgroup_index_fill(struct mcgroup_index *, struct ovsdb_idl *);
void mcgroup_index_remove(struct mcgroup_index *, const struct uuid *);
void mcgroup_index_clear(struct mcgroup_index *);
void mcgroup_index_destroy(struct mcgroup_index *);
void mcgroup_index_rebuild(void);

const struct sbrec_multicast_group *mcgroup_lookup_by_dp_name(
    const struct mcgroup_index *,
    const struct sbrec_datapath_binding *,
    const char *name);

const struct mcgroup *mcgroup_lookup_by_uuid(
    const struct mcgroup_index *, const struct uuid *uuid);

#endif /* ovn/lport.h */
