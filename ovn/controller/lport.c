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

#include <config.h>

#include "lport.h"
#include "hash.h"
#include "lflow.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(lport);

/* A logical port. */
struct lport {
    struct hmap_node name_node;  /* Index by name. */
    struct hmap_node key_node;   /* Index by (dp_key, port_key). */
    struct hmap_node uuid_node;  /* Index by row uuid. */
    struct uuid uuid;
    const struct sbrec_port_binding *pb;
};

static bool full_lport_rebuild = false;

void
lport_index_reset(void)
{
    full_lport_rebuild = true;
}

void
lport_index_init(struct lport_index *lports)
{
    hmap_init(&lports->by_name);
    hmap_init(&lports->by_key);
    hmap_init(&lports->by_uuid);
}

void
lport_index_remove(struct lport_index *lports, const struct uuid *uuid)
{
    const struct lport *port_ = lport_lookup_by_uuid(lports, uuid);
    struct lport *port = CONST_CAST(struct lport *, port_);
    if (port) {
        hmap_remove(&lports->by_name, &port->name_node);
        hmap_remove(&lports->by_key, &port->key_node);
        hmap_remove(&lports->by_uuid, &port->uuid_node);
        free(port);
    }
}

void
lport_index_clear(struct lport_index *lports)
{
    /* Destroy all of the "struct lport"s.
     *
     * We have to remove the node from all indexes. */
    struct lport *port, *next;
    HMAP_FOR_EACH_SAFE (port, next, name_node, &lports->by_name) {
        hmap_remove(&lports->by_name, &port->name_node);
        hmap_remove(&lports->by_key, &port->key_node);
        hmap_remove(&lports->by_uuid, &port->uuid_node);
        free(port);
    }
}

static void
consider_lport_index(struct lport_index *lports,
                     const struct sbrec_port_binding *pb)
{
    if (lport_lookup_by_name(lports, pb->logical_port)) {
        return;
    }

    struct lport *p = xmalloc(sizeof *p);
    hmap_insert(&lports->by_name, &p->name_node,
                hash_string(pb->logical_port, 0));
    hmap_insert(&lports->by_key, &p->key_node,
                hash_int(pb->tunnel_key, pb->datapath->tunnel_key));
    hmap_insert(&lports->by_uuid, &p->uuid_node,
                uuid_hash(&pb->header_.uuid));
    memcpy(&p->uuid, &pb->header_.uuid, sizeof p->uuid);
    p->pb = pb;
}

void
lport_index_fill(struct lport_index *lports, struct ovsdb_idl *ovnsb_idl)
{
    const struct sbrec_port_binding *pb;
    if (full_lport_rebuild) {
        lport_index_clear(lports);
        SBREC_PORT_BINDING_FOR_EACH (pb, ovnsb_idl) {
            consider_lport_index(lports, pb);
        }
        full_lport_rebuild = false;
    } else {
        SBREC_PORT_BINDING_FOR_EACH_TRACKED (pb, ovnsb_idl) {
            if (sbrec_port_binding_is_deleted(pb)) {
                lport_index_remove(lports, &pb->header_.uuid);
            } else {
                consider_lport_index(lports, pb);
            }
        }
    }
}

void
lport_index_destroy(struct lport_index *lports)
{
    lport_index_clear(lports);

    hmap_destroy(&lports->by_name);
    hmap_destroy(&lports->by_key);
    hmap_destroy(&lports->by_uuid);
}

/* Finds and returns the lport with the given 'name', or NULL if no such lport
 * exists. */
const struct sbrec_port_binding *
lport_lookup_by_name(const struct lport_index *lports, const char *name)
{
    const struct lport *lport;
    HMAP_FOR_EACH_WITH_HASH (lport, name_node, hash_string(name, 0),
                             &lports->by_name) {
        if (!strcmp(lport->pb->logical_port, name)) {
            return lport->pb;
        }
    }
    return NULL;
}

const struct lport *
lport_lookup_by_uuid(const struct lport_index *lports,
                     const struct uuid *uuid)
{
    const struct lport *lport;
    HMAP_FOR_EACH_WITH_HASH (lport, uuid_node, uuid_hash(uuid),
                             &lports->by_uuid) {
        if (uuid_equals(uuid, &lport->uuid)) {
            return lport;
        }
    }
    return NULL;
}

const struct sbrec_port_binding *
lport_lookup_by_key(const struct lport_index *lports,
                    uint32_t dp_key, uint16_t port_key)
{
    const struct lport *lport;
    HMAP_FOR_EACH_WITH_HASH (lport, key_node, hash_int(port_key, dp_key),
                             &lports->by_key) {
        if (port_key == lport->pb->tunnel_key
            && dp_key == lport->pb->datapath->tunnel_key) {
            return lport->pb;
        }
    }
    return NULL;
}

struct mcgroup {
    struct hmap_node dp_name_node; /* Index by (logical datapath, name). */
    struct hmap_node uuid_node;    /* Index by insert uuid. */
    struct uuid uuid;
    const struct sbrec_multicast_group *mg;
};

static bool full_mc_rebuild = false;

void
mcgroup_index_reset(void)
{
    full_mc_rebuild = true;
}

void
mcgroup_index_init(struct mcgroup_index *mcgroups)
{
    hmap_init(&mcgroups->by_dp_name);
    hmap_init(&mcgroups->by_uuid);
}

void
mcgroup_index_remove(struct mcgroup_index *mcgroups, const struct uuid *uuid)
{
    const struct mcgroup *mcgroup_ = mcgroup_lookup_by_uuid(mcgroups, uuid);
    struct mcgroup *mcgroup = CONST_CAST(struct mcgroup *, mcgroup_);
    if (mcgroup) {
        hmap_remove(&mcgroups->by_dp_name, &mcgroup->dp_name_node);
        hmap_remove(&mcgroups->by_uuid, &mcgroup->uuid_node);
        free(mcgroup);
    }
}

void
mcgroup_index_clear(struct mcgroup_index *mcgroups)
{
    struct mcgroup *mcgroup, *next;
    HMAP_FOR_EACH_SAFE (mcgroup, next, dp_name_node, &mcgroups->by_dp_name) {
        hmap_remove(&mcgroups->by_dp_name, &mcgroup->dp_name_node);
        hmap_remove(&mcgroups->by_uuid, &mcgroup->uuid_node);
        free(mcgroup);
    }
}

static void
consider_mcgroup_index(struct mcgroup_index *mcgroups,
                       const struct sbrec_multicast_group *mg)
{
    const struct uuid *dp_uuid = &mg->datapath->header_.uuid;
    if (mcgroup_lookup_by_dp_name(mcgroups, mg->datapath, mg->name)) {
        return;
    }

    struct mcgroup *m = xmalloc(sizeof *m);
    hmap_insert(&mcgroups->by_dp_name, &m->dp_name_node,
                hash_string(mg->name, uuid_hash(dp_uuid)));
    hmap_insert(&mcgroups->by_uuid, &m->uuid_node,
                uuid_hash(&mg->header_.uuid));
    memcpy(&m->uuid, &mg->header_.uuid, sizeof m->uuid);
    m->mg = mg;
}

void
mcgroup_index_fill(struct mcgroup_index *mcgroups, struct ovsdb_idl *ovnsb_idl)
{
    const struct sbrec_multicast_group *mg;
    if (full_mc_rebuild) {
        mcgroup_index_clear(mcgroups);
        SBREC_MULTICAST_GROUP_FOR_EACH (mg, ovnsb_idl) {
            consider_mcgroup_index(mcgroups, mg);
        }
        full_mc_rebuild = false;
    } else {
        SBREC_MULTICAST_GROUP_FOR_EACH_TRACKED (mg, ovnsb_idl) {
            if (sbrec_multicast_group_is_deleted(mg)) {
                mcgroup_index_remove(mcgroups, &mg->header_.uuid);
            } else {
                consider_mcgroup_index(mcgroups, mg);
            }
        }
    }
}

void
mcgroup_index_destroy(struct mcgroup_index *mcgroups)
{
    mcgroup_index_clear(mcgroups);

    hmap_destroy(&mcgroups->by_dp_name);
}

const struct mcgroup *
mcgroup_lookup_by_uuid(const struct mcgroup_index *mcgroups,
                       const struct uuid *uuid)
{
    const struct mcgroup *mcgroup;
    HMAP_FOR_EACH_WITH_HASH (mcgroup, uuid_node, uuid_hash(uuid),
                             &mcgroups->by_uuid) {
        if (uuid_equals(&mcgroup->uuid, uuid)) {
            return mcgroup;
        }
    }
    return NULL;
}

const struct sbrec_multicast_group *
mcgroup_lookup_by_dp_name(const struct mcgroup_index *mcgroups,
                          const struct sbrec_datapath_binding *dp,
                          const char *name)
{
    const struct uuid *dp_uuid = &dp->header_.uuid;
    const struct mcgroup *mcgroup;
    HMAP_FOR_EACH_WITH_HASH (mcgroup, dp_name_node,
                             hash_string(name, uuid_hash(dp_uuid)),
                             &mcgroups->by_dp_name) {
        if (uuid_equals(&mcgroup->mg->datapath->header_.uuid, dp_uuid)
            && !strcmp(mcgroup->mg->name, name)) {
            return mcgroup->mg;
        }
    }
    return NULL;
}
