/* Copyright (c) 2019, Red Hat, Inc.
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

#include "ip-mcast.h"
#include "lport.h"
#include "ovn/lib/ovn-sb-idl.h"

/*
 * Used for (faster) updating of IGMP_Group ports.
 */
struct igmp_group_port {
    struct hmap_node hmap_node;
    const struct sbrec_port_binding *port;
};

struct ovsdb_idl_index *
igmp_group_index_create(struct ovsdb_idl *idl)
{
    const struct ovsdb_idl_index_column cols[] = {
        { .column = &sbrec_igmp_group_col_address },
        { .column = &sbrec_igmp_group_col_datapath },
        { .column = &sbrec_igmp_group_col_chassis },
    };

    return ovsdb_idl_index_create(idl, cols, ARRAY_SIZE(cols));
}

/* Looks up an IGMP group based on an IPv4 (mapped in IPv6) or IPv6 'address'
 * and 'datapath'.
 */
const struct sbrec_igmp_group *
igmp_group_lookup(struct ovsdb_idl_index *igmp_groups,
                  const struct in6_addr *address,
                  const struct sbrec_datapath_binding *datapath,
                  const struct sbrec_chassis *chassis)
{
    char addr_str[INET6_ADDRSTRLEN];

    if (!ipv6_string_mapped(addr_str, address)) {
        return NULL;
    }

    struct sbrec_igmp_group *target =
        sbrec_igmp_group_index_init_row(igmp_groups);

    sbrec_igmp_group_index_set_address(target, addr_str);
    sbrec_igmp_group_index_set_datapath(target, datapath);
    sbrec_igmp_group_index_set_chassis(target, chassis);

    const struct sbrec_igmp_group *g =
        sbrec_igmp_group_index_find(igmp_groups, target);
    sbrec_igmp_group_index_destroy_row(target);
    return g;
}

/* Creates and returns a new IGMP group based on an IPv4 (mapped in IPv6) or
 * IPv6 'address', 'datapath' and 'chassis'.
 */
struct sbrec_igmp_group *
igmp_group_create(struct ovsdb_idl_txn *idl_txn,
                  const struct in6_addr *address,
                  const struct sbrec_datapath_binding *datapath,
                  const struct sbrec_chassis *chassis)
{
    char addr_str[INET6_ADDRSTRLEN];

    if (!ipv6_string_mapped(addr_str, address)) {
        return NULL;
    }

    struct sbrec_igmp_group *g = sbrec_igmp_group_insert(idl_txn);

    sbrec_igmp_group_set_address(g, addr_str);
    sbrec_igmp_group_set_datapath(g, datapath);
    sbrec_igmp_group_set_chassis(g, chassis);

    return g;
}

void
igmp_group_update_ports(const struct sbrec_igmp_group *g,
                        struct ovsdb_idl_index *datapaths,
                        struct ovsdb_idl_index *port_bindings,
                        const struct mcast_snooping *ms OVS_UNUSED,
                        const struct mcast_group *mc_group)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct igmp_group_port *old_ports_storage =
        (g->n_ports ? xmalloc(g->n_ports * sizeof *old_ports_storage) : NULL);

    struct hmap old_ports = HMAP_INITIALIZER(&old_ports);

    for (size_t i = 0; i < g->n_ports; i++) {
        struct igmp_group_port *old_port = &old_ports_storage[i];

        old_port->port = g->ports[i];
        hmap_insert(&old_ports, &old_port->hmap_node,
                    old_port->port->tunnel_key);
    }

    struct mcast_group_bundle *bundle;
    uint64_t dp_key = g->datapath->tunnel_key;

    LIST_FOR_EACH (bundle, bundle_node, &mc_group->bundle_lru) {
        uint32_t port_key = (uintptr_t)bundle->port;
        const struct sbrec_port_binding *sbrec_port =
            lport_lookup_by_key(datapaths, port_bindings, dp_key, port_key);
        if (!sbrec_port) {
            continue;
        }

        struct hmap_node *node = hmap_first_with_hash(&old_ports, port_key);
        if (!node) {
            sbrec_igmp_group_update_ports_addvalue(g, sbrec_port);
        } else {
            hmap_remove(&old_ports, node);
        }
    }

    struct igmp_group_port *igmp_port;
    HMAP_FOR_EACH_POP (igmp_port, hmap_node, &old_ports) {
        sbrec_igmp_group_update_ports_delvalue(g, igmp_port->port);
    }

    free(old_ports_storage);
    hmap_destroy(&old_ports);
}

void
igmp_group_delete(const struct sbrec_igmp_group *g)
{
    sbrec_igmp_group_delete(g);
}

bool
igmp_group_cleanup(struct ovsdb_idl_txn *ovnsb_idl_txn,
                   struct ovsdb_idl_index *igmp_groups)
{
    const struct sbrec_igmp_group *g;

    if (!ovnsb_idl_txn) {
        return true;
    }

    SBREC_IGMP_GROUP_FOR_EACH_BYINDEX (g, igmp_groups) {
        igmp_group_delete(g);
    }

    return true;
}
