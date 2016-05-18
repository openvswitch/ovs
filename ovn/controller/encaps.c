/* Copyright (c) 2015 Nicira, Inc.
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
#include "encaps.h"

#include "lib/hash.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(encaps);

void
encaps_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_type);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_options);
}

/* Enough context to create a new tunnel, using tunnel_add(). */
struct tunnel_ctx {
    /* Contains "struct port_hash_node"s.  Used to figure out what
     * existing tunnels should be deleted: we index all of the OVN encap
     * rows into this data structure, then as existing rows are
     * generated we remove them.  After generating all the rows, any
     * remaining in 'tunnel_hmap' must be deleted from the database. */
    struct hmap tunnel_hmap;

    /* Names of all ports in the bridge, to allow checking uniqueness when
     * adding a new tunnel. */
    struct sset port_names;

    struct ovsdb_idl_txn *ovs_txn;
    const struct ovsrec_bridge *br_int;
};

struct port_hash_node {
    struct hmap_node node;
    const struct ovsrec_port *port;
    const struct ovsrec_bridge *bridge;
};

static size_t
port_hash(const char *chassis_id, const char *type, const char *ip)
{
    size_t hash = hash_string(chassis_id, 0);
    hash = hash_string(type, hash);
    return hash_string(ip, hash);
}

static size_t
port_hash_rec(const struct ovsrec_port *port)
{
    const char *chassis_id, *ip;
    const struct ovsrec_interface *iface;

    chassis_id = smap_get(&port->external_ids, "ovn-chassis-id");

    if (!chassis_id || !port->n_interfaces) {
        /* This should not happen for an OVN-created port. */
        return 0;
    }

    iface = port->interfaces[0];
    ip = smap_get(&iface->options, "remote_ip");

    return port_hash(chassis_id, iface->type, ip);
}

static char *
tunnel_create_name(struct tunnel_ctx *tc, const char *chassis_id)
{
    int i;

    for (i = 0; i < UINT16_MAX; i++) {
        char *port_name;
        port_name = xasprintf("ovn-%.6s-%x", chassis_id, i);

        if (!sset_contains(&tc->port_names, port_name)) {
            return port_name;
        }

        free(port_name);
    }

    return NULL;
}


static void
tunnel_add(struct tunnel_ctx *tc, const char *new_chassis_id,
           const struct sbrec_encap *encap)
{
    struct port_hash_node *hash_node;

    /* Check whether such a row already exists in OVS.  If so, remove it
     * from 'tc->tunnel_hmap' and we're done. */
    HMAP_FOR_EACH_WITH_HASH (hash_node, node,
                             port_hash(new_chassis_id,
                                       encap->type, encap->ip),
                             &tc->tunnel_hmap) {
        const struct ovsrec_port *port = hash_node->port;
        const char *chassis_id = smap_get(&port->external_ids,
                                          "ovn-chassis-id");
        const struct ovsrec_interface *iface;
        const char *ip;

        if (!chassis_id || !port->n_interfaces) {
            continue;
        }

        iface = port->interfaces[0];
        ip = smap_get(&iface->options, "remote_ip");
        if (!ip) {
            continue;
        }

        if (!strcmp(new_chassis_id, chassis_id)
            && !strcmp(encap->type, iface->type)
            && !strcmp(encap->ip, ip)) {
            hmap_remove(&tc->tunnel_hmap, &hash_node->node);
            free(hash_node);
            return;
        }
    }

    /* No such port, so add one. */
    struct smap options = SMAP_INITIALIZER(&options);
    struct ovsrec_port *port, **ports;
    struct ovsrec_interface *iface;
    char *port_name;
    size_t i;

    port_name = tunnel_create_name(tc, new_chassis_id);
    if (!port_name) {
        VLOG_WARN("Unable to allocate unique name for '%s' tunnel",
                  new_chassis_id);
        return;
    }

    iface = ovsrec_interface_insert(tc->ovs_txn);
    ovsrec_interface_set_name(iface, port_name);
    ovsrec_interface_set_type(iface, encap->type);
    smap_add(&options, "remote_ip", encap->ip);
    smap_add(&options, "key", "flow");
    ovsrec_interface_set_options(iface, &options);
    smap_destroy(&options);

    port = ovsrec_port_insert(tc->ovs_txn);
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, &iface, 1);
    const struct smap id = SMAP_CONST1(&id, "ovn-chassis-id", new_chassis_id);
    ovsrec_port_set_external_ids(port, &id);

    ports = xmalloc(sizeof *tc->br_int->ports * (tc->br_int->n_ports + 1));
    for (i = 0; i < tc->br_int->n_ports; i++) {
        ports[i] = tc->br_int->ports[i];
    }
    ports[tc->br_int->n_ports] = port;
    ovsrec_bridge_verify_ports(tc->br_int);
    ovsrec_bridge_set_ports(tc->br_int, ports, tc->br_int->n_ports + 1);

    sset_add(&tc->port_names, port_name);
    free(port_name);
    free(ports);
}

static void
bridge_delete_port(const struct ovsrec_bridge *br,
                   const struct ovsrec_port *port)
{
    struct ovsrec_port **ports;
    size_t i, n;

    ports = xmalloc(sizeof *br->ports * br->n_ports);
    for (i = n = 0; i < br->n_ports; i++) {
        if (br->ports[i] != port) {
            ports[n++] = br->ports[i];
        }
    }
    ovsrec_bridge_verify_ports(br);
    ovsrec_bridge_set_ports(br, ports, n);
    free(ports);
}

static struct sbrec_encap *
preferred_encap(const struct sbrec_chassis *chassis_rec)
{
    struct sbrec_encap *best_encap = NULL;
    uint32_t best_type = 0;

    for (int i = 0; i < chassis_rec->n_encaps; i++) {
        uint32_t tun_type = get_tunnel_type(chassis_rec->encaps[i]->type);
        if (tun_type > best_type) {
            best_type = tun_type;
            best_encap = chassis_rec->encaps[i];
        }
    }

    return best_encap;
}

void
encaps_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int,
           const char *chassis_id)
{
    if (!ctx->ovs_idl_txn || !br_int) {
        return;
    }

    const struct sbrec_chassis *chassis_rec;
    const struct ovsrec_bridge *br;

    struct tunnel_ctx tc = {
        .tunnel_hmap = HMAP_INITIALIZER(&tc.tunnel_hmap),
        .port_names = SSET_INITIALIZER(&tc.port_names),
        .br_int = br_int
    };

    tc.ovs_txn = ctx->ovs_idl_txn;
    ovsdb_idl_txn_add_comment(tc.ovs_txn,
                              "ovn-controller: modifying OVS tunnels '%s'",
                              chassis_id);

    /* Collect all port names into tc.port_names.
     *
     * Collect all the OVN-created tunnels into tc.tunnel_hmap. */
    OVSREC_BRIDGE_FOR_EACH(br, ctx->ovs_idl) {
        size_t i;

        for (i = 0; i < br->n_ports; i++) {
            const struct ovsrec_port *port = br->ports[i];

            sset_add(&tc.port_names, port->name);

            if (smap_get(&port->external_ids, "ovn-chassis-id")) {
                struct port_hash_node *hash_node = xzalloc(sizeof *hash_node);
                hash_node->bridge = br;
                hash_node->port = port;
                hmap_insert(&tc.tunnel_hmap, &hash_node->node,
                            port_hash_rec(port));
            }
        }
    }

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->ovnsb_idl) {
        if (strcmp(chassis_rec->name, chassis_id)) {
            /* Create tunnels to the other chassis. */
            const struct sbrec_encap *encap = preferred_encap(chassis_rec);
            if (!encap) {
                VLOG_INFO("No supported encaps for '%s'", chassis_rec->name);
                continue;
            }
            tunnel_add(&tc, chassis_rec->name, encap);
        }
    }

    /* Delete any existing OVN tunnels that were not still around. */
    struct port_hash_node *hash_node;
    HMAP_FOR_EACH_POP (hash_node, node, &tc.tunnel_hmap) {
        bridge_delete_port(hash_node->bridge, hash_node->port);
        free(hash_node);
    }
    hmap_destroy(&tc.tunnel_hmap);
    sset_destroy(&tc.port_names);
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
encaps_cleanup(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int)
{
    if (!br_int) {
        return true;
    }

    /* Delete all the OVS-created tunnels from the integration bridge. */
    struct ovsrec_port **ports
        = xmalloc(sizeof *br_int->ports * br_int->n_ports);
    size_t n = 0;
    for (size_t i = 0; i < br_int->n_ports; i++) {
        if (!smap_get(&br_int->ports[i]->external_ids, "ovn-chassis-id")) {
            ports[n++] = br_int->ports[i];
        }
    }

    bool any_changes = n != br_int->n_ports;
    if (any_changes && ctx->ovs_idl_txn) {
        ovsdb_idl_txn_add_comment(ctx->ovs_idl_txn,
                                  "ovn-controller: destroying tunnels");
        ovsrec_bridge_verify_ports(br_int);
        ovsrec_bridge_set_ports(br_int, ports, n);
    }
    free(ports);

    return !any_changes;
}
