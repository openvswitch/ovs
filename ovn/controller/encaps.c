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
    /* Maps from a chassis name to "struct chassis_node *". */
    struct shash chassis;

    /* Names of all ports in the bridge, to allow checking uniqueness when
     * adding a new tunnel. */
    struct sset port_names;

    struct ovsdb_idl_txn *ovs_txn;
    const struct ovsrec_bridge *br_int;
};

struct chassis_node {
    const struct ovsrec_port *port;
    const struct ovsrec_bridge *bridge;
};

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
    struct smap options = SMAP_INITIALIZER(&options);
    smap_add(&options, "remote_ip", encap->ip);
    smap_add(&options, "key", "flow");
    const char *csum = smap_get(&encap->options, "csum");
    if (csum && (!strcmp(csum, "true") || !strcmp(csum, "false"))) {
        smap_add(&options, "csum", csum);
    }

    /* If there's an existing chassis record that does not need any change,
     * keep it.  Otherwise, create a new record (if there was an existing
     * record, the new record will supplant it and encaps_run() will delete
     * it). */
    struct chassis_node *chassis = shash_find_data(&tc->chassis,
                                                   new_chassis_id);
    if (chassis
        && chassis->port->n_interfaces == 1
        && !strcmp(chassis->port->interfaces[0]->type, encap->type)
        && smap_equal(&chassis->port->interfaces[0]->options, &options)) {
        shash_find_and_delete(&tc->chassis, new_chassis_id);
        free(chassis);
        goto exit;
    }

    /* Choose a name for the new port.  If we're replacing an old port, reuse
     * its name, otherwise generate a new, unique name. */
    char *port_name = (chassis
                       ? xstrdup(chassis->port->name)
                       : tunnel_create_name(tc, new_chassis_id));
    if (!port_name) {
        VLOG_WARN("Unable to allocate unique name for '%s' tunnel",
                  new_chassis_id);
        goto exit;
    }

    struct ovsrec_interface *iface = ovsrec_interface_insert(tc->ovs_txn);
    ovsrec_interface_set_name(iface, port_name);
    ovsrec_interface_set_type(iface, encap->type);
    ovsrec_interface_set_options(iface, &options);

    struct ovsrec_port *port = ovsrec_port_insert(tc->ovs_txn);
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, &iface, 1);
    const struct smap id = SMAP_CONST1(&id, "ovn-chassis-id", new_chassis_id);
    ovsrec_port_set_external_ids(port, &id);

    ovsrec_bridge_update_ports_addvalue(tc->br_int, port);

    sset_add_and_free(&tc->port_names, port_name);

exit:
    smap_destroy(&options);
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
encaps_run(struct controller_ctx *ctx,
           const struct ovsrec_bridge_table *bridge_table,
           const struct ovsrec_bridge *br_int,
           const struct sbrec_chassis_table *chassis_table,
           const char *chassis_id)
{
    if (!ctx->ovs_idl_txn || !br_int) {
        return;
    }

    const struct sbrec_chassis *chassis_rec;
    const struct ovsrec_bridge *br;

    struct tunnel_ctx tc = {
        .chassis = SHASH_INITIALIZER(&tc.chassis),
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
    OVSREC_BRIDGE_TABLE_FOR_EACH (br, bridge_table) {
        for (size_t i = 0; i < br->n_ports; i++) {
            const struct ovsrec_port *port = br->ports[i];
            sset_add(&tc.port_names, port->name);

            const char *id = smap_get(&port->external_ids, "ovn-chassis-id");
            if (id) {
                if (!shash_find(&tc.chassis, id)) {
                    struct chassis_node *chassis = xzalloc(sizeof *chassis);
                    chassis->bridge = br;
                    chassis->port = port;
                    shash_add_assert(&tc.chassis, id, chassis);
                } else {
                    /* Duplicate port for ovn-chassis-id.  Arbitrarily choose
                     * to delete this one. */
                    ovsrec_bridge_update_ports_delvalue(br, port);
                }
            }
        }
    }

    SBREC_CHASSIS_TABLE_FOR_EACH (chassis_rec, chassis_table) {
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
    struct shash_node *node, *next_node;
    SHASH_FOR_EACH_SAFE (node, next_node, &tc.chassis) {
        struct chassis_node *chassis = node->data;
        ovsrec_bridge_update_ports_delvalue(chassis->bridge, chassis->port);
        shash_delete(&tc.chassis, node);
        free(chassis);
    }
    shash_destroy(&tc.chassis);
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
