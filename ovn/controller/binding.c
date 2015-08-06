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
#include "binding.h"

#include "lib/sset.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(binding);

void
binding_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_bridges);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_interfaces);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
}

static void
get_local_iface_ids(const struct ovsrec_bridge *br_int, struct sset *lports)
{
    int i;

    for (i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        const char *iface_id;
        int j;

        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }

        for (j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            iface_id = smap_get(&iface_rec->external_ids, "iface-id");
            if (!iface_id) {
                continue;
            }
            sset_add(lports, iface_id);
        }
    }
}

void
binding_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int,
            const char *chassis_id)
{
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_port_binding *binding_rec;
    struct sset lports, all_lports;
    const char *name;

    if (!ctx->ovnsb_idl_txn) {
        return;
    }

    chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, chassis_id);
    if (!chassis_rec) {
        return;
    }

    sset_init(&lports);
    sset_init(&all_lports);
    if (br_int) {
        get_local_iface_ids(br_int, &lports);
    } else {
        /* We have no integration bridge, therefore no local logical ports.
         * We'll remove our chassis from all port binding records below. */
    }
    sset_clone(&all_lports, &lports);

    ovsdb_idl_txn_add_comment(
        ctx->ovnsb_idl_txn,"ovn-controller: updating port bindings for '%s'",
        chassis_id);

    SBREC_PORT_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
        if (sset_find_and_delete(&lports, binding_rec->logical_port) ||
                (binding_rec->parent_port && binding_rec->parent_port[0] &&
                 sset_contains(&all_lports, binding_rec->parent_port))) {
            if (binding_rec->chassis == chassis_rec) {
                continue;
            }
            if (binding_rec->chassis) {
                VLOG_INFO("Changing chassis for lport %s from %s to %s",
                          binding_rec->logical_port,
                          binding_rec->chassis->name,
                          chassis_rec->name);
            }
            sbrec_port_binding_set_chassis(binding_rec, chassis_rec);
        } else if (binding_rec->chassis == chassis_rec) {
            sbrec_port_binding_set_chassis(binding_rec, NULL);
        }
    }

    SSET_FOR_EACH (name, &lports) {
        VLOG_DBG("No port binding record for lport %s", name);
    }
    sset_destroy(&lports);
    sset_destroy(&all_lports);
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
binding_cleanup(struct controller_ctx *ctx, const char *chassis_id)
{
    if (!ctx->ovnsb_idl_txn) {
        return false;
    }

    if (!chassis_id) {
        return true;
    }
    const struct sbrec_chassis *chassis_rec
        = get_chassis_by_name(ctx->ovnsb_idl, chassis_id);
    if (!chassis_rec) {
        return true;
    }

    ovsdb_idl_txn_add_comment(
        ctx->ovnsb_idl_txn,
        "ovn-controller: removing all port bindings for '%s'", chassis_id);

    const struct sbrec_port_binding *binding_rec;
    bool any_changes = false;
    SBREC_PORT_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
        if (binding_rec->chassis == chassis_rec) {
            sbrec_port_binding_set_chassis(binding_rec, NULL);
            any_changes = true;
        }
    }
    return !any_changes;
}
