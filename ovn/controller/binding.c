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
binding_init(struct controller_ctx *ctx)
{
    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_open_vswitch_col_bridges);

    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_port_col_interfaces);

    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_interface_col_external_ids);
}

static void
get_local_iface_ids(struct controller_ctx *ctx, struct sset *lports)
{
    int i;

    for (i = 0; i < ctx->br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = ctx->br_int->ports[i];
        const char *iface_id;
        int j;

        if (!strcmp(port_rec->name, ctx->br_int_name)) {
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
binding_run(struct controller_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_binding *binding_rec;
    struct ovsdb_idl_txn *txn;
    struct sset lports, all_lports;
    const char *name;
    int retval;

    chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, ctx->chassis_id);
    if (!chassis_rec) {
        return;
    }

    sset_init(&lports);
    sset_init(&all_lports);
    get_local_iface_ids(ctx, &lports);
    sset_clone(&all_lports, &lports);

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller: updating bindings for '%s'",
                              ctx->chassis_id);

    SBREC_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
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
            sbrec_binding_set_chassis(binding_rec, chassis_rec);
        } else if (binding_rec->chassis == chassis_rec) {
            sbrec_binding_set_chassis(binding_rec, NULL);
        }
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval == TXN_ERROR) {
        VLOG_INFO("Problem committing binding information: %s",
                  ovsdb_idl_txn_status_to_string(retval));
    }

    ovsdb_idl_txn_destroy(txn);

    SSET_FOR_EACH (name, &lports) {
        VLOG_DBG("No binding record for lport %s", name);
    }
    sset_destroy(&lports);
    sset_destroy(&all_lports);
}

void
binding_destroy(struct controller_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    int retval = TXN_TRY_AGAIN;

    ovs_assert(ctx->ovnsb_idl);

    chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, ctx->chassis_id);
    if (!chassis_rec) {
        return;
    }

    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct sbrec_binding *binding_rec;
        struct ovsdb_idl_txn *txn;

        txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
        ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller: removing all bindings for '%s'",
                              ctx->chassis_id);

        SBREC_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
            if (binding_rec->chassis == chassis_rec) {
                sbrec_binding_set_chassis(binding_rec, NULL);
            }
        }

        retval = ovsdb_idl_txn_commit_block(txn);
        if (retval == TXN_ERROR) {
            VLOG_INFO("Problem removing bindings: %s",
                      ovsdb_idl_txn_status_to_string(retval));
        }

        ovsdb_idl_txn_destroy(txn);
    }
}
