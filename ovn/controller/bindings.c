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
#include "bindings.h"

#include "lib/sset.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(bindings);

#define DEFAULT_BRIDGE_NAME "br-int"

void
bindings_init(struct controller_ctx *ctx)
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
    const struct ovsrec_open_vswitch *cfg;
    const struct ovsrec_bridge *bridge_rec;
    const char *bridge_name;
    int i;

    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (!cfg) {
        VLOG_INFO("No Open_vSwitch row defined.");
        return;
    }

    bridge_name = smap_get(&cfg->external_ids, "ovn-bridge");
    if (!bridge_name) {
        bridge_name = DEFAULT_BRIDGE_NAME;
    }

    OVSREC_BRIDGE_FOR_EACH(bridge_rec, ctx->ovs_idl) {
        if (!strcmp(bridge_rec->name, bridge_name)) {
            break;
        }
    }

    if (!bridge_rec) {
        VLOG_INFO("Could not find bridge '%s'", bridge_name);
        return;
    }

    for (i = 0; i < bridge_rec->n_ports; i++) {
        const struct ovsrec_port *port_rec = bridge_rec->ports[i];
        const char *iface_id;
        int j;

        if (!strcmp(port_rec->name, bridge_rec->name)) {
            continue;
        }

        for (j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            iface_id = smap_get(&iface_rec->external_ids, "iface-id");
            if (!iface_id) {
                VLOG_DBG("Could not find iface-id for '%s'", iface_rec->name);
                continue;
            }
            sset_add(lports, iface_id);
        }
    }
}

void
bindings_run(struct controller_ctx *ctx)
{
    const struct sbrec_bindings *bindings_rec;
    struct ovsdb_idl_txn *txn;
    struct sset lports;
    const char *name;
    int retval;

    sset_init(&lports);
    get_local_iface_ids(ctx, &lports);

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller: updating bindings for '%s'",
                              ctx->chassis_name);

    SBREC_BINDINGS_FOR_EACH(bindings_rec, ctx->ovnsb_idl) {
        if (sset_find_and_delete(&lports, bindings_rec->logical_port)) {
            if (!strcmp(bindings_rec->chassis, ctx->chassis_name)) {
                continue;
            }
            if (bindings_rec->chassis[0]) {
                VLOG_INFO("Changing chassis for lport %s from %s to %s",
                          bindings_rec->logical_port, bindings_rec->chassis,
                          ctx->chassis_name);
            }
            sbrec_bindings_set_chassis(bindings_rec, ctx->chassis_name);
        } else if (!strcmp(bindings_rec->chassis, ctx->chassis_name)) {
            sbrec_bindings_set_chassis(bindings_rec, "");
        }
    }

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval == TXN_ERROR) {
        VLOG_INFO("Problem committing bindings information: %s",
                  ovsdb_idl_txn_status_to_string(retval));
    }

    ovsdb_idl_txn_destroy(txn);

    SSET_FOR_EACH (name, &lports) {
        VLOG_DBG("No binding record for lport %s", name);
    }
    sset_destroy(&lports);
}

void
bindings_destroy(struct controller_ctx *ctx)
{
    int retval = TXN_TRY_AGAIN;

    ovs_assert(ctx->ovnsb_idl);

    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct sbrec_bindings *bindings_rec;
        struct ovsdb_idl_txn *txn;

        txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
        ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller: removing all bindings for '%s'",
                              ctx->chassis_name);

        SBREC_BINDINGS_FOR_EACH(bindings_rec, ctx->ovnsb_idl) {
            if (!strcmp(bindings_rec->chassis, ctx->chassis_name)) {
                sbrec_bindings_set_chassis(bindings_rec, "");
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
