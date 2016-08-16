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
#include "binding.h"
#include "lflow.h"
#include "lport.h"

#include "lib/bitmap.h"
#include "lib/poll-loop.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(binding);

/* A set of the iface-id values of local interfaces on this chassis. */
static struct sset local_ids = SSET_INITIALIZER(&local_ids);

/* When this gets set to true, the next run will re-check all binding records. */
static bool process_full_binding = false;

void
binding_reset_processing(void)
{
    process_full_binding = true;
}

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
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_ingress_policing_rate);
    ovsdb_idl_add_column(ovs_idl,
                         &ovsrec_interface_col_ingress_policing_burst);
}

static bool
get_local_iface_ids(const struct ovsrec_bridge *br_int,
                    struct shash *lport_to_iface,
                    struct sset *all_lports)
{
    int i;
    bool changed = false;

    struct sset old_local_ids = SSET_INITIALIZER(&old_local_ids);
    sset_clone(&old_local_ids, &local_ids);

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
            shash_add(lport_to_iface, iface_id, iface_rec);
            if (!sset_find_and_delete(&old_local_ids, iface_id)) {
                sset_add(&local_ids, iface_id);
                sset_add(all_lports, iface_id);
                changed = true;
            }
        }
    }

    /* Any item left in old_local_ids is an ID for an interface
     * that has been removed. */
    if (!changed && !sset_is_empty(&old_local_ids)) {
        changed = true;

        const char *cur_id;
        SSET_FOR_EACH(cur_id, &old_local_ids) {
            sset_find_and_delete(&local_ids, cur_id);
            sset_find_and_delete(all_lports, cur_id);
        }
    }

    sset_destroy(&old_local_ids);

    return changed;
}

static struct local_datapath *
local_datapath_lookup_by_uuid(struct hmap *hmap_p, const struct uuid *uuid)
{
    struct local_datapath *ld;
    HMAP_FOR_EACH_WITH_HASH(ld, uuid_hmap_node, uuid_hash(uuid), hmap_p) {
        if (uuid_equals(&ld->uuid, uuid)) {
            return ld;
        }
    }
    return NULL;
}

static void
remove_local_datapath(struct hmap *local_datapaths, struct local_datapath *ld)
{
    if (ld->logical_port) {
        free(ld->logical_port);
        ld->logical_port = NULL;
    }
    hmap_remove(local_datapaths, &ld->hmap_node);
    free(ld);
    lflow_reset_processing();
}

static void
add_local_datapath(struct hmap *local_datapaths,
        const struct sbrec_port_binding *binding_rec)
{
    if (get_local_datapath(local_datapaths,
                           binding_rec->datapath->tunnel_key)) {
        return;
    }

    struct local_datapath *ld = xzalloc(sizeof *ld);
    ld->logical_port = xstrdup(binding_rec->logical_port);
    memcpy(&ld->uuid, &binding_rec->header_.uuid, sizeof ld->uuid);
    hmap_insert(local_datapaths, &ld->hmap_node,
                binding_rec->datapath->tunnel_key);
    lport_index_reset();
    mcgroup_index_reset();
    lflow_reset_processing();
}

static void
update_qos(const struct ovsrec_interface *iface_rec,
           const struct sbrec_port_binding *pb)
{
    int rate = smap_get_int(&pb->options, "policing_rate", 0);
    int burst = smap_get_int(&pb->options, "policing_burst", 0);

    ovsrec_interface_set_ingress_policing_rate(iface_rec, MAX(0, rate));
    ovsrec_interface_set_ingress_policing_burst(iface_rec, MAX(0, burst));
}

static void
consider_local_datapath(struct controller_ctx *ctx,
                        const struct sbrec_chassis *chassis_rec,
                        const struct sbrec_port_binding *binding_rec,
                        struct hmap *local_datapaths,
                        struct shash *lport_to_iface,
                        struct sset *all_lports)
{
    const struct ovsrec_interface *iface_rec
        = shash_find_data(lport_to_iface, binding_rec->logical_port);

    if (iface_rec
        || (binding_rec->parent_port && binding_rec->parent_port[0] &&
            sset_contains(&local_ids, binding_rec->parent_port))) {
        add_local_datapath(local_datapaths, binding_rec);
        if (iface_rec && ctx->ovs_idl_txn) {
            update_qos(iface_rec, binding_rec);
        }
        if (binding_rec->chassis == chassis_rec) {
            return;
        }
        if (ctx->ovnsb_idl_txn) {
            if (binding_rec->chassis) {
                VLOG_INFO("Changing chassis for lport %s from %s to %s.",
                          binding_rec->logical_port,
                          binding_rec->chassis->name,
                          chassis_rec->name);
            } else {
                VLOG_INFO("Claiming lport %s for this chassis.",
                          binding_rec->logical_port);
            }
            sbrec_port_binding_set_chassis(binding_rec, chassis_rec);
            if (binding_rec->parent_port && binding_rec->parent_port[0]) {
                sset_add(all_lports, binding_rec->logical_port);
            }
        }
    } else if (!strcmp(binding_rec->type, "l2gateway")) {
        const char *chassis_id = smap_get(&binding_rec->options,
                                          "l2gateway-chassis");
        if (!chassis_id || strcmp(chassis_id, chassis_rec->name)) {
            if (binding_rec->chassis == chassis_rec && ctx->ovnsb_idl_txn) {
                VLOG_INFO("Releasing l2gateway port %s from this chassis.",
                          binding_rec->logical_port);
                sbrec_port_binding_set_chassis(binding_rec, NULL);
                sset_find_and_delete(all_lports, binding_rec->logical_port);
            }
            return;
        }

        if (binding_rec->chassis == chassis_rec) {
            return;
        }

        if (!strcmp(chassis_id, chassis_rec->name) && ctx->ovnsb_idl_txn) {
            VLOG_INFO("Claiming l2gateway port %s for this chassis.",
                      binding_rec->logical_port);
            sbrec_port_binding_set_chassis(binding_rec, chassis_rec);
            sset_add(all_lports, binding_rec->logical_port);
            add_local_datapath(local_datapaths, binding_rec);
        }
    } else if (!strcmp(binding_rec->type, "l3gateway")) {
        const char *chassis = smap_get(&binding_rec->options,
                                       "l3gateway-chassis");
        if (!strcmp(chassis, chassis_rec->name) && ctx->ovnsb_idl_txn) {
            add_local_datapath(local_datapaths, binding_rec);
        }
    } else if (chassis_rec && binding_rec->chassis == chassis_rec) {
        if (ctx->ovnsb_idl_txn) {
            VLOG_INFO("Releasing lport %s from this chassis.",
                      binding_rec->logical_port);
            sbrec_port_binding_set_chassis(binding_rec, NULL);
            sset_find_and_delete(all_lports, binding_rec->logical_port);
        }
    } else if (!binding_rec->chassis
               && !strcmp(binding_rec->type, "localnet")) {
        /* Add all localnet ports to all_lports so that we allocate ct zones
         * for them. */
        sset_add(all_lports, binding_rec->logical_port);
    }
}

void
binding_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int,
            const char *chassis_id, struct hmap *local_datapaths,
            struct sset *all_lports)
{
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_port_binding *binding_rec;
    struct shash lport_to_iface = SHASH_INITIALIZER(&lport_to_iface);

    chassis_rec = get_chassis(ctx->ovnsb_idl, chassis_id);
    if (!chassis_rec) {
        return;
    }

    if (br_int) {
        if (ctx->ovnsb_idl_txn && get_local_iface_ids(br_int, &lport_to_iface,
                                                      all_lports)) {
            process_full_binding = true;
        }
    } else {
        /* We have no integration bridge, therefore no local logical ports.
         * We'll remove our chassis from all port binding records below. */
        process_full_binding = true;
    }

    /* Run through each binding record to see if it is resident on this
     * chassis and update the binding accordingly.  This includes both
     * directly connected logical ports and children of those ports. */
    if (process_full_binding) {
        /* Detect any entries in all_lports that have been deleted.
         * In particular, this will catch localnet ports that we
         * put in all_lports. */
        struct sset removed_lports = SSET_INITIALIZER(&removed_lports);
        sset_clone(&removed_lports, all_lports);

        struct hmap keep_local_datapath_by_uuid =
            HMAP_INITIALIZER(&keep_local_datapath_by_uuid);
        SBREC_PORT_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
            sset_find_and_delete(&removed_lports, binding_rec->logical_port);
            consider_local_datapath(ctx, chassis_rec, binding_rec,
                                    local_datapaths, &lport_to_iface,
                                    all_lports);
            struct local_datapath *ld = xzalloc(sizeof *ld);
            memcpy(&ld->uuid, &binding_rec->header_.uuid, sizeof ld->uuid);
            hmap_insert(&keep_local_datapath_by_uuid, &ld->uuid_hmap_node,
                        uuid_hash(&ld->uuid));
        }
        struct local_datapath *old_ld, *next;
        HMAP_FOR_EACH_SAFE (old_ld, next, hmap_node, local_datapaths) {
            if (!local_datapath_lookup_by_uuid(&keep_local_datapath_by_uuid,
                                               &old_ld->uuid)) {
                remove_local_datapath(local_datapaths, old_ld);
            }
        }
        hmap_destroy(&keep_local_datapath_by_uuid);

        /* Any remaining entries in removed_lports are logical ports that
         * have been deleted and should also be removed from all_ports. */
        const char *cur_id;
        SSET_FOR_EACH(cur_id, &removed_lports) {
            sset_find_and_delete(all_lports, cur_id);
        }

        process_full_binding = false;
    } else {
        SBREC_PORT_BINDING_FOR_EACH_TRACKED(binding_rec, ctx->ovnsb_idl) {
            if (sbrec_port_binding_is_deleted(binding_rec)) {
                /* If a port binding was bound to this chassis and removed before
                 * the ovs interface was removed, we'll catch that here and trigger
                 * a full bindings refresh.  This is to see if we need to clear
                 * an entry out of local_datapaths. */
                if (binding_rec->chassis == chassis_rec) {
                    process_full_binding = true;
                    poll_immediate_wake();
                }
            } else {
                consider_local_datapath(ctx, chassis_rec, binding_rec,
                                        local_datapaths, &lport_to_iface,
                                        all_lports);
            }
        }
    }

    shash_destroy(&lport_to_iface);
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
        = get_chassis(ctx->ovnsb_idl, chassis_id);
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
