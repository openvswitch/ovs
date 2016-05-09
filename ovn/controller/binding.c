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

#include "lib/bitmap.h"
#include "lib/hmap.h"
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
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_ingress_policing_rate);
    ovsdb_idl_add_column(ovs_idl,
                         &ovsrec_interface_col_ingress_policing_burst);
}

static void
get_local_iface_ids(const struct ovsrec_bridge *br_int, struct shash *lports)
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
            shash_add(lports, iface_id, iface_rec);
        }
    }
}

static void
update_ct_zones(struct sset *lports, struct simap *ct_zones,
                unsigned long *ct_zone_bitmap)
{
    struct simap_node *ct_zone, *ct_zone_next;
    const char *iface_id;
    int scan_start = 1;

    /* xxx This is wasteful to assign a zone to each port--even if no
     * xxx security policy is applied. */

    /* Delete any zones that are associated with removed ports. */
    SIMAP_FOR_EACH_SAFE(ct_zone, ct_zone_next, ct_zones) {
        if (!sset_contains(lports, ct_zone->name)) {
            bitmap_set0(ct_zone_bitmap, ct_zone->data);
            simap_delete(ct_zones, ct_zone);
        }
    }

    /* Assign a unique zone id for each logical port. */
    SSET_FOR_EACH(iface_id, lports) {
        size_t zone;

        if (simap_contains(ct_zones, iface_id)) {
            continue;
        }

        /* We assume that there are 64K zones and that we own them all. */
        zone = bitmap_scan(ct_zone_bitmap, 0, scan_start, MAX_CT_ZONES + 1);
        if (zone == MAX_CT_ZONES + 1) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "exhausted all ct zones");
            return;
        }
        scan_start = zone + 1;

        bitmap_set1(ct_zone_bitmap, zone);
        simap_put(ct_zones, iface_id, zone);

        /* xxx We should erase any old entries for this
         * xxx zone, but we need a generic interface to the conntrack
         * xxx table. */
    }
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
    hmap_insert(local_datapaths, &ld->hmap_node,
                binding_rec->datapath->tunnel_key);
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

void
binding_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int,
            const char *chassis_id, struct simap *ct_zones,
            unsigned long *ct_zone_bitmap, struct hmap *local_datapaths)
{
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_port_binding *binding_rec;

    chassis_rec = get_chassis(ctx->ovnsb_idl, chassis_id);

    struct shash lports = SHASH_INITIALIZER(&lports);
    if (br_int) {
        get_local_iface_ids(br_int, &lports);
    } else {
        /* We have no integration bridge, therefore no local logical ports.
         * We'll remove our chassis from all port binding records below. */
    }

    struct sset all_lports = SSET_INITIALIZER(&all_lports);
    struct shash_node *node;
    SHASH_FOR_EACH (node, &lports) {
        sset_add(&all_lports, node->name);
    }

    /* Run through each binding record to see if it is resident on this
     * chassis and update the binding accordingly.  This includes both
     * directly connected logical ports and children of those ports. */
    SBREC_PORT_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
        const struct ovsrec_interface *iface_rec
            = shash_find_and_delete(&lports, binding_rec->logical_port);
        if (iface_rec
            || (binding_rec->parent_port && binding_rec->parent_port[0] &&
                sset_contains(&all_lports, binding_rec->parent_port))) {
            if (binding_rec->parent_port && binding_rec->parent_port[0]) {
                /* Add child logical port to the set of all local ports. */
                sset_add(&all_lports, binding_rec->logical_port);
            }
            add_local_datapath(local_datapaths, binding_rec);
            if (iface_rec && ctx->ovs_idl_txn) {
                update_qos(iface_rec, binding_rec);
            }
            if (ctx->ovnsb_idl_txn && chassis_rec
                && binding_rec->chassis != chassis_rec) {
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
            }
        } else if (chassis_rec && binding_rec->chassis == chassis_rec
                   && strcmp(binding_rec->type, "gateway")) {
            if (ctx->ovnsb_idl_txn) {
                VLOG_INFO("Releasing lport %s from this chassis.",
                          binding_rec->logical_port);
                sbrec_port_binding_set_chassis(binding_rec, NULL);
            }
        } else if (!binding_rec->chassis
                   && !strcmp(binding_rec->type, "localnet")) {
            /* localnet ports will never be bound to a chassis, but we want
             * to list them in all_lports because we want to allocate
             * a conntrack zone ID for each one, as we'll be creating
             * a patch port for each one. */
            sset_add(&all_lports, binding_rec->logical_port);
        }
    }

    SHASH_FOR_EACH (node, &lports) {
        VLOG_DBG("No port binding record for lport %s", node->name);
    }

    update_ct_zones(&all_lports, ct_zones, ct_zone_bitmap);

    shash_destroy(&lports);
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
