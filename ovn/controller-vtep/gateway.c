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
#include "gateway.h"

#include "lib/poll-loop.h"
#include "lib/simap.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"
#include "ovn-controller-vtep.h"

VLOG_DEFINE_THIS_MODULE(gateway);

/*
 * Registers the physical switches in vtep to ovnsb as chassis.  For each
 * physical switch in the vtep database, finds all vtep logical switches that
 * are associated with the physical switch, and updates the corresponding
 * chassis's 'vtep_logical_switches' column.
 *
 */

/* Global revalidation sequence number, incremented at each call to
 * 'revalidate_gateway()'. */
static unsigned int gw_reval_seq;

/* Maps all chassis created by the gateway module to their own reval_seq. */
static struct simap gw_chassis_map = SIMAP_INITIALIZER(&gw_chassis_map);

/* Creates and returns a new instance of 'struct sbrec_chassis'. */
static const struct sbrec_chassis *
create_chassis_rec(struct ovsdb_idl_txn *txn, const char *name,
                   const char *encap_ip)
{
    const struct sbrec_chassis *chassis_rec;
    struct sbrec_encap *encap_rec;

    VLOG_INFO("add Chassis row for VTEP physical switch (%s)", name);

    chassis_rec = sbrec_chassis_insert(txn);
    sbrec_chassis_set_name(chassis_rec, name);
    encap_rec = sbrec_encap_insert(txn);
    sbrec_encap_set_type(encap_rec, OVN_SB_ENCAP_TYPE);
    sbrec_encap_set_ip(encap_rec, encap_ip);
    const struct smap options = SMAP_CONST1(&options, "csum", "false");
    sbrec_encap_set_options(encap_rec, &options);
    sbrec_chassis_set_encaps(chassis_rec, &encap_rec, 1);

    return chassis_rec;
}

/* Revalidates chassis in ovnsb against vtep database.  Creates chassis for
 * new vtep physical switch.  And removes chassis which no longer have
 * physical switch in vtep.
 *
 * xxx: Support multiple tunnel encaps.
 *
 * */
static void
revalidate_gateway(struct controller_vtep_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;

    /* Increments the global revalidation sequence number. */
    gw_reval_seq++;

    ovsdb_idl_txn_add_comment(ctx->ovnsb_idl_txn,
                              "ovn-controller-vtep: updating vtep chassis");

    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec;
        struct simap_node *gw_node;
        const char *encap_ip;

        encap_ip = pswitch->n_tunnel_ips ? pswitch->tunnel_ips[0] : "";
        gw_node = simap_find(&gw_chassis_map, pswitch->name);
        chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        if (chassis_rec) {
            if (!gw_node &&
                (strcmp(chassis_rec->encaps[0]->type, OVN_SB_ENCAP_TYPE)
                 || strcmp(chassis_rec->encaps[0]->ip, encap_ip))) {
                VLOG_WARN("Chassis config changing on startup, make sure "
                          "multiple chassis are not configured : %s/%s->%s/%s",
                          chassis_rec->encaps[0]->type,
                          chassis_rec->encaps[0]->ip,
                          OVN_SB_ENCAP_TYPE, encap_ip);
            }
            /* Updates chassis's encap if anything changed. */
            if (strcmp(chassis_rec->encaps[0]->type, OVN_SB_ENCAP_TYPE)) {
                VLOG_WARN("Chassis for VTEP physical switch (%s) can only have "
                          "encap type \"%s\"", pswitch->name, OVN_SB_ENCAP_TYPE);
                sbrec_encap_set_type(chassis_rec->encaps[0], OVN_SB_ENCAP_TYPE);
            }
            if (strcmp(chassis_rec->encaps[0]->ip, encap_ip)) {
                sbrec_encap_set_ip(chassis_rec->encaps[0], encap_ip);
            }
            if (smap_get_bool(&chassis_rec->encaps[0]->options, "csum", true)) {
                const struct smap options = SMAP_CONST1(&options, "csum",
                                                                  "false");
                sbrec_encap_set_options(chassis_rec->encaps[0], &options);
            }
        } else {
            if (gw_node) {
                VLOG_WARN("Chassis for VTEP physical switch (%s) disappears, "
                          "maybe deleted by ovn-sbctl, adding it back",
                          pswitch->name);
            }
            /* Creates a new chassis for the VTEP physical switch. */
            create_chassis_rec(ctx->ovnsb_idl_txn, pswitch->name, encap_ip);
        }
        /* Updates or creates the simap node for 'pswitch->name'. */
        simap_put(&gw_chassis_map, pswitch->name, gw_reval_seq);
    }

    struct simap_node *iter, *next;
    /* For 'gw_node' in 'gw_chassis_map' whose data is not
     * 'gw_reval_seq', it means the corresponding physical switch no
     * longer exist.  So, garbage collects them. */
    SIMAP_FOR_EACH_SAFE (iter, next, &gw_chassis_map) {
        if (iter->data != gw_reval_seq) {
            const struct sbrec_chassis *chassis_rec;

            chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, iter->name);
            if (chassis_rec) {
                sbrec_chassis_delete(chassis_rec);
            }
            simap_delete(&gw_chassis_map, iter);
        }
    }
}

/* Updates the 'vtep_logical_switches' column in the Chassis table based
 * on vtep database configuration. */
static void
update_vtep_logical_switches(struct controller_vtep_ctx *ctx)
{
    const struct vteprec_physical_switch *pswitch;

    ovsdb_idl_txn_add_comment(ctx->ovnsb_idl_txn, "ovn-controller-vtep: "
                              "updating chassis's vtep_logical_switches");

    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec =
            get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        struct sset lswitches = SSET_INITIALIZER(&lswitches);
        size_t i;

        for (i = 0; i < pswitch->n_ports; i++) {
            const struct vteprec_physical_port *port = pswitch->ports[i];
            size_t j;

            for (j = 0; j < port->n_vlan_bindings; j++) {
                const struct vteprec_logical_switch *vtep_lswitch;

                vtep_lswitch = port->value_vlan_bindings[j];
                /* If not already in 'lswitches', records it. */
                if (!sset_find(&lswitches, vtep_lswitch->name)) {
                    sset_add(&lswitches, vtep_lswitch->name);
                }
            }
        }

        const char **ls_arr = sset_array(&lswitches);
        sbrec_chassis_set_vtep_logical_switches(chassis_rec, ls_arr,
                                                sset_count(&lswitches));
        free(ls_arr);
        sset_destroy(&lswitches);
    }
}


void
gateway_run(struct controller_vtep_ctx *ctx)
{
    if (!ctx->ovnsb_idl_txn) {
        return;
    }

    revalidate_gateway(ctx);
    update_vtep_logical_switches(ctx);
}

/* Destroys the chassis table entries for vtep physical switches.
 * Returns true when done (i.e. there is no change made to 'ctx->ovnsb_idl'),
 * otherwise returns false. */
bool
gateway_cleanup(struct controller_vtep_ctx *ctx)
{
    static bool simap_destroyed = false;
    const struct vteprec_physical_switch *pswitch;

    if (!ctx->ovnsb_idl_txn) {
        return false;
    }

    bool all_done = true;
    ovsdb_idl_txn_add_comment(ctx->ovnsb_idl_txn, "ovn-controller-vtep: "
                              "unregistering vtep chassis");
    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec;

        chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        if (!chassis_rec) {
            continue;
        }
        all_done = false;
        sbrec_chassis_delete(chassis_rec);
    }
    if (!simap_destroyed) {
        simap_destroy(&gw_chassis_map);
        simap_destroyed = true;
    }

    return all_done;
}
