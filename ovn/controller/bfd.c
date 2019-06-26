/* Copyright (c) 2017 Red Hat, Inc.
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
#include "bfd.h"
#include "encaps.h"
#include "lport.h"
#include "ovn-controller.h"

#include "lib/hash.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(ovn_bfd);

void
bfd_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    /* NOTE: this assumes that binding.c has added the
     * ovsrec_interface table */
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd_status);
}

void
bfd_calculate_active_tunnels(const struct ovsrec_bridge *br_int,
                             struct sset *active_tunnels)
{
    int i;

    if (!br_int) {
        /* Nothing to do if integration bridge doesn't exist. */
        return;
    }

    for (i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];

        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }

        int j;
        for (j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;
            iface_rec = port_rec->interfaces[j];

            /* Check if this is a tunnel interface. */
            if (smap_get(&iface_rec->options, "remote_ip")) {
                /* Add ovn-chassis-id if the bfd_status of the tunnel
                 * is active */
                const char *bfd = smap_get(&iface_rec->bfd, "enable");
                if (bfd && !strcmp(bfd, "true")) {
                    const char *status = smap_get(&iface_rec->bfd_status,
                                                  "state");
                    if (status && !strcmp(status, "up")) {
                        const char *id = smap_get(&port_rec->external_ids,
                                                  "ovn-chassis-id");
                        if (id) {
                            char *chassis_name = NULL;

                            if (encaps_tunnel_id_parse(id, &chassis_name,
                                                       NULL)) {
                                if (!sset_contains(active_tunnels,
                                                   chassis_name)) {
                                    sset_add(active_tunnels, chassis_name);
                                }
                                free(chassis_name);
                            }
                        }
                    }
                }
            }
        }
    }
}

/* Loops through the HA chassis groups in the SB DB and returns
 * the set of chassis which the call can establish the BFD sessions
 * with.
 * Eg.
 * If there are 2 HA chassis groups.
 * Group name - hapgrp1
 *   - HA chassis - (HA1, HA2, HA3)
 *   - ref chassis - (C1, C2)
 *
 * Group name - hapgrp2
 *   - HA chassis - (HA1, HA4, HA5)
 *   - ref chassis - (C1, C3, C4)
 *
 * If 'our_chassis' is HA1 then this function returns
 *  bfd chassis set - (HA2, HA3, HA4 HA5, C1, C2, C3, C4)
 *
 * If 'our_chassis' is C1 then this function returns
 *  bfd chassis set - (HA1, HA2, HA3, HA4, HA5)
 *
 * If 'our_chassis' is HA5 then this function returns
 *  bfd chassis set - (HA1, HA4, C1, C3, C4)
 *
 * If 'our_chassis' is C2 then this function returns
 *  bfd chassis set - (HA1, HA2, HA3)
 *
 * If 'our_chassis' is C5 then this function returns empty bfd set.
 */
static void
bfd_calculate_chassis(
    const struct sbrec_chassis *our_chassis,
    const struct sbrec_ha_chassis_group_table *ha_chassis_grp_table,
    struct sset *bfd_chassis)
{
    const struct sbrec_ha_chassis_group *ha_chassis_grp;
    SBREC_HA_CHASSIS_GROUP_TABLE_FOR_EACH (ha_chassis_grp,
                                           ha_chassis_grp_table) {
        bool is_ha_chassis = false;
        struct sset grp_chassis = SSET_INITIALIZER(&grp_chassis);
        const struct sbrec_ha_chassis *ha_ch;
        bool bfd_setup_required = false;
        if (ha_chassis_grp->n_ha_chassis < 2) {
            /* No need to consider the chassis group for BFD if
             * there is  1 or no chassis in it. */
            continue;
        }
        for (size_t i = 0; i < ha_chassis_grp->n_ha_chassis; i++) {
            ha_ch = ha_chassis_grp->ha_chassis[i];
            if (!ha_ch->chassis) {
                continue;
            }
            sset_add(&grp_chassis, ha_ch->chassis->name);
            if (our_chassis == ha_ch->chassis) {
                is_ha_chassis = true;
                bfd_setup_required = true;
            }
        }

        if (is_ha_chassis) {
            /* It's an HA chassis. So add the ref_chassis to the bfd set. */
            for (size_t i = 0; i < ha_chassis_grp->n_ref_chassis; i++) {
                sset_add(&grp_chassis, ha_chassis_grp->ref_chassis[i]->name);
            }
        } else {
            /* This is not an HA chassis. Check if this chassis is present
             * in the ref_chassis list. If so add the ha_chassis to the
             * sset .*/
            for (size_t i = 0; i < ha_chassis_grp->n_ref_chassis; i++) {
                if (our_chassis == ha_chassis_grp->ref_chassis[i]) {
                    bfd_setup_required = true;
                    break;
                }
            }
        }

        if (bfd_setup_required) {
            const char *name;
            SSET_FOR_EACH (name, &grp_chassis) {
                sset_add(bfd_chassis, name);
            }
        }
        sset_destroy(&grp_chassis);
    }
}

void
bfd_run(const struct ovsrec_interface_table *interface_table,
        const struct ovsrec_bridge *br_int,
        const struct sbrec_chassis *chassis_rec,
        const struct sbrec_ha_chassis_group_table *ha_chassis_grp_table,
        const struct sbrec_sb_global_table *sb_global_table)
{
    if (!chassis_rec) {
        return;
    }
    struct sset bfd_chassis = SSET_INITIALIZER(&bfd_chassis);
    bfd_calculate_chassis(chassis_rec, ha_chassis_grp_table,
                          &bfd_chassis);

    /* Identify tunnels ports(connected to remote chassis id) to enable bfd */
    struct sset tunnels = SSET_INITIALIZER(&tunnels);
    struct sset bfd_ifaces = SSET_INITIALIZER(&bfd_ifaces);
    for (size_t k = 0; k < br_int->n_ports; k++) {
        const char *tunnel_id = smap_get(&br_int->ports[k]->external_ids,
                                          "ovn-chassis-id");
        if (tunnel_id) {
            char *chassis_name = NULL;
            char *port_name = br_int->ports[k]->name;

            sset_add(&tunnels, port_name);

            if (encaps_tunnel_id_parse(tunnel_id, &chassis_name, NULL)) {
                if (sset_contains(&bfd_chassis, chassis_name)) {
                    sset_add(&bfd_ifaces, port_name);
                }
                free(chassis_name);
            }
        }
    }

    const struct sbrec_sb_global *sb
        = sbrec_sb_global_table_first(sb_global_table);
    struct smap bfd = SMAP_INITIALIZER(&bfd);
    smap_add(&bfd, "enable", "true");

    if (sb) {
        const char *min_rx = smap_get(&sb->options, "bfd-min-rx");
        const char *decay_min_rx = smap_get(&sb->options, "bfd-decay-min-rx");
        const char *min_tx = smap_get(&sb->options, "bfd-min-tx");
        const char *mult = smap_get(&sb->options, "bfd-mult");
        if (min_rx) {
            smap_add(&bfd, "min_rx", min_rx);
        }
        if (decay_min_rx) {
            smap_add(&bfd, "decay_min_rx", decay_min_rx);
        }
        if (min_tx) {
            smap_add(&bfd, "min_tx", min_tx);
        }
        if (mult) {
            smap_add(&bfd, "mult", mult);
        }
    }

    /* Enable or disable bfd */
    const struct ovsrec_interface *iface;
    OVSREC_INTERFACE_TABLE_FOR_EACH (iface, interface_table) {
        if (sset_contains(&tunnels, iface->name)) {
            if (sset_contains(&bfd_ifaces, iface->name)) {
                /* We need to enable BFD for this interface. Configure the
                 * BFD params if
                 *  - If BFD was disabled earlier
                 *  - Or if CMS has updated BFD config options.
                 */
                if (!smap_equal(&iface->bfd, &bfd)) {
                    ovsrec_interface_verify_bfd(iface);
                    ovsrec_interface_set_bfd(iface, &bfd);
                    VLOG_INFO("Enabled BFD on interface %s", iface->name);
                }
            } else {
                /* We need to disable BFD for this interface if it was enabled
                 * earlier. */
                if (smap_count(&iface->bfd)) {
                    ovsrec_interface_verify_bfd(iface);
                    ovsrec_interface_set_bfd(iface, NULL);
                    VLOG_INFO("Disabled BFD on interface %s", iface->name);
                }
            }
        }
    }

    smap_destroy(&bfd);
    sset_destroy(&tunnels);
    sset_destroy(&bfd_ifaces);
    sset_destroy(&bfd_chassis);
}
