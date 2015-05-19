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
#include "physical.h"
#include "match.h"
#include "ofctrl.h"
#include "ofp-actions.h"
#include "ofpbuf.h"
#include "ovn-controller.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "pipeline.h"
#include "simap.h"
#include "vswitch-idl.h"

void
physical_init(struct controller_ctx *ctx)
{
    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_port_col_external_ids);

    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_interface_col_external_ids);
}

void
physical_run(struct controller_ctx *ctx)
{
    struct simap lport_to_ofport = SIMAP_INITIALIZER(&lport_to_ofport);
    struct simap chassis_to_ofport = SIMAP_INITIALIZER(&chassis_to_ofport);
    for (int i = 0; i < ctx->br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = ctx->br_int->ports[i];
        if (!strcmp(port_rec->name, ctx->br_int_name)) {
            continue;
        }

        const char *chassis_id = smap_get(&port_rec->external_ids,
                                          "ovn-chassis-id");
        if (chassis_id && !strcmp(chassis_id, ctx->chassis_id)) {
            continue;
        }

        for (int j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec = port_rec->interfaces[j];

            /* Get OpenFlow port number. */
            if (!iface_rec->n_ofport) {
                continue;
            }
            int64_t ofport = iface_rec->ofport[0];
            if (ofport < 1 || ofport > ofp_to_u16(OFPP_MAX)) {
                continue;
            }

            /* Record as chassis or local logical port. */
            if (chassis_id) {
                simap_put(&chassis_to_ofport, chassis_id, ofport);
                break;
            } else {
                const char *iface_id = smap_get(&iface_rec->external_ids,
                                                "iface-id");
                if (iface_id) {
                    simap_put(&lport_to_ofport, iface_id, ofport);
                }
            }
        }
    }

    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);

    /* Set up flows in table 0 for physical-to-logical translation and in table
     * 64 for logical-to-physical translation. */
    const struct sbrec_binding *binding;
    SBREC_BINDING_FOR_EACH (binding, ctx->ovnsb_idl) {
        /* Find the Openflow port for the logical port, as 'ofport'.  If it's
         * on a remote chassis, this is the OpenFlow port for the tunnel to
         * that chassis (and set 'local' to false).  Otherwise, if it's on the
         * chassis we're managing, this is the OpenFlow port for the vif itself
         * (and set 'local' to true). When 'parent_port' is set for a binding,
         * it implies a container sitting inside a VM reachable via a 'tag'.
         */

        int tag = 0;
        ofp_port_t ofport;
        if (binding->parent_port) {
            ofport = u16_to_ofp(simap_get(&lport_to_ofport,
                                          binding->parent_port));
            if (ofport && binding->tag) {
                tag = *binding->tag;
            }
        } else {
            ofport = u16_to_ofp(simap_get(&lport_to_ofport,
                                          binding->logical_port));
        }

        bool local = ofport != 0;
        if (!local) {
            ofport = u16_to_ofp(simap_get(&chassis_to_ofport,
                                          binding->chassis->name));
            if (!ofport) {
                continue;
            }
        }

        /* Translate the logical datapath into the form we use in
         * MFF_METADATA. */
        uint32_t ldp = ldp_to_integer(&binding->logical_datapath);
        if (!ldp) {
            continue;
        }

        struct match match;
        if (local) {
            /*
             * Packets that arrive from a vif can belong to a VM or
             * to a container located inside that VM. Packets that
             * arrive from containers have a tag (vlan) associated with them.
             *
             * Table 0, Priority 150 and 100.
             * ==============================
             * Priority 150 is for traffic belonging to containers. For such
             * traffic, match on the tags and then strip the tag.
             * Priority 100 is for traffic belonging to VMs.
             *
             * For both types of traffic: set MFF_LOG_INPORT to the
             * logical input port, MFF_METADATA to the logical datapath, and
             * resubmit into the logical pipeline starting at table 16. */
            match_init_catchall(&match);
            ofpbuf_clear(&ofpacts);
            match_set_in_port(&match, ofport);
            if (tag) {
                match_set_dl_vlan(&match, htons(tag));
            }

            /* Set MFF_METADATA. */
            struct ofpact_set_field *sf = ofpact_put_SET_FIELD(&ofpacts);
            sf->field = mf_from_id(MFF_METADATA);
            sf->value.be64 = htonll(ldp);
            sf->mask.be64 = OVS_BE64_MAX;

            /* Set MFF_LOG_INPORT. */
            sf = ofpact_put_SET_FIELD(&ofpacts);
            sf->field = mf_from_id(MFF_LOG_INPORT);
            sf->value.be32 = htonl(binding->tunnel_key);
            sf->mask.be32 = OVS_BE32_MAX;

            /* Strip vlans. */
            if (tag) {
                ofpact_put_STRIP_VLAN(&ofpacts);
            }

            /* Resubmit to first logical pipeline table. */
            struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
            resubmit->in_port = OFPP_IN_PORT;
            resubmit->table_id = 16;
            ofctrl_add_flow(0, tag ? 150 : 100, &match, &ofpacts);

            /* Table 0, Priority 50.
             * =====================
             *
             * For packets that arrive from a remote node destined to this
             * local vif: deliver directly to the vif. If the destination
             * is a container sitting behind a vif, tag the packets. */
            match_init_catchall(&match);
            ofpbuf_clear(&ofpacts);
            match_set_tun_id(&match, htonll(binding->tunnel_key));
            if (tag) {
                struct ofpact_vlan_vid *vlan_vid;
                vlan_vid = ofpact_put_SET_VLAN_VID(&ofpacts);
                vlan_vid->vlan_vid = tag;
                vlan_vid->push_vlan_if_needed = true;
            }
            ofpact_put_OUTPUT(&ofpacts)->port = ofport;
            ofctrl_add_flow(0, 50, &match, &ofpacts);
        }

        /* Table 64, Priority 100.
         * =======================
         *
         * Drop packets whose logical inport and outport are the same. */
        match_init_catchall(&match);
        ofpbuf_clear(&ofpacts);
        match_set_reg(&match, MFF_LOG_INPORT - MFF_REG0, binding->tunnel_key);
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, binding->tunnel_key);
        ofctrl_add_flow(64, 100, &match, &ofpacts);

        /* Table 64, Priority 50.
         * ======================
         *
         * For packets to remote machines, send them over a tunnel to the
         * remote chassis.
         *
         * For packets to local vifs, deliver them directly. */
        match_init_catchall(&match);
        ofpbuf_clear(&ofpacts);
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, binding->tunnel_key);
        if (!local) {
            /* Set MFF_TUN_ID. */
            struct ofpact_set_field *sf = ofpact_put_SET_FIELD(&ofpacts);
            sf->field = mf_from_id(MFF_TUN_ID);
            sf->value.be64 = htonll(binding->tunnel_key);
            sf->mask.be64 = OVS_BE64_MAX;
        }
        if (tag) {
            /* For containers sitting behind a local vif, tag the packets
             * before delivering them. Since there is a possibility of
             * packets needing to hair-pin back into the same vif from
             * which it came, make the in_port as zero. */
            struct ofpact_vlan_vid *vlan_vid;
            vlan_vid = ofpact_put_SET_VLAN_VID(&ofpacts);
            vlan_vid->vlan_vid = tag;
            vlan_vid->push_vlan_if_needed = true;

            struct ofpact_set_field *sf = ofpact_put_SET_FIELD(&ofpacts);
            sf->field = mf_from_id(MFF_IN_PORT);
            sf->value.be16 = 0;
            sf->mask.be16 = OVS_BE16_MAX;
        }
        ofpact_put_OUTPUT(&ofpacts)->port = ofport;
        ofctrl_add_flow(64, 50, &match, &ofpacts);
    }

    ofpbuf_uninit(&ofpacts);
    simap_destroy(&lport_to_ofport);
    simap_destroy(&chassis_to_ofport);
}
