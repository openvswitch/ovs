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
#include "byte-order.h"
#include "flow.h"
#include "lflow.h"
#include "lib/poll-loop.h"
#include "ofctrl.h"
#include "openvswitch/hmap.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn/lib/ovn-util.h"
#include "physical.h"
#include "openvswitch/shash.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "util.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(physical);

void
physical_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_external_ids);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
}

static struct simap localvif_to_ofport =
    SIMAP_INITIALIZER(&localvif_to_ofport);
static struct hmap tunnels = HMAP_INITIALIZER(&tunnels);

/* Maps from a chassis to the OpenFlow port number of the tunnel that can be
 * used to reach that chassis. */
struct chassis_tunnel {
    struct hmap_node hmap_node;
    const char *chassis_id;
    ofp_port_t ofport;
    enum chassis_tunnel_type type;
};

static struct chassis_tunnel *
chassis_tunnel_find(const char *chassis_id)
{
    struct chassis_tunnel *tun;
    HMAP_FOR_EACH_WITH_HASH (tun, hmap_node, hash_string(chassis_id, 0),
                             &tunnels) {
        if (!strcmp(tun->chassis_id, chassis_id)) {
            return tun;
        }
    }
    return NULL;
}

static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, 8, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

static void
put_move(enum mf_field_id src, int src_ofs,
         enum mf_field_id dst, int dst_ofs,
         int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_reg_move *move = ofpact_put_REG_MOVE(ofpacts);
    move->src.field = mf_from_id(src);
    move->src.ofs = src_ofs;
    move->src.n_bits = n_bits;
    move->dst.field = mf_from_id(dst);
    move->dst.ofs = dst_ofs;
    move->dst.n_bits = n_bits;
}

static void
put_resubmit(uint8_t table_id, struct ofpbuf *ofpacts)
{
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = table_id;
}

static void
put_encapsulation(enum mf_field_id mff_ovn_geneve,
                  const struct chassis_tunnel *tun,
                  const struct sbrec_datapath_binding *datapath,
                  uint16_t outport, struct ofpbuf *ofpacts)
{
    if (tun->type == GENEVE) {
        put_load(datapath->tunnel_key, MFF_TUN_ID, 0, 24, ofpacts);
        put_load(outport, mff_ovn_geneve, 0, 32, ofpacts);
        put_move(MFF_LOG_INPORT, 0, mff_ovn_geneve, 16, 15, ofpacts);
    } else if (tun->type == STT) {
        put_load(datapath->tunnel_key | (outport << 24), MFF_TUN_ID, 0, 64,
                 ofpacts);
        put_move(MFF_LOG_INPORT, 0, MFF_TUN_ID, 40, 15, ofpacts);
    } else if (tun->type == VXLAN) {
        put_load(datapath->tunnel_key, MFF_TUN_ID, 0, 24, ofpacts);
    } else {
        OVS_NOT_REACHED();
    }
}

static void
put_stack(enum mf_field_id field, struct ofpact_stack *stack)
{
    stack->subfield.field = mf_from_id(field);
    stack->subfield.ofs = 0;
    stack->subfield.n_bits = stack->subfield.field->n_bits;
}

static const struct sbrec_port_binding*
get_localnet_port(struct hmap *local_datapaths, int64_t tunnel_key)
{
    struct local_datapath *ld = get_local_datapath(local_datapaths,
                                                   tunnel_key);
    return ld ? ld->localnet_port : NULL;
}

static void
consider_port_binding(enum mf_field_id mff_ovn_geneve,
                      const struct simap *ct_zones,
                      struct hmap *local_datapaths,
                      struct hmap *patched_datapaths,
                      const struct sbrec_port_binding *binding,
                      struct ofpbuf *ofpacts_p,
                      struct hmap *flow_table)
{
    /* Skip the port binding if the port is on a datapath that is neither
     * local nor with any logical patch port connected, because local ports
     * would never need to talk to those ports.
     *
     * Even with this approach there could still be unnecessary port
     * bindings processed. A better approach would be a kind of "flood
     * fill" algorithm:
     *
     *   1. Initialize set S to the logical datapaths that have a port
     *      located on the hypervisor.
     *
     *   2. For each patch port P in a logical datapath in S, add the
     *      logical datapath of the remote end of P to S.  Iterate
     *      until S reaches a fixed point.
     *
     * This can be implemented in northd, which can generate the sets and
     * save it on each port-binding record in SB, and ovn-controller can
     * use the information directly. However, there can be update storms
     * when a pair of patch ports are added/removed to connect/disconnect
     * large lrouters and lswitches. This need to be studied further.
     */
    uint32_t dp_key = binding->datapath->tunnel_key;
    uint32_t port_key = binding->tunnel_key;
    if (!get_local_datapath(local_datapaths, dp_key)
        && !get_patched_datapath(patched_datapaths, dp_key)) {
        return;
    }

    /* Find the OpenFlow port for the logical port, as 'ofport'.  This is
     * one of:
     *
     *     - If the port is a VIF on the chassis we're managing, the
     *       OpenFlow port for the VIF.  'tun' will be NULL.
     *
     *       The same logic handles logical patch ports, as well as
     *       localnet patch ports.
     *
     *       For a container nested inside a VM and accessible via a VLAN,
     *       'tag' is the VLAN ID; otherwise 'tag' is 0.
     *
     *       For a localnet or l2gateway patch port, if a VLAN ID was
     *       configured, 'tag' is set to that VLAN ID; otherwise 'tag' is 0.
     *
     *     - If the port is on a remote chassis, the OpenFlow port for a
     *       tunnel to the VIF's remote chassis.  'tun' identifies that
     *       tunnel.
     */

    int tag = 0;
    bool nested_container = false;
    ofp_port_t ofport;
    bool is_remote = false;
    if (binding->parent_port && *binding->parent_port) {
        if (!binding->tag) {
            return;
        }
        ofport = u16_to_ofp(simap_get(&localvif_to_ofport,
                                      binding->parent_port));
        if (ofport) {
            tag = *binding->tag;
            nested_container = true;
        }
    } else {
        ofport = u16_to_ofp(simap_get(&localvif_to_ofport,
                                      binding->logical_port));
        if ((!strcmp(binding->type, "localnet")
            || !strcmp(binding->type, "l2gateway"))
            && ofport && binding->tag) {
            tag = *binding->tag;
        }
    }

    const struct chassis_tunnel *tun = NULL;
    const struct sbrec_port_binding *localnet_port =
        get_localnet_port(local_datapaths, dp_key);
    if (!ofport) {
        /* It is remote port, may be reached by tunnel or localnet port */
        is_remote = true;
        if (!binding->chassis) {
            return;
        }
        if (localnet_port) {
            ofport = u16_to_ofp(simap_get(&localvif_to_ofport,
                                          localnet_port->logical_port));
            if (!ofport) {
                return;
            }
        } else {
            tun = chassis_tunnel_find(binding->chassis->name);
            if (!tun) {
                return;
            }
            ofport = tun->ofport;
        }
    }

    struct match match;
    if (!is_remote) {
        int zone_id = simap_get(ct_zones, binding->logical_port);
        /* Packets that arrive from a vif can belong to a VM or
         * to a container located inside that VM. Packets that
         * arrive from containers have a tag (vlan) associated with them.
         */

        /* Table 0, Priority 150 and 100.
         * ==============================
         *
         * Priority 150 is for tagged traffic. This may be containers in a
         * VM or a VLAN on a local network. For such traffic, match on the
         * tags and then strip the tag.
         *
         * Priority 100 is for traffic belonging to VMs or untagged locally
         * connected networks.
         *
         * For both types of traffic: set MFF_LOG_INPORT to the logical
         * input port, MFF_LOG_DATAPATH to the logical datapath, and
         * resubmit into the logical ingress pipeline starting at table
         * 16. */
        ofpbuf_clear(ofpacts_p);
        match_init_catchall(&match);
        match_set_in_port(&match, ofport);

        /* Match a VLAN tag and strip it, including stripping priority tags
         * (e.g. VLAN ID 0).  In the latter case we'll add a second flow
         * for frames that lack any 802.1Q header later. */
        if (tag || !strcmp(binding->type, "localnet")
            || !strcmp(binding->type, "l2gateway")) {
            match_set_dl_vlan(&match, htons(tag));
            if (nested_container) {
                /* When a packet comes from a container sitting behind a
                 * parent_port, we should let it loopback to other containers
                 * or the parent_port itself. */
                put_load(MLF_ALLOW_LOOPBACK, MFF_LOG_FLAGS, 0, 1, ofpacts_p);
            }
            ofpact_put_STRIP_VLAN(ofpacts_p);
        }

        /* Remember the size with just strip vlan added so far,
         * as we're going to remove this with ofpbuf_pull() later. */
        uint32_t ofpacts_orig_size = ofpacts_p->size;

        if (zone_id) {
            put_load(zone_id, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
        }

        int zone_id_dnat, zone_id_snat;
        const struct uuid *key = &binding->datapath->header_.uuid;
        char *dnat = alloc_nat_zone_key(key, "dnat");
        char *snat = alloc_nat_zone_key(key, "snat");

        zone_id_dnat = simap_get(ct_zones, dnat);
        if (zone_id_dnat) {
            put_load(zone_id_dnat, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
        }
        free(dnat);

        zone_id_snat = simap_get(ct_zones, snat);
        if (zone_id_snat) {
            put_load(zone_id_snat, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
        }
        free(snat);

        /* Set MFF_LOG_DATAPATH and MFF_LOG_INPORT. */
        put_load(dp_key, MFF_LOG_DATAPATH, 0, 64, ofpacts_p);
        put_load(port_key, MFF_LOG_INPORT, 0, 32, ofpacts_p);

        /* Resubmit to first logical ingress pipeline table. */
        put_resubmit(OFTABLE_LOG_INGRESS_PIPELINE, ofpacts_p);
        ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG,
                        tag ? 150 : 100, &match, ofpacts_p);

        if (!tag && (!strcmp(binding->type, "localnet")
                     || !strcmp(binding->type, "l2gateway"))) {

            /* Add a second flow for frames that lack any 802.1Q
             * header.  For these, drop the OFPACT_STRIP_VLAN
             * action. */
            ofpbuf_pull(ofpacts_p, ofpacts_orig_size);
            match_set_dl_tci_masked(&match, 0, htons(VLAN_CFI));
            ofctrl_add_flow(flow_table, 0, 100, &match, ofpacts_p);
        }

        /* Table 33, priority 100.
         * =======================
         *
         * Implements output to local hypervisor.  Each flow matches a
         * logical output port on the local hypervisor, and resubmits to
         * table 34.
         */

        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);

        /* Match MFF_LOG_DATAPATH, MFF_LOG_OUTPORT. */
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        if (zone_id) {
            put_load(zone_id, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_id_dnat) {
            put_load(zone_id_dnat, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_id_snat) {
            put_load(zone_id_snat, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
        }

        /* Resubmit to table 34. */
        put_resubmit(OFTABLE_CHECK_LOOPBACK, ofpacts_p);
        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100,
                        &match, ofpacts_p);

        /* Table 34, Priority 100.
         * =======================
         *
         * Drop packets whose logical inport and outport are the same
         * and the MLF_ALLOW_LOOPBACK flag is not set. */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                             0, MLF_ALLOW_LOOPBACK);
        match_set_reg(&match, MFF_LOG_INPORT - MFF_REG0, port_key);
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
        ofctrl_add_flow(flow_table, OFTABLE_CHECK_LOOPBACK, 100,
                        &match, ofpacts_p);

        /* Table 64, Priority 100.
         * =======================
         *
         * If the packet is supposed to hair-pin because the "loopback"
         * flag is set (or if the destination is a nested container),
         * temporarily set the in_port to zero, resubmit to
         * table 65 for logical-to-physical translation, then restore
         * the port number. */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
        if (!nested_container) {
            match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                                 MLF_ALLOW_LOOPBACK, MLF_ALLOW_LOOPBACK);
        }

        put_stack(MFF_IN_PORT, ofpact_put_STACK_PUSH(ofpacts_p));
        put_load(0, MFF_IN_PORT, 0, 16, ofpacts_p);
        put_resubmit(OFTABLE_LOG_TO_PHY, ofpacts_p);
        put_stack(MFF_IN_PORT, ofpact_put_STACK_POP(ofpacts_p));
        ofctrl_add_flow(flow_table, OFTABLE_SAVE_INPORT, 100,
                        &match, ofpacts_p);

        /* Table 65, Priority 100.
         * =======================
         *
         * Deliver the packet to the local vif. */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
        if (tag) {
            /* For containers sitting behind a local vif, tag the packets
             * before delivering them. */
            struct ofpact_vlan_vid *vlan_vid;
            vlan_vid = ofpact_put_SET_VLAN_VID(ofpacts_p);
            vlan_vid->vlan_vid = tag;
            vlan_vid->push_vlan_if_needed = true;
        }
        ofpact_put_OUTPUT(ofpacts_p)->port = ofport;
        if (tag) {
            /* Revert the tag added to the packets headed to containers
             * in the previous step. If we don't do this, the packets
             * that are to be broadcasted to a VM in the same logical
             * switch will also contain the tag. */
            ofpact_put_STRIP_VLAN(ofpacts_p);
        }
        ofctrl_add_flow(flow_table, OFTABLE_LOG_TO_PHY, 100,
                        &match, ofpacts_p);
    } else if (!tun) {
        /* Remote port connected by localnet port */
        /* Table 33, priority 100.
         * =======================
         *
         * Implements switching to localnet port. Each flow matches a
         * logical output port on remote hypervisor, switch the output port
         * to connected localnet port and resubmits to same table.
         */

        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);

        /* Match MFF_LOG_DATAPATH, MFF_LOG_OUTPORT. */
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        put_load(localnet_port->tunnel_key, MFF_LOG_OUTPORT, 0, 32, ofpacts_p);

        /* Resubmit to table 33. */
        put_resubmit(OFTABLE_LOCAL_OUTPUT, ofpacts_p);
        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100,
                        &match, ofpacts_p);
    } else {
        /* Remote port connected by tunnel */

        /* Table 32, priority 150 and 100.
         * ===============================
         *
         * Priority 150 is for packets received from a VXLAN tunnel
         * which get resubmitted to OFTABLE_LOG_INGRESS_PIPELINE due to
         * lack of needed metadata in VXLAN, explicitly skip sending
         * back out any tunnels and resubmit to table 33 for local
         * delivery.
         *
         * Priority 100 is for all other traffic which need to be sent
         * to a remote hypervisor.  Each flow matches an output port
         * that includes a logical port on a remote hypervisor, and
         * tunnels the packet to that hypervisor.
         */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                             MLF_RCV_FROM_VXLAN, MLF_RCV_FROM_VXLAN);

        /* Resubmit to table 33. */
        put_resubmit(OFTABLE_LOCAL_OUTPUT, ofpacts_p);
        ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 150, &match,
                        ofpacts_p);


        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);

        /* Match MFF_LOG_DATAPATH, MFF_LOG_OUTPORT. */
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        put_encapsulation(mff_ovn_geneve, tun, binding->datapath,
                          port_key, ofpacts_p);

        /* Output to tunnel. */
        ofpact_put_OUTPUT(ofpacts_p)->port = ofport;
        ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 100,
                        &match, ofpacts_p);
    }
}

static void
consider_mc_group(enum mf_field_id mff_ovn_geneve,
                  const struct simap *ct_zones,
                  struct hmap *local_datapaths,
                  const struct sbrec_multicast_group *mc,
                  struct ofpbuf *ofpacts_p,
                  struct ofpbuf *remote_ofpacts_p,
                  struct hmap *flow_table)
{
    struct sset remote_chassis = SSET_INITIALIZER(&remote_chassis);
    struct match match;

    match_init_catchall(&match);
    match_set_metadata(&match, htonll(mc->datapath->tunnel_key));
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, mc->tunnel_key);

    /* Go through all of the ports in the multicast group:
     *
     *    - For remote ports, add the chassis to 'remote_chassis'.
     *
     *    - For local ports (other than logical patch ports), add actions
     *      to 'ofpacts_p' to set the output port and resubmit.
     *
     *    - For logical patch ports, add actions to 'remote_ofpacts_p'
     *      instead.  (If we put them in 'ofpacts', then the output
     *      would happen on every hypervisor in the multicast group,
     *      effectively duplicating the packet.)
     */
    ofpbuf_clear(ofpacts_p);
    ofpbuf_clear(remote_ofpacts_p);
    for (size_t i = 0; i < mc->n_ports; i++) {
        struct sbrec_port_binding *port = mc->ports[i];

        if (port->datapath != mc->datapath) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, UUID_FMT": multicast group contains ports "
                         "in wrong datapath",
                         UUID_ARGS(&mc->header_.uuid));
            continue;
        }

        int zone_id = simap_get(ct_zones, port->logical_port);
        if (zone_id) {
            put_load(zone_id, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
        }

        if (!strcmp(port->type, "patch")) {
            put_load(port->tunnel_key, MFF_LOG_OUTPORT, 0, 32,
                     remote_ofpacts_p);
            put_resubmit(OFTABLE_CHECK_LOOPBACK, remote_ofpacts_p);
        } else if (simap_contains(&localvif_to_ofport,
                           (port->parent_port && *port->parent_port)
                           ? port->parent_port : port->logical_port)) {
            put_load(port->tunnel_key, MFF_LOG_OUTPORT, 0, 32, ofpacts_p);
            put_resubmit(OFTABLE_CHECK_LOOPBACK, ofpacts_p);
        } else if (port->chassis && !get_localnet_port(local_datapaths,
                                         mc->datapath->tunnel_key)) {
            /* Add remote chassis only when localnet port not exist,
             * otherwise multicast will reach remote ports through localnet
             * port. */
            sset_add(&remote_chassis, port->chassis->name);
        }
    }

    /* Table 33, priority 100.
     * =======================
     *
     * Handle output to the local logical ports in the multicast group, if
     * any. */
    bool local_ports = ofpacts_p->size > 0;
    if (local_ports) {
        /* Following delivery to local logical ports, restore the multicast
         * group as the logical output port. */
        put_load(mc->tunnel_key, MFF_LOG_OUTPORT, 0, 32, ofpacts_p);

        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100,
                        &match, ofpacts_p);
    }

    /* Table 32, priority 100.
     * =======================
     *
     * Handle output to the remote chassis in the multicast group, if
     * any. */
    if (!sset_is_empty(&remote_chassis) || remote_ofpacts_p->size > 0) {
        if (remote_ofpacts_p->size > 0) {
            /* Following delivery to logical patch ports, restore the
             * multicast group as the logical output port. */
            put_load(mc->tunnel_key, MFF_LOG_OUTPORT, 0, 32,
                     remote_ofpacts_p);
        }

        const char *chassis;
        const struct chassis_tunnel *prev = NULL;
        SSET_FOR_EACH (chassis, &remote_chassis) {
            const struct chassis_tunnel *tun
                = chassis_tunnel_find(chassis);
            if (!tun) {
                continue;
            }

            if (!prev || tun->type != prev->type) {
                put_encapsulation(mff_ovn_geneve, tun, mc->datapath,
                                  mc->tunnel_key, remote_ofpacts_p);
                prev = tun;
            }
            ofpact_put_OUTPUT(remote_ofpacts_p)->port = tun->ofport;
        }

        if (remote_ofpacts_p->size) {
            if (local_ports) {
                put_resubmit(OFTABLE_LOCAL_OUTPUT, remote_ofpacts_p);
            }
            ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 100,
                            &match, remote_ofpacts_p);
        }
    }
    sset_destroy(&remote_chassis);
}

void
physical_run(struct controller_ctx *ctx, enum mf_field_id mff_ovn_geneve,
             const struct ovsrec_bridge *br_int, const char *this_chassis_id,
             const struct simap *ct_zones, struct hmap *flow_table,
             struct hmap *local_datapaths, struct hmap *patched_datapaths)
{

    /* This bool tracks physical mapping changes. */
    bool physical_map_changed = false;

    struct simap new_localvif_to_ofport =
        SIMAP_INITIALIZER(&new_localvif_to_ofport);
    struct simap new_tunnel_to_ofport =
        SIMAP_INITIALIZER(&new_tunnel_to_ofport);
    for (int i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }

        const char *chassis_id = smap_get(&port_rec->external_ids,
                                          "ovn-chassis-id");
        if (chassis_id && !strcmp(chassis_id, this_chassis_id)) {
            continue;
        }

        const char *localnet = smap_get(&port_rec->external_ids,
                                        "ovn-localnet-port");
        const char *l2gateway = smap_get(&port_rec->external_ids,
                                        "ovn-l2gateway-port");
        const char *l3gateway = smap_get(&port_rec->external_ids,
                                        "ovn-l3gateway-port");
        const char *logpatch = smap_get(&port_rec->external_ids,
                                        "ovn-logical-patch-port");

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

            /* Record as patch to local net, logical patch port, chassis, or
             * local logical port. */
            bool is_patch = !strcmp(iface_rec->type, "patch");
            if (is_patch && localnet) {
                /* localnet patch ports can be handled just like VIFs. */
                simap_put(&new_localvif_to_ofport, localnet, ofport);
                break;
            } else if (is_patch && l2gateway) {
                /* L2 gateway patch ports can be handled just like VIFs. */
                simap_put(&new_localvif_to_ofport, l2gateway, ofport);
                break;
            } else if (is_patch && l3gateway) {
                /* L3 gateway patch ports can be handled just like VIFs. */
                simap_put(&new_localvif_to_ofport, l3gateway, ofport);
                break;
            } else if (is_patch && logpatch) {
                /* Logical patch ports can be handled just like VIFs. */
                simap_put(&new_localvif_to_ofport, logpatch, ofport);
                break;
            } else if (chassis_id) {
                enum chassis_tunnel_type tunnel_type;
                if (!strcmp(iface_rec->type, "geneve")) {
                    tunnel_type = GENEVE;
                    if (!mff_ovn_geneve) {
                        continue;
                    }
                } else if (!strcmp(iface_rec->type, "stt")) {
                    tunnel_type = STT;
                } else if (!strcmp(iface_rec->type, "vxlan")) {
                    tunnel_type = VXLAN;
                } else {
                    continue;
                }

                simap_put(&new_tunnel_to_ofport, chassis_id, ofport);
                struct chassis_tunnel *tun = chassis_tunnel_find(chassis_id);
                if (tun) {
                    /* If the tunnel's ofport has changed, update. */
                    if (tun->ofport != u16_to_ofp(ofport) ||
                        tun->type != tunnel_type) {
                        tun->ofport = u16_to_ofp(ofport);
                        tun->type = tunnel_type;
                        physical_map_changed = true;
                    }
                } else {
                    tun = xmalloc(sizeof *tun);
                    hmap_insert(&tunnels, &tun->hmap_node,
                                hash_string(chassis_id, 0));
                    tun->chassis_id = chassis_id;
                    tun->ofport = u16_to_ofp(ofport);
                    tun->type = tunnel_type;
                    physical_map_changed = true;
                }
                break;
            } else {
                const char *iface_id = smap_get(&iface_rec->external_ids,
                                                "iface-id");
                if (iface_id) {
                    simap_put(&new_localvif_to_ofport, iface_id, ofport);
                }
            }
        }
    }

    /* Remove tunnels that are no longer here. */
    struct chassis_tunnel *tun, *tun_next;
    HMAP_FOR_EACH_SAFE (tun, tun_next, hmap_node, &tunnels) {
        if (!simap_find(&new_tunnel_to_ofport, tun->chassis_id)) {
            hmap_remove(&tunnels, &tun->hmap_node);
            physical_map_changed = true;
            free(tun);
        }
    }

    /* Capture changed or removed openflow ports. */
    struct simap_node *vif_name, *vif_name_next;
    SIMAP_FOR_EACH_SAFE (vif_name, vif_name_next, &localvif_to_ofport) {
        int newport;
        if ((newport = simap_get(&new_localvif_to_ofport, vif_name->name))) {
            if (newport != simap_get(&localvif_to_ofport, vif_name->name)) {
                simap_put(&localvif_to_ofport, vif_name->name, newport);
                physical_map_changed = true;
            }
        } else {
            simap_find_and_delete(&localvif_to_ofport, vif_name->name);
            physical_map_changed = true;
        }
    }
    SIMAP_FOR_EACH (vif_name, &new_localvif_to_ofport) {
        if (!simap_get(&localvif_to_ofport, vif_name->name)) {
            simap_put(&localvif_to_ofport, vif_name->name,
                      simap_get(&new_localvif_to_ofport, vif_name->name));
            physical_map_changed = true;
        }
    }
    if (physical_map_changed) {
        /* Reprocess logical flow table immediately. */
        poll_immediate_wake();
    }

    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);

    /* Set up flows in table 0 for physical-to-logical translation and in table
     * 64 for logical-to-physical translation. */
    const struct sbrec_port_binding *binding;
    SBREC_PORT_BINDING_FOR_EACH (binding, ctx->ovnsb_idl) {
        /* Because it is possible in the above code to enter this
         * for loop without having cleared the flow table first, we
         * should clear the old flows to avoid collisions. */
        consider_port_binding(mff_ovn_geneve, ct_zones, local_datapaths,
                              patched_datapaths, binding, &ofpacts,
                              flow_table);
    }

    /* Handle output to multicast groups, in tables 32 and 33. */
    const struct sbrec_multicast_group *mc;
    struct ofpbuf remote_ofpacts;
    ofpbuf_init(&remote_ofpacts, 0);
    SBREC_MULTICAST_GROUP_FOR_EACH (mc, ctx->ovnsb_idl) {
        /* As multicast groups are always reprocessed each time,
         * the first step is to clean the old flows for the group
         * so that we avoid warning messages on collisions. */
        consider_mc_group(mff_ovn_geneve, ct_zones,
                          local_datapaths, mc, &ofpacts, &remote_ofpacts,
                          flow_table);
    }

    ofpbuf_uninit(&remote_ofpacts);

    /* Table 0, priority 100.
     * ======================
     *
     * Process packets that arrive from a remote hypervisor (by matching
     * on tunnel in_port). */

    /* Add flows for Geneve and STT encapsulations.  These
     * encapsulations have metadata about the ingress and egress logical
     * ports.  We set MFF_LOG_DATAPATH, MFF_LOG_INPORT, and
     * MFF_LOG_OUTPORT from the tunnel key data, then resubmit to table
     * 33 to handle packets to the local hypervisor. */
    HMAP_FOR_EACH (tun, hmap_node, &tunnels) {
        struct match match = MATCH_CATCHALL_INITIALIZER;
        match_set_in_port(&match, tun->ofport);

        ofpbuf_clear(&ofpacts);
        if (tun->type == GENEVE) {
            put_move(MFF_TUN_ID, 0,  MFF_LOG_DATAPATH, 0, 24, &ofpacts);
            put_move(mff_ovn_geneve, 16, MFF_LOG_INPORT, 0, 15,
                     &ofpacts);
            put_move(mff_ovn_geneve, 0, MFF_LOG_OUTPORT, 0, 16,
                     &ofpacts);
        } else if (tun->type == STT) {
            put_move(MFF_TUN_ID, 40, MFF_LOG_INPORT,   0, 15, &ofpacts);
            put_move(MFF_TUN_ID, 24, MFF_LOG_OUTPORT,  0, 16, &ofpacts);
            put_move(MFF_TUN_ID,  0, MFF_LOG_DATAPATH, 0, 24, &ofpacts);
        } else if (tun->type == VXLAN) {
            /* We'll handle VXLAN later. */
            continue;
        } else {
            OVS_NOT_REACHED();
        }

        put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);

        ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 100, &match, &ofpacts);
    }

    /* Add flows for VXLAN encapsulations.  Due to the limited amount of
     * metadata, we only support VXLAN for connections to gateways.  The
     * VNI is used to populate MFF_LOG_DATAPATH.  The gateway's logical
     * port is set to MFF_LOG_INPORT.  Then the packet is resubmitted to
     * table 16 to determine the logical egress port. */
    HMAP_FOR_EACH (tun, hmap_node, &tunnels) {
        if (tun->type != VXLAN) {
            continue;
        }

        SBREC_PORT_BINDING_FOR_EACH (binding, ctx->ovnsb_idl) {
            struct match match = MATCH_CATCHALL_INITIALIZER;

            if (!binding->chassis ||
                strcmp(tun->chassis_id, binding->chassis->name)) {
                continue;
            }

            match_set_in_port(&match, tun->ofport);
            match_set_tun_id(&match, htonll(binding->datapath->tunnel_key));

            ofpbuf_clear(&ofpacts);
            put_move(MFF_TUN_ID, 0,  MFF_LOG_DATAPATH, 0, 24, &ofpacts);
            put_load(binding->tunnel_key, MFF_LOG_INPORT, 0, 15, &ofpacts);
            /* For packets received from a vxlan tunnel, set a flag to that
             * effect. */
            put_load(1, MFF_LOG_FLAGS, MLF_RCV_FROM_VXLAN_BIT, 1, &ofpacts);
            put_resubmit(OFTABLE_LOG_INGRESS_PIPELINE, &ofpacts);

            ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 100, &match,
                            &ofpacts);
        }
    }

    /* Table 32, Priority 0.
     * =======================
     *
     * Resubmit packets that are not directed at tunnels or part of a
     * multicast group to the local output table. */
    struct match match;
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 0, &match, &ofpacts);

    /* Table 34, Priority 0.
     * =======================
     *
     * Resubmit packets that don't output to the ingress port (already checked
     * in table 33) to the logical egress pipeline, clearing the logical
     * registers (for consistent behavior with packets that get tunneled). */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    for (int i = 0; i < MFF_N_LOG_REGS; i++) {
        put_load(0, MFF_REG0 + i, 0, 32, &ofpacts);
    }
    put_resubmit(OFTABLE_LOG_EGRESS_PIPELINE, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_CHECK_LOOPBACK, 0, &match, &ofpacts);

    /* Table 64, Priority 0.
     * =======================
     *
     * Resubmit packets that do not have the MLF_ALLOW_LOOPBACK flag set
     * to table 65 for logical-to-physical translation. */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOG_TO_PHY, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_SAVE_INPORT, 0, &match, &ofpacts);

    ofpbuf_uninit(&ofpacts);

    simap_destroy(&new_localvif_to_ofport);
    simap_destroy(&new_tunnel_to_ofport);
}
