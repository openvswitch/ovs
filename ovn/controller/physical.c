/* Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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
#include "encaps.h"
#include "flow.h"
#include "ha-chassis.h"
#include "lflow.h"
#include "lport.h"
#include "chassis.h"
#include "lib/bundle.h"
#include "openvswitch/poll-loop.h"
#include "lib/uuid.h"
#include "ofctrl.h"
#include "openvswitch/list.h"
#include "openvswitch/hmap.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "openvswitch/ofp-parse.h"
#include "ovn-controller.h"
#include "ovn/lib/chassis-index.h"
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

/* UUID to identify OF flows not associated with ovsdb rows. */
static struct uuid *hc_uuid = NULL;

void
physical_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_external_ids);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
}

static struct simap localvif_to_ofport =
    SIMAP_INITIALIZER(&localvif_to_ofport);
static struct hmap tunnels = HMAP_INITIALIZER(&tunnels);

/* Maps from a chassis to the OpenFlow port number of the tunnel that can be
 * used to reach that chassis. */
struct chassis_tunnel {
    struct hmap_node hmap_node;
    char *chassis_id;
    ofp_port_t ofport;
    enum chassis_tunnel_type type;
};

/*
 * This function looks up the list of tunnel ports (provided by
 * ovn-chassis-id ports) and returns the tunnel for the given chassid-id and
 * encap-ip. The ovn-chassis-id is formed using the chassis-id and encap-ip.
 * The list is hashed using the chassis-id. If the encap-ip is not specified,
 * it means we'll just return a tunnel for that chassis-id, i.e. we just check
 * for chassis-id and if there is a match, we'll return the tunnel.
 * If encap-ip is also provided we use both chassis-id and encap-ip to do
 * a more specific lookup.
 */
static struct chassis_tunnel *
chassis_tunnel_find(const char *chassis_id, char *encap_ip)
{
    /*
     * If the specific encap_ip is given, look for the chassisid_ip entry,
     * else return the 1st found entry for the chassis.
     */
    struct chassis_tunnel *tun = NULL;
    HMAP_FOR_EACH_WITH_HASH (tun, hmap_node, hash_string(chassis_id, 0),
                             &tunnels) {
        if (encaps_tunnel_id_match(tun->chassis_id, chassis_id, encap_ip)) {
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

/*
 * For a port binding, get the corresponding ovn-chassis-id tunnel port
 * from the associated encap.
 */
static struct chassis_tunnel *
get_port_binding_tun(const struct sbrec_port_binding *binding)
{
    struct sbrec_encap *encap = binding->encap;
    struct sbrec_chassis *chassis = binding->chassis;
    struct chassis_tunnel *tun = NULL;

    if (encap) {
        tun = chassis_tunnel_find(chassis->name, encap->ip);
    }
    if (!tun) {
        tun = chassis_tunnel_find(chassis->name, NULL);
    }
    return tun;
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
        put_load(datapath->tunnel_key | ((uint64_t) outport << 24),
                 MFF_TUN_ID, 0, 64, ofpacts);
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

static const struct sbrec_port_binding *
get_localnet_port(const struct hmap *local_datapaths, int64_t tunnel_key)
{
    const struct local_datapath *ld = get_local_datapath(local_datapaths,
                                                         tunnel_key);
    return ld ? ld->localnet_port : NULL;
}

/* Datapath zone IDs for connection tracking and NAT */
struct zone_ids {
    int ct;                     /* MFF_LOG_CT_ZONE. */
    int dnat;                   /* MFF_LOG_DNAT_ZONE. */
    int snat;                   /* MFF_LOG_SNAT_ZONE. */
};

static struct zone_ids
get_zone_ids(const struct sbrec_port_binding *binding,
             const struct simap *ct_zones)
{
    struct zone_ids zone_ids;

    zone_ids.ct = simap_get(ct_zones, binding->logical_port);

    const struct uuid *key = &binding->datapath->header_.uuid;

    char *dnat = alloc_nat_zone_key(key, "dnat");
    zone_ids.dnat = simap_get(ct_zones, dnat);
    free(dnat);

    char *snat = alloc_nat_zone_key(key, "snat");
    zone_ids.snat = simap_get(ct_zones, snat);
    free(snat);

    return zone_ids;
}

static void
put_replace_router_port_mac_flows(const struct
                                  sbrec_port_binding *localnet_port,
                                  const struct sbrec_chassis *chassis,
                                  const struct hmap *local_datapaths,
                                  struct ofpbuf *ofpacts_p,
                                  ofp_port_t ofport,
                                  struct ovn_desired_flow_table *flow_table)
{
    struct local_datapath *ld = get_local_datapath(local_datapaths,
                                                   localnet_port->datapath->
                                                   tunnel_key);
    ovs_assert(ld);

    uint32_t dp_key = localnet_port->datapath->tunnel_key;
    uint32_t port_key = localnet_port->tunnel_key;
    int tag = localnet_port->tag ? *localnet_port->tag : 0;
    const char *network = smap_get(&localnet_port->options, "network_name");
    struct eth_addr chassis_mac;

    if (!network) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "Physical network not configured for datapath:"
                     "%"PRId64" with localnet port",
                     localnet_port->datapath->tunnel_key);
        return;
    }

    /* Get chassis mac */
    if (!chassis_get_mac(chassis, network, &chassis_mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        /* Keeping the log level low for backward compatibility.
         * Chassis mac is a new configuration.
         */
        VLOG_DBG_RL(&rl, "Could not get chassis mac for network: %s", network);
        return;
    }

    for (int i = 0; i < ld->n_peer_ports; i++) {
        const struct sbrec_port_binding *rport_binding = ld->peer_ports[i];
        struct eth_addr router_port_mac;
        struct match match;
        struct ofpact_mac *replace_mac;

        /* Table 65, priority 150.
         * =======================
         *
         * Implements output to localnet port.
         * a. Flow replaces ingress router port mac with a chassis mac.
         * b. Flow appends the vlan id localnet port is configured with.
         */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);

        ovs_assert(rport_binding->n_mac == 1);
        char *err_str = str_to_mac(rport_binding->mac[0], &router_port_mac);
        if (err_str) {
            /* Parsing of mac failed. */
            VLOG_WARN("Parsing or router port mac failed for router port: %s, "
                      "with error: %s", rport_binding->logical_port, err_str);
            free(err_str);
            return;
        }

        /* Replace Router mac flow */
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
        match_set_dl_src(&match, router_port_mac);

        replace_mac = ofpact_put_SET_ETH_SRC(ofpacts_p);
        replace_mac->mac = chassis_mac;

        if (tag) {
            struct ofpact_vlan_vid *vlan_vid;
            vlan_vid = ofpact_put_SET_VLAN_VID(ofpacts_p);
            vlan_vid->vlan_vid = tag;
            vlan_vid->push_vlan_if_needed = true;
        }

        ofpact_put_OUTPUT(ofpacts_p)->port = ofport;

        ofctrl_add_flow(flow_table, OFTABLE_LOG_TO_PHY, 150, 0,
                        &match, ofpacts_p, &localnet_port->header_.uuid);
    }
}

static void
put_local_common_flows(uint32_t dp_key, uint32_t port_key,
                       uint32_t parent_port_key,
                       const struct zone_ids *zone_ids,
                       struct ofpbuf *ofpacts_p,
                       struct ovn_desired_flow_table *flow_table)
{
    struct match match;

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

    if (zone_ids) {
        if (zone_ids->ct) {
            put_load(zone_ids->ct, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_ids->dnat) {
            put_load(zone_ids->dnat, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_ids->snat) {
            put_load(zone_ids->snat, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
        }
    }

    /* Resubmit to table 34. */
    put_resubmit(OFTABLE_CHECK_LOOPBACK, ofpacts_p);
    ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100, 0,
                    &match, ofpacts_p, hc_uuid);

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
    ofctrl_add_flow(flow_table, OFTABLE_CHECK_LOOPBACK, 100, 0,
                    &match, ofpacts_p, hc_uuid);

    /* Table 64, Priority 100.
     * =======================
     *
     * If the packet is supposed to hair-pin because the
     *   - "loopback" flag is set
     *   - or if the destination is a nested container
     *   - or if "nested_container" flag is set and the destination is the
     *     parent port,
     * temporarily set the in_port to zero, resubmit to
     * table 65 for logical-to-physical translation, then restore
     * the port number.
     *
     * If 'parent_port_key' is set, then the 'port_key' represents a nested
     * container. */

    bool nested_container = parent_port_key ? true: false;
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
    ofctrl_add_flow(flow_table, OFTABLE_SAVE_INPORT, 100, 0,
                    &match, ofpacts_p, hc_uuid);

    if (nested_container) {
        /* It's a nested container and when the packet from the nested
         * container is to be sent to the parent port, "nested_container"
         * flag will be set. We need to temporarily set the in_port to zero
         * as mentioned in the comment above.
         *
         * If a parent port has multiple child ports, then this if condition
         * will be hit multiple times, but we want to add only one flow.
         * ofctrl_add_flow() logs a warning message for duplicate flows.
         * So use the function 'ofctrl_check_and_add_flow' which doesn't
         * log a warning.
         *
         * Other option is to add this flow for all the ports which are not
         * nested containers. In which case we will add this flow for all the
         * ports even if they don't have any child ports which is
         * unnecessary.
         */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, parent_port_key);
        match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                             MLF_NESTED_CONTAINER, MLF_NESTED_CONTAINER);

        put_stack(MFF_IN_PORT, ofpact_put_STACK_PUSH(ofpacts_p));
        put_load(0, MFF_IN_PORT, 0, 16, ofpacts_p);
        put_resubmit(OFTABLE_LOG_TO_PHY, ofpacts_p);
        put_stack(MFF_IN_PORT, ofpact_put_STACK_POP(ofpacts_p));
        ofctrl_check_and_add_flow(flow_table, OFTABLE_SAVE_INPORT, 100, 0,
                                  &match, ofpacts_p, hc_uuid, false);
    }
}

static void
load_logical_ingress_metadata(const struct sbrec_port_binding *binding,
                              const struct zone_ids *zone_ids,
                              struct ofpbuf *ofpacts_p)
{
    if (zone_ids) {
        if (zone_ids->ct) {
            put_load(zone_ids->ct, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_ids->dnat) {
            put_load(zone_ids->dnat, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_ids->snat) {
            put_load(zone_ids->snat, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
        }
    }

    /* Set MFF_LOG_DATAPATH and MFF_LOG_INPORT. */
    uint32_t dp_key = binding->datapath->tunnel_key;
    uint32_t port_key = binding->tunnel_key;
    put_load(dp_key, MFF_LOG_DATAPATH, 0, 64, ofpacts_p);
    put_load(port_key, MFF_LOG_INPORT, 0, 32, ofpacts_p);
}

static void
consider_port_binding(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                      enum mf_field_id mff_ovn_geneve,
                      const struct simap *ct_zones,
                      const struct sset *active_tunnels,
                      const struct hmap *local_datapaths,
                      const struct sbrec_port_binding *binding,
                      const struct sbrec_chassis *chassis,
                      struct ovn_desired_flow_table *flow_table,
                      struct ofpbuf *ofpacts_p)
{
    uint32_t dp_key = binding->datapath->tunnel_key;
    uint32_t port_key = binding->tunnel_key;
    if (!get_local_datapath(local_datapaths, dp_key)) {
        return;
    }

    struct match match;
    if (!strcmp(binding->type, "patch")
        || (!strcmp(binding->type, "l3gateway")
            && binding->chassis == chassis)) {
        const char *peer_name = smap_get(&binding->options, "peer");
        if (!peer_name) {
            return;
        }

        const struct sbrec_port_binding *peer = lport_lookup_by_name(
            sbrec_port_binding_by_name, peer_name);
        if (!peer || strcmp(peer->type, binding->type)) {
            return;
        }
        const char *peer_peer_name = smap_get(&peer->options, "peer");
        if (!peer_peer_name || strcmp(peer_peer_name, binding->logical_port)) {
            return;
        }

        struct zone_ids binding_zones = get_zone_ids(binding, ct_zones);
        put_local_common_flows(dp_key, port_key, 0, &binding_zones,
                               ofpacts_p, flow_table);

        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        size_t clone_ofs = ofpacts_p->size;
        struct ofpact_nest *clone = ofpact_put_CLONE(ofpacts_p);
        ofpact_put_CT_CLEAR(ofpacts_p);
        put_load(0, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
        put_load(0, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
        put_load(0, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
        struct zone_ids peer_zones = get_zone_ids(peer, ct_zones);
        load_logical_ingress_metadata(peer, &peer_zones, ofpacts_p);
        put_load(0, MFF_LOG_FLAGS, 0, 32, ofpacts_p);
        put_load(0, MFF_LOG_OUTPORT, 0, 32, ofpacts_p);
        for (int i = 0; i < MFF_N_LOG_REGS; i++) {
            put_load(0, MFF_LOG_REG0 + i, 0, 32, ofpacts_p);
        }
        put_load(0, MFF_IN_PORT, 0, 16, ofpacts_p);
        put_resubmit(OFTABLE_LOG_INGRESS_PIPELINE, ofpacts_p);
        clone = ofpbuf_at_assert(ofpacts_p, clone_ofs, sizeof *clone);
        ofpacts_p->header = clone;
        ofpact_finish_CLONE(ofpacts_p, &clone);

        ofctrl_add_flow(flow_table, OFTABLE_LOG_TO_PHY, 100, 0,
                        &match, ofpacts_p, &binding->header_.uuid);
        return;
    }

    struct ha_chassis_ordered *ha_ch_ordered
        = ha_chassis_get_ordered(binding->ha_chassis_group);

    if (!strcmp(binding->type, "chassisredirect")
        && (binding->chassis == chassis
            || ha_chassis_group_is_active(binding->ha_chassis_group,
                                          active_tunnels, chassis))) {

        /* Table 33, priority 100.
         * =======================
         *
         * Implements output to local hypervisor.  Each flow matches a
         * logical output port on the local hypervisor, and resubmits to
         * table 34.  For ports of type "chassisredirect", the logical
         * output port is changed from the "chassisredirect" port to the
         * underlying distributed port. */

        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        const char *distributed_port = smap_get_def(&binding->options,
                                                    "distributed-port", "");
        const struct sbrec_port_binding *distributed_binding
            = lport_lookup_by_name(sbrec_port_binding_by_name,
                                   distributed_port);

        if (!distributed_binding) {
            /* Packet will be dropped. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "No port binding record for distributed "
                         "port %s referred by chassisredirect port %s",
                         distributed_port,
                         binding->logical_port);
        } else if (binding->datapath !=
                   distributed_binding->datapath) {
            /* Packet will be dropped. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl,
                         "chassisredirect port %s refers to "
                         "distributed port %s in wrong datapath",
                         binding->logical_port,
                         distributed_port);
        } else {
            put_load(distributed_binding->tunnel_key,
                     MFF_LOG_OUTPORT, 0, 32, ofpacts_p);

            struct zone_ids zone_ids = get_zone_ids(distributed_binding,
                                                    ct_zones);
            if (zone_ids.ct) {
                put_load(zone_ids.ct, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
            }
            if (zone_ids.dnat) {
                put_load(zone_ids.dnat, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
            }
            if (zone_ids.snat) {
                put_load(zone_ids.snat, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
            }

            /* Resubmit to table 34. */
            put_resubmit(OFTABLE_CHECK_LOOPBACK, ofpacts_p);
        }

        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100, 0,
                        &match, ofpacts_p, &binding->header_.uuid);

        goto out;
    }

    /* Find the OpenFlow port for the logical port, as 'ofport'.  This is
     * one of:
     *
     *     - If the port is a VIF on the chassis we're managing, the
     *       OpenFlow port for the VIF.  'tun' will be NULL.
     *
     *       The same logic handles ports that OVN implements as Open vSwitch
     *       patch ports, that is, "localnet" and "l2gateway" ports.
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
    const struct sbrec_port_binding *parent_port = NULL;
    ofp_port_t ofport;
    bool is_remote = false;
    if (binding->parent_port && *binding->parent_port) {
        if (!binding->tag) {
            goto out;
        }
        ofport = u16_to_ofp(simap_get(&localvif_to_ofport,
                                      binding->parent_port));
        if (ofport) {
            tag = *binding->tag;
            nested_container = true;
            parent_port = lport_lookup_by_name(
                sbrec_port_binding_by_name, binding->parent_port);
        }
    } else {
        ofport = u16_to_ofp(simap_get(&localvif_to_ofport,
                                      binding->logical_port));
        const char *requested_chassis = smap_get(&binding->options,
                                                 "requested-chassis");
        if (ofport && requested_chassis && requested_chassis[0] &&
            strcmp(requested_chassis, chassis->name) &&
            strcmp(requested_chassis, chassis->hostname)) {
            /* Even though there is an ofport for this port_binding, it is
             * requested on a different chassis. So ignore this ofport.
             */
            ofport = 0;
        }

        if ((!strcmp(binding->type, "localnet")
            || !strcmp(binding->type, "l2gateway"))
            && ofport && binding->tag) {
            tag = *binding->tag;
        }
    }

    bool is_ha_remote = false;
    const struct chassis_tunnel *tun = NULL;
    const struct sbrec_port_binding *localnet_port =
        get_localnet_port(local_datapaths, dp_key);
    if (!ofport) {
        /* It is remote port, may be reached by tunnel or localnet port */
        is_remote = true;
        if (localnet_port) {
            ofport = u16_to_ofp(simap_get(&localvif_to_ofport,
                                          localnet_port->logical_port));
            if (!ofport) {
                goto out;
            }
        } else {
            if (!ha_ch_ordered || ha_ch_ordered->n_ha_ch < 2) {
                /* It's on a single remote chassis */
                if (!binding->chassis) {
                    goto out;
                }
                tun = chassis_tunnel_find(binding->chassis->name, NULL);
                if (!tun) {
                    goto out;
                }
                ofport = tun->ofport;
            } else {
                /* It's distributed across the chassis belonging to
                 * an HA chassis group. */
                is_ha_remote = true;
            }
        }
    }

    if (!is_remote) {
        /* Packets that arrive from a vif can belong to a VM or
         * to a container located inside that VM. Packets that
         * arrive from containers have a tag (vlan) associated with them.
         */

        struct zone_ids zone_ids = get_zone_ids(binding, ct_zones);
        uint32_t parent_port_key = parent_port ? parent_port->tunnel_key : 0;
        /* Pass the parent port tunnel key if the port is a nested
         * container. */
        put_local_common_flows(dp_key, port_key, parent_port_key, &zone_ids,
                               ofpacts_p, flow_table);

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
            match_set_dl_vlan(&match, htons(tag), 0);
            if (nested_container) {
                /* When a packet comes from a container sitting behind a
                 * parent_port, we should let it loopback to other containers
                 * or the parent_port itself. Indicate this by setting the
                 * MLF_NESTED_CONTAINER_BIT in MFF_LOG_FLAGS.*/
                put_load(1, MFF_LOG_FLAGS, MLF_NESTED_CONTAINER_BIT, 1,
                         ofpacts_p);
            }
            ofpact_put_STRIP_VLAN(ofpacts_p);
        }

        /* Remember the size with just strip vlan added so far,
         * as we're going to remove this with ofpbuf_pull() later. */
        uint32_t ofpacts_orig_size = ofpacts_p->size;

        load_logical_ingress_metadata(binding, &zone_ids, ofpacts_p);

        /* Resubmit to first logical ingress pipeline table. */
        put_resubmit(OFTABLE_LOG_INGRESS_PIPELINE, ofpacts_p);
        ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG,
                        tag ? 150 : 100, 0, &match, ofpacts_p,
                        &binding->header_.uuid);

        if (!tag && (!strcmp(binding->type, "localnet")
                     || !strcmp(binding->type, "l2gateway"))) {

            /* Add a second flow for frames that lack any 802.1Q
             * header.  For these, drop the OFPACT_STRIP_VLAN
             * action. */
            ofpbuf_pull(ofpacts_p, ofpacts_orig_size);
            match_set_dl_tci_masked(&match, 0, htons(VLAN_CFI));
            ofctrl_add_flow(flow_table, 0, 100, 0, &match, ofpacts_p,
                            &binding->header_.uuid);
        }

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
        ofctrl_add_flow(flow_table, OFTABLE_LOG_TO_PHY, 100, 0,
                        &match, ofpacts_p, &binding->header_.uuid);

        if (!strcmp(binding->type, "localnet")) {
            put_replace_router_port_mac_flows(binding, chassis,
                                              local_datapaths, ofpacts_p,
                                              ofport, flow_table);
        }

    } else if (!tun && !is_ha_remote) {
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
        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100, 0,
                        &match, ofpacts_p, &binding->header_.uuid);
    } else {
        /* Remote port connected by tunnel */

        /* Table 32, priority 100.
         * =======================
         *
         * Handles traffic that needs to be sent to a remote hypervisor.  Each
         * flow matches an output port that includes a logical port on a remote
         * hypervisor, and tunnels the packet to that hypervisor.
         */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);

        /* Match MFF_LOG_DATAPATH, MFF_LOG_OUTPORT. */
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        if (!is_ha_remote) {
            /* Setup encapsulation */
            const struct chassis_tunnel *rem_tun =
                get_port_binding_tun(binding);
            if (!rem_tun) {
                goto out;
            }
            put_encapsulation(mff_ovn_geneve, tun, binding->datapath,
                              port_key, ofpacts_p);
            /* Output to tunnel. */
            ofpact_put_OUTPUT(ofpacts_p)->port = rem_tun->ofport;
        } else {
            /* Make sure all tunnel endpoints use the same encapsulation,
             * and set it up */
            for (size_t i = 0; i < ha_ch_ordered->n_ha_ch; i++) {
                const struct sbrec_chassis *ch =
                    ha_ch_ordered->ha_ch[i].chassis;
                if (!ch) {
                    continue;
                }
                if (!tun) {
                    tun = chassis_tunnel_find(ch->name, NULL);
                } else {
                    struct chassis_tunnel *chassis_tunnel =
                        chassis_tunnel_find(ch->name, NULL);
                    if (chassis_tunnel &&
                        tun->type != chassis_tunnel->type) {
                        static struct vlog_rate_limit rl =
                            VLOG_RATE_LIMIT_INIT(1, 1);
                        VLOG_ERR_RL(&rl, "Port %s has Gateway_Chassis "
                                            "with mixed encapsulations, only "
                                            "uniform encapsulations are "
                                            "supported.",
                                    binding->logical_port);
                        goto out;
                    }
                }
            }
            if (!tun) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_ERR_RL(&rl, "No tunnel endpoint found for HA chassis in "
                                 "HA chassis group of port %s",
                            binding->logical_port);
                goto out;
            }

            put_encapsulation(mff_ovn_geneve, tun, binding->datapath,
                              port_key, ofpacts_p);

            /* Output to tunnels with active/backup */
            struct ofpact_bundle *bundle = ofpact_put_BUNDLE(ofpacts_p);

            for (size_t i = 0; i < ha_ch_ordered->n_ha_ch; i++) {
                const struct sbrec_chassis *ch =
                    ha_ch_ordered->ha_ch[i].chassis;
                if (!ch) {
                    continue;
                }
                tun = chassis_tunnel_find(ch->name, NULL);
                if (!tun) {
                    continue;
                }
                if (bundle->n_slaves >= BUNDLE_MAX_SLAVES) {
                    static struct vlog_rate_limit rl =
                            VLOG_RATE_LIMIT_INIT(1, 1);
                    VLOG_WARN_RL(&rl, "Remote endpoints for port beyond "
                                        "BUNDLE_MAX_SLAVES");
                    break;
                }
                ofpbuf_put(ofpacts_p, &tun->ofport,
                            sizeof tun->ofport);
                bundle = ofpacts_p->header;
                bundle->n_slaves++;
            }

            bundle->algorithm = NX_BD_ALG_ACTIVE_BACKUP;
            /* Although ACTIVE_BACKUP bundle algorithm seems to ignore
             * the next two fields, those are always set */
            bundle->basis = 0;
            bundle->fields = NX_HASH_FIELDS_ETH_SRC;
            ofpact_finish_BUNDLE(ofpacts_p, &bundle);
        }
        ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 100, 0,
                        &match, ofpacts_p, &binding->header_.uuid);
    }
out:
    if (ha_ch_ordered) {
        ha_chassis_destroy_ordered(ha_ch_ordered);
    }
}

static void
consider_mc_group(enum mf_field_id mff_ovn_geneve,
                  const struct simap *ct_zones,
                  const struct hmap *local_datapaths,
                  const struct sbrec_chassis *chassis,
                  const struct sbrec_multicast_group *mc,
                  struct ovn_desired_flow_table *flow_table)
{
    uint32_t dp_key = mc->datapath->tunnel_key;
    if (!get_local_datapath(local_datapaths, dp_key)) {
        return;
    }

    struct sset remote_chassis = SSET_INITIALIZER(&remote_chassis);
    struct match match;

    match_init_catchall(&match);
    match_set_metadata(&match, htonll(dp_key));
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, mc->tunnel_key);

    /* Go through all of the ports in the multicast group:
     *
     *    - For remote ports, add the chassis to 'remote_chassis'.
     *
     *    - For local ports (other than logical patch ports), add actions
     *      to 'ofpacts' to set the output port and resubmit.
     *
     *    - For logical patch ports, add actions to 'remote_ofpacts'
     *      instead.  (If we put them in 'ofpacts', then the output
     *      would happen on every hypervisor in the multicast group,
     *      effectively duplicating the packet.)
     */
    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);
    struct ofpbuf remote_ofpacts;
    ofpbuf_init(&remote_ofpacts, 0);
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
            put_load(zone_id, MFF_LOG_CT_ZONE, 0, 32, &ofpacts);
        }

        if (!strcmp(port->type, "patch")) {
            put_load(port->tunnel_key, MFF_LOG_OUTPORT, 0, 32,
                     &remote_ofpacts);
            put_resubmit(OFTABLE_CHECK_LOOPBACK, &remote_ofpacts);
        } else if (simap_contains(&localvif_to_ofport,
                           (port->parent_port && *port->parent_port)
                           ? port->parent_port : port->logical_port)
                   || (!strcmp(port->type, "l3gateway")
                       && port->chassis == chassis)) {
            put_load(port->tunnel_key, MFF_LOG_OUTPORT, 0, 32, &ofpacts);
            put_resubmit(OFTABLE_CHECK_LOOPBACK, &ofpacts);
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
    bool local_ports = ofpacts.size > 0;
    if (local_ports) {
        /* Following delivery to local logical ports, restore the multicast
         * group as the logical output port. */
        put_load(mc->tunnel_key, MFF_LOG_OUTPORT, 0, 32, &ofpacts);

        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100, 0,
                        &match, &ofpacts, &mc->header_.uuid);
    }

    /* Table 32, priority 100.
     * =======================
     *
     * Handle output to the remote chassis in the multicast group, if
     * any. */
    if (!sset_is_empty(&remote_chassis) || remote_ofpacts.size > 0) {
        if (remote_ofpacts.size > 0) {
            /* Following delivery to logical patch ports, restore the
             * multicast group as the logical output port. */
            put_load(mc->tunnel_key, MFF_LOG_OUTPORT, 0, 32,
                     &remote_ofpacts);
        }

        const char *chassis_name;
        const struct chassis_tunnel *prev = NULL;
        SSET_FOR_EACH (chassis_name, &remote_chassis) {
            const struct chassis_tunnel *tun
                = chassis_tunnel_find(chassis_name, NULL);
            if (!tun) {
                continue;
            }

            if (!prev || tun->type != prev->type) {
                put_encapsulation(mff_ovn_geneve, tun, mc->datapath,
                                  mc->tunnel_key, &remote_ofpacts);
                prev = tun;
            }
            ofpact_put_OUTPUT(&remote_ofpacts)->port = tun->ofport;
        }

        if (remote_ofpacts.size) {
            if (local_ports) {
                put_resubmit(OFTABLE_LOCAL_OUTPUT, &remote_ofpacts);
            }
            ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 100, 0,
                            &match, &remote_ofpacts, &mc->header_.uuid);
        }
    }
    ofpbuf_uninit(&ofpacts);
    ofpbuf_uninit(&remote_ofpacts);
    sset_destroy(&remote_chassis);
}

/* Replaces 'old' by 'new' (destroying 'new').  Returns true if 'old' and 'new'
 * contained different data, false if they were the same. */
static bool
update_ofports(struct simap *old, struct simap *new)
{
    bool changed = !simap_equal(old, new);
    simap_swap(old, new);
    simap_destroy(new);
    return changed;
}

void physical_handle_port_binding_changes(
        struct ovsdb_idl_index *sbrec_port_binding_by_name,
        const struct sbrec_port_binding_table *pb_table,
        enum mf_field_id mff_ovn_geneve,
        const struct sbrec_chassis *chassis,
        const struct simap *ct_zones,
        struct hmap *local_datapaths,
        struct sset *active_tunnels,
        struct ovn_desired_flow_table *flow_table)
{
    const struct sbrec_port_binding *binding;
    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (binding, pb_table) {
        if (sbrec_port_binding_is_deleted(binding)) {
            ofctrl_remove_flows(flow_table, &binding->header_.uuid);
        } else {
            if (!sbrec_port_binding_is_new(binding)) {
                ofctrl_remove_flows(flow_table, &binding->header_.uuid);
            }
            consider_port_binding(sbrec_port_binding_by_name,
                                  mff_ovn_geneve, ct_zones,
                                  active_tunnels, local_datapaths,
                                  binding, chassis,
                                  flow_table, &ofpacts);
        }
    }

}

void
physical_handle_mc_group_changes(
        const struct sbrec_multicast_group_table *multicast_group_table,
        enum mf_field_id mff_ovn_geneve,
        const struct sbrec_chassis *chassis,
        const struct simap *ct_zones,
        const struct hmap *local_datapaths,
        struct ovn_desired_flow_table *flow_table)
{
    const struct sbrec_multicast_group *mc;
    SBREC_MULTICAST_GROUP_TABLE_FOR_EACH_TRACKED (mc, multicast_group_table) {
        if (sbrec_multicast_group_is_deleted(mc)) {
            ofctrl_remove_flows(flow_table, &mc->header_.uuid);
        } else {
            if (!sbrec_multicast_group_is_new(mc)) {
                ofctrl_remove_flows(flow_table, &mc->header_.uuid);
            }
            consider_mc_group(mff_ovn_geneve, ct_zones, local_datapaths,
                              chassis, mc, flow_table);
        }
    }
}

void
physical_run(struct ovsdb_idl_index *sbrec_port_binding_by_name,
             const struct sbrec_multicast_group_table *multicast_group_table,
             const struct sbrec_port_binding_table *port_binding_table,
             enum mf_field_id mff_ovn_geneve,
             const struct ovsrec_bridge *br_int,
             const struct sbrec_chassis *chassis,
             const struct simap *ct_zones,
             const struct hmap *local_datapaths,
             const struct sset *local_lports,
             const struct sset *active_tunnels,
             struct ovn_desired_flow_table *flow_table)
{
    if (!hc_uuid) {
        hc_uuid = xmalloc(sizeof(struct uuid));
        uuid_generate(hc_uuid);
    }

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

        const char *tunnel_id = smap_get(&port_rec->external_ids,
                                         "ovn-chassis-id");
        if (tunnel_id &&
                encaps_tunnel_id_match(tunnel_id, chassis->name, NULL)) {
            continue;
        }

        const char *localnet = smap_get(&port_rec->external_ids,
                                        "ovn-localnet-port");
        const char *l2gateway = smap_get(&port_rec->external_ids,
                                        "ovn-l2gateway-port");

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
            } else if (tunnel_id) {
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

                simap_put(&new_tunnel_to_ofport, tunnel_id, ofport);
                /*
                 * We split the tunnel_id to get the chassis-id
                 * and hash the tunnel list on the chassis-id. The
                 * reason to use the chassis-id alone is because 
                 * there might be cases (multicast, gateway chassis)
                 * where we need to tunnel to the chassis, but won't
                 * have the encap-ip specifically.
                 */
                char *hash_id = NULL;
                char *ip = NULL;

                if (!encaps_tunnel_id_parse(tunnel_id, &hash_id, &ip)) {
                    continue;
                }
                struct chassis_tunnel *tun = chassis_tunnel_find(hash_id, ip);
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
                                hash_string(hash_id, 0));
                    tun->chassis_id = xstrdup(tunnel_id);
                    tun->ofport = u16_to_ofp(ofport);
                    tun->type = tunnel_type;
                    physical_map_changed = true;
                }
                free(hash_id);
                free(ip);
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
            free(tun->chassis_id);
            free(tun);
        }
    }

    /* Capture changed or removed openflow ports. */
    physical_map_changed |= update_ofports(&localvif_to_ofport,
                                           &new_localvif_to_ofport);
    if (physical_map_changed) {
        /* Reprocess logical flow table immediately. */
        poll_immediate_wake();
    }

    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);

    /* Set up flows in table 0 for physical-to-logical translation and in table
     * 64 for logical-to-physical translation. */
    const struct sbrec_port_binding *binding;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (binding, port_binding_table) {
        consider_port_binding(sbrec_port_binding_by_name,
                              mff_ovn_geneve, ct_zones,
                              active_tunnels, local_datapaths,
                              binding, chassis,
                              flow_table, &ofpacts);
    }

    /* Handle output to multicast groups, in tables 32 and 33. */
    const struct sbrec_multicast_group *mc;
    SBREC_MULTICAST_GROUP_TABLE_FOR_EACH (mc, multicast_group_table) {
        consider_mc_group(mff_ovn_geneve, ct_zones, local_datapaths,
                          chassis, mc, flow_table);
    }

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

        ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 100, 0, &match,
                        &ofpacts, hc_uuid);
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

        SBREC_PORT_BINDING_TABLE_FOR_EACH (binding, port_binding_table) {
            struct match match = MATCH_CATCHALL_INITIALIZER;

            if (!binding->chassis ||
                !encaps_tunnel_id_match(tun->chassis_id,
                                        binding->chassis->name, NULL)) {
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

            ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 100, 0, &match,
                            &ofpacts, hc_uuid);
        }
    }

    /* Table 32, priority 150.
     * =======================
     *
     * Handles packets received from a VXLAN tunnel which get resubmitted to
     * OFTABLE_LOG_INGRESS_PIPELINE due to lack of needed metadata in VXLAN,
     * explicitly skip sending back out any tunnels and resubmit to table 33
     * for local delivery.
     */
    struct match match;
    match_init_catchall(&match);
    match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                         MLF_RCV_FROM_VXLAN, MLF_RCV_FROM_VXLAN);

    /* Resubmit to table 33. */
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 150, 0,
                    &match, &ofpacts, hc_uuid);

    /* Table 32, priority 150.
     * =======================
     *
     * Packets that should not be sent to other hypervisors.
     */
    match_init_catchall(&match);
    match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                         MLF_LOCAL_ONLY, MLF_LOCAL_ONLY);
    /* Resubmit to table 33. */
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 150, 0,
                    &match, &ofpacts, hc_uuid);

    /* Table 32, priority 150.
     * =======================
     *
     * Handles packets received from ports of type "localport".  These ports
     * are present on every hypervisor.  Traffic that originates at one should
     * never go over a tunnel to a remote hypervisor, so resubmit them to table
     * 33 for local delivery. */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);
    const char *localport;
    SSET_FOR_EACH (localport, local_lports) {
        /* Iterate over all local logical ports and insert a drop
         * rule with higher priority for every localport in this
         * datapath. */
        const struct sbrec_port_binding *pb = lport_lookup_by_name(
            sbrec_port_binding_by_name, localport);
        if (pb && !strcmp(pb->type, "localport")) {
            match_set_reg(&match, MFF_LOG_INPORT - MFF_REG0, pb->tunnel_key);
            match_set_metadata(&match, htonll(pb->datapath->tunnel_key));
            ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 150, 0,
                            &match, &ofpacts, hc_uuid);
        }
    }

    /* Table 32, Priority 0.
     * =======================
     *
     * Resubmit packets that are not directed at tunnels or part of a
     * multicast group to the local output table. */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 0, 0, &match, &ofpacts,
                    hc_uuid);

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
    ofctrl_add_flow(flow_table, OFTABLE_CHECK_LOOPBACK, 0, 0, &match,
                    &ofpacts, hc_uuid);

    /* Table 64, Priority 0.
     * =======================
     *
     * Resubmit packets that do not have the MLF_ALLOW_LOOPBACK flag set
     * to table 65 for logical-to-physical translation. */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOG_TO_PHY, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_SAVE_INPORT, 0, 0, &match, &ofpacts,
                    hc_uuid);

    ofpbuf_uninit(&ofpacts);

    simap_destroy(&new_tunnel_to_ofport);
}
