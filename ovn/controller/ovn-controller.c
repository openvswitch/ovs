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

#include "ovn-controller.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "bfd.h"
#include "binding.h"
#include "chassis.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "encaps.h"
#include "fatal-signal.h"
#include "openvswitch/hmap.h"
#include "lflow.h"
#include "lib/vswitch-idl.h"
#include "lport.h"
#include "ofctrl.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn/actions.h"
#include "ovn/lib/chassis-index.h"
#include "ovn/lib/extend-table.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn/lib/ovn-util.h"
#include "patch.h"
#include "physical.h"
#include "pinctrl.h"
#include "openvswitch/poll-loop.h"
#include "lib/bitmap.h"
#include "lib/hash.h"
#include "smap.h"
#include "sset.h"
#include "stream-ssl.h"
#include "stream.h"
#include "unixctl.h"
#include "util.h"
#include "timeval.h"
#include "timer.h"
#include "stopwatch.h"

VLOG_DEFINE_THIS_MODULE(main);

static unixctl_cb_func ovn_controller_exit;
static unixctl_cb_func ct_zone_list;
static unixctl_cb_func inject_pkt;

#define DEFAULT_BRIDGE_NAME "br-int"
#define DEFAULT_PROBE_INTERVAL_MSEC 5000

#define CONTROLLER_LOOP_STOPWATCH_NAME "ovn-controller-flow-generation"

static void update_probe_interval(struct controller_ctx *,
                                  const char *ovnsb_remote);
static void parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

/* Pending packet to be injected into connected OVS. */
struct pending_pkt {
    /* Setting 'conn' indicates that a request is pending. */
    struct unixctl_conn *conn;
    char *flow_s;
};

static char *ovs_remote;

struct local_datapath *
get_local_datapath(const struct hmap *local_datapaths, uint32_t tunnel_key)
{
    struct hmap_node *node = hmap_first_with_hash(local_datapaths, tunnel_key);
    return (node
            ? CONTAINER_OF(node, struct local_datapath, hmap_node)
            : NULL);
}

const struct sbrec_chassis *
get_chassis(struct ovsdb_idl *ovnsb_idl, const char *chassis_id)
{
    const struct sbrec_chassis *chassis_rec;

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ovnsb_idl) {
        if (!strcmp(chassis_rec->name, chassis_id)) {
            break;
        }
    }

    return chassis_rec;
}

uint32_t
get_tunnel_type(const char *name)
{
    if (!strcmp(name, "geneve")) {
        return GENEVE;
    } else if (!strcmp(name, "stt")) {
        return STT;
    } else if (!strcmp(name, "vxlan")) {
        return VXLAN;
    }

    return 0;
}

const struct ovsrec_bridge *
get_bridge(struct ovsdb_idl *ovs_idl, const char *br_name)
{
    const struct ovsrec_bridge *br;
    OVSREC_BRIDGE_FOR_EACH (br, ovs_idl) {
        if (!strcmp(br->name, br_name)) {
            return br;
        }
    }
    return NULL;
}

static void
update_sb_monitors(struct ovsdb_idl *ovnsb_idl,
                   const struct sbrec_chassis *chassis,
                   const struct sset *local_ifaces,
                   struct hmap *local_datapaths)
{
    /* Monitor Port_Bindings rows for local interfaces and local datapaths.
     *
     * Monitor Logical_Flow, MAC_Binding, Multicast_Group, and DNS tables for
     * local datapaths.
     *
     * We always monitor patch ports because they allow us to see the linkages
     * between related logical datapaths.  That way, when we know that we have
     * a VIF on a particular logical switch, we immediately know to monitor all
     * the connected logical routers and logical switches. */
    struct ovsdb_idl_condition pb = OVSDB_IDL_CONDITION_INIT(&pb);
    struct ovsdb_idl_condition lf = OVSDB_IDL_CONDITION_INIT(&lf);
    struct ovsdb_idl_condition mb = OVSDB_IDL_CONDITION_INIT(&mb);
    struct ovsdb_idl_condition mg = OVSDB_IDL_CONDITION_INIT(&mg);
    struct ovsdb_idl_condition dns = OVSDB_IDL_CONDITION_INIT(&dns);
    sbrec_port_binding_add_clause_type(&pb, OVSDB_F_EQ, "patch");
    /* XXX: We can optimize this, if we find a way to only monitor
     * ports that have a Gateway_Chassis that point's to our own
     * chassis */
    sbrec_port_binding_add_clause_type(&pb, OVSDB_F_EQ, "chassisredirect");
    if (chassis) {
        /* This should be mostly redundant with the other clauses for port
         * bindings, but it allows us to catch any ports that are assigned to
         * us but should not be.  That way, we can clear their chassis
         * assignments. */
        sbrec_port_binding_add_clause_chassis(&pb, OVSDB_F_EQ,
                                              &chassis->header_.uuid);

        /* Ensure that we find out about l2gateway and l3gateway ports that
         * should be present on this chassis.  Otherwise, we might never find
         * out about those ports, if their datapaths don't otherwise have a VIF
         * in this chassis. */
        const char *id = chassis->name;
        const struct smap l2 = SMAP_CONST1(&l2, "l2gateway-chassis", id);
        sbrec_port_binding_add_clause_options(&pb, OVSDB_F_INCLUDES, &l2);
        const struct smap l3 = SMAP_CONST1(&l3, "l3gateway-chassis", id);
        sbrec_port_binding_add_clause_options(&pb, OVSDB_F_INCLUDES, &l3);
    }
    if (local_ifaces) {
        const char *name;
        SSET_FOR_EACH (name, local_ifaces) {
            sbrec_port_binding_add_clause_logical_port(&pb, OVSDB_F_EQ, name);
            sbrec_port_binding_add_clause_parent_port(&pb, OVSDB_F_EQ, name);
        }
    }
    if (local_datapaths) {
        const struct local_datapath *ld;
        HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
            struct uuid *uuid = CONST_CAST(struct uuid *,
                                           &ld->datapath->header_.uuid);
            sbrec_port_binding_add_clause_datapath(&pb, OVSDB_F_EQ, uuid);
            sbrec_logical_flow_add_clause_logical_datapath(&lf, OVSDB_F_EQ,
                                                           uuid);
            sbrec_mac_binding_add_clause_datapath(&mb, OVSDB_F_EQ, uuid);
            sbrec_multicast_group_add_clause_datapath(&mg, OVSDB_F_EQ, uuid);
            sbrec_dns_add_clause_datapaths(&dns, OVSDB_F_INCLUDES, &uuid, 1);
        }
    }
    sbrec_port_binding_set_condition(ovnsb_idl, &pb);
    sbrec_logical_flow_set_condition(ovnsb_idl, &lf);
    sbrec_mac_binding_set_condition(ovnsb_idl, &mb);
    sbrec_multicast_group_set_condition(ovnsb_idl, &mg);
    sbrec_dns_set_condition(ovnsb_idl, &dns);
    ovsdb_idl_condition_destroy(&pb);
    ovsdb_idl_condition_destroy(&lf);
    ovsdb_idl_condition_destroy(&mb);
    ovsdb_idl_condition_destroy(&mg);
    ovsdb_idl_condition_destroy(&dns);
}

static const struct ovsrec_bridge *
create_br_int(struct controller_ctx *ctx,
              const struct ovsrec_open_vswitch *cfg,
              const char *bridge_name)
{
    if (!ctx->ovs_idl_txn) {
        return NULL;
    }

    ovsdb_idl_txn_add_comment(ctx->ovs_idl_txn,
            "ovn-controller: creating integration bridge '%s'", bridge_name);

    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ctx->ovs_idl_txn);
    ovsrec_interface_set_name(iface, bridge_name);
    ovsrec_interface_set_type(iface, "internal");

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ctx->ovs_idl_txn);
    ovsrec_port_set_name(port, bridge_name);
    ovsrec_port_set_interfaces(port, &iface, 1);

    struct ovsrec_bridge *bridge;
    bridge = ovsrec_bridge_insert(ctx->ovs_idl_txn);
    ovsrec_bridge_set_name(bridge, bridge_name);
    ovsrec_bridge_set_fail_mode(bridge, "secure");
    const struct smap oc = SMAP_CONST1(&oc, "disable-in-band", "true");
    ovsrec_bridge_set_other_config(bridge, &oc);
    ovsrec_bridge_set_ports(bridge, &port, 1);

    struct ovsrec_bridge **bridges;
    size_t bytes = sizeof *bridges * cfg->n_bridges;
    bridges = xmalloc(bytes + sizeof *bridges);
    memcpy(bridges, cfg->bridges, bytes);
    bridges[cfg->n_bridges] = bridge;
    ovsrec_open_vswitch_verify_bridges(cfg);
    ovsrec_open_vswitch_set_bridges(cfg, bridges, cfg->n_bridges + 1);
    free(bridges);

    return bridge;
}

static const struct ovsrec_bridge *
get_br_int(struct controller_ctx *ctx)
{
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (!cfg) {
        return NULL;
    }

    const char *br_int_name = smap_get_def(&cfg->external_ids, "ovn-bridge",
                                           DEFAULT_BRIDGE_NAME);

    const struct ovsrec_bridge *br;
    br = get_bridge(ctx->ovs_idl, br_int_name);
    if (!br) {
        return create_br_int(ctx, cfg, br_int_name);
    }
    return br;
}

static const char *
get_chassis_id(const struct ovsdb_idl *ovs_idl)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(ovs_idl);
    const char *chassis_id = cfg ? smap_get(&cfg->external_ids, "system-id") : NULL;

    if (!chassis_id) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "'system-id' in Open_vSwitch database is missing.");
    }

    return chassis_id;
}

/* Iterate address sets in the southbound database.  Create and update the
 * corresponding symtab entries as necessary. */
static void
addr_sets_init(struct controller_ctx *ctx, struct shash *addr_sets)
{
    const struct sbrec_address_set *as;
    SBREC_ADDRESS_SET_FOR_EACH (as, ctx->ovnsb_idl) {
        expr_addr_sets_add(addr_sets, as->name,
                           (const char *const *) as->addresses,
                           as->n_addresses);
    }
}

static void
update_ssl_config(const struct ovsdb_idl *ovs_idl)
{
    const struct ovsrec_ssl *ssl = ovsrec_ssl_first(ovs_idl);

    if (ssl) {
        stream_ssl_set_key_and_cert(ssl->private_key, ssl->certificate);
        stream_ssl_set_ca_cert_file(ssl->ca_cert, ssl->bootstrap_ca_cert);
    }
}

/* Retrieves the OVN Southbound remote location from the
 * "external-ids:ovn-remote" key in 'ovs_idl' and returns a copy of it. */
static char *
get_ovnsb_remote(struct ovsdb_idl *ovs_idl)
{
    while (1) {
        ovsdb_idl_run(ovs_idl);

        const struct ovsrec_open_vswitch *cfg
            = ovsrec_open_vswitch_first(ovs_idl);
        if (cfg) {
            const char *remote = smap_get(&cfg->external_ids, "ovn-remote");
            if (remote) {
                update_ssl_config(ovs_idl);
                return xstrdup(remote);
            }
        }

        VLOG_INFO("OVN OVSDB remote not specified.  Waiting...");
        ovsdb_idl_wait(ovs_idl);
        poll_block();
    }
}

static void
update_ct_zones(struct sset *lports, const struct hmap *local_datapaths,
                struct simap *ct_zones, unsigned long *ct_zone_bitmap,
                struct shash *pending_ct_zones)
{
    struct simap_node *ct_zone, *ct_zone_next;
    int scan_start = 1;
    const char *user;
    struct sset all_users = SSET_INITIALIZER(&all_users);

    SSET_FOR_EACH(user, lports) {
        sset_add(&all_users, user);
    }

    /* Local patched datapath (gateway routers) need zones assigned. */
    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        /* XXX Add method to limit zone assignment to logical router
         * datapaths with NAT */
        char *dnat = alloc_nat_zone_key(&ld->datapath->header_.uuid, "dnat");
        char *snat = alloc_nat_zone_key(&ld->datapath->header_.uuid, "snat");
        sset_add(&all_users, dnat);
        sset_add(&all_users, snat);
        free(dnat);
        free(snat);
    }

    /* Delete zones that do not exist in above sset. */
    SIMAP_FOR_EACH_SAFE(ct_zone, ct_zone_next, ct_zones) {
        if (!sset_contains(&all_users, ct_zone->name)) {
            VLOG_DBG("removing ct zone %"PRId32" for '%s'",
                     ct_zone->data, ct_zone->name);

            struct ct_zone_pending_entry *pending = xmalloc(sizeof *pending);
            pending->state = CT_ZONE_DB_QUEUED; /* Skip flushing zone. */
            pending->zone = ct_zone->data;
            pending->add = false;
            shash_add(pending_ct_zones, ct_zone->name, pending);

            bitmap_set0(ct_zone_bitmap, ct_zone->data);
            simap_delete(ct_zones, ct_zone);
        }
    }

    /* xxx This is wasteful to assign a zone to each port--even if no
     * xxx security policy is applied. */

    /* Assign a unique zone id for each logical port and two zones
     * to a gateway router. */
    SSET_FOR_EACH(user, &all_users) {
        int zone;

        if (simap_contains(ct_zones, user)) {
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

        VLOG_DBG("assigning ct zone %"PRId32" to '%s'", zone, user);

        struct ct_zone_pending_entry *pending = xmalloc(sizeof *pending);
        pending->state = CT_ZONE_OF_QUEUED;
        pending->zone = zone;
        pending->add = true;
        shash_add(pending_ct_zones, user, pending);

        bitmap_set1(ct_zone_bitmap, zone);
        simap_put(ct_zones, user, zone);
    }

    sset_destroy(&all_users);
}

static void
commit_ct_zones(const struct ovsrec_bridge *br_int,
                struct shash *pending_ct_zones)
{
    struct smap new_ids;
    smap_clone(&new_ids, &br_int->external_ids);

    bool updated = false;
    struct shash_node *iter;
    SHASH_FOR_EACH(iter, pending_ct_zones) {
        struct ct_zone_pending_entry *ctzpe = iter->data;

        /* The transaction is open, so any pending entries in the
         * CT_ZONE_DB_QUEUED must be sent and any in CT_ZONE_DB_QUEUED
         * need to be retried. */
        if (ctzpe->state != CT_ZONE_DB_QUEUED
            && ctzpe->state != CT_ZONE_DB_SENT) {
            continue;
        }

        char *user_str = xasprintf("ct-zone-%s", iter->name);
        if (ctzpe->add) {
            char *zone_str = xasprintf("%"PRId32, ctzpe->zone);
            smap_replace(&new_ids, user_str, zone_str);
            free(zone_str);
        } else {
            smap_remove(&new_ids, user_str);
        }
        free(user_str);

        ctzpe->state = CT_ZONE_DB_SENT;
        updated = true;
    }

    if (updated) {
        ovsrec_bridge_verify_external_ids(br_int);
        ovsrec_bridge_set_external_ids(br_int, &new_ids);
    }
    smap_destroy(&new_ids);
}

static void
restore_ct_zones(struct ovsdb_idl *ovs_idl,
                 struct simap *ct_zones, unsigned long *ct_zone_bitmap)
{
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_first(ovs_idl);
    if (!cfg) {
        return;
    }

    const char *br_int_name = smap_get_def(&cfg->external_ids, "ovn-bridge",
                                           DEFAULT_BRIDGE_NAME);

    const struct ovsrec_bridge *br_int;
    br_int = get_bridge(ovs_idl, br_int_name);
    if (!br_int) {
        /* If the integration bridge hasn't been defined, assume that
         * any existing ct-zone definitions aren't valid. */
        return;
    }

    struct smap_node *node;
    SMAP_FOR_EACH(node, &br_int->external_ids) {
        if (strncmp(node->key, "ct-zone-", 8)) {
            continue;
        }

        const char *user = node->key + 8;
        int zone = atoi(node->value);

        if (user[0] && zone) {
            VLOG_DBG("restoring ct zone %"PRId32" for '%s'", zone, user);
            bitmap_set1(ct_zone_bitmap, zone);
            simap_put(ct_zones, user, zone);
        }
    }
}

static int64_t
get_nb_cfg(struct ovsdb_idl *idl)
{
    const struct sbrec_sb_global *sb = sbrec_sb_global_first(idl);
    return sb ? sb->nb_cfg : 0;
}

static void
ctrl_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    /* We do not monitor all tables by default, so modules must register
     * their interest explicitly. */
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_bridges);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_bfd);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_bfd_status);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_type);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_options);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_fail_mode);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_other_config);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_ssl);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_bootstrap_ca_cert);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_ca_cert);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_certificate);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_private_key);
    chassis_register_ovs_idl(ovs_idl);
    encaps_register_ovs_idl(ovs_idl);
    binding_register_ovs_idl(ovs_idl);
    bfd_register_ovs_idl(ovs_idl);
    physical_register_ovs_idl(ovs_idl);
}

static void
create_ovnsb_indexes(struct ovsdb_idl *ovnsb_idl)
{
    struct ovsdb_idl_index *index;

    /* Index multicast group table by name and datapath. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_multicast_group,
                                   "multicast-group-by-dp-name");
    ovsdb_idl_index_add_column(index, &sbrec_multicast_group_col_name,
                               OVSDB_INDEX_ASC, NULL);
    ovsdb_idl_index_add_column(index, &sbrec_multicast_group_col_datapath,
                               OVSDB_INDEX_ASC, NULL);

    /* Index logical port table by name. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_port_binding,
                                   "lport-by-name");
    ovsdb_idl_index_add_column(index, &sbrec_port_binding_col_logical_port,
                               OVSDB_INDEX_ASC, NULL);

    /* Index logical port table by tunnel key and datapath. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_port_binding,
                                   "lport-by-key");
    ovsdb_idl_index_add_column(index, &sbrec_port_binding_col_tunnel_key,
                               OVSDB_INDEX_ASC, NULL);
    ovsdb_idl_index_add_column(index, &sbrec_port_binding_col_datapath,
                               OVSDB_INDEX_ASC, NULL);

    /* Index logical port table by datapath. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_port_binding,
                                   "lport-by-datapath");
    ovsdb_idl_index_add_column(index, &sbrec_port_binding_col_datapath,
                               OVSDB_INDEX_ASC, NULL);

    /* Index datapath binding table by tunnel key. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_datapath_binding,
                                   "dpath-by-key");
    ovsdb_idl_index_add_column(index, &sbrec_datapath_binding_col_tunnel_key,
                               OVSDB_INDEX_ASC, NULL);
}

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    bool exiting;
    int retval;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemonize_start(false);

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_controller_exit, &exiting);

    /* Initialize group ids for loadbalancing. */
    struct ovn_extend_table group_table;
    ovn_extend_table_init(&group_table);

    /* Initialize meter ids for QoS. */
    struct ovn_extend_table meter_table;
    ovn_extend_table_init(&meter_table);

    daemonize_complete();

    ofctrl_init(&group_table, &meter_table);
    pinctrl_init();
    lflow_init();

    /* Connect to OVS OVSDB instance. */
    struct ovsdb_idl_loop ovs_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovs_remote, &ovsrec_idl_class, false, true));
    ctrl_register_ovs_idl(ovs_idl_loop.idl);
    ovsdb_idl_get_initial_snapshot(ovs_idl_loop.idl);

    /* Connect to OVN SB database and get a snapshot. */
    char *ovnsb_remote = get_ovnsb_remote(ovs_idl_loop.idl);
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_remote, &sbrec_idl_class, true, true));
    ovsdb_idl_set_leader_only(ovnsb_idl_loop.idl, false);

    create_ovnsb_indexes(ovnsb_idl_loop.idl);
    lport_init(ovnsb_idl_loop.idl);

    ovsdb_idl_omit_alert(ovnsb_idl_loop.idl, &sbrec_chassis_col_nb_cfg);
    update_sb_monitors(ovnsb_idl_loop.idl, NULL, NULL, NULL);
    ovsdb_idl_get_initial_snapshot(ovnsb_idl_loop.idl);

    /* Initialize connection tracking zones. */
    struct simap ct_zones = SIMAP_INITIALIZER(&ct_zones);
    struct shash pending_ct_zones = SHASH_INITIALIZER(&pending_ct_zones);
    unsigned long ct_zone_bitmap[BITMAP_N_LONGS(MAX_CT_ZONES)];
    memset(ct_zone_bitmap, 0, sizeof ct_zone_bitmap);
    bitmap_set1(ct_zone_bitmap, 0); /* Zone 0 is reserved. */
    restore_ct_zones(ovs_idl_loop.idl, &ct_zones, ct_zone_bitmap);
    unixctl_command_register("ct-zone-list", "", 0, 0,
                             ct_zone_list, &ct_zones);

    struct pending_pkt pending_pkt = { .conn = NULL };
    unixctl_command_register("inject-pkt", "MICROFLOW", 1, 1, inject_pkt,
                             &pending_pkt);

    stopwatch_create(CONTROLLER_LOOP_STOPWATCH_NAME, SW_MS);
    /* Main loop. */
    exiting = false;
    while (!exiting) {
        /* Check OVN SB database. */
        char *new_ovnsb_remote = get_ovnsb_remote(ovs_idl_loop.idl);
        if (strcmp(ovnsb_remote, new_ovnsb_remote)) {
            free(ovnsb_remote);
            ovnsb_remote = new_ovnsb_remote;
            ovsdb_idl_set_remote(ovnsb_idl_loop.idl, ovnsb_remote, true);
        } else {
            free(new_ovnsb_remote);
        }

        struct controller_ctx ctx = {
            .ovs_idl = ovs_idl_loop.idl,
            .ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_idl_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        update_probe_interval(&ctx, ovnsb_remote);

        update_ssl_config(ctx.ovs_idl);

        /* Contains "struct local_datapath" nodes. */
        struct hmap local_datapaths = HMAP_INITIALIZER(&local_datapaths);

        /* Contains the name of each logical port resident on the local
         * hypervisor.  These logical ports include the VIFs (and their child
         * logical ports, if any) that belong to VMs running on the hypervisor,
         * l2gateway ports for which options:l2gateway-chassis designates the
         * local hypervisor, and localnet ports. */
        struct sset local_lports = SSET_INITIALIZER(&local_lports);
        /* Contains the same ports as local_lports, but in the format:
         * <datapath-tunnel-key>_<port-tunnel-key> */
        struct sset local_lport_ids = SSET_INITIALIZER(&local_lport_ids);
        struct sset active_tunnels = SSET_INITIALIZER(&active_tunnels);

        const struct ovsrec_bridge *br_int = get_br_int(&ctx);
        const char *chassis_id = get_chassis_id(ctx.ovs_idl);

        struct chassis_index chassis_index;

        chassis_index_init(&chassis_index, ctx.ovnsb_idl);

        const struct sbrec_chassis *chassis = NULL;
        if (chassis_id) {
            chassis = chassis_run(&ctx, chassis_id, br_int);
            encaps_run(&ctx, br_int, chassis_id);
            bfd_calculate_active_tunnels(br_int, &active_tunnels);
            binding_run(&ctx, br_int, chassis,
                        &chassis_index, &active_tunnels, &local_datapaths,
                        &local_lports, &local_lport_ids);
        }
        if (br_int && chassis) {
            struct shash addr_sets = SHASH_INITIALIZER(&addr_sets);
            addr_sets_init(&ctx, &addr_sets);

            patch_run(&ctx, br_int, chassis);

            enum mf_field_id mff_ovn_geneve = ofctrl_run(br_int,
                                                         &pending_ct_zones);

            pinctrl_run(&ctx, br_int, chassis, &chassis_index,
                        &local_datapaths, &active_tunnels);
            update_ct_zones(&local_lports, &local_datapaths, &ct_zones,
                            ct_zone_bitmap, &pending_ct_zones);
            if (ctx.ovs_idl_txn) {
                if (ofctrl_can_put()) {
                    stopwatch_start(CONTROLLER_LOOP_STOPWATCH_NAME,
                                    time_msec());

                    commit_ct_zones(br_int, &pending_ct_zones);

                    struct hmap flow_table = HMAP_INITIALIZER(&flow_table);
                    lflow_run(&ctx, chassis,
                              &chassis_index, &local_datapaths, &group_table,
                              &meter_table, &addr_sets, &flow_table,
                              &active_tunnels, &local_lport_ids);

                    if (chassis_id) {
                        bfd_run(&ctx, br_int, chassis, &local_datapaths,
                                &chassis_index);
                    }
                    physical_run(&ctx, mff_ovn_geneve,
                                 br_int, chassis, &ct_zones,
                                 &flow_table, &local_datapaths, &local_lports,
                                 &chassis_index, &active_tunnels);

                    stopwatch_stop(CONTROLLER_LOOP_STOPWATCH_NAME,
                                   time_msec());

                    ofctrl_put(&flow_table, &pending_ct_zones,
                               get_nb_cfg(ctx.ovnsb_idl));

                    hmap_destroy(&flow_table);
                }
                if (ctx.ovnsb_idl_txn) {
                    int64_t cur_cfg = ofctrl_get_cur_cfg();
                    if (cur_cfg && cur_cfg != chassis->nb_cfg) {
                        sbrec_chassis_set_nb_cfg(chassis, cur_cfg);
                    }
                }
            }

            if (pending_pkt.conn) {
                char *error = ofctrl_inject_pkt(br_int, pending_pkt.flow_s,
                                                &addr_sets);
                if (error) {
                    unixctl_command_reply_error(pending_pkt.conn, error);
                    free(error);
                } else {
                    unixctl_command_reply(pending_pkt.conn, NULL);
                }
                pending_pkt.conn = NULL;
                free(pending_pkt.flow_s);
            }

            update_sb_monitors(ctx.ovnsb_idl, chassis,
                               &local_lports, &local_datapaths);

            expr_addr_sets_destroy(&addr_sets);
            shash_destroy(&addr_sets);
        }

        /* If we haven't handled the pending packet insertion
         * request, the system is not ready. */
        if (pending_pkt.conn) {
            unixctl_command_reply_error(pending_pkt.conn,
                                        "ovn-controller not ready.");
            pending_pkt.conn = NULL;
            free(pending_pkt.flow_s);
        }

        chassis_index_destroy(&chassis_index);

        sset_destroy(&local_lports);
        sset_destroy(&local_lport_ids);
        sset_destroy(&active_tunnels);

        struct local_datapath *cur_node, *next_node;
        HMAP_FOR_EACH_SAFE (cur_node, next_node, hmap_node, &local_datapaths) {
            free(cur_node->peer_dps);
            hmap_remove(&local_datapaths, &cur_node->hmap_node);
            free(cur_node);
        }
        hmap_destroy(&local_datapaths);

        unixctl_server_run(unixctl);

        unixctl_server_wait(unixctl);
        if (exiting || pending_pkt.conn) {
            poll_immediate_wake();
        }

        if (br_int) {
            ofctrl_wait();
            pinctrl_wait(&ctx);
        }

        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);

        if (ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop) == 1) {
            struct shash_node *iter, *iter_next;
            SHASH_FOR_EACH_SAFE(iter, iter_next, &pending_ct_zones) {
                struct ct_zone_pending_entry *ctzpe = iter->data;
                if (ctzpe->state == CT_ZONE_DB_SENT) {
                    shash_delete(&pending_ct_zones, iter);
                    free(ctzpe);
                }
            }
        }
        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }

    /* It's time to exit.  Clean up the databases. */
    bool done = false;
    while (!done) {
        struct controller_ctx ctx = {
            .ovs_idl = ovs_idl_loop.idl,
            .ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_idl_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        const struct ovsrec_bridge *br_int = get_br_int(&ctx);
        const char *chassis_id = get_chassis_id(ctx.ovs_idl);
        const struct sbrec_chassis *chassis
            = chassis_id ? get_chassis(ctx.ovnsb_idl, chassis_id) : NULL;

        /* Run all of the cleanup functions, even if one of them returns false.
         * We're done if all of them return true. */
        done = binding_cleanup(&ctx, chassis);
        done = chassis_cleanup(&ctx, chassis) && done;
        done = encaps_cleanup(&ctx, br_int) && done;
        if (done) {
            poll_immediate_wake();
        }

        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
        ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop);
        poll_block();
    }

    unixctl_server_destroy(unixctl);
    lflow_destroy();
    ofctrl_destroy();
    pinctrl_destroy();

    simap_destroy(&ct_zones);
    shash_destroy(&pending_ct_zones);

    ovn_extend_table_destroy(&group_table);
    ovn_extend_table_destroy(&meter_table);

    ovsdb_idl_loop_destroy(&ovs_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);

    free(ovnsb_remote);
    free(ovs_remote);
    service_stop();

    exit(retval);
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_BOOTSTRAP_CA_CERT,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        DAEMON_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {NULL, 0, NULL, 0}
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(OFP13_VERSION, OFP13_VERSION);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    if (argc == 0) {
        ovs_remote = xasprintf("unix:%s/db.sock", ovs_rundir());
    } else if (argc == 1) {
        ovs_remote = xstrdup(argv[0]);
    } else {
        VLOG_FATAL("exactly zero or one non-option argument required; "
                   "use --help for usage");
    }
}

static void
usage(void)
{
    printf("%s: OVN controller\n"
           "usage %s [OPTIONS] [OVS-DATABASE]\n"
           "where OVS-DATABASE is a socket on which the OVS OVSDB server is listening.\n",
               program_name, program_name);
    stream_usage("OVS-DATABASE", true, false, false);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

static void
ovn_controller_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}

static void
ct_zone_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *ct_zones_)
{
    struct simap *ct_zones = ct_zones_;
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct simap_node *zone;

    SIMAP_FOR_EACH(zone, ct_zones) {
        ds_put_format(&ds, "%s %d\n", zone->name, zone->data);
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
inject_pkt(struct unixctl_conn *conn, int argc OVS_UNUSED,
           const char *argv[], void *pending_pkt_)
{
    struct pending_pkt *pending_pkt = pending_pkt_;

    if (pending_pkt->conn) {
        unixctl_command_reply_error(conn, "already pending packet injection");
        return;
    }
    pending_pkt->conn = conn;
    pending_pkt->flow_s = xstrdup(argv[1]);
}

/* Get the desired SB probe timer from the OVS database and configure it into
 * the SB database. */
static void
update_probe_interval(struct controller_ctx *ctx, const char *ovnsb_remote)
{
    const struct ovsrec_open_vswitch *cfg
        = ovsrec_open_vswitch_first(ctx->ovs_idl);
    int interval = -1;
    if (cfg) {
        interval = smap_get_int(&cfg->external_ids,
                                "ovn-remote-probe-interval",
                                -1);
    }
    if (interval == -1) {
        interval = stream_or_pstream_needs_probes(ovnsb_remote)
                   ? DEFAULT_PROBE_INTERVAL_MSEC
                   : 0;
    }

    ovsdb_idl_set_probe_interval(ctx->ovnsb_idl, interval);
}
