/* Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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
#include "bridge.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>

#include "async-append.h"
#include "bfd.h"
#include "bitmap.h"
#include "cfm.h"
#include "connectivity.h"
#include "coverage.h"
#include "daemon.h"
#include "dirs.h"
#include "dpif.h"
#include "dpdk.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "hmapx.h"
#include "if-notifier.h"
#include "jsonrpc.h"
#include "lacp.h"
#include "mac-learning.h"
#include "mcast-snooping.h"
#include "netdev.h"
#include "nx-match.h"
#include "ofproto/bond.h"
#include "ofproto/ofproto.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovs-lldp.h"
#include "ovs-numa.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "sflow_api.h"
#include "sha1.h"
#include "openvswitch/shash.h"
#include "smap.h"
#include "socket-util.h"
#include "stream.h"
#include "stream-ssl.h"
#include "sset.h"
#include "system-stats.h"
#include "timeval.h"
#include "util.h"
#include "unixctl.h"
#include "lib/vswitch-idl.h"
#include "xenserver.h"
#include "vlan-bitmap.h"

VLOG_DEFINE_THIS_MODULE(bridge);

COVERAGE_DEFINE(bridge_reconfigure);

struct iface {
    /* These members are always valid.
     *
     * They are immutable: they never change between iface_create() and
     * iface_destroy(). */
    struct ovs_list port_elem;  /* Element in struct port's "ifaces" list. */
    struct hmap_node name_node; /* In struct bridge's "iface_by_name" hmap. */
    struct hmap_node ofp_port_node; /* In struct bridge's "ifaces" hmap. */
    struct port *port;          /* Containing port. */
    char *name;                 /* Host network device name. */
    struct netdev *netdev;      /* Network device. */
    ofp_port_t ofp_port;        /* OpenFlow port number. */
    uint64_t change_seq;

    /* These members are valid only within bridge_reconfigure(). */
    const char *type;           /* Usually same as cfg->type. */
    const struct ovsrec_interface *cfg;
};

struct mirror {
    struct uuid uuid;           /* UUID of this "mirror" record in database. */
    struct hmap_node hmap_node; /* In struct bridge's "mirrors" hmap. */
    struct bridge *bridge;
    char *name;
    const struct ovsrec_mirror *cfg;
};

struct port {
    struct hmap_node hmap_node; /* Element in struct bridge's "ports" hmap. */
    struct bridge *bridge;
    char *name;

    const struct ovsrec_port *cfg;

    /* An ordinary bridge port has 1 interface.
     * A bridge port for bonding has at least 2 interfaces. */
    struct ovs_list ifaces;    /* List of "struct iface"s. */
};

struct bridge {
    struct hmap_node node;      /* In 'all_bridges'. */
    char *name;                 /* User-specified arbitrary name. */
    char *type;                 /* Datapath type. */
    struct eth_addr ea;         /* Bridge Ethernet Address. */
    struct eth_addr default_ea; /* Default MAC. */
    const struct ovsrec_bridge *cfg;

    /* OpenFlow switch processing. */
    struct ofproto *ofproto;    /* OpenFlow switch. */

    /* Bridge ports. */
    struct hmap ports;          /* "struct port"s indexed by name. */
    struct hmap ifaces;         /* "struct iface"s indexed by ofp_port. */
    struct hmap iface_by_name;  /* "struct iface"s indexed by name. */

    /* Port mirroring. */
    struct hmap mirrors;        /* "struct mirror" indexed by UUID. */

    /* Auto Attach */
    struct hmap mappings;       /* "struct" indexed by UUID */

    /* Used during reconfiguration. */
    struct shash wanted_ports;

    /* Synthetic local port if necessary. */
    struct ovsrec_port synth_local_port;
    struct ovsrec_interface synth_local_iface;
    struct ovsrec_interface *synth_local_ifacep;
};

struct aa_mapping {
    struct hmap_node hmap_node; /* In struct bridge's "mappings" hmap. */
    struct bridge *bridge;
    uint32_t isid;
    uint16_t vlan;
    char *br_name;
};

/* All bridges, indexed by name. */
static struct hmap all_bridges = HMAP_INITIALIZER(&all_bridges);

/* OVSDB IDL used to obtain configuration. */
static struct ovsdb_idl *idl;

/* We want to complete daemonization, fully detaching from our parent process,
 * only after we have completed our initial configuration, committed our state
 * to the database, and received confirmation back from the database server
 * that it applied the commit.  This allows our parent process to know that,
 * post-detach, ephemeral fields such as datapath-id and ofport are very likely
 * to have already been filled in.  (It is only "very likely" rather than
 * certain because there is always a slim possibility that the transaction will
 * fail or that some other client has added new bridges, ports, etc. while
 * ovs-vswitchd was configuring using an old configuration.)
 *
 * We only need to do this once for our initial configuration at startup, so
 * 'initial_config_done' tracks whether we've already done it.  While we are
 * waiting for a response to our commit, 'daemonize_txn' tracks the transaction
 * itself and is otherwise NULL. */
static bool initial_config_done;
static struct ovsdb_idl_txn *daemonize_txn;

/* Most recently processed IDL sequence number. */
static unsigned int idl_seqno;

/* Track changes to port connectivity. */
static uint64_t connectivity_seqno = LLONG_MIN;

/* Status update to database.
 *
 * Some information in the database must be kept as up-to-date as possible to
 * allow controllers to respond rapidly to network outages.  Those status are
 * updated via the 'status_txn'.
 *
 * We use the global connectivity sequence number to detect the status change.
 * Also, to prevent the status update from sending too much to the database,
 * we check the return status of each update transaction and do not start new
 * update if the previous transaction status is 'TXN_INCOMPLETE'.
 *
 * 'statux_txn' is NULL if there is no ongoing status update.
 *
 * If the previous database transaction was failed (is not 'TXN_SUCCESS',
 * 'TXN_UNCHANGED' or 'TXN_INCOMPLETE'), 'status_txn_try_again' is set to true,
 * which will cause the main thread wake up soon and retry the status update.
 */
static struct ovsdb_idl_txn *status_txn;
static bool status_txn_try_again;

/* When the status update transaction returns 'TXN_INCOMPLETE', should register a
 * timeout in 'STATUS_CHECK_AGAIN_MSEC' to check again. */
#define STATUS_CHECK_AGAIN_MSEC 100

/* Statistics update to database. */
static struct ovsdb_idl_txn *stats_txn;

/* Each time this timer expires, the bridge fetches interface and mirror
 * statistics and pushes them into the database. */
static int stats_timer_interval;
static long long int stats_timer = LLONG_MIN;

/* Each time this timer expires, the bridge fetches the list of port/VLAN
 * membership that has been modified by the AA.
 */
#define AA_REFRESH_INTERVAL (1000) /* In milliseconds. */
static long long int aa_refresh_timer = LLONG_MIN;

/* Whenever system interfaces are added, removed or change state, the bridge
 * will be reconfigured.
 */
static struct if_notifier *ifnotifier;
static struct seq *ifaces_changed;
static uint64_t last_ifaces_changed;

static void add_del_bridges(const struct ovsrec_open_vswitch *);
static void bridge_run__(void);
static void bridge_create(const struct ovsrec_bridge *);
static void bridge_destroy(struct bridge *, bool del);
static struct bridge *bridge_lookup(const char *name);
static unixctl_cb_func bridge_unixctl_dump_flows;
static unixctl_cb_func bridge_unixctl_reconnect;
static size_t bridge_get_controllers(const struct bridge *br,
                                     struct ovsrec_controller ***controllersp);
static void bridge_collect_wanted_ports(struct bridge *,
                                        struct shash *wanted_ports);
static void bridge_delete_ofprotos(void);
static void bridge_delete_or_reconfigure_ports(struct bridge *);
static void bridge_del_ports(struct bridge *,
                             const struct shash *wanted_ports);
static void bridge_add_ports(struct bridge *,
                             const struct shash *wanted_ports);

static void bridge_configure_datapath_id(struct bridge *);
static void bridge_configure_netflow(struct bridge *);
static void bridge_configure_forward_bpdu(struct bridge *);
static void bridge_configure_mac_table(struct bridge *);
static void bridge_configure_mcast_snooping(struct bridge *);
static void bridge_configure_sflow(struct bridge *, int *sflow_bridge_number);
static void bridge_configure_ipfix(struct bridge *);
static void bridge_configure_spanning_tree(struct bridge *);
static void bridge_configure_tables(struct bridge *);
static void bridge_configure_dp_desc(struct bridge *);
static void bridge_configure_aa(struct bridge *);
static void bridge_aa_refresh_queued(struct bridge *);
static bool bridge_aa_need_refresh(struct bridge *);
static void bridge_configure_remotes(struct bridge *,
                                     const struct sockaddr_in *managers,
                                     size_t n_managers);
static void bridge_pick_local_hw_addr(struct bridge *, struct eth_addr *ea,
                                      struct iface **hw_addr_iface);
static uint64_t bridge_pick_datapath_id(struct bridge *,
                                        const struct eth_addr bridge_ea,
                                        struct iface *hw_addr_iface);
static uint64_t dpid_from_hash(const void *, size_t nbytes);
static bool bridge_has_bond_fake_iface(const struct bridge *,
                                       const char *name);
static bool port_is_bond_fake_iface(const struct port *);

static unixctl_cb_func qos_unixctl_show_types;
static unixctl_cb_func qos_unixctl_show;

static struct port *port_create(struct bridge *, const struct ovsrec_port *);
static void port_del_ifaces(struct port *);
static void port_destroy(struct port *);
static struct port *port_lookup(const struct bridge *, const char *name);
static void port_configure(struct port *);
static struct lacp_settings *port_configure_lacp(struct port *,
                                                 struct lacp_settings *);
static void port_configure_bond(struct port *, struct bond_settings *);
static bool port_is_synthetic(const struct port *);

static void reconfigure_system_stats(const struct ovsrec_open_vswitch *);
static void run_system_stats(void);

static void bridge_configure_mirrors(struct bridge *);
static struct mirror *mirror_create(struct bridge *,
                                    const struct ovsrec_mirror *);
static void mirror_destroy(struct mirror *);
static bool mirror_configure(struct mirror *);
static void mirror_refresh_stats(struct mirror *);

static void iface_configure_lacp(struct iface *, struct lacp_slave_settings *);
static bool iface_create(struct bridge *, const struct ovsrec_interface *,
                         const struct ovsrec_port *);
static bool iface_is_internal(const struct ovsrec_interface *iface,
                              const struct ovsrec_bridge *br);
static const char *iface_get_type(const struct ovsrec_interface *,
                                  const struct ovsrec_bridge *);
static void iface_destroy(struct iface *);
static void iface_destroy__(struct iface *);
static struct iface *iface_lookup(const struct bridge *, const char *name);
static struct iface *iface_find(const char *name);
static struct iface *iface_from_ofp_port(const struct bridge *,
                                         ofp_port_t ofp_port);
static void iface_set_mac(const struct bridge *, const struct port *, struct iface *);
static void iface_set_ofport(const struct ovsrec_interface *, ofp_port_t ofport);
static void iface_clear_db_record(const struct ovsrec_interface *if_cfg, char *errp);
static void iface_configure_qos(struct iface *, const struct ovsrec_qos *);
static void iface_configure_cfm(struct iface *);
static void iface_refresh_cfm_stats(struct iface *);
static void iface_refresh_stats(struct iface *);
static void iface_refresh_netdev_status(struct iface *);
static void iface_refresh_ofproto_status(struct iface *);
static bool iface_is_synthetic(const struct iface *);
static ofp_port_t iface_get_requested_ofp_port(
    const struct ovsrec_interface *);
static ofp_port_t iface_pick_ofport(const struct ovsrec_interface *);


static void discover_types(const struct ovsrec_open_vswitch *cfg);

static void
bridge_init_ofproto(const struct ovsrec_open_vswitch *cfg)
{
    struct shash iface_hints;
    static bool initialized = false;
    int i;

    if (initialized) {
        return;
    }

    shash_init(&iface_hints);

    if (cfg) {
        for (i = 0; i < cfg->n_bridges; i++) {
            const struct ovsrec_bridge *br_cfg = cfg->bridges[i];
            int j;

            for (j = 0; j < br_cfg->n_ports; j++) {
                struct ovsrec_port *port_cfg = br_cfg->ports[j];
                int k;

                for (k = 0; k < port_cfg->n_interfaces; k++) {
                    struct ovsrec_interface *if_cfg = port_cfg->interfaces[k];
                    struct iface_hint *iface_hint;

                    iface_hint = xmalloc(sizeof *iface_hint);
                    iface_hint->br_name = br_cfg->name;
                    iface_hint->br_type = br_cfg->datapath_type;
                    iface_hint->ofp_port = iface_pick_ofport(if_cfg);

                    shash_add(&iface_hints, if_cfg->name, iface_hint);
                }
            }
        }
    }

    ofproto_init(&iface_hints);

    shash_destroy_free_data(&iface_hints);
    initialized = true;
}

static void
if_change_cb(void *aux OVS_UNUSED)
{
    seq_change(ifaces_changed);
}

static bool
if_notifier_changed(struct if_notifier *notifier OVS_UNUSED)
{
    uint64_t new_seq;
    bool changed = false;
    new_seq = seq_read(ifaces_changed);
    if (new_seq != last_ifaces_changed) {
        changed = true;
        last_ifaces_changed = new_seq;
    }
    seq_wait(ifaces_changed, last_ifaces_changed);
    return changed;
}

/* Public functions. */

/* Initializes the bridge module, configuring it to obtain its configuration
 * from an OVSDB server accessed over 'remote', which should be a string in a
 * form acceptable to ovsdb_idl_create(). */
void
bridge_init(const char *remote)
{
    /* Create connection to database. */
    idl = ovsdb_idl_create(remote, &ovsrec_idl_class, true, true);
    idl_seqno = ovsdb_idl_get_seqno(idl);
    ovsdb_idl_set_lock(idl, "ovs_vswitchd");
    ovsdb_idl_verify_write_only(idl);

    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_cur_cfg);
    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_statistics);
    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_datapath_types);
    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_iface_types);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_ovs_version);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_db_version);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_system_type);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_system_version);
    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_dpdk_version);
    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_dpdk_initialized);

    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_datapath_id);
    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_datapath_version);
    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_rstp_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_stp_enable);
    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_rstp_enable);
    ovsdb_idl_omit(idl, &ovsrec_bridge_col_external_ids);

    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_rstp_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_rstp_statistics);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_statistics);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_bond_active_slave);
    ovsdb_idl_omit(idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_trunks);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_vlan_mode);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_admin_state);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_duplex);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_link_speed);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_link_state);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_link_resets);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_mac_in_use);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_ifindex);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_mtu);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_statistics);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_fault);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_fault_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_remote_mpids);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_flap_count);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_health);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_remote_opstate);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_bfd_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_lacp_current);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_error);
    ovsdb_idl_omit(idl, &ovsrec_interface_col_external_ids);

    ovsdb_idl_omit_alert(idl, &ovsrec_controller_col_is_connected);
    ovsdb_idl_omit_alert(idl, &ovsrec_controller_col_role);
    ovsdb_idl_omit_alert(idl, &ovsrec_controller_col_status);
    ovsdb_idl_omit(idl, &ovsrec_controller_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_qos_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_queue_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_mirror_col_external_ids);
    ovsdb_idl_omit_alert(idl, &ovsrec_mirror_col_statistics);

    ovsdb_idl_omit(idl, &ovsrec_netflow_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_sflow_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_ipfix_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_flow_sample_collector_set_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_manager_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_inactivity_probe);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_is_connected);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_max_backoff);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_status);

    ovsdb_idl_omit(idl, &ovsrec_ssl_col_external_ids);

    /* Register unixctl commands. */
    unixctl_command_register("qos/show-types", "interface", 1, 1,
                             qos_unixctl_show_types, NULL);
    unixctl_command_register("qos/show", "interface", 1, 1,
                             qos_unixctl_show, NULL);
    unixctl_command_register("bridge/dump-flows", "bridge", 1, 1,
                             bridge_unixctl_dump_flows, NULL);
    unixctl_command_register("bridge/reconnect", "[bridge]", 0, 1,
                             bridge_unixctl_reconnect, NULL);
    lacp_init();
    bond_init();
    cfm_init();
    bfd_init();
    ovs_numa_init();
    stp_init();
    lldp_init();
    rstp_init();
    ifaces_changed = seq_create();
    last_ifaces_changed = seq_read(ifaces_changed);
    ifnotifier = if_notifier_create(if_change_cb, NULL);
}

void
bridge_exit(bool delete_datapath)
{
    struct bridge *br, *next_br;

    if_notifier_destroy(ifnotifier);
    seq_destroy(ifaces_changed);
    HMAP_FOR_EACH_SAFE (br, next_br, node, &all_bridges) {
        bridge_destroy(br, delete_datapath);
    }
    ovsdb_idl_destroy(idl);
}

/* Looks at the list of managers in 'ovs_cfg' and extracts their remote IP
 * addresses and ports into '*managersp' and '*n_managersp'.  The caller is
 * responsible for freeing '*managersp' (with free()).
 *
 * You may be asking yourself "why does ovs-vswitchd care?", because
 * ovsdb-server is responsible for connecting to the managers, and ovs-vswitchd
 * should not be and in fact is not directly involved in that.  But
 * ovs-vswitchd needs to make sure that ovsdb-server can reach the managers, so
 * it has to tell in-band control where the managers are to enable that.
 * (Thus, only managers connected in-band and with non-loopback addresses
 * are collected.)
 */
static void
collect_in_band_managers(const struct ovsrec_open_vswitch *ovs_cfg,
                         struct sockaddr_in **managersp, size_t *n_managersp)
{
    struct sockaddr_in *managers = NULL;
    size_t n_managers = 0;
    struct sset targets;
    size_t i;

    /* Collect all of the potential targets from the "targets" columns of the
     * rows pointed to by "manager_options", excluding any that are
     * out-of-band. */
    sset_init(&targets);
    for (i = 0; i < ovs_cfg->n_manager_options; i++) {
        struct ovsrec_manager *m = ovs_cfg->manager_options[i];

        if (m->connection_mode && !strcmp(m->connection_mode, "out-of-band")) {
            sset_find_and_delete(&targets, m->target);
        } else {
            sset_add(&targets, m->target);
        }
    }

    /* Now extract the targets' IP addresses. */
    if (!sset_is_empty(&targets)) {
        const char *target;

        managers = xmalloc(sset_count(&targets) * sizeof *managers);
        SSET_FOR_EACH (target, &targets) {
            union {
                struct sockaddr_storage ss;
                struct sockaddr_in in;
            } sa;

            /* Ignore loopback. */
            if (stream_parse_target_with_default_port(target, OVSDB_PORT,
                                                      &sa.ss)
                && sa.ss.ss_family == AF_INET
                && sa.in.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                managers[n_managers++] = sa.in;
            }
        }
    }
    sset_destroy(&targets);

    *managersp = managers;
    *n_managersp = n_managers;
}

static void
config_ofproto_types(const struct smap *other_config)
{
    struct sset types;
    const char *type;

    /* Pass custom configuration to datapath types. */
    sset_init(&types);
    ofproto_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        ofproto_type_set_config(type, other_config);
    }
    sset_destroy(&types);
}

static void
bridge_reconfigure(const struct ovsrec_open_vswitch *ovs_cfg)
{
    struct sockaddr_in *managers;
    struct bridge *br, *next;
    int sflow_bridge_number;
    size_t n_managers;

    COVERAGE_INC(bridge_reconfigure);

    ofproto_set_flow_limit(smap_get_int(&ovs_cfg->other_config, "flow-limit",
                                        OFPROTO_FLOW_LIMIT_DEFAULT));
    ofproto_set_max_idle(smap_get_int(&ovs_cfg->other_config, "max-idle",
                                      OFPROTO_MAX_IDLE_DEFAULT));
    ofproto_set_vlan_limit(smap_get_int(&ovs_cfg->other_config, "vlan-limit",
                                       LEGACY_MAX_VLAN_HEADERS));
    ofproto_set_bundle_idle_timeout(smap_get_int(&ovs_cfg->other_config,
                                                 "bundle-idle-timeout", 0));
    ofproto_set_threads(
        smap_get_int(&ovs_cfg->other_config, "n-handler-threads", 0),
        smap_get_int(&ovs_cfg->other_config, "n-revalidator-threads", 0));

    /* Destroy "struct bridge"s, "struct port"s, and "struct iface"s according
     * to 'ovs_cfg', with only very minimal configuration otherwise.
     *
     * This is mostly an update to bridge data structures. Nothing is pushed
     * down to ofproto or lower layers. */
    add_del_bridges(ovs_cfg);
    HMAP_FOR_EACH (br, node, &all_bridges) {
        bridge_collect_wanted_ports(br, &br->wanted_ports);
        bridge_del_ports(br, &br->wanted_ports);
    }

    /* Start pushing configuration changes down to the ofproto layer:
     *
     *   - Delete ofprotos that are no longer configured.
     *
     *   - Delete ports that are no longer configured.
     *
     *   - Reconfigure existing ports to their desired configurations, or
     *     delete them if not possible.
     *
     * We have to do all the deletions before we can do any additions, because
     * the ports to be added might require resources that will be freed up by
     * deletions (they might especially overlap in name). */
    bridge_delete_ofprotos();
    HMAP_FOR_EACH (br, node, &all_bridges) {
        if (br->ofproto) {
            bridge_delete_or_reconfigure_ports(br);
        }
    }

    /* Finish pushing configuration changes to the ofproto layer:
     *
     *     - Create ofprotos that are missing.
     *
     *     - Add ports that are missing. */
    HMAP_FOR_EACH_SAFE (br, next, node, &all_bridges) {
        if (!br->ofproto) {
            int error;

            error = ofproto_create(br->name, br->type, &br->ofproto);
            if (error) {
                VLOG_ERR("failed to create bridge %s: %s", br->name,
                         ovs_strerror(error));
                shash_destroy(&br->wanted_ports);
                bridge_destroy(br, true);
            } else {
                /* Trigger storing datapath version. */
                seq_change(connectivity_seq_get());
            }
        }
    }

    config_ofproto_types(&ovs_cfg->other_config);

    HMAP_FOR_EACH (br, node, &all_bridges) {
        bridge_add_ports(br, &br->wanted_ports);
        shash_destroy(&br->wanted_ports);
    }

    reconfigure_system_stats(ovs_cfg);

    /* Complete the configuration. */
    sflow_bridge_number = 0;
    collect_in_band_managers(ovs_cfg, &managers, &n_managers);
    HMAP_FOR_EACH (br, node, &all_bridges) {
        struct port *port;

        /* We need the datapath ID early to allow LACP ports to use it as the
         * default system ID. */
        bridge_configure_datapath_id(br);

        HMAP_FOR_EACH (port, hmap_node, &br->ports) {
            struct iface *iface;

            port_configure(port);

            LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                iface_set_ofport(iface->cfg, iface->ofp_port);
                /* Clear eventual previous errors */
                ovsrec_interface_set_error(iface->cfg, NULL);
                iface_configure_cfm(iface);
                iface_configure_qos(iface, port->cfg->qos);
                iface_set_mac(br, port, iface);
                ofproto_port_set_bfd(br->ofproto, iface->ofp_port,
                                     &iface->cfg->bfd);
                ofproto_port_set_lldp(br->ofproto, iface->ofp_port,
                                      &iface->cfg->lldp);
                ofproto_port_set_config(br->ofproto, iface->ofp_port,
                                        &iface->cfg->other_config);
            }
        }
        bridge_configure_mirrors(br);
        bridge_configure_forward_bpdu(br);
        bridge_configure_mac_table(br);
        bridge_configure_mcast_snooping(br);
        bridge_configure_remotes(br, managers, n_managers);
        bridge_configure_netflow(br);
        bridge_configure_sflow(br, &sflow_bridge_number);
        bridge_configure_ipfix(br);
        bridge_configure_spanning_tree(br);
        bridge_configure_tables(br);
        bridge_configure_dp_desc(br);
        bridge_configure_aa(br);
    }
    free(managers);

    /* The ofproto-dpif provider does some final reconfiguration in its
     * ->type_run() function.  We have to call it before notifying the database
     * client that reconfiguration is complete, otherwise there is a very
     * narrow race window in which e.g. ofproto/trace will not recognize the
     * new configuration (sometimes this causes unit test failures). */
    bridge_run__();
}

/* Delete ofprotos which aren't configured or have the wrong type.  Create
 * ofprotos which don't exist but need to. */
static void
bridge_delete_ofprotos(void)
{
    struct bridge *br;
    struct sset names;
    struct sset types;
    const char *type;

    /* Delete ofprotos with no bridge or with the wrong type. */
    sset_init(&names);
    sset_init(&types);
    ofproto_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        const char *name;

        ofproto_enumerate_names(type, &names);
        SSET_FOR_EACH (name, &names) {
            br = bridge_lookup(name);
            if (!br || strcmp(type, br->type)) {
                ofproto_delete(name, type);
            }
        }
    }
    sset_destroy(&names);
    sset_destroy(&types);
}

static ofp_port_t *
add_ofp_port(ofp_port_t port, ofp_port_t *ports, size_t *n, size_t *allocated)
{
    if (*n >= *allocated) {
        ports = x2nrealloc(ports, allocated, sizeof *ports);
    }
    ports[(*n)++] = port;
    return ports;
}

/* Configures the MTU of 'netdev' based on the "mtu_request" column
 * in 'iface_cfg'. */
static int
iface_set_netdev_mtu(const struct ovsrec_interface *iface_cfg,
                     struct netdev *netdev)
{
    if (iface_cfg->n_mtu_request == 1) {
        /* The user explicitly asked for this MTU. */
        netdev_mtu_user_config(netdev, true);
        /* Try to set the MTU to the requested value. */
        return netdev_set_mtu(netdev, *iface_cfg->mtu_request);
    }

    /* The user didn't explicitly asked for any MTU. */
    netdev_mtu_user_config(netdev, false);
    return 0;
}

static void
bridge_delete_or_reconfigure_ports(struct bridge *br)
{
    struct ofproto_port ofproto_port;
    struct ofproto_port_dump dump;

    struct sset ofproto_ports;
    struct port *port, *port_next;

    /* List of "ofp_port"s to delete.  We make a list instead of deleting them
     * right away because ofproto implementations aren't necessarily able to
     * iterate through a changing list of ports in an entirely robust way. */
    ofp_port_t *del;
    size_t n, allocated;
    size_t i;

    del = NULL;
    n = allocated = 0;
    sset_init(&ofproto_ports);

    /* Main task: Iterate over the ports in 'br->ofproto' and remove the ports
     * that are not configured in the database.  (This commonly happens when
     * ports have been deleted, e.g. with "ovs-vsctl del-port".)
     *
     * Side tasks: Reconfigure the ports that are still in 'br'.  Delete ports
     * that have the wrong OpenFlow port number (and arrange to add them back
     * with the correct OpenFlow port number). */
    OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, br->ofproto) {
        ofp_port_t requested_ofp_port;
        struct iface *iface;

        sset_add(&ofproto_ports, ofproto_port.name);

        iface = iface_lookup(br, ofproto_port.name);
        if (!iface) {
            /* No such iface is configured, so we should delete this
             * ofproto_port.
             *
             * As a corner case exception, keep the port if it's a bond fake
             * interface. */
            if (bridge_has_bond_fake_iface(br, ofproto_port.name)
                && !strcmp(ofproto_port.type, "internal")) {
                continue;
            }
            goto delete;
        }

        const char *netdev_type = ofproto_port_open_type(br->ofproto,
                                                         iface->type);
        if (strcmp(ofproto_port.type, netdev_type)
            || netdev_set_config(iface->netdev, &iface->cfg->options, NULL)) {
            /* The interface is the wrong type or can't be configured.
             * Delete it. */
            goto delete;
        }

        iface_set_netdev_mtu(iface->cfg, iface->netdev);

        /* If the requested OpenFlow port for 'iface' changed, and it's not
         * already the correct port, then we might want to temporarily delete
         * this interface, so we can add it back again with the new OpenFlow
         * port number. */
        requested_ofp_port = iface_get_requested_ofp_port(iface->cfg);
        if (iface->ofp_port != OFPP_LOCAL &&
            requested_ofp_port != OFPP_NONE &&
            requested_ofp_port != iface->ofp_port) {
            ofp_port_t victim_request;
            struct iface *victim;

            /* Check for an existing OpenFlow port currently occupying
             * 'iface''s requested port number.  If there isn't one, then
             * delete this port.  Otherwise we need to consider further. */
            victim = iface_from_ofp_port(br, requested_ofp_port);
            if (!victim) {
                goto delete;
            }

            /* 'victim' is a port currently using 'iface''s requested port
             * number.  Unless 'victim' specifically requested that port
             * number, too, then we can delete both 'iface' and 'victim'
             * temporarily.  (We'll add both of them back again later with new
             * OpenFlow port numbers.)
             *
             * If 'victim' did request port number 'requested_ofp_port', just
             * like 'iface', then that's a configuration inconsistency that we
             * can't resolve.  We might as well let it keep its current port
             * number. */
            victim_request = iface_get_requested_ofp_port(victim->cfg);
            if (victim_request != requested_ofp_port) {
                del = add_ofp_port(victim->ofp_port, del, &n, &allocated);
                iface_destroy(victim);
                goto delete;
            }
        }

        /* Keep it. */
        continue;

    delete:
        iface_destroy(iface);
        del = add_ofp_port(ofproto_port.ofp_port, del, &n, &allocated);
    }
    for (i = 0; i < n; i++) {
        ofproto_port_del(br->ofproto, del[i]);
    }
    free(del);

    /* Iterate over this module's idea of interfaces in 'br'.  Remove any ports
     * that we didn't see when we iterated through the datapath, i.e. ports
     * that disappeared underneath use.  This is an unusual situation, but it
     * can happen in some cases:
     *
     *     - An admin runs a command like "ovs-dpctl del-port" (which is a bad
     *       idea but could happen).
     *
     *     - The port represented a device that disappeared, e.g. a tuntap
     *       device destroyed via "tunctl -d", a physical Ethernet device
     *       whose module was just unloaded via "rmmod", or a virtual NIC for a
     *       VM whose VM was just terminated. */
    HMAP_FOR_EACH_SAFE (port, port_next, hmap_node, &br->ports) {
        struct iface *iface, *iface_next;

        LIST_FOR_EACH_SAFE (iface, iface_next, port_elem, &port->ifaces) {
            if (!sset_contains(&ofproto_ports, iface->name)) {
                iface_destroy__(iface);
            }
        }

        if (ovs_list_is_empty(&port->ifaces)) {
            port_destroy(port);
        }
    }
    sset_destroy(&ofproto_ports);
}

static void
bridge_add_ports__(struct bridge *br, const struct shash *wanted_ports,
                   bool with_requested_port)
{
    struct shash_node *port_node;

    SHASH_FOR_EACH (port_node, wanted_ports) {
        const struct ovsrec_port *port_cfg = port_node->data;
        size_t i;

        for (i = 0; i < port_cfg->n_interfaces; i++) {
            const struct ovsrec_interface *iface_cfg = port_cfg->interfaces[i];
            ofp_port_t requested_ofp_port;

            requested_ofp_port = iface_get_requested_ofp_port(iface_cfg);
            if ((requested_ofp_port != OFPP_NONE) == with_requested_port) {
                struct iface *iface = iface_lookup(br, iface_cfg->name);

                if (!iface) {
                    iface_create(br, iface_cfg, port_cfg);
                }
            }
        }
    }
}

static void
bridge_add_ports(struct bridge *br, const struct shash *wanted_ports)
{
    /* First add interfaces that request a particular port number. */
    bridge_add_ports__(br, wanted_ports, true);

    /* Then add interfaces that want automatic port number assignment.
     * We add these afterward to avoid accidentally taking a specifically
     * requested port number. */
    bridge_add_ports__(br, wanted_ports, false);
}

static void
port_configure(struct port *port)
{
    const struct ovsrec_port *cfg = port->cfg;
    struct bond_settings bond_settings;
    struct lacp_settings lacp_settings;
    struct ofproto_bundle_settings s;
    struct iface *iface;

    /* Get name. */
    s.name = port->name;

    /* Get slaves. */
    s.n_slaves = 0;
    s.slaves = xmalloc(ovs_list_size(&port->ifaces) * sizeof *s.slaves);
    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
        s.slaves[s.n_slaves++] = iface->ofp_port;
    }

    /* Get VLAN tag. */
    s.vlan = -1;
    if (cfg->tag && *cfg->tag >= 0 && *cfg->tag <= 4095) {
        s.vlan = *cfg->tag;
    }

    /* Get VLAN trunks. */
    s.trunks = NULL;
    if (cfg->n_trunks) {
        s.trunks = vlan_bitmap_from_array(cfg->trunks, cfg->n_trunks);
    }

    s.cvlans = NULL;
    if (cfg->n_cvlans) {
        s.cvlans = vlan_bitmap_from_array(cfg->cvlans, cfg->n_cvlans);
    }

    /* Get VLAN mode. */
    if (cfg->vlan_mode) {
        if (!strcmp(cfg->vlan_mode, "access")) {
            s.vlan_mode = PORT_VLAN_ACCESS;
        } else if (!strcmp(cfg->vlan_mode, "trunk")) {
            s.vlan_mode = PORT_VLAN_TRUNK;
        } else if (!strcmp(cfg->vlan_mode, "native-tagged")) {
            s.vlan_mode = PORT_VLAN_NATIVE_TAGGED;
        } else if (!strcmp(cfg->vlan_mode, "native-untagged")) {
            s.vlan_mode = PORT_VLAN_NATIVE_UNTAGGED;
        } else if (!strcmp(cfg->vlan_mode, "dot1q-tunnel")) {
            s.vlan_mode = PORT_VLAN_DOT1Q_TUNNEL;
        } else {
            /* This "can't happen" because ovsdb-server should prevent it. */
            VLOG_WARN("port %s: unknown VLAN mode %s, falling "
                      "back to trunk mode", port->name, cfg->vlan_mode);
            s.vlan_mode = PORT_VLAN_TRUNK;
        }
    } else {
        if (s.vlan >= 0) {
            s.vlan_mode = PORT_VLAN_ACCESS;
            if (cfg->n_trunks || cfg->n_cvlans) {
                VLOG_WARN("port %s: ignoring trunks in favor of implicit vlan",
                          port->name);
            }
        } else {
            s.vlan_mode = PORT_VLAN_TRUNK;
        }
    }

    const char *qe = smap_get_def(&cfg->other_config, "qinq-ethtype", "");
    s.qinq_ethtype = (!strcmp(qe, "802.1q")
                      ? ETH_TYPE_VLAN_8021Q
                      : ETH_TYPE_VLAN_8021AD);

    s.use_priority_tags = smap_get_bool(&cfg->other_config, "priority-tags",
                                        false);

    /* Get LACP settings. */
    s.lacp = port_configure_lacp(port, &lacp_settings);
    if (s.lacp) {
        size_t i = 0;

        s.lacp_slaves = xmalloc(s.n_slaves * sizeof *s.lacp_slaves);
        LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
            iface_configure_lacp(iface, &s.lacp_slaves[i++]);
        }
    } else {
        s.lacp_slaves = NULL;
    }

    /* Get bond settings. */
    if (s.n_slaves > 1) {
        s.bond = &bond_settings;
        port_configure_bond(port, &bond_settings);
    } else {
        s.bond = NULL;
        LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
            netdev_set_miimon_interval(iface->netdev, 0);
        }
    }

    /* Protected port mode */
    s.protected = cfg->protected_;

    /* Register. */
    ofproto_bundle_register(port->bridge->ofproto, port, &s);

    /* Clean up. */
    free(s.cvlans);
    free(s.slaves);
    free(s.trunks);
    free(s.lacp_slaves);
}

/* Pick local port hardware address and datapath ID for 'br'. */
static void
bridge_configure_datapath_id(struct bridge *br)
{
    struct eth_addr ea;
    uint64_t dpid;
    struct iface *local_iface;
    struct iface *hw_addr_iface;
    char *dpid_string;

    bridge_pick_local_hw_addr(br, &ea, &hw_addr_iface);
    local_iface = iface_from_ofp_port(br, OFPP_LOCAL);
    if (local_iface) {
        int error = netdev_set_etheraddr(local_iface->netdev, ea);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_ERR_RL(&rl, "bridge %s: failed to set bridge "
                        "Ethernet address: %s",
                        br->name, ovs_strerror(error));
        }
    }
    br->ea = ea;

    dpid = bridge_pick_datapath_id(br, ea, hw_addr_iface);
    if (dpid != ofproto_get_datapath_id(br->ofproto)) {
        VLOG_INFO("bridge %s: using datapath ID %016"PRIx64, br->name, dpid);
        ofproto_set_datapath_id(br->ofproto, dpid);
    }

    dpid_string = xasprintf("%016"PRIx64, dpid);
    ovsrec_bridge_set_datapath_id(br->cfg, dpid_string);
    free(dpid_string);
}

/* Returns a bitmap of "enum ofputil_protocol"s that are allowed for use with
 * 'br'. */
static uint32_t
bridge_get_allowed_versions(struct bridge *br)
{
    if (!br->cfg->n_protocols) {
        return 0;
    }

    return ofputil_versions_from_strings(br->cfg->protocols,
                                         br->cfg->n_protocols);
}

/* Set NetFlow configuration on 'br'. */
static void
bridge_configure_netflow(struct bridge *br)
{
    struct ovsrec_netflow *cfg = br->cfg->netflow;
    struct netflow_options opts;

    if (!cfg) {
        ofproto_set_netflow(br->ofproto, NULL);
        return;
    }

    memset(&opts, 0, sizeof opts);

    /* Get default NetFlow configuration from datapath.
     * Apply overrides from 'cfg'. */
    ofproto_get_netflow_ids(br->ofproto, &opts.engine_type, &opts.engine_id);
    if (cfg->engine_type) {
        opts.engine_type = *cfg->engine_type;
    }
    if (cfg->engine_id) {
        opts.engine_id = *cfg->engine_id;
    }

    /* Configure active timeout interval. */
    opts.active_timeout = cfg->active_timeout;
    if (!opts.active_timeout) {
        opts.active_timeout = -1;
    } else if (opts.active_timeout < 0) {
        VLOG_WARN("bridge %s: active timeout interval set to negative "
                  "value, using default instead (%d seconds)", br->name,
                  NF_ACTIVE_TIMEOUT_DEFAULT);
        opts.active_timeout = -1;
    }

    /* Add engine ID to interface number to disambiguate bridgs? */
    opts.add_id_to_iface = cfg->add_id_to_interface;
    if (opts.add_id_to_iface) {
        if (opts.engine_id > 0x7f) {
            VLOG_WARN("bridge %s: NetFlow port mangling may conflict with "
                      "another vswitch, choose an engine id less than 128",
                      br->name);
        }
        if (hmap_count(&br->ports) > 508) {
            VLOG_WARN("bridge %s: NetFlow port mangling will conflict with "
                      "another port when more than 508 ports are used",
                      br->name);
        }
    }

    /* Collectors. */
    sset_init(&opts.collectors);
    sset_add_array(&opts.collectors, cfg->targets, cfg->n_targets);

    /* Configure. */
    if (ofproto_set_netflow(br->ofproto, &opts)) {
        VLOG_ERR("bridge %s: problem setting netflow collectors", br->name);
    }
    sset_destroy(&opts.collectors);
}

/* Set sFlow configuration on 'br'. */
static void
bridge_configure_sflow(struct bridge *br, int *sflow_bridge_number)
{
    const struct ovsrec_sflow *cfg = br->cfg->sflow;
    struct ovsrec_controller **controllers;
    struct ofproto_sflow_options oso;
    size_t n_controllers;
    size_t i;

    if (!cfg) {
        ofproto_set_sflow(br->ofproto, NULL);
        return;
    }

    memset(&oso, 0, sizeof oso);

    sset_init(&oso.targets);
    sset_add_array(&oso.targets, cfg->targets, cfg->n_targets);

    oso.sampling_rate = SFL_DEFAULT_SAMPLING_RATE;
    if (cfg->sampling) {
        oso.sampling_rate = *cfg->sampling;
    }

    oso.polling_interval = SFL_DEFAULT_POLLING_INTERVAL;
    if (cfg->polling) {
        oso.polling_interval = *cfg->polling;
    }

    oso.header_len = SFL_DEFAULT_HEADER_SIZE;
    if (cfg->header) {
        oso.header_len = *cfg->header;
    }

    oso.sub_id = (*sflow_bridge_number)++;
    oso.agent_device = cfg->agent;

    oso.control_ip = NULL;
    n_controllers = bridge_get_controllers(br, &controllers);
    for (i = 0; i < n_controllers; i++) {
        if (controllers[i]->local_ip) {
            oso.control_ip = controllers[i]->local_ip;
            break;
        }
    }
    ofproto_set_sflow(br->ofproto, &oso);

    sset_destroy(&oso.targets);
}

/* Returns whether a IPFIX row is valid. */
static bool
ovsrec_ipfix_is_valid(const struct ovsrec_ipfix *ipfix)
{
    return ipfix && ipfix->n_targets > 0;
}

/* Returns whether a Flow_Sample_Collector_Set row is valid. */
static bool
ovsrec_fscs_is_valid(const struct ovsrec_flow_sample_collector_set *fscs,
                     const struct bridge *br)
{
    return ovsrec_ipfix_is_valid(fscs->ipfix) && fscs->bridge == br->cfg;
}

/* Set IPFIX configuration on 'br'. */
static void
bridge_configure_ipfix(struct bridge *br)
{
    const struct ovsrec_ipfix *be_cfg = br->cfg->ipfix;
    bool valid_be_cfg = ovsrec_ipfix_is_valid(be_cfg);
    const struct ovsrec_flow_sample_collector_set *fe_cfg;
    struct ofproto_ipfix_bridge_exporter_options be_opts;
    struct ofproto_ipfix_flow_exporter_options *fe_opts = NULL;
    size_t n_fe_opts = 0;
    const char *virtual_obs_id;

    OVSREC_FLOW_SAMPLE_COLLECTOR_SET_FOR_EACH(fe_cfg, idl) {
        if (ovsrec_fscs_is_valid(fe_cfg, br)) {
            n_fe_opts++;
        }
    }

    if (!valid_be_cfg && n_fe_opts == 0) {
        ofproto_set_ipfix(br->ofproto, NULL, NULL, 0);
        return;
    }

    if (valid_be_cfg) {
        memset(&be_opts, 0, sizeof be_opts);

        sset_init(&be_opts.targets);
        sset_add_array(&be_opts.targets, be_cfg->targets, be_cfg->n_targets);

        if (be_cfg->sampling) {
            be_opts.sampling_rate = *be_cfg->sampling;
        } else {
            be_opts.sampling_rate = SFL_DEFAULT_SAMPLING_RATE;
        }
        if (be_cfg->obs_domain_id) {
            be_opts.obs_domain_id = *be_cfg->obs_domain_id;
        }
        if (be_cfg->obs_point_id) {
            be_opts.obs_point_id = *be_cfg->obs_point_id;
        }
        if (be_cfg->cache_active_timeout) {
            be_opts.cache_active_timeout = *be_cfg->cache_active_timeout;
        }
        if (be_cfg->cache_max_flows) {
            be_opts.cache_max_flows = *be_cfg->cache_max_flows;
        }

        be_opts.enable_tunnel_sampling = smap_get_bool(&be_cfg->other_config,
                                             "enable-tunnel-sampling", true);

        be_opts.enable_input_sampling = !smap_get_bool(&be_cfg->other_config,
                                              "enable-input-sampling", false);

        be_opts.enable_output_sampling = !smap_get_bool(&be_cfg->other_config,
                                              "enable-output-sampling", false);

        virtual_obs_id = smap_get(&be_cfg->other_config, "virtual_obs_id");
        be_opts.virtual_obs_id = nullable_xstrdup(virtual_obs_id);
    }

    if (n_fe_opts > 0) {
        struct ofproto_ipfix_flow_exporter_options *opts;
        fe_opts = xcalloc(n_fe_opts, sizeof *fe_opts);
        opts = fe_opts;
        OVSREC_FLOW_SAMPLE_COLLECTOR_SET_FOR_EACH(fe_cfg, idl) {
            if (ovsrec_fscs_is_valid(fe_cfg, br)) {
                opts->collector_set_id = fe_cfg->id;
                sset_init(&opts->targets);
                sset_add_array(&opts->targets, fe_cfg->ipfix->targets,
                               fe_cfg->ipfix->n_targets);
                opts->cache_active_timeout = fe_cfg->ipfix->cache_active_timeout
                    ? *fe_cfg->ipfix->cache_active_timeout : 0;
                opts->cache_max_flows = fe_cfg->ipfix->cache_max_flows
                    ? *fe_cfg->ipfix->cache_max_flows : 0;
                opts->enable_tunnel_sampling = smap_get_bool(
                                                   &fe_cfg->ipfix->other_config,
                                                  "enable-tunnel-sampling", true);
                virtual_obs_id = smap_get(&fe_cfg->ipfix->other_config,
                                          "virtual_obs_id");
                opts->virtual_obs_id = nullable_xstrdup(virtual_obs_id);
                opts++;
            }
        }
    }

    ofproto_set_ipfix(br->ofproto, valid_be_cfg ? &be_opts : NULL, fe_opts,
                      n_fe_opts);

    if (valid_be_cfg) {
        sset_destroy(&be_opts.targets);
        free(be_opts.virtual_obs_id);
    }

    if (n_fe_opts > 0) {
        struct ofproto_ipfix_flow_exporter_options *opts = fe_opts;
        size_t i;
        for (i = 0; i < n_fe_opts; i++) {
            sset_destroy(&opts->targets);
            free(opts->virtual_obs_id);
            opts++;
        }
        free(fe_opts);
    }
}

static void
port_configure_stp(const struct ofproto *ofproto, struct port *port,
                   struct ofproto_port_stp_settings *port_s,
                   int *port_num_counter, unsigned long *port_num_bitmap)
{
    const char *config_str;
    struct iface *iface;

    if (!smap_get_bool(&port->cfg->other_config, "stp-enable", true)) {
        port_s->enable = false;
        return;
    } else {
        port_s->enable = true;
    }

    /* STP over bonds is not supported. */
    if (!ovs_list_is_singleton(&port->ifaces)) {
        VLOG_ERR("port %s: cannot enable STP on bonds, disabling",
                 port->name);
        port_s->enable = false;
        return;
    }

    iface = CONTAINER_OF(ovs_list_front(&port->ifaces), struct iface, port_elem);

    /* Internal ports shouldn't participate in spanning tree, so
     * skip them. */
    if (!strcmp(iface->type, "internal")) {
        VLOG_DBG("port %s: disable STP on internal ports", port->name);
        port_s->enable = false;
        return;
    }

    /* STP on mirror output ports is not supported. */
    if (ofproto_is_mirror_output_bundle(ofproto, port)) {
        VLOG_DBG("port %s: disable STP on mirror ports", port->name);
        port_s->enable = false;
        return;
    }

    config_str = smap_get(&port->cfg->other_config, "stp-port-num");
    if (config_str) {
        unsigned long int port_num = strtoul(config_str, NULL, 0);
        int port_idx = port_num - 1;

        if (port_num < 1 || port_num > STP_MAX_PORTS) {
            VLOG_ERR("port %s: invalid stp-port-num", port->name);
            port_s->enable = false;
            return;
        }

        if (bitmap_is_set(port_num_bitmap, port_idx)) {
            VLOG_ERR("port %s: duplicate stp-port-num %lu, disabling",
                    port->name, port_num);
            port_s->enable = false;
            return;
        }
        bitmap_set1(port_num_bitmap, port_idx);
        port_s->port_num = port_idx;
    } else {
        if (*port_num_counter >= STP_MAX_PORTS) {
            VLOG_ERR("port %s: too many STP ports, disabling", port->name);
            port_s->enable = false;
            return;
        }

        port_s->port_num = (*port_num_counter)++;
    }

    config_str = smap_get(&port->cfg->other_config, "stp-path-cost");
    if (config_str) {
        port_s->path_cost = strtoul(config_str, NULL, 10);
    } else {
        enum netdev_features current;
        unsigned int mbps;

        netdev_get_features(iface->netdev, &current, NULL, NULL, NULL);
        mbps = netdev_features_to_bps(current, 100 * 1000 * 1000) / 1000000;
        port_s->path_cost = stp_convert_speed_to_cost(mbps);
    }

    config_str = smap_get(&port->cfg->other_config, "stp-port-priority");
    if (config_str) {
        port_s->priority = strtoul(config_str, NULL, 0);
    } else {
        port_s->priority = STP_DEFAULT_PORT_PRIORITY;
    }
}

static void
port_configure_rstp(const struct ofproto *ofproto, struct port *port,
        struct ofproto_port_rstp_settings *port_s, int *port_num_counter)
{
    const char *config_str;
    struct iface *iface;

    if (!smap_get_bool(&port->cfg->other_config, "rstp-enable", true)) {
        port_s->enable = false;
        return;
    } else {
        port_s->enable = true;
    }

    /* RSTP over bonds is not supported. */
    if (!ovs_list_is_singleton(&port->ifaces)) {
        VLOG_ERR("port %s: cannot enable RSTP on bonds, disabling",
                port->name);
        port_s->enable = false;
        return;
    }

    iface = CONTAINER_OF(ovs_list_front(&port->ifaces), struct iface, port_elem);

    /* Internal ports shouldn't participate in spanning tree, so
     * skip them. */
    if (!strcmp(iface->type, "internal")) {
        VLOG_DBG("port %s: disable RSTP on internal ports", port->name);
        port_s->enable = false;
        return;
    }

    /* RSTP on mirror output ports is not supported. */
    if (ofproto_is_mirror_output_bundle(ofproto, port)) {
        VLOG_DBG("port %s: disable RSTP on mirror ports", port->name);
        port_s->enable = false;
        return;
    }

    config_str = smap_get(&port->cfg->other_config, "rstp-port-num");
    if (config_str) {
        unsigned long int port_num = strtoul(config_str, NULL, 0);
        if (port_num < 1 || port_num > RSTP_MAX_PORTS) {
            VLOG_ERR("port %s: invalid rstp-port-num", port->name);
            port_s->enable = false;
            return;
        }
        port_s->port_num = port_num;
    } else {
        if (*port_num_counter >= RSTP_MAX_PORTS) {
            VLOG_ERR("port %s: too many RSTP ports, disabling", port->name);
            port_s->enable = false;
            return;
        }
        /* If rstp-port-num is not specified, use 0.
         * rstp_port_set_port_number() will look for the first free one. */
        port_s->port_num = 0;
    }

    /* Increment the port num counter, because we only support
     * RSTP_MAX_PORTS rstp ports. */
    (*port_num_counter)++;

    config_str = smap_get(&port->cfg->other_config, "rstp-path-cost");
    if (config_str) {
        port_s->path_cost = strtoul(config_str, NULL, 10);
    } else {
        enum netdev_features current;
        unsigned int mbps;

        netdev_get_features(iface->netdev, &current, NULL, NULL, NULL);
        mbps = netdev_features_to_bps(current, 100 * 1000 * 1000) / 1000000;
        port_s->path_cost = rstp_convert_speed_to_cost(mbps);
    }

    config_str = smap_get(&port->cfg->other_config, "rstp-port-priority");
    if (config_str) {
        port_s->priority = strtoul(config_str, NULL, 0);
    } else {
        port_s->priority = RSTP_DEFAULT_PORT_PRIORITY;
    }

    port_s->admin_p2p_mac_state = smap_get_ullong(
        &port->cfg->other_config, "rstp-admin-p2p-mac",
        RSTP_ADMIN_P2P_MAC_FORCE_TRUE);

    port_s->admin_port_state = smap_get_bool(&port->cfg->other_config,
                                             "rstp-admin-port-state", true);

    port_s->admin_edge_port = smap_get_bool(&port->cfg->other_config,
                                            "rstp-port-admin-edge", false);
    port_s->auto_edge = smap_get_bool(&port->cfg->other_config,
                                      "rstp-port-auto-edge", true);
    port_s->mcheck = smap_get_bool(&port->cfg->other_config,
                                   "rstp-port-mcheck", false);
}

/* Set spanning tree configuration on 'br'. */
static void
bridge_configure_stp(struct bridge *br, bool enable_stp)
{
    if (!enable_stp) {
        ofproto_set_stp(br->ofproto, NULL);
    } else {
        struct ofproto_stp_settings br_s;
        const char *config_str;
        struct port *port;
        int port_num_counter;
        unsigned long *port_num_bitmap;

        config_str = smap_get(&br->cfg->other_config, "stp-system-id");
        if (config_str) {
            struct eth_addr ea;

            if (eth_addr_from_string(config_str, &ea)) {
                br_s.system_id = eth_addr_to_uint64(ea);
            } else {
                br_s.system_id = eth_addr_to_uint64(br->ea);
                VLOG_ERR("bridge %s: invalid stp-system-id, defaulting "
                         "to "ETH_ADDR_FMT, br->name, ETH_ADDR_ARGS(br->ea));
            }
        } else {
            br_s.system_id = eth_addr_to_uint64(br->ea);
        }

        br_s.priority = smap_get_ullong(&br->cfg->other_config, "stp-priority",
                                        STP_DEFAULT_BRIDGE_PRIORITY);
        br_s.hello_time = smap_get_ullong(&br->cfg->other_config,
                                          "stp-hello-time",
                                          STP_DEFAULT_HELLO_TIME);

        br_s.max_age = smap_get_ullong(&br->cfg->other_config, "stp-max-age",
                                       STP_DEFAULT_MAX_AGE / 1000) * 1000;
        br_s.fwd_delay = smap_get_ullong(&br->cfg->other_config,
                                         "stp-forward-delay",
                                         STP_DEFAULT_FWD_DELAY / 1000) * 1000;

        /* Configure STP on the bridge. */
        if (ofproto_set_stp(br->ofproto, &br_s)) {
            VLOG_ERR("bridge %s: could not enable STP", br->name);
            return;
        }

        /* Users must either set the port number with the "stp-port-num"
         * configuration on all ports or none.  If manual configuration
         * is not done, then we allocate them sequentially. */
        port_num_counter = 0;
        port_num_bitmap = bitmap_allocate(STP_MAX_PORTS);
        HMAP_FOR_EACH (port, hmap_node, &br->ports) {
            struct ofproto_port_stp_settings port_s;
            struct iface *iface;

            port_configure_stp(br->ofproto, port, &port_s,
                               &port_num_counter, port_num_bitmap);

            /* As bonds are not supported, just apply configuration to
             * all interfaces. */
            LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                if (ofproto_port_set_stp(br->ofproto, iface->ofp_port,
                                         &port_s)) {
                    VLOG_ERR("port %s: could not enable STP", port->name);
                    continue;
                }
            }
        }

        if (bitmap_scan(port_num_bitmap, 1, 0, STP_MAX_PORTS) != STP_MAX_PORTS
                    && port_num_counter) {
            VLOG_ERR("bridge %s: must manually configure all STP port "
                     "IDs or none, disabling", br->name);
            ofproto_set_stp(br->ofproto, NULL);
        }
        bitmap_free(port_num_bitmap);
    }
}

static void
bridge_configure_rstp(struct bridge *br, bool enable_rstp)
{
    if (!enable_rstp) {
        ofproto_set_rstp(br->ofproto, NULL);
    } else {
        struct ofproto_rstp_settings br_s;
        const char *config_str;
        struct port *port;
        int port_num_counter;

        config_str = smap_get(&br->cfg->other_config, "rstp-address");
        if (config_str) {
            struct eth_addr ea;

            if (eth_addr_from_string(config_str, &ea)) {
                br_s.address = eth_addr_to_uint64(ea);
            }
            else {
                br_s.address = eth_addr_to_uint64(br->ea);
                VLOG_ERR("bridge %s: invalid rstp-address, defaulting "
                        "to "ETH_ADDR_FMT, br->name, ETH_ADDR_ARGS(br->ea));
            }
        }
        else {
            br_s.address = eth_addr_to_uint64(br->ea);
        }

        const struct smap *oc = &br->cfg->other_config;
        br_s.priority = smap_get_ullong(oc, "rstp-priority",
                                        RSTP_DEFAULT_PRIORITY);
        br_s.ageing_time = smap_get_ullong(oc, "rstp-ageing-time",
                                           RSTP_DEFAULT_AGEING_TIME);
        br_s.force_protocol_version = smap_get_ullong(
            oc, "rstp-force-protocol-version", FPV_DEFAULT);
        br_s.bridge_max_age = smap_get_ullong(oc, "rstp-max-age",
                                              RSTP_DEFAULT_BRIDGE_MAX_AGE);
        br_s.bridge_forward_delay = smap_get_ullong(
            oc, "rstp-forward-delay", RSTP_DEFAULT_BRIDGE_FORWARD_DELAY);
        br_s.transmit_hold_count = smap_get_ullong(
            oc, "rstp-transmit-hold-count", RSTP_DEFAULT_TRANSMIT_HOLD_COUNT);

        /* Configure RSTP on the bridge. */
        if (ofproto_set_rstp(br->ofproto, &br_s)) {
            VLOG_ERR("bridge %s: could not enable RSTP", br->name);
            return;
        }

        port_num_counter = 0;
        HMAP_FOR_EACH (port, hmap_node, &br->ports) {
            struct ofproto_port_rstp_settings port_s;
            struct iface *iface;

            port_configure_rstp(br->ofproto, port, &port_s,
                    &port_num_counter);

            /* As bonds are not supported, just apply configuration to
             * all interfaces. */
            LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                if (ofproto_port_set_rstp(br->ofproto, iface->ofp_port,
                            &port_s)) {
                    VLOG_ERR("port %s: could not enable RSTP", port->name);
                    continue;
                }
            }
        }
    }
}

static void
bridge_configure_spanning_tree(struct bridge *br)
{
    bool enable_rstp = br->cfg->rstp_enable;
    bool enable_stp = br->cfg->stp_enable;

    if (enable_rstp && enable_stp) {
        VLOG_WARN("%s: RSTP and STP are mutually exclusive but both are "
                  "configured; enabling RSTP", br->name);
        enable_stp = false;
    }

    bridge_configure_stp(br, enable_stp);
    bridge_configure_rstp(br, enable_rstp);
}

static bool
bridge_has_bond_fake_iface(const struct bridge *br, const char *name)
{
    const struct port *port = port_lookup(br, name);
    return port && port_is_bond_fake_iface(port);
}

static bool
port_is_bond_fake_iface(const struct port *port)
{
    return port->cfg->bond_fake_iface && !ovs_list_is_short(&port->ifaces);
}

static void
add_del_bridges(const struct ovsrec_open_vswitch *cfg)
{
    struct bridge *br, *next;
    struct shash_node *node;
    struct shash new_br;
    size_t i;

    /* Collect new bridges' names and types. */
    shash_init(&new_br);
    for (i = 0; i < cfg->n_bridges; i++) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        const struct ovsrec_bridge *br_cfg = cfg->bridges[i];

        if (strchr(br_cfg->name, '/') || strchr(br_cfg->name, '\\')) {
            /* Prevent remote ovsdb-server users from accessing arbitrary
             * directories, e.g. consider a bridge named "../../../etc/".
             *
             * Prohibiting "\" is only necessary on Windows but it's no great
             * loss elsewhere. */
            VLOG_WARN_RL(&rl, "ignoring bridge with invalid name \"%s\"",
                         br_cfg->name);
        } else if (!shash_add_once(&new_br, br_cfg->name, br_cfg)) {
            VLOG_WARN_RL(&rl, "bridge %s specified twice", br_cfg->name);
        }
    }

    /* Get rid of deleted bridges or those whose types have changed.
     * Update 'cfg' of bridges that still exist. */
    HMAP_FOR_EACH_SAFE (br, next, node, &all_bridges) {
        br->cfg = shash_find_data(&new_br, br->name);
        if (!br->cfg || strcmp(br->type, ofproto_normalize_type(
                                   br->cfg->datapath_type))) {
            bridge_destroy(br, true);
        }
    }

    /* Add new bridges. */
    SHASH_FOR_EACH(node, &new_br) {
        const struct ovsrec_bridge *br_cfg = node->data;
        if (!bridge_lookup(br_cfg->name)) {
            bridge_create(br_cfg);
        }
    }

    shash_destroy(&new_br);
}

/* Configures 'netdev' based on the "options" column in 'iface_cfg'.
 * Returns 0 if successful, otherwise a positive errno value. */
static int
iface_set_netdev_config(const struct ovsrec_interface *iface_cfg,
                        struct netdev *netdev, char **errp)
{
    return netdev_set_config(netdev, &iface_cfg->options, errp);
}

/* Opens a network device for 'if_cfg' and configures it.  Adds the network
 * device to br->ofproto and stores the OpenFlow port number in '*ofp_portp'.
 *
 * If successful, returns 0 and stores the network device in '*netdevp'.  On
 * failure, returns a positive errno value and stores NULL in '*netdevp'. */
static int
iface_do_create(const struct bridge *br,
                const struct ovsrec_interface *iface_cfg,
                ofp_port_t *ofp_portp, struct netdev **netdevp,
                char **errp)
{
    struct netdev *netdev = NULL;
    int error;
    const char *type;

    if (netdev_is_reserved_name(iface_cfg->name)) {
        VLOG_WARN("could not create interface %s, name is reserved",
                  iface_cfg->name);
        error = EINVAL;
        goto error;
    }

    type = ofproto_port_open_type(br->ofproto,
                                  iface_get_type(iface_cfg, br->cfg));
    error = netdev_open(iface_cfg->name, type, &netdev);
    if (error) {
        VLOG_WARN_BUF(errp, "could not open network device %s (%s)",
                      iface_cfg->name, ovs_strerror(error));
        goto error;
    }

    error = iface_set_netdev_config(iface_cfg, netdev, errp);
    if (error) {
        goto error;
    }

    iface_set_netdev_mtu(iface_cfg, netdev);

    *ofp_portp = iface_pick_ofport(iface_cfg);
    error = ofproto_port_add(br->ofproto, netdev, ofp_portp);
    if (error) {
        VLOG_WARN_BUF(errp, "could not add network device %s to ofproto (%s)",
                      iface_cfg->name, ovs_strerror(error));
        goto error;
    }

    VLOG_INFO("bridge %s: added interface %s on port %d",
              br->name, iface_cfg->name, *ofp_portp);

    *netdevp = netdev;
    return 0;

error:
    *netdevp = NULL;
    netdev_close(netdev);
    return error;
}

/* Creates a new iface on 'br' based on 'if_cfg'.  The new iface has OpenFlow
 * port number 'ofp_port'.  If ofp_port is OFPP_NONE, an OpenFlow port is
 * automatically allocated for the iface.  Takes ownership of and
 * deallocates 'if_cfg'.
 *
 * Return true if an iface is successfully created, false otherwise. */
static bool
iface_create(struct bridge *br, const struct ovsrec_interface *iface_cfg,
             const struct ovsrec_port *port_cfg)
{
    struct netdev *netdev;
    struct iface *iface;
    ofp_port_t ofp_port;
    struct port *port;
    char *errp = NULL;
    int error;

    /* Do the bits that can fail up front. */
    ovs_assert(!iface_lookup(br, iface_cfg->name));
    error = iface_do_create(br, iface_cfg, &ofp_port, &netdev, &errp);
    if (error) {
        iface_clear_db_record(iface_cfg, errp);
        free(errp);
        return false;
    }

    /* Get or create the port structure. */
    port = port_lookup(br, port_cfg->name);
    if (!port) {
        port = port_create(br, port_cfg);
    }

    /* Create the iface structure. */
    iface = xzalloc(sizeof *iface);
    ovs_list_push_back(&port->ifaces, &iface->port_elem);
    hmap_insert(&br->iface_by_name, &iface->name_node,
                hash_string(iface_cfg->name, 0));
    iface->port = port;
    iface->name = xstrdup(iface_cfg->name);
    iface->ofp_port = ofp_port;
    iface->netdev = netdev;
    iface->type = iface_get_type(iface_cfg, br->cfg);
    iface->cfg = iface_cfg;
    hmap_insert(&br->ifaces, &iface->ofp_port_node,
                hash_ofp_port(ofp_port));

    /* Populate initial status in database. */
    iface_refresh_stats(iface);
    iface_refresh_netdev_status(iface);

    /* Add bond fake iface if necessary. */
    if (port_is_bond_fake_iface(port)) {
        struct ofproto_port ofproto_port;

        if (ofproto_port_query_by_name(br->ofproto, port->name,
                                       &ofproto_port)) {
            error = netdev_open(port->name, "internal", &netdev);
            if (!error) {
                ofp_port_t fake_ofp_port = OFPP_NONE;
                ofproto_port_add(br->ofproto, netdev, &fake_ofp_port);
                netdev_close(netdev);
            } else {
                VLOG_WARN("could not open network device %s (%s)",
                          port->name, ovs_strerror(error));
            }
        } else {
            /* Already exists, nothing to do. */
            ofproto_port_destroy(&ofproto_port);
        }
    }

    return true;
}

/* Set forward BPDU option. */
static void
bridge_configure_forward_bpdu(struct bridge *br)
{
    ofproto_set_forward_bpdu(br->ofproto,
                             smap_get_bool(&br->cfg->other_config,
                                           "forward-bpdu",
                                           false));
}

/* Set MAC learning table configuration for 'br'. */
static void
bridge_configure_mac_table(struct bridge *br)
{
    const struct smap *oc = &br->cfg->other_config;
    int idle_time = smap_get_int(oc, "mac-aging-time", 0);
    if (!idle_time) {
        idle_time = MAC_ENTRY_DEFAULT_IDLE_TIME;
    }

    int mac_table_size = smap_get_int(oc, "mac-table-size", 0);
    if (!mac_table_size) {
        mac_table_size = MAC_DEFAULT_MAX;
    }

    ofproto_set_mac_table_config(br->ofproto, idle_time, mac_table_size);
}

/* Set multicast snooping table configuration for 'br'. */
static void
bridge_configure_mcast_snooping(struct bridge *br)
{
    if (!br->cfg->mcast_snooping_enable) {
        ofproto_set_mcast_snooping(br->ofproto, NULL);
    } else {
        struct port *port;
        struct ofproto_mcast_snooping_settings br_s;

        const struct smap *oc = &br->cfg->other_config;
        int idle_time = smap_get_int(oc, "mcast-snooping-aging-time", 0);
        br_s.idle_time = idle_time ? idle_time : MCAST_ENTRY_DEFAULT_IDLE_TIME;
        int max_entries = smap_get_int(oc, "mcast-snooping-table-size", 0);
        br_s.max_entries = (max_entries
                            ? max_entries
                            : MCAST_DEFAULT_MAX_ENTRIES);

        br_s.flood_unreg = !smap_get_bool(
            oc, "mcast-snooping-disable-flood-unregistered", false);

        /* Configure multicast snooping on the bridge */
        if (ofproto_set_mcast_snooping(br->ofproto, &br_s)) {
            VLOG_ERR("bridge %s: could not enable multicast snooping",
                     br->name);
            return;
        }

        HMAP_FOR_EACH (port, hmap_node, &br->ports) {
            struct ofproto_mcast_snooping_port_settings port_s;
            port_s.flood = smap_get_bool(&port->cfg->other_config,
                                       "mcast-snooping-flood", false);
            port_s.flood_reports = smap_get_bool(&port->cfg->other_config,
                                       "mcast-snooping-flood-reports", false);
            if (ofproto_port_set_mcast_snooping(br->ofproto, port, &port_s)) {
                VLOG_ERR("port %s: could not configure mcast snooping",
                         port->name);
            }
        }
    }
}

static void
find_local_hw_addr(const struct bridge *br, struct eth_addr *ea,
                   const struct port *fake_br, struct iface **hw_addr_iface)
{
    struct hmapx mirror_output_ports;
    struct port *port;
    bool found_addr = false;
    int error;
    int i;

    /* Mirror output ports don't participate in picking the local hardware
     * address.  ofproto can't help us find out whether a given port is a
     * mirror output because we haven't configured mirrors yet, so we need to
     * accumulate them ourselves. */
    hmapx_init(&mirror_output_ports);
    for (i = 0; i < br->cfg->n_mirrors; i++) {
        struct ovsrec_mirror *m = br->cfg->mirrors[i];
        if (m->output_port) {
            hmapx_add(&mirror_output_ports, m->output_port);
        }
    }

    /* Otherwise choose the minimum non-local MAC address among all of the
     * interfaces. */
    HMAP_FOR_EACH (port, hmap_node, &br->ports) {
        struct eth_addr iface_ea;
        struct iface *candidate;
        struct iface *iface;

        /* Mirror output ports don't participate. */
        if (hmapx_contains(&mirror_output_ports, port->cfg)) {
            continue;
        }

        /* Choose the MAC address to represent the port. */
        iface = NULL;
        if (port->cfg->mac && eth_addr_from_string(port->cfg->mac,
                                                   &iface_ea)) {
            /* Find the interface with this Ethernet address (if any) so that
             * we can provide the correct devname to the caller. */
            LIST_FOR_EACH (candidate, port_elem, &port->ifaces) {
                struct eth_addr candidate_ea;
                if (!netdev_get_etheraddr(candidate->netdev, &candidate_ea)
                    && eth_addr_equals(iface_ea, candidate_ea)) {
                    iface = candidate;
                }
            }
        } else {
            /* Choose the interface whose MAC address will represent the port.
             * The Linux kernel bonding code always chooses the MAC address of
             * the first slave added to a bond, and the Fedora networking
             * scripts always add slaves to a bond in alphabetical order, so
             * for compatibility we choose the interface with the name that is
             * first in alphabetical order. */
            LIST_FOR_EACH (candidate, port_elem, &port->ifaces) {
                if (!iface || strcmp(candidate->name, iface->name) < 0) {
                    iface = candidate;
                }
            }

            /* A port always has at least one interface. */
            ovs_assert(iface != NULL);

            /* The local port doesn't count (since we're trying to choose its
             * MAC address anyway). */
            if (iface->ofp_port == OFPP_LOCAL) {
                continue;
            }

            /* For fake bridges we only choose from ports with the same tag */
            if (fake_br && fake_br->cfg && fake_br->cfg->tag) {
                if (!port->cfg->tag) {
                    continue;
                }
                if (*port->cfg->tag != *fake_br->cfg->tag) {
                    continue;
                }
            }

            /* Grab MAC. */
            error = netdev_get_etheraddr(iface->netdev, &iface_ea);
            if (error) {
                continue;
            }
        }

        /* Compare against our current choice. */
        if (!eth_addr_is_multicast(iface_ea) &&
            !eth_addr_is_local(iface_ea) &&
            !eth_addr_is_reserved(iface_ea) &&
            !eth_addr_is_zero(iface_ea) &&
            (!found_addr || eth_addr_compare_3way(iface_ea, *ea) < 0))
        {
            *ea = iface_ea;
            *hw_addr_iface = iface;
            found_addr = true;
        }
    }

    if (!found_addr) {
        *ea = br->default_ea;
        *hw_addr_iface = NULL;
    }

    hmapx_destroy(&mirror_output_ports);
}

static void
bridge_pick_local_hw_addr(struct bridge *br, struct eth_addr *ea,
                          struct iface **hw_addr_iface)
{
    *hw_addr_iface = NULL;

    /* Did the user request a particular MAC? */
    const char *hwaddr = smap_get_def(&br->cfg->other_config, "hwaddr", "");
    if (eth_addr_from_string(hwaddr, ea)) {
        if (eth_addr_is_multicast(*ea)) {
            VLOG_ERR("bridge %s: cannot set MAC address to multicast "
                     "address "ETH_ADDR_FMT, br->name, ETH_ADDR_ARGS(*ea));
        } else if (eth_addr_is_zero(*ea)) {
            VLOG_ERR("bridge %s: cannot set MAC address to zero", br->name);
        } else {
            return;
        }
    }

    /* Find a local hw address */
    find_local_hw_addr(br, ea, NULL, hw_addr_iface);
}

/* Choose and returns the datapath ID for bridge 'br' given that the bridge
 * Ethernet address is 'bridge_ea'.  If 'bridge_ea' is the Ethernet address of
 * an interface on 'br', then that interface must be passed in as
 * 'hw_addr_iface'; if 'bridge_ea' was derived some other way, then
 * 'hw_addr_iface' must be passed in as a null pointer. */
static uint64_t
bridge_pick_datapath_id(struct bridge *br,
                        const struct eth_addr bridge_ea,
                        struct iface *hw_addr_iface)
{
    /*
     * The procedure for choosing a bridge MAC address will, in the most
     * ordinary case, also choose a unique MAC that we can use as a datapath
     * ID.  In some special cases, though, multiple bridges will end up with
     * the same MAC address.  This is OK for the bridges, but it will confuse
     * the OpenFlow controller, because each datapath needs a unique datapath
     * ID.
     *
     * Datapath IDs must be unique.  It is also very desirable that they be
     * stable from one run to the next, so that policy set on a datapath
     * "sticks".
     */
    const char *datapath_id;
    uint64_t dpid;

    datapath_id = smap_get_def(&br->cfg->other_config, "datapath-id", "");
    if (dpid_from_string(datapath_id, &dpid)) {
        return dpid;
    }

    if (!hw_addr_iface) {
        /*
         * A purely internal bridge, that is, one that has no non-virtual
         * network devices on it at all, is difficult because it has no
         * natural unique identifier at all.
         *
         * When the host is a XenServer, we handle this case by hashing the
         * host's UUID with the name of the bridge.  Names of bridges are
         * persistent across XenServer reboots, although they can be reused if
         * an internal network is destroyed and then a new one is later
         * created, so this is fairly effective.
         *
         * When the host is not a XenServer, we punt by using a random MAC
         * address on each run.
         */
        const char *host_uuid = xenserver_get_host_uuid();
        if (host_uuid) {
            char *combined = xasprintf("%s,%s", host_uuid, br->name);
            dpid = dpid_from_hash(combined, strlen(combined));
            free(combined);
            return dpid;
        }
    }

    return eth_addr_to_uint64(bridge_ea);
}

static uint64_t
dpid_from_hash(const void *data, size_t n)
{
    union {
        uint8_t bytes[SHA1_DIGEST_SIZE];
        struct eth_addr ea;
    } hash;

    sha1_bytes(data, n, hash.bytes);
    eth_addr_mark_random(&hash.ea);
    return eth_addr_to_uint64(hash.ea);
}

static void
iface_refresh_netdev_status(struct iface *iface)
{
    struct smap smap;

    enum netdev_features current;
    enum netdev_flags flags;
    const char *link_state;
    struct eth_addr mac;
    int64_t bps, mtu_64, ifindex64, link_resets;
    int mtu, error;

    if (iface_is_synthetic(iface)) {
        return;
    }

    if (iface->change_seq == netdev_get_change_seq(iface->netdev)
        && !status_txn_try_again) {
        return;
    }

    iface->change_seq = netdev_get_change_seq(iface->netdev);

    smap_init(&smap);

    if (!netdev_get_status(iface->netdev, &smap)) {
        ovsrec_interface_set_status(iface->cfg, &smap);
    } else {
        ovsrec_interface_set_status(iface->cfg, NULL);
    }

    smap_destroy(&smap);

    error = netdev_get_flags(iface->netdev, &flags);
    if (!error) {
        const char *state = flags & NETDEV_UP ? "up" : "down";

        ovsrec_interface_set_admin_state(iface->cfg, state);
    } else {
        ovsrec_interface_set_admin_state(iface->cfg, NULL);
    }

    link_state = netdev_get_carrier(iface->netdev) ? "up" : "down";
    ovsrec_interface_set_link_state(iface->cfg, link_state);

    link_resets = netdev_get_carrier_resets(iface->netdev);
    ovsrec_interface_set_link_resets(iface->cfg, &link_resets, 1);

    error = netdev_get_features(iface->netdev, &current, NULL, NULL, NULL);
    bps = !error ? netdev_features_to_bps(current, 0) : 0;
    if (bps) {
        ovsrec_interface_set_duplex(iface->cfg,
                                    netdev_features_is_full_duplex(current)
                                    ? "full" : "half");
        ovsrec_interface_set_link_speed(iface->cfg, &bps, 1);
    } else {
        ovsrec_interface_set_duplex(iface->cfg, NULL);
        ovsrec_interface_set_link_speed(iface->cfg, NULL, 0);
    }

    error = netdev_get_mtu(iface->netdev, &mtu);
    if (!error) {
        mtu_64 = mtu;
        ovsrec_interface_set_mtu(iface->cfg, &mtu_64, 1);
    } else {
        ovsrec_interface_set_mtu(iface->cfg, NULL, 0);
    }

    error = netdev_get_etheraddr(iface->netdev, &mac);
    if (!error) {
        char mac_string[ETH_ADDR_STRLEN + 1];

        snprintf(mac_string, sizeof mac_string,
                 ETH_ADDR_FMT, ETH_ADDR_ARGS(mac));
        ovsrec_interface_set_mac_in_use(iface->cfg, mac_string);
    } else {
        ovsrec_interface_set_mac_in_use(iface->cfg, NULL);
    }

    /* The netdev may return a negative number (such as -EOPNOTSUPP)
     * if there is no valid ifindex number. */
    ifindex64 = netdev_get_ifindex(iface->netdev);
    if (ifindex64 < 0) {
        ifindex64 = 0;
    }
    ovsrec_interface_set_ifindex(iface->cfg, &ifindex64, 1);
}

static void
iface_refresh_ofproto_status(struct iface *iface)
{
    int current;

    if (iface_is_synthetic(iface)) {
        return;
    }

    current = ofproto_port_is_lacp_current(iface->port->bridge->ofproto,
                                           iface->ofp_port);
    if (current >= 0) {
        bool bl = current;
        ovsrec_interface_set_lacp_current(iface->cfg, &bl, 1);
    } else {
        ovsrec_interface_set_lacp_current(iface->cfg, NULL, 0);
    }

    if (ofproto_port_cfm_status_changed(iface->port->bridge->ofproto,
                                        iface->ofp_port)
        || status_txn_try_again) {
        iface_refresh_cfm_stats(iface);
    }

    if (ofproto_port_bfd_status_changed(iface->port->bridge->ofproto,
                                        iface->ofp_port)
        || status_txn_try_again) {
        struct smap smap;

        smap_init(&smap);
        ofproto_port_get_bfd_status(iface->port->bridge->ofproto,
                                    iface->ofp_port, &smap);
        ovsrec_interface_set_bfd_status(iface->cfg, &smap);
        smap_destroy(&smap);
    }
}

/* Writes 'iface''s CFM statistics to the database. 'iface' must not be
 * synthetic. */
static void
iface_refresh_cfm_stats(struct iface *iface)
{
    const struct ovsrec_interface *cfg = iface->cfg;
    struct cfm_status status;
    int error;

    error = ofproto_port_get_cfm_status(iface->port->bridge->ofproto,
                                        iface->ofp_port, &status);
    if (error > 0) {
        ovsrec_interface_set_cfm_fault(cfg, NULL, 0);
        ovsrec_interface_set_cfm_fault_status(cfg, NULL, 0);
        ovsrec_interface_set_cfm_remote_opstate(cfg, NULL);
        ovsrec_interface_set_cfm_flap_count(cfg, NULL, 0);
        ovsrec_interface_set_cfm_health(cfg, NULL, 0);
        ovsrec_interface_set_cfm_remote_mpids(cfg, NULL, 0);
    } else {
        const char *reasons[CFM_FAULT_N_REASONS];
        int64_t cfm_health = status.health;
        int64_t cfm_flap_count = status.flap_count;
        bool faulted = status.faults != 0;
        size_t i, j;

        ovsrec_interface_set_cfm_fault(cfg, &faulted, 1);

        j = 0;
        for (i = 0; i < CFM_FAULT_N_REASONS; i++) {
            int reason = 1 << i;
            if (status.faults & reason) {
                reasons[j++] = cfm_fault_reason_to_str(reason);
            }
        }
        ovsrec_interface_set_cfm_fault_status(cfg, reasons, j);

        ovsrec_interface_set_cfm_flap_count(cfg, &cfm_flap_count, 1);

        if (status.remote_opstate >= 0) {
            const char *remote_opstate = status.remote_opstate ? "up" : "down";
            ovsrec_interface_set_cfm_remote_opstate(cfg, remote_opstate);
        } else {
            ovsrec_interface_set_cfm_remote_opstate(cfg, NULL);
        }

        ovsrec_interface_set_cfm_remote_mpids(cfg,
                                              (const int64_t *)status.rmps,
                                              status.n_rmps);
        if (cfm_health >= 0) {
            ovsrec_interface_set_cfm_health(cfg, &cfm_health, 1);
        } else {
            ovsrec_interface_set_cfm_health(cfg, NULL, 0);
        }

        free(status.rmps);
    }
}

static void
iface_refresh_stats(struct iface *iface)
{
    struct netdev_custom_stats custom_stats;
    struct netdev_stats stats;
    int n;
    uint32_t i, counters_size;

#define IFACE_STATS                             \
    IFACE_STAT(rx_packets,              "rx_packets")               \
    IFACE_STAT(tx_packets,              "tx_packets")               \
    IFACE_STAT(rx_bytes,                "rx_bytes")                 \
    IFACE_STAT(tx_bytes,                "tx_bytes")                 \
    IFACE_STAT(rx_dropped,              "rx_dropped")               \
    IFACE_STAT(tx_dropped,              "tx_dropped")               \
    IFACE_STAT(rx_errors,               "rx_errors")                \
    IFACE_STAT(tx_errors,               "tx_errors")                \
    IFACE_STAT(rx_frame_errors,         "rx_frame_err")             \
    IFACE_STAT(rx_over_errors,          "rx_over_err")              \
    IFACE_STAT(rx_crc_errors,           "rx_crc_err")               \
    IFACE_STAT(collisions,              "collisions")               \
    IFACE_STAT(rx_1_to_64_packets,      "rx_1_to_64_packets")       \
    IFACE_STAT(rx_65_to_127_packets,    "rx_65_to_127_packets")     \
    IFACE_STAT(rx_128_to_255_packets,   "rx_128_to_255_packets")    \
    IFACE_STAT(rx_256_to_511_packets,   "rx_256_to_511_packets")    \
    IFACE_STAT(rx_512_to_1023_packets,  "rx_512_to_1023_packets")   \
    IFACE_STAT(rx_1024_to_1522_packets, "rx_1024_to_1522_packets")  \
    IFACE_STAT(rx_1523_to_max_packets,  "rx_1523_to_max_packets")   \
    IFACE_STAT(tx_1_to_64_packets,      "tx_1_to_64_packets")       \
    IFACE_STAT(tx_65_to_127_packets,    "tx_65_to_127_packets")     \
    IFACE_STAT(tx_128_to_255_packets,   "tx_128_to_255_packets")    \
    IFACE_STAT(tx_256_to_511_packets,   "tx_256_to_511_packets")    \
    IFACE_STAT(tx_512_to_1023_packets,  "tx_512_to_1023_packets")   \
    IFACE_STAT(tx_1024_to_1522_packets, "tx_1024_to_1522_packets")  \
    IFACE_STAT(tx_1523_to_max_packets,  "tx_1523_to_max_packets")   \
    IFACE_STAT(tx_multicast_packets,    "tx_multicast_packets")     \
    IFACE_STAT(rx_broadcast_packets,    "rx_broadcast_packets")     \
    IFACE_STAT(tx_broadcast_packets,    "tx_broadcast_packets")     \
    IFACE_STAT(rx_undersized_errors,    "rx_undersized_errors")     \
    IFACE_STAT(rx_oversize_errors,      "rx_oversize_errors")       \
    IFACE_STAT(rx_fragmented_errors,    "rx_fragmented_errors")     \
    IFACE_STAT(rx_jabber_errors,        "rx_jabber_errors")

#define IFACE_STAT(MEMBER, NAME) + 1
    enum { N_IFACE_STATS = IFACE_STATS };
#undef IFACE_STAT

    if (iface_is_synthetic(iface)) {
        return;
    }

    netdev_get_custom_stats(iface->netdev, &custom_stats);

    counters_size = custom_stats.size + N_IFACE_STATS;
    int64_t *values = xmalloc(counters_size * sizeof(int64_t));
    const char **keys = xmalloc(counters_size * sizeof(char *));

    /* Intentionally ignore return value, since errors will set 'stats' to
     * all-1s, and we will deal with that correctly below. */
    netdev_get_stats(iface->netdev, &stats);

    /* Copy statistics into keys[] and values[]. */
    n = 0;
#define IFACE_STAT(MEMBER, NAME)                \
    if (stats.MEMBER != UINT64_MAX) {           \
        keys[n] = NAME;                         \
        values[n] = stats.MEMBER;               \
        n++;                                    \
    }
    IFACE_STATS;
#undef IFACE_STAT

    /* Copy custom statistics into keys[] and values[]. */
    if (custom_stats.size && custom_stats.counters) {
        for (i = 0 ; i < custom_stats.size ; i++) {
            values[n] = custom_stats.counters[i].value;
            keys[n] = custom_stats.counters[i].name;
            n++;
        }
    }

    ovs_assert(n <= counters_size);

    ovsrec_interface_set_statistics(iface->cfg, keys, values, n);
#undef IFACE_STATS

    free(values);
    free(keys);
    netdev_free_custom_stats_counters(&custom_stats);
}

static void
br_refresh_datapath_info(struct bridge *br)
{
    const char *version;

    version = (br->ofproto && br->ofproto->ofproto_class->get_datapath_version
               ? br->ofproto->ofproto_class->get_datapath_version(br->ofproto)
               : NULL);

    ovsrec_bridge_set_datapath_version(br->cfg,
                                       version ? version : "<unknown>");
}

static void
br_refresh_stp_status(struct bridge *br)
{
    struct smap smap = SMAP_INITIALIZER(&smap);
    struct ofproto *ofproto = br->ofproto;
    struct ofproto_stp_status status;

    if (ofproto_get_stp_status(ofproto, &status)) {
        return;
    }

    if (!status.enabled) {
        ovsrec_bridge_set_status(br->cfg, NULL);
        return;
    }

    smap_add_format(&smap, "stp_bridge_id", STP_ID_FMT,
                    STP_ID_ARGS(status.bridge_id));
    smap_add_format(&smap, "stp_designated_root", STP_ID_FMT,
                    STP_ID_ARGS(status.designated_root));
    smap_add_format(&smap, "stp_root_path_cost", "%d", status.root_path_cost);

    ovsrec_bridge_set_status(br->cfg, &smap);
    smap_destroy(&smap);
}

static void
port_refresh_stp_status(struct port *port)
{
    struct ofproto *ofproto = port->bridge->ofproto;
    struct iface *iface;
    struct ofproto_port_stp_status status;
    struct smap smap;

    if (port_is_synthetic(port)) {
        return;
    }

    /* STP doesn't currently support bonds. */
    if (!ovs_list_is_singleton(&port->ifaces)) {
        ovsrec_port_set_status(port->cfg, NULL);
        return;
    }

    iface = CONTAINER_OF(ovs_list_front(&port->ifaces), struct iface, port_elem);
    if (ofproto_port_get_stp_status(ofproto, iface->ofp_port, &status)) {
        return;
    }

    if (!status.enabled) {
        ovsrec_port_set_status(port->cfg, NULL);
        return;
    }

    /* Set Status column. */
    smap_init(&smap);
    smap_add_format(&smap, "stp_port_id", "%d", status.port_id);
    smap_add(&smap, "stp_state", stp_state_name(status.state));
    smap_add_format(&smap, "stp_sec_in_state", "%u", status.sec_in_state);
    smap_add(&smap, "stp_role", stp_role_name(status.role));
    ovsrec_port_set_status(port->cfg, &smap);
    smap_destroy(&smap);
}

static void
port_refresh_stp_stats(struct port *port)
{
    struct ofproto *ofproto = port->bridge->ofproto;
    struct iface *iface;
    struct ofproto_port_stp_stats stats;
    const char *keys[3];
    int64_t int_values[3];

    if (port_is_synthetic(port)) {
        return;
    }

    /* STP doesn't currently support bonds. */
    if (!ovs_list_is_singleton(&port->ifaces)) {
        return;
    }

    iface = CONTAINER_OF(ovs_list_front(&port->ifaces), struct iface, port_elem);
    if (ofproto_port_get_stp_stats(ofproto, iface->ofp_port, &stats)) {
        return;
    }

    if (!stats.enabled) {
        ovsrec_port_set_statistics(port->cfg, NULL, NULL, 0);
        return;
    }

    /* Set Statistics column. */
    keys[0] = "stp_tx_count";
    int_values[0] = stats.tx_count;
    keys[1] = "stp_rx_count";
    int_values[1] = stats.rx_count;
    keys[2] = "stp_error_count";
    int_values[2] = stats.error_count;

    ovsrec_port_set_statistics(port->cfg, keys, int_values,
                               ARRAY_SIZE(int_values));
}

static void
br_refresh_rstp_status(struct bridge *br)
{
    struct smap smap = SMAP_INITIALIZER(&smap);
    struct ofproto *ofproto = br->ofproto;
    struct ofproto_rstp_status status;

    if (ofproto_get_rstp_status(ofproto, &status)) {
        return;
    }
    if (!status.enabled) {
        ovsrec_bridge_set_rstp_status(br->cfg, NULL);
        return;
    }
    smap_add_format(&smap, "rstp_bridge_id", RSTP_ID_FMT,
                    RSTP_ID_ARGS(status.bridge_id));
    smap_add_format(&smap, "rstp_root_path_cost", "%"PRIu32,
                    status.root_path_cost);
    smap_add_format(&smap, "rstp_root_id", RSTP_ID_FMT,
                    RSTP_ID_ARGS(status.root_id));
    smap_add_format(&smap, "rstp_designated_id", RSTP_ID_FMT,
                    RSTP_ID_ARGS(status.designated_id));
    smap_add_format(&smap, "rstp_designated_port_id", RSTP_PORT_ID_FMT,
                    status.designated_port_id);
    smap_add_format(&smap, "rstp_bridge_port_id", RSTP_PORT_ID_FMT,
                    status.bridge_port_id);
    ovsrec_bridge_set_rstp_status(br->cfg, &smap);
    smap_destroy(&smap);
}

static void
port_refresh_rstp_status(struct port *port)
{
    struct ofproto *ofproto = port->bridge->ofproto;
    struct iface *iface;
    struct ofproto_port_rstp_status status;
    const char *keys[4];
    int64_t int_values[4];
    struct smap smap;

    if (port_is_synthetic(port)) {
        return;
    }

    /* RSTP doesn't currently support bonds. */
    if (!ovs_list_is_singleton(&port->ifaces)) {
        ovsrec_port_set_rstp_status(port->cfg, NULL);
        return;
    }

    iface = CONTAINER_OF(ovs_list_front(&port->ifaces), struct iface, port_elem);
    if (ofproto_port_get_rstp_status(ofproto, iface->ofp_port, &status)) {
        return;
    }

    if (!status.enabled) {
        ovsrec_port_set_rstp_status(port->cfg, NULL);
        ovsrec_port_set_rstp_statistics(port->cfg, NULL, NULL, 0);
        return;
    }
    /* Set Status column. */
    smap_init(&smap);

    smap_add_format(&smap, "rstp_port_id", RSTP_PORT_ID_FMT,
                    status.port_id);
    smap_add_format(&smap, "rstp_port_role", "%s",
                    rstp_port_role_name(status.role));
    smap_add_format(&smap, "rstp_port_state", "%s",
                    rstp_state_name(status.state));
    smap_add_format(&smap, "rstp_designated_bridge_id", RSTP_ID_FMT,
                    RSTP_ID_ARGS(status.designated_bridge_id));
    smap_add_format(&smap, "rstp_designated_port_id", RSTP_PORT_ID_FMT,
                    status.designated_port_id);
    smap_add_format(&smap, "rstp_designated_path_cost", "%"PRIu32,
                    status.designated_path_cost);

    ovsrec_port_set_rstp_status(port->cfg, &smap);
    smap_destroy(&smap);

    /* Set Statistics column. */
    keys[0] = "rstp_tx_count";
    int_values[0] = status.tx_count;
    keys[1] = "rstp_rx_count";
    int_values[1] = status.rx_count;
    keys[2] = "rstp_uptime";
    int_values[2] = status.uptime;
    keys[3] = "rstp_error_count";
    int_values[3] = status.error_count;
    ovsrec_port_set_rstp_statistics(port->cfg, keys, int_values,
            ARRAY_SIZE(int_values));
}

static void
port_refresh_bond_status(struct port *port, bool force_update)
{
    struct eth_addr mac;

    /* Return if port is not a bond */
    if (ovs_list_is_singleton(&port->ifaces)) {
        return;
    }

    if (bond_get_changed_active_slave(port->name, &mac, force_update)) {
        struct ds mac_s;

        ds_init(&mac_s);
        ds_put_format(&mac_s, ETH_ADDR_FMT, ETH_ADDR_ARGS(mac));
        ovsrec_port_set_bond_active_slave(port->cfg, ds_cstr(&mac_s));
        ds_destroy(&mac_s);
    }
}

static bool
enable_system_stats(const struct ovsrec_open_vswitch *cfg)
{
    return smap_get_bool(&cfg->other_config, "enable-statistics", false);
}

static void
reconfigure_system_stats(const struct ovsrec_open_vswitch *cfg)
{
    bool enable = enable_system_stats(cfg);

    system_stats_enable(enable);
    if (!enable) {
        ovsrec_open_vswitch_set_statistics(cfg, NULL);
    }
}

static void
run_system_stats(void)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(idl);
    struct smap *stats;

    stats = system_stats_run();
    if (stats && cfg) {
        struct ovsdb_idl_txn *txn;
        struct ovsdb_datum datum;

        txn = ovsdb_idl_txn_create(idl);
        ovsdb_datum_from_smap(&datum, stats);
        smap_destroy(stats);
        ovsdb_idl_txn_write(&cfg->header_, &ovsrec_open_vswitch_col_statistics,
                            &datum);
        ovsdb_idl_txn_commit(txn);
        ovsdb_idl_txn_destroy(txn);

        free(stats);
    }
}

static const char *
ofp12_controller_role_to_str(enum ofp12_controller_role role)
{
    switch (role) {
    case OFPCR12_ROLE_EQUAL:
        return "other";
    case OFPCR12_ROLE_MASTER:
        return "master";
    case OFPCR12_ROLE_SLAVE:
        return "slave";
    case OFPCR12_ROLE_NOCHANGE:
    default:
        return "*** INVALID ROLE ***";
    }
}

static void
refresh_controller_status(void)
{
    struct bridge *br;

    /* Accumulate status for controllers on all bridges. */
    HMAP_FOR_EACH (br, node, &all_bridges) {
        struct shash info = SHASH_INITIALIZER(&info);
        ofproto_get_ofproto_controller_info(br->ofproto, &info);

        /* Update each controller of the bridge in the database with
         * current status. */
        struct ovsrec_controller **controllers;
        size_t n_controllers = bridge_get_controllers(br, &controllers);
        size_t i;
        for (i = 0; i < n_controllers; i++) {
            struct ovsrec_controller *cfg = controllers[i];
            struct ofproto_controller_info *cinfo =
                shash_find_data(&info, cfg->target);

            /* cinfo is NULL when 'cfg->target' is a passive connection.  */
            if (cinfo) {
                ovsrec_controller_set_is_connected(cfg, cinfo->is_connected);
                const char *role = ofp12_controller_role_to_str(cinfo->role);
                ovsrec_controller_set_role(cfg, role);
                ovsrec_controller_set_status(cfg, &cinfo->pairs);
            } else {
                ovsrec_controller_set_is_connected(cfg, false);
                ovsrec_controller_set_role(cfg, NULL);
                ovsrec_controller_set_status(cfg, NULL);
            }
        }

        ofproto_free_ofproto_controller_info(&info);
    }
}

/* Update interface and mirror statistics if necessary. */
static void
run_stats_update(void)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(idl);
    int stats_interval;

    if (!cfg) {
        return;
    }

    /* Statistics update interval should always be greater than or equal to
     * 5000 ms. */
    stats_interval = MAX(smap_get_int(&cfg->other_config,
                                      "stats-update-interval",
                                      5000), 5000);
    if (stats_timer_interval != stats_interval) {
        stats_timer_interval = stats_interval;
        stats_timer = LLONG_MIN;
    }

    if (time_msec() >= stats_timer) {
        enum ovsdb_idl_txn_status status;

        /* Rate limit the update.  Do not start a new update if the
         * previous one is not done. */
        if (!stats_txn) {
            struct bridge *br;

            stats_txn = ovsdb_idl_txn_create(idl);
            HMAP_FOR_EACH (br, node, &all_bridges) {
                struct port *port;
                struct mirror *m;

                HMAP_FOR_EACH (port, hmap_node, &br->ports) {
                    struct iface *iface;

                    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                        iface_refresh_stats(iface);
                    }
                    port_refresh_stp_stats(port);
                }
                HMAP_FOR_EACH (m, hmap_node, &br->mirrors) {
                    mirror_refresh_stats(m);
                }
            }
            refresh_controller_status();
        }

        status = ovsdb_idl_txn_commit(stats_txn);
        if (status != TXN_INCOMPLETE) {
            stats_timer = time_msec() + stats_timer_interval;
            ovsdb_idl_txn_destroy(stats_txn);
            stats_txn = NULL;
        }
    }
}

static void
stats_update_wait(void)
{
    /* If the 'stats_txn' is non-null (transaction incomplete), waits for the
     * transaction to complete.  Otherwise, waits for the 'stats_timer'. */
    if (stats_txn) {
        ovsdb_idl_txn_wait(stats_txn);
    } else {
        poll_timer_wait_until(stats_timer);
    }
}

/* Update bridge/port/interface status if necessary. */
static void
run_status_update(void)
{
    if (!status_txn) {
        uint64_t seq;

        /* Rate limit the update.  Do not start a new update if the
         * previous one is not done. */
        seq = seq_read(connectivity_seq_get());
        if (seq != connectivity_seqno || status_txn_try_again) {
            const struct ovsrec_open_vswitch *cfg =
                ovsrec_open_vswitch_first(idl);
            struct bridge *br;

            connectivity_seqno = seq;
            status_txn = ovsdb_idl_txn_create(idl);
            dpdk_status(cfg);
            HMAP_FOR_EACH (br, node, &all_bridges) {
                struct port *port;

                br_refresh_stp_status(br);
                br_refresh_rstp_status(br);
                br_refresh_datapath_info(br);
                HMAP_FOR_EACH (port, hmap_node, &br->ports) {
                    struct iface *iface;

                    port_refresh_stp_status(port);
                    port_refresh_rstp_status(port);
                    port_refresh_bond_status(port, status_txn_try_again);
                    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                        iface_refresh_netdev_status(iface);
                        iface_refresh_ofproto_status(iface);
                    }
                }
            }
        }
    }

    /* Commit the transaction and get the status. If the transaction finishes,
     * then destroy the transaction. Otherwise, keep it so that we can check
     * progress the next time that this function is called. */
    if (status_txn) {
        enum ovsdb_idl_txn_status status;

        status = ovsdb_idl_txn_commit(status_txn);
        if (status != TXN_INCOMPLETE) {
            ovsdb_idl_txn_destroy(status_txn);
            status_txn = NULL;

            /* Sets the 'status_txn_try_again' if the transaction fails. */
            if (status == TXN_SUCCESS || status == TXN_UNCHANGED) {
                status_txn_try_again = false;
            } else {
                status_txn_try_again = true;
            }
        }
    }

    /* Refresh AA port status if necessary. */
    if (time_msec() >= aa_refresh_timer) {
        struct bridge *br;

        HMAP_FOR_EACH (br, node, &all_bridges) {
            if (bridge_aa_need_refresh(br)) {
                struct ovsdb_idl_txn *txn;

                txn = ovsdb_idl_txn_create(idl);
                bridge_aa_refresh_queued(br);
                ovsdb_idl_txn_commit(txn);
                ovsdb_idl_txn_destroy(txn);
            }
        }

        aa_refresh_timer = time_msec() + AA_REFRESH_INTERVAL;
    }
}

static void
status_update_wait(void)
{
    /* If the 'status_txn' is non-null (transaction incomplete), waits for the
     * transaction to complete.  If the status update to database needs to be
     * run again (transaction fails), registers a timeout in
     * 'STATUS_CHECK_AGAIN_MSEC'.  Otherwise, waits on the global connectivity
     * sequence number. */
    if (status_txn) {
        ovsdb_idl_txn_wait(status_txn);
    } else if (status_txn_try_again) {
        poll_timer_wait_until(time_msec() + STATUS_CHECK_AGAIN_MSEC);
    } else {
        seq_wait(connectivity_seq_get(), connectivity_seqno);
    }
}

static void
bridge_run__(void)
{
    struct bridge *br;
    struct sset types;
    const char *type;

    /* Let each datapath type do the work that it needs to do. */
    sset_init(&types);
    ofproto_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        ofproto_type_run(type);
    }
    sset_destroy(&types);

    /* Let each bridge do the work that it needs to do. */
    HMAP_FOR_EACH (br, node, &all_bridges) {
        ofproto_run(br->ofproto);
    }
}

void
bridge_run(void)
{
    static struct ovsrec_open_vswitch null_cfg;
    const struct ovsrec_open_vswitch *cfg;

    ovsrec_open_vswitch_init(&null_cfg);

    ovsdb_idl_run(idl);

    if_notifier_run();

    if (ovsdb_idl_is_lock_contended(idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        struct bridge *br, *next_br;

        VLOG_ERR_RL(&rl, "another ovs-vswitchd process is running, "
                    "disabling this process (pid %ld) until it goes away",
                    (long int) getpid());

        HMAP_FOR_EACH_SAFE (br, next_br, node, &all_bridges) {
            bridge_destroy(br, false);
        }
        /* Since we will not be running system_stats_run() in this process
         * with the current situation of multiple ovs-vswitchd daemons,
         * disable system stats collection. */
        system_stats_enable(false);
        return;
    } else if (!ovsdb_idl_has_lock(idl)
               || !ovsdb_idl_has_ever_connected(idl)) {
        /* Returns if not holding the lock or not done retrieving db
         * contents. */
        return;
    }
    cfg = ovsrec_open_vswitch_first(idl);

    if (cfg) {
        netdev_set_flow_api_enabled(&cfg->other_config);
        dpdk_init(&cfg->other_config);
    }

    /* Initialize the ofproto library.  This only needs to run once, but
     * it must be done after the configuration is set.  If the
     * initialization has already occurred, bridge_init_ofproto()
     * returns immediately. */
    bridge_init_ofproto(cfg);

    /* Once the value of flow-restore-wait is false, we no longer should
     * check its value from the database. */
    if (cfg && ofproto_get_flow_restore_wait()) {
        ofproto_set_flow_restore_wait(smap_get_bool(&cfg->other_config,
                                        "flow-restore-wait", false));
    }

    bridge_run__();

    /* Re-configure SSL.  We do this on every trip through the main loop,
     * instead of just when the database changes, because the contents of the
     * key and certificate files can change without the database changing.
     *
     * We do this before bridge_reconfigure() because that function might
     * initiate SSL connections and thus requires SSL to be configured. */
    if (cfg && cfg->ssl) {
        const struct ovsrec_ssl *ssl = cfg->ssl;

        stream_ssl_set_key_and_cert(ssl->private_key, ssl->certificate);
        stream_ssl_set_ca_cert_file(ssl->ca_cert, ssl->bootstrap_ca_cert);
    }

    if (ovsdb_idl_get_seqno(idl) != idl_seqno ||
        if_notifier_changed(ifnotifier)) {
        struct ovsdb_idl_txn *txn;

        idl_seqno = ovsdb_idl_get_seqno(idl);
        txn = ovsdb_idl_txn_create(idl);
        bridge_reconfigure(cfg ? cfg : &null_cfg);

        if (cfg) {
            ovsrec_open_vswitch_set_cur_cfg(cfg, cfg->next_cfg);
            discover_types(cfg);
        }

        /* If we are completing our initial configuration for this run
         * of ovs-vswitchd, then keep the transaction around to monitor
         * it for completion. */
        if (initial_config_done) {
            /* Always sets the 'status_txn_try_again' to check again,
             * in case that this transaction fails. */
            status_txn_try_again = true;
            ovsdb_idl_txn_commit(txn);
            ovsdb_idl_txn_destroy(txn);
        } else {
            initial_config_done = true;
            daemonize_txn = txn;
        }
    }

    if (daemonize_txn) {
        enum ovsdb_idl_txn_status status = ovsdb_idl_txn_commit(daemonize_txn);
        if (status != TXN_INCOMPLETE) {
            ovsdb_idl_txn_destroy(daemonize_txn);
            daemonize_txn = NULL;

            /* ovs-vswitchd has completed initialization, so allow the
             * process that forked us to exit successfully. */
            daemonize_complete();

            vlog_enable_async();

            VLOG_INFO_ONCE("%s (Open vSwitch) %s", program_name, VERSION);
        }
    }

    run_stats_update();
    run_status_update();
    run_system_stats();
}

void
bridge_wait(void)
{
    struct sset types;
    const char *type;

    ovsdb_idl_wait(idl);
    if (daemonize_txn) {
        ovsdb_idl_txn_wait(daemonize_txn);
    }

    if_notifier_wait();

    sset_init(&types);
    ofproto_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        ofproto_type_wait(type);
    }
    sset_destroy(&types);

    if (!hmap_is_empty(&all_bridges)) {
        struct bridge *br;

        HMAP_FOR_EACH (br, node, &all_bridges) {
            ofproto_wait(br->ofproto);
        }
        stats_update_wait();
        status_update_wait();
    }

    system_stats_wait();
}

/* Adds some memory usage statistics for bridges into 'usage', for use with
 * memory_report(). */
void
bridge_get_memory_usage(struct simap *usage)
{
    struct bridge *br;
    struct sset types;
    const char *type;

    sset_init(&types);
    ofproto_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        ofproto_type_get_memory_usage(type, usage);
    }
    sset_destroy(&types);

    HMAP_FOR_EACH (br, node, &all_bridges) {
        ofproto_get_memory_usage(br->ofproto, usage);
    }
}

/* QoS unixctl user interface functions. */

struct qos_unixctl_show_cbdata {
    struct ds *ds;
    struct iface *iface;
};

static void
qos_unixctl_show_queue(unsigned int queue_id,
                       const struct smap *details,
                       struct iface *iface,
                       struct ds *ds)
{
    struct netdev_queue_stats stats;
    struct smap_node *node;
    int error;

    ds_put_cstr(ds, "\n");
    if (queue_id) {
        ds_put_format(ds, "Queue %u:\n", queue_id);
    } else {
        ds_put_cstr(ds, "Default:\n");
    }

    SMAP_FOR_EACH (node, details) {
        ds_put_format(ds, "\t%s: %s\n", node->key, node->value);
    }

    error = netdev_get_queue_stats(iface->netdev, queue_id, &stats);
    if (!error) {
        if (stats.tx_packets != UINT64_MAX) {
            ds_put_format(ds, "\ttx_packets: %"PRIu64"\n", stats.tx_packets);
        }

        if (stats.tx_bytes != UINT64_MAX) {
            ds_put_format(ds, "\ttx_bytes: %"PRIu64"\n", stats.tx_bytes);
        }

        if (stats.tx_errors != UINT64_MAX) {
            ds_put_format(ds, "\ttx_errors: %"PRIu64"\n", stats.tx_errors);
        }
    } else {
        ds_put_format(ds, "\tFailed to get statistics for queue %u: %s",
                      queue_id, ovs_strerror(error));
    }
}

static void
qos_unixctl_show_types(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct sset types = SSET_INITIALIZER(&types);
    struct iface *iface;
    const char * types_name;
    int error;

    iface = iface_find(argv[1]);
    if (!iface) {
        unixctl_command_reply_error(conn, "no such interface");
        return;
    }

    error = netdev_get_qos_types(iface->netdev, &types);
    if (!error) {
        if (!sset_is_empty(&types)) {
            SSET_FOR_EACH (types_name, &types) {
                ds_put_format(&ds, "QoS type: %s\n", types_name);
            }
            unixctl_command_reply(conn, ds_cstr(&ds));
        } else {
            ds_put_format(&ds, "No QoS types supported for interface: %s\n",
                          iface->name);
            unixctl_command_reply(conn, ds_cstr(&ds));
        }
    } else {
        ds_put_format(&ds, "%s: failed to retrieve supported QoS types (%s)",
                      iface->name, ovs_strerror(error));
        unixctl_command_reply_error(conn, ds_cstr(&ds));
    }

    sset_destroy(&types);
    ds_destroy(&ds);
}

static void
qos_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct smap smap = SMAP_INITIALIZER(&smap);
    struct iface *iface;
    const char *type;
    struct smap_node *node;
    int error;

    iface = iface_find(argv[1]);
    if (!iface) {
        unixctl_command_reply_error(conn, "no such interface");
        return;
    }

    error = netdev_get_qos(iface->netdev, &type, &smap);
    if (!error) {
        if (*type != '\0') {
            struct netdev_queue_dump dump;
            struct smap details;
            unsigned int queue_id;

            ds_put_format(&ds, "QoS: %s %s\n", iface->name, type);

            SMAP_FOR_EACH (node, &smap) {
                ds_put_format(&ds, "%s: %s\n", node->key, node->value);
            }

            smap_init(&details);
            NETDEV_QUEUE_FOR_EACH (&queue_id, &details, &dump, iface->netdev) {
                qos_unixctl_show_queue(queue_id, &details, iface, &ds);
            }
            smap_destroy(&details);

            unixctl_command_reply(conn, ds_cstr(&ds));
        } else {
            ds_put_format(&ds, "QoS not configured on %s\n", iface->name);
            unixctl_command_reply(conn, ds_cstr(&ds));
        }
    } else {
        ds_put_format(&ds, "%s: failed to retrieve QOS configuration (%s)\n",
                      iface->name, ovs_strerror(error));
        unixctl_command_reply_error(conn, ds_cstr(&ds));
    }

    smap_destroy(&smap);
    ds_destroy(&ds);
}

/* Bridge reconfiguration functions. */
static void
bridge_create(const struct ovsrec_bridge *br_cfg)
{
    struct bridge *br;

    ovs_assert(!bridge_lookup(br_cfg->name));
    br = xzalloc(sizeof *br);

    br->name = xstrdup(br_cfg->name);
    br->type = xstrdup(ofproto_normalize_type(br_cfg->datapath_type));
    br->cfg = br_cfg;

    /* Derive the default Ethernet address from the bridge's UUID.  This should
     * be unique and it will be stable between ovs-vswitchd runs.  */
    memcpy(&br->default_ea, &br_cfg->header_.uuid, ETH_ADDR_LEN);
    eth_addr_mark_random(&br->default_ea);

    hmap_init(&br->ports);
    hmap_init(&br->ifaces);
    hmap_init(&br->iface_by_name);
    hmap_init(&br->mirrors);

    hmap_init(&br->mappings);
    hmap_insert(&all_bridges, &br->node, hash_string(br->name, 0));
}

static void
bridge_destroy(struct bridge *br, bool del)
{
    if (br) {
        struct mirror *mirror, *next_mirror;
        struct port *port, *next_port;

        HMAP_FOR_EACH_SAFE (port, next_port, hmap_node, &br->ports) {
            port_destroy(port);
        }
        HMAP_FOR_EACH_SAFE (mirror, next_mirror, hmap_node, &br->mirrors) {
            mirror_destroy(mirror);
        }

        hmap_remove(&all_bridges, &br->node);
        ofproto_destroy(br->ofproto, del);
        hmap_destroy(&br->ifaces);
        hmap_destroy(&br->ports);
        hmap_destroy(&br->iface_by_name);
        hmap_destroy(&br->mirrors);
        hmap_destroy(&br->mappings);
        free(br->name);
        free(br->type);
        free(br);
    }
}

static struct bridge *
bridge_lookup(const char *name)
{
    struct bridge *br;

    HMAP_FOR_EACH_WITH_HASH (br, node, hash_string(name, 0), &all_bridges) {
        if (!strcmp(br->name, name)) {
            return br;
        }
    }
    return NULL;
}

/* Handle requests for a listing of all flows known by the OpenFlow
 * stack, including those normally hidden. */
static void
bridge_unixctl_dump_flows(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[], void *aux OVS_UNUSED)
{
    struct bridge *br;
    struct ds results;

    br = bridge_lookup(argv[1]);
    if (!br) {
        unixctl_command_reply_error(conn, "Unknown bridge");
        return;
    }

    ds_init(&results);
    ofproto_get_all_flows(br->ofproto, &results);

    unixctl_command_reply(conn, ds_cstr(&results));
    ds_destroy(&results);
}

/* "bridge/reconnect [BRIDGE]": makes BRIDGE drop all of its controller
 * connections and reconnect.  If BRIDGE is not specified, then all bridges
 * drop their controller connections and reconnect. */
static void
bridge_unixctl_reconnect(struct unixctl_conn *conn, int argc,
                         const char *argv[], void *aux OVS_UNUSED)
{
    struct bridge *br;
    if (argc > 1) {
        br = bridge_lookup(argv[1]);
        if (!br) {
            unixctl_command_reply_error(conn,  "Unknown bridge");
            return;
        }
        ofproto_reconnect_controllers(br->ofproto);
    } else {
        HMAP_FOR_EACH (br, node, &all_bridges) {
            ofproto_reconnect_controllers(br->ofproto);
        }
    }
    unixctl_command_reply(conn, NULL);
}

static size_t
bridge_get_controllers(const struct bridge *br,
                       struct ovsrec_controller ***controllersp)
{
    struct ovsrec_controller **controllers;
    size_t n_controllers;

    controllers = br->cfg->controller;
    n_controllers = br->cfg->n_controller;

    if (n_controllers == 1 && !strcmp(controllers[0]->target, "none")) {
        controllers = NULL;
        n_controllers = 0;
    }

    if (controllersp) {
        *controllersp = controllers;
    }
    return n_controllers;
}

static void
bridge_collect_wanted_ports(struct bridge *br,
                            struct shash *wanted_ports)
{
    size_t i;

    shash_init(wanted_ports);

    for (i = 0; i < br->cfg->n_ports; i++) {
        const char *name = br->cfg->ports[i]->name;
        if (!shash_add_once(wanted_ports, name, br->cfg->ports[i])) {
            VLOG_WARN("bridge %s: %s specified twice as bridge port",
                      br->name, name);
        }
    }
    if (bridge_get_controllers(br, NULL)
        && !shash_find(wanted_ports, br->name)) {
        VLOG_WARN("bridge %s: no port named %s, synthesizing one",
                  br->name, br->name);

        ovsrec_interface_init(&br->synth_local_iface);
        ovsrec_port_init(&br->synth_local_port);

        br->synth_local_port.interfaces = &br->synth_local_ifacep;
        br->synth_local_port.n_interfaces = 1;
        br->synth_local_port.name = br->name;

        br->synth_local_iface.name = br->name;
        br->synth_local_iface.type = "internal";

        br->synth_local_ifacep = &br->synth_local_iface;

        shash_add(wanted_ports, br->name, &br->synth_local_port);
    }
}

/* Deletes "struct port"s and "struct iface"s under 'br' which aren't
 * consistent with 'br->cfg'.  Updates 'br->if_cfg_queue' with interfaces which
 * 'br' needs to complete its configuration. */
static void
bridge_del_ports(struct bridge *br, const struct shash *wanted_ports)
{
    struct shash_node *port_node;
    struct port *port, *next;

    /* Get rid of deleted ports.
     * Get rid of deleted interfaces on ports that still exist. */
    HMAP_FOR_EACH_SAFE (port, next, hmap_node, &br->ports) {
        port->cfg = shash_find_data(wanted_ports, port->name);
        if (!port->cfg) {
            port_destroy(port);
        } else {
            port_del_ifaces(port);
        }
    }

    /* Update iface->cfg and iface->type in interfaces that still exist. */
    SHASH_FOR_EACH (port_node, wanted_ports) {
        const struct ovsrec_port *port_rec = port_node->data;
        size_t i;

        for (i = 0; i < port_rec->n_interfaces; i++) {
            const struct ovsrec_interface *cfg = port_rec->interfaces[i];
            struct iface *iface = iface_lookup(br, cfg->name);
            const char *type = iface_get_type(cfg, br->cfg);

            if (iface) {
                iface->cfg = cfg;
                iface->type = type;
            } else {
                /* We will add new interfaces later. */
            }
        }
    }
}

/* Initializes 'oc' appropriately as a management service controller for
 * 'br'.
 *
 * The caller must free oc->target when it is no longer needed. */
static void
bridge_ofproto_controller_for_mgmt(const struct bridge *br,
                                   struct ofproto_controller *oc)
{
    oc->target = xasprintf("punix:%s/%s.mgmt", ovs_rundir(), br->name);
    oc->max_backoff = 0;
    oc->probe_interval = 60;
    oc->band = OFPROTO_OUT_OF_BAND;
    oc->rate_limit = 0;
    oc->burst_limit = 0;
    oc->enable_async_msgs = true;
    oc->dscp = 0;
}

/* Converts ovsrec_controller 'c' into an ofproto_controller in 'oc'.  */
static void
bridge_ofproto_controller_from_ovsrec(const struct ovsrec_controller *c,
                                      struct ofproto_controller *oc)
{
    int dscp;

    oc->target = c->target;
    oc->max_backoff = c->max_backoff ? *c->max_backoff / 1000 : 8;
    oc->probe_interval = c->inactivity_probe ? *c->inactivity_probe / 1000 : 5;
    oc->band = (!c->connection_mode || !strcmp(c->connection_mode, "in-band")
                ? OFPROTO_IN_BAND : OFPROTO_OUT_OF_BAND);
    oc->rate_limit = c->controller_rate_limit ? *c->controller_rate_limit : 0;
    oc->burst_limit = (c->controller_burst_limit
                       ? *c->controller_burst_limit : 0);
    oc->enable_async_msgs = (!c->enable_async_messages
                             || *c->enable_async_messages);
    dscp = smap_get_int(&c->other_config, "dscp", DSCP_DEFAULT);
    if (dscp < 0 || dscp > 63) {
        dscp = DSCP_DEFAULT;
    }
    oc->dscp = dscp;
}

/* Configures the IP stack for 'br''s local interface properly according to the
 * configuration in 'c'.  */
static void
bridge_configure_local_iface_netdev(struct bridge *br,
                                    struct ovsrec_controller *c)
{
    struct netdev *netdev;
    struct in_addr mask, gateway;

    struct iface *local_iface;
    struct in_addr ip;

    /* If there's no local interface or no IP address, give up. */
    local_iface = iface_from_ofp_port(br, OFPP_LOCAL);
    if (!local_iface || !c->local_ip || !ip_parse(c->local_ip, &ip.s_addr)) {
        return;
    }

    /* Bring up the local interface. */
    netdev = local_iface->netdev;
    netdev_turn_flags_on(netdev, NETDEV_UP, NULL);

    /* Configure the IP address and netmask. */
    if (!c->local_netmask
        || !ip_parse(c->local_netmask, &mask.s_addr)
        || !mask.s_addr) {
        mask.s_addr = guess_netmask(ip.s_addr);
    }
    if (!netdev_set_in4(netdev, ip, mask)) {
        VLOG_INFO("bridge %s: configured IP address "IP_FMT", netmask "IP_FMT,
                  br->name, IP_ARGS(ip.s_addr), IP_ARGS(mask.s_addr));
    }

    /* Configure the default gateway. */
    if (c->local_gateway
        && ip_parse(c->local_gateway, &gateway.s_addr)
        && gateway.s_addr) {
        if (!netdev_add_router(netdev, gateway)) {
            VLOG_INFO("bridge %s: configured gateway "IP_FMT,
                      br->name, IP_ARGS(gateway.s_addr));
        }
    }
}

/* Returns true if 'a' and 'b' are the same except that any number of slashes
 * in either string are treated as equal to any number of slashes in the other,
 * e.g. "x///y" is equal to "x/y".
 *
 * Also, if 'b_stoplen' bytes from 'b' are found to be equal to corresponding
 * bytes from 'a', the function considers this success.  Specify 'b_stoplen' as
 * SIZE_MAX to compare all of 'a' to all of 'b' rather than just a prefix of
 * 'b' against a prefix of 'a'.
 */
static bool
equal_pathnames(const char *a, const char *b, size_t b_stoplen)
{
    const char *b_start = b;
    for (;;) {
        if (b - b_start >= b_stoplen) {
            return true;
        } else if (*a != *b) {
            return false;
        } else if (*a == '/') {
            a += strspn(a, "/");
            b += strspn(b, "/");
        } else if (*a == '\0') {
            return true;
        } else {
            a++;
            b++;
        }
    }
}

static void
bridge_configure_remotes(struct bridge *br,
                         const struct sockaddr_in *managers, size_t n_managers)
{
    bool disable_in_band;

    struct ovsrec_controller **controllers;
    size_t n_controllers;

    enum ofproto_fail_mode fail_mode;

    struct ofproto_controller *ocs;
    size_t n_ocs;
    size_t i;

    /* Check if we should disable in-band control on this bridge. */
    disable_in_band = smap_get_bool(&br->cfg->other_config, "disable-in-band",
                                    false);

    /* Set OpenFlow queue ID for in-band control. */
    ofproto_set_in_band_queue(br->ofproto,
                              smap_get_int(&br->cfg->other_config,
                                           "in-band-queue", -1));

    if (disable_in_band) {
        ofproto_set_extra_in_band_remotes(br->ofproto, NULL, 0);
    } else {
        ofproto_set_extra_in_band_remotes(br->ofproto, managers, n_managers);
    }

    n_controllers = bridge_get_controllers(br, &controllers);

    ocs = xmalloc((n_controllers + 1) * sizeof *ocs);
    n_ocs = 0;

    bridge_ofproto_controller_for_mgmt(br, &ocs[n_ocs++]);
    for (i = 0; i < n_controllers; i++) {
        struct ovsrec_controller *c = controllers[i];

        if (daemon_should_self_confine()
            && (!strncmp(c->target, "punix:", 6)
            || !strncmp(c->target, "unix:", 5))) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            char *whitelist;

            if (!strncmp(c->target, "unix:", 5)) {
                /* Connect to a listening socket */
                whitelist = xasprintf("unix:%s/", ovs_rundir());
                if (strchr(c->target, '/') &&
                   !equal_pathnames(c->target, whitelist,
                     strlen(whitelist))) {
                    /* Absolute path specified, but not in ovs_rundir */
                    VLOG_ERR_RL(&rl, "bridge %s: Not connecting to socket "
                                  "controller \"%s\" due to possibility for "
                                  "remote exploit.  Instead, specify socket "
                                  "in whitelisted \"%s\" or connect to "
                                  "\"unix:%s/%s.mgmt\" (which is always "
                                  "available without special configuration).",
                                  br->name, c->target, whitelist,
                                  ovs_rundir(), br->name);
                    free(whitelist);
                    continue;
                }
            } else {
               whitelist = xasprintf("punix:%s/%s.",
                                     ovs_rundir(), br->name);
               if (!equal_pathnames(c->target, whitelist, strlen(whitelist))
                   || strchr(c->target + strlen(whitelist), '/')) {
                   /* Prevent remote ovsdb-server users from accessing
                    * arbitrary Unix domain sockets and overwriting arbitrary
                    * local files. */
                   VLOG_ERR_RL(&rl, "bridge %s: Not adding Unix domain socket "
                                  "controller \"%s\" due to possibility of "
                                  "overwriting local files. Instead, specify "
                                  "path in whitelisted format \"%s*\" or "
                                  "connect to \"unix:%s/%s.mgmt\" (which is "
                                  "always available without special "
                                  "configuration).",
                                  br->name, c->target, whitelist,
                                  ovs_rundir(), br->name);
                   free(whitelist);
                   continue;
               }
            }

            free(whitelist);
        }

        bridge_configure_local_iface_netdev(br, c);
        bridge_ofproto_controller_from_ovsrec(c, &ocs[n_ocs]);
        if (disable_in_band) {
            ocs[n_ocs].band = OFPROTO_OUT_OF_BAND;
        }
        n_ocs++;
    }

    ofproto_set_controllers(br->ofproto, ocs, n_ocs,
                            bridge_get_allowed_versions(br));
    free(ocs[0].target); /* From bridge_ofproto_controller_for_mgmt(). */
    free(ocs);

    /* Set the fail-mode. */
    fail_mode = !br->cfg->fail_mode
                || !strcmp(br->cfg->fail_mode, "standalone")
                    ? OFPROTO_FAIL_STANDALONE
                    : OFPROTO_FAIL_SECURE;
    ofproto_set_fail_mode(br->ofproto, fail_mode);

    /* Configure OpenFlow controller connection snooping. */
    if (!ofproto_has_snoops(br->ofproto)) {
        struct sset snoops;

        sset_init(&snoops);
        sset_add_and_free(&snoops, xasprintf("punix:%s/%s.snoop",
                                             ovs_rundir(), br->name));
        ofproto_set_snoops(br->ofproto, &snoops);
        sset_destroy(&snoops);
    }
}

static void
bridge_configure_tables(struct bridge *br)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    int n_tables;
    int i, j;

    n_tables = ofproto_get_n_tables(br->ofproto);
    j = 0;
    for (i = 0; i < n_tables; i++) {
        struct ofproto_table_settings s;
        bool use_default_prefixes = true;

        s.name = NULL;
        s.max_flows = UINT_MAX;
        s.groups = NULL;
        s.enable_eviction = false;
        s.n_groups = 0;
        s.n_prefix_fields = 0;
        memset(s.prefix_fields, ~0, sizeof(s.prefix_fields));

        if (j < br->cfg->n_flow_tables && i == br->cfg->key_flow_tables[j]) {
            struct ovsrec_flow_table *cfg = br->cfg->value_flow_tables[j++];

            s.name = cfg->name;
            if (cfg->n_flow_limit && *cfg->flow_limit < UINT_MAX) {
                s.max_flows = *cfg->flow_limit;
            }

            s.enable_eviction = (cfg->overflow_policy
                                 && !strcmp(cfg->overflow_policy, "evict"));
            if (cfg->n_groups) {
                s.groups = xmalloc(cfg->n_groups * sizeof *s.groups);
                for (int k = 0; k < cfg->n_groups; k++) {
                    const char *string = cfg->groups[k];
                    char *msg;

                    msg = mf_parse_subfield__(&s.groups[k], &string);
                    if (msg) {
                        VLOG_WARN_RL(&rl, "bridge %s table %d: error parsing "
                                     "'groups' (%s)", br->name, i, msg);
                        free(msg);
                    } else if (*string) {
                        VLOG_WARN_RL(&rl, "bridge %s table %d: 'groups' "
                                     "element '%s' contains trailing garbage",
                                     br->name, i, cfg->groups[k]);
                    } else {
                        s.n_groups++;
                    }
                }
            }

            /* Prefix lookup fields. */
            s.n_prefix_fields = 0;
            for (int k = 0; k < cfg->n_prefixes; k++) {
                const char *name = cfg->prefixes[k];
                const struct mf_field *mf;

                if (strcmp(name, "none") == 0) {
                    use_default_prefixes = false;
                    s.n_prefix_fields = 0;
                    break;
                }
                mf = mf_from_name(name);
                if (!mf) {
                    VLOG_WARN("bridge %s: 'prefixes' with unknown field: %s",
                              br->name, name);
                    continue;
                }
                if (mf->flow_be32ofs < 0 || mf->n_bits % 32) {
                    VLOG_WARN("bridge %s: 'prefixes' with incompatible field: "
                              "%s", br->name, name);
                    continue;
                }
                if (s.n_prefix_fields >= ARRAY_SIZE(s.prefix_fields)) {
                    VLOG_WARN("bridge %s: 'prefixes' with too many fields, "
                              "field not used: %s", br->name, name);
                    continue;
                }
                use_default_prefixes = false;
                s.prefix_fields[s.n_prefix_fields++] = mf->id;
            }
        }
        if (use_default_prefixes) {
            /* Use default values. */
            s.n_prefix_fields = ARRAY_SIZE(default_prefix_fields);
            memcpy(s.prefix_fields, default_prefix_fields,
                   sizeof default_prefix_fields);
        } else {
            struct ds ds = DS_EMPTY_INITIALIZER;
            for (int k = 0; k < s.n_prefix_fields; k++) {
                if (k) {
                    ds_put_char(&ds, ',');
                }
                ds_put_cstr(&ds, mf_from_id(s.prefix_fields[k])->name);
            }
            if (s.n_prefix_fields == 0) {
                ds_put_cstr(&ds, "none");
            }
            VLOG_INFO("bridge %s table %d: Prefix lookup with: %s.",
                      br->name, i, ds_cstr(&ds));
            ds_destroy(&ds);
        }

        ofproto_configure_table(br->ofproto, i, &s);

        free(s.groups);
    }
    for (; j < br->cfg->n_flow_tables; j++) {
        VLOG_WARN_RL(&rl, "bridge %s: ignoring configuration for flow table "
                     "%"PRId64" not supported by this datapath", br->name,
                     br->cfg->key_flow_tables[j]);
    }
}

static void
bridge_configure_dp_desc(struct bridge *br)
{
    ofproto_set_dp_desc(br->ofproto,
                        smap_get(&br->cfg->other_config, "dp-desc"));
}

static struct aa_mapping *
bridge_aa_mapping_find(struct bridge *br, const int64_t isid)
{
    struct aa_mapping *m;

    HMAP_FOR_EACH_IN_BUCKET (m,
                             hmap_node,
                             hash_bytes(&isid, sizeof isid, 0),
                             &br->mappings) {
        if (isid == m->isid) {
            return m;
        }
    }
    return NULL;
}

static struct aa_mapping *
bridge_aa_mapping_create(struct bridge *br,
                         const int64_t isid,
                         const int64_t vlan)
{
    struct aa_mapping *m;

    m = xzalloc(sizeof *m);
    m->bridge = br;
    m->isid = isid;
    m->vlan = vlan;
    m->br_name = xstrdup(br->name);
    hmap_insert(&br->mappings,
                &m->hmap_node,
                hash_bytes(&isid, sizeof isid, 0));

    return m;
}

static void
bridge_aa_mapping_destroy(struct aa_mapping *m)
{
    if (m) {
        struct bridge *br = m->bridge;

        if (br->ofproto) {
            ofproto_aa_mapping_unregister(br->ofproto, m);
        }

        hmap_remove(&br->mappings, &m->hmap_node);
        if (m->br_name) {
            free(m->br_name);
        }
        free(m);
    }
}

static bool
bridge_aa_mapping_configure(struct aa_mapping *m)
{
    struct aa_mapping_settings s;

    s.isid = m->isid;
    s.vlan = m->vlan;

    /* Configure. */
    ofproto_aa_mapping_register(m->bridge->ofproto, m, &s);

    return true;
}

static void
bridge_configure_aa(struct bridge *br)
{
    const struct ovsdb_datum *mc;
    struct ovsrec_autoattach *auto_attach = br->cfg->auto_attach;
    struct aa_settings aa_s;
    struct aa_mapping *m, *next;
    size_t i;

    if (!auto_attach) {
        ofproto_set_aa(br->ofproto, NULL, NULL);
        return;
    }

    memset(&aa_s, 0, sizeof aa_s);
    aa_s.system_description = auto_attach->system_description;
    aa_s.system_name = auto_attach->system_name;
    ofproto_set_aa(br->ofproto, NULL, &aa_s);

    mc = ovsrec_autoattach_get_mappings(auto_attach,
                                        OVSDB_TYPE_INTEGER,
                                        OVSDB_TYPE_INTEGER);
    HMAP_FOR_EACH_SAFE (m, next, hmap_node, &br->mappings) {
        union ovsdb_atom atom;

        atom.integer = m->isid;
        if (ovsdb_datum_find_key(mc, &atom, OVSDB_TYPE_INTEGER) == UINT_MAX) {
            VLOG_INFO("Deleting isid=%"PRIu32", vlan=%"PRIu16,
                      m->isid, m->vlan);
            bridge_aa_mapping_destroy(m);
        }
    }

    /* Add new mappings and reconfigure existing ones. */
    for (i = 0; i < auto_attach->n_mappings; ++i) {
        m = bridge_aa_mapping_find(br, auto_attach->key_mappings[i]);

        if (!m) {
            VLOG_INFO("Adding isid=%"PRId64", vlan=%"PRId64,
                      auto_attach->key_mappings[i],
                      auto_attach->value_mappings[i]);
            m = bridge_aa_mapping_create(br,
                                         auto_attach->key_mappings[i],
                                         auto_attach->value_mappings[i]);

            if (!bridge_aa_mapping_configure(m)) {
                bridge_aa_mapping_destroy(m);
            }
        }
    }
}

static bool
bridge_aa_need_refresh(struct bridge *br)
{
    return ofproto_aa_vlan_get_queue_size(br->ofproto) > 0;
}

static void
bridge_aa_update_trunks(struct port *port, struct bridge_aa_vlan *m)
{
    int64_t *trunks = NULL;
    unsigned int i = 0;
    bool found = false, reconfigure = false;

    for (i = 0; i < port->cfg->n_trunks; i++) {
        if (port->cfg->trunks[i] == m->vlan) {
            found = true;
            break;
        }
    }

    switch (m->oper) {
        case BRIDGE_AA_VLAN_OPER_ADD:
            if (!found) {
                trunks = xmalloc(sizeof *trunks * (port->cfg->n_trunks + 1));

                for (i = 0; i < port->cfg->n_trunks; i++) {
                    trunks[i] = port->cfg->trunks[i];
                }
                trunks[i++] = m->vlan;
                reconfigure = true;
            }

            break;

        case BRIDGE_AA_VLAN_OPER_REMOVE:
            if (found) {
                unsigned int j = 0;

                trunks = xmalloc(sizeof *trunks * (port->cfg->n_trunks - 1));

                for (i = 0; i < port->cfg->n_trunks; i++) {
                    if (port->cfg->trunks[i] != m->vlan) {
                        trunks[j++] = port->cfg->trunks[i];
                    }
                }
                i = j;
                reconfigure = true;
            }

            break;

        case BRIDGE_AA_VLAN_OPER_UNDEF:
        default:
            VLOG_WARN("unrecognized operation %u", m->oper);
            break;
    }

    if (reconfigure) {
        /* VLAN switching under trunk mode cause the trunk port to switch all
         * VLANs, see ovs-vswitchd.conf.db
         */
        if (i == 0)  {
            static char *vlan_mode_access = "access";
            ovsrec_port_set_vlan_mode(port->cfg, vlan_mode_access);
        }

        if (i == 1) {
            static char *vlan_mode_trunk = "trunk";
            ovsrec_port_set_vlan_mode(port->cfg, vlan_mode_trunk);
        }

        ovsrec_port_set_trunks(port->cfg, trunks, i);

        /* Force reconfigure of the port. */
        port_configure(port);
    }

    free(trunks);
}

static void
bridge_aa_refresh_queued(struct bridge *br)
{
    struct ovs_list *list = xmalloc(sizeof *list);
    struct bridge_aa_vlan *node, *next;

    ovs_list_init(list);
    ofproto_aa_vlan_get_queued(br->ofproto, list);

    LIST_FOR_EACH_SAFE (node, next, list_node, list) {
        struct port *port;

        VLOG_INFO("ifname=%s, vlan=%u, oper=%u", node->port_name, node->vlan,
                  node->oper);

        port = port_lookup(br, node->port_name);
        if (port) {
            bridge_aa_update_trunks(port, node);
        }

        ovs_list_remove(&node->list_node);
        free(node->port_name);
        free(node);
    }

    free(list);
}


/* Port functions. */

static struct port *
port_create(struct bridge *br, const struct ovsrec_port *cfg)
{
    struct port *port;

    port = xzalloc(sizeof *port);
    port->bridge = br;
    port->name = xstrdup(cfg->name);
    port->cfg = cfg;
    ovs_list_init(&port->ifaces);

    hmap_insert(&br->ports, &port->hmap_node, hash_string(port->name, 0));
    return port;
}

/* Deletes interfaces from 'port' that are no longer configured for it. */
static void
port_del_ifaces(struct port *port)
{
    struct iface *iface, *next;
    struct sset new_ifaces;
    size_t i;

    /* Collect list of new interfaces. */
    sset_init(&new_ifaces);
    for (i = 0; i < port->cfg->n_interfaces; i++) {
        sset_add(&new_ifaces, port->cfg->interfaces[i]->name);
    }

    /* Get rid of deleted interfaces. */
    LIST_FOR_EACH_SAFE (iface, next, port_elem, &port->ifaces) {
        if (!sset_contains(&new_ifaces, iface->name)) {
            iface_destroy(iface);
        }
    }

    sset_destroy(&new_ifaces);
}

static void
port_destroy(struct port *port)
{
    if (port) {
        struct bridge *br = port->bridge;
        struct iface *iface, *next;

        if (br->ofproto) {
            ofproto_bundle_unregister(br->ofproto, port);
        }

        LIST_FOR_EACH_SAFE (iface, next, port_elem, &port->ifaces) {
            iface_destroy__(iface);
        }

        hmap_remove(&br->ports, &port->hmap_node);
        free(port->name);
        free(port);
    }
}

static struct port *
port_lookup(const struct bridge *br, const char *name)
{
    struct port *port;

    HMAP_FOR_EACH_WITH_HASH (port, hmap_node, hash_string(name, 0),
                             &br->ports) {
        if (!strcmp(port->name, name)) {
            return port;
        }
    }
    return NULL;
}

static bool
enable_lacp(struct port *port, bool *activep)
{
    if (!port->cfg->lacp) {
        /* XXX when LACP implementation has been sufficiently tested, enable by
         * default and make active on bonded ports. */
        return false;
    } else if (!strcmp(port->cfg->lacp, "off")) {
        return false;
    } else if (!strcmp(port->cfg->lacp, "active")) {
        *activep = true;
        return true;
    } else if (!strcmp(port->cfg->lacp, "passive")) {
        *activep = false;
        return true;
    } else {
        VLOG_WARN("port %s: unknown LACP mode %s",
                  port->name, port->cfg->lacp);
        return false;
    }
}

static struct lacp_settings *
port_configure_lacp(struct port *port, struct lacp_settings *s)
{
    const char *lacp_time, *system_id;
    int priority;

    if (!enable_lacp(port, &s->active)) {
        return NULL;
    }

    s->name = port->name;

    system_id = smap_get(&port->cfg->other_config, "lacp-system-id");
    if (system_id) {
        if (!ovs_scan(system_id, ETH_ADDR_SCAN_FMT,
                      ETH_ADDR_SCAN_ARGS(s->id))) {
            VLOG_WARN("port %s: LACP system ID (%s) must be an Ethernet"
                      " address.", port->name, system_id);
            return NULL;
        }
    } else {
        s->id = port->bridge->ea;
    }

    if (eth_addr_is_zero(s->id)) {
        VLOG_WARN("port %s: Invalid zero LACP system ID.", port->name);
        return NULL;
    }

    /* Prefer bondable links if unspecified. */
    priority = smap_get_int(&port->cfg->other_config, "lacp-system-priority",
                            0);
    s->priority = (priority > 0 && priority <= UINT16_MAX
                   ? priority
                   : UINT16_MAX - !ovs_list_is_short(&port->ifaces));

    lacp_time = smap_get_def(&port->cfg->other_config, "lacp-time", "");
    s->fast = !strcasecmp(lacp_time, "fast");

    s->fallback_ab_cfg = smap_get_bool(&port->cfg->other_config,
                                       "lacp-fallback-ab", false);

    return s;
}

static void
iface_configure_lacp(struct iface *iface, struct lacp_slave_settings *s)
{
    int priority, portid, key;

    portid = smap_get_int(&iface->cfg->other_config, "lacp-port-id", 0);
    priority = smap_get_int(&iface->cfg->other_config, "lacp-port-priority",
                            0);
    key = smap_get_int(&iface->cfg->other_config, "lacp-aggregation-key", 0);

    if (portid <= 0 || portid > UINT16_MAX) {
        portid = ofp_to_u16(iface->ofp_port);
    }

    if (priority <= 0 || priority > UINT16_MAX) {
        priority = UINT16_MAX;
    }

    if (key < 0 || key > UINT16_MAX) {
        key = 0;
    }

    s->name = iface->name;
    s->id = portid;
    s->priority = priority;
    s->key = key;
}

static void
port_configure_bond(struct port *port, struct bond_settings *s)
{
    const char *detect_s;
    struct iface *iface;
    const char *mac_s;
    int miimon_interval;

    s->name = port->name;
    s->balance = BM_AB;
    if (port->cfg->bond_mode) {
        if (!bond_mode_from_string(&s->balance, port->cfg->bond_mode)) {
            VLOG_WARN("port %s: unknown bond_mode %s, defaulting to %s",
                      port->name, port->cfg->bond_mode,
                      bond_mode_to_string(s->balance));
        }
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        /* XXX: Post version 1.5.*, the default bond_mode changed from SLB to
         * active-backup. At some point we should remove this warning. */
        VLOG_WARN_RL(&rl, "port %s: Using the default bond_mode %s. Note that"
                     " in previous versions, the default bond_mode was"
                     " balance-slb", port->name,
                     bond_mode_to_string(s->balance));
    }
    if (s->balance == BM_SLB && port->bridge->cfg->n_flood_vlans) {
        VLOG_WARN("port %s: SLB bonds are incompatible with flood_vlans, "
                  "please use another bond type or disable flood_vlans",
                  port->name);
    }

    miimon_interval = smap_get_int(&port->cfg->other_config,
                                   "bond-miimon-interval", 0);
    if (miimon_interval <= 0) {
        miimon_interval = 200;
    }

    detect_s = smap_get(&port->cfg->other_config, "bond-detect-mode");
    if (!detect_s || !strcmp(detect_s, "carrier")) {
        miimon_interval = 0;
    } else if (strcmp(detect_s, "miimon")) {
        VLOG_WARN("port %s: unsupported bond-detect-mode %s, "
                  "defaulting to carrier", port->name, detect_s);
        miimon_interval = 0;
    }

    s->up_delay = MAX(0, port->cfg->bond_updelay);
    s->down_delay = MAX(0, port->cfg->bond_downdelay);
    s->basis = smap_get_int(&port->cfg->other_config, "bond-hash-basis", 0);
    s->rebalance_interval = smap_get_int(&port->cfg->other_config,
                                           "bond-rebalance-interval", 10000);
    if (s->rebalance_interval && s->rebalance_interval < 1000) {
        s->rebalance_interval = 1000;
    }

    s->lacp_fallback_ab_cfg = smap_get_bool(&port->cfg->other_config,
                                       "lacp-fallback-ab", false);

    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
        netdev_set_miimon_interval(iface->netdev, miimon_interval);
    }

    mac_s = port->cfg->bond_active_slave;
    if (!mac_s || !ovs_scan(mac_s, ETH_ADDR_SCAN_FMT,
                            ETH_ADDR_SCAN_ARGS(s->active_slave_mac))) {
        /* OVSDB did not store the last active interface */
        s->active_slave_mac = eth_addr_zero;
    }
}

/* Returns true if 'port' is synthetic, that is, if we constructed it locally
 * instead of obtaining it from the database. */
static bool
port_is_synthetic(const struct port *port)
{
    return ovsdb_idl_row_is_synthetic(&port->cfg->header_);
}

/* Interface functions. */

static bool
iface_is_internal(const struct ovsrec_interface *iface,
                  const struct ovsrec_bridge *br)
{
    /* The local port and "internal" ports are always "internal". */
    return !strcmp(iface->type, "internal") || !strcmp(iface->name, br->name);
}

/* Returns the correct network device type for interface 'iface' in bridge
 * 'br'. */
static const char *
iface_get_type(const struct ovsrec_interface *iface,
               const struct ovsrec_bridge *br)
{
    const char *type;

    /* The local port always has type "internal".  Other ports take
     * their type from the database and default to "system" if none is
     * specified. */
    if (iface_is_internal(iface, br)) {
        type = "internal";
    } else {
        type = iface->type[0] ? iface->type : "system";
    }

    return type;
}

static void
iface_destroy__(struct iface *iface)
{
    if (iface) {
        struct port *port = iface->port;
        struct bridge *br = port->bridge;

        VLOG_INFO("bridge %s: deleted interface %s on port %d",
                  br->name, iface->name, iface->ofp_port);

        if (br->ofproto && iface->ofp_port != OFPP_NONE) {
            ofproto_port_unregister(br->ofproto, iface->ofp_port);
        }

        if (iface->ofp_port != OFPP_NONE) {
            hmap_remove(&br->ifaces, &iface->ofp_port_node);
        }

        ovs_list_remove(&iface->port_elem);
        hmap_remove(&br->iface_by_name, &iface->name_node);

        /* The user is changing configuration here, so netdev_remove needs to be
         * used as opposed to netdev_close */
        netdev_remove(iface->netdev);

        free(iface->name);
        free(iface);
    }
}

static void
iface_destroy(struct iface *iface)
{
    if (iface) {
        struct port *port = iface->port;

        iface_destroy__(iface);
        if (ovs_list_is_empty(&port->ifaces)) {
            port_destroy(port);
        }
    }
}

static struct iface *
iface_lookup(const struct bridge *br, const char *name)
{
    struct iface *iface;

    HMAP_FOR_EACH_WITH_HASH (iface, name_node, hash_string(name, 0),
                             &br->iface_by_name) {
        if (!strcmp(iface->name, name)) {
            return iface;
        }
    }

    return NULL;
}

static struct iface *
iface_find(const char *name)
{
    const struct bridge *br;

    HMAP_FOR_EACH (br, node, &all_bridges) {
        struct iface *iface = iface_lookup(br, name);

        if (iface) {
            return iface;
        }
    }
    return NULL;
}

static struct iface *
iface_from_ofp_port(const struct bridge *br, ofp_port_t ofp_port)
{
    struct iface *iface;

    HMAP_FOR_EACH_IN_BUCKET (iface, ofp_port_node, hash_ofp_port(ofp_port),
                             &br->ifaces) {
        if (iface->ofp_port == ofp_port) {
            return iface;
        }
    }
    return NULL;
}

/* Set Ethernet address of 'iface', if one is specified in the configuration
 * file. */
static void
iface_set_mac(const struct bridge *br, const struct port *port, struct iface *iface)
{
    struct eth_addr ea, *mac = NULL;
    struct iface *hw_addr_iface;

    if (strcmp(iface->type, "internal")) {
        return;
    }

    if (iface->cfg->mac && eth_addr_from_string(iface->cfg->mac, &ea)) {
        mac = &ea;
    } else if (port->cfg->fake_bridge) {
        /* Fake bridge and no MAC set in the configuration. Pick a local one. */
        find_local_hw_addr(br, &ea, port, &hw_addr_iface);
        mac = &ea;
    }

    if (mac) {
        if (iface->ofp_port == OFPP_LOCAL) {
            VLOG_ERR("interface %s: ignoring mac in Interface record "
                     "(use Bridge record to set local port's mac)",
                     iface->name);
        } else if (eth_addr_is_multicast(*mac)) {
            VLOG_ERR("interface %s: cannot set MAC to multicast address",
                     iface->name);
        } else if (eth_addr_is_zero(*mac)) {
            VLOG_ERR("interface %s: cannot set MAC to all zero address",
                     iface->name);
        } else {
            int error = netdev_set_etheraddr(iface->netdev, *mac);
            if (error) {
                VLOG_ERR("interface %s: setting MAC failed (%s)",
                         iface->name, ovs_strerror(error));
            }
        }
    }
}

/* Sets the ofport column of 'if_cfg' to 'ofport'. */
static void
iface_set_ofport(const struct ovsrec_interface *if_cfg, ofp_port_t ofport)
{
    if (if_cfg && !ovsdb_idl_row_is_synthetic(&if_cfg->header_)) {
        int64_t port = ofport == OFPP_NONE ? -1 : ofp_to_u16(ofport);
        ovsrec_interface_set_ofport(if_cfg, &port, 1);
    }
}

/* Clears all of the fields in 'if_cfg' that indicate interface status, and
 * sets the "ofport" field to -1.
 *
 * This is appropriate when 'if_cfg''s interface cannot be created or is
 * otherwise invalid. */
static void
iface_clear_db_record(const struct ovsrec_interface *if_cfg, char *errp)
{
    if (!ovsdb_idl_row_is_synthetic(&if_cfg->header_)) {
        iface_set_ofport(if_cfg, OFPP_NONE);
        ovsrec_interface_set_error(if_cfg, errp);
        ovsrec_interface_set_status(if_cfg, NULL);
        ovsrec_interface_set_admin_state(if_cfg, NULL);
        ovsrec_interface_set_duplex(if_cfg, NULL);
        ovsrec_interface_set_link_speed(if_cfg, NULL, 0);
        ovsrec_interface_set_link_state(if_cfg, NULL);
        ovsrec_interface_set_mac_in_use(if_cfg, NULL);
        ovsrec_interface_set_mtu(if_cfg, NULL, 0);
        ovsrec_interface_set_cfm_fault(if_cfg, NULL, 0);
        ovsrec_interface_set_cfm_fault_status(if_cfg, NULL, 0);
        ovsrec_interface_set_cfm_remote_mpids(if_cfg, NULL, 0);
        ovsrec_interface_set_lacp_current(if_cfg, NULL, 0);
        ovsrec_interface_set_statistics(if_cfg, NULL, NULL, 0);
        ovsrec_interface_set_ifindex(if_cfg, NULL, 0);
    }
}

static bool
queue_ids_include(const struct ovsdb_datum *queues, int64_t target)
{
    union ovsdb_atom atom;

    atom.integer = target;
    return ovsdb_datum_find_key(queues, &atom, OVSDB_TYPE_INTEGER) != UINT_MAX;
}

static void
iface_configure_qos(struct iface *iface, const struct ovsrec_qos *qos)
{
    struct ofpbuf queues_buf;

    ofpbuf_init(&queues_buf, 0);

    if (!qos || qos->type[0] == '\0') {
        netdev_set_qos(iface->netdev, NULL, NULL);
    } else {
        const struct ovsdb_datum *queues;
        struct netdev_queue_dump dump;
        unsigned int queue_id;
        struct smap details;
        bool queue_zero;
        size_t i;

        /* Configure top-level Qos for 'iface'. */
        netdev_set_qos(iface->netdev, qos->type, &qos->other_config);

        /* Deconfigure queues that were deleted. */
        queues = ovsrec_qos_get_queues(qos, OVSDB_TYPE_INTEGER,
                                       OVSDB_TYPE_UUID);
        smap_init(&details);
        NETDEV_QUEUE_FOR_EACH (&queue_id, &details, &dump, iface->netdev) {
            if (!queue_ids_include(queues, queue_id)) {
                netdev_delete_queue(iface->netdev, queue_id);
            }
        }
        smap_destroy(&details);

        /* Configure queues for 'iface'. */
        queue_zero = false;
        for (i = 0; i < qos->n_queues; i++) {
            const struct ovsrec_queue *queue = qos->value_queues[i];
            queue_id = qos->key_queues[i];

            if (queue_id == 0) {
                queue_zero = true;
            }

            if (queue->n_dscp == 1) {
                struct ofproto_port_queue *port_queue;

                port_queue = ofpbuf_put_uninit(&queues_buf,
                                               sizeof *port_queue);
                port_queue->queue = queue_id;
                port_queue->dscp = queue->dscp[0];
            }

            netdev_set_queue(iface->netdev, queue_id, &queue->other_config);
        }
        if (!queue_zero) {
            smap_init(&details);
            netdev_set_queue(iface->netdev, 0, &details);
            smap_destroy(&details);
        }
    }

    if (iface->ofp_port != OFPP_NONE) {
        const struct ofproto_port_queue *port_queues = queues_buf.data;
        size_t n_queues = queues_buf.size / sizeof *port_queues;

        ofproto_port_set_queues(iface->port->bridge->ofproto, iface->ofp_port,
                                port_queues, n_queues);
    }

    netdev_set_policing(iface->netdev,
                        MIN(UINT32_MAX, iface->cfg->ingress_policing_rate),
                        MIN(UINT32_MAX, iface->cfg->ingress_policing_burst));

    ofpbuf_uninit(&queues_buf);
}

static void
iface_configure_cfm(struct iface *iface)
{
    const struct ovsrec_interface *cfg = iface->cfg;
    const char *opstate_str;
    const char *cfm_ccm_vlan;
    struct cfm_settings s;
    struct smap netdev_args;

    if (!cfg->n_cfm_mpid) {
        ofproto_port_clear_cfm(iface->port->bridge->ofproto, iface->ofp_port);
        return;
    }

    s.check_tnl_key = false;
    smap_init(&netdev_args);
    if (!netdev_get_config(iface->netdev, &netdev_args)) {
        const char *key = smap_get(&netdev_args, "key");
        const char *in_key = smap_get(&netdev_args, "in_key");

        s.check_tnl_key = (key && !strcmp(key, "flow"))
                           || (in_key && !strcmp(in_key, "flow"));
    }
    smap_destroy(&netdev_args);

    s.mpid = *cfg->cfm_mpid;
    s.interval = smap_get_int(&iface->cfg->other_config, "cfm_interval", 0);
    cfm_ccm_vlan = smap_get(&iface->cfg->other_config, "cfm_ccm_vlan");
    s.ccm_pcp = smap_get_int(&iface->cfg->other_config, "cfm_ccm_pcp", 0);

    if (s.interval <= 0) {
        s.interval = 1000;
    }

    if (!cfm_ccm_vlan) {
        s.ccm_vlan = 0;
    } else if (!strcasecmp("random", cfm_ccm_vlan)) {
        s.ccm_vlan = CFM_RANDOM_VLAN;
    } else {
        s.ccm_vlan = atoi(cfm_ccm_vlan);
        if (s.ccm_vlan == CFM_RANDOM_VLAN) {
            s.ccm_vlan = 0;
        }
    }

    s.extended = smap_get_bool(&iface->cfg->other_config, "cfm_extended",
                               false);
    s.demand = smap_get_bool(&iface->cfg->other_config, "cfm_demand", false);

    opstate_str = smap_get(&iface->cfg->other_config, "cfm_opstate");
    s.opup = !opstate_str || !strcasecmp("up", opstate_str);

    ofproto_port_set_cfm(iface->port->bridge->ofproto, iface->ofp_port, &s);
}

/* Returns true if 'iface' is synthetic, that is, if we constructed it locally
 * instead of obtaining it from the database. */
static bool
iface_is_synthetic(const struct iface *iface)
{
    return ovsdb_idl_row_is_synthetic(&iface->cfg->header_);
}

static ofp_port_t
iface_validate_ofport__(size_t n, int64_t *ofport)
{
    return (n && *ofport >= 1 && *ofport < ofp_to_u16(OFPP_MAX)
            ? u16_to_ofp(*ofport)
            : OFPP_NONE);
}

static ofp_port_t
iface_get_requested_ofp_port(const struct ovsrec_interface *cfg)
{
    return iface_validate_ofport__(cfg->n_ofport_request, cfg->ofport_request);
}

static ofp_port_t
iface_pick_ofport(const struct ovsrec_interface *cfg)
{
    ofp_port_t requested_ofport = iface_get_requested_ofp_port(cfg);
    return (requested_ofport != OFPP_NONE
            ? requested_ofport
            : iface_validate_ofport__(cfg->n_ofport, cfg->ofport));
}

/* Port mirroring. */

static struct mirror *
mirror_find_by_uuid(struct bridge *br, const struct uuid *uuid)
{
    struct mirror *m;

    HMAP_FOR_EACH_IN_BUCKET (m, hmap_node, uuid_hash(uuid), &br->mirrors) {
        if (uuid_equals(uuid, &m->uuid)) {
            return m;
        }
    }
    return NULL;
}

static void
bridge_configure_mirrors(struct bridge *br)
{
    const struct ovsdb_datum *mc;
    unsigned long *flood_vlans;
    struct mirror *m, *next;
    size_t i;

    /* Get rid of deleted mirrors. */
    mc = ovsrec_bridge_get_mirrors(br->cfg, OVSDB_TYPE_UUID);
    HMAP_FOR_EACH_SAFE (m, next, hmap_node, &br->mirrors) {
        union ovsdb_atom atom;

        atom.uuid = m->uuid;
        if (ovsdb_datum_find_key(mc, &atom, OVSDB_TYPE_UUID) == UINT_MAX) {
            mirror_destroy(m);
        }
    }

    /* Add new mirrors and reconfigure existing ones. */
    for (i = 0; i < br->cfg->n_mirrors; i++) {
        const struct ovsrec_mirror *cfg = br->cfg->mirrors[i];
        m = mirror_find_by_uuid(br, &cfg->header_.uuid);
        if (!m) {
            m = mirror_create(br, cfg);
        }
        m->cfg = cfg;
        if (!mirror_configure(m)) {
            mirror_destroy(m);
        }
    }

    /* Update flooded vlans (for RSPAN). */
    flood_vlans = vlan_bitmap_from_array(br->cfg->flood_vlans,
                                         br->cfg->n_flood_vlans);
    ofproto_set_flood_vlans(br->ofproto, flood_vlans);
    bitmap_free(flood_vlans);
}

static struct mirror *
mirror_create(struct bridge *br, const struct ovsrec_mirror *cfg)
{
    struct mirror *m;

    m = xzalloc(sizeof *m);
    m->uuid = cfg->header_.uuid;
    hmap_insert(&br->mirrors, &m->hmap_node, uuid_hash(&m->uuid));
    m->bridge = br;
    m->name = xstrdup(cfg->name);

    return m;
}

static void
mirror_destroy(struct mirror *m)
{
    if (m) {
        struct bridge *br = m->bridge;

        if (br->ofproto) {
            ofproto_mirror_unregister(br->ofproto, m);
        }

        hmap_remove(&br->mirrors, &m->hmap_node);
        free(m->name);
        free(m);
    }
}

static void
mirror_collect_ports(struct mirror *m,
                     struct ovsrec_port **in_ports, int n_in_ports,
                     void ***out_portsp, size_t *n_out_portsp)
{
    void **out_ports = xmalloc(n_in_ports * sizeof *out_ports);
    size_t n_out_ports = 0;
    size_t i;

    for (i = 0; i < n_in_ports; i++) {
        const char *name = in_ports[i]->name;
        struct port *port = port_lookup(m->bridge, name);
        if (port) {
            out_ports[n_out_ports++] = port;
        } else {
            VLOG_WARN("bridge %s: mirror %s cannot match on nonexistent "
                      "port %s", m->bridge->name, m->name, name);
        }
    }
    *out_portsp = out_ports;
    *n_out_portsp = n_out_ports;
}

static bool
mirror_configure(struct mirror *m)
{
    const struct ovsrec_mirror *cfg = m->cfg;
    struct ofproto_mirror_settings s;

    /* Set name. */
    if (strcmp(cfg->name, m->name)) {
        free(m->name);
        m->name = xstrdup(cfg->name);
    }
    s.name = m->name;

    /* Get output port or VLAN. */
    if (cfg->output_port) {
        s.out_bundle = port_lookup(m->bridge, cfg->output_port->name);
        if (!s.out_bundle) {
            VLOG_ERR("bridge %s: mirror %s outputs to port not on bridge",
                     m->bridge->name, m->name);
            return false;
        }
        s.out_vlan = UINT16_MAX;

        if (cfg->output_vlan) {
            VLOG_ERR("bridge %s: mirror %s specifies both output port and "
                     "output vlan; ignoring output vlan",
                     m->bridge->name, m->name);
        }
    } else if (cfg->output_vlan) {
        /* The database should prevent invalid VLAN values. */
        s.out_bundle = NULL;
        s.out_vlan = *cfg->output_vlan;
    } else {
        VLOG_ERR("bridge %s: mirror %s does not specify output; ignoring",
                 m->bridge->name, m->name);
        return false;
    }

    if (cfg->snaplen) {
        s.snaplen = *cfg->snaplen;
    } else {
        s.snaplen = 0;
    }

    /* Get port selection. */
    if (cfg->select_all) {
        size_t n_ports = hmap_count(&m->bridge->ports);
        void **ports = xmalloc(n_ports * sizeof *ports);
        struct port *port;
        size_t i;

        i = 0;
        HMAP_FOR_EACH (port, hmap_node, &m->bridge->ports) {
            ports[i++] = port;
        }

        s.srcs = ports;
        s.n_srcs = n_ports;

        s.dsts = ports;
        s.n_dsts = n_ports;
    } else {
        /* Get ports, dropping ports that don't exist.
         * The IDL ensures that there are no duplicates. */
        mirror_collect_ports(m, cfg->select_src_port, cfg->n_select_src_port,
                             &s.srcs, &s.n_srcs);
        mirror_collect_ports(m, cfg->select_dst_port, cfg->n_select_dst_port,
                             &s.dsts, &s.n_dsts);
    }

    /* Get VLAN selection. */
    s.src_vlans = vlan_bitmap_from_array(cfg->select_vlan, cfg->n_select_vlan);

    /* Configure. */
    ofproto_mirror_register(m->bridge->ofproto, m, &s);

    /* Clean up. */
    if (s.srcs != s.dsts) {
        free(s.dsts);
    }
    free(s.srcs);
    free(s.src_vlans);

    return true;
}


static void
mirror_refresh_stats(struct mirror *m)
{
    struct ofproto *ofproto = m->bridge->ofproto;
    uint64_t tx_packets, tx_bytes;
    const char *keys[2];
    int64_t values[2];
    size_t stat_cnt = 0;

    if (ofproto_mirror_get_stats(ofproto, m, &tx_packets, &tx_bytes)) {
        ovsrec_mirror_set_statistics(m->cfg, NULL, NULL, 0);
        return;
    }

    if (tx_packets != UINT64_MAX) {
        keys[stat_cnt] = "tx_packets";
        values[stat_cnt] = tx_packets;
        stat_cnt++;
    }
    if (tx_bytes != UINT64_MAX) {
        keys[stat_cnt] = "tx_bytes";
        values[stat_cnt] = tx_bytes;
        stat_cnt++;
    }

    ovsrec_mirror_set_statistics(m->cfg, keys, values, stat_cnt);
}

/*
 * Add registered netdev and dpif types to ovsdb to allow external
 * applications to query the capabilities of the Open vSwitch instance
 * running on the node.
 */
static void
discover_types(const struct ovsrec_open_vswitch *cfg)
{
    struct sset types;

    /* Datapath types. */
    sset_init(&types);
    dp_enumerate_types(&types);
    const char **datapath_types = sset_array(&types);
    ovsrec_open_vswitch_set_datapath_types(cfg, datapath_types,
                                           sset_count(&types));
    free(datapath_types);
    sset_destroy(&types);

    /* Port types. */
    sset_init(&types);
    netdev_enumerate_types(&types);
    const char **iface_types = sset_array(&types);
    ovsrec_open_vswitch_set_iface_types(cfg, iface_types, sset_count(&types));
    free(iface_types);
    sset_destroy(&types);
}
