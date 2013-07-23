/* Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include "bitmap.h"
#include "bond.h"
#include "cfm.h"
#include "coverage.h"
#include "daemon.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "hmapx.h"
#include "jsonrpc.h"
#include "lacp.h"
#include "list.h"
#include "mac-learning.h"
#include "meta-flow.h"
#include "netdev.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "poll-loop.h"
#include "sha1.h"
#include "shash.h"
#include "smap.h"
#include "socket-util.h"
#include "stream.h"
#include "stream-ssl.h"
#include "sset.h"
#include "system-stats.h"
#include "timeval.h"
#include "util.h"
#include "unixctl.h"
#include "vlandev.h"
#include "lib/vswitch-idl.h"
#include "xenserver.h"
#include "vlog.h"
#include "sflow_api.h"
#include "vlan-bitmap.h"

VLOG_DEFINE_THIS_MODULE(bridge);

COVERAGE_DEFINE(bridge_reconfigure);

/* Configuration of an uninstantiated iface. */
struct if_cfg {
    struct hmap_node hmap_node;         /* Node in bridge's if_cfg_todo. */
    const struct ovsrec_interface *cfg; /* Interface record. */
    const struct ovsrec_port *parent;   /* Parent port record. */
};

/* OpenFlow port slated for removal from ofproto. */
struct ofpp_garbage {
    struct list list_node;      /* Node in bridge's ofpp_garbage. */
    uint16_t ofp_port;          /* Port to be deleted. */
};

struct iface {
    /* These members are always valid. */
    struct list port_elem;      /* Element in struct port's "ifaces" list. */
    struct hmap_node name_node; /* In struct bridge's "iface_by_name" hmap. */
    struct port *port;          /* Containing port. */
    char *name;                 /* Host network device name. */

    /* These members are valid only after bridge_reconfigure() causes them to
     * be initialized. */
    struct hmap_node ofp_port_node; /* In struct bridge's "ifaces" hmap. */
    int ofp_port;               /* OpenFlow port number, -1 if unknown. */
    struct netdev *netdev;      /* Network device. */
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
    struct list ifaces;         /* List of "struct iface"s. */
};

struct bridge {
    struct hmap_node node;      /* In 'all_bridges'. */
    char *name;                 /* User-specified arbitrary name. */
    char *type;                 /* Datapath type. */
    uint8_t ea[ETH_ADDR_LEN];   /* Bridge Ethernet Address. */
    uint8_t default_ea[ETH_ADDR_LEN]; /* Default MAC. */
    const struct ovsrec_bridge *cfg;

    /* OpenFlow switch processing. */
    struct ofproto *ofproto;    /* OpenFlow switch. */

    /* Bridge ports. */
    struct hmap ports;          /* "struct port"s indexed by name. */
    struct hmap ifaces;         /* "struct iface"s indexed by ofp_port. */
    struct hmap iface_by_name;  /* "struct iface"s indexed by name. */

    struct list ofpp_garbage;   /* "struct ofpp_garbage" slated for removal. */
    struct hmap if_cfg_todo;    /* "struct if_cfg"s slated for creation.
                                   Indexed on 'cfg->name'. */

    /* Port mirroring. */
    struct hmap mirrors;        /* "struct mirror" indexed by UUID. */

    /* Synthetic local port if necessary. */
    struct ovsrec_port synth_local_port;
    struct ovsrec_interface synth_local_iface;
    struct ovsrec_interface *synth_local_ifacep;
};

/* All bridges, indexed by name. */
static struct hmap all_bridges = HMAP_INITIALIZER(&all_bridges);

/* OVSDB IDL used to obtain configuration. */
static struct ovsdb_idl *idl;

/* Most recently processed IDL sequence number. */
static unsigned int idl_seqno;

/* Each time this timer expires, the bridge fetches interface and mirror
 * statistics and pushes them into the database. */
#define IFACE_STATS_INTERVAL (5 * 1000) /* In milliseconds. */
static long long int iface_stats_timer = LLONG_MIN;

/* In some datapaths, creating and destroying OpenFlow ports can be extremely
 * expensive.  This can cause bridge_reconfigure() to take a long time during
 * which no other work can be done.  To deal with this problem, we limit port
 * adds and deletions to a window of OFP_PORT_ACTION_WINDOW milliseconds per
 * call to bridge_reconfigure().  If there is more work to do after the limit
 * is reached, 'need_reconfigure', is flagged and it's done on the next loop.
 * This allows the rest of the code to catch up on important things like
 * forwarding packets. */
#define OFP_PORT_ACTION_WINDOW 10
static bool reconfiguring = false;

static void add_del_bridges(const struct ovsrec_open_vswitch *);
static void bridge_update_ofprotos(void);
static void bridge_create(const struct ovsrec_bridge *);
static void bridge_destroy(struct bridge *);
static struct bridge *bridge_lookup(const char *name);
static unixctl_cb_func bridge_unixctl_dump_flows;
static unixctl_cb_func bridge_unixctl_reconnect;
static size_t bridge_get_controllers(const struct bridge *br,
                                     struct ovsrec_controller ***controllersp);
static void bridge_add_del_ports(struct bridge *,
                                 const unsigned long int *splinter_vlans);
static void bridge_refresh_ofp_port(struct bridge *);
static void bridge_configure_datapath_id(struct bridge *);
static void bridge_configure_flow_eviction_threshold(struct bridge *);
static void bridge_configure_netflow(struct bridge *);
static void bridge_configure_forward_bpdu(struct bridge *);
static void bridge_configure_mac_idle_time(struct bridge *);
static void bridge_configure_sflow(struct bridge *, int *sflow_bridge_number);
static void bridge_configure_stp(struct bridge *);
static void bridge_configure_tables(struct bridge *);
static void bridge_configure_remotes(struct bridge *,
                                     const struct sockaddr_in *managers,
                                     size_t n_managers);
static void bridge_pick_local_hw_addr(struct bridge *,
                                      uint8_t ea[ETH_ADDR_LEN],
                                      struct iface **hw_addr_iface);
static uint64_t bridge_pick_datapath_id(struct bridge *,
                                        const uint8_t bridge_ea[ETH_ADDR_LEN],
                                        struct iface *hw_addr_iface);
static void bridge_queue_if_cfg(struct bridge *,
                                const struct ovsrec_interface *,
                                const struct ovsrec_port *);
static uint64_t dpid_from_hash(const void *, size_t nbytes);
static bool bridge_has_bond_fake_iface(const struct bridge *,
                                       const char *name);
static bool port_is_bond_fake_iface(const struct port *);

static unixctl_cb_func qos_unixctl_show;

static struct port *port_create(struct bridge *, const struct ovsrec_port *);
static void port_del_ifaces(struct port *);
static void port_destroy(struct port *);
static struct port *port_lookup(const struct bridge *, const char *name);
static void port_configure(struct port *);
static struct lacp_settings *port_configure_lacp(struct port *,
                                                 struct lacp_settings *);
static void port_configure_bond(struct port *, struct bond_settings *,
                                uint32_t *bond_stable_ids);
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
static bool iface_create(struct bridge *, struct if_cfg *, int ofp_port);
static const char *iface_get_type(const struct ovsrec_interface *,
                                  const struct ovsrec_bridge *);
static void iface_destroy(struct iface *);
static struct iface *iface_lookup(const struct bridge *, const char *name);
static struct iface *iface_find(const char *name);
static struct if_cfg *if_cfg_lookup(const struct bridge *, const char *name);
static struct iface *iface_from_ofp_port(const struct bridge *,
                                         uint16_t ofp_port);
static void iface_set_mac(struct iface *);
static void iface_set_ofport(const struct ovsrec_interface *, int64_t ofport);
static void iface_clear_db_record(const struct ovsrec_interface *if_cfg);
static void iface_configure_qos(struct iface *, const struct ovsrec_qos *);
static void iface_configure_cfm(struct iface *);
static void iface_refresh_cfm_stats(struct iface *);
static void iface_refresh_stats(struct iface *);
static void iface_refresh_status(struct iface *);
static bool iface_is_synthetic(const struct iface *);

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

/* True if VLAN splinters are enabled on any interface, false otherwise.*/
static bool vlan_splinters_enabled_anywhere;

static bool vlan_splinters_is_enabled(const struct ovsrec_interface *);
static unsigned long int *collect_splinter_vlans(
    const struct ovsrec_open_vswitch *);
static void configure_splinter_port(struct port *);
static void add_vlan_splinter_ports(struct bridge *,
                                    const unsigned long int *splinter_vlans,
                                    struct shash *ports);

/* Public functions. */

/* Initializes the bridge module, configuring it to obtain its configuration
 * from an OVSDB server accessed over 'remote', which should be a string in a
 * form acceptable to ovsdb_idl_create(). */
void
bridge_init(const char *remote)
{
    /* Create connection to database. */
    idl = ovsdb_idl_create(remote, &ovsrec_idl_class, true);
    idl_seqno = ovsdb_idl_get_seqno(idl);
    ovsdb_idl_set_lock(idl, "ovs_vswitchd");
    ovsdb_idl_verify_write_only(idl);

    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_cur_cfg);
    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_statistics);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_ovs_version);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_db_version);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_system_type);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_system_version);

    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_datapath_id);
    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_status);
    ovsdb_idl_omit(idl, &ovsrec_bridge_col_external_ids);

    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_port_col_statistics);
    ovsdb_idl_omit(idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_port_col_fake_bridge);

    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_admin_state);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_duplex);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_link_speed);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_link_state);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_link_resets);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_mtu);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_statistics);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_fault);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_fault_status);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_remote_mpids);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_health);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_cfm_remote_opstate);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_lacp_current);
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

    ovsdb_idl_omit(idl, &ovsrec_manager_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_inactivity_probe);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_is_connected);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_max_backoff);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_status);

    ovsdb_idl_omit(idl, &ovsrec_ssl_col_external_ids);

    /* Register unixctl commands. */
    unixctl_command_register("qos/show", "interface", 1, 1,
                             qos_unixctl_show, NULL);
    unixctl_command_register("bridge/dump-flows", "bridge", 1, 1,
                             bridge_unixctl_dump_flows, NULL);
    unixctl_command_register("bridge/reconnect", "[bridge]", 0, 1,
                             bridge_unixctl_reconnect, NULL);
    lacp_init();
    bond_init();
    cfm_init();
    stp_init();
}

void
bridge_exit(void)
{
    struct bridge *br, *next_br;

    HMAP_FOR_EACH_SAFE (br, next_br, node, &all_bridges) {
        bridge_destroy(br);
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
 * (Thus, only managers connected in-band are collected.)
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
            struct sockaddr_in *sin = &managers[n_managers];

            if (stream_parse_target_with_default_ports(target,
                                                       JSONRPC_TCP_PORT,
                                                       JSONRPC_SSL_PORT,
                                                       sin)) {
                n_managers++;
            }
        }
    }
    sset_destroy(&targets);

    *managersp = managers;
    *n_managersp = n_managers;
}

static void
bridge_reconfigure(const struct ovsrec_open_vswitch *ovs_cfg)
{
    unsigned long int *splinter_vlans;
    struct bridge *br;

    COVERAGE_INC(bridge_reconfigure);

    assert(!reconfiguring);
    reconfiguring = true;

    /* Destroy "struct bridge"s, "struct port"s, and "struct iface"s according
     * to 'ovs_cfg' while update the "if_cfg_queue", with only very minimal
     * configuration otherwise.
     *
     * This is mostly an update to bridge data structures. Nothing is pushed
     * down to ofproto or lower layers. */
    add_del_bridges(ovs_cfg);
    splinter_vlans = collect_splinter_vlans(ovs_cfg);
    HMAP_FOR_EACH (br, node, &all_bridges) {
        bridge_add_del_ports(br, splinter_vlans);
    }
    free(splinter_vlans);

    /* Delete datapaths that are no longer configured, and create ones which
     * don't exist but should. */
    bridge_update_ofprotos();

    /* Make sure each "struct iface" has a correct ofp_port in its ofproto. */
    HMAP_FOR_EACH (br, node, &all_bridges) {
        bridge_refresh_ofp_port(br);
    }

    /* Clear database records for "if_cfg"s which haven't been instantiated. */
    HMAP_FOR_EACH (br, node, &all_bridges) {
        struct if_cfg *if_cfg;

        HMAP_FOR_EACH (if_cfg, hmap_node, &br->if_cfg_todo) {
            iface_clear_db_record(if_cfg->cfg);
        }
    }

    reconfigure_system_stats(ovs_cfg);
}

static bool
bridge_reconfigure_ofp(void)
{
    long long int deadline;
    struct bridge *br;

    time_refresh();
    deadline = time_msec() + OFP_PORT_ACTION_WINDOW;

    /* The kernel will reject any attempt to add a given port to a datapath if
     * that port already belongs to a different datapath, so we must do all
     * port deletions before any port additions. */
    HMAP_FOR_EACH (br, node, &all_bridges) {
        struct ofpp_garbage *garbage, *next;

        LIST_FOR_EACH_SAFE (garbage, next, list_node, &br->ofpp_garbage) {
            /* It's a bit dangerous to call bridge_run_fast() here as ofproto's
             * internal datastructures may not be consistent.  Eventually, when
             * port additions and deletions are cheaper, these calls should be
             * removed. */
            bridge_run_fast();
            ofproto_port_del(br->ofproto, garbage->ofp_port);
            list_remove(&garbage->list_node);
            free(garbage);

            time_refresh();
            if (time_msec() >= deadline) {
                return false;
            }
            bridge_run_fast();
        }
    }

    HMAP_FOR_EACH (br, node, &all_bridges) {
        struct if_cfg *if_cfg, *next;

        HMAP_FOR_EACH_SAFE (if_cfg, next, hmap_node, &br->if_cfg_todo) {
            iface_create(br, if_cfg, -1);
            time_refresh();
            if (time_msec() >= deadline) {
                return false;
            }
        }
    }

    return true;
}

static bool
bridge_reconfigure_continue(const struct ovsrec_open_vswitch *ovs_cfg)
{
    struct sockaddr_in *managers;
    int sflow_bridge_number;
    size_t n_managers;
    struct bridge *br;
    bool done;

    assert(reconfiguring);
    done = bridge_reconfigure_ofp();

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
                iface_configure_cfm(iface);
                iface_configure_qos(iface, port->cfg->qos);
                iface_set_mac(iface);
            }
        }
        bridge_configure_mirrors(br);
        bridge_configure_flow_eviction_threshold(br);
        bridge_configure_forward_bpdu(br);
        bridge_configure_mac_idle_time(br);
        bridge_configure_remotes(br, managers, n_managers);
        bridge_configure_netflow(br);
        bridge_configure_sflow(br, &sflow_bridge_number);
        bridge_configure_stp(br);
        bridge_configure_tables(br);
    }
    free(managers);

    if (done) {
        /* ovs-vswitchd has completed initialization, so allow the process that
         * forked us to exit successfully. */
        daemonize_complete();
        reconfiguring = false;

        VLOG_INFO("%s (Open vSwitch) %s", program_name, VERSION);
    }

    return done;
}

/* Delete ofprotos which aren't configured or have the wrong type.  Create
 * ofprotos which don't exist but need to. */
static void
bridge_update_ofprotos(void)
{
    struct bridge *br, *next;
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

    /* Add ofprotos for bridges which don't have one yet. */
    HMAP_FOR_EACH_SAFE (br, next, node, &all_bridges) {
        struct bridge *br2;
        int error;

        if (br->ofproto) {
            continue;
        }

        /* Remove ports from any datapath with the same name as 'br'.  If we
         * don't do this, creating 'br''s ofproto will fail because a port with
         * the same name as its local port already exists. */
        HMAP_FOR_EACH (br2, node, &all_bridges) {
            struct ofproto_port ofproto_port;

            if (!br2->ofproto) {
                continue;
            }

            if (!ofproto_port_query_by_name(br2->ofproto, br->name,
                                            &ofproto_port)) {
                error = ofproto_port_del(br2->ofproto, ofproto_port.ofp_port);
                if (error) {
                    VLOG_ERR("failed to delete port %s: %s", ofproto_port.name,
                             strerror(error));
                }
                ofproto_port_destroy(&ofproto_port);
            }
        }

        error = ofproto_create(br->name, br->type, &br->ofproto);
        if (error) {
            VLOG_ERR("failed to create bridge %s: %s", br->name,
                     strerror(error));
            bridge_destroy(br);
        }
    }
}

static void
port_configure(struct port *port)
{
    const struct ovsrec_port *cfg = port->cfg;
    struct bond_settings bond_settings;
    struct lacp_settings lacp_settings;
    struct ofproto_bundle_settings s;
    struct iface *iface;

    if (cfg->vlan_mode && !strcmp(cfg->vlan_mode, "splinter")) {
        configure_splinter_port(port);
        return;
    }

    /* Get name. */
    s.name = port->name;

    /* Get slaves. */
    s.n_slaves = 0;
    s.slaves = xmalloc(list_size(&port->ifaces) * sizeof *s.slaves);
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
        } else {
            /* This "can't happen" because ovsdb-server should prevent it. */
            VLOG_ERR("unknown VLAN mode %s", cfg->vlan_mode);
            s.vlan_mode = PORT_VLAN_TRUNK;
        }
    } else {
        if (s.vlan >= 0) {
            s.vlan_mode = PORT_VLAN_ACCESS;
            if (cfg->n_trunks) {
                VLOG_ERR("port %s: ignoring trunks in favor of implicit vlan",
                         port->name);
            }
        } else {
            s.vlan_mode = PORT_VLAN_TRUNK;
        }
    }
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
        s.bond_stable_ids = xmalloc(s.n_slaves * sizeof *s.bond_stable_ids);
        port_configure_bond(port, &bond_settings, s.bond_stable_ids);
    } else {
        s.bond = NULL;
        s.bond_stable_ids = NULL;

        LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
            netdev_set_miimon_interval(iface->netdev, 0);
        }
    }

    /* Register. */
    ofproto_bundle_register(port->bridge->ofproto, port, &s);

    /* Clean up. */
    free(s.slaves);
    free(s.trunks);
    free(s.lacp_slaves);
    free(s.bond_stable_ids);
}

/* Pick local port hardware address and datapath ID for 'br'. */
static void
bridge_configure_datapath_id(struct bridge *br)
{
    uint8_t ea[ETH_ADDR_LEN];
    uint64_t dpid;
    struct iface *local_iface;
    struct iface *hw_addr_iface;
    char *dpid_string;

    bridge_pick_local_hw_addr(br, ea, &hw_addr_iface);
    local_iface = iface_from_ofp_port(br, OFPP_LOCAL);
    if (local_iface) {
        int error = netdev_set_etheraddr(local_iface->netdev, ea);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_ERR_RL(&rl, "bridge %s: failed to set bridge "
                        "Ethernet address: %s",
                        br->name, strerror(error));
        }
    }
    memcpy(br->ea, ea, ETH_ADDR_LEN);

    dpid = bridge_pick_datapath_id(br, ea, hw_addr_iface);
    if (dpid != ofproto_get_datapath_id(br->ofproto)) {
        VLOG_INFO("bridge %s: using datapath ID %016"PRIx64, br->name, dpid);
        ofproto_set_datapath_id(br->ofproto, dpid);
    }

    dpid_string = xasprintf("%016"PRIx64, dpid);
    ovsrec_bridge_set_datapath_id(br->cfg, dpid_string);
    free(dpid_string);
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
    if (!list_is_singleton(&port->ifaces)) {
        VLOG_ERR("port %s: cannot enable STP on bonds, disabling",
                 port->name);
        port_s->enable = false;
        return;
    }

    iface = CONTAINER_OF(list_front(&port->ifaces), struct iface, port_elem);

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

        if (netdev_get_features(iface->netdev, &current, NULL, NULL, NULL)) {
            /* Couldn't get speed, so assume 100Mb/s. */
            port_s->path_cost = 19;
        } else {
            unsigned int mbps;

            mbps = netdev_features_to_bps(current) / 1000000;
            port_s->path_cost = stp_convert_speed_to_cost(mbps);
        }
    }

    config_str = smap_get(&port->cfg->other_config, "stp-port-priority");
    if (config_str) {
        port_s->priority = strtoul(config_str, NULL, 0);
    } else {
        port_s->priority = STP_DEFAULT_PORT_PRIORITY;
    }
}

/* Set spanning tree configuration on 'br'. */
static void
bridge_configure_stp(struct bridge *br)
{
    if (!br->cfg->stp_enable) {
        ofproto_set_stp(br->ofproto, NULL);
    } else {
        struct ofproto_stp_settings br_s;
        const char *config_str;
        struct port *port;
        int port_num_counter;
        unsigned long *port_num_bitmap;

        config_str = smap_get(&br->cfg->other_config, "stp-system-id");
        if (config_str) {
            uint8_t ea[ETH_ADDR_LEN];

            if (eth_addr_from_string(config_str, ea)) {
                br_s.system_id = eth_addr_to_uint64(ea);
            } else {
                br_s.system_id = eth_addr_to_uint64(br->ea);
                VLOG_ERR("bridge %s: invalid stp-system-id, defaulting "
                         "to "ETH_ADDR_FMT, br->name, ETH_ADDR_ARGS(br->ea));
            }
        } else {
            br_s.system_id = eth_addr_to_uint64(br->ea);
        }

        config_str = smap_get(&br->cfg->other_config, "stp-priority");
        if (config_str) {
            br_s.priority = strtoul(config_str, NULL, 0);
        } else {
            br_s.priority = STP_DEFAULT_BRIDGE_PRIORITY;
        }

        config_str = smap_get(&br->cfg->other_config, "stp-hello-time");
        if (config_str) {
            br_s.hello_time = strtoul(config_str, NULL, 10) * 1000;
        } else {
            br_s.hello_time = STP_DEFAULT_HELLO_TIME;
        }

        config_str = smap_get(&br->cfg->other_config, "stp-max-age");
        if (config_str) {
            br_s.max_age = strtoul(config_str, NULL, 10) * 1000;
        } else {
            br_s.max_age = STP_DEFAULT_MAX_AGE;
        }

        config_str = smap_get(&br->cfg->other_config, "stp-forward-delay");
        if (config_str) {
            br_s.fwd_delay = strtoul(config_str, NULL, 10) * 1000;
        } else {
            br_s.fwd_delay = STP_DEFAULT_FWD_DELAY;
        }

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

        if (bitmap_scan(port_num_bitmap, 0, STP_MAX_PORTS) != STP_MAX_PORTS
                    && port_num_counter) {
            VLOG_ERR("bridge %s: must manually configure all STP port "
                     "IDs or none, disabling", br->name);
            ofproto_set_stp(br->ofproto, NULL);
        }
        bitmap_free(port_num_bitmap);
    }
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
    return port->cfg->bond_fake_iface && !list_is_short(&port->ifaces);
}

static void
add_del_bridges(const struct ovsrec_open_vswitch *cfg)
{
    struct bridge *br, *next;
    struct shash new_br;
    size_t i;

    /* Collect new bridges' names and types. */
    shash_init(&new_br);
    for (i = 0; i < cfg->n_bridges; i++) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        const struct ovsrec_bridge *br_cfg = cfg->bridges[i];

        if (strchr(br_cfg->name, '/')) {
            /* Prevent remote ovsdb-server users from accessing arbitrary
             * directories, e.g. consider a bridge named "../../../etc/". */
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
            bridge_destroy(br);
        }
    }

    /* Add new bridges. */
    for (i = 0; i < cfg->n_bridges; i++) {
        const struct ovsrec_bridge *br_cfg = cfg->bridges[i];
        struct bridge *br = bridge_lookup(br_cfg->name);
        if (!br) {
            bridge_create(br_cfg);
        }
    }

    shash_destroy(&new_br);
}

static void
iface_set_ofp_port(struct iface *iface, int ofp_port)
{
    struct bridge *br = iface->port->bridge;

    assert(iface->ofp_port < 0 && ofp_port >= 0);
    iface->ofp_port = ofp_port;
    hmap_insert(&br->ifaces, &iface->ofp_port_node, hash_int(ofp_port, 0));
    iface_set_ofport(iface->cfg, ofp_port);
}

/* Configures 'netdev' based on the "options" column in 'iface_cfg'.
 * Returns 0 if successful, otherwise a positive errno value. */
static int
iface_set_netdev_config(const struct ovsrec_interface *iface_cfg,
                        struct netdev *netdev)
{
    int error;

    error = netdev_set_config(netdev, &iface_cfg->options);
    if (error) {
        VLOG_WARN("could not configure network device %s (%s)",
                  iface_cfg->name, strerror(error));
    }
    return error;
}

/* This function determines whether 'ofproto_port', which is attached to
 * br->ofproto's datapath, is one that we want in 'br'.
 *
 * If it is, it returns true, after creating an iface (if necessary),
 * configuring the iface's netdev according to the iface's options, and setting
 * iface's ofp_port member to 'ofproto_port->ofp_port'.
 *
 * If, on the other hand, 'port' should be removed, it returns false.  The
 * caller should later detach the port from br->ofproto. */
static bool
bridge_refresh_one_ofp_port(struct bridge *br,
                            const struct ofproto_port *ofproto_port)
{
    const char *name = ofproto_port->name;
    const char *type = ofproto_port->type;
    uint16_t ofp_port = ofproto_port->ofp_port;

    struct iface *iface = iface_lookup(br, name);
    if (iface) {
        /* Check that the name-to-number mapping is one-to-one. */
        if (iface->ofp_port >= 0) {
            VLOG_WARN("bridge %s: interface %s reported twice",
                      br->name, name);
            return false;
        } else if (iface_from_ofp_port(br, ofp_port)) {
            VLOG_WARN("bridge %s: interface %"PRIu16" reported twice",
                      br->name, ofp_port);
            return false;
        }

        /* There's a configured interface named 'name'. */
        if (strcmp(type, iface->type)
            || iface_set_netdev_config(iface->cfg, iface->netdev)) {
            /* It's the wrong type, or it's the right type but can't be
             * configured as the user requested, so we must destroy it. */
            return false;
        } else {
            /* It's the right type and configured correctly.  keep it. */
            iface_set_ofp_port(iface, ofp_port);
            return true;
        }
    } else if (bridge_has_bond_fake_iface(br, name)
               && !strcmp(type, "internal")) {
        /* It's a bond fake iface.  Keep it. */
        return true;
    } else {
        /* There's no configured interface named 'name', but there might be an
         * interface of that name queued to be created.
         *
         * If there is, and it has the correct type, then try to configure it
         * and add it.  If that's successful, we'll keep it.  Otherwise, we'll
         * delete it and later try to re-add it. */
        struct if_cfg *if_cfg = if_cfg_lookup(br, name);
        return (if_cfg
                && !strcmp(type, iface_get_type(if_cfg->cfg, br->cfg))
                && iface_create(br, if_cfg, ofp_port));
    }
}

/* Update bridges "if_cfg"s, "struct port"s, and "struct iface"s to be
 * consistent with the ofp_ports in "br->ofproto". */
static void
bridge_refresh_ofp_port(struct bridge *br)
{
    struct ofproto_port_dump dump;
    struct ofproto_port ofproto_port;
    struct port *port, *port_next;

    /* Clear each "struct iface"s ofp_port so we can get its correct value. */
    hmap_clear(&br->ifaces);
    HMAP_FOR_EACH (port, hmap_node, &br->ports) {
        struct iface *iface;

        LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
            iface->ofp_port = -1;
        }
    }

    /* Obtain the correct "ofp_port"s from ofproto. Find any if_cfg's which
     * already exist in the datapath and promote them to full fledged "struct
     * iface"s.  Mark ports in the datapath which don't belong as garbage. */
    OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, br->ofproto) {
        if (!bridge_refresh_one_ofp_port(br, &ofproto_port)) {
            struct ofpp_garbage *garbage = xmalloc(sizeof *garbage);
            garbage->ofp_port = ofproto_port.ofp_port;
            list_push_front(&br->ofpp_garbage, &garbage->list_node);
        }
    }

    /* Some ifaces may not have "ofp_port"s in ofproto and therefore don't
     * deserve to have "struct iface"s.  Demote these to "if_cfg"s so that
     * later they can be added to ofproto. */
    HMAP_FOR_EACH_SAFE (port, port_next, hmap_node, &br->ports) {
        struct iface *iface, *iface_next;

        LIST_FOR_EACH_SAFE (iface, iface_next, port_elem, &port->ifaces) {
            if (iface->ofp_port < 0) {
                bridge_queue_if_cfg(br, iface->cfg, port->cfg);
                iface_destroy(iface);
            }
        }

        if (list_is_empty(&port->ifaces)) {
            port_destroy(port);
        }
    }
}

/* Opens a network device for 'iface_cfg' and configures it.  If '*ofp_portp'
 * is negative, adds the network device to br->ofproto and stores the OpenFlow
 * port number in '*ofp_portp'; otherwise leaves br->ofproto and '*ofp_portp'
 * untouched.
 *
 * If successful, returns 0 and stores the network device in '*netdevp'.  On
 * failure, returns a positive errno value and stores NULL in '*netdevp'. */
static int
iface_do_create(const struct bridge *br,
                const struct ovsrec_interface *iface_cfg,
                const struct ovsrec_port *port_cfg,
                int *ofp_portp, struct netdev **netdevp)
{
    struct netdev *netdev;
    int error;

    error = netdev_open(iface_cfg->name,
                        iface_get_type(iface_cfg, br->cfg), &netdev);
    if (error) {
        VLOG_WARN("could not open network device %s (%s)",
                  iface_cfg->name, strerror(error));
        goto error;
    }

    error = iface_set_netdev_config(iface_cfg, netdev);
    if (error) {
        goto error;
    }

    if (*ofp_portp < 0) {
        uint16_t ofp_port;

        error = ofproto_port_add(br->ofproto, netdev, &ofp_port);
        if (error) {
            goto error;
        }
        *ofp_portp = ofp_port;

        VLOG_INFO("bridge %s: added interface %s on port %d",
                  br->name, iface_cfg->name, *ofp_portp);
    } else {
        VLOG_DBG("bridge %s: interface %s is on port %d",
                 br->name, iface_cfg->name, *ofp_portp);
    }

    if (port_cfg->vlan_mode && !strcmp(port_cfg->vlan_mode, "splinter")) {
        netdev_turn_flags_on(netdev, NETDEV_UP, true);
    }

    *netdevp = netdev;
    return 0;

error:
    *netdevp = NULL;
    netdev_close(netdev);
    return error;
}

/* Creates a new iface on 'br' based on 'if_cfg'.  The new iface has OpenFlow
 * port number 'ofp_port'.  If ofp_port is negative, an OpenFlow port is
 * automatically allocated for the iface.  Takes ownership of and
 * deallocates 'if_cfg'.
 *
 * Return true if an iface is successfully created, false otherwise. */
static bool
iface_create(struct bridge *br, struct if_cfg *if_cfg, int ofp_port)
{
    const struct ovsrec_interface *iface_cfg = if_cfg->cfg;
    const struct ovsrec_port *port_cfg = if_cfg->parent;

    struct netdev *netdev;
    struct iface *iface;
    struct port *port;
    int error;

    /* Get rid of 'if_cfg' itself.  We already copied out the interesting
     * bits. */
    hmap_remove(&br->if_cfg_todo, &if_cfg->hmap_node);
    free(if_cfg);

    /* Do the bits that can fail up front.
     *
     * It's a bit dangerous to call bridge_run_fast() here as ofproto's
     * internal datastructures may not be consistent.  Eventually, when port
     * additions and deletions are cheaper, these calls should be removed. */
    bridge_run_fast();
    assert(!iface_lookup(br, iface_cfg->name));
    error = iface_do_create(br, iface_cfg, port_cfg, &ofp_port, &netdev);
    bridge_run_fast();
    if (error) {
        iface_clear_db_record(iface_cfg);
        return false;
    }

    /* Get or create the port structure. */
    port = port_lookup(br, port_cfg->name);
    if (!port) {
        port = port_create(br, port_cfg);
    }

    /* Create the iface structure. */
    iface = xzalloc(sizeof *iface);
    list_push_back(&port->ifaces, &iface->port_elem);
    hmap_insert(&br->iface_by_name, &iface->name_node,
                hash_string(iface_cfg->name, 0));
    iface->port = port;
    iface->name = xstrdup(iface_cfg->name);
    iface->ofp_port = -1;
    iface->netdev = netdev;
    iface->type = iface_get_type(iface_cfg, br->cfg);
    iface->cfg = iface_cfg;

    iface_set_ofp_port(iface, ofp_port);

    /* Populate initial status in database. */
    iface_refresh_stats(iface);
    iface_refresh_status(iface);

    /* Add bond fake iface if necessary. */
    if (port_is_bond_fake_iface(port)) {
        struct ofproto_port ofproto_port;

        if (ofproto_port_query_by_name(br->ofproto, port->name,
                                       &ofproto_port)) {
            struct netdev *netdev;
            int error;

            error = netdev_open(port->name, "internal", &netdev);
            if (!error) {
                ofproto_port_add(br->ofproto, netdev, NULL);
                netdev_close(netdev);
            } else {
                VLOG_WARN("could not open network device %s (%s)",
                          port->name, strerror(error));
            }
        } else {
            /* Already exists, nothing to do. */
            ofproto_port_destroy(&ofproto_port);
        }
    }

    return true;
}

/* Set Flow eviction threshold */
static void
bridge_configure_flow_eviction_threshold(struct bridge *br)
{
    const char *threshold_str;
    unsigned threshold;

    threshold_str = smap_get(&br->cfg->other_config,
                             "flow-eviction-threshold");
    if (threshold_str) {
        threshold = strtoul(threshold_str, NULL, 10);
    } else {
        threshold = OFPROTO_FLOW_EVICTION_THRESHOLD_DEFAULT;
    }
    ofproto_set_flow_eviction_threshold(br->ofproto, threshold);
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

/* Set MAC aging time for 'br'. */
static void
bridge_configure_mac_idle_time(struct bridge *br)
{
    const char *idle_time_str;
    int idle_time;

    idle_time_str = smap_get(&br->cfg->other_config, "mac-aging-time");
    idle_time = (idle_time_str && atoi(idle_time_str)
                 ? atoi(idle_time_str)
                 : MAC_ENTRY_DEFAULT_IDLE_TIME);
    ofproto_set_mac_idle_time(br->ofproto, idle_time);
}

static void
bridge_pick_local_hw_addr(struct bridge *br, uint8_t ea[ETH_ADDR_LEN],
                          struct iface **hw_addr_iface)
{
    struct hmapx mirror_output_ports;
    const char *hwaddr;
    struct port *port;
    bool found_addr = false;
    int error;
    int i;

    *hw_addr_iface = NULL;

    /* Did the user request a particular MAC? */
    hwaddr = smap_get(&br->cfg->other_config, "hwaddr");
    if (hwaddr && eth_addr_from_string(hwaddr, ea)) {
        if (eth_addr_is_multicast(ea)) {
            VLOG_ERR("bridge %s: cannot set MAC address to multicast "
                     "address "ETH_ADDR_FMT, br->name, ETH_ADDR_ARGS(ea));
        } else if (eth_addr_is_zero(ea)) {
            VLOG_ERR("bridge %s: cannot set MAC address to zero", br->name);
        } else {
            return;
        }
    }

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
        uint8_t iface_ea[ETH_ADDR_LEN];
        struct iface *candidate;
        struct iface *iface;

        /* Mirror output ports don't participate. */
        if (hmapx_contains(&mirror_output_ports, port->cfg)) {
            continue;
        }

        /* Choose the MAC address to represent the port. */
        iface = NULL;
        if (port->cfg->mac && eth_addr_from_string(port->cfg->mac, iface_ea)) {
            /* Find the interface with this Ethernet address (if any) so that
             * we can provide the correct devname to the caller. */
            LIST_FOR_EACH (candidate, port_elem, &port->ifaces) {
                uint8_t candidate_ea[ETH_ADDR_LEN];
                if (!netdev_get_etheraddr(candidate->netdev, candidate_ea)
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

            /* The local port doesn't count (since we're trying to choose its
             * MAC address anyway). */
            if (iface->ofp_port == OFPP_LOCAL) {
                continue;
            }

            /* Grab MAC. */
            error = netdev_get_etheraddr(iface->netdev, iface_ea);
            if (error) {
                continue;
            }
        }

        /* Compare against our current choice. */
        if (!eth_addr_is_multicast(iface_ea) &&
            !eth_addr_is_local(iface_ea) &&
            !eth_addr_is_reserved(iface_ea) &&
            !eth_addr_is_zero(iface_ea) &&
            (!found_addr || eth_addr_compare_3way(iface_ea, ea) < 0))
        {
            memcpy(ea, iface_ea, ETH_ADDR_LEN);
            *hw_addr_iface = iface;
            found_addr = true;
        }
    }
    if (found_addr) {
        VLOG_DBG("bridge %s: using bridge Ethernet address "ETH_ADDR_FMT,
                 br->name, ETH_ADDR_ARGS(ea));
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 10);
        memcpy(ea, br->default_ea, ETH_ADDR_LEN);
        *hw_addr_iface = NULL;
        VLOG_WARN_RL(&rl, "bridge %s: using default bridge Ethernet "
                     "address "ETH_ADDR_FMT, br->name, ETH_ADDR_ARGS(ea));
    }

    hmapx_destroy(&mirror_output_ports);
}

/* Choose and returns the datapath ID for bridge 'br' given that the bridge
 * Ethernet address is 'bridge_ea'.  If 'bridge_ea' is the Ethernet address of
 * an interface on 'br', then that interface must be passed in as
 * 'hw_addr_iface'; if 'bridge_ea' was derived some other way, then
 * 'hw_addr_iface' must be passed in as a null pointer. */
static uint64_t
bridge_pick_datapath_id(struct bridge *br,
                        const uint8_t bridge_ea[ETH_ADDR_LEN],
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

    datapath_id = smap_get(&br->cfg->other_config, "datapath-id");
    if (datapath_id && dpid_from_string(datapath_id, &dpid)) {
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
    uint8_t hash[SHA1_DIGEST_SIZE];

    BUILD_ASSERT_DECL(sizeof hash >= ETH_ADDR_LEN);
    sha1_bytes(data, n, hash);
    eth_addr_mark_random(hash);
    return eth_addr_to_uint64(hash);
}

static void
iface_refresh_status(struct iface *iface)
{
    struct smap smap;

    enum netdev_features current;
    int64_t bps;
    int mtu;
    int64_t mtu_64;
    int error;

    if (iface_is_synthetic(iface)) {
        return;
    }

    smap_init(&smap);

    if (!netdev_get_drv_info(iface->netdev, &smap)) {
        ovsrec_interface_set_status(iface->cfg, &smap);
    } else {
        ovsrec_interface_set_status(iface->cfg, NULL);
    }

    smap_destroy(&smap);

    error = netdev_get_features(iface->netdev, &current, NULL, NULL, NULL);
    if (!error) {
        ovsrec_interface_set_duplex(iface->cfg,
                                    netdev_features_is_full_duplex(current)
                                    ? "full" : "half");
        /* warning: uint64_t -> int64_t conversion */
        bps = netdev_features_to_bps(current);
        ovsrec_interface_set_link_speed(iface->cfg, &bps, 1);
    }
    else {
        ovsrec_interface_set_duplex(iface->cfg, NULL);
        ovsrec_interface_set_link_speed(iface->cfg, NULL, 0);
    }

    error = netdev_get_mtu(iface->netdev, &mtu);
    if (!error) {
        mtu_64 = mtu;
        ovsrec_interface_set_mtu(iface->cfg, &mtu_64, 1);
    }
    else {
        ovsrec_interface_set_mtu(iface->cfg, NULL, 0);
    }
}

/* Writes 'iface''s CFM statistics to the database. 'iface' must not be
 * synthetic. */
static void
iface_refresh_cfm_stats(struct iface *iface)
{
    const struct ovsrec_interface *cfg = iface->cfg;
    int fault, opup, error;
    const uint64_t *rmps;
    size_t n_rmps;
    int health;

    fault = ofproto_port_get_cfm_fault(iface->port->bridge->ofproto,
                                       iface->ofp_port);
    if (fault >= 0) {
        const char *reasons[CFM_FAULT_N_REASONS];
        bool fault_bool = fault;
        size_t i, j;

        j = 0;
        for (i = 0; i < CFM_FAULT_N_REASONS; i++) {
            int reason = 1 << i;
            if (fault & reason) {
                reasons[j++] = cfm_fault_reason_to_str(reason);
            }
        }

        ovsrec_interface_set_cfm_fault(cfg, &fault_bool, 1);
        ovsrec_interface_set_cfm_fault_status(cfg, (char **) reasons, j);
    } else {
        ovsrec_interface_set_cfm_fault(cfg, NULL, 0);
        ovsrec_interface_set_cfm_fault_status(cfg, NULL, 0);
    }

    opup = ofproto_port_get_cfm_opup(iface->port->bridge->ofproto,
                                     iface->ofp_port);
    if (opup >= 0) {
        ovsrec_interface_set_cfm_remote_opstate(cfg, opup ? "up" : "down");
    } else {
        ovsrec_interface_set_cfm_remote_opstate(cfg, NULL);
    }

    error = ofproto_port_get_cfm_remote_mpids(iface->port->bridge->ofproto,
                                              iface->ofp_port, &rmps, &n_rmps);
    if (error >= 0) {
        ovsrec_interface_set_cfm_remote_mpids(cfg, (const int64_t *)rmps,
                                              n_rmps);
    } else {
        ovsrec_interface_set_cfm_remote_mpids(cfg, NULL, 0);
    }

    health = ofproto_port_get_cfm_health(iface->port->bridge->ofproto,
                                        iface->ofp_port);
    if (health >= 0) {
        int64_t cfm_health = health;
        ovsrec_interface_set_cfm_health(cfg, &cfm_health, 1);
    } else {
        ovsrec_interface_set_cfm_health(cfg, NULL, 0);
    }
}

static void
iface_refresh_stats(struct iface *iface)
{
#define IFACE_STATS                             \
    IFACE_STAT(rx_packets,      "rx_packets")   \
    IFACE_STAT(tx_packets,      "tx_packets")   \
    IFACE_STAT(rx_bytes,        "rx_bytes")     \
    IFACE_STAT(tx_bytes,        "tx_bytes")     \
    IFACE_STAT(rx_dropped,      "rx_dropped")   \
    IFACE_STAT(tx_dropped,      "tx_dropped")   \
    IFACE_STAT(rx_errors,       "rx_errors")    \
    IFACE_STAT(tx_errors,       "tx_errors")    \
    IFACE_STAT(rx_frame_errors, "rx_frame_err") \
    IFACE_STAT(rx_over_errors,  "rx_over_err")  \
    IFACE_STAT(rx_crc_errors,   "rx_crc_err")   \
    IFACE_STAT(collisions,      "collisions")

#define IFACE_STAT(MEMBER, NAME) NAME,
    static char *keys[] = { IFACE_STATS };
#undef IFACE_STAT
    int64_t values[ARRAY_SIZE(keys)];
    int i;

    struct netdev_stats stats;

    if (iface_is_synthetic(iface)) {
        return;
    }

    /* Intentionally ignore return value, since errors will set 'stats' to
     * all-1s, and we will deal with that correctly below. */
    netdev_get_stats(iface->netdev, &stats);

    /* Copy statistics into values[] array. */
    i = 0;
#define IFACE_STAT(MEMBER, NAME) values[i++] = stats.MEMBER;
    IFACE_STATS;
#undef IFACE_STAT
    assert(i == ARRAY_SIZE(keys));

    ovsrec_interface_set_statistics(iface->cfg, keys, values,
                                    ARRAY_SIZE(keys));
#undef IFACE_STATS
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
    char *keys[3];
    int64_t int_values[3];
    struct smap smap;

    if (port_is_synthetic(port)) {
        return;
    }

    /* STP doesn't currently support bonds. */
    if (!list_is_singleton(&port->ifaces)) {
        ovsrec_port_set_status(port->cfg, NULL);
        return;
    }

    iface = CONTAINER_OF(list_front(&port->ifaces), struct iface, port_elem);

    if (ofproto_port_get_stp_status(ofproto, iface->ofp_port, &status)) {
        return;
    }

    if (!status.enabled) {
        ovsrec_port_set_status(port->cfg, NULL);
        ovsrec_port_set_statistics(port->cfg, NULL, NULL, 0);
        return;
    }

    /* Set Status column. */
    smap_init(&smap);
    smap_add_format(&smap, "stp_port_id", STP_PORT_ID_FMT, status.port_id);
    smap_add(&smap, "stp_state", stp_state_name(status.state));
    smap_add_format(&smap, "stp_sec_in_state", "%u", status.sec_in_state);
    smap_add(&smap, "stp_role", stp_role_name(status.role));
    ovsrec_port_set_status(port->cfg, &smap);
    smap_destroy(&smap);

    /* Set Statistics column. */
    keys[0] = "stp_tx_count";
    int_values[0] = status.tx_count;
    keys[1] = "stp_rx_count";
    int_values[1] = status.rx_count;
    keys[2] = "stp_error_count";
    int_values[2] = status.error_count;

    ovsrec_port_set_statistics(port->cfg, keys, int_values,
                               ARRAY_SIZE(int_values));
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
        ovsdb_idl_txn_write(&cfg->header_, &ovsrec_open_vswitch_col_statistics,
                            &datum);
        ovsdb_idl_txn_commit(txn);
        ovsdb_idl_txn_destroy(txn);

        free(stats);
    }
}

static inline const char *
nx_role_to_str(enum nx_role role)
{
    switch (role) {
    case NX_ROLE_OTHER:
        return "other";
    case NX_ROLE_MASTER:
        return "master";
    case NX_ROLE_SLAVE:
        return "slave";
    default:
        return "*** INVALID ROLE ***";
    }
}

static void
refresh_controller_status(void)
{
    struct bridge *br;
    struct shash info;
    const struct ovsrec_controller *cfg;

    shash_init(&info);

    /* Accumulate status for controllers on all bridges. */
    HMAP_FOR_EACH (br, node, &all_bridges) {
        ofproto_get_ofproto_controller_info(br->ofproto, &info);
    }

    /* Update each controller in the database with current status. */
    OVSREC_CONTROLLER_FOR_EACH(cfg, idl) {
        struct ofproto_controller_info *cinfo =
            shash_find_data(&info, cfg->target);

        if (cinfo) {
            struct smap smap = SMAP_INITIALIZER(&smap);
            const char **values = cinfo->pairs.values;
            const char **keys = cinfo->pairs.keys;
            size_t i;

            for (i = 0; i < cinfo->pairs.n; i++) {
                smap_add(&smap, keys[i], values[i]);
            }

            ovsrec_controller_set_is_connected(cfg, cinfo->is_connected);
            ovsrec_controller_set_role(cfg, nx_role_to_str(cinfo->role));
            ovsrec_controller_set_status(cfg, &smap);
            smap_destroy(&smap);
        } else {
            ovsrec_controller_set_is_connected(cfg, false);
            ovsrec_controller_set_role(cfg, NULL);
            ovsrec_controller_set_status(cfg, NULL);
        }
    }

    ofproto_free_ofproto_controller_info(&info);
}

static void
refresh_instant_stats(void)
{
    static struct ovsdb_idl_txn *txn = NULL;

    if (!txn) {
        struct bridge *br;

        txn = ovsdb_idl_txn_create(idl);

        HMAP_FOR_EACH (br, node, &all_bridges) {
            struct iface *iface;
            struct port *port;

            br_refresh_stp_status(br);

            HMAP_FOR_EACH (port, hmap_node, &br->ports) {
                port_refresh_stp_status(port);
            }

            HMAP_FOR_EACH (iface, name_node, &br->iface_by_name) {
                enum netdev_flags flags;
                const char *link_state;
                int64_t link_resets;
                int current, error;

                if (iface_is_synthetic(iface)) {
                    continue;
                }

                current = ofproto_port_is_lacp_current(br->ofproto,
                                                       iface->ofp_port);
                if (current >= 0) {
                    bool bl = current;
                    ovsrec_interface_set_lacp_current(iface->cfg, &bl, 1);
                } else {
                    ovsrec_interface_set_lacp_current(iface->cfg, NULL, 0);
                }

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

                iface_refresh_cfm_stats(iface);
            }
        }
    }

    if (ovsdb_idl_txn_commit(txn) != TXN_INCOMPLETE) {
        ovsdb_idl_txn_destroy(txn);
        txn = NULL;
    }
}

/* Performs periodic activity required by bridges that needs to be done with
 * the least possible latency.
 *
 * It makes sense to call this function a couple of times per poll loop, to
 * provide a significant performance boost on some benchmarks with ofprotos
 * that use the ofproto-dpif implementation. */
void
bridge_run_fast(void)
{
    struct bridge *br;

    HMAP_FOR_EACH (br, node, &all_bridges) {
        ofproto_run_fast(br->ofproto);
    }
}

void
bridge_run(void)
{
    static const struct ovsrec_open_vswitch null_cfg;
    const struct ovsrec_open_vswitch *cfg;
    struct ovsdb_idl_txn *reconf_txn = NULL;

    bool vlan_splinters_changed;
    struct bridge *br;

    ovsrec_open_vswitch_init((struct ovsrec_open_vswitch *) &null_cfg);

    /* (Re)configure if necessary. */
    if (!reconfiguring) {
        ovsdb_idl_run(idl);

        if (ovsdb_idl_is_lock_contended(idl)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            struct bridge *br, *next_br;

            VLOG_ERR_RL(&rl, "another ovs-vswitchd process is running, "
                        "disabling this process until it goes away");

            HMAP_FOR_EACH_SAFE (br, next_br, node, &all_bridges) {
                bridge_destroy(br);
            }
            return;
        } else if (!ovsdb_idl_has_lock(idl)) {
            return;
        }
    }
    cfg = ovsrec_open_vswitch_first(idl);

    /* Let each bridge do the work that it needs to do. */
    HMAP_FOR_EACH (br, node, &all_bridges) {
        ofproto_run(br->ofproto);
    }

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

    if (!reconfiguring) {
        /* If VLAN splinters are in use, then we need to reconfigure if VLAN
         * usage has changed. */
        vlan_splinters_changed = false;
        if (vlan_splinters_enabled_anywhere) {
            HMAP_FOR_EACH (br, node, &all_bridges) {
                if (ofproto_has_vlan_usage_changed(br->ofproto)) {
                    vlan_splinters_changed = true;
                    break;
                }
            }
        }

        if (ovsdb_idl_get_seqno(idl) != idl_seqno || vlan_splinters_changed) {
            idl_seqno = ovsdb_idl_get_seqno(idl);
            if (cfg) {
                reconf_txn = ovsdb_idl_txn_create(idl);
                bridge_reconfigure(cfg);
            } else {
                /* We still need to reconfigure to avoid dangling pointers to
                 * now-destroyed ovsrec structures inside bridge data. */
                bridge_reconfigure(&null_cfg);
            }
        }
    }

    if (reconfiguring) {
        if (cfg) {
            if (!reconf_txn) {
                reconf_txn = ovsdb_idl_txn_create(idl);
            }
            if (bridge_reconfigure_continue(cfg)) {
                ovsrec_open_vswitch_set_cur_cfg(cfg, cfg->next_cfg);
            }
        } else {
            bridge_reconfigure_continue(&null_cfg);
        }
    }

    if (reconf_txn) {
        ovsdb_idl_txn_commit(reconf_txn);
        ovsdb_idl_txn_destroy(reconf_txn);
        reconf_txn = NULL;
    }

    /* Refresh interface and mirror stats if necessary. */
    if (time_msec() >= iface_stats_timer) {
        if (cfg) {
            struct ovsdb_idl_txn *txn;

            txn = ovsdb_idl_txn_create(idl);
            HMAP_FOR_EACH (br, node, &all_bridges) {
                struct port *port;
                struct mirror *m;

                HMAP_FOR_EACH (port, hmap_node, &br->ports) {
                    struct iface *iface;

                    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                        iface_refresh_stats(iface);
                        iface_refresh_status(iface);
                    }
                }

                HMAP_FOR_EACH (m, hmap_node, &br->mirrors) {
                    mirror_refresh_stats(m);
                }

            }
            refresh_controller_status();
            ovsdb_idl_txn_commit(txn);
            ovsdb_idl_txn_destroy(txn); /* XXX */
        }

        iface_stats_timer = time_msec() + IFACE_STATS_INTERVAL;
    }

    run_system_stats();
    refresh_instant_stats();
}

void
bridge_wait(void)
{
    ovsdb_idl_wait(idl);

    if (reconfiguring) {
        poll_immediate_wake();
    }

    if (!hmap_is_empty(&all_bridges)) {
        struct bridge *br;

        HMAP_FOR_EACH (br, node, &all_bridges) {
            ofproto_wait(br->ofproto);
        }
        poll_timer_wait_until(iface_stats_timer);
    }

    system_stats_wait();
}

/* Adds some memory usage statistics for bridges into 'usage', for use with
 * memory_report(). */
void
bridge_get_memory_usage(struct simap *usage)
{
    struct bridge *br;

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
qos_unixctl_show_cb(unsigned int queue_id,
                    const struct smap *details,
                    void *aux)
{
    struct qos_unixctl_show_cbdata *data = aux;
    struct ds *ds = data->ds;
    struct iface *iface = data->iface;
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
                      queue_id, strerror(error));
    }
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
    struct qos_unixctl_show_cbdata data;
    int error;

    iface = iface_find(argv[1]);
    if (!iface) {
        unixctl_command_reply_error(conn, "no such interface");
        return;
    }

    netdev_get_qos(iface->netdev, &type, &smap);

    if (*type != '\0') {
        ds_put_format(&ds, "QoS: %s %s\n", iface->name, type);

        SMAP_FOR_EACH (node, &smap) {
            ds_put_format(&ds, "%s: %s\n", node->key, node->value);
        }

        data.ds = &ds;
        data.iface = iface;
        error = netdev_dump_queues(iface->netdev, qos_unixctl_show_cb, &data);

        if (error) {
            ds_put_format(&ds, "failed to dump queues: %s", strerror(error));
        }
        unixctl_command_reply(conn, ds_cstr(&ds));
    } else {
        ds_put_format(&ds, "QoS not configured on %s\n", iface->name);
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

    assert(!bridge_lookup(br_cfg->name));
    br = xzalloc(sizeof *br);

    br->name = xstrdup(br_cfg->name);
    br->type = xstrdup(ofproto_normalize_type(br_cfg->datapath_type));
    br->cfg = br_cfg;

    /* Derive the default Ethernet address from the bridge's UUID.  This should
     * be unique and it will be stable between ovs-vswitchd runs.  */
    memcpy(br->default_ea, &br_cfg->header_.uuid, ETH_ADDR_LEN);
    eth_addr_mark_random(br->default_ea);

    hmap_init(&br->ports);
    hmap_init(&br->ifaces);
    hmap_init(&br->iface_by_name);
    hmap_init(&br->mirrors);

    hmap_init(&br->if_cfg_todo);
    list_init(&br->ofpp_garbage);

    hmap_insert(&all_bridges, &br->node, hash_string(br->name, 0));
}

static void
bridge_destroy(struct bridge *br)
{
    if (br) {
        struct mirror *mirror, *next_mirror;
        struct port *port, *next_port;
        struct if_cfg *if_cfg, *next_if_cfg;
        struct ofpp_garbage *garbage, *next_garbage;

        HMAP_FOR_EACH_SAFE (port, next_port, hmap_node, &br->ports) {
            port_destroy(port);
        }
        HMAP_FOR_EACH_SAFE (mirror, next_mirror, hmap_node, &br->mirrors) {
            mirror_destroy(mirror);
        }
        HMAP_FOR_EACH_SAFE (if_cfg, next_if_cfg, hmap_node, &br->if_cfg_todo) {
            hmap_remove(&br->if_cfg_todo, &if_cfg->hmap_node);
            free(if_cfg);
        }
        LIST_FOR_EACH_SAFE (garbage, next_garbage, list_node,
                            &br->ofpp_garbage) {
            list_remove(&garbage->list_node);
            free(garbage);
        }

        hmap_remove(&all_bridges, &br->node);
        ofproto_destroy(br->ofproto);
        hmap_destroy(&br->ifaces);
        hmap_destroy(&br->ports);
        hmap_destroy(&br->iface_by_name);
        hmap_destroy(&br->mirrors);
        hmap_destroy(&br->if_cfg_todo);
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
bridge_queue_if_cfg(struct bridge *br,
                    const struct ovsrec_interface *cfg,
                    const struct ovsrec_port *parent)
{
    struct if_cfg *if_cfg = xmalloc(sizeof *if_cfg);

    if_cfg->cfg = cfg;
    if_cfg->parent = parent;
    hmap_insert(&br->if_cfg_todo, &if_cfg->hmap_node,
                hash_string(if_cfg->cfg->name, 0));
}

/* Deletes "struct port"s and "struct iface"s under 'br' which aren't
 * consistent with 'br->cfg'.  Updates 'br->if_cfg_queue' with interfaces which
 * 'br' needs to complete its configuration. */
static void
bridge_add_del_ports(struct bridge *br,
                     const unsigned long int *splinter_vlans)
{
    struct shash_node *port_node;
    struct port *port, *next;
    struct shash new_ports;
    size_t i;

    assert(hmap_is_empty(&br->if_cfg_todo));

    /* Collect new ports. */
    shash_init(&new_ports);
    for (i = 0; i < br->cfg->n_ports; i++) {
        const char *name = br->cfg->ports[i]->name;
        if (!shash_add_once(&new_ports, name, br->cfg->ports[i])) {
            VLOG_WARN("bridge %s: %s specified twice as bridge port",
                      br->name, name);
        }
    }
    if (bridge_get_controllers(br, NULL)
        && !shash_find(&new_ports, br->name)) {
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

        shash_add(&new_ports, br->name, &br->synth_local_port);
    }

    if (splinter_vlans) {
        add_vlan_splinter_ports(br, splinter_vlans, &new_ports);
    }

    /* Get rid of deleted ports.
     * Get rid of deleted interfaces on ports that still exist. */
    HMAP_FOR_EACH_SAFE (port, next, hmap_node, &br->ports) {
        port->cfg = shash_find_data(&new_ports, port->name);
        if (!port->cfg) {
            port_destroy(port);
        } else {
            port_del_ifaces(port);
        }
    }

    /* Update iface->cfg and iface->type in interfaces that still exist.
     * Add new interfaces to creation queue. */
    SHASH_FOR_EACH (port_node, &new_ports) {
        const struct ovsrec_port *port = port_node->data;
        size_t i;

        for (i = 0; i < port->n_interfaces; i++) {
            const struct ovsrec_interface *cfg = port->interfaces[i];
            struct iface *iface = iface_lookup(br, cfg->name);
            const char *type = iface_get_type(cfg, br->cfg);

            if (iface) {
                iface->cfg = cfg;
                iface->type = type;
            } else if (!strcmp(type, "null")) {
                VLOG_WARN_ONCE("%s: The null interface type is deprecated and"
                               " may be removed in February 2013. Please email"
                               " dev@openvswitch.org with concerns.",
                               cfg->name);
            } else {
                bridge_queue_if_cfg(br, cfg, port);
            }
        }
    }

    shash_destroy(&new_ports);
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
    if (!local_iface || !c->local_ip || !inet_aton(c->local_ip, &ip)) {
        return;
    }

    /* Bring up the local interface. */
    netdev = local_iface->netdev;
    netdev_turn_flags_on(netdev, NETDEV_UP, true);

    /* Configure the IP address and netmask. */
    if (!c->local_netmask
        || !inet_aton(c->local_netmask, &mask)
        || !mask.s_addr) {
        mask.s_addr = guess_netmask(ip.s_addr);
    }
    if (!netdev_set_in4(netdev, ip, mask)) {
        VLOG_INFO("bridge %s: configured IP address "IP_FMT", netmask "IP_FMT,
                  br->name, IP_ARGS(&ip.s_addr), IP_ARGS(&mask.s_addr));
    }

    /* Configure the default gateway. */
    if (c->local_gateway
        && inet_aton(c->local_gateway, &gateway)
        && gateway.s_addr) {
        if (!netdev_add_router(netdev, gateway)) {
            VLOG_INFO("bridge %s: configured gateway "IP_FMT,
                      br->name, IP_ARGS(&gateway.s_addr));
        }
    }
}

/* Returns true if 'a' and 'b' are the same except that any number of slashes
 * in either string are treated as equal to any number of slashes in the other,
 * e.g. "x///y" is equal to "x/y". */
static bool
equal_pathnames(const char *a, const char *b)
{
    while (*a == *b) {
        if (*a == '/') {
            a += strspn(a, "/");
            b += strspn(b, "/");
        } else if (*a == '\0') {
            return true;
        } else {
            a++;
            b++;
        }
    }
    return false;
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

        if (!strncmp(c->target, "punix:", 6)
            || !strncmp(c->target, "unix:", 5)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            char *whitelist;

            whitelist = xasprintf("unix:%s/%s.controller",
                                  ovs_rundir(), br->name);
            if (!equal_pathnames(c->target, whitelist)) {
                /* Prevent remote ovsdb-server users from accessing arbitrary
                 * Unix domain sockets and overwriting arbitrary local
                 * files. */
                VLOG_ERR_RL(&rl, "bridge %s: Not adding Unix domain socket "
                            "controller \"%s\" due to possibility for remote "
                            "exploit.  Instead, specify whitelisted \"%s\" or "
                            "connect to \"unix:%s/%s.mgmt\" (which is always "
                            "available without special configuration).",
                            br->name, c->target, whitelist,
                            ovs_rundir(), br->name);
                free(whitelist);
                continue;
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

    ofproto_set_controllers(br->ofproto, ocs, n_ocs);
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

        s.name = NULL;
        s.max_flows = UINT_MAX;
        s.groups = NULL;
        s.n_groups = 0;

        if (j < br->cfg->n_flow_tables && i == br->cfg->key_flow_tables[j]) {
            struct ovsrec_flow_table *cfg = br->cfg->value_flow_tables[j++];

            s.name = cfg->name;
            if (cfg->n_flow_limit && *cfg->flow_limit < UINT_MAX) {
                s.max_flows = *cfg->flow_limit;
            }
            if (cfg->overflow_policy
                && !strcmp(cfg->overflow_policy, "evict")) {
                size_t k;

                s.groups = xmalloc(cfg->n_groups * sizeof *s.groups);
                for (k = 0; k < cfg->n_groups; k++) {
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

/* Port functions. */

static struct port *
port_create(struct bridge *br, const struct ovsrec_port *cfg)
{
    struct port *port;

    port = xzalloc(sizeof *port);
    port->bridge = br;
    port->name = xstrdup(cfg->name);
    port->cfg = cfg;
    list_init(&port->ifaces);

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
        const char *name = port->cfg->interfaces[i]->name;
        const char *type = port->cfg->interfaces[i]->type;
        if (strcmp(type, "null")) {
            sset_add(&new_ifaces, name);
        }
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
            iface_destroy(iface);
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
        if (sscanf(system_id, ETH_ADDR_SCAN_FMT,
                   ETH_ADDR_SCAN_ARGS(s->id)) != ETH_ADDR_SCAN_COUNT) {
            VLOG_WARN("port %s: LACP system ID (%s) must be an Ethernet"
                      " address.", port->name, system_id);
            return NULL;
        }
    } else {
        memcpy(s->id, port->bridge->ea, ETH_ADDR_LEN);
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
                   : UINT16_MAX - !list_is_short(&port->ifaces));

    lacp_time = smap_get(&port->cfg->other_config, "lacp-time");
    s->fast = lacp_time && !strcasecmp(lacp_time, "fast");
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
        portid = iface->ofp_port;
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
port_configure_bond(struct port *port, struct bond_settings *s,
                    uint32_t *bond_stable_ids)
{
    const char *detect_s;
    struct iface *iface;
    int miimon_interval;
    size_t i;

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

    s->fake_iface = port->cfg->bond_fake_iface;

    i = 0;
    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
        long long stable_id;

        stable_id = smap_get_int(&iface->cfg->other_config, "bond-stable-id",
                                 0);
        if (stable_id <= 0 || stable_id >= UINT32_MAX) {
            stable_id = iface->ofp_port;
        }
        bond_stable_ids[i++] = stable_id;

        netdev_set_miimon_interval(iface->netdev, miimon_interval);
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

/* Returns the correct network device type for interface 'iface' in bridge
 * 'br'. */
static const char *
iface_get_type(const struct ovsrec_interface *iface,
               const struct ovsrec_bridge *br)
{
    /* The local port always has type "internal".  Other ports take their type
     * from the database and default to "system" if none is specified. */
    return (!strcmp(iface->name, br->name) ? "internal"
            : iface->type[0] ? iface->type
            : "system");
}

static void
iface_destroy(struct iface *iface)
{
    if (iface) {
        struct port *port = iface->port;
        struct bridge *br = port->bridge;

        if (br->ofproto && iface->ofp_port >= 0) {
            ofproto_port_unregister(br->ofproto, iface->ofp_port);
        }

        if (iface->ofp_port >= 0) {
            hmap_remove(&br->ifaces, &iface->ofp_port_node);
        }

        list_remove(&iface->port_elem);
        hmap_remove(&br->iface_by_name, &iface->name_node);

        netdev_close(iface->netdev);

        free(iface->name);
        free(iface);
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

static struct if_cfg *
if_cfg_lookup(const struct bridge *br, const char *name)
{
    struct if_cfg *if_cfg;

    HMAP_FOR_EACH_WITH_HASH (if_cfg, hmap_node, hash_string(name, 0),
                             &br->if_cfg_todo) {
        if (!strcmp(if_cfg->cfg->name, name)) {
            return if_cfg;
        }
    }

    return NULL;
}

static struct iface *
iface_from_ofp_port(const struct bridge *br, uint16_t ofp_port)
{
    struct iface *iface;

    HMAP_FOR_EACH_IN_BUCKET (iface, ofp_port_node,
                             hash_int(ofp_port, 0), &br->ifaces) {
        if (iface->ofp_port == ofp_port) {
            return iface;
        }
    }
    return NULL;
}

/* Set Ethernet address of 'iface', if one is specified in the configuration
 * file. */
static void
iface_set_mac(struct iface *iface)
{
    uint8_t ea[ETH_ADDR_LEN];

    if (!strcmp(iface->type, "internal")
        && iface->cfg->mac && eth_addr_from_string(iface->cfg->mac, ea)) {
        if (iface->ofp_port == OFPP_LOCAL) {
            VLOG_ERR("interface %s: ignoring mac in Interface record "
                     "(use Bridge record to set local port's mac)",
                     iface->name);
        } else if (eth_addr_is_multicast(ea)) {
            VLOG_ERR("interface %s: cannot set MAC to multicast address",
                     iface->name);
        } else {
            int error = netdev_set_etheraddr(iface->netdev, ea);
            if (error) {
                VLOG_ERR("interface %s: setting MAC failed (%s)",
                         iface->name, strerror(error));
            }
        }
    }
}

/* Sets the ofport column of 'if_cfg' to 'ofport'. */
static void
iface_set_ofport(const struct ovsrec_interface *if_cfg, int64_t ofport)
{
    if (if_cfg && !ovsdb_idl_row_is_synthetic(&if_cfg->header_)) {
        ovsrec_interface_set_ofport(if_cfg, &ofport, 1);
    }
}

/* Clears all of the fields in 'if_cfg' that indicate interface status, and
 * sets the "ofport" field to -1.
 *
 * This is appropriate when 'if_cfg''s interface cannot be created or is
 * otherwise invalid. */
static void
iface_clear_db_record(const struct ovsrec_interface *if_cfg)
{
    if (!ovsdb_idl_row_is_synthetic(&if_cfg->header_)) {
        iface_set_ofport(if_cfg, -1);
        ovsrec_interface_set_status(if_cfg, NULL);
        ovsrec_interface_set_admin_state(if_cfg, NULL);
        ovsrec_interface_set_duplex(if_cfg, NULL);
        ovsrec_interface_set_link_speed(if_cfg, NULL, 0);
        ovsrec_interface_set_link_state(if_cfg, NULL);
        ovsrec_interface_set_mtu(if_cfg, NULL, 0);
        ovsrec_interface_set_cfm_fault(if_cfg, NULL, 0);
        ovsrec_interface_set_cfm_fault_status(if_cfg, NULL, 0);
        ovsrec_interface_set_cfm_remote_mpids(if_cfg, NULL, 0);
        ovsrec_interface_set_lacp_current(if_cfg, NULL, 0);
        ovsrec_interface_set_statistics(if_cfg, NULL, NULL, 0);
    }
}

struct iface_delete_queues_cbdata {
    struct netdev *netdev;
    const struct ovsdb_datum *queues;
};

static bool
queue_ids_include(const struct ovsdb_datum *queues, int64_t target)
{
    union ovsdb_atom atom;

    atom.integer = target;
    return ovsdb_datum_find_key(queues, &atom, OVSDB_TYPE_INTEGER) != UINT_MAX;
}

static void
iface_delete_queues(unsigned int queue_id,
                    const struct smap *details OVS_UNUSED, void *cbdata_)
{
    struct iface_delete_queues_cbdata *cbdata = cbdata_;

    if (!queue_ids_include(cbdata->queues, queue_id)) {
        netdev_delete_queue(cbdata->netdev, queue_id);
    }
}

static void
iface_configure_qos(struct iface *iface, const struct ovsrec_qos *qos)
{
    struct ofpbuf queues_buf;

    ofpbuf_init(&queues_buf, 0);

    if (!qos || qos->type[0] == '\0' || qos->n_queues < 1) {
        netdev_set_qos(iface->netdev, NULL, NULL);
    } else {
        struct iface_delete_queues_cbdata cbdata;
        bool queue_zero;
        size_t i;

        /* Configure top-level Qos for 'iface'. */
        netdev_set_qos(iface->netdev, qos->type, &qos->other_config);

        /* Deconfigure queues that were deleted. */
        cbdata.netdev = iface->netdev;
        cbdata.queues = ovsrec_qos_get_queues(qos, OVSDB_TYPE_INTEGER,
                                              OVSDB_TYPE_UUID);
        netdev_dump_queues(iface->netdev, iface_delete_queues, &cbdata);

        /* Configure queues for 'iface'. */
        queue_zero = false;
        for (i = 0; i < qos->n_queues; i++) {
            const struct ovsrec_queue *queue = qos->value_queues[i];
            unsigned int queue_id = qos->key_queues[i];

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
            struct smap details;

            smap_init(&details);
            netdev_set_queue(iface->netdev, 0, &details);
            smap_destroy(&details);
        }
    }

    if (iface->ofp_port >= 0) {
        const struct ofproto_port_queue *port_queues = queues_buf.data;
        size_t n_queues = queues_buf.size / sizeof *port_queues;

        ofproto_port_set_queues(iface->port->bridge->ofproto, iface->ofp_port,
                                port_queues, n_queues);
    }

    netdev_set_policing(iface->netdev,
                        iface->cfg->ingress_policing_rate,
                        iface->cfg->ingress_policing_burst);

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
        struct mirror *m = mirror_find_by_uuid(br, &cfg->header_.uuid);
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

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

static struct ovsrec_port **recs;
static size_t n_recs, allocated_recs;

/* Adds 'rec' to a list of recs that have to be destroyed when the VLAN
 * splinters are reconfigured. */
static void
register_rec(struct ovsrec_port *rec)
{
    if (n_recs >= allocated_recs) {
        recs = x2nrealloc(recs, &allocated_recs, sizeof *recs);
    }
    recs[n_recs++] = rec;
}

/* Frees all of the ports registered with register_reg(). */
static void
free_registered_recs(void)
{
    size_t i;

    for (i = 0; i < n_recs; i++) {
        struct ovsrec_port *port = recs[i];
        size_t j;

        for (j = 0; j < port->n_interfaces; j++) {
            struct ovsrec_interface *iface = port->interfaces[j];
            free(iface->name);
            free(iface);
        }

        smap_destroy(&port->other_config);
        free(port->interfaces);
        free(port->name);
        free(port->tag);
        free(port);
    }
    n_recs = 0;
}

/* Returns true if VLAN splinters are enabled on 'iface_cfg', false
 * otherwise. */
static bool
vlan_splinters_is_enabled(const struct ovsrec_interface *iface_cfg)
{
    return smap_get_bool(&iface_cfg->other_config, "enable-vlan-splinters",
                         false);
}

/* Figures out the set of VLANs that are in use for the purpose of VLAN
 * splinters.
 *
 * If VLAN splinters are enabled on at least one interface and any VLANs are in
 * use, returns a 4096-bit bitmap with a 1-bit for each in-use VLAN (bits 0 and
 * 4095 will not be set).  The caller is responsible for freeing the bitmap,
 * with free().
 *
 * If VLANs splinters are not enabled on any interface or if no VLANs are in
 * use, returns NULL.
 *
 * Updates 'vlan_splinters_enabled_anywhere'. */
static unsigned long int *
collect_splinter_vlans(const struct ovsrec_open_vswitch *ovs_cfg)
{
    unsigned long int *splinter_vlans;
    struct sset splinter_ifaces;
    const char *real_dev_name;
    struct shash *real_devs;
    struct shash_node *node;
    struct bridge *br;
    size_t i;

    /* Free space allocated for synthesized ports and interfaces, since we're
     * in the process of reconstructing all of them. */
    free_registered_recs();

    splinter_vlans = bitmap_allocate(4096);
    sset_init(&splinter_ifaces);
    vlan_splinters_enabled_anywhere = false;
    for (i = 0; i < ovs_cfg->n_bridges; i++) {
        struct ovsrec_bridge *br_cfg = ovs_cfg->bridges[i];
        size_t j;

        for (j = 0; j < br_cfg->n_ports; j++) {
            struct ovsrec_port *port_cfg = br_cfg->ports[j];
            int k;

            for (k = 0; k < port_cfg->n_interfaces; k++) {
                struct ovsrec_interface *iface_cfg = port_cfg->interfaces[k];

                if (vlan_splinters_is_enabled(iface_cfg)) {
                    vlan_splinters_enabled_anywhere = true;
                    sset_add(&splinter_ifaces, iface_cfg->name);
                    vlan_bitmap_from_array__(port_cfg->trunks,
                                             port_cfg->n_trunks,
                                             splinter_vlans);
                }
            }

            if (port_cfg->tag && *port_cfg->tag > 0 && *port_cfg->tag < 4095) {
                bitmap_set1(splinter_vlans, *port_cfg->tag);
            }
        }
    }

    if (!vlan_splinters_enabled_anywhere) {
        free(splinter_vlans);
        sset_destroy(&splinter_ifaces);
        return NULL;
    }

    HMAP_FOR_EACH (br, node, &all_bridges) {
        if (br->ofproto) {
            ofproto_get_vlan_usage(br->ofproto, splinter_vlans);
        }
    }

    /* Don't allow VLANs 0 or 4095 to be splintered.  VLAN 0 should appear on
     * the real device.  VLAN 4095 is reserved and Linux doesn't allow a VLAN
     * device to be created for it. */
    bitmap_set0(splinter_vlans, 0);
    bitmap_set0(splinter_vlans, 4095);

    /* Delete all VLAN devices that we don't need. */
    vlandev_refresh();
    real_devs = vlandev_get_real_devs();
    SHASH_FOR_EACH (node, real_devs) {
        const struct vlan_real_dev *real_dev = node->data;
        const struct vlan_dev *vlan_dev;
        bool real_dev_has_splinters;

        real_dev_has_splinters = sset_contains(&splinter_ifaces,
                                               real_dev->name);
        HMAP_FOR_EACH (vlan_dev, hmap_node, &real_dev->vlan_devs) {
            if (!real_dev_has_splinters
                || !bitmap_is_set(splinter_vlans, vlan_dev->vid)) {
                struct netdev *netdev;

                if (!netdev_open(vlan_dev->name, "system", &netdev)) {
                    if (!netdev_get_in4(netdev, NULL, NULL) ||
                        !netdev_get_in6(netdev, NULL)) {
                        /* It has an IP address configured, so we don't own
                         * it.  Don't delete it. */
                    } else {
                        vlandev_del(vlan_dev->name);
                    }
                    netdev_close(netdev);
                }
            }

        }
    }

    /* Add all VLAN devices that we need. */
    SSET_FOR_EACH (real_dev_name, &splinter_ifaces) {
        int vid;

        BITMAP_FOR_EACH_1 (vid, 4096, splinter_vlans) {
            if (!vlandev_get_name(real_dev_name, vid)) {
                vlandev_add(real_dev_name, vid);
            }
        }
    }

    vlandev_refresh();

    sset_destroy(&splinter_ifaces);

    if (bitmap_scan(splinter_vlans, 0, 4096) >= 4096) {
        free(splinter_vlans);
        return NULL;
    }
    return splinter_vlans;
}

/* Pushes the configure of VLAN splinter port 'port' (e.g. eth0.9) down to
 * ofproto.  */
static void
configure_splinter_port(struct port *port)
{
    struct ofproto *ofproto = port->bridge->ofproto;
    uint16_t realdev_ofp_port;
    const char *realdev_name;
    struct iface *vlandev, *realdev;

    ofproto_bundle_unregister(port->bridge->ofproto, port);

    vlandev = CONTAINER_OF(list_front(&port->ifaces), struct iface,
                           port_elem);

    realdev_name = smap_get(&port->cfg->other_config, "realdev");
    realdev = iface_lookup(port->bridge, realdev_name);
    realdev_ofp_port = realdev ? realdev->ofp_port : 0;

    ofproto_port_set_realdev(ofproto, vlandev->ofp_port, realdev_ofp_port,
                             *port->cfg->tag);
}

static struct ovsrec_port *
synthesize_splinter_port(const char *real_dev_name,
                         const char *vlan_dev_name, int vid)
{
    struct ovsrec_interface *iface;
    struct ovsrec_port *port;

    iface = xmalloc(sizeof *iface);
    ovsrec_interface_init(iface);
    iface->name = xstrdup(vlan_dev_name);
    iface->type = "system";

    port = xmalloc(sizeof *port);
    ovsrec_port_init(port);
    port->interfaces = xmemdup(&iface, sizeof iface);
    port->n_interfaces = 1;
    port->name = xstrdup(vlan_dev_name);
    port->vlan_mode = "splinter";
    port->tag = xmalloc(sizeof *port->tag);
    *port->tag = vid;

    smap_add(&port->other_config, "realdev", real_dev_name);

    register_rec(port);
    return port;
}

/* For each interface with 'br' that has VLAN splinters enabled, adds a
 * corresponding ovsrec_port to 'ports' for each splinter VLAN marked with a
 * 1-bit in the 'splinter_vlans' bitmap. */
static void
add_vlan_splinter_ports(struct bridge *br,
                        const unsigned long int *splinter_vlans,
                        struct shash *ports)
{
    size_t i;

    /* We iterate through 'br->cfg->ports' instead of 'ports' here because
     * we're modifying 'ports'. */
    for (i = 0; i < br->cfg->n_ports; i++) {
        const char *name = br->cfg->ports[i]->name;
        struct ovsrec_port *port_cfg = shash_find_data(ports, name);
        size_t j;

        for (j = 0; j < port_cfg->n_interfaces; j++) {
            struct ovsrec_interface *iface_cfg = port_cfg->interfaces[j];

            if (vlan_splinters_is_enabled(iface_cfg)) {
                const char *real_dev_name;
                uint16_t vid;

                real_dev_name = iface_cfg->name;
                BITMAP_FOR_EACH_1 (vid, 4096, splinter_vlans) {
                    const char *vlan_dev_name;

                    vlan_dev_name = vlandev_get_name(real_dev_name, vid);
                    if (vlan_dev_name
                        && !shash_find(ports, vlan_dev_name)) {
                        shash_add(ports, vlan_dev_name,
                                  synthesize_splinter_port(
                                      real_dev_name, vlan_dev_name, vid));
                    }
                }
            }
        }
    }
}

static void
mirror_refresh_stats(struct mirror *m)
{
    struct ofproto *ofproto = m->bridge->ofproto;
    uint64_t tx_packets, tx_bytes;
    char *keys[2];
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
