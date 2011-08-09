/* Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks
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
#include "jsonrpc.h"
#include "lacp.h"
#include "list.h"
#include "netdev.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "poll-loop.h"
#include "sha1.h"
#include "shash.h"
#include "socket-util.h"
#include "stream-ssl.h"
#include "sset.h"
#include "system-stats.h"
#include "timeval.h"
#include "util.h"
#include "unixctl.h"
#include "vswitchd/vswitch-idl.h"
#include "xenserver.h"
#include "vlog.h"
#include "sflow_api.h"
#include "vlan-bitmap.h"

VLOG_DEFINE_THIS_MODULE(bridge);

COVERAGE_DEFINE(bridge_reconfigure);

struct iface {
    /* These members are always valid. */
    struct list port_elem;      /* Element in struct port's "ifaces" list. */
    struct hmap_node name_node; /* In struct bridge's "iface_by_name" hmap. */
    struct port *port;          /* Containing port. */
    char *name;                 /* Host network device name. */
    tag_type tag;               /* Tag associated with this interface. */

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
};

struct port {
    struct bridge *bridge;
    struct hmap_node hmap_node; /* Element in struct bridge's "ports" hmap. */
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

/* Each time this timer expires, the bridge fetches systems and interface
 * statistics and pushes them into the database. */
#define STATS_INTERVAL (5 * 1000) /* In milliseconds. */
static long long int stats_timer = LLONG_MIN;

/* Stores the time after which rate limited statistics may be written to the
 * database.  Only updated when changes to the database require rate limiting.
 */
#define DB_LIMIT_INTERVAL (1 * 1000) /* In milliseconds. */
static long long int db_limiter = LLONG_MIN;

static void add_del_bridges(const struct ovsrec_open_vswitch *);
static void bridge_del_ofprotos(void);
static bool bridge_add_ofprotos(struct bridge *);
static void bridge_create(const struct ovsrec_bridge *);
static void bridge_destroy(struct bridge *);
static struct bridge *bridge_lookup(const char *name);
static unixctl_cb_func bridge_unixctl_dump_flows;
static unixctl_cb_func bridge_unixctl_reconnect;
static size_t bridge_get_controllers(const struct bridge *br,
                                     struct ovsrec_controller ***controllersp);
static void bridge_add_del_ports(struct bridge *);
static void bridge_add_ofproto_ports(struct bridge *);
static void bridge_del_ofproto_ports(struct bridge *);
static void bridge_refresh_ofp_port(struct bridge *);
static void bridge_configure_datapath_id(struct bridge *);
static void bridge_configure_flow_eviction_threshold(struct bridge *);
static void bridge_configure_netflow(struct bridge *);
static void bridge_configure_forward_bpdu(struct bridge *);
static void bridge_configure_sflow(struct bridge *, int *sflow_bridge_number);
static void bridge_configure_remotes(struct bridge *,
                                     const struct sockaddr_in *managers,
                                     size_t n_managers);
static void bridge_pick_local_hw_addr(struct bridge *,
                                      uint8_t ea[ETH_ADDR_LEN],
                                      struct iface **hw_addr_iface);
static uint64_t bridge_pick_datapath_id(struct bridge *,
                                        const uint8_t bridge_ea[ETH_ADDR_LEN],
                                        struct iface *hw_addr_iface);
static uint64_t dpid_from_hash(const void *, size_t nbytes);
static bool bridge_has_bond_fake_iface(const struct bridge *,
                                       const char *name);
static bool port_is_bond_fake_iface(const struct port *);

static unixctl_cb_func qos_unixctl_show;

static struct port *port_create(struct bridge *, const struct ovsrec_port *);
static void port_add_ifaces(struct port *);
static void port_del_ifaces(struct port *);
static void port_destroy(struct port *);
static struct port *port_lookup(const struct bridge *, const char *name);
static void port_configure(struct port *);
static struct lacp_settings *port_configure_lacp(struct port *,
                                                 struct lacp_settings *);
static void port_configure_bond(struct port *, struct bond_settings *,
                                uint32_t *bond_stable_ids);

static void bridge_configure_mirrors(struct bridge *);
static struct mirror *mirror_create(struct bridge *,
                                    const struct ovsrec_mirror *);
static void mirror_destroy(struct mirror *);
static bool mirror_configure(struct mirror *, const struct ovsrec_mirror *);

static void iface_configure_lacp(struct iface *, struct lacp_slave_settings *);
static struct iface *iface_create(struct port *port,
                                  const struct ovsrec_interface *if_cfg);
static void iface_destroy(struct iface *);
static struct iface *iface_lookup(const struct bridge *, const char *name);
static struct iface *iface_find(const char *name);
static struct iface *iface_from_ofp_port(const struct bridge *,
                                         uint16_t ofp_port);
static void iface_set_mac(struct iface *);
static void iface_set_ofport(const struct ovsrec_interface *, int64_t ofport);
static void iface_configure_qos(struct iface *, const struct ovsrec_qos *);
static void iface_configure_cfm(struct iface *);
static bool iface_refresh_cfm_stats(struct iface *);
static void iface_refresh_stats(struct iface *);
static void iface_refresh_status(struct iface *);
static bool iface_get_carrier(const struct iface *);
static bool iface_is_synthetic(const struct iface *);

static void shash_from_ovs_idl_map(char **keys, char **values, size_t n,
                                   struct shash *);
static void shash_to_ovs_idl_map(struct shash *,
                                 char ***keys, char ***values, size_t *n);

/* Public functions. */

/* Initializes the bridge module, configuring it to obtain its configuration
 * from an OVSDB server accessed over 'remote', which should be a string in a
 * form acceptable to ovsdb_idl_create(). */
void
bridge_init(const char *remote)
{
    /* Create connection to database. */
    idl = ovsdb_idl_create(remote, &ovsrec_idl_class, true);
    ovsdb_idl_set_lock(idl, "ovs_vswitchd");

    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_cur_cfg);
    ovsdb_idl_omit_alert(idl, &ovsrec_open_vswitch_col_statistics);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_ovs_version);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_db_version);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_system_type);
    ovsdb_idl_omit(idl, &ovsrec_open_vswitch_col_system_version);

    ovsdb_idl_omit_alert(idl, &ovsrec_bridge_col_datapath_id);
    ovsdb_idl_omit(idl, &ovsrec_bridge_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_port_col_fake_bridge);

    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_admin_state);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_duplex);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_link_speed);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_link_state);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_mtu);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_statistics);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_status);
    ovsdb_idl_omit(idl, &ovsrec_interface_col_external_ids);

    ovsdb_idl_omit_alert(idl, &ovsrec_controller_col_is_connected);
    ovsdb_idl_omit_alert(idl, &ovsrec_controller_col_role);
    ovsdb_idl_omit_alert(idl, &ovsrec_controller_col_status);
    ovsdb_idl_omit(idl, &ovsrec_controller_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_qos_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_queue_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_mirror_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_netflow_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_sflow_col_external_ids);

    ovsdb_idl_omit(idl, &ovsrec_manager_col_external_ids);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_inactivity_probe);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_is_connected);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_max_backoff);
    ovsdb_idl_omit(idl, &ovsrec_manager_col_status);

    ovsdb_idl_omit(idl, &ovsrec_ssl_col_external_ids);

    /* Register unixctl commands. */
    unixctl_command_register("qos/show", qos_unixctl_show, NULL);
    unixctl_command_register("bridge/dump-flows", bridge_unixctl_dump_flows,
                             NULL);
    unixctl_command_register("bridge/reconnect", bridge_unixctl_reconnect,
                             NULL);
    lacp_init();
    bond_init();
    cfm_init();
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

            if ((!strncmp(target, "tcp:", 4)
                 && inet_parse_active(target + 4, JSONRPC_TCP_PORT, sin)) ||
                (!strncmp(target, "ssl:", 4)
                 && inet_parse_active(target + 4, JSONRPC_SSL_PORT, sin))) {
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
    struct sockaddr_in *managers;
    struct bridge *br, *next;
    int sflow_bridge_number;
    size_t n_managers;

    COVERAGE_INC(bridge_reconfigure);

    /* Create and destroy "struct bridge"s, "struct port"s, and "struct
     * iface"s according to 'ovs_cfg', with only very minimal configuration
     * otherwise.
     *
     * This is purely an update to bridge data structures.  Nothing is pushed
     * down to ofproto or lower layers. */
    add_del_bridges(ovs_cfg);
    HMAP_FOR_EACH (br, node, &all_bridges) {
        bridge_add_del_ports(br);
    }

    /* Delete all datapaths and datapath ports that are no longer configured.
     *
     * The kernel will reject any attempt to add a given port to a datapath if
     * that port already belongs to a different datapath, so we must do all
     * port deletions before any port additions.  A datapath always has a
     * "local port" so we must delete not-configured datapaths too. */
    bridge_del_ofprotos();
    HMAP_FOR_EACH (br, node, &all_bridges) {
        if (br->ofproto) {
            bridge_del_ofproto_ports(br);
        }
    }

    /* Create datapaths and datapath ports that are missing.
     *
     * After this is done, we have our final set of bridges, ports, and
     * interfaces.  Every "struct bridge" has an ofproto, every "struct port"
     * has at least one iface, every "struct iface" has a valid ofp_port and
     * netdev. */
    HMAP_FOR_EACH_SAFE (br, next, node, &all_bridges) {
        if (!br->ofproto && !bridge_add_ofprotos(br)) {
            bridge_destroy(br);
        }
    }
    HMAP_FOR_EACH (br, node, &all_bridges) {
        bridge_refresh_ofp_port(br);
        bridge_add_ofproto_ports(br);
    }

    /* Complete the configuration. */
    sflow_bridge_number = 0;
    collect_in_band_managers(ovs_cfg, &managers, &n_managers);
    HMAP_FOR_EACH (br, node, &all_bridges) {
        struct port *port;

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
        bridge_configure_datapath_id(br);
        bridge_configure_flow_eviction_threshold(br);
        bridge_configure_forward_bpdu(br);
        bridge_configure_remotes(br, managers, n_managers);
        bridge_configure_netflow(br);
        bridge_configure_sflow(br, &sflow_bridge_number);
    }
    free(managers);

    /* ovs-vswitchd has completed initialization, so allow the process that
     * forked us to exit successfully. */
    daemonize_complete();
}

/* Iterate over all ofprotos and delete any of them that do not have a
 * configured bridge or that are the wrong type. */
static void
bridge_del_ofprotos(void)
{
    struct sset names;
    struct sset types;
    const char *type;

    sset_init(&names);
    sset_init(&types);
    ofproto_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        const char *name;

        ofproto_enumerate_names(type, &names);
        SSET_FOR_EACH (name, &names) {
            struct bridge *br = bridge_lookup(name);
            if (!br || strcmp(type, br->type)) {
                ofproto_delete(name, type);
            }
        }
    }
    sset_destroy(&names);
    sset_destroy(&types);
}

static bool
bridge_add_ofprotos(struct bridge *br)
{
    int error = ofproto_create(br->name, br->type, &br->ofproto);
    if (error) {
        VLOG_ERR("failed to create bridge %s: %s", br->name, strerror(error));
        return false;
    }
    return true;
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
    s.slaves = xmalloc(list_size(&port->ifaces) * sizeof *s.slaves);
    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
        s.slaves[s.n_slaves++] = iface->ofp_port;
    }

    /* Get VLAN tag. */
    s.vlan = -1;
    if (cfg->tag) {
        if (list_is_short(&port->ifaces)) {
            if (*cfg->tag >= 0 && *cfg->tag <= 4095) {
                s.vlan = *cfg->tag;
                VLOG_DBG("port %s: assigning VLAN tag %d", port->name, s.vlan);
            }
        } else {
            /* It's possible that bonded, VLAN-tagged ports make sense.  Maybe
             * they even work as-is.  But they have not been tested. */
            VLOG_WARN("port %s: VLAN tags not supported on bonded ports",
                      port->name);
        }
    }

    /* Get VLAN trunks. */
    s.trunks = NULL;
    if (s.vlan < 0 && cfg->n_trunks) {
        s.trunks = vlan_bitmap_from_array(cfg->trunks, cfg->n_trunks);
    } else if (s.vlan >= 0 && cfg->n_trunks) {
        VLOG_ERR("port %s: ignoring trunks in favor of implicit vlan",
                 port->name);
    }

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
    ofproto_set_datapath_id(br->ofproto, dpid);

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
        const struct ovsrec_bridge *br_cfg = cfg->bridges[i];
        if (!shash_add_once(&new_br, br_cfg->name, br_cfg)) {
            VLOG_WARN("bridge %s specified twice", br_cfg->name);
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

/* Delete each ofproto port on 'br' that doesn't have a corresponding "struct
 * iface".
 *
 * The kernel will reject any attempt to add a given port to a datapath if that
 * port already belongs to a different datapath, so we must do all port
 * deletions before any port additions. */
static void
bridge_del_ofproto_ports(struct bridge *br)
{
    struct ofproto_port_dump dump;
    struct ofproto_port ofproto_port;

    OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, br->ofproto) {
        const char *name = ofproto_port.name;
        struct iface *iface;
        const char *type;
        int error;

        /* Ignore the local port.  We can't change it anyhow. */
        if (!strcmp(name, br->name)) {
            continue;
        }

        /* Get the type that 'ofproto_port' should have (ordinarily the
         * type of its corresponding iface) or NULL if it should be
         * deleted. */
        iface = iface_lookup(br, name);
        type = (iface ? iface->type
                : bridge_has_bond_fake_iface(br, name) ? "internal"
                : NULL);

        /* If it's the wrong type then delete the ofproto port. */
        if (type
            && !strcmp(ofproto_port.type, type)
            && (!iface || !iface->netdev
                || !strcmp(netdev_get_type(iface->netdev), type))) {
            continue;
        }
        error = ofproto_port_del(br->ofproto, ofproto_port.ofp_port);
        if (error) {
            VLOG_WARN("bridge %s: failed to remove %s interface (%s)",
                      br->name, name, strerror(error));
        }
        if (iface) {
            netdev_close(iface->netdev);
            iface->netdev = NULL;
        }
    }
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

static void
bridge_refresh_ofp_port(struct bridge *br)
{
    struct ofproto_port_dump dump;
    struct ofproto_port ofproto_port;
    struct port *port;

    /* Clear all the "ofp_port"es. */
    hmap_clear(&br->ifaces);
    HMAP_FOR_EACH (port, hmap_node, &br->ports) {
        struct iface *iface;

        LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
            iface->ofp_port = -1;
        }
    }

    /* Obtain the correct "ofp_port"s from ofproto. */
    OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, br->ofproto) {
        struct iface *iface = iface_lookup(br, ofproto_port.name);
        if (iface) {
            if (iface->ofp_port >= 0) {
                VLOG_WARN("bridge %s: interface %s reported twice",
                          br->name, ofproto_port.name);
            } else if (iface_from_ofp_port(br, ofproto_port.ofp_port)) {
                VLOG_WARN("bridge %s: interface %"PRIu16" reported twice",
                          br->name, ofproto_port.ofp_port);
            } else {
                iface_set_ofp_port(iface, ofproto_port.ofp_port);
            }
        }
    }
}

/* Add an ofproto port for any "struct iface" that doesn't have one.
 * Delete any "struct iface" for which this fails.
 * Delete any "struct port" that thereby ends up with no ifaces. */
static void
bridge_add_ofproto_ports(struct bridge *br)
{
    struct port *port, *next_port;

    HMAP_FOR_EACH_SAFE (port, next_port, hmap_node, &br->ports) {
        struct iface *iface, *next_iface;
        struct ofproto_port ofproto_port;

        LIST_FOR_EACH_SAFE (iface, next_iface, port_elem, &port->ifaces) {
            struct shash args;
            int error;

            /* Open the netdev or reconfigure it. */
            shash_init(&args);
            shash_from_ovs_idl_map(iface->cfg->key_options,
                                   iface->cfg->value_options,
                                   iface->cfg->n_options, &args);
            if (!iface->netdev) {
                struct netdev_options options;
                options.name = iface->name;
                options.type = iface->type;
                options.args = &args;
                options.ethertype = NETDEV_ETH_TYPE_NONE;
                error = netdev_open(&options, &iface->netdev);
            } else {
                error = netdev_set_config(iface->netdev, &args);
            }
            shash_destroy(&args);
            if (error) {
                VLOG_WARN("could not %s network device %s (%s)",
                          iface->netdev ? "reconfigure" : "open",
                          iface->name, strerror(error));
            }

            /* Add the port, if necessary. */
            if (iface->netdev && iface->ofp_port < 0) {
                uint16_t ofp_port;
                int error;

                error = ofproto_port_add(br->ofproto, iface->netdev,
                                         &ofp_port);
                if (!error) {
                    iface_set_ofp_port(iface, ofp_port);
                } else {
                    netdev_close(iface->netdev);
                    iface->netdev = NULL;
                }
            }

            /* Populate stats columns in new Interface rows. */
            if (iface->netdev && !iface->cfg->mtu) {
                iface_refresh_stats(iface);
                iface_refresh_status(iface);
            }

            /* Delete the iface if  */
            if (iface->netdev && iface->ofp_port >= 0) {
                VLOG_DBG("bridge %s: interface %s is on port %d",
                         br->name, iface->name, iface->ofp_port);
            } else {
                if (iface->netdev) {
                    VLOG_ERR("bridge %s: missing %s interface, dropping",
                             br->name, iface->name);
                } else {
                    /* We already reported a related error, don't bother
                     * duplicating it. */
                }
                iface_set_ofport(iface->cfg, -1);
                iface_destroy(iface);
            }
        }
        if (list_is_empty(&port->ifaces)) {
            VLOG_WARN("%s port has no interfaces, dropping", port->name);
            port_destroy(port);
            continue;
        }

        /* Add bond fake iface if necessary. */
        if (port_is_bond_fake_iface(port)) {
            if (ofproto_port_query_by_name(br->ofproto, port->name,
                                           &ofproto_port)) {
                struct netdev_options options;
                struct netdev *netdev;
                int error;

                options.name = port->name;
                options.type = "internal";
                options.args = NULL;
                options.ethertype = NETDEV_ETH_TYPE_NONE;
                error = netdev_open(&options, &netdev);
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
    }
}

static const char *
get_ovsrec_key_value(const struct ovsdb_idl_row *row,
                     const struct ovsdb_idl_column *column,
                     const char *key)
{
    const struct ovsdb_datum *datum;
    union ovsdb_atom atom;
    unsigned int idx;

    datum = ovsdb_idl_get(row, column, OVSDB_TYPE_STRING, OVSDB_TYPE_STRING);
    atom.string = (char *) key;
    idx = ovsdb_datum_find_key(datum, &atom, OVSDB_TYPE_STRING);
    return idx == UINT_MAX ? NULL : datum->values[idx].string;
}

static const char *
bridge_get_other_config(const struct ovsrec_bridge *br_cfg, const char *key)
{
    return get_ovsrec_key_value(&br_cfg->header_,
                                &ovsrec_bridge_col_other_config, key);
}

/* Set Flow eviction threshold */
static void
bridge_configure_flow_eviction_threshold(struct bridge *br)
{
    const char *threshold_str;
    unsigned threshold;

    threshold_str = bridge_get_other_config(br->cfg, "flow-eviction-threshold");
    if (threshold_str) {
        threshold = strtoul(threshold_str, NULL, 10);
    } else {
        threshold = OFPROTO_FLOW_EVICTON_THRESHOLD_DEFAULT;
    }
    ofproto_set_flow_eviction_threshold(br->ofproto, threshold);
}

/* Set forward BPDU option. */
static void
bridge_configure_forward_bpdu(struct bridge *br)
{
    const char *forward_bpdu_str;
    bool forward_bpdu = false;

    forward_bpdu_str = bridge_get_other_config(br->cfg, "forward-bpdu");
    if (forward_bpdu_str && !strcmp(forward_bpdu_str, "true")) {
        forward_bpdu = true;
    }
    ofproto_set_forward_bpdu(br->ofproto, forward_bpdu);
}

static void
bridge_pick_local_hw_addr(struct bridge *br, uint8_t ea[ETH_ADDR_LEN],
                          struct iface **hw_addr_iface)
{
    const char *hwaddr;
    struct port *port;
    int error;

    *hw_addr_iface = NULL;

    /* Did the user request a particular MAC? */
    hwaddr = bridge_get_other_config(br->cfg, "hwaddr");
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

    /* Otherwise choose the minimum non-local MAC address among all of the
     * interfaces. */
    memset(ea, 0xff, ETH_ADDR_LEN);
    HMAP_FOR_EACH (port, hmap_node, &br->ports) {
        uint8_t iface_ea[ETH_ADDR_LEN];
        struct iface *candidate;
        struct iface *iface;

        /* Mirror output ports don't participate. */
        if (ofproto_is_mirror_output_bundle(br->ofproto, port)) {
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
            eth_addr_compare_3way(iface_ea, ea) < 0)
        {
            memcpy(ea, iface_ea, ETH_ADDR_LEN);
            *hw_addr_iface = iface;
        }
    }
    if (eth_addr_is_multicast(ea)) {
        memcpy(ea, br->default_ea, ETH_ADDR_LEN);
        *hw_addr_iface = NULL;
        VLOG_WARN("bridge %s: using default bridge Ethernet "
                  "address "ETH_ADDR_FMT, br->name, ETH_ADDR_ARGS(ea));
    } else {
        VLOG_DBG("bridge %s: using bridge Ethernet address "ETH_ADDR_FMT,
                 br->name, ETH_ADDR_ARGS(ea));
    }
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

    datapath_id = bridge_get_other_config(br->cfg, "datapath-id");
    if (datapath_id && dpid_from_string(datapath_id, &dpid)) {
        return dpid;
    }

    if (hw_addr_iface) {
        int vlan;
        if (!netdev_get_vlan_vid(hw_addr_iface->netdev, &vlan)) {
            /*
             * A bridge whose MAC address is taken from a VLAN network device
             * (that is, a network device created with vconfig(8) or similar
             * tool) will have the same MAC address as a bridge on the VLAN
             * device's physical network device.
             *
             * Handle this case by hashing the physical network device MAC
             * along with the VLAN identifier.
             */
            uint8_t buf[ETH_ADDR_LEN + 2];
            memcpy(buf, bridge_ea, ETH_ADDR_LEN);
            buf[ETH_ADDR_LEN] = vlan >> 8;
            buf[ETH_ADDR_LEN + 1] = vlan;
            return dpid_from_hash(buf, sizeof buf);
        } else {
            /*
             * Assume that this bridge's MAC address is unique, since it
             * doesn't fit any of the cases we handle specially.
             */
        }
    } else {
        /*
         * A purely internal bridge, that is, one that has no non-virtual
         * network devices on it at all, is more difficult because it has no
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
    struct shash sh;

    enum netdev_flags flags;
    uint32_t current;
    int64_t bps;
    int mtu;
    int64_t mtu_64;
    int error;

    if (iface_is_synthetic(iface)) {
        return;
    }

    shash_init(&sh);

    if (!netdev_get_status(iface->netdev, &sh)) {
        size_t n;
        char **keys, **values;

        shash_to_ovs_idl_map(&sh, &keys, &values, &n);
        ovsrec_interface_set_status(iface->cfg, keys, values, n);

        free(keys);
        free(values);
    } else {
        ovsrec_interface_set_status(iface->cfg, NULL, NULL, 0);
    }

    shash_destroy_free_data(&sh);

    error = netdev_get_flags(iface->netdev, &flags);
    if (!error) {
        ovsrec_interface_set_admin_state(iface->cfg, flags & NETDEV_UP ? "up" : "down");
    }
    else {
        ovsrec_interface_set_admin_state(iface->cfg, NULL);
    }

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

    ovsrec_interface_set_link_state(iface->cfg,
                                    iface_get_carrier(iface) ? "up" : "down");

    error = netdev_get_mtu(iface->netdev, &mtu);
    if (!error && mtu != INT_MAX) {
        mtu_64 = mtu;
        ovsrec_interface_set_mtu(iface->cfg, &mtu_64, 1);
    }
    else {
        ovsrec_interface_set_mtu(iface->cfg, NULL, 0);
    }
}

/* Writes 'iface''s CFM statistics to the database.  Returns true if anything
 * changed, false otherwise. */
static bool
iface_refresh_cfm_stats(struct iface *iface)
{
    const struct ovsrec_interface *cfg = iface->cfg;
    bool changed = false;
    int fault;

    fault = ofproto_port_get_cfm_fault(iface->port->bridge->ofproto,
                                       iface->ofp_port);

    if (fault < 0) {
        return false;
    }

    if (cfg->n_cfm_fault != 1 || cfg->cfm_fault[0] != fault) {
        bool fault_bool = fault;
        ovsrec_interface_set_cfm_fault(cfg, &fault_bool, 1);
        changed = true;
    }

    return changed;
}

static bool
iface_refresh_lacp_stats(struct iface *iface)
{
    struct ofproto *ofproto = iface->port->bridge->ofproto;
    int old = iface->cfg->lacp_current ? *iface->cfg->lacp_current : -1;
    int new = ofproto_port_is_lacp_current(ofproto, iface->ofp_port);

    if (old != new) {
        bool current = new;
        ovsrec_interface_set_lacp_current(iface->cfg, &current, new >= 0);
    }
    return old != new;
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

    ovsrec_interface_set_statistics(iface->cfg, keys, values, ARRAY_SIZE(keys));
#undef IFACE_STATS
}

static bool
enable_system_stats(const struct ovsrec_open_vswitch *cfg)
{
    const char *enable;

    /* Use other-config:enable-system-stats by preference. */
    enable = get_ovsrec_key_value(&cfg->header_,
                                  &ovsrec_open_vswitch_col_other_config,
                                  "enable-statistics");
    if (enable) {
        return !strcmp(enable, "true");
    }

    /* Disable by default. */
    return false;
}

static void
refresh_system_stats(const struct ovsrec_open_vswitch *cfg)
{
    struct ovsdb_datum datum;
    struct shash stats;

    shash_init(&stats);
    if (enable_system_stats(cfg)) {
        get_system_stats(&stats);
    }

    ovsdb_datum_from_shash(&datum, &stats);
    ovsdb_idl_txn_write(&cfg->header_, &ovsrec_open_vswitch_col_statistics,
                        &datum);
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
            ovsrec_controller_set_is_connected(cfg, cinfo->is_connected);
            ovsrec_controller_set_role(cfg, nx_role_to_str(cinfo->role));
            ovsrec_controller_set_status(cfg, (char **) cinfo->pairs.keys,
                                         (char **) cinfo->pairs.values,
                                         cinfo->pairs.n);
        } else {
            ovsrec_controller_set_is_connected(cfg, false);
            ovsrec_controller_set_role(cfg, NULL);
            ovsrec_controller_set_status(cfg, NULL, NULL, 0);
        }
    }

    ofproto_free_ofproto_controller_info(&info);
}

void
bridge_run(void)
{
    const struct ovsrec_open_vswitch *cfg;

    bool datapath_destroyed;
    bool database_changed;
    struct bridge *br;

    /* (Re)configure if necessary. */
    database_changed = ovsdb_idl_run(idl);
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
    cfg = ovsrec_open_vswitch_first(idl);

    /* Let each bridge do the work that it needs to do. */
    datapath_destroyed = false;
    HMAP_FOR_EACH (br, node, &all_bridges) {
        int error = ofproto_run(br->ofproto);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_ERR_RL(&rl, "bridge %s: datapath was destroyed externally, "
                        "forcing reconfiguration", br->name);
            datapath_destroyed = true;
        }
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

    if (database_changed || datapath_destroyed) {
        if (cfg) {
            struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(idl);

            bridge_reconfigure(cfg);

            ovsrec_open_vswitch_set_cur_cfg(cfg, cfg->next_cfg);
            ovsdb_idl_txn_commit(txn);
            ovsdb_idl_txn_destroy(txn); /* XXX */
        } else {
            /* We still need to reconfigure to avoid dangling pointers to
             * now-destroyed ovsrec structures inside bridge data. */
            static const struct ovsrec_open_vswitch null_cfg;

            bridge_reconfigure(&null_cfg);
        }
    }

    /* Refresh system and interface stats if necessary. */
    if (time_msec() >= stats_timer) {
        if (cfg) {
            struct ovsdb_idl_txn *txn;

            txn = ovsdb_idl_txn_create(idl);
            HMAP_FOR_EACH (br, node, &all_bridges) {
                struct port *port;

                HMAP_FOR_EACH (port, hmap_node, &br->ports) {
                    struct iface *iface;

                    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                        iface_refresh_stats(iface);
                        iface_refresh_status(iface);
                    }
                }
            }
            refresh_system_stats(cfg);
            refresh_controller_status();
            ovsdb_idl_txn_commit(txn);
            ovsdb_idl_txn_destroy(txn); /* XXX */
        }

        stats_timer = time_msec() + STATS_INTERVAL;
    }

    if (time_msec() >= db_limiter) {
        struct ovsdb_idl_txn *txn;
        bool changed = false;

        txn = ovsdb_idl_txn_create(idl);
        HMAP_FOR_EACH (br, node, &all_bridges) {
            struct port *port;

            HMAP_FOR_EACH (port, hmap_node, &br->ports) {
                struct iface *iface;

                LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                    changed = iface_refresh_cfm_stats(iface) || changed;
                    changed = iface_refresh_lacp_stats(iface) || changed;
                }
            }
        }

        if (changed) {
            db_limiter = time_msec() + DB_LIMIT_INTERVAL;
        }

        ovsdb_idl_txn_commit(txn);
        ovsdb_idl_txn_destroy(txn);
    }
}

void
bridge_wait(void)
{
    ovsdb_idl_wait(idl);
    if (!hmap_is_empty(&all_bridges)) {
        struct bridge *br;

        HMAP_FOR_EACH (br, node, &all_bridges) {
            ofproto_wait(br->ofproto);
        }
        poll_timer_wait_until(stats_timer);

        if (db_limiter > time_msec()) {
            poll_timer_wait_until(db_limiter);
        }
    }
}

/* QoS unixctl user interface functions. */

struct qos_unixctl_show_cbdata {
    struct ds *ds;
    struct iface *iface;
};

static void
qos_unixctl_show_cb(unsigned int queue_id,
                    const struct shash *details,
                    void *aux)
{
    struct qos_unixctl_show_cbdata *data = aux;
    struct ds *ds = data->ds;
    struct iface *iface = data->iface;
    struct netdev_queue_stats stats;
    struct shash_node *node;
    int error;

    ds_put_cstr(ds, "\n");
    if (queue_id) {
        ds_put_format(ds, "Queue %u:\n", queue_id);
    } else {
        ds_put_cstr(ds, "Default:\n");
    }

    SHASH_FOR_EACH (node, details) {
        ds_put_format(ds, "\t%s: %s\n", node->name, (char *)node->data);
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
qos_unixctl_show(struct unixctl_conn *conn,
                 const char *args, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct shash sh = SHASH_INITIALIZER(&sh);
    struct iface *iface;
    const char *type;
    struct shash_node *node;
    struct qos_unixctl_show_cbdata data;
    int error;

    iface = iface_find(args);
    if (!iface) {
        unixctl_command_reply(conn, 501, "no such interface");
        return;
    }

    netdev_get_qos(iface->netdev, &type, &sh);

    if (*type != '\0') {
        ds_put_format(&ds, "QoS: %s %s\n", iface->name, type);

        SHASH_FOR_EACH (node, &sh) {
            ds_put_format(&ds, "%s: %s\n", node->name, (char *)node->data);
        }

        data.ds = &ds;
        data.iface = iface;
        error = netdev_dump_queues(iface->netdev, qos_unixctl_show_cb, &data);

        if (error) {
            ds_put_format(&ds, "failed to dump queues: %s", strerror(error));
        }
        unixctl_command_reply(conn, 200, ds_cstr(&ds));
    } else {
        ds_put_format(&ds, "QoS not configured on %s\n", iface->name);
        unixctl_command_reply(conn, 501, ds_cstr(&ds));
    }

    shash_destroy_free_data(&sh);
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

    hmap_insert(&all_bridges, &br->node, hash_string(br->name, 0));
}

static void
bridge_destroy(struct bridge *br)
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
        ofproto_destroy(br->ofproto);
        hmap_destroy(&br->ifaces);
        hmap_destroy(&br->ports);
        hmap_destroy(&br->iface_by_name);
        hmap_destroy(&br->mirrors);
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
bridge_unixctl_dump_flows(struct unixctl_conn *conn,
                          const char *args, void *aux OVS_UNUSED)
{
    struct bridge *br;
    struct ds results;

    br = bridge_lookup(args);
    if (!br) {
        unixctl_command_reply(conn, 501, "Unknown bridge");
        return;
    }

    ds_init(&results);
    ofproto_get_all_flows(br->ofproto, &results);

    unixctl_command_reply(conn, 200, ds_cstr(&results));
    ds_destroy(&results);
}

/* "bridge/reconnect [BRIDGE]": makes BRIDGE drop all of its controller
 * connections and reconnect.  If BRIDGE is not specified, then all bridges
 * drop their controller connections and reconnect. */
static void
bridge_unixctl_reconnect(struct unixctl_conn *conn,
                         const char *args, void *aux OVS_UNUSED)
{
    struct bridge *br;
    if (args[0] != '\0') {
        br = bridge_lookup(args);
        if (!br) {
            unixctl_command_reply(conn, 501, "Unknown bridge");
            return;
        }
        ofproto_reconnect_controllers(br->ofproto);
    } else {
        HMAP_FOR_EACH (br, node, &all_bridges) {
            ofproto_reconnect_controllers(br->ofproto);
        }
    }
    unixctl_command_reply(conn, 200, NULL);
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

/* Adds and deletes "struct port"s and "struct iface"s under 'br' to match
 * those configured in 'br->cfg'. */
static void
bridge_add_del_ports(struct bridge *br)
{
    struct port *port, *next;
    struct shash_node *node;
    struct shash new_ports;
    size_t i;

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

        br->synth_local_port.interfaces = &br->synth_local_ifacep;
        br->synth_local_port.n_interfaces = 1;
        br->synth_local_port.name = br->name;

        br->synth_local_iface.name = br->name;
        br->synth_local_iface.type = "internal";

        br->synth_local_ifacep = &br->synth_local_iface;

        shash_add(&new_ports, br->name, &br->synth_local_port);
    }

    /* Get rid of deleted ports.
     * Get rid of deleted interfaces on ports that still exist.
     * Update 'cfg' of ports that still exist. */
    HMAP_FOR_EACH_SAFE (port, next, hmap_node, &br->ports) {
        port->cfg = shash_find_data(&new_ports, port->name);
        if (!port->cfg) {
            port_destroy(port);
        } else {
            port_del_ifaces(port);
        }
    }

    /* Create new ports.
     * Add new interfaces to existing ports. */
    SHASH_FOR_EACH (node, &new_ports) {
        struct port *port = port_lookup(br, node->name);
        if (!port) {
            struct ovsrec_port *cfg = node->data;
            port = port_create(br, cfg);
        }
        port_add_ifaces(port);
        if (list_is_empty(&port->ifaces)) {
            VLOG_WARN("bridge %s: port %s has no interfaces, dropping",
                      br->name, port->name);
            port_destroy(port);
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
}

/* Converts ovsrec_controller 'c' into an ofproto_controller in 'oc'.  */
static void
bridge_ofproto_controller_from_ovsrec(const struct ovsrec_controller *c,
                                      struct ofproto_controller *oc)
{
    oc->target = c->target;
    oc->max_backoff = c->max_backoff ? *c->max_backoff / 1000 : 8;
    oc->probe_interval = c->inactivity_probe ? *c->inactivity_probe / 1000 : 5;
    oc->band = (!c->connection_mode || !strcmp(c->connection_mode, "in-band")
                ? OFPROTO_IN_BAND : OFPROTO_OUT_OF_BAND);
    oc->rate_limit = c->controller_rate_limit ? *c->controller_rate_limit : 0;
    oc->burst_limit = (c->controller_burst_limit
                       ? *c->controller_burst_limit : 0);
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

static void
bridge_configure_remotes(struct bridge *br,
                         const struct sockaddr_in *managers, size_t n_managers)
{
    const char *disable_ib_str, *queue_id_str;
    bool disable_in_band = false;
    int queue_id;

    struct ovsrec_controller **controllers;
    size_t n_controllers;

    enum ofproto_fail_mode fail_mode;

    struct ofproto_controller *ocs;
    size_t n_ocs;
    size_t i;

    /* Check if we should disable in-band control on this bridge. */
    disable_ib_str = bridge_get_other_config(br->cfg, "disable-in-band");
    if (disable_ib_str && !strcmp(disable_ib_str, "true")) {
        disable_in_band = true;
    }

    /* Set OpenFlow queue ID for in-band control. */
    queue_id_str = bridge_get_other_config(br->cfg, "in-band-queue");
    queue_id = queue_id_str ? strtol(queue_id_str, NULL, 10) : -1;
    ofproto_set_in_band_queue(br->ofproto, queue_id);

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

            /* Prevent remote ovsdb-server users from accessing arbitrary Unix
             * domain sockets and overwriting arbitrary local files. */
            VLOG_ERR_RL(&rl, "bridge %s: not adding Unix domain socket "
                        "controller \"%s\" due to possibility for remote "
                        "exploit", br->name, c->target);
            continue;
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

    VLOG_INFO("created port %s on bridge %s", port->name, br->name);

    return port;
}

static const char *
get_port_other_config(const struct ovsrec_port *port, const char *key,
                      const char *default_value)
{
    const char *value;

    value = get_ovsrec_key_value(&port->header_, &ovsrec_port_col_other_config,
                                 key);
    return value ? value : default_value;
}

static const char *
get_interface_other_config(const struct ovsrec_interface *iface,
                           const char *key, const char *default_value)
{
    const char *value;

    value = get_ovsrec_key_value(&iface->header_,
                                 &ovsrec_interface_col_other_config, key);
    return value ? value : default_value;
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
        const char *type = port->cfg->interfaces[i]->name;
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

/* Adds new interfaces to 'port' and updates 'type' and 'cfg' members of
 * existing ones. */
static void
port_add_ifaces(struct port *port)
{
    struct shash new_ifaces;
    struct shash_node *node;
    size_t i;

    /* Collect new ifaces. */
    shash_init(&new_ifaces);
    for (i = 0; i < port->cfg->n_interfaces; i++) {
        const struct ovsrec_interface *cfg = port->cfg->interfaces[i];
        if (strcmp(cfg->type, "null")
            && !shash_add_once(&new_ifaces, cfg->name, cfg)) {
            VLOG_WARN("port %s: %s specified twice as port interface",
                      port->name, cfg->name);
            iface_set_ofport(cfg, -1);
        }
    }

    /* Create new interfaces.
     * Update interface types and 'cfg' members. */
    SHASH_FOR_EACH (node, &new_ifaces) {
        const struct ovsrec_interface *cfg = node->data;
        const char *iface_name = node->name;
        struct iface *iface;

        iface = iface_lookup(port->bridge, iface_name);
        if (!iface) {
            iface = iface_create(port, cfg);
        } else {
            iface->cfg = cfg;
        }

        /* Determine interface type.  The local port always has type
         * "internal".  Other ports take their type from the database and
         * default to "system" if none is specified. */
        iface->type = (!strcmp(iface_name, port->bridge->name) ? "internal"
                       : cfg->type[0] ? cfg->type
                       : "system");
    }
    shash_destroy(&new_ifaces);
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

        VLOG_INFO("destroyed port %s on bridge %s", port->name, br->name);

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
    const char *lacp_time;
    long long int custom_time;
    int priority;

    if (!enable_lacp(port, &s->active)) {
        return NULL;
    }

    s->name = port->name;
    memcpy(s->id, port->bridge->ea, ETH_ADDR_LEN);

    /* Prefer bondable links if unspecified. */
    priority = atoi(get_port_other_config(port->cfg, "lacp-system-priority",
                                          "0"));
    s->priority = (priority > 0 && priority <= UINT16_MAX
                   ? priority
                   : UINT16_MAX - !list_is_short(&port->ifaces));

    s->heartbeat = !strcmp(get_port_other_config(port->cfg,
                                                 "lacp-heartbeat",
                                                 "false"), "true");


    lacp_time = get_port_other_config(port->cfg, "lacp-time", "slow");
    custom_time = atoi(lacp_time);
    if (!strcmp(lacp_time, "fast")) {
        s->lacp_time = LACP_TIME_FAST;
    } else if (!strcmp(lacp_time, "slow")) {
        s->lacp_time = LACP_TIME_SLOW;
    } else if (custom_time > 0) {
        s->lacp_time = LACP_TIME_CUSTOM;
        s->custom_time = custom_time;
    } else {
        s->lacp_time = LACP_TIME_SLOW;
    }

    return s;
}

static void
iface_configure_lacp(struct iface *iface, struct lacp_slave_settings *s)
{
    int priority, portid, key;

    portid = atoi(get_interface_other_config(iface->cfg, "lacp-port-id", "0"));
    priority = atoi(get_interface_other_config(iface->cfg,
                                               "lacp-port-priority", "0"));
    key = atoi(get_interface_other_config(iface->cfg, "lacp-aggregation-key",
                                          "0"));

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
    s->balance = BM_SLB;
    if (port->cfg->bond_mode
        && !bond_mode_from_string(&s->balance, port->cfg->bond_mode)) {
        VLOG_WARN("port %s: unknown bond_mode %s, defaulting to %s",
                  port->name, port->cfg->bond_mode,
                  bond_mode_to_string(s->balance));
    }
    if (s->balance == BM_SLB && port->bridge->cfg->n_flood_vlans) {
        VLOG_WARN("port %s: SLB bonds are incompatible with flood_vlans, "
                  "please use another bond type or disable flood_vlans",
                  port->name);
    }

    miimon_interval = atoi(get_port_other_config(port->cfg,
                                                 "bond-miimon-interval", "0"));
    if (miimon_interval <= 0) {
        miimon_interval = 200;
    }

    detect_s = get_port_other_config(port->cfg, "bond-detect-mode", "carrier");
    if (!strcmp(detect_s, "carrier")) {
        miimon_interval = 0;
    } else if (strcmp(detect_s, "miimon")) {
        VLOG_WARN("port %s: unsupported bond-detect-mode %s, "
                  "defaulting to carrier", port->name, detect_s);
        miimon_interval = 0;
    }

    s->up_delay = MAX(0, port->cfg->bond_updelay);
    s->down_delay = MAX(0, port->cfg->bond_downdelay);
    s->basis = atoi(get_port_other_config(port->cfg, "bond-hash-basis", "0"));
    s->rebalance_interval = atoi(
        get_port_other_config(port->cfg, "bond-rebalance-interval", "10000"));
    if (s->rebalance_interval < 1000) {
        s->rebalance_interval = 1000;
    }

    s->fake_iface = port->cfg->bond_fake_iface;

    i = 0;
    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
        long long stable_id;

        stable_id = atoll(get_interface_other_config(iface->cfg,
                                                     "bond-stable-id", "0"));
        if (stable_id <= 0 || stable_id >= UINT32_MAX) {
            stable_id = iface->ofp_port;
        }
        bond_stable_ids[i++] = stable_id;

        netdev_set_miimon_interval(iface->netdev, miimon_interval);
    }
}

/* Interface functions. */

static struct iface *
iface_create(struct port *port, const struct ovsrec_interface *if_cfg)
{
    struct bridge *br = port->bridge;
    struct iface *iface;
    char *name = if_cfg->name;

    iface = xzalloc(sizeof *iface);
    iface->port = port;
    iface->name = xstrdup(name);
    iface->ofp_port = -1;
    iface->tag = tag_create_random();
    iface->netdev = NULL;
    iface->cfg = if_cfg;

    hmap_insert(&br->iface_by_name, &iface->name_node, hash_string(name, 0));

    list_push_back(&port->ifaces, &iface->port_elem);

    VLOG_DBG("attached network device %s to port %s", iface->name, port->name);

    return iface;
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

/* Adds the 'n' key-value pairs in 'keys' in 'values' to 'shash'.
 *
 * The value strings in '*shash' are taken directly from values[], not copied,
 * so the caller should not modify or free them. */
static void
shash_from_ovs_idl_map(char **keys, char **values, size_t n,
                       struct shash *shash)
{
    size_t i;

    shash_init(shash);
    for (i = 0; i < n; i++) {
        shash_add(shash, keys[i], values[i]);
    }
}

/* Creates 'keys' and 'values' arrays from 'shash'.
 *
 * Sets 'keys' and 'values' to heap allocated arrays representing the key-value
 * pairs in 'shash'.  The caller takes ownership of 'keys' and 'values'.  They
 * are populated with with strings taken directly from 'shash' and thus have
 * the same ownership of the key-value pairs in shash.
 */
static void
shash_to_ovs_idl_map(struct shash *shash,
                     char ***keys, char ***values, size_t *n)
{
    size_t i, count;
    char **k, **v;
    struct shash_node *sn;

    count = shash_count(shash);

    k = xmalloc(count * sizeof *k);
    v = xmalloc(count * sizeof *v);

    i = 0;
    SHASH_FOR_EACH(sn, shash) {
        k[i] = sn->name;
        v[i] = sn->data;
        i++;
    }

    *n      = count;
    *keys   = k;
    *values = v;
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
                    const struct shash *details OVS_UNUSED, void *cbdata_)
{
    struct iface_delete_queues_cbdata *cbdata = cbdata_;

    if (!queue_ids_include(cbdata->queues, queue_id)) {
        netdev_delete_queue(cbdata->netdev, queue_id);
    }
}

static void
iface_configure_qos(struct iface *iface, const struct ovsrec_qos *qos)
{
    if (!qos || qos->type[0] == '\0' || qos->n_queues < 1) {
        netdev_set_qos(iface->netdev, NULL, NULL);
    } else {
        struct iface_delete_queues_cbdata cbdata;
        struct shash details;
        bool queue_zero;
        size_t i;

        /* Configure top-level Qos for 'iface'. */
        shash_from_ovs_idl_map(qos->key_other_config, qos->value_other_config,
                               qos->n_other_config, &details);
        netdev_set_qos(iface->netdev, qos->type, &details);
        shash_destroy(&details);

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

            shash_from_ovs_idl_map(queue->key_other_config,
                                   queue->value_other_config,
                                   queue->n_other_config, &details);
            netdev_set_queue(iface->netdev, queue_id, &details);
            shash_destroy(&details);
        }
        if (!queue_zero) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "interface %s: QoS configured without a default "
                         "queue (queue 0).  Packets not directed to a "
                         "correctly configured queue may be dropped.",
                         iface->name);
        }
    }

    netdev_set_policing(iface->netdev,
                        iface->cfg->ingress_policing_rate,
                        iface->cfg->ingress_policing_burst);
}

static void
iface_configure_cfm(struct iface *iface)
{
    const struct ovsrec_interface *cfg = iface->cfg;
    struct cfm_settings s;
    uint16_t remote_mpid;

    if (!cfg->n_cfm_mpid || !cfg->n_cfm_remote_mpid) {
        ofproto_port_clear_cfm(iface->port->bridge->ofproto, iface->ofp_port);
        return;
    }

    s.mpid = *cfg->cfm_mpid;
    remote_mpid = *cfg->cfm_remote_mpid;
    s.remote_mpids = &remote_mpid;
    s.n_remote_mpids = 1;

    s.interval = atoi(get_interface_other_config(iface->cfg, "cfm_interval",
                                                 "0"));
    if (s.interval <= 0) {
        s.interval = 1000;
    }

    ofproto_port_set_cfm(iface->port->bridge->ofproto, iface->ofp_port, &s);
}

/* Read carrier or miimon status directly from 'iface''s netdev, according to
 * how 'iface''s port is configured.
 *
 * Returns true if 'iface' is up, false otherwise. */
static bool
iface_get_carrier(const struct iface *iface)
{
    /* XXX */
    return netdev_get_carrier(iface->netdev);
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
        if (!mirror_configure(m, cfg)) {
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
mirror_configure(struct mirror *m, const struct ovsrec_mirror *cfg)
{
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
