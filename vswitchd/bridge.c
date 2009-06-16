/* Copyright (c) 2008, 2009 Nicira Networks
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
#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
#include <net/if.h>
#include <openflow/openflow.h>
#include <signal.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "bitmap.h"
#include "cfg.h"
#include "coverage.h"
#include "dirs.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"
#include "list.h"
#include "mac-learning.h"
#include "netdev.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "port-array.h"
#include "proc-net-compat.h"
#include "process.h"
#include "secchan/ofproto.h"
#include "socket-util.h"
#include "stp.h"
#include "svec.h"
#include "timeval.h"
#include "util.h"
#include "unixctl.h"
#include "vconn.h"
#include "vconn-ssl.h"
#include "xenserver.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_bridge
#include "vlog.h"

struct dst {
    uint16_t vlan;
    uint16_t dp_ifidx;
};

extern uint64_t mgmt_id;

struct iface {
    struct port *port;          /* Containing port. */
    size_t port_ifidx;          /* Index within containing port. */

    char *name;                 /* Host network device name. */
    int dp_ifidx;               /* Index within kernel datapath. */

    uint8_t mac[ETH_ADDR_LEN];  /* Ethernet address (all zeros if unknowns). */

    tag_type tag;               /* Tag associated with this interface. */
    bool enabled;               /* May be chosen for flows? */
    long long delay_expires;    /* Time after which 'enabled' may change. */
};

#define BOND_MASK 0xff
struct bond_entry {
    int iface_idx;              /* Index of assigned iface, or -1 if none. */
    uint64_t tx_bytes;          /* Count of bytes recently transmitted. */
    tag_type iface_tag;         /* Tag associated with iface_idx. */
};

#define MAX_MIRRORS 32
typedef uint32_t mirror_mask_t;
#define MIRROR_MASK_C(X) UINT32_C(X)
BUILD_ASSERT_DECL(sizeof(mirror_mask_t) * CHAR_BIT >= MAX_MIRRORS);
struct mirror {
    struct bridge *bridge;
    size_t idx;
    char *name;

    /* Selection criteria. */
    struct svec src_ports;
    struct svec dst_ports;
    int *vlans;
    size_t n_vlans;

    /* Output. */
    struct port *out_port;
    int out_vlan;
};

#define FLOOD_PORT ((struct port *) 1) /* The 'flood' output port. */
struct port {
    struct bridge *bridge;
    size_t port_idx;
    int vlan;                   /* -1=trunk port, else a 12-bit VLAN ID. */
    unsigned long *trunks;      /* Bitmap of trunked VLANs, if 'vlan' == -1. */
    char *name;

    /* An ordinary bridge port has 1 interface.
     * A bridge port for bonding has at least 2 interfaces. */
    struct iface **ifaces;
    size_t n_ifaces, allocated_ifaces;

    /* Bonding info. */
    struct bond_entry *bond_hash; /* An array of (BOND_MASK + 1) elements. */
    int active_iface;           /* Ifidx on which bcasts accepted, or -1. */
    tag_type active_iface_tag;  /* Tag for bcast flows. */
    tag_type no_ifaces_tag;     /* Tag for flows when all ifaces disabled. */
    int updelay, downdelay;     /* Delay before iface goes up/down, in ms. */

    /* Port mirroring info. */
    mirror_mask_t src_mirrors;  /* Mirrors triggered when packet received. */
    mirror_mask_t dst_mirrors;  /* Mirrors triggered when packet sent. */
    bool is_mirror_output_port; /* Does port mirroring send frames here? */

    /* Spanning tree info. */
    enum stp_state stp_state;   /* Always STP_FORWARDING if STP not in use. */
    tag_type stp_state_tag;     /* Tag for STP state change. */
};

#define DP_MAX_PORTS 255
struct bridge {
    struct list node;           /* Node in global list of bridges. */
    char *name;                 /* User-specified arbitrary name. */
    struct mac_learning *ml;    /* MAC learning table, or null not to learn. */
    bool sent_config_request;   /* Successfully sent config request? */
    uint8_t default_ea[ETH_ADDR_LEN]; /* Default MAC. */

    /* Support for remote controllers. */
    char *controller;           /* NULL if there is no remote controller;
                                 * "discover" to do controller discovery;
                                 * otherwise a vconn name. */

    /* OpenFlow switch processing. */
    struct ofproto *ofproto;    /* OpenFlow switch. */

    /* Kernel datapath information. */
    struct dpif dpif;           /* Kernel datapath. */
    struct port_array ifaces;   /* Indexed by kernel datapath port number. */

    /* Bridge ports. */
    struct port **ports;
    size_t n_ports, allocated_ports;

    /* Bonding. */
    bool has_bonded_ports;
    long long int bond_next_rebalance;

    /* Flow tracking. */
    bool flush;

    /* Flow statistics gathering. */
    time_t next_stats_request;

    /* Port mirroring. */
    struct mirror *mirrors[MAX_MIRRORS];

    /* Spanning tree. */
    struct stp *stp;
    long long int stp_last_tick;
};

/* List of all bridges. */
static struct list all_bridges = LIST_INITIALIZER(&all_bridges);

/* Maximum number of datapaths. */
enum { DP_MAX = 256 };

static struct bridge *bridge_create(const char *name);
static void bridge_destroy(struct bridge *);
static struct bridge *bridge_lookup(const char *name);
static int bridge_run_one(struct bridge *);
static void bridge_reconfigure_one(struct bridge *);
static void bridge_reconfigure_controller(struct bridge *);
static void bridge_get_all_ifaces(const struct bridge *, struct svec *ifaces);
static void bridge_fetch_dp_ifaces(struct bridge *);
static void bridge_flush(struct bridge *);
static void bridge_pick_local_hw_addr(struct bridge *,
                                      uint8_t ea[ETH_ADDR_LEN],
                                      const char **devname);
static uint64_t bridge_pick_datapath_id(struct bridge *,
                                        const uint8_t bridge_ea[ETH_ADDR_LEN],
                                        const char *devname);
static uint64_t dpid_from_hash(const void *, size_t nbytes);

static void bond_init(void);
static void bond_run(struct bridge *);
static void bond_wait(struct bridge *);
static void bond_rebalance_port(struct port *);
static void bond_send_learning_packets(struct port *);

static void port_create(struct bridge *, const char *name);
static void port_reconfigure(struct port *);
static void port_destroy(struct port *);
static struct port *port_lookup(const struct bridge *, const char *name);
static struct iface *port_lookup_iface(const struct port *, const char *name);
static struct port *port_from_dp_ifidx(const struct bridge *,
                                       uint16_t dp_ifidx);
static void port_update_bond_compat(struct port *);
static void port_update_vlan_compat(struct port *);

static void mirror_create(struct bridge *, const char *name);
static void mirror_destroy(struct mirror *);
static void mirror_reconfigure(struct bridge *);
static void mirror_reconfigure_one(struct mirror *);
static bool vlan_is_mirrored(const struct mirror *, int vlan);

static void brstp_reconfigure(struct bridge *);
static void brstp_adjust_timers(struct bridge *);
static void brstp_run(struct bridge *);
static void brstp_wait(struct bridge *);

static void iface_create(struct port *, const char *name);
static void iface_destroy(struct iface *);
static struct iface *iface_lookup(const struct bridge *, const char *name);
static struct iface *iface_from_dp_ifidx(const struct bridge *,
                                         uint16_t dp_ifidx);

/* Hooks into ofproto processing. */
static struct ofhooks bridge_ofhooks;

/* Public functions. */

/* Adds the name of each interface used by a bridge, including local and
 * internal ports, to 'svec'. */
void
bridge_get_ifaces(struct svec *svec) 
{
    struct bridge *br, *next;
    size_t i, j;

    LIST_FOR_EACH_SAFE (br, next, struct bridge, node, &all_bridges) {
        for (i = 0; i < br->n_ports; i++) {
            struct port *port = br->ports[i];

            for (j = 0; j < port->n_ifaces; j++) {
                struct iface *iface = port->ifaces[j];
                if (iface->dp_ifidx < 0) {
                    VLOG_ERR("%s interface not in dp%u, ignoring",
                             iface->name, dpif_id(&br->dpif));
                } else {
                    if (iface->dp_ifidx != ODPP_LOCAL) {
                        svec_add(svec, iface->name);
                    }
                }
            }
        }
    }
}

/* The caller must already have called cfg_read(). */
void
bridge_init(void)
{
    int retval;
    int i;

    bond_init();

    for (i = 0; i < DP_MAX; i++) {
        struct dpif dpif;
        char devname[16];

        sprintf(devname, "dp%d", i);
        retval = dpif_open(devname, &dpif);
        if (!retval) {
            char dpif_name[IF_NAMESIZE];
            if (dpif_port_get_name(&dpif, ODPP_LOCAL,
                                   dpif_name, sizeof dpif_name)
                || !cfg_has("bridge.%s.port", dpif_name)) {
                dpif_delete(&dpif);
            }
            dpif_close(&dpif);
        } else if (retval != ENODEV) {
            VLOG_ERR("failed to delete datapath dp%d: %s",
                     i, strerror(retval));
        }
    }

    bridge_reconfigure();
}

#ifdef HAVE_OPENSSL
static bool
config_string_change(const char *key, char **valuep)
{
    const char *value = cfg_get_string(0, "%s", key);
    if (value && (!*valuep || strcmp(value, *valuep))) {
        free(*valuep);
        *valuep = xstrdup(value);
        return true;
    } else {
        return false;
    }
}

static void
bridge_configure_ssl(void)
{
    /* XXX SSL should be configurable on a per-bridge basis.
     * XXX should be possible to de-configure SSL. */
    static char *private_key_file;
    static char *certificate_file;
    static char *cacert_file;
    struct stat s;

    if (config_string_change("ssl.private-key", &private_key_file)) {
        vconn_ssl_set_private_key_file(private_key_file);
    }

    if (config_string_change("ssl.certificate", &certificate_file)) {
        vconn_ssl_set_certificate_file(certificate_file);
    }

    /* We assume that even if the filename hasn't changed, if the CA cert 
     * file has been removed, that we want to move back into
     * boot-strapping mode.  This opens a small security hole, because
     * the old certificate will still be trusted until vSwitch is
     * restarted.  We may want to address this in vconn's SSL library. */
    if (config_string_change("ssl.ca-cert", &cacert_file)
            || (stat(cacert_file, &s) && errno == ENOENT)) {
        vconn_ssl_set_ca_cert_file(cacert_file,
                                   cfg_get_bool(0, "ssl.bootstrap-ca-cert"));
    }
}
#endif

void
bridge_reconfigure(void)
{
    struct svec old_br, new_br, raw_new_br;
    struct bridge *br, *next;
    size_t i, j;

    COVERAGE_INC(bridge_reconfigure);

    /* Collect old bridges. */
    svec_init(&old_br);
    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        svec_add(&old_br, br->name);
    }

    /* Collect new bridges. */
    svec_init(&raw_new_br);
    cfg_get_subsections(&raw_new_br, "bridge");
    svec_init(&new_br);
    for (i = 0; i < raw_new_br.n; i++) {
        const char *name = raw_new_br.names[i];
        if ((!strncmp(name, "dp", 2) && isdigit(name[2])) ||
            (!strncmp(name, "nl:", 3) && isdigit(name[3]))) {
            VLOG_ERR("%s is not a valid bridge name (bridges may not be "
                     "named \"dp\" or \"nl:\" followed by a digit)", name);
        } else {
            svec_add(&new_br, name);
        }
    }
    svec_destroy(&raw_new_br);

    /* Get rid of deleted bridges and add new bridges. */
    svec_sort(&old_br);
    svec_sort(&new_br);
    assert(svec_is_unique(&old_br));
    assert(svec_is_unique(&new_br));
    LIST_FOR_EACH_SAFE (br, next, struct bridge, node, &all_bridges) {
        if (!svec_contains(&new_br, br->name)) {
            bridge_destroy(br);
        }
    }
    for (i = 0; i < new_br.n; i++) {
        const char *name = new_br.names[i];
        if (!svec_contains(&old_br, name)) {
            bridge_create(name);
        }
    }
    svec_destroy(&old_br);
    svec_destroy(&new_br);

#ifdef HAVE_OPENSSL
    /* Configure SSL. */
    bridge_configure_ssl();
#endif

    /* Reconfigure all bridges. */
    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        bridge_reconfigure_one(br);
    }

    /* Add and delete ports on all datapaths.
     *
     * The kernel will reject any attempt to add a given port to a datapath if
     * that port already belongs to a different datapath, so we must do all
     * port deletions before any port additions. */
    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        struct odp_port *dpif_ports;
        size_t n_dpif_ports;
        struct svec want_ifaces;

        dpif_port_list(&br->dpif, &dpif_ports, &n_dpif_ports);
        bridge_get_all_ifaces(br, &want_ifaces);
        for (i = 0; i < n_dpif_ports; i++) {
            const struct odp_port *p = &dpif_ports[i];
            if (!svec_contains(&want_ifaces, p->devname)
                && strcmp(p->devname, br->name)) {
                int retval = dpif_port_del(&br->dpif, p->port);
                if (retval) {
                    VLOG_ERR("failed to remove %s interface from dp%u: %s",
                             p->devname, dpif_id(&br->dpif), strerror(retval));
                }
            }
        }
        svec_destroy(&want_ifaces);
        free(dpif_ports);
    }
    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        struct odp_port *dpif_ports;
        size_t n_dpif_ports;
        struct svec cur_ifaces, want_ifaces, add_ifaces;
        int next_port_no;

        dpif_port_list(&br->dpif, &dpif_ports, &n_dpif_ports);
        svec_init(&cur_ifaces);
        for (i = 0; i < n_dpif_ports; i++) {
            svec_add(&cur_ifaces, dpif_ports[i].devname);
        }
        free(dpif_ports);
        svec_sort_unique(&cur_ifaces);
        bridge_get_all_ifaces(br, &want_ifaces);
        svec_diff(&want_ifaces, &cur_ifaces, &add_ifaces, NULL, NULL);

        next_port_no = 1;
        for (i = 0; i < add_ifaces.n; i++) {
            const char *if_name = add_ifaces.names[i];
            for (;;) {
                int internal = cfg_get_bool(0, "iface.%s.internal", if_name);
                int error = dpif_port_add(&br->dpif, if_name, next_port_no++,
                                          internal ? ODP_PORT_INTERNAL : 0);
                if (error != EEXIST) {
                    if (next_port_no >= 256) {
                        VLOG_ERR("ran out of valid port numbers on dp%u",
                                 dpif_id(&br->dpif));
                        goto out;
                    }
                    if (error) {
                        VLOG_ERR("failed to add %s interface to dp%u: %s",
                                 if_name, dpif_id(&br->dpif), strerror(error));
                    }
                    break;
                }
            }
        }
    out:
        svec_destroy(&cur_ifaces);
        svec_destroy(&want_ifaces);
        svec_destroy(&add_ifaces);
    }
    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        uint8_t ea[8];
        uint64_t dpid;
        struct iface *local_iface = NULL;
        const char *devname;
        uint8_t engine_type, engine_id;
        bool add_id_to_iface = false;
        struct svec nf_hosts;

        bridge_fetch_dp_ifaces(br);
        for (i = 0; i < br->n_ports; ) {
            struct port *port = br->ports[i];

            for (j = 0; j < port->n_ifaces; ) {
                struct iface *iface = port->ifaces[j];
                if (iface->dp_ifidx < 0) {
                    VLOG_ERR("%s interface not in dp%u, dropping",
                             iface->name, dpif_id(&br->dpif));
                    iface_destroy(iface);
                } else {
                    if (iface->dp_ifidx == ODPP_LOCAL) {
                        local_iface = iface;
                    }
                    VLOG_DBG("dp%u has interface %s on port %d",
                             dpif_id(&br->dpif), iface->name, iface->dp_ifidx);
                    j++;
                }
            }
            if (!port->n_ifaces) {
                VLOG_ERR("%s port has no interfaces, dropping", port->name);
                port_destroy(port);
                continue;
            }
            i++;
        }

        /* Pick local port hardware address, datapath ID. */
        bridge_pick_local_hw_addr(br, ea, &devname);
        if (local_iface) {
            int error = netdev_nodev_set_etheraddr(local_iface->name, ea);
            if (error) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_ERR_RL(&rl, "bridge %s: failed to set bridge "
                            "Ethernet address: %s",
                            br->name, strerror(error));
            }
        }

        dpid = bridge_pick_datapath_id(br, ea, devname);
        ofproto_set_datapath_id(br->ofproto, dpid);

        /* Set NetFlow configuration on this bridge. */
        dpif_get_netflow_ids(&br->dpif, &engine_type, &engine_id);
        if (cfg_has("netflow.%s.engine-type", br->name)) {
            engine_type = cfg_get_int(0, "netflow.%s.engine-type", 
                    br->name);
        }
        if (cfg_has("netflow.%s.engine-id", br->name)) {
            engine_id = cfg_get_int(0, "netflow.%s.engine-id", br->name);
        }
        if (cfg_has("netflow.%s.add-id-to-iface", br->name)) {
            add_id_to_iface = cfg_get_bool(0, "netflow.%s.add-id-to-iface",
                    br->name);
        }
        if (add_id_to_iface && engine_id > 0x7f) {
            VLOG_WARN("bridge %s: netflow port mangling may conflict with "
                    "another vswitch, choose an engine id less than 128", 
                    br->name);
        }
        if (add_id_to_iface && br->n_ports > 0x1ff) {
            VLOG_WARN("bridge %s: netflow port mangling will conflict with "
                    "another port when 512 or more ports are used", 
                    br->name);
        }
        svec_init(&nf_hosts);
        cfg_get_all_keys(&nf_hosts, "netflow.%s.host", br->name);
        if (ofproto_set_netflow(br->ofproto, &nf_hosts,  engine_type, 
                    engine_id, add_id_to_iface)) {
            VLOG_ERR("bridge %s: problem setting netflow collectors", 
                    br->name);
        }

        /* Update the controller and related settings.  It would be more
         * straightforward to call this from bridge_reconfigure_one(), but we
         * can't do it there for two reasons.  First, and most importantly, at
         * that point we don't know the dp_ifidx of any interfaces that have
         * been added to the bridge (because we haven't actually added them to
         * the datapath).  Second, at that point we haven't set the datapath ID
         * yet; when a controller is configured, resetting the datapath ID will
         * immediately disconnect from the controller, so it's better to set
         * the datapath ID before the controller. */
        bridge_reconfigure_controller(br);
    }
    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        for (i = 0; i < br->n_ports; i++) {
            struct port *port = br->ports[i];
            port_update_vlan_compat(port);
        }
    }
    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        brstp_reconfigure(br);
    }
}

static void
bridge_pick_local_hw_addr(struct bridge *br, uint8_t ea[ETH_ADDR_LEN],
                          const char **devname)
{
    uint64_t requested_ea;
    size_t i, j;
    int error;

    *devname = NULL;

    /* Did the user request a particular MAC? */
    requested_ea = cfg_get_mac(0, "bridge.%s.mac", br->name);
    if (requested_ea) {
        eth_addr_from_uint64(requested_ea, ea);
        if (eth_addr_is_multicast(ea)) {
            VLOG_ERR("bridge %s: cannot set MAC address to multicast "
                     "address "ETH_ADDR_FMT, br->name, ETH_ADDR_ARGS(ea));
        } else if (eth_addr_is_zero(ea)) {
            VLOG_ERR("bridge %s: cannot set MAC address to zero", br->name);
        } else {
            return;
        }
    }

    /* Otherwise choose the minimum MAC address among all of the interfaces.
     * (Xen uses FE:FF:FF:FF:FF:FF for virtual interfaces so this will get the
     * MAC of the physical interface in such an environment.) */
    memset(ea, 0xff, sizeof ea);
    for (i = 0; i < br->n_ports; i++) {
        struct port *port = br->ports[i];
        if (port->is_mirror_output_port) {
            continue;
        }
        for (j = 0; j < port->n_ifaces; j++) {
            struct iface *iface = port->ifaces[j];
            uint8_t iface_ea[ETH_ADDR_LEN];
            if (iface->dp_ifidx == ODPP_LOCAL
                || cfg_get_bool(0, "iface.%s.internal", iface->name)) {
                continue;
            }
            error = netdev_nodev_get_etheraddr(iface->name, iface_ea);
            if (!error) {
                if (!eth_addr_is_multicast(iface_ea) &&
                    !eth_addr_is_reserved(iface_ea) &&
                    !eth_addr_is_zero(iface_ea) &&
                    memcmp(iface_ea, ea, ETH_ADDR_LEN) < 0) {
                    memcpy(ea, iface_ea, ETH_ADDR_LEN);
                    *devname = iface->name;
                }
            } else {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_ERR_RL(&rl, "failed to obtain Ethernet address of %s: %s",
                            iface->name, strerror(error));
            }
        }
    }
    if (eth_addr_is_multicast(ea) || eth_addr_is_vif(ea)) {
        memcpy(ea, br->default_ea, ETH_ADDR_LEN);
        *devname = NULL;
        VLOG_WARN("bridge %s: using default bridge Ethernet "
                  "address "ETH_ADDR_FMT, br->name, ETH_ADDR_ARGS(ea));
    } else {
        VLOG_DBG("bridge %s: using bridge Ethernet address "ETH_ADDR_FMT,
                 br->name, ETH_ADDR_ARGS(ea));
    }
}

/* Choose and returns the datapath ID for bridge 'br' given that the bridge
 * Ethernet address is 'bridge_ea'.  If 'bridge_ea' is the Ethernet address of
 * a network device, then that network device's name must be passed in as
 * 'devname'; if 'bridge_ea' was derived some other way, then 'devname' must be
 * passed in as a null pointer. */
static uint64_t
bridge_pick_datapath_id(struct bridge *br,
                        const uint8_t bridge_ea[ETH_ADDR_LEN],
                        const char *devname)
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
    uint64_t dpid;

    dpid = cfg_get_dpid(0, "bridge.%s.datapath-id", br->name);
    if (dpid) {
        return dpid;
    }

    if (devname) {
        int vlan;
        if (!netdev_get_vlan_vid(devname, &vlan)) {
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

int
bridge_run(void)
{
    struct bridge *br, *next;
    int retval;

    retval = 0;
    LIST_FOR_EACH_SAFE (br, next, struct bridge, node, &all_bridges) {
        int error = bridge_run_one(br);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_ERR_RL(&rl, "bridge %s: datapath was destroyed externally, "
                        "forcing reconfiguration", br->name);
            if (!retval) {
                retval = error;
            }
        }
    }
    return retval;
}

void
bridge_wait(void)
{
    struct bridge *br;

    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        ofproto_wait(br->ofproto);
        if (br->controller) {
            continue;
        }

        if (br->ml) {
            mac_learning_wait(br->ml);
        }
        bond_wait(br);
        brstp_wait(br);
    }
}

/* Forces 'br' to revalidate all of its flows.  This is appropriate when 'br''s
 * configuration changes.  */
static void
bridge_flush(struct bridge *br)
{
    COVERAGE_INC(bridge_flush);
    br->flush = true;
    if (br->ml) {
        mac_learning_flush(br->ml);
    }
}

/* Bridge reconfiguration functions. */

static struct bridge *
bridge_create(const char *name)
{
    struct bridge *br;
    int error;

    assert(!bridge_lookup(name));
    br = xcalloc(1, sizeof *br);

    error = dpif_create(name, &br->dpif);
    if (error == EEXIST) {
        error = dpif_open(name, &br->dpif);
        if (error) {
            VLOG_ERR("datapath %s already exists but cannot be opened: %s",
                     name, strerror(error));
            free(br);
            return NULL;
        }
        dpif_flow_flush(&br->dpif);
    } else if (error) {
        VLOG_ERR("failed to create datapath %s: %s", name, strerror(error));
        free(br);
        return NULL;
    }

    error = ofproto_create(name, &bridge_ofhooks, br, &br->ofproto);
    if (error) {
        VLOG_ERR("failed to create switch %s: %s", name, strerror(error));
        dpif_delete(&br->dpif);
        dpif_close(&br->dpif);
        free(br);
        return NULL;
    }

    br->name = xstrdup(name);
    br->ml = mac_learning_create();
    br->sent_config_request = false;
    eth_addr_random(br->default_ea);

    port_array_init(&br->ifaces);

    br->flush = false;
    br->bond_next_rebalance = time_msec() + 10000;

    list_push_back(&all_bridges, &br->node);

    VLOG_INFO("created bridge %s on dp%u", br->name, dpif_id(&br->dpif));

    return br;
}

static void
bridge_destroy(struct bridge *br)
{
    if (br) {
        int error;

        while (br->n_ports > 0) {
            port_destroy(br->ports[br->n_ports - 1]);
        }
        list_remove(&br->node);
        error = dpif_delete(&br->dpif);
        if (error && error != ENOENT) {
            VLOG_ERR("failed to delete dp%u: %s",
                     dpif_id(&br->dpif), strerror(error));
        }
        dpif_close(&br->dpif);
        ofproto_destroy(br->ofproto);
        free(br->controller);
        mac_learning_destroy(br->ml);
        port_array_destroy(&br->ifaces);
        free(br->ports);
        free(br->name);
        free(br);
    }
}

static struct bridge *
bridge_lookup(const char *name)
{
    struct bridge *br;

    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        if (!strcmp(br->name, name)) {
            return br;
        }
    }
    return NULL;
}

bool
bridge_exists(const char *name)
{
    return bridge_lookup(name) ? true : false;
}

uint64_t
bridge_get_datapathid(const char *name)
{
    struct bridge *br = bridge_lookup(name);
    return br ? ofproto_get_datapath_id(br->ofproto) : 0;
}

static int
bridge_run_one(struct bridge *br)
{
    int error;

    error = ofproto_run1(br->ofproto);
    if (error) {
        return error;
    }

    if (br->ml) {
        mac_learning_run(br->ml, ofproto_get_revalidate_set(br->ofproto));
    }
    bond_run(br);
    brstp_run(br);

    error = ofproto_run2(br->ofproto, br->flush);
    br->flush = false;

    return error;
}

static const char *
bridge_get_controller(const struct bridge *br)
{
    const char *controller;

    controller = cfg_get_string(0, "bridge.%s.controller", br->name);
    if (!controller) {
        controller = cfg_get_string(0, "mgmt.controller");
    }
    return controller && controller[0] ? controller : NULL;
}

static void
bridge_reconfigure_one(struct bridge *br)
{
    struct svec old_ports, new_ports, ifaces;
    struct svec listeners, old_listeners;
    struct svec snoops, old_snoops;
    size_t i, j;

    /* Collect old ports. */
    svec_init(&old_ports);
    for (i = 0; i < br->n_ports; i++) {
        svec_add(&old_ports, br->ports[i]->name);
    }
    svec_sort(&old_ports);
    assert(svec_is_unique(&old_ports));

    /* Collect new ports. */
    svec_init(&new_ports);
    cfg_get_all_keys(&new_ports, "bridge.%s.port", br->name);
    svec_sort(&new_ports);
    if (bridge_get_controller(br) && !svec_contains(&new_ports, br->name)) {
        svec_add(&new_ports, br->name);
        svec_sort(&new_ports);
    }
    if (!svec_is_unique(&new_ports)) {
        VLOG_WARN("bridge %s: %s specified twice as bridge port",
                  br->name, svec_get_duplicate(&new_ports));
        svec_unique(&new_ports);
    }

    ofproto_set_mgmt_id(br->ofproto, mgmt_id);

    /* Get rid of deleted ports and add new ports. */
    for (i = 0; i < br->n_ports; ) {
        struct port *port = br->ports[i];
        if (!svec_contains(&new_ports, port->name)) {
            port_destroy(port);
        } else {
            i++;
        }
    }
    for (i = 0; i < new_ports.n; i++) {
        const char *name = new_ports.names[i];
        if (!svec_contains(&old_ports, name)) {
            port_create(br, name);
        }
    }
    svec_destroy(&old_ports);
    svec_destroy(&new_ports);

    /* Reconfigure all ports. */
    for (i = 0; i < br->n_ports; i++) {
        port_reconfigure(br->ports[i]);
    }

    /* Check and delete duplicate interfaces. */
    svec_init(&ifaces);
    for (i = 0; i < br->n_ports; ) {
        struct port *port = br->ports[i];
        for (j = 0; j < port->n_ifaces; ) {
            struct iface *iface = port->ifaces[j];
            if (svec_contains(&ifaces, iface->name)) {
                VLOG_ERR("bridge %s: %s interface is on multiple ports, "
                         "removing from %s",
                         br->name, iface->name, port->name);
                iface_destroy(iface);
            } else {
                svec_add(&ifaces, iface->name);
                svec_sort(&ifaces);
                j++;
            }
        }
        if (!port->n_ifaces) {
            VLOG_ERR("%s port has no interfaces, dropping", port->name);
            port_destroy(port);
        } else {
            i++;
        }
    }
    svec_destroy(&ifaces);

    /* Delete all flows if we're switching from connected to standalone or vice
     * versa.  (XXX Should we delete all flows if we are switching from one
     * controller to another?) */

    /* Configure OpenFlow management listeners. */
    svec_init(&listeners);
    cfg_get_all_strings(&listeners, "bridge.%s.openflow.listeners", br->name);
    if (!listeners.n) {
        svec_add_nocopy(&listeners, xasprintf("punix:%s/%s.mgmt",
                                              ovs_rundir, br->name));
    } else if (listeners.n == 1 && !strcmp(listeners.names[0], "none")) {
        svec_clear(&listeners);
    }
    svec_sort_unique(&listeners);

    svec_init(&old_listeners);
    ofproto_get_listeners(br->ofproto, &old_listeners);
    svec_sort_unique(&old_listeners);

    if (!svec_equal(&listeners, &old_listeners)) {
        ofproto_set_listeners(br->ofproto, &listeners);
    }
    svec_destroy(&listeners);
    svec_destroy(&old_listeners);

    /* Configure OpenFlow controller connection snooping. */
    svec_init(&snoops);
    cfg_get_all_strings(&snoops, "bridge.%s.openflow.snoops", br->name);
    if (!snoops.n) {
        svec_add_nocopy(&snoops, xasprintf("punix:%s/%s.snoop",
                                           ovs_rundir, br->name));
    } else if (snoops.n == 1 && !strcmp(snoops.names[0], "none")) {
        svec_clear(&snoops);
    }
    svec_sort_unique(&snoops);

    svec_init(&old_snoops);
    ofproto_get_snoops(br->ofproto, &old_snoops);
    svec_sort_unique(&old_snoops);

    if (!svec_equal(&snoops, &old_snoops)) {
        ofproto_set_snoops(br->ofproto, &snoops);
    }
    svec_destroy(&snoops);
    svec_destroy(&old_snoops);

    mirror_reconfigure(br);
}

static void
bridge_reconfigure_controller(struct bridge *br)
{
    char *pfx = xasprintf("bridge.%s.controller", br->name);
    const char *controller;

    controller = bridge_get_controller(br);
    if ((br->controller != NULL) != (controller != NULL)) {
        ofproto_flush_flows(br->ofproto);
    }
    free(br->controller);
    br->controller = controller ? xstrdup(controller) : NULL;

    if (controller) {
        const char *fail_mode;
        int max_backoff, probe;
        int rate_limit, burst_limit;

        if (!strcmp(controller, "discover")) {
            ofproto_set_discovery(br->ofproto, true,
                                  cfg_get_string(0, "%s.accept-regex", pfx),
                                  cfg_get_bool(0, "%s.update-resolv.conf",
                                               pfx));
        } else {
            struct netdev *netdev;
            bool in_band;
            int error;

            in_band = (!cfg_is_valid(CFG_BOOL | CFG_REQUIRED,
                                     "%s.in-band", pfx)
                       || cfg_get_bool(0, "%s.in-band", pfx));
            ofproto_set_discovery(br->ofproto, false, NULL, NULL);
            ofproto_set_in_band(br->ofproto, in_band);

            error = netdev_open(br->name, NETDEV_ETH_TYPE_NONE, &netdev);
            if (!error) {
                if (cfg_is_valid(CFG_IP | CFG_REQUIRED, "%s.ip", pfx)) {
                    struct in_addr ip, mask, gateway;
                    ip.s_addr = cfg_get_ip(0, "%s.ip", pfx);
                    mask.s_addr = cfg_get_ip(0, "%s.netmask", pfx);
                    gateway.s_addr = cfg_get_ip(0, "%s.gateway", pfx);

                    netdev_turn_flags_on(netdev, NETDEV_UP, true);
                    if (!mask.s_addr) {
                        mask.s_addr = guess_netmask(ip.s_addr);
                    }
                    if (!netdev_set_in4(netdev, ip, mask)) {
                        VLOG_INFO("bridge %s: configured IP address "IP_FMT", "
                                  "netmask "IP_FMT,
                                  br->name, IP_ARGS(&ip.s_addr),
                                  IP_ARGS(&mask.s_addr));
                    }

                    if (gateway.s_addr) {
                        if (!netdev_add_router(gateway)) {
                            VLOG_INFO("bridge %s: configured gateway "IP_FMT,
                                      br->name, IP_ARGS(&gateway.s_addr));
                        }
                    }
                }
                netdev_close(netdev);
            }
        }

        fail_mode = cfg_get_string(0, "%s.fail-mode", pfx);
        if (!fail_mode) {
            fail_mode = cfg_get_string(0, "mgmt.fail-mode");
        }
        ofproto_set_failure(br->ofproto,
                            (!fail_mode
                             || !strcmp(fail_mode, "standalone")
                             || !strcmp(fail_mode, "open")));

        probe = cfg_get_int(0, "%s.inactivity-probe", pfx);
        if (probe < 5) {
            probe = cfg_get_int(0, "mgmt.inactivity-probe");
            if (probe < 5) {
                probe = 15;
            }
        }
        ofproto_set_probe_interval(br->ofproto, probe);

        max_backoff = cfg_get_int(0, "%s.max-backoff", pfx);
        if (!max_backoff) {
            max_backoff = cfg_get_int(0, "mgmt.max-backoff");
            if (!max_backoff) {
                max_backoff = 15;
            }
        }
        ofproto_set_max_backoff(br->ofproto, max_backoff);

        rate_limit = cfg_get_int(0, "%s.rate-limit", pfx);
        if (!rate_limit) {
            rate_limit = cfg_get_int(0, "mgmt.rate-limit");
        }
        burst_limit = cfg_get_int(0, "%s.burst-limit", pfx);
        if (!burst_limit) {
            burst_limit = cfg_get_int(0, "mgmt.burst-limit");
        }
        ofproto_set_rate_limit(br->ofproto, rate_limit, burst_limit);

        ofproto_set_stp(br->ofproto, cfg_get_bool(0, "%s.stp", pfx));

        if (cfg_has("%s.commands.acl", pfx)) {
            struct svec command_acls;
            char *command_acl;

            svec_init(&command_acls);
            cfg_get_all_strings(&command_acls, "%s.commands.acl", pfx);
            command_acl = svec_join(&command_acls, ",", "");

            ofproto_set_remote_execution(br->ofproto, command_acl,
                                         cfg_get_string(0, "%s.commands.dir",
                                                        pfx));

            svec_destroy(&command_acls);
            free(command_acl);
        } else {
            ofproto_set_remote_execution(br->ofproto, NULL, NULL);
        }
    } else {
        union ofp_action action;
        flow_t flow;

        /* Set up a flow that matches every packet and directs them to
         * OFPP_NORMAL (which goes to us). */
        memset(&action, 0, sizeof action);
        action.type = htons(OFPAT_OUTPUT);
        action.output.len = htons(sizeof action);
        action.output.port = htons(OFPP_NORMAL);
        memset(&flow, 0, sizeof flow);
        ofproto_add_flow(br->ofproto, &flow, OFPFW_ALL, 0,
                         &action, 1, 0);

        ofproto_set_in_band(br->ofproto, false);
        ofproto_set_max_backoff(br->ofproto, 1);
        ofproto_set_probe_interval(br->ofproto, 5);
        ofproto_set_failure(br->ofproto, false);
        ofproto_set_stp(br->ofproto, false);
    }
    free(pfx);

    ofproto_set_controller(br->ofproto, br->controller);
}

static void
bridge_get_all_ifaces(const struct bridge *br, struct svec *ifaces)
{
    size_t i, j;

    svec_init(ifaces);
    for (i = 0; i < br->n_ports; i++) {
        struct port *port = br->ports[i];
        for (j = 0; j < port->n_ifaces; j++) {
            struct iface *iface = port->ifaces[j];
            svec_add(ifaces, iface->name);
        }
    }
    svec_sort(ifaces);
    assert(svec_is_unique(ifaces));
}

/* For robustness, in case the administrator moves around datapath ports behind
 * our back, we re-check all the datapath port numbers here.
 *
 * This function will set the 'dp_ifidx' members of interfaces that have
 * disappeared to -1, so only call this function from a context where those
 * 'struct iface's will be removed from the bridge.  Otherwise, the -1
 * 'dp_ifidx'es will cause trouble later when we try to send them to the
 * datapath, which doesn't support UINT16_MAX+1 ports. */
static void
bridge_fetch_dp_ifaces(struct bridge *br)
{
    struct odp_port *dpif_ports;
    size_t n_dpif_ports;
    size_t i, j;

    /* Reset all interface numbers. */
    for (i = 0; i < br->n_ports; i++) {
        struct port *port = br->ports[i];
        for (j = 0; j < port->n_ifaces; j++) {
            struct iface *iface = port->ifaces[j];
            iface->dp_ifidx = -1;
        }
    }
    port_array_clear(&br->ifaces);

    dpif_port_list(&br->dpif, &dpif_ports, &n_dpif_ports);
    for (i = 0; i < n_dpif_ports; i++) {
        struct odp_port *p = &dpif_ports[i];
        struct iface *iface = iface_lookup(br, p->devname);
        if (iface) {
            if (iface->dp_ifidx >= 0) {
                VLOG_WARN("dp%u reported interface %s twice",
                          dpif_id(&br->dpif), p->devname);
            } else if (iface_from_dp_ifidx(br, p->port)) {
                VLOG_WARN("dp%u reported interface %"PRIu16" twice",
                          dpif_id(&br->dpif), p->port);
            } else {
                port_array_set(&br->ifaces, p->port, iface);
                iface->dp_ifidx = p->port;
            }
        }
    }
    free(dpif_ports);
}

/* Bridge packet processing functions. */

static int
bond_hash(const uint8_t mac[ETH_ADDR_LEN])
{
    return hash_bytes(mac, ETH_ADDR_LEN, 0) & BOND_MASK;
}

static struct bond_entry *
lookup_bond_entry(const struct port *port, const uint8_t mac[ETH_ADDR_LEN])
{
    return &port->bond_hash[bond_hash(mac)];
}

static int
bond_choose_iface(const struct port *port)
{
    size_t i;
    for (i = 0; i < port->n_ifaces; i++) {
        if (port->ifaces[i]->enabled) {
            return i;
        }
    }
    return -1;
}

static bool
choose_output_iface(const struct port *port, const uint8_t *dl_src,
                    uint16_t *dp_ifidx, tag_type *tags)
{
    struct iface *iface;

    assert(port->n_ifaces);
    if (port->n_ifaces == 1) {
        iface = port->ifaces[0];
    } else {
        struct bond_entry *e = lookup_bond_entry(port, dl_src);
        if (e->iface_idx < 0 || e->iface_idx >= port->n_ifaces
            || !port->ifaces[e->iface_idx]->enabled) {
            /* XXX select interface properly.  The current interface selection
             * is only good for testing the rebalancing code. */
            e->iface_idx = bond_choose_iface(port);
            if (e->iface_idx < 0) {
                *tags |= port->no_ifaces_tag;
                return false;
            }
            e->iface_tag = tag_create_random();
        }
        *tags |= e->iface_tag;
        iface = port->ifaces[e->iface_idx];
    }
    *dp_ifidx = iface->dp_ifidx;
    *tags |= iface->tag;        /* Currently only used for bonding. */
    return true;
}

static void
bond_link_status_update(struct iface *iface, bool carrier)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct port *port = iface->port;

    if ((carrier == iface->enabled) == (iface->delay_expires == LLONG_MAX)) {
        /* Nothing to do. */
        return;
    }
    VLOG_INFO_RL(&rl, "interface %s: carrier %s",
                 iface->name, carrier ? "detected" : "dropped");
    if (carrier == iface->enabled) {
        iface->delay_expires = LLONG_MAX;
        VLOG_INFO_RL(&rl, "interface %s: will not be %s",
                     iface->name, carrier ? "disabled" : "enabled");
    } else {
        int delay = carrier ? port->updelay : port->downdelay;
        iface->delay_expires = time_msec() + delay;
        if (delay) {
            VLOG_INFO_RL(&rl,
                         "interface %s: will be %s if it stays %s for %d ms",
                         iface->name,
                         carrier ? "enabled" : "disabled",
                         carrier ? "up" : "down",
                         delay);
        }
    }
}

static void
bond_choose_active_iface(struct port *port)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

    port->active_iface = bond_choose_iface(port);
    port->active_iface_tag = tag_create_random();
    if (port->active_iface >= 0) {
        VLOG_INFO_RL(&rl, "port %s: active interface is now %s",
                     port->name, port->ifaces[port->active_iface]->name);
    } else {
        VLOG_WARN_RL(&rl, "port %s: all ports disabled, no active interface",
                     port->name);
    }
}

static void
bond_enable_slave(struct iface *iface, bool enable)
{
    struct port *port = iface->port;
    struct bridge *br = port->bridge;

    iface->delay_expires = LLONG_MAX;
    if (enable == iface->enabled) {
        return;
    }

    iface->enabled = enable;
    if (!iface->enabled) {
        VLOG_WARN("interface %s: enabled", iface->name);
        ofproto_revalidate(br->ofproto, iface->tag);
        if (iface->port_ifidx == port->active_iface) {
            ofproto_revalidate(br->ofproto,
                               port->active_iface_tag);
            bond_choose_active_iface(port);
        }
        bond_send_learning_packets(port);
    } else {
        VLOG_WARN("interface %s: disabled", iface->name);
        if (port->active_iface < 0) {
            ofproto_revalidate(br->ofproto, port->no_ifaces_tag);
            bond_choose_active_iface(port);
            bond_send_learning_packets(port);
        }
        iface->tag = tag_create_random();
    }
}

static void
bond_run(struct bridge *br)
{
    size_t i, j;

    for (i = 0; i < br->n_ports; i++) {
        struct port *port = br->ports[i];
        if (port->n_ifaces < 2) {
            continue;
        }
        for (j = 0; j < port->n_ifaces; j++) {
            struct iface *iface = port->ifaces[j];
            if (time_msec() >= iface->delay_expires) {
                bond_enable_slave(iface, !iface->enabled);
            }
        }
    }
}

static void
bond_wait(struct bridge *br)
{
    size_t i, j;

    for (i = 0; i < br->n_ports; i++) {
        struct port *port = br->ports[i];
        if (port->n_ifaces < 2) {
            continue;
        }
        for (j = 0; j < port->n_ifaces; j++) {
            struct iface *iface = port->ifaces[j];
            if (iface->delay_expires != LLONG_MAX) {
                poll_timer_wait(iface->delay_expires - time_msec());
            }
        }
    }
}

static bool
set_dst(struct dst *p, const flow_t *flow,
        const struct port *in_port, const struct port *out_port,
        tag_type *tags)
{
    /* STP handling.
     *
     * XXX This uses too many tags: any broadcast flow will get one tag per
     * destination port, and thus a broadcast on a switch of any size is likely
     * to have all tag bits set.  We should figure out a way to be smarter.
     *
     * This is OK when STP is disabled, because stp_state_tag is 0 then. */
    *tags |= out_port->stp_state_tag;
    if (!(out_port->stp_state & (STP_DISABLED | STP_FORWARDING))) {
        return false;
    }

    p->vlan = (out_port->vlan >= 0 ? OFP_VLAN_NONE
              : in_port->vlan >= 0 ? in_port->vlan
              : ntohs(flow->dl_vlan));
    return choose_output_iface(out_port, flow->dl_src, &p->dp_ifidx, tags);
}

static void
swap_dst(struct dst *p, struct dst *q)
{
    struct dst tmp = *p;
    *p = *q;
    *q = tmp;
}

/* Moves all the dsts with vlan == 'vlan' to the front of the 'n_dsts' in
 * 'dsts'.  (This may help performance by reducing the number of VLAN changes
 * that we push to the datapath.  We could in fact fully sort the array by
 * vlan, but in most cases there are at most two different vlan tags so that's
 * possibly overkill.) */
static void
partition_dsts(struct dst *dsts, size_t n_dsts, int vlan)
{
    struct dst *first = dsts;
    struct dst *last = dsts + n_dsts;

    while (first != last) {
        /* Invariants:
         *      - All dsts < first have vlan == 'vlan'.
         *      - All dsts >= last have vlan != 'vlan'.
         *      - first < last. */
        while (first->vlan == vlan) {
            if (++first == last) {
                return;
            }
        }

        /* Same invariants, plus one additional:
         *      - first->vlan != vlan.
         */
        while (last[-1].vlan != vlan) {
            if (--last == first) {
                return;
            }
        }

        /* Same invariants, plus one additional:
         *      - last[-1].vlan == vlan.*/
        swap_dst(first++, --last);
    }
}

static int
mirror_mask_ffs(mirror_mask_t mask)
{
    BUILD_ASSERT_DECL(sizeof(unsigned int) >= sizeof(mask));
    return ffs(mask);
}

static bool
dst_is_duplicate(const struct dst *dsts, size_t n_dsts,
                 const struct dst *test)
{
    size_t i;
    for (i = 0; i < n_dsts; i++) {
        if (dsts[i].vlan == test->vlan && dsts[i].dp_ifidx == test->dp_ifidx) {
            return true;
        }
    }
    return false;
}

static bool
port_trunks_vlan(const struct port *port, uint16_t vlan)
{
    return port->vlan < 0 && bitmap_is_set(port->trunks, vlan);
}

static bool
port_includes_vlan(const struct port *port, uint16_t vlan)
{
    return vlan == port->vlan || port_trunks_vlan(port, vlan);
}

static size_t
compose_dsts(const struct bridge *br, const flow_t *flow, uint16_t vlan,
             const struct port *in_port, const struct port *out_port,
             struct dst dsts[], tag_type *tags)
{
    mirror_mask_t mirrors = in_port->src_mirrors;
    struct dst *dst = dsts;
    size_t i;

    *tags |= in_port->stp_state_tag;
    if (out_port == FLOOD_PORT) {
        /* XXX use ODP_FLOOD if no vlans or bonding. */
        /* XXX even better, define each VLAN as a datapath port group */
        for (i = 0; i < br->n_ports; i++) {
            struct port *port = br->ports[i];
            if (port != in_port && port_includes_vlan(port, vlan)
                && !port->is_mirror_output_port
                && set_dst(dst, flow, in_port, port, tags)) {
                mirrors |= port->dst_mirrors;
                dst++;
            }
        }
    } else if (out_port && set_dst(dst, flow, in_port, out_port, tags)) {
        mirrors |= out_port->dst_mirrors;
        dst++;
    }

    while (mirrors) {
        struct mirror *m = br->mirrors[mirror_mask_ffs(mirrors) - 1];
        if (!m->n_vlans || vlan_is_mirrored(m, vlan)) {
            if (m->out_port) {
                if (set_dst(dst, flow, in_port, m->out_port, tags)
                    && !dst_is_duplicate(dsts, dst - dsts, dst)) {
                    dst++;
                }
            } else {
                for (i = 0; i < br->n_ports; i++) {
                    struct port *port = br->ports[i];
                    if (port_includes_vlan(port, m->out_vlan)
                        && set_dst(dst, flow, in_port, port, tags)
                        && !dst_is_duplicate(dsts, dst - dsts, dst))
                    {
                        if (port->vlan < 0) {
                            dst->vlan = m->out_vlan;
                        }
                        if (dst->dp_ifidx == flow->in_port
                            && dst->vlan == vlan) {
                            /* Don't send out input port on same VLAN. */
                            continue;
                        }
                        dst++;
                    }
                }
            }
        }
        mirrors &= mirrors - 1;
    }

    partition_dsts(dsts, dst - dsts, ntohs(flow->dl_vlan));
    return dst - dsts;
}

static void UNUSED
print_dsts(const struct dst *dsts, size_t n)
{
    for (; n--; dsts++) {
        printf(">p%"PRIu16, dsts->dp_ifidx);
        if (dsts->vlan != OFP_VLAN_NONE) {
            printf("v%"PRIu16, dsts->vlan);
        }
    }
}

static void
compose_actions(struct bridge *br, const flow_t *flow, uint16_t vlan,
                const struct port *in_port, const struct port *out_port,
                tag_type *tags, struct odp_actions *actions)
{
    struct dst dsts[DP_MAX_PORTS * (MAX_MIRRORS + 1)];
    size_t n_dsts;
    const struct dst *p;
    uint16_t cur_vlan;

    n_dsts = compose_dsts(br, flow, vlan, in_port, out_port, dsts, tags);

    cur_vlan = ntohs(flow->dl_vlan);
    for (p = dsts; p < &dsts[n_dsts]; p++) {
        union odp_action *a;
        if (p->vlan != cur_vlan) {
            if (p->vlan == OFP_VLAN_NONE) {
                odp_actions_add(actions, ODPAT_STRIP_VLAN);
            } else {
                a = odp_actions_add(actions, ODPAT_SET_VLAN_VID);
                a->vlan_vid.vlan_vid = htons(p->vlan);
            }
            cur_vlan = p->vlan;
        }
        a = odp_actions_add(actions, ODPAT_OUTPUT);
        a->output.port = p->dp_ifidx;
    }
}

static bool
is_bcast_arp_reply(const flow_t *flow, const struct ofpbuf *packet)
{
    struct arp_eth_header *arp = (struct arp_eth_header *) packet->data;
    return (flow->dl_type == htons(ETH_TYPE_ARP)
            && eth_addr_is_broadcast(flow->dl_dst)
            && packet->size >= sizeof(struct arp_eth_header)
            && arp->ar_op == ARP_OP_REQUEST);
}

/* If the composed actions may be applied to any packet in the given 'flow',
 * returns true.  Otherwise, the actions should only be applied to 'packet', or
 * not at all, if 'packet' was NULL. */
static bool
process_flow(struct bridge *br, const flow_t *flow,
             const struct ofpbuf *packet, struct odp_actions *actions,
             tag_type *tags)
{
    struct iface *in_iface;
    struct port *in_port;
    struct port *out_port = NULL; /* By default, drop the packet/flow. */
    int vlan;

    /* Find the interface and port structure for the received packet. */
    in_iface = iface_from_dp_ifidx(br, flow->in_port);
    if (!in_iface) {
        /* No interface?  Something fishy... */
        if (packet != NULL) {
            /* Odd.  A few possible reasons here:
             *
             * - We deleted an interface but there are still a few packets
             *   queued up from it.
             *
             * - Someone externally added an interface (e.g. with "ovs-dpctl
             *   add-if") that we don't know about.
             *
             * - Packet arrived on the local port but the local port is not
             *   one of our bridge ports.
             */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_WARN_RL(&rl, "bridge %s: received packet on unknown "
                         "interface %"PRIu16, br->name, flow->in_port); 
        }

        /* Return without adding any actions, to drop packets on this flow. */
        return true;
    }
    in_port = in_iface->port;

    /* Figure out what VLAN this packet belongs to.
     *
     * Note that dl_vlan of 0 and of OFP_VLAN_NONE both mean that the packet
     * belongs to VLAN 0, so we should treat both cases identically.  (In the
     * former case, the packet has an 802.1Q header that specifies VLAN 0,
     * presumably to allow a priority to be specified.  In the latter case, the
     * packet does not have any 802.1Q header.) */
    vlan = ntohs(flow->dl_vlan);
    if (vlan == OFP_VLAN_NONE) {
        vlan = 0;
    }
    if (in_port->vlan >= 0) {
        if (vlan) {
            /* XXX support double tagging? */
            if (packet != NULL) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "bridge %s: dropping VLAN %"PRIu16" tagged "
                             "packet received on port %s configured with "
                             "implicit VLAN %"PRIu16,
                             br->name, ntohs(flow->dl_vlan),
                             in_port->name, in_port->vlan);
            }
            goto done;
        }
        vlan = in_port->vlan;
    } else {
        if (!port_includes_vlan(in_port, vlan)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping VLAN %d tagged "
                         "packet received on port %s not configured for "
                         "trunking VLAN %d",
                         br->name, vlan, in_port->name, vlan);
            goto done;
        }
    }

    /* Drop frames for ports that STP wants entirely killed (both for
     * forwarding and for learning).  Later, after we do learning, we'll drop
     * the frames that STP wants to do learning but not forwarding on. */
    if (in_port->stp_state & (STP_LISTENING | STP_BLOCKING)) {
        goto done;
    }

    /* Drop frames for reserved multicast addresses. */
    if (eth_addr_is_reserved(flow->dl_dst)) {
        goto done;
    }

    /* Drop frames on ports reserved for mirroring. */
    if (in_port->is_mirror_output_port) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port %s, "
                     "which is reserved exclusively for mirroring",
                     br->name, in_port->name);
        goto done;
    }

    /* Multicast (and broadcast) packets on bonds need special attention, to
     * avoid receiving duplicates. */
    if (in_port->n_ifaces > 1 && eth_addr_is_multicast(flow->dl_dst)) {
        *tags |= in_port->active_iface_tag;
        if (in_port->active_iface != in_iface->port_ifidx) {
            /* Drop all multicast packets on inactive slaves. */
            goto done;
        } else {
            /* Drop all multicast packets for which we have learned a different
             * input port, because we probably sent the packet on one slaves
             * and got it back on the active slave.  Broadcast ARP replies are
             * an exception to this rule: the host has moved to another
             * switch. */
            int src_idx = mac_learning_lookup(br->ml, flow->dl_src, vlan);
            if (src_idx != -1 && src_idx != in_port->port_idx) {
                if (packet) {
                    if (!is_bcast_arp_reply(flow, packet)) {
                        goto done;
                    }
                } else {
                    /* No way to know whether it's an ARP reply, because the
                     * flow entry doesn't include enough information and we
                     * don't have a packet.  Punt. */
                    return false;
                }
            }
        }
    }

    /* MAC learning. */
    out_port = FLOOD_PORT;
    if (br->ml) {
        int out_port_idx;

        /* Learn source MAC (but don't try to learn from revalidation). */
        if (packet) {
            tag_type rev_tag = mac_learning_learn(br->ml, flow->dl_src,
                                                  vlan, in_port->port_idx);
            if (rev_tag) {
                /* The log messages here could actually be useful in debugging,
                 * so keep the rate limit relatively high. */
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30,
                                                                        300);
                VLOG_DBG_RL(&rl, "bridge %s: learned that "ETH_ADDR_FMT" is "
                            "on port %s in VLAN %d",
                            br->name, ETH_ADDR_ARGS(flow->dl_src),
                            in_port->name, vlan);
                ofproto_revalidate(br->ofproto, rev_tag);
            }
        }

        /* Determine output port. */
        out_port_idx = mac_learning_lookup_tag(br->ml, flow->dl_dst, vlan,
                                               tags);
        if (out_port_idx >= 0 && out_port_idx < br->n_ports) {
            out_port = br->ports[out_port_idx];
        }
    }

    /* Don't send packets out their input ports.  Don't forward frames that STP
     * wants us to discard. */
    if (in_port == out_port || in_port->stp_state == STP_LEARNING) {
        out_port = NULL;
    }

done:
    compose_actions(br, flow, vlan, in_port, out_port, tags, actions);

    /*
     * We send out only a single packet, instead of setting up a flow, if the
     * packet is an ARP directed to broadcast that arrived on a bonded
     * interface.  In such a situation ARP requests and replies must be handled
     * differently, but OpenFlow unfortunately can't distinguish them.
     */
    return (in_port->n_ifaces < 2
            || flow->dl_type != htons(ETH_TYPE_ARP)
            || !eth_addr_is_broadcast(flow->dl_dst));
}

/* Careful: 'opp' is in host byte order and opp->port_no is an OFP port
 * number. */
static void
bridge_port_changed_ofhook_cb(enum ofp_port_reason reason,
                              const struct ofp_phy_port *opp,
                              void *br_)
{
    struct bridge *br = br_;
    struct iface *iface;
    struct port *port;

    iface = iface_from_dp_ifidx(br, ofp_port_to_odp_port(opp->port_no));
    if (!iface) {
        return;
    }
    port = iface->port;

    if (reason == OFPPR_DELETE) {
        VLOG_WARN("bridge %s: interface %s deleted unexpectedly",
                  br->name, iface->name);
        iface_destroy(iface);
        if (!port->n_ifaces) {
            VLOG_WARN("bridge %s: port %s has no interfaces, dropping",
                      br->name, port->name);
            port_destroy(port);
        }

        bridge_flush(br);
    } else {
        memcpy(iface->mac, opp->hw_addr, ETH_ADDR_LEN);
        if (port->n_ifaces > 1) {
            bool up = !(opp->state & OFPPS_LINK_DOWN);
            bond_link_status_update(iface, up);
            port_update_bond_compat(port);
        }
    }
}

static bool
bridge_normal_ofhook_cb(const flow_t *flow, const struct ofpbuf *packet,
                        struct odp_actions *actions, tag_type *tags, void *br_)
{
    struct bridge *br = br_;

#if 0
    if (flow->dl_type == htons(OFP_DL_TYPE_NOT_ETH_TYPE)
        && eth_addr_equals(flow->dl_dst, stp_eth_addr)) {
        brstp_receive(br, flow, payload);
        return true;
    }
#endif

    COVERAGE_INC(bridge_process_flow);
    return process_flow(br, flow, packet, actions, tags);
}

static void
bridge_account_flow_ofhook_cb(const flow_t *flow,
                              const union odp_action *actions,
                              size_t n_actions, unsigned long long int n_bytes,
                              void *br_)
{
    struct bridge *br = br_;
    const union odp_action *a;

    if (!br->has_bonded_ports) {
        return;
    }

    for (a = actions; a < &actions[n_actions]; a++) {
        if (a->type == ODPAT_OUTPUT) {
            struct port *port = port_from_dp_ifidx(br, a->output.port);
            if (port && port->n_ifaces >= 2) {
                struct bond_entry *e = lookup_bond_entry(port, flow->dl_src);
                e->tx_bytes += n_bytes;
            }
        }
    }
}

static void
bridge_account_checkpoint_ofhook_cb(void *br_)
{
    struct bridge *br = br_;
    size_t i;

    if (!br->has_bonded_ports) {
        return;
    }

    /* The current ofproto implementation calls this callback at least once a
     * second, so this timer implementation is sufficient. */
    if (time_msec() < br->bond_next_rebalance) {
        return;
    }
    br->bond_next_rebalance = time_msec() + 10000;

    for (i = 0; i < br->n_ports; i++) {
        struct port *port = br->ports[i];
        if (port->n_ifaces > 1) {
            bond_rebalance_port(port);
        }
    }
}

static struct ofhooks bridge_ofhooks = {
    bridge_port_changed_ofhook_cb,
    bridge_normal_ofhook_cb,
    bridge_account_flow_ofhook_cb,
    bridge_account_checkpoint_ofhook_cb,
};

/* Bonding functions. */

/* Statistics for a single interface on a bonded port, used for load-based
 * bond rebalancing.  */
struct slave_balance {
    struct iface *iface;        /* The interface. */
    uint64_t tx_bytes;          /* Sum of hashes[*]->tx_bytes. */

    /* All the "bond_entry"s that are assigned to this interface, in order of
     * increasing tx_bytes. */
    struct bond_entry **hashes;
    size_t n_hashes;
};

/* Sorts pointers to pointers to bond_entries in ascending order by the
 * interface to which they are assigned, and within a single interface in
 * ascending order of bytes transmitted. */
static int
compare_bond_entries(const void *a_, const void *b_)
{
    const struct bond_entry *const *ap = a_;
    const struct bond_entry *const *bp = b_;
    const struct bond_entry *a = *ap;
    const struct bond_entry *b = *bp;
    if (a->iface_idx != b->iface_idx) {
        return a->iface_idx > b->iface_idx ? 1 : -1;
    } else if (a->tx_bytes != b->tx_bytes) {
        return a->tx_bytes > b->tx_bytes ? 1 : -1;
    } else {
        return 0;
    }
}

/* Sorts slave_balances so that enabled ports come first, and otherwise in
 * *descending* order by number of bytes transmitted. */
static int
compare_slave_balance(const void *a_, const void *b_)
{
    const struct slave_balance *a = a_;
    const struct slave_balance *b = b_;
    if (a->iface->enabled != b->iface->enabled) {
        return a->iface->enabled ? -1 : 1;
    } else if (a->tx_bytes != b->tx_bytes) {
        return a->tx_bytes > b->tx_bytes ? -1 : 1;
    } else {
        return 0;
    }
}

static void
swap_bals(struct slave_balance *a, struct slave_balance *b)
{
    struct slave_balance tmp = *a;
    *a = *b;
    *b = tmp;
}

/* Restores the 'n_bals' slave_balance structures in 'bals' to sorted order
 * given that 'p' (and only 'p') might be in the wrong location.
 *
 * This function invalidates 'p', since it might now be in a different memory
 * location. */
static void
resort_bals(struct slave_balance *p,
            struct slave_balance bals[], size_t n_bals)
{
    if (n_bals > 1) {
        for (; p > bals && p->tx_bytes > p[-1].tx_bytes; p--) {
            swap_bals(p, p - 1);
        }
        for (; p < &bals[n_bals - 1] && p->tx_bytes < p[1].tx_bytes; p++) {
            swap_bals(p, p + 1);
        }
    }
}

static void
log_bals(const struct slave_balance *bals, size_t n_bals, struct port *port)
{
    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        const struct slave_balance *b;

        for (b = bals; b < bals + n_bals; b++) {
            size_t i;

            if (b > bals) {
                ds_put_char(&ds, ',');
            }
            ds_put_format(&ds, " %s %"PRIu64"kB",
                          b->iface->name, b->tx_bytes / 1024);

            if (!b->iface->enabled) {
                ds_put_cstr(&ds, " (disabled)");
            }
            if (b->n_hashes > 0) {
                ds_put_cstr(&ds, " (");
                for (i = 0; i < b->n_hashes; i++) {
                    const struct bond_entry *e = b->hashes[i];
                    if (i > 0) {
                        ds_put_cstr(&ds, " + ");
                    }
                    ds_put_format(&ds, "h%td: %"PRIu64"kB",
                                  e - port->bond_hash, e->tx_bytes / 1024);
                }
                ds_put_cstr(&ds, ")");
            }
        }
        VLOG_DBG("bond %s:%s", port->name, ds_cstr(&ds));
        ds_destroy(&ds);
    }
}

/* Shifts 'hash' from 'from' to 'to' within 'port'. */
static void
bond_shift_load(struct slave_balance *from, struct slave_balance *to,
                struct bond_entry *hash)
{
    struct port *port = from->iface->port;
    uint64_t delta = hash->tx_bytes;

    VLOG_INFO("bond %s: shift %"PRIu64"kB of load (with hash %td) "
              "from %s to %s (now carrying %"PRIu64"kB and "
              "%"PRIu64"kB load, respectively)",
              port->name, delta / 1024, hash - port->bond_hash,
              from->iface->name, to->iface->name,
              (from->tx_bytes - delta) / 1024,
              (to->tx_bytes + delta) / 1024);

    /* Delete element from from->hashes.
     *
     * We don't bother to add the element to to->hashes because not only would
     * it require more work, the only purpose it would be to allow that hash to
     * be migrated to another slave in this rebalancing run, and there is no
     * point in doing that.  */
    if (from->hashes[0] == hash) {
        from->hashes++;
    } else {
        int i = hash - from->hashes[0];
        memmove(from->hashes + i, from->hashes + i + 1,
                (from->n_hashes - (i + 1)) * sizeof *from->hashes);
    }
    from->n_hashes--;

    /* Shift load away from 'from' to 'to'. */
    from->tx_bytes -= delta;
    to->tx_bytes += delta;

    /* Arrange for flows to be revalidated. */
    ofproto_revalidate(port->bridge->ofproto, hash->iface_tag);
    hash->iface_idx = to->iface->port_ifidx;
    hash->iface_tag = tag_create_random();
}

static void
bond_rebalance_port(struct port *port)
{
    struct slave_balance bals[DP_MAX_PORTS];
    size_t n_bals;
    struct bond_entry *hashes[BOND_MASK + 1];
    struct slave_balance *b, *from, *to;
    struct bond_entry *e;
    size_t i;

    /* Sets up 'bals' to describe each of the port's interfaces, sorted in
     * descending order of tx_bytes, so that bals[0] represents the most
     * heavily loaded slave and bals[n_bals - 1] represents the least heavily
     * loaded slave.
     *
     * The code is a bit tricky: to avoid dynamically allocating a 'hashes'
     * array for each slave_balance structure, we sort our local array of
     * hashes in order by slave, so that all of the hashes for a given slave
     * become contiguous in memory, and then we point each 'hashes' members of
     * a slave_balance structure to the start of a contiguous group. */
    n_bals = port->n_ifaces;
    for (b = bals; b < &bals[n_bals]; b++) {
        b->iface = port->ifaces[b - bals];
        b->tx_bytes = 0;
        b->hashes = NULL;
        b->n_hashes = 0;
    }
    for (i = 0; i <= BOND_MASK; i++) {
        hashes[i] = &port->bond_hash[i];
    }
    qsort(hashes, BOND_MASK + 1, sizeof *hashes, compare_bond_entries);
    for (i = 0; i <= BOND_MASK; i++) {
        e = hashes[i];
        if (e->iface_idx >= 0 && e->iface_idx < port->n_ifaces) {
            b = &bals[e->iface_idx];
            b->tx_bytes += e->tx_bytes;
            if (!b->hashes) {
                b->hashes = &hashes[i];
            }
            b->n_hashes++;
        }
    }
    qsort(bals, n_bals, sizeof *bals, compare_slave_balance);
    log_bals(bals, n_bals, port);

    /* Discard slaves that aren't enabled (which were sorted to the back of the
     * array earlier). */
    while (!bals[n_bals - 1].iface->enabled) {
        n_bals--;
        if (!n_bals) {
            return;
        }
    }

    /* Shift load from the most-loaded slaves to the least-loaded slaves. */
    to = &bals[n_bals - 1];
    for (from = bals; from < to; ) {
        uint64_t overload = from->tx_bytes - to->tx_bytes;
        if (overload < to->tx_bytes >> 5 || overload < 100000) {
            /* The extra load on 'from' (and all less-loaded slaves), compared
             * to that of 'to' (the least-loaded slave), is less than ~3%, or
             * it is less than ~1Mbps.  No point in rebalancing. */
            break;
        } else if (from->n_hashes == 1) {
            /* 'from' only carries a single MAC hash, so we can't shift any
             * load away from it, even though we want to. */
            from++;
        } else {
            /* 'from' is carrying significantly more load than 'to', and that
             * load is split across at least two different hashes.  Pick a hash
             * to migrate to 'to' (the least-loaded slave), given that doing so
             * must not cause 'to''s load to exceed 'from''s load.
             *
             * The sort order we use means that we prefer to shift away the
             * smallest hashes instead of the biggest ones.  There is little
             * reason behind this decision; we could use the opposite sort
             * order to shift away big hashes ahead of small ones. */
            size_t i;

            for (i = 0; i < from->n_hashes; i++) {
                uint64_t delta = from->hashes[i]->tx_bytes;
                if (to->tx_bytes + delta < from->tx_bytes - delta) {
                    break;
                }
            }
            if (i < from->n_hashes) {
                bond_shift_load(from, to, from->hashes[i]);

                /* Re-sort 'bals'.  Note that this may make 'from' and 'to'
                 * point to different slave_balance structures.  It is only
                 * valid to do these two operations in a row at all because we
                 * know that 'from' will not move past 'to' and vice versa. */
                resort_bals(from, bals, n_bals);
                resort_bals(to, bals, n_bals);
            } else {
                from++;
            }
        }
    }

    /* Implement exponentially weighted moving average.  A weight of 1/2 causes
     * historical data to decay to <1% in 7 rebalancing runs.  */
    for (e = &port->bond_hash[0]; e <= &port->bond_hash[BOND_MASK]; e++) {
        e->tx_bytes /= 2;
    }
}

static void
bond_send_learning_packets(struct port *port)
{
    struct bridge *br = port->bridge;
    struct mac_entry *e;
    struct ofpbuf packet;
    int error, n_packets, n_errors;

    if (!port->n_ifaces || port->active_iface < 0 || !br->ml) {
        return;
    }

    ofpbuf_init(&packet, 128);
    error = n_packets = n_errors = 0;
    LIST_FOR_EACH (e, struct mac_entry, lru_node, &br->ml->lrus) {
        static const char s[] = "Open vSwitch Bond Failover";
        union ofp_action actions[2], *a;
        struct eth_header *eth;
        struct llc_snap_header *llc_snap;
        uint16_t dp_ifidx;
        tag_type tags = 0;
        flow_t flow;
        int retval;

        if (e->port == port->port_idx
            || !choose_output_iface(port, e->mac, &dp_ifidx, &tags)) {
            continue;
        }

        /* Compose packet to send. */
        ofpbuf_clear(&packet);
        eth = ofpbuf_put_zeros(&packet, ETH_HEADER_LEN);
        llc_snap = ofpbuf_put_zeros(&packet, LLC_SNAP_HEADER_LEN);
        ofpbuf_put(&packet, s, sizeof s); /* Includes null byte. */
        ofpbuf_put(&packet, e->mac, ETH_ADDR_LEN);

        memcpy(eth->eth_dst, eth_addr_broadcast, ETH_ADDR_LEN);
        memcpy(eth->eth_src, e->mac, ETH_ADDR_LEN);
        eth->eth_type = htons(packet.size - ETH_HEADER_LEN);

        llc_snap->llc.llc_dsap = LLC_DSAP_SNAP;
        llc_snap->llc.llc_ssap = LLC_SSAP_SNAP;
        llc_snap->llc.llc_cntl = LLC_CNTL_SNAP;
        memcpy(llc_snap->snap.snap_org, "\x00\x23\x20", 3);
        llc_snap->snap.snap_type = htons(0xf177); /* Random number. */

        /* Compose actions. */
        memset(actions, 0, sizeof actions);
        a = actions;
        if (e->vlan) {
            a->vlan_vid.type = htons(OFPAT_SET_VLAN_VID);
            a->vlan_vid.len = htons(sizeof *a);
            a->vlan_vid.vlan_vid = htons(e->vlan);
            a++;
        }
        a->output.type = htons(OFPAT_OUTPUT);
        a->output.len = htons(sizeof *a);
        a->output.port = htons(odp_port_to_ofp_port(dp_ifidx));
        a++;

        /* Send packet. */
        n_packets++;
        flow_extract(&packet, ODPP_NONE, &flow);
        retval = ofproto_send_packet(br->ofproto, &flow, actions, a - actions,
                                     &packet);
        if (retval) {
            error = retval;
            n_errors++;
        }
    }
    ofpbuf_uninit(&packet);

    if (n_errors) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bond %s: %d errors sending %d gratuitous learning "
                     "packets, last error was: %s",
                     port->name, n_errors, n_packets, strerror(error));
    } else {
        VLOG_DBG("bond %s: sent %d gratuitous learning packets",
                 port->name, n_packets);
    }
}

/* Bonding unixctl user interface functions. */

static void
bond_unixctl_list(struct unixctl_conn *conn, const char *args UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct bridge *br;

    ds_put_cstr(&ds, "bridge\tbond\tslaves\n");

    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        size_t i;

        for (i = 0; i < br->n_ports; i++) {
            const struct port *port = br->ports[i];
            if (port->n_ifaces > 1) {
                size_t j;

                ds_put_format(&ds, "%s\t%s\t", br->name, port->name);
                for (j = 0; j < port->n_ifaces; j++) {
                    const struct iface *iface = port->ifaces[j];
                    if (j) {
                        ds_put_cstr(&ds, ", ");
                    }
                    ds_put_cstr(&ds, iface->name);
                }
                ds_put_char(&ds, '\n');
            }
        }
    }
    unixctl_command_reply(conn, 200, ds_cstr(&ds));
    ds_destroy(&ds);
}

static struct port *
bond_find(const char *name)
{
    const struct bridge *br;

    LIST_FOR_EACH (br, struct bridge, node, &all_bridges) {
        size_t i;

        for (i = 0; i < br->n_ports; i++) {
            struct port *port = br->ports[i];
            if (!strcmp(port->name, name) && port->n_ifaces > 1) {
                return port;
            }
        }
    }
    return NULL;
}

static void
bond_unixctl_show(struct unixctl_conn *conn, const char *args)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct port *port;
    size_t j;

    port = bond_find(args);
    if (!port) {
        unixctl_command_reply(conn, 501, "no such bond");
        return;
    }

    ds_put_format(&ds, "updelay: %d ms\n", port->updelay);
    ds_put_format(&ds, "downdelay: %d ms\n", port->downdelay);
    ds_put_format(&ds, "next rebalance: %lld ms\n",
                  port->bridge->bond_next_rebalance - time_msec());
    for (j = 0; j < port->n_ifaces; j++) {
        const struct iface *iface = port->ifaces[j];
        struct bond_entry *be;

        /* Basic info. */
        ds_put_format(&ds, "slave %s: %s\n",
                      iface->name, iface->enabled ? "enabled" : "disabled");
        if (j == port->active_iface) {
            ds_put_cstr(&ds, "\tactive slave\n");
        }
        if (iface->delay_expires != LLONG_MAX) {
            ds_put_format(&ds, "\t%s expires in %lld ms\n",
                          iface->enabled ? "downdelay" : "updelay",
                          iface->delay_expires - time_msec());
        }

        /* Hashes. */
        for (be = port->bond_hash; be <= &port->bond_hash[BOND_MASK]; be++) {
            int hash = be - port->bond_hash;
            struct mac_entry *me;

            if (be->iface_idx != j) {
                continue;
            }

            ds_put_format(&ds, "\thash %d: %lld kB load\n",
                          hash, be->tx_bytes / 1024);

            /* MACs. */
            if (!port->bridge->ml) {
                break;
            }

            LIST_FOR_EACH (me, struct mac_entry, lru_node,
                           &port->bridge->ml->lrus) {
                uint16_t dp_ifidx;
                tag_type tags = 0;
                if (bond_hash(me->mac) == hash
                    && me->port != port->port_idx
                    && choose_output_iface(port, me->mac, &dp_ifidx, &tags)
                    && dp_ifidx == iface->dp_ifidx)
                {
                    ds_put_format(&ds, "\t\t"ETH_ADDR_FMT"\n",
                                  ETH_ADDR_ARGS(me->mac));
                }
            }
        }
    }
    unixctl_command_reply(conn, 200, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
bond_unixctl_migrate(struct unixctl_conn *conn, const char *args_)
{
    char *args = (char *) args_;
    char *save_ptr = NULL;
    char *bond_s, *hash_s, *slave_s;
    uint8_t mac[ETH_ADDR_LEN];
    struct port *port;
    struct iface *iface;
    struct bond_entry *entry;
    int hash;

    bond_s = strtok_r(args, " ", &save_ptr);
    hash_s = strtok_r(NULL, " ", &save_ptr);
    slave_s = strtok_r(NULL, " ", &save_ptr);
    if (!slave_s) {
        unixctl_command_reply(conn, 501,
                              "usage: bond/migrate BOND HASH SLAVE");
        return;
    }

    port = bond_find(bond_s);
    if (!port) {
        unixctl_command_reply(conn, 501, "no such bond");
        return;
    }

    if (sscanf(hash_s, "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
        hash = bond_hash(mac);
    } else if (strspn(hash_s, "0123456789") == strlen(hash_s)) {
        hash = atoi(hash_s) & BOND_MASK;
    } else {
        unixctl_command_reply(conn, 501, "bad hash");
        return;
    }

    iface = port_lookup_iface(port, slave_s);
    if (!iface) {
        unixctl_command_reply(conn, 501, "no such slave");
        return;
    }

    if (!iface->enabled) {
        unixctl_command_reply(conn, 501, "cannot migrate to disabled slave");
        return;
    }

    entry = &port->bond_hash[hash];
    ofproto_revalidate(port->bridge->ofproto, entry->iface_tag);
    entry->iface_idx = iface->port_ifidx;
    entry->iface_tag = tag_create_random();
    unixctl_command_reply(conn, 200, "migrated");
}

static void
bond_unixctl_set_active_slave(struct unixctl_conn *conn, const char *args_)
{
    char *args = (char *) args_;
    char *save_ptr = NULL;
    char *bond_s, *slave_s;
    struct port *port;
    struct iface *iface;

    bond_s = strtok_r(args, " ", &save_ptr);
    slave_s = strtok_r(NULL, " ", &save_ptr);
    if (!slave_s) {
        unixctl_command_reply(conn, 501,
                              "usage: bond/set-active-slave BOND SLAVE");
        return;
    }

    port = bond_find(bond_s);
    if (!port) {
        unixctl_command_reply(conn, 501, "no such bond");
        return;
    }

    iface = port_lookup_iface(port, slave_s);
    if (!iface) {
        unixctl_command_reply(conn, 501, "no such slave");
        return;
    }

    if (!iface->enabled) {
        unixctl_command_reply(conn, 501, "cannot make disabled slave active");
        return;
    }

    if (port->active_iface != iface->port_ifidx) {
        ofproto_revalidate(port->bridge->ofproto, port->active_iface_tag);
        port->active_iface = iface->port_ifidx;
        port->active_iface_tag = tag_create_random();
        VLOG_INFO("port %s: active interface is now %s",
                  port->name, iface->name);
        bond_send_learning_packets(port);
        unixctl_command_reply(conn, 200, "done");
    } else {
        unixctl_command_reply(conn, 200, "no change");
    }
}

static void
enable_slave(struct unixctl_conn *conn, const char *args_, bool enable)
{
    char *args = (char *) args_;
    char *save_ptr = NULL;
    char *bond_s, *slave_s;
    struct port *port;
    struct iface *iface;

    bond_s = strtok_r(args, " ", &save_ptr);
    slave_s = strtok_r(NULL, " ", &save_ptr);
    if (!slave_s) {
        unixctl_command_reply(conn, 501,
                              "usage: bond/enable/disable-slave BOND SLAVE");
        return;
    }

    port = bond_find(bond_s);
    if (!port) {
        unixctl_command_reply(conn, 501, "no such bond");
        return;
    }

    iface = port_lookup_iface(port, slave_s);
    if (!iface) {
        unixctl_command_reply(conn, 501, "no such slave");
        return;
    }

    bond_enable_slave(iface, enable);
    unixctl_command_reply(conn, 501, enable ? "enabled" : "disabled");
}

static void
bond_unixctl_enable_slave(struct unixctl_conn *conn, const char *args)
{
    enable_slave(conn, args, true);
}

static void
bond_unixctl_disable_slave(struct unixctl_conn *conn, const char *args)
{
    enable_slave(conn, args, false);
}

static void
bond_init(void)
{
    unixctl_command_register("bond/list", bond_unixctl_list);
    unixctl_command_register("bond/show", bond_unixctl_show);
    unixctl_command_register("bond/migrate", bond_unixctl_migrate);
    unixctl_command_register("bond/set-active-slave",
                             bond_unixctl_set_active_slave);
    unixctl_command_register("bond/enable-slave", bond_unixctl_enable_slave);
    unixctl_command_register("bond/disable-slave", bond_unixctl_disable_slave);
}

/* Port functions. */

static void
port_create(struct bridge *br, const char *name)
{
    struct port *port;

    port = xcalloc(1, sizeof *port);
    port->bridge = br;
    port->port_idx = br->n_ports;
    port->vlan = -1;
    port->trunks = NULL;
    port->name = xstrdup(name);
    port->active_iface = -1;
    port->stp_state = STP_DISABLED;
    port->stp_state_tag = 0;

    if (br->n_ports >= br->allocated_ports) {
        br->ports = x2nrealloc(br->ports, &br->allocated_ports,
                               sizeof *br->ports);
    }
    br->ports[br->n_ports++] = port;

    VLOG_INFO("created port %s on bridge %s", port->name, br->name);
    bridge_flush(br);
}

static void
port_reconfigure(struct port *port)
{
    bool bonded = cfg_has_section("bonding.%s", port->name);
    struct svec old_ifaces, new_ifaces;
    unsigned long *trunks;
    int vlan;
    size_t i;

    /* Collect old and new interfaces. */
    svec_init(&old_ifaces);
    svec_init(&new_ifaces);
    for (i = 0; i < port->n_ifaces; i++) {
        svec_add(&old_ifaces, port->ifaces[i]->name);
    }
    svec_sort(&old_ifaces);
    if (bonded) {
        cfg_get_all_keys(&new_ifaces, "bonding.%s.slave", port->name);
        if (!new_ifaces.n) {
            VLOG_ERR("port %s: no interfaces specified for bonded port",
                     port->name);
        } else if (new_ifaces.n == 1) {
            VLOG_WARN("port %s: only 1 interface specified for bonded port",
                      port->name);
        }

        port->updelay = cfg_get_int(0, "bonding.%s.updelay", port->name);
        if (port->updelay < 0) {
            port->updelay = 0;
        }
        port->downdelay = cfg_get_int(0, "bonding.%s.downdelay", port->name);
        if (port->downdelay < 0) {
            port->downdelay = 0;
        }
    } else {
        svec_init(&new_ifaces);
        svec_add(&new_ifaces, port->name);
    }

    /* Get rid of deleted interfaces and add new interfaces. */
    for (i = 0; i < port->n_ifaces; i++) {
        struct iface *iface = port->ifaces[i];
        if (!svec_contains(&new_ifaces, iface->name)) {
            iface_destroy(iface);
        } else {
            i++;
        }
    }
    for (i = 0; i < new_ifaces.n; i++) {
        const char *name = new_ifaces.names[i];
        if (!svec_contains(&old_ifaces, name)) {
            iface_create(port, name);
        }
    }

    /* Get VLAN tag. */
    vlan = -1;
    if (cfg_has("vlan.%s.tag", port->name)) {
        if (!bonded) {
            vlan = cfg_get_vlan(0, "vlan.%s.tag", port->name);
            if (vlan >= 0 && vlan <= 4095) {
                VLOG_DBG("port %s: assigning VLAN tag %d", port->name, vlan);
            }
        } else {
            /* It's possible that bonded, VLAN-tagged ports make sense.  Maybe
             * they even work as-is.  But they have not been tested. */
            VLOG_WARN("port %s: VLAN tags not supported on bonded ports",
                      port->name);
        }
    }
    if (port->vlan != vlan) {
        port->vlan = vlan;
        bridge_flush(port->bridge);
    }

    /* Get trunked VLANs. */
    trunks = NULL;
    if (vlan < 0) {
        size_t n_trunks, n_errors;
        size_t i;

        trunks = bitmap_allocate(4096);
        n_trunks = cfg_count("vlan.%s.trunks", port->name);
        n_errors = 0;
        for (i = 0; i < n_trunks; i++) {
            int trunk = cfg_get_vlan(i, "vlan.%s.trunks", port->name);
            if (trunk >= 0) {
                bitmap_set1(trunks, trunk);
            } else {
                n_errors++;
            }
        }
        if (n_errors) {
            VLOG_ERR("port %s: invalid values for %zu trunk VLANs",
                     port->name, n_trunks);
        }
        if (n_errors == n_trunks) {
            if (n_errors) {
                VLOG_ERR("port %s: no valid trunks, trunking all VLANs",
                         port->name);
            }
            bitmap_set_multiple(trunks, 0, 4096, 1);
        }
    } else {
        if (cfg_has("vlan.%s.trunks", port->name)) {
            VLOG_ERR("ignoring vlan.%s.trunks in favor of vlan.%s.vlan",
                     port->name, port->name);
        }
    }
    if (trunks == NULL
        ? port->trunks != NULL
        : port->trunks == NULL || !bitmap_equal(trunks, port->trunks, 4096)) {
        bridge_flush(port->bridge);
    }
    bitmap_free(port->trunks);
    port->trunks = trunks;

    svec_destroy(&old_ifaces);
    svec_destroy(&new_ifaces);
}

static void
port_destroy(struct port *port)
{
    if (port) {
        struct bridge *br = port->bridge;
        struct port *del;
        size_t i;

        proc_net_compat_update_vlan(port->name, NULL, 0);

        for (i = 0; i < MAX_MIRRORS; i++) {
            struct mirror *m = br->mirrors[i];
            if (m && m->out_port == port) {
                mirror_destroy(m);
            }
        }

        while (port->n_ifaces > 0) {
            iface_destroy(port->ifaces[port->n_ifaces - 1]);
        }

        del = br->ports[port->port_idx] = br->ports[--br->n_ports];
        del->port_idx = port->port_idx;

        free(port->ifaces);
        bitmap_free(port->trunks);
        free(port->name);
        free(port);
        bridge_flush(br);
    }
}

static struct port *
port_from_dp_ifidx(const struct bridge *br, uint16_t dp_ifidx)
{
    struct iface *iface = iface_from_dp_ifidx(br, dp_ifidx);
    return iface ? iface->port : NULL;
}

static struct port *
port_lookup(const struct bridge *br, const char *name)
{
    size_t i;

    for (i = 0; i < br->n_ports; i++) {
        struct port *port = br->ports[i];
        if (!strcmp(port->name, name)) {
            return port;
        }
    }
    return NULL;
}

static struct iface *
port_lookup_iface(const struct port *port, const char *name)
{
    size_t j;

    for (j = 0; j < port->n_ifaces; j++) {
        struct iface *iface = port->ifaces[j];
        if (!strcmp(iface->name, name)) {
            return iface;
        }
    }
    return NULL;
}

static void
port_update_bonding(struct port *port)
{
    if (port->n_ifaces < 2) {
        /* Not a bonded port. */
        if (port->bond_hash) {
            free(port->bond_hash);
            port->bond_hash = NULL;
            proc_net_compat_update_bond(port->name, NULL);
        }
    } else {
        if (!port->bond_hash) {
            size_t i;

            port->bond_hash = xcalloc(BOND_MASK + 1, sizeof *port->bond_hash);
            for (i = 0; i <= BOND_MASK; i++) {
                struct bond_entry *e = &port->bond_hash[i];
                e->iface_idx = -1;
                e->tx_bytes = 0;
            }
            port->no_ifaces_tag = tag_create_random();
            bond_choose_active_iface(port);
        }
        port_update_bond_compat(port);
    }
}

static void
port_update_bond_compat(struct port *port)
{
    struct compat_bond bond;
    size_t i;

    if (port->n_ifaces < 2) {
        return;
    }

    bond.up = false;
    bond.updelay = port->updelay;
    bond.downdelay = port->downdelay;
    bond.n_slaves = port->n_ifaces;
    bond.slaves = xmalloc(port->n_ifaces * sizeof *bond.slaves);
    for (i = 0; i < port->n_ifaces; i++) {
        struct iface *iface = port->ifaces[i];
        struct compat_bond_slave *slave = &bond.slaves[i];
        slave->name = iface->name;
        slave->up = ((iface->enabled && iface->delay_expires == LLONG_MAX) ||
                     (!iface->enabled && iface->delay_expires != LLONG_MAX));
        if (slave->up) {
            bond.up = true;
        }
        memcpy(slave->mac, iface->mac, ETH_ADDR_LEN);
    }
    proc_net_compat_update_bond(port->name, &bond);
    free(bond.slaves);
}

static void
port_update_vlan_compat(struct port *port)
{
    struct bridge *br = port->bridge;
    char *vlandev_name = NULL;

    if (port->vlan > 0) {
        /* Figure out the name that the VLAN device should actually have, if it
         * existed.  This takes some work because the VLAN device would not
         * have port->name in its name; rather, it would have the trunk port's
         * name, and 'port' would be attached to a bridge that also had the
         * VLAN device one of its ports.  So we need to find a trunk port that
         * includes port->vlan.
         *
         * There might be more than one candidate.  This doesn't happen on
         * XenServer, so if it happens we just pick the first choice in
         * alphabetical order instead of creating multiple VLAN devices. */
        size_t i;
        for (i = 0; i < br->n_ports; i++) {
            struct port *p = br->ports[i];
            if (port_trunks_vlan(p, port->vlan)
                && p->n_ifaces
                && (!vlandev_name || strcmp(p->name, vlandev_name) <= 0))
            {
                const uint8_t *ea = p->ifaces[0]->mac;
                if (!eth_addr_is_multicast(ea) &&
                    !eth_addr_is_reserved(ea) &&
                    !eth_addr_is_zero(ea)) {
                    vlandev_name = p->name;
                }
            }
        }
    }
    proc_net_compat_update_vlan(port->name, vlandev_name, port->vlan);
}

/* Interface functions. */

static void
iface_create(struct port *port, const char *name)
{
    struct iface *iface;

    iface = xcalloc(1, sizeof *iface);
    iface->port = port;
    iface->port_ifidx = port->n_ifaces;
    iface->name = xstrdup(name);
    iface->dp_ifidx = -1;
    iface->tag = tag_create_random();
    iface->delay_expires = LLONG_MAX;

    netdev_nodev_get_etheraddr(name, iface->mac);
    netdev_nodev_get_carrier(name, &iface->enabled);

    if (port->n_ifaces >= port->allocated_ifaces) {
        port->ifaces = x2nrealloc(port->ifaces, &port->allocated_ifaces,
                                  sizeof *port->ifaces);
    }
    port->ifaces[port->n_ifaces++] = iface;
    if (port->n_ifaces > 1) {
        port->bridge->has_bonded_ports = true;
    }

    VLOG_DBG("attached network device %s to port %s", iface->name, port->name);

    port_update_bonding(port);
    bridge_flush(port->bridge);
}

static void
iface_destroy(struct iface *iface)
{
    if (iface) {
        struct port *port = iface->port;
        struct bridge *br = port->bridge;
        bool del_active = port->active_iface == iface->port_ifidx;
        struct iface *del;

        if (iface->dp_ifidx >= 0) {
            port_array_set(&br->ifaces, iface->dp_ifidx, NULL);
        }

        del = port->ifaces[iface->port_ifidx] = port->ifaces[--port->n_ifaces];
        del->port_ifidx = iface->port_ifidx;

        free(iface->name);
        free(iface);

        if (del_active) {
            ofproto_revalidate(port->bridge->ofproto, port->active_iface_tag);
            bond_choose_active_iface(port);
            bond_send_learning_packets(port);
        }

        port_update_bonding(port);
        bridge_flush(port->bridge);
    }
}

static struct iface *
iface_lookup(const struct bridge *br, const char *name)
{
    size_t i, j;

    for (i = 0; i < br->n_ports; i++) {
        struct port *port = br->ports[i];
        for (j = 0; j < port->n_ifaces; j++) {
            struct iface *iface = port->ifaces[j];
            if (!strcmp(iface->name, name)) {
                return iface;
            }
        }
    }
    return NULL;
}

static struct iface *
iface_from_dp_ifidx(const struct bridge *br, uint16_t dp_ifidx)
{
    return port_array_get(&br->ifaces, dp_ifidx);
}

/* Port mirroring. */

static void
mirror_reconfigure(struct bridge *br)
{
    struct svec old_mirrors, new_mirrors;
    size_t i;

    /* Collect old and new mirrors. */
    svec_init(&old_mirrors);
    svec_init(&new_mirrors);
    cfg_get_subsections(&new_mirrors, "mirror.%s", br->name);
    for (i = 0; i < MAX_MIRRORS; i++) {
        if (br->mirrors[i]) {
            svec_add(&old_mirrors, br->mirrors[i]->name);
        }
    }

    /* Get rid of deleted mirrors and add new mirrors. */
    svec_sort(&old_mirrors);
    assert(svec_is_unique(&old_mirrors));
    svec_sort(&new_mirrors);
    assert(svec_is_unique(&new_mirrors));
    for (i = 0; i < MAX_MIRRORS; i++) {
        struct mirror *m = br->mirrors[i];
        if (m && !svec_contains(&new_mirrors, m->name)) {
            mirror_destroy(m);
        }
    }
    for (i = 0; i < new_mirrors.n; i++) {
        const char *name = new_mirrors.names[i];
        if (!svec_contains(&old_mirrors, name)) {
            mirror_create(br, name);
        }
    }
    svec_destroy(&old_mirrors);
    svec_destroy(&new_mirrors);

    /* Reconfigure all mirrors. */
    for (i = 0; i < MAX_MIRRORS; i++) {
        if (br->mirrors[i]) {
            mirror_reconfigure_one(br->mirrors[i]);
        }
    }

    /* Update port reserved status. */
    for (i = 0; i < br->n_ports; i++) {
        br->ports[i]->is_mirror_output_port = false;
    }
    for (i = 0; i < MAX_MIRRORS; i++) {
        struct mirror *m = br->mirrors[i];
        if (m && m->out_port) {
            m->out_port->is_mirror_output_port = true;
        }
    }
}

static void
mirror_create(struct bridge *br, const char *name)
{
    struct mirror *m;
    size_t i;

    for (i = 0; ; i++) {
        if (i >= MAX_MIRRORS) {
            VLOG_WARN("bridge %s: maximum of %d port mirrors reached, "
                      "cannot create %s", br->name, MAX_MIRRORS, name);
            return;
        }
        if (!br->mirrors[i]) {
            break;
        }
    }

    VLOG_INFO("created port mirror %s on bridge %s", name, br->name);
    bridge_flush(br);

    br->mirrors[i] = m = xcalloc(1, sizeof *m);
    m->bridge = br;
    m->idx = i;
    m->name = xstrdup(name);
    svec_init(&m->src_ports);
    svec_init(&m->dst_ports);
    m->vlans = NULL;
    m->n_vlans = 0;
    m->out_vlan = -1;
    m->out_port = NULL;
}

static void
mirror_destroy(struct mirror *m)
{
    if (m) {
        struct bridge *br = m->bridge;
        size_t i;

        for (i = 0; i < br->n_ports; i++) {
            br->ports[i]->src_mirrors &= ~(MIRROR_MASK_C(1) << m->idx);
            br->ports[i]->dst_mirrors &= ~(MIRROR_MASK_C(1) << m->idx);
        }

        svec_destroy(&m->src_ports);
        svec_destroy(&m->dst_ports);
        free(m->vlans);

        m->bridge->mirrors[m->idx] = NULL;
        free(m);

        bridge_flush(br);
    }
}

static void
prune_ports(struct mirror *m, struct svec *ports)
{
    struct svec tmp;
    size_t i;

    svec_sort_unique(ports);

    svec_init(&tmp);
    for (i = 0; i < ports->n; i++) {
        const char *name = ports->names[i];
        if (port_lookup(m->bridge, name)) {
            svec_add(&tmp, name);
        } else {
            VLOG_WARN("mirror.%s.%s: cannot match on nonexistent port %s",
                      m->bridge->name, m->name, name);
        }
    }
    svec_swap(ports, &tmp);
    svec_destroy(&tmp);
}

static size_t
prune_vlans(struct mirror *m, struct svec *vlan_strings, int **vlans)
{
    size_t n_vlans, i;

    /* This isn't perfect: it won't combine "0" and "00", and the textual sort
     * order won't give us numeric sort order.  But that's good enough for what
     * we need right now. */
    svec_sort_unique(vlan_strings);

    *vlans = xmalloc(sizeof *vlans * vlan_strings->n);
    n_vlans = 0;
    for (i = 0; i < vlan_strings->n; i++) {
        const char *name = vlan_strings->names[i];
        int vlan;
        if (!str_to_int(name, 10, &vlan) || vlan < 0 || vlan > 4095) {
            VLOG_WARN("mirror.%s.%s.select.vlan: ignoring invalid VLAN %s",
                      m->bridge->name, m->name, name);
        } else {
            (*vlans)[n_vlans++] = vlan;
        }
    }
    return n_vlans;
}

static bool
vlan_is_mirrored(const struct mirror *m, int vlan)
{
    size_t i;

    for (i = 0; i < m->n_vlans; i++) {
        if (m->vlans[i] == vlan) {
            return true;
        }
    }
    return false;
}

static bool
port_trunks_any_mirrored_vlan(const struct mirror *m, const struct port *p)
{
    size_t i;

    for (i = 0; i < m->n_vlans; i++) {
        if (port_trunks_vlan(p, m->vlans[i])) {
            return true;
        }
    }
    return false;
}

static void
mirror_reconfigure_one(struct mirror *m)
{
    char *pfx = xasprintf("mirror.%s.%s", m->bridge->name, m->name);
    struct svec src_ports, dst_ports, ports;
    struct svec vlan_strings;
    mirror_mask_t mirror_bit;
    const char *out_port_name;
    struct port *out_port;
    int out_vlan;
    size_t n_vlans;
    int *vlans;
    size_t i;
    bool mirror_all_ports;

    /* Get output port. */
    out_port_name = cfg_get_key(0, "mirror.%s.%s.output.port",
                                m->bridge->name, m->name);
    if (out_port_name) {
        out_port = port_lookup(m->bridge, out_port_name);
        if (!out_port) {
            VLOG_ERR("%s.output.port: bridge %s does not have a port "
                      "named %s", pfx, m->bridge->name, out_port_name);
            mirror_destroy(m);
            free(pfx);
            return;
        }
        out_vlan = -1;

        if (cfg_has("%s.output.vlan", pfx)) {
            VLOG_ERR("%s.output.port and %s.output.vlan both specified; "
                     "ignoring %s.output.vlan", pfx, pfx, pfx);
        }
    } else if (cfg_has("%s.output.vlan", pfx)) {
        out_port = NULL;
        out_vlan = cfg_get_vlan(0, "%s.output.vlan", pfx);
    } else {
        VLOG_ERR("%s: neither %s.output.port nor %s.output.vlan specified, "
                 "but exactly one is required; disabling port mirror %s",
                 pfx, pfx, pfx, pfx);
        mirror_destroy(m);
        free(pfx);
        return;
    }

    /* Get all the ports, and drop duplicates and ports that don't exist. */
    svec_init(&src_ports);
    svec_init(&dst_ports);
    svec_init(&ports);
    cfg_get_all_keys(&src_ports, "%s.select.src-port", pfx);
    cfg_get_all_keys(&dst_ports, "%s.select.dst-port", pfx);
    cfg_get_all_keys(&ports, "%s.select.port", pfx);
    svec_append(&src_ports, &ports);
    svec_append(&dst_ports, &ports);
    svec_destroy(&ports);
    prune_ports(m, &src_ports);
    prune_ports(m, &dst_ports);

    /* Get all the vlans, and drop duplicate and invalid vlans. */
    svec_init(&vlan_strings);
    cfg_get_all_keys(&vlan_strings, "%s.select.vlan", pfx);
    n_vlans = prune_vlans(m, &vlan_strings, &vlans);
    svec_destroy(&vlan_strings);

    /* Update mirror data. */
    if (!svec_equal(&m->src_ports, &src_ports)
        || !svec_equal(&m->dst_ports, &dst_ports)
        || m->n_vlans != n_vlans
        || memcmp(m->vlans, vlans, sizeof *vlans * n_vlans)
        || m->out_port != out_port
        || m->out_vlan != out_vlan) {
        bridge_flush(m->bridge);
    }
    svec_swap(&m->src_ports, &src_ports);
    svec_swap(&m->dst_ports, &dst_ports);
    free(m->vlans);
    m->vlans = vlans;
    m->n_vlans = n_vlans;
    m->out_port = out_port;
    m->out_vlan = out_vlan;

    /* If no selection criteria have been given, mirror for all ports. */
    mirror_all_ports = (!m->src_ports.n) && (!m->dst_ports.n) && (!m->n_vlans);

    /* Update ports. */
    mirror_bit = MIRROR_MASK_C(1) << m->idx;
    for (i = 0; i < m->bridge->n_ports; i++) {
        struct port *port = m->bridge->ports[i];

        if (mirror_all_ports
            || svec_contains(&m->src_ports, port->name)
            || (m->n_vlans
                && (!port->vlan
                    ? port_trunks_any_mirrored_vlan(m, port)
                    : vlan_is_mirrored(m, port->vlan)))) {
            port->src_mirrors |= mirror_bit;
        } else {
            port->src_mirrors &= ~mirror_bit;
        }

        if (mirror_all_ports || svec_contains(&m->dst_ports, port->name)) {
            port->dst_mirrors |= mirror_bit;
        } else {
            port->dst_mirrors &= ~mirror_bit;
        }
    }

    /* Clean up. */
    svec_destroy(&src_ports);
    svec_destroy(&dst_ports);
    free(pfx);
}

/* Spanning tree protocol. */

static void brstp_update_port_state(struct port *);

static void
brstp_send_bpdu(struct ofpbuf *pkt, int port_no, void *br_)
{
    struct bridge *br = br_;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    struct iface *iface = iface_from_dp_ifidx(br, port_no);
    if (!iface) {
        VLOG_WARN_RL(&rl, "%s: cannot send BPDU on unknown port %d",
                     br->name, port_no);
    } else if (eth_addr_is_zero(iface->mac)) {
        VLOG_WARN_RL(&rl, "%s: cannot send BPDU on port %d with unknown MAC",
                     br->name, port_no);
    } else {
        union ofp_action action;
        struct eth_header *eth = pkt->l2;
        flow_t flow;

        memcpy(eth->eth_src, iface->mac, ETH_ADDR_LEN);

        memset(&action, 0, sizeof action);
        action.type = htons(OFPAT_OUTPUT);
        action.output.len = htons(sizeof action);
        action.output.port = htons(port_no);

        flow_extract(pkt, ODPP_NONE, &flow);
        ofproto_send_packet(br->ofproto, &flow, &action, 1, pkt);
    }
    ofpbuf_delete(pkt);
}

static void
brstp_reconfigure(struct bridge *br)
{
    size_t i;

    if (!cfg_get_bool(0, "stp.%s.enabled", br->name)) {
        if (br->stp) {
            stp_destroy(br->stp);
            br->stp = NULL;

            bridge_flush(br);
        }
    } else {
        uint64_t bridge_address, bridge_id;
        int bridge_priority;

        bridge_address = cfg_get_mac(0, "stp.%s.address", br->name);
        if (!bridge_address) {
            if (br->stp) {
                bridge_address = (stp_get_bridge_id(br->stp)
                                  & ((UINT64_C(1) << 48) - 1));
            } else {
                uint8_t mac[ETH_ADDR_LEN];
                eth_addr_random(mac);
                bridge_address = eth_addr_to_uint64(mac);
            }
        }

        if (cfg_is_valid(CFG_INT | CFG_REQUIRED, "stp.%s.priority",
                         br->name)) {
            bridge_priority = cfg_get_int(0, "stp.%s.priority", br->name);
        } else {
            bridge_priority = STP_DEFAULT_BRIDGE_PRIORITY;
        }

        bridge_id = bridge_address | ((uint64_t) bridge_priority << 48);
        if (!br->stp) {
            br->stp = stp_create(br->name, bridge_id, brstp_send_bpdu, br);
            br->stp_last_tick = time_msec();
            bridge_flush(br);
        } else {
            if (bridge_id != stp_get_bridge_id(br->stp)) {
                stp_set_bridge_id(br->stp, bridge_id);
                bridge_flush(br);
            }
        }

        for (i = 0; i < br->n_ports; i++) {
            struct port *p = br->ports[i];
            int dp_ifidx;
            struct stp_port *sp;
            int path_cost, priority;
            bool enable;

            if (!p->n_ifaces) {
                continue;
            }
            dp_ifidx = p->ifaces[0]->dp_ifidx;
            if (dp_ifidx < 0 || dp_ifidx >= STP_MAX_PORTS) {
                continue;
            }

            sp = stp_get_port(br->stp, dp_ifidx);
            enable = (!cfg_is_valid(CFG_BOOL | CFG_REQUIRED,
                                    "stp.%s.port.%s.enabled",
                                    br->name, p->name)
                      || cfg_get_bool(0, "stp.%s.port.%s.enabled",
                                      br->name, p->name));
            if (p->is_mirror_output_port) {
                enable = false;
            }
            if (enable != (stp_port_get_state(sp) != STP_DISABLED)) {
                bridge_flush(br); /* Might not be necessary. */
                if (enable) {
                    stp_port_enable(sp);
                } else {
                    stp_port_disable(sp);
                }
            }

            path_cost = cfg_get_int(0, "stp.%s.port.%s.path-cost",
                                    br->name, p->name);
            stp_port_set_path_cost(sp, path_cost ? path_cost : 19 /* XXX */);

            priority = (cfg_is_valid(CFG_INT | CFG_REQUIRED,
                                     "stp.%s.port.%s.priority",
                                     br->name, p->name)
                        ? cfg_get_int(0, "stp.%s.port.%s.priority",
                                      br->name, p->name)
                        : STP_DEFAULT_PORT_PRIORITY);
            stp_port_set_priority(sp, priority);
        }

        brstp_adjust_timers(br);
    }
    for (i = 0; i < br->n_ports; i++) {
        brstp_update_port_state(br->ports[i]);
    }
}

static void
brstp_update_port_state(struct port *p)
{
    struct bridge *br = p->bridge;
    enum stp_state state;

    /* Figure out new state. */
    state = STP_DISABLED;
    if (br->stp && p->n_ifaces > 0) {
        int dp_ifidx = p->ifaces[0]->dp_ifidx;
        if (dp_ifidx >= 0 && dp_ifidx < STP_MAX_PORTS) {
            state = stp_port_get_state(stp_get_port(br->stp, dp_ifidx));
        }
    }

    /* Update state. */
    if (p->stp_state != state) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
        VLOG_INFO_RL(&rl, "port %s: STP state changed from %s to %s",
                     p->name, stp_state_name(p->stp_state),
                     stp_state_name(state));
        if (p->stp_state == STP_DISABLED) {
            bridge_flush(br);
        } else {
            ofproto_revalidate(p->bridge->ofproto, p->stp_state_tag);
        }
        p->stp_state = state;
        p->stp_state_tag = (p->stp_state == STP_DISABLED ? 0
                            : tag_create_random());
    }
}

static void
brstp_adjust_timers(struct bridge *br)
{
    int hello_time = cfg_get_int(0, "stp.%s.hello-time", br->name);
    int max_age = cfg_get_int(0, "stp.%s.max-age", br->name);
    int forward_delay = cfg_get_int(0, "stp.%s.forward-delay", br->name);

    stp_set_hello_time(br->stp, hello_time ? hello_time : 2000);
    stp_set_max_age(br->stp, max_age ? max_age : 20000);
    stp_set_forward_delay(br->stp, forward_delay ? forward_delay : 15000);
}

static void
brstp_run(struct bridge *br)
{
    if (br->stp) {
        long long int now = time_msec();
        long long int elapsed = now - br->stp_last_tick;
        struct stp_port *sp;

        if (elapsed > 0) {
            stp_tick(br->stp, MIN(INT_MAX, elapsed));
            br->stp_last_tick = now;
        }
        while (stp_get_changed_port(br->stp, &sp)) {
            struct port *p = port_from_dp_ifidx(br, stp_port_no(sp));
            if (p) {
                brstp_update_port_state(p);
            }
        }
    }
}

static void
brstp_wait(struct bridge *br)
{
    if (br->stp) {
        poll_timer_wait(1000);
    }
}
