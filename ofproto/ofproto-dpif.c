/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include "ofproto/ofproto-dpif.h"
#include "ofproto/ofproto-provider.h"

#include <errno.h>

#include "bfd.h"
#include "bond.h"
#include "bundle.h"
#include "byte-order.h"
#include "connectivity.h"
#include "connmgr.h"
#include "coverage.h"
#include "cfm.h"
#include "ovs-lldp.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "fail-open.h"
#include "guarded-list.h"
#include "hmapx.h"
#include "lacp.h"
#include "learn.h"
#include "mac-learning.h"
#include "mcast-snooping.h"
#include "meta-flow.h"
#include "multipath.h"
#include "netdev-vport.h"
#include "netdev.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-util.h"
#include "odp-execute.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofp-actions.h"
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofproto-dpif-ipfix.h"
#include "ofproto-dpif-mirror.h"
#include "ofproto-dpif-monitor.h"
#include "ofproto-dpif-rid.h"
#include "ofproto-dpif-sflow.h"
#include "ofproto-dpif-upcall.h"
#include "ofproto-dpif-xlate.h"
#include "poll-loop.h"
#include "ovs-rcu.h"
#include "ovs-router.h"
#include "seq.h"
#include "simap.h"
#include "smap.h"
#include "timer.h"
#include "tunnel.h"
#include "unaligned.h"
#include "unixctl.h"
#include "vlan-bitmap.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif);

COVERAGE_DEFINE(ofproto_dpif_expired);
COVERAGE_DEFINE(packet_in_overflow);

struct flow_miss;

struct rule_dpif {
    struct rule up;

    /* These statistics:
     *
     *   - Do include packets and bytes from datapath flows which have not
     *   recently been processed by a revalidator. */
    struct ovs_mutex stats_mutex;
    struct dpif_flow_stats stats OVS_GUARDED;

    /* If non-zero then the recirculation id that has
     * been allocated for use with this rule.
     * The recirculation id and associated internal flow should
     * be freed when the rule is freed */
    uint32_t recirc_id;
};

/* RULE_CAST() depends on this. */
BUILD_ASSERT_DECL(offsetof(struct rule_dpif, up) == 0);

static void rule_get_stats(struct rule *, uint64_t *packets, uint64_t *bytes,
                           long long int *used);
static struct rule_dpif *rule_dpif_cast(const struct rule *);
static void rule_expire(struct rule_dpif *);

struct group_dpif {
    struct ofgroup up;

    /* These statistics:
     *
     *   - Do include packets and bytes from datapath flows which have not
     *   recently been processed by a revalidator. */
    struct ovs_mutex stats_mutex;
    uint64_t packet_count OVS_GUARDED;  /* Number of packets received. */
    uint64_t byte_count OVS_GUARDED;    /* Number of bytes received. */
};

struct ofbundle {
    struct hmap_node hmap_node; /* In struct ofproto's "bundles" hmap. */
    struct ofproto_dpif *ofproto; /* Owning ofproto. */
    void *aux;                  /* Key supplied by ofproto's client. */
    char *name;                 /* Identifier for log messages. */

    /* Configuration. */
    struct ovs_list ports;      /* Contains "struct ofport"s. */
    enum port_vlan_mode vlan_mode; /* VLAN mode */
    int vlan;                   /* -1=trunk port, else a 12-bit VLAN ID. */
    unsigned long *trunks;      /* Bitmap of trunked VLANs, if 'vlan' == -1.
                                 * NULL if all VLANs are trunked. */
    struct lacp *lacp;          /* LACP if LACP is enabled, otherwise NULL. */
    struct bond *bond;          /* Nonnull iff more than one port. */
    bool use_priority_tags;     /* Use 802.1p tag for frames in VLAN 0? */

    /* Status. */
    bool floodable;          /* True if no port has OFPUTIL_PC_NO_FLOOD set. */
};

static void bundle_remove(struct ofport *);
static void bundle_update(struct ofbundle *);
static void bundle_destroy(struct ofbundle *);
static void bundle_del_port(struct ofport_dpif *);
static void bundle_run(struct ofbundle *);
static void bundle_wait(struct ofbundle *);
static void bundle_flush_macs(struct ofbundle *, bool);
static void bundle_move(struct ofbundle *, struct ofbundle *);

static void stp_run(struct ofproto_dpif *ofproto);
static void stp_wait(struct ofproto_dpif *ofproto);
static int set_stp_port(struct ofport *,
                        const struct ofproto_port_stp_settings *);

static void rstp_run(struct ofproto_dpif *ofproto);
static void set_rstp_port(struct ofport *,
                         const struct ofproto_port_rstp_settings *);

struct ofport_dpif {
    struct hmap_node odp_port_node; /* In dpif_backer's "odp_to_ofport_map". */
    struct ofport up;

    odp_port_t odp_port;
    struct ofbundle *bundle;    /* Bundle that contains this port, if any. */
    struct ovs_list bundle_node;/* In struct ofbundle's "ports" list. */
    struct cfm *cfm;            /* Connectivity Fault Management, if any. */
    struct bfd *bfd;            /* BFD, if any. */
    struct lldp *lldp;          /* lldp, if any. */
    bool may_enable;            /* May be enabled in bonds. */
    bool is_tunnel;             /* This port is a tunnel. */
    bool is_layer3;             /* This is a layer 3 port. */
    long long int carrier_seq;  /* Carrier status changes. */
    struct ofport_dpif *peer;   /* Peer if patch port. */

    /* Spanning tree. */
    struct stp_port *stp_port;  /* Spanning Tree Protocol, if any. */
    enum stp_state stp_state;   /* Always STP_DISABLED if STP not in use. */
    long long int stp_state_entered;

    /* Rapid Spanning Tree. */
    struct rstp_port *rstp_port; /* Rapid Spanning Tree Protocol, if any. */
    enum rstp_state rstp_state; /* Always RSTP_DISABLED if RSTP not in use. */

    /* Queue to DSCP mapping. */
    struct ofproto_port_queue *qdscp;
    size_t n_qdscp;

    /* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
     *
     * This is deprecated.  It is only for compatibility with broken device
     * drivers in old versions of Linux that do not properly support VLANs when
     * VLAN devices are not used.  When broken device drivers are no longer in
     * widespread use, we will delete these interfaces. */
    ofp_port_t realdev_ofp_port;
    int vlandev_vid;
};

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */
struct vlan_splinter {
    struct hmap_node realdev_vid_node;
    struct hmap_node vlandev_node;
    ofp_port_t realdev_ofp_port;
    ofp_port_t vlandev_ofp_port;
    int vid;
};

static void vsp_remove(struct ofport_dpif *);
static void vsp_add(struct ofport_dpif *, ofp_port_t realdev_ofp_port, int vid);

static odp_port_t ofp_port_to_odp_port(const struct ofproto_dpif *,
                                       ofp_port_t);

static ofp_port_t odp_port_to_ofp_port(const struct ofproto_dpif *,
                                       odp_port_t);

static struct ofport_dpif *
ofport_dpif_cast(const struct ofport *ofport)
{
    return ofport ? CONTAINER_OF(ofport, struct ofport_dpif, up) : NULL;
}

static void port_run(struct ofport_dpif *);
static int set_bfd(struct ofport *, const struct smap *);
static int set_cfm(struct ofport *, const struct cfm_settings *);
static int set_lldp(struct ofport *ofport_, const struct smap *cfg);
static void ofport_update_peer(struct ofport_dpif *);

/* Reasons that we might need to revalidate every datapath flow, and
 * corresponding coverage counters.
 *
 * A value of 0 means that there is no need to revalidate.
 *
 * It would be nice to have some cleaner way to integrate with coverage
 * counters, but with only a few reasons I guess this is good enough for
 * now. */
enum revalidate_reason {
    REV_RECONFIGURE = 1,       /* Switch configuration changed. */
    REV_STP,                   /* Spanning tree protocol port status change. */
    REV_RSTP,                  /* RSTP port status change. */
    REV_BOND,                  /* Bonding changed. */
    REV_PORT_TOGGLED,          /* Port enabled or disabled by CFM, LACP, ...*/
    REV_FLOW_TABLE,            /* Flow table changed. */
    REV_MAC_LEARNING,          /* Mac learning changed. */
    REV_MCAST_SNOOPING,        /* Multicast snooping changed. */
};
COVERAGE_DEFINE(rev_reconfigure);
COVERAGE_DEFINE(rev_stp);
COVERAGE_DEFINE(rev_rstp);
COVERAGE_DEFINE(rev_bond);
COVERAGE_DEFINE(rev_port_toggled);
COVERAGE_DEFINE(rev_flow_table);
COVERAGE_DEFINE(rev_mac_learning);
COVERAGE_DEFINE(rev_mcast_snooping);

/* All datapaths of a given type share a single dpif backer instance. */
struct dpif_backer {
    char *type;
    int refcount;
    struct dpif *dpif;
    struct udpif *udpif;

    struct ovs_rwlock odp_to_ofport_lock;
    struct hmap odp_to_ofport_map OVS_GUARDED; /* Contains "struct ofport"s. */

    struct simap tnl_backers;      /* Set of dpif ports backing tunnels. */

    enum revalidate_reason need_revalidate; /* Revalidate all flows. */

    bool recv_set_enable; /* Enables or disables receiving packets. */

    /* Version string of the datapath stored in OVSDB. */
    char *dp_version_string;

    /* Datapath feature support. */
    struct dpif_backer_support support;
    struct atomic_count tnl_count;
};

/* All existing ofproto_backer instances, indexed by ofproto->up.type. */
static struct shash all_dpif_backers = SHASH_INITIALIZER(&all_dpif_backers);

struct ofproto_dpif {
    struct hmap_node all_ofproto_dpifs_node; /* In 'all_ofproto_dpifs'. */
    struct ofproto up;
    struct dpif_backer *backer;

    uint64_t dump_seq; /* Last read of udpif_dump_seq(). */

    /* Special OpenFlow rules. */
    struct rule_dpif *miss_rule; /* Sends flow table misses to controller. */
    struct rule_dpif *no_packet_in_rule; /* Drops flow table misses. */
    struct rule_dpif *drop_frags_rule; /* Used in OFPC_FRAG_DROP mode. */

    /* Bridging. */
    struct netflow *netflow;
    struct dpif_sflow *sflow;
    struct dpif_ipfix *ipfix;
    struct hmap bundles;        /* Contains "struct ofbundle"s. */
    struct mac_learning *ml;
    struct mcast_snooping *ms;
    bool has_bonded_bundles;
    bool lacp_enabled;
    struct mbridge *mbridge;

    struct ovs_mutex stats_mutex;
    struct netdev_stats stats OVS_GUARDED; /* To account packets generated and
                                            * consumed in userspace. */

    /* Spanning tree. */
    struct stp *stp;
    long long int stp_last_tick;

    /* Rapid Spanning Tree. */
    struct rstp *rstp;
    long long int rstp_last_tick;

    /* VLAN splinters. */
    struct ovs_mutex vsp_mutex;
    struct hmap realdev_vid_map OVS_GUARDED; /* (realdev,vid) -> vlandev. */
    struct hmap vlandev_map OVS_GUARDED;     /* vlandev -> (realdev,vid). */

    /* Ports. */
    struct sset ports;             /* Set of standard port names. */
    struct sset ghost_ports;       /* Ports with no datapath port. */
    struct sset port_poll_set;     /* Queued names for port_poll() reply. */
    int port_poll_errno;           /* Last errno for port_poll() reply. */
    uint64_t change_seq;           /* Connectivity status changes. */

    /* Work queues. */
    struct guarded_list pins;      /* Contains "struct ofputil_packet_in"s. */
    struct seq *pins_seq;          /* For notifying 'pins' reception. */
    uint64_t pins_seqno;
};

/* All existing ofproto_dpif instances, indexed by ->up.name. */
static struct hmap all_ofproto_dpifs = HMAP_INITIALIZER(&all_ofproto_dpifs);

static bool ofproto_use_tnl_push_pop = true;
static void ofproto_unixctl_init(void);

static inline struct ofproto_dpif *
ofproto_dpif_cast(const struct ofproto *ofproto)
{
    ovs_assert(ofproto->ofproto_class == &ofproto_dpif_class);
    return CONTAINER_OF(ofproto, struct ofproto_dpif, up);
}

size_t
ofproto_dpif_get_max_mpls_depth(const struct ofproto_dpif *ofproto)
{
    return ofproto->backer->support.max_mpls_depth;
}

bool
ofproto_dpif_get_enable_recirc(const struct ofproto_dpif *ofproto)
{
    return ofproto->backer->support.recirc;
}

bool
ofproto_dpif_get_enable_ufid(struct dpif_backer *backer)
{
    return backer->support.ufid;
}

static void ofproto_trace(struct ofproto_dpif *, struct flow *,
                          const struct dp_packet *packet,
                          const struct ofpact[], size_t ofpacts_len,
                          struct ds *);

/* Global variables. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Initial mappings of port to bridge mappings. */
static struct shash init_ofp_ports = SHASH_INITIALIZER(&init_ofp_ports);

/* Executes 'fm'.  The caller retains ownership of 'fm' and everything in
 * it. */
void
ofproto_dpif_flow_mod(struct ofproto_dpif *ofproto,
                      struct ofputil_flow_mod *fm)
{
    ofproto_flow_mod(&ofproto->up, fm);
}

/* Appends 'pin' to the queue of "packet ins" to be sent to the controller.
 * Takes ownership of 'pin' and pin->packet. */
void
ofproto_dpif_send_packet_in(struct ofproto_dpif *ofproto,
                            struct ofproto_packet_in *pin)
{
    if (!guarded_list_push_back(&ofproto->pins, &pin->list_node, 1024)) {
        COVERAGE_INC(packet_in_overflow);
        free(CONST_CAST(void *, pin->up.packet));
        free(pin);
    }

    /* Wakes up main thread for packet-in I/O. */
    seq_change(ofproto->pins_seq);
}

/* The default "table-miss" behaviour for OpenFlow1.3+ is to drop the
 * packet rather than to send the packet to the controller.
 *
 * This function returns false to indicate that a packet_in message
 * for a "table-miss" should be sent to at least one controller.
 * False otherwise. */
bool
ofproto_dpif_wants_packet_in_on_miss(struct ofproto_dpif *ofproto)
{
    return connmgr_wants_packet_in_on_miss(ofproto->up.connmgr);
}

/* Factory functions. */

static void
init(const struct shash *iface_hints)
{
    struct shash_node *node;

    /* Make a local copy, since we don't own 'iface_hints' elements. */
    SHASH_FOR_EACH(node, iface_hints) {
        const struct iface_hint *orig_hint = node->data;
        struct iface_hint *new_hint = xmalloc(sizeof *new_hint);

        new_hint->br_name = xstrdup(orig_hint->br_name);
        new_hint->br_type = xstrdup(orig_hint->br_type);
        new_hint->ofp_port = orig_hint->ofp_port;

        shash_add(&init_ofp_ports, node->name, new_hint);
    }
}

static void
enumerate_types(struct sset *types)
{
    dp_enumerate_types(types);
}

static int
enumerate_names(const char *type, struct sset *names)
{
    struct ofproto_dpif *ofproto;

    sset_clear(names);
    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
        if (strcmp(type, ofproto->up.type)) {
            continue;
        }
        sset_add(names, ofproto->up.name);
    }

    return 0;
}

static int
del(const char *type, const char *name)
{
    struct dpif *dpif;
    int error;

    error = dpif_open(name, type, &dpif);
    if (!error) {
        error = dpif_delete(dpif);
        dpif_close(dpif);
    }
    return error;
}

static const char *
port_open_type(const char *datapath_type, const char *port_type)
{
    return dpif_port_open_type(datapath_type, port_type);
}

/* Type functions. */

static void process_dpif_port_changes(struct dpif_backer *);
static void process_dpif_all_ports_changed(struct dpif_backer *);
static void process_dpif_port_change(struct dpif_backer *,
                                     const char *devname);
static void process_dpif_port_error(struct dpif_backer *, int error);

static struct ofproto_dpif *
lookup_ofproto_dpif_by_port_name(const char *name)
{
    struct ofproto_dpif *ofproto;

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
        if (sset_contains(&ofproto->ports, name)) {
            return ofproto;
        }
    }

    return NULL;
}

static int
type_run(const char *type)
{
    struct dpif_backer *backer;

    backer = shash_find_data(&all_dpif_backers, type);
    if (!backer) {
        /* This is not necessarily a problem, since backers are only
         * created on demand. */
        return 0;
    }


    if (dpif_run(backer->dpif)) {
        backer->need_revalidate = REV_RECONFIGURE;
    }

    udpif_run(backer->udpif);

    /* If vswitchd started with other_config:flow_restore_wait set as "true",
     * and the configuration has now changed to "false", enable receiving
     * packets from the datapath. */
    if (!backer->recv_set_enable && !ofproto_get_flow_restore_wait()) {
        int error;

        backer->recv_set_enable = true;

        error = dpif_recv_set(backer->dpif, backer->recv_set_enable);
        if (error) {
            VLOG_ERR("Failed to enable receiving packets in dpif.");
            return error;
        }
        dpif_flow_flush(backer->dpif);
        backer->need_revalidate = REV_RECONFIGURE;
    }

    if (backer->recv_set_enable) {
        udpif_set_threads(backer->udpif, n_handlers, n_revalidators);
    }

    dpif_poll_threads_set(backer->dpif, n_dpdk_rxqs, pmd_cpu_mask);

    if (backer->need_revalidate) {
        struct ofproto_dpif *ofproto;
        struct simap_node *node;
        struct simap tmp_backers;

        /* Handle tunnel garbage collection. */
        simap_init(&tmp_backers);
        simap_swap(&backer->tnl_backers, &tmp_backers);

        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
            struct ofport_dpif *iter;

            if (backer != ofproto->backer) {
                continue;
            }

            HMAP_FOR_EACH (iter, up.hmap_node, &ofproto->up.ports) {
                char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
                const char *dp_port;

                if (!iter->is_tunnel) {
                    continue;
                }

                dp_port = netdev_vport_get_dpif_port(iter->up.netdev,
                                                     namebuf, sizeof namebuf);
                node = simap_find(&tmp_backers, dp_port);
                if (node) {
                    simap_put(&backer->tnl_backers, dp_port, node->data);
                    simap_delete(&tmp_backers, node);
                    node = simap_find(&backer->tnl_backers, dp_port);
                } else {
                    node = simap_find(&backer->tnl_backers, dp_port);
                    if (!node) {
                        odp_port_t odp_port = ODPP_NONE;

                        if (!dpif_port_add(backer->dpif, iter->up.netdev,
                                           &odp_port)) {
                            simap_put(&backer->tnl_backers, dp_port,
                                      odp_to_u32(odp_port));
                            node = simap_find(&backer->tnl_backers, dp_port);
                        }
                    }
                }

                iter->odp_port = node ? u32_to_odp(node->data) : ODPP_NONE;
                if (tnl_port_reconfigure(iter, iter->up.netdev,
                                         iter->odp_port,
                                         ovs_native_tunneling_is_on(ofproto), dp_port)) {
                    backer->need_revalidate = REV_RECONFIGURE;
                }
            }
        }

        SIMAP_FOR_EACH (node, &tmp_backers) {
            dpif_port_del(backer->dpif, u32_to_odp(node->data));
        }
        simap_destroy(&tmp_backers);

        switch (backer->need_revalidate) {
        case REV_RECONFIGURE:    COVERAGE_INC(rev_reconfigure);    break;
        case REV_STP:            COVERAGE_INC(rev_stp);            break;
        case REV_RSTP:           COVERAGE_INC(rev_rstp);           break;
        case REV_BOND:           COVERAGE_INC(rev_bond);           break;
        case REV_PORT_TOGGLED:   COVERAGE_INC(rev_port_toggled);   break;
        case REV_FLOW_TABLE:     COVERAGE_INC(rev_flow_table);     break;
        case REV_MAC_LEARNING:   COVERAGE_INC(rev_mac_learning);   break;
        case REV_MCAST_SNOOPING: COVERAGE_INC(rev_mcast_snooping); break;
        }
        backer->need_revalidate = 0;

        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
            struct ofport_dpif *ofport;
            struct ofbundle *bundle;

            if (ofproto->backer != backer) {
                continue;
            }

            xlate_txn_start();
            xlate_ofproto_set(ofproto, ofproto->up.name,
                              ofproto->backer->dpif, ofproto->ml,
                              ofproto->stp, ofproto->rstp, ofproto->ms,
                              ofproto->mbridge, ofproto->sflow, ofproto->ipfix,
                              ofproto->netflow,
                              ofproto->up.forward_bpdu,
                              connmgr_has_in_band(ofproto->up.connmgr),
                              &ofproto->backer->support);

            HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
                xlate_bundle_set(ofproto, bundle, bundle->name,
                                 bundle->vlan_mode, bundle->vlan,
                                 bundle->trunks, bundle->use_priority_tags,
                                 bundle->bond, bundle->lacp,
                                 bundle->floodable);
            }

            HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
                int stp_port = ofport->stp_port
                    ? stp_port_no(ofport->stp_port)
                    : -1;
                xlate_ofport_set(ofproto, ofport->bundle, ofport,
                                 ofport->up.ofp_port, ofport->odp_port,
                                 ofport->up.netdev, ofport->cfm, ofport->bfd,
                                 ofport->lldp, ofport->peer, stp_port,
                                 ofport->rstp_port, ofport->qdscp,
                                 ofport->n_qdscp, ofport->up.pp.config,
                                 ofport->up.pp.state, ofport->is_tunnel,
                                 ofport->may_enable);
            }
            xlate_txn_commit();
        }

        udpif_revalidate(backer->udpif);
    }

    process_dpif_port_changes(backer);

    return 0;
}

/* Check for and handle port changes in 'backer''s dpif. */
static void
process_dpif_port_changes(struct dpif_backer *backer)
{
    for (;;) {
        char *devname;
        int error;

        error = dpif_port_poll(backer->dpif, &devname);
        switch (error) {
        case EAGAIN:
            return;

        case ENOBUFS:
            process_dpif_all_ports_changed(backer);
            break;

        case 0:
            process_dpif_port_change(backer, devname);
            free(devname);
            break;

        default:
            process_dpif_port_error(backer, error);
            break;
        }
    }
}

static void
process_dpif_all_ports_changed(struct dpif_backer *backer)
{
    struct ofproto_dpif *ofproto;
    struct dpif_port dpif_port;
    struct dpif_port_dump dump;
    struct sset devnames;
    const char *devname;

    sset_init(&devnames);
    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
        if (ofproto->backer == backer) {
            struct ofport *ofport;

            HMAP_FOR_EACH (ofport, hmap_node, &ofproto->up.ports) {
                sset_add(&devnames, netdev_get_name(ofport->netdev));
            }
        }
    }
    DPIF_PORT_FOR_EACH (&dpif_port, &dump, backer->dpif) {
        sset_add(&devnames, dpif_port.name);
    }

    SSET_FOR_EACH (devname, &devnames) {
        process_dpif_port_change(backer, devname);
    }
    sset_destroy(&devnames);
}

static void
process_dpif_port_change(struct dpif_backer *backer, const char *devname)
{
    struct ofproto_dpif *ofproto;
    struct dpif_port port;

    /* Don't report on the datapath's device. */
    if (!strcmp(devname, dpif_base_name(backer->dpif))) {
        return;
    }

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node,
                   &all_ofproto_dpifs) {
        if (simap_contains(&ofproto->backer->tnl_backers, devname)) {
            return;
        }
    }

    ofproto = lookup_ofproto_dpif_by_port_name(devname);
    if (dpif_port_query_by_name(backer->dpif, devname, &port)) {
        /* The port was removed.  If we know the datapath,
         * report it through poll_set().  If we don't, it may be
         * notifying us of a removal we initiated, so ignore it.
         * If there's a pending ENOBUFS, let it stand, since
         * everything will be reevaluated. */
        if (ofproto && ofproto->port_poll_errno != ENOBUFS) {
            sset_add(&ofproto->port_poll_set, devname);
            ofproto->port_poll_errno = 0;
        }
    } else if (!ofproto) {
        /* The port was added, but we don't know with which
         * ofproto we should associate it.  Delete it. */
        dpif_port_del(backer->dpif, port.port_no);
    } else {
        struct ofport_dpif *ofport;

        ofport = ofport_dpif_cast(shash_find_data(
                                      &ofproto->up.port_by_name, devname));
        if (ofport
            && ofport->odp_port != port.port_no
            && !odp_port_to_ofport(backer, port.port_no))
        {
            /* 'ofport''s datapath port number has changed from
             * 'ofport->odp_port' to 'port.port_no'.  Update our internal data
             * structures to match. */
            ovs_rwlock_wrlock(&backer->odp_to_ofport_lock);
            hmap_remove(&backer->odp_to_ofport_map, &ofport->odp_port_node);
            ofport->odp_port = port.port_no;
            hmap_insert(&backer->odp_to_ofport_map, &ofport->odp_port_node,
                        hash_odp_port(port.port_no));
            ovs_rwlock_unlock(&backer->odp_to_ofport_lock);
            backer->need_revalidate = REV_RECONFIGURE;
        }
    }
    dpif_port_destroy(&port);
}

/* Propagate 'error' to all ofprotos based on 'backer'. */
static void
process_dpif_port_error(struct dpif_backer *backer, int error)
{
    struct ofproto_dpif *ofproto;

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
        if (ofproto->backer == backer) {
            sset_clear(&ofproto->port_poll_set);
            ofproto->port_poll_errno = error;
        }
    }
}

static void
type_wait(const char *type)
{
    struct dpif_backer *backer;

    backer = shash_find_data(&all_dpif_backers, type);
    if (!backer) {
        /* This is not necessarily a problem, since backers are only
         * created on demand. */
        return;
    }

    dpif_wait(backer->dpif);
}

/* Basic life-cycle. */

static int add_internal_flows(struct ofproto_dpif *);

static struct ofproto *
alloc(void)
{
    struct ofproto_dpif *ofproto = xzalloc(sizeof *ofproto);
    return &ofproto->up;
}

static void
dealloc(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    free(ofproto);
}

static void
close_dpif_backer(struct dpif_backer *backer)
{
    ovs_assert(backer->refcount > 0);

    if (--backer->refcount) {
        return;
    }

    udpif_destroy(backer->udpif);

    simap_destroy(&backer->tnl_backers);
    ovs_rwlock_destroy(&backer->odp_to_ofport_lock);
    hmap_destroy(&backer->odp_to_ofport_map);
    shash_find_and_delete(&all_dpif_backers, backer->type);
    free(backer->type);
    free(backer->dp_version_string);
    dpif_close(backer->dpif);
    free(backer);
}

/* Datapath port slated for removal from datapath. */
struct odp_garbage {
    struct ovs_list list_node;
    odp_port_t odp_port;
};

static bool check_variable_length_userdata(struct dpif_backer *backer);
static void check_support(struct dpif_backer *backer);

static int
open_dpif_backer(const char *type, struct dpif_backer **backerp)
{
    struct dpif_backer *backer;
    struct dpif_port_dump port_dump;
    struct dpif_port port;
    struct shash_node *node;
    struct ovs_list garbage_list;
    struct odp_garbage *garbage;

    struct sset names;
    char *backer_name;
    const char *name;
    int error;

    recirc_init();

    backer = shash_find_data(&all_dpif_backers, type);
    if (backer) {
        backer->refcount++;
        *backerp = backer;
        return 0;
    }

    backer_name = xasprintf("ovs-%s", type);

    /* Remove any existing datapaths, since we assume we're the only
     * userspace controlling the datapath. */
    sset_init(&names);
    dp_enumerate_names(type, &names);
    SSET_FOR_EACH(name, &names) {
        struct dpif *old_dpif;

        /* Don't remove our backer if it exists. */
        if (!strcmp(name, backer_name)) {
            continue;
        }

        if (dpif_open(name, type, &old_dpif)) {
            VLOG_WARN("couldn't open old datapath %s to remove it", name);
        } else {
            dpif_delete(old_dpif);
            dpif_close(old_dpif);
        }
    }
    sset_destroy(&names);

    backer = xmalloc(sizeof *backer);

    error = dpif_create_and_open(backer_name, type, &backer->dpif);
    free(backer_name);
    if (error) {
        VLOG_ERR("failed to open datapath of type %s: %s", type,
                 ovs_strerror(error));
        free(backer);
        return error;
    }
    backer->udpif = udpif_create(backer, backer->dpif);

    backer->type = xstrdup(type);
    backer->refcount = 1;
    hmap_init(&backer->odp_to_ofport_map);
    ovs_rwlock_init(&backer->odp_to_ofport_lock);
    backer->need_revalidate = 0;
    simap_init(&backer->tnl_backers);
    backer->recv_set_enable = !ofproto_get_flow_restore_wait();
    *backerp = backer;

    if (backer->recv_set_enable) {
        dpif_flow_flush(backer->dpif);
    }

    /* Loop through the ports already on the datapath and remove any
     * that we don't need anymore. */
    list_init(&garbage_list);
    dpif_port_dump_start(&port_dump, backer->dpif);
    while (dpif_port_dump_next(&port_dump, &port)) {
        node = shash_find(&init_ofp_ports, port.name);
        if (!node && strcmp(port.name, dpif_base_name(backer->dpif))) {
            garbage = xmalloc(sizeof *garbage);
            garbage->odp_port = port.port_no;
            list_push_front(&garbage_list, &garbage->list_node);
        }
    }
    dpif_port_dump_done(&port_dump);

    LIST_FOR_EACH_POP (garbage, list_node, &garbage_list) {
        dpif_port_del(backer->dpif, garbage->odp_port);
        free(garbage);
    }

    shash_add(&all_dpif_backers, type, backer);

    check_support(backer);
    atomic_count_init(&backer->tnl_count, 0);

    error = dpif_recv_set(backer->dpif, backer->recv_set_enable);
    if (error) {
        VLOG_ERR("failed to listen on datapath of type %s: %s",
                 type, ovs_strerror(error));
        close_dpif_backer(backer);
        return error;
    }

    if (backer->recv_set_enable) {
        udpif_set_threads(backer->udpif, n_handlers, n_revalidators);
    }

    /* This check fails if performed before udpif threads have been set,
     * as the kernel module checks that the 'pid' in userspace action
     * is non-zero. */
    backer->support.variable_length_userdata
        = check_variable_length_userdata(backer);
    backer->dp_version_string = dpif_get_dp_version(backer->dpif);

    return error;
}

bool
ovs_native_tunneling_is_on(struct ofproto_dpif *ofproto)
{
    return ofproto_use_tnl_push_pop && ofproto->backer->support.tnl_push_pop &&
           atomic_count_get(&ofproto->backer->tnl_count);
}

/* Tests whether 'backer''s datapath supports recirculation.  Only newer
 * datapaths support OVS_KEY_ATTR_RECIRC_ID in keys.  We need to disable some
 * features on older datapaths that don't support this feature.
 *
 * Returns false if 'backer' definitely does not support recirculation, true if
 * it seems to support recirculation or if at least the error we get is
 * ambiguous. */
static bool
check_recirc(struct dpif_backer *backer)
{
    struct flow flow;
    struct odputil_keybuf keybuf;
    struct ofpbuf key;
    bool enable_recirc;

    memset(&flow, 0, sizeof flow);
    flow.recirc_id = 1;
    flow.dp_hash = 1;

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&key, &flow, NULL, 0, true);
    enable_recirc = dpif_probe_feature(backer->dpif, "recirculation", &key,
                                       NULL);

    if (enable_recirc) {
        VLOG_INFO("%s: Datapath supports recirculation",
                  dpif_name(backer->dpif));
    } else {
        VLOG_INFO("%s: Datapath does not support recirculation",
                  dpif_name(backer->dpif));
    }

    return enable_recirc;
}

/* Tests whether 'dpif' supports unique flow ids. We can skip serializing
 * some flow attributes for datapaths that support this feature.
 *
 * Returns true if 'dpif' supports UFID for flow operations.
 * Returns false if  'dpif' does not support UFID. */
static bool
check_ufid(struct dpif_backer *backer)
{
    struct flow flow;
    struct odputil_keybuf keybuf;
    struct ofpbuf key;
    ovs_u128 ufid;
    bool enable_ufid;

    memset(&flow, 0, sizeof flow);
    flow.dl_type = htons(0x1234);

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&key, &flow, NULL, 0, true);
    dpif_flow_hash(backer->dpif, key.data, key.size, &ufid);

    enable_ufid = dpif_probe_feature(backer->dpif, "UFID", &key, &ufid);

    if (enable_ufid) {
        VLOG_INFO("%s: Datapath supports unique flow ids",
                  dpif_name(backer->dpif));
    } else {
        VLOG_INFO("%s: Datapath does not support unique flow ids",
                  dpif_name(backer->dpif));
    }
    return enable_ufid;
}

/* Tests whether 'backer''s datapath supports variable-length
 * OVS_USERSPACE_ATTR_USERDATA in OVS_ACTION_ATTR_USERSPACE actions.  We need
 * to disable some features on older datapaths that don't support this
 * feature.
 *
 * Returns false if 'backer' definitely does not support variable-length
 * userdata, true if it seems to support them or if at least the error we get
 * is ambiguous. */
static bool
check_variable_length_userdata(struct dpif_backer *backer)
{
    struct eth_header *eth;
    struct ofpbuf actions;
    struct dpif_execute execute;
    struct dp_packet packet;
    size_t start;
    int error;

    /* Compose a userspace action that will cause an ERANGE error on older
     * datapaths that don't support variable-length userdata.
     *
     * We really test for using userdata longer than 8 bytes, but older
     * datapaths accepted these, silently truncating the userdata to 8 bytes.
     * The same older datapaths rejected userdata shorter than 8 bytes, so we
     * test for that instead as a proxy for longer userdata support. */
    ofpbuf_init(&actions, 64);
    start = nl_msg_start_nested(&actions, OVS_ACTION_ATTR_USERSPACE);
    nl_msg_put_u32(&actions, OVS_USERSPACE_ATTR_PID,
                   dpif_port_get_pid(backer->dpif, ODPP_NONE, 0));
    nl_msg_put_unspec_zero(&actions, OVS_USERSPACE_ATTR_USERDATA, 4);
    nl_msg_end_nested(&actions, start);

    /* Compose a dummy ethernet packet. */
    dp_packet_init(&packet, ETH_HEADER_LEN);
    eth = dp_packet_put_zeros(&packet, ETH_HEADER_LEN);
    eth->eth_type = htons(0x1234);

    /* Execute the actions.  On older datapaths this fails with ERANGE, on
     * newer datapaths it succeeds. */
    execute.actions = actions.data;
    execute.actions_len = actions.size;
    execute.packet = &packet;
    execute.needs_help = false;
    execute.probe = true;

    error = dpif_execute(backer->dpif, &execute);

    dp_packet_uninit(&packet);
    ofpbuf_uninit(&actions);

    switch (error) {
    case 0:
        return true;

    case ERANGE:
        /* Variable-length userdata is not supported. */
        VLOG_WARN("%s: datapath does not support variable-length userdata "
                  "feature (needs Linux 3.10+ or kernel module from OVS "
                  "1..11+).  The NXAST_SAMPLE action will be ignored.",
                  dpif_name(backer->dpif));
        return false;

    default:
        /* Something odd happened.  We're not sure whether variable-length
         * userdata is supported.  Default to "yes". */
        VLOG_WARN("%s: variable-length userdata feature probe failed (%s)",
                  dpif_name(backer->dpif), ovs_strerror(error));
        return true;
    }
}

/* Tests the MPLS label stack depth supported by 'backer''s datapath.
 *
 * Returns the number of elements in a struct flow's mpls_lse field
 * if the datapath supports at least that many entries in an
 * MPLS label stack.
 * Otherwise returns the number of MPLS push actions supported by
 * the datapath. */
static size_t
check_max_mpls_depth(struct dpif_backer *backer)
{
    struct flow flow;
    int n;

    for (n = 0; n < FLOW_MAX_MPLS_LABELS; n++) {
        struct odputil_keybuf keybuf;
        struct ofpbuf key;

        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_MPLS);
        flow_set_mpls_bos(&flow, n, 1);

        ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
        odp_flow_key_from_flow(&key, &flow, NULL, 0, false);
        if (!dpif_probe_feature(backer->dpif, "MPLS", &key, NULL)) {
            break;
        }
    }

    VLOG_INFO("%s: MPLS label stack length probed as %d",
              dpif_name(backer->dpif), n);
    return n;
}

/* Tests whether 'backer''s datapath supports masked data in
 * OVS_ACTION_ATTR_SET actions.  We need to disable some features on older
 * datapaths that don't support this feature. */
static bool
check_masked_set_action(struct dpif_backer *backer)
{
    struct eth_header *eth;
    struct ofpbuf actions;
    struct dpif_execute execute;
    struct dp_packet packet;
    int error;
    struct ovs_key_ethernet key, mask;

    /* Compose a set action that will cause an EINVAL error on older
     * datapaths that don't support masked set actions.
     * Avoid using a full mask, as it could be translated to a non-masked
     * set action instead. */
    ofpbuf_init(&actions, 64);
    memset(&key, 0x53, sizeof key);
    memset(&mask, 0x7f, sizeof mask);
    commit_masked_set_action(&actions, OVS_KEY_ATTR_ETHERNET, &key, &mask,
                             sizeof key);

    /* Compose a dummy ethernet packet. */
    dp_packet_init(&packet, ETH_HEADER_LEN);
    eth = dp_packet_put_zeros(&packet, ETH_HEADER_LEN);
    eth->eth_type = htons(0x1234);

    /* Execute the actions.  On older datapaths this fails with EINVAL, on
     * newer datapaths it succeeds. */
    execute.actions = actions.data;
    execute.actions_len = actions.size;
    execute.packet = &packet;
    execute.needs_help = false;
    execute.probe = true;

    error = dpif_execute(backer->dpif, &execute);

    dp_packet_uninit(&packet);
    ofpbuf_uninit(&actions);

    if (error) {
        /* Masked set action is not supported. */
        VLOG_INFO("%s: datapath does not support masked set action feature.",
                  dpif_name(backer->dpif));
    }
    return !error;
}

static void
check_support(struct dpif_backer *backer)
{
    /* This feature needs to be tested after udpif threads are set. */
    backer->support.variable_length_userdata = false;

    backer->support.recirc = check_recirc(backer);
    backer->support.max_mpls_depth = check_max_mpls_depth(backer);
    backer->support.masked_set_action = check_masked_set_action(backer);
    backer->support.ufid = check_ufid(backer);
    backer->support.tnl_push_pop = dpif_supports_tnl_push_pop(backer->dpif);
}

static int
construct(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct shash_node *node, *next;
    int error;

    /* Tunnel module can get used right after the udpif threads are running. */
    ofproto_tunnel_init();

    error = open_dpif_backer(ofproto->up.type, &ofproto->backer);
    if (error) {
        return error;
    }

    ofproto->netflow = NULL;
    ofproto->sflow = NULL;
    ofproto->ipfix = NULL;
    ofproto->stp = NULL;
    ofproto->rstp = NULL;
    ofproto->dump_seq = 0;
    hmap_init(&ofproto->bundles);
    ofproto->ml = mac_learning_create(MAC_ENTRY_DEFAULT_IDLE_TIME);
    ofproto->ms = NULL;
    ofproto->mbridge = mbridge_create();
    ofproto->has_bonded_bundles = false;
    ofproto->lacp_enabled = false;
    ovs_mutex_init_adaptive(&ofproto->stats_mutex);
    ovs_mutex_init(&ofproto->vsp_mutex);

    guarded_list_init(&ofproto->pins);

    ofproto_unixctl_init();

    hmap_init(&ofproto->vlandev_map);
    hmap_init(&ofproto->realdev_vid_map);

    sset_init(&ofproto->ports);
    sset_init(&ofproto->ghost_ports);
    sset_init(&ofproto->port_poll_set);
    ofproto->port_poll_errno = 0;
    ofproto->change_seq = 0;
    ofproto->pins_seq = seq_create();
    ofproto->pins_seqno = seq_read(ofproto->pins_seq);


    SHASH_FOR_EACH_SAFE (node, next, &init_ofp_ports) {
        struct iface_hint *iface_hint = node->data;

        if (!strcmp(iface_hint->br_name, ofproto->up.name)) {
            /* Check if the datapath already has this port. */
            if (dpif_port_exists(ofproto->backer->dpif, node->name)) {
                sset_add(&ofproto->ports, node->name);
            }

            free(iface_hint->br_name);
            free(iface_hint->br_type);
            free(iface_hint);
            shash_delete(&init_ofp_ports, node);
        }
    }

    hmap_insert(&all_ofproto_dpifs, &ofproto->all_ofproto_dpifs_node,
                hash_string(ofproto->up.name, 0));
    memset(&ofproto->stats, 0, sizeof ofproto->stats);

    ofproto_init_tables(ofproto_, N_TABLES);
    error = add_internal_flows(ofproto);

    ofproto->up.tables[TBL_INTERNAL].flags = OFTABLE_HIDDEN | OFTABLE_READONLY;

    return error;
}

static int
add_internal_miss_flow(struct ofproto_dpif *ofproto, int id,
                  const struct ofpbuf *ofpacts, struct rule_dpif **rulep)
{
    struct match match;
    int error;
    struct rule *rule;

    match_init_catchall(&match);
    match_set_reg(&match, 0, id);

    error = ofproto_dpif_add_internal_flow(ofproto, &match, 0, 0, ofpacts,
                                           &rule);
    *rulep = error ? NULL : rule_dpif_cast(rule);

    return error;
}

static int
add_internal_flows(struct ofproto_dpif *ofproto)
{
    struct ofpact_controller *controller;
    uint64_t ofpacts_stub[128 / 8];
    struct ofpbuf ofpacts;
    struct rule *unused_rulep OVS_UNUSED;
    struct match match;
    int error;
    int id;

    ofpbuf_use_stack(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    id = 1;

    controller = ofpact_put_CONTROLLER(&ofpacts);
    controller->max_len = UINT16_MAX;
    controller->controller_id = 0;
    controller->reason = OFPR_NO_MATCH;
    ofpact_pad(&ofpacts);

    error = add_internal_miss_flow(ofproto, id++, &ofpacts,
                                   &ofproto->miss_rule);
    if (error) {
        return error;
    }

    ofpbuf_clear(&ofpacts);
    error = add_internal_miss_flow(ofproto, id++, &ofpacts,
                                   &ofproto->no_packet_in_rule);
    if (error) {
        return error;
    }

    error = add_internal_miss_flow(ofproto, id++, &ofpacts,
                                   &ofproto->drop_frags_rule);
    if (error) {
        return error;
    }

    /* Drop any run away non-recirc rule lookups. Recirc_id has to be
     * zero when reaching this rule.
     *
     * (priority=2), recirc_id=0, actions=drop
     */
    ofpbuf_clear(&ofpacts);
    match_init_catchall(&match);
    match_set_recirc_id(&match, 0);
    error = ofproto_dpif_add_internal_flow(ofproto, &match, 2, 0, &ofpacts,
                                           &unused_rulep);
    return error;
}

static void
destruct(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofproto_packet_in *pin;
    struct rule_dpif *rule;
    struct oftable *table;
    struct ovs_list pins;

    ofproto->backer->need_revalidate = REV_RECONFIGURE;
    xlate_txn_start();
    xlate_remove_ofproto(ofproto);
    xlate_txn_commit();

    /* Ensure that the upcall processing threads have no remaining references
     * to the ofproto or anything in it. */
    udpif_synchronize(ofproto->backer->udpif);

    hmap_remove(&all_ofproto_dpifs, &ofproto->all_ofproto_dpifs_node);

    OFPROTO_FOR_EACH_TABLE (table, &ofproto->up) {
        CLS_FOR_EACH (rule, up.cr, &table->cls) {
            ofproto_rule_delete(&ofproto->up, &rule->up);
        }
    }

    guarded_list_pop_all(&ofproto->pins, &pins);
    LIST_FOR_EACH_POP (pin, list_node, &pins) {
        free(CONST_CAST(void *, pin->up.packet));
        free(pin);
    }
    guarded_list_destroy(&ofproto->pins);

    recirc_free_ofproto(ofproto, ofproto->up.name);

    mbridge_unref(ofproto->mbridge);

    netflow_unref(ofproto->netflow);
    dpif_sflow_unref(ofproto->sflow);
    dpif_ipfix_unref(ofproto->ipfix);
    hmap_destroy(&ofproto->bundles);
    mac_learning_unref(ofproto->ml);
    mcast_snooping_unref(ofproto->ms);

    hmap_destroy(&ofproto->vlandev_map);
    hmap_destroy(&ofproto->realdev_vid_map);

    sset_destroy(&ofproto->ports);
    sset_destroy(&ofproto->ghost_ports);
    sset_destroy(&ofproto->port_poll_set);

    ovs_mutex_destroy(&ofproto->stats_mutex);
    ovs_mutex_destroy(&ofproto->vsp_mutex);

    seq_destroy(ofproto->pins_seq);

    close_dpif_backer(ofproto->backer);
}

static int
run(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    uint64_t new_seq, new_dump_seq;

    if (mbridge_need_revalidate(ofproto->mbridge)) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
        ovs_rwlock_wrlock(&ofproto->ml->rwlock);
        mac_learning_flush(ofproto->ml);
        ovs_rwlock_unlock(&ofproto->ml->rwlock);
        mcast_snooping_mdb_flush(ofproto->ms);
    }

    /* Always updates the ofproto->pins_seqno to avoid frequent wakeup during
     * flow restore.  Even though nothing is processed during flow restore,
     * all queued 'pins' will be handled immediately when flow restore
     * completes. */
    ofproto->pins_seqno = seq_read(ofproto->pins_seq);

    /* Do not perform any periodic activity required by 'ofproto' while
     * waiting for flow restore to complete. */
    if (!ofproto_get_flow_restore_wait()) {
        struct ofproto_packet_in *pin;
        struct ovs_list pins;

        guarded_list_pop_all(&ofproto->pins, &pins);
        LIST_FOR_EACH_POP (pin, list_node, &pins) {
            connmgr_send_packet_in(ofproto->up.connmgr, pin);
            free(CONST_CAST(void *, pin->up.packet));
            free(pin);
        }
    }

    if (ofproto->netflow) {
        netflow_run(ofproto->netflow);
    }
    if (ofproto->sflow) {
        dpif_sflow_run(ofproto->sflow);
    }
    if (ofproto->ipfix) {
        dpif_ipfix_run(ofproto->ipfix);
    }

    new_seq = seq_read(connectivity_seq_get());
    if (ofproto->change_seq != new_seq) {
        struct ofport_dpif *ofport;

        HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
            port_run(ofport);
        }

        ofproto->change_seq = new_seq;
    }
    if (ofproto->lacp_enabled || ofproto->has_bonded_bundles) {
        struct ofbundle *bundle;

        HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
            bundle_run(bundle);
        }
    }

    stp_run(ofproto);
    rstp_run(ofproto);
    ovs_rwlock_wrlock(&ofproto->ml->rwlock);
    if (mac_learning_run(ofproto->ml)) {
        ofproto->backer->need_revalidate = REV_MAC_LEARNING;
    }
    ovs_rwlock_unlock(&ofproto->ml->rwlock);

    if (mcast_snooping_run(ofproto->ms)) {
        ofproto->backer->need_revalidate = REV_MCAST_SNOOPING;
    }

    new_dump_seq = seq_read(udpif_dump_seq(ofproto->backer->udpif));
    if (ofproto->dump_seq != new_dump_seq) {
        struct rule *rule, *next_rule;

        /* We know stats are relatively fresh, so now is a good time to do some
         * periodic work. */
        ofproto->dump_seq = new_dump_seq;

        /* Expire OpenFlow flows whose idle_timeout or hard_timeout
         * has passed. */
        ovs_mutex_lock(&ofproto_mutex);
        LIST_FOR_EACH_SAFE (rule, next_rule, expirable,
                            &ofproto->up.expirable) {
            rule_expire(rule_dpif_cast(rule));
        }
        ovs_mutex_unlock(&ofproto_mutex);

        /* All outstanding data in existing flows has been accounted, so it's a
         * good time to do bond rebalancing. */
        if (ofproto->has_bonded_bundles) {
            struct ofbundle *bundle;

            HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
                if (bundle->bond) {
                    bond_rebalance(bundle->bond);
                }
            }
        }
    }
    return 0;
}

static void
wait(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    if (ofproto_get_flow_restore_wait()) {
        return;
    }

    if (ofproto->sflow) {
        dpif_sflow_wait(ofproto->sflow);
    }
    if (ofproto->ipfix) {
        dpif_ipfix_wait(ofproto->ipfix);
    }
    if (ofproto->lacp_enabled || ofproto->has_bonded_bundles) {
        struct ofbundle *bundle;

        HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
            bundle_wait(bundle);
        }
    }
    if (ofproto->netflow) {
        netflow_wait(ofproto->netflow);
    }
    ovs_rwlock_rdlock(&ofproto->ml->rwlock);
    mac_learning_wait(ofproto->ml);
    ovs_rwlock_unlock(&ofproto->ml->rwlock);
    mcast_snooping_wait(ofproto->ms);
    stp_wait(ofproto);
    if (ofproto->backer->need_revalidate) {
        /* Shouldn't happen, but if it does just go around again. */
        VLOG_DBG_RL(&rl, "need revalidate in ofproto_wait_cb()");
        poll_immediate_wake();
    }

    seq_wait(udpif_dump_seq(ofproto->backer->udpif), ofproto->dump_seq);
    seq_wait(ofproto->pins_seq, ofproto->pins_seqno);
}

static void
type_get_memory_usage(const char *type, struct simap *usage)
{
    struct dpif_backer *backer;

    backer = shash_find_data(&all_dpif_backers, type);
    if (backer) {
        udpif_get_memory_usage(backer->udpif, usage);
    }
}

static void
flush(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_backer *backer = ofproto->backer;

    if (backer) {
        udpif_flush(backer->udpif);
    }
}

static void
query_tables(struct ofproto *ofproto,
             struct ofputil_table_features *features,
             struct ofputil_table_stats *stats)
{
    strcpy(features->name, "classifier");

    if (stats) {
        int i;

        for (i = 0; i < ofproto->n_tables; i++) {
            unsigned long missed, matched;

            atomic_read_relaxed(&ofproto->tables[i].n_matched, &matched);
            atomic_read_relaxed(&ofproto->tables[i].n_missed, &missed);

            stats[i].matched_count = matched;
            stats[i].lookup_count = matched + missed;
        }
    }
}

static struct ofport *
port_alloc(void)
{
    struct ofport_dpif *port = xzalloc(sizeof *port);
    return &port->up;
}

static void
port_dealloc(struct ofport *port_)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    free(port);
}

static int
port_construct(struct ofport *port_)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);
    const struct netdev *netdev = port->up.netdev;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dp_port_name;
    struct dpif_port dpif_port;
    int error;

    ofproto->backer->need_revalidate = REV_RECONFIGURE;
    port->bundle = NULL;
    port->cfm = NULL;
    port->bfd = NULL;
    port->lldp = NULL;
    port->may_enable = false;
    port->stp_port = NULL;
    port->stp_state = STP_DISABLED;
    port->rstp_port = NULL;
    port->rstp_state = RSTP_DISABLED;
    port->is_tunnel = false;
    port->peer = NULL;
    port->qdscp = NULL;
    port->n_qdscp = 0;
    port->realdev_ofp_port = 0;
    port->vlandev_vid = 0;
    port->carrier_seq = netdev_get_carrier_resets(netdev);
    port->is_layer3 = netdev_vport_is_layer3(netdev);

    if (netdev_vport_is_patch(netdev)) {
        /* By bailing out here, we don't submit the port to the sFlow module
         * to be considered for counter polling export.  This is correct
         * because the patch port represents an interface that sFlow considers
         * to be "internal" to the switch as a whole, and therefore not a
         * candidate for counter polling. */
        port->odp_port = ODPP_NONE;
        ofport_update_peer(port);
        return 0;
    }

    dp_port_name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    error = dpif_port_query_by_name(ofproto->backer->dpif, dp_port_name,
                                    &dpif_port);
    if (error) {
        return error;
    }

    port->odp_port = dpif_port.port_no;

    if (netdev_get_tunnel_config(netdev)) {
        atomic_count_inc(&ofproto->backer->tnl_count);
        error = tnl_port_add(port, port->up.netdev, port->odp_port,
                             ovs_native_tunneling_is_on(ofproto), dp_port_name);
        if (error) {
            atomic_count_dec(&ofproto->backer->tnl_count);
            dpif_port_destroy(&dpif_port);
            return error;
        }

        port->is_tunnel = true;
        if (ofproto->ipfix) {
           dpif_ipfix_add_tunnel_port(ofproto->ipfix, port_, port->odp_port);
        }
    } else {
        /* Sanity-check that a mapping doesn't already exist.  This
         * shouldn't happen for non-tunnel ports. */
        if (odp_port_to_ofp_port(ofproto, port->odp_port) != OFPP_NONE) {
            VLOG_ERR("port %s already has an OpenFlow port number",
                     dpif_port.name);
            dpif_port_destroy(&dpif_port);
            return EBUSY;
        }

        ovs_rwlock_wrlock(&ofproto->backer->odp_to_ofport_lock);
        hmap_insert(&ofproto->backer->odp_to_ofport_map, &port->odp_port_node,
                    hash_odp_port(port->odp_port));
        ovs_rwlock_unlock(&ofproto->backer->odp_to_ofport_lock);
    }
    dpif_port_destroy(&dpif_port);

    if (ofproto->sflow) {
        dpif_sflow_add_port(ofproto->sflow, port_, port->odp_port);
    }

    return 0;
}

static void
port_destruct(struct ofport *port_)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);
    const char *devname = netdev_get_name(port->up.netdev);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dp_port_name;

    ofproto->backer->need_revalidate = REV_RECONFIGURE;
    xlate_txn_start();
    xlate_ofport_remove(port);
    xlate_txn_commit();

    dp_port_name = netdev_vport_get_dpif_port(port->up.netdev, namebuf,
                                              sizeof namebuf);
    if (dpif_port_exists(ofproto->backer->dpif, dp_port_name)) {
        /* The underlying device is still there, so delete it.  This
         * happens when the ofproto is being destroyed, since the caller
         * assumes that removal of attached ports will happen as part of
         * destruction. */
        if (!port->is_tunnel) {
            dpif_port_del(ofproto->backer->dpif, port->odp_port);
        }
    }

    if (port->peer) {
        port->peer->peer = NULL;
        port->peer = NULL;
    }

    if (port->odp_port != ODPP_NONE && !port->is_tunnel) {
        ovs_rwlock_wrlock(&ofproto->backer->odp_to_ofport_lock);
        hmap_remove(&ofproto->backer->odp_to_ofport_map, &port->odp_port_node);
        ovs_rwlock_unlock(&ofproto->backer->odp_to_ofport_lock);
    }

    if (port->is_tunnel) {
        atomic_count_dec(&ofproto->backer->tnl_count);
    }

    if (port->is_tunnel && ofproto->ipfix) {
       dpif_ipfix_del_tunnel_port(ofproto->ipfix, port->odp_port);
    }

    tnl_port_del(port);
    sset_find_and_delete(&ofproto->ports, devname);
    sset_find_and_delete(&ofproto->ghost_ports, devname);
    bundle_remove(port_);
    set_cfm(port_, NULL);
    set_bfd(port_, NULL);
    set_lldp(port_, NULL);
    if (port->stp_port) {
        stp_port_disable(port->stp_port);
    }
    set_rstp_port(port_, NULL);
    if (ofproto->sflow) {
        dpif_sflow_del_port(ofproto->sflow, port->odp_port);
    }

    free(port->qdscp);
}

static void
port_modified(struct ofport *port_)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dp_port_name;
    struct netdev *netdev = port->up.netdev;

    if (port->bundle && port->bundle->bond) {
        bond_slave_set_netdev(port->bundle->bond, port, netdev);
    }

    if (port->cfm) {
        cfm_set_netdev(port->cfm, netdev);
    }

    if (port->bfd) {
        bfd_set_netdev(port->bfd, netdev);
    }

    ofproto_dpif_monitor_port_update(port, port->bfd, port->cfm,
                                     port->lldp, port->up.pp.hw_addr);

    dp_port_name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

    if (port->is_tunnel) {
        struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);

        if (tnl_port_reconfigure(port, netdev, port->odp_port,
                                 ovs_native_tunneling_is_on(ofproto),
                                 dp_port_name)) {
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
        }
    }

    ofport_update_peer(port);
}

static void
port_reconfigured(struct ofport *port_, enum ofputil_port_config old_config)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);
    enum ofputil_port_config changed = old_config ^ port->up.pp.config;

    if (changed & (OFPUTIL_PC_NO_RECV | OFPUTIL_PC_NO_RECV_STP |
                   OFPUTIL_PC_NO_FWD | OFPUTIL_PC_NO_FLOOD |
                   OFPUTIL_PC_NO_PACKET_IN)) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;

        if (changed & OFPUTIL_PC_NO_FLOOD && port->bundle) {
            bundle_update(port->bundle);
        }
    }
}

static int
set_sflow(struct ofproto *ofproto_,
          const struct ofproto_sflow_options *sflow_options)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_sflow *ds = ofproto->sflow;

    if (sflow_options) {
        uint32_t old_probability = ds ? dpif_sflow_get_probability(ds) : 0;
        if (!ds) {
            struct ofport_dpif *ofport;

            ds = ofproto->sflow = dpif_sflow_create();
            HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
                dpif_sflow_add_port(ds, &ofport->up, ofport->odp_port);
            }
        }
        dpif_sflow_set_options(ds, sflow_options);
        if (dpif_sflow_get_probability(ds) != old_probability) {
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
        }
    } else {
        if (ds) {
            dpif_sflow_unref(ds);
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
            ofproto->sflow = NULL;
        }
    }
    return 0;
}

static int
set_ipfix(
    struct ofproto *ofproto_,
    const struct ofproto_ipfix_bridge_exporter_options *bridge_exporter_options,
    const struct ofproto_ipfix_flow_exporter_options *flow_exporters_options,
    size_t n_flow_exporters_options)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_ipfix *di = ofproto->ipfix;
    bool has_options = bridge_exporter_options || flow_exporters_options;
    bool new_di = false;

    if (has_options && !di) {
        di = ofproto->ipfix = dpif_ipfix_create();
        new_di = true;
    }

    if (di) {
        /* Call set_options in any case to cleanly flush the flow
         * caches in the last exporters that are to be destroyed. */
        dpif_ipfix_set_options(
            di, bridge_exporter_options, flow_exporters_options,
            n_flow_exporters_options);

        /* Add tunnel ports only when a new ipfix created */
        if (new_di == true) {
            struct ofport_dpif *ofport;
            HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
                if (ofport->is_tunnel == true) {
                    dpif_ipfix_add_tunnel_port(di, &ofport->up, ofport->odp_port);
                }
            }
        }

        if (!has_options) {
            dpif_ipfix_unref(di);
            ofproto->ipfix = NULL;
        }
    }

    return 0;
}

static int
set_cfm(struct ofport *ofport_, const struct cfm_settings *s)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    struct cfm *old = ofport->cfm;
    int error = 0;

    if (s) {
        if (!ofport->cfm) {
            ofport->cfm = cfm_create(ofport->up.netdev);
        }

        if (cfm_configure(ofport->cfm, s)) {
            error = 0;
            goto out;
        }

        error = EINVAL;
    }
    cfm_unref(ofport->cfm);
    ofport->cfm = NULL;
out:
    if (ofport->cfm != old) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
    }
    ofproto_dpif_monitor_port_update(ofport, ofport->bfd, ofport->cfm,
                                     ofport->lldp, ofport->up.pp.hw_addr);
    return error;
}

static bool
cfm_status_changed(struct ofport *ofport_)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);

    return ofport->cfm ? cfm_check_status_change(ofport->cfm) : true;
}

static int
get_cfm_status(const struct ofport *ofport_,
               struct cfm_status *status)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    int ret = 0;

    if (ofport->cfm) {
        cfm_get_status(ofport->cfm, status);
    } else {
        ret = ENOENT;
    }

    return ret;
}

static int
set_bfd(struct ofport *ofport_, const struct smap *cfg)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport_->ofproto);
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct bfd *old;

    old = ofport->bfd;
    ofport->bfd = bfd_configure(old, netdev_get_name(ofport->up.netdev),
                                cfg, ofport->up.netdev);
    if (ofport->bfd != old) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
    }
    ofproto_dpif_monitor_port_update(ofport, ofport->bfd, ofport->cfm,
                                     ofport->lldp, ofport->up.pp.hw_addr);
    return 0;
}

static bool
bfd_status_changed(struct ofport *ofport_)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);

    return ofport->bfd ? bfd_check_status_change(ofport->bfd) : true;
}

static int
get_bfd_status(struct ofport *ofport_, struct smap *smap)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    int ret = 0;

    if (ofport->bfd) {
        bfd_get_status(ofport->bfd, smap);
    } else {
        ret = ENOENT;
    }

    return ret;
}

static int
set_lldp(struct ofport *ofport_,
         const struct smap *cfg)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    int error = 0;

    if (cfg) {
        if (!ofport->lldp) {
            struct ofproto_dpif *ofproto;

            ofproto = ofproto_dpif_cast(ofport->up.ofproto);
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
            ofport->lldp = lldp_create(ofport->up.netdev, ofport_->mtu, cfg);
        }

        if (!lldp_configure(ofport->lldp, cfg)) {
            error = EINVAL;
        }
    }
    if (error) {
        lldp_unref(ofport->lldp);
        ofport->lldp = NULL;
    }

    ofproto_dpif_monitor_port_update(ofport,
                                     ofport->bfd,
                                     ofport->cfm,
                                     ofport->lldp,
                                     ofport->up.pp.hw_addr);
    return error;
}

static bool
get_lldp_status(const struct ofport *ofport_,
               struct lldp_status *status OVS_UNUSED)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);

    return ofport->lldp ? true : false;
}

static int
set_aa(struct ofproto *ofproto OVS_UNUSED,
       const struct aa_settings *s)
{
    return aa_configure(s);
}

static int
aa_mapping_set(struct ofproto *ofproto_ OVS_UNUSED, void *aux,
               const struct aa_mapping_settings *s)
{
    return aa_mapping_register(aux, s);
}

static int
aa_mapping_unset(struct ofproto *ofproto OVS_UNUSED, void *aux)
{
    return aa_mapping_unregister(aux);
}

static int
aa_vlan_get_queued(struct ofproto *ofproto OVS_UNUSED, struct ovs_list *list)
{
    return aa_get_vlan_queued(list);
}

static unsigned int
aa_vlan_get_queue_size(struct ofproto *ofproto OVS_UNUSED)
{
    return aa_get_vlan_queue_size();
}


/* Spanning Tree. */

/* Called while rstp_mutex is held. */
static void
rstp_send_bpdu_cb(struct dp_packet *pkt, void *ofport_, void *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_;
    struct ofport_dpif *ofport = ofport_;
    struct eth_header *eth = dp_packet_l2(pkt);

    netdev_get_etheraddr(ofport->up.netdev, eth->eth_src);
    if (eth_addr_is_zero(eth->eth_src)) {
        VLOG_WARN_RL(&rl, "%s port %d: cannot send RSTP BPDU on a port which "
                     "does not have a configured source MAC address.",
                     ofproto->up.name, ofp_to_u16(ofport->up.ofp_port));
    } else {
        ofproto_dpif_send_packet(ofport, pkt);
    }
    dp_packet_delete(pkt);
}

static void
send_bpdu_cb(struct dp_packet *pkt, int port_num, void *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_;
    struct stp_port *sp = stp_get_port(ofproto->stp, port_num);
    struct ofport_dpif *ofport;

    ofport = stp_port_get_aux(sp);
    if (!ofport) {
        VLOG_WARN_RL(&rl, "%s: cannot send BPDU on unknown port %d",
                     ofproto->up.name, port_num);
    } else {
        struct eth_header *eth = dp_packet_l2(pkt);

        netdev_get_etheraddr(ofport->up.netdev, eth->eth_src);
        if (eth_addr_is_zero(eth->eth_src)) {
            VLOG_WARN_RL(&rl, "%s: cannot send BPDU on port %d "
                         "with unknown MAC", ofproto->up.name, port_num);
        } else {
            ofproto_dpif_send_packet(ofport, pkt);
        }
    }
    dp_packet_delete(pkt);
}

/* Configure RSTP on 'ofproto_' using the settings defined in 's'. */
static void
set_rstp(struct ofproto *ofproto_, const struct ofproto_rstp_settings *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    /* Only revalidate flows if the configuration changed. */
    if (!s != !ofproto->rstp) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
    }

    if (s) {
        if (!ofproto->rstp) {
            ofproto->rstp = rstp_create(ofproto_->name, s->address,
                                        rstp_send_bpdu_cb, ofproto);
            ofproto->rstp_last_tick = time_msec();
        }
        rstp_set_bridge_address(ofproto->rstp, s->address);
        rstp_set_bridge_priority(ofproto->rstp, s->priority);
        rstp_set_bridge_ageing_time(ofproto->rstp, s->ageing_time);
        rstp_set_bridge_force_protocol_version(ofproto->rstp,
                                               s->force_protocol_version);
        rstp_set_bridge_max_age(ofproto->rstp, s->bridge_max_age);
        rstp_set_bridge_forward_delay(ofproto->rstp, s->bridge_forward_delay);
        rstp_set_bridge_transmit_hold_count(ofproto->rstp,
                                            s->transmit_hold_count);
    } else {
        struct ofport *ofport;
        HMAP_FOR_EACH (ofport, hmap_node, &ofproto->up.ports) {
            set_rstp_port(ofport, NULL);
        }
        rstp_unref(ofproto->rstp);
        ofproto->rstp = NULL;
    }
}

static void
get_rstp_status(struct ofproto *ofproto_, struct ofproto_rstp_status *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    if (ofproto->rstp) {
        s->enabled = true;
        s->root_id = rstp_get_root_id(ofproto->rstp);
        s->bridge_id = rstp_get_bridge_id(ofproto->rstp);
        s->designated_id = rstp_get_designated_id(ofproto->rstp);
        s->root_path_cost = rstp_get_root_path_cost(ofproto->rstp);
        s->designated_port_id = rstp_get_designated_port_id(ofproto->rstp);
        s->bridge_port_id = rstp_get_bridge_port_id(ofproto->rstp);
    } else {
        s->enabled = false;
    }
}

static void
update_rstp_port_state(struct ofport_dpif *ofport)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    enum rstp_state state;

    /* Figure out new state. */
    state = ofport->rstp_port ? rstp_port_get_state(ofport->rstp_port)
        : RSTP_DISABLED;

    /* Update state. */
    if (ofport->rstp_state != state) {
        enum ofputil_port_state of_state;
        bool fwd_change;

        VLOG_DBG("port %s: RSTP state changed from %s to %s",
                 netdev_get_name(ofport->up.netdev),
                 rstp_state_name(ofport->rstp_state),
                 rstp_state_name(state));

        if (rstp_learn_in_state(ofport->rstp_state)
            != rstp_learn_in_state(state)) {
            /* XXX: Learning action flows should also be flushed. */
            if (ofport->bundle) {
                if (!rstp_shift_root_learned_address(ofproto->rstp)
                    || rstp_get_old_root_aux(ofproto->rstp) != ofport) {
                    bundle_flush_macs(ofport->bundle, false);
                }
            }
        }
        fwd_change = rstp_forward_in_state(ofport->rstp_state)
            != rstp_forward_in_state(state);

        ofproto->backer->need_revalidate = REV_RSTP;
        ofport->rstp_state = state;

        if (fwd_change && ofport->bundle) {
            bundle_update(ofport->bundle);
        }

        /* Update the RSTP state bits in the OpenFlow port description. */
        of_state = ofport->up.pp.state & ~OFPUTIL_PS_STP_MASK;
        of_state |= (state == RSTP_LEARNING ? OFPUTIL_PS_STP_LEARN
                : state == RSTP_FORWARDING ? OFPUTIL_PS_STP_FORWARD
                : state == RSTP_DISCARDING ?  OFPUTIL_PS_STP_LISTEN
                : 0);
        ofproto_port_set_state(&ofport->up, of_state);
    }
}

static void
rstp_run(struct ofproto_dpif *ofproto)
{
    if (ofproto->rstp) {
        long long int now = time_msec();
        long long int elapsed = now - ofproto->rstp_last_tick;
        struct rstp_port *rp;
        struct ofport_dpif *ofport;

        /* Every second, decrease the values of the timers. */
        if (elapsed >= 1000) {
            rstp_tick_timers(ofproto->rstp);
            ofproto->rstp_last_tick = now;
        }
        rp = NULL;
        while ((ofport = rstp_get_next_changed_port_aux(ofproto->rstp, &rp))) {
            update_rstp_port_state(ofport);
        }
        rp = NULL;
        ofport = NULL;
        /* FIXME: This check should be done on-event (i.e., when setting
         * p->fdb_flush) and not periodically.
         */
        while ((ofport = rstp_check_and_reset_fdb_flush(ofproto->rstp, &rp))) {
            if (!rstp_shift_root_learned_address(ofproto->rstp)
                || rstp_get_old_root_aux(ofproto->rstp) != ofport) {
                bundle_flush_macs(ofport->bundle, false);
            }
        }

        if (rstp_shift_root_learned_address(ofproto->rstp)) {
            bundle_move(((struct ofport_dpif *)rstp_get_old_root_aux(ofproto->rstp))->bundle,
                        ((struct ofport_dpif *)rstp_get_new_root_aux(ofproto->rstp))->bundle);
            rstp_reset_root_changed(ofproto->rstp);
        }
    }
}

/* Configures STP on 'ofproto_' using the settings defined in 's'. */
static int
set_stp(struct ofproto *ofproto_, const struct ofproto_stp_settings *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    /* Only revalidate flows if the configuration changed. */
    if (!s != !ofproto->stp) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
    }

    if (s) {
        if (!ofproto->stp) {
            ofproto->stp = stp_create(ofproto_->name, s->system_id,
                                      send_bpdu_cb, ofproto);
            ofproto->stp_last_tick = time_msec();
        }

        stp_set_bridge_id(ofproto->stp, s->system_id);
        stp_set_bridge_priority(ofproto->stp, s->priority);
        stp_set_hello_time(ofproto->stp, s->hello_time);
        stp_set_max_age(ofproto->stp, s->max_age);
        stp_set_forward_delay(ofproto->stp, s->fwd_delay);
    }  else {
        struct ofport *ofport;

        HMAP_FOR_EACH (ofport, hmap_node, &ofproto->up.ports) {
            set_stp_port(ofport, NULL);
        }

        stp_unref(ofproto->stp);
        ofproto->stp = NULL;
    }

    return 0;
}

static int
get_stp_status(struct ofproto *ofproto_, struct ofproto_stp_status *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    if (ofproto->stp) {
        s->enabled = true;
        s->bridge_id = stp_get_bridge_id(ofproto->stp);
        s->designated_root = stp_get_designated_root(ofproto->stp);
        s->root_path_cost = stp_get_root_path_cost(ofproto->stp);
    } else {
        s->enabled = false;
    }

    return 0;
}

static void
update_stp_port_state(struct ofport_dpif *ofport)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    enum stp_state state;

    /* Figure out new state. */
    state = ofport->stp_port ? stp_port_get_state(ofport->stp_port)
                             : STP_DISABLED;

    /* Update state. */
    if (ofport->stp_state != state) {
        enum ofputil_port_state of_state;
        bool fwd_change;

        VLOG_DBG("port %s: STP state changed from %s to %s",
                 netdev_get_name(ofport->up.netdev),
                 stp_state_name(ofport->stp_state),
                 stp_state_name(state));
        if (stp_learn_in_state(ofport->stp_state)
                != stp_learn_in_state(state)) {
            /* xxx Learning action flows should also be flushed. */
            ovs_rwlock_wrlock(&ofproto->ml->rwlock);
            mac_learning_flush(ofproto->ml);
            ovs_rwlock_unlock(&ofproto->ml->rwlock);
            mcast_snooping_mdb_flush(ofproto->ms);
        }
        fwd_change = stp_forward_in_state(ofport->stp_state)
                        != stp_forward_in_state(state);

        ofproto->backer->need_revalidate = REV_STP;
        ofport->stp_state = state;
        ofport->stp_state_entered = time_msec();

        if (fwd_change && ofport->bundle) {
            bundle_update(ofport->bundle);
        }

        /* Update the STP state bits in the OpenFlow port description. */
        of_state = ofport->up.pp.state & ~OFPUTIL_PS_STP_MASK;
        of_state |= (state == STP_LISTENING ? OFPUTIL_PS_STP_LISTEN
                     : state == STP_LEARNING ? OFPUTIL_PS_STP_LEARN
                     : state == STP_FORWARDING ? OFPUTIL_PS_STP_FORWARD
                     : state == STP_BLOCKING ?  OFPUTIL_PS_STP_BLOCK
                     : 0);
        ofproto_port_set_state(&ofport->up, of_state);
    }
}

/* Configures STP on 'ofport_' using the settings defined in 's'.  The
 * caller is responsible for assigning STP port numbers and ensuring
 * there are no duplicates. */
static int
set_stp_port(struct ofport *ofport_,
             const struct ofproto_port_stp_settings *s)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    struct stp_port *sp = ofport->stp_port;

    if (!s || !s->enable) {
        if (sp) {
            ofport->stp_port = NULL;
            stp_port_disable(sp);
            update_stp_port_state(ofport);
        }
        return 0;
    } else if (sp && stp_port_no(sp) != s->port_num
               && ofport == stp_port_get_aux(sp)) {
        /* The port-id changed, so disable the old one if it's not
         * already in use by another port. */
        stp_port_disable(sp);
    }

    sp = ofport->stp_port = stp_get_port(ofproto->stp, s->port_num);

    /* Set name before enabling the port so that debugging messages can print
     * the name. */
    stp_port_set_name(sp, netdev_get_name(ofport->up.netdev));
    stp_port_enable(sp);

    stp_port_set_aux(sp, ofport);
    stp_port_set_priority(sp, s->priority);
    stp_port_set_path_cost(sp, s->path_cost);

    update_stp_port_state(ofport);

    return 0;
}

static int
get_stp_port_status(struct ofport *ofport_,
                    struct ofproto_port_stp_status *s)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    struct stp_port *sp = ofport->stp_port;

    if (!ofproto->stp || !sp) {
        s->enabled = false;
        return 0;
    }

    s->enabled = true;
    s->port_id = stp_port_get_id(sp);
    s->state = stp_port_get_state(sp);
    s->sec_in_state = (time_msec() - ofport->stp_state_entered) / 1000;
    s->role = stp_port_get_role(sp);

    return 0;
}

static int
get_stp_port_stats(struct ofport *ofport_,
                   struct ofproto_port_stp_stats *s)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    struct stp_port *sp = ofport->stp_port;

    if (!ofproto->stp || !sp) {
        s->enabled = false;
        return 0;
    }

    s->enabled = true;
    stp_port_get_counts(sp, &s->tx_count, &s->rx_count, &s->error_count);

    return 0;
}

static void
stp_run(struct ofproto_dpif *ofproto)
{
    if (ofproto->stp) {
        long long int now = time_msec();
        long long int elapsed = now - ofproto->stp_last_tick;
        struct stp_port *sp;

        if (elapsed > 0) {
            stp_tick(ofproto->stp, MIN(INT_MAX, elapsed));
            ofproto->stp_last_tick = now;
        }
        while (stp_get_changed_port(ofproto->stp, &sp)) {
            struct ofport_dpif *ofport = stp_port_get_aux(sp);

            if (ofport) {
                update_stp_port_state(ofport);
            }
        }

        if (stp_check_and_reset_fdb_flush(ofproto->stp)) {
            ovs_rwlock_wrlock(&ofproto->ml->rwlock);
            mac_learning_flush(ofproto->ml);
            ovs_rwlock_unlock(&ofproto->ml->rwlock);
            mcast_snooping_mdb_flush(ofproto->ms);
        }
    }
}

static void
stp_wait(struct ofproto_dpif *ofproto)
{
    if (ofproto->stp) {
        poll_timer_wait(1000);
    }
}

/* Configures RSTP on 'ofport_' using the settings defined in 's'.  The
 * caller is responsible for assigning RSTP port numbers and ensuring
 * there are no duplicates. */
static void
set_rstp_port(struct ofport *ofport_,
              const struct ofproto_port_rstp_settings *s)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    struct rstp_port *rp = ofport->rstp_port;

    if (!s || !s->enable) {
        if (rp) {
            rstp_port_unref(rp);
            ofport->rstp_port = NULL;
            update_rstp_port_state(ofport);
        }
        return;
    }

    /* Check if need to add a new port. */
    if (!rp) {
        rp = ofport->rstp_port = rstp_add_port(ofproto->rstp);
    }

    rstp_port_set(rp, s->port_num, s->priority, s->path_cost,
                  s->admin_edge_port, s->auto_edge,
                  s->admin_p2p_mac_state, s->admin_port_state, s->mcheck,
                  ofport);
    update_rstp_port_state(ofport);
    /* Synchronize operational status. */
    rstp_port_set_mac_operational(rp, ofport->may_enable);
}

static void
get_rstp_port_status(struct ofport *ofport_,
        struct ofproto_port_rstp_status *s)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    struct rstp_port *rp = ofport->rstp_port;

    if (!ofproto->rstp || !rp) {
        s->enabled = false;
        return;
    }

    s->enabled = true;
    rstp_port_get_status(rp, &s->port_id, &s->state, &s->role,
                         &s->designated_bridge_id, &s->designated_port_id,
                         &s->designated_path_cost, &s->tx_count,
                         &s->rx_count, &s->error_count, &s->uptime);
}


static int
set_queues(struct ofport *ofport_, const struct ofproto_port_queue *qdscp,
           size_t n_qdscp)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);

    if (ofport->n_qdscp != n_qdscp
        || (n_qdscp && memcmp(ofport->qdscp, qdscp,
                              n_qdscp * sizeof *qdscp))) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
        free(ofport->qdscp);
        ofport->qdscp = n_qdscp
            ? xmemdup(qdscp, n_qdscp * sizeof *qdscp)
            : NULL;
        ofport->n_qdscp = n_qdscp;
    }

    return 0;
}

/* Bundles. */

/* Expires all MAC learning entries associated with 'bundle' and forces its
 * ofproto to revalidate every flow.
 *
 * Normally MAC learning entries are removed only from the ofproto associated
 * with 'bundle', but if 'all_ofprotos' is true, then the MAC learning entries
 * are removed from every ofproto.  When patch ports and SLB bonds are in use
 * and a VM migration happens and the gratuitous ARPs are somehow lost, this
 * avoids a MAC_ENTRY_IDLE_TIME delay before the migrated VM can communicate
 * with the host from which it migrated. */
static void
bundle_flush_macs(struct ofbundle *bundle, bool all_ofprotos)
{
    struct ofproto_dpif *ofproto = bundle->ofproto;
    struct mac_learning *ml = ofproto->ml;
    struct mac_entry *mac, *next_mac;

    ofproto->backer->need_revalidate = REV_RECONFIGURE;
    ovs_rwlock_wrlock(&ml->rwlock);
    LIST_FOR_EACH_SAFE (mac, next_mac, lru_node, &ml->lrus) {
        if (mac_entry_get_port(ml, mac) == bundle) {
            if (all_ofprotos) {
                struct ofproto_dpif *o;

                HMAP_FOR_EACH (o, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
                    if (o != ofproto) {
                        struct mac_entry *e;

                        ovs_rwlock_wrlock(&o->ml->rwlock);
                        e = mac_learning_lookup(o->ml, mac->mac, mac->vlan);
                        if (e) {
                            mac_learning_expire(o->ml, e);
                        }
                        ovs_rwlock_unlock(&o->ml->rwlock);
                    }
                }
            }

            mac_learning_expire(ml, mac);
        }
    }
    ovs_rwlock_unlock(&ml->rwlock);
}

static void
bundle_move(struct ofbundle *old, struct ofbundle *new)
{
    struct ofproto_dpif *ofproto = old->ofproto;
    struct mac_learning *ml = ofproto->ml;
    struct mac_entry *mac, *next_mac;

    ovs_assert(new->ofproto == old->ofproto);

    ofproto->backer->need_revalidate = REV_RECONFIGURE;
    ovs_rwlock_wrlock(&ml->rwlock);
    LIST_FOR_EACH_SAFE (mac, next_mac, lru_node, &ml->lrus) {
        if (mac_entry_get_port(ml, mac) == old) {
            mac_entry_set_port(ml, mac, new);
        }
    }
    ovs_rwlock_unlock(&ml->rwlock);
}

static struct ofbundle *
bundle_lookup(const struct ofproto_dpif *ofproto, void *aux)
{
    struct ofbundle *bundle;

    HMAP_FOR_EACH_IN_BUCKET (bundle, hmap_node, hash_pointer(aux, 0),
                             &ofproto->bundles) {
        if (bundle->aux == aux) {
            return bundle;
        }
    }
    return NULL;
}

static void
bundle_update(struct ofbundle *bundle)
{
    struct ofport_dpif *port;

    bundle->floodable = true;
    LIST_FOR_EACH (port, bundle_node, &bundle->ports) {
        if (port->up.pp.config & OFPUTIL_PC_NO_FLOOD
            || port->is_layer3
            || (bundle->ofproto->stp && !stp_forward_in_state(port->stp_state))
            || (bundle->ofproto->rstp && !rstp_forward_in_state(port->rstp_state))) {
            bundle->floodable = false;
            break;
        }
    }
}

static void
bundle_del_port(struct ofport_dpif *port)
{
    struct ofbundle *bundle = port->bundle;

    bundle->ofproto->backer->need_revalidate = REV_RECONFIGURE;

    list_remove(&port->bundle_node);
    port->bundle = NULL;

    if (bundle->lacp) {
        lacp_slave_unregister(bundle->lacp, port);
    }
    if (bundle->bond) {
        bond_slave_unregister(bundle->bond, port);
    }

    bundle_update(bundle);
}

static bool
bundle_add_port(struct ofbundle *bundle, ofp_port_t ofp_port,
                struct lacp_slave_settings *lacp)
{
    struct ofport_dpif *port;

    port = ofp_port_to_ofport(bundle->ofproto, ofp_port);
    if (!port) {
        return false;
    }

    if (port->bundle != bundle) {
        bundle->ofproto->backer->need_revalidate = REV_RECONFIGURE;
        if (port->bundle) {
            bundle_remove(&port->up);
        }

        port->bundle = bundle;
        list_push_back(&bundle->ports, &port->bundle_node);
        if (port->up.pp.config & OFPUTIL_PC_NO_FLOOD
            || port->is_layer3
            || (bundle->ofproto->stp && !stp_forward_in_state(port->stp_state))
            || (bundle->ofproto->rstp && !rstp_forward_in_state(port->rstp_state))) {
            bundle->floodable = false;
        }
    }
    if (lacp) {
        bundle->ofproto->backer->need_revalidate = REV_RECONFIGURE;
        lacp_slave_register(bundle->lacp, port, lacp);
    }

    return true;
}

static void
bundle_destroy(struct ofbundle *bundle)
{
    struct ofproto_dpif *ofproto;
    struct ofport_dpif *port, *next_port;

    if (!bundle) {
        return;
    }

    ofproto = bundle->ofproto;
    mbridge_unregister_bundle(ofproto->mbridge, bundle);

    xlate_txn_start();
    xlate_bundle_remove(bundle);
    xlate_txn_commit();

    LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
        bundle_del_port(port);
    }

    bundle_flush_macs(bundle, true);
    hmap_remove(&ofproto->bundles, &bundle->hmap_node);
    free(bundle->name);
    free(bundle->trunks);
    lacp_unref(bundle->lacp);
    bond_unref(bundle->bond);
    free(bundle);
}

static int
bundle_set(struct ofproto *ofproto_, void *aux,
           const struct ofproto_bundle_settings *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    bool need_flush = false;
    struct ofport_dpif *port;
    struct ofbundle *bundle;
    unsigned long *trunks;
    int vlan;
    size_t i;
    bool ok;

    if (!s) {
        bundle_destroy(bundle_lookup(ofproto, aux));
        return 0;
    }

    ovs_assert(s->n_slaves == 1 || s->bond != NULL);
    ovs_assert((s->lacp != NULL) == (s->lacp_slaves != NULL));

    bundle = bundle_lookup(ofproto, aux);
    if (!bundle) {
        bundle = xmalloc(sizeof *bundle);

        bundle->ofproto = ofproto;
        hmap_insert(&ofproto->bundles, &bundle->hmap_node,
                    hash_pointer(aux, 0));
        bundle->aux = aux;
        bundle->name = NULL;

        list_init(&bundle->ports);
        bundle->vlan_mode = PORT_VLAN_TRUNK;
        bundle->vlan = -1;
        bundle->trunks = NULL;
        bundle->use_priority_tags = s->use_priority_tags;
        bundle->lacp = NULL;
        bundle->bond = NULL;

        bundle->floodable = true;
        mbridge_register_bundle(ofproto->mbridge, bundle);
    }

    if (!bundle->name || strcmp(s->name, bundle->name)) {
        free(bundle->name);
        bundle->name = xstrdup(s->name);
    }

    /* LACP. */
    if (s->lacp) {
        ofproto->lacp_enabled = true;
        if (!bundle->lacp) {
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
            bundle->lacp = lacp_create();
        }
        lacp_configure(bundle->lacp, s->lacp);
    } else {
        lacp_unref(bundle->lacp);
        bundle->lacp = NULL;
    }

    /* Update set of ports. */
    ok = true;
    for (i = 0; i < s->n_slaves; i++) {
        if (!bundle_add_port(bundle, s->slaves[i],
                             s->lacp ? &s->lacp_slaves[i] : NULL)) {
            ok = false;
        }
    }
    if (!ok || list_size(&bundle->ports) != s->n_slaves) {
        struct ofport_dpif *next_port;

        LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
            for (i = 0; i < s->n_slaves; i++) {
                if (s->slaves[i] == port->up.ofp_port) {
                    goto found;
                }
            }

            bundle_del_port(port);
        found: ;
        }
    }
    ovs_assert(list_size(&bundle->ports) <= s->n_slaves);

    if (list_is_empty(&bundle->ports)) {
        bundle_destroy(bundle);
        return EINVAL;
    }

    /* Set VLAN tagging mode */
    if (s->vlan_mode != bundle->vlan_mode
        || s->use_priority_tags != bundle->use_priority_tags) {
        bundle->vlan_mode = s->vlan_mode;
        bundle->use_priority_tags = s->use_priority_tags;
        need_flush = true;
    }

    /* Set VLAN tag. */
    vlan = (s->vlan_mode == PORT_VLAN_TRUNK ? -1
            : s->vlan >= 0 && s->vlan <= 4095 ? s->vlan
            : 0);
    if (vlan != bundle->vlan) {
        bundle->vlan = vlan;
        need_flush = true;
    }

    /* Get trunked VLANs. */
    switch (s->vlan_mode) {
    case PORT_VLAN_ACCESS:
        trunks = NULL;
        break;

    case PORT_VLAN_TRUNK:
        trunks = CONST_CAST(unsigned long *, s->trunks);
        break;

    case PORT_VLAN_NATIVE_UNTAGGED:
    case PORT_VLAN_NATIVE_TAGGED:
        if (vlan != 0 && (!s->trunks
                          || !bitmap_is_set(s->trunks, vlan)
                          || bitmap_is_set(s->trunks, 0))) {
            /* Force trunking the native VLAN and prohibit trunking VLAN 0. */
            if (s->trunks) {
                trunks = bitmap_clone(s->trunks, 4096);
            } else {
                trunks = bitmap_allocate1(4096);
            }
            bitmap_set1(trunks, vlan);
            bitmap_set0(trunks, 0);
        } else {
            trunks = CONST_CAST(unsigned long *, s->trunks);
        }
        break;

    default:
        OVS_NOT_REACHED();
    }
    if (!vlan_bitmap_equal(trunks, bundle->trunks)) {
        free(bundle->trunks);
        if (trunks == s->trunks) {
            bundle->trunks = vlan_bitmap_clone(trunks);
        } else {
            bundle->trunks = trunks;
            trunks = NULL;
        }
        need_flush = true;
    }
    if (trunks != s->trunks) {
        free(trunks);
    }

    /* Bonding. */
    if (!list_is_short(&bundle->ports)) {
        bundle->ofproto->has_bonded_bundles = true;
        if (bundle->bond) {
            if (bond_reconfigure(bundle->bond, s->bond)) {
                ofproto->backer->need_revalidate = REV_RECONFIGURE;
            }
        } else {
            bundle->bond = bond_create(s->bond, ofproto);
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
        }

        LIST_FOR_EACH (port, bundle_node, &bundle->ports) {
            bond_slave_register(bundle->bond, port,
                                port->up.ofp_port, port->up.netdev);
        }
    } else {
        bond_unref(bundle->bond);
        bundle->bond = NULL;
    }

    /* If we changed something that would affect MAC learning, un-learn
     * everything on this port and force flow revalidation. */
    if (need_flush) {
        bundle_flush_macs(bundle, false);
    }

    return 0;
}

static void
bundle_remove(struct ofport *port_)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    struct ofbundle *bundle = port->bundle;

    if (bundle) {
        bundle_del_port(port);
        if (list_is_empty(&bundle->ports)) {
            bundle_destroy(bundle);
        } else if (list_is_short(&bundle->ports)) {
            bond_unref(bundle->bond);
            bundle->bond = NULL;
        }
    }
}

static void
send_pdu_cb(void *port_, const void *pdu, size_t pdu_size)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 10);
    struct ofport_dpif *port = port_;
    uint8_t ea[ETH_ADDR_LEN];
    int error;

    error = netdev_get_etheraddr(port->up.netdev, ea);
    if (!error) {
        struct dp_packet packet;
        void *packet_pdu;

        dp_packet_init(&packet, 0);
        packet_pdu = eth_compose(&packet, eth_addr_lacp, ea, ETH_TYPE_LACP,
                                 pdu_size);
        memcpy(packet_pdu, pdu, pdu_size);

        ofproto_dpif_send_packet(port, &packet);
        dp_packet_uninit(&packet);
    } else {
        VLOG_ERR_RL(&rl, "port %s: cannot obtain Ethernet address of iface "
                    "%s (%s)", port->bundle->name,
                    netdev_get_name(port->up.netdev), ovs_strerror(error));
    }
}

static void
bundle_send_learning_packets(struct ofbundle *bundle)
{
    struct ofproto_dpif *ofproto = bundle->ofproto;
    int error, n_packets, n_errors;
    struct mac_entry *e;
    struct pkt_list {
        struct ovs_list list_node;
        struct ofport_dpif *port;
        struct dp_packet *pkt;
    } *pkt_node;
    struct ovs_list packets;

    list_init(&packets);
    ovs_rwlock_rdlock(&ofproto->ml->rwlock);
    LIST_FOR_EACH (e, lru_node, &ofproto->ml->lrus) {
        if (mac_entry_get_port(ofproto->ml, e) != bundle) {
            pkt_node = xmalloc(sizeof *pkt_node);
            pkt_node->pkt = bond_compose_learning_packet(bundle->bond,
                                                         e->mac, e->vlan,
                                                         (void **)&pkt_node->port);
            list_push_back(&packets, &pkt_node->list_node);
        }
    }
    ovs_rwlock_unlock(&ofproto->ml->rwlock);

    error = n_packets = n_errors = 0;
    LIST_FOR_EACH_POP (pkt_node, list_node, &packets) {
        int ret;

        ret = ofproto_dpif_send_packet(pkt_node->port, pkt_node->pkt);
        dp_packet_delete(pkt_node->pkt);
        free(pkt_node);
        if (ret) {
            error = ret;
            n_errors++;
        }
        n_packets++;
    }

    if (n_errors) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bond %s: %d errors sending %d gratuitous learning "
                     "packets, last error was: %s",
                     bundle->name, n_errors, n_packets, ovs_strerror(error));
    } else {
        VLOG_DBG("bond %s: sent %d gratuitous learning packets",
                 bundle->name, n_packets);
    }
}

static void
bundle_run(struct ofbundle *bundle)
{
    if (bundle->lacp) {
        lacp_run(bundle->lacp, send_pdu_cb);
    }
    if (bundle->bond) {
        struct ofport_dpif *port;

        LIST_FOR_EACH (port, bundle_node, &bundle->ports) {
            bond_slave_set_may_enable(bundle->bond, port, port->may_enable);
        }

        if (bond_run(bundle->bond, lacp_status(bundle->lacp))) {
            bundle->ofproto->backer->need_revalidate = REV_BOND;
        }

        if (bond_should_send_learning_packets(bundle->bond)) {
            bundle_send_learning_packets(bundle);
        }
    }
}

static void
bundle_wait(struct ofbundle *bundle)
{
    if (bundle->lacp) {
        lacp_wait(bundle->lacp);
    }
    if (bundle->bond) {
        bond_wait(bundle->bond);
    }
}

/* Mirrors. */

static int
mirror_set__(struct ofproto *ofproto_, void *aux,
             const struct ofproto_mirror_settings *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofbundle **srcs, **dsts;
    int error;
    size_t i;

    if (!s) {
        mirror_destroy(ofproto->mbridge, aux);
        return 0;
    }

    srcs = xmalloc(s->n_srcs * sizeof *srcs);
    dsts = xmalloc(s->n_dsts * sizeof *dsts);

    for (i = 0; i < s->n_srcs; i++) {
        srcs[i] = bundle_lookup(ofproto, s->srcs[i]);
    }

    for (i = 0; i < s->n_dsts; i++) {
        dsts[i] = bundle_lookup(ofproto, s->dsts[i]);
    }

    error = mirror_set(ofproto->mbridge, aux, s->name, srcs, s->n_srcs, dsts,
                       s->n_dsts, s->src_vlans,
                       bundle_lookup(ofproto, s->out_bundle), s->out_vlan);
    free(srcs);
    free(dsts);
    return error;
}

static int
mirror_get_stats__(struct ofproto *ofproto, void *aux,
                   uint64_t *packets, uint64_t *bytes)
{
    return mirror_get_stats(ofproto_dpif_cast(ofproto)->mbridge, aux, packets,
                            bytes);
}

static int
set_flood_vlans(struct ofproto *ofproto_, unsigned long *flood_vlans)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    ovs_rwlock_wrlock(&ofproto->ml->rwlock);
    if (mac_learning_set_flood_vlans(ofproto->ml, flood_vlans)) {
        mac_learning_flush(ofproto->ml);
    }
    ovs_rwlock_unlock(&ofproto->ml->rwlock);
    return 0;
}

static bool
is_mirror_output_bundle(const struct ofproto *ofproto_, void *aux)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofbundle *bundle = bundle_lookup(ofproto, aux);
    return bundle && mirror_bundle_out(ofproto->mbridge, bundle) != 0;
}

static void
forward_bpdu_changed(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    ofproto->backer->need_revalidate = REV_RECONFIGURE;
}

static void
set_mac_table_config(struct ofproto *ofproto_, unsigned int idle_time,
                     size_t max_entries)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    ovs_rwlock_wrlock(&ofproto->ml->rwlock);
    mac_learning_set_idle_time(ofproto->ml, idle_time);
    mac_learning_set_max_entries(ofproto->ml, max_entries);
    ovs_rwlock_unlock(&ofproto->ml->rwlock);
}

/* Configures multicast snooping on 'ofport' using the settings
 * defined in 's'. */
static int
set_mcast_snooping(struct ofproto *ofproto_,
                   const struct ofproto_mcast_snooping_settings *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    /* Only revalidate flows if the configuration changed. */
    if (!s != !ofproto->ms) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
    }

    if (s) {
        if (!ofproto->ms) {
            ofproto->ms = mcast_snooping_create();
        }

        ovs_rwlock_wrlock(&ofproto->ms->rwlock);
        mcast_snooping_set_idle_time(ofproto->ms, s->idle_time);
        mcast_snooping_set_max_entries(ofproto->ms, s->max_entries);
        if (mcast_snooping_set_flood_unreg(ofproto->ms, s->flood_unreg)) {
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
        }
        ovs_rwlock_unlock(&ofproto->ms->rwlock);
    } else {
        mcast_snooping_unref(ofproto->ms);
        ofproto->ms = NULL;
    }

    return 0;
}

/* Configures multicast snooping port's flood settings on 'ofproto'. */
static int
set_mcast_snooping_port(struct ofproto *ofproto_, void *aux,
                        const struct ofproto_mcast_snooping_port_settings *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofbundle *bundle = bundle_lookup(ofproto, aux);

    if (ofproto->ms && s) {
        ovs_rwlock_wrlock(&ofproto->ms->rwlock);
        mcast_snooping_set_port_flood(ofproto->ms, bundle, s->flood);
        mcast_snooping_set_port_flood_reports(ofproto->ms, bundle,
                                              s->flood_reports);
        ovs_rwlock_unlock(&ofproto->ms->rwlock);
    }
    return 0;
}


/* Ports. */

struct ofport_dpif *
ofp_port_to_ofport(const struct ofproto_dpif *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(&ofproto->up, ofp_port);
    return ofport ? ofport_dpif_cast(ofport) : NULL;
}

static void
ofproto_port_from_dpif_port(struct ofproto_dpif *ofproto,
                            struct ofproto_port *ofproto_port,
                            struct dpif_port *dpif_port)
{
    ofproto_port->name = dpif_port->name;
    ofproto_port->type = dpif_port->type;
    ofproto_port->ofp_port = odp_port_to_ofp_port(ofproto, dpif_port->port_no);
}

static void
ofport_update_peer(struct ofport_dpif *ofport)
{
    const struct ofproto_dpif *ofproto;
    struct dpif_backer *backer;
    char *peer_name;

    if (!netdev_vport_is_patch(ofport->up.netdev)) {
        return;
    }

    backer = ofproto_dpif_cast(ofport->up.ofproto)->backer;
    backer->need_revalidate = REV_RECONFIGURE;

    if (ofport->peer) {
        ofport->peer->peer = NULL;
        ofport->peer = NULL;
    }

    peer_name = netdev_vport_patch_peer(ofport->up.netdev);
    if (!peer_name) {
        return;
    }

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
        struct ofport *peer_ofport;
        struct ofport_dpif *peer;
        char *peer_peer;

        if (ofproto->backer != backer) {
            continue;
        }

        peer_ofport = shash_find_data(&ofproto->up.port_by_name, peer_name);
        if (!peer_ofport) {
            continue;
        }

        peer = ofport_dpif_cast(peer_ofport);
        peer_peer = netdev_vport_patch_peer(peer->up.netdev);
        if (peer_peer && !strcmp(netdev_get_name(ofport->up.netdev),
                                 peer_peer)) {
            ofport->peer = peer;
            ofport->peer->peer = ofport;
        }
        free(peer_peer);

        break;
    }
    free(peer_name);
}

static void
port_run(struct ofport_dpif *ofport)
{
    long long int carrier_seq = netdev_get_carrier_resets(ofport->up.netdev);
    bool carrier_changed = carrier_seq != ofport->carrier_seq;
    bool enable = netdev_get_carrier(ofport->up.netdev);
    bool cfm_enable = false;
    bool bfd_enable = false;

    ofport->carrier_seq = carrier_seq;

    if (ofport->cfm) {
        int cfm_opup = cfm_get_opup(ofport->cfm);

        cfm_enable = !cfm_get_fault(ofport->cfm);

        if (cfm_opup >= 0) {
            cfm_enable = cfm_enable && cfm_opup;
        }
    }

    if (ofport->bfd) {
        bfd_enable = bfd_forwarding(ofport->bfd);
    }

    if (ofport->bfd || ofport->cfm) {
        enable = enable && (cfm_enable || bfd_enable);
    }

    if (ofport->bundle) {
        enable = enable && lacp_slave_may_enable(ofport->bundle->lacp, ofport);
        if (carrier_changed) {
            lacp_slave_carrier_changed(ofport->bundle->lacp, ofport);
        }
    }

    if (ofport->may_enable != enable) {
        struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);

        ofproto->backer->need_revalidate = REV_PORT_TOGGLED;

        if (ofport->rstp_port) {
            rstp_port_set_mac_operational(ofport->rstp_port, enable);
        }
    }

    ofport->may_enable = enable;
}

static int
port_query_by_name(const struct ofproto *ofproto_, const char *devname,
                   struct ofproto_port *ofproto_port)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_port dpif_port;
    int error;

    if (sset_contains(&ofproto->ghost_ports, devname)) {
        const char *type = netdev_get_type_from_name(devname);

        /* We may be called before ofproto->up.port_by_name is populated with
         * the appropriate ofport.  For this reason, we must get the name and
         * type from the netdev layer directly. */
        if (type) {
            const struct ofport *ofport;

            ofport = shash_find_data(&ofproto->up.port_by_name, devname);
            ofproto_port->ofp_port = ofport ? ofport->ofp_port : OFPP_NONE;
            ofproto_port->name = xstrdup(devname);
            ofproto_port->type = xstrdup(type);
            return 0;
        }
        return ENODEV;
    }

    if (!sset_contains(&ofproto->ports, devname)) {
        return ENODEV;
    }
    error = dpif_port_query_by_name(ofproto->backer->dpif,
                                    devname, &dpif_port);
    if (!error) {
        ofproto_port_from_dpif_port(ofproto, ofproto_port, &dpif_port);
    }
    return error;
}

static int
port_add(struct ofproto *ofproto_, struct netdev *netdev)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    const char *devname = netdev_get_name(netdev);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dp_port_name;

    if (netdev_vport_is_patch(netdev)) {
        sset_add(&ofproto->ghost_ports, netdev_get_name(netdev));
        return 0;
    }

    dp_port_name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (!dpif_port_exists(ofproto->backer->dpif, dp_port_name)) {
        odp_port_t port_no = ODPP_NONE;
        int error;

        error = dpif_port_add(ofproto->backer->dpif, netdev, &port_no);
        if (error) {
            return error;
        }
        if (netdev_get_tunnel_config(netdev)) {
            simap_put(&ofproto->backer->tnl_backers,
                      dp_port_name, odp_to_u32(port_no));
        }
    }

    if (netdev_get_tunnel_config(netdev)) {
        sset_add(&ofproto->ghost_ports, devname);
    } else {
        sset_add(&ofproto->ports, devname);
    }
    return 0;
}

static int
port_del(struct ofproto *ofproto_, ofp_port_t ofp_port)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofport_dpif *ofport = ofp_port_to_ofport(ofproto, ofp_port);
    int error = 0;

    if (!ofport) {
        return 0;
    }

    sset_find_and_delete(&ofproto->ghost_ports,
                         netdev_get_name(ofport->up.netdev));
    ofproto->backer->need_revalidate = REV_RECONFIGURE;
    if (!ofport->is_tunnel && !netdev_vport_is_patch(ofport->up.netdev)) {
        error = dpif_port_del(ofproto->backer->dpif, ofport->odp_port);
        if (!error) {
            /* The caller is going to close ofport->up.netdev.  If this is a
             * bonded port, then the bond is using that netdev, so remove it
             * from the bond.  The client will need to reconfigure everything
             * after deleting ports, so then the slave will get re-added. */
            bundle_remove(&ofport->up);
        }
    }
    return error;
}

static int
port_get_stats(const struct ofport *ofport_, struct netdev_stats *stats)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    int error;

    error = netdev_get_stats(ofport->up.netdev, stats);

    if (!error && ofport_->ofp_port == OFPP_LOCAL) {
        struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);

        ovs_mutex_lock(&ofproto->stats_mutex);
        /* ofproto->stats.tx_packets represents packets that we created
         * internally and sent to some port (e.g. packets sent with
         * ofproto_dpif_send_packet()).  Account for them as if they had
         * come from OFPP_LOCAL and got forwarded. */

        if (stats->rx_packets != UINT64_MAX) {
            stats->rx_packets += ofproto->stats.tx_packets;
        }

        if (stats->rx_bytes != UINT64_MAX) {
            stats->rx_bytes += ofproto->stats.tx_bytes;
        }

        /* ofproto->stats.rx_packets represents packets that were received on
         * some port and we processed internally and dropped (e.g. STP).
         * Account for them as if they had been forwarded to OFPP_LOCAL. */

        if (stats->tx_packets != UINT64_MAX) {
            stats->tx_packets += ofproto->stats.rx_packets;
        }

        if (stats->tx_bytes != UINT64_MAX) {
            stats->tx_bytes += ofproto->stats.rx_bytes;
        }
        ovs_mutex_unlock(&ofproto->stats_mutex);
    }

    return error;
}

static int
port_get_lacp_stats(const struct ofport *ofport_, struct lacp_slave_stats *stats)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    if (ofport->bundle && ofport->bundle->lacp) {
        if (lacp_get_slave_stats(ofport->bundle->lacp, ofport, stats)) {
            return 0;
        }
    }
    return -1;
}

struct port_dump_state {
    uint32_t bucket;
    uint32_t offset;
    bool ghost;

    struct ofproto_port port;
    bool has_port;
};

static int
port_dump_start(const struct ofproto *ofproto_ OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct port_dump_state));
    return 0;
}

static int
port_dump_next(const struct ofproto *ofproto_, void *state_,
               struct ofproto_port *port)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct port_dump_state *state = state_;
    const struct sset *sset;
    struct sset_node *node;

    if (state->has_port) {
        ofproto_port_destroy(&state->port);
        state->has_port = false;
    }
    sset = state->ghost ? &ofproto->ghost_ports : &ofproto->ports;
    while ((node = sset_at_position(sset, &state->bucket, &state->offset))) {
        int error;

        error = port_query_by_name(ofproto_, node->name, &state->port);
        if (!error) {
            *port = state->port;
            state->has_port = true;
            return 0;
        } else if (error != ENODEV) {
            return error;
        }
    }

    if (!state->ghost) {
        state->ghost = true;
        state->bucket = 0;
        state->offset = 0;
        return port_dump_next(ofproto_, state_, port);
    }

    return EOF;
}

static int
port_dump_done(const struct ofproto *ofproto_ OVS_UNUSED, void *state_)
{
    struct port_dump_state *state = state_;

    if (state->has_port) {
        ofproto_port_destroy(&state->port);
    }
    free(state);
    return 0;
}

static int
port_poll(const struct ofproto *ofproto_, char **devnamep)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    if (ofproto->port_poll_errno) {
        int error = ofproto->port_poll_errno;
        ofproto->port_poll_errno = 0;
        return error;
    }

    if (sset_is_empty(&ofproto->port_poll_set)) {
        return EAGAIN;
    }

    *devnamep = sset_pop(&ofproto->port_poll_set);
    return 0;
}

static void
port_poll_wait(const struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    dpif_port_poll_wait(ofproto->backer->dpif);
}

static int
port_is_lacp_current(const struct ofport *ofport_)
{
    const struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    return (ofport->bundle && ofport->bundle->lacp
            ? lacp_slave_is_current(ofport->bundle->lacp, ofport)
            : -1);
}

/* If 'rule' is an OpenFlow rule, that has expired according to OpenFlow rules,
 * then delete it entirely. */
static void
rule_expire(struct rule_dpif *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    uint16_t hard_timeout, idle_timeout;
    long long int now = time_msec();
    int reason = -1;

    hard_timeout = rule->up.hard_timeout;
    idle_timeout = rule->up.idle_timeout;

    /* Has 'rule' expired? */
    if (hard_timeout) {
        long long int modified;

        ovs_mutex_lock(&rule->up.mutex);
        modified = rule->up.modified;
        ovs_mutex_unlock(&rule->up.mutex);

        if (now > modified + hard_timeout * 1000) {
            reason = OFPRR_HARD_TIMEOUT;
        }
    }

    if (reason < 0 && idle_timeout) {
        long long int used;

        ovs_mutex_lock(&rule->stats_mutex);
        used = rule->stats.used;
        ovs_mutex_unlock(&rule->stats_mutex);

        if (now > used + idle_timeout * 1000) {
            reason = OFPRR_IDLE_TIMEOUT;
        }
    }

    if (reason >= 0) {
        COVERAGE_INC(ofproto_dpif_expired);
        ofproto_rule_expire(&rule->up, reason);
    }
}

/* Executes, within 'ofproto', the actions in 'rule' or 'ofpacts' on 'packet'.
 * 'flow' must reflect the data in 'packet'. */
int
ofproto_dpif_execute_actions(struct ofproto_dpif *ofproto,
                             const struct flow *flow,
                             struct rule_dpif *rule,
                             const struct ofpact *ofpacts, size_t ofpacts_len,
                             struct dp_packet *packet)
{
    struct dpif_flow_stats stats;
    struct xlate_out xout;
    struct xlate_in xin;
    ofp_port_t in_port;
    struct dpif_execute execute;
    int error;

    ovs_assert((rule != NULL) != (ofpacts != NULL));

    dpif_flow_stats_extract(flow, packet, time_msec(), &stats);

    if (rule) {
        rule_dpif_credit_stats(rule, &stats);
    }

    xlate_in_init(&xin, ofproto, flow, flow->in_port.ofp_port, rule,
                  stats.tcp_flags, packet);
    xin.ofpacts = ofpacts;
    xin.ofpacts_len = ofpacts_len;
    xin.resubmit_stats = &stats;
    xlate_actions(&xin, &xout);

    execute.actions = xout.odp_actions->data;
    execute.actions_len = xout.odp_actions->size;

    pkt_metadata_from_flow(&packet->md, flow);
    execute.packet = packet;
    execute.needs_help = (xout.slow & SLOW_ACTION) != 0;
    execute.probe = false;

    /* Fix up in_port. */
    in_port = flow->in_port.ofp_port;
    if (in_port == OFPP_NONE) {
        in_port = OFPP_LOCAL;
    }
    execute.packet->md.in_port.odp_port = ofp_port_to_odp_port(ofproto, in_port);

    error = dpif_execute(ofproto->backer->dpif, &execute);

    xlate_out_uninit(&xout);

    return error;
}

void
rule_dpif_credit_stats(struct rule_dpif *rule,
                       const struct dpif_flow_stats *stats)
{
    ovs_mutex_lock(&rule->stats_mutex);
    rule->stats.n_packets += stats->n_packets;
    rule->stats.n_bytes += stats->n_bytes;
    rule->stats.used = MAX(rule->stats.used, stats->used);
    ovs_mutex_unlock(&rule->stats_mutex);
}

ovs_be64
rule_dpif_get_flow_cookie(const struct rule_dpif *rule)
    OVS_REQUIRES(rule->up.mutex)
{
    return rule->up.flow_cookie;
}

void
rule_dpif_reduce_timeouts(struct rule_dpif *rule, uint16_t idle_timeout,
                     uint16_t hard_timeout)
{
    ofproto_rule_reduce_timeouts(&rule->up, idle_timeout, hard_timeout);
}

/* Returns 'rule''s actions.  The returned actions are RCU-protected, and can
 * be read until the calling thread quiesces. */
const struct rule_actions *
rule_dpif_get_actions(const struct rule_dpif *rule)
{
    return rule_get_actions(&rule->up);
}

/* Sets 'rule''s recirculation id. */
static void
rule_dpif_set_recirc_id(struct rule_dpif *rule, uint32_t id)
    OVS_REQUIRES(rule->up.mutex)
{
    ovs_assert(!rule->recirc_id || rule->recirc_id == id);
    if (rule->recirc_id == id) {
        /* Release the new reference to the same id. */
        recirc_free_id(id);
    } else {
        rule->recirc_id = id;
    }
}

/* Sets 'rule''s recirculation id. */
void
rule_set_recirc_id(struct rule *rule_, uint32_t id)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);

    ovs_mutex_lock(&rule->up.mutex);
    rule_dpif_set_recirc_id(rule, id);
    ovs_mutex_unlock(&rule->up.mutex);
}

/* The returned rule (if any) is valid at least until the next RCU quiescent
 * period.  If the rule needs to stay around longer, a non-zero 'take_ref'
 * must be passed in to cause a reference to be taken on it.
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
static struct rule_dpif *
rule_dpif_lookup_in_table(struct ofproto_dpif *ofproto, uint8_t table_id,
                          struct flow *flow, struct flow_wildcards *wc,
                          bool take_ref)
{
    struct classifier *cls = &ofproto->up.tables[table_id].cls;
    const struct cls_rule *cls_rule;
    struct rule_dpif *rule;

    do {
        cls_rule = classifier_lookup(cls, flow, wc);

        rule = rule_dpif_cast(rule_from_cls_rule(cls_rule));

        /* Try again if the rule was released before we get the reference. */
    } while (rule && take_ref && !rule_dpif_try_ref(rule));

    return rule;
}

/* Look up 'flow' in 'ofproto''s classifier starting from table '*table_id'.
 * Returns the rule that was found, which may be one of the special rules
 * according to packet miss hadling.  If 'may_packet_in' is false, returning of
 * the miss_rule (which issues packet ins for the controller) is avoided.
 * Updates 'wc', if nonnull, to reflect the fields that were used during the
 * lookup.
 *
 * If 'honor_table_miss' is true, the first lookup occurs in '*table_id', but
 * if none is found then the table miss configuration for that table is
 * honored, which can result in additional lookups in other OpenFlow tables.
 * In this case the function updates '*table_id' to reflect the final OpenFlow
 * table that was searched.
 *
 * If 'honor_table_miss' is false, then only one table lookup occurs, in
 * '*table_id'.
 *
 * The rule is returned in '*rule', which is valid at least until the next
 * RCU quiescent period.  If the '*rule' needs to stay around longer,
 * a non-zero 'take_ref' must be passed in to cause a reference to be taken
 * on it before this returns.
 *
 * 'in_port' allows the lookup to take place as if the in port had the value
 * 'in_port'.  This is needed for resubmit action support.
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
struct rule_dpif *
rule_dpif_lookup_from_table(struct ofproto_dpif *ofproto, struct flow *flow,
                            struct flow_wildcards *wc, bool take_ref,
                            const struct dpif_flow_stats *stats,
                            uint8_t *table_id, ofp_port_t in_port,
                            bool may_packet_in, bool honor_table_miss)
{
    ovs_be16 old_tp_src = flow->tp_src, old_tp_dst = flow->tp_dst;
    ofp_port_t old_in_port = flow->in_port.ofp_port;
    enum ofputil_table_miss miss_config;
    struct rule_dpif *rule;
    uint8_t next_id;

    /* We always unwildcard nw_frag (for IP), so they
     * need not be unwildcarded here. */
    if (flow->nw_frag & FLOW_NW_FRAG_ANY
        && ofproto->up.frag_handling != OFPC_FRAG_NX_MATCH) {
        if (ofproto->up.frag_handling == OFPC_FRAG_NORMAL) {
            /* We must pretend that transport ports are unavailable. */
            flow->tp_src = htons(0);
            flow->tp_dst = htons(0);
        } else {
            /* Must be OFPC_FRAG_DROP (we don't have OFPC_FRAG_REASM).
             * Use the drop_frags_rule (which cannot disappear). */
            rule = ofproto->drop_frags_rule;
            if (take_ref) {
                rule_dpif_ref(rule);
            }
            if (stats) {
                struct oftable *tbl = &ofproto->up.tables[*table_id];
                unsigned long orig;

                atomic_add_relaxed(&tbl->n_matched, stats->n_packets, &orig);
            }
            return rule;
        }
    }

    /* Look up a flow with 'in_port' as the input port.  Then restore the
     * original input port (otherwise OFPP_NORMAL and OFPP_IN_PORT will
     * have surprising behavior). */
    flow->in_port.ofp_port = in_port;

    /* Our current implementation depends on n_tables == N_TABLES, and
     * TBL_INTERNAL being the last table. */
    BUILD_ASSERT_DECL(N_TABLES == TBL_INTERNAL + 1);

    miss_config = OFPUTIL_TABLE_MISS_CONTINUE;

    for (next_id = *table_id;
         next_id < ofproto->up.n_tables;
         next_id++, next_id += (next_id == TBL_INTERNAL))
    {
        *table_id = next_id;
        rule = rule_dpif_lookup_in_table(ofproto, next_id, flow, wc, take_ref);
        if (stats) {
            struct oftable *tbl = &ofproto->up.tables[next_id];
            unsigned long orig;

            atomic_add_relaxed(rule ? &tbl->n_matched : &tbl->n_missed,
                               stats->n_packets, &orig);
        }
        if (rule) {
            goto out;   /* Match. */
        }
        if (honor_table_miss) {
            miss_config = ofproto_table_get_miss_config(&ofproto->up,
                                                        *table_id);
            if (miss_config == OFPUTIL_TABLE_MISS_CONTINUE) {
                continue;
            }
        }
        break;
    }
    /* Miss. */
    rule = ofproto->no_packet_in_rule;
    if (may_packet_in) {
        if (miss_config == OFPUTIL_TABLE_MISS_CONTINUE
            || miss_config == OFPUTIL_TABLE_MISS_CONTROLLER) {
            struct ofport_dpif *port;

            port = ofp_port_to_ofport(ofproto, old_in_port);
            if (!port) {
                VLOG_WARN_RL(&rl, "packet-in on unknown OpenFlow port %"PRIu16,
                             old_in_port);
            } else if (!(port->up.pp.config & OFPUTIL_PC_NO_PACKET_IN)) {
                rule = ofproto->miss_rule;
            }
        } else if (miss_config == OFPUTIL_TABLE_MISS_DEFAULT &&
                   connmgr_wants_packet_in_on_miss(ofproto->up.connmgr)) {
            rule = ofproto->miss_rule;
        }
    }
    if (take_ref) {
        rule_dpif_ref(rule);
    }
out:
    /* Restore port numbers, as they may have been modified above. */
    flow->tp_src = old_tp_src;
    flow->tp_dst = old_tp_dst;
    /* Restore the old in port. */
    flow->in_port.ofp_port = old_in_port;

    return rule;
}

static void
complete_operation(struct rule_dpif *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);

    ofproto->backer->need_revalidate = REV_FLOW_TABLE;
}

static struct rule_dpif *rule_dpif_cast(const struct rule *rule)
{
    return rule ? CONTAINER_OF(rule, struct rule_dpif, up) : NULL;
}

static struct rule *
rule_alloc(void)
{
    struct rule_dpif *rule = xzalloc(sizeof *rule);
    return &rule->up;
}

static void
rule_dealloc(struct rule *rule_)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    free(rule);
}

static enum ofperr
rule_construct(struct rule *rule_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    ovs_mutex_init_adaptive(&rule->stats_mutex);
    rule->stats.n_packets = 0;
    rule->stats.n_bytes = 0;
    rule->stats.used = rule->up.modified;
    rule->recirc_id = 0;

    return 0;
}

static enum ofperr
rule_insert(struct rule *rule_)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    complete_operation(rule);
    return 0;
}

static void
rule_delete(struct rule *rule_)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    complete_operation(rule);
}

static void
rule_destruct(struct rule *rule_)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);

    ovs_mutex_destroy(&rule->stats_mutex);
    if (rule->recirc_id) {
        recirc_free_id(rule->recirc_id);
    }
}

static void
rule_get_stats(struct rule *rule_, uint64_t *packets, uint64_t *bytes,
               long long int *used)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);

    ovs_mutex_lock(&rule->stats_mutex);
    *packets = rule->stats.n_packets;
    *bytes = rule->stats.n_bytes;
    *used = rule->stats.used;
    ovs_mutex_unlock(&rule->stats_mutex);
}

static void
rule_dpif_execute(struct rule_dpif *rule, const struct flow *flow,
                  struct dp_packet *packet)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);

    ofproto_dpif_execute_actions(ofproto, flow, rule, NULL, 0, packet);
}

static enum ofperr
rule_execute(struct rule *rule, const struct flow *flow,
             struct dp_packet *packet)
{
    rule_dpif_execute(rule_dpif_cast(rule), flow, packet);
    dp_packet_delete(packet);
    return 0;
}

static void
rule_modify_actions(struct rule *rule_, bool reset_counters)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);

    if (reset_counters) {
        ovs_mutex_lock(&rule->stats_mutex);
        rule->stats.n_packets = 0;
        rule->stats.n_bytes = 0;
        ovs_mutex_unlock(&rule->stats_mutex);
    }

    complete_operation(rule);
}

static struct group_dpif *group_dpif_cast(const struct ofgroup *group)
{
    return group ? CONTAINER_OF(group, struct group_dpif, up) : NULL;
}

static struct ofgroup *
group_alloc(void)
{
    struct group_dpif *group = xzalloc(sizeof *group);
    return &group->up;
}

static void
group_dealloc(struct ofgroup *group_)
{
    struct group_dpif *group = group_dpif_cast(group_);
    free(group);
}

static void
group_construct_stats(struct group_dpif *group)
    OVS_REQUIRES(group->stats_mutex)
{
    struct ofputil_bucket *bucket;
    const struct ovs_list *buckets;

    group->packet_count = 0;
    group->byte_count = 0;

    group_dpif_get_buckets(group, &buckets);
    LIST_FOR_EACH (bucket, list_node, buckets) {
        bucket->stats.packet_count = 0;
        bucket->stats.byte_count = 0;
    }
}

void
group_dpif_credit_stats(struct group_dpif *group,
                        struct ofputil_bucket *bucket,
                        const struct dpif_flow_stats *stats)
{
    ovs_mutex_lock(&group->stats_mutex);
    group->packet_count += stats->n_packets;
    group->byte_count += stats->n_bytes;
    if (bucket) {
        bucket->stats.packet_count += stats->n_packets;
        bucket->stats.byte_count += stats->n_bytes;
    } else { /* Credit to all buckets */
        const struct ovs_list *buckets;

        group_dpif_get_buckets(group, &buckets);
        LIST_FOR_EACH (bucket, list_node, buckets) {
            bucket->stats.packet_count += stats->n_packets;
            bucket->stats.byte_count += stats->n_bytes;
        }
    }
    ovs_mutex_unlock(&group->stats_mutex);
}

static enum ofperr
group_construct(struct ofgroup *group_)
{
    struct group_dpif *group = group_dpif_cast(group_);
    const struct ofputil_bucket *bucket;

    /* Prevent group chaining because our locking structure makes it hard to
     * implement deadlock-free.  (See xlate_group_resource_check().) */
    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
        const struct ofpact *a;

        OFPACT_FOR_EACH (a, bucket->ofpacts, bucket->ofpacts_len) {
            if (a->type == OFPACT_GROUP) {
                return OFPERR_OFPGMFC_CHAINING_UNSUPPORTED;
            }
        }
    }

    ovs_mutex_init_adaptive(&group->stats_mutex);
    ovs_mutex_lock(&group->stats_mutex);
    group_construct_stats(group);
    ovs_mutex_unlock(&group->stats_mutex);
    return 0;
}

static void
group_destruct(struct ofgroup *group_)
{
    struct group_dpif *group = group_dpif_cast(group_);
    ovs_mutex_destroy(&group->stats_mutex);
}

static enum ofperr
group_modify(struct ofgroup *group_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(group_->ofproto);

    ofproto->backer->need_revalidate = REV_FLOW_TABLE;

    return 0;
}

static enum ofperr
group_get_stats(const struct ofgroup *group_, struct ofputil_group_stats *ogs)
{
    struct group_dpif *group = group_dpif_cast(group_);
    struct ofputil_bucket *bucket;
    const struct ovs_list *buckets;
    struct bucket_counter *bucket_stats;

    ovs_mutex_lock(&group->stats_mutex);
    ogs->packet_count = group->packet_count;
    ogs->byte_count = group->byte_count;

    group_dpif_get_buckets(group, &buckets);
    bucket_stats = ogs->bucket_stats;
    LIST_FOR_EACH (bucket, list_node, buckets) {
        bucket_stats->packet_count = bucket->stats.packet_count;
        bucket_stats->byte_count = bucket->stats.byte_count;
        bucket_stats++;
    }
    ovs_mutex_unlock(&group->stats_mutex);

    return 0;
}

/* If the group exists, this function increments the groups's reference count.
 *
 * Make sure to call group_dpif_unref() after no longer needing to maintain
 * a reference to the group. */
bool
group_dpif_lookup(struct ofproto_dpif *ofproto, uint32_t group_id,
                  struct group_dpif **group)
{
    struct ofgroup *ofgroup;
    bool found;

    found = ofproto_group_lookup(&ofproto->up, group_id, &ofgroup);
    *group = found ?  group_dpif_cast(ofgroup) : NULL;

    return found;
}

void
group_dpif_get_buckets(const struct group_dpif *group,
                       const struct ovs_list **buckets)
{
    *buckets = &group->up.buckets;
}

enum ofp11_group_type
group_dpif_get_type(const struct group_dpif *group)
{
    return group->up.type;
}

const char *
group_dpif_get_selection_method(const struct group_dpif *group)
{
    return group->up.props.selection_method;
}

/* Sends 'packet' out 'ofport'.
 * May modify 'packet'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
ofproto_dpif_send_packet(const struct ofport_dpif *ofport, struct dp_packet *packet)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    int error;

    error = xlate_send_packet(ofport, packet);

    ovs_mutex_lock(&ofproto->stats_mutex);
    ofproto->stats.tx_packets++;
    ofproto->stats.tx_bytes += dp_packet_size(packet);
    ovs_mutex_unlock(&ofproto->stats_mutex);
    return error;
}

uint64_t
group_dpif_get_selection_method_param(const struct group_dpif *group)
{
    return group->up.props.selection_method_param;
}

const struct field_array *
group_dpif_get_fields(const struct group_dpif *group)
{
    return &group->up.props.fields;
}

/* Return the version string of the datapath that backs up
 * this 'ofproto'.
 */
static const char *
get_datapath_version(const struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    return ofproto->backer->dp_version_string;
}

static bool
set_frag_handling(struct ofproto *ofproto_,
                  enum ofp_config_flags frag_handling)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    if (frag_handling != OFPC_FRAG_REASM) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
        return true;
    } else {
        return false;
    }
}

static enum ofperr
packet_out(struct ofproto *ofproto_, struct dp_packet *packet,
           const struct flow *flow,
           const struct ofpact *ofpacts, size_t ofpacts_len)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    ofproto_dpif_execute_actions(ofproto, flow, NULL, ofpacts,
                                 ofpacts_len, packet);
    return 0;
}

/* NetFlow. */

static int
set_netflow(struct ofproto *ofproto_,
            const struct netflow_options *netflow_options)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    if (netflow_options) {
        if (!ofproto->netflow) {
            ofproto->netflow = netflow_create();
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
        }
        return netflow_set_options(ofproto->netflow, netflow_options);
    } else if (ofproto->netflow) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
        netflow_unref(ofproto->netflow);
        ofproto->netflow = NULL;
    }

    return 0;
}

static void
get_netflow_ids(const struct ofproto *ofproto_,
                uint8_t *engine_type, uint8_t *engine_id)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    dpif_get_netflow_ids(ofproto->backer->dpif, engine_type, engine_id);
}

static struct ofproto_dpif *
ofproto_dpif_lookup(const char *name)
{
    struct ofproto_dpif *ofproto;

    HMAP_FOR_EACH_WITH_HASH (ofproto, all_ofproto_dpifs_node,
                             hash_string(name, 0), &all_ofproto_dpifs) {
        if (!strcmp(ofproto->up.name, name)) {
            return ofproto;
        }
    }
    return NULL;
}

static void
ofproto_unixctl_fdb_flush(struct unixctl_conn *conn, int argc,
                          const char *argv[], void *aux OVS_UNUSED)
{
    struct ofproto_dpif *ofproto;

    if (argc > 1) {
        ofproto = ofproto_dpif_lookup(argv[1]);
        if (!ofproto) {
            unixctl_command_reply_error(conn, "no such bridge");
            return;
        }
        ovs_rwlock_wrlock(&ofproto->ml->rwlock);
        mac_learning_flush(ofproto->ml);
        ovs_rwlock_unlock(&ofproto->ml->rwlock);
    } else {
        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
            ovs_rwlock_wrlock(&ofproto->ml->rwlock);
            mac_learning_flush(ofproto->ml);
            ovs_rwlock_unlock(&ofproto->ml->rwlock);
        }
    }

    unixctl_command_reply(conn, "table successfully flushed");
}

static void
ofproto_unixctl_mcast_snooping_flush(struct unixctl_conn *conn, int argc,
                                     const char *argv[], void *aux OVS_UNUSED)
{
    struct ofproto_dpif *ofproto;

    if (argc > 1) {
        ofproto = ofproto_dpif_lookup(argv[1]);
        if (!ofproto) {
            unixctl_command_reply_error(conn, "no such bridge");
            return;
        }

        if (!mcast_snooping_enabled(ofproto->ms)) {
            unixctl_command_reply_error(conn, "multicast snooping is disabled");
            return;
        }
        mcast_snooping_mdb_flush(ofproto->ms);
    } else {
        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
            if (!mcast_snooping_enabled(ofproto->ms)) {
                continue;
            }
            mcast_snooping_mdb_flush(ofproto->ms);
        }
    }

    unixctl_command_reply(conn, "table successfully flushed");
}

static struct ofport_dpif *
ofbundle_get_a_port(const struct ofbundle *bundle)
{
    return CONTAINER_OF(list_front(&bundle->ports), struct ofport_dpif,
                        bundle_node);
}

static void
ofproto_unixctl_fdb_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                         const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct ofproto_dpif *ofproto;
    const struct mac_entry *e;

    ofproto = ofproto_dpif_lookup(argv[1]);
    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    ds_put_cstr(&ds, " port  VLAN  MAC                Age\n");
    ovs_rwlock_rdlock(&ofproto->ml->rwlock);
    LIST_FOR_EACH (e, lru_node, &ofproto->ml->lrus) {
        struct ofbundle *bundle = mac_entry_get_port(ofproto->ml, e);
        char name[OFP_MAX_PORT_NAME_LEN];

        ofputil_port_to_string(ofbundle_get_a_port(bundle)->up.ofp_port,
                               name, sizeof name);
        ds_put_format(&ds, "%5s  %4d  "ETH_ADDR_FMT"  %3d\n",
                      name, e->vlan, ETH_ADDR_ARGS(e->mac),
                      mac_entry_age(ofproto->ml, e));
    }
    ovs_rwlock_unlock(&ofproto->ml->rwlock);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ofproto_unixctl_mcast_snooping_show(struct unixctl_conn *conn,
                                    int argc OVS_UNUSED,
                                    const char *argv[],
                                    void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct ofproto_dpif *ofproto;
    const struct ofbundle *bundle;
    const struct mcast_group *grp;
    struct mcast_group_bundle *b;
    struct mcast_mrouter_bundle *mrouter;

    ofproto = ofproto_dpif_lookup(argv[1]);
    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    if (!mcast_snooping_enabled(ofproto->ms)) {
        unixctl_command_reply_error(conn, "multicast snooping is disabled");
        return;
    }

    ds_put_cstr(&ds, " port  VLAN  GROUP                Age\n");
    ovs_rwlock_rdlock(&ofproto->ms->rwlock);
    LIST_FOR_EACH (grp, group_node, &ofproto->ms->group_lru) {
        LIST_FOR_EACH(b, bundle_node, &grp->bundle_lru) {
            char name[OFP_MAX_PORT_NAME_LEN];

            bundle = b->port;
            ofputil_port_to_string(ofbundle_get_a_port(bundle)->up.ofp_port,
                                   name, sizeof name);
            ds_put_format(&ds, "%5s  %4d  "IP_FMT"         %3d\n",
                          name, grp->vlan, IP_ARGS(grp->ip4),
                          mcast_bundle_age(ofproto->ms, b));
        }
    }

    /* ports connected to multicast routers */
    LIST_FOR_EACH(mrouter, mrouter_node, &ofproto->ms->mrouter_lru) {
        char name[OFP_MAX_PORT_NAME_LEN];

        bundle = mrouter->port;
        ofputil_port_to_string(ofbundle_get_a_port(bundle)->up.ofp_port,
                               name, sizeof name);
            ds_put_format(&ds, "%5s  %4d  querier             %3d\n",
                      name, mrouter->vlan,
                      mcast_mrouter_age(ofproto->ms, mrouter));
    }
    ovs_rwlock_unlock(&ofproto->ms->rwlock);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

struct trace_ctx {
    struct xlate_out xout;
    struct xlate_in xin;
    const struct flow *key;
    struct flow flow;
    struct flow_wildcards wc;
    struct ds *result;
};

static void
trace_format_rule(struct ds *result, int level, const struct rule_dpif *rule)
{
    const struct rule_actions *actions;
    ovs_be64 cookie;

    ds_put_char_multiple(result, '\t', level);
    if (!rule) {
        ds_put_cstr(result, "No match\n");
        return;
    }

    ovs_mutex_lock(&rule->up.mutex);
    cookie = rule->up.flow_cookie;
    ovs_mutex_unlock(&rule->up.mutex);

    ds_put_format(result, "Rule: table=%"PRIu8" cookie=%#"PRIx64" ",
                  rule ? rule->up.table_id : 0, ntohll(cookie));
    cls_rule_format(&rule->up.cr, result);
    ds_put_char(result, '\n');

    actions = rule_dpif_get_actions(rule);

    ds_put_char_multiple(result, '\t', level);
    ds_put_cstr(result, "OpenFlow actions=");
    ofpacts_format(actions->ofpacts, actions->ofpacts_len, result);
    ds_put_char(result, '\n');
}

static void
trace_format_flow(struct ds *result, int level, const char *title,
                  struct trace_ctx *trace)
{
    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s: ", title);
    /* Do not report unchanged flows for resubmits. */
    if ((level > 0 && flow_equal(&trace->xin.flow, &trace->flow))
        || (level == 0 && flow_equal(&trace->xin.flow, trace->key))) {
        ds_put_cstr(result, "unchanged");
    } else {
        flow_format(result, &trace->xin.flow);
        trace->flow = trace->xin.flow;
    }
    ds_put_char(result, '\n');
}

static void
trace_format_regs(struct ds *result, int level, const char *title,
                  struct trace_ctx *trace)
{
    size_t i;

    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s:", title);
    for (i = 0; i < FLOW_N_REGS; i++) {
        ds_put_format(result, " reg%"PRIuSIZE"=0x%"PRIx32, i, trace->flow.regs[i]);
    }
    ds_put_char(result, '\n');
}

static void
trace_format_odp(struct ds *result, int level, const char *title,
                 struct trace_ctx *trace)
{
    struct ofpbuf *odp_actions = trace->xout.odp_actions;

    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s: ", title);
    format_odp_actions(result, odp_actions->data, odp_actions->size);
    ds_put_char(result, '\n');
}

static void
trace_format_megaflow(struct ds *result, int level, const char *title,
                      struct trace_ctx *trace)
{
    struct match match;

    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s: ", title);
    flow_wildcards_or(&trace->wc, &trace->xout.wc, &trace->wc);
    match_init(&match, trace->key, &trace->wc);
    match_format(&match, result, OFP_DEFAULT_PRIORITY);
    ds_put_char(result, '\n');
}

static void trace_report(struct xlate_in *xin, const char *s, int recurse);

static void
trace_resubmit(struct xlate_in *xin, struct rule_dpif *rule, int recurse)
{
    struct trace_ctx *trace = CONTAINER_OF(xin, struct trace_ctx, xin);
    struct ds *result = trace->result;

    if (!recurse) {
        if (rule == xin->ofproto->miss_rule) {
            trace_report(xin, "No match, flow generates \"packet in\"s.",
                         recurse);
        } else if (rule == xin->ofproto->no_packet_in_rule) {
            trace_report(xin, "No match, packets dropped because "
                         "OFPPC_NO_PACKET_IN is set on in_port.", recurse);
        } else if (rule == xin->ofproto->drop_frags_rule) {
            trace_report(xin, "Packets dropped because they are IP "
                         "fragments and the fragment handling mode is "
                         "\"drop\".", recurse);
        }
    }

    ds_put_char(result, '\n');
    if (recurse) {
        trace_format_flow(result, recurse, "Resubmitted flow", trace);
        trace_format_regs(result, recurse, "Resubmitted regs", trace);
        trace_format_odp(result,  recurse, "Resubmitted  odp", trace);
        trace_format_megaflow(result, recurse, "Resubmitted megaflow", trace);
    }
    trace_format_rule(result, recurse, rule);
}

static void
trace_report(struct xlate_in *xin, const char *s, int recurse)
{
    struct trace_ctx *trace = CONTAINER_OF(xin, struct trace_ctx, xin);
    struct ds *result = trace->result;

    ds_put_char_multiple(result, '\t', recurse);
    ds_put_cstr(result, s);
    ds_put_char(result, '\n');
}

/* Parses the 'argc' elements of 'argv', ignoring argv[0].  The following
 * forms are supported:
 *
 *     - [dpname] odp_flow [-generate | packet]
 *     - bridge br_flow [-generate | packet]
 *
 * On success, initializes '*ofprotop' and 'flow' and returns NULL.  On failure
 * returns a nonnull malloced error message. */
static char * OVS_WARN_UNUSED_RESULT
parse_flow_and_packet(int argc, const char *argv[],
                      struct ofproto_dpif **ofprotop, struct flow *flow,
                      struct dp_packet **packetp)
{
    const struct dpif_backer *backer = NULL;
    const char *error = NULL;
    char *m_err = NULL;
    struct simap port_names = SIMAP_INITIALIZER(&port_names);
    struct dp_packet *packet;
    struct ofpbuf odp_key;
    struct ofpbuf odp_mask;

    ofpbuf_init(&odp_key, 0);
    ofpbuf_init(&odp_mask, 0);

    /* Handle "-generate" or a hex string as the last argument. */
    if (!strcmp(argv[argc - 1], "-generate")) {
        packet = dp_packet_new(0);
        argc--;
    } else {
        error = eth_from_hex(argv[argc - 1], &packet);
        if (!error) {
            argc--;
        } else if (argc == 4) {
            /* The 3-argument form must end in "-generate' or a hex string. */
            goto exit;
        }
        error = NULL;
    }

    /* odp_flow can have its in_port specified as a name instead of port no.
     * We do not yet know whether a given flow is a odp_flow or a br_flow.
     * But, to know whether a flow is odp_flow through odp_flow_from_string(),
     * we need to create a simap of name to port no. */
    if (argc == 3) {
        const char *dp_type;
        if (!strncmp(argv[1], "ovs-", 4)) {
            dp_type = argv[1] + 4;
        } else {
            dp_type = argv[1];
        }
        backer = shash_find_data(&all_dpif_backers, dp_type);
    } else if (argc == 2) {
        struct shash_node *node;
        if (shash_count(&all_dpif_backers) == 1) {
            node = shash_first(&all_dpif_backers);
            backer = node->data;
        }
    } else {
        error = "Syntax error";
        goto exit;
    }
    if (backer && backer->dpif) {
        struct dpif_port dpif_port;
        struct dpif_port_dump port_dump;
        DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, backer->dpif) {
            simap_put(&port_names, dpif_port.name,
                      odp_to_u32(dpif_port.port_no));
        }
    }

    /* Parse the flow and determine whether a datapath or
     * bridge is specified. If function odp_flow_key_from_string()
     * returns 0, the flow is a odp_flow. If function
     * parse_ofp_exact_flow() returns NULL, the flow is a br_flow. */
    if (!odp_flow_from_string(argv[argc - 1], &port_names,
                              &odp_key, &odp_mask)) {
        if (!backer) {
            error = "Cannot find the datapath";
            goto exit;
        }

        if (odp_flow_key_to_flow(odp_key.data, odp_key.size, flow) == ODP_FIT_ERROR) {
            error = "Failed to parse datapath flow key";
            goto exit;
        }

        *ofprotop = xlate_lookup_ofproto(backer, flow,
                                         &flow->in_port.ofp_port);
        if (*ofprotop == NULL) {
            error = "Invalid datapath flow";
            goto exit;
        }

        vsp_adjust_flow(*ofprotop, flow, NULL);

    } else {
        char *err = parse_ofp_exact_flow(flow, NULL, argv[argc - 1], NULL);

        if (err) {
            m_err = xasprintf("Bad openflow flow syntax: %s", err);
            free(err);
            goto exit;
        } else {
            if (argc != 3) {
                error = "Must specify bridge name";
                goto exit;
            }

            *ofprotop = ofproto_dpif_lookup(argv[1]);
            if (!*ofprotop) {
                error = "Unknown bridge name";
                goto exit;
            }
        }
    }

    /* Generate a packet, if requested. */
    if (packet) {
        if (!dp_packet_size(packet)) {
            flow_compose(packet, flow);
        } else {
            /* Use the metadata from the flow and the packet argument
             * to reconstruct the flow. */
            pkt_metadata_from_flow(&packet->md, flow);
            flow_extract(packet, flow);
        }
    }

exit:
    if (error && !m_err) {
        m_err = xstrdup(error);
    }
    if (m_err) {
        dp_packet_delete(packet);
        packet = NULL;
    }
    *packetp = packet;
    ofpbuf_uninit(&odp_key);
    ofpbuf_uninit(&odp_mask);
    simap_destroy(&port_names);
    return m_err;
}

static void
ofproto_unixctl_trace(struct unixctl_conn *conn, int argc, const char *argv[],
                      void *aux OVS_UNUSED)
{
    struct ofproto_dpif *ofproto;
    struct dp_packet *packet;
    char *error;
    struct flow flow;

    error = parse_flow_and_packet(argc, argv, &ofproto, &flow, &packet);
    if (!error) {
        struct ds result;

        ds_init(&result);
        ofproto_trace(ofproto, &flow, packet, NULL, 0, &result);
        unixctl_command_reply(conn, ds_cstr(&result));
        ds_destroy(&result);
        dp_packet_delete(packet);
    } else {
        unixctl_command_reply_error(conn, error);
        free(error);
    }
}

static void
ofproto_unixctl_trace_actions(struct unixctl_conn *conn, int argc,
                              const char *argv[], void *aux OVS_UNUSED)
{
    enum ofputil_protocol usable_protocols;
    struct ofproto_dpif *ofproto;
    bool enforce_consistency;
    struct ofpbuf ofpacts;
    struct dp_packet *packet;
    struct ds result;
    struct flow flow;
    uint16_t in_port;

    /* Three kinds of error return values! */
    enum ofperr retval;
    char *error;

    packet = NULL;
    ds_init(&result);
    ofpbuf_init(&ofpacts, 0);

    /* Parse actions. */
    error = ofpacts_parse_actions(argv[--argc], &ofpacts, &usable_protocols);
    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
        goto exit;
    }

    /* OpenFlow 1.1 and later suggest that the switch enforces certain forms of
     * consistency between the flow and the actions.  With -consistent, we
     * enforce consistency even for a flow supported in OpenFlow 1.0. */
    if (!strcmp(argv[1], "-consistent")) {
        enforce_consistency = true;
        argv++;
        argc--;
    } else {
        enforce_consistency = false;
    }

    error = parse_flow_and_packet(argc, argv, &ofproto, &flow, &packet);
    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
        goto exit;
    }

    /* Do the same checks as handle_packet_out() in ofproto.c.
     *
     * We pass a 'table_id' of 0 to ofpacts_check(), which isn't
     * strictly correct because these actions aren't in any table, but it's OK
     * because it 'table_id' is used only to check goto_table instructions, but
     * packet-outs take a list of actions and therefore it can't include
     * instructions.
     *
     * We skip the "meter" check here because meter is an instruction, not an
     * action, and thus cannot appear in ofpacts. */
    in_port = ofp_to_u16(flow.in_port.ofp_port);
    if (in_port >= ofproto->up.max_ports && in_port < ofp_to_u16(OFPP_MAX)) {
        unixctl_command_reply_error(conn, "invalid in_port");
        goto exit;
    }
    if (enforce_consistency) {
        retval = ofpacts_check_consistency(ofpacts.data, ofpacts.size,
                                           &flow, u16_to_ofp(ofproto->up.max_ports),
                                           0, 0, usable_protocols);
    } else {
        retval = ofpacts_check(ofpacts.data, ofpacts.size, &flow,
                               u16_to_ofp(ofproto->up.max_ports), 0, 0,
                               &usable_protocols);
    }

    if (retval) {
        ds_clear(&result);
        ds_put_format(&result, "Bad actions: %s", ofperr_to_string(retval));
        unixctl_command_reply_error(conn, ds_cstr(&result));
        goto exit;
    }

    ofproto_trace(ofproto, &flow, packet,
                  ofpacts.data, ofpacts.size, &result);
    unixctl_command_reply(conn, ds_cstr(&result));

exit:
    ds_destroy(&result);
    dp_packet_delete(packet);
    ofpbuf_uninit(&ofpacts);
}

/* Implements a "trace" through 'ofproto''s flow table, appending a textual
 * description of the results to 'ds'.
 *
 * The trace follows a packet with the specified 'flow' through the flow
 * table.  'packet' may be nonnull to trace an actual packet, with consequent
 * side effects (if it is nonnull then its flow must be 'flow').
 *
 * If 'ofpacts' is nonnull then its 'ofpacts_len' bytes specify the actions to
 * trace, otherwise the actions are determined by a flow table lookup. */
static void
ofproto_trace(struct ofproto_dpif *ofproto, struct flow *flow,
              const struct dp_packet *packet,
              const struct ofpact ofpacts[], size_t ofpacts_len,
              struct ds *ds)
{
    struct trace_ctx trace;

    ds_put_format(ds, "Bridge: %s\n", ofproto->up.name);
    ds_put_cstr(ds, "Flow: ");
    flow_format(ds, flow);
    ds_put_char(ds, '\n');

    flow_wildcards_init_catchall(&trace.wc);

    trace.result = ds;
    trace.key = flow; /* Original flow key, used for megaflow. */
    trace.flow = *flow; /* May be modified by actions. */
    xlate_in_init(&trace.xin, ofproto, flow, flow->in_port.ofp_port, NULL,
                  ntohs(flow->tcp_flags), packet);
    trace.xin.ofpacts = ofpacts;
    trace.xin.ofpacts_len = ofpacts_len;
    trace.xin.resubmit_hook = trace_resubmit;
    trace.xin.report_hook = trace_report;

    xlate_actions(&trace.xin, &trace.xout);

    ds_put_char(ds, '\n');
    trace_format_flow(ds, 0, "Final flow", &trace);
    trace_format_megaflow(ds, 0, "Megaflow", &trace);

    ds_put_cstr(ds, "Datapath actions: ");
    format_odp_actions(ds, trace.xout.odp_actions->data,
                       trace.xout.odp_actions->size);

    if (trace.xout.slow) {
        enum slow_path_reason slow;

        ds_put_cstr(ds, "\nThis flow is handled by the userspace "
                    "slow path because it:");

        slow = trace.xout.slow;
        while (slow) {
            enum slow_path_reason bit = rightmost_1bit(slow);

            ds_put_format(ds, "\n\t- %s.",
                          slow_path_reason_to_explanation(bit));

            slow &= ~bit;
        }
    }

    xlate_out_uninit(&trace.xout);
}

/* Store the current ofprotos in 'ofproto_shash'.  Returns a sorted list
 * of the 'ofproto_shash' nodes.  It is the responsibility of the caller
 * to destroy 'ofproto_shash' and free the returned value. */
static const struct shash_node **
get_ofprotos(struct shash *ofproto_shash)
{
    const struct ofproto_dpif *ofproto;

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
        char *name = xasprintf("%s@%s", ofproto->up.type, ofproto->up.name);
        shash_add_nocopy(ofproto_shash, name, ofproto);
    }

    return shash_sort(ofproto_shash);
}

static void
ofproto_unixctl_dpif_dump_dps(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[] OVS_UNUSED,
                              void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct shash ofproto_shash;
    const struct shash_node **sorted_ofprotos;
    int i;

    shash_init(&ofproto_shash);
    sorted_ofprotos = get_ofprotos(&ofproto_shash);
    for (i = 0; i < shash_count(&ofproto_shash); i++) {
        const struct shash_node *node = sorted_ofprotos[i];
        ds_put_format(&ds, "%s\n", node->name);
    }

    shash_destroy(&ofproto_shash);
    free(sorted_ofprotos);

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
dpif_show_backer(const struct dpif_backer *backer, struct ds *ds)
{
    const struct shash_node **ofprotos;
    struct dpif_dp_stats dp_stats;
    struct shash ofproto_shash;
    size_t i;

    dpif_get_dp_stats(backer->dpif, &dp_stats);

    ds_put_format(ds, "%s: hit:%"PRIu64" missed:%"PRIu64"\n",
                  dpif_name(backer->dpif), dp_stats.n_hit, dp_stats.n_missed);

    shash_init(&ofproto_shash);
    ofprotos = get_ofprotos(&ofproto_shash);
    for (i = 0; i < shash_count(&ofproto_shash); i++) {
        struct ofproto_dpif *ofproto = ofprotos[i]->data;
        const struct shash_node **ports;
        size_t j;

        if (ofproto->backer != backer) {
            continue;
        }

        ds_put_format(ds, "\t%s:\n", ofproto->up.name);

        ports = shash_sort(&ofproto->up.port_by_name);
        for (j = 0; j < shash_count(&ofproto->up.port_by_name); j++) {
            const struct shash_node *node = ports[j];
            struct ofport *ofport = node->data;
            struct smap config;
            odp_port_t odp_port;

            ds_put_format(ds, "\t\t%s %u/", netdev_get_name(ofport->netdev),
                          ofport->ofp_port);

            odp_port = ofp_port_to_odp_port(ofproto, ofport->ofp_port);
            if (odp_port != ODPP_NONE) {
                ds_put_format(ds, "%"PRIu32":", odp_port);
            } else {
                ds_put_cstr(ds, "none:");
            }

            ds_put_format(ds, " (%s", netdev_get_type(ofport->netdev));

            smap_init(&config);
            if (!netdev_get_config(ofport->netdev, &config)) {
                const struct smap_node **nodes;
                size_t i;

                nodes = smap_sort(&config);
                for (i = 0; i < smap_count(&config); i++) {
                    const struct smap_node *node = nodes[i];
                    ds_put_format(ds, "%c %s=%s", i ? ',' : ':',
                                  node->key, node->value);
                }
                free(nodes);
            }
            smap_destroy(&config);

            ds_put_char(ds, ')');
            ds_put_char(ds, '\n');
        }
        free(ports);
    }
    shash_destroy(&ofproto_shash);
    free(ofprotos);
}

static void
ofproto_unixctl_dpif_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct shash_node **backers;
    int i;

    backers = shash_sort(&all_dpif_backers);
    for (i = 0; i < shash_count(&all_dpif_backers); i++) {
        dpif_show_backer(backers[i]->data, &ds);
    }
    free(backers);

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ofproto_unixctl_dpif_dump_flows(struct unixctl_conn *conn,
                                int argc OVS_UNUSED, const char *argv[],
                                void *aux OVS_UNUSED)
{
    const struct ofproto_dpif *ofproto;

    struct ds ds = DS_EMPTY_INITIALIZER;
    bool verbosity = false;

    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct hmap portno_names;

    struct dpif_flow_dump *flow_dump;
    struct dpif_flow_dump_thread *flow_dump_thread;
    struct dpif_flow f;
    int error;

    ofproto = ofproto_dpif_lookup(argv[argc - 1]);
    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    if (argc > 2 && !strcmp(argv[1], "-m")) {
        verbosity = true;
    }

    hmap_init(&portno_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, ofproto->backer->dpif) {
        odp_portno_names_set(&portno_names, dpif_port.port_no, dpif_port.name);
    }

    ds_init(&ds);
    flow_dump = dpif_flow_dump_create(ofproto->backer->dpif, false);
    flow_dump_thread = dpif_flow_dump_thread_create(flow_dump);
    while (dpif_flow_dump_next(flow_dump_thread, &f, 1)) {
        struct flow flow;

        if (odp_flow_key_to_flow(f.key, f.key_len, &flow) == ODP_FIT_ERROR
            || xlate_lookup_ofproto(ofproto->backer, &flow, NULL) != ofproto) {
            continue;
        }

        if (verbosity) {
            odp_format_ufid(&f.ufid, &ds);
            ds_put_cstr(&ds, " ");
        }
        odp_flow_format(f.key, f.key_len, f.mask, f.mask_len,
                        &portno_names, &ds, verbosity);
        ds_put_cstr(&ds, ", ");
        dpif_flow_stats_format(&f.stats, &ds);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, f.actions, f.actions_len);
        ds_put_char(&ds, '\n');
    }
    dpif_flow_dump_thread_destroy(flow_dump_thread);
    error = dpif_flow_dump_destroy(flow_dump);

    if (error) {
        ds_clear(&ds);
        ds_put_format(&ds, "dpif/dump_flows failed: %s", ovs_strerror(errno));
        unixctl_command_reply_error(conn, ds_cstr(&ds));
    } else {
        unixctl_command_reply(conn, ds_cstr(&ds));
    }
    odp_portno_names_destroy(&portno_names);
    hmap_destroy(&portno_names);
    ds_destroy(&ds);
}

static void
ofproto_revalidate_all_backers(void)
{
    const struct shash_node **backers;
    int i;

    backers = shash_sort(&all_dpif_backers);
    for (i = 0; i < shash_count(&all_dpif_backers); i++) {
        struct dpif_backer *backer = backers[i]->data;
        backer->need_revalidate = REV_RECONFIGURE;
    }
    free(backers);
}

static void
disable_tnl_push_pop(struct unixctl_conn *conn OVS_UNUSED, int argc OVS_UNUSED,
                     const char *argv[], void *aux OVS_UNUSED)
{
    if (!strcasecmp(argv[1], "off")) {
        ofproto_use_tnl_push_pop = false;
        unixctl_command_reply(conn, "Tunnel push-pop off");
        ofproto_revalidate_all_backers();
    } else if (!strcasecmp(argv[1], "on")) {
        ofproto_use_tnl_push_pop = true;
        unixctl_command_reply(conn, "Tunnel push-pop on");
        ofproto_revalidate_all_backers();
    }
}

static void
ofproto_unixctl_init(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    unixctl_command_register(
        "ofproto/trace",
        "{[dp_name] odp_flow | bridge br_flow} [-generate|packet]",
        1, 3, ofproto_unixctl_trace, NULL);
    unixctl_command_register(
        "ofproto/trace-packet-out",
        "[-consistent] {[dp_name] odp_flow | bridge br_flow} [-generate|packet] actions",
        2, 6, ofproto_unixctl_trace_actions, NULL);
    unixctl_command_register("fdb/flush", "[bridge]", 0, 1,
                             ofproto_unixctl_fdb_flush, NULL);
    unixctl_command_register("fdb/show", "bridge", 1, 1,
                             ofproto_unixctl_fdb_show, NULL);
    unixctl_command_register("mdb/flush", "[bridge]", 0, 1,
                             ofproto_unixctl_mcast_snooping_flush, NULL);
    unixctl_command_register("mdb/show", "bridge", 1, 1,
                             ofproto_unixctl_mcast_snooping_show, NULL);
    unixctl_command_register("dpif/dump-dps", "", 0, 0,
                             ofproto_unixctl_dpif_dump_dps, NULL);
    unixctl_command_register("dpif/show", "", 0, 0, ofproto_unixctl_dpif_show,
                             NULL);
    unixctl_command_register("dpif/dump-flows", "[-m] bridge", 1, 2,
                             ofproto_unixctl_dpif_dump_flows, NULL);

    unixctl_command_register("ofproto/tnl-push-pop", "[on]|[off]", 1, 1,
                             disable_tnl_push_pop, NULL);
}

/* Returns true if 'table' is the table used for internal rules,
 * false otherwise. */
bool
table_is_internal(uint8_t table_id)
{
    return table_id == TBL_INTERNAL;
}

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

static int
set_realdev(struct ofport *ofport_, ofp_port_t realdev_ofp_port, int vid)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport_->ofproto);
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);

    if (realdev_ofp_port == ofport->realdev_ofp_port
        && vid == ofport->vlandev_vid) {
        return 0;
    }

    ofproto->backer->need_revalidate = REV_RECONFIGURE;

    if (ofport->realdev_ofp_port) {
        vsp_remove(ofport);
    }
    if (realdev_ofp_port && ofport->bundle) {
        /* vlandevs are enslaved to their realdevs, so they are not allowed to
         * themselves be part of a bundle. */
        bundle_set(ofport_->ofproto, ofport->bundle, NULL);
    }

    ofport->realdev_ofp_port = realdev_ofp_port;
    ofport->vlandev_vid = vid;

    if (realdev_ofp_port) {
        vsp_add(ofport, realdev_ofp_port, vid);
    }

    return 0;
}

static uint32_t
hash_realdev_vid(ofp_port_t realdev_ofp_port, int vid)
{
    return hash_2words(ofp_to_u16(realdev_ofp_port), vid);
}

bool
ofproto_has_vlan_splinters(const struct ofproto_dpif *ofproto)
    OVS_EXCLUDED(ofproto->vsp_mutex)
{
    /* hmap_is_empty is thread safe. */
    return !hmap_is_empty(&ofproto->realdev_vid_map);
}


static ofp_port_t
vsp_realdev_to_vlandev__(const struct ofproto_dpif *ofproto,
                         ofp_port_t realdev_ofp_port, ovs_be16 vlan_tci)
    OVS_REQUIRES(ofproto->vsp_mutex)
{
    if (!hmap_is_empty(&ofproto->realdev_vid_map)) {
        int vid = vlan_tci_to_vid(vlan_tci);
        const struct vlan_splinter *vsp;

        HMAP_FOR_EACH_WITH_HASH (vsp, realdev_vid_node,
                                 hash_realdev_vid(realdev_ofp_port, vid),
                                 &ofproto->realdev_vid_map) {
            if (vsp->realdev_ofp_port == realdev_ofp_port
                && vsp->vid == vid) {
                return vsp->vlandev_ofp_port;
            }
        }
    }
    return realdev_ofp_port;
}

/* Returns the OFP port number of the Linux VLAN device that corresponds to
 * 'vlan_tci' on the network device with port number 'realdev_ofp_port' in
 * 'struct ofport_dpif'.  For example, given 'realdev_ofp_port' of eth0 and
 * 'vlan_tci' 9, it would return the port number of eth0.9.
 *
 * Unless VLAN splinters are enabled for port 'realdev_ofp_port', this
 * function just returns its 'realdev_ofp_port' argument. */
ofp_port_t
vsp_realdev_to_vlandev(const struct ofproto_dpif *ofproto,
                       ofp_port_t realdev_ofp_port, ovs_be16 vlan_tci)
    OVS_EXCLUDED(ofproto->vsp_mutex)
{
    ofp_port_t ret;

    /* hmap_is_empty is thread safe, see if we can return immediately. */
    if (hmap_is_empty(&ofproto->realdev_vid_map)) {
        return realdev_ofp_port;
    }
    ovs_mutex_lock(&ofproto->vsp_mutex);
    ret = vsp_realdev_to_vlandev__(ofproto, realdev_ofp_port, vlan_tci);
    ovs_mutex_unlock(&ofproto->vsp_mutex);
    return ret;
}

static struct vlan_splinter *
vlandev_find(const struct ofproto_dpif *ofproto, ofp_port_t vlandev_ofp_port)
{
    struct vlan_splinter *vsp;

    HMAP_FOR_EACH_WITH_HASH (vsp, vlandev_node,
                             hash_ofp_port(vlandev_ofp_port),
                             &ofproto->vlandev_map) {
        if (vsp->vlandev_ofp_port == vlandev_ofp_port) {
            return vsp;
        }
    }

    return NULL;
}

/* Returns the OpenFlow port number of the "real" device underlying the Linux
 * VLAN device with OpenFlow port number 'vlandev_ofp_port' and stores the
 * VLAN VID of the Linux VLAN device in '*vid'.  For example, given
 * 'vlandev_ofp_port' of eth0.9, it would return the OpenFlow port number of
 * eth0 and store 9 in '*vid'.
 *
 * Returns 0 and does not modify '*vid' if 'vlandev_ofp_port' is not a Linux
 * VLAN device.  Unless VLAN splinters are enabled, this is what this function
 * always does.*/
static ofp_port_t
vsp_vlandev_to_realdev(const struct ofproto_dpif *ofproto,
                       ofp_port_t vlandev_ofp_port, int *vid)
    OVS_REQUIRES(ofproto->vsp_mutex)
{
    if (!hmap_is_empty(&ofproto->vlandev_map)) {
        const struct vlan_splinter *vsp;

        vsp = vlandev_find(ofproto, vlandev_ofp_port);
        if (vsp) {
            if (vid) {
                *vid = vsp->vid;
            }
            return vsp->realdev_ofp_port;
        }
    }
    return 0;
}

/* Given 'flow', a flow representing a packet received on 'ofproto', checks
 * whether 'flow->in_port' represents a Linux VLAN device.  If so, changes
 * 'flow->in_port' to the "real" device backing the VLAN device, sets
 * 'flow->vlan_tci' to the VLAN VID, and returns true.  Optionally pushes the
 * appropriate VLAN on 'packet' if provided.  Otherwise (which is always the
 * case unless VLAN splinters are enabled), returns false without making any
 * changes. */
bool
vsp_adjust_flow(const struct ofproto_dpif *ofproto, struct flow *flow,
                struct dp_packet *packet)
    OVS_EXCLUDED(ofproto->vsp_mutex)
{
    ofp_port_t realdev;
    int vid;

    /* hmap_is_empty is thread safe. */
    if (hmap_is_empty(&ofproto->vlandev_map)) {
        return false;
    }

    ovs_mutex_lock(&ofproto->vsp_mutex);
    realdev = vsp_vlandev_to_realdev(ofproto, flow->in_port.ofp_port, &vid);
    ovs_mutex_unlock(&ofproto->vsp_mutex);
    if (!realdev) {
        return false;
    }

    /* Cause the flow to be processed as if it came in on the real device with
     * the VLAN device's VLAN ID. */
    flow->in_port.ofp_port = realdev;
    flow->vlan_tci = htons((vid & VLAN_VID_MASK) | VLAN_CFI);

    if (packet) {
        /* Make the packet resemble the flow, so that it gets sent to an
         * OpenFlow controller properly, so that it looks correct for sFlow,
         * and so that flow_extract() will get the correct vlan_tci if it is
         * called on 'packet'. */
        eth_push_vlan(packet, htons(ETH_TYPE_VLAN), flow->vlan_tci);
    }

    return true;
}

static void
vsp_remove(struct ofport_dpif *port)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);
    struct vlan_splinter *vsp;

    ovs_mutex_lock(&ofproto->vsp_mutex);
    vsp = vlandev_find(ofproto, port->up.ofp_port);
    if (vsp) {
        hmap_remove(&ofproto->vlandev_map, &vsp->vlandev_node);
        hmap_remove(&ofproto->realdev_vid_map, &vsp->realdev_vid_node);
        free(vsp);

        port->realdev_ofp_port = 0;
    } else {
        VLOG_ERR("missing vlan device record");
    }
    ovs_mutex_unlock(&ofproto->vsp_mutex);
}

static void
vsp_add(struct ofport_dpif *port, ofp_port_t realdev_ofp_port, int vid)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);

    ovs_mutex_lock(&ofproto->vsp_mutex);
    if (!vsp_vlandev_to_realdev(ofproto, port->up.ofp_port, NULL)
        && (vsp_realdev_to_vlandev__(ofproto, realdev_ofp_port, htons(vid))
            == realdev_ofp_port)) {
        struct vlan_splinter *vsp;

        vsp = xmalloc(sizeof *vsp);
        vsp->realdev_ofp_port = realdev_ofp_port;
        vsp->vlandev_ofp_port = port->up.ofp_port;
        vsp->vid = vid;

        port->realdev_ofp_port = realdev_ofp_port;

        hmap_insert(&ofproto->vlandev_map, &vsp->vlandev_node,
                    hash_ofp_port(port->up.ofp_port));
        hmap_insert(&ofproto->realdev_vid_map, &vsp->realdev_vid_node,
                    hash_realdev_vid(realdev_ofp_port, vid));
    } else {
        VLOG_ERR("duplicate vlan device record");
    }
    ovs_mutex_unlock(&ofproto->vsp_mutex);
}

static odp_port_t
ofp_port_to_odp_port(const struct ofproto_dpif *ofproto, ofp_port_t ofp_port)
{
    const struct ofport_dpif *ofport = ofp_port_to_ofport(ofproto, ofp_port);
    return ofport ? ofport->odp_port : ODPP_NONE;
}

struct ofport_dpif *
odp_port_to_ofport(const struct dpif_backer *backer, odp_port_t odp_port)
{
    struct ofport_dpif *port;

    ovs_rwlock_rdlock(&backer->odp_to_ofport_lock);
    HMAP_FOR_EACH_IN_BUCKET (port, odp_port_node, hash_odp_port(odp_port),
                             &backer->odp_to_ofport_map) {
        if (port->odp_port == odp_port) {
            ovs_rwlock_unlock(&backer->odp_to_ofport_lock);
            return port;
        }
    }

    ovs_rwlock_unlock(&backer->odp_to_ofport_lock);
    return NULL;
}

static ofp_port_t
odp_port_to_ofp_port(const struct ofproto_dpif *ofproto, odp_port_t odp_port)
{
    struct ofport_dpif *port;

    port = odp_port_to_ofport(ofproto->backer, odp_port);
    if (port && &ofproto->up == port->up.ofproto) {
        return port->up.ofp_port;
    } else {
        return OFPP_NONE;
    }
}

int
ofproto_dpif_add_internal_flow(struct ofproto_dpif *ofproto,
                               const struct match *match, int priority,
                               uint16_t idle_timeout,
                               const struct ofpbuf *ofpacts,
                               struct rule **rulep)
{
    struct ofputil_flow_mod fm;
    struct rule_dpif *rule;
    int error;

    fm.match = *match;
    fm.priority = priority;
    fm.new_cookie = htonll(0);
    fm.cookie = htonll(0);
    fm.cookie_mask = htonll(0);
    fm.modify_cookie = false;
    fm.table_id = TBL_INTERNAL;
    fm.command = OFPFC_ADD;
    fm.idle_timeout = idle_timeout;
    fm.hard_timeout = 0;
    fm.importance = 0;
    fm.buffer_id = 0;
    fm.out_port = 0;
    fm.flags = OFPUTIL_FF_HIDDEN_FIELDS | OFPUTIL_FF_NO_READONLY;
    fm.ofpacts = ofpacts->data;
    fm.ofpacts_len = ofpacts->size;

    error = ofproto_flow_mod(&ofproto->up, &fm);
    if (error) {
        VLOG_ERR_RL(&rl, "failed to add internal flow (%s)",
                    ofperr_to_string(error));
        *rulep = NULL;
        return error;
    }

    rule = rule_dpif_lookup_in_table(ofproto, TBL_INTERNAL, &fm.match.flow,
                                     &fm.match.wc, false);
    if (rule) {
        *rulep = &rule->up;
    } else {
        OVS_NOT_REACHED();
    }
    return 0;
}

int
ofproto_dpif_delete_internal_flow(struct ofproto_dpif *ofproto,
                                  struct match *match, int priority)
{
    struct ofputil_flow_mod fm;
    int error;

    fm.match = *match;
    fm.priority = priority;
    fm.new_cookie = htonll(0);
    fm.cookie = htonll(0);
    fm.cookie_mask = htonll(0);
    fm.modify_cookie = false;
    fm.table_id = TBL_INTERNAL;
    fm.flags = OFPUTIL_FF_HIDDEN_FIELDS | OFPUTIL_FF_NO_READONLY;
    fm.command = OFPFC_DELETE_STRICT;

    error = ofproto_flow_mod(&ofproto->up, &fm);
    if (error) {
        VLOG_ERR_RL(&rl, "failed to delete internal flow (%s)",
                    ofperr_to_string(error));
        return error;
    }

    return 0;
}

const struct ofproto_class ofproto_dpif_class = {
    init,
    enumerate_types,
    enumerate_names,
    del,
    port_open_type,
    type_run,
    type_wait,
    alloc,
    construct,
    destruct,
    dealloc,
    run,
    wait,
    NULL,                       /* get_memory_usage. */
    type_get_memory_usage,
    flush,
    query_tables,
    port_alloc,
    port_construct,
    port_destruct,
    port_dealloc,
    port_modified,
    port_reconfigured,
    port_query_by_name,
    port_add,
    port_del,
    port_get_stats,
    port_dump_start,
    port_dump_next,
    port_dump_done,
    port_poll,
    port_poll_wait,
    port_is_lacp_current,
    port_get_lacp_stats,
    NULL,                       /* rule_choose_table */
    rule_alloc,
    rule_construct,
    rule_insert,
    rule_delete,
    rule_destruct,
    rule_dealloc,
    rule_get_stats,
    rule_execute,
    NULL,                       /* rule_premodify_actions */
    rule_modify_actions,
    set_frag_handling,
    packet_out,
    set_netflow,
    get_netflow_ids,
    set_sflow,
    set_ipfix,
    set_cfm,
    cfm_status_changed,
    get_cfm_status,
    set_lldp,
    get_lldp_status,
    set_aa,
    aa_mapping_set,
    aa_mapping_unset,
    aa_vlan_get_queued,
    aa_vlan_get_queue_size,
    set_bfd,
    bfd_status_changed,
    get_bfd_status,
    set_stp,
    get_stp_status,
    set_stp_port,
    get_stp_port_status,
    get_stp_port_stats,
    set_rstp,
    get_rstp_status,
    set_rstp_port,
    get_rstp_port_status,
    set_queues,
    bundle_set,
    bundle_remove,
    mirror_set__,
    mirror_get_stats__,
    set_flood_vlans,
    is_mirror_output_bundle,
    forward_bpdu_changed,
    set_mac_table_config,
    set_mcast_snooping,
    set_mcast_snooping_port,
    set_realdev,
    NULL,                       /* meter_get_features */
    NULL,                       /* meter_set */
    NULL,                       /* meter_get */
    NULL,                       /* meter_del */
    group_alloc,                /* group_alloc */
    group_construct,            /* group_construct */
    group_destruct,             /* group_destruct */
    group_dealloc,              /* group_dealloc */
    group_modify,               /* group_modify */
    group_get_stats,            /* group_get_stats */
    get_datapath_version,       /* get_datapath_version */
};
