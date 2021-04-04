/*
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
#include <errno.h>

#include "bfd.h"
#include "bond.h"
#include "bundle.h"
#include "byte-order.h"
#include "connectivity.h"
#include "connmgr.h"
#include "coverage.h"
#include "cfm.h"
#include "ct-dpif.h"
#include "fail-open.h"
#include "guarded-list.h"
#include "hmapx.h"
#include "lacp.h"
#include "learn.h"
#include "mac-learning.h"
#include "math.h"
#include "mcast-snooping.h"
#include "multipath.h"
#include "netdev-vport.h"
#include "netdev.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-util.h"
#include "odp-execute.h"
#include "ofproto/ofproto-dpif.h"
#include "ofproto/ofproto-provider.h"
#include "ofproto-dpif-ipfix.h"
#include "ofproto-dpif-mirror.h"
#include "ofproto-dpif-monitor.h"
#include "ofproto-dpif-rid.h"
#include "ofproto-dpif-sflow.h"
#include "ofproto-dpif-trace.h"
#include "ofproto-dpif-upcall.h"
#include "ofproto-dpif-xlate.h"
#include "ofproto-dpif-xlate-cache.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/uuid.h"
#include "openvswitch/vlog.h"
#include "ovs-lldp.h"
#include "ovs-rcu.h"
#include "ovs-router.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "simap.h"
#include "smap.h"
#include "timer.h"
#include "tunnel.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "vlan-bitmap.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif);

COVERAGE_DEFINE(ofproto_dpif_expired);
COVERAGE_DEFINE(packet_in_overflow);

struct flow_miss;

static void rule_get_stats(struct rule *, struct pkt_stats *stats,
                           long long int *used);
static struct rule_dpif *rule_dpif_cast(const struct rule *);
static void rule_expire(struct rule_dpif *, long long now);

struct ofbundle {
    struct hmap_node hmap_node; /* In struct ofproto's "bundles" hmap. */
    struct ofproto_dpif *ofproto; /* Owning ofproto. */
    void *aux;                  /* Key supplied by ofproto's client. */
    char *name;                 /* Identifier for log messages. */

    /* Configuration. */
    struct ovs_list ports;      /* Contains "struct ofport_dpif"s. */
    enum port_vlan_mode vlan_mode; /* VLAN mode */
    uint16_t qinq_ethtype;
    int vlan;                   /* -1=trunk port, else a 12-bit VLAN ID. */
    unsigned long *trunks;      /* Bitmap of trunked VLANs, if 'vlan' == -1.
                                 * NULL if all VLANs are trunked. */
    unsigned long *cvlans;
    struct lacp *lacp;          /* LACP if LACP is enabled, otherwise NULL. */
    struct bond *bond;          /* Nonnull iff more than one port. */
    enum port_priority_tags_mode use_priority_tags;
                                /* Use 802.1p tag for frames in VLAN 0? */

    bool protected;             /* Protected port mode */

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
    bool is_tunnel;             /* This port is a tunnel. */
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
};

struct ct_timeout_policy {
    int ref_count;              /* The number of ct zones that use this
                                 * timeout policy. */
    uint32_t tp_id;             /* Timeout policy id in the datapath. */
    struct simap tp;            /* A map from timeout policy attribute to
                                 * timeout value. */
    struct hmap_node node;      /* Element in struct dpif_backer's "ct_tps"
                                 * cmap. */
    struct ovs_list list_node;  /* Element in struct dpif_backer's
                                 * "ct_tp_kill_list" list. */
};

/* Periodically try to purge deleted timeout policies from the datapath. Retry
 * may be necessary if the kernel datapath has a non-zero datapath flow
 * reference count for the timeout policy. */
#define TIMEOUT_POLICY_CLEANUP_INTERVAL (20000) /* 20 seconds. */
static long long int timeout_policy_cleanup_timer = LLONG_MIN;

struct ct_zone {
    uint16_t zone_id;
    struct ct_timeout_policy *ct_tp;
    struct cmap_node node;          /* Element in struct dpif_backer's
                                     * "ct_zones" cmap. */
};

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

COVERAGE_DEFINE(rev_reconfigure);
COVERAGE_DEFINE(rev_stp);
COVERAGE_DEFINE(rev_rstp);
COVERAGE_DEFINE(rev_bond);
COVERAGE_DEFINE(rev_port_toggled);
COVERAGE_DEFINE(rev_flow_table);
COVERAGE_DEFINE(rev_mac_learning);
COVERAGE_DEFINE(rev_mcast_snooping);

/* All existing ofproto_backer instances, indexed by ofproto->up.type. */
struct shash all_dpif_backers = SHASH_INITIALIZER(&all_dpif_backers);

/* All existing ofproto_dpif instances, indexed by ->up.name. */
static struct hmap all_ofproto_dpifs_by_name =
                          HMAP_INITIALIZER(&all_ofproto_dpifs_by_name);

/* All existing ofproto_dpif instances, indexed by ->uuid. */
static struct hmap all_ofproto_dpifs_by_uuid =
                          HMAP_INITIALIZER(&all_ofproto_dpifs_by_uuid);

static bool ofproto_use_tnl_push_pop = true;
static void ofproto_unixctl_init(void);
static void ct_zone_config_init(struct dpif_backer *backer);
static void ct_zone_config_uninit(struct dpif_backer *backer);
static void ct_zone_timeout_policy_sweep(struct dpif_backer *backer);

static inline struct ofproto_dpif *
ofproto_dpif_cast(const struct ofproto *ofproto)
{
    ovs_assert(ofproto->ofproto_class == &ofproto_dpif_class);
    return CONTAINER_OF(ofproto, struct ofproto_dpif, up);
}

/* Global variables. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Initial mappings of port to bridge mappings. */
static struct shash init_ofp_ports = SHASH_INITIALIZER(&init_ofp_ports);

/* Initialize 'ofm' for a learn action.  If the rule already existed, reference
 * to that rule is taken, otherwise a new rule is created.  'ofm' keeps the
 * rule reference in both cases. */
enum ofperr
ofproto_dpif_flow_mod_init_for_learn(struct ofproto_dpif *ofproto,
                                     const struct ofputil_flow_mod *fm,
                                     struct ofproto_flow_mod *ofm)
{
    /* This will not take the global 'ofproto_mutex'. */
    return ofproto_flow_mod_init_for_learn(&ofproto->up, fm, ofm);
}

/* Appends 'am' to the queue of asynchronous messages to be sent to the
 * controller.  Takes ownership of 'am' and any data it points to. */
void
ofproto_dpif_send_async_msg(struct ofproto_dpif *ofproto,
                            struct ofproto_async_msg *am)
{
    if (!guarded_list_push_back(&ofproto->ams, &am->list_node, 1024)) {
        COVERAGE_INC(packet_in_overflow);
        ofproto_async_msg_free(am);
    }

    /* Wakes up main thread for packet-in I/O. */
    seq_change(ofproto->ams_seq);
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

    ofproto_unixctl_init();
    ofproto_dpif_trace_init();
    udpif_init();
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
    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                   &all_ofproto_dpifs_by_name) {
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

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                   &all_ofproto_dpifs_by_name) {
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

    if (backer->need_revalidate) {
        struct ofproto_dpif *ofproto;
        struct simap_node *node;
        struct simap tmp_backers;

        /* Handle tunnel garbage collection. */
        simap_init(&tmp_backers);
        simap_swap(&backer->tnl_backers, &tmp_backers);

        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                       &all_ofproto_dpifs_by_name) {
            struct ofport_dpif *iter;

            if (backer != ofproto->backer) {
                continue;
            }

            HMAP_FOR_EACH (iter, up.hmap_node, &ofproto->up.ports) {
                char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
                const char *dp_port;
                odp_port_t old_odp_port;

                if (!iter->is_tunnel) {
                    continue;
                }

                dp_port = netdev_vport_get_dpif_port(iter->up.netdev,
                                                     namebuf, sizeof namebuf);
                old_odp_port = iter->odp_port;
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
                                         iter->odp_port, old_odp_port,
                                         ovs_native_tunneling_is_on(ofproto), dp_port)) {
                    backer->need_revalidate = REV_RECONFIGURE;
                }
            }
        }

        SIMAP_FOR_EACH (node, &tmp_backers) {
            dpif_port_del(backer->dpif, u32_to_odp(node->data), false);
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

        xlate_txn_start();
        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                       &all_ofproto_dpifs_by_name) {
            struct ofport_dpif *ofport;
            struct ofbundle *bundle;

            if (ofproto->backer != backer) {
                continue;
            }

            xlate_ofproto_set(ofproto, ofproto->up.name,
                              ofproto->backer->dpif, ofproto->ml,
                              ofproto->stp, ofproto->rstp, ofproto->ms,
                              ofproto->mbridge, ofproto->sflow, ofproto->ipfix,
                              ofproto->netflow,
                              ofproto->up.forward_bpdu,
                              connmgr_has_in_band(ofproto->up.connmgr),
                              &ofproto->backer->rt_support);

            HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
                xlate_bundle_set(ofproto, bundle, bundle->name,
                                 bundle->vlan_mode, bundle->qinq_ethtype,
                                 bundle->vlan, bundle->trunks, bundle->cvlans,
                                 bundle->use_priority_tags,
                                 bundle->bond, bundle->lacp,
                                 bundle->floodable, bundle->protected);
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
                                 ofport->up.may_enable);
            }
        }
        xlate_txn_commit();

        udpif_revalidate(backer->udpif);
    }

    process_dpif_port_changes(backer);
    ct_zone_timeout_policy_sweep(backer);

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
    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                   &all_ofproto_dpifs_by_name) {
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

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                   &all_ofproto_dpifs_by_name) {
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
        dpif_port_del(backer->dpif, port.port_no, false);
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

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                   &all_ofproto_dpifs_by_name) {
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
close_dpif_backer(struct dpif_backer *backer, bool del)
{
    struct simap_node *node;

    ovs_assert(backer->refcount > 0);

    if (--backer->refcount) {
        return;
    }

    udpif_destroy(backer->udpif);

    if (del) {
        SIMAP_FOR_EACH (node, &backer->tnl_backers) {
            dpif_port_del(backer->dpif, u32_to_odp(node->data), false);
        }
    }
    simap_destroy(&backer->tnl_backers);
    ovs_rwlock_destroy(&backer->odp_to_ofport_lock);
    hmap_destroy(&backer->odp_to_ofport_map);
    shash_find_and_delete(&all_dpif_backers, backer->type);
    free(backer->type);
    free(backer->dp_version_string);
    if (del) {
        dpif_delete(backer->dpif);
    }
    dpif_close(backer->dpif);
    id_pool_destroy(backer->meter_ids);
    ct_zone_config_uninit(backer);
    free(backer);
}

/* Datapath port slated for removal from datapath. */
struct odp_garbage {
    struct ovs_list list_node;
    odp_port_t odp_port;
};

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
    ovs_list_init(&garbage_list);
    dpif_port_dump_start(&port_dump, backer->dpif);
    while (dpif_port_dump_next(&port_dump, &port)) {
        node = shash_find(&init_ofp_ports, port.name);
        if (!node && strcmp(port.name, dpif_base_name(backer->dpif))) {
            garbage = xmalloc(sizeof *garbage);
            garbage->odp_port = port.port_no;
            ovs_list_push_front(&garbage_list, &garbage->list_node);
        }
    }
    dpif_port_dump_done(&port_dump);

    LIST_FOR_EACH_POP (garbage, list_node, &garbage_list) {
        dpif_port_del(backer->dpif, garbage->odp_port, false);
        free(garbage);
    }

    shash_add(&all_dpif_backers, type, backer);

    check_support(backer);
    atomic_count_init(&backer->tnl_count, 0);

    error = dpif_recv_set(backer->dpif, backer->recv_set_enable);
    if (error) {
        VLOG_ERR("failed to listen on datapath of type %s: %s",
                 type, ovs_strerror(error));
        close_dpif_backer(backer, false);
        return error;
    }

    if (backer->recv_set_enable) {
        udpif_set_threads(backer->udpif, n_handlers, n_revalidators);
    }

    backer->dp_version_string = dpif_get_dp_version(backer->dpif);

    /* Manage Datapath meter IDs if supported. */
    struct ofputil_meter_features features;
    dpif_meter_get_features(backer->dpif, &features);
    if (features.max_meters) {
        backer->meter_ids = id_pool_create(0, features.max_meters);
    } else {
        backer->meter_ids = NULL;
    }

    ct_zone_config_init(backer);

    /* Make a pristine snapshot of 'support' into 'boottime_support'.
     * 'boottime_support' can be checked to prevent 'support' to be changed
     * beyond the datapath capabilities. In case 'support' is changed by
     * the user, 'boottime_support' can be used to restore it.  */
    backer->bt_support = backer->rt_support;

    return error;
}

bool
ovs_native_tunneling_is_on(struct ofproto_dpif *ofproto)
{
    return ofproto_use_tnl_push_pop
        && ofproto->backer->rt_support.tnl_push_pop
        && atomic_count_get(&ofproto->backer->tnl_count);
}

bool
ovs_explicit_drop_action_supported(struct ofproto_dpif *ofproto)
{
    return ofproto->backer->rt_support.explicit_drop_action;
}

bool
ovs_lb_output_action_supported(struct ofproto_dpif *ofproto)
{
    return ofproto->backer->rt_support.lb_output_action;
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
    struct odp_flow_key_parms odp_parms = {
        .flow = &flow,
        .support = {
            .recirc = true,
        },
    };

    memset(&flow, 0, sizeof flow);
    flow.recirc_id = 1;
    flow.dp_hash = 1;

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&odp_parms, &key);
    enable_recirc = dpif_probe_feature(backer->dpif, "recirculation", &key,
                                       NULL, NULL);

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
    struct odp_flow_key_parms odp_parms = {
        .flow = &flow,
    };

    memset(&flow, 0, sizeof flow);
    flow.dl_type = htons(0x1234);

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&odp_parms, &key);
    odp_flow_key_hash(key.data, key.size, &ufid);

    enable_ufid = dpif_probe_feature(backer->dpif, "UFID", &key, NULL, &ufid);

    if (enable_ufid) {
        VLOG_INFO("%s: Datapath supports unique flow ids",
                  dpif_name(backer->dpif));
    } else {
        VLOG_INFO("%s: Datapath does not support unique flow ids",
                  dpif_name(backer->dpif));
    }
    return enable_ufid;
}

/* Tests number of 802.1q VLAN headers supported by 'backer''s datapath.
 *
 * Returns the number of elements in a struct flow's vlan
 * if the datapath supports at least that many VLAN headers. */
static size_t
check_max_vlan_headers(struct dpif_backer *backer)
{
    struct flow flow;
    struct odp_flow_key_parms odp_parms = {
        .flow = &flow,
        .probe = true,
    };
    int n;

    memset(&flow, 0, sizeof flow);
    flow.dl_type = htons(ETH_TYPE_IP);
    for (n = 0; n < FLOW_MAX_VLAN_HEADERS; n++) {
        struct odputil_keybuf keybuf;
        struct ofpbuf key;

        flow_push_vlan_uninit(&flow, NULL);
        flow.vlans[0].tpid = htons(ETH_TYPE_VLAN);
        flow.vlans[0].tci = htons(1) | htons(VLAN_CFI);

        ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
        odp_flow_key_from_flow(&odp_parms, &key);
        if (!dpif_probe_feature(backer->dpif, "VLAN", &key, NULL, NULL)) {
            break;
        }
    }

    VLOG_INFO("%s: VLAN header stack length probed as %d",
              dpif_name(backer->dpif), n);
    return n;
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
        struct odp_flow_key_parms odp_parms = {
            .flow = &flow,
        };

        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_MPLS);
        flow_set_mpls_bos(&flow, n, 1);

        ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
        odp_flow_key_from_flow(&odp_parms, &key);
        if (!dpif_probe_feature(backer->dpif, "MPLS", &key, NULL, NULL)) {
            break;
        }
    }

    VLOG_INFO("%s: MPLS label stack length probed as %d",
              dpif_name(backer->dpif), n);
    return n;
}

static void
add_sample_actions(struct ofpbuf *actions, int nesting)
{
    if (nesting == 0) {
        nl_msg_put_odp_port(actions, OVS_ACTION_ATTR_OUTPUT, u32_to_odp(1));
        return;
    }

    size_t start, actions_start;

    start = nl_msg_start_nested(actions, OVS_ACTION_ATTR_SAMPLE);
    actions_start = nl_msg_start_nested(actions, OVS_SAMPLE_ATTR_ACTIONS);
    add_sample_actions(actions, nesting - 1);
    nl_msg_end_nested(actions, actions_start);
    nl_msg_put_u32(actions, OVS_SAMPLE_ATTR_PROBABILITY, UINT32_MAX);
    nl_msg_end_nested(actions, start);
}

/* Tests the nested sample actions levels supported by 'backer''s datapath.
 *
 * Returns the number of nested sample actions accepted by the datapath.  */
static size_t
check_max_sample_nesting(struct dpif_backer *backer)
{
    struct odputil_keybuf keybuf;
    struct ofpbuf key;
    struct flow flow;
    int n;

    struct odp_flow_key_parms odp_parms = {
        .flow = &flow,
    };

    memset(&flow, 0, sizeof flow);
    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&odp_parms, &key);

    /* OVS datapath has always supported at least 3 nested levels.  */
    for (n = 3; n < FLOW_MAX_SAMPLE_NESTING; n++) {
        struct ofpbuf actions;
        bool ok;

        ofpbuf_init(&actions, 300);
        add_sample_actions(&actions, n);
        ok = dpif_probe_feature(backer->dpif, "Sample action nesting", &key,
                                &actions, NULL);
        ofpbuf_uninit(&actions);
        if (!ok) {
            break;
        }
    }

    VLOG_INFO("%s: Max sample nesting level probed as %d",
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
    struct dp_packet packet;
    struct flow flow;
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

    flow_extract(&packet, &flow);

    /* Execute the actions.  On older datapaths this fails with EINVAL, on
     * newer datapaths it succeeds. */
    struct dpif_execute execute = {
        .actions = actions.data,
        .actions_len = actions.size,
        .packet = &packet,
        .flow = &flow,
        .probe = true,
    };
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

/* Tests whether 'backer''s datapath supports truncation of a packet in
 * OVS_ACTION_ATTR_TRUNC.  We need to disable some features on older
 * datapaths that don't support this feature. */
static bool
check_trunc_action(struct dpif_backer *backer)
{
    struct eth_header *eth;
    struct ofpbuf actions;
    struct dp_packet packet;
    struct ovs_action_trunc *trunc;
    struct flow flow;
    int error;

    /* Compose an action with output(port:1,
     *              max_len:OVS_ACTION_OUTPUT_MIN + 1).
     * This translates to one truncate action and one output action. */
    ofpbuf_init(&actions, 64);
    trunc = nl_msg_put_unspec_uninit(&actions,
                            OVS_ACTION_ATTR_TRUNC, sizeof *trunc);

    trunc->max_len = ETH_HEADER_LEN + 1;
    nl_msg_put_odp_port(&actions, OVS_ACTION_ATTR_OUTPUT, u32_to_odp(1));

    /* Compose a dummy Ethernet packet. */
    dp_packet_init(&packet, ETH_HEADER_LEN);
    eth = dp_packet_put_zeros(&packet, ETH_HEADER_LEN);
    eth->eth_type = htons(0x1234);

    flow_extract(&packet, &flow);

    /* Execute the actions.  On older datapaths this fails with EINVAL, on
     * newer datapaths it succeeds. */
    struct dpif_execute execute = {
        .actions = actions.data,
        .actions_len = actions.size,
        .packet = &packet,
        .flow = &flow,
        .probe = true,
    };
    error = dpif_execute(backer->dpif, &execute);

    dp_packet_uninit(&packet);
    ofpbuf_uninit(&actions);

    if (error) {
        VLOG_INFO("%s: Datapath does not support truncate action",
                  dpif_name(backer->dpif));
    } else {
        VLOG_INFO("%s: Datapath supports truncate action",
                  dpif_name(backer->dpif));
    }

    return !error;
}

/* Tests whether 'backer''s datapath supports the clone action
 * OVS_ACTION_ATTR_CLONE.   */
static bool
check_clone(struct dpif_backer *backer)
{
    struct eth_header *eth;
    struct flow flow;
    struct dp_packet packet;
    struct ofpbuf actions;
    size_t clone_start;
    int error;

    /* Compose clone with an empty action list.
     * and check if datapath can decode the message.  */
    ofpbuf_init(&actions, 64);
    clone_start = nl_msg_start_nested(&actions, OVS_ACTION_ATTR_CLONE);
    nl_msg_end_nested(&actions, clone_start);

    /* Compose a dummy Ethernet packet. */
    dp_packet_init(&packet, ETH_HEADER_LEN);
    eth = dp_packet_put_zeros(&packet, ETH_HEADER_LEN);
    eth->eth_type = htons(0x1234);

    flow_extract(&packet, &flow);

    /* Execute the actions.  On older datapaths this fails with EINVAL, on
     * newer datapaths it succeeds. */
    struct dpif_execute execute = {
        .actions = actions.data,
        .actions_len = actions.size,
        .packet = &packet,
        .flow = &flow,
        .probe = true,
    };
    error = dpif_execute(backer->dpif, &execute);

    dp_packet_uninit(&packet);
    ofpbuf_uninit(&actions);

    if (error) {
        VLOG_INFO("%s: Datapath does not support clone action",
                  dpif_name(backer->dpif));
    } else {
        VLOG_INFO("%s: Datapath supports clone action",
                  dpif_name(backer->dpif));
    }

    return !error;
}

/* Tests whether 'backer''s datapath supports the OVS_CT_ATTR_EVENTMASK
 * attribute in OVS_ACTION_ATTR_CT. */
static bool
check_ct_eventmask(struct dpif_backer *backer)
{
    struct dp_packet packet;
    struct ofpbuf actions;
    struct flow flow = {
        .dl_type = CONSTANT_HTONS(ETH_TYPE_IP),
        .nw_proto = IPPROTO_UDP,
        .nw_ttl = 64,
        /* Use the broadcast address on the loopback address range 127/8 to
         * avoid hitting any real conntrack entries.  We leave the UDP ports to
         * zeroes for the same purpose. */
        .nw_src = CONSTANT_HTONL(0x7fffffff),
        .nw_dst = CONSTANT_HTONL(0x7fffffff),
    };
    size_t ct_start;
    int error;

    /* Compose CT action with eventmask attribute and check if datapath can
     * decode the message.  */
    ofpbuf_init(&actions, 64);
    ct_start = nl_msg_start_nested(&actions, OVS_ACTION_ATTR_CT);
    /* Eventmask has no effect without the commit flag, but currently the
     * datapath will accept an eventmask even without commit.  This is useful
     * as we do not want to persist the probe connection in the conntrack
     * table. */
    nl_msg_put_u32(&actions, OVS_CT_ATTR_EVENTMASK, ~0);
    nl_msg_end_nested(&actions, ct_start);

    /* Compose a dummy UDP packet. */
    dp_packet_init(&packet, 0);
    flow_compose(&packet, &flow, NULL, 64);

    /* Execute the actions.  On older datapaths this fails with EINVAL, on
     * newer datapaths it succeeds. */
    struct dpif_execute execute = {
        .actions = actions.data,
        .actions_len = actions.size,
        .packet = &packet,
        .flow = &flow,
        .probe = true,
    };
    error = dpif_execute(backer->dpif, &execute);

    dp_packet_uninit(&packet);
    ofpbuf_uninit(&actions);

    if (error) {
        VLOG_INFO("%s: Datapath does not support eventmask in conntrack action",
                  dpif_name(backer->dpif));
    } else {
        VLOG_INFO("%s: Datapath supports eventmask in conntrack action",
                  dpif_name(backer->dpif));
    }

    return !error;
}

/* Tests whether 'backer''s datapath supports the OVS_ACTION_ATTR_CT_CLEAR
 * action. */
static bool
check_ct_clear(struct dpif_backer *backer)
{
    struct odputil_keybuf keybuf;
    uint8_t actbuf[NL_A_FLAG_SIZE];
    struct ofpbuf actions;
    struct ofpbuf key;
    struct flow flow;
    bool supported;

    struct odp_flow_key_parms odp_parms = {
        .flow = &flow,
        .probe = true,
    };

    memset(&flow, 0, sizeof flow);
    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&odp_parms, &key);

    ofpbuf_use_stack(&actions, &actbuf, sizeof actbuf);
    nl_msg_put_flag(&actions, OVS_ACTION_ATTR_CT_CLEAR);

    supported = dpif_probe_feature(backer->dpif, "ct_clear", &key,
                                   &actions, NULL);

    VLOG_INFO("%s: Datapath %s ct_clear action",
              dpif_name(backer->dpif), (supported) ? "supports"
                                                   : "does not support");
    return supported;
}

/* Tests whether 'backer''s datapath supports the OVS_CT_ATTR_TIMEOUT
 * attribute in OVS_ACTION_ATTR_CT. */
static bool
check_ct_timeout_policy(struct dpif_backer *backer)
{
    struct dp_packet packet;
    struct ofpbuf actions;
    struct flow flow = {
        .dl_type = CONSTANT_HTONS(ETH_TYPE_IP),
        .nw_proto = IPPROTO_UDP,
        .nw_ttl = 64,
        /* Use the broadcast address on the loopback address range 127/8 to
         * avoid hitting any real conntrack entries.  We leave the UDP ports to
         * zeroes for the same purpose. */
        .nw_src = CONSTANT_HTONL(0x7fffffff),
        .nw_dst = CONSTANT_HTONL(0x7fffffff),
    };
    size_t ct_start;
    int error;

    /* Compose CT action with timeout policy attribute and check if datapath
     * can decode the message.  */
    ofpbuf_init(&actions, 64);
    ct_start = nl_msg_start_nested(&actions, OVS_ACTION_ATTR_CT);
    /* Timeout policy has no effect without the commit flag, but currently the
     * datapath will accept a timeout policy even without commit.  This is
     * useful as we do not want to persist the probe connection in the
     * conntrack table. */
    nl_msg_put_string(&actions, OVS_CT_ATTR_TIMEOUT, "ovs_test_tp");
    nl_msg_end_nested(&actions, ct_start);

    /* Compose a dummy UDP packet. */
    dp_packet_init(&packet, 0);
    flow_compose(&packet, &flow, NULL, 64);

    /* Execute the actions.  On older datapaths this fails with EINVAL, on
     * newer datapaths it succeeds. */
    struct dpif_execute execute = {
        .actions = actions.data,
        .actions_len = actions.size,
        .packet = &packet,
        .flow = &flow,
        .probe = true,
    };
    error = dpif_execute(backer->dpif, &execute);

    dp_packet_uninit(&packet);
    ofpbuf_uninit(&actions);

    if (error) {
        VLOG_INFO("%s: Datapath does not support timeout policy in conntrack "
                  "action", dpif_name(backer->dpif));
    } else {
        VLOG_INFO("%s: Datapath supports timeout policy in conntrack action",
                  dpif_name(backer->dpif));
    }

    return !error;
}

/* Tests whether 'backer''s datapath supports the
 * OVS_ACTION_ATTR_CHECK_PKT_LEN action. */
static bool
check_check_pkt_len(struct dpif_backer *backer)
{
    struct odputil_keybuf keybuf;
    struct ofpbuf actions;
    struct ofpbuf key;
    struct flow flow;
    bool supported;

    struct odp_flow_key_parms odp_parms = {
        .flow = &flow,
        .probe = true,
    };

    memset(&flow, 0, sizeof flow);
    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&odp_parms, &key);
    ofpbuf_init(&actions, 64);
    size_t cpl_start;

    cpl_start = nl_msg_start_nested(&actions, OVS_ACTION_ATTR_CHECK_PKT_LEN);
    nl_msg_put_u16(&actions, OVS_CHECK_PKT_LEN_ATTR_PKT_LEN, 100);

    /* Putting these actions without any data is good enough to check
     * if check_pkt_len is supported or not. */
    nl_msg_put_flag(&actions, OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER);
    nl_msg_put_flag(&actions, OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL);

    nl_msg_end_nested(&actions, cpl_start);

    supported = dpif_probe_feature(backer->dpif, "check_pkt_len", &key,
                                   &actions, NULL);
    ofpbuf_uninit(&actions);
    VLOG_INFO("%s: Datapath %s check_pkt_len action",
              dpif_name(backer->dpif), supported ? "supports"
                                                 : "does not support");
    return supported;
}

/* Probe the highest dp_hash algorithm supported by the datapath. */
static size_t
check_max_dp_hash_alg(struct dpif_backer *backer)
{
    struct odputil_keybuf keybuf;
    struct ofpbuf key;
    struct flow flow;
    struct ovs_action_hash *hash;
    int max_alg = 0;

    struct odp_flow_key_parms odp_parms = {
        .flow = &flow,
        .probe = true,
    };

    memset(&flow, 0, sizeof flow);
    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&odp_parms, &key);

    /* All datapaths support algortithm 0 (OVS_HASH_ALG_L4). */
    for (int alg = 1; alg < __OVS_HASH_MAX; alg++) {
        struct ofpbuf actions;
        bool ok;

        ofpbuf_init(&actions, 300);
        hash = nl_msg_put_unspec_uninit(&actions,
                                        OVS_ACTION_ATTR_HASH, sizeof *hash);
        hash->hash_basis = 0;
        hash->hash_alg = alg;
        ok = dpif_probe_feature(backer->dpif, "Max dp_hash algorithm", &key,
                                &actions, NULL);
        ofpbuf_uninit(&actions);
        if (ok) {
            max_alg = alg;
        } else {
            break;
        }
    }

    VLOG_INFO("%s: Max dp_hash algorithm probed to be %d",
            dpif_name(backer->dpif), max_alg);
    return max_alg;
}

/* Tests whether 'backer''s datapath supports IPv6 ND extensions.
 * Only userspace datapath support OVS_KEY_ATTR_ND_EXTENSIONS in keys.
 *
 * Returns false if 'backer' definitely does not support matching and
 * setting reserved and options type, true if it seems to support. */
static bool
check_nd_extensions(struct dpif_backer *backer)
{
    struct eth_header *eth;
    struct ofpbuf actions;
    struct dp_packet packet;
    struct flow flow;
    int error;
    struct ovs_key_nd_extensions key, mask;

    ofpbuf_init(&actions, 64);
    memset(&key, 0x53, sizeof key);
    memset(&mask, 0x7f, sizeof mask);
    commit_masked_set_action(&actions, OVS_KEY_ATTR_ND_EXTENSIONS, &key, &mask,
                             sizeof key);

    /* Compose a dummy ethernet packet. */
    dp_packet_init(&packet, ETH_HEADER_LEN);
    eth = dp_packet_put_zeros(&packet, ETH_HEADER_LEN);
    eth->eth_type = htons(0x1234);

    flow_extract(&packet, &flow);

    /* Execute the actions.  On datapaths without support fails with EINVAL. */
    struct dpif_execute execute = {
        .actions = actions.data,
        .actions_len = actions.size,
        .packet = &packet,
        .flow = &flow,
        .probe = true,
    };
    error = dpif_execute(backer->dpif, &execute);

    dp_packet_uninit(&packet);
    ofpbuf_uninit(&actions);

    VLOG_INFO("%s: Datapath %s IPv6 ND Extensions", dpif_name(backer->dpif),
              error ? "does not support" : "supports");

    return !error;
}

#define CHECK_FEATURE__(NAME, SUPPORT, FIELD, VALUE, ETHTYPE)               \
static bool                                                                 \
check_##NAME(struct dpif_backer *backer)                                    \
{                                                                           \
    struct flow flow;                                                       \
    struct odputil_keybuf keybuf;                                           \
    struct ofpbuf key;                                                      \
    bool enable;                                                            \
    struct odp_flow_key_parms odp_parms = {                                 \
        .flow = &flow,                                                      \
        .support = {                                                        \
            .SUPPORT = true,                                                \
        },                                                                  \
    };                                                                      \
                                                                            \
    memset(&flow, 0, sizeof flow);                                          \
    flow.FIELD = VALUE;                                                     \
    flow.dl_type = htons(ETHTYPE);                                          \
                                                                            \
    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);                         \
    odp_flow_key_from_flow(&odp_parms, &key);                               \
    enable = dpif_probe_feature(backer->dpif, #NAME, &key, NULL, NULL);     \
                                                                            \
    if (enable) {                                                           \
        VLOG_INFO("%s: Datapath supports "#NAME, dpif_name(backer->dpif));  \
    } else {                                                                \
        VLOG_INFO("%s: Datapath does not support "#NAME,                    \
                  dpif_name(backer->dpif));                                 \
    }                                                                       \
                                                                            \
    return enable;                                                          \
}
#define CHECK_FEATURE(FIELD) CHECK_FEATURE__(FIELD, FIELD, FIELD, 1, \
                                             ETH_TYPE_IP)

CHECK_FEATURE(ct_state)
CHECK_FEATURE(ct_zone)
CHECK_FEATURE(ct_mark)
CHECK_FEATURE__(ct_label, ct_label, ct_label.u64.lo, 1, ETH_TYPE_IP)
CHECK_FEATURE__(ct_state_nat, ct_state, ct_state, \
                CS_TRACKED|CS_SRC_NAT, ETH_TYPE_IP)
CHECK_FEATURE__(ct_orig_tuple, ct_orig_tuple, ct_nw_proto, 1, ETH_TYPE_IP)
CHECK_FEATURE__(ct_orig_tuple6, ct_orig_tuple6, ct_nw_proto, 1, ETH_TYPE_IPV6)

#undef CHECK_FEATURE
#undef CHECK_FEATURE__

static void
check_support(struct dpif_backer *backer)
{
    /* Actions. */
    backer->rt_support.odp.recirc = check_recirc(backer);
    backer->rt_support.odp.max_vlan_headers = check_max_vlan_headers(backer);
    backer->rt_support.odp.max_mpls_depth = check_max_mpls_depth(backer);
    backer->rt_support.masked_set_action = check_masked_set_action(backer);
    backer->rt_support.trunc = check_trunc_action(backer);
    backer->rt_support.ufid = check_ufid(backer);
    backer->rt_support.tnl_push_pop = dpif_supports_tnl_push_pop(backer->dpif);
    backer->rt_support.clone = check_clone(backer);
    backer->rt_support.sample_nesting = check_max_sample_nesting(backer);
    backer->rt_support.ct_eventmask = check_ct_eventmask(backer);
    backer->rt_support.ct_clear = check_ct_clear(backer);
    backer->rt_support.max_hash_alg = check_max_dp_hash_alg(backer);
    backer->rt_support.check_pkt_len = check_check_pkt_len(backer);
    backer->rt_support.ct_timeout = check_ct_timeout_policy(backer);
    backer->rt_support.explicit_drop_action =
        dpif_supports_explicit_drop_action(backer->dpif);
    backer->rt_support.lb_output_action=
        dpif_supports_lb_output_action(backer->dpif);

    /* Flow fields. */
    backer->rt_support.odp.ct_state = check_ct_state(backer);
    backer->rt_support.odp.ct_zone = check_ct_zone(backer);
    backer->rt_support.odp.ct_mark = check_ct_mark(backer);
    backer->rt_support.odp.ct_label = check_ct_label(backer);
    backer->rt_support.odp.ct_state_nat = check_ct_state_nat(backer);
    backer->rt_support.odp.ct_orig_tuple = check_ct_orig_tuple(backer);
    backer->rt_support.odp.ct_orig_tuple6 = check_ct_orig_tuple6(backer);
    backer->rt_support.odp.nd_ext = check_nd_extensions(backer);
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

    uuid_generate(&ofproto->uuid);
    atomic_init(&ofproto->tables_version, OVS_VERSION_MIN);
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

    guarded_list_init(&ofproto->ams);

    sset_init(&ofproto->ports);
    sset_init(&ofproto->ghost_ports);
    sset_init(&ofproto->port_poll_set);
    ofproto->port_poll_errno = 0;
    ofproto->change_seq = 0;
    ofproto->ams_seq = seq_create();
    ofproto->ams_seqno = seq_read(ofproto->ams_seq);


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

    hmap_insert(&all_ofproto_dpifs_by_name,
                &ofproto->all_ofproto_dpifs_by_name_node,
                hash_string(ofproto->up.name, 0));
    hmap_insert(&all_ofproto_dpifs_by_uuid,
                &ofproto->all_ofproto_dpifs_by_uuid_node,
                uuid_hash(&ofproto->uuid));
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
    controller->reason = OFPR_IMPLICIT_MISS;
    controller->meter_id = NX_CTLR_NO_METER;
    ofpact_finish_CONTROLLER(&ofpacts, &controller);

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
destruct(struct ofproto *ofproto_, bool del)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofproto_async_msg *am;
    struct rule_dpif *rule;
    struct oftable *table;
    struct ovs_list ams;

    ofproto->backer->need_revalidate = REV_RECONFIGURE;
    xlate_txn_start();
    xlate_remove_ofproto(ofproto);
    xlate_txn_commit();

    hmap_remove(&all_ofproto_dpifs_by_name,
                &ofproto->all_ofproto_dpifs_by_name_node);
    hmap_remove(&all_ofproto_dpifs_by_uuid,
                &ofproto->all_ofproto_dpifs_by_uuid_node);

    OFPROTO_FOR_EACH_TABLE (table, &ofproto->up) {
        CLS_FOR_EACH (rule, up.cr, &table->cls) {
            ofproto_rule_delete(&ofproto->up, &rule->up);
        }
    }
    ofproto_group_delete_all(&ofproto->up);

    guarded_list_pop_all(&ofproto->ams, &ams);
    LIST_FOR_EACH_POP (am, list_node, &ams) {
        ofproto_async_msg_free(am);
    }
    guarded_list_destroy(&ofproto->ams);

    recirc_free_ofproto(ofproto, ofproto->up.name);

    mbridge_unref(ofproto->mbridge);

    netflow_unref(ofproto->netflow);
    dpif_sflow_unref(ofproto->sflow);
    dpif_ipfix_unref(ofproto->ipfix);
    hmap_destroy(&ofproto->bundles);
    mac_learning_unref(ofproto->ml);
    mcast_snooping_unref(ofproto->ms);
    stp_unref(ofproto->stp);
    rstp_unref(ofproto->rstp);

    sset_destroy(&ofproto->ports);
    sset_destroy(&ofproto->ghost_ports);
    sset_destroy(&ofproto->port_poll_set);

    ovs_mutex_destroy(&ofproto->stats_mutex);

    seq_destroy(ofproto->ams_seq);

    close_dpif_backer(ofproto->backer, del);
}

static int
run(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    uint64_t new_seq, new_dump_seq;
    bool is_connected;

    if (mbridge_need_revalidate(ofproto->mbridge)) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
        ovs_rwlock_wrlock(&ofproto->ml->rwlock);
        mac_learning_flush(ofproto->ml);
        ovs_rwlock_unlock(&ofproto->ml->rwlock);
        mcast_snooping_mdb_flush(ofproto->ms);
    }

    /* Always updates the ofproto->ams_seqno to avoid frequent wakeup during
     * flow restore.  Even though nothing is processed during flow restore,
     * all queued 'ams' will be handled immediately when flow restore
     * completes. */
    ofproto->ams_seqno = seq_read(ofproto->ams_seq);

    /* Do not perform any periodic activity required by 'ofproto' while
     * waiting for flow restore to complete. */
    if (!ofproto_get_flow_restore_wait()) {
        struct ofproto_async_msg *am;
        struct ovs_list ams;

        guarded_list_pop_all(&ofproto->ams, &ams);
        LIST_FOR_EACH_POP (am, list_node, &ams) {
            connmgr_send_async_msg(ofproto->up.connmgr, am);
            ofproto_async_msg_free(am);
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

    /* Check if controller connection is toggled. */
    is_connected = ofproto_is_alive(&ofproto->up);
    if (ofproto->is_controller_connected != is_connected) {
        ofproto->is_controller_connected = is_connected;
        /* Trigger revalidation as fast failover group monitoring
         * controller port may need to check liveness again. */
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
    }

    new_dump_seq = seq_read(udpif_dump_seq(ofproto->backer->udpif));
    if (ofproto->dump_seq != new_dump_seq) {
        struct rule *rule, *next_rule;
        long long now = time_msec();

        /* We know stats are relatively fresh, so now is a good time to do some
         * periodic work. */
        ofproto->dump_seq = new_dump_seq;

        /* Expire OpenFlow flows whose idle_timeout or hard_timeout
         * has passed. */
        ovs_mutex_lock(&ofproto_mutex);
        LIST_FOR_EACH_SAFE (rule, next_rule, expirable,
                            &ofproto->up.expirable) {
            rule_expire(rule_dpif_cast(rule), now);
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
ofproto_dpif_wait(struct ofproto *ofproto_)
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
        poll_immediate_wake();
    }

    seq_wait(udpif_dump_seq(ofproto->backer->udpif), ofproto->dump_seq);
    seq_wait(ofproto->ams_seq, ofproto->ams_seqno);
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
             struct ofputil_table_features *features OVS_UNUSED,
             struct ofputil_table_stats *stats)
{
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

static void
set_tables_version(struct ofproto *ofproto_, ovs_version_t version)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    /* Use memory_order_release to signify that any prior memory accesses can
     * not be reordered to happen after this atomic store.  This makes sure the
     * new version is properly set up when the readers can read this 'version'
     * value. */
    atomic_store_explicit(&ofproto->tables_version, version,
                          memory_order_release);
    /* 'need_revalidate' can be reordered to happen before the atomic_store
     * above, but it does not matter as this variable is not accessed by other
     * threads. */
    ofproto->backer->need_revalidate = REV_FLOW_TABLE;
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
    port->stp_port = NULL;
    port->stp_state = STP_DISABLED;
    port->rstp_port = NULL;
    port->rstp_state = RSTP_DISABLED;
    port->is_tunnel = false;
    port->peer = NULL;
    port->qdscp = NULL;
    port->n_qdscp = 0;
    port->carrier_seq = netdev_get_carrier_resets(netdev);

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
    if (ofproto->ipfix) {
       dpif_ipfix_add_port(ofproto->ipfix, port_, port->odp_port);
    }

    return 0;
}

static void
port_destruct(struct ofport *port_, bool del)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);
    const char *devname = netdev_get_name(port->up.netdev);
    const char *netdev_type = netdev_get_type(port->up.netdev);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dp_port_name;

    ofproto->backer->need_revalidate = REV_RECONFIGURE;
    xlate_txn_start();
    xlate_ofport_remove(port);
    xlate_txn_commit();

    if (!del && strcmp(netdev_type,
                       ofproto_port_open_type(port->up.ofproto, "internal"))) {
        /* Check if datapath requires removal of attached ports.  Avoid
         * removal of 'internal' ports to preserve user ip/route settings. */
        del = dpif_cleanup_required(ofproto->backer->dpif);
    }

    dp_port_name = netdev_vport_get_dpif_port(port->up.netdev, namebuf,
                                              sizeof namebuf);
    if (del && dpif_port_exists(ofproto->backer->dpif, dp_port_name)) {
        /* The underlying device is still there, so delete it.  This
         * happens when the ofproto is being destroyed, since the caller
         * assumes that removal of attached ports will happen as part of
         * destruction. */
        if (!port->is_tunnel) {
            dpif_port_del(ofproto->backer->dpif, port->odp_port, false);
        }
    } else if (del) {
        /* The underlying device is already deleted (e.g. tunctl -d).
         * Calling dpif_port_remove to do local cleanup for the netdev */
        if (!port->is_tunnel) {
            dpif_port_del(ofproto->backer->dpif, port->odp_port, true);
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

    tnl_port_del(port, port->odp_port);
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
    if (ofproto->ipfix) {
       dpif_ipfix_del_port(ofproto->ipfix, port->odp_port);
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
        bond_member_set_netdev(port->bundle->bond, port, netdev);
    }

    if (port->cfm) {
        cfm_set_netdev(port->cfm, netdev);
    }

    if (port->bfd) {
        bfd_set_netdev(port->bfd, netdev);
    }

    ofproto_dpif_monitor_port_update(port, port->bfd, port->cfm,
                                     port->lldp, &port->up.pp.hw_addr);

    dp_port_name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

    if (port->is_tunnel) {
        struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);

        if (tnl_port_reconfigure(port, netdev, port->odp_port, port->odp_port,
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
    port_run(port);
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

        /* Add ports only when a new ipfix created */
        if (new_di == true) {
            struct ofport_dpif *ofport;
            HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
                dpif_ipfix_add_port(di, &ofport->up, ofport->odp_port);
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
get_ipfix_stats(const struct ofproto *ofproto_,
                bool bridge_ipfix,
                struct ovs_list *replies)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_ipfix *di = ofproto->ipfix;

    if (!di) {
        return OFPERR_NXST_NOT_CONFIGURED;
    }

    return dpif_ipfix_get_stats(di, bridge_ipfix, replies);
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
                                     ofport->lldp, &ofport->up.pp.hw_addr);
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
                                     ofport->lldp, &ofport->up.pp.hw_addr);
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
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    int error = 0;

    if (cfg) {
        if (!ofport->lldp) {
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
            ofport->lldp = lldp_create(ofport->up.netdev, ofport_->mtu, cfg);
        }

        if (!lldp_configure(ofport->lldp, cfg)) {
            lldp_unref(ofport->lldp);
            ofport->lldp = NULL;
            error = EINVAL;
        }
    } else if (ofport->lldp) {
        lldp_unref(ofport->lldp);
        ofport->lldp = NULL;
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
    }

    ofproto_dpif_monitor_port_update(ofport,
                                     ofport->bfd,
                                     ofport->cfm,
                                     ofport->lldp,
                                     &ofport->up.pp.hw_addr);
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
    struct eth_header *eth = dp_packet_eth(pkt);

    netdev_get_etheraddr(ofport->up.netdev, &eth->eth_src);
    if (eth_addr_is_zero(eth->eth_src)) {
        VLOG_WARN_RL(&rl, "%s port %d: cannot send RSTP BPDU on a port which "
                     "does not have a configured source MAC address.",
                     ofproto->up.name, ofp_to_u16(ofport->up.ofp_port));
    } else {
        ofproto_dpif_send_packet(ofport, false, pkt);
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
        struct eth_header *eth = dp_packet_eth(pkt);

        netdev_get_etheraddr(ofport->up.netdev, &eth->eth_src);
        if (eth_addr_is_zero(eth->eth_src)) {
            VLOG_WARN_RL(&rl, "%s: cannot send BPDU on port %d "
                         "with unknown MAC", ofproto->up.name, port_num);
        } else {
            ofproto_dpif_send_packet(ofport, false, pkt);
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
            struct ofport_dpif *old_root_aux =
                (struct ofport_dpif *)rstp_get_old_root_aux(ofproto->rstp);
            struct ofport_dpif *new_root_aux =
                (struct ofport_dpif *)rstp_get_new_root_aux(ofproto->rstp);
            if (old_root_aux != NULL && new_root_aux != NULL) {
                bundle_move(old_root_aux->bundle, new_root_aux->bundle);
                rstp_reset_root_changed(ofproto->rstp);
            }
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

static void
stp_check_and_update_link_state(struct ofproto_dpif *ofproto)
{
    struct ofport_dpif *ofport;

    HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
        bool up = netdev_get_carrier(ofport->up.netdev);

        if (ofport->stp_port &&
            up != (stp_port_get_state(ofport->stp_port) != STP_DISABLED)) {

            VLOG_DBG("bridge %s, port %s is %s, %s it.",
                     ofproto->up.name, netdev_get_name(ofport->up.netdev),
                     up ? "up" : "down",
                     up ? "enabling" : "disabling");

            if (up) {
                stp_port_enable(ofport->stp_port);
                stp_port_set_aux(ofport->stp_port, ofport);
            } else {
                stp_port_disable(ofport->stp_port);
            }

            update_stp_port_state(ofport);
        }
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

    if (netdev_get_carrier(ofport_->netdev)) {
        stp_port_enable(sp);
    } else {
        stp_port_disable(sp);
    }

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
    stp_port_get_status(sp, &s->port_id, &s->state, &s->role);
    s->sec_in_state = (time_msec() - ofport->stp_state_entered) / 1000;

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

        stp_check_and_update_link_state(ofproto);

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
            rstp_port_set_aux(rp, NULL);
            rstp_port_set_state(rp, RSTP_DISABLED);
            rstp_port_set_mac_operational(rp, false);
            ofport->rstp_port = NULL;
            rstp_port_unref(rp);
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
                  ofport, netdev_get_name(ofport->up.netdev));
    update_rstp_port_state(ofport);
    /* Synchronize operational status. */
    rstp_port_set_mac_operational(rp, ofport->up.may_enable);
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

                HMAP_FOR_EACH (o, all_ofproto_dpifs_by_name_node,
                               &all_ofproto_dpifs_by_name) {
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
            || netdev_get_pt_mode(port->up.netdev) == NETDEV_PT_LEGACY_L3
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

    ovs_list_remove(&port->bundle_node);
    port->bundle = NULL;

    if (bundle->lacp) {
        lacp_member_unregister(bundle->lacp, port);
    }
    if (bundle->bond) {
        bond_member_unregister(bundle->bond, port);
    }

    bundle_update(bundle);
}

static bool
bundle_add_port(struct ofbundle *bundle, ofp_port_t ofp_port,
                struct lacp_member_settings *lacp)
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
        ovs_list_push_back(&bundle->ports, &port->bundle_node);
        if (port->up.pp.config & OFPUTIL_PC_NO_FLOOD
            || netdev_get_pt_mode(port->up.netdev) == NETDEV_PT_LEGACY_L3
            || (bundle->ofproto->stp && !stp_forward_in_state(port->stp_state))
            || (bundle->ofproto->rstp && !rstp_forward_in_state(port->rstp_state))) {
            bundle->floodable = false;
        }
    }
    if (lacp) {
        bundle->ofproto->backer->need_revalidate = REV_RECONFIGURE;
        lacp_member_register(bundle->lacp, port, lacp);
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
    mcast_snooping_flush_bundle(ofproto->ms, bundle);
    hmap_remove(&ofproto->bundles, &bundle->hmap_node);
    free(bundle->name);
    free(bundle->trunks);
    free(bundle->cvlans);
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
    unsigned long *trunks = NULL;
    unsigned long *cvlans = NULL;
    int vlan;
    size_t i;
    bool ok;

    bundle = bundle_lookup(ofproto, aux);

    if (!s) {
        bundle_destroy(bundle);
        return 0;
    }

    ovs_assert(s->n_members == 1 || s->bond != NULL);
    ovs_assert((s->lacp != NULL) == (s->lacp_members != NULL));

    if (!bundle) {
        bundle = xmalloc(sizeof *bundle);

        bundle->ofproto = ofproto;
        hmap_insert(&ofproto->bundles, &bundle->hmap_node,
                    hash_pointer(aux, 0));
        bundle->aux = aux;
        bundle->name = NULL;

        ovs_list_init(&bundle->ports);
        bundle->vlan_mode = PORT_VLAN_TRUNK;
        bundle->qinq_ethtype = ETH_TYPE_VLAN_8021AD;
        bundle->vlan = -1;
        bundle->trunks = NULL;
        bundle->cvlans = NULL;
        bundle->use_priority_tags = s->use_priority_tags;
        bundle->lacp = NULL;
        bundle->bond = NULL;

        bundle->floodable = true;
        bundle->protected = false;
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
    for (i = 0; i < s->n_members; i++) {
        if (!bundle_add_port(bundle, s->members[i],
                             s->lacp ? &s->lacp_members[i] : NULL)) {
            ok = false;
        }
    }
    if (!ok || ovs_list_size(&bundle->ports) != s->n_members) {
        struct ofport_dpif *next_port;

        LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
            for (i = 0; i < s->n_members; i++) {
                if (s->members[i] == port->up.ofp_port) {
                    goto found;
                }
            }

            bundle_del_port(port);
        found: ;
        }
    }
    ovs_assert(ovs_list_size(&bundle->ports) <= s->n_members);

    if (ovs_list_is_empty(&bundle->ports)) {
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

    if (s->qinq_ethtype != bundle->qinq_ethtype) {
        bundle->qinq_ethtype = s->qinq_ethtype;
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

    case PORT_VLAN_DOT1Q_TUNNEL:
        cvlans = CONST_CAST(unsigned long *, s->cvlans);
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

    if (!vlan_bitmap_equal(cvlans, bundle->cvlans)) {
        free(bundle->cvlans);
        if (cvlans == s->cvlans) {
            bundle->cvlans = vlan_bitmap_clone(cvlans);
        } else {
            bundle->cvlans = cvlans;
            cvlans = NULL;
        }
        need_flush = true;
    }
    if (cvlans != s->cvlans) {
        free(cvlans);
    }

    /* Bonding. */
    if (!ovs_list_is_short(&bundle->ports)) {
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
            bond_member_register(bundle->bond, port,
                                 port->up.ofp_port, port->up.netdev);
        }
    } else {
        bond_unref(bundle->bond);
        bundle->bond = NULL;
    }

    /* Set proteced port mode */
    if (s->protected != bundle->protected) {
        bundle->protected = s->protected;
        need_flush = true;
    }

    /* If we changed something that would affect MAC learning, un-learn
     * everything on this port and force flow revalidation. */
    if (need_flush) {
        bundle_flush_macs(bundle, false);
        mcast_snooping_flush_bundle(ofproto->ms, bundle);
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
        if (ovs_list_is_empty(&bundle->ports)) {
            bundle_destroy(bundle);
        } else if (ovs_list_is_short(&bundle->ports)) {
            bond_unref(bundle->bond);
            bundle->bond = NULL;
        }
    }
}

int
ofproto_dpif_add_lb_output_buckets(struct ofproto_dpif *ofproto,
                                   uint32_t bond_id,
                                   const ofp_port_t *slave_map)
{
    odp_port_t odp_map[BOND_BUCKETS];

    for (int bucket = 0; bucket < BOND_BUCKETS; bucket++) {
        /* Convert ofp_port to odp_port. */
        odp_map[bucket] = ofp_port_to_odp_port(ofproto, slave_map[bucket]);
    }
    return dpif_bond_add(ofproto->backer->dpif, bond_id, odp_map);
}

int
ofproto_dpif_delete_lb_output_buckets(struct ofproto_dpif *ofproto,
                                      uint32_t bond_id)
{
    return dpif_bond_del(ofproto->backer->dpif, bond_id);
}

static void
send_pdu_cb(void *port_, const void *pdu, size_t pdu_size)
{
    struct ofport_dpif *port = port_;
    struct eth_addr ea;
    int error;

    error = netdev_get_etheraddr(port->up.netdev, &ea);
    if (!error) {
        struct dp_packet packet;
        void *packet_pdu;

        dp_packet_init(&packet, 0);
        packet_pdu = eth_compose(&packet, eth_addr_lacp, ea, ETH_TYPE_LACP,
                                 pdu_size);
        memcpy(packet_pdu, pdu, pdu_size);

        error = ofproto_dpif_send_packet(port, false, &packet);
        if (error) {
            VLOG_WARN_RL(&rl, "port %s: cannot transmit LACP PDU (%s).",
                         port->bundle->name, ovs_strerror(error));
        }
        dp_packet_uninit(&packet);
    } else {
        static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(1, 10);
        VLOG_ERR_RL(&rll, "port %s: cannot obtain Ethernet address of iface "
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

    ovs_list_init(&packets);
    ovs_rwlock_rdlock(&ofproto->ml->rwlock);
    LIST_FOR_EACH (e, lru_node, &ofproto->ml->lrus) {
        if (mac_entry_get_port(ofproto->ml, e) != bundle) {
            pkt_node = xmalloc(sizeof *pkt_node);
            pkt_node->pkt = bond_compose_learning_packet(bundle->bond,
                                                         e->mac, e->vlan,
                                                         (void **)&pkt_node->port);
            ovs_list_push_back(&packets, &pkt_node->list_node);
        }
    }
    ovs_rwlock_unlock(&ofproto->ml->rwlock);

    error = n_packets = n_errors = 0;
    LIST_FOR_EACH_POP (pkt_node, list_node, &packets) {
        int ret;

        ret = ofproto_dpif_send_packet(pkt_node->port, false, pkt_node->pkt);
        dp_packet_delete(pkt_node->pkt);
        free(pkt_node);
        if (ret) {
            error = ret;
            n_errors++;
        }
        n_packets++;
    }

    if (n_errors) {
        static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rll, "bond %s: %d errors sending %d gratuitous learning "
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
            bond_member_set_may_enable(bundle->bond, port, port->up.may_enable);
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
                       bundle_lookup(ofproto, s->out_bundle),
                       s->snaplen, s->out_vlan);
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

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                   &all_ofproto_dpifs_by_name) {
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

static bool
may_enable_port(struct ofport_dpif *ofport)
{
    /* If CFM or BFD is enabled, then at least one of them must report that the
     * port is up. */
    if ((ofport->bfd || ofport->cfm)
        && !(ofport->cfm
             && !cfm_get_fault(ofport->cfm)
             && cfm_get_opup(ofport->cfm) != 0)
        && !(ofport->bfd
             && bfd_forwarding(ofport->bfd))) {
        return false;
    }

    /* If LACP is enabled, it must report that the link is enabled. */
    if (ofport->bundle
        && !lacp_member_may_enable(ofport->bundle->lacp, ofport)) {
        return false;
    }

    return true;
}

static void
port_run(struct ofport_dpif *ofport)
{
    long long int carrier_seq = netdev_get_carrier_resets(ofport->up.netdev);
    bool carrier_changed = carrier_seq != ofport->carrier_seq;
    bool enable = netdev_get_carrier(ofport->up.netdev);

    ofport->carrier_seq = carrier_seq;
    if (carrier_changed && ofport->bundle) {
        lacp_member_carrier_changed(ofport->bundle->lacp, ofport, enable);
    }

    if (enable) {
        enable = may_enable_port(ofport);
    }

    if (ofport->up.may_enable != enable) {
        ofproto_port_set_enable(&ofport->up, enable);

        struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
        ofproto->backer->need_revalidate = REV_PORT_TOGGLED;

        if (ofport->rstp_port) {
            rstp_port_set_mac_operational(ofport->rstp_port, enable);
        }
    }
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
        error = dpif_port_del(ofproto->backer->dpif, ofport->odp_port, false);
        if (!error) {
            /* The caller is going to close ofport->up.netdev.  If this is a
             * bonded port, then the bond is using that netdev, so remove it
             * from the bond.  The client will need to reconfigure everything
             * after deleting ports, so then the member will get re-added. */
            bundle_remove(&ofport->up);
        }
    }
    return error;
}

static int
port_set_config(const struct ofport *ofport_, const struct smap *cfg)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);

    if (sset_contains(&ofproto->ghost_ports,
                      netdev_get_name(ofport->up.netdev))) {
        return 0;
    }

    return dpif_port_set_config(ofproto->backer->dpif, ofport->odp_port, cfg);
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
vport_get_status(const struct ofport *ofport_, char **errp)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    char *peer_name;

    if (!netdev_vport_is_patch(ofport->up.netdev) || ofport->peer) {
        return 0;
    }

    peer_name = netdev_vport_patch_peer(ofport->up.netdev);
    if (!peer_name) {
        return 0;
    }
    *errp = xasprintf("No usable peer '%s' exists in '%s' datapath.",
                      peer_name, ofport->up.ofproto->type);
    free(peer_name);
    return EINVAL;
}

static int
port_get_lacp_stats(const struct ofport *ofport_,
                    struct lacp_member_stats *stats)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    if (ofport->bundle && ofport->bundle->lacp) {
        if (lacp_get_member_stats(ofport->bundle->lacp, ofport, stats)) {
            return 0;
        }
    }
    return -1;
}

struct port_dump_state {
    struct sset_position pos;
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
    while ((node = sset_at_position(sset, &state->pos))) {
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
        memset(&state->pos, 0, sizeof state->pos);
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
            ? lacp_member_is_current(ofport->bundle->lacp, ofport)
            : -1);
}

/* If 'rule' is an OpenFlow rule, that has expired according to OpenFlow rules,
 * then delete it entirely. */
static void
rule_expire(struct rule_dpif *rule, long long now)
    OVS_REQUIRES(ofproto_mutex)
{
    uint16_t hard_timeout, idle_timeout;
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

static void
ofproto_dpif_set_packet_odp_port(const struct ofproto_dpif *ofproto,
                                 ofp_port_t in_port, struct dp_packet *packet)
{
    if (in_port == OFPP_NONE) {
        in_port = OFPP_LOCAL;
    }
    packet->md.in_port.odp_port = ofp_port_to_odp_port(ofproto, in_port);
}

int
ofproto_dpif_execute_actions__(struct ofproto_dpif *ofproto,
                               ovs_version_t version, const struct flow *flow,
                               struct rule_dpif *rule,
                               const struct ofpact *ofpacts, size_t ofpacts_len,
                               int depth, int resubmits,
                               struct dp_packet *packet)
{
    struct dpif_flow_stats stats;
    struct xlate_out xout;
    struct xlate_in xin;
    int error;

    ovs_assert((rule != NULL) != (ofpacts != NULL));

    dpif_flow_stats_extract(flow, packet, time_msec(), &stats);

    if (rule) {
        rule_dpif_credit_stats(rule, &stats, false);
    }

    uint64_t odp_actions_stub[1024 / 8];
    struct ofpbuf odp_actions = OFPBUF_STUB_INITIALIZER(odp_actions_stub);
    xlate_in_init(&xin, ofproto, version, flow, flow->in_port.ofp_port, rule,
                  stats.tcp_flags, packet, NULL, &odp_actions);
    xin.ofpacts = ofpacts;
    xin.ofpacts_len = ofpacts_len;
    xin.resubmit_stats = &stats;
    xin.depth = depth;
    xin.resubmits = resubmits;
    if (xlate_actions(&xin, &xout) != XLATE_OK) {
        error = EINVAL;
        goto out;
    }

    pkt_metadata_from_flow(&packet->md, flow);

    struct dpif_execute execute = {
        .actions = odp_actions.data,
        .actions_len = odp_actions.size,
        .packet = packet,
        .flow = flow,
        .needs_help = (xout.slow & SLOW_ACTION) != 0,
    };

    /* Fix up in_port. */
    ofproto_dpif_set_packet_odp_port(ofproto, flow->in_port.ofp_port, packet);

    error = dpif_execute(ofproto->backer->dpif, &execute);
out:
    xlate_out_uninit(&xout);
    ofpbuf_uninit(&odp_actions);

    return error;
}

/* Executes, within 'ofproto', the actions in 'rule' or 'ofpacts' on 'packet'.
 * 'flow' must reflect the data in 'packet'. */
int
ofproto_dpif_execute_actions(struct ofproto_dpif *ofproto,
                             ovs_version_t version, const struct flow *flow,
                             struct rule_dpif *rule,
                             const struct ofpact *ofpacts, size_t ofpacts_len,
                             struct dp_packet *packet)
{
    return ofproto_dpif_execute_actions__(ofproto, version, flow, rule,
                                          ofpacts, ofpacts_len, 0, 0, packet);
}

static void
rule_dpif_credit_stats__(struct rule_dpif *rule,
                         const struct dpif_flow_stats *stats,
                         bool credit_counts, bool offloaded)
    OVS_REQUIRES(rule->stats_mutex)
{
    if (credit_counts) {
        if (offloaded) {
            rule->stats.n_offload_packets += stats->n_packets;
            rule->stats.n_offload_bytes += stats->n_bytes;
        }
        rule->stats.n_packets += stats->n_packets;
        rule->stats.n_bytes += stats->n_bytes;
    }
    rule->stats.used = MAX(rule->stats.used, stats->used);
}

void
rule_dpif_credit_stats(struct rule_dpif *rule,
                       const struct dpif_flow_stats *stats, bool offloaded)
{
    ovs_mutex_lock(&rule->stats_mutex);
    if (OVS_UNLIKELY(rule->new_rule)) {
        ovs_mutex_lock(&rule->new_rule->stats_mutex);
        rule_dpif_credit_stats__(rule->new_rule, stats, rule->forward_counts,
                                 offloaded);
        ovs_mutex_unlock(&rule->new_rule->stats_mutex);
    } else {
        rule_dpif_credit_stats__(rule, stats, true, offloaded);
    }
    ovs_mutex_unlock(&rule->stats_mutex);
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

ovs_version_t
ofproto_dpif_get_tables_version(struct ofproto_dpif *ofproto)
{
    ovs_version_t version;

    /* Use memory_order_acquire to signify that any following memory accesses
     * can not be reordered to happen before this atomic read.  This makes sure
     * all following reads relate to this or a newer version, but never to an
     * older version. */
    atomic_read_explicit(&ofproto->tables_version, &version,
                         memory_order_acquire);
    return version;
}

/* The returned rule (if any) is valid at least until the next RCU quiescent
 * period.  If the rule needs to stay around longer, the caller should take
 * a reference.
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
static struct rule_dpif *
rule_dpif_lookup_in_table(struct ofproto_dpif *ofproto, ovs_version_t version,
                          uint8_t table_id, struct flow *flow,
                          struct flow_wildcards *wc)
{
    struct classifier *cls = &ofproto->up.tables[table_id].cls;
    return rule_dpif_cast(rule_from_cls_rule(classifier_lookup(cls, version,
                                                               flow, wc)));
}

void
ofproto_dpif_credit_table_stats(struct ofproto_dpif *ofproto, uint8_t table_id,
                                uint64_t n_matches, uint64_t n_misses)
{
    struct oftable *tbl = &ofproto->up.tables[table_id];
    unsigned long orig;

    if (n_matches) {
        atomic_add_relaxed(&tbl->n_matched, n_matches, &orig);
    }
    if (n_misses) {
        atomic_add_relaxed(&tbl->n_missed, n_misses, &orig);
    }
}

/* Look up 'flow' in 'ofproto''s classifier version 'version', starting from
 * table '*table_id'.  Returns the rule that was found, which may be one of the
 * special rules according to packet miss hadling.  If 'may_packet_in' is
 * false, returning of the miss_rule (which issues packet ins for the
 * controller) is avoided.  Updates 'wc', if nonnull, to reflect the fields
 * that were used during the lookup.
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
 * RCU quiescent period.  If the '*rule' needs to stay around longer, the
 * caller must take a reference.
 *
 * 'in_port' allows the lookup to take place as if the in port had the value
 * 'in_port'.  This is needed for resubmit action support.
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
struct rule_dpif *
rule_dpif_lookup_from_table(struct ofproto_dpif *ofproto,
                            ovs_version_t version, struct flow *flow,
                            struct flow_wildcards *wc,
                            const struct dpif_flow_stats *stats,
                            uint8_t *table_id, ofp_port_t in_port,
                            bool may_packet_in, bool honor_table_miss,
                            struct xlate_cache *xcache)
{
    ovs_be16 old_tp_src = flow->tp_src, old_tp_dst = flow->tp_dst;
    ofp_port_t old_in_port = flow->in_port.ofp_port;
    enum ofputil_table_miss miss_config;
    struct rule_dpif *rule;
    uint8_t next_id;

    /* We always unwildcard nw_frag (for IP), so they
     * need not be unwildcarded here. */
    if (flow->nw_frag & FLOW_NW_FRAG_ANY
        && ofproto->up.frag_handling != OFPUTIL_FRAG_NX_MATCH) {
        if (ofproto->up.frag_handling == OFPUTIL_FRAG_NORMAL) {
            /* We must pretend that transport ports are unavailable. */
            flow->tp_src = htons(0);
            flow->tp_dst = htons(0);
        } else {
            /* Must be OFPUTIL_FRAG_DROP (we don't have OFPUTIL_FRAG_REASM).
             * Use the drop_frags_rule (which cannot disappear). */
            rule = ofproto->drop_frags_rule;
            if (stats) {
                struct oftable *tbl = &ofproto->up.tables[*table_id];
                unsigned long orig;

                atomic_add_relaxed(&tbl->n_matched, stats->n_packets, &orig);
            }
            if (xcache) {
                struct xc_entry *entry;

                entry = xlate_cache_add_entry(xcache, XC_TABLE);
                entry->table.ofproto = ofproto;
                entry->table.id = *table_id;
                entry->table.match = true;
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
        rule = rule_dpif_lookup_in_table(ofproto, version, next_id, flow, wc);
        if (stats) {
            struct oftable *tbl = &ofproto->up.tables[next_id];
            unsigned long orig;

            atomic_add_relaxed(rule ? &tbl->n_matched : &tbl->n_missed,
                               stats->n_packets, &orig);
        }
        if (xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(xcache, XC_TABLE);
            entry->table.ofproto = ofproto;
            entry->table.id = next_id;
            entry->table.match = (rule != NULL);
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
                VLOG_WARN_RL(&rl, "packet-in on unknown OpenFlow port %"PRIu32,
                             old_in_port);
            } else if (!(port->up.pp.config & OFPUTIL_PC_NO_PACKET_IN)) {
                rule = ofproto->miss_rule;
            }
        } else if (miss_config == OFPUTIL_TABLE_MISS_DEFAULT &&
                   connmgr_wants_packet_in_on_miss(ofproto->up.connmgr)) {
            rule = ofproto->miss_rule;
        }
    }
out:
    /* Restore port numbers, as they may have been modified above. */
    flow->tp_src = old_tp_src;
    flow->tp_dst = old_tp_dst;
    /* Restore the old in port. */
    flow->in_port.ofp_port = old_in_port;

    return rule;
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
check_mask(struct ofproto_dpif *ofproto, const struct miniflow *flow)
{
    const struct odp_support *support;
    uint16_t ct_state, ct_zone;
    ovs_u128 ct_label;
    uint32_t ct_mark;

    support = &ofproto->backer->rt_support.odp;
    ct_state = MINIFLOW_GET_U8(flow, ct_state);

    if (ct_state & CS_UNSUPPORTED_MASK) {
        return OFPERR_OFPBMC_BAD_MASK;
    }

    /* Do not bother dissecting the flow further if the datapath supports all
     * the features we know of. */
    if (support->ct_state && support->ct_zone && support->ct_mark
        && support->ct_label && support->ct_state_nat
        && support->ct_orig_tuple && support->ct_orig_tuple6) {
        return 0;
    }

    ct_zone = MINIFLOW_GET_U16(flow, ct_zone);
    ct_mark = MINIFLOW_GET_U32(flow, ct_mark);
    ct_label = MINIFLOW_GET_U128(flow, ct_label);

    if ((ct_state && !support->ct_state)
        || ((ct_state & (CS_SRC_NAT | CS_DST_NAT)) && !support->ct_state_nat)
        || (ct_zone && !support->ct_zone)
        || (ct_mark && !support->ct_mark)
        || (!ovs_u128_is_zero(ct_label) && !support->ct_label)) {
        return OFPERR_NXBMC_CT_DATAPATH_SUPPORT;
    }

    if (!support->ct_orig_tuple && !support->ct_orig_tuple6
        && (MINIFLOW_GET_U8(flow, ct_nw_proto)
            || MINIFLOW_GET_U16(flow, ct_tp_src)
            || MINIFLOW_GET_U16(flow, ct_tp_dst))) {
        return OFPERR_NXBMC_CT_DATAPATH_SUPPORT;
    }

    if (!support->ct_orig_tuple
        && (MINIFLOW_GET_U32(flow, ct_nw_src)
            || MINIFLOW_GET_U32(flow, ct_nw_dst))) {
        return OFPERR_NXBMC_CT_DATAPATH_SUPPORT;
    }

    if (!support->ct_orig_tuple6
        && (!ovs_u128_is_zero(MINIFLOW_GET_U128(flow, ct_ipv6_src))
            || !ovs_u128_is_zero(MINIFLOW_GET_U128(flow, ct_ipv6_dst)))) {
        return OFPERR_NXBMC_CT_DATAPATH_SUPPORT;
    }

    return 0;
}

static void
report_unsupported_act(const char *action, const char *detail)
{
    static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(1, 5);
    VLOG_WARN_RL(&rll, "Rejecting %s action because datapath does not support"
                 "%s%s (your kernel module may be out of date)",
                 action, detail ? " " : "", detail ? detail : "");
}

static enum ofperr
check_actions(const struct ofproto_dpif *ofproto,
              const struct rule_actions *const actions)
{
    const struct ofpact *ofpact;
    const struct odp_support *support = &ofproto->backer->rt_support.odp;

    OFPACT_FOR_EACH (ofpact, actions->ofpacts, actions->ofpacts_len) {
        if (ofpact->type == OFPACT_CT) {
            const struct ofpact_conntrack *ct;
            const struct ofpact *a;

            ct = CONTAINER_OF(ofpact, struct ofpact_conntrack, ofpact);

            if (!support->ct_state) {
                report_unsupported_act("ct", "ct action");
                return OFPERR_NXBAC_CT_DATAPATH_SUPPORT;
            }
            if ((ct->zone_imm || ct->zone_src.field) && !support->ct_zone) {
                report_unsupported_act("ct", "ct zones");
                return OFPERR_NXBAC_CT_DATAPATH_SUPPORT;
            }
            /* So far the force commit feature is implemented together with the
             * original direction tuple feature by all datapaths, so we use the
             * support flag for the 'ct_orig_tuple' to indicate support for the
             * force commit feature as well. */
            if ((ct->flags & NX_CT_F_FORCE) && !support->ct_orig_tuple) {
                report_unsupported_act("ct", "force commit");
                return OFPERR_NXBAC_CT_DATAPATH_SUPPORT;
            }

            OFPACT_FOR_EACH(a, ct->actions, ofpact_ct_get_action_len(ct)) {
                const struct mf_field *dst = ofpact_get_mf_dst(a);

                if (a->type == OFPACT_NAT && !support->ct_state_nat) {
                    /* The backer doesn't seem to support the NAT bits in
                     * 'ct_state': assume that it doesn't support the NAT
                     * action. */
                    report_unsupported_act("ct", "nat");
                    return OFPERR_NXBAC_CT_DATAPATH_SUPPORT;
                }
                if (dst && ((dst->id == MFF_CT_MARK && !support->ct_mark) ||
                            (dst->id == MFF_CT_LABEL && !support->ct_label))) {
                    report_unsupported_act("ct", "setting mark and/or label");
                    return OFPERR_NXBAC_CT_DATAPATH_SUPPORT;
                }
            }
        } else if (ofpact->type == OFPACT_RESUBMIT) {
            struct ofpact_resubmit *resubmit = ofpact_get_RESUBMIT(ofpact);

            if (resubmit->with_ct_orig && !support->ct_orig_tuple) {
                report_unsupported_act("resubmit",
                                       "ct original direction tuple");
                return OFPERR_NXBAC_CT_DATAPATH_SUPPORT;
            }
        } else if (!support->nd_ext && ofpact->type == OFPACT_SET_FIELD) {
            const struct mf_field *dst = ofpact_get_mf_dst(ofpact);

            if (dst->id == MFF_ND_RESERVED || dst->id == MFF_ND_OPTIONS_TYPE) {
                report_unsupported_act("set field",
                                       "setting IPv6 ND Extensions fields");
                return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
            }
        }
    }

    return 0;
}

static enum ofperr
rule_check(struct rule *rule)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->ofproto);
    enum ofperr err;

    err = check_mask(ofproto, &rule->cr.match.mask->masks);
    if (err) {
        return err;
    }
    return check_actions(ofproto, rule->actions);
}

static enum ofperr
rule_construct(struct rule *rule_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    int error;

    error = rule_check(rule_);
    if (error) {
        return error;
    }

    ovs_mutex_init_adaptive(&rule->stats_mutex);
    rule->stats.n_packets = 0;
    rule->stats.n_bytes = 0;
    rule->stats.used = rule->up.modified;
    rule->recirc_id = 0;
    rule->new_rule = NULL;
    rule->forward_counts = false;

    return 0;
}

static enum ofperr
rule_insert(struct rule *rule_, struct rule *old_rule_, bool forward_counts)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);

    if (old_rule_) {
        struct rule_dpif *old_rule = rule_dpif_cast(old_rule_);

        ovs_assert(!old_rule->new_rule);

        /* Take a reference to the new rule, and refer all stats updates from
         * the old rule to the new rule. */
        ofproto_rule_ref(&rule->up);

        ovs_mutex_lock(&old_rule->stats_mutex);
        ovs_mutex_lock(&rule->stats_mutex);
        old_rule->new_rule = rule;       /* Forward future stats. */
        old_rule->forward_counts = forward_counts;

        if (forward_counts) {
            rule->stats = old_rule->stats;   /* Transfer stats to the new
                                              * rule. */
        } else {
            /* Used timestamp must be forwarded whenever a rule is modified. */
            rule->stats.used = old_rule->stats.used;
        }
        ovs_mutex_unlock(&rule->stats_mutex);
        ovs_mutex_unlock(&old_rule->stats_mutex);
    }

    return 0;
}

static void
rule_destruct(struct rule *rule_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);

    ovs_mutex_destroy(&rule->stats_mutex);
    /* Release reference to the new rule, if any. */
    if (rule->new_rule) {
        ofproto_rule_unref(&rule->new_rule->up);
    }
    if (rule->recirc_id) {
        recirc_free_id(rule->recirc_id);
    }
}

static void
rule_get_stats(struct rule *rule_, struct pkt_stats *stats,
               long long int *used)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);

    ovs_mutex_lock(&rule->stats_mutex);
    if (OVS_UNLIKELY(rule->new_rule)) {
        rule_get_stats(&rule->new_rule->up, stats, used);
    } else {
        stats->n_packets = rule->stats.n_packets;
        stats->n_bytes = rule->stats.n_bytes;
        stats->n_offload_packets = rule->stats.n_offload_packets;
        stats->n_offload_bytes = rule->stats.n_offload_bytes;
        *used = rule->stats.used;
    }
    ovs_mutex_unlock(&rule->stats_mutex);
}

struct ofproto_dpif_packet_out {
    struct xlate_cache xcache;
    struct ofpbuf odp_actions;
    struct recirc_refs rr;
    bool needs_help;
};


static struct ofproto_dpif_packet_out *
ofproto_dpif_packet_out_new(void)
{
    struct ofproto_dpif_packet_out *aux = xmalloc(sizeof *aux);
    xlate_cache_init(&aux->xcache);
    ofpbuf_init(&aux->odp_actions, 64);
    aux->rr = RECIRC_REFS_EMPTY_INITIALIZER;
    aux->needs_help = false;

    return aux;
}

static void
ofproto_dpif_packet_out_delete(struct ofproto_dpif_packet_out *aux)
{
    if (aux) {
        xlate_cache_uninit(&aux->xcache);
        ofpbuf_uninit(&aux->odp_actions);
        recirc_refs_unref(&aux->rr);
        free(aux);
    }
}

static enum ofperr
packet_xlate(struct ofproto *ofproto_, struct ofproto_packet_out *opo)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct xlate_out xout;
    struct xlate_in xin;
    enum ofperr error = 0;

    struct ofproto_dpif_packet_out *aux = ofproto_dpif_packet_out_new();

    xlate_in_init(&xin, ofproto, opo->version, opo->flow,
                  opo->flow->in_port.ofp_port, NULL, 0, opo->packet, NULL,
                  &aux->odp_actions);
    xin.ofpacts = opo->ofpacts;
    xin.ofpacts_len = opo->ofpacts_len;
    /* No learning or stats, but collect side effects to xcache. */
    xin.allow_side_effects = false;
    xin.resubmit_stats = NULL;
    xin.xcache = &aux->xcache;
    xin.in_packet_out = true;

    if (xlate_actions(&xin, &xout) != XLATE_OK) {
        error = OFPERR_OFPFMFC_UNKNOWN;   /* Error processing actions. */
        goto error_out;
    } else {
        /* Prepare learn actions. */
        struct xc_entry *entry;
        struct ofpbuf entries = aux->xcache.entries;

        XC_ENTRY_FOR_EACH (entry, &entries) {
            if (entry->type == XC_LEARN) {
                struct ofproto_flow_mod *ofm = entry->learn.ofm;

                error = ofproto_flow_mod_learn_refresh(ofm);
                if (error) {
                    goto error_out;
                }
                struct rule *rule = ofm->temp_rule;
                ofm->learn_adds_rule = (rule->state == RULE_INITIALIZED);
                if (ofm->learn_adds_rule) {
                    /* If learning on a different bridge, must use its next
                     * version number. */
                    ofm->version = (rule->ofproto == ofproto_)
                        ? opo->version : rule->ofproto->tables_version + 1;
                    error = ofproto_flow_mod_learn_start(ofm);
                    if (error) {
                        goto error_out;
                    }
                }
            }
        }

        /* Success. */
        aux->needs_help = (xout.slow & SLOW_ACTION) != 0;
        recirc_refs_swap(&aux->rr, &xout.recircs); /* Hold recirc refs. */
    }
    xlate_out_uninit(&xout);
    opo->aux = aux;
    return 0;

error_out:
    xlate_out_uninit(&xout);
    ofproto_dpif_packet_out_delete(aux);
    opo->aux = NULL;
    return error;
}

static void
packet_xlate_revert(struct ofproto *ofproto OVS_UNUSED,
                    struct ofproto_packet_out *opo)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto_dpif_packet_out *aux = opo->aux;
    ovs_assert(aux);

    /* Revert the learned flows. */
    struct xc_entry *entry;
    struct ofpbuf entries = aux->xcache.entries;

    XC_ENTRY_FOR_EACH (entry, &entries) {
        if (entry->type == XC_LEARN && entry->learn.ofm->learn_adds_rule) {
            ofproto_flow_mod_learn_revert(entry->learn.ofm);
        }
    }

    ofproto_dpif_packet_out_delete(aux);
    opo->aux = NULL;
}

/* Push stats and perform side effects of flow translation. */
static void
ofproto_dpif_xcache_execute(struct ofproto_dpif *ofproto,
                            struct xlate_cache *xcache,
                            struct dpif_flow_stats *stats)
    OVS_REQUIRES(ofproto_mutex)
{
    struct xc_entry *entry;
    struct ofpbuf entries = xcache->entries;

    XC_ENTRY_FOR_EACH (entry, &entries) {
        switch (entry->type) {
        case XC_LEARN:
            /* Finish the learned flows. */
            if (entry->learn.ofm->learn_adds_rule) {
                ofproto_flow_mod_learn_finish(entry->learn.ofm, &ofproto->up);
            }
            break;
        case XC_FIN_TIMEOUT:
            if (stats->tcp_flags & (TCP_FIN | TCP_RST)) {
                /* 'ofproto_mutex' already held */
                ofproto_rule_reduce_timeouts__(&entry->fin.rule->up,
                                               entry->fin.idle,
                                               entry->fin.hard);
            }
            break;
            /* All the rest can be dealt with by the xlate layer. */
        case XC_TABLE:
        case XC_RULE:
        case XC_BOND:
        case XC_NETDEV:
        case XC_NETFLOW:
        case XC_MIRROR:
        case XC_NORMAL:
        case XC_GROUP:
        case XC_TNL_NEIGH:
        case XC_TUNNEL_HEADER:
            xlate_push_stats_entry(entry, stats, false);
            break;
        default:
            OVS_NOT_REACHED();
        }
    }
}

static void
packet_execute_prepare(struct ofproto *ofproto_,
                       struct ofproto_packet_out *opo)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_flow_stats stats;
    struct dpif_execute *execute;

    struct ofproto_dpif_packet_out *aux = opo->aux;
    ovs_assert(aux);

    /* Run the side effects from the xcache. */
    dpif_flow_stats_extract(opo->flow, opo->packet, time_msec(), &stats);
    ofproto_dpif_xcache_execute(ofproto, &aux->xcache, &stats);

    execute = xzalloc(sizeof *execute);
    execute->actions = xmemdup(aux->odp_actions.data, aux->odp_actions.size);
    execute->actions_len = aux->odp_actions.size;

    pkt_metadata_from_flow(&opo->packet->md, opo->flow);
    execute->packet = opo->packet;
    execute->flow = opo->flow;
    execute->needs_help = aux->needs_help;
    execute->probe = false;
    execute->mtu = 0;

    /* Fix up in_port. */
    ofproto_dpif_set_packet_odp_port(ofproto, opo->flow->in_port.ofp_port,
                                     opo->packet);

    ofproto_dpif_packet_out_delete(aux);
    opo->aux = execute;
}

static void
packet_execute(struct ofproto *ofproto_, struct ofproto_packet_out *opo)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_execute *execute = opo->aux;

    if (!execute) {
        return;
    }

    dpif_execute(ofproto->backer->dpif, execute);

    free(CONST_CAST(struct nlattr *, execute->actions));
    free(execute);
    opo->aux = NULL;
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
    group->packet_count = 0;
    group->byte_count = 0;

    struct ofputil_bucket *bucket;
    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
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
        LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
            bucket->stats.packet_count += stats->n_packets;
            bucket->stats.byte_count += stats->n_bytes;
        }
    }
    ovs_mutex_unlock(&group->stats_mutex);
}

/* Calculate the dp_hash mask needed to provide the least weighted bucket
 * with at least one hash value and construct a mapping table from masked
 * dp_hash value to group bucket using the Webster method.
 * If the caller specifies a non-zero max_hash value, abort and return false
 * if more hash values would be required. The absolute maximum number of
 * hash values supported is 256. */

#define MAX_SELECT_GROUP_HASH_VALUES 256

static bool
group_setup_dp_hash_table(struct group_dpif *group, size_t max_hash)
{
    struct ofputil_bucket *bucket;
    uint32_t n_buckets = group->up.n_buckets;
    uint64_t total_weight = 0;
    uint16_t min_weight = UINT16_MAX;
    struct webster {
        struct ofputil_bucket *bucket;
        uint32_t divisor;
        double value;
        int hits;
    } *webster;

    if (n_buckets == 0) {
        VLOG_DBG("  Don't apply dp_hash method without buckets.");
        return false;
    }

    webster = xcalloc(n_buckets, sizeof(struct webster));
    int i = 0;
    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
        if (bucket->weight > 0 && bucket->weight < min_weight) {
            min_weight = bucket->weight;
        }
        total_weight += bucket->weight;
        webster[i].bucket = bucket;
        webster[i].divisor = 1;
        webster[i].value = bucket->weight;
        webster[i].hits = 0;
        i++;
    }

    if (total_weight == 0) {
        VLOG_DBG("  Total weight is zero. No active buckets.");
        free(webster);
        return false;
    }
    VLOG_DBG("  Minimum weight: %d, total weight: %"PRIu64,
             min_weight, total_weight);

    uint64_t min_slots = DIV_ROUND_UP(total_weight, min_weight);
    uint64_t min_slots2 = ROUND_UP_POW2(min_slots);
    uint64_t n_hash = MAX(16, min_slots2);
    if (n_hash > MAX_SELECT_GROUP_HASH_VALUES ||
        (max_hash != 0 && n_hash > max_hash)) {
        VLOG_DBG("  Too many hash values required: %"PRIu64, n_hash);
        free(webster);
        return false;
    }

    VLOG_DBG("  Using %"PRIu64" hash values:", n_hash);
    group->hash_mask = n_hash - 1;
    if (group->hash_map) {
        free(group->hash_map);
    }
    group->hash_map = xcalloc(n_hash, sizeof(struct ofputil_bucket *));

    /* Use Webster method to distribute hash values over buckets. */
    for (int hash = 0; hash < n_hash; hash++) {
        struct webster *winner = &webster[0];
        for (i = 1; i < n_buckets; i++) {
            if (webster[i].value > winner->value) {
                winner = &webster[i];
            }
        }
        winner->hits++;
        winner->divisor += 2;
        winner->value = (double) winner->bucket->weight / winner->divisor;
        group->hash_map[hash] = winner->bucket;
    }

    i = 0;
    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
        double target = (n_hash * bucket->weight) / (double) total_weight;
        VLOG_DBG("  Bucket %d: weight=%d, target=%.2f hits=%d",
                 bucket->bucket_id, bucket->weight,
                 target, webster[i].hits);
        i++;
    }

    free(webster);
    return true;
}

static void
group_set_selection_method(struct group_dpif *group)
{
    const struct ofputil_group_props *props = &group->up.props;
    const char *selection_method = props->selection_method;

    VLOG_DBG("Constructing select group %"PRIu32, group->up.group_id);
    if (selection_method[0] == '\0') {
        VLOG_DBG("No selection method specified. Trying dp_hash.");
        /* If the controller has not specified a selection method, check if
         * the dp_hash selection method with max 64 hash values is appropriate
         * for the given bucket configuration. */
        if (group_setup_dp_hash_table(group, 64)) {
            /* Use dp_hash selection method with symmetric L4 hash. */
            group->selection_method = SEL_METHOD_DP_HASH;
            group->hash_alg = OVS_HASH_ALG_SYM_L4;
            group->hash_basis = 0;
            VLOG_DBG("Use dp_hash with %d hash values using algorithm %d.",
                     group->hash_mask + 1, group->hash_alg);
        } else {
            /* Fall back to original default hashing in slow path. */
            VLOG_DBG("Falling back to default hash method.");
            group->selection_method = SEL_METHOD_DEFAULT;
        }
    } else if (!strcmp(selection_method, "dp_hash")) {
        VLOG_DBG("Selection method specified: dp_hash.");
        /* Try to use dp_hash if possible at all. */
        if (group_setup_dp_hash_table(group, 0)) {
            group->selection_method = SEL_METHOD_DP_HASH;
            group->hash_alg = props->selection_method_param >> 32;
            if (group->hash_alg >= __OVS_HASH_MAX) {
                VLOG_DBG("Invalid dp_hash algorithm %d. "
                         "Defaulting to OVS_HASH_ALG_L4", group->hash_alg);
                group->hash_alg = OVS_HASH_ALG_L4;
            }
            group->hash_basis = (uint32_t) props->selection_method_param;
            VLOG_DBG("Use dp_hash with %d hash values using algorithm %d.",
                     group->hash_mask + 1, group->hash_alg);
        } else {
            /* Fall back to original default hashing in slow path. */
            VLOG_DBG("Falling back to default hash method.");
            group->selection_method = SEL_METHOD_DEFAULT;
        }
    } else if (!strcmp(selection_method, "hash")) {
        VLOG_DBG("Selection method specified: hash.");
        if (props->fields.values_size > 0) {
            /* Controller has specified hash fields. */
            struct ds s = DS_EMPTY_INITIALIZER;
            oxm_format_field_array(&s, &props->fields);
            VLOG_DBG("Hash fields: %s", ds_cstr(&s));
            ds_destroy(&s);
            group->selection_method = SEL_METHOD_HASH;
        } else {
            /* No hash fields. Fall back to original default hashing. */
            VLOG_DBG("No hash fields. Falling back to default hash method.");
            group->selection_method = SEL_METHOD_DEFAULT;
        }
    } else {
        /* Parsing of groups should ensure this never happens */
        OVS_NOT_REACHED();
    }
}

static enum ofperr
group_construct(struct ofgroup *group_)
{
    struct group_dpif *group = group_dpif_cast(group_);

    ovs_mutex_init_adaptive(&group->stats_mutex);
    ovs_mutex_lock(&group->stats_mutex);
    group_construct_stats(group);
    group->hash_map = NULL;
    if (group->up.type == OFPGT11_SELECT) {
        group_set_selection_method(group);
    }
    ovs_mutex_unlock(&group->stats_mutex);
    return 0;
}

static void
group_destruct(struct ofgroup *group_)
{
    struct group_dpif *group = group_dpif_cast(group_);
    ovs_mutex_destroy(&group->stats_mutex);
    if (group->hash_map) {
        free(group->hash_map);
        group->hash_map = NULL;
    }
}

static enum ofperr
group_get_stats(const struct ofgroup *group_, struct ofputil_group_stats *ogs)
{
    struct group_dpif *group = group_dpif_cast(group_);

    ovs_mutex_lock(&group->stats_mutex);
    ogs->packet_count = group->packet_count;
    ogs->byte_count = group->byte_count;

    struct bucket_counter *bucket_stats = ogs->bucket_stats;
    struct ofputil_bucket *bucket;
    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
        bucket_stats->packet_count = bucket->stats.packet_count;
        bucket_stats->byte_count = bucket->stats.byte_count;
        bucket_stats++;
    }
    ovs_mutex_unlock(&group->stats_mutex);

    return 0;
}

/* If the group exists, this function increments the groups's reference count.
 *
 * Make sure to call ofproto_group_unref() after no longer needing to maintain
 * a reference to the group. */
struct group_dpif *
group_dpif_lookup(struct ofproto_dpif *ofproto, uint32_t group_id,
                  ovs_version_t version, bool take_ref)
{
    struct ofgroup *ofgroup = ofproto_group_lookup(&ofproto->up, group_id,
                                                   version, take_ref);
    return ofgroup ? group_dpif_cast(ofgroup) : NULL;
}

/* Sends 'packet' out 'ofport'. If 'port' is a tunnel and that tunnel type
 * supports a notion of an OAM flag, sets it if 'oam' is true.
 * May modify 'packet'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
ofproto_dpif_send_packet(const struct ofport_dpif *ofport, bool oam,
                         struct dp_packet *packet)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    int error;

    error = xlate_send_packet(ofport, oam, packet);

    ovs_mutex_lock(&ofproto->stats_mutex);
    ofproto->stats.tx_packets++;
    ofproto->stats.tx_bytes += dp_packet_size(packet);
    ovs_mutex_unlock(&ofproto->stats_mutex);
    return error;
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

static void
type_set_config(const char *type, const struct smap *other_config)
{
    struct dpif_backer *backer;

    backer = shash_find_data(&all_dpif_backers, type);
    if (!backer) {
        /* This is not necessarily a problem, since backers are only
         * created on demand. */
        return;
    }

    dpif_set_config(backer->dpif, other_config);
}

static void
ct_flush(const struct ofproto *ofproto_, const uint16_t *zone)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    ct_dpif_flush(ofproto->backer->dpif, zone, NULL);
}

static struct ct_timeout_policy *
ct_timeout_policy_lookup(const struct hmap *ct_tps, struct simap *tp)
{
    struct ct_timeout_policy *ct_tp;

    HMAP_FOR_EACH_WITH_HASH (ct_tp, node, simap_hash(tp), ct_tps) {
        if (simap_equal(&ct_tp->tp, tp)) {
            return ct_tp;
        }
    }
    return NULL;
}

static struct ct_timeout_policy *
ct_timeout_policy_alloc__(void)
{
    struct ct_timeout_policy *ct_tp = xzalloc(sizeof *ct_tp);
    simap_init(&ct_tp->tp);
    return ct_tp;
}

static struct ct_timeout_policy *
ct_timeout_policy_alloc(struct simap *tp, struct id_pool *tp_ids)
{
    struct simap_node *node;

    struct ct_timeout_policy *ct_tp = ct_timeout_policy_alloc__();
    SIMAP_FOR_EACH (node, tp) {
        simap_put(&ct_tp->tp, node->name, node->data);
    }

    if (!id_pool_alloc_id(tp_ids, &ct_tp->tp_id)) {
        VLOG_ERR_RL(&rl, "failed to allocate timeout policy id.");
        simap_destroy(&ct_tp->tp);
        free(ct_tp);
        return NULL;
    }

    return ct_tp;
}

static void
ct_timeout_policy_destroy__(struct ct_timeout_policy *ct_tp)
{
    simap_destroy(&ct_tp->tp);
    free(ct_tp);
}

static void
ct_timeout_policy_destroy(struct ct_timeout_policy *ct_tp,
                          struct id_pool *tp_ids)
{
    id_pool_free_id(tp_ids, ct_tp->tp_id);
    ovsrcu_postpone(ct_timeout_policy_destroy__, ct_tp);
}

static void
ct_timeout_policy_unref(struct dpif_backer *backer,
                        struct ct_timeout_policy *ct_tp)
{
    if (ct_tp) {
        ct_tp->ref_count--;

        if (!ct_tp->ref_count) {
            hmap_remove(&backer->ct_tps, &ct_tp->node);
            ovs_list_push_back(&backer->ct_tp_kill_list, &ct_tp->list_node);
        }
    }
}

static struct ct_zone *
ct_zone_lookup(const struct cmap *ct_zones, uint16_t zone_id)
{
    struct ct_zone *ct_zone;

    CMAP_FOR_EACH_WITH_HASH (ct_zone, node, hash_int(zone_id, 0), ct_zones) {
        if (ct_zone->zone_id == zone_id) {
            return ct_zone;
        }
    }
    return NULL;
}

static struct ct_zone *
ct_zone_alloc(uint16_t zone_id)
{
    struct ct_zone *ct_zone = xzalloc(sizeof *ct_zone);
    ct_zone->zone_id = zone_id;
    return ct_zone;
}

static void
ct_zone_destroy(struct ct_zone *ct_zone)
{
    ovsrcu_postpone(free, ct_zone);
}

static void
ct_zone_remove_and_destroy(struct dpif_backer *backer, struct ct_zone *ct_zone)
{
    cmap_remove(&backer->ct_zones, &ct_zone->node,
                hash_int(ct_zone->zone_id, 0));
    ct_zone_destroy(ct_zone);
}

static void
ct_add_timeout_policy_to_dpif(struct dpif *dpif,
                              struct ct_timeout_policy *ct_tp)
{
    struct ct_dpif_timeout_policy cdtp;
    struct simap_node *node;

    memset(&cdtp, 0, sizeof cdtp);

    cdtp.id = ct_tp->tp_id;
    SIMAP_FOR_EACH (node, &ct_tp->tp) {
        ct_dpif_set_timeout_policy_attr_by_name(&cdtp, node->name, node->data);
    }

    int err = ct_dpif_set_timeout_policy(dpif, &cdtp);
    if (err) {
        VLOG_ERR_RL(&rl, "failed to set timeout policy %"PRIu32" (%s)",
                    ct_tp->tp_id, ovs_strerror(err));
    }
}

static void
clear_existing_ct_timeout_policies(struct dpif_backer *backer)
{
    /* In kernel datapath, when OVS starts, there may be some pre-existing
     * timeout policies in the kernel.  To avoid reassigning the same timeout
     * policy ids, we dump all the pre-existing timeout policies and keep
     * the ids in the pool.  Since OVS will not use those timeout policies
     * for new datapath flow, we add them to the kill list and remove
     * them later on. */
    struct ct_dpif_timeout_policy cdtp;
    void *state;

    if (ct_dpif_timeout_policy_dump_start(backer->dpif, &state)) {
        return;
    }

    while (!ct_dpif_timeout_policy_dump_next(backer->dpif, state, &cdtp)) {
        struct ct_timeout_policy *ct_tp = ct_timeout_policy_alloc__();
        ct_tp->tp_id = cdtp.id;
        id_pool_add(backer->tp_ids, cdtp.id);
        ovs_list_push_back(&backer->ct_tp_kill_list, &ct_tp->list_node);
    }

    ct_dpif_timeout_policy_dump_done(backer->dpif, state);
}

#define MAX_TIMEOUT_POLICY_ID UINT32_MAX

static void
ct_zone_config_init(struct dpif_backer *backer)
{
    backer->tp_ids = id_pool_create(DEFAULT_TP_ID + 1,
                                    MAX_TIMEOUT_POLICY_ID - 1);
    cmap_init(&backer->ct_zones);
    hmap_init(&backer->ct_tps);
    ovs_list_init(&backer->ct_tp_kill_list);
    clear_existing_ct_timeout_policies(backer);
}

static void
ct_zone_config_uninit(struct dpif_backer *backer)
{
    struct ct_zone *ct_zone;
    CMAP_FOR_EACH (ct_zone, node, &backer->ct_zones) {
        ct_zone_remove_and_destroy(backer, ct_zone);
    }

    struct ct_timeout_policy *ct_tp;
    HMAP_FOR_EACH_POP (ct_tp, node, &backer->ct_tps) {
        ct_timeout_policy_destroy(ct_tp, backer->tp_ids);
    }

    LIST_FOR_EACH_POP (ct_tp, list_node, &backer->ct_tp_kill_list) {
        ct_timeout_policy_destroy(ct_tp, backer->tp_ids);
    }

    id_pool_destroy(backer->tp_ids);
    cmap_destroy(&backer->ct_zones);
    hmap_destroy(&backer->ct_tps);
}

static void
ct_zone_timeout_policy_sweep(struct dpif_backer *backer)
{
    if (!ovs_list_is_empty(&backer->ct_tp_kill_list)
        && time_msec() >= timeout_policy_cleanup_timer) {
        struct ct_timeout_policy *ct_tp, *next;

        LIST_FOR_EACH_SAFE (ct_tp, next, list_node, &backer->ct_tp_kill_list) {
            if (!ct_dpif_del_timeout_policy(backer->dpif, ct_tp->tp_id)) {
                ovs_list_remove(&ct_tp->list_node);
                ct_timeout_policy_destroy(ct_tp, backer->tp_ids);
            } else {
                /* INFO log raised by 'dpif' layer. */
            }
        }
        timeout_policy_cleanup_timer = time_msec() +
            TIMEOUT_POLICY_CLEANUP_INTERVAL;
    }
}

static void
ct_set_zone_timeout_policy(const char *datapath_type, uint16_t zone_id,
                           struct simap *timeout_policy)
{
    struct dpif_backer *backer = shash_find_data(&all_dpif_backers,
                                                 datapath_type);
    if (!backer) {
        return;
    }

    struct ct_timeout_policy *ct_tp = ct_timeout_policy_lookup(&backer->ct_tps,
                                                               timeout_policy);
    if (!ct_tp) {
        ct_tp = ct_timeout_policy_alloc(timeout_policy, backer->tp_ids);
        if (ct_tp) {
            hmap_insert(&backer->ct_tps, &ct_tp->node, simap_hash(&ct_tp->tp));
            ct_add_timeout_policy_to_dpif(backer->dpif, ct_tp);
        } else {
            return;
        }
    }

    struct ct_zone *ct_zone = ct_zone_lookup(&backer->ct_zones, zone_id);
    if (ct_zone) {
        if (ct_zone->ct_tp != ct_tp) {
            /* Update the zone timeout policy. */
            ct_timeout_policy_unref(backer, ct_zone->ct_tp);
            ct_zone->ct_tp = ct_tp;
            ct_tp->ref_count++;
        }
    } else {
        struct ct_zone *new_ct_zone = ct_zone_alloc(zone_id);
        new_ct_zone->ct_tp = ct_tp;
        cmap_insert(&backer->ct_zones, &new_ct_zone->node,
                    hash_int(zone_id, 0));
        ct_tp->ref_count++;
    }
}

static void
ct_del_zone_timeout_policy(const char *datapath_type, uint16_t zone_id)
{
    struct dpif_backer *backer = shash_find_data(&all_dpif_backers,
                                                 datapath_type);
    if (!backer) {
        return;
    }

    struct ct_zone *ct_zone = ct_zone_lookup(&backer->ct_zones, zone_id);
    if (ct_zone) {
        ct_timeout_policy_unref(backer, ct_zone->ct_tp);
        ct_zone_remove_and_destroy(backer, ct_zone);
    }
}

static void
get_datapath_cap(const char *datapath_type, struct smap *cap)
{
    struct odp_support odp;
    struct dpif_backer_support s;
    struct dpif_backer *backer = shash_find_data(&all_dpif_backers,
                                                 datapath_type);
    if (!backer) {
        return;
    }
    s = backer->rt_support;
    odp = s.odp;

    /* ODP_SUPPORT_FIELDS */
    smap_add_format(cap, "max_vlan_headers", "%"PRIuSIZE,
                    odp.max_vlan_headers);
    smap_add_format(cap, "max_mpls_depth", "%"PRIuSIZE, odp.max_mpls_depth);
    smap_add(cap, "recirc", odp.recirc ? "true" : "false");
    smap_add(cap, "ct_state", odp.ct_state ? "true" : "false");
    smap_add(cap, "ct_zone", odp.ct_zone ? "true" : "false");
    smap_add(cap, "ct_mark", odp.ct_mark ? "true" : "false");
    smap_add(cap, "ct_label", odp.ct_label ? "true" : "false");
    smap_add(cap, "ct_state_nat", odp.ct_state_nat ? "true" : "false");
    smap_add(cap, "ct_orig_tuple", odp.ct_orig_tuple ? "true" : "false");
    smap_add(cap, "ct_orig_tuple6", odp.ct_orig_tuple6 ? "true" : "false");
    smap_add(cap, "nd_ext", odp.nd_ext ? "true" : "false");

    /* DPIF_SUPPORT_FIELDS */
    smap_add(cap, "masked_set_action", s.masked_set_action ? "true" : "false");
    smap_add(cap, "tnl_push_pop", s.tnl_push_pop ? "true" : "false");
    smap_add(cap, "ufid", s.ufid ? "true" : "false");
    smap_add(cap, "trunc", s.trunc ? "true" : "false");
    smap_add(cap, "clone", s.clone ? "true" : "false");
    smap_add(cap, "sample_nesting", s.sample_nesting ? "true" : "false");
    smap_add(cap, "ct_eventmask", s.ct_eventmask ? "true" : "false");
    smap_add(cap, "ct_clear", s.ct_clear ? "true" : "false");
    smap_add_format(cap, "max_hash_alg", "%"PRIuSIZE, s.max_hash_alg);
    smap_add(cap, "check_pkt_len", s.check_pkt_len ? "true" : "false");
    smap_add(cap, "ct_timeout", s.ct_timeout ? "true" : "false");
    smap_add(cap, "explicit_drop_action",
             s.explicit_drop_action ? "true" :"false");
    smap_add(cap, "lb_output_action", s.lb_output_action ? "true" : "false");
}

/* Gets timeout policy name in 'backer' based on 'zone', 'dl_type' and
 * 'nw_proto'.  Returns true if the zone-based timeout policy is configured.
 * On success, stores the timeout policy name in 'tp_name', and sets
 * 'unwildcard' based on the dpif implementation.  If 'unwildcard' is true,
 * the returned timeout policy is 'dl_type' and 'nw_proto' specific, and OVS
 * needs to unwildcard the datapath flow for this timeout policy in flow
 * translation.
 *
 * The caller is responsible for freeing 'tp_name'. */
bool
ofproto_dpif_ct_zone_timeout_policy_get_name(
    const struct dpif_backer *backer, uint16_t zone, uint16_t dl_type,
    uint8_t nw_proto, char **tp_name, bool *unwildcard)
{
    if (!ct_dpif_timeout_policy_support_ipproto(nw_proto)) {
        return false;
    }

    struct ct_zone *ct_zone = ct_zone_lookup(&backer->ct_zones, zone);
    if (!ct_zone) {
        return false;
    }

    bool is_generic;
    if (ct_dpif_get_timeout_policy_name(backer->dpif,
                                        ct_zone->ct_tp->tp_id, dl_type,
                                        nw_proto, tp_name, &is_generic)) {
        return false;
    }

    /* Unwildcard datapath flow if it is not a generic timeout policy. */
    *unwildcard = !is_generic;
    return true;
}

static bool
set_frag_handling(struct ofproto *ofproto_,
                  enum ofputil_frag_handling frag_handling)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    if (frag_handling != OFPUTIL_FRAG_REASM) {
        ofproto->backer->need_revalidate = REV_RECONFIGURE;
        return true;
    } else {
        return false;
    }
}

static enum ofperr
nxt_resume(struct ofproto *ofproto_,
           const struct ofputil_packet_in_private *pin)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_flow_stats stats;
    struct xlate_cache xcache;
    struct flow flow;
    xlate_cache_init(&xcache);

    /* Translate pin into datapath actions. */
    uint64_t odp_actions_stub[1024 / 8];
    struct ofpbuf odp_actions = OFPBUF_STUB_INITIALIZER(odp_actions_stub);
    enum slow_path_reason slow;
    enum ofperr error = xlate_resume(ofproto, pin, &odp_actions, &slow,
                                     &flow, &xcache);

    /* Steal 'pin->packet' and put it into a dp_packet. */
    struct dp_packet packet;
    dp_packet_init(&packet, pin->base.packet_len);
    dp_packet_put(&packet, pin->base.packet, pin->base.packet_len);

    /* Run the side effects from the xcache. */
    dpif_flow_stats_extract(&flow, &packet, time_msec(), &stats);
    ovs_mutex_lock(&ofproto_mutex);
    ofproto_dpif_xcache_execute(ofproto, &xcache, &stats);
    ovs_mutex_unlock(&ofproto_mutex);

    pkt_metadata_from_flow(&packet.md, &pin->base.flow_metadata.flow);

    /* Fix up in_port. */
    packet.md.in_port.odp_port = pin->odp_port;

    struct flow headers;
    flow_extract(&packet, &headers);

    /* Execute the datapath actions on the packet. */
    struct dpif_execute execute = {
        .actions = odp_actions.data,
        .actions_len = odp_actions.size,
        .needs_help = (slow & SLOW_ACTION) != 0,
        .packet = &packet,
        .flow = &headers,
    };
    dpif_execute(ofproto->backer->dpif, &execute);

    /* Clean up. */
    ofpbuf_uninit(&odp_actions);
    dp_packet_uninit(&packet);
    xlate_cache_uninit(&xcache);

    return error;
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

struct ofproto_dpif *
ofproto_dpif_lookup_by_name(const char *name)
{
    struct ofproto_dpif *ofproto;

    HMAP_FOR_EACH_WITH_HASH (ofproto, all_ofproto_dpifs_by_name_node,
                             hash_string(name, 0),
                             &all_ofproto_dpifs_by_name) {
        if (!strcmp(ofproto->up.name, name)) {
            return ofproto;
        }
    }
    return NULL;
}

struct ofproto_dpif *
ofproto_dpif_lookup_by_uuid(const struct uuid *uuid)
{
    struct ofproto_dpif *ofproto;

    HMAP_FOR_EACH_WITH_HASH (ofproto, all_ofproto_dpifs_by_uuid_node,
                             uuid_hash(uuid), &all_ofproto_dpifs_by_uuid) {
        if (uuid_equals(&ofproto->uuid, uuid)) {
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
        ofproto = ofproto_dpif_lookup_by_name(argv[1]);
        if (!ofproto) {
            unixctl_command_reply_error(conn, "no such bridge");
            return;
        }
        ovs_rwlock_wrlock(&ofproto->ml->rwlock);
        mac_learning_flush(ofproto->ml);
        ovs_rwlock_unlock(&ofproto->ml->rwlock);
    } else {
        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                       &all_ofproto_dpifs_by_name) {
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
        ofproto = ofproto_dpif_lookup_by_name(argv[1]);
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
        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                       &all_ofproto_dpifs_by_name) {
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
    return CONTAINER_OF(ovs_list_front(&bundle->ports), struct ofport_dpif,
                        bundle_node);
}

static void
ofproto_unixctl_fdb_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                         const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct ofproto_dpif *ofproto;
    const struct mac_entry *e;

    ofproto = ofproto_dpif_lookup_by_name(argv[1]);
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
                               NULL, name, sizeof name);
        ds_put_format(&ds, "%5s  %4d  "ETH_ADDR_FMT"  %3d\n",
                      name, e->vlan, ETH_ADDR_ARGS(e->mac),
                      mac_entry_age(ofproto->ml, e));
    }
    ovs_rwlock_unlock(&ofproto->ml->rwlock);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ofproto_unixctl_fdb_stats_clear(struct unixctl_conn *conn, int argc,
                                const char *argv[], void *aux OVS_UNUSED)
{
    struct ofproto_dpif *ofproto;

    if (argc > 1) {
        ofproto = ofproto_dpif_lookup_by_name(argv[1]);
        if (!ofproto) {
            unixctl_command_reply_error(conn, "no such bridge");
            return;
        }
        ovs_rwlock_wrlock(&ofproto->ml->rwlock);
        mac_learning_clear_statistics(ofproto->ml);
        ovs_rwlock_unlock(&ofproto->ml->rwlock);
    } else {
        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                       &all_ofproto_dpifs_by_name) {
            ovs_rwlock_wrlock(&ofproto->ml->rwlock);
            mac_learning_clear_statistics(ofproto->ml);
            ovs_rwlock_unlock(&ofproto->ml->rwlock);
        }
    }

    unixctl_command_reply(conn, "statistics successfully cleared");
}

static void
ofproto_unixctl_fdb_stats_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                               const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct ofproto_dpif *ofproto;
    ofproto = ofproto_dpif_lookup_by_name(argv[1]);
    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    ds_put_format(&ds, "Statistics for bridge \"%s\":\n", argv[1]);
    ovs_rwlock_rdlock(&ofproto->ml->rwlock);

    ds_put_format(&ds, "  Current/maximum MAC entries in the table: %"
                  PRIuSIZE"/%"PRIuSIZE"\n",
                  hmap_count(&ofproto->ml->table), ofproto->ml->max_entries);
    ds_put_format(&ds,
                  "  Total number of learned MAC entries     : %"PRIu64"\n",
                  ofproto->ml->total_learned);
    ds_put_format(&ds,
                  "  Total number of expired MAC entries     : %"PRIu64"\n",
                  ofproto->ml->total_expired);
    ds_put_format(&ds,
                  "  Total number of evicted MAC entries     : %"PRIu64"\n",
                  ofproto->ml->total_evicted);
    ds_put_format(&ds,
                  "  Total number of port moved MAC entries  : %"PRIu64"\n",
                  ofproto->ml->total_moved);

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

    ofproto = ofproto_dpif_lookup_by_name(argv[1]);
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
                                   NULL, name, sizeof name);
            ds_put_format(&ds, "%5s  %4d  ", name, grp->vlan);
            ipv6_format_mapped(&grp->addr, &ds);
            ds_put_format(&ds, "         %3d\n",
                          mcast_bundle_age(ofproto->ms, b));
        }
    }

    /* ports connected to multicast routers */
    LIST_FOR_EACH(mrouter, mrouter_node, &ofproto->ms->mrouter_lru) {
        char name[OFP_MAX_PORT_NAME_LEN];

        bundle = mrouter->port;
        ofputil_port_to_string(ofbundle_get_a_port(bundle)->up.ofp_port,
                               NULL, name, sizeof name);
        ds_put_format(&ds, "%5s  %4d  querier             %3d\n",
                      name, mrouter->vlan,
                      mcast_mrouter_age(ofproto->ms, mrouter));
    }
    ovs_rwlock_unlock(&ofproto->ms->rwlock);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/* Store the current ofprotos in 'ofproto_shash'.  Returns a sorted list
 * of the 'ofproto_shash' nodes.  It is the responsibility of the caller
 * to destroy 'ofproto_shash' and free the returned value. */
static const struct shash_node **
get_ofprotos(struct shash *ofproto_shash)
{
    const struct ofproto_dpif *ofproto;

    HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_by_name_node,
                   &all_ofproto_dpifs_by_name) {
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
show_dp_feature_bool(struct ds *ds, const char *feature, bool b)
{
    ds_put_format(ds, "%s: %s\n", feature, b ? "Yes" : "No");
}

static void
show_dp_feature_size_t(struct ds *ds, const char *feature, size_t s)
{
    ds_put_format(ds, "%s: %"PRIuSIZE"\n", feature, s);
}

enum dpif_support_field_type {
    DPIF_SUPPORT_FIELD_bool,
    DPIF_SUPPORT_FIELD_size_t,
};

struct dpif_support_field {
    void *rt_ptr;        /* Points to the 'rt_support' field. */
    const void *bt_ptr;  /* Points to the 'bt_support' field. */
    const char *title;
    enum dpif_support_field_type type;
};

#define DPIF_SUPPORT_FIELD_INTIALIZER(RT_PTR, BT_PTR, TITLE, TYPE) \
    (struct dpif_support_field) {RT_PTR, BT_PTR, TITLE, TYPE}

static void
dpif_show_support(const struct dpif_backer_support *support, struct ds *ds)
{
#define DPIF_SUPPORT_FIELD(TYPE, NAME, TITLE) \
    show_dp_feature_##TYPE (ds, TITLE, support->NAME);
    DPIF_SUPPORT_FIELDS
#undef DPIF_SUPPORT_FIELD

#define ODP_SUPPORT_FIELD(TYPE, NAME, TITLE) \
    show_dp_feature_##TYPE (ds, TITLE, support->odp.NAME );
    ODP_SUPPORT_FIELDS
#undef ODP_SUPPORT_FIELD
}

static void
display_support_field(const char *name,
                      const struct dpif_support_field *field,
                      struct ds *ds)
{
    switch (field->type) {
    case DPIF_SUPPORT_FIELD_bool: {
        bool v = *(bool *)field->rt_ptr;
        bool b = *(bool *)field->bt_ptr;
        ds_put_format(ds, "%s (%s) : [run time]:%s, [boot time]:%s\n", name,
                      field->title, v ? "true" : "false",
                      b ? "true" : "false");
        break;
    }
    case DPIF_SUPPORT_FIELD_size_t:
        ds_put_format(ds, "%s (%s) : [run time]:%"PRIuSIZE
                      ", [boot time]:%"PRIuSIZE"\n", name,
                      field->title, *(size_t *)field->rt_ptr,
                      *(size_t *)field->bt_ptr);
        break;
    default:
        OVS_NOT_REACHED();
    }
}

/* Set a field of 'rt_support' to a new value.
 *
 * Returns 'true' if the value is actually set. */
static bool
dpif_set_support(struct dpif_backer_support *rt_support,
                 struct dpif_backer_support *bt_support,
                 const char *name, const char *value, struct ds *ds)
{
    struct shash all_fields = SHASH_INITIALIZER(&all_fields);
    struct dpif_support_field *field;
    struct shash_node *node;
    bool changed = false;

#define DPIF_SUPPORT_FIELD(TYPE, NAME, TITLE) \
    {\
      struct dpif_support_field *f = xmalloc(sizeof *f);            \
      *f = DPIF_SUPPORT_FIELD_INTIALIZER(&rt_support->NAME,         \
                                         &bt_support->NAME,         \
                                         TITLE,                     \
                                         DPIF_SUPPORT_FIELD_##TYPE);\
      shash_add_once(&all_fields, #NAME, f);                        \
    }
    DPIF_SUPPORT_FIELDS;
#undef DPIF_SUPPORT_FIELD

#define ODP_SUPPORT_FIELD(TYPE, NAME, TITLE) \
    {\
        struct dpif_support_field *f = xmalloc(sizeof *f);            \
        *f = DPIF_SUPPORT_FIELD_INTIALIZER(&rt_support->odp.NAME,     \
                                           &bt_support->odp.NAME,     \
                                           TITLE,                     \
                                           DPIF_SUPPORT_FIELD_##TYPE);\
      shash_add_once(&all_fields, #NAME, f);                          \
    }
    ODP_SUPPORT_FIELDS;
#undef ODP_SUPPORT_FIELD

    if (!name) {
        SHASH_FOR_EACH (node, &all_fields) {
            display_support_field(node->name, node->data, ds);
        }
        goto done;
    }

    node = shash_find(&all_fields, name);
    if (!node) {
        ds_put_cstr(ds, "Unexpected support field");
        goto done;
    }
    field = node->data;

    if (!value) {
        display_support_field(node->name, field, ds);
        goto done;
    }

    if (field->type == DPIF_SUPPORT_FIELD_bool) {
        if (!strcasecmp(value, "true")) {
            if (*(bool *)field->bt_ptr) {
                *(bool *)field->rt_ptr = true;
                changed = true;
            } else {
                ds_put_cstr(ds, "Can not enable features not supported by the datapth");
            }
        } else if (!strcasecmp(value, "false")) {
            *(bool *)field->rt_ptr = false;
            changed = true;
        } else {
            ds_put_cstr(ds, "Boolean value expected");
        }
    } else if (field->type == DPIF_SUPPORT_FIELD_size_t) {
        int v;
        if (str_to_int(value, 10, &v)) {
            if (v >= 0) {
                if (v <= *(size_t *)field->bt_ptr) {
                    *(size_t *)field->rt_ptr = v;
                    changed = true;
                } else {
                    ds_put_cstr(ds, "Can not set value beyond the datapath capability");
                }
            } else {
                ds_put_format(ds, "Negative number not expected");
            }
        } else {
            ds_put_cstr(ds, "Integer number expected");
        }
    }

done:
    shash_destroy_free_data(&all_fields);
    return changed;
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

        ds_put_format(ds, "  %s:\n", ofproto->up.name);

        ports = shash_sort(&ofproto->up.port_by_name);
        for (j = 0; j < shash_count(&ofproto->up.port_by_name); j++) {
            const struct shash_node *node = ports[j];
            struct ofport *ofport = node->data;
            struct smap config;
            odp_port_t odp_port;

            ds_put_format(ds, "    %s %u/", netdev_get_name(ofport->netdev),
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
                const struct smap_node **nodes = smap_sort(&config);
                for (size_t k = 0; k < smap_count(&config); k++) {
                    ds_put_format(ds, "%c %s=%s", k ? ',' : ':',
                                  nodes[k]->key, nodes[k]->value);
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

    struct dpif_flow_dump *flow_dump;
    struct dpif_flow_dump_thread *flow_dump_thread;
    struct dpif_flow f;
    int error;

    ofproto = ofproto_dpif_lookup_by_name(argv[argc - 1]);
    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    bool verbosity = false;
    bool names = false;
    bool set_names = false;
    for (int i = 1; i < argc - 1; i++) {
        if (!strcmp(argv[i], "-m")) {
            verbosity = true;
        } else if (!strcmp(argv[i], "--names")) {
            names = true;
            set_names = true;
        } else if (!strcmp(argv[i], "--no-names")) {
            names = false;
            set_names = true;
        }
    }
    if (!set_names) {
        names = verbosity;
    }

    struct hmap *portno_names = NULL;
    if (names) {
        portno_names = xmalloc(sizeof *portno_names);
        hmap_init(portno_names);

        struct dpif_port dpif_port;
        struct dpif_port_dump port_dump;
        DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, ofproto->backer->dpif) {
            odp_portno_names_set(portno_names, dpif_port.port_no,
                                 dpif_port.name);
        }
    }

    ds_init(&ds);
    flow_dump = dpif_flow_dump_create(ofproto->backer->dpif, false, NULL);
    flow_dump_thread = dpif_flow_dump_thread_create(flow_dump);
    while (dpif_flow_dump_next(flow_dump_thread, &f, 1)) {
        struct flow flow;

        if ((odp_flow_key_to_flow(f.key, f.key_len, &flow, NULL)
             == ODP_FIT_ERROR)
            || (xlate_lookup_ofproto(ofproto->backer, &flow, NULL, NULL)
                != ofproto)) {
            continue;
        }

        if (verbosity) {
            odp_format_ufid(&f.ufid, &ds);
            ds_put_cstr(&ds, " ");
        }
        odp_flow_format(f.key, f.key_len, f.mask, f.mask_len,
                        portno_names, &ds, verbosity);
        ds_put_cstr(&ds, ", ");
        dpif_flow_stats_format(&f.stats, &ds);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, f.actions, f.actions_len, portno_names);
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
    if (portno_names) {
        odp_portno_names_destroy(portno_names);
        hmap_destroy(portno_names);
        free(portno_names);
    }
    ds_destroy(&ds);
}

static void
ofproto_unixctl_dpif_show_dp_features(struct unixctl_conn *conn,
                                      int argc, const char *argv[],
                                      void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const char *br = argv[argc -1];
    struct ofproto_dpif *ofproto = ofproto_dpif_lookup_by_name(br);

    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    dpif_show_support(&ofproto->backer->bt_support, &ds);
    unixctl_command_reply(conn, ds_cstr(&ds));
}

static void
ofproto_unixctl_dpif_set_dp_features(struct unixctl_conn *conn,
                                     int argc, const char *argv[],
                                     void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const char *br = argv[1];
    const char *name, *value;
    struct ofproto_dpif *ofproto = ofproto_dpif_lookup_by_name(br);
    bool changed;

    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    name = argc > 2 ? argv[2] : NULL;
    value = argc > 3 ? argv[3] : NULL;
    changed = dpif_set_support(&ofproto->backer->rt_support,
                               &ofproto->backer->bt_support,
                               name, value, &ds);
    if (changed) {
        xlate_set_support(ofproto, &ofproto->backer->rt_support);
        udpif_flush(ofproto->backer->udpif);
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ofproto_unixctl_init(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    unixctl_command_register("fdb/flush", "[bridge]", 0, 1,
                             ofproto_unixctl_fdb_flush, NULL);
    unixctl_command_register("fdb/show", "bridge", 1, 1,
                             ofproto_unixctl_fdb_show, NULL);
    unixctl_command_register("fdb/stats-clear", "[bridge]", 0, 1,
                             ofproto_unixctl_fdb_stats_clear, NULL);
    unixctl_command_register("fdb/stats-show", "bridge", 1, 1,
                             ofproto_unixctl_fdb_stats_show, NULL);
    unixctl_command_register("mdb/flush", "[bridge]", 0, 1,
                             ofproto_unixctl_mcast_snooping_flush, NULL);
    unixctl_command_register("mdb/show", "bridge", 1, 1,
                             ofproto_unixctl_mcast_snooping_show, NULL);
    unixctl_command_register("dpif/dump-dps", "", 0, 0,
                             ofproto_unixctl_dpif_dump_dps, NULL);
    unixctl_command_register("dpif/show", "", 0, 0, ofproto_unixctl_dpif_show,
                             NULL);
    unixctl_command_register("dpif/show-dp-features", "bridge", 1, 1,
                             ofproto_unixctl_dpif_show_dp_features, NULL);
    unixctl_command_register("dpif/dump-flows",
                             "[-m] [--names | --no-names] bridge", 1, INT_MAX,
                             ofproto_unixctl_dpif_dump_flows, NULL);
    unixctl_command_register("dpif/set-dp-features", "bridge", 1, 3 ,
                             ofproto_unixctl_dpif_set_dp_features, NULL);
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

/* 'match' is non-const to allow for temporary modifications.  Any changes are
 * restored before returning. */
int
ofproto_dpif_add_internal_flow(struct ofproto_dpif *ofproto,
                               struct match *match, int priority,
                               uint16_t idle_timeout,
                               const struct ofpbuf *ofpacts,
                               struct rule **rulep)
{
    struct ofputil_flow_mod fm;
    struct rule_dpif *rule;
    int error;

    fm = (struct ofputil_flow_mod) {
        .buffer_id = UINT32_MAX,
        .priority = priority,
        .table_id = TBL_INTERNAL,
        .command = OFPFC_ADD,
        .idle_timeout = idle_timeout,
        .flags = OFPUTIL_FF_HIDDEN_FIELDS | OFPUTIL_FF_NO_READONLY,
        .ofpacts = ofpacts->data,
        .ofpacts_len = ofpacts->size,
    };
    minimatch_init(&fm.match, match);
    error = ofproto_flow_mod(&ofproto->up, &fm);
    minimatch_destroy(&fm.match);

    if (error) {
        VLOG_ERR_RL(&rl, "failed to add internal flow (%s)",
                    ofperr_to_string(error));
        *rulep = NULL;
        return error;
    }

    rule = rule_dpif_lookup_in_table(ofproto,
                                     ofproto_dpif_get_tables_version(ofproto),
                                     TBL_INTERNAL, &match->flow, &match->wc);
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

    fm = (struct ofputil_flow_mod) {
        .buffer_id = UINT32_MAX,
        .priority = priority,
        .table_id = TBL_INTERNAL,
        .out_port = OFPP_ANY,
        .out_group = OFPG_ANY,
        .flags = OFPUTIL_FF_HIDDEN_FIELDS | OFPUTIL_FF_NO_READONLY,
        .command = OFPFC_DELETE_STRICT,
    };
    minimatch_init(&fm.match, match);
    error = ofproto_flow_mod(&ofproto->up, &fm);
    minimatch_destroy(&fm.match);

    if (error) {
        VLOG_ERR_RL(&rl, "failed to delete internal flow (%s)",
                    ofperr_to_string(error));
        return error;
    }

    return 0;
}

static void
meter_get_features(const struct ofproto *ofproto_,
                   struct ofputil_meter_features *features)
{
    const struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    dpif_meter_get_features(ofproto->backer->dpif, features);
}

static enum ofperr
meter_set(struct ofproto *ofproto_, ofproto_meter_id *meter_id,
          struct ofputil_meter_config *config)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    /* Provider ID unknown. Use backer to allocate a new DP meter */
    if (meter_id->uint32 == UINT32_MAX) {
        if (!ofproto->backer->meter_ids) {
            return OFPERR_OFPMMFC_OUT_OF_METERS; /* Meters not supported. */
        }

        if(!id_pool_alloc_id(ofproto->backer->meter_ids, &meter_id->uint32)) {
            return OFPERR_OFPMMFC_OUT_OF_METERS; /* Can't allocate meter. */
        }
    }

    switch (dpif_meter_set(ofproto->backer->dpif, *meter_id, config)) {
    case 0:
        return 0;
    case EFBIG: /* meter_id out of range */
    case ENOMEM: /* Cannot allocate meter */
        return OFPERR_OFPMMFC_OUT_OF_METERS;
    case EBADF: /* Unsupported flags */
        return OFPERR_OFPMMFC_BAD_FLAGS;
    case EINVAL: /* Too many bands */
        return OFPERR_OFPMMFC_OUT_OF_BANDS;
    case ENODEV: /* Unsupported band type */
        return OFPERR_OFPMMFC_BAD_BAND;
    case EDOM: /* Rate must be non-zero */
        return OFPERR_OFPMMFC_BAD_RATE;
    default:
        return OFPERR_OFPMMFC_UNKNOWN;
    }
}

static enum ofperr
meter_get(const struct ofproto *ofproto_, ofproto_meter_id meter_id,
          struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    const struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    if (!dpif_meter_get(ofproto->backer->dpif, meter_id, stats, n_bands)) {
        return 0;
    }
    return OFPERR_OFPMMFC_UNKNOWN_METER;
}

struct free_meter_id_args {
    struct ofproto_dpif *ofproto;
    ofproto_meter_id meter_id;
};

static void
free_meter_id(struct free_meter_id_args *args)
{
    struct ofproto_dpif *ofproto = args->ofproto;

    dpif_meter_del(ofproto->backer->dpif, args->meter_id, NULL, 0);
    id_pool_free_id(ofproto->backer->meter_ids, args->meter_id.uint32);
    free(args);
}

static void
meter_del(struct ofproto *ofproto_, ofproto_meter_id meter_id)
{
    struct free_meter_id_args *arg = xmalloc(sizeof *arg);

    /* Before a meter can be deleted, Openflow spec requires all rules
     * referring to the meter to be (automatically) removed before the
     * meter is deleted. However, since vswitchd is multi-threaded,
     * those rules and their actions remain accessible by other threads,
     * especially by the handler and revalidator threads.
     * Postpone meter deletion after RCU grace period, so that ongoing
     * upcall translation or flow revalidation can complete. */
    arg->ofproto = ofproto_dpif_cast(ofproto_);
    arg->meter_id = meter_id;
    ovsrcu_postpone(free_meter_id, arg);
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
    ofproto_dpif_wait,
    NULL,                       /* get_memory_usage. */
    type_get_memory_usage,
    flush,
    query_tables,
    NULL,                       /* modify_tables */
    set_tables_version,
    port_alloc,
    port_construct,
    port_destruct,
    port_dealloc,
    port_modified,
    port_reconfigured,
    port_query_by_name,
    port_add,
    port_del,
    port_set_config,
    port_get_stats,
    vport_get_status,
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
    NULL,                       /* rule_delete */
    rule_destruct,
    rule_dealloc,
    rule_get_stats,
    packet_xlate,
    packet_xlate_revert,
    packet_execute_prepare,
    packet_execute,
    set_frag_handling,
    nxt_resume,
    set_netflow,
    get_netflow_ids,
    set_sflow,
    set_ipfix,
    get_ipfix_stats,
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
    meter_get_features,
    meter_set,
    meter_get,
    meter_del,
    group_alloc,                /* group_alloc */
    group_construct,            /* group_construct */
    group_destruct,             /* group_destruct */
    group_dealloc,              /* group_dealloc */
    NULL,                       /* group_modify */
    group_get_stats,            /* group_get_stats */
    get_datapath_version,       /* get_datapath_version */
    get_datapath_cap,
    type_set_config,
    ct_flush,                   /* ct_flush */
    ct_set_zone_timeout_policy,
    ct_del_zone_timeout_policy,
};
