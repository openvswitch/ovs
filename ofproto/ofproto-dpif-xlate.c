/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
 * limitations under the License. */

#include <config.h>

#include "ofproto/ofproto-dpif-xlate.h"

#include <errno.h>

#include "bfd.h"
#include "bitmap.h"
#include "bond.h"
#include "bundle.h"
#include "byte-order.h"
#include "cfm.h"
#include "connmgr.h"
#include "coverage.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "in-band.h"
#include "lacp.h"
#include "learn.h"
#include "list.h"
#include "mac-learning.h"
#include "meta-flow.h"
#include "multipath.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-execute.h"
#include "ofp-actions.h"
#include "ofproto/ofproto-dpif-ipfix.h"
#include "ofproto/ofproto-dpif-mirror.h"
#include "ofproto/ofproto-dpif-monitor.h"
#include "ofproto/ofproto-dpif-sflow.h"
#include "ofproto/ofproto-dpif.h"
#include "ofproto/ofproto-provider.h"
#include "tunnel.h"
#include "vlog.h"

COVERAGE_DEFINE(xlate_actions);
COVERAGE_DEFINE(xlate_actions_oversize);

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_xlate);

/* Maximum depth of flow table recursion (due to resubmit actions) in a
 * flow translation. */
#define MAX_RESUBMIT_RECURSION 64

/* Maximum number of resubmit actions in a flow translation, whether they are
 * recursive or not. */
#define MAX_RESUBMITS (MAX_RESUBMIT_RECURSION * MAX_RESUBMIT_RECURSION)

struct ovs_rwlock xlate_rwlock = OVS_RWLOCK_INITIALIZER;

struct xbridge {
    struct hmap_node hmap_node;   /* Node in global 'xbridges' map. */
    struct ofproto_dpif *ofproto; /* Key in global 'xbridges' map. */

    struct list xbundles;         /* Owned xbundles. */
    struct hmap xports;           /* Indexed by ofp_port. */

    char *name;                   /* Name used in log messages. */
    struct dpif *dpif;            /* Datapath interface. */
    struct mac_learning *ml;      /* Mac learning handle. */
    struct mbridge *mbridge;      /* Mirroring. */
    struct dpif_sflow *sflow;     /* SFlow handle, or null. */
    struct dpif_ipfix *ipfix;     /* Ipfix handle, or null. */
    struct netflow *netflow;      /* Netflow handle, or null. */
    struct stp *stp;              /* STP or null if disabled. */

    /* Special rules installed by ofproto-dpif. */
    struct rule_dpif *miss_rule;
    struct rule_dpif *no_packet_in_rule;

    enum ofp_config_flags frag;   /* Fragmentation handling. */
    bool has_in_band;             /* Bridge has in band control? */
    bool forward_bpdu;            /* Bridge forwards STP BPDUs? */
};

struct xbundle {
    struct hmap_node hmap_node;    /* In global 'xbundles' map. */
    struct ofbundle *ofbundle;     /* Key in global 'xbundles' map. */

    struct list list_node;         /* In parent 'xbridges' list. */
    struct xbridge *xbridge;       /* Parent xbridge. */

    struct list xports;            /* Contains "struct xport"s. */

    char *name;                    /* Name used in log messages. */
    struct bond *bond;             /* Nonnull iff more than one port. */
    struct lacp *lacp;             /* LACP handle or null. */

    enum port_vlan_mode vlan_mode; /* VLAN mode. */
    int vlan;                      /* -1=trunk port, else a 12-bit VLAN ID. */
    unsigned long *trunks;         /* Bitmap of trunked VLANs, if 'vlan' == -1.
                                    * NULL if all VLANs are trunked. */
    bool use_priority_tags;        /* Use 802.1p tag for frames in VLAN 0? */
    bool floodable;                /* No port has OFPUTIL_PC_NO_FLOOD set? */
};

struct xport {
    struct hmap_node hmap_node;      /* Node in global 'xports' map. */
    struct ofport_dpif *ofport;      /* Key in global 'xports map. */

    struct hmap_node ofp_node;       /* Node in parent xbridge 'xports' map. */
    ofp_port_t ofp_port;             /* Key in parent xbridge 'xports' map. */

    odp_port_t odp_port;             /* Datapath port number or ODPP_NONE. */

    struct list bundle_node;         /* In parent xbundle (if it exists). */
    struct xbundle *xbundle;         /* Parent xbundle or null. */

    struct netdev *netdev;           /* 'ofport''s netdev. */

    struct xbridge *xbridge;         /* Parent bridge. */
    struct xport *peer;              /* Patch port peer or null. */

    enum ofputil_port_config config; /* OpenFlow port configuration. */
    enum ofputil_port_state state;   /* OpenFlow port state. */
    int stp_port_no;                 /* STP port number or -1 if not in use. */

    struct hmap skb_priorities;      /* Map of 'skb_priority_to_dscp's. */

    bool may_enable;                 /* May be enabled in bonds. */
    bool is_tunnel;                  /* Is a tunnel port. */

    struct cfm *cfm;                 /* CFM handle or null. */
    struct bfd *bfd;                 /* BFD handle or null. */
};

struct xlate_ctx {
    struct xlate_in *xin;
    struct xlate_out *xout;

    const struct xbridge *xbridge;

    /* Flow at the last commit. */
    struct flow base_flow;

    /* Tunnel IP destination address as received.  This is stored separately
     * as the base_flow.tunnel is cleared on init to reflect the datapath
     * behavior.  Used to make sure not to send tunneled output to ourselves,
     * which might lead to an infinite loop.  This could happen easily
     * if a tunnel is marked as 'ip_remote=flow', and the flow does not
     * actually set the tun_dst field. */
    ovs_be32 orig_tunnel_ip_dst;

    /* Stack for the push and pop actions.  Each stack element is of type
     * "union mf_subvalue". */
    union mf_subvalue init_stack[1024 / sizeof(union mf_subvalue)];
    struct ofpbuf stack;

    /* The rule that we are currently translating, or NULL. */
    struct rule_dpif *rule;

    int mpls_depth_delta;       /* Delta of the mpls stack depth since
                                 * actions were last committed.
                                 * Must be between -1 and 1 inclusive. */
    ovs_be32 pre_push_mpls_lse; /* Used to record the top-most MPLS LSE
                                 * prior to an mpls_push so that it may be
                                 * used for a subsequent mpls_pop. */

    /* Resubmit statistics, via xlate_table_action(). */
    int recurse;                /* Current resubmit nesting depth. */
    int resubmits;              /* Total number of resubmits. */

    uint32_t orig_skb_priority; /* Priority when packet arrived. */
    uint8_t table_id;           /* OpenFlow table ID where flow was found. */
    uint32_t sflow_n_outputs;   /* Number of output ports. */
    odp_port_t sflow_odp_port;  /* Output port for composing sFlow action. */
    uint16_t user_cookie_offset;/* Used for user_action_cookie fixup. */
    bool exit;                  /* No further actions should be processed. */

    /* OpenFlow 1.1+ action set.
     *
     * 'action_set' accumulates "struct ofpact"s added by OFPACT_WRITE_ACTIONS.
     * When translation is otherwise complete, ofpacts_execute_action_set()
     * converts it to a set of "struct ofpact"s that can be translated into
     * datapath actions.   */
    struct ofpbuf action_set;   /* Action set. */
    uint64_t action_set_stub[1024 / 8];
};

/* A controller may use OFPP_NONE as the ingress port to indicate that
 * it did not arrive on a "real" port.  'ofpp_none_bundle' exists for
 * when an input bundle is needed for validation (e.g., mirroring or
 * OFPP_NORMAL processing).  It is not connected to an 'ofproto' or have
 * any 'port' structs, so care must be taken when dealing with it.
 * The bundle's name and vlan mode are initialized in lookup_input_bundle() */
static struct xbundle ofpp_none_bundle;

/* Node in 'xport''s 'skb_priorities' map.  Used to maintain a map from
 * 'priority' (the datapath's term for QoS queue) to the dscp bits which all
 * traffic egressing the 'ofport' with that priority should be marked with. */
struct skb_priority_to_dscp {
    struct hmap_node hmap_node; /* Node in 'ofport_dpif''s 'skb_priorities'. */
    uint32_t skb_priority;      /* Priority of this queue (see struct flow). */

    uint8_t dscp;               /* DSCP bits to mark outgoing traffic with. */
};

static struct hmap xbridges = HMAP_INITIALIZER(&xbridges);
static struct hmap xbundles = HMAP_INITIALIZER(&xbundles);
static struct hmap xports = HMAP_INITIALIZER(&xports);

static bool may_receive(const struct xport *, struct xlate_ctx *);
static void do_xlate_actions(const struct ofpact *, size_t ofpacts_len,
                             struct xlate_ctx *);
static void xlate_actions__(struct xlate_in *, struct xlate_out *)
    OVS_REQ_RDLOCK(xlate_rwlock);
    static void xlate_normal(struct xlate_ctx *);
    static void xlate_report(struct xlate_ctx *, const char *);
    static void xlate_table_action(struct xlate_ctx *, ofp_port_t in_port,
                                   uint8_t table_id, bool may_packet_in);
static bool input_vid_is_valid(uint16_t vid, struct xbundle *, bool warn);
static uint16_t input_vid_to_vlan(const struct xbundle *, uint16_t vid);
static void output_normal(struct xlate_ctx *, const struct xbundle *,
                          uint16_t vlan);
static void compose_output_action(struct xlate_ctx *, ofp_port_t ofp_port);

static struct xbridge *xbridge_lookup(const struct ofproto_dpif *);
static struct xbundle *xbundle_lookup(const struct ofbundle *);
static struct xport *xport_lookup(const struct ofport_dpif *);
static struct xport *get_ofp_port(const struct xbridge *, ofp_port_t ofp_port);
static struct skb_priority_to_dscp *get_skb_priority(const struct xport *,
                                                     uint32_t skb_priority);
static void clear_skb_priorities(struct xport *);
static bool dscp_from_skb_priority(const struct xport *, uint32_t skb_priority,
                                   uint8_t *dscp);

void
xlate_ofproto_set(struct ofproto_dpif *ofproto, const char *name,
                  struct dpif *dpif, struct rule_dpif *miss_rule,
                  struct rule_dpif *no_packet_in_rule,
                  const struct mac_learning *ml, struct stp *stp,
                  const struct mbridge *mbridge,
                  const struct dpif_sflow *sflow,
                  const struct dpif_ipfix *ipfix,
                  const struct netflow *netflow, enum ofp_config_flags frag,
                  bool forward_bpdu, bool has_in_band)
{
    struct xbridge *xbridge = xbridge_lookup(ofproto);

    if (!xbridge) {
        xbridge = xzalloc(sizeof *xbridge);
        xbridge->ofproto = ofproto;

        hmap_insert(&xbridges, &xbridge->hmap_node, hash_pointer(ofproto, 0));
        hmap_init(&xbridge->xports);
        list_init(&xbridge->xbundles);
    }

    if (xbridge->ml != ml) {
        mac_learning_unref(xbridge->ml);
        xbridge->ml = mac_learning_ref(ml);
    }

    if (xbridge->mbridge != mbridge) {
        mbridge_unref(xbridge->mbridge);
        xbridge->mbridge = mbridge_ref(mbridge);
    }

    if (xbridge->sflow != sflow) {
        dpif_sflow_unref(xbridge->sflow);
        xbridge->sflow = dpif_sflow_ref(sflow);
    }

    if (xbridge->ipfix != ipfix) {
        dpif_ipfix_unref(xbridge->ipfix);
        xbridge->ipfix = dpif_ipfix_ref(ipfix);
    }

    if (xbridge->stp != stp) {
        stp_unref(xbridge->stp);
        xbridge->stp = stp_ref(stp);
    }

    if (xbridge->netflow != netflow) {
        netflow_unref(xbridge->netflow);
        xbridge->netflow = netflow_ref(netflow);
    }

    free(xbridge->name);
    xbridge->name = xstrdup(name);

    xbridge->dpif = dpif;
    xbridge->forward_bpdu = forward_bpdu;
    xbridge->has_in_band = has_in_band;
    xbridge->frag = frag;
    xbridge->miss_rule = miss_rule;
    xbridge->no_packet_in_rule = no_packet_in_rule;
}

void
xlate_remove_ofproto(struct ofproto_dpif *ofproto)
{
    struct xbridge *xbridge = xbridge_lookup(ofproto);
    struct xbundle *xbundle, *next_xbundle;
    struct xport *xport, *next_xport;

    if (!xbridge) {
        return;
    }

    HMAP_FOR_EACH_SAFE (xport, next_xport, ofp_node, &xbridge->xports) {
        xlate_ofport_remove(xport->ofport);
    }

    LIST_FOR_EACH_SAFE (xbundle, next_xbundle, list_node, &xbridge->xbundles) {
        xlate_bundle_remove(xbundle->ofbundle);
    }

    hmap_remove(&xbridges, &xbridge->hmap_node);
    mac_learning_unref(xbridge->ml);
    mbridge_unref(xbridge->mbridge);
    dpif_sflow_unref(xbridge->sflow);
    dpif_ipfix_unref(xbridge->ipfix);
    stp_unref(xbridge->stp);
    hmap_destroy(&xbridge->xports);
    free(xbridge->name);
    free(xbridge);
}

void
xlate_bundle_set(struct ofproto_dpif *ofproto, struct ofbundle *ofbundle,
                 const char *name, enum port_vlan_mode vlan_mode, int vlan,
                 unsigned long *trunks, bool use_priority_tags,
                 const struct bond *bond, const struct lacp *lacp,
                 bool floodable)
{
    struct xbundle *xbundle = xbundle_lookup(ofbundle);

    if (!xbundle) {
        xbundle = xzalloc(sizeof *xbundle);
        xbundle->ofbundle = ofbundle;
        xbundle->xbridge = xbridge_lookup(ofproto);

        hmap_insert(&xbundles, &xbundle->hmap_node, hash_pointer(ofbundle, 0));
        list_insert(&xbundle->xbridge->xbundles, &xbundle->list_node);
        list_init(&xbundle->xports);
    }

    ovs_assert(xbundle->xbridge);

    free(xbundle->name);
    xbundle->name = xstrdup(name);

    xbundle->vlan_mode = vlan_mode;
    xbundle->vlan = vlan;
    xbundle->trunks = trunks;
    xbundle->use_priority_tags = use_priority_tags;
    xbundle->floodable = floodable;

    if (xbundle->bond != bond) {
        bond_unref(xbundle->bond);
        xbundle->bond = bond_ref(bond);
    }

    if (xbundle->lacp != lacp) {
        lacp_unref(xbundle->lacp);
        xbundle->lacp = lacp_ref(lacp);
    }
}

void
xlate_bundle_remove(struct ofbundle *ofbundle)
{
    struct xbundle *xbundle = xbundle_lookup(ofbundle);
    struct xport *xport, *next;

    if (!xbundle) {
        return;
    }

    LIST_FOR_EACH_SAFE (xport, next, bundle_node, &xbundle->xports) {
        list_remove(&xport->bundle_node);
        xport->xbundle = NULL;
    }

    hmap_remove(&xbundles, &xbundle->hmap_node);
    list_remove(&xbundle->list_node);
    bond_unref(xbundle->bond);
    lacp_unref(xbundle->lacp);
    free(xbundle->name);
    free(xbundle);
}

void
xlate_ofport_set(struct ofproto_dpif *ofproto, struct ofbundle *ofbundle,
                 struct ofport_dpif *ofport, ofp_port_t ofp_port,
                 odp_port_t odp_port, const struct netdev *netdev,
                 const struct cfm *cfm, const struct bfd *bfd,
                 struct ofport_dpif *peer, int stp_port_no,
                 const struct ofproto_port_queue *qdscp_list, size_t n_qdscp,
                 enum ofputil_port_config config,
                 enum ofputil_port_state state, bool is_tunnel,
                 bool may_enable)
{
    struct xport *xport = xport_lookup(ofport);
    size_t i;

    if (!xport) {
        xport = xzalloc(sizeof *xport);
        xport->ofport = ofport;
        xport->xbridge = xbridge_lookup(ofproto);
        xport->ofp_port = ofp_port;

        hmap_init(&xport->skb_priorities);
        hmap_insert(&xports, &xport->hmap_node, hash_pointer(ofport, 0));
        hmap_insert(&xport->xbridge->xports, &xport->ofp_node,
                    hash_ofp_port(xport->ofp_port));
    }

    ovs_assert(xport->ofp_port == ofp_port);

    xport->config = config;
    xport->state = state;
    xport->stp_port_no = stp_port_no;
    xport->is_tunnel = is_tunnel;
    xport->may_enable = may_enable;
    xport->odp_port = odp_port;

    if (xport->netdev != netdev) {
        netdev_close(xport->netdev);
        xport->netdev = netdev_ref(netdev);
    }

    if (xport->cfm != cfm) {
        cfm_unref(xport->cfm);
        xport->cfm = cfm_ref(cfm);
    }

    if (xport->bfd != bfd) {
        bfd_unref(xport->bfd);
        xport->bfd = bfd_ref(bfd);
    }

    if (xport->peer) {
        xport->peer->peer = NULL;
    }
    xport->peer = xport_lookup(peer);
    if (xport->peer) {
        xport->peer->peer = xport;
    }

    if (xport->xbundle) {
        list_remove(&xport->bundle_node);
    }
    xport->xbundle = xbundle_lookup(ofbundle);
    if (xport->xbundle) {
        list_insert(&xport->xbundle->xports, &xport->bundle_node);
    }

    clear_skb_priorities(xport);
    for (i = 0; i < n_qdscp; i++) {
        struct skb_priority_to_dscp *pdscp;
        uint32_t skb_priority;

        if (dpif_queue_to_priority(xport->xbridge->dpif, qdscp_list[i].queue,
                                   &skb_priority)) {
            continue;
        }

        pdscp = xmalloc(sizeof *pdscp);
        pdscp->skb_priority = skb_priority;
        pdscp->dscp = (qdscp_list[i].dscp << 2) & IP_DSCP_MASK;
        hmap_insert(&xport->skb_priorities, &pdscp->hmap_node,
                    hash_int(pdscp->skb_priority, 0));
    }
}

void
xlate_ofport_remove(struct ofport_dpif *ofport)
{
    struct xport *xport = xport_lookup(ofport);

    if (!xport) {
        return;
    }

    if (xport->peer) {
        xport->peer->peer = NULL;
        xport->peer = NULL;
    }

    if (xport->xbundle) {
        list_remove(&xport->bundle_node);
    }

    clear_skb_priorities(xport);
    hmap_destroy(&xport->skb_priorities);

    hmap_remove(&xports, &xport->hmap_node);
    hmap_remove(&xport->xbridge->xports, &xport->ofp_node);

    netdev_close(xport->netdev);
    cfm_unref(xport->cfm);
    bfd_unref(xport->bfd);
    free(xport);
}

/* Given a datpath, packet, and flow metadata ('backer', 'packet', and 'key'
 * respectively), populates 'flow' with the result of odp_flow_key_to_flow().
 * Optionally, if nonnull, populates 'fitnessp' with the fitness of 'flow' as
 * returned by odp_flow_key_to_flow().  Also, optionally populates 'ofproto'
 * with the ofproto_dpif, 'odp_in_port' with the datapath in_port, that
 * 'packet' ingressed, and 'ipfix', 'sflow', and 'netflow' with the appropriate
 * handles for those protocols if they're enabled.  Caller is responsible for
 * unrefing them.
 *
 * If 'ofproto' is nonnull, requires 'flow''s in_port to exist.  Otherwise sets
 * 'flow''s in_port to OFPP_NONE.
 *
 * This function does post-processing on data returned from
 * odp_flow_key_to_flow() to help make VLAN splinters transparent to the rest
 * of the upcall processing logic.  In particular, if the extracted in_port is
 * a VLAN splinter port, it replaces flow->in_port by the "real" port, sets
 * flow->vlan_tci correctly for the VLAN of the VLAN splinter port, and pushes
 * a VLAN header onto 'packet' (if it is nonnull).
 *
 * Similarly, this function also includes some logic to help with tunnels.  It
 * may modify 'flow' as necessary to make the tunneling implementation
 * transparent to the upcall processing logic.
 *
 * Returns 0 if successful, ENODEV if the parsed flow has no associated ofport,
 * or some other positive errno if there are other problems. */
int
xlate_receive(const struct dpif_backer *backer, struct ofpbuf *packet,
              const struct nlattr *key, size_t key_len,
              struct flow *flow, enum odp_key_fitness *fitnessp,
              struct ofproto_dpif **ofproto, struct dpif_ipfix **ipfix,
              struct dpif_sflow **sflow, struct netflow **netflow,
              odp_port_t *odp_in_port)
{
    enum odp_key_fitness fitness;
    const struct xport *xport;
    int error = ENODEV;

    ovs_rwlock_rdlock(&xlate_rwlock);
    fitness = odp_flow_key_to_flow(key, key_len, flow);
    if (fitness == ODP_FIT_ERROR) {
        error = EINVAL;
        goto exit;
    }

    if (odp_in_port) {
        *odp_in_port = flow->in_port.odp_port;
    }

    xport = xport_lookup(tnl_port_should_receive(flow)
                         ? tnl_port_receive(flow)
                         : odp_port_to_ofport(backer, flow->in_port.odp_port));

    flow->in_port.ofp_port = xport ? xport->ofp_port : OFPP_NONE;
    if (!xport) {
        goto exit;
    }

    if (vsp_adjust_flow(xport->xbridge->ofproto, flow)) {
        if (packet) {
            /* Make the packet resemble the flow, so that it gets sent to
             * an OpenFlow controller properly, so that it looks correct
             * for sFlow, and so that flow_extract() will get the correct
             * vlan_tci if it is called on 'packet'. */
            eth_push_vlan(packet, flow->vlan_tci);
        }
        /* We can't reproduce 'key' from 'flow'. */
        fitness = fitness == ODP_FIT_PERFECT ? ODP_FIT_TOO_MUCH : fitness;
    }
    error = 0;

    if (ofproto) {
        *ofproto = xport->xbridge->ofproto;
    }

    if (ipfix) {
        *ipfix = dpif_ipfix_ref(xport->xbridge->ipfix);
    }

    if (sflow) {
        *sflow = dpif_sflow_ref(xport->xbridge->sflow);
    }

    if (netflow) {
        *netflow = netflow_ref(xport->xbridge->netflow);
    }

exit:
    if (fitnessp) {
        *fitnessp = fitness;
    }
    ovs_rwlock_unlock(&xlate_rwlock);
    return error;
}

static struct xbridge *
xbridge_lookup(const struct ofproto_dpif *ofproto)
{
    struct xbridge *xbridge;

    if (!ofproto) {
        return NULL;
    }

    HMAP_FOR_EACH_IN_BUCKET (xbridge, hmap_node, hash_pointer(ofproto, 0),
                             &xbridges) {
        if (xbridge->ofproto == ofproto) {
            return xbridge;
        }
    }
    return NULL;
}

static struct xbundle *
xbundle_lookup(const struct ofbundle *ofbundle)
{
    struct xbundle *xbundle;

    if (!ofbundle) {
        return NULL;
    }

    HMAP_FOR_EACH_IN_BUCKET (xbundle, hmap_node, hash_pointer(ofbundle, 0),
                             &xbundles) {
        if (xbundle->ofbundle == ofbundle) {
            return xbundle;
        }
    }
    return NULL;
}

static struct xport *
xport_lookup(const struct ofport_dpif *ofport)
{
    struct xport *xport;

    if (!ofport) {
        return NULL;
    }

    HMAP_FOR_EACH_IN_BUCKET (xport, hmap_node, hash_pointer(ofport, 0),
                             &xports) {
        if (xport->ofport == ofport) {
            return xport;
        }
    }
    return NULL;
}

static struct stp_port *
xport_get_stp_port(const struct xport *xport)
{
    return xport->xbridge->stp && xport->stp_port_no != -1
        ? stp_get_port(xport->xbridge->stp, xport->stp_port_no)
        : NULL;
}

static bool
xport_stp_learn_state(const struct xport *xport)
{
    struct stp_port *sp = xport_get_stp_port(xport);
    return stp_learn_in_state(sp ? stp_port_get_state(sp) : STP_DISABLED);
}

static bool
xport_stp_forward_state(const struct xport *xport)
{
    struct stp_port *sp = xport_get_stp_port(xport);
    return stp_forward_in_state(sp ? stp_port_get_state(sp) : STP_DISABLED);
}

static bool
xport_stp_listen_state(const struct xport *xport)
{
    struct stp_port *sp = xport_get_stp_port(xport);
    return stp_listen_in_state(sp ? stp_port_get_state(sp) : STP_DISABLED);
}

/* Returns true if STP should process 'flow'.  Sets fields in 'wc' that
 * were used to make the determination.*/
static bool
stp_should_process_flow(const struct flow *flow, struct flow_wildcards *wc)
{
    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
    return eth_addr_equals(flow->dl_dst, eth_addr_stp);
}

static void
stp_process_packet(const struct xport *xport, const struct ofpbuf *packet)
{
    struct stp_port *sp = xport_get_stp_port(xport);
    struct ofpbuf payload = *packet;
    struct eth_header *eth = payload.data;

    /* Sink packets on ports that have STP disabled when the bridge has
     * STP enabled. */
    if (!sp || stp_port_get_state(sp) == STP_DISABLED) {
        return;
    }

    /* Trim off padding on payload. */
    if (payload.size > ntohs(eth->eth_type) + ETH_HEADER_LEN) {
        payload.size = ntohs(eth->eth_type) + ETH_HEADER_LEN;
    }

    if (ofpbuf_try_pull(&payload, ETH_HEADER_LEN + LLC_HEADER_LEN)) {
        stp_received_bpdu(sp, payload.data, payload.size);
    }
}

static struct xport *
get_ofp_port(const struct xbridge *xbridge, ofp_port_t ofp_port)
{
    struct xport *xport;

    HMAP_FOR_EACH_IN_BUCKET (xport, ofp_node, hash_ofp_port(ofp_port),
                             &xbridge->xports) {
        if (xport->ofp_port == ofp_port) {
            return xport;
        }
    }
    return NULL;
}

static odp_port_t
ofp_port_to_odp_port(const struct xbridge *xbridge, ofp_port_t ofp_port)
{
    const struct xport *xport = get_ofp_port(xbridge, ofp_port);
    return xport ? xport->odp_port : ODPP_NONE;
}

static bool
odp_port_is_alive(const struct xlate_ctx *ctx, ofp_port_t ofp_port)
{
    struct xport *xport;

    xport = get_ofp_port(ctx->xbridge, ofp_port);
    if (!xport || xport->config & OFPUTIL_PC_PORT_DOWN ||
        xport->state & OFPUTIL_PS_LINK_DOWN) {
        return false;
    }

    return true;
}

static const struct ofputil_bucket *
group_first_live_bucket(const struct xlate_ctx *, const struct group_dpif *,
                        int depth);

static bool
group_is_alive(const struct xlate_ctx *ctx, uint32_t group_id, int depth)
{
    struct group_dpif *group;
    bool hit;

    hit = group_dpif_lookup(ctx->xbridge->ofproto, group_id, &group);
    if (!hit) {
        return false;
    }

    hit = group_first_live_bucket(ctx, group, depth) != NULL;

    group_dpif_release(group);
    return hit;
}

#define MAX_LIVENESS_RECURSION 128 /* Arbitrary limit */

static bool
bucket_is_alive(const struct xlate_ctx *ctx,
                const struct ofputil_bucket *bucket, int depth)
{
    if (depth >= MAX_LIVENESS_RECURSION) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_WARN_RL(&rl, "bucket chaining exceeded %d links",
                     MAX_LIVENESS_RECURSION);
        return false;
    }

    return !ofputil_bucket_has_liveness(bucket) ||
        (bucket->watch_port != OFPP_ANY &&
         odp_port_is_alive(ctx, bucket->watch_port)) ||
        (bucket->watch_group != OFPG_ANY &&
         group_is_alive(ctx, bucket->watch_group, depth + 1));
}

static const struct ofputil_bucket *
group_first_live_bucket(const struct xlate_ctx *ctx,
                        const struct group_dpif *group, int depth)
{
    struct ofputil_bucket *bucket;
    const struct list *buckets;

    group_dpif_get_buckets(group, &buckets);
    LIST_FOR_EACH (bucket, list_node, buckets) {
        if (bucket_is_alive(ctx, bucket, depth)) {
            return bucket;
        }
    }

    return NULL;
}

static const struct ofputil_bucket *
group_best_live_bucket(const struct xlate_ctx *ctx,
                       const struct group_dpif *group,
                       uint32_t basis)
{
    const struct ofputil_bucket *best_bucket = NULL;
    uint32_t best_score = 0;
    int i = 0;

    const struct ofputil_bucket *bucket;
    const struct list *buckets;

    group_dpif_get_buckets(group, &buckets);
    LIST_FOR_EACH (bucket, list_node, buckets) {
        if (bucket_is_alive(ctx, bucket, 0)) {
            uint32_t score = (hash_int(i, basis) & 0xffff) * bucket->weight;
            if (score >= best_score) {
                best_bucket = bucket;
                best_score = score;
            }
        }
        i++;
    }

    return best_bucket;
}

static bool
xbundle_trunks_vlan(const struct xbundle *bundle, uint16_t vlan)
{
    return (bundle->vlan_mode != PORT_VLAN_ACCESS
            && (!bundle->trunks || bitmap_is_set(bundle->trunks, vlan)));
}

static bool
xbundle_includes_vlan(const struct xbundle *xbundle, uint16_t vlan)
{
    return vlan == xbundle->vlan || xbundle_trunks_vlan(xbundle, vlan);
}

static mirror_mask_t
xbundle_mirror_out(const struct xbridge *xbridge, struct xbundle *xbundle)
{
    return xbundle != &ofpp_none_bundle
        ? mirror_bundle_out(xbridge->mbridge, xbundle->ofbundle)
        : 0;
}

static mirror_mask_t
xbundle_mirror_src(const struct xbridge *xbridge, struct xbundle *xbundle)
{
    return xbundle != &ofpp_none_bundle
        ? mirror_bundle_src(xbridge->mbridge, xbundle->ofbundle)
        : 0;
}

static mirror_mask_t
xbundle_mirror_dst(const struct xbridge *xbridge, struct xbundle *xbundle)
{
    return xbundle != &ofpp_none_bundle
        ? mirror_bundle_dst(xbridge->mbridge, xbundle->ofbundle)
        : 0;
}

static struct xbundle *
lookup_input_bundle(const struct xbridge *xbridge, ofp_port_t in_port,
                    bool warn, struct xport **in_xportp)
{
    struct xport *xport;

    /* Find the port and bundle for the received packet. */
    xport = get_ofp_port(xbridge, in_port);
    if (in_xportp) {
        *in_xportp = xport;
    }
    if (xport && xport->xbundle) {
        return xport->xbundle;
    }

    /* Special-case OFPP_NONE, which a controller may use as the ingress
     * port for traffic that it is sourcing. */
    if (in_port == OFPP_NONE) {
        ofpp_none_bundle.name = "OFPP_NONE";
        ofpp_none_bundle.vlan_mode = PORT_VLAN_TRUNK;
        return &ofpp_none_bundle;
    }

    /* Odd.  A few possible reasons here:
     *
     * - We deleted a port but there are still a few packets queued up
     *   from it.
     *
     * - Someone externally added a port (e.g. "ovs-dpctl add-if") that
     *   we don't know about.
     *
     * - The ofproto client didn't configure the port as part of a bundle.
     *   This is particularly likely to happen if a packet was received on the
     *   port after it was created, but before the client had a chance to
     *   configure its bundle.
     */
    if (warn) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_WARN_RL(&rl, "bridge %s: received packet on unknown "
                     "port %"PRIu16, xbridge->name, in_port);
    }
    return NULL;
}

static void
add_mirror_actions(struct xlate_ctx *ctx, const struct flow *orig_flow)
{
    const struct xbridge *xbridge = ctx->xbridge;
    mirror_mask_t mirrors;
    struct xbundle *in_xbundle;
    uint16_t vlan;
    uint16_t vid;

    mirrors = ctx->xout->mirrors;
    ctx->xout->mirrors = 0;

    in_xbundle = lookup_input_bundle(xbridge, orig_flow->in_port.ofp_port,
                                     ctx->xin->packet != NULL, NULL);
    if (!in_xbundle) {
        return;
    }
    mirrors |= xbundle_mirror_src(xbridge, in_xbundle);

    /* Drop frames on bundles reserved for mirroring. */
    if (xbundle_mirror_out(xbridge, in_xbundle)) {
        if (ctx->xin->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port "
                         "%s, which is reserved exclusively for mirroring",
                         ctx->xbridge->name, in_xbundle->name);
        }
        ofpbuf_clear(&ctx->xout->odp_actions);
        return;
    }

    /* Check VLAN. */
    vid = vlan_tci_to_vid(orig_flow->vlan_tci);
    if (!input_vid_is_valid(vid, in_xbundle, ctx->xin->packet != NULL)) {
        return;
    }
    vlan = input_vid_to_vlan(in_xbundle, vid);

    if (!mirrors) {
        return;
    }

    /* Restore the original packet before adding the mirror actions. */
    ctx->xin->flow = *orig_flow;

    while (mirrors) {
        mirror_mask_t dup_mirrors;
        struct ofbundle *out;
        unsigned long *vlans;
        bool vlan_mirrored;
        bool has_mirror;
        int out_vlan;

        has_mirror = mirror_get(xbridge->mbridge, raw_ctz(mirrors),
                                &vlans, &dup_mirrors, &out, &out_vlan);
        ovs_assert(has_mirror);

        if (vlans) {
            ctx->xout->wc.masks.vlan_tci |= htons(VLAN_CFI | VLAN_VID_MASK);
        }
        vlan_mirrored = !vlans || bitmap_is_set(vlans, vlan);
        free(vlans);

        if (!vlan_mirrored) {
            mirrors = zero_rightmost_1bit(mirrors);
            continue;
        }

        mirrors &= ~dup_mirrors;
        ctx->xout->mirrors |= dup_mirrors;
        if (out) {
            struct xbundle *out_xbundle = xbundle_lookup(out);
            if (out_xbundle) {
                output_normal(ctx, out_xbundle, vlan);
            }
        } else if (vlan != out_vlan
                   && !eth_addr_is_reserved(orig_flow->dl_dst)) {
            struct xbundle *xbundle;

            LIST_FOR_EACH (xbundle, list_node, &xbridge->xbundles) {
                if (xbundle_includes_vlan(xbundle, out_vlan)
                    && !xbundle_mirror_out(xbridge, xbundle)) {
                    output_normal(ctx, xbundle, out_vlan);
                }
            }
        }
    }
}

/* Given 'vid', the VID obtained from the 802.1Q header that was received as
 * part of a packet (specify 0 if there was no 802.1Q header), and 'in_xbundle',
 * the bundle on which the packet was received, returns the VLAN to which the
 * packet belongs.
 *
 * Both 'vid' and the return value are in the range 0...4095. */
static uint16_t
input_vid_to_vlan(const struct xbundle *in_xbundle, uint16_t vid)
{
    switch (in_xbundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        return in_xbundle->vlan;
        break;

    case PORT_VLAN_TRUNK:
        return vid;

    case PORT_VLAN_NATIVE_UNTAGGED:
    case PORT_VLAN_NATIVE_TAGGED:
        return vid ? vid : in_xbundle->vlan;

    default:
        OVS_NOT_REACHED();
    }
}

/* Checks whether a packet with the given 'vid' may ingress on 'in_xbundle'.
 * If so, returns true.  Otherwise, returns false and, if 'warn' is true, logs
 * a warning.
 *
 * 'vid' should be the VID obtained from the 802.1Q header that was received as
 * part of a packet (specify 0 if there was no 802.1Q header), in the range
 * 0...4095. */
static bool
input_vid_is_valid(uint16_t vid, struct xbundle *in_xbundle, bool warn)
{
    /* Allow any VID on the OFPP_NONE port. */
    if (in_xbundle == &ofpp_none_bundle) {
        return true;
    }

    switch (in_xbundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        if (vid) {
            if (warn) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "dropping VLAN %"PRIu16" tagged "
                             "packet received on port %s configured as VLAN "
                             "%"PRIu16" access port", vid, in_xbundle->name,
                             in_xbundle->vlan);
            }
            return false;
        }
        return true;

    case PORT_VLAN_NATIVE_UNTAGGED:
    case PORT_VLAN_NATIVE_TAGGED:
        if (!vid) {
            /* Port must always carry its native VLAN. */
            return true;
        }
        /* Fall through. */
    case PORT_VLAN_TRUNK:
        if (!xbundle_includes_vlan(in_xbundle, vid)) {
            if (warn) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "dropping VLAN %"PRIu16" packet "
                             "received on port %s not configured for trunking "
                             "VLAN %"PRIu16, vid, in_xbundle->name, vid);
            }
            return false;
        }
        return true;

    default:
        OVS_NOT_REACHED();
    }

}

/* Given 'vlan', the VLAN that a packet belongs to, and
 * 'out_xbundle', a bundle on which the packet is to be output, returns the VID
 * that should be included in the 802.1Q header.  (If the return value is 0,
 * then the 802.1Q header should only be included in the packet if there is a
 * nonzero PCP.)
 *
 * Both 'vlan' and the return value are in the range 0...4095. */
static uint16_t
output_vlan_to_vid(const struct xbundle *out_xbundle, uint16_t vlan)
{
    switch (out_xbundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        return 0;

    case PORT_VLAN_TRUNK:
    case PORT_VLAN_NATIVE_TAGGED:
        return vlan;

    case PORT_VLAN_NATIVE_UNTAGGED:
        return vlan == out_xbundle->vlan ? 0 : vlan;

    default:
        OVS_NOT_REACHED();
    }
}

static void
output_normal(struct xlate_ctx *ctx, const struct xbundle *out_xbundle,
              uint16_t vlan)
{
    ovs_be16 *flow_tci = &ctx->xin->flow.vlan_tci;
    uint16_t vid;
    ovs_be16 tci, old_tci;
    struct xport *xport;

    vid = output_vlan_to_vid(out_xbundle, vlan);
    if (list_is_empty(&out_xbundle->xports)) {
        /* Partially configured bundle with no slaves.  Drop the packet. */
        return;
    } else if (!out_xbundle->bond) {
        xport = CONTAINER_OF(list_front(&out_xbundle->xports), struct xport,
                             bundle_node);
    } else {
        struct ofport_dpif *ofport;

        ofport = bond_choose_output_slave(out_xbundle->bond, &ctx->xin->flow,
                                          &ctx->xout->wc, vid);
        xport = xport_lookup(ofport);

        if (!xport) {
            /* No slaves enabled, so drop packet. */
            return;
        }

        if (ctx->xin->resubmit_stats) {
            bond_account(out_xbundle->bond, &ctx->xin->flow, vid,
                         ctx->xin->resubmit_stats->n_bytes);
        }
    }

    old_tci = *flow_tci;
    tci = htons(vid);
    if (tci || out_xbundle->use_priority_tags) {
        tci |= *flow_tci & htons(VLAN_PCP_MASK);
        if (tci) {
            tci |= htons(VLAN_CFI);
        }
    }
    *flow_tci = tci;

    compose_output_action(ctx, xport->ofp_port);
    *flow_tci = old_tci;
}

/* A VM broadcasts a gratuitous ARP to indicate that it has resumed after
 * migration.  Older Citrix-patched Linux DomU used gratuitous ARP replies to
 * indicate this; newer upstream kernels use gratuitous ARP requests. */
static bool
is_gratuitous_arp(const struct flow *flow, struct flow_wildcards *wc)
{
    if (flow->dl_type != htons(ETH_TYPE_ARP)) {
        return false;
    }

    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
    if (!eth_addr_is_broadcast(flow->dl_dst)) {
        return false;
    }

    memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
    if (flow->nw_proto == ARP_OP_REPLY) {
        return true;
    } else if (flow->nw_proto == ARP_OP_REQUEST) {
        memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
        memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);

        return flow->nw_src == flow->nw_dst;
    } else {
        return false;
    }
}

/* Checks whether a MAC learning update is necessary for MAC learning table
 * 'ml' given that a packet matching 'flow' was received  on 'in_xbundle' in
 * 'vlan'.
 *
 * Most packets processed through the MAC learning table do not actually
 * change it in any way.  This function requires only a read lock on the MAC
 * learning table, so it is much cheaper in this common case.
 *
 * Keep the code here synchronized with that in update_learning_table__()
 * below. */
static bool
is_mac_learning_update_needed(const struct mac_learning *ml,
                              const struct flow *flow,
                              struct flow_wildcards *wc,
                              int vlan, struct xbundle *in_xbundle)
OVS_REQ_RDLOCK(ml->rwlock)
{
    struct mac_entry *mac;

    if (!mac_learning_may_learn(ml, flow->dl_src, vlan)) {
        return false;
    }

    mac = mac_learning_lookup(ml, flow->dl_src, vlan);
    if (!mac || mac_entry_age(ml, mac)) {
        return true;
    }

    if (is_gratuitous_arp(flow, wc)) {
        /* We don't want to learn from gratuitous ARP packets that are
         * reflected back over bond slaves so we lock the learning table. */
        if (!in_xbundle->bond) {
            return true;
        } else if (mac_entry_is_grat_arp_locked(mac)) {
            return false;
        }
    }

    return mac->port.p != in_xbundle->ofbundle;
}


/* Updates MAC learning table 'ml' given that a packet matching 'flow' was
 * received on 'in_xbundle' in 'vlan'.
 *
 * This code repeats all the checks in is_mac_learning_update_needed() because
 * the lock was released between there and here and thus the MAC learning state
 * could have changed.
 *
 * Keep the code here synchronized with that in is_mac_learning_update_needed()
 * above. */
static void
update_learning_table__(const struct xbridge *xbridge,
                        const struct flow *flow, struct flow_wildcards *wc,
                        int vlan, struct xbundle *in_xbundle)
OVS_REQ_WRLOCK(xbridge->ml->rwlock)
{
    struct mac_entry *mac;

    if (!mac_learning_may_learn(xbridge->ml, flow->dl_src, vlan)) {
        return;
    }

    mac = mac_learning_insert(xbridge->ml, flow->dl_src, vlan);
    if (is_gratuitous_arp(flow, wc)) {
        /* We don't want to learn from gratuitous ARP packets that are
         * reflected back over bond slaves so we lock the learning table. */
        if (!in_xbundle->bond) {
            mac_entry_set_grat_arp_lock(mac);
        } else if (mac_entry_is_grat_arp_locked(mac)) {
            return;
        }
    }

    if (mac->port.p != in_xbundle->ofbundle) {
        /* The log messages here could actually be useful in debugging,
         * so keep the rate limit relatively high. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

        VLOG_DBG_RL(&rl, "bridge %s: learned that "ETH_ADDR_FMT" is "
                    "on port %s in VLAN %d",
                    xbridge->name, ETH_ADDR_ARGS(flow->dl_src),
                    in_xbundle->name, vlan);

        mac->port.p = in_xbundle->ofbundle;
        mac_learning_changed(xbridge->ml);
    }
}

static void
update_learning_table(const struct xbridge *xbridge,
                      const struct flow *flow, struct flow_wildcards *wc,
                      int vlan, struct xbundle *in_xbundle)
{
    bool need_update;

    /* Don't learn the OFPP_NONE port. */
    if (in_xbundle == &ofpp_none_bundle) {
        return;
    }

    /* First try the common case: no change to MAC learning table. */
    ovs_rwlock_rdlock(&xbridge->ml->rwlock);
    need_update = is_mac_learning_update_needed(xbridge->ml, flow, wc, vlan,
                                                in_xbundle);
    ovs_rwlock_unlock(&xbridge->ml->rwlock);

    if (need_update) {
        /* Slow path: MAC learning table might need an update. */
        ovs_rwlock_wrlock(&xbridge->ml->rwlock);
        update_learning_table__(xbridge, flow, wc, vlan, in_xbundle);
        ovs_rwlock_unlock(&xbridge->ml->rwlock);
    }
}

/* Determines whether packets in 'flow' within 'xbridge' should be forwarded or
 * dropped.  Returns true if they may be forwarded, false if they should be
 * dropped.
 *
 * 'in_port' must be the xport that corresponds to flow->in_port.
 * 'in_port' must be part of a bundle (e.g. in_port->bundle must be nonnull).
 *
 * 'vlan' must be the VLAN that corresponds to flow->vlan_tci on 'in_port', as
 * returned by input_vid_to_vlan().  It must be a valid VLAN for 'in_port', as
 * checked by input_vid_is_valid().
 *
 * May also add tags to '*tags', although the current implementation only does
 * so in one special case.
 */
static bool
is_admissible(struct xlate_ctx *ctx, struct xport *in_port,
              uint16_t vlan)
{
    struct xbundle *in_xbundle = in_port->xbundle;
    const struct xbridge *xbridge = ctx->xbridge;
    struct flow *flow = &ctx->xin->flow;

    /* Drop frames for reserved multicast addresses
     * only if forward_bpdu option is absent. */
    if (!xbridge->forward_bpdu && eth_addr_is_reserved(flow->dl_dst)) {
        xlate_report(ctx, "packet has reserved destination MAC, dropping");
        return false;
    }

    if (in_xbundle->bond) {
        struct mac_entry *mac;

        switch (bond_check_admissibility(in_xbundle->bond, in_port->ofport,
                                         flow->dl_dst)) {
        case BV_ACCEPT:
            break;

        case BV_DROP:
            xlate_report(ctx, "bonding refused admissibility, dropping");
            return false;

        case BV_DROP_IF_MOVED:
            ovs_rwlock_rdlock(&xbridge->ml->rwlock);
            mac = mac_learning_lookup(xbridge->ml, flow->dl_src, vlan);
            if (mac && mac->port.p != in_xbundle->ofbundle &&
                (!is_gratuitous_arp(flow, &ctx->xout->wc)
                 || mac_entry_is_grat_arp_locked(mac))) {
                ovs_rwlock_unlock(&xbridge->ml->rwlock);
                xlate_report(ctx, "SLB bond thinks this packet looped back, "
                             "dropping");
                return false;
            }
            ovs_rwlock_unlock(&xbridge->ml->rwlock);
            break;
        }
    }

    return true;
}

static void
xlate_normal(struct xlate_ctx *ctx)
{
    struct flow_wildcards *wc = &ctx->xout->wc;
    struct flow *flow = &ctx->xin->flow;
    struct xbundle *in_xbundle;
    struct xport *in_port;
    struct mac_entry *mac;
    void *mac_port;
    uint16_t vlan;
    uint16_t vid;

    ctx->xout->has_normal = true;

    memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
    wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);

    in_xbundle = lookup_input_bundle(ctx->xbridge, flow->in_port.ofp_port,
                                     ctx->xin->packet != NULL, &in_port);
    if (!in_xbundle) {
        xlate_report(ctx, "no input bundle, dropping");
        return;
    }

    /* Drop malformed frames. */
    if (flow->dl_type == htons(ETH_TYPE_VLAN) &&
        !(flow->vlan_tci & htons(VLAN_CFI))) {
        if (ctx->xin->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet with partial "
                         "VLAN tag received on port %s",
                         ctx->xbridge->name, in_xbundle->name);
        }
        xlate_report(ctx, "partial VLAN tag, dropping");
        return;
    }

    /* Drop frames on bundles reserved for mirroring. */
    if (xbundle_mirror_out(ctx->xbridge, in_xbundle)) {
        if (ctx->xin->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port "
                         "%s, which is reserved exclusively for mirroring",
                         ctx->xbridge->name, in_xbundle->name);
        }
        xlate_report(ctx, "input port is mirror output port, dropping");
        return;
    }

    /* Check VLAN. */
    vid = vlan_tci_to_vid(flow->vlan_tci);
    if (!input_vid_is_valid(vid, in_xbundle, ctx->xin->packet != NULL)) {
        xlate_report(ctx, "disallowed VLAN VID for this input port, dropping");
        return;
    }
    vlan = input_vid_to_vlan(in_xbundle, vid);

    /* Check other admissibility requirements. */
    if (in_port && !is_admissible(ctx, in_port, vlan)) {
        return;
    }

    /* Learn source MAC. */
    if (ctx->xin->may_learn) {
        update_learning_table(ctx->xbridge, flow, wc, vlan, in_xbundle);
    }

    /* Determine output bundle. */
    ovs_rwlock_rdlock(&ctx->xbridge->ml->rwlock);
    mac = mac_learning_lookup(ctx->xbridge->ml, flow->dl_dst, vlan);
    mac_port = mac ? mac->port.p : NULL;
    ovs_rwlock_unlock(&ctx->xbridge->ml->rwlock);

    if (mac_port) {
        struct xbundle *mac_xbundle = xbundle_lookup(mac_port);
        if (mac_xbundle && mac_xbundle != in_xbundle) {
            xlate_report(ctx, "forwarding to learned port");
            output_normal(ctx, mac_xbundle, vlan);
        } else if (!mac_xbundle) {
            xlate_report(ctx, "learned port is unknown, dropping");
        } else {
            xlate_report(ctx, "learned port is input port, dropping");
        }
    } else {
        struct xbundle *xbundle;

        xlate_report(ctx, "no learned MAC for destination, flooding");
        LIST_FOR_EACH (xbundle, list_node, &ctx->xbridge->xbundles) {
            if (xbundle != in_xbundle
                && xbundle_includes_vlan(xbundle, vlan)
                && xbundle->floodable
                && !xbundle_mirror_out(ctx->xbridge, xbundle)) {
                output_normal(ctx, xbundle, vlan);
            }
        }
        ctx->xout->nf_output_iface = NF_OUT_FLOOD;
    }
}

/* Compose SAMPLE action for sFlow or IPFIX.  The given probability is
 * the number of packets out of UINT32_MAX to sample.  The given
 * cookie is passed back in the callback for each sampled packet.
 */
static size_t
compose_sample_action(const struct xbridge *xbridge,
                      struct ofpbuf *odp_actions,
                      const struct flow *flow,
                      const uint32_t probability,
                      const union user_action_cookie *cookie,
                      const size_t cookie_size)
{
    size_t sample_offset, actions_offset;
    odp_port_t odp_port;
    int cookie_offset;
    uint32_t pid;

    sample_offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_SAMPLE);

    nl_msg_put_u32(odp_actions, OVS_SAMPLE_ATTR_PROBABILITY, probability);

    actions_offset = nl_msg_start_nested(odp_actions, OVS_SAMPLE_ATTR_ACTIONS);

    odp_port = ofp_port_to_odp_port(xbridge, flow->in_port.ofp_port);
    pid = dpif_port_get_pid(xbridge->dpif, odp_port);
    cookie_offset = odp_put_userspace_action(pid, cookie, cookie_size, odp_actions);

    nl_msg_end_nested(odp_actions, actions_offset);
    nl_msg_end_nested(odp_actions, sample_offset);
    return cookie_offset;
}

static void
compose_sflow_cookie(const struct xbridge *xbridge, ovs_be16 vlan_tci,
                     odp_port_t odp_port, unsigned int n_outputs,
                     union user_action_cookie *cookie)
{
    int ifindex;

    cookie->type = USER_ACTION_COOKIE_SFLOW;
    cookie->sflow.vlan_tci = vlan_tci;

    /* See http://www.sflow.org/sflow_version_5.txt (search for "Input/output
     * port information") for the interpretation of cookie->output. */
    switch (n_outputs) {
    case 0:
        /* 0x40000000 | 256 means "packet dropped for unknown reason". */
        cookie->sflow.output = 0x40000000 | 256;
        break;

    case 1:
        ifindex = dpif_sflow_odp_port_to_ifindex(xbridge->sflow, odp_port);
        if (ifindex) {
            cookie->sflow.output = ifindex;
            break;
        }
        /* Fall through. */
    default:
        /* 0x80000000 means "multiple output ports. */
        cookie->sflow.output = 0x80000000 | n_outputs;
        break;
    }
}

/* Compose SAMPLE action for sFlow bridge sampling. */
static size_t
compose_sflow_action(const struct xbridge *xbridge,
                     struct ofpbuf *odp_actions,
                     const struct flow *flow,
                     odp_port_t odp_port)
{
    uint32_t probability;
    union user_action_cookie cookie;

    if (!xbridge->sflow || flow->in_port.ofp_port == OFPP_NONE) {
        return 0;
    }

    probability = dpif_sflow_get_probability(xbridge->sflow);
    compose_sflow_cookie(xbridge, htons(0), odp_port,
                         odp_port == ODPP_NONE ? 0 : 1, &cookie);

    return compose_sample_action(xbridge, odp_actions, flow,  probability,
                                 &cookie, sizeof cookie.sflow);
}

static void
compose_flow_sample_cookie(uint16_t probability, uint32_t collector_set_id,
                           uint32_t obs_domain_id, uint32_t obs_point_id,
                           union user_action_cookie *cookie)
{
    cookie->type = USER_ACTION_COOKIE_FLOW_SAMPLE;
    cookie->flow_sample.probability = probability;
    cookie->flow_sample.collector_set_id = collector_set_id;
    cookie->flow_sample.obs_domain_id = obs_domain_id;
    cookie->flow_sample.obs_point_id = obs_point_id;
}

static void
compose_ipfix_cookie(union user_action_cookie *cookie)
{
    cookie->type = USER_ACTION_COOKIE_IPFIX;
}

/* Compose SAMPLE action for IPFIX bridge sampling. */
static void
compose_ipfix_action(const struct xbridge *xbridge,
                     struct ofpbuf *odp_actions,
                     const struct flow *flow)
{
    uint32_t probability;
    union user_action_cookie cookie;

    if (!xbridge->ipfix || flow->in_port.ofp_port == OFPP_NONE) {
        return;
    }

    probability = dpif_ipfix_get_bridge_exporter_probability(xbridge->ipfix);
    compose_ipfix_cookie(&cookie);

    compose_sample_action(xbridge, odp_actions, flow,  probability,
                          &cookie, sizeof cookie.ipfix);
}

/* SAMPLE action for sFlow must be first action in any given list of
 * actions.  At this point we do not have all information required to
 * build it. So try to build sample action as complete as possible. */
static void
add_sflow_action(struct xlate_ctx *ctx)
{
    ctx->user_cookie_offset = compose_sflow_action(ctx->xbridge,
                                                   &ctx->xout->odp_actions,
                                                   &ctx->xin->flow, ODPP_NONE);
    ctx->sflow_odp_port = 0;
    ctx->sflow_n_outputs = 0;
}

/* SAMPLE action for IPFIX must be 1st or 2nd action in any given list
 * of actions, eventually after the SAMPLE action for sFlow. */
static void
add_ipfix_action(struct xlate_ctx *ctx)
{
    compose_ipfix_action(ctx->xbridge, &ctx->xout->odp_actions,
                         &ctx->xin->flow);
}

/* Fix SAMPLE action according to data collected while composing ODP actions.
 * We need to fix SAMPLE actions OVS_SAMPLE_ATTR_ACTIONS attribute, i.e. nested
 * USERSPACE action's user-cookie which is required for sflow. */
static void
fix_sflow_action(struct xlate_ctx *ctx)
{
    const struct flow *base = &ctx->base_flow;
    union user_action_cookie *cookie;

    if (!ctx->user_cookie_offset) {
        return;
    }

    cookie = ofpbuf_at(&ctx->xout->odp_actions, ctx->user_cookie_offset,
                       sizeof cookie->sflow);
    ovs_assert(cookie->type == USER_ACTION_COOKIE_SFLOW);

    compose_sflow_cookie(ctx->xbridge, base->vlan_tci,
                         ctx->sflow_odp_port, ctx->sflow_n_outputs, cookie);
}

static enum slow_path_reason
process_special(struct xlate_ctx *ctx, const struct flow *flow,
                const struct xport *xport, const struct ofpbuf *packet)
{
    struct flow_wildcards *wc = &ctx->xout->wc;
    const struct xbridge *xbridge = ctx->xbridge;

    if (!xport) {
        return 0;
    } else if (xport->cfm && cfm_should_process_flow(xport->cfm, flow, wc)) {
        if (packet) {
            cfm_process_heartbeat(xport->cfm, packet);
        }
        return SLOW_CFM;
    } else if (xport->bfd && bfd_should_process_flow(xport->bfd, flow, wc)) {
        if (packet) {
            bfd_process_packet(xport->bfd, flow, packet);
            /* If POLL received, immediately sends FINAL back. */
            if (bfd_should_send_packet(xport->bfd)) {
                if (xport->peer) {
                    ofproto_dpif_monitor_port_send_soon(xport->ofport);
                } else {
                    ofproto_dpif_monitor_port_send_soon_safe(xport->ofport);
                }
            }
        }
        return SLOW_BFD;
    } else if (xport->xbundle && xport->xbundle->lacp
               && flow->dl_type == htons(ETH_TYPE_LACP)) {
        if (packet) {
            lacp_process_packet(xport->xbundle->lacp, xport->ofport, packet);
        }
        return SLOW_LACP;
    } else if (xbridge->stp && stp_should_process_flow(flow, wc)) {
        if (packet) {
            stp_process_packet(xport, packet);
        }
        return SLOW_STP;
    } else {
        return 0;
    }
}

static void
compose_output_action__(struct xlate_ctx *ctx, ofp_port_t ofp_port,
                        bool check_stp)
{
    const struct xport *xport = get_ofp_port(ctx->xbridge, ofp_port);
    struct flow_wildcards *wc = &ctx->xout->wc;
    struct flow *flow = &ctx->xin->flow;
    ovs_be16 flow_vlan_tci;
    uint32_t flow_pkt_mark;
    uint8_t flow_nw_tos;
    odp_port_t out_port, odp_port;
    uint8_t dscp;

    /* If 'struct flow' gets additional metadata, we'll need to zero it out
     * before traversing a patch port. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 23);

    if (!xport) {
        xlate_report(ctx, "Nonexistent output port");
        return;
    } else if (xport->config & OFPUTIL_PC_NO_FWD) {
        xlate_report(ctx, "OFPPC_NO_FWD set, skipping output");
        return;
    } else if (check_stp) {
        if (eth_addr_equals(ctx->base_flow.dl_dst, eth_addr_stp)) {
            if (!xport_stp_listen_state(xport)) {
                xlate_report(ctx, "STP not in listening state, "
                             "skipping bpdu output");
                return;
            }
        } else if (!xport_stp_forward_state(xport)) {
            xlate_report(ctx, "STP not in forwarding state, "
                         "skipping output");
            return;
        }
    }

    if (mbridge_has_mirrors(ctx->xbridge->mbridge) && xport->xbundle) {
        ctx->xout->mirrors |= xbundle_mirror_dst(xport->xbundle->xbridge,
                                                 xport->xbundle);
    }

    if (xport->peer) {
        const struct xport *peer = xport->peer;
        struct flow old_flow = ctx->xin->flow;
        enum slow_path_reason special;

        ctx->xbridge = peer->xbridge;
        flow->in_port.ofp_port = peer->ofp_port;
        flow->metadata = htonll(0);
        memset(&flow->tunnel, 0, sizeof flow->tunnel);
        memset(flow->regs, 0, sizeof flow->regs);

        special = process_special(ctx, &ctx->xin->flow, peer,
                                  ctx->xin->packet);
        if (special) {
            ctx->xout->slow |= special;
        } else if (may_receive(peer, ctx)) {
            if (xport_stp_forward_state(peer)) {
                xlate_table_action(ctx, flow->in_port.ofp_port, 0, true);
            } else {
                /* Forwarding is disabled by STP.  Let OFPP_NORMAL and the
                 * learning action look at the packet, then drop it. */
                struct flow old_base_flow = ctx->base_flow;
                size_t old_size = ctx->xout->odp_actions.size;
                mirror_mask_t old_mirrors = ctx->xout->mirrors;
                xlate_table_action(ctx, flow->in_port.ofp_port, 0, true);
                ctx->xout->mirrors = old_mirrors;
                ctx->base_flow = old_base_flow;
                ctx->xout->odp_actions.size = old_size;
            }
        }

        ctx->xin->flow = old_flow;
        ctx->xbridge = xport->xbridge;

        if (ctx->xin->resubmit_stats) {
            netdev_vport_inc_tx(xport->netdev, ctx->xin->resubmit_stats);
            netdev_vport_inc_rx(peer->netdev, ctx->xin->resubmit_stats);
            if (peer->bfd) {
                bfd_account_rx(peer->bfd, ctx->xin->resubmit_stats);
            }
        }

        return;
    }

    flow_vlan_tci = flow->vlan_tci;
    flow_pkt_mark = flow->pkt_mark;
    flow_nw_tos = flow->nw_tos;

    if (dscp_from_skb_priority(xport, flow->skb_priority, &dscp)) {
        wc->masks.nw_tos |= IP_ECN_MASK;
        flow->nw_tos &= ~IP_DSCP_MASK;
        flow->nw_tos |= dscp;
    }

    if (xport->is_tunnel) {
         /* Save tunnel metadata so that changes made due to
          * the Logical (tunnel) Port are not visible for any further
          * matches, while explicit set actions on tunnel metadata are.
          */
        struct flow_tnl flow_tnl = flow->tunnel;
        odp_port = tnl_port_send(xport->ofport, flow, &ctx->xout->wc);
        if (odp_port == ODPP_NONE) {
            xlate_report(ctx, "Tunneling decided against output");
            goto out; /* restore flow_nw_tos */
        }
        if (flow->tunnel.ip_dst == ctx->orig_tunnel_ip_dst) {
            xlate_report(ctx, "Not tunneling to our own address");
            goto out; /* restore flow_nw_tos */
        }
        if (ctx->xin->resubmit_stats) {
            netdev_vport_inc_tx(xport->netdev, ctx->xin->resubmit_stats);
        }
        out_port = odp_port;
        commit_odp_tunnel_action(flow, &ctx->base_flow,
                                 &ctx->xout->odp_actions);
        flow->tunnel = flow_tnl; /* Restore tunnel metadata */
    } else {
        ofp_port_t vlandev_port;

        odp_port = xport->odp_port;
        if (ofproto_has_vlan_splinters(ctx->xbridge->ofproto)) {
            wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
        }
        vlandev_port = vsp_realdev_to_vlandev(ctx->xbridge->ofproto, ofp_port,
                                              flow->vlan_tci);
        if (vlandev_port == ofp_port) {
            out_port = odp_port;
        } else {
            out_port = ofp_port_to_odp_port(ctx->xbridge, vlandev_port);
            flow->vlan_tci = htons(0);
        }
    }

    if (out_port != ODPP_NONE) {
        ctx->xout->slow |= commit_odp_actions(flow, &ctx->base_flow,
                                              &ctx->xout->odp_actions,
                                              &ctx->xout->wc,
                                              &ctx->mpls_depth_delta);
        nl_msg_put_odp_port(&ctx->xout->odp_actions, OVS_ACTION_ATTR_OUTPUT,
                            out_port);

        ctx->sflow_odp_port = odp_port;
        ctx->sflow_n_outputs++;
        ctx->xout->nf_output_iface = ofp_port;
    }

 out:
    /* Restore flow */
    flow->vlan_tci = flow_vlan_tci;
    flow->pkt_mark = flow_pkt_mark;
    flow->nw_tos = flow_nw_tos;
}

static void
compose_output_action(struct xlate_ctx *ctx, ofp_port_t ofp_port)
{
    compose_output_action__(ctx, ofp_port, true);
}

static void
xlate_recursively(struct xlate_ctx *ctx, struct rule_dpif *rule)
{
    struct rule_dpif *old_rule = ctx->rule;
    struct rule_actions *actions;

    if (ctx->xin->resubmit_stats) {
        rule_dpif_credit_stats(rule, ctx->xin->resubmit_stats);
    }

    ctx->resubmits++;
    ctx->recurse++;
    ctx->rule = rule;
    actions = rule_dpif_get_actions(rule);
    do_xlate_actions(actions->ofpacts, actions->ofpacts_len, ctx);
    rule_actions_unref(actions);
    ctx->rule = old_rule;
    ctx->recurse--;
}

static bool
xlate_resubmit_resource_check(struct xlate_ctx *ctx)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

    if (ctx->recurse >= MAX_RESUBMIT_RECURSION) {
        VLOG_ERR_RL(&rl, "resubmit actions recursed over %d times",
                    MAX_RESUBMIT_RECURSION);
    } else if (ctx->resubmits >= MAX_RESUBMITS) {
        VLOG_ERR_RL(&rl, "over %d resubmit actions", MAX_RESUBMITS);
    } else if (ctx->xout->odp_actions.size > UINT16_MAX) {
        VLOG_ERR_RL(&rl, "resubmits yielded over 64 kB of actions");
    } else if (ctx->stack.size >= 65536) {
        VLOG_ERR_RL(&rl, "resubmits yielded over 64 kB of stack");
    } else {
        return true;
    }

    return false;
}

static void
xlate_table_action(struct xlate_ctx *ctx,
                   ofp_port_t in_port, uint8_t table_id, bool may_packet_in)
{
    if (xlate_resubmit_resource_check(ctx)) {
        ofp_port_t old_in_port = ctx->xin->flow.in_port.ofp_port;
        bool skip_wildcards = ctx->xin->skip_wildcards;
        uint8_t old_table_id = ctx->table_id;
        struct rule_dpif *rule;

        ctx->table_id = table_id;

        /* Look up a flow with 'in_port' as the input port.  Then restore the
         * original input port (otherwise OFPP_NORMAL and OFPP_IN_PORT will
         * have surprising behavior). */
        ctx->xin->flow.in_port.ofp_port = in_port;
        rule_dpif_lookup_in_table(ctx->xbridge->ofproto, &ctx->xin->flow,
                                  !skip_wildcards ? &ctx->xout->wc : NULL,
                                  table_id, &rule);
        ctx->xin->flow.in_port.ofp_port = old_in_port;

        if (ctx->xin->resubmit_hook) {
            ctx->xin->resubmit_hook(ctx->xin, rule, ctx->recurse);
        }

        if (!rule && may_packet_in) {
            struct xport *xport;

            /* XXX
             * check if table configuration flags
             * OFPTC11_TABLE_MISS_CONTROLLER, default.
             * OFPTC11_TABLE_MISS_CONTINUE,
             * OFPTC11_TABLE_MISS_DROP
             * When OF1.0, OFPTC11_TABLE_MISS_CONTINUE is used. What to do? */
            xport = get_ofp_port(ctx->xbridge, ctx->xin->flow.in_port.ofp_port);
            choose_miss_rule(xport ? xport->config : 0,
                             ctx->xbridge->miss_rule,
                             ctx->xbridge->no_packet_in_rule, &rule);
        }
        if (rule) {
            xlate_recursively(ctx, rule);
            rule_dpif_unref(rule);
        }

        ctx->table_id = old_table_id;
        return;
    }

    ctx->exit = true;
}

static void
xlate_group_bucket(struct xlate_ctx *ctx, const struct ofputil_bucket *bucket)
{
    uint64_t action_list_stub[1024 / 8];
    struct ofpbuf action_list, action_set;

    ofpbuf_use_const(&action_set, bucket->ofpacts, bucket->ofpacts_len);
    ofpbuf_use_stub(&action_list, action_list_stub, sizeof action_list_stub);

    ofpacts_execute_action_set(&action_list, &action_set);
    ctx->recurse++;
    do_xlate_actions(action_list.data, action_list.size, ctx);
    ctx->recurse--;

    ofpbuf_uninit(&action_set);
    ofpbuf_uninit(&action_list);
}

static void
xlate_all_group(struct xlate_ctx *ctx, struct group_dpif *group)
{
    const struct ofputil_bucket *bucket;
    const struct list *buckets;
    struct flow old_flow = ctx->xin->flow;

    group_dpif_get_buckets(group, &buckets);

    LIST_FOR_EACH (bucket, list_node, buckets) {
        xlate_group_bucket(ctx, bucket);
        /* Roll back flow to previous state.
         * This is equivalent to cloning the packet for each bucket.
         *
         * As a side effect any subsequently applied actions will
         * also effectively be applied to a clone of the packet taken
         * just before applying the all or indirect group. */
        ctx->xin->flow = old_flow;
    }
}

static void
xlate_ff_group(struct xlate_ctx *ctx, struct group_dpif *group)
{
    const struct ofputil_bucket *bucket;

    bucket = group_first_live_bucket(ctx, group, 0);
    if (bucket) {
        xlate_group_bucket(ctx, bucket);
    }
}

static void
xlate_select_group(struct xlate_ctx *ctx, struct group_dpif *group)
{
    struct flow_wildcards *wc = &ctx->xout->wc;
    const struct ofputil_bucket *bucket;
    uint32_t basis;

    basis = hash_bytes(ctx->xin->flow.dl_dst, sizeof ctx->xin->flow.dl_dst, 0);
    bucket = group_best_live_bucket(ctx, group, basis);
    if (bucket) {
        memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
        xlate_group_bucket(ctx, bucket);
    }
}

static void
xlate_group_action__(struct xlate_ctx *ctx, struct group_dpif *group)
{
    switch (group_dpif_get_type(group)) {
    case OFPGT11_ALL:
    case OFPGT11_INDIRECT:
        xlate_all_group(ctx, group);
        break;
    case OFPGT11_SELECT:
        xlate_select_group(ctx, group);
        break;
    case OFPGT11_FF:
        xlate_ff_group(ctx, group);
        break;
    default:
        OVS_NOT_REACHED();
    }
    group_dpif_release(group);
}

static bool
xlate_group_action(struct xlate_ctx *ctx, uint32_t group_id)
{
    if (xlate_resubmit_resource_check(ctx)) {
        struct group_dpif *group;
        bool got_group;

        got_group = group_dpif_lookup(ctx->xbridge->ofproto, group_id, &group);
        if (got_group) {
            xlate_group_action__(ctx, group);
        } else {
            return true;
        }
    }

    return false;
}

static void
xlate_ofpact_resubmit(struct xlate_ctx *ctx,
                      const struct ofpact_resubmit *resubmit)
{
    ofp_port_t in_port;
    uint8_t table_id;

    in_port = resubmit->in_port;
    if (in_port == OFPP_IN_PORT) {
        in_port = ctx->xin->flow.in_port.ofp_port;
    }

    table_id = resubmit->table_id;
    if (table_id == 255) {
        table_id = ctx->table_id;
    }

    xlate_table_action(ctx, in_port, table_id, false);
}

static void
flood_packets(struct xlate_ctx *ctx, bool all)
{
    const struct xport *xport;

    HMAP_FOR_EACH (xport, ofp_node, &ctx->xbridge->xports) {
        if (xport->ofp_port == ctx->xin->flow.in_port.ofp_port) {
            continue;
        }

        if (all) {
            compose_output_action__(ctx, xport->ofp_port, false);
        } else if (!(xport->config & OFPUTIL_PC_NO_FLOOD)) {
            compose_output_action(ctx, xport->ofp_port);
        }
    }

    ctx->xout->nf_output_iface = NF_OUT_FLOOD;
}

static void
execute_controller_action(struct xlate_ctx *ctx, int len,
                          enum ofp_packet_in_reason reason,
                          uint16_t controller_id)
{
    struct ofproto_packet_in *pin;
    struct ofpbuf *packet;
    struct flow key;

    ctx->xout->slow |= SLOW_CONTROLLER;
    if (!ctx->xin->packet) {
        return;
    }

    packet = ofpbuf_clone(ctx->xin->packet);

    key.skb_priority = 0;
    key.pkt_mark = 0;
    memset(&key.tunnel, 0, sizeof key.tunnel);

    ctx->xout->slow |= commit_odp_actions(&ctx->xin->flow, &ctx->base_flow,
                                          &ctx->xout->odp_actions,
                                          &ctx->xout->wc,
                                          &ctx->mpls_depth_delta);

    odp_execute_actions(NULL, packet, &key, ctx->xout->odp_actions.data,
                        ctx->xout->odp_actions.size, NULL, NULL);

    pin = xmalloc(sizeof *pin);
    pin->up.packet_len = packet->size;
    pin->up.packet = ofpbuf_steal_data(packet);
    pin->up.reason = reason;
    pin->up.table_id = ctx->table_id;
    pin->up.cookie = (ctx->rule
                      ? rule_dpif_get_flow_cookie(ctx->rule)
                      : OVS_BE64_MAX);

    flow_get_metadata(&ctx->xin->flow, &pin->up.fmd);

    pin->controller_id = controller_id;
    pin->send_len = len;
    pin->generated_by_table_miss = (ctx->rule
                                    && rule_dpif_is_table_miss(ctx->rule));
    ofproto_dpif_send_packet_in(ctx->xbridge->ofproto, pin);
    ofpbuf_delete(packet);
}

static bool
compose_mpls_push_action(struct xlate_ctx *ctx, ovs_be16 eth_type)
{
    struct flow_wildcards *wc = &ctx->xout->wc;
    struct flow *flow = &ctx->xin->flow;

    ovs_assert(eth_type_mpls(eth_type));

    /* If mpls_depth_delta is negative then an MPLS POP action has been
     * composed and the resulting MPLS label stack is unknown.  This means
     * an MPLS PUSH action can't be composed as it needs to know either the
     * top-most MPLS LSE to use as a template for the new MPLS LSE, or that
     * there is no MPLS label stack present.  Thus, stop processing.
     *
     * If mpls_depth_delta is positive then an MPLS PUSH action has been
     * composed and no further MPLS PUSH action may be performed without
     * losing MPLS LSE and ether type information held in xtx->xin->flow.
     * Thus, stop processing.
     *
     * If the MPLS LSE of the flow and base_flow differ then the MPLS LSE
     * has been updated.  Performing a MPLS PUSH action may be would result in
     * losing MPLS LSE and ether type information held in xtx->xin->flow.
     * Thus, stop processing.
     *
     * It is planned that in the future this case will be handled
     * by recirculation */
    if (ctx->mpls_depth_delta ||
        ctx->xin->flow.mpls_lse != ctx->base_flow.mpls_lse) {
        return true;
    }

    memset(&wc->masks.mpls_lse, 0xff, sizeof wc->masks.mpls_lse);

    ctx->pre_push_mpls_lse = ctx->xin->flow.mpls_lse;

    if (eth_type_mpls(ctx->xin->flow.dl_type)) {
        flow->mpls_lse &= ~htonl(MPLS_BOS_MASK);
    } else {
        ovs_be32 label;
        uint8_t tc, ttl;

        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            label = htonl(0x2); /* IPV6 Explicit Null. */
        } else {
            label = htonl(0x0); /* IPV4 Explicit Null. */
        }
        wc->masks.nw_tos |= IP_DSCP_MASK;
        wc->masks.nw_ttl = 0xff;
        tc = (flow->nw_tos & IP_DSCP_MASK) >> 2;
        ttl = flow->nw_ttl ? flow->nw_ttl : 0x40;
        flow->mpls_lse = set_mpls_lse_values(ttl, tc, 1, label);
    }
    flow->dl_type = eth_type;
    ctx->mpls_depth_delta++;

    return false;
}

static bool
compose_mpls_pop_action(struct xlate_ctx *ctx, ovs_be16 eth_type)
{
    struct flow_wildcards *wc = &ctx->xout->wc;

    if (!eth_type_mpls(ctx->xin->flow.dl_type)) {
        return true;
    }

    /* If mpls_depth_delta is negative then an MPLS POP action has been
     * composed.  Performing another MPLS POP action
     * would result in losing ether type that results from
     * the already composed MPLS POP. Thus, stop processing.
     *
     * It is planned that in the future this case will be handled
     * by recirculation */
    if (ctx->mpls_depth_delta < 0) {
        return true;
    }

    memset(&wc->masks.mpls_lse, 0xff, sizeof wc->masks.mpls_lse);

    /* If mpls_depth_delta is positive then an MPLS PUSH action has been
     * executed and the previous MPLS LSE saved in ctx->pre_push_mpls_lse. The
     * flow's MPLS LSE should be restored to that value to allow any
     * subsequent actions that update of the LSE to be executed correctly.
     */
    if (ctx->mpls_depth_delta > 0) {
        ctx->xin->flow.mpls_lse = ctx->pre_push_mpls_lse;
    }

    ctx->xin->flow.dl_type = eth_type;
    ctx->mpls_depth_delta--;

    return false;
}

static bool
compose_dec_ttl(struct xlate_ctx *ctx, struct ofpact_cnt_ids *ids)
{
    struct flow *flow = &ctx->xin->flow;

    if (!is_ip_any(flow)) {
        return false;
    }

    ctx->xout->wc.masks.nw_ttl = 0xff;
    if (flow->nw_ttl > 1) {
        flow->nw_ttl--;
        return false;
    } else {
        size_t i;

        for (i = 0; i < ids->n_controllers; i++) {
            execute_controller_action(ctx, UINT16_MAX, OFPR_INVALID_TTL,
                                      ids->cnt_ids[i]);
        }

        /* Stop processing for current table. */
        return true;
    }
}

static bool
compose_set_mpls_label_action(struct xlate_ctx *ctx, ovs_be32 label)
{
    if (!eth_type_mpls(ctx->xin->flow.dl_type)) {
        return true;
    }

    /* If mpls_depth_delta is negative then an MPLS POP action has been
     * executed and the resulting MPLS label stack is unknown.  This means
     * a SET MPLS LABEL action can't be executed as it needs to manipulate
     * the top-most MPLS LSE. Thus, stop processing.
     *
     * It is planned that in the future this case will be handled
     * by recirculation.
     */
    if (ctx->mpls_depth_delta < 0) {
        return true;
    }

    ctx->xout->wc.masks.mpls_lse |= htonl(MPLS_LABEL_MASK);
    set_mpls_lse_label(&ctx->xin->flow.mpls_lse, label);
    return false;
}

static bool
compose_set_mpls_tc_action(struct xlate_ctx *ctx, uint8_t tc)
{
    if (!eth_type_mpls(ctx->xin->flow.dl_type)) {
        return true;
    }

    /* If mpls_depth_delta is negative then an MPLS POP action has been
     * executed and the resulting MPLS label stack is unknown.  This means
     * a SET MPLS TC action can't be executed as it needs to manipulate
     * the top-most MPLS LSE. Thus, stop processing.
     *
     * It is planned that in the future this case will be handled
     * by recirculation.
     */
    if (ctx->mpls_depth_delta < 0) {
        return true;
    }

    ctx->xout->wc.masks.mpls_lse |= htonl(MPLS_TC_MASK);
    set_mpls_lse_tc(&ctx->xin->flow.mpls_lse, tc);
    return false;
}

static bool
compose_set_mpls_ttl_action(struct xlate_ctx *ctx, uint8_t ttl)
{
    if (!eth_type_mpls(ctx->xin->flow.dl_type)) {
        return true;
    }

    /* If mpls_depth_delta is negative then an MPLS POP action has been
     * executed and the resulting MPLS label stack is unknown.  This means
     * a SET MPLS TTL push action can't be executed as it needs to manipulate
     * the top-most MPLS LSE. Thus, stop processing.
     *
     * It is planned that in the future this case will be handled
     * by recirculation.
     */
    if (ctx->mpls_depth_delta < 0) {
        return true;
    }

    ctx->xout->wc.masks.mpls_lse |= htonl(MPLS_TTL_MASK);
    set_mpls_lse_ttl(&ctx->xin->flow.mpls_lse, ttl);
    return false;
}

static bool
compose_dec_mpls_ttl_action(struct xlate_ctx *ctx)
{
    struct flow *flow = &ctx->xin->flow;
    uint8_t ttl = mpls_lse_to_ttl(flow->mpls_lse);
    struct flow_wildcards *wc = &ctx->xout->wc;

    memset(&wc->masks.mpls_lse, 0xff, sizeof wc->masks.mpls_lse);

    if (!eth_type_mpls(flow->dl_type)) {
        return false;
    }

    if (ttl > 1) {
        ttl--;
        set_mpls_lse_ttl(&flow->mpls_lse, ttl);
        return false;
    } else {
        execute_controller_action(ctx, UINT16_MAX, OFPR_INVALID_TTL, 0);

        /* Stop processing for current table. */
        return true;
    }
}

static void
xlate_output_action(struct xlate_ctx *ctx,
                    ofp_port_t port, uint16_t max_len, bool may_packet_in)
{
    ofp_port_t prev_nf_output_iface = ctx->xout->nf_output_iface;

    ctx->xout->nf_output_iface = NF_OUT_DROP;

    switch (port) {
    case OFPP_IN_PORT:
        compose_output_action(ctx, ctx->xin->flow.in_port.ofp_port);
        break;
    case OFPP_TABLE:
        xlate_table_action(ctx, ctx->xin->flow.in_port.ofp_port,
                           0, may_packet_in);
        break;
    case OFPP_NORMAL:
        xlate_normal(ctx);
        break;
    case OFPP_FLOOD:
        flood_packets(ctx,  false);
        break;
    case OFPP_ALL:
        flood_packets(ctx, true);
        break;
    case OFPP_CONTROLLER:
        execute_controller_action(ctx, max_len, OFPR_ACTION, 0);
        break;
    case OFPP_NONE:
        break;
    case OFPP_LOCAL:
    default:
        if (port != ctx->xin->flow.in_port.ofp_port) {
            compose_output_action(ctx, port);
        } else {
            xlate_report(ctx, "skipping output to input port");
        }
        break;
    }

    if (prev_nf_output_iface == NF_OUT_FLOOD) {
        ctx->xout->nf_output_iface = NF_OUT_FLOOD;
    } else if (ctx->xout->nf_output_iface == NF_OUT_DROP) {
        ctx->xout->nf_output_iface = prev_nf_output_iface;
    } else if (prev_nf_output_iface != NF_OUT_DROP &&
               ctx->xout->nf_output_iface != NF_OUT_FLOOD) {
        ctx->xout->nf_output_iface = NF_OUT_MULTI;
    }
}

static void
xlate_output_reg_action(struct xlate_ctx *ctx,
                        const struct ofpact_output_reg *or)
{
    uint64_t port = mf_get_subfield(&or->src, &ctx->xin->flow);
    if (port <= UINT16_MAX) {
        union mf_subvalue value;

        memset(&value, 0xff, sizeof value);
        mf_write_subfield_flow(&or->src, &value, &ctx->xout->wc.masks);
        xlate_output_action(ctx, u16_to_ofp(port),
                            or->max_len, false);
    }
}

static void
xlate_enqueue_action(struct xlate_ctx *ctx,
                     const struct ofpact_enqueue *enqueue)
{
    ofp_port_t ofp_port = enqueue->port;
    uint32_t queue_id = enqueue->queue;
    uint32_t flow_priority, priority;
    int error;

    /* Translate queue to priority. */
    error = dpif_queue_to_priority(ctx->xbridge->dpif, queue_id, &priority);
    if (error) {
        /* Fall back to ordinary output action. */
        xlate_output_action(ctx, enqueue->port, 0, false);
        return;
    }

    /* Check output port. */
    if (ofp_port == OFPP_IN_PORT) {
        ofp_port = ctx->xin->flow.in_port.ofp_port;
    } else if (ofp_port == ctx->xin->flow.in_port.ofp_port) {
        return;
    }

    /* Add datapath actions. */
    flow_priority = ctx->xin->flow.skb_priority;
    ctx->xin->flow.skb_priority = priority;
    compose_output_action(ctx, ofp_port);
    ctx->xin->flow.skb_priority = flow_priority;

    /* Update NetFlow output port. */
    if (ctx->xout->nf_output_iface == NF_OUT_DROP) {
        ctx->xout->nf_output_iface = ofp_port;
    } else if (ctx->xout->nf_output_iface != NF_OUT_FLOOD) {
        ctx->xout->nf_output_iface = NF_OUT_MULTI;
    }
}

static void
xlate_set_queue_action(struct xlate_ctx *ctx, uint32_t queue_id)
{
    uint32_t skb_priority;

    if (!dpif_queue_to_priority(ctx->xbridge->dpif, queue_id, &skb_priority)) {
        ctx->xin->flow.skb_priority = skb_priority;
    } else {
        /* Couldn't translate queue to a priority.  Nothing to do.  A warning
         * has already been logged. */
    }
}

static bool
slave_enabled_cb(ofp_port_t ofp_port, void *xbridge_)
{
    const struct xbridge *xbridge = xbridge_;
    struct xport *port;

    switch (ofp_port) {
    case OFPP_IN_PORT:
    case OFPP_TABLE:
    case OFPP_NORMAL:
    case OFPP_FLOOD:
    case OFPP_ALL:
    case OFPP_NONE:
        return true;
    case OFPP_CONTROLLER: /* Not supported by the bundle action. */
        return false;
    default:
        port = get_ofp_port(xbridge, ofp_port);
        return port ? port->may_enable : false;
    }
}

static void
xlate_bundle_action(struct xlate_ctx *ctx,
                    const struct ofpact_bundle *bundle)
{
    ofp_port_t port;

    port = bundle_execute(bundle, &ctx->xin->flow, &ctx->xout->wc,
                          slave_enabled_cb,
                          CONST_CAST(struct xbridge *, ctx->xbridge));
    if (bundle->dst.field) {
        nxm_reg_load(&bundle->dst, ofp_to_u16(port), &ctx->xin->flow,
                     &ctx->xout->wc);
    } else {
        xlate_output_action(ctx, port, 0, false);
    }
}

static void
xlate_learn_action(struct xlate_ctx *ctx,
                   const struct ofpact_learn *learn)
{
    uint64_t ofpacts_stub[1024 / 8];
    struct ofputil_flow_mod fm;
    struct ofpbuf ofpacts;

    ctx->xout->has_learn = true;

    learn_mask(learn, &ctx->xout->wc);

    if (!ctx->xin->may_learn) {
        return;
    }

    ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    learn_execute(learn, &ctx->xin->flow, &fm, &ofpacts);
    ofproto_dpif_flow_mod(ctx->xbridge->ofproto, &fm);
    ofpbuf_uninit(&ofpacts);
}

static void
xlate_fin_timeout(struct xlate_ctx *ctx,
                  const struct ofpact_fin_timeout *oft)
{
    if (ctx->xin->tcp_flags & (TCP_FIN | TCP_RST) && ctx->rule) {
        rule_dpif_reduce_timeouts(ctx->rule, oft->fin_idle_timeout,
                                  oft->fin_hard_timeout);
    }
}

static void
xlate_sample_action(struct xlate_ctx *ctx,
                    const struct ofpact_sample *os)
{
  union user_action_cookie cookie;
  /* Scale the probability from 16-bit to 32-bit while representing
   * the same percentage. */
  uint32_t probability = (os->probability << 16) | os->probability;

  ctx->xout->slow |= commit_odp_actions(&ctx->xin->flow, &ctx->base_flow,
                                        &ctx->xout->odp_actions,
                                        &ctx->xout->wc,
                                        &ctx->mpls_depth_delta);

  compose_flow_sample_cookie(os->probability, os->collector_set_id,
                             os->obs_domain_id, os->obs_point_id, &cookie);
  compose_sample_action(ctx->xbridge, &ctx->xout->odp_actions, &ctx->xin->flow,
                        probability, &cookie, sizeof cookie.flow_sample);
}

static bool
may_receive(const struct xport *xport, struct xlate_ctx *ctx)
{
    if (xport->config & (eth_addr_equals(ctx->xin->flow.dl_dst, eth_addr_stp)
                         ? OFPUTIL_PC_NO_RECV_STP
                         : OFPUTIL_PC_NO_RECV)) {
        return false;
    }

    /* Only drop packets here if both forwarding and learning are
     * disabled.  If just learning is enabled, we need to have
     * OFPP_NORMAL and the learning action have a look at the packet
     * before we can drop it. */
    if (!xport_stp_forward_state(xport) && !xport_stp_learn_state(xport)) {
        return false;
    }

    return true;
}

static void
xlate_write_actions(struct xlate_ctx *ctx, const struct ofpact *a)
{
    struct ofpact_nest *on = ofpact_get_WRITE_ACTIONS(a);
    ofpbuf_put(&ctx->action_set, on->actions, ofpact_nest_get_action_len(on));
    ofpact_pad(&ctx->action_set);
}

static void
xlate_action_set(struct xlate_ctx *ctx)
{
    uint64_t action_list_stub[1024 / 64];
    struct ofpbuf action_list;

    ofpbuf_use_stub(&action_list, action_list_stub, sizeof action_list_stub);
    ofpacts_execute_action_set(&action_list, &ctx->action_set);
    do_xlate_actions(action_list.data, action_list.size, ctx);
    ofpbuf_uninit(&action_list);
}

static void
do_xlate_actions(const struct ofpact *ofpacts, size_t ofpacts_len,
                 struct xlate_ctx *ctx)
{
    struct flow_wildcards *wc = &ctx->xout->wc;
    struct flow *flow = &ctx->xin->flow;
    const struct ofpact *a;

    /* dl_type already in the mask, not set below. */

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        struct ofpact_controller *controller;
        const struct ofpact_metadata *metadata;
        const struct ofpact_set_field *set_field;
        const struct mf_field *mf;

        if (ctx->exit) {
            break;
        }

        switch (a->type) {
        case OFPACT_OUTPUT:
            xlate_output_action(ctx, ofpact_get_OUTPUT(a)->port,
                                ofpact_get_OUTPUT(a)->max_len, true);
            break;

        case OFPACT_GROUP:
            if (xlate_group_action(ctx, ofpact_get_GROUP(a)->group_id)) {
                return;
            }
            break;

        case OFPACT_CONTROLLER:
            controller = ofpact_get_CONTROLLER(a);
            execute_controller_action(ctx, controller->max_len,
                                      controller->reason,
                                      controller->controller_id);
            break;

        case OFPACT_ENQUEUE:
            xlate_enqueue_action(ctx, ofpact_get_ENQUEUE(a));
            break;

        case OFPACT_SET_VLAN_VID:
            wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
            if (flow->vlan_tci & htons(VLAN_CFI) ||
                ofpact_get_SET_VLAN_VID(a)->push_vlan_if_needed) {
                flow->vlan_tci &= ~htons(VLAN_VID_MASK);
                flow->vlan_tci |= (htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid)
                                   | htons(VLAN_CFI));
            }
            break;

        case OFPACT_SET_VLAN_PCP:
            wc->masks.vlan_tci |= htons(VLAN_PCP_MASK | VLAN_CFI);
            if (flow->vlan_tci & htons(VLAN_CFI) ||
                ofpact_get_SET_VLAN_PCP(a)->push_vlan_if_needed) {
                flow->vlan_tci &= ~htons(VLAN_PCP_MASK);
                flow->vlan_tci |= htons((ofpact_get_SET_VLAN_PCP(a)->vlan_pcp
                                         << VLAN_PCP_SHIFT) | VLAN_CFI);
            }
            break;

        case OFPACT_STRIP_VLAN:
            memset(&wc->masks.vlan_tci, 0xff, sizeof wc->masks.vlan_tci);
            flow->vlan_tci = htons(0);
            break;

        case OFPACT_PUSH_VLAN:
            /* XXX 802.1AD(QinQ) */
            memset(&wc->masks.vlan_tci, 0xff, sizeof wc->masks.vlan_tci);
            flow->vlan_tci = htons(VLAN_CFI);
            break;

        case OFPACT_SET_ETH_SRC:
            memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
            memcpy(flow->dl_src, ofpact_get_SET_ETH_SRC(a)->mac, ETH_ADDR_LEN);
            break;

        case OFPACT_SET_ETH_DST:
            memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
            memcpy(flow->dl_dst, ofpact_get_SET_ETH_DST(a)->mac, ETH_ADDR_LEN);
            break;

        case OFPACT_SET_IPV4_SRC:
            if (flow->dl_type == htons(ETH_TYPE_IP)) {
                memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
                flow->nw_src = ofpact_get_SET_IPV4_SRC(a)->ipv4;
            }
            break;

        case OFPACT_SET_IPV4_DST:
            if (flow->dl_type == htons(ETH_TYPE_IP)) {
                memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
                flow->nw_dst = ofpact_get_SET_IPV4_DST(a)->ipv4;
            }
            break;

        case OFPACT_SET_IP_DSCP:
            if (is_ip_any(flow)) {
                wc->masks.nw_tos |= IP_DSCP_MASK;
                flow->nw_tos &= ~IP_DSCP_MASK;
                flow->nw_tos |= ofpact_get_SET_IP_DSCP(a)->dscp;
            }
            break;

        case OFPACT_SET_IP_ECN:
            if (is_ip_any(flow)) {
                wc->masks.nw_tos |= IP_ECN_MASK;
                flow->nw_tos &= ~IP_ECN_MASK;
                flow->nw_tos |= ofpact_get_SET_IP_ECN(a)->ecn;
            }
            break;

        case OFPACT_SET_IP_TTL:
            if (is_ip_any(flow)) {
                wc->masks.nw_ttl = 0xff;
                flow->nw_ttl = ofpact_get_SET_IP_TTL(a)->ttl;
            }
            break;

        case OFPACT_SET_L4_SRC_PORT:
            if (is_ip_any(flow)) {
                memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
                memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
                flow->tp_src = htons(ofpact_get_SET_L4_SRC_PORT(a)->port);
            }
            break;

        case OFPACT_SET_L4_DST_PORT:
            if (is_ip_any(flow)) {
                memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
                memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
                flow->tp_dst = htons(ofpact_get_SET_L4_DST_PORT(a)->port);
            }
            break;

        case OFPACT_RESUBMIT:
            xlate_ofpact_resubmit(ctx, ofpact_get_RESUBMIT(a));
            break;

        case OFPACT_SET_TUNNEL:
            flow->tunnel.tun_id = htonll(ofpact_get_SET_TUNNEL(a)->tun_id);
            break;

        case OFPACT_SET_QUEUE:
            xlate_set_queue_action(ctx, ofpact_get_SET_QUEUE(a)->queue_id);
            break;

        case OFPACT_POP_QUEUE:
            flow->skb_priority = ctx->orig_skb_priority;
            break;

        case OFPACT_REG_MOVE:
            nxm_execute_reg_move(ofpact_get_REG_MOVE(a), flow, wc);
            break;

        case OFPACT_REG_LOAD:
            nxm_execute_reg_load(ofpact_get_REG_LOAD(a), flow, wc);
            break;

        case OFPACT_SET_FIELD:
            set_field = ofpact_get_SET_FIELD(a);
            mf = set_field->field;
            mf_mask_field_and_prereqs(mf, &wc->masks);

            /* Set field action only ever overwrites packet's outermost
             * applicable header fields.  Do nothing if no header exists. */
            if ((mf->id != MFF_VLAN_VID || flow->vlan_tci & htons(VLAN_CFI))
                && ((mf->id != MFF_MPLS_LABEL && mf->id != MFF_MPLS_TC)
                    || flow->mpls_lse)) {
                mf_set_flow_value(mf, &set_field->value, flow);
            }
            break;

        case OFPACT_STACK_PUSH:
            nxm_execute_stack_push(ofpact_get_STACK_PUSH(a), flow, wc,
                                   &ctx->stack);
            break;

        case OFPACT_STACK_POP:
            nxm_execute_stack_pop(ofpact_get_STACK_POP(a), flow, wc,
                                  &ctx->stack);
            break;

        case OFPACT_PUSH_MPLS:
            if (compose_mpls_push_action(ctx,
                                         ofpact_get_PUSH_MPLS(a)->ethertype)) {
                return;
            }
            break;

        case OFPACT_POP_MPLS:
            if (compose_mpls_pop_action(ctx,
                                        ofpact_get_POP_MPLS(a)->ethertype)) {
                return;
            }
            break;

        case OFPACT_SET_MPLS_LABEL:
            if (compose_set_mpls_label_action(ctx,
                                              ofpact_get_SET_MPLS_LABEL(a)->label)) {
                return;
            }
            break;

        case OFPACT_SET_MPLS_TC:
            if (compose_set_mpls_tc_action(ctx,
                                           ofpact_get_SET_MPLS_TC(a)->tc)) {
                return;
            }
            break;

        case OFPACT_SET_MPLS_TTL:
            if (compose_set_mpls_ttl_action(ctx,
                                            ofpact_get_SET_MPLS_TTL(a)->ttl)) {
                return;
            }
            break;

        case OFPACT_DEC_MPLS_TTL:
            if (compose_dec_mpls_ttl_action(ctx)) {
                return;
            }
            break;

        case OFPACT_DEC_TTL:
            wc->masks.nw_ttl = 0xff;
            if (compose_dec_ttl(ctx, ofpact_get_DEC_TTL(a))) {
                return;
            }
            break;

        case OFPACT_NOTE:
            /* Nothing to do. */
            break;

        case OFPACT_MULTIPATH:
            multipath_execute(ofpact_get_MULTIPATH(a), flow, wc);
            break;

        case OFPACT_BUNDLE:
            xlate_bundle_action(ctx, ofpact_get_BUNDLE(a));
            break;

        case OFPACT_OUTPUT_REG:
            xlate_output_reg_action(ctx, ofpact_get_OUTPUT_REG(a));
            break;

        case OFPACT_LEARN:
            xlate_learn_action(ctx, ofpact_get_LEARN(a));
            break;

        case OFPACT_EXIT:
            ctx->exit = true;
            break;

        case OFPACT_FIN_TIMEOUT:
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
            ctx->xout->has_fin_timeout = true;
            xlate_fin_timeout(ctx, ofpact_get_FIN_TIMEOUT(a));
            break;

        case OFPACT_CLEAR_ACTIONS:
            ofpbuf_clear(&ctx->action_set);
            break;

        case OFPACT_WRITE_ACTIONS:
            xlate_write_actions(ctx, a);
            break;

        case OFPACT_WRITE_METADATA:
            metadata = ofpact_get_WRITE_METADATA(a);
            flow->metadata &= ~metadata->mask;
            flow->metadata |= metadata->metadata & metadata->mask;
            break;

        case OFPACT_METER:
            /* Not implemented yet. */
            break;

        case OFPACT_GOTO_TABLE: {
            struct ofpact_goto_table *ogt = ofpact_get_GOTO_TABLE(a);

            ovs_assert(ctx->table_id < ogt->table_id);
            xlate_table_action(ctx, ctx->xin->flow.in_port.ofp_port,
                               ogt->table_id, true);
            break;
        }

        case OFPACT_SAMPLE:
            xlate_sample_action(ctx, ofpact_get_SAMPLE(a));
            break;
        }
    }
}

void
xlate_in_init(struct xlate_in *xin, struct ofproto_dpif *ofproto,
              const struct flow *flow, struct rule_dpif *rule,
              uint16_t tcp_flags, const struct ofpbuf *packet)
{
    xin->ofproto = ofproto;
    xin->flow = *flow;
    xin->packet = packet;
    xin->may_learn = packet != NULL;
    xin->rule = rule;
    xin->ofpacts = NULL;
    xin->ofpacts_len = 0;
    xin->tcp_flags = tcp_flags;
    xin->resubmit_hook = NULL;
    xin->report_hook = NULL;
    xin->resubmit_stats = NULL;
    xin->skip_wildcards = false;
}

void
xlate_out_uninit(struct xlate_out *xout)
{
    if (xout) {
        ofpbuf_uninit(&xout->odp_actions);
    }
}

/* Translates the 'ofpacts_len' bytes of "struct ofpact"s starting at 'ofpacts'
 * into datapath actions, using 'ctx', and discards the datapath actions. */
void
xlate_actions_for_side_effects(struct xlate_in *xin)
{
    struct xlate_out xout;

    xlate_actions(xin, &xout);
    xlate_out_uninit(&xout);
}

static void
xlate_report(struct xlate_ctx *ctx, const char *s)
{
    if (ctx->xin->report_hook) {
        ctx->xin->report_hook(ctx->xin, s, ctx->recurse);
    }
}

void
xlate_out_copy(struct xlate_out *dst, const struct xlate_out *src)
{
    dst->wc = src->wc;
    dst->slow = src->slow;
    dst->has_learn = src->has_learn;
    dst->has_normal = src->has_normal;
    dst->has_fin_timeout = src->has_fin_timeout;
    dst->nf_output_iface = src->nf_output_iface;
    dst->mirrors = src->mirrors;

    ofpbuf_use_stub(&dst->odp_actions, dst->odp_actions_stub,
                    sizeof dst->odp_actions_stub);
    ofpbuf_put(&dst->odp_actions, src->odp_actions.data,
               src->odp_actions.size);
}

static struct skb_priority_to_dscp *
get_skb_priority(const struct xport *xport, uint32_t skb_priority)
{
    struct skb_priority_to_dscp *pdscp;
    uint32_t hash;

    hash = hash_int(skb_priority, 0);
    HMAP_FOR_EACH_IN_BUCKET (pdscp, hmap_node, hash, &xport->skb_priorities) {
        if (pdscp->skb_priority == skb_priority) {
            return pdscp;
        }
    }
    return NULL;
}

static bool
dscp_from_skb_priority(const struct xport *xport, uint32_t skb_priority,
                       uint8_t *dscp)
{
    struct skb_priority_to_dscp *pdscp = get_skb_priority(xport, skb_priority);
    *dscp = pdscp ? pdscp->dscp : 0;
    return pdscp != NULL;
}

static void
clear_skb_priorities(struct xport *xport)
{
    struct skb_priority_to_dscp *pdscp, *next;

    HMAP_FOR_EACH_SAFE (pdscp, next, hmap_node, &xport->skb_priorities) {
        hmap_remove(&xport->skb_priorities, &pdscp->hmap_node);
        free(pdscp);
    }
}

static bool
actions_output_to_local_port(const struct xlate_ctx *ctx)
{
    odp_port_t local_odp_port = ofp_port_to_odp_port(ctx->xbridge, OFPP_LOCAL);
    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, ctx->xout->odp_actions.data,
                             ctx->xout->odp_actions.size) {
        if (nl_attr_type(a) == OVS_ACTION_ATTR_OUTPUT
            && nl_attr_get_odp_port(a) == local_odp_port) {
            return true;
        }
    }
    return false;
}

/* Thread safe call to xlate_actions__(). */
void
xlate_actions(struct xlate_in *xin, struct xlate_out *xout)
{
    ovs_rwlock_rdlock(&xlate_rwlock);
    xlate_actions__(xin, xout);
    ovs_rwlock_unlock(&xlate_rwlock);
}

/* Translates the 'ofpacts_len' bytes of "struct ofpacts" starting at 'ofpacts'
 * into datapath actions in 'odp_actions', using 'ctx'.
 *
 * The caller must take responsibility for eventually freeing 'xout', with
 * xlate_out_uninit(). */
static void
xlate_actions__(struct xlate_in *xin, struct xlate_out *xout)
    OVS_REQ_RDLOCK(xlate_rwlock)
{
    struct flow_wildcards *wc = &xout->wc;
    struct flow *flow = &xin->flow;
    struct rule_dpif *rule = NULL;

    struct rule_actions *actions = NULL;
    enum slow_path_reason special;
    const struct ofpact *ofpacts;
    struct xport *in_port;
    struct flow orig_flow;
    struct xlate_ctx ctx;
    size_t ofpacts_len;
    bool tnl_may_send;
    bool is_icmp;

    COVERAGE_INC(xlate_actions);

    /* Flow initialization rules:
     * - 'base_flow' must match the kernel's view of the packet at the
     *   time that action processing starts.  'flow' represents any
     *   transformations we wish to make through actions.
     * - By default 'base_flow' and 'flow' are the same since the input
     *   packet matches the output before any actions are applied.
     * - When using VLAN splinters, 'base_flow''s VLAN is set to the value
     *   of the received packet as seen by the kernel.  If we later output
     *   to another device without any modifications this will cause us to
     *   insert a new tag since the original one was stripped off by the
     *   VLAN device.
     * - Tunnel metadata as received is retained in 'flow'. This allows
     *   tunnel metadata matching also in later tables.
     *   Since a kernel action for setting the tunnel metadata will only be
     *   generated with actual tunnel output, changing the tunnel metadata
     *   values in 'flow' (such as tun_id) will only have effect with a later
     *   tunnel output action.
     * - Tunnel 'base_flow' is completely cleared since that is what the
     *   kernel does.  If we wish to maintain the original values an action
     *   needs to be generated. */

    ctx.xin = xin;
    ctx.xout = xout;
    ctx.xout->slow = 0;
    ctx.xout->has_learn = false;
    ctx.xout->has_normal = false;
    ctx.xout->has_fin_timeout = false;
    ctx.xout->nf_output_iface = NF_OUT_DROP;
    ctx.xout->mirrors = 0;
    ofpbuf_use_stub(&ctx.xout->odp_actions, ctx.xout->odp_actions_stub,
                    sizeof ctx.xout->odp_actions_stub);
    ofpbuf_reserve(&ctx.xout->odp_actions, NL_A_U32_SIZE);

    ctx.xbridge = xbridge_lookup(xin->ofproto);
    if (!ctx.xbridge) {
        goto out;
    }

    ctx.rule = xin->rule;

    ctx.base_flow = *flow;
    memset(&ctx.base_flow.tunnel, 0, sizeof ctx.base_flow.tunnel);
    ctx.orig_tunnel_ip_dst = flow->tunnel.ip_dst;

    flow_wildcards_init_catchall(wc);
    memset(&wc->masks.in_port, 0xff, sizeof wc->masks.in_port);
    memset(&wc->masks.skb_priority, 0xff, sizeof wc->masks.skb_priority);
    memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
    if (is_ip_any(flow)) {
        wc->masks.nw_frag |= FLOW_NW_FRAG_MASK;
    }
    is_icmp = is_icmpv4(flow) || is_icmpv6(flow);

    tnl_may_send = tnl_xlate_init(&ctx.base_flow, flow, wc);
    if (ctx.xbridge->netflow) {
        netflow_mask_wc(flow, wc);
    }

    ctx.recurse = 0;
    ctx.resubmits = 0;
    ctx.orig_skb_priority = flow->skb_priority;
    ctx.table_id = 0;
    ctx.exit = false;
    ctx.mpls_depth_delta = 0;

    if (!xin->ofpacts && !ctx.rule) {
        rule_dpif_lookup(ctx.xbridge->ofproto, flow,
                         !xin->skip_wildcards ? wc : NULL, &rule);
        if (ctx.xin->resubmit_stats) {
            rule_dpif_credit_stats(rule, ctx.xin->resubmit_stats);
        }
        ctx.rule = rule;
    }
    xout->fail_open = ctx.rule && rule_dpif_is_fail_open(ctx.rule);

    if (xin->ofpacts) {
        ofpacts = xin->ofpacts;
        ofpacts_len = xin->ofpacts_len;
    } else if (ctx.rule) {
        actions = rule_dpif_get_actions(ctx.rule);
        ofpacts = actions->ofpacts;
        ofpacts_len = actions->ofpacts_len;
    } else {
        OVS_NOT_REACHED();
    }

    ofpbuf_use_stub(&ctx.stack, ctx.init_stack, sizeof ctx.init_stack);
    ofpbuf_use_stub(&ctx.action_set,
                    ctx.action_set_stub, sizeof ctx.action_set_stub);

    if (mbridge_has_mirrors(ctx.xbridge->mbridge)) {
        /* Do this conditionally because the copy is expensive enough that it
         * shows up in profiles. */
        orig_flow = *flow;
    }

    if (flow->nw_frag & FLOW_NW_FRAG_ANY) {
        switch (ctx.xbridge->frag) {
        case OFPC_FRAG_NORMAL:
            /* We must pretend that transport ports are unavailable. */
            flow->tp_src = ctx.base_flow.tp_src = htons(0);
            flow->tp_dst = ctx.base_flow.tp_dst = htons(0);
            break;

        case OFPC_FRAG_DROP:
            goto out;

        case OFPC_FRAG_REASM:
            OVS_NOT_REACHED();

        case OFPC_FRAG_NX_MATCH:
            /* Nothing to do. */
            break;

        case OFPC_INVALID_TTL_TO_CONTROLLER:
            OVS_NOT_REACHED();
        }
    }

    in_port = get_ofp_port(ctx.xbridge, flow->in_port.ofp_port);
    if (in_port && in_port->is_tunnel && ctx.xin->resubmit_stats) {
        netdev_vport_inc_rx(in_port->netdev, ctx.xin->resubmit_stats);
        if (in_port->bfd) {
            bfd_account_rx(in_port->bfd, ctx.xin->resubmit_stats);
        }
    }

    special = process_special(&ctx, flow, in_port, ctx.xin->packet);
    if (special) {
        ctx.xout->slow |= special;
    } else {
        size_t sample_actions_len;

        if (flow->in_port.ofp_port
            != vsp_realdev_to_vlandev(ctx.xbridge->ofproto,
                                      flow->in_port.ofp_port,
                                      flow->vlan_tci)) {
            ctx.base_flow.vlan_tci = 0;
        }

        add_sflow_action(&ctx);
        add_ipfix_action(&ctx);
        sample_actions_len = ctx.xout->odp_actions.size;

        if (tnl_may_send && (!in_port || may_receive(in_port, &ctx))) {
            do_xlate_actions(ofpacts, ofpacts_len, &ctx);

            /* We've let OFPP_NORMAL and the learning action look at the
             * packet, so drop it now if forwarding is disabled. */
            if (in_port && !xport_stp_forward_state(in_port)) {
                ctx.xout->odp_actions.size = sample_actions_len;
            }
        }

        if (ctx.action_set.size) {
            xlate_action_set(&ctx);
        }

        if (ctx.xbridge->has_in_band
            && in_band_must_output_to_local_port(flow)
            && !actions_output_to_local_port(&ctx)) {
            compose_output_action(&ctx, OFPP_LOCAL);
        }

        fix_sflow_action(&ctx);

        if (mbridge_has_mirrors(ctx.xbridge->mbridge)) {
            add_mirror_actions(&ctx, &orig_flow);
        }
    }

    if (nl_attr_oversized(ctx.xout->odp_actions.size)) {
        /* These datapath actions are too big for a Netlink attribute, so we
         * can't hand them to the kernel directly.  dpif_execute() can execute
         * them one by one with help, so just mark the result as SLOW_ACTION to
         * prevent the flow from being installed. */
        COVERAGE_INC(xlate_actions_oversize);
        ctx.xout->slow |= SLOW_ACTION;
    }

    if (ctx.xin->resubmit_stats) {
        mirror_update_stats(ctx.xbridge->mbridge, xout->mirrors,
                            ctx.xin->resubmit_stats->n_packets,
                            ctx.xin->resubmit_stats->n_bytes);

        if (ctx.xbridge->netflow) {
            const struct ofpact *ofpacts;
            size_t ofpacts_len;

            ofpacts_len = actions->ofpacts_len;
            ofpacts = actions->ofpacts;
            if (ofpacts_len == 0
                || ofpacts->type != OFPACT_CONTROLLER
                || ofpact_next(ofpacts) < ofpact_end(ofpacts, ofpacts_len)) {
                /* Only update netflow if we don't have controller flow.  We don't
                 * report NetFlow expiration messages for such facets because they
                 * are just part of the control logic for the network, not real
                 * traffic. */
                netflow_flow_update(ctx.xbridge->netflow, flow,
                                    xout->nf_output_iface,
                                    ctx.xin->resubmit_stats);
            }
        }
    }

    ofpbuf_uninit(&ctx.stack);
    ofpbuf_uninit(&ctx.action_set);

    /* Clear the metadata and register wildcard masks, because we won't
     * use non-header fields as part of the cache. */
    flow_wildcards_clear_non_packet_fields(wc);

    /* ICMPv4 and ICMPv6 have 8-bit "type" and "code" fields.  struct flow uses
     * the low 8 bits of the 16-bit tp_src and tp_dst members to represent
     * these fields.  The datapath interface, on the other hand, represents
     * them with just 8 bits each.  This means that if the high 8 bits of the
     * masks for these fields somehow become set, then they will get chopped
     * off by a round trip through the datapath, and revalidation will spot
     * that as an inconsistency and delete the flow.  Avoid the problem here by
     * making sure that only the low 8 bits of either field can be unwildcarded
     * for ICMP.
     */
    if (is_icmp) {
        wc->masks.tp_src &= htons(UINT8_MAX);
        wc->masks.tp_dst &= htons(UINT8_MAX);
    }

out:
    rule_actions_unref(actions);
    rule_dpif_unref(rule);
}

/* Sends 'packet' out 'ofport'.
 * May modify 'packet'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
xlate_send_packet(const struct ofport_dpif *ofport, struct ofpbuf *packet)
{
    struct xport *xport;
    struct ofpact_output output;
    struct flow flow;
    union flow_in_port in_port_;

    ofpact_init(&output.ofpact, OFPACT_OUTPUT, sizeof output);
    /* Use OFPP_NONE as the in_port to avoid special packet processing. */
    in_port_.ofp_port = OFPP_NONE;
    flow_extract(packet, 0, 0, NULL, &in_port_, &flow);

    ovs_rwlock_rdlock(&xlate_rwlock);
    xport = xport_lookup(ofport);
    if (!xport) {
        ovs_rwlock_unlock(&xlate_rwlock);
        return EINVAL;
    }
    output.port = xport->ofp_port;
    output.max_len = 0;
    ovs_rwlock_unlock(&xlate_rwlock);

    return ofproto_dpif_execute_actions(xport->xbridge->ofproto, &flow, NULL,
                                        &output.ofpact, sizeof output,
                                        packet);
}
