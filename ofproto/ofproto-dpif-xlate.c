/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>

#include "bfd.h"
#include "bitmap.h"
#include "bond.h"
#include "bundle.h"
#include "byte-order.h"
#include "cfm.h"
#include "connmgr.h"
#include "coverage.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif.h"
#include "in-band.h"
#include "lacp.h"
#include "learn.h"
#include "mac-learning.h"
#include "mcast-snooping.h"
#include "multipath.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-execute.h"
#include "ofproto/ofproto-dpif-ipfix.h"
#include "ofproto/ofproto-dpif-mirror.h"
#include "ofproto/ofproto-dpif-monitor.h"
#include "ofproto/ofproto-dpif-sflow.h"
#include "ofproto/ofproto-dpif-trace.h"
#include "ofproto/ofproto-dpif-xlate-cache.h"
#include "ofproto/ofproto-dpif.h"
#include "ofproto/ofproto-provider.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-ed-props.h"
#include "openvswitch/vlog.h"
#include "ovs-lldp.h"
#include "ovs-router.h"
#include "packets.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "tunnel.h"
#include "util.h"
#include "uuid.h"

COVERAGE_DEFINE(xlate_actions);
COVERAGE_DEFINE(xlate_actions_oversize);
COVERAGE_DEFINE(xlate_actions_too_many_output);

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_xlate);

/* Maximum depth of flow table recursion (due to resubmit actions) in a
 * flow translation.
 *
 * The goal of limiting the depth of resubmits is to ensure that flow
 * translation eventually terminates.  Only resubmits to the same table or an
 * earlier table count against the maximum depth.  This is because resubmits to
 * strictly monotonically increasing table IDs will eventually terminate, since
 * any OpenFlow switch has a finite number of tables.  OpenFlow tables are most
 * commonly traversed in numerically increasing order, so this limit has little
 * effect on conventionally designed OpenFlow pipelines.
 *
 * Outputs to patch ports and to groups also count against the depth limit. */
#define MAX_DEPTH 64

/* Maximum number of resubmit actions in a flow translation, whether they are
 * recursive or not. */
#define MAX_RESUBMITS (MAX_DEPTH * MAX_DEPTH)

/* The structure holds an array of IP addresses assigned to a bridge and the
 * number of elements in the array. These data are mutable and are evaluated
 * when ARP or Neighbor Advertisement packets received on a native tunnel
 * port are xlated. So 'ref_cnt' and RCU are used for synchronization. */
struct xbridge_addr {
    struct in6_addr *addr;        /* Array of IP addresses of xbridge. */
    int n_addr;                   /* Number of IP addresses. */
    struct ovs_refcount ref_cnt;
};

struct xbridge {
    struct hmap_node hmap_node;   /* Node in global 'xbridges' map. */
    struct ofproto_dpif *ofproto; /* Key in global 'xbridges' map. */

    struct ovs_list xbundles;     /* Owned xbundles. */
    struct hmap xports;           /* Indexed by ofp_port. */

    char *name;                   /* Name used in log messages. */
    struct dpif *dpif;            /* Datapath interface. */
    struct mac_learning *ml;      /* Mac learning handle. */
    struct mcast_snooping *ms;    /* Multicast Snooping handle. */
    struct mbridge *mbridge;      /* Mirroring. */
    struct dpif_sflow *sflow;     /* SFlow handle, or null. */
    struct dpif_ipfix *ipfix;     /* Ipfix handle, or null. */
    struct netflow *netflow;      /* Netflow handle, or null. */
    struct stp *stp;              /* STP or null if disabled. */
    struct rstp *rstp;            /* RSTP or null if disabled. */

    bool has_in_band;             /* Bridge has in band control? */
    bool forward_bpdu;            /* Bridge forwards STP BPDUs? */

    /* Datapath feature support. */
    struct dpif_backer_support support;

    struct xbridge_addr *addr;
};

struct xbundle {
    struct hmap_node hmap_node;    /* In global 'xbundles' map. */
    struct ofbundle *ofbundle;     /* Key in global 'xbundles' map. */

    struct ovs_list list_node;     /* In parent 'xbridges' list. */
    struct xbridge *xbridge;       /* Parent xbridge. */

    struct ovs_list xports;        /* Contains "struct xport"s. */

    char *name;                    /* Name used in log messages. */
    struct bond *bond;             /* Nonnull iff more than one port. */
    struct lacp *lacp;             /* LACP handle or null. */

    enum port_vlan_mode vlan_mode; /* VLAN mode. */
    uint16_t qinq_ethtype;         /* Ethertype of dot1q-tunnel interface
                                    * either 0x8100 or 0x88a8. */
    int vlan;                      /* -1=trunk port, else a 12-bit VLAN ID. */
    unsigned long *trunks;         /* Bitmap of trunked VLANs, if 'vlan' == -1.
                                    * NULL if all VLANs are trunked. */
    unsigned long *cvlans;         /* Bitmap of allowed customer vlans,
                                    * NULL if all VLANs are allowed */
    bool use_priority_tags;        /* Use 802.1p tag for frames in VLAN 0? */
    bool floodable;                /* No port has OFPUTIL_PC_NO_FLOOD set? */
    bool protected;                /* Protected port mode */
};

struct xport {
    struct hmap_node hmap_node;      /* Node in global 'xports' map. */
    struct ofport_dpif *ofport;      /* Key in global 'xports map. */

    struct hmap_node ofp_node;       /* Node in parent xbridge 'xports' map. */
    ofp_port_t ofp_port;             /* Key in parent xbridge 'xports' map. */

    struct hmap_node uuid_node;      /* Node in global 'xports_uuid' map. */
    struct uuid uuid;                /* Key in global 'xports_uuid' map. */

    odp_port_t odp_port;             /* Datapath port number or ODPP_NONE. */

    struct ovs_list bundle_node;     /* In parent xbundle (if it exists). */
    struct xbundle *xbundle;         /* Parent xbundle or null. */

    struct netdev *netdev;           /* 'ofport''s netdev. */

    struct xbridge *xbridge;         /* Parent bridge. */
    struct xport *peer;              /* Patch port peer or null. */

    enum ofputil_port_config config; /* OpenFlow port configuration. */
    enum ofputil_port_state state;   /* OpenFlow port state. */
    int stp_port_no;                 /* STP port number or -1 if not in use. */
    struct rstp_port *rstp_port;     /* RSTP port or null. */

    struct hmap skb_priorities;      /* Map of 'skb_priority_to_dscp's. */

    bool may_enable;                 /* May be enabled in bonds. */
    bool is_tunnel;                  /* Is a tunnel port. */
    enum netdev_pt_mode pt_mode;     /* packet_type handling. */

    struct cfm *cfm;                 /* CFM handle or null. */
    struct bfd *bfd;                 /* BFD handle or null. */
    struct lldp *lldp;               /* LLDP handle or null. */
};

struct xlate_ctx {
    struct xlate_in *xin;
    struct xlate_out *xout;

    struct xlate_cfg *xcfg;
    const struct xbridge *xbridge;

    /* Flow at the last commit. */
    struct flow base_flow;

    /* Tunnel IP destination address as received.  This is stored separately
     * as the base_flow.tunnel is cleared on init to reflect the datapath
     * behavior.  Used to make sure not to send tunneled output to ourselves,
     * which might lead to an infinite loop.  This could happen easily
     * if a tunnel is marked as 'ip_remote=flow', and the flow does not
     * actually set the tun_dst field. */
    struct in6_addr orig_tunnel_ipv6_dst;

    /* Stack for the push and pop actions.  See comment above nx_stack_push()
     * in nx-match.c for info on how the stack is stored. */
    struct ofpbuf stack;

    /* The rule that we are currently translating, or NULL. */
    struct rule_dpif *rule;

    /* Flow translation populates this with wildcards relevant in translation.
     * When 'xin->wc' is nonnull, this is the same pointer.  When 'xin->wc' is
     * null, this is a pointer to a temporary buffer. */
    struct flow_wildcards *wc;

    /* Output buffer for datapath actions.  When 'xin->odp_actions' is nonnull,
     * this is the same pointer.  When 'xin->odp_actions' is null, this points
     * to a scratch ofpbuf.  This allows code to add actions to
     * 'ctx->odp_actions' without worrying about whether the caller really
     * wants actions. */
    struct ofpbuf *odp_actions;

    /* Statistics maintained by xlate_table_action().
     *
     * These statistics limit the amount of work that a single flow
     * translation can perform.  The goal of the first of these, 'depth', is
     * primarily to prevent translation from performing an infinite amount of
     * work.  It counts the current depth of nested "resubmit"s (and a few
     * other activities); when a resubmit returns, it decreases.  Resubmits to
     * tables in strictly monotonically increasing order don't contribute to
     * 'depth' because they cannot cause a flow translation to take an infinite
     * amount of time (because the number of tables is finite).  Translation
     * aborts when 'depth' exceeds MAX_DEPTH.
     *
     * 'resubmits', on the other hand, prevents flow translation from
     * performing an extraordinarily large while still finite amount of work.
     * It counts the total number of resubmits (and a few other activities)
     * that have been executed.  Returning from a resubmit does not affect this
     * counter.  Thus, this limits the amount of work that a particular
     * translation can perform.  Translation aborts when 'resubmits' exceeds
     * MAX_RESUBMITS (which is much larger than MAX_DEPTH).
     */
    int depth;                  /* Current resubmit nesting depth. */
    int resubmits;              /* Total number of resubmits. */
    bool in_group;              /* Currently translating ofgroup, if true. */
    bool in_action_set;         /* Currently translating action_set, if true. */
    bool in_packet_out;         /* Currently translating a packet_out msg, if
                                 * true. */
    bool pending_encap;         /* True when waiting to commit a pending
                                 * encap action. */
    bool pending_decap;         /* True when waiting to commit a pending
                                 * decap action. */
    struct ofpbuf *encap_data;  /* May contain a pointer to an ofpbuf with
                                 * context for the datapath encap action.*/

    uint8_t table_id;           /* OpenFlow table ID where flow was found. */
    ovs_be64 rule_cookie;       /* Cookie of the rule being translated. */
    uint32_t orig_skb_priority; /* Priority when packet arrived. */
    uint32_t sflow_n_outputs;   /* Number of output ports. */
    odp_port_t sflow_odp_port;  /* Output port for composing sFlow action. */
    ofp_port_t nf_output_iface; /* Output interface index for NetFlow. */
    bool exit;                  /* No further actions should be processed. */
    mirror_mask_t mirrors;      /* Bitmap of associated mirrors. */
    int mirror_snaplen;         /* Max size of a mirror packet in byte. */

   /* Freezing Translation
    * ====================
    *
    * At some point during translation, the code may recognize the need to halt
    * and checkpoint the translation in a way that it can be restarted again
    * later.  We call the checkpointing process "freezing" and the restarting
    * process "thawing".
    *
    * The use cases for freezing are:
    *
    *     - "Recirculation", where the translation process discovers that it
    *       doesn't have enough information to complete translation without
    *       actually executing the actions that have already been translated,
    *       which provides the additionally needed information.  In these
    *       situations, translation freezes translation and assigns the frozen
    *       data a unique "recirculation ID", which it associates with the data
    *       in a table in userspace (see ofproto-dpif-rid.h).  It also adds a
    *       OVS_ACTION_ATTR_RECIRC action specifying that ID to the datapath
    *       actions.  When a packet hits that action, the datapath looks its
    *       flow up again using the ID.  If there's a miss, it comes back to
    *       userspace, which find the recirculation table entry for the ID,
    *       thaws the associated frozen data, and continues translation from
    *       that point given the additional information that is now known.
    *
    *       The archetypal example is MPLS.  As MPLS is implemented in
    *       OpenFlow, the protocol that follows the last MPLS label becomes
    *       known only when that label is popped by an OpenFlow action.  That
    *       means that Open vSwitch can't extract the headers beyond the MPLS
    *       labels until the pop action is executed.  Thus, at that point
    *       translation uses the recirculation process to extract the headers
    *       beyond the MPLS labels.
    *
    *       (OVS also uses OVS_ACTION_ATTR_RECIRC to implement hashing for
    *       output to bonds.  OVS pre-populates all the datapath flows for bond
    *       output in the datapath, though, which means that the elaborate
    *       process of coming back to userspace for a second round of
    *       translation isn't needed, and so bonds don't follow the above
    *       process.)
    *
    *     - "Continuation".  A continuation is a way for an OpenFlow controller
    *       to interpose on a packet's traversal of the OpenFlow tables.  When
    *       the translation process encounters a "controller" action with the
    *       "pause" flag, it freezes translation, serializes the frozen data,
    *       and sends it to an OpenFlow controller.  The controller then
    *       examines and possibly modifies the frozen data and eventually sends
    *       it back to the switch, which thaws it and continues translation.
    *
    * The main problem of freezing translation is preserving state, so that
    * when the translation is thawed later it resumes from where it left off,
    * without disruption.  In particular, actions must be preserved as follows:
    *
    *     - If we're freezing because an action needed more information, the
    *       action that prompted it.
    *
    *     - Any actions remaining to be translated within the current flow.
    *
    *     - If translation was frozen within a NXAST_RESUBMIT, then any actions
    *       following the resubmit action.  Resubmit actions can be nested, so
    *       this has to go all the way up the control stack.
    *
    *     - The OpenFlow 1.1+ action set.
    *
    * State that actions and flow table lookups can depend on, such as the
    * following, must also be preserved:
    *
    *     - Metadata fields (input port, registers, OF1.1+ metadata, ...).
    *
    *     - The stack used by NXAST_STACK_PUSH and NXAST_STACK_POP actions.
    *
    *     - The table ID and cookie of the flow being translated at each level
    *       of the control stack, because these can become visible through
    *       OFPAT_CONTROLLER actions (and other ways).
    *
    * Translation allows for the control of this state preservation via these
    * members.  When a need to freeze translation is identified, the
    * translation process:
    *
    * 1. Sets 'freezing' to true.
    *
    * 2. Sets 'exit' to true to tell later steps that we're exiting from the
    *    translation process.
    *
    * 3. Adds an OFPACT_UNROLL_XLATE action to 'frozen_actions', and points
    *    frozen_actions.header to the action to make it easy to find it later.
    *    This action holds the current table ID and cookie so that they can be
    *    restored during a post-recirculation upcall translation.
    *
    * 4. Adds the action that prompted recirculation and any actions following
    *    it within the same flow to 'frozen_actions', so that they can be
    *    executed during a post-recirculation upcall translation.
    *
    * 5. Returns.
    *
    * 6. The action that prompted recirculation might be nested in a stack of
    *    nested "resubmit"s that have actions remaining.  Each of these notices
    *    that we're exiting and freezing and responds by adding more
    *    OFPACT_UNROLL_XLATE actions to 'frozen_actions', as necessary,
    *    followed by any actions that were yet unprocessed.
    *
    * If we're freezing because of recirculation, the caller generates a
    * recirculation ID and associates all the state produced by this process
    * with it.  For post-recirculation upcall translation, the caller passes it
    * back in for the new translation to execute.  The process yielded a set of
    * ofpacts that can be translated directly, so it is not much of a special
    * case at that point.
    */
    bool freezing;
    bool recirc_update_dp_hash;    /* Generated recirculation will be preceded
                                    * by datapath HASH action to get an updated
                                    * dp_hash after recirculation. */
    uint32_t dp_hash_alg;
    uint32_t dp_hash_basis;
    struct ofpbuf frozen_actions;
    const struct ofpact_controller *pause;

    /* True if a packet was but is no longer MPLS (due to an MPLS pop action).
     * This is a trigger for recirculation in cases where translating an action
     * or looking up a flow requires access to the fields of the packet after
     * the MPLS label stack that was originally present. */
    bool was_mpls;

    /* True if conntrack has been performed on this packet during processing
     * on the current bridge. This is used to determine whether conntrack
     * state from the datapath should be honored after thawing. */
    bool conntracked;

    /* Pointer to an embedded NAT action in a conntrack action, or NULL. */
    struct ofpact_nat *ct_nat_action;

    /* OpenFlow 1.1+ action set.
     *
     * 'action_set' accumulates "struct ofpact"s added by OFPACT_WRITE_ACTIONS.
     * When translation is otherwise complete, ofpacts_execute_action_set()
     * converts it to a set of "struct ofpact"s that can be translated into
     * datapath actions. */
    bool action_set_has_group;  /* Action set contains OFPACT_GROUP? */
    struct ofpbuf action_set;   /* Action set. */

    enum xlate_error error;     /* Translation failed. */
};

/* Structure to track VLAN manipulation */
struct xvlan_single {
    uint16_t tpid;
    uint16_t vid;
    uint16_t pcp;
};

struct xvlan {
    struct xvlan_single v[FLOW_MAX_VLAN_HEADERS];
};

const char *xlate_strerror(enum xlate_error error)
{
    switch (error) {
    case XLATE_OK:
        return "OK";
    case XLATE_BRIDGE_NOT_FOUND:
        return "Bridge not found";
    case XLATE_RECURSION_TOO_DEEP:
        return "Recursion too deep";
    case XLATE_TOO_MANY_RESUBMITS:
        return "Too many resubmits";
    case XLATE_STACK_TOO_DEEP:
        return "Stack too deep";
    case XLATE_NO_RECIRCULATION_CONTEXT:
        return "No recirculation context";
    case XLATE_RECIRCULATION_CONFLICT:
        return "Recirculation conflict";
    case XLATE_TOO_MANY_MPLS_LABELS:
        return "Too many MPLS labels";
    case XLATE_INVALID_TUNNEL_METADATA:
        return "Invalid tunnel metadata";
    case XLATE_UNSUPPORTED_PACKET_TYPE:
        return "Unsupported packet type";
    }
    return "Unknown error";
}

static void xlate_action_set(struct xlate_ctx *ctx);
static void xlate_commit_actions(struct xlate_ctx *ctx);

static void
patch_port_output(struct xlate_ctx *ctx, const struct xport *in_dev,
                  struct xport *out_dev);

static void
ctx_trigger_freeze(struct xlate_ctx *ctx)
{
    ctx->exit = true;
    ctx->freezing = true;
}

static void
ctx_trigger_recirculate_with_hash(struct xlate_ctx *ctx, uint32_t type,
                                  uint32_t basis)
{
    ctx->exit = true;
    ctx->freezing = true;
    ctx->recirc_update_dp_hash = true;
    ctx->dp_hash_alg = type;
    ctx->dp_hash_basis = basis;
}

static bool
ctx_first_frozen_action(const struct xlate_ctx *ctx)
{
    return !ctx->frozen_actions.size;
}

static void
ctx_cancel_freeze(struct xlate_ctx *ctx)
{
    if (ctx->freezing) {
        ctx->freezing = false;
        ctx->recirc_update_dp_hash = false;
        ofpbuf_clear(&ctx->frozen_actions);
        ctx->frozen_actions.header = NULL;
    }
}

static void finish_freezing(struct xlate_ctx *ctx);

/* A controller may use OFPP_NONE as the ingress port to indicate that
 * it did not arrive on a "real" port.  'ofpp_none_bundle' exists for
 * when an input bundle is needed for validation (e.g., mirroring or
 * OFPP_NORMAL processing).  It is not connected to an 'ofproto' or have
 * any 'port' structs, so care must be taken when dealing with it. */
static struct xbundle ofpp_none_bundle = {
    .name      = "OFPP_NONE",
    .vlan_mode = PORT_VLAN_TRUNK
};

/* Node in 'xport''s 'skb_priorities' map.  Used to maintain a map from
 * 'priority' (the datapath's term for QoS queue) to the dscp bits which all
 * traffic egressing the 'ofport' with that priority should be marked with. */
struct skb_priority_to_dscp {
    struct hmap_node hmap_node; /* Node in 'ofport_dpif''s 'skb_priorities'. */
    uint32_t skb_priority;      /* Priority of this queue (see struct flow). */

    uint8_t dscp;               /* DSCP bits to mark outgoing traffic with. */
};

/* Xlate config contains hash maps of all bridges, bundles and ports.
 * Xcfgp contains the pointer to the current xlate configuration.
 * When the main thread needs to change the configuration, it copies xcfgp to
 * new_xcfg and edits new_xcfg. This enables the use of RCU locking which
 * does not block handler and revalidator threads. */
struct xlate_cfg {
    struct hmap xbridges;
    struct hmap xbundles;
    struct hmap xports;
    struct hmap xports_uuid;
};
static OVSRCU_TYPE(struct xlate_cfg *) xcfgp = OVSRCU_INITIALIZER(NULL);
static struct xlate_cfg *new_xcfg = NULL;

typedef void xlate_actions_handler(const struct ofpact *, size_t ofpacts_len,
                                   struct xlate_ctx *, bool);
static bool may_receive(const struct xport *, struct xlate_ctx *);
static void do_xlate_actions(const struct ofpact *, size_t ofpacts_len,
                             struct xlate_ctx *, bool);
static void clone_xlate_actions(const struct ofpact *, size_t ofpacts_len,
                                struct xlate_ctx *, bool);
static void xlate_normal(struct xlate_ctx *);
static void xlate_table_action(struct xlate_ctx *, ofp_port_t in_port,
                               uint8_t table_id, bool may_packet_in,
                               bool honor_table_miss, bool with_ct_orig,
                               bool is_last_action, xlate_actions_handler *);

static bool input_vid_is_valid(const struct xlate_ctx *,
                               uint16_t vid, struct xbundle *);
static void xvlan_copy(struct xvlan *dst, const struct xvlan *src);
static void xvlan_pop(struct xvlan *src);
static void xvlan_push_uninit(struct xvlan *src);
static void xvlan_extract(const struct flow *, struct xvlan *);
static void xvlan_put(struct flow *, const struct xvlan *);
static void xvlan_input_translate(const struct xbundle *,
                                  const struct xvlan *in,
                                  struct xvlan *xvlan);
static void xvlan_output_translate(const struct xbundle *,
                                   const struct xvlan *xvlan,
                                   struct xvlan *out);
static void output_normal(struct xlate_ctx *, const struct xbundle *,
                          const struct xvlan *);

/* Optional bond recirculation parameter to compose_output_action(). */
struct xlate_bond_recirc {
    uint32_t recirc_id;  /* !0 Use recirculation instead of output. */
    uint8_t  hash_alg;   /* !0 Compute hash for recirc before. */
    uint32_t hash_basis;  /* Compute hash for recirc before. */
};

static void compose_output_action(struct xlate_ctx *, ofp_port_t ofp_port,
                                  const struct xlate_bond_recirc *xr,
                                  bool is_last_action, bool truncate);

static struct xbridge *xbridge_lookup(struct xlate_cfg *,
                                      const struct ofproto_dpif *);
static struct xbridge *xbridge_lookup_by_uuid(struct xlate_cfg *,
                                              const struct uuid *);
static struct xbundle *xbundle_lookup(struct xlate_cfg *,
                                      const struct ofbundle *);
static struct xport *xport_lookup(struct xlate_cfg *,
                                  const struct ofport_dpif *);
static struct xport *xport_lookup_by_uuid(struct xlate_cfg *,
                                          const struct uuid *);
static struct xport *get_ofp_port(const struct xbridge *, ofp_port_t ofp_port);
static struct skb_priority_to_dscp *get_skb_priority(const struct xport *,
                                                     uint32_t skb_priority);
static void clear_skb_priorities(struct xport *);
static size_t count_skb_priorities(const struct xport *);
static bool dscp_from_skb_priority(const struct xport *, uint32_t skb_priority,
                                   uint8_t *dscp);

static void xlate_xbridge_init(struct xlate_cfg *, struct xbridge *);
static void xlate_xbundle_init(struct xlate_cfg *, struct xbundle *);
static void xlate_xport_init(struct xlate_cfg *, struct xport *);
static void xlate_xbridge_set(struct xbridge *, struct dpif *,
                              const struct mac_learning *, struct stp *,
                              struct rstp *, const struct mcast_snooping *,
                              const struct mbridge *,
                              const struct dpif_sflow *,
                              const struct dpif_ipfix *,
                              const struct netflow *,
                              bool forward_bpdu, bool has_in_band,
                              const struct dpif_backer_support *,
                              const struct xbridge_addr *);
static void xlate_xbundle_set(struct xbundle *xbundle,
                              enum port_vlan_mode vlan_mode,
                              uint16_t qinq_ethtype, int vlan,
                              unsigned long *trunks, unsigned long *cvlans,
                              bool use_priority_tags,
                              const struct bond *bond, const struct lacp *lacp,
                              bool floodable, bool protected);
static void xlate_xport_set(struct xport *xport, odp_port_t odp_port,
                            const struct netdev *netdev, const struct cfm *cfm,
                            const struct bfd *bfd, const struct lldp *lldp,
                            int stp_port_no, const struct rstp_port *rstp_port,
                            enum ofputil_port_config config,
                            enum ofputil_port_state state, bool is_tunnel,
                            bool may_enable);
static void xlate_xbridge_remove(struct xlate_cfg *, struct xbridge *);
static void xlate_xbundle_remove(struct xlate_cfg *, struct xbundle *);
static void xlate_xport_remove(struct xlate_cfg *, struct xport *);
static void xlate_xbridge_copy(struct xbridge *);
static void xlate_xbundle_copy(struct xbridge *, struct xbundle *);
static void xlate_xport_copy(struct xbridge *, struct xbundle *,
                             struct xport *);
static void xlate_xcfg_free(struct xlate_cfg *);

/* Tracing helpers. */

/* If tracing is enabled in 'ctx', creates a new trace node and appends it to
 * the list of nodes maintained in ctx->xin.  The new node has type 'type' and
 * its text is created from 'format' by treating it as a printf format string.
 * Returns the list of nodes embedded within the new trace node; ordinarily,
 * the calleer can ignore this, but it is useful if the caller needs to nest
 * more trace nodes within the new node.
 *
 * If tracing is not enabled, does nothing and returns NULL. */
static struct ovs_list * OVS_PRINTF_FORMAT(3, 4)
xlate_report(const struct xlate_ctx *ctx, enum oftrace_node_type type,
             const char *format, ...)
{
    struct ovs_list *subtrace = NULL;
    if (OVS_UNLIKELY(ctx->xin->trace)) {
        va_list args;
        va_start(args, format);
        char *text = xvasprintf(format, args);
        subtrace = &oftrace_report(ctx->xin->trace, type, text)->subs;
        va_end(args);
        free(text);
    }
    return subtrace;
}

/* This is like xlate_report() for errors that are serious enough that we
 * should log them even if we are not tracing. */
static void OVS_PRINTF_FORMAT(2, 3)
xlate_report_error(const struct xlate_ctx *ctx, const char *format, ...)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    if (!OVS_UNLIKELY(ctx->xin->trace)
        && (!ctx->xin->packet || VLOG_DROP_WARN(&rl))) {
        return;
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    va_list args;
    va_start(args, format);
    ds_put_format_valist(&s, format, args);
    va_end(args);

    if (ctx->xin->trace) {
        oftrace_report(ctx->xin->trace, OFT_ERROR, ds_cstr(&s));
    } else {
        ds_put_cstr(&s, " while processing ");
        flow_format(&s, &ctx->base_flow, NULL);
        ds_put_format(&s, " on bridge %s", ctx->xbridge->name);
        VLOG_WARN("%s", ds_cstr(&s));
    }
    ds_destroy(&s);
}

/* This is like xlate_report() for messages that should be logged at debug
 * level (even if we are not tracing) because they can be valuable for
 * debugging. */
static void OVS_PRINTF_FORMAT(3, 4)
xlate_report_debug(const struct xlate_ctx *ctx, enum oftrace_node_type type,
                   const char *format, ...)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
    if (!OVS_UNLIKELY(ctx->xin->trace)
        && (!ctx->xin->packet || VLOG_DROP_DBG(&rl))) {
        return;
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    va_list args;
    va_start(args, format);
    ds_put_format_valist(&s, format, args);
    va_end(args);

    if (ctx->xin->trace) {
        oftrace_report(ctx->xin->trace, type, ds_cstr(&s));
    } else {
        VLOG_DBG("bridge %s: %s", ctx->xbridge->name, ds_cstr(&s));
    }
    ds_destroy(&s);
}

/* If tracing is enabled in 'ctx', appends a node of the given 'type' to the
 * trace, whose text is 'title' followed by a formatted version of the
 * 'ofpacts_len' OpenFlow actions in 'ofpacts'.
 *
 * If tracing is not enabled, does nothing. */
static void
xlate_report_actions(const struct xlate_ctx *ctx, enum oftrace_node_type type,
                     const char *title,
                     const struct ofpact *ofpacts, size_t ofpacts_len)
{
    if (OVS_UNLIKELY(ctx->xin->trace)) {
        struct ds s = DS_EMPTY_INITIALIZER;
        ds_put_format(&s, "%s: ", title);
        struct ofpact_format_params fp = { .s = &s };
        ofpacts_format(ofpacts, ofpacts_len, &fp);
        oftrace_report(ctx->xin->trace, type, ds_cstr(&s));
        ds_destroy(&s);
    }
}

/* If tracing is enabled in 'ctx', appends a node of type OFT_DETAIL to the
 * trace, whose the message is a formatted version of the OpenFlow action set.
 * 'verb' should be "was" or "is", depending on whether the action set reported
 * is the new action set or the old one.
 *
 * If tracing is not enabled, does nothing. */
static void
xlate_report_action_set(const struct xlate_ctx *ctx, const char *verb)
{
    if (OVS_UNLIKELY(ctx->xin->trace)) {
        struct ofpbuf action_list;
        ofpbuf_init(&action_list, 0);
        ofpacts_execute_action_set(&action_list, &ctx->action_set);
        if (action_list.size) {
            struct ds s = DS_EMPTY_INITIALIZER;
            struct ofpact_format_params fp = { .s = &s };
            ofpacts_format(action_list.data, action_list.size, &fp);
            xlate_report(ctx, OFT_DETAIL, "action set %s: %s",
                         verb, ds_cstr(&s));
            ds_destroy(&s);
        } else {
            xlate_report(ctx, OFT_DETAIL, "action set %s empty", verb);
        }
        ofpbuf_uninit(&action_list);
    }
}


/* If tracing is enabled in 'ctx', appends a node representing 'rule' (in
 * OpenFlow table 'table_id') to the trace and makes this node the parent for
 * future trace nodes.  The caller should save ctx->xin->trace before calling
 * this function, then after tracing all of the activities under the table,
 * restore its previous value.
 *
 * If tracing is not enabled, does nothing. */
static void
xlate_report_table(const struct xlate_ctx *ctx, struct rule_dpif *rule,
                   uint8_t table_id)
{
    if (OVS_LIKELY(!ctx->xin->trace)) {
        return;
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "%2d. ", table_id);
    if (rule == ctx->xin->ofproto->miss_rule) {
        ds_put_cstr(&s, "No match, and a \"packet-in\" is called for.");
    } else if (rule == ctx->xin->ofproto->no_packet_in_rule) {
        ds_put_cstr(&s, "No match.");
    } else if (rule == ctx->xin->ofproto->drop_frags_rule) {
        ds_put_cstr(&s, "Packets are IP fragments and "
                    "the fragment handling mode is \"drop\".");
    } else {
        minimatch_format(&rule->up.cr.match,
                         ofproto_get_tun_tab(&ctx->xin->ofproto->up),
                         NULL, &s, OFP_DEFAULT_PRIORITY);
        if (ds_last(&s) != ' ') {
            ds_put_cstr(&s, ", ");
        }
        ds_put_format(&s, "priority %d", rule->up.cr.priority);
        if (rule->up.flow_cookie) {
            ds_put_format(&s, ", cookie %#"PRIx64,
                          ntohll(rule->up.flow_cookie));
        }
    }
    ctx->xin->trace = &oftrace_report(ctx->xin->trace, OFT_TABLE,
                                      ds_cstr(&s))->subs;
    ds_destroy(&s);
}

/* If tracing is enabled in 'ctx', adds an OFT_DETAIL trace node to 'ctx'
 * reporting the value of subfield 'sf'.
 *
 * If tracing is not enabled, does nothing. */
static void
xlate_report_subfield(const struct xlate_ctx *ctx,
                      const struct mf_subfield *sf)
{
    if (OVS_UNLIKELY(ctx->xin->trace)) {
        struct ds s = DS_EMPTY_INITIALIZER;
        mf_format_subfield(sf, &s);
        ds_put_cstr(&s, " is now ");

        if (sf->ofs == 0 && sf->n_bits >= sf->field->n_bits) {
            union mf_value value;
            mf_get_value(sf->field, &ctx->xin->flow, &value);
            mf_format(sf->field, &value, NULL, NULL, &s);
        } else {
            union mf_subvalue cst;
            mf_read_subfield(sf, &ctx->xin->flow, &cst);
            ds_put_hex(&s, &cst, sizeof cst);
        }

        xlate_report(ctx, OFT_DETAIL, "%s", ds_cstr(&s));

        ds_destroy(&s);
    }
}

static void
xlate_xbridge_init(struct xlate_cfg *xcfg, struct xbridge *xbridge)
{
    ovs_list_init(&xbridge->xbundles);
    hmap_init(&xbridge->xports);
    hmap_insert(&xcfg->xbridges, &xbridge->hmap_node,
                hash_pointer(xbridge->ofproto, 0));
}

static void
xlate_xbundle_init(struct xlate_cfg *xcfg, struct xbundle *xbundle)
{
    ovs_list_init(&xbundle->xports);
    ovs_list_insert(&xbundle->xbridge->xbundles, &xbundle->list_node);
    hmap_insert(&xcfg->xbundles, &xbundle->hmap_node,
                hash_pointer(xbundle->ofbundle, 0));
}

static void
xlate_xport_init(struct xlate_cfg *xcfg, struct xport *xport)
{
    hmap_init(&xport->skb_priorities);
    hmap_insert(&xcfg->xports, &xport->hmap_node,
                hash_pointer(xport->ofport, 0));
    hmap_insert(&xport->xbridge->xports, &xport->ofp_node,
                hash_ofp_port(xport->ofp_port));
    hmap_insert(&xcfg->xports_uuid, &xport->uuid_node,
                uuid_hash(&xport->uuid));
}

static struct xbridge_addr *
xbridge_addr_create(struct xbridge *xbridge)
{
    struct xbridge_addr *xbridge_addr = xbridge->addr;
    struct in6_addr *addr = NULL, *mask = NULL;
    struct netdev *dev;
    int err, n_addr = 0;

    err = netdev_open(xbridge->name, NULL, &dev);
    if (!err) {
        err = netdev_get_addr_list(dev, &addr, &mask, &n_addr);
        if (!err) {
            if (!xbridge->addr ||
                n_addr != xbridge->addr->n_addr ||
                (xbridge->addr->addr && memcmp(addr, xbridge->addr->addr,
                                               sizeof(*addr) * n_addr))) {
                xbridge_addr = xzalloc(sizeof *xbridge_addr);
                xbridge_addr->addr = addr;
                xbridge_addr->n_addr = n_addr;
                ovs_refcount_init(&xbridge_addr->ref_cnt);
            } else {
                free(addr);
            }
            free(mask);
        }
        netdev_close(dev);
    }

    return xbridge_addr;
}

static struct xbridge_addr *
xbridge_addr_ref(const struct xbridge_addr *addr_)
{
    struct xbridge_addr *addr = CONST_CAST(struct xbridge_addr *, addr_);
    if (addr) {
        ovs_refcount_ref(&addr->ref_cnt);
    }
    return addr;
}

static void
xbridge_addr_unref(struct xbridge_addr *addr)
{
    if (addr && ovs_refcount_unref_relaxed(&addr->ref_cnt) == 1) {
        free(addr->addr);
        free(addr);
    }
}

static void
xlate_xbridge_set(struct xbridge *xbridge,
                  struct dpif *dpif,
                  const struct mac_learning *ml, struct stp *stp,
                  struct rstp *rstp, const struct mcast_snooping *ms,
                  const struct mbridge *mbridge,
                  const struct dpif_sflow *sflow,
                  const struct dpif_ipfix *ipfix,
                  const struct netflow *netflow,
                  bool forward_bpdu, bool has_in_band,
                  const struct dpif_backer_support *support,
                  const struct xbridge_addr *addr)
{
    if (xbridge->ml != ml) {
        mac_learning_unref(xbridge->ml);
        xbridge->ml = mac_learning_ref(ml);
    }

    if (xbridge->ms != ms) {
        mcast_snooping_unref(xbridge->ms);
        xbridge->ms = mcast_snooping_ref(ms);
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

    if (xbridge->rstp != rstp) {
        rstp_unref(xbridge->rstp);
        xbridge->rstp = rstp_ref(rstp);
    }

    if (xbridge->netflow != netflow) {
        netflow_unref(xbridge->netflow);
        xbridge->netflow = netflow_ref(netflow);
    }

    if (xbridge->addr != addr) {
        xbridge_addr_unref(xbridge->addr);
        xbridge->addr = xbridge_addr_ref(addr);
    }

    xbridge->dpif = dpif;
    xbridge->forward_bpdu = forward_bpdu;
    xbridge->has_in_band = has_in_band;
    xbridge->support = *support;
}

static void
xlate_xbundle_set(struct xbundle *xbundle,
                  enum port_vlan_mode vlan_mode, uint16_t qinq_ethtype,
                  int vlan, unsigned long *trunks, unsigned long *cvlans,
                  bool use_priority_tags,
                  const struct bond *bond, const struct lacp *lacp,
                  bool floodable, bool protected)
{
    ovs_assert(xbundle->xbridge);

    xbundle->vlan_mode = vlan_mode;
    xbundle->qinq_ethtype = qinq_ethtype;
    xbundle->vlan = vlan;
    xbundle->trunks = trunks;
    xbundle->cvlans = cvlans;
    xbundle->use_priority_tags = use_priority_tags;
    xbundle->floodable = floodable;
    xbundle->protected = protected;

    if (xbundle->bond != bond) {
        bond_unref(xbundle->bond);
        xbundle->bond = bond_ref(bond);
    }

    if (xbundle->lacp != lacp) {
        lacp_unref(xbundle->lacp);
        xbundle->lacp = lacp_ref(lacp);
    }
}

static void
xlate_xport_set(struct xport *xport, odp_port_t odp_port,
                const struct netdev *netdev, const struct cfm *cfm,
                const struct bfd *bfd, const struct lldp *lldp, int stp_port_no,
                const struct rstp_port* rstp_port,
                enum ofputil_port_config config, enum ofputil_port_state state,
                bool is_tunnel, bool may_enable)
{
    xport->config = config;
    xport->state = state;
    xport->stp_port_no = stp_port_no;
    xport->is_tunnel = is_tunnel;
    xport->pt_mode = netdev_get_pt_mode(netdev);
    xport->may_enable = may_enable;
    xport->odp_port = odp_port;

    if (xport->rstp_port != rstp_port) {
        rstp_port_unref(xport->rstp_port);
        xport->rstp_port = rstp_port_ref(rstp_port);
    }

    if (xport->cfm != cfm) {
        cfm_unref(xport->cfm);
        xport->cfm = cfm_ref(cfm);
    }

    if (xport->bfd != bfd) {
        bfd_unref(xport->bfd);
        xport->bfd = bfd_ref(bfd);
    }

    if (xport->lldp != lldp) {
        lldp_unref(xport->lldp);
        xport->lldp = lldp_ref(lldp);
    }

    if (xport->netdev != netdev) {
        netdev_close(xport->netdev);
        xport->netdev = netdev_ref(netdev);
    }
}

static void
xlate_xbridge_copy(struct xbridge *xbridge)
{
    struct xbundle *xbundle;
    struct xport *xport;
    struct xbridge *new_xbridge = xzalloc(sizeof *xbridge);
    new_xbridge->ofproto = xbridge->ofproto;
    new_xbridge->name = xstrdup(xbridge->name);
    xlate_xbridge_init(new_xcfg, new_xbridge);

    xlate_xbridge_set(new_xbridge,
                      xbridge->dpif, xbridge->ml, xbridge->stp,
                      xbridge->rstp, xbridge->ms, xbridge->mbridge,
                      xbridge->sflow, xbridge->ipfix, xbridge->netflow,
                      xbridge->forward_bpdu, xbridge->has_in_band,
                      &xbridge->support, xbridge->addr);
    LIST_FOR_EACH (xbundle, list_node, &xbridge->xbundles) {
        xlate_xbundle_copy(new_xbridge, xbundle);
    }

    /* Copy xports which are not part of a xbundle */
    HMAP_FOR_EACH (xport, ofp_node, &xbridge->xports) {
        if (!xport->xbundle) {
            xlate_xport_copy(new_xbridge, NULL, xport);
        }
    }
}

static void
xlate_xbundle_copy(struct xbridge *xbridge, struct xbundle *xbundle)
{
    struct xport *xport;
    struct xbundle *new_xbundle = xzalloc(sizeof *xbundle);
    new_xbundle->ofbundle = xbundle->ofbundle;
    new_xbundle->xbridge = xbridge;
    new_xbundle->name = xstrdup(xbundle->name);
    xlate_xbundle_init(new_xcfg, new_xbundle);

    xlate_xbundle_set(new_xbundle, xbundle->vlan_mode, xbundle->qinq_ethtype,
                      xbundle->vlan, xbundle->trunks, xbundle->cvlans,
                      xbundle->use_priority_tags, xbundle->bond, xbundle->lacp,
                      xbundle->floodable, xbundle->protected);
    LIST_FOR_EACH (xport, bundle_node, &xbundle->xports) {
        xlate_xport_copy(xbridge, new_xbundle, xport);
    }
}

static void
xlate_xport_copy(struct xbridge *xbridge, struct xbundle *xbundle,
                 struct xport *xport)
{
    struct skb_priority_to_dscp *pdscp, *new_pdscp;
    struct xport *new_xport = xzalloc(sizeof *xport);
    new_xport->ofport = xport->ofport;
    new_xport->ofp_port = xport->ofp_port;
    new_xport->xbridge = xbridge;
    new_xport->uuid = xport->uuid;
    xlate_xport_init(new_xcfg, new_xport);

    xlate_xport_set(new_xport, xport->odp_port, xport->netdev, xport->cfm,
                    xport->bfd, xport->lldp, xport->stp_port_no,
                    xport->rstp_port, xport->config, xport->state,
                    xport->is_tunnel, xport->may_enable);

    if (xport->peer) {
        struct xport *peer = xport_lookup(new_xcfg, xport->peer->ofport);
        if (peer) {
            new_xport->peer = peer;
            new_xport->peer->peer = new_xport;
        }
    }

    if (xbundle) {
        new_xport->xbundle = xbundle;
        ovs_list_insert(&new_xport->xbundle->xports, &new_xport->bundle_node);
    }

    HMAP_FOR_EACH (pdscp, hmap_node, &xport->skb_priorities) {
        new_pdscp = xmalloc(sizeof *pdscp);
        new_pdscp->skb_priority = pdscp->skb_priority;
        new_pdscp->dscp = pdscp->dscp;
        hmap_insert(&new_xport->skb_priorities, &new_pdscp->hmap_node,
                    hash_int(new_pdscp->skb_priority, 0));
    }
}

/* Sets the current xlate configuration to new_xcfg and frees the old xlate
 * configuration in xcfgp.
 *
 * This needs to be called after editing the xlate configuration.
 *
 * Functions that edit the new xlate configuration are
 * xlate_<ofproto/bundle/ofport>_set and xlate_<ofproto/bundle/ofport>_remove.
 *
 * A sample workflow:
 *
 * xlate_txn_start();
 * ...
 * edit_xlate_configuration();
 * ...
 * xlate_txn_commit(); */
void
xlate_txn_commit(void)
{
    struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);

    ovsrcu_set(&xcfgp, new_xcfg);
    ovsrcu_synchronize();
    xlate_xcfg_free(xcfg);
    new_xcfg = NULL;
}

/* Copies the current xlate configuration in xcfgp to new_xcfg.
 *
 * This needs to be called prior to editing the xlate configuration. */
void
xlate_txn_start(void)
{
    struct xbridge *xbridge;
    struct xlate_cfg *xcfg;

    ovs_assert(!new_xcfg);

    new_xcfg = xmalloc(sizeof *new_xcfg);
    hmap_init(&new_xcfg->xbridges);
    hmap_init(&new_xcfg->xbundles);
    hmap_init(&new_xcfg->xports);
    hmap_init(&new_xcfg->xports_uuid);

    xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    if (!xcfg) {
        return;
    }

    HMAP_FOR_EACH (xbridge, hmap_node, &xcfg->xbridges) {
        xlate_xbridge_copy(xbridge);
    }
}


static void
xlate_xcfg_free(struct xlate_cfg *xcfg)
{
    struct xbridge *xbridge, *next_xbridge;

    if (!xcfg) {
        return;
    }

    HMAP_FOR_EACH_SAFE (xbridge, next_xbridge, hmap_node, &xcfg->xbridges) {
        xlate_xbridge_remove(xcfg, xbridge);
    }

    hmap_destroy(&xcfg->xbridges);
    hmap_destroy(&xcfg->xbundles);
    hmap_destroy(&xcfg->xports);
    hmap_destroy(&xcfg->xports_uuid);
    free(xcfg);
}

void
xlate_ofproto_set(struct ofproto_dpif *ofproto, const char *name,
                  struct dpif *dpif,
                  const struct mac_learning *ml, struct stp *stp,
                  struct rstp *rstp, const struct mcast_snooping *ms,
                  const struct mbridge *mbridge,
                  const struct dpif_sflow *sflow,
                  const struct dpif_ipfix *ipfix,
                  const struct netflow *netflow,
                  bool forward_bpdu, bool has_in_band,
                  const struct dpif_backer_support *support)
{
    struct xbridge *xbridge;
    struct xbridge_addr *xbridge_addr, *old_addr;

    ovs_assert(new_xcfg);

    xbridge = xbridge_lookup(new_xcfg, ofproto);
    if (!xbridge) {
        xbridge = xzalloc(sizeof *xbridge);
        xbridge->ofproto = ofproto;

        xlate_xbridge_init(new_xcfg, xbridge);
    }

    free(xbridge->name);
    xbridge->name = xstrdup(name);

    xbridge_addr = xbridge_addr_create(xbridge);
    old_addr = xbridge->addr;

    xlate_xbridge_set(xbridge, dpif, ml, stp, rstp, ms, mbridge, sflow, ipfix,
                      netflow, forward_bpdu, has_in_band, support,
                      xbridge_addr);

    if (xbridge_addr != old_addr) {
        xbridge_addr_unref(xbridge_addr);
    }
}

static void
xlate_xbridge_remove(struct xlate_cfg *xcfg, struct xbridge *xbridge)
{
    struct xbundle *xbundle, *next_xbundle;
    struct xport *xport, *next_xport;

    if (!xbridge) {
        return;
    }

    HMAP_FOR_EACH_SAFE (xport, next_xport, ofp_node, &xbridge->xports) {
        xlate_xport_remove(xcfg, xport);
    }

    LIST_FOR_EACH_SAFE (xbundle, next_xbundle, list_node, &xbridge->xbundles) {
        xlate_xbundle_remove(xcfg, xbundle);
    }

    hmap_remove(&xcfg->xbridges, &xbridge->hmap_node);
    mac_learning_unref(xbridge->ml);
    mcast_snooping_unref(xbridge->ms);
    mbridge_unref(xbridge->mbridge);
    dpif_sflow_unref(xbridge->sflow);
    dpif_ipfix_unref(xbridge->ipfix);
    netflow_unref(xbridge->netflow);
    stp_unref(xbridge->stp);
    rstp_unref(xbridge->rstp);
    xbridge_addr_unref(xbridge->addr);
    hmap_destroy(&xbridge->xports);
    free(xbridge->name);
    free(xbridge);
}

void
xlate_remove_ofproto(struct ofproto_dpif *ofproto)
{
    struct xbridge *xbridge;

    ovs_assert(new_xcfg);

    xbridge = xbridge_lookup(new_xcfg, ofproto);
    xlate_xbridge_remove(new_xcfg, xbridge);
}

void
xlate_bundle_set(struct ofproto_dpif *ofproto, struct ofbundle *ofbundle,
                 const char *name, enum port_vlan_mode vlan_mode,
                 uint16_t qinq_ethtype, int vlan,
                 unsigned long *trunks, unsigned long *cvlans,
                 bool use_priority_tags,
                 const struct bond *bond, const struct lacp *lacp,
                 bool floodable, bool protected)
{
    struct xbundle *xbundle;

    ovs_assert(new_xcfg);

    xbundle = xbundle_lookup(new_xcfg, ofbundle);
    if (!xbundle) {
        xbundle = xzalloc(sizeof *xbundle);
        xbundle->ofbundle = ofbundle;
        xbundle->xbridge = xbridge_lookup(new_xcfg, ofproto);

        xlate_xbundle_init(new_xcfg, xbundle);
    }

    free(xbundle->name);
    xbundle->name = xstrdup(name);

    xlate_xbundle_set(xbundle, vlan_mode, qinq_ethtype, vlan, trunks, cvlans,
                      use_priority_tags, bond, lacp, floodable, protected);
}

static void
xlate_xbundle_remove(struct xlate_cfg *xcfg, struct xbundle *xbundle)
{
    struct xport *xport;

    if (!xbundle) {
        return;
    }

    LIST_FOR_EACH_POP (xport, bundle_node, &xbundle->xports) {
        xport->xbundle = NULL;
    }

    hmap_remove(&xcfg->xbundles, &xbundle->hmap_node);
    ovs_list_remove(&xbundle->list_node);
    bond_unref(xbundle->bond);
    lacp_unref(xbundle->lacp);
    free(xbundle->name);
    free(xbundle);
}

void
xlate_bundle_remove(struct ofbundle *ofbundle)
{
    struct xbundle *xbundle;

    ovs_assert(new_xcfg);

    xbundle = xbundle_lookup(new_xcfg, ofbundle);
    xlate_xbundle_remove(new_xcfg, xbundle);
}

void
xlate_ofport_set(struct ofproto_dpif *ofproto, struct ofbundle *ofbundle,
                 struct ofport_dpif *ofport, ofp_port_t ofp_port,
                 odp_port_t odp_port, const struct netdev *netdev,
                 const struct cfm *cfm, const struct bfd *bfd,
                 const struct lldp *lldp, struct ofport_dpif *peer,
                 int stp_port_no, const struct rstp_port *rstp_port,
                 const struct ofproto_port_queue *qdscp_list, size_t n_qdscp,
                 enum ofputil_port_config config,
                 enum ofputil_port_state state, bool is_tunnel,
                 bool may_enable)
{
    size_t i;
    struct xport *xport;

    ovs_assert(new_xcfg);

    xport = xport_lookup(new_xcfg, ofport);
    if (!xport) {
        xport = xzalloc(sizeof *xport);
        xport->ofport = ofport;
        xport->xbridge = xbridge_lookup(new_xcfg, ofproto);
        xport->ofp_port = ofp_port;
        uuid_generate(&xport->uuid);

        xlate_xport_init(new_xcfg, xport);
    }

    ovs_assert(xport->ofp_port == ofp_port);

    xlate_xport_set(xport, odp_port, netdev, cfm, bfd, lldp,
                    stp_port_no, rstp_port, config, state, is_tunnel,
                    may_enable);

    if (xport->peer) {
        xport->peer->peer = NULL;
    }
    xport->peer = xport_lookup(new_xcfg, peer);
    if (xport->peer) {
        xport->peer->peer = xport;
    }

    if (xport->xbundle) {
        ovs_list_remove(&xport->bundle_node);
    }
    xport->xbundle = xbundle_lookup(new_xcfg, ofbundle);
    if (xport->xbundle) {
        ovs_list_insert(&xport->xbundle->xports, &xport->bundle_node);
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

static void
xlate_xport_remove(struct xlate_cfg *xcfg, struct xport *xport)
{
    if (!xport) {
        return;
    }

    if (xport->peer) {
        xport->peer->peer = NULL;
        xport->peer = NULL;
    }

    if (xport->xbundle) {
        ovs_list_remove(&xport->bundle_node);
    }

    clear_skb_priorities(xport);
    hmap_destroy(&xport->skb_priorities);

    hmap_remove(&xcfg->xports, &xport->hmap_node);
    hmap_remove(&xcfg->xports_uuid, &xport->uuid_node);
    hmap_remove(&xport->xbridge->xports, &xport->ofp_node);

    netdev_close(xport->netdev);
    rstp_port_unref(xport->rstp_port);
    cfm_unref(xport->cfm);
    bfd_unref(xport->bfd);
    lldp_unref(xport->lldp);
    free(xport);
}

void
xlate_ofport_remove(struct ofport_dpif *ofport)
{
    struct xport *xport;

    ovs_assert(new_xcfg);

    xport = xport_lookup(new_xcfg, ofport);
    xlate_xport_remove(new_xcfg, xport);
}

static struct ofproto_dpif *
xlate_lookup_ofproto_(const struct dpif_backer *backer, const struct flow *flow,
                      ofp_port_t *ofp_in_port, const struct xport **xportp)
{
    struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    const struct xport *xport;

    /* If packet is recirculated, xport can be retrieved from frozen state. */
    if (flow->recirc_id) {
        const struct recirc_id_node *recirc_id_node;

        recirc_id_node = recirc_id_node_find(flow->recirc_id);

        if (OVS_UNLIKELY(!recirc_id_node)) {
            return NULL;
        }

        /* If recirculation was initiated due to bond (in_port = OFPP_NONE)
         * then frozen state is static and xport_uuid is not defined, so xport
         * cannot be restored from frozen state. */
        if (recirc_id_node->state.metadata.in_port != OFPP_NONE) {
            struct uuid xport_uuid = recirc_id_node->state.xport_uuid;
            xport = xport_lookup_by_uuid(xcfg, &xport_uuid);
            if (xport && xport->xbridge && xport->xbridge->ofproto) {
                goto out;
            }
        }
    }

    xport = xport_lookup(xcfg, tnl_port_should_receive(flow)
                         ? tnl_port_receive(flow)
                         : odp_port_to_ofport(backer, flow->in_port.odp_port));
    if (OVS_UNLIKELY(!xport)) {
        return NULL;
    }

out:
    *xportp = xport;
    if (ofp_in_port) {
        *ofp_in_port = xport->ofp_port;
    }
    return xport->xbridge->ofproto;
}

/* Given a datapath and flow metadata ('backer', and 'flow' respectively)
 * returns the corresponding struct ofproto_dpif and OpenFlow port number. */
struct ofproto_dpif *
xlate_lookup_ofproto(const struct dpif_backer *backer, const struct flow *flow,
                     ofp_port_t *ofp_in_port)
{
    const struct xport *xport;

    return xlate_lookup_ofproto_(backer, flow, ofp_in_port, &xport);
}

/* Given a datapath and flow metadata ('backer', and 'flow' respectively),
 * optionally populates 'ofprotop' with the ofproto_dpif, 'ofp_in_port' with the
 * openflow in_port, and 'ipfix', 'sflow', and 'netflow' with the appropriate
 * handles for those protocols if they're enabled.  Caller may use the returned
 * pointers until quiescing, for longer term use additional references must
 * be taken.
 *
 * Returns 0 if successful, ENODEV if the parsed flow has no associated ofproto.
 */
int
xlate_lookup(const struct dpif_backer *backer, const struct flow *flow,
             struct ofproto_dpif **ofprotop, struct dpif_ipfix **ipfix,
             struct dpif_sflow **sflow, struct netflow **netflow,
             ofp_port_t *ofp_in_port)
{
    struct ofproto_dpif *ofproto;
    const struct xport *xport;

    ofproto = xlate_lookup_ofproto_(backer, flow, ofp_in_port, &xport);

    if (!ofproto) {
        return ENODEV;
    }

    if (ofprotop) {
        *ofprotop = ofproto;
    }

    if (ipfix) {
        *ipfix = xport ? xport->xbridge->ipfix : NULL;
    }

    if (sflow) {
        *sflow = xport ? xport->xbridge->sflow : NULL;
    }

    if (netflow) {
        *netflow = xport ? xport->xbridge->netflow : NULL;
    }

    return 0;
}

static struct xbridge *
xbridge_lookup(struct xlate_cfg *xcfg, const struct ofproto_dpif *ofproto)
{
    struct hmap *xbridges;
    struct xbridge *xbridge;

    if (!ofproto || !xcfg) {
        return NULL;
    }

    xbridges = &xcfg->xbridges;

    HMAP_FOR_EACH_IN_BUCKET (xbridge, hmap_node, hash_pointer(ofproto, 0),
                             xbridges) {
        if (xbridge->ofproto == ofproto) {
            return xbridge;
        }
    }
    return NULL;
}

static struct xbridge *
xbridge_lookup_by_uuid(struct xlate_cfg *xcfg, const struct uuid *uuid)
{
    struct xbridge *xbridge;

    HMAP_FOR_EACH (xbridge, hmap_node, &xcfg->xbridges) {
        if (uuid_equals(&xbridge->ofproto->uuid, uuid)) {
            return xbridge;
        }
    }
    return NULL;
}

static struct xbundle *
xbundle_lookup(struct xlate_cfg *xcfg, const struct ofbundle *ofbundle)
{
    struct hmap *xbundles;
    struct xbundle *xbundle;

    if (!ofbundle || !xcfg) {
        return NULL;
    }

    xbundles = &xcfg->xbundles;

    HMAP_FOR_EACH_IN_BUCKET (xbundle, hmap_node, hash_pointer(ofbundle, 0),
                             xbundles) {
        if (xbundle->ofbundle == ofbundle) {
            return xbundle;
        }
    }
    return NULL;
}

static struct xport *
xport_lookup(struct xlate_cfg *xcfg, const struct ofport_dpif *ofport)
{
    struct hmap *xports;
    struct xport *xport;

    if (!ofport || !xcfg) {
        return NULL;
    }

    xports = &xcfg->xports;

    HMAP_FOR_EACH_IN_BUCKET (xport, hmap_node, hash_pointer(ofport, 0),
                             xports) {
        if (xport->ofport == ofport) {
            return xport;
        }
    }
    return NULL;
}

static struct xport *
xport_lookup_by_uuid(struct xlate_cfg *xcfg, const struct uuid *uuid)
{
    struct hmap *xports;
    struct xport *xport;

    if (uuid_is_zero(uuid) || !xcfg) {
        return NULL;
    }

    xports = &xcfg->xports_uuid;

    HMAP_FOR_EACH_IN_BUCKET (xport, uuid_node, uuid_hash(uuid), xports) {
        if (uuid_equals(&xport->uuid, uuid)) {
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
    return sp
        ? stp_learn_in_state(stp_port_get_state(sp))
        : true;
}

static bool
xport_stp_forward_state(const struct xport *xport)
{
    struct stp_port *sp = xport_get_stp_port(xport);
    return sp
        ? stp_forward_in_state(stp_port_get_state(sp))
        : true;
}

static bool
xport_stp_should_forward_bpdu(const struct xport *xport)
{
    struct stp_port *sp = xport_get_stp_port(xport);
    return stp_should_forward_bpdu(sp ? stp_port_get_state(sp) : STP_DISABLED);
}

/* Returns true if STP should process 'flow'.  Sets fields in 'wc' that
 * were used to make the determination.*/
static bool
stp_should_process_flow(const struct flow *flow, struct flow_wildcards *wc)
{
    /* is_stp() also checks dl_type, but dl_type is always set in 'wc'. */
    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
    return is_stp(flow);
}

static void
stp_process_packet(const struct xport *xport, const struct dp_packet *packet)
{
    struct stp_port *sp = xport_get_stp_port(xport);
    struct dp_packet payload = *packet;
    struct eth_header *eth = dp_packet_data(&payload);

    /* Sink packets on ports that have STP disabled when the bridge has
     * STP enabled. */
    if (!sp || stp_port_get_state(sp) == STP_DISABLED) {
        return;
    }

    /* Trim off padding on payload. */
    if (dp_packet_size(&payload) > ntohs(eth->eth_type) + ETH_HEADER_LEN) {
        dp_packet_set_size(&payload, ntohs(eth->eth_type) + ETH_HEADER_LEN);
    }

    if (dp_packet_try_pull(&payload, ETH_HEADER_LEN + LLC_HEADER_LEN)) {
        stp_received_bpdu(sp, dp_packet_data(&payload), dp_packet_size(&payload));
    }
}

static enum rstp_state
xport_get_rstp_port_state(const struct xport *xport)
{
    return xport->rstp_port
        ? rstp_port_get_state(xport->rstp_port)
        : RSTP_DISABLED;
}

static bool
xport_rstp_learn_state(const struct xport *xport)
{
    return xport->xbridge->rstp && xport->rstp_port
        ? rstp_learn_in_state(xport_get_rstp_port_state(xport))
        : true;
}

static bool
xport_rstp_forward_state(const struct xport *xport)
{
    return xport->xbridge->rstp && xport->rstp_port
        ? rstp_forward_in_state(xport_get_rstp_port_state(xport))
        : true;
}

static bool
xport_rstp_should_manage_bpdu(const struct xport *xport)
{
    return rstp_should_manage_bpdu(xport_get_rstp_port_state(xport));
}

static void
rstp_process_packet(const struct xport *xport, const struct dp_packet *packet)
{
    struct dp_packet payload = *packet;
    struct eth_header *eth = dp_packet_data(&payload);

    /* Sink packets on ports that have no RSTP. */
    if (!xport->rstp_port) {
        return;
    }

    /* Trim off padding on payload. */
    if (dp_packet_size(&payload) > ntohs(eth->eth_type) + ETH_HEADER_LEN) {
        dp_packet_set_size(&payload, ntohs(eth->eth_type) + ETH_HEADER_LEN);
    }

    if (dp_packet_try_pull(&payload, ETH_HEADER_LEN + LLC_HEADER_LEN)) {
        rstp_port_received_bpdu(xport->rstp_port, dp_packet_data(&payload),
                                dp_packet_size(&payload));
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
    struct xport *xport = get_ofp_port(ctx->xbridge, ofp_port);
    return xport && xport->may_enable;
}

static struct ofputil_bucket *
group_first_live_bucket(const struct xlate_ctx *, const struct group_dpif *,
                        int depth);

static bool
group_is_alive(const struct xlate_ctx *ctx, uint32_t group_id, int depth)
{
    struct group_dpif *group;

    group = group_dpif_lookup(ctx->xbridge->ofproto, group_id,
                              ctx->xin->tables_version, false);
    if (group) {
        return group_first_live_bucket(ctx, group, depth) != NULL;
    }

    return false;
}

#define MAX_LIVENESS_RECURSION 128 /* Arbitrary limit */

static bool
bucket_is_alive(const struct xlate_ctx *ctx,
                struct ofputil_bucket *bucket, int depth)
{
    if (depth >= MAX_LIVENESS_RECURSION) {
        xlate_report_error(ctx, "bucket chaining exceeded %d links",
                           MAX_LIVENESS_RECURSION);
        return false;
    }

    return (!ofputil_bucket_has_liveness(bucket)
            || (bucket->watch_port != OFPP_ANY
               && odp_port_is_alive(ctx, bucket->watch_port))
            || (bucket->watch_group != OFPG_ANY
               && group_is_alive(ctx, bucket->watch_group, depth + 1)));
}

static struct ofputil_bucket *
group_first_live_bucket(const struct xlate_ctx *ctx,
                        const struct group_dpif *group, int depth)
{
    struct ofputil_bucket *bucket;
    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
        if (bucket_is_alive(ctx, bucket, depth)) {
            return bucket;
        }
    }

    return NULL;
}

static struct ofputil_bucket *
group_best_live_bucket(const struct xlate_ctx *ctx,
                       const struct group_dpif *group,
                       uint32_t basis)
{
    struct ofputil_bucket *best_bucket = NULL;
    uint32_t best_score = 0;

    struct ofputil_bucket *bucket;
    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
        if (bucket_is_alive(ctx, bucket, 0)) {
            uint32_t score =
                (hash_int(bucket->bucket_id, basis) & 0xffff) * bucket->weight;
            if (score >= best_score) {
                best_bucket = bucket;
                best_score = score;
            }
        }
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
xbundle_allows_cvlan(const struct xbundle *bundle, uint16_t vlan)
{
    return (!bundle->cvlans || bitmap_is_set(bundle->cvlans, vlan));
}

static bool
xbundle_includes_vlan(const struct xbundle *xbundle, const struct xvlan *xvlan)
{
    switch (xbundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        return xvlan->v[0].vid == xbundle->vlan && xvlan->v[1].vid == 0;

    case PORT_VLAN_TRUNK:
    case PORT_VLAN_NATIVE_UNTAGGED:
    case PORT_VLAN_NATIVE_TAGGED:
        return xbundle_trunks_vlan(xbundle, xvlan->v[0].vid);

    case PORT_VLAN_DOT1Q_TUNNEL:
        return xvlan->v[0].vid == xbundle->vlan &&
               xbundle_allows_cvlan(xbundle, xvlan->v[1].vid);

    default:
        OVS_NOT_REACHED();
    }
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
lookup_input_bundle__(const struct xbridge *xbridge,
                      ofp_port_t in_port, struct xport **in_xportp)
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

    /* Special-case OFPP_NONE (OF1.0) and OFPP_CONTROLLER (OF1.1+),
     * which a controller may use as the ingress port for traffic that
     * it is sourcing. */
    if (in_port == OFPP_CONTROLLER || in_port == OFPP_NONE) {
        return &ofpp_none_bundle;
    }
    return NULL;
}

static struct xbundle *
lookup_input_bundle(const struct xlate_ctx *ctx,
                      ofp_port_t in_port, struct xport **in_xportp)
{
    struct xbundle *xbundle = lookup_input_bundle__(ctx->xbridge,
                                                    in_port, in_xportp);
    if (!xbundle) {
        /* Odd.  A few possible reasons here:
         *
         * - We deleted a port but there are still a few packets queued up
         *   from it.
         *
         * - Someone externally added a port (e.g. "ovs-dpctl add-if") that
         *   we don't know about.
         *
         * - The ofproto client didn't configure the port as part of a bundle.
         *   This is particularly likely to happen if a packet was received on
         *   the port after it was created, but before the client had a chance
         *   to configure its bundle.
         */
        xlate_report_error(ctx, "received packet on unknown port %"PRIu32,
                           in_port);
    }
    return xbundle;
}

/* Mirrors the packet represented by 'ctx' to appropriate mirror destinations,
 * given the packet is ingressing or egressing on 'xbundle', which has ingress
 * or egress (as appropriate) mirrors 'mirrors'. */
static void
mirror_packet(struct xlate_ctx *ctx, struct xbundle *xbundle,
              mirror_mask_t mirrors)
{
    struct xvlan in_xvlan;
    struct xvlan xvlan;

    /* Figure out what VLAN the packet is in (because mirrors can select
     * packets on basis of VLAN). */
    xvlan_extract(&ctx->xin->flow, &in_xvlan);
    if (!input_vid_is_valid(ctx, in_xvlan.v[0].vid, xbundle)) {
        return;
    }
    xvlan_input_translate(xbundle, &in_xvlan, &xvlan);

    const struct xbridge *xbridge = ctx->xbridge;

    /* Don't mirror to destinations that we've already mirrored to. */
    mirrors &= ~ctx->mirrors;
    if (!mirrors) {
        return;
    }

    if (ctx->xin->resubmit_stats) {
        mirror_update_stats(xbridge->mbridge, mirrors,
                            ctx->xin->resubmit_stats->n_packets,
                            ctx->xin->resubmit_stats->n_bytes);
    }
    if (ctx->xin->xcache) {
        struct xc_entry *entry;

        entry = xlate_cache_add_entry(ctx->xin->xcache, XC_MIRROR);
        entry->mirror.mbridge = mbridge_ref(xbridge->mbridge);
        entry->mirror.mirrors = mirrors;
    }

    /* 'mirrors' is a bit-mask of candidates for mirroring.  Iterate as long as
     * some candidates remain.  */
    while (mirrors) {
        const unsigned long *vlans;
        mirror_mask_t dup_mirrors;
        struct ofbundle *out;
        int out_vlan;
        int snaplen;

        /* Get the details of the mirror represented by the rightmost 1-bit. */
        ovs_assert(mirror_get(xbridge->mbridge, raw_ctz(mirrors),
                              &vlans, &dup_mirrors,
                              &out, &snaplen, &out_vlan));


        /* If this mirror selects on the basis of VLAN, and it does not select
         * 'vlan', then discard this mirror and go on to the next one. */
        if (vlans) {
            ctx->wc->masks.vlans[0].tci |= htons(VLAN_CFI | VLAN_VID_MASK);
        }
        if (vlans && !bitmap_is_set(vlans, xvlan.v[0].vid)) {
            mirrors = zero_rightmost_1bit(mirrors);
            continue;
        }

        /* Record the mirror, and the mirrors that output to the same
         * destination, so that we don't mirror to them again.  This must be
         * done now to ensure that output_normal(), below, doesn't recursively
         * output to the same mirrors. */
        ctx->mirrors |= dup_mirrors;
        ctx->mirror_snaplen = snaplen;

        /* Send the packet to the mirror. */
        if (out) {
            struct xbundle *out_xbundle = xbundle_lookup(ctx->xcfg, out);
            if (out_xbundle) {
                output_normal(ctx, out_xbundle, &xvlan);
            }
        } else if (xvlan.v[0].vid != out_vlan
                   && !eth_addr_is_reserved(ctx->xin->flow.dl_dst)) {
            struct xbundle *xb;
            uint16_t old_vid = xvlan.v[0].vid;

            xvlan.v[0].vid = out_vlan;
            LIST_FOR_EACH (xb, list_node, &xbridge->xbundles) {
                if (xbundle_includes_vlan(xb, &xvlan)
                    && !xbundle_mirror_out(xbridge, xb)) {
                    output_normal(ctx, xb, &xvlan);
                }
            }
            xvlan.v[0].vid = old_vid;
        }

        /* output_normal() could have recursively output (to different
         * mirrors), so make sure that we don't send duplicates. */
        mirrors &= ~ctx->mirrors;
        ctx->mirror_snaplen = 0;
    }
}

static void
mirror_ingress_packet(struct xlate_ctx *ctx)
{
    if (mbridge_has_mirrors(ctx->xbridge->mbridge)) {
        struct xbundle *xbundle = lookup_input_bundle(
            ctx, ctx->xin->flow.in_port.ofp_port, NULL);
        if (xbundle) {
            mirror_packet(ctx, xbundle,
                          xbundle_mirror_src(ctx->xbridge, xbundle));
        }
    }
}

/* Checks whether a packet with the given 'vid' may ingress on 'in_xbundle'.
 * If so, returns true.  Otherwise, returns false.
 *
 * 'vid' should be the VID obtained from the 802.1Q header that was received as
 * part of a packet (specify 0 if there was no 802.1Q header), in the range
 * 0...4095. */
static bool
input_vid_is_valid(const struct xlate_ctx *ctx,
                   uint16_t vid, struct xbundle *in_xbundle)
{
    /* Allow any VID on the OFPP_NONE port. */
    if (in_xbundle == &ofpp_none_bundle) {
        return true;
    }

    switch (in_xbundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        if (vid) {
            xlate_report_error(ctx, "dropping VLAN %"PRIu16" tagged "
                               "packet received on port %s configured as VLAN "
                               "%d access port", vid, in_xbundle->name,
                               in_xbundle->vlan);
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
        if (!xbundle_trunks_vlan(in_xbundle, vid)) {
            xlate_report_error(ctx, "dropping VLAN %"PRIu16" packet "
                               "received on port %s not configured for "
                               "trunking VLAN %"PRIu16,
                               vid, in_xbundle->name, vid);
            return false;
        }
        return true;

    case PORT_VLAN_DOT1Q_TUNNEL:
        if (!xbundle_allows_cvlan(in_xbundle, vid)) {
            xlate_report_error(ctx, "dropping VLAN %"PRIu16" packet received "
                               "on dot1q-tunnel port %s that excludes this "
                               "VLAN", vid, in_xbundle->name);
            return false;
        }
        return true;

    default:
        OVS_NOT_REACHED();
    }

}

static void
xvlan_copy(struct xvlan *dst, const struct xvlan *src)
{
    *dst = *src;
}

static void
xvlan_pop(struct xvlan *src)
{
    memmove(&src->v[0], &src->v[1], sizeof(src->v) - sizeof(src->v[0]));
    memset(&src->v[FLOW_MAX_VLAN_HEADERS - 1], 0,
           sizeof(src->v[FLOW_MAX_VLAN_HEADERS - 1]));
}

static void
xvlan_push_uninit(struct xvlan *src)
{
    memmove(&src->v[1], &src->v[0], sizeof(src->v) - sizeof(src->v[0]));
    memset(&src->v[0], 0, sizeof(src->v[0]));
}

/* Extract VLAN information (headers) from flow */
static void
xvlan_extract(const struct flow *flow, struct xvlan *xvlan)
{
    int i;
    memset(xvlan, 0, sizeof(*xvlan));
    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        if (!eth_type_vlan(flow->vlans[i].tpid) ||
            !(flow->vlans[i].tci & htons(VLAN_CFI))) {
            break;
        }
        xvlan->v[i].tpid = ntohs(flow->vlans[i].tpid);
        xvlan->v[i].vid = vlan_tci_to_vid(flow->vlans[i].tci);
        xvlan->v[i].pcp = ntohs(flow->vlans[i].tci) & VLAN_PCP_MASK;
    }
}

/* Put VLAN information (headers) to flow */
static void
xvlan_put(struct flow *flow, const struct xvlan *xvlan)
{
    ovs_be16 tci;
    int i;
    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        tci = htons(xvlan->v[i].vid | (xvlan->v[i].pcp & VLAN_PCP_MASK));
        if (tci) {
            tci |= htons(VLAN_CFI);
            flow->vlans[i].tpid = xvlan->v[i].tpid ?
                                  htons(xvlan->v[i].tpid) :
                                  htons(ETH_TYPE_VLAN_8021Q);
        }
        flow->vlans[i].tci = tci;
    }
}

/* Given 'in_xvlan', extracted from the input 802.1Q headers received as part
 * of a packet, and 'in_xbundle', the bundle on which the packet was received,
 * returns the VLANs of the packet during bridge internal processing. */
static void
xvlan_input_translate(const struct xbundle *in_xbundle,
                      const struct xvlan *in_xvlan, struct xvlan *xvlan)
{

    switch (in_xbundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        memset(xvlan, 0, sizeof(*xvlan));
        xvlan->v[0].tpid = in_xvlan->v[0].tpid ? in_xvlan->v[0].tpid :
                                                 ETH_TYPE_VLAN_8021Q;
        xvlan->v[0].vid = in_xbundle->vlan;
        xvlan->v[0].pcp = in_xvlan->v[0].pcp;
        break;

    case PORT_VLAN_TRUNK:
        xvlan_copy(xvlan, in_xvlan);
        break;

    case PORT_VLAN_NATIVE_UNTAGGED:
    case PORT_VLAN_NATIVE_TAGGED:
        xvlan_copy(xvlan, in_xvlan);
        if (!in_xvlan->v[0].vid) {
            xvlan->v[0].tpid = in_xvlan->v[0].tpid ? in_xvlan->v[0].tpid :
                                                     ETH_TYPE_VLAN_8021Q;
            xvlan->v[0].vid = in_xbundle->vlan;
            xvlan->v[0].pcp = in_xvlan->v[0].pcp;
        }
        break;

    case PORT_VLAN_DOT1Q_TUNNEL:
        xvlan_copy(xvlan, in_xvlan);
        xvlan_push_uninit(xvlan);
        xvlan->v[0].tpid = in_xbundle->qinq_ethtype;
        xvlan->v[0].vid = in_xbundle->vlan;
        xvlan->v[0].pcp = 0;
        break;

    default:
        OVS_NOT_REACHED();
    }
}

/* Given 'xvlan', the VLANs of a packet during internal processing, and
 * 'out_xbundle', a bundle on which the packet is to be output, returns the
 * VLANs that should be included in output packet. */
static void
xvlan_output_translate(const struct xbundle *out_xbundle,
                       const struct xvlan *xvlan, struct xvlan *out_xvlan)
{
    switch (out_xbundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        memset(out_xvlan, 0, sizeof(*out_xvlan));
        break;

    case PORT_VLAN_TRUNK:
    case PORT_VLAN_NATIVE_TAGGED:
        xvlan_copy(out_xvlan, xvlan);
        break;

    case PORT_VLAN_NATIVE_UNTAGGED:
        xvlan_copy(out_xvlan, xvlan);
        if (xvlan->v[0].vid == out_xbundle->vlan) {
            xvlan_pop(out_xvlan);
        }
        break;

    case PORT_VLAN_DOT1Q_TUNNEL:
        xvlan_copy(out_xvlan, xvlan);
        xvlan_pop(out_xvlan);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

/* If output xbundle is dot1q-tunnel, set mask bits of cvlan */
static void
check_and_set_cvlan_mask(struct flow_wildcards *wc,
                         const struct xbundle *xbundle)
{
    if (xbundle->vlan_mode == PORT_VLAN_DOT1Q_TUNNEL && xbundle->cvlans) {
        wc->masks.vlans[1].tci = htons(0xffff);
    }
}

static void
output_normal(struct xlate_ctx *ctx, const struct xbundle *out_xbundle,
              const struct xvlan *xvlan)
{
    uint16_t vid;
    union flow_vlan_hdr old_vlans[FLOW_MAX_VLAN_HEADERS];
    struct xport *xport;
    struct xlate_bond_recirc xr;
    bool use_recirc = false;
    struct xvlan out_xvlan;

    check_and_set_cvlan_mask(ctx->wc, out_xbundle);

    xvlan_output_translate(out_xbundle, xvlan, &out_xvlan);
    if (out_xbundle->use_priority_tags) {
        out_xvlan.v[0].pcp = ntohs(ctx->xin->flow.vlans[0].tci) &
                             VLAN_PCP_MASK;
    }
    vid = out_xvlan.v[0].vid;
    if (ovs_list_is_empty(&out_xbundle->xports)) {
        /* Partially configured bundle with no slaves.  Drop the packet. */
        return;
    } else if (!out_xbundle->bond) {
        xport = CONTAINER_OF(ovs_list_front(&out_xbundle->xports), struct xport,
                             bundle_node);
    } else {
        struct flow_wildcards *wc = ctx->wc;
        struct ofport_dpif *ofport;

        if (ctx->xbridge->support.odp.recirc) {
            /* In case recirculation is not actually in use, 'xr.recirc_id'
             * will be set to '0', since a valid 'recirc_id' can
             * not be zero.  */
            bond_update_post_recirc_rules(out_xbundle->bond,
                                          &xr.recirc_id,
                                          &xr.hash_basis);
            if (xr.recirc_id) {
                /* Use recirculation instead of output. */
                use_recirc = true;
                xr.hash_alg = OVS_HASH_ALG_L4;
                /* Recirculation does not require unmasking hash fields. */
                wc = NULL;
            }
        }

        ofport = bond_choose_output_slave(out_xbundle->bond,
                                          &ctx->xin->flow, wc, vid);
        xport = xport_lookup(ctx->xcfg, ofport);

        if (!xport) {
            /* No slaves enabled, so drop packet. */
            return;
        }

        /* If use_recirc is set, the main thread will handle stats
         * accounting for this bond. */
        if (!use_recirc) {
            if (ctx->xin->resubmit_stats) {
                bond_account(out_xbundle->bond, &ctx->xin->flow, vid,
                             ctx->xin->resubmit_stats->n_bytes);
            }
            if (ctx->xin->xcache) {
                struct xc_entry *entry;
                struct flow *flow;

                flow = &ctx->xin->flow;
                entry = xlate_cache_add_entry(ctx->xin->xcache, XC_BOND);
                entry->bond.bond = bond_ref(out_xbundle->bond);
                entry->bond.flow = xmemdup(flow, sizeof *flow);
                entry->bond.vid = vid;
            }
        }
    }

    memcpy(&old_vlans, &ctx->xin->flow.vlans, sizeof(old_vlans));
    xvlan_put(&ctx->xin->flow, &out_xvlan);

    compose_output_action(ctx, xport->ofp_port, use_recirc ? &xr : NULL,
                          false, false);
    memcpy(&ctx->xin->flow.vlans, &old_vlans, sizeof(old_vlans));
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
        xlate_report(ctx, OFT_DETAIL,
                     "packet has reserved destination MAC, dropping");
        return false;
    }

    if (in_xbundle->bond) {
        struct mac_entry *mac;

        switch (bond_check_admissibility(in_xbundle->bond, in_port->ofport,
                                         flow->dl_dst)) {
        case BV_ACCEPT:
            break;

        case BV_DROP:
            xlate_report(ctx, OFT_DETAIL,
                         "bonding refused admissibility, dropping");
            return false;

        case BV_DROP_IF_MOVED:
            ovs_rwlock_rdlock(&xbridge->ml->rwlock);
            mac = mac_learning_lookup(xbridge->ml, flow->dl_src, vlan);
            if (mac
                && mac_entry_get_port(xbridge->ml, mac) != in_xbundle->ofbundle
                && (!is_gratuitous_arp(flow, ctx->wc)
                    || mac_entry_is_grat_arp_locked(mac))) {
                ovs_rwlock_unlock(&xbridge->ml->rwlock);
                xlate_report(ctx, OFT_DETAIL,
                             "SLB bond thinks this packet looped back, "
                             "dropping");
                return false;
            }
            ovs_rwlock_unlock(&xbridge->ml->rwlock);
            break;
        }
    }

    return true;
}

static bool
update_learning_table__(const struct xbridge *xbridge,
                        struct xbundle *in_xbundle, struct eth_addr dl_src,
                        int vlan, bool is_grat_arp)
{
    return (in_xbundle == &ofpp_none_bundle
            || !mac_learning_update(xbridge->ml, dl_src, vlan,
                                    is_grat_arp,
                                    in_xbundle->bond != NULL,
                                    in_xbundle->ofbundle));
}

static void
update_learning_table(const struct xlate_ctx *ctx,
                      struct xbundle *in_xbundle, struct eth_addr dl_src,
                      int vlan, bool is_grat_arp)
{
    if (!update_learning_table__(ctx->xbridge, in_xbundle, dl_src, vlan,
                                 is_grat_arp)) {
        xlate_report_debug(ctx, OFT_DETAIL, "learned that "ETH_ADDR_FMT" is "
                           "on port %s in VLAN %d",
                           ETH_ADDR_ARGS(dl_src), in_xbundle->name, vlan);
    }
}

/* Updates multicast snooping table 'ms' given that a packet matching 'flow'
 * was received on 'in_xbundle' in 'vlan' and is either Report or Query. */
static void
update_mcast_snooping_table4__(const struct xlate_ctx *ctx,
                               const struct flow *flow,
                               struct mcast_snooping *ms, int vlan,
                               struct xbundle *in_xbundle,
                               const struct dp_packet *packet)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    const struct igmp_header *igmp;
    int count;
    size_t offset;
    ovs_be32 ip4 = flow->igmp_group_ip4;

    offset = (char *) dp_packet_l4(packet) - (char *) dp_packet_data(packet);
    igmp = dp_packet_at(packet, offset, IGMP_HEADER_LEN);
    if (!igmp || csum(igmp, dp_packet_l4_size(packet)) != 0) {
        xlate_report_debug(ctx, OFT_DETAIL,
                           "multicast snooping received bad IGMP "
                           "checksum on port %s in VLAN %d",
                           in_xbundle->name, vlan);
        return;
    }

    switch (ntohs(flow->tp_src)) {
    case IGMP_HOST_MEMBERSHIP_REPORT:
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        if (mcast_snooping_add_group4(ms, ip4, vlan, in_xbundle->ofbundle)) {
            xlate_report_debug(ctx, OFT_DETAIL,
                               "multicast snooping learned that "
                               IP_FMT" is on port %s in VLAN %d",
                               IP_ARGS(ip4), in_xbundle->name, vlan);
        }
        break;
    case IGMP_HOST_LEAVE_MESSAGE:
        if (mcast_snooping_leave_group4(ms, ip4, vlan, in_xbundle->ofbundle)) {
            xlate_report_debug(ctx, OFT_DETAIL, "multicast snooping leaving "
                               IP_FMT" is on port %s in VLAN %d",
                               IP_ARGS(ip4), in_xbundle->name, vlan);
        }
        break;
    case IGMP_HOST_MEMBERSHIP_QUERY:
        if (flow->nw_src && mcast_snooping_add_mrouter(ms, vlan,
                                                       in_xbundle->ofbundle)) {
            xlate_report_debug(ctx, OFT_DETAIL, "multicast snooping query "
                               "from "IP_FMT" is on port %s in VLAN %d",
                               IP_ARGS(flow->nw_src), in_xbundle->name, vlan);
        }
        break;
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        count = mcast_snooping_add_report(ms, packet, vlan,
                                          in_xbundle->ofbundle);
        if (count) {
            xlate_report_debug(ctx, OFT_DETAIL, "multicast snooping processed "
                               "%d addresses on port %s in VLAN %d",
                               count, in_xbundle->name, vlan);
        }
        break;
    }
}

static void
update_mcast_snooping_table6__(const struct xlate_ctx *ctx,
                               const struct flow *flow,
                               struct mcast_snooping *ms, int vlan,
                               struct xbundle *in_xbundle,
                               const struct dp_packet *packet)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    const struct mld_header *mld;
    int count;
    size_t offset;

    offset = (char *) dp_packet_l4(packet) - (char *) dp_packet_data(packet);
    mld = dp_packet_at(packet, offset, MLD_HEADER_LEN);

    if (!mld ||
        packet_csum_upperlayer6(dp_packet_l3(packet),
                                mld, IPPROTO_ICMPV6,
                                dp_packet_l4_size(packet)) != 0) {
        xlate_report_debug(ctx, OFT_DETAIL, "multicast snooping received "
                           "bad MLD checksum on port %s in VLAN %d",
                           in_xbundle->name, vlan);
        return;
    }

    switch (ntohs(flow->tp_src)) {
    case MLD_QUERY:
        if (!ipv6_addr_equals(&flow->ipv6_src, &in6addr_any)
            && mcast_snooping_add_mrouter(ms, vlan, in_xbundle->ofbundle)) {
            xlate_report_debug(ctx, OFT_DETAIL, "multicast snooping query on "
                               "port %s in VLAN %d", in_xbundle->name, vlan);
        }
        break;
    case MLD_REPORT:
    case MLD_DONE:
    case MLD2_REPORT:
        count = mcast_snooping_add_mld(ms, packet, vlan, in_xbundle->ofbundle);
        if (count) {
            xlate_report_debug(ctx, OFT_DETAIL, "multicast snooping processed "
                               "%d addresses on port %s in VLAN %d",
                               count, in_xbundle->name, vlan);
        }
        break;
    }
}

/* Updates multicast snooping table 'ms' given that a packet matching 'flow'
 * was received on 'in_xbundle' in 'vlan'. */
static void
update_mcast_snooping_table(const struct xlate_ctx *ctx,
                            const struct flow *flow, int vlan,
                            struct xbundle *in_xbundle,
                            const struct dp_packet *packet)
{
    struct mcast_snooping *ms = ctx->xbridge->ms;
    struct xbundle *mcast_xbundle;
    struct mcast_port_bundle *fport;

    /* Don't learn the OFPP_NONE port. */
    if (in_xbundle == &ofpp_none_bundle) {
        return;
    }

    /* Don't learn from flood ports */
    mcast_xbundle = NULL;
    ovs_rwlock_wrlock(&ms->rwlock);
    LIST_FOR_EACH(fport, node, &ms->fport_list) {
        mcast_xbundle = xbundle_lookup(ctx->xcfg, fport->port);
        if (mcast_xbundle == in_xbundle) {
            break;
        }
    }

    if (!mcast_xbundle || mcast_xbundle != in_xbundle) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            update_mcast_snooping_table4__(ctx, flow, ms, vlan,
                                           in_xbundle, packet);
        } else {
            update_mcast_snooping_table6__(ctx, flow, ms, vlan,
                                           in_xbundle, packet);
        }
    }
    ovs_rwlock_unlock(&ms->rwlock);
}

/* send the packet to ports having the multicast group learned */
static void
xlate_normal_mcast_send_group(struct xlate_ctx *ctx,
                              struct mcast_snooping *ms OVS_UNUSED,
                              struct mcast_group *grp,
                              struct xbundle *in_xbundle,
                              const struct xvlan *xvlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct mcast_group_bundle *b;
    struct xbundle *mcast_xbundle;

    LIST_FOR_EACH(b, bundle_node, &grp->bundle_lru) {
        mcast_xbundle = xbundle_lookup(ctx->xcfg, b->port);
        if (mcast_xbundle && mcast_xbundle != in_xbundle) {
            xlate_report(ctx, OFT_DETAIL, "forwarding to mcast group port");
            output_normal(ctx, mcast_xbundle, xvlan);
        } else if (!mcast_xbundle) {
            xlate_report(ctx, OFT_WARN,
                         "mcast group port is unknown, dropping");
        } else {
            xlate_report(ctx, OFT_DETAIL,
                         "mcast group port is input port, dropping");
        }
    }
}

/* send the packet to ports connected to multicast routers */
static void
xlate_normal_mcast_send_mrouters(struct xlate_ctx *ctx,
                                 struct mcast_snooping *ms,
                                 struct xbundle *in_xbundle,
                                 const struct xvlan *xvlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct mcast_mrouter_bundle *mrouter;
    struct xbundle *mcast_xbundle;

    LIST_FOR_EACH(mrouter, mrouter_node, &ms->mrouter_lru) {
        mcast_xbundle = xbundle_lookup(ctx->xcfg, mrouter->port);
        if (mcast_xbundle && mcast_xbundle != in_xbundle
            && mrouter->vlan == xvlan->v[0].vid) {
            xlate_report(ctx, OFT_DETAIL, "forwarding to mcast router port");
            output_normal(ctx, mcast_xbundle, xvlan);
        } else if (!mcast_xbundle) {
            xlate_report(ctx, OFT_WARN,
                         "mcast router port is unknown, dropping");
        } else if (mrouter->vlan != xvlan->v[0].vid) {
            xlate_report(ctx, OFT_DETAIL,
                         "mcast router is on another vlan, dropping");
        } else {
            xlate_report(ctx, OFT_DETAIL,
                         "mcast router port is input port, dropping");
        }
    }
}

/* send the packet to ports flagged to be flooded */
static void
xlate_normal_mcast_send_fports(struct xlate_ctx *ctx,
                               struct mcast_snooping *ms,
                               struct xbundle *in_xbundle,
                               const struct xvlan *xvlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct mcast_port_bundle *fport;
    struct xbundle *mcast_xbundle;

    LIST_FOR_EACH(fport, node, &ms->fport_list) {
        mcast_xbundle = xbundle_lookup(ctx->xcfg, fport->port);
        if (mcast_xbundle && mcast_xbundle != in_xbundle) {
            xlate_report(ctx, OFT_DETAIL, "forwarding to mcast flood port");
            output_normal(ctx, mcast_xbundle, xvlan);
        } else if (!mcast_xbundle) {
            xlate_report(ctx, OFT_WARN,
                         "mcast flood port is unknown, dropping");
        } else {
            xlate_report(ctx, OFT_DETAIL,
                         "mcast flood port is input port, dropping");
        }
    }
}

/* forward the Reports to configured ports */
static void
xlate_normal_mcast_send_rports(struct xlate_ctx *ctx,
                               struct mcast_snooping *ms,
                               struct xbundle *in_xbundle,
                               const struct xvlan *xvlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct mcast_port_bundle *rport;
    struct xbundle *mcast_xbundle;

    LIST_FOR_EACH(rport, node, &ms->rport_list) {
        mcast_xbundle = xbundle_lookup(ctx->xcfg, rport->port);
        if (mcast_xbundle
            && mcast_xbundle != in_xbundle
            && mcast_xbundle->ofbundle != in_xbundle->ofbundle) {
            xlate_report(ctx, OFT_DETAIL,
                         "forwarding report to mcast flagged port");
            output_normal(ctx, mcast_xbundle, xvlan);
        } else if (!mcast_xbundle) {
            xlate_report(ctx, OFT_WARN,
                         "mcast port is unknown, dropping the report");
        } else {
            xlate_report(ctx, OFT_DETAIL,
                         "mcast port is input port, dropping the Report");
        }
    }
}

static void
xlate_normal_flood(struct xlate_ctx *ctx, struct xbundle *in_xbundle,
                   struct xvlan *xvlan)
{
    struct xbundle *xbundle;

    LIST_FOR_EACH (xbundle, list_node, &ctx->xbridge->xbundles) {
        if (xbundle != in_xbundle
            && xbundle->ofbundle != in_xbundle->ofbundle
            && xbundle_includes_vlan(xbundle, xvlan)
            && xbundle->floodable
            && !xbundle_mirror_out(ctx->xbridge, xbundle)) {
            output_normal(ctx, xbundle, xvlan);
        }
    }
    ctx->nf_output_iface = NF_OUT_FLOOD;
}

static bool
is_ip_local_multicast(const struct flow *flow, struct flow_wildcards *wc)
{
    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
        return ip_is_local_multicast(flow->nw_dst);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
        return ipv6_is_all_hosts(&flow->ipv6_dst);
    } else {
        return false;
    }
}

static void
xlate_normal(struct xlate_ctx *ctx)
{
    struct flow_wildcards *wc = ctx->wc;
    struct flow *flow = &ctx->xin->flow;
    struct xbundle *in_xbundle;
    struct xport *in_port;
    struct mac_entry *mac;
    void *mac_port;
    struct xvlan in_xvlan;
    struct xvlan xvlan;
    uint16_t vlan;

    memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
    wc->masks.vlans[0].tci |= htons(VLAN_VID_MASK | VLAN_CFI);

    in_xbundle = lookup_input_bundle(ctx, flow->in_port.ofp_port, &in_port);
    if (!in_xbundle) {
        xlate_report(ctx, OFT_WARN, "no input bundle, dropping");
        return;
    }

    /* Drop malformed frames. */
    if (eth_type_vlan(flow->dl_type) &&
        !(flow->vlans[0].tci & htons(VLAN_CFI))) {
        if (ctx->xin->packet != NULL) {
            xlate_report_error(ctx, "dropping packet with partial "
                               "VLAN tag received on port %s",
                               in_xbundle->name);
        }
        xlate_report(ctx, OFT_WARN, "partial VLAN tag, dropping");
        return;
    }

    /* Drop frames on bundles reserved for mirroring. */
    if (xbundle_mirror_out(ctx->xbridge, in_xbundle)) {
        if (ctx->xin->packet != NULL) {
            xlate_report_error(ctx, "dropping packet received on port %s, "
                               "which is reserved exclusively for mirroring",
                               in_xbundle->name);
        }
        xlate_report(ctx, OFT_WARN,
                     "input port is mirror output port, dropping");
        return;
    }

    /* Check VLAN. */
    xvlan_extract(flow, &in_xvlan);
    if (!input_vid_is_valid(ctx, in_xvlan.v[0].vid, in_xbundle)) {
        xlate_report(ctx, OFT_WARN,
                     "disallowed VLAN VID for this input port, dropping");
        return;
    }
    xvlan_input_translate(in_xbundle, &in_xvlan, &xvlan);
    vlan = xvlan.v[0].vid;

    /* Check other admissibility requirements. */
    if (in_port && !is_admissible(ctx, in_port, vlan)) {
        return;
    }

    /* Learn source MAC. */
    bool is_grat_arp = is_gratuitous_arp(flow, wc);
    if (ctx->xin->allow_side_effects
        && flow->packet_type == htonl(PT_ETH)
        && in_port->pt_mode != NETDEV_PT_LEGACY_L3
    ) {
        update_learning_table(ctx, in_xbundle, flow->dl_src, vlan,
                              is_grat_arp);
    }
    if (ctx->xin->xcache && in_xbundle != &ofpp_none_bundle) {
        struct xc_entry *entry;

        /* Save just enough info to update mac learning table later. */
        entry = xlate_cache_add_entry(ctx->xin->xcache, XC_NORMAL);
        entry->normal.ofproto = ctx->xbridge->ofproto;
        entry->normal.in_port = flow->in_port.ofp_port;
        entry->normal.dl_src = flow->dl_src;
        entry->normal.vlan = vlan;
        entry->normal.is_gratuitous_arp = is_grat_arp;
    }

    /* Determine output bundle. */
    if (mcast_snooping_enabled(ctx->xbridge->ms)
        && !eth_addr_is_broadcast(flow->dl_dst)
        && eth_addr_is_multicast(flow->dl_dst)
        && is_ip_any(flow)) {
        struct mcast_snooping *ms = ctx->xbridge->ms;
        struct mcast_group *grp = NULL;

        if (is_igmp(flow, wc)) {
            /*
             * IGMP packets need to take the slow path, in order to be
             * processed for mdb updates. That will prevent expires
             * firing off even after hosts have sent reports.
             */
            ctx->xout->slow |= SLOW_ACTION;

            memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
            if (mcast_snooping_is_membership(flow->tp_src) ||
                mcast_snooping_is_query(flow->tp_src)) {
                if (ctx->xin->allow_side_effects && ctx->xin->packet) {
                    update_mcast_snooping_table(ctx, flow, vlan,
                                                in_xbundle, ctx->xin->packet);
                }
            }

            if (mcast_snooping_is_membership(flow->tp_src)) {
                ovs_rwlock_rdlock(&ms->rwlock);
                xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, &xvlan);
                /* RFC4541: section 2.1.1, item 1: A snooping switch should
                 * forward IGMP Membership Reports only to those ports where
                 * multicast routers are attached.  Alternatively stated: a
                 * snooping switch should not forward IGMP Membership Reports
                 * to ports on which only hosts are attached.
                 * An administrative control may be provided to override this
                 * restriction, allowing the report messages to be flooded to
                 * other ports. */
                xlate_normal_mcast_send_rports(ctx, ms, in_xbundle, &xvlan);
                ovs_rwlock_unlock(&ms->rwlock);
            } else {
                xlate_report(ctx, OFT_DETAIL, "multicast traffic, flooding");
                xlate_normal_flood(ctx, in_xbundle, &xvlan);
            }
            return;
        } else if (is_mld(flow, wc)) {
            ctx->xout->slow |= SLOW_ACTION;
            if (ctx->xin->allow_side_effects && ctx->xin->packet) {
                update_mcast_snooping_table(ctx, flow, vlan,
                                            in_xbundle, ctx->xin->packet);
            }
            if (is_mld_report(flow, wc)) {
                ovs_rwlock_rdlock(&ms->rwlock);
                xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, &xvlan);
                xlate_normal_mcast_send_rports(ctx, ms, in_xbundle, &xvlan);
                ovs_rwlock_unlock(&ms->rwlock);
            } else {
                xlate_report(ctx, OFT_DETAIL, "MLD query, flooding");
                xlate_normal_flood(ctx, in_xbundle, &xvlan);
            }
        } else {
            if (is_ip_local_multicast(flow, wc)) {
                /* RFC4541: section 2.1.2, item 2: Packets with a dst IP
                 * address in the 224.0.0.x range which are not IGMP must
                 * be forwarded on all ports */
                xlate_report(ctx, OFT_DETAIL,
                             "RFC4541: section 2.1.2, item 2, flooding");
                xlate_normal_flood(ctx, in_xbundle, &xvlan);
                return;
            }
        }

        /* forwarding to group base ports */
        ovs_rwlock_rdlock(&ms->rwlock);
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            grp = mcast_snooping_lookup4(ms, flow->nw_dst, vlan);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            grp = mcast_snooping_lookup(ms, &flow->ipv6_dst, vlan);
        }
        if (grp) {
            xlate_normal_mcast_send_group(ctx, ms, grp, in_xbundle, &xvlan);
            xlate_normal_mcast_send_fports(ctx, ms, in_xbundle, &xvlan);
            xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, &xvlan);
        } else {
            if (mcast_snooping_flood_unreg(ms)) {
                xlate_report(ctx, OFT_DETAIL,
                             "unregistered multicast, flooding");
                xlate_normal_flood(ctx, in_xbundle, &xvlan);
            } else {
                xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, &xvlan);
                xlate_normal_mcast_send_fports(ctx, ms, in_xbundle, &xvlan);
            }
        }
        ovs_rwlock_unlock(&ms->rwlock);
    } else {
        ovs_rwlock_rdlock(&ctx->xbridge->ml->rwlock);
        mac = mac_learning_lookup(ctx->xbridge->ml, flow->dl_dst, vlan);
        mac_port = mac ? mac_entry_get_port(ctx->xbridge->ml, mac) : NULL;
        ovs_rwlock_unlock(&ctx->xbridge->ml->rwlock);

        if (mac_port) {
            struct xbundle *mac_xbundle = xbundle_lookup(ctx->xcfg, mac_port);
            if (mac_xbundle
                && mac_xbundle != in_xbundle
                && mac_xbundle->ofbundle != in_xbundle->ofbundle) {
                xlate_report(ctx, OFT_DETAIL, "forwarding to learned port");
                output_normal(ctx, mac_xbundle, &xvlan);
            } else if (!mac_xbundle) {
                xlate_report(ctx, OFT_WARN,
                             "learned port is unknown, dropping");
            } else {
                xlate_report(ctx, OFT_DETAIL,
                             "learned port is input port, dropping");
            }
        } else {
            xlate_report(ctx, OFT_DETAIL,
                         "no learned MAC for destination, flooding");
            xlate_normal_flood(ctx, in_xbundle, &xvlan);
        }
    }
}

/* Appends a "sample" action for sFlow or IPFIX to 'ctx->odp_actions'.  The
 * 'probability' is the number of packets out of UINT32_MAX to sample.  The
 * 'cookie' is passed back in the callback for each sampled packet.
 * 'tunnel_out_port', if not ODPP_NONE, is added as the
 * OVS_USERSPACE_ATTR_EGRESS_TUN_PORT attribute.  If 'include_actions',
 * an OVS_USERSPACE_ATTR_ACTIONS attribute is added.  If
 * 'emit_set_tunnel', sample(sampling_port=1) would translate into
 * datapath sample action set(tunnel(...)), sample(...) and it is used
 * for sampling egress tunnel information.
 */
static size_t
compose_sample_action(struct xlate_ctx *ctx,
                      const uint32_t probability,
                      const struct user_action_cookie *cookie,
                      const odp_port_t tunnel_out_port,
                      bool include_actions)
{
    if (probability == 0) {
        /* No need to generate sampling or the inner action. */
        return 0;
    }

    /* If the slow path meter is configured by the controller,
     * insert a meter action before the user space action.  */
    struct ofproto *ofproto = &ctx->xin->ofproto->up;
    uint32_t meter_id = ofproto->slowpath_meter_id;

    /* When meter action is not required, avoid generate sample action
     * for 100% sampling rate.  */
    bool is_sample = probability < UINT32_MAX || meter_id != UINT32_MAX;
    size_t sample_offset, actions_offset;
    if (is_sample) {
        sample_offset = nl_msg_start_nested(ctx->odp_actions,
                                            OVS_ACTION_ATTR_SAMPLE);
        nl_msg_put_u32(ctx->odp_actions, OVS_SAMPLE_ATTR_PROBABILITY,
                       probability);
        actions_offset = nl_msg_start_nested(ctx->odp_actions,
                                             OVS_SAMPLE_ATTR_ACTIONS);
    }

    if (meter_id != UINT32_MAX) {
        nl_msg_put_u32(ctx->odp_actions, OVS_ACTION_ATTR_METER, meter_id);
    }

    odp_port_t odp_port = ofp_port_to_odp_port(
        ctx->xbridge, ctx->xin->flow.in_port.ofp_port);
    uint32_t pid = dpif_port_get_pid(ctx->xbridge->dpif, odp_port,
                                     flow_hash_5tuple(&ctx->xin->flow, 0));
    size_t cookie_offset = odp_put_userspace_action(pid, cookie,
                                                    sizeof *cookie,
                                                    tunnel_out_port,
                                                    include_actions,
                                                    ctx->odp_actions);

    if (is_sample) {
        nl_msg_end_nested(ctx->odp_actions, actions_offset);
        nl_msg_end_nested(ctx->odp_actions, sample_offset);
    }

    return cookie_offset;
}

/* If sFLow is not enabled, returns 0 without doing anything.
 *
 * If sFlow is enabled, appends a template "sample" action to the ODP actions
 * in 'ctx'.  This action is a template because some of the information needed
 * to fill it out is not available until flow translation is complete.  In this
 * case, this functions returns an offset, which is always nonzero, to pass
 * later to fix_sflow_action() to fill in the rest of the template. */
static size_t
compose_sflow_action(struct xlate_ctx *ctx)
{
    struct dpif_sflow *sflow = ctx->xbridge->sflow;
    if (!sflow || ctx->xin->flow.in_port.ofp_port == OFPP_NONE) {
        return 0;
    }

    struct user_action_cookie cookie = {
        .type = USER_ACTION_COOKIE_SFLOW,
        .ofp_in_port = ctx->xin->flow.in_port.ofp_port,
        .ofproto_uuid = ctx->xbridge->ofproto->uuid
    };
    return compose_sample_action(ctx, dpif_sflow_get_probability(sflow),
                                 &cookie, ODPP_NONE, true);
}

/* If flow IPFIX is enabled, make sure IPFIX flow sample action
 * at egress point of tunnel port is just in front of corresponding
 * output action. If bridge IPFIX is enabled, this appends an IPFIX
 * sample action to 'ctx->odp_actions'. */
static void
compose_ipfix_action(struct xlate_ctx *ctx, odp_port_t output_odp_port)
{
    struct dpif_ipfix *ipfix = ctx->xbridge->ipfix;
    odp_port_t tunnel_out_port = ODPP_NONE;

    if (!ipfix || ctx->xin->flow.in_port.ofp_port == OFPP_NONE) {
        return;
    }

    /* For input case, output_odp_port is ODPP_NONE, which is an invalid port
     * number. */
    if (output_odp_port == ODPP_NONE &&
        !dpif_ipfix_get_bridge_exporter_input_sampling(ipfix)) {
        return;
    }

    /* For output case, output_odp_port is valid. */
    if (output_odp_port != ODPP_NONE) {
        if (!dpif_ipfix_get_bridge_exporter_output_sampling(ipfix)) {
            return;
        }
        /* If tunnel sampling is enabled, put an additional option attribute:
         * OVS_USERSPACE_ATTR_TUNNEL_OUT_PORT
         */
        if (dpif_ipfix_get_bridge_exporter_tunnel_sampling(ipfix) &&
            dpif_ipfix_is_tunnel_port(ipfix, output_odp_port) ) {
           tunnel_out_port = output_odp_port;
        }
    }

    struct user_action_cookie cookie = {
        .type = USER_ACTION_COOKIE_IPFIX,
        .ofp_in_port = ctx->xin->flow.in_port.ofp_port,
        .ofproto_uuid = ctx->xbridge->ofproto->uuid,
        .ipfix.output_odp_port = output_odp_port
    };
    compose_sample_action(ctx,
                          dpif_ipfix_get_bridge_exporter_probability(ipfix),
                          &cookie, tunnel_out_port, false);
}

/* Fix "sample" action according to data collected while composing ODP actions,
 * as described in compose_sflow_action().
 *
 * 'user_cookie_offset' must be the offset returned by
 * compose_sflow_action(). */
static void
fix_sflow_action(struct xlate_ctx *ctx, unsigned int user_cookie_offset)
{
    const struct flow *base = &ctx->base_flow;
    struct user_action_cookie *cookie;

    cookie = ofpbuf_at(ctx->odp_actions, user_cookie_offset, sizeof *cookie);
    ovs_assert(cookie->type == USER_ACTION_COOKIE_SFLOW);

    cookie->sflow.vlan_tci = base->vlans[0].tci;

    /* See http://www.sflow.org/sflow_version_5.txt (search for "Input/output
     * port information") for the interpretation of cookie->output. */
    switch (ctx->sflow_n_outputs) {
    case 0:
        /* 0x40000000 | 256 means "packet dropped for unknown reason". */
        cookie->sflow.output = 0x40000000 | 256;
        break;

    case 1:
        cookie->sflow.output = dpif_sflow_odp_port_to_ifindex(
            ctx->xbridge->sflow, ctx->sflow_odp_port);
        if (cookie->sflow.output) {
            break;
        }
        /* Fall through. */
    default:
        /* 0x80000000 means "multiple output ports. */
        cookie->sflow.output = 0x80000000 | ctx->sflow_n_outputs;
        break;
    }
}

static bool
process_special(struct xlate_ctx *ctx, const struct xport *xport)
{
    const struct flow *flow = &ctx->xin->flow;
    struct flow_wildcards *wc = ctx->wc;
    const struct xbridge *xbridge = ctx->xbridge;
    const struct dp_packet *packet = ctx->xin->packet;
    enum slow_path_reason slow;

    if (!xport) {
        slow = 0;
    } else if (xport->cfm && cfm_should_process_flow(xport->cfm, flow, wc)) {
        if (packet) {
            cfm_process_heartbeat(xport->cfm, packet);
        }
        slow = SLOW_CFM;
    } else if (xport->bfd && bfd_should_process_flow(xport->bfd, flow, wc)) {
        if (packet) {
            bfd_process_packet(xport->bfd, flow, packet);
            /* If POLL received, immediately sends FINAL back. */
            if (bfd_should_send_packet(xport->bfd)) {
                ofproto_dpif_monitor_port_send_soon(xport->ofport);
            }
        }
        slow = SLOW_BFD;
    } else if (xport->xbundle && xport->xbundle->lacp
               && flow->dl_type == htons(ETH_TYPE_LACP)) {
        if (packet) {
            lacp_process_packet(xport->xbundle->lacp, xport->ofport, packet);
        }
        slow = SLOW_LACP;
    } else if ((xbridge->stp || xbridge->rstp) &&
               stp_should_process_flow(flow, wc)) {
        if (packet) {
            xbridge->stp
                ? stp_process_packet(xport, packet)
                : rstp_process_packet(xport, packet);
        }
        slow = SLOW_STP;
    } else if (xport->lldp && lldp_should_process_flow(xport->lldp, flow)) {
        if (packet) {
            lldp_process_packet(xport->lldp, packet);
        }
        slow = SLOW_LLDP;
    } else {
        slow = 0;
    }

    if (slow) {
        ctx->xout->slow |= slow;
        return true;
    } else {
        return false;
    }
}

static int
tnl_route_lookup_flow(const struct xlate_ctx *ctx,
                      const struct flow *oflow,
                      struct in6_addr *ip, struct in6_addr *src,
                      struct xport **out_port)
{
    char out_dev[IFNAMSIZ];
    struct xbridge *xbridge;
    struct in6_addr gw;
    struct in6_addr dst;

    dst = flow_tnl_dst(&oflow->tunnel);
    if (!ovs_router_lookup(oflow->pkt_mark, &dst, out_dev, src, &gw)) {
        return -ENOENT;
    }

    if (ipv6_addr_is_set(&gw) &&
        (!IN6_IS_ADDR_V4MAPPED(&gw) || in6_addr_get_mapped_ipv4(&gw))) {
        *ip = gw;
    } else {
        *ip = dst;
    }

    HMAP_FOR_EACH (xbridge, hmap_node, &ctx->xcfg->xbridges) {
        if (!strncmp(xbridge->name, out_dev, IFNAMSIZ)) {
            struct xport *port;

            HMAP_FOR_EACH (port, ofp_node, &xbridge->xports) {
                if (!strncmp(netdev_get_name(port->netdev), out_dev, IFNAMSIZ)) {
                    *out_port = port;
                    return 0;
                }
            }
        }
    }
    return -ENOENT;
}

static int
compose_table_xlate(struct xlate_ctx *ctx, const struct xport *out_dev,
                    struct dp_packet *packet)
{
    struct xbridge *xbridge = out_dev->xbridge;
    struct ofpact_output output;
    struct flow flow;

    ofpact_init(&output.ofpact, OFPACT_OUTPUT, sizeof output);
    flow_extract(packet, &flow);
    flow.in_port.ofp_port = out_dev->ofp_port;
    output.port = OFPP_TABLE;
    output.max_len = 0;

    return ofproto_dpif_execute_actions__(xbridge->ofproto,
                                          ctx->xin->tables_version, &flow,
                                          NULL, &output.ofpact, sizeof output,
                                          ctx->depth, ctx->resubmits, packet);
}

static void
tnl_send_nd_request(struct xlate_ctx *ctx, const struct xport *out_dev,
                     const struct eth_addr eth_src,
                     struct in6_addr * ipv6_src, struct in6_addr * ipv6_dst)
{
    struct dp_packet packet;

    dp_packet_init(&packet, 0);
    compose_nd_ns(&packet, eth_src, ipv6_src, ipv6_dst);
    compose_table_xlate(ctx, out_dev, &packet);
    dp_packet_uninit(&packet);
}

static void
tnl_send_arp_request(struct xlate_ctx *ctx, const struct xport *out_dev,
                     const struct eth_addr eth_src,
                     ovs_be32 ip_src, ovs_be32 ip_dst)
{
    struct dp_packet packet;

    dp_packet_init(&packet, 0);
    compose_arp(&packet, ARP_OP_REQUEST,
                eth_src, eth_addr_zero, true, ip_src, ip_dst);

    compose_table_xlate(ctx, out_dev, &packet);
    dp_packet_uninit(&packet);
}

static void
propagate_tunnel_data_to_flow__(struct flow *dst_flow,
                                const struct flow *src_flow,
                                struct eth_addr dmac, struct eth_addr smac,
                                struct in6_addr s_ip6, ovs_be32 s_ip,
                                bool is_tnl_ipv6, uint8_t nw_proto)
{
    dst_flow->dl_dst = dmac;
    dst_flow->dl_src = smac;

    dst_flow->packet_type = htonl(PT_ETH);
    dst_flow->nw_dst = src_flow->tunnel.ip_dst;
    dst_flow->nw_src = src_flow->tunnel.ip_src;
    dst_flow->ipv6_dst = src_flow->tunnel.ipv6_dst;
    dst_flow->ipv6_src = src_flow->tunnel.ipv6_src;

    dst_flow->nw_frag = 0; /* Tunnel packets are unfragmented. */
    dst_flow->nw_tos = src_flow->tunnel.ip_tos;
    dst_flow->nw_ttl = src_flow->tunnel.ip_ttl;
    dst_flow->tp_dst = src_flow->tunnel.tp_dst;
    dst_flow->tp_src = src_flow->tunnel.tp_src;

    if (is_tnl_ipv6) {
        dst_flow->dl_type = htons(ETH_TYPE_IPV6);
        if (ipv6_mask_is_any(&dst_flow->ipv6_src)
            && !ipv6_mask_is_any(&s_ip6)) {
            dst_flow->ipv6_src = s_ip6;
        }
    } else {
        dst_flow->dl_type = htons(ETH_TYPE_IP);
        if (dst_flow->nw_src == 0 && s_ip) {
            dst_flow->nw_src = s_ip;
        }
    }
    dst_flow->nw_proto = nw_proto;
}

/*
 * Populate the 'flow' and 'base_flow' L3 fields to do the post tunnel push
 * translations.
 */
static void
propagate_tunnel_data_to_flow(struct xlate_ctx *ctx, struct eth_addr dmac,
                              struct eth_addr smac,   struct in6_addr s_ip6,
                              ovs_be32 s_ip, bool is_tnl_ipv6,
                              enum ovs_vport_type tnl_type)
{
    struct flow *base_flow, *flow;
    flow = &ctx->xin->flow;
    base_flow = &ctx->base_flow;
    uint8_t nw_proto = 0;

    switch (tnl_type) {
    case OVS_VPORT_TYPE_GRE:
        nw_proto = IPPROTO_GRE;
        break;
    case OVS_VPORT_TYPE_VXLAN:
    case OVS_VPORT_TYPE_GENEVE:
        nw_proto = IPPROTO_UDP;
        break;
    case OVS_VPORT_TYPE_LISP:
    case OVS_VPORT_TYPE_STT:
    case OVS_VPORT_TYPE_UNSPEC:
    case OVS_VPORT_TYPE_NETDEV:
    case OVS_VPORT_TYPE_INTERNAL:
    case __OVS_VPORT_TYPE_MAX:
    default:
        OVS_NOT_REACHED();
    }
    /*
     * Update base_flow first followed by flow as the dst_flow gets modified
     * in the function.
     */
    propagate_tunnel_data_to_flow__(base_flow, flow, dmac, smac, s_ip6, s_ip,
                                    is_tnl_ipv6, nw_proto);
    propagate_tunnel_data_to_flow__(flow, flow, dmac, smac, s_ip6, s_ip,
                                    is_tnl_ipv6, nw_proto);
}

static int
native_tunnel_output(struct xlate_ctx *ctx, const struct xport *xport,
                     const struct flow *flow, odp_port_t tunnel_odp_port,
                     bool truncate)
{
    struct netdev_tnl_build_header_params tnl_params;
    struct ovs_action_push_tnl tnl_push_data;
    struct xport *out_dev = NULL;
    ovs_be32 s_ip = 0, d_ip = 0;
    struct in6_addr s_ip6 = in6addr_any;
    struct in6_addr d_ip6 = in6addr_any;
    struct eth_addr smac;
    struct eth_addr dmac;
    int err;
    char buf_sip6[INET6_ADDRSTRLEN];
    char buf_dip6[INET6_ADDRSTRLEN];

    /* Store sFlow data. */
    uint32_t sflow_n_outputs = ctx->sflow_n_outputs;

    /* Structures to backup Ethernet and IP of base_flow. */
    struct flow old_base_flow;
    struct flow old_flow;

    /* Backup flow & base_flow data. */
    memcpy(&old_base_flow, &ctx->base_flow, sizeof old_base_flow);
    memcpy(&old_flow, &ctx->xin->flow, sizeof old_flow);
	
    if (flow->tunnel.ip_src) {
        in6_addr_set_mapped_ipv4(&s_ip6, flow->tunnel.ip_src);
    }

    err = tnl_route_lookup_flow(ctx, flow, &d_ip6, &s_ip6, &out_dev);
    if (err) {
        xlate_report(ctx, OFT_WARN, "native tunnel routing failed");
        return err;
    }

    xlate_report(ctx, OFT_DETAIL, "tunneling to %s via %s",
                 ipv6_string_mapped(buf_dip6, &d_ip6),
                 netdev_get_name(out_dev->netdev));

    /* Use mac addr of bridge port of the peer. */
    err = netdev_get_etheraddr(out_dev->netdev, &smac);
    if (err) {
        xlate_report(ctx, OFT_WARN,
                     "tunnel output device lacks Ethernet address");
        return err;
    }

    d_ip = in6_addr_get_mapped_ipv4(&d_ip6);
    if (d_ip) {
        s_ip = in6_addr_get_mapped_ipv4(&s_ip6);
    }

    err = tnl_neigh_lookup(out_dev->xbridge->name, &d_ip6, &dmac);
    if (err) {
        xlate_report(ctx, OFT_DETAIL,
                     "neighbor cache miss for %s on bridge %s, "
                     "sending %s request",
                     buf_dip6, out_dev->xbridge->name, d_ip ? "ARP" : "ND");
        if (d_ip) {
            tnl_send_arp_request(ctx, out_dev, smac, s_ip, d_ip);
        } else {
            tnl_send_nd_request(ctx, out_dev, smac, &s_ip6, &d_ip6);
        }
        return err;
    }

    if (ctx->xin->xcache) {
        struct xc_entry *entry;

        entry = xlate_cache_add_entry(ctx->xin->xcache, XC_TNL_NEIGH);
        ovs_strlcpy(entry->tnl_neigh_cache.br_name, out_dev->xbridge->name,
                    sizeof entry->tnl_neigh_cache.br_name);
        entry->tnl_neigh_cache.d_ipv6 = d_ip6;
    }

    xlate_report(ctx, OFT_DETAIL, "tunneling from "ETH_ADDR_FMT" %s"
                 " to "ETH_ADDR_FMT" %s",
                 ETH_ADDR_ARGS(smac), ipv6_string_mapped(buf_sip6, &s_ip6),
                 ETH_ADDR_ARGS(dmac), buf_dip6);

    netdev_init_tnl_build_header_params(&tnl_params, flow, &s_ip6, dmac, smac);
    err = tnl_port_build_header(xport->ofport, &tnl_push_data, &tnl_params);
    if (err) {
        return err;
    }
    tnl_push_data.tnl_port = tunnel_odp_port;
    tnl_push_data.out_port = out_dev->odp_port;

    /* After tunnel header has been added, MAC and IP data of flow and
     * base_flow need to be set properly, since there is not recirculation
     * any more when sending packet to tunnel. */

    propagate_tunnel_data_to_flow(ctx, dmac, smac, s_ip6,
                                  s_ip, tnl_params.is_ipv6,
                                  tnl_push_data.tnl_type);

    size_t clone_ofs = 0;
    size_t push_action_size;

    clone_ofs = nl_msg_start_nested(ctx->odp_actions, OVS_ACTION_ATTR_CLONE);
    odp_put_tnl_push_action(ctx->odp_actions, &tnl_push_data);
    push_action_size = ctx->odp_actions->size;

    if (!truncate) {
        const struct dpif_flow_stats *backup_resubmit_stats;
        struct xlate_cache *backup_xcache;
        struct flow_wildcards *backup_wc, wc;
        bool backup_side_effects;
        const struct dp_packet *backup_packet;

        memset(&wc, 0 , sizeof wc);
        backup_wc = ctx->wc;
        ctx->wc = &wc;
        ctx->xin->wc = NULL;
        backup_resubmit_stats = ctx->xin->resubmit_stats;
        backup_xcache = ctx->xin->xcache;
        backup_side_effects = ctx->xin->allow_side_effects;
        backup_packet = ctx->xin->packet;

        ctx->xin->resubmit_stats =  NULL;
        ctx->xin->xcache = xlate_cache_new(); /* Use new temporary cache. */
        ctx->xin->allow_side_effects = false;
        ctx->xin->packet = NULL;

        /* Push the cache entry for the tunnel first. */
        struct xc_entry *entry;
        entry = xlate_cache_add_entry(ctx->xin->xcache, XC_TUNNEL_HEADER);
        entry->tunnel_hdr.hdr_size = tnl_push_data.header_len;
        entry->tunnel_hdr.operation = ADD;

        patch_port_output(ctx, xport, out_dev);

        /* Similar to the stats update in revalidation, the x_cache entries
         * are populated by the previous translation are used to update the
         * stats correctly.
         */
        if (backup_resubmit_stats) {
            struct dpif_flow_stats stats = *backup_resubmit_stats;
            xlate_push_stats(ctx->xin->xcache, &stats);
        }
        xlate_cache_steal_entries(backup_xcache, ctx->xin->xcache);

        if (ctx->odp_actions->size > push_action_size) {
            nl_msg_end_non_empty_nested(ctx->odp_actions, clone_ofs);
        } else {
            nl_msg_cancel_nested(ctx->odp_actions, clone_ofs);
            /* XXX : There is no real use-case for a tunnel push without
             * any post actions. However keeping it now
             * as is to make the 'make check' happy. Should remove when all the
             * make check tunnel test case does something meaningful on a
             * tunnel encap packets.
             */
            odp_put_tnl_push_action(ctx->odp_actions, &tnl_push_data);
        }

        /* Restore context status. */
        ctx->xin->resubmit_stats = backup_resubmit_stats;
        xlate_cache_delete(ctx->xin->xcache);
        ctx->xin->xcache = backup_xcache;
        ctx->xin->allow_side_effects = backup_side_effects;
        ctx->xin->packet = backup_packet;
        ctx->wc = backup_wc;
    } else {
        /* In order to maintain accurate stats, use recirc for
         * natvie tunneling.  */
        nl_msg_put_u32(ctx->odp_actions, OVS_ACTION_ATTR_RECIRC, 0);
        nl_msg_end_nested(ctx->odp_actions, clone_ofs);
    }

    /* Restore the flows after the translation. */
    memcpy(&ctx->xin->flow, &old_flow, sizeof ctx->xin->flow);
    memcpy(&ctx->base_flow, &old_base_flow, sizeof ctx->base_flow);

    /* Restore sFlow data. */
    ctx->sflow_n_outputs = sflow_n_outputs;

    return 0;
}

static void
xlate_commit_actions(struct xlate_ctx *ctx)
{
    bool use_masked = ctx->xbridge->support.masked_set_action;

    ctx->xout->slow |= commit_odp_actions(&ctx->xin->flow, &ctx->base_flow,
                                          ctx->odp_actions, ctx->wc,
                                          use_masked, ctx->pending_encap,
                                          ctx->pending_decap, ctx->encap_data);
    ctx->pending_encap = false;
    ctx->pending_decap = false;
    ofpbuf_delete(ctx->encap_data);
    ctx->encap_data = NULL;
}

static void
clear_conntrack(struct xlate_ctx *ctx)
{
    ctx->conntracked = false;
    flow_clear_conntrack(&ctx->xin->flow);
}

static bool
xlate_flow_is_protected(const struct xlate_ctx *ctx, const struct flow *flow, const struct xport *xport_out)
{
    const struct xport *xport_in;

    if (!xport_out) {
        return false;
    }

    xport_in = get_ofp_port(ctx->xbridge, flow->in_port.ofp_port);

    return (xport_in && xport_in->xbundle && xport_out->xbundle &&
            xport_in->xbundle->protected && xport_out->xbundle->protected);
}

/* Function handles when a packet is sent from one bridge to another bridge.
 *
 * The bridges are internally connected, either with patch ports or with
 * tunnel ports.
 *
 * The output action to another bridge causes translation to continue within
 * the next bridge. This process can be recursive; the next bridge can
 * output yet to another bridge.
 *
 * The translated actions from the second bridge onwards are enclosed within
 * the clone action, so that any modification to the packet will not be visible
 * to the remaining actions of the originating bridge.
 */
static void
patch_port_output(struct xlate_ctx *ctx, const struct xport *in_dev,
                  struct xport *out_dev)
{
    struct flow *flow = &ctx->xin->flow;
    struct flow old_flow = ctx->xin->flow;
    struct flow_tnl old_flow_tnl_wc = ctx->wc->masks.tunnel;
    bool old_conntrack = ctx->conntracked;
    bool old_was_mpls = ctx->was_mpls;
    ovs_version_t old_version = ctx->xin->tables_version;
    struct ofpbuf old_stack = ctx->stack;
    uint8_t new_stack[1024];
    struct ofpbuf old_action_set = ctx->action_set;
    struct ovs_list *old_trace = ctx->xin->trace;
    uint64_t actset_stub[1024 / 8];

    ofpbuf_use_stub(&ctx->stack, new_stack, sizeof new_stack);
    ofpbuf_use_stub(&ctx->action_set, actset_stub, sizeof actset_stub);
    flow->in_port.ofp_port = out_dev->ofp_port;
    flow->metadata = htonll(0);
    memset(&flow->tunnel, 0, sizeof flow->tunnel);
    memset(&ctx->wc->masks.tunnel, 0, sizeof ctx->wc->masks.tunnel);
    flow->tunnel.metadata.tab =
                           ofproto_get_tun_tab(&out_dev->xbridge->ofproto->up);
    ctx->wc->masks.tunnel.metadata.tab = flow->tunnel.metadata.tab;
    memset(flow->regs, 0, sizeof flow->regs);
    flow->actset_output = OFPP_UNSET;
    clear_conntrack(ctx);
    ctx->xin->trace = xlate_report(ctx, OFT_BRIDGE, "bridge(\"%s\")",
                                   out_dev->xbridge->name);
    mirror_mask_t old_mirrors = ctx->mirrors;
    bool independent_mirrors = out_dev->xbridge != ctx->xbridge;
    if (independent_mirrors) {
        ctx->mirrors = 0;
    }
    ctx->xbridge = out_dev->xbridge;

    /* The bridge is now known so obtain its table version. */
    ctx->xin->tables_version
              = ofproto_dpif_get_tables_version(ctx->xbridge->ofproto);

    if (!process_special(ctx, out_dev) && may_receive(out_dev, ctx)) {
        if (xport_stp_forward_state(out_dev) &&
            xport_rstp_forward_state(out_dev)) {
            xlate_table_action(ctx, flow->in_port.ofp_port, 0, true, true,
                               false, true, clone_xlate_actions);
            if (!ctx->freezing) {
                xlate_action_set(ctx);
            }
            if (ctx->freezing) {
                finish_freezing(ctx);
            }
        } else {
            /* Forwarding is disabled by STP and RSTP.  Let OFPP_NORMAL and
             * the learning action look at the packet, then drop it. */
            struct flow old_base_flow = ctx->base_flow;
            size_t old_size = ctx->odp_actions->size;
            mirror_mask_t old_mirrors2 = ctx->mirrors;

            xlate_table_action(ctx, flow->in_port.ofp_port, 0, true, true,
                               false, true, clone_xlate_actions);
            ctx->mirrors = old_mirrors2;
            ctx->base_flow = old_base_flow;
            ctx->odp_actions->size = old_size;

            /* Undo changes that may have been done for freezing. */
            ctx_cancel_freeze(ctx);
        }
    }

    ctx->xin->trace = old_trace;
    if (independent_mirrors) {
        ctx->mirrors = old_mirrors;
    }
    ctx->xin->flow = old_flow;
    ctx->xbridge = in_dev->xbridge;
    ofpbuf_uninit(&ctx->action_set);
    ctx->action_set = old_action_set;
    ofpbuf_uninit(&ctx->stack);
    ctx->stack = old_stack;

    /* Restore calling bridge's lookup version. */
    ctx->xin->tables_version = old_version;

    /* Restore to calling bridge tunneling information */
    ctx->wc->masks.tunnel = old_flow_tnl_wc;

    /* The out bridge popping MPLS should have no effect on the original
     * bridge. */
    ctx->was_mpls = old_was_mpls;

    /* The out bridge's conntrack execution should have no effect on the
     * original bridge. */
    ctx->conntracked = old_conntrack;

    /* The fact that the out bridge exits (for any reason) does not mean
     * that the original bridge should exit.  Specifically, if the out
     * bridge freezes translation, the original bridge must continue
     * processing with the original, not the frozen packet! */
    ctx->exit = false;

    /* Out bridge errors do not propagate back. */
    ctx->error = XLATE_OK;

    if (ctx->xin->resubmit_stats) {
        netdev_vport_inc_tx(in_dev->netdev, ctx->xin->resubmit_stats);
        netdev_vport_inc_rx(out_dev->netdev, ctx->xin->resubmit_stats);
        if (out_dev->bfd) {
            bfd_account_rx(out_dev->bfd, ctx->xin->resubmit_stats);
        }
    }
    if (ctx->xin->xcache) {
        struct xc_entry *entry;

        entry = xlate_cache_add_entry(ctx->xin->xcache, XC_NETDEV);
        entry->dev.tx = netdev_ref(in_dev->netdev);
        entry->dev.rx = netdev_ref(out_dev->netdev);
        entry->dev.bfd = bfd_ref(out_dev->bfd);
    }
}

static bool
check_output_prerequisites(struct xlate_ctx *ctx,
                           const struct xport *xport,
                           struct flow *flow,
                           bool check_stp)
{
    struct flow_wildcards *wc = ctx->wc;

    if (!xport) {
        xlate_report(ctx, OFT_WARN, "Nonexistent output port");
        return false;
    } else if (xport->config & OFPUTIL_PC_NO_FWD) {
        xlate_report(ctx, OFT_DETAIL, "OFPPC_NO_FWD set, skipping output");
        return false;
    } else if (ctx->mirror_snaplen != 0 && xport->odp_port == ODPP_NONE) {
        xlate_report(ctx, OFT_WARN,
                     "Mirror truncate to ODPP_NONE, skipping output");
        return false;
    } else if (xlate_flow_is_protected(ctx, flow, xport)) {
        xlate_report(ctx, OFT_WARN,
                     "Flow is between protected ports, skipping output.");
        return false;
    } else if (check_stp) {
        if (is_stp(&ctx->base_flow)) {
            if (!xport_stp_should_forward_bpdu(xport) &&
                !xport_rstp_should_manage_bpdu(xport)) {
                if (ctx->xbridge->stp != NULL) {
                    xlate_report(ctx, OFT_WARN,
                                 "STP not in listening state, "
                                 "skipping bpdu output");
                } else if (ctx->xbridge->rstp != NULL) {
                    xlate_report(ctx, OFT_WARN,
                                 "RSTP not managing BPDU in this state, "
                                 "skipping bpdu output");
                }
                return false;
            }
        } else if ((xport->cfm && cfm_should_process_flow(xport->cfm, flow, wc))
                   || (xport->bfd && bfd_should_process_flow(xport->bfd, flow,
                                                             wc))) {
            /* Pass; STP should not block link health detection. */
        } else if (!xport_stp_forward_state(xport) ||
                   !xport_rstp_forward_state(xport)) {
            if (ctx->xbridge->stp != NULL) {
                xlate_report(ctx, OFT_WARN,
                             "STP not in forwarding state, skipping output");
            } else if (ctx->xbridge->rstp != NULL) {
                xlate_report(ctx, OFT_WARN,
                             "RSTP not in forwarding state, skipping output");
            }
            return false;
        }
    }

    if (xport->pt_mode == NETDEV_PT_LEGACY_L2 &&
        flow->packet_type != htonl(PT_ETH)) {
        xlate_report(ctx, OFT_WARN, "Trying to send non-Ethernet packet "
                     "through legacy L2 port. Dropping packet.");
        return false;
    }

    return true;
}

/* Function verifies if destination address of received Neighbor Advertisement
 * message stored in 'flow' is correct. It should be either FF02::1:FFXX:XXXX
 * where XX:XXXX stands for the last 24 bits of 'ipv6_addr' or it should match
 * 'ipv6_addr'. */
static bool
is_nd_dst_correct(const struct flow *flow, const struct in6_addr *ipv6_addr)
{
    const uint8_t *flow_ipv6_addr = (uint8_t *) &flow->ipv6_dst;
    const uint8_t *addr = (uint8_t *) ipv6_addr;

    return (IN6_IS_ADDR_MC_LINKLOCAL(flow_ipv6_addr) &&
            flow_ipv6_addr[11] == 0x01 &&
            flow_ipv6_addr[12] == 0xff &&
            flow_ipv6_addr[13] == addr[13] &&
            flow_ipv6_addr[14] == addr[14] &&
            flow_ipv6_addr[15] == addr[15]) ||
            IN6_ARE_ADDR_EQUAL(&flow->ipv6_dst, ipv6_addr);
}

/* Function verifies if the ARP reply or Neighbor Advertisement represented by
 * 'flow' addresses the 'xbridge' of 'ctx'. Returns true if the ARP TA or
 * neighbor discovery destination is in the list of configured IP addresses of
 * the bridge. Otherwise, it returns false. */
static bool
is_neighbor_reply_correct(const struct xlate_ctx *ctx, const struct flow *flow)
{
    bool ret = false;
    int i;
    struct xbridge_addr *xbridge_addr = xbridge_addr_ref(ctx->xbridge->addr);

    /* Verify if 'nw_dst' of ARP or 'ipv6_dst' of ICMPV6 is in the list. */
    for (i = 0; xbridge_addr && i < xbridge_addr->n_addr; i++) {
        struct in6_addr *ip_addr = &xbridge_addr->addr[i];
        if ((IN6_IS_ADDR_V4MAPPED(ip_addr) &&
             flow->dl_type == htons(ETH_TYPE_ARP) &&
             in6_addr_get_mapped_ipv4(ip_addr) == flow->nw_dst) ||
            (!IN6_IS_ADDR_V4MAPPED(ip_addr) &&
              is_nd_dst_correct(flow, ip_addr))) {
            /* Found a match. */
            ret = true;
            break;
        }
    }

    xbridge_addr_unref(xbridge_addr);
    return ret;
}

static bool
terminate_native_tunnel(struct xlate_ctx *ctx, ofp_port_t ofp_port,
                        struct flow *flow, struct flow_wildcards *wc,
                        odp_port_t *tnl_port)
{
    *tnl_port = ODPP_NONE;

    /* XXX: Write better Filter for tunnel port. We can use in_port
     * in tunnel-port flow to avoid these checks completely. */
    if (ofp_port == OFPP_LOCAL &&
        ovs_native_tunneling_is_on(ctx->xbridge->ofproto)) {
        *tnl_port = tnl_port_map_lookup(flow, wc);

        /* If no tunnel port was found and it's about an ARP or ICMPv6 packet,
         * do tunnel neighbor snooping. */
        if (*tnl_port == ODPP_NONE &&
            (flow->dl_type == htons(ETH_TYPE_ARP) ||
             flow->nw_proto == IPPROTO_ICMPV6) &&
             is_neighbor_reply_correct(ctx, flow)) {
            tnl_neigh_snoop(flow, wc, ctx->xbridge->name);
        }
    }

    return *tnl_port != ODPP_NONE;
}

static void
compose_output_action__(struct xlate_ctx *ctx, ofp_port_t ofp_port,
                        const struct xlate_bond_recirc *xr, bool check_stp,
                        bool is_last_action OVS_UNUSED, bool truncate)
{
    const struct xport *xport = get_ofp_port(ctx->xbridge, ofp_port);
    struct flow_wildcards *wc = ctx->wc;
    struct flow *flow = &ctx->xin->flow;
    struct flow_tnl flow_tnl;
    union flow_vlan_hdr flow_vlans[FLOW_MAX_VLAN_HEADERS];
    uint8_t flow_nw_tos;
    odp_port_t out_port, odp_port, odp_tnl_port;
    bool is_native_tunnel = false;
    uint8_t dscp;
    struct eth_addr flow_dl_dst = flow->dl_dst;
    struct eth_addr flow_dl_src = flow->dl_src;
    ovs_be32 flow_packet_type = flow->packet_type;
    ovs_be16 flow_dl_type = flow->dl_type;

    /* If 'struct flow' gets additional metadata, we'll need to zero it out
     * before traversing a patch port. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 40);
    memset(&flow_tnl, 0, sizeof flow_tnl);

    if (!check_output_prerequisites(ctx, xport, flow, check_stp)) {
        return;
    }

    if (flow->packet_type == htonl(PT_ETH)) {
        /* Strip Ethernet header for legacy L3 port. */
        if (xport->pt_mode == NETDEV_PT_LEGACY_L3) {
            flow->packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE,
                                               ntohs(flow->dl_type));
        }
    }

    if (xport->peer) {
       if (truncate) {
           xlate_report_error(ctx, "Cannot truncate output to patch port");
       }
       patch_port_output(ctx, xport, xport->peer);
       return;
    }

    memcpy(flow_vlans, flow->vlans, sizeof flow_vlans);
    flow_nw_tos = flow->nw_tos;

    if (count_skb_priorities(xport)) {
        memset(&wc->masks.skb_priority, 0xff, sizeof wc->masks.skb_priority);
        if (dscp_from_skb_priority(xport, flow->skb_priority, &dscp)) {
            wc->masks.nw_tos |= IP_DSCP_MASK;
            flow->nw_tos &= ~IP_DSCP_MASK;
            flow->nw_tos |= dscp;
        }
    }

    if (xport->is_tunnel) {
        struct in6_addr dst;
         /* Save tunnel metadata so that changes made due to
          * the Logical (tunnel) Port are not visible for any further
          * matches, while explicit set actions on tunnel metadata are.
          */
        flow_tnl = flow->tunnel;
        odp_port = tnl_port_send(xport->ofport, flow, ctx->wc);
        if (odp_port == ODPP_NONE) {
            xlate_report(ctx, OFT_WARN, "Tunneling decided against output");
            goto out; /* restore flow_nw_tos */
        }
        dst = flow_tnl_dst(&flow->tunnel);
        if (ipv6_addr_equals(&dst, &ctx->orig_tunnel_ipv6_dst)) {
            xlate_report(ctx, OFT_WARN, "Not tunneling to our own address");
            goto out; /* restore flow_nw_tos */
        }
        if (ctx->xin->resubmit_stats) {
            netdev_vport_inc_tx(xport->netdev, ctx->xin->resubmit_stats);
        }
        if (ctx->xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx->xin->xcache, XC_NETDEV);
            entry->dev.tx = netdev_ref(xport->netdev);
        }
        out_port = odp_port;
        if (ovs_native_tunneling_is_on(ctx->xbridge->ofproto)) {
            xlate_report(ctx, OFT_DETAIL, "output to native tunnel");
            is_native_tunnel = true;
        } else {
            xlate_report(ctx, OFT_DETAIL, "output to kernel tunnel");
            commit_odp_tunnel_action(flow, &ctx->base_flow, ctx->odp_actions);
            flow->tunnel = flow_tnl; /* Restore tunnel metadata */
        }
    } else {
        odp_port = xport->odp_port;
        out_port = odp_port;
    }

    if (out_port != ODPP_NONE) {
        /* Commit accumulated flow updates before output. */
        xlate_commit_actions(ctx);

        if (xr) {
            /* Recirculate the packet. */
            struct ovs_action_hash *act_hash;

            /* Hash action. */
            act_hash = nl_msg_put_unspec_uninit(ctx->odp_actions,
                                                OVS_ACTION_ATTR_HASH,
                                                sizeof *act_hash);
            act_hash->hash_alg = xr->hash_alg;
            act_hash->hash_basis = xr->hash_basis;

            /* Recirc action. */
            nl_msg_put_u32(ctx->odp_actions, OVS_ACTION_ATTR_RECIRC,
                           xr->recirc_id);
        } else if (is_native_tunnel) {
            /* Output to native tunnel port. */
            native_tunnel_output(ctx, xport, flow, odp_port, truncate);
            flow->tunnel = flow_tnl; /* Restore tunnel metadata */

        } else if (terminate_native_tunnel(ctx, ofp_port, flow, wc,
                                           &odp_tnl_port)) {
            /* Intercept packet to be received on native tunnel port. */
            nl_msg_put_odp_port(ctx->odp_actions, OVS_ACTION_ATTR_TUNNEL_POP,
                                odp_tnl_port);

        } else {
            /* Tunnel push-pop action is not compatible with
             * IPFIX action. */
            compose_ipfix_action(ctx, out_port);

            /* Handle truncation of the mirrored packet. */
            if (ctx->mirror_snaplen > 0 &&
                    ctx->mirror_snaplen < UINT16_MAX) {
                struct ovs_action_trunc *trunc;

                trunc = nl_msg_put_unspec_uninit(ctx->odp_actions,
                                                 OVS_ACTION_ATTR_TRUNC,
                                                 sizeof *trunc);
                trunc->max_len = ctx->mirror_snaplen;
                if (!ctx->xbridge->support.trunc) {
                    ctx->xout->slow |= SLOW_ACTION;
                }
            }

            nl_msg_put_odp_port(ctx->odp_actions,
                                OVS_ACTION_ATTR_OUTPUT,
                                out_port);
        }

        ctx->sflow_odp_port = odp_port;
        ctx->sflow_n_outputs++;
        ctx->nf_output_iface = ofp_port;
    }

    if (mbridge_has_mirrors(ctx->xbridge->mbridge) && xport->xbundle) {
        mirror_packet(ctx, xport->xbundle,
                      xbundle_mirror_dst(xport->xbundle->xbridge,
                                         xport->xbundle));
    }

 out:
    /* Restore flow */
    memcpy(flow->vlans, flow_vlans, sizeof flow->vlans);
    flow->nw_tos = flow_nw_tos;
    flow->dl_dst = flow_dl_dst;
    flow->dl_src = flow_dl_src;
    flow->packet_type = flow_packet_type;
    flow->dl_type = flow_dl_type;
}

static void
compose_output_action(struct xlate_ctx *ctx, ofp_port_t ofp_port,
                      const struct xlate_bond_recirc *xr,
                      bool is_last_action, bool truncate)
{
    compose_output_action__(ctx, ofp_port, xr, true,
                            is_last_action, truncate);
}

static void
xlate_recursively(struct xlate_ctx *ctx, struct rule_dpif *rule,
                  bool deepens, bool is_last_action,
                  xlate_actions_handler *actions_xlator)
{
    struct rule_dpif *old_rule = ctx->rule;
    ovs_be64 old_cookie = ctx->rule_cookie;
    const struct rule_actions *actions;

    if (ctx->xin->resubmit_stats) {
        rule_dpif_credit_stats(rule, ctx->xin->resubmit_stats);
    }

    ctx->resubmits++;

    ctx->depth += deepens;
    ctx->rule = rule;
    ctx->rule_cookie = rule->up.flow_cookie;
    actions = rule_get_actions(&rule->up);
    actions_xlator(actions->ofpacts, actions->ofpacts_len, ctx,
                   is_last_action);
    ctx->rule_cookie = old_cookie;
    ctx->rule = old_rule;
    ctx->depth -= deepens;
}

static bool
xlate_resubmit_resource_check(struct xlate_ctx *ctx)
{
    if (ctx->depth >= MAX_DEPTH) {
        xlate_report_error(ctx, "over max translation depth %d", MAX_DEPTH);
        ctx->error = XLATE_RECURSION_TOO_DEEP;
    } else if (ctx->resubmits >= MAX_RESUBMITS) {
        xlate_report_error(ctx, "over %d resubmit actions", MAX_RESUBMITS);
        ctx->error = XLATE_TOO_MANY_RESUBMITS;
    } else if (ctx->odp_actions->size > UINT16_MAX) {
        xlate_report_error(ctx, "resubmits yielded over 64 kB of actions");
        /* NOT an error, as we'll be slow-pathing the flow in this case? */
        ctx->exit = true; /* XXX: translation still terminated! */
    } else if (ctx->stack.size >= 65536) {
        xlate_report_error(ctx, "resubmits yielded over 64 kB of stack");
        ctx->error = XLATE_STACK_TOO_DEEP;
    } else {
        return true;
    }

    return false;
}

static void
tuple_swap_flow(struct flow *flow, bool ipv4)
{
    uint8_t nw_proto = flow->nw_proto;
    flow->nw_proto = flow->ct_nw_proto;
    flow->ct_nw_proto = nw_proto;

    if (ipv4) {
        ovs_be32 nw_src = flow->nw_src;
        flow->nw_src = flow->ct_nw_src;
        flow->ct_nw_src = nw_src;

        ovs_be32 nw_dst = flow->nw_dst;
        flow->nw_dst = flow->ct_nw_dst;
        flow->ct_nw_dst = nw_dst;
    } else {
        struct in6_addr ipv6_src = flow->ipv6_src;
        flow->ipv6_src = flow->ct_ipv6_src;
        flow->ct_ipv6_src = ipv6_src;

        struct in6_addr ipv6_dst = flow->ipv6_dst;
        flow->ipv6_dst = flow->ct_ipv6_dst;
        flow->ct_ipv6_dst = ipv6_dst;
    }

    ovs_be16 tp_src = flow->tp_src;
    flow->tp_src = flow->ct_tp_src;
    flow->ct_tp_src = tp_src;

    ovs_be16 tp_dst = flow->tp_dst;
    flow->tp_dst = flow->ct_tp_dst;
    flow->ct_tp_dst = tp_dst;
}

static void
tuple_swap(struct flow *flow, struct flow_wildcards *wc)
{
    bool ipv4 = (flow->dl_type == htons(ETH_TYPE_IP));

    tuple_swap_flow(flow, ipv4);
    tuple_swap_flow(&wc->masks, ipv4);
}

static void
xlate_table_action(struct xlate_ctx *ctx, ofp_port_t in_port, uint8_t table_id,
                   bool may_packet_in, bool honor_table_miss,
                   bool with_ct_orig, bool is_last_action,
                   xlate_actions_handler *xlator)
{
    /* Check if we need to recirculate before matching in a table. */
    if (ctx->was_mpls) {
        ctx_trigger_freeze(ctx);
        return;
    }
    if (xlate_resubmit_resource_check(ctx)) {
        uint8_t old_table_id = ctx->table_id;
        struct rule_dpif *rule;

        ctx->table_id = table_id;

        /* Swap packet fields with CT 5-tuple if requested. */
        if (with_ct_orig) {
            /* Do not swap if there is no CT tuple, or if key is not IP. */
            if (ctx->xin->flow.ct_nw_proto == 0 ||
                !is_ip_any(&ctx->xin->flow)) {
                xlate_report_error(ctx,
                                   "resubmit(ct) with non-tracked or non-IP packet!");
                return;
            }
            tuple_swap(&ctx->xin->flow, ctx->wc);
        }
        rule = rule_dpif_lookup_from_table(ctx->xbridge->ofproto,
                                           ctx->xin->tables_version,
                                           &ctx->xin->flow, ctx->wc,
                                           ctx->xin->resubmit_stats,
                                           &ctx->table_id, in_port,
                                           may_packet_in, honor_table_miss,
                                           ctx->xin->xcache);
        /* Swap back. */
        if (with_ct_orig) {
            tuple_swap(&ctx->xin->flow, ctx->wc);
        }

        if (rule) {
            /* Fill in the cache entry here instead of xlate_recursively
             * to make the reference counting more explicit.  We take a
             * reference in the lookups above if we are going to cache the
             * rule. */
            if (ctx->xin->xcache) {
                struct xc_entry *entry;

                entry = xlate_cache_add_entry(ctx->xin->xcache, XC_RULE);
                entry->rule = rule;
                ofproto_rule_ref(&rule->up);
            }

            struct ovs_list *old_trace = ctx->xin->trace;
            xlate_report_table(ctx, rule, table_id);
            xlate_recursively(ctx, rule, table_id <= old_table_id,
                              is_last_action, xlator);
            ctx->xin->trace = old_trace;
        }

        ctx->table_id = old_table_id;
        return;
    }
}

/* Consumes the group reference, which is only taken if xcache exists. */
static void
xlate_group_stats(struct xlate_ctx *ctx, struct group_dpif *group,
                  struct ofputil_bucket *bucket)
{
    if (ctx->xin->resubmit_stats) {
        group_dpif_credit_stats(group, bucket, ctx->xin->resubmit_stats);
    }
    if (ctx->xin->xcache) {
        struct xc_entry *entry;

        entry = xlate_cache_add_entry(ctx->xin->xcache, XC_GROUP);
        entry->group.group = group;
        entry->group.bucket = bucket;
    }
}

static void
xlate_group_bucket(struct xlate_ctx *ctx, struct ofputil_bucket *bucket,
                   bool is_last_action)
{
    uint64_t action_list_stub[1024 / 8];
    struct ofpbuf action_list = OFPBUF_STUB_INITIALIZER(action_list_stub);
    struct ofpbuf action_set = ofpbuf_const_initializer(bucket->ofpacts,
                                                        bucket->ofpacts_len);
    struct flow old_flow = ctx->xin->flow;
    bool old_was_mpls = ctx->was_mpls;

    ofpacts_execute_action_set(&action_list, &action_set);
    ctx->depth++;
    do_xlate_actions(action_list.data, action_list.size, ctx, is_last_action);
    ctx->depth--;

    ofpbuf_uninit(&action_list);

    /* Check if need to freeze. */
    if (ctx->freezing) {
        finish_freezing(ctx);
    }

    /* Roll back flow to previous state.
     * This is equivalent to cloning the packet for each bucket.
     *
     * As a side effect any subsequently applied actions will
     * also effectively be applied to a clone of the packet taken
     * just before applying the all or indirect group.
     *
     * Note that group buckets are action sets, hence they cannot modify the
     * main action set.  Also any stack actions are ignored when executing an
     * action set, so group buckets cannot change the stack either.
     * However, we do allow resubmit actions in group buckets, which could
     * break the above assumptions.  It is up to the controller to not mess up
     * with the action_set and stack in the tables resubmitted to from
     * group buckets. */
    ctx->xin->flow = old_flow;

    /* The group bucket popping MPLS should have no effect after bucket
     * execution. */
    ctx->was_mpls = old_was_mpls;

    /* The fact that the group bucket exits (for any reason) does not mean that
     * the translation after the group action should exit.  Specifically, if
     * the group bucket freezes translation, the actions after the group action
     * must continue processing with the original, not the frozen packet! */
    ctx->exit = false;

    /* Context error in a bucket should not impact processing of other buckets
     * or actions. This is similar to cloning a packet for group buckets.
     * There is no need to restore the error back to old value due to the fact
     * that we actually processed group action which can happen only when there
     * is no previous context error.
     *
     * Exception to above is errors which are system limits to protect
     * translation from running too long or occupy too much space. These errors
     * should not be masked. XLATE_RECURSION_TOO_DEEP, XLATE_TOO_MANY_RESUBMITS
     * and XLATE_STACK_TOO_DEEP fall in this category. */
    if (ctx->error == XLATE_TOO_MANY_MPLS_LABELS ||
        ctx->error == XLATE_UNSUPPORTED_PACKET_TYPE) {
        /* reset the error and continue processing other buckets */
        ctx->error = XLATE_OK;
    }
}

static void
xlate_all_group(struct xlate_ctx *ctx, struct group_dpif *group,
                bool is_last_action)
{
    struct ofputil_bucket *bucket;
    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
        bool last = is_last_action && !bucket->list_node.next;
        xlate_group_bucket(ctx, bucket, last);
    }
    xlate_group_stats(ctx, group, NULL);
}

static void
xlate_ff_group(struct xlate_ctx *ctx, struct group_dpif *group,
               bool is_last_action)
{
    struct ofputil_bucket *bucket;

    bucket = group_first_live_bucket(ctx, group, 0);
    if (bucket) {
        xlate_group_bucket(ctx, bucket, is_last_action);
        xlate_group_stats(ctx, group, bucket);
    } else if (ctx->xin->xcache) {
        ofproto_group_unref(&group->up);
    }
}

static void
xlate_default_select_group(struct xlate_ctx *ctx, struct group_dpif *group,
                           bool is_last_action)
{
    struct flow_wildcards *wc = ctx->wc;
    struct ofputil_bucket *bucket;
    uint32_t basis;

    basis = flow_hash_symmetric_l4(&ctx->xin->flow, 0);
    flow_mask_hash_fields(&ctx->xin->flow, wc, NX_HASH_FIELDS_SYMMETRIC_L4);
    bucket = group_best_live_bucket(ctx, group, basis);
    if (bucket) {
        xlate_group_bucket(ctx, bucket, is_last_action);
        xlate_group_stats(ctx, group, bucket);
    } else if (ctx->xin->xcache) {
        ofproto_group_unref(&group->up);
    }
}

static void
xlate_hash_fields_select_group(struct xlate_ctx *ctx, struct group_dpif *group,
                               bool is_last_action)
{
    const struct field_array *fields = &group->up.props.fields;
    const uint8_t *mask_values = fields->values;
    uint32_t basis = hash_uint64(group->up.props.selection_method_param);

    size_t i;
    BITMAP_FOR_EACH_1 (i, MFF_N_IDS, fields->used.bm) {
        const struct mf_field *mf = mf_from_id(i);

        /* Skip fields for which prerequisites are not met. */
        if (!mf_are_prereqs_ok(mf, &ctx->xin->flow, ctx->wc)) {
            /* Skip the mask bytes for this field. */
            mask_values += mf->n_bytes;
            continue;
        }

        union mf_value value;
        union mf_value mask;

        mf_get_value(mf, &ctx->xin->flow, &value);
        /* Mask the value. */
        for (int j = 0; j < mf->n_bytes; j++) {
            mask.b[j] = *mask_values++;
            value.b[j] &= mask.b[j];
        }
        basis = hash_bytes(&value, mf->n_bytes, basis);

        /* For tunnels, hash in whether the field is present. */
        if (mf_is_tun_metadata(mf)) {
            basis = hash_boolean(mf_is_set(mf, &ctx->xin->flow), basis);
        }

        mf_mask_field_masked(mf, &mask, ctx->wc);
    }

    struct ofputil_bucket *bucket = group_best_live_bucket(ctx, group, basis);
    if (bucket) {
        xlate_group_bucket(ctx, bucket, is_last_action);
        xlate_group_stats(ctx, group, bucket);
    } else if (ctx->xin->xcache) {
        ofproto_group_unref(&group->up);
    }
}

static void
xlate_dp_hash_select_group(struct xlate_ctx *ctx, struct group_dpif *group,
                           bool is_last_action)
{
    struct ofputil_bucket *bucket;

    /* dp_hash value 0 is special since it means that the dp_hash has not been
     * computed, as all computed dp_hash values are non-zero.  Therefore
     * compare to zero can be used to decide if the dp_hash value is valid
     * without masking the dp_hash field. */
    if (!ctx->xin->flow.dp_hash) {
        uint64_t param = group->up.props.selection_method_param;

        ctx_trigger_recirculate_with_hash(ctx, param >> 32, (uint32_t)param);
    } else {
        uint32_t n_buckets = group->up.n_buckets;
        if (n_buckets) {
            /* Minimal mask to cover the number of buckets. */
            uint32_t mask = (1 << log_2_ceil(n_buckets)) - 1;
            /* Multiplier chosen to make the trivial 1 bit case to
             * actually distribute amongst two equal weight buckets. */
            uint32_t basis = 0xc2b73583 * (ctx->xin->flow.dp_hash & mask);

            ctx->wc->masks.dp_hash |= mask;
            bucket = group_best_live_bucket(ctx, group, basis);
            if (bucket) {
                xlate_group_bucket(ctx, bucket, is_last_action);
                xlate_group_stats(ctx, group, bucket);
            }
        }
    }
}

static void
xlate_select_group(struct xlate_ctx *ctx, struct group_dpif *group,
                   bool is_last_action)
{
    const char *selection_method = group->up.props.selection_method;

    /* Select groups may access flow keys beyond L2 in order to
     * select a bucket. Recirculate as appropriate to make this possible.
     */
    if (ctx->was_mpls) {
        ctx_trigger_freeze(ctx);
    }

    if (selection_method[0] == '\0') {
        xlate_default_select_group(ctx, group, is_last_action);
    } else if (!strcasecmp("hash", selection_method)) {
        xlate_hash_fields_select_group(ctx, group, is_last_action);
    } else if (!strcasecmp("dp_hash", selection_method)) {
        xlate_dp_hash_select_group(ctx, group, is_last_action);
    } else {
        /* Parsing of groups should ensure this never happens */
        OVS_NOT_REACHED();
    }
}

static void
xlate_group_action__(struct xlate_ctx *ctx, struct group_dpif *group,
                     bool is_last_action)
{
    bool was_in_group = ctx->in_group;
    ctx->in_group = true;

    switch (group->up.type) {
    case OFPGT11_ALL:
    case OFPGT11_INDIRECT:
        xlate_all_group(ctx, group, is_last_action);
        break;
    case OFPGT11_SELECT:
        xlate_select_group(ctx, group, is_last_action);
        break;
    case OFPGT11_FF:
        xlate_ff_group(ctx, group, is_last_action);
        break;
    default:
        OVS_NOT_REACHED();
    }

    ctx->in_group = was_in_group;
}

static bool
xlate_group_action(struct xlate_ctx *ctx, uint32_t group_id,
                   bool is_last_action)
{
    if (xlate_resubmit_resource_check(ctx)) {
        struct group_dpif *group;

        /* Take ref only if xcache exists. */
        group = group_dpif_lookup(ctx->xbridge->ofproto, group_id,
                                  ctx->xin->tables_version, ctx->xin->xcache);
        if (!group) {
            /* XXX: Should set ctx->error ? */
            xlate_report(ctx, OFT_WARN, "output to nonexistent group %"PRIu32,
                         group_id);
            return true;
        }
        xlate_group_action__(ctx, group, is_last_action);
    }

    return false;
}

static void
xlate_ofpact_resubmit(struct xlate_ctx *ctx,
                      const struct ofpact_resubmit *resubmit,
                      bool is_last_action)
{
    ofp_port_t in_port;
    uint8_t table_id;
    bool may_packet_in = false;
    bool honor_table_miss = false;

    if (ctx->rule && rule_dpif_is_internal(ctx->rule)) {
        /* Still allow missed packets to be sent to the controller
         * if resubmitting from an internal table. */
        may_packet_in = true;
        honor_table_miss = true;
    }

    in_port = resubmit->in_port;
    if (in_port == OFPP_IN_PORT) {
        in_port = ctx->xin->flow.in_port.ofp_port;
    }

    table_id = resubmit->table_id;
    if (table_id == 255) {
        table_id = ctx->table_id;
    }

    xlate_table_action(ctx, in_port, table_id, may_packet_in,
                       honor_table_miss, resubmit->with_ct_orig,
                       is_last_action, do_xlate_actions);
}

static void
flood_packet_to_port(struct xlate_ctx *ctx, const struct xport *xport,
                     bool all, bool is_last_action)
{
    if (!xport) {
        return;
    }

    if (all) {
        compose_output_action__(ctx, xport->ofp_port, NULL, false,
                                is_last_action, false);
    } else {
        compose_output_action(ctx, xport->ofp_port, NULL, is_last_action,
                              false);
    }
}

static void
flood_packets(struct xlate_ctx *ctx, bool all, bool is_last_action)
{
    const struct xport *xport, *last = NULL;

    /* Use 'last' the keep track of the last output port. */
    HMAP_FOR_EACH (xport, ofp_node, &ctx->xbridge->xports) {
        if (xport->ofp_port == ctx->xin->flow.in_port.ofp_port) {
            continue;
        }

        if (all || !(xport->config & OFPUTIL_PC_NO_FLOOD)) {
            /* 'last' is not the last port, send a packet out, and
             * update 'last'. */
            flood_packet_to_port(ctx, last, all, false);
            last = xport;
        }
    }

    /* Send the packet to the 'last' port. */
    flood_packet_to_port(ctx, last, all, is_last_action);
    ctx->nf_output_iface = NF_OUT_FLOOD;
}

static void
put_controller_user_action(struct xlate_ctx *ctx,
                           bool dont_send, bool continuation,
                           uint32_t recirc_id, int len,
                           enum ofp_packet_in_reason reason,
                           uint16_t controller_id)
{
    struct user_action_cookie cookie;

    memset(&cookie, 0, sizeof cookie);
    cookie.type = USER_ACTION_COOKIE_CONTROLLER;
    cookie.ofp_in_port = OFPP_NONE,
    cookie.ofproto_uuid = ctx->xbridge->ofproto->uuid;
    cookie.controller.dont_send = dont_send;
    cookie.controller.continuation = continuation;
    cookie.controller.reason = reason;
    cookie.controller.recirc_id = recirc_id;
    put_32aligned_be64(&cookie.controller.rule_cookie, ctx->rule_cookie);
    cookie.controller.controller_id = controller_id;
    cookie.controller.max_len = len;

    odp_port_t odp_port = ofp_port_to_odp_port(ctx->xbridge,
                                             ctx->xin->flow.in_port.ofp_port);
    uint32_t pid = dpif_port_get_pid(ctx->xbridge->dpif, odp_port,
                                     flow_hash_5tuple(&ctx->xin->flow, 0));
    odp_put_userspace_action(pid, &cookie, sizeof cookie, ODPP_NONE,
                             false, ctx->odp_actions);
}

static void
xlate_controller_action(struct xlate_ctx *ctx, int len,
                        enum ofp_packet_in_reason reason,
                        uint16_t controller_id,
                        const uint8_t *userdata, size_t userdata_len)
{
    xlate_commit_actions(ctx);

    /* A packet sent by an action in a table-miss rule is considered an
     * explicit table miss.  OpenFlow before 1.3 doesn't have that concept so
     * it will get translated back to OFPR_ACTION for those versions. */
    if (reason == OFPR_ACTION
        && ctx->rule && rule_is_table_miss(&ctx->rule->up)) {
        reason = OFPR_EXPLICIT_MISS;
    }

    struct frozen_state state = {
        .table_id = ctx->table_id,
        .ofproto_uuid = ctx->xbridge->ofproto->uuid,
        .stack = ctx->stack.data,
        .stack_size = ctx->stack.size,
        .mirrors = ctx->mirrors,
        .conntracked = ctx->conntracked,
        .ofpacts = NULL,
        .ofpacts_len = 0,
        .action_set = NULL,
        .action_set_len = 0,
        .userdata = CONST_CAST(uint8_t *, userdata),
        .userdata_len = userdata_len,
    };
    frozen_metadata_from_flow(&state.metadata, &ctx->xin->flow);

    uint32_t recirc_id = recirc_alloc_id_ctx(&state);
    if (!recirc_id) {
        xlate_report_error(ctx, "Failed to allocate recirculation id");
        ctx->error = XLATE_NO_RECIRCULATION_CONTEXT;
        return;
    }
    recirc_refs_add(&ctx->xout->recircs, recirc_id);

    size_t offset;
    size_t ac_offset;
    uint32_t meter_id = ctx->xbridge->ofproto->up.controller_meter_id;
    if (meter_id != UINT32_MAX) {
        /* If controller meter is configured, generate clone(meter, userspace)
         * action. */
        offset = nl_msg_start_nested(ctx->odp_actions, OVS_ACTION_ATTR_SAMPLE);
        nl_msg_put_u32(ctx->odp_actions, OVS_SAMPLE_ATTR_PROBABILITY,
                       UINT32_MAX);
        ac_offset = nl_msg_start_nested(ctx->odp_actions,
                                        OVS_SAMPLE_ATTR_ACTIONS);
        nl_msg_put_u32(ctx->odp_actions, OVS_ACTION_ATTR_METER, meter_id);
    }

    /* Generate the datapath flows even if we don't send the packet-in
     * so that debugging more closely represents normal state. */
    bool dont_send = false;
    if (!ctx->xin->allow_side_effects && !ctx->xin->xcache) {
        dont_send = true;
    }
    put_controller_user_action(ctx, dont_send, false, recirc_id, len,
                               reason, controller_id);

    if (meter_id != UINT32_MAX) {
        nl_msg_end_nested(ctx->odp_actions, ac_offset);
        nl_msg_end_nested(ctx->odp_actions, offset);
    }
}

/* Creates a frozen state, and allocates a unique recirc id for the given
 * state.  Returns a non-zero recirc id if it is allocated successfully.
 * Returns 0 otherwise.
 **/
static uint32_t
finish_freezing__(struct xlate_ctx *ctx, uint8_t table)
{
    ovs_assert(ctx->freezing);

    struct frozen_state state = {
        .table_id = table,
        .ofproto_uuid = ctx->xbridge->ofproto->uuid,
        .stack = ctx->stack.data,
        .stack_size = ctx->stack.size,
        .mirrors = ctx->mirrors,
        .conntracked = ctx->conntracked,
        .xport_uuid = ctx->xin->xport_uuid,
        .ofpacts = ctx->frozen_actions.data,
        .ofpacts_len = ctx->frozen_actions.size,
        .action_set = ctx->action_set.data,
        .action_set_len = ctx->action_set.size,
        .userdata = ctx->pause ? CONST_CAST(uint8_t *,ctx->pause->userdata)
                               : NULL,
        .userdata_len = ctx->pause ? ctx->pause->userdata_len : 0,
    };
    frozen_metadata_from_flow(&state.metadata, &ctx->xin->flow);

    /* Allocate a unique recirc id for the given metadata state in the
     * flow.  An existing id, with a new reference to the corresponding
     * recirculation context, will be returned if possible.
     * The life-cycle of this recirc id is managed by associating it
     * with the udpif key ('ukey') created for each new datapath flow. */
    uint32_t recirc_id = recirc_alloc_id_ctx(&state);
    if (!recirc_id) {
        xlate_report_error(ctx, "Failed to allocate recirculation id");
        ctx->error = XLATE_NO_RECIRCULATION_CONTEXT;
        return 0;
    }
    recirc_refs_add(&ctx->xout->recircs, recirc_id);

    if (ctx->pause) {
        if (!ctx->xin->allow_side_effects && !ctx->xin->xcache) {
            return 0;
        }

        put_controller_user_action(ctx, false, true, recirc_id,
                                   ctx->pause->max_len,
                                   ctx->pause->reason,
                                   ctx->pause->controller_id);
    } else {
        if (ctx->recirc_update_dp_hash) {
            struct ovs_action_hash *act_hash;

            /* Hash action. */
            act_hash = nl_msg_put_unspec_uninit(ctx->odp_actions,
                                                OVS_ACTION_ATTR_HASH,
                                                sizeof *act_hash);
            act_hash->hash_alg = OVS_HASH_ALG_L4;  /* Make configurable. */
            act_hash->hash_basis = 0;              /* Make configurable. */
        }
        nl_msg_put_u32(ctx->odp_actions, OVS_ACTION_ATTR_RECIRC, recirc_id);
    }

    /* Undo changes done by freezing. */
    ctx_cancel_freeze(ctx);
    return recirc_id;
}

/* Called only when we're freezing. */
static void
finish_freezing(struct xlate_ctx *ctx)
{
    xlate_commit_actions(ctx);
    finish_freezing__(ctx, 0);
}

/* Fork the pipeline here. The current packet will continue processing the
 * current action list. A clone of the current packet will recirculate, skip
 * the remainder of the current action list and asynchronously resume pipeline
 * processing in 'table' with the current metadata and action set. */
static void
compose_recirculate_and_fork(struct xlate_ctx *ctx, uint8_t table,
                             const uint16_t zone)
{
    uint32_t recirc_id;
    ctx->freezing = true;
    recirc_id = finish_freezing__(ctx, table);

    if (OVS_UNLIKELY(ctx->xin->trace) && recirc_id) {
        if (oftrace_add_recirc_node(ctx->xin->recirc_queue,
                                    OFT_RECIRC_CONNTRACK, &ctx->xin->flow,
                                    ctx->xin->packet, recirc_id, zone)) {
            xlate_report(ctx, OFT_DETAIL, "A clone of the packet is forked to "
                         "recirculate. The forked pipeline will be resumed at "
                         "table %u.", table);
        } else {
            xlate_report(ctx, OFT_DETAIL, "Failed to trace the conntrack "
                        "forked pipeline with recirc_id = %d.", recirc_id);
        }
    }
}

static void
compose_mpls_push_action(struct xlate_ctx *ctx, struct ofpact_push_mpls *mpls)
{
    struct flow *flow = &ctx->xin->flow;
    int n;

    ovs_assert(eth_type_mpls(mpls->ethertype));

    n = flow_count_mpls_labels(flow, ctx->wc);
    if (!n) {
        xlate_commit_actions(ctx);
    } else if (n >= FLOW_MAX_MPLS_LABELS) {
        if (ctx->xin->packet != NULL) {
            xlate_report_error(ctx, "dropping packet on which an MPLS push "
                               "action can't be performed as it would have "
                               "more MPLS LSEs than the %d supported.",
                               FLOW_MAX_MPLS_LABELS);
        }
        ctx->error = XLATE_TOO_MANY_MPLS_LABELS;
        return;
    }

    /* Update flow's MPLS stack, and clear L3/4 fields to mark them invalid. */
    flow_push_mpls(flow, n, mpls->ethertype, ctx->wc, true);
}

static void
compose_mpls_pop_action(struct xlate_ctx *ctx, ovs_be16 eth_type)
{
    struct flow *flow = &ctx->xin->flow;
    int n = flow_count_mpls_labels(flow, ctx->wc);

    if (flow_pop_mpls(flow, n, eth_type, ctx->wc)) {
        if (!eth_type_mpls(eth_type) && ctx->xbridge->support.odp.recirc) {
            ctx->was_mpls = true;
        }
    } else if (n >= FLOW_MAX_MPLS_LABELS) {
        if (ctx->xin->packet != NULL) {
            xlate_report_error(ctx, "dropping packet on which an "
                               "MPLS pop action can't be performed as it has "
                               "more MPLS LSEs than the %d supported.",
                               FLOW_MAX_MPLS_LABELS);
        }
        ctx->error = XLATE_TOO_MANY_MPLS_LABELS;
        ofpbuf_clear(ctx->odp_actions);
    }
}

static bool
compose_dec_ttl(struct xlate_ctx *ctx, struct ofpact_cnt_ids *ids)
{
    struct flow *flow = &ctx->xin->flow;

    if (!is_ip_any(flow)) {
        return false;
    }

    ctx->wc->masks.nw_ttl = 0xff;
    if (flow->nw_ttl > 1) {
        flow->nw_ttl--;
        return false;
    } else {
        size_t i;

        for (i = 0; i < ids->n_controllers; i++) {
            xlate_controller_action(ctx, UINT16_MAX, OFPR_INVALID_TTL,
                                    ids->cnt_ids[i], NULL, 0);
        }

        /* Stop processing for current table. */
        xlate_report(ctx, OFT_WARN, "IPv%d decrement TTL exception",
                     flow->dl_type == htons(ETH_TYPE_IP) ? 4 : 6);
        return true;
    }
}

static void
compose_set_mpls_label_action(struct xlate_ctx *ctx, ovs_be32 label)
{
    if (eth_type_mpls(ctx->xin->flow.dl_type)) {
        ctx->wc->masks.mpls_lse[0] |= htonl(MPLS_LABEL_MASK);
        set_mpls_lse_label(&ctx->xin->flow.mpls_lse[0], label);
    }
}

static void
compose_set_mpls_tc_action(struct xlate_ctx *ctx, uint8_t tc)
{
    if (eth_type_mpls(ctx->xin->flow.dl_type)) {
        ctx->wc->masks.mpls_lse[0] |= htonl(MPLS_TC_MASK);
        set_mpls_lse_tc(&ctx->xin->flow.mpls_lse[0], tc);
    }
}

static bool
compose_dec_nsh_ttl_action(struct xlate_ctx *ctx)
{
    struct flow *flow = &ctx->xin->flow;

    if ((flow->packet_type == htonl(PT_NSH)) ||
        (flow->dl_type == htons(ETH_TYPE_NSH))) {
        ctx->wc->masks.nsh.ttl = 0xff;
        if (flow->nsh.ttl > 1) {
            flow->nsh.ttl--;
            return false;
        } else {
            xlate_controller_action(ctx, UINT16_MAX, OFPR_INVALID_TTL,
                                    0, NULL, 0);
        }
    }

    /* Stop processing for current table. */
    xlate_report(ctx, OFT_WARN, "NSH decrement TTL exception");
    return true;
}

static void
compose_set_mpls_ttl_action(struct xlate_ctx *ctx, uint8_t ttl)
{
    if (eth_type_mpls(ctx->xin->flow.dl_type)) {
        ctx->wc->masks.mpls_lse[0] |= htonl(MPLS_TTL_MASK);
        set_mpls_lse_ttl(&ctx->xin->flow.mpls_lse[0], ttl);
    }
}

static bool
compose_dec_mpls_ttl_action(struct xlate_ctx *ctx)
{
    struct flow *flow = &ctx->xin->flow;

    if (eth_type_mpls(flow->dl_type)) {
        uint8_t ttl = mpls_lse_to_ttl(flow->mpls_lse[0]);

        ctx->wc->masks.mpls_lse[0] |= htonl(MPLS_TTL_MASK);
        if (ttl > 1) {
            ttl--;
            set_mpls_lse_ttl(&flow->mpls_lse[0], ttl);
            return false;
        } else {
            xlate_controller_action(ctx, UINT16_MAX, OFPR_INVALID_TTL, 0,
                                    NULL, 0);
        }
    }

    /* Stop processing for current table. */
    xlate_report(ctx, OFT_WARN, "MPLS decrement TTL exception");
    return true;
}

/* Emits an action that outputs to 'port', within 'ctx'.
 *
 * 'controller_len' affects only packets sent to an OpenFlow controller.  It
 * is the maximum number of bytes of the packet to send.  UINT16_MAX means to
 * send the whole packet (and 0 means to omit the packet entirely).
 *
 * 'may_packet_in' determines whether the packet may be sent to an OpenFlow
 * controller.  If it is false, then the packet is never sent to the OpenFlow
 * controller.
 *
 * 'is_last_action' should be true if this output is the last OpenFlow action
 * to be processed, which enables certain optimizations.
 *
 * 'truncate' should be true if the packet to be output is being truncated,
 * which suppresses certain optimizations. */
static void
xlate_output_action(struct xlate_ctx *ctx, ofp_port_t port,
                    uint16_t controller_len, bool may_packet_in,
                    bool is_last_action, bool truncate)
{
    ofp_port_t prev_nf_output_iface = ctx->nf_output_iface;

    ctx->nf_output_iface = NF_OUT_DROP;

    switch (port) {
    case OFPP_IN_PORT:
        compose_output_action(ctx, ctx->xin->flow.in_port.ofp_port, NULL,
                              is_last_action, truncate);
        break;
    case OFPP_TABLE:
        xlate_table_action(ctx, ctx->xin->flow.in_port.ofp_port,
                           0, may_packet_in, true, false, false,
                           do_xlate_actions);
        break;
    case OFPP_NORMAL:
        xlate_normal(ctx);
        break;
    case OFPP_FLOOD:
        flood_packets(ctx, false, is_last_action);
        break;
    case OFPP_ALL:
        flood_packets(ctx, true, is_last_action);
        break;
    case OFPP_CONTROLLER:
        xlate_controller_action(ctx, controller_len,
                                (ctx->in_packet_out ? OFPR_PACKET_OUT
                                 : ctx->in_group ? OFPR_GROUP
                                 : ctx->in_action_set ? OFPR_ACTION_SET
                                 : OFPR_ACTION),
                                0, NULL, 0);
        break;
    case OFPP_NONE:
        break;
    case OFPP_LOCAL:
    default:
        if (port != ctx->xin->flow.in_port.ofp_port) {
            compose_output_action(ctx, port, NULL, is_last_action, truncate);
        } else {
            xlate_report(ctx, OFT_WARN, "skipping output to input port");
        }
        break;
    }

    if (prev_nf_output_iface == NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_FLOOD;
    } else if (ctx->nf_output_iface == NF_OUT_DROP) {
        ctx->nf_output_iface = prev_nf_output_iface;
    } else if (prev_nf_output_iface != NF_OUT_DROP &&
               ctx->nf_output_iface != NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_MULTI;
    }
}

static void
xlate_output_reg_action(struct xlate_ctx *ctx,
                        const struct ofpact_output_reg *or,
                        bool is_last_action)
{
    uint64_t port = mf_get_subfield(&or->src, &ctx->xin->flow);
    if (port <= UINT16_MAX) {
        xlate_report(ctx, OFT_DETAIL, "output port is %"PRIu64, port);

        union mf_subvalue value;

        memset(&value, 0xff, sizeof value);
        mf_write_subfield_flow(&or->src, &value, &ctx->wc->masks);
        xlate_output_action(ctx, u16_to_ofp(port), or->max_len,
                            false, is_last_action, false);
    } else {
        xlate_report(ctx, OFT_WARN, "output port %"PRIu64" is out of range",
                     port);
    }
}

static void
xlate_output_trunc_action(struct xlate_ctx *ctx,
                    ofp_port_t port, uint32_t max_len,
                    bool is_last_action)
{
    bool support_trunc = ctx->xbridge->support.trunc;
    struct ovs_action_trunc *trunc;
    char name[OFP10_MAX_PORT_NAME_LEN];

    switch (port) {
    case OFPP_TABLE:
    case OFPP_NORMAL:
    case OFPP_FLOOD:
    case OFPP_ALL:
    case OFPP_CONTROLLER:
    case OFPP_NONE:
        ofputil_port_to_string(port, NULL, name, sizeof name);
        xlate_report(ctx, OFT_WARN,
                     "output_trunc does not support port: %s", name);
        break;
    case OFPP_LOCAL:
    case OFPP_IN_PORT:
    default:
        if (port != ctx->xin->flow.in_port.ofp_port) {
            const struct xport *xport = get_ofp_port(ctx->xbridge, port);

            if (xport == NULL || xport->odp_port == ODPP_NONE) {
                /* Since truncate happens at its following output action, if
                 * the output port is a patch port, the behavior is somehow
                 * unpredictable.  For simplicity, disallow this case. */
                ofputil_port_to_string(port, NULL, name, sizeof name);
                xlate_report_error(ctx, "output_trunc does not support "
                                   "patch port %s", name);
                break;
            }

            trunc = nl_msg_put_unspec_uninit(ctx->odp_actions,
                                OVS_ACTION_ATTR_TRUNC,
                                sizeof *trunc);
            trunc->max_len = max_len;
            xlate_output_action(ctx, port, 0, false, is_last_action, true);
            if (!support_trunc) {
                ctx->xout->slow |= SLOW_ACTION;
            }
        } else {
            xlate_report(ctx, OFT_WARN, "skipping output to input port");
        }
        break;
    }
}

static void
xlate_enqueue_action(struct xlate_ctx *ctx,
                     const struct ofpact_enqueue *enqueue,
                     bool is_last_action)
{
    ofp_port_t ofp_port = enqueue->port;
    uint32_t queue_id = enqueue->queue;
    uint32_t flow_priority, priority;
    int error;

    /* Translate queue to priority. */
    error = dpif_queue_to_priority(ctx->xbridge->dpif, queue_id, &priority);
    if (error) {
        /* Fall back to ordinary output action. */
        xlate_output_action(ctx, enqueue->port, 0, false,
                            is_last_action, false);
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
    compose_output_action(ctx, ofp_port, NULL, is_last_action, false);
    ctx->xin->flow.skb_priority = flow_priority;

    /* Update NetFlow output port. */
    if (ctx->nf_output_iface == NF_OUT_DROP) {
        ctx->nf_output_iface = ofp_port;
    } else if (ctx->nf_output_iface != NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_MULTI;
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
                    const struct ofpact_bundle *bundle,
                    bool is_last_action)
{
    ofp_port_t port;

    port = bundle_execute(bundle, &ctx->xin->flow, ctx->wc, slave_enabled_cb,
                          CONST_CAST(struct xbridge *, ctx->xbridge));
    if (bundle->dst.field) {
        nxm_reg_load(&bundle->dst, ofp_to_u16(port), &ctx->xin->flow, ctx->wc);
        xlate_report_subfield(ctx, &bundle->dst);
    } else {
        xlate_output_action(ctx, port, 0, false, is_last_action, false);
    }
}

static void
xlate_learn_action(struct xlate_ctx *ctx, const struct ofpact_learn *learn)
{
    learn_mask(learn, ctx->wc);

    if (ctx->xin->xcache || ctx->xin->allow_side_effects) {
        uint64_t ofpacts_stub[1024 / 8];
        struct ofputil_flow_mod fm;
        struct ofproto_flow_mod ofm__, *ofm;
        struct ofpbuf ofpacts;
        enum ofperr error;

        if (ctx->xin->xcache) {
            ofm = xmalloc(sizeof *ofm);
        } else {
            ofm = &ofm__;
        }

        ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
        learn_execute(learn, &ctx->xin->flow, &fm, &ofpacts);
        if (OVS_UNLIKELY(ctx->xin->trace)) {
            struct ds s = DS_EMPTY_INITIALIZER;
            ds_put_format(&s, "table=%"PRIu8" ", fm.table_id);
            minimatch_format(&fm.match,
                             ofproto_get_tun_tab(&ctx->xin->ofproto->up),
                             NULL, &s, OFP_DEFAULT_PRIORITY);
            ds_chomp(&s, ' ');
            ds_put_format(&s, " priority=%d", fm.priority);
            if (fm.new_cookie) {
                ds_put_format(&s, " cookie=%#"PRIx64, ntohll(fm.new_cookie));
            }
            if (fm.idle_timeout != OFP_FLOW_PERMANENT) {
                ds_put_format(&s, " idle=%"PRIu16, fm.idle_timeout);
            }
            if (fm.hard_timeout != OFP_FLOW_PERMANENT) {
                ds_put_format(&s, " hard=%"PRIu16, fm.hard_timeout);
            }
            if (fm.flags & NX_LEARN_F_SEND_FLOW_REM) {
                ds_put_cstr(&s, " send_flow_rem");
            }
            ds_put_cstr(&s, " actions=");
            struct ofpact_format_params fp = { .s = &s };
            ofpacts_format(fm.ofpacts, fm.ofpacts_len, &fp);
            xlate_report(ctx, OFT_DETAIL, "%s", ds_cstr(&s));
            ds_destroy(&s);
        }
        error = ofproto_dpif_flow_mod_init_for_learn(ctx->xbridge->ofproto,
                                                     &fm, ofm);
        ofpbuf_uninit(&ofpacts);

        if (!error) {
            bool success = true;
            if (ctx->xin->allow_side_effects) {
                error = ofproto_flow_mod_learn(ofm, ctx->xin->xcache != NULL,
                                               learn->limit, &success);
            } else if (learn->limit) {
                if (!ofm->temp_rule
                    || ofm->temp_rule->state != RULE_INSERTED) {
                    /* The learned rule expired and there are no packets, so
                     * we cannot learn again.  Since the translated actions
                     * depend on the result of learning, we tell the caller
                     * that there's no point in caching this result. */
                    ctx->xout->avoid_caching = true;
                }
            }

            if (learn->flags & NX_LEARN_F_WRITE_RESULT) {
                nxm_reg_load(&learn->result_dst, success ? 1 : 0,
                             &ctx->xin->flow, ctx->wc);
                xlate_report_subfield(ctx, &learn->result_dst);
            }

            if (success && ctx->xin->xcache) {
                struct xc_entry *entry;

                entry = xlate_cache_add_entry(ctx->xin->xcache, XC_LEARN);
                entry->learn.ofm = ofm;
                entry->learn.limit = learn->limit;
                ofm = NULL;
            } else {
                ofproto_flow_mod_uninit(ofm);
            }

            if (OVS_UNLIKELY(ctx->xin->trace && !success)) {
                xlate_report(ctx, OFT_DETAIL, "Limit exceeded, learn failed");
            }
        }

        if (ofm != &ofm__) {
            free(ofm);
        }

        if (error) {
            xlate_report_error(ctx, "LEARN action execution failed (%s).",
                               ofperr_to_string(error));
        }

        minimatch_destroy(&fm.match);
    } else {
        xlate_report(ctx, OFT_WARN,
                     "suppressing side effects, so learn action ignored");
    }
}

static void
xlate_fin_timeout__(struct rule_dpif *rule, uint16_t tcp_flags,
                    uint16_t idle_timeout, uint16_t hard_timeout)
{
    if (tcp_flags & (TCP_FIN | TCP_RST)) {
        ofproto_rule_reduce_timeouts(&rule->up, idle_timeout, hard_timeout);
    }
}

static void
xlate_fin_timeout(struct xlate_ctx *ctx,
                  const struct ofpact_fin_timeout *oft)
{
    if (ctx->rule) {
        if (ctx->xin->allow_side_effects) {
            xlate_fin_timeout__(ctx->rule, ctx->xin->tcp_flags,
                                oft->fin_idle_timeout, oft->fin_hard_timeout);
        }
        if (ctx->xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx->xin->xcache, XC_FIN_TIMEOUT);
            /* XC_RULE already holds a reference on the rule, none is taken
             * here. */
            entry->fin.rule = ctx->rule;
            entry->fin.idle = oft->fin_idle_timeout;
            entry->fin.hard = oft->fin_hard_timeout;
        }
    }
}

static void
xlate_sample_action(struct xlate_ctx *ctx,
                    const struct ofpact_sample *os)
{
    odp_port_t output_odp_port = ODPP_NONE;
    odp_port_t tunnel_out_port = ODPP_NONE;
    struct dpif_ipfix *ipfix = ctx->xbridge->ipfix;
    bool emit_set_tunnel = false;

    if (!ipfix || ctx->xin->flow.in_port.ofp_port == OFPP_NONE) {
        return;
    }

    /* Scale the probability from 16-bit to 32-bit while representing
     * the same percentage. */
    uint32_t probability = (os->probability << 16) | os->probability;

    /* If ofp_port in flow sample action is equel to ofp_port,
     * this sample action is a input port action. */
    if (os->sampling_port != OFPP_NONE &&
        os->sampling_port != ctx->xin->flow.in_port.ofp_port) {
        output_odp_port = ofp_port_to_odp_port(ctx->xbridge,
                                               os->sampling_port);
        if (output_odp_port == ODPP_NONE) {
            xlate_report_error(ctx, "can't use unknown port %d in flow sample "
                               "action", os->sampling_port);
            return;
        }

        if (dpif_ipfix_get_flow_exporter_tunnel_sampling(ipfix,
                                                         os->collector_set_id)
            && dpif_ipfix_is_tunnel_port(ipfix, output_odp_port)) {
            tunnel_out_port = output_odp_port;
            emit_set_tunnel = true;
        }
    }

     xlate_commit_actions(ctx);
    /* If 'emit_set_tunnel', sample(sampling_port=1) would translate
     * into datapath sample action set(tunnel(...)), sample(...) and
     * it is used for sampling egress tunnel information. */
    if (emit_set_tunnel) {
        const struct xport *xport = get_ofp_port(ctx->xbridge,
                                                 os->sampling_port);

        if (xport && xport->is_tunnel) {
            struct flow *flow = &ctx->xin->flow;
            tnl_port_send(xport->ofport, flow, ctx->wc);
            if (!ovs_native_tunneling_is_on(ctx->xbridge->ofproto)) {
                struct flow_tnl flow_tnl = flow->tunnel;

                commit_odp_tunnel_action(flow, &ctx->base_flow,
                                         ctx->odp_actions);
                flow->tunnel = flow_tnl;
            }
        } else {
            xlate_report_error(ctx,
                               "sampling_port:%d should be a tunnel port.",
                               os->sampling_port);
        }
    }

    struct user_action_cookie cookie = {
        .type = USER_ACTION_COOKIE_FLOW_SAMPLE,
        .ofp_in_port = ctx->xin->flow.in_port.ofp_port,
        .ofproto_uuid = ctx->xbridge->ofproto->uuid,
        .flow_sample = {
            .probability = os->probability,
            .collector_set_id = os->collector_set_id,
            .obs_domain_id = os->obs_domain_id,
            .obs_point_id = os->obs_point_id,
            .output_odp_port = output_odp_port,
            .direction = os->direction,
        }
    };
    compose_sample_action(ctx, probability, &cookie, tunnel_out_port, false);
}

/* Determine if an datapath action translated from the openflow action
 * can be reversed by another datapath action.
 *
 * Openflow actions that do not emit datapath actions are trivially
 * reversible. Reversiblity of other actions depends on nature of
 * action and their translation.  */
static bool
reversible_actions(const struct ofpact *ofpacts, size_t ofpacts_len)
{
    const struct ofpact *a;

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        switch (a->type) {
        case OFPACT_BUNDLE:
        case OFPACT_CLEAR_ACTIONS:
        case OFPACT_CLONE:
        case OFPACT_CONJUNCTION:
        case OFPACT_CONTROLLER:
        case OFPACT_CT_CLEAR:
        case OFPACT_DEBUG_RECIRC:
        case OFPACT_DEBUG_SLOW:
        case OFPACT_DEC_MPLS_TTL:
        case OFPACT_DEC_TTL:
        case OFPACT_ENQUEUE:
        case OFPACT_EXIT:
        case OFPACT_FIN_TIMEOUT:
        case OFPACT_GOTO_TABLE:
        case OFPACT_GROUP:
        case OFPACT_LEARN:
        case OFPACT_MULTIPATH:
        case OFPACT_NOTE:
        case OFPACT_OUTPUT:
        case OFPACT_OUTPUT_REG:
        case OFPACT_POP_MPLS:
        case OFPACT_POP_QUEUE:
        case OFPACT_PUSH_MPLS:
        case OFPACT_PUSH_VLAN:
        case OFPACT_REG_MOVE:
        case OFPACT_RESUBMIT:
        case OFPACT_SAMPLE:
        case OFPACT_SET_ETH_DST:
        case OFPACT_SET_ETH_SRC:
        case OFPACT_SET_FIELD:
        case OFPACT_SET_IP_DSCP:
        case OFPACT_SET_IP_ECN:
        case OFPACT_SET_IP_TTL:
        case OFPACT_SET_IPV4_DST:
        case OFPACT_SET_IPV4_SRC:
        case OFPACT_SET_L4_DST_PORT:
        case OFPACT_SET_L4_SRC_PORT:
        case OFPACT_SET_MPLS_LABEL:
        case OFPACT_SET_MPLS_TC:
        case OFPACT_SET_MPLS_TTL:
        case OFPACT_SET_QUEUE:
        case OFPACT_SET_TUNNEL:
        case OFPACT_SET_VLAN_PCP:
        case OFPACT_SET_VLAN_VID:
        case OFPACT_STACK_POP:
        case OFPACT_STACK_PUSH:
        case OFPACT_STRIP_VLAN:
        case OFPACT_UNROLL_XLATE:
        case OFPACT_WRITE_ACTIONS:
        case OFPACT_WRITE_METADATA:
            break;

        case OFPACT_CT:
        case OFPACT_METER:
        case OFPACT_NAT:
        case OFPACT_OUTPUT_TRUNC:
        case OFPACT_ENCAP:
        case OFPACT_DECAP:
        case OFPACT_DEC_NSH_TTL:
            return false;
        }
    }
    return true;
}

static void
clone_xlate_actions(const struct ofpact *actions, size_t actions_len,
                    struct xlate_ctx *ctx, bool is_last_action)
{
    struct ofpbuf old_stack = ctx->stack;
    union mf_subvalue new_stack[1024 / sizeof(union mf_subvalue)];
    ofpbuf_use_stub(&ctx->stack, new_stack, sizeof new_stack);
    ofpbuf_put(&ctx->stack, old_stack.data, old_stack.size);

    struct ofpbuf old_action_set = ctx->action_set;
    uint64_t actset_stub[1024 / 8];
    ofpbuf_use_stub(&ctx->action_set, actset_stub, sizeof actset_stub);
    ofpbuf_put(&ctx->action_set, old_action_set.data, old_action_set.size);

    size_t offset, ac_offset;
    struct flow old_flow = ctx->xin->flow;

    if (reversible_actions(actions, actions_len) || is_last_action) {
        old_flow = ctx->xin->flow;
        do_xlate_actions(actions, actions_len, ctx, is_last_action);
        if (!ctx->freezing) {
            xlate_action_set(ctx);
        }
        if (ctx->freezing) {
            finish_freezing(ctx);
        }
        goto xlate_done;
    }

    /* Commit datapath actions before emitting the clone action to
     * avoid emitting those actions twice. Once inside
     * the clone, another time for the action after clone.  */
    xlate_commit_actions(ctx);
    struct flow old_base = ctx->base_flow;
    bool old_was_mpls = ctx->was_mpls;
    bool old_conntracked = ctx->conntracked;

    /* The actions are not reversible, a datapath clone action is
     * required to encode the translation. Select the clone action
     * based on datapath capabilities.  */
    if (ctx->xbridge->support.clone) { /* Use clone action */
        /* Use clone action as datapath clone. */
        offset = nl_msg_start_nested(ctx->odp_actions, OVS_ACTION_ATTR_CLONE);
        do_xlate_actions(actions, actions_len, ctx, true);
        if (!ctx->freezing) {
            xlate_action_set(ctx);
        }
        if (ctx->freezing) {
            finish_freezing(ctx);
        }
        nl_msg_end_non_empty_nested(ctx->odp_actions, offset);
        goto dp_clone_done;
    }

    if (ctx->xbridge->support.sample_nesting > 3) {
        /* Use sample action as datapath clone. */
        offset = nl_msg_start_nested(ctx->odp_actions, OVS_ACTION_ATTR_SAMPLE);
        ac_offset = nl_msg_start_nested(ctx->odp_actions,
                                        OVS_SAMPLE_ATTR_ACTIONS);
        do_xlate_actions(actions, actions_len, ctx, true);
        if (!ctx->freezing) {
            xlate_action_set(ctx);
        }
        if (ctx->freezing) {
            finish_freezing(ctx);
        }
        if (nl_msg_end_non_empty_nested(ctx->odp_actions, ac_offset)) {
            nl_msg_cancel_nested(ctx->odp_actions, offset);
        } else {
            nl_msg_put_u32(ctx->odp_actions, OVS_SAMPLE_ATTR_PROBABILITY,
                           UINT32_MAX); /* 100% probability. */
            nl_msg_end_nested(ctx->odp_actions, offset);
        }
        goto dp_clone_done;
    }

    /* Datapath does not support clone, skip xlate 'oc' and
     * report an error */
    xlate_report_error(ctx, "Failed to compose clone action");

dp_clone_done:
    /* The clone's conntrack execution should have no effect on the original
     * packet. */
    ctx->conntracked = old_conntracked;

    /* Popping MPLS from the clone should have no effect on the original
     * packet. */
    ctx->was_mpls = old_was_mpls;

    /* Restore the 'base_flow' for the next action.  */
    ctx->base_flow = old_base;

xlate_done:
    ofpbuf_uninit(&ctx->action_set);
    ctx->action_set = old_action_set;
    ofpbuf_uninit(&ctx->stack);
    ctx->stack = old_stack;
    ctx->xin->flow = old_flow;
}

static void
compose_clone(struct xlate_ctx *ctx, const struct ofpact_nest *oc,
              bool is_last_action)
{
    size_t oc_actions_len = ofpact_nest_get_action_len(oc);

    clone_xlate_actions(oc->actions, oc_actions_len, ctx, is_last_action);
}

static void
xlate_meter_action(struct xlate_ctx *ctx, const struct ofpact_meter *meter)
{
    if (meter->provider_meter_id != UINT32_MAX) {
        nl_msg_put_u32(ctx->odp_actions, OVS_ACTION_ATTR_METER,
                       meter->provider_meter_id);
    }
}

static bool
may_receive(const struct xport *xport, struct xlate_ctx *ctx)
{
    if (xport->config & (is_stp(&ctx->xin->flow)
                         ? OFPUTIL_PC_NO_RECV_STP
                         : OFPUTIL_PC_NO_RECV)) {
        return false;
    }

    /* Only drop packets here if both forwarding and learning are
     * disabled.  If just learning is enabled, we need to have
     * OFPP_NORMAL and the learning action have a look at the packet
     * before we can drop it. */
    if ((!xport_stp_forward_state(xport) && !xport_stp_learn_state(xport)) ||
        (!xport_rstp_forward_state(xport) && !xport_rstp_learn_state(xport))) {
        return false;
    }

    return true;
}

static void
xlate_write_actions__(struct xlate_ctx *ctx,
                      const struct ofpact *ofpacts, size_t ofpacts_len)
{
    /* Maintain actset_output depending on the contents of the action set:
     *
     *   - OFPP_UNSET, if there is no "output" action.
     *
     *   - The output port, if there is an "output" action and no "group"
     *     action.
     *
     *   - OFPP_UNSET, if there is a "group" action.
     */
    if (!ctx->action_set_has_group) {
        const struct ofpact *a;
        OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
            if (a->type == OFPACT_OUTPUT) {
                ctx->xin->flow.actset_output = ofpact_get_OUTPUT(a)->port;
            } else if (a->type == OFPACT_GROUP) {
                ctx->xin->flow.actset_output = OFPP_UNSET;
                ctx->action_set_has_group = true;
                break;
            }
        }
    }

    ofpbuf_put(&ctx->action_set, ofpacts, ofpacts_len);
}

static void
xlate_write_actions(struct xlate_ctx *ctx, const struct ofpact_nest *a)
{
    xlate_write_actions__(ctx, a->actions, ofpact_nest_get_action_len(a));
}

static void
xlate_action_set(struct xlate_ctx *ctx)
{
    uint64_t action_list_stub[1024 / 8];
    struct ofpbuf action_list = OFPBUF_STUB_INITIALIZER(action_list_stub);
    ofpacts_execute_action_set(&action_list, &ctx->action_set);
    /* Clear the action set, as it is not needed any more. */
    ofpbuf_clear(&ctx->action_set);
    if (action_list.size) {
        ctx->in_action_set = true;

        struct ovs_list *old_trace = ctx->xin->trace;
        ctx->xin->trace = xlate_report(ctx, OFT_TABLE,
                                       "--. Executing action set:");
        do_xlate_actions(action_list.data, action_list.size, ctx, true);
        ctx->xin->trace = old_trace;

        ctx->in_action_set = false;
    }
    ofpbuf_uninit(&action_list);
}

static void
freeze_put_unroll_xlate(struct xlate_ctx *ctx)
{
    struct ofpact_unroll_xlate *unroll = ctx->frozen_actions.header;

    /* Restore the table_id and rule cookie for a potential PACKET
     * IN if needed. */
    if (!unroll ||
        (ctx->table_id != unroll->rule_table_id
         || ctx->rule_cookie != unroll->rule_cookie)) {
        unroll = ofpact_put_UNROLL_XLATE(&ctx->frozen_actions);
        unroll->rule_table_id = ctx->table_id;
        unroll->rule_cookie = ctx->rule_cookie;
        ctx->frozen_actions.header = unroll;
    }
}


/* Copy actions 'a' through 'end' to ctx->frozen_actions, which will be
 * executed after thawing.  Inserts an UNROLL_XLATE action, if none is already
 * present, before any action that may depend on the current table ID or flow
 * cookie. */
static void
freeze_unroll_actions(const struct ofpact *a, const struct ofpact *end,
                      struct xlate_ctx *ctx)
{
    for (; a < end; a = ofpact_next(a)) {
        switch (a->type) {
        case OFPACT_OUTPUT_REG:
        case OFPACT_OUTPUT_TRUNC:
        case OFPACT_GROUP:
        case OFPACT_OUTPUT:
        case OFPACT_CONTROLLER:
        case OFPACT_DEC_MPLS_TTL:
        case OFPACT_DEC_NSH_TTL:
        case OFPACT_DEC_TTL:
            /* These actions may generate asynchronous messages, which include
             * table ID and flow cookie information. */
            freeze_put_unroll_xlate(ctx);
            break;

        case OFPACT_RESUBMIT:
            if (ofpact_get_RESUBMIT(a)->table_id == 0xff) {
                /* This resubmit action is relative to the current table, so we
                 * need to track what table that is.*/
                freeze_put_unroll_xlate(ctx);
            }
            break;

        case OFPACT_SET_TUNNEL:
        case OFPACT_REG_MOVE:
        case OFPACT_SET_FIELD:
        case OFPACT_STACK_PUSH:
        case OFPACT_STACK_POP:
        case OFPACT_LEARN:
        case OFPACT_WRITE_METADATA:
        case OFPACT_GOTO_TABLE:
        case OFPACT_ENQUEUE:
        case OFPACT_SET_VLAN_VID:
        case OFPACT_SET_VLAN_PCP:
        case OFPACT_STRIP_VLAN:
        case OFPACT_PUSH_VLAN:
        case OFPACT_SET_ETH_SRC:
        case OFPACT_SET_ETH_DST:
        case OFPACT_SET_IPV4_SRC:
        case OFPACT_SET_IPV4_DST:
        case OFPACT_SET_IP_DSCP:
        case OFPACT_SET_IP_ECN:
        case OFPACT_SET_IP_TTL:
        case OFPACT_SET_L4_SRC_PORT:
        case OFPACT_SET_L4_DST_PORT:
        case OFPACT_SET_QUEUE:
        case OFPACT_POP_QUEUE:
        case OFPACT_PUSH_MPLS:
        case OFPACT_POP_MPLS:
        case OFPACT_SET_MPLS_LABEL:
        case OFPACT_SET_MPLS_TC:
        case OFPACT_SET_MPLS_TTL:
        case OFPACT_MULTIPATH:
        case OFPACT_BUNDLE:
        case OFPACT_EXIT:
        case OFPACT_UNROLL_XLATE:
        case OFPACT_FIN_TIMEOUT:
        case OFPACT_CLEAR_ACTIONS:
        case OFPACT_WRITE_ACTIONS:
        case OFPACT_METER:
        case OFPACT_SAMPLE:
        case OFPACT_CLONE:
        case OFPACT_ENCAP:
        case OFPACT_DECAP:
        case OFPACT_DEBUG_RECIRC:
        case OFPACT_DEBUG_SLOW:
        case OFPACT_CT:
        case OFPACT_CT_CLEAR:
        case OFPACT_NAT:
            /* These may not generate PACKET INs. */
            break;

        case OFPACT_NOTE:
        case OFPACT_CONJUNCTION:
            /* These need not be copied for restoration. */
            continue;
        }
        /* Copy the action over. */
        ofpbuf_put(&ctx->frozen_actions, a, OFPACT_ALIGN(a->len));
    }
}

static void
put_ct_mark(const struct flow *flow, struct ofpbuf *odp_actions,
            struct flow_wildcards *wc)
{
    if (wc->masks.ct_mark) {
        struct {
            uint32_t key;
            uint32_t mask;
        } *odp_ct_mark;

        odp_ct_mark = nl_msg_put_unspec_uninit(odp_actions, OVS_CT_ATTR_MARK,
                                               sizeof(*odp_ct_mark));
        odp_ct_mark->key = flow->ct_mark & wc->masks.ct_mark;
        odp_ct_mark->mask = wc->masks.ct_mark;
    }
}

static void
put_ct_label(const struct flow *flow, struct ofpbuf *odp_actions,
             struct flow_wildcards *wc)
{
    if (!ovs_u128_is_zero(wc->masks.ct_label)) {
        struct {
            ovs_u128 key;
            ovs_u128 mask;
        } odp_ct_label;

        odp_ct_label.key = ovs_u128_and(flow->ct_label, wc->masks.ct_label);
        odp_ct_label.mask = wc->masks.ct_label;
        nl_msg_put_unspec(odp_actions, OVS_CT_ATTR_LABELS,
                          &odp_ct_label, sizeof odp_ct_label);
    }
}

static void
put_ct_helper(struct xlate_ctx *ctx,
              struct ofpbuf *odp_actions, struct ofpact_conntrack *ofc)
{
    if (ofc->alg) {
        switch(ofc->alg) {
        case IPPORT_FTP:
            nl_msg_put_string(odp_actions, OVS_CT_ATTR_HELPER, "ftp");
            break;
        case IPPORT_TFTP:
            nl_msg_put_string(odp_actions, OVS_CT_ATTR_HELPER, "tftp");
            break;
        default:
            xlate_report_error(ctx, "cannot serialize ct_helper %d", ofc->alg);
            break;
        }
    }
}

static void
put_ct_nat(struct xlate_ctx *ctx)
{
    struct ofpact_nat *ofn = ctx->ct_nat_action;
    size_t nat_offset;

    if (!ofn) {
        return;
    }

    nat_offset = nl_msg_start_nested(ctx->odp_actions, OVS_CT_ATTR_NAT);
    if (ofn->flags & NX_NAT_F_SRC || ofn->flags & NX_NAT_F_DST) {
        nl_msg_put_flag(ctx->odp_actions, ofn->flags & NX_NAT_F_SRC
                        ? OVS_NAT_ATTR_SRC : OVS_NAT_ATTR_DST);
        if (ofn->flags & NX_NAT_F_PERSISTENT) {
            nl_msg_put_flag(ctx->odp_actions, OVS_NAT_ATTR_PERSISTENT);
        }
        if (ofn->flags & NX_NAT_F_PROTO_HASH) {
            nl_msg_put_flag(ctx->odp_actions, OVS_NAT_ATTR_PROTO_HASH);
        } else if (ofn->flags & NX_NAT_F_PROTO_RANDOM) {
            nl_msg_put_flag(ctx->odp_actions, OVS_NAT_ATTR_PROTO_RANDOM);
        }
        if (ofn->range_af == AF_INET) {
            nl_msg_put_be32(ctx->odp_actions, OVS_NAT_ATTR_IP_MIN,
                           ofn->range.addr.ipv4.min);
            if (ofn->range.addr.ipv4.max &&
                (ntohl(ofn->range.addr.ipv4.max)
                 > ntohl(ofn->range.addr.ipv4.min))) {
                nl_msg_put_be32(ctx->odp_actions, OVS_NAT_ATTR_IP_MAX,
                                ofn->range.addr.ipv4.max);
            }
        } else if (ofn->range_af == AF_INET6) {
            nl_msg_put_unspec(ctx->odp_actions, OVS_NAT_ATTR_IP_MIN,
                              &ofn->range.addr.ipv6.min,
                              sizeof ofn->range.addr.ipv6.min);
            if (!ipv6_mask_is_any(&ofn->range.addr.ipv6.max) &&
                memcmp(&ofn->range.addr.ipv6.max, &ofn->range.addr.ipv6.min,
                       sizeof ofn->range.addr.ipv6.max) > 0) {
                nl_msg_put_unspec(ctx->odp_actions, OVS_NAT_ATTR_IP_MAX,
                                  &ofn->range.addr.ipv6.max,
                                  sizeof ofn->range.addr.ipv6.max);
            }
        }
        if (ofn->range_af != AF_UNSPEC && ofn->range.proto.min) {
            nl_msg_put_u16(ctx->odp_actions, OVS_NAT_ATTR_PROTO_MIN,
                           ofn->range.proto.min);
            if (ofn->range.proto.max &&
                ofn->range.proto.max > ofn->range.proto.min) {
                nl_msg_put_u16(ctx->odp_actions, OVS_NAT_ATTR_PROTO_MAX,
                               ofn->range.proto.max);
            }
        }
    }
    nl_msg_end_nested(ctx->odp_actions, nat_offset);
}

static void
compose_conntrack_action(struct xlate_ctx *ctx, struct ofpact_conntrack *ofc,
                         bool is_last_action)
{
    ovs_u128 old_ct_label_mask = ctx->wc->masks.ct_label;
    uint32_t old_ct_mark_mask = ctx->wc->masks.ct_mark;
    size_t ct_offset;
    uint16_t zone;

    /* Ensure that any prior actions are applied before composing the new
     * conntrack action. */
    xlate_commit_actions(ctx);

    /* Process nested actions first, to populate the key. */
    ctx->ct_nat_action = NULL;
    ctx->wc->masks.ct_mark = 0;
    ctx->wc->masks.ct_label = OVS_U128_ZERO;
    do_xlate_actions(ofc->actions, ofpact_ct_get_action_len(ofc), ctx,
                     is_last_action);

    if (ofc->zone_src.field) {
        zone = mf_get_subfield(&ofc->zone_src, &ctx->xin->flow);
    } else {
        zone = ofc->zone_imm;
    }

    ct_offset = nl_msg_start_nested(ctx->odp_actions, OVS_ACTION_ATTR_CT);
    if (ofc->flags & NX_CT_F_COMMIT) {
        nl_msg_put_flag(ctx->odp_actions, ofc->flags & NX_CT_F_FORCE ?
                        OVS_CT_ATTR_FORCE_COMMIT : OVS_CT_ATTR_COMMIT);
        if (ctx->xbridge->support.ct_eventmask) {
            nl_msg_put_u32(ctx->odp_actions, OVS_CT_ATTR_EVENTMASK,
                           OVS_CT_EVENTMASK_DEFAULT);
        }
    }
    nl_msg_put_u16(ctx->odp_actions, OVS_CT_ATTR_ZONE, zone);
    put_ct_mark(&ctx->xin->flow, ctx->odp_actions, ctx->wc);
    put_ct_label(&ctx->xin->flow, ctx->odp_actions, ctx->wc);
    put_ct_helper(ctx, ctx->odp_actions, ofc);
    put_ct_nat(ctx);
    ctx->ct_nat_action = NULL;
    nl_msg_end_nested(ctx->odp_actions, ct_offset);

    ctx->wc->masks.ct_mark = old_ct_mark_mask;
    ctx->wc->masks.ct_label = old_ct_label_mask;

    if (ofc->recirc_table != NX_CT_RECIRC_NONE) {
        ctx->conntracked = true;
        compose_recirculate_and_fork(ctx, ofc->recirc_table, zone);
    }

    /* The ct_* fields are only available in the scope of the 'recirc_table'
     * call chain. */
    flow_clear_conntrack(&ctx->xin->flow);
    xlate_report(ctx, OFT_DETAIL, "Sets the packet to an untracked state, "
                 "and clears all the conntrack fields.");
    ctx->conntracked = false;
}

static void
compose_ct_clear_action(struct xlate_ctx *ctx)
{
    clear_conntrack(ctx);
    /* This action originally existed without dpif support. So to preserve
     * compatibility, only append it if the dpif supports it. */
    if (ctx->xbridge->support.ct_clear) {
        nl_msg_put_flag(ctx->odp_actions,  OVS_ACTION_ATTR_CT_CLEAR);
    }
}

static void
rewrite_flow_encap_ethernet(struct xlate_ctx *ctx,
                            struct flow *flow,
                            struct flow_wildcards *wc)
{
    wc->masks.packet_type = OVS_BE32_MAX;
    if (pt_ns(flow->packet_type) == OFPHTN_ETHERTYPE) {
        /* Only adjust the packet_type and zero the dummy Ethernet addresses. */
        ovs_be16 ethertype = pt_ns_type_be(flow->packet_type);
        flow->packet_type = htonl(PT_ETH);
        flow->dl_src = eth_addr_zero;
        flow->dl_dst = eth_addr_zero;
        flow->dl_type = ethertype;
    } else {
        /* Error handling: drop packet. */
        xlate_report_debug(ctx, OFT_ACTION,
                           "Dropping packet as encap(ethernet) is not "
                           "supported for packet type ethernet.");
        ctx->error = XLATE_UNSUPPORTED_PACKET_TYPE;
    }
}

/* For an MD2 NSH header returns a pointer to an ofpbuf with the encoded
 * MD2 TLVs provided as encap properties to the encap operation. This
 * will be stored as encap_data in the ctx and copied into the push_nsh
 * action at the next commit. */
static struct ofpbuf *
rewrite_flow_push_nsh(struct xlate_ctx *ctx,
                      const struct ofpact_encap *encap,
                      struct flow *flow,
                      struct flow_wildcards *wc)
{
    ovs_be32 packet_type = flow->packet_type;
    const char *ptr = (char *) encap->props;
    struct ofpbuf *buf = ofpbuf_new(NSH_CTX_HDRS_MAX_LEN);
    uint8_t md_type = NSH_M_TYPE1;
    uint8_t np = 0;
    int i;

    /* Scan the optional NSH encap TLV properties, if any. */
    for (i = 0; i < encap->n_props; i++) {
        struct ofpact_ed_prop *prop_ptr =
            ALIGNED_CAST(struct ofpact_ed_prop *, ptr);
        if (prop_ptr->prop_class == OFPPPC_NSH) {
            switch (prop_ptr->type) {
                case OFPPPT_PROP_NSH_MDTYPE: {
                    struct ofpact_ed_prop_nsh_md_type *prop_md_type =
                        ALIGNED_CAST(struct ofpact_ed_prop_nsh_md_type *,
                                     prop_ptr);
                    md_type = prop_md_type->md_type;
                    break;
                }
                case OFPPPT_PROP_NSH_TLV: {
                    struct ofpact_ed_prop_nsh_tlv *tlv_prop =
                        ALIGNED_CAST(struct ofpact_ed_prop_nsh_tlv *,
                                     prop_ptr);
                    struct nsh_md2_tlv *md2_ctx =
                            ofpbuf_put_uninit(buf, sizeof(*md2_ctx));
                    md2_ctx->md_class = tlv_prop->tlv_class;
                    md2_ctx->type = tlv_prop->tlv_type;
                    md2_ctx->length = tlv_prop->tlv_len;
                    size_t len = ROUND_UP(md2_ctx->length, 4);
                    size_t padding = len - md2_ctx->length;
                    ofpbuf_put(buf, tlv_prop->data, md2_ctx->length);
                    ofpbuf_put_zeros(buf, padding);
                    break;
                }
                default:
                    /* No other NSH encap properties defined yet. */
                    break;
            }
        }
        ptr += ROUND_UP(prop_ptr->len, 8);
    }
    if (buf->size == 0 || buf->size > NSH_CTX_HDRS_MAX_LEN) {
        ofpbuf_delete(buf);
        buf = NULL;
    }

    /* Determine the Next Protocol field for NSH header. */
    switch (ntohl(packet_type)) {
        case PT_ETH:
            np = NSH_P_ETHERNET;
            break;
        case PT_IPV4:
            np = NSH_P_IPV4;
            break;
        case PT_IPV6:
            np = NSH_P_IPV6;
            break;
        case PT_NSH:
            np = NSH_P_NSH;
            break;
        default:
            /* Error handling: drop packet. */
            xlate_report_debug(ctx, OFT_ACTION,
                               "Dropping packet as encap(nsh) is not "
                               "supported for packet type (%d,0x%x)",
                               pt_ns(packet_type), pt_ns_type(packet_type));
            ctx->error = XLATE_UNSUPPORTED_PACKET_TYPE;
            return buf;
    }
    /* Note that we have matched on packet_type! */
    wc->masks.packet_type = OVS_BE32_MAX;

    /* Reset all current flow packet headers. */
    memset(&flow->dl_dst, 0,
           sizeof(struct flow) - offsetof(struct flow, dl_dst));

    /* Populate the flow with the new NSH header. */
    flow->packet_type = htonl(PT_NSH);
    flow->dl_type = htons(ETH_TYPE_NSH);
    flow->nsh.flags = 0;
    flow->nsh.ttl = 63;
    flow->nsh.np = np;
    flow->nsh.path_hdr = htonl(255);

    if (md_type == NSH_M_TYPE1) {
        flow->nsh.mdtype = NSH_M_TYPE1;
        memset(flow->nsh.context, 0, sizeof flow->nsh.context);
        if (buf) {
            /* Drop any MD2 context TLVs. */
            ofpbuf_delete(buf);
            buf = NULL;
        }
    } else if (md_type == NSH_M_TYPE2) {
        flow->nsh.mdtype = NSH_M_TYPE2;
    }
    flow->nsh.mdtype &= NSH_MDTYPE_MASK;

    return buf;
}

static void
xlate_generic_encap_action(struct xlate_ctx *ctx,
                           const struct ofpact_encap *encap)
{
    struct flow *flow = &ctx->xin->flow;
    struct flow_wildcards *wc = ctx->wc;
    struct ofpbuf *encap_data = NULL;

    /* Ensure that any pending actions on the inner packet are applied before
     * rewriting the flow */
    xlate_commit_actions(ctx);

    /* Rewrite the flow to reflect the effect of pushing the new encap header. */
    switch (ntohl(encap->new_pkt_type)) {
        case PT_ETH:
            rewrite_flow_encap_ethernet(ctx, flow, wc);
            break;
        case PT_NSH:
            encap_data = rewrite_flow_push_nsh(ctx, encap, flow, wc);
            break;
        default:
            /* New packet type was checked during decoding. */
            OVS_NOT_REACHED();
    }

    if (!ctx->error) {
        /* The actual encap datapath action will be generated at next commit. */
        ctx->pending_encap = true;
        ctx->encap_data = encap_data;
    }
}

/* Returns true if packet must be recirculated after decapsulation. */
static bool
xlate_generic_decap_action(struct xlate_ctx *ctx,
                           const struct ofpact_decap *decap OVS_UNUSED)
{
    struct flow *flow = &ctx->xin->flow;

    /* Ensure that any pending actions on the current packet are applied
     * before generating the decap action. */
    xlate_commit_actions(ctx);

    /* We assume for now that the new_pkt_type is PT_USE_NEXT_PROTO. */
    switch (ntohl(flow->packet_type)) {
        case PT_ETH:
            if (flow->vlans[0].tci & htons(VLAN_CFI)) {
                /* Error handling: drop packet. */
                xlate_report_debug(ctx, OFT_ACTION, "Dropping packet, cannot "
                                   "decap Ethernet if VLAN is present.");
                ctx->error = XLATE_UNSUPPORTED_PACKET_TYPE;
            } else {
                /* Just change the packet_type.
                 * Delay generating pop_eth to the next commit. */
                flow->packet_type = htonl(PACKET_TYPE(OFPHTN_ETHERTYPE,
                                                      ntohs(flow->dl_type)));
                ctx->wc->masks.dl_type = OVS_BE16_MAX;
            }
            return false;
        case PT_NSH:
            /* The pop_nsh action is generated at the commit executed as
             * part of freezing the ctx for recirculation. Here we just set
             * the new packet type based on the NSH next protocol field. */
            switch (flow->nsh.np) {
            case NSH_P_ETHERNET:
                flow->packet_type = htonl(PT_ETH);
                break;
            case NSH_P_IPV4:
                flow->packet_type = htonl(PT_IPV4);
                break;
            case NSH_P_IPV6:
                flow->packet_type = htonl(PT_IPV6);
                break;
            case NSH_P_NSH:
                flow->packet_type = htonl(PT_NSH);
                break;
            default:
                /* Error handling: drop packet. */
                xlate_report_debug(ctx, OFT_ACTION,
                                   "Dropping packet as NSH next protocol %d "
                                   "is not supported", flow->nsh.np);
                ctx->error = XLATE_UNSUPPORTED_PACKET_TYPE;
                return false;
                break;
            }
            ctx->wc->masks.nsh.np = UINT8_MAX;
            ctx->pending_decap = true;
            /* Trigger recirculation. */
            return true;
        default:
            /* Error handling: drop packet. */
            xlate_report_debug(
                    ctx, OFT_ACTION,
                    "Dropping packet as the decap() does not support "
                    "packet type (%d,0x%x)",
                    pt_ns(flow->packet_type), pt_ns_type(flow->packet_type));
            ctx->error = XLATE_UNSUPPORTED_PACKET_TYPE;
            return false;
    }
}

static void
recirc_for_mpls(const struct ofpact *a, struct xlate_ctx *ctx)
{
    /* No need to recirculate if already exiting. */
    if (ctx->exit) {
        return;
    }

    /* Do not consider recirculating unless the packet was previously MPLS. */
    if (!ctx->was_mpls) {
        return;
    }

    /* Special case these actions, only recirculating if necessary.
     * This avoids the overhead of recirculation in common use-cases.
     */
    switch (a->type) {

    /* Output actions  do not require recirculation. */
    case OFPACT_OUTPUT:
    case OFPACT_OUTPUT_TRUNC:
    case OFPACT_ENQUEUE:
    case OFPACT_OUTPUT_REG:
    /* Set actions that don't touch L3+ fields do not require recirculation. */
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    /* If actions of a group require recirculation that can be detected
     * when translating them. */
    case OFPACT_GROUP:
        return;

    /* Set field that don't touch L3+ fields don't require recirculation. */
    case OFPACT_SET_FIELD:
        if (mf_is_l3_or_higher(ofpact_get_SET_FIELD(a)->field)) {
            break;
        }
        return;

    /* For simplicity, recirculate in all other cases. */
    case OFPACT_CONTROLLER:
    case OFPACT_BUNDLE:
    case OFPACT_STRIP_VLAN:
    case OFPACT_PUSH_VLAN:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IP_DSCP:
    case OFPACT_SET_IP_ECN:
    case OFPACT_SET_IP_TTL:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_REG_MOVE:
    case OFPACT_STACK_PUSH:
    case OFPACT_STACK_POP:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_CONJUNCTION:
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_SAMPLE:
    case OFPACT_CLONE:
    case OFPACT_ENCAP:
    case OFPACT_DECAP:
    case OFPACT_DEC_NSH_TTL:
    case OFPACT_UNROLL_XLATE:
    case OFPACT_CT:
    case OFPACT_CT_CLEAR:
    case OFPACT_NAT:
    case OFPACT_DEBUG_RECIRC:
    case OFPACT_DEBUG_SLOW:
    case OFPACT_METER:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_WRITE_METADATA:
    case OFPACT_GOTO_TABLE:
    default:
        break;
    }

    /* Recirculate */
    ctx_trigger_freeze(ctx);
}

static void
xlate_ofpact_reg_move(struct xlate_ctx *ctx, const struct ofpact_reg_move *a)
{
    mf_subfield_copy(&a->src, &a->dst, &ctx->xin->flow, ctx->wc);
    xlate_report_subfield(ctx, &a->dst);
}

static void
xlate_ofpact_stack_pop(struct xlate_ctx *ctx, const struct ofpact_stack *a)
{
    if (nxm_execute_stack_pop(a, &ctx->xin->flow, ctx->wc, &ctx->stack)) {
        xlate_report_subfield(ctx, &a->subfield);
    } else {
        xlate_report_error(ctx, "stack underflow");
    }
}

/* Restore translation context data that was stored earlier. */
static void
xlate_ofpact_unroll_xlate(struct xlate_ctx *ctx,
                          const struct ofpact_unroll_xlate *a)
{
    ctx->table_id = a->rule_table_id;
    ctx->rule_cookie = a->rule_cookie;
    xlate_report(ctx, OFT_THAW, "restored state: table=%"PRIu8", "
                 "cookie=%#"PRIx64, a->rule_table_id, a->rule_cookie);
}

static void
do_xlate_actions(const struct ofpact *ofpacts, size_t ofpacts_len,
                 struct xlate_ctx *ctx, bool is_last_action)
{
    struct flow_wildcards *wc = ctx->wc;
    struct flow *flow = &ctx->xin->flow;
    const struct ofpact *a;

    /* dl_type already in the mask, not set below. */

    if (!ofpacts_len) {
        xlate_report(ctx, OFT_ACTION, "drop");
        return;
    }

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        struct ofpact_controller *controller;
        const struct ofpact_metadata *metadata;
        const struct ofpact_set_field *set_field;
        const struct mf_field *mf;
        bool last = is_last_action && ofpact_last(a, ofpacts, ofpacts_len)
                    && ctx->action_set.size;

        if (ctx->error) {
            break;
        }

        recirc_for_mpls(a, ctx);

        if (ctx->exit) {
            /* Check if need to store the remaining actions for later
             * execution. */
            if (ctx->freezing) {
                freeze_unroll_actions(a, ofpact_end(ofpacts, ofpacts_len),
                                      ctx);
            }
            break;
        }

        if (OVS_UNLIKELY(ctx->xin->trace)) {
            struct ds s = DS_EMPTY_INITIALIZER;
            struct ofpact_format_params fp = { .s = &s };
            ofpacts_format(a, OFPACT_ALIGN(a->len), &fp);
            xlate_report(ctx, OFT_ACTION, "%s", ds_cstr(&s));
            ds_destroy(&s);
        }

        switch (a->type) {
        case OFPACT_OUTPUT:
            xlate_output_action(ctx, ofpact_get_OUTPUT(a)->port,
                                ofpact_get_OUTPUT(a)->max_len, true, last,
                                false);
            break;

        case OFPACT_GROUP:
            if (xlate_group_action(ctx, ofpact_get_GROUP(a)->group_id, last)) {
                /* Group could not be found. */

                /* XXX: Terminates action list translation, but does not
                 * terminate the pipeline. */
                return;
            }
            break;

        case OFPACT_CONTROLLER:
            controller = ofpact_get_CONTROLLER(a);
            if (controller->pause) {
                ctx->pause = controller;
                ctx_trigger_freeze(ctx);
                a = ofpact_next(a);
            } else {
                xlate_controller_action(ctx, controller->max_len,
                                        controller->reason,
                                        controller->controller_id,
                                        controller->userdata,
                                        controller->userdata_len);
            }
            break;

        case OFPACT_ENQUEUE:
            memset(&wc->masks.skb_priority, 0xff,
                   sizeof wc->masks.skb_priority);
            xlate_enqueue_action(ctx, ofpact_get_ENQUEUE(a), last);
            break;

        case OFPACT_SET_VLAN_VID:
            wc->masks.vlans[0].tci |= htons(VLAN_VID_MASK | VLAN_CFI);
            if (flow->vlans[0].tci & htons(VLAN_CFI) ||
                ofpact_get_SET_VLAN_VID(a)->push_vlan_if_needed) {
                if (!flow->vlans[0].tpid) {
                    flow->vlans[0].tpid = htons(ETH_TYPE_VLAN);
                }
                flow->vlans[0].tci &= ~htons(VLAN_VID_MASK);
                flow->vlans[0].tci |=
                    (htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid) |
                     htons(VLAN_CFI));
            }
            break;

        case OFPACT_SET_VLAN_PCP:
            wc->masks.vlans[0].tci |= htons(VLAN_PCP_MASK | VLAN_CFI);
            if (flow->vlans[0].tci & htons(VLAN_CFI) ||
                ofpact_get_SET_VLAN_PCP(a)->push_vlan_if_needed) {
                if (!flow->vlans[0].tpid) {
                    flow->vlans[0].tpid = htons(ETH_TYPE_VLAN);
                }
                flow->vlans[0].tci &= ~htons(VLAN_PCP_MASK);
                flow->vlans[0].tci |=
                    htons((ofpact_get_SET_VLAN_PCP(a)->vlan_pcp
                           << VLAN_PCP_SHIFT) | VLAN_CFI);
            }
            break;

        case OFPACT_STRIP_VLAN:
            flow_pop_vlan(flow, wc);
            break;

        case OFPACT_PUSH_VLAN:
            flow_push_vlan_uninit(flow, wc);
            flow->vlans[0].tpid = ofpact_get_PUSH_VLAN(a)->ethertype;
            flow->vlans[0].tci = htons(VLAN_CFI);
            break;

        case OFPACT_SET_ETH_SRC:
            WC_MASK_FIELD(wc, dl_src);
            flow->dl_src = ofpact_get_SET_ETH_SRC(a)->mac;
            break;

        case OFPACT_SET_ETH_DST:
            WC_MASK_FIELD(wc, dl_dst);
            flow->dl_dst = ofpact_get_SET_ETH_DST(a)->mac;
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
            if (is_ip_any(flow) && !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
                memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
                memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
                flow->tp_src = htons(ofpact_get_SET_L4_SRC_PORT(a)->port);
            }
            break;

        case OFPACT_SET_L4_DST_PORT:
            if (is_ip_any(flow) && !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
                memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
                memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
                flow->tp_dst = htons(ofpact_get_SET_L4_DST_PORT(a)->port);
            }
            break;

        case OFPACT_RESUBMIT:
            /* Freezing complicates resubmit.  Some action in the flow
             * entry found by resubmit might trigger freezing.  If that
             * happens, then we do not want to execute the resubmit again after
             * during thawing, so we want to skip back to the head of the loop
             * to avoid that, only adding any actions that follow the resubmit
             * to the frozen actions.
             */
            xlate_ofpact_resubmit(ctx, ofpact_get_RESUBMIT(a), last);
            continue;

        case OFPACT_SET_TUNNEL:
            flow->tunnel.tun_id = htonll(ofpact_get_SET_TUNNEL(a)->tun_id);
            break;

        case OFPACT_SET_QUEUE:
            memset(&wc->masks.skb_priority, 0xff,
                   sizeof wc->masks.skb_priority);
            xlate_set_queue_action(ctx, ofpact_get_SET_QUEUE(a)->queue_id);
            break;

        case OFPACT_POP_QUEUE:
            memset(&wc->masks.skb_priority, 0xff,
                   sizeof wc->masks.skb_priority);
            if (flow->skb_priority != ctx->orig_skb_priority) {
                flow->skb_priority = ctx->orig_skb_priority;
                xlate_report(ctx, OFT_DETAIL, "queue = %#"PRIx32,
                             flow->skb_priority);
            }
            break;

        case OFPACT_REG_MOVE:
            xlate_ofpact_reg_move(ctx, ofpact_get_REG_MOVE(a));
            break;

        case OFPACT_SET_FIELD:
            set_field = ofpact_get_SET_FIELD(a);
            mf = set_field->field;

            /* Set the field only if the packet actually has it. */
            if (mf_are_prereqs_ok(mf, flow, wc)) {
                mf_mask_field_masked(mf, ofpact_set_field_mask(set_field), wc);
                mf_set_flow_value_masked(mf, set_field->value,
                                         ofpact_set_field_mask(set_field),
                                         flow);
            } else {
                xlate_report(ctx, OFT_WARN,
                             "unmet prerequisites for %s, set_field ignored",
                             mf->name);

            }
            break;

        case OFPACT_STACK_PUSH:
            nxm_execute_stack_push(ofpact_get_STACK_PUSH(a), flow, wc,
                                   &ctx->stack);
            break;

        case OFPACT_STACK_POP:
            xlate_ofpact_stack_pop(ctx, ofpact_get_STACK_POP(a));
            break;

        case OFPACT_PUSH_MPLS:
            compose_mpls_push_action(ctx, ofpact_get_PUSH_MPLS(a));
            break;

        case OFPACT_POP_MPLS:
            compose_mpls_pop_action(ctx, ofpact_get_POP_MPLS(a)->ethertype);
            break;

        case OFPACT_SET_MPLS_LABEL:
            compose_set_mpls_label_action(
                ctx, ofpact_get_SET_MPLS_LABEL(a)->label);
            break;

        case OFPACT_SET_MPLS_TC:
            compose_set_mpls_tc_action(ctx, ofpact_get_SET_MPLS_TC(a)->tc);
            break;

        case OFPACT_SET_MPLS_TTL:
            compose_set_mpls_ttl_action(ctx, ofpact_get_SET_MPLS_TTL(a)->ttl);
            break;

        case OFPACT_DEC_MPLS_TTL:
            if (compose_dec_mpls_ttl_action(ctx)) {
                return;
            }
            break;

        case OFPACT_DEC_NSH_TTL:
            if (compose_dec_nsh_ttl_action(ctx)) {
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
            xlate_report_subfield(ctx, &ofpact_get_MULTIPATH(a)->dst);
            break;

        case OFPACT_BUNDLE:
            xlate_bundle_action(ctx, ofpact_get_BUNDLE(a), last);
            break;

        case OFPACT_OUTPUT_REG:
            xlate_output_reg_action(ctx, ofpact_get_OUTPUT_REG(a), last);
            break;

        case OFPACT_OUTPUT_TRUNC:
            xlate_output_trunc_action(ctx, ofpact_get_OUTPUT_TRUNC(a)->port,
                                ofpact_get_OUTPUT_TRUNC(a)->max_len, last);
            break;

        case OFPACT_LEARN:
            xlate_learn_action(ctx, ofpact_get_LEARN(a));
            break;

        case OFPACT_CONJUNCTION:
            /* A flow with a "conjunction" action represents part of a special
             * kind of "set membership match".  Such a flow should not actually
             * get executed, but it could via, say, a "packet-out", even though
             * that wouldn't be useful.  Log it to help debugging. */
            xlate_report_error(ctx, "executing no-op conjunction action");
            break;

        case OFPACT_EXIT:
            ctx->exit = true;
            break;

        case OFPACT_UNROLL_XLATE:
            xlate_ofpact_unroll_xlate(ctx, ofpact_get_UNROLL_XLATE(a));
            break;

        case OFPACT_FIN_TIMEOUT:
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
            xlate_fin_timeout(ctx, ofpact_get_FIN_TIMEOUT(a));
            break;

        case OFPACT_CLEAR_ACTIONS:
            xlate_report_action_set(ctx, "was");
            ofpbuf_clear(&ctx->action_set);
            ctx->xin->flow.actset_output = OFPP_UNSET;
            ctx->action_set_has_group = false;
            break;

        case OFPACT_WRITE_ACTIONS:
            xlate_write_actions(ctx, ofpact_get_WRITE_ACTIONS(a));
            xlate_report_action_set(ctx, "is");
            break;

        case OFPACT_WRITE_METADATA:
            metadata = ofpact_get_WRITE_METADATA(a);
            flow->metadata &= ~metadata->mask;
            flow->metadata |= metadata->metadata & metadata->mask;
            break;

        case OFPACT_METER:
            xlate_meter_action(ctx, ofpact_get_METER(a));
            break;

        case OFPACT_GOTO_TABLE: {
            struct ofpact_goto_table *ogt = ofpact_get_GOTO_TABLE(a);

            ovs_assert(ctx->table_id < ogt->table_id);

            xlate_table_action(ctx, ctx->xin->flow.in_port.ofp_port,
                               ogt->table_id, true, true, false, last,
                               do_xlate_actions);
            break;
        }

        case OFPACT_SAMPLE:
            xlate_sample_action(ctx, ofpact_get_SAMPLE(a));
            break;

        case OFPACT_CLONE:
            compose_clone(ctx, ofpact_get_CLONE(a), last);
            break;

        case OFPACT_ENCAP:
            xlate_generic_encap_action(ctx, ofpact_get_ENCAP(a));
            break;

        case OFPACT_DECAP: {
            bool recirc_needed =
                    xlate_generic_decap_action(ctx, ofpact_get_DECAP(a));
            if (!ctx->error && recirc_needed) {
                /* Recirculate for parsing of inner packet. */
                ctx_trigger_freeze(ctx);
                /* Then continue with next action. */
                a = ofpact_next(a);
            }
            break;
        }

        case OFPACT_CT:
            compose_conntrack_action(ctx, ofpact_get_CT(a), last);
            break;

        case OFPACT_CT_CLEAR:
            compose_ct_clear_action(ctx);
            break;

        case OFPACT_NAT:
            /* This will be processed by compose_conntrack_action(). */
            ctx->ct_nat_action = ofpact_get_NAT(a);
            break;

        case OFPACT_DEBUG_RECIRC:
            ctx_trigger_freeze(ctx);
            a = ofpact_next(a);
            break;

        case OFPACT_DEBUG_SLOW:
            ctx->xout->slow |= SLOW_ACTION;
            break;
        }

        /* Check if need to store this and the remaining actions for later
         * execution. */
        if (!ctx->error && ctx->exit && ctx_first_frozen_action(ctx)) {
            freeze_unroll_actions(a, ofpact_end(ofpacts, ofpacts_len), ctx);
            break;
        }
    }
}

void
xlate_in_init(struct xlate_in *xin, struct ofproto_dpif *ofproto,
              ovs_version_t version, const struct flow *flow,
              ofp_port_t in_port, struct rule_dpif *rule, uint16_t tcp_flags,
              const struct dp_packet *packet, struct flow_wildcards *wc,
              struct ofpbuf *odp_actions)
{
    xin->ofproto = ofproto;
    xin->tables_version = version;
    xin->flow = *flow;
    xin->upcall_flow = flow;
    xin->flow.in_port.ofp_port = in_port;
    xin->flow.actset_output = OFPP_UNSET;
    xin->packet = packet;
    xin->allow_side_effects = packet != NULL;
    xin->rule = rule;
    xin->xcache = NULL;
    xin->ofpacts = NULL;
    xin->ofpacts_len = 0;
    xin->tcp_flags = tcp_flags;
    xin->trace = NULL;
    xin->resubmit_stats = NULL;
    xin->depth = 0;
    xin->resubmits = 0;
    xin->wc = wc;
    xin->odp_actions = odp_actions;
    xin->in_packet_out = false;
    xin->recirc_queue = NULL;
    xin->xport_uuid = UUID_ZERO;

    /* Do recirc lookup. */
    xin->frozen_state = NULL;
    if (flow->recirc_id) {
        const struct recirc_id_node *node
            = recirc_id_node_find(flow->recirc_id);
        if (node) {
            xin->frozen_state = &node->state;
        }
    }
}

void
xlate_out_uninit(struct xlate_out *xout)
{
    if (xout) {
        recirc_refs_unref(&xout->recircs);
    }
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

static size_t
count_skb_priorities(const struct xport *xport)
{
    return hmap_count(&xport->skb_priorities);
}

static void
clear_skb_priorities(struct xport *xport)
{
    struct skb_priority_to_dscp *pdscp;

    HMAP_FOR_EACH_POP (pdscp, hmap_node, &xport->skb_priorities) {
        free(pdscp);
    }
}

static bool
actions_output_to_local_port(const struct xlate_ctx *ctx)
{
    odp_port_t local_odp_port = ofp_port_to_odp_port(ctx->xbridge, OFPP_LOCAL);
    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, ctx->odp_actions->data,
                             ctx->odp_actions->size) {
        if (nl_attr_type(a) == OVS_ACTION_ATTR_OUTPUT
            && nl_attr_get_odp_port(a) == local_odp_port) {
            return true;
        }
    }
    return false;
}

#if defined(__linux__)
/* Returns the maximum number of packets that the Linux kernel is willing to
 * queue up internally to certain kinds of software-implemented ports, or the
 * default (and rarely modified) value if it cannot be determined. */
static int
netdev_max_backlog(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int max_backlog = 1000; /* The normal default value. */

    if (ovsthread_once_start(&once)) {
        static const char filename[] = "/proc/sys/net/core/netdev_max_backlog";
        FILE *stream;
        int n;

        stream = fopen(filename, "r");
        if (!stream) {
            VLOG_INFO("%s: open failed (%s)", filename, ovs_strerror(errno));
        } else {
            if (fscanf(stream, "%d", &n) != 1) {
                VLOG_WARN("%s: read error", filename);
            } else if (n <= 100) {
                VLOG_WARN("%s: unexpectedly small value %d", filename, n);
            } else {
                max_backlog = n;
            }
            fclose(stream);
        }
        ovsthread_once_done(&once);

        VLOG_DBG("%s: using %d max_backlog", filename, max_backlog);
    }

    return max_backlog;
}

/* Counts and returns the number of OVS_ACTION_ATTR_OUTPUT actions in
 * 'odp_actions'. */
static int
count_output_actions(const struct ofpbuf *odp_actions)
{
    const struct nlattr *a;
    size_t left;
    int n = 0;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, odp_actions->data, odp_actions->size) {
        if (a->nla_type == OVS_ACTION_ATTR_OUTPUT) {
            n++;
        }
    }
    return n;
}
#endif /* defined(__linux__) */

/* Returns true if 'odp_actions' contains more output actions than the datapath
 * can reliably handle in one go.  On Linux, this is the value of the
 * net.core.netdev_max_backlog sysctl, which limits the maximum number of
 * packets that the kernel is willing to queue up for processing while the
 * datapath is processing a set of actions. */
static bool
too_many_output_actions(const struct ofpbuf *odp_actions OVS_UNUSED)
{
#ifdef __linux__
    return (odp_actions->size / NL_A_U32_SIZE > netdev_max_backlog()
            && count_output_actions(odp_actions) > netdev_max_backlog());
#else
    /* OSes other than Linux might have similar limits, but we don't know how
     * to determine them.*/
    return false;
#endif
}

static void
xlate_wc_init(struct xlate_ctx *ctx)
{
    flow_wildcards_init_catchall(ctx->wc);

    /* Some fields we consider to always be examined. */
    WC_MASK_FIELD(ctx->wc, packet_type);
    WC_MASK_FIELD(ctx->wc, in_port);
    if (is_ethernet(&ctx->xin->flow, NULL)) {
        WC_MASK_FIELD(ctx->wc, dl_type);
    }
    if (is_ip_any(&ctx->xin->flow)) {
        WC_MASK_FIELD_MASK(ctx->wc, nw_frag, FLOW_NW_FRAG_MASK);
    }

    if (ctx->xbridge->support.odp.recirc) {
        /* Always exactly match recirc_id when datapath supports
         * recirculation.  */
        WC_MASK_FIELD(ctx->wc, recirc_id);
    }

    if (ctx->xbridge->netflow) {
        netflow_mask_wc(&ctx->xin->flow, ctx->wc);
    }

    tnl_wc_init(&ctx->xin->flow, ctx->wc);
}

static void
xlate_wc_finish(struct xlate_ctx *ctx)
{
    int i;

    /* Clear the metadata and register wildcard masks, because we won't
     * use non-header fields as part of the cache. */
    flow_wildcards_clear_non_packet_fields(ctx->wc);

    /* Wildcard ethernet fields if the original packet type was not
     * Ethernet. */
    if (ctx->xin->upcall_flow->packet_type != htonl(PT_ETH)) {
        ctx->wc->masks.dl_dst = eth_addr_zero;
        ctx->wc->masks.dl_src = eth_addr_zero;
        ctx->wc->masks.dl_type = 0;
    }

    /* ICMPv4 and ICMPv6 have 8-bit "type" and "code" fields.  struct flow
     * uses the low 8 bits of the 16-bit tp_src and tp_dst members to
     * represent these fields.  The datapath interface, on the other hand,
     * represents them with just 8 bits each.  This means that if the high
     * 8 bits of the masks for these fields somehow become set, then they
     * will get chopped off by a round trip through the datapath, and
     * revalidation will spot that as an inconsistency and delete the flow.
     * Avoid the problem here by making sure that only the low 8 bits of
     * either field can be unwildcarded for ICMP.
     */
    if (is_icmpv4(&ctx->xin->flow, NULL) || is_icmpv6(&ctx->xin->flow, NULL)) {
        ctx->wc->masks.tp_src &= htons(UINT8_MAX);
        ctx->wc->masks.tp_dst &= htons(UINT8_MAX);
    }
    /* VLAN_TCI CFI bit must be matched if any of the TCI is matched. */
    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        if (ctx->wc->masks.vlans[i].tci) {
            ctx->wc->masks.vlans[i].tci |= htons(VLAN_CFI);
        }
    }

    /* The classifier might return masks that match on tp_src and tp_dst even
     * for later fragments.  This happens because there might be flows that
     * match on tp_src or tp_dst without matching on the frag bits, because
     * it is not a prerequisite for OpenFlow.  Since it is a prerequisite for
     * datapath flows and since tp_src and tp_dst are always going to be 0,
     * wildcard the fields here. */
    if (ctx->xin->flow.nw_frag & FLOW_NW_FRAG_LATER) {
        ctx->wc->masks.tp_src = 0;
        ctx->wc->masks.tp_dst = 0;
    }
}

/* Translates the flow, actions, or rule in 'xin' into datapath actions in
 * 'xout'.
 * The caller must take responsibility for eventually freeing 'xout', with
 * xlate_out_uninit().
 * Returns 'XLATE_OK' if translation was successful.  In case of an error an
 * empty set of actions will be returned in 'xin->odp_actions' (if non-NULL),
 * so that most callers may ignore the return value and transparently install a
 * drop flow when the translation fails. */
enum xlate_error
xlate_actions(struct xlate_in *xin, struct xlate_out *xout)
{
    *xout = (struct xlate_out) {
        .slow = 0,
        .recircs = RECIRC_REFS_EMPTY_INITIALIZER,
    };

    struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    struct xbridge *xbridge = xbridge_lookup(xcfg, xin->ofproto);
    if (!xbridge) {
        return XLATE_BRIDGE_NOT_FOUND;
    }

    struct flow *flow = &xin->flow;

    uint8_t stack_stub[1024];
    uint64_t action_set_stub[1024 / 8];
    uint64_t frozen_actions_stub[1024 / 8];
    uint64_t actions_stub[256 / 8];
    struct ofpbuf scratch_actions = OFPBUF_STUB_INITIALIZER(actions_stub);
    struct xlate_ctx ctx = {
        .xin = xin,
        .xout = xout,
        .base_flow = *flow,
        .orig_tunnel_ipv6_dst = flow_tnl_dst(&flow->tunnel),
        .xcfg = xcfg,
        .xbridge = xbridge,
        .stack = OFPBUF_STUB_INITIALIZER(stack_stub),
        .rule = xin->rule,
        .wc = (xin->wc
               ? xin->wc
               : &(struct flow_wildcards) { .masks = { .dl_type = 0 } }),
        .odp_actions = xin->odp_actions ? xin->odp_actions : &scratch_actions,

        .depth = xin->depth,
        .resubmits = xin->resubmits,
        .in_group = false,
        .in_action_set = false,
        .in_packet_out = xin->in_packet_out,
        .pending_encap = false,
        .pending_decap = false,
        .encap_data = NULL,

        .table_id = 0,
        .rule_cookie = OVS_BE64_MAX,
        .orig_skb_priority = flow->skb_priority,
        .sflow_n_outputs = 0,
        .sflow_odp_port = 0,
        .nf_output_iface = NF_OUT_DROP,
        .exit = false,
        .error = XLATE_OK,
        .mirrors = 0,

        .freezing = false,
        .recirc_update_dp_hash = false,
        .frozen_actions = OFPBUF_STUB_INITIALIZER(frozen_actions_stub),
        .pause = NULL,

        .was_mpls = false,
        .conntracked = false,

        .ct_nat_action = NULL,

        .action_set_has_group = false,
        .action_set = OFPBUF_STUB_INITIALIZER(action_set_stub),
    };

    /* 'base_flow' reflects the packet as it came in, but we need it to reflect
     * the packet as the datapath will treat it for output actions. Our
     * datapath doesn't retain tunneling information without us re-setting
     * it, so clear the tunnel data.
     */

    memset(&ctx.base_flow.tunnel, 0, sizeof ctx.base_flow.tunnel);

    ofpbuf_reserve(ctx.odp_actions, NL_A_U32_SIZE);
    xlate_wc_init(&ctx);

    COVERAGE_INC(xlate_actions);

    xin->trace = xlate_report(&ctx, OFT_BRIDGE, "bridge(\"%s\")",
                              xbridge->name);
    if (xin->frozen_state) {
        const struct frozen_state *state = xin->frozen_state;

        struct ovs_list *old_trace = xin->trace;
        xin->trace = xlate_report(&ctx, OFT_THAW, "thaw");

        if (xin->ofpacts_len > 0 || ctx.rule) {
            xlate_report_error(&ctx, "Recirculation conflict (%s)!",
                               xin->ofpacts_len ? "actions" : "rule");
            ctx.error = XLATE_RECIRCULATION_CONFLICT;
            goto exit;
        }

        /* Set the bridge for post-recirculation processing if needed. */
        if (!uuid_equals(&ctx.xbridge->ofproto->uuid, &state->ofproto_uuid)) {
            const struct xbridge *new_bridge
                = xbridge_lookup_by_uuid(xcfg, &state->ofproto_uuid);

            if (OVS_UNLIKELY(!new_bridge)) {
                /* Drop the packet if the bridge cannot be found. */
                xlate_report_error(&ctx, "Frozen bridge no longer exists.");
                ctx.error = XLATE_BRIDGE_NOT_FOUND;
                xin->trace = old_trace;
                goto exit;
            }
            ctx.xbridge = new_bridge;
            /* The bridge is now known so obtain its table version. */
            ctx.xin->tables_version
                = ofproto_dpif_get_tables_version(ctx.xbridge->ofproto);
        }

        /* Set the thawed table id.  Note: A table lookup is done only if there
         * are no frozen actions. */
        ctx.table_id = state->table_id;
        xlate_report(&ctx, OFT_THAW,
                     "Resuming from table %"PRIu8, ctx.table_id);

        ctx.conntracked = state->conntracked;
        if (!state->conntracked) {
            clear_conntrack(&ctx);
        }

        /* Restore pipeline metadata. May change flow's in_port and other
         * metadata to the values that existed when freezing was triggered. */
        frozen_metadata_to_flow(&state->metadata, flow);

        /* Restore stack, if any. */
        if (state->stack) {
            ofpbuf_put(&ctx.stack, state->stack, state->stack_size);
        }

        /* Restore mirror state. */
        ctx.mirrors = state->mirrors;

        /* Restore action set, if any. */
        if (state->action_set_len) {
            xlate_report_actions(&ctx, OFT_THAW, "Restoring action set",
                                 state->action_set, state->action_set_len);

            flow->actset_output = OFPP_UNSET;
            xlate_write_actions__(&ctx, state->action_set,
                                  state->action_set_len);
        }

        /* Restore frozen actions.  If there are no actions, processing will
         * start with a lookup in the table set above. */
        xin->ofpacts = state->ofpacts;
        xin->ofpacts_len = state->ofpacts_len;
        if (state->ofpacts_len) {
            xlate_report_actions(&ctx, OFT_THAW, "Restoring actions",
                                 xin->ofpacts, xin->ofpacts_len);
        }

        xin->trace = old_trace;
    } else if (OVS_UNLIKELY(flow->recirc_id)) {
        xlate_report_error(&ctx,
                           "Recirculation context not found for ID %"PRIx32,
                           flow->recirc_id);
        ctx.error = XLATE_NO_RECIRCULATION_CONTEXT;
        goto exit;
    }

    /* Tunnel metadata in udpif format must be normalized before translation. */
    if (flow->tunnel.flags & FLOW_TNL_F_UDPIF) {
        const struct tun_table *tun_tab = ofproto_get_tun_tab(
            &ctx.xbridge->ofproto->up);
        int err;

        err = tun_metadata_from_geneve_udpif(tun_tab, &xin->upcall_flow->tunnel,
                                             &xin->upcall_flow->tunnel,
                                             &flow->tunnel);
        if (err) {
            xlate_report_error(&ctx, "Invalid Geneve tunnel metadata");
            ctx.error = XLATE_INVALID_TUNNEL_METADATA;
            goto exit;
        }
    } else if (!flow->tunnel.metadata.tab || xin->frozen_state) {
        /* If the original flow did not come in on a tunnel, then it won't have
         * FLOW_TNL_F_UDPIF set. However, we still need to have a metadata
         * table in case we generate tunnel actions. */
        /* If the translation is from a frozen state, we use the latest
         * TLV map to avoid segmentation fault in case the old TLV map is
         * replaced by a new one.
         * XXX: It is better to abort translation if the table is changed. */
        flow->tunnel.metadata.tab = ofproto_get_tun_tab(
            &ctx.xbridge->ofproto->up);
    }
    ctx.wc->masks.tunnel.metadata.tab = flow->tunnel.metadata.tab;

    /* Get the proximate input port of the packet.  (If xin->frozen_state,
     * flow->in_port is the ultimate input port of the packet.) */
    struct xport *in_port = get_ofp_port(xbridge,
                                         ctx.base_flow.in_port.ofp_port);
    if (in_port && !in_port->peer) {
        ctx.xin->xport_uuid = in_port->uuid;
    }

    if (flow->packet_type != htonl(PT_ETH) && in_port &&
        in_port->pt_mode == NETDEV_PT_LEGACY_L3 && ctx.table_id == 0) {
        /* Add dummy Ethernet header to non-L2 packet if it's coming from a
         * L3 port. So all packets will be L2 packets for lookup.
         * The dl_type has already been set from the packet_type. */
        flow->packet_type = htonl(PT_ETH);
        flow->dl_src = eth_addr_zero;
        flow->dl_dst = eth_addr_zero;
        ctx.pending_encap = true;
    }

    if (!xin->ofpacts && !ctx.rule) {
        ctx.rule = rule_dpif_lookup_from_table(
            ctx.xbridge->ofproto, ctx.xin->tables_version, flow, ctx.wc,
            ctx.xin->resubmit_stats, &ctx.table_id,
            flow->in_port.ofp_port, true, true, ctx.xin->xcache);
        if (ctx.xin->resubmit_stats) {
            rule_dpif_credit_stats(ctx.rule, ctx.xin->resubmit_stats);
        }
        if (ctx.xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx.xin->xcache, XC_RULE);
            entry->rule = ctx.rule;
            ofproto_rule_ref(&ctx.rule->up);
        }

        xlate_report_table(&ctx, ctx.rule, ctx.table_id);
    }

    /* Tunnel stats only for not-thawed packets. */
    if (!xin->frozen_state && in_port && in_port->is_tunnel) {
        if (ctx.xin->resubmit_stats) {
            netdev_vport_inc_rx(in_port->netdev, ctx.xin->resubmit_stats);
            if (in_port->bfd) {
                bfd_account_rx(in_port->bfd, ctx.xin->resubmit_stats);
            }
        }
        if (ctx.xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx.xin->xcache, XC_NETDEV);
            entry->dev.rx = netdev_ref(in_port->netdev);
            entry->dev.bfd = bfd_ref(in_port->bfd);
        }
    }

    if (!xin->frozen_state && process_special(&ctx, in_port)) {
        /* process_special() did all the processing for this packet.
         *
         * We do not perform special processing on thawed packets, since that
         * was done before they were frozen and should not be redone. */
    } else if (in_port && in_port->xbundle
               && xbundle_mirror_out(xbridge, in_port->xbundle)) {
        xlate_report_error(&ctx, "dropping packet received on port "
                           "%s, which is reserved exclusively for mirroring",
                           in_port->xbundle->name);
    } else {
        /* Sampling is done on initial reception; don't redo after thawing. */
        unsigned int user_cookie_offset = 0;
        if (!xin->frozen_state) {
            user_cookie_offset = compose_sflow_action(&ctx);
            compose_ipfix_action(&ctx, ODPP_NONE);
        }
        size_t sample_actions_len = ctx.odp_actions->size;

        if (tnl_process_ecn(flow)
            && (!in_port || may_receive(in_port, &ctx))) {
            const struct ofpact *ofpacts;
            size_t ofpacts_len;

            if (xin->ofpacts) {
                ofpacts = xin->ofpacts;
                ofpacts_len = xin->ofpacts_len;
            } else if (ctx.rule) {
                const struct rule_actions *actions
                    = rule_get_actions(&ctx.rule->up);
                ofpacts = actions->ofpacts;
                ofpacts_len = actions->ofpacts_len;
                ctx.rule_cookie = ctx.rule->up.flow_cookie;
            } else {
                OVS_NOT_REACHED();
            }

            mirror_ingress_packet(&ctx);
            do_xlate_actions(ofpacts, ofpacts_len, &ctx, true);
            if (ctx.error) {
                goto exit;
            }

            /* We've let OFPP_NORMAL and the learning action look at the
             * packet, so cancel all actions and freezing if forwarding is
             * disabled. */
            if (in_port && (!xport_stp_forward_state(in_port) ||
                            !xport_rstp_forward_state(in_port))) {
                ctx.odp_actions->size = sample_actions_len;
                ctx_cancel_freeze(&ctx);
                ofpbuf_clear(&ctx.action_set);
            }

            if (!ctx.freezing) {
                xlate_action_set(&ctx);
            }
            if (ctx.freezing) {
                finish_freezing(&ctx);
            }
        }

        /* Output only fully processed packets. */
        if (!ctx.freezing
            && xbridge->has_in_band
            && in_band_must_output_to_local_port(flow)
            && !actions_output_to_local_port(&ctx)) {
            compose_output_action(&ctx, OFPP_LOCAL, NULL, false, false);
        }

        if (user_cookie_offset) {
            fix_sflow_action(&ctx, user_cookie_offset);
        }
    }

    if (nl_attr_oversized(ctx.odp_actions->size)) {
        /* These datapath actions are too big for a Netlink attribute, so we
         * can't hand them to the kernel directly.  dpif_execute() can execute
         * them one by one with help, so just mark the result as SLOW_ACTION to
         * prevent the flow from being installed. */
        COVERAGE_INC(xlate_actions_oversize);
        ctx.xout->slow |= SLOW_ACTION;
    } else if (too_many_output_actions(ctx.odp_actions)) {
        COVERAGE_INC(xlate_actions_too_many_output);
        ctx.xout->slow |= SLOW_ACTION;
    }

    /* Update NetFlow for non-frozen traffic. */
    if (xbridge->netflow && !xin->frozen_state) {
        if (ctx.xin->resubmit_stats) {
            netflow_flow_update(xbridge->netflow, flow,
                                ctx.nf_output_iface,
                                ctx.xin->resubmit_stats);
        }
        if (ctx.xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx.xin->xcache, XC_NETFLOW);
            entry->nf.netflow = netflow_ref(xbridge->netflow);
            entry->nf.flow = xmemdup(flow, sizeof *flow);
            entry->nf.iface = ctx.nf_output_iface;
        }
    }

    /* Translate tunnel metadata masks to udpif format if necessary. */
    if (xin->upcall_flow->tunnel.flags & FLOW_TNL_F_UDPIF) {
        if (ctx.wc->masks.tunnel.metadata.present.map) {
            const struct flow_tnl *upcall_tnl = &xin->upcall_flow->tunnel;
            struct geneve_opt opts[TLV_TOT_OPT_SIZE /
                                   sizeof(struct geneve_opt)];

            tun_metadata_to_geneve_udpif_mask(&flow->tunnel,
                                              &ctx.wc->masks.tunnel,
                                              upcall_tnl->metadata.opts.gnv,
                                              upcall_tnl->metadata.present.len,
                                              opts);
             memset(&ctx.wc->masks.tunnel.metadata, 0,
                    sizeof ctx.wc->masks.tunnel.metadata);
             memcpy(&ctx.wc->masks.tunnel.metadata.opts.gnv, opts,
                    upcall_tnl->metadata.present.len);
        }
        ctx.wc->masks.tunnel.metadata.present.len = 0xff;
        ctx.wc->masks.tunnel.metadata.tab = NULL;
        ctx.wc->masks.tunnel.flags |= FLOW_TNL_F_UDPIF;
    } else if (!xin->upcall_flow->tunnel.metadata.tab) {
        /* If we didn't have options in UDPIF format and didn't have an existing
         * metadata table, then it means that there were no options at all when
         * we started processing and any wildcards we picked up were from
         * action generation. Without options on the incoming packet, wildcards
         * aren't meaningful. To avoid them possibly getting misinterpreted,
         * just clear everything. */
        if (ctx.wc->masks.tunnel.metadata.present.map) {
            memset(&ctx.wc->masks.tunnel.metadata, 0,
                   sizeof ctx.wc->masks.tunnel.metadata);
        } else {
            ctx.wc->masks.tunnel.metadata.tab = NULL;
        }
    }

    xlate_wc_finish(&ctx);

exit:
    /* Reset the table to what it was when we came in. If we only fetched
     * it locally, then it has no meaning outside of flow translation. */
    flow->tunnel.metadata.tab = xin->upcall_flow->tunnel.metadata.tab;

    ofpbuf_uninit(&ctx.stack);
    ofpbuf_uninit(&ctx.action_set);
    ofpbuf_uninit(&ctx.frozen_actions);
    ofpbuf_uninit(&scratch_actions);
    ofpbuf_delete(ctx.encap_data);

    /* Make sure we return a "drop flow" in case of an error. */
    if (ctx.error) {
        xout->slow = 0;
        if (xin->odp_actions) {
            ofpbuf_clear(xin->odp_actions);
        }
    }
    return ctx.error;
}

enum ofperr
xlate_resume(struct ofproto_dpif *ofproto,
             const struct ofputil_packet_in_private *pin,
             struct ofpbuf *odp_actions,
             enum slow_path_reason *slow)
{
    struct dp_packet packet;
    dp_packet_use_const(&packet, pin->base.packet,
                        pin->base.packet_len);

    struct flow flow;
    flow_extract(&packet, &flow);

    struct xlate_in xin;
    xlate_in_init(&xin, ofproto, ofproto_dpif_get_tables_version(ofproto),
                  &flow, 0, NULL, ntohs(flow.tcp_flags),
                  &packet, NULL, odp_actions);

    struct ofpact_note noop;
    ofpact_init_NOTE(&noop);
    noop.length = 0;

    bool any_actions = pin->actions_len > 0;
    struct frozen_state state = {
        .table_id = 0,     /* Not the table where NXAST_PAUSE was executed. */
        .ofproto_uuid = pin->bridge,
        .stack = pin->stack,
        .stack_size = pin->stack_size,
        .mirrors = pin->mirrors,
        .conntracked = pin->conntracked,
        .xport_uuid = UUID_ZERO,

        /* When there are no actions, xlate_actions() will search the flow
         * table.  We don't want it to do that (we want it to resume), so
         * supply a no-op action if there aren't any.
         *
         * (We can't necessarily avoid translating actions entirely if there
         * aren't any actions, because there might be some finishing-up to do
         * at the end of the pipeline, and we don't check for those
         * conditions.) */
        .ofpacts = any_actions ? pin->actions : &noop.ofpact,
        .ofpacts_len = any_actions ? pin->actions_len : sizeof noop,

        .action_set = pin->action_set,
        .action_set_len = pin->action_set_len,
    };
    frozen_metadata_from_flow(&state.metadata,
                              &pin->base.flow_metadata.flow);
    xin.frozen_state = &state;

    struct xlate_out xout;
    enum xlate_error error = xlate_actions(&xin, &xout);
    *slow = xout.slow;
    xlate_out_uninit(&xout);

    /* xlate_actions() can generate a number of errors, but only
     * XLATE_BRIDGE_NOT_FOUND really stands out to me as one that we should be
     * sure to report over OpenFlow.  The others could come up in packet-outs
     * or regular flow translation and I don't think that it's going to be too
     * useful to report them to the controller. */
    return error == XLATE_BRIDGE_NOT_FOUND ? OFPERR_NXR_STALE : 0;
}

/* Sends 'packet' out 'ofport'. If 'port' is a tunnel and that tunnel type
 * supports a notion of an OAM flag, sets it if 'oam' is true.
 * May modify 'packet'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
xlate_send_packet(const struct ofport_dpif *ofport, bool oam,
                  struct dp_packet *packet)
{
    struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    struct xport *xport;
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts;
    struct flow flow;

    ofpbuf_use_stack(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    /* Use OFPP_NONE as the in_port to avoid special packet processing. */
    flow_extract(packet, &flow);
    flow.in_port.ofp_port = OFPP_NONE;

    xport = xport_lookup(xcfg, ofport);
    if (!xport) {
        return EINVAL;
    }

    if (oam) {
        const ovs_be16 flag = htons(NX_TUN_FLAG_OAM);
        ofpact_put_set_field(&ofpacts, mf_from_id(MFF_TUN_FLAGS),
                             &flag, &flag);
    }

    ofpact_put_OUTPUT(&ofpacts)->port = xport->ofp_port;

    /* Actions here are not referring to anything versionable (flow tables or
     * groups) so we don't need to worry about the version here. */
    return ofproto_dpif_execute_actions(xport->xbridge->ofproto,
                                        OVS_VERSION_MAX, &flow, NULL,
                                        ofpacts.data, ofpacts.size, packet);
}

void
xlate_mac_learning_update(const struct ofproto_dpif *ofproto,
                          ofp_port_t in_port, struct eth_addr dl_src,
                          int vlan, bool is_grat_arp)
{
    struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    struct xbridge *xbridge;
    struct xbundle *xbundle;

    xbridge = xbridge_lookup(xcfg, ofproto);
    if (!xbridge) {
        return;
    }

    xbundle = lookup_input_bundle__(xbridge, in_port, NULL);
    if (!xbundle) {
        return;
    }

    update_learning_table__(xbridge, xbundle, dl_src, vlan, is_grat_arp);
}

void
xlate_set_support(const struct ofproto_dpif *ofproto,
                    const struct dpif_backer_support *support)
{
    struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    struct xbridge *xbridge = xbridge_lookup(xcfg, ofproto);

    if (xbridge) {
        xbridge->support = *support;
    }
}
