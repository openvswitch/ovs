/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "bfd.h"
#include "bitmap.h"
#include "bond.h"
#include "bundle.h"
#include "byte-order.h"
#include "cfm.h"
#include "connmgr.h"
#include "coverage.h"
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
#include "ofproto/ofproto-dpif.h"
#include "ofproto/ofproto-provider.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/vlog.h"
#include "ovs-lldp.h"
#include "ovs-router.h"
#include "packets.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "tunnel.h"

COVERAGE_DEFINE(xlate_actions);
COVERAGE_DEFINE(xlate_actions_oversize);
COVERAGE_DEFINE(xlate_actions_too_many_output);

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_xlate);

/* Maximum depth of flow table recursion (due to resubmit actions) in a
 * flow translation. */
#define MAX_RESUBMIT_RECURSION 64
#define MAX_INTERNAL_RESUBMITS 1   /* Max resbmits allowed using rules in
                                      internal table. */

/* Maximum number of resubmit actions in a flow translation, whether they are
 * recursive or not. */
#define MAX_RESUBMITS (MAX_RESUBMIT_RECURSION * MAX_RESUBMIT_RECURSION)

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

    struct cfm *cfm;                 /* CFM handle or null. */
    struct bfd *bfd;                 /* BFD handle or null. */
    struct lldp *lldp;               /* LLDP handle or null. */
};

struct xlate_ctx {
    struct xlate_in *xin;
    struct xlate_out *xout;

    const struct xbridge *xbridge;

    /* Flow tables version at the beginning of the translation. */
    cls_version_t tables_version;

    /* Flow at the last commit. */
    struct flow base_flow;

    /* Tunnel IP destination address as received.  This is stored separately
     * as the base_flow.tunnel is cleared on init to reflect the datapath
     * behavior.  Used to make sure not to send tunneled output to ourselves,
     * which might lead to an infinite loop.  This could happen easily
     * if a tunnel is marked as 'ip_remote=flow', and the flow does not
     * actually set the tun_dst field. */
    struct in6_addr orig_tunnel_ipv6_dst;

    /* Stack for the push and pop actions.  Each stack element is of type
     * "union mf_subvalue". */
    struct ofpbuf stack;

    /* The rule that we are currently translating, or NULL. */
    struct rule_dpif *rule;

    /* Flow translation populates this with wildcards relevant in translation.
     * When 'xin->wc' is nonnull, this is the same pointer.  When 'xin->wc' is
     * null, this is a pointer to uninitialized scratch memory.  This allows
     * code to blindly write to 'ctx->wc' without worrying about whether the
     * caller really wants wildcards. */
    struct flow_wildcards *wc;

    /* Output buffer for datapath actions.  When 'xin->odp_actions' is nonnull,
     * this is the same pointer.  When 'xin->odp_actions' is null, this points
     * to a scratch ofpbuf.  This allows code to add actions to
     * 'ctx->odp_actions' without worrying about whether the caller really
     * wants actions. */
    struct ofpbuf *odp_actions;

    /* Resubmit statistics, via xlate_table_action(). */
    int recurse;                /* Current resubmit nesting depth. */
    int resubmits;              /* Total number of resubmits. */
    bool in_group;              /* Currently translating ofgroup, if true. */
    bool in_action_set;         /* Currently translating action_set, if true. */

    uint8_t table_id;           /* OpenFlow table ID where flow was found. */
    ovs_be64 rule_cookie;       /* Cookie of the rule being translated. */
    uint32_t orig_skb_priority; /* Priority when packet arrived. */
    uint32_t sflow_n_outputs;   /* Number of output ports. */
    odp_port_t sflow_odp_port;  /* Output port for composing sFlow action. */
    ofp_port_t nf_output_iface; /* Output interface index for NetFlow. */
    bool exit;                  /* No further actions should be processed. */
    mirror_mask_t mirrors;      /* Bitmap of associated mirrors. */

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
    struct ofpbuf frozen_actions;
    const struct ofpact_controller *pause;

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
    }
    return "Unknown error";
}

static void xlate_action_set(struct xlate_ctx *ctx);
static void xlate_commit_actions(struct xlate_ctx *ctx);

static void
ctx_trigger_freeze(struct xlate_ctx *ctx)
{
    ctx->exit = true;
    ctx->freezing = true;
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

enum xc_type {
    XC_RULE,
    XC_BOND,
    XC_NETDEV,
    XC_NETFLOW,
    XC_MIRROR,
    XC_LEARN,
    XC_NORMAL,
    XC_FIN_TIMEOUT,
    XC_GROUP,
    XC_TNL_NEIGH,
};

/* xlate_cache entries hold enough information to perform the side effects of
 * xlate_actions() for a rule, without needing to perform rule translation
 * from scratch. The primary usage of these is to submit statistics to objects
 * that a flow relates to, although they may be used for other effects as well
 * (for instance, refreshing hard timeouts for learned flows). */
struct xc_entry {
    enum xc_type type;
    union {
        struct rule_dpif *rule;
        struct {
            struct netdev *tx;
            struct netdev *rx;
            struct bfd *bfd;
        } dev;
        struct {
            struct netflow *netflow;
            struct flow *flow;
            ofp_port_t iface;
        } nf;
        struct {
            struct mbridge *mbridge;
            mirror_mask_t mirrors;
        } mirror;
        struct {
            struct bond *bond;
            struct flow *flow;
            uint16_t vid;
        } bond;
        struct {
            struct ofproto_dpif *ofproto;
            struct ofputil_flow_mod *fm;
            struct ofpbuf *ofpacts;
        } learn;
        struct {
            struct ofproto_dpif *ofproto;
            struct flow *flow;
            int vlan;
        } normal;
        struct {
            struct rule_dpif *rule;
            uint16_t idle;
            uint16_t hard;
        } fin;
        struct {
            struct group_dpif *group;
            struct ofputil_bucket *bucket;
        } group;
        struct {
            char br_name[IFNAMSIZ];
            struct in6_addr d_ipv6;
        } tnl_neigh_cache;
    } u;
};

#define XC_ENTRY_FOR_EACH(ENTRY, ENTRIES, XCACHE)               \
    ENTRIES = XCACHE->entries;                                  \
    for (ENTRY = ofpbuf_try_pull(&ENTRIES, sizeof *ENTRY);      \
         ENTRY;                                                 \
         ENTRY = ofpbuf_try_pull(&ENTRIES, sizeof *ENTRY))

struct xlate_cache {
    struct ofpbuf entries;
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
};
static OVSRCU_TYPE(struct xlate_cfg *) xcfgp = OVSRCU_INITIALIZER(NULL);
static struct xlate_cfg *new_xcfg = NULL;

static bool may_receive(const struct xport *, struct xlate_ctx *);
static void do_xlate_actions(const struct ofpact *, size_t ofpacts_len,
                             struct xlate_ctx *);
static void xlate_normal(struct xlate_ctx *);
static inline void xlate_report(struct xlate_ctx *, const char *, ...)
    OVS_PRINTF_FORMAT(2, 3);
static void xlate_table_action(struct xlate_ctx *, ofp_port_t in_port,
                               uint8_t table_id, bool may_packet_in,
                               bool honor_table_miss);
static bool input_vid_is_valid(uint16_t vid, struct xbundle *, bool warn);
static uint16_t input_vid_to_vlan(const struct xbundle *, uint16_t vid);
static void output_normal(struct xlate_ctx *, const struct xbundle *,
                          uint16_t vlan);

/* Optional bond recirculation parameter to compose_output_action(). */
struct xlate_bond_recirc {
    uint32_t recirc_id;  /* !0 Use recirculation instead of output. */
    uint8_t  hash_alg;   /* !0 Compute hash for recirc before. */
    uint32_t hash_basis;  /* Compute hash for recirc before. */
};

static void compose_output_action(struct xlate_ctx *, ofp_port_t ofp_port,
                                  const struct xlate_bond_recirc *xr);

static struct xbridge *xbridge_lookup(struct xlate_cfg *,
                                      const struct ofproto_dpif *);
static struct xbridge *xbridge_lookup_by_uuid(struct xlate_cfg *,
                                              const struct uuid *);
static struct xbundle *xbundle_lookup(struct xlate_cfg *,
                                      const struct ofbundle *);
static struct xport *xport_lookup(struct xlate_cfg *,
                                  const struct ofport_dpif *);
static struct xport *get_ofp_port(const struct xbridge *, ofp_port_t ofp_port);
static struct skb_priority_to_dscp *get_skb_priority(const struct xport *,
                                                     uint32_t skb_priority);
static void clear_skb_priorities(struct xport *);
static size_t count_skb_priorities(const struct xport *);
static bool dscp_from_skb_priority(const struct xport *, uint32_t skb_priority,
                                   uint8_t *dscp);

static struct xc_entry *xlate_cache_add_entry(struct xlate_cache *xc,
                                              enum xc_type type);
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
                              const struct dpif_backer_support *);
static void xlate_xbundle_set(struct xbundle *xbundle,
                              enum port_vlan_mode vlan_mode, int vlan,
                              unsigned long *trunks, bool use_priority_tags,
                              const struct bond *bond, const struct lacp *lacp,
                              bool floodable);
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

static inline void
xlate_report(struct xlate_ctx *ctx, const char *format, ...)
{
    if (OVS_UNLIKELY(ctx->xin->report_hook)) {
        va_list args;

        va_start(args, format);
        ctx->xin->report_hook(ctx->xin, ctx->recurse, format, args);
        va_end(args);
    }
}

static struct vlog_rate_limit error_report_rl = VLOG_RATE_LIMIT_INIT(1, 5);

#define XLATE_REPORT_ERROR(CTX, ...)                    \
    do {                                                \
        if (OVS_UNLIKELY((CTX)->xin->report_hook)) {    \
            xlate_report(CTX, __VA_ARGS__);             \
        } else {                                        \
            VLOG_ERR_RL(&error_report_rl, __VA_ARGS__); \
        }                                               \
    } while (0)

static inline void
xlate_report_actions(struct xlate_ctx *ctx, const char *title,
                     const struct ofpact *ofpacts, size_t ofpacts_len)
{
    if (OVS_UNLIKELY(ctx->xin->report_hook)) {
        struct ds s = DS_EMPTY_INITIALIZER;
        ofpacts_format(ofpacts, ofpacts_len, &s);
        xlate_report(ctx, "%s: %s", title, ds_cstr(&s));
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
                  const struct dpif_backer_support *support)
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

    xbridge->dpif = dpif;
    xbridge->forward_bpdu = forward_bpdu;
    xbridge->has_in_band = has_in_band;
    xbridge->support = *support;
}

static void
xlate_xbundle_set(struct xbundle *xbundle,
                  enum port_vlan_mode vlan_mode, int vlan,
                  unsigned long *trunks, bool use_priority_tags,
                  const struct bond *bond, const struct lacp *lacp,
                  bool floodable)
{
    ovs_assert(xbundle->xbridge);

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
                      &xbridge->support);
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

    xlate_xbundle_set(new_xbundle, xbundle->vlan_mode,
                      xbundle->vlan, xbundle->trunks,
                      xbundle->use_priority_tags, xbundle->bond, xbundle->lacp,
                      xbundle->floodable);
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
 * xlate_<ofport/bundle/ofport>_set and xlate_<ofport/bundle/ofport>_remove.
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

    ovs_assert(new_xcfg);

    xbridge = xbridge_lookup(new_xcfg, ofproto);
    if (!xbridge) {
        xbridge = xzalloc(sizeof *xbridge);
        xbridge->ofproto = ofproto;

        xlate_xbridge_init(new_xcfg, xbridge);
    }

    free(xbridge->name);
    xbridge->name = xstrdup(name);

    xlate_xbridge_set(xbridge, dpif, ml, stp, rstp, ms, mbridge, sflow, ipfix,
                      netflow, forward_bpdu, has_in_band, support);
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
    stp_unref(xbridge->stp);
    rstp_unref(xbridge->rstp);
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
                 const char *name, enum port_vlan_mode vlan_mode, int vlan,
                 unsigned long *trunks, bool use_priority_tags,
                 const struct bond *bond, const struct lacp *lacp,
                 bool floodable)
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

    xlate_xbundle_set(xbundle, vlan_mode, vlan, trunks,
                      use_priority_tags, bond, lacp, floodable);
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

    xport = xport_lookup(xcfg, tnl_port_should_receive(flow)
                         ? tnl_port_receive(flow)
                         : odp_port_to_ofport(backer, flow->in_port.odp_port));
    if (OVS_UNLIKELY(!xport)) {
        return NULL;
    }
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
 * optionally populates 'ofproto' with the ofproto_dpif, 'ofp_in_port' with the
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
        if (uuid_equals(ofproto_dpif_get_uuid(xbridge->ofproto), uuid)) {
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

    if (group_dpif_lookup(ctx->xbridge->ofproto, group_id, &group)) {
        struct ofputil_bucket *bucket;

        bucket = group_first_live_bucket(ctx, group, depth);
        group_dpif_unref(group);
        return bucket == NULL;
    }

    return false;
}

#define MAX_LIVENESS_RECURSION 128 /* Arbitrary limit */

static bool
bucket_is_alive(const struct xlate_ctx *ctx,
                struct ofputil_bucket *bucket, int depth)
{
    if (depth >= MAX_LIVENESS_RECURSION) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_WARN_RL(&rl, "bucket chaining exceeded %d links",
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
    const struct ovs_list *buckets;

    group_dpif_get_buckets(group, &buckets);
    LIST_FOR_EACH (bucket, list_node, buckets) {
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
    int i = 0;

    struct ofputil_bucket *bucket;
    const struct ovs_list *buckets;

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

    /* Special-case OFPP_NONE (OF1.0) and OFPP_CONTROLLER (OF1.1+),
     * which a controller may use as the ingress port for traffic that
     * it is sourcing. */
    if (in_port == OFPP_CONTROLLER || in_port == OFPP_NONE) {
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

/* Mirrors the packet represented by 'ctx' to appropriate mirror destinations,
 * given the packet is ingressing or egressing on 'xbundle', which has ingress
 * or egress (as appropriate) mirrors 'mirrors'. */
static void
mirror_packet(struct xlate_ctx *ctx, struct xbundle *xbundle,
              mirror_mask_t mirrors)
{
    /* Figure out what VLAN the packet is in (because mirrors can select
     * packets on basis of VLAN). */
    bool warn = ctx->xin->packet != NULL;
    uint16_t vid = vlan_tci_to_vid(ctx->xin->flow.vlan_tci);
    if (!input_vid_is_valid(vid, xbundle, warn)) {
        return;
    }
    uint16_t vlan = input_vid_to_vlan(xbundle, vid);

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
        entry->u.mirror.mbridge = mbridge_ref(xbridge->mbridge);
        entry->u.mirror.mirrors = mirrors;
    }

    /* 'mirrors' is a bit-mask of candidates for mirroring.  Iterate as long as
     * some candidates remain.  */
    while (mirrors) {
        const unsigned long *vlans;
        mirror_mask_t dup_mirrors;
        struct ofbundle *out;
        int out_vlan;

        /* Get the details of the mirror represented by the rightmost 1-bit. */
        bool has_mirror = mirror_get(xbridge->mbridge, raw_ctz(mirrors),
                                     &vlans, &dup_mirrors, &out, &out_vlan);
        ovs_assert(has_mirror);

        /* If this mirror selects on the basis of VLAN, and it does not select
         * 'vlan', then discard this mirror and go on to the next one. */
        if (vlans) {
            ctx->wc->masks.vlan_tci |= htons(VLAN_CFI | VLAN_VID_MASK);
        }
        if (vlans && !bitmap_is_set(vlans, vlan)) {
            mirrors = zero_rightmost_1bit(mirrors);
            continue;
        }

        /* Record the mirror, and the mirrors that output to the same
         * destination, so that we don't mirror to them again.  This must be
         * done now to ensure that output_normal(), below, doesn't recursively
         * output to the same mirrors. */
        ctx->mirrors |= dup_mirrors;

        /* Send the packet to the mirror. */
        if (out) {
            struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
            struct xbundle *out_xbundle = xbundle_lookup(xcfg, out);
            if (out_xbundle) {
                output_normal(ctx, out_xbundle, vlan);
            }
        } else if (vlan != out_vlan
                   && !eth_addr_is_reserved(ctx->xin->flow.dl_dst)) {
            struct xbundle *xbundle;

            LIST_FOR_EACH (xbundle, list_node, &xbridge->xbundles) {
                if (xbundle_includes_vlan(xbundle, out_vlan)
                    && !xbundle_mirror_out(xbridge, xbundle)) {
                    output_normal(ctx, xbundle, out_vlan);
                }
            }
        }

        /* output_normal() could have recursively output (to different
         * mirrors), so make sure that we don't send duplicates. */
        mirrors &= ~ctx->mirrors;
    }
}

static void
mirror_ingress_packet(struct xlate_ctx *ctx)
{
    if (mbridge_has_mirrors(ctx->xbridge->mbridge)) {
        bool warn = ctx->xin->packet != NULL;
        struct xbundle *xbundle = lookup_input_bundle(
            ctx->xbridge, ctx->xin->flow.in_port.ofp_port, warn, NULL);
        if (xbundle) {
            mirror_packet(ctx, xbundle,
                          xbundle_mirror_src(ctx->xbridge, xbundle));
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
    struct xlate_bond_recirc xr;
    bool use_recirc = false;

    vid = output_vlan_to_vid(out_xbundle, vlan);
    if (ovs_list_is_empty(&out_xbundle->xports)) {
        /* Partially configured bundle with no slaves.  Drop the packet. */
        return;
    } else if (!out_xbundle->bond) {
        xport = CONTAINER_OF(ovs_list_front(&out_xbundle->xports), struct xport,
                             bundle_node);
    } else {
        struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
        struct flow_wildcards *wc = ctx->wc;
        struct ofport_dpif *ofport;

        if (ctx->xbridge->support.odp.recirc) {
            use_recirc = bond_may_recirc(
                out_xbundle->bond, &xr.recirc_id, &xr.hash_basis);

            if (use_recirc) {
                /* Only TCP mode uses recirculation. */
                xr.hash_alg = OVS_HASH_ALG_L4;
                bond_update_post_recirc_rules(out_xbundle->bond, false);

                /* Recirculation does not require unmasking hash fields. */
                wc = NULL;
            }
        }

        ofport = bond_choose_output_slave(out_xbundle->bond,
                                          &ctx->xin->flow, wc, vid);
        xport = xport_lookup(xcfg, ofport);

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
                entry->u.bond.bond = bond_ref(out_xbundle->bond);
                entry->u.bond.flow = xmemdup(flow, sizeof *flow);
                entry->u.bond.vid = vid;
            }
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

    compose_output_action(ctx, xport->ofp_port, use_recirc ? &xr : NULL);
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
            if (mac
                && mac_entry_get_port(xbridge->ml, mac) != in_xbundle->ofbundle
                && (!is_gratuitous_arp(flow, ctx->wc)
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

    return mac_entry_get_port(ml, mac) != in_xbundle->ofbundle;
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

    if (mac_entry_get_port(xbridge->ml, mac) != in_xbundle->ofbundle) {
        /* The log messages here could actually be useful in debugging,
         * so keep the rate limit relatively high. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

        VLOG_DBG_RL(&rl, "bridge %s: learned that "ETH_ADDR_FMT" is "
                    "on port %s in VLAN %d",
                    xbridge->name, ETH_ADDR_ARGS(flow->dl_src),
                    in_xbundle->name, vlan);

        mac_entry_set_port(xbridge->ml, mac, in_xbundle->ofbundle);
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

/* Updates multicast snooping table 'ms' given that a packet matching 'flow'
 * was received on 'in_xbundle' in 'vlan' and is either Report or Query. */
static void
update_mcast_snooping_table4__(const struct xbridge *xbridge,
                               const struct flow *flow,
                               struct mcast_snooping *ms, int vlan,
                               struct xbundle *in_xbundle,
                               const struct dp_packet *packet)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 30);
    int count;
    ovs_be32 ip4 = flow->igmp_group_ip4;

    switch (ntohs(flow->tp_src)) {
    case IGMP_HOST_MEMBERSHIP_REPORT:
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        if (mcast_snooping_add_group4(ms, ip4, vlan, in_xbundle->ofbundle)) {
            VLOG_DBG_RL(&rl, "bridge %s: multicast snooping learned that "
                        IP_FMT" is on port %s in VLAN %d",
                        xbridge->name, IP_ARGS(ip4), in_xbundle->name, vlan);
        }
        break;
    case IGMP_HOST_LEAVE_MESSAGE:
        if (mcast_snooping_leave_group4(ms, ip4, vlan, in_xbundle->ofbundle)) {
            VLOG_DBG_RL(&rl, "bridge %s: multicast snooping leaving "
                        IP_FMT" is on port %s in VLAN %d",
                        xbridge->name, IP_ARGS(ip4), in_xbundle->name, vlan);
        }
        break;
    case IGMP_HOST_MEMBERSHIP_QUERY:
        if (flow->nw_src && mcast_snooping_add_mrouter(ms, vlan,
            in_xbundle->ofbundle)) {
            VLOG_DBG_RL(&rl, "bridge %s: multicast snooping query from "
                        IP_FMT" is on port %s in VLAN %d",
                        xbridge->name, IP_ARGS(flow->nw_src),
                        in_xbundle->name, vlan);
        }
        break;
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        if ((count = mcast_snooping_add_report(ms, packet, vlan,
                                               in_xbundle->ofbundle))) {
            VLOG_DBG_RL(&rl, "bridge %s: multicast snooping processed %d "
                        "addresses on port %s in VLAN %d",
                        xbridge->name, count, in_xbundle->name, vlan);
        }
        break;
    }
}

static void
update_mcast_snooping_table6__(const struct xbridge *xbridge,
                               const struct flow *flow,
                               struct mcast_snooping *ms, int vlan,
                               struct xbundle *in_xbundle,
                               const struct dp_packet *packet)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 30);
    int count;

    switch (ntohs(flow->tp_src)) {
    case MLD_QUERY:
        if (!ipv6_addr_equals(&flow->ipv6_src, &in6addr_any)
            && mcast_snooping_add_mrouter(ms, vlan, in_xbundle->ofbundle)) {
            VLOG_DBG_RL(&rl, "bridge %s: multicast snooping query on port %s"
                        "in VLAN %d",
                        xbridge->name, in_xbundle->name, vlan);
        }
        break;
    case MLD_REPORT:
    case MLD_DONE:
    case MLD2_REPORT:
        count = mcast_snooping_add_mld(ms, packet, vlan, in_xbundle->ofbundle);
        if (count) {
            VLOG_DBG_RL(&rl, "bridge %s: multicast snooping processed %d "
                        "addresses on port %s in VLAN %d",
                        xbridge->name, count, in_xbundle->name, vlan);
        }
        break;
    }
}

/* Updates multicast snooping table 'ms' given that a packet matching 'flow'
 * was received on 'in_xbundle' in 'vlan'. */
static void
update_mcast_snooping_table(const struct xbridge *xbridge,
                            const struct flow *flow, int vlan,
                            struct xbundle *in_xbundle,
                            const struct dp_packet *packet)
{
    struct mcast_snooping *ms = xbridge->ms;
    struct xlate_cfg *xcfg;
    struct xbundle *mcast_xbundle;
    struct mcast_port_bundle *fport;

    /* Don't learn the OFPP_NONE port. */
    if (in_xbundle == &ofpp_none_bundle) {
        return;
    }

    /* Don't learn from flood ports */
    mcast_xbundle = NULL;
    ovs_rwlock_wrlock(&ms->rwlock);
    xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    LIST_FOR_EACH(fport, node, &ms->fport_list) {
        mcast_xbundle = xbundle_lookup(xcfg, fport->port);
        if (mcast_xbundle == in_xbundle) {
            break;
        }
    }

    if (!mcast_xbundle || mcast_xbundle != in_xbundle) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            update_mcast_snooping_table4__(xbridge, flow, ms, vlan,
                                           in_xbundle, packet);
        } else {
            update_mcast_snooping_table6__(xbridge, flow, ms, vlan,
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
                              struct xbundle *in_xbundle, uint16_t vlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct xlate_cfg *xcfg;
    struct mcast_group_bundle *b;
    struct xbundle *mcast_xbundle;

    xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    LIST_FOR_EACH(b, bundle_node, &grp->bundle_lru) {
        mcast_xbundle = xbundle_lookup(xcfg, b->port);
        if (mcast_xbundle && mcast_xbundle != in_xbundle) {
            xlate_report(ctx, "forwarding to mcast group port");
            output_normal(ctx, mcast_xbundle, vlan);
        } else if (!mcast_xbundle) {
            xlate_report(ctx, "mcast group port is unknown, dropping");
        } else {
            xlate_report(ctx, "mcast group port is input port, dropping");
        }
    }
}

/* send the packet to ports connected to multicast routers */
static void
xlate_normal_mcast_send_mrouters(struct xlate_ctx *ctx,
                                 struct mcast_snooping *ms,
                                 struct xbundle *in_xbundle, uint16_t vlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct xlate_cfg *xcfg;
    struct mcast_mrouter_bundle *mrouter;
    struct xbundle *mcast_xbundle;

    xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    LIST_FOR_EACH(mrouter, mrouter_node, &ms->mrouter_lru) {
        mcast_xbundle = xbundle_lookup(xcfg, mrouter->port);
        if (mcast_xbundle && mcast_xbundle != in_xbundle) {
            xlate_report(ctx, "forwarding to mcast router port");
            output_normal(ctx, mcast_xbundle, vlan);
        } else if (!mcast_xbundle) {
            xlate_report(ctx, "mcast router port is unknown, dropping");
        } else {
            xlate_report(ctx, "mcast router port is input port, dropping");
        }
    }
}

/* send the packet to ports flagged to be flooded */
static void
xlate_normal_mcast_send_fports(struct xlate_ctx *ctx,
                               struct mcast_snooping *ms,
                               struct xbundle *in_xbundle, uint16_t vlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct xlate_cfg *xcfg;
    struct mcast_port_bundle *fport;
    struct xbundle *mcast_xbundle;

    xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    LIST_FOR_EACH(fport, node, &ms->fport_list) {
        mcast_xbundle = xbundle_lookup(xcfg, fport->port);
        if (mcast_xbundle && mcast_xbundle != in_xbundle) {
            xlate_report(ctx, "forwarding to mcast flood port");
            output_normal(ctx, mcast_xbundle, vlan);
        } else if (!mcast_xbundle) {
            xlate_report(ctx, "mcast flood port is unknown, dropping");
        } else {
            xlate_report(ctx, "mcast flood port is input port, dropping");
        }
    }
}

/* forward the Reports to configured ports */
static void
xlate_normal_mcast_send_rports(struct xlate_ctx *ctx,
                               struct mcast_snooping *ms,
                               struct xbundle *in_xbundle, uint16_t vlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct xlate_cfg *xcfg;
    struct mcast_port_bundle *rport;
    struct xbundle *mcast_xbundle;

    xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    LIST_FOR_EACH(rport, node, &ms->rport_list) {
        mcast_xbundle = xbundle_lookup(xcfg, rport->port);
        if (mcast_xbundle && mcast_xbundle != in_xbundle) {
            xlate_report(ctx, "forwarding Report to mcast flagged port");
            output_normal(ctx, mcast_xbundle, vlan);
        } else if (!mcast_xbundle) {
            xlate_report(ctx, "mcast port is unknown, dropping the Report");
        } else {
            xlate_report(ctx, "mcast port is input port, dropping the Report");
        }
    }
}

static void
xlate_normal_flood(struct xlate_ctx *ctx, struct xbundle *in_xbundle,
                   uint16_t vlan)
{
    struct xbundle *xbundle;

    LIST_FOR_EACH (xbundle, list_node, &ctx->xbridge->xbundles) {
        if (xbundle != in_xbundle
            && xbundle_includes_vlan(xbundle, vlan)
            && xbundle->floodable
            && !xbundle_mirror_out(ctx->xbridge, xbundle)) {
            output_normal(ctx, xbundle, vlan);
        }
    }
    ctx->nf_output_iface = NF_OUT_FLOOD;
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
    uint16_t vlan;
    uint16_t vid;

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
    if (ctx->xin->xcache) {
        struct xc_entry *entry;

        /* Save enough info to update mac learning table later. */
        entry = xlate_cache_add_entry(ctx->xin->xcache, XC_NORMAL);
        entry->u.normal.ofproto = ctx->xbridge->ofproto;
        entry->u.normal.flow = xmemdup(flow, sizeof *flow);
        entry->u.normal.vlan = vlan;
    }

    /* Determine output bundle. */
    if (mcast_snooping_enabled(ctx->xbridge->ms)
        && !eth_addr_is_broadcast(flow->dl_dst)
        && eth_addr_is_multicast(flow->dl_dst)
        && is_ip_any(flow)) {
        struct mcast_snooping *ms = ctx->xbridge->ms;
        struct mcast_group *grp = NULL;

        if (is_igmp(flow)) {
            if (mcast_snooping_is_membership(flow->tp_src) ||
                mcast_snooping_is_query(flow->tp_src)) {
                if (ctx->xin->may_learn && ctx->xin->packet) {
                    update_mcast_snooping_table(ctx->xbridge, flow, vlan,
                                                in_xbundle, ctx->xin->packet);
                }
                /*
                 * IGMP packets need to take the slow path, in order to be
                 * processed for mdb updates. That will prevent expires
                 * firing off even after hosts have sent reports.
                 */
                ctx->xout->slow |= SLOW_ACTION;
            }

            if (mcast_snooping_is_membership(flow->tp_src)) {
                ovs_rwlock_rdlock(&ms->rwlock);
                xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, vlan);
                /* RFC4541: section 2.1.1, item 1: A snooping switch should
                 * forward IGMP Membership Reports only to those ports where
                 * multicast routers are attached.  Alternatively stated: a
                 * snooping switch should not forward IGMP Membership Reports
                 * to ports on which only hosts are attached.
                 * An administrative control may be provided to override this
                 * restriction, allowing the report messages to be flooded to
                 * other ports. */
                xlate_normal_mcast_send_rports(ctx, ms, in_xbundle, vlan);
                ovs_rwlock_unlock(&ms->rwlock);
            } else {
                xlate_report(ctx, "multicast traffic, flooding");
                xlate_normal_flood(ctx, in_xbundle, vlan);
            }
            return;
        } else if (is_mld(flow)) {
            ctx->xout->slow |= SLOW_ACTION;
            if (ctx->xin->may_learn && ctx->xin->packet) {
                update_mcast_snooping_table(ctx->xbridge, flow, vlan,
                                            in_xbundle, ctx->xin->packet);
            }
            if (is_mld_report(flow)) {
                ovs_rwlock_rdlock(&ms->rwlock);
                xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, vlan);
                xlate_normal_mcast_send_rports(ctx, ms, in_xbundle, vlan);
                ovs_rwlock_unlock(&ms->rwlock);
            } else {
                xlate_report(ctx, "MLD query, flooding");
                xlate_normal_flood(ctx, in_xbundle, vlan);
            }
        } else {
            if ((flow->dl_type == htons(ETH_TYPE_IP)
                 && ip_is_local_multicast(flow->nw_dst))
                || (flow->dl_type == htons(ETH_TYPE_IPV6)
                    && ipv6_is_all_hosts(&flow->ipv6_dst))) {
                /* RFC4541: section 2.1.2, item 2: Packets with a dst IP
                 * address in the 224.0.0.x range which are not IGMP must
                 * be forwarded on all ports */
                xlate_report(ctx, "RFC4541: section 2.1.2, item 2, flooding");
                xlate_normal_flood(ctx, in_xbundle, vlan);
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
            xlate_normal_mcast_send_group(ctx, ms, grp, in_xbundle, vlan);
            xlate_normal_mcast_send_fports(ctx, ms, in_xbundle, vlan);
            xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, vlan);
        } else {
            if (mcast_snooping_flood_unreg(ms)) {
                xlate_report(ctx, "unregistered multicast, flooding");
                xlate_normal_flood(ctx, in_xbundle, vlan);
            } else {
                xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, vlan);
                xlate_normal_mcast_send_fports(ctx, ms, in_xbundle, vlan);
            }
        }
        ovs_rwlock_unlock(&ms->rwlock);
    } else {
        ovs_rwlock_rdlock(&ctx->xbridge->ml->rwlock);
        mac = mac_learning_lookup(ctx->xbridge->ml, flow->dl_dst, vlan);
        mac_port = mac ? mac_entry_get_port(ctx->xbridge->ml, mac) : NULL;
        ovs_rwlock_unlock(&ctx->xbridge->ml->rwlock);

        if (mac_port) {
            struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
            struct xbundle *mac_xbundle = xbundle_lookup(xcfg, mac_port);
            if (mac_xbundle && mac_xbundle != in_xbundle) {
                xlate_report(ctx, "forwarding to learned port");
                output_normal(ctx, mac_xbundle, vlan);
            } else if (!mac_xbundle) {
                xlate_report(ctx, "learned port is unknown, dropping");
            } else {
                xlate_report(ctx, "learned port is input port, dropping");
            }
        } else {
            xlate_report(ctx, "no learned MAC for destination, flooding");
            xlate_normal_flood(ctx, in_xbundle, vlan);
        }
    }
}

/* Appends a "sample" action for sFlow or IPFIX to 'ctx->odp_actions'.  The
 * 'probability' is the number of packets out of UINT32_MAX to sample.  The
 * 'cookie' (of length 'cookie_size' bytes) is passed back in the callback for
 * each sampled packet.  'tunnel_out_port', if not ODPP_NONE, is added as the
 * OVS_USERSPACE_ATTR_EGRESS_TUN_PORT attribute.  If 'include_actions', an
 * OVS_USERSPACE_ATTR_ACTIONS attribute is added.
 */
static size_t
compose_sample_action(struct xlate_ctx *ctx,
                      const uint32_t probability,
                      const union user_action_cookie *cookie,
                      const size_t cookie_size,
                      const odp_port_t tunnel_out_port,
                      bool include_actions)
{
    size_t sample_offset = nl_msg_start_nested(ctx->odp_actions,
                                               OVS_ACTION_ATTR_SAMPLE);

    nl_msg_put_u32(ctx->odp_actions, OVS_SAMPLE_ATTR_PROBABILITY, probability);

    size_t actions_offset = nl_msg_start_nested(ctx->odp_actions,
                                                OVS_SAMPLE_ATTR_ACTIONS);

    odp_port_t odp_port = ofp_port_to_odp_port(
        ctx->xbridge, ctx->xin->flow.in_port.ofp_port);
    uint32_t pid = dpif_port_get_pid(ctx->xbridge->dpif, odp_port,
                                     flow_hash_5tuple(&ctx->xin->flow, 0));
    int cookie_offset = odp_put_userspace_action(pid, cookie, cookie_size,
                                                 tunnel_out_port,
                                                 include_actions,
                                                 ctx->odp_actions);

    nl_msg_end_nested(ctx->odp_actions, actions_offset);
    nl_msg_end_nested(ctx->odp_actions, sample_offset);

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

    union user_action_cookie cookie = { .type = USER_ACTION_COOKIE_SFLOW };
    return compose_sample_action(ctx, dpif_sflow_get_probability(sflow),
                                 &cookie, sizeof cookie.sflow, ODPP_NONE,
                                 true);
}

/* If IPFIX is enabled, this appends a "sample" action to implement IPFIX to
 * 'ctx->odp_actions'. */
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

    /* For output case, output_odp_port is valid*/
    if (output_odp_port != ODPP_NONE) {
        if (!dpif_ipfix_get_bridge_exporter_output_sampling(ipfix)) {
            return;
        }
        /* If tunnel sampling is enabled, put an additional option attribute:
         * OVS_USERSPACE_ATTR_TUNNEL_OUT_PORT
         */
        if (dpif_ipfix_get_bridge_exporter_tunnel_sampling(ipfix) &&
            dpif_ipfix_get_tunnel_port(ipfix, output_odp_port) ) {
           tunnel_out_port = output_odp_port;
        }
    }

    union user_action_cookie cookie = {
        .ipfix = {
            .type = USER_ACTION_COOKIE_IPFIX,
            .output_odp_port = output_odp_port,
        }
    };
    compose_sample_action(ctx,
                          dpif_ipfix_get_bridge_exporter_probability(ipfix),
                          &cookie, sizeof cookie.ipfix, tunnel_out_port,
                          false);
}

/* Fix "sample" action according to data collected while composing ODP actions,
 * as described in compose_sflow_action().
 *
 * 'user_cookie_offset' must be the offset returned by add_sflow_action(). */
static void
fix_sflow_action(struct xlate_ctx *ctx, unsigned int user_cookie_offset)
{
    const struct flow *base = &ctx->base_flow;
    union user_action_cookie *cookie;

    cookie = ofpbuf_at(ctx->odp_actions, user_cookie_offset,
                       sizeof cookie->sflow);
    ovs_assert(cookie->type == USER_ACTION_COOKIE_SFLOW);

    cookie->type = USER_ACTION_COOKIE_SFLOW;
    cookie->sflow.vlan_tci = base->vlan_tci;

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
tnl_route_lookup_flow(const struct flow *oflow,
                      struct in6_addr *ip, struct in6_addr *src,
                      struct xport **out_port)
{
    char out_dev[IFNAMSIZ];
    struct xbridge *xbridge;
    struct xlate_cfg *xcfg;
    struct in6_addr gw;
    struct in6_addr dst;

    dst = flow_tnl_dst(&oflow->tunnel);
    if (!ovs_router_lookup(&dst, out_dev, src, &gw)) {
        return -ENOENT;
    }

    if (ipv6_addr_is_set(&gw) &&
        (!IN6_IS_ADDR_V4MAPPED(&gw) || in6_addr_get_mapped_ipv4(&gw))) {
        *ip = gw;
    } else {
        *ip = dst;
    }

    xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    ovs_assert(xcfg);

    HMAP_FOR_EACH (xbridge, hmap_node, &xcfg->xbridges) {
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

    return ofproto_dpif_execute_actions__(xbridge->ofproto, &flow, NULL,
                                          &output.ofpact, sizeof output,
                                          ctx->recurse, ctx->resubmits, packet);
}

static void
tnl_send_nd_request(struct xlate_ctx *ctx, const struct xport *out_dev,
                     const struct eth_addr eth_src,
                     struct in6_addr * ipv6_src, struct in6_addr * ipv6_dst)
{
    struct dp_packet packet;

    dp_packet_init(&packet, 0);
    compose_nd(&packet, eth_src, ipv6_src, ipv6_dst);
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

static int
build_tunnel_send(struct xlate_ctx *ctx, const struct xport *xport,
                  const struct flow *flow, odp_port_t tunnel_odp_port)
{
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

    err = tnl_route_lookup_flow(flow, &d_ip6, &s_ip6, &out_dev);
    if (err) {
        xlate_report(ctx, "native tunnel routing failed");
        return err;
    }

    xlate_report(ctx, "tunneling to %s via %s",
                 ipv6_string_mapped(buf_dip6, &d_ip6),
                 netdev_get_name(out_dev->netdev));

    /* Use mac addr of bridge port of the peer. */
    err = netdev_get_etheraddr(out_dev->netdev, &smac);
    if (err) {
        xlate_report(ctx, "tunnel output device lacks Ethernet address");
        return err;
    }

    d_ip = in6_addr_get_mapped_ipv4(&d_ip6);
    if (d_ip) {
        s_ip = in6_addr_get_mapped_ipv4(&s_ip6);
    }

    err = tnl_neigh_lookup(out_dev->xbridge->name, &d_ip6, &dmac);
    if (err) {
        xlate_report(ctx, "neighbor cache miss for %s on bridge %s, "
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
        ovs_strlcpy(entry->u.tnl_neigh_cache.br_name, out_dev->xbridge->name,
                    sizeof entry->u.tnl_neigh_cache.br_name);
        entry->u.tnl_neigh_cache.d_ipv6 = d_ip6;
    }

    xlate_report(ctx, "tunneling from "ETH_ADDR_FMT" %s"
                 " to "ETH_ADDR_FMT" %s",
                 ETH_ADDR_ARGS(smac), ipv6_string_mapped(buf_sip6, &s_ip6),
                 ETH_ADDR_ARGS(dmac), buf_dip6);

    err = tnl_port_build_header(xport->ofport, flow,
                                dmac, smac, &s_ip6, &tnl_push_data);
    if (err) {
        return err;
    }
    tnl_push_data.tnl_port = odp_to_u32(tunnel_odp_port);
    tnl_push_data.out_port = odp_to_u32(out_dev->odp_port);
    odp_put_tnl_push_action(ctx->odp_actions, &tnl_push_data);
    return 0;
}

static void
xlate_commit_actions(struct xlate_ctx *ctx)
{
    bool use_masked = ctx->xbridge->support.masked_set_action;

    ctx->xout->slow |= commit_odp_actions(&ctx->xin->flow, &ctx->base_flow,
                                          ctx->odp_actions, ctx->wc,
                                          use_masked);
}

static void
clear_conntrack(struct flow *flow)
{
    flow->ct_state = 0;
    flow->ct_zone = 0;
    flow->ct_mark = 0;
    memset(&flow->ct_label, 0, sizeof flow->ct_label);
}

static void
compose_output_action__(struct xlate_ctx *ctx, ofp_port_t ofp_port,
                        const struct xlate_bond_recirc *xr, bool check_stp)
{
    const struct xport *xport = get_ofp_port(ctx->xbridge, ofp_port);
    struct flow_wildcards *wc = ctx->wc;
    struct flow *flow = &ctx->xin->flow;
    struct flow_tnl flow_tnl;
    ovs_be16 flow_vlan_tci;
    uint32_t flow_pkt_mark;
    uint8_t flow_nw_tos;
    odp_port_t out_port, odp_port;
    bool tnl_push_pop_send = false;
    uint8_t dscp;

    /* If 'struct flow' gets additional metadata, we'll need to zero it out
     * before traversing a patch port. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 35);
    memset(&flow_tnl, 0, sizeof flow_tnl);

    if (!xport) {
        xlate_report(ctx, "Nonexistent output port");
        return;
    } else if (xport->config & OFPUTIL_PC_NO_FWD) {
        xlate_report(ctx, "OFPPC_NO_FWD set, skipping output");
        return;
    } else if (check_stp) {
        if (is_stp(&ctx->base_flow)) {
            if (!xport_stp_should_forward_bpdu(xport) &&
                !xport_rstp_should_manage_bpdu(xport)) {
                if (ctx->xbridge->stp != NULL) {
                    xlate_report(ctx, "STP not in listening state, "
                            "skipping bpdu output");
                } else if (ctx->xbridge->rstp != NULL) {
                    xlate_report(ctx, "RSTP not managing BPDU in this state, "
                            "skipping bpdu output");
                }
                return;
            }
        } else if (!xport_stp_forward_state(xport) ||
                   !xport_rstp_forward_state(xport)) {
            if (ctx->xbridge->stp != NULL) {
                xlate_report(ctx, "STP not in forwarding state, "
                        "skipping output");
            } else if (ctx->xbridge->rstp != NULL) {
                xlate_report(ctx, "RSTP not in forwarding state, "
                        "skipping output");
            }
            return;
        }
    }

    if (xport->peer) {
        const struct xport *peer = xport->peer;
        struct flow old_flow = ctx->xin->flow;
        bool old_conntrack = ctx->conntracked;
        cls_version_t old_version = ctx->tables_version;
        struct ofpbuf old_stack = ctx->stack;
        union mf_subvalue new_stack[1024 / sizeof(union mf_subvalue)];
        struct ofpbuf old_action_set = ctx->action_set;
        uint64_t actset_stub[1024 / 8];

        ofpbuf_use_stub(&ctx->stack, new_stack, sizeof new_stack);
        ofpbuf_use_stub(&ctx->action_set, actset_stub, sizeof actset_stub);
        ctx->xbridge = peer->xbridge;
        flow->in_port.ofp_port = peer->ofp_port;
        flow->metadata = htonll(0);
        memset(&flow->tunnel, 0, sizeof flow->tunnel);
        memset(flow->regs, 0, sizeof flow->regs);
        flow->actset_output = OFPP_UNSET;
        ctx->conntracked = false;
        clear_conntrack(flow);

        /* The bridge is now known so obtain its table version. */
        ctx->tables_version
            = ofproto_dpif_get_tables_version(ctx->xbridge->ofproto);

        if (!process_special(ctx, peer) && may_receive(peer, ctx)) {
            if (xport_stp_forward_state(peer) && xport_rstp_forward_state(peer)) {
                xlate_table_action(ctx, flow->in_port.ofp_port, 0, true, true);
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
                mirror_mask_t old_mirrors = ctx->mirrors;

                xlate_table_action(ctx, flow->in_port.ofp_port, 0, true, true);
                ctx->mirrors = old_mirrors;
                ctx->base_flow = old_base_flow;
                ctx->odp_actions->size = old_size;

                /* Undo changes that may have been done for freezing. */
                ctx_cancel_freeze(ctx);
            }
        }

        ctx->xin->flow = old_flow;
        ctx->xbridge = xport->xbridge;
        ofpbuf_uninit(&ctx->action_set);
        ctx->action_set = old_action_set;
        ofpbuf_uninit(&ctx->stack);
        ctx->stack = old_stack;

        /* Restore calling bridge's lookup version. */
        ctx->tables_version = old_version;

        /* The peer bridge's conntrack execution should have no effect on the
         * original bridge. */
        ctx->conntracked = old_conntrack;

        /* The fact that the peer bridge exits (for any reason) does not mean
         * that the original bridge should exit.  Specifically, if the peer
         * bridge freezes translation, the original bridge must continue
         * processing with the original, not the frozen packet! */
        ctx->exit = false;

        /* Peer bridge errors do not propagate back. */
        ctx->error = XLATE_OK;

        if (ctx->xin->resubmit_stats) {
            netdev_vport_inc_tx(xport->netdev, ctx->xin->resubmit_stats);
            netdev_vport_inc_rx(peer->netdev, ctx->xin->resubmit_stats);
            if (peer->bfd) {
                bfd_account_rx(peer->bfd, ctx->xin->resubmit_stats);
            }
        }
        if (ctx->xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx->xin->xcache, XC_NETDEV);
            entry->u.dev.tx = netdev_ref(xport->netdev);
            entry->u.dev.rx = netdev_ref(peer->netdev);
            entry->u.dev.bfd = bfd_ref(peer->bfd);
        }
        return;
    }

    flow_vlan_tci = flow->vlan_tci;
    flow_pkt_mark = flow->pkt_mark;
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
            xlate_report(ctx, "Tunneling decided against output");
            goto out; /* restore flow_nw_tos */
        }
        dst = flow_tnl_dst(&flow->tunnel);
        if (ipv6_addr_equals(&dst, &ctx->orig_tunnel_ipv6_dst)) {
            xlate_report(ctx, "Not tunneling to our own address");
            goto out; /* restore flow_nw_tos */
        }
        if (ctx->xin->resubmit_stats) {
            netdev_vport_inc_tx(xport->netdev, ctx->xin->resubmit_stats);
        }
        if (ctx->xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx->xin->xcache, XC_NETDEV);
            entry->u.dev.tx = netdev_ref(xport->netdev);
        }
        out_port = odp_port;
        if (ovs_native_tunneling_is_on(ctx->xbridge->ofproto)) {
            xlate_report(ctx, "output to native tunnel");
            tnl_push_pop_send = true;
        } else {
            xlate_report(ctx, "output to kernel tunnel");
            commit_odp_tunnel_action(flow, &ctx->base_flow, ctx->odp_actions);
            flow->tunnel = flow_tnl; /* Restore tunnel metadata */
        }
    } else {
        odp_port = xport->odp_port;
        out_port = odp_port;
        if (ofproto_has_vlan_splinters(ctx->xbridge->ofproto)) {
            ofp_port_t vlandev_port;

            wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
            vlandev_port = vsp_realdev_to_vlandev(ctx->xbridge->ofproto,
                                                  ofp_port, flow->vlan_tci);
            if (vlandev_port != ofp_port) {
                out_port = ofp_port_to_odp_port(ctx->xbridge, vlandev_port);
                flow->vlan_tci = htons(0);
            }
        }
    }

    if (out_port != ODPP_NONE) {
        xlate_commit_actions(ctx);

        if (xr) {
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
        } else {

            if (tnl_push_pop_send) {
                build_tunnel_send(ctx, xport, flow, odp_port);
                flow->tunnel = flow_tnl; /* Restore tunnel metadata */
            } else {
                odp_port_t odp_tnl_port = ODPP_NONE;

                /* XXX: Write better Filter for tunnel port. We can use inport
                * int tunnel-port flow to avoid these checks completely. */
                if (ofp_port == OFPP_LOCAL &&
                    ovs_native_tunneling_is_on(ctx->xbridge->ofproto)) {

                    odp_tnl_port = tnl_port_map_lookup(flow, wc);
                }

                if (odp_tnl_port != ODPP_NONE) {
                    nl_msg_put_odp_port(ctx->odp_actions,
                                        OVS_ACTION_ATTR_TUNNEL_POP,
                                        odp_tnl_port);
                } else {
                    /* Tunnel push-pop action is not compatible with
                     * IPFIX action. */
                    compose_ipfix_action(ctx, out_port);
                    nl_msg_put_odp_port(ctx->odp_actions,
                                        OVS_ACTION_ATTR_OUTPUT,
                                        out_port);
               }
           }
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
    flow->vlan_tci = flow_vlan_tci;
    flow->pkt_mark = flow_pkt_mark;
    flow->nw_tos = flow_nw_tos;
}

static void
compose_output_action(struct xlate_ctx *ctx, ofp_port_t ofp_port,
                      const struct xlate_bond_recirc *xr)
{
    compose_output_action__(ctx, ofp_port, xr, true);
}

static void
xlate_recursively(struct xlate_ctx *ctx, struct rule_dpif *rule)
{
    struct rule_dpif *old_rule = ctx->rule;
    ovs_be64 old_cookie = ctx->rule_cookie;
    const struct rule_actions *actions;

    if (ctx->xin->resubmit_stats) {
        rule_dpif_credit_stats(rule, ctx->xin->resubmit_stats);
    }

    ctx->resubmits++;
    ctx->recurse++;
    ctx->rule = rule;
    ctx->rule_cookie = rule_dpif_get_flow_cookie(rule);
    actions = rule_dpif_get_actions(rule);
    do_xlate_actions(actions->ofpacts, actions->ofpacts_len, ctx);
    ctx->rule_cookie = old_cookie;
    ctx->rule = old_rule;
    ctx->recurse--;
}

static bool
xlate_resubmit_resource_check(struct xlate_ctx *ctx)
{
    if (ctx->recurse >= MAX_RESUBMIT_RECURSION + MAX_INTERNAL_RESUBMITS) {
        XLATE_REPORT_ERROR(ctx, "resubmit actions recursed over %d times",
                           MAX_RESUBMIT_RECURSION);
        ctx->error = XLATE_RECURSION_TOO_DEEP;
    } else if (ctx->resubmits >= MAX_RESUBMITS + MAX_INTERNAL_RESUBMITS) {
        XLATE_REPORT_ERROR(ctx, "over %d resubmit actions", MAX_RESUBMITS);
        ctx->error = XLATE_TOO_MANY_RESUBMITS;
    } else if (ctx->odp_actions->size > UINT16_MAX) {
        XLATE_REPORT_ERROR(ctx, "resubmits yielded over 64 kB of actions");
        /* NOT an error, as we'll be slow-pathing the flow in this case? */
        ctx->exit = true; /* XXX: translation still terminated! */
    } else if (ctx->stack.size >= 65536) {
        XLATE_REPORT_ERROR(ctx, "resubmits yielded over 64 kB of stack");
        ctx->error = XLATE_STACK_TOO_DEEP;
    } else {
        return true;
    }

    return false;
}

static void
xlate_table_action(struct xlate_ctx *ctx, ofp_port_t in_port, uint8_t table_id,
                   bool may_packet_in, bool honor_table_miss)
{
    if (xlate_resubmit_resource_check(ctx)) {
        uint8_t old_table_id = ctx->table_id;
        struct rule_dpif *rule;

        ctx->table_id = table_id;

        rule = rule_dpif_lookup_from_table(ctx->xbridge->ofproto,
                                           ctx->tables_version,
                                           &ctx->xin->flow, ctx->xin->wc,
                                           ctx->xin->resubmit_stats,
                                           &ctx->table_id, in_port,
                                           may_packet_in, honor_table_miss);

        if (OVS_UNLIKELY(ctx->xin->resubmit_hook)) {
            ctx->xin->resubmit_hook(ctx->xin, rule, ctx->recurse + 1);
        }

        if (rule) {
            /* Fill in the cache entry here instead of xlate_recursively
             * to make the reference counting more explicit.  We take a
             * reference in the lookups above if we are going to cache the
             * rule. */
            if (ctx->xin->xcache) {
                struct xc_entry *entry;

                entry = xlate_cache_add_entry(ctx->xin->xcache, XC_RULE);
                entry->u.rule = rule;
                rule_dpif_ref(rule);
            }
            xlate_recursively(ctx, rule);
        }

        ctx->table_id = old_table_id;
        return;
    }
}

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
        entry->u.group.group = group_dpif_ref(group);
        entry->u.group.bucket = bucket;
    }
}

static void
xlate_group_bucket(struct xlate_ctx *ctx, struct ofputil_bucket *bucket)
{
    uint64_t action_list_stub[1024 / 8];
    struct ofpbuf action_list = OFPBUF_STUB_INITIALIZER(action_list_stub);
    struct ofpbuf action_set = ofpbuf_const_initializer(bucket->ofpacts,
                                                        bucket->ofpacts_len);
    struct flow old_flow = ctx->xin->flow;

    ofpacts_execute_action_set(&action_list, &action_set);
    ctx->recurse++;
    do_xlate_actions(action_list.data, action_list.size, ctx);
    ctx->recurse--;

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

    /* The fact that the group bucket exits (for any reason) does not mean that
     * the translation after the group action should exit.  Specifically, if
     * the group bucket freezes translation, the actions after the group action
     * must continue processing with the original, not the frozen packet! */
    ctx->exit = false;
}

static void
xlate_all_group(struct xlate_ctx *ctx, struct group_dpif *group)
{
    struct ofputil_bucket *bucket;
    const struct ovs_list *buckets;

    group_dpif_get_buckets(group, &buckets);

    LIST_FOR_EACH (bucket, list_node, buckets) {
        xlate_group_bucket(ctx, bucket);
    }
    xlate_group_stats(ctx, group, NULL);
}

static void
xlate_ff_group(struct xlate_ctx *ctx, struct group_dpif *group)
{
    struct ofputil_bucket *bucket;

    bucket = group_first_live_bucket(ctx, group, 0);
    if (bucket) {
        xlate_group_bucket(ctx, bucket);
        xlate_group_stats(ctx, group, bucket);
    }
}

static void
xlate_default_select_group(struct xlate_ctx *ctx, struct group_dpif *group)
{
    struct flow_wildcards *wc = ctx->wc;
    struct ofputil_bucket *bucket;
    uint32_t basis;

    basis = flow_hash_symmetric_l4(&ctx->xin->flow, 0);
    flow_mask_hash_fields(&ctx->xin->flow, wc, NX_HASH_FIELDS_SYMMETRIC_L4);
    bucket = group_best_live_bucket(ctx, group, basis);
    if (bucket) {
        xlate_group_bucket(ctx, bucket);
        xlate_group_stats(ctx, group, bucket);
    }
}

static void
xlate_hash_fields_select_group(struct xlate_ctx *ctx, struct group_dpif *group)
{
    struct mf_bitmap hash_fields = MF_BITMAP_INITIALIZER;
    const struct field_array *fields;
    struct ofputil_bucket *bucket;
    uint32_t basis;
    int i;

    fields = group_dpif_get_fields(group);
    basis = hash_uint64(group_dpif_get_selection_method_param(group));

    /* Determine which fields to hash */
    for (i = 0; i < MFF_N_IDS; i++) {
        if (bitmap_is_set(fields->used.bm, i)) {
            const struct mf_field *mf;

            /* If the field is already present in 'hash_fields' then
             * this loop has already checked that it and its pre-requisites
             * are present in the flow and its pre-requisites have
             * already been added to 'hash_fields'. There is nothing more
             * to do here and as an optimisation the loop can continue. */
            if (bitmap_is_set(hash_fields.bm, i)) {
                continue;
            }

            mf = mf_from_id(i);

            /* Only hash a field if it and its pre-requisites are present
             * in the flow. */
            if (!mf_are_prereqs_ok(mf, &ctx->xin->flow)) {
                continue;
            }

            /* Hash both the field and its pre-requisites */
            mf_bitmap_set_field_and_prereqs(mf, &hash_fields);
        }
    }

    /* Hash the fields */
    for (i = 0; i < MFF_N_IDS; i++) {
        if (bitmap_is_set(hash_fields.bm, i)) {
            const struct mf_field *mf = mf_from_id(i);
            union mf_value value;
            int j;

            mf_get_value(mf, &ctx->xin->flow, &value);
            /* This seems inefficient but so does apply_mask() */
            for (j = 0; j < mf->n_bytes; j++) {
                ((uint8_t *) &value)[j] &= ((uint8_t *) &fields->value[i])[j];
            }
            basis = hash_bytes(&value, mf->n_bytes, basis);

            /* For tunnels, hash in whether the field is present. */
            if (mf_is_tun_metadata(mf)) {
                basis = hash_boolean(mf_is_set(mf, &ctx->xin->flow), basis);
            }

            mf_mask_field(mf, &ctx->wc->masks);
        }
    }

    bucket = group_best_live_bucket(ctx, group, basis);
    if (bucket) {
        xlate_group_bucket(ctx, bucket);
        xlate_group_stats(ctx, group, bucket);
    }
}

static void
xlate_select_group(struct xlate_ctx *ctx, struct group_dpif *group)
{
    const char *selection_method = group_dpif_get_selection_method(group);

    if (selection_method[0] == '\0') {
        xlate_default_select_group(ctx, group);
    } else if (!strcasecmp("hash", selection_method)) {
        xlate_hash_fields_select_group(ctx, group);
    } else {
        /* Parsing of groups should ensure this never happens */
        OVS_NOT_REACHED();
    }
}

static void
xlate_group_action__(struct xlate_ctx *ctx, struct group_dpif *group)
{
    bool was_in_group = ctx->in_group;
    ctx->in_group = true;

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
    group_dpif_unref(group);

    ctx->in_group = was_in_group;
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
                       honor_table_miss);
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
            compose_output_action__(ctx, xport->ofp_port, NULL, false);
        } else if (!(xport->config & OFPUTIL_PC_NO_FLOOD)) {
            compose_output_action(ctx, xport->ofp_port, NULL);
        }
    }

    ctx->nf_output_iface = NF_OUT_FLOOD;
}

static void
execute_controller_action(struct xlate_ctx *ctx, int len,
                          enum ofp_packet_in_reason reason,
                          uint16_t controller_id,
                          const uint8_t *userdata, size_t userdata_len)
{
    struct dp_packet *packet;

    ctx->xout->slow |= SLOW_CONTROLLER;
    xlate_commit_actions(ctx);
    if (!ctx->xin->packet) {
        return;
    }

    packet = dp_packet_clone(ctx->xin->packet);

    odp_execute_actions(NULL, &packet, 1, false,
                        ctx->odp_actions->data, ctx->odp_actions->size, NULL);

    /* A packet sent by an action in a table-miss rule is considered an
     * explicit table miss.  OpenFlow before 1.3 doesn't have that concept so
     * it will get translated back to OFPR_ACTION for those versions. */
    if (reason == OFPR_ACTION
        && ctx->rule && rule_dpif_is_table_miss(ctx->rule)) {
        reason = OFPR_EXPLICIT_MISS;
    }

    size_t packet_len = dp_packet_size(packet);

    struct ofproto_async_msg *am = xmalloc(sizeof *am);
    *am = (struct ofproto_async_msg) {
        .controller_id = controller_id,
        .oam = OAM_PACKET_IN,
        .pin = {
            .up = {
                .public = {
                    .packet = dp_packet_steal_data(packet),
                    .packet_len = packet_len,
                    .reason = reason,
                    .table_id = ctx->table_id,
                    .cookie = ctx->rule_cookie,
                    .userdata = (userdata_len
                                 ? xmemdup(userdata, userdata_len)
                                 : NULL),
                    .userdata_len = userdata_len,
                }
            },
            .max_len = len,
        },
    };
    flow_get_metadata(&ctx->xin->flow, &am->pin.up.public.flow_metadata);

    ofproto_dpif_send_async_msg(ctx->xbridge->ofproto, am);
    dp_packet_delete(packet);
}

static void
emit_continuation(struct xlate_ctx *ctx, const struct frozen_state *state)
{
    struct ofproto_async_msg *am = xmalloc(sizeof *am);
    *am = (struct ofproto_async_msg) {
        .controller_id = ctx->pause->controller_id,
        .oam = OAM_PACKET_IN,
        .pin = {
            .up = {
                .public = {
                    .userdata = xmemdup(ctx->pause->userdata,
                                        ctx->pause->userdata_len),
                    .userdata_len = ctx->pause->userdata_len,
                    .packet = xmemdup(dp_packet_data(ctx->xin->packet),
                                      dp_packet_size(ctx->xin->packet)),
                    .packet_len = dp_packet_size(ctx->xin->packet),
                    .reason = ctx->pause->reason,
                },
                .bridge = *ofproto_dpif_get_uuid(ctx->xbridge->ofproto),
                .stack = xmemdup(state->stack,
                                 state->n_stack * sizeof *state->stack),
                .n_stack = state->n_stack,
                .mirrors = state->mirrors,
                .conntracked = state->conntracked,
                .actions = xmemdup(state->ofpacts, state->ofpacts_len),
                .actions_len = state->ofpacts_len,
                .action_set = xmemdup(state->action_set,
                                      state->action_set_len),
                .action_set_len = state->action_set_len,
            },
            .max_len = UINT16_MAX,
        },
    };
    flow_get_metadata(&ctx->xin->flow, &am->pin.up.public.flow_metadata);
    ofproto_dpif_send_async_msg(ctx->xbridge->ofproto, am);
}

static void
finish_freezing__(struct xlate_ctx *ctx, uint8_t table)
{
    ovs_assert(ctx->freezing);

    struct frozen_state state = {
        .table_id = table,
        .ofproto_uuid = *ofproto_dpif_get_uuid(ctx->xbridge->ofproto),
        .stack = ctx->stack.data,
        .n_stack = ctx->stack.size / sizeof(union mf_subvalue),
        .mirrors = ctx->mirrors,
        .conntracked = ctx->conntracked,
        .ofpacts = ctx->frozen_actions.data,
        .ofpacts_len = ctx->frozen_actions.size,
        .action_set = ctx->action_set.data,
        .action_set_len = ctx->action_set.size,
    };
    frozen_metadata_from_flow(&state.metadata, &ctx->xin->flow);

    if (ctx->pause) {
        if (ctx->xin->packet) {
            emit_continuation(ctx, &state);
        }
    } else {
        /* Allocate a unique recirc id for the given metadata state in the
         * flow.  An existing id, with a new reference to the corresponding
         * recirculation context, will be returned if possible.
         * The life-cycle of this recirc id is managed by associating it
         * with the udpif key ('ukey') created for each new datapath flow. */
        uint32_t id = recirc_alloc_id_ctx(&state);
        if (!id) {
            XLATE_REPORT_ERROR(ctx, "Failed to allocate recirculation id");
            ctx->error = XLATE_NO_RECIRCULATION_CONTEXT;
            return;
        }
        recirc_refs_add(&ctx->xout->recircs, id);

        nl_msg_put_u32(ctx->odp_actions, OVS_ACTION_ATTR_RECIRC, id);
    }

    /* Undo changes done by freezing. */
    ctx_cancel_freeze(ctx);
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
compose_recirculate_and_fork(struct xlate_ctx *ctx, uint8_t table)
{
    ctx->freezing = true;
    finish_freezing__(ctx, table);
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
            XLATE_REPORT_ERROR(ctx, "bridge %s: dropping packet on which an "
                         "MPLS push action can't be performed as it would "
                         "have more MPLS LSEs than the %d supported.",
                         ctx->xbridge->name, FLOW_MAX_MPLS_LABELS);
        }
        ctx->error = XLATE_TOO_MANY_MPLS_LABELS;
        return;
    }

    flow_push_mpls(flow, n, mpls->ethertype, ctx->wc);
}

static void
compose_mpls_pop_action(struct xlate_ctx *ctx, ovs_be16 eth_type)
{
    struct flow *flow = &ctx->xin->flow;
    int n = flow_count_mpls_labels(flow, ctx->wc);

    if (flow_pop_mpls(flow, n, eth_type, ctx->wc)) {
        if (!eth_type_mpls(eth_type) && ctx->xbridge->support.odp.recirc) {
            ctx_trigger_freeze(ctx);
        }
    } else if (n >= FLOW_MAX_MPLS_LABELS) {
        if (ctx->xin->packet != NULL) {
            XLATE_REPORT_ERROR(ctx, "bridge %s: dropping packet on which an "
                         "MPLS pop action can't be performed as it has "
                         "more MPLS LSEs than the %d supported.",
                         ctx->xbridge->name, FLOW_MAX_MPLS_LABELS);
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
            execute_controller_action(ctx, UINT16_MAX, OFPR_INVALID_TTL,
                                      ids->cnt_ids[i], NULL, 0);
        }

        /* Stop processing for current table. */
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
            execute_controller_action(ctx, UINT16_MAX, OFPR_INVALID_TTL, 0,
                                      NULL, 0);
        }
    }

    /* Stop processing for current table. */
    return true;
}

static void
xlate_output_action(struct xlate_ctx *ctx,
                    ofp_port_t port, uint16_t max_len, bool may_packet_in)
{
    ofp_port_t prev_nf_output_iface = ctx->nf_output_iface;

    ctx->nf_output_iface = NF_OUT_DROP;

    switch (port) {
    case OFPP_IN_PORT:
        compose_output_action(ctx, ctx->xin->flow.in_port.ofp_port, NULL);
        break;
    case OFPP_TABLE:
        xlate_table_action(ctx, ctx->xin->flow.in_port.ofp_port,
                           0, may_packet_in, true);
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
        execute_controller_action(ctx, max_len,
                                  (ctx->in_group ? OFPR_GROUP
                                   : ctx->in_action_set ? OFPR_ACTION_SET
                                   : OFPR_ACTION),
                                  0, NULL, 0);
        break;
    case OFPP_NONE:
        break;
    case OFPP_LOCAL:
    default:
        if (port != ctx->xin->flow.in_port.ofp_port) {
            compose_output_action(ctx, port, NULL);
        } else {
            xlate_report(ctx, "skipping output to input port");
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
                        const struct ofpact_output_reg *or)
{
    uint64_t port = mf_get_subfield(&or->src, &ctx->xin->flow);
    if (port <= UINT16_MAX) {
        union mf_subvalue value;

        memset(&value, 0xff, sizeof value);
        mf_write_subfield_flow(&or->src, &value, &ctx->wc->masks);
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
    compose_output_action(ctx, ofp_port, NULL);
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
                    const struct ofpact_bundle *bundle)
{
    ofp_port_t port;

    port = bundle_execute(bundle, &ctx->xin->flow, ctx->wc, slave_enabled_cb,
                          CONST_CAST(struct xbridge *, ctx->xbridge));
    if (bundle->dst.field) {
        nxm_reg_load(&bundle->dst, ofp_to_u16(port), &ctx->xin->flow, ctx->wc);
    } else {
        xlate_output_action(ctx, port, 0, false);
    }
}

static void
xlate_learn_action__(struct xlate_ctx *ctx, const struct ofpact_learn *learn,
                     struct ofputil_flow_mod *fm, struct ofpbuf *ofpacts)
{
    learn_execute(learn, &ctx->xin->flow, fm, ofpacts);
    if (ctx->xin->may_learn) {
        ofproto_dpif_flow_mod(ctx->xbridge->ofproto, fm);
    }
}

static void
xlate_learn_action(struct xlate_ctx *ctx, const struct ofpact_learn *learn)
{
    learn_mask(learn, ctx->wc);

    if (ctx->xin->xcache) {
        struct xc_entry *entry;

        entry = xlate_cache_add_entry(ctx->xin->xcache, XC_LEARN);
        entry->u.learn.ofproto = ctx->xbridge->ofproto;
        entry->u.learn.fm = xmalloc(sizeof *entry->u.learn.fm);
        entry->u.learn.ofpacts = ofpbuf_new(64);
        xlate_learn_action__(ctx, learn, entry->u.learn.fm,
                             entry->u.learn.ofpacts);
    } else if (ctx->xin->may_learn) {
        uint64_t ofpacts_stub[1024 / 8];
        struct ofputil_flow_mod fm;
        struct ofpbuf ofpacts;

        ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
        xlate_learn_action__(ctx, learn, &fm, &ofpacts);
        ofpbuf_uninit(&ofpacts);
    }
}

static void
xlate_fin_timeout__(struct rule_dpif *rule, uint16_t tcp_flags,
                    uint16_t idle_timeout, uint16_t hard_timeout)
{
    if (tcp_flags & (TCP_FIN | TCP_RST)) {
        rule_dpif_reduce_timeouts(rule, idle_timeout, hard_timeout);
    }
}

static void
xlate_fin_timeout(struct xlate_ctx *ctx,
                  const struct ofpact_fin_timeout *oft)
{
    if (ctx->rule) {
        xlate_fin_timeout__(ctx->rule, ctx->xin->tcp_flags,
                            oft->fin_idle_timeout, oft->fin_hard_timeout);
        if (ctx->xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx->xin->xcache, XC_FIN_TIMEOUT);
            /* XC_RULE already holds a reference on the rule, none is taken
             * here. */
            entry->u.fin.rule = ctx->rule;
            entry->u.fin.idle = oft->fin_idle_timeout;
            entry->u.fin.hard = oft->fin_hard_timeout;
        }
    }
}

static void
xlate_sample_action(struct xlate_ctx *ctx,
                    const struct ofpact_sample *os)
{
    /* Scale the probability from 16-bit to 32-bit while representing
     * the same percentage. */
    uint32_t probability = (os->probability << 16) | os->probability;

    if (!ctx->xbridge->support.variable_length_userdata) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&rl, "ignoring NXAST_SAMPLE action because datapath "
                    "lacks support (needs Linux 3.10+ or kernel module from "
                    "OVS 1.11+)");
        return;
    }

    xlate_commit_actions(ctx);

    union user_action_cookie cookie = {
        .flow_sample = {
            .type = USER_ACTION_COOKIE_FLOW_SAMPLE,
            .probability = os->probability,
            .collector_set_id = os->collector_set_id,
            .obs_domain_id = os->obs_domain_id,
            .obs_point_id = os->obs_point_id,
        }
    };
    compose_sample_action(ctx, probability, &cookie, sizeof cookie.flow_sample,
                          ODPP_NONE, false);
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
    uint64_t action_list_stub[1024 / 64];
    struct ofpbuf action_list;

    ctx->in_action_set = true;
    ofpbuf_use_stub(&action_list, action_list_stub, sizeof action_list_stub);
    ofpacts_execute_action_set(&action_list, &ctx->action_set);
    /* Clear the action set, as it is not needed any more. */
    ofpbuf_clear(&ctx->action_set);
    do_xlate_actions(action_list.data, action_list.size, ctx);
    ctx->in_action_set = false;
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
        case OFPACT_GROUP:
        case OFPACT_OUTPUT:
        case OFPACT_CONTROLLER:
        case OFPACT_DEC_MPLS_TTL:
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
        case OFPACT_DEBUG_RECIRC:
        case OFPACT_CT:
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
    if (!ovs_u128_is_zero(&wc->masks.ct_label)) {
        struct {
            ovs_u128 key;
            ovs_u128 mask;
        } *odp_ct_label;

        odp_ct_label = nl_msg_put_unspec_uninit(odp_actions,
                                                OVS_CT_ATTR_LABELS,
                                                sizeof(*odp_ct_label));
        odp_ct_label->key = ovs_u128_and(flow->ct_label, wc->masks.ct_label);
        odp_ct_label->mask = wc->masks.ct_label;
    }
}

static void
put_ct_helper(struct ofpbuf *odp_actions, struct ofpact_conntrack *ofc)
{
    if (ofc->alg) {
        if (ofc->alg == IPPORT_FTP) {
            nl_msg_put_string(odp_actions, OVS_CT_ATTR_HELPER, "ftp");
        } else {
            VLOG_WARN("Cannot serialize ct_helper %d\n", ofc->alg);
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
compose_conntrack_action(struct xlate_ctx *ctx, struct ofpact_conntrack *ofc)
{
    ovs_u128 old_ct_label = ctx->base_flow.ct_label;
    ovs_u128 old_ct_label_mask = ctx->wc->masks.ct_label;
    uint32_t old_ct_mark = ctx->base_flow.ct_mark;
    uint32_t old_ct_mark_mask = ctx->wc->masks.ct_mark;
    size_t ct_offset;
    uint16_t zone;

    /* Ensure that any prior actions are applied before composing the new
     * conntrack action. */
    xlate_commit_actions(ctx);

    /* Process nested actions first, to populate the key. */
    ctx->ct_nat_action = NULL;
    ctx->wc->masks.ct_mark = 0;
    ctx->wc->masks.ct_label.u64.hi = ctx->wc->masks.ct_label.u64.lo = 0;
    do_xlate_actions(ofc->actions, ofpact_ct_get_action_len(ofc), ctx);

    if (ofc->zone_src.field) {
        zone = mf_get_subfield(&ofc->zone_src, &ctx->xin->flow);
    } else {
        zone = ofc->zone_imm;
    }

    ct_offset = nl_msg_start_nested(ctx->odp_actions, OVS_ACTION_ATTR_CT);
    if (ofc->flags & NX_CT_F_COMMIT) {
        nl_msg_put_flag(ctx->odp_actions, OVS_CT_ATTR_COMMIT);
    }
    nl_msg_put_u16(ctx->odp_actions, OVS_CT_ATTR_ZONE, zone);
    put_ct_mark(&ctx->xin->flow, ctx->odp_actions, ctx->wc);
    put_ct_label(&ctx->xin->flow, ctx->odp_actions, ctx->wc);
    put_ct_helper(ctx->odp_actions, ofc);
    put_ct_nat(ctx);
    ctx->ct_nat_action = NULL;
    nl_msg_end_nested(ctx->odp_actions, ct_offset);

    /* Restore the original ct fields in the key. These should only be exposed
     * after recirculation to another table. */
    ctx->base_flow.ct_mark = old_ct_mark;
    ctx->wc->masks.ct_mark = old_ct_mark_mask;
    ctx->base_flow.ct_label = old_ct_label;
    ctx->wc->masks.ct_label = old_ct_label_mask;

    if (ofc->recirc_table == NX_CT_RECIRC_NONE) {
        /* If we do not recirculate as part of this action, hide the results of
         * connection tracking from subsequent recirculations. */
        ctx->conntracked = false;
    } else {
        /* Use ct_* fields from datapath during recirculation upcall. */
        ctx->conntracked = true;
        compose_recirculate_and_fork(ctx, ofc->recirc_table);
    }
}

static void
do_xlate_actions(const struct ofpact *ofpacts, size_t ofpacts_len,
                 struct xlate_ctx *ctx)
{
    struct flow_wildcards *wc = ctx->wc;
    struct flow *flow = &ctx->xin->flow;
    const struct ofpact *a;

    if (ovs_native_tunneling_is_on(ctx->xbridge->ofproto)) {
        tnl_neigh_snoop(flow, wc, ctx->xbridge->name);
    }
    /* dl_type already in the mask, not set below. */

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        struct ofpact_controller *controller;
        const struct ofpact_metadata *metadata;
        const struct ofpact_set_field *set_field;
        const struct mf_field *mf;

        if (ctx->error) {
            break;
        }

        if (ctx->exit) {
            /* Check if need to store the remaining actions for later
             * execution. */
            if (ctx->freezing) {
                freeze_unroll_actions(a, ofpact_end(ofpacts, ofpacts_len),
                                      ctx);
            }
            break;
        }

        switch (a->type) {
        case OFPACT_OUTPUT:
            xlate_output_action(ctx, ofpact_get_OUTPUT(a)->port,
                                ofpact_get_OUTPUT(a)->max_len, true);
            break;

        case OFPACT_GROUP:
            if (xlate_group_action(ctx, ofpact_get_GROUP(a)->group_id)) {
                /* Group could not be found. */
                return;
            }
            break;

        case OFPACT_CONTROLLER:
            controller = ofpact_get_CONTROLLER(a);
            if (controller->pause) {
                ctx->pause = controller;
                ctx->xout->slow |= SLOW_CONTROLLER;
                ctx_trigger_freeze(ctx);
                a = ofpact_next(a);
            } else {
                execute_controller_action(ctx, controller->max_len,
                                          controller->reason,
                                          controller->controller_id,
                                          controller->userdata,
                                          controller->userdata_len);
            }
            break;

        case OFPACT_ENQUEUE:
            memset(&wc->masks.skb_priority, 0xff,
                   sizeof wc->masks.skb_priority);
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
            xlate_ofpact_resubmit(ctx, ofpact_get_RESUBMIT(a));
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
            flow->skb_priority = ctx->orig_skb_priority;
            break;

        case OFPACT_REG_MOVE:
            nxm_execute_reg_move(ofpact_get_REG_MOVE(a), flow, wc);
            break;

        case OFPACT_SET_FIELD:
            set_field = ofpact_get_SET_FIELD(a);
            mf = set_field->field;

            /* Set field action only ever overwrites packet's outermost
             * applicable header fields.  Do nothing if no header exists. */
            if (mf->id == MFF_VLAN_VID) {
                wc->masks.vlan_tci |= htons(VLAN_CFI);
                if (!(flow->vlan_tci & htons(VLAN_CFI))) {
                    break;
                }
            } else if ((mf->id == MFF_MPLS_LABEL || mf->id == MFF_MPLS_TC)
                       /* 'dl_type' is already unwildcarded. */
                       && !eth_type_mpls(flow->dl_type)) {
                break;
            }
            /* A flow may wildcard nw_frag.  Do nothing if setting a transport
             * header field on a packet that does not have them. */
            mf_mask_field_and_prereqs__(mf, &set_field->mask, wc);
            if (mf_are_prereqs_ok(mf, flow)) {
                mf_set_flow_value_masked(mf, &set_field->value,
                                         &set_field->mask, flow);
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

        case OFPACT_CONJUNCTION: {
            /* A flow with a "conjunction" action represents part of a special
             * kind of "set membership match".  Such a flow should not actually
             * get executed, but it could via, say, a "packet-out", even though
             * that wouldn't be useful.  Log it to help debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl, "executing no-op conjunction action");
            break;
        }

        case OFPACT_EXIT:
            ctx->exit = true;
            break;

        case OFPACT_UNROLL_XLATE: {
            struct ofpact_unroll_xlate *unroll = ofpact_get_UNROLL_XLATE(a);

            /* Restore translation context data that was stored earlier. */
            ctx->table_id = unroll->rule_table_id;
            ctx->rule_cookie = unroll->rule_cookie;
            break;
        }
        case OFPACT_FIN_TIMEOUT:
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
            xlate_fin_timeout(ctx, ofpact_get_FIN_TIMEOUT(a));
            break;

        case OFPACT_CLEAR_ACTIONS:
            ofpbuf_clear(&ctx->action_set);
            ctx->xin->flow.actset_output = OFPP_UNSET;
            ctx->action_set_has_group = false;
            break;

        case OFPACT_WRITE_ACTIONS:
            xlate_write_actions(ctx, ofpact_get_WRITE_ACTIONS(a));
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
                               ogt->table_id, true, true);
            break;
        }

        case OFPACT_SAMPLE:
            xlate_sample_action(ctx, ofpact_get_SAMPLE(a));
            break;

        case OFPACT_CT:
            compose_conntrack_action(ctx, ofpact_get_CT(a));
            break;

        case OFPACT_NAT:
            /* This will be processed by compose_conntrack_action(). */
            ctx->ct_nat_action = ofpact_get_NAT(a);
            break;

        case OFPACT_DEBUG_RECIRC:
            ctx_trigger_freeze(ctx);
            a = ofpact_next(a);
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
              const struct flow *flow, ofp_port_t in_port,
              struct rule_dpif *rule, uint16_t tcp_flags,
              const struct dp_packet *packet, struct flow_wildcards *wc,
              struct ofpbuf *odp_actions)
{
    xin->ofproto = ofproto;
    xin->flow = *flow;
    xin->flow.in_port.ofp_port = in_port;
    xin->flow.actset_output = OFPP_UNSET;
    xin->packet = packet;
    xin->may_learn = packet != NULL;
    xin->rule = rule;
    xin->xcache = NULL;
    xin->ofpacts = NULL;
    xin->ofpacts_len = 0;
    xin->tcp_flags = tcp_flags;
    xin->resubmit_hook = NULL;
    xin->report_hook = NULL;
    xin->resubmit_stats = NULL;
    xin->recurse = 0;
    xin->resubmits = 0;
    xin->wc = wc;
    xin->odp_actions = odp_actions;

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

/* Translates the 'ofpacts_len' bytes of "struct ofpact"s starting at 'ofpacts'
 * into datapath actions, using 'ctx', and discards the datapath actions. */
void
xlate_actions_for_side_effects(struct xlate_in *xin)
{
    struct xlate_out xout;
    enum xlate_error error;

    error = xlate_actions(xin, &xout);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_WARN_RL(&rl, "xlate_actions failed (%s)!", xlate_strerror(error));
    }

    xlate_out_uninit(&xout);
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
    WC_MASK_FIELD(ctx->wc, in_port);
    WC_MASK_FIELD(ctx->wc, dl_type);
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
    /* Clear the metadata and register wildcard masks, because we won't
     * use non-header fields as part of the cache. */
    flow_wildcards_clear_non_packet_fields(ctx->wc);

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
    if (is_icmpv4(&ctx->xin->flow) || is_icmpv6(&ctx->xin->flow)) {
        ctx->wc->masks.tp_src &= htons(UINT8_MAX);
        ctx->wc->masks.tp_dst &= htons(UINT8_MAX);
    }
    /* VLAN_TCI CFI bit must be matched if any of the TCI is matched. */
    if (ctx->wc->masks.vlan_tci) {
        ctx->wc->masks.vlan_tci |= htons(VLAN_CFI);
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

    union mf_subvalue stack_stub[1024 / sizeof(union mf_subvalue)];
    uint64_t action_set_stub[1024 / 8];
    uint64_t frozen_actions_stub[1024 / 8];
    struct flow_wildcards scratch_wc;
    uint64_t actions_stub[256 / 8];
    struct ofpbuf scratch_actions = OFPBUF_STUB_INITIALIZER(actions_stub);
    struct xlate_ctx ctx = {
        .xin = xin,
        .xout = xout,
        .base_flow = *flow,
        .orig_tunnel_ipv6_dst = flow_tnl_dst(&flow->tunnel),
        .xbridge = xbridge,
        .stack = OFPBUF_STUB_INITIALIZER(stack_stub),
        .rule = xin->rule,
        .wc = xin->wc ? xin->wc : &scratch_wc,
        .odp_actions = xin->odp_actions ? xin->odp_actions : &scratch_actions,

        .recurse = xin->recurse,
        .resubmits = xin->resubmits,
        .in_group = false,
        .in_action_set = false,

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
        .frozen_actions = OFPBUF_STUB_INITIALIZER(frozen_actions_stub),
        .pause = NULL,

        .conntracked = false,

        .ct_nat_action = NULL,

        .action_set_has_group = false,
        .action_set = OFPBUF_STUB_INITIALIZER(action_set_stub),
    };

    /* 'base_flow' reflects the packet as it came in, but we need it to reflect
     * the packet as the datapath will treat it for output actions:
     *
     *     - Our datapath doesn't retain tunneling information without us
     *       re-setting it, so clear the tunnel data.
     *
     *     - For VLAN splinters, a higher layer may pretend that the packet
     *       came in on 'flow->in_port.ofp_port' with 'flow->vlan_tci'
     *       attached, because that's how we want to treat it from an OpenFlow
     *       perspective.  But from the datapath's perspective it actually came
     *       in on a VLAN device without any VLAN attached.  So here we put the
     *       datapath's view of the VLAN information in 'base_flow' to ensure
     *       correct treatment.
     */
    memset(&ctx.base_flow.tunnel, 0, sizeof ctx.base_flow.tunnel);
    if (flow->in_port.ofp_port
        != vsp_realdev_to_vlandev(xbridge->ofproto,
                                  flow->in_port.ofp_port,
                                  flow->vlan_tci)) {
        ctx.base_flow.vlan_tci = 0;
    }

    ofpbuf_reserve(ctx.odp_actions, NL_A_U32_SIZE);
    if (xin->wc) {
        xlate_wc_init(&ctx);
    }

    COVERAGE_INC(xlate_actions);

    if (xin->frozen_state) {
        const struct frozen_state *state = xin->frozen_state;

        xlate_report(&ctx, "Thawing frozen state:");

        if (xin->ofpacts_len > 0 || ctx.rule) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            const char *conflict = xin->ofpacts_len ? "actions" : "rule";

            VLOG_WARN_RL(&rl, "Recirculation conflict (%s)!", conflict);
            xlate_report(&ctx, "- Recirculation conflict (%s)!", conflict);
            ctx.error = XLATE_RECIRCULATION_CONFLICT;
            goto exit;
        }

        /* Set the bridge for post-recirculation processing if needed. */
        if (!uuid_equals(ofproto_dpif_get_uuid(ctx.xbridge->ofproto),
                         &state->ofproto_uuid)) {
            struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
            const struct xbridge *new_bridge
                = xbridge_lookup_by_uuid(xcfg, &state->ofproto_uuid);

            if (OVS_UNLIKELY(!new_bridge)) {
                /* Drop the packet if the bridge cannot be found. */
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "Frozen bridge no longer exists.");
                xlate_report(&ctx, "- Frozen bridge no longer exists.");
                ctx.error = XLATE_BRIDGE_NOT_FOUND;
                goto exit;
            }
            ctx.xbridge = new_bridge;
        }

        /* Set the thawed table id.  Note: A table lookup is done only if there
         * are no frozen actions. */
        ctx.table_id = state->table_id;
        xlate_report(&ctx, "- Resuming from table %"PRIu8, ctx.table_id);

        if (!state->conntracked) {
            clear_conntrack(flow);
        }

        /* Restore pipeline metadata. May change flow's in_port and other
         * metadata to the values that existed when freezing was triggered. */
        frozen_metadata_to_flow(&state->metadata, flow);

        /* Restore stack, if any. */
        if (state->stack) {
            ofpbuf_put(&ctx.stack, state->stack,
                       state->n_stack * sizeof *state->stack);
        }

        /* Restore mirror state. */
        ctx.mirrors = state->mirrors;

        /* Restore action set, if any. */
        if (state->action_set_len) {
            xlate_report_actions(&ctx, "- Restoring action set",
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
            xlate_report_actions(&ctx, "- Restoring actions",
                                 xin->ofpacts, xin->ofpacts_len);
        }
    } else if (OVS_UNLIKELY(flow->recirc_id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_WARN_RL(&rl, "Recirculation context not found for ID %"PRIx32,
                     flow->recirc_id);
        ctx.error = XLATE_NO_RECIRCULATION_CONTEXT;
        goto exit;
    }
    /* The bridge is now known so obtain its table version. */
    ctx.tables_version = ofproto_dpif_get_tables_version(ctx.xbridge->ofproto);

    if (!xin->ofpacts && !ctx.rule) {
        ctx.rule = rule_dpif_lookup_from_table(
            ctx.xbridge->ofproto, ctx.tables_version, flow, xin->wc,
            ctx.xin->resubmit_stats, &ctx.table_id,
            flow->in_port.ofp_port, true, true);
        if (ctx.xin->resubmit_stats) {
            rule_dpif_credit_stats(ctx.rule, ctx.xin->resubmit_stats);
        }
        if (ctx.xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx.xin->xcache, XC_RULE);
            entry->u.rule = ctx.rule;
            rule_dpif_ref(ctx.rule);
        }

        if (OVS_UNLIKELY(ctx.xin->resubmit_hook)) {
            ctx.xin->resubmit_hook(ctx.xin, ctx.rule, 0);
        }
    }

    /* Get the proximate input port of the packet.  (If xin->frozen_state,
     * flow->in_port is the ultimate input port of the packet.) */
    struct xport *in_port = get_ofp_port(xbridge,
                                         ctx.base_flow.in_port.ofp_port);

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
            entry->u.dev.rx = netdev_ref(in_port->netdev);
            entry->u.dev.bfd = bfd_ref(in_port->bfd);
        }
    }

    if (!xin->frozen_state && process_special(&ctx, in_port)) {
        /* process_special() did all the processing for this packet.
         *
         * We do not perform special processing on thawed packets, since that
         * was done before they were frozen and should not be redone. */
    } else if (in_port && in_port->xbundle
               && xbundle_mirror_out(xbridge, in_port->xbundle)) {
        if (ctx.xin->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port "
                         "%s, which is reserved exclusively for mirroring",
                         ctx.xbridge->name, in_port->xbundle->name);
        }
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
                    = rule_dpif_get_actions(ctx.rule);
                ofpacts = actions->ofpacts;
                ofpacts_len = actions->ofpacts_len;
                ctx.rule_cookie = rule_dpif_get_flow_cookie(ctx.rule);
            } else {
                OVS_NOT_REACHED();
            }

            mirror_ingress_packet(&ctx);
            do_xlate_actions(ofpacts, ofpacts_len, &ctx);
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
            compose_output_action(&ctx, OFPP_LOCAL, NULL);
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

    /* Do netflow only for packets on initial reception, that are not sent to
     * the controller.  We consider packets sent to the controller to be part
     * of the control plane rather than the data plane. */
    if (!xin->frozen_state
        && xbridge->netflow
        && !(xout->slow & SLOW_CONTROLLER)) {
        if (ctx.xin->resubmit_stats) {
            netflow_flow_update(xbridge->netflow, flow,
                                ctx.nf_output_iface,
                                ctx.xin->resubmit_stats);
        }
        if (ctx.xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx.xin->xcache, XC_NETFLOW);
            entry->u.nf.netflow = netflow_ref(xbridge->netflow);
            entry->u.nf.flow = xmemdup(flow, sizeof *flow);
            entry->u.nf.iface = ctx.nf_output_iface;
        }
    }

    if (xin->wc) {
        xlate_wc_finish(&ctx);
    }

exit:
    ofpbuf_uninit(&ctx.stack);
    ofpbuf_uninit(&ctx.action_set);
    ofpbuf_uninit(&ctx.frozen_actions);
    ofpbuf_uninit(&scratch_actions);

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
    dp_packet_use_const(&packet, pin->public.packet,
                        pin->public.packet_len);

    struct flow flow;
    flow_extract(&packet, &flow);

    struct xlate_in xin;
    xlate_in_init(&xin, ofproto, &flow, 0, NULL, ntohs(flow.tcp_flags),
                  &packet, NULL, odp_actions);

    struct ofpact_note noop;
    ofpact_init_NOTE(&noop);
    noop.length = 0;

    bool any_actions = pin->actions_len > 0;
    struct frozen_state state = {
        .table_id = 0,     /* Not the table where NXAST_PAUSE was executed. */
        .ofproto_uuid = pin->bridge,
        .stack = pin->stack,
        .n_stack = pin->n_stack,
        .mirrors = pin->mirrors,
        .conntracked = pin->conntracked,

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
                              &pin->public.flow_metadata.flow);
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

/* Sends 'packet' out 'ofport'.
 * May modify 'packet'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
xlate_send_packet(const struct ofport_dpif *ofport, struct dp_packet *packet)
{
    struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    struct xport *xport;
    struct ofpact_output output;
    struct flow flow;

    ofpact_init(&output.ofpact, OFPACT_OUTPUT, sizeof output);
    /* Use OFPP_NONE as the in_port to avoid special packet processing. */
    flow_extract(packet, &flow);
    flow.in_port.ofp_port = OFPP_NONE;

    xport = xport_lookup(xcfg, ofport);
    if (!xport) {
        return EINVAL;
    }
    output.port = xport->ofp_port;
    output.max_len = 0;

    return ofproto_dpif_execute_actions(xport->xbridge->ofproto, &flow, NULL,
                                        &output.ofpact, sizeof output,
                                        packet);
}

struct xlate_cache *
xlate_cache_new(void)
{
    struct xlate_cache *xcache = xmalloc(sizeof *xcache);

    ofpbuf_init(&xcache->entries, 512);
    return xcache;
}

static struct xc_entry *
xlate_cache_add_entry(struct xlate_cache *xcache, enum xc_type type)
{
    struct xc_entry *entry;

    entry = ofpbuf_put_zeros(&xcache->entries, sizeof *entry);
    entry->type = type;

    return entry;
}

static void
xlate_cache_netdev(struct xc_entry *entry, const struct dpif_flow_stats *stats)
{
    if (entry->u.dev.tx) {
        netdev_vport_inc_tx(entry->u.dev.tx, stats);
    }
    if (entry->u.dev.rx) {
        netdev_vport_inc_rx(entry->u.dev.rx, stats);
    }
    if (entry->u.dev.bfd) {
        bfd_account_rx(entry->u.dev.bfd, stats);
    }
}

static void
xlate_cache_normal(struct ofproto_dpif *ofproto, struct flow *flow, int vlan)
{
    struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    struct xbridge *xbridge;
    struct xbundle *xbundle;
    struct flow_wildcards wc;

    xbridge = xbridge_lookup(xcfg, ofproto);
    if (!xbridge) {
        return;
    }

    xbundle = lookup_input_bundle(xbridge, flow->in_port.ofp_port, false,
                                  NULL);
    if (!xbundle) {
        return;
    }

    update_learning_table(xbridge, flow, &wc, vlan, xbundle);
}

/* Push stats and perform side effects of flow translation. */
void
xlate_push_stats(struct xlate_cache *xcache,
                 const struct dpif_flow_stats *stats)
{
    struct xc_entry *entry;
    struct ofpbuf entries = xcache->entries;
    struct eth_addr dmac;

    if (!stats->n_packets) {
        return;
    }

    XC_ENTRY_FOR_EACH (entry, entries, xcache) {
        switch (entry->type) {
        case XC_RULE:
            rule_dpif_credit_stats(entry->u.rule, stats);
            break;
        case XC_BOND:
            bond_account(entry->u.bond.bond, entry->u.bond.flow,
                         entry->u.bond.vid, stats->n_bytes);
            break;
        case XC_NETDEV:
            xlate_cache_netdev(entry, stats);
            break;
        case XC_NETFLOW:
            netflow_flow_update(entry->u.nf.netflow, entry->u.nf.flow,
                                entry->u.nf.iface, stats);
            break;
        case XC_MIRROR:
            mirror_update_stats(entry->u.mirror.mbridge,
                                entry->u.mirror.mirrors,
                                stats->n_packets, stats->n_bytes);
            break;
        case XC_LEARN:
            ofproto_dpif_flow_mod(entry->u.learn.ofproto, entry->u.learn.fm);
            break;
        case XC_NORMAL:
            xlate_cache_normal(entry->u.normal.ofproto, entry->u.normal.flow,
                               entry->u.normal.vlan);
            break;
        case XC_FIN_TIMEOUT:
            xlate_fin_timeout__(entry->u.fin.rule, stats->tcp_flags,
                                entry->u.fin.idle, entry->u.fin.hard);
            break;
        case XC_GROUP:
            group_dpif_credit_stats(entry->u.group.group, entry->u.group.bucket,
                                    stats);
            break;
        case XC_TNL_NEIGH:
            /* Lookup neighbor to avoid timeout. */
            tnl_neigh_lookup(entry->u.tnl_neigh_cache.br_name,
                             &entry->u.tnl_neigh_cache.d_ipv6, &dmac);
            break;
        default:
            OVS_NOT_REACHED();
        }
    }
}

static void
xlate_dev_unref(struct xc_entry *entry)
{
    if (entry->u.dev.tx) {
        netdev_close(entry->u.dev.tx);
    }
    if (entry->u.dev.rx) {
        netdev_close(entry->u.dev.rx);
    }
    if (entry->u.dev.bfd) {
        bfd_unref(entry->u.dev.bfd);
    }
}

static void
xlate_cache_clear_netflow(struct netflow *netflow, struct flow *flow)
{
    netflow_flow_clear(netflow, flow);
    netflow_unref(netflow);
    free(flow);
}

void
xlate_cache_clear(struct xlate_cache *xcache)
{
    struct xc_entry *entry;
    struct ofpbuf entries;

    if (!xcache) {
        return;
    }

    XC_ENTRY_FOR_EACH (entry, entries, xcache) {
        switch (entry->type) {
        case XC_RULE:
            rule_dpif_unref(entry->u.rule);
            break;
        case XC_BOND:
            free(entry->u.bond.flow);
            bond_unref(entry->u.bond.bond);
            break;
        case XC_NETDEV:
            xlate_dev_unref(entry);
            break;
        case XC_NETFLOW:
            xlate_cache_clear_netflow(entry->u.nf.netflow, entry->u.nf.flow);
            break;
        case XC_MIRROR:
            mbridge_unref(entry->u.mirror.mbridge);
            break;
        case XC_LEARN:
            free(entry->u.learn.fm);
            ofpbuf_delete(entry->u.learn.ofpacts);
            break;
        case XC_NORMAL:
            free(entry->u.normal.flow);
            break;
        case XC_FIN_TIMEOUT:
            /* 'u.fin.rule' is always already held as a XC_RULE, which
             * has already released it's reference above. */
            break;
        case XC_GROUP:
            group_dpif_unref(entry->u.group.group);
            break;
        case XC_TNL_NEIGH:
            break;
        default:
            OVS_NOT_REACHED();
        }
    }

    ofpbuf_clear(&xcache->entries);
}

void
xlate_cache_delete(struct xlate_cache *xcache)
{
    xlate_cache_clear(xcache);
    ofpbuf_uninit(&xcache->entries);
    free(xcache);
}
