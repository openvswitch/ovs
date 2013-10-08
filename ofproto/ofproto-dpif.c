/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#include "ofproto/ofproto-provider.h"

#include <errno.h>

#include "autopath.h"
#include "bond.h"
#include "bundle.h"
#include "byte-order.h"
#include "connmgr.h"
#include "coverage.h"
#include "cfm.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "fail-open.h"
#include "hmapx.h"
#include "lacp.h"
#include "learn.h"
#include "mac-learning.h"
#include "meta-flow.h"
#include "multipath.h"
#include "netdev.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofp-actions.h"
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofproto-dpif-governor.h"
#include "ofproto-dpif-sflow.h"
#include "poll-loop.h"
#include "simap.h"
#include "timer.h"
#include "unaligned.h"
#include "unixctl.h"
#include "vlan-bitmap.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif);

COVERAGE_DEFINE(ofproto_dpif_expired);
COVERAGE_DEFINE(ofproto_dpif_xlate);
COVERAGE_DEFINE(facet_changed_rule);
COVERAGE_DEFINE(facet_revalidate);
COVERAGE_DEFINE(facet_unexpected);
COVERAGE_DEFINE(facet_suppress);

/* Maximum depth of flow table recursion (due to resubmit actions) in a
 * flow translation. */
#define MAX_RESUBMIT_RECURSION 64

/* Number of implemented OpenFlow tables. */
enum { N_TABLES = 255 };
enum { TBL_INTERNAL = N_TABLES - 1 };    /* Used for internal hidden rules. */
BUILD_ASSERT_DECL(N_TABLES >= 2 && N_TABLES <= 255);

struct ofport_dpif;
struct ofproto_dpif;

struct rule_dpif {
    struct rule up;

    /* These statistics:
     *
     *   - Do include packets and bytes from facets that have been deleted or
     *     whose own statistics have been folded into the rule.
     *
     *   - Do include packets and bytes sent "by hand" that were accounted to
     *     the rule without any facet being involved (this is a rare corner
     *     case in rule_execute()).
     *
     *   - Do not include packet or bytes that can be obtained from any facet's
     *     packet_count or byte_count member or that can be obtained from the
     *     datapath by, e.g., dpif_flow_get() for any subfacet.
     */
    uint64_t packet_count;       /* Number of packets received. */
    uint64_t byte_count;         /* Number of bytes received. */

    tag_type tag;                /* Caches rule_calculate_tag() result. */

    struct list facets;          /* List of "struct facet"s. */
};

static struct rule_dpif *rule_dpif_cast(const struct rule *rule)
{
    return rule ? CONTAINER_OF(rule, struct rule_dpif, up) : NULL;
}

static struct rule_dpif *rule_dpif_lookup(struct ofproto_dpif *,
                                          const struct flow *);
static struct rule_dpif *rule_dpif_lookup__(struct ofproto_dpif *,
                                            const struct flow *,
                                            uint8_t table);
static struct rule_dpif *rule_dpif_miss_rule(struct ofproto_dpif *ofproto,
                                             const struct flow *flow);

static void rule_get_stats(struct rule *, uint64_t *packets, uint64_t *bytes);
static void rule_credit_stats(struct rule_dpif *,
                              const struct dpif_flow_stats *);
static void flow_push_stats(struct rule_dpif *, const struct flow *,
                            const struct dpif_flow_stats *);
static tag_type rule_calculate_tag(const struct flow *,
                                   const struct minimask *, uint32_t basis);
static void rule_invalidate(const struct rule_dpif *);

#define MAX_MIRRORS 32
typedef uint32_t mirror_mask_t;
#define MIRROR_MASK_C(X) UINT32_C(X)
BUILD_ASSERT_DECL(sizeof(mirror_mask_t) * CHAR_BIT >= MAX_MIRRORS);
struct ofmirror {
    struct ofproto_dpif *ofproto; /* Owning ofproto. */
    size_t idx;                 /* In ofproto's "mirrors" array. */
    void *aux;                  /* Key supplied by ofproto's client. */
    char *name;                 /* Identifier for log messages. */

    /* Selection criteria. */
    struct hmapx srcs;          /* Contains "struct ofbundle *"s. */
    struct hmapx dsts;          /* Contains "struct ofbundle *"s. */
    unsigned long *vlans;       /* Bitmap of chosen VLANs, NULL selects all. */

    /* Output (exactly one of out == NULL and out_vlan == -1 is true). */
    struct ofbundle *out;       /* Output port or NULL. */
    int out_vlan;               /* Output VLAN or -1. */
    mirror_mask_t dup_mirrors;  /* Bitmap of mirrors with the same output. */

    /* Counters. */
    int64_t packet_count;       /* Number of packets sent. */
    int64_t byte_count;         /* Number of bytes sent. */
};

static void mirror_destroy(struct ofmirror *);
static void update_mirror_stats(struct ofproto_dpif *ofproto,
                                mirror_mask_t mirrors,
                                uint64_t packets, uint64_t bytes);

struct ofbundle {
    struct hmap_node hmap_node; /* In struct ofproto's "bundles" hmap. */
    struct ofproto_dpif *ofproto; /* Owning ofproto. */
    void *aux;                  /* Key supplied by ofproto's client. */
    char *name;                 /* Identifier for log messages. */

    /* Configuration. */
    struct list ports;          /* Contains "struct ofport"s. */
    enum port_vlan_mode vlan_mode; /* VLAN mode */
    int vlan;                   /* -1=trunk port, else a 12-bit VLAN ID. */
    unsigned long *trunks;      /* Bitmap of trunked VLANs, if 'vlan' == -1.
                                 * NULL if all VLANs are trunked. */
    struct lacp *lacp;          /* LACP if LACP is enabled, otherwise NULL. */
    struct bond *bond;          /* Nonnull iff more than one port. */
    bool use_priority_tags;     /* Use 802.1p tag for frames in VLAN 0? */

    /* Status. */
    bool floodable;          /* True if no port has OFPUTIL_PC_NO_FLOOD set. */

    /* Port mirroring info. */
    mirror_mask_t src_mirrors;  /* Mirrors triggered when packet received. */
    mirror_mask_t dst_mirrors;  /* Mirrors triggered when packet sent. */
    mirror_mask_t mirror_out;   /* Mirrors that output to this bundle. */
};

static void bundle_remove(struct ofport *);
static void bundle_update(struct ofbundle *);
static void bundle_destroy(struct ofbundle *);
static void bundle_del_port(struct ofport_dpif *);
static void bundle_run(struct ofbundle *);
static void bundle_wait(struct ofbundle *);
static struct ofbundle *lookup_input_bundle(const struct ofproto_dpif *,
                                            uint16_t in_port, bool warn,
                                            struct ofport_dpif **in_ofportp);

/* A controller may use OFPP_NONE as the ingress port to indicate that
 * it did not arrive on a "real" port.  'ofpp_none_bundle' exists for
 * when an input bundle is needed for validation (e.g., mirroring or
 * OFPP_NORMAL processing).  It is not connected to an 'ofproto' or have
 * any 'port' structs, so care must be taken when dealing with it. */
static struct ofbundle ofpp_none_bundle = {
    .name      = "OFPP_NONE",
    .vlan_mode = PORT_VLAN_TRUNK
};

static void stp_run(struct ofproto_dpif *ofproto);
static void stp_wait(struct ofproto_dpif *ofproto);
static int set_stp_port(struct ofport *,
                        const struct ofproto_port_stp_settings *);

static bool ofbundle_includes_vlan(const struct ofbundle *, uint16_t vlan);

struct action_xlate_ctx {
/* action_xlate_ctx_init() initializes these members. */

    /* The ofproto. */
    struct ofproto_dpif *ofproto;

    /* Flow to which the OpenFlow actions apply.  xlate_actions() will modify
     * this flow when actions change header fields. */
    struct flow flow;

    /* The packet corresponding to 'flow', or a null pointer if we are
     * revalidating without a packet to refer to. */
    const struct ofpbuf *packet;

    /* Should OFPP_NORMAL update the MAC learning table?  Should "learn"
     * actions update the flow table?
     *
     * We want to update these tables if we are actually processing a packet,
     * or if we are accounting for packets that the datapath has processed, but
     * not if we are just revalidating. */
    bool may_learn;

    /* The rule that we are currently translating, or NULL. */
    struct rule_dpif *rule;

    /* Union of the set of TCP flags seen so far in this flow.  (Used only by
     * NXAST_FIN_TIMEOUT.  Set to zero to avoid updating updating rules'
     * timeouts.) */
    uint8_t tcp_flags;

    /* If nonnull, flow translation calls this function just before executing a
     * resubmit or OFPP_TABLE action.  In addition, disables logging of traces
     * when the recursion depth is exceeded.
     *
     * 'rule' is the rule being submitted into.  It will be null if the
     * resubmit or OFPP_TABLE action didn't find a matching rule.
     *
     * This is normally null so the client has to set it manually after
     * calling action_xlate_ctx_init(). */
    void (*resubmit_hook)(struct action_xlate_ctx *, struct rule_dpif *rule);

    /* If nonnull, flow translation calls this function to report some
     * significant decision, e.g. to explain why OFPP_NORMAL translation
     * dropped a packet. */
    void (*report_hook)(struct action_xlate_ctx *, const char *s);

    /* If nonnull, flow translation credits the specified statistics to each
     * rule reached through a resubmit or OFPP_TABLE action.
     *
     * This is normally null so the client has to set it manually after
     * calling action_xlate_ctx_init(). */
    const struct dpif_flow_stats *resubmit_stats;

/* xlate_actions() initializes and uses these members.  The client might want
 * to look at them after it returns. */

    struct ofpbuf *odp_actions; /* Datapath actions. */
    tag_type tags;              /* Tags associated with actions. */
    enum slow_path_reason slow; /* 0 if fast path may be used. */
    bool has_learn;             /* Actions include NXAST_LEARN? */
    bool has_normal;            /* Actions output to OFPP_NORMAL? */
    bool has_fin_timeout;       /* Actions include NXAST_FIN_TIMEOUT? */
    uint16_t nf_output_iface;   /* Output interface index for NetFlow. */
    mirror_mask_t mirrors;      /* Bitmap of associated mirrors. */

/* xlate_actions() initializes and uses these members, but the client has no
 * reason to look at them. */

    int recurse;                /* Recursion level, via xlate_table_action. */
    bool max_resubmit_trigger;  /* Recursed too deeply during translation. */
    struct flow base_flow;      /* Flow at the last commit. */
    uint32_t orig_skb_priority; /* Priority when packet arrived. */
    uint8_t table_id;           /* OpenFlow table ID where flow was found. */
    uint32_t sflow_n_outputs;   /* Number of output ports. */
    uint16_t sflow_odp_port;    /* Output port for composing sFlow action. */
    uint16_t user_cookie_offset;/* Used for user_action_cookie fixup. */
    bool exit;                  /* No further actions should be processed. */
    struct flow orig_flow;      /* Copy of original flow. */
};

static void action_xlate_ctx_init(struct action_xlate_ctx *,
                                  struct ofproto_dpif *, const struct flow *,
                                  ovs_be16 initial_tci, struct rule_dpif *,
                                  uint8_t tcp_flags, const struct ofpbuf *);
static void xlate_actions(struct action_xlate_ctx *,
                          const struct ofpact *ofpacts, size_t ofpacts_len,
                          struct ofpbuf *odp_actions);
static void xlate_actions_for_side_effects(struct action_xlate_ctx *,
                                           const struct ofpact *ofpacts,
                                           size_t ofpacts_len);

static size_t put_userspace_action(const struct ofproto_dpif *,
                                   struct ofpbuf *odp_actions,
                                   const struct flow *,
                                   const union user_action_cookie *);

static void compose_slow_path(const struct ofproto_dpif *, const struct flow *,
                              enum slow_path_reason,
                              uint64_t *stub, size_t stub_size,
                              const struct nlattr **actionsp,
                              size_t *actions_lenp);

static void xlate_report(struct action_xlate_ctx *ctx, const char *s);

/* A subfacet (see "struct subfacet" below) has three possible installation
 * states:
 *
 *   - SF_NOT_INSTALLED: Not installed in the datapath.  This will only be the
 *     case just after the subfacet is created, just before the subfacet is
 *     destroyed, or if the datapath returns an error when we try to install a
 *     subfacet.
 *
 *   - SF_FAST_PATH: The subfacet's actions are installed in the datapath.
 *
 *   - SF_SLOW_PATH: An action that sends every packet for the subfacet through
 *     ofproto_dpif is installed in the datapath.
 */
enum subfacet_path {
    SF_NOT_INSTALLED,           /* No datapath flow for this subfacet. */
    SF_FAST_PATH,               /* Full actions are installed. */
    SF_SLOW_PATH,               /* Send-to-userspace action is installed. */
};

static const char *subfacet_path_to_string(enum subfacet_path);

/* A dpif flow and actions associated with a facet.
 *
 * See also the large comment on struct facet. */
struct subfacet {
    /* Owners. */
    struct hmap_node hmap_node; /* In struct ofproto_dpif 'subfacets' list. */
    struct list list_node;      /* In struct facet's 'facets' list. */
    struct facet *facet;        /* Owning facet. */

    /* Key.
     *
     * To save memory in the common case, 'key' is NULL if 'key_fitness' is
     * ODP_FIT_PERFECT, that is, odp_flow_key_from_flow() can accurately
     * regenerate the ODP flow key from ->facet->flow. */
    enum odp_key_fitness key_fitness;
    struct nlattr *key;
    int key_len;

    long long int used;         /* Time last used; time created if not used. */

    uint64_t dp_packet_count;   /* Last known packet count in the datapath. */
    uint64_t dp_byte_count;     /* Last known byte count in the datapath. */

    /* Datapath actions.
     *
     * These should be essentially identical for every subfacet in a facet, but
     * may differ in trivial ways due to VLAN splinters. */
    size_t actions_len;         /* Number of bytes in actions[]. */
    struct nlattr *actions;     /* Datapath actions. */

    enum slow_path_reason slow; /* 0 if fast path may be used. */
    enum subfacet_path path;    /* Installed in datapath? */

    /* This value is normally the same as ->facet->flow.vlan_tci.  Only VLAN
     * splinters can cause it to differ.  This value should be removed when
     * the VLAN splinters feature is no longer needed.  */
    ovs_be16 initial_tci;       /* Initial VLAN TCI value. */
};

static struct subfacet *subfacet_create(struct facet *, enum odp_key_fitness,
                                        const struct nlattr *key,
                                        size_t key_len, ovs_be16 initial_tci,
                                        long long int now);
static struct subfacet *subfacet_find(struct ofproto_dpif *,
                                      const struct nlattr *key, size_t key_len);
static void subfacet_destroy(struct subfacet *);
static void subfacet_destroy__(struct subfacet *);
static void subfacet_get_key(struct subfacet *, struct odputil_keybuf *,
                             struct ofpbuf *key);
static void subfacet_reset_dp_stats(struct subfacet *,
                                    struct dpif_flow_stats *);
static void subfacet_update_time(struct subfacet *, long long int used);
static void subfacet_update_stats(struct subfacet *,
                                  const struct dpif_flow_stats *);
static void subfacet_make_actions(struct subfacet *,
                                  const struct ofpbuf *packet,
                                  struct ofpbuf *odp_actions);
static int subfacet_install(struct subfacet *,
                            const struct nlattr *actions, size_t actions_len,
                            struct dpif_flow_stats *, enum slow_path_reason);
static void subfacet_uninstall(struct subfacet *);

static enum subfacet_path subfacet_want_path(enum slow_path_reason);

/* An exact-match instantiation of an OpenFlow flow.
 *
 * A facet associates a "struct flow", which represents the Open vSwitch
 * userspace idea of an exact-match flow, with one or more subfacets.  Each
 * subfacet tracks the datapath's idea of the exact-match flow equivalent to
 * the facet.  When the kernel module (or other dpif implementation) and Open
 * vSwitch userspace agree on the definition of a flow key, there is exactly
 * one subfacet per facet.  If the dpif implementation supports more-specific
 * flow matching than userspace, however, a facet can have more than one
 * subfacet, each of which corresponds to some distinction in flow that
 * userspace simply doesn't understand.
 *
 * Flow expiration works in terms of subfacets, so a facet must have at least
 * one subfacet or it will never expire, leaking memory. */
struct facet {
    /* Owners. */
    struct hmap_node hmap_node;  /* In owning ofproto's 'facets' hmap. */
    struct list list_node;       /* In owning rule's 'facets' list. */
    struct rule_dpif *rule;      /* Owning rule. */

    /* Owned data. */
    struct list subfacets;
    long long int used;         /* Time last used; time created if not used. */

    /* Key. */
    struct flow flow;

    /* These statistics:
     *
     *   - Do include packets and bytes sent "by hand", e.g. with
     *     dpif_execute().
     *
     *   - Do include packets and bytes that were obtained from the datapath
     *     when a subfacet's statistics were reset (e.g. dpif_flow_put() with
     *     DPIF_FP_ZERO_STATS).
     *
     *   - Do not include packets or bytes that can be obtained from the
     *     datapath for any existing subfacet.
     */
    uint64_t packet_count;       /* Number of packets received. */
    uint64_t byte_count;         /* Number of bytes received. */

    /* Resubmit statistics. */
    uint64_t prev_packet_count;  /* Number of packets from last stats push. */
    uint64_t prev_byte_count;    /* Number of bytes from last stats push. */
    long long int prev_used;     /* Used time from last stats push. */

    /* Accounting. */
    uint64_t accounted_bytes;    /* Bytes processed by facet_account(). */
    struct netflow_flow nf_flow; /* Per-flow NetFlow tracking data. */
    uint8_t tcp_flags;           /* TCP flags seen for this 'rule'. */

    /* Properties of datapath actions.
     *
     * Every subfacet has its own actions because actions can differ slightly
     * between splintered and non-splintered subfacets due to the VLAN tag
     * being initially different (present vs. absent).  All of them have these
     * properties in common so we just store one copy of them here. */
    bool has_learn;              /* Actions include NXAST_LEARN? */
    bool has_normal;             /* Actions output to OFPP_NORMAL? */
    bool has_fin_timeout;        /* Actions include NXAST_FIN_TIMEOUT? */
    tag_type tags;               /* Tags that would require revalidation. */
    mirror_mask_t mirrors;       /* Bitmap of dependent mirrors. */

    /* Storage for a single subfacet, to reduce malloc() time and space
     * overhead.  (A facet always has at least one subfacet and in the common
     * case has exactly one subfacet.) */
    struct subfacet one_subfacet;
};

static struct facet *facet_create(struct rule_dpif *,
                                  const struct flow *, uint32_t hash);
static void facet_remove(struct facet *);
static void facet_free(struct facet *);

static struct facet *facet_find(struct ofproto_dpif *,
                                const struct flow *, uint32_t hash);
static struct facet *facet_lookup_valid(struct ofproto_dpif *,
                                        const struct flow *, uint32_t hash);
static void facet_revalidate(struct facet *);
static bool facet_check_consistency(struct facet *);

static void facet_flush_stats(struct facet *);

static void facet_update_time(struct facet *, long long int used);
static void facet_reset_counters(struct facet *);
static void facet_push_stats(struct facet *);
static void facet_learn(struct facet *);
static void facet_account(struct facet *);

static bool facet_is_controller_flow(struct facet *);

struct ofport_dpif {
    struct ofport up;

    uint32_t odp_port;
    struct ofbundle *bundle;    /* Bundle that contains this port, if any. */
    struct list bundle_node;    /* In struct ofbundle's "ports" list. */
    struct cfm *cfm;            /* Connectivity Fault Management, if any. */
    tag_type tag;               /* Tag associated with this port. */
    uint32_t bond_stable_id;    /* stable_id to use as bond slave, or 0. */
    bool may_enable;            /* May be enabled in bonds. */
    long long int carrier_seq;  /* Carrier status changes. */

    /* Spanning tree. */
    struct stp_port *stp_port;  /* Spanning Tree Protocol, if any. */
    enum stp_state stp_state;   /* Always STP_DISABLED if STP not in use. */
    long long int stp_state_entered;

    struct hmap priorities;     /* Map of attached 'priority_to_dscp's. */

    /* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
     *
     * This is deprecated.  It is only for compatibility with broken device
     * drivers in old versions of Linux that do not properly support VLANs when
     * VLAN devices are not used.  When broken device drivers are no longer in
     * widespread use, we will delete these interfaces. */
    uint16_t realdev_ofp_port;
    int vlandev_vid;
};

/* Node in 'ofport_dpif''s 'priorities' map.  Used to maintain a map from
 * 'priority' (the datapath's term for QoS queue) to the dscp bits which all
 * traffic egressing the 'ofport' with that priority should be marked with. */
struct priority_to_dscp {
    struct hmap_node hmap_node; /* Node in 'ofport_dpif''s 'priorities' map. */
    uint32_t priority;          /* Priority of this queue (see struct flow). */

    uint8_t dscp;               /* DSCP bits to mark outgoing traffic with. */
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
    uint16_t realdev_ofp_port;
    uint16_t vlandev_ofp_port;
    int vid;
};

static uint32_t vsp_realdev_to_vlandev(const struct ofproto_dpif *,
                                       uint32_t realdev, ovs_be16 vlan_tci);
static bool vsp_adjust_flow(const struct ofproto_dpif *, struct flow *);
static void vsp_remove(struct ofport_dpif *);
static void vsp_add(struct ofport_dpif *, uint16_t realdev_ofp_port, int vid);

static struct ofport_dpif *
ofport_dpif_cast(const struct ofport *ofport)
{
    assert(ofport->ofproto->ofproto_class == &ofproto_dpif_class);
    return ofport ? CONTAINER_OF(ofport, struct ofport_dpif, up) : NULL;
}

static void port_run(struct ofport_dpif *);
static void port_run_fast(struct ofport_dpif *);
static void port_wait(struct ofport_dpif *);
static int set_cfm(struct ofport *, const struct cfm_settings *);
static void ofport_clear_priorities(struct ofport_dpif *);

struct dpif_completion {
    struct list list_node;
    struct ofoperation *op;
};

/* Extra information about a classifier table.
 * Currently used just for optimized flow revalidation. */
struct table_dpif {
    /* If either of these is nonnull, then this table has a form that allows
     * flows to be tagged to avoid revalidating most flows for the most common
     * kinds of flow table changes. */
    struct cls_table *catchall_table; /* Table that wildcards all fields. */
    struct cls_table *other_table;    /* Table with any other wildcard set. */
    uint32_t basis;                   /* Keeps each table's tags separate. */
};

/* Reasons that we might need to revalidate every facet, and corresponding
 * coverage counters.
 *
 * A value of 0 means that there is no need to revalidate.
 *
 * It would be nice to have some cleaner way to integrate with coverage
 * counters, but with only a few reasons I guess this is good enough for
 * now. */
enum revalidate_reason {
    REV_RECONFIGURE = 1,       /* Switch configuration changed. */
    REV_STP,                   /* Spanning tree protocol port status change. */
    REV_PORT_TOGGLED,          /* Port enabled or disabled by CFM, LACP, ...*/
    REV_FLOW_TABLE,            /* Flow table changed. */
    REV_INCONSISTENCY          /* Facet self-check failed. */
};
COVERAGE_DEFINE(rev_reconfigure);
COVERAGE_DEFINE(rev_stp);
COVERAGE_DEFINE(rev_port_toggled);
COVERAGE_DEFINE(rev_flow_table);
COVERAGE_DEFINE(rev_inconsistency);

struct ofproto_dpif {
    struct hmap_node all_ofproto_dpifs_node; /* In 'all_ofproto_dpifs'. */
    struct ofproto up;
    struct dpif *dpif;

    /* Special OpenFlow rules. */
    struct rule_dpif *miss_rule; /* Sends flow table misses to controller. */
    struct rule_dpif *no_packet_in_rule; /* Drops flow table misses. */
    struct rule_dpif *drop_frags_rule; /* Used in OFPC_FRAG_DROP mode. */

    /* Bridging. */
    struct netflow *netflow;
    struct dpif_sflow *sflow;
    struct hmap bundles;        /* Contains "struct ofbundle"s. */
    struct mac_learning *ml;
    struct ofmirror *mirrors[MAX_MIRRORS];
    bool has_mirrors;
    bool has_bonded_bundles;

    /* Expiration. */
    struct timer next_expiration;

    /* Facets. */
    struct hmap facets;
    struct hmap subfacets;
    struct governor *governor;

    /* Revalidation. */
    struct table_dpif tables[N_TABLES];
    enum revalidate_reason need_revalidate;
    struct tag_set revalidate_set;

    /* Support for debugging async flow mods. */
    struct list completions;

    bool has_bundle_action; /* True when the first bundle action appears. */
    struct netdev_stats stats; /* To account packets generated and consumed in
                                * userspace. */

    /* Spanning tree. */
    struct stp *stp;
    long long int stp_last_tick;

    /* VLAN splinters. */
    struct hmap realdev_vid_map; /* (realdev,vid) -> vlandev. */
    struct hmap vlandev_map;     /* vlandev -> (realdev,vid). */
};

/* Defer flow mod completion until "ovs-appctl ofproto/unclog"?  (Useful only
 * for debugging the asynchronous flow_mod implementation.) */
static bool clogged;

/* All existing ofproto_dpif instances, indexed by ->up.name. */
static struct hmap all_ofproto_dpifs = HMAP_INITIALIZER(&all_ofproto_dpifs);

static void ofproto_dpif_unixctl_init(void);

static struct ofproto_dpif *
ofproto_dpif_cast(const struct ofproto *ofproto)
{
    assert(ofproto->ofproto_class == &ofproto_dpif_class);
    return CONTAINER_OF(ofproto, struct ofproto_dpif, up);
}

static struct ofport_dpif *get_ofp_port(const struct ofproto_dpif *,
                                        uint16_t ofp_port);
static struct ofport_dpif *get_odp_port(const struct ofproto_dpif *,
                                        uint32_t odp_port);
static void ofproto_trace(struct ofproto_dpif *, const struct flow *,
                          const struct ofpbuf *, ovs_be16 initial_tci,
                          struct ds *);

/* Packet processing. */
static void update_learning_table(struct ofproto_dpif *,
                                  const struct flow *, int vlan,
                                  struct ofbundle *);
/* Upcalls. */
#define FLOW_MISS_MAX_BATCH 50
static int handle_upcalls(struct ofproto_dpif *, unsigned int max_batch);

/* Flow expiration. */
static int expire(struct ofproto_dpif *);

/* NetFlow. */
static void send_netflow_active_timeouts(struct ofproto_dpif *);

/* Utilities. */
static int send_packet(const struct ofport_dpif *, struct ofpbuf *packet);
static size_t compose_sflow_action(const struct ofproto_dpif *,
                                   struct ofpbuf *odp_actions,
                                   const struct flow *, uint32_t odp_port);
static void add_mirror_actions(struct action_xlate_ctx *ctx,
                               const struct flow *flow);
/* Global variables. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Factory functions. */

static void
enumerate_types(struct sset *types)
{
    dp_enumerate_types(types);
}

static int
enumerate_names(const char *type, struct sset *names)
{
    return dp_enumerate_names(type, names);
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

/* Basic life-cycle. */

static int add_internal_flows(struct ofproto_dpif *);

static struct ofproto *
alloc(void)
{
    struct ofproto_dpif *ofproto = xmalloc(sizeof *ofproto);
    return &ofproto->up;
}

static void
dealloc(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    free(ofproto);
}

static int
construct(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    const char *name = ofproto->up.name;
    int max_ports;
    int error;
    int i;

    error = dpif_create_and_open(name, ofproto->up.type, &ofproto->dpif);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s", name, strerror(error));
        return error;
    }

    max_ports = dpif_get_max_ports(ofproto->dpif);
    ofproto_init_max_ports(ofproto_, MIN(max_ports, OFPP_MAX));

    dpif_flow_flush(ofproto->dpif);
    dpif_recv_purge(ofproto->dpif);

    error = dpif_recv_set(ofproto->dpif, true);
    if (error) {
        VLOG_ERR("failed to listen on datapath %s: %s", name, strerror(error));
        dpif_close(ofproto->dpif);
        return error;
    }

    ofproto->netflow = NULL;
    ofproto->sflow = NULL;
    ofproto->stp = NULL;
    hmap_init(&ofproto->bundles);
    ofproto->ml = mac_learning_create(MAC_ENTRY_DEFAULT_IDLE_TIME);
    for (i = 0; i < MAX_MIRRORS; i++) {
        ofproto->mirrors[i] = NULL;
    }
    ofproto->has_bonded_bundles = false;

    timer_set_duration(&ofproto->next_expiration, 1000);

    hmap_init(&ofproto->facets);
    hmap_init(&ofproto->subfacets);
    ofproto->governor = NULL;

    for (i = 0; i < N_TABLES; i++) {
        struct table_dpif *table = &ofproto->tables[i];

        table->catchall_table = NULL;
        table->other_table = NULL;
        table->basis = random_uint32();
    }
    ofproto->need_revalidate = 0;
    tag_set_init(&ofproto->revalidate_set);

    list_init(&ofproto->completions);

    ofproto_dpif_unixctl_init();

    ofproto->has_mirrors = false;
    ofproto->has_bundle_action = false;

    hmap_init(&ofproto->vlandev_map);
    hmap_init(&ofproto->realdev_vid_map);

    hmap_insert(&all_ofproto_dpifs, &ofproto->all_ofproto_dpifs_node,
                hash_string(ofproto->up.name, 0));
    memset(&ofproto->stats, 0, sizeof ofproto->stats);

    ofproto_init_tables(ofproto_, N_TABLES);
    error = add_internal_flows(ofproto);
    ofproto->up.tables[TBL_INTERNAL].flags = OFTABLE_HIDDEN | OFTABLE_READONLY;

    return error;
}

static int
add_internal_flow(struct ofproto_dpif *ofproto, int id,
                  const struct ofpbuf *ofpacts, struct rule_dpif **rulep)
{
    struct ofputil_flow_mod fm;
    int error;

    match_init_catchall(&fm.match);
    fm.priority = 0;
    match_set_reg(&fm.match, 0, id);
    fm.new_cookie = htonll(0);
    fm.cookie = htonll(0);
    fm.cookie_mask = htonll(0);
    fm.table_id = TBL_INTERNAL;
    fm.command = OFPFC_ADD;
    fm.idle_timeout = 0;
    fm.hard_timeout = 0;
    fm.buffer_id = 0;
    fm.out_port = 0;
    fm.flags = 0;
    fm.ofpacts = ofpacts->data;
    fm.ofpacts_len = ofpacts->size;

    error = ofproto_flow_mod(&ofproto->up, &fm);
    if (error) {
        VLOG_ERR_RL(&rl, "failed to add internal flow %d (%s)",
                    id, ofperr_to_string(error));
        return error;
    }

    *rulep = rule_dpif_lookup__(ofproto, &fm.match.flow, TBL_INTERNAL);
    assert(*rulep != NULL);

    return 0;
}

static int
add_internal_flows(struct ofproto_dpif *ofproto)
{
    struct ofpact_controller *controller;
    uint64_t ofpacts_stub[128 / 8];
    struct ofpbuf ofpacts;
    int error;
    int id;

    ofpbuf_use_stack(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    id = 1;

    controller = ofpact_put_CONTROLLER(&ofpacts);
    controller->max_len = UINT16_MAX;
    controller->controller_id = 0;
    controller->reason = OFPR_NO_MATCH;
    ofpact_pad(&ofpacts);

    error = add_internal_flow(ofproto, id++, &ofpacts, &ofproto->miss_rule);
    if (error) {
        return error;
    }

    ofpbuf_clear(&ofpacts);
    error = add_internal_flow(ofproto, id++, &ofpacts,
                              &ofproto->no_packet_in_rule);
    if (error) {
        return error;
    }

    error = add_internal_flow(ofproto, id++, &ofpacts,
                              &ofproto->drop_frags_rule);
    return error;
}

static void
complete_operations(struct ofproto_dpif *ofproto)
{
    struct dpif_completion *c, *next;

    LIST_FOR_EACH_SAFE (c, next, list_node, &ofproto->completions) {
        ofoperation_complete(c->op, 0);
        list_remove(&c->list_node);
        free(c);
    }
}

static void
destruct(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct rule_dpif *rule, *next_rule;
    struct oftable *table;
    int i;

    hmap_remove(&all_ofproto_dpifs, &ofproto->all_ofproto_dpifs_node);
    complete_operations(ofproto);

    OFPROTO_FOR_EACH_TABLE (table, &ofproto->up) {
        struct cls_cursor cursor;

        cls_cursor_init(&cursor, &table->cls, NULL);
        CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, up.cr, &cursor) {
            ofproto_rule_destroy(&rule->up);
        }
    }

    for (i = 0; i < MAX_MIRRORS; i++) {
        mirror_destroy(ofproto->mirrors[i]);
    }

    netflow_destroy(ofproto->netflow);
    dpif_sflow_destroy(ofproto->sflow);
    hmap_destroy(&ofproto->bundles);
    mac_learning_destroy(ofproto->ml);

    hmap_destroy(&ofproto->facets);
    hmap_destroy(&ofproto->subfacets);
    governor_destroy(ofproto->governor);

    hmap_destroy(&ofproto->vlandev_map);
    hmap_destroy(&ofproto->realdev_vid_map);

    dpif_close(ofproto->dpif);
}

static int
run_fast(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofport_dpif *ofport;
    unsigned int work;

    HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
        port_run_fast(ofport);
    }

    /* Handle one or more batches of upcalls, until there's nothing left to do
     * or until we do a fixed total amount of work.
     *
     * We do work in batches because it can be much cheaper to set up a number
     * of flows and fire off their patches all at once.  We do multiple batches
     * because in some cases handling a packet can cause another packet to be
     * queued almost immediately as part of the return flow.  Both
     * optimizations can make major improvements on some benchmarks and
     * presumably for real traffic as well. */
    work = 0;
    while (work < FLOW_MISS_MAX_BATCH) {
        int retval = handle_upcalls(ofproto, FLOW_MISS_MAX_BATCH - work);
        if (retval <= 0) {
            return -retval;
        }
        work += retval;
    }
    return 0;
}

static int
run(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofport_dpif *ofport;
    struct ofbundle *bundle;
    int error;

    if (!clogged) {
        complete_operations(ofproto);
    }
    dpif_run(ofproto->dpif);

    error = run_fast(ofproto_);
    if (error) {
        return error;
    }

    if (timer_expired(&ofproto->next_expiration)) {
        int delay = expire(ofproto);
        timer_set_duration(&ofproto->next_expiration, delay);
    }

    if (ofproto->netflow) {
        if (netflow_run(ofproto->netflow)) {
            send_netflow_active_timeouts(ofproto);
        }
    }
    if (ofproto->sflow) {
        dpif_sflow_run(ofproto->sflow);
    }

    HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
        port_run(ofport);
    }
    HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
        bundle_run(bundle);
    }

    stp_run(ofproto);
    mac_learning_run(ofproto->ml, &ofproto->revalidate_set);

    /* Now revalidate if there's anything to do. */
    if (ofproto->need_revalidate
        || !tag_set_is_empty(&ofproto->revalidate_set)) {
        struct tag_set revalidate_set = ofproto->revalidate_set;
        bool revalidate_all = ofproto->need_revalidate;
        struct facet *facet;

        switch (ofproto->need_revalidate) {
        case REV_RECONFIGURE:   COVERAGE_INC(rev_reconfigure);   break;
        case REV_STP:           COVERAGE_INC(rev_stp);           break;
        case REV_PORT_TOGGLED:  COVERAGE_INC(rev_port_toggled);  break;
        case REV_FLOW_TABLE:    COVERAGE_INC(rev_flow_table);    break;
        case REV_INCONSISTENCY: COVERAGE_INC(rev_inconsistency); break;
        }

        /* Clear the revalidation flags. */
        tag_set_init(&ofproto->revalidate_set);
        ofproto->need_revalidate = 0;

        HMAP_FOR_EACH (facet, hmap_node, &ofproto->facets) {
            if (revalidate_all
                || tag_set_intersects(&revalidate_set, facet->tags)) {
                facet_revalidate(facet);
            }
        }
    }

    /* Check the consistency of a random facet, to aid debugging. */
    if (!hmap_is_empty(&ofproto->facets) && !ofproto->need_revalidate) {
        struct facet *facet;

        facet = CONTAINER_OF(hmap_random_node(&ofproto->facets),
                             struct facet, hmap_node);
        if (!tag_set_intersects(&ofproto->revalidate_set, facet->tags)) {
            if (!facet_check_consistency(facet)) {
                ofproto->need_revalidate = REV_INCONSISTENCY;
            }
        }
    }

    if (ofproto->governor) {
        size_t n_subfacets;

        governor_run(ofproto->governor);

        /* If the governor has shrunk to its minimum size and the number of
         * subfacets has dwindled, then drop the governor entirely.
         *
         * For hysteresis, the number of subfacets to drop the governor is
         * smaller than the number needed to trigger its creation. */
        n_subfacets = hmap_count(&ofproto->subfacets);
        if (n_subfacets * 4 < ofproto->up.flow_eviction_threshold
            && governor_is_idle(ofproto->governor)) {
            governor_destroy(ofproto->governor);
            ofproto->governor = NULL;
        }
    }

    return 0;
}

static void
wait(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofport_dpif *ofport;
    struct ofbundle *bundle;

    if (!clogged && !list_is_empty(&ofproto->completions)) {
        poll_immediate_wake();
    }

    dpif_wait(ofproto->dpif);
    dpif_recv_wait(ofproto->dpif);
    if (ofproto->sflow) {
        dpif_sflow_wait(ofproto->sflow);
    }
    if (!tag_set_is_empty(&ofproto->revalidate_set)) {
        poll_immediate_wake();
    }
    HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
        port_wait(ofport);
    }
    HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
        bundle_wait(bundle);
    }
    if (ofproto->netflow) {
        netflow_wait(ofproto->netflow);
    }
    mac_learning_wait(ofproto->ml);
    stp_wait(ofproto);
    if (ofproto->need_revalidate) {
        /* Shouldn't happen, but if it does just go around again. */
        VLOG_DBG_RL(&rl, "need revalidate in ofproto_wait_cb()");
        poll_immediate_wake();
    } else {
        timer_wait(&ofproto->next_expiration);
    }
    if (ofproto->governor) {
        governor_wait(ofproto->governor);
    }
}

static void
get_memory_usage(const struct ofproto *ofproto_, struct simap *usage)
{
    const struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    simap_increase(usage, "facets", hmap_count(&ofproto->facets));
    simap_increase(usage, "subfacets", hmap_count(&ofproto->subfacets));
}

static void
flush(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct facet *facet, *next_facet;

    HMAP_FOR_EACH_SAFE (facet, next_facet, hmap_node, &ofproto->facets) {
        /* Mark the facet as not installed so that facet_remove() doesn't
         * bother trying to uninstall it.  There is no point in uninstalling it
         * individually since we are about to blow away all the facets with
         * dpif_flow_flush(). */
        struct subfacet *subfacet;

        LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
            subfacet->path = SF_NOT_INSTALLED;
            subfacet->dp_packet_count = 0;
            subfacet->dp_byte_count = 0;
        }
        facet_remove(facet);
    }
    dpif_flow_flush(ofproto->dpif);
}

static void
get_features(struct ofproto *ofproto_ OVS_UNUSED,
             bool *arp_match_ip, enum ofputil_action_bitmap *actions)
{
    *arp_match_ip = true;
    *actions = (OFPUTIL_A_OUTPUT |
                OFPUTIL_A_SET_VLAN_VID |
                OFPUTIL_A_SET_VLAN_PCP |
                OFPUTIL_A_STRIP_VLAN |
                OFPUTIL_A_SET_DL_SRC |
                OFPUTIL_A_SET_DL_DST |
                OFPUTIL_A_SET_NW_SRC |
                OFPUTIL_A_SET_NW_DST |
                OFPUTIL_A_SET_NW_TOS |
                OFPUTIL_A_SET_TP_SRC |
                OFPUTIL_A_SET_TP_DST |
                OFPUTIL_A_ENQUEUE);
}

static void
get_tables(struct ofproto *ofproto_, struct ofp12_table_stats *ots)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_dp_stats s;
    uint64_t n_miss, n_no_pkt_in, n_bytes, n_dropped_frags;
    uint64_t n_lookup;

    strcpy(ots->name, "classifier");

    dpif_get_dp_stats(ofproto->dpif, &s);
    rule_get_stats(&ofproto->miss_rule->up, &n_miss, &n_bytes);
    rule_get_stats(&ofproto->no_packet_in_rule->up, &n_no_pkt_in, &n_bytes);
    rule_get_stats(&ofproto->drop_frags_rule->up, &n_dropped_frags, &n_bytes);

    n_lookup = s.n_hit + s.n_missed - n_dropped_frags;
    ots->lookup_count = htonll(n_lookup);
    ots->matched_count = htonll(n_lookup - n_miss - n_no_pkt_in);
}

static struct ofport *
port_alloc(void)
{
    struct ofport_dpif *port = xmalloc(sizeof *port);
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

    ofproto->need_revalidate = REV_RECONFIGURE;
    port->odp_port = ofp_port_to_odp_port(port->up.ofp_port);
    port->bundle = NULL;
    port->cfm = NULL;
    port->tag = tag_create_random();
    port->may_enable = true;
    port->stp_port = NULL;
    port->stp_state = STP_DISABLED;
    hmap_init(&port->priorities);
    port->realdev_ofp_port = 0;
    port->vlandev_vid = 0;
    port->carrier_seq = netdev_get_carrier_resets(port->up.netdev);

    if (ofproto->sflow) {
        dpif_sflow_add_port(ofproto->sflow, port_);
    }

    return 0;
}

static void
port_destruct(struct ofport *port_)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);

    ofproto->need_revalidate = REV_RECONFIGURE;
    bundle_remove(port_);
    set_cfm(port_, NULL);
    if (ofproto->sflow) {
        dpif_sflow_del_port(ofproto->sflow, port->odp_port);
    }

    ofport_clear_priorities(port);
    hmap_destroy(&port->priorities);
}

static void
port_modified(struct ofport *port_)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);

    if (port->bundle && port->bundle->bond) {
        bond_slave_set_netdev(port->bundle->bond, port, port->up.netdev);
    }
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
        ofproto->need_revalidate = REV_RECONFIGURE;

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
        if (!ds) {
            struct ofport_dpif *ofport;

            ds = ofproto->sflow = dpif_sflow_create(ofproto->dpif);
            HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
                dpif_sflow_add_port(ds, &ofport->up);
            }
            ofproto->need_revalidate = REV_RECONFIGURE;
        }
        dpif_sflow_set_options(ds, sflow_options);
    } else {
        if (ds) {
            dpif_sflow_destroy(ds);
            ofproto->need_revalidate = REV_RECONFIGURE;
            ofproto->sflow = NULL;
        }
    }
    return 0;
}

static int
set_cfm(struct ofport *ofport_, const struct cfm_settings *s)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    int error;

    if (!s) {
        error = 0;
    } else {
        if (!ofport->cfm) {
            struct ofproto_dpif *ofproto;

            ofproto = ofproto_dpif_cast(ofport->up.ofproto);
            ofproto->need_revalidate = REV_RECONFIGURE;
            ofport->cfm = cfm_create(netdev_get_name(ofport->up.netdev));
        }

        if (cfm_configure(ofport->cfm, s)) {
            return 0;
        }

        error = EINVAL;
    }
    cfm_destroy(ofport->cfm);
    ofport->cfm = NULL;
    return error;
}

static int
get_cfm_fault(const struct ofport *ofport_)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);

    return ofport->cfm ? cfm_get_fault(ofport->cfm) : -1;
}

static int
get_cfm_opup(const struct ofport *ofport_)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);

    return ofport->cfm ? cfm_get_opup(ofport->cfm) : -1;
}

static int
get_cfm_remote_mpids(const struct ofport *ofport_, const uint64_t **rmps,
                     size_t *n_rmps)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);

    if (ofport->cfm) {
        cfm_get_remote_mpids(ofport->cfm, rmps, n_rmps);
        return 0;
    } else {
        return -1;
    }
}

static int
get_cfm_health(const struct ofport *ofport_)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);

    return ofport->cfm ? cfm_get_health(ofport->cfm) : -1;
}

/* Spanning Tree. */

static void
send_bpdu_cb(struct ofpbuf *pkt, int port_num, void *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_;
    struct stp_port *sp = stp_get_port(ofproto->stp, port_num);
    struct ofport_dpif *ofport;

    ofport = stp_port_get_aux(sp);
    if (!ofport) {
        VLOG_WARN_RL(&rl, "%s: cannot send BPDU on unknown port %d",
                     ofproto->up.name, port_num);
    } else {
        struct eth_header *eth = pkt->l2;

        netdev_get_etheraddr(ofport->up.netdev, eth->eth_src);
        if (eth_addr_is_zero(eth->eth_src)) {
            VLOG_WARN_RL(&rl, "%s: cannot send BPDU on port %d "
                         "with unknown MAC", ofproto->up.name, port_num);
        } else {
            send_packet(ofport, pkt);
        }
    }
    ofpbuf_delete(pkt);
}

/* Configures STP on 'ofproto_' using the settings defined in 's'. */
static int
set_stp(struct ofproto *ofproto_, const struct ofproto_stp_settings *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    /* Only revalidate flows if the configuration changed. */
    if (!s != !ofproto->stp) {
        ofproto->need_revalidate = REV_RECONFIGURE;
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

        stp_destroy(ofproto->stp);
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

        VLOG_DBG_RL(&rl, "port %s: STP state changed from %s to %s",
                    netdev_get_name(ofport->up.netdev),
                    stp_state_name(ofport->stp_state),
                    stp_state_name(state));
        if (stp_learn_in_state(ofport->stp_state)
                != stp_learn_in_state(state)) {
            /* xxx Learning action flows should also be flushed. */
            mac_learning_flush(ofproto->ml, &ofproto->revalidate_set);
        }
        fwd_change = stp_forward_in_state(ofport->stp_state)
                        != stp_forward_in_state(state);

        ofproto->need_revalidate = REV_STP;
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
            mac_learning_flush(ofproto->ml, &ofproto->revalidate_set);
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

/* Returns true if STP should process 'flow'. */
static bool
stp_should_process_flow(const struct flow *flow)
{
    return eth_addr_equals(flow->dl_dst, eth_addr_stp);
}

static void
stp_process_packet(const struct ofport_dpif *ofport,
                   const struct ofpbuf *packet)
{
    struct ofpbuf payload = *packet;
    struct eth_header *eth = payload.data;
    struct stp_port *sp = ofport->stp_port;

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

static struct priority_to_dscp *
get_priority(const struct ofport_dpif *ofport, uint32_t priority)
{
    struct priority_to_dscp *pdscp;
    uint32_t hash;

    hash = hash_int(priority, 0);
    HMAP_FOR_EACH_IN_BUCKET (pdscp, hmap_node, hash, &ofport->priorities) {
        if (pdscp->priority == priority) {
            return pdscp;
        }
    }
    return NULL;
}

static void
ofport_clear_priorities(struct ofport_dpif *ofport)
{
    struct priority_to_dscp *pdscp, *next;

    HMAP_FOR_EACH_SAFE (pdscp, next, hmap_node, &ofport->priorities) {
        hmap_remove(&ofport->priorities, &pdscp->hmap_node);
        free(pdscp);
    }
}

static int
set_queues(struct ofport *ofport_,
           const struct ofproto_port_queue *qdscp_list,
           size_t n_qdscp)
{
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    struct hmap new = HMAP_INITIALIZER(&new);
    size_t i;

    for (i = 0; i < n_qdscp; i++) {
        struct priority_to_dscp *pdscp;
        uint32_t priority;
        uint8_t dscp;

        dscp = (qdscp_list[i].dscp << 2) & IP_DSCP_MASK;
        if (dpif_queue_to_priority(ofproto->dpif, qdscp_list[i].queue,
                                   &priority)) {
            continue;
        }

        pdscp = get_priority(ofport, priority);
        if (pdscp) {
            hmap_remove(&ofport->priorities, &pdscp->hmap_node);
        } else {
            pdscp = xmalloc(sizeof *pdscp);
            pdscp->priority = priority;
            pdscp->dscp = dscp;
            ofproto->need_revalidate = REV_RECONFIGURE;
        }

        if (pdscp->dscp != dscp) {
            pdscp->dscp = dscp;
            ofproto->need_revalidate = REV_RECONFIGURE;
        }

        hmap_insert(&new, &pdscp->hmap_node, hash_int(pdscp->priority, 0));
    }

    if (!hmap_is_empty(&ofport->priorities)) {
        ofport_clear_priorities(ofport);
        ofproto->need_revalidate = REV_RECONFIGURE;
    }

    hmap_swap(&new, &ofport->priorities);
    hmap_destroy(&new);

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

    ofproto->need_revalidate = REV_RECONFIGURE;
    LIST_FOR_EACH_SAFE (mac, next_mac, lru_node, &ml->lrus) {
        if (mac->port.p == bundle) {
            if (all_ofprotos) {
                struct ofproto_dpif *o;

                HMAP_FOR_EACH (o, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
                    if (o != ofproto) {
                        struct mac_entry *e;

                        e = mac_learning_lookup(o->ml, mac->mac, mac->vlan,
                                                NULL);
                        if (e) {
                            tag_set_add(&o->revalidate_set, e->tag);
                            mac_learning_expire(o->ml, e);
                        }
                    }
                }
            }

            mac_learning_expire(ml, mac);
        }
    }
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

/* Looks up each of the 'n_auxes' pointers in 'auxes' as bundles and adds the
 * ones that are found to 'bundles'. */
static void
bundle_lookup_multiple(struct ofproto_dpif *ofproto,
                       void **auxes, size_t n_auxes,
                       struct hmapx *bundles)
{
    size_t i;

    hmapx_init(bundles);
    for (i = 0; i < n_auxes; i++) {
        struct ofbundle *bundle = bundle_lookup(ofproto, auxes[i]);
        if (bundle) {
            hmapx_add(bundles, bundle);
        }
    }
}

static void
bundle_update(struct ofbundle *bundle)
{
    struct ofport_dpif *port;

    bundle->floodable = true;
    LIST_FOR_EACH (port, bundle_node, &bundle->ports) {
        if (port->up.pp.config & OFPUTIL_PC_NO_FLOOD
            || !stp_forward_in_state(port->stp_state)) {
            bundle->floodable = false;
            break;
        }
    }
}

static void
bundle_del_port(struct ofport_dpif *port)
{
    struct ofbundle *bundle = port->bundle;

    bundle->ofproto->need_revalidate = REV_RECONFIGURE;

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
bundle_add_port(struct ofbundle *bundle, uint32_t ofp_port,
                struct lacp_slave_settings *lacp,
                uint32_t bond_stable_id)
{
    struct ofport_dpif *port;

    port = get_ofp_port(bundle->ofproto, ofp_port);
    if (!port) {
        return false;
    }

    if (port->bundle != bundle) {
        bundle->ofproto->need_revalidate = REV_RECONFIGURE;
        if (port->bundle) {
            bundle_remove(&port->up);
        }

        port->bundle = bundle;
        list_push_back(&bundle->ports, &port->bundle_node);
        if (port->up.pp.config & OFPUTIL_PC_NO_FLOOD
            || !stp_forward_in_state(port->stp_state)) {
            bundle->floodable = false;
        }
    }
    if (lacp) {
        port->bundle->ofproto->need_revalidate = REV_RECONFIGURE;
        lacp_slave_register(bundle->lacp, port, lacp);
    }

    port->bond_stable_id = bond_stable_id;

    return true;
}

static void
bundle_destroy(struct ofbundle *bundle)
{
    struct ofproto_dpif *ofproto;
    struct ofport_dpif *port, *next_port;
    int i;

    if (!bundle) {
        return;
    }

    ofproto = bundle->ofproto;
    for (i = 0; i < MAX_MIRRORS; i++) {
        struct ofmirror *m = ofproto->mirrors[i];
        if (m) {
            if (m->out == bundle) {
                mirror_destroy(m);
            } else if (hmapx_find_and_delete(&m->srcs, bundle)
                       || hmapx_find_and_delete(&m->dsts, bundle)) {
                ofproto->need_revalidate = REV_RECONFIGURE;
            }
        }
    }

    LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
        bundle_del_port(port);
    }

    bundle_flush_macs(bundle, true);
    hmap_remove(&ofproto->bundles, &bundle->hmap_node);
    free(bundle->name);
    free(bundle->trunks);
    lacp_destroy(bundle->lacp);
    bond_destroy(bundle->bond);
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

    assert(s->n_slaves == 1 || s->bond != NULL);
    assert((s->lacp != NULL) == (s->lacp_slaves != NULL));

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

        bundle->src_mirrors = 0;
        bundle->dst_mirrors = 0;
        bundle->mirror_out = 0;
    }

    if (!bundle->name || strcmp(s->name, bundle->name)) {
        free(bundle->name);
        bundle->name = xstrdup(s->name);
    }

    /* LACP. */
    if (s->lacp) {
        if (!bundle->lacp) {
            ofproto->need_revalidate = REV_RECONFIGURE;
            bundle->lacp = lacp_create();
        }
        lacp_configure(bundle->lacp, s->lacp);
    } else {
        lacp_destroy(bundle->lacp);
        bundle->lacp = NULL;
    }

    /* Update set of ports. */
    ok = true;
    for (i = 0; i < s->n_slaves; i++) {
        if (!bundle_add_port(bundle, s->slaves[i],
                             s->lacp ? &s->lacp_slaves[i] : NULL,
                             s->bond_stable_ids ? s->bond_stable_ids[i] : 0)) {
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
    assert(list_size(&bundle->ports) <= s->n_slaves);

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
        NOT_REACHED();
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
                ofproto->need_revalidate = REV_RECONFIGURE;
            }
        } else {
            bundle->bond = bond_create(s->bond);
            ofproto->need_revalidate = REV_RECONFIGURE;
        }

        LIST_FOR_EACH (port, bundle_node, &bundle->ports) {
            bond_slave_register(bundle->bond, port, port->bond_stable_id,
                                port->up.netdev);
        }
    } else {
        bond_destroy(bundle->bond);
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
            bond_destroy(bundle->bond);
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
        struct ofpbuf packet;
        void *packet_pdu;

        ofpbuf_init(&packet, 0);
        packet_pdu = eth_compose(&packet, eth_addr_lacp, ea, ETH_TYPE_LACP,
                                 pdu_size);
        memcpy(packet_pdu, pdu, pdu_size);

        send_packet(port, &packet);
        ofpbuf_uninit(&packet);
    } else {
        VLOG_ERR_RL(&rl, "port %s: cannot obtain Ethernet address of iface "
                    "%s (%s)", port->bundle->name,
                    netdev_get_name(port->up.netdev), strerror(error));
    }
}

static void
bundle_send_learning_packets(struct ofbundle *bundle)
{
    struct ofproto_dpif *ofproto = bundle->ofproto;
    int error, n_packets, n_errors;
    struct mac_entry *e;

    error = n_packets = n_errors = 0;
    LIST_FOR_EACH (e, lru_node, &ofproto->ml->lrus) {
        if (e->port.p != bundle) {
            struct ofpbuf *learning_packet;
            struct ofport_dpif *port;
            void *port_void;
            int ret;

            /* The assignment to "port" is unnecessary but makes "grep"ing for
             * struct ofport_dpif more effective. */
            learning_packet = bond_compose_learning_packet(bundle->bond,
                                                           e->mac, e->vlan,
                                                           &port_void);
            port = port_void;
            ret = send_packet(port, learning_packet);
            ofpbuf_delete(learning_packet);
            if (ret) {
                error = ret;
                n_errors++;
            }
            n_packets++;
        }
    }

    if (n_errors) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bond %s: %d errors sending %d gratuitous learning "
                     "packets, last error was: %s",
                     bundle->name, n_errors, n_packets, strerror(error));
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

        bond_run(bundle->bond, &bundle->ofproto->revalidate_set,
                 lacp_status(bundle->lacp));
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
mirror_scan(struct ofproto_dpif *ofproto)
{
    int idx;

    for (idx = 0; idx < MAX_MIRRORS; idx++) {
        if (!ofproto->mirrors[idx]) {
            return idx;
        }
    }
    return -1;
}

static struct ofmirror *
mirror_lookup(struct ofproto_dpif *ofproto, void *aux)
{
    int i;

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct ofmirror *mirror = ofproto->mirrors[i];
        if (mirror && mirror->aux == aux) {
            return mirror;
        }
    }

    return NULL;
}

/* Update the 'dup_mirrors' member of each of the ofmirrors in 'ofproto'. */
static void
mirror_update_dups(struct ofproto_dpif *ofproto)
{
    int i;

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct ofmirror *m = ofproto->mirrors[i];

        if (m) {
            m->dup_mirrors = MIRROR_MASK_C(1) << i;
        }
    }

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct ofmirror *m1 = ofproto->mirrors[i];
        int j;

        if (!m1) {
            continue;
        }

        for (j = i + 1; j < MAX_MIRRORS; j++) {
            struct ofmirror *m2 = ofproto->mirrors[j];

            if (m2 && m1->out == m2->out && m1->out_vlan == m2->out_vlan) {
                m1->dup_mirrors |= MIRROR_MASK_C(1) << j;
                m2->dup_mirrors |= m1->dup_mirrors;
            }
        }
    }
}

static int
mirror_set(struct ofproto *ofproto_, void *aux,
           const struct ofproto_mirror_settings *s)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    mirror_mask_t mirror_bit;
    struct ofbundle *bundle;
    struct ofmirror *mirror;
    struct ofbundle *out;
    struct hmapx srcs;          /* Contains "struct ofbundle *"s. */
    struct hmapx dsts;          /* Contains "struct ofbundle *"s. */
    int out_vlan;

    mirror = mirror_lookup(ofproto, aux);
    if (!s) {
        mirror_destroy(mirror);
        return 0;
    }
    if (!mirror) {
        int idx;

        idx = mirror_scan(ofproto);
        if (idx < 0) {
            VLOG_WARN("bridge %s: maximum of %d port mirrors reached, "
                      "cannot create %s",
                      ofproto->up.name, MAX_MIRRORS, s->name);
            return EFBIG;
        }

        mirror = ofproto->mirrors[idx] = xzalloc(sizeof *mirror);
        mirror->ofproto = ofproto;
        mirror->idx = idx;
        mirror->aux = aux;
        mirror->out_vlan = -1;
        mirror->name = NULL;
    }

    if (!mirror->name || strcmp(s->name, mirror->name)) {
        free(mirror->name);
        mirror->name = xstrdup(s->name);
    }

    /* Get the new configuration. */
    if (s->out_bundle) {
        out = bundle_lookup(ofproto, s->out_bundle);
        if (!out) {
            mirror_destroy(mirror);
            return EINVAL;
        }
        out_vlan = -1;
    } else {
        out = NULL;
        out_vlan = s->out_vlan;
    }
    bundle_lookup_multiple(ofproto, s->srcs, s->n_srcs, &srcs);
    bundle_lookup_multiple(ofproto, s->dsts, s->n_dsts, &dsts);

    /* If the configuration has not changed, do nothing. */
    if (hmapx_equals(&srcs, &mirror->srcs)
        && hmapx_equals(&dsts, &mirror->dsts)
        && vlan_bitmap_equal(mirror->vlans, s->src_vlans)
        && mirror->out == out
        && mirror->out_vlan == out_vlan)
    {
        hmapx_destroy(&srcs);
        hmapx_destroy(&dsts);
        return 0;
    }

    hmapx_swap(&srcs, &mirror->srcs);
    hmapx_destroy(&srcs);

    hmapx_swap(&dsts, &mirror->dsts);
    hmapx_destroy(&dsts);

    free(mirror->vlans);
    mirror->vlans = vlan_bitmap_clone(s->src_vlans);

    mirror->out = out;
    mirror->out_vlan = out_vlan;

    /* Update bundles. */
    mirror_bit = MIRROR_MASK_C(1) << mirror->idx;
    HMAP_FOR_EACH (bundle, hmap_node, &mirror->ofproto->bundles) {
        if (hmapx_contains(&mirror->srcs, bundle)) {
            bundle->src_mirrors |= mirror_bit;
        } else {
            bundle->src_mirrors &= ~mirror_bit;
        }

        if (hmapx_contains(&mirror->dsts, bundle)) {
            bundle->dst_mirrors |= mirror_bit;
        } else {
            bundle->dst_mirrors &= ~mirror_bit;
        }

        if (mirror->out == bundle) {
            bundle->mirror_out |= mirror_bit;
        } else {
            bundle->mirror_out &= ~mirror_bit;
        }
    }

    ofproto->need_revalidate = REV_RECONFIGURE;
    ofproto->has_mirrors = true;
    mac_learning_flush(ofproto->ml, &ofproto->revalidate_set);
    mirror_update_dups(ofproto);

    return 0;
}

static void
mirror_destroy(struct ofmirror *mirror)
{
    struct ofproto_dpif *ofproto;
    mirror_mask_t mirror_bit;
    struct ofbundle *bundle;
    int i;

    if (!mirror) {
        return;
    }

    ofproto = mirror->ofproto;
    ofproto->need_revalidate = REV_RECONFIGURE;
    mac_learning_flush(ofproto->ml, &ofproto->revalidate_set);

    mirror_bit = MIRROR_MASK_C(1) << mirror->idx;
    HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
        bundle->src_mirrors &= ~mirror_bit;
        bundle->dst_mirrors &= ~mirror_bit;
        bundle->mirror_out &= ~mirror_bit;
    }

    hmapx_destroy(&mirror->srcs);
    hmapx_destroy(&mirror->dsts);
    free(mirror->vlans);

    ofproto->mirrors[mirror->idx] = NULL;
    free(mirror->name);
    free(mirror);

    mirror_update_dups(ofproto);

    ofproto->has_mirrors = false;
    for (i = 0; i < MAX_MIRRORS; i++) {
        if (ofproto->mirrors[i]) {
            ofproto->has_mirrors = true;
            break;
        }
    }
}

static int
mirror_get_stats(struct ofproto *ofproto_, void *aux,
                 uint64_t *packets, uint64_t *bytes)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofmirror *mirror = mirror_lookup(ofproto, aux);

    if (!mirror) {
        *packets = *bytes = UINT64_MAX;
        return 0;
    }

    *packets = mirror->packet_count;
    *bytes = mirror->byte_count;

    return 0;
}

static int
set_flood_vlans(struct ofproto *ofproto_, unsigned long *flood_vlans)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    if (mac_learning_set_flood_vlans(ofproto->ml, flood_vlans)) {
        mac_learning_flush(ofproto->ml, &ofproto->revalidate_set);
    }
    return 0;
}

static bool
is_mirror_output_bundle(const struct ofproto *ofproto_, void *aux)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofbundle *bundle = bundle_lookup(ofproto, aux);
    return bundle && bundle->mirror_out != 0;
}

static void
forward_bpdu_changed(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    ofproto->need_revalidate = REV_RECONFIGURE;
}

static void
set_mac_idle_time(struct ofproto *ofproto_, unsigned int idle_time)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    mac_learning_set_idle_time(ofproto->ml, idle_time);
}

/* Ports. */

static struct ofport_dpif *
get_ofp_port(const struct ofproto_dpif *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(&ofproto->up, ofp_port);
    return ofport ? ofport_dpif_cast(ofport) : NULL;
}

static struct ofport_dpif *
get_odp_port(const struct ofproto_dpif *ofproto, uint32_t odp_port)
{
    return get_ofp_port(ofproto, odp_port_to_ofp_port(odp_port));
}

static void
ofproto_port_from_dpif_port(struct ofproto_port *ofproto_port,
                            struct dpif_port *dpif_port)
{
    ofproto_port->name = dpif_port->name;
    ofproto_port->type = dpif_port->type;
    ofproto_port->ofp_port = odp_port_to_ofp_port(dpif_port->port_no);
}

static void
port_run_fast(struct ofport_dpif *ofport)
{
    if (ofport->cfm && cfm_should_send_ccm(ofport->cfm)) {
        struct ofpbuf packet;

        ofpbuf_init(&packet, 0);
        cfm_compose_ccm(ofport->cfm, &packet, ofport->up.pp.hw_addr);
        send_packet(ofport, &packet);
        ofpbuf_uninit(&packet);
    }
}

static void
port_run(struct ofport_dpif *ofport)
{
    long long int carrier_seq = netdev_get_carrier_resets(ofport->up.netdev);
    bool carrier_changed = carrier_seq != ofport->carrier_seq;
    bool enable = netdev_get_carrier(ofport->up.netdev);

    ofport->carrier_seq = carrier_seq;

    port_run_fast(ofport);
    if (ofport->cfm) {
        int cfm_opup = cfm_get_opup(ofport->cfm);

        cfm_run(ofport->cfm);
        enable = enable && !cfm_get_fault(ofport->cfm);

        if (cfm_opup >= 0) {
            enable = enable && cfm_opup;
        }
    }

    if (ofport->bundle) {
        enable = enable && lacp_slave_may_enable(ofport->bundle->lacp, ofport);
        if (carrier_changed) {
            lacp_slave_carrier_changed(ofport->bundle->lacp, ofport);
        }
    }

    if (ofport->may_enable != enable) {
        struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);

        if (ofproto->has_bundle_action) {
            ofproto->need_revalidate = REV_PORT_TOGGLED;
        }
    }

    ofport->may_enable = enable;
}

static void
port_wait(struct ofport_dpif *ofport)
{
    if (ofport->cfm) {
        cfm_wait(ofport->cfm);
    }
}

static int
port_query_by_name(const struct ofproto *ofproto_, const char *devname,
                   struct ofproto_port *ofproto_port)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_port dpif_port;
    int error;

    error = dpif_port_query_by_name(ofproto->dpif, devname, &dpif_port);
    if (!error) {
        ofproto_port_from_dpif_port(ofproto_port, &dpif_port);
    }
    return error;
}

static int
port_add(struct ofproto *ofproto_, struct netdev *netdev, uint16_t *ofp_portp)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    uint16_t odp_port = UINT16_MAX;
    int error;

    error = dpif_port_add(ofproto->dpif, netdev, &odp_port);
    if (!error) {
        *ofp_portp = odp_port_to_ofp_port(odp_port);
        if (*ofp_portp >= OFPP_MAX) {
            /* Out of ports in the OpenFlow range. */
            dpif_port_del(ofproto->dpif, odp_port);
            error = EFBIG;
        }
    }
    return error;
}

static int
port_del(struct ofproto *ofproto_, uint16_t ofp_port)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    int error;

    error = dpif_port_del(ofproto->dpif, ofp_port_to_odp_port(ofp_port));
    if (!error) {
        struct ofport_dpif *ofport = get_ofp_port(ofproto, ofp_port);
        if (ofport) {
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

    if (!error && ofport->odp_port == OVSP_LOCAL) {
        struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);

        /* ofproto->stats.tx_packets represents packets that we created
         * internally and sent to some port (e.g. packets sent with
         * send_packet()).  Account for them as if they had come from
         * OFPP_LOCAL and got forwarded. */

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
    }

    return error;
}

/* Account packets for LOCAL port. */
static void
ofproto_update_local_port_stats(const struct ofproto *ofproto_,
                                size_t tx_size, size_t rx_size)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    if (rx_size) {
        ofproto->stats.rx_packets++;
        ofproto->stats.rx_bytes += rx_size;
    }
    if (tx_size) {
        ofproto->stats.tx_packets++;
        ofproto->stats.tx_bytes += tx_size;
    }
}

struct port_dump_state {
    struct dpif_port_dump dump;
    bool done;
};

static int
port_dump_start(const struct ofproto *ofproto_, void **statep)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct port_dump_state *state;

    *statep = state = xmalloc(sizeof *state);
    dpif_port_dump_start(&state->dump, ofproto->dpif);
    state->done = false;
    return 0;
}

static int
port_dump_next(const struct ofproto *ofproto_ OVS_UNUSED, void *state_,
               struct ofproto_port *port)
{
    struct port_dump_state *state = state_;
    struct dpif_port dpif_port;

    if (dpif_port_dump_next(&state->dump, &dpif_port)) {
        ofproto_port_from_dpif_port(port, &dpif_port);
        return 0;
    } else {
        int error = dpif_port_dump_done(&state->dump);
        state->done = true;
        return error ? error : EOF;
    }
}

static int
port_dump_done(const struct ofproto *ofproto_ OVS_UNUSED, void *state_)
{
    struct port_dump_state *state = state_;

    if (!state->done) {
        dpif_port_dump_done(&state->dump);
    }
    free(state);
    return 0;
}

static int
port_poll(const struct ofproto *ofproto_, char **devnamep)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    return dpif_port_poll(ofproto->dpif, devnamep);
}

static void
port_poll_wait(const struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    dpif_port_poll_wait(ofproto->dpif);
}

static int
port_is_lacp_current(const struct ofport *ofport_)
{
    const struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);
    return (ofport->bundle && ofport->bundle->lacp
            ? lacp_slave_is_current(ofport->bundle->lacp, ofport)
            : -1);
}

/* Upcall handling. */

/* Flow miss batching.
 *
 * Some dpifs implement operations faster when you hand them off in a batch.
 * To allow batching, "struct flow_miss" queues the dpif-related work needed
 * for a given flow.  Each "struct flow_miss" corresponds to sending one or
 * more packets, plus possibly installing the flow in the dpif.
 *
 * So far we only batch the operations that affect flow setup time the most.
 * It's possible to batch more than that, but the benefit might be minimal. */
struct flow_miss {
    struct hmap_node hmap_node;
    struct flow flow;
    enum odp_key_fitness key_fitness;
    const struct nlattr *key;
    size_t key_len;
    ovs_be16 initial_tci;
    struct list packets;
    enum dpif_upcall_type upcall_type;
};

struct flow_miss_op {
    struct dpif_op dpif_op;
    struct subfacet *subfacet;  /* Subfacet  */
    void *garbage;              /* Pointer to pass to free(), NULL if none. */
    uint64_t stub[1024 / 8];    /* Temporary buffer. */
};

/* Sends an OFPT_PACKET_IN message for 'packet' of type OFPR_NO_MATCH to each
 * OpenFlow controller as necessary according to their individual
 * configurations. */
static void
send_packet_in_miss(struct ofproto_dpif *ofproto, const struct ofpbuf *packet,
                    const struct flow *flow)
{
    struct ofputil_packet_in pin;

    pin.packet = packet->data;
    pin.packet_len = packet->size;
    pin.reason = OFPR_NO_MATCH;
    pin.controller_id = 0;

    pin.table_id = 0;
    pin.cookie = 0;

    pin.send_len = 0;           /* not used for flow table misses */

    flow_get_metadata(flow, &pin.fmd);

    connmgr_send_packet_in(ofproto->up.connmgr, &pin);
}

static enum slow_path_reason
process_special(struct ofproto_dpif *ofproto, const struct flow *flow,
                const struct ofpbuf *packet)
{
    struct ofport_dpif *ofport = get_ofp_port(ofproto, flow->in_port);

    if (!ofport) {
        return 0;
    }

    if (ofport->cfm && cfm_should_process_flow(ofport->cfm, flow)) {
        if (packet) {
            cfm_process_heartbeat(ofport->cfm, packet);
        }
        return SLOW_CFM;
    } else if (ofport->bundle && ofport->bundle->lacp
               && flow->dl_type == htons(ETH_TYPE_LACP)) {
        if (packet) {
            lacp_process_packet(ofport->bundle->lacp, ofport, packet);
        }
        return SLOW_LACP;
    } else if (ofproto->stp && stp_should_process_flow(flow)) {
        if (packet) {
            stp_process_packet(ofport, packet);
        }
        return SLOW_STP;
    }
    return 0;
}

static struct flow_miss *
flow_miss_find(struct hmap *todo, const struct flow *flow, uint32_t hash)
{
    struct flow_miss *miss;

    HMAP_FOR_EACH_WITH_HASH (miss, hmap_node, hash, todo) {
        if (flow_equal(&miss->flow, flow)) {
            return miss;
        }
    }

    return NULL;
}

/* Partially Initializes 'op' as an "execute" operation for 'miss' and
 * 'packet'.  The caller must initialize op->actions and op->actions_len.  If
 * 'miss' is associated with a subfacet the caller must also initialize the
 * returned op->subfacet, and if anything needs to be freed after processing
 * the op, the caller must initialize op->garbage also. */
static void
init_flow_miss_execute_op(struct flow_miss *miss, struct ofpbuf *packet,
                          struct flow_miss_op *op)
{
    if (miss->flow.vlan_tci != miss->initial_tci) {
        /* This packet was received on a VLAN splinter port.  We
         * added a VLAN to the packet to make the packet resemble
         * the flow, but the actions were composed assuming that
         * the packet contained no VLAN.  So, we must remove the
         * VLAN header from the packet before trying to execute the
         * actions. */
        eth_pop_vlan(packet);
    }

    op->subfacet = NULL;
    op->garbage = NULL;
    op->dpif_op.type = DPIF_OP_EXECUTE;
    op->dpif_op.u.execute.key = miss->key;
    op->dpif_op.u.execute.key_len = miss->key_len;
    op->dpif_op.u.execute.packet = packet;
}

/* Helper for handle_flow_miss_without_facet() and
 * handle_flow_miss_with_facet(). */
static void
handle_flow_miss_common(struct rule_dpif *rule,
                        struct ofpbuf *packet, const struct flow *flow)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);

    if (rule->up.cr.priority == FAIL_OPEN_PRIORITY) {
        /*
         * Extra-special case for fail-open mode.
         *
         * We are in fail-open mode and the packet matched the fail-open
         * rule, but we are connected to a controller too.  We should send
         * the packet up to the controller in the hope that it will try to
         * set up a flow and thereby allow us to exit fail-open.
         *
         * See the top-level comment in fail-open.c for more information.
         */
        send_packet_in_miss(ofproto, packet, flow);
    }
}

/* Figures out whether a flow that missed in 'ofproto', whose details are in
 * 'miss', is likely to be worth tracking in detail in userspace and (usually)
 * installing a datapath flow.  The answer is usually "yes" (a return value of
 * true).  However, for short flows the cost of bookkeeping is much higher than
 * the benefits, so when the datapath holds a large number of flows we impose
 * some heuristics to decide which flows are likely to be worth tracking. */
static bool
flow_miss_should_make_facet(struct ofproto_dpif *ofproto,
                            struct flow_miss *miss, uint32_t hash)
{
    if (!ofproto->governor) {
        size_t n_subfacets;

        n_subfacets = hmap_count(&ofproto->subfacets);
        if (n_subfacets * 2 <= ofproto->up.flow_eviction_threshold) {
            return true;
        }

        ofproto->governor = governor_create(ofproto->up.name);
    }

    return governor_should_install_flow(ofproto->governor, hash,
                                        list_size(&miss->packets));
}

/* Handles 'miss', which matches 'rule', without creating a facet or subfacet
 * or creating any datapath flow.  May add an "execute" operation to 'ops' and
 * increment '*n_ops'. */
static void
handle_flow_miss_without_facet(struct flow_miss *miss,
                               struct rule_dpif *rule,
                               struct flow_miss_op *ops, size_t *n_ops)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    long long int now = time_msec();
    struct action_xlate_ctx ctx;
    struct ofpbuf *packet;

    LIST_FOR_EACH (packet, list_node, &miss->packets) {
        struct flow_miss_op *op = &ops[*n_ops];
        struct dpif_flow_stats stats;
        struct ofpbuf odp_actions;

        COVERAGE_INC(facet_suppress);

        ofpbuf_use_stub(&odp_actions, op->stub, sizeof op->stub);

        dpif_flow_stats_extract(&miss->flow, packet, now, &stats);
        rule_credit_stats(rule, &stats);

        action_xlate_ctx_init(&ctx, ofproto, &miss->flow, miss->initial_tci,
                              rule, stats.tcp_flags, packet);
        ctx.resubmit_stats = &stats;
        xlate_actions(&ctx, rule->up.ofpacts, rule->up.ofpacts_len,
                      &odp_actions);

        if (odp_actions.size) {
            struct dpif_execute *execute = &op->dpif_op.u.execute;

            init_flow_miss_execute_op(miss, packet, op);
            execute->actions = odp_actions.data;
            execute->actions_len = odp_actions.size;
            op->garbage = ofpbuf_get_uninit_pointer(&odp_actions);

            (*n_ops)++;
        } else {
            ofpbuf_uninit(&odp_actions);
        }
    }
}

/* Handles 'miss', which matches 'facet'.  May add any required datapath
 * operations to 'ops', incrementing '*n_ops' for each new op.
 *
 * All of the packets in 'miss' are considered to have arrived at time 'now'.
 * This is really important only for new facets: if we just called time_msec()
 * here, then the new subfacet or its packets could look (occasionally) as
 * though it was used some time after the facet was used.  That can make a
 * one-packet flow look like it has a nonzero duration, which looks odd in
 * e.g. NetFlow statistics. */
static void
handle_flow_miss_with_facet(struct flow_miss *miss, struct facet *facet,
                            long long int now,
                            struct flow_miss_op *ops, size_t *n_ops)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);
    enum subfacet_path want_path;
    struct subfacet *subfacet;
    struct ofpbuf *packet;

    subfacet = subfacet_create(facet,
                               miss->key_fitness, miss->key, miss->key_len,
                               miss->initial_tci, now);

    LIST_FOR_EACH (packet, list_node, &miss->packets) {
        struct flow_miss_op *op = &ops[*n_ops];
        struct dpif_flow_stats stats;
        struct ofpbuf odp_actions;

        handle_flow_miss_common(facet->rule, packet, &miss->flow);

        ofpbuf_use_stub(&odp_actions, op->stub, sizeof op->stub);
        if (!subfacet->actions || subfacet->slow) {
            subfacet_make_actions(subfacet, packet, &odp_actions);
        }

        dpif_flow_stats_extract(&facet->flow, packet, now, &stats);
        subfacet_update_stats(subfacet, &stats);

        if (subfacet->actions_len) {
            struct dpif_execute *execute = &op->dpif_op.u.execute;

            init_flow_miss_execute_op(miss, packet, op);
            op->subfacet = subfacet;
            if (!subfacet->slow) {
                execute->actions = subfacet->actions;
                execute->actions_len = subfacet->actions_len;
                ofpbuf_uninit(&odp_actions);
            } else {
                execute->actions = odp_actions.data;
                execute->actions_len = odp_actions.size;
                op->garbage = ofpbuf_get_uninit_pointer(&odp_actions);
            }

            (*n_ops)++;
        } else {
            ofpbuf_uninit(&odp_actions);
        }
    }

    want_path = subfacet_want_path(subfacet->slow);
    if (miss->upcall_type == DPIF_UC_MISS || subfacet->path != want_path) {
        struct flow_miss_op *op = &ops[(*n_ops)++];
        struct dpif_flow_put *put = &op->dpif_op.u.flow_put;

        op->subfacet = subfacet;
        op->garbage = NULL;
        op->dpif_op.type = DPIF_OP_FLOW_PUT;
        put->flags = DPIF_FP_CREATE | DPIF_FP_MODIFY;
        put->key = miss->key;
        put->key_len = miss->key_len;
        if (want_path == SF_FAST_PATH) {
            put->actions = subfacet->actions;
            put->actions_len = subfacet->actions_len;
        } else {
            compose_slow_path(ofproto, &facet->flow, subfacet->slow,
                              op->stub, sizeof op->stub,
                              &put->actions, &put->actions_len);
        }
        put->stats = NULL;
    }
}

/* Handles flow miss 'miss' on 'ofproto'.  May add any required datapath
 * operations to 'ops', incrementing '*n_ops' for each new op. */
static void
handle_flow_miss(struct ofproto_dpif *ofproto, struct flow_miss *miss,
                 struct flow_miss_op *ops, size_t *n_ops)
{
    struct facet *facet;
    long long int now;
    uint32_t hash;

    /* The caller must ensure that miss->hmap_node.hash contains
     * flow_hash(miss->flow, 0). */
    hash = miss->hmap_node.hash;

    facet = facet_lookup_valid(ofproto, &miss->flow, hash);
    if (!facet) {
        struct rule_dpif *rule = rule_dpif_lookup(ofproto, &miss->flow);

        if (!flow_miss_should_make_facet(ofproto, miss, hash)) {
            handle_flow_miss_without_facet(miss, rule, ops, n_ops);
            return;
        }

        facet = facet_create(rule, &miss->flow, hash);
        now = facet->used;
    } else {
        now = time_msec();
    }
    handle_flow_miss_with_facet(miss, facet, now, ops, n_ops);
}

/* Like odp_flow_key_to_flow(), this function converts the 'key_len' bytes of
 * OVS_KEY_ATTR_* attributes in 'key' to a flow structure in 'flow' and returns
 * an ODP_FIT_* value that indicates how well 'key' fits our expectations for
 * what a flow key should contain.
 *
 * This function also includes some logic to help make VLAN splinters
 * transparent to the rest of the upcall processing logic.  In particular, if
 * the extracted in_port is a VLAN splinter port, it replaces flow->in_port by
 * the "real" port, sets flow->vlan_tci correctly for the VLAN of the VLAN
 * splinter port, and pushes a VLAN header onto 'packet' (if it is nonnull).
 *
 * Sets '*initial_tci' to the VLAN TCI with which the packet was really
 * received, that is, the actual VLAN TCI extracted by odp_flow_key_to_flow().
 * (This differs from the value returned in flow->vlan_tci only for packets
 * received on VLAN splinters.)
 */
static enum odp_key_fitness
ofproto_dpif_extract_flow_key(const struct ofproto_dpif *ofproto,
                              const struct nlattr *key, size_t key_len,
                              struct flow *flow, ovs_be16 *initial_tci,
                              struct ofpbuf *packet)
{
    enum odp_key_fitness fitness;

    fitness = odp_flow_key_to_flow(key, key_len, flow);
    if (fitness == ODP_FIT_ERROR) {
        return fitness;
    }
    *initial_tci = flow->vlan_tci;

    if (vsp_adjust_flow(ofproto, flow)) {
        if (packet) {
            /* Make the packet resemble the flow, so that it gets sent to an
             * OpenFlow controller properly, so that it looks correct for
             * sFlow, and so that flow_extract() will get the correct vlan_tci
             * if it is called on 'packet'.
             *
             * The allocated space inside 'packet' probably also contains
             * 'key', that is, both 'packet' and 'key' are probably part of a
             * struct dpif_upcall (see the large comment on that structure
             * definition), so pushing data on 'packet' is in general not a
             * good idea since it could overwrite 'key' or free it as a side
             * effect.  However, it's OK in this special case because we know
             * that 'packet' is inside a Netlink attribute: pushing 4 bytes
             * will just overwrite the 4-byte "struct nlattr", which is fine
             * since we don't need that header anymore. */
            eth_push_vlan(packet, flow->vlan_tci);
        }

        /* Let the caller know that we can't reproduce 'key' from 'flow'. */
        if (fitness == ODP_FIT_PERFECT) {
            fitness = ODP_FIT_TOO_MUCH;
        }
    }

    return fitness;
}

static void
handle_miss_upcalls(struct ofproto_dpif *ofproto, struct dpif_upcall *upcalls,
                    size_t n_upcalls)
{
    struct dpif_upcall *upcall;
    struct flow_miss *miss;
    struct flow_miss misses[FLOW_MISS_MAX_BATCH];
    struct flow_miss_op flow_miss_ops[FLOW_MISS_MAX_BATCH * 2];
    struct dpif_op *dpif_ops[FLOW_MISS_MAX_BATCH * 2];
    struct hmap todo;
    int n_misses;
    size_t n_ops;
    size_t i;

    if (!n_upcalls) {
        return;
    }

    /* Construct the to-do list.
     *
     * This just amounts to extracting the flow from each packet and sticking
     * the packets that have the same flow in the same "flow_miss" structure so
     * that we can process them together. */
    hmap_init(&todo);
    n_misses = 0;
    for (upcall = upcalls; upcall < &upcalls[n_upcalls]; upcall++) {
        struct flow_miss *miss = &misses[n_misses];
        struct flow_miss *existing_miss;
        struct flow flow;
        uint32_t hash;

        /* Obtain metadata and check userspace/kernel agreement on flow match,
         * then set 'flow''s header pointers. */
        miss->key_fitness = ofproto_dpif_extract_flow_key(
            ofproto, upcall->key, upcall->key_len,
            &flow, &miss->initial_tci, upcall->packet);
        if (miss->key_fitness == ODP_FIT_ERROR) {
            continue;
        }
        flow_extract(upcall->packet, flow.skb_priority, flow.skb_mark,
                     &flow.tunnel, flow.in_port, &miss->flow);

        /* Add other packets to a to-do list. */
        hash = flow_hash(&miss->flow, 0);
        existing_miss = flow_miss_find(&todo, &miss->flow, hash);
        if (!existing_miss) {
            hmap_insert(&todo, &miss->hmap_node, hash);
            miss->key = upcall->key;
            miss->key_len = upcall->key_len;
            miss->upcall_type = upcall->type;
            list_init(&miss->packets);

            n_misses++;
        } else {
            miss = existing_miss;
        }
        list_push_back(&miss->packets, &upcall->packet->list_node);
    }

    /* Process each element in the to-do list, constructing the set of
     * operations to batch. */
    n_ops = 0;
    HMAP_FOR_EACH (miss, hmap_node, &todo) {
        handle_flow_miss(ofproto, miss, flow_miss_ops, &n_ops);
    }
    assert(n_ops <= ARRAY_SIZE(flow_miss_ops));

    /* Execute batch. */
    for (i = 0; i < n_ops; i++) {
        dpif_ops[i] = &flow_miss_ops[i].dpif_op;
    }
    dpif_operate(ofproto->dpif, dpif_ops, n_ops);

    /* Free memory and update facets. */
    for (i = 0; i < n_ops; i++) {
        struct flow_miss_op *op = &flow_miss_ops[i];

        switch (op->dpif_op.type) {
        case DPIF_OP_EXECUTE:
            break;

        case DPIF_OP_FLOW_PUT:
            if (!op->dpif_op.error) {
                op->subfacet->path = subfacet_want_path(op->subfacet->slow);
            }
            break;

        case DPIF_OP_FLOW_DEL:
            NOT_REACHED();
        }

        free(op->garbage);
    }
    hmap_destroy(&todo);
}

static enum { SFLOW_UPCALL, MISS_UPCALL, BAD_UPCALL }
classify_upcall(const struct dpif_upcall *upcall)
{
    union user_action_cookie cookie;

    /* First look at the upcall type. */
    switch (upcall->type) {
    case DPIF_UC_ACTION:
        break;

    case DPIF_UC_MISS:
        return MISS_UPCALL;

    case DPIF_N_UC_TYPES:
    default:
        VLOG_WARN_RL(&rl, "upcall has unexpected type %"PRIu32, upcall->type);
        return BAD_UPCALL;
    }

    /* "action" upcalls need a closer look. */
    memcpy(&cookie, &upcall->userdata, sizeof(cookie));
    switch (cookie.type) {
    case USER_ACTION_COOKIE_SFLOW:
        return SFLOW_UPCALL;

    case USER_ACTION_COOKIE_SLOW_PATH:
        return MISS_UPCALL;

    case USER_ACTION_COOKIE_UNSPEC:
    default:
        VLOG_WARN_RL(&rl, "invalid user cookie : 0x%"PRIx64, upcall->userdata);
        return BAD_UPCALL;
    }
}

static void
handle_sflow_upcall(struct ofproto_dpif *ofproto,
                    const struct dpif_upcall *upcall)
{
    union user_action_cookie cookie;
    enum odp_key_fitness fitness;
    ovs_be16 initial_tci;
    struct flow flow;

    fitness = ofproto_dpif_extract_flow_key(ofproto, upcall->key,
                                            upcall->key_len, &flow,
                                            &initial_tci, upcall->packet);
    if (fitness == ODP_FIT_ERROR) {
        return;
    }

    memcpy(&cookie, &upcall->userdata, sizeof(cookie));
    dpif_sflow_received(ofproto->sflow, upcall->packet, &flow, &cookie);
}

static int
handle_upcalls(struct ofproto_dpif *ofproto, unsigned int max_batch)
{
    struct dpif_upcall misses[FLOW_MISS_MAX_BATCH];
    struct ofpbuf miss_bufs[FLOW_MISS_MAX_BATCH];
    uint64_t miss_buf_stubs[FLOW_MISS_MAX_BATCH][4096 / 8];
    int n_processed;
    int n_misses;
    int i;

    assert(max_batch <= FLOW_MISS_MAX_BATCH);

    n_misses = 0;
    for (n_processed = 0; n_processed < max_batch; n_processed++) {
        struct dpif_upcall *upcall = &misses[n_misses];
        struct ofpbuf *buf = &miss_bufs[n_misses];
        int error;

        ofpbuf_use_stub(buf, miss_buf_stubs[n_misses],
                        sizeof miss_buf_stubs[n_misses]);
        error = dpif_recv(ofproto->dpif, upcall, buf);
        if (error) {
            ofpbuf_uninit(buf);
            break;
        }

        switch (classify_upcall(upcall)) {
        case MISS_UPCALL:
            /* Handle it later. */
            n_misses++;
            break;

        case SFLOW_UPCALL:
            if (ofproto->sflow) {
                handle_sflow_upcall(ofproto, upcall);
            }
            ofpbuf_uninit(buf);
            break;

        case BAD_UPCALL:
            ofpbuf_uninit(buf);
            break;
        }
    }

    /* Handle deferred MISS_UPCALL processing. */
    handle_miss_upcalls(ofproto, misses, n_misses);
    for (i = 0; i < n_misses; i++) {
        ofpbuf_uninit(&miss_bufs[i]);
    }

    return n_processed;
}

/* Flow expiration. */

static int subfacet_max_idle(const struct ofproto_dpif *);
static void update_stats(struct ofproto_dpif *);
static void rule_expire(struct rule_dpif *);
static void expire_subfacets(struct ofproto_dpif *, int dp_max_idle);

/* This function is called periodically by run().  Its job is to collect
 * updates for the flows that have been installed into the datapath, most
 * importantly when they last were used, and then use that information to
 * expire flows that have not been used recently.
 *
 * Returns the number of milliseconds after which it should be called again. */
static int
expire(struct ofproto_dpif *ofproto)
{
    struct rule_dpif *rule, *next_rule;
    struct oftable *table;
    int dp_max_idle;

    /* Update stats for each flow in the datapath. */
    update_stats(ofproto);

    /* Expire subfacets that have been idle too long. */
    dp_max_idle = subfacet_max_idle(ofproto);
    expire_subfacets(ofproto, dp_max_idle);

    /* Expire OpenFlow flows whose idle_timeout or hard_timeout has passed. */
    OFPROTO_FOR_EACH_TABLE (table, &ofproto->up) {
        struct cls_cursor cursor;

        cls_cursor_init(&cursor, &table->cls, NULL);
        CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, up.cr, &cursor) {
            rule_expire(rule);
        }
    }

    /* All outstanding data in existing flows has been accounted, so it's a
     * good time to do bond rebalancing. */
    if (ofproto->has_bonded_bundles) {
        struct ofbundle *bundle;

        HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
            if (bundle->bond) {
                bond_rebalance(bundle->bond, &ofproto->revalidate_set);
            }
        }
    }

    return MIN(dp_max_idle, 1000);
}

/* Updates flow table statistics given that the datapath just reported 'stats'
 * as 'subfacet''s statistics. */
static void
update_subfacet_stats(struct subfacet *subfacet,
                      const struct dpif_flow_stats *stats)
{
    struct facet *facet = subfacet->facet;

    if (stats->n_packets >= subfacet->dp_packet_count) {
        uint64_t extra = stats->n_packets - subfacet->dp_packet_count;
        facet->packet_count += extra;
    } else {
        VLOG_WARN_RL(&rl, "unexpected packet count from the datapath");
    }

    if (stats->n_bytes >= subfacet->dp_byte_count) {
        facet->byte_count += stats->n_bytes - subfacet->dp_byte_count;
    } else {
        VLOG_WARN_RL(&rl, "unexpected byte count from datapath");
    }

    subfacet->dp_packet_count = stats->n_packets;
    subfacet->dp_byte_count = stats->n_bytes;

    facet->tcp_flags |= stats->tcp_flags;

    subfacet_update_time(subfacet, stats->used);
    if (facet->accounted_bytes < facet->byte_count) {
        facet_learn(facet);
        facet_account(facet);
        facet->accounted_bytes = facet->byte_count;
    }
    facet_push_stats(facet);
}

/* 'key' with length 'key_len' bytes is a flow in 'dpif' that we know nothing
 * about, or a flow that shouldn't be installed but was anyway.  Delete it. */
static void
delete_unexpected_flow(struct dpif *dpif,
                       const struct nlattr *key, size_t key_len)
{
    if (!VLOG_DROP_WARN(&rl)) {
        struct ds s;

        ds_init(&s);
        odp_flow_key_format(key, key_len, &s);
        VLOG_WARN("unexpected flow from datapath %s", ds_cstr(&s));
        ds_destroy(&s);
    }

    COVERAGE_INC(facet_unexpected);
    dpif_flow_del(dpif, key, key_len, NULL);
}

/* Update 'packet_count', 'byte_count', and 'used' members of installed facets.
 *
 * This function also pushes statistics updates to rules which each facet
 * resubmits into.  Generally these statistics will be accurate.  However, if a
 * facet changes the rule it resubmits into at some time in between
 * update_stats() runs, it is possible that statistics accrued to the
 * old rule will be incorrectly attributed to the new rule.  This could be
 * avoided by calling update_stats() whenever rules are created or
 * deleted.  However, the performance impact of making so many calls to the
 * datapath do not justify the benefit of having perfectly accurate statistics.
 */
static void
update_stats(struct ofproto_dpif *p)
{
    const struct dpif_flow_stats *stats;
    struct dpif_flow_dump dump;
    const struct nlattr *key;
    size_t key_len;

    dpif_flow_dump_start(&dump, p->dpif);
    while (dpif_flow_dump_next(&dump, &key, &key_len, NULL, NULL, &stats)) {
        struct subfacet *subfacet;

        subfacet = subfacet_find(p, key, key_len);
        switch (subfacet ? subfacet->path : SF_NOT_INSTALLED) {
        case SF_FAST_PATH:
            update_subfacet_stats(subfacet, stats);
            break;

        case SF_SLOW_PATH:
            /* Stats are updated per-packet. */
            break;

        case SF_NOT_INSTALLED:
        default:
            delete_unexpected_flow(p->dpif, key, key_len);
            break;
        }
    }
    dpif_flow_dump_done(&dump);
}

/* Calculates and returns the number of milliseconds of idle time after which
 * subfacets should expire from the datapath.  When a subfacet expires, we fold
 * its statistics into its facet, and when a facet's last subfacet expires, we
 * fold its statistic into its rule. */
static int
subfacet_max_idle(const struct ofproto_dpif *ofproto)
{
    /*
     * Idle time histogram.
     *
     * Most of the time a switch has a relatively small number of subfacets.
     * When this is the case we might as well keep statistics for all of them
     * in userspace and to cache them in the kernel datapath for performance as
     * well.
     *
     * As the number of subfacets increases, the memory required to maintain
     * statistics about them in userspace and in the kernel becomes
     * significant.  However, with a large number of subfacets it is likely
     * that only a few of them are "heavy hitters" that consume a large amount
     * of bandwidth.  At this point, only heavy hitters are worth caching in
     * the kernel and maintaining in userspaces; other subfacets we can
     * discard.
     *
     * The technique used to compute the idle time is to build a histogram with
     * N_BUCKETS buckets whose width is BUCKET_WIDTH msecs each.  Each subfacet
     * that is installed in the kernel gets dropped in the appropriate bucket.
     * After the histogram has been built, we compute the cutoff so that only
     * the most-recently-used 1% of subfacets (but at least
     * ofproto->up.flow_eviction_threshold flows) are kept cached.  At least
     * the most-recently-used bucket of subfacets is kept, so actually an
     * arbitrary number of subfacets can be kept in any given expiration run
     * (though the next run will delete most of those unless they receive
     * additional data).
     *
     * This requires a second pass through the subfacets, in addition to the
     * pass made by update_stats(), because the former function never looks at
     * uninstallable subfacets.
     */
    enum { BUCKET_WIDTH = ROUND_UP(100, TIME_UPDATE_INTERVAL) };
    enum { N_BUCKETS = 5000 / BUCKET_WIDTH };
    int buckets[N_BUCKETS] = { 0 };
    int total, subtotal, bucket;
    struct subfacet *subfacet;
    long long int now;
    int i;

    total = hmap_count(&ofproto->subfacets);
    if (total <= ofproto->up.flow_eviction_threshold) {
        return N_BUCKETS * BUCKET_WIDTH;
    }

    /* Build histogram. */
    now = time_msec();
    HMAP_FOR_EACH (subfacet, hmap_node, &ofproto->subfacets) {
        long long int idle = now - subfacet->used;
        int bucket = (idle <= 0 ? 0
                      : idle >= BUCKET_WIDTH * N_BUCKETS ? N_BUCKETS - 1
                      : (unsigned int) idle / BUCKET_WIDTH);
        buckets[bucket]++;
    }

    /* Find the first bucket whose flows should be expired. */
    subtotal = bucket = 0;
    do {
        subtotal += buckets[bucket++];
    } while (bucket < N_BUCKETS &&
             subtotal < MAX(ofproto->up.flow_eviction_threshold, total / 100));

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds s;

        ds_init(&s);
        ds_put_cstr(&s, "keep");
        for (i = 0; i < N_BUCKETS; i++) {
            if (i == bucket) {
                ds_put_cstr(&s, ", drop");
            }
            if (buckets[i]) {
                ds_put_format(&s, " %d:%d", i * BUCKET_WIDTH, buckets[i]);
            }
        }
        VLOG_INFO("%s: %s (msec:count)", ofproto->up.name, ds_cstr(&s));
        ds_destroy(&s);
    }

    return bucket * BUCKET_WIDTH;
}

enum { EXPIRE_MAX_BATCH = 50 };

static void
expire_batch(struct ofproto_dpif *ofproto, struct subfacet **subfacets, int n)
{
    struct odputil_keybuf keybufs[EXPIRE_MAX_BATCH];
    struct dpif_op ops[EXPIRE_MAX_BATCH];
    struct dpif_op *opsp[EXPIRE_MAX_BATCH];
    struct ofpbuf keys[EXPIRE_MAX_BATCH];
    struct dpif_flow_stats stats[EXPIRE_MAX_BATCH];
    int i;

    for (i = 0; i < n; i++) {
        ops[i].type = DPIF_OP_FLOW_DEL;
        subfacet_get_key(subfacets[i], &keybufs[i], &keys[i]);
        ops[i].u.flow_del.key = keys[i].data;
        ops[i].u.flow_del.key_len = keys[i].size;
        ops[i].u.flow_del.stats = &stats[i];
        opsp[i] = &ops[i];
    }

    dpif_operate(ofproto->dpif, opsp, n);
    for (i = 0; i < n; i++) {
        subfacet_reset_dp_stats(subfacets[i], &stats[i]);
        subfacets[i]->path = SF_NOT_INSTALLED;
        subfacet_destroy(subfacets[i]);
    }
}

static void
expire_subfacets(struct ofproto_dpif *ofproto, int dp_max_idle)
{
    /* Cutoff time for most flows. */
    long long int normal_cutoff = time_msec() - dp_max_idle;

    /* We really want to keep flows for special protocols around, so use a more
     * conservative cutoff. */
    long long int special_cutoff = time_msec() - 10000;

    struct subfacet *subfacet, *next_subfacet;
    struct subfacet *batch[EXPIRE_MAX_BATCH];
    int n_batch;

    n_batch = 0;
    HMAP_FOR_EACH_SAFE (subfacet, next_subfacet, hmap_node,
                        &ofproto->subfacets) {
        long long int cutoff;

        cutoff = (subfacet->slow & (SLOW_CFM | SLOW_LACP | SLOW_STP)
                  ? special_cutoff
                  : normal_cutoff);
        if (subfacet->used < cutoff) {
            if (subfacet->path != SF_NOT_INSTALLED) {
                batch[n_batch++] = subfacet;
                if (n_batch >= EXPIRE_MAX_BATCH) {
                    expire_batch(ofproto, batch, n_batch);
                    n_batch = 0;
                }
            } else {
                subfacet_destroy(subfacet);
            }
        }
    }

    if (n_batch > 0) {
        expire_batch(ofproto, batch, n_batch);
    }
}

/* If 'rule' is an OpenFlow rule, that has expired according to OpenFlow rules,
 * then delete it entirely. */
static void
rule_expire(struct rule_dpif *rule)
{
    struct facet *facet, *next_facet;
    long long int now;
    uint8_t reason;

    if (rule->up.pending) {
        /* We'll have to expire it later. */
        return;
    }

    /* Has 'rule' expired? */
    now = time_msec();
    if (rule->up.hard_timeout
        && now > rule->up.modified + rule->up.hard_timeout * 1000) {
        reason = OFPRR_HARD_TIMEOUT;
    } else if (rule->up.idle_timeout
               && now > rule->up.used + rule->up.idle_timeout * 1000) {
        reason = OFPRR_IDLE_TIMEOUT;
    } else {
        return;
    }

    COVERAGE_INC(ofproto_dpif_expired);

    /* Update stats.  (This is a no-op if the rule expired due to an idle
     * timeout, because that only happens when the rule has no facets left.) */
    LIST_FOR_EACH_SAFE (facet, next_facet, list_node, &rule->facets) {
        facet_remove(facet);
    }

    /* Get rid of the rule. */
    ofproto_rule_expire(&rule->up, reason);
}

/* Facets. */

/* Creates and returns a new facet owned by 'rule', given a 'flow'.
 *
 * The caller must already have determined that no facet with an identical
 * 'flow' exists in 'ofproto' and that 'flow' is the best match for 'rule' in
 * the ofproto's classifier table.
 *
 * 'hash' must be the return value of flow_hash(flow, 0).
 *
 * The facet will initially have no subfacets.  The caller should create (at
 * least) one subfacet with subfacet_create(). */
static struct facet *
facet_create(struct rule_dpif *rule, const struct flow *flow, uint32_t hash)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    struct facet *facet;

    facet = xzalloc(sizeof *facet);
    facet->used = time_msec();
    hmap_insert(&ofproto->facets, &facet->hmap_node, hash);
    list_push_back(&rule->facets, &facet->list_node);
    facet->rule = rule;
    facet->flow = *flow;
    list_init(&facet->subfacets);
    netflow_flow_init(&facet->nf_flow);
    netflow_flow_update_time(ofproto->netflow, &facet->nf_flow, facet->used);

    return facet;
}

static void
facet_free(struct facet *facet)
{
    free(facet);
}

/* Executes, within 'ofproto', the 'n_actions' actions in 'actions' on
 * 'packet', which arrived on 'in_port'.
 *
 * Takes ownership of 'packet'. */
static bool
execute_odp_actions(struct ofproto_dpif *ofproto, const struct flow *flow,
                    const struct nlattr *odp_actions, size_t actions_len,
                    struct ofpbuf *packet)
{
    struct odputil_keybuf keybuf;
    struct ofpbuf key;
    int error;

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&key, flow);

    error = dpif_execute(ofproto->dpif, key.data, key.size,
                         odp_actions, actions_len, packet);

    ofpbuf_delete(packet);
    return !error;
}

/* Remove 'facet' from 'ofproto' and free up the associated memory:
 *
 *   - If 'facet' was installed in the datapath, uninstalls it and updates its
 *     rule's statistics, via subfacet_uninstall().
 *
 *   - Removes 'facet' from its rule and from ofproto->facets.
 */
static void
facet_remove(struct facet *facet)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);
    struct subfacet *subfacet, *next_subfacet;

    assert(!list_is_empty(&facet->subfacets));

    /* First uninstall all of the subfacets to get final statistics. */
    LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
        subfacet_uninstall(subfacet);
    }

    /* Flush the final stats to the rule.
     *
     * This might require us to have at least one subfacet around so that we
     * can use its actions for accounting in facet_account(), which is why we
     * have uninstalled but not yet destroyed the subfacets. */
    facet_flush_stats(facet);

    /* Now we're really all done so destroy everything. */
    LIST_FOR_EACH_SAFE (subfacet, next_subfacet, list_node,
                        &facet->subfacets) {
        subfacet_destroy__(subfacet);
    }
    hmap_remove(&ofproto->facets, &facet->hmap_node);
    list_remove(&facet->list_node);
    facet_free(facet);
}

/* Feed information from 'facet' back into the learning table to keep it in
 * sync with what is actually flowing through the datapath. */
static void
facet_learn(struct facet *facet)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);
    struct action_xlate_ctx ctx;

    if (!facet->has_learn
        && !facet->has_normal
        && (!facet->has_fin_timeout
            || !(facet->tcp_flags & (TCP_FIN | TCP_RST)))) {
        return;
    }

    action_xlate_ctx_init(&ctx, ofproto, &facet->flow,
                          facet->flow.vlan_tci,
                          facet->rule, facet->tcp_flags, NULL);
    ctx.may_learn = true;
    xlate_actions_for_side_effects(&ctx, facet->rule->up.ofpacts,
                                   facet->rule->up.ofpacts_len);
}

static void
facet_account(struct facet *facet)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);
    struct subfacet *subfacet;
    const struct nlattr *a;
    unsigned int left;
    ovs_be16 vlan_tci;
    uint64_t n_bytes;

    if (!facet->has_normal || !ofproto->has_bonded_bundles) {
        return;
    }
    n_bytes = facet->byte_count - facet->accounted_bytes;

    /* This loop feeds byte counters to bond_account() for rebalancing to use
     * as a basis.  We also need to track the actual VLAN on which the packet
     * is going to be sent to ensure that it matches the one passed to
     * bond_choose_output_slave().  (Otherwise, we will account to the wrong
     * hash bucket.)
     *
     * We use the actions from an arbitrary subfacet because they should all
     * be equally valid for our purpose. */
    subfacet = CONTAINER_OF(list_front(&facet->subfacets),
                            struct subfacet, list_node);
    vlan_tci = facet->flow.vlan_tci;
    NL_ATTR_FOR_EACH_UNSAFE (a, left,
                             subfacet->actions, subfacet->actions_len) {
        const struct ovs_action_push_vlan *vlan;
        struct ofport_dpif *port;

        switch (nl_attr_type(a)) {
        case OVS_ACTION_ATTR_OUTPUT:
            port = get_odp_port(ofproto, nl_attr_get_u32(a));
            if (port && port->bundle && port->bundle->bond) {
                bond_account(port->bundle->bond, &facet->flow,
                             vlan_tci_to_vid(vlan_tci), n_bytes);
            }
            break;

        case OVS_ACTION_ATTR_POP_VLAN:
            vlan_tci = htons(0);
            break;

        case OVS_ACTION_ATTR_PUSH_VLAN:
            vlan = nl_attr_get(a);
            vlan_tci = vlan->vlan_tci;
            break;
        }
    }
}

/* Returns true if the only action for 'facet' is to send to the controller.
 * (We don't report NetFlow expiration messages for such facets because they
 * are just part of the control logic for the network, not real traffic). */
static bool
facet_is_controller_flow(struct facet *facet)
{
    if (facet) {
        const struct rule *rule = &facet->rule->up;
        const struct ofpact *ofpacts = rule->ofpacts;
        size_t ofpacts_len = rule->ofpacts_len;

        if (ofpacts_len > 0 &&
            ofpacts->type == OFPACT_CONTROLLER &&
            ofpact_next(ofpacts) >= ofpact_end(ofpacts, ofpacts_len)) {
            return true;
        }
    }
    return false;
}

/* Folds all of 'facet''s statistics into its rule.  Also updates the
 * accounting ofhook and emits a NetFlow expiration if appropriate.  All of
 * 'facet''s statistics in the datapath should have been zeroed and folded into
 * its packet and byte counts before this function is called. */
static void
facet_flush_stats(struct facet *facet)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);
    struct subfacet *subfacet;

    LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
        assert(!subfacet->dp_byte_count);
        assert(!subfacet->dp_packet_count);
    }

    facet_push_stats(facet);
    if (facet->accounted_bytes < facet->byte_count) {
        facet_account(facet);
        facet->accounted_bytes = facet->byte_count;
    }

    if (ofproto->netflow && !facet_is_controller_flow(facet)) {
        struct ofexpired expired;
        expired.flow = facet->flow;
        expired.packet_count = facet->packet_count;
        expired.byte_count = facet->byte_count;
        expired.used = facet->used;
        netflow_expire(ofproto->netflow, &facet->nf_flow, &expired);
    }

    facet->rule->packet_count += facet->packet_count;
    facet->rule->byte_count += facet->byte_count;

    /* Reset counters to prevent double counting if 'facet' ever gets
     * reinstalled. */
    facet_reset_counters(facet);

    netflow_flow_clear(&facet->nf_flow);
    facet->tcp_flags = 0;
}

/* Searches 'ofproto''s table of facets for one exactly equal to 'flow'.
 * Returns it if found, otherwise a null pointer.
 *
 * 'hash' must be the return value of flow_hash(flow, 0).
 *
 * The returned facet might need revalidation; use facet_lookup_valid()
 * instead if that is important. */
static struct facet *
facet_find(struct ofproto_dpif *ofproto,
           const struct flow *flow, uint32_t hash)
{
    struct facet *facet;

    HMAP_FOR_EACH_WITH_HASH (facet, hmap_node, hash, &ofproto->facets) {
        if (flow_equal(flow, &facet->flow)) {
            return facet;
        }
    }

    return NULL;
}

/* Searches 'ofproto''s table of facets for one exactly equal to 'flow'.
 * Returns it if found, otherwise a null pointer.
 *
 * 'hash' must be the return value of flow_hash(flow, 0).
 *
 * The returned facet is guaranteed to be valid. */
static struct facet *
facet_lookup_valid(struct ofproto_dpif *ofproto, const struct flow *flow,
                   uint32_t hash)
{
    struct facet *facet;

    facet = facet_find(ofproto, flow, hash);
    if (facet
        && (ofproto->need_revalidate
            || tag_set_intersects(&ofproto->revalidate_set, facet->tags))) {
        facet_revalidate(facet);
    }

    return facet;
}

static const char *
subfacet_path_to_string(enum subfacet_path path)
{
    switch (path) {
    case SF_NOT_INSTALLED:
        return "not installed";
    case SF_FAST_PATH:
        return "in fast path";
    case SF_SLOW_PATH:
        return "in slow path";
    default:
        return "<error>";
    }
}

/* Returns the path in which a subfacet should be installed if its 'slow'
 * member has the specified value. */
static enum subfacet_path
subfacet_want_path(enum slow_path_reason slow)
{
    return slow ? SF_SLOW_PATH : SF_FAST_PATH;
}

/* Returns true if 'subfacet' needs to have its datapath flow updated,
 * supposing that its actions have been recalculated as 'want_actions' and that
 * 'slow' is nonzero iff 'subfacet' should be in the slow path. */
static bool
subfacet_should_install(struct subfacet *subfacet, enum slow_path_reason slow,
                        const struct ofpbuf *want_actions)
{
    enum subfacet_path want_path = subfacet_want_path(slow);
    return (want_path != subfacet->path
            || (want_path == SF_FAST_PATH
                && (subfacet->actions_len != want_actions->size
                    || memcmp(subfacet->actions, want_actions->data,
                              subfacet->actions_len))));
}

static bool
facet_check_consistency(struct facet *facet)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 15);

    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);

    uint64_t odp_actions_stub[1024 / 8];
    struct ofpbuf odp_actions;

    struct rule_dpif *rule;
    struct subfacet *subfacet;
    bool may_log = false;
    bool ok;

    /* Check the rule for consistency. */
    rule = rule_dpif_lookup(ofproto, &facet->flow);
    ok = rule == facet->rule;
    if (!ok) {
        may_log = !VLOG_DROP_WARN(&rl);
        if (may_log) {
            struct ds s;

            ds_init(&s);
            flow_format(&s, &facet->flow);
            ds_put_format(&s, ": facet associated with wrong rule (was "
                          "table=%"PRIu8",", facet->rule->up.table_id);
            cls_rule_format(&facet->rule->up.cr, &s);
            ds_put_format(&s, ") (should have been table=%"PRIu8",",
                          rule->up.table_id);
            cls_rule_format(&rule->up.cr, &s);
            ds_put_char(&s, ')');

            VLOG_WARN("%s", ds_cstr(&s));
            ds_destroy(&s);
        }
    }

    /* Check the datapath actions for consistency. */
    ofpbuf_use_stub(&odp_actions, odp_actions_stub, sizeof odp_actions_stub);
    LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
        enum subfacet_path want_path;
        struct odputil_keybuf keybuf;
        struct action_xlate_ctx ctx;
        struct ofpbuf key;
        struct ds s;

        action_xlate_ctx_init(&ctx, ofproto, &facet->flow,
                              subfacet->initial_tci, rule, 0, NULL);
        xlate_actions(&ctx, rule->up.ofpacts, rule->up.ofpacts_len,
                      &odp_actions);

        if (subfacet->path == SF_NOT_INSTALLED) {
            /* This only happens if the datapath reported an error when we
             * tried to install the flow.  Don't flag another error here. */
            continue;
        }

        want_path = subfacet_want_path(subfacet->slow);
        if (want_path == SF_SLOW_PATH && subfacet->path == SF_SLOW_PATH) {
            /* The actions for slow-path flows may legitimately vary from one
             * packet to the next.  We're done. */
            continue;
        }

        if (!subfacet_should_install(subfacet, subfacet->slow, &odp_actions)) {
            continue;
        }

        /* Inconsistency! */
        if (ok) {
            may_log = !VLOG_DROP_WARN(&rl);
            ok = false;
        }
        if (!may_log) {
            /* Rate-limited, skip reporting. */
            continue;
        }

        ds_init(&s);
        subfacet_get_key(subfacet, &keybuf, &key);
        odp_flow_key_format(key.data, key.size, &s);

        ds_put_cstr(&s, ": inconsistency in subfacet");
        if (want_path != subfacet->path) {
            enum odp_key_fitness fitness = subfacet->key_fitness;

            ds_put_format(&s, " (%s, fitness=%s)",
                          subfacet_path_to_string(subfacet->path),
                          odp_key_fitness_to_string(fitness));
            ds_put_format(&s, " (should have been %s)",
                          subfacet_path_to_string(want_path));
        } else if (want_path == SF_FAST_PATH) {
            ds_put_cstr(&s, " (actions were: ");
            format_odp_actions(&s, subfacet->actions,
                               subfacet->actions_len);
            ds_put_cstr(&s, ") (correct actions: ");
            format_odp_actions(&s, odp_actions.data, odp_actions.size);
            ds_put_char(&s, ')');
        } else {
            ds_put_cstr(&s, " (actions: ");
            format_odp_actions(&s, subfacet->actions,
                               subfacet->actions_len);
            ds_put_char(&s, ')');
        }
        VLOG_WARN("%s", ds_cstr(&s));
        ds_destroy(&s);
    }
    ofpbuf_uninit(&odp_actions);

    return ok;
}

/* Re-searches the classifier for 'facet':
 *
 *   - If the rule found is different from 'facet''s current rule, moves
 *     'facet' to the new rule and recompiles its actions.
 *
 *   - If the rule found is the same as 'facet''s current rule, leaves 'facet'
 *     where it is and recompiles its actions anyway. */
static void
facet_revalidate(struct facet *facet)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);
    struct actions {
        struct nlattr *odp_actions;
        size_t actions_len;
    };
    struct actions *new_actions;

    struct action_xlate_ctx ctx;
    uint64_t odp_actions_stub[1024 / 8];
    struct ofpbuf odp_actions;

    struct rule_dpif *new_rule;
    struct subfacet *subfacet;
    int i;

    COVERAGE_INC(facet_revalidate);

    new_rule = rule_dpif_lookup(ofproto, &facet->flow);

    /* Calculate new datapath actions.
     *
     * We do not modify any 'facet' state yet, because we might need to, e.g.,
     * emit a NetFlow expiration and, if so, we need to have the old state
     * around to properly compose it. */

    /* If the datapath actions changed or the installability changed,
     * then we need to talk to the datapath. */
    i = 0;
    new_actions = NULL;
    memset(&ctx, 0, sizeof ctx);
    ofpbuf_use_stub(&odp_actions, odp_actions_stub, sizeof odp_actions_stub);
    LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
        enum slow_path_reason slow;

        action_xlate_ctx_init(&ctx, ofproto, &facet->flow,
                              subfacet->initial_tci, new_rule, 0, NULL);
        xlate_actions(&ctx, new_rule->up.ofpacts, new_rule->up.ofpacts_len,
                      &odp_actions);

        slow = (subfacet->slow & SLOW_MATCH) | ctx.slow;
        if (subfacet_should_install(subfacet, slow, &odp_actions)) {
            struct dpif_flow_stats stats;

            subfacet_install(subfacet,
                             odp_actions.data, odp_actions.size, &stats, slow);
            subfacet_update_stats(subfacet, &stats);

            if (!new_actions) {
                new_actions = xcalloc(list_size(&facet->subfacets),
                                      sizeof *new_actions);
            }
            new_actions[i].odp_actions = xmemdup(odp_actions.data,
                                                 odp_actions.size);
            new_actions[i].actions_len = odp_actions.size;
        }

        i++;
    }
    ofpbuf_uninit(&odp_actions);

    if (new_actions) {
        facet_flush_stats(facet);
    }

    /* Update 'facet' now that we've taken care of all the old state. */
    facet->tags = ctx.tags;
    facet->nf_flow.output_iface = ctx.nf_output_iface;
    facet->has_learn = ctx.has_learn;
    facet->has_normal = ctx.has_normal;
    facet->has_fin_timeout = ctx.has_fin_timeout;
    facet->mirrors = ctx.mirrors;

    i = 0;
    LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
        subfacet->slow = (subfacet->slow & SLOW_MATCH) | ctx.slow;

        if (new_actions && new_actions[i].odp_actions) {
            free(subfacet->actions);
            subfacet->actions = new_actions[i].odp_actions;
            subfacet->actions_len = new_actions[i].actions_len;
        }
        i++;
    }
    free(new_actions);

    if (facet->rule != new_rule) {
        COVERAGE_INC(facet_changed_rule);
        list_remove(&facet->list_node);
        list_push_back(&new_rule->facets, &facet->list_node);
        facet->rule = new_rule;
        facet->used = new_rule->up.created;
        facet->prev_used = facet->used;
    }
}

/* Updates 'facet''s used time.  Caller is responsible for calling
 * facet_push_stats() to update the flows which 'facet' resubmits into. */
static void
facet_update_time(struct facet *facet, long long int used)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);
    if (used > facet->used) {
        facet->used = used;
        ofproto_rule_update_used(&facet->rule->up, used);
        netflow_flow_update_time(ofproto->netflow, &facet->nf_flow, used);
    }
}

static void
facet_reset_counters(struct facet *facet)
{
    facet->packet_count = 0;
    facet->byte_count = 0;
    facet->prev_packet_count = 0;
    facet->prev_byte_count = 0;
    facet->accounted_bytes = 0;
}

static void
facet_push_stats(struct facet *facet)
{
    struct dpif_flow_stats stats;

    assert(facet->packet_count >= facet->prev_packet_count);
    assert(facet->byte_count >= facet->prev_byte_count);
    assert(facet->used >= facet->prev_used);

    stats.n_packets = facet->packet_count - facet->prev_packet_count;
    stats.n_bytes = facet->byte_count - facet->prev_byte_count;
    stats.used = facet->used;
    stats.tcp_flags = 0;

    if (stats.n_packets || stats.n_bytes || facet->used > facet->prev_used) {
        facet->prev_packet_count = facet->packet_count;
        facet->prev_byte_count = facet->byte_count;
        facet->prev_used = facet->used;

        flow_push_stats(facet->rule, &facet->flow, &stats);

        update_mirror_stats(ofproto_dpif_cast(facet->rule->up.ofproto),
                            facet->mirrors, stats.n_packets, stats.n_bytes);
    }
}

static void
rule_credit_stats(struct rule_dpif *rule, const struct dpif_flow_stats *stats)
{
    rule->packet_count += stats->n_packets;
    rule->byte_count += stats->n_bytes;
    ofproto_rule_update_used(&rule->up, stats->used);
}

/* Pushes flow statistics to the rules which 'flow' resubmits into given
 * 'rule''s actions and mirrors. */
static void
flow_push_stats(struct rule_dpif *rule,
                const struct flow *flow, const struct dpif_flow_stats *stats)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    struct action_xlate_ctx ctx;

    ofproto_rule_update_used(&rule->up, stats->used);

    action_xlate_ctx_init(&ctx, ofproto, flow, flow->vlan_tci, rule,
                          0, NULL);
    ctx.resubmit_stats = stats;
    xlate_actions_for_side_effects(&ctx, rule->up.ofpacts,
                                   rule->up.ofpacts_len);
}

/* Subfacets. */

static struct subfacet *
subfacet_find__(struct ofproto_dpif *ofproto,
                const struct nlattr *key, size_t key_len, uint32_t key_hash,
                const struct flow *flow)
{
    struct subfacet *subfacet;

    HMAP_FOR_EACH_WITH_HASH (subfacet, hmap_node, key_hash,
                             &ofproto->subfacets) {
        if (subfacet->key
            ? (subfacet->key_len == key_len
               && !memcmp(key, subfacet->key, key_len))
            : flow_equal(flow, &subfacet->facet->flow)) {
            return subfacet;
        }
    }

    return NULL;
}

/* Searches 'facet' (within 'ofproto') for a subfacet with the specified
 * 'key_fitness', 'key', and 'key_len'.  Returns the existing subfacet if
 * there is one, otherwise creates and returns a new subfacet.
 *
 * If the returned subfacet is new, then subfacet->actions will be NULL, in
 * which case the caller must populate the actions with
 * subfacet_make_actions(). */
static struct subfacet *
subfacet_create(struct facet *facet, enum odp_key_fitness key_fitness,
                const struct nlattr *key, size_t key_len,
                ovs_be16 initial_tci, long long int now)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);
    uint32_t key_hash = odp_flow_key_hash(key, key_len);
    struct subfacet *subfacet;

    if (list_is_empty(&facet->subfacets)) {
        subfacet = &facet->one_subfacet;
    } else {
        subfacet = subfacet_find__(ofproto, key, key_len, key_hash,
                                   &facet->flow);
        if (subfacet) {
            if (subfacet->facet == facet) {
                return subfacet;
            }

            /* This shouldn't happen. */
            VLOG_ERR_RL(&rl, "subfacet with wrong facet");
            subfacet_destroy(subfacet);
        }

        subfacet = xmalloc(sizeof *subfacet);
    }

    hmap_insert(&ofproto->subfacets, &subfacet->hmap_node, key_hash);
    list_push_back(&facet->subfacets, &subfacet->list_node);
    subfacet->facet = facet;
    subfacet->key_fitness = key_fitness;
    if (key_fitness != ODP_FIT_PERFECT) {
        subfacet->key = xmemdup(key, key_len);
        subfacet->key_len = key_len;
    } else {
        subfacet->key = NULL;
        subfacet->key_len = 0;
    }
    subfacet->used = now;
    subfacet->dp_packet_count = 0;
    subfacet->dp_byte_count = 0;
    subfacet->actions_len = 0;
    subfacet->actions = NULL;
    subfacet->slow = (subfacet->key_fitness == ODP_FIT_TOO_LITTLE
                      ? SLOW_MATCH
                      : 0);
    subfacet->path = SF_NOT_INSTALLED;
    subfacet->initial_tci = initial_tci;

    return subfacet;
}

/* Searches 'ofproto' for a subfacet with the given 'key', 'key_len', and
 * 'flow'.  Returns the subfacet if one exists, otherwise NULL. */
static struct subfacet *
subfacet_find(struct ofproto_dpif *ofproto,
              const struct nlattr *key, size_t key_len)
{
    uint32_t key_hash = odp_flow_key_hash(key, key_len);
    enum odp_key_fitness fitness;
    struct flow flow;

    fitness = odp_flow_key_to_flow(key, key_len, &flow);
    if (fitness == ODP_FIT_ERROR) {
        return NULL;
    }

    return subfacet_find__(ofproto, key, key_len, key_hash, &flow);
}

/* Uninstalls 'subfacet' from the datapath, if it is installed, removes it from
 * its facet within 'ofproto', and frees it. */
static void
subfacet_destroy__(struct subfacet *subfacet)
{
    struct facet *facet = subfacet->facet;
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);

    subfacet_uninstall(subfacet);
    hmap_remove(&ofproto->subfacets, &subfacet->hmap_node);
    list_remove(&subfacet->list_node);
    free(subfacet->key);
    free(subfacet->actions);
    if (subfacet != &facet->one_subfacet) {
        free(subfacet);
    }
}

/* Destroys 'subfacet', as with subfacet_destroy__(), and then if this was the
 * last remaining subfacet in its facet destroys the facet too. */
static void
subfacet_destroy(struct subfacet *subfacet)
{
    struct facet *facet = subfacet->facet;

    if (list_is_singleton(&facet->subfacets)) {
        /* facet_remove() needs at least one subfacet (it will remove it). */
        facet_remove(facet);
    } else {
        subfacet_destroy__(subfacet);
    }
}

/* Initializes 'key' with the sequence of OVS_KEY_ATTR_* Netlink attributes
 * that can be used to refer to 'subfacet'.  The caller must provide 'keybuf'
 * for use as temporary storage. */
static void
subfacet_get_key(struct subfacet *subfacet, struct odputil_keybuf *keybuf,
                 struct ofpbuf *key)
{
    if (!subfacet->key) {
        ofpbuf_use_stack(key, keybuf, sizeof *keybuf);
        odp_flow_key_from_flow(key, &subfacet->facet->flow);
    } else {
        ofpbuf_use_const(key, subfacet->key, subfacet->key_len);
    }
}

/* Composes the datapath actions for 'subfacet' based on its rule's actions.
 * Translates the actions into 'odp_actions', which the caller must have
 * initialized and is responsible for uninitializing. */
static void
subfacet_make_actions(struct subfacet *subfacet, const struct ofpbuf *packet,
                      struct ofpbuf *odp_actions)
{
    struct facet *facet = subfacet->facet;
    struct rule_dpif *rule = facet->rule;
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);

    struct action_xlate_ctx ctx;

    action_xlate_ctx_init(&ctx, ofproto, &facet->flow, subfacet->initial_tci,
                          rule, 0, packet);
    xlate_actions(&ctx, rule->up.ofpacts, rule->up.ofpacts_len, odp_actions);
    facet->tags = ctx.tags;
    facet->has_learn = ctx.has_learn;
    facet->has_normal = ctx.has_normal;
    facet->has_fin_timeout = ctx.has_fin_timeout;
    facet->nf_flow.output_iface = ctx.nf_output_iface;
    facet->mirrors = ctx.mirrors;

    subfacet->slow = (subfacet->slow & SLOW_MATCH) | ctx.slow;
    if (subfacet->actions_len != odp_actions->size
        || memcmp(subfacet->actions, odp_actions->data, odp_actions->size)) {
        free(subfacet->actions);
        subfacet->actions_len = odp_actions->size;
        subfacet->actions = xmemdup(odp_actions->data, odp_actions->size);
    }
}

/* Updates 'subfacet''s datapath flow, setting its actions to 'actions_len'
 * bytes of actions in 'actions'.  If 'stats' is non-null, statistics counters
 * in the datapath will be zeroed and 'stats' will be updated with traffic new
 * since 'subfacet' was last updated.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
subfacet_install(struct subfacet *subfacet,
                 const struct nlattr *actions, size_t actions_len,
                 struct dpif_flow_stats *stats,
                 enum slow_path_reason slow)
{
    struct facet *facet = subfacet->facet;
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(facet->rule->up.ofproto);
    enum subfacet_path path = subfacet_want_path(slow);
    uint64_t slow_path_stub[128 / 8];
    struct odputil_keybuf keybuf;
    enum dpif_flow_put_flags flags;
    struct ofpbuf key;
    int ret;

    flags = DPIF_FP_CREATE | DPIF_FP_MODIFY;
    if (stats) {
        flags |= DPIF_FP_ZERO_STATS;
    }

    if (path == SF_SLOW_PATH) {
        compose_slow_path(ofproto, &facet->flow, slow,
                          slow_path_stub, sizeof slow_path_stub,
                          &actions, &actions_len);
    }

    subfacet_get_key(subfacet, &keybuf, &key);
    ret = dpif_flow_put(ofproto->dpif, flags, key.data, key.size,
                        actions, actions_len, stats);

    if (stats) {
        subfacet_reset_dp_stats(subfacet, stats);
    }

    if (!ret) {
        subfacet->path = path;
    }
    return ret;
}

static int
subfacet_reinstall(struct subfacet *subfacet, struct dpif_flow_stats *stats)
{
    return subfacet_install(subfacet, subfacet->actions, subfacet->actions_len,
                            stats, subfacet->slow);
}

/* If 'subfacet' is installed in the datapath, uninstalls it. */
static void
subfacet_uninstall(struct subfacet *subfacet)
{
    if (subfacet->path != SF_NOT_INSTALLED) {
        struct rule_dpif *rule = subfacet->facet->rule;
        struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
        struct odputil_keybuf keybuf;
        struct dpif_flow_stats stats;
        struct ofpbuf key;
        int error;

        subfacet_get_key(subfacet, &keybuf, &key);
        error = dpif_flow_del(ofproto->dpif, key.data, key.size, &stats);
        subfacet_reset_dp_stats(subfacet, &stats);
        if (!error) {
            subfacet_update_stats(subfacet, &stats);
        }
        subfacet->path = SF_NOT_INSTALLED;
    } else {
        assert(subfacet->dp_packet_count == 0);
        assert(subfacet->dp_byte_count == 0);
    }
}

/* Resets 'subfacet''s datapath statistics counters.  This should be called
 * when 'subfacet''s statistics are cleared in the datapath.  If 'stats' is
 * non-null, it should contain the statistics returned by dpif when 'subfacet'
 * was reset in the datapath.  'stats' will be modified to include only
 * statistics new since 'subfacet' was last updated. */
static void
subfacet_reset_dp_stats(struct subfacet *subfacet,
                        struct dpif_flow_stats *stats)
{
    if (stats
        && subfacet->dp_packet_count <= stats->n_packets
        && subfacet->dp_byte_count <= stats->n_bytes) {
        stats->n_packets -= subfacet->dp_packet_count;
        stats->n_bytes -= subfacet->dp_byte_count;
    }

    subfacet->dp_packet_count = 0;
    subfacet->dp_byte_count = 0;
}

/* Updates 'subfacet''s used time.  The caller is responsible for calling
 * facet_push_stats() to update the flows which 'subfacet' resubmits into. */
static void
subfacet_update_time(struct subfacet *subfacet, long long int used)
{
    if (used > subfacet->used) {
        subfacet->used = used;
        facet_update_time(subfacet->facet, used);
    }
}

/* Folds the statistics from 'stats' into the counters in 'subfacet'.
 *
 * Because of the meaning of a subfacet's counters, it only makes sense to do
 * this if 'stats' are not tracked in the datapath, that is, if 'stats'
 * represents a packet that was sent by hand or if it represents statistics
 * that have been cleared out of the datapath. */
static void
subfacet_update_stats(struct subfacet *subfacet,
                      const struct dpif_flow_stats *stats)
{
    if (stats->n_packets || stats->used > subfacet->used) {
        struct facet *facet = subfacet->facet;

        subfacet_update_time(subfacet, stats->used);
        facet->packet_count += stats->n_packets;
        facet->byte_count += stats->n_bytes;
        facet->tcp_flags |= stats->tcp_flags;
        facet_push_stats(facet);
        netflow_flow_update_flags(&facet->nf_flow, stats->tcp_flags);
    }
}

/* Rules. */

static struct rule_dpif *
rule_dpif_lookup(struct ofproto_dpif *ofproto, const struct flow *flow)
{
    struct rule_dpif *rule;

    rule = rule_dpif_lookup__(ofproto, flow, 0);
    if (rule) {
        return rule;
    }

    return rule_dpif_miss_rule(ofproto, flow);
}

static struct rule_dpif *
rule_dpif_lookup__(struct ofproto_dpif *ofproto, const struct flow *flow,
                   uint8_t table_id)
{
    struct cls_rule *cls_rule;
    struct classifier *cls;
    bool frag;

    if (table_id >= N_TABLES) {
        return NULL;
    }

    cls = &ofproto->up.tables[table_id].cls;
    frag = (flow->nw_frag & FLOW_NW_FRAG_ANY) != 0;
    if (frag && ofproto->up.frag_handling == OFPC_FRAG_NORMAL) {
        /* We must pretend that transport ports are unavailable. */
        struct flow ofpc_normal_flow = *flow;
        ofpc_normal_flow.tp_src = htons(0);
        ofpc_normal_flow.tp_dst = htons(0);
        cls_rule = classifier_lookup(cls, &ofpc_normal_flow);
    } else if (frag && ofproto->up.frag_handling == OFPC_FRAG_DROP) {
        cls_rule = &ofproto->drop_frags_rule->up.cr;
    } else {
        cls_rule = classifier_lookup(cls, flow);
    }
    return rule_dpif_cast(rule_from_cls_rule(cls_rule));
}

static struct rule_dpif *
rule_dpif_miss_rule(struct ofproto_dpif *ofproto, const struct flow *flow)
{
    struct ofport_dpif *port;

    port = get_ofp_port(ofproto, flow->in_port);
    if (!port) {
        VLOG_WARN_RL(&rl, "packet-in on unknown port %"PRIu16, flow->in_port);
        return ofproto->miss_rule;
    }

    if (port->up.pp.config & OFPUTIL_PC_NO_PACKET_IN) {
        return ofproto->no_packet_in_rule;
    }
    return ofproto->miss_rule;
}

static void
complete_operation(struct rule_dpif *rule)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);

    rule_invalidate(rule);
    if (clogged) {
        struct dpif_completion *c = xmalloc(sizeof *c);
        c->op = rule->up.pending;
        list_push_back(&ofproto->completions, &c->list_node);
    } else {
        ofoperation_complete(rule->up.pending, 0);
    }
}

static struct rule *
rule_alloc(void)
{
    struct rule_dpif *rule = xmalloc(sizeof *rule);
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
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    struct rule_dpif *victim;
    uint8_t table_id;

    rule->packet_count = 0;
    rule->byte_count = 0;

    victim = rule_dpif_cast(ofoperation_get_victim(rule->up.pending));
    if (victim && !list_is_empty(&victim->facets)) {
        struct facet *facet;

        rule->facets = victim->facets;
        list_moved(&rule->facets);
        LIST_FOR_EACH (facet, list_node, &rule->facets) {
            /* XXX: We're only clearing our local counters here.  It's possible
             * that quite a few packets are unaccounted for in the datapath
             * statistics.  These will be accounted to the new rule instead of
             * cleared as required.  This could be fixed by clearing out the
             * datapath statistics for this facet, but currently it doesn't
             * seem worth it. */
            facet_reset_counters(facet);
            facet->rule = rule;
        }
    } else {
        /* Must avoid list_moved() in this case. */
        list_init(&rule->facets);
    }

    table_id = rule->up.table_id;
    if (victim) {
        rule->tag = victim->tag;
    } else if (table_id == 0) {
        rule->tag = 0;
    } else {
        struct flow flow;

        miniflow_expand(&rule->up.cr.match.flow, &flow);
        rule->tag = rule_calculate_tag(&flow, &rule->up.cr.match.mask,
                                       ofproto->tables[table_id].basis);
    }

    complete_operation(rule);
    return 0;
}

static void
rule_destruct(struct rule *rule_)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    struct facet *facet, *next_facet;

    LIST_FOR_EACH_SAFE (facet, next_facet, list_node, &rule->facets) {
        facet_revalidate(facet);
    }

    complete_operation(rule);
}

static void
rule_get_stats(struct rule *rule_, uint64_t *packets, uint64_t *bytes)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    struct facet *facet;

    /* Start from historical data for 'rule' itself that are no longer tracked
     * in facets.  This counts, for example, facets that have expired. */
    *packets = rule->packet_count;
    *bytes = rule->byte_count;

    /* Add any statistics that are tracked by facets.  This includes
     * statistical data recently updated by ofproto_update_stats() as well as
     * stats for packets that were executed "by hand" via dpif_execute(). */
    LIST_FOR_EACH (facet, list_node, &rule->facets) {
        *packets += facet->packet_count;
        *bytes += facet->byte_count;
    }
}

static enum ofperr
rule_execute(struct rule *rule_, const struct flow *flow,
             struct ofpbuf *packet)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);

    struct dpif_flow_stats stats;

    struct action_xlate_ctx ctx;
    uint64_t odp_actions_stub[1024 / 8];
    struct ofpbuf odp_actions;

    dpif_flow_stats_extract(flow, packet, time_msec(), &stats);
    rule_credit_stats(rule, &stats);

    ofpbuf_use_stub(&odp_actions, odp_actions_stub, sizeof odp_actions_stub);
    action_xlate_ctx_init(&ctx, ofproto, flow, flow->vlan_tci,
                          rule, stats.tcp_flags, packet);
    ctx.resubmit_stats = &stats;
    xlate_actions(&ctx, rule->up.ofpacts, rule->up.ofpacts_len, &odp_actions);

    execute_odp_actions(ofproto, flow, odp_actions.data,
                        odp_actions.size, packet);

    ofpbuf_uninit(&odp_actions);

    return 0;
}

static void
rule_modify_actions(struct rule *rule_)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);

    complete_operation(rule);
}

/* Sends 'packet' out 'ofport'.
 * May modify 'packet'.
 * Returns 0 if successful, otherwise a positive errno value. */
static int
send_packet(const struct ofport_dpif *ofport, struct ofpbuf *packet)
{
    const struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);
    struct ofpbuf key, odp_actions;
    struct odputil_keybuf keybuf;
    uint16_t odp_port;
    struct flow flow;
    int error;

    flow_extract(packet, 0, 0, NULL, 0, &flow);
    odp_port = vsp_realdev_to_vlandev(ofproto, ofport->odp_port,
                                      flow.vlan_tci);
    if (odp_port != ofport->odp_port) {
        eth_pop_vlan(packet);
        flow.vlan_tci = htons(0);
    }

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&key, &flow);

    ofpbuf_init(&odp_actions, 32);
    compose_sflow_action(ofproto, &odp_actions, &flow, odp_port);

    nl_msg_put_u32(&odp_actions, OVS_ACTION_ATTR_OUTPUT, odp_port);
    error = dpif_execute(ofproto->dpif,
                         key.data, key.size,
                         odp_actions.data, odp_actions.size,
                         packet);
    ofpbuf_uninit(&odp_actions);

    if (error) {
        VLOG_WARN_RL(&rl, "%s: failed to send packet on port %"PRIu32" (%s)",
                     ofproto->up.name, odp_port, strerror(error));
    }
    ofproto_update_local_port_stats(ofport->up.ofproto, packet->size, 0);
    return error;
}

/* OpenFlow to datapath action translation. */

static void do_xlate_actions(const struct ofpact *, size_t ofpacts_len,
                             struct action_xlate_ctx *);
static void xlate_normal(struct action_xlate_ctx *);

/* Composes an ODP action for a "slow path" action for 'flow' within 'ofproto'.
 * The action will state 'slow' as the reason that the action is in the slow
 * path.  (This is purely informational: it allows a human viewing "ovs-dpctl
 * dump-flows" output to see why a flow is in the slow path.)
 *
 * The 'stub_size' bytes in 'stub' will be used to store the action.
 * 'stub_size' must be large enough for the action.
 *
 * The action and its size will be stored in '*actionsp' and '*actions_lenp',
 * respectively. */
static void
compose_slow_path(const struct ofproto_dpif *ofproto, const struct flow *flow,
                  enum slow_path_reason slow,
                  uint64_t *stub, size_t stub_size,
                  const struct nlattr **actionsp, size_t *actions_lenp)
{
    union user_action_cookie cookie;
    struct ofpbuf buf;

    cookie.type = USER_ACTION_COOKIE_SLOW_PATH;
    cookie.slow_path.unused = 0;
    cookie.slow_path.reason = slow;

    ofpbuf_use_stack(&buf, stub, stub_size);
    if (slow & (SLOW_CFM | SLOW_LACP | SLOW_STP)) {
        uint32_t pid = dpif_port_get_pid(ofproto->dpif, UINT16_MAX);
        odp_put_userspace_action(pid, &cookie, &buf);
    } else {
        put_userspace_action(ofproto, &buf, flow, &cookie);
    }
    *actionsp = buf.data;
    *actions_lenp = buf.size;
}

static size_t
put_userspace_action(const struct ofproto_dpif *ofproto,
                     struct ofpbuf *odp_actions,
                     const struct flow *flow,
                     const union user_action_cookie *cookie)
{
    uint32_t pid;

    pid = dpif_port_get_pid(ofproto->dpif,
                            ofp_port_to_odp_port(flow->in_port));

    return odp_put_userspace_action(pid, cookie, odp_actions);
}

static void
compose_sflow_cookie(const struct ofproto_dpif *ofproto,
                     ovs_be16 vlan_tci, uint32_t odp_port,
                     unsigned int n_outputs, union user_action_cookie *cookie)
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
        ifindex = dpif_sflow_odp_port_to_ifindex(ofproto->sflow, odp_port);
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

/* Compose SAMPLE action for sFlow. */
static size_t
compose_sflow_action(const struct ofproto_dpif *ofproto,
                     struct ofpbuf *odp_actions,
                     const struct flow *flow,
                     uint32_t odp_port)
{
    uint32_t probability;
    union user_action_cookie cookie;
    size_t sample_offset, actions_offset;
    int cookie_offset;

    if (!ofproto->sflow || flow->in_port == OFPP_NONE) {
        return 0;
    }

    sample_offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_SAMPLE);

    /* Number of packets out of UINT_MAX to sample. */
    probability = dpif_sflow_get_probability(ofproto->sflow);
    nl_msg_put_u32(odp_actions, OVS_SAMPLE_ATTR_PROBABILITY, probability);

    actions_offset = nl_msg_start_nested(odp_actions, OVS_SAMPLE_ATTR_ACTIONS);
    compose_sflow_cookie(ofproto, htons(0), odp_port,
                         odp_port == OVSP_NONE ? 0 : 1, &cookie);
    cookie_offset = put_userspace_action(ofproto, odp_actions, flow, &cookie);

    nl_msg_end_nested(odp_actions, actions_offset);
    nl_msg_end_nested(odp_actions, sample_offset);
    return cookie_offset;
}

/* SAMPLE action must be first action in any given list of actions.
 * At this point we do not have all information required to build it. So try to
 * build sample action as complete as possible. */
static void
add_sflow_action(struct action_xlate_ctx *ctx)
{
    ctx->user_cookie_offset = compose_sflow_action(ctx->ofproto,
                                                   ctx->odp_actions,
                                                   &ctx->flow, OVSP_NONE);
    ctx->sflow_odp_port = 0;
    ctx->sflow_n_outputs = 0;
}

/* Fix SAMPLE action according to data collected while composing ODP actions.
 * We need to fix SAMPLE actions OVS_SAMPLE_ATTR_ACTIONS attribute, i.e. nested
 * USERSPACE action's user-cookie which is required for sflow. */
static void
fix_sflow_action(struct action_xlate_ctx *ctx)
{
    const struct flow *base = &ctx->base_flow;
    union user_action_cookie *cookie;

    if (!ctx->user_cookie_offset) {
        return;
    }

    cookie = ofpbuf_at(ctx->odp_actions, ctx->user_cookie_offset,
                       sizeof(*cookie));
    assert(cookie->type == USER_ACTION_COOKIE_SFLOW);

    compose_sflow_cookie(ctx->ofproto, base->vlan_tci,
                         ctx->sflow_odp_port, ctx->sflow_n_outputs, cookie);
}

static void
compose_output_action__(struct action_xlate_ctx *ctx, uint16_t ofp_port,
                        bool check_stp)
{
    const struct ofport_dpif *ofport = get_ofp_port(ctx->ofproto, ofp_port);
    uint16_t odp_port = ofp_port_to_odp_port(ofp_port);
    ovs_be16 flow_vlan_tci = ctx->flow.vlan_tci;
    uint8_t flow_nw_tos = ctx->flow.nw_tos;
    uint16_t out_port;

    if (ofport) {
        struct priority_to_dscp *pdscp;

        if (ofport->up.pp.config & OFPUTIL_PC_NO_FWD) {
            xlate_report(ctx, "OFPPC_NO_FWD set, skipping output");
            return;
        } else if (check_stp && !stp_forward_in_state(ofport->stp_state)) {
            xlate_report(ctx, "STP not in forwarding state, skipping output");
            return;
        }

        pdscp = get_priority(ofport, ctx->flow.skb_priority);
        if (pdscp) {
            ctx->flow.nw_tos &= ~IP_DSCP_MASK;
            ctx->flow.nw_tos |= pdscp->dscp;
        }
    } else {
        /* We may not have an ofport record for this port, but it doesn't hurt
         * to allow forwarding to it anyhow.  Maybe such a port will appear
         * later and we're pre-populating the flow table.  */
    }

    out_port = vsp_realdev_to_vlandev(ctx->ofproto, odp_port,
                                      ctx->flow.vlan_tci);
    if (out_port != odp_port) {
        ctx->flow.vlan_tci = htons(0);
    }
    commit_odp_actions(&ctx->flow, &ctx->base_flow, ctx->odp_actions);
    nl_msg_put_u32(ctx->odp_actions, OVS_ACTION_ATTR_OUTPUT, out_port);

    ctx->sflow_odp_port = odp_port;
    ctx->sflow_n_outputs++;
    ctx->nf_output_iface = ofp_port;
    ctx->flow.vlan_tci = flow_vlan_tci;
    ctx->flow.nw_tos = flow_nw_tos;
}

static void
compose_output_action(struct action_xlate_ctx *ctx, uint16_t ofp_port)
{
    compose_output_action__(ctx, ofp_port, true);
}

static void
xlate_table_action(struct action_xlate_ctx *ctx,
                   uint16_t in_port, uint8_t table_id, bool may_packet_in)
{
    if (ctx->recurse < MAX_RESUBMIT_RECURSION) {
        struct ofproto_dpif *ofproto = ctx->ofproto;
        struct rule_dpif *rule;
        uint16_t old_in_port;
        uint8_t old_table_id;

        old_table_id = ctx->table_id;
        ctx->table_id = table_id;

        /* Look up a flow with 'in_port' as the input port. */
        old_in_port = ctx->flow.in_port;
        ctx->flow.in_port = in_port;
        rule = rule_dpif_lookup__(ofproto, &ctx->flow, table_id);

        /* Tag the flow. */
        if (table_id > 0 && table_id < N_TABLES) {
            struct table_dpif *table = &ofproto->tables[table_id];
            if (table->other_table) {
                ctx->tags |= (rule && rule->tag
                              ? rule->tag
                              : rule_calculate_tag(&ctx->flow,
                                                   &table->other_table->mask,
                                                   table->basis));
            }
        }

        /* Restore the original input port.  Otherwise OFPP_NORMAL and
         * OFPP_IN_PORT will have surprising behavior. */
        ctx->flow.in_port = old_in_port;

        if (ctx->resubmit_hook) {
            ctx->resubmit_hook(ctx, rule);
        }

        if (rule == NULL && may_packet_in) {
            /* TODO:XXX
             * check if table configuration flags
             * OFPTC_TABLE_MISS_CONTROLLER, default.
             * OFPTC_TABLE_MISS_CONTINUE,
             * OFPTC_TABLE_MISS_DROP
             * When OF1.0, OFPTC_TABLE_MISS_CONTINUE is used. What to do?
             */
            rule = rule_dpif_miss_rule(ofproto, &ctx->flow);
        }

        if (rule) {
            struct rule_dpif *old_rule = ctx->rule;

            if (ctx->resubmit_stats) {
                rule_credit_stats(rule, ctx->resubmit_stats);
            }

            ctx->recurse++;
            ctx->rule = rule;
            do_xlate_actions(rule->up.ofpacts, rule->up.ofpacts_len, ctx);
            ctx->rule = old_rule;
            ctx->recurse--;
        }

        ctx->table_id = old_table_id;
    } else {
        static struct vlog_rate_limit recurse_rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&recurse_rl, "resubmit actions recursed over %d times",
                    MAX_RESUBMIT_RECURSION);
        ctx->max_resubmit_trigger = true;
    }
}

static void
xlate_ofpact_resubmit(struct action_xlate_ctx *ctx,
                      const struct ofpact_resubmit *resubmit)
{
    uint16_t in_port;
    uint8_t table_id;

    in_port = resubmit->in_port;
    if (in_port == OFPP_IN_PORT) {
        in_port = ctx->flow.in_port;
    }

    table_id = resubmit->table_id;
    if (table_id == 255) {
        table_id = ctx->table_id;
    }

    xlate_table_action(ctx, in_port, table_id, false);
}

static void
flood_packets(struct action_xlate_ctx *ctx, bool all)
{
    struct ofport_dpif *ofport;

    HMAP_FOR_EACH (ofport, up.hmap_node, &ctx->ofproto->up.ports) {
        uint16_t ofp_port = ofport->up.ofp_port;

        if (ofp_port == ctx->flow.in_port) {
            continue;
        }

        if (all) {
            compose_output_action__(ctx, ofp_port, false);
        } else if (!(ofport->up.pp.config & OFPUTIL_PC_NO_FLOOD)) {
            compose_output_action(ctx, ofp_port);
        }
    }

    ctx->nf_output_iface = NF_OUT_FLOOD;
}

static void
execute_controller_action(struct action_xlate_ctx *ctx, int len,
                          enum ofp_packet_in_reason reason,
                          uint16_t controller_id)
{
    struct ofputil_packet_in pin;
    struct ofpbuf *packet;

    ctx->slow |= SLOW_CONTROLLER;
    if (!ctx->packet) {
        return;
    }

    packet = ofpbuf_clone(ctx->packet);

    if (packet->l2 && packet->l3) {
        struct eth_header *eh;

        eth_pop_vlan(packet);
        eh = packet->l2;

        /* If the Ethernet type is less than ETH_TYPE_MIN, it's likely an 802.2
         * LLC frame.  Calculating the Ethernet type of these frames is more
         * trouble than seems appropriate for a simple assertion. */
        assert(ntohs(eh->eth_type) < ETH_TYPE_MIN
               || eh->eth_type == ctx->flow.dl_type);

        memcpy(eh->eth_src, ctx->flow.dl_src, sizeof eh->eth_src);
        memcpy(eh->eth_dst, ctx->flow.dl_dst, sizeof eh->eth_dst);

        if (ctx->flow.vlan_tci & htons(VLAN_CFI)) {
            eth_push_vlan(packet, ctx->flow.vlan_tci);
        }

        if (packet->l4) {
            if (ctx->flow.dl_type == htons(ETH_TYPE_IP)) {
                packet_set_ipv4(packet, ctx->flow.nw_src, ctx->flow.nw_dst,
                                ctx->flow.nw_tos, ctx->flow.nw_ttl);
            }

            if (packet->l7) {
                if (ctx->flow.nw_proto == IPPROTO_TCP) {
                    packet_set_tcp_port(packet, ctx->flow.tp_src,
                                        ctx->flow.tp_dst);
                } else if (ctx->flow.nw_proto == IPPROTO_UDP) {
                    packet_set_udp_port(packet, ctx->flow.tp_src,
                                        ctx->flow.tp_dst);
                }
            }
        }
    }

    pin.packet = packet->data;
    pin.packet_len = packet->size;
    pin.reason = reason;
    pin.controller_id = controller_id;
    pin.table_id = ctx->table_id;
    pin.cookie = ctx->rule ? ctx->rule->up.flow_cookie : 0;

    pin.send_len = len;
    flow_get_metadata(&ctx->flow, &pin.fmd);

    connmgr_send_packet_in(ctx->ofproto->up.connmgr, &pin);
    ofpbuf_delete(packet);
}

static bool
compose_dec_ttl(struct action_xlate_ctx *ctx, struct ofpact_cnt_ids *ids)
{
    if (ctx->flow.dl_type != htons(ETH_TYPE_IP) &&
        ctx->flow.dl_type != htons(ETH_TYPE_IPV6)) {
        return false;
    }

    if (ctx->flow.nw_ttl > 1) {
        ctx->flow.nw_ttl--;
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

static void
xlate_output_action(struct action_xlate_ctx *ctx,
                    uint16_t port, uint16_t max_len, bool may_packet_in)
{
    uint16_t prev_nf_output_iface = ctx->nf_output_iface;

    ctx->nf_output_iface = NF_OUT_DROP;

    switch (port) {
    case OFPP_IN_PORT:
        compose_output_action(ctx, ctx->flow.in_port);
        break;
    case OFPP_TABLE:
        xlate_table_action(ctx, ctx->flow.in_port, 0, may_packet_in);
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
        if (port != ctx->flow.in_port) {
            compose_output_action(ctx, port);
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
xlate_output_reg_action(struct action_xlate_ctx *ctx,
                        const struct ofpact_output_reg *or)
{
    uint64_t port = mf_get_subfield(&or->src, &ctx->flow);
    if (port <= UINT16_MAX) {
        xlate_output_action(ctx, port, or->max_len, false);
    }
}

static void
xlate_enqueue_action(struct action_xlate_ctx *ctx,
                     const struct ofpact_enqueue *enqueue)
{
    uint16_t ofp_port = enqueue->port;
    uint32_t queue_id = enqueue->queue;
    uint32_t flow_priority, priority;
    int error;

    /* Translate queue to priority. */
    error = dpif_queue_to_priority(ctx->ofproto->dpif, queue_id, &priority);
    if (error) {
        /* Fall back to ordinary output action. */
        xlate_output_action(ctx, enqueue->port, 0, false);
        return;
    }

    /* Check output port. */
    if (ofp_port == OFPP_IN_PORT) {
        ofp_port = ctx->flow.in_port;
    } else if (ofp_port == ctx->flow.in_port) {
        return;
    }

    /* Add datapath actions. */
    flow_priority = ctx->flow.skb_priority;
    ctx->flow.skb_priority = priority;
    compose_output_action(ctx, ofp_port);
    ctx->flow.skb_priority = flow_priority;

    /* Update NetFlow output port. */
    if (ctx->nf_output_iface == NF_OUT_DROP) {
        ctx->nf_output_iface = ofp_port;
    } else if (ctx->nf_output_iface != NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_MULTI;
    }
}

static void
xlate_set_queue_action(struct action_xlate_ctx *ctx, uint32_t queue_id)
{
    uint32_t skb_priority;

    if (!dpif_queue_to_priority(ctx->ofproto->dpif, queue_id, &skb_priority)) {
        ctx->flow.skb_priority = skb_priority;
    } else {
        /* Couldn't translate queue to a priority.  Nothing to do.  A warning
         * has already been logged. */
    }
}

struct xlate_reg_state {
    ovs_be16 vlan_tci;
    ovs_be64 tun_id;
};

static void
xlate_autopath(struct action_xlate_ctx *ctx,
               const struct ofpact_autopath *ap)
{
    uint16_t ofp_port = ap->port;
    struct ofport_dpif *port = get_ofp_port(ctx->ofproto, ofp_port);

    if (!port || !port->bundle) {
        ofp_port = OFPP_NONE;
    } else if (port->bundle->bond) {
        /* Autopath does not support VLAN hashing. */
        struct ofport_dpif *slave = bond_choose_output_slave(
            port->bundle->bond, &ctx->flow, 0, &ctx->tags);
        if (slave) {
            ofp_port = slave->up.ofp_port;
        }
    }
    nxm_reg_load(&ap->dst, ofp_port, &ctx->flow);
}

static bool
slave_enabled_cb(uint16_t ofp_port, void *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_;
    struct ofport_dpif *port;

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
        port = get_ofp_port(ofproto, ofp_port);
        return port ? port->may_enable : false;
    }
}

static void
xlate_bundle_action(struct action_xlate_ctx *ctx,
                    const struct ofpact_bundle *bundle)
{
    uint16_t port;

    port = bundle_execute(bundle, &ctx->flow, slave_enabled_cb, ctx->ofproto);
    if (bundle->dst.field) {
        nxm_reg_load(&bundle->dst, port, &ctx->flow);
    } else {
        xlate_output_action(ctx, port, 0, false);
    }
}

static void
xlate_learn_action(struct action_xlate_ctx *ctx,
                   const struct ofpact_learn *learn)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    struct ofputil_flow_mod fm;
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts;
    int error;

    ofpbuf_use_stack(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    learn_execute(learn, &ctx->flow, &fm, &ofpacts);

    error = ofproto_flow_mod(&ctx->ofproto->up, &fm);
    if (error && !VLOG_DROP_WARN(&rl)) {
        VLOG_WARN("learning action failed to modify flow table (%s)",
                  ofperr_get_name(error));
    }

    ofpbuf_uninit(&ofpacts);
}

/* Reduces '*timeout' to no more than 'max'.  A value of zero in either case
 * means "infinite". */
static void
reduce_timeout(uint16_t max, uint16_t *timeout)
{
    if (max && (!*timeout || *timeout > max)) {
        *timeout = max;
    }
}

static void
xlate_fin_timeout(struct action_xlate_ctx *ctx,
                  const struct ofpact_fin_timeout *oft)
{
    if (ctx->tcp_flags & (TCP_FIN | TCP_RST) && ctx->rule) {
        struct rule_dpif *rule = ctx->rule;

        reduce_timeout(oft->fin_idle_timeout, &rule->up.idle_timeout);
        reduce_timeout(oft->fin_hard_timeout, &rule->up.hard_timeout);
    }
}

static bool
may_receive(const struct ofport_dpif *port, struct action_xlate_ctx *ctx)
{
    if (port->up.pp.config & (eth_addr_equals(ctx->flow.dl_dst, eth_addr_stp)
                              ? OFPUTIL_PC_NO_RECV_STP
                              : OFPUTIL_PC_NO_RECV)) {
        return false;
    }

    /* Only drop packets here if both forwarding and learning are
     * disabled.  If just learning is enabled, we need to have
     * OFPP_NORMAL and the learning action have a look at the packet
     * before we can drop it. */
    if (!stp_forward_in_state(port->stp_state)
            && !stp_learn_in_state(port->stp_state)) {
        return false;
    }

    return true;
}

static void
do_xlate_actions(const struct ofpact *ofpacts, size_t ofpacts_len,
                 struct action_xlate_ctx *ctx)
{
    const struct ofport_dpif *port;
    bool was_evictable = true;
    const struct ofpact *a;

    port = get_ofp_port(ctx->ofproto, ctx->flow.in_port);
    if (port && !may_receive(port, ctx)) {
        /* Drop this flow. */
        return;
    }

    if (ctx->rule) {
        /* Don't let the rule we're working on get evicted underneath us. */
        was_evictable = ctx->rule->up.evictable;
        ctx->rule->up.evictable = false;
    }
    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        struct ofpact_controller *controller;
        const struct ofpact_metadata *metadata;

        if (ctx->exit) {
            break;
        }

        switch (a->type) {
        case OFPACT_OUTPUT:
            xlate_output_action(ctx, ofpact_get_OUTPUT(a)->port,
                                ofpact_get_OUTPUT(a)->max_len, true);
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
            ctx->flow.vlan_tci &= ~htons(VLAN_VID_MASK);
            ctx->flow.vlan_tci |= (htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid)
                                   | htons(VLAN_CFI));
            break;

        case OFPACT_SET_VLAN_PCP:
            ctx->flow.vlan_tci &= ~htons(VLAN_PCP_MASK);
            ctx->flow.vlan_tci |= htons((ofpact_get_SET_VLAN_PCP(a)->vlan_pcp
                                         << VLAN_PCP_SHIFT)
                                        | VLAN_CFI);
            break;

        case OFPACT_STRIP_VLAN:
            ctx->flow.vlan_tci = htons(0);
            break;

        case OFPACT_SET_ETH_SRC:
            memcpy(ctx->flow.dl_src, ofpact_get_SET_ETH_SRC(a)->mac,
                   ETH_ADDR_LEN);
            break;

        case OFPACT_SET_ETH_DST:
            memcpy(ctx->flow.dl_dst, ofpact_get_SET_ETH_DST(a)->mac,
                   ETH_ADDR_LEN);
            break;

        case OFPACT_SET_IPV4_SRC:
            ctx->flow.nw_src = ofpact_get_SET_IPV4_SRC(a)->ipv4;
            break;

        case OFPACT_SET_IPV4_DST:
            ctx->flow.nw_dst = ofpact_get_SET_IPV4_DST(a)->ipv4;
            break;

        case OFPACT_SET_IPV4_DSCP:
            /* OpenFlow 1.0 only supports IPv4. */
            if (ctx->flow.dl_type == htons(ETH_TYPE_IP)) {
                ctx->flow.nw_tos &= ~IP_DSCP_MASK;
                ctx->flow.nw_tos |= ofpact_get_SET_IPV4_DSCP(a)->dscp;
            }
            break;

        case OFPACT_SET_L4_SRC_PORT:
            ctx->flow.tp_src = htons(ofpact_get_SET_L4_SRC_PORT(a)->port);
            break;

        case OFPACT_SET_L4_DST_PORT:
            ctx->flow.tp_dst = htons(ofpact_get_SET_L4_DST_PORT(a)->port);
            break;

        case OFPACT_RESUBMIT:
            xlate_ofpact_resubmit(ctx, ofpact_get_RESUBMIT(a));
            break;

        case OFPACT_SET_TUNNEL:
            ctx->flow.tunnel.tun_id = htonll(ofpact_get_SET_TUNNEL(a)->tun_id);
            break;

        case OFPACT_SET_QUEUE:
            xlate_set_queue_action(ctx, ofpact_get_SET_QUEUE(a)->queue_id);
            break;

        case OFPACT_POP_QUEUE:
            ctx->flow.skb_priority = ctx->orig_skb_priority;
            break;

        case OFPACT_REG_MOVE:
            nxm_execute_reg_move(ofpact_get_REG_MOVE(a), &ctx->flow);
            break;

        case OFPACT_REG_LOAD:
            nxm_execute_reg_load(ofpact_get_REG_LOAD(a), &ctx->flow);
            break;

        case OFPACT_DEC_TTL:
            if (compose_dec_ttl(ctx, ofpact_get_DEC_TTL(a))) {
                goto out;
            }
            break;

        case OFPACT_NOTE:
            /* Nothing to do. */
            break;

        case OFPACT_MULTIPATH:
            multipath_execute(ofpact_get_MULTIPATH(a), &ctx->flow);
            break;

        case OFPACT_AUTOPATH:
            xlate_autopath(ctx, ofpact_get_AUTOPATH(a));
            break;

        case OFPACT_BUNDLE:
            ctx->ofproto->has_bundle_action = true;
            xlate_bundle_action(ctx, ofpact_get_BUNDLE(a));
            break;

        case OFPACT_OUTPUT_REG:
            xlate_output_reg_action(ctx, ofpact_get_OUTPUT_REG(a));
            break;

        case OFPACT_LEARN:
            ctx->has_learn = true;
            if (ctx->may_learn) {
                xlate_learn_action(ctx, ofpact_get_LEARN(a));
            }
            break;

        case OFPACT_EXIT:
            ctx->exit = true;
            break;

        case OFPACT_FIN_TIMEOUT:
            ctx->has_fin_timeout = true;
            xlate_fin_timeout(ctx, ofpact_get_FIN_TIMEOUT(a));
            break;

        case OFPACT_CLEAR_ACTIONS:
            /* TODO:XXX
             * Nothing to do because writa-actions is not supported for now.
             * When writa-actions is supported, clear-actions also must
             * be supported at the same time.
             */
            break;

        case OFPACT_WRITE_METADATA:
            metadata = ofpact_get_WRITE_METADATA(a);
            ctx->flow.metadata &= ~metadata->mask;
            ctx->flow.metadata |= metadata->metadata & metadata->mask;
            break;

        case OFPACT_GOTO_TABLE: {
            /* TODO:XXX remove recursion */
            /* It is assumed that goto-table is last action */
            struct ofpact_goto_table *ogt = ofpact_get_GOTO_TABLE(a);
            assert(ctx->table_id < ogt->table_id);
            xlate_table_action(ctx, ctx->flow.in_port, ogt->table_id, true);
            break;
        }
        }
    }

out:
    /* We've let OFPP_NORMAL and the learning action look at the packet,
     * so drop it now if forwarding is disabled. */
    if (port && !stp_forward_in_state(port->stp_state)) {
        ofpbuf_clear(ctx->odp_actions);
        add_sflow_action(ctx);
    }
    if (ctx->rule) {
        ctx->rule->up.evictable = was_evictable;
    }
}

static void
action_xlate_ctx_init(struct action_xlate_ctx *ctx,
                      struct ofproto_dpif *ofproto, const struct flow *flow,
                      ovs_be16 initial_tci, struct rule_dpif *rule,
                      uint8_t tcp_flags, const struct ofpbuf *packet)
{
    ctx->ofproto = ofproto;
    ctx->flow = *flow;
    ctx->base_flow = ctx->flow;
    memset(&ctx->base_flow.tunnel, 0, sizeof ctx->base_flow.tunnel);
    ctx->base_flow.vlan_tci = initial_tci;
    ctx->rule = rule;
    ctx->packet = packet;
    ctx->may_learn = packet != NULL;
    ctx->tcp_flags = tcp_flags;
    ctx->resubmit_hook = NULL;
    ctx->report_hook = NULL;
    ctx->resubmit_stats = NULL;
}

/* Translates the 'ofpacts_len' bytes of "struct ofpacts" starting at 'ofpacts'
 * into datapath actions in 'odp_actions', using 'ctx'. */
static void
xlate_actions(struct action_xlate_ctx *ctx,
              const struct ofpact *ofpacts, size_t ofpacts_len,
              struct ofpbuf *odp_actions)
{
    /* Normally false.  Set to true if we ever hit MAX_RESUBMIT_RECURSION, so
     * that in the future we always keep a copy of the original flow for
     * tracing purposes. */
    static bool hit_resubmit_limit;

    enum slow_path_reason special;

    COVERAGE_INC(ofproto_dpif_xlate);

    ofpbuf_clear(odp_actions);
    ofpbuf_reserve(odp_actions, NL_A_U32_SIZE);

    ctx->odp_actions = odp_actions;
    ctx->tags = 0;
    ctx->slow = 0;
    ctx->has_learn = false;
    ctx->has_normal = false;
    ctx->has_fin_timeout = false;
    ctx->nf_output_iface = NF_OUT_DROP;
    ctx->mirrors = 0;
    ctx->recurse = 0;
    ctx->max_resubmit_trigger = false;
    ctx->orig_skb_priority = ctx->flow.skb_priority;
    ctx->table_id = 0;
    ctx->exit = false;

    if (ctx->ofproto->has_mirrors || hit_resubmit_limit) {
        /* Do this conditionally because the copy is expensive enough that it
         * shows up in profiles.
         *
         * We keep orig_flow in 'ctx' only because I couldn't make GCC 4.4
         * believe that I wasn't using it without initializing it if I kept it
         * in a local variable. */
        ctx->orig_flow = ctx->flow;
    }

    if (ctx->flow.nw_frag & FLOW_NW_FRAG_ANY) {
        switch (ctx->ofproto->up.frag_handling) {
        case OFPC_FRAG_NORMAL:
            /* We must pretend that transport ports are unavailable. */
            ctx->flow.tp_src = ctx->base_flow.tp_src = htons(0);
            ctx->flow.tp_dst = ctx->base_flow.tp_dst = htons(0);
            break;

        case OFPC_FRAG_DROP:
            return;

        case OFPC_FRAG_REASM:
            NOT_REACHED();

        case OFPC_FRAG_NX_MATCH:
            /* Nothing to do. */
            break;

        case OFPC_INVALID_TTL_TO_CONTROLLER:
            NOT_REACHED();
        }
    }

    special = process_special(ctx->ofproto, &ctx->flow, ctx->packet);
    if (special) {
        ctx->slow |= special;
    } else {
        static struct vlog_rate_limit trace_rl = VLOG_RATE_LIMIT_INIT(1, 1);
        ovs_be16 initial_tci = ctx->base_flow.vlan_tci;

        add_sflow_action(ctx);
        do_xlate_actions(ofpacts, ofpacts_len, ctx);

        if (ctx->max_resubmit_trigger && !ctx->resubmit_hook) {
            if (!hit_resubmit_limit) {
                /* We didn't record the original flow.  Make sure we do from
                 * now on. */
                hit_resubmit_limit = true;
            } else if (!VLOG_DROP_ERR(&trace_rl)) {
                struct ds ds = DS_EMPTY_INITIALIZER;

                ofproto_trace(ctx->ofproto, &ctx->orig_flow, ctx->packet,
                              initial_tci, &ds);
                VLOG_ERR("Trace triggered by excessive resubmit "
                         "recursion:\n%s", ds_cstr(&ds));
                ds_destroy(&ds);
            }
        }

        if (!connmgr_may_set_up_flow(ctx->ofproto->up.connmgr, &ctx->flow,
                                     ctx->odp_actions->data,
                                     ctx->odp_actions->size)) {
            ctx->slow |= SLOW_IN_BAND;
            if (ctx->packet
                && connmgr_msg_in_hook(ctx->ofproto->up.connmgr, &ctx->flow,
                                       ctx->packet)) {
                compose_output_action(ctx, OFPP_LOCAL);
            }
        }
        if (ctx->ofproto->has_mirrors) {
            add_mirror_actions(ctx, &ctx->orig_flow);
        }
        fix_sflow_action(ctx);
    }
}

/* Translates the 'ofpacts_len' bytes of "struct ofpact"s starting at 'ofpacts'
 * into datapath actions, using 'ctx', and discards the datapath actions. */
static void
xlate_actions_for_side_effects(struct action_xlate_ctx *ctx,
                               const struct ofpact *ofpacts,
                               size_t ofpacts_len)
{
    uint64_t odp_actions_stub[1024 / 8];
    struct ofpbuf odp_actions;

    ofpbuf_use_stub(&odp_actions, odp_actions_stub, sizeof odp_actions_stub);
    xlate_actions(ctx, ofpacts, ofpacts_len, &odp_actions);
    ofpbuf_uninit(&odp_actions);
}

static void
xlate_report(struct action_xlate_ctx *ctx, const char *s)
{
    if (ctx->report_hook) {
        ctx->report_hook(ctx, s);
    }
}

/* OFPP_NORMAL implementation. */

static struct ofport_dpif *ofbundle_get_a_port(const struct ofbundle *);

/* Given 'vid', the VID obtained from the 802.1Q header that was received as
 * part of a packet (specify 0 if there was no 802.1Q header), and 'in_bundle',
 * the bundle on which the packet was received, returns the VLAN to which the
 * packet belongs.
 *
 * Both 'vid' and the return value are in the range 0...4095. */
static uint16_t
input_vid_to_vlan(const struct ofbundle *in_bundle, uint16_t vid)
{
    switch (in_bundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        return in_bundle->vlan;
        break;

    case PORT_VLAN_TRUNK:
        return vid;

    case PORT_VLAN_NATIVE_UNTAGGED:
    case PORT_VLAN_NATIVE_TAGGED:
        return vid ? vid : in_bundle->vlan;

    default:
        NOT_REACHED();
    }
}

/* Checks whether a packet with the given 'vid' may ingress on 'in_bundle'.
 * If so, returns true.  Otherwise, returns false and, if 'warn' is true, logs
 * a warning.
 *
 * 'vid' should be the VID obtained from the 802.1Q header that was received as
 * part of a packet (specify 0 if there was no 802.1Q header), in the range
 * 0...4095. */
static bool
input_vid_is_valid(uint16_t vid, struct ofbundle *in_bundle, bool warn)
{
    /* Allow any VID on the OFPP_NONE port. */
    if (in_bundle == &ofpp_none_bundle) {
        return true;
    }

    switch (in_bundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        if (vid) {
            if (warn) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "bridge %s: dropping VLAN %"PRIu16" tagged "
                             "packet received on port %s configured as VLAN "
                             "%"PRIu16" access port",
                             in_bundle->ofproto->up.name, vid,
                             in_bundle->name, in_bundle->vlan);
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
        if (!ofbundle_includes_vlan(in_bundle, vid)) {
            if (warn) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "bridge %s: dropping VLAN %"PRIu16" packet "
                             "received on port %s not configured for trunking "
                             "VLAN %"PRIu16,
                             in_bundle->ofproto->up.name, vid,
                             in_bundle->name, vid);
            }
            return false;
        }
        return true;

    default:
        NOT_REACHED();
    }

}

/* Given 'vlan', the VLAN that a packet belongs to, and
 * 'out_bundle', a bundle on which the packet is to be output, returns the VID
 * that should be included in the 802.1Q header.  (If the return value is 0,
 * then the 802.1Q header should only be included in the packet if there is a
 * nonzero PCP.)
 *
 * Both 'vlan' and the return value are in the range 0...4095. */
static uint16_t
output_vlan_to_vid(const struct ofbundle *out_bundle, uint16_t vlan)
{
    switch (out_bundle->vlan_mode) {
    case PORT_VLAN_ACCESS:
        return 0;

    case PORT_VLAN_TRUNK:
    case PORT_VLAN_NATIVE_TAGGED:
        return vlan;

    case PORT_VLAN_NATIVE_UNTAGGED:
        return vlan == out_bundle->vlan ? 0 : vlan;

    default:
        NOT_REACHED();
    }
}

static void
output_normal(struct action_xlate_ctx *ctx, const struct ofbundle *out_bundle,
              uint16_t vlan)
{
    struct ofport_dpif *port;
    uint16_t vid;
    ovs_be16 tci, old_tci;

    vid = output_vlan_to_vid(out_bundle, vlan);
    if (!out_bundle->bond) {
        port = ofbundle_get_a_port(out_bundle);
    } else {
        port = bond_choose_output_slave(out_bundle->bond, &ctx->flow,
                                        vid, &ctx->tags);
        if (!port) {
            /* No slaves enabled, so drop packet. */
            return;
        }
    }

    old_tci = ctx->flow.vlan_tci;
    tci = htons(vid);
    if (tci || out_bundle->use_priority_tags) {
        tci |= ctx->flow.vlan_tci & htons(VLAN_PCP_MASK);
        if (tci) {
            tci |= htons(VLAN_CFI);
        }
    }
    ctx->flow.vlan_tci = tci;

    compose_output_action(ctx, port->up.ofp_port);
    ctx->flow.vlan_tci = old_tci;
}

static int
mirror_mask_ffs(mirror_mask_t mask)
{
    BUILD_ASSERT_DECL(sizeof(unsigned int) >= sizeof(mask));
    return ffs(mask);
}

static bool
ofbundle_trunks_vlan(const struct ofbundle *bundle, uint16_t vlan)
{
    return (bundle->vlan_mode != PORT_VLAN_ACCESS
            && (!bundle->trunks || bitmap_is_set(bundle->trunks, vlan)));
}

static bool
ofbundle_includes_vlan(const struct ofbundle *bundle, uint16_t vlan)
{
    return vlan == bundle->vlan || ofbundle_trunks_vlan(bundle, vlan);
}

/* Returns an arbitrary interface within 'bundle'. */
static struct ofport_dpif *
ofbundle_get_a_port(const struct ofbundle *bundle)
{
    return CONTAINER_OF(list_front(&bundle->ports),
                        struct ofport_dpif, bundle_node);
}

static bool
vlan_is_mirrored(const struct ofmirror *m, int vlan)
{
    return !m->vlans || bitmap_is_set(m->vlans, vlan);
}

static void
add_mirror_actions(struct action_xlate_ctx *ctx, const struct flow *orig_flow)
{
    struct ofproto_dpif *ofproto = ctx->ofproto;
    mirror_mask_t mirrors;
    struct ofbundle *in_bundle;
    uint16_t vlan;
    uint16_t vid;
    const struct nlattr *a;
    size_t left;

    in_bundle = lookup_input_bundle(ctx->ofproto, orig_flow->in_port,
                                    ctx->packet != NULL, NULL);
    if (!in_bundle) {
        return;
    }
    mirrors = in_bundle->src_mirrors;

    /* Drop frames on bundles reserved for mirroring. */
    if (in_bundle->mirror_out) {
        if (ctx->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port "
                         "%s, which is reserved exclusively for mirroring",
                         ctx->ofproto->up.name, in_bundle->name);
        }
        return;
    }

    /* Check VLAN. */
    vid = vlan_tci_to_vid(orig_flow->vlan_tci);
    if (!input_vid_is_valid(vid, in_bundle, ctx->packet != NULL)) {
        return;
    }
    vlan = input_vid_to_vlan(in_bundle, vid);

    /* Look at the output ports to check for destination selections. */

    NL_ATTR_FOR_EACH (a, left, ctx->odp_actions->data,
                      ctx->odp_actions->size) {
        enum ovs_action_attr type = nl_attr_type(a);
        struct ofport_dpif *ofport;

        if (type != OVS_ACTION_ATTR_OUTPUT) {
            continue;
        }

        ofport = get_odp_port(ofproto, nl_attr_get_u32(a));
        if (ofport && ofport->bundle) {
            mirrors |= ofport->bundle->dst_mirrors;
        }
    }

    if (!mirrors) {
        return;
    }

    /* Restore the original packet before adding the mirror actions. */
    ctx->flow = *orig_flow;

    while (mirrors) {
        struct ofmirror *m;

        m = ofproto->mirrors[mirror_mask_ffs(mirrors) - 1];

        if (!vlan_is_mirrored(m, vlan)) {
            mirrors = zero_rightmost_1bit(mirrors);
            continue;
        }

        mirrors &= ~m->dup_mirrors;
        ctx->mirrors |= m->dup_mirrors;
        if (m->out) {
            output_normal(ctx, m->out, vlan);
        } else if (vlan != m->out_vlan
                   && !eth_addr_is_reserved(orig_flow->dl_dst)) {
            struct ofbundle *bundle;

            HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {
                if (ofbundle_includes_vlan(bundle, m->out_vlan)
                    && !bundle->mirror_out) {
                    output_normal(ctx, bundle, m->out_vlan);
                }
            }
        }
    }
}

static void
update_mirror_stats(struct ofproto_dpif *ofproto, mirror_mask_t mirrors,
                    uint64_t packets, uint64_t bytes)
{
    if (!mirrors) {
        return;
    }

    for (; mirrors; mirrors = zero_rightmost_1bit(mirrors)) {
        struct ofmirror *m;

        m = ofproto->mirrors[mirror_mask_ffs(mirrors) - 1];

        if (!m) {
            /* In normal circumstances 'm' will not be NULL.  However,
             * if mirrors are reconfigured, we can temporarily get out
             * of sync in facet_revalidate().  We could "correct" the
             * mirror list before reaching here, but doing that would
             * not properly account the traffic stats we've currently
             * accumulated for previous mirror configuration. */
            continue;
        }

        m->packet_count += packets;
        m->byte_count += bytes;
    }
}

/* A VM broadcasts a gratuitous ARP to indicate that it has resumed after
 * migration.  Older Citrix-patched Linux DomU used gratuitous ARP replies to
 * indicate this; newer upstream kernels use gratuitous ARP requests. */
static bool
is_gratuitous_arp(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_ARP)
            && eth_addr_is_broadcast(flow->dl_dst)
            && (flow->nw_proto == ARP_OP_REPLY
                || (flow->nw_proto == ARP_OP_REQUEST
                    && flow->nw_src == flow->nw_dst)));
}

static void
update_learning_table(struct ofproto_dpif *ofproto,
                      const struct flow *flow, int vlan,
                      struct ofbundle *in_bundle)
{
    struct mac_entry *mac;

    /* Don't learn the OFPP_NONE port. */
    if (in_bundle == &ofpp_none_bundle) {
        return;
    }

    if (!mac_learning_may_learn(ofproto->ml, flow->dl_src, vlan)) {
        return;
    }

    mac = mac_learning_insert(ofproto->ml, flow->dl_src, vlan);
    if (is_gratuitous_arp(flow)) {
        /* We don't want to learn from gratuitous ARP packets that are
         * reflected back over bond slaves so we lock the learning table. */
        if (!in_bundle->bond) {
            mac_entry_set_grat_arp_lock(mac);
        } else if (mac_entry_is_grat_arp_locked(mac)) {
            return;
        }
    }

    if (mac_entry_is_new(mac) || mac->port.p != in_bundle) {
        /* The log messages here could actually be useful in debugging,
         * so keep the rate limit relatively high. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
        VLOG_DBG_RL(&rl, "bridge %s: learned that "ETH_ADDR_FMT" is "
                    "on port %s in VLAN %d",
                    ofproto->up.name, ETH_ADDR_ARGS(flow->dl_src),
                    in_bundle->name, vlan);

        mac->port.p = in_bundle;
        tag_set_add(&ofproto->revalidate_set,
                    mac_learning_changed(ofproto->ml, mac));
    }
}

static struct ofbundle *
lookup_input_bundle(const struct ofproto_dpif *ofproto, uint16_t in_port,
                    bool warn, struct ofport_dpif **in_ofportp)
{
    struct ofport_dpif *ofport;

    /* Find the port and bundle for the received packet. */
    ofport = get_ofp_port(ofproto, in_port);
    if (in_ofportp) {
        *in_ofportp = ofport;
    }
    if (ofport && ofport->bundle) {
        return ofport->bundle;
    }

    /* Special-case OFPP_NONE, which a controller may use as the ingress
     * port for traffic that it is sourcing. */
    if (in_port == OFPP_NONE) {
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
                     "port %"PRIu16, ofproto->up.name, in_port);
    }
    return NULL;
}

/* Determines whether packets in 'flow' within 'ofproto' should be forwarded or
 * dropped.  Returns true if they may be forwarded, false if they should be
 * dropped.
 *
 * 'in_port' must be the ofport_dpif that corresponds to flow->in_port.
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
is_admissible(struct action_xlate_ctx *ctx, struct ofport_dpif *in_port,
              uint16_t vlan)
{
    struct ofproto_dpif *ofproto = ctx->ofproto;
    struct flow *flow = &ctx->flow;
    struct ofbundle *in_bundle = in_port->bundle;

    /* Drop frames for reserved multicast addresses
     * only if forward_bpdu option is absent. */
    if (!ofproto->up.forward_bpdu && eth_addr_is_reserved(flow->dl_dst)) {
        xlate_report(ctx, "packet has reserved destination MAC, dropping");
        return false;
    }

    if (in_bundle->bond) {
        struct mac_entry *mac;

        switch (bond_check_admissibility(in_bundle->bond, in_port,
                                         flow->dl_dst, &ctx->tags)) {
        case BV_ACCEPT:
            break;

        case BV_DROP:
            xlate_report(ctx, "bonding refused admissibility, dropping");
            return false;

        case BV_DROP_IF_MOVED:
            mac = mac_learning_lookup(ofproto->ml, flow->dl_src, vlan, NULL);
            if (mac && mac->port.p != in_bundle &&
                (!is_gratuitous_arp(flow)
                 || mac_entry_is_grat_arp_locked(mac))) {
                xlate_report(ctx, "SLB bond thinks this packet looped back, "
                            "dropping");
                return false;
            }
            break;
        }
    }

    return true;
}

static void
xlate_normal(struct action_xlate_ctx *ctx)
{
    struct ofport_dpif *in_port;
    struct ofbundle *in_bundle;
    struct mac_entry *mac;
    uint16_t vlan;
    uint16_t vid;

    ctx->has_normal = true;

    in_bundle = lookup_input_bundle(ctx->ofproto, ctx->flow.in_port,
                                    ctx->packet != NULL, &in_port);
    if (!in_bundle) {
        xlate_report(ctx, "no input bundle, dropping");
        return;
    }

    /* Drop malformed frames. */
    if (ctx->flow.dl_type == htons(ETH_TYPE_VLAN) &&
        !(ctx->flow.vlan_tci & htons(VLAN_CFI))) {
        if (ctx->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet with partial "
                         "VLAN tag received on port %s",
                         ctx->ofproto->up.name, in_bundle->name);
        }
        xlate_report(ctx, "partial VLAN tag, dropping");
        return;
    }

    /* Drop frames on bundles reserved for mirroring. */
    if (in_bundle->mirror_out) {
        if (ctx->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port "
                         "%s, which is reserved exclusively for mirroring",
                         ctx->ofproto->up.name, in_bundle->name);
        }
        xlate_report(ctx, "input port is mirror output port, dropping");
        return;
    }

    /* Check VLAN. */
    vid = vlan_tci_to_vid(ctx->flow.vlan_tci);
    if (!input_vid_is_valid(vid, in_bundle, ctx->packet != NULL)) {
        xlate_report(ctx, "disallowed VLAN VID for this input port, dropping");
        return;
    }
    vlan = input_vid_to_vlan(in_bundle, vid);

    /* Check other admissibility requirements. */
    if (in_port && !is_admissible(ctx, in_port, vlan)) {
        return;
    }

    /* Learn source MAC. */
    if (ctx->may_learn) {
        update_learning_table(ctx->ofproto, &ctx->flow, vlan, in_bundle);
    }

    /* Determine output bundle. */
    mac = mac_learning_lookup(ctx->ofproto->ml, ctx->flow.dl_dst, vlan,
                              &ctx->tags);
    if (mac) {
        if (mac->port.p != in_bundle) {
            xlate_report(ctx, "forwarding to learned port");
            output_normal(ctx, mac->port.p, vlan);
        } else {
            xlate_report(ctx, "learned port is input port, dropping");
        }
    } else {
        struct ofbundle *bundle;

        xlate_report(ctx, "no learned MAC for destination, flooding");
        HMAP_FOR_EACH (bundle, hmap_node, &ctx->ofproto->bundles) {
            if (bundle != in_bundle
                && ofbundle_includes_vlan(bundle, vlan)
                && bundle->floodable
                && !bundle->mirror_out) {
                output_normal(ctx, bundle, vlan);
            }
        }
        ctx->nf_output_iface = NF_OUT_FLOOD;
    }
}

/* Optimized flow revalidation.
 *
 * It's a difficult problem, in general, to tell which facets need to have
 * their actions recalculated whenever the OpenFlow flow table changes.  We
 * don't try to solve that general problem: for most kinds of OpenFlow flow
 * table changes, we recalculate the actions for every facet.  This is
 * relatively expensive, but it's good enough if the OpenFlow flow table
 * doesn't change very often.
 *
 * However, we can expect one particular kind of OpenFlow flow table change to
 * happen frequently: changes caused by MAC learning.  To avoid wasting a lot
 * of CPU on revalidating every facet whenever MAC learning modifies the flow
 * table, we add a special case that applies to flow tables in which every rule
 * has the same form (that is, the same wildcards), except that the table is
 * also allowed to have a single "catch-all" flow that matches all packets.  We
 * optimize this case by tagging all of the facets that resubmit into the table
 * and invalidating the same tag whenever a flow changes in that table.  The
 * end result is that we revalidate just the facets that need it (and sometimes
 * a few more, but not all of the facets or even all of the facets that
 * resubmit to the table modified by MAC learning). */

/* Calculates the tag to use for 'flow' and mask 'mask' when it is inserted
 * into an OpenFlow table with the given 'basis'. */
static tag_type
rule_calculate_tag(const struct flow *flow, const struct minimask *mask,
                   uint32_t secret)
{
    if (minimask_is_catchall(mask)) {
        return 0;
    } else {
        uint32_t hash = flow_hash_in_minimask(flow, mask, secret);
        return tag_create_deterministic(hash);
    }
}

/* Following a change to OpenFlow table 'table_id' in 'ofproto', update the
 * taggability of that table.
 *
 * This function must be called after *each* change to a flow table.  If you
 * skip calling it on some changes then the pointer comparisons at the end can
 * be invalid if you get unlucky.  For example, if a flow removal causes a
 * cls_table to be destroyed and then a flow insertion causes a cls_table with
 * different wildcards to be created with the same address, then this function
 * will incorrectly skip revalidation. */
static void
table_update_taggable(struct ofproto_dpif *ofproto, uint8_t table_id)
{
    struct table_dpif *table = &ofproto->tables[table_id];
    const struct oftable *oftable = &ofproto->up.tables[table_id];
    struct cls_table *catchall, *other;
    struct cls_table *t;

    catchall = other = NULL;

    switch (hmap_count(&oftable->cls.tables)) {
    case 0:
        /* We could tag this OpenFlow table but it would make the logic a
         * little harder and it's a corner case that doesn't seem worth it
         * yet. */
        break;

    case 1:
    case 2:
        HMAP_FOR_EACH (t, hmap_node, &oftable->cls.tables) {
            if (cls_table_is_catchall(t)) {
                catchall = t;
            } else if (!other) {
                other = t;
            } else {
                /* Indicate that we can't tag this by setting both tables to
                 * NULL.  (We know that 'catchall' is already NULL.) */
                other = NULL;
            }
        }
        break;

    default:
        /* Can't tag this table. */
        break;
    }

    if (table->catchall_table != catchall || table->other_table != other) {
        table->catchall_table = catchall;
        table->other_table = other;
        ofproto->need_revalidate = REV_FLOW_TABLE;
    }
}

/* Given 'rule' that has changed in some way (either it is a rule being
 * inserted, a rule being deleted, or a rule whose actions are being
 * modified), marks facets for revalidation to ensure that packets will be
 * forwarded correctly according to the new state of the flow table.
 *
 * This function must be called after *each* change to a flow table.  See
 * the comment on table_update_taggable() for more information. */
static void
rule_invalidate(const struct rule_dpif *rule)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);

    table_update_taggable(ofproto, rule->up.table_id);

    if (!ofproto->need_revalidate) {
        struct table_dpif *table = &ofproto->tables[rule->up.table_id];

        if (table->other_table && rule->tag) {
            tag_set_add(&ofproto->revalidate_set, rule->tag);
        } else {
            ofproto->need_revalidate = REV_FLOW_TABLE;
        }
    }
}

static bool
set_frag_handling(struct ofproto *ofproto_,
                  enum ofp_config_flags frag_handling)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    if (frag_handling != OFPC_FRAG_REASM) {
        ofproto->need_revalidate = REV_RECONFIGURE;
        return true;
    } else {
        return false;
    }
}

static enum ofperr
packet_out(struct ofproto *ofproto_, struct ofpbuf *packet,
           const struct flow *flow,
           const struct ofpact *ofpacts, size_t ofpacts_len)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct odputil_keybuf keybuf;
    struct dpif_flow_stats stats;

    struct ofpbuf key;

    struct action_xlate_ctx ctx;
    uint64_t odp_actions_stub[1024 / 8];
    struct ofpbuf odp_actions;

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&key, flow);

    dpif_flow_stats_extract(flow, packet, time_msec(), &stats);

    action_xlate_ctx_init(&ctx, ofproto, flow, flow->vlan_tci, NULL,
                          packet_get_tcp_flags(packet, flow), packet);
    ctx.resubmit_stats = &stats;

    ofpbuf_use_stub(&odp_actions,
                    odp_actions_stub, sizeof odp_actions_stub);
    xlate_actions(&ctx, ofpacts, ofpacts_len, &odp_actions);
    dpif_execute(ofproto->dpif, key.data, key.size,
                 odp_actions.data, odp_actions.size, packet);
    ofpbuf_uninit(&odp_actions);

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
        }
        return netflow_set_options(ofproto->netflow, netflow_options);
    } else {
        netflow_destroy(ofproto->netflow);
        ofproto->netflow = NULL;
        return 0;
    }
}

static void
get_netflow_ids(const struct ofproto *ofproto_,
                uint8_t *engine_type, uint8_t *engine_id)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    dpif_get_netflow_ids(ofproto->dpif, engine_type, engine_id);
}

static void
send_active_timeout(struct ofproto_dpif *ofproto, struct facet *facet)
{
    if (!facet_is_controller_flow(facet) &&
        netflow_active_timeout_expired(ofproto->netflow, &facet->nf_flow)) {
        struct subfacet *subfacet;
        struct ofexpired expired;

        LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
            if (subfacet->path == SF_FAST_PATH) {
                struct dpif_flow_stats stats;

                subfacet_reinstall(subfacet, &stats);
                subfacet_update_stats(subfacet, &stats);
            }
        }

        expired.flow = facet->flow;
        expired.packet_count = facet->packet_count;
        expired.byte_count = facet->byte_count;
        expired.used = facet->used;
        netflow_expire(ofproto->netflow, &facet->nf_flow, &expired);
    }
}

static void
send_netflow_active_timeouts(struct ofproto_dpif *ofproto)
{
    struct facet *facet;

    HMAP_FOR_EACH (facet, hmap_node, &ofproto->facets) {
        send_active_timeout(ofproto, facet);
    }
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
        mac_learning_flush(ofproto->ml, &ofproto->revalidate_set);
    } else {
        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
            mac_learning_flush(ofproto->ml, &ofproto->revalidate_set);
        }
    }

    unixctl_command_reply(conn, "table successfully flushed");
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
    LIST_FOR_EACH (e, lru_node, &ofproto->ml->lrus) {
        struct ofbundle *bundle = e->port.p;
        ds_put_format(&ds, "%5d  %4d  "ETH_ADDR_FMT"  %3d\n",
                      ofbundle_get_a_port(bundle)->odp_port,
                      e->vlan, ETH_ADDR_ARGS(e->mac),
                      mac_entry_age(ofproto->ml, e));
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

struct trace_ctx {
    struct action_xlate_ctx ctx;
    struct flow flow;
    struct ds *result;
};

static void
trace_format_rule(struct ds *result, uint8_t table_id, int level,
                  const struct rule_dpif *rule)
{
    ds_put_char_multiple(result, '\t', level);
    if (!rule) {
        ds_put_cstr(result, "No match\n");
        return;
    }

    ds_put_format(result, "Rule: table=%"PRIu8" cookie=%#"PRIx64" ",
                  table_id, ntohll(rule->up.flow_cookie));
    cls_rule_format(&rule->up.cr, result);
    ds_put_char(result, '\n');

    ds_put_char_multiple(result, '\t', level);
    ds_put_cstr(result, "OpenFlow ");
    ofpacts_format(rule->up.ofpacts, rule->up.ofpacts_len, result);
    ds_put_char(result, '\n');
}

static void
trace_format_flow(struct ds *result, int level, const char *title,
                 struct trace_ctx *trace)
{
    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s: ", title);
    if (flow_equal(&trace->ctx.flow, &trace->flow)) {
        ds_put_cstr(result, "unchanged");
    } else {
        flow_format(result, &trace->ctx.flow);
        trace->flow = trace->ctx.flow;
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
        ds_put_format(result, " reg%zu=0x%"PRIx32, i, trace->flow.regs[i]);
    }
    ds_put_char(result, '\n');
}

static void
trace_format_odp(struct ds *result, int level, const char *title,
                 struct trace_ctx *trace)
{
    struct ofpbuf *odp_actions = trace->ctx.odp_actions;

    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s: ", title);
    format_odp_actions(result, odp_actions->data, odp_actions->size);
    ds_put_char(result, '\n');
}

static void
trace_resubmit(struct action_xlate_ctx *ctx, struct rule_dpif *rule)
{
    struct trace_ctx *trace = CONTAINER_OF(ctx, struct trace_ctx, ctx);
    struct ds *result = trace->result;

    ds_put_char(result, '\n');
    trace_format_flow(result, ctx->recurse + 1, "Resubmitted flow", trace);
    trace_format_regs(result, ctx->recurse + 1, "Resubmitted regs", trace);
    trace_format_odp(result,  ctx->recurse + 1, "Resubmitted  odp", trace);
    trace_format_rule(result, ctx->table_id, ctx->recurse + 1, rule);
}

static void
trace_report(struct action_xlate_ctx *ctx, const char *s)
{
    struct trace_ctx *trace = CONTAINER_OF(ctx, struct trace_ctx, ctx);
    struct ds *result = trace->result;

    ds_put_char_multiple(result, '\t', ctx->recurse);
    ds_put_cstr(result, s);
    ds_put_char(result, '\n');
}

static void
ofproto_unixctl_trace(struct unixctl_conn *conn, int argc, const char *argv[],
                      void *aux OVS_UNUSED)
{
    const char *dpname = argv[1];
    struct ofproto_dpif *ofproto;
    struct ofpbuf odp_key;
    struct ofpbuf *packet;
    ovs_be16 initial_tci;
    struct ds result;
    struct flow flow;
    char *s;

    packet = NULL;
    ofpbuf_init(&odp_key, 0);
    ds_init(&result);

    ofproto = ofproto_dpif_lookup(dpname);
    if (!ofproto) {
        unixctl_command_reply_error(conn, "Unknown ofproto (use ofproto/list "
                                    "for help)");
        goto exit;
    }
    if (argc == 3 || (argc == 4 && !strcmp(argv[3], "-generate"))) {
        /* ofproto/trace dpname flow [-generate] */
        const char *flow_s = argv[2];
        const char *generate_s = argv[3];

        /* Allow 'flow_s' to be either a datapath flow or an OpenFlow-like
         * flow.  We guess which type it is based on whether 'flow_s' contains
         * an '(', since a datapath flow always contains '(') but an
         * OpenFlow-like flow should not (in fact it's allowed but I believe
         * that's not documented anywhere).
         *
         * An alternative would be to try to parse 'flow_s' both ways, but then
         * it would be tricky giving a sensible error message.  After all, do
         * you just say "syntax error" or do you present both error messages?
         * Both choices seem lousy. */
        if (strchr(flow_s, '(')) {
            int error;

            /* Convert string to datapath key. */
            ofpbuf_init(&odp_key, 0);
            error = odp_flow_key_from_string(flow_s, NULL, &odp_key);
            if (error) {
                unixctl_command_reply_error(conn, "Bad flow syntax");
                goto exit;
            }

            /* Convert odp_key to flow. */
            error = ofproto_dpif_extract_flow_key(ofproto, odp_key.data,
                                                  odp_key.size, &flow,
                                                  &initial_tci, NULL);
            if (error == ODP_FIT_ERROR) {
                unixctl_command_reply_error(conn, "Invalid flow");
                goto exit;
            }
        } else {
            char *error_s;

            error_s = parse_ofp_exact_flow(&flow, argv[2]);
            if (error_s) {
                unixctl_command_reply_error(conn, error_s);
                free(error_s);
                goto exit;
            }

            initial_tci = flow.vlan_tci;
            vsp_adjust_flow(ofproto, &flow);
        }

        /* Generate a packet, if requested. */
        if (generate_s) {
            packet = ofpbuf_new(0);
            flow_compose(packet, &flow);
        }
    } else if (argc == 7) {
        /* ofproto/trace dpname priority tun_id in_port mark packet */
        const char *priority_s = argv[2];
        const char *tun_id_s = argv[3];
        const char *in_port_s = argv[4];
        const char *mark_s = argv[5];
        const char *packet_s = argv[6];
        uint16_t in_port = ofp_port_to_odp_port(atoi(in_port_s));
        ovs_be64 tun_id = htonll(strtoull(tun_id_s, NULL, 0));
        uint32_t priority = atoi(priority_s);
        uint32_t mark = atoi(mark_s);
        const char *msg;

        msg = eth_from_hex(packet_s, &packet);
        if (msg) {
            unixctl_command_reply_error(conn, msg);
            goto exit;
        }

        ds_put_cstr(&result, "Packet: ");
        s = ofp_packet_to_string(packet->data, packet->size);
        ds_put_cstr(&result, s);
        free(s);

        flow_extract(packet, priority, mark, NULL, in_port, &flow);
        flow.tunnel.tun_id = tun_id;
        initial_tci = flow.vlan_tci;
    } else {
        unixctl_command_reply_error(conn, "Bad command syntax");
        goto exit;
    }

    ofproto_trace(ofproto, &flow, packet, initial_tci, &result);
    unixctl_command_reply(conn, ds_cstr(&result));

exit:
    ds_destroy(&result);
    ofpbuf_delete(packet);
    ofpbuf_uninit(&odp_key);
}

static void
ofproto_trace(struct ofproto_dpif *ofproto, const struct flow *flow,
              const struct ofpbuf *packet, ovs_be16 initial_tci,
              struct ds *ds)
{
    struct rule_dpif *rule;

    ds_put_cstr(ds, "Flow: ");
    flow_format(ds, flow);
    ds_put_char(ds, '\n');

    rule = rule_dpif_lookup(ofproto, flow);

    trace_format_rule(ds, 0, 0, rule);
    if (rule == ofproto->miss_rule) {
        ds_put_cstr(ds, "\nNo match, flow generates \"packet in\"s.\n");
    } else if (rule == ofproto->no_packet_in_rule) {
        ds_put_cstr(ds, "\nNo match, packets dropped because "
                    "OFPPC_NO_PACKET_IN is set on in_port.\n");
    } else if (rule == ofproto->drop_frags_rule) {
        ds_put_cstr(ds, "\nPackets dropped because they are IP fragments "
                    "and the fragment handling mode is \"drop\".\n");
    }

    if (rule) {
        uint64_t odp_actions_stub[1024 / 8];
        struct ofpbuf odp_actions;

        struct trace_ctx trace;
        uint8_t tcp_flags;

        tcp_flags = packet ? packet_get_tcp_flags(packet, flow) : 0;
        trace.result = ds;
        trace.flow = *flow;
        ofpbuf_use_stub(&odp_actions,
                        odp_actions_stub, sizeof odp_actions_stub);
        action_xlate_ctx_init(&trace.ctx, ofproto, flow, initial_tci,
                              rule, tcp_flags, packet);
        trace.ctx.resubmit_hook = trace_resubmit;
        trace.ctx.report_hook = trace_report;
        xlate_actions(&trace.ctx, rule->up.ofpacts, rule->up.ofpacts_len,
                      &odp_actions);

        ds_put_char(ds, '\n');
        trace_format_flow(ds, 0, "Final flow", &trace);
        ds_put_cstr(ds, "Datapath actions: ");
        format_odp_actions(ds, odp_actions.data, odp_actions.size);
        ofpbuf_uninit(&odp_actions);

        if (trace.ctx.slow) {
            enum slow_path_reason slow;

            ds_put_cstr(ds, "\nThis flow is handled by the userspace "
                        "slow path because it:");
            for (slow = trace.ctx.slow; slow; ) {
                enum slow_path_reason bit = rightmost_1bit(slow);

                switch (bit) {
                case SLOW_CFM:
                    ds_put_cstr(ds, "\n\t- Consists of CFM packets.");
                    break;
                case SLOW_LACP:
                    ds_put_cstr(ds, "\n\t- Consists of LACP packets.");
                    break;
                case SLOW_STP:
                    ds_put_cstr(ds, "\n\t- Consists of STP packets.");
                    break;
                case SLOW_IN_BAND:
                    ds_put_cstr(ds, "\n\t- Needs in-band special case "
                                "processing.");
                    if (!packet) {
                        ds_put_cstr(ds, "\n\t  (The datapath actions are "
                                    "incomplete--for complete actions, "
                                    "please supply a packet.)");
                    }
                    break;
                case SLOW_CONTROLLER:
                    ds_put_cstr(ds, "\n\t- Sends \"packet-in\" messages "
                                "to the OpenFlow controller.");
                    break;
                case SLOW_MATCH:
                    ds_put_cstr(ds, "\n\t- Needs more specific matching "
                                "than the datapath supports.");
                    break;
                }

                slow &= ~bit;
            }

            if (slow & ~SLOW_MATCH) {
                ds_put_cstr(ds, "\nThe datapath actions above do not reflect "
                            "the special slow-path processing.");
            }
        }
    }
}

static void
ofproto_dpif_clog(struct unixctl_conn *conn OVS_UNUSED, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    clogged = true;
    unixctl_command_reply(conn, NULL);
}

static void
ofproto_dpif_unclog(struct unixctl_conn *conn OVS_UNUSED, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    clogged = false;
    unixctl_command_reply(conn, NULL);
}

/* Runs a self-check of flow translations in 'ofproto'.  Appends a message to
 * 'reply' describing the results. */
static void
ofproto_dpif_self_check__(struct ofproto_dpif *ofproto, struct ds *reply)
{
    struct facet *facet;
    int errors;

    errors = 0;
    HMAP_FOR_EACH (facet, hmap_node, &ofproto->facets) {
        if (!facet_check_consistency(facet)) {
            errors++;
        }
    }
    if (errors) {
        ofproto->need_revalidate = REV_INCONSISTENCY;
    }

    if (errors) {
        ds_put_format(reply, "%s: self-check failed (%d errors)\n",
                      ofproto->up.name, errors);
    } else {
        ds_put_format(reply, "%s: self-check passed\n", ofproto->up.name);
    }
}

static void
ofproto_dpif_self_check(struct unixctl_conn *conn,
                        int argc, const char *argv[], void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct ofproto_dpif *ofproto;

    if (argc > 1) {
        ofproto = ofproto_dpif_lookup(argv[1]);
        if (!ofproto) {
            unixctl_command_reply_error(conn, "Unknown ofproto (use "
                                        "ofproto/list for help)");
            return;
        }
        ofproto_dpif_self_check__(ofproto, &reply);
    } else {
        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
            ofproto_dpif_self_check__(ofproto, &reply);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
ofproto_dpif_unixctl_init(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    unixctl_command_register(
        "ofproto/trace",
        "bridge {priority tun_id in_port mark packet | odp_flow [-generate]}",
        2, 6, ofproto_unixctl_trace, NULL);
    unixctl_command_register("fdb/flush", "[bridge]", 0, 1,
                             ofproto_unixctl_fdb_flush, NULL);
    unixctl_command_register("fdb/show", "bridge", 1, 1,
                             ofproto_unixctl_fdb_show, NULL);
    unixctl_command_register("ofproto/clog", "", 0, 0,
                             ofproto_dpif_clog, NULL);
    unixctl_command_register("ofproto/unclog", "", 0, 0,
                             ofproto_dpif_unclog, NULL);
    unixctl_command_register("ofproto/self-check", "[bridge]", 0, 1,
                             ofproto_dpif_self_check, NULL);
}

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

static int
set_realdev(struct ofport *ofport_, uint16_t realdev_ofp_port, int vid)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport_->ofproto);
    struct ofport_dpif *ofport = ofport_dpif_cast(ofport_);

    if (realdev_ofp_port == ofport->realdev_ofp_port
        && vid == ofport->vlandev_vid) {
        return 0;
    }

    ofproto->need_revalidate = REV_RECONFIGURE;

    if (ofport->realdev_ofp_port) {
        vsp_remove(ofport);
    }
    if (realdev_ofp_port && ofport->bundle) {
        /* vlandevs are enslaved to their realdevs, so they are not allowed to
         * themselves be part of a bundle. */
        bundle_set(ofport->up.ofproto, ofport->bundle, NULL);
    }

    ofport->realdev_ofp_port = realdev_ofp_port;
    ofport->vlandev_vid = vid;

    if (realdev_ofp_port) {
        vsp_add(ofport, realdev_ofp_port, vid);
    }

    return 0;
}

static uint32_t
hash_realdev_vid(uint16_t realdev_ofp_port, int vid)
{
    return hash_2words(realdev_ofp_port, vid);
}

/* Returns the ODP port number of the Linux VLAN device that corresponds to
 * 'vlan_tci' on the network device with port number 'realdev_odp_port' in
 * 'ofproto'.  For example, given 'realdev_odp_port' of eth0 and 'vlan_tci' 9,
 * it would return the port number of eth0.9.
 *
 * Unless VLAN splinters are enabled for port 'realdev_odp_port', this
 * function just returns its 'realdev_odp_port' argument. */
static uint32_t
vsp_realdev_to_vlandev(const struct ofproto_dpif *ofproto,
                       uint32_t realdev_odp_port, ovs_be16 vlan_tci)
{
    if (!hmap_is_empty(&ofproto->realdev_vid_map)) {
        uint16_t realdev_ofp_port = odp_port_to_ofp_port(realdev_odp_port);
        int vid = vlan_tci_to_vid(vlan_tci);
        const struct vlan_splinter *vsp;

        HMAP_FOR_EACH_WITH_HASH (vsp, realdev_vid_node,
                                 hash_realdev_vid(realdev_ofp_port, vid),
                                 &ofproto->realdev_vid_map) {
            if (vsp->realdev_ofp_port == realdev_ofp_port
                && vsp->vid == vid) {
                return ofp_port_to_odp_port(vsp->vlandev_ofp_port);
            }
        }
    }
    return realdev_odp_port;
}

static struct vlan_splinter *
vlandev_find(const struct ofproto_dpif *ofproto, uint16_t vlandev_ofp_port)
{
    struct vlan_splinter *vsp;

    HMAP_FOR_EACH_WITH_HASH (vsp, vlandev_node, hash_int(vlandev_ofp_port, 0),
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
static uint16_t
vsp_vlandev_to_realdev(const struct ofproto_dpif *ofproto,
                       uint16_t vlandev_ofp_port, int *vid)
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
 * 'flow->vlan_tci' to the VLAN VID, and returns true.  Otherwise (which is
 * always the case unless VLAN splinters are enabled), returns false without
 * making any changes. */
static bool
vsp_adjust_flow(const struct ofproto_dpif *ofproto, struct flow *flow)
{
    uint16_t realdev;
    int vid;

    realdev = vsp_vlandev_to_realdev(ofproto, flow->in_port, &vid);
    if (!realdev) {
        return false;
    }

    /* Cause the flow to be processed as if it came in on the real device with
     * the VLAN device's VLAN ID. */
    flow->in_port = realdev;
    flow->vlan_tci = htons((vid & VLAN_VID_MASK) | VLAN_CFI);
    return true;
}

static void
vsp_remove(struct ofport_dpif *port)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);
    struct vlan_splinter *vsp;

    vsp = vlandev_find(ofproto, port->up.ofp_port);
    if (vsp) {
        hmap_remove(&ofproto->vlandev_map, &vsp->vlandev_node);
        hmap_remove(&ofproto->realdev_vid_map, &vsp->realdev_vid_node);
        free(vsp);

        port->realdev_ofp_port = 0;
    } else {
        VLOG_ERR("missing vlan device record");
    }
}

static void
vsp_add(struct ofport_dpif *port, uint16_t realdev_ofp_port, int vid)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);

    if (!vsp_vlandev_to_realdev(ofproto, port->up.ofp_port, NULL)
        && (vsp_realdev_to_vlandev(ofproto, realdev_ofp_port, htons(vid))
            == realdev_ofp_port)) {
        struct vlan_splinter *vsp;

        vsp = xmalloc(sizeof *vsp);
        hmap_insert(&ofproto->vlandev_map, &vsp->vlandev_node,
                    hash_int(port->up.ofp_port, 0));
        hmap_insert(&ofproto->realdev_vid_map, &vsp->realdev_vid_node,
                    hash_realdev_vid(realdev_ofp_port, vid));
        vsp->realdev_ofp_port = realdev_ofp_port;
        vsp->vlandev_ofp_port = port->up.ofp_port;
        vsp->vid = vid;

        port->realdev_ofp_port = realdev_ofp_port;
    } else {
        VLOG_ERR("duplicate vlan device record");
    }
}

const struct ofproto_class ofproto_dpif_class = {
    enumerate_types,
    enumerate_names,
    del,
    alloc,
    construct,
    destruct,
    dealloc,
    run,
    run_fast,
    wait,
    get_memory_usage,
    flush,
    get_features,
    get_tables,
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
    NULL,                       /* rule_choose_table */
    rule_alloc,
    rule_construct,
    rule_destruct,
    rule_dealloc,
    rule_get_stats,
    rule_execute,
    rule_modify_actions,
    set_frag_handling,
    packet_out,
    set_netflow,
    get_netflow_ids,
    set_sflow,
    set_cfm,
    get_cfm_fault,
    get_cfm_opup,
    get_cfm_remote_mpids,
    get_cfm_health,
    set_stp,
    get_stp_status,
    set_stp_port,
    get_stp_port_status,
    set_queues,
    bundle_set,
    bundle_remove,
    mirror_set,
    mirror_get_stats,
    set_flood_vlans,
    is_mirror_output_bundle,
    forward_bpdu_changed,
    set_mac_idle_time,
    set_realdev,
};
