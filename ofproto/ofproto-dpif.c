/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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
#include "multipath.h"
#include "netdev.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofp-print.h"
#include "ofproto-dpif-sflow.h"
#include "poll-loop.h"
#include "timer.h"
#include "unaligned.h"
#include "unixctl.h"
#include "vlan-bitmap.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif);

COVERAGE_DEFINE(ofproto_dpif_ctlr_action);
COVERAGE_DEFINE(ofproto_dpif_expired);
COVERAGE_DEFINE(ofproto_dpif_no_packet_in);
COVERAGE_DEFINE(ofproto_dpif_xlate);
COVERAGE_DEFINE(facet_changed_rule);
COVERAGE_DEFINE(facet_invalidated);
COVERAGE_DEFINE(facet_revalidate);
COVERAGE_DEFINE(facet_unexpected);

/* Maximum depth of flow table recursion (due to resubmit actions) in a
 * flow translation. */
#define MAX_RESUBMIT_RECURSION 32

/* Number of implemented OpenFlow tables. */
enum { N_TABLES = 255 };
BUILD_ASSERT_DECL(N_TABLES >= 1 && N_TABLES <= 255);

struct ofport_dpif;
struct ofproto_dpif;

struct rule_dpif {
    struct rule up;

    long long int used;         /* Time last used; time created if not used. */

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
                                          const struct flow *, uint8_t table);

static void flow_push_stats(const struct rule_dpif *, const struct flow *,
                            uint64_t packets, uint64_t bytes,
                            long long int used);

static uint32_t rule_calculate_tag(const struct flow *,
                                   const struct flow_wildcards *,
                                   uint32_t basis);
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
    struct ofproto_dpif *ofproto; /* Owning ofproto. */
    struct hmap_node hmap_node; /* In struct ofproto's "bundles" hmap. */
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
    bool floodable;             /* True if no port has OFPPC_NO_FLOOD set. */

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
static struct ofbundle *lookup_input_bundle(struct ofproto_dpif *,
                                            uint16_t in_port, bool warn);

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

    /* Should OFPP_NORMAL MAC learning and NXAST_LEARN actions execute?  We
     * want to execute them if we are actually processing a packet, or if we
     * are accounting for packets that the datapath has processed, but not if
     * we are just revalidating. */
    bool may_learn;

    /* If nonnull, called just before executing a resubmit action.
     *
     * This is normally null so the client has to set it manually after
     * calling action_xlate_ctx_init(). */
    void (*resubmit_hook)(struct action_xlate_ctx *, struct rule_dpif *);

/* xlate_actions() initializes and uses these members.  The client might want
 * to look at them after it returns. */

    struct ofpbuf *odp_actions; /* Datapath actions. */
    tag_type tags;              /* Tags associated with actions. */
    bool may_set_up_flow;       /* True ordinarily; false if the actions must
                                 * be reassessed for every packet. */
    bool has_learn;             /* Actions include NXAST_LEARN? */
    bool has_normal;            /* Actions output to OFPP_NORMAL? */
    uint16_t nf_output_iface;   /* Output interface index for NetFlow. */
    mirror_mask_t mirrors;      /* Bitmap of associated mirrors. */

/* xlate_actions() initializes and uses these members, but the client has no
 * reason to look at them. */

    int recurse;                /* Recursion level, via xlate_table_action. */
    struct flow base_flow;      /* Flow at the last commit. */
    uint32_t original_priority; /* Priority when packet arrived. */
    uint8_t table_id;           /* OpenFlow table ID where flow was found. */
    uint32_t sflow_n_outputs;   /* Number of output ports. */
    uint16_t sflow_odp_port;    /* Output port for composing sFlow action. */
    uint16_t user_cookie_offset;/* Used for user_action_cookie fixup. */
    bool exit;                  /* No further actions should be processed. */
};

static void action_xlate_ctx_init(struct action_xlate_ctx *,
                                  struct ofproto_dpif *, const struct flow *,
                                  ovs_be16 initial_tci, const struct ofpbuf *);
static struct ofpbuf *xlate_actions(struct action_xlate_ctx *,
                                    const union ofp_action *in, size_t n_in);

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

    /* Properties of datapath actions.
     *
     * Every subfacet has its own actions because actions can differ slightly
     * between splintered and non-splintered subfacets due to the VLAN tag
     * being initially different (present vs. absent).  All of them have these
     * properties in common so we just store one copy of them here. */
    bool may_install;            /* Reassess actions for every packet? */
    bool has_learn;              /* Actions include NXAST_LEARN? */
    bool has_normal;             /* Actions output to OFPP_NORMAL? */
    tag_type tags;               /* Tags that would require revalidation. */
    mirror_mask_t mirrors;       /* Bitmap of dependent mirrors. */
};

static struct facet *facet_create(struct rule_dpif *, const struct flow *);
static void facet_remove(struct ofproto_dpif *, struct facet *);
static void facet_free(struct facet *);

static struct facet *facet_find(struct ofproto_dpif *, const struct flow *);
static struct facet *facet_lookup_valid(struct ofproto_dpif *,
                                        const struct flow *);
static bool facet_revalidate(struct ofproto_dpif *, struct facet *);

static bool execute_controller_action(struct ofproto_dpif *,
                                      const struct flow *,
                                      const struct nlattr *odp_actions,
                                      size_t actions_len,
                                      struct ofpbuf *packet, bool clone);

static void facet_flush_stats(struct ofproto_dpif *, struct facet *);

static void facet_update_time(struct ofproto_dpif *, struct facet *,
                              long long int used);
static void facet_reset_counters(struct facet *);
static void facet_push_stats(struct facet *);
static void facet_account(struct ofproto_dpif *, struct facet *);

static bool facet_is_controller_flow(struct facet *);

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

    bool installed;             /* Installed in datapath? */

    /* This value is normally the same as ->facet->flow.vlan_tci.  Only VLAN
     * splinters can cause it to differ.  This value should be removed when
     * the VLAN splinters feature is no longer needed.  */
    ovs_be16 initial_tci;       /* Initial VLAN TCI value. */
};

static struct subfacet *subfacet_create(struct ofproto_dpif *, struct facet *,
                                        enum odp_key_fitness,
                                        const struct nlattr *key,
                                        size_t key_len, ovs_be16 initial_tci);
static struct subfacet *subfacet_find(struct ofproto_dpif *,
                                      const struct nlattr *key, size_t key_len);
static void subfacet_destroy(struct ofproto_dpif *, struct subfacet *);
static void subfacet_destroy__(struct ofproto_dpif *, struct subfacet *);
static void subfacet_reset_dp_stats(struct subfacet *,
                                    struct dpif_flow_stats *);
static void subfacet_update_time(struct ofproto_dpif *, struct subfacet *,
                                 long long int used);
static void subfacet_update_stats(struct ofproto_dpif *, struct subfacet *,
                                  const struct dpif_flow_stats *);
static void subfacet_make_actions(struct ofproto_dpif *, struct subfacet *,
                                  const struct ofpbuf *packet);
static int subfacet_install(struct ofproto_dpif *, struct subfacet *,
                            const struct nlattr *actions, size_t actions_len,
                            struct dpif_flow_stats *);
static void subfacet_uninstall(struct ofproto_dpif *, struct subfacet *);

struct ofport_dpif {
    struct ofport up;

    uint32_t odp_port;
    struct ofbundle *bundle;    /* Bundle that contains this port, if any. */
    struct list bundle_node;    /* In struct ofbundle's "ports" list. */
    struct cfm *cfm;            /* Connectivity Fault Management, if any. */
    tag_type tag;               /* Tag associated with this port. */
    uint32_t bond_stable_id;    /* stable_id to use as bond slave, or 0. */
    bool may_enable;            /* May be enabled in bonds. */

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
static uint16_t vsp_vlandev_to_realdev(const struct ofproto_dpif *,
                                       uint16_t vlandev, int *vid);
static void vsp_remove(struct ofport_dpif *);
static void vsp_add(struct ofport_dpif *, uint16_t realdev_ofp_port, int vid);

static struct ofport_dpif *
ofport_dpif_cast(const struct ofport *ofport)
{
    assert(ofport->ofproto->ofproto_class == &ofproto_dpif_class);
    return ofport ? CONTAINER_OF(ofport, struct ofport_dpif, up) : NULL;
}

static void port_run(struct ofport_dpif *);
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

struct ofproto_dpif {
    struct hmap_node all_ofproto_dpifs_node; /* In 'all_ofproto_dpifs'. */
    struct ofproto up;
    struct dpif *dpif;
    int max_ports;

    /* Statistics. */
    uint64_t n_matches;

    /* Bridging. */
    struct netflow *netflow;
    struct dpif_sflow *sflow;
    struct hmap bundles;        /* Contains "struct ofbundle"s. */
    struct mac_learning *ml;
    struct ofmirror *mirrors[MAX_MIRRORS];
    bool has_bonded_bundles;

    /* Expiration. */
    struct timer next_expiration;

    /* Facets. */
    struct hmap facets;
    struct hmap subfacets;

    /* Revalidation. */
    struct table_dpif tables[N_TABLES];
    bool need_revalidate;
    struct tag_set revalidate_set;

    /* Support for debugging async flow mods. */
    struct list completions;

    bool has_bundle_action; /* True when the first bundle action appears. */

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

static struct ofport_dpif *get_ofp_port(struct ofproto_dpif *,
                                        uint16_t ofp_port);
static struct ofport_dpif *get_odp_port(struct ofproto_dpif *,
                                        uint32_t odp_port);

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
static size_t
compose_sflow_action(const struct ofproto_dpif *, struct ofpbuf *odp_actions,
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
construct(struct ofproto *ofproto_, int *n_tablesp)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    const char *name = ofproto->up.name;
    int error;
    int i;

    error = dpif_create_and_open(name, ofproto->up.type, &ofproto->dpif);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s", name, strerror(error));
        return error;
    }

    ofproto->max_ports = dpif_get_max_ports(ofproto->dpif);
    ofproto->n_matches = 0;

    dpif_flow_flush(ofproto->dpif);
    dpif_recv_purge(ofproto->dpif);

    error = dpif_recv_set_mask(ofproto->dpif,
                               ((1u << DPIF_UC_MISS) |
                                (1u << DPIF_UC_ACTION)));
    if (error) {
        VLOG_ERR("failed to listen on datapath %s: %s", name, strerror(error));
        dpif_close(ofproto->dpif);
        return error;
    }

    ofproto->netflow = NULL;
    ofproto->sflow = NULL;
    ofproto->stp = NULL;
    hmap_init(&ofproto->bundles);
    ofproto->ml = mac_learning_create();
    for (i = 0; i < MAX_MIRRORS; i++) {
        ofproto->mirrors[i] = NULL;
    }
    ofproto->has_bonded_bundles = false;

    timer_set_duration(&ofproto->next_expiration, 1000);

    hmap_init(&ofproto->facets);
    hmap_init(&ofproto->subfacets);

    for (i = 0; i < N_TABLES; i++) {
        struct table_dpif *table = &ofproto->tables[i];

        table->catchall_table = NULL;
        table->other_table = NULL;
        table->basis = random_uint32();
    }
    ofproto->need_revalidate = false;
    tag_set_init(&ofproto->revalidate_set);

    list_init(&ofproto->completions);

    ofproto_dpif_unixctl_init();

    ofproto->has_bundle_action = false;

    hmap_init(&ofproto->vlandev_map);
    hmap_init(&ofproto->realdev_vid_map);

    hmap_insert(&all_ofproto_dpifs, &ofproto->all_ofproto_dpifs_node,
                hash_string(ofproto->up.name, 0));

    *n_tablesp = N_TABLES;
    return 0;
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
    struct classifier *table;
    int i;

    hmap_remove(&all_ofproto_dpifs, &ofproto->all_ofproto_dpifs_node);
    complete_operations(ofproto);

    OFPROTO_FOR_EACH_TABLE (table, &ofproto->up) {
        struct cls_cursor cursor;

        cls_cursor_init(&cursor, table, NULL);
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

    hmap_destroy(&ofproto->vlandev_map);
    hmap_destroy(&ofproto->realdev_vid_map);

    dpif_close(ofproto->dpif);
}

static int
run_fast(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    unsigned int work;

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
        struct facet *facet, *next;

        /* Clear the revalidation flags. */
        tag_set_init(&ofproto->revalidate_set);
        ofproto->need_revalidate = false;

        HMAP_FOR_EACH_SAFE (facet, next, hmap_node, &ofproto->facets) {
            if (revalidate_all
                || tag_set_intersects(&revalidate_set, facet->tags)) {
                facet_revalidate(ofproto, facet);
            }
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
            subfacet->installed = false;
            subfacet->dp_packet_count = 0;
            subfacet->dp_byte_count = 0;
        }
        facet_remove(ofproto, facet);
    }
    dpif_flow_flush(ofproto->dpif);
}

static void
get_features(struct ofproto *ofproto_ OVS_UNUSED,
             bool *arp_match_ip, uint32_t *actions)
{
    *arp_match_ip = true;
    *actions = ((1u << OFPAT_OUTPUT) |
                (1u << OFPAT_SET_VLAN_VID) |
                (1u << OFPAT_SET_VLAN_PCP) |
                (1u << OFPAT_STRIP_VLAN) |
                (1u << OFPAT_SET_DL_SRC) |
                (1u << OFPAT_SET_DL_DST) |
                (1u << OFPAT_SET_NW_SRC) |
                (1u << OFPAT_SET_NW_DST) |
                (1u << OFPAT_SET_NW_TOS) |
                (1u << OFPAT_SET_TP_SRC) |
                (1u << OFPAT_SET_TP_DST) |
                (1u << OFPAT_ENQUEUE));
}

static void
get_tables(struct ofproto *ofproto_, struct ofp_table_stats *ots)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct dpif_dp_stats s;

    strcpy(ots->name, "classifier");

    dpif_get_dp_stats(ofproto->dpif, &s);
    put_32aligned_be64(&ots->lookup_count, htonll(s.n_hit + s.n_missed));
    put_32aligned_be64(&ots->matched_count,
                       htonll(s.n_hit + ofproto->n_matches));
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

    ofproto->need_revalidate = true;
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

    if (ofproto->sflow) {
        dpif_sflow_add_port(ofproto->sflow, port->odp_port,
                            netdev_get_name(port->up.netdev));
    }

    return 0;
}

static void
port_destruct(struct ofport *port_)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);

    ofproto->need_revalidate = true;
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
port_reconfigured(struct ofport *port_, ovs_be32 old_config)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);
    ovs_be32 changed = old_config ^ port->up.opp.config;

    if (changed & htonl(OFPPC_NO_RECV | OFPPC_NO_RECV_STP |
                        OFPPC_NO_FWD | OFPPC_NO_FLOOD)) {
        ofproto->need_revalidate = true;

        if (changed & htonl(OFPPC_NO_FLOOD) && port->bundle) {
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
                dpif_sflow_add_port(ds, ofport->odp_port,
                                    netdev_get_name(ofport->up.netdev));
            }
            ofproto->need_revalidate = true;
        }
        dpif_sflow_set_options(ds, sflow_options);
    } else {
        if (ds) {
            dpif_sflow_destroy(ds);
            ofproto->need_revalidate = true;
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
            ofproto->need_revalidate = true;
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
        ofproto->need_revalidate = true;
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
        ovs_be32 of_state;
        bool fwd_change;

        VLOG_DBG_RL(&rl, "port %s: STP state changed from %s to %s",
                    netdev_get_name(ofport->up.netdev),
                    stp_state_name(ofport->stp_state),
                    stp_state_name(state));
        if (stp_learn_in_state(ofport->stp_state)
                != stp_learn_in_state(state)) {
            /* xxx Learning action flows should also be flushed. */
            mac_learning_flush(ofproto->ml);
        }
        fwd_change = stp_forward_in_state(ofport->stp_state)
                        != stp_forward_in_state(state);

        ofproto->need_revalidate = true;
        ofport->stp_state = state;
        ofport->stp_state_entered = time_msec();

        if (fwd_change && ofport->bundle) {
            bundle_update(ofport->bundle);
        }

        /* Update the STP state bits in the OpenFlow port description. */
        of_state = (ofport->up.opp.state & htonl(~OFPPS_STP_MASK))
                         | htonl(state == STP_LISTENING ? OFPPS_STP_LISTEN
                               : state == STP_LEARNING ? OFPPS_STP_LEARN
                               : state == STP_FORWARDING ? OFPPS_STP_FORWARD
                               : state == STP_BLOCKING ?  OFPPS_STP_BLOCK
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
            ofproto->need_revalidate = true;
        }

        if (pdscp->dscp != dscp) {
            pdscp->dscp = dscp;
            ofproto->need_revalidate = true;
        }

        hmap_insert(&new, &pdscp->hmap_node, hash_int(pdscp->priority, 0));
    }

    if (!hmap_is_empty(&ofport->priorities)) {
        ofport_clear_priorities(ofport);
        ofproto->need_revalidate = true;
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

    ofproto->need_revalidate = true;
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
        if (port->up.opp.config & htonl(OFPPC_NO_FLOOD)) {
            bundle->floodable = false;
            break;
        }
    }
}

static void
bundle_del_port(struct ofport_dpif *port)
{
    struct ofbundle *bundle = port->bundle;

    bundle->ofproto->need_revalidate = true;

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
        bundle->ofproto->need_revalidate = true;
        if (port->bundle) {
            bundle_del_port(port);
        }

        port->bundle = bundle;
        list_push_back(&bundle->ports, &port->bundle_node);
        if (port->up.opp.config & htonl(OFPPC_NO_FLOOD)) {
            bundle->floodable = false;
        }
    }
    if (lacp) {
        port->bundle->ofproto->need_revalidate = true;
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
                ofproto->need_revalidate = true;
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
            ofproto->need_revalidate = true;
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
        trunks = (unsigned long *) s->trunks;
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
            trunks = (unsigned long *) s->trunks;
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
                ofproto->need_revalidate = true;
            }
        } else {
            bundle->bond = bond_create(s->bond);
            ofproto->need_revalidate = true;
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
            int ret;

            learning_packet = bond_compose_learning_packet(bundle->bond, e->mac,
                                                           e->vlan,
                                                           (void **)&port);
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
                 lacp_negotiated(bundle->lacp));
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

    ofproto->need_revalidate = true;
    mac_learning_flush(ofproto->ml);
    mirror_update_dups(ofproto);

    return 0;
}

static void
mirror_destroy(struct ofmirror *mirror)
{
    struct ofproto_dpif *ofproto;
    mirror_mask_t mirror_bit;
    struct ofbundle *bundle;

    if (!mirror) {
        return;
    }

    ofproto = mirror->ofproto;
    ofproto->need_revalidate = true;
    mac_learning_flush(ofproto->ml);

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
        ofproto->need_revalidate = true;
        mac_learning_flush(ofproto->ml);
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
    /* Revalidate cached flows whenever forward_bpdu option changes. */
    ofproto->need_revalidate = true;
}

/* Ports. */

static struct ofport_dpif *
get_ofp_port(struct ofproto_dpif *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(&ofproto->up, ofp_port);
    return ofport ? ofport_dpif_cast(ofport) : NULL;
}

static struct ofport_dpif *
get_odp_port(struct ofproto_dpif *ofproto, uint32_t odp_port)
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
port_run(struct ofport_dpif *ofport)
{
    bool enable = netdev_get_carrier(ofport->up.netdev);

    if (ofport->cfm) {
        cfm_run(ofport->cfm);

        if (cfm_should_send_ccm(ofport->cfm)) {
            struct ofpbuf packet;

            ofpbuf_init(&packet, 0);
            cfm_compose_ccm(ofport->cfm, &packet, ofport->up.opp.hw_addr);
            send_packet(ofport, &packet);
            ofpbuf_uninit(&packet);
        }

        enable = enable && !cfm_get_fault(ofport->cfm)
            && cfm_get_opup(ofport->cfm);
    }

    if (ofport->bundle) {
        enable = enable && lacp_slave_may_enable(ofport->bundle->lacp, ofport);
    }

    if (ofport->may_enable != enable) {
        struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofport->up.ofproto);

        if (ofproto->has_bundle_action) {
            ofproto->need_revalidate = true;
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
    uint16_t odp_port;
    int error;

    error = dpif_port_add(ofproto->dpif, netdev, &odp_port);
    if (!error) {
        *ofp_portp = odp_port_to_ofp_port(odp_port);
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
};

struct flow_miss_op {
    union dpif_op dpif_op;
    struct subfacet *subfacet;
};

/* Sends an OFPT_PACKET_IN message for 'packet' of type OFPR_NO_MATCH to each
 * OpenFlow controller as necessary according to their individual
 * configurations.
 *
 * If 'clone' is true, the caller retains ownership of 'packet'.  Otherwise,
 * ownership is transferred to this function. */
static void
send_packet_in_miss(struct ofproto_dpif *ofproto, struct ofpbuf *packet,
                    const struct flow *flow, bool clone)
{
    struct ofputil_packet_in pin;

    pin.packet = packet;
    pin.in_port = flow->in_port;
    pin.reason = OFPR_NO_MATCH;
    pin.buffer_id = 0;          /* not yet known */
    pin.send_len = 0;           /* not used for flow table misses */
    connmgr_send_packet_in(ofproto->up.connmgr, &pin, flow,
                           clone ? NULL : packet);
}

/* Sends an OFPT_PACKET_IN message for 'packet' of type OFPR_ACTION to each
 * OpenFlow controller as necessary according to their individual
 * configurations.
 *
 * 'send_len' should be the number of bytes of 'packet' to send to the
 * controller, as specified in the action that caused the packet to be sent.
 *
 * If 'clone' is true, the caller retains ownership of 'upcall->packet'.
 * Otherwise, ownership is transferred to this function. */
static void
send_packet_in_action(struct ofproto_dpif *ofproto, struct ofpbuf *packet,
                      uint64_t userdata, const struct flow *flow, bool clone)
{
    struct ofputil_packet_in pin;
    struct user_action_cookie cookie;

    memcpy(&cookie, &userdata, sizeof(cookie));

    pin.packet = packet;
    pin.in_port = flow->in_port;
    pin.reason = OFPR_ACTION;
    pin.buffer_id = 0;          /* not yet known */
    pin.send_len = cookie.data;
    connmgr_send_packet_in(ofproto->up.connmgr, &pin, flow,
                           clone ? NULL : packet);
}

static bool
process_special(struct ofproto_dpif *ofproto, const struct flow *flow,
                const struct ofpbuf *packet)
{
    struct ofport_dpif *ofport = get_ofp_port(ofproto, flow->in_port);

    if (!ofport) {
        return false;
    }

    if (ofport->cfm && cfm_should_process_flow(ofport->cfm, flow)) {
        if (packet) {
            cfm_process_heartbeat(ofport->cfm, packet);
        }
        return true;
    } else if (ofport->bundle && ofport->bundle->lacp
               && flow->dl_type == htons(ETH_TYPE_LACP)) {
        if (packet) {
            lacp_process_packet(ofport->bundle->lacp, ofport, packet);
        }
        return true;
    } else if (ofproto->stp && stp_should_process_flow(flow)) {
        if (packet) {
            stp_process_packet(ofport, packet);
        }
        return true;
    }
    return false;
}

static struct flow_miss *
flow_miss_create(struct hmap *todo, const struct flow *flow,
                 enum odp_key_fitness key_fitness,
                 const struct nlattr *key, size_t key_len,
                 ovs_be16 initial_tci)
{
    uint32_t hash = flow_hash(flow, 0);
    struct flow_miss *miss;

    HMAP_FOR_EACH_WITH_HASH (miss, hmap_node, hash, todo) {
        if (flow_equal(&miss->flow, flow)) {
            return miss;
        }
    }

    miss = xmalloc(sizeof *miss);
    hmap_insert(todo, &miss->hmap_node, hash);
    miss->flow = *flow;
    miss->key_fitness = key_fitness;
    miss->key = key;
    miss->key_len = key_len;
    miss->initial_tci = initial_tci;
    list_init(&miss->packets);
    return miss;
}

static void
handle_flow_miss(struct ofproto_dpif *ofproto, struct flow_miss *miss,
                 struct flow_miss_op *ops, size_t *n_ops)
{
    const struct flow *flow = &miss->flow;
    struct ofpbuf *packet, *next_packet;
    struct subfacet *subfacet;
    struct facet *facet;

    facet = facet_lookup_valid(ofproto, flow);
    if (!facet) {
        struct rule_dpif *rule;

        rule = rule_dpif_lookup(ofproto, flow, 0);
        if (!rule) {
            /* Don't send a packet-in if OFPPC_NO_PACKET_IN asserted. */
            struct ofport_dpif *port = get_ofp_port(ofproto, flow->in_port);
            if (port) {
                if (port->up.opp.config & htonl(OFPPC_NO_PACKET_IN)) {
                    COVERAGE_INC(ofproto_dpif_no_packet_in);
                    /* XXX install 'drop' flow entry */
                    return;
                }
            } else {
                VLOG_WARN_RL(&rl, "packet-in on unknown port %"PRIu16,
                             flow->in_port);
            }

            LIST_FOR_EACH_SAFE (packet, next_packet, list_node,
                                &miss->packets) {
                list_remove(&packet->list_node);
                send_packet_in_miss(ofproto, packet, flow, false);
            }

            return;
        }

        facet = facet_create(rule, flow);
    }

    subfacet = subfacet_create(ofproto, facet,
                               miss->key_fitness, miss->key, miss->key_len,
                               miss->initial_tci);

    LIST_FOR_EACH_SAFE (packet, next_packet, list_node, &miss->packets) {
        struct dpif_flow_stats stats;

        list_remove(&packet->list_node);
        ofproto->n_matches++;

        if (facet->rule->up.cr.priority == FAIL_OPEN_PRIORITY) {
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
            send_packet_in_miss(ofproto, packet, flow, true);
        }

        if (!facet->may_install || !subfacet->actions) {
            subfacet_make_actions(ofproto, subfacet, packet);
        }

        /* Credit statistics to subfacet for this packet.  We must do this now
         * because execute_controller_action() below may destroy 'packet'. */
        dpif_flow_stats_extract(&facet->flow, packet, &stats);
        subfacet_update_stats(ofproto, subfacet, &stats);

        if (!execute_controller_action(ofproto, &facet->flow,
                                       subfacet->actions,
                                       subfacet->actions_len, packet, true)) {
            struct flow_miss_op *op = &ops[(*n_ops)++];
            struct dpif_execute *execute = &op->dpif_op.execute;

            if (flow->vlan_tci != subfacet->initial_tci) {
                /* This packet was received on a VLAN splinter port.  We added
                 * a VLAN to the packet to make the packet resemble the flow,
                 * but the actions were composed assuming that the packet
                 * contained no VLAN.  So, we must remove the VLAN header from
                 * the packet before trying to execute the actions. */
                eth_pop_vlan(packet);
            }

            op->subfacet = subfacet;
            execute->type = DPIF_OP_EXECUTE;
            execute->key = miss->key;
            execute->key_len = miss->key_len;
            execute->actions
                = (facet->may_install
                   ? subfacet->actions
                   : xmemdup(subfacet->actions, subfacet->actions_len));
            execute->actions_len = subfacet->actions_len;
            execute->packet = packet;
        }
    }

    if (facet->may_install && subfacet->key_fitness != ODP_FIT_TOO_LITTLE) {
        struct flow_miss_op *op = &ops[(*n_ops)++];
        struct dpif_flow_put *put = &op->dpif_op.flow_put;

        op->subfacet = subfacet;
        put->type = DPIF_OP_FLOW_PUT;
        put->flags = DPIF_FP_CREATE | DPIF_FP_MODIFY;
        put->key = miss->key;
        put->key_len = miss->key_len;
        put->actions = subfacet->actions;
        put->actions_len = subfacet->actions_len;
        put->stats = NULL;
    }
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
    uint16_t realdev;
    int vid;

    fitness = odp_flow_key_to_flow(key, key_len, flow);
    if (fitness == ODP_FIT_ERROR) {
        return fitness;
    }
    *initial_tci = flow->vlan_tci;

    realdev = vsp_vlandev_to_realdev(ofproto, flow->in_port, &vid);
    if (realdev) {
        /* Cause the flow to be processed as if it came in on the real device
         * with the VLAN device's VLAN ID. */
        flow->in_port = realdev;
        flow->vlan_tci = htons((vid & VLAN_VID_MASK) | VLAN_CFI);
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
    struct flow_miss *miss, *next_miss;
    struct flow_miss_op flow_miss_ops[FLOW_MISS_MAX_BATCH * 2];
    union dpif_op *dpif_ops[FLOW_MISS_MAX_BATCH * 2];
    struct hmap todo;
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
    for (upcall = upcalls; upcall < &upcalls[n_upcalls]; upcall++) {
        enum odp_key_fitness fitness;
        struct flow_miss *miss;
        ovs_be16 initial_tci;
        struct flow flow;

        /* Obtain metadata and check userspace/kernel agreement on flow match,
         * then set 'flow''s header pointers. */
        fitness = ofproto_dpif_extract_flow_key(ofproto,
                                                upcall->key, upcall->key_len,
                                                &flow, &initial_tci,
                                                upcall->packet);
        if (fitness == ODP_FIT_ERROR) {
            ofpbuf_delete(upcall->packet);
            continue;
        }
        flow_extract(upcall->packet, flow.priority, flow.tun_id,
                     flow.in_port, &flow);

        /* Handle 802.1ag, LACP, and STP specially. */
        if (process_special(ofproto, &flow, upcall->packet)) {
            ofpbuf_delete(upcall->packet);
            ofproto->n_matches++;
            continue;
        }

        /* Add other packets to a to-do list. */
        miss = flow_miss_create(&todo, &flow, fitness,
                                upcall->key, upcall->key_len, initial_tci);
        list_push_back(&miss->packets, &upcall->packet->list_node);
    }

    /* Process each element in the to-do list, constructing the set of
     * operations to batch. */
    n_ops = 0;
    HMAP_FOR_EACH_SAFE (miss, next_miss, hmap_node, &todo) {
        handle_flow_miss(ofproto, miss, flow_miss_ops, &n_ops);
        ofpbuf_list_delete(&miss->packets);
        hmap_remove(&todo, &miss->hmap_node);
        free(miss);
    }
    assert(n_ops <= ARRAY_SIZE(flow_miss_ops));
    hmap_destroy(&todo);

    /* Execute batch. */
    for (i = 0; i < n_ops; i++) {
        dpif_ops[i] = &flow_miss_ops[i].dpif_op;
    }
    dpif_operate(ofproto->dpif, dpif_ops, n_ops);

    /* Free memory and update facets. */
    for (i = 0; i < n_ops; i++) {
        struct flow_miss_op *op = &flow_miss_ops[i];
        struct dpif_execute *execute;
        struct dpif_flow_put *put;

        switch (op->dpif_op.type) {
        case DPIF_OP_EXECUTE:
            execute = &op->dpif_op.execute;
            if (op->subfacet->actions != execute->actions) {
                free((struct nlattr *) execute->actions);
            }
            ofpbuf_delete((struct ofpbuf *) execute->packet);
            break;

        case DPIF_OP_FLOW_PUT:
            put = &op->dpif_op.flow_put;
            if (!put->error) {
                op->subfacet->installed = true;
            }
            break;
        }
    }
}

static void
handle_userspace_upcall(struct ofproto_dpif *ofproto,
                        struct dpif_upcall *upcall)
{
    struct user_action_cookie cookie;
    enum odp_key_fitness fitness;
    ovs_be16 initial_tci;
    struct flow flow;

    memcpy(&cookie, &upcall->userdata, sizeof(cookie));

    fitness = ofproto_dpif_extract_flow_key(ofproto, upcall->key,
                                            upcall->key_len, &flow,
                                            &initial_tci, upcall->packet);
    if (fitness == ODP_FIT_ERROR) {
        ofpbuf_delete(upcall->packet);
        return;
    }

    if (cookie.type == USER_ACTION_COOKIE_SFLOW) {
        if (ofproto->sflow) {
            dpif_sflow_received(ofproto->sflow, upcall->packet, &flow,
                                &cookie);
        }
        ofpbuf_delete(upcall->packet);
    } else if (cookie.type == USER_ACTION_COOKIE_CONTROLLER) {
        COVERAGE_INC(ofproto_dpif_ctlr_action);
        send_packet_in_action(ofproto, upcall->packet, upcall->userdata,
                              &flow, false);
    } else {
        VLOG_WARN_RL(&rl, "invalid user cookie : 0x%"PRIx64, upcall->userdata);
        ofpbuf_delete(upcall->packet);
    }
}

static int
handle_upcalls(struct ofproto_dpif *ofproto, unsigned int max_batch)
{
    struct dpif_upcall misses[FLOW_MISS_MAX_BATCH];
    int n_misses;
    int i;

    assert (max_batch <= FLOW_MISS_MAX_BATCH);

    n_misses = 0;
    for (i = 0; i < max_batch; i++) {
        struct dpif_upcall *upcall = &misses[n_misses];
        int error;

        error = dpif_recv(ofproto->dpif, upcall);
        if (error) {
            break;
        }

        switch (upcall->type) {
        case DPIF_UC_ACTION:
            handle_userspace_upcall(ofproto, upcall);
            break;

        case DPIF_UC_MISS:
            /* Handle it later. */
            n_misses++;
            break;

        case DPIF_N_UC_TYPES:
        default:
            VLOG_WARN_RL(&rl, "upcall has unexpected type %"PRIu32,
                         upcall->type);
            break;
        }
    }

    handle_miss_upcalls(ofproto, misses, n_misses);

    return i;
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
    struct classifier *table;
    int dp_max_idle;

    /* Update stats for each flow in the datapath. */
    update_stats(ofproto);

    /* Expire subfacets that have been idle too long. */
    dp_max_idle = subfacet_max_idle(ofproto);
    expire_subfacets(ofproto, dp_max_idle);

    /* Expire OpenFlow flows whose idle_timeout or hard_timeout has passed. */
    OFPROTO_FOR_EACH_TABLE (table, &ofproto->up) {
        struct cls_cursor cursor;

        cls_cursor_init(&cursor, table, NULL);
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
        if (subfacet && subfacet->installed) {
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

            subfacet_update_time(p, subfacet, stats->used);
            facet_account(p, facet);
            facet_push_stats(facet);
        } else {
            if (!VLOG_DROP_WARN(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_key_format(key, key_len, &s);
                VLOG_WARN("unexpected flow from datapath %s", ds_cstr(&s));
                ds_destroy(&s);
            }

            COVERAGE_INC(facet_unexpected);
            /* There's a flow in the datapath that we know nothing about, or a
             * flow that shouldn't be installed but was anyway.  Delete it. */
            dpif_flow_del(p->dpif, key, key_len, NULL);
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

static void
expire_subfacets(struct ofproto_dpif *ofproto, int dp_max_idle)
{
    long long int cutoff = time_msec() - dp_max_idle;
    struct subfacet *subfacet, *next_subfacet;

    HMAP_FOR_EACH_SAFE (subfacet, next_subfacet, hmap_node,
                        &ofproto->subfacets) {
        if (subfacet->used < cutoff) {
            subfacet_destroy(ofproto, subfacet);
        }
    }
}

/* If 'rule' is an OpenFlow rule, that has expired according to OpenFlow rules,
 * then delete it entirely. */
static void
rule_expire(struct rule_dpif *rule)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    struct facet *facet, *next_facet;
    long long int now;
    uint8_t reason;

    /* Has 'rule' expired? */
    now = time_msec();
    if (rule->up.hard_timeout
        && now > rule->up.modified + rule->up.hard_timeout * 1000) {
        reason = OFPRR_HARD_TIMEOUT;
    } else if (rule->up.idle_timeout && list_is_empty(&rule->facets)
               && now > rule->used + rule->up.idle_timeout * 1000) {
        reason = OFPRR_IDLE_TIMEOUT;
    } else {
        return;
    }

    COVERAGE_INC(ofproto_dpif_expired);

    /* Update stats.  (This is a no-op if the rule expired due to an idle
     * timeout, because that only happens when the rule has no facets left.) */
    LIST_FOR_EACH_SAFE (facet, next_facet, list_node, &rule->facets) {
        facet_remove(ofproto, facet);
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
 * The facet will initially have no subfacets.  The caller should create (at
 * least) one subfacet with subfacet_create(). */
static struct facet *
facet_create(struct rule_dpif *rule, const struct flow *flow)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    struct facet *facet;

    facet = xzalloc(sizeof *facet);
    facet->used = time_msec();
    hmap_insert(&ofproto->facets, &facet->hmap_node, flow_hash(flow, 0));
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

/* If the 'actions_len' bytes of actions in 'odp_actions' are just a single
 * OVS_ACTION_ATTR_USERSPACE action, executes it internally and returns true.
 * Otherwise, returns false without doing anything.
 *
 * If 'clone' is true, the caller always retains ownership of 'packet'.
 * Otherwise, ownership is transferred to this function if it returns true. */
static bool
execute_controller_action(struct ofproto_dpif *ofproto,
                          const struct flow *flow,
                          const struct nlattr *odp_actions, size_t actions_len,
                          struct ofpbuf *packet, bool clone)
{
    if (actions_len
        && odp_actions->nla_type == OVS_ACTION_ATTR_USERSPACE
        && NLA_ALIGN(odp_actions->nla_len) == actions_len) {
        /* As an optimization, avoid a round-trip from userspace to kernel to
         * userspace.  This also avoids possibly filling up kernel packet
         * buffers along the way.
         *
         * This optimization will not accidentally catch sFlow
         * OVS_ACTION_ATTR_USERSPACE actions, since those are encapsulated
         * inside OVS_ACTION_ATTR_SAMPLE. */
        const struct nlattr *nla;

        nla = nl_attr_find_nested(odp_actions, OVS_USERSPACE_ATTR_USERDATA);
        send_packet_in_action(ofproto, packet, nl_attr_get_u64(nla), flow,
                              clone);
        return true;
    } else {
        return false;
    }
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

    if (execute_controller_action(ofproto, flow, odp_actions, actions_len,
                                  packet, false)) {
        return true;
    }

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
facet_remove(struct ofproto_dpif *ofproto, struct facet *facet)
{
    struct subfacet *subfacet, *next_subfacet;

    assert(!list_is_empty(&facet->subfacets));

    /* First uninstall all of the subfacets to get final statistics. */
    LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
        subfacet_uninstall(ofproto, subfacet);
    }

    /* Flush the final stats to the rule.
     *
     * This might require us to have at least one subfacet around so that we
     * can use its actions for accounting in facet_account(), which is why we
     * have uninstalled but not yet destroyed the subfacets. */
    facet_flush_stats(ofproto, facet);

    /* Now we're really all done so destroy everything. */
    LIST_FOR_EACH_SAFE (subfacet, next_subfacet, list_node,
                        &facet->subfacets) {
        subfacet_destroy__(ofproto, subfacet);
    }
    hmap_remove(&ofproto->facets, &facet->hmap_node);
    list_remove(&facet->list_node);
    facet_free(facet);
}

static void
facet_account(struct ofproto_dpif *ofproto, struct facet *facet)
{
    uint64_t n_bytes;
    struct subfacet *subfacet;
    const struct nlattr *a;
    unsigned int left;
    ovs_be16 vlan_tci;

    if (facet->byte_count <= facet->accounted_bytes) {
        return;
    }
    n_bytes = facet->byte_count - facet->accounted_bytes;
    facet->accounted_bytes = facet->byte_count;

    /* Feed information from the active flows back into the learning table to
     * ensure that table is always in sync with what is actually flowing
     * through the datapath. */
    if (facet->has_learn || facet->has_normal) {
        struct action_xlate_ctx ctx;

        action_xlate_ctx_init(&ctx, ofproto, &facet->flow,
                              facet->flow.vlan_tci, NULL);
        ctx.may_learn = true;
        ofpbuf_delete(xlate_actions(&ctx, facet->rule->up.actions,
                                    facet->rule->up.n_actions));
    }

    if (!facet->has_normal || !ofproto->has_bonded_bundles) {
        return;
    }

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
    return (facet
            && facet->rule->up.n_actions == 1
            && action_outputs_to_port(&facet->rule->up.actions[0],
                                      htons(OFPP_CONTROLLER)));
}

/* Folds all of 'facet''s statistics into its rule.  Also updates the
 * accounting ofhook and emits a NetFlow expiration if appropriate.  All of
 * 'facet''s statistics in the datapath should have been zeroed and folded into
 * its packet and byte counts before this function is called. */
static void
facet_flush_stats(struct ofproto_dpif *ofproto, struct facet *facet)
{
    struct subfacet *subfacet;

    LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
        assert(!subfacet->dp_byte_count);
        assert(!subfacet->dp_packet_count);
    }

    facet_push_stats(facet);
    facet_account(ofproto, facet);

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
}

/* Searches 'ofproto''s table of facets for one exactly equal to 'flow'.
 * Returns it if found, otherwise a null pointer.
 *
 * The returned facet might need revalidation; use facet_lookup_valid()
 * instead if that is important. */
static struct facet *
facet_find(struct ofproto_dpif *ofproto, const struct flow *flow)
{
    struct facet *facet;

    HMAP_FOR_EACH_WITH_HASH (facet, hmap_node, flow_hash(flow, 0),
                             &ofproto->facets) {
        if (flow_equal(flow, &facet->flow)) {
            return facet;
        }
    }

    return NULL;
}

/* Searches 'ofproto''s table of facets for one exactly equal to 'flow'.
 * Returns it if found, otherwise a null pointer.
 *
 * The returned facet is guaranteed to be valid. */
static struct facet *
facet_lookup_valid(struct ofproto_dpif *ofproto, const struct flow *flow)
{
    struct facet *facet = facet_find(ofproto, flow);

    /* The facet we found might not be valid, since we could be in need of
     * revalidation.  If it is not valid, don't return it. */
    if (facet
        && (ofproto->need_revalidate
            || tag_set_intersects(&ofproto->revalidate_set, facet->tags))
        && !facet_revalidate(ofproto, facet)) {
        COVERAGE_INC(facet_invalidated);
        return NULL;
    }

    return facet;
}

/* Re-searches 'ofproto''s classifier for a rule matching 'facet':
 *
 *   - If the rule found is different from 'facet''s current rule, moves
 *     'facet' to the new rule and recompiles its actions.
 *
 *   - If the rule found is the same as 'facet''s current rule, leaves 'facet'
 *     where it is and recompiles its actions anyway.
 *
 *   - If there is none, destroys 'facet'.
 *
 * Returns true if 'facet' still exists, false if it has been destroyed. */
static bool
facet_revalidate(struct ofproto_dpif *ofproto, struct facet *facet)
{
    struct actions {
        struct nlattr *odp_actions;
        size_t actions_len;
    };
    struct actions *new_actions;

    struct action_xlate_ctx ctx;
    struct rule_dpif *new_rule;
    struct subfacet *subfacet;
    bool actions_changed;
    int i;

    COVERAGE_INC(facet_revalidate);

    /* Determine the new rule. */
    new_rule = rule_dpif_lookup(ofproto, &facet->flow, 0);
    if (!new_rule) {
        /* No new rule, so delete the facet. */
        facet_remove(ofproto, facet);
        return false;
    }

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
    LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
        struct ofpbuf *odp_actions;
        bool should_install;

        action_xlate_ctx_init(&ctx, ofproto, &facet->flow,
                              subfacet->initial_tci, NULL);
        odp_actions = xlate_actions(&ctx, new_rule->up.actions,
                                    new_rule->up.n_actions);
        actions_changed = (subfacet->actions_len != odp_actions->size
                           || memcmp(subfacet->actions, odp_actions->data,
                                     subfacet->actions_len));

        should_install = (ctx.may_set_up_flow
                          && subfacet->key_fitness != ODP_FIT_TOO_LITTLE);
        if (actions_changed || should_install != subfacet->installed) {
            if (should_install) {
                struct dpif_flow_stats stats;

                subfacet_install(ofproto, subfacet,
                                 odp_actions->data, odp_actions->size, &stats);
                subfacet_update_stats(ofproto, subfacet, &stats);
            } else {
                subfacet_uninstall(ofproto, subfacet);
            }

            if (!new_actions) {
                new_actions = xcalloc(list_size(&facet->subfacets),
                                      sizeof *new_actions);
            }
            new_actions[i].odp_actions = xmemdup(odp_actions->data,
                                                 odp_actions->size);
            new_actions[i].actions_len = odp_actions->size;
        }

        ofpbuf_delete(odp_actions);
        i++;
    }
    if (new_actions) {
        facet_flush_stats(ofproto, facet);
    }

    /* Update 'facet' now that we've taken care of all the old state. */
    facet->tags = ctx.tags;
    facet->nf_flow.output_iface = ctx.nf_output_iface;
    facet->may_install = ctx.may_set_up_flow;
    facet->has_learn = ctx.has_learn;
    facet->has_normal = ctx.has_normal;
    facet->mirrors = ctx.mirrors;
    if (new_actions) {
        i = 0;
        LIST_FOR_EACH (subfacet, list_node, &facet->subfacets) {
            if (new_actions[i].odp_actions) {
                free(subfacet->actions);
                subfacet->actions = new_actions[i].odp_actions;
                subfacet->actions_len = new_actions[i].actions_len;
            }
            i++;
        }
        free(new_actions);
    }
    if (facet->rule != new_rule) {
        COVERAGE_INC(facet_changed_rule);
        list_remove(&facet->list_node);
        list_push_back(&new_rule->facets, &facet->list_node);
        facet->rule = new_rule;
        facet->used = new_rule->up.created;
        facet->prev_used = facet->used;
    }

    return true;
}

/* Updates 'facet''s used time.  Caller is responsible for calling
 * facet_push_stats() to update the flows which 'facet' resubmits into. */
static void
facet_update_time(struct ofproto_dpif *ofproto, struct facet *facet,
                  long long int used)
{
    if (used > facet->used) {
        facet->used = used;
        if (used > facet->rule->used) {
            facet->rule->used = used;
        }
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
    uint64_t new_packets, new_bytes;

    assert(facet->packet_count >= facet->prev_packet_count);
    assert(facet->byte_count >= facet->prev_byte_count);
    assert(facet->used >= facet->prev_used);

    new_packets = facet->packet_count - facet->prev_packet_count;
    new_bytes = facet->byte_count - facet->prev_byte_count;

    if (new_packets || new_bytes || facet->used > facet->prev_used) {
        facet->prev_packet_count = facet->packet_count;
        facet->prev_byte_count = facet->byte_count;
        facet->prev_used = facet->used;

        flow_push_stats(facet->rule, &facet->flow,
                        new_packets, new_bytes, facet->used);

        update_mirror_stats(ofproto_dpif_cast(facet->rule->up.ofproto),
                            facet->mirrors, new_packets, new_bytes);
    }
}

struct ofproto_push {
    struct action_xlate_ctx ctx;
    uint64_t packets;
    uint64_t bytes;
    long long int used;
};

static void
push_resubmit(struct action_xlate_ctx *ctx, struct rule_dpif *rule)
{
    struct ofproto_push *push = CONTAINER_OF(ctx, struct ofproto_push, ctx);

    if (rule) {
        rule->packet_count += push->packets;
        rule->byte_count += push->bytes;
        rule->used = MAX(push->used, rule->used);
    }
}

/* Pushes flow statistics to the rules which 'flow' resubmits into given
 * 'rule''s actions and mirrors. */
static void
flow_push_stats(const struct rule_dpif *rule,
                const struct flow *flow, uint64_t packets, uint64_t bytes,
                long long int used)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    struct ofproto_push push;

    push.packets = packets;
    push.bytes = bytes;
    push.used = used;

    action_xlate_ctx_init(&push.ctx, ofproto, flow, flow->vlan_tci, NULL);
    push.ctx.resubmit_hook = push_resubmit;
    ofpbuf_delete(xlate_actions(&push.ctx,
                                rule->up.actions, rule->up.n_actions));
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
subfacet_create(struct ofproto_dpif *ofproto, struct facet *facet,
                enum odp_key_fitness key_fitness,
                const struct nlattr *key, size_t key_len, ovs_be16 initial_tci)
{
    uint32_t key_hash = odp_flow_key_hash(key, key_len);
    struct subfacet *subfacet;

    subfacet = subfacet_find__(ofproto, key, key_len, key_hash, &facet->flow);
    if (subfacet) {
        if (subfacet->facet == facet) {
            return subfacet;
        }

        /* This shouldn't happen. */
        VLOG_ERR_RL(&rl, "subfacet with wrong facet");
        subfacet_destroy(ofproto, subfacet);
    }

    subfacet = xzalloc(sizeof *subfacet);
    hmap_insert(&ofproto->subfacets, &subfacet->hmap_node, key_hash);
    list_push_back(&facet->subfacets, &subfacet->list_node);
    subfacet->facet = facet;
    subfacet->used = time_msec();
    subfacet->key_fitness = key_fitness;
    if (key_fitness != ODP_FIT_PERFECT) {
        subfacet->key = xmemdup(key, key_len);
        subfacet->key_len = key_len;
    }
    subfacet->installed = false;
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
subfacet_destroy__(struct ofproto_dpif *ofproto, struct subfacet *subfacet)
{
    subfacet_uninstall(ofproto, subfacet);
    hmap_remove(&ofproto->subfacets, &subfacet->hmap_node);
    list_remove(&subfacet->list_node);
    free(subfacet->key);
    free(subfacet->actions);
    free(subfacet);
}

/* Destroys 'subfacet', as with subfacet_destroy__(), and then if this was the
 * last remaining subfacet in its facet destroys the facet too. */
static void
subfacet_destroy(struct ofproto_dpif *ofproto, struct subfacet *subfacet)
{
    struct facet *facet = subfacet->facet;

    if (list_is_singleton(&facet->subfacets)) {
        /* facet_remove() needs at least one subfacet (it will remove it). */
        facet_remove(ofproto, facet);
    } else {
        subfacet_destroy__(ofproto, subfacet);
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

/* Composes the datapath actions for 'subfacet' based on its rule's actions. */
static void
subfacet_make_actions(struct ofproto_dpif *p, struct subfacet *subfacet,
                      const struct ofpbuf *packet)
{
    struct facet *facet = subfacet->facet;
    const struct rule_dpif *rule = facet->rule;
    struct ofpbuf *odp_actions;
    struct action_xlate_ctx ctx;

    action_xlate_ctx_init(&ctx, p, &facet->flow, subfacet->initial_tci,
                          packet);
    odp_actions = xlate_actions(&ctx, rule->up.actions, rule->up.n_actions);
    facet->tags = ctx.tags;
    facet->may_install = ctx.may_set_up_flow;
    facet->has_learn = ctx.has_learn;
    facet->has_normal = ctx.has_normal;
    facet->nf_flow.output_iface = ctx.nf_output_iface;
    facet->mirrors = ctx.mirrors;

    if (subfacet->actions_len != odp_actions->size
        || memcmp(subfacet->actions, odp_actions->data, odp_actions->size)) {
        free(subfacet->actions);
        subfacet->actions_len = odp_actions->size;
        subfacet->actions = xmemdup(odp_actions->data, odp_actions->size);
    }

    ofpbuf_delete(odp_actions);
}

/* Updates 'subfacet''s datapath flow, setting its actions to 'actions_len'
 * bytes of actions in 'actions'.  If 'stats' is non-null, statistics counters
 * in the datapath will be zeroed and 'stats' will be updated with traffic new
 * since 'subfacet' was last updated.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
subfacet_install(struct ofproto_dpif *ofproto, struct subfacet *subfacet,
                 const struct nlattr *actions, size_t actions_len,
                 struct dpif_flow_stats *stats)
{
    struct odputil_keybuf keybuf;
    enum dpif_flow_put_flags flags;
    struct ofpbuf key;
    int ret;

    flags = DPIF_FP_CREATE | DPIF_FP_MODIFY;
    if (stats) {
        flags |= DPIF_FP_ZERO_STATS;
    }

    subfacet_get_key(subfacet, &keybuf, &key);
    ret = dpif_flow_put(ofproto->dpif, flags, key.data, key.size,
                        actions, actions_len, stats);

    if (stats) {
        subfacet_reset_dp_stats(subfacet, stats);
    }

    return ret;
}

/* If 'subfacet' is installed in the datapath, uninstalls it. */
static void
subfacet_uninstall(struct ofproto_dpif *p, struct subfacet *subfacet)
{
    if (subfacet->installed) {
        struct odputil_keybuf keybuf;
        struct dpif_flow_stats stats;
        struct ofpbuf key;
        int error;

        subfacet_get_key(subfacet, &keybuf, &key);
        error = dpif_flow_del(p->dpif, key.data, key.size, &stats);
        subfacet_reset_dp_stats(subfacet, &stats);
        if (!error) {
            subfacet_update_stats(p, subfacet, &stats);
        }
        subfacet->installed = false;
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
subfacet_update_time(struct ofproto_dpif *ofproto, struct subfacet *subfacet,
                     long long int used)
{
    if (used > subfacet->used) {
        subfacet->used = used;
        facet_update_time(ofproto, subfacet->facet, used);
    }
}

/* Folds the statistics from 'stats' into the counters in 'subfacet'.
 *
 * Because of the meaning of a subfacet's counters, it only makes sense to do
 * this if 'stats' are not tracked in the datapath, that is, if 'stats'
 * represents a packet that was sent by hand or if it represents statistics
 * that have been cleared out of the datapath. */
static void
subfacet_update_stats(struct ofproto_dpif *ofproto, struct subfacet *subfacet,
                      const struct dpif_flow_stats *stats)
{
    if (stats->n_packets || stats->used > subfacet->used) {
        struct facet *facet = subfacet->facet;

        subfacet_update_time(ofproto, subfacet, stats->used);
        facet->packet_count += stats->n_packets;
        facet->byte_count += stats->n_bytes;
        facet_push_stats(facet);
        netflow_flow_update_flags(&facet->nf_flow, stats->tcp_flags);
    }
}

/* Rules. */

static struct rule_dpif *
rule_dpif_lookup(struct ofproto_dpif *ofproto, const struct flow *flow,
                 uint8_t table_id)
{
    struct cls_rule *cls_rule;
    struct classifier *cls;

    if (table_id >= N_TABLES) {
        return NULL;
    }

    cls = &ofproto->up.tables[table_id];
    if (flow->nw_frag & FLOW_NW_FRAG_ANY
        && ofproto->up.frag_handling == OFPC_FRAG_NORMAL) {
        /* For OFPC_NORMAL frag_handling, we must pretend that transport ports
         * are unavailable. */
        struct flow ofpc_normal_flow = *flow;
        ofpc_normal_flow.tp_src = htons(0);
        ofpc_normal_flow.tp_dst = htons(0);
        cls_rule = classifier_lookup(cls, &ofpc_normal_flow);
    } else {
        cls_rule = classifier_lookup(cls, flow);
    }
    return rule_dpif_cast(rule_from_cls_rule(cls_rule));
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

static int
rule_construct(struct rule *rule_)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    struct rule_dpif *victim;
    uint8_t table_id;
    int error;

    error = validate_actions(rule->up.actions, rule->up.n_actions,
                             &rule->up.cr.flow, ofproto->max_ports);
    if (error) {
        return error;
    }

    rule->used = rule->up.created;
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
    rule->tag = (victim ? victim->tag
                 : table_id == 0 ? 0
                 : rule_calculate_tag(&rule->up.cr.flow, &rule->up.cr.wc,
                                      ofproto->tables[table_id].basis));

    complete_operation(rule);
    return 0;
}

static void
rule_destruct(struct rule *rule_)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    struct facet *facet, *next_facet;

    LIST_FOR_EACH_SAFE (facet, next_facet, list_node, &rule->facets) {
        facet_revalidate(ofproto, facet);
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

static int
rule_execute(struct rule *rule_, const struct flow *flow,
             struct ofpbuf *packet)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    struct action_xlate_ctx ctx;
    struct ofpbuf *odp_actions;
    size_t size;

    action_xlate_ctx_init(&ctx, ofproto, flow, flow->vlan_tci, packet);
    odp_actions = xlate_actions(&ctx, rule->up.actions, rule->up.n_actions);
    size = packet->size;
    if (execute_odp_actions(ofproto, flow, odp_actions->data,
                            odp_actions->size, packet)) {
        rule->used = time_msec();
        rule->packet_count++;
        rule->byte_count += size;
        flow_push_stats(rule, flow, 1, size, rule->used);
    }
    ofpbuf_delete(odp_actions);

    return 0;
}

static void
rule_modify_actions(struct rule *rule_)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(rule->up.ofproto);
    int error;

    error = validate_actions(rule->up.actions, rule->up.n_actions,
                             &rule->up.cr.flow, ofproto->max_ports);
    if (error) {
        ofoperation_complete(rule->up.pending, error);
        return;
    }

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

    flow_extract((struct ofpbuf *) packet, 0, 0, 0, &flow);
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
    return error;
}

/* OpenFlow to datapath action translation. */

static void do_xlate_actions(const union ofp_action *in, size_t n_in,
                             struct action_xlate_ctx *ctx);
static void xlate_normal(struct action_xlate_ctx *);

static size_t
put_userspace_action(const struct ofproto_dpif *ofproto,
                     struct ofpbuf *odp_actions,
                     const struct flow *flow,
                     const struct user_action_cookie *cookie)
{
    uint32_t pid;

    pid = dpif_port_get_pid(ofproto->dpif,
                            ofp_port_to_odp_port(flow->in_port));

    return odp_put_userspace_action(pid, cookie, odp_actions);
}

/* Compose SAMPLE action for sFlow. */
static size_t
compose_sflow_action(const struct ofproto_dpif *ofproto,
                     struct ofpbuf *odp_actions,
                     const struct flow *flow,
                     uint32_t odp_port)
{
    uint32_t port_ifindex;
    uint32_t probability;
    struct user_action_cookie cookie;
    size_t sample_offset, actions_offset;
    int cookie_offset, n_output;

    if (!ofproto->sflow || flow->in_port == OFPP_NONE) {
        return 0;
    }

    if (odp_port == OVSP_NONE) {
        port_ifindex = 0;
        n_output = 0;
    } else {
        port_ifindex = dpif_sflow_odp_port_to_ifindex(ofproto->sflow, odp_port);
        n_output = 1;
    }

    sample_offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_SAMPLE);

    /* Number of packets out of UINT_MAX to sample. */
    probability = dpif_sflow_get_probability(ofproto->sflow);
    nl_msg_put_u32(odp_actions, OVS_SAMPLE_ATTR_PROBABILITY, probability);

    actions_offset = nl_msg_start_nested(odp_actions, OVS_SAMPLE_ATTR_ACTIONS);

    cookie.type = USER_ACTION_COOKIE_SFLOW;
    cookie.data = port_ifindex;
    cookie.n_output = n_output;
    cookie.vlan_tci = 0;
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
    struct user_action_cookie *cookie;

    if (!ctx->user_cookie_offset) {
        return;
    }

    cookie = ofpbuf_at(ctx->odp_actions, ctx->user_cookie_offset,
                     sizeof(*cookie));
    assert(cookie != NULL);
    assert(cookie->type == USER_ACTION_COOKIE_SFLOW);

    if (ctx->sflow_n_outputs) {
        cookie->data = dpif_sflow_odp_port_to_ifindex(ctx->ofproto->sflow,
                                                    ctx->sflow_odp_port);
    }
    if (ctx->sflow_n_outputs >= 255) {
        cookie->n_output = 255;
    } else {
        cookie->n_output = ctx->sflow_n_outputs;
    }
    cookie->vlan_tci = base->vlan_tci;
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

        if (ofport->up.opp.config & htonl(OFPPC_NO_FWD)
            || (check_stp && !stp_forward_in_state(ofport->stp_state))) {
            return;
        }

        pdscp = get_priority(ofport, ctx->flow.priority);
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
                   uint16_t in_port, uint8_t table_id)
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
        rule = rule_dpif_lookup(ofproto, &ctx->flow, table_id);

        /* Tag the flow. */
        if (table_id > 0 && table_id < N_TABLES) {
            struct table_dpif *table = &ofproto->tables[table_id];
            if (table->other_table) {
                ctx->tags |= (rule
                              ? rule->tag
                              : rule_calculate_tag(&ctx->flow,
                                                   &table->other_table->wc,
                                                   table->basis));
            }
        }

        /* Restore the original input port.  Otherwise OFPP_NORMAL and
         * OFPP_IN_PORT will have surprising behavior. */
        ctx->flow.in_port = old_in_port;

        if (ctx->resubmit_hook) {
            ctx->resubmit_hook(ctx, rule);
        }

        if (rule) {
            ctx->recurse++;
            do_xlate_actions(rule->up.actions, rule->up.n_actions, ctx);
            ctx->recurse--;
        }

        ctx->table_id = old_table_id;
    } else {
        static struct vlog_rate_limit recurse_rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&recurse_rl, "resubmit actions recursed over %d times",
                    MAX_RESUBMIT_RECURSION);
    }
}

static void
xlate_resubmit_table(struct action_xlate_ctx *ctx,
                     const struct nx_action_resubmit *nar)
{
    uint16_t in_port;
    uint8_t table_id;

    in_port = (nar->in_port == htons(OFPP_IN_PORT)
               ? ctx->flow.in_port
               : ntohs(nar->in_port));
    table_id = nar->table == 255 ? ctx->table_id : nar->table;

    xlate_table_action(ctx, in_port, table_id);
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
        } else if (!(ofport->up.opp.config & htonl(OFPPC_NO_FLOOD))) {
            compose_output_action(ctx, ofp_port);
        }
    }

    ctx->nf_output_iface = NF_OUT_FLOOD;
}

static void
compose_controller_action(struct action_xlate_ctx *ctx, int len)
{
    struct user_action_cookie cookie;

    commit_odp_actions(&ctx->flow, &ctx->base_flow, ctx->odp_actions);
    cookie.type = USER_ACTION_COOKIE_CONTROLLER;
    cookie.data = len;
    cookie.n_output = 0;
    cookie.vlan_tci = 0;
    put_userspace_action(ctx->ofproto, ctx->odp_actions, &ctx->flow, &cookie);
}

static void
xlate_output_action__(struct action_xlate_ctx *ctx,
                      uint16_t port, uint16_t max_len)
{
    uint16_t prev_nf_output_iface = ctx->nf_output_iface;

    ctx->nf_output_iface = NF_OUT_DROP;

    switch (port) {
    case OFPP_IN_PORT:
        compose_output_action(ctx, ctx->flow.in_port);
        break;
    case OFPP_TABLE:
        xlate_table_action(ctx, ctx->flow.in_port, ctx->table_id);
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
        compose_controller_action(ctx, max_len);
        break;
    case OFPP_LOCAL:
        compose_output_action(ctx, OFPP_LOCAL);
        break;
    case OFPP_NONE:
        break;
    default:
        if (port != ctx->flow.in_port) {
            compose_output_action(ctx, port);
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
                        const struct nx_action_output_reg *naor)
{
    uint64_t ofp_port;

    ofp_port = nxm_read_field_bits(naor->src, naor->ofs_nbits, &ctx->flow);

    if (ofp_port <= UINT16_MAX) {
        xlate_output_action__(ctx, ofp_port, ntohs(naor->max_len));
    }
}

static void
xlate_output_action(struct action_xlate_ctx *ctx,
                    const struct ofp_action_output *oao)
{
    xlate_output_action__(ctx, ntohs(oao->port), ntohs(oao->max_len));
}

static void
xlate_enqueue_action(struct action_xlate_ctx *ctx,
                     const struct ofp_action_enqueue *oae)
{
    uint16_t ofp_port;
    uint32_t flow_priority, priority;
    int error;

    error = dpif_queue_to_priority(ctx->ofproto->dpif, ntohl(oae->queue_id),
                                   &priority);
    if (error) {
        /* Fall back to ordinary output action. */
        xlate_output_action__(ctx, ntohs(oae->port), 0);
        return;
    }

    /* Figure out datapath output port. */
    ofp_port = ntohs(oae->port);
    if (ofp_port == OFPP_IN_PORT) {
        ofp_port = ctx->flow.in_port;
    } else if (ofp_port == ctx->flow.in_port) {
        return;
    }

    /* Add datapath actions. */
    flow_priority = ctx->flow.priority;
    ctx->flow.priority = priority;
    compose_output_action(ctx, ofp_port);
    ctx->flow.priority = flow_priority;

    /* Update NetFlow output port. */
    if (ctx->nf_output_iface == NF_OUT_DROP) {
        ctx->nf_output_iface = ofp_port;
    } else if (ctx->nf_output_iface != NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_MULTI;
    }
}

static void
xlate_set_queue_action(struct action_xlate_ctx *ctx,
                       const struct nx_action_set_queue *nasq)
{
    uint32_t priority;
    int error;

    error = dpif_queue_to_priority(ctx->ofproto->dpif, ntohl(nasq->queue_id),
                                   &priority);
    if (error) {
        /* Couldn't translate queue to a priority, so ignore.  A warning
         * has already been logged. */
        return;
    }

    ctx->flow.priority = priority;
}

struct xlate_reg_state {
    ovs_be16 vlan_tci;
    ovs_be64 tun_id;
};

static void
xlate_autopath(struct action_xlate_ctx *ctx,
               const struct nx_action_autopath *naa)
{
    uint16_t ofp_port = ntohl(naa->id);
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
    autopath_execute(naa, &ctx->flow, ofp_port);
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
xlate_learn_action(struct action_xlate_ctx *ctx,
                   const struct nx_action_learn *learn)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    struct ofputil_flow_mod fm;
    int error;

    learn_execute(learn, &ctx->flow, &fm);

    error = ofproto_flow_mod(&ctx->ofproto->up, &fm);
    if (error && !VLOG_DROP_WARN(&rl)) {
        char *msg = ofputil_error_to_string(error);
        VLOG_WARN("learning action failed to modify flow table (%s)", msg);
        free(msg);
    }

    free(fm.actions);
}

static bool
may_receive(const struct ofport_dpif *port, struct action_xlate_ctx *ctx)
{
    if (port->up.opp.config & (eth_addr_equals(ctx->flow.dl_dst, eth_addr_stp)
                               ? htonl(OFPPC_NO_RECV_STP)
                               : htonl(OFPPC_NO_RECV))) {
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
do_xlate_actions(const union ofp_action *in, size_t n_in,
                 struct action_xlate_ctx *ctx)
{
    const struct ofport_dpif *port;
    const union ofp_action *ia;
    size_t left;

    port = get_ofp_port(ctx->ofproto, ctx->flow.in_port);
    if (port && !may_receive(port, ctx)) {
        /* Drop this flow. */
        return;
    }

    OFPUTIL_ACTION_FOR_EACH_UNSAFE (ia, left, in, n_in) {
        const struct ofp_action_dl_addr *oada;
        const struct nx_action_resubmit *nar;
        const struct nx_action_set_tunnel *nast;
        const struct nx_action_set_queue *nasq;
        const struct nx_action_multipath *nam;
        const struct nx_action_autopath *naa;
        const struct nx_action_bundle *nab;
        const struct nx_action_output_reg *naor;
        enum ofputil_action_code code;
        ovs_be64 tun_id;

        if (ctx->exit) {
            break;
        }

        code = ofputil_decode_action_unsafe(ia);
        switch (code) {
        case OFPUTIL_OFPAT_OUTPUT:
            xlate_output_action(ctx, &ia->output);
            break;

        case OFPUTIL_OFPAT_SET_VLAN_VID:
            ctx->flow.vlan_tci &= ~htons(VLAN_VID_MASK);
            ctx->flow.vlan_tci |= ia->vlan_vid.vlan_vid | htons(VLAN_CFI);
            break;

        case OFPUTIL_OFPAT_SET_VLAN_PCP:
            ctx->flow.vlan_tci &= ~htons(VLAN_PCP_MASK);
            ctx->flow.vlan_tci |= htons(
                (ia->vlan_pcp.vlan_pcp << VLAN_PCP_SHIFT) | VLAN_CFI);
            break;

        case OFPUTIL_OFPAT_STRIP_VLAN:
            ctx->flow.vlan_tci = htons(0);
            break;

        case OFPUTIL_OFPAT_SET_DL_SRC:
            oada = ((struct ofp_action_dl_addr *) ia);
            memcpy(ctx->flow.dl_src, oada->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPUTIL_OFPAT_SET_DL_DST:
            oada = ((struct ofp_action_dl_addr *) ia);
            memcpy(ctx->flow.dl_dst, oada->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPUTIL_OFPAT_SET_NW_SRC:
            ctx->flow.nw_src = ia->nw_addr.nw_addr;
            break;

        case OFPUTIL_OFPAT_SET_NW_DST:
            ctx->flow.nw_dst = ia->nw_addr.nw_addr;
            break;

        case OFPUTIL_OFPAT_SET_NW_TOS:
            ctx->flow.nw_tos &= ~IP_DSCP_MASK;
            ctx->flow.nw_tos |= ia->nw_tos.nw_tos & IP_DSCP_MASK;
            break;

        case OFPUTIL_OFPAT_SET_TP_SRC:
            ctx->flow.tp_src = ia->tp_port.tp_port;
            break;

        case OFPUTIL_OFPAT_SET_TP_DST:
            ctx->flow.tp_dst = ia->tp_port.tp_port;
            break;

        case OFPUTIL_OFPAT_ENQUEUE:
            xlate_enqueue_action(ctx, (const struct ofp_action_enqueue *) ia);
            break;

        case OFPUTIL_NXAST_RESUBMIT:
            nar = (const struct nx_action_resubmit *) ia;
            xlate_table_action(ctx, ntohs(nar->in_port), ctx->table_id);
            break;

        case OFPUTIL_NXAST_RESUBMIT_TABLE:
            xlate_resubmit_table(ctx, (const struct nx_action_resubmit *) ia);
            break;

        case OFPUTIL_NXAST_SET_TUNNEL:
            nast = (const struct nx_action_set_tunnel *) ia;
            tun_id = htonll(ntohl(nast->tun_id));
            ctx->flow.tun_id = tun_id;
            break;

        case OFPUTIL_NXAST_SET_QUEUE:
            nasq = (const struct nx_action_set_queue *) ia;
            xlate_set_queue_action(ctx, nasq);
            break;

        case OFPUTIL_NXAST_POP_QUEUE:
            ctx->flow.priority = ctx->original_priority;
            break;

        case OFPUTIL_NXAST_REG_MOVE:
            nxm_execute_reg_move((const struct nx_action_reg_move *) ia,
                                 &ctx->flow);
            break;

        case OFPUTIL_NXAST_REG_LOAD:
            nxm_execute_reg_load((const struct nx_action_reg_load *) ia,
                                 &ctx->flow);
            break;

        case OFPUTIL_NXAST_NOTE:
            /* Nothing to do. */
            break;

        case OFPUTIL_NXAST_SET_TUNNEL64:
            tun_id = ((const struct nx_action_set_tunnel64 *) ia)->tun_id;
            ctx->flow.tun_id = tun_id;
            break;

        case OFPUTIL_NXAST_MULTIPATH:
            nam = (const struct nx_action_multipath *) ia;
            multipath_execute(nam, &ctx->flow);
            break;

        case OFPUTIL_NXAST_AUTOPATH:
            naa = (const struct nx_action_autopath *) ia;
            xlate_autopath(ctx, naa);
            break;

        case OFPUTIL_NXAST_BUNDLE:
            ctx->ofproto->has_bundle_action = true;
            nab = (const struct nx_action_bundle *) ia;
            xlate_output_action__(ctx, bundle_execute(nab, &ctx->flow,
                                                      slave_enabled_cb,
                                                      ctx->ofproto), 0);
            break;

        case OFPUTIL_NXAST_BUNDLE_LOAD:
            ctx->ofproto->has_bundle_action = true;
            nab = (const struct nx_action_bundle *) ia;
            bundle_execute_load(nab, &ctx->flow, slave_enabled_cb,
                                ctx->ofproto);
            break;

        case OFPUTIL_NXAST_OUTPUT_REG:
            naor = (const struct nx_action_output_reg *) ia;
            xlate_output_reg_action(ctx, naor);
            break;

        case OFPUTIL_NXAST_LEARN:
            ctx->has_learn = true;
            if (ctx->may_learn) {
                xlate_learn_action(ctx, (const struct nx_action_learn *) ia);
            }
            break;

        case OFPUTIL_NXAST_EXIT:
            ctx->exit = true;
            break;
        }
    }

    /* We've let OFPP_NORMAL and the learning action look at the packet,
     * so drop it now if forwarding is disabled. */
    if (port && !stp_forward_in_state(port->stp_state)) {
        ofpbuf_clear(ctx->odp_actions);
        add_sflow_action(ctx);
    }
}

static void
action_xlate_ctx_init(struct action_xlate_ctx *ctx,
                      struct ofproto_dpif *ofproto, const struct flow *flow,
                      ovs_be16 initial_tci, const struct ofpbuf *packet)
{
    ctx->ofproto = ofproto;
    ctx->flow = *flow;
    ctx->base_flow = ctx->flow;
    ctx->base_flow.tun_id = 0;
    ctx->base_flow.vlan_tci = initial_tci;
    ctx->packet = packet;
    ctx->may_learn = packet != NULL;
    ctx->resubmit_hook = NULL;
}

static struct ofpbuf *
xlate_actions(struct action_xlate_ctx *ctx,
              const union ofp_action *in, size_t n_in)
{
    struct flow orig_flow = ctx->flow;

    COVERAGE_INC(ofproto_dpif_xlate);

    ctx->odp_actions = ofpbuf_new(512);
    ofpbuf_reserve(ctx->odp_actions, NL_A_U32_SIZE);
    ctx->tags = 0;
    ctx->may_set_up_flow = true;
    ctx->has_learn = false;
    ctx->has_normal = false;
    ctx->nf_output_iface = NF_OUT_DROP;
    ctx->mirrors = 0;
    ctx->recurse = 0;
    ctx->original_priority = ctx->flow.priority;
    ctx->table_id = 0;
    ctx->exit = false;

    if (ctx->flow.nw_frag & FLOW_NW_FRAG_ANY) {
        switch (ctx->ofproto->up.frag_handling) {
        case OFPC_FRAG_NORMAL:
            /* We must pretend that transport ports are unavailable. */
            ctx->flow.tp_src = ctx->base_flow.tp_src = htons(0);
            ctx->flow.tp_dst = ctx->base_flow.tp_dst = htons(0);
            break;

        case OFPC_FRAG_DROP:
            return ctx->odp_actions;

        case OFPC_FRAG_REASM:
            NOT_REACHED();

        case OFPC_FRAG_NX_MATCH:
            /* Nothing to do. */
            break;
        }
    }

    if (process_special(ctx->ofproto, &ctx->flow, ctx->packet)) {
        ctx->may_set_up_flow = false;
        return ctx->odp_actions;
    } else {
        add_sflow_action(ctx);
        do_xlate_actions(in, n_in, ctx);

        if (!connmgr_may_set_up_flow(ctx->ofproto->up.connmgr, &ctx->flow,
                                     ctx->odp_actions->data,
                                     ctx->odp_actions->size)) {
            ctx->may_set_up_flow = false;
            if (ctx->packet
                && connmgr_msg_in_hook(ctx->ofproto->up.connmgr, &ctx->flow,
                                       ctx->packet)) {
                compose_output_action(ctx, OFPP_LOCAL);
            }
        }
        add_mirror_actions(ctx, &orig_flow);
        fix_sflow_action(ctx);
    }

    return ctx->odp_actions;
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

/* Returns true if a packet with Ethernet destination MAC 'dst' may be mirrored
 * to a VLAN.  In general most packets may be mirrored but we want to drop
 * protocols that may confuse switches. */
static bool
eth_dst_may_rspan(const uint8_t dst[ETH_ADDR_LEN])
{
    /* If you change this function's behavior, please update corresponding
     * documentation in vswitch.xml at the same time. */
    if (dst[0] != 0x01) {
        /* All the currently banned MACs happen to start with 01 currently, so
         * this is a quick way to eliminate most of the good ones. */
    } else {
        if (eth_addr_is_reserved(dst)) {
            /* Drop STP, IEEE pause frames, and other reserved protocols
             * (01-80-c2-00-00-0x). */
            return false;
        }

        if (dst[0] == 0x01 && dst[1] == 0x00 && dst[2] == 0x0c) {
            /* Cisco OUI. */
            if ((dst[3] & 0xfe) == 0xcc &&
                (dst[4] & 0xfe) == 0xcc &&
                (dst[5] & 0xfe) == 0xcc) {
                /* Drop the following protocols plus others following the same
                   pattern:

                   CDP, VTP, DTP, PAgP  (01-00-0c-cc-cc-cc)
                   Spanning Tree PVSTP+ (01-00-0c-cc-cc-cd)
                   STP Uplink Fast      (01-00-0c-cd-cd-cd) */
                return false;
            }

            if (!(dst[3] | dst[4] | dst[5])) {
                /* Drop Inter Switch Link packets (01-00-0c-00-00-00). */
                return false;
            }
        }
    }
    return true;
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
                                    ctx->packet != NULL);
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
            mirrors &= mirrors - 1;
            continue;
        }

        mirrors &= ~m->dup_mirrors;
        ctx->mirrors |= m->dup_mirrors;
        if (m->out) {
            output_normal(ctx, m->out, vlan);
        } else if (eth_dst_may_rspan(orig_flow->dl_dst)
                   && vlan != m->out_vlan) {
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

    for (; mirrors; mirrors &= mirrors - 1) {
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
lookup_input_bundle(struct ofproto_dpif *ofproto, uint16_t in_port, bool warn)
{
    struct ofport_dpif *ofport;

    /* Special-case OFPP_NONE, which a controller may use as the ingress
     * port for traffic that it is sourcing. */
    if (in_port == OFPP_NONE) {
        return &ofpp_none_bundle;
    }

    /* Find the port and bundle for the received packet. */
    ofport = get_ofp_port(ofproto, in_port);
    if (ofport && ofport->bundle) {
        return ofport->bundle;
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
is_admissible(struct ofproto_dpif *ofproto, const struct flow *flow,
              struct ofport_dpif *in_port, uint16_t vlan, tag_type *tags)
{
    struct ofbundle *in_bundle = in_port->bundle;

    /* Drop frames for reserved multicast addresses
     * only if forward_bpdu option is absent. */
    if (eth_addr_is_reserved(flow->dl_dst) && !ofproto->up.forward_bpdu) {
        return false;
    }

    if (in_bundle->bond) {
        struct mac_entry *mac;

        switch (bond_check_admissibility(in_bundle->bond, in_port,
                                         flow->dl_dst, tags)) {
        case BV_ACCEPT:
            break;

        case BV_DROP:
            return false;

        case BV_DROP_IF_MOVED:
            mac = mac_learning_lookup(ofproto->ml, flow->dl_src, vlan, NULL);
            if (mac && mac->port.p != in_bundle &&
                (!is_gratuitous_arp(flow)
                 || mac_entry_is_grat_arp_locked(mac))) {
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
                                  ctx->packet != NULL);
    if (!in_bundle) {
        return;
    }

    /* We know 'in_port' exists unless it is "ofpp_none_bundle",
     * since lookup_input_bundle() succeeded. */
    in_port = get_ofp_port(ctx->ofproto, ctx->flow.in_port);

    /* Drop malformed frames. */
    if (ctx->flow.dl_type == htons(ETH_TYPE_VLAN) &&
        !(ctx->flow.vlan_tci & htons(VLAN_CFI))) {
        if (ctx->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet with partial "
                         "VLAN tag received on port %s",
                         ctx->ofproto->up.name, in_bundle->name);
        }
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
        return;
    }

    /* Check VLAN. */
    vid = vlan_tci_to_vid(ctx->flow.vlan_tci);
    if (!input_vid_is_valid(vid, in_bundle, ctx->packet != NULL)) {
        return;
    }
    vlan = input_vid_to_vlan(in_bundle, vid);

    /* Check other admissibility requirements. */
    if (in_port &&
         !is_admissible(ctx->ofproto, &ctx->flow, in_port, vlan, &ctx->tags)) {
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
            output_normal(ctx, mac->port.p, vlan);
        }
    } else if (!ctx->packet && !eth_addr_is_multicast(ctx->flow.dl_dst)) {
        /* If we are revalidating but don't have a learning entry then eject
         * the flow.  Installing a flow that floods packets opens up a window
         * of time where we could learn from a packet reflected on a bond and
         * blackhole packets before the learning table is updated to reflect
         * the correct port. */
        ctx->may_set_up_flow = false;
        return;
    } else {
        struct ofbundle *bundle;

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

/* Calculates the tag to use for 'flow' and wildcards 'wc' when it is inserted
 * into an OpenFlow table with the given 'basis'. */
static uint32_t
rule_calculate_tag(const struct flow *flow, const struct flow_wildcards *wc,
                   uint32_t secret)
{
    if (flow_wildcards_is_catchall(wc)) {
        return 0;
    } else {
        struct flow tag_flow = *flow;
        flow_zero_wildcards(&tag_flow, wc);
        return tag_create_deterministic(flow_hash(&tag_flow, secret));
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
    const struct classifier *cls = &ofproto->up.tables[table_id];
    struct cls_table *catchall, *other;
    struct cls_table *t;

    catchall = other = NULL;

    switch (hmap_count(&cls->tables)) {
    case 0:
        /* We could tag this OpenFlow table but it would make the logic a
         * little harder and it's a corner case that doesn't seem worth it
         * yet. */
        break;

    case 1:
    case 2:
        HMAP_FOR_EACH (t, hmap_node, &cls->tables) {
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
        ofproto->need_revalidate = true;
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
            ofproto->need_revalidate = true;
        }
    }
}

static bool
set_frag_handling(struct ofproto *ofproto_,
                  enum ofp_config_flags frag_handling)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);

    if (frag_handling != OFPC_FRAG_REASM) {
        ofproto->need_revalidate = true;
        return true;
    } else {
        return false;
    }
}

static int
packet_out(struct ofproto *ofproto_, struct ofpbuf *packet,
           const struct flow *flow,
           const union ofp_action *ofp_actions, size_t n_ofp_actions)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    int error;

    if (flow->in_port >= ofproto->max_ports && flow->in_port < OFPP_MAX) {
        return ofp_mkerr_nicira(OFPET_BAD_REQUEST, NXBRC_BAD_IN_PORT);
    }

    error = validate_actions(ofp_actions, n_ofp_actions, flow,
                             ofproto->max_ports);
    if (!error) {
        struct odputil_keybuf keybuf;
        struct action_xlate_ctx ctx;
        struct ofpbuf *odp_actions;
        struct ofpbuf key;

        ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
        odp_flow_key_from_flow(&key, flow);

        action_xlate_ctx_init(&ctx, ofproto, flow, flow->vlan_tci, packet);
        odp_actions = xlate_actions(&ctx, ofp_actions, n_ofp_actions);
        dpif_execute(ofproto->dpif, key.data, key.size,
                     odp_actions->data, odp_actions->size, packet);
        ofpbuf_delete(odp_actions);
    }
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
            if (subfacet->installed) {
                struct dpif_flow_stats stats;

                subfacet_install(ofproto, subfacet, subfacet->actions,
                                 subfacet->actions_len, &stats);
                subfacet_update_stats(ofproto, subfacet, &stats);
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
ofproto_unixctl_fdb_flush(struct unixctl_conn *conn,
                          const char *args, void *aux OVS_UNUSED)
{
    struct ofproto_dpif *ofproto;

    if (args[0] != '\0') {
        ofproto = ofproto_dpif_lookup(args);
        if (!ofproto) {
            unixctl_command_reply(conn, 501, "no such bridge");
            return;
        }
        mac_learning_flush(ofproto->ml);
        ofproto->need_revalidate = true;
    } else {
        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
            mac_learning_flush(ofproto->ml);
            ofproto->need_revalidate = true;
        }
    }

    unixctl_command_reply(conn, 200, "table successfully flushed");
}

static void
ofproto_unixctl_fdb_show(struct unixctl_conn *conn,
                         const char *args, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct ofproto_dpif *ofproto;
    const struct mac_entry *e;

    ofproto = ofproto_dpif_lookup(args);
    if (!ofproto) {
        unixctl_command_reply(conn, 501, "no such bridge");
        return;
    }

    ds_put_cstr(&ds, " port  VLAN  MAC                Age\n");
    LIST_FOR_EACH (e, lru_node, &ofproto->ml->lrus) {
        struct ofbundle *bundle = e->port.p;
        ds_put_format(&ds, "%5d  %4d  "ETH_ADDR_FMT"  %3d\n",
                      ofbundle_get_a_port(bundle)->odp_port,
                      e->vlan, ETH_ADDR_ARGS(e->mac), mac_entry_age(e));
    }
    unixctl_command_reply(conn, 200, ds_cstr(&ds));
    ds_destroy(&ds);
}

struct ofproto_trace {
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
    ofp_print_actions(result, rule->up.actions, rule->up.n_actions);
    ds_put_char(result, '\n');
}

static void
trace_format_flow(struct ds *result, int level, const char *title,
                 struct ofproto_trace *trace)
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
                  struct ofproto_trace *trace)
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
trace_resubmit(struct action_xlate_ctx *ctx, struct rule_dpif *rule)
{
    struct ofproto_trace *trace = CONTAINER_OF(ctx, struct ofproto_trace, ctx);
    struct ds *result = trace->result;

    ds_put_char(result, '\n');
    trace_format_flow(result, ctx->recurse + 1, "Resubmitted flow", trace);
    trace_format_regs(result, ctx->recurse + 1, "Resubmitted regs", trace);
    trace_format_rule(result, ctx->table_id, ctx->recurse + 1, rule);
}

static void
ofproto_unixctl_trace(struct unixctl_conn *conn, const char *args_,
                      void *aux OVS_UNUSED)
{
    char *dpname, *arg1, *arg2, *arg3, *arg4;
    char *args = xstrdup(args_);
    char *save_ptr = NULL;
    struct ofproto_dpif *ofproto;
    struct ofpbuf odp_key;
    struct ofpbuf *packet;
    struct rule_dpif *rule;
    ovs_be16 initial_tci;
    struct ds result;
    struct flow flow;
    char *s;

    packet = NULL;
    ofpbuf_init(&odp_key, 0);
    ds_init(&result);

    dpname = strtok_r(args, " ", &save_ptr);
    if (!dpname) {
        unixctl_command_reply(conn, 501, "Bad command syntax");
        goto exit;
    }

    ofproto = ofproto_dpif_lookup(dpname);
    if (!ofproto) {
        unixctl_command_reply(conn, 501, "Unknown ofproto (use ofproto/list "
                              "for help)");
        goto exit;
    }
    arg1 = strtok_r(NULL, " ", &save_ptr);
    arg2 = strtok_r(NULL, " ", &save_ptr);
    arg3 = strtok_r(NULL, " ", &save_ptr);
    arg4 = strtok_r(NULL, "", &save_ptr); /* Get entire rest of line. */
    if (dpname && arg1 && (!arg2 || !strcmp(arg2, "-generate")) && !arg3) {
        /* ofproto/trace dpname flow [-generate] */
        int error;

        /* Convert string to datapath key. */
        ofpbuf_init(&odp_key, 0);
        error = odp_flow_key_from_string(arg1, NULL, &odp_key);
        if (error) {
            unixctl_command_reply(conn, 501, "Bad flow syntax");
            goto exit;
        }

        /* Convert odp_key to flow. */
        error = ofproto_dpif_extract_flow_key(ofproto, odp_key.data,
                                              odp_key.size, &flow,
                                              &initial_tci, NULL);
        if (error == ODP_FIT_ERROR) {
            unixctl_command_reply(conn, 501, "Invalid flow");
            goto exit;
        }

        /* Generate a packet, if requested. */
        if (arg2) {
            packet = ofpbuf_new(0);
            flow_compose(packet, &flow);
        }
    } else if (dpname && arg1 && arg2 && arg3 && arg4) {
        /* ofproto/trace dpname priority tun_id in_port packet */
        uint16_t in_port;
        ovs_be64 tun_id;
        uint32_t priority;

        priority = atoi(arg1);
        tun_id = htonll(strtoull(arg2, NULL, 0));
        in_port = ofp_port_to_odp_port(atoi(arg3));

        packet = ofpbuf_new(strlen(args) / 2);
        arg4 = ofpbuf_put_hex(packet, arg4, NULL);
        arg4 += strspn(arg4, " ");
        if (*arg4 != '\0') {
            unixctl_command_reply(conn, 501, "Trailing garbage in command");
            goto exit;
        }
        if (packet->size < ETH_HEADER_LEN) {
            unixctl_command_reply(conn, 501,
                                  "Packet data too short for Ethernet");
            goto exit;
        }

        ds_put_cstr(&result, "Packet: ");
        s = ofp_packet_to_string(packet->data, packet->size, packet->size);
        ds_put_cstr(&result, s);
        free(s);

        flow_extract(packet, priority, tun_id, in_port, &flow);
        initial_tci = flow.vlan_tci;
    } else {
        unixctl_command_reply(conn, 501, "Bad command syntax");
        goto exit;
    }

    ds_put_cstr(&result, "Flow: ");
    flow_format(&result, &flow);
    ds_put_char(&result, '\n');

    rule = rule_dpif_lookup(ofproto, &flow, 0);
    trace_format_rule(&result, 0, 0, rule);
    if (rule) {
        struct ofproto_trace trace;
        struct ofpbuf *odp_actions;

        trace.result = &result;
        trace.flow = flow;
        action_xlate_ctx_init(&trace.ctx, ofproto, &flow, initial_tci, packet);
        trace.ctx.resubmit_hook = trace_resubmit;
        odp_actions = xlate_actions(&trace.ctx,
                                    rule->up.actions, rule->up.n_actions);

        ds_put_char(&result, '\n');
        trace_format_flow(&result, 0, "Final flow", &trace);
        ds_put_cstr(&result, "Datapath actions: ");
        format_odp_actions(&result, odp_actions->data, odp_actions->size);
        ofpbuf_delete(odp_actions);

        if (!trace.ctx.may_set_up_flow) {
            if (packet) {
                ds_put_cstr(&result, "\nThis flow is not cachable.");
            } else {
                ds_put_cstr(&result, "\nThe datapath actions are incomplete--"
                            "for complete actions, please supply a packet.");
            }
        }
    }

    unixctl_command_reply(conn, 200, ds_cstr(&result));

exit:
    ds_destroy(&result);
    ofpbuf_delete(packet);
    ofpbuf_uninit(&odp_key);
    free(args);
}

static void
ofproto_dpif_clog(struct unixctl_conn *conn OVS_UNUSED,
                  const char *args_ OVS_UNUSED, void *aux OVS_UNUSED)
{
    clogged = true;
    unixctl_command_reply(conn, 200, NULL);
}

static void
ofproto_dpif_unclog(struct unixctl_conn *conn OVS_UNUSED,
                    const char *args_ OVS_UNUSED, void *aux OVS_UNUSED)
{
    clogged = false;
    unixctl_command_reply(conn, 200, NULL);
}

static void
ofproto_dpif_unixctl_init(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    unixctl_command_register("ofproto/trace",
                      "bridge {tun_id in_port packet | odp_flow [-generate]}",
                      ofproto_unixctl_trace, NULL);
    unixctl_command_register("fdb/flush", "[bridge]",
                             ofproto_unixctl_fdb_flush, NULL);
    unixctl_command_register("fdb/show", "bridge", ofproto_unixctl_fdb_show,
                             NULL);
    unixctl_command_register("ofproto/clog", "", ofproto_dpif_clog, NULL);
    unixctl_command_register("ofproto/unclog", "", ofproto_dpif_unclog, NULL);
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

    ofproto->need_revalidate = true;

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
    get_cfm_remote_mpids,
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
    set_realdev,
};
