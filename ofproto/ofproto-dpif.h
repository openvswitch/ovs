/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef OFPROTO_DPIF_H
#define OFPROTO_DPIF_H 1

#include <stdint.h>

#include "hmapx.h"
#include "ofproto/ofproto-provider.h"
#include "tag.h"
#include "timer.h"
#include "util.h"

union user_action_cookie;

#define MAX_MIRRORS 32
typedef uint32_t mirror_mask_t;
#define MIRROR_MASK_C(X) UINT32_C(X)
BUILD_ASSERT_DECL(sizeof(mirror_mask_t) * CHAR_BIT >= MAX_MIRRORS);

/* Number of implemented OpenFlow tables. */
enum { N_TABLES = 255 };
enum { TBL_INTERNAL = N_TABLES - 1 };    /* Used for internal hidden rules. */
BUILD_ASSERT_DECL(N_TABLES >= 2 && N_TABLES <= 255);

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
    struct dpif_backer *backer;

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
    struct ofmirror *mirrors[MAX_MIRRORS];
    bool has_mirrors;
    bool has_bonded_bundles;

    /* Facets. */
    struct classifier facets;     /* Contains 'struct facet's. */
    long long int consistency_rl;

    /* Revalidation. */
    struct table_dpif tables[N_TABLES];

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

    /* Ports. */
    struct sset ports;             /* Set of standard port names. */
    struct sset ghost_ports;       /* Ports with no datapath port. */
    struct sset port_poll_set;     /* Queued names for port_poll() reply. */
    int port_poll_errno;           /* Last errno for port_poll() reply. */

    /* Per ofproto's dpif stats. */
    uint64_t n_hit;
    uint64_t n_missed;
};

struct ofport_dpif {
    struct hmap_node odp_port_node; /* In dpif_backer's "odp_to_ofport_map". */
    struct ofport up;

    odp_port_t odp_port;
    struct ofbundle *bundle;    /* Bundle that contains this port, if any. */
    struct list bundle_node;    /* In struct ofbundle's "ports" list. */
    struct cfm *cfm;            /* Connectivity Fault Management, if any. */
    struct bfd *bfd;            /* BFD, if any. */
    tag_type tag;               /* Tag associated with this port. */
    bool may_enable;            /* May be enabled in bonds. */
    long long int carrier_seq;  /* Carrier status changes. */
    struct tnl_port *tnl_port;  /* Tunnel handle, or null. */
    struct ofport_dpif *peer;   /* Peer if patch port. */

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
    ofp_port_t realdev_ofp_port;
    int vlandev_vid;
};

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

static inline struct rule_dpif *rule_dpif_cast(const struct rule *rule)
{
    return rule ? CONTAINER_OF(rule, struct rule_dpif, up) : NULL;
}

static inline struct ofproto_dpif *
ofproto_dpif_cast(const struct ofproto *ofproto)
{
    ovs_assert(ofproto->ofproto_class == &ofproto_dpif_class);
    return CONTAINER_OF(ofproto, struct ofproto_dpif, up);
}

static inline struct ofport_dpif *
ofbundle_get_a_port(const struct ofbundle *bundle)
{
    return CONTAINER_OF(list_front(&bundle->ports), struct ofport_dpif,
                        bundle_node);
}

static inline int
mirror_mask_ffs(mirror_mask_t mask)
{
    BUILD_ASSERT_DECL(sizeof(unsigned int) >= sizeof(mask));
    return ffs(mask);
}

struct ofport_dpif *get_ofp_port(const struct ofproto_dpif *,
                                 ofp_port_t ofp_port);

struct ofport_dpif *get_odp_port(const struct ofproto_dpif *,
                                        odp_port_t odp_port);

odp_port_t ofp_port_to_odp_port(const struct ofproto_dpif *,
                              ofp_port_t ofp_port);

struct rule_dpif *rule_dpif_lookup_in_table(struct ofproto_dpif *,
                                            const struct flow *,
                                            struct flow_wildcards *,
                                            uint8_t table_id);

tag_type rule_calculate_tag(const struct flow *flow, const struct minimask *,
                            uint32_t secret);

struct rule_dpif *rule_dpif_miss_rule(struct ofproto_dpif *ofproto,
                                      const struct flow *);

void rule_credit_stats(struct rule_dpif *, const struct dpif_flow_stats *);

void ofproto_trace(struct ofproto_dpif *, const struct flow *,
                   const struct ofpbuf *packet, struct ds *);

size_t put_userspace_action(const struct ofproto_dpif *,
                            struct ofpbuf *odp_actions, const struct flow *,
                            const union user_action_cookie *,
                            const size_t cookie_size);

bool stp_should_process_flow(const struct flow *, struct flow_wildcards *);
void stp_process_packet(const struct ofport_dpif *,
                        const struct ofpbuf *packet);

ofp_port_t vsp_realdev_to_vlandev(const struct ofproto_dpif *,
                                  ofp_port_t realdev_ofp_port,
                                  ovs_be16 vlan_tci);

bool ofproto_dpif_dscp_from_priority(const struct ofport_dpif *,
                                     uint32_t priority, uint8_t *dscp);
int ofproto_dpif_queue_to_priority(const struct ofproto_dpif *,
                                   uint32_t queue_id, uint32_t *priority);


#endif /* ofproto-dpif.h */
