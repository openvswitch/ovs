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

#ifndef OFPROTO_DPIF_XLATE_H
#define OFPROTO_DPIF_XLATE_H 1

#include "flow.h"
#include "meta-flow.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "ofproto-dpif-mirror.h"
#include "ofproto-dpif.h"
#include "ofproto.h"
#include "stp.h"

struct bfd;
struct bond;
struct dpif;
struct lacp;
struct dpif_ipfix;
struct dpif_sflow;
struct mac_learning;

struct xlate_out {
    /* Wildcards relevant in translation.  Any fields that were used to
     * calculate the action must be set for caching and kernel
     * wildcarding to work.  For example, if the flow lookup involved
     * performing the "normal" action on IPv4 and ARP packets, 'wc'
     * would have the 'in_port' (always set), 'dl_type' (flow match),
     * 'vlan_tci' (normal action), and 'dl_dst' (normal action) fields
     * set. */
    struct flow_wildcards wc;

    enum slow_path_reason slow; /* 0 if fast path may be used. */
    bool fail_open;             /* Initial rule is fail open? */
    bool has_learn;             /* Actions include NXAST_LEARN? */
    bool has_normal;            /* Actions output to OFPP_NORMAL? */
    bool has_fin_timeout;       /* Actions include NXAST_FIN_TIMEOUT? */
    ofp_port_t nf_output_iface; /* Output interface index for NetFlow. */
    mirror_mask_t mirrors;      /* Bitmap of associated mirrors. */

    uint64_t odp_actions_stub[256 / 8];
    struct ofpbuf odp_actions;
};

struct xlate_in {
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

    /* If the caller of xlate_actions() doesn't need the flow_wildcards
     * contained in struct xlate_out.  'skip_wildcards' can be set to true
     * disabling the expensive wildcard computation.  When true, 'wc' in struct
     * xlate_out is undefined and should not be read. */
    bool skip_wildcards;

    /* The rule initiating translation or NULL. If both 'rule' and 'ofpacts'
     * are NULL, xlate_actions() will do the initial rule lookup itself. */
    struct rule_dpif *rule;

    /* The actions to translate.  If 'rule' is not NULL, these may be NULL. */
    const struct ofpact *ofpacts;
    size_t ofpacts_len;

    /* Union of the set of TCP flags seen so far in this flow.  (Used only by
     * NXAST_FIN_TIMEOUT.  Set to zero to avoid updating updating rules'
     * timeouts.) */
    uint16_t tcp_flags;

    /* If nonnull, flow translation calls this function just before executing a
     * resubmit or OFPP_TABLE action.  In addition, disables logging of traces
     * when the recursion depth is exceeded.
     *
     * 'rule' is the rule being submitted into.  It will be null if the
     * resubmit or OFPP_TABLE action didn't find a matching rule.
     *
     * 'recurse' is the resubmit recursion depth at time of invocation.
     *
     * This is normally null so the client has to set it manually after
     * calling xlate_in_init(). */
    void (*resubmit_hook)(struct xlate_in *, struct rule_dpif *rule,
                          int recurse);

    /* If nonnull, flow translation calls this function to report some
     * significant decision, e.g. to explain why OFPP_NORMAL translation
     * dropped a packet.  'recurse' is the resubmit recursion depth at time of
     * invocation. */
    void (*report_hook)(struct xlate_in *, const char *s, int recurse);

    /* If nonnull, flow translation credits the specified statistics to each
     * rule reached through a resubmit or OFPP_TABLE action.
     *
     * This is normally null so the client has to set it manually after
     * calling xlate_in_init(). */
    const struct dpif_flow_stats *resubmit_stats;
};

extern struct ovs_rwlock xlate_rwlock;

void xlate_ofproto_set(struct ofproto_dpif *, const char *name,
                       struct dpif *, struct rule_dpif *miss_rule,
                       struct rule_dpif *no_packet_in_rule,
                       const struct mac_learning *, struct stp *,
                       const struct mbridge *, const struct dpif_sflow *,
                       const struct dpif_ipfix *, const struct netflow *,
                       enum ofp_config_flags, bool forward_bpdu,
                       bool has_in_band)
    OVS_REQ_WRLOCK(xlate_rwlock);
void xlate_remove_ofproto(struct ofproto_dpif *) OVS_REQ_WRLOCK(xlate_rwlock);

void xlate_bundle_set(struct ofproto_dpif *, struct ofbundle *,
                      const char *name, enum port_vlan_mode, int vlan,
                      unsigned long *trunks, bool use_priority_tags,
                      const struct bond *, const struct lacp *,
                      bool floodable) OVS_REQ_WRLOCK(xlate_rwlock);
void xlate_bundle_remove(struct ofbundle *) OVS_REQ_WRLOCK(xlate_rwlock);

void xlate_ofport_set(struct ofproto_dpif *, struct ofbundle *,
                      struct ofport_dpif *, ofp_port_t, odp_port_t,
                      const struct netdev *, const struct cfm *,
                      const struct bfd *, struct ofport_dpif *peer,
                      int stp_port_no, const struct ofproto_port_queue *qdscp,
                      size_t n_qdscp, enum ofputil_port_config,
                      enum ofputil_port_state, bool is_tunnel,
                      bool may_enable) OVS_REQ_WRLOCK(xlate_rwlock);
void xlate_ofport_remove(struct ofport_dpif *) OVS_REQ_WRLOCK(xlate_rwlock);

int xlate_receive(const struct dpif_backer *, struct ofpbuf *packet,
                  const struct nlattr *key, size_t key_len,
                  struct flow *, enum odp_key_fitness *,
                  struct ofproto_dpif **, struct dpif_ipfix **,
                  struct dpif_sflow **, struct netflow **,
                  odp_port_t *odp_in_port)
    OVS_EXCLUDED(xlate_rwlock);

void xlate_actions(struct xlate_in *, struct xlate_out *)
    OVS_EXCLUDED(xlate_rwlock);
void xlate_in_init(struct xlate_in *, struct ofproto_dpif *,
                   const struct flow *, struct rule_dpif *, uint16_t tcp_flags,
                   const struct ofpbuf *packet);
void xlate_out_uninit(struct xlate_out *);
void xlate_actions_for_side_effects(struct xlate_in *);
void xlate_out_copy(struct xlate_out *dst, const struct xlate_out *src);

int xlate_send_packet(const struct ofport_dpif *, struct ofpbuf *);

#endif /* ofproto-dpif-xlate.h */
