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

#ifndef OFPROT_DPIF_XLATE_H
#define OFPROT_DPIF_XLATE_H 1

#include "flow.h"
#include "meta-flow.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "ofproto-dpif.h"
#include "tag.h"

/* Maximum depth of flow table recursion (due to resubmit actions) in a
 * flow translation. */
#define MAX_RESUBMIT_RECURSION 64

struct xlate_ctx;

struct xlate_out {
    /* Wildcards relevant in translation.  Any fields that were used to
     * calculate the action must be set for caching and kernel
     * wildcarding to work.  For example, if the flow lookup involved
     * performing the "normal" action on IPv4 and ARP packets, 'wc'
     * would have the 'in_port' (always set), 'dl_type' (flow match),
     * 'vlan_tci' (normal action), and 'dl_dst' (normal action) fields
     * set. */
    struct flow_wildcards wc;

    tag_type tags;              /* Tags associated with actions. */
    enum slow_path_reason slow; /* 0 if fast path may be used. */
    bool has_learn;             /* Actions include NXAST_LEARN? */
    bool has_normal;            /* Actions output to OFPP_NORMAL? */
    bool has_fin_timeout;       /* Actions include NXAST_FIN_TIMEOUT? */
    uint16_t nf_output_iface;   /* Output interface index for NetFlow. */
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

    /* The rule initiating translation or NULL. */
    struct rule_dpif *rule;

    /* The actions to translate.  If 'rule' is not NULL, these may be NULL. */
    const struct ofpact *ofpacts;
    size_t ofpacts_len;

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
     * calling xlate_in_init(). */
    void (*resubmit_hook)(struct xlate_ctx *, struct rule_dpif *rule);

    /* If nonnull, flow translation calls this function to report some
     * significant decision, e.g. to explain why OFPP_NORMAL translation
     * dropped a packet. */
    void (*report_hook)(struct xlate_ctx *, const char *s);

    /* If nonnull, flow translation credits the specified statistics to each
     * rule reached through a resubmit or OFPP_TABLE action.
     *
     * This is normally null so the client has to set it manually after
     * calling xlate_in_init(). */
    const struct dpif_flow_stats *resubmit_stats;
};

/* Context used by xlate_actions() and its callees. */
struct xlate_ctx {
    struct xlate_in *xin;
    struct xlate_out *xout;

    struct ofproto_dpif *ofproto;

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

    int recurse;                /* Recursion level, via xlate_table_action. */
    bool max_resubmit_trigger;  /* Recursed too deeply during translation. */
    uint32_t orig_skb_priority; /* Priority when packet arrived. */
    uint8_t table_id;           /* OpenFlow table ID where flow was found. */
    uint32_t sflow_n_outputs;   /* Number of output ports. */
    uint32_t sflow_odp_port;    /* Output port for composing sFlow action. */
    uint16_t user_cookie_offset;/* Used for user_action_cookie fixup. */
    bool exit;                  /* No further actions should be processed. */
};

void xlate_actions(struct xlate_in *, struct xlate_out *);
void xlate_in_init(struct xlate_in *, struct ofproto_dpif *,
                   const struct flow *, struct rule_dpif *,
                   uint8_t tcp_flags, const struct ofpbuf *packet);
void xlate_out_uninit(struct xlate_out *);
void xlate_actions_for_side_effects(struct xlate_in *);
void xlate_out_copy(struct xlate_out *dst, const struct xlate_out *src);

#endif /* ofproto-dpif-xlate.h */
