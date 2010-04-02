/*
 * Copyright (c) 2010 Nicira Networks.
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

#include "wdp-xflow.h"

#include <errno.h>
#include <inttypes.h>

#include "coverage.h"
#include "dhcp.h"
#include "netdev.h"
#include "netflow.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "port-array.h"
#include "shash.h"
#include "stp.h"
#include "svec.h"
#include "timeval.h"
#include "util.h"
#include "vconn.h"
#include "wdp-provider.h"
#include "xfif.h"
#include "xflow-util.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_wdp_xflow
#include "vlog.h"

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Maximum numbers of rules. */
#define WX_MAX_WILD     65536   /* Wildcarded rules. */
#define WX_MAX_EXACT    1048576 /* Exact-match rules. */

struct wx {
    struct list list_node;
    struct wdp wdp;
    struct xfif *xfif;
    struct classifier cls;
    struct netdev_monitor *netdev_monitor;
    struct port_array ports;    /* Index is ODP port nr; wdp_port->opp.port_no
                                 * is OFP port nr. */
    struct shash port_by_name;
    bool need_revalidate;
    long long int next_expiration;
};

static struct list all_wx = LIST_INITIALIZER(&all_wx);

static int wx_port_init(struct wx *);
static void wx_port_run(struct wx *);
static void wx_port_refresh_groups(struct wx *);

enum {
    WX_GROUP_FLOOD = 0,
    WX_GROUP_ALL = 1
};

static struct wx *
wx_cast(const struct wdp *wdp)
{
    return CONTAINER_OF(wdp, struct wx, wdp);
}

static int
wx_xlate_actions(struct wx *, const union ofp_action *, size_t n,
                 const flow_t *flow, const struct ofpbuf *packet,
                 struct xflow_actions *out, bool *may_set_up_flow);

struct wx_rule {
    struct wdp_rule wr;

    uint64_t packet_count;      /* Number of packets received. */
    uint64_t byte_count;        /* Number of bytes received. */
    uint64_t accounted_bytes;   /* Number of bytes passed to account_cb. */
    long long int used;         /* Last-used time (0 if never used). */

    /* If 'super' is non-NULL, this rule is a subrule, that is, it is an
     * exact-match rule (having cr.wc.wildcards of 0) generated from the
     * wildcard rule 'super'.  In this case, 'list' is an element of the
     * super-rule's list.
     *
     * If 'super' is NULL, this rule is a super-rule, and 'list' is the head of
     * a list of subrules.  A super-rule with no wildcards (where
     * cr.wc.wildcards is 0) will never have any subrules. */
    struct wx_rule *super;
    struct list list;

    /* Datapath actions.
     *
     * A super-rule with wildcard fields never has XFLOW actions (since the
     * datapath only supports exact-match flows). */
    bool installed;             /* Installed in datapath? */
    bool may_install;           /* True ordinarily; false if actions must
                                 * be reassessed for every packet. */
    int n_xflow_actions;
    union xflow_action *xflow_actions;
};

static void wx_rule_destroy(struct wx *, struct wx_rule *);
static void wx_rule_update_actions(struct wx *, struct wx_rule *);
static void wx_rule_execute(struct wx *, struct wx_rule *,
                            struct ofpbuf *packet, const flow_t *);
static bool wx_rule_make_actions(struct wx *, struct wx_rule *,
                                 const struct ofpbuf *packet);
static void wx_rule_install(struct wx *, struct wx_rule *,
                            struct wx_rule *displaced_rule);

static struct wx_rule *
wx_rule_cast(const struct cls_rule *cls_rule)
{
    return cls_rule ? CONTAINER_OF(cls_rule, struct wx_rule, wr.cr) : NULL;
}

/* Returns true if 'rule' is merely an implementation detail that should be
 * hidden from the client. */
static inline bool
wx_rule_is_hidden(const struct wx_rule *rule)
{
    return rule->super != NULL;
}

static void
wx_rule_free(struct wx_rule *rule)
{
    wdp_rule_uninit(&rule->wr);
    free(rule->xflow_actions);
    free(rule);
}

static void
wx_rule_account(struct wx *wx OVS_UNUSED, struct wx_rule *rule OVS_UNUSED,
                uint64_t extra_bytes OVS_UNUSED)
{
    /* XXX call account_cb hook */
}

static void
wx_rule_post_uninstall(struct wx *wx, struct wx_rule *rule)
{
    struct wx_rule *super = rule->super;

    wx_rule_account(wx, rule, 0);

    /* XXX netflow expiration */

    if (super) {
        super->packet_count += rule->packet_count;
        super->byte_count += rule->byte_count;

        /* Reset counters to prevent double counting if the rule ever gets
         * reinstalled. */
        rule->packet_count = 0;
        rule->byte_count = 0;
        rule->accounted_bytes = 0;

        //XXX netflow_flow_clear(&rule->nf_flow);
    }
}

static long long int
xflow_flow_stats_to_msec(const struct xflow_flow_stats *stats)
{
    return (stats->used_sec
            ? stats->used_sec * 1000 + stats->used_nsec / 1000000
            : 0);
}

static void
wx_rule_update_time(struct wx *wx OVS_UNUSED, struct wx_rule *rule,
                    const struct xflow_flow_stats *stats)
{
    long long int used = xflow_flow_stats_to_msec(stats);
    if (used > rule->used) {
        rule->used = used;
        if (rule->super && used > rule->super->used) {
            rule->super->used = used;
        }
        //XXX netflow_flow_update_time(ofproto->netflow, &rule->nf_flow, used);
    }
}

static void
wx_rule_update_stats(struct wx *wx, struct wx_rule *rule,
                     const struct xflow_flow_stats *stats)
{
    if (stats->n_packets) {
        wx_rule_update_time(wx, rule, stats);
        rule->packet_count += stats->n_packets;
        rule->byte_count += stats->n_bytes;
        /* XXX netflow_flow_update_flags(&rule->nf_flow, stats->ip_tos,
           stats->tcp_flags); */
    }
}

static void
wx_rule_uninstall(struct wx *wx, struct wx_rule *rule)
{
    assert(!rule->wr.cr.flow.wildcards);
    if (rule->installed) {
        struct xflow_flow xflow_flow;

        xflow_key_from_flow(&xflow_flow.key, &rule->wr.cr.flow);
        xflow_flow.actions = NULL;
        xflow_flow.n_actions = 0;
        xflow_flow.flags = 0;
        if (!xfif_flow_del(wx->xfif, &xflow_flow)) {
            wx_rule_update_stats(wx, rule, &xflow_flow.stats);
        }
        rule->installed = false;

        wx_rule_post_uninstall(wx, rule);
    }
}

#if 0
static bool
is_controller_rule(struct wx_rule *rule)
{
    /* If the only action is send to the controller then don't report
     * NetFlow expiration messages since it is just part of the control
     * logic for the network and not real traffic. */

    if (rule && rule->super) {
        struct wdp_rule *super = &rule->super->wr;

        return super->n_actions == 1 &&
            super->actions[0].type == htons(OFPAT_OUTPUT) &&
            super->actions[0].output.port == htons(OFPP_CONTROLLER);
    }

    return false;
}
#endif

static void
wx_rule_remove(struct wx *wx, struct wx_rule *rule)
{
    if (rule->wr.cr.flow.wildcards) {
        COVERAGE_INC(wx_del_wc_flow);
        wx->need_revalidate = true;
    } else {
        wx_rule_uninstall(wx, rule);
    }
    classifier_remove(&wx->cls, &rule->wr.cr);
    wx_rule_destroy(wx, rule);
}

static bool
wx_rule_revalidate(struct wx *wx, struct wx_rule *rule)
{
    const flow_t *flow = &rule->wr.cr.flow;

    COVERAGE_INC(wx_rule_revalidate);
    if (rule->super) {
        struct wx_rule *super;
        super = wx_rule_cast(classifier_lookup_wild(&wx->cls, flow));
        if (!super) {
            wx_rule_remove(wx, rule);
            return false;
        } else if (super != rule->super) {
            COVERAGE_INC(wx_revalidate_moved);
            list_remove(&rule->list);
            list_push_back(&super->list, &rule->list);
            rule->super = super;
            rule->wr.hard_timeout = super->wr.hard_timeout;
            rule->wr.idle_timeout = super->wr.idle_timeout;
            rule->wr.created = super->wr.created;
            rule->used = 0;
        }
    }

    wx_rule_update_actions(wx, rule);
    return true;
}

/* Destroys 'rule'.  If 'rule' is a subrule, also removes it from its
 * super-rule's list of subrules.  If 'rule' is a super-rule, also iterates
 * through all of its subrules and revalidates them, destroying any that no
 * longer has a super-rule (which is probably all of them).
 *
 * Before calling this function, the caller must make have removed 'rule' from
 * the classifier.  If 'rule' is an exact-match rule, the caller is also
 * responsible for ensuring that it has been uninstalled from the datapath. */
static void
wx_rule_destroy(struct wx *wx, struct wx_rule *rule)
{
    if (!rule->super) {
        struct wx_rule *subrule, *next;
        LIST_FOR_EACH_SAFE (subrule, next, struct wx_rule, list, &rule->list) {
            wx_rule_revalidate(wx, subrule);
        }
    } else {
        list_remove(&rule->list);
    }
    wx_rule_free(rule);
}

#if 0
static bool
wx_rule_has_out_port(const struct wx_rule *rule, uint16_t out_port)
{
    const union ofp_action *oa;
    struct actions_iterator i;

    if (out_port == htons(OFPP_NONE)) {
        return true;
    }
    for (oa = actions_first(&i, rule->wr.actions,
                            rule->wr.n_actions);
         oa;
         oa = actions_next(&i)) {
        if (oa->type == htons(OFPAT_OUTPUT) && oa->output.port == out_port) {
            return true;
        }
    }
    return false;
}
#endif

/* Caller is responsible for initializing the 'cr' member of the returned
 * rule. */
static struct wx_rule *
wx_rule_create(struct wx_rule *super,
               const union ofp_action *actions, size_t n_actions,
               uint16_t idle_timeout, uint16_t hard_timeout)
{
    struct wx_rule *rule = xzalloc(sizeof *rule);
    wdp_rule_init(&rule->wr, actions, n_actions);
    rule->wr.idle_timeout = idle_timeout;
    rule->wr.hard_timeout = hard_timeout;
    rule->used = rule->wr.created;
    rule->super = super;
    if (super) {
        list_push_back(&super->list, &rule->list);
    } else {
        list_init(&rule->list);
    }
#if 0
    netflow_flow_clear(&rule->nf_flow);
    netflow_flow_update_time(ofproto->netflow, &rule->nf_flow, rule->created);
#endif

    return rule;
}

/* Executes the actions indicated by 'rule' on 'packet', which is in flow
 * 'flow' and is considered to have arrived on XFLOW port 'in_port'.
 *
 * The flow that 'packet' actually contains does not need to actually match
 * 'rule'; the actions in 'rule' will be applied to it either way.  Likewise,
 * the packet and byte counters for 'rule' will be credited for the packet sent
 * out whether or not the packet actually matches 'rule'.
 *
 * If 'rule' is an exact-match rule and 'flow' actually equals the rule's flow,
 * the caller must already have accurately composed XFLOW actions for it given
 * 'packet' using rule_make_actions().  If 'rule' is a wildcard rule, or if
 * 'rule' is an exact-match rule but 'flow' is not the rule's flow, then this
 * function will compose a set of XFLOW actions based on 'rule''s OpenFlow
 * actions and apply them to 'packet'. */
static void
wx_rule_execute(struct wx *wx, struct wx_rule *rule,
                struct ofpbuf *packet, const flow_t *flow)
{
    const union xflow_action *actions;
    size_t n_actions;
    struct xflow_actions a;

    /* Grab or compose the XFLOW actions.
     *
     * The special case for an exact-match 'rule' where 'flow' is not the
     * rule's flow is important to avoid, e.g., sending a packet out its input
     * port simply because the XFLOW actions were composed for the wrong
     * scenario. */
    if (rule->wr.cr.flow.wildcards
        || !flow_equal(flow, &rule->wr.cr.flow))
    {
        struct wx_rule *super = rule->super ? rule->super : rule;
        if (wx_xlate_actions(wx, super->wr.actions, super->wr.n_actions, flow,
                             packet, &a, NULL)) {
            return;
        }
        actions = a.actions;
        n_actions = a.n_actions;
    } else {
        actions = rule->xflow_actions;
        n_actions = rule->n_xflow_actions;
    }

    /* Execute the XFLOW actions. */
    if (!xfif_execute(wx->xfif, flow->in_port,
                      actions, n_actions, packet)) {
        struct xflow_flow_stats stats;
        flow_extract_stats(flow, packet, &stats);
        wx_rule_update_stats(wx, rule, &stats);
        rule->used = time_msec();
        //XXX netflow_flow_update_time(wx->netflow, &rule->nf_flow, rule->used);
    }
}

static void
wx_rule_insert(struct wx *wx, struct wx_rule *rule, struct ofpbuf *packet,
               uint16_t in_port)
{
    struct wx_rule *displaced_rule;

    /* Insert the rule in the classifier. */
    displaced_rule = wx_rule_cast(classifier_insert(&wx->cls, &rule->wr.cr));
    if (!rule->wr.cr.flow.wildcards) {
        wx_rule_make_actions(wx, rule, packet);
    }

    /* Send the packet and credit it to the rule. */
    if (packet) {
        flow_t flow;
        flow_extract(packet, in_port, &flow);
        wx_rule_execute(wx, rule, packet, &flow);
    }

    /* Install the rule in the datapath only after sending the packet, to
     * avoid packet reordering.  */
    if (rule->wr.cr.flow.wildcards) {
        COVERAGE_INC(wx_add_wc_flow);
        wx->need_revalidate = true;
    } else {
        wx_rule_install(wx, rule, displaced_rule);
    }

    /* Free the rule that was displaced, if any. */
    if (displaced_rule) {
        wx_rule_destroy(wx, displaced_rule);
    }
}

static struct wx_rule *
wx_rule_create_subrule(struct wx *wx, struct wx_rule *rule, const flow_t *flow)
{
    struct wx_rule *subrule;

    subrule = wx_rule_create(rule, NULL, 0,
                             rule->wr.idle_timeout,
                             rule->wr.hard_timeout);
    COVERAGE_INC(wx_subrule_create);
    cls_rule_from_flow(&subrule->wr.cr, flow);
    classifier_insert_exact(&wx->cls, &subrule->wr.cr);

    return subrule;
}

/* Returns true if the actions changed, false otherwise. */
static bool
wx_rule_make_actions(struct wx *wx, struct wx_rule *rule,
                     const struct ofpbuf *packet)
{
    const struct wx_rule *super;
    struct xflow_actions a;
    size_t actions_len;

    assert(!rule->wr.cr.flow.wildcards);

    super = rule->super ? rule->super : rule;
    wx_xlate_actions(wx, super->wr.actions, super->wr.n_actions,
                     &rule->wr.cr.flow, packet, &a, &rule->may_install);

    actions_len = a.n_actions * sizeof *a.actions;
    if (rule->n_xflow_actions != a.n_actions
        || memcmp(rule->xflow_actions, a.actions, actions_len)) {
        COVERAGE_INC(wx_xflow_unchanged);
        free(rule->xflow_actions);
        rule->n_xflow_actions = a.n_actions;
        rule->xflow_actions = xmemdup(a.actions, actions_len);
        return true;
    } else {
        return false;
    }
}

static int
do_put_flow(struct wx *wx, struct wx_rule *rule, int flags,
            struct xflow_flow_put *put)
{
    memset(&put->flow.stats, 0, sizeof put->flow.stats);
    xflow_key_from_flow(&put->flow.key, &rule->wr.cr.flow);
    put->flow.actions = rule->xflow_actions;
    put->flow.n_actions = rule->n_xflow_actions;
    put->flow.flags = 0;
    put->flags = flags;
    return xfif_flow_put(wx->xfif, put);
}

static void
wx_rule_install(struct wx *wx, struct wx_rule *rule, struct wx_rule *displaced_rule)
{
    assert(!rule->wr.cr.flow.wildcards);

    if (rule->may_install) {
        struct xflow_flow_put put;
        if (!do_put_flow(wx, rule,
                         XFLOWPF_CREATE | XFLOWPF_MODIFY | XFLOWPF_ZERO_STATS,
                         &put)) {
            rule->installed = true;
            if (displaced_rule) {
                wx_rule_update_stats(wx, displaced_rule, &put.flow.stats);
                wx_rule_post_uninstall(wx, displaced_rule);
            }
        }
    } else if (displaced_rule) {
        wx_rule_uninstall(wx, displaced_rule);
    }
}

static void
wx_rule_reinstall(struct wx *wx, struct wx_rule *rule)
{
    if (rule->installed) {
        struct xflow_flow_put put;
        COVERAGE_INC(wx_dp_missed);
        do_put_flow(wx, rule, XFLOWPF_CREATE | XFLOWPF_MODIFY, &put);
    } else {
        wx_rule_install(wx, rule, NULL);
    }
}

static void
wx_rule_update_actions(struct wx *wx, struct wx_rule *rule)
{
    bool actions_changed;
#if 0
    uint16_t new_out_iface, old_out_iface;

    old_out_iface = rule->nf_flow.output_iface;
#endif
    actions_changed = wx_rule_make_actions(wx, rule, NULL);

    if (rule->may_install) {
        if (rule->installed) {
            if (actions_changed) {
                struct xflow_flow_put put;
                do_put_flow(wx, rule, XFLOWPF_CREATE | XFLOWPF_MODIFY
                            | XFLOWPF_ZERO_STATS, &put);
                wx_rule_update_stats(wx, rule, &put.flow.stats);
#if 0
                /* Temporarily set the old output iface so that NetFlow
                 * messages have the correct output interface for the old
                 * stats. */
                new_out_iface = rule->nf_flow.output_iface;
                rule->nf_flow.output_iface = old_out_iface;
#endif
                wx_rule_post_uninstall(wx, rule);
                //rule->nf_flow.output_iface = new_out_iface;
            }
        } else {
            wx_rule_install(wx, rule, NULL);
        }
    } else {
        wx_rule_uninstall(wx, rule);
    }
}

static void
add_output_group_action(struct xflow_actions *actions, uint16_t group,
                        uint16_t *nf_output_iface)
{
    xflow_actions_add(actions, XFLOWAT_OUTPUT_GROUP)->output_group.group = group;

    if (group == WX_GROUP_ALL || group == WX_GROUP_FLOOD) {
        *nf_output_iface = NF_OUT_FLOOD;
    }
}

static void
add_controller_action(struct xflow_actions *actions,
                      const struct ofp_action_output *oao)
{
    union xflow_action *a = xflow_actions_add(actions, XFLOWAT_CONTROLLER);
    a->controller.arg = oao->max_len ? ntohs(oao->max_len) : UINT32_MAX;
}

struct wx_xlate_ctx {
    /* Input. */
    const flow_t *flow;         /* Flow to which these actions correspond. */
    int recurse;                /* Recursion level, via xlate_table_action. */
    struct wx *wx;
    const struct ofpbuf *packet; /* The packet corresponding to 'flow', or a
                                  * null pointer if we are revalidating
                                  * without a packet to refer to. */

    /* Output. */
    struct xflow_actions *out;    /* Datapath actions. */
    //tag_type *tags;             /* Tags associated with OFPP_NORMAL actions. */
    bool may_set_up_flow;       /* True ordinarily; false if the actions must
                                 * be reassessed for every packet. */
    uint16_t nf_output_iface;   /* Output interface index for NetFlow. */
};

static void do_xlate_actions(const union ofp_action *in, size_t n_in,
                             struct wx_xlate_ctx *ctx);

static void
add_output_action(struct wx_xlate_ctx *ctx, uint16_t port)
{
    const struct wdp_port *wdp_port = port_array_get(&ctx->wx->ports, port);

    if (wdp_port) {
        if (wdp_port->opp.config & OFPPC_NO_FWD) {
            /* Forwarding disabled on port. */
            return;
        }
    } else {
        /*
         * We don't have an ofport record for this port, but it doesn't hurt to
         * allow forwarding to it anyhow.  Maybe such a port will appear later
         * and we're pre-populating the flow table.
         */
    }

    xflow_actions_add(ctx->out, XFLOWAT_OUTPUT)->output.port = port;
    //ctx->nf_output_iface = port;
}

static struct wx_rule *
wx_rule_lookup_valid(struct wx *wx, const flow_t *flow)
{
    struct wx_rule *rule = wx_rule_cast(classifier_lookup(&wx->cls, flow));

    /* The rule we found might not be valid, since we could be in need of
     * revalidation.  If it is not valid, don't return it. */
    if (rule
        && rule->super
        && wx->need_revalidate
        && !wx_rule_revalidate(wx, rule)) {
        COVERAGE_INC(wx_invalidated);
        return NULL;
    }

    return rule;
}

static void
xlate_table_action(struct wx_xlate_ctx *ctx, uint16_t in_port)
{
    if (!ctx->recurse) {
        struct wx_rule *rule;
        flow_t flow;

        flow = *ctx->flow;
        flow.in_port = in_port;

        rule = wx_rule_lookup_valid(ctx->wx, &flow);
        if (rule) {
            if (rule->super) {
                rule = rule->super;
            }

            ctx->recurse++;
            do_xlate_actions(rule->wr.actions, rule->wr.n_actions, ctx);
            ctx->recurse--;
        }
    }
}

static void
xlate_output_action(struct wx_xlate_ctx *ctx,
                    const struct ofp_action_output *oao)
{
    uint16_t xflow_port;
    uint16_t prev_nf_output_iface = ctx->nf_output_iface;

    ctx->nf_output_iface = NF_OUT_DROP;

    switch (ntohs(oao->port)) {
    case OFPP_IN_PORT:
        add_output_action(ctx, ctx->flow->in_port);
        break;
    case OFPP_TABLE:
        xlate_table_action(ctx, ctx->flow->in_port);
        break;
    case OFPP_NORMAL:
#if 0
        if (!ctx->wx->ofhooks->normal_cb(ctx->flow, ctx->packet,
                                         ctx->out, ctx->tags,
                                         &ctx->nf_output_iface,
                                         ctx->wx->aux)) {
            COVERAGE_INC(wx_uninstallable);
            ctx->may_set_up_flow = false;
        }
        break;
#else
        /* fall through to flood for now */
#endif
    case OFPP_FLOOD:
        add_output_group_action(ctx->out, WX_GROUP_FLOOD,
                                &ctx->nf_output_iface);
        break;
    case OFPP_ALL:
        add_output_group_action(ctx->out, WX_GROUP_ALL, &ctx->nf_output_iface);
        break;
    case OFPP_CONTROLLER:
        add_controller_action(ctx->out, oao);
        break;
    case OFPP_LOCAL:
        add_output_action(ctx, XFLOWP_LOCAL);
        break;
    default:
        xflow_port = ofp_port_to_xflow_port(ntohs(oao->port));
        if (xflow_port != ctx->flow->in_port) {
            add_output_action(ctx, xflow_port);
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
xlate_nicira_action(struct wx_xlate_ctx *ctx,
                    const struct nx_action_header *nah)
{
    const struct nx_action_resubmit *nar;
    int subtype = ntohs(nah->subtype);

    assert(nah->vendor == htonl(NX_VENDOR_ID));
    switch (subtype) {
    case NXAST_RESUBMIT:
        nar = (const struct nx_action_resubmit *) nah;
        xlate_table_action(ctx, ofp_port_to_xflow_port(ntohs(nar->in_port)));
        break;

    default:
        VLOG_DBG_RL(&rl, "unknown Nicira action type %"PRIu16, subtype);
        break;
    }
}

static void
do_xlate_actions(const union ofp_action *in, size_t n_in,
                 struct wx_xlate_ctx *ctx)
{
    struct actions_iterator iter;
    const union ofp_action *ia;
    const struct wdp_port *port;

    port = port_array_get(&ctx->wx->ports, ctx->flow->in_port);
    if (port && port->opp.config & (OFPPC_NO_RECV | OFPPC_NO_RECV_STP) &&
        port->opp.config & (eth_addr_equals(ctx->flow->dl_dst, stp_eth_addr)
                            ? OFPPC_NO_RECV_STP : OFPPC_NO_RECV)) {
        /* Drop this flow. */
        return;
    }

    for (ia = actions_first(&iter, in, n_in); ia; ia = actions_next(&iter)) {
        uint16_t type = ntohs(ia->type);
        union xflow_action *oa;

        switch (type) {
        case OFPAT_OUTPUT:
            xlate_output_action(ctx, &ia->output);
            break;

        case OFPAT_SET_VLAN_VID:
            oa = xflow_actions_add(ctx->out, XFLOWAT_SET_DL_TCI);
            oa->dl_tci.tci = ia->vlan_vid.vlan_vid & htons(VLAN_VID_MASK);
            oa->dl_tci.mask = htons(VLAN_VID_MASK);
            break;

        case OFPAT_SET_VLAN_PCP:
            oa = xflow_actions_add(ctx->out, XFLOWAT_SET_DL_TCI);
            oa->dl_tci.tci = htons((ia->vlan_pcp.vlan_pcp << VLAN_PCP_SHIFT)
                                   & VLAN_PCP_MASK);
            oa->dl_tci.mask = htons(VLAN_PCP_MASK);
            break;

        case OFPAT_STRIP_VLAN:
            xflow_actions_add(ctx->out, XFLOWAT_STRIP_VLAN);
            break;

        case OFPAT_SET_DL_SRC:
            oa = xflow_actions_add(ctx->out, XFLOWAT_SET_DL_SRC);
            memcpy(oa->dl_addr.dl_addr,
                   ((struct ofp_action_dl_addr *) ia)->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_DL_DST:
            oa = xflow_actions_add(ctx->out, XFLOWAT_SET_DL_DST);
            memcpy(oa->dl_addr.dl_addr,
                   ((struct ofp_action_dl_addr *) ia)->dl_addr, ETH_ADDR_LEN);
            break;

        case OFPAT_SET_NW_SRC:
            oa = xflow_actions_add(ctx->out, XFLOWAT_SET_NW_SRC);
            oa->nw_addr.nw_addr = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_DST:
            oa = xflow_actions_add(ctx->out, XFLOWAT_SET_NW_DST);
            oa->nw_addr.nw_addr = ia->nw_addr.nw_addr;
            break;

        case OFPAT_SET_NW_TOS:
            oa = xflow_actions_add(ctx->out, XFLOWAT_SET_NW_TOS);
            oa->nw_tos.nw_tos = ia->nw_tos.nw_tos;
            break;

        case OFPAT_SET_TP_SRC:
            oa = xflow_actions_add(ctx->out, XFLOWAT_SET_TP_SRC);
            oa->tp_port.tp_port = ia->tp_port.tp_port;
            break;

        case OFPAT_SET_TP_DST:
            oa = xflow_actions_add(ctx->out, XFLOWAT_SET_TP_DST);
            oa->tp_port.tp_port = ia->tp_port.tp_port;
            break;

        case OFPAT_VENDOR:
            xlate_nicira_action(ctx, (const struct nx_action_header *) ia);
            break;

        default:
            VLOG_DBG_RL(&rl, "unknown action type %"PRIu16, type);
            break;
        }
    }
}

/* Returns true if 'flow' and 'actions' may be set up as a flow in the kernel.
 * This is true most of the time, but we don't allow flows that would prevent
 * DHCP replies from being seen by the local port to be set up in the
 * kernel.
 *
 * We only need this, strictly speaking, when in-band control is turned on. */
static bool
wx_may_set_up(const flow_t *flow, const struct xflow_actions *actions)
{
    if (flow->dl_type == htons(ETH_TYPE_IP)
        && flow->nw_proto == IP_TYPE_UDP
        && flow->tp_src == htons(DHCP_SERVER_PORT)
        && flow->tp_dst == htons(DHCP_CLIENT_PORT)) {
        int i;

        for (i = 0; i < actions->n_actions; i++) {
            const struct xflow_action_output *oao = &actions->actions[i].output;
            if (oao->type == XFLOWAT_OUTPUT && oao->port == XFLOWP_LOCAL) {
                return true;
            }
        }
        return false;
    }

    return true;
}

static int
wx_xlate_actions(struct wx *wx, const union ofp_action *in, size_t n_in,
                 const flow_t *flow, const struct ofpbuf *packet,
                 struct xflow_actions *out, bool *may_set_up_flow)
{
    //tag_type no_tags = 0;
    struct wx_xlate_ctx ctx;
    COVERAGE_INC(wx_ofp2xflow);
    xflow_actions_init(out);
    ctx.flow = flow;
    ctx.recurse = 0;
    ctx.wx = wx;
    ctx.packet = packet;
    ctx.out = out;
    //ctx.tags = tags ? tags : &no_tags;
    ctx.may_set_up_flow = true;
    ctx.nf_output_iface = NF_OUT_DROP;
    do_xlate_actions(in, n_in, &ctx);

    if (may_set_up_flow) {
        *may_set_up_flow = ctx.may_set_up_flow && wx_may_set_up(flow, out);
    }
#if 0
    if (nf_output_iface) {
        *nf_output_iface = ctx.nf_output_iface;
    }
#endif
    if (xflow_actions_overflow(out)) {
        xflow_actions_init(out);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_TOO_MANY);
    }
    return 0;
}

static void
update_used(struct wx *wx)
{
    struct xflow_flow *flows;
    size_t n_flows;
    size_t i;
    int error;

    error = xfif_flow_list_all(wx->xfif, &flows, &n_flows);
    if (error) {
        return;
    }

    for (i = 0; i < n_flows; i++) {
        struct xflow_flow *f = &flows[i];
        struct wx_rule *rule;
        flow_t flow;

        xflow_key_to_flow(&f->key, &flow);
        rule = wx_rule_cast(classifier_find_rule_exactly(&wx->cls, &flow));
        if (!rule || !rule->installed) {
            COVERAGE_INC(wx_unexpected_rule);
            xfif_flow_del(wx->xfif, f);
            continue;
        }

        wx_rule_update_time(wx, rule, &f->stats);
        wx_rule_account(wx, rule, f->stats.n_bytes);
    }
    free(flows);
}

static void
uninstall_idle_flow(struct wx *wx, struct wx_rule *rule)
{
    assert(rule->installed);
    assert(!rule->wr.cr.flow.wildcards);

    if (rule->super) {
        wx_rule_remove(wx, rule);
    } else {
        wx_rule_uninstall(wx, rule);
    }
}

static void
expire_rule(struct cls_rule *cls_rule, void *wx_)
{
    struct wx *wx = wx_;
    struct wx_rule *rule = wx_rule_cast(cls_rule);
    long long int hard_expire, idle_expire, expire, now;

    hard_expire = (rule->wr.hard_timeout
                   ? rule->wr.created + rule->wr.hard_timeout * 1000
                   : LLONG_MAX);
    idle_expire = (rule->wr.idle_timeout
                   && (rule->super || list_is_empty(&rule->list))
                   ? rule->used + rule->wr.idle_timeout * 1000
                   : LLONG_MAX);
    expire = MIN(hard_expire, idle_expire);

    now = time_msec();
    if (now < expire) {
        if (rule->installed && now >= rule->used + 5000) {
            uninstall_idle_flow(wx, rule);
        } else if (!rule->wr.cr.flow.wildcards) {
            //XXX active_timeout(wx, rule);
        }

        return;
    }

    COVERAGE_INC(wx_expired);

    /* Update stats.  This code will be a no-op if the rule expired
     * due to an idle timeout. */
    if (rule->wr.cr.flow.wildcards) {
        struct wx_rule *subrule, *next;
        LIST_FOR_EACH_SAFE (subrule, next, struct wx_rule, list, &rule->list) {
            wx_rule_remove(wx, subrule);
        }
    } else {
        wx_rule_uninstall(wx, rule);
    }

#if 0                           /* XXX */
    if (!wx_rule_is_hidden(rule)) {
        send_flow_removed(wx, rule, now,
                          (now >= hard_expire
                           ? OFPRR_HARD_TIMEOUT : OFPRR_IDLE_TIMEOUT));
    }
#endif
    wx_rule_remove(wx, rule);
}

struct revalidate_cbdata {
    struct wx *wx;
    bool revalidate_all;        /* Revalidate all exact-match rules? */
    bool revalidate_subrules;   /* Revalidate all exact-match subrules? */
    //struct tag_set revalidate_set; /* Set of tags to revalidate. */
};

static bool
revalidate_rule(struct wx *wx, struct wx_rule *rule)
{
    const flow_t *flow = &rule->wr.cr.flow;

    COVERAGE_INC(wx_revalidate_rule);
    if (rule->super) {
        struct wx_rule *super;
        super = wx_rule_cast(classifier_lookup_wild(&wx->cls, flow));
        if (!super) {
            wx_rule_remove(wx, rule);
            return false;
        } else if (super != rule->super) {
            COVERAGE_INC(wx_revalidate_moved);
            list_remove(&rule->list);
            list_push_back(&super->list, &rule->list);
            rule->super = super;
            rule->wr.hard_timeout = super->wr.hard_timeout;
            rule->wr.idle_timeout = super->wr.idle_timeout;
            rule->wr.created = super->wr.created;
            rule->used = 0;
        }
    }

    wx_rule_update_actions(wx, rule);
    return true;
}

static void
revalidate_cb(struct cls_rule *sub_, void *cbdata_)
{
    struct wx_rule *sub = wx_rule_cast(sub_);
    struct revalidate_cbdata *cbdata = cbdata_;

    if (cbdata->revalidate_all
        || (cbdata->revalidate_subrules && sub->super)
        /*|| (tag_set_intersects(&cbdata->revalidate_set, sub->tags))*/) {
        revalidate_rule(cbdata->wx, sub);
    }
}

static void
wx_run_one(struct wx *wx)
{
    wx_port_run(wx);

    if (time_msec() >= wx->next_expiration) {
        COVERAGE_INC(wx_expiration);
        wx->next_expiration = time_msec() + 1000;
        update_used(wx);

        classifier_for_each(&wx->cls, CLS_INC_ALL, expire_rule, wx);

        /* XXX account_checkpoint_cb */
    }

    if (wx->need_revalidate /*|| !tag_set_is_empty(&p->revalidate_set)*/) {
        struct revalidate_cbdata cbdata;
        cbdata.wx = wx;
        cbdata.revalidate_all = false;
        cbdata.revalidate_subrules = wx->need_revalidate;
        //cbdata.revalidate_set = wx->revalidate_set;
        //tag_set_init(&wx->revalidate_set);
        COVERAGE_INC(wx_revalidate);
        classifier_for_each(&wx->cls, CLS_INC_EXACT, revalidate_cb, &cbdata);
        wx->need_revalidate = false;
    }
}

static void
wx_run(void)
{
    struct wx *wx;

    LIST_FOR_EACH (wx, struct wx, list_node, &all_wx) {
        wx_run_one(wx);
    }
    xf_run();
}

static void
wx_wait_one(struct wx *wx)
{
    xfif_port_poll_wait(wx->xfif);
    netdev_monitor_poll_wait(wx->netdev_monitor);
    if (wx->need_revalidate /*|| !tag_set_is_empty(&p->revalidate_set)*/) {
        poll_immediate_wake();
    } else if (wx->next_expiration != LLONG_MAX) {
        poll_timer_wait(wx->next_expiration - time_msec());
    }
}

static void
wx_wait(void)
{
    struct wx *wx;

    LIST_FOR_EACH (wx, struct wx, list_node, &all_wx) {
        wx_wait_one(wx);
    }
    xf_wait();
}

static int wx_flow_flush(struct wdp *);

static int
wx_enumerate(const struct wdp_class *wdp_class, struct svec *all_wdps)
{
    struct svec names = SVEC_EMPTY_INITIALIZER;
    int error = xf_enumerate_names(wdp_class->type, &names);
    svec_move(all_wdps, &names);
    return error;
}

static int
wx_open(const struct wdp_class *wdp_class, const char *name, bool create,
        struct wdp **wdpp)
{
    struct xfif *xfif;
    int error;

    error = (create
             ? xfif_create_and_open(name, wdp_class->type, &xfif)
             : xfif_open(name, wdp_class->type, &xfif));
    if (!error) {
        struct wx *wx;

        wx = xmalloc(sizeof *wx);
        list_push_back(&all_wx, &wx->list_node);
        wdp_init(&wx->wdp, wdp_class, name, 0, 0);
        wx->xfif = xfif;
        classifier_init(&wx->cls);
        wx->netdev_monitor = netdev_monitor_create();
        port_array_init(&wx->ports);
        shash_init(&wx->port_by_name);
        wx->next_expiration = time_msec() + 1000;

        wx_port_init(wx);

        *wdpp = &wx->wdp;
    }

    return error;
}

static void
wx_close(struct wdp *wdp)
{
    struct wx *wx = wx_cast(wdp);

    wx_flow_flush(wdp);
    xfif_close(wx->xfif);
    classifier_destroy(&wx->cls);
    netdev_monitor_destroy(wx->netdev_monitor);
    list_remove(&wx->list_node);
    free(wx);
}

static int
wx_get_all_names(const struct wdp *wdp, struct svec *all_names)
{
    struct wx *wx = wx_cast(wdp);

    return xfif_get_all_names(wx->xfif, all_names);
}

static int
wx_destroy(struct wdp *wdp)
{
    struct wx *wx = wx_cast(wdp);

    return xfif_delete(wx->xfif);
}

static void
hton_ofp_phy_port(struct ofp_phy_port *opp)
{
    opp->port_no = htons(opp->port_no);
    opp->config = htonl(opp->config);
    opp->state = htonl(opp->state);
    opp->curr = htonl(opp->curr);
    opp->advertised = htonl(opp->advertised);
    opp->supported = htonl(opp->supported);
    opp->peer = htonl(opp->peer);
}

static int
wx_get_features(const struct wdp *wdp, struct ofpbuf **featuresp)
{
    struct wx *wx = wx_cast(wdp);
    struct ofp_switch_features *osf;
    struct ofpbuf *buf;
    unsigned int port_no;
    struct wdp_port *port;

    osf = make_openflow(sizeof *osf, OFPT_FEATURES_REPLY, &buf);
    osf->n_tables = 2;
    osf->capabilities = htonl(OFPC_ARP_MATCH_IP);
    osf->actions = htonl((1u << OFPAT_OUTPUT) |
                         (1u << OFPAT_SET_VLAN_VID) |
                         (1u << OFPAT_SET_VLAN_PCP) |
                         (1u << OFPAT_STRIP_VLAN) |
                         (1u << OFPAT_SET_DL_SRC) |
                         (1u << OFPAT_SET_DL_DST) |
                         (1u << OFPAT_SET_NW_SRC) |
                         (1u << OFPAT_SET_NW_DST) |
                         (1u << OFPAT_SET_NW_TOS) |
                         (1u << OFPAT_SET_TP_SRC) |
                         (1u << OFPAT_SET_TP_DST));

    PORT_ARRAY_FOR_EACH (port, &wx->ports, port_no) {
        hton_ofp_phy_port(ofpbuf_put(buf, &port->opp, sizeof port->opp));
    }

    *featuresp = buf;
    return 0;
}

static void
count_subrules(struct cls_rule *cls_rule, void *n_subrules_)
{
    struct wx_rule *rule = wx_rule_cast(cls_rule);
    int *n_subrules = n_subrules_;

    if (rule->super) {
        (*n_subrules)++;
    }
}

static int
wx_get_stats(const struct wdp *wdp, struct wdp_stats *stats)
{
    struct wx *wx = wx_cast(wdp);
    struct xflow_stats xflow_stats;
    int n_subrules;
    int error;

    error = xfif_get_xf_stats(wx->xfif, &xflow_stats);

    n_subrules = 0;
    classifier_for_each(&wx->cls, CLS_INC_EXACT, count_subrules, &n_subrules);

    stats->exact.n_flows = classifier_count_exact(&wx->cls) - n_subrules;
    stats->exact.cur_capacity = xflow_stats.cur_capacity;
    stats->exact.max_capacity = MIN(WX_MAX_EXACT, xflow_stats.max_capacity);
    stats->exact.n_hit = xflow_stats.n_hit;
    stats->exact.n_missed = xflow_stats.n_missed;
    stats->exact.n_lost = xflow_stats.n_lost;

    stats->wild.n_flows = classifier_count_wild(&wx->cls);
    stats->wild.cur_capacity = WX_MAX_WILD;
    stats->wild.max_capacity = WX_MAX_WILD;
    stats->wild.n_hit = 0;      /* XXX */
    stats->wild.n_missed = 0;   /* XXX */
    stats->wild.n_lost = 0;     /* XXX */

    stats->n_ports = xflow_stats.n_ports;
    stats->max_ports = xflow_stats.max_ports;

    stats->n_frags = xflow_stats.n_frags;

    stats->max_miss_queue = xflow_stats.max_miss_queue;
    stats->max_action_queue = xflow_stats.max_action_queue;
    stats->max_sflow_queue = xflow_stats.max_sflow_queue;

    return error;
}

static int
wx_get_drop_frags(const struct wdp *wdp, bool *drop_frags)
{
    struct wx *wx = wx_cast(wdp);

    return xfif_get_drop_frags(wx->xfif, drop_frags);
}

static int
wx_set_drop_frags(struct wdp *wdp, bool drop_frags)
{
    struct wx *wx = wx_cast(wdp);

    return xfif_set_drop_frags(wx->xfif, drop_frags);
}

static int
wx_port_add(struct wdp *wdp, const char *devname,
            bool internal, uint16_t *port_no)
{
    struct wx *wx = wx_cast(wdp);
    uint16_t xflow_flags = internal ? XFLOW_PORT_INTERNAL : 0;
    return xfif_port_add(wx->xfif, devname, xflow_flags, port_no);
}

static int
wx_port_del(struct wdp *wdp, uint16_t port_no)
{
    struct wx *wx = wx_cast(wdp);

    return xfif_port_del(wx->xfif, port_no);
}

static int
wx_port_query_by_number(const struct wdp *wdp, uint16_t port_no,
                        struct wdp_port **portp)
{
    struct wx *wx = wx_cast(wdp);

    *portp = port_array_get(&wx->ports, ofp_port_to_xflow_port(port_no));
    return *portp ? 0 : ENOENT;
}

static int
wx_port_query_by_name(const struct wdp *wdp, const char *devname,
                      struct wdp_port **portp)
{
    struct wx *wx = wx_cast(wdp);

    *portp = shash_find_data(&wx->port_by_name, devname);
    return *portp ? 0 : ENOENT;
}

static int
wx_port_set_config(struct wdp *wdp, uint16_t port_no, uint32_t config)
{
    struct wx *wx = wx_cast(wdp);
    struct wdp_port *port;
    uint32_t changes;

    port = port_array_get(&wx->ports, ofp_port_to_xflow_port(port_no));
    if (!port) {
        return ENOENT;
    }
    changes = config ^ port->opp.config;

    if (changes & OFPPC_PORT_DOWN) {
        int error;
        if (config & OFPPC_PORT_DOWN) {
            error = netdev_turn_flags_off(port->netdev, NETDEV_UP, true);
        } else {
            error = netdev_turn_flags_on(port->netdev, NETDEV_UP, true);
        }
        if (!error) {
            port->opp.config ^= OFPPC_PORT_DOWN;
        }
    }

#define REVALIDATE_BITS (OFPPC_NO_RECV | OFPPC_NO_RECV_STP | OFPPC_NO_FWD)
    if (changes & REVALIDATE_BITS) {
        COVERAGE_INC(wx_costly_flags);
        port->opp.config ^= changes & REVALIDATE_BITS;
        wx->need_revalidate = true;
    }
#undef REVALIDATE_BITS

    if (changes & OFPPC_NO_FLOOD) {
        port->opp.config ^= OFPPC_NO_FLOOD;
        wx_port_refresh_groups(wx);
    }

    if (changes & OFPPC_NO_PACKET_IN) {
        port->opp.config ^= OFPPC_NO_PACKET_IN;
    }

    return 0;
}

static int
wx_port_list(const struct wdp *wdp, struct wdp_port ***portsp,
             size_t *n_portsp)
{
    struct wx *wx = wx_cast(wdp);
    struct wdp_port **ports;
    struct wdp_port *port;
    unsigned int port_no;
    size_t n_ports, i;

    *n_portsp = n_ports = port_array_count(&wx->ports);
    *portsp = ports = xmalloc(n_ports * sizeof *ports);
    i = 0;
    PORT_ARRAY_FOR_EACH (port, &wx->ports, port_no) {
        ports[i++] = port;
    }
    assert(i == n_ports);

    return 0;
}

static int
wx_port_poll(const struct wdp *wdp, char **devnamep)
{
    struct wx *wx = wx_cast(wdp);

    return xfif_port_poll(wx->xfif, devnamep);
}

static void
wx_port_poll_wait(const struct wdp *wdp)
{
    struct wx *wx = wx_cast(wdp);

    xfif_port_poll_wait(wx->xfif);
}

static struct wdp_rule *
wx_flow_get(const struct wdp *wdp, const flow_t *flow)
{
    struct wx *wx = wx_cast(wdp);
    struct wx_rule *rule;

    rule = wx_rule_cast(classifier_find_rule_exactly(&wx->cls, flow));
    return rule && !wx_rule_is_hidden(rule) ? &rule->wr : NULL;
}

static struct wdp_rule *
wx_flow_match(const struct wdp *wdp, const flow_t *flow)
{
    struct wx *wx = wx_cast(wdp);
    struct wx_rule *rule;

    rule = wx_rule_cast(classifier_lookup(&wx->cls, flow));
    if (rule) {
        if (wx_rule_is_hidden(rule)) {
            rule = rule->super;
        }
        return &rule->wr;
    } else {
        return NULL;
    }
}

struct wx_for_each_thunk_aux {
    wdp_flow_cb_func *client_callback;
    void *client_aux;
};

static void
wx_for_each_thunk(struct cls_rule *cls_rule, void *aux_)
{
    struct wx_for_each_thunk_aux *aux = aux_;
    struct wx_rule *rule = wx_rule_cast(cls_rule);

    if (!wx_rule_is_hidden(rule)) {
        aux->client_callback(&rule->wr, aux->client_aux);
    }
}

static void
wx_flow_for_each_match(const struct wdp *wdp, const flow_t *target,
                       int include,
                       wdp_flow_cb_func *client_callback, void *client_aux)
{
    struct wx *wx = wx_cast(wdp);
    struct wx_for_each_thunk_aux aux;

    aux.client_callback = client_callback;
    aux.client_aux = client_aux;
    classifier_for_each_match(&wx->cls, target, include,
                              wx_for_each_thunk, &aux);
}

/* Obtains statistic counters for 'rule' within 'wx' and stores them into
 * '*stats'.  If 'rule' is a wildcarded rule, the returned statistic include
 * statistics for all of 'rule''s subrules. */
static void
query_stats(struct wx *wx, struct wx_rule *rule, struct wdp_flow_stats *stats)
{
    struct wx_rule *subrule;
    struct xflow_flow *xflow_flows;
    size_t n_xflow_flows;

    /* Start from historical data for 'rule' itself that are no longer tracked
     * by the datapath.  This counts, for example, subrules that have
     * expired. */
    stats->n_packets = rule->packet_count;
    stats->n_bytes = rule->byte_count;
    stats->inserted = rule->wr.created;
    stats->used = LLONG_MIN;
    stats->tcp_flags = 0;
    stats->ip_tos = 0;

    /* Prepare to ask the datapath for statistics on 'rule', or if it is
     * wildcarded then on all of its subrules.
     *
     * Also, add any statistics that are not tracked by the datapath for each
     * subrule.  This includes, for example, statistics for packets that were
     * executed "by hand" by ofproto via xfif_execute() but must be accounted
     * to a flow. */
    n_xflow_flows = rule->wr.cr.flow.wildcards ? list_size(&rule->list) : 1;
    xflow_flows = xzalloc(n_xflow_flows * sizeof *xflow_flows);
    if (rule->wr.cr.flow.wildcards) {
        size_t i = 0;
        LIST_FOR_EACH (subrule, struct wx_rule, list, &rule->list) {
            xflow_key_from_flow(&xflow_flows[i++].key, &subrule->wr.cr.flow);
            stats->n_packets += subrule->packet_count;
            stats->n_bytes += subrule->byte_count;
        }
    } else {
        xflow_key_from_flow(&xflow_flows[0].key, &rule->wr.cr.flow);
    }

    /* Fetch up-to-date statistics from the datapath and add them in. */
    if (!xfif_flow_get_multiple(wx->xfif, xflow_flows, n_xflow_flows)) {
        size_t i;
        for (i = 0; i < n_xflow_flows; i++) {
            struct xflow_flow *xflow_flow = &xflow_flows[i];
            long long int used;

            stats->n_packets += xflow_flow->stats.n_packets;
            stats->n_bytes += xflow_flow->stats.n_bytes;
            used = xflow_flow_stats_to_msec(&xflow_flow->stats);
            if (used > stats->used) {
                stats->used = used;
                if (xflow_flow->key.dl_type == htons(ETH_TYPE_IP)
                    && xflow_flow->key.nw_proto == IP_TYPE_TCP) {
                    stats->ip_tos = xflow_flow->stats.ip_tos;
                }
            }
            stats->tcp_flags |= xflow_flow->stats.tcp_flags;
        }
    }
    free(xflow_flows);
}

static int
wx_flow_get_stats(const struct wdp *wdp,
                  const struct wdp_rule *wdp_rule,
                  struct wdp_flow_stats *stats)
{
    struct wx *wx = wx_cast(wdp);
    struct wx_rule *rule = wx_rule_cast(&wdp_rule->cr);

    query_stats(wx, rule, stats);
    return 0;
}

static bool
wx_flow_overlaps(const struct wdp *wdp, const flow_t *flow)
{
    struct wx *wx = wx_cast(wdp);

    /* XXX overlap with a subrule? */
    return classifier_rule_overlaps(&wx->cls, flow);
}

static int
wx_flow_put(struct wdp *wdp, const struct wdp_flow_put *put,
            struct wdp_flow_stats *old_stats, struct wdp_rule **rulep)
{
    struct wx *wx = wx_cast(wdp);
    struct wx_rule *rule;

    rule = wx_rule_cast(classifier_find_rule_exactly(&wx->cls, put->flow));
    if (rule && wx_rule_is_hidden(rule)) {
        rule = NULL;
    }

    if (rule) {
        if (!(put->flags & WDP_PUT_MODIFY)) {
            return EEXIST;
        }
    } else {
        if (!(put->flags & WDP_PUT_CREATE)) {
            return EINVAL;
        }
        if ((put->flow->wildcards
             ? classifier_count_wild(&wx->cls) >= WX_MAX_WILD
             : classifier_count_exact(&wx->cls) >= WX_MAX_EXACT)) {
            /* XXX subrules should not count against exact-match limit */
            return ENOBUFS;
        }
    }

    rule = wx_rule_create(NULL, put->actions, put->n_actions,
                          put->idle_timeout, put->hard_timeout);
    cls_rule_from_flow(&rule->wr.cr, put->flow);
    wx_rule_insert(wx, rule, NULL, 0);

    if (old_stats) {
        /* XXX */
        memset(old_stats, 0, sizeof *old_stats);
    }
    if (rulep) {
        *rulep = &rule->wr;
    }

    return 0;
}

static int
wx_flow_delete(struct wdp *wdp, struct wdp_rule *wdp_rule,
               struct wdp_flow_stats *final_stats)
{
    struct wx *wx = wx_cast(wdp);
    struct wx_rule *rule = wx_rule_cast(&wdp_rule->cr);

    wx_rule_remove(wx, rule);
    if (final_stats) {
        memset(final_stats, 0, sizeof *final_stats); /* XXX */
    }
    return 0;
}

static void
wx_flush_rule(struct cls_rule *cls_rule, void *wx_)
{
    struct wx_rule *rule = wx_rule_cast(cls_rule);
    struct wx *wx = wx_;

    /* Mark the flow as not installed, even though it might really be
     * installed, so that wx_rule_remove() doesn't bother trying to uninstall
     * it.  There is no point in uninstalling it individually since we are
     * about to blow away all the flows with xfif_flow_flush(). */
    rule->installed = false;

    wx_rule_remove(wx, rule);
}

static int
wx_flow_flush(struct wdp *wdp)
{
    struct wx *wx = wx_cast(wdp);

    COVERAGE_INC(wx_flow_flush);
    classifier_for_each(&wx->cls, CLS_INC_ALL, wx_flush_rule, wx);
    xfif_flow_flush(wx->xfif);
    return 0;
}

static int
wx_execute(struct wdp *wdp, uint16_t in_port,
           const union ofp_action actions[], int n_actions,
           const struct ofpbuf *packet)
{
    struct wx *wx = wx_cast(wdp);
    struct xflow_actions xflow_actions;
    flow_t flow;
    int error;

    flow_extract((struct ofpbuf *) packet, in_port, &flow);
    error = wx_xlate_actions(wx, actions, n_actions, &flow, packet,
                             &xflow_actions, NULL);
    if (error) {
        return error;
    }
    xfif_execute(wx->xfif, ofp_port_to_xflow_port(in_port),
                 xflow_actions.actions, xflow_actions.n_actions, packet);
    return 0;
}

static int
wx_flow_inject(struct wdp *wdp, struct wdp_rule *wdp_rule,
               uint16_t in_port, const struct ofpbuf *packet)
{
    struct wx_rule *rule = wx_rule_cast(&wdp_rule->cr);
    int error;

    error = wx_execute(wdp, in_port, rule->wr.actions, rule->wr.n_actions,
                       packet);
    if (!error) {
        rule->packet_count++;
        rule->byte_count += packet->size;
        rule->used = time_msec();
    }
    return error;
}

static int
wx_recv_get_mask(const struct wdp *wdp, int *listen_mask)
{
    struct wx *wx = wx_cast(wdp);
    int xflow_listen_mask;
    int error;

    error = xfif_recv_get_mask(wx->xfif, &xflow_listen_mask);
    if (!error) {
        *listen_mask = 0;
        if (xflow_listen_mask & XFLOWL_MISS) {
            *listen_mask |= 1 << WDP_CHAN_MISS;
        }
        if (xflow_listen_mask & XFLOWL_ACTION) {
            *listen_mask |= 1 << WDP_CHAN_ACTION;
        }
        if (xflow_listen_mask & XFLOWL_SFLOW) {
            *listen_mask |= 1 << WDP_CHAN_SFLOW;
        }
    }
    return error;
}

static int
wx_recv_set_mask(struct wdp *wdp, int listen_mask)
{
    struct wx *wx = wx_cast(wdp);
    int xflow_listen_mask;

    xflow_listen_mask = 0;
    if (listen_mask & (1 << WDP_CHAN_MISS)) {
        xflow_listen_mask |= XFLOWL_MISS;
    }
    if (listen_mask & (1 << WDP_CHAN_ACTION)) {
        xflow_listen_mask |= XFLOWL_ACTION;
    }
    if (listen_mask & (1 << WDP_CHAN_SFLOW)) {
        xflow_listen_mask |= XFLOWL_SFLOW;
    }

    return xfif_recv_set_mask(wx->xfif, xflow_listen_mask);
}

static int
wx_get_sflow_probability(const struct wdp *wdp, uint32_t *probability)
{
    struct wx *wx = wx_cast(wdp);

    return xfif_get_sflow_probability(wx->xfif, probability);
}

static int
wx_set_sflow_probability(struct wdp *wdp, uint32_t probability)
{
    struct wx *wx = wx_cast(wdp);

    return xfif_set_sflow_probability(wx->xfif, probability);
}

static int
wx_translate_xflow_msg(struct xflow_msg *msg, struct ofpbuf *payload,
                       struct wdp_packet *packet)
{
    packet->in_port = xflow_port_to_ofp_port(msg->port);
    packet->send_len = 0;

    switch (msg->type) {
    case _XFLOWL_MISS_NR:
        packet->channel = WDP_CHAN_MISS;
        packet->payload = payload;
        return 0;

    case _XFLOWL_ACTION_NR:
        packet->channel = WDP_CHAN_ACTION;
        packet->payload = payload;
        packet->send_len = msg->arg;
        return 0;

    case _XFLOWL_SFLOW_NR:
        /* XXX */
        ofpbuf_delete(payload);
        return ENOSYS;

    default:
        VLOG_WARN_RL(&rl, "received XFLOW message of unexpected type %"PRIu32,
                     msg->type);
        ofpbuf_delete(payload);
        return ENOSYS;
    }
}

static const uint8_t *
get_local_mac(const struct wx *wx)
{
    const struct wdp_port *port = port_array_get(&wx->ports, XFLOWP_LOCAL);
    return port ? port->opp.hw_addr : NULL;
}

/* Returns true if 'packet' is a DHCP reply to the local port.  Such a reply
 * should be sent to the local port regardless of the flow table.
 *
 * We only need this, strictly speaking, when in-band control is turned on. */
static bool
wx_is_local_dhcp_reply(const struct wx *wx,
                       const flow_t *flow, const struct ofpbuf *packet)
{
    if (flow->dl_type == htons(ETH_TYPE_IP)
        && flow->nw_proto == IP_TYPE_UDP
        && flow->tp_src == htons(DHCP_SERVER_PORT)
        && flow->tp_dst == htons(DHCP_CLIENT_PORT)
        && packet->l7)
    {
        const uint8_t *local_mac = get_local_mac(wx);
        struct dhcp_header *dhcp = ofpbuf_at(
            packet, (char *)packet->l7 - (char *)packet->data, sizeof *dhcp);
        return dhcp && local_mac && eth_addr_equals(dhcp->chaddr, local_mac);
    }

    return false;
}

static bool
wx_explode_rule(struct wx *wx, struct xflow_msg *msg, struct ofpbuf *payload)
{
    struct wx_rule *rule;
    flow_t flow;

    flow_extract(payload, xflow_port_to_ofp_port(msg->port), &flow);

    if (wx_is_local_dhcp_reply(wx, &flow, payload)) {
        union xflow_action action;

        memset(&action, 0, sizeof(action));
        action.output.type = XFLOWAT_OUTPUT;
        action.output.port = XFLOWP_LOCAL;
        xfif_execute(wx->xfif, msg->port, &action, 1, payload);
    }

    rule = wx_rule_lookup_valid(wx, &flow);
    if (!rule) {
        return false;
    }

    if (rule->wr.cr.flow.wildcards) {
        rule = wx_rule_create_subrule(wx, rule, &flow);
        wx_rule_make_actions(wx, rule, payload);
    } else {
        if (!rule->may_install) {
            /* The rule is not installable, that is, we need to process every
             * packet, so process the current packet and set its actions into
             * 'subrule'. */
            wx_rule_make_actions(wx, rule, payload);
        } else {
            /* XXX revalidate rule if it needs it */
        }
    }

    wx_rule_execute(wx, rule, payload, &flow);
    wx_rule_reinstall(wx, rule);

    return true;
}

static int
wx_recv(struct wdp *wdp, struct wdp_packet *packet)
{
    struct wx *wx = wx_cast(wdp);
    int i;

    /* XXX need to avoid 50*50 potential cost for caller. */
    for (i = 0; i < 50; i++) {
        struct xflow_msg *msg;
        struct ofpbuf *buf;
        int error;

        error = xfif_recv(wx->xfif, &buf);
        if (error) {
            return error;
        }

        msg = ofpbuf_pull(buf, sizeof *msg);
        if (msg->type != _XFLOWL_MISS_NR || !wx_explode_rule(wx, msg, buf)) {
            return wx_translate_xflow_msg(msg, buf, packet);
        }
        ofpbuf_delete(buf);
    }
    return EAGAIN;
}

static void
wx_recv_wait(struct wdp *wdp)
{
    struct wx *wx = wx_cast(wdp);

    xfif_recv_wait(wx->xfif);
}

static void wx_port_update(struct wx *, const char *devname);
static void wx_port_reinit(struct wx *);

static void
wx_port_process_change(struct wx *wx, int error, char *devname)
{
    if (error == ENOBUFS) {
        wx_port_reinit(wx);
    } else if (!error) {
        wx_port_update(wx, devname);
        free(devname);
    }
}

static void
wx_port_run(struct wx *wx)
{
    char *devname;
    int error;

    while ((error = xfif_port_poll(wx->xfif, &devname)) != EAGAIN) {
        wx_port_process_change(wx, error, devname);
    }
    while ((error = netdev_monitor_poll(wx->netdev_monitor,
                                        &devname)) != EAGAIN) {
        wx_port_process_change(wx, error, devname);
    }
}

static size_t
wx_port_refresh_group(struct wx *wx, unsigned int group)
{
    uint16_t *ports;
    size_t n_ports;
    struct wdp_port *port;
    unsigned int port_no;

    assert(group == WX_GROUP_ALL || group == WX_GROUP_FLOOD);

    ports = xmalloc(port_array_count(&wx->ports) * sizeof *ports);
    n_ports = 0;
    PORT_ARRAY_FOR_EACH (port, &wx->ports, port_no) {
        if (group == WX_GROUP_ALL || !(port->opp.config & OFPPC_NO_FLOOD)) {
            ports[n_ports++] = port_no;
        }
    }
    xfif_port_group_set(wx->xfif, group, ports, n_ports);
    free(ports);

    return n_ports;
}

static void
wx_port_refresh_groups(struct wx *wx)
{
    wx_port_refresh_group(wx, WX_GROUP_FLOOD);
    wx_port_refresh_group(wx, WX_GROUP_ALL);
}

static void
wx_port_reinit(struct wx *wx)
{
    struct svec devnames;
    struct wdp_port *wdp_port;
    unsigned int port_no;
    struct xflow_port *xflow_ports;
    size_t n_xflow_ports;
    size_t i;

    svec_init(&devnames);
    PORT_ARRAY_FOR_EACH (wdp_port, &wx->ports, port_no) {
        svec_add (&devnames, (char *) wdp_port->opp.name);
    }
    xfif_port_list(wx->xfif, &xflow_ports, &n_xflow_ports);
    for (i = 0; i < n_xflow_ports; i++) {
        svec_add(&devnames, xflow_ports[i].devname);
    }
    free(xflow_ports);

    svec_sort_unique(&devnames);
    for (i = 0; i < devnames.n; i++) {
        wx_port_update(wx, devnames.names[i]);
    }
    svec_destroy(&devnames);

    wx_port_refresh_groups(wx);
}

static struct wdp_port *
make_wdp_port(const struct xflow_port *xflow_port)
{
    struct netdev_options netdev_options;
    enum netdev_flags flags;
    struct wdp_port *wdp_port;
    struct netdev *netdev;
    bool carrier;
    int error;

    memset(&netdev_options, 0, sizeof netdev_options);
    netdev_options.name = xflow_port->devname;
    netdev_options.ethertype = NETDEV_ETH_TYPE_NONE;
    netdev_options.may_create = true;
    netdev_options.may_open = true;

    error = netdev_open(&netdev_options, &netdev);
    if (error) {
        VLOG_WARN_RL(&rl, "ignoring port %s (%"PRIu16") because netdev %s "
                     "cannot be opened (%s)",
                     xflow_port->devname, xflow_port->port,
                     xflow_port->devname, strerror(error));
        return NULL;
    }

    wdp_port = xmalloc(sizeof *wdp_port);
    wdp_port->netdev = netdev;
    wdp_port->opp.port_no = xflow_port_to_ofp_port(xflow_port->port);
    netdev_get_etheraddr(netdev, wdp_port->opp.hw_addr);
    strncpy((char *) wdp_port->opp.name, xflow_port->devname,
            sizeof wdp_port->opp.name);
    wdp_port->opp.name[sizeof wdp_port->opp.name - 1] = '\0';

    netdev_get_flags(netdev, &flags);
    wdp_port->opp.config = flags & NETDEV_UP ? 0 : OFPPC_PORT_DOWN;

    netdev_get_carrier(netdev, &carrier);
    wdp_port->opp.state = carrier ? 0 : OFPPS_LINK_DOWN;

    netdev_get_features(netdev,
                        &wdp_port->opp.curr, &wdp_port->opp.advertised,
                        &wdp_port->opp.supported, &wdp_port->opp.peer);

    wdp_port->devname = xstrdup(xflow_port->devname);
    wdp_port->internal = (xflow_port->flags & XFLOW_PORT_INTERNAL) != 0;
    return wdp_port;
}

static bool
wx_port_conflicts(const struct wx *wx, const struct xflow_port *xflow_port)
{
    if (port_array_get(&wx->ports, xflow_port->port)) {
        VLOG_WARN_RL(&rl, "ignoring duplicate port %"PRIu16" in datapath",
                     xflow_port->port);
        return true;
    } else if (shash_find(&wx->port_by_name, xflow_port->devname)) {
        VLOG_WARN_RL(&rl, "ignoring duplicate device %s in datapath",
                     xflow_port->devname);
        return true;
    } else {
        return false;
    }
}

static int
wdp_port_equal(const struct wdp_port *a_, const struct wdp_port *b_)
{
    const struct ofp_phy_port *a = &a_->opp;
    const struct ofp_phy_port *b = &b_->opp;

    BUILD_ASSERT_DECL(sizeof *a == 48); /* Detect ofp_phy_port changes. */
    return (a->port_no == b->port_no
            && !memcmp(a->hw_addr, b->hw_addr, sizeof a->hw_addr)
            && !strcmp((char *) a->name, (char *) b->name)
            && a->state == b->state
            && a->config == b->config
            && a->curr == b->curr
            && a->advertised == b->advertised
            && a->supported == b->supported
            && a->peer == b->peer);
}

static void
wx_port_install(struct wx *wx, struct wdp_port *wdp_port)
{
    uint16_t xflow_port = ofp_port_to_xflow_port(wdp_port->opp.port_no);
    const char *netdev_name = (const char *) wdp_port->opp.name;

    netdev_monitor_add(wx->netdev_monitor, wdp_port->netdev);
    port_array_set(&wx->ports, xflow_port, wdp_port);
    shash_add(&wx->port_by_name, netdev_name, wdp_port);
}

static void
wx_port_remove(struct wx *wx, struct wdp_port *wdp_port)
{
    uint16_t xflow_port = ofp_port_to_xflow_port(wdp_port->opp.port_no);

    netdev_monitor_remove(wx->netdev_monitor, wdp_port->netdev);
    port_array_set(&wx->ports, xflow_port, NULL);
    shash_delete(&wx->port_by_name,
                 shash_find(&wx->port_by_name, (char *) wdp_port->opp.name));
}

static void
wx_port_free(struct wdp_port *wdp_port)
{
    if (wdp_port) {
        netdev_close(wdp_port->netdev);
        free(wdp_port);
    }
}

static void
wx_port_update(struct wx *wx, const char *devname)
{
    struct xflow_port xflow_port;
    struct wdp_port *old_wdp_port;
    struct wdp_port *new_wdp_port;
    int error;

    COVERAGE_INC(wx_update_port);

    /* Query the datapath for port information. */
    error = xfif_port_query_by_name(wx->xfif, devname, &xflow_port);

    /* Find the old wdp_port. */
    old_wdp_port = shash_find_data(&wx->port_by_name, devname);
    if (!error) {
        if (!old_wdp_port) {
            /* There's no port named 'devname' but there might be a port with
             * the same port number.  This could happen if a port is deleted
             * and then a new one added in its place very quickly, or if a port
             * is renamed.  In the former case we want to send an OFPPR_DELETE
             * and an OFPPR_ADD, and in the latter case we want to send a
             * single OFPPR_MODIFY.  We can distinguish the cases by comparing
             * the old port's ifindex against the new port, or perhaps less
             * reliably but more portably by comparing the old port's MAC
             * against the new port's MAC.  However, this code isn't that smart
             * and always sends an OFPPR_MODIFY (XXX). */
            old_wdp_port = port_array_get(&wx->ports, xflow_port.port);
        }
    } else if (error != ENOENT && error != ENODEV) {
        VLOG_WARN_RL(&rl, "xfif_port_query_by_name returned unexpected error "
                     "%s", strerror(error));
        return;
    }

    /* Create a new wdp_port. */
    new_wdp_port = !error ? make_wdp_port(&xflow_port) : NULL;

    /* Eliminate a few pathological cases. */
    if (!old_wdp_port && !new_wdp_port) {
        return;
    } else if (old_wdp_port && new_wdp_port) {
        /* Most of the 'config' bits are OpenFlow soft state, but
         * OFPPC_PORT_DOWN is maintained by the kernel.  So transfer the
         * OpenFlow bits from old_wdp_port.  (make_wdp_port() only sets
         * OFPPC_PORT_DOWN and leaves the other bits 0.)  */
        new_wdp_port->opp.config |= old_wdp_port->opp.config & ~OFPPC_PORT_DOWN;

        if (wdp_port_equal(old_wdp_port, new_wdp_port)) {
            /* False alarm--no change. */
            wx_port_free(new_wdp_port);
            return;
        }
    }

    /* Now deal with the normal cases. */
    if (old_wdp_port) {
        wx_port_remove(wx, old_wdp_port);
    }
    if (new_wdp_port) {
        wx_port_install(wx, new_wdp_port);
    }
    wx_port_free(old_wdp_port);
}

static int
wx_port_init(struct wx *wx)
{
    struct xflow_port *ports;
    size_t n_ports;
    size_t i;
    int error;

    error = xfif_port_list(wx->xfif, &ports, &n_ports);
    if (error) {
        return error;
    }

    for (i = 0; i < n_ports; i++) {
        const struct xflow_port *xflow_port = &ports[i];
        if (!wx_port_conflicts(wx, xflow_port)) {
            struct wdp_port *wdp_port = make_wdp_port(xflow_port);
            if (wdp_port) {
                wx_port_install(wx, wdp_port);
            }
        }
    }
    free(ports);
    wx_port_refresh_groups(wx);
    return 0;
}

void
wdp_xflow_register(void)
{
    static const struct wdp_class wdp_xflow_class = {
        NULL,                   /* name */
        wx_run,
        wx_wait,
        wx_enumerate,
        wx_open,
        wx_close,
        wx_get_all_names,
        wx_destroy,
        wx_get_features,
        wx_get_stats,
        wx_get_drop_frags,
        wx_set_drop_frags,
        wx_port_add,
        wx_port_del,
        wx_port_query_by_number,
        wx_port_query_by_name,
        wx_port_list,
        wx_port_set_config,
        wx_port_poll,
        wx_port_poll_wait,
        wx_flow_get,
        wx_flow_match,
        wx_flow_for_each_match,
        wx_flow_get_stats,
        wx_flow_overlaps,
        wx_flow_put,
        wx_flow_delete,
        wx_flow_flush,
        wx_flow_inject,
        wx_execute,
        wx_recv_get_mask,
        wx_recv_set_mask,
        wx_get_sflow_probability,
        wx_set_sflow_probability,
        wx_recv,
        wx_recv_wait,
    };

    static bool inited = false;

    struct svec types;
    const char *type;
    bool registered;
    int i;

    if (inited) {
        return;
    }
    inited = true;

    svec_init(&types);
    xf_enumerate_types(&types);

    registered = false;
    SVEC_FOR_EACH (i, type, &types) {
        struct wdp_class *class;

        class = xmalloc(sizeof *class);
        *class = wdp_xflow_class;
        class->type = xstrdup(type);
        if (registered) {
            class->run = NULL;
            class->wait = NULL;
        }
        if (!wdp_register_provider(class)) {
            registered = true;
        }
    }

    svec_destroy(&types);
}
