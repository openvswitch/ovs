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

#include <config.h>

#include "ofproto/ofproto-dpif-xlate.h"

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
#include "lacp.h"
#include "learn.h"
#include "mac-learning.h"
#include "meta-flow.h"
#include "multipath.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-execute.h"
#include "ofp-actions.h"
#include "ofproto/ofproto-dpif-ipfix.h"
#include "ofproto/ofproto-dpif-sflow.h"
#include "ofproto/ofproto-dpif.h"
#include "tunnel.h"
#include "vlog.h"

COVERAGE_DEFINE(ofproto_dpif_xlate);

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_xlate);

/* Maximum depth of flow table recursion (due to resubmit actions) in a
 * flow translation. */
#define MAX_RESUBMIT_RECURSION 64

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
    odp_port_t sflow_odp_port;  /* Output port for composing sFlow action. */
    uint16_t user_cookie_offset;/* Used for user_action_cookie fixup. */
    bool exit;                  /* No further actions should be processed. */
};

/* A controller may use OFPP_NONE as the ingress port to indicate that
 * it did not arrive on a "real" port.  'ofpp_none_bundle' exists for
 * when an input bundle is needed for validation (e.g., mirroring or
 * OFPP_NORMAL processing).  It is not connected to an 'ofproto' or have
 * any 'port' structs, so care must be taken when dealing with it. */
static struct ofbundle ofpp_none_bundle = {
    .name      = "OFPP_NONE",
    .vlan_mode = PORT_VLAN_TRUNK
};

static bool may_receive(const struct ofport_dpif *, struct xlate_ctx *);
static void do_xlate_actions(const struct ofpact *, size_t ofpacts_len,
                             struct xlate_ctx *);
static void xlate_normal(struct xlate_ctx *);
static void xlate_report(struct xlate_ctx *, const char *);
static void xlate_table_action(struct xlate_ctx *, ofp_port_t in_port,
                               uint8_t table_id, bool may_packet_in);
static bool input_vid_is_valid(uint16_t vid, struct ofbundle *, bool warn);
static uint16_t input_vid_to_vlan(const struct ofbundle *, uint16_t vid);
static void output_normal(struct xlate_ctx *, const struct ofbundle *,
                          uint16_t vlan);
static void compose_output_action(struct xlate_ctx *, ofp_port_t ofp_port);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

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

static bool
vlan_is_mirrored(const struct ofmirror *m, int vlan)
{
    return !m->vlans || bitmap_is_set(m->vlans, vlan);
}

static struct ofbundle *
lookup_input_bundle(const struct ofproto_dpif *ofproto, ofp_port_t in_port,
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

static void
add_mirror_actions(struct xlate_ctx *ctx, const struct flow *orig_flow)
{
    struct ofproto_dpif *ofproto = ctx->ofproto;
    mirror_mask_t mirrors;
    struct ofbundle *in_bundle;
    uint16_t vlan;
    uint16_t vid;
    const struct nlattr *a;
    size_t left;

    in_bundle = lookup_input_bundle(ctx->ofproto, orig_flow->in_port.ofp_port,
                                    ctx->xin->packet != NULL, NULL);
    if (!in_bundle) {
        return;
    }
    mirrors = in_bundle->src_mirrors;

    /* Drop frames on bundles reserved for mirroring. */
    if (in_bundle->mirror_out) {
        if (ctx->xin->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port "
                         "%s, which is reserved exclusively for mirroring",
                         ctx->ofproto->up.name, in_bundle->name);
        }
        return;
    }

    /* Check VLAN. */
    vid = vlan_tci_to_vid(orig_flow->vlan_tci);
    if (!input_vid_is_valid(vid, in_bundle, ctx->xin->packet != NULL)) {
        return;
    }
    vlan = input_vid_to_vlan(in_bundle, vid);

    /* Look at the output ports to check for destination selections. */

    NL_ATTR_FOR_EACH (a, left, ctx->xout->odp_actions.data,
                      ctx->xout->odp_actions.size) {
        enum ovs_action_attr type = nl_attr_type(a);
        struct ofport_dpif *ofport;

        if (type != OVS_ACTION_ATTR_OUTPUT) {
            continue;
        }

        ofport = get_odp_port(ofproto, nl_attr_get_odp_port(a));
        if (ofport && ofport->bundle) {
            mirrors |= ofport->bundle->dst_mirrors;
        }
    }

    if (!mirrors) {
        return;
    }

    /* Restore the original packet before adding the mirror actions. */
    ctx->xin->flow = *orig_flow;

    while (mirrors) {
        struct ofmirror *m;

        m = ofproto->mirrors[mirror_mask_ffs(mirrors) - 1];

        if (m->vlans) {
            ctx->xout->wc.masks.vlan_tci |= htons(VLAN_CFI | VLAN_VID_MASK);
        }

        if (!vlan_is_mirrored(m, vlan)) {
            mirrors = zero_rightmost_1bit(mirrors);
            continue;
        }

        mirrors &= ~m->dup_mirrors;
        ctx->xout->mirrors |= m->dup_mirrors;
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
output_normal(struct xlate_ctx *ctx, const struct ofbundle *out_bundle,
              uint16_t vlan)
{
    ovs_be16 *flow_tci = &ctx->xin->flow.vlan_tci;
    struct ofport_dpif *port;
    uint16_t vid;
    ovs_be16 tci, old_tci;

    vid = output_vlan_to_vid(out_bundle, vlan);
    if (!out_bundle->bond) {
        port = ofbundle_get_a_port(out_bundle);
    } else {
        port = bond_choose_output_slave(out_bundle->bond, &ctx->xin->flow,
                                        &ctx->xout->wc, vid, &ctx->xout->tags);
        if (!port) {
            /* No slaves enabled, so drop packet. */
            return;
        }
    }

    old_tci = *flow_tci;
    tci = htons(vid);
    if (tci || out_bundle->use_priority_tags) {
        tci |= *flow_tci & htons(VLAN_PCP_MASK);
        if (tci) {
            tci |= htons(VLAN_CFI);
        }
    }
    *flow_tci = tci;

    compose_output_action(ctx, port->up.ofp_port);
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

static void
update_learning_table(struct ofproto_dpif *ofproto,
                      const struct flow *flow, struct flow_wildcards *wc,
                      int vlan, struct ofbundle *in_bundle)
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
    if (is_gratuitous_arp(flow, wc)) {
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
        mac_learning_changed(ofproto->ml, mac);
    }
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
is_admissible(struct xlate_ctx *ctx, struct ofport_dpif *in_port,
              uint16_t vlan)
{
    struct ofproto_dpif *ofproto = ctx->ofproto;
    struct flow *flow = &ctx->xin->flow;
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
                                         flow->dl_dst, &ctx->xout->tags)) {
        case BV_ACCEPT:
            break;

        case BV_DROP:
            xlate_report(ctx, "bonding refused admissibility, dropping");
            return false;

        case BV_DROP_IF_MOVED:
            mac = mac_learning_lookup(ofproto->ml, flow->dl_src, vlan, NULL);
            if (mac && mac->port.p != in_bundle &&
                (!is_gratuitous_arp(flow, &ctx->xout->wc)
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
xlate_normal(struct xlate_ctx *ctx)
{
    struct flow_wildcards *wc = &ctx->xout->wc;
    struct flow *flow = &ctx->xin->flow;
    struct ofport_dpif *in_port;
    struct ofbundle *in_bundle;
    struct mac_entry *mac;
    uint16_t vlan;
    uint16_t vid;

    ctx->xout->has_normal = true;

    /* Check the dl_type, since we may check for gratuituous ARP. */
    memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
    memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
    wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);

    in_bundle = lookup_input_bundle(ctx->ofproto, flow->in_port.ofp_port,
                                    ctx->xin->packet != NULL, &in_port);
    if (!in_bundle) {
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
                         ctx->ofproto->up.name, in_bundle->name);
        }
        xlate_report(ctx, "partial VLAN tag, dropping");
        return;
    }

    /* Drop frames on bundles reserved for mirroring. */
    if (in_bundle->mirror_out) {
        if (ctx->xin->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port "
                         "%s, which is reserved exclusively for mirroring",
                         ctx->ofproto->up.name, in_bundle->name);
        }
        xlate_report(ctx, "input port is mirror output port, dropping");
        return;
    }

    /* Check VLAN. */
    vid = vlan_tci_to_vid(flow->vlan_tci);
    if (!input_vid_is_valid(vid, in_bundle, ctx->xin->packet != NULL)) {
        xlate_report(ctx, "disallowed VLAN VID for this input port, dropping");
        return;
    }
    vlan = input_vid_to_vlan(in_bundle, vid);

    /* Check other admissibility requirements. */
    if (in_port && !is_admissible(ctx, in_port, vlan)) {
        return;
    }

    /* Learn source MAC. */
    if (ctx->xin->may_learn) {
        update_learning_table(ctx->ofproto, flow, wc, vlan, in_bundle);
    }

    /* Determine output bundle. */
    mac = mac_learning_lookup(ctx->ofproto->ml, flow->dl_dst, vlan,
                              &ctx->xout->tags);
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
        ctx->xout->nf_output_iface = NF_OUT_FLOOD;
    }
}

/* Compose SAMPLE action for sFlow or IPFIX.  The given probability is
 * the number of packets out of UINT32_MAX to sample.  The given
 * cookie is passed back in the callback for each sampled packet.
 */
static size_t
compose_sample_action(const struct ofproto_dpif *ofproto,
                      struct ofpbuf *odp_actions,
                      const struct flow *flow,
                      const uint32_t probability,
                      const union user_action_cookie *cookie,
                      const size_t cookie_size)
{
    size_t sample_offset, actions_offset;
    int cookie_offset;

    sample_offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_SAMPLE);

    nl_msg_put_u32(odp_actions, OVS_SAMPLE_ATTR_PROBABILITY, probability);

    actions_offset = nl_msg_start_nested(odp_actions, OVS_SAMPLE_ATTR_ACTIONS);
    cookie_offset = put_userspace_action(ofproto, odp_actions, flow, cookie,
                                         cookie_size);

    nl_msg_end_nested(odp_actions, actions_offset);
    nl_msg_end_nested(odp_actions, sample_offset);
    return cookie_offset;
}

static void
compose_sflow_cookie(const struct ofproto_dpif *ofproto,
                     ovs_be16 vlan_tci, odp_port_t odp_port,
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

/* Compose SAMPLE action for sFlow bridge sampling. */
static size_t
compose_sflow_action(const struct ofproto_dpif *ofproto,
                     struct ofpbuf *odp_actions,
                     const struct flow *flow,
                     odp_port_t odp_port)
{
    uint32_t probability;
    union user_action_cookie cookie;

    if (!ofproto->sflow || flow->in_port.ofp_port == OFPP_NONE) {
        return 0;
    }

    probability = dpif_sflow_get_probability(ofproto->sflow);
    compose_sflow_cookie(ofproto, htons(0), odp_port,
                         odp_port == ODPP_NONE ? 0 : 1, &cookie);

    return compose_sample_action(ofproto, odp_actions, flow,  probability,
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
compose_ipfix_action(const struct ofproto_dpif *ofproto,
                     struct ofpbuf *odp_actions,
                     const struct flow *flow)
{
    uint32_t probability;
    union user_action_cookie cookie;

    if (!ofproto->ipfix || flow->in_port.ofp_port == OFPP_NONE) {
        return;
    }

    probability = dpif_ipfix_get_bridge_exporter_probability(ofproto->ipfix);
    compose_ipfix_cookie(&cookie);

    compose_sample_action(ofproto, odp_actions, flow,  probability,
                          &cookie, sizeof cookie.ipfix);
}

/* SAMPLE action for sFlow must be first action in any given list of
 * actions.  At this point we do not have all information required to
 * build it. So try to build sample action as complete as possible. */
static void
add_sflow_action(struct xlate_ctx *ctx)
{
    ctx->user_cookie_offset = compose_sflow_action(ctx->ofproto,
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
    compose_ipfix_action(ctx->ofproto, &ctx->xout->odp_actions,
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

    compose_sflow_cookie(ctx->ofproto, base->vlan_tci,
                         ctx->sflow_odp_port, ctx->sflow_n_outputs, cookie);
}

static enum slow_path_reason
process_special(struct xlate_ctx *ctx, const struct flow *flow,
                const struct ofport_dpif *ofport, const struct ofpbuf *packet)
{
    struct ofproto_dpif *ofproto = ctx->ofproto;
    struct flow_wildcards *wc = &ctx->xout->wc;

    if (!ofport) {
        return 0;
    } else if (ofport->cfm && cfm_should_process_flow(ofport->cfm, flow, wc)) {
        if (packet) {
            cfm_process_heartbeat(ofport->cfm, packet);
        }
        return SLOW_CFM;
    } else if (ofport->bfd && bfd_should_process_flow(flow, wc)) {
        if (packet) {
            bfd_process_packet(ofport->bfd, flow, packet);
        }
        return SLOW_BFD;
    } else if (ofport->bundle && ofport->bundle->lacp
               && flow->dl_type == htons(ETH_TYPE_LACP)) {
        memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
        if (packet) {
            lacp_process_packet(ofport->bundle->lacp, ofport, packet);
        }
        return SLOW_LACP;
    } else if (ofproto->stp && stp_should_process_flow(flow, wc)) {
        if (packet) {
            stp_process_packet(ofport, packet);
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
    const struct ofport_dpif *ofport = get_ofp_port(ctx->ofproto, ofp_port);
    struct flow_wildcards *wc = &ctx->xout->wc;
    struct flow *flow = &ctx->xin->flow;
    ovs_be16 flow_vlan_tci;
    uint32_t flow_skb_mark;
    uint8_t flow_nw_tos;
    odp_port_t out_port, odp_port;
    uint8_t dscp;

    /* If 'struct flow' gets additional metadata, we'll need to zero it out
     * before traversing a patch port. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 20);

    if (!ofport) {
        xlate_report(ctx, "Nonexistent output port");
        return;
    } else if (ofport->up.pp.config & OFPUTIL_PC_NO_FWD) {
        xlate_report(ctx, "OFPPC_NO_FWD set, skipping output");
        return;
    } else if (check_stp && !stp_forward_in_state(ofport->stp_state)) {
        xlate_report(ctx, "STP not in forwarding state, skipping output");
        return;
    }

    if (ofport->peer) {
        struct ofport_dpif *peer = ofport->peer;
        struct flow old_flow = ctx->xin->flow;
        enum slow_path_reason special;

        ctx->ofproto = ofproto_dpif_cast(peer->up.ofproto);
        flow->in_port.ofp_port = peer->up.ofp_port;
        flow->metadata = htonll(0);
        memset(&flow->tunnel, 0, sizeof flow->tunnel);
        memset(flow->regs, 0, sizeof flow->regs);

        special = process_special(ctx, &ctx->xin->flow, peer,
                                  ctx->xin->packet);
        if (special) {
            ctx->xout->slow = special;
        } else if (may_receive(peer, ctx)) {
            if (stp_forward_in_state(peer->stp_state)) {
                xlate_table_action(ctx, flow->in_port.ofp_port, 0, true);
            } else {
                /* Forwarding is disabled by STP.  Let OFPP_NORMAL and the
                 * learning action look at the packet, then drop it. */
                struct flow old_base_flow = ctx->base_flow;
                size_t old_size = ctx->xout->odp_actions.size;
                xlate_table_action(ctx, flow->in_port.ofp_port, 0, true);
                ctx->base_flow = old_base_flow;
                ctx->xout->odp_actions.size = old_size;
            }
        }

        ctx->xin->flow = old_flow;
        ctx->ofproto = ofproto_dpif_cast(ofport->up.ofproto);

        if (ctx->xin->resubmit_stats) {
            netdev_vport_inc_tx(ofport->up.netdev, ctx->xin->resubmit_stats);
            netdev_vport_inc_rx(peer->up.netdev, ctx->xin->resubmit_stats);
        }

        return;
    }

    flow_vlan_tci = flow->vlan_tci;
    flow_skb_mark = flow->skb_mark;
    flow_nw_tos = flow->nw_tos;

    if (ofproto_dpif_dscp_from_priority(ofport, flow->skb_priority, &dscp)) {
        wc->masks.nw_tos |= IP_ECN_MASK;
        flow->nw_tos &= ~IP_DSCP_MASK;
        flow->nw_tos |= dscp;
    }

    if (ofport->tnl_port) {
         /* Save tunnel metadata so that changes made due to
          * the Logical (tunnel) Port are not visible for any further
          * matches, while explicit set actions on tunnel metadata are.
          */
        struct flow_tnl flow_tnl = flow->tunnel;
        odp_port = tnl_port_send(ofport->tnl_port, flow, &ctx->xout->wc);
        if (odp_port == ODPP_NONE) {
            xlate_report(ctx, "Tunneling decided against output");
            goto out; /* restore flow_nw_tos */
        }
        if (flow->tunnel.ip_dst == ctx->orig_tunnel_ip_dst) {
            xlate_report(ctx, "Not tunneling to our own address");
            goto out; /* restore flow_nw_tos */
        }
        if (ctx->xin->resubmit_stats) {
            netdev_vport_inc_tx(ofport->up.netdev, ctx->xin->resubmit_stats);
        }
        out_port = odp_port;
        commit_odp_tunnel_action(flow, &ctx->base_flow,
                                 &ctx->xout->odp_actions);
        flow->tunnel = flow_tnl; /* Restore tunnel metadata */
    } else {
        ofp_port_t vlandev_port;

        odp_port = ofport->odp_port;
        if (!hmap_is_empty(&ctx->ofproto->realdev_vid_map)) {
            wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
        }
        vlandev_port = vsp_realdev_to_vlandev(ctx->ofproto, ofp_port,
                                              flow->vlan_tci);
        if (vlandev_port == ofp_port) {
            out_port = odp_port;
        } else {
            out_port = ofp_port_to_odp_port(ctx->ofproto, vlandev_port);
            flow->vlan_tci = htons(0);
        }
        flow->skb_mark &= ~IPSEC_MARK;
    }

    if (out_port != ODPP_NONE) {
        commit_odp_actions(flow, &ctx->base_flow,
                           &ctx->xout->odp_actions, &ctx->xout->wc);
        nl_msg_put_odp_port(&ctx->xout->odp_actions, OVS_ACTION_ATTR_OUTPUT,
                            out_port);

        ctx->sflow_odp_port = odp_port;
        ctx->sflow_n_outputs++;
        ctx->xout->nf_output_iface = ofp_port;
    }

 out:
    /* Restore flow */
    flow->vlan_tci = flow_vlan_tci;
    flow->skb_mark = flow_skb_mark;
    flow->nw_tos = flow_nw_tos;
}

static void
compose_output_action(struct xlate_ctx *ctx, ofp_port_t ofp_port)
{
    compose_output_action__(ctx, ofp_port, true);
}

static void
tag_the_flow(struct xlate_ctx *ctx, struct rule_dpif *rule)
{
    struct ofproto_dpif *ofproto = ctx->ofproto;
    uint8_t table_id = ctx->table_id;

    if (table_id > 0 && table_id < N_TABLES) {
        struct table_dpif *table = &ofproto->tables[table_id];
        if (table->other_table) {
            ctx->xout->tags |= (rule && rule->tag
                                ? rule->tag
                                : rule_calculate_tag(&ctx->xin->flow,
                                                     &table->other_table->mask,
                                                     table->basis));
        }
    }
}

/* Common rule processing in one place to avoid duplicating code. */
static struct rule_dpif *
ctx_rule_hooks(struct xlate_ctx *ctx, struct rule_dpif *rule,
               bool may_packet_in)
{
    if (ctx->xin->resubmit_hook) {
        ctx->xin->resubmit_hook(ctx->xin, rule, ctx->recurse);
    }
    if (rule == NULL && may_packet_in) {
        /* XXX
         * check if table configuration flags
         * OFPTC_TABLE_MISS_CONTROLLER, default.
         * OFPTC_TABLE_MISS_CONTINUE,
         * OFPTC_TABLE_MISS_DROP
         * When OF1.0, OFPTC_TABLE_MISS_CONTINUE is used. What to do?
         */
        rule = rule_dpif_miss_rule(ctx->ofproto, &ctx->xin->flow);
    }
    if (rule && ctx->xin->resubmit_stats) {
        rule_credit_stats(rule, ctx->xin->resubmit_stats);
    }
    return rule;
}

static void
xlate_table_action(struct xlate_ctx *ctx,
                   ofp_port_t in_port, uint8_t table_id, bool may_packet_in)
{
    if (ctx->recurse < MAX_RESUBMIT_RECURSION) {
        struct rule_dpif *rule;
        ofp_port_t old_in_port = ctx->xin->flow.in_port.ofp_port;
        uint8_t old_table_id = ctx->table_id;

        ctx->table_id = table_id;

        /* Look up a flow with 'in_port' as the input port. */
        ctx->xin->flow.in_port.ofp_port = in_port;
        rule = rule_dpif_lookup_in_table(ctx->ofproto, &ctx->xin->flow,
                                         &ctx->xout->wc, table_id);

        tag_the_flow(ctx, rule);

        /* Restore the original input port.  Otherwise OFPP_NORMAL and
         * OFPP_IN_PORT will have surprising behavior. */
        ctx->xin->flow.in_port.ofp_port = old_in_port;

        rule = ctx_rule_hooks(ctx, rule, may_packet_in);

        if (rule) {
            struct rule_dpif *old_rule = ctx->rule;

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
    struct ofport_dpif *ofport;

    HMAP_FOR_EACH (ofport, up.hmap_node, &ctx->ofproto->up.ports) {
        ofp_port_t ofp_port = ofport->up.ofp_port;

        if (ofp_port == ctx->xin->flow.in_port.ofp_port) {
            continue;
        }

        if (all) {
            compose_output_action__(ctx, ofp_port, false);
        } else if (!(ofport->up.pp.config & OFPUTIL_PC_NO_FLOOD)) {
            compose_output_action(ctx, ofp_port);
        }
    }

    ctx->xout->nf_output_iface = NF_OUT_FLOOD;
}

static void
execute_controller_action(struct xlate_ctx *ctx, int len,
                          enum ofp_packet_in_reason reason,
                          uint16_t controller_id)
{
    struct ofputil_packet_in pin;
    struct ofpbuf *packet;
    struct flow key;

    ovs_assert(!ctx->xout->slow || ctx->xout->slow == SLOW_CONTROLLER);
    ctx->xout->slow = SLOW_CONTROLLER;
    if (!ctx->xin->packet) {
        return;
    }

    packet = ofpbuf_clone(ctx->xin->packet);

    key.skb_priority = 0;
    key.skb_mark = 0;
    memset(&key.tunnel, 0, sizeof key.tunnel);

    commit_odp_actions(&ctx->xin->flow, &ctx->base_flow,
                       &ctx->xout->odp_actions, &ctx->xout->wc);

    odp_execute_actions(NULL, packet, &key, ctx->xout->odp_actions.data,
                        ctx->xout->odp_actions.size, NULL, NULL);

    pin.packet = packet->data;
    pin.packet_len = packet->size;
    pin.reason = reason;
    pin.controller_id = controller_id;
    pin.table_id = ctx->table_id;
    pin.cookie = ctx->rule ? ctx->rule->up.flow_cookie : 0;

    pin.send_len = len;
    flow_get_metadata(&ctx->xin->flow, &pin.fmd);

    connmgr_send_packet_in(ctx->ofproto->up.connmgr, &pin);
    ofpbuf_delete(packet);
}

static void
compose_mpls_push_action(struct xlate_ctx *ctx, ovs_be16 eth_type)
{
    struct flow_wildcards *wc = &ctx->xout->wc;
    struct flow *flow = &ctx->xin->flow;

    ovs_assert(eth_type_mpls(eth_type));

    memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
    memset(&wc->masks.mpls_lse, 0xff, sizeof wc->masks.mpls_lse);
    memset(&wc->masks.mpls_depth, 0xff, sizeof wc->masks.mpls_depth);

    if (flow->mpls_depth) {
        flow->mpls_lse &= ~htonl(MPLS_BOS_MASK);
        flow->mpls_depth++;
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
        flow->mpls_depth = 1;
    }
    flow->dl_type = eth_type;
}

static void
compose_mpls_pop_action(struct xlate_ctx *ctx, ovs_be16 eth_type)
{
    struct flow_wildcards *wc = &ctx->xout->wc;
    struct flow *flow = &ctx->xin->flow;

    ovs_assert(eth_type_mpls(ctx->xin->flow.dl_type));
    ovs_assert(!eth_type_mpls(eth_type));

    memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
    memset(&wc->masks.mpls_lse, 0xff, sizeof wc->masks.mpls_lse);
    memset(&wc->masks.mpls_depth, 0xff, sizeof wc->masks.mpls_depth);

    if (flow->mpls_depth) {
        flow->mpls_depth--;
        flow->mpls_lse = htonl(0);
        if (!flow->mpls_depth) {
            flow->dl_type = eth_type;
        }
    }
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
compose_set_mpls_ttl_action(struct xlate_ctx *ctx, uint8_t ttl)
{
    if (!eth_type_mpls(ctx->xin->flow.dl_type)) {
        return true;
    }

    set_mpls_lse_ttl(&ctx->xin->flow.mpls_lse, ttl);
    return false;
}

static bool
compose_dec_mpls_ttl_action(struct xlate_ctx *ctx)
{
    struct flow *flow = &ctx->xin->flow;
    uint8_t ttl = mpls_lse_to_ttl(flow->mpls_lse);
    struct flow_wildcards *wc = &ctx->xout->wc;

    memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
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
    error = ofproto_dpif_queue_to_priority(ctx->ofproto, queue_id, &priority);
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

    if (!ofproto_dpif_queue_to_priority(ctx->ofproto, queue_id,
                                        &skb_priority)) {
        ctx->xin->flow.skb_priority = skb_priority;
    } else {
        /* Couldn't translate queue to a priority.  Nothing to do.  A warning
         * has already been logged. */
    }
}

static bool
slave_enabled_cb(ofp_port_t ofp_port, void *ofproto_)
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
xlate_bundle_action(struct xlate_ctx *ctx,
                    const struct ofpact_bundle *bundle)
{
    ofp_port_t port;

    port = bundle_execute(bundle, &ctx->xin->flow, &ctx->xout->wc,
                          slave_enabled_cb, ctx->ofproto);
    if (bundle->dst.field) {
        nxm_reg_load(&bundle->dst, ofp_to_u16(port), &ctx->xin->flow);
    } else {
        xlate_output_action(ctx, port, 0, false);
    }
}

static void
xlate_learn_action(struct xlate_ctx *ctx,
                   const struct ofpact_learn *learn)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    struct ofputil_flow_mod fm;
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts;
    int error;

    ctx->xout->has_learn = true;

    learn_mask(learn, &ctx->xout->wc);

    if (!ctx->xin->may_learn) {
        return;
    }

    ofpbuf_use_stack(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    learn_execute(learn, &ctx->xin->flow, &fm, &ofpacts);

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
xlate_fin_timeout(struct xlate_ctx *ctx,
                  const struct ofpact_fin_timeout *oft)
{
    if (ctx->xin->tcp_flags & (TCP_FIN | TCP_RST) && ctx->rule) {
        struct rule_dpif *rule = ctx->rule;

        reduce_timeout(oft->fin_idle_timeout, &rule->up.idle_timeout);
        reduce_timeout(oft->fin_hard_timeout, &rule->up.hard_timeout);
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

  commit_odp_actions(&ctx->xin->flow, &ctx->base_flow,
                     &ctx->xout->odp_actions, &ctx->xout->wc);

  compose_flow_sample_cookie(os->probability, os->collector_set_id,
                             os->obs_domain_id, os->obs_point_id, &cookie);
  compose_sample_action(ctx->ofproto, &ctx->xout->odp_actions, &ctx->xin->flow,
                        probability, &cookie, sizeof cookie.flow_sample);
}

static bool
may_receive(const struct ofport_dpif *port, struct xlate_ctx *ctx)
{
    if (port->up.pp.config & (eth_addr_equals(ctx->xin->flow.dl_dst,
                                              eth_addr_stp)
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

static bool
tunnel_ecn_ok(struct xlate_ctx *ctx)
{
    if (is_ip_any(&ctx->base_flow)
        && (ctx->xin->flow.tunnel.ip_tos & IP_ECN_MASK) == IP_ECN_CE) {
        if ((ctx->base_flow.nw_tos & IP_ECN_MASK) == IP_ECN_NOT_ECT) {
            VLOG_WARN_RL(&rl, "dropping tunnel packet marked ECN CE"
                         " but is not ECN capable");
            return false;
        } else {
            /* Set the ECN CE value in the tunneled packet. */
            ctx->xin->flow.nw_tos |= IP_ECN_CE;
        }
    }

    return true;
}

static void
do_xlate_actions(const struct ofpact *ofpacts, size_t ofpacts_len,
                 struct xlate_ctx *ctx)
{
    struct flow_wildcards *wc = &ctx->xout->wc;
    struct flow *flow = &ctx->xin->flow;
    bool was_evictable = true;
    const struct ofpact *a;

    if (ctx->rule) {
        /* Don't let the rule we're working on get evicted underneath us. */
        was_evictable = ctx->rule->up.evictable;
        ctx->rule->up.evictable = false;
    }

 do_xlate_actions_again:
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
            flow->vlan_tci &= ~htons(VLAN_VID_MASK);
            flow->vlan_tci |= (htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid)
                               | htons(VLAN_CFI));
            break;

        case OFPACT_SET_VLAN_PCP:
            flow->vlan_tci &= ~htons(VLAN_PCP_MASK);
            flow->vlan_tci |=
                htons((ofpact_get_SET_VLAN_PCP(a)->vlan_pcp << VLAN_PCP_SHIFT)
                      | VLAN_CFI);
            break;

        case OFPACT_STRIP_VLAN:
            flow->vlan_tci = htons(0);
            break;

        case OFPACT_PUSH_VLAN:
            /* XXX 802.1AD(QinQ) */
            flow->vlan_tci = htons(VLAN_CFI);
            break;

        case OFPACT_SET_ETH_SRC:
            memcpy(flow->dl_src, ofpact_get_SET_ETH_SRC(a)->mac, ETH_ADDR_LEN);
            break;

        case OFPACT_SET_ETH_DST:
            memcpy(flow->dl_dst, ofpact_get_SET_ETH_DST(a)->mac, ETH_ADDR_LEN);
            break;

        case OFPACT_SET_IPV4_SRC:
            memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
            if (flow->dl_type == htons(ETH_TYPE_IP)) {
                flow->nw_src = ofpact_get_SET_IPV4_SRC(a)->ipv4;
            }
            break;

        case OFPACT_SET_IPV4_DST:
            memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
            if (flow->dl_type == htons(ETH_TYPE_IP)) {
                flow->nw_dst = ofpact_get_SET_IPV4_DST(a)->ipv4;
            }
            break;

        case OFPACT_SET_IPV4_DSCP:
            /* OpenFlow 1.0 only supports IPv4. */
            memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
            if (flow->dl_type == htons(ETH_TYPE_IP)) {
                flow->nw_tos &= ~IP_DSCP_MASK;
                flow->nw_tos |= ofpact_get_SET_IPV4_DSCP(a)->dscp;
            }
            break;

        case OFPACT_SET_L4_SRC_PORT:
            memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
            if (is_ip_any(flow)) {
                flow->tp_src = htons(ofpact_get_SET_L4_SRC_PORT(a)->port);
            }
            break;

        case OFPACT_SET_L4_DST_PORT:
            memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
            if (is_ip_any(flow)) {
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
            nxm_execute_reg_load(ofpact_get_REG_LOAD(a), flow);
            break;

        case OFPACT_STACK_PUSH:
            nxm_execute_stack_push(ofpact_get_STACK_PUSH(a), flow, wc,
                                   &ctx->stack);
            break;

        case OFPACT_STACK_POP:
            nxm_execute_stack_pop(ofpact_get_STACK_POP(a), flow, &ctx->stack);
            break;

        case OFPACT_PUSH_MPLS:
            compose_mpls_push_action(ctx, ofpact_get_PUSH_MPLS(a)->ethertype);
            break;

        case OFPACT_POP_MPLS:
            compose_mpls_pop_action(ctx, ofpact_get_POP_MPLS(a)->ethertype);
            break;

        case OFPACT_SET_MPLS_TTL:
            if (compose_set_mpls_ttl_action(ctx,
                                            ofpact_get_SET_MPLS_TTL(a)->ttl)) {
                goto out;
            }
            break;

        case OFPACT_DEC_MPLS_TTL:
            if (compose_dec_mpls_ttl_action(ctx)) {
                goto out;
            }
            break;

        case OFPACT_DEC_TTL:
            memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
            if (compose_dec_ttl(ctx, ofpact_get_DEC_TTL(a))) {
                goto out;
            }
            break;

        case OFPACT_NOTE:
            /* Nothing to do. */
            break;

        case OFPACT_MULTIPATH:
            multipath_execute(ofpact_get_MULTIPATH(a), flow, wc);
            break;

        case OFPACT_BUNDLE:
            ctx->ofproto->has_bundle_action = true;
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
            memset(&wc->masks.dl_type, 0xff, sizeof wc->masks.dl_type);
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
            ctx->xout->has_fin_timeout = true;
            xlate_fin_timeout(ctx, ofpact_get_FIN_TIMEOUT(a));
            break;

        case OFPACT_CLEAR_ACTIONS:
            /* XXX
             * Nothing to do because writa-actions is not supported for now.
             * When writa-actions is supported, clear-actions also must
             * be supported at the same time.
             */
            break;

        case OFPACT_WRITE_METADATA:
            metadata = ofpact_get_WRITE_METADATA(a);
            flow->metadata &= ~metadata->mask;
            flow->metadata |= metadata->metadata & metadata->mask;
            break;

        case OFPACT_GOTO_TABLE: {
            /* It is assumed that goto-table is the last action. */
            struct ofpact_goto_table *ogt = ofpact_get_GOTO_TABLE(a);
            struct rule_dpif *rule;

            ovs_assert(ctx->table_id < ogt->table_id);

            ctx->table_id = ogt->table_id;

            /* Look up a flow from the new table. */
            rule = rule_dpif_lookup_in_table(ctx->ofproto, flow, wc,
                                             ctx->table_id);

            tag_the_flow(ctx, rule);

            rule = ctx_rule_hooks(ctx, rule, true);

            if (rule) {
                if (ctx->rule) {
                    ctx->rule->up.evictable = was_evictable;
                }
                ctx->rule = rule;
                was_evictable = rule->up.evictable;
                rule->up.evictable = false;

                /* Tail recursion removal. */
                ofpacts = rule->up.ofpacts;
                ofpacts_len = rule->up.ofpacts_len;
                goto do_xlate_actions_again;
            }
            break;
        }

        case OFPACT_SAMPLE:
            xlate_sample_action(ctx, ofpact_get_SAMPLE(a));
            break;
        }
    }

out:
    if (ctx->rule) {
        ctx->rule->up.evictable = was_evictable;
    }
}

void
xlate_in_init(struct xlate_in *xin, struct ofproto_dpif *ofproto,
              const struct flow *flow, struct rule_dpif *rule,
              uint8_t tcp_flags, const struct ofpbuf *packet)
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
    dst->tags = src->tags;
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


/* Translates the 'ofpacts_len' bytes of "struct ofpacts" starting at 'ofpacts'
 * into datapath actions in 'odp_actions', using 'ctx'. */
void
xlate_actions(struct xlate_in *xin, struct xlate_out *xout)
{
    /* Normally false.  Set to true if we ever hit MAX_RESUBMIT_RECURSION, so
     * that in the future we always keep a copy of the original flow for
     * tracing purposes. */
    static bool hit_resubmit_limit;

    struct flow_wildcards *wc = &xout->wc;
    struct flow *flow = &xin->flow;

    enum slow_path_reason special;
    const struct ofpact *ofpacts;
    struct ofport_dpif *in_port;
    struct flow orig_flow;
    struct xlate_ctx ctx;
    size_t ofpacts_len;

    COVERAGE_INC(ofproto_dpif_xlate);

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

    ctx.ofproto = xin->ofproto;
    ctx.rule = xin->rule;

    ctx.base_flow = *flow;
    memset(&ctx.base_flow.tunnel, 0, sizeof ctx.base_flow.tunnel);
    ctx.orig_tunnel_ip_dst = flow->tunnel.ip_dst;

    flow_wildcards_init_catchall(wc);
    memset(&wc->masks.in_port, 0xff, sizeof wc->masks.in_port);
    memset(&wc->masks.skb_priority, 0xff, sizeof wc->masks.skb_priority);
    wc->masks.nw_frag |= FLOW_NW_FRAG_MASK;

    if (tnl_port_should_receive(&ctx.xin->flow)) {
        memset(&wc->masks.tunnel, 0xff, sizeof wc->masks.tunnel);
    }
    if (xin->ofproto->netflow) {
        netflow_mask_wc(wc);
    }

    ctx.xout->tags = 0;
    ctx.xout->slow = 0;
    ctx.xout->has_learn = false;
    ctx.xout->has_normal = false;
    ctx.xout->has_fin_timeout = false;
    ctx.xout->nf_output_iface = NF_OUT_DROP;
    ctx.xout->mirrors = 0;

    ofpbuf_use_stub(&ctx.xout->odp_actions, ctx.xout->odp_actions_stub,
                    sizeof ctx.xout->odp_actions_stub);
    ofpbuf_reserve(&ctx.xout->odp_actions, NL_A_U32_SIZE);

    ctx.recurse = 0;
    ctx.max_resubmit_trigger = false;
    ctx.orig_skb_priority = flow->skb_priority;
    ctx.table_id = 0;
    ctx.exit = false;

    if (xin->ofpacts) {
        ofpacts = xin->ofpacts;
        ofpacts_len = xin->ofpacts_len;
    } else if (xin->rule) {
        ofpacts = xin->rule->up.ofpacts;
        ofpacts_len = xin->rule->up.ofpacts_len;
    } else {
        NOT_REACHED();
    }

    ofpbuf_use_stub(&ctx.stack, ctx.init_stack, sizeof ctx.init_stack);

    if (ctx.ofproto->has_mirrors || hit_resubmit_limit) {
        /* Do this conditionally because the copy is expensive enough that it
         * shows up in profiles. */
        orig_flow = *flow;
    }

    if (flow->nw_frag & FLOW_NW_FRAG_ANY) {
        switch (ctx.ofproto->up.frag_handling) {
        case OFPC_FRAG_NORMAL:
            /* We must pretend that transport ports are unavailable. */
            flow->tp_src = ctx.base_flow.tp_src = htons(0);
            flow->tp_dst = ctx.base_flow.tp_dst = htons(0);
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

    in_port = get_ofp_port(ctx.ofproto, flow->in_port.ofp_port);
    special = process_special(&ctx, flow, in_port, ctx.xin->packet);
    if (special) {
        ctx.xout->slow = special;
    } else {
        static struct vlog_rate_limit trace_rl = VLOG_RATE_LIMIT_INIT(1, 1);
        size_t sample_actions_len;
        odp_port_t local_odp_port;

        if (flow->in_port.ofp_port
            != vsp_realdev_to_vlandev(ctx.ofproto, flow->in_port.ofp_port,
                                      flow->vlan_tci)) {
            ctx.base_flow.vlan_tci = 0;
        }

        add_sflow_action(&ctx);
        add_ipfix_action(&ctx);
        sample_actions_len = ctx.xout->odp_actions.size;

        if (tunnel_ecn_ok(&ctx) && (!in_port || may_receive(in_port, &ctx))) {
            do_xlate_actions(ofpacts, ofpacts_len, &ctx);

            /* We've let OFPP_NORMAL and the learning action look at the
             * packet, so drop it now if forwarding is disabled. */
            if (in_port && !stp_forward_in_state(in_port->stp_state)) {
                ctx.xout->odp_actions.size = sample_actions_len;
            }
        }

        if (ctx.max_resubmit_trigger && !ctx.xin->resubmit_hook) {
            if (!hit_resubmit_limit) {
                /* We didn't record the original flow.  Make sure we do from
                 * now on. */
                hit_resubmit_limit = true;
            } else if (!VLOG_DROP_ERR(&trace_rl)) {
                struct ds ds = DS_EMPTY_INITIALIZER;

                ofproto_trace(ctx.ofproto, &orig_flow, ctx.xin->packet, &ds);
                VLOG_ERR("Trace triggered by excessive resubmit "
                         "recursion:\n%s", ds_cstr(&ds));
                ds_destroy(&ds);
            }
        }

        local_odp_port = ofp_port_to_odp_port(ctx.ofproto, OFPP_LOCAL);
        if (!connmgr_must_output_local(ctx.ofproto->up.connmgr, flow,
                                       local_odp_port,
                                       ctx.xout->odp_actions.data,
                                       ctx.xout->odp_actions.size)) {
            compose_output_action(&ctx, OFPP_LOCAL);
        }
        if (ctx.ofproto->has_mirrors) {
            add_mirror_actions(&ctx, &orig_flow);
        }
        fix_sflow_action(&ctx);
    }

    ofpbuf_uninit(&ctx.stack);

    /* Clear the metadata and register wildcard masks, because we won't
     * use non-header fields as part of the cache. */
    memset(&wc->masks.metadata, 0, sizeof wc->masks.metadata);
    memset(&wc->masks.regs, 0, sizeof wc->masks.regs);
}
