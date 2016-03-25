/* Copyright (c) 2015, 2016 Nicira, Inc.
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
#include "lflow.h"
#include "lport.h"
#include "openvswitch/dynamic-string.h"
#include "ofctrl.h"
#include "ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "ovn/lib/actions.h"
#include "ovn/lib/expr.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "packets.h"
#include "simap.h"

VLOG_DEFINE_THIS_MODULE(lflow);

/* Symbol table. */

/* Contains "struct expr_symbol"s for fields supported by OVN lflows. */
static struct shash symtab;

static void
add_logical_register(struct shash *symtab, enum mf_field_id id)
{
    char name[8];

    snprintf(name, sizeof name, "reg%d", id - MFF_REG0);
    expr_symtab_add_field(symtab, name, id, NULL, false);
}

void
lflow_init(void)
{
    shash_init(&symtab);

    /* Reserve a pair of registers for the logical inport and outport.  A full
     * 32-bit register each is bigger than we need, but the expression code
     * doesn't yet support string fields that occupy less than a full OXM. */
    expr_symtab_add_string(&symtab, "inport", MFF_LOG_INPORT, NULL);
    expr_symtab_add_string(&symtab, "outport", MFF_LOG_OUTPORT, NULL);

    /* Logical registers. */
#define MFF_LOG_REG(ID) add_logical_register(&symtab, ID);
    MFF_LOG_REGS;
#undef MFF_LOG_REG

    /* Connection tracking state. */
    expr_symtab_add_field(&symtab, "ct_mark", MFF_CT_MARK, NULL, false);
    expr_symtab_add_field(&symtab, "ct_label", MFF_CT_LABEL, NULL, false);
    expr_symtab_add_field(&symtab, "ct_state", MFF_CT_STATE, NULL, false);
    char ct_state_str[16];
    snprintf(ct_state_str, sizeof ct_state_str, "ct_state[%d]", CS_TRACKED_BIT);
    expr_symtab_add_predicate(&symtab, "ct.trk", ct_state_str);
    snprintf(ct_state_str, sizeof ct_state_str, "ct_state[%d]", CS_NEW_BIT);
    expr_symtab_add_subfield(&symtab, "ct.new", "ct.trk", ct_state_str);
    snprintf(ct_state_str, sizeof ct_state_str, "ct_state[%d]", CS_ESTABLISHED_BIT);
    expr_symtab_add_subfield(&symtab, "ct.est", "ct.trk", ct_state_str);
    snprintf(ct_state_str, sizeof ct_state_str, "ct_state[%d]", CS_RELATED_BIT);
    expr_symtab_add_subfield(&symtab, "ct.rel", "ct.trk", ct_state_str);
    snprintf(ct_state_str, sizeof ct_state_str, "ct_state[%d]", CS_REPLY_DIR_BIT);
    expr_symtab_add_subfield(&symtab, "ct.rpl", "ct.trk", ct_state_str);
    snprintf(ct_state_str, sizeof ct_state_str, "ct_state[%d]", CS_INVALID_BIT);
    expr_symtab_add_subfield(&symtab, "ct.inv", "ct.trk", ct_state_str);

    /* Data fields. */
    expr_symtab_add_field(&symtab, "eth.src", MFF_ETH_SRC, NULL, false);
    expr_symtab_add_field(&symtab, "eth.dst", MFF_ETH_DST, NULL, false);
    expr_symtab_add_field(&symtab, "eth.type", MFF_ETH_TYPE, NULL, true);
    expr_symtab_add_predicate(&symtab, "eth.bcast",
                              "eth.dst == ff:ff:ff:ff:ff:ff");
    expr_symtab_add_subfield(&symtab, "eth.mcast", NULL, "eth.dst[40]");

    expr_symtab_add_field(&symtab, "vlan.tci", MFF_VLAN_TCI, NULL, false);
    expr_symtab_add_predicate(&symtab, "vlan.present", "vlan.tci[12]");
    expr_symtab_add_subfield(&symtab, "vlan.pcp", "vlan.present",
                             "vlan.tci[13..15]");
    expr_symtab_add_subfield(&symtab, "vlan.vid", "vlan.present",
                             "vlan.tci[0..11]");

    expr_symtab_add_predicate(&symtab, "ip4", "eth.type == 0x800");
    expr_symtab_add_predicate(&symtab, "ip6", "eth.type == 0x86dd");
    expr_symtab_add_predicate(&symtab, "ip", "ip4 || ip6");
    expr_symtab_add_field(&symtab, "ip.proto", MFF_IP_PROTO, "ip", true);
    expr_symtab_add_field(&symtab, "ip.dscp", MFF_IP_DSCP, "ip", false);
    expr_symtab_add_field(&symtab, "ip.ecn", MFF_IP_ECN, "ip", false);
    expr_symtab_add_field(&symtab, "ip.ttl", MFF_IP_TTL, "ip", false);

    expr_symtab_add_field(&symtab, "ip4.src", MFF_IPV4_SRC, "ip4", false);
    expr_symtab_add_field(&symtab, "ip4.dst", MFF_IPV4_DST, "ip4", false);
    expr_symtab_add_predicate(&symtab, "ip4.mcast", "ip4.dst[28..31] == 0xe");

    expr_symtab_add_predicate(&symtab, "icmp4", "ip4 && ip.proto == 1");
    expr_symtab_add_field(&symtab, "icmp4.type", MFF_ICMPV4_TYPE, "icmp4",
              false);
    expr_symtab_add_field(&symtab, "icmp4.code", MFF_ICMPV4_CODE, "icmp4",
              false);

    expr_symtab_add_field(&symtab, "ip6.src", MFF_IPV6_SRC, "ip6", false);
    expr_symtab_add_field(&symtab, "ip6.dst", MFF_IPV6_DST, "ip6", false);
    expr_symtab_add_field(&symtab, "ip6.label", MFF_IPV6_LABEL, "ip6", false);

    expr_symtab_add_predicate(&symtab, "icmp6", "ip6 && ip.proto == 58");
    expr_symtab_add_field(&symtab, "icmp6.type", MFF_ICMPV6_TYPE, "icmp6",
                          true);
    expr_symtab_add_field(&symtab, "icmp6.code", MFF_ICMPV6_CODE, "icmp6",
                          true);

    expr_symtab_add_predicate(&symtab, "icmp", "icmp4 || icmp6");

    expr_symtab_add_field(&symtab, "ip.frag", MFF_IP_FRAG, "ip", false);
    expr_symtab_add_predicate(&symtab, "ip.is_frag", "ip.frag[0]");
    expr_symtab_add_predicate(&symtab, "ip.later_frag", "ip.frag[1]");
    expr_symtab_add_predicate(&symtab, "ip.first_frag",
                              "ip.is_frag && !ip.later_frag");

    expr_symtab_add_predicate(&symtab, "arp", "eth.type == 0x806");
    expr_symtab_add_field(&symtab, "arp.op", MFF_ARP_OP, "arp", false);
    expr_symtab_add_field(&symtab, "arp.spa", MFF_ARP_SPA, "arp", false);
    expr_symtab_add_field(&symtab, "arp.sha", MFF_ARP_SHA, "arp", false);
    expr_symtab_add_field(&symtab, "arp.tpa", MFF_ARP_TPA, "arp", false);
    expr_symtab_add_field(&symtab, "arp.tha", MFF_ARP_THA, "arp", false);

    expr_symtab_add_predicate(&symtab, "nd",
                              "icmp6.type == {135, 136} && icmp6.code == 0");
    expr_symtab_add_field(&symtab, "nd.target", MFF_ND_TARGET, "nd", false);
    expr_symtab_add_field(&symtab, "nd.sll", MFF_ND_SLL,
              "nd && icmp6.type == 135", false);
    expr_symtab_add_field(&symtab, "nd.tll", MFF_ND_TLL,
              "nd && icmp6.type == 136", false);

    expr_symtab_add_predicate(&symtab, "tcp", "ip.proto == 6");
    expr_symtab_add_field(&symtab, "tcp.src", MFF_TCP_SRC, "tcp", false);
    expr_symtab_add_field(&symtab, "tcp.dst", MFF_TCP_DST, "tcp", false);
    expr_symtab_add_field(&symtab, "tcp.flags", MFF_TCP_FLAGS, "tcp", false);

    expr_symtab_add_predicate(&symtab, "udp", "ip.proto == 17");
    expr_symtab_add_field(&symtab, "udp.src", MFF_UDP_SRC, "udp", false);
    expr_symtab_add_field(&symtab, "udp.dst", MFF_UDP_DST, "udp", false);

    expr_symtab_add_predicate(&symtab, "sctp", "ip.proto == 132");
    expr_symtab_add_field(&symtab, "sctp.src", MFF_SCTP_SRC, "sctp", false);
    expr_symtab_add_field(&symtab, "sctp.dst", MFF_SCTP_DST, "sctp", false);
}

struct lookup_port_aux {
    const struct lport_index *lports;
    const struct mcgroup_index *mcgroups;
    const struct sbrec_datapath_binding *dp;
};

static bool
lookup_port_cb(const void *aux_, const char *port_name, unsigned int *portp)
{
    const struct lookup_port_aux *aux = aux_;

    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(aux->lports, port_name);
    if (pb && pb->datapath == aux->dp) {
        *portp = pb->tunnel_key;
        return true;
    }

    const struct sbrec_multicast_group *mg
        = mcgroup_lookup_by_dp_name(aux->mcgroups, aux->dp, port_name);
    if (mg) {
        *portp = mg->tunnel_key;
        return true;
    }

    return false;
}

static bool
is_switch(const struct sbrec_datapath_binding *ldp)
{
    return smap_get(&ldp->external_ids, "logical-switch") != NULL;

}

/* Adds the logical flows from the Logical_Flow table to 'flow_table'. */
static void
add_logical_flows(struct controller_ctx *ctx, const struct lport_index *lports,
                  const struct mcgroup_index *mcgroups,
                  const struct hmap *local_datapaths,
                  const struct simap *ct_zones, struct hmap *flow_table)
{
    uint32_t conj_id_ofs = 1;

    const struct sbrec_logical_flow *lflow;
    SBREC_LOGICAL_FLOW_FOR_EACH (lflow, ctx->ovnsb_idl) {
        /* Determine translation of logical table IDs to physical table IDs. */
        bool ingress = !strcmp(lflow->pipeline, "ingress");

        const struct sbrec_datapath_binding *ldp = lflow->logical_datapath;
        if (!ldp) {
            continue;
        }
        if (!ingress && is_switch(ldp)) {
            /* For a logical switch datapath, local_datapaths tells us if there
             * are any local ports for this datapath.  If not, processing
             * logical flows for the egress pipeline of this datapath is
             * unnecessary.
             *
             * We still need the ingress pipeline because even if there are no
             * local ports, we still may need to execute the ingress pipeline
             * after a packet leaves a logical router.  Further optimization
             * is possible, but not based on what we know with local_datapaths
             * right now.
             *
             * A better approach would be a kind of "flood fill" algorithm:
             *
             *   1. Initialize set S to the logical datapaths that have a port
             *      located on the hypervisor.
             *
             *   2. For each patch port P in a logical datapath in S, add the
             *      logical datapath of the remote end of P to S.  Iterate
             *      until S reaches a fixed point.
             */

            struct hmap_node *ld;
            ld = hmap_first_with_hash(local_datapaths, ldp->tunnel_key);
            if (!ld) {
                continue;
            }
        }

        /* Determine translation of logical table IDs to physical table IDs. */
        uint8_t first_ptable = (ingress
                                ? OFTABLE_LOG_INGRESS_PIPELINE
                                : OFTABLE_LOG_EGRESS_PIPELINE);
        uint8_t ptable = first_ptable + lflow->table_id;
        uint8_t output_ptable = (ingress
                                 ? OFTABLE_REMOTE_OUTPUT
                                 : OFTABLE_LOG_TO_PHY);

        /* Translate OVN actions into OpenFlow actions.
         *
         * XXX Deny changes to 'outport' in egress pipeline. */
        uint64_t ofpacts_stub[64 / 8];
        struct ofpbuf ofpacts;
        struct expr *prereqs;
        char *error;

        ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
        struct lookup_port_aux aux = {
            .lports = lports,
            .mcgroups = mcgroups,
            .dp = lflow->logical_datapath
        };
        struct action_params ap = {
            .symtab = &symtab,
            .lookup_port = lookup_port_cb,
            .aux = &aux,
            .ct_zones = ct_zones,

            .n_tables = LOG_PIPELINE_LEN,
            .first_ptable = first_ptable,
            .cur_ltable = lflow->table_id,
            .output_ptable = output_ptable,
            .arp_ptable = OFTABLE_MAC_BINDING,
        };
        error = actions_parse_string(lflow->actions, &ap, &ofpacts, &prereqs);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "error parsing actions \"%s\": %s",
                         lflow->actions, error);
            free(error);
            continue;
        }

        /* Translate OVN match into table of OpenFlow matches. */
        struct hmap matches;
        struct expr *expr;

        expr = expr_parse_string(lflow->match, &symtab, &error);
        if (!error) {
            if (prereqs) {
                expr = expr_combine(EXPR_T_AND, expr, prereqs);
                prereqs = NULL;
            }
            expr = expr_annotate(expr, &symtab, &error);
        }
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "error parsing match \"%s\": %s",
                         lflow->match, error);
            expr_destroy(prereqs);
            ofpbuf_uninit(&ofpacts);
            free(error);
            continue;
        }

        expr = expr_simplify(expr);
        expr = expr_normalize(expr);
        uint32_t n_conjs = expr_to_matches(expr, lookup_port_cb, &aux,
                                           &matches);
        expr_destroy(expr);

        /* Prepare the OpenFlow matches for adding to the flow table. */
        struct expr_match *m;
        HMAP_FOR_EACH (m, hmap_node, &matches) {
            match_set_metadata(&m->match,
                               htonll(lflow->logical_datapath->tunnel_key));
            if (m->match.wc.masks.conj_id) {
                m->match.flow.conj_id += conj_id_ofs;
            }
            if (!m->n) {
                ofctrl_add_flow(flow_table, ptable, lflow->priority,
                                &m->match, &ofpacts);
            } else {
                uint64_t conj_stubs[64 / 8];
                struct ofpbuf conj;

                ofpbuf_use_stub(&conj, conj_stubs, sizeof conj_stubs);
                for (int i = 0; i < m->n; i++) {
                    const struct cls_conjunction *src = &m->conjunctions[i];
                    struct ofpact_conjunction *dst;

                    dst = ofpact_put_CONJUNCTION(&conj);
                    dst->id = src->id + conj_id_ofs;
                    dst->clause = src->clause;
                    dst->n_clauses = src->n_clauses;
                }
                ofctrl_add_flow(flow_table, ptable, lflow->priority,
                                &m->match, &conj);
                ofpbuf_uninit(&conj);
            }
        }

        /* Clean up. */
        expr_matches_destroy(&matches);
        ofpbuf_uninit(&ofpacts);
        conj_id_ofs += n_conjs;
    }
}

static void
put_load(const uint8_t *data, size_t len,
         enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_SET_FIELD(ofpacts);
    sf->field = mf_from_id(dst);
    sf->flow_has_vlan = false;

    bitwise_copy(data, len, 0, &sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(&sf->mask, sf->field->n_bytes, ofs, n_bits);
}

/* Adds an OpenFlow flow to 'flow_table' for each MAC binding in the OVN
 * southbound database, using 'lports' to resolve logical port names to
 * numbers. */
static void
add_neighbor_flows(struct controller_ctx *ctx,
                   const struct lport_index *lports, struct hmap *flow_table)
{
    struct ofpbuf ofpacts;
    struct match match;
    match_init_catchall(&match);
    ofpbuf_init(&ofpacts, 0);

    const struct sbrec_mac_binding *b;
    SBREC_MAC_BINDING_FOR_EACH (b, ctx->ovnsb_idl) {
        const struct sbrec_port_binding *pb
            = lport_lookup_by_name(lports, b->logical_port);
        if (!pb) {
            continue;
        }

        struct eth_addr mac;
        if (!eth_addr_from_string(b->mac, &mac)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'mac' %s", b->mac);
            continue;
        }

        ovs_be32 ip;
        if (!ip_parse(b->ip, &ip)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'ip' %s", b->ip);
            continue;
        }

        match_set_metadata(&match, htonll(pb->datapath->tunnel_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, pb->tunnel_key);
        match_set_reg(&match, 0, ntohl(ip));

        ofpbuf_clear(&ofpacts);
        put_load(mac.ea, sizeof mac.ea, MFF_ETH_DST, 0, 48, &ofpacts);

        ofctrl_add_flow(flow_table, OFTABLE_MAC_BINDING, 100,
                        &match, &ofpacts);
    }
    ofpbuf_uninit(&ofpacts);
}

/* Translates logical flows in the Logical_Flow table in the OVN_SB database
 * into OpenFlow flows.  See ovn-architecture(7) for more information. */
void
lflow_run(struct controller_ctx *ctx, const struct lport_index *lports,
          const struct mcgroup_index *mcgroups,
          const struct hmap *local_datapaths,
          const struct simap *ct_zones, struct hmap *flow_table)
{
    add_logical_flows(ctx, lports, mcgroups, local_datapaths,
                      ct_zones, flow_table);
    add_neighbor_flows(ctx, lports, flow_table);
}

void
lflow_destroy(void)
{
    expr_symtab_destroy(&symtab);
}
