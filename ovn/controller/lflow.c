/* Copyright (c) 2015 Nicira, Inc.
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
#include "dynamic-string.h"
#include "ofctrl.h"
#include "ofp-actions.h"
#include "ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn/controller/ovn-controller.h"
#include "ovn/lib/actions.h"
#include "ovn/lib/expr.h"
#include "ovn/lib/ovn-sb-idl.h"
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

static void
symtab_init(void)
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

    /* Connection tracking state. See CS_* in lib/packets.h. */
    expr_symtab_add_field(&symtab, "ct_state", MFF_CT_STATE, NULL, false);
    expr_symtab_add_predicate(&symtab, "ct.trk", "ct_state[5]");
    expr_symtab_add_subfield(&symtab, "ct.new", "ct.trk", "ct_state[0]");
    expr_symtab_add_subfield(&symtab, "ct.est", "ct.trk", "ct_state[1]");
    expr_symtab_add_subfield(&symtab, "ct.rel", "ct.trk", "ct_state[2]");
    expr_symtab_add_subfield(&symtab, "ct.rpl", "ct.trk", "ct_state[3]");
    expr_symtab_add_subfield(&symtab, "ct.inv", "ct.trk", "ct_state[4]");

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

/* Logical datapaths and logical port numbers. */

/* A logical datapath.
 *
 * 'ports' maps 'logical_port' names to 'tunnel_key' values in the OVN_SB
 * Port_Binding table within the logical datapath. */
struct logical_datapath {
    struct hmap_node hmap_node; /* Indexed on 'uuid'. */
    struct uuid uuid;           /* UUID from Datapath_Binding row. */
    uint32_t tunnel_key;        /* 'tunnel_key' from Datapath_Binding row. */
    struct simap ports;         /* Logical port name to port number. */
};

/* Contains "struct logical_datapath"s. */
static struct hmap logical_datapaths = HMAP_INITIALIZER(&logical_datapaths);

/* Finds and returns the logical_datapath for 'binding', or NULL if no such
 * logical_datapath exists. */
static struct logical_datapath *
ldp_lookup(const struct sbrec_datapath_binding *binding)
{
    struct logical_datapath *ldp;
    HMAP_FOR_EACH_IN_BUCKET (ldp, hmap_node, uuid_hash(&binding->header_.uuid),
                             &logical_datapaths) {
        if (uuid_equals(&ldp->uuid, &binding->header_.uuid)) {
            return ldp;
        }
    }
    return NULL;
}

/* Creates a new logical_datapath for the given 'binding'. */
static struct logical_datapath *
ldp_create(const struct sbrec_datapath_binding *binding)
{
    struct logical_datapath *ldp;

    ldp = xmalloc(sizeof *ldp);
    hmap_insert(&logical_datapaths, &ldp->hmap_node,
                uuid_hash(&binding->header_.uuid));
    ldp->uuid = binding->header_.uuid;
    ldp->tunnel_key = binding->tunnel_key;
    simap_init(&ldp->ports);
    return ldp;
}

static struct logical_datapath *
ldp_lookup_or_create(const struct sbrec_datapath_binding *binding)
{
    struct logical_datapath *ldp = ldp_lookup(binding);
    return ldp ? ldp : ldp_create(binding);
}

static void
ldp_free(struct logical_datapath *ldp)
{
    simap_destroy(&ldp->ports);
    hmap_remove(&logical_datapaths, &ldp->hmap_node);
    free(ldp);
}

/* Iterates through all of the records in the Port_Binding table, updating the
 * table of logical_datapaths to match the values found in active
 * Port_Bindings. */
static void
ldp_run(struct controller_ctx *ctx)
{
    struct logical_datapath *ldp;
    HMAP_FOR_EACH (ldp, hmap_node, &logical_datapaths) {
        simap_clear(&ldp->ports);
    }

    const struct sbrec_port_binding *binding;
    SBREC_PORT_BINDING_FOR_EACH (binding, ctx->ovnsb_idl) {
        struct logical_datapath *ldp = ldp_lookup_or_create(binding->datapath);

        simap_put(&ldp->ports, binding->logical_port, binding->tunnel_key);
    }

    const struct sbrec_multicast_group *mc;
    SBREC_MULTICAST_GROUP_FOR_EACH (mc, ctx->ovnsb_idl) {
        struct logical_datapath *ldp = ldp_lookup_or_create(mc->datapath);
        simap_put(&ldp->ports, mc->name, mc->tunnel_key);
    }

    struct logical_datapath *next_ldp;
    HMAP_FOR_EACH_SAFE (ldp, next_ldp, hmap_node, &logical_datapaths) {
        if (simap_is_empty(&ldp->ports)) {
            ldp_free(ldp);
        }
    }
}

static void
ldp_destroy(void)
{
    struct logical_datapath *ldp, *next_ldp;
    HMAP_FOR_EACH_SAFE (ldp, next_ldp, hmap_node, &logical_datapaths) {
        ldp_free(ldp);
    }
}

void
lflow_init(void)
{
    symtab_init();
}

/* Translates logical flows in the Logical_Flow table in the OVN_SB database
 * into OpenFlow flows.  See ovn-architecture(7) for more information. */
void
lflow_run(struct controller_ctx *ctx, struct hmap *flow_table,
          const struct simap *ct_zones)
{
    struct hmap flows = HMAP_INITIALIZER(&flows);
    uint32_t conj_id_ofs = 1;

    ldp_run(ctx);

    const struct sbrec_logical_flow *lflow;
    SBREC_LOGICAL_FLOW_FOR_EACH (lflow, ctx->ovnsb_idl) {
        /* Find the "struct logical_datapath" asssociated with this
         * Logical_Flow row.  If there's no such struct, that must be because
         * no logical ports are bound to that logical datapath, so there's no
         * point in maintaining any flows for it anyway, so skip it. */
        const struct logical_datapath *ldp;
        ldp = ldp_lookup(lflow->logical_datapath);
        if (!ldp) {
            continue;
        }

        /* Determine translation of logical table IDs to physical table IDs. */
        bool ingress = !strcmp(lflow->pipeline, "ingress");
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
        error = actions_parse_string(lflow->actions, &symtab, &ldp->ports,
                                     ct_zones, first_ptable, LOG_PIPELINE_LEN,
                                     lflow->table_id, output_ptable,
                                     &ofpacts, &prereqs);
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
        uint32_t n_conjs = expr_to_matches(expr, &ldp->ports, &matches);
        expr_destroy(expr);

        /* Prepare the OpenFlow matches for adding to the flow table. */
        struct expr_match *m;
        HMAP_FOR_EACH (m, hmap_node, &matches) {
            match_set_metadata(&m->match, htonll(ldp->tunnel_key));
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

void
lflow_destroy(void)
{
    expr_symtab_destroy(&symtab);
    ldp_destroy();
}
