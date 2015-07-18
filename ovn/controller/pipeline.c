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
#include "pipeline.h"
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

VLOG_DEFINE_THIS_MODULE(pipeline);

/* Symbol table. */

/* Contains "struct expr_symbol"s for fields supported by OVN pipeline. */
static struct shash symtab;

static void
symtab_init(void)
{
    shash_init(&symtab);

    /* Reserve a pair of registers for the logical inport and outport.  A full
     * 32-bit register each is bigger than we need, but the expression code
     * doesn't yet support string fields that occupy less than a full OXM. */
    expr_symtab_add_string(&symtab, "inport", MFF_LOG_INPORT, NULL);
    expr_symtab_add_string(&symtab, "outport", MFF_LOG_OUTPORT, NULL);

    /* Registers.  We omit the registers that would otherwise overlap the
     * reserved fields. */
    for (enum mf_field_id id = MFF_REG0; id < MFF_REG0 + FLOW_N_REGS; id++) {
        if (id != MFF_LOG_INPORT && id != MFF_LOG_OUTPORT) {
            char name[8];

            snprintf(name, sizeof name, "reg%d", id - MFF_REG0);
            expr_symtab_add_field(&symtab, name, id, NULL, false);
        }
    }

    /* Data fields. */
    expr_symtab_add_field(&symtab, "eth.src", MFF_ETH_SRC, NULL, false);
    expr_symtab_add_field(&symtab, "eth.dst", MFF_ETH_DST, NULL, false);
    expr_symtab_add_field(&symtab, "eth.type", MFF_ETH_TYPE, NULL, true);

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
 * 'uuid' is the UUID that represents the logical datapath in the OVN_SB
 * database.
 *
 * 'integer' represents the logical datapath as an integer value that is unique
 * only within the local hypervisor.  Because of its size, this value is more
 * practical for use in an OpenFlow flow table than a UUID.
 *
 * 'ports' maps 'logical_port' names to 'tunnel_key' values in the OVN_SB
 * Binding table within the logical datapath. */
struct logical_datapath {
    struct hmap_node hmap_node; /* Indexed on 'uuid'. */
    struct uuid uuid;           /* The logical_datapath's UUID. */
    uint32_t integer;           /* Locally unique among logical datapaths. */
    struct simap ports;         /* Logical port name to port number. */
};

/* Contains "struct logical_datapath"s. */
static struct hmap logical_datapaths = HMAP_INITIALIZER(&logical_datapaths);

/* Finds and returns the logical_datapath with the given 'uuid', or NULL if
 * no such logical_datapath exists. */
static struct logical_datapath *
ldp_lookup(const struct uuid *uuid)
{
    struct logical_datapath *ldp;
    HMAP_FOR_EACH_IN_BUCKET (ldp, hmap_node, uuid_hash(uuid),
                             &logical_datapaths) {
        if (uuid_equals(&ldp->uuid, uuid)) {
            return ldp;
        }
    }
    return NULL;
}

/* Finds and returns the integer value corresponding to the given 'uuid', or 0
 * if no such logical datapath exists. */
uint32_t
ldp_to_integer(const struct uuid *logical_datapath)
{
    const struct logical_datapath *ldp = ldp_lookup(logical_datapath);
    return ldp ? ldp->integer : 0;
}

/* Creates a new logical_datapath with the given 'uuid'. */
static struct logical_datapath *
ldp_create(const struct uuid *uuid)
{
    static uint32_t next_integer = 1;
    struct logical_datapath *ldp;

    /* We don't handle the case where the logical datapaths wrap around. */
    ovs_assert(next_integer);

    ldp = xmalloc(sizeof *ldp);
    hmap_insert(&logical_datapaths, &ldp->hmap_node, uuid_hash(uuid));
    ldp->uuid = *uuid;
    ldp->integer = next_integer++;
    simap_init(&ldp->ports);
    return ldp;
}

static void
ldp_free(struct logical_datapath *ldp)
{
    simap_destroy(&ldp->ports);
    hmap_remove(&logical_datapaths, &ldp->hmap_node);
    free(ldp);
}

/* Iterates through all of the records in the Binding table, updating the
 * table of logical_datapaths to match the values found in active Bindings. */
static void
ldp_run(struct controller_ctx *ctx)
{
    struct logical_datapath *ldp;
    HMAP_FOR_EACH (ldp, hmap_node, &logical_datapaths) {
        simap_clear(&ldp->ports);
    }

    const struct sbrec_binding *binding;
    SBREC_BINDING_FOR_EACH (binding, ctx->ovnsb_idl) {
        struct logical_datapath *ldp;

        ldp = ldp_lookup(&binding->logical_datapath);
        if (!ldp) {
            ldp = ldp_create(&binding->logical_datapath);
        }

        simap_put(&ldp->ports, binding->logical_port, binding->tunnel_key);
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
pipeline_init(void)
{
    symtab_init();
}

/* Translates logical flows in the Pipeline table in the OVN_SB database
 * into OpenFlow flows, adding the OpenFlow flows to 'flow_table'.
 *
 * We put the Pipeline flows into OpenFlow tables 16 through 47 (inclusive). */
void
pipeline_run(struct controller_ctx *ctx, struct hmap *flow_table)
{
    struct hmap flows = HMAP_INITIALIZER(&flows);
    uint32_t conj_id_ofs = 1;

    ldp_run(ctx);

    const struct sbrec_pipeline *pipeline;
    SBREC_PIPELINE_FOR_EACH (pipeline, ctx->ovnsb_idl) {
        /* Find the "struct logical_datapath" asssociated with this Pipeline
         * row.  If there's no such struct, that must be because no logical
         * ports are bound to that logical datapath, so there's no point in
         * maintaining any flows for it anyway, so skip it. */
        const struct logical_datapath *ldp;
        ldp = ldp_lookup(&pipeline->logical_datapath);
        if (!ldp) {
            continue;
        }

        /* Translate OVN actions into OpenFlow actions. */
        uint64_t ofpacts_stub[64 / 8];
        struct ofpbuf ofpacts;
        struct expr *prereqs;
        uint8_t next_table_id;
        char *error;

        ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
        next_table_id = pipeline->table_id < 31 ? pipeline->table_id + 17 : 0;
        error = actions_parse_string(pipeline->actions, &symtab, &ldp->ports,
                                     next_table_id, &ofpacts, &prereqs);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "error parsing actions \"%s\": %s",
                         pipeline->actions, error);
            free(error);
            continue;
        }

        /* Translate OVN match into table of OpenFlow matches. */
        struct hmap matches;
        struct expr *expr;

        expr = expr_parse_string(pipeline->match, &symtab, &error);
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
                         pipeline->match, error);
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
            match_set_metadata(&m->match, htonll(ldp->integer));
            if (m->match.wc.masks.conj_id) {
                m->match.flow.conj_id += conj_id_ofs;
            }
            if (!m->n) {
                ofctrl_add_flow(flow_table, pipeline->table_id + 16,
                                pipeline->priority, &m->match, &ofpacts);
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
                ofctrl_add_flow(flow_table, pipeline->table_id + 16,
                                pipeline->priority, &m->match, &conj);
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
pipeline_destroy(struct controller_ctx *ctx OVS_UNUSED)
{
    expr_symtab_destroy(&symtab);
    ldp_destroy();
}
