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
#include "ofctrl.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "ovn/actions.h"
#include "ovn/expr.h"
#include "ovn/lib/ovn-dhcp.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "packets.h"
#include "physical.h"
#include "simap.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(lflow);

/* Symbol table. */

/* Contains "struct expr_symbol"s for fields supported by OVN lflows. */
static struct shash symtab;

void
lflow_init(void)
{
    ovn_init_symtab(&symtab);
}

/* Iterate address sets in the southbound database.  Create and update the
 * corresponding symtab entries as necessary. */
static void
update_address_sets(struct controller_ctx *ctx,
                    struct shash *expr_address_sets_p)

{
    const struct sbrec_address_set *as;
    SBREC_ADDRESS_SET_FOR_EACH (as, ctx->ovnsb_idl) {
        expr_macros_add(expr_address_sets_p, as->name,
                        (const char *const *) as->addresses, as->n_addresses);
    }
}

struct lookup_port_aux {
    const struct lport_index *lports;
    const struct mcgroup_index *mcgroups;
    const struct sbrec_datapath_binding *dp;
};

static void consider_logical_flow(const struct lport_index *lports,
                                  const struct mcgroup_index *mcgroups,
                                  const struct sbrec_logical_flow *lflow,
                                  const struct hmap *local_datapaths,
                                  const struct hmap *patched_datapaths,
                                  struct group_table *group_table,
                                  const struct simap *ct_zones,
                                  struct hmap *dhcp_opts_p,
                                  struct hmap *dhcpv6_opts_p,
                                  uint32_t *conj_id_ofs_p,
                                  struct hmap *flow_table,
                                  struct shash *expr_address_sets_p);

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

/* Adds the logical flows from the Logical_Flow table to flow tables. */
static void
add_logical_flows(struct controller_ctx *ctx, const struct lport_index *lports,
                  const struct mcgroup_index *mcgroups,
                  const struct hmap *local_datapaths,
                  const struct hmap *patched_datapaths,
                  struct group_table *group_table,
                  const struct simap *ct_zones,
                  struct hmap *flow_table,
                  struct shash *expr_address_sets_p)
{
    uint32_t conj_id_ofs = 1;
    const struct sbrec_logical_flow *lflow;

    struct hmap dhcp_opts = HMAP_INITIALIZER(&dhcp_opts);
    struct hmap dhcpv6_opts = HMAP_INITIALIZER(&dhcpv6_opts);
    const struct sbrec_dhcp_options *dhcp_opt_row;
    SBREC_DHCP_OPTIONS_FOR_EACH(dhcp_opt_row, ctx->ovnsb_idl) {
        dhcp_opt_add(&dhcp_opts, dhcp_opt_row->name, dhcp_opt_row->code,
                     dhcp_opt_row->type);
    }


    const struct sbrec_dhcpv6_options *dhcpv6_opt_row;
    SBREC_DHCPV6_OPTIONS_FOR_EACH(dhcpv6_opt_row, ctx->ovnsb_idl) {
       dhcp_opt_add(&dhcpv6_opts, dhcpv6_opt_row->name, dhcpv6_opt_row->code,
                    dhcpv6_opt_row->type);
    }

    SBREC_LOGICAL_FLOW_FOR_EACH (lflow, ctx->ovnsb_idl) {
        consider_logical_flow(lports, mcgroups, lflow, local_datapaths,
                              patched_datapaths, group_table, ct_zones,
                              &dhcp_opts, &dhcpv6_opts, &conj_id_ofs,
                              flow_table, expr_address_sets_p);
    }

    dhcp_opts_destroy(&dhcp_opts);
    dhcp_opts_destroy(&dhcpv6_opts);
}

static void
consider_logical_flow(const struct lport_index *lports,
                      const struct mcgroup_index *mcgroups,
                      const struct sbrec_logical_flow *lflow,
                      const struct hmap *local_datapaths,
                      const struct hmap *patched_datapaths,
                      struct group_table *group_table,
                      const struct simap *ct_zones,
                      struct hmap *dhcp_opts_p,
                      struct hmap *dhcpv6_opts_p,
                      uint32_t *conj_id_ofs_p,
                      struct hmap *flow_table,
                      struct shash *expr_address_sets_p)
{
    /* Determine translation of logical table IDs to physical table IDs. */
    bool ingress = !strcmp(lflow->pipeline, "ingress");

    const struct sbrec_datapath_binding *ldp = lflow->logical_datapath;
    if (!ldp) {
        return;
    }
    if (is_switch(ldp)) {
        /* For a logical switch datapath, local_datapaths tells us if there
         * are any local ports for this datapath.  If not, we can skip
         * processing logical flows if that logical switch datapath is not
         * patched to any logical router.
         *
         * Otherwise, we still need both ingress and egress pipeline
         * because even if there are no local ports, we still may need to
         * execute the ingress pipeline after a packet leaves a logical
         * router and we need to do egress pipeline for a switch that
         * is connected to only routers.  Further optimization is possible,
         * but not based on what we know with local_datapaths right now.
         *
         * A better approach would be a kind of "flood fill" algorithm:
         *
         *   1. Initialize set S to the logical datapaths that have a port
         *      located on the hypervisor.
         *
         *   2. For each patch port P in a logical datapath in S, add the
         *      logical datapath of the remote end of P to S.  Iterate
         *      until S reaches a fixed point.
         *
         * This can be implemented in northd, which can generate the sets and
         * save it on each port-binding record in SB, and ovn-controller can
         * use the information directly. However, there can be update storms
         * when a pair of patch ports are added/removed to connect/disconnect
         * large lrouters and lswitches. This need to be studied further.
         */

        if (!get_local_datapath(local_datapaths, ldp->tunnel_key)) {
            if (!get_patched_datapath(patched_datapaths,
                                      ldp->tunnel_key)) {
                return;
            }
        }
    }

    /* Determine translation of logical table IDs to physical table IDs. */
    uint8_t first_ptable = (ingress
                            ? OFTABLE_LOG_INGRESS_PIPELINE
                            : OFTABLE_LOG_EGRESS_PIPELINE);
    uint8_t ptable = first_ptable + lflow->table_id;
    uint8_t output_ptable = (ingress
                             ? OFTABLE_REMOTE_OUTPUT
                             : OFTABLE_SAVE_INPORT);

    /* Parse OVN logical actions.
     *
     * XXX Deny changes to 'outport' in egress pipeline. */
    uint64_t ovnacts_stub[1024 / 8];
    struct ofpbuf ovnacts = OFPBUF_STUB_INITIALIZER(ovnacts_stub);
    struct ovnact_parse_params pp = {
        .symtab = &symtab,
        .dhcp_opts = dhcp_opts_p,
        .dhcpv6_opts = dhcpv6_opts_p,

        .n_tables = LOG_PIPELINE_LEN,
        .cur_ltable = lflow->table_id,
    };
    struct expr *prereqs;
    char *error;

    error = ovnacts_parse_string(lflow->actions, &pp, &ovnacts, &prereqs);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "error parsing actions \"%s\": %s",
                     lflow->actions, error);
        free(error);
        ovnacts_free(ovnacts.data, ovnacts.size);
        ofpbuf_uninit(&ovnacts);
        return;
    }

    /* Encode OVN logical actions into OpenFlow. */
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    struct lookup_port_aux aux = {
        .lports = lports,
        .mcgroups = mcgroups,
        .dp = lflow->logical_datapath
    };
    struct ovnact_encode_params ep = {
        .lookup_port = lookup_port_cb,
        .aux = &aux,
        .is_switch = is_switch(ldp),
        .ct_zones = ct_zones,
        .group_table = group_table,

        .first_ptable = first_ptable,
        .output_ptable = output_ptable,
        .mac_bind_ptable = OFTABLE_MAC_BINDING,
    };
    ovnacts_encode(ovnacts.data, ovnacts.size, &ep, &ofpacts);
    ovnacts_free(ovnacts.data, ovnacts.size);
    ofpbuf_uninit(&ovnacts);

    /* Translate OVN match into table of OpenFlow matches. */
    struct hmap matches;
    struct expr *expr;

    expr = expr_parse_string(lflow->match, &symtab,
                             expr_address_sets_p, &error);
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
        return;
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
            m->match.flow.conj_id += *conj_id_ofs_p;
        }
        if (!m->n) {
            ofctrl_add_flow(flow_table, ptable, lflow->priority, &m->match,
                            &ofpacts);
        } else {
            uint64_t conj_stubs[64 / 8];
            struct ofpbuf conj;

            ofpbuf_use_stub(&conj, conj_stubs, sizeof conj_stubs);
            for (int i = 0; i < m->n; i++) {
                const struct cls_conjunction *src = &m->conjunctions[i];
                struct ofpact_conjunction *dst;

                dst = ofpact_put_CONJUNCTION(&conj);
                dst->id = src->id + *conj_id_ofs_p;
                dst->clause = src->clause;
                dst->n_clauses = src->n_clauses;
            }
            ofctrl_add_flow(flow_table, ptable, lflow->priority, &m->match,
                            &conj);
            ofpbuf_uninit(&conj);
        }
    }

    /* Clean up. */
    expr_matches_destroy(&matches);
    ofpbuf_uninit(&ofpacts);
    *conj_id_ofs_p += n_conjs;
}

static void
put_load(const uint8_t *data, size_t len,
         enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    bitwise_copy(data, len, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

static void
consider_neighbor_flow(const struct lport_index *lports,
                       const struct sbrec_mac_binding *b,
                       struct hmap *flow_table)
{
    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(lports, b->logical_port);
    if (!pb) {
        return;
    }

    struct eth_addr mac;
    if (!eth_addr_from_string(b->mac, &mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'mac' %s", b->mac);
        return;
    }

    struct match match = MATCH_CATCHALL_INITIALIZER;
    if (strchr(b->ip, '.')) {
        ovs_be32 ip;
        if (!ip_parse(b->ip, &ip)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'ip' %s", b->ip);
            return;
        }
        match_set_reg(&match, 0, ntohl(ip));
    } else {
        struct in6_addr ip6;
        if (!ipv6_parse(b->ip, &ip6)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'ip' %s", b->ip);
            return;
        }
        ovs_be128 value;
        memcpy(&value, &ip6, sizeof(value));
        match_set_xxreg(&match, 0, ntoh128(value));
    }

    match_set_metadata(&match, htonll(pb->datapath->tunnel_key));
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, pb->tunnel_key);

    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    put_load(mac.ea, sizeof mac.ea, MFF_ETH_DST, 0, 48, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_MAC_BINDING, 100, &match, &ofpacts);
    ofpbuf_uninit(&ofpacts);
}

/* Adds an OpenFlow flow to flow tables for each MAC binding in the OVN
 * southbound database, using 'lports' to resolve logical port names to
 * numbers. */
static void
add_neighbor_flows(struct controller_ctx *ctx,
                   const struct lport_index *lports,
                   struct hmap *flow_table)
{
    const struct sbrec_mac_binding *b;
    SBREC_MAC_BINDING_FOR_EACH (b, ctx->ovnsb_idl) {
        consider_neighbor_flow(lports, b, flow_table);
    }
}

/* Translates logical flows in the Logical_Flow table in the OVN_SB database
 * into OpenFlow flows.  See ovn-architecture(7) for more information. */
void
lflow_run(struct controller_ctx *ctx, const struct lport_index *lports,
          const struct mcgroup_index *mcgroups,
          const struct hmap *local_datapaths,
          const struct hmap *patched_datapaths,
          struct group_table *group_table,
          const struct simap *ct_zones,
          struct hmap *flow_table)
{
    struct shash expr_address_sets = SHASH_INITIALIZER(&expr_address_sets);

    update_address_sets(ctx, &expr_address_sets);
    add_logical_flows(ctx, lports, mcgroups, local_datapaths,
                      patched_datapaths, group_table, ct_zones, flow_table,
                      &expr_address_sets);
    add_neighbor_flows(ctx, lports, flow_table);

    expr_macros_destroy(&expr_address_sets);
    shash_destroy(&expr_address_sets);
}

void
lflow_destroy(void)
{
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
}
