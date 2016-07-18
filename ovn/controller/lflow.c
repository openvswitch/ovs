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
#include "ovn/lib/actions.h"
#include "ovn/lib/expr.h"
#include "ovn/lib/ovn-dhcp.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "packets.h"
#include "simap.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(lflow);

/* Symbol table. */

/* Contains "struct expr_symbol"s for fields supported by OVN lflows. */
static struct shash symtab;

/* Contains an internal expr datastructure that represents an address set. */
static struct shash expr_address_sets;

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
    shash_init(&expr_address_sets);

    /* Reserve a pair of registers for the logical inport and outport.  A full
     * 32-bit register each is bigger than we need, but the expression code
     * doesn't yet support string fields that occupy less than a full OXM. */
    expr_symtab_add_string(&symtab, "inport", MFF_LOG_INPORT, NULL);
    expr_symtab_add_string(&symtab, "outport", MFF_LOG_OUTPORT, NULL);

    /* Logical registers. */
#define MFF_LOG_REG(ID) add_logical_register(&symtab, ID);
    MFF_LOG_REGS;
#undef MFF_LOG_REG

    expr_symtab_add_field(&symtab, "xxreg0", MFF_XXREG0, NULL, false);
    expr_symtab_add_field(&symtab, "xxreg1", MFF_XXREG1, NULL, false);

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

/* Details of an address set currently in address_sets. We keep a cached
 * copy of sets still in their string form here to make it easier to compare
 * with the current values in the OVN_Southbound database. */
struct address_set {
    char **addresses;
    size_t n_addresses;
};

/* struct address_set instances for address sets currently in the symtab,
 * hashed on the address set name. */
static struct shash local_address_sets = SHASH_INITIALIZER(&local_address_sets);

static int
addr_cmp(const void *p1, const void *p2)
{
    const char *s1 = p1;
    const char *s2 = p2;
    return strcmp(s1, s2);
}

/* Return true if the address sets match, false otherwise. */
static bool
address_sets_match(const struct address_set *addr_set,
                   const struct sbrec_address_set *addr_set_rec)
{
    char **addrs1;
    char **addrs2;

    if (addr_set->n_addresses != addr_set_rec->n_addresses) {
        return false;
    }
    size_t n_addresses = addr_set->n_addresses;

    addrs1 = xmemdup(addr_set->addresses,
                     n_addresses * sizeof addr_set->addresses[0]);
    addrs2 = xmemdup(addr_set_rec->addresses,
                     n_addresses * sizeof addr_set_rec->addresses[0]);

    qsort(addrs1, n_addresses, sizeof *addrs1, addr_cmp);
    qsort(addrs2, n_addresses, sizeof *addrs2, addr_cmp);

    bool res = true;
    size_t i;
    for (i = 0; i <  n_addresses; i++) {
        if (strcmp(addrs1[i], addrs2[i])) {
            res = false;
            break;
        }
    }

    free(addrs1);
    free(addrs2);

    return res;
}

static void
address_set_destroy(struct address_set *addr_set)
{
    size_t i;
    for (i = 0; i < addr_set->n_addresses; i++) {
        free(addr_set->addresses[i]);
    }
    if (addr_set->n_addresses) {
        free(addr_set->addresses);
    }
    free(addr_set);
}

static void
update_address_sets(struct controller_ctx *ctx)
{
    /* Remember the names of all address sets currently in expr_address_sets
     * so we can detect address sets that have been deleted. */
    struct sset cur_addr_set_names = SSET_INITIALIZER(&cur_addr_set_names);

    struct shash_node *node;
    SHASH_FOR_EACH (node, &local_address_sets) {
        sset_add(&cur_addr_set_names, node->name);
    }

    /* Iterate address sets in the southbound database.  Create and update the
     * corresponding symtab entries as necessary. */
    const struct sbrec_address_set *addr_set_rec;
    SBREC_ADDRESS_SET_FOR_EACH (addr_set_rec, ctx->ovnsb_idl) {
        struct address_set *addr_set =
            shash_find_data(&local_address_sets, addr_set_rec->name);

        bool create_set = false;
        if (addr_set) {
            /* This address set has already been added.  We must determine
             * if the symtab entry needs to be updated due to a change. */
            sset_find_and_delete(&cur_addr_set_names, addr_set_rec->name);
            if (!address_sets_match(addr_set, addr_set_rec)) {
                shash_find_and_delete(&local_address_sets, addr_set_rec->name);
                expr_macros_remove(&expr_address_sets, addr_set_rec->name);
                address_set_destroy(addr_set);
                addr_set = NULL;
                create_set = true;
            }
        } else {
            /* This address set is not yet in the symtab, so add it. */
            create_set = true;
        }

        if (create_set) {
            /* The address set is either new or has changed.  Create a symbol
             * that resolves to the full set of addresses.  Store it in
             * address_sets to remember that we created this symbol. */
            addr_set = xzalloc(sizeof *addr_set);
            addr_set->n_addresses = addr_set_rec->n_addresses;
            if (addr_set_rec->n_addresses) {
                addr_set->addresses = xmalloc(addr_set_rec->n_addresses
                                              * sizeof addr_set->addresses[0]);
                size_t i;
                for (i = 0; i < addr_set_rec->n_addresses; i++) {
                    addr_set->addresses[i] = xstrdup(addr_set_rec->addresses[i]);
                }
            }
            shash_add(&local_address_sets, addr_set_rec->name, addr_set);

            expr_macros_add(&expr_address_sets, addr_set_rec->name,
                            (const char * const *) addr_set->addresses,
                            addr_set->n_addresses);
        }
    }

    /* Anything remaining in cur_addr_set_names refers to an address set that
     * has been deleted from the southbound database.  We should delete
     * the corresponding symtab entry. */
    const char *cur_node, *next_node;
    SSET_FOR_EACH_SAFE (cur_node, next_node, &cur_addr_set_names) {
        expr_macros_remove(&expr_address_sets, cur_node);

        struct address_set *addr_set
            = shash_find_and_delete(&local_address_sets, cur_node);
        address_set_destroy(addr_set);

        struct sset_node *sset_node = SSET_NODE_FROM_NAME(cur_node);
        sset_delete(&cur_addr_set_names, sset_node);
    }

    sset_destroy(&cur_addr_set_names);
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
                                  uint32_t *conj_id_ofs_p);

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
                  const struct simap *ct_zones)
{
    uint32_t conj_id_ofs = 1;

    struct hmap dhcp_opts = HMAP_INITIALIZER(&dhcp_opts);
    const struct sbrec_dhcp_options *dhcp_opt_row;
    SBREC_DHCP_OPTIONS_FOR_EACH(dhcp_opt_row, ctx->ovnsb_idl) {
        dhcp_opt_add(&dhcp_opts, dhcp_opt_row->name, dhcp_opt_row->code,
                     dhcp_opt_row->type);
    }

    const struct sbrec_logical_flow *lflow;
    SBREC_LOGICAL_FLOW_FOR_EACH (lflow, ctx->ovnsb_idl) {
        consider_logical_flow(lports, mcgroups, lflow, local_datapaths,
                              patched_datapaths, group_table, ct_zones,
                              &dhcp_opts, &conj_id_ofs);
    }

    dhcp_opts_destroy(&dhcp_opts);
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
                      uint32_t *conj_id_ofs_p)
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
        .dhcp_opts = dhcp_opts_p,
        .lookup_port = lookup_port_cb,
        .aux = &aux,
        .ct_zones = ct_zones,
        .group_table = group_table,

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
        return;
    }

    /* Translate OVN match into table of OpenFlow matches. */
    struct hmap matches;
    struct expr *expr;

    expr = expr_parse_string(lflow->match, &symtab,
                             &expr_address_sets, &error);
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
            ofctrl_add_flow(ptable, lflow->priority, &m->match, &ofpacts,
                            &lflow->header_.uuid);
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
            ofctrl_add_flow(ptable, lflow->priority, &m->match, &conj,
                            &lflow->header_.uuid);
                ofpbuf_uninit(&conj);
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
    struct ofpact_set_field *sf = ofpact_put_SET_FIELD(ofpacts);
    sf->field = mf_from_id(dst);
    sf->flow_has_vlan = false;

    bitwise_copy(data, len, 0, &sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(&sf->mask, sf->field->n_bytes, ofs, n_bits);
}

static void
consider_neighbor_flow(const struct lport_index *lports,
                       const struct sbrec_mac_binding *b,
                       struct ofpbuf *ofpacts_p,
                       struct match *match_p)
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

    ovs_be32 ip;
    if (!ip_parse(b->ip, &ip)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'ip' %s", b->ip);
        return;
    }

    match_set_metadata(match_p, htonll(pb->datapath->tunnel_key));
    match_set_reg(match_p, MFF_LOG_OUTPORT - MFF_REG0, pb->tunnel_key);
    match_set_reg(match_p, 0, ntohl(ip));

    ofpbuf_clear(ofpacts_p);
    put_load(mac.ea, sizeof mac.ea, MFF_ETH_DST, 0, 48, ofpacts_p);

    ofctrl_add_flow(OFTABLE_MAC_BINDING, 100, match_p, ofpacts_p,
                    &b->header_.uuid);
}

/* Adds an OpenFlow flow to flow tables for each MAC binding in the OVN
 * southbound database, using 'lports' to resolve logical port names to
 * numbers. */
static void
add_neighbor_flows(struct controller_ctx *ctx,
                   const struct lport_index *lports)
{
    struct ofpbuf ofpacts;
    struct match match;
    match_init_catchall(&match);
    ofpbuf_init(&ofpacts, 0);

    const struct sbrec_mac_binding *b;
    SBREC_MAC_BINDING_FOR_EACH (b, ctx->ovnsb_idl) {
        consider_neighbor_flow(lports, b, &ofpacts, &match);
    }
    ofpbuf_uninit(&ofpacts);
}

/* Translates logical flows in the Logical_Flow table in the OVN_SB database
 * into OpenFlow flows.  See ovn-architecture(7) for more information. */
void
lflow_run(struct controller_ctx *ctx, const struct lport_index *lports,
          const struct mcgroup_index *mcgroups,
          const struct hmap *local_datapaths,
          const struct hmap *patched_datapaths,
          struct group_table *group_table,
          const struct simap *ct_zones)
{
    update_address_sets(ctx);
    add_logical_flows(ctx, lports, mcgroups, local_datapaths,
                      patched_datapaths, group_table, ct_zones);
    add_neighbor_flows(ctx, lports);
}

void
lflow_destroy(void)
{
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
    expr_macros_destroy(&expr_address_sets);
    shash_destroy(&expr_address_sets);
}
