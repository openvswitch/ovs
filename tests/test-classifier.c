/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

/* "White box" tests for classifier.
 *
 * With very few exceptions, these tests obtain complete coverage of every
 * basic block and every branch in the classifier implementation, e.g. a clean
 * report from "gcov -b".  (Covering the exceptions would require finding
 * collisions in the hash function used for flow data, etc.)
 *
 * This test should receive a clean report from "valgrind --leak-check=full":
 * it frees every heap block that it allocates.
 */

#include <config.h>
#undef NDEBUG
#include "classifier.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include "byte-order.h"
#include "classifier-private.h"
#include "command-line.h"
#include "fatal-signal.h"
#include "flow.h"
#include "openvswitch/ofp-util.h"
#include "ovstest.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "packets.h"
#include "random.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"

static bool versioned = false;

/* Fields in a rule. */
#define CLS_FIELDS                            \
    /*        struct flow        all-caps */  \
    /*        member name        name     */  \
    /*        -----------        -------- */  \
    CLS_FIELD(tunnel.tun_id,     TUN_ID)      \
    CLS_FIELD(metadata,          METADATA)    \
    CLS_FIELD(nw_src,            NW_SRC)      \
    CLS_FIELD(nw_dst,            NW_DST)      \
    CLS_FIELD(in_port.ofp_port,  IN_PORT)     \
    CLS_FIELD(vlans[0].tci,      VLAN_TCI)    \
    CLS_FIELD(dl_type,           DL_TYPE)     \
    CLS_FIELD(tp_src,            TP_SRC)      \
    CLS_FIELD(tp_dst,            TP_DST)      \
    CLS_FIELD(dl_src,            DL_SRC)      \
    CLS_FIELD(dl_dst,            DL_DST)      \
    CLS_FIELD(nw_proto,          NW_PROTO)    \
    CLS_FIELD(nw_tos,            NW_DSCP)

/* Field indexes.
 *
 * (These are also indexed into struct classifier's 'tables' array.) */
enum {
#define CLS_FIELD(MEMBER, NAME) CLS_F_IDX_##NAME,
    CLS_FIELDS
#undef CLS_FIELD
    CLS_N_FIELDS
};

/* Field information. */
struct cls_field {
    int ofs;                    /* Offset in struct flow. */
    int len;                    /* Length in bytes. */
    const char *name;           /* Name (for debugging). */
};

static const struct cls_field cls_fields[CLS_N_FIELDS] = {
#define CLS_FIELD(MEMBER, NAME)                 \
    { offsetof(struct flow, MEMBER),            \
      sizeof ((struct flow *)0)->MEMBER,        \
      #NAME },
    CLS_FIELDS
#undef CLS_FIELD
};

struct test_rule {
    struct ovs_list list_node;
    int aux;                    /* Auxiliary data. */
    struct cls_rule cls_rule;   /* Classifier rule data. */
};

static struct test_rule *
test_rule_from_cls_rule(const struct cls_rule *rule)
{
    return rule ? CONTAINER_OF(rule, struct test_rule, cls_rule) : NULL;
}

static void
test_rule_destroy(struct test_rule *rule)
{
    if (rule) {
        cls_rule_destroy(&rule->cls_rule);
        free(rule);
    }
}

static struct test_rule *make_rule(int wc_fields, int priority, int value_pat);
static void free_rule(struct test_rule *);
static struct test_rule *clone_rule(const struct test_rule *);

/* Trivial (linear) classifier. */
struct tcls {
    size_t n_rules;
    size_t allocated_rules;
    struct test_rule **rules;
};

static void
tcls_init(struct tcls *tcls)
{
    tcls->n_rules = 0;
    tcls->allocated_rules = 0;
    tcls->rules = NULL;
}

static void
tcls_destroy(struct tcls *tcls)
{
    if (tcls) {
        size_t i;

        for (i = 0; i < tcls->n_rules; i++) {
            test_rule_destroy(tcls->rules[i]);
        }
        free(tcls->rules);
    }
}

static bool
tcls_is_empty(const struct tcls *tcls)
{
    return tcls->n_rules == 0;
}

static struct test_rule *
tcls_insert(struct tcls *tcls, const struct test_rule *rule)
{
    size_t i;

    for (i = 0; i < tcls->n_rules; i++) {
        const struct cls_rule *pos = &tcls->rules[i]->cls_rule;
        if (cls_rule_equal(pos, &rule->cls_rule)) {
            /* Exact match. */
            ovsrcu_postpone(free_rule, tcls->rules[i]);
            tcls->rules[i] = clone_rule(rule);
            return tcls->rules[i];
        } else if (pos->priority < rule->cls_rule.priority) {
            break;
        }
    }

    if (tcls->n_rules >= tcls->allocated_rules) {
        tcls->rules = x2nrealloc(tcls->rules, &tcls->allocated_rules,
                                 sizeof *tcls->rules);
    }
    if (i != tcls->n_rules) {
        memmove(&tcls->rules[i + 1], &tcls->rules[i],
                sizeof *tcls->rules * (tcls->n_rules - i));
    }
    tcls->rules[i] = clone_rule(rule);
    tcls->n_rules++;
    return tcls->rules[i];
}

static void
tcls_remove(struct tcls *cls, const struct test_rule *rule)
{
    size_t i;

    for (i = 0; i < cls->n_rules; i++) {
        struct test_rule *pos = cls->rules[i];
        if (pos == rule) {
            test_rule_destroy(pos);

            memmove(&cls->rules[i], &cls->rules[i + 1],
                    sizeof *cls->rules * (cls->n_rules - i - 1));

            cls->n_rules--;
            return;
        }
    }
    OVS_NOT_REACHED();
}

static bool
match(const struct cls_rule *wild_, const struct flow *fixed)
{
    struct match wild;
    int f_idx;

    minimatch_expand(&wild_->match, &wild);
    for (f_idx = 0; f_idx < CLS_N_FIELDS; f_idx++) {
        bool eq;

        if (f_idx == CLS_F_IDX_NW_SRC) {
            eq = !((fixed->nw_src ^ wild.flow.nw_src)
                   & wild.wc.masks.nw_src);
        } else if (f_idx == CLS_F_IDX_NW_DST) {
            eq = !((fixed->nw_dst ^ wild.flow.nw_dst)
                   & wild.wc.masks.nw_dst);
        } else if (f_idx == CLS_F_IDX_TP_SRC) {
            eq = !((fixed->tp_src ^ wild.flow.tp_src)
                   & wild.wc.masks.tp_src);
        } else if (f_idx == CLS_F_IDX_TP_DST) {
            eq = !((fixed->tp_dst ^ wild.flow.tp_dst)
                   & wild.wc.masks.tp_dst);
        } else if (f_idx == CLS_F_IDX_DL_SRC) {
            eq = eth_addr_equal_except(fixed->dl_src, wild.flow.dl_src,
                                       wild.wc.masks.dl_src);
        } else if (f_idx == CLS_F_IDX_DL_DST) {
            eq = eth_addr_equal_except(fixed->dl_dst, wild.flow.dl_dst,
                                       wild.wc.masks.dl_dst);
        } else if (f_idx == CLS_F_IDX_VLAN_TCI) {
            eq = !((fixed->vlans[0].tci ^ wild.flow.vlans[0].tci)
                   & wild.wc.masks.vlans[0].tci);
        } else if (f_idx == CLS_F_IDX_TUN_ID) {
            eq = !((fixed->tunnel.tun_id ^ wild.flow.tunnel.tun_id)
                   & wild.wc.masks.tunnel.tun_id);
        } else if (f_idx == CLS_F_IDX_METADATA) {
            eq = !((fixed->metadata ^ wild.flow.metadata)
                   & wild.wc.masks.metadata);
        } else if (f_idx == CLS_F_IDX_NW_DSCP) {
            eq = !((fixed->nw_tos ^ wild.flow.nw_tos) &
                   (wild.wc.masks.nw_tos & IP_DSCP_MASK));
        } else if (f_idx == CLS_F_IDX_NW_PROTO) {
            eq = !((fixed->nw_proto ^ wild.flow.nw_proto)
                   & wild.wc.masks.nw_proto);
        } else if (f_idx == CLS_F_IDX_DL_TYPE) {
            eq = !((fixed->dl_type ^ wild.flow.dl_type)
                   & wild.wc.masks.dl_type);
        } else if (f_idx == CLS_F_IDX_IN_PORT) {
            eq = !((fixed->in_port.ofp_port
                    ^ wild.flow.in_port.ofp_port)
                   & wild.wc.masks.in_port.ofp_port);
        } else {
            OVS_NOT_REACHED();
        }

        if (!eq) {
            return false;
        }
    }
    return true;
}

static struct cls_rule *
tcls_lookup(const struct tcls *cls, const struct flow *flow)
{
    size_t i;

    for (i = 0; i < cls->n_rules; i++) {
        struct test_rule *pos = cls->rules[i];
        if (match(&pos->cls_rule, flow)) {
            return &pos->cls_rule;
        }
    }
    return NULL;
}

static void
tcls_delete_matches(struct tcls *cls, const struct cls_rule *target)
{
    size_t i;

    for (i = 0; i < cls->n_rules; ) {
        struct test_rule *pos = cls->rules[i];
        if (!minimask_has_extra(pos->cls_rule.match.mask,
                                target->match.mask)) {
            struct flow flow;

            miniflow_expand(pos->cls_rule.match.flow, &flow);
            if (match(target, &flow)) {
                tcls_remove(cls, pos);
                continue;
            }
        }
        i++;
    }
}

static ovs_be32 nw_src_values[] = { CONSTANT_HTONL(0xc0a80001),
                                    CONSTANT_HTONL(0xc0a04455) };
static ovs_be32 nw_dst_values[] = { CONSTANT_HTONL(0xc0a80002),
                                    CONSTANT_HTONL(0xc0a04455) };
static ovs_be64 tun_id_values[] = {
    0,
    CONSTANT_HTONLL(UINT64_C(0xfedcba9876543210)) };
static ovs_be64 metadata_values[] = {
    0,
    CONSTANT_HTONLL(UINT64_C(0xfedcba9876543210)) };
static ofp_port_t in_port_values[] = { OFP_PORT_C(1), OFPP_LOCAL };
static ovs_be16 vlan_tci_values[] = { CONSTANT_HTONS(101), CONSTANT_HTONS(0) };
static ovs_be16 dl_type_values[]
            = { CONSTANT_HTONS(ETH_TYPE_IP), CONSTANT_HTONS(ETH_TYPE_ARP) };
static ovs_be16 tp_src_values[] = { CONSTANT_HTONS(49362),
                                    CONSTANT_HTONS(80) };
static ovs_be16 tp_dst_values[] = { CONSTANT_HTONS(6667), CONSTANT_HTONS(22) };
static struct eth_addr dl_src_values[] = {
    ETH_ADDR_C(00,02,e3,0f,80,a4),
    ETH_ADDR_C(5e,33,7f,5f,1e,99)
};
static struct eth_addr dl_dst_values[] = {
    ETH_ADDR_C(4a,27,71,ae,64,c1),
    ETH_ADDR_C(ff,ff,ff,ff,ff,ff)
};
static uint8_t nw_proto_values[] = { IPPROTO_TCP, IPPROTO_ICMP };
static uint8_t nw_dscp_values[] = { 48, 0 };

static void *values[CLS_N_FIELDS][2];

static void
init_values(void)
{
    values[CLS_F_IDX_TUN_ID][0] = &tun_id_values[0];
    values[CLS_F_IDX_TUN_ID][1] = &tun_id_values[1];

    values[CLS_F_IDX_METADATA][0] = &metadata_values[0];
    values[CLS_F_IDX_METADATA][1] = &metadata_values[1];

    values[CLS_F_IDX_IN_PORT][0] = &in_port_values[0];
    values[CLS_F_IDX_IN_PORT][1] = &in_port_values[1];

    values[CLS_F_IDX_VLAN_TCI][0] = &vlan_tci_values[0];
    values[CLS_F_IDX_VLAN_TCI][1] = &vlan_tci_values[1];

    values[CLS_F_IDX_DL_SRC][0] = &dl_src_values[0];
    values[CLS_F_IDX_DL_SRC][1] = &dl_src_values[1];

    values[CLS_F_IDX_DL_DST][0] = &dl_dst_values[0];
    values[CLS_F_IDX_DL_DST][1] = &dl_dst_values[1];

    values[CLS_F_IDX_DL_TYPE][0] = &dl_type_values[0];
    values[CLS_F_IDX_DL_TYPE][1] = &dl_type_values[1];

    values[CLS_F_IDX_NW_SRC][0] = &nw_src_values[0];
    values[CLS_F_IDX_NW_SRC][1] = &nw_src_values[1];

    values[CLS_F_IDX_NW_DST][0] = &nw_dst_values[0];
    values[CLS_F_IDX_NW_DST][1] = &nw_dst_values[1];

    values[CLS_F_IDX_NW_PROTO][0] = &nw_proto_values[0];
    values[CLS_F_IDX_NW_PROTO][1] = &nw_proto_values[1];

    values[CLS_F_IDX_NW_DSCP][0] = &nw_dscp_values[0];
    values[CLS_F_IDX_NW_DSCP][1] = &nw_dscp_values[1];

    values[CLS_F_IDX_TP_SRC][0] = &tp_src_values[0];
    values[CLS_F_IDX_TP_SRC][1] = &tp_src_values[1];

    values[CLS_F_IDX_TP_DST][0] = &tp_dst_values[0];
    values[CLS_F_IDX_TP_DST][1] = &tp_dst_values[1];
}

#define N_NW_SRC_VALUES ARRAY_SIZE(nw_src_values)
#define N_NW_DST_VALUES ARRAY_SIZE(nw_dst_values)
#define N_TUN_ID_VALUES ARRAY_SIZE(tun_id_values)
#define N_METADATA_VALUES ARRAY_SIZE(metadata_values)
#define N_IN_PORT_VALUES ARRAY_SIZE(in_port_values)
#define N_VLAN_TCI_VALUES ARRAY_SIZE(vlan_tci_values)
#define N_DL_TYPE_VALUES ARRAY_SIZE(dl_type_values)
#define N_TP_SRC_VALUES ARRAY_SIZE(tp_src_values)
#define N_TP_DST_VALUES ARRAY_SIZE(tp_dst_values)
#define N_DL_SRC_VALUES ARRAY_SIZE(dl_src_values)
#define N_DL_DST_VALUES ARRAY_SIZE(dl_dst_values)
#define N_NW_PROTO_VALUES ARRAY_SIZE(nw_proto_values)
#define N_NW_DSCP_VALUES ARRAY_SIZE(nw_dscp_values)

#define N_FLOW_VALUES (N_NW_SRC_VALUES *        \
                       N_NW_DST_VALUES *        \
                       N_TUN_ID_VALUES *        \
                       N_IN_PORT_VALUES *       \
                       N_VLAN_TCI_VALUES *       \
                       N_DL_TYPE_VALUES *       \
                       N_TP_SRC_VALUES *        \
                       N_TP_DST_VALUES *        \
                       N_DL_SRC_VALUES *        \
                       N_DL_DST_VALUES *        \
                       N_NW_PROTO_VALUES *      \
                       N_NW_DSCP_VALUES)

static unsigned int
get_value(unsigned int *x, unsigned n_values)
{
    unsigned int rem = *x % n_values;
    *x /= n_values;
    return rem;
}

static void
compare_classifiers(struct classifier *cls, size_t n_invisible_rules,
                    ovs_version_t version, struct tcls *tcls)
{
    static const int confidence = 500;
    unsigned int i;

    assert(classifier_count(cls) == tcls->n_rules + n_invisible_rules);
    for (i = 0; i < confidence; i++) {
        const struct cls_rule *cr0, *cr1, *cr2;
        struct flow flow;
        struct flow_wildcards wc;
        unsigned int x;

        flow_wildcards_init_catchall(&wc);
        x = random_range(N_FLOW_VALUES);
        memset(&flow, 0, sizeof flow);
        flow.nw_src = nw_src_values[get_value(&x, N_NW_SRC_VALUES)];
        flow.nw_dst = nw_dst_values[get_value(&x, N_NW_DST_VALUES)];
        flow.tunnel.tun_id = tun_id_values[get_value(&x, N_TUN_ID_VALUES)];
        flow.metadata = metadata_values[get_value(&x, N_METADATA_VALUES)];
        flow.in_port.ofp_port = in_port_values[get_value(&x,
                                                   N_IN_PORT_VALUES)];
        flow.vlans[0].tci = vlan_tci_values[get_value(&x, N_VLAN_TCI_VALUES)];
        flow.dl_type = dl_type_values[get_value(&x, N_DL_TYPE_VALUES)];
        flow.tp_src = tp_src_values[get_value(&x, N_TP_SRC_VALUES)];
        flow.tp_dst = tp_dst_values[get_value(&x, N_TP_DST_VALUES)];
        flow.dl_src = dl_src_values[get_value(&x, N_DL_SRC_VALUES)];
        flow.dl_dst = dl_dst_values[get_value(&x, N_DL_DST_VALUES)];
        flow.nw_proto = nw_proto_values[get_value(&x, N_NW_PROTO_VALUES)];
        flow.nw_tos = nw_dscp_values[get_value(&x, N_NW_DSCP_VALUES)];

        /* This assertion is here to suppress a GCC 4.9 array-bounds warning */
        ovs_assert(cls->n_tries <= CLS_MAX_TRIES);

        cr0 = classifier_lookup(cls, version, &flow, &wc);
        cr1 = tcls_lookup(tcls, &flow);
        assert((cr0 == NULL) == (cr1 == NULL));
        if (cr0 != NULL) {
            const struct test_rule *tr0 = test_rule_from_cls_rule(cr0);
            const struct test_rule *tr1 = test_rule_from_cls_rule(cr1);

            assert(cls_rule_equal(cr0, cr1));
            assert(tr0->aux == tr1->aux);

            /* Make sure the rule should have been visible. */
            assert(cls_rule_visible_in_version(cr0, version));
        }
        cr2 = classifier_lookup(cls, version, &flow, NULL);
        assert(cr2 == cr0);
    }
}

static void
destroy_classifier(struct classifier *cls)
{
    struct test_rule *rule;

    classifier_defer(cls);
    CLS_FOR_EACH (rule, cls_rule, cls) {
        classifier_remove_assert(cls, &rule->cls_rule);
        ovsrcu_postpone(free_rule, rule);
    }
    classifier_destroy(cls);
}

static void
pvector_verify(const struct pvector *pvec)
{
    void *ptr OVS_UNUSED;
    int prev_priority = INT_MAX;

    PVECTOR_FOR_EACH (ptr, pvec) {
        int priority = cursor__.vector[cursor__.entry_idx].priority;
        if (priority > prev_priority) {
            ovs_abort(0, "Priority vector is out of order (%u > %u)",
                      priority, prev_priority);
        }
        prev_priority = priority;
    }
}

static unsigned int
trie_verify(const rcu_trie_ptr *trie, unsigned int ofs, unsigned int n_bits)
{
    const struct trie_node *node = ovsrcu_get(struct trie_node *, trie);

    if (node) {
        assert(node->n_rules == 0 || node->n_bits > 0);
        ofs += node->n_bits;
        assert((ofs > 0 || (ofs == 0 && node->n_bits == 0)) && ofs <= n_bits);

        return node->n_rules
            + trie_verify(&node->edges[0], ofs, n_bits)
            + trie_verify(&node->edges[1], ofs, n_bits);
    }
    return 0;
}

static void
verify_tries(struct classifier *cls)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    unsigned int n_rules = 0;
    int i;

    for (i = 0; i < cls->n_tries; i++) {
        n_rules += trie_verify(&cls->tries[i].root, 0,
                               cls->tries[i].field->n_bits);
    }
    assert(n_rules <= cls->n_rules);
}

static void
check_tables(const struct classifier *cls, int n_tables, int n_rules,
             int n_dups, int n_invisible, ovs_version_t version)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    const struct cls_subtable *table;
    struct test_rule *test_rule;
    int found_tables = 0;
    int found_tables_with_visible_rules = 0;
    int found_rules = 0;
    int found_dups = 0;
    int found_invisible = 0;
    int found_visible_but_removable = 0;
    int found_rules2 = 0;

    pvector_verify(&cls->subtables);
    CMAP_FOR_EACH (table, cmap_node, &cls->subtables_map) {
        const struct cls_match *head;
        int max_priority = INT_MIN;
        unsigned int max_count = 0;
        bool found = false;
        bool found_visible_rules = false;
        const struct cls_subtable *iter;

        /* Locate the subtable from 'subtables'. */
        PVECTOR_FOR_EACH (iter, &cls->subtables) {
            if (iter == table) {
                if (found) {
                    ovs_abort(0, "Subtable %p duplicated in 'subtables'.",
                              table);
                }
                found = true;
            }
        }
        if (!found) {
            ovs_abort(0, "Subtable %p not found from 'subtables'.", table);
        }

        assert(!cmap_is_empty(&table->rules));
        assert(trie_verify(&table->ports_trie, 0, table->ports_mask_len)
               == (table->ports_mask_len ? cmap_count(&table->rules) : 0));

        found_tables++;

        CMAP_FOR_EACH (head, cmap_node, &table->rules) {
            int prev_priority = INT_MAX;
            ovs_version_t prev_version = 0;
            const struct cls_match *rule, *prev;
            bool found_visible_rules_in_list = false;

            assert(head->priority <= table->max_priority);

            if (head->priority > max_priority) {
                max_priority = head->priority;
                max_count = 0;
            }

            FOR_EACH_RULE_IN_LIST_PROTECTED(rule, prev, head) {
                ovs_version_t rule_version;
                const struct cls_rule *found_rule;

                /* Priority may not increase. */
                assert(rule->priority <= prev_priority);

                if (rule->priority == max_priority) {
                    ++max_count;
                }

                /* Count invisible rules and visible duplicates. */
                if (!cls_match_visible_in_version(rule, version)) {
                    found_invisible++;
                } else {
                    if (cls_match_is_eventually_invisible(rule)) {
                        found_visible_but_removable++;
                    }
                    if (found_visible_rules_in_list) {
                        found_dups++;
                    }
                    found_visible_rules_in_list = true;
                    found_visible_rules = true;
                }

                /* Rule must be visible in the version it was inserted. */
                rule_version = rule->versions.add_version;
                assert(cls_match_visible_in_version(rule, rule_version));

                /* We should always find the latest version of the rule,
                 * unless all rules have been marked for removal.
                 * Later versions must always be later in the list. */
                found_rule = classifier_find_rule_exactly(cls, rule->cls_rule,
                                                          rule_version);
                if (found_rule && found_rule != rule->cls_rule) {
                    struct cls_match *cls_match;
                    cls_match = get_cls_match_protected(found_rule);

                    assert(found_rule->priority == rule->priority);

                    /* Found rule may not have a lower version. */
                    assert(cls_match->versions.add_version >= rule_version);

                    /* This rule must not be visible in the found rule's
                     * version. */
                    assert(!cls_match_visible_in_version(
                               rule, cls_match->versions.add_version));
                }

                if (rule->priority == prev_priority) {
                    /* Exact duplicate rule may not have a lower version. */
                    assert(rule_version >= prev_version);

                    /* Previous rule must not be visible in rule's version. */
                    assert(!cls_match_visible_in_version(prev, rule_version));
                }

                prev_priority = rule->priority;
                prev_version = rule_version;
                found_rules++;
            }
        }

        if (found_visible_rules) {
            found_tables_with_visible_rules++;
        }

        assert(table->max_priority == max_priority);
        assert(table->max_count == max_count);
    }

    assert(found_tables == cmap_count(&cls->subtables_map));
    assert(found_tables == pvector_count(&cls->subtables));
    assert(n_tables == -1 || n_tables == found_tables_with_visible_rules);
    assert(n_rules == -1 || found_rules == n_rules + found_invisible);
    assert(n_dups == -1 || found_dups == n_dups);
    assert(found_invisible == n_invisible);

    CLS_FOR_EACH (test_rule, cls_rule, cls) {
        found_rules2++;
    }
    /* Iteration does not see removable rules. */
    assert(found_rules
           == found_rules2 + found_visible_but_removable + found_invisible);
}

static struct test_rule *
make_rule(int wc_fields, int priority, int value_pat)
{
    const struct cls_field *f;
    struct test_rule *rule;
    struct match match;

    match_init_catchall(&match);
    for (f = &cls_fields[0]; f < &cls_fields[CLS_N_FIELDS]; f++) {
        int f_idx = f - cls_fields;
        int value_idx = (value_pat & (1u << f_idx)) != 0;
        memcpy((char *) &match.flow + f->ofs,
               values[f_idx][value_idx], f->len);

        if (f_idx == CLS_F_IDX_NW_SRC) {
            match.wc.masks.nw_src = OVS_BE32_MAX;
        } else if (f_idx == CLS_F_IDX_NW_DST) {
            match.wc.masks.nw_dst = OVS_BE32_MAX;
        } else if (f_idx == CLS_F_IDX_TP_SRC) {
            match.wc.masks.tp_src = OVS_BE16_MAX;
        } else if (f_idx == CLS_F_IDX_TP_DST) {
            match.wc.masks.tp_dst = OVS_BE16_MAX;
        } else if (f_idx == CLS_F_IDX_DL_SRC) {
            WC_MASK_FIELD(&match.wc, dl_src);
        } else if (f_idx == CLS_F_IDX_DL_DST) {
            WC_MASK_FIELD(&match.wc, dl_dst);
        } else if (f_idx == CLS_F_IDX_VLAN_TCI) {
            match.wc.masks.vlans[0].tci = OVS_BE16_MAX;
        } else if (f_idx == CLS_F_IDX_TUN_ID) {
            match.wc.masks.tunnel.tun_id = OVS_BE64_MAX;
        } else if (f_idx == CLS_F_IDX_METADATA) {
            match.wc.masks.metadata = OVS_BE64_MAX;
        } else if (f_idx == CLS_F_IDX_NW_DSCP) {
            match.wc.masks.nw_tos |= IP_DSCP_MASK;
        } else if (f_idx == CLS_F_IDX_NW_PROTO) {
            match.wc.masks.nw_proto = UINT8_MAX;
        } else if (f_idx == CLS_F_IDX_DL_TYPE) {
            match.wc.masks.dl_type = OVS_BE16_MAX;
        } else if (f_idx == CLS_F_IDX_IN_PORT) {
            match.wc.masks.in_port.ofp_port = u16_to_ofp(UINT16_MAX);
        } else {
            OVS_NOT_REACHED();
        }
    }

    rule = xzalloc(sizeof *rule);
    cls_rule_init(&rule->cls_rule, &match, wc_fields
                  ? (priority == INT_MIN ? priority + 1 :
                     priority == INT_MAX ? priority - 1 : priority)
                  : 0);
    return rule;
}

static struct test_rule *
clone_rule(const struct test_rule *src)
{
    struct test_rule *dst;

    dst = xmalloc(sizeof *dst);
    dst->aux = src->aux;
    cls_rule_clone(&dst->cls_rule, &src->cls_rule);
    return dst;
}

static void
free_rule(struct test_rule *rule)
{
    cls_rule_destroy(&rule->cls_rule);
    free(rule);
}

static void
shuffle(int *p, size_t n)
{
    for (; n > 1; n--, p++) {
        int *q = &p[random_range(n)];
        int tmp = *p;
        *p = *q;
        *q = tmp;
    }
}

static void
shuffle_u32s(uint32_t *p, size_t n)
{
    for (; n > 1; n--, p++) {
        uint32_t *q = &p[random_range(n)];
        uint32_t tmp = *p;
        *p = *q;
        *q = tmp;
    }
}

/* Classifier tests. */

static enum mf_field_id trie_fields[2] = {
    MFF_IPV4_DST, MFF_IPV4_SRC
};

static void
set_prefix_fields(struct classifier *cls)
{
    verify_tries(cls);
    classifier_set_prefix_fields(cls, trie_fields, ARRAY_SIZE(trie_fields));
    verify_tries(cls);
}

/* Tests an empty classifier. */
static void
test_empty(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct classifier cls;
    struct tcls tcls;

    classifier_init(&cls, flow_segment_u64s);
    set_prefix_fields(&cls);
    tcls_init(&tcls);
    assert(classifier_is_empty(&cls));
    assert(tcls_is_empty(&tcls));
    compare_classifiers(&cls, 0, OVS_VERSION_MIN, &tcls);
    classifier_destroy(&cls);
    tcls_destroy(&tcls);
}

/* Destroys a null classifier. */
static void
test_destroy_null(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    classifier_destroy(NULL);
}

/* Tests classification with one rule at a time. */
static void
test_single_rule(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    unsigned int wc_fields;     /* Hilarious. */

    for (wc_fields = 0; wc_fields < (1u << CLS_N_FIELDS); wc_fields++) {
        struct classifier cls;
        struct test_rule *rule, *tcls_rule;
        struct tcls tcls;

        rule = make_rule(wc_fields,
                         hash_bytes(&wc_fields, sizeof wc_fields, 0), 0);
        classifier_init(&cls, flow_segment_u64s);
        set_prefix_fields(&cls);
        tcls_init(&tcls);
        tcls_rule = tcls_insert(&tcls, rule);

        classifier_insert(&cls, &rule->cls_rule, OVS_VERSION_MIN, NULL, 0);
        compare_classifiers(&cls, 0, OVS_VERSION_MIN, &tcls);
        check_tables(&cls, 1, 1, 0, 0, OVS_VERSION_MIN);

        classifier_remove_assert(&cls, &rule->cls_rule);
        tcls_remove(&tcls, tcls_rule);
        assert(classifier_is_empty(&cls));
        assert(tcls_is_empty(&tcls));
        compare_classifiers(&cls, 0, OVS_VERSION_MIN, &tcls);

        ovsrcu_postpone(free_rule, rule);
        classifier_destroy(&cls);
        tcls_destroy(&tcls);
    }
}

/* Tests replacing one rule by another. */
static void
test_rule_replacement(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    unsigned int wc_fields;

    for (wc_fields = 0; wc_fields < (1u << CLS_N_FIELDS); wc_fields++) {
        struct classifier cls;
        struct test_rule *rule1;
        struct test_rule *rule2;
        struct tcls tcls;

        rule1 = make_rule(wc_fields, OFP_DEFAULT_PRIORITY, UINT_MAX);
        rule2 = make_rule(wc_fields, OFP_DEFAULT_PRIORITY, UINT_MAX);
        rule2->aux += 5;
        rule2->aux += 5;

        classifier_init(&cls, flow_segment_u64s);
        set_prefix_fields(&cls);
        tcls_init(&tcls);
        tcls_insert(&tcls, rule1);
        classifier_insert(&cls, &rule1->cls_rule, OVS_VERSION_MIN, NULL, 0);
        compare_classifiers(&cls, 0, OVS_VERSION_MIN, &tcls);
        check_tables(&cls, 1, 1, 0, 0, OVS_VERSION_MIN);
        tcls_destroy(&tcls);

        tcls_init(&tcls);
        tcls_insert(&tcls, rule2);

        assert(test_rule_from_cls_rule(
                   classifier_replace(&cls, &rule2->cls_rule, OVS_VERSION_MIN,
                                      NULL, 0)) == rule1);
        ovsrcu_postpone(free_rule, rule1);
        compare_classifiers(&cls, 0, OVS_VERSION_MIN, &tcls);
        check_tables(&cls, 1, 1, 0, 0, OVS_VERSION_MIN);
        classifier_defer(&cls);
        classifier_remove_assert(&cls, &rule2->cls_rule);

        tcls_destroy(&tcls);
        destroy_classifier(&cls);
    }
}

static int
factorial(int n_items)
{
    int n, i;

    n = 1;
    for (i = 2; i <= n_items; i++) {
        n *= i;
    }
    return n;
}

static void
swap(int *a, int *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

static void
reverse(int *a, int n)
{
    int i;

    for (i = 0; i < n / 2; i++) {
        int j = n - (i + 1);
        swap(&a[i], &a[j]);
    }
}

static bool
next_permutation(int *a, int n)
{
    int k;

    for (k = n - 2; k >= 0; k--) {
        if (a[k] < a[k + 1]) {
            int l;

            for (l = n - 1; ; l--) {
                if (a[l] > a[k]) {
                    swap(&a[k], &a[l]);
                    reverse(a + (k + 1), n - (k + 1));
                    return true;
                }
            }
        }
    }
    return false;
}

/* Tests classification with rules that have the same matching criteria. */
static void
test_many_rules_in_one_list (struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    enum { N_RULES = 3 };
    int n_pris;

    for (n_pris = N_RULES; n_pris >= 1; n_pris--) {
        int ops[N_RULES * 2];
        int pris[N_RULES];
        int n_permutations;
        int i;

        pris[0] = 0;
        for (i = 1; i < N_RULES; i++) {
            pris[i] = pris[i - 1] + (n_pris > i);
        }

        for (i = 0; i < N_RULES * 2; i++) {
            ops[i] = i / 2;
        }

        n_permutations = 0;
        do {
            struct test_rule *rules[N_RULES];
            struct test_rule *tcls_rules[N_RULES];
            int pri_rules[N_RULES];
            struct classifier cls;
            struct tcls tcls;
            ovs_version_t version = OVS_VERSION_MIN;
            size_t n_invisible_rules = 0;

            n_permutations++;

            for (i = 0; i < N_RULES; i++) {
                rules[i] = make_rule(456, pris[i], 0);
                tcls_rules[i] = NULL;
                pri_rules[i] = -1;
            }

            classifier_init(&cls, flow_segment_u64s);
            set_prefix_fields(&cls);
            tcls_init(&tcls);

            for (i = 0; i < ARRAY_SIZE(ops); i++) {
                struct test_rule *displaced_rule = NULL;
                struct cls_rule *removable_rule = NULL;
                int j = ops[i];
                int m, n;

                if (!tcls_rules[j]) {
                    tcls_rules[j] = tcls_insert(&tcls, rules[j]);
                    if (versioned) {
                        /* Insert the new rule in the next version. */
                        ++version;

                        displaced_rule = test_rule_from_cls_rule(
                            classifier_find_rule_exactly(&cls,
                                                         &rules[j]->cls_rule,
                                                         version));
                        if (displaced_rule) {
                            /* Mark the old rule for removal after the current
                             * version. */
                            cls_rule_make_invisible_in_version(
                                &displaced_rule->cls_rule, version);
                            n_invisible_rules++;
                            removable_rule = &displaced_rule->cls_rule;
                        }
                        classifier_insert(&cls, &rules[j]->cls_rule, version,
                                          NULL, 0);
                    } else {
                        displaced_rule = test_rule_from_cls_rule(
                            classifier_replace(&cls, &rules[j]->cls_rule,
                                               version, NULL, 0));
                    }
                    if (pri_rules[pris[j]] >= 0) {
                        int k = pri_rules[pris[j]];
                        assert(displaced_rule != NULL);
                        assert(displaced_rule != rules[j]);
                        assert(pris[j] == displaced_rule->cls_rule.priority);
                        tcls_rules[k] = NULL;
                    } else {
                        assert(displaced_rule == NULL);
                    }
                    pri_rules[pris[j]] = j;
                } else {
                    if (versioned) {
                        /* Mark the rule for removal after the current
                         * version. */
                        ++version;
                        cls_rule_make_invisible_in_version(
                            &rules[j]->cls_rule, version);
                        n_invisible_rules++;
                        removable_rule = &rules[j]->cls_rule;
                    } else {
                        classifier_remove_assert(&cls, &rules[j]->cls_rule);
                    }
                    tcls_remove(&tcls, tcls_rules[j]);
                    tcls_rules[j] = NULL;
                    pri_rules[pris[j]] = -1;
                }
                compare_classifiers(&cls, n_invisible_rules, version, &tcls);
                n = 0;
                for (m = 0; m < N_RULES; m++) {
                    n += tcls_rules[m] != NULL;
                }
                check_tables(&cls, n > 0, n, n - 1, n_invisible_rules,
                             version);

                if (versioned && removable_rule) {
                    struct cls_match *cls_match =
                        get_cls_match_protected(removable_rule);

                    /* Removable rule is no longer visible. */
                    assert(cls_match);
                    assert(!cls_match_visible_in_version(cls_match, version));
                    classifier_remove_assert(&cls, removable_rule);
                    n_invisible_rules--;
                }
            }

            classifier_defer(&cls);
            for (i = 0; i < N_RULES; i++) {
                if (classifier_remove(&cls, &rules[i]->cls_rule)) {
                    ovsrcu_postpone(free_rule, rules[i]);
                }
            }
            classifier_destroy(&cls);
            tcls_destroy(&tcls);
        } while (next_permutation(ops, ARRAY_SIZE(ops)));
        assert(n_permutations == (factorial(N_RULES * 2) >> N_RULES));
    }
}

static int
count_ones(unsigned long int x)
{
    int n = 0;

    while (x) {
        x = zero_rightmost_1bit(x);
        n++;
    }

    return n;
}

static bool
array_contains(int *array, int n, int value)
{
    int i;

    for (i = 0; i < n; i++) {
        if (array[i] == value) {
            return true;
        }
    }

    return false;
}

/* Tests classification with two rules at a time that fall into the same
 * table but different lists. */
static void
test_many_rules_in_one_table(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int iteration;

    for (iteration = 0; iteration < 50; iteration++) {
        enum { N_RULES = 20 };
        struct test_rule *rules[N_RULES];
        struct test_rule *tcls_rules[N_RULES];
        struct classifier cls;
        struct tcls tcls;
        ovs_version_t version = OVS_VERSION_MIN;
        size_t n_invisible_rules = 0;
        int value_pats[N_RULES];
        int value_mask;
        int wcf;
        int i;

        do {
            wcf = random_uint32() & ((1u << CLS_N_FIELDS) - 1);
            value_mask = ~wcf & ((1u << CLS_N_FIELDS) - 1);
        } while ((1 << count_ones(value_mask)) < N_RULES);

        classifier_init(&cls, flow_segment_u64s);
        set_prefix_fields(&cls);
        tcls_init(&tcls);

        for (i = 0; i < N_RULES; i++) {
            int priority = random_range(INT_MAX);

            do {
                value_pats[i] = random_uint32() & value_mask;
            } while (array_contains(value_pats, i, value_pats[i]));

            ++version;
            rules[i] = make_rule(wcf, priority, value_pats[i]);
            tcls_rules[i] = tcls_insert(&tcls, rules[i]);

            classifier_insert(&cls, &rules[i]->cls_rule, version, NULL, 0);
            compare_classifiers(&cls, n_invisible_rules, version, &tcls);

            check_tables(&cls, 1, i + 1, 0, n_invisible_rules, version);
        }

        for (i = 0; i < N_RULES; i++) {
            tcls_remove(&tcls, tcls_rules[i]);
            if (versioned) {
                /* Mark the rule for removal after the current version. */
                ++version;
                cls_rule_make_invisible_in_version(&rules[i]->cls_rule,
                                                   version);
                n_invisible_rules++;
            } else {
                classifier_remove_assert(&cls, &rules[i]->cls_rule);
            }
            compare_classifiers(&cls, n_invisible_rules, version, &tcls);
            check_tables(&cls, i < N_RULES - 1, N_RULES - (i + 1), 0,
                         n_invisible_rules, version);
            if (!versioned) {
                ovsrcu_postpone(free_rule, rules[i]);
            }
        }

        if (versioned) {
            for (i = 0; i < N_RULES; i++) {
                classifier_remove_assert(&cls, &rules[i]->cls_rule);
                n_invisible_rules--;

                compare_classifiers(&cls, n_invisible_rules, version, &tcls);
                check_tables(&cls, 0, 0, 0, n_invisible_rules, version);
                ovsrcu_postpone(free_rule, rules[i]);
            }
        }

        classifier_destroy(&cls);
        tcls_destroy(&tcls);
    }
}

/* Tests classification with many rules at a time that fall into random lists
 * in 'n' tables. */
static void
test_many_rules_in_n_tables(int n_tables)
{
    enum { MAX_RULES = 50 };
    int wcfs[10];
    int iteration;
    int i;

    assert(n_tables < 10);
    for (i = 0; i < n_tables; i++) {
        do {
            wcfs[i] = random_uint32() & ((1u << CLS_N_FIELDS) - 1);
        } while (array_contains(wcfs, i, wcfs[i]));
    }

    for (iteration = 0; iteration < 30; iteration++) {
        int priorities[MAX_RULES];
        struct classifier cls;
        struct tcls tcls;
        ovs_version_t version = OVS_VERSION_MIN;
        size_t n_invisible_rules = 0;
        struct ovs_list list = OVS_LIST_INITIALIZER(&list);

        random_set_seed(iteration + 1);
        for (i = 0; i < MAX_RULES; i++) {
            priorities[i] = (i * 129) & INT_MAX;
        }
        shuffle(priorities, ARRAY_SIZE(priorities));

        classifier_init(&cls, flow_segment_u64s);
        set_prefix_fields(&cls);
        tcls_init(&tcls);

        for (i = 0; i < MAX_RULES; i++) {
            struct test_rule *rule;
            int priority = priorities[i];
            int wcf = wcfs[random_range(n_tables)];
            int value_pat = random_uint32() & ((1u << CLS_N_FIELDS) - 1);
            rule = make_rule(wcf, priority, value_pat);
            tcls_insert(&tcls, rule);
            classifier_insert(&cls, &rule->cls_rule, version, NULL, 0);
            compare_classifiers(&cls, n_invisible_rules, version, &tcls);
            check_tables(&cls, -1, i + 1, -1, n_invisible_rules, version);
        }

        while (classifier_count(&cls) - n_invisible_rules > 0) {
            struct test_rule *target;
            struct test_rule *rule;
            size_t n_removable_rules = 0;

            target = clone_rule(tcls.rules[random_range(tcls.n_rules)]);

            CLS_FOR_EACH_TARGET (rule, cls_rule, &cls, &target->cls_rule,
                                 version) {
                if (versioned) {
                    /* Mark the rule for removal after the current version. */
                    cls_rule_make_invisible_in_version(&rule->cls_rule,
                                                       version + 1);
                    n_removable_rules++;
                    compare_classifiers(&cls, n_invisible_rules, version,
                                        &tcls);
                    check_tables(&cls, -1, -1, -1, n_invisible_rules, version);

                    ovs_list_push_back(&list, &rule->list_node);
                } else if (classifier_remove(&cls, &rule->cls_rule)) {
                    ovsrcu_postpone(free_rule, rule);
                }
            }

            ++version;
            n_invisible_rules += n_removable_rules;

            tcls_delete_matches(&tcls, &target->cls_rule);
            free_rule(target);

            compare_classifiers(&cls, n_invisible_rules, version, &tcls);
            check_tables(&cls, -1, -1, -1, n_invisible_rules, version);
        }
        if (versioned) {
            struct test_rule *rule;

            /* Remove rules that are no longer visible. */
            LIST_FOR_EACH_POP (rule, list_node, &list) {
                classifier_remove_assert(&cls, &rule->cls_rule);
                n_invisible_rules--;

                compare_classifiers(&cls, n_invisible_rules, version,
                                    &tcls);
                check_tables(&cls, -1, -1, -1, n_invisible_rules, version);
            }
        }

        destroy_classifier(&cls);
        tcls_destroy(&tcls);
    }
}

static void
test_many_rules_in_two_tables(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_many_rules_in_n_tables(2);
}

static void
test_many_rules_in_five_tables(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_many_rules_in_n_tables(5);
}

/* Classifier benchmarks. */

static int n_rules;             /* Number of rules to insert. */
static int n_priorities;        /* Number of priorities to use. */
static int n_tables;            /* Number of subtables. */
static int n_threads;           /* Number of threads to search and mutate. */
static int n_lookups;           /* Number of lookups each thread performs. */

static void benchmark(bool use_wc);

static int
elapsed(const struct timeval *start)
{
    struct timeval end;

    xgettimeofday(&end);
    return timeval_to_msec(&end) - timeval_to_msec(start);
}

static void
run_benchmarks(struct ovs_cmdl_context *ctx)
{
    if (ctx->argc < 5
        || (ctx->argc > 1 && !strcmp(ctx->argv[1], "--help"))) {
        printf(
            "usage: ovstest %s benchmark <n_rules> <n_priorities> <n_subtables> <n_threads> <n_lookups>\n"
            "\n"
            "where:\n"
            "\n"
            "<n_rules>      - The number of rules to install for lookups.  More rules\n"
            "                 makes misses less likely.\n"
            "<n_priorities> - How many different priorities to use.  Using only 1\n"
            "                 priority will force lookups to continue through all\n"
            "                 subtables.\n"
            "<n_subtables>  - Number of subtables to use.  Normally a classifier has\n"
            "                 rules with different kinds of masks, resulting in\n"
            "                 multiple subtables (one per mask).  However, in some\n"
            "                 special cases a table may consist of only one kind of\n"
            "                 rules, so there will be only one subtable.\n"
            "<n_threads>    - How many lookup threads to use.  Using one thread should\n"
            "                 give less variance accross runs, but classifier\n"
            "                 scaling can be tested with multiple threads.\n"
            "<n_lookups>    - How many lookups each thread should perform.\n"
            "\n", program_name);
        return;
    }

    n_rules = strtol(ctx->argv[1], NULL, 10);
    n_priorities = strtol(ctx->argv[2], NULL, 10);
    n_tables = strtol(ctx->argv[3], NULL, 10);
    n_threads = strtol(ctx->argv[4], NULL, 10);
    n_lookups = strtol(ctx->argv[5], NULL, 10);

    printf("\nBenchmarking with:\n"
           "%d rules with %d priorities in %d tables, "
           "%d threads doing %d lookups each\n",
           n_rules, n_priorities, n_tables, n_threads, n_lookups);

    puts("\nWithout wildcards: \n");
    benchmark(false);
    puts("\nWith wildcards: \n");
    benchmark(true);
}

struct cls_aux {
    const struct classifier *cls;
    size_t n_lookup_flows;
    struct flow *lookup_flows;
    bool use_wc;
    atomic_int hits;
    atomic_int misses;
};

static void *
lookup_classifier(void *aux_)
{
    struct cls_aux *aux = aux_;
    ovs_version_t version = OVS_VERSION_MIN;
    int hits = 0, old_hits;
    int misses = 0, old_misses;
    size_t i;

    random_set_seed(1);

    for (i = 0; i < n_lookups; i++) {
        const struct cls_rule *cr;
        struct flow_wildcards wc;
        unsigned int x;

        x = random_range(aux->n_lookup_flows);

        if (aux->use_wc) {
            flow_wildcards_init_catchall(&wc);
            cr = classifier_lookup(aux->cls, version, &aux->lookup_flows[x],
                                   &wc);
        } else {
            cr = classifier_lookup(aux->cls, version, &aux->lookup_flows[x],
                                   NULL);
        }
        if (cr) {
            hits++;
        } else {
            misses++;
        }
    }
    atomic_add(&aux->hits, hits, &old_hits);
    atomic_add(&aux->misses, misses, &old_misses);
    return NULL;
}

/* Benchmark classification. */
static void
benchmark(bool use_wc)
{
    struct classifier cls;
    ovs_version_t version = OVS_VERSION_MIN;
    struct cls_aux aux;
    int *wcfs = xmalloc(n_tables * sizeof *wcfs);
    int *priorities = xmalloc(n_priorities * sizeof *priorities);
    struct timeval start;
    pthread_t *threads;
    int i;

    fatal_signal_init();

    random_set_seed(1);

    for (i = 0; i < n_tables; i++) {
        do {
            wcfs[i] = random_uint32() & ((1u << CLS_N_FIELDS) - 1);
        } while (array_contains(wcfs, i, wcfs[i]));
    }

    for (i = 0; i < n_priorities; i++) {
        priorities[i] = (i * 129) & INT_MAX;
    }
    shuffle(priorities, n_priorities);

    classifier_init(&cls, flow_segment_u64s);
    set_prefix_fields(&cls);

    /* Create lookup flows. */
    aux.use_wc = use_wc;
    aux.cls = &cls;
    aux.n_lookup_flows = 2 * N_FLOW_VALUES;
    aux.lookup_flows = xzalloc(aux.n_lookup_flows * sizeof *aux.lookup_flows);
    for (i = 0; i < aux.n_lookup_flows; i++) {
        struct flow *flow = &aux.lookup_flows[i];
        unsigned int x;

        x = random_range(N_FLOW_VALUES);
        flow->nw_src = nw_src_values[get_value(&x, N_NW_SRC_VALUES)];
        flow->nw_dst = nw_dst_values[get_value(&x, N_NW_DST_VALUES)];
        flow->tunnel.tun_id = tun_id_values[get_value(&x, N_TUN_ID_VALUES)];
        flow->metadata = metadata_values[get_value(&x, N_METADATA_VALUES)];
        flow->in_port.ofp_port = in_port_values[get_value(&x,
                                                          N_IN_PORT_VALUES)];
        flow->vlans[0].tci = vlan_tci_values[get_value(&x, N_VLAN_TCI_VALUES)];
        flow->dl_type = dl_type_values[get_value(&x, N_DL_TYPE_VALUES)];
        flow->tp_src = tp_src_values[get_value(&x, N_TP_SRC_VALUES)];
        flow->tp_dst = tp_dst_values[get_value(&x, N_TP_DST_VALUES)];
        flow->dl_src = dl_src_values[get_value(&x, N_DL_SRC_VALUES)];
        flow->dl_dst = dl_dst_values[get_value(&x, N_DL_DST_VALUES)];
        flow->nw_proto = nw_proto_values[get_value(&x, N_NW_PROTO_VALUES)];
        flow->nw_tos = nw_dscp_values[get_value(&x, N_NW_DSCP_VALUES)];
    }
    atomic_init(&aux.hits, 0);
    atomic_init(&aux.misses, 0);

    /* Rule insertion. */
    for (i = 0; i < n_rules; i++) {
        struct test_rule *rule;
        const struct cls_rule *old_cr;

        int priority = priorities[random_range(n_priorities)];
        int wcf = wcfs[random_range(n_tables)];
        int value_pat = random_uint32() & ((1u << CLS_N_FIELDS) - 1);

        rule = make_rule(wcf, priority, value_pat);
        old_cr = classifier_find_rule_exactly(&cls, &rule->cls_rule, version);
        if (!old_cr) {
            classifier_insert(&cls, &rule->cls_rule, version, NULL, 0);
        } else {
            free_rule(rule);
        }
    }

    /* Lookup. */
    xgettimeofday(&start);
    threads = xmalloc(n_threads * sizeof *threads);
    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("lookups", lookup_classifier, &aux);
    }
    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    int elapsed_msec = elapsed(&start);

    free(threads);

    int hits, misses;
    atomic_read(&aux.hits, &hits);
    atomic_read(&aux.misses, &misses);
    printf("hits: %d, misses: %d\n", hits, misses);

    printf("classifier lookups:  %5d ms, %"PRId64" lookups/sec\n",
           elapsed_msec,
           (((uint64_t)hits + misses) * 1000) / elapsed_msec);

    destroy_classifier(&cls);
    free(aux.lookup_flows);
    free(priorities);
    free(wcfs);
}

/* Miniflow tests. */

static uint32_t
random_value(void)
{
    static const uint32_t values[] =
        { 0xffffffff, 0xaaaaaaaa, 0x55555555, 0x80000000,
          0x00000001, 0xface0000, 0x00d00d1e, 0xdeadbeef };

    return values[random_range(ARRAY_SIZE(values))];
}

static bool
choose(unsigned int n, unsigned int *idxp)
{
    if (*idxp < n) {
        return true;
    } else {
        *idxp -= n;
        return false;
    }
}

#define FLOW_U32S (FLOW_U64S * 2)

static bool
init_consecutive_values(int n_consecutive, struct flow *flow,
                        unsigned int *idxp)
{
    uint32_t *flow_u32 = (uint32_t *) flow;

    if (choose(FLOW_U32S - n_consecutive + 1, idxp)) {
        int i;

        for (i = 0; i < n_consecutive; i++) {
            flow_u32[*idxp + i] = random_value();
        }
        return true;
    } else {
        return false;
    }
}

static bool
next_random_flow(struct flow *flow, unsigned int idx)
{
    uint32_t *flow_u32 = (uint32_t *) flow;

    memset(flow, 0, sizeof *flow);

    /* Empty flow. */
    if (choose(1, &idx)) {
        return true;
    }

    /* All flows with a small number of consecutive nonzero values. */
    for (int i = 1; i <= 4; i++) {
        if (init_consecutive_values(i, flow, &idx)) {
            return true;
        }
    }

    /* All flows with a large number of consecutive nonzero values. */
    for (int i = FLOW_U32S - 4; i <= FLOW_U32S; i++) {
        if (init_consecutive_values(i, flow, &idx)) {
            return true;
        }
    }

    /* All flows with exactly two nonconsecutive nonzero values. */
    if (choose((FLOW_U32S - 1) * (FLOW_U32S - 2) / 2, &idx)) {
        int ofs1;

        for (ofs1 = 0; ofs1 < FLOW_U32S - 2; ofs1++) {
            int ofs2;

            for (ofs2 = ofs1 + 2; ofs2 < FLOW_U32S; ofs2++) {
                if (choose(1, &idx)) {
                    flow_u32[ofs1] = random_value();
                    flow_u32[ofs2] = random_value();
                    return true;
                }
            }
        }
        OVS_NOT_REACHED();
    }

    /* 16 randomly chosen flows with N >= 3 nonzero values. */
    if (choose(16 * (FLOW_U32S - 4), &idx)) {
        int n = idx / 16 + 3;

        for (int i = 0; i < n; i++) {
            flow_u32[i] = random_value();
        }
        shuffle_u32s(flow_u32, FLOW_U32S);

        return true;
    }

    return false;
}

static void
any_random_flow(struct flow *flow)
{
    static unsigned int max;
    if (!max) {
        while (next_random_flow(flow, max)) {
            max++;
        }
    }

    next_random_flow(flow, random_range(max));
}

static void
toggle_masked_flow_bits(struct flow *flow, const struct flow_wildcards *mask)
{
    const uint32_t *mask_u32 = (const uint32_t *) &mask->masks;
    uint32_t *flow_u32 = (uint32_t *) flow;
    int i;

    for (i = 0; i < FLOW_U32S; i++) {
        if (mask_u32[i] != 0) {
            uint32_t bit;

            do {
                bit = 1u << random_range(32);
            } while (!(bit & mask_u32[i]));
            flow_u32[i] ^= bit;
        }
    }
}

static void
wildcard_extra_bits(struct flow_wildcards *mask)
{
    uint32_t *mask_u32 = (uint32_t *) &mask->masks;
    int i;

    for (i = 0; i < FLOW_U32S; i++) {
        if (mask_u32[i] != 0) {
            uint32_t bit;

            do {
                bit = 1u << random_range(32);
            } while (!(bit & mask_u32[i]));
            mask_u32[i] &= ~bit;
        }
    }
}

/* Returns a copy of 'src'.  The caller must eventually free the returned
 * miniflow with free(). */
static struct miniflow *
miniflow_clone__(const struct miniflow *src)
{
    struct miniflow *dst;
    size_t data_size;

    data_size = miniflow_alloc(&dst, 1, src);
    miniflow_clone(dst, src, data_size / sizeof(uint64_t));
    return dst;
}

/* Returns a hash value for 'flow', given 'basis'. */
static inline uint32_t
miniflow_hash__(const struct miniflow *flow, uint32_t basis)
{
    const uint64_t *p = miniflow_get_values(flow);
    size_t n_values = miniflow_n_values(flow);
    struct flowmap hash_map = FLOWMAP_EMPTY_INITIALIZER;
    uint32_t hash = basis;
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, flow->map) {
        uint64_t value = *p++;

        if (value) {
            hash = hash_add64(hash, value);
            flowmap_set(&hash_map, idx, 1);
        }
    }
    map_t map;
    FLOWMAP_FOR_EACH_MAP (map, hash_map) {
        hash = hash_add64(hash, map);
    }

    return hash_finish(hash, n_values);
}

static void
test_miniflow(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct flow flow;
    unsigned int idx;

    random_set_seed(0xb3faca38);
    for (idx = 0; next_random_flow(&flow, idx); idx++) {
        const uint64_t *flow_u64 = (const uint64_t *) &flow;
        struct miniflow *miniflow, *miniflow2, *miniflow3;
        struct flow flow2, flow3;
        struct flow_wildcards mask;
        struct minimask *minimask;
        int i;

        /* Convert flow to miniflow. */
        miniflow = miniflow_create(&flow);

        /* Check that the flow equals its miniflow. */
        for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
            assert(miniflow_get_vid(miniflow, i) ==
                   vlan_tci_to_vid(flow.vlans[i].tci));
        }
        for (i = 0; i < FLOW_U64S; i++) {
            assert(miniflow_get(miniflow, i) == flow_u64[i]);
        }

        /* Check that the miniflow equals itself. */
        assert(miniflow_equal(miniflow, miniflow));

        /* Convert miniflow back to flow and verify that it's the same. */
        miniflow_expand(miniflow, &flow2);
        assert(flow_equal(&flow, &flow2));

        /* Check that copying a miniflow works properly. */
        miniflow2 = miniflow_clone__(miniflow);
        assert(miniflow_equal(miniflow, miniflow2));
        assert(miniflow_hash__(miniflow, 0) == miniflow_hash__(miniflow2, 0));
        miniflow_expand(miniflow2, &flow3);
        assert(flow_equal(&flow, &flow3));

        /* Check that masked matches work as expected for identical flows and
         * miniflows. */
        do {
            next_random_flow(&mask.masks, 1);
        } while (flow_wildcards_is_catchall(&mask));
        minimask = minimask_create(&mask);
        assert(minimask_is_catchall(minimask)
               == flow_wildcards_is_catchall(&mask));
        assert(miniflow_equal_in_minimask(miniflow, miniflow2, minimask));
        assert(miniflow_equal_flow_in_minimask(miniflow, &flow2, minimask));
        assert(miniflow_hash_in_minimask(miniflow, minimask, 0x12345678) ==
               flow_hash_in_minimask(&flow, minimask, 0x12345678));
        assert(minimask_hash(minimask, 0) ==
               miniflow_hash__(&minimask->masks, 0));

        /* Check that masked matches work as expected for differing flows and
         * miniflows. */
        toggle_masked_flow_bits(&flow2, &mask);
        assert(!miniflow_equal_flow_in_minimask(miniflow, &flow2, minimask));
        miniflow3 = miniflow_create(&flow2);
        assert(!miniflow_equal_in_minimask(miniflow, miniflow3, minimask));

        /* Clean up. */
        free(miniflow);
        free(miniflow2);
        free(miniflow3);
        free(minimask);
    }
}

static void
test_minimask_has_extra(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct flow_wildcards catchall;
    struct minimask *minicatchall;
    struct flow flow;
    unsigned int idx;

    flow_wildcards_init_catchall(&catchall);
    minicatchall = minimask_create(&catchall);
    assert(minimask_is_catchall(minicatchall));

    random_set_seed(0x2ec7905b);
    for (idx = 0; next_random_flow(&flow, idx); idx++) {
        struct flow_wildcards mask;
        struct minimask *minimask;

        mask.masks = flow;
        minimask = minimask_create(&mask);
        assert(!minimask_has_extra(minimask, minimask));
        assert(minimask_has_extra(minicatchall, minimask)
               == !minimask_is_catchall(minimask));
        if (!minimask_is_catchall(minimask)) {
            struct minimask *minimask2;

            wildcard_extra_bits(&mask);
            minimask2 = minimask_create(&mask);
            assert(minimask_has_extra(minimask2, minimask));
            assert(!minimask_has_extra(minimask, minimask2));
            free(minimask2);
        }

        free(minimask);
    }

    free(minicatchall);
}

static void
test_minimask_combine(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct flow_wildcards catchall;
    struct minimask *minicatchall;
    struct flow flow;
    unsigned int idx;

    flow_wildcards_init_catchall(&catchall);
    minicatchall = minimask_create(&catchall);
    assert(minimask_is_catchall(minicatchall));

    random_set_seed(0x181bf0cd);
    for (idx = 0; next_random_flow(&flow, idx); idx++) {
        struct minimask *minimask, *minimask2;
        struct flow_wildcards mask, mask2, combined, combined2;
        struct {
            struct minimask minicombined;
            uint64_t storage[FLOW_U64S];
        } m;
        struct flow flow2;

        mask.masks = flow;
        minimask = minimask_create(&mask);

        minimask_combine(&m.minicombined, minimask, minicatchall, m.storage);
        assert(minimask_is_catchall(&m.minicombined));

        any_random_flow(&flow2);
        mask2.masks = flow2;
        minimask2 = minimask_create(&mask2);

        minimask_combine(&m.minicombined, minimask, minimask2, m.storage);
        flow_wildcards_and(&combined, &mask, &mask2);
        minimask_expand(&m.minicombined, &combined2);
        assert(flow_wildcards_equal(&combined, &combined2));

        free(minimask);
        free(minimask2);
    }

    free(minicatchall);
}


static void help(struct ovs_cmdl_context *ctx);

static const struct ovs_cmdl_command commands[] = {
    /* Classifier tests. */
    {"empty", NULL, 0, 0, test_empty, OVS_RO },
    {"destroy-null", NULL, 0, 0, test_destroy_null, OVS_RO },
    {"single-rule", NULL, 0, 0, test_single_rule, OVS_RO },
    {"rule-replacement", NULL, 0, 0, test_rule_replacement, OVS_RO },
    {"many-rules-in-one-list", NULL, 0, 1, test_many_rules_in_one_list, OVS_RO },
    {"many-rules-in-one-table", NULL, 0, 1, test_many_rules_in_one_table, OVS_RO },
    {"many-rules-in-two-tables", NULL, 0, 0, test_many_rules_in_two_tables, OVS_RO },
    {"many-rules-in-five-tables", NULL, 0, 0, test_many_rules_in_five_tables, OVS_RO },
    {"benchmark", NULL, 0, 5, run_benchmarks, OVS_RO },

    /* Miniflow and minimask tests. */
    {"miniflow", NULL, 0, 0, test_miniflow, OVS_RO },
    {"minimask_has_extra", NULL, 0, 0, test_minimask_has_extra, OVS_RO },
    {"minimask_combine", NULL, 0, 0, test_minimask_combine, OVS_RO },

    {"--help", NULL, 0, 0, help, OVS_RO },
    {NULL, NULL, 0, 0, NULL, OVS_RO },
};

static void
help(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    const struct ovs_cmdl_command *p;
    struct ds test_names = DS_EMPTY_INITIALIZER;
    const int linesize = 80;

    printf("usage: ovstest %s TEST [TESTARGS]\n"
           "where TEST is one of the following:\n\n",
           program_name);

    for (p = commands; p->name != NULL; p++) {
        if (*p->name != '-') { /* Skip internal commands */
            if (test_names.length > 1
                && test_names.length + strlen(p->name) + 1 >= linesize) {
                test_names.length -= 1;
                printf ("%s\n", ds_cstr(&test_names));
                ds_clear(&test_names);
            }
            ds_put_format(&test_names, "%s, ", p->name);
        }
    }
    if (test_names.length > 2) {
        test_names.length -= 2;
        printf("%s\n", ds_cstr(&test_names));
    }
    ds_destroy(&test_names);
}

static void
test_classifier_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - 1,
        .argv = argv + 1,
    };
    set_program_name(argv[0]);

    if (argc > 1 && !strcmp(argv[1], "--versioned")) {
        versioned = true;
        ctx.argc--;
        ctx.argv++;
    }

    init_values();
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-classifier", test_classifier_main);
