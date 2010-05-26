/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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
#include "classifier.h"
#include <errno.h>
#include <limits.h>
#include "command-line.h"
#include "flow.h"
#include "packets.h"

#undef NDEBUG
#include <assert.h>

struct test_rule {
    int aux;                    /* Auxiliary data. */
    struct cls_rule cls_rule;   /* Classifier rule data. */
};

static struct test_rule *
test_rule_from_cls_rule(const struct cls_rule *rule)
{
    return rule ? CONTAINER_OF(rule, struct test_rule, cls_rule) : NULL;
}

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
            free(tcls->rules[i]);
        }
        free(tcls->rules);
    }
}

static int
tcls_count_exact(const struct tcls *tcls)
{
    int n_exact;
    size_t i;

    n_exact = 0;
    for (i = 0; i < tcls->n_rules; i++) {
        n_exact += tcls->rules[i]->cls_rule.wc.wildcards == 0;
    }
    return n_exact;
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

    assert(rule->cls_rule.wc.wildcards || rule->cls_rule.priority == UINT_MAX);
    for (i = 0; i < tcls->n_rules; i++) {
        const struct cls_rule *pos = &tcls->rules[i]->cls_rule;
        if (pos->priority == rule->cls_rule.priority
            && pos->wc.wildcards == rule->cls_rule.wc.wildcards
            && flow_equal(&pos->flow, &rule->cls_rule.flow)) {
            /* Exact match.
             * XXX flow_equal should ignore wildcarded fields */
            free(tcls->rules[i]);
            tcls->rules[i] = xmemdup(rule, sizeof *rule);
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
    tcls->rules[i] = xmemdup(rule, sizeof *rule);
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
            free(pos);
            memmove(&cls->rules[i], &cls->rules[i + 1],
                    sizeof *cls->rules * (cls->n_rules - i - 1));
            cls->n_rules--;
            return;
        }
    }
    NOT_REACHED();
}

static uint32_t
read_uint32(const void *p)
{
    uint32_t x;
    memcpy(&x, p, sizeof x);
    return x;
}

static bool
match(const struct cls_rule *wild, const flow_t *fixed)
{
    int f_idx;

    for (f_idx = 0; f_idx < CLS_N_FIELDS; f_idx++) {
        const struct cls_field *f = &cls_fields[f_idx];
        void *wild_field = (char *) &wild->flow + f->ofs;
        void *fixed_field = (char *) fixed + f->ofs;

        if ((wild->wc.wildcards & f->wildcards) == f->wildcards ||
            !memcmp(wild_field, fixed_field, f->len)) {
            /* Definite match. */
            continue;
        }

        if (wild->wc.wildcards & f->wildcards) {
            uint32_t test = read_uint32(wild_field);
            uint32_t ip = read_uint32(fixed_field);
            int shift = (f_idx == CLS_F_IDX_NW_SRC
                         ? OFPFW_NW_SRC_SHIFT : OFPFW_NW_DST_SHIFT);
            uint32_t mask = flow_nw_bits_to_mask(wild->wc.wildcards, shift);
            if (!((test ^ ip) & mask)) {
                continue;
            }
        }

        return false;
    }
    return true;
}

static struct cls_rule *
tcls_lookup(const struct tcls *cls, const flow_t *flow, int include)
{
    size_t i;

    for (i = 0; i < cls->n_rules; i++) {
        struct test_rule *pos = cls->rules[i];
        uint32_t wildcards = pos->cls_rule.wc.wildcards;
        if (include & (wildcards ? CLS_INC_WILD : CLS_INC_EXACT)
            && match(&pos->cls_rule, flow)) {
            return &pos->cls_rule;
        }
    }
    return NULL;
}

static void
tcls_delete_matches(struct tcls *cls,
                    const struct cls_rule *target,
                    int include)
{
    size_t i;

    for (i = 0; i < cls->n_rules; ) {
        struct test_rule *pos = cls->rules[i];
        uint32_t wildcards = pos->cls_rule.wc.wildcards;
        if (include & (wildcards ? CLS_INC_WILD : CLS_INC_EXACT)
            && match(target, &pos->cls_rule.flow)) {
            tcls_remove(cls, pos);
        } else {
            i++;
        }
    }
}

#ifdef WORDS_BIGENDIAN
#define T_HTONL(VALUE) ((uint32_t) (VALUE))
#define T_HTONS(VALUE) ((uint32_t) (VALUE))
#else
#define T_HTONL(VALUE) (((((uint32_t) (VALUE)) & 0x000000ff) << 24) | \
                      ((((uint32_t) (VALUE)) & 0x0000ff00) <<  8) | \
                      ((((uint32_t) (VALUE)) & 0x00ff0000) >>  8) | \
                      ((((uint32_t) (VALUE)) & 0xff000000) >> 24))
#define T_HTONS(VALUE) (((((uint16_t) (VALUE)) & 0xff00) >> 8) |  \
                      ((((uint16_t) (VALUE)) & 0x00ff) << 8))
#endif

static uint32_t nw_src_values[] = { T_HTONL(0xc0a80001),
                                    T_HTONL(0xc0a04455) };
static uint32_t nw_dst_values[] = { T_HTONL(0xc0a80002),
                                    T_HTONL(0xc0a04455) };
static uint32_t tun_id_values[] = { 0, 0xffff0000 };
static uint16_t in_port_values[] = { T_HTONS(1), T_HTONS(OFPP_LOCAL) };
static uint16_t dl_vlan_values[] = { T_HTONS(101), T_HTONS(0) };
static uint8_t dl_vlan_pcp_values[] = { 7, 0 };
static uint16_t dl_type_values[]
            = { T_HTONS(ETH_TYPE_IP), T_HTONS(ETH_TYPE_ARP) };
static uint16_t tp_src_values[] = { T_HTONS(49362), T_HTONS(80) };
static uint16_t tp_dst_values[] = { T_HTONS(6667), T_HTONS(22) };
static uint8_t dl_src_values[][6] = { { 0x00, 0x02, 0xe3, 0x0f, 0x80, 0xa4 },
                                      { 0x5e, 0x33, 0x7f, 0x5f, 0x1e, 0x99 } };
static uint8_t dl_dst_values[][6] = { { 0x4a, 0x27, 0x71, 0xae, 0x64, 0xc1 },
                                      { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
static uint8_t nw_proto_values[] = { IP_TYPE_TCP, IP_TYPE_ICMP };
static uint8_t nw_tos_values[] = { 49, 0 };

static void *values[CLS_N_FIELDS][2];

static void
init_values(void)
{
    values[CLS_F_IDX_TUN_ID][0] = &tun_id_values[0];
    values[CLS_F_IDX_TUN_ID][1] = &tun_id_values[1];

    values[CLS_F_IDX_IN_PORT][0] = &in_port_values[0];
    values[CLS_F_IDX_IN_PORT][1] = &in_port_values[1];

    values[CLS_F_IDX_DL_VLAN][0] = &dl_vlan_values[0];
    values[CLS_F_IDX_DL_VLAN][1] = &dl_vlan_values[1];

    values[CLS_F_IDX_DL_VLAN_PCP][0] = &dl_vlan_pcp_values[0];
    values[CLS_F_IDX_DL_VLAN_PCP][1] = &dl_vlan_pcp_values[1];

    values[CLS_F_IDX_DL_SRC][0] = dl_src_values[0];
    values[CLS_F_IDX_DL_SRC][1] = dl_src_values[1];

    values[CLS_F_IDX_DL_DST][0] = dl_dst_values[0];
    values[CLS_F_IDX_DL_DST][1] = dl_dst_values[1];

    values[CLS_F_IDX_DL_TYPE][0] = &dl_type_values[0];
    values[CLS_F_IDX_DL_TYPE][1] = &dl_type_values[1];

    values[CLS_F_IDX_NW_SRC][0] = &nw_src_values[0];
    values[CLS_F_IDX_NW_SRC][1] = &nw_src_values[1];

    values[CLS_F_IDX_NW_DST][0] = &nw_dst_values[0];
    values[CLS_F_IDX_NW_DST][1] = &nw_dst_values[1];

    values[CLS_F_IDX_NW_PROTO][0] = &nw_proto_values[0];
    values[CLS_F_IDX_NW_PROTO][1] = &nw_proto_values[1];

    values[CLS_F_IDX_NW_TOS][0] = &nw_tos_values[0];
    values[CLS_F_IDX_NW_TOS][1] = &nw_tos_values[1];

    values[CLS_F_IDX_TP_SRC][0] = &tp_src_values[0];
    values[CLS_F_IDX_TP_SRC][1] = &tp_src_values[1];

    values[CLS_F_IDX_TP_DST][0] = &tp_dst_values[0];
    values[CLS_F_IDX_TP_DST][1] = &tp_dst_values[1];
}

#define N_NW_SRC_VALUES ARRAY_SIZE(nw_src_values)
#define N_NW_DST_VALUES ARRAY_SIZE(nw_dst_values)
#define N_TUN_ID_VALUES ARRAY_SIZE(tun_id_values)
#define N_IN_PORT_VALUES ARRAY_SIZE(in_port_values)
#define N_DL_VLAN_VALUES ARRAY_SIZE(dl_vlan_values)
#define N_DL_VLAN_PCP_VALUES ARRAY_SIZE(dl_vlan_pcp_values)
#define N_DL_TYPE_VALUES ARRAY_SIZE(dl_type_values)
#define N_TP_SRC_VALUES ARRAY_SIZE(tp_src_values)
#define N_TP_DST_VALUES ARRAY_SIZE(tp_dst_values)
#define N_DL_SRC_VALUES ARRAY_SIZE(dl_src_values)
#define N_DL_DST_VALUES ARRAY_SIZE(dl_dst_values)
#define N_NW_PROTO_VALUES ARRAY_SIZE(nw_proto_values)
#define N_NW_TOS_VALUES ARRAY_SIZE(nw_tos_values)

#define N_FLOW_VALUES (N_NW_SRC_VALUES *        \
                       N_NW_DST_VALUES *        \
                       N_TUN_ID_VALUES *        \
                       N_IN_PORT_VALUES *       \
                       N_DL_VLAN_VALUES *       \
                       N_DL_VLAN_PCP_VALUES *   \
                       N_DL_TYPE_VALUES *       \
                       N_TP_SRC_VALUES *        \
                       N_TP_DST_VALUES *        \
                       N_DL_SRC_VALUES *        \
                       N_DL_DST_VALUES *        \
                       N_NW_PROTO_VALUES *      \
                       N_NW_TOS_VALUES)

static unsigned int
get_value(unsigned int *x, unsigned n_values)
{
    unsigned int rem = *x % n_values;
    *x /= n_values;
    return rem;
}

static struct cls_rule *
lookup_with_include_bits(const struct classifier *cls,
                         const flow_t *flow, int include)
{
    switch (include) {
    case CLS_INC_WILD:
        return classifier_lookup_wild(cls, flow);
    case CLS_INC_EXACT:
        return classifier_lookup_exact(cls, flow);
    case CLS_INC_WILD | CLS_INC_EXACT:
        return classifier_lookup(cls, flow);
    default:
        abort();
    }
}

static void
compare_classifiers(struct classifier *cls, struct tcls *tcls)
{
    static const int confidence = 500;
    unsigned int i;

    assert(classifier_count(cls) == tcls->n_rules);
    assert(classifier_count_exact(cls) == tcls_count_exact(tcls));
    for (i = 0; i < confidence; i++) {
        struct cls_rule *cr0, *cr1;
        flow_t flow;
        unsigned int x;
        int include;

        x = rand () % N_FLOW_VALUES;
        flow.nw_src = nw_src_values[get_value(&x, N_NW_SRC_VALUES)];
        flow.nw_dst = nw_dst_values[get_value(&x, N_NW_DST_VALUES)];
        flow.tun_id = tun_id_values[get_value(&x, N_TUN_ID_VALUES)];
        flow.in_port = in_port_values[get_value(&x, N_IN_PORT_VALUES)];
        flow.dl_vlan = dl_vlan_values[get_value(&x, N_DL_VLAN_VALUES)];
        flow.dl_vlan_pcp = dl_vlan_pcp_values[get_value(&x,
                N_DL_VLAN_PCP_VALUES)];
        flow.dl_type = dl_type_values[get_value(&x, N_DL_TYPE_VALUES)];
        flow.tp_src = tp_src_values[get_value(&x, N_TP_SRC_VALUES)];
        flow.tp_dst = tp_dst_values[get_value(&x, N_TP_DST_VALUES)];
        memcpy(flow.dl_src, dl_src_values[get_value(&x, N_DL_SRC_VALUES)],
               ETH_ADDR_LEN);
        memcpy(flow.dl_dst, dl_dst_values[get_value(&x, N_DL_DST_VALUES)],
               ETH_ADDR_LEN);
        flow.nw_proto = nw_proto_values[get_value(&x, N_NW_PROTO_VALUES)];
        flow.nw_tos = nw_tos_values[get_value(&x, N_NW_TOS_VALUES)];
        memset(flow.reserved, 0, sizeof flow.reserved);

        for (include = 1; include <= 3; include++) {
            cr0 = lookup_with_include_bits(cls, &flow, include);
            cr1 = tcls_lookup(tcls, &flow, include);
            assert((cr0 == NULL) == (cr1 == NULL));
            if (cr0 != NULL) {
                const struct test_rule *tr0 = test_rule_from_cls_rule(cr0);
                const struct test_rule *tr1 = test_rule_from_cls_rule(cr1);

                assert(flow_equal(&cr0->flow, &cr1->flow));
                assert(cr0->wc.wildcards == cr1->wc.wildcards);
                assert(cr0->priority == cr1->priority);
                /* Skip nw_src_mask and nw_dst_mask, because they are derived
                 * members whose values are used only for optimization. */
                assert(tr0->aux == tr1->aux);
            }
        }
    }
}

static void
free_rule(struct cls_rule *cls_rule, void *cls)
{
    classifier_remove(cls, cls_rule);
    free(test_rule_from_cls_rule(cls_rule));
}

static void
destroy_classifier(struct classifier *cls)
{
    classifier_for_each(cls, CLS_INC_ALL, free_rule, cls);
    classifier_destroy(cls);
}

static void
check_tables(const struct classifier *cls,
             int n_tables, int n_buckets, int n_rules)
{
    int found_tables = 0;
    int found_buckets = 0;
    int found_rules = 0;
    int i;

    BUILD_ASSERT(CLS_N_FIELDS == ARRAY_SIZE(cls->tables));
    for (i = 0; i < CLS_N_FIELDS; i++) {
        const struct cls_bucket *bucket;
        if (!hmap_is_empty(&cls->tables[i])) {
            found_tables++;
        }
        HMAP_FOR_EACH (bucket, struct cls_bucket, hmap_node, &cls->tables[i]) {
            found_buckets++;
            assert(!list_is_empty(&bucket->rules));
            found_rules += list_size(&bucket->rules);
        }
    }

    if (!hmap_is_empty(&cls->exact_table)) {
        found_tables++;
        found_buckets++;
        found_rules += hmap_count(&cls->exact_table);
    }

    assert(n_tables == -1 || found_tables == n_tables);
    assert(n_rules == -1 || found_rules == n_rules);
    assert(n_buckets == -1 || found_buckets == n_buckets);
}

static struct test_rule *
make_rule(int wc_fields, unsigned int priority, int value_pat)
{
    const struct cls_field *f;
    struct test_rule *rule;
    uint32_t wildcards;
    flow_t flow;

    wildcards = 0;
    memset(&flow, 0, sizeof flow);
    for (f = &cls_fields[0]; f < &cls_fields[CLS_N_FIELDS]; f++) {
        int f_idx = f - cls_fields;
        if (wc_fields & (1u << f_idx)) {
            wildcards |= f->wildcards;
        } else {
            int value_idx = (value_pat & (1u << f_idx)) != 0;
            memcpy((char *) &flow + f->ofs, values[f_idx][value_idx], f->len);
        }
    }

    rule = xzalloc(sizeof *rule);
    cls_rule_from_flow(&flow, wildcards, !wildcards ? UINT_MAX : priority,
                       &rule->cls_rule);
    return rule;
}

static void
shuffle(unsigned int *p, size_t n)
{
    for (; n > 1; n--, p++) {
        unsigned int *q = &p[rand() % n];
        unsigned int tmp = *p;
        *p = *q;
        *q = tmp;
    }
}

/* Tests an empty classifier. */
static void
test_empty(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct classifier cls;
    struct tcls tcls;

    classifier_init(&cls);
    tcls_init(&tcls);
    assert(classifier_is_empty(&cls));
    assert(tcls_is_empty(&tcls));
    compare_classifiers(&cls, &tcls);
    classifier_destroy(&cls);
    tcls_destroy(&tcls);
}

/* Destroys a null classifier. */
static void
test_destroy_null(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    classifier_destroy(NULL);
}

/* Tests classification with one rule at a time. */
static void
test_single_rule(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned int wc_fields;     /* Hilarious. */

    for (wc_fields = 0; wc_fields < (1u << CLS_N_FIELDS); wc_fields++) {
        struct classifier cls;
        struct test_rule *rule, *tcls_rule;
        struct tcls tcls;

        rule = make_rule(wc_fields,
                         hash_bytes(&wc_fields, sizeof wc_fields, 0), 0);

        classifier_init(&cls);
        tcls_init(&tcls);

        tcls_rule = tcls_insert(&tcls, rule);
        if (wc_fields) {
            assert(!classifier_insert(&cls, &rule->cls_rule));
        } else {
            classifier_insert_exact(&cls, &rule->cls_rule);
        }
        check_tables(&cls, 1, 1, 1);
        compare_classifiers(&cls, &tcls);

        classifier_remove(&cls, &rule->cls_rule);
        tcls_remove(&tcls, tcls_rule);
        assert(classifier_is_empty(&cls));
        assert(tcls_is_empty(&tcls));
        compare_classifiers(&cls, &tcls);

        free(rule);
        classifier_destroy(&cls);
        tcls_destroy(&tcls);
    }
}

/* Tests replacing one rule by another. */
static void
test_rule_replacement(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
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

        classifier_init(&cls);
        tcls_init(&tcls);
        tcls_insert(&tcls, rule1);
        assert(!classifier_insert(&cls, &rule1->cls_rule));
        check_tables(&cls, 1, 1, 1);
        compare_classifiers(&cls, &tcls);
        tcls_destroy(&tcls);

        tcls_init(&tcls);
        tcls_insert(&tcls, rule2);
        assert(test_rule_from_cls_rule(
                   classifier_insert(&cls, &rule2->cls_rule)) == rule1);
        free(rule1);
        check_tables(&cls, 1, 1, 1);
        compare_classifiers(&cls, &tcls);
        tcls_destroy(&tcls);
        destroy_classifier(&cls);
    }
}

static int
table_mask(int table)
{
    return ((1u << CLS_N_FIELDS) - 1) & ~((1u << table) - 1);
}

static int
random_wcf_in_table(int table, int seed)
{
    int wc_fields = (1u << table) | hash_int(seed, 0);
    return wc_fields & table_mask(table);
}

/* Tests classification with two rules at a time that fall into the same
 * bucket. */
static void
test_two_rules_in_one_bucket(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    int table, rel_pri, wcf_pat, value_pat;

    for (table = 0; table <= CLS_N_FIELDS; table++) {
        for (rel_pri = -1; rel_pri <= +1; rel_pri++) {
            for (wcf_pat = 0; wcf_pat < 4; wcf_pat++) {
                int n_value_pats = table == CLS_N_FIELDS - 1 ? 1 : 2;
                for (value_pat = 0; value_pat < n_value_pats; value_pat++) {
                    struct test_rule *rule1, *tcls_rule1;
                    struct test_rule *rule2, *tcls_rule2;
                    struct test_rule *displaced_rule;
                    struct classifier cls;
                    struct tcls tcls;
                    unsigned int pri1, pri2;
                    int wcf1, wcf2;

                    if (table != CLS_F_IDX_EXACT) {
                        /* We can use identical priorities in this test because
                         * the classifier always chooses the rule added later
                         * for equal-priority rules that fall into the same
                         * bucket.  */
                        pri1 = table * 257 + 50;
                        pri2 = pri1 + rel_pri;

                        wcf1 = (wcf_pat & 1
                                ? random_wcf_in_table(table, pri1)
                                : 1u << table);
                        wcf2 = (wcf_pat & 2
                                ? random_wcf_in_table(table, pri2)
                                : 1u << table);
                        if (value_pat) {
                            wcf1 &= ~(1u << (CLS_N_FIELDS - 1));
                            wcf2 &= ~(1u << (CLS_N_FIELDS - 1));
                        }
                    } else {
                        /* This classifier always puts exact-match rules at
                         * maximum priority.  */
                        pri1 = pri2 = UINT_MAX;

                        /* No wildcard fields. */
                        wcf1 = wcf2 = 0;
                    }

                    rule1 = make_rule(wcf1, pri1, 0);
                    rule2 = make_rule(wcf2, pri2,
                                      value_pat << (CLS_N_FIELDS - 1));

                    classifier_init(&cls);
                    tcls_init(&tcls);

                    tcls_rule1 = tcls_insert(&tcls, rule1);
                    tcls_rule2 = tcls_insert(&tcls, rule2);
                    assert(!classifier_insert(&cls, &rule1->cls_rule));
                    displaced_rule = test_rule_from_cls_rule(
                        classifier_insert(&cls, &rule2->cls_rule));
                    if (wcf1 != wcf2 || pri1 != pri2 || value_pat) {
                        assert(!displaced_rule);

                        check_tables(&cls, 1, 1, 2);
                        compare_classifiers(&cls, &tcls);

                        classifier_remove(&cls, &rule1->cls_rule);
                        tcls_remove(&tcls, tcls_rule1);
                        check_tables(&cls, 1, 1, 1);
                        compare_classifiers(&cls, &tcls);
                    } else {
                        assert(displaced_rule == rule1);
                        check_tables(&cls, 1, 1, 1);
                        compare_classifiers(&cls, &tcls);
                    }
                    free(rule1);

                    classifier_remove(&cls, &rule2->cls_rule);
                    tcls_remove(&tcls, tcls_rule2);
                    compare_classifiers(&cls, &tcls);
                    free(rule2);

                    destroy_classifier(&cls);
                    tcls_destroy(&tcls);
                }
            }
        }
    }
}

/* Tests classification with two rules at a time that fall into the same
 * table but different buckets. */
static void
test_two_rules_in_one_table(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    int table, rel_pri, wcf_pat;

    /* Skip tables 0 and CLS_F_IDX_EXACT because they have one bucket. */
    for (table = 1; table < CLS_N_FIELDS; table++) {
        for (rel_pri = -1; rel_pri <= +1; rel_pri++) {
            for (wcf_pat = 0; wcf_pat < 5; wcf_pat++) {
                struct test_rule *rule1, *tcls_rule1;
                struct test_rule *rule2, *tcls_rule2;
                struct classifier cls;
                struct tcls tcls;
                unsigned int pri1, pri2;
                int wcf1, wcf2;
                int value_mask, value_pat1, value_pat2;
                int i;

                /* We can use identical priorities in this test because the
                 * classifier always chooses the rule added later for
                 * equal-priority rules that fall into the same table.  */
                pri1 = table * 257 + 50;
                pri2 = pri1 + rel_pri;

                if (wcf_pat & 4) {
                    wcf1 = wcf2 = random_wcf_in_table(table, pri1);
                } else {
                    wcf1 = (wcf_pat & 1
                            ? random_wcf_in_table(table, pri1)
                            : 1u << table);
                    wcf2 = (wcf_pat & 2
                            ? random_wcf_in_table(table, pri2)
                            : 1u << table);
                }

                /* Generate value patterns that will put the two rules into
                 * different buckets. */
                value_mask = ((1u << table) - 1);
                value_pat1 = hash_int(pri1, 1) & value_mask;
                i = 0;
                do {
                    value_pat2 = (hash_int(pri2, i++) & value_mask);
                } while (value_pat1 == value_pat2);
                rule1 = make_rule(wcf1, pri1, value_pat1);
                rule2 = make_rule(wcf2, pri2, value_pat2);

                classifier_init(&cls);
                tcls_init(&tcls);

                tcls_rule1 = tcls_insert(&tcls, rule1);
                tcls_rule2 = tcls_insert(&tcls, rule2);
                assert(!classifier_insert(&cls, &rule1->cls_rule));
                assert(!classifier_insert(&cls, &rule2->cls_rule));
                check_tables(&cls, 1, 2, 2);
                compare_classifiers(&cls, &tcls);

                classifier_remove(&cls, &rule1->cls_rule);
                tcls_remove(&tcls, tcls_rule1);
                check_tables(&cls, 1, 1, 1);
                compare_classifiers(&cls, &tcls);
                free(rule1);

                classifier_remove(&cls, &rule2->cls_rule);
                tcls_remove(&tcls, tcls_rule2);
                compare_classifiers(&cls, &tcls);
                free(rule2);

                classifier_destroy(&cls);
                tcls_destroy(&tcls);
            }
        }
    }
}

/* Tests classification with two rules at a time that fall into different
 * tables. */
static void
test_two_rules_in_different_tables(int argc OVS_UNUSED,
                                   char *argv[] OVS_UNUSED)
{
    int table1, table2, rel_pri, wcf_pat;

    for (table1 = 0; table1 < CLS_N_FIELDS; table1++) {
        for (table2 = table1 + 1; table2 <= CLS_N_FIELDS; table2++) {
            for (rel_pri = 0; rel_pri < 2; rel_pri++) {
                for (wcf_pat = 0; wcf_pat < 4; wcf_pat++) {
                    struct test_rule *rule1, *tcls_rule1;
                    struct test_rule *rule2, *tcls_rule2;
                    struct classifier cls;
                    struct tcls tcls;
                    unsigned int pri1, pri2;
                    int wcf1, wcf2;

                    /* We must use unique priorities in this test because the
                     * classifier makes the rule choice undefined for rules of
                     * equal priority that fall into different tables.  (In
                     * practice, lower-numbered tables win.)  */
                    pri1 = table1 * 257 + 50;
                    pri2 = rel_pri ? pri1 - 1 : pri1 + 1;

                    wcf1 = (wcf_pat & 1
                            ? random_wcf_in_table(table1, pri1)
                            : 1u << table1);
                    wcf2 = (wcf_pat & 2
                            ? random_wcf_in_table(table2, pri2)
                            : 1u << table2);

                    if (table2 == CLS_F_IDX_EXACT) {
                        pri2 = UINT16_MAX;
                        wcf2 = 0;
                    }

                    rule1 = make_rule(wcf1, pri1, 0);
                    rule2 = make_rule(wcf2, pri2, 0);

                    classifier_init(&cls);
                    tcls_init(&tcls);

                    tcls_rule1 = tcls_insert(&tcls, rule1);
                    tcls_rule2 = tcls_insert(&tcls, rule2);
                    assert(!classifier_insert(&cls, &rule1->cls_rule));
                    assert(!classifier_insert(&cls, &rule2->cls_rule));
                    check_tables(&cls, 2, 2, 2);
                    compare_classifiers(&cls, &tcls);

                    classifier_remove(&cls, &rule1->cls_rule);
                    tcls_remove(&tcls, tcls_rule1);
                    check_tables(&cls, 1, 1, 1);
                    compare_classifiers(&cls, &tcls);
                    free(rule1);

                    classifier_remove(&cls, &rule2->cls_rule);
                    tcls_remove(&tcls, tcls_rule2);
                    compare_classifiers(&cls, &tcls);
                    free(rule2);

                    classifier_destroy(&cls);
                    tcls_destroy(&tcls);
                }
            }
        }
    }
}

/* Tests classification with many rules at a time that fall into the same
 * bucket but have unique priorities (and various wildcards). */
static void
test_many_rules_in_one_bucket(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum { MAX_RULES = 50 };
    int iteration, table;

    for (iteration = 0; iteration < 3; iteration++) {
        for (table = 0; table <= CLS_N_FIELDS; table++) {
            unsigned int priorities[MAX_RULES];
            struct classifier cls;
            struct tcls tcls;
            int i;

            srand(hash_int(table, iteration));
            for (i = 0; i < MAX_RULES; i++) {
                priorities[i] = i * 129;
            }
            shuffle(priorities, ARRAY_SIZE(priorities));

            classifier_init(&cls);
            tcls_init(&tcls);

            for (i = 0; i < MAX_RULES; i++) {
                struct test_rule *rule;
                unsigned int priority = priorities[i];
                int wcf;

                wcf = random_wcf_in_table(table, priority);
                rule = make_rule(wcf, priority,
                                 table == CLS_F_IDX_EXACT ? i : 1234);
                tcls_insert(&tcls, rule);
                assert(!classifier_insert(&cls, &rule->cls_rule));
                check_tables(&cls, 1, 1, i + 1);
                compare_classifiers(&cls, &tcls);
            }

            destroy_classifier(&cls);
            tcls_destroy(&tcls);
        }
    }
}

/* Tests classification with many rules at a time that fall into the same
 * table but random buckets. */
static void
test_many_rules_in_one_table(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum { MAX_RULES = 50 };
    int iteration, table;

    for (iteration = 0; iteration < 3; iteration++) {
        for (table = 0; table < CLS_N_FIELDS; table++) {
            unsigned int priorities[MAX_RULES];
            struct classifier cls;
            struct tcls tcls;
            int i;

            srand(hash_int(table, iteration));
            for (i = 0; i < MAX_RULES; i++) {
                priorities[i] = i * 129;
            }
            shuffle(priorities, ARRAY_SIZE(priorities));

            classifier_init(&cls);
            tcls_init(&tcls);

            for (i = 0; i < MAX_RULES; i++) {
                struct test_rule *rule;
                unsigned int priority = priorities[i];
                int wcf;

                wcf = random_wcf_in_table(table, priority);
                rule = make_rule(wcf, priority, hash_int(priority, 1));
                tcls_insert(&tcls, rule);
                assert(!classifier_insert(&cls, &rule->cls_rule));
                check_tables(&cls, 1, -1, i + 1);
                compare_classifiers(&cls, &tcls);
            }

            destroy_classifier(&cls);
            tcls_destroy(&tcls);
        }
    }
}

/* Tests classification with many rules at a time that fall into random buckets
 * in random tables. */
static void
test_many_rules_in_different_tables(int argc OVS_UNUSED,
                                    char *argv[] OVS_UNUSED)
{
    enum { MAX_RULES = 50 };
    int iteration;

    for (iteration = 0; iteration < 30; iteration++) {
        unsigned int priorities[MAX_RULES];
        struct classifier cls;
        struct tcls tcls;
        int i;

        srand(iteration);
        for (i = 0; i < MAX_RULES; i++) {
            priorities[i] = i * 129;
        }
        shuffle(priorities, ARRAY_SIZE(priorities));

        classifier_init(&cls);
        tcls_init(&tcls);

        for (i = 0; i < MAX_RULES; i++) {
            struct test_rule *rule;
            unsigned int priority = priorities[i];
            int table = rand() % (CLS_N_FIELDS + 1);
            int wcf = random_wcf_in_table(table, rand());
            int value_pat = rand() & ((1u << CLS_N_FIELDS) - 1);
            rule = make_rule(wcf, priority, value_pat);
            tcls_insert(&tcls, rule);
            assert(!classifier_insert(&cls, &rule->cls_rule));
            check_tables(&cls, -1, -1, i + 1);
            compare_classifiers(&cls, &tcls);
        }

        while (!classifier_is_empty(&cls)) {
            struct test_rule *rule = xmemdup(tcls.rules[rand() % tcls.n_rules],
                                             sizeof(struct test_rule));
            int include = rand() % 2 ? CLS_INC_WILD : CLS_INC_EXACT;
            include |= (rule->cls_rule.wc.wildcards
                        ? CLS_INC_WILD : CLS_INC_EXACT);
            classifier_for_each_match(&cls, &rule->cls_rule, include,
                                      free_rule, &cls);
            tcls_delete_matches(&tcls, &rule->cls_rule, include);
            compare_classifiers(&cls, &tcls);
            free(rule);
        }

        destroy_classifier(&cls);
        tcls_destroy(&tcls);
    }
}

static const struct command commands[] = {
    {"empty", 0, 0, test_empty},
    {"destroy-null", 0, 0, test_destroy_null},
    {"single-rule", 0, 0, test_single_rule},
    {"rule-replacement", 0, 0, test_rule_replacement},
    {"two-rules-in-one-bucket", 0, 0, test_two_rules_in_one_bucket},
    {"two-rules-in-one-table", 0, 0, test_two_rules_in_one_table},
    {"two-rules-in-different-tables", 0, 0,
     test_two_rules_in_different_tables},
    {"many-rules-in-one-bucket", 0, 0, test_many_rules_in_one_bucket},
    {"many-rules-in-one-table", 0, 0, test_many_rules_in_one_table},
    {"many-rules-in-different-tables", 0, 0,
     test_many_rules_in_different_tables},
    {NULL, 0, 0, NULL},
};

int
main(int argc, char *argv[])
{
    init_values();
    run_command(argc - 1, argv + 1, commands);
    return 0;
}
