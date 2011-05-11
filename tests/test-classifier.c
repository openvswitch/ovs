/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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
#include "byte-order.h"
#include "command-line.h"
#include "flow.h"
#include "ofp-util.h"
#include "packets.h"
#include "unaligned.h"

#undef NDEBUG
#include <assert.h>

/* Fields in a rule. */
#define CLS_FIELDS                                                  \
    /*                                    struct flow  all-caps */  \
    /*        FWW_* bit(s)                member name  name     */  \
    /*        --------------------------  -----------  -------- */  \
    CLS_FIELD(0,                          tun_id,      TUN_ID)      \
    CLS_FIELD(0,                          nw_src,      NW_SRC)      \
    CLS_FIELD(0,                          nw_dst,      NW_DST)      \
    CLS_FIELD(FWW_IN_PORT,                in_port,     IN_PORT)     \
    CLS_FIELD(0,                          vlan_tci,    VLAN_TCI)    \
    CLS_FIELD(FWW_DL_TYPE,                dl_type,     DL_TYPE)     \
    CLS_FIELD(FWW_TP_SRC,                 tp_src,      TP_SRC)      \
    CLS_FIELD(FWW_TP_DST,                 tp_dst,      TP_DST)      \
    CLS_FIELD(FWW_DL_SRC,                 dl_src,      DL_SRC)      \
    CLS_FIELD(FWW_DL_DST | FWW_ETH_MCAST, dl_dst,      DL_DST)      \
    CLS_FIELD(FWW_NW_PROTO,               nw_proto,    NW_PROTO)    \
    CLS_FIELD(FWW_NW_TOS,                 nw_tos,      NW_TOS)

/* Field indexes.
 *
 * (These are also indexed into struct classifier's 'tables' array.) */
enum {
#define CLS_FIELD(WILDCARDS, MEMBER, NAME) CLS_F_IDX_##NAME,
    CLS_FIELDS
#undef CLS_FIELD
    CLS_N_FIELDS
};

/* Field information. */
struct cls_field {
    int ofs;                    /* Offset in struct flow. */
    int len;                    /* Length in bytes. */
    flow_wildcards_t wildcards; /* FWW_* bit or bits for this field. */
    const char *name;           /* Name (for debugging). */
};

static const struct cls_field cls_fields[CLS_N_FIELDS] = {
#define CLS_FIELD(WILDCARDS, MEMBER, NAME)      \
    { offsetof(struct flow, MEMBER),            \
      sizeof ((struct flow *)0)->MEMBER,        \
      WILDCARDS,                                \
      #NAME },
    CLS_FIELDS
#undef CLS_FIELD
};

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

static bool
tcls_is_empty(const struct tcls *tcls)
{
    return tcls->n_rules == 0;
}

static struct test_rule *
tcls_insert(struct tcls *tcls, const struct test_rule *rule)
{
    size_t i;

    assert(!flow_wildcards_is_exact(&rule->cls_rule.wc)
           || rule->cls_rule.priority == UINT_MAX);
    for (i = 0; i < tcls->n_rules; i++) {
        const struct cls_rule *pos = &tcls->rules[i]->cls_rule;
        if (cls_rule_equal(pos, &rule->cls_rule)) {
            /* Exact match. */
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

static bool
match(const struct cls_rule *wild, const struct flow *fixed)
{
    int f_idx;

    for (f_idx = 0; f_idx < CLS_N_FIELDS; f_idx++) {
        const struct cls_field *f = &cls_fields[f_idx];
        bool eq;

        if (f->wildcards) {
            void *wild_field = (char *) &wild->flow + f->ofs;
            void *fixed_field = (char *) fixed + f->ofs;
            eq = ((wild->wc.wildcards & f->wildcards) == f->wildcards
                  || !memcmp(wild_field, fixed_field, f->len));
        } else if (f_idx == CLS_F_IDX_NW_SRC) {
            eq = !((fixed->nw_src ^ wild->flow.nw_src) & wild->wc.nw_src_mask);
        } else if (f_idx == CLS_F_IDX_NW_DST) {
            eq = !((fixed->nw_dst ^ wild->flow.nw_dst) & wild->wc.nw_dst_mask);
        } else if (f_idx == CLS_F_IDX_VLAN_TCI) {
            eq = !((fixed->vlan_tci ^ wild->flow.vlan_tci)
                   & wild->wc.vlan_tci_mask);
        } else if (f_idx == CLS_F_IDX_TUN_ID) {
            eq = !((fixed->tun_id ^ wild->flow.tun_id) & wild->wc.tun_id_mask);
        } else {
            NOT_REACHED();
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
        if (!flow_wildcards_has_extra(&pos->cls_rule.wc, &target->wc)
            && match(target, &pos->cls_rule.flow)) {
            tcls_remove(cls, pos);
        } else {
            i++;
        }
    }
}

static ovs_be32 nw_src_values[] = { CONSTANT_HTONL(0xc0a80001),
                                    CONSTANT_HTONL(0xc0a04455) };
static ovs_be32 nw_dst_values[] = { CONSTANT_HTONL(0xc0a80002),
                                    CONSTANT_HTONL(0xc0a04455) };
static ovs_be64 tun_id_values[] = {
    0,
    CONSTANT_HTONLL(UINT64_C(0xfedcba9876543210)) };
static uint16_t in_port_values[] = { 1, OFPP_LOCAL };
static ovs_be16 vlan_tci_values[] = { CONSTANT_HTONS(101), CONSTANT_HTONS(0) };
static ovs_be16 dl_type_values[]
            = { CONSTANT_HTONS(ETH_TYPE_IP), CONSTANT_HTONS(ETH_TYPE_ARP) };
static ovs_be16 tp_src_values[] = { CONSTANT_HTONS(49362),
                                    CONSTANT_HTONS(80) };
static ovs_be16 tp_dst_values[] = { CONSTANT_HTONS(6667), CONSTANT_HTONS(22) };
static uint8_t dl_src_values[][6] = { { 0x00, 0x02, 0xe3, 0x0f, 0x80, 0xa4 },
                                      { 0x5e, 0x33, 0x7f, 0x5f, 0x1e, 0x99 } };
static uint8_t dl_dst_values[][6] = { { 0x4a, 0x27, 0x71, 0xae, 0x64, 0xc1 },
                                      { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
static uint8_t nw_proto_values[] = { IPPROTO_TCP, IPPROTO_ICMP };
static uint8_t nw_tos_values[] = { 49, 0 };

static void *values[CLS_N_FIELDS][2];

static void
init_values(void)
{
    values[CLS_F_IDX_TUN_ID][0] = &tun_id_values[0];
    values[CLS_F_IDX_TUN_ID][1] = &tun_id_values[1];

    values[CLS_F_IDX_IN_PORT][0] = &in_port_values[0];
    values[CLS_F_IDX_IN_PORT][1] = &in_port_values[1];

    values[CLS_F_IDX_VLAN_TCI][0] = &vlan_tci_values[0];
    values[CLS_F_IDX_VLAN_TCI][1] = &vlan_tci_values[1];

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
#define N_VLAN_TCI_VALUES ARRAY_SIZE(vlan_tci_values)
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
                       N_VLAN_TCI_VALUES *       \
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

static void
compare_classifiers(struct classifier *cls, struct tcls *tcls)
{
    static const int confidence = 500;
    unsigned int i;

    assert(classifier_count(cls) == tcls->n_rules);
    for (i = 0; i < confidence; i++) {
        struct cls_rule *cr0, *cr1;
        struct flow flow;
        unsigned int x;

        x = rand () % N_FLOW_VALUES;
        flow.nw_src = nw_src_values[get_value(&x, N_NW_SRC_VALUES)];
        flow.nw_dst = nw_dst_values[get_value(&x, N_NW_DST_VALUES)];
        flow.tun_id = tun_id_values[get_value(&x, N_TUN_ID_VALUES)];
        flow.in_port = in_port_values[get_value(&x, N_IN_PORT_VALUES)];
        flow.vlan_tci = vlan_tci_values[get_value(&x, N_VLAN_TCI_VALUES)];
        flow.dl_type = dl_type_values[get_value(&x, N_DL_TYPE_VALUES)];
        flow.tp_src = tp_src_values[get_value(&x, N_TP_SRC_VALUES)];
        flow.tp_dst = tp_dst_values[get_value(&x, N_TP_DST_VALUES)];
        memcpy(flow.dl_src, dl_src_values[get_value(&x, N_DL_SRC_VALUES)],
               ETH_ADDR_LEN);
        memcpy(flow.dl_dst, dl_dst_values[get_value(&x, N_DL_DST_VALUES)],
               ETH_ADDR_LEN);
        flow.nw_proto = nw_proto_values[get_value(&x, N_NW_PROTO_VALUES)];
        flow.nw_tos = nw_tos_values[get_value(&x, N_NW_TOS_VALUES)];

        cr0 = classifier_lookup(cls, &flow);
        cr1 = tcls_lookup(tcls, &flow);
        assert((cr0 == NULL) == (cr1 == NULL));
        if (cr0 != NULL) {
            const struct test_rule *tr0 = test_rule_from_cls_rule(cr0);
            const struct test_rule *tr1 = test_rule_from_cls_rule(cr1);

            assert(cls_rule_equal(cr0, cr1));
            assert(tr0->aux == tr1->aux);
        }
    }
}

static void
destroy_classifier(struct classifier *cls)
{
    struct test_rule *rule, *next_rule;
    struct cls_cursor cursor;

    cls_cursor_init(&cursor, cls, NULL);
    CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cls_rule, &cursor) {
        classifier_remove(cls, &rule->cls_rule);
        free(rule);
    }
    classifier_destroy(cls);
}

static void
check_tables(const struct classifier *cls,
             int n_tables, int n_rules, int n_dups)
{
    const struct cls_table *table;
    struct flow_wildcards exact_wc;
    struct test_rule *test_rule;
    struct cls_cursor cursor;
    int found_tables = 0;
    int found_rules = 0;
    int found_dups = 0;
    int found_rules2 = 0;

    flow_wildcards_init_exact(&exact_wc);
    HMAP_FOR_EACH (table, hmap_node, &cls->tables) {
        const struct cls_rule *head;

        assert(!hmap_is_empty(&table->rules));

        found_tables++;
        HMAP_FOR_EACH (head, hmap_node, &table->rules) {
            unsigned int prev_priority = UINT_MAX;
            const struct cls_rule *rule;

            found_rules++;
            LIST_FOR_EACH (rule, list, &head->list) {
                assert(rule->priority < prev_priority);
                prev_priority = rule->priority;
                found_rules++;
                found_dups++;
                assert(classifier_find_rule_exactly(cls, rule) == rule);
            }
        }
    }

    assert(found_tables == hmap_count(&cls->tables));
    assert(n_tables == -1 || n_tables == hmap_count(&cls->tables));
    assert(n_rules == -1 || found_rules == n_rules);
    assert(n_dups == -1 || found_dups == n_dups);

    cls_cursor_init(&cursor, cls, NULL);
    CLS_CURSOR_FOR_EACH (test_rule, cls_rule, &cursor) {
        found_rules2++;
    }
    assert(found_rules == found_rules2);
}

static struct test_rule *
make_rule(int wc_fields, unsigned int priority, int value_pat)
{
    const struct cls_field *f;
    struct test_rule *rule;

    rule = xzalloc(sizeof *rule);
    cls_rule_init_catchall(&rule->cls_rule, wc_fields ? priority : UINT_MAX);
    for (f = &cls_fields[0]; f < &cls_fields[CLS_N_FIELDS]; f++) {
        int f_idx = f - cls_fields;
        int value_idx = (value_pat & (1u << f_idx)) != 0;
        memcpy((char *) &rule->cls_rule.flow + f->ofs,
               values[f_idx][value_idx], f->len);

        if (f->wildcards) {
            rule->cls_rule.wc.wildcards &= ~f->wildcards;
        } else if (f_idx == CLS_F_IDX_NW_SRC) {
            rule->cls_rule.wc.nw_src_mask = htonl(UINT32_MAX);
        } else if (f_idx == CLS_F_IDX_NW_DST) {
            rule->cls_rule.wc.nw_dst_mask = htonl(UINT32_MAX);
        } else if (f_idx == CLS_F_IDX_VLAN_TCI) {
            rule->cls_rule.wc.vlan_tci_mask = htons(UINT16_MAX);
        } else if (f_idx == CLS_F_IDX_TUN_ID) {
            rule->cls_rule.wc.tun_id_mask = htonll(UINT64_MAX);
        } else {
            NOT_REACHED();
        }
    }
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
        classifier_insert(&cls, &rule->cls_rule);
        check_tables(&cls, 1, 1, 0);
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
        classifier_insert(&cls, &rule1->cls_rule);
        check_tables(&cls, 1, 1, 0);
        compare_classifiers(&cls, &tcls);
        tcls_destroy(&tcls);

        tcls_init(&tcls);
        tcls_insert(&tcls, rule2);
        assert(test_rule_from_cls_rule(
                   classifier_replace(&cls, &rule2->cls_rule)) == rule1);
        free(rule1);
        check_tables(&cls, 1, 1, 0);
        compare_classifiers(&cls, &tcls);
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
test_many_rules_in_one_list (int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
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

            n_permutations++;

            for (i = 0; i < N_RULES; i++) {
                rules[i] = make_rule(456, pris[i], 0);
                tcls_rules[i] = NULL;
                pri_rules[i] = -1;
            }

            classifier_init(&cls);
            tcls_init(&tcls);

            for (i = 0; i < ARRAY_SIZE(ops); i++) {
                int j = ops[i];
                int m, n;

                if (!tcls_rules[j]) {
                    struct test_rule *displaced_rule;

                    tcls_rules[j] = tcls_insert(&tcls, rules[j]);
                    displaced_rule = test_rule_from_cls_rule(
                        classifier_replace(&cls, &rules[j]->cls_rule));
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
                    classifier_remove(&cls, &rules[j]->cls_rule);
                    tcls_remove(&tcls, tcls_rules[j]);
                    tcls_rules[j] = NULL;
                    pri_rules[pris[j]] = -1;
                }

                n = 0;
                for (m = 0; m < N_RULES; m++) {
                    n += tcls_rules[m] != NULL;
                }
                check_tables(&cls, n > 0, n, n - 1);

                compare_classifiers(&cls, &tcls);
            }

            classifier_destroy(&cls);
            tcls_destroy(&tcls);

            for (i = 0; i < N_RULES; i++) {
                free(rules[i]);
            }
        } while (next_permutation(ops, ARRAY_SIZE(ops)));
        assert(n_permutations == (factorial(N_RULES * 2) >> N_RULES));
    }
}

static int
count_ones(unsigned long int x)
{
    int n = 0;

    while (x) {
        x &= x - 1;
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
test_many_rules_in_one_table(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    int iteration;

    for (iteration = 0; iteration < 50; iteration++) {
        enum { N_RULES = 20 };
        struct test_rule *rules[N_RULES];
        struct test_rule *tcls_rules[N_RULES];
        struct classifier cls;
        struct tcls tcls;
        int value_pats[N_RULES];
        int value_mask;
        int wcf;
        int i;

        do {
            wcf = rand() & ((1u << CLS_N_FIELDS) - 1);
            value_mask = ~wcf & ((1u << CLS_N_FIELDS) - 1);
        } while ((1 << count_ones(value_mask)) < N_RULES);

        classifier_init(&cls);
        tcls_init(&tcls);

        for (i = 0; i < N_RULES; i++) {
            unsigned int priority = rand();

            do {
                value_pats[i] = rand() & value_mask;
            } while (array_contains(value_pats, i, value_pats[i]));

            rules[i] = make_rule(wcf, priority, value_pats[i]);
            tcls_rules[i] = tcls_insert(&tcls, rules[i]);
            classifier_insert(&cls, &rules[i]->cls_rule);

            check_tables(&cls, 1, i + 1, 0);
            compare_classifiers(&cls, &tcls);
        }

        for (i = 0; i < N_RULES; i++) {
            tcls_remove(&tcls, tcls_rules[i]);
            classifier_remove(&cls, &rules[i]->cls_rule);
            free(rules[i]);

            check_tables(&cls, i < N_RULES - 1, N_RULES - (i + 1), 0);
            compare_classifiers(&cls, &tcls);
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
            wcfs[i] = rand() & ((1u << CLS_N_FIELDS) - 1);
        } while (array_contains(wcfs, i, wcfs[i]));
    }

    for (iteration = 0; iteration < 30; iteration++) {
        unsigned int priorities[MAX_RULES];
        struct classifier cls;
        struct tcls tcls;

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
            int wcf = wcfs[rand() % n_tables];
            int value_pat = rand() & ((1u << CLS_N_FIELDS) - 1);
            rule = make_rule(wcf, priority, value_pat);
            tcls_insert(&tcls, rule);
            classifier_insert(&cls, &rule->cls_rule);
            check_tables(&cls, -1, i + 1, -1);
            compare_classifiers(&cls, &tcls);
        }

        while (!classifier_is_empty(&cls)) {
            struct test_rule *rule, *next_rule;
            struct test_rule *target;
            struct cls_cursor cursor;

            target = xmemdup(tcls.rules[rand() % tcls.n_rules],
                             sizeof(struct test_rule));

            cls_cursor_init(&cursor, &cls, &target->cls_rule);
            CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cls_rule, &cursor) {
                classifier_remove(&cls, &rule->cls_rule);
                free(rule);
            }
            tcls_delete_matches(&tcls, &target->cls_rule);
            compare_classifiers(&cls, &tcls);
            check_tables(&cls, -1, -1, -1);
            free(target);
        }

        destroy_classifier(&cls);
        tcls_destroy(&tcls);
    }
}

static void
test_many_rules_in_two_tables(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    test_many_rules_in_n_tables(2);
}

static void
test_many_rules_in_five_tables(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    test_many_rules_in_n_tables(5);
}

static const struct command commands[] = {
    {"empty", 0, 0, test_empty},
    {"destroy-null", 0, 0, test_destroy_null},
    {"single-rule", 0, 0, test_single_rule},
    {"rule-replacement", 0, 0, test_rule_replacement},
    {"many-rules-in-one-list", 0, 0, test_many_rules_in_one_list},
    {"many-rules-in-one-table", 0, 0, test_many_rules_in_one_table},
    {"many-rules-in-two-tables", 0, 0, test_many_rules_in_two_tables},
    {"many-rules-in-five-tables", 0, 0, test_many_rules_in_five_tables},
    {NULL, 0, 0, NULL},
};

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    init_values();
    run_command(argc - 1, argv + 1, commands);
    return 0;
}
