/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include <errno.h>
#include <limits.h>
#include "byte-order.h"
#include "command-line.h"
#include "flow.h"
#include "ofp-util.h"
#include "packets.h"
#include "random.h"
#include "unaligned.h"
#include "ovstest.h"
#undef NDEBUG
#include <assert.h>

/* We need access to classifier internal definitions to be able to fully
 * test them.  The alternative would be to expose them all in the classifier
 * API. */
#include "classifier.c"

/* Fields in a rule. */
#define CLS_FIELDS                                                  \
    /*        struct flow    all-caps */  \
    /*        member name    name     */  \
    /*        -----------    -------- */  \
    CLS_FIELD(tunnel.tun_id, TUN_ID)      \
    CLS_FIELD(metadata,      METADATA)    \
    CLS_FIELD(nw_src,        NW_SRC)      \
    CLS_FIELD(nw_dst,        NW_DST)      \
    CLS_FIELD(in_port,       IN_PORT)     \
    CLS_FIELD(vlan_tci,      VLAN_TCI)    \
    CLS_FIELD(dl_type,       DL_TYPE)     \
    CLS_FIELD(tp_src,        TP_SRC)      \
    CLS_FIELD(tp_dst,        TP_DST)      \
    CLS_FIELD(dl_src,        DL_SRC)      \
    CLS_FIELD(dl_dst,        DL_DST)      \
    CLS_FIELD(nw_proto,      NW_PROTO)    \
    CLS_FIELD(nw_tos,        NW_DSCP)

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

static struct test_rule *make_rule(int wc_fields, unsigned int priority,
                                   int value_pat);
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
            free_rule(tcls->rules[i]);
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
            eq = !((fixed->vlan_tci ^ wild.flow.vlan_tci)
                   & wild.wc.masks.vlan_tci);
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
        if (!minimask_has_extra(&pos->cls_rule.match.mask,
                                &target->match.mask)) {
            struct flow flow;

            miniflow_expand(&pos->cls_rule.match.flow, &flow);
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
static uint8_t dl_src_values[][6] = { { 0x00, 0x02, 0xe3, 0x0f, 0x80, 0xa4 },
                                      { 0x5e, 0x33, 0x7f, 0x5f, 0x1e, 0x99 } };
static uint8_t dl_dst_values[][6] = { { 0x4a, 0x27, 0x71, 0xae, 0x64, 0xc1 },
                                      { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
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
compare_classifiers(struct classifier *cls, struct tcls *tcls)
    OVS_REQ_RDLOCK(cls->rwlock)
{
    static const int confidence = 500;
    unsigned int i;

    assert(classifier_count(cls) == tcls->n_rules);
    for (i = 0; i < confidence; i++) {
        struct cls_rule *cr0, *cr1, *cr2;
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
        flow.vlan_tci = vlan_tci_values[get_value(&x, N_VLAN_TCI_VALUES)];
        flow.dl_type = dl_type_values[get_value(&x, N_DL_TYPE_VALUES)];
        flow.tp_src = tp_src_values[get_value(&x, N_TP_SRC_VALUES)];
        flow.tp_dst = tp_dst_values[get_value(&x, N_TP_DST_VALUES)];
        memcpy(flow.dl_src, dl_src_values[get_value(&x, N_DL_SRC_VALUES)],
               ETH_ADDR_LEN);
        memcpy(flow.dl_dst, dl_dst_values[get_value(&x, N_DL_DST_VALUES)],
               ETH_ADDR_LEN);
        flow.nw_proto = nw_proto_values[get_value(&x, N_NW_PROTO_VALUES)];
        flow.nw_tos = nw_dscp_values[get_value(&x, N_NW_DSCP_VALUES)];

        cr0 = classifier_lookup(cls, &flow, &wc);
        cr1 = tcls_lookup(tcls, &flow);
        assert((cr0 == NULL) == (cr1 == NULL));
        if (cr0 != NULL) {
            const struct test_rule *tr0 = test_rule_from_cls_rule(cr0);
            const struct test_rule *tr1 = test_rule_from_cls_rule(cr1);

            assert(cls_rule_equal(cr0, cr1));
            assert(tr0->aux == tr1->aux);
        }
        cr2 = classifier_lookup(cls, &flow, NULL);
        assert(cr2 == cr0);
    }
}

static void
destroy_classifier(struct classifier *cls)
{
    struct test_rule *rule, *next_rule;
    struct cls_cursor cursor;

    fat_rwlock_wrlock(&cls->rwlock);
    cls_cursor_init(&cursor, cls, NULL);
    CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cls_rule, &cursor) {
        classifier_remove(cls, &rule->cls_rule);
        free_rule(rule);
    }
    fat_rwlock_unlock(&cls->rwlock);
    classifier_destroy(cls);
}

static void
check_tables(const struct classifier *cls, int n_tables, int n_rules,
             int n_dups) OVS_REQ_RDLOCK(cls->rwlock)
{
    const struct cls_subtable *table;
    struct test_rule *test_rule;
    struct cls_cursor cursor;
    int found_tables = 0;
    int found_rules = 0;
    int found_dups = 0;
    int found_rules2 = 0;

    HMAP_FOR_EACH (table, hmap_node, &cls->cls->subtables) {
        const struct cls_match *head;
        unsigned int max_priority = 0;
        unsigned int max_count = 0;

        assert(!hmap_is_empty(&table->rules));

        found_tables++;
        HMAP_FOR_EACH (head, hmap_node, &table->rules) {
            unsigned int prev_priority = UINT_MAX;
            const struct cls_match *rule;

            if (head->priority > max_priority) {
                max_priority = head->priority;
                max_count = 1;
            } else if (head->priority == max_priority) {
                ++max_count;
            }

            found_rules++;
            LIST_FOR_EACH (rule, list, &head->list) {
                assert(rule->priority < prev_priority);
                assert(rule->priority <= table->max_priority);

                prev_priority = rule->priority;
                found_rules++;
                found_dups++;
                assert(classifier_find_rule_exactly(cls, rule->cls_rule)
                       == rule->cls_rule);
            }
        }
        assert(table->max_priority == max_priority);
        assert(table->max_count == max_count);
    }

    assert(found_tables == hmap_count(&cls->cls->subtables));
    assert(n_tables == -1 || n_tables == hmap_count(&cls->cls->subtables));
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
            memset(match.wc.masks.dl_src, 0xff, ETH_ADDR_LEN);
        } else if (f_idx == CLS_F_IDX_DL_DST) {
            memset(match.wc.masks.dl_dst, 0xff, ETH_ADDR_LEN);
        } else if (f_idx == CLS_F_IDX_VLAN_TCI) {
            match.wc.masks.vlan_tci = OVS_BE16_MAX;
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
    cls_rule_init(&rule->cls_rule, &match, wc_fields ? priority : UINT_MAX);
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
shuffle(unsigned int *p, size_t n)
{
    for (; n > 1; n--, p++) {
        unsigned int *q = &p[random_range(n)];
        unsigned int tmp = *p;
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

/* Tests an empty classifier. */
static void
test_empty(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct classifier cls;
    struct tcls tcls;

    classifier_init(&cls, flow_segment_u32s);
    fat_rwlock_wrlock(&cls.rwlock);
    classifier_set_prefix_fields(&cls, trie_fields, ARRAY_SIZE(trie_fields));
    tcls_init(&tcls);
    assert(classifier_is_empty(&cls));
    assert(tcls_is_empty(&tcls));
    compare_classifiers(&cls, &tcls);
    fat_rwlock_unlock(&cls.rwlock);
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

        classifier_init(&cls, flow_segment_u32s);
        fat_rwlock_wrlock(&cls.rwlock);
        classifier_set_prefix_fields(&cls, trie_fields,
                                     ARRAY_SIZE(trie_fields));
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

        free_rule(rule);
        fat_rwlock_unlock(&cls.rwlock);
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

        classifier_init(&cls, flow_segment_u32s);
        fat_rwlock_wrlock(&cls.rwlock);
        classifier_set_prefix_fields(&cls, trie_fields,
                                     ARRAY_SIZE(trie_fields));
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
        free_rule(rule1);
        check_tables(&cls, 1, 1, 0);
        compare_classifiers(&cls, &tcls);
        tcls_destroy(&tcls);
        fat_rwlock_unlock(&cls.rwlock);
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

            classifier_init(&cls, flow_segment_u32s);
            fat_rwlock_wrlock(&cls.rwlock);
            classifier_set_prefix_fields(&cls, trie_fields,
                                         ARRAY_SIZE(trie_fields));
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

            for (i = 0; i < N_RULES; i++) {
                if (rules[i]->cls_rule.cls_match) {
                    classifier_remove(&cls, &rules[i]->cls_rule);
                }
                free_rule(rules[i]);
            }

            fat_rwlock_unlock(&cls.rwlock);
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
            wcf = random_uint32() & ((1u << CLS_N_FIELDS) - 1);
            value_mask = ~wcf & ((1u << CLS_N_FIELDS) - 1);
        } while ((1 << count_ones(value_mask)) < N_RULES);

        classifier_init(&cls, flow_segment_u32s);
        fat_rwlock_wrlock(&cls.rwlock);
        classifier_set_prefix_fields(&cls, trie_fields,
                                     ARRAY_SIZE(trie_fields));
        tcls_init(&tcls);

        for (i = 0; i < N_RULES; i++) {
            unsigned int priority = random_uint32();

            do {
                value_pats[i] = random_uint32() & value_mask;
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
            free_rule(rules[i]);

            check_tables(&cls, i < N_RULES - 1, N_RULES - (i + 1), 0);
            compare_classifiers(&cls, &tcls);
        }

        fat_rwlock_unlock(&cls.rwlock);
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
        unsigned int priorities[MAX_RULES];
        struct classifier cls;
        struct tcls tcls;

        random_set_seed(iteration + 1);
        for (i = 0; i < MAX_RULES; i++) {
            priorities[i] = i * 129;
        }
        shuffle(priorities, ARRAY_SIZE(priorities));

        classifier_init(&cls, flow_segment_u32s);
        fat_rwlock_wrlock(&cls.rwlock);
        classifier_set_prefix_fields(&cls, trie_fields,
                                     ARRAY_SIZE(trie_fields));
        tcls_init(&tcls);

        for (i = 0; i < MAX_RULES; i++) {
            struct test_rule *rule;
            unsigned int priority = priorities[i];
            int wcf = wcfs[random_range(n_tables)];
            int value_pat = random_uint32() & ((1u << CLS_N_FIELDS) - 1);
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

            target = clone_rule(tcls.rules[random_range(tcls.n_rules)]);

            cls_cursor_init(&cursor, &cls, &target->cls_rule);
            CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cls_rule, &cursor) {
                classifier_remove(&cls, &rule->cls_rule);
                free_rule(rule);
            }
            tcls_delete_matches(&tcls, &target->cls_rule);
            compare_classifiers(&cls, &tcls);
            check_tables(&cls, -1, -1, -1);
            free_rule(target);
        }

        fat_rwlock_unlock(&cls.rwlock);
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
    int i;

    memset(flow, 0, sizeof *flow);

    /* Empty flow. */
    if (choose(1, &idx)) {
        return true;
    }

    /* All flows with a small number of consecutive nonzero values. */
    for (i = 1; i <= 4; i++) {
        if (init_consecutive_values(i, flow, &idx)) {
            return true;
        }
    }

    /* All flows with a large number of consecutive nonzero values. */
    for (i = FLOW_U32S - 4; i <= FLOW_U32S; i++) {
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
        int i;

        for (i = 0; i < n; i++) {
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

static void
test_miniflow(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct flow flow;
    unsigned int idx;

    random_set_seed(0xb3faca38);
    for (idx = 0; next_random_flow(&flow, idx); idx++) {
        const uint32_t *flow_u32 = (const uint32_t *) &flow;
        struct miniflow miniflow, miniflow2, miniflow3;
        struct flow flow2, flow3;
        struct flow_wildcards mask;
        struct minimask minimask;
        int i;

        /* Convert flow to miniflow. */
        miniflow_init(&miniflow, &flow);

        /* Check that the flow equals its miniflow. */
        assert(miniflow_get_vid(&miniflow) == vlan_tci_to_vid(flow.vlan_tci));
        for (i = 0; i < FLOW_U32S; i++) {
            assert(MINIFLOW_GET_TYPE(&miniflow, uint32_t, i * 4)
                   == flow_u32[i]);
        }

        /* Check that the miniflow equals itself. */
        assert(miniflow_equal(&miniflow, &miniflow));

        /* Convert miniflow back to flow and verify that it's the same. */
        miniflow_expand(&miniflow, &flow2);
        assert(flow_equal(&flow, &flow2));

        /* Check that copying a miniflow works properly. */
        miniflow_clone(&miniflow2, &miniflow);
        assert(miniflow_equal(&miniflow, &miniflow2));
        assert(miniflow_hash(&miniflow, 0) == miniflow_hash(&miniflow2, 0));
        miniflow_expand(&miniflow2, &flow3);
        assert(flow_equal(&flow, &flow3));

        /* Check that masked matches work as expected for identical flows and
         * miniflows. */
        do {
            next_random_flow(&mask.masks, 1);
        } while (flow_wildcards_is_catchall(&mask));
        minimask_init(&minimask, &mask);
        assert(minimask_is_catchall(&minimask)
               == flow_wildcards_is_catchall(&mask));
        assert(miniflow_equal_in_minimask(&miniflow, &miniflow2, &minimask));
        assert(miniflow_equal_flow_in_minimask(&miniflow, &flow2, &minimask));
        assert(miniflow_hash_in_minimask(&miniflow, &minimask, 0x12345678) ==
               flow_hash_in_minimask(&flow, &minimask, 0x12345678));

        /* Check that masked matches work as expected for differing flows and
         * miniflows. */
        toggle_masked_flow_bits(&flow2, &mask);
        assert(!miniflow_equal_flow_in_minimask(&miniflow, &flow2, &minimask));
        miniflow_init(&miniflow3, &flow2);
        assert(!miniflow_equal_in_minimask(&miniflow, &miniflow3, &minimask));

        /* Clean up. */
        miniflow_destroy(&miniflow);
        miniflow_destroy(&miniflow2);
        miniflow_destroy(&miniflow3);
        minimask_destroy(&minimask);
    }
}

static void
test_minimask_has_extra(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct flow_wildcards catchall;
    struct minimask minicatchall;
    struct flow flow;
    unsigned int idx;

    flow_wildcards_init_catchall(&catchall);
    minimask_init(&minicatchall, &catchall);
    assert(minimask_is_catchall(&minicatchall));

    random_set_seed(0x2ec7905b);
    for (idx = 0; next_random_flow(&flow, idx); idx++) {
        struct flow_wildcards mask;
        struct minimask minimask;

        mask.masks = flow;
        minimask_init(&minimask, &mask);
        assert(!minimask_has_extra(&minimask, &minimask));
        assert(minimask_has_extra(&minicatchall, &minimask)
               == !minimask_is_catchall(&minimask));
        if (!minimask_is_catchall(&minimask)) {
            struct minimask minimask2;

            wildcard_extra_bits(&mask);
            minimask_init(&minimask2, &mask);
            assert(minimask_has_extra(&minimask2, &minimask));
            assert(!minimask_has_extra(&minimask, &minimask2));
            minimask_destroy(&minimask2);
        }

        minimask_destroy(&minimask);
    }

    minimask_destroy(&minicatchall);
}

static void
test_minimask_combine(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct flow_wildcards catchall;
    struct minimask minicatchall;
    struct flow flow;
    unsigned int idx;

    flow_wildcards_init_catchall(&catchall);
    minimask_init(&minicatchall, &catchall);
    assert(minimask_is_catchall(&minicatchall));

    random_set_seed(0x181bf0cd);
    for (idx = 0; next_random_flow(&flow, idx); idx++) {
        struct minimask minimask, minimask2, minicombined;
        struct flow_wildcards mask, mask2, combined, combined2;
        uint32_t storage[FLOW_U32S];
        struct flow flow2;

        mask.masks = flow;
        minimask_init(&minimask, &mask);

        minimask_combine(&minicombined, &minimask, &minicatchall, storage);
        assert(minimask_is_catchall(&minicombined));

        any_random_flow(&flow2);
        mask2.masks = flow2;
        minimask_init(&minimask2, &mask2);

        minimask_combine(&minicombined, &minimask, &minimask2, storage);
        flow_wildcards_and(&combined, &mask, &mask2);
        minimask_expand(&minicombined, &combined2);
        assert(flow_wildcards_equal(&combined, &combined2));

        minimask_destroy(&minimask);
        minimask_destroy(&minimask2);
    }

    minimask_destroy(&minicatchall);
}

static const struct command commands[] = {
    /* Classifier tests. */
    {"empty", 0, 0, test_empty},
    {"destroy-null", 0, 0, test_destroy_null},
    {"single-rule", 0, 0, test_single_rule},
    {"rule-replacement", 0, 0, test_rule_replacement},
    {"many-rules-in-one-list", 0, 0, test_many_rules_in_one_list},
    {"many-rules-in-one-table", 0, 0, test_many_rules_in_one_table},
    {"many-rules-in-two-tables", 0, 0, test_many_rules_in_two_tables},
    {"many-rules-in-five-tables", 0, 0, test_many_rules_in_five_tables},

    /* Miniflow and minimask tests. */
    {"miniflow", 0, 0, test_miniflow},
    {"minimask_has_extra", 0, 0, test_minimask_has_extra},
    {"minimask_combine", 0, 0, test_minimask_combine},

    {NULL, 0, 0, NULL},
};

static void
test_classifier_main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    init_values();
    run_command(argc - 1, argv + 1, commands);
}

OVSTEST_REGISTER("test-classifier", test_classifier_main);
