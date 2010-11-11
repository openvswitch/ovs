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

#ifndef CLASSIFIER_H
#define CLASSIFIER_H 1

/* Flow classifier.
 *
 * A classifier is a "struct classifier",
 *      a hash map from a set of wildcards to a "struct cls_table",
 *              a hash map from fixed field values to "struct cls_rule",
 *                      which can contain a list of otherwise identical rules
 *                      with lower priorities.
 */

#include "flow.h"
#include "hmap.h"
#include "list.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"

/* A flow classifier. */
struct classifier {
    int n_rules;                /* Total number of rules. */
    struct hmap tables;         /* Contains "struct cls_table"s.  */
};

/* A set of rules that all have the same fields wildcarded. */
struct cls_table {
    struct hmap_node hmap_node; /* Within struct classifier 'wctables'. */
    struct hmap rules;          /* Contains "struct cls_rule"s. */
    struct flow_wildcards wc;   /* Wildcards for fields. */
    int n_table_rules;          /* Number of rules, including duplicates. */
    int n_refs;                 /* Reference count used during iteration. */
};

/* A flow classification rule.
 *
 * Use one of the cls_rule_*() functions to initialize a cls_rule.
 *
 * The cls_rule_*() functions below maintain the following important
 * invariant that the classifier depends on:
 *
 *   - If a bit or a field is wildcarded in 'wc', then the corresponding bit or
 *     field in 'flow' is set to all-0-bits.  (The
 *     cls_rule_zero_wildcarded_fields() function can be used to restore this
 *     invariant after adding wildcards.)
 */
struct cls_rule {
    struct hmap_node hmap_node; /* Within struct cls_table 'rules'. */
    struct list list;           /* List of identical, lower-priority rules. */
    struct flow flow;           /* All field values. */
    struct flow_wildcards wc;   /* Wildcards for fields. */
    unsigned int priority;      /* Larger numbers are higher priorities. */
};

void cls_rule_init(const struct flow *, const struct flow_wildcards *,
                   unsigned int priority, struct cls_rule *);
void cls_rule_init_exact(const struct flow *, unsigned int priority,
                         struct cls_rule *);
void cls_rule_from_match(const struct ofp_match *, unsigned int priority,
                         int flow_format, uint64_t cookie, struct cls_rule *);
void cls_rule_init_catchall(struct cls_rule *, unsigned int priority);

void cls_rule_zero_wildcarded_fields(struct cls_rule *);

void cls_rule_set_in_port(struct cls_rule *, uint16_t odp_port);
void cls_rule_set_dl_type(struct cls_rule *, ovs_be16);
void cls_rule_set_dl_src(struct cls_rule *, const uint8_t[6]);
void cls_rule_set_dl_dst(struct cls_rule *, const uint8_t[6]);
bool cls_rule_set_dl_tci(struct cls_rule *, ovs_be16 tci);
bool cls_rule_set_dl_tci_masked(struct cls_rule *,
                                ovs_be16 tci, ovs_be16 mask);
void cls_rule_set_dl_vlan(struct cls_rule *, ovs_be16);
void cls_rule_set_dl_vlan_pcp(struct cls_rule *, uint8_t);
void cls_rule_set_tp_src(struct cls_rule *, ovs_be16);
void cls_rule_set_tp_dst(struct cls_rule *, ovs_be16);
void cls_rule_set_nw_proto(struct cls_rule *, uint8_t);
void cls_rule_set_nw_src(struct cls_rule *, ovs_be32);
bool cls_rule_set_nw_src_masked(struct cls_rule *, ovs_be32 ip, ovs_be32 mask);
void cls_rule_set_nw_dst(struct cls_rule *, ovs_be32);
bool cls_rule_set_nw_dst_masked(struct cls_rule *, ovs_be32 ip, ovs_be32 mask);
void cls_rule_set_nw_tos(struct cls_rule *, uint8_t);
void cls_rule_set_icmp_type(struct cls_rule *, uint8_t);
void cls_rule_set_icmp_code(struct cls_rule *, uint8_t);

char *cls_rule_to_string(const struct cls_rule *);
void cls_rule_print(const struct cls_rule *);

void classifier_init(struct classifier *);
void classifier_destroy(struct classifier *);
bool classifier_is_empty(const struct classifier *);
int classifier_count(const struct classifier *);
struct cls_rule *classifier_insert(struct classifier *, struct cls_rule *);
void classifier_remove(struct classifier *, struct cls_rule *);
struct cls_rule *classifier_lookup(const struct classifier *,
                                   const struct flow *);
bool classifier_rule_overlaps(const struct classifier *,
                              const struct cls_rule *);

typedef void cls_cb_func(struct cls_rule *, void *aux);

void classifier_for_each(const struct classifier *,
                         cls_cb_func *, void *aux);
void classifier_for_each_match(const struct classifier *,
                               const struct cls_rule *,
                               cls_cb_func *, void *aux);
struct cls_rule *classifier_find_rule_exactly(const struct classifier *,
                                              const struct cls_rule *);

#endif /* classifier.h */
