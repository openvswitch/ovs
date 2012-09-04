/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "match.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A flow classifier. */
struct classifier {
    int n_rules;                /* Total number of rules. */
    struct hmap tables;         /* Contains "struct cls_table"s.  */
};

/* A set of rules that all have the same fields wildcarded. */
struct cls_table {
    struct hmap_node hmap_node; /* Within struct classifier 'tables' hmap. */
    struct hmap rules;          /* Contains "struct cls_rule"s. */
    struct minimask mask;       /* Wildcards for fields. */
    int n_table_rules;          /* Number of rules, including duplicates. */
};

/* Returns true if 'table' is a "catch-all" table that will match every
 * packet (if there is no higher-priority match). */
static inline bool
cls_table_is_catchall(const struct cls_table *table)
{
    return minimask_is_catchall(&table->mask);
}

/* A rule in a "struct classifier". */
struct cls_rule {
    struct hmap_node hmap_node; /* Within struct cls_table 'rules'. */
    struct list list;           /* List of identical, lower-priority rules. */
    struct minimatch match;     /* Matching rule. */
    unsigned int priority;      /* Larger numbers are higher priorities. */
};

void cls_rule_init(struct cls_rule *, const struct match *,
                   unsigned int priority);
void cls_rule_init_from_minimatch(struct cls_rule *, const struct minimatch *,
                                  unsigned int priority);
void cls_rule_clone(struct cls_rule *, const struct cls_rule *);
void cls_rule_destroy(struct cls_rule *);

bool cls_rule_equal(const struct cls_rule *, const struct cls_rule *);
uint32_t cls_rule_hash(const struct cls_rule *, uint32_t basis);

void cls_rule_format(const struct cls_rule *, struct ds *);

bool cls_rule_is_catchall(const struct cls_rule *);

bool cls_rule_is_loose_match(const struct cls_rule *rule,
                             const struct minimatch *criteria);

void classifier_init(struct classifier *);
void classifier_destroy(struct classifier *);
bool classifier_is_empty(const struct classifier *);
int classifier_count(const struct classifier *);
void classifier_insert(struct classifier *, struct cls_rule *);
struct cls_rule *classifier_replace(struct classifier *, struct cls_rule *);
void classifier_remove(struct classifier *, struct cls_rule *);
struct cls_rule *classifier_lookup(const struct classifier *,
                                   const struct flow *);
bool classifier_rule_overlaps(const struct classifier *,
                              const struct cls_rule *);

typedef void cls_cb_func(struct cls_rule *, void *aux);

struct cls_rule *classifier_find_rule_exactly(const struct classifier *,
                                              const struct cls_rule *);
struct cls_rule *classifier_find_match_exactly(const struct classifier *,
                                               const struct match *,
                                               unsigned int priority);

/* Iteration. */

struct cls_cursor {
    const struct classifier *cls;
    const struct cls_table *table;
    const struct cls_rule *target;
};

void cls_cursor_init(struct cls_cursor *, const struct classifier *,
                     const struct cls_rule *match);
struct cls_rule *cls_cursor_first(struct cls_cursor *);
struct cls_rule *cls_cursor_next(struct cls_cursor *, struct cls_rule *);

#define CLS_CURSOR_FOR_EACH(RULE, MEMBER, CURSOR)                       \
    for (ASSIGN_CONTAINER(RULE, cls_cursor_first(CURSOR), MEMBER);      \
         &(RULE)->MEMBER != NULL;                                       \
         ASSIGN_CONTAINER(RULE, cls_cursor_next(CURSOR, &(RULE)->MEMBER), \
                          MEMBER))

#define CLS_CURSOR_FOR_EACH_SAFE(RULE, NEXT, MEMBER, CURSOR)            \
    for (ASSIGN_CONTAINER(RULE, cls_cursor_first(CURSOR), MEMBER);      \
         (&(RULE)->MEMBER != NULL                                       \
          ? ASSIGN_CONTAINER(NEXT, cls_cursor_next(CURSOR, &(RULE)->MEMBER), \
                             MEMBER)                                    \
          : 0);                                                         \
         (RULE) = (NEXT))

#ifdef __cplusplus
}
#endif

#endif /* classifier.h */
