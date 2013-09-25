/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
 *
 * What?
 * =====
 *
 * A flow classifier holds any number of "rules", each of which specifies
 * values to match for some fields or subfields and a priority.  The primary
 * design goal for the classifier is that, given a packet, it can as quickly as
 * possible find the highest-priority rule that matches the packet.
 *
 * Each OpenFlow table is implemented as a flow classifier.
 *
 *
 * Basic Design
 * ============
 *
 * Suppose that all the rules in a classifier had the same form.  For example,
 * suppose that they all matched on the source and destination Ethernet address
 * and wildcarded all the other fields.  Then the obvious way to implement a
 * classifier would be a hash table on the source and destination Ethernet
 * addresses.  If new classification rules came along with a different form,
 * you could add a second hash table that hashed on the fields matched in those
 * rules.  With two hash tables, you look up a given flow in each hash table.
 * If there are no matches, the classifier didn't contain a match; if you find
 * a match in one of them, that's the result; if you find a match in both of
 * them, then the result is the rule with the higher priority.
 *
 * This is how the classifier works.  In a "struct classifier", each form of
 * "struct cls_rule" present (based on its ->match.mask) goes into a separate
 * "struct cls_table".  A lookup does a hash lookup in every "struct cls_table"
 * in the classifier and tracks the highest-priority match that it finds.  The
 * tables are kept in a descending priority order according to the highest
 * priority rule in each table, which allows lookup to skip over tables that
 * can't possibly have a higher-priority match than already found.
 *
 * One detail: a classifier can contain multiple rules that are identical other
 * than their priority.  When this happens, only the highest priority rule out
 * of a group of otherwise identical rules is stored directly in the "struct
 * cls_table", with the other almost-identical rules chained off a linked list
 * inside that highest-priority rule.
 *
 *
 * Partitioning
 * ============
 *
 * Suppose that a given classifier is being used to handle multiple stages in a
 * pipeline using "resubmit", with metadata (that is, the OpenFlow 1.1+ field
 * named "metadata") distinguishing between the different stages.  For example,
 * metadata value 1 might identify ingress rules, metadata value 2 might
 * identify ACLs, and metadata value 3 might identify egress rules.  Such a
 * classifier is essentially partitioned into multiple sub-classifiers on the
 * basis of the metadata value.
 *
 * The classifier has a special optimization to speed up matching in this
 * scenario:
 *
 *     - Each cls_table that matches on metadata gets a tag derived from the
 *       table's mask, so that it is likely that each table has a unique tag.
 *       (Duplicate tags have a performance cost but do not affect
 *       correctness.)
 *
 *     - For each metadata value matched by any cls_rule, the classifier
 *       constructs a "struct cls_partition" indexed by the metadata value.
 *       The cls_partition has a 'tags' member whose value is the bitwise-OR of
 *       the tags of each cls_table that contains any rule that matches on the
 *       cls_partition's metadata value.  In other words, struct cls_partition
 *       associates metadata values with tables that need to be checked with
 *       flows with that specific metadata value.
 *
 * Thus, a flow lookup can start by looking up the partition associated with
 * the flow's metadata, and then skip over any cls_table whose 'tag' does not
 * intersect the partition's 'tags'.  (The flow must also be looked up in any
 * cls_table that doesn't match on metadata.  We handle that by giving any such
 * cls_table TAG_ALL as its 'tags' so that it matches any tag.)
 *
 *
 * Thread-safety
 * =============
 *
 * When locked properly, the classifier is thread safe as long as the following
 * conditions are satisfied.
 * - Only the main thread calls functions requiring a write lock.
 * - Only the main thread is allowed to iterate over rules. */

#include "flow.h"
#include "hmap.h"
#include "list.h"
#include "match.h"
#include "tag.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "ovs-thread.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Needed only for the lock annotation in struct classifier. */
extern struct ovs_mutex ofproto_mutex;

/* A flow classifier. */
struct classifier {
    int n_rules;                /* Total number of rules. */
    struct hmap tables;         /* Contains "struct cls_table"s.  */
    struct list tables_priority; /* Tables in descending priority order */
    struct hmap partitions;     /* Contains "struct cls_partition"s. */
    struct ovs_rwlock rwlock OVS_ACQ_AFTER(ofproto_mutex);
};

/* A set of rules that all have the same fields wildcarded. */
struct cls_table {
    struct hmap_node hmap_node; /* Within struct classifier 'tables' hmap. */
    struct list list_node;      /* Within classifier 'tables_priority_list' */
    struct hmap rules;          /* Contains "struct cls_rule"s. */
    struct minimask mask;       /* Wildcards for fields. */
    int n_table_rules;          /* Number of rules, including duplicates. */
    unsigned int max_priority;  /* Max priority of any rule in the table. */
    unsigned int max_count;     /* Count of max_priority rules. */
    tag_type tag;               /* Tag generated from mask for partitioning. */
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
    struct cls_partition *partition;
};

/* Associates a metadata value (that is, a value of the OpenFlow 1.1+ metadata
 * field) with tags for the "cls_table"s that contain rules that match that
 * metadata value.  */
struct cls_partition {
    struct hmap_node hmap_node; /* In struct classifier's 'partitions' hmap. */
    ovs_be64 metadata;          /* metadata value for this partition. */
    tag_type tags;              /* OR of each included flow's cls_table tag. */
    struct tag_tracker tracker; /* Tracks the bits in 'tags'. */
};

void cls_rule_init(struct cls_rule *, const struct match *,
                   unsigned int priority);
void cls_rule_init_from_minimatch(struct cls_rule *, const struct minimatch *,
                                  unsigned int priority);
void cls_rule_clone(struct cls_rule *, const struct cls_rule *);
void cls_rule_move(struct cls_rule *dst, struct cls_rule *src);
void cls_rule_destroy(struct cls_rule *);

bool cls_rule_equal(const struct cls_rule *, const struct cls_rule *);
uint32_t cls_rule_hash(const struct cls_rule *, uint32_t basis);

void cls_rule_format(const struct cls_rule *, struct ds *);

bool cls_rule_is_catchall(const struct cls_rule *);

bool cls_rule_is_loose_match(const struct cls_rule *rule,
                             const struct minimatch *criteria);

void classifier_init(struct classifier *cls);
void classifier_destroy(struct classifier *);
bool classifier_is_empty(const struct classifier *cls)
    OVS_REQ_RDLOCK(cls->rwlock);
int classifier_count(const struct classifier *cls)
    OVS_REQ_RDLOCK(cls->rwlock);
void classifier_insert(struct classifier *cls, struct cls_rule *)
    OVS_REQ_WRLOCK(cls->rwlock);
struct cls_rule *classifier_replace(struct classifier *cls, struct cls_rule *)
    OVS_REQ_WRLOCK(cls->rwlock);
void classifier_remove(struct classifier *cls, struct cls_rule *)
    OVS_REQ_WRLOCK(cls->rwlock);
struct cls_rule *classifier_lookup(const struct classifier *cls,
                                   const struct flow *,
                                   struct flow_wildcards *)
    OVS_REQ_RDLOCK(cls->rwlock);
bool classifier_rule_overlaps(const struct classifier *cls,
                              const struct cls_rule *)
    OVS_REQ_RDLOCK(cls->rwlock);

typedef void cls_cb_func(struct cls_rule *, void *aux);

struct cls_rule *classifier_find_rule_exactly(const struct classifier *cls,
                                              const struct cls_rule *)
    OVS_REQ_RDLOCK(cls->rwlock);
struct cls_rule *classifier_find_match_exactly(const struct classifier *cls,
                                               const struct match *,
                                               unsigned int priority)
    OVS_REQ_RDLOCK(cls->rwlock);

/* Iteration. */

struct cls_cursor {
    const struct classifier *cls;
    const struct cls_table *table;
    const struct cls_rule *target;
};

void cls_cursor_init(struct cls_cursor *cursor, const struct classifier *cls,
                     const struct cls_rule *match) OVS_REQ_RDLOCK(cls->rwlock);
struct cls_rule *cls_cursor_first(struct cls_cursor *cursor);
struct cls_rule *cls_cursor_next(struct cls_cursor *cursor, const struct cls_rule *);

#define CLS_CURSOR_FOR_EACH(RULE, MEMBER, CURSOR)                       \
    for (ASSIGN_CONTAINER(RULE, cls_cursor_first(CURSOR), MEMBER);      \
         RULE != OBJECT_CONTAINING(NULL, RULE, MEMBER);                 \
         ASSIGN_CONTAINER(RULE, cls_cursor_next(CURSOR, &(RULE)->MEMBER), \
                          MEMBER))

#define CLS_CURSOR_FOR_EACH_SAFE(RULE, NEXT, MEMBER, CURSOR)            \
    for (ASSIGN_CONTAINER(RULE, cls_cursor_first(CURSOR), MEMBER);      \
         (RULE != OBJECT_CONTAINING(NULL, RULE, MEMBER)                 \
          ? ASSIGN_CONTAINER(NEXT, cls_cursor_next(CURSOR, &(RULE)->MEMBER), \
                             MEMBER), 1                                 \
          : 0);                                                         \
         (RULE) = (NEXT))

#ifdef __cplusplus
}
#endif

#endif /* classifier.h */
