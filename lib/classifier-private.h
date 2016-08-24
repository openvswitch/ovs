/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#ifndef CLASSIFIER_PRIVATE_H
#define CLASSIFIER_PRIVATE_H 1

#include "ccmap.h"
#include "cmap.h"
#include "flow.h"
#include "hash.h"
#include "rculist.h"

/* Classifier internal definitions, subject to change at any time. */

/* A set of rules that all have the same fields wildcarded. */
struct cls_subtable {
    struct cmap_node cmap_node;    /* Within classifier's 'subtables_map'. */

    /* These fields are only used by writers. */
    int max_priority;              /* Max priority of any rule in subtable. */
    unsigned int max_count;        /* Count of max_priority rules. */

    /* Accessed by iterators. */
    struct rculist rules_list;              /* Unordered. */

    /* Identical, but lower priority rules are not inserted to any of the
     * following data structures. */

    /* These fields are accessed by readers who care about wildcarding. */
    const uint8_t n_indices;                   /* How many indices to use. */
    const struct flowmap index_maps[CLS_MAX_INDICES + 1]; /* Stage maps. */
    unsigned int trie_plen[CLS_MAX_TRIES];  /* Trie prefix length in 'mask'
                                             * (runtime configurable). */
    const int ports_mask_len;
    struct ccmap indices[CLS_MAX_INDICES];  /* Staged lookup indices. */
    rcu_trie_ptr ports_trie;                /* NULL if none. */

    /* These fields are accessed by all readers. */
    struct cmap rules;                      /* Contains 'cls_match'es. */
    const struct minimask mask;             /* Wildcards for fields. */
    /* 'mask' must be the last field. */
};

/* Internal representation of a rule in a "struct cls_subtable".
 *
 * The 'next' member is an element in a singly linked, null-terminated list.
 * This list links together identical "cls_match"es in order of decreasing
 * priority.  The classifier code maintains the invariant that at most one rule
 * of a given priority is visible for any given lookup version.
 */
struct cls_match {
    /* Accessed by everybody. */
    OVSRCU_TYPE(struct cls_match *) next; /* Equal, lower-priority matches. */
    OVSRCU_TYPE(struct cls_conjunction_set *) conj_set;

    /* Accessed by readers interested in wildcarding. */
    const int priority;         /* Larger numbers are higher priorities. */

    /* Accessed by all readers. */
    struct cmap_node cmap_node; /* Within struct cls_subtable 'rules'. */

    /* Rule versioning. */
    struct versions versions;

    const struct cls_rule *cls_rule;
    const struct miniflow flow; /* Matching rule. Mask is in the subtable. */
    /* 'flow' must be the last field. */
};

/* Utilities for accessing the 'cls_match' member of struct cls_rule. */
static inline struct cls_match *
get_cls_match_protected(const struct cls_rule *rule)
{
    return ovsrcu_get_protected(struct cls_match *, &rule->cls_match);
}

static inline struct cls_match *
get_cls_match(const struct cls_rule *rule)
{
    return ovsrcu_get(struct cls_match *, &rule->cls_match);
}

/* Must be RCU postponed. */
void cls_match_free_cb(struct cls_match *);

static inline void
cls_match_set_remove_version(struct cls_match *rule, ovs_version_t version)
{
    versions_set_remove_version(&rule->versions, version);
}

static inline bool
cls_match_visible_in_version(const struct cls_match *rule,
                             ovs_version_t version)
{
    return versions_visible_in_version(&rule->versions, version);
}

static inline bool
cls_match_is_eventually_invisible(const struct cls_match *rule)
{
    return versions_is_eventually_invisible(&rule->versions);
}


/* cls_match 'next' */

static inline const struct cls_match *
cls_match_next(const struct cls_match *rule)
{
    return ovsrcu_get(struct cls_match *, &rule->next);
}

static inline struct cls_match *
cls_match_next_protected(const struct cls_match *rule)
{
    return ovsrcu_get_protected(struct cls_match *, &rule->next);
}

/* Puts 'rule' in the position between 'prev' and 'next'.  If 'prev' == NULL,
 * then the 'rule' is the new list head, and if 'next' == NULL, the rule is the
 * new list tail.
 * If there are any nodes between 'prev' and 'next', they are dropped from the
 * list. */
static inline void
cls_match_insert(struct cls_match *prev, struct cls_match *next,
                 struct cls_match *rule)
{
    ovsrcu_set_hidden(&rule->next, next);

    if (prev) {
        ovsrcu_set(&prev->next, rule);
    }
}

/* Puts 'new_rule' in the position of 'old_rule', which is the next node after
 * 'prev'. If 'prev' == NULL, then the 'new_rule' is the new list head.
 *
 * The replaced cls_match still links to the later rules, and may still be
 * referenced by other threads until all other threads quiesce.  The replaced
 * rule may not be re-inserted, re-initialized, or deleted until after all
 * other threads have quiesced (use ovsrcu_postpone). */
static inline void
cls_match_replace(struct cls_match *prev,
                  struct cls_match *old_rule, struct cls_match *new_rule)
{
    cls_match_insert(prev, cls_match_next_protected(old_rule), new_rule);
}

/* Removes 'rule' following 'prev' from the list. If 'prev' is NULL, then the
 * 'rule' is a list head, and the caller is responsible for maintaining its
 * list head pointer (if any).
 *
 * Afterward, the removed rule is not linked to any more, but still links to
 * the following rules, and may still be referenced by other threads until all
 * other threads quiesce.  The removed rule may not be re-inserted,
 * re-initialized, or deleted until after all other threads have quiesced (use
 * ovsrcu_postpone).
 */
static inline void
cls_match_remove(struct cls_match *prev, struct cls_match *rule)
{
    if (prev) {
        ovsrcu_set(&prev->next, cls_match_next_protected(rule));
    }
}

#define CLS_MATCH_FOR_EACH(ITER, HEAD)                              \
    for ((ITER) = (HEAD); (ITER); (ITER) = cls_match_next(ITER))

#define CLS_MATCH_FOR_EACH_AFTER_HEAD(ITER, HEAD)   \
    CLS_MATCH_FOR_EACH(ITER, cls_match_next(HEAD))

/* Iterate cls_matches keeping the previous pointer for modifications. */
#define FOR_EACH_RULE_IN_LIST_PROTECTED(ITER, PREV, HEAD)           \
    for ((PREV) = NULL, (ITER) = (HEAD);                            \
         (ITER);                                                    \
         (PREV) = (ITER), (ITER) = cls_match_next_protected(ITER))


/* A longest-prefix match tree. */
struct trie_node {
    uint32_t prefix;           /* Prefix bits for this node, MSB first. */
    uint8_t  n_bits;           /* Never zero, except for the root node. */
    unsigned int n_rules;      /* Number of rules that have this prefix. */
    rcu_trie_ptr edges[2];     /* Both NULL if leaf. */
};

/* Max bits per node.  Must fit in struct trie_node's 'prefix'.
 * Also tested with 16, 8, and 5 to stress the implementation. */
#define TRIE_PREFIX_BITS 32

/* flow/miniflow/minimask/minimatch utilities.
 * These are only used by the classifier, so place them here to allow
 * for better optimization. */

/* Returns a hash value for the bits of 'flow' where there are 1-bits in
 * 'mask', given 'basis'.
 *
 * The hash values returned by this function are the same as those returned by
 * miniflow_hash_in_minimask(), only the form of the arguments differ. */
static inline uint32_t
flow_hash_in_minimask(const struct flow *flow, const struct minimask *mask,
                      uint32_t basis)
{
    const uint64_t *mask_values = miniflow_get_values(&mask->masks);
    const uint64_t *flow_u64 = (const uint64_t *)flow;
    const uint64_t *p = mask_values;
    uint32_t hash = basis;
    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, mask->masks.map) {
        size_t idx;

        MAP_FOR_EACH_INDEX (idx, map) {
            hash = hash_add64(hash, flow_u64[idx] & *p++);
        }
        flow_u64 += MAP_T_BITS;
    }

    return hash_finish(hash, (p - mask_values) * 8);
}

/* Returns a hash value for the bits of 'flow' where there are 1-bits in
 * 'mask', given 'basis'.
 *
 * The hash values returned by this function are the same as those returned by
 * flow_hash_in_minimask(), only the form of the arguments differ. */
static inline uint32_t
miniflow_hash_in_minimask(const struct miniflow *flow,
                          const struct minimask *mask, uint32_t basis)
{
    const uint64_t *mask_values = miniflow_get_values(&mask->masks);
    const uint64_t *p = mask_values;
    uint32_t hash = basis;
    uint64_t value;

    MINIFLOW_FOR_EACH_IN_FLOWMAP(value, flow, mask->masks.map) {
        hash = hash_add64(hash, value & *p++);
    }

    return hash_finish(hash, (p - mask_values) * 8);
}

/* Returns a hash value for the values of 'flow', indicated by 'range', where
 * there are 1-bits in 'mask', given 'basis'.  'range' must be a continuous
 * subset of the bits in 'mask''s map, representing a continuous range of the
 * minimask's mask data.  '*offset' must be the number of 64-bit units of the
 * minimask's data to skip to get to the first unit covered by 'range'. On
 * return '*offset' is updated with the number of 64-bit units of the minimask
 * consumed.
 *
 * Typically this function is called for successive ranges of minimask's masks,
 * and the first invocation passes '*offset' as zero.
 *
 * The hash values returned by this function are the same as those returned by
 * minimatch_hash_range(), only the form of the arguments differ. */
static inline uint32_t
flow_hash_in_minimask_range(const struct flow *flow,
                            const struct minimask *mask,
                            const struct flowmap range,
                            unsigned int *offset,
                            uint32_t *basis)
{
    const uint64_t *mask_values = miniflow_get_values(&mask->masks);
    const uint64_t *flow_u64 = (const uint64_t *)flow;
    const uint64_t *p = mask_values + *offset;
    uint32_t hash = *basis;
    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, range) {
        size_t idx;

        MAP_FOR_EACH_INDEX (idx, map) {
            hash = hash_add64(hash, flow_u64[idx] & *p++);
        }
        flow_u64 += MAP_T_BITS;
    }

    *basis = hash; /* Allow continuation from the unfinished value. */
    *offset = p - mask_values;
    return hash_finish(hash, *offset * 8);
}

/* Fold minimask 'mask''s wildcard mask into 'wc's wildcard mask. */
static inline void
flow_wildcards_fold_minimask(struct flow_wildcards *wc,
                             const struct minimask *mask)
{
    flow_union_with_miniflow(&wc->masks, &mask->masks);
}

/* Fold minimask 'mask''s wildcard mask into 'wc's wildcard mask for bits in
 * 'fmap'.  1-bits in 'fmap' are a subset of 1-bits in 'mask''s map. */
static inline void
flow_wildcards_fold_minimask_in_map(struct flow_wildcards *wc,
                                    const struct minimask *mask,
                                    const struct flowmap fmap)
{
    flow_union_with_miniflow_subset(&wc->masks, &mask->masks, fmap);
}

/* Returns a hash value for 'mask', given 'basis'. */
static inline uint32_t
minimask_hash(const struct minimask *mask, uint32_t basis)
{
    const uint64_t *p = miniflow_get_values(&mask->masks);
    size_t n_values = miniflow_n_values(&mask->masks);
    uint32_t hash = basis;

    for (size_t i = 0; i < n_values; i++) {
        hash = hash_add64(hash, *p++);
    }

    map_t map;
    FLOWMAP_FOR_EACH_MAP (map, mask->masks.map) {
        hash = hash_add64(hash, map);
    }

    return hash_finish(hash, n_values);
}

/* Returns a hash value for the values of 'match->flow', indicated by 'range',
 * where there are 1-bits in 'match->mask', given 'basis'.  'range' must be a
 * continuous subset of the bits in the map of 'match', representing a
 * continuous range of the mask data of 'match'.  '*offset' must be the number
 * of 64-bit units of the match data to skip to get to the first unit covered
 * by 'range'.  On return '*offset' is updated with the number of 64-bit units
 * of the match consumed.
 *
 * Typically this function is called for successive ranges of minimask's masks,
 * and the first invocation passes '*offset' as zero.
 *
 * The hash values returned by this function are the same as those returned by
 * flow_hash_in_minimask_range(), only the form of the arguments differ. */
static inline uint32_t
minimatch_hash_range(const struct minimatch *match,
                     const struct flowmap range, unsigned int *offset,
                     uint32_t *basis)
{
    const uint64_t *p = miniflow_get_values(match->flow) + *offset;
    const uint64_t *q = miniflow_get_values(&match->mask->masks) + *offset;
    unsigned int n = flowmap_n_1bits(range);
    uint32_t hash = *basis;

    for (unsigned int i = 0; i < n; i++) {
        hash = hash_add64(hash, p[i] & q[i]);
    }
    *basis = hash; /* Allow continuation from the unfinished value. */
    *offset += n;
    return hash_finish(hash, *offset * 8);
}

#endif
