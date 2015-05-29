/*
 * Copyright (c) 2014, 2015 Nicira, Inc.
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

#include "cmap.h"
#include "flow.h"
#include "hash.h"
#include "rculist.h"
#include "tag.h"

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
    const tag_type tag;       /* Tag generated from mask for partitioning. */
    const uint8_t n_indices;                   /* How many indices to use. */
    const uint8_t index_ofs[CLS_MAX_INDICES];  /* u64 segment boundaries. */
    unsigned int trie_plen[CLS_MAX_TRIES];  /* Trie prefix length in 'mask'
                                             * (runtime configurable). */
    const int ports_mask_len;
    struct cmap indices[CLS_MAX_INDICES];   /* Staged lookup indices. */
    rcu_trie_ptr ports_trie;                /* NULL if none. */

    /* These fields are accessed by all readers. */
    struct cmap rules;                      /* Contains 'cls_match'es. */
    const struct minimask mask;             /* Wildcards for fields. */
    /* 'mask' must be the last field. */
};

/* Associates a metadata value (that is, a value of the OpenFlow 1.1+ metadata
 * field) with tags for the "cls_subtable"s that contain rules that match that
 * metadata value.  */
struct cls_partition {
    struct cmap_node cmap_node; /* In struct classifier's 'partitions' map. */
    ovs_be64 metadata;          /* metadata value for this partition. */
    tag_type tags;              /* OR of each flow's cls_subtable tag. */
    struct tag_tracker tracker; /* Tracks the bits in 'tags'. */
};

/* Internal representation of a rule in a "struct cls_subtable". */
struct cls_match {
    /* Accessed by everybody. */
    struct rculist list; /* Identical, lower-priority "cls_match"es. */

    /* Accessed only by writers. */
    struct cls_partition *partition;

    /* Accessed by readers interested in wildcarding. */
    const int priority;         /* Larger numbers are higher priorities. */
    struct cmap_node index_nodes[CLS_MAX_INDICES]; /* Within subtable's
                                                    * 'indices'. */
    /* Accessed by all readers. */
    struct cmap_node cmap_node; /* Within struct cls_subtable 'rules'. */
    bool visible;
    const struct cls_rule *cls_rule;
    OVSRCU_TYPE(struct cls_conjunction_set *) conj_set;
    const struct miniflow flow; /* Matching rule. Mask is in the subtable. */
    /* 'flow' must be the last field. */
};

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

static inline uint64_t
miniflow_get_map_in_range(const struct miniflow *miniflow,
                          uint8_t start, uint8_t end, unsigned int *offset)
{
    uint64_t map = miniflow->map;
    *offset = 0;

    if (start > 0) {
        uint64_t msk = (UINT64_C(1) << start) - 1; /* 'start' LSBs set */
        *offset = count_1bits(map & msk);
        map &= ~msk;
    }
    if (end < FLOW_U64S) {
        uint64_t msk = (UINT64_C(1) << end) - 1; /* 'end' LSBs set */
        map &= msk;
    }
    return map;
}

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
    uint32_t hash;
    int idx;

    hash = basis;
    MAP_FOR_EACH_INDEX(idx, mask->masks.map) {
        hash = hash_add64(hash, flow_u64[idx] & *p++);
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
    uint64_t flow_u64;

    MINIFLOW_FOR_EACH_IN_MAP(flow_u64, flow, mask->masks.map) {
        hash = hash_add64(hash, flow_u64 & *p++);
    }

    return hash_finish(hash, (p - mask_values) * 8);
}

/* Returns a hash value for the bits of range [start, end) in 'flow',
 * where there are 1-bits in 'mask', given 'hash'.
 *
 * The hash values returned by this function are the same as those returned by
 * minimatch_hash_range(), only the form of the arguments differ. */
static inline uint32_t
flow_hash_in_minimask_range(const struct flow *flow,
                            const struct minimask *mask,
                            uint8_t start, uint8_t end, uint32_t *basis)
{
    const uint64_t *mask_values = miniflow_get_values(&mask->masks);
    const uint64_t *flow_u64 = (const uint64_t *)flow;
    unsigned int offset;
    uint64_t map;
    const uint64_t *p;
    uint32_t hash = *basis;
    int idx;

    map = miniflow_get_map_in_range(&mask->masks, start, end, &offset);
    p = mask_values + offset;
    MAP_FOR_EACH_INDEX(idx, map) {
        hash = hash_add64(hash, flow_u64[idx] & *p++);
    }

    *basis = hash; /* Allow continuation from the unfinished value. */
    return hash_finish(hash, (p - mask_values) * 8);
}

/* Fold minimask 'mask''s wildcard mask into 'wc's wildcard mask. */
static inline void
flow_wildcards_fold_minimask(struct flow_wildcards *wc,
                             const struct minimask *mask)
{
    flow_union_with_miniflow(&wc->masks, &mask->masks);
}

/* Fold minimask 'mask''s wildcard mask into 'wc's wildcard mask
 * in range [start, end). */
static inline void
flow_wildcards_fold_minimask_range(struct flow_wildcards *wc,
                                   const struct minimask *mask,
                                   uint8_t start, uint8_t end)
{
    uint64_t *dst_u64 = (uint64_t *)&wc->masks;
    unsigned int offset;
    uint64_t map;
    const uint64_t *p;
    int idx;

    map = miniflow_get_map_in_range(&mask->masks, start, end, &offset);
    p = miniflow_get_values(&mask->masks) + offset;
    MAP_FOR_EACH_INDEX(idx, map) {
        dst_u64[idx] |= *p++;
    }
}

/* Returns a hash value for 'flow', given 'basis'. */
static inline uint32_t
miniflow_hash(const struct miniflow *flow, uint32_t basis)
{
    const uint64_t *values = miniflow_get_values(flow);
    const uint64_t *p = values;
    uint32_t hash = basis;
    uint64_t hash_map = 0;
    uint64_t map;

    for (map = flow->map; map; map = zero_rightmost_1bit(map)) {
        if (*p) {
            hash = hash_add64(hash, *p);
            hash_map |= rightmost_1bit(map);
        }
        p++;
    }
    hash = hash_add64(hash, hash_map);

    return hash_finish(hash, p - values);
}

/* Returns a hash value for 'mask', given 'basis'. */
static inline uint32_t
minimask_hash(const struct minimask *mask, uint32_t basis)
{
    return miniflow_hash(&mask->masks, basis);
}

/* Returns a hash value for 'match', given 'basis'. */
static inline uint32_t
minimatch_hash(const struct minimatch *match, uint32_t basis)
{
    return miniflow_hash(&match->flow, minimask_hash(&match->mask, basis));
}

/* Returns a hash value for the bits of range [start, end) in 'minimatch',
 * given 'basis'.
 *
 * The hash values returned by this function are the same as those returned by
 * flow_hash_in_minimask_range(), only the form of the arguments differ. */
static inline uint32_t
minimatch_hash_range(const struct minimatch *match, uint8_t start, uint8_t end,
                     uint32_t *basis)
{
    unsigned int offset;
    const uint64_t *p, *q;
    uint32_t hash = *basis;
    int n, i;

    n = count_1bits(miniflow_get_map_in_range(&match->mask.masks, start, end,
                                              &offset));
    q = miniflow_get_values(&match->mask.masks) + offset;
    p = miniflow_get_values(&match->flow) + offset;

    for (i = 0; i < n; i++) {
        hash = hash_add64(hash, p[i] & q[i]);
    }
    *basis = hash; /* Allow continuation from the unfinished value. */
    return hash_finish(hash, (offset + n) * 8);
}

#endif
