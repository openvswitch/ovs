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

#include <config.h>
#include "classifier.h"
#include <errno.h>
#include <netinet/in.h>
#include "byte-order.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"
#include "cmap.h"
#include "list.h"
#include "odp-util.h"
#include "ofp-util.h"
#include "ovs-thread.h"
#include "packets.h"
#include "pvector.h"
#include "tag.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(classifier);

struct trie_node;
struct trie_ctx;

/* Ports trie depends on both ports sharing the same ovs_be32. */
#define TP_PORTS_OFS32 (offsetof(struct flow, tp_src) / 4)
BUILD_ASSERT_DECL(TP_PORTS_OFS32 == offsetof(struct flow, tp_dst) / 4);

typedef OVSRCU_TYPE(struct trie_node *) rcu_trie_ptr;

/* Prefix trie for a 'field' */
struct cls_trie {
    const struct mf_field *field; /* Trie field, or NULL. */
    rcu_trie_ptr root;            /* NULL if none. */
};

enum {
    CLS_MAX_INDICES = 3   /* Maximum number of lookup indices per subtable. */
};

struct cls_classifier {
    struct ovs_mutex mutex;
    int n_rules OVS_GUARDED;        /* Total number of rules. */
    uint8_t n_flow_segments;
    uint8_t flow_segments[CLS_MAX_INDICES]; /* Flow segment boundaries to use
                                             * for staged lookup. */
    struct cmap subtables_map;      /* Contains "struct cls_subtable"s.  */
    struct pvector subtables;
    struct cmap partitions;         /* Contains "struct cls_partition"s. */
    struct cls_trie tries[CLS_MAX_TRIES]; /* Prefix tries. */
    unsigned int n_tries;
};

/* A set of rules that all have the same fields wildcarded. */
struct cls_subtable {
    /* The fields are only used by writers and iterators. */
    struct cmap_node cmap_node; /* Within struct cls_classifier
                                 * 'subtables_map'. */

    /* The fields are only used by writers. */
    int n_rules OVS_GUARDED;                /* Number of rules, including
                                             * duplicates. */
    unsigned int max_priority OVS_GUARDED;  /* Max priority of any rule in
                                             * the subtable. */
    unsigned int max_count OVS_GUARDED;     /* Count of max_priority rules. */

    /* These fields are accessed by readers who care about wildcarding. */
    tag_type tag;       /* Tag generated from mask for partitioning (const). */
    uint8_t n_indices;                   /* How many indices to use (const). */
    uint8_t index_ofs[CLS_MAX_INDICES];   /* u32 segment boundaries (const). */
    unsigned int trie_plen[CLS_MAX_TRIES];  /* Trie prefix length in 'mask'
                                             * (runtime configurable). */
    int ports_mask_len;                     /* (const) */
    struct cmap indices[CLS_MAX_INDICES];   /* Staged lookup indices. */
    rcu_trie_ptr ports_trie;                /* NULL if none. */

    /* These fields are accessed by all readers. */
    struct cmap rules;                      /* Contains "struct cls_rule"s. */
    struct minimask mask;                   /* Wildcards for fields (const). */
    /* 'mask' must be the last field. */
};

/* Associates a metadata value (that is, a value of the OpenFlow 1.1+ metadata
 * field) with tags for the "cls_subtable"s that contain rules that match that
 * metadata value.  */
struct cls_partition {
    struct cmap_node cmap_node; /* In struct cls_classifier's 'partitions'
                                 * map. */
    ovs_be64 metadata;          /* metadata value for this partition. */
    tag_type tags;              /* OR of each flow's cls_subtable tag. */
    struct tag_tracker tracker OVS_GUARDED; /* Tracks the bits in 'tags'. */
};

/* Internal representation of a rule in a "struct cls_subtable". */
struct cls_match {
    /* Accessed only by writers and iterators. */
    struct list list OVS_GUARDED; /* List of identical, lower-priority rules. */

    /* Accessed only by writers. */
    struct cls_partition *partition OVS_GUARDED;

    /* Accessed by readers interested in wildcarding. */
    unsigned int priority;      /* Larger numbers are higher priorities. */
    struct cmap_node index_nodes[CLS_MAX_INDICES]; /* Within subtable's
                                                    * 'indices'. */
    /* Accessed by all readers. */
    struct cmap_node cmap_node; /* Within struct cls_subtable 'rules'. */
    struct cls_rule *cls_rule;
    struct miniflow flow;       /* Matching rule. Mask is in the subtable. */
    /* 'flow' must be the last field. */
};

static struct cls_match *
cls_match_alloc(struct cls_rule *rule)
{
    int count = count_1bits(rule->match.flow.map);

    struct cls_match *cls_match
        = xmalloc(sizeof *cls_match - sizeof cls_match->flow.inline_values
                  + MINIFLOW_VALUES_SIZE(count));

    cls_match->cls_rule = rule;
    miniflow_clone_inline(&cls_match->flow, &rule->match.flow, count);
    cls_match->priority = rule->priority;
    rule->cls_match = cls_match;

    return cls_match;
}

static struct cls_subtable *find_subtable(const struct cls_classifier *cls,
                                          const struct minimask *)
    OVS_REQUIRES(cls->mutex);
static struct cls_subtable *insert_subtable(struct cls_classifier *cls,
                                            const struct minimask *)
    OVS_REQUIRES(cls->mutex);
static void destroy_subtable(struct cls_classifier *cls, struct cls_subtable *)
    OVS_REQUIRES(cls->mutex);
static struct cls_match *insert_rule(struct cls_classifier *cls,
                                     struct cls_subtable *, struct cls_rule *)
    OVS_REQUIRES(cls->mutex);

static struct cls_match *find_match_wc(const struct cls_subtable *,
                                       const struct flow *, struct trie_ctx *,
                                       unsigned int n_tries,
                                       struct flow_wildcards *);
static struct cls_match *find_equal(struct cls_subtable *,
                                    const struct miniflow *, uint32_t hash);

/* Iterates RULE over HEAD and all of the cls_rules on HEAD->list.
 * Classifier's mutex must be held while iterating, as the list is
 * protoceted by it. */
#define FOR_EACH_RULE_IN_LIST(RULE, HEAD)                               \
    for ((RULE) = (HEAD); (RULE) != NULL; (RULE) = next_rule_in_list(RULE))
#define FOR_EACH_RULE_IN_LIST_SAFE(RULE, NEXT, HEAD)                    \
    for ((RULE) = (HEAD);                                               \
         (RULE) != NULL && ((NEXT) = next_rule_in_list(RULE), true);    \
         (RULE) = (NEXT))

static struct cls_match *next_rule_in_list__(struct cls_match *);
static struct cls_match *next_rule_in_list(struct cls_match *);

static unsigned int minimask_get_prefix_len(const struct minimask *,
                                            const struct mf_field *);
static void trie_init(struct cls_classifier *cls, int trie_idx,
                      const struct mf_field *)
    OVS_REQUIRES(cls->mutex);
static unsigned int trie_lookup(const struct cls_trie *, const struct flow *,
                                unsigned int *checkbits);
static unsigned int trie_lookup_value(const rcu_trie_ptr *,
                                      const ovs_be32 value[],
                                      unsigned int value_bits,
                                      unsigned int *checkbits);
static void trie_destroy(rcu_trie_ptr *);
static void trie_insert(struct cls_trie *, const struct cls_rule *, int mlen);
static void trie_insert_prefix(rcu_trie_ptr *, const ovs_be32 *prefix,
                               int mlen);
static void trie_remove(struct cls_trie *, const struct cls_rule *, int mlen);
static void trie_remove_prefix(rcu_trie_ptr *, const ovs_be32 *prefix,
                               int mlen);
static void mask_set_prefix_bits(struct flow_wildcards *, uint8_t be32ofs,
                                 unsigned int n_bits);
static bool mask_prefix_bits_set(const struct flow_wildcards *,
                                 uint8_t be32ofs, unsigned int n_bits);

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
    if (end < FLOW_U32S) {
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
    const uint32_t *mask_values = miniflow_get_u32_values(&mask->masks);
    const uint32_t *flow_u32 = (const uint32_t *)flow;
    const uint32_t *p = mask_values;
    uint32_t hash;
    uint64_t map;

    hash = basis;
    for (map = mask->masks.map; map; map = zero_rightmost_1bit(map)) {
        hash = hash_add(hash, flow_u32[raw_ctz(map)] & *p++);
    }

    return hash_finish(hash, (p - mask_values) * 4);
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
    const uint32_t *mask_values = miniflow_get_u32_values(&mask->masks);
    const uint32_t *p = mask_values;
    uint32_t hash = basis;
    uint32_t flow_u32;

    MINIFLOW_FOR_EACH_IN_MAP(flow_u32, flow, mask->masks.map) {
        hash = hash_add(hash, flow_u32 & *p++);
    }

    return hash_finish(hash, (p - mask_values) * 4);
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
    const uint32_t *mask_values = miniflow_get_u32_values(&mask->masks);
    const uint32_t *flow_u32 = (const uint32_t *)flow;
    unsigned int offset;
    uint64_t map = miniflow_get_map_in_range(&mask->masks, start, end,
                                             &offset);
    const uint32_t *p = mask_values + offset;
    uint32_t hash = *basis;

    for (; map; map = zero_rightmost_1bit(map)) {
        hash = hash_add(hash, flow_u32[raw_ctz(map)] & *p++);
    }

    *basis = hash; /* Allow continuation from the unfinished value. */
    return hash_finish(hash, (p - mask_values) * 4);
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
    uint32_t *dst_u32 = (uint32_t *)&wc->masks;
    unsigned int offset;
    uint64_t map = miniflow_get_map_in_range(&mask->masks, start, end,
                                             &offset);
    const uint32_t *p = miniflow_get_u32_values(&mask->masks) + offset;

    for (; map; map = zero_rightmost_1bit(map)) {
        dst_u32[raw_ctz(map)] |= *p++;
    }
}

/* Returns a hash value for 'flow', given 'basis'. */
static inline uint32_t
miniflow_hash(const struct miniflow *flow, uint32_t basis)
{
    const uint32_t *values = miniflow_get_u32_values(flow);
    const uint32_t *p = values;
    uint32_t hash = basis;
    uint64_t hash_map = 0;
    uint64_t map;

    for (map = flow->map; map; map = zero_rightmost_1bit(map)) {
        if (*p) {
            hash = hash_add(hash, *p);
            hash_map |= rightmost_1bit(map);
        }
        p++;
    }
    hash = hash_add(hash, hash_map);
    hash = hash_add(hash, hash_map >> 32);

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
    const uint32_t *p, *q;
    uint32_t hash = *basis;
    int n, i;

    n = count_1bits(miniflow_get_map_in_range(&match->mask.masks, start, end,
                                              &offset));
    q = miniflow_get_u32_values(&match->mask.masks) + offset;
    p = miniflow_get_u32_values(&match->flow) + offset;

    for (i = 0; i < n; i++) {
        hash = hash_add(hash, p[i] & q[i]);
    }
    *basis = hash; /* Allow continuation from the unfinished value. */
    return hash_finish(hash, (offset + n) * 4);
}


/* cls_rule. */

/* Initializes 'rule' to match packets specified by 'match' at the given
 * 'priority'.  'match' must satisfy the invariant described in the comment at
 * the definition of struct match.
 *
 * The caller must eventually destroy 'rule' with cls_rule_destroy().
 *
 * (OpenFlow uses priorities between 0 and UINT16_MAX, inclusive, but
 * internally Open vSwitch supports a wider range.) */
void
cls_rule_init(struct cls_rule *rule,
              const struct match *match, unsigned int priority)
{
    minimatch_init(&rule->match, match);
    rule->priority = priority;
    rule->cls_match = NULL;
}

/* Same as cls_rule_init() for initialization from a "struct minimatch". */
void
cls_rule_init_from_minimatch(struct cls_rule *rule,
                             const struct minimatch *match,
                             unsigned int priority)
{
    minimatch_clone(&rule->match, match);
    rule->priority = priority;
    rule->cls_match = NULL;
}

/* Initializes 'dst' as a copy of 'src'.
 *
 * The caller must eventually destroy 'dst' with cls_rule_destroy(). */
void
cls_rule_clone(struct cls_rule *dst, const struct cls_rule *src)
{
    minimatch_clone(&dst->match, &src->match);
    dst->priority = src->priority;
    dst->cls_match = NULL;
}

/* Initializes 'dst' with the data in 'src', destroying 'src'.
 *
 * The caller must eventually destroy 'dst' with cls_rule_destroy(). */
void
cls_rule_move(struct cls_rule *dst, struct cls_rule *src)
{
    minimatch_move(&dst->match, &src->match);
    dst->priority = src->priority;
    dst->cls_match = NULL;
}

/* Frees memory referenced by 'rule'.  Doesn't free 'rule' itself (it's
 * normally embedded into a larger structure).
 *
 * ('rule' must not currently be in a classifier.) */
void
cls_rule_destroy(struct cls_rule *rule)
{
    ovs_assert(!rule->cls_match);
    minimatch_destroy(&rule->match);
}

/* Returns true if 'a' and 'b' match the same packets at the same priority,
 * false if they differ in some way. */
bool
cls_rule_equal(const struct cls_rule *a, const struct cls_rule *b)
{
    return a->priority == b->priority && minimatch_equal(&a->match, &b->match);
}

/* Returns a hash value for 'rule', folding in 'basis'. */
uint32_t
cls_rule_hash(const struct cls_rule *rule, uint32_t basis)
{
    return minimatch_hash(&rule->match, hash_int(rule->priority, basis));
}

/* Appends a string describing 'rule' to 's'. */
void
cls_rule_format(const struct cls_rule *rule, struct ds *s)
{
    minimatch_format(&rule->match, s, rule->priority);
}

/* Returns true if 'rule' matches every packet, false otherwise. */
bool
cls_rule_is_catchall(const struct cls_rule *rule)
{
    return minimask_is_catchall(&rule->match.mask);
}

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
void
classifier_init(struct classifier *cls_, const uint8_t *flow_segments)
    OVS_EXCLUDED(cls_->cls->mutex)
{
    struct cls_classifier *cls = xmalloc(sizeof *cls);

    ovs_mutex_init(&cls->mutex);

    ovs_mutex_lock(&cls->mutex);
    cls_->cls = cls;

    cls->n_rules = 0;
    cmap_init(&cls->subtables_map);
    pvector_init(&cls->subtables);
    cmap_init(&cls->partitions);
    cls->n_flow_segments = 0;
    if (flow_segments) {
        while (cls->n_flow_segments < CLS_MAX_INDICES
               && *flow_segments < FLOW_U32S) {
            cls->flow_segments[cls->n_flow_segments++] = *flow_segments++;
        }
    }
    cls->n_tries = 0;
    for (int i = 0; i < CLS_MAX_TRIES; i++) {
        trie_init(cls, i, NULL);
    }
    ovs_mutex_unlock(&cls->mutex);
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility.
 * May only be called after all the readers have been terminated. */
void
classifier_destroy(struct classifier *cls_)
    OVS_EXCLUDED(cls_->cls->mutex)
{
    if (cls_) {
        struct cls_classifier *cls = cls_->cls;
        struct cls_partition *partition, *next_partition;
        struct cls_subtable *subtable, *next_subtable;
        int i;

        if (!cls) {
            return;
        }

        ovs_mutex_lock(&cls->mutex);
        for (i = 0; i < cls->n_tries; i++) {
            trie_destroy(&cls->tries[i].root);
        }

        CMAP_FOR_EACH_SAFE (subtable, next_subtable, cmap_node,
                            &cls->subtables_map) {
            destroy_subtable(cls, subtable);
        }
        cmap_destroy(&cls->subtables_map);

        CMAP_FOR_EACH_SAFE (partition, next_partition, cmap_node,
                            &cls->partitions) {
            ovsrcu_postpone(free, partition);
        }
        cmap_destroy(&cls->partitions);

        pvector_destroy(&cls->subtables);
        ovs_mutex_unlock(&cls->mutex);
        ovs_mutex_destroy(&cls->mutex);
        free(cls);
    }
}

/* We use uint64_t as a set for the fields below. */
BUILD_ASSERT_DECL(MFF_N_IDS <= 64);

/* Set the fields for which prefix lookup should be performed. */
bool
classifier_set_prefix_fields(struct classifier *cls_,
                             const enum mf_field_id *trie_fields,
                             unsigned int n_fields)
    OVS_EXCLUDED(cls_->cls->mutex)
{
    struct cls_classifier *cls = cls_->cls;
    uint64_t fields = 0;
    const struct mf_field * new_fields[CLS_MAX_TRIES];
    int i, n_tries = 0;
    bool changed = false;

    ovs_mutex_lock(&cls->mutex);
    for (i = 0; i < n_fields && n_tries < CLS_MAX_TRIES; i++) {
        const struct mf_field *field = mf_from_id(trie_fields[i]);
        if (field->flow_be32ofs < 0 || field->n_bits % 32) {
            /* Incompatible field.  This is the only place where we
             * enforce these requirements, but the rest of the trie code
             * depends on the flow_be32ofs to be non-negative and the
             * field length to be a multiple of 32 bits. */
            continue;
        }

        if (fields & (UINT64_C(1) << trie_fields[i])) {
            /* Duplicate field, there is no need to build more than
             * one index for any one field. */
            continue;
        }
        fields |= UINT64_C(1) << trie_fields[i];

        new_fields[n_tries] = NULL;
        if (n_tries >= cls->n_tries || field != cls->tries[n_tries].field) {
            new_fields[n_tries] = field;
            changed = true;
        }
        n_tries++;
    }

    if (changed || n_tries < cls->n_tries) {
        struct cls_subtable *subtable;

        /* Trie configuration needs to change.  Disable trie lookups
         * for the tries that are changing and wait all the current readers
         * with the old configuration to be done. */
        changed = false;
        CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) {
            for (i = 0; i < cls->n_tries; i++) {
                if ((i < n_tries && new_fields[i]) || i >= n_tries) {
                    if (subtable->trie_plen[i]) {
                        subtable->trie_plen[i] = 0;
                        changed = true;
                    }
                }
            }
        }
        /* Synchronize if any readers were using tries.  The readers may
         * temporarily function without the trie lookup based optimizations. */
        if (changed) {
            /* ovsrcu_synchronize() functions as a memory barrier, so it does
             * not matter that subtable->trie_plen is not atomic. */
            ovsrcu_synchronize();
        }

        /* Now set up the tries. */
        for (i = 0; i < n_tries; i++) {
            if (new_fields[i]) {
                trie_init(cls, i, new_fields[i]);
            }
        }
        /* Destroy the rest, if any. */
        for (; i < cls->n_tries; i++) {
            trie_init(cls, i, NULL);
        }

        cls->n_tries = n_tries;
        ovs_mutex_unlock(&cls->mutex);
        return true;
    }

    ovs_mutex_unlock(&cls->mutex);
    return false; /* No change. */
}

static void
trie_init(struct cls_classifier *cls, int trie_idx,
          const struct mf_field *field)
    OVS_REQUIRES(cls->mutex)
{
    struct cls_trie *trie = &cls->tries[trie_idx];
    struct cls_subtable *subtable;

    if (trie_idx < cls->n_tries) {
        trie_destroy(&trie->root);
    } else {
        ovsrcu_set_hidden(&trie->root, NULL);
    }
    trie->field = field;

    /* Add existing rules to the new trie. */
    CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) {
        unsigned int plen;

        plen = field ? minimask_get_prefix_len(&subtable->mask, field) : 0;
        if (plen) {
            struct cls_match *head;

            CMAP_FOR_EACH (head, cmap_node, &subtable->rules) {
                struct cls_match *match;

                FOR_EACH_RULE_IN_LIST (match, head) {
                    trie_insert(trie, match->cls_rule, plen);
                }
            }
        }
        /* Initialize subtable's prefix length on this field.  This will
         * allow readers to use the trie. */
        atomic_thread_fence(memory_order_release);
        subtable->trie_plen[trie_idx] = plen;
    }
}

/* Returns true if 'cls' contains no classification rules, false otherwise.
 * Checking the cmap requires no locking. */
bool
classifier_is_empty(const struct classifier *cls)
{
    return cmap_is_empty(&cls->cls->subtables_map);
}

/* Returns the number of rules in 'cls'. */
int
classifier_count(const struct classifier *cls)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    /* n_rules is an int, so in the presence of concurrent writers this will
     * return either the old or a new value. */
    return cls->cls->n_rules;
}

static uint32_t
hash_metadata(ovs_be64 metadata_)
{
    uint64_t metadata = (OVS_FORCE uint64_t) metadata_;
    return hash_uint64(metadata);
}

static struct cls_partition *
find_partition(const struct cls_classifier *cls, ovs_be64 metadata,
               uint32_t hash)
{
    struct cls_partition *partition;

    CMAP_FOR_EACH_WITH_HASH (partition, cmap_node, hash, &cls->partitions) {
        if (partition->metadata == metadata) {
            return partition;
        }
    }

    return NULL;
}

static struct cls_partition *
create_partition(struct cls_classifier *cls, struct cls_subtable *subtable,
                 ovs_be64 metadata)
    OVS_REQUIRES(cls->mutex)
{
    uint32_t hash = hash_metadata(metadata);
    struct cls_partition *partition = find_partition(cls, metadata, hash);
    if (!partition) {
        partition = xmalloc(sizeof *partition);
        partition->metadata = metadata;
        partition->tags = 0;
        tag_tracker_init(&partition->tracker);
        cmap_insert(&cls->partitions, &partition->cmap_node, hash);
    }
    tag_tracker_add(&partition->tracker, &partition->tags, subtable->tag);
    return partition;
}

static inline ovs_be32 minimatch_get_ports(const struct minimatch *match)
{
    /* Could optimize to use the same map if needed for fast path. */
    return MINIFLOW_GET_BE32(&match->flow, tp_src)
        & MINIFLOW_GET_BE32(&match->mask.masks, tp_src);
}

/* Inserts 'rule' into 'cls'.  Until 'rule' is removed from 'cls', the caller
 * must not modify or free it.
 *
 * If 'cls' already contains an identical rule (including wildcards, values of
 * fixed fields, and priority), replaces the old rule by 'rule' and returns the
 * rule that was replaced.  The caller takes ownership of the returned rule and
 * is thus responsible for destroying it with cls_rule_destroy(), freeing the
 * memory block in which it resides, etc., as necessary.
 *
 * Returns NULL if 'cls' does not contain a rule with an identical key, after
 * inserting the new rule.  In this case, no rules are displaced by the new
 * rule, even rules that cannot have any effect because the new rule matches a
 * superset of their flows and has higher priority. */
struct cls_rule *
classifier_replace(struct classifier *cls_, struct cls_rule *rule)
    OVS_EXCLUDED(cls_->cls->mutex)
{
    struct cls_classifier *cls = cls_->cls;
    struct cls_match *old_rule;
    struct cls_subtable *subtable;
    struct cls_rule *old_cls_rule = NULL;

    ovs_mutex_lock(&cls->mutex);
    subtable = find_subtable(cls, &rule->match.mask);
    if (!subtable) {
        subtable = insert_subtable(cls, &rule->match.mask);
    }

    old_rule = insert_rule(cls, subtable, rule);
    if (!old_rule) {
        old_cls_rule = NULL;

        rule->cls_match->partition = NULL;
        if (minimask_get_metadata_mask(&rule->match.mask) == OVS_BE64_MAX) {
            ovs_be64 metadata = miniflow_get_metadata(&rule->match.flow);
            rule->cls_match->partition = create_partition(cls, subtable,
                                                          metadata);
        }

        cls->n_rules++;

        for (int i = 0; i < cls->n_tries; i++) {
            if (subtable->trie_plen[i]) {
                trie_insert(&cls->tries[i], rule, subtable->trie_plen[i]);
            }
        }

        /* Ports trie. */
        if (subtable->ports_mask_len) {
            /* We mask the value to be inserted to always have the wildcarded
             * bits in known (zero) state, so we can include them in comparison
             * and they will always match (== their original value does not
             * matter). */
            ovs_be32 masked_ports = minimatch_get_ports(&rule->match);

            trie_insert_prefix(&subtable->ports_trie, &masked_ports,
                               subtable->ports_mask_len);
        }
    } else {
        old_cls_rule = old_rule->cls_rule;
        rule->cls_match->partition = old_rule->partition;
        old_cls_rule->cls_match = NULL;

        /* 'old_rule' contains a cmap_node, which may not be freed
         * immediately. */
        ovsrcu_postpone(free, old_rule);
    }
    ovs_mutex_unlock(&cls->mutex);
    return old_cls_rule;
}

/* Inserts 'rule' into 'cls'.  Until 'rule' is removed from 'cls', the caller
 * must not modify or free it.
 *
 * 'cls' must not contain an identical rule (including wildcards, values of
 * fixed fields, and priority).  Use classifier_find_rule_exactly() to find
 * such a rule. */
void
classifier_insert(struct classifier *cls, struct cls_rule *rule)
{
    struct cls_rule *displaced_rule = classifier_replace(cls, rule);
    ovs_assert(!displaced_rule);
}

/* Removes 'rule' from 'cls'.  It is the caller's responsibility to destroy
 * 'rule' with cls_rule_destroy(), freeing the memory block in which 'rule'
 * resides, etc., as necessary. */
void
classifier_remove(struct classifier *cls_, struct cls_rule *rule)
    OVS_EXCLUDED(cls_->cls->mutex)
{
    struct cls_classifier *cls = cls_->cls;
    struct cls_partition *partition;
    struct cls_match *cls_match = rule->cls_match;
    struct cls_match *head;
    struct cls_subtable *subtable;
    int i;
    uint32_t basis = 0, hash, ihash[CLS_MAX_INDICES];
    uint8_t prev_be32ofs = 0;

    ovs_assert(cls_match);

    ovs_mutex_lock(&cls->mutex);
    subtable = find_subtable(cls, &rule->match.mask);
    ovs_assert(subtable);

    if (subtable->ports_mask_len) {
        ovs_be32 masked_ports = minimatch_get_ports(&rule->match);

        trie_remove_prefix(&subtable->ports_trie,
                           &masked_ports, subtable->ports_mask_len);
    }
    for (i = 0; i < cls->n_tries; i++) {
        if (subtable->trie_plen[i]) {
            trie_remove(&cls->tries[i], rule, subtable->trie_plen[i]);
        }
    }

    /* Remove rule node from indices. */
    for (i = 0; i < subtable->n_indices; i++) {
        ihash[i] = minimatch_hash_range(&rule->match, prev_be32ofs,
                                        subtable->index_ofs[i], &basis);
        cmap_remove(&subtable->indices[i], &cls_match->index_nodes[i],
                    ihash[i]);
        prev_be32ofs = subtable->index_ofs[i];
    }
    hash = minimatch_hash_range(&rule->match, prev_be32ofs, FLOW_U32S, &basis);

    head = find_equal(subtable, &rule->match.flow, hash);
    if (head != cls_match) {
        list_remove(&cls_match->list);
    } else if (list_is_empty(&cls_match->list)) {
        cmap_remove(&subtable->rules, &cls_match->cmap_node, hash);
    } else {
        struct cls_match *next = CONTAINER_OF(cls_match->list.next,
                                              struct cls_match, list);

        list_remove(&cls_match->list);
        cmap_replace(&subtable->rules, &cls_match->cmap_node,
                     &next->cmap_node, hash);
    }

    partition = cls_match->partition;
    if (partition) {
        tag_tracker_subtract(&partition->tracker, &partition->tags,
                             subtable->tag);
        if (!partition->tags) {
            cmap_remove(&cls->partitions, &partition->cmap_node,
                        hash_metadata(partition->metadata));
            ovsrcu_postpone(free, partition);
        }
    }

    if (--subtable->n_rules == 0) {
        destroy_subtable(cls, subtable);
    } else if (subtable->max_priority == cls_match->priority
               && --subtable->max_count == 0) {
        /* Find the new 'max_priority' and 'max_count'. */
        struct cls_match *head;
        unsigned int max_priority = 0;

        CMAP_FOR_EACH (head, cmap_node, &subtable->rules) {
            if (head->priority > max_priority) {
                max_priority = head->priority;
                subtable->max_count = 1;
            } else if (head->priority == max_priority) {
                ++subtable->max_count;
            }
        }
        subtable->max_priority = max_priority;
        pvector_change_priority(&cls->subtables, subtable, max_priority);
    }

    cls->n_rules--;

    rule->cls_match = NULL;
    ovsrcu_postpone(free, cls_match);
    ovs_mutex_unlock(&cls->mutex);
}

/* Prefix tree context.  Valid when 'lookup_done' is true.  Can skip all
 * subtables which have more than 'match_plen' bits in their corresponding
 * field at offset 'be32ofs'.  If skipped, 'maskbits' prefix bits should be
 * unwildcarded to quarantee datapath flow matches only packets it should. */
struct trie_ctx {
    const struct cls_trie *trie;
    bool lookup_done;        /* Status of the lookup. */
    uint8_t be32ofs;         /* U32 offset of the field in question. */
    unsigned int match_plen; /* Longest prefix than could possibly match. */
    unsigned int maskbits;   /* Prefix length needed to avoid false matches. */
};

static void
trie_ctx_init(struct trie_ctx *ctx, const struct cls_trie *trie)
{
    ctx->trie = trie;
    ctx->be32ofs = trie->field->flow_be32ofs;
    ctx->lookup_done = false;
}

/* Finds and returns the highest-priority rule in 'cls' that matches 'flow'.
 * Returns a null pointer if no rules in 'cls' match 'flow'.  If multiple rules
 * of equal priority match 'flow', returns one arbitrarily.
 *
 * If a rule is found and 'wc' is non-null, bitwise-OR's 'wc' with the
 * set of bits that were significant in the lookup.  At some point
 * earlier, 'wc' should have been initialized (e.g., by
 * flow_wildcards_init_catchall()). */
struct cls_rule *
classifier_lookup(const struct classifier *cls_, const struct flow *flow,
                  struct flow_wildcards *wc)
{
    struct cls_classifier *cls = cls_->cls;
    const struct cls_partition *partition;
    tag_type tags;
    int64_t best_priority = -1;
    const struct cls_match *best;
    struct trie_ctx trie_ctx[CLS_MAX_TRIES];
    struct cls_subtable *subtable;

    /* Synchronize for cls->n_tries and subtable->trie_plen.  They can change
     * when table configuration changes, which happens typically only on
     * startup. */
    atomic_thread_fence(memory_order_acquire);

    /* Determine 'tags' such that, if 'subtable->tag' doesn't intersect them,
     * then 'flow' cannot possibly match in 'subtable':
     *
     *     - If flow->metadata maps to a given 'partition', then we can use
     *       'tags' for 'partition->tags'.
     *
     *     - If flow->metadata has no partition, then no rule in 'cls' has an
     *       exact-match for flow->metadata.  That means that we don't need to
     *       search any subtable that includes flow->metadata in its mask.
     *
     * In either case, we always need to search any cls_subtables that do not
     * include flow->metadata in its mask.  One way to do that would be to
     * check the "cls_subtable"s explicitly for that, but that would require an
     * extra branch per subtable.  Instead, we mark such a cls_subtable's
     * 'tags' as TAG_ALL and make sure that 'tags' is never empty.  This means
     * that 'tags' always intersects such a cls_subtable's 'tags', so we don't
     * need a special case.
     */
    partition = (cmap_is_empty(&cls->partitions)
                 ? NULL
                 : find_partition(cls, flow->metadata,
                                  hash_metadata(flow->metadata)));
    tags = partition ? partition->tags : TAG_ARBITRARY;

    /* Initialize trie contexts for match_find_wc(). */
    for (int i = 0; i < cls->n_tries; i++) {
        trie_ctx_init(&trie_ctx[i], &cls->tries[i]);
    }

    best = NULL;
    PVECTOR_FOR_EACH_PRIORITY(subtable, best_priority, 2,
                              sizeof(struct cls_subtable), &cls->subtables) {
        struct cls_match *rule;

        if (!tag_intersects(tags, subtable->tag)) {
            continue;
        }

        rule = find_match_wc(subtable, flow, trie_ctx, cls->n_tries, wc);
        if (rule && (int64_t)rule->priority > best_priority) {
            best_priority = (int64_t)rule->priority;
            best = rule;
        }
    }

    return best ? best->cls_rule : NULL;
}

/* Returns true if 'target' satisifies 'match', that is, if each bit for which
 * 'match' specifies a particular value has the correct value in 'target'.
 *
 * 'flow' and 'mask' have the same mask! */
static bool
miniflow_and_mask_matches_miniflow(const struct miniflow *flow,
                                   const struct minimask *mask,
                                   const struct miniflow *target)
{
    const uint32_t *flowp = miniflow_get_u32_values(flow);
    const uint32_t *maskp = miniflow_get_u32_values(&mask->masks);
    uint32_t target_u32;

    MINIFLOW_FOR_EACH_IN_MAP(target_u32, target, mask->masks.map) {
        if ((*flowp++ ^ target_u32) & *maskp++) {
            return false;
        }
    }

    return true;
}

static inline struct cls_match *
find_match_miniflow(const struct cls_subtable *subtable,
                    const struct miniflow *flow,
                    uint32_t hash)
{
    struct cls_match *rule;

    CMAP_FOR_EACH_WITH_HASH (rule, cmap_node, hash, &subtable->rules) {
        if (miniflow_and_mask_matches_miniflow(&rule->flow, &subtable->mask,
                                               flow)) {
            return rule;
        }
    }

    return NULL;
}

/* For each miniflow in 'flows' performs a classifier lookup writing the result
 * into the corresponding slot in 'rules'.  If a particular entry in 'flows' is
 * NULL it is skipped.
 *
 * This function is optimized for use in the userspace datapath and therefore
 * does not implement a lot of features available in the standard
 * classifier_lookup() function.  Specifically, it does not implement
 * priorities, instead returning any rule which matches the flow. */
void
classifier_lookup_miniflow_batch(const struct classifier *cls_,
                                 const struct miniflow **flows,
                                 struct cls_rule **rules, size_t len)
{
    struct cls_classifier *cls = cls_->cls;
    struct cls_subtable *subtable;
    size_t i, begin = 0;

    memset(rules, 0, len * sizeof *rules);
    PVECTOR_FOR_EACH (subtable, &cls->subtables) {
        for (i = begin; i < len; i++) {
            struct cls_match *match;
            uint32_t hash;

            if (OVS_UNLIKELY(rules[i] || !flows[i])) {
                continue;
            }

            hash = miniflow_hash_in_minimask(flows[i], &subtable->mask, 0);
            match = find_match_miniflow(subtable, flows[i], hash);
            if (OVS_UNLIKELY(match)) {
                rules[i] = match->cls_rule;
            }
        }

        while (begin < len && (rules[begin] || !flows[begin])) {
            begin++;
        }
        if (begin >= len) {
            break;
        }
    }
}

/* Finds and returns a rule in 'cls' with exactly the same priority and
 * matching criteria as 'target'.  Returns a null pointer if 'cls' doesn't
 * contain an exact match. */
struct cls_rule *
classifier_find_rule_exactly(const struct classifier *cls_,
                             const struct cls_rule *target)
    OVS_EXCLUDED(cls_->cls->mutex)
{
    struct cls_classifier *cls = cls_->cls;
    struct cls_match *head, *rule;
    struct cls_subtable *subtable;

    ovs_mutex_lock(&cls->mutex);
    subtable = find_subtable(cls, &target->match.mask);
    if (!subtable) {
        goto out;
    }

    /* Skip if there is no hope. */
    if (target->priority > subtable->max_priority) {
        goto out;
    }

    head = find_equal(subtable, &target->match.flow,
                      miniflow_hash_in_minimask(&target->match.flow,
                                                &target->match.mask, 0));
    FOR_EACH_RULE_IN_LIST (rule, head) {
        if (target->priority >= rule->priority) {
            ovs_mutex_unlock(&cls->mutex);
            return target->priority == rule->priority ? rule->cls_rule : NULL;
        }
    }
out:
    ovs_mutex_unlock(&cls->mutex);
    return NULL;
}

/* Finds and returns a rule in 'cls' with priority 'priority' and exactly the
 * same matching criteria as 'target'.  Returns a null pointer if 'cls' doesn't
 * contain an exact match. */
struct cls_rule *
classifier_find_match_exactly(const struct classifier *cls,
                              const struct match *target,
                              unsigned int priority)
{
    struct cls_rule *retval;
    struct cls_rule cr;

    cls_rule_init(&cr, target, priority);
    retval = classifier_find_rule_exactly(cls, &cr);
    cls_rule_destroy(&cr);

    return retval;
}

/* Checks if 'target' would overlap any other rule in 'cls'.  Two rules are
 * considered to overlap if both rules have the same priority and a packet
 * could match both. */
bool
classifier_rule_overlaps(const struct classifier *cls_,
                         const struct cls_rule *target)
    OVS_EXCLUDED(cls_->cls->mutex)
{
    struct cls_classifier *cls = cls_->cls;
    struct cls_subtable *subtable;
    int64_t stop_at_priority = (int64_t)target->priority - 1;

    ovs_mutex_lock(&cls->mutex);
    /* Iterate subtables in the descending max priority order. */
    PVECTOR_FOR_EACH_PRIORITY (subtable, stop_at_priority, 2,
                               sizeof(struct cls_subtable), &cls->subtables) {
        uint32_t storage[FLOW_U32S];
        struct minimask mask;
        struct cls_match *head;

        minimask_combine(&mask, &target->match.mask, &subtable->mask, storage);
        CMAP_FOR_EACH (head, cmap_node, &subtable->rules) {
            struct cls_match *rule;

            FOR_EACH_RULE_IN_LIST (rule, head) {
                if (rule->priority < target->priority) {
                    break; /* Rules in descending priority order. */
                }
                if (rule->priority == target->priority
                    && miniflow_equal_in_minimask(&target->match.flow,
                                                  &rule->flow, &mask)) {
                    ovs_mutex_unlock(&cls->mutex);
                    return true;
                }
            }
        }
    }

    ovs_mutex_unlock(&cls->mutex);
    return false;
}

/* Returns true if 'rule' exactly matches 'criteria' or if 'rule' is more
 * specific than 'criteria'.  That is, 'rule' matches 'criteria' and this
 * function returns true if, for every field:
 *
 *   - 'criteria' and 'rule' specify the same (non-wildcarded) value for the
 *     field, or
 *
 *   - 'criteria' wildcards the field,
 *
 * Conversely, 'rule' does not match 'criteria' and this function returns false
 * if, for at least one field:
 *
 *   - 'criteria' and 'rule' specify different values for the field, or
 *
 *   - 'criteria' specifies a value for the field but 'rule' wildcards it.
 *
 * Equivalently, the truth table for whether a field matches is:
 *
 *                                     rule
 *
 *                   c         wildcard    exact
 *                   r        +---------+---------+
 *                   i   wild |   yes   |   yes   |
 *                   t   card |         |         |
 *                   e        +---------+---------+
 *                   r  exact |    no   |if values|
 *                   i        |         |are equal|
 *                   a        +---------+---------+
 *
 * This is the matching rule used by OpenFlow 1.0 non-strict OFPT_FLOW_MOD
 * commands and by OpenFlow 1.0 aggregate and flow stats.
 *
 * Ignores rule->priority. */
bool
cls_rule_is_loose_match(const struct cls_rule *rule,
                        const struct minimatch *criteria)
{
    return (!minimask_has_extra(&rule->match.mask, &criteria->mask)
            && miniflow_equal_in_minimask(&rule->match.flow, &criteria->flow,
                                          &criteria->mask));
}

/* Iteration. */

static bool
rule_matches(const struct cls_match *rule, const struct cls_rule *target)
{
    return (!target
            || miniflow_equal_in_minimask(&rule->flow,
                                          &target->match.flow,
                                          &target->match.mask));
}

static struct cls_match *
search_subtable(const struct cls_subtable *subtable,
                struct cls_cursor *cursor)
{
    if (!cursor->target
        || !minimask_has_extra(&subtable->mask, &cursor->target->match.mask)) {
        struct cls_match *rule;

        CMAP_CURSOR_FOR_EACH (rule, cmap_node, &cursor->rules,
                              &subtable->rules) {
            if (rule_matches(rule, cursor->target)) {
                return rule;
            }
        }
    }
    return NULL;
}

/* Initializes 'cursor' for iterating through rules in 'cls', and returns the
 * first matching cls_rule via '*pnode', or NULL if there are no matches.
 *
 *     - If 'target' is null, the cursor will visit every rule in 'cls'.
 *
 *     - If 'target' is nonnull, the cursor will visit each 'rule' in 'cls'
 *       such that cls_rule_is_loose_match(rule, target) returns true.
 *
 * Ignores target->priority. */
struct cls_cursor cls_cursor_init(const struct classifier *cls,
                                  const struct cls_rule *target,
                                  void **pnode, const void *offset, bool safe)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct cls_cursor cursor;
    struct cls_subtable *subtable;
    struct cls_rule *cls_rule = NULL;

    cursor.safe = safe;
    cursor.cls = cls->cls;
    cursor.target = target && !cls_rule_is_catchall(target) ? target : NULL;

    /* Find first rule. */
    ovs_mutex_lock(&cursor.cls->mutex);
    CMAP_CURSOR_FOR_EACH (subtable, cmap_node, &cursor.subtables,
                          &cursor.cls->subtables_map) {
        struct cls_match *rule = search_subtable(subtable, &cursor);

        if (rule) {
            cursor.subtable = subtable;
            cls_rule = rule->cls_rule;
            break;
        }
    }
    *pnode = (char *)cls_rule + (ptrdiff_t)offset;

    /* Leave locked if requested and have a rule. */
    if (safe || !cls_rule) {
        ovs_mutex_unlock(&cursor.cls->mutex);
    }
    return cursor;
}

static void
cls_cursor_next_unlock(struct cls_cursor *cursor, struct cls_rule *rule)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    /* Release the mutex if no rule, or 'safe' mode. */
    if (!rule || cursor->safe) {
        ovs_mutex_unlock(&cursor->cls->mutex);
    }
}

/* Returns the next matching cls_rule in 'cursor''s iteration, or a null
 * pointer if there are no more matches. */
struct cls_rule *
cls_cursor_next(struct cls_cursor *cursor, const struct cls_rule *rule_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct cls_match *rule = CONST_CAST(struct cls_match *, rule_->cls_match);
    const struct cls_subtable *subtable;
    struct cls_match *next;

    /* Lock if not locked already. */
    if (cursor->safe) {
        ovs_mutex_lock(&cursor->cls->mutex);
    }

    next = next_rule_in_list__(rule);
    if (next->priority < rule->priority) {
        cls_cursor_next_unlock(cursor, next->cls_rule);
        return next->cls_rule;
    }

    /* 'next' is the head of the list, that is, the rule that is included in
     * the subtable's map.  (This is important when the classifier contains
     * rules that differ only in priority.) */
    rule = next;
    CMAP_CURSOR_FOR_EACH_CONTINUE (rule, cmap_node, &cursor->rules) {
        if (rule_matches(rule, cursor->target)) {
            cls_cursor_next_unlock(cursor, rule->cls_rule);
            return rule->cls_rule;
        }
    }

    subtable = cursor->subtable;
    CMAP_CURSOR_FOR_EACH_CONTINUE (subtable, cmap_node, &cursor->subtables) {
        rule = search_subtable(subtable, cursor);
        if (rule) {
            cursor->subtable = subtable;
            cls_cursor_next_unlock(cursor, rule->cls_rule);
            return rule->cls_rule;
        }
    }

    ovs_mutex_unlock(&cursor->cls->mutex);
    return NULL;
}

static struct cls_subtable *
find_subtable(const struct cls_classifier *cls, const struct minimask *mask)
    OVS_REQUIRES(cls->mutex)
{
    struct cls_subtable *subtable;

    CMAP_FOR_EACH_WITH_HASH (subtable, cmap_node, minimask_hash(mask, 0),
                             &cls->subtables_map) {
        if (minimask_equal(mask, &subtable->mask)) {
            return subtable;
        }
    }
    return NULL;
}

/* The new subtable will be visible to the readers only after this. */
static struct cls_subtable *
insert_subtable(struct cls_classifier *cls, const struct minimask *mask)
    OVS_REQUIRES(cls->mutex)
{
    uint32_t hash = minimask_hash(mask, 0);
    struct cls_subtable *subtable;
    int i, index = 0;
    struct flow_wildcards old, new;
    uint8_t prev;
    int count = count_1bits(mask->masks.map);

    subtable = xzalloc(sizeof *subtable - sizeof mask->masks.inline_values
                       + MINIFLOW_VALUES_SIZE(count));
    cmap_init(&subtable->rules);
    miniflow_clone_inline(&subtable->mask.masks, &mask->masks, count);

    /* Init indices for segmented lookup, if any. */
    flow_wildcards_init_catchall(&new);
    old = new;
    prev = 0;
    for (i = 0; i < cls->n_flow_segments; i++) {
        flow_wildcards_fold_minimask_range(&new, mask, prev,
                                           cls->flow_segments[i]);
        /* Add an index if it adds mask bits. */
        if (!flow_wildcards_equal(&new, &old)) {
            cmap_init(&subtable->indices[index]);
            subtable->index_ofs[index] = cls->flow_segments[i];
            index++;
            old = new;
        }
        prev = cls->flow_segments[i];
    }
    /* Check if the rest of the subtable's mask adds any bits,
     * and remove the last index if it doesn't. */
    if (index > 0) {
        flow_wildcards_fold_minimask_range(&new, mask, prev, FLOW_U32S);
        if (flow_wildcards_equal(&new, &old)) {
            --index;
            subtable->index_ofs[index] = 0;
            cmap_destroy(&subtable->indices[index]);
        }
    }
    subtable->n_indices = index;

    subtable->tag = (minimask_get_metadata_mask(mask) == OVS_BE64_MAX
                     ? tag_create_deterministic(hash)
                     : TAG_ALL);

    for (i = 0; i < cls->n_tries; i++) {
        subtable->trie_plen[i] = minimask_get_prefix_len(mask,
                                                         cls->tries[i].field);
    }

    /* Ports trie. */
    ovsrcu_set_hidden(&subtable->ports_trie, NULL);
    subtable->ports_mask_len
        = 32 - ctz32(ntohl(MINIFLOW_GET_BE32(&mask->masks, tp_src)));

    cmap_insert(&cls->subtables_map, &subtable->cmap_node, hash);

    return subtable;
}

static void
destroy_subtable(struct cls_classifier *cls, struct cls_subtable *subtable)
    OVS_REQUIRES(cls->mutex)
{
    int i;

    pvector_remove(&cls->subtables, subtable);
    trie_destroy(&subtable->ports_trie);

    for (i = 0; i < subtable->n_indices; i++) {
        cmap_destroy(&subtable->indices[i]);
    }
    cmap_remove(&cls->subtables_map, &subtable->cmap_node,
                minimask_hash(&subtable->mask, 0));
    minimask_destroy(&subtable->mask);
    cmap_destroy(&subtable->rules);
    ovsrcu_postpone(free, subtable);
}

struct range {
    uint8_t start;
    uint8_t end;
};

/* Return 'true' if can skip rest of the subtable based on the prefix trie
 * lookup results. */
static inline bool
check_tries(struct trie_ctx trie_ctx[CLS_MAX_TRIES], unsigned int n_tries,
            const unsigned int field_plen[CLS_MAX_TRIES],
            const struct range ofs, const struct flow *flow,
            struct flow_wildcards *wc)
{
    int j;

    /* Check if we could avoid fully unwildcarding the next level of
     * fields using the prefix tries.  The trie checks are done only as
     * needed to avoid folding in additional bits to the wildcards mask. */
    for (j = 0; j < n_tries; j++) {
        /* Is the trie field relevant for this subtable? */
        if (field_plen[j]) {
            struct trie_ctx *ctx = &trie_ctx[j];
            uint8_t be32ofs = ctx->be32ofs;

            /* Is the trie field within the current range of fields? */
            if (be32ofs >= ofs.start && be32ofs < ofs.end) {
                /* On-demand trie lookup. */
                if (!ctx->lookup_done) {
                    ctx->match_plen = trie_lookup(ctx->trie, flow,
                                                  &ctx->maskbits);
                    ctx->lookup_done = true;
                }
                /* Possible to skip the rest of the subtable if subtable's
                 * prefix on the field is longer than what is known to match
                 * based on the trie lookup. */
                if (field_plen[j] > ctx->match_plen) {
                    /* RFC: We want the trie lookup to never result in
                     * unwildcarding any bits that would not be unwildcarded
                     * otherwise.  Since the trie is shared by the whole
                     * classifier, it is possible that the 'maskbits' contain
                     * bits that are irrelevant for the partition of the
                     * classifier relevant for the current flow. */

                    /* Can skip if the field is already unwildcarded. */
                    if (mask_prefix_bits_set(wc, be32ofs, ctx->maskbits)) {
                        return true;
                    }
                    /* Check that the trie result will not unwildcard more bits
                     * than this stage will. */
                    if (ctx->maskbits <= field_plen[j]) {
                        /* Unwildcard the bits and skip the rest. */
                        mask_set_prefix_bits(wc, be32ofs, ctx->maskbits);
                        /* Note: Prerequisite already unwildcarded, as the only
                         * prerequisite of the supported trie lookup fields is
                         * the ethertype, which is currently always
                         * unwildcarded.
                         */
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

/* Returns true if 'target' satisifies 'flow'/'mask', that is, if each bit
 * for which 'flow', for which 'mask' has a bit set, specifies a particular
 * value has the correct value in 'target'.
 *
 * This function is equivalent to miniflow_equal_flow_in_minimask(flow,
 * target, mask) but this is faster because of the invariant that
 * flow->map and mask->masks.map are the same, and that this version
 * takes the 'wc'. */
static inline bool
miniflow_and_mask_matches_flow(const struct miniflow *flow,
                               const struct minimask *mask,
                               const struct flow *target)
{
    const uint32_t *flowp = miniflow_get_u32_values(flow);
    const uint32_t *maskp = miniflow_get_u32_values(&mask->masks);
    uint32_t idx;

    MAP_FOR_EACH_INDEX(idx, mask->masks.map) {
        uint32_t diff = (*flowp++ ^ flow_u32_value(target, idx)) & *maskp++;

        if (diff) {
            return false;
        }
    }

    return true;
}

static inline struct cls_match *
find_match(const struct cls_subtable *subtable, const struct flow *flow,
           uint32_t hash)
{
    struct cls_match *rule;

    CMAP_FOR_EACH_WITH_HASH (rule, cmap_node, hash, &subtable->rules) {
        if (miniflow_and_mask_matches_flow(&rule->flow, &subtable->mask,
                                           flow)) {
            return rule;
        }
    }

    return NULL;
}

/* Returns true if 'target' satisifies 'flow'/'mask', that is, if each bit
 * for which 'flow', for which 'mask' has a bit set, specifies a particular
 * value has the correct value in 'target'.
 *
 * This function is equivalent to miniflow_and_mask_matches_flow() but this
 * version fills in the mask bits in 'wc'. */
static inline bool
miniflow_and_mask_matches_flow_wc(const struct miniflow *flow,
                                  const struct minimask *mask,
                                  const struct flow *target,
                                  struct flow_wildcards *wc)
{
    const uint32_t *flowp = miniflow_get_u32_values(flow);
    const uint32_t *maskp = miniflow_get_u32_values(&mask->masks);
    uint32_t idx;

    MAP_FOR_EACH_INDEX(idx, mask->masks.map) {
        uint32_t mask = *maskp++;
        uint32_t diff = (*flowp++ ^ flow_u32_value(target, idx)) & mask;

        if (diff) {
            /* Only unwildcard if none of the differing bits is already
             * exact-matched. */
            if (!(flow_u32_value(&wc->masks, idx) & diff)) {
                /* Keep one bit of the difference. */
                *flow_u32_lvalue(&wc->masks, idx) |= rightmost_1bit(diff);
            }
            return false;
        }
        /* Fill in the bits that were looked at. */
        *flow_u32_lvalue(&wc->masks, idx) |= mask;
    }

    return true;
}

/* Unwildcard the fields looked up so far, if any. */
static void
fill_range_wc(const struct cls_subtable *subtable, struct flow_wildcards *wc,
              uint8_t to)
{
    if (to) {
        flow_wildcards_fold_minimask_range(wc, &subtable->mask, 0, to);
    }
}

static struct cls_match *
find_match_wc(const struct cls_subtable *subtable, const struct flow *flow,
              struct trie_ctx trie_ctx[CLS_MAX_TRIES], unsigned int n_tries,
              struct flow_wildcards *wc)
{
    uint32_t basis = 0, hash;
    struct cls_match *rule;
    int i;
    struct range ofs;

    if (OVS_UNLIKELY(!wc)) {
        return find_match(subtable, flow,
                          flow_hash_in_minimask(flow, &subtable->mask, 0));
    }

    ofs.start = 0;
    /* Try to finish early by checking fields in segments. */
    for (i = 0; i < subtable->n_indices; i++) {
        struct cmap_node *inode;

        ofs.end = subtable->index_ofs[i];

        if (check_tries(trie_ctx, n_tries, subtable->trie_plen, ofs, flow,
                        wc)) {
            /* 'wc' bits for the trie field set, now unwildcard the preceding
             * bits used so far. */
            fill_range_wc(subtable, wc, ofs.start);
            return NULL;
        }
        hash = flow_hash_in_minimask_range(flow, &subtable->mask, ofs.start,
                                           ofs.end, &basis);
        inode = cmap_find(&subtable->indices[i], hash);
        if (!inode) {
            /* No match, can stop immediately, but must fold in the bits
             * used in lookup so far. */
            fill_range_wc(subtable, wc, ofs.end);
            return NULL;
        }

        /* If we have narrowed down to a single rule already, check whether
         * that rule matches.  Either way, we're done.
         *
         * (Rare) hash collisions may cause us to miss the opportunity for this
         * optimization. */
        if (!cmap_node_next(inode)) {
            ASSIGN_CONTAINER(rule, inode - i, index_nodes);
            if (miniflow_and_mask_matches_flow_wc(&rule->flow, &subtable->mask,
                                                  flow, wc)) {
                return rule;
            }
            return NULL;
        }
        ofs.start = ofs.end;
    }
    ofs.end = FLOW_U32S;
    /* Trie check for the final range. */
    if (check_tries(trie_ctx, n_tries, subtable->trie_plen, ofs, flow, wc)) {
        fill_range_wc(subtable, wc, ofs.start);
        return NULL;
    }
    hash = flow_hash_in_minimask_range(flow, &subtable->mask, ofs.start,
                                       ofs.end, &basis);
    rule = find_match(subtable, flow, hash);
    if (!rule && subtable->ports_mask_len) {
        /* Ports are always part of the final range, if any.
         * No match was found for the ports.  Use the ports trie to figure out
         * which ports bits to unwildcard. */
        unsigned int mbits;
        ovs_be32 value, mask;

        mask = MINIFLOW_GET_BE32(&subtable->mask.masks, tp_src);
        value = ((OVS_FORCE ovs_be32 *)flow)[TP_PORTS_OFS32] & mask;
        trie_lookup_value(&subtable->ports_trie, &value, 32, &mbits);

        ((OVS_FORCE ovs_be32 *)&wc->masks)[TP_PORTS_OFS32] |=
            mask & htonl(~0 << (32 - mbits));

        /* Unwildcard all bits in the mask upto the ports, as they were used
         * to determine there is no match. */
        fill_range_wc(subtable, wc, TP_PORTS_OFS32);
        return NULL;
    }

    /* Must unwildcard all the fields, as they were looked at. */
    flow_wildcards_fold_minimask(wc, &subtable->mask);
    return rule;
}

static struct cls_match *
find_equal(struct cls_subtable *subtable, const struct miniflow *flow,
           uint32_t hash)
{
    struct cls_match *head;

    CMAP_FOR_EACH_WITH_HASH (head, cmap_node, hash, &subtable->rules) {
        if (miniflow_equal(&head->flow, flow)) {
            return head;
        }
    }
    return NULL;
}

/*
 * As the readers are operating concurrently with the modifications, a
 * concurrent reader may or may not see the new rule, depending on how
 * the concurrent events overlap with each other.  This is no
 * different from the former locked behavior, but there the visibility
 * of the new rule only depended on the timing of the locking
 * functions.
 *
 * The new rule is first added to the segment indices, so the readers
 * may find the rule in the indices before the rule is visible in the
 * subtables 'rules' map.  This may result in us losing the
 * opportunity to quit lookups earlier, resulting in sub-optimal
 * wildcarding.  This will be fixed by forthcoming revalidation always
 * scheduled after flow table changes.
 *
 * Similar behavior may happen due to us removing the overlapping rule
 * (if any) from the indices only after the new rule has been added.
 *
 * The subtable's max priority is updated only after the rule is
 * inserted, so the concurrent readers may not see the rule, as the
 * updated priority ordered subtable list will only be visible after
 * the subtable's max priority is updated.
 *
 * Similarly, the classifier's partitions for new rules are updated by
 * the caller after this function, so the readers may keep skipping
 * the subtable until they see the updated partitions.
 */
static struct cls_match *
insert_rule(struct cls_classifier *cls, struct cls_subtable *subtable,
            struct cls_rule *new_rule)
    OVS_REQUIRES(cls->mutex)
{
    struct cls_match *old = NULL;
    struct cls_match *new = cls_match_alloc(new_rule);
    struct cls_match *head;
    int i;
    uint32_t basis = 0, hash, ihash[CLS_MAX_INDICES];
    uint8_t prev_be32ofs = 0;

    /* Add new node to segment indices. */
    for (i = 0; i < subtable->n_indices; i++) {
        ihash[i] = minimatch_hash_range(&new_rule->match, prev_be32ofs,
                                        subtable->index_ofs[i], &basis);
        cmap_insert(&subtable->indices[i], &new->index_nodes[i], ihash[i]);
        prev_be32ofs = subtable->index_ofs[i];
    }
    hash = minimatch_hash_range(&new_rule->match, prev_be32ofs, FLOW_U32S,
                                &basis);
    head = find_equal(subtable, &new_rule->match.flow, hash);
    if (!head) {
        cmap_insert(&subtable->rules, &new->cmap_node, hash);
        list_init(&new->list);
        goto out;
    } else {
        /* Scan the list for the insertion point that will keep the list in
         * order of decreasing priority. */
        struct cls_match *rule;

        FOR_EACH_RULE_IN_LIST (rule, head) {
            if (new->priority >= rule->priority) {
                if (rule == head) {
                    /* 'new' is the new highest-priority flow in the list. */
                    cmap_replace(&subtable->rules, &rule->cmap_node,
                                 &new->cmap_node, hash);
                }

                if (new->priority == rule->priority) {
                    list_replace(&new->list, &rule->list);
                    old = rule;
                } else {
                    list_insert(&rule->list, &new->list);
                }
                goto out;
            }
        }

        /* Insert 'new' at the end of the list. */
        list_push_back(&head->list, &new->list);
    }

 out:
    if (!old) {
        subtable->n_rules++;

        /* Rule was added, not replaced.  Update 'subtable's 'max_priority'
         * and 'max_count', if necessary. */
        if (subtable->n_rules == 1) {
            subtable->max_priority = new->priority;
            subtable->max_count = 1;
            pvector_insert(&cls->subtables, subtable, new->priority);
        } else if (subtable->max_priority == new->priority) {
            ++subtable->max_count;
        } else if (new->priority > subtable->max_priority) {
            subtable->max_priority = new->priority;
            subtable->max_count = 1;
            pvector_change_priority(&cls->subtables, subtable, new->priority);
        }
    } else {
        /* Remove old node from indices. */
        for (i = 0; i < subtable->n_indices; i++) {
            cmap_remove(&subtable->indices[i], &old->index_nodes[i], ihash[i]);
        }
    }
    return old;
}

static struct cls_match *
next_rule_in_list__(struct cls_match *rule)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct cls_match *next = OBJECT_CONTAINING(rule->list.next, next, list);
    return next;
}

static struct cls_match *
next_rule_in_list(struct cls_match *rule)
{
    struct cls_match *next = next_rule_in_list__(rule);
    return next->priority < rule->priority ? next : NULL;
}

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

/* Return at least 'plen' bits of the 'prefix', starting at bit offset 'ofs'.
 * Prefixes are in the network byte order, and the offset 0 corresponds to
 * the most significant bit of the first byte.  The offset can be read as
 * "how many bits to skip from the start of the prefix starting at 'pr'". */
static uint32_t
raw_get_prefix(const ovs_be32 pr[], unsigned int ofs, unsigned int plen)
{
    uint32_t prefix;

    pr += ofs / 32; /* Where to start. */
    ofs %= 32;      /* How many bits to skip at 'pr'. */

    prefix = ntohl(*pr) << ofs; /* Get the first 32 - ofs bits. */
    if (plen > 32 - ofs) {      /* Need more than we have already? */
        prefix |= ntohl(*++pr) >> (32 - ofs);
    }
    /* Return with possible unwanted bits at the end. */
    return prefix;
}

/* Return min(TRIE_PREFIX_BITS, plen) bits of the 'prefix', starting at bit
 * offset 'ofs'.  Prefixes are in the network byte order, and the offset 0
 * corresponds to the most significant bit of the first byte.  The offset can
 * be read as "how many bits to skip from the start of the prefix starting at
 * 'pr'". */
static uint32_t
trie_get_prefix(const ovs_be32 pr[], unsigned int ofs, unsigned int plen)
{
    if (!plen) {
        return 0;
    }
    if (plen > TRIE_PREFIX_BITS) {
        plen = TRIE_PREFIX_BITS; /* Get at most TRIE_PREFIX_BITS. */
    }
    /* Return with unwanted bits cleared. */
    return raw_get_prefix(pr, ofs, plen) & ~0u << (32 - plen);
}

/* Return the number of equal bits in 'n_bits' of 'prefix's MSBs and a 'value'
 * starting at "MSB 0"-based offset 'ofs'. */
static unsigned int
prefix_equal_bits(uint32_t prefix, unsigned int n_bits, const ovs_be32 value[],
                  unsigned int ofs)
{
    uint64_t diff = prefix ^ raw_get_prefix(value, ofs, n_bits);
    /* Set the bit after the relevant bits to limit the result. */
    return raw_clz64(diff << 32 | UINT64_C(1) << (63 - n_bits));
}

/* Return the number of equal bits in 'node' prefix and a 'prefix' of length
 * 'plen', starting at "MSB 0"-based offset 'ofs'. */
static unsigned int
trie_prefix_equal_bits(const struct trie_node *node, const ovs_be32 prefix[],
                       unsigned int ofs, unsigned int plen)
{
    return prefix_equal_bits(node->prefix, MIN(node->n_bits, plen - ofs),
                             prefix, ofs);
}

/* Return the bit at ("MSB 0"-based) offset 'ofs' as an int.  'ofs' can
 * be greater than 31. */
static unsigned int
be_get_bit_at(const ovs_be32 value[], unsigned int ofs)
{
    return (((const uint8_t *)value)[ofs / 8] >> (7 - ofs % 8)) & 1u;
}

/* Return the bit at ("MSB 0"-based) offset 'ofs' as an int.  'ofs' must
 * be between 0 and 31, inclusive. */
static unsigned int
get_bit_at(const uint32_t prefix, unsigned int ofs)
{
    return (prefix >> (31 - ofs)) & 1u;
}

/* Create new branch. */
static struct trie_node *
trie_branch_create(const ovs_be32 *prefix, unsigned int ofs, unsigned int plen,
                   unsigned int n_rules)
{
    struct trie_node *node = xmalloc(sizeof *node);

    node->prefix = trie_get_prefix(prefix, ofs, plen);

    if (plen <= TRIE_PREFIX_BITS) {
        node->n_bits = plen;
        ovsrcu_set_hidden(&node->edges[0], NULL);
        ovsrcu_set_hidden(&node->edges[1], NULL);
        node->n_rules = n_rules;
    } else { /* Need intermediate nodes. */
        struct trie_node *subnode = trie_branch_create(prefix,
                                                       ofs + TRIE_PREFIX_BITS,
                                                       plen - TRIE_PREFIX_BITS,
                                                       n_rules);
        int bit = get_bit_at(subnode->prefix, 0);
        node->n_bits = TRIE_PREFIX_BITS;
        ovsrcu_set_hidden(&node->edges[bit], subnode);
        ovsrcu_set_hidden(&node->edges[!bit], NULL);
        node->n_rules = 0;
    }
    return node;
}

static void
trie_node_destroy(const struct trie_node *node)
{
    ovsrcu_postpone(free, CONST_CAST(struct trie_node *, node));
}

/* Copy a trie node for modification and postpone delete the old one. */
static struct trie_node *
trie_node_rcu_realloc(const struct trie_node *node)
{
    struct trie_node *new_node = xmalloc(sizeof *node);

    *new_node = *node;
    trie_node_destroy(node);

    return new_node;
}

/* May only be called while holding the cls_classifier mutex. */
static void
trie_destroy(rcu_trie_ptr *trie)
{
    struct trie_node *node = ovsrcu_get_protected(struct trie_node *, trie);

    if (node) {
        ovsrcu_set_hidden(trie, NULL);
        trie_destroy(&node->edges[0]);
        trie_destroy(&node->edges[1]);
        trie_node_destroy(node);
    }
}

static bool
trie_is_leaf(const struct trie_node *trie)
{
    /* No children? */
    return !ovsrcu_get(struct trie_node *, &trie->edges[0])
        && !ovsrcu_get(struct trie_node *, &trie->edges[1]);
}

static void
mask_set_prefix_bits(struct flow_wildcards *wc, uint8_t be32ofs,
                     unsigned int n_bits)
{
    ovs_be32 *mask = &((ovs_be32 *)&wc->masks)[be32ofs];
    unsigned int i;

    for (i = 0; i < n_bits / 32; i++) {
        mask[i] = OVS_BE32_MAX;
    }
    if (n_bits % 32) {
        mask[i] |= htonl(~0u << (32 - n_bits % 32));
    }
}

static bool
mask_prefix_bits_set(const struct flow_wildcards *wc, uint8_t be32ofs,
                     unsigned int n_bits)
{
    ovs_be32 *mask = &((ovs_be32 *)&wc->masks)[be32ofs];
    unsigned int i;
    ovs_be32 zeroes = 0;

    for (i = 0; i < n_bits / 32; i++) {
        zeroes |= ~mask[i];
    }
    if (n_bits % 32) {
        zeroes |= ~mask[i] & htonl(~0u << (32 - n_bits % 32));
    }

    return !zeroes; /* All 'n_bits' bits set. */
}

static rcu_trie_ptr *
trie_next_edge(struct trie_node *node, const ovs_be32 value[],
               unsigned int ofs)
{
    return node->edges + be_get_bit_at(value, ofs);
}

static const struct trie_node *
trie_next_node(const struct trie_node *node, const ovs_be32 value[],
               unsigned int ofs)
{
    return ovsrcu_get(struct trie_node *,
                      &node->edges[be_get_bit_at(value, ofs)]);
}

/* Return the prefix mask length necessary to find the longest-prefix match for
 * the '*value' in the prefix tree 'node'.
 * '*checkbits' is set to the number of bits in the prefix mask necessary to
 * determine a mismatch, in case there are longer prefixes in the tree below
 * the one that matched.
 */
static unsigned int
trie_lookup_value(const rcu_trie_ptr *trie, const ovs_be32 value[],
                  unsigned int n_bits, unsigned int *checkbits)
{
    const struct trie_node *node = ovsrcu_get(struct trie_node *, trie);
    unsigned int ofs = 0, match_len = 0;
    const struct trie_node *prev = NULL;

    for (; node; prev = node, node = trie_next_node(node, value, ofs)) {
        unsigned int eqbits;
        /* Check if this edge can be followed. */
        eqbits = prefix_equal_bits(node->prefix, node->n_bits, value, ofs);
        ofs += eqbits;
        if (eqbits < node->n_bits) { /* Mismatch, nothing more to be found. */
            /* Bit at offset 'ofs' differed. */
            *checkbits = ofs + 1; /* Includes the first mismatching bit. */
            return match_len;
        }
        /* Full match, check if rules exist at this prefix length. */
        if (node->n_rules > 0) {
            match_len = ofs;
        }
        if (ofs >= n_bits) {
            *checkbits = n_bits; /* Full prefix. */
            return match_len;
        }
    }
    /* node == NULL.  Full match so far, but we came to a dead end.
     * need to exclude the other branch if it exists. */
    *checkbits = !prev || trie_is_leaf(prev) ? ofs : ofs + 1;
    return match_len;
}

static unsigned int
trie_lookup(const struct cls_trie *trie, const struct flow *flow,
            unsigned int *checkbits)
{
    const struct mf_field *mf = trie->field;

    /* Check that current flow matches the prerequisites for the trie
     * field.  Some match fields are used for multiple purposes, so we
     * must check that the trie is relevant for this flow. */
    if (mf_are_prereqs_ok(mf, flow)) {
        return trie_lookup_value(&trie->root,
                                 &((ovs_be32 *)flow)[mf->flow_be32ofs],
                                 mf->n_bits, checkbits);
    }
    *checkbits = 0; /* Value not used in this case. */
    return UINT_MAX;
}

/* Returns the length of a prefix match mask for the field 'mf' in 'minimask'.
 * Returns the u32 offset to the miniflow data in '*miniflow_index', if
 * 'miniflow_index' is not NULL. */
static unsigned int
minimask_get_prefix_len(const struct minimask *minimask,
                        const struct mf_field *mf)
{
    unsigned int n_bits = 0, mask_tz = 0; /* Non-zero when end of mask seen. */
    uint8_t u32_ofs = mf->flow_be32ofs;
    uint8_t u32_end = u32_ofs + mf->n_bytes / 4;

    for (; u32_ofs < u32_end; ++u32_ofs) {
        uint32_t mask;
        mask = ntohl((OVS_FORCE ovs_be32)minimask_get(minimask, u32_ofs));

        /* Validate mask, count the mask length. */
        if (mask_tz) {
            if (mask) {
                return 0; /* No bits allowed after mask ended. */
            }
        } else {
            if (~mask & (~mask + 1)) {
                return 0; /* Mask not contiguous. */
            }
            mask_tz = ctz32(mask);
            n_bits += 32 - mask_tz;
        }
    }

    return n_bits;
}

/*
 * This is called only when mask prefix is known to be CIDR and non-zero.
 * Relies on the fact that the flow and mask have the same map, and since
 * the mask is CIDR, the storage for the flow field exists even if it
 * happened to be zeros.
 */
static const ovs_be32 *
minimatch_get_prefix(const struct minimatch *match, const struct mf_field *mf)
{
    return miniflow_get_be32_values(&match->flow) +
        count_1bits(match->flow.map & ((UINT64_C(1) << mf->flow_be32ofs) - 1));
}

/* Insert rule in to the prefix tree.
 * 'mlen' must be the (non-zero) CIDR prefix length of the 'trie->field' mask
 * in 'rule'. */
static void
trie_insert(struct cls_trie *trie, const struct cls_rule *rule, int mlen)
{
    trie_insert_prefix(&trie->root,
                       minimatch_get_prefix(&rule->match, trie->field), mlen);
}

static void
trie_insert_prefix(rcu_trie_ptr *edge, const ovs_be32 *prefix, int mlen)
{
    struct trie_node *node;
    int ofs = 0;

    /* Walk the tree. */
    for (; (node = ovsrcu_get_protected(struct trie_node *, edge));
         edge = trie_next_edge(node, prefix, ofs)) {
        unsigned int eqbits = trie_prefix_equal_bits(node, prefix, ofs, mlen);
        ofs += eqbits;
        if (eqbits < node->n_bits) {
            /* Mismatch, new node needs to be inserted above. */
            int old_branch = get_bit_at(node->prefix, eqbits);
            struct trie_node *new_parent;

            new_parent = trie_branch_create(prefix, ofs - eqbits, eqbits,
                                            ofs == mlen ? 1 : 0);
            /* Copy the node to modify it. */
            node = trie_node_rcu_realloc(node);
            /* Adjust the new node for its new position in the tree. */
            node->prefix <<= eqbits;
            node->n_bits -= eqbits;
            ovsrcu_set_hidden(&new_parent->edges[old_branch], node);

            /* Check if need a new branch for the new rule. */
            if (ofs < mlen) {
                ovsrcu_set_hidden(&new_parent->edges[!old_branch],
                                  trie_branch_create(prefix, ofs, mlen - ofs,
                                                     1));
            }
            ovsrcu_set(edge, new_parent); /* Publish changes. */
            return;
        }
        /* Full match so far. */

        if (ofs == mlen) {
            /* Full match at the current node, rule needs to be added here. */
            node->n_rules++;
            return;
        }
    }
    /* Must insert a new tree branch for the new rule. */
    ovsrcu_set(edge, trie_branch_create(prefix, ofs, mlen - ofs, 1));
}

/* 'mlen' must be the (non-zero) CIDR prefix length of the 'trie->field' mask
 * in 'rule'. */
static void
trie_remove(struct cls_trie *trie, const struct cls_rule *rule, int mlen)
{
    trie_remove_prefix(&trie->root,
                       minimatch_get_prefix(&rule->match, trie->field), mlen);
}

/* 'mlen' must be the (non-zero) CIDR prefix length of the 'trie->field' mask
 * in 'rule'. */
static void
trie_remove_prefix(rcu_trie_ptr *root, const ovs_be32 *prefix, int mlen)
{
    struct trie_node *node;
    rcu_trie_ptr *edges[sizeof(union mf_value) * 8];
    int depth = 0, ofs = 0;

    /* Walk the tree. */
    for (edges[0] = root;
         (node = ovsrcu_get_protected(struct trie_node *, edges[depth]));
         edges[++depth] = trie_next_edge(node, prefix, ofs)) {
        unsigned int eqbits = trie_prefix_equal_bits(node, prefix, ofs, mlen);

        if (eqbits < node->n_bits) {
            /* Mismatch, nothing to be removed.  This should never happen, as
             * only rules in the classifier are ever removed. */
            break; /* Log a warning. */
        }
        /* Full match so far. */
        ofs += eqbits;

        if (ofs == mlen) {
            /* Full prefix match at the current node, remove rule here. */
            if (!node->n_rules) {
                break; /* Log a warning. */
            }
            node->n_rules--;

            /* Check if can prune the tree. */
            while (!node->n_rules) {
                struct trie_node *next,
                    *edge0 = ovsrcu_get_protected(struct trie_node *,
                                                  &node->edges[0]),
                    *edge1 = ovsrcu_get_protected(struct trie_node *,
                                                  &node->edges[1]);

                if (edge0 && edge1) {
                    break; /* A branching point, cannot prune. */
                }

                /* Else have at most one child node, remove this node. */
                next = edge0 ? edge0 : edge1;

                if (next) {
                    if (node->n_bits + next->n_bits > TRIE_PREFIX_BITS) {
                        break;   /* Cannot combine. */
                    }
                    next = trie_node_rcu_realloc(next); /* Modify. */

                    /* Combine node with next. */
                    next->prefix = node->prefix | next->prefix >> node->n_bits;
                    next->n_bits += node->n_bits;
                }
                /* Update the parent's edge. */
                ovsrcu_set(edges[depth], next); /* Publish changes. */
                trie_node_destroy(node);

                if (next || !depth) {
                    /* Branch not pruned or at root, nothing more to do. */
                    break;
                }
                node = ovsrcu_get_protected(struct trie_node *,
                                            edges[--depth]);
            }
            return;
        }
    }
    /* Cannot go deeper. This should never happen, since only rules
     * that actually exist in the classifier are ever removed. */
    VLOG_WARN("Trying to remove non-existing rule from a prefix trie.");
}
