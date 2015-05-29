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

#include <config.h>
#include "classifier.h"
#include "classifier-private.h"
#include <errno.h>
#include <netinet/in.h>
#include "byte-order.h"
#include "dynamic-string.h"
#include "odp-util.h"
#include "ofp-util.h"
#include "packets.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(classifier);

struct trie_ctx;

/* A collection of "struct cls_conjunction"s currently embedded into a
 * cls_match. */
struct cls_conjunction_set {
    /* Link back to the cls_match.
     *
     * cls_conjunction_set is mostly used during classifier lookup, and, in
     * turn, during classifier lookup the most used member of
     * cls_conjunction_set is the rule's priority, so we cache it here for fast
     * access. */
    struct cls_match *match;
    int priority;               /* Cached copy of match->priority. */

    /* Conjunction information.
     *
     * 'min_n_clauses' allows some optimization during classifier lookup. */
    unsigned int n;             /* Number of elements in 'conj'. */
    unsigned int min_n_clauses; /* Smallest 'n' among elements of 'conj'. */
    struct cls_conjunction conj[];
};

/* Ports trie depends on both ports sharing the same ovs_be32. */
#define TP_PORTS_OFS32 (offsetof(struct flow, tp_src) / 4)
BUILD_ASSERT_DECL(TP_PORTS_OFS32 == offsetof(struct flow, tp_dst) / 4);
BUILD_ASSERT_DECL(TP_PORTS_OFS32 % 2 == 0);
#define TP_PORTS_OFS64 (TP_PORTS_OFS32 / 2)

static size_t
cls_conjunction_set_size(size_t n)
{
    return (sizeof(struct cls_conjunction_set)
            + n * sizeof(struct cls_conjunction));
}

static struct cls_conjunction_set *
cls_conjunction_set_alloc(struct cls_match *match,
                          const struct cls_conjunction conj[], size_t n)
{
    if (n) {
        size_t min_n_clauses = conj[0].n_clauses;
        for (size_t i = 1; i < n; i++) {
            min_n_clauses = MIN(min_n_clauses, conj[i].n_clauses);
        }

        struct cls_conjunction_set *set = xmalloc(cls_conjunction_set_size(n));
        set->match = match;
        set->priority = match->priority;
        set->n = n;
        set->min_n_clauses = min_n_clauses;
        memcpy(set->conj, conj, n * sizeof *conj);
        return set;
    } else {
        return NULL;
    }
}

static struct cls_match *
cls_match_alloc(const struct cls_rule *rule,
                const struct cls_conjunction conj[], size_t n)
{
    int count = count_1bits(rule->match.flow.map);

    struct cls_match *cls_match
        = xmalloc(sizeof *cls_match - sizeof cls_match->flow.inline_values
                  + MINIFLOW_VALUES_SIZE(count));

    rculist_init(&cls_match->list);
    *CONST_CAST(const struct cls_rule **, &cls_match->cls_rule) = rule;
    *CONST_CAST(int *, &cls_match->priority) = rule->priority;
    cls_match->visible = false;
    miniflow_clone_inline(CONST_CAST(struct miniflow *, &cls_match->flow),
                          &rule->match.flow, count);
    ovsrcu_set_hidden(&cls_match->conj_set,
                      cls_conjunction_set_alloc(cls_match, conj, n));

    return cls_match;
}

static struct cls_subtable *find_subtable(const struct classifier *cls,
                                          const struct minimask *);
static struct cls_subtable *insert_subtable(struct classifier *cls,
                                            const struct minimask *);
static void destroy_subtable(struct classifier *cls, struct cls_subtable *);

static const struct cls_match *find_match_wc(const struct cls_subtable *,
                                             const struct flow *,
                                             struct trie_ctx *,
                                             unsigned int n_tries,
                                             struct flow_wildcards *);
static struct cls_match *find_equal(const struct cls_subtable *,
                                    const struct miniflow *, uint32_t hash);

static inline const struct cls_match *
next_rule_in_list__(const struct cls_match *rule)
{
    const struct cls_match *next = NULL;
    next = OBJECT_CONTAINING(rculist_next(&rule->list), next, list);
    return next;
}

static inline const struct cls_match *
next_rule_in_list(const struct cls_match *rule, const struct cls_match *head)
{
    const struct cls_match *next = next_rule_in_list__(rule);
    return next != head ? next : NULL;
}

/* Return the next lower-priority rule in the list that is visible.  Multiple
 * identical rules with the same priority may exist transitionally.  In that
 * case the first rule of a given priority has been marked as 'to_be_removed',
 * and the later rules are marked as '!visible'.  This gets a bit complex if
 * there are two rules of the same priority in the list, as in that case the
 * head and tail of the list will have the same priority. */
static inline const struct cls_match *
next_visible_rule_in_list(const struct cls_match *rule)
{
    const struct cls_match *next = rule;

    do {
        next = next_rule_in_list__(next);
        if (next->priority > rule->priority || next == rule) {
            /* We have reached the head of the list, stop. */
            return NULL;
        }
    } while (!next->visible);

    return next;
}

static inline struct cls_match *
next_rule_in_list_protected__(struct cls_match *rule)
{
    struct cls_match *next = NULL;
    next = OBJECT_CONTAINING(rculist_next_protected(&rule->list), next, list);
    return next;
}

static inline struct cls_match *
next_rule_in_list_protected(struct cls_match *rule, struct cls_match *head)
{
    struct cls_match *next = next_rule_in_list_protected__(rule);
    return next != head ? next : NULL;
}

/* Iterates RULE over HEAD and all of the cls_rules on HEAD->list. */
#define FOR_EACH_RULE_IN_LIST(RULE, HEAD)           \
    for ((RULE) = (HEAD); (RULE) != NULL;           \
         (RULE) = next_rule_in_list(RULE, HEAD))
#define FOR_EACH_RULE_IN_LIST_PROTECTED(RULE, HEAD)         \
    for ((RULE) = (HEAD); (RULE) != NULL;                   \
         (RULE) = next_rule_in_list_protected(RULE, HEAD))

static unsigned int minimask_get_prefix_len(const struct minimask *,
                                            const struct mf_field *);
static void trie_init(struct classifier *cls, int trie_idx,
                      const struct mf_field *);
static unsigned int trie_lookup(const struct cls_trie *, const struct flow *,
                                union mf_value *plens);
static unsigned int trie_lookup_value(const rcu_trie_ptr *,
                                      const ovs_be32 value[], ovs_be32 plens[],
                                      unsigned int value_bits);
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

/* cls_rule. */

static inline void
cls_rule_init__(struct cls_rule *rule, unsigned int priority)
{
    rculist_init(&rule->node);
    rule->priority = priority;
    rule->to_be_removed = false;
    rule->cls_match = NULL;
}

/* Initializes 'rule' to match packets specified by 'match' at the given
 * 'priority'.  'match' must satisfy the invariant described in the comment at
 * the definition of struct match.
 *
 * The caller must eventually destroy 'rule' with cls_rule_destroy().
 *
 * Clients should not use priority INT_MIN.  (OpenFlow uses priorities between
 * 0 and UINT16_MAX, inclusive.) */
void
cls_rule_init(struct cls_rule *rule, const struct match *match, int priority)
{
    cls_rule_init__(rule, priority);
    minimatch_init(&rule->match, match);
}

/* Same as cls_rule_init() for initialization from a "struct minimatch". */
void
cls_rule_init_from_minimatch(struct cls_rule *rule,
                             const struct minimatch *match, int priority)
{
    cls_rule_init__(rule, priority);
    minimatch_clone(&rule->match, match);
}

/* Initializes 'dst' as a copy of 'src'.
 *
 * The caller must eventually destroy 'dst' with cls_rule_destroy(). */
void
cls_rule_clone(struct cls_rule *dst, const struct cls_rule *src)
{
    cls_rule_init__(dst, src->priority);
    minimatch_clone(&dst->match, &src->match);
}

/* Initializes 'dst' with the data in 'src', destroying 'src'.
 * 'src' must be a cls_rule NOT in a classifier.
 *
 * The caller must eventually destroy 'dst' with cls_rule_destroy(). */
void
cls_rule_move(struct cls_rule *dst, struct cls_rule *src)
{
    ovs_assert(!src->cls_match);   /* Must not be in a classifier. */
    cls_rule_init__(dst, src->priority);
    minimatch_move(&dst->match, &src->match);
}

/* Frees memory referenced by 'rule'.  Doesn't free 'rule' itself (it's
 * normally embedded into a larger structure).
 *
 * ('rule' must not currently be in a classifier.) */
void
cls_rule_destroy(struct cls_rule *rule)
{
    ovs_assert(!rule->cls_match);   /* Must not be in a classifier. */

    /* Check that the rule has been properly removed from the classifier and
     * that the destruction only happens after the RCU grace period, or that
     * the rule was never inserted to the classifier in the first place. */
    ovs_assert(rculist_next_protected(&rule->node) == RCULIST_POISON
               || rculist_is_empty(&rule->node));

    minimatch_destroy(&rule->match);
}

void
cls_rule_set_conjunctions(struct cls_rule *cr,
                          const struct cls_conjunction *conj, size_t n)
{
    struct cls_match *match = cr->cls_match;
    struct cls_conjunction_set *old
        = ovsrcu_get_protected(struct cls_conjunction_set *, &match->conj_set);
    struct cls_conjunction *old_conj = old ? old->conj : NULL;
    unsigned int old_n = old ? old->n : 0;

    if (old_n != n || (n && memcmp(old_conj, conj, n * sizeof *conj))) {
        if (old) {
            ovsrcu_postpone(free, old);
        }
        ovsrcu_set(&match->conj_set,
                   cls_conjunction_set_alloc(match, conj, n));
    }
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

/* Rules inserted during classifier_defer() need to be made visible before
 * calling classifier_publish().
 *
 * 'rule' must be in a classifier. */
void cls_rule_make_visible(const struct cls_rule *rule)
{
    rule->cls_match->visible = true;
}


/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
void
classifier_init(struct classifier *cls, const uint8_t *flow_segments)
{
    cls->n_rules = 0;
    cmap_init(&cls->subtables_map);
    pvector_init(&cls->subtables);
    cmap_init(&cls->partitions);
    cls->n_flow_segments = 0;
    if (flow_segments) {
        while (cls->n_flow_segments < CLS_MAX_INDICES
               && *flow_segments < FLOW_U64S) {
            cls->flow_segments[cls->n_flow_segments++] = *flow_segments++;
        }
    }
    cls->n_tries = 0;
    for (int i = 0; i < CLS_MAX_TRIES; i++) {
        trie_init(cls, i, NULL);
    }
    cls->publish = true;
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility.
 * May only be called after all the readers have been terminated. */
void
classifier_destroy(struct classifier *cls)
{
    if (cls) {
        struct cls_partition *partition;
        struct cls_subtable *subtable;
        int i;

        for (i = 0; i < cls->n_tries; i++) {
            trie_destroy(&cls->tries[i].root);
        }

        CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) {
            destroy_subtable(cls, subtable);
        }
        cmap_destroy(&cls->subtables_map);

        CMAP_FOR_EACH (partition, cmap_node, &cls->partitions) {
            ovsrcu_postpone(free, partition);
        }
        cmap_destroy(&cls->partitions);

        pvector_destroy(&cls->subtables);
    }
}

/* Set the fields for which prefix lookup should be performed. */
bool
classifier_set_prefix_fields(struct classifier *cls,
                             const enum mf_field_id *trie_fields,
                             unsigned int n_fields)
{
    const struct mf_field * new_fields[CLS_MAX_TRIES];
    struct mf_bitmap fields = MF_BITMAP_INITIALIZER;
    int i, n_tries = 0;
    bool changed = false;

    for (i = 0; i < n_fields && n_tries < CLS_MAX_TRIES; i++) {
        const struct mf_field *field = mf_from_id(trie_fields[i]);
        if (field->flow_be32ofs < 0 || field->n_bits % 32) {
            /* Incompatible field.  This is the only place where we
             * enforce these requirements, but the rest of the trie code
             * depends on the flow_be32ofs to be non-negative and the
             * field length to be a multiple of 32 bits. */
            continue;
        }

        if (bitmap_is_set(fields.bm, trie_fields[i])) {
            /* Duplicate field, there is no need to build more than
             * one index for any one field. */
            continue;
        }
        bitmap_set1(fields.bm, trie_fields[i]);

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
        return true;
    }

    return false; /* No change. */
}

static void
trie_init(struct classifier *cls, int trie_idx, const struct mf_field *field)
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
                trie_insert(trie, head->cls_rule, plen);
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
    return cmap_is_empty(&cls->subtables_map);
}

/* Returns the number of rules in 'cls'. */
int
classifier_count(const struct classifier *cls)
{
    /* n_rules is an int, so in the presence of concurrent writers this will
     * return either the old or a new value. */
    return cls->n_rules;
}

static uint32_t
hash_metadata(ovs_be64 metadata)
{
    return hash_uint64((OVS_FORCE uint64_t) metadata);
}

static struct cls_partition *
find_partition(const struct classifier *cls, ovs_be64 metadata, uint32_t hash)
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
create_partition(struct classifier *cls, struct cls_subtable *subtable,
                 ovs_be64 metadata)
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

static void
subtable_replace_head_rule(struct classifier *cls OVS_UNUSED,
                           struct cls_subtable *subtable,
                           struct cls_match *head, struct cls_match *new,
                           uint32_t hash, uint32_t ihash[CLS_MAX_INDICES])
{
    /* Rule's data is already in the tries. */

    new->partition = head->partition; /* Steal partition, if any. */
    head->partition = NULL;

    for (int i = 0; i < subtable->n_indices; i++) {
        cmap_replace(&subtable->indices[i], &head->index_nodes[i],
                     &new->index_nodes[i], ihash[i]);
    }
    cmap_replace(&subtable->rules, &head->cmap_node, &new->cmap_node, hash);
}

/* Inserts 'rule' into 'cls'.  Until 'rule' is removed from 'cls', the caller
 * must not modify or free it.
 *
 * If 'cls' already contains an identical rule (including wildcards, values of
 * fixed fields, and priority), replaces the old rule by 'rule' and returns the
 * rule that was replaced.  The caller takes ownership of the returned rule and
 * is thus responsible for destroying it with cls_rule_destroy(), after RCU
 * grace period has passed (see ovsrcu_postpone()).
 *
 * Returns NULL if 'cls' does not contain a rule with an identical key, after
 * inserting the new rule.  In this case, no rules are displaced by the new
 * rule, even rules that cannot have any effect because the new rule matches a
 * superset of their flows and has higher priority.
 */
const struct cls_rule *
classifier_replace(struct classifier *cls, const struct cls_rule *rule,
                   const struct cls_conjunction *conjs, size_t n_conjs)
{
    struct cls_match *new = cls_match_alloc(rule, conjs, n_conjs);
    struct cls_subtable *subtable;
    uint32_t ihash[CLS_MAX_INDICES];
    uint8_t prev_be64ofs = 0;
    struct cls_match *head;
    size_t n_rules = 0;
    uint32_t basis;
    uint32_t hash;
    int i;

    CONST_CAST(struct cls_rule *, rule)->cls_match = new;

    subtable = find_subtable(cls, &rule->match.mask);
    if (!subtable) {
        subtable = insert_subtable(cls, &rule->match.mask);
    }

    /* Compute hashes in segments. */
    basis = 0;
    for (i = 0; i < subtable->n_indices; i++) {
        ihash[i] = minimatch_hash_range(&rule->match, prev_be64ofs,
                                        subtable->index_ofs[i], &basis);
        prev_be64ofs = subtable->index_ofs[i];
    }
    hash = minimatch_hash_range(&rule->match, prev_be64ofs, FLOW_U64S, &basis);

    head = find_equal(subtable, &rule->match.flow, hash);
    if (!head) {
        /* Add rule to tries.
         *
         * Concurrent readers might miss seeing the rule until this update,
         * which might require being fixed up by revalidation later. */
        for (i = 0; i < cls->n_tries; i++) {
            if (subtable->trie_plen[i]) {
                trie_insert(&cls->tries[i], rule, subtable->trie_plen[i]);
            }
        }

        /* Add rule to ports trie. */
        if (subtable->ports_mask_len) {
            /* We mask the value to be inserted to always have the wildcarded
             * bits in known (zero) state, so we can include them in comparison
             * and they will always match (== their original value does not
             * matter). */
            ovs_be32 masked_ports = minimatch_get_ports(&rule->match);

            trie_insert_prefix(&subtable->ports_trie, &masked_ports,
                               subtable->ports_mask_len);
        }

        /* Add rule to partitions.
         *
         * Concurrent readers might miss seeing the rule until this update,
         * which might require being fixed up by revalidation later. */
        new->partition = NULL;
        if (minimask_get_metadata_mask(&rule->match.mask) == OVS_BE64_MAX) {
            ovs_be64 metadata = miniflow_get_metadata(&rule->match.flow);

            new->partition = create_partition(cls, subtable, metadata);
        }

        /* Add new node to segment indices.
         *
         * Readers may find the rule in the indices before the rule is visible
         * in the subtables 'rules' map.  This may result in us losing the
         * opportunity to quit lookups earlier, resulting in sub-optimal
         * wildcarding.  This will be fixed later by revalidation (always
         * scheduled after flow table changes). */
        for (i = 0; i < subtable->n_indices; i++) {
            cmap_insert(&subtable->indices[i], &new->index_nodes[i], ihash[i]);
        }
        n_rules = cmap_insert(&subtable->rules, &new->cmap_node, hash);
    } else {   /* Equal rules exist in the classifier already. */
        struct cls_match *iter;

        /* Scan the list for the insertion point that will keep the list in
         * order of decreasing priority.
         * Insert after 'to_be_removed' rules of the same priority. */
        FOR_EACH_RULE_IN_LIST_PROTECTED (iter, head) {
            if (rule->priority > iter->priority
                || (rule->priority == iter->priority
                    && !iter->cls_rule->to_be_removed)) {
                break;
            }
        }

        /* 'iter' now at the insertion point or NULL if at end. */
        if (iter) {
            struct cls_rule *old;

            if (rule->priority == iter->priority) {
                rculist_replace(&new->list, &iter->list);
                old = CONST_CAST(struct cls_rule *, iter->cls_rule);
            } else {
                rculist_insert(&iter->list, &new->list);
                old = NULL;
            }

            /* Replace the existing head in data structures, if rule is the new
             * head. */
            if (iter == head) {
                subtable_replace_head_rule(cls, subtable, head, new, hash,
                                           ihash);
            }

            if (old) {
                struct cls_conjunction_set *conj_set;

                conj_set = ovsrcu_get_protected(struct cls_conjunction_set *,
                                                &iter->conj_set);
                if (conj_set) {
                    ovsrcu_postpone(free, conj_set);
                }

                ovsrcu_postpone(free, iter);
                old->cls_match = NULL;

                /* No change in subtable's max priority or max count. */

                /* Make rule visible to lookups? */
                new->visible = cls->publish;

                /* Make rule visible to iterators (immediately). */
                rculist_replace(CONST_CAST(struct rculist *, &rule->node),
                                &old->node);

                /* Return displaced rule.  Caller is responsible for keeping it
                 * around until all threads quiesce. */
                return old;
            }
        } else {
            rculist_push_back(&head->list, &new->list);
        }
    }

    /* Make rule visible to lookups? */
    new->visible = cls->publish;

    /* Make rule visible to iterators (immediately). */
    rculist_push_back(&subtable->rules_list,
                      CONST_CAST(struct rculist *, &rule->node));

    /* Rule was added, not replaced.  Update 'subtable's 'max_priority' and
     * 'max_count', if necessary.
     *
     * The rule was already inserted, but concurrent readers may not see the
     * rule yet as the subtables vector is not updated yet.  This will have to
     * be fixed by revalidation later. */
    if (n_rules == 1) {
        subtable->max_priority = rule->priority;
        subtable->max_count = 1;
        pvector_insert(&cls->subtables, subtable, rule->priority);
    } else if (rule->priority == subtable->max_priority) {
        ++subtable->max_count;
    } else if (rule->priority > subtable->max_priority) {
        subtable->max_priority = rule->priority;
        subtable->max_count = 1;
        pvector_change_priority(&cls->subtables, subtable, rule->priority);
    }

    /* Nothing was replaced. */
    cls->n_rules++;

    if (cls->publish) {
        pvector_publish(&cls->subtables);
    }

    return NULL;
}

/* Inserts 'rule' into 'cls'.  Until 'rule' is removed from 'cls', the caller
 * must not modify or free it.
 *
 * 'cls' must not contain an identical rule (including wildcards, values of
 * fixed fields, and priority).  Use classifier_find_rule_exactly() to find
 * such a rule. */
void
classifier_insert(struct classifier *cls, const struct cls_rule *rule,
                  const struct cls_conjunction conj[], size_t n_conj)
{
    const struct cls_rule *displaced_rule
        = classifier_replace(cls, rule, conj, n_conj);
    ovs_assert(!displaced_rule);
}

/* Removes 'rule' from 'cls'.  It is the caller's responsibility to destroy
 * 'rule' with cls_rule_destroy(), freeing the memory block in which 'rule'
 * resides, etc., as necessary.
 *
 * Does nothing if 'rule' has been already removed, or was never inserted.
 *
 * Returns the removed rule, or NULL, if it was already removed.
 */
const struct cls_rule *
classifier_remove(struct classifier *cls, const struct cls_rule *cls_rule)
{
    struct cls_match *rule, *prev, *next;
    struct cls_partition *partition;
    struct cls_conjunction_set *conj_set;
    struct cls_subtable *subtable;
    int i;
    uint32_t basis = 0, hash, ihash[CLS_MAX_INDICES];
    uint8_t prev_be64ofs = 0;
    size_t n_rules;

    rule = cls_rule->cls_match;
    if (!rule) {
        return NULL;
    }
    /* Mark as removed. */
    CONST_CAST(struct cls_rule *, cls_rule)->cls_match = NULL;

    /* Remove 'cls_rule' from the subtable's rules list. */
    rculist_remove(CONST_CAST(struct rculist *, &cls_rule->node));

    INIT_CONTAINER(prev, rculist_back_protected(&rule->list), list);
    INIT_CONTAINER(next, rculist_next(&rule->list), list);

    /* Remove from the list of equal rules. */
    rculist_remove(&rule->list);

    /* Cheap check for a non-head rule. */
    if (prev->priority > rule->priority) {
        /* Not the highest priority rule, no need to check subtable's
         * 'max_priority'. */
        goto free;
    }

    subtable = find_subtable(cls, &cls_rule->match.mask);
    ovs_assert(subtable);

    for (i = 0; i < subtable->n_indices; i++) {
        ihash[i] = minimatch_hash_range(&cls_rule->match, prev_be64ofs,
                                        subtable->index_ofs[i], &basis);
        prev_be64ofs = subtable->index_ofs[i];
    }
    hash = minimatch_hash_range(&cls_rule->match, prev_be64ofs, FLOW_U64S,
                                &basis);

    /* Check if the rule is not the head rule. */
    if (rule != prev &&
        rule != find_equal(subtable, &cls_rule->match.flow, hash)) {
        /* Not the head rule, but potentially one with the same priority. */
        goto check_priority;
    }

    /* 'rule' is the head rule.  Check if there is another rule to
     * replace 'rule' in the data structures. */
    if (next != rule) {
        subtable_replace_head_rule(cls, subtable, rule, next, hash, ihash);
        goto check_priority;
    }

    /* 'rule' is last of the kind in the classifier, must remove from all the
     * data structures. */

    if (subtable->ports_mask_len) {
        ovs_be32 masked_ports = minimatch_get_ports(&cls_rule->match);

        trie_remove_prefix(&subtable->ports_trie,
                           &masked_ports, subtable->ports_mask_len);
    }
    for (i = 0; i < cls->n_tries; i++) {
        if (subtable->trie_plen[i]) {
            trie_remove(&cls->tries[i], cls_rule, subtable->trie_plen[i]);
        }
    }

    /* Remove rule node from indices. */
    for (i = 0; i < subtable->n_indices; i++) {
        cmap_remove(&subtable->indices[i], &rule->index_nodes[i], ihash[i]);
    }
    n_rules = cmap_remove(&subtable->rules, &rule->cmap_node, hash);

    partition = rule->partition;
    if (partition) {
        tag_tracker_subtract(&partition->tracker, &partition->tags,
                             subtable->tag);
        if (!partition->tags) {
            cmap_remove(&cls->partitions, &partition->cmap_node,
                        hash_metadata(partition->metadata));
            ovsrcu_postpone(free, partition);
        }
    }

    if (n_rules == 0) {
        destroy_subtable(cls, subtable);
    } else {
check_priority:
        if (subtable->max_priority == rule->priority
            && --subtable->max_count == 0) {
            /* Find the new 'max_priority' and 'max_count'. */
            int max_priority = INT_MIN;
            struct cls_match *head;

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
    }

    if (cls->publish) {
        pvector_publish(&cls->subtables);
    }

free:
    conj_set = ovsrcu_get_protected(struct cls_conjunction_set *,
                                    &rule->conj_set);
    if (conj_set) {
        ovsrcu_postpone(free, conj_set);
    }
    ovsrcu_postpone(free, rule);
    cls->n_rules--;

    return cls_rule;
}

/* Prefix tree context.  Valid when 'lookup_done' is true.  Can skip all
 * subtables which have a prefix match on the trie field, but whose prefix
 * length is not indicated in 'match_plens'.  For example, a subtable that
 * has a 8-bit trie field prefix match can be skipped if
 * !be_get_bit_at(&match_plens, 8 - 1).  If skipped, 'maskbits' prefix bits
 * must be unwildcarded to make datapath flow only match packets it should. */
struct trie_ctx {
    const struct cls_trie *trie;
    bool lookup_done;        /* Status of the lookup. */
    uint8_t be32ofs;         /* U32 offset of the field in question. */
    unsigned int maskbits;   /* Prefix length needed to avoid false matches. */
    union mf_value match_plens; /* Bitmask of prefix lengths with possible
                                 * matches. */
};

static void
trie_ctx_init(struct trie_ctx *ctx, const struct cls_trie *trie)
{
    ctx->trie = trie;
    ctx->be32ofs = trie->field->flow_be32ofs;
    ctx->lookup_done = false;
}

struct conjunctive_match {
    struct hmap_node hmap_node;
    uint32_t id;
    uint64_t clauses;
};

static struct conjunctive_match *
find_conjunctive_match__(struct hmap *matches, uint64_t id, uint32_t hash)
{
    struct conjunctive_match *m;

    HMAP_FOR_EACH_IN_BUCKET (m, hmap_node, hash, matches) {
        if (m->id == id) {
            return m;
        }
    }
    return NULL;
}

static bool
find_conjunctive_match(const struct cls_conjunction_set *set,
                       unsigned int max_n_clauses, struct hmap *matches,
                       struct conjunctive_match *cm_stubs, size_t n_cm_stubs,
                       uint32_t *idp)
{
    const struct cls_conjunction *c;

    if (max_n_clauses < set->min_n_clauses) {
        return false;
    }

    for (c = set->conj; c < &set->conj[set->n]; c++) {
        struct conjunctive_match *cm;
        uint32_t hash;

        if (c->n_clauses > max_n_clauses) {
            continue;
        }

        hash = hash_int(c->id, 0);
        cm = find_conjunctive_match__(matches, c->id, hash);
        if (!cm) {
            size_t n = hmap_count(matches);

            cm = n < n_cm_stubs ? &cm_stubs[n] : xmalloc(sizeof *cm);
            hmap_insert(matches, &cm->hmap_node, hash);
            cm->id = c->id;
            cm->clauses = UINT64_MAX << (c->n_clauses & 63);
        }
        cm->clauses |= UINT64_C(1) << c->clause;
        if (cm->clauses == UINT64_MAX) {
            *idp = cm->id;
            return true;
        }
    }
    return false;
}

static void
free_conjunctive_matches(struct hmap *matches,
                         struct conjunctive_match *cm_stubs, size_t n_cm_stubs)
{
    if (hmap_count(matches) > n_cm_stubs) {
        struct conjunctive_match *cm, *next;

        HMAP_FOR_EACH_SAFE (cm, next, hmap_node, matches) {
            if (!(cm >= cm_stubs && cm < &cm_stubs[n_cm_stubs])) {
                free(cm);
            }
        }
    }
    hmap_destroy(matches);
}

/* Like classifier_lookup(), except that support for conjunctive matches can be
 * configured with 'allow_conjunctive_matches'.  That feature is not exposed
 * externally because turning off conjunctive matches is only useful to avoid
 * recursion within this function itself.
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
static const struct cls_rule *
classifier_lookup__(const struct classifier *cls, struct flow *flow,
                    struct flow_wildcards *wc, bool allow_conjunctive_matches)
{
    const struct cls_partition *partition;
    struct trie_ctx trie_ctx[CLS_MAX_TRIES];
    const struct cls_match *match;
    tag_type tags;

    /* Highest-priority flow in 'cls' that certainly matches 'flow'. */
    const struct cls_match *hard = NULL;
    int hard_pri = INT_MIN;     /* hard ? hard->priority : INT_MIN. */

    /* Highest-priority conjunctive flows in 'cls' matching 'flow'.  Since
     * these are (components of) conjunctive flows, we can only know whether
     * the full conjunctive flow matches after seeing multiple of them.  Thus,
     * we refer to these as "soft matches". */
    struct cls_conjunction_set *soft_stub[64];
    struct cls_conjunction_set **soft = soft_stub;
    size_t n_soft = 0, allocated_soft = ARRAY_SIZE(soft_stub);
    int soft_pri = INT_MIN;    /* n_soft ? MAX(soft[*]->priority) : INT_MIN. */

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

    /* Initialize trie contexts for find_match_wc(). */
    for (int i = 0; i < cls->n_tries; i++) {
        trie_ctx_init(&trie_ctx[i], &cls->tries[i]);
    }

    /* Main loop. */
    struct cls_subtable *subtable;
    PVECTOR_FOR_EACH_PRIORITY (subtable, hard_pri, 2, sizeof *subtable,
                               &cls->subtables) {
        struct cls_conjunction_set *conj_set;

        /* Skip subtables not in our partition. */
        if (!tag_intersects(tags, subtable->tag)) {
            continue;
        }

        /* Skip subtables with no match, or where the match is lower-priority
         * than some certain match we've already found. */
        match = find_match_wc(subtable, flow, trie_ctx, cls->n_tries, wc);
        if (!match || match->priority <= hard_pri) {
            continue;
        }

        conj_set = ovsrcu_get(struct cls_conjunction_set *, &match->conj_set);
        if (!conj_set) {
            /* 'match' isn't part of a conjunctive match.  It's the best
             * certain match we've got so far, since we know that it's
             * higher-priority than hard_pri.
             *
             * (There might be a higher-priority conjunctive match.  We can't
             * tell yet.) */
            hard = match;
            hard_pri = hard->priority;
        } else if (allow_conjunctive_matches) {
            /* 'match' is part of a conjunctive match.  Add it to the list. */
            if (OVS_UNLIKELY(n_soft >= allocated_soft)) {
                struct cls_conjunction_set **old_soft = soft;

                allocated_soft *= 2;
                soft = xmalloc(allocated_soft * sizeof *soft);
                memcpy(soft, old_soft, n_soft * sizeof *soft);
                if (old_soft != soft_stub) {
                    free(old_soft);
                }
            }
            soft[n_soft++] = conj_set;

            /* Keep track of the highest-priority soft match. */
            if (soft_pri < match->priority) {
                soft_pri = match->priority;
            }
        }
    }

    /* In the common case, at this point we have no soft matches and we can
     * return immediately.  (We do the same thing if we have potential soft
     * matches but none of them are higher-priority than our hard match.) */
    if (hard_pri >= soft_pri) {
        if (soft != soft_stub) {
            free(soft);
        }
        return hard ? hard->cls_rule : NULL;
    }

    /* At this point, we have some soft matches.  We might also have a hard
     * match; if so, its priority is lower than the highest-priority soft
     * match. */

    /* Soft match loop.
     *
     * Check whether soft matches are real matches. */
    for (;;) {
        /* Delete soft matches that are null.  This only happens in second and
         * subsequent iterations of the soft match loop, when we drop back from
         * a high-priority soft match to a lower-priority one.
         *
         * Also, delete soft matches whose priority is less than or equal to
         * the hard match's priority.  In the first iteration of the soft
         * match, these can be in 'soft' because the earlier main loop found
         * the soft match before the hard match.  In second and later iteration
         * of the soft match loop, these can be in 'soft' because we dropped
         * back from a high-priority soft match to a lower-priority soft match.
         *
         * It is tempting to delete soft matches that cannot be satisfied
         * because there are fewer soft matches than required to satisfy any of
         * their conjunctions, but we cannot do that because there might be
         * lower priority soft or hard matches with otherwise identical
         * matches.  (We could special case those here, but there's no
         * need--we'll do so at the bottom of the soft match loop anyway and
         * this duplicates less code.)
         *
         * It's also tempting to break out of the soft match loop if 'n_soft ==
         * 1' but that would also miss lower-priority hard matches.  We could
         * special case that also but again there's no need. */
        for (int i = 0; i < n_soft; ) {
            if (!soft[i] || soft[i]->priority <= hard_pri) {
                soft[i] = soft[--n_soft];
            } else {
                i++;
            }
        }
        if (!n_soft) {
            break;
        }

        /* Find the highest priority among the soft matches.  (We know this
         * must be higher than the hard match's priority; otherwise we would
         * have deleted all of the soft matches in the previous loop.)  Count
         * the number of soft matches that have that priority. */
        soft_pri = INT_MIN;
        int n_soft_pri = 0;
        for (int i = 0; i < n_soft; i++) {
            if (soft[i]->priority > soft_pri) {
                soft_pri = soft[i]->priority;
                n_soft_pri = 1;
            } else if (soft[i]->priority == soft_pri) {
                n_soft_pri++;
            }
        }
        ovs_assert(soft_pri > hard_pri);

        /* Look for a real match among the highest-priority soft matches.
         *
         * It's unusual to have many conjunctive matches, so we use stubs to
         * avoid calling malloc() in the common case.  An hmap has a built-in
         * stub for up to 2 hmap_nodes; possibly, we would benefit a variant
         * with a bigger stub. */
        struct conjunctive_match cm_stubs[16];
        struct hmap matches;

        hmap_init(&matches);
        for (int i = 0; i < n_soft; i++) {
            uint32_t id;

            if (soft[i]->priority == soft_pri
                && find_conjunctive_match(soft[i], n_soft_pri, &matches,
                                          cm_stubs, ARRAY_SIZE(cm_stubs),
                                          &id)) {
                uint32_t saved_conj_id = flow->conj_id;
                const struct cls_rule *rule;

                flow->conj_id = id;
                rule = classifier_lookup__(cls, flow, wc, false);
                flow->conj_id = saved_conj_id;

                if (rule) {
                    free_conjunctive_matches(&matches,
                                             cm_stubs, ARRAY_SIZE(cm_stubs));
                    if (soft != soft_stub) {
                        free(soft);
                    }
                    return rule;
                }
            }
        }
        free_conjunctive_matches(&matches, cm_stubs, ARRAY_SIZE(cm_stubs));

        /* There's no real match among the highest-priority soft matches.
         * However, if any of those soft matches has a lower-priority but
         * otherwise identical flow match, then we need to consider those for
         * soft or hard matches.
         *
         * The next iteration of the soft match loop will delete any null
         * pointers we put into 'soft' (and some others too). */
        for (int i = 0; i < n_soft; i++) {
            if (soft[i]->priority != soft_pri) {
                continue;
            }

            /* Find next-lower-priority flow with identical flow match. */
            match = next_visible_rule_in_list(soft[i]->match);
            if (match) {
                soft[i] = ovsrcu_get(struct cls_conjunction_set *,
                                     &match->conj_set);
                if (!soft[i]) {
                    /* The flow is a hard match; don't treat as a soft
                     * match. */
                    if (match->priority > hard_pri) {
                        hard = match;
                        hard_pri = hard->priority;
                    }
                }
            } else {
                /* No such lower-priority flow (probably the common case). */
                soft[i] = NULL;
            }
        }
    }

    if (soft != soft_stub) {
        free(soft);
    }
    return hard ? hard->cls_rule : NULL;
}

/* Finds and returns the highest-priority rule in 'cls' that matches 'flow'.
 * Returns a null pointer if no rules in 'cls' match 'flow'.  If multiple rules
 * of equal priority match 'flow', returns one arbitrarily.
 *
 * If a rule is found and 'wc' is non-null, bitwise-OR's 'wc' with the
 * set of bits that were significant in the lookup.  At some point
 * earlier, 'wc' should have been initialized (e.g., by
 * flow_wildcards_init_catchall()).
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
const struct cls_rule *
classifier_lookup(const struct classifier *cls, struct flow *flow,
                  struct flow_wildcards *wc)
{
    return classifier_lookup__(cls, flow, wc, true);
}

/* Finds and returns a rule in 'cls' with exactly the same priority and
 * matching criteria as 'target'.  Returns a null pointer if 'cls' doesn't
 * contain an exact match.
 *
 * Returns the first matching rule that is not 'to_be_removed'.  Only one such
 * rule may exist. */
const struct cls_rule *
classifier_find_rule_exactly(const struct classifier *cls,
                             const struct cls_rule *target)
{
    const struct cls_match *head, *rule;
    const struct cls_subtable *subtable;

    subtable = find_subtable(cls, &target->match.mask);
    if (!subtable) {
        return NULL;
    }

    head = find_equal(subtable, &target->match.flow,
                      miniflow_hash_in_minimask(&target->match.flow,
                                                &target->match.mask, 0));
    if (!head) {
        return NULL;
    }
    FOR_EACH_RULE_IN_LIST (rule, head) {
        if (rule->priority < target->priority) {
            break; /* Not found. */
        }
        if (rule->priority == target->priority
            && !rule->cls_rule->to_be_removed) {
            return rule->cls_rule;
        }
    }
    return NULL;
}

/* Finds and returns a rule in 'cls' with priority 'priority' and exactly the
 * same matching criteria as 'target'.  Returns a null pointer if 'cls' doesn't
 * contain an exact match. */
const struct cls_rule *
classifier_find_match_exactly(const struct classifier *cls,
                              const struct match *target, int priority)
{
    const struct cls_rule *retval;
    struct cls_rule cr;

    cls_rule_init(&cr, target, priority);
    retval = classifier_find_rule_exactly(cls, &cr);
    cls_rule_destroy(&cr);

    return retval;
}

/* Checks if 'target' would overlap any other rule in 'cls'.  Two rules are
 * considered to overlap if both rules have the same priority and a packet
 * could match both.
 *
 * A trivial example of overlapping rules is two rules matching disjoint sets
 * of fields. E.g., if one rule matches only on port number, while another only
 * on dl_type, any packet from that specific port and with that specific
 * dl_type could match both, if the rules also have the same priority.
 *
 * 'target' is not considered to overlap with a rule that has been marked
 * as 'to_be_removed'.
 */
bool
classifier_rule_overlaps(const struct classifier *cls,
                         const struct cls_rule *target)
{
    struct cls_subtable *subtable;

    /* Iterate subtables in the descending max priority order. */
    PVECTOR_FOR_EACH_PRIORITY (subtable, target->priority - 1, 2,
                               sizeof(struct cls_subtable), &cls->subtables) {
        uint64_t storage[FLOW_U64S];
        struct minimask mask;
        const struct cls_rule *rule;

        minimask_combine(&mask, &target->match.mask, &subtable->mask, storage);

        RCULIST_FOR_EACH (rule, node, &subtable->rules_list) {
            if (rule->priority == target->priority
                && !rule->to_be_removed
                && miniflow_equal_in_minimask(&target->match.flow,
                                              &rule->match.flow, &mask)) {
                return true;
            }
        }
    }
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
rule_matches(const struct cls_rule *rule, const struct cls_rule *target)
{
    /* Iterators never see rules that have been marked for removal.
     * This allows them to be oblivious of duplicate rules. */
    return (!rule->to_be_removed &&
            (!target
             || miniflow_equal_in_minimask(&rule->match.flow,
                                           &target->match.flow,
                                           &target->match.mask)));
}

static const struct cls_rule *
search_subtable(const struct cls_subtable *subtable,
                struct cls_cursor *cursor)
{
    if (!cursor->target
        || !minimask_has_extra(&subtable->mask, &cursor->target->match.mask)) {
        const struct cls_rule *rule;

        RCULIST_FOR_EACH (rule, node, &subtable->rules_list) {
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
struct cls_cursor
cls_cursor_start(const struct classifier *cls, const struct cls_rule *target)
{
    struct cls_cursor cursor;
    struct cls_subtable *subtable;

    cursor.cls = cls;
    cursor.target = target && !cls_rule_is_catchall(target) ? target : NULL;
    cursor.rule = NULL;

    /* Find first rule. */
    PVECTOR_CURSOR_FOR_EACH (subtable, &cursor.subtables,
                             &cursor.cls->subtables) {
        const struct cls_rule *rule = search_subtable(subtable, &cursor);

        if (rule) {
            cursor.subtable = subtable;
            cursor.rule = rule;
            break;
        }
    }

    return cursor;
}

static const struct cls_rule *
cls_cursor_next(struct cls_cursor *cursor)
{
    const struct cls_rule *rule;
    const struct cls_subtable *subtable;

    rule = cursor->rule;
    subtable = cursor->subtable;
    RCULIST_FOR_EACH_CONTINUE (rule, node, &subtable->rules_list) {
        if (rule_matches(rule, cursor->target)) {
            return rule;
        }
    }

    PVECTOR_CURSOR_FOR_EACH_CONTINUE (subtable, &cursor->subtables) {
        rule = search_subtable(subtable, cursor);
        if (rule) {
            cursor->subtable = subtable;
            return rule;
        }
    }

    return NULL;
}

/* Sets 'cursor->rule' to the next matching cls_rule in 'cursor''s iteration,
 * or to null if all matching rules have been visited. */
void
cls_cursor_advance(struct cls_cursor *cursor)
{
    cursor->rule = cls_cursor_next(cursor);
}

static struct cls_subtable *
find_subtable(const struct classifier *cls, const struct minimask *mask)
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
insert_subtable(struct classifier *cls, const struct minimask *mask)
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
    miniflow_clone_inline(CONST_CAST(struct miniflow *, &subtable->mask.masks),
                          &mask->masks, count);

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
            *CONST_CAST(uint8_t *, &subtable->index_ofs[index])
                = cls->flow_segments[i];
            index++;
            old = new;
        }
        prev = cls->flow_segments[i];
    }
    /* Check if the rest of the subtable's mask adds any bits,
     * and remove the last index if it doesn't. */
    if (index > 0) {
        flow_wildcards_fold_minimask_range(&new, mask, prev, FLOW_U64S);
        if (flow_wildcards_equal(&new, &old)) {
            --index;
            *CONST_CAST(uint8_t *, &subtable->index_ofs[index]) = 0;
            cmap_destroy(&subtable->indices[index]);
        }
    }
    *CONST_CAST(uint8_t *, &subtable->n_indices) = index;

    *CONST_CAST(tag_type *, &subtable->tag) =
        (minimask_get_metadata_mask(mask) == OVS_BE64_MAX
         ? tag_create_deterministic(hash)
         : TAG_ALL);

    for (i = 0; i < cls->n_tries; i++) {
        subtable->trie_plen[i] = minimask_get_prefix_len(mask,
                                                         cls->tries[i].field);
    }

    /* Ports trie. */
    ovsrcu_set_hidden(&subtable->ports_trie, NULL);
    *CONST_CAST(int *, &subtable->ports_mask_len)
        = 32 - ctz32(ntohl(MINIFLOW_GET_BE32(&mask->masks, tp_src)));

    /* List of rules. */
    rculist_init(&subtable->rules_list);

    cmap_insert(&cls->subtables_map, &subtable->cmap_node, hash);

    return subtable;
}

/* RCU readers may still access the subtable before it is actually freed. */
static void
destroy_subtable(struct classifier *cls, struct cls_subtable *subtable)
{
    int i;

    pvector_remove(&cls->subtables, subtable);
    cmap_remove(&cls->subtables_map, &subtable->cmap_node,
                minimask_hash(&subtable->mask, 0));

    ovs_assert(ovsrcu_get_protected(struct trie_node *, &subtable->ports_trie)
               == NULL);
    ovs_assert(cmap_is_empty(&subtable->rules));
    ovs_assert(rculist_is_empty(&subtable->rules_list));

    for (i = 0; i < subtable->n_indices; i++) {
        cmap_destroy(&subtable->indices[i]);
    }
    cmap_destroy(&subtable->rules);
    ovsrcu_postpone(free, subtable);
}

struct range {
    uint8_t start;
    uint8_t end;
};

static unsigned int be_get_bit_at(const ovs_be32 value[], unsigned int ofs);

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
            uint8_t be64ofs = be32ofs / 2;

            /* Is the trie field within the current range of fields? */
            if (be64ofs >= ofs.start && be64ofs < ofs.end) {
                /* On-demand trie lookup. */
                if (!ctx->lookup_done) {
                    memset(&ctx->match_plens, 0, sizeof ctx->match_plens);
                    ctx->maskbits = trie_lookup(ctx->trie, flow,
                                                &ctx->match_plens);
                    ctx->lookup_done = true;
                }
                /* Possible to skip the rest of the subtable if subtable's
                 * prefix on the field is not included in the lookup result. */
                if (!be_get_bit_at(&ctx->match_plens.be32, field_plen[j] - 1)) {
                    /* We want the trie lookup to never result in unwildcarding
                     * any bits that would not be unwildcarded otherwise.
                     * Since the trie is shared by the whole classifier, it is
                     * possible that the 'maskbits' contain bits that are
                     * irrelevant for the partition relevant for the current
                     * packet.  Hence the checks below. */

                    /* Check that the trie result will not unwildcard more bits
                     * than this subtable would otherwise. */
                    if (ctx->maskbits <= field_plen[j]) {
                        /* Unwildcard the bits and skip the rest. */
                        mask_set_prefix_bits(wc, be32ofs, ctx->maskbits);
                        /* Note: Prerequisite already unwildcarded, as the only
                         * prerequisite of the supported trie lookup fields is
                         * the ethertype, which is always unwildcarded. */
                        return true;
                    }
                    /* Can skip if the field is already unwildcarded. */
                    if (mask_prefix_bits_set(wc, be32ofs, ctx->maskbits)) {
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
    const uint64_t *flowp = miniflow_get_values(flow);
    const uint64_t *maskp = miniflow_get_values(&mask->masks);
    int idx;

    MAP_FOR_EACH_INDEX(idx, mask->masks.map) {
        uint64_t diff = (*flowp++ ^ flow_u64_value(target, idx)) & *maskp++;

        if (diff) {
            return false;
        }
    }

    return true;
}

static inline const struct cls_match *
find_match(const struct cls_subtable *subtable, const struct flow *flow,
           uint32_t hash)
{
    const struct cls_match *head, *rule;

    CMAP_FOR_EACH_WITH_HASH (head, cmap_node, hash, &subtable->rules) {
        if (OVS_LIKELY(miniflow_and_mask_matches_flow(&head->flow,
                                                      &subtable->mask,
                                                      flow))) {
            /* Return highest priority rule that is visible. */
            FOR_EACH_RULE_IN_LIST(rule, head) {
                if (OVS_LIKELY(rule->visible)) {
                    return rule;
                }
            }
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
    const uint64_t *flowp = miniflow_get_values(flow);
    const uint64_t *maskp = miniflow_get_values(&mask->masks);
    int idx;

    MAP_FOR_EACH_INDEX(idx, mask->masks.map) {
        uint64_t mask = *maskp++;
        uint64_t diff = (*flowp++ ^ flow_u64_value(target, idx)) & mask;

        if (diff) {
            /* Only unwildcard if none of the differing bits is already
             * exact-matched. */
            if (!(flow_u64_value(&wc->masks, idx) & diff)) {
                /* Keep one bit of the difference.  The selected bit may be
                 * different in big-endian v.s. little-endian systems. */
                *flow_u64_lvalue(&wc->masks, idx) |= rightmost_1bit(diff);
            }
            return false;
        }
        /* Fill in the bits that were looked at. */
        *flow_u64_lvalue(&wc->masks, idx) |= mask;
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

static const struct cls_match *
find_match_wc(const struct cls_subtable *subtable, const struct flow *flow,
              struct trie_ctx trie_ctx[CLS_MAX_TRIES], unsigned int n_tries,
              struct flow_wildcards *wc)
{
    uint32_t basis = 0, hash;
    const struct cls_match *rule = NULL;
    int i;
    struct range ofs;

    if (OVS_UNLIKELY(!wc)) {
        return find_match(subtable, flow,
                          flow_hash_in_minimask(flow, &subtable->mask, 0));
    }

    ofs.start = 0;
    /* Try to finish early by checking fields in segments. */
    for (i = 0; i < subtable->n_indices; i++) {
        const struct cmap_node *inode;

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
            const struct cls_match *head;

            ASSIGN_CONTAINER(head, inode - i, index_nodes);
            if (miniflow_and_mask_matches_flow_wc(&head->flow, &subtable->mask,
                                                  flow, wc)) {
                /* Return highest priority rule that is visible. */
                FOR_EACH_RULE_IN_LIST(rule, head) {
                    if (OVS_LIKELY(rule->visible)) {
                        return rule;
                    }
                }
            }
            return NULL;
        }
        ofs.start = ofs.end;
    }
    ofs.end = FLOW_U64S;
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
        ovs_be32 value, plens, mask;

        mask = MINIFLOW_GET_BE32(&subtable->mask.masks, tp_src);
        value = ((OVS_FORCE ovs_be32 *)flow)[TP_PORTS_OFS32] & mask;
        mbits = trie_lookup_value(&subtable->ports_trie, &value, &plens, 32);

        ((OVS_FORCE ovs_be32 *)&wc->masks)[TP_PORTS_OFS32] |=
            mask & be32_prefix_mask(mbits);

        /* Unwildcard all bits in the mask upto the ports, as they were used
         * to determine there is no match. */
        fill_range_wc(subtable, wc, TP_PORTS_OFS64);
        return NULL;
    }

    /* Must unwildcard all the fields, as they were looked at. */
    flow_wildcards_fold_minimask(wc, &subtable->mask);
    return rule;
}

static struct cls_match *
find_equal(const struct cls_subtable *subtable, const struct miniflow *flow,
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

/* A longest-prefix match tree. */

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

/* Set the bit at ("MSB 0"-based) offset 'ofs'.  'ofs' can be greater than 31.
 */
static void
be_set_bit_at(ovs_be32 value[], unsigned int ofs)
{
    ((uint8_t *)value)[ofs / 8] |= 1u << (7 - ofs % 8);
}

/* Returns the number of bits in the prefix mask necessary to determine a
 * mismatch, in case there are longer prefixes in the tree below the one that
 * matched.
 * '*plens' will have a bit set for each prefix length that may have matching
 * rules.  The caller is responsible for clearing the '*plens' prior to
 * calling this.
 */
static unsigned int
trie_lookup_value(const rcu_trie_ptr *trie, const ovs_be32 value[],
                  ovs_be32 plens[], unsigned int n_bits)
{
    const struct trie_node *prev = NULL;
    const struct trie_node *node = ovsrcu_get(struct trie_node *, trie);
    unsigned int match_len = 0; /* Number of matching bits. */

    for (; node; prev = node, node = trie_next_node(node, value, match_len)) {
        unsigned int eqbits;
        /* Check if this edge can be followed. */
        eqbits = prefix_equal_bits(node->prefix, node->n_bits, value,
                                   match_len);
        match_len += eqbits;
        if (eqbits < node->n_bits) { /* Mismatch, nothing more to be found. */
            /* Bit at offset 'match_len' differed. */
            return match_len + 1; /* Includes the first mismatching bit. */
        }
        /* Full match, check if rules exist at this prefix length. */
        if (node->n_rules > 0) {
            be_set_bit_at(plens, match_len - 1);
        }
        if (match_len >= n_bits) {
            return n_bits; /* Full prefix. */
        }
    }
    /* node == NULL.  Full match so far, but we tried to follow an
     * non-existing branch.  Need to exclude the other branch if it exists
     * (it does not if we were called on an empty trie or 'prev' is a leaf
     * node). */
    return !prev || trie_is_leaf(prev) ? match_len : match_len + 1;
}

static unsigned int
trie_lookup(const struct cls_trie *trie, const struct flow *flow,
            union mf_value *plens)
{
    const struct mf_field *mf = trie->field;

    /* Check that current flow matches the prerequisites for the trie
     * field.  Some match fields are used for multiple purposes, so we
     * must check that the trie is relevant for this flow. */
    if (mf_are_prereqs_ok(mf, flow)) {
        return trie_lookup_value(&trie->root,
                                 &((ovs_be32 *)flow)[mf->flow_be32ofs],
                                 &plens->be32, mf->n_bits);
    }
    memset(plens, 0xff, sizeof *plens); /* All prefixes, no skipping. */
    return 0; /* Value not used in this case. */
}

/* Returns the length of a prefix match mask for the field 'mf' in 'minimask'.
 * Returns the u32 offset to the miniflow data in '*miniflow_index', if
 * 'miniflow_index' is not NULL. */
static unsigned int
minimask_get_prefix_len(const struct minimask *minimask,
                        const struct mf_field *mf)
{
    unsigned int n_bits = 0, mask_tz = 0; /* Non-zero when end of mask seen. */
    uint8_t be32_ofs = mf->flow_be32ofs;
    uint8_t be32_end = be32_ofs + mf->n_bytes / 4;

    for (; be32_ofs < be32_end; ++be32_ofs) {
        uint32_t mask = ntohl(minimask_get_be32(minimask, be32_ofs));

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
    return (OVS_FORCE const ovs_be32 *)
        (miniflow_get_values(&match->flow)
         + count_1bits(match->flow.map &
                       ((UINT64_C(1) << mf->flow_be32ofs / 2) - 1)))
        + (mf->flow_be32ofs & 1);
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
