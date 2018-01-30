/*
 * Copyright (c) 2009-2017 Nicira, Inc.
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
#include <sys/types.h>
#include <netinet/in.h>
#include "byte-order.h"
#include "openvswitch/dynamic-string.h"
#include "odp-util.h"
#include "openvswitch/ofp-util.h"
#include "packets.h"
#include "util.h"

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
cls_match_alloc(const struct cls_rule *rule, ovs_version_t version,
                const struct cls_conjunction conj[], size_t n)
{
    size_t count = miniflow_n_values(rule->match.flow);

    struct cls_match *cls_match
        = xmalloc(sizeof *cls_match + MINIFLOW_VALUES_SIZE(count));

    ovsrcu_init(&cls_match->next, NULL);
    *CONST_CAST(const struct cls_rule **, &cls_match->cls_rule) = rule;
    *CONST_CAST(int *, &cls_match->priority) = rule->priority;
    /* Make rule initially invisible. */
    cls_match->versions = VERSIONS_INITIALIZER(version, version);
    miniflow_clone(CONST_CAST(struct miniflow *, &cls_match->flow),
                   rule->match.flow, count);
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
                                             ovs_version_t version,
                                             const struct flow *,
                                             struct trie_ctx *,
                                             unsigned int n_tries,
                                             struct flow_wildcards *);
static struct cls_match *find_equal(const struct cls_subtable *,
                                    const struct miniflow *, uint32_t hash);

/* Return the next visible (lower-priority) rule in the list.  Multiple
 * identical rules with the same priority may exist transitionally, but when
 * versioning is used at most one of them is ever visible for lookups on any
 * given 'version'. */
static inline const struct cls_match *
next_visible_rule_in_list(const struct cls_match *rule, ovs_version_t version)
{
    do {
        rule = cls_match_next(rule);
    } while (rule && !cls_match_visible_in_version(rule, version));

    return rule;
}

/* Type with maximum supported prefix length. */
union trie_prefix {
    struct in6_addr ipv6;  /* For sizing. */
    ovs_be32 be32;         /* For access. */
};

static unsigned int minimask_get_prefix_len(const struct minimask *,
                                            const struct mf_field *);
static void trie_init(struct classifier *cls, int trie_idx,
                      const struct mf_field *);
static unsigned int trie_lookup(const struct cls_trie *, const struct flow *,
                                union trie_prefix *plens);
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
    *CONST_CAST(int *, &rule->priority) = priority;
    ovsrcu_init(&rule->cls_match, NULL);
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
    minimatch_init(CONST_CAST(struct minimatch *, &rule->match), match);
}

/* Same as cls_rule_init() for initialization from a "struct minimatch". */
void
cls_rule_init_from_minimatch(struct cls_rule *rule,
                             const struct minimatch *match, int priority)
{
    cls_rule_init__(rule, priority);
    minimatch_clone(CONST_CAST(struct minimatch *, &rule->match), match);
}

/* Initializes 'dst' as a copy of 'src'.
 *
 * The caller must eventually destroy 'dst' with cls_rule_destroy(). */
void
cls_rule_clone(struct cls_rule *dst, const struct cls_rule *src)
{
    cls_rule_init__(dst, src->priority);
    minimatch_clone(CONST_CAST(struct minimatch *, &dst->match), &src->match);
}

/* Initializes 'dst' with the data in 'src', destroying 'src'.
 *
 * 'src' must be a cls_rule NOT in a classifier.
 *
 * The caller must eventually destroy 'dst' with cls_rule_destroy(). */
void
cls_rule_move(struct cls_rule *dst, struct cls_rule *src)
{
    cls_rule_init__(dst, src->priority);
    minimatch_move(CONST_CAST(struct minimatch *, &dst->match),
                   CONST_CAST(struct minimatch *, &src->match));
}

/* Frees memory referenced by 'rule'.  Doesn't free 'rule' itself (it's
 * normally embedded into a larger structure).
 *
 * ('rule' must not currently be in a classifier.) */
void
cls_rule_destroy(struct cls_rule *rule)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    /* Must not be in a classifier. */
    ovs_assert(!get_cls_match_protected(rule));

    /* Check that the rule has been properly removed from the classifier. */
    ovs_assert(rule->node.prev == RCULIST_POISON
               || rculist_is_empty(&rule->node));
    rculist_poison__(&rule->node);   /* Poisons also the next pointer. */

    minimatch_destroy(CONST_CAST(struct minimatch *, &rule->match));
}

/* This may only be called by the exclusive writer. */
void
cls_rule_set_conjunctions(struct cls_rule *cr,
                          const struct cls_conjunction *conj, size_t n)
{
    struct cls_match *match = get_cls_match_protected(cr);
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

/* Appends a string describing 'rule' to 's'. */
void
cls_rule_format(const struct cls_rule *rule, const struct tun_table *tun_table,
                const struct ofputil_port_map *port_map, struct ds *s)
{
    minimatch_format(&rule->match, tun_table, port_map, s, rule->priority);
}

/* Returns true if 'rule' matches every packet, false otherwise. */
bool
cls_rule_is_catchall(const struct cls_rule *rule)
{
    return minimask_is_catchall(rule->match.mask);
}

/* Makes 'rule' invisible in 'remove_version'.  Once that version is used in
 * lookups, the caller should remove 'rule' via ovsrcu_postpone().
 *
 * 'rule' must be in a classifier.
 * This may only be called by the exclusive writer. */
void
cls_rule_make_invisible_in_version(const struct cls_rule *rule,
                                   ovs_version_t remove_version)
{
    struct cls_match *cls_match = get_cls_match_protected(rule);

    ovs_assert(remove_version >= cls_match->versions.add_version);

    cls_match_set_remove_version(cls_match, remove_version);
}

/* This undoes the change made by cls_rule_make_invisible_in_version().
 *
 * 'rule' must be in a classifier.
 * This may only be called by the exclusive writer. */
void
cls_rule_restore_visibility(const struct cls_rule *rule)
{
    cls_match_set_remove_version(get_cls_match_protected(rule),
                                 OVS_VERSION_NOT_REMOVED);
}

/* Return true if 'rule' is visible in 'version'.
 *
 * 'rule' must be in a classifier. */
bool
cls_rule_visible_in_version(const struct cls_rule *rule, ovs_version_t version)
{
    struct cls_match *cls_match = get_cls_match(rule);

    return cls_match && cls_match_visible_in_version(cls_match, version);
}

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
void
classifier_init(struct classifier *cls, const uint8_t *flow_segments)
{
    cls->n_rules = 0;
    cmap_init(&cls->subtables_map);
    pvector_init(&cls->subtables);
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
        struct cls_subtable *subtable;
        int i;

        for (i = 0; i < cls->n_tries; i++) {
            trie_destroy(&cls->tries[i].root);
        }

        CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) {
            destroy_subtable(cls, subtable);
        }
        cmap_destroy(&cls->subtables_map);

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

static inline ovs_be32 minimatch_get_ports(const struct minimatch *match)
{
    /* Could optimize to use the same map if needed for fast path. */
    return MINIFLOW_GET_BE32(match->flow, tp_src)
        & MINIFLOW_GET_BE32(&match->mask->masks, tp_src);
}

/* Inserts 'rule' into 'cls' in 'version'.  Until 'rule' is removed from 'cls',
 * the caller must not modify or free it.
 *
 * If 'cls' already contains an identical rule (including wildcards, values of
 * fixed fields, and priority) that is visible in 'version', replaces the old
 * rule by 'rule' and returns the rule that was replaced.  The caller takes
 * ownership of the returned rule and is thus responsible for destroying it
 * with cls_rule_destroy(), after RCU grace period has passed (see
 * ovsrcu_postpone()).
 *
 * Returns NULL if 'cls' does not contain a rule with an identical key, after
 * inserting the new rule.  In this case, no rules are displaced by the new
 * rule, even rules that cannot have any effect because the new rule matches a
 * superset of their flows and has higher priority.
 */
const struct cls_rule *
classifier_replace(struct classifier *cls, const struct cls_rule *rule,
                   ovs_version_t version,
                   const struct cls_conjunction *conjs, size_t n_conjs)
{
    struct cls_match *new;
    struct cls_subtable *subtable;
    uint32_t ihash[CLS_MAX_INDICES];
    struct cls_match *head;
    unsigned int mask_offset;
    size_t n_rules = 0;
    uint32_t basis;
    uint32_t hash;
    unsigned int i;

    /* 'new' is initially invisible to lookups. */
    new = cls_match_alloc(rule, version, conjs, n_conjs);
    ovsrcu_set(&CONST_CAST(struct cls_rule *, rule)->cls_match, new);

    subtable = find_subtable(cls, rule->match.mask);
    if (!subtable) {
        subtable = insert_subtable(cls, rule->match.mask);
    }

    /* Compute hashes in segments. */
    basis = 0;
    mask_offset = 0;
    for (i = 0; i < subtable->n_indices; i++) {
        ihash[i] = minimatch_hash_range(&rule->match, subtable->index_maps[i],
                                        &mask_offset, &basis);
    }
    hash = minimatch_hash_range(&rule->match, subtable->index_maps[i],
                                &mask_offset, &basis);

    head = find_equal(subtable, rule->match.flow, hash);
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

        /* Add new node to segment indices. */
        for (i = 0; i < subtable->n_indices; i++) {
            ccmap_inc(&subtable->indices[i], ihash[i]);
        }
        n_rules = cmap_insert(&subtable->rules, &new->cmap_node, hash);
    } else {   /* Equal rules exist in the classifier already. */
        struct cls_match *prev, *iter;

        /* Scan the list for the insertion point that will keep the list in
         * order of decreasing priority.  Insert after rules marked invisible
         * in any version of the same priority. */
        FOR_EACH_RULE_IN_LIST_PROTECTED (iter, prev, head) {
            if (rule->priority > iter->priority
                || (rule->priority == iter->priority
                    && !cls_match_is_eventually_invisible(iter))) {
                break;
            }
        }

        /* Replace 'iter' with 'new' or insert 'new' between 'prev' and
         * 'iter'. */
        if (iter) {
            struct cls_rule *old;

            if (rule->priority == iter->priority) {
                cls_match_replace(prev, iter, new);
                old = CONST_CAST(struct cls_rule *, iter->cls_rule);
            } else {
                cls_match_insert(prev, iter, new);
                old = NULL;
            }

            /* Replace the existing head in data structures, if rule is the new
             * head. */
            if (iter == head) {
                cmap_replace(&subtable->rules, &head->cmap_node,
                             &new->cmap_node, hash);
            }

            if (old) {
                struct cls_conjunction_set *conj_set;

                conj_set = ovsrcu_get_protected(struct cls_conjunction_set *,
                                                &iter->conj_set);
                if (conj_set) {
                    ovsrcu_postpone(free, conj_set);
                }

                ovsrcu_set(&old->cls_match, NULL); /* Marks old rule as removed
                                                    * from the classifier. */
                ovsrcu_postpone(cls_match_free_cb, iter);

                /* No change in subtable's max priority or max count. */

                /* Make 'new' visible to lookups in the appropriate version. */
                cls_match_set_remove_version(new, OVS_VERSION_NOT_REMOVED);

                /* Make rule visible to iterators (immediately). */
                rculist_replace(CONST_CAST(struct rculist *, &rule->node),
                                &old->node);

                /* Return displaced rule.  Caller is responsible for keeping it
                 * around until all threads quiesce. */
                return old;
            }
        } else {
            /* 'new' is new node after 'prev' */
            cls_match_insert(prev, iter, new);
        }
    }

    /* Make 'new' visible to lookups in the appropriate version. */
    cls_match_set_remove_version(new, OVS_VERSION_NOT_REMOVED);

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
                  ovs_version_t version, const struct cls_conjunction conj[],
                  size_t n_conj)
{
    const struct cls_rule *displaced_rule
        = classifier_replace(cls, rule, version, conj, n_conj);
    ovs_assert(!displaced_rule);
}

/* If 'rule' is in 'cls', removes 'rule' from 'cls' and returns true.  It is
 * the caller's responsibility to destroy 'rule' with cls_rule_destroy(),
 * freeing the memory block in which 'rule' resides, etc., as necessary.
 *
 * If 'rule' is not in any classifier, returns false without making any
 * changes.
 *
 * 'rule' must not be in some classifier other than 'cls'.
 */
bool
classifier_remove(struct classifier *cls, const struct cls_rule *cls_rule)
{
    struct cls_match *rule, *prev, *next, *head;
    struct cls_conjunction_set *conj_set;
    struct cls_subtable *subtable;
    uint32_t basis = 0, hash, ihash[CLS_MAX_INDICES];
    unsigned int mask_offset;
    size_t n_rules;
    unsigned int i;

    rule = get_cls_match_protected(cls_rule);
    if (!rule) {
        return false;
    }
    /* Mark as removed. */
    ovsrcu_set(&CONST_CAST(struct cls_rule *, cls_rule)->cls_match, NULL);

    /* Remove 'cls_rule' from the subtable's rules list. */
    rculist_remove(CONST_CAST(struct rculist *, &cls_rule->node));

    subtable = find_subtable(cls, cls_rule->match.mask);
    ovs_assert(subtable);

    mask_offset = 0;
    for (i = 0; i < subtable->n_indices; i++) {
        ihash[i] = minimatch_hash_range(&cls_rule->match,
                                        subtable->index_maps[i],
                                        &mask_offset, &basis);
    }
    hash = minimatch_hash_range(&cls_rule->match, subtable->index_maps[i],
                                &mask_offset, &basis);

    head = find_equal(subtable, cls_rule->match.flow, hash);

    /* Check if the rule is not the head rule. */
    if (rule != head) {
        struct cls_match *iter;

        /* Not the head rule, but potentially one with the same priority. */
        /* Remove from the list of equal rules. */
        FOR_EACH_RULE_IN_LIST_PROTECTED (iter, prev, head) {
            if (rule == iter) {
                break;
            }
        }
        ovs_assert(iter == rule);

        cls_match_remove(prev, rule);

        goto check_priority;
    }

    /* 'rule' is the head rule.  Check if there is another rule to
     * replace 'rule' in the data structures. */
    next = cls_match_next_protected(rule);
    if (next) {
        cmap_replace(&subtable->rules, &rule->cmap_node, &next->cmap_node,
                     hash);
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
        ccmap_dec(&subtable->indices[i], ihash[i]);
    }
    n_rules = cmap_remove(&subtable->rules, &rule->cmap_node, hash);

    if (n_rules == 0) {
        destroy_subtable(cls, subtable);
    } else {
check_priority:
        if (subtable->max_priority == rule->priority
            && --subtable->max_count == 0) {
            /* Find the new 'max_priority' and 'max_count'. */
            int max_priority = INT_MIN;
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

    /* free the rule. */
    conj_set = ovsrcu_get_protected(struct cls_conjunction_set *,
                                    &rule->conj_set);
    if (conj_set) {
        ovsrcu_postpone(free, conj_set);
    }
    ovsrcu_postpone(cls_match_free_cb, rule);
    cls->n_rules--;

    return true;
}

void
classifier_remove_assert(struct classifier *cls,
                         const struct cls_rule *cls_rule)
{
    ovs_assert(classifier_remove(cls, cls_rule));
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
    union trie_prefix match_plens;  /* Bitmask of prefix lengths with possible
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
classifier_lookup__(const struct classifier *cls, ovs_version_t version,
                    struct flow *flow, struct flow_wildcards *wc,
                    bool allow_conjunctive_matches)
{
    struct trie_ctx trie_ctx[CLS_MAX_TRIES];
    const struct cls_match *match;
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

    /* Initialize trie contexts for find_match_wc(). */
    for (int i = 0; i < cls->n_tries; i++) {
        trie_ctx_init(&trie_ctx[i], &cls->tries[i]);
    }

    /* Main loop. */
    struct cls_subtable *subtable;
    PVECTOR_FOR_EACH_PRIORITY (subtable, hard_pri + 1, 2, sizeof *subtable,
                               &cls->subtables) {
        struct cls_conjunction_set *conj_set;

        /* Skip subtables with no match, or where the match is lower-priority
         * than some certain match we've already found. */
        match = find_match_wc(subtable, version, flow, trie_ctx, cls->n_tries,
                              wc);
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
                rule = classifier_lookup__(cls, version, flow, wc, false);
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
            match = next_visible_rule_in_list(soft[i]->match, version);
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

/* Finds and returns the highest-priority rule in 'cls' that matches 'flow' and
 * that is visible in 'version'.  Returns a null pointer if no rules in 'cls'
 * match 'flow'.  If multiple rules of equal priority match 'flow', returns one
 * arbitrarily.
 *
 * If a rule is found and 'wc' is non-null, bitwise-OR's 'wc' with the
 * set of bits that were significant in the lookup.  At some point
 * earlier, 'wc' should have been initialized (e.g., by
 * flow_wildcards_init_catchall()).
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
const struct cls_rule *
classifier_lookup(const struct classifier *cls, ovs_version_t version,
                  struct flow *flow, struct flow_wildcards *wc)
{
    return classifier_lookup__(cls, version, flow, wc, true);
}

/* Finds and returns a rule in 'cls' with exactly the same priority and
 * matching criteria as 'target', and that is visible in 'version'.
 * Only one such rule may ever exist.  Returns a null pointer if 'cls' doesn't
 * contain an exact match. */
const struct cls_rule *
classifier_find_rule_exactly(const struct classifier *cls,
                             const struct cls_rule *target,
                             ovs_version_t version)
{
    const struct cls_match *head, *rule;
    const struct cls_subtable *subtable;

    subtable = find_subtable(cls, target->match.mask);
    if (!subtable) {
        return NULL;
    }

    head = find_equal(subtable, target->match.flow,
                      miniflow_hash_in_minimask(target->match.flow,
                                                target->match.mask, 0));
    if (!head) {
        return NULL;
    }
    CLS_MATCH_FOR_EACH (rule, head) {
        if (rule->priority < target->priority) {
            break; /* Not found. */
        }
        if (rule->priority == target->priority
            && cls_match_visible_in_version(rule, version)) {
            return rule->cls_rule;
        }
    }
    return NULL;
}

/* Finds and returns a rule in 'cls' with priority 'priority' and exactly the
 * same matching criteria as 'target', and that is visible in 'version'.
 * Returns a null pointer if 'cls' doesn't contain an exact match visible in
 * 'version'. */
const struct cls_rule *
classifier_find_match_exactly(const struct classifier *cls,
                              const struct match *target, int priority,
                              ovs_version_t version)
{
    const struct cls_rule *retval;
    struct cls_rule cr;

    cls_rule_init(&cr, target, priority);
    retval = classifier_find_rule_exactly(cls, &cr, version);
    cls_rule_destroy(&cr);

    return retval;
}

/* Checks if 'target' would overlap any other rule in 'cls' in 'version'.  Two
 * rules are considered to overlap if both rules have the same priority and a
 * packet could match both, and if both rules are visible in the same version.
 *
 * A trivial example of overlapping rules is two rules matching disjoint sets
 * of fields. E.g., if one rule matches only on port number, while another only
 * on dl_type, any packet from that specific port and with that specific
 * dl_type could match both, if the rules also have the same priority. */
bool
classifier_rule_overlaps(const struct classifier *cls,
                         const struct cls_rule *target, ovs_version_t version)
{
    struct cls_subtable *subtable;

    /* Iterate subtables in the descending max priority order. */
    PVECTOR_FOR_EACH_PRIORITY (subtable, target->priority, 2,
                               sizeof(struct cls_subtable), &cls->subtables) {
        struct {
            struct minimask mask;
            uint64_t storage[FLOW_U64S];
        } m;
        const struct cls_rule *rule;

        minimask_combine(&m.mask, target->match.mask, &subtable->mask,
                         m.storage);

        RCULIST_FOR_EACH (rule, node, &subtable->rules_list) {
            if (rule->priority == target->priority
                && miniflow_equal_in_minimask(target->match.flow,
                                              rule->match.flow, &m.mask)
                && cls_rule_visible_in_version(rule, version)) {
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
    return (!minimask_has_extra(rule->match.mask, criteria->mask)
            && miniflow_equal_in_minimask(rule->match.flow, criteria->flow,
                                          criteria->mask));
}

/* Iteration. */

static bool
rule_matches(const struct cls_rule *rule, const struct cls_rule *target,
             ovs_version_t version)
{
    /* Rule may only match a target if it is visible in target's version. */
    return cls_rule_visible_in_version(rule, version)
        && (!target || miniflow_equal_in_minimask(rule->match.flow,
                                                  target->match.flow,
                                                  target->match.mask));
}

static const struct cls_rule *
search_subtable(const struct cls_subtable *subtable,
                struct cls_cursor *cursor)
{
    if (!cursor->target
        || !minimask_has_extra(&subtable->mask, cursor->target->match.mask)) {
        const struct cls_rule *rule;

        RCULIST_FOR_EACH (rule, node, &subtable->rules_list) {
            if (rule_matches(rule, cursor->target, cursor->version)) {
                return rule;
            }
        }
    }
    return NULL;
}

/* Initializes 'cursor' for iterating through rules in 'cls', and returns the
 * cursor.
 *
 *     - If 'target' is null, or if the 'target' is a catchall target, the
 *       cursor will visit every rule in 'cls' that is visible in 'version'.
 *
 *     - If 'target' is nonnull, the cursor will visit each 'rule' in 'cls'
 *       such that cls_rule_is_loose_match(rule, target) returns true and that
 *       the rule is visible in 'version'.
 *
 * Ignores target->priority. */
struct cls_cursor
cls_cursor_start(const struct classifier *cls, const struct cls_rule *target,
                 ovs_version_t version)
{
    struct cls_cursor cursor;
    struct cls_subtable *subtable;

    cursor.cls = cls;
    cursor.target = target && !cls_rule_is_catchall(target) ? target : NULL;
    cursor.version = version;
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
        if (rule_matches(rule, cursor->target, cursor->version)) {
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

/* Initializes 'map' with a subset of 'miniflow''s maps that includes only the
 * portions with u64-offset 'i' such that 'start' <= i < 'end'.  Does not copy
 * any data from 'miniflow' to 'map'. */
static struct flowmap
miniflow_get_map_in_range(const struct miniflow *miniflow, uint8_t start,
                          uint8_t end)
{
    struct flowmap map;
    size_t ofs = 0;

    map = miniflow->map;

    /* Clear the bits before 'start'. */
    while (start >= MAP_T_BITS) {
        start -= MAP_T_BITS;
        ofs += MAP_T_BITS;
        map.bits[start / MAP_T_BITS] = 0;
    }
    if (start > 0) {
        flowmap_clear(&map, ofs, start);
    }

    /* Clear the bits starting at 'end'. */
    if (end < FLOW_U64S) {
        /* flowmap_clear() can handle at most MAP_T_BITS at a time. */
        ovs_assert(FLOW_U64S - end <= MAP_T_BITS);
        flowmap_clear(&map, end, FLOW_U64S - end);
    }
    return map;
}

/* The new subtable will be visible to the readers only after this. */
static struct cls_subtable *
insert_subtable(struct classifier *cls, const struct minimask *mask)
{
    uint32_t hash = minimask_hash(mask, 0);
    struct cls_subtable *subtable;
    int i, index = 0;
    struct flowmap stage_map;
    uint8_t prev;
    size_t count = miniflow_n_values(&mask->masks);

    subtable = xzalloc(sizeof *subtable + MINIFLOW_VALUES_SIZE(count));
    cmap_init(&subtable->rules);
    miniflow_clone(CONST_CAST(struct miniflow *, &subtable->mask.masks),
                   &mask->masks, count);

    /* Init indices for segmented lookup, if any. */
    prev = 0;
    for (i = 0; i < cls->n_flow_segments; i++) {
        stage_map = miniflow_get_map_in_range(&mask->masks, prev,
                                              cls->flow_segments[i]);
        /* Add an index if it adds mask bits. */
        if (!flowmap_is_empty(stage_map)) {
            ccmap_init(&subtable->indices[index]);
            *CONST_CAST(struct flowmap *, &subtable->index_maps[index])
                = stage_map;
            index++;
        }
        prev = cls->flow_segments[i];
    }
    /* Map for the final stage. */
    *CONST_CAST(struct flowmap *, &subtable->index_maps[index])
        = miniflow_get_map_in_range(&mask->masks, prev, FLOW_U64S);
    /* Check if the final stage adds any bits. */
    if (index > 0) {
        if (flowmap_is_empty(subtable->index_maps[index])) {
            /* Remove the last index, as it has the same fields as the rules
             * map. */
            --index;
            ccmap_destroy(&subtable->indices[index]);
        }
    }
    *CONST_CAST(uint8_t *, &subtable->n_indices) = index;

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
        ccmap_destroy(&subtable->indices[i]);
    }
    cmap_destroy(&subtable->rules);
    ovsrcu_postpone(free, subtable);
}

static unsigned int be_get_bit_at(const ovs_be32 value[], unsigned int ofs);

/* Return 'true' if can skip rest of the subtable based on the prefix trie
 * lookup results. */
static inline bool
check_tries(struct trie_ctx trie_ctx[CLS_MAX_TRIES], unsigned int n_tries,
            const unsigned int field_plen[CLS_MAX_TRIES],
            const struct flowmap range_map, const struct flow *flow,
            struct flow_wildcards *wc)
{
    int j;

    /* Check if we could avoid fully unwildcarding the next level of
     * fields using the prefix tries.  The trie checks are done only as
     * needed to avoid folding in additional bits to the wildcards mask. */
    for (j = 0; j < n_tries; j++) {
        /* Is the trie field relevant for this subtable, and
           is the trie field within the current range of fields? */
        if (field_plen[j] &&
            flowmap_is_set(&range_map, trie_ctx[j].be32ofs / 2)) {
            struct trie_ctx *ctx = &trie_ctx[j];

            /* On-demand trie lookup. */
            if (!ctx->lookup_done) {
                memset(&ctx->match_plens, 0, sizeof ctx->match_plens);
                ctx->maskbits = trie_lookup(ctx->trie, flow, &ctx->match_plens);
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
                    mask_set_prefix_bits(wc, ctx->be32ofs, ctx->maskbits);
                    /* Note: Prerequisite already unwildcarded, as the only
                     * prerequisite of the supported trie lookup fields is
                     * the ethertype, which is always unwildcarded. */
                    return true;
                }
                /* Can skip if the field is already unwildcarded. */
                if (mask_prefix_bits_set(wc, ctx->be32ofs, ctx->maskbits)) {
                    return true;
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
    const uint64_t *target_u64 = (const uint64_t *)target;
    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, mask->masks.map) {
        size_t idx;

        MAP_FOR_EACH_INDEX (idx, map) {
            if ((*flowp++ ^ target_u64[idx]) & *maskp++) {
                return false;
            }
        }
        target_u64 += MAP_T_BITS;
    }
    return true;
}

static inline const struct cls_match *
find_match(const struct cls_subtable *subtable, ovs_version_t version,
           const struct flow *flow, uint32_t hash)
{
    const struct cls_match *head, *rule;

    CMAP_FOR_EACH_WITH_HASH (head, cmap_node, hash, &subtable->rules) {
        if (OVS_LIKELY(miniflow_and_mask_matches_flow(&head->flow,
                                                      &subtable->mask,
                                                      flow))) {
            /* Return highest priority rule that is visible. */
            CLS_MATCH_FOR_EACH (rule, head) {
                if (OVS_LIKELY(cls_match_visible_in_version(rule, version))) {
                    return rule;
                }
            }
        }
    }

    return NULL;
}

static const struct cls_match *
find_match_wc(const struct cls_subtable *subtable, ovs_version_t version,
              const struct flow *flow, struct trie_ctx trie_ctx[CLS_MAX_TRIES],
              unsigned int n_tries, struct flow_wildcards *wc)
{
    if (OVS_UNLIKELY(!wc)) {
        return find_match(subtable, version, flow,
                          flow_hash_in_minimask(flow, &subtable->mask, 0));
    }

    uint32_t basis = 0, hash;
    const struct cls_match *rule = NULL;
    struct flowmap stages_map = FLOWMAP_EMPTY_INITIALIZER;
    unsigned int mask_offset = 0;
    int i;

    /* Try to finish early by checking fields in segments. */
    for (i = 0; i < subtable->n_indices; i++) {
        if (check_tries(trie_ctx, n_tries, subtable->trie_plen,
                        subtable->index_maps[i], flow, wc)) {
            /* 'wc' bits for the trie field set, now unwildcard the preceding
             * bits used so far. */
            goto no_match;
        }

        /* Accumulate the map used so far. */
        stages_map = flowmap_or(stages_map, subtable->index_maps[i]);

        hash = flow_hash_in_minimask_range(flow, &subtable->mask,
                                           subtable->index_maps[i],
                                           &mask_offset, &basis);

        if (!ccmap_find(&subtable->indices[i], hash)) {
            goto no_match;
        }
    }
    /* Trie check for the final range. */
    if (check_tries(trie_ctx, n_tries, subtable->trie_plen,
                    subtable->index_maps[i], flow, wc)) {
        goto no_match;
    }
    hash = flow_hash_in_minimask_range(flow, &subtable->mask,
                                       subtable->index_maps[i],
                                       &mask_offset, &basis);
    rule = find_match(subtable, version, flow, hash);
    if (!rule && subtable->ports_mask_len) {
        /* The final stage had ports, but there was no match.  Instead of
         * unwildcarding all the ports bits, use the ports trie to figure out a
         * smaller set of bits to unwildcard. */
        unsigned int mbits;
        ovs_be32 value, plens, mask;

        mask = MINIFLOW_GET_BE32(&subtable->mask.masks, tp_src);
        value = ((OVS_FORCE ovs_be32 *)flow)[TP_PORTS_OFS32] & mask;
        mbits = trie_lookup_value(&subtable->ports_trie, &value, &plens, 32);

        ((OVS_FORCE ovs_be32 *)&wc->masks)[TP_PORTS_OFS32] |=
            mask & be32_prefix_mask(mbits);

        goto no_match;
    }

    /* Must unwildcard all the fields, as they were looked at. */
    flow_wildcards_fold_minimask(wc, &subtable->mask);
    return rule;

no_match:
    /* Unwildcard the bits in stages so far, as they were used in determining
     * there is no match. */
    flow_wildcards_fold_minimask_in_map(wc, &subtable->mask, stages_map);
    return NULL;
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
            union trie_prefix *plens)
{
    const struct mf_field *mf = trie->field;

    /* Check that current flow matches the prerequisites for the trie
     * field.  Some match fields are used for multiple purposes, so we
     * must check that the trie is relevant for this flow. */
    if (mf_are_prereqs_ok(mf, flow, NULL)) {
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
    size_t u64_ofs = mf->flow_be32ofs / 2;

    return (OVS_FORCE const ovs_be32 *)miniflow_get__(match->flow, u64_ofs)
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
    rcu_trie_ptr *edges[sizeof(union trie_prefix) * CHAR_BIT];
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
}


#define CLS_MATCH_POISON (struct cls_match *)(UINTPTR_MAX / 0xf * 0xb)

void
cls_match_free_cb(struct cls_match *rule)
{
    ovsrcu_set_hidden(&rule->next, CLS_MATCH_POISON);
    free(rule);
}
