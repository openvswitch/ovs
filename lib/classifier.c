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
#include "odp-util.h"
#include "ofp-util.h"
#include "packets.h"
#include "ovs-thread.h"

static struct cls_subtable *find_subtable(const struct classifier *,
                                          const struct minimask *);
static struct cls_subtable *insert_subtable(struct classifier *,
                                            const struct minimask *);

static void destroy_subtable(struct classifier *, struct cls_subtable *);

static void update_subtables_after_insertion(struct classifier *,
                                             struct cls_subtable *,
                                             unsigned int new_priority);
static void update_subtables_after_removal(struct classifier *,
                                           struct cls_subtable *,
                                           unsigned int del_priority);

static struct cls_rule *find_match_wc(const struct cls_subtable *,
                                      const struct flow *,
                                      struct flow_wildcards *);
static struct cls_rule *find_equal(struct cls_subtable *,
                                   const struct miniflow *, uint32_t hash);
static struct cls_rule *insert_rule(struct classifier *,
                                    struct cls_subtable *, struct cls_rule *);

/* Iterates RULE over HEAD and all of the cls_rules on HEAD->list. */
#define FOR_EACH_RULE_IN_LIST(RULE, HEAD)                               \
    for ((RULE) = (HEAD); (RULE) != NULL; (RULE) = next_rule_in_list(RULE))
#define FOR_EACH_RULE_IN_LIST_SAFE(RULE, NEXT, HEAD)                    \
    for ((RULE) = (HEAD);                                               \
         (RULE) != NULL && ((NEXT) = next_rule_in_list(RULE), true);    \
         (RULE) = (NEXT))

static struct cls_rule *next_rule_in_list__(struct cls_rule *);
static struct cls_rule *next_rule_in_list(struct cls_rule *);

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
}

/* Same as cls_rule_init() for initialization from a "struct minimatch". */
void
cls_rule_init_from_minimatch(struct cls_rule *rule,
                             const struct minimatch *match,
                             unsigned int priority)
{
    minimatch_clone(&rule->match, match);
    rule->priority = priority;
}

/* Initializes 'dst' as a copy of 'src'.
 *
 * The caller must eventually destroy 'dst' with cls_rule_destroy(). */
void
cls_rule_clone(struct cls_rule *dst, const struct cls_rule *src)
{
    minimatch_clone(&dst->match, &src->match);
    dst->priority = src->priority;
}

/* Initializes 'dst' with the data in 'src', destroying 'src'.
 *
 * The caller must eventually destroy 'dst' with cls_rule_destroy(). */
void
cls_rule_move(struct cls_rule *dst, struct cls_rule *src)
{
    minimatch_move(&dst->match, &src->match);
    dst->priority = src->priority;
}

/* Frees memory referenced by 'rule'.  Doesn't free 'rule' itself (it's
 * normally embedded into a larger structure).
 *
 * ('rule' must not currently be in a classifier.) */
void
cls_rule_destroy(struct cls_rule *rule)
{
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
classifier_init(struct classifier *cls, const uint8_t *flow_segments)
{
    cls->n_rules = 0;
    hmap_init(&cls->subtables);
    list_init(&cls->subtables_priority);
    hmap_init(&cls->partitions);
    ovs_rwlock_init(&cls->rwlock);
    cls->n_flow_segments = 0;
    if (flow_segments) {
        while (cls->n_flow_segments < CLS_MAX_INDICES
               && *flow_segments < FLOW_U32S) {
            cls->flow_segments[cls->n_flow_segments++] = *flow_segments++;
        }
    }
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility. */
void
classifier_destroy(struct classifier *cls)
{
    if (cls) {
        struct cls_subtable *partition, *next_partition;
        struct cls_subtable *subtable, *next_subtable;

        HMAP_FOR_EACH_SAFE (subtable, next_subtable, hmap_node,
                            &cls->subtables) {
            destroy_subtable(cls, subtable);
        }
        hmap_destroy(&cls->subtables);

        HMAP_FOR_EACH_SAFE (partition, next_partition, hmap_node,
                            &cls->partitions) {
            hmap_remove(&cls->partitions, &partition->hmap_node);
            free(partition);
        }
        hmap_destroy(&cls->partitions);
        ovs_rwlock_destroy(&cls->rwlock);
    }
}

/* Returns true if 'cls' contains no classification rules, false otherwise. */
bool
classifier_is_empty(const struct classifier *cls)
{
    return cls->n_rules == 0;
}

/* Returns the number of rules in 'cls'. */
int
classifier_count(const struct classifier *cls)
{
    return cls->n_rules;
}

static uint32_t
hash_metadata(ovs_be64 metadata_)
{
    uint64_t metadata = (OVS_FORCE uint64_t) metadata_;
    return hash_2words(metadata, metadata >> 32);
}

static struct cls_partition *
find_partition(const struct classifier *cls, ovs_be64 metadata, uint32_t hash)
{
    struct cls_partition *partition;

    HMAP_FOR_EACH_IN_BUCKET (partition, hmap_node, hash, &cls->partitions) {
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
        hmap_insert(&cls->partitions, &partition->hmap_node, hash);
    }
    tag_tracker_add(&partition->tracker, &partition->tags, subtable->tag);
    return partition;
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
classifier_replace(struct classifier *cls, struct cls_rule *rule)
{
    struct cls_rule *old_rule;
    struct cls_subtable *subtable;

    subtable = find_subtable(cls, &rule->match.mask);
    if (!subtable) {
        subtable = insert_subtable(cls, &rule->match.mask);
    }

    old_rule = insert_rule(cls, subtable, rule);
    if (!old_rule) {
        if (minimask_get_metadata_mask(&rule->match.mask) == OVS_BE64_MAX) {
            ovs_be64 metadata = miniflow_get_metadata(&rule->match.flow);
            rule->partition = create_partition(cls, subtable, metadata);
        } else {
            rule->partition = NULL;
        }

        subtable->n_rules++;
        cls->n_rules++;
    } else {
        rule->partition = old_rule->partition;
    }
    return old_rule;
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
classifier_remove(struct classifier *cls, struct cls_rule *rule)
{
    struct cls_partition *partition;
    struct cls_rule *head;
    struct cls_subtable *subtable;
    int i;

    subtable = find_subtable(cls, &rule->match.mask);

    /* Remove rule node from indices. */
    for (i = 0; i < subtable->n_indices; i++) {
        hindex_remove(&subtable->indices[i], &rule->index_nodes[i]);
    }

    head = find_equal(subtable, &rule->match.flow, rule->hmap_node.hash);
    if (head != rule) {
        list_remove(&rule->list);
    } else if (list_is_empty(&rule->list)) {
        hmap_remove(&subtable->rules, &rule->hmap_node);
    } else {
        struct cls_rule *next = CONTAINER_OF(rule->list.next,
                                             struct cls_rule, list);

        list_remove(&rule->list);
        hmap_replace(&subtable->rules, &rule->hmap_node, &next->hmap_node);
    }

    partition = rule->partition;
    if (partition) {
        tag_tracker_subtract(&partition->tracker, &partition->tags,
                             subtable->tag);
        if (!partition->tags) {
            hmap_remove(&cls->partitions, &partition->hmap_node);
            free(partition);
        }
    }

    if (--subtable->n_rules == 0) {
        destroy_subtable(cls, subtable);
    } else {
        update_subtables_after_removal(cls, subtable, rule->priority);
    }
    cls->n_rules--;
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
classifier_lookup(const struct classifier *cls, const struct flow *flow,
                  struct flow_wildcards *wc)
{
    const struct cls_partition *partition;
    struct cls_subtable *subtable;
    struct cls_rule *best;
    tag_type tags;

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
    partition = (hmap_is_empty(&cls->partitions)
                 ? NULL
                 : find_partition(cls, flow->metadata,
                                  hash_metadata(flow->metadata)));
    tags = partition ? partition->tags : TAG_ARBITRARY;

    best = NULL;
    LIST_FOR_EACH (subtable, list_node, &cls->subtables_priority) {
        struct cls_rule *rule;

        if (!tag_intersects(tags, subtable->tag)) {
            continue;
        }

        rule = find_match_wc(subtable, flow, wc);
        if (rule) {
            best = rule;
            LIST_FOR_EACH_CONTINUE (subtable, list_node,
                                    &cls->subtables_priority) {
                if (subtable->max_priority <= best->priority) {
                    /* Subtables are in descending priority order,
                     * can not find anything better. */
                    return best;
                }
                if (!tag_intersects(tags, subtable->tag)) {
                    continue;
                }

                rule = find_match_wc(subtable, flow, wc);
                if (rule && rule->priority > best->priority) {
                    best = rule;
                }
            }
            break;
        }
    }
    return best;
}

/* Finds and returns a rule in 'cls' with exactly the same priority and
 * matching criteria as 'target'.  Returns a null pointer if 'cls' doesn't
 * contain an exact match. */
struct cls_rule *
classifier_find_rule_exactly(const struct classifier *cls,
                             const struct cls_rule *target)
{
    struct cls_rule *head, *rule;
    struct cls_subtable *subtable;

    subtable = find_subtable(cls, &target->match.mask);
    if (!subtable) {
        return NULL;
    }

    /* Skip if there is no hope. */
    if (target->priority > subtable->max_priority) {
        return NULL;
    }

    head = find_equal(subtable, &target->match.flow,
                      miniflow_hash_in_minimask(&target->match.flow,
                                                &target->match.mask, 0));
    FOR_EACH_RULE_IN_LIST (rule, head) {
        if (target->priority >= rule->priority) {
            return target->priority == rule->priority ? rule : NULL;
        }
    }
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
classifier_rule_overlaps(const struct classifier *cls,
                         const struct cls_rule *target)
{
    struct cls_subtable *subtable;

    /* Iterate subtables in the descending max priority order. */
    LIST_FOR_EACH (subtable, list_node, &cls->subtables_priority) {
        uint32_t storage[FLOW_U32S];
        struct minimask mask;
        struct cls_rule *head;

        if (target->priority > subtable->max_priority) {
            break; /* Can skip this and the rest of the subtables. */
        }

        minimask_combine(&mask, &target->match.mask, &subtable->mask, storage);
        HMAP_FOR_EACH (head, hmap_node, &subtable->rules) {
            struct cls_rule *rule;

            FOR_EACH_RULE_IN_LIST (rule, head) {
                if (rule->priority < target->priority) {
                    break; /* Rules in descending priority order. */
                }
                if (rule->priority == target->priority
                    && miniflow_equal_in_minimask(&target->match.flow,
                                                  &rule->match.flow, &mask)) {
                    return true;
                }
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
    return (!target
            || miniflow_equal_in_minimask(&rule->match.flow,
                                          &target->match.flow,
                                          &target->match.mask));
}

static struct cls_rule *
search_subtable(const struct cls_subtable *subtable,
                const struct cls_rule *target)
{
    if (!target || !minimask_has_extra(&subtable->mask, &target->match.mask)) {
        struct cls_rule *rule;

        HMAP_FOR_EACH (rule, hmap_node, &subtable->rules) {
            if (rule_matches(rule, target)) {
                return rule;
            }
        }
    }
    return NULL;
}

/* Initializes 'cursor' for iterating through rules in 'cls':
 *
 *     - If 'target' is null, the cursor will visit every rule in 'cls'.
 *
 *     - If 'target' is nonnull, the cursor will visit each 'rule' in 'cls'
 *       such that cls_rule_is_loose_match(rule, target) returns true.
 *
 * Ignores target->priority. */
void
cls_cursor_init(struct cls_cursor *cursor, const struct classifier *cls,
                const struct cls_rule *target)
{
    cursor->cls = cls;
    cursor->target = target && !cls_rule_is_catchall(target) ? target : NULL;
}

/* Returns the first matching cls_rule in 'cursor''s iteration, or a null
 * pointer if there are no matches. */
struct cls_rule *
cls_cursor_first(struct cls_cursor *cursor)
{
    struct cls_subtable *subtable;

    HMAP_FOR_EACH (subtable, hmap_node, &cursor->cls->subtables) {
        struct cls_rule *rule = search_subtable(subtable, cursor->target);
        if (rule) {
            cursor->subtable = subtable;
            return rule;
        }
    }

    return NULL;
}

/* Returns the next matching cls_rule in 'cursor''s iteration, or a null
 * pointer if there are no more matches. */
struct cls_rule *
cls_cursor_next(struct cls_cursor *cursor, const struct cls_rule *rule_)
{
    struct cls_rule *rule = CONST_CAST(struct cls_rule *, rule_);
    const struct cls_subtable *subtable;
    struct cls_rule *next;

    next = next_rule_in_list__(rule);
    if (next->priority < rule->priority) {
        return next;
    }

    /* 'next' is the head of the list, that is, the rule that is included in
     * the subtable's hmap.  (This is important when the classifier contains
     * rules that differ only in priority.) */
    rule = next;
    HMAP_FOR_EACH_CONTINUE (rule, hmap_node, &cursor->subtable->rules) {
        if (rule_matches(rule, cursor->target)) {
            return rule;
        }
    }

    subtable = cursor->subtable;
    HMAP_FOR_EACH_CONTINUE (subtable, hmap_node, &cursor->cls->subtables) {
        rule = search_subtable(subtable, cursor->target);
        if (rule) {
            cursor->subtable = subtable;
            return rule;
        }
    }

    return NULL;
}

static struct cls_subtable *
find_subtable(const struct classifier *cls, const struct minimask *mask)
{
    struct cls_subtable *subtable;

    HMAP_FOR_EACH_IN_BUCKET (subtable, hmap_node, minimask_hash(mask, 0),
                             &cls->subtables) {
        if (minimask_equal(mask, &subtable->mask)) {
            return subtable;
        }
    }
    return NULL;
}

static struct cls_subtable *
insert_subtable(struct classifier *cls, const struct minimask *mask)
{
    uint32_t hash = minimask_hash(mask, 0);
    struct cls_subtable *subtable;
    int i, index = 0;
    struct flow_wildcards old, new;
    uint8_t prev;

    subtable = xzalloc(sizeof *subtable);
    hmap_init(&subtable->rules);
    minimask_clone(&subtable->mask, mask);

    /* Init indices for segmented lookup, if any. */
    flow_wildcards_init_catchall(&new);
    old = new;
    prev = 0;
    for (i = 0; i < cls->n_flow_segments; i++) {
        flow_wildcards_fold_minimask_range(&new, mask, prev,
                                           cls->flow_segments[i]);
        /* Add an index if it adds mask bits. */
        if (!flow_wildcards_equal(&new, &old)) {
            hindex_init(&subtable->indices[index]);
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
            hindex_destroy(&subtable->indices[index]);
        }
    }
    subtable->n_indices = index;

    hmap_insert(&cls->subtables, &subtable->hmap_node, hash);
    list_push_back(&cls->subtables_priority, &subtable->list_node);
    subtable->tag = (minimask_get_metadata_mask(mask) == OVS_BE64_MAX
                     ? tag_create_deterministic(hash)
                     : TAG_ALL);

    return subtable;
}

static void
destroy_subtable(struct classifier *cls, struct cls_subtable *subtable)
{
    int i;

    for (i = 0; i < subtable->n_indices; i++) {
        hindex_destroy(&subtable->indices[i]);
    }
    minimask_destroy(&subtable->mask);
    hmap_remove(&cls->subtables, &subtable->hmap_node);
    hmap_destroy(&subtable->rules);
    list_remove(&subtable->list_node);
    free(subtable);
}

/* This function performs the following updates for 'subtable' in 'cls'
 * following the addition of a new rule with priority 'new_priority' to
 * 'subtable':
 *
 *    - Update 'subtable->max_priority' and 'subtable->max_count' if necessary.
 *
 *    - Update 'subtable''s position in 'cls->subtables_priority' if necessary.
 *
 * This function should only be called after adding a new rule, not after
 * replacing a rule by an identical one or modifying a rule in-place. */
static void
update_subtables_after_insertion(struct classifier *cls,
                                 struct cls_subtable *subtable,
                                 unsigned int new_priority)
{
    if (new_priority == subtable->max_priority) {
        ++subtable->max_count;
    } else if (new_priority > subtable->max_priority) {
        struct cls_subtable *iter;

        subtable->max_priority = new_priority;
        subtable->max_count = 1;

        /* Possibly move 'subtable' earlier in the priority list.  If we break
         * out of the loop, then 'subtable' should be moved just after that
         * 'iter'.  If the loop terminates normally, then 'iter' will be the
         * list head and we'll move subtable just after that (e.g. to the front
         * of the list). */
        iter = subtable;
        LIST_FOR_EACH_REVERSE_CONTINUE (iter, list_node,
                                        &cls->subtables_priority) {
            if (iter->max_priority >= subtable->max_priority) {
                break;
            }
        }

        /* Move 'subtable' just after 'iter' (unless it's already there). */
        if (iter->list_node.next != &subtable->list_node) {
            list_splice(iter->list_node.next,
                        &subtable->list_node, subtable->list_node.next);
        }
    }
}

/* This function performs the following updates for 'subtable' in 'cls'
 * following the deletion of a rule with priority 'del_priority' from
 * 'subtable':
 *
 *    - Update 'subtable->max_priority' and 'subtable->max_count' if necessary.
 *
 *    - Update 'subtable''s position in 'cls->subtables_priority' if necessary.
 *
 * This function should only be called after removing a rule, not after
 * replacing a rule by an identical one or modifying a rule in-place. */
static void
update_subtables_after_removal(struct classifier *cls,
                               struct cls_subtable *subtable,
                               unsigned int del_priority)
{
    struct cls_subtable *iter;

    if (del_priority == subtable->max_priority && --subtable->max_count == 0) {
        struct cls_rule *head;

        subtable->max_priority = 0;
        HMAP_FOR_EACH (head, hmap_node, &subtable->rules) {
            if (head->priority > subtable->max_priority) {
                subtable->max_priority = head->priority;
                subtable->max_count = 1;
            } else if (head->priority == subtable->max_priority) {
                ++subtable->max_count;
            }
        }

        /* Possibly move 'subtable' later in the priority list.  If we break
         * out of the loop, then 'subtable' should be moved just before that
         * 'iter'.  If the loop terminates normally, then 'iter' will be the
         * list head and we'll move subtable just before that (e.g. to the back
         * of the list). */
        iter = subtable;
        LIST_FOR_EACH_CONTINUE (iter, list_node, &cls->subtables_priority) {
            if (iter->max_priority <= subtable->max_priority) {
                break;
            }
        }

        /* Move 'subtable' just before 'iter' (unless it's already there). */
        if (iter->list_node.prev != &subtable->list_node) {
            list_splice(&iter->list_node,
                        &subtable->list_node, subtable->list_node.next);
        }
    }
}

static inline struct cls_rule *
find_match(const struct cls_subtable *subtable, const struct flow *flow,
           uint32_t hash)
{
    struct cls_rule *rule;

    HMAP_FOR_EACH_WITH_HASH (rule, hmap_node, hash, &subtable->rules) {
        if (minimatch_matches_flow(&rule->match, flow)) {
            return rule;
        }
    }

    return NULL;
}

static struct cls_rule *
find_match_wc(const struct cls_subtable *subtable, const struct flow *flow,
              struct flow_wildcards * wc)
{
    uint32_t basis = 0, hash;
    struct cls_rule *rule = NULL;
    uint8_t prev_u32ofs = 0;
    int i;

    if (!wc) {
        return find_match(subtable, flow,
                          flow_hash_in_minimask(flow, &subtable->mask, 0));
    }

    /* Try to finish early by checking fields in segments. */
    for (i = 0; i < subtable->n_indices; i++) {
        struct hindex_node *inode;

        hash = flow_hash_in_minimask_range(flow, &subtable->mask, prev_u32ofs,
                                           subtable->index_ofs[i], &basis);
        prev_u32ofs = subtable->index_ofs[i];
        inode = hindex_node_with_hash(&subtable->indices[i], hash);
        if (!inode) {
            /* No match, can stop immediately, but must fold in the mask
             * covered so far. */
            flow_wildcards_fold_minimask_range(wc, &subtable->mask, 0,
                                               prev_u32ofs);
            return NULL;
        }

        /* If we have narrowed down to a single rule already, check whether
         * that rule matches.  If it does match, then we're done.  If it does
         * not match, then we know that we will never get a match, but we do
         * not yet know how many wildcards we need to fold into 'wc' so we
         * continue iterating through indices to find that out.  (We won't
         * waste time calling minimatch_matches_flow() again because we've set
         * 'rule' nonnull.)
         *
         * This check shows a measurable benefit with non-trivial flow tables.
         *
         * (Rare) hash collisions may cause us to miss the opportunity for this
         * optimization. */
        if (!inode->s && !rule) {
            ASSIGN_CONTAINER(rule, inode - i, index_nodes);
            if (minimatch_matches_flow(&rule->match, flow)) {
                goto out;
            }
        }
    }

    if (!rule) {
        /* Multiple potential matches exist, look for one. */
        hash = flow_hash_in_minimask_range(flow, &subtable->mask, prev_u32ofs,
                                           FLOW_U32S, &basis);
        rule = find_match(subtable, flow, hash);
    } else {
        /* We already narrowed the matching candidates down to just 'rule',
         * but it didn't match. */
        rule = NULL;
    }
 out:
    flow_wildcards_fold_minimask(wc, &subtable->mask);
    return rule;
}

static struct cls_rule *
find_equal(struct cls_subtable *subtable, const struct miniflow *flow,
           uint32_t hash)
{
    struct cls_rule *head;

    HMAP_FOR_EACH_WITH_HASH (head, hmap_node, hash, &subtable->rules) {
        if (miniflow_equal(&head->match.flow, flow)) {
            return head;
        }
    }
    return NULL;
}

static struct cls_rule *
insert_rule(struct classifier *cls, struct cls_subtable *subtable,
            struct cls_rule *new)
{
    struct cls_rule *head;
    struct cls_rule *old = NULL;
    int i;
    uint32_t basis = 0, hash;
    uint8_t prev_u32ofs = 0;

    /* Add new node to segment indices. */
    for (i = 0; i < subtable->n_indices; i++) {
        hash = minimatch_hash_range(&new->match, prev_u32ofs,
                                    subtable->index_ofs[i], &basis);
        hindex_insert(&subtable->indices[i], &new->index_nodes[i], hash);
        prev_u32ofs = subtable->index_ofs[i];
    }
    hash = minimatch_hash_range(&new->match, prev_u32ofs, FLOW_U32S, &basis);
    head = find_equal(subtable, &new->match.flow, hash);
    if (!head) {
        hmap_insert(&subtable->rules, &new->hmap_node, hash);
        list_init(&new->list);
        goto out;
    } else {
        /* Scan the list for the insertion point that will keep the list in
         * order of decreasing priority. */
        struct cls_rule *rule;

        new->hmap_node.hash = hash; /* Otherwise done by hmap_insert. */

        FOR_EACH_RULE_IN_LIST (rule, head) {
            if (new->priority >= rule->priority) {
                if (rule == head) {
                    /* 'new' is the new highest-priority flow in the list. */
                    hmap_replace(&subtable->rules,
                                 &rule->hmap_node, &new->hmap_node);
                }

                if (new->priority == rule->priority) {
                    list_replace(&new->list, &rule->list);
                    old = rule;
                    goto out;
                } else {
                    list_insert(&rule->list, &new->list);
                    goto out;
                }
            }
        }

        /* Insert 'new' at the end of the list. */
        list_push_back(&head->list, &new->list);
    }

 out:
    if (!old) {
        update_subtables_after_insertion(cls, subtable, new->priority);
    } else {
        /* Remove old node from indices. */
        for (i = 0; i < subtable->n_indices; i++) {
            hindex_remove(&subtable->indices[i], &old->index_nodes[i]);
        }
    }
    return old;
}

static struct cls_rule *
next_rule_in_list__(struct cls_rule *rule)
{
    struct cls_rule *next = OBJECT_CONTAINING(rule->list.next, next, list);
    return next;
}

static struct cls_rule *
next_rule_in_list(struct cls_rule *rule)
{
    struct cls_rule *next = next_rule_in_list__(rule);
    return next->priority < rule->priority ? next : NULL;
}
