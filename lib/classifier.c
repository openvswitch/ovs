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

static struct cls_table *find_table(const struct classifier *,
                                    const struct minimask *);
static struct cls_table *insert_table(struct classifier *,
                                      const struct minimask *);

static void destroy_table(struct classifier *, struct cls_table *);

static void update_tables_after_insertion(struct classifier *,
                                          struct cls_table *,
                                          unsigned int new_priority);
static void update_tables_after_removal(struct classifier *,
                                        struct cls_table *,
                                        unsigned int del_priority);

static struct cls_rule *find_match(const struct cls_table *,
                                   const struct flow *);
static struct cls_rule *find_equal(struct cls_table *,
                                   const struct miniflow *, uint32_t hash);
static struct cls_rule *insert_rule(struct classifier *,
                                    struct cls_table *, struct cls_rule *);

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
classifier_init(struct classifier *cls)
{
    cls->n_rules = 0;
    hmap_init(&cls->tables);
    list_init(&cls->tables_priority);
    ovs_rwlock_init(&cls->rwlock);
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility. */
void
classifier_destroy(struct classifier *cls)
{
    if (cls) {
        struct cls_table *table, *next_table;

        HMAP_FOR_EACH_SAFE (table, next_table, hmap_node, &cls->tables) {
            destroy_table(cls, table);
        }
        hmap_destroy(&cls->tables);
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
    struct cls_table *table;

    table = find_table(cls, &rule->match.mask);
    if (!table) {
        table = insert_table(cls, &rule->match.mask);
    }

    old_rule = insert_rule(cls, table, rule);
    if (!old_rule) {
        table->n_table_rules++;
        cls->n_rules++;
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
    struct cls_rule *head;
    struct cls_table *table;

    table = find_table(cls, &rule->match.mask);
    head = find_equal(table, &rule->match.flow, rule->hmap_node.hash);
    if (head != rule) {
        list_remove(&rule->list);
    } else if (list_is_empty(&rule->list)) {
        hmap_remove(&table->rules, &rule->hmap_node);
    } else {
        struct cls_rule *next = CONTAINER_OF(rule->list.next,
                                             struct cls_rule, list);

        list_remove(&rule->list);
        hmap_replace(&table->rules, &rule->hmap_node, &next->hmap_node);
    }

    if (--table->n_table_rules == 0) {
        destroy_table(cls, table);
    } else {
        update_tables_after_removal(cls, table, rule->priority);
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
    struct cls_table *table;
    struct cls_rule *best;

    best = NULL;
    LIST_FOR_EACH (table, list_node, &cls->tables_priority) {
        struct cls_rule *rule = find_match(table, flow);

        if (wc) {
            flow_wildcards_fold_minimask(wc, &table->mask);
        }
        if (rule) {
            best = rule;
            LIST_FOR_EACH_CONTINUE (table, list_node, &cls->tables_priority) {
                if (table->max_priority <= best->priority) {
                    /* Tables in descending priority order,
                     * can not find anything better. */
                    return best;
                }
                rule = find_match(table, flow);
                if (wc) {
                    flow_wildcards_fold_minimask(wc, &table->mask);
                }
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
    struct cls_table *table;

    table = find_table(cls, &target->match.mask);
    if (!table) {
        return NULL;
    }

    /* Skip if there is no hope. */
    if (target->priority > table->max_priority) {
        return NULL;
    }

    head = find_equal(table, &target->match.flow,
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
    struct cls_table *table;

    /* Iterate tables in the descending max priority order. */
    LIST_FOR_EACH (table, list_node, &cls->tables_priority) {
        uint32_t storage[FLOW_U32S];
        struct minimask mask;
        struct cls_rule *head;

        if (target->priority > table->max_priority) {
            break; /* Can skip this and the rest of the tables. */
        }

        minimask_combine(&mask, &target->match.mask, &table->mask, storage);
        HMAP_FOR_EACH (head, hmap_node, &table->rules) {
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
search_table(const struct cls_table *table, const struct cls_rule *target)
{
    if (!target || !minimask_has_extra(&table->mask, &target->match.mask)) {
        struct cls_rule *rule;

        HMAP_FOR_EACH (rule, hmap_node, &table->rules) {
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
    struct cls_table *table;

    HMAP_FOR_EACH (table, hmap_node, &cursor->cls->tables) {
        struct cls_rule *rule = search_table(table, cursor->target);
        if (rule) {
            cursor->table = table;
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
    const struct cls_table *table;
    struct cls_rule *next;

    next = next_rule_in_list__(rule);
    if (next->priority < rule->priority) {
        return next;
    }

    /* 'next' is the head of the list, that is, the rule that is included in
     * the table's hmap.  (This is important when the classifier contains rules
     * that differ only in priority.) */
    rule = next;
    HMAP_FOR_EACH_CONTINUE (rule, hmap_node, &cursor->table->rules) {
        if (rule_matches(rule, cursor->target)) {
            return rule;
        }
    }

    table = cursor->table;
    HMAP_FOR_EACH_CONTINUE (table, hmap_node, &cursor->cls->tables) {
        rule = search_table(table, cursor->target);
        if (rule) {
            cursor->table = table;
            return rule;
        }
    }

    return NULL;
}

static struct cls_table *
find_table(const struct classifier *cls, const struct minimask *mask)
{
    struct cls_table *table;

    HMAP_FOR_EACH_IN_BUCKET (table, hmap_node, minimask_hash(mask, 0),
                             &cls->tables) {
        if (minimask_equal(mask, &table->mask)) {
            return table;
        }
    }
    return NULL;
}

static struct cls_table *
insert_table(struct classifier *cls, const struct minimask *mask)
{
    struct cls_table *table;

    table = xzalloc(sizeof *table);
    hmap_init(&table->rules);
    minimask_clone(&table->mask, mask);
    hmap_insert(&cls->tables, &table->hmap_node, minimask_hash(mask, 0));
    list_push_back(&cls->tables_priority, &table->list_node);

    return table;
}

static void
destroy_table(struct classifier *cls, struct cls_table *table)
{
    minimask_destroy(&table->mask);
    hmap_remove(&cls->tables, &table->hmap_node);
    hmap_destroy(&table->rules);
    list_remove(&table->list_node);
    free(table);
}

/* This function performs the following updates for 'table' in 'cls' following
 * the addition of a new rule with priority 'new_priority' to 'table':
 *
 *    - Update 'table->max_priority' and 'table->max_count' if necessary.
 *
 *    - Update 'table''s position in 'cls->tables_priority' if necessary.
 *
 * This function should only be called after adding a new rule, not after
 * replacing a rule by an identical one or modifying a rule in-place. */
static void
update_tables_after_insertion(struct classifier *cls, struct cls_table *table,
                              unsigned int new_priority)
{
    if (new_priority == table->max_priority) {
        ++table->max_count;
    } else if (new_priority > table->max_priority) {
        struct cls_table *iter;

        table->max_priority = new_priority;
        table->max_count = 1;

        /* Possibly move 'table' earlier in the priority list.  If we break out
         * of the loop, then 'table' should be moved just after that 'iter'.
         * If the loop terminates normally, then 'iter' will be the list head
         * and we'll move table just after that (e.g. to the front of the
         * list). */
        iter = table;
        LIST_FOR_EACH_REVERSE_CONTINUE (iter, list_node,
                                        &cls->tables_priority) {
            if (iter->max_priority >= table->max_priority) {
                break;
            }
        }

        /* Move 'table' just after 'iter' (unless it's already there). */
        if (iter->list_node.next != &table->list_node) {
            list_splice(iter->list_node.next,
                        &table->list_node, table->list_node.next);
        }
    }
}

/* This function performs the following updates for 'table' in 'cls' following
 * the deletion of a rule with priority 'del_priority' from 'table':
 *
 *    - Update 'table->max_priority' and 'table->max_count' if necessary.
 *
 *    - Update 'table''s position in 'cls->tables_priority' if necessary.
 *
 * This function should only be called after removing a rule, not after
 * replacing a rule by an identical one or modifying a rule in-place. */
static void
update_tables_after_removal(struct classifier *cls, struct cls_table *table,
                            unsigned int del_priority)
{
    struct cls_table *iter;

    if (del_priority == table->max_priority && --table->max_count == 0) {
        struct cls_rule *head;

        table->max_priority = 0;
        HMAP_FOR_EACH (head, hmap_node, &table->rules) {
            if (head->priority > table->max_priority) {
                table->max_priority = head->priority;
                table->max_count = 1;
            } else if (head->priority == table->max_priority) {
                ++table->max_count;
            }
        }

        /* Possibly move 'table' later in the priority list.  If we break out
         * of the loop, then 'table' should be moved just before that 'iter'.
         * If the loop terminates normally, then 'iter' will be the list head
         * and we'll move table just before that (e.g. to the back of the
         * list). */
        iter = table;
        LIST_FOR_EACH_CONTINUE (iter, list_node, &cls->tables_priority) {
            if (iter->max_priority <= table->max_priority) {
                break;
            }
        }

        /* Move 'table' just before 'iter' (unless it's already there). */
        if (iter->list_node.prev != &table->list_node) {
            list_splice(&iter->list_node,
                        &table->list_node, table->list_node.next);
        }
    }
}

static struct cls_rule *
find_match(const struct cls_table *table, const struct flow *flow)
{
    uint32_t hash = flow_hash_in_minimask(flow, &table->mask, 0);
    struct cls_rule *rule;

    HMAP_FOR_EACH_WITH_HASH (rule, hmap_node, hash, &table->rules) {
        if (miniflow_equal_flow_in_minimask(&rule->match.flow, flow,
                                            &table->mask)) {
            return rule;
        }
    }

    return NULL;
}

static struct cls_rule *
find_equal(struct cls_table *table, const struct miniflow *flow, uint32_t hash)
{
    struct cls_rule *head;

    HMAP_FOR_EACH_WITH_HASH (head, hmap_node, hash, &table->rules) {
        if (miniflow_equal(&head->match.flow, flow)) {
            return head;
        }
    }
    return NULL;
}

static struct cls_rule *
insert_rule(struct classifier *cls,
            struct cls_table *table, struct cls_rule *new)
{
    struct cls_rule *head;
    struct cls_rule *old = NULL;

    new->hmap_node.hash = miniflow_hash_in_minimask(&new->match.flow,
                                                    &new->match.mask, 0);

    head = find_equal(table, &new->match.flow, new->hmap_node.hash);
    if (!head) {
        hmap_insert(&table->rules, &new->hmap_node, new->hmap_node.hash);
        list_init(&new->list);
        goto out;
    } else {
        /* Scan the list for the insertion point that will keep the list in
         * order of decreasing priority. */
        struct cls_rule *rule;
        FOR_EACH_RULE_IN_LIST (rule, head) {
            if (new->priority >= rule->priority) {
                if (rule == head) {
                    /* 'new' is the new highest-priority flow in the list. */
                    hmap_replace(&table->rules,
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
        update_tables_after_insertion(cls, table, new->priority);
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
