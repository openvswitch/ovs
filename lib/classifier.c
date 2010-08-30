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

#include <config.h>
#include "classifier.h"
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"

const struct cls_field cls_fields[CLS_N_FIELDS + 1] = {
#define CLS_FIELD(WILDCARDS, MEMBER, NAME)      \
    { offsetof(flow_t, MEMBER),                 \
      sizeof ((flow_t *)0)->MEMBER,             \
      WILDCARDS,                                \
      #NAME },
    CLS_FIELDS
#undef CLS_FIELD
    { sizeof(flow_t), 0, 0, "exact" },
};

static uint32_t hash_fields(const flow_t *, int table_idx);
static bool equal_fields(const flow_t *, const flow_t *, int table_idx);

static int table_idx_from_wildcards(uint32_t wildcards);
static struct cls_rule *table_insert(struct hmap *, struct cls_rule *);
static struct cls_rule *insert_exact_rule(struct classifier *,
                                          struct cls_rule *);
static struct cls_bucket *find_bucket(struct hmap *, size_t hash,
                                      const struct cls_rule *);
static struct cls_rule *search_table(const struct hmap *table, int field_idx,
                                     const struct cls_rule *);
static struct cls_rule *search_exact_table(const struct classifier *,
                                           size_t hash, const flow_t *);
static bool rules_match_1wild(const struct cls_rule *fixed,
                              const struct cls_rule *wild, int field_idx);
static bool rules_match_2wild(const struct cls_rule *wild1,
                              const struct cls_rule *wild2, int field_idx);

/* Converts the flow in 'flow' into a cls_rule in 'rule', with the given
 * 'wildcards' and 'priority'.*/
void
cls_rule_from_flow(const flow_t *flow, uint32_t wildcards,
                   unsigned int priority, struct cls_rule *rule)
{
    assert(!flow->reserved[0] && !flow->reserved[1] && !flow->reserved[2]);
    rule->flow = *flow;
    flow_wildcards_init(&rule->wc, wildcards);
    rule->priority = priority;
    rule->table_idx = table_idx_from_wildcards(rule->wc.wildcards);
}

/* Converts the ofp_match in 'match' into a cls_rule in 'rule', with the given
 * 'priority'.  If 'tun_id_from_cookie' is set then the upper 32 bits of
 * 'cookie' are stored in the rule as the tunnel ID. */
void
cls_rule_from_match(const struct ofp_match *match, unsigned int priority,
                    bool tun_id_from_cookie, uint64_t cookie,
                    struct cls_rule *rule)
{
    uint32_t wildcards;
    flow_from_match(match, tun_id_from_cookie, cookie, &rule->flow, &wildcards);
    flow_wildcards_init(&rule->wc, wildcards);
    rule->priority = rule->wc.wildcards ? priority : UINT16_MAX;
    rule->table_idx = table_idx_from_wildcards(rule->wc.wildcards);
}

/* Converts 'rule' to a string and returns the string.  The caller must free
 * the string (with free()). */
char *
cls_rule_to_string(const struct cls_rule *rule)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "wildcards=%x priority=%u ",
                  rule->wc.wildcards, rule->priority);
    flow_format(&s, &rule->flow);
    return ds_cstr(&s);
}

/* Prints cls_rule 'rule', for debugging.
 *
 * (The output could be improved and expanded, but this was good enough to
 * debug the classifier.) */
void
cls_rule_print(const struct cls_rule *rule)
{
    printf("wildcards=%x priority=%u ", rule->wc.wildcards, rule->priority);
    flow_print(stdout, &rule->flow);
    putc('\n', stdout);
}

/* Adjusts pointers around 'old', which must be in classifier 'cls', to
 * compensate for it having been moved in memory to 'new' (e.g. due to
 * realloc()).
 *
 * This function cannot be realized in all possible flow classifier
 * implementations, so we will probably have to change the interface if we
 * change the implementation.  Shouldn't be a big deal though. */
void
cls_rule_moved(struct classifier *cls, struct cls_rule *old,
               struct cls_rule *new)
{
    if (old != new) {
        if (new->wc.wildcards) {
            list_moved(&new->node.list);
        } else {
            hmap_node_moved(&cls->exact_table,
                            &old->node.hmap, &new->node.hmap);
        }
    }
}

/* Replaces 'old', which must be in classifier 'cls', by 'new' (e.g. due to
 * realloc()); that is, after calling this function 'new' will be in 'cls' in
 * place of 'old'.
 *
 * 'new' and 'old' must be exactly the same: wildcard the same fields, have the
 * same fixed values for non-wildcarded fields, and have the same priority.
 *
 * The caller takes ownership of 'old' and is thus responsible for freeing it,
 * etc., as necessary.
 *
 * This function cannot be realized in all possible flow classifier
 * implementations, so we will probably have to change the interface if we
 * change the implementation.  Shouldn't be a big deal though. */
void
cls_rule_replace(struct classifier *cls, const struct cls_rule *old,
                 struct cls_rule *new)
{
    assert(old != new);
    assert(old->wc.wildcards == new->wc.wildcards);
    assert(old->priority == new->priority);

    if (new->wc.wildcards) {
        list_replace(&new->node.list, &old->node.list);
    } else {
        hmap_replace(&cls->exact_table, &old->node.hmap, &new->node.hmap);
    }
}

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
void
classifier_init(struct classifier *cls)
{
    int i;

    cls->n_rules = 0;
    for (i = 0; i < ARRAY_SIZE(cls->tables); i++) {
        hmap_init(&cls->tables[i]);
    }
    hmap_init(&cls->exact_table);
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility. */
void
classifier_destroy(struct classifier *cls)
{
    if (cls) {
        struct cls_bucket *bucket, *next_bucket;
        struct hmap *tbl;

        for (tbl = &cls->tables[0]; tbl < &cls->tables[CLS_N_FIELDS]; tbl++) {
            HMAP_FOR_EACH_SAFE (bucket, next_bucket,
                                struct cls_bucket, hmap_node, tbl) {
                free(bucket);
            }
            hmap_destroy(tbl);
        }
        hmap_destroy(&cls->exact_table);
    }
}

/* Returns true if 'cls' does not contain any classification rules, false
 * otherwise. */
bool
classifier_is_empty(const struct classifier *cls)
{
    return cls->n_rules == 0;
}

/* Returns the number of rules in 'classifier'. */
int
classifier_count(const struct classifier *cls)
{
    return cls->n_rules;
}

/* Returns the number of rules in 'classifier' that have no wildcards. */
int
classifier_count_exact(const struct classifier *cls)
{
    return hmap_count(&cls->exact_table);
}

/* Inserts 'rule' into 'cls'.  Transfers ownership of 'rule' to 'cls'.
 *
 * If 'cls' already contains an identical rule (including wildcards, values of
 * fixed fields, and priority), replaces the old rule by 'rule' and returns the
 * rule that was replaced.  The caller takes ownership of the returned rule and
 * is thus responsible for freeing it, etc., as necessary.
 *
 * Returns NULL if 'cls' does not contain a rule with an identical key, after
 * inserting the new rule.  In this case, no rules are displaced by the new
 * rule, even rules that cannot have any effect because the new rule matches a
 * superset of their flows and has higher priority. */
struct cls_rule *
classifier_insert(struct classifier *cls, struct cls_rule *rule)
{
    struct cls_rule *old;
    assert((rule->wc.wildcards == 0) == (rule->table_idx == CLS_F_IDX_EXACT));
    old = (rule->wc.wildcards
           ? table_insert(&cls->tables[rule->table_idx], rule)
           : insert_exact_rule(cls, rule));
    if (!old) {
        cls->n_rules++;
    }
    return old;
}

/* Inserts 'rule' into 'cls'.  Transfers ownership of 'rule' to 'cls'.
 *
 * 'rule' must be an exact-match rule (rule->wc.wildcards must be 0) and 'cls'
 * must not contain any rule with an identical key. */
void
classifier_insert_exact(struct classifier *cls, struct cls_rule *rule)
{
    hmap_insert(&cls->exact_table, &rule->node.hmap,
                flow_hash(&rule->flow, 0));
    cls->n_rules++;
}

/* Removes 'rule' from 'cls'.  It is caller's responsibility to free 'rule', if
 * this is desirable. */
void
classifier_remove(struct classifier *cls, struct cls_rule *rule)
{
    if (rule->wc.wildcards) {
        /* Remove 'rule' from bucket.  If that empties the bucket, remove the
         * bucket from its table. */
        struct hmap *table = &cls->tables[rule->table_idx];
        struct list *rules = list_remove(&rule->node.list);
        if (list_is_empty(rules)) {
            /* This code is a little tricky.  list_remove() returns the list
             * element just after the one removed.  Since the list is now
             * empty, this will be the address of the 'rules' member of the
             * bucket that was just emptied, so pointer arithmetic (via
             * CONTAINER_OF) can find that bucket. */
            struct cls_bucket *bucket;
            bucket = CONTAINER_OF(rules, struct cls_bucket, rules);
            hmap_remove(table, &bucket->hmap_node);
            free(bucket);
        }
    } else {
        /* Remove 'rule' from cls->exact_table. */
        hmap_remove(&cls->exact_table, &rule->node.hmap);
    }
    cls->n_rules--;
}

/* Finds and returns the highest-priority rule in 'cls' that matches 'flow'.
 * Returns a null pointer if no rules in 'cls' match 'flow'.  If multiple rules
 * of equal priority match 'flow', returns one arbitrarily.
 *
 * (When multiple rules of equal priority happen to fall into the same bucket,
 * rules added more recently take priority over rules added less recently, but
 * this is subject to change and should not be depended upon.) */
struct cls_rule *
classifier_lookup(const struct classifier *cls, const flow_t *flow)
{
    struct cls_rule *rule = classifier_lookup_exact(cls, flow);
    if (!rule) {
        rule = classifier_lookup_wild(cls, flow);
    }
    return rule;
}

struct cls_rule *
classifier_lookup_exact(const struct classifier *cls, const flow_t *flow)
{
    return (!hmap_is_empty(&cls->exact_table)
            ? search_exact_table(cls, flow_hash(flow, 0), flow)
            : NULL);
}

struct cls_rule *
classifier_lookup_wild(const struct classifier *cls, const flow_t *flow)
{
    struct cls_rule *best = NULL;
    if (cls->n_rules > hmap_count(&cls->exact_table)) {
        struct cls_rule target;
        int i;

        cls_rule_from_flow(flow, 0, 0, &target);
        for (i = 0; i < CLS_N_FIELDS; i++) {
            struct cls_rule *rule = search_table(&cls->tables[i], i, &target);
            if (rule && (!best || rule->priority > best->priority)) {
                best = rule;
            }
        }
    }
    return best;
}

struct cls_rule *
classifier_find_rule_exactly(const struct classifier *cls,
                             const flow_t *target, uint32_t wildcards,
                             unsigned int priority)
{
    struct cls_bucket *bucket;
    int table_idx;
    uint32_t hash;

    if (!wildcards) {
        /* Ignores 'priority'. */
        return search_exact_table(cls, flow_hash(target, 0), target);
    }

    assert(wildcards == (wildcards & OVSFW_ALL));
    table_idx = table_idx_from_wildcards(wildcards);
    hash = hash_fields(target, table_idx);
    HMAP_FOR_EACH_WITH_HASH (bucket, struct cls_bucket, hmap_node, hash,
                             &cls->tables[table_idx]) {
        if (equal_fields(&bucket->fixed, target, table_idx)) {
            struct cls_rule *pos;
            LIST_FOR_EACH (pos, struct cls_rule, node.list, &bucket->rules) {
                if (pos->priority < priority) {
                    return NULL;
                } else if (pos->priority == priority &&
                           pos->wc.wildcards == wildcards &&
                           flow_equal(target, &pos->flow)) {
                    return pos;
                }
            }
        }
    }
    return NULL;
}

/* Checks if the flow defined by 'target' with 'wildcards' at 'priority'
 * overlaps with any other rule at the same priority in the classifier.
 * Two rules are considered overlapping if a packet could match both. */
bool
classifier_rule_overlaps(const struct classifier *cls,
                         const flow_t *target, uint32_t wildcards,
                         unsigned int priority)
{
    struct cls_rule target_rule;
    const struct hmap *tbl;

    if (!wildcards) {
        return search_exact_table(cls, flow_hash(target, 0), target) ?
            true : false;
    }

    cls_rule_from_flow(target, wildcards, priority, &target_rule);

    for (tbl = &cls->tables[0]; tbl < &cls->tables[CLS_N_FIELDS]; tbl++) {
        struct cls_bucket *bucket;

        HMAP_FOR_EACH (bucket, struct cls_bucket, hmap_node, tbl) {
            struct cls_rule *rule;

            LIST_FOR_EACH (rule, struct cls_rule, node.list,
                           &bucket->rules) {
                if (rule->priority == priority
                        && rules_match_2wild(rule, &target_rule, 0)) {
                    return true;
                }
            }
        }
    }

    return false;
}

/* Ignores target->priority.
 *
 * 'callback' is allowed to delete the rule that is passed as its argument, but
 * it must not delete (or move) any other rules in 'cls' that are in the same
 * table as the argument rule.  Two rules are in the same table if their
 * cls_rule structs have the same table_idx; as a special case, a rule with
 * wildcards and an exact-match rule will never be in the same table. */
void
classifier_for_each_match(const struct classifier *cls,
                          const struct cls_rule *target,
                          int include, cls_cb_func *callback, void *aux)
{
    if (include & CLS_INC_WILD) {
        const struct hmap *table;

        for (table = &cls->tables[0]; table < &cls->tables[CLS_N_FIELDS];
             table++) {
            struct cls_bucket *bucket, *next_bucket;

            HMAP_FOR_EACH_SAFE (bucket, next_bucket,
                                struct cls_bucket, hmap_node, table) {
                /* XXX there is a bit of room for optimization here based on
                 * rejecting entire buckets on their fixed fields, but it will
                 * only be worthwhile for big buckets (which we hope we won't
                 * get anyway, but...) */
                struct cls_rule *prev_rule, *rule;

                /* We can't just use LIST_FOR_EACH_SAFE here because, if the
                 * callback deletes the last rule in the bucket, then the
                 * bucket itself will be destroyed.  The bucket contains the
                 * list head so that's a use-after-free error. */
                prev_rule = NULL;
                LIST_FOR_EACH (rule, struct cls_rule, node.list,
                               &bucket->rules) {
                    if (rules_match_1wild(rule, target, 0)) {
                        if (prev_rule) {
                            callback(prev_rule, aux);
                        }
                        prev_rule = rule;
                    }
                }
                if (prev_rule) {
                    callback(prev_rule, aux);
                }
            }
        }
    }

    if (include & CLS_INC_EXACT) {
        if (target->wc.wildcards) {
            struct cls_rule *rule, *next_rule;

            HMAP_FOR_EACH_SAFE (rule, next_rule, struct cls_rule, node.hmap,
                                &cls->exact_table) {
                if (rules_match_1wild(rule, target, 0)) {
                    callback(rule, aux);
                }
            }
        } else {
            /* Optimization: there can be at most one match in the exact
             * table. */
            size_t hash = flow_hash(&target->flow, 0);
            struct cls_rule *rule = search_exact_table(cls, hash,
                                                       &target->flow);
            if (rule) {
                callback(rule, aux);
            }
        }
    }
}

/* 'callback' is allowed to delete the rule that is passed as its argument, but
 * it must not delete (or move) any other rules in 'cls' that are in the same
 * table as the argument rule.  Two rules are in the same table if their
 * cls_rule structs have the same table_idx; as a special case, a rule with
 * wildcards and an exact-match rule will never be in the same table. */
void
classifier_for_each(const struct classifier *cls, int include,
                    void (*callback)(struct cls_rule *, void *aux),
                    void *aux)
{
    if (include & CLS_INC_WILD) {
        const struct hmap *tbl;

        for (tbl = &cls->tables[0]; tbl < &cls->tables[CLS_N_FIELDS]; tbl++) {
            struct cls_bucket *bucket, *next_bucket;

            HMAP_FOR_EACH_SAFE (bucket, next_bucket,
                                struct cls_bucket, hmap_node, tbl) {
                struct cls_rule *prev_rule, *rule;

                /* We can't just use LIST_FOR_EACH_SAFE here because, if the
                 * callback deletes the last rule in the bucket, then the
                 * bucket itself will be destroyed.  The bucket contains the
                 * list head so that's a use-after-free error. */
                prev_rule = NULL;
                LIST_FOR_EACH (rule, struct cls_rule, node.list,
                               &bucket->rules) {
                    if (prev_rule) {
                        callback(prev_rule, aux);
                    }
                    prev_rule = rule;
                }
                if (prev_rule) {
                    callback(prev_rule, aux);
                }
            }
        }
    }

    if (include & CLS_INC_EXACT) {
        struct cls_rule *rule, *next_rule;

        HMAP_FOR_EACH_SAFE (rule, next_rule,
                            struct cls_rule, node.hmap, &cls->exact_table) {
            callback(rule, aux);
        }
    }
}

static struct cls_bucket *create_bucket(struct hmap *, size_t hash,
                                        const flow_t *fixed);
static struct cls_rule *bucket_insert(struct cls_bucket *, struct cls_rule *);

static inline bool equal_bytes(const void *, const void *, size_t n);

/* Returns a hash computed across the fields in 'flow' whose field indexes
 * (CLS_F_IDX_*) are less than 'table_idx'.  (If 'table_idx' is
 * CLS_F_IDX_EXACT, hashes all the fields in 'flow'). */
static uint32_t
hash_fields(const flow_t *flow, int table_idx)
{
    /* I just know I'm going to hell for writing code this way.
     *
     * GCC generates pretty good code here, with only a single taken
     * conditional jump per execution.  Now the question is, would we be better
     * off marking this function ALWAYS_INLINE and writing a wrapper that
     * switches on the value of 'table_idx' to get rid of all the conditional
     * jumps entirely (except for one in the wrapper)?  Honestly I really,
     * really hope that it doesn't matter in practice.
     *
     * We could do better by calculating hashes incrementally, instead of
     * starting over from the top each time.  But that would be even uglier. */
    uint32_t a, b, c;
    uint32_t tmp[3];
    size_t n;

    a = b = c = 0xdeadbeef + table_idx;
    n = 0;

#define CLS_FIELD(WILDCARDS, MEMBER, NAME)                      \
    if (table_idx == CLS_F_IDX_##NAME) {                        \
        /* Done. */                                             \
        memset((uint8_t *) tmp + n, 0, sizeof tmp - n);         \
        goto finish;                                            \
    } else {                                                    \
        const size_t size = sizeof flow->MEMBER;                \
        const uint8_t *p1 = (const uint8_t *) &flow->MEMBER;    \
        const size_t p1_size = MIN(sizeof tmp - n, size);       \
        const uint8_t *p2 = p1 + p1_size;                       \
        const size_t p2_size = size - p1_size;                  \
                                                                \
        /* Append to 'tmp' as much data as will fit. */         \
        memcpy((uint8_t *) tmp + n, p1, p1_size);               \
        n += p1_size;                                           \
                                                                \
        /* If 'tmp' is full, mix. */                            \
        if (n == sizeof tmp) {                                  \
            a += tmp[0];                                        \
            b += tmp[1];                                        \
            c += tmp[2];                                        \
            HASH_MIX(a, b, c);                                  \
            n = 0;                                              \
        }                                                       \
                                                                \
        /* Append to 'tmp' any data that didn't fit. */         \
        memcpy(tmp, p2, p2_size);                               \
        n += p2_size;                                           \
    }
    CLS_FIELDS
#undef CLS_FIELD

finish:
    a += tmp[0];
    b += tmp[1];
    c += tmp[2];
    HASH_FINAL(a, b, c);
    return c;
}

/* Compares the fields in 'a' and 'b' whose field indexes (CLS_F_IDX_*) are
 * less than 'table_idx'.  (If 'table_idx' is CLS_F_IDX_EXACT, compares all the
 * fields in 'a' and 'b').
 *
 * Returns true if all the compared fields are equal, false otherwise. */
static bool
equal_fields(const flow_t *a, const flow_t *b, int table_idx)
{
    /* XXX The generated code could be better here. */
#define CLS_FIELD(WILDCARDS, MEMBER, NAME)                              \
    if (table_idx == CLS_F_IDX_##NAME) {                                \
        return true;                                                    \
    } else if (!equal_bytes(&a->MEMBER, &b->MEMBER, sizeof a->MEMBER)) { \
        return false;                                                   \
    }
    CLS_FIELDS
#undef CLS_FIELD

    return true;
}

static int
table_idx_from_wildcards(uint32_t wildcards)
{
    if (!wildcards) {
        return CLS_F_IDX_EXACT;
    }
#define CLS_FIELD(WILDCARDS, MEMBER, NAME) \
    if (wildcards & WILDCARDS) {           \
        return CLS_F_IDX_##NAME;           \
    }
    CLS_FIELDS
#undef CLS_FIELD
    NOT_REACHED();
}

/* Inserts 'rule' into 'table'.  Returns the rule, if any, that was displaced
 * in favor of 'rule'. */
static struct cls_rule *
table_insert(struct hmap *table, struct cls_rule *rule)
{
    struct cls_bucket *bucket;
    size_t hash;

    hash = hash_fields(&rule->flow, rule->table_idx);
    bucket = find_bucket(table, hash, rule);
    if (!bucket) {
        bucket = create_bucket(table, hash, &rule->flow);
    }

    return bucket_insert(bucket, rule);
}

/* Inserts 'rule' into 'bucket', given that 'field' is the first wildcarded
 * field in 'rule'.
 *
 * Returns the rule, if any, that was displaced in favor of 'rule'. */
static struct cls_rule *
bucket_insert(struct cls_bucket *bucket, struct cls_rule *rule)
{
    struct cls_rule *pos;
    LIST_FOR_EACH (pos, struct cls_rule, node.list, &bucket->rules) {
        if (pos->priority == rule->priority) {
            if (pos->wc.wildcards == rule->wc.wildcards
                && rules_match_1wild(pos, rule, rule->table_idx))
            {
                list_replace(&rule->node.list, &pos->node.list);
                return pos;
            }
        } else if (pos->priority < rule->priority) {
            break;
        }
    }
    list_insert(&pos->node.list, &rule->node.list);
    return NULL;
}

static struct cls_rule *
insert_exact_rule(struct classifier *cls, struct cls_rule *rule)
{
    struct cls_rule *old_rule;
    size_t hash;

    hash = flow_hash(&rule->flow, 0);
    old_rule = search_exact_table(cls, hash, &rule->flow);
    if (old_rule) {
        hmap_remove(&cls->exact_table, &old_rule->node.hmap);
    }
    hmap_insert(&cls->exact_table, &rule->node.hmap, hash);
    return old_rule;
}

/* Returns the bucket in 'table' that has the given 'hash' and the same fields
 * as 'rule->flow' (up to 'rule->table_idx'), or a null pointer if no bucket
 * matches. */
static struct cls_bucket *
find_bucket(struct hmap *table, size_t hash, const struct cls_rule *rule)
{
    struct cls_bucket *bucket;
    HMAP_FOR_EACH_WITH_HASH (bucket, struct cls_bucket, hmap_node, hash,
                             table) {
        if (equal_fields(&bucket->fixed, &rule->flow, rule->table_idx)) {
            return bucket;
        }
    }
    return NULL;
}

/* Creates a bucket and inserts it in 'table' with the given 'hash' and 'fixed'
 * values.  Returns the new bucket. */
static struct cls_bucket *
create_bucket(struct hmap *table, size_t hash, const flow_t *fixed)
{
    struct cls_bucket *bucket = xmalloc(sizeof *bucket);
    list_init(&bucket->rules);
    bucket->fixed = *fixed;
    hmap_insert(table, &bucket->hmap_node, hash);
    return bucket;
}

/* Returns true if the 'n' bytes in 'a' and 'b' are equal, false otherwise. */
static inline bool ALWAYS_INLINE
equal_bytes(const void *a, const void *b, size_t n)
{
#ifdef __i386__
    /* For some reason GCC generates stupid code for memcmp() of small
     * constant integer lengths.  Help it out.
     *
     * This function is always inlined, and it is always called with 'n' as a
     * compile-time constant, so the switch statement gets optimized out and
     * this whole function just expands to an instruction or two. */
    switch (n) {
    case 1:
        return *(uint8_t *) a == *(uint8_t *) b;

    case 2:
        return *(uint16_t *) a == *(uint16_t *) b;

    case 4:
        return *(uint32_t *) a == *(uint32_t *) b;

    case 6:
        return (*(uint32_t *) a == *(uint32_t *) b
                && ((uint16_t *) a)[2] == ((uint16_t *) b)[2]);

    default:
        abort();
    }
#else
    /* I hope GCC is smarter on your platform. */
    return !memcmp(a, b, n);
#endif
}

/* Returns the 32-bit unsigned integer at 'p'. */
static inline uint32_t
read_uint32(const void *p)
{
    /* GCC optimizes this into a single machine instruction on x86. */
    uint32_t x;
    memcpy(&x, p, sizeof x);
    return x;
}

/* Compares the specified field in 'a' and 'b'.  Returns true if the fields are
 * equal, or if the ofp_match wildcard bits in 'wildcards' are set such that
 * non-equal values may be ignored.  'nw_src_mask' and 'nw_dst_mask' must be
 * those that would be set for 'wildcards' by cls_rule_set_masks().
 *
 * The compared field is the one with wildcard bit or bits 'field_wc', offset
 * 'rule_ofs' within cls_rule's "fields" member, and length 'len', in bytes. */
static inline bool ALWAYS_INLINE
field_matches(const flow_t *a_, const flow_t *b_,
              uint32_t wildcards, uint32_t nw_src_mask, uint32_t nw_dst_mask,
              uint32_t field_wc, int ofs, int len)
{
    /* This function is always inlined, and it is always called with 'field_wc'
     * as a compile-time constant, so the "if" conditionals here generate no
     * code. */
    const void *a = (const uint8_t *) a_ + ofs;
    const void *b = (const uint8_t *) b_ + ofs;
    if (!(field_wc & (field_wc - 1))) {
        /* Handle all the single-bit wildcard cases. */
        return wildcards & field_wc || equal_bytes(a, b, len);
    } else if (field_wc == OFPFW_NW_SRC_MASK ||
               field_wc == OFPFW_NW_DST_MASK) {
        uint32_t a_ip = read_uint32(a);
        uint32_t b_ip = read_uint32(b);
        uint32_t mask = (field_wc == OFPFW_NW_SRC_MASK
                         ? nw_src_mask : nw_dst_mask);
        return ((a_ip ^ b_ip) & mask) == 0;
    } else {
        abort();
    }
}

/* Returns true if 'a' and 'b' match, ignoring fields for which the wildcards
 * in 'wildcards' are set.  'nw_src_mask' and 'nw_dst_mask' must be those that
 * would be set for 'wildcards' by cls_rule_set_masks().  'field_idx' is the
 * index of the first field to be compared; fields before 'field_idx' are
 * assumed to match.  (Always returns true if 'field_idx' is CLS_N_FIELDS.) */
static bool
rules_match(const struct cls_rule *a, const struct cls_rule *b,
            uint32_t wildcards, uint32_t nw_src_mask, uint32_t nw_dst_mask,
            int field_idx)
{
    /* This is related to Duff's device (see
     * http://en.wikipedia.org/wiki/Duff's_device).  */
    switch (field_idx) {
#define CLS_FIELD(WILDCARDS, MEMBER, NAME)                          \
        case CLS_F_IDX_##NAME:                                      \
            if (!field_matches(&a->flow, &b->flow,                  \
                               wildcards, nw_src_mask, nw_dst_mask, \
                               WILDCARDS, offsetof(flow_t, MEMBER), \
                               sizeof a->flow.MEMBER)) {            \
                return false;                                       \
            }                                                       \
        /* Fall though */
        CLS_FIELDS
#undef CLS_FIELD
    }
    return true;
}

/* Returns true if 'fixed' and 'wild' match.  All fields in 'fixed' must have
 * fixed values; 'wild' may contain wildcards.
 *
 * 'field_idx' is the index of the first field to be compared; fields before
 * 'field_idx' are assumed to match.  Always returns true if 'field_idx' is
 * CLS_N_FIELDS. */
static bool
rules_match_1wild(const struct cls_rule *fixed, const struct cls_rule *wild,
                  int field_idx)
{
    return rules_match(fixed, wild, wild->wc.wildcards, wild->wc.nw_src_mask,
                       wild->wc.nw_dst_mask, field_idx);
}

/* Returns true if 'wild1' and 'wild2' match, that is, if their fields
 * are equal modulo wildcards in 'wild1' or 'wild2'.
 *
 * 'field_idx' is the index of the first field to be compared; fields before
 * 'field_idx' are assumed to match.  Always returns true if 'field_idx' is
 * CLS_N_FIELDS. */
static bool
rules_match_2wild(const struct cls_rule *wild1, const struct cls_rule *wild2,
                  int field_idx)
{
    return rules_match(wild1, wild2,
                       wild1->wc.wildcards | wild2->wc.wildcards,
                       wild1->wc.nw_src_mask & wild2->wc.nw_src_mask,
                       wild1->wc.nw_dst_mask & wild2->wc.nw_dst_mask,
                       field_idx);
}

/* Searches 'bucket' for a rule that matches 'target'.  Returns the
 * highest-priority match, if one is found, or a null pointer if there is no
 * match.
 *
 * 'field_idx' must be the index of the first wildcarded field in 'bucket'. */
static struct cls_rule *
search_bucket(struct cls_bucket *bucket, int field_idx,
              const struct cls_rule *target)
{
    struct cls_rule *pos;

    if (!equal_fields(&bucket->fixed, &target->flow, field_idx)) {
        return NULL;
    }

    LIST_FOR_EACH (pos, struct cls_rule, node.list, &bucket->rules) {
        if (rules_match_1wild(target, pos, field_idx)) {
            return pos;
        }
    }
    return NULL;
}

/* Searches 'table' for a rule that matches 'target'.  Returns the
 * highest-priority match, if one is found, or a null pointer if there is no
 * match.
 *
 * 'field_idx' must be the index of the first wildcarded field in 'table'. */
static struct cls_rule *
search_table(const struct hmap *table, int field_idx,
             const struct cls_rule *target)
{
    struct cls_bucket *bucket;

    switch (hmap_count(table)) {
        /* In these special cases there's no need to hash.  */
    case 0:
        return NULL;
    case 1:
        bucket = CONTAINER_OF(hmap_first(table), struct cls_bucket, hmap_node);
        return search_bucket(bucket, field_idx, target);
    }

    HMAP_FOR_EACH_WITH_HASH (bucket, struct cls_bucket, hmap_node,
                             hash_fields(&target->flow, field_idx), table) {
        struct cls_rule *rule = search_bucket(bucket, field_idx, target);
        if (rule) {
            return rule;
        }
    }
    return NULL;
}

static struct cls_rule *
search_exact_table(const struct classifier *cls, size_t hash,
                   const flow_t *target)
{
    struct cls_rule *rule;

    HMAP_FOR_EACH_WITH_HASH (rule, struct cls_rule, node.hmap,
                             hash, &cls->exact_table) {
        if (flow_equal(&rule->flow, target)) {
            return rule;
        }
    }
    return NULL;
}
