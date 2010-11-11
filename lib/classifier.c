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
#include "packets.h"

static struct cls_table *find_table(const struct classifier *,
                                    const struct flow_wildcards *);
static struct cls_table *insert_table(struct classifier *,
                                      const struct flow_wildcards *);

static struct cls_table *classifier_first_table(const struct classifier *);
static struct cls_table *classifier_next_table(const struct classifier *,
                                               const struct cls_table *);
static void destroy_table(struct classifier *, struct cls_table *);

static struct cls_rule *find_match(const struct cls_table *,
                                   const struct flow *);
static struct cls_rule *find_equal(struct cls_table *, const struct flow *,
                                   uint32_t hash);
static struct cls_rule *insert_rule(struct cls_table *, struct cls_rule *);

static bool flow_equal_except(const struct flow *, const struct flow *,
                                const struct flow_wildcards *);
static void zero_wildcards(struct flow *, const struct flow_wildcards *);

/* Iterates RULE over HEAD and all of the cls_rules on HEAD->list. */
#define FOR_EACH_RULE_IN_LIST(RULE, HEAD)                               \
    for ((RULE) = (HEAD); (RULE) != NULL; (RULE) = next_rule_in_list(RULE))
#define FOR_EACH_RULE_IN_LIST_SAFE(RULE, NEXT, HEAD)                    \
    for ((RULE) = (HEAD);                                               \
         (RULE) != NULL && ((NEXT) = next_rule_in_list(RULE), true);    \
         (RULE) = (NEXT))

static struct cls_rule *next_rule_in_list(struct cls_rule *);

static struct cls_table *
cls_table_from_hmap_node(const struct hmap_node *node)
{
    return node ? CONTAINER_OF(node, struct cls_table, hmap_node) : NULL;
}

/* Converts the flow in 'flow' into a cls_rule in 'rule', with the given
 * 'wildcards' and 'priority'. */
void
cls_rule_init(const struct flow *flow, const struct flow_wildcards *wildcards,
              unsigned int priority, struct cls_rule *rule)
{
    rule->flow = *flow;
    rule->wc = *wildcards;
    rule->priority = priority;
    cls_rule_zero_wildcarded_fields(rule);
}

/* Converts the flow in 'flow' into an exact-match cls_rule in 'rule', with the
 * given 'priority'.  (For OpenFlow 1.0, exact-match rule are always highest
 * priority, so 'priority' should be at least 65535.) */
void
cls_rule_init_exact(const struct flow *flow,
                    unsigned int priority, struct cls_rule *rule)
{
    rule->flow = *flow;
    flow_wildcards_init_exact(&rule->wc);
    rule->priority = priority;
}

/* Converts the ofp_match in 'match' (with format 'flow_format', one of NXFF_*)
 * into a cls_rule in 'rule', with the given 'priority'.  'cookie' is used
 * when 'flow_format' is NXFF_TUN_ID_FROM_COOKIE. */
void
cls_rule_from_match(const struct ofp_match *match, unsigned int priority,
                    int flow_format, uint64_t cookie,
                    struct cls_rule *rule)
{
    flow_from_match(match, flow_format, cookie, &rule->flow, &rule->wc);
    rule->priority = !rule->wc.wildcards ? UINT16_MAX : priority;
    cls_rule_zero_wildcarded_fields(rule);
}

/* Initializes 'rule' as a "catch-all" rule that matches every packet, with
 * priority 'priority'. */
void
cls_rule_init_catchall(struct cls_rule *rule, unsigned int priority)
{
    memset(&rule->flow, 0, sizeof rule->flow);
    flow_wildcards_init(&rule->wc, OVSFW_ALL | FWW_ALL);
    rule->priority = priority;
}

/* For each bit or field wildcarded in 'rule', sets the corresponding bit or
 * field in 'flow' to all-0-bits.  It is important to maintain this invariant
 * in a clr_rule that might be inserted into a classifier.
 *
 * It is never necessary to call this function directly for a cls_rule that is
 * initialized or modified only by cls_rule_*() functions.  It is useful to
 * restore the invariant in a cls_rule whose 'wc' member is modified by hand.
 */
void
cls_rule_zero_wildcarded_fields(struct cls_rule *rule)
{
    zero_wildcards(&rule->flow, &rule->wc);
}

void
cls_rule_set_in_port(struct cls_rule *rule, uint16_t odp_port)
{
    rule->wc.wildcards &= ~OFPFW_IN_PORT;
    rule->flow.in_port = odp_port;
}

void
cls_rule_set_dl_type(struct cls_rule *rule, ovs_be16 dl_type)
{
    rule->wc.wildcards &= ~OFPFW_DL_TYPE;
    rule->flow.dl_type = dl_type;
}

void
cls_rule_set_dl_src(struct cls_rule *rule, const uint8_t dl_src[ETH_ADDR_LEN])
{
    rule->wc.wildcards &= ~OFPFW_DL_SRC;
    memcpy(rule->flow.dl_src, dl_src, ETH_ADDR_LEN);
}

void
cls_rule_set_dl_dst(struct cls_rule *rule, const uint8_t dl_dst[ETH_ADDR_LEN])
{
    rule->wc.wildcards &= ~(OFPFW_DL_DST | FWW_ETH_MCAST);
    memcpy(rule->flow.dl_dst, dl_dst, ETH_ADDR_LEN);
}

bool
cls_rule_set_dl_tci(struct cls_rule *rule, ovs_be16 tci)
{
    return cls_rule_set_dl_tci_masked(rule, tci, htons(0xffff));
}

bool
cls_rule_set_dl_tci_masked(struct cls_rule *rule, ovs_be16 tci, ovs_be16 mask)
{
    switch (ntohs(mask)) {
    case 0xffff:
        if (tci == htons(0)) {
            /* Match only packets that have no 802.1Q header. */
            rule->wc.wildcards &= ~(OFPFW_DL_VLAN | OFPFW_DL_VLAN_PCP);
            rule->flow.dl_vlan = htons(OFP_VLAN_NONE);
            rule->flow.dl_vlan_pcp = 0;
            return true;
        } else if (tci & htons(VLAN_CFI)) {
            /* Match only packets that have a specific 802.1Q VID and PCP. */
            rule->wc.wildcards &= ~(OFPFW_DL_VLAN | OFPFW_DL_VLAN_PCP);
            rule->flow.dl_vlan = htons(vlan_tci_to_vid(tci));
            rule->flow.dl_vlan_pcp = vlan_tci_to_pcp(tci);
            return true;
        } else {
            /* Impossible. */
            return false;
        }

    case 0x1fff:
        if (!(tci & htons(VLAN_CFI))) {
            return false;
        } else {
            /* Match only packets that have a specific 802.1Q VID. */
            cls_rule_set_dl_vlan(rule, tci & htons(VLAN_VID_MASK));
            rule->wc.wildcards |= OFPFW_DL_VLAN_PCP;
            rule->flow.dl_vlan_pcp = 0;
            return true;
        }

    case 0xf000:
        if (!(tci & htons(VLAN_CFI))) {
            return false;
        } else {
            /* Match only packets that have a specific 802.1Q PCP. */
            cls_rule_set_dl_vlan_pcp(rule, vlan_tci_to_pcp(tci));
            rule->wc.wildcards |= OFPFW_DL_VLAN;
            rule->flow.dl_vlan = 0;
            return true;
        }

    case 0x0000:
        /* Match anything. */
        rule->wc.wildcards |= OFPFW_DL_VLAN | OFPFW_DL_VLAN_PCP;
        rule->flow.dl_vlan = htons(0);
        rule->flow.dl_vlan_pcp = 0;
        return true;

    default:
        return false;
    }
}

void
cls_rule_set_dl_vlan(struct cls_rule *rule, ovs_be16 dl_vlan)
{
    if (dl_vlan != htons(OFP_VLAN_NONE)) {
        dl_vlan &= htons(VLAN_VID_MASK);
    }

    rule->wc.wildcards &= ~OFPFW_DL_VLAN;
    rule->flow.dl_vlan = dl_vlan;
}

void
cls_rule_set_dl_vlan_pcp(struct cls_rule *rule, uint8_t dl_vlan_pcp)
{
    rule->wc.wildcards &= ~OFPFW_DL_VLAN_PCP;
    rule->flow.dl_vlan_pcp = dl_vlan_pcp & 0x07;
}

void
cls_rule_set_tp_src(struct cls_rule *rule, ovs_be16 tp_src)
{
    rule->wc.wildcards &= ~OFPFW_TP_SRC;
    rule->flow.tp_src = tp_src;
}

void
cls_rule_set_tp_dst(struct cls_rule *rule, ovs_be16 tp_dst)
{
    rule->wc.wildcards &= ~OFPFW_TP_DST;
    rule->flow.tp_dst = tp_dst;
}

void
cls_rule_set_nw_proto(struct cls_rule *rule, uint8_t nw_proto)
{
    rule->wc.wildcards &= ~OFPFW_NW_PROTO;
    rule->flow.nw_proto = nw_proto;
}

void
cls_rule_set_nw_src(struct cls_rule *rule, ovs_be32 nw_src)
{
    cls_rule_set_nw_src_masked(rule, nw_src, htonl(UINT32_MAX));
}

bool
cls_rule_set_nw_src_masked(struct cls_rule *rule, ovs_be32 ip, ovs_be32 mask)
{
    if (flow_wildcards_set_nw_src_mask(&rule->wc, mask)) {
        rule->flow.nw_src = ip & mask;
        return true;
    } else {
        return false;
    }
}

void
cls_rule_set_nw_dst(struct cls_rule *rule, ovs_be32 nw_dst)
{
    cls_rule_set_nw_dst_masked(rule, nw_dst, htonl(UINT32_MAX));
}

bool
cls_rule_set_nw_dst_masked(struct cls_rule *rule, ovs_be32 ip, ovs_be32 mask)
{
    if (flow_wildcards_set_nw_dst_mask(&rule->wc, mask)) {
        rule->flow.nw_dst = ip & mask;
        return true;
    } else {
        return false;
    }
}

void
cls_rule_set_nw_tos(struct cls_rule *rule, uint8_t nw_tos)
{
    rule->wc.wildcards &= ~OFPFW_NW_TOS;
    rule->flow.nw_tos = nw_tos & IP_DSCP_MASK;
}

void
cls_rule_set_icmp_type(struct cls_rule *rule, uint8_t icmp_type)
{
    rule->wc.wildcards &= ~OFPFW_ICMP_TYPE;
    rule->flow.icmp_type = htons(icmp_type);

}

void
cls_rule_set_icmp_code(struct cls_rule *rule, uint8_t icmp_code)
{
    rule->wc.wildcards &= ~OFPFW_ICMP_CODE;
    rule->flow.icmp_code = htons(icmp_code);
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

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
void
classifier_init(struct classifier *cls)
{
    cls->n_rules = 0;
    hmap_init(&cls->tables);
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility. */
void
classifier_destroy(struct classifier *cls)
{
    if (cls) {
        struct cls_table *table, *next_table;

        HMAP_FOR_EACH_SAFE (table, next_table, hmap_node, &cls->tables) {
            hmap_destroy(&table->rules);
            hmap_remove(&cls->tables, &table->hmap_node);
            free(table);
        }
        hmap_destroy(&cls->tables);
    }
}

/* Returns true if 'cls' contains no classification rules, false otherwise. */
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

/* Inserts 'rule' into 'cls'.  Until 'rule' is removed from 'cls', the caller
 * must not modify or free it.
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
    struct cls_rule *old_rule;
    struct cls_table *table;

    table = find_table(cls, &rule->wc);
    if (!table) {
        table = insert_table(cls, &rule->wc);
    }

    old_rule = insert_rule(table, rule);
    if (!old_rule) {
        table->n_table_rules++;
        cls->n_rules++;
    }
    return old_rule;
}

/* Removes 'rule' from 'cls'.  It is the caller's responsibility to free
 * 'rule', if this is desirable. */
void
classifier_remove(struct classifier *cls, struct cls_rule *rule)
{
    struct cls_rule *head;
    struct cls_table *table;

    table = find_table(cls, &rule->wc);
    head = find_equal(table, &rule->flow, rule->hmap_node.hash);
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

    if (--table->n_table_rules == 0 && !table->n_refs) {
        destroy_table(cls, table);
    }

    cls->n_rules--;
}

/* Finds and returns the highest-priority rule in 'cls' that matches 'flow'.
 * Returns a null pointer if no rules in 'cls' match 'flow'.  If multiple rules
 * of equal priority match 'flow', returns one arbitrarily. */
struct cls_rule *
classifier_lookup(const struct classifier *cls, const struct flow *flow)
{
    struct cls_table *table;
    struct cls_rule *best;

    best = NULL;
    HMAP_FOR_EACH (table, hmap_node, &cls->tables) {
        struct cls_rule *rule = find_match(table, flow);
        if (rule && (!best || rule->priority > best->priority)) {
            best = rule;
        }
    }
    return best;
}

/* Finds and returns a rule in 'cls' with exactly the same priority and
 * matching criteria as 'target'.  Returns a null pointer if 'cls' doesn't
 * contain an exact match.
 *
 * Priority is ignored for exact-match rules (because OpenFlow 1.0 always
 * treats exact-match rules as highest priority). */
struct cls_rule *
classifier_find_rule_exactly(const struct classifier *cls,
                             const struct cls_rule *target)
{
    struct cls_rule *head, *rule;
    struct cls_table *table;

    table = find_table(cls, &target->wc);
    if (!table) {
        return NULL;
    }

    head = find_equal(table, &target->flow, flow_hash(&target->flow, 0));
    if (!target->wc.wildcards) {
        return head;
    }
    FOR_EACH_RULE_IN_LIST (rule, head) {
        if (target->priority >= rule->priority) {
            return target->priority == rule->priority ? rule : NULL;
        }
    }
    return NULL;
}

/* Checks if 'target' would overlap any other rule in 'cls'.  Two rules are
 * considered to overlap if both rules have the same priority and a packet
 * could match both. */
bool
classifier_rule_overlaps(const struct classifier *cls,
                         const struct cls_rule *target)
{
    struct cls_table *table;

    HMAP_FOR_EACH (table, hmap_node, &cls->tables) {
        struct flow_wildcards wc;
        struct cls_rule *head;

        flow_wildcards_combine(&wc, &target->wc, &table->wc);
        HMAP_FOR_EACH (head, hmap_node, &table->rules) {
            struct cls_rule *rule;

            FOR_EACH_RULE_IN_LIST (rule, head) {
                if (rule->priority == target->priority
                    && flow_equal_except(&target->flow, &rule->flow, &wc)) {
                    return true;
                }
            }
        }
    }

    return false;
}

/* Searches 'cls' for rules that exactly match 'target' or are more specific
 * than 'target'.  That is, a given 'rule' matches 'target' if, for every
 * field:
 *
 *   - 'target' and 'rule' specify the same (non-wildcarded) value for the
 *     field, or
 *
 *   - 'target' wildcards the field,
 *
 * but not if:
 *
 *   - 'target' and 'rule' specify different values for the field, or
 *
 *   - 'target' specifies a value for the field but 'rule' wildcards it.
 *
 * Equivalently, the truth table for whether a field matches is:
 *
 *                                     rule
 *
 *                             wildcard    exact
 *                            +---------+---------+
 *                   t   wild |   yes   |   yes   |
 *                   a   card |         |         |
 *                   r        +---------+---------+
 *                   g  exact |    no   |if values|
 *                   e        |         |are equal|
 *                   t        +---------+---------+
 *
 * This is the matching rule used by OpenFlow 1.0 non-strict OFPT_FLOW_MOD
 * commands and by OpenFlow 1.0 aggregate and flow stats.
 *
 * Ignores target->priority.
 *
 * 'callback' is allowed to delete the rule that is passed as its argument, but
 * it must not delete (or move) any other rules in 'cls' that have the same
 * wildcards as the argument rule. */
void
classifier_for_each_match(const struct classifier *cls_,
                          const struct cls_rule *target,
                          cls_cb_func *callback, void *aux)
{
    struct classifier *cls = (struct classifier *) cls_;
    struct cls_table *table, *next_table;

    for (table = classifier_first_table(cls); table; table = next_table) {
        if (!flow_wildcards_has_extra(&table->wc, &target->wc)) {
            /* We have eliminated the "no" case in the truth table above.  Two
             * of the three remaining cases are trivial.  We only need to check
             * the fourth case, where both 'rule' and 'target' require an exact
             * match. */
            struct cls_rule *head, *next_head;

            table->n_refs++;
            HMAP_FOR_EACH_SAFE (head, next_head, hmap_node, &table->rules) {
                if (flow_equal_except(&head->flow, &target->flow,
                                      &target->wc)) {
                    struct cls_rule *rule, *next_rule;

                    FOR_EACH_RULE_IN_LIST_SAFE (rule, next_rule, head) {
                        callback(rule, aux);
                    }
                }
            }
            next_table = classifier_next_table(cls, table);
            if (!--table->n_refs && !table->n_table_rules) {
                destroy_table(cls, table);
            }
        } else {
            next_table = classifier_next_table(cls, table);
        }
    }
}

/* 'callback' is allowed to delete the rule that is passed as its argument, but
 * it must not delete (or move) any other rules in 'cls' that have the same
 * wildcards as the argument rule. */
void
classifier_for_each(const struct classifier *cls_,
                    cls_cb_func *callback, void *aux)
{
    struct classifier *cls = (struct classifier *) cls_;
    struct cls_table *table, *next_table;

    for (table = classifier_first_table(cls); table; table = next_table) {
        struct cls_rule *head, *next_head;

        table->n_refs++;
        HMAP_FOR_EACH_SAFE (head, next_head, hmap_node, &table->rules) {
            struct cls_rule *rule, *next_rule;

            FOR_EACH_RULE_IN_LIST_SAFE (rule, next_rule, head) {
                callback(rule, aux);
            }
        }
        next_table = classifier_next_table(cls, table);
        if (!--table->n_refs && !table->n_table_rules) {
            destroy_table(cls, table);
        }
    }
}

static struct cls_table *
find_table(const struct classifier *cls, const struct flow_wildcards *wc)
{
    struct cls_table *table;

    HMAP_FOR_EACH_IN_BUCKET (table, hmap_node, flow_wildcards_hash(wc),
                             &cls->tables) {
        if (flow_wildcards_equal(wc, &table->wc)) {
            return table;
        }
    }
    return NULL;
}

static struct cls_table *
insert_table(struct classifier *cls, const struct flow_wildcards *wc)
{
    struct cls_table *table;

    table = xzalloc(sizeof *table);
    hmap_init(&table->rules);
    table->wc = *wc;
    hmap_insert(&cls->tables, &table->hmap_node, flow_wildcards_hash(wc));

    return table;
}

static struct cls_table *
classifier_first_table(const struct classifier *cls)
{
    return cls_table_from_hmap_node(hmap_first(&cls->tables));
}

static struct cls_table *
classifier_next_table(const struct classifier *cls,
                      const struct cls_table *table)
{
    return cls_table_from_hmap_node(hmap_next(&cls->tables,
                                              &table->hmap_node));
}

static void
destroy_table(struct classifier *cls, struct cls_table *table)
{
    hmap_remove(&cls->tables, &table->hmap_node);
    hmap_destroy(&table->rules);
    free(table);
}

static struct cls_rule *
find_match(const struct cls_table *table, const struct flow *flow)
{
    struct cls_rule *rule;
    struct flow f;

    f = *flow;
    zero_wildcards(&f, &table->wc);
    HMAP_FOR_EACH_WITH_HASH (rule, hmap_node, flow_hash(&f, 0),
                             &table->rules) {
        if (flow_equal(&f, &rule->flow)) {
            return rule;
        }
    }
    return NULL;
}

static struct cls_rule *
find_equal(struct cls_table *table, const struct flow *flow, uint32_t hash)
{
    struct cls_rule *head;

    HMAP_FOR_EACH_WITH_HASH (head, hmap_node, hash, &table->rules) {
        if (flow_equal(&head->flow, flow)) {
            return head;
        }
    }
    return NULL;
}

static struct cls_rule *
insert_rule(struct cls_table *table, struct cls_rule *new)
{
    struct cls_rule *head;

    new->hmap_node.hash = flow_hash(&new->flow, 0);

    head = find_equal(table, &new->flow, new->hmap_node.hash);
    if (!head) {
        hmap_insert(&table->rules, &new->hmap_node, new->hmap_node.hash);
        list_init(&new->list);
        return NULL;
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
                    return rule;
                } else {
                    list_insert(&rule->list, &new->list);
                    return NULL;
                }
            }
        }

        /* Insert 'new' at the end of the list. */
        list_push_back(&head->list, &new->list);
        return NULL;
    }
}

static struct cls_rule *
next_rule_in_list(struct cls_rule *rule)
{
    struct cls_rule *next = OBJECT_CONTAINING(rule->list.next, next, list);
    return next->priority < rule->priority ? next : NULL;
}

static bool
flow_equal_except(const struct flow *a, const struct flow *b,
                  const struct flow_wildcards *wildcards)
{
    const uint32_t wc = wildcards->wildcards;
    int i;

    BUILD_ASSERT_DECL(FLOW_SIG_SIZE == 37 + FLOW_N_REGS * 4);

    for (i = 0; i < FLOW_N_REGS; i++) {
        if ((a->regs[i] ^ b->regs[i]) & wildcards->reg_masks[i]) {
            return false;
        }
    }

    return ((wc & NXFW_TUN_ID || a->tun_id == b->tun_id)
            && !((a->nw_src ^ b->nw_src) & wildcards->nw_src_mask)
            && !((a->nw_dst ^ b->nw_dst) & wildcards->nw_dst_mask)
            && (wc & OFPFW_IN_PORT || a->in_port == b->in_port)
            && (wc & OFPFW_DL_VLAN || a->dl_vlan == b->dl_vlan)
            && (wc & OFPFW_DL_TYPE || a->dl_type == b->dl_type)
            && (wc & OFPFW_TP_SRC || a->tp_src == b->tp_src)
            && (wc & OFPFW_TP_DST || a->tp_dst == b->tp_dst)
            && (wc & OFPFW_DL_SRC || eth_addr_equals(a->dl_src, b->dl_src))
            && (wc & OFPFW_DL_DST
                || (!((a->dl_dst[0] ^ b->dl_dst[0]) & 0xfe)
                    && a->dl_dst[1] == b->dl_dst[1]
                    && a->dl_dst[2] == b->dl_dst[2]
                    && a->dl_dst[3] == b->dl_dst[3]
                    && a->dl_dst[4] == b->dl_dst[4]
                    && a->dl_dst[5] == b->dl_dst[5]))
            && (wc & FWW_ETH_MCAST || !((a->dl_dst[0] ^ b->dl_dst[0]) & 0x01))
            && (wc & OFPFW_NW_PROTO || a->nw_proto == b->nw_proto)
            && (wc & OFPFW_DL_VLAN_PCP || a->dl_vlan_pcp == b->dl_vlan_pcp)
            && (wc & OFPFW_NW_TOS || a->nw_tos == b->nw_tos));
}

static void
zero_wildcards(struct flow *flow, const struct flow_wildcards *wildcards)
{
    const uint32_t wc = wildcards->wildcards;
    int i;

    BUILD_ASSERT_DECL(FLOW_SIG_SIZE == 37 + 4 * FLOW_N_REGS);

    for (i = 0; i < FLOW_N_REGS; i++) {
        flow->regs[i] &= wildcards->reg_masks[i];
    }
    if (wc & NXFW_TUN_ID) {
        flow->tun_id = 0;
    }
    flow->nw_src &= wildcards->nw_src_mask;
    flow->nw_dst &= wildcards->nw_dst_mask;
    if (wc & OFPFW_IN_PORT) {
        flow->in_port = 0;
    }
    if (wc & OFPFW_DL_VLAN) {
        flow->dl_vlan = 0;
    }
    if (wc & OFPFW_DL_TYPE) {
        flow->dl_type = 0;
    }
    if (wc & OFPFW_TP_SRC) {
        flow->tp_src = 0;
    }
    if (wc & OFPFW_TP_DST) {
        flow->tp_dst = 0;
    }
    if (wc & OFPFW_DL_SRC) {
        memset(flow->dl_src, 0, sizeof flow->dl_src);
    }
    if (wc & OFPFW_DL_DST) {
        flow->dl_dst[0] &= 0x01;
        memset(&flow->dl_dst[1], 0, 5);
    }
    if (wc & FWW_ETH_MCAST) {
        flow->dl_dst[0] &= 0xfe;
    }
    if (wc & OFPFW_NW_PROTO) {
        flow->nw_proto = 0;
    }
    if (wc & OFPFW_DL_VLAN_PCP) {
        flow->dl_vlan_pcp = 0;
    }
    if (wc & OFPFW_NW_TOS) {
        flow->nw_tos = 0;
    }
}
