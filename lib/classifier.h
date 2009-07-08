/*
 * Copyright (c) 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef CLASSIFIER_H
#define CLASSIFIER_H 1

/* Flow classifier.
 *
 * This flow classifier assumes that we can arrange the fields in a flow in an
 * order such that the set of wildcarded fields in a rule tend to fall toward
 * the end of the ordering.  That is, if field F is wildcarded, then all the
 * fields after F tend to be wildcarded as well.  If this assumption is
 * violated, then the classifier will still classify flows correctly, but its
 * performance will suffer.
 */

#include "flow.h"
#include "hmap.h"
#include "list.h"
#include "openflow/openflow.h"

/* Number of bytes of fields in a rule. */
#define CLS_N_BYTES 31

/* Fields in a rule.
 *
 * This definition sets the ordering of fields, which is important for
 * performance (see above).  To adjust the ordering, change the order of the
 * lines. */
#define CLS_FIELDS                                          \
    /*                           flow_t       all-caps */   \
    /*        wildcard bit(s)    member name  name     */   \
    /*        -----------------  -----------  -------- */   \
    CLS_FIELD(OFPFW_IN_PORT,     in_port,     IN_PORT)      \
    CLS_FIELD(OFPFW_DL_VLAN,     dl_vlan,     DL_VLAN)      \
    CLS_FIELD(OFPFW_DL_SRC,      dl_src,      DL_SRC)       \
    CLS_FIELD(OFPFW_DL_DST,      dl_dst,      DL_DST)       \
    CLS_FIELD(OFPFW_DL_TYPE,     dl_type,     DL_TYPE)      \
    CLS_FIELD(OFPFW_NW_SRC_MASK, nw_src,      NW_SRC)       \
    CLS_FIELD(OFPFW_NW_DST_MASK, nw_dst,      NW_DST)       \
    CLS_FIELD(OFPFW_NW_PROTO,    nw_proto,    NW_PROTO)     \
    CLS_FIELD(OFPFW_TP_SRC,      tp_src,      TP_SRC)       \
    CLS_FIELD(OFPFW_TP_DST,      tp_dst,      TP_DST)

/* Field indexes.
 *
 * (These are also indexed into struct classifier's 'tables' array.) */
enum {
#define CLS_FIELD(WILDCARDS, MEMBER, NAME) CLS_F_IDX_##NAME,
    CLS_FIELDS
#undef CLS_FIELD
    CLS_F_IDX_EXACT,            /* Exact-match table. */
    CLS_N_FIELDS = CLS_F_IDX_EXACT
};

/* Field information. */
struct cls_field {
    int ofs;                    /* Offset in flow_t. */
    int len;                    /* Length in bytes. */
    uint32_t wildcards;         /* OFPFW_* bit or bits for this field. */
    const char *name;           /* Name (for debugging). */
};
extern const struct cls_field cls_fields[CLS_N_FIELDS + 1];

/* A flow classifier. */
struct classifier {
    int n_rules;                /* Sum of hmap_count() over tables[]. */
    struct hmap tables[CLS_N_FIELDS]; /* Contain cls_bucket elements. */
    struct hmap exact_table;          /* Contain cls_rule elements. */
};

/* A group of rules with the same fixed values for initial fields. */
struct cls_bucket {
    struct hmap_node hmap_node; /* Within struct classifier 'tables'. */
    struct list rules;          /* In order from highest to lowest priority. */
    flow_t fixed;               /* Values for fixed fields. */
};

/* A flow classification rule.
 *
 * Use cls_rule_from_flow() or cls_rule_from_match() to initialize a cls_rule
 * or you will almost certainly not initialize 'table_idx' correctly, with
 * disastrous results! */
struct cls_rule {
    union {
        struct list list;       /* Within struct cls_bucket 'rules'. */
        struct hmap_node hmap;  /* Within struct classifier 'exact_table'. */
    } node;
    flow_t flow;                /* All field values. */
    struct flow_wildcards wc;   /* Wildcards for fields. */
    unsigned int priority;      /* Larger numbers are higher priorities. */
    unsigned int table_idx;     /* Index into struct classifier 'tables'. */
};

void cls_rule_from_flow(struct cls_rule *, const flow_t *, uint32_t wildcards,
                        unsigned int priority);
void cls_rule_from_match(struct cls_rule *, const struct ofp_match *,
                         unsigned int priority);
void cls_rule_print(const struct cls_rule *);
void cls_rule_moved(struct classifier *,
                    struct cls_rule *old, struct cls_rule *new);
void cls_rule_replace(struct classifier *, const struct cls_rule *old,
                      struct cls_rule *new);

void classifier_init(struct classifier *);
void classifier_destroy(struct classifier *);
bool classifier_is_empty(const struct classifier *);
int classifier_count(const struct classifier *);
int classifier_count_exact(const struct classifier *);
struct cls_rule *classifier_insert(struct classifier *, struct cls_rule *);
void classifier_insert_exact(struct classifier *, struct cls_rule *);
void classifier_remove(struct classifier *, struct cls_rule *);
struct cls_rule *classifier_lookup(const struct classifier *, const flow_t *);
struct cls_rule *classifier_lookup_wild(const struct classifier *,
                                        const flow_t *);
struct cls_rule *classifier_lookup_exact(const struct classifier *,
                                         const flow_t *);

typedef void cls_cb_func(struct cls_rule *, void *aux);

enum {
    CLS_INC_EXACT = 1 << 0,     /* Include exact-match flows? */
    CLS_INC_WILD = 1 << 1,      /* Include flows with wildcards? */
    CLS_INC_ALL = CLS_INC_EXACT | CLS_INC_WILD
};
void classifier_for_each(const struct classifier *, int include,
                         cls_cb_func *, void *aux);
void classifier_for_each_match(const struct classifier *,
                               const struct cls_rule *,
                               int include, cls_cb_func *, void *aux);
struct cls_rule *classifier_find_rule_exactly(const struct classifier *,
                                              const flow_t *target,
                                              uint32_t wildcards,
                                              unsigned int priority);

#endif /* classifier.h */
