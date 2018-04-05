/*
 * Copyright (c) 2015, 2016 Nicira, Inc.
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

#ifndef OVN_EXPR_H
#define OVN_EXPR_H 1

/* OVN matching expression tree
 * ============================
 *
 * The data structures here form an abstract expression tree for matching
 * expressions in OVN.
 *
 * The abstract syntax tree representation of a matching expression is one of:
 *
 *    - A Boolean literal ("true" or "false").
 *
 *    - A comparison of a field (or part of a field) against a constant
 *      with one of the operators == != < <= > >=.
 *
 *    - The logical AND or OR of two or more matching expressions.
 *
 * Literals and comparisons are called "terminal" nodes, logical AND and OR
 * nodes are "nonterminal" nodes.
 *
 * The syntax for expressions includes a few other concepts that are not part
 * of the abstract syntax tree.  In these examples, x is a field, a, b, and c
 * are constants, and e1 and e2 are arbitrary expressions:
 *
 *    - Logical NOT.  The parser implements NOT by inverting the sense of the
 *      operand: !(x == a) becomes x != a, !(e1 && e2) becomes !e1 || !e2, and
 *      so on.
 *
 *    - Set membership.  The parser translates x == {a, b, c} into
 *      x == a || x == b || x == c.
 *
 *    - Reversed comparisons.  The parser translates a < x into x > a.
 *
 *    - Range expressions.  The parser translates a < x < b into
 *      x > a && x < b.
 */

#include "classifier.h"
#include "lex.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/meta-flow.h"

struct ds;
struct expr;
struct flow;
struct ofpbuf;
struct shash;
struct simap;

/* "Measurement level" of a field.  See "Level of Measurement" in the large
 * comment on struct expr_symbol below for more information. */
enum expr_level {
    EXPR_L_NOMINAL,

    /* Boolean values are nominal, however because of their simple nature OVN
     * can allow both equality and inequality tests on them. */
    EXPR_L_BOOLEAN,

    /* Ordinal values can at least be ordered on a scale.  OVN allows equality
     * and inequality and relational tests on ordinal values.  These are the
     * fields on which OVS allows bitwise matching. */
    EXPR_L_ORDINAL
};

const char *expr_level_to_string(enum expr_level);

/* A symbol.
 *
 *
 * Name
 * ====
 *
 * Every symbol must have a name.  To be useful, the name must satisfy the
 * lexer's syntax for an identifier.
 *
 *
 * Width
 * =====
 *
 * Every symbol has a width.  For integer symbols, this is the number of bits
 * in the value; for string symbols, this is 0.
 *
 *
 * Types
 * =====
 *
 * There are three kinds of symbols:
 *
 *   Fields:
 *
 *     One might, for example, define a field named "vlan.tci" to refer to
 *     MFF_VLAN_TCI.  'field' specifies the field.
 *
 *     'parent' and 'predicate' are NULL, and 'parent_ofs' is 0.
 *
 *     Integer fields can be nominal or ordinal (see below).  String fields are
 *     always nominal.
 *
 *   Subfields:
 *
 *     'parent' specifies the field (which may itself be a subfield,
 *     recursively) in which the subfield is embedded, and 'parent_ofs' a
 *     bitwise offset from the least-significant bit of the parent.  The
 *     subfield can contain a subset of the bits of the parent or all of them
 *     (in the latter case the subfield is really just a synonym for the
 *     parent).
 *
 *     'field' and 'predicate' are NULL.
 *
 *     Only ordinal fields (see below) may have subfields, and subfields are
 *     always ordinal.
 *
 *   Predicates:
 *
 *     A predicate is an arbitrary Boolean expression that can be used in an
 *     expression much like a 1-bit field.  'predicate' specifies the Boolean
 *     expression, e.g. "ip4" might expand to "eth.type == 0x800".  The
 *     epxression might refer to other predicates, e.g. "icmp4" might expand to
 *     "ip4 && ip4.proto == 1".
 *
 *     'field' and 'parent' are NULL, and 'parent_ofs' is 0.
 *
 *     A predicate that refers to any nominal field or predicate (see below) is
 *     nominal; other predicates have Boolean level of measurement.
 *
 *
 * Level of Measurement
 * ====================
 *
 * See http://en.wikipedia.org/wiki/Level_of_measurement for the statistical
 * concept on which this classification is based.  There are three levels:
 *
 *   Ordinal:
 *
 *     In statistics, ordinal values can be ordered on a scale.  Here, we
 *     consider a field (or subfield) to be ordinal if its bits can be examined
 *     individually.  This is true for the OpenFlow fields that OpenFlow or
 *     Open vSwitch makes "maskable".
 *
 *     OVN supports all the usual arithmetic relations (== != < <= > >=) on
 *     ordinal fields and their subfields, because all of these can be
 *     implemented as collections of bitwise tests.
 *
 *   Nominal:
 *
 *     In statistics, nominal values cannot be usefully compared except for
 *     equality.  This is true of OpenFlow port numbers, Ethernet types, and IP
 *     protocols are examples: all of these are just identifiers assigned
 *     arbitrarily with no deeper meaning.  In OpenFlow and Open vSwitch, bits
 *     in these fields generally aren't individually addressable.
 *
 *     OVN only supports arithmetic tests for equality on nominal fields,
 *     because OpenFlow and Open vSwitch provide no way for a flow to
 *     efficiently implement other comparisons on them.  (A test for inequality
 *     can be sort of built out of two flows with different priorities, but OVN
 *     matching expressions always generate flows with a single priority.)
 *
 *     String fields are always nominal.
 *
 *   Boolean:
 *
 *     A nominal field that has only two values, 0 and 1, is somewhat
 *     exceptional, since it is easy to support both equality and inequality
 *     tests on such a field: either one can be implemented as a test for 0 or
 *     1.
 *
 *     Only predicates (see above) have a Boolean level of measurement.
 *
 *     This isn't a standard level of measurement.
 *
 *
 * Prerequisites
 * =============
 *
 * Any symbol can have prerequisites, which are specified as a string giving an
 * additional expression that must be true whenever the symbol is referenced.
 * For example, the "icmp4.type" symbol might have prerequisite "icmp4", which
 * would cause an expression "icmp4.type == 0" to be interpreted as "icmp4.type
 * == 0 && icmp4", which would in turn expand to "icmp4.type == 0 && eth.type
 * == 0x800 && ip4.proto == 1" (assuming "icmp4" is a predicate defined as
 * suggested under "Types" above).
 *
 *
 * Crossproducting
 * ===============
 *
 * Ordinarily OVN is willing to consider using any field as a dimension in the
 * Open vSwitch "conjunctive match" extension (see ovs-ofctl(8)).  However,
 * some fields can't actually be used that way because they are necessary as
 * prerequisites.  For example, from an expression like "tcp.src == {1,2,3}
 * && tcp.dst == {4,5,6}", OVN might naturally generate flows like this:
 *
 *     conj_id=1,actions=...
 *     ip,actions=conjunction(1,1/3)
 *     ip6,actions=conjunction(1,1/3)
 *     tp_src=1,actions=conjunction(1,2/3)
 *     tp_src=2,actions=conjunction(1,2/3)
 *     tp_src=3,actions=conjunction(1,2/3)
 *     tp_dst=4,actions=conjunction(1,3/3)
 *     tp_dst=5,actions=conjunction(1,3/3)
 *     tp_dst=6,actions=conjunction(1,3/3)
 *
 * but that's not valid because any flow that matches on tp_src or tp_dst must
 * also match on either ip or ip6.  Thus, one would mark eth.type as "must
 * crossproduct", to force generating flows like this:
 *
 *     conj_id=1,actions=...
 *     ip,tp_src=1,actions=conjunction(1,1/2)
 *     ip,tp_src=2,actions=conjunction(1,1/2)
 *     ip,tp_src=3,actions=conjunction(1,1/2)
 *     ip6,tp_src=1,actions=conjunction(1,1/2)
 *     ip6,tp_src=2,actions=conjunction(1,1/2)
 *     ip6,tp_src=3,actions=conjunction(1,1/2)
 *     ip,tp_dst=4,actions=conjunction(1,2/2)
 *     ip,tp_dst=5,actions=conjunction(1,2/2)
 *     ip,tp_dst=6,actions=conjunction(1,2/2)
 *     ip6,tp_dst=4,actions=conjunction(1,2/2)
 *     ip6,tp_dst=5,actions=conjunction(1,2/2)
 *     ip6,tp_dst=6,actions=conjunction(1,2/2)
 *
 * which are acceptable.
 */
struct expr_symbol {
    char *name;
    int width;

    const struct mf_field *field;     /* Fields only, otherwise NULL. */
    const struct expr_symbol *parent; /* Subfields only, otherwise NULL. */
    int parent_ofs;                   /* Subfields only, otherwise 0. */
    char *predicate;                  /* Predicates only, otherwise NULL. */

    enum expr_level level;

    char *prereqs;
    bool must_crossproduct;
    bool rw;
};

void expr_symbol_format(const struct expr_symbol *, struct ds *);

/* A reference to a symbol or a subfield of a symbol.
 *
 * For string fields, ofs and n_bits are 0. */
struct expr_field {
    const struct expr_symbol *symbol; /* The symbol. */
    int ofs;                          /* Starting bit offset. */
    int n_bits;                       /* Number of bits. */
};

bool expr_field_parse(struct lexer *, const struct shash *symtab,
                      struct expr_field *, struct expr **prereqsp);
void expr_field_format(const struct expr_field *, struct ds *);

struct expr_symbol *expr_symtab_add_field(struct shash *symtab,
                                          const char *name, enum mf_field_id,
                                          const char *prereqs,
                                          bool must_crossproduct);
struct expr_symbol *expr_symtab_add_subfield(struct shash *symtab,
                                             const char *name,
                                             const char *prereqs,
                                             const char *subfield);
struct expr_symbol *expr_symtab_add_string(struct shash *symtab,
                                           const char *name, enum mf_field_id,
                                           const char *prereqs);
struct expr_symbol *expr_symtab_add_predicate(struct shash *symtab,
                                              const char *name,
                                              const char *expansion);
void expr_symtab_destroy(struct shash *symtab);

/* Expression type. */
enum expr_type {
    EXPR_T_CMP,                 /* Compare symbol with constant. */
    EXPR_T_AND,                 /* Logical AND of 2 or more subexpressions. */
    EXPR_T_OR,                  /* Logical OR of 2 or more subexpressions. */
    EXPR_T_BOOLEAN,             /* True or false constant. */
    EXPR_T_CONDITION,           /* Conditional to be evaluated in the
                                 * controller during expr_simplify(),
                                 * prior to constructing OpenFlow matches. */
};

/* Expression condition type. */
enum expr_cond_type {
    EXPR_COND_CHASSIS_RESIDENT, /* Check if specified logical port name is
                                 * resident on the controller chassis. */
};

/* Relational operator. */
enum expr_relop {
    EXPR_R_EQ,                  /* == */
    EXPR_R_NE,                  /* != */
    EXPR_R_LT,                  /* < */
    EXPR_R_LE,                  /* <= */
    EXPR_R_GT,                  /* > */
    EXPR_R_GE,                  /* >= */
};
const char *expr_relop_to_string(enum expr_relop);
bool expr_relop_from_token(enum lex_type type, enum expr_relop *relop);

/* An abstract syntax tree for a matching expression.
 *
 * The expression code maintains and relies on a few important invariants:
 *
 *     - An EXPR_T_AND or EXPR_T_OR node never has a child of the same type.
 *       (Any such children could be merged into their parent.)  A node may
 *       have grandchildren of its own type.
 *
 *       As a consequence, every nonterminal node at the same distance from the
 *       root has the same type.
 *
 *     - EXPR_T_AND and EXPR_T_OR nodes must have at least two children.
 *
 *     - An EXPR_T_CMP node always has a nonzero mask, and never has a 1-bit
 *       in its value in a position where the mask is a 0-bit.
 *
 * The expr_honors_invariants() function can check invariants. */
struct expr {
    struct ovs_list node;       /* In parent EXPR_T_AND or EXPR_T_OR if any. */
    enum expr_type type;        /* Expression type. */

    union {
        /* EXPR_T_CMP.
         *
         * The symbol is on the left, e.g. "field < constant". */
        struct {
            const struct expr_symbol *symbol;
            enum expr_relop relop;

            union {
                char *string;
                struct {
                    union mf_subvalue value;
                    union mf_subvalue mask;
                };
            };
        } cmp;

        /* EXPR_T_AND, EXPR_T_OR. */
        struct ovs_list andor;

        /* EXPR_T_BOOLEAN. */
        bool boolean;

        /* EXPR_T_CONDITION. */
        struct {
            enum expr_cond_type type;
            bool not;
            /* XXX Should arguments for conditions be generic? */
            char *string;
        } cond;
    };
};

struct expr *expr_create_boolean(bool b);
struct expr *expr_create_andor(enum expr_type);
struct expr *expr_combine(enum expr_type, struct expr *a, struct expr *b);

static inline struct expr *
expr_from_node(const struct ovs_list *node)
{
    return CONTAINER_OF(node, struct expr, node);
}

void expr_format(const struct expr *, struct ds *);
void expr_print(const struct expr *);
struct expr *expr_parse(struct lexer *, const struct shash *symtab,
                        const struct shash *addr_sets,
                        const struct shash *port_groups);
struct expr *expr_parse_string(const char *, const struct shash *symtab,
                               const struct shash *addr_sets,
                               const struct shash *port_groups,
                               char **errorp);

struct expr *expr_clone(struct expr *);
void expr_destroy(struct expr *);

struct expr *expr_annotate(struct expr *, const struct shash *symtab,
                           char **errorp);
struct expr *expr_simplify(struct expr *,
                           bool (*is_chassis_resident)(const void *c_aux,
                                                       const char *port_name),
                           const void *c_aux);
struct expr *expr_normalize(struct expr *);

bool expr_honors_invariants(const struct expr *);
bool expr_is_simplified(const struct expr *);
bool expr_is_normalized(const struct expr *);

char *expr_parse_microflow(const char *, const struct shash *symtab,
                           const struct shash *addr_sets,
                           const struct shash *port_groups,
                           bool (*lookup_port)(const void *aux,
                                               const char *port_name,
                                               unsigned int *portp),
                           const void *aux, struct flow *uflow)
    OVS_WARN_UNUSED_RESULT;

bool expr_evaluate(const struct expr *, const struct flow *uflow,
                   bool (*lookup_port)(const void *aux, const char *port_name,
                                       unsigned int *portp),
                   const void *aux);

/* Converting expressions to OpenFlow flows. */

/* An OpenFlow match generated from a Boolean expression.  See
 * expr_to_matches() for more information. */
struct expr_match {
    struct hmap_node hmap_node;
    struct match match;
    struct cls_conjunction *conjunctions;
    size_t n, allocated;
};

uint32_t expr_to_matches(const struct expr *,
                         bool (*lookup_port)(const void *aux,
                                             const char *port_name,
                                             unsigned int *portp),
                         const void *aux,
                         struct hmap *matches);
void expr_matches_destroy(struct hmap *matches);
void expr_matches_print(const struct hmap *matches, FILE *);

/* Action parsing helper. */

char *expr_type_check(const struct expr_field *, int n_bits, bool rw)
    OVS_WARN_UNUSED_RESULT;
struct mf_subfield expr_resolve_field(const struct expr_field *);

/* Type of a "union expr_constant" or "struct expr_constant_set". */
enum expr_constant_type {
    EXPR_C_INTEGER,
    EXPR_C_STRING
};

/* A string or integer constant (one must know which from context). */
union expr_constant {
    /* Integer constant.
     *
     * The width of a constant isn't always clear, e.g. if you write "1",
     * there's no way to tell whether you mean for that to be a 1-bit constant
     * or a 128-bit constant or somewhere in between. */
    struct {
        union mf_subvalue value;
        union mf_subvalue mask; /* Only initialized if 'masked'. */
        bool masked;

        enum lex_format format; /* From the constant's lex_token. */
    };

    /* Null-terminated string constant. */
    char *string;
};

bool expr_constant_parse(struct lexer *, const struct expr_field *,
                         union expr_constant *);
void expr_constant_format(const union expr_constant *,
                          enum expr_constant_type, struct ds *);
void expr_constant_destroy(const union expr_constant *,
                           enum expr_constant_type);

/* A collection of "union expr_constant"s of the same type. */
struct expr_constant_set {
    union expr_constant *values;  /* Constants. */
    size_t n_values;              /* Number of constants. */
    enum expr_constant_type type; /* Type of the constants. */
    bool in_curlies;              /* Whether the constants were in {}. */
};

bool expr_constant_set_parse(struct lexer *, struct expr_constant_set *);
void expr_constant_set_format(const struct expr_constant_set *, struct ds *);
void expr_constant_set_destroy(struct expr_constant_set *cs);


/* Constant sets.
 *
 * For example, instead of referring to a set of IP addresses as:
 *    {addr1, addr2, ..., addrN}
 * You can register a set of values and refer to them as:
 *    $name
 *
 * If convert_to_integer is true, the set must contain
 * integer/masked-integer values. The values that don't qualify
 * are ignored.
 */

void expr_const_sets_add(struct shash *const_sets, const char *name,
                         const char * const *values, size_t n_values,
                         bool convert_to_integer);
void expr_const_sets_remove(struct shash *const_sets, const char *name);
void expr_const_sets_destroy(struct shash *const_sets);

#endif /* ovn/expr.h */
