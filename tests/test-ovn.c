/*
 * Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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
#include <errno.h>
#include <getopt.h>
#include <sys/wait.h>

#include "command-line.h"
#include "dp-packet.h"
#include "fatal-signal.h"
#include "flow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn/actions.h"
#include "ovn/expr.h"
#include "ovn/lex.h"
#include "ovn/lib/logical-fields.h"
#include "ovn/lib/ovn-l7.h"
#include "ovn/lib/extend-table.h"
#include "ovs-thread.h"
#include "ovstest.h"
#include "openvswitch/shash.h"
#include "simap.h"
#include "util.h"

/* --relops: Bitmap of the relational operators to test, in exhaustive test. */
static unsigned int test_relops;

/* --nvars: Number of numeric variables to test, in exhaustive test. */
static int test_nvars = 2;

/* --svars: Number of string variables to test, in exhaustive test. */
static int test_svars = 2;

/* --bits: Number of bits per variable, in exhaustive test. */
static int test_bits = 3;

/* --operation: The operation to test, in exhaustive test. */
static enum { OP_CONVERT, OP_SIMPLIFY, OP_NORMALIZE, OP_FLOW } operation
    = OP_FLOW;

/* --parallel: Number of parallel processes to use in test. */
static int test_parallel = 1;

/* -m, --more: Message verbosity */
static int verbosity;

static void
compare_token(const struct lex_token *a, const struct lex_token *b)
{
    if (a->type != b->type) {
        fprintf(stderr, "type differs: %d -> %d\n", a->type, b->type);
        return;
    }

    if (!((a->s && b->s && !strcmp(a->s, b->s))
          || (!a->s && !b->s))) {
        fprintf(stderr, "string differs: %s -> %s\n",
                a->s ? a->s : "(null)",
                b->s ? b->s : "(null)");
        return;
    }

    if (a->type == LEX_T_INTEGER || a->type == LEX_T_MASKED_INTEGER) {
        if (memcmp(&a->value, &b->value, sizeof a->value)) {
            fprintf(stderr, "value differs\n");
            return;
        }

        if (a->type == LEX_T_MASKED_INTEGER
            && memcmp(&a->mask, &b->mask, sizeof a->mask)) {
            fprintf(stderr, "mask differs\n");
            return;
        }

        if (a->format != b->format
            && !(a->format == LEX_F_HEXADECIMAL
                 && b->format == LEX_F_DECIMAL
                 && a->value.integer == 0)) {
            fprintf(stderr, "format differs: %d -> %d\n",
                    a->format, b->format);
        }
    }
}

static void
test_lex(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct ds input;
    struct ds output;

    ds_init(&input);
    ds_init(&output);
    while (!ds_get_test_line(&input, stdin)) {
        struct lexer lexer;

        lexer_init(&lexer, ds_cstr(&input));
        ds_clear(&output);
        while (lexer_get(&lexer) != LEX_T_END) {
            size_t len = output.length;
            lex_token_format(&lexer.token, &output);

            /* Check that the formatted version can really be parsed back
             * losslessly. */
            if (lexer.token.type != LEX_T_ERROR) {
                const char *s = ds_cstr(&output) + len;
                struct lexer l2;

                lexer_init(&l2, s);
                lexer_get(&l2);
                compare_token(&lexer.token, &l2.token);
                lexer_destroy(&l2);
            }
            ds_put_char(&output, ' ');
        }
        lexer_destroy(&lexer);

        ds_chomp(&output, ' ');
        puts(ds_cstr(&output));
    }
    ds_destroy(&input);
    ds_destroy(&output);
}

static void
create_symtab(struct shash *symtab)
{
    ovn_init_symtab(symtab);

    /* For negative testing. */
    expr_symtab_add_field(symtab, "bad_prereq", MFF_XREG0, "xyzzy", false);
    expr_symtab_add_field(symtab, "self_recurse", MFF_XREG0,
                          "self_recurse != 0", false);
    expr_symtab_add_field(symtab, "mutual_recurse_1", MFF_XREG0,
                          "mutual_recurse_2 != 0", false);
    expr_symtab_add_field(symtab, "mutual_recurse_2", MFF_XREG0,
                          "mutual_recurse_1 != 0", false);
    expr_symtab_add_string(symtab, "big_string", MFF_XREG0, NULL);
}

static void
create_gen_opts(struct hmap *dhcp_opts, struct hmap *dhcpv6_opts,
                struct hmap *nd_ra_opts)
{
    hmap_init(dhcp_opts);
    dhcp_opt_add(dhcp_opts, "offerip", 0, "ipv4");
    dhcp_opt_add(dhcp_opts, "netmask", 1, "ipv4");
    dhcp_opt_add(dhcp_opts, "router",  3, "ipv4");
    dhcp_opt_add(dhcp_opts, "dns_server", 6, "ipv4");
    dhcp_opt_add(dhcp_opts, "log_server", 7, "ipv4");
    dhcp_opt_add(dhcp_opts, "lpr_server",  9, "ipv4");
    dhcp_opt_add(dhcp_opts, "domain", 15, "str");
    dhcp_opt_add(dhcp_opts, "swap_server", 16, "ipv4");
    dhcp_opt_add(dhcp_opts, "policy_filter", 21, "ipv4");
    dhcp_opt_add(dhcp_opts, "router_solicitation",  32, "ipv4");
    dhcp_opt_add(dhcp_opts, "nis_server", 41, "ipv4");
    dhcp_opt_add(dhcp_opts, "ntp_server", 42, "ipv4");
    dhcp_opt_add(dhcp_opts, "server_id",  54, "ipv4");
    dhcp_opt_add(dhcp_opts, "tftp_server", 66, "ipv4");
    dhcp_opt_add(dhcp_opts, "classless_static_route", 121, "static_routes");
    dhcp_opt_add(dhcp_opts, "ip_forward_enable",  19, "bool");
    dhcp_opt_add(dhcp_opts, "router_discovery", 31, "bool");
    dhcp_opt_add(dhcp_opts, "ethernet_encap", 36, "bool");
    dhcp_opt_add(dhcp_opts, "default_ttl",  23, "uint8");
    dhcp_opt_add(dhcp_opts, "tcp_ttl", 37, "uint8");
    dhcp_opt_add(dhcp_opts, "mtu", 26, "uint16");
    dhcp_opt_add(dhcp_opts, "lease_time",  51, "uint32");

    /* DHCPv6 options. */
    hmap_init(dhcpv6_opts);
    dhcp_opt_add(dhcpv6_opts, "server_id",  2, "mac");
    dhcp_opt_add(dhcpv6_opts, "ia_addr",  5, "ipv6");
    dhcp_opt_add(dhcpv6_opts, "dns_server",  23, "ipv6");
    dhcp_opt_add(dhcpv6_opts, "domain_search",  24, "str");

    /* IPv6 ND RA options. */
    hmap_init(nd_ra_opts);
    nd_ra_opts_init(nd_ra_opts);
}

static void
create_addr_sets(struct shash *addr_sets)
{
    shash_init(addr_sets);

    static const char *const addrs1[] = {
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
    };
    static const char *const addrs2[] = {
        "::1", "::2", "::3",
    };
    static const char *const addrs3[] = {
        "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03",
    };
    static const char *const addrs4[] = { NULL };

    expr_addr_sets_add(addr_sets, "set1", addrs1, 3);
    expr_addr_sets_add(addr_sets, "set2", addrs2, 3);
    expr_addr_sets_add(addr_sets, "set3", addrs3, 3);
    expr_addr_sets_add(addr_sets, "set4", addrs4, 0);
}

static bool
lookup_port_cb(const void *ports_, const char *port_name, unsigned int *portp)
{
    const struct simap *ports = ports_;
    const struct simap_node *node = simap_find(ports, port_name);
    if (!node) {
        return false;
    }
    *portp = node->data;
    return true;
}

static bool
is_chassis_resident_cb(const void *ports_, const char *port_name)
{
    const struct simap *ports = ports_;
    const struct simap_node *node = simap_find(ports, port_name);
    if (node) {
        return true;
    }
    return false;
}

static void
test_parse_expr__(int steps)
{
    struct shash symtab;
    struct shash addr_sets;
    struct simap ports;
    struct ds input;

    create_symtab(&symtab);
    create_addr_sets(&addr_sets);

    simap_init(&ports);
    simap_put(&ports, "eth0", 5);
    simap_put(&ports, "eth1", 6);
    simap_put(&ports, "LOCAL", ofp_to_u16(OFPP_LOCAL));

    ds_init(&input);
    while (!ds_get_test_line(&input, stdin)) {
        struct expr *expr;
        char *error;

        expr = expr_parse_string(ds_cstr(&input), &symtab, &addr_sets, &error);
        if (!error && steps > 0) {
            expr = expr_annotate(expr, &symtab, &error);
        }
        if (!error) {
            if (steps > 1) {
                expr = expr_simplify(expr, is_chassis_resident_cb, &ports);
            }
            if (steps > 2) {
                expr = expr_normalize(expr);
                ovs_assert(expr_is_normalized(expr));
            }
        }
        if (!error) {
            if (steps > 3) {
                struct hmap matches;

                expr_to_matches(expr, lookup_port_cb, &ports, &matches);
                expr_matches_print(&matches, stdout);
                expr_matches_destroy(&matches);
            } else {
                struct ds output = DS_EMPTY_INITIALIZER;
                expr_format(expr, &output);
                puts(ds_cstr(&output));
                ds_destroy(&output);
            }
        } else {
            puts(error);
            free(error);
        }
        expr_destroy(expr);
    }
    ds_destroy(&input);

    simap_destroy(&ports);
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
    expr_addr_sets_destroy(&addr_sets);
    shash_destroy(&addr_sets);
}

static void
test_parse_expr(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_parse_expr__(0);
}

static void
test_annotate_expr(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_parse_expr__(1);
}

static void
test_simplify_expr(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_parse_expr__(2);
}

static void
test_normalize_expr(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_parse_expr__(3);
}

static void
test_expr_to_flows(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_parse_expr__(4);
}

/* Print the symbol table. */

static void
test_dump_symtab(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct shash symtab;
    create_symtab(&symtab);

    const struct shash_node **nodes = shash_sort(&symtab);
    for (size_t i = 0; i < shash_count(&symtab); i++) {
        const struct expr_symbol *symbol = nodes[i]->data;
        struct ds s = DS_EMPTY_INITIALIZER;
        expr_symbol_format(symbol, &s);
        puts(ds_cstr(&s));
        ds_destroy(&s);
    }

    free(nodes);
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
}

/* Evaluate an expression. */

static bool
lookup_atoi_cb(const void *aux OVS_UNUSED, const char *port_name,
               unsigned int *portp)
{
    *portp = atoi(port_name);
    return true;
}

static void
test_evaluate_expr(struct ovs_cmdl_context *ctx)
{
    struct shash symtab;
    struct ds input;

    ovn_init_symtab(&symtab);

    struct flow uflow;
    char *error = expr_parse_microflow(ctx->argv[1], &symtab, NULL,
                                       lookup_atoi_cb, NULL, &uflow);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    ds_init(&input);
    while (!ds_get_test_line(&input, stdin)) {
        struct expr *expr;

        expr = expr_parse_string(ds_cstr(&input), &symtab, NULL, &error);
        if (!error) {
            expr = expr_annotate(expr, &symtab, &error);
        }
        if (!error) {
            printf("%d\n", expr_evaluate(expr, &uflow, lookup_atoi_cb, NULL));
        } else {
            puts(error);
            free(error);
        }
        expr_destroy(expr);
    }
    ds_destroy(&input);

    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
}

/* Compositions.
 *
 * The "compositions" of a positive integer N are all of the ways that one can
 * add up positive integers to sum to N.  For example, the compositions of 3
 * are 3, 2+1, 1+2, and 1+1+1.
 *
 * We use compositions to find all the ways to break up N terms of a Boolean
 * expression into subexpressions.  Suppose we want to generate all expressions
 * with 3 terms.  The compositions of 3 (ignoring 3 itself) provide the
 * possibilities (x && x) || x, x || (x && x), and x || x || x.  (Of course one
 * can exchange && for || in each case.)  One must recursively compose the
 * sub-expressions whose values are 3 or greater; that is what the "tree shape"
 * concept later covers.
 *
 * To iterate through all compositions of, e.g., 5:
 *
 *     unsigned int state;
 *     int s[5];
 *     int n;
 *
 *     for (n = first_composition(ARRAY_SIZE(s), &state, s); n > 0;
 *          n = next_composition(&state, s, n)) {
 *          // Do something with composition 's' with 'n' elements.
 *     }
 *
 * Algorithm from D. E. Knuth, _The Art of Computer Programming, Vol. 4A:
 * Combinatorial Algorithms, Part 1_, section 7.2.1.1, answer to exercise
 * 12(a).
 */

/* Begins iteration through the compositions of 'n'.  Initializes 's' to the
 * number of elements in the first composition of 'n' and returns that number
 * of elements.  The first composition in fact is always 'n' itself, so the
 * return value will be 1.
 *
 * Initializes '*state' to some internal state information.  The caller must
 * maintain this state (and 's') for use by next_composition().
 *
 * 's' must have room for at least 'n' elements. */
static int
first_composition(int n, unsigned int *state, int s[])
{
    *state = 0;
    s[0] = n;
    return 1;
}

/* Advances 's', with 'sn' elements, to the next composition and returns the
 * number of elements in this new composition, or 0 if no compositions are
 * left.  'state' is the same internal state passed to first_composition(). */
static int
next_composition(unsigned int *state, int s[], int sn)
{
    int j = sn - 1;
    if (++*state & 1) {
        if (s[j] > 1) {
            s[j]--;
            s[j + 1] = 1;
            j++;
        } else {
            j--;
            s[j]++;
        }
    } else {
        if (s[j - 1] > 1) {
            s[j - 1]--;
            s[j + 1] = s[j];
            s[j] = 1;
            j++;
        } else {
            j--;
            if (!j) {
                return 0;
            }
            s[j] = s[j + 1];
            s[j - 1]++;
        }
    }
    return j + 1;
}

static void
test_composition(struct ovs_cmdl_context *ctx)
{
    int n = atoi(ctx->argv[1]);
    unsigned int state;
    int s[50];

    for (int sn = first_composition(n, &state, s); sn;
         sn = next_composition(&state, s, sn)) {
        for (int i = 0; i < sn; i++) {
            printf("%d%c", s[i], i == sn - 1 ? '\n' : ' ');
        }
    }
}

/* Tree shapes.
 *
 * This code generates all possible Boolean expressions with a specified number
 * of terms N (equivalent to the number of external nodes in a tree).
 *
 * See test_tree_shape() for a simple example. */

/* An array of these structures describes the shape of a tree.
 *
 * A single element of struct tree_shape describes a single node in the tree.
 * The node has 'sn' direct children.  From left to right, for i in 0...sn-1,
 * s[i] is 1 if the child is a leaf node, otherwise the child is a subtree and
 * s[i] is the number of leaf nodes within that subtree.  In the latter case,
 * the subtree is described by another struct tree_shape within the enclosing
 * array.  The tree_shapes are ordered in the array in in-order.
 */
struct tree_shape {
    unsigned int state;
    int s[50];
    int sn;
};

static int
init_tree_shape__(struct tree_shape ts[], int n)
{
    if (n <= 2) {
        return 0;
    }

    int n_tses = 1;
    /* Skip the first composition intentionally. */
    ts->sn = first_composition(n, &ts->state, ts->s);
    ts->sn = next_composition(&ts->state, ts->s, ts->sn);
    for (int i = 0; i < ts->sn; i++) {
        n_tses += init_tree_shape__(&ts[n_tses], ts->s[i]);
    }
    return n_tses;
}

/* Initializes 'ts[]' as the first in the set of all of possible shapes of
 * trees with 'n' leaves.  Returns the number of "struct tree_shape"s in the
 * first tree shape. */
static int
init_tree_shape(struct tree_shape ts[], int n)
{
    switch (n) {
    case 1:
        ts->sn = 1;
        ts->s[0] = 1;
        return 1;
    case 2:
        ts->sn = 2;
        ts->s[0] = 1;
        ts->s[1] = 1;
        return 1;
    default:
        return init_tree_shape__(ts, n);
    }
}

/* Advances 'ts', which currently has 'n_tses' elements, to the next possible
 * tree shape with the number of leaves passed to init_tree_shape().  Returns
 * the number of "struct tree_shape"s in the next shape, or 0 if all tree
 * shapes have been visited. */
static int
next_tree_shape(struct tree_shape ts[], int n_tses)
{
    if (n_tses == 1 && ts->sn == 2 && ts->s[0] == 1 && ts->s[1] == 1) {
        return 0;
    }
    while (n_tses > 0) {
        struct tree_shape *p = &ts[n_tses - 1];
        p->sn = p->sn > 1 ? next_composition(&p->state, p->s, p->sn) : 0;
        if (p->sn) {
            for (int i = 0; i < p->sn; i++) {
                n_tses += init_tree_shape__(&ts[n_tses], p->s[i]);
            }
            break;
        }
        n_tses--;
    }
    return n_tses;
}

static void
print_tree_shape(const struct tree_shape ts[], int n_tses)
{
    for (int i = 0; i < n_tses; i++) {
        if (i) {
            printf(", ");
        }
        for (int j = 0; j < ts[i].sn; j++) {
            int k = ts[i].s[j];
            if (k > 9) {
                printf("(%d)", k);
            } else {
                printf("%d", k);
            }
        }
    }
}

static void
test_tree_shape(struct ovs_cmdl_context *ctx)
{
    int n = atoi(ctx->argv[1]);
    struct tree_shape ts[50];
    int n_tses;

    for (n_tses = init_tree_shape(ts, n); n_tses;
         n_tses = next_tree_shape(ts, n_tses)) {
        print_tree_shape(ts, n_tses);
        putchar('\n');
    }
}

/* Iteration through all possible terminal expressions (e.g. EXPR_T_CMP and
 * EXPR_T_BOOLEAN expressions).
 *
 * Given a tree shape, this allows the code to try all possible ways to plug in
 * terms.
 *
 * Example use:
 *
 *     struct expr terminal;
 *     const struct expr_symbol *vars = ...;
 *     int n_vars = ...;
 *     int n_bits = ...;
 *
 *     init_terminal(&terminal, vars[0]);
 *     do {
 *         // Something with 'terminal'.
 *     } while (next_terminal(&terminal, vars, n_vars, n_bits));
 */

/* Sets 'expr' to the first possible terminal expression.  'var' should be the
 * first variable in the ones to be tested. */
static void
init_terminal(struct expr *expr, int phase,
              const struct expr_symbol *nvars[], int n_nvars,
              const struct expr_symbol *svars[], int n_svars)
{
    if (phase < 1 && n_nvars) {
        expr->type = EXPR_T_CMP;
        expr->cmp.symbol = nvars[0];
        expr->cmp.relop = rightmost_1bit_idx(test_relops);
        memset(&expr->cmp.value, 0, sizeof expr->cmp.value);
        memset(&expr->cmp.mask, 0, sizeof expr->cmp.mask);
        expr->cmp.value.integer = htonll(0);
        expr->cmp.mask.integer = htonll(0);
        return;
    }

    if (phase < 2 && n_svars) {
        expr->type = EXPR_T_CMP;
        expr->cmp.symbol = svars[0];
        expr->cmp.relop = EXPR_R_EQ;
        expr->cmp.string = xstrdup("0");
        return;
    }

    expr->type = EXPR_T_BOOLEAN;
    expr->boolean = false;
}

/* Returns 'x' with the rightmost contiguous string of 1s changed to 0s,
 * e.g. 01011100 => 01000000.  See H. S. Warren, Jr., _Hacker's Delight_, 2nd
 * ed., section 2-1. */
static unsigned int
turn_off_rightmost_1s(unsigned int x)
{
    return ((x & -x) + x) & x;
}

static const struct expr_symbol *
next_var(const struct expr_symbol *symbol,
         const struct expr_symbol *vars[], int n_vars)
{
    for (int i = 0; i < n_vars; i++) {
        if (symbol == vars[i]) {
            return i + 1 >= n_vars ? NULL : vars[i + 1];
        }
    }
    OVS_NOT_REACHED();
}

static enum expr_relop
next_relop(enum expr_relop relop)
{
    unsigned int remaining_relops = test_relops & ~((1u << (relop + 1)) - 1);
    return (remaining_relops
            ? rightmost_1bit_idx(remaining_relops)
            : rightmost_1bit_idx(test_relops));
}

/* Advances 'expr' to the next possible terminal expression within the 'n_vars'
 * variables of 'n_bits' bits each in 'vars[]'. */
static bool
next_terminal(struct expr *expr,
              const struct expr_symbol *nvars[], int n_nvars, int n_bits,
              const struct expr_symbol *svars[], int n_svars)
{
    if (expr->type == EXPR_T_BOOLEAN) {
        if (expr->boolean) {
            return false;
        } else {
            expr->boolean = true;
            return true;
        }
    }

    if (!expr->cmp.symbol->width) {
        int next_value = atoi(expr->cmp.string) + 1;
        free(expr->cmp.string);
        if (next_value > 1) {
            expr->cmp.symbol = next_var(expr->cmp.symbol, svars, n_svars);
            if (!expr->cmp.symbol) {
                init_terminal(expr, 2, nvars, n_nvars, svars, n_svars);
                return true;
            }
            next_value = 0;
        }
        expr->cmp.string = xasprintf("%d", next_value);
        return true;
    }

    unsigned int next;

    next = (ntohll(expr->cmp.value.integer)
            + (ntohll(expr->cmp.mask.integer) << n_bits));
    for (;;) {
        next++;
        unsigned m = next >> n_bits;
        unsigned v = next & ((1u << n_bits) - 1);
        if (next >= (1u << (2 * n_bits))) {
            enum expr_relop old_relop = expr->cmp.relop;
            expr->cmp.relop = next_relop(old_relop);
            if (expr->cmp.relop <= old_relop) {
                expr->cmp.symbol = next_var(expr->cmp.symbol, nvars, n_nvars);
                if (!expr->cmp.symbol) {
                    init_terminal(expr, 1, nvars, n_nvars, svars, n_svars);
                    return true;
                }
            }
            next = UINT_MAX;
        } else if (v & ~m) {
            /* Skip: 1-bits in value correspond to 0-bits in mask. */
        } else if ((!m || turn_off_rightmost_1s(m))
                   && (expr->cmp.relop != EXPR_R_EQ &&
                       expr->cmp.relop != EXPR_R_NE)) {
            /* Skip: can't have discontiguous or all-0 mask for > >= < <=. */
        } else {
            expr->cmp.value.integer = htonll(v);
            expr->cmp.mask.integer = htonll(m);
            return true;
        }
    }
}

static struct expr *
make_terminal(struct expr ***terminalp)
{
    struct expr *e = expr_create_boolean(true);
    **terminalp = e;
    (*terminalp)++;
    return e;
}

static struct expr *
build_simple_tree(enum expr_type type, int n, struct expr ***terminalp)
{
    if (n == 2) {
        struct expr *e = expr_create_andor(type);
        for (int i = 0; i < 2; i++) {
            struct expr *sub = make_terminal(terminalp);
            ovs_list_push_back(&e->andor, &sub->node);
        }
        return e;
    } else if (n == 1) {
        return make_terminal(terminalp);
    } else {
        OVS_NOT_REACHED();
    }
}

static struct expr *
build_tree_shape(enum expr_type type, const struct tree_shape **tsp,
                 struct expr ***terminalp)
{
    const struct tree_shape *ts = *tsp;
    (*tsp)++;

    struct expr *e = expr_create_andor(type);
    enum expr_type t = type == EXPR_T_AND ? EXPR_T_OR : EXPR_T_AND;
    for (int i = 0; i < ts->sn; i++) {
        struct expr *sub = (ts->s[i] > 2
                            ? build_tree_shape(t, tsp, terminalp)
                            : build_simple_tree(t, ts->s[i], terminalp));
        ovs_list_push_back(&e->andor, &sub->node);
    }
    return e;
}

struct test_rule {
    struct cls_rule cr;
};

static void
free_rule(struct test_rule *test_rule)
{
    cls_rule_destroy(&test_rule->cr);
    free(test_rule);
}

static bool
tree_shape_is_chassis_resident_cb(const void *c_aux OVS_UNUSED,
                                  const char *port_name OVS_UNUSED)
{
    return true;
}

static int
test_tree_shape_exhaustively(struct expr *expr, struct shash *symtab,
                             struct expr *terminals[], int n_terminals,
                             const struct expr_symbol *nvars[], int n_nvars,
                             int n_bits,
                             const struct expr_symbol *svars[], int n_svars)
{
    int n_tested = 0;

    const unsigned int var_mask = (1u << n_bits) - 1;
    for (int i = 0; i < n_terminals; i++) {
        init_terminal(terminals[i], 0, nvars, n_nvars, svars, n_svars);
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    struct flow f;
    memset(&f, 0, sizeof f);
    for (;;) {
        for (int i = n_terminals - 1; ; i--) {
            if (!i) {
                ds_destroy(&s);
                return n_tested;
            }
            if (next_terminal(terminals[i], nvars, n_nvars, n_bits,
                              svars, n_svars)) {
                break;
            }
            init_terminal(terminals[i], 0, nvars, n_nvars, svars, n_svars);
        }
        ovs_assert(expr_honors_invariants(expr));

        n_tested++;

        struct expr *modified;
        if (operation == OP_CONVERT) {
            ds_clear(&s);
            expr_format(expr, &s);

            char *error;
            modified = expr_parse_string(ds_cstr(&s), symtab, NULL, &error);
            if (error) {
                fprintf(stderr, "%s fails to parse (%s)\n",
                        ds_cstr(&s), error);
                exit(EXIT_FAILURE);
            }
        } else if (operation >= OP_SIMPLIFY) {
            modified = expr_simplify(expr_clone(expr),
                                     tree_shape_is_chassis_resident_cb,
                                     NULL);
            ovs_assert(expr_honors_invariants(modified));

            if (operation >= OP_NORMALIZE) {
                modified = expr_normalize(modified);
                ovs_assert(expr_honors_invariants(modified));
                ovs_assert(expr_is_normalized(modified));
            }
        }

        struct hmap matches;
        struct classifier cls;
        if (operation >= OP_FLOW) {
            struct expr_match *m;
            struct test_rule *test_rule;

            expr_to_matches(modified, lookup_atoi_cb, NULL, &matches);

            classifier_init(&cls, NULL);
            HMAP_FOR_EACH (m, hmap_node, &matches) {
                test_rule = xmalloc(sizeof *test_rule);
                cls_rule_init(&test_rule->cr, &m->match, 0);
                classifier_insert(&cls, &test_rule->cr, OVS_VERSION_MIN,
                                  m->conjunctions, m->n);
            }
        }
        for (int subst = 0; subst < 1 << (n_bits * n_nvars + n_svars);
             subst++) {
            for (int i = 0; i < n_nvars; i++) {
                f.regs[i] = (subst >> (i * n_bits)) & var_mask;
            }
            for (int i = 0; i < n_svars; i++) {
                f.regs[n_nvars + i] = ((subst >> (n_nvars * n_bits + i))
                                       & 1);
            }

            bool expected = expr_evaluate(expr, &f, lookup_atoi_cb, NULL);
            bool actual = expr_evaluate(modified, &f, lookup_atoi_cb, NULL);
            if (actual != expected) {
                struct ds expr_s, modified_s;

                ds_init(&expr_s);
                expr_format(expr, &expr_s);

                ds_init(&modified_s);
                expr_format(modified, &modified_s);

                fprintf(stderr,
                        "%s evaluates to %d, but %s evaluates to %d, for",
                        ds_cstr(&expr_s), expected,
                        ds_cstr(&modified_s), actual);
                for (int i = 0; i < n_nvars; i++) {
                    if (i > 0) {
                        fputs(",", stderr);
                    }
                    fprintf(stderr, " n%d = 0x%x", i,
                            (subst >> (n_bits * i)) & var_mask);
                }
                for (int i = 0; i < n_svars; i++) {
                    fprintf(stderr, ", s%d = \"%d\"", i,
                            (subst >> (n_bits * n_nvars + i)) & 1);
                }
                putc('\n', stderr);
                exit(EXIT_FAILURE);
            }

            if (operation >= OP_FLOW) {
                bool found = classifier_lookup(&cls, OVS_VERSION_MIN,
                                               &f, NULL) != NULL;
                if (expected != found) {
                    struct ds expr_s, modified_s;

                    ds_init(&expr_s);
                    expr_format(expr, &expr_s);

                    ds_init(&modified_s);
                    expr_format(modified, &modified_s);

                    fprintf(stderr,
                            "%s and %s evaluate to %d, for",
                            ds_cstr(&expr_s), ds_cstr(&modified_s), expected);
                    for (int i = 0; i < n_nvars; i++) {
                        if (i > 0) {
                            fputs(",", stderr);
                        }
                        fprintf(stderr, " n%d = 0x%x", i,
                                (subst >> (n_bits * i)) & var_mask);
                    }
                    for (int i = 0; i < n_svars; i++) {
                        fprintf(stderr, ", s%d = \"%d\"", i,
                                (subst >> (n_bits * n_nvars + i)) & 1);
                    }
                    fputs(".\n", stderr);

                    fprintf(stderr, "Converted to classifier:\n");
                    expr_matches_print(&matches, stderr);
                    fprintf(stderr,
                            "However, %s flow was found in the classifier.\n",
                            found ? "a" : "no");
                    exit(EXIT_FAILURE);
                }
            }
        }
        if (operation >= OP_FLOW) {
            struct test_rule *test_rule;

            CLS_FOR_EACH (test_rule, cr, &cls) {
                classifier_remove_assert(&cls, &test_rule->cr);
                ovsrcu_postpone(free_rule, test_rule);
            }
            classifier_destroy(&cls);
            ovsrcu_quiesce();

            expr_matches_destroy(&matches);
        }
        expr_destroy(modified);
    }
}

#ifndef _WIN32
static void
wait_pid(pid_t *pids, int *n)
{
    int status;
    pid_t pid;

    pid = waitpid(-1, &status, 0);
    if (pid < 0) {
        ovs_fatal(errno, "waitpid failed");
    } else if (WIFEXITED(status)) {
        if (WEXITSTATUS(status)) {
            exit(WEXITSTATUS(status));
        }
    } else if (WIFSIGNALED(status)) {
        raise(WTERMSIG(status));
        exit(1);
    } else {
        OVS_NOT_REACHED();
    }

    for (int i = 0; i < *n; i++) {
        if (pids[i] == pid) {
            pids[i] = pids[--*n];
            return;
        }
    }
    ovs_fatal(0, "waitpid returned unknown child");
}
#endif

static void
test_exhaustive(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int n_terminals = atoi(ctx->argv[1]);
    struct tree_shape ts[50];
    int n_tses;

    struct shash symtab;
    const struct expr_symbol *nvars[4];
    const struct expr_symbol *svars[4];

    ovs_assert(test_nvars <= ARRAY_SIZE(nvars));
    ovs_assert(test_svars <= ARRAY_SIZE(svars));
    ovs_assert(test_nvars + test_svars <= FLOW_N_REGS);

    shash_init(&symtab);
    for (int i = 0; i < test_nvars; i++) {
        char *name = xasprintf("n%d", i);
        nvars[i] = expr_symtab_add_field(&symtab, name, MFF_REG0 + i, NULL,
                                         false);
        free(name);
    }
    for (int i = 0; i < test_svars; i++) {
        char *name = xasprintf("s%d", i);
        svars[i] = expr_symtab_add_string(&symtab, name,
                                          MFF_REG0 + test_nvars + i, NULL);
        free(name);
    }

#ifndef _WIN32
    pid_t *children = xmalloc(test_parallel * sizeof *children);
    int n_children = 0;
#endif

    int n_tested = 0;
    for (int i = 0; i < 2; i++) {
        enum expr_type base_type = i ? EXPR_T_OR : EXPR_T_AND;

        for (n_tses = init_tree_shape(ts, n_terminals); n_tses;
             n_tses = next_tree_shape(ts, n_tses)) {
            const struct tree_shape *tsp = ts;
            struct expr *terminals[50];
            struct expr **terminalp = terminals;
            struct expr *expr = build_tree_shape(base_type, &tsp, &terminalp);
            ovs_assert(terminalp == &terminals[n_terminals]);

            if (verbosity > 0) {
                print_tree_shape(ts, n_tses);
                printf(": ");
                struct ds s = DS_EMPTY_INITIALIZER;
                expr_format(expr, &s);
                puts(ds_cstr(&s));
                ds_destroy(&s);
            }

#ifndef _WIN32
            if (test_parallel > 1) {
                pid_t pid = xfork();
                if (!pid) {
                    test_tree_shape_exhaustively(expr, &symtab,
                                                 terminals, n_terminals,
                                                 nvars, test_nvars, test_bits,
                                                 svars, test_svars);
                    expr_destroy(expr);
                    exit(0);
                } else {
                    if (n_children >= test_parallel) {
                        wait_pid(children, &n_children);
                    }
                    children[n_children++] = pid;
                }
            } else
#endif
            {
                n_tested += test_tree_shape_exhaustively(
                    expr, &symtab, terminals, n_terminals,
                    nvars, test_nvars, test_bits,
                    svars, test_svars);
            }
            expr_destroy(expr);
        }
    }
#ifndef _WIN32
    while (n_children > 0) {
        wait_pid(children, &n_children);
    }
    free(children);
#endif

    printf("Tested ");
    switch (operation) {
    case OP_CONVERT:
        printf("converting");
        break;
    case OP_SIMPLIFY:
        printf("simplifying");
        break;
    case OP_NORMALIZE:
        printf("normalizing");
        break;
    case OP_FLOW:
        printf("converting to flows");
        break;
    }
    if (n_tested) {
        printf(" %d expressions of %d terminals", n_tested, n_terminals);
    } else {
        printf(" all %d-terminal expressions", n_terminals);
    }
    if (test_nvars || test_svars) {
        printf(" with");
        if (test_nvars) {
            printf(" %d numeric vars (each %d bits) in terms of operators",
                   test_nvars, test_bits);
            for (unsigned int relops = test_relops; relops;
                 relops = zero_rightmost_1bit(relops)) {
                enum expr_relop r = rightmost_1bit_idx(relops);
                printf(" %s", expr_relop_to_string(r));
            }
        }
        if (test_nvars && test_svars) {
            printf (" and");
        }
        if (test_svars) {
            printf(" %d string vars", test_svars);
        }
    } else {
        printf(" in terms of Boolean constants only");
    }
    printf(".\n");

    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
}

static void
test_expr_to_packets(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct shash symtab;
    struct ds input;

    create_symtab(&symtab);

    ds_init(&input);
    while (!ds_get_test_line(&input, stdin)) {
        struct flow uflow;
        char *error = expr_parse_microflow(ds_cstr(&input), &symtab, NULL,
                                           lookup_atoi_cb, NULL, &uflow);
        if (error) {
            puts(error);
            free(error);
            continue;
        }

        uint64_t packet_stub[128 / 8];
        struct dp_packet packet;
        dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
        flow_compose(&packet, &uflow, NULL, 64);

        struct ds output = DS_EMPTY_INITIALIZER;
        const uint8_t *buf = dp_packet_data(&packet);
        for (int i = 0; i < dp_packet_size(&packet); i++) {
            uint8_t val = buf[i];
            ds_put_format(&output, "%02"PRIx8, val);
        }
        puts(ds_cstr(&output));
        ds_destroy(&output);

        dp_packet_uninit(&packet);
    }
    ds_destroy(&input);

    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
}

/* Actions. */

static void
test_parse_actions(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct shash symtab;
    struct hmap dhcp_opts;
    struct hmap dhcpv6_opts;
    struct hmap nd_ra_opts;
    struct simap ports;
    struct ds input;
    bool ok = true;

    create_symtab(&symtab);
    create_gen_opts(&dhcp_opts, &dhcpv6_opts, &nd_ra_opts);

    /* Initialize group ids. */
    struct ovn_extend_table group_table;
    ovn_extend_table_init(&group_table);

    /* Initialize meter ids for QoS. */
    struct ovn_extend_table meter_table;
    ovn_extend_table_init(&meter_table);

    simap_init(&ports);
    simap_put(&ports, "eth0", 5);
    simap_put(&ports, "eth1", 6);
    simap_put(&ports, "LOCAL", ofp_to_u16(OFPP_LOCAL));

    ds_init(&input);
    while (!ds_get_test_line(&input, stdin)) {
        struct ofpbuf ovnacts;
        struct expr *prereqs;
        char *error;

        puts(ds_cstr(&input));

        ofpbuf_init(&ovnacts, 0);

        const struct ovnact_parse_params pp = {
            .symtab = &symtab,
            .dhcp_opts = &dhcp_opts,
            .dhcpv6_opts = &dhcpv6_opts,
            .nd_ra_opts = &nd_ra_opts,
            .n_tables = 24,
            .cur_ltable = 10,
        };
        error = ovnacts_parse_string(ds_cstr(&input), &pp, &ovnacts, &prereqs);
        if (!error) {
            /* Convert the parsed representation back to a string and print it,
             * if it's different from the input. */
            struct ds ovnacts_s = DS_EMPTY_INITIALIZER;
            ovnacts_format(ovnacts.data, ovnacts.size, &ovnacts_s);
            if (strcmp(ds_cstr(&input), ds_cstr(&ovnacts_s))) {
                printf("    formats as %s\n", ds_cstr(&ovnacts_s));
            }

            /* Encode the actions into OpenFlow and print. */
            const struct ovnact_encode_params ep = {
                .lookup_port = lookup_port_cb,
                .aux = &ports,
                .is_switch = true,
                .group_table = &group_table,
                .meter_table = &meter_table,

                .pipeline = OVNACT_P_INGRESS,
                .ingress_ptable = 8,
                .egress_ptable = 40,
                .output_ptable = 64,
                .mac_bind_ptable = 65,
            };
            struct ofpbuf ofpacts;
            ofpbuf_init(&ofpacts, 0);
            ovnacts_encode(ovnacts.data, ovnacts.size, &ep, &ofpacts);
            struct ds ofpacts_s = DS_EMPTY_INITIALIZER;
            struct ofpact_format_params fp = { .s = &ofpacts_s };
            ofpacts_format(ofpacts.data, ofpacts.size, &fp);
            printf("    encodes as %s\n", ds_cstr(&ofpacts_s));
            ds_destroy(&ofpacts_s);
            ofpbuf_uninit(&ofpacts);

            /* Print prerequisites if any. */
            if (prereqs) {
                struct ds prereqs_s = DS_EMPTY_INITIALIZER;
                expr_format(prereqs, &prereqs_s);
                printf("    has prereqs %s\n", ds_cstr(&prereqs_s));
                ds_destroy(&prereqs_s);
            }

            /* Now re-parse and re-format the string to verify that it's
             * round-trippable. */
            struct ofpbuf ovnacts2;
            struct expr *prereqs2;
            ofpbuf_init(&ovnacts2, 0);
            error = ovnacts_parse_string(ds_cstr(&ovnacts_s), &pp, &ovnacts2,
                                         &prereqs2);
            if (!error) {
                struct ds ovnacts2_s = DS_EMPTY_INITIALIZER;
                ovnacts_format(ovnacts2.data, ovnacts2.size, &ovnacts2_s);
                if (strcmp(ds_cstr(&ovnacts_s), ds_cstr(&ovnacts2_s))) {
                    printf("    bad reformat: %s\n", ds_cstr(&ovnacts2_s));
                    ok = false;
                }
                ds_destroy(&ovnacts2_s);
            } else {
                printf("    reparse error: %s\n", error);
                free(error);
                ok = false;
            }
            expr_destroy(prereqs2);

            ovnacts_free(ovnacts2.data, ovnacts2.size);
            ofpbuf_uninit(&ovnacts2);
            ds_destroy(&ovnacts_s);
        } else {
            printf("    %s\n", error);
            free(error);
        }

        expr_destroy(prereqs);
        ovnacts_free(ovnacts.data, ovnacts.size);
        ofpbuf_uninit(&ovnacts);
    }
    ds_destroy(&input);

    simap_destroy(&ports);
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
    dhcp_opts_destroy(&dhcp_opts);
    dhcp_opts_destroy(&dhcpv6_opts);
    nd_ra_opts_destroy(&nd_ra_opts);
    exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
}

static unsigned int
parse_relops(const char *s)
{
    unsigned int relops = 0;
    struct lexer lexer;

    lexer_init(&lexer, s);
    lexer_get(&lexer);
    do {
        enum expr_relop relop;

        if (expr_relop_from_token(lexer.token.type, &relop)) {
            relops |= 1u << relop;
            lexer_get(&lexer);
        } else {
            ovs_fatal(0, "%s: relational operator expected at `%.*s'",
                      s, (int) (lexer.input - lexer.start), lexer.start);
        }
        lexer_match(&lexer, LEX_T_COMMA);
    } while (lexer.token.type != LEX_T_END);
    lexer_destroy(&lexer);

    return relops;
}

static void
usage(void)
{
    printf("\
%s: OVN test utility\n\
usage: test-ovn %s [OPTIONS] COMMAND [ARG...]\n\
\n\
lex\n\
  Lexically analyzes OVN input from stdin and print them back on stdout.\n\
\n\
parse-expr\n\
annotate-expr\n\
simplify-expr\n\
normalize-expr\n\
expr-to-flows\n\
  Parses OVN expressions from stdin and prints them back on stdout after\n\
  differing degrees of analysis.  Available fields are based on packet\n\
  headers.\n\
\n\
expr-to-packets\n\
  Parses OVN expressions from stdin and prints out matching packets in\n\
  hexadecimal on stdout.\n\
\n\
evaluate-expr MICROFLOW\n\
  Parses OVN expressions from stdin and evaluates them against the flow\n\
  specified in MICROFLOW, which must be an expression that constrains\n\
  the packet, e.g. \"ip4 && tcp.src == 80\" for a TCP packet with source\n\
  port 80, and prints the results on stdout, either 1 for true or 0 for\n\
  false.  Use quoted integers, e.g. \"123\", for string fields.\n\
\n\
  Example: for MICROFLOW of \"ip4 && tcp.src == 80\", \"eth.type == 0x800\"\n\
  evaluates to true, \"udp\" evaluates to false, and \"udp || tcp\"\n\
  evaluates to true.\n\
\n\
composition N\n\
  Prints all the compositions of N on stdout.\n\
\n\
tree-shape N\n\
  Prints all the tree shapes with N terminals on stdout.\n\
\n\
exhaustive N\n\
  Tests that all possible Boolean expressions with N terminals are properly\n\
  simplified, normalized, and converted to flows.  Available options:\n\
   Overall options:\n\
    --operation=OPERATION  Operation to test, one of: convert, simplify,\n\
        normalize, flow.  Default: flow.  'normalize' includes 'simplify',\n\
        'flow' includes 'simplify' and 'normalize'.\n\
    --parallel=N  Number of processes to use in parallel, default 1.\n\
   Numeric vars:\n\
    --nvars=N  Number of numeric vars to test, in range 0...4, default 2.\n\
    --bits=N  Number of bits per variable, in range 1...3, default 3.\n\
    --relops=OPERATORS   Test only the specified Boolean operators.\n\
                         OPERATORS may include == != < <= > >=, space or\n\
                         comma separated.  Default is all operators.\n\
   String vars:\n\
    --svars=N  Number of string vars to test, in range 0...4, default 2.\n\
\n\
parse-actions\n\
  Parses OVN actions from stdin and prints the equivalent OpenFlow actions\n\
  on stdout.\n\
",
           program_name, program_name);
    exit(EXIT_SUCCESS);
}

static void
test_ovn_main(int argc, char *argv[])
{
    enum {
        OPT_RELOPS = UCHAR_MAX + 1,
        OPT_NVARS,
        OPT_SVARS,
        OPT_BITS,
        OPT_OPERATION,
        OPT_PARALLEL
    };
    static const struct option long_options[] = {
        {"relops", required_argument, NULL, OPT_RELOPS},
        {"nvars", required_argument, NULL, OPT_NVARS},
        {"svars", required_argument, NULL, OPT_SVARS},
        {"bits", required_argument, NULL, OPT_BITS},
        {"operation", required_argument, NULL, OPT_OPERATION},
        {"parallel", required_argument, NULL, OPT_PARALLEL},
        {"more", no_argument, NULL, 'm'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    set_program_name(argv[0]);

    test_relops = parse_relops("== != < <= > >=");
    for (;;) {
        int option_index = 0;
        int c = getopt_long (argc, argv, short_options, long_options,
                             &option_index);

        if (c == -1) {
            break;
        }
        switch (c) {
        case OPT_RELOPS:
            test_relops = parse_relops(optarg);
            break;

        case OPT_NVARS:
            test_nvars = atoi(optarg);
            if (test_nvars < 0 || test_nvars > 4) {
                ovs_fatal(0, "number of numeric variables must be "
                          "between 0 and 4");
            }
            break;

        case OPT_SVARS:
            test_svars = atoi(optarg);
            if (test_svars < 0 || test_svars > 4) {
                ovs_fatal(0, "number of string variables must be "
                          "between 0 and 4");
            }
            break;

        case OPT_BITS:
            test_bits = atoi(optarg);
            if (test_bits < 1 || test_bits > 3) {
                ovs_fatal(0, "number of bits must be between 1 and 3");
            }
            break;

        case OPT_OPERATION:
            if (!strcmp(optarg, "convert")) {
                operation = OP_CONVERT;
            } else if (!strcmp(optarg, "simplify")) {
                operation = OP_SIMPLIFY;
            } else if (!strcmp(optarg, "normalize")) {
                operation = OP_NORMALIZE;
            } else if (!strcmp(optarg, "flow")) {
                operation = OP_FLOW;
            } else {
                ovs_fatal(0, "%s: unknown operation", optarg);
            }
            break;

        case OPT_PARALLEL:
            test_parallel = atoi(optarg);
            break;

        case 'm':
            verbosity++;
            break;

        case 'h':
            usage();
            /* fall through */

        case '?':
            exit(1);

        default:
            abort();
        }
    }
    free(short_options);

    static const struct ovs_cmdl_command commands[] = {
        /* Lexer. */
        {"lex", NULL, 0, 0, test_lex, OVS_RO},

        /* Symbol table. */
        {"dump-symtab", NULL, 0, 0, test_dump_symtab, OVS_RO},

        /* Expressions. */
        {"parse-expr", NULL, 0, 0, test_parse_expr, OVS_RO},
        {"annotate-expr", NULL, 0, 0, test_annotate_expr, OVS_RO},
        {"simplify-expr", NULL, 0, 0, test_simplify_expr, OVS_RO},
        {"normalize-expr", NULL, 0, 0, test_normalize_expr, OVS_RO},
        {"expr-to-flows", NULL, 0, 0, test_expr_to_flows, OVS_RO},
        {"evaluate-expr", NULL, 1, 1, test_evaluate_expr, OVS_RO},
        {"composition", NULL, 1, 1, test_composition, OVS_RO},
        {"tree-shape", NULL, 1, 1, test_tree_shape, OVS_RO},
        {"exhaustive", NULL, 1, 1, test_exhaustive, OVS_RO},
        {"expr-to-packets", NULL, 0, 0, test_expr_to_packets, OVS_RO},

        /* Actions. */
        {"parse-actions", NULL, 0, 0, test_parse_actions, OVS_RO},

        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ovn", test_ovn_main);
