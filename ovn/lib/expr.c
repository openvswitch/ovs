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

#include <config.h>
#include "byte-order.h"
#include "expr.h"
#include "json.h"
#include "lex.h"
#include "logical-fields.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/vlog.h"
#include "shash.h"
#include "simap.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(expr);

/* Returns the name of measurement level 'level'. */
const char *
expr_level_to_string(enum expr_level level)
{
    switch (level) {
    case EXPR_L_NOMINAL: return "nominal";
    case EXPR_L_BOOLEAN: return "Boolean";
    case EXPR_L_ORDINAL: return "ordinal";
    default: OVS_NOT_REACHED();
    }
}

/* Relational operators. */

/* Returns a string form of relational operator 'relop'. */
const char *
expr_relop_to_string(enum expr_relop relop)
{
    switch (relop) {
    case EXPR_R_EQ: return "==";
    case EXPR_R_NE: return "!=";
    case EXPR_R_LT: return "<";
    case EXPR_R_LE: return "<=";
    case EXPR_R_GT: return ">";
    case EXPR_R_GE: return ">=";
    default: OVS_NOT_REACHED();
    }
}

bool
expr_relop_from_token(enum lex_type type, enum expr_relop *relop)
{
    enum expr_relop r;

    switch ((int) type) {
    case LEX_T_EQ: r = EXPR_R_EQ; break;
    case LEX_T_NE: r = EXPR_R_NE; break;
    case LEX_T_LT: r = EXPR_R_LT; break;
    case LEX_T_LE: r = EXPR_R_LE; break;
    case LEX_T_GT: r = EXPR_R_GT; break;
    case LEX_T_GE: r = EXPR_R_GE; break;
    default: return false;
    }

    if (relop) {
        *relop = r;
    }
    return true;
}

/* Returns the relational operator that 'relop' becomes if you turn the
 * relation's operands around, e.g. EXPR_R_EQ does not change because "a == b"
 * and "b == a" are equivalent, but EXPR_R_LE becomes EXPR_R_GE because "a <=
 * b" is equivalent to "b >= a". */
static enum expr_relop
expr_relop_turn(enum expr_relop relop)
{
    switch (relop) {
    case EXPR_R_EQ: return EXPR_R_EQ;
    case EXPR_R_NE: return EXPR_R_NE;
    case EXPR_R_LT: return EXPR_R_GT;
    case EXPR_R_LE: return EXPR_R_GE;
    case EXPR_R_GT: return EXPR_R_LT;
    case EXPR_R_GE: return EXPR_R_LE;
    default: OVS_NOT_REACHED();
    }
}

/* Returns the relational operator that is the opposite of 'relop'. */
static enum expr_relop
expr_relop_invert(enum expr_relop relop)
{
    switch (relop) {
    case EXPR_R_EQ: return EXPR_R_NE;
    case EXPR_R_NE: return EXPR_R_EQ;
    case EXPR_R_LT: return EXPR_R_GE;
    case EXPR_R_LE: return EXPR_R_GT;
    case EXPR_R_GT: return EXPR_R_LE;
    case EXPR_R_GE: return EXPR_R_LT;
    default: OVS_NOT_REACHED();
    }
}

/* Constructing and manipulating expressions. */

/* Creates and returns a logical AND or OR expression (according to 'type',
 * which must be EXPR_T_AND or EXPR_T_OR) that initially has no
 * sub-expressions.  (To satisfy the invariants for expressions, the caller
 * must add at least two sub-expressions whose types are different from
 * 'type'.) */
struct expr *
expr_create_andor(enum expr_type type)
{
    struct expr *e = xmalloc(sizeof *e);
    e->type = type;
    ovs_list_init(&e->andor);
    return e;
}

/* Returns a logical AND or OR expression (according to 'type', which must be
 * EXPR_T_AND or EXPR_T_OR) whose sub-expressions are 'a' and 'b', with some
 * flexibility:
 *
 *     - If 'a' or 'b' is NULL, just returns the other one (which means that if
 *       that other one is not of the given 'type', then the returned
 *       expression is not either).
 *
 *     - If 'a' or 'b', or both, have type 'type', then they are combined into
 *       a single node that satisfies the invariants for expressions. */
struct expr *
expr_combine(enum expr_type type, struct expr *a, struct expr *b)
{
    if (!a) {
        return b;
    } else if (!b) {
        return a;
    } else if (a->type == type) {
        if (b->type == type) {
            ovs_list_splice(&a->andor, b->andor.next, &b->andor);
            free(b);
        } else {
            ovs_list_push_back(&a->andor, &b->node);
        }
        return a;
    } else if (b->type == type) {
        ovs_list_push_front(&b->andor, &a->node);
        return b;
    } else {
        struct expr *e = expr_create_andor(type);
        ovs_list_push_back(&e->andor, &a->node);
        ovs_list_push_back(&e->andor, &b->node);
        return e;
    }
}

static void
expr_insert_andor(struct expr *andor, struct expr *before, struct expr *new)
{
    if (new->type == andor->type) {
        if (andor->type == EXPR_T_AND) {
            /* Conjunction junction, what's your function? */
        }
        ovs_list_splice(&before->node, new->andor.next, &new->andor);
        free(new);
    } else {
        ovs_list_insert(&before->node, &new->node);
    }
}

/* Returns an EXPR_T_BOOLEAN expression with value 'b'. */
struct expr *
expr_create_boolean(bool b)
{
    struct expr *e = xmalloc(sizeof *e);
    e->type = EXPR_T_BOOLEAN;
    e->boolean = b;
    return e;
}

static void
expr_not(struct expr *expr)
{
    struct expr *sub;

    switch (expr->type) {
    case EXPR_T_CMP:
        expr->cmp.relop = expr_relop_invert(expr->cmp.relop);
        break;

    case EXPR_T_AND:
    case EXPR_T_OR:
        LIST_FOR_EACH (sub, node, &expr->andor) {
            expr_not(sub);
        }
        expr->type = expr->type == EXPR_T_AND ? EXPR_T_OR : EXPR_T_AND;
        break;

    case EXPR_T_BOOLEAN:
        expr->boolean = !expr->boolean;
        break;
    default:
        OVS_NOT_REACHED();
    }
}

static struct expr *
expr_fix_andor(struct expr *expr, bool short_circuit)
{
    struct expr *sub, *next;

    LIST_FOR_EACH_SAFE (sub, next, node, &expr->andor) {
        if (sub->type == EXPR_T_BOOLEAN) {
            if (sub->boolean == short_circuit) {
                expr_destroy(expr);
                return expr_create_boolean(short_circuit);
            } else {
                ovs_list_remove(&sub->node);
                expr_destroy(sub);
            }
        }
    }

    if (ovs_list_is_short(&expr->andor)) {
        if (ovs_list_is_empty(&expr->andor)) {
            free(expr);
            return expr_create_boolean(!short_circuit);
        } else {
            sub = expr_from_node(ovs_list_front(&expr->andor));
            free(expr);
            return sub;
        }
    } else {
        return expr;
    }
}

/* Returns 'expr' modified so that top-level oddities are fixed up:
 *
 *     - Eliminates any EXPR_T_BOOLEAN operands at the top level.
 *
 *     - Replaces one-operand EXPR_T_AND or EXPR_T_OR by its subexpression. */
static struct expr *
expr_fix(struct expr *expr)
{
    switch (expr->type) {
    case EXPR_T_CMP:
        return expr;

    case EXPR_T_AND:
        return expr_fix_andor(expr, false);

    case EXPR_T_OR:
        return expr_fix_andor(expr, true);

    case EXPR_T_BOOLEAN:
        return expr;

    default:
        OVS_NOT_REACHED();
    }
}

/* Formatting. */

static void
find_bitwise_range(const union mf_subvalue *sv, int width,
                   int *startp, int *n_bitsp)
{
    unsigned int start = bitwise_scan(sv, sizeof *sv, true, 0, width);
    if (start < width) {
        unsigned int end = bitwise_scan(sv, sizeof *sv, false, start, width);
        if (end >= width
            || bitwise_scan(sv, sizeof *sv, true, end, width) >= width) {
            *startp = start;
            *n_bitsp = end - start;
            return;
        }
    }
    *startp = *n_bitsp = 0;
}

static void
expr_format_cmp(const struct expr *e, struct ds *s)
{
    /* The common case is numerical comparisons.
     * Handle string comparisons as a special case. */
    if (!e->cmp.symbol->width) {
        ds_put_format(s, "%s %s ", e->cmp.symbol->name,
                      expr_relop_to_string(e->cmp.relop));
        json_string_escape(e->cmp.string, s);
        return;
    }

    int ofs, n;
    find_bitwise_range(&e->cmp.mask, e->cmp.symbol->width, &ofs, &n);
    if (n == 1 && (e->cmp.relop == EXPR_R_EQ || e->cmp.relop == EXPR_R_NE)) {
        bool positive;

        positive = bitwise_get_bit(&e->cmp.value, sizeof e->cmp.value, ofs);
        positive ^= e->cmp.relop == EXPR_R_NE;
        if (!positive) {
            ds_put_char(s, '!');
        }
        ds_put_cstr(s, e->cmp.symbol->name);
        if (e->cmp.symbol->width > 1) {
            ds_put_format(s, "[%d]", ofs);
        }
        return;
    }

    ds_put_cstr(s, e->cmp.symbol->name);
    if (n > 0 && n < e->cmp.symbol->width) {
        if (n > 1) {
            ds_put_format(s, "[%d..%d]", ofs, ofs + n - 1);
        } else {
            ds_put_format(s, "[%d]", ofs);
        }
    }

    ds_put_format(s, " %s ", expr_relop_to_string(e->cmp.relop));

    if (n) {
        union mf_subvalue value;

        memset(&value, 0, sizeof value);
        bitwise_copy(&e->cmp.value, sizeof e->cmp.value, ofs,
                     &value, sizeof value, 0,
                     n);
        mf_format_subvalue(&value, s);
    } else {
        mf_format_subvalue(&e->cmp.value, s);
        ds_put_char(s, '/');
        mf_format_subvalue(&e->cmp.mask, s);
    }
}

static void
expr_format_andor(const struct expr *e, const char *op, struct ds *s)
{
    struct expr *sub;
    int i = 0;

    LIST_FOR_EACH (sub, node, &e->andor) {
        if (i++) {
            ds_put_format(s, " %s ", op);
        }

        if (sub->type == EXPR_T_AND || sub->type == EXPR_T_OR) {
            ds_put_char(s, '(');
            expr_format(sub, s);
            ds_put_char(s, ')');
        } else {
            expr_format(sub, s);
        }
    }
}

/* Appends a string form of 'e' to 's'.  The string form is acceptable for
 * parsing back into an equivalent expression. */
void
expr_format(const struct expr *e, struct ds *s)
{
    switch (e->type) {
    case EXPR_T_CMP:
        expr_format_cmp(e, s);
        break;

    case EXPR_T_AND:
        expr_format_andor(e, "&&", s);
        break;

    case EXPR_T_OR:
        expr_format_andor(e, "||", s);
        break;

    case EXPR_T_BOOLEAN:
        ds_put_char(s, e->boolean ? '1' : '0');
        break;
    }
}

/* Prints a string form of 'e' on stdout, followed by a new-line. */
void
expr_print(const struct expr *e)
{
    struct ds output;

    ds_init(&output);
    expr_format(e, &output);
    puts(ds_cstr(&output));
    ds_destroy(&output);
}

/* Parsing. */

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

/* A collection of "union expr_constant"s of the same type. */
struct expr_constant_set {
    union expr_constant *values;  /* Constants. */
    size_t n_values;              /* Number of constants. */
    enum expr_constant_type type; /* Type of the constants. */
    bool in_curlies;              /* Whether the constants were in {}. */
};

/* A reference to a symbol or a subfield of a symbol.
 *
 * For string fields, ofs and n_bits are 0. */
struct expr_field {
    const struct expr_symbol *symbol; /* The symbol. */
    int ofs;                          /* Starting bit offset. */
    int n_bits;                       /* Number of bits. */
};

/* Context maintained during expr_parse(). */
struct expr_context {
    struct lexer *lexer;        /* Lexer for pulling more tokens. */
    const struct shash *symtab; /* Symbol table. */
    char *error;                /* Error, if any, otherwise NULL. */
    bool not;                   /* True inside odd number of NOT operators. */
};

struct expr *expr_parse__(struct expr_context *);
static void expr_not(struct expr *);
static void expr_constant_set_destroy(struct expr_constant_set *);
static bool parse_field(struct expr_context *, struct expr_field *);

static bool
expr_error_handle_common(struct expr_context *ctx)
{
    if (ctx->error) {
        /* Already have an error, suppress this one since the cascade seems
         * unlikely to be useful. */
        return true;
    } else if (ctx->lexer->token.type == LEX_T_ERROR) {
        /* The lexer signaled an error.  Nothing at the expression level
         * accepts an error token, so we'll inevitably end up here with some
         * meaningless parse error.  Report the lexical error instead. */
        ctx->error = xstrdup(ctx->lexer->token.s);
        return true;
    } else {
        return false;
    }
}

static void OVS_PRINTF_FORMAT(2, 3)
expr_error(struct expr_context *ctx, const char *message, ...)
{
    if (expr_error_handle_common(ctx)) {
        return;
    }

    va_list args;
    va_start(args, message);
    ctx->error = xvasprintf(message, args);
    va_end(args);
}

static void OVS_PRINTF_FORMAT(2, 3)
expr_syntax_error(struct expr_context *ctx, const char *message, ...)
{
    if (expr_error_handle_common(ctx)) {
        return;
    }

    struct ds s;

    ds_init(&s);
    ds_put_cstr(&s, "Syntax error ");
    if (ctx->lexer->token.type == LEX_T_END) {
        ds_put_cstr(&s, "at end of input ");
    } else if (ctx->lexer->start) {
        ds_put_format(&s, "at `%.*s' ",
                      (int) (ctx->lexer->input - ctx->lexer->start),
                      ctx->lexer->start);
    }

    va_list args;
    va_start(args, message);
    ds_put_format_valist(&s, message, args);
    va_end(args);

    ctx->error = ds_steal_cstr(&s);
}

static struct expr *
make_cmp__(const struct expr_field *f, enum expr_relop r,
             const union expr_constant *c)
{
    struct expr *e = xzalloc(sizeof *e);
    e->type = EXPR_T_CMP;
    e->cmp.symbol = f->symbol;
    e->cmp.relop = r;
    if (f->symbol->width) {
        bitwise_copy(&c->value, sizeof c->value, 0,
                     &e->cmp.value, sizeof e->cmp.value, f->ofs,
                     f->n_bits);
        if (c->masked) {
            bitwise_copy(&c->mask, sizeof c->mask, 0,
                         &e->cmp.mask, sizeof e->cmp.mask, f->ofs,
                         f->n_bits);
        } else {
            bitwise_one(&e->cmp.mask, sizeof e->cmp.mask, f->ofs,
                        f->n_bits);
        }
    } else {
        e->cmp.string = xstrdup(c->string);
    }
    return e;
}

/* Returns the minimum reasonable width for integer constant 'c'. */
static int
expr_constant_width(const union expr_constant *c)
{
    if (c->masked) {
        return mf_subvalue_width(&c->mask);
    }

    switch (c->format) {
    case LEX_F_DECIMAL:
    case LEX_F_HEXADECIMAL:
        return mf_subvalue_width(&c->value);

    case LEX_F_IPV4:
        return 32;

    case LEX_F_IPV6:
        return 128;

    case LEX_F_ETHERNET:
        return 48;

    default:
        OVS_NOT_REACHED();
    }
}

static bool
type_check(struct expr_context *ctx, const struct expr_field *f,
           struct expr_constant_set *cs)
{
    if (cs->type != (f->symbol->width ? EXPR_C_INTEGER : EXPR_C_STRING)) {
        expr_error(ctx, "%s field %s is not compatible with %s constant.",
                   f->symbol->width ? "Integer" : "String",
                   f->symbol->name,
                   cs->type == EXPR_C_INTEGER ? "integer" : "string");
        return false;
    }

    if (f->symbol->width) {
        for (size_t i = 0; i < cs->n_values; i++) {
            int w = expr_constant_width(&cs->values[i]);
            if (w > f->symbol->width) {
                expr_error(ctx, "%d-bit constant is not compatible with "
                           "%d-bit field %s.",
                           w, f->symbol->width, f->symbol->name);
                return false;
            }
        }
    }

    return true;
}

static struct expr *
make_cmp(struct expr_context *ctx,
         const struct expr_field *f, enum expr_relop r,
         struct expr_constant_set *cs)
{
    struct expr *e = NULL;

    if (!type_check(ctx, f, cs)) {
        goto exit;
    }

    if (r != EXPR_R_EQ && r != EXPR_R_NE) {
        if (cs->in_curlies) {
            expr_error(ctx, "Only == and != operators may be used "
                       "with value sets.");
            goto exit;
        }
        if (f->symbol->level == EXPR_L_NOMINAL ||
            f->symbol->level == EXPR_L_BOOLEAN) {
            expr_error(ctx, "Only == and != operators may be used "
                       "with %s field %s.",
                       expr_level_to_string(f->symbol->level),
                       f->symbol->name);
            goto exit;
        }
        if (cs->values[0].masked) {
            expr_error(ctx, "Only == and != operators may be used with "
                       "masked constants.  Consider using subfields instead "
                       "(e.g. eth.src[0..15] > 0x1111 in place of "
                       "eth.src > 00:00:00:00:11:11/00:00:00:00:ff:ff).");
            goto exit;
        }
    }

    if (f->symbol->level == EXPR_L_NOMINAL) {
        if (f->symbol->expansion) {
            ovs_assert(f->symbol->width > 0);
            for (size_t i = 0; i < cs->n_values; i++) {
                const union mf_subvalue *value = &cs->values[i].value;
                bool positive = (value->integer & htonll(1)) != 0;
                positive ^= r == EXPR_R_NE;
                positive ^= ctx->not;
                if (!positive) {
                    const char *name = f->symbol->name;
                    expr_error(ctx, "Nominal predicate %s may only be tested "
                               "positively, e.g. `%s' or `%s == 1' but not "
                               "`!%s' or `%s == 0'.",
                               name, name, name, name, name);
                    goto exit;
                }
            }
        } else if (r != (ctx->not ? EXPR_R_NE : EXPR_R_EQ)) {
            expr_error(ctx, "Nominal field %s may only be tested for "
                       "equality (taking enclosing `!' operators into "
                       "account).", f->symbol->name);
            goto exit;
        }
    }

    e = make_cmp__(f, r, &cs->values[0]);
    for (size_t i = 1; i < cs->n_values; i++) {
        e = expr_combine(r == EXPR_R_EQ ? EXPR_T_OR : EXPR_T_AND,
                         e, make_cmp__(f, r, &cs->values[i]));
    }
exit:
    expr_constant_set_destroy(cs);
    return e;
}

static bool
expr_get_int(struct expr_context *ctx, int *value)
{
    bool ok = lexer_get_int(ctx->lexer, value);
    if (!ok) {
        expr_syntax_error(ctx, "expecting small integer.");
    }
    return ok;
}

static bool
parse_field(struct expr_context *ctx, struct expr_field *f)
{
    const struct expr_symbol *symbol;

    if (ctx->lexer->token.type != LEX_T_ID) {
        expr_syntax_error(ctx, "expecting field name.");
        return false;
    }

    symbol = shash_find_data(ctx->symtab, ctx->lexer->token.s);
    if (!symbol) {
        expr_syntax_error(ctx, "expecting field name.");
        return false;
    }
    lexer_get(ctx->lexer);

    f->symbol = symbol;
    if (lexer_match(ctx->lexer, LEX_T_LSQUARE)) {
        int low, high;

        if (!symbol->width) {
            expr_error(ctx, "Cannot select subfield of string field %s.",
                       symbol->name);
            return false;
        }

        if (!expr_get_int(ctx, &low)) {
            return false;
        }
        if (lexer_match(ctx->lexer, LEX_T_ELLIPSIS)) {
            if (!expr_get_int(ctx, &high)) {
                return false;
            }
        } else {
            high = low;
        }

        if (!lexer_match(ctx->lexer, LEX_T_RSQUARE)) {
            expr_syntax_error(ctx, "expecting `]'.");
            return false;
        }

        if (low > high) {
            expr_error(ctx, "Invalid bit range %d to %d.", low, high);
            return false;
        } else if (high >= symbol->width) {
            expr_error(ctx, "Cannot select bits %d to %d of %d-bit field %s.",
                       low, high, symbol->width, symbol->name);
            return false;
        } else if (symbol->level == EXPR_L_NOMINAL
                   && (low != 0 || high != symbol->width - 1)) {
            expr_error(ctx, "Cannot select subfield of nominal field %s.",
                       symbol->name);
            return false;
        }

        f->ofs = low;
        f->n_bits = high - low + 1;
    } else {
        f->ofs = 0;
        f->n_bits = symbol->width;
    }

    return true;
}

static bool
parse_relop(struct expr_context *ctx, enum expr_relop *relop)
{
    if (expr_relop_from_token(ctx->lexer->token.type, relop)) {
        lexer_get(ctx->lexer);
        return true;
    } else {
        expr_syntax_error(ctx, "expecting relational operator.");
        return false;
    }
}

static bool
assign_constant_set_type(struct expr_context *ctx,
                         struct expr_constant_set *cs,
                         enum expr_constant_type type)
{
    if (!cs->n_values || cs->type == type) {
        cs->type = type;
        return true;
    } else {
        expr_syntax_error(ctx, "expecting %s.",
                          cs->type == EXPR_C_INTEGER ? "integer" : "string");
        return false;
    }
}

static bool
parse_constant(struct expr_context *ctx, struct expr_constant_set *cs,
               size_t *allocated_values)
{
    if (cs->n_values >= *allocated_values) {
        cs->values = x2nrealloc(cs->values, allocated_values,
                                sizeof *cs->values);
    }

    if (ctx->lexer->token.type == LEX_T_STRING) {
        if (!assign_constant_set_type(ctx, cs, EXPR_C_STRING)) {
            return false;
        }
        cs->values[cs->n_values++].string = xstrdup(ctx->lexer->token.s);
        lexer_get(ctx->lexer);
        return true;
    } else if (ctx->lexer->token.type == LEX_T_INTEGER ||
               ctx->lexer->token.type == LEX_T_MASKED_INTEGER) {
        if (!assign_constant_set_type(ctx, cs, EXPR_C_INTEGER)) {
            return false;
        }

        union expr_constant *c = &cs->values[cs->n_values++];
        c->value = ctx->lexer->token.value;
        c->format = ctx->lexer->token.format;
        c->masked = ctx->lexer->token.type == LEX_T_MASKED_INTEGER;
        if (c->masked) {
            c->mask = ctx->lexer->token.mask;
        }
        lexer_get(ctx->lexer);
        return true;
    } else {
        expr_syntax_error(ctx, "expecting constant.");
        return false;
    }
}

/* Parses a single or {}-enclosed set of integer or string constants into 'cs',
 * which the caller need not have initialized.  Returns true on success, in
 * which case the caller owns 'cs', false on failure, in which case 'cs' is
 * indeterminate. */
static bool
parse_constant_set(struct expr_context *ctx, struct expr_constant_set *cs)
{
    size_t allocated_values = 0;
    bool ok;

    memset(cs, 0, sizeof *cs);
    if (lexer_match(ctx->lexer, LEX_T_LCURLY)) {
        ok = true;
        cs->in_curlies = true;
        do {
            if (!parse_constant(ctx, cs, &allocated_values)) {
                ok = false;
                break;
            }
            lexer_match(ctx->lexer, LEX_T_COMMA);
        } while (!lexer_match(ctx->lexer, LEX_T_RCURLY));
    } else {
        ok = parse_constant(ctx, cs, &allocated_values);
    }
    if (!ok) {
        expr_constant_set_destroy(cs);
    }
    return ok;
}

static void
expr_constant_set_destroy(struct expr_constant_set *cs)
{
    if (cs) {
        if (cs->type == EXPR_C_STRING) {
            for (size_t i = 0; i < cs->n_values; i++) {
                free(cs->values[i].string);
            }
        }
        free(cs->values);
    }
}

static struct expr *
expr_parse_primary(struct expr_context *ctx, bool *atomic)
{
    *atomic = false;
    if (lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        struct expr *e = expr_parse__(ctx);
        if (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
            expr_destroy(e);
            expr_syntax_error(ctx, "expecting `)'.");
            return NULL;
        }
        *atomic = true;
        return e;
    }

    if (ctx->lexer->token.type == LEX_T_ID) {
        struct expr_field f;
        enum expr_relop r;
        struct expr_constant_set c;

        if (!parse_field(ctx, &f)) {
            return NULL;
        }

        if (!expr_relop_from_token(ctx->lexer->token.type, &r)) {
            if (f.n_bits > 1 && !ctx->not) {
                expr_error(ctx, "Explicit `!= 0' is required for inequality "
                           "test of multibit field against 0.");
                return NULL;
            }

            *atomic = true;

            union expr_constant *cst = xzalloc(sizeof *cst);
            cst->format = LEX_F_HEXADECIMAL;
            cst->masked = false;

            c.type = EXPR_C_INTEGER;
            c.values = cst;
            c.n_values = 1;
            c.in_curlies = false;
            return make_cmp(ctx, &f, EXPR_R_NE, &c);
        } else if (parse_relop(ctx, &r) && parse_constant_set(ctx, &c)) {
            return make_cmp(ctx, &f, r, &c);
        } else {
            return NULL;
        }
    } else {
        struct expr_constant_set c1;
        if (!parse_constant_set(ctx, &c1)) {
            return NULL;
        }

        if (!expr_relop_from_token(ctx->lexer->token.type, NULL)
            && c1.n_values == 1
            && c1.type == EXPR_C_INTEGER
            && c1.values[0].format == LEX_F_DECIMAL
            && !c1.values[0].masked
            && !c1.in_curlies) {
            uint64_t x = ntohll(c1.values[0].value.integer);
            if (x <= 1) {
                *atomic = true;
                expr_constant_set_destroy(&c1);
                return expr_create_boolean(x);
            }
        }

        enum expr_relop r1;
        struct expr_field f;
        if (!parse_relop(ctx, &r1) || !parse_field(ctx, &f)) {
            expr_constant_set_destroy(&c1);
            return NULL;
        }

        if (!expr_relop_from_token(ctx->lexer->token.type, NULL)) {
            return make_cmp(ctx, &f, expr_relop_turn(r1), &c1);
        }

        enum expr_relop r2;
        struct expr_constant_set c2;
        if (!parse_relop(ctx, &r2) || !parse_constant_set(ctx, &c2)) {
            expr_constant_set_destroy(&c1);
            return NULL;
        } else {
            /* Reject "1 == field == 2", "1 < field > 2", and so on. */
            if (!(((r1 == EXPR_R_LT || r1 == EXPR_R_LE) &&
                   (r2 == EXPR_R_LT || r2 == EXPR_R_LE)) ||
                  ((r1 == EXPR_R_GT || r1 == EXPR_R_GE) &&
                   (r2 == EXPR_R_GT || r2 == EXPR_R_GE)))) {
                expr_error(ctx, "Range expressions must have the form "
                           "`x < field < y' or `x > field > y', with each "
                           "`<' optionally replaced by `<=' or `>' by `>=').");
                expr_constant_set_destroy(&c1);
                expr_constant_set_destroy(&c2);
                return NULL;
            }

            struct expr *e1 = make_cmp(ctx, &f, expr_relop_turn(r1), &c1);
            struct expr *e2 = make_cmp(ctx, &f, r2, &c2);
            if (ctx->error) {
                expr_destroy(e1);
                expr_destroy(e2);
                return NULL;
            }
            return expr_combine(EXPR_T_AND, e1, e2);
        }
    }
}

static struct expr *
expr_parse_not(struct expr_context *ctx)
{
    bool atomic;

    if (lexer_match(ctx->lexer, LEX_T_LOG_NOT)) {
        ctx->not = !ctx->not;
        struct expr *expr = expr_parse_primary(ctx, &atomic);
        ctx->not = !ctx->not;

        if (expr) {
            if (!atomic) {
                expr_error(ctx, "Missing parentheses around operand of !.");
                expr_destroy(expr);
                return NULL;
            }
            expr_not(expr);
        }
        return expr;
    } else {
        return expr_parse_primary(ctx, &atomic);
    }
}

struct expr *
expr_parse__(struct expr_context *ctx)
{
    struct expr *e = expr_parse_not(ctx);
    if (!e) {
        return NULL;
    }

    enum lex_type lex_type = ctx->lexer->token.type;
    if (lex_type == LEX_T_LOG_AND || lex_type == LEX_T_LOG_OR) {
        enum expr_type expr_type
            = lex_type == LEX_T_LOG_AND ? EXPR_T_AND : EXPR_T_OR;

        lexer_get(ctx->lexer);
        do {
            struct expr *e2 = expr_parse_not(ctx);
            if (!e2) {
                expr_destroy(e);
                return NULL;
            }
            e = expr_combine(expr_type, e, e2);
        } while (lexer_match(ctx->lexer, lex_type));
        if (ctx->lexer->token.type == LEX_T_LOG_AND
            || ctx->lexer->token.type == LEX_T_LOG_OR) {
            expr_destroy(e);
            expr_error(ctx,
                       "&& and || must be parenthesized when used together.");
            return NULL;
        }
    }
    return e;
}

/* Parses an expression using the symbols in 'symtab' from 'lexer'.  If
 * successful, returns the new expression and sets '*errorp' to NULL.  On
 * failure, returns NULL and sets '*errorp' to an explanatory error message.
 * The caller must eventually free the returned expression (with
 * expr_destroy()) or error (with free()). */
struct expr *
expr_parse(struct lexer *lexer, const struct shash *symtab, char **errorp)
{
    struct expr_context ctx;

    ctx.lexer = lexer;
    ctx.symtab = symtab;
    ctx.error = NULL;
    ctx.not = false;

    struct expr *e = expr_parse__(&ctx);
    *errorp = ctx.error;
    ovs_assert((ctx.error != NULL) != (e != NULL));
    return e;
}

/* Like expr_parse(), but the expression is taken from 's'. */
struct expr *
expr_parse_string(const char *s, const struct shash *symtab, char **errorp)
{
    struct lexer lexer;
    struct expr *expr;

    lexer_init(&lexer, s);
    lexer_get(&lexer);
    expr = expr_parse(&lexer, symtab, errorp);
    if (!*errorp && lexer.token.type != LEX_T_END) {
        *errorp = xstrdup("Extra tokens at end of input.");
        expr_destroy(expr);
        expr = NULL;
    }
    lexer_destroy(&lexer);

    return expr;
}

static struct expr_symbol *
add_symbol(struct shash *symtab, const char *name, int width,
           const char *prereqs, enum expr_level level,
           bool must_crossproduct)
{
    struct expr_symbol *symbol = xzalloc(sizeof *symbol);
    symbol->name = xstrdup(name);
    symbol->prereqs = prereqs && prereqs[0] ? xstrdup(prereqs) : NULL;
    symbol->width = width;
    symbol->level = level;
    symbol->must_crossproduct = must_crossproduct;
    shash_add_assert(symtab, symbol->name, symbol);
    return symbol;
}

/* Adds field 'id' to symbol table 'symtab' under the given 'name'.  Whenever
 * 'name' is referenced, expression annotation (see expr_annotate()) will
 * ensure that 'prereqs' are also true.  If 'must_crossproduct' is true, then
 * conversion to flows will never attempt to use the field as a conjunctive
 * match dimension (see "Crossproducting" in the large comment on struct
 * expr_symbol in expr.h for an example).
 *
 * A given field 'id' must only be used for a single symbol in a symbol table.
 * Use subfields to duplicate or subset a field (you can even make a subfield
 * include all the bits of the "parent" field if you like). */
struct expr_symbol *
expr_symtab_add_field(struct shash *symtab, const char *name,
                      enum mf_field_id id, const char *prereqs,
                      bool must_crossproduct)
{
    const struct mf_field *field = mf_from_id(id);
    struct expr_symbol *symbol;

    symbol = add_symbol(symtab, name, field->n_bits, prereqs,
                        (field->maskable == MFM_FULLY
                         ? EXPR_L_ORDINAL
                         : EXPR_L_NOMINAL),
                        must_crossproduct);
    symbol->field = field;
    return symbol;
}

static bool
parse_field_from_string(const char *s, const struct shash *symtab,
                        struct expr_field *field, char **errorp)
{
    struct lexer lexer;
    lexer_init(&lexer, s);
    lexer_get(&lexer);

    struct expr_context ctx;
    ctx.lexer = &lexer;
    ctx.symtab = symtab;
    ctx.error = NULL;
    ctx.not = false;

    bool ok = parse_field(&ctx, field);
    if (!ok) {
        *errorp = ctx.error;
    } else if (lexer.token.type != LEX_T_END) {
        *errorp = xstrdup("Extra tokens at end of input.");
        ok = false;
    }

    lexer_destroy(&lexer);

    return ok;
}

/* Adds 'name' as a subfield of a larger field in 'symtab'.  Whenever
 * 'name' is referenced, expression annotation (see expr_annotate()) will
 * ensure that 'prereqs' are also true.
 *
 * 'subfield' must describe the subfield as a string, e.g. "vlan.tci[0..11]"
 * for the low 12 bits of a larger field named "vlan.tci". */
struct expr_symbol *
expr_symtab_add_subfield(struct shash *symtab, const char *name,
                         const char *prereqs, const char *subfield)
{
    struct expr_symbol *symbol;
    struct expr_field f;
    char *error;

    if (!parse_field_from_string(subfield, symtab, &f, &error)) {
        VLOG_WARN("%s: error parsing %s subfield (%s)", subfield, name, error);
        free(error);
        return NULL;
    }

    enum expr_level level = f.symbol->level;
    if (level != EXPR_L_ORDINAL) {
        VLOG_WARN("can't define %s as subfield of %s field %s",
                  name, expr_level_to_string(level), f.symbol->name);
    }

    symbol = add_symbol(symtab, name, f.n_bits, prereqs, level, false);
    symbol->expansion = xstrdup(subfield);
    return symbol;
}

/* Adds a string-valued symbol named 'name' to 'symtab' with the specified
 * 'prereqs'. */
struct expr_symbol *
expr_symtab_add_string(struct shash *symtab, const char *name,
                       enum mf_field_id id, const char *prereqs)
{
    const struct mf_field *field = mf_from_id(id);
    struct expr_symbol *symbol;

    symbol = add_symbol(symtab, name, 0, prereqs, EXPR_L_NOMINAL, false);
    symbol->field = field;
    return symbol;
}

static enum expr_level
expr_get_level(const struct expr *expr)
{
    const struct expr *sub;
    enum expr_level level = EXPR_L_ORDINAL;

    switch (expr->type) {
    case EXPR_T_CMP:
        return (expr->cmp.symbol->level == EXPR_L_NOMINAL
                ? EXPR_L_NOMINAL
                : EXPR_L_BOOLEAN);

    case EXPR_T_AND:
    case EXPR_T_OR:
        LIST_FOR_EACH (sub, node, &expr->andor) {
            enum expr_level sub_level = expr_get_level(sub);
            level = MIN(level, sub_level);
        }
        return level;

    case EXPR_T_BOOLEAN:
        return EXPR_L_BOOLEAN;

    default:
        OVS_NOT_REACHED();
    }
}

static enum expr_level
expr_parse_level(const char *s, const struct shash *symtab, char **errorp)
{
    struct expr *expr = expr_parse_string(s, symtab, errorp);
    enum expr_level level = expr ? expr_get_level(expr) : EXPR_L_NOMINAL;
    expr_destroy(expr);
    return level;
}

/* Adds a predicate symbol, whose value is the given Boolean 'expression',
 * named 'name' to 'symtab'.  For example, "ip4 && ip4.proto == 6" might be an
 * appropriate predicate named "tcp4". */
struct expr_symbol *
expr_symtab_add_predicate(struct shash *symtab, const char *name,
                          const char *expansion)
{
    struct expr_symbol *symbol;
    enum expr_level level;
    char *error;

    level = expr_parse_level(expansion, symtab, &error);
    if (error) {
        VLOG_WARN("%s: error parsing %s expansion (%s)",
                  expansion, name, error);
        free(error);
        return NULL;
    }

    symbol = add_symbol(symtab, name, 1, NULL, level, false);
    symbol->expansion = xstrdup(expansion);
    return symbol;
}

/* Destroys 'symtab' and all of its symbols. */
void
expr_symtab_destroy(struct shash *symtab)
{
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, symtab) {
        struct expr_symbol *symbol = node->data;

        shash_delete(symtab, node);
        free(symbol->name);
        free(symbol->prereqs);
        free(symbol->expansion);
        free(symbol);
    }
}

/* Cloning. */

static struct expr *
expr_clone_cmp(struct expr *expr)
{
    struct expr *new = xmemdup(expr, sizeof *expr);
    if (!new->cmp.symbol->width) {
        new->cmp.string = xstrdup(new->cmp.string);
    }
    return new;
}

static struct expr *
expr_clone_andor(struct expr *expr)
{
    struct expr *new = expr_create_andor(expr->type);
    struct expr *sub;

    LIST_FOR_EACH (sub, node, &expr->andor) {
        struct expr *new_sub = expr_clone(sub);
        ovs_list_push_back(&new->andor, &new_sub->node);
    }
    return new;
}

/* Returns a clone of 'expr'.  This is a "deep copy": neither the returned
 * expression nor any of its substructure will be shared with 'expr'. */
struct expr *
expr_clone(struct expr *expr)
{
    switch (expr->type) {
    case EXPR_T_CMP:
        return expr_clone_cmp(expr);

    case EXPR_T_AND:
    case EXPR_T_OR:
        return expr_clone_andor(expr);

    case EXPR_T_BOOLEAN:
        return expr_create_boolean(expr->boolean);
    }
    OVS_NOT_REACHED();
}

/* Destroys 'expr' and all of the sub-expressions it references. */
void
expr_destroy(struct expr *expr)
{
    if (!expr) {
        return;
    }

    struct expr *sub, *next;

    switch (expr->type) {
    case EXPR_T_CMP:
        if (!expr->cmp.symbol->width) {
            free(expr->cmp.string);
        }
        break;

    case EXPR_T_AND:
    case EXPR_T_OR:
        LIST_FOR_EACH_SAFE (sub, next, node, &expr->andor) {
            ovs_list_remove(&sub->node);
            expr_destroy(sub);
        }
        break;

    case EXPR_T_BOOLEAN:
        break;
    }
    free(expr);
}

/* Annotation. */

/* An element in a linked list of symbols.
 *
 * Used to detect when a symbol is being expanded recursively, to allow
 * flagging an error. */
struct annotation_nesting {
    struct ovs_list node;
    const struct expr_symbol *symbol;
};

struct expr *expr_annotate__(struct expr *, const struct shash *symtab,
                             struct ovs_list *nesting, char **errorp);

static struct expr *
parse_and_annotate(const char *s, const struct shash *symtab,
                   struct ovs_list *nesting, char **errorp)
{
    char *error;
    struct expr *expr;

    expr = expr_parse_string(s, symtab, &error);
    if (expr) {
        expr = expr_annotate__(expr, symtab, nesting, &error);
    }
    if (expr) {
        *errorp = NULL;
    } else {
        *errorp = xasprintf("Error parsing expression `%s' encountered as "
                            "prerequisite or predicate of initial expression: "
                            "%s", s, error);
        free(error);
    }
    return expr;
}

static struct expr *
expr_annotate_cmp(struct expr *expr, const struct shash *symtab,
                  struct ovs_list *nesting, char **errorp)
{
    const struct expr_symbol *symbol = expr->cmp.symbol;
    const struct annotation_nesting *iter;
    LIST_FOR_EACH (iter, node, nesting) {
        if (iter->symbol == symbol) {
            *errorp = xasprintf("Recursive expansion of symbol `%s'.",
                                symbol->name);
            expr_destroy(expr);
            return NULL;
        }
    }

    struct annotation_nesting an;
    an.symbol = symbol;
    ovs_list_push_back(nesting, &an.node);

    struct expr *prereqs = NULL;
    if (symbol->prereqs) {
        prereqs = parse_and_annotate(symbol->prereqs, symtab, nesting, errorp);
        if (!prereqs) {
            goto error;
        }
    }

    if (symbol->expansion) {
        if (symbol->level == EXPR_L_ORDINAL) {
            struct expr_field field;

            if (!parse_field_from_string(symbol->expansion, symtab,
                                         &field, errorp)) {
                goto error;
            }

            expr->cmp.symbol = field.symbol;
            mf_subvalue_shift(&expr->cmp.value, field.ofs);
            mf_subvalue_shift(&expr->cmp.mask, field.ofs);
        } else {
            struct expr *expansion;

            expansion = parse_and_annotate(symbol->expansion, symtab,
                                           nesting, errorp);
            if (!expansion) {
                goto error;
            }

            bool positive = (expr->cmp.value.integer & htonll(1)) != 0;
            positive ^= expr->cmp.relop == EXPR_R_NE;
            if (!positive) {
                expr_not(expansion);
            }

            expr_destroy(expr);
            expr = expansion;
        }
    }

    ovs_list_remove(&an.node);
    return prereqs ? expr_combine(EXPR_T_AND, expr, prereqs) : expr;

error:
    expr_destroy(expr);
    expr_destroy(prereqs);
    ovs_list_remove(&an.node);
    return NULL;
}

struct expr *
expr_annotate__(struct expr *expr, const struct shash *symtab,
                struct ovs_list *nesting, char **errorp)
{
    switch (expr->type) {
    case EXPR_T_CMP:
        return expr_annotate_cmp(expr, symtab, nesting, errorp);

    case EXPR_T_AND:
    case EXPR_T_OR: {
        struct expr *sub, *next;

        LIST_FOR_EACH_SAFE (sub, next, node, &expr->andor) {
            ovs_list_remove(&sub->node);
            struct expr *new_sub = expr_annotate__(sub, symtab,
                                                   nesting, errorp);
            if (!new_sub) {
                expr_destroy(expr);
                return NULL;
            }
            expr_insert_andor(expr, next, new_sub);
        }
        *errorp = NULL;
        return expr;
    }

    case EXPR_T_BOOLEAN:
        *errorp = NULL;
        return expr;

    default:
        OVS_NOT_REACHED();
    }
}

/* "Annotates" 'expr', which does the following:
 *
 *     - Applies prerequisites, by locating each comparison operator whose
 *       field has a prerequisite and adding a logical AND against those
 *       prerequisites.
 *
 *     - Expands references to subfield symbols, by replacing them by
 *       references to their underlying field symbols (suitably shifted).
 *
 *     - Expands references to predicate symbols, by replacing them by the
 *       expressions that they expand to.
 *
 * In each case, annotation occurs recursively as necessary.
 *
 * On failure, returns NULL and sets '*errorp' to an explanatory error
 * message, which the caller must free. */
struct expr *
expr_annotate(struct expr *expr, const struct shash *symtab, char **errorp)
{
    struct ovs_list nesting = OVS_LIST_INITIALIZER(&nesting);
    return expr_annotate__(expr, symtab, &nesting, errorp);
}

static struct expr *
expr_simplify_ne(struct expr *expr)
{
    struct expr *new = NULL;
    const union mf_subvalue *value = &expr->cmp.value;
    const union mf_subvalue *mask = &expr->cmp.mask;
    int w = expr->cmp.symbol->width;
    int i;

    for (i = 0; (i = bitwise_scan(mask, sizeof *mask, true, i, w)) < w; i++) {
        struct expr *e;

        e = xzalloc(sizeof *e);
        e->type = EXPR_T_CMP;
        e->cmp.symbol = expr->cmp.symbol;
        e->cmp.relop = EXPR_R_EQ;
        bitwise_put_bit(&e->cmp.value, sizeof e->cmp.value, i,
                        !bitwise_get_bit(value, sizeof *value, i));
        bitwise_put1(&e->cmp.mask, sizeof e->cmp.mask, i);

        new = expr_combine(EXPR_T_OR, new, e);
    }
    ovs_assert(new);

    expr_destroy(expr);

    return new;
}

static struct expr *
expr_simplify_relational(struct expr *expr)
{
    const union mf_subvalue *value = &expr->cmp.value;
    int start, n_bits, end;

    find_bitwise_range(&expr->cmp.mask, expr->cmp.symbol->width,
                       &start, &n_bits);
    ovs_assert(n_bits > 0);
    end = start + n_bits;

    struct expr *new;
    if (expr->cmp.relop == EXPR_R_LE || expr->cmp.relop == EXPR_R_GE) {
        new = xmemdup(expr, sizeof *expr);
        new->cmp.relop = EXPR_R_EQ;
    } else {
        new = NULL;
    }

    bool b = expr->cmp.relop == EXPR_R_LT || expr->cmp.relop == EXPR_R_LE;
    for (int z = bitwise_scan(value, sizeof *value, b, start, end);
         z < end;
         z = bitwise_scan(value, sizeof *value, b, z + 1, end)) {
        struct expr *e;

        e = xmemdup(expr, sizeof *expr);
        e->cmp.relop = EXPR_R_EQ;
        bitwise_toggle_bit(&e->cmp.value, sizeof e->cmp.value, z);
        bitwise_zero(&e->cmp.value, sizeof e->cmp.value, start, z - start);
        bitwise_zero(&e->cmp.mask, sizeof e->cmp.mask, start, z - start);
        new = expr_combine(EXPR_T_OR, new, e);
    }
    expr_destroy(expr);
    return new ? new : expr_create_boolean(false);
}

/* Takes ownership of 'expr' and returns an equivalent expression whose
 * EXPR_T_CMP nodes use only tests for equality (EXPR_R_EQ). */
struct expr *
expr_simplify(struct expr *expr)
{
    struct expr *sub, *next;

    switch (expr->type) {
    case EXPR_T_CMP:
        return (expr->cmp.relop == EXPR_R_EQ || !expr->cmp.symbol->width ? expr
                : expr->cmp.relop == EXPR_R_NE ? expr_simplify_ne(expr)
                : expr_simplify_relational(expr));

    case EXPR_T_AND:
    case EXPR_T_OR:
        LIST_FOR_EACH_SAFE (sub, next, node, &expr->andor) {
            ovs_list_remove(&sub->node);
            expr_insert_andor(expr, next, expr_simplify(sub));
        }
        return expr_fix(expr);

    case EXPR_T_BOOLEAN:
        return expr;
    }
    OVS_NOT_REACHED();
}

static const struct expr_symbol *
expr_is_cmp(const struct expr *expr)
{
    switch (expr->type) {
    case EXPR_T_CMP:
        return expr->cmp.symbol;

    case EXPR_T_AND:
    case EXPR_T_OR: {
        const struct expr_symbol *prev = NULL;
        struct expr *sub;

        LIST_FOR_EACH (sub, node, &expr->andor) {
            const struct expr_symbol *symbol = expr_is_cmp(sub);
            if (!symbol || (prev && symbol != prev)) {
                return NULL;
            }
            prev = symbol;
        }
        return prev;
    }

    case EXPR_T_BOOLEAN:
        return NULL;

    default:
        OVS_NOT_REACHED();
    }
}

struct expr_sort {
    struct expr *expr;
    const struct expr_symbol *relop;
    enum expr_type type;
};

static int
compare_expr_sort(const void *a_, const void *b_)
{
    const struct expr_sort *a = a_;
    const struct expr_sort *b = b_;

    if (a->type != b->type) {
        return a->type < b->type ? -1 : 1;
    } else if (a->relop) {
        int cmp = strcmp(a->relop->name, b->relop->name);
        if (cmp) {
            return cmp;
        }

        enum expr_type a_type = a->expr->type;
        enum expr_type b_type = a->expr->type;
        return a_type < b_type ? -1 : a_type > b_type;
    } else if (a->type == EXPR_T_AND || a->type == EXPR_T_OR) {
        size_t a_len = ovs_list_size(&a->expr->andor);
        size_t b_len = ovs_list_size(&b->expr->andor);
        return a_len < b_len ? -1 : a_len > b_len;
    } else {
        return 0;
    }
}

static struct expr *crush_cmps(struct expr *, const struct expr_symbol *);

static bool
disjunction_matches_string(const struct expr *or, const char *s)
{
    const struct expr *sub;

    LIST_FOR_EACH (sub, node, &or->andor) {
        if (!strcmp(sub->cmp.string, s)) {
            return true;
        }
    }

    return false;
}

/* Implementation of crush_cmps() for expr->type == EXPR_T_AND and a
 * string-typed 'symbol'. */
static struct expr *
crush_and_string(struct expr *expr, const struct expr_symbol *symbol)
{
    ovs_assert(!ovs_list_is_short(&expr->andor));

    struct expr *singleton = NULL;

    /* First crush each subexpression into either a single EXPR_T_CMP or an
     * EXPR_T_OR with EXPR_T_CMP subexpressions. */
    struct expr *sub, *next = NULL;
    LIST_FOR_EACH_SAFE (sub, next, node, &expr->andor) {
        ovs_list_remove(&sub->node);
        struct expr *new = crush_cmps(sub, symbol);
        switch (new->type) {
        case EXPR_T_CMP:
            if (!singleton) {
                ovs_list_insert(&next->node, &new->node);
                singleton = new;
            } else {
                bool match = !strcmp(new->cmp.string, singleton->cmp.string);
                expr_destroy(new);
                if (!match) {
                    expr_destroy(expr);
                    return expr_create_boolean(false);
                }
            }
            break;
        case EXPR_T_AND:
            OVS_NOT_REACHED();
        case EXPR_T_OR:
            ovs_list_insert(&next->node, &new->node);
            break;
        case EXPR_T_BOOLEAN:
            if (!new->boolean) {
                expr_destroy(expr);
                return new;
            }
            free(new);
            break;
        }
    }

    /* If we have a singleton, then the result is either the singleton itself
     * (if the ORs allow the singleton) or false. */
    if (singleton) {
        LIST_FOR_EACH (sub, node, &expr->andor) {
            if (sub->type == EXPR_T_OR
                && !disjunction_matches_string(sub, singleton->cmp.string)) {
                expr_destroy(expr);
                return expr_create_boolean(false);
            }
        }
        ovs_list_remove(&singleton->node);
        expr_destroy(expr);
        return singleton;
    }

    /* Otherwise the result is the intersection of all of the ORs. */
    struct sset result = SSET_INITIALIZER(&result);
    LIST_FOR_EACH_SAFE (sub, next, node, &expr->andor) {
        struct sset strings = SSET_INITIALIZER(&strings);
        const struct expr *s;
        LIST_FOR_EACH (s, node, &sub->andor) {
            sset_add(&strings, s->cmp.string);
        }
        if (sset_is_empty(&result)) {
            sset_swap(&result, &strings);
        } else {
            sset_intersect(&result, &strings);
        }
        sset_destroy(&strings);

        if (sset_is_empty(&result)) {
            expr_destroy(expr);
            sset_destroy(&result);
            return expr_create_boolean(false);
        }
    }

    expr_destroy(expr);
    expr = expr_create_andor(EXPR_T_OR);

    const char *string;
    SSET_FOR_EACH (string, &result) {
        sub = xmalloc(sizeof *sub);
        sub->type = EXPR_T_CMP;
        sub->cmp.symbol = symbol;
        sub->cmp.string = xstrdup(string);
        ovs_list_push_back(&expr->andor, &sub->node);
    }
    sset_destroy(&result);
    return expr_fix(expr);
}

/* Implementation of crush_cmps() for expr->type == EXPR_T_AND and a
 * numeric-typed 'symbol'. */
static struct expr *
crush_and_numeric(struct expr *expr, const struct expr_symbol *symbol)
{
    ovs_assert(!ovs_list_is_short(&expr->andor));

    union mf_subvalue value, mask;
    memset(&value, 0, sizeof value);
    memset(&mask, 0, sizeof mask);

    struct expr *sub, *next = NULL;
    LIST_FOR_EACH_SAFE (sub, next, node, &expr->andor) {
        ovs_list_remove(&sub->node);
        struct expr *new = crush_cmps(sub, symbol);
        switch (new->type) {
        case EXPR_T_CMP:
            if (!mf_subvalue_intersect(&value, &mask,
                                       &new->cmp.value, &new->cmp.mask,
                                       &value, &mask)) {
                expr_destroy(new);
                expr_destroy(expr);
                return expr_create_boolean(false);
            }
            expr_destroy(new);
            break;
        case EXPR_T_AND:
            OVS_NOT_REACHED();
        case EXPR_T_OR:
            ovs_list_insert(&next->node, &new->node);
            break;
        case EXPR_T_BOOLEAN:
            if (!new->boolean) {
                expr_destroy(expr);
                return new;
            }
            expr_destroy(new);
            break;
        }
    }
    if (ovs_list_is_empty(&expr->andor)) {
        if (is_all_zeros(&mask, sizeof mask)) {
            expr_destroy(expr);
            return expr_create_boolean(true);
        } else {
            struct expr *cmp;
            cmp = xmalloc(sizeof *cmp);
            cmp->type = EXPR_T_CMP;
            cmp->cmp.symbol = symbol;
            cmp->cmp.relop = EXPR_R_EQ;
            cmp->cmp.value = value;
            cmp->cmp.mask = mask;
            expr_destroy(expr);
            return cmp;
        }
    } else if (ovs_list_is_short(&expr->andor)) {
        /* Transform "a && (b || c || d)" into "ab || ac || ad" where "ab" is
         * computed as "a && b", etc. */
        struct expr *disjuncts = expr_from_node(ovs_list_pop_front(&expr->andor));
        struct expr *or;

        or = xmalloc(sizeof *or);
        or->type = EXPR_T_OR;
        ovs_list_init(&or->andor);

        ovs_assert(disjuncts->type == EXPR_T_OR);
        LIST_FOR_EACH_SAFE (sub, next, node, &disjuncts->andor) {
            ovs_assert(sub->type == EXPR_T_CMP);
            ovs_list_remove(&sub->node);
            if (mf_subvalue_intersect(&value, &mask,
                                      &sub->cmp.value, &sub->cmp.mask,
                                      &sub->cmp.value, &sub->cmp.mask)) {
                ovs_list_push_back(&or->andor, &sub->node);
            } else {
                expr_destroy(sub);
            }
        }
        free(disjuncts);
        free(expr);
        if (ovs_list_is_empty(&or->andor)) {
            free(or);
            return expr_create_boolean(false);
        } else if (ovs_list_is_short(&or->andor)) {
            struct expr *cmp = expr_from_node(ovs_list_pop_front(&or->andor));
            free(or);
            return cmp;
        } else {
            return or;
        }
    } else {
        /* Transform "x && (a0 || a1) && (b0 || b1) && ..." into
         *           "(xa0b0 || xa0b1 || xa1b0 || xa1b1) && ...". */
        struct expr *as = expr_from_node(ovs_list_pop_front(&expr->andor));
        struct expr *bs = expr_from_node(ovs_list_pop_front(&expr->andor));
        struct expr *new = NULL;
        struct expr *or;

        or = xmalloc(sizeof *or);
        or->type = EXPR_T_OR;
        ovs_list_init(&or->andor);

        struct expr *a;
        LIST_FOR_EACH (a, node, &as->andor) {
            union mf_subvalue a_value, a_mask;

            ovs_assert(a->type == EXPR_T_CMP);
            if (!mf_subvalue_intersect(&value, &mask,
                                       &a->cmp.value, &a->cmp.mask,
                                       &a_value, &a_mask)) {
                continue;
            }

            struct expr *b;
            LIST_FOR_EACH (b, node, &bs->andor) {
                ovs_assert(b->type == EXPR_T_CMP);
                if (!new) {
                    new = xmalloc(sizeof *new);
                    new->type = EXPR_T_CMP;
                    new->cmp.symbol = symbol;
                    new->cmp.relop = EXPR_R_EQ;
                }
                if (mf_subvalue_intersect(&a_value, &a_mask,
                                          &b->cmp.value, &b->cmp.mask,
                                          &new->cmp.value, &new->cmp.mask)) {
                    ovs_list_push_back(&or->andor, &new->node);
                    new = NULL;
                }
            }
        }
        expr_destroy(as);
        expr_destroy(bs);
        free(new);

        if (ovs_list_is_empty(&or->andor)) {
            expr_destroy(expr);
            free(or);
            return expr_create_boolean(false);
        } else if (ovs_list_is_short(&or->andor)) {
            struct expr *cmp = expr_from_node(ovs_list_pop_front(&or->andor));
            free(or);
            if (ovs_list_is_empty(&expr->andor)) {
                expr_destroy(expr);
                return crush_cmps(cmp, symbol);
            } else {
                return crush_cmps(expr_combine(EXPR_T_AND, cmp, expr), symbol);
            }
        } else if (!ovs_list_is_empty(&expr->andor)) {
            struct expr *e = expr_combine(EXPR_T_AND, or, expr);
            ovs_assert(!ovs_list_is_short(&e->andor));
            return crush_cmps(e, symbol);
        } else {
            expr_destroy(expr);
            return crush_cmps(or, symbol);
        }
    }
}

static int
compare_cmps_3way(const struct expr *a, const struct expr *b)
{
    ovs_assert(a->cmp.symbol == b->cmp.symbol);
    if (!a->cmp.symbol->width) {
        return strcmp(a->cmp.string, b->cmp.string);
    } else {
        int d = memcmp(&a->cmp.value, &b->cmp.value, sizeof a->cmp.value);
        if (!d) {
            d = memcmp(&a->cmp.mask, &b->cmp.mask, sizeof a->cmp.mask);
        }
        return d;
    }
}

static int
compare_cmps_cb(const void *a_, const void *b_)
{
    const struct expr *const *ap = a_;
    const struct expr *const *bp = b_;
    const struct expr *a = *ap;
    const struct expr *b = *bp;
    return compare_cmps_3way(a, b);
}

/* Implementation of crush_cmps() for expr->type == EXPR_T_OR. */
static struct expr *
crush_or(struct expr *expr, const struct expr_symbol *symbol)
{
    struct expr *sub, *next = NULL;

    /* First, crush all the subexpressions.  That might eliminate the
     * OR-expression entirely; if so, return the result.  Otherwise, 'expr'
     * is now a disjunction of cmps over the same symbol. */
    LIST_FOR_EACH_SAFE (sub, next, node, &expr->andor) {
        ovs_list_remove(&sub->node);
        expr_insert_andor(expr, next, crush_cmps(sub, symbol));
    }
    expr = expr_fix(expr);
    if (expr->type != EXPR_T_OR) {
        return expr;
    }

    /* Sort subexpressions by value and mask, to bring together duplicates. */
    size_t n = ovs_list_size(&expr->andor);
    struct expr **subs = xmalloc(n * sizeof *subs);

    size_t i = 0;
    LIST_FOR_EACH (sub, node, &expr->andor) {
        subs[i++] = sub;
    }
    ovs_assert(i == n);

    qsort(subs, n, sizeof *subs, compare_cmps_cb);

    /* Eliminate duplicates. */
    ovs_list_init(&expr->andor);
    ovs_list_push_back(&expr->andor, &subs[0]->node);
    for (i = 1; i < n; i++) {
        struct expr *a = expr_from_node(ovs_list_back(&expr->andor));
        struct expr *b = subs[i];
        if (compare_cmps_3way(a, b)) {
            ovs_list_push_back(&expr->andor, &b->node);
        } else {
            expr_destroy(b);
        }
    }
    free(subs);
    return expr_fix(expr);
}

/* Takes ownership of 'expr', which must be a cmp in the sense determined by
 * 'expr_is_cmp(expr)', where 'symbol' is the symbol returned by that function.
 * Returns an equivalent expression owned by the caller that is a single
 * EXPR_T_CMP or a disjunction of them or a EXPR_T_BOOLEAN. */
static struct expr *
crush_cmps(struct expr *expr, const struct expr_symbol *symbol)
{
    switch (expr->type) {
    case EXPR_T_OR:
        return crush_or(expr, symbol);

    case EXPR_T_AND:
        return (symbol->width
                ? crush_and_numeric(expr, symbol)
                : crush_and_string(expr, symbol));

    case EXPR_T_CMP:
        return expr;

    case EXPR_T_BOOLEAN:
        return expr;

    default:
        OVS_NOT_REACHED();
    }
}

static struct expr *
expr_sort(struct expr *expr)
{
    size_t n = ovs_list_size(&expr->andor);
    struct expr_sort *subs = xmalloc(n * sizeof *subs);
    struct expr *sub;
    size_t i;

    i = 0;
    LIST_FOR_EACH (sub, node, &expr->andor) {
        subs[i].expr = sub;
        subs[i].relop = expr_is_cmp(sub);
        subs[i].type = subs[i].relop ? EXPR_T_CMP : sub->type;
        i++;
    }
    ovs_assert(i == n);

    qsort(subs, n, sizeof *subs, compare_expr_sort);

    ovs_list_init(&expr->andor);
    for (int i = 0; i < n; ) {
        if (subs[i].relop) {
            int j;
            for (j = i + 1; j < n; j++) {
                if (subs[i].relop != subs[j].relop) {
                    break;
                }
            }

            struct expr *crushed;
            if (j == i + 1) {
                crushed = crush_cmps(subs[i].expr, subs[i].relop);
            } else {
                struct expr *combined = subs[i].expr;
                for (int k = i + 1; k < j; k++) {
                    combined = expr_combine(EXPR_T_AND, combined,
                                            subs[k].expr);
                }
                ovs_assert(!ovs_list_is_short(&combined->andor));
                crushed = crush_cmps(combined, subs[i].relop);
            }
            if (crushed->type == EXPR_T_BOOLEAN) {
                if (!crushed->boolean) {
                    for (int k = j; k < n; k++) {
                        expr_destroy(subs[k].expr);
                    }
                    expr_destroy(expr);
                    expr = crushed;
                    break;
                } else {
                    free(crushed);
                }
            } else {
                expr = expr_combine(EXPR_T_AND, expr, crushed);
            }
            i = j;
        } else {
            expr = expr_combine(EXPR_T_AND, expr, subs[i++].expr);
        }
    }
    free(subs);

    return expr;
}

static struct expr *expr_normalize_or(struct expr *expr);

/* Returns 'expr', which is an AND, reduced to OR(AND(clause)) where
 * a clause is a cmp or a disjunction of cmps on a single field. */
static struct expr *
expr_normalize_and(struct expr *expr)
{
    ovs_assert(expr->type == EXPR_T_AND);

    expr = expr_sort(expr);
    if (expr->type != EXPR_T_AND) {
        ovs_assert(expr->type == EXPR_T_BOOLEAN);
        return expr;
    }

    struct expr *a, *b;
    LIST_FOR_EACH_SAFE (a, b, node, &expr->andor) {
        if (&b->node == &expr->andor
            || a->type != EXPR_T_CMP || b->type != EXPR_T_CMP
            || a->cmp.symbol != b->cmp.symbol) {
            continue;
        } else if (a->cmp.symbol->width
                   ? mf_subvalue_intersect(&a->cmp.value, &a->cmp.mask,
                                           &b->cmp.value, &b->cmp.mask,
                                           &b->cmp.value, &b->cmp.mask)
                   : !strcmp(a->cmp.string, b->cmp.string)) {
            ovs_list_remove(&a->node);
            expr_destroy(a);
        } else {
            expr_destroy(expr);
            return expr_create_boolean(false);
        }
    }
    if (ovs_list_is_short(&expr->andor)) {
        struct expr *sub = expr_from_node(ovs_list_front(&expr->andor));
        free(expr);
        return sub;
    }

    struct expr *sub;
    LIST_FOR_EACH (sub, node, &expr->andor) {
        if (sub->type == EXPR_T_CMP) {
            continue;
        }

        ovs_assert(sub->type == EXPR_T_OR);
        const struct expr_symbol *symbol = expr_is_cmp(sub);
        if (!symbol || symbol->must_crossproduct) {
            struct expr *or = expr_create_andor(EXPR_T_OR);
            struct expr *k;

            LIST_FOR_EACH (k, node, &sub->andor) {
                struct expr *and = expr_create_andor(EXPR_T_AND);
                struct expr *m;

                LIST_FOR_EACH (m, node, &expr->andor) {
                    struct expr *term = m == sub ? k : m;
                    if (term->type == EXPR_T_AND) {
                        struct expr *p;

                        LIST_FOR_EACH (p, node, &term->andor) {
                            struct expr *new = expr_clone(p);
                            ovs_list_push_back(&and->andor, &new->node);
                        }
                    } else {
                        struct expr *new = expr_clone(term);
                        ovs_list_push_back(&and->andor, &new->node);
                    }
                }
                ovs_list_push_back(&or->andor, &and->node);
            }
            expr_destroy(expr);
            return expr_normalize_or(or);
        }
    }
    return expr;
}

static struct expr *
expr_normalize_or(struct expr *expr)
{
    struct expr *sub, *next;

    LIST_FOR_EACH_SAFE (sub, next, node, &expr->andor) {
        if (sub->type == EXPR_T_AND) {
            ovs_list_remove(&sub->node);

            struct expr *new = expr_normalize_and(sub);
            if (new->type == EXPR_T_BOOLEAN) {
                if (new->boolean) {
                    expr_destroy(expr);
                    return new;
                }
                free(new);
            } else {
                expr_insert_andor(expr, next, new);
            }
        } else {
            ovs_assert(sub->type == EXPR_T_CMP);
        }
    }
    if (ovs_list_is_empty(&expr->andor)) {
        free(expr);
        return expr_create_boolean(false);
    }
    if (ovs_list_is_short(&expr->andor)) {
        struct expr *sub = expr_from_node(ovs_list_pop_front(&expr->andor));
        free(expr);
        return sub;
    }

    return expr;
}

/* Takes ownership of 'expr', which is either a constant "true" or "false" or
 * an expression in terms of only relationals, AND, and OR.  Returns either a
 * constant "true" or "false" or 'expr' reduced to OR(AND(clause)) where a
 * clause is a cmp or a disjunction of cmps on a single field.  This form is
 * significant because it is a form that can be directly converted to OpenFlow
 * flows with the Open vSwitch "conjunctive match" extension.
 *
 * 'expr' must already have been simplified, with expr_simplify(). */
struct expr *
expr_normalize(struct expr *expr)
{
    switch (expr->type) {
    case EXPR_T_CMP:
        return expr;

    case EXPR_T_AND:
        return expr_normalize_and(expr);

    case EXPR_T_OR:
        return expr_normalize_or(expr);

    case EXPR_T_BOOLEAN:
        return expr;
    }
    OVS_NOT_REACHED();
}

/* Creates, initializes, and returns a new 'struct expr_match'.  If 'm' is
 * nonnull then it is copied into the new expr_match, otherwise the new
 * expr_match's 'match' member is initialized to a catch-all match for the
 * caller to refine in-place.
 *
 * If 'conj_id' is nonzero, adds one conjunction based on 'conj_id', 'clause',
 * and 'n_clauses' to the returned 'struct expr_match', otherwise the
 * expr_match will not have any conjunctions.
 *
 * The caller should use expr_match_add() to add the expr_match to a hash table
 * after it is finalized. */
static struct expr_match *
expr_match_new(const struct match *m, uint8_t clause, uint8_t n_clauses,
               uint32_t conj_id)
{
    struct expr_match *match = xmalloc(sizeof *match);
    if (m) {
        match->match = *m;
    } else {
        match_init_catchall(&match->match);
    }
    if (conj_id) {
        match->conjunctions = xmalloc(sizeof *match->conjunctions);
        match->conjunctions[0].id = conj_id;
        match->conjunctions[0].clause = clause;
        match->conjunctions[0].n_clauses = n_clauses;
        match->n = 1;
        match->allocated = 1;
    } else {
        match->conjunctions = NULL;
        match->n = 0;
        match->allocated = 0;
    }
    return match;
}

/* Adds 'match' to hash table 'matches', which becomes the new owner of
 * 'match'.
 *
 * This might actually destroy 'match' because it gets merged together with
 * some existing conjunction.*/
static void
expr_match_add(struct hmap *matches, struct expr_match *match)
{
    uint32_t hash = match_hash(&match->match, 0);
    struct expr_match *m;

    HMAP_FOR_EACH_WITH_HASH (m, hmap_node, hash, matches) {
        if (match_equal(&m->match, &match->match)) {
            if (!m->n || !match->n) {
                free(m->conjunctions);
                m->conjunctions = NULL;
                m->n = 0;
                m->allocated = 0;
            } else {
                ovs_assert(match->n == 1);
                if (m->n >= m->allocated) {
                    m->conjunctions = x2nrealloc(m->conjunctions,
                                                 &m->allocated,
                                                 sizeof *m->conjunctions);
                }
                m->conjunctions[m->n++] = match->conjunctions[0];
            }
            free(match->conjunctions);
            free(match);
            return;
        }
    }

    hmap_insert(matches, &match->hmap_node, hash);
}

static bool
constrain_match(const struct expr *expr,
                bool (*lookup_port)(const void *aux, const char *port_name,
                                    unsigned int *portp),
                const void *aux, struct match *m)
{
    ovs_assert(expr->type == EXPR_T_CMP);
    if (expr->cmp.symbol->width) {
        mf_mask_subfield(expr->cmp.symbol->field, &expr->cmp.value,
                         &expr->cmp.mask, m);
    } else {
        unsigned int port;
        if (!lookup_port(aux, expr->cmp.string, &port)) {
            return false;
        }

        struct mf_subfield sf;
        sf.field = expr->cmp.symbol->field;
        sf.ofs = 0;
        sf.n_bits = expr->cmp.symbol->field->n_bits;

        union mf_subvalue x;
        memset(&x, 0, sizeof x);
        x.integer = htonll(port);

        mf_write_subfield(&sf, &x, m);
    }
    return true;
}

static bool
add_disjunction(const struct expr *or,
                bool (*lookup_port)(const void *aux, const char *port_name,
                                    unsigned int *portp),
                const void *aux,
                struct match *m, uint8_t clause, uint8_t n_clauses,
                uint32_t conj_id, struct hmap *matches)
{
    struct expr *sub;
    int n = 0;

    ovs_assert(or->type == EXPR_T_OR);
    LIST_FOR_EACH (sub, node, &or->andor) {
        struct expr_match *match = expr_match_new(m, clause, n_clauses,
                                                  conj_id);
        if (constrain_match(sub, lookup_port, aux, &match->match)) {
            expr_match_add(matches, match);
            n++;
        } else {
            free(match->conjunctions);
            free(match);
        }
    }

    /* If n == 1, then this didn't really need to be a disjunction.  Oh well,
     * that shouldn't happen much. */
    return n > 0;
}

static void
add_conjunction(const struct expr *and,
                bool (*lookup_port)(const void *aux, const char *port_name,
                                    unsigned int *portp),
                const void *aux, uint32_t *n_conjsp, struct hmap *matches)
{
    struct match match;
    int n_clauses = 0;
    struct expr *sub;

    match_init_catchall(&match);

    ovs_assert(and->type == EXPR_T_AND);
    LIST_FOR_EACH (sub, node, &and->andor) {
        switch (sub->type) {
        case EXPR_T_CMP:
            if (!constrain_match(sub, lookup_port, aux, &match)) {
                return;
            }
            break;
        case EXPR_T_OR:
            n_clauses++;
            break;
        case EXPR_T_AND:
        case EXPR_T_BOOLEAN:
            OVS_NOT_REACHED();
        }
    }

    if (!n_clauses) {
        expr_match_add(matches, expr_match_new(&match, 0, 0, 0));
    } else if (n_clauses == 1) {
        LIST_FOR_EACH (sub, node, &and->andor) {
            if (sub->type == EXPR_T_OR) {
                add_disjunction(sub, lookup_port, aux, &match, 0, 0, 0,
                                matches);
            }
        }
    } else {
        int clause = 0;
        (*n_conjsp)++;
        LIST_FOR_EACH (sub, node, &and->andor) {
            if (sub->type == EXPR_T_OR) {
                if (!add_disjunction(sub, lookup_port, aux, &match, clause++,
                                     n_clauses, *n_conjsp, matches)) {
                    /* This clause can't ever match, so we might as well skip
                     * adding the other clauses--the overall disjunctive flow
                     * can't ever match.  Ideally we would also back out all of
                     * the clauses we already added, but that seems like a lot
                     * of trouble for a case that might never occur in
                     * practice. */
                    return;
                }
            }
        }

        /* Add the flow that matches on conj_id. */
        match_set_conj_id(&match, *n_conjsp);
        expr_match_add(matches, expr_match_new(&match, 0, 0, 0));
    }
}

static void
add_cmp_flow(const struct expr *cmp,
             bool (*lookup_port)(const void *aux, const char *port_name,
                                 unsigned int *portp),
             const void *aux, struct hmap *matches)
{
    struct expr_match *m = expr_match_new(NULL, 0, 0, 0);
    if (constrain_match(cmp, lookup_port, aux, &m->match)) {
        expr_match_add(matches, m);
    } else {
        free(m);
    }
}

/* Converts 'expr', which must be in the form returned by expr_normalize(), to
 * a collection of Open vSwitch flows in 'matches', which this function
 * initializes to an hmap of "struct expr_match" structures.  Returns the
 * number of conjunctive match IDs consumed by 'matches', which uses
 * conjunctive match IDs beginning with 0; the caller must offset or remap them
 * into the desired range as necessary.
 *
 * The matches inserted into 'matches' will be of three distinct kinds:
 *
 *     - Ordinary flows.  The caller should add these OpenFlow flows with
 *       its desired actions.
 *
 *     - Conjunctive flows, distinguished by 'n > 0' in the expr_match
 *       structure.  The caller should add these OpenFlow flows with the
 *       conjunction(id, k/n) actions as specified in the 'conjunctions' array,
 *       remapping the ids.
 *
 *     - conj_id flows, distinguished by matching on the "conj_id" field.  The
 *       caller should remap the conj_id and add the OpenFlow flow with its
 *       desired actions.
 *
 * 'lookup_port' must be a function to map from a port name to a port number.
 * When successful, 'lookup_port' stores the port number into '*portp' and
 * returns true; when there is no port by the given name, it returns false.
 * 'aux' is passed to 'lookup_port' as auxiliary data.  Any comparisons against
 * string fields in 'expr' are translated into integers through this function.
 * A comparison against a string that is not in 'ports' acts like a Boolean
 * "false"; that is, it will always fail to match.  For a simple expression,
 * this means that the overall expression always fails to match, but an
 * expression with a disjunction on the string field might still match on other
 * port names.
 *
 * (This treatment of string fields might be too simplistic in general, but it
 * seems reasonable for now when string fields are used only for ports.) */
uint32_t
expr_to_matches(const struct expr *expr,
                bool (*lookup_port)(const void *aux, const char *port_name,
                                    unsigned int *portp),
                const void *aux, struct hmap *matches)
{
    uint32_t n_conjs = 0;

    hmap_init(matches);
    switch (expr->type) {
    case EXPR_T_CMP:
        add_cmp_flow(expr, lookup_port, aux, matches);
        break;

    case EXPR_T_AND:
        add_conjunction(expr, lookup_port, aux, &n_conjs, matches);
        break;

    case EXPR_T_OR:
        if (expr_is_cmp(expr)) {
            struct expr *sub;

            LIST_FOR_EACH (sub, node, &expr->andor) {
                add_cmp_flow(sub, lookup_port, aux, matches);
            }
        } else {
            struct expr *sub;

            LIST_FOR_EACH (sub, node, &expr->andor) {
                if (sub->type == EXPR_T_AND) {
                    add_conjunction(sub, lookup_port, aux, &n_conjs, matches);
                } else {
                    add_cmp_flow(sub, lookup_port, aux, matches);
                }
            }
        }
        break;

    case EXPR_T_BOOLEAN:
        if (expr->boolean) {
            struct expr_match *m = expr_match_new(NULL, 0, 0, 0);
            expr_match_add(matches, m);
        } else {
            /* No match. */
        }
        break;
    }
    return n_conjs;
}

/* Destroys all of the 'struct expr_match'es in 'matches', as well as the
 * 'matches' hmap itself. */
void
expr_matches_destroy(struct hmap *matches)
{
    struct expr_match *m;

    HMAP_FOR_EACH_POP (m, hmap_node, matches) {
        free(m->conjunctions);
        free(m);
    }
    hmap_destroy(matches);
}

/* Prints a representation of the 'struct expr_match'es in 'matches' to
 * 'stream'. */
void
expr_matches_print(const struct hmap *matches, FILE *stream)
{
    if (hmap_is_empty(matches)) {
        fputs("(no flows)\n", stream);
        return;
    }

    const struct expr_match *m;
    HMAP_FOR_EACH (m, hmap_node, matches) {
        char *s = match_to_string(&m->match, OFP_DEFAULT_PRIORITY);
        fputs(s, stream);
        free(s);

        if (m->n) {
            for (int i = 0; i < m->n; i++) {
                const struct cls_conjunction *c = &m->conjunctions[i];
                fprintf(stream, "%c conjunction(%"PRIu32", %d/%d)",
                        i == 0 ? ':' : ',', c->id, c->clause, c->n_clauses);
            }
        }
        putc('\n', stream);
    }
}

/* Returns true if 'expr' honors the invariants for expressions (see the large
 * comment above "struct expr" in expr.h), false otherwise. */
bool
expr_honors_invariants(const struct expr *expr)
{
    const struct expr *sub;

    switch (expr->type) {
    case EXPR_T_CMP:
        if (expr->cmp.symbol->width) {
            for (int i = 0; i < ARRAY_SIZE(expr->cmp.value.be64); i++) {
                if (expr->cmp.value.be64[i] & ~expr->cmp.mask.be64[i]) {
                    return false;
                }
            }
        }
        return true;

    case EXPR_T_AND:
    case EXPR_T_OR:
        if (ovs_list_is_short(&expr->andor)) {
            return false;
        }
        LIST_FOR_EACH (sub, node, &expr->andor) {
            if (sub->type == expr->type || !expr_honors_invariants(sub)) {
                return false;
            }
        }
        return true;

    case EXPR_T_BOOLEAN:
        return true;

    default:
        OVS_NOT_REACHED();
    }
}

static bool
expr_is_normalized_and(const struct expr *expr)
{
    /* XXX should also check that no symbol is repeated. */
    const struct expr *sub;

    LIST_FOR_EACH (sub, node, &expr->andor) {
        if (!expr_is_cmp(sub)) {
            return false;
        }
    }
    return true;
}

/* Returns true if 'expr' is in the form returned by expr_normalize(), false
 * otherwise. */
bool
expr_is_normalized(const struct expr *expr)
{
    switch (expr->type) {
    case EXPR_T_CMP:
        return true;

    case EXPR_T_AND:
        return expr_is_normalized_and(expr);

    case EXPR_T_OR:
        if (!expr_is_cmp(expr)) {
            const struct expr *sub;

            LIST_FOR_EACH (sub, node, &expr->andor) {
                if (!expr_is_cmp(sub) && !expr_is_normalized_and(sub)) {
                    return false;
                }
            }
        }
        return true;

    case EXPR_T_BOOLEAN:
        return true;

    default:
        OVS_NOT_REACHED();
    }
}

/* Action parsing helper. */

/* Expands 'f' repeatedly as long as it has an expansion, that is, as long as
 * it is a subfield or a predicate.  Adds any prerequisites for 'f' to
 * '*prereqs'.
 *
 * If 'rw', verifies that 'f' is a read/write field.
 *
 * Returns true if successful, false if an error was encountered (in which case
 * 'ctx->error' reports the particular error). */
static bool
expand_symbol(struct expr_context *ctx, bool rw,
              struct expr_field *f, struct expr **prereqsp)
{
    const struct expr_symbol *orig_symbol = f->symbol;

    if (f->symbol->expansion && f->symbol->level != EXPR_L_ORDINAL) {
        expr_error(ctx, "Predicate symbol %s used where lvalue required.",
                   f->symbol->name);
        return false;
    }

    for (;;) {
        /* Accumulate prerequisites. */
        if (f->symbol->prereqs) {
            struct ovs_list nesting = OVS_LIST_INITIALIZER(&nesting);
            char *error;
            struct expr *e;
            e = parse_and_annotate(f->symbol->prereqs, ctx->symtab, &nesting,
                                   &error);
            if (error) {
                expr_error(ctx, "%s", error);
                free(error);
                return false;
            }
            *prereqsp = expr_combine(EXPR_T_AND, *prereqsp, e);
        }

        /* If there's no expansion, we're done. */
        if (!f->symbol->expansion) {
            break;
        }

        /* Expand. */
        struct expr_field expansion;
        char *error;
        if (!parse_field_from_string(f->symbol->expansion, ctx->symtab,
                                     &expansion, &error)) {
            expr_error(ctx, "%s", error);
            free(error);
            return false;
        }
        f->symbol = expansion.symbol;
        f->ofs += expansion.ofs;
    }

    if (rw && !f->symbol->field->writable) {
        expr_error(ctx, "Field %s is not modifiable.", orig_symbol->name);
        return false;
    }

    return true;
}

static void
mf_subfield_from_expr_field(const struct expr_field *f, struct mf_subfield *sf)
{
    sf->field = f->symbol->field;
    sf->ofs = f->ofs;
    sf->n_bits = f->n_bits ? f->n_bits : f->symbol->field->n_bits;
}

static void
init_stack_action(const struct expr_field *f, struct ofpact_stack *stack)
{
    mf_subfield_from_expr_field(f, &stack->subfield);
}

static struct expr *
parse_assignment(struct expr_context *ctx,
                 bool (*lookup_port)(const void *aux, const char *port_name,
                                     unsigned int *portp),
                 const void *aux, struct ofpbuf *ofpacts)
{
    struct expr *prereqs = NULL;

    /* Parse destination and do basic checking. */
    struct expr_field dst;
    if (!parse_field(ctx, &dst)) {
        goto exit;
    }
    bool exchange = lexer_match(ctx->lexer, LEX_T_EXCHANGE);
    if (!exchange && !lexer_match(ctx->lexer, LEX_T_EQUALS)) {
        expr_syntax_error(ctx, "expecting `='.");
        goto exit;
    }
    const struct expr_symbol *orig_dst = dst.symbol;
    if (!expand_symbol(ctx, true, &dst, &prereqs)) {
        goto exit;
    }

    if (exchange || ctx->lexer->token.type == LEX_T_ID) {
        struct expr_field src;
        if (!parse_field(ctx, &src)) {
            goto exit;
        }
        const struct expr_symbol *orig_src = src.symbol;
        if (!expand_symbol(ctx, exchange, &src, &prereqs)) {
            goto exit;
        }

        if ((dst.symbol->width != 0) != (src.symbol->width != 0)) {
            if (exchange) {
                expr_error(ctx,
                           "Can't exchange %s field (%s) with %s field (%s).",
                           orig_dst->width ? "integer" : "string",
                           orig_dst->name,
                           orig_src->width ? "integer" : "string",
                           orig_src->name);
            } else {
                expr_error(ctx, "Can't assign %s field (%s) to %s field (%s).",
                           orig_src->width ? "integer" : "string",
                           orig_src->name,
                           orig_dst->width ? "integer" : "string",
                           orig_dst->name);
            }
            goto exit;
        }

        if (dst.n_bits != src.n_bits) {
            if (exchange) {
                expr_error(ctx,
                           "Can't exchange %d-bit field with %d-bit field.",
                           dst.n_bits, src.n_bits);
            } else {
                expr_error(ctx,
                           "Can't assign %d-bit value to %d-bit destination.",
                           src.n_bits, dst.n_bits);
            }
            goto exit;
        } else if (!dst.n_bits
                   && dst.symbol->field->n_bits != src.symbol->field->n_bits) {
            expr_error(ctx, "String fields %s and %s are incompatible for "
                       "%s.", orig_dst->name, orig_src->name,
                       exchange ? "exchange" : "assignment");
            goto exit;
        }

        if (exchange) {
            init_stack_action(&src, ofpact_put_STACK_PUSH(ofpacts));
            init_stack_action(&dst, ofpact_put_STACK_PUSH(ofpacts));
            init_stack_action(&src, ofpact_put_STACK_POP(ofpacts));
            init_stack_action(&dst, ofpact_put_STACK_POP(ofpacts));
        } else {
            struct ofpact_reg_move *move = ofpact_put_REG_MOVE(ofpacts);
            mf_subfield_from_expr_field(&src, &move->src);
            mf_subfield_from_expr_field(&dst, &move->dst);
        }
    } else {
        struct expr_constant_set cs;
        if (!parse_constant_set(ctx, &cs)) {
            goto exit;
        }

        if (!type_check(ctx, &dst, &cs)) {
            goto exit_destroy_cs;
        }
        if (cs.in_curlies) {
            expr_error(ctx, "Assignments require a single value.");
            goto exit_destroy_cs;
        }

        union expr_constant *c = cs.values;
        struct ofpact_set_field *sf = ofpact_put_SET_FIELD(ofpacts);
        sf->field = dst.symbol->field;
        if (dst.symbol->width) {
            mf_subvalue_shift(&c->value, dst.ofs);
            if (!c->masked) {
                memset(&c->mask, 0, sizeof c->mask);
                bitwise_one(&c->mask, sizeof c->mask, dst.ofs, dst.n_bits);
            } else {
                mf_subvalue_shift(&c->mask, dst.ofs);
            }

            memcpy(&sf->value,
                   &c->value.u8[sizeof c->value - sf->field->n_bytes],
                   sf->field->n_bytes);
            memcpy(&sf->mask,
                   &c->mask.u8[sizeof c->mask - sf->field->n_bytes],
                   sf->field->n_bytes);
        } else {
            uint32_t port;
            if (!lookup_port(aux, c->string, &port)) {
                port = 0;
            }
            bitwise_put(port, &sf->value,
                        sf->field->n_bytes, 0, sf->field->n_bits);
            bitwise_one(&sf->mask, sf->field->n_bytes, 0, sf->field->n_bits);

            /* If the logical input port is being zeroed, clear the OpenFlow
             * ingress port also, to allow a packet to be sent back to its
             * origin. */
            if (!port && sf->field->id == MFF_LOG_INPORT) {
                sf = ofpact_put_SET_FIELD(ofpacts);
                sf->field = mf_from_id(MFF_IN_PORT);
                bitwise_one(&sf->mask,
                            sf->field->n_bytes, 0, sf->field->n_bits);
            }
        }

    exit_destroy_cs:
        expr_constant_set_destroy(&cs);
    }

exit:
    return prereqs;
}

/* A helper for actions_parse(), to parse an OVN assignment action in the form
 * "field = value" or "field1 = field2", or a "exchange" action in the form
 * "field1 <-> field2", into 'ofpacts'.  The parameters and return value match
 * those for actions_parse(). */
char *
expr_parse_assignment(struct lexer *lexer, const struct shash *symtab,
                      bool (*lookup_port)(const void *aux,
                                          const char *port_name,
                                          unsigned int *portp),
                      const void *aux,
                      struct ofpbuf *ofpacts, struct expr **prereqsp)
{
    struct expr_context ctx;
    ctx.lexer = lexer;
    ctx.symtab = symtab;
    ctx.error = NULL;
    ctx.not = false;

    struct expr *prereqs = parse_assignment(&ctx, lookup_port, aux, ofpacts);
    if (ctx.error) {
        expr_destroy(prereqs);
        prereqs = NULL;
    }
    *prereqsp = prereqs;
    return ctx.error;
}

char *
expr_parse_field(struct lexer *lexer, int n_bits, bool rw,
                 const struct shash *symtab,
                 struct mf_subfield *sf, struct expr **prereqsp)
{
    struct expr *prereqs = NULL;
    struct expr_context ctx;
    ctx.lexer = lexer;
    ctx.symtab = symtab;
    ctx.error = NULL;
    ctx.not = false;

    struct expr_field field;
    if (!parse_field(&ctx, &field)) {
        goto exit;
    }

    const struct expr_field orig_field = field;
    if (!expand_symbol(&ctx, rw, &field, &prereqs)) {
        goto exit;
    }
    ovs_assert(field.n_bits == orig_field.n_bits);

    if (n_bits != field.n_bits) {
        if (n_bits && field.n_bits) {
            expr_error(&ctx, "Cannot use %d-bit field %s[%d..%d] "
                       "where %d-bit field is required.",
                       orig_field.n_bits, orig_field.symbol->name,
                       orig_field.ofs, orig_field.ofs + orig_field.n_bits - 1,
                       n_bits);
        } else if (n_bits) {
            expr_error(&ctx, "Cannot use string field %s where numeric "
                       "field is required.",
                       orig_field.symbol->name);
        } else {
            expr_error(&ctx, "Cannot use numeric field %s where string "
                       "field is required.",
                       orig_field.symbol->name);
        }
    }

exit:
    if (!ctx.error) {
        mf_subfield_from_expr_field(&field, sf);
        *prereqsp = prereqs;
    } else {
        memset(sf, 0, sizeof *sf);
        expr_destroy(prereqs);
        *prereqsp = NULL;
    }
    return ctx.error;
}
