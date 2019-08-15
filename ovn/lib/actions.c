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
#include <stdarg.h>
#include <stdbool.h>
#include "bitmap.h"
#include "byte-order.h"
#include "compiler.h"
#include "ovn-l7.h"
#include "hash.h"
#include "lib/packets.h"
#include "nx-match.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn/actions.h"
#include "ovn/expr.h"
#include "ovn/lex.h"
#include "ovn/lib/acl-log.h"
#include "ovn/lib/extend-table.h"
#include "packets.h"
#include "openvswitch/shash.h"
#include "simap.h"
#include "uuid.h"
#include "socket-util.h"

VLOG_DEFINE_THIS_MODULE(actions);

/* Prototypes for functions to be defined by each action. */
#define OVNACT(ENUM, STRUCT)                                        \
    static void format_##ENUM(const struct STRUCT *, struct ds *);  \
    static void encode_##ENUM(const struct STRUCT *,                \
                              const struct ovnact_encode_params *,  \
                              struct ofpbuf *ofpacts);              \
    static void STRUCT##_free(struct STRUCT *a);
OVNACTS
#undef OVNACT

/* Helpers. */

/* Implementation of ovnact_put_<ENUM>(). */
void *
ovnact_put(struct ofpbuf *ovnacts, enum ovnact_type type, size_t len)
{
    ovs_assert(len == OVNACT_ALIGN(len));

    ovnacts->header = ofpbuf_put_uninit(ovnacts, len);
    struct ovnact *ovnact = ovnacts->header;
    ovnact_init(ovnact, type, len);
    return ovnact;
}

/* Implementation of ovnact_init_<ENUM>(). */
void
ovnact_init(struct ovnact *ovnact, enum ovnact_type type, size_t len)
{
    ovs_assert(len == OVNACT_ALIGN(len));
    memset(ovnact, 0, len);
    ovnact->type = type;
    ovnact->len = len;
}

static size_t
encode_start_controller_op(enum action_opcode opcode, bool pause,
                           uint32_t meter_id, struct ofpbuf *ofpacts)
{
    size_t ofs = ofpacts->size;

    struct ofpact_controller *oc = ofpact_put_CONTROLLER(ofpacts);
    oc->max_len = UINT16_MAX;
    oc->reason = OFPR_ACTION;
    oc->pause = pause;
    oc->meter_id = meter_id;

    struct action_header ah = { .opcode = htonl(opcode) };
    ofpbuf_put(ofpacts, &ah, sizeof ah);

    return ofs;
}

static void
encode_finish_controller_op(size_t ofs, struct ofpbuf *ofpacts)
{
    struct ofpact_controller *oc = ofpbuf_at_assert(ofpacts, ofs, sizeof *oc);
    ofpacts->header = oc;
    oc->userdata_len = ofpacts->size - (ofs + sizeof *oc);
    ofpact_finish_CONTROLLER(ofpacts, &oc);
}

static void
encode_controller_op(enum action_opcode opcode, struct ofpbuf *ofpacts)
{
    size_t ofs = encode_start_controller_op(opcode, false, NX_CTLR_NO_METER,
                                            ofpacts);
    encode_finish_controller_op(ofs, ofpacts);
}

static void
init_stack(struct ofpact_stack *stack, enum mf_field_id field)
{
    stack->subfield.field = mf_from_id(field);
    stack->subfield.ofs = 0;
    stack->subfield.n_bits = stack->subfield.field->n_bits;
}

struct arg {
    const struct mf_subfield src;
    enum mf_field_id dst;
};

static void
encode_setup_args(const struct arg args[], size_t n_args,
                  struct ofpbuf *ofpacts)
{
    /* 1. Save all of the destinations that will be modified. */
    for (const struct arg *a = args; a < &args[n_args]; a++) {
        ovs_assert(a->src.n_bits == mf_from_id(a->dst)->n_bits);
        if (a->src.field->id != a->dst) {
            init_stack(ofpact_put_STACK_PUSH(ofpacts), a->dst);
        }
    }

    /* 2. Push the sources, in reverse order. */
    for (size_t i = n_args - 1; i < n_args; i--) {
        const struct arg *a = &args[i];
        if (a->src.field->id != a->dst) {
            ofpact_put_STACK_PUSH(ofpacts)->subfield = a->src;
        }
    }

    /* 3. Pop the sources into the destinations. */
    for (const struct arg *a = args; a < &args[n_args]; a++) {
        if (a->src.field->id != a->dst) {
            init_stack(ofpact_put_STACK_POP(ofpacts), a->dst);
        }
    }
}

static void
encode_restore_args(const struct arg args[], size_t n_args,
                    struct ofpbuf *ofpacts)
{
    for (size_t i = n_args - 1; i < n_args; i--) {
        const struct arg *a = &args[i];
        if (a->src.field->id != a->dst) {
            init_stack(ofpact_put_STACK_POP(ofpacts), a->dst);
        }
    }
}

static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, 8, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

static uint8_t
first_ptable(const struct ovnact_encode_params *ep,
             enum ovnact_pipeline pipeline)
{
    return (pipeline == OVNACT_P_INGRESS
            ? ep->ingress_ptable
            : ep->egress_ptable);
}

#define MAX_NESTED_ACTION_DEPTH 32

/* Context maintained during ovnacts_parse(). */
struct action_context {
    const struct ovnact_parse_params *pp; /* Parameters. */
    struct lexer *lexer;        /* Lexer for pulling more tokens. */
    struct ofpbuf *ovnacts;     /* Actions. */
    struct expr *prereqs;       /* Prerequisites to apply to match. */
    int depth;                  /* Current nested action depth. */
};

static void parse_actions(struct action_context *, enum lex_type sentinel);

static bool
action_parse_field(struct action_context *ctx,
                   int n_bits, bool rw, struct expr_field *f)
{
    if (!expr_field_parse(ctx->lexer, ctx->pp->symtab, f, &ctx->prereqs)) {
        return false;
    }

    char *error = expr_type_check(f, n_bits, rw);
    if (error) {
        lexer_error(ctx->lexer, "%s", error);
        free(error);
        return false;
    }

    return true;
}

static bool
action_parse_port(struct action_context *ctx, uint16_t *port)
{
    if (lexer_is_int(ctx->lexer)) {
        int value = ntohll(ctx->lexer->token.value.integer);
        if (value <= UINT16_MAX) {
            *port = value;
            lexer_get(ctx->lexer);
            return true;
        }
    }
    lexer_syntax_error(ctx->lexer, "expecting port number");
    return false;
}

/* Parses 'prerequisite' as an expression in the context of 'ctx', then adds it
 * as a conjunction with the existing 'ctx->prereqs'. */
static void
add_prerequisite(struct action_context *ctx, const char *prerequisite)
{
    struct expr *expr;
    char *error;

    expr = expr_parse_string(prerequisite, ctx->pp->symtab, NULL, NULL, NULL,
                             &error);
    ovs_assert(!error);
    ctx->prereqs = expr_combine(EXPR_T_AND, ctx->prereqs, expr);
}

static void
ovnact_null_free(struct ovnact_null *a OVS_UNUSED)
{
}

static void
format_OUTPUT(const struct ovnact_null *a OVS_UNUSED, struct ds *s)
{
    ds_put_cstr(s, "output;");
}

static void
emit_resubmit(struct ofpbuf *ofpacts, uint8_t ptable)
{
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = ptable;
}

static void
encode_OUTPUT(const struct ovnact_null *a OVS_UNUSED,
              const struct ovnact_encode_params *ep,
              struct ofpbuf *ofpacts)
{
    emit_resubmit(ofpacts, ep->output_ptable);
}

static void
parse_NEXT(struct action_context *ctx)
{
    if (!ctx->pp->n_tables) {
        lexer_error(ctx->lexer, "\"next\" action not allowed here.");
        return;
    }

    int pipeline = ctx->pp->pipeline;
    int table = ctx->pp->cur_ltable + 1;
    if (lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        if (lexer_is_int(ctx->lexer)) {
            lexer_get_int(ctx->lexer, &table);
        } else {
            do {
                if (lexer_match_id(ctx->lexer, "pipeline")) {
                    if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)) {
                        return;
                    }
                    if (lexer_match_id(ctx->lexer, "ingress")) {
                        pipeline = OVNACT_P_INGRESS;
                    } else if (lexer_match_id(ctx->lexer, "egress")) {
                        pipeline = OVNACT_P_EGRESS;
                    } else {
                        lexer_syntax_error(
                            ctx->lexer, "expecting \"ingress\" or \"egress\"");
                        return;
                    }
                } else if (lexer_match_id(ctx->lexer, "table")) {
                    if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS) ||
                        !lexer_force_int(ctx->lexer, &table)) {
                        return;
                    }
                } else {
                    lexer_syntax_error(ctx->lexer,
                                       "expecting \"pipeline\" or \"table\"");
                    return;
                }
            } while (lexer_match(ctx->lexer, LEX_T_COMMA));
        }
        if (!lexer_force_match(ctx->lexer, LEX_T_RPAREN)) {
            return;
        }
    }

    if (pipeline == OVNACT_P_EGRESS && ctx->pp->pipeline == OVNACT_P_INGRESS) {
        lexer_error(ctx->lexer,
                    "\"next\" action cannot advance from ingress to egress "
                    "pipeline (use \"output\" action instead)");
    } else if (table >= ctx->pp->n_tables) {
        lexer_error(ctx->lexer,
                    "\"next\" action cannot advance beyond table %d.",
                    ctx->pp->n_tables - 1);
        return;
    }

    struct ovnact_next *next = ovnact_put_NEXT(ctx->ovnacts);
    next->pipeline = pipeline;
    next->ltable = table;
    next->src_pipeline = ctx->pp->pipeline;
    next->src_ltable = ctx->pp->cur_ltable;
}

static void
format_NEXT(const struct ovnact_next *next, struct ds *s)
{
    if (next->pipeline != next->src_pipeline) {
        ds_put_format(s, "next(pipeline=%s, table=%d);",
                      (next->pipeline == OVNACT_P_INGRESS
                       ? "ingress" : "egress"),
                      next->ltable);
    } else if (next->ltable != next->src_ltable + 1) {
        ds_put_format(s, "next(%d);", next->ltable);
    } else {
        ds_put_cstr(s, "next;");
    }
}

static void
encode_NEXT(const struct ovnact_next *next,
            const struct ovnact_encode_params *ep,
            struct ofpbuf *ofpacts)
{
    emit_resubmit(ofpacts, first_ptable(ep, next->pipeline) + next->ltable);
}

static void
ovnact_next_free(struct ovnact_next *a OVS_UNUSED)
{
}

static void
parse_LOAD(struct action_context *ctx, const struct expr_field *lhs)
{
    size_t ofs = ctx->ovnacts->size;
    struct ovnact_load *load;
    if (lhs->symbol->ovn_field) {
        load = ovnact_put_OVNFIELD_LOAD(ctx->ovnacts);
    } else {
        load = ovnact_put_LOAD(ctx->ovnacts);
    }

    load->dst = *lhs;

    char *error = expr_type_check(lhs, lhs->n_bits, true);
    if (error) {
        ctx->ovnacts->size = ofs;
        lexer_error(ctx->lexer, "%s", error);
        free(error);
        return;
    }
    if (!expr_constant_parse(ctx->lexer, lhs, &load->imm)) {
        ctx->ovnacts->size = ofs;
        return;
    }
}

static enum expr_constant_type
load_type(const struct ovnact_load *load)
{
    return load->dst.symbol->width > 0 ? EXPR_C_INTEGER : EXPR_C_STRING;
}

static void
format_LOAD(const struct ovnact_load *load, struct ds *s)
{
    expr_field_format(&load->dst, s);
    ds_put_cstr(s, " = ");
    expr_constant_format(&load->imm, load_type(load), s);
    ds_put_char(s, ';');
}

static void
encode_LOAD(const struct ovnact_load *load,
            const struct ovnact_encode_params *ep,
            struct ofpbuf *ofpacts)
{
    const union expr_constant *c = &load->imm;
    struct mf_subfield dst = expr_resolve_field(&load->dst);
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts, dst.field,
                                                       NULL, NULL);

    if (load->dst.symbol->width) {
        bitwise_copy(&c->value, sizeof c->value, 0,
                     sf->value, dst.field->n_bytes, dst.ofs,
                     dst.n_bits);
        if (c->masked) {
            bitwise_copy(&c->mask, sizeof c->mask, 0,
                         ofpact_set_field_mask(sf), dst.field->n_bytes,
                         dst.ofs, dst.n_bits);
        } else {
            bitwise_one(ofpact_set_field_mask(sf), dst.field->n_bytes,
                        dst.ofs, dst.n_bits);
        }
    } else {
        uint32_t port;
        if (!ep->lookup_port(ep->aux, load->imm.string, &port)) {
            port = 0;
        }
        bitwise_put(port, sf->value,
                    sf->field->n_bytes, 0, sf->field->n_bits);
        bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, 0,
                    sf->field->n_bits);
    }
}

static void
ovnact_load_free(struct ovnact_load *load)
{
    expr_constant_destroy(&load->imm, load_type(load));
}

static void
format_assignment(const struct ovnact_move *move, const char *operator,
                  struct ds *s)
{
    expr_field_format(&move->lhs, s);
    ds_put_format(s, " %s ", operator);
    expr_field_format(&move->rhs, s);
    ds_put_char(s, ';');
}

static void
format_MOVE(const struct ovnact_move *move, struct ds *s)
{
    format_assignment(move, "=", s);
}

static void
format_EXCHANGE(const struct ovnact_move *move, struct ds *s)
{
    format_assignment(move, "<->", s);
}

static void
parse_assignment_action(struct action_context *ctx, bool exchange,
                        const struct expr_field *lhs)
{
    struct expr_field rhs;
    if (!expr_field_parse(ctx->lexer, ctx->pp->symtab, &rhs, &ctx->prereqs)) {
        return;
    }

    const struct expr_symbol *ls = lhs->symbol;
    const struct expr_symbol *rs = rhs.symbol;
    if ((ls->width != 0) != (rs->width != 0)) {
        if (exchange) {
            lexer_error(ctx->lexer,
                        "Can't exchange %s field (%s) with %s field (%s).",
                        ls->width ? "integer" : "string",
                        ls->name,
                        rs->width ? "integer" : "string",
                        rs->name);
        } else {
            lexer_error(ctx->lexer,
                        "Can't assign %s field (%s) to %s field (%s).",
                        rs->width ? "integer" : "string",
                        rs->name,
                        ls->width ? "integer" : "string",
                        ls->name);
        }
        return;
    }

    if (lhs->n_bits != rhs.n_bits) {
        if (exchange) {
            lexer_error(ctx->lexer,
                        "Can't exchange %d-bit field with %d-bit field.",
                        lhs->n_bits, rhs.n_bits);
        } else {
            lexer_error(ctx->lexer,
                        "Can't assign %d-bit value to %d-bit destination.",
                        rhs.n_bits, lhs->n_bits);
        }
        return;
    } else if (!lhs->n_bits &&
               ls->field->n_bits != rs->field->n_bits) {
        lexer_error(ctx->lexer, "String fields %s and %s are incompatible for "
                    "%s.", ls->name, rs->name,
                    exchange ? "exchange" : "assignment");
        return;
    }

    char *error = expr_type_check(lhs, lhs->n_bits, true);
    if (!error) {
        error = expr_type_check(&rhs, rhs.n_bits, true);
    }
    if (error) {
        lexer_error(ctx->lexer, "%s", error);
        free(error);
        return;
    }

    struct ovnact_move *move;
    move = (exchange
            ? ovnact_put_EXCHANGE(ctx->ovnacts)
            : ovnact_put_MOVE(ctx->ovnacts));
    move->lhs = *lhs;
    move->rhs = rhs;
}

static void
encode_MOVE(const struct ovnact_move *move,
            const struct ovnact_encode_params *ep OVS_UNUSED,
            struct ofpbuf *ofpacts)
{
    struct ofpact_reg_move *orm = ofpact_put_REG_MOVE(ofpacts);
    orm->src = expr_resolve_field(&move->rhs);
    orm->dst = expr_resolve_field(&move->lhs);
}

static void
encode_EXCHANGE(const struct ovnact_move *xchg,
                const struct ovnact_encode_params *ep OVS_UNUSED,
                struct ofpbuf *ofpacts)
{
    ofpact_put_STACK_PUSH(ofpacts)->subfield = expr_resolve_field(&xchg->rhs);
    ofpact_put_STACK_PUSH(ofpacts)->subfield = expr_resolve_field(&xchg->lhs);
    ofpact_put_STACK_POP(ofpacts)->subfield = expr_resolve_field(&xchg->rhs);
    ofpact_put_STACK_POP(ofpacts)->subfield = expr_resolve_field(&xchg->lhs);
}

static void
ovnact_move_free(struct ovnact_move *move OVS_UNUSED)
{
}

static void
parse_DEC_TTL(struct action_context *ctx)
{
    lexer_force_match(ctx->lexer, LEX_T_DECREMENT);
    ovnact_put_DEC_TTL(ctx->ovnacts);
    add_prerequisite(ctx, "ip");
}

static void
format_DEC_TTL(const struct ovnact_null *null OVS_UNUSED, struct ds *s)
{
    ds_put_cstr(s, "ip.ttl--;");
}

static void
encode_DEC_TTL(const struct ovnact_null *null OVS_UNUSED,
               const struct ovnact_encode_params *ep OVS_UNUSED,
               struct ofpbuf *ofpacts)
{
    ofpact_put_DEC_TTL(ofpacts);
}

static void
parse_CT_NEXT(struct action_context *ctx)
{
    if (ctx->pp->cur_ltable >= ctx->pp->n_tables) {
        lexer_error(ctx->lexer,
                    "\"ct_next\" action not allowed in last table.");
        return;
    }

    add_prerequisite(ctx, "ip");
    ovnact_put_CT_NEXT(ctx->ovnacts)->ltable = ctx->pp->cur_ltable + 1;
}

static void
format_CT_NEXT(const struct ovnact_ct_next *ct_next OVS_UNUSED, struct ds *s)
{
    ds_put_cstr(s, "ct_next;");
}

static void
encode_CT_NEXT(const struct ovnact_ct_next *ct_next,
                const struct ovnact_encode_params *ep,
                struct ofpbuf *ofpacts)
{
    struct ofpact_conntrack *ct = ofpact_put_CT(ofpacts);
    ct->recirc_table = first_ptable(ep, ep->pipeline) + ct_next->ltable;
    ct->zone_src.field = ep->is_switch ? mf_from_id(MFF_LOG_CT_ZONE)
                            : mf_from_id(MFF_LOG_DNAT_ZONE);
    ct->zone_src.ofs = 0;
    ct->zone_src.n_bits = 16;
    ofpact_finish(ofpacts, &ct->ofpact);
}

static void
ovnact_ct_next_free(struct ovnact_ct_next *a OVS_UNUSED)
{
}

static void
parse_ct_commit_arg(struct action_context *ctx,
                    struct ovnact_ct_commit *cc)
{
    if (lexer_match_id(ctx->lexer, "ct_mark")) {
        if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)) {
            return;
        }
        if (ctx->lexer->token.type == LEX_T_INTEGER) {
            cc->ct_mark = ntohll(ctx->lexer->token.value.integer);
            cc->ct_mark_mask = UINT32_MAX;
        } else if (ctx->lexer->token.type == LEX_T_MASKED_INTEGER) {
            cc->ct_mark = ntohll(ctx->lexer->token.value.integer);
            cc->ct_mark_mask = ntohll(ctx->lexer->token.mask.integer);
        } else {
            lexer_syntax_error(ctx->lexer, "expecting integer");
            return;
        }
        lexer_get(ctx->lexer);
    } else if (lexer_match_id(ctx->lexer, "ct_label")) {
        if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)) {
            return;
        }
        if (ctx->lexer->token.type == LEX_T_INTEGER) {
            cc->ct_label = ctx->lexer->token.value.be128_int;
            cc->ct_label_mask = OVS_BE128_MAX;
        } else if (ctx->lexer->token.type == LEX_T_MASKED_INTEGER) {
            cc->ct_label = ctx->lexer->token.value.be128_int;
            cc->ct_label_mask = ctx->lexer->token.mask.be128_int;
        } else {
            lexer_syntax_error(ctx->lexer, "expecting integer");
            return;
        }
        lexer_get(ctx->lexer);
    } else {
        lexer_syntax_error(ctx->lexer, NULL);
    }
}

static void
parse_CT_COMMIT(struct action_context *ctx)
{
    add_prerequisite(ctx, "ip");

    struct ovnact_ct_commit *ct_commit = ovnact_put_CT_COMMIT(ctx->ovnacts);
    if (lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        while (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
            parse_ct_commit_arg(ctx, ct_commit);
            if (ctx->lexer->error) {
                return;
            }
            lexer_match(ctx->lexer, LEX_T_COMMA);
        }
    }
}

static void
format_CT_COMMIT(const struct ovnact_ct_commit *cc, struct ds *s)
{
    ds_put_cstr(s, "ct_commit(");
    if (cc->ct_mark_mask) {
        ds_put_format(s, "ct_mark=%#"PRIx32, cc->ct_mark);
        if (cc->ct_mark_mask != UINT32_MAX) {
            ds_put_format(s, "/%#"PRIx32, cc->ct_mark_mask);
        }
    }
    if (!ovs_be128_is_zero(cc->ct_label_mask)) {
        if (ds_last(s) != '(') {
            ds_put_cstr(s, ", ");
        }

        ds_put_format(s, "ct_label=");
        ds_put_hex(s, &cc->ct_label, sizeof cc->ct_label);
        if (!ovs_be128_equals(cc->ct_label_mask, OVS_BE128_MAX)) {
            ds_put_char(s, '/');
            ds_put_hex(s, &cc->ct_label_mask, sizeof cc->ct_label_mask);
        }
    }
    if (!ds_chomp(s, '(')) {
        ds_put_char(s, ')');
    }
    ds_put_char(s, ';');
}

static void
encode_CT_COMMIT(const struct ovnact_ct_commit *cc,
                 const struct ovnact_encode_params *ep OVS_UNUSED,
                 struct ofpbuf *ofpacts)
{
    struct ofpact_conntrack *ct = ofpact_put_CT(ofpacts);
    ct->flags = NX_CT_F_COMMIT;
    ct->recirc_table = NX_CT_RECIRC_NONE;
    ct->zone_src.field = mf_from_id(MFF_LOG_CT_ZONE);
    ct->zone_src.ofs = 0;
    ct->zone_src.n_bits = 16;

    size_t set_field_offset = ofpacts->size;
    ofpbuf_pull(ofpacts, set_field_offset);

    if (cc->ct_mark_mask) {
        const ovs_be32 value = htonl(cc->ct_mark);
        const ovs_be32 mask = htonl(cc->ct_mark_mask);
        ofpact_put_set_field(ofpacts, mf_from_id(MFF_CT_MARK), &value, &mask);
    }

    if (!ovs_be128_is_zero(cc->ct_label_mask)) {
        ofpact_put_set_field(ofpacts, mf_from_id(MFF_CT_LABEL), &cc->ct_label,
                             &cc->ct_label_mask);
    }

    ofpacts->header = ofpbuf_push_uninit(ofpacts, set_field_offset);
    ct = ofpacts->header;
    ofpact_finish(ofpacts, &ct->ofpact);
}

static void
ovnact_ct_commit_free(struct ovnact_ct_commit *cc OVS_UNUSED)
{
}

static void
parse_ct_nat(struct action_context *ctx, const char *name,
             struct ovnact_ct_nat *cn)
{
    add_prerequisite(ctx, "ip");

    if (ctx->pp->cur_ltable >= ctx->pp->n_tables) {
        lexer_error(ctx->lexer,
                    "\"%s\" action not allowed in last table.", name);
        return;
    }
    cn->ltable = ctx->pp->cur_ltable + 1;

    if (lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        if (ctx->lexer->token.type != LEX_T_INTEGER
            || ctx->lexer->token.format != LEX_F_IPV4) {
            lexer_syntax_error(ctx->lexer, "expecting IPv4 address");
            return;
        }
        cn->ip = ctx->lexer->token.value.ipv4;
        lexer_get(ctx->lexer);

        if (!lexer_force_match(ctx->lexer, LEX_T_RPAREN)) {
            return;
        }
    }
}

static void
parse_CT_DNAT(struct action_context *ctx)
{
    parse_ct_nat(ctx, "ct_dnat", ovnact_put_CT_DNAT(ctx->ovnacts));
}

static void
parse_CT_SNAT(struct action_context *ctx)
{
    parse_ct_nat(ctx, "ct_snat", ovnact_put_CT_SNAT(ctx->ovnacts));
}

static void
format_ct_nat(const struct ovnact_ct_nat *cn, const char *name, struct ds *s)
{
    ds_put_cstr(s, name);
    if (cn->ip) {
        ds_put_format(s, "("IP_FMT")", IP_ARGS(cn->ip));
    }
    ds_put_char(s, ';');
}

static void
format_CT_DNAT(const struct ovnact_ct_nat *cn, struct ds *s)
{
    format_ct_nat(cn, "ct_dnat", s);
}

static void
format_CT_SNAT(const struct ovnact_ct_nat *cn, struct ds *s)
{
    format_ct_nat(cn, "ct_snat", s);
}

static void
encode_ct_nat(const struct ovnact_ct_nat *cn,
              const struct ovnact_encode_params *ep,
              bool snat, struct ofpbuf *ofpacts)
{
    const size_t ct_offset = ofpacts->size;
    ofpbuf_pull(ofpacts, ct_offset);

    struct ofpact_conntrack *ct = ofpact_put_CT(ofpacts);
    ct->recirc_table = cn->ltable + first_ptable(ep, ep->pipeline);
    if (snat) {
        ct->zone_src.field = mf_from_id(MFF_LOG_SNAT_ZONE);
    } else {
        ct->zone_src.field = mf_from_id(MFF_LOG_DNAT_ZONE);
    }
    ct->zone_src.ofs = 0;
    ct->zone_src.n_bits = 16;
    ct->flags = 0;
    ct->alg = 0;

    struct ofpact_nat *nat;
    size_t nat_offset;
    nat_offset = ofpacts->size;
    ofpbuf_pull(ofpacts, nat_offset);

    nat = ofpact_put_NAT(ofpacts);
    nat->flags = 0;
    nat->range_af = AF_UNSPEC;

    if (cn->ip) {
        nat->range_af = AF_INET;
        nat->range.addr.ipv4.min = cn->ip;
        if (snat) {
            nat->flags |= NX_NAT_F_SRC;
        } else {
            nat->flags |= NX_NAT_F_DST;
        }
    }

    ofpacts->header = ofpbuf_push_uninit(ofpacts, nat_offset);
    ct = ofpacts->header;
    if (cn->ip) {
        ct->flags |= NX_CT_F_COMMIT;
    }
    ofpact_finish(ofpacts, &ct->ofpact);
    ofpbuf_push_uninit(ofpacts, ct_offset);
}

static void
encode_CT_DNAT(const struct ovnact_ct_nat *cn,
               const struct ovnact_encode_params *ep,
               struct ofpbuf *ofpacts)
{
    encode_ct_nat(cn, ep, false, ofpacts);
}

static void
encode_CT_SNAT(const struct ovnact_ct_nat *cn,
               const struct ovnact_encode_params *ep,
               struct ofpbuf *ofpacts)
{
    encode_ct_nat(cn, ep, true, ofpacts);
}

static void
ovnact_ct_nat_free(struct ovnact_ct_nat *ct_nat OVS_UNUSED)
{
}

static void
parse_ct_lb_action(struct action_context *ctx)
{
    if (ctx->pp->cur_ltable >= ctx->pp->n_tables) {
        lexer_error(ctx->lexer, "\"ct_lb\" action not allowed in last table.");
        return;
    }

    add_prerequisite(ctx, "ip");

    struct ovnact_ct_lb_dst *dsts = NULL;
    size_t allocated_dsts = 0;
    size_t n_dsts = 0;

    if (lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        while (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
            struct ovnact_ct_lb_dst dst;
            if (lexer_match(ctx->lexer, LEX_T_LSQUARE)) {
                /* IPv6 address and port */
                if (ctx->lexer->token.type != LEX_T_INTEGER
                    || ctx->lexer->token.format != LEX_F_IPV6) {
                    free(dsts);
                    lexer_syntax_error(ctx->lexer, "expecting IPv6 address");
                    return;
                }
                dst.family = AF_INET6;
                dst.ipv6 = ctx->lexer->token.value.ipv6;

                lexer_get(ctx->lexer);
                if (!lexer_match(ctx->lexer, LEX_T_RSQUARE)) {
                    free(dsts);
                    lexer_syntax_error(ctx->lexer, "no closing square "
                                                   "bracket");
                    return;
                }
                dst.port = 0;
                if (lexer_match(ctx->lexer, LEX_T_COLON)
                    && !action_parse_port(ctx, &dst.port)) {
                    free(dsts);
                    return;
                }
            } else {
                if (ctx->lexer->token.type != LEX_T_INTEGER
                    || (ctx->lexer->token.format != LEX_F_IPV4
                    && ctx->lexer->token.format != LEX_F_IPV6)) {
                    free(dsts);
                    lexer_syntax_error(ctx->lexer, "expecting IP address");
                    return;
                }

                /* Parse IP. */
                if (ctx->lexer->token.format == LEX_F_IPV4) {
                    dst.family = AF_INET;
                    dst.ipv4 = ctx->lexer->token.value.ipv4;
                } else {
                    dst.family = AF_INET6;
                    dst.ipv6 = ctx->lexer->token.value.ipv6;
                }

                lexer_get(ctx->lexer);
                dst.port = 0;
                if (lexer_match(ctx->lexer, LEX_T_COLON)) {
                    if (dst.family == AF_INET6) {
                        free(dsts);
                        lexer_syntax_error(ctx->lexer, "IPv6 address needs "
                                "square brackets if port is included");
                        return;
                    } else if (!action_parse_port(ctx, &dst.port)) {
                        free(dsts);
                        return;
                    }
                }
            }
            lexer_match(ctx->lexer, LEX_T_COMMA);

            /* Append to dsts. */
            if (n_dsts >= allocated_dsts) {
                dsts = x2nrealloc(dsts, &allocated_dsts, sizeof *dsts);
            }
            dsts[n_dsts++] = dst;
        }
    }

    struct ovnact_ct_lb *cl = ovnact_put_CT_LB(ctx->ovnacts);
    cl->ltable = ctx->pp->cur_ltable + 1;
    cl->dsts = dsts;
    cl->n_dsts = n_dsts;
}

static void
format_CT_LB(const struct ovnact_ct_lb *cl, struct ds *s)
{
    ds_put_cstr(s, "ct_lb");
    if (cl->n_dsts) {
        ds_put_char(s, '(');
        for (size_t i = 0; i < cl->n_dsts; i++) {
            if (i) {
                ds_put_cstr(s, ", ");
            }

            const struct ovnact_ct_lb_dst *dst = &cl->dsts[i];
            if (dst->family == AF_INET) {
                ds_put_format(s, IP_FMT, IP_ARGS(dst->ipv4));
                if (dst->port) {
                    ds_put_format(s, ":%"PRIu16, dst->port);
                }
            } else {
                if (dst->port) {
                    ds_put_char(s, '[');
                }
                ipv6_format_addr(&dst->ipv6, s);
                if (dst->port) {
                    ds_put_format(s, "]:%"PRIu16, dst->port);
                }
            }
        }
        ds_put_char(s, ')');
    }
    ds_put_char(s, ';');
}

static void
encode_CT_LB(const struct ovnact_ct_lb *cl,
             const struct ovnact_encode_params *ep,
             struct ofpbuf *ofpacts)
{
    uint8_t recirc_table = cl->ltable + first_ptable(ep, ep->pipeline);
    if (!cl->n_dsts) {
        /* ct_lb without any destinations means that this is an established
         * connection and we just need to do a NAT. */
        const size_t ct_offset = ofpacts->size;
        ofpbuf_pull(ofpacts, ct_offset);

        struct ofpact_conntrack *ct = ofpact_put_CT(ofpacts);
        struct ofpact_nat *nat;
        size_t nat_offset;
        ct->zone_src.field = ep->is_switch ? mf_from_id(MFF_LOG_CT_ZONE)
                                : mf_from_id(MFF_LOG_DNAT_ZONE);
        ct->zone_src.ofs = 0;
        ct->zone_src.n_bits = 16;
        ct->flags = 0;
        ct->recirc_table = recirc_table;
        ct->alg = 0;

        nat_offset = ofpacts->size;
        ofpbuf_pull(ofpacts, nat_offset);

        nat = ofpact_put_NAT(ofpacts);
        nat->flags = 0;
        nat->range_af = AF_UNSPEC;

        ofpacts->header = ofpbuf_push_uninit(ofpacts, nat_offset);
        ct = ofpacts->header;
        ofpact_finish(ofpacts, &ct->ofpact);
        ofpbuf_push_uninit(ofpacts, ct_offset);
        return;
    }

    uint32_t table_id = 0;
    struct ofpact_group *og;
    uint32_t zone_reg = ep->is_switch ? MFF_LOG_CT_ZONE - MFF_REG0
                            : MFF_LOG_DNAT_ZONE - MFF_REG0;

    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "type=select,selection_method=dp_hash");

    BUILD_ASSERT(MFF_LOG_CT_ZONE >= MFF_REG0);
    BUILD_ASSERT(MFF_LOG_CT_ZONE < MFF_REG0 + FLOW_N_REGS);
    BUILD_ASSERT(MFF_LOG_DNAT_ZONE >= MFF_REG0);
    BUILD_ASSERT(MFF_LOG_DNAT_ZONE < MFF_REG0 + FLOW_N_REGS);
    for (size_t bucket_id = 0; bucket_id < cl->n_dsts; bucket_id++) {
        const struct ovnact_ct_lb_dst *dst = &cl->dsts[bucket_id];
        char ip_addr[INET6_ADDRSTRLEN];
        if (dst->family == AF_INET) {
            inet_ntop(AF_INET, &dst->ipv4, ip_addr, sizeof ip_addr);
        } else {
            inet_ntop(AF_INET6, &dst->ipv6, ip_addr, sizeof ip_addr);
        }
        ds_put_format(&ds, ",bucket=bucket_id=%"PRIuSIZE",weight:100,actions="
                      "ct(nat(dst=%s%s%s", bucket_id,
                      dst->family == AF_INET6 && dst->port ? "[" : "",
                      ip_addr,
                      dst->family == AF_INET6 && dst->port ? "]" : "");
        if (dst->port) {
            ds_put_format(&ds, ":%"PRIu16, dst->port);
        }
        ds_put_format(&ds, "),commit,table=%d,zone=NXM_NX_REG%d[0..15])",
                      recirc_table, zone_reg);
    }

    table_id = ovn_extend_table_assign_id(ep->group_table, ds_cstr(&ds),
                                          ep->lflow_uuid);
    ds_destroy(&ds);
    if (table_id == EXT_TABLE_ID_INVALID) {
        return;
    }

    /* Create an action to set the group. */
    og = ofpact_put_GROUP(ofpacts);
    og->group_id = table_id;
}

static void
ovnact_ct_lb_free(struct ovnact_ct_lb *ct_lb)
{
    free(ct_lb->dsts);
}

static void
format_CT_CLEAR(const struct ovnact_null *null OVS_UNUSED, struct ds *s)
{
    ds_put_cstr(s, "ct_clear;");
}

static void
encode_CT_CLEAR(const struct ovnact_null *null OVS_UNUSED,
                const struct ovnact_encode_params *ep OVS_UNUSED,
                struct ofpbuf *ofpacts)
{
    ofpact_put_CT_CLEAR(ofpacts);
}

/* Implements the "arp", "nd_na", and "clone" actions, which execute nested
 * actions on a packet derived from the one being processed. */
static void
parse_nested_action(struct action_context *ctx, enum ovnact_type type,
                    const char *prereq)
{
    if (!lexer_force_match(ctx->lexer, LEX_T_LCURLY)) {
        return;
    }

    if (ctx->depth + 1 == MAX_NESTED_ACTION_DEPTH) {
        lexer_error(ctx->lexer, "maximum depth of nested actions reached");
        return;
    }

    uint64_t stub[1024 / 8];
    struct ofpbuf nested = OFPBUF_STUB_INITIALIZER(stub);

    struct action_context inner_ctx = {
        .pp = ctx->pp,
        .lexer = ctx->lexer,
        .ovnacts = &nested,
        .prereqs = NULL,
        .depth = ctx->depth + 1,
    };
    parse_actions(&inner_ctx, LEX_T_RCURLY);

    if (prereq) {
        /* XXX Not really sure what we should do with prerequisites for "arp"
         * and "nd_na" actions. */
        expr_destroy(inner_ctx.prereqs);
        add_prerequisite(ctx, prereq);
    } else {
        /* For "clone", the inner prerequisites should just add to the outer
         * ones. */
        ctx->prereqs = expr_combine(EXPR_T_AND,
                                    inner_ctx.prereqs, ctx->prereqs);
    }

    if (inner_ctx.lexer->error) {
        ovnacts_free(nested.data, nested.size);
        ofpbuf_uninit(&nested);
        return;
    }

    struct ovnact_nest *on = ovnact_put(ctx->ovnacts, type,
                                        OVNACT_ALIGN(sizeof *on));
    on->nested_len = nested.size;
    on->nested = ofpbuf_steal_data(&nested);
}

static void
parse_ARP(struct action_context *ctx)
{
    parse_nested_action(ctx, OVNACT_ARP, "ip4");
}

static void
parse_ICMP4(struct action_context *ctx)
{
    parse_nested_action(ctx, OVNACT_ICMP4, "ip4");
}

static void
parse_ICMP4_ERROR(struct action_context *ctx)
{
    parse_nested_action(ctx, OVNACT_ICMP4_ERROR, "ip4");
}

static void
parse_ICMP6(struct action_context *ctx)
{
    parse_nested_action(ctx, OVNACT_ICMP6, "ip6");
}

static void
parse_TCP_RESET(struct action_context *ctx)
{
    parse_nested_action(ctx, OVNACT_TCP_RESET, "tcp");
}

static void
parse_ND_NA(struct action_context *ctx)
{
    parse_nested_action(ctx, OVNACT_ND_NA, "nd_ns");
}

static void
parse_ND_NA_ROUTER(struct action_context *ctx)
{
    parse_nested_action(ctx, OVNACT_ND_NA_ROUTER, "nd_ns");
}

static void
parse_ND_NS(struct action_context *ctx)
{
    parse_nested_action(ctx, OVNACT_ND_NS, "ip6");
}

static void
parse_CLONE(struct action_context *ctx)
{
    parse_nested_action(ctx, OVNACT_CLONE, NULL);
}

static void
format_nested_action(const struct ovnact_nest *on, const char *name,
                     struct ds *s)
{
    ds_put_format(s, "%s { ", name);
    ovnacts_format(on->nested, on->nested_len, s);
    ds_put_format(s, " };");
}

static void
format_ARP(const struct ovnact_nest *nest, struct ds *s)
{
    format_nested_action(nest, "arp", s);
}

static void
format_ICMP4(const struct ovnact_nest *nest, struct ds *s)
{
    format_nested_action(nest, "icmp4", s);
}

static void
format_ICMP4_ERROR(const struct ovnact_nest *nest, struct ds *s)
{
    format_nested_action(nest, "icmp4_error", s);
}

static void
format_ICMP6(const struct ovnact_nest *nest, struct ds *s)
{
    format_nested_action(nest, "icmp6", s);
}

static void
format_IGMP(const struct ovnact_null *a OVS_UNUSED, struct ds *s)
{
    ds_put_cstr(s, "igmp;");
}

static void
format_TCP_RESET(const struct ovnact_nest *nest, struct ds *s)
{
    format_nested_action(nest, "tcp_reset", s);
}

static void
format_ND_NA(const struct ovnact_nest *nest, struct ds *s)
{
    format_nested_action(nest, "nd_na", s);
}

static void
format_ND_NA_ROUTER(const struct ovnact_nest *nest, struct ds *s)
{
    format_nested_action(nest, "nd_na_router", s);
}

static void
format_ND_NS(const struct ovnact_nest *nest, struct ds *s)
{
    format_nested_action(nest, "nd_ns", s);
}

static void
format_CLONE(const struct ovnact_nest *nest, struct ds *s)
{
    format_nested_action(nest, "clone", s);
}

static void
format_TRIGGER_EVENT(const struct ovnact_controller_event *event,
                     struct ds *s)
{
    ds_put_format(s, "trigger_event(event = \"%s\"",
                  event_to_string(event->event_type));
    for (const struct ovnact_gen_option *o = event->options;
         o < &event->options[event->n_options]; o++) {
        ds_put_cstr(s, ", ");
        ds_put_format(s, "%s = ", o->option->name);
        expr_constant_set_format(&o->value, s);
    }
    ds_put_cstr(s, ");");
}

static void
encode_nested_actions(const struct ovnact_nest *on,
                      const struct ovnact_encode_params *ep,
                      enum action_opcode opcode,
                      struct ofpbuf *ofpacts)
{
    /* Convert nested actions into ofpacts. */
    uint64_t inner_ofpacts_stub[1024 / 8];
    struct ofpbuf inner_ofpacts = OFPBUF_STUB_INITIALIZER(inner_ofpacts_stub);
    ovnacts_encode(on->nested, on->nested_len, ep, &inner_ofpacts);

    /* Add a "controller" action with the actions nested inside "{...}",
     * converted to OpenFlow, as its userdata.  ovn-controller will convert the
     * packet to ARP or NA and then send the packet and actions back to the
     * switch inside an OFPT_PACKET_OUT message. */
    size_t oc_offset = encode_start_controller_op(opcode, false,
                                                  NX_CTLR_NO_METER, ofpacts);
    ofpacts_put_openflow_actions(inner_ofpacts.data, inner_ofpacts.size,
                                 ofpacts, OFP13_VERSION);
    encode_finish_controller_op(oc_offset, ofpacts);

    /* Free memory. */
    ofpbuf_uninit(&inner_ofpacts);
}

static void
encode_ARP(const struct ovnact_nest *on,
           const struct ovnact_encode_params *ep,
           struct ofpbuf *ofpacts)
{
    encode_nested_actions(on, ep, ACTION_OPCODE_ARP, ofpacts);
}

static void
encode_ICMP4(const struct ovnact_nest *on,
             const struct ovnact_encode_params *ep,
             struct ofpbuf *ofpacts)
{
    encode_nested_actions(on, ep, ACTION_OPCODE_ICMP, ofpacts);
}

static void
encode_ICMP4_ERROR(const struct ovnact_nest *on,
                   const struct ovnact_encode_params *ep,
                   struct ofpbuf *ofpacts)
{
    encode_nested_actions(on, ep, ACTION_OPCODE_ICMP4_ERROR, ofpacts);
}

static void
encode_ICMP6(const struct ovnact_nest *on,
             const struct ovnact_encode_params *ep,
             struct ofpbuf *ofpacts)
{
    encode_nested_actions(on, ep, ACTION_OPCODE_ICMP, ofpacts);
}

static void
encode_IGMP(const struct ovnact_null *a OVS_UNUSED,
            const struct ovnact_encode_params *ep OVS_UNUSED,
            struct ofpbuf *ofpacts)
{
    encode_controller_op(ACTION_OPCODE_IGMP, ofpacts);
}

static void
encode_TCP_RESET(const struct ovnact_nest *on,
                 const struct ovnact_encode_params *ep,
                 struct ofpbuf *ofpacts)
{
    encode_nested_actions(on, ep, ACTION_OPCODE_TCP_RESET, ofpacts);
}

static void
encode_ND_NA(const struct ovnact_nest *on,
             const struct ovnact_encode_params *ep,
             struct ofpbuf *ofpacts)
{
    encode_nested_actions(on, ep, ACTION_OPCODE_ND_NA, ofpacts);
}

static void
encode_ND_NA_ROUTER(const struct ovnact_nest *on,
             const struct ovnact_encode_params *ep,
             struct ofpbuf *ofpacts)
{
    encode_nested_actions(on, ep, ACTION_OPCODE_ND_NA_ROUTER, ofpacts);
}

static void
encode_ND_NS(const struct ovnact_nest *on,
             const struct ovnact_encode_params *ep,
             struct ofpbuf *ofpacts)
{
    encode_nested_actions(on, ep, ACTION_OPCODE_ND_NS, ofpacts);
}

static void
encode_CLONE(const struct ovnact_nest *on,
             const struct ovnact_encode_params *ep,
             struct ofpbuf *ofpacts)
{
    size_t ofs = ofpacts->size;
    ofpact_put_CLONE(ofpacts);
    ovnacts_encode(on->nested, on->nested_len, ep, ofpacts);

    struct ofpact_nest *clone = ofpbuf_at_assert(ofpacts, ofs, sizeof *clone);
    ofpacts->header = clone;
    ofpact_finish_CLONE(ofpacts, &clone);
}

static void
encode_event_empty_lb_backends_opts(struct ofpbuf *ofpacts,
        const struct ovnact_controller_event *event)
{
    for (const struct ovnact_gen_option *o = event->options;
         o < &event->options[event->n_options]; o++) {
        struct controller_event_opt_header *hdr =
            ofpbuf_put_uninit(ofpacts, sizeof *hdr);
        const union expr_constant *c = o->value.values;
        size_t size;
        hdr->opt_code = htons(o->option->code);
        if (!strcmp(o->option->type, "str")) {
            size = strlen(c->string);
            hdr->size = htons(size);
            ofpbuf_put(ofpacts, c->string, size);
        } else {
            /* All empty_lb_backends fields are of type 'str' */
            OVS_NOT_REACHED();
        }
    }
}

static void
encode_TRIGGER_EVENT(const struct ovnact_controller_event *event,
                     const struct ovnact_encode_params *ep OVS_UNUSED,
                     struct ofpbuf *ofpacts)
{
    size_t oc_offset;

    oc_offset = encode_start_controller_op(ACTION_OPCODE_EVENT, false,
                                           NX_CTLR_NO_METER, ofpacts);
    ovs_be32 ofs = htonl(event->event_type);
    ofpbuf_put(ofpacts, &ofs, sizeof ofs);

    switch (event->event_type) {
    case OVN_EVENT_EMPTY_LB_BACKENDS:
        encode_event_empty_lb_backends_opts(ofpacts, event);
        break;
    case OVN_EVENT_MAX:
    default:
        OVS_NOT_REACHED();
    }

    encode_finish_controller_op(oc_offset, ofpacts);
}

static void
ovnact_nest_free(struct ovnact_nest *on)
{
    ovnacts_free(on->nested, on->nested_len);
    free(on->nested);
}

static void
parse_get_mac_bind(struct action_context *ctx, int width,
                   struct ovnact_get_mac_bind *get_mac)
{
    lexer_force_match(ctx->lexer, LEX_T_LPAREN);
    action_parse_field(ctx, 0, false, &get_mac->port);
    lexer_force_match(ctx->lexer, LEX_T_COMMA);
    action_parse_field(ctx, width, false, &get_mac->ip);
    lexer_force_match(ctx->lexer, LEX_T_RPAREN);
}

static void
format_get_mac_bind(const struct ovnact_get_mac_bind *get_mac,
                    const char *name, struct ds *s)
{
    ds_put_format(s, "%s(", name);
    expr_field_format(&get_mac->port, s);
    ds_put_cstr(s, ", ");
    expr_field_format(&get_mac->ip, s);
    ds_put_cstr(s, ");");
}

static void
format_GET_ARP(const struct ovnact_get_mac_bind *get_mac, struct ds *s)
{
    format_get_mac_bind(get_mac, "get_arp", s);
}

static void
format_GET_ND(const struct ovnact_get_mac_bind *get_mac, struct ds *s)
{
    format_get_mac_bind(get_mac, "get_nd", s);
}

static void
encode_get_mac(const struct ovnact_get_mac_bind *get_mac,
               enum mf_field_id ip_field,
               const struct ovnact_encode_params *ep,
               struct ofpbuf *ofpacts)
{
    const struct arg args[] = {
        { expr_resolve_field(&get_mac->port), MFF_LOG_OUTPORT },
        { expr_resolve_field(&get_mac->ip), ip_field },
    };
    encode_setup_args(args, ARRAY_SIZE(args), ofpacts);

    put_load(0, MFF_ETH_DST, 0, 48, ofpacts);
    emit_resubmit(ofpacts, ep->mac_bind_ptable);

    encode_restore_args(args, ARRAY_SIZE(args), ofpacts);
}

static void
encode_GET_ARP(const struct ovnact_get_mac_bind *get_mac,
               const struct ovnact_encode_params *ep,
               struct ofpbuf *ofpacts)
{
    encode_get_mac(get_mac, MFF_REG0, ep, ofpacts);
}

static void
encode_GET_ND(const struct ovnact_get_mac_bind *get_mac,
              const struct ovnact_encode_params *ep,
              struct ofpbuf *ofpacts)
{
    encode_get_mac(get_mac, MFF_XXREG0, ep, ofpacts);
}

static void
ovnact_get_mac_bind_free(struct ovnact_get_mac_bind *get_mac OVS_UNUSED)
{
}

static void
parse_put_mac_bind(struct action_context *ctx, int width,
                   struct ovnact_put_mac_bind *put_mac)
{
    lexer_force_match(ctx->lexer, LEX_T_LPAREN);
    action_parse_field(ctx, 0, false, &put_mac->port);
    lexer_force_match(ctx->lexer, LEX_T_COMMA);
    action_parse_field(ctx, width, false, &put_mac->ip);
    lexer_force_match(ctx->lexer, LEX_T_COMMA);
    action_parse_field(ctx, 48, false, &put_mac->mac);
    lexer_force_match(ctx->lexer, LEX_T_RPAREN);
}

static void
format_put_mac_bind(const struct ovnact_put_mac_bind *put_mac,
                    const char *name, struct ds *s)
{
    ds_put_format(s, "%s(", name);
    expr_field_format(&put_mac->port, s);
    ds_put_cstr(s, ", ");
    expr_field_format(&put_mac->ip, s);
    ds_put_cstr(s, ", ");
    expr_field_format(&put_mac->mac, s);
    ds_put_cstr(s, ");");
}

static void
format_PUT_ARP(const struct ovnact_put_mac_bind *put_mac, struct ds *s)
{
    format_put_mac_bind(put_mac, "put_arp", s);
}

static void
format_PUT_ND(const struct ovnact_put_mac_bind *put_mac, struct ds *s)
{
    format_put_mac_bind(put_mac, "put_nd", s);
}

static void
encode_put_mac(const struct ovnact_put_mac_bind *put_mac,
               enum mf_field_id ip_field, enum action_opcode opcode,
               struct ofpbuf *ofpacts)
{
    const struct arg args[] = {
        { expr_resolve_field(&put_mac->port), MFF_LOG_INPORT },
        { expr_resolve_field(&put_mac->ip), ip_field },
        { expr_resolve_field(&put_mac->mac), MFF_ETH_SRC }
    };
    encode_setup_args(args, ARRAY_SIZE(args), ofpacts);
    encode_controller_op(opcode, ofpacts);
    encode_restore_args(args, ARRAY_SIZE(args), ofpacts);
}

static void
encode_PUT_ARP(const struct ovnact_put_mac_bind *put_mac,
               const struct ovnact_encode_params *ep OVS_UNUSED,
               struct ofpbuf *ofpacts)
{
    encode_put_mac(put_mac, MFF_REG0, ACTION_OPCODE_PUT_ARP, ofpacts);
}

static void
encode_PUT_ND(const struct ovnact_put_mac_bind *put_mac,
              const struct ovnact_encode_params *ep OVS_UNUSED,
              struct ofpbuf *ofpacts)
{
    encode_put_mac(put_mac, MFF_XXREG0, ACTION_OPCODE_PUT_ND, ofpacts);
}

static void
ovnact_put_mac_bind_free(struct ovnact_put_mac_bind *put_mac OVS_UNUSED)
{
}

static void
parse_gen_opt(struct action_context *ctx, struct ovnact_gen_option *o,
              const struct hmap *gen_opts, const char *opts_type)
{
    if (ctx->lexer->token.type != LEX_T_ID) {
        lexer_syntax_error(ctx->lexer, NULL);
        return;
    }

    o->option = gen_opts ? gen_opts_find(gen_opts, ctx->lexer->token.s) : NULL;
    if (!o->option) {
        lexer_syntax_error(ctx->lexer, "expecting %s option name", opts_type);
        return;
    }
    lexer_get(ctx->lexer);

    if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)) {
        return;
    }

    if (!expr_constant_set_parse(ctx->lexer, &o->value)) {
        memset(&o->value, 0, sizeof o->value);
        return;
    }

    if (!strcmp(o->option->type, "str")) {
        if (o->value.type != EXPR_C_STRING) {
            lexer_error(ctx->lexer, "%s option %s requires string value.",
                        opts_type, o->option->name);
            return;
        }
    } else {
        if (o->value.type != EXPR_C_INTEGER) {
            lexer_error(ctx->lexer, "%s option %s requires numeric value.",
                        opts_type, o->option->name);
            return;
        }
    }
}

static const struct ovnact_gen_option *
find_offerip(const struct ovnact_gen_option *options, size_t n)
{
    for (const struct ovnact_gen_option *o = options; o < &options[n]; o++) {
        if (o->option->code == 0) {
            return o;
        }
    }
    return NULL;
}

static void
free_gen_options(struct ovnact_gen_option *options, size_t n)
{
    for (struct ovnact_gen_option *o = options; o < &options[n]; o++) {
        expr_constant_set_destroy(&o->value);
    }
    free(options);
}

static void
validate_empty_lb_backends(struct action_context *ctx,
                           const struct ovnact_gen_option *options,
                           size_t n_options)
{
    for (const struct ovnact_gen_option *o = options;
         o < &options[n_options]; o++) {
        const union expr_constant *c = o->value.values;
        struct sockaddr_storage ss;
        struct uuid uuid;

        if (o->value.n_values > 1 || !c->string) {
            lexer_error(ctx->lexer, "Invalid value for \"%s\" option",
                        o->option->name);
            return;
        }

        switch (o->option->code) {
        case EMPTY_LB_VIP:
            if (!inet_parse_active(c->string, 0, &ss, false)) {
                lexer_error(ctx->lexer, "Invalid load balancer VIP '%s'",
                            c->string);
                return;
            }
            break;
        case EMPTY_LB_PROTOCOL:
            if (strcmp(c->string, "tcp") && strcmp(c->string, "udp")) {
                lexer_error(ctx->lexer,
                    "Load balancer protocol '%s' is not 'tcp' or 'udp'",
                    c->string);
                return;
            }
            break;
        case EMPTY_LB_LOAD_BALANCER:
            if (!uuid_from_string(&uuid, c->string)) {
                lexer_error(ctx->lexer, "Load balancer '%s' is not a UUID",
                            c->string);
                return;
            }
            break;
        }
    }
}

static void
parse_trigger_event(struct action_context *ctx,
                    struct ovnact_controller_event *event)
{
    int event_type = 0;

    lexer_force_match(ctx->lexer, LEX_T_LPAREN);

    /* Event type must be listed first */
    if (!lexer_match_id(ctx->lexer, "event")) {
        lexer_syntax_error(ctx->lexer, "Expecting 'event' option");
        return;
    }
    if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)) {
        return;
    }

    if (ctx->lexer->token.type != LEX_T_STRING ||
        strlen(ctx->lexer->token.s) >= 64) {
        lexer_syntax_error(ctx->lexer, "Expecting string");
        return;
    }

    event_type = string_to_event(ctx->lexer->token.s);
    if (event_type < 0 || event_type >= OVN_EVENT_MAX) {
        lexer_syntax_error(ctx->lexer, "Unknown event '%d'", event_type);
        return;
    }

    event->event_type = event_type;
    lexer_get(ctx->lexer);

    lexer_match(ctx->lexer, LEX_T_COMMA);

    size_t allocated_options = 0;
    while (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
        if (event->n_options >= allocated_options) {
            event->options = x2nrealloc(event->options, &allocated_options,
                                     sizeof *event->options);
        }

        struct ovnact_gen_option *o = &event->options[event->n_options++];
        memset(o, 0, sizeof *o);
        parse_gen_opt(ctx, o,
                      &ctx->pp->controller_event_opts->event_opts[event_type],
                      event_to_string(event_type));
        if (ctx->lexer->error) {
            return;
        }

        lexer_match(ctx->lexer, LEX_T_COMMA);
    }

    switch (event_type) {
    case OVN_EVENT_EMPTY_LB_BACKENDS:
        validate_empty_lb_backends(ctx, event->options, event->n_options);
        break;
    default:
        OVS_NOT_REACHED();
    }
}

static void
ovnact_controller_event_free(struct ovnact_controller_event *event)
{
    free_gen_options(event->options, event->n_options);
}

static void
parse_put_opts(struct action_context *ctx, const struct expr_field *dst,
               struct ovnact_put_opts *po, const struct hmap *gen_opts,
               const char *opts_type)
{
    lexer_get(ctx->lexer); /* Skip put_dhcp[v6]_opts / put_nd_ra_opts. */
    lexer_get(ctx->lexer); /* Skip '('. */

    /* Validate that the destination is a 1-bit, modifiable field. */
    char *error = expr_type_check(dst, 1, true);
    if (error) {
        lexer_error(ctx->lexer, "%s", error);
        free(error);
        return;
    }
    po->dst = *dst;

    size_t allocated_options = 0;
    while (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
        if (po->n_options >= allocated_options) {
            po->options = x2nrealloc(po->options, &allocated_options,
                                     sizeof *po->options);
        }

        struct ovnact_gen_option *o = &po->options[po->n_options++];
        memset(o, 0, sizeof *o);
        parse_gen_opt(ctx, o, gen_opts, opts_type);
        if (ctx->lexer->error) {
            return;
        }

        lexer_match(ctx->lexer, LEX_T_COMMA);
    }
}

/* Parses the "put_dhcp_opts" and "put_dhcpv6_opts" actions.
 *
 * The caller has already consumed "<dst> =", so this just parses the rest. */
static void
parse_put_dhcp_opts(struct action_context *ctx,
                    const struct expr_field *dst,
                    struct ovnact_put_opts *po)
{
    const struct hmap *dhcp_opts =
        (po->ovnact.type == OVNACT_PUT_DHCPV6_OPTS) ?
            ctx->pp->dhcpv6_opts : ctx->pp->dhcp_opts;
    const char *opts_type =
        (po->ovnact.type == OVNACT_PUT_DHCPV6_OPTS) ? "DHCPv6" : "DHCPv4";

    parse_put_opts(ctx, dst, po, dhcp_opts, opts_type);

    if (!ctx->lexer->error && po->ovnact.type == OVNACT_PUT_DHCPV4_OPTS
        && !find_offerip(po->options, po->n_options)) {
        lexer_error(ctx->lexer,
                    "put_dhcp_opts requires offerip to be specified.");
        return;
    }
}

static void
format_put_opts(const char *name, const struct ovnact_put_opts *pdo,
                struct ds *s)
{
    expr_field_format(&pdo->dst, s);
    ds_put_format(s, " = %s(", name);
    for (const struct ovnact_gen_option *o = pdo->options;
         o < &pdo->options[pdo->n_options]; o++) {
        if (o != pdo->options) {
            ds_put_cstr(s, ", ");
        }
        ds_put_format(s, "%s = ", o->option->name);
        expr_constant_set_format(&o->value, s);
    }
    ds_put_cstr(s, ");");
}

static void
format_PUT_DHCPV4_OPTS(const struct ovnact_put_opts *pdo, struct ds *s)
{
    format_put_opts("put_dhcp_opts", pdo, s);
}

static void
format_PUT_DHCPV6_OPTS(const struct ovnact_put_opts *pdo, struct ds *s)
{
    format_put_opts("put_dhcpv6_opts", pdo, s);
}

static void
encode_put_dhcpv4_option(const struct ovnact_gen_option *o,
                         struct ofpbuf *ofpacts)
{
    uint8_t *opt_header = ofpbuf_put_zeros(ofpacts, 2);
    opt_header[0] = o->option->code;

    const union expr_constant *c = o->value.values;
    size_t n_values = o->value.n_values;
    if (!strcmp(o->option->type, "bool") ||
        !strcmp(o->option->type, "uint8")) {
        opt_header[1] = 1;
        ofpbuf_put(ofpacts, &c->value.u8_val, 1);
    } else if (!strcmp(o->option->type, "uint16")) {
        opt_header[1] = 2;
        ofpbuf_put(ofpacts, &c->value.be16_int, 2);
    } else if (!strcmp(o->option->type, "uint32")) {
        opt_header[1] = 4;
        ofpbuf_put(ofpacts, &c->value.be32_int, 4);
    } else if (!strcmp(o->option->type, "ipv4")) {
        opt_header[1] = n_values * sizeof(ovs_be32);
        for (size_t i = 0; i < n_values; i++) {
            ofpbuf_put(ofpacts, &c[i].value.ipv4, sizeof(ovs_be32));
        }
    } else if (!strcmp(o->option->type, "static_routes")) {
        size_t no_of_routes = n_values;
        if (no_of_routes % 2) {
            no_of_routes -= 1;
        }
        opt_header[1] = 0;

        /* Calculating the length of this option first because when
         * we call ofpbuf_put, it might reallocate the buffer if the
         * tail room is short making "opt_header" pointer invalid.
         * So running the for loop twice.
         */
        for (size_t i = 0; i < no_of_routes; i += 2) {
            uint8_t plen = 32;
            if (c[i].masked) {
                plen = (uint8_t) ip_count_cidr_bits(c[i].mask.ipv4);
            }
            opt_header[1] += (1 + DIV_ROUND_UP(plen, 8) + sizeof(ovs_be32));
        }

        /* Copied from RFC 3442. Please refer to this RFC for the format of
         * the classless static route option.
         *
         *  The following table contains some examples of how various subnet
         *  number/mask combinations can be encoded:
         *
         *  Subnet number   Subnet mask      Destination descriptor
         *  0               0                0
         *  10.0.0.0        255.0.0.0        8.10
         *  10.0.0.0        255.255.255.0    24.10.0.0
         *  10.17.0.0       255.255.0.0      16.10.17
         *  10.27.129.0     255.255.255.0    24.10.27.129
         *  10.229.0.128    255.255.255.128  25.10.229.0.128
         *  10.198.122.47   255.255.255.255  32.10.198.122.47
         */

        for (size_t i = 0; i < no_of_routes; i += 2) {
            uint8_t plen = 32;
            if (c[i].masked) {
                plen = ip_count_cidr_bits(c[i].mask.ipv4);
            }
            ofpbuf_put(ofpacts, &plen, 1);
            ofpbuf_put(ofpacts, &c[i].value.ipv4, DIV_ROUND_UP(plen, 8));
            ofpbuf_put(ofpacts, &c[i + 1].value.ipv4,
                       sizeof(ovs_be32));
        }
    } else if (!strcmp(o->option->type, "str")) {
        opt_header[1] = strlen(c->string);
        ofpbuf_put(ofpacts, c->string, opt_header[1]);
    }
}

static void
encode_put_dhcpv6_option(const struct ovnact_gen_option *o,
                         struct ofpbuf *ofpacts)
{
    struct dhcp_opt6_header *opt = ofpbuf_put_uninit(ofpacts, sizeof *opt);
    const union expr_constant *c = o->value.values;
    size_t n_values = o->value.n_values;
    size_t size;

    opt->opt_code = htons(o->option->code);

    if (!strcmp(o->option->type, "ipv6")) {
        size = n_values * sizeof(struct in6_addr);
        opt->size = htons(size);
        for (size_t i = 0; i < n_values; i++) {
            ofpbuf_put(ofpacts, &c[i].value.ipv6, sizeof(struct in6_addr));
        }
    } else if (!strcmp(o->option->type, "mac")) {
        size = sizeof(struct eth_addr);
        opt->size = htons(size);
        ofpbuf_put(ofpacts, &c->value.mac, size);
    } else if (!strcmp(o->option->type, "str")) {
        size = strlen(c->string);
        opt->size = htons(size);
        ofpbuf_put(ofpacts, c->string, size);
    }
}

static void
encode_PUT_DHCPV4_OPTS(const struct ovnact_put_opts *pdo,
                       const struct ovnact_encode_params *ep OVS_UNUSED,
                       struct ofpbuf *ofpacts)
{
    struct mf_subfield dst = expr_resolve_field(&pdo->dst);

    size_t oc_offset = encode_start_controller_op(ACTION_OPCODE_PUT_DHCP_OPTS,
                                                  true, NX_CTLR_NO_METER,
                                                  ofpacts);
    nx_put_header(ofpacts, dst.field->id, OFP13_VERSION, false);
    ovs_be32 ofs = htonl(dst.ofs);
    ofpbuf_put(ofpacts, &ofs, sizeof ofs);

    /* Encode the offerip option first, because it's a special case and needs
     * to be first in the actual DHCP response, and then encode the rest
     * (skipping offerip the second time around). */
    const struct ovnact_gen_option *offerip_opt = find_offerip(
        pdo->options, pdo->n_options);
    ovs_be32 offerip = offerip_opt->value.values[0].value.ipv4;
    ofpbuf_put(ofpacts, &offerip, sizeof offerip);

    for (const struct ovnact_gen_option *o = pdo->options;
         o < &pdo->options[pdo->n_options]; o++) {
        if (o != offerip_opt) {
            encode_put_dhcpv4_option(o, ofpacts);
        }
    }

    encode_finish_controller_op(oc_offset, ofpacts);
}

static void
encode_PUT_DHCPV6_OPTS(const struct ovnact_put_opts *pdo,
                       const struct ovnact_encode_params *ep OVS_UNUSED,
                       struct ofpbuf *ofpacts)
{
    struct mf_subfield dst = expr_resolve_field(&pdo->dst);

    size_t oc_offset = encode_start_controller_op(
        ACTION_OPCODE_PUT_DHCPV6_OPTS, true, NX_CTLR_NO_METER, ofpacts);
    nx_put_header(ofpacts, dst.field->id, OFP13_VERSION, false);
    ovs_be32 ofs = htonl(dst.ofs);
    ofpbuf_put(ofpacts, &ofs, sizeof ofs);

    for (const struct ovnact_gen_option *o = pdo->options;
         o < &pdo->options[pdo->n_options]; o++) {
        encode_put_dhcpv6_option(o, ofpacts);
    }

    encode_finish_controller_op(oc_offset, ofpacts);
}

static void
ovnact_put_opts_free(struct ovnact_put_opts *pdo)
{
    free_gen_options(pdo->options, pdo->n_options);
}

static void
parse_SET_QUEUE(struct action_context *ctx)
{
    int queue_id;

    if (!lexer_force_match(ctx->lexer, LEX_T_LPAREN)
        || !lexer_get_int(ctx->lexer, &queue_id)
        || !lexer_force_match(ctx->lexer, LEX_T_RPAREN)) {
        return;
    }

    if (queue_id < QDISC_MIN_QUEUE_ID || queue_id > QDISC_MAX_QUEUE_ID) {
        lexer_error(ctx->lexer, "Queue ID %d for set_queue is "
                    "not in valid range %d to %d.",
                    queue_id, QDISC_MIN_QUEUE_ID, QDISC_MAX_QUEUE_ID);
        return;
    }

    ovnact_put_SET_QUEUE(ctx->ovnacts)->queue_id = queue_id;
}

static void
format_SET_QUEUE(const struct ovnact_set_queue *set_queue, struct ds *s)
{
    ds_put_format(s, "set_queue(%d);", set_queue->queue_id);
}

static void
encode_SET_QUEUE(const struct ovnact_set_queue *set_queue,
                 const struct ovnact_encode_params *ep OVS_UNUSED,
                 struct ofpbuf *ofpacts)
{
    ofpact_put_SET_QUEUE(ofpacts)->queue_id = set_queue->queue_id;
}

static void
ovnact_set_queue_free(struct ovnact_set_queue *a OVS_UNUSED)
{
}

static void
parse_dns_lookup(struct action_context *ctx, const struct expr_field *dst,
                 struct ovnact_dns_lookup *dl)
{
    lexer_get(ctx->lexer); /* Skip dns_lookup. */
    lexer_get(ctx->lexer); /* Skip '('. */
    if (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
        lexer_error(ctx->lexer, "dns_lookup doesn't take any parameters");
        return;
    }
    /* Validate that the destination is a 1-bit, modifiable field. */
    char *error = expr_type_check(dst, 1, true);
    if (error) {
        lexer_error(ctx->lexer, "%s", error);
        free(error);
        return;
    }
    dl->dst = *dst;
    add_prerequisite(ctx, "udp");
}

static void
format_DNS_LOOKUP(const struct ovnact_dns_lookup *dl, struct ds *s)
{
    expr_field_format(&dl->dst, s);
    ds_put_cstr(s, " = dns_lookup();");
}

static void
encode_DNS_LOOKUP(const struct ovnact_dns_lookup *dl,
                  const struct ovnact_encode_params *ep OVS_UNUSED,
                  struct ofpbuf *ofpacts)
{
    struct mf_subfield dst = expr_resolve_field(&dl->dst);

    size_t oc_offset = encode_start_controller_op(ACTION_OPCODE_DNS_LOOKUP,
                                                  true, NX_CTLR_NO_METER,
                                                  ofpacts);
    nx_put_header(ofpacts, dst.field->id, OFP13_VERSION, false);
    ovs_be32 ofs = htonl(dst.ofs);
    ofpbuf_put(ofpacts, &ofs, sizeof ofs);
    encode_finish_controller_op(oc_offset, ofpacts);
}


static void
ovnact_dns_lookup_free(struct ovnact_dns_lookup *dl OVS_UNUSED)
{
}

/* Parses the "put_nd_ra_opts" action.
 * The caller has already consumed "<dst> =", so this just parses the rest. */
static void
parse_put_nd_ra_opts(struct action_context *ctx, const struct expr_field *dst,
                     struct ovnact_put_opts *po)
{
    parse_put_opts(ctx, dst, po, ctx->pp->nd_ra_opts, "IPv6 ND RA");

    if (ctx->lexer->error) {
        return;
    }

    bool addr_mode_stateful = false;
    bool prefix_set = false;
    bool slla_present = false;
    /* Let's validate the options. */
    for (struct ovnact_gen_option *o = po->options;
            o < &po->options[po->n_options]; o++) {
        const union expr_constant *c = o->value.values;
        if (o->value.n_values > 1) {
            lexer_error(ctx->lexer, "Invalid value for \"%s\" option",
                        o->option->name);
            return;
        }

        bool ok = true;
        switch (o->option->code) {
        case ND_RA_FLAG_ADDR_MODE:
            ok = (c->string && (!strcmp(c->string, "slaac") ||
                                !strcmp(c->string, "dhcpv6_stateful") ||
                                !strcmp(c->string, "dhcpv6_stateless")));
            if (ok && !strcmp(c->string, "dhcpv6_stateful")) {
                addr_mode_stateful = true;
            }
            break;

        case ND_OPT_SOURCE_LINKADDR:
            ok = c->format == LEX_F_ETHERNET;
            slla_present = true;
            break;

        case ND_OPT_PREFIX_INFORMATION:
            ok = c->format == LEX_F_IPV6 && c->masked;
            prefix_set = true;
            break;

        case ND_OPT_MTU:
            ok = c->format == LEX_F_DECIMAL;
            break;
        }

        if (!ok) {
            lexer_error(ctx->lexer, "Invalid value for \"%s\" option",
                        o->option->name);
            return;
        }
    }

    if (!slla_present) {
        lexer_error(ctx->lexer, "slla option not present");
        return;
    }

    if (!addr_mode_stateful && !prefix_set) {
        lexer_error(ctx->lexer, "prefix option needs "
                    "to be set when address mode is slaac/dhcpv6_stateless.");
        return;
    }

    add_prerequisite(ctx, "ip6");
}

static void
format_PUT_ND_RA_OPTS(const struct ovnact_put_opts *po,
                      struct ds *s)
{
    format_put_opts("put_nd_ra_opts", po, s);
}

static void
encode_put_nd_ra_option(const struct ovnact_gen_option *o,
                        struct ofpbuf *ofpacts, ptrdiff_t ra_offset)
{
    const union expr_constant *c = o->value.values;

    switch (o->option->code) {
    case ND_RA_FLAG_ADDR_MODE:
    {
        struct ovs_ra_msg *ra = ofpbuf_at(ofpacts, ra_offset, sizeof *ra);
        if (!strcmp(c->string, "dhcpv6_stateful")) {
            ra->mo_flags = IPV6_ND_RA_FLAG_MANAGED_ADDR_CONFIG;
        } else if (!strcmp(c->string, "dhcpv6_stateless")) {
            ra->mo_flags = IPV6_ND_RA_FLAG_OTHER_ADDR_CONFIG;
        }
        break;
    }

    case ND_OPT_SOURCE_LINKADDR:
    {
        struct ovs_nd_lla_opt *lla_opt =
            ofpbuf_put_uninit(ofpacts, sizeof *lla_opt);
        lla_opt->type = ND_OPT_SOURCE_LINKADDR;
        lla_opt->len = 1;
        lla_opt->mac = c->value.mac;
        break;
    }

    case ND_OPT_MTU:
    {
        struct ovs_nd_mtu_opt *mtu_opt =
            ofpbuf_put_uninit(ofpacts, sizeof *mtu_opt);
        mtu_opt->type = ND_OPT_MTU;
        mtu_opt->len = 1;
        mtu_opt->reserved = 0;
        put_16aligned_be32(&mtu_opt->mtu, c->value.be32_int);
        break;
    }

    case ND_OPT_PREFIX_INFORMATION:
    {
        struct ovs_nd_prefix_opt *prefix_opt =
            ofpbuf_put_uninit(ofpacts, sizeof *prefix_opt);
        uint8_t prefix_len = ipv6_count_cidr_bits(&c->mask.ipv6);
        struct ovs_ra_msg *ra = ofpbuf_at(ofpacts, ra_offset, sizeof *ra);
        prefix_opt->type = ND_OPT_PREFIX_INFORMATION;
        prefix_opt->len = 4;
        prefix_opt->prefix_len = prefix_len;
        prefix_opt->la_flags = IPV6_ND_RA_OPT_PREFIX_ON_LINK;
        if (!(ra->mo_flags & IPV6_ND_RA_FLAG_MANAGED_ADDR_CONFIG)) {
            prefix_opt->la_flags |= IPV6_ND_RA_OPT_PREFIX_AUTONOMOUS;
        }
        put_16aligned_be32(&prefix_opt->valid_lifetime,
                           htonl(IPV6_ND_RA_OPT_PREFIX_VALID_LIFETIME));
        put_16aligned_be32(&prefix_opt->preferred_lifetime,
                           htonl(IPV6_ND_RA_OPT_PREFIX_PREFERRED_LIFETIME));
        put_16aligned_be32(&prefix_opt->reserved, 0);
        memcpy(prefix_opt->prefix.be32, &c->value.be128[7].be32,
               sizeof(ovs_be32[4]));
        break;
    }
    }
}

static void
encode_PUT_ND_RA_OPTS(const struct ovnact_put_opts *po,
                      const struct ovnact_encode_params *ep OVS_UNUSED,
                      struct ofpbuf *ofpacts)
{
    struct mf_subfield dst = expr_resolve_field(&po->dst);

    size_t oc_offset = encode_start_controller_op(
        ACTION_OPCODE_PUT_ND_RA_OPTS, true, NX_CTLR_NO_METER, ofpacts);
    nx_put_header(ofpacts, dst.field->id, OFP13_VERSION, false);
    ovs_be32 ofs = htonl(dst.ofs);
    ofpbuf_put(ofpacts, &ofs, sizeof ofs);

    /* Frame the complete ICMPv6 Router Advertisement data encoding
     * the ND RA options in it, in the userdata field, so that when
     * pinctrl module receives the ICMPv6 Router Solicitation packet
     * it can copy the userdata field AS IS and resume the packet.
     */
    size_t ra_offset = ofpacts->size;
    struct ovs_ra_msg *ra = ofpbuf_put_zeros(ofpacts, sizeof *ra);
    ra->icmph.icmp6_type = ND_ROUTER_ADVERT;
    ra->cur_hop_limit = IPV6_ND_RA_CUR_HOP_LIMIT;
    ra->mo_flags = 0;
    ra->router_lifetime = htons(IPV6_ND_RA_LIFETIME);

    for (const struct ovnact_gen_option *o = po->options;
         o < &po->options[po->n_options]; o++) {
        encode_put_nd_ra_option(o, ofpacts, ra_offset);
    }

    encode_finish_controller_op(oc_offset, ofpacts);
}


static void
parse_log_arg(struct action_context *ctx, struct ovnact_log *log)
{
    if (lexer_match_id(ctx->lexer, "verdict")) {
        if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)) {
            return;
        }
        if (lexer_match_id(ctx->lexer, "drop")) {
            log->verdict = LOG_VERDICT_DROP;
        } else if (lexer_match_id(ctx->lexer, "reject")) {
            log->verdict = LOG_VERDICT_REJECT;
        } else if (lexer_match_id(ctx->lexer, "allow")) {
            log->verdict = LOG_VERDICT_ALLOW;
        } else {
            lexer_syntax_error(ctx->lexer, "unknown verdict");
            return;
        }
    } else if (lexer_match_id(ctx->lexer, "name")) {
        if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)) {
            return;
        }
        /* If multiple names are given, use the most recent. */
        if (ctx->lexer->token.type == LEX_T_STRING) {
            /* Arbitrarily limit the name length to 64 bytes, since
             * these will be encoded in datapath actions. */
            if (strlen(ctx->lexer->token.s) >= 64) {
                lexer_syntax_error(ctx->lexer, "name must be shorter "
                                               "than 64 characters");
                return;
            }
            free(log->name);
            log->name = xstrdup(ctx->lexer->token.s);
        } else {
            lexer_syntax_error(ctx->lexer, "expecting string");
            return;
        }
        lexer_get(ctx->lexer);
    } else if (lexer_match_id(ctx->lexer, "severity")) {
        if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)) {
            return;
        }
        if (ctx->lexer->token.type == LEX_T_ID) {
            uint8_t severity = log_severity_from_string(ctx->lexer->token.s);
            if (severity != UINT8_MAX) {
                log->severity = severity;
                lexer_get(ctx->lexer);
                return;
            } else {
                lexer_syntax_error(ctx->lexer, "unknown severity");
                return;
            }
        }
        lexer_syntax_error(ctx->lexer, "expecting severity");
    } else if (lexer_match_id(ctx->lexer, "meter")) {
        if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)) {
            return;
        }
        /* If multiple meters are given, use the most recent. */
        if (ctx->lexer->token.type == LEX_T_STRING) {
            free(log->meter);
            log->meter = xstrdup(ctx->lexer->token.s);
        } else {
            lexer_syntax_error(ctx->lexer, "expecting string");
            return;
        }
        lexer_get(ctx->lexer);
    } else {
        lexer_syntax_error(ctx->lexer, NULL);
    }
}

static void
parse_LOG(struct action_context *ctx)
{
    struct ovnact_log *log = ovnact_put_LOG(ctx->ovnacts);

    /* Provide default values. */
    log->severity = LOG_SEVERITY_INFO;
    log->verdict = LOG_VERDICT_UNKNOWN;

    if (lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        while (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
            parse_log_arg(ctx, log);
            if (ctx->lexer->error) {
                return;
            }
            lexer_match(ctx->lexer, LEX_T_COMMA);
        }
    }
    if (log->verdict == LOG_VERDICT_UNKNOWN) {
        lexer_syntax_error(ctx->lexer, "expecting verdict");
    }
}

static void
format_LOG(const struct ovnact_log *log, struct ds *s)
{
    ds_put_cstr(s, "log(");

    if (log->name) {
        ds_put_format(s, "name=\"%s\", ", log->name);
    }

    ds_put_format(s, "verdict=%s, ", log_verdict_to_string(log->verdict));
    ds_put_format(s, "severity=%s", log_severity_to_string(log->severity));

    if (log->meter) {
        ds_put_format(s, ", meter=\"%s\"", log->meter);
    }

    ds_put_cstr(s, ");");
}

static void
encode_LOG(const struct ovnact_log *log,
           const struct ovnact_encode_params *ep, struct ofpbuf *ofpacts)
{
    uint32_t meter_id = NX_CTLR_NO_METER;

    if (log->meter) {
        meter_id = ovn_extend_table_assign_id(ep->meter_table, log->meter,
                                              ep->lflow_uuid);
        if (meter_id == EXT_TABLE_ID_INVALID) {
            VLOG_WARN("Unable to assign id for log meter: %s", log->meter);
            return;
        }
    }

    size_t oc_offset = encode_start_controller_op(ACTION_OPCODE_LOG, false,
                                                  meter_id, ofpacts);

    struct log_pin_header *lph = ofpbuf_put_uninit(ofpacts, sizeof *lph);
    lph->verdict = log->verdict;
    lph->severity = log->severity;

    if (log->name) {
        int name_len = strlen(log->name);
        ofpbuf_put(ofpacts, log->name, name_len);
    }

    encode_finish_controller_op(oc_offset, ofpacts);
}

static void
ovnact_log_free(struct ovnact_log *log)
{
    free(log->name);
    free(log->meter);
}

static void
parse_set_meter_action(struct action_context *ctx)
{
    uint64_t rate = 0;
    uint64_t burst = 0;

    lexer_force_match(ctx->lexer, LEX_T_LPAREN); /* Skip '('. */
    if (ctx->lexer->token.type == LEX_T_INTEGER
        && ctx->lexer->token.format == LEX_F_DECIMAL) {
        rate = ntohll(ctx->lexer->token.value.integer);
    }
    lexer_get(ctx->lexer);
    if (lexer_match(ctx->lexer, LEX_T_COMMA)) {  /* Skip ','. */
        if (ctx->lexer->token.type == LEX_T_INTEGER
            && ctx->lexer->token.format == LEX_F_DECIMAL) {
            burst = ntohll(ctx->lexer->token.value.integer);
        }
        lexer_get(ctx->lexer);
    }
    lexer_force_match(ctx->lexer, LEX_T_RPAREN); /* Skip ')'. */

    if (!rate) {
        lexer_error(ctx->lexer,
                    "Rate %"PRId64" for set_meter is not in valid.",
                    rate);
        return;
    }

    struct ovnact_set_meter *cl = ovnact_put_SET_METER(ctx->ovnacts);
    cl->rate = rate;
    cl->burst = burst;
}

static void
format_SET_METER(const struct ovnact_set_meter *cl, struct ds *s)
{
    if (cl->burst) {
        ds_put_format(s, "set_meter(%"PRId64", %"PRId64");",
                      cl->rate, cl->burst);
    } else {
        ds_put_format(s, "set_meter(%"PRId64");", cl->rate);
    }
}

static void
encode_SET_METER(const struct ovnact_set_meter *cl,
                 const struct ovnact_encode_params *ep,
                 struct ofpbuf *ofpacts)
{
    uint32_t table_id;
    struct ofpact_meter *om;

    /* Use the special "__string:" prefix to indicate that the name
     * describes the meter itself. */
    char *name;
    if (cl->burst) {
        name = xasprintf("__string: kbps burst stats bands=type=drop "
                         "rate=%"PRId64" burst_size=%"PRId64"", cl->rate,
                         cl->burst);
    } else {
        name = xasprintf("__string: kbps stats bands=type=drop "
                         "rate=%"PRId64"", cl->rate);
    }

    table_id = ovn_extend_table_assign_id(ep->meter_table, name,
                                          ep->lflow_uuid);
    free(name);
    if (table_id == EXT_TABLE_ID_INVALID) {
        return;
    }

    /* Create an action to set the meter. */
    om = ofpact_put_METER(ofpacts);
    om->meter_id = table_id;
}

static void
ovnact_set_meter_free(struct ovnact_set_meter *ct OVS_UNUSED)
{
}

static void
format_OVNFIELD_LOAD(const struct ovnact_load *load , struct ds *s)
{
    const struct ovn_field *f = ovn_field_from_name(load->dst.symbol->name);
    switch (f->id) {
    case OVN_ICMP4_FRAG_MTU:
        ds_put_format(s, "%s = %u;", f->name,
                      ntohs(load->imm.value.be16_int));
        break;

    case OVN_FIELD_N_IDS:
    default:
        OVS_NOT_REACHED();
    }
}

static void
encode_OVNFIELD_LOAD(const struct ovnact_load *load,
            const struct ovnact_encode_params *ep OVS_UNUSED,
            struct ofpbuf *ofpacts)
{
    const struct ovn_field *f = ovn_field_from_name(load->dst.symbol->name);
    switch (f->id) {
    case OVN_ICMP4_FRAG_MTU: {
        size_t oc_offset = encode_start_controller_op(
            ACTION_OPCODE_PUT_ICMP4_FRAG_MTU, true, NX_CTLR_NO_METER,
            ofpacts);
        ofpbuf_put(ofpacts, &load->imm.value.be16_int, sizeof(ovs_be16));
        encode_finish_controller_op(oc_offset, ofpacts);
        break;
    }
    case OVN_FIELD_N_IDS:
    default:
        OVS_NOT_REACHED();
    }
}

static void
parse_check_pkt_larger(struct action_context *ctx,
                       const struct expr_field *dst,
                       struct ovnact_check_pkt_larger *cipl)
{
     /* Validate that the destination is a 1-bit, modifiable field. */
    char *error = expr_type_check(dst, 1, true);
    if (error) {
        lexer_error(ctx->lexer, "%s", error);
        free(error);
        return;
    }

    int pkt_len;
    lexer_get(ctx->lexer); /* Skip check_pkt_len. */
    if (!lexer_force_match(ctx->lexer, LEX_T_LPAREN)
        || !lexer_get_int(ctx->lexer, &pkt_len)
        || !lexer_force_match(ctx->lexer, LEX_T_RPAREN)) {
        return;
    }

    cipl->dst = *dst;
    cipl->pkt_len = pkt_len;
}

static void
format_CHECK_PKT_LARGER(const struct ovnact_check_pkt_larger *cipl,
                        struct ds *s)
{
    expr_field_format(&cipl->dst, s);
    ds_put_format(s, " = check_pkt_larger(%d);", cipl->pkt_len);
}

static void
encode_CHECK_PKT_LARGER(const struct ovnact_check_pkt_larger *cipl,
                        const struct ovnact_encode_params *ep OVS_UNUSED,
                        struct ofpbuf *ofpacts)
{
    struct ofpact_check_pkt_larger *check_pkt_larger =
        ofpact_put_CHECK_PKT_LARGER(ofpacts);
    check_pkt_larger->pkt_len = cipl->pkt_len;
    check_pkt_larger->dst = expr_resolve_field(&cipl->dst);
}

static void
ovnact_check_pkt_larger_free(struct ovnact_check_pkt_larger *cipl OVS_UNUSED)
{
}

static void
parse_bind_vport(struct action_context *ctx)
{
    if (!lexer_force_match(ctx->lexer, LEX_T_LPAREN)) {
        return;
    }

    if (ctx->lexer->token.type != LEX_T_STRING) {
        lexer_syntax_error(ctx->lexer, "expecting port name string");
        return;
    }

    struct ovnact_bind_vport *bind_vp = ovnact_put_BIND_VPORT(ctx->ovnacts);
    bind_vp->vport = xstrdup(ctx->lexer->token.s);
    lexer_get(ctx->lexer);
    (void) (lexer_force_match(ctx->lexer, LEX_T_COMMA)
            && action_parse_field(ctx, 0, false, &bind_vp->vport_parent)
            && lexer_force_match(ctx->lexer, LEX_T_RPAREN));
}

static void
format_BIND_VPORT(const struct ovnact_bind_vport *bind_vp,
                  struct ds *s )
{
    ds_put_format(s, "bind_vport(\"%s\", ", bind_vp->vport);
    expr_field_format(&bind_vp->vport_parent, s);
    ds_put_cstr(s, ");");
}

static void
encode_BIND_VPORT(const struct ovnact_bind_vport *vp,
                 const struct ovnact_encode_params *ep,
                 struct ofpbuf *ofpacts)
{
    uint32_t vport_key;
    if (!ep->lookup_port(ep->aux, vp->vport, &vport_key)) {
        return;
    }

    const struct arg args[] = {
        { expr_resolve_field(&vp->vport_parent), MFF_LOG_INPORT },
    };
    encode_setup_args(args, ARRAY_SIZE(args), ofpacts);
    size_t oc_offset = encode_start_controller_op(ACTION_OPCODE_BIND_VPORT,
                                                  false, NX_CTLR_NO_METER,
                                                  ofpacts);
    ovs_be32 vp_key = htonl(vport_key);
    ofpbuf_put(ofpacts, &vp_key, sizeof(ovs_be32));
    encode_finish_controller_op(oc_offset, ofpacts);
    encode_restore_args(args, ARRAY_SIZE(args), ofpacts);
}

static void
ovnact_bind_vport_free(struct ovnact_bind_vport *bp)
{
    free(bp->vport);
}

/* Parses an assignment or exchange or put_dhcp_opts action. */
static void
parse_set_action(struct action_context *ctx)
{
    struct expr_field lhs;
    if (!expr_field_parse(ctx->lexer, ctx->pp->symtab, &lhs, &ctx->prereqs)) {
        return;
    }

    if (lexer_match(ctx->lexer, LEX_T_EXCHANGE)) {
        parse_assignment_action(ctx, true, &lhs);
    } else if (lexer_match(ctx->lexer, LEX_T_EQUALS)) {
        if (ctx->lexer->token.type != LEX_T_ID) {
            parse_LOAD(ctx, &lhs);
        } else if (!strcmp(ctx->lexer->token.s, "put_dhcp_opts")
                   && lexer_lookahead(ctx->lexer) == LEX_T_LPAREN) {
            parse_put_dhcp_opts(ctx, &lhs, ovnact_put_PUT_DHCPV4_OPTS(
                                    ctx->ovnacts));
        } else if (!strcmp(ctx->lexer->token.s, "put_dhcpv6_opts")
                   && lexer_lookahead(ctx->lexer) == LEX_T_LPAREN) {
            parse_put_dhcp_opts(ctx, &lhs, ovnact_put_PUT_DHCPV6_OPTS(
                                    ctx->ovnacts));
        } else if (!strcmp(ctx->lexer->token.s, "dns_lookup")
                   && lexer_lookahead(ctx->lexer) == LEX_T_LPAREN) {
            parse_dns_lookup(ctx, &lhs, ovnact_put_DNS_LOOKUP(ctx->ovnacts));
        } else if (!strcmp(ctx->lexer->token.s, "put_nd_ra_opts")
                && lexer_lookahead(ctx->lexer) == LEX_T_LPAREN) {
            parse_put_nd_ra_opts(ctx, &lhs,
                                 ovnact_put_PUT_ND_RA_OPTS(ctx->ovnacts));
        } else if (!strcmp(ctx->lexer->token.s, "check_pkt_larger")
                && lexer_lookahead(ctx->lexer) == LEX_T_LPAREN) {
            parse_check_pkt_larger(ctx, &lhs,
                                   ovnact_put_CHECK_PKT_LARGER(ctx->ovnacts));
        } else {
            parse_assignment_action(ctx, false, &lhs);
        }
    } else {
        lexer_syntax_error(ctx->lexer, "expecting `=' or `<->'");
    }
}

static bool
parse_action(struct action_context *ctx)
{
    if (ctx->lexer->token.type != LEX_T_ID) {
        lexer_syntax_error(ctx->lexer, NULL);
        return false;
    }

    enum lex_type lookahead = lexer_lookahead(ctx->lexer);
    if (lookahead == LEX_T_EQUALS || lookahead == LEX_T_EXCHANGE
        || lookahead == LEX_T_LSQUARE) {
        parse_set_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "next")) {
        parse_NEXT(ctx);
    } else if (lexer_match_id(ctx->lexer, "output")) {
        ovnact_put_OUTPUT(ctx->ovnacts);
    } else if (lexer_match_id(ctx->lexer, "ip.ttl")) {
        parse_DEC_TTL(ctx);
    } else if (lexer_match_id(ctx->lexer, "ct_next")) {
        parse_CT_NEXT(ctx);
    } else if (lexer_match_id(ctx->lexer, "ct_commit")) {
        parse_CT_COMMIT(ctx);
    } else if (lexer_match_id(ctx->lexer, "ct_dnat")) {
        parse_CT_DNAT(ctx);
    } else if (lexer_match_id(ctx->lexer, "ct_snat")) {
        parse_CT_SNAT(ctx);
    } else if (lexer_match_id(ctx->lexer, "ct_lb")) {
        parse_ct_lb_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "ct_clear")) {
        ovnact_put_CT_CLEAR(ctx->ovnacts);
    } else if (lexer_match_id(ctx->lexer, "clone")) {
        parse_CLONE(ctx);
    } else if (lexer_match_id(ctx->lexer, "arp")) {
        parse_ARP(ctx);
    } else if (lexer_match_id(ctx->lexer, "icmp4")) {
        parse_ICMP4(ctx);
    } else if (lexer_match_id(ctx->lexer, "icmp4_error")) {
        parse_ICMP4_ERROR(ctx);
    } else if (lexer_match_id(ctx->lexer, "icmp6")) {
        parse_ICMP6(ctx);
    } else if (lexer_match_id(ctx->lexer, "igmp")) {
        ovnact_put_IGMP(ctx->ovnacts);
    } else if (lexer_match_id(ctx->lexer, "tcp_reset")) {
        parse_TCP_RESET(ctx);
    } else if (lexer_match_id(ctx->lexer, "nd_na")) {
        parse_ND_NA(ctx);
    } else if (lexer_match_id(ctx->lexer, "nd_na_router")) {
        parse_ND_NA_ROUTER(ctx);
    } else if (lexer_match_id(ctx->lexer, "nd_ns")) {
        parse_ND_NS(ctx);
    } else if (lexer_match_id(ctx->lexer, "get_arp")) {
        parse_get_mac_bind(ctx, 32, ovnact_put_GET_ARP(ctx->ovnacts));
    } else if (lexer_match_id(ctx->lexer, "put_arp")) {
        parse_put_mac_bind(ctx, 32, ovnact_put_PUT_ARP(ctx->ovnacts));
    } else if (lexer_match_id(ctx->lexer, "get_nd")) {
        parse_get_mac_bind(ctx, 128, ovnact_put_GET_ND(ctx->ovnacts));
    } else if (lexer_match_id(ctx->lexer, "put_nd")) {
        parse_put_mac_bind(ctx, 128, ovnact_put_PUT_ND(ctx->ovnacts));
    } else if (lexer_match_id(ctx->lexer, "set_queue")) {
        parse_SET_QUEUE(ctx);
    } else if (lexer_match_id(ctx->lexer, "log")) {
        parse_LOG(ctx);
    } else if (lexer_match_id(ctx->lexer, "set_meter")) {
        parse_set_meter_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "trigger_event")) {
        parse_trigger_event(ctx, ovnact_put_TRIGGER_EVENT(ctx->ovnacts));
    } else if (lexer_match_id(ctx->lexer, "bind_vport")) {
        parse_bind_vport(ctx);
    } else {
        lexer_syntax_error(ctx->lexer, "expecting action");
    }
    lexer_force_match(ctx->lexer, LEX_T_SEMICOLON);
    return !ctx->lexer->error;
}

static void
parse_actions(struct action_context *ctx, enum lex_type sentinel)
{
    /* "drop;" by itself is a valid (empty) set of actions, but it can't be
     * combined with other actions because that doesn't make sense. */
    if (ctx->lexer->token.type == LEX_T_ID
        && !strcmp(ctx->lexer->token.s, "drop")
        && lexer_lookahead(ctx->lexer) == LEX_T_SEMICOLON) {
        lexer_get(ctx->lexer);  /* Skip "drop". */
        lexer_get(ctx->lexer);  /* Skip ";". */
        lexer_force_match(ctx->lexer, sentinel);
        return;
    }

    while (!lexer_match(ctx->lexer, sentinel)) {
        if (!parse_action(ctx)) {
            return;
        }
    }
}

/* Parses OVN actions, in the format described for the "actions" column in the
 * Logical_Flow table in ovn-sb(5), and appends the parsed versions of the
 * actions to 'ovnacts' as "struct ovnact"s.  The caller must eventually free
 * the parsed ovnacts with ovnacts_free().
 *
 * 'pp' provides most of the parameters for translation.
 *
 * Some actions add extra requirements (prerequisites) to the flow's match.  If
 * so, this function sets '*prereqsp' to the actions' prerequisites; otherwise,
 * it sets '*prereqsp' to NULL.  The caller owns '*prereqsp' and must
 * eventually free it.
 *
 * Returns true if successful, false if an error occurred.  Upon return,
 * returns true if and only if lexer->error is NULL.
 */
bool
ovnacts_parse(struct lexer *lexer, const struct ovnact_parse_params *pp,
              struct ofpbuf *ovnacts, struct expr **prereqsp)
{
    size_t ovnacts_start = ovnacts->size;

    struct action_context ctx = {
        .pp = pp,
        .lexer = lexer,
        .ovnacts = ovnacts,
        .prereqs = NULL,
    };
    if (!lexer->error) {
        parse_actions(&ctx, LEX_T_END);
    }

    if (!lexer->error) {
        *prereqsp = ctx.prereqs;
        return true;
    } else {
        ofpbuf_pull(ovnacts, ovnacts_start);
        ovnacts_free(ovnacts->data, ovnacts->size);
        ofpbuf_push_uninit(ovnacts, ovnacts_start);

        ovnacts->size = ovnacts_start;
        expr_destroy(ctx.prereqs);
        *prereqsp = NULL;
        return false;
    }
}

/* Like ovnacts_parse(), but the actions are taken from 's'. */
char * OVS_WARN_UNUSED_RESULT
ovnacts_parse_string(const char *s, const struct ovnact_parse_params *pp,
                     struct ofpbuf *ofpacts, struct expr **prereqsp)
{
    struct lexer lexer;

    lexer_init(&lexer, s);
    lexer_get(&lexer);
    ovnacts_parse(&lexer, pp, ofpacts, prereqsp);
    char *error = lexer_steal_error(&lexer);
    lexer_destroy(&lexer);

    return error;
}

/* Formatting ovnacts. */

static void
ovnact_format(const struct ovnact *a, struct ds *s)
{
    switch (a->type) {
#define OVNACT(ENUM, STRUCT)                                            \
        case OVNACT_##ENUM:                                             \
            format_##ENUM(ALIGNED_CAST(const struct STRUCT *, a), s);   \
            break;
        OVNACTS
#undef OVNACT
    default:
        OVS_NOT_REACHED();
    }
}

/* Appends a string representing the 'ovnacts_len' bytes of ovnacts in
 * 'ovnacts' to 'string'. */
void
ovnacts_format(const struct ovnact *ovnacts, size_t ovnacts_len,
               struct ds *string)
{
    if (!ovnacts_len) {
        ds_put_cstr(string, "drop;");
    } else {
        const struct ovnact *a;

        OVNACT_FOR_EACH (a, ovnacts, ovnacts_len) {
            if (a != ovnacts) {
                ds_put_char(string, ' ');
            }
            ovnact_format(a, string);
        }
    }
}

/* Encoding ovnacts to OpenFlow. */

static void
ovnact_encode(const struct ovnact *a, const struct ovnact_encode_params *ep,
              struct ofpbuf *ofpacts)
{
    switch (a->type) {
#define OVNACT(ENUM, STRUCT)                                            \
        case OVNACT_##ENUM:                                             \
            encode_##ENUM(ALIGNED_CAST(const struct STRUCT *, a),       \
                          ep, ofpacts);                                 \
            break;
        OVNACTS
#undef OVNACT
    default:
        OVS_NOT_REACHED();
    }
}

/* Appends ofpacts to 'ofpacts' that represent the actions in the 'ovnacts_len'
 * bytes of actions starting at 'ovnacts'. */
void
ovnacts_encode(const struct ovnact *ovnacts, size_t ovnacts_len,
               const struct ovnact_encode_params *ep,
               struct ofpbuf *ofpacts)
{
    if (ovnacts) {
        const struct ovnact *a;

        OVNACT_FOR_EACH (a, ovnacts, ovnacts_len) {
            ovnact_encode(a, ep, ofpacts);
        }
    }
}

/* Freeing ovnacts. */

static void
ovnact_free(struct ovnact *a)
{
    switch (a->type) {
#define OVNACT(ENUM, STRUCT)                                            \
        case OVNACT_##ENUM:                                             \
            STRUCT##_free(ALIGNED_CAST(struct STRUCT *, a));            \
            break;
        OVNACTS
#undef OVNACT
    default:
        OVS_NOT_REACHED();
    }
}

/* Frees each of the actions in the 'ovnacts_len' bytes of actions starting at
 * 'ovnacts'.
 *
 * Does not call free(ovnacts); the caller must do so if desirable. */
void
ovnacts_free(struct ovnact *ovnacts, size_t ovnacts_len)
{
    if (ovnacts) {
        struct ovnact *a;

        OVNACT_FOR_EACH (a, ovnacts, ovnacts_len) {
            ovnact_free(a);
        }
    }
}
