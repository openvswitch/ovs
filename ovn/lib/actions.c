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
#include <stdarg.h>
#include <stdbool.h>
#include "bitmap.h"
#include "byte-order.h"
#include "compiler.h"
#include "ovn-dhcp.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "logical-fields.h"
#include "nx-match.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "ovn/actions.h"
#include "ovn/expr.h"
#include "ovn/lex.h"
#include "packets.h"
#include "openvswitch/shash.h"
#include "simap.h"

/* Context maintained during actions_parse(). */
struct action_context {
    const struct action_params *ap; /* Parameters. */
    struct lexer *lexer;        /* Lexer for pulling more tokens. */
    char *error;                /* Error, if any, otherwise NULL. */
    struct ofpbuf *ofpacts;     /* Actions. */
    struct expr *prereqs;       /* Prerequisites to apply to match. */
};

static bool parse_action(struct action_context *);
static void parse_put_dhcp_opts_action(struct action_context *,
                                       const struct expr_field *dst);

static bool
action_error_handle_common(struct action_context *ctx)
{
    if (ctx->error) {
        /* Already have an error, suppress this one since the cascade seems
         * unlikely to be useful. */
        return true;
    } else if (ctx->lexer->token.type == LEX_T_ERROR) {
        /* The lexer signaled an error.  Nothing at the action level
         * accepts an error token, so we'll inevitably end up here with some
         * meaningless parse error.  Report the lexical error instead. */
        ctx->error = xstrdup(ctx->lexer->token.s);
        return true;
    } else {
        return false;
    }
}

static void OVS_PRINTF_FORMAT(2, 3)
action_error(struct action_context *ctx, const char *message, ...)
{
    if (action_error_handle_common(ctx)) {
        return;
    }

    va_list args;
    va_start(args, message);
    ctx->error = xvasprintf(message, args);
    va_end(args);
}

static void OVS_PRINTF_FORMAT(2, 3)
action_syntax_error(struct action_context *ctx, const char *message, ...)
{
    if (action_error_handle_common(ctx)) {
        return;
    }

    struct ds s;

    ds_init(&s);
    ds_put_cstr(&s, "Syntax error");
    if (ctx->lexer->token.type == LEX_T_END) {
        ds_put_cstr(&s, " at end of input");
    } else if (ctx->lexer->start) {
        ds_put_format(&s, " at `%.*s'",
                      (int) (ctx->lexer->input - ctx->lexer->start),
                      ctx->lexer->start);
    }

    if (message) {
        ds_put_char(&s, ' ');

        va_list args;
        va_start(args, message);
        ds_put_format_valist(&s, message, args);
        va_end(args);
    }
    ds_put_char(&s, '.');

    ctx->error = ds_steal_cstr(&s);
}

/* Parses an assignment or exchange or put_dhcp_opts action. */
static void
parse_set_action(struct action_context *ctx)
{
    struct expr *prereqs = NULL;
    struct expr_field dst;
    char *error;

    error = expr_parse_field(ctx->lexer, ctx->ap->symtab, &dst);
    if (!error) {
        if (lexer_match(ctx->lexer, LEX_T_EXCHANGE)) {
            error = expr_parse_exchange(ctx->lexer, &dst, ctx->ap->symtab,
                                        ctx->ap->lookup_port, ctx->ap->aux,
                                        ctx->ofpacts, &prereqs);
        } else if (lexer_match(ctx->lexer, LEX_T_EQUALS)) {
            if (ctx->lexer->token.type == LEX_T_ID
                && !strcmp(ctx->lexer->token.s, "put_dhcp_opts")
                && lexer_lookahead(ctx->lexer) == LEX_T_LPAREN) {
                lexer_get(ctx->lexer); /* Skip put_dhcp_opts. */
                lexer_get(ctx->lexer); /* Skip '('. */
                parse_put_dhcp_opts_action(ctx, &dst);
            } else {
                error = expr_parse_assignment(
                    ctx->lexer, &dst, ctx->ap->symtab, ctx->ap->lookup_port,
                    ctx->ap->aux, ctx->ofpacts, &prereqs);
            }
        } else {
            action_syntax_error(ctx, "expecting `=' or `<->'");
        }
        if (!error) {
            ctx->prereqs = expr_combine(EXPR_T_AND, ctx->prereqs, prereqs);
        }
    }

    if (error) {
        expr_destroy(prereqs);
        action_error(ctx, "%s", error);
        free(error);
    }
}

static void
emit_resubmit(struct action_context *ctx, uint8_t table_id)
{
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ctx->ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = table_id;
}

static bool
action_get_int(struct action_context *ctx, int *value)
{
    bool ok = lexer_get_int(ctx->lexer, value);
    if (!ok) {
        action_syntax_error(ctx, "expecting small integer");
    }
    return ok;
}

static void
parse_next_action(struct action_context *ctx)
{
    if (!ctx->ap->n_tables) {
        action_error(ctx, "\"next\" action not allowed here.");
    } else if (lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        int ltable;

        if (!action_get_int(ctx, &ltable)) {
            return;
        }
        if (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
            action_syntax_error(ctx, "expecting `)'");
            return;
        }

        if (ltable >= ctx->ap->n_tables) {
            action_error(ctx, "\"next\" argument must be in range 0 to %d.",
                         ctx->ap->n_tables - 1);
            return;
        }

        emit_resubmit(ctx, ctx->ap->first_ptable + ltable);
    } else {
        if (ctx->ap->cur_ltable < ctx->ap->n_tables) {
            emit_resubmit(ctx,
                          ctx->ap->first_ptable + ctx->ap->cur_ltable + 1);
        } else {
            action_error(ctx, "\"next\" action not allowed in last table.");
        }
    }
}

/* Parses 'prerequisite' as an expression in the context of 'ctx', then adds it
 * as a conjunction with the existing 'ctx->prereqs'. */
static void
add_prerequisite(struct action_context *ctx, const char *prerequisite)
{
    struct expr *expr;
    char *error;

    expr = expr_parse_string(prerequisite, ctx->ap->symtab, NULL, &error);
    ovs_assert(!error);
    ctx->prereqs = expr_combine(EXPR_T_AND, ctx->prereqs, expr);
}

static size_t
start_controller_op(struct ofpbuf *ofpacts, enum action_opcode opcode,
                    bool pause)
{
    size_t ofs = ofpacts->size;

    struct ofpact_controller *oc = ofpact_put_CONTROLLER(ofpacts);
    oc->max_len = UINT16_MAX;
    oc->reason = OFPR_ACTION;
    oc->pause = pause;

    struct action_header ah = { .opcode = htonl(opcode) };
    ofpbuf_put(ofpacts, &ah, sizeof ah);

    return ofs;
}

static void
finish_controller_op(struct ofpbuf *ofpacts, size_t ofs)
{
    struct ofpact_controller *oc = ofpbuf_at_assert(ofpacts, ofs, sizeof *oc);
    ofpacts->header = oc;
    oc->userdata_len = ofpacts->size - (ofs + sizeof *oc);
    ofpact_finish_CONTROLLER(ofpacts, &oc);
}

static void
put_controller_op(struct ofpbuf *ofpacts, enum action_opcode opcode)
{
    size_t ofs = start_controller_op(ofpacts, opcode, false);
    finish_controller_op(ofpacts, ofs);
}

/* Implements the "arp" and "nd_na" actions, which execute nested
 * actions on a packet derived fro: the one being processed. */
static void
parse_nested_action(struct action_context *ctx, enum action_opcode opcode,
                    const char *prereq)
{
    if (!lexer_match(ctx->lexer, LEX_T_LCURLY)) {
        action_syntax_error(ctx, "expecting `{'");
        return;
    }

    struct ofpbuf *outer_ofpacts = ctx->ofpacts;
    uint64_t inner_ofpacts_stub[1024 / 8];
    struct ofpbuf inner_ofpacts = OFPBUF_STUB_INITIALIZER(inner_ofpacts_stub);
    ctx->ofpacts = &inner_ofpacts;

    /* Save prerequisites.  (XXX What is the right treatment for prereqs?) */
    struct expr *outer_prereqs = ctx->prereqs;
    ctx->prereqs = NULL;

    /* Parse inner actions. */
    while (!lexer_match(ctx->lexer, LEX_T_RCURLY)) {
        if (!parse_action(ctx)) {
            break;
        }
    }

    ctx->ofpacts = outer_ofpacts;

    /* Add a "controller" OpenFlow action with the actions nested inside the
     * requested OVN action's "{...}", converted to OpenFlow, as its userdata.
     * ovn-controller will convert the packet to the requested type and
     * then send the packet and actions back to the switch inside an
     * OFPT_PACKET_OUT message. */
    size_t oc_offset = start_controller_op(ctx->ofpacts, opcode, false);
    ofpacts_put_openflow_actions(inner_ofpacts.data, inner_ofpacts.size,
                                 ctx->ofpacts, OFP13_VERSION);
    finish_controller_op(ctx->ofpacts, oc_offset);

    /* Restore prerequisites. */
    expr_destroy(ctx->prereqs);
    ctx->prereqs = outer_prereqs;
    add_prerequisite(ctx, prereq);

    /* Free memory. */
    ofpbuf_uninit(&inner_ofpacts);
}

static bool
action_force_match(struct action_context *ctx, enum lex_type t)
{
    if (lexer_match(ctx->lexer, t)) {
        return true;
    } else {
        struct lex_token token = { .type = t };
        struct ds s = DS_EMPTY_INITIALIZER;
        lex_token_format(&token, &s);

        action_syntax_error(ctx, "expecting `%s'", ds_cstr(&s));

        ds_destroy(&s);

        return false;
    }
}

static bool
action_parse_field(struct action_context *ctx,
                   int n_bits, struct mf_subfield *sf)
{
    struct expr_field field;
    char *error;

    error = expr_parse_field(ctx->lexer, ctx->ap->symtab, &field);
    if (!error) {
        struct expr *prereqs;
        error = expr_expand_field(ctx->lexer, ctx->ap->symtab,
                                  &field, n_bits, false, sf, &prereqs);
        if (!error) {
            ctx->prereqs = expr_combine(EXPR_T_AND, ctx->prereqs, prereqs);
            return true;
        }
    }

    action_error(ctx, "%s", error);
    free(error);
    return false;
}

static void
init_stack(struct ofpact_stack *stack, enum mf_field_id field)
{
    stack->subfield.field = mf_from_id(field);
    stack->subfield.ofs = 0;
    stack->subfield.n_bits = stack->subfield.field->n_bits;
}

struct arg {
    const struct mf_subfield *src;
    enum mf_field_id dst;
};

static void
setup_args(struct action_context *ctx,
           const struct arg args[], size_t n_args)
{
    /* 1. Save all of the destinations that will be modified. */
    for (const struct arg *a = args; a < &args[n_args]; a++) {
        ovs_assert(a->src->n_bits == mf_from_id(a->dst)->n_bits);
        if (a->src->field->id != a->dst) {
            init_stack(ofpact_put_STACK_PUSH(ctx->ofpacts), a->dst);
        }
    }

    /* 2. Push the sources, in reverse order. */
    for (size_t i = n_args - 1; i < n_args; i--) {
        const struct arg *a = &args[i];
        if (a->src->field->id != a->dst) {
            ofpact_put_STACK_PUSH(ctx->ofpacts)->subfield = *a->src;
        }
    }

    /* 3. Pop the sources into the destinations. */
    for (const struct arg *a = args; a < &args[n_args]; a++) {
        if (a->src->field->id != a->dst) {
            init_stack(ofpact_put_STACK_POP(ctx->ofpacts), a->dst);
        }
    }
}

static void
restore_args(struct action_context *ctx,
             const struct arg args[], size_t n_args)
{
    for (size_t i = n_args - 1; i < n_args; i--) {
        const struct arg *a = &args[i];
        if (a->src->field->id != a->dst) {
            init_stack(ofpact_put_STACK_POP(ctx->ofpacts), a->dst);
        }
    }
}

static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_SET_FIELD(ofpacts);
    sf->field = mf_from_id(dst);
    sf->flow_has_vlan = false;

    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, 8, 0, &sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(&sf->mask, sf->field->n_bytes, ofs, n_bits);
}

static void
parse_get_arp_action(struct action_context *ctx)
{
    struct mf_subfield port, ip;

    if (!action_force_match(ctx, LEX_T_LPAREN)
        || !action_parse_field(ctx, 0, &port)
        || !action_force_match(ctx, LEX_T_COMMA)
        || !action_parse_field(ctx, 32, &ip)
        || !action_force_match(ctx, LEX_T_RPAREN)) {
        return;
    }

    const struct arg args[] = {
        { &port, MFF_LOG_OUTPORT },
        { &ip, MFF_REG0 },
    };
    setup_args(ctx, args, ARRAY_SIZE(args));

    put_load(0, MFF_ETH_DST, 0, 48, ctx->ofpacts);
    emit_resubmit(ctx, ctx->ap->mac_bind_ptable);

    restore_args(ctx, args, ARRAY_SIZE(args));
}

static void
parse_put_arp_action(struct action_context *ctx)
{
    struct mf_subfield port, ip, mac;

    if (!action_force_match(ctx, LEX_T_LPAREN)
        || !action_parse_field(ctx, 0, &port)
        || !action_force_match(ctx, LEX_T_COMMA)
        || !action_parse_field(ctx, 32, &ip)
        || !action_force_match(ctx, LEX_T_COMMA)
        || !action_parse_field(ctx, 48, &mac)
        || !action_force_match(ctx, LEX_T_RPAREN)) {
        return;
    }

    const struct arg args[] = {
        { &port, MFF_LOG_INPORT },
        { &ip, MFF_REG0 },
        { &mac, MFF_ETH_SRC }
    };
    setup_args(ctx, args, ARRAY_SIZE(args));
    put_controller_op(ctx->ofpacts, ACTION_OPCODE_PUT_ARP);
    restore_args(ctx, args, ARRAY_SIZE(args));
}

static void
parse_dhcp_opt(struct action_context *ctx, struct ofpbuf *ofpacts)
{
    if (ctx->lexer->token.type != LEX_T_ID) {
        action_syntax_error(ctx, NULL);
        return;
    }
    const struct dhcp_opts_map *dhcp_opt = dhcp_opts_find(
        ctx->ap->dhcp_opts, ctx->lexer->token.s);
    if (!dhcp_opt) {
        action_syntax_error(ctx, "expecting DHCP option name");
        return;
    }
    lexer_get(ctx->lexer);

    if (!action_force_match(ctx, LEX_T_EQUALS)) {
        return;
    }

    struct expr_constant_set cs;
    memset(&cs, 0, sizeof(struct expr_constant_set));
    char *error = expr_parse_constant_set(ctx->lexer, NULL, &cs);
    if (error) {
        action_error(ctx, "%s", error);
        free(error);
        return;
    }

    if (!strcmp(dhcp_opt->type, "str")) {
        if (cs.type != EXPR_C_STRING) {
            action_error(ctx, "DHCP option %s requires string value.",
                         dhcp_opt->name);
            return;
        }
    } else {
        if (cs.type != EXPR_C_INTEGER) {
            action_error(ctx, "DHCP option %s requires numeric value.",
                         dhcp_opt->name);
            return;
        }
    }

    if (!lexer_match(ctx->lexer, LEX_T_COMMA) && (
        ctx->lexer->token.type != LEX_T_RPAREN)) {
        action_syntax_error(ctx, NULL);
        return;
    }


    if (dhcp_opt->code == 0) {
        /* offer-ip */
        ofpbuf_put(ofpacts, &cs.values[0].value.ipv4, sizeof(ovs_be32));
        goto exit;
    }

    uint8_t *opt_header = ofpbuf_put_uninit(ofpacts, 2);
    opt_header[0] = dhcp_opt->code;

    if (!strcmp(dhcp_opt->type, "bool") || !strcmp(dhcp_opt->type, "uint8")) {
        opt_header[1] = 1;
        ofpbuf_put(ofpacts, &cs.values[0].value.u8_val, 1);
    } else if (!strcmp(dhcp_opt->type, "uint16")) {
        opt_header[1] = 2;
        ofpbuf_put(ofpacts, &cs.values[0].value.be16_int, 2);
    } else if (!strcmp(dhcp_opt->type, "uint32")) {
        opt_header[1] = 4;
        ofpbuf_put(ofpacts, &cs.values[0].value.be32_int, 4);
    } else if (!strcmp(dhcp_opt->type, "ipv4")) {
        opt_header[1] = cs.n_values * sizeof(ovs_be32);
        for (size_t i = 0; i < cs.n_values; i++) {
            ofpbuf_put(ofpacts, &cs.values[i].value.ipv4, sizeof(ovs_be32));
        }
    } else if (!strcmp(dhcp_opt->type, "static_routes")) {
        size_t no_of_routes = cs.n_values;
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
            if (cs.values[i].masked) {
                plen = (uint8_t) ip_count_cidr_bits(cs.values[i].mask.ipv4);
            }
            opt_header[1] += (1 + (plen / 8) + sizeof(ovs_be32)) ;
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
            if (cs.values[i].masked) {
                plen = ip_count_cidr_bits(cs.values[i].mask.ipv4);
            }
            ofpbuf_put(ofpacts, &plen, 1);
            ofpbuf_put(ofpacts, &cs.values[i].value.ipv4, plen / 8);
            ofpbuf_put(ofpacts, &cs.values[i + 1].value.ipv4,
                       sizeof(ovs_be32));
        }
    } else if (!strcmp(dhcp_opt->type, "str")) {
        opt_header[1] = strlen(cs.values[0].string);
        ofpbuf_put(ofpacts, cs.values[0].string, opt_header[1]);
    }

exit:
    expr_constant_set_destroy(&cs);
}

/* Parses the "put_dhcp_opts" action.  The result should be stored into 'dst'.
 *
 * The caller has already consumed "put_dhcp_opts(", so this just parses the
 * rest. */
static void
parse_put_dhcp_opts_action(struct action_context *ctx,
                           const struct expr_field *dst)
{
    /* Validate that the destination is a 1-bit, modifiable field. */
    struct mf_subfield sf;
    struct expr *prereqs;
    char *error = expr_expand_field(ctx->lexer, ctx->ap->symtab,
                                    dst, 1, true, &sf, &prereqs);
    if (error) {
        action_error(ctx, "%s", error);
        free(error);
        return;
    }
    ctx->prereqs = expr_combine(EXPR_T_AND, ctx->prereqs, prereqs);

    /* Make sure the first option is "offer_ip" */
    if (ctx->lexer->token.type != LEX_T_ID) {
        action_syntax_error(ctx, NULL);
        return;
    }
    const struct dhcp_opts_map *dhcp_opt = dhcp_opts_find(
        ctx->ap->dhcp_opts, ctx->lexer->token.s);
    if (!dhcp_opt || dhcp_opt->code != 0) {
        action_syntax_error(ctx, "expecting offerip option");
        return;
    }

    /* controller. */
    size_t oc_offset = start_controller_op(ctx->ofpacts,
                                           ACTION_OPCODE_PUT_DHCP_OPTS, true);
    nx_put_header(ctx->ofpacts, sf.field->id, OFP13_VERSION, false);
    ovs_be32 ofs = htonl(sf.ofs);
    ofpbuf_put(ctx->ofpacts, &ofs, sizeof ofs);
    while (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
        parse_dhcp_opt(ctx, ctx->ofpacts);
        if (ctx->error) {
            return;
        }
    }
    finish_controller_op(ctx->ofpacts, oc_offset);
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
    action_syntax_error(ctx, "expecting port number");
    return false;
}

static void
parse_ct_lb_action(struct action_context *ctx)
{
    uint8_t recirc_table;
    if (ctx->ap->cur_ltable < ctx->ap->n_tables) {
        recirc_table = ctx->ap->first_ptable + ctx->ap->cur_ltable + 1;
    } else {
        action_error(ctx, "\"ct_lb\" action not allowed in last table.");
        return;
    }

    if (!lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        /* ct_lb without parentheses means that this is an established
         * connection and we just need to do a NAT. */
        const size_t ct_offset = ctx->ofpacts->size;
        ofpbuf_pull(ctx->ofpacts, ct_offset);

        struct ofpact_conntrack *ct = ofpact_put_CT(ctx->ofpacts);
        struct ofpact_nat *nat;
        size_t nat_offset;
        ct->zone_src.field = mf_from_id(MFF_LOG_CT_ZONE);
        ct->zone_src.ofs = 0;
        ct->zone_src.n_bits = 16;
        ct->flags = 0;
        ct->recirc_table = recirc_table;
        ct->alg = 0;

        add_prerequisite(ctx, "ip");

        nat_offset = ctx->ofpacts->size;
        ofpbuf_pull(ctx->ofpacts, nat_offset);

        nat = ofpact_put_NAT(ctx->ofpacts);
        nat->flags = 0;
        nat->range_af = AF_UNSPEC;

        ctx->ofpacts->header = ofpbuf_push_uninit(ctx->ofpacts, nat_offset);
        ct = ctx->ofpacts->header;
        ofpact_finish(ctx->ofpacts, &ct->ofpact);
        ofpbuf_push_uninit(ctx->ofpacts, ct_offset);
        return;
    }

    uint32_t group_id = 0, bucket_id = 0, hash;
    struct group_info *group_info;
    struct ofpact_group *og;

    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "type=select");

    BUILD_ASSERT(MFF_LOG_CT_ZONE >= MFF_REG0);
    BUILD_ASSERT(MFF_LOG_CT_ZONE < MFF_REG0 + FLOW_N_REGS);
    do {
        if (ctx->lexer->token.type != LEX_T_INTEGER
            || mf_subvalue_width(&ctx->lexer->token.value) > 32) {
            action_syntax_error(ctx, "expecting IPv4 address");
            ds_destroy(&ds);
            return;
        }
        ovs_be32 ip = ctx->lexer->token.value.ipv4;
        lexer_get(ctx->lexer);

        uint16_t port = 0;
        if (lexer_match(ctx->lexer, LEX_T_COLON)
            && !action_parse_port(ctx, &port)) {
            ds_destroy(&ds);
            return;
        }

        bucket_id++;
        ds_put_format(&ds, ",bucket=bucket_id=%u,weight:100,actions="
                      "ct(nat(dst="IP_FMT, bucket_id, IP_ARGS(ip));
        if (port) {
            ds_put_format(&ds, ":%"PRIu16, port);
        }
        ds_put_format(&ds, "),commit,table=%d,zone=NXM_NX_REG%d[0..15])",
                      recirc_table, MFF_LOG_CT_ZONE - MFF_REG0);

        lexer_match(ctx->lexer, LEX_T_COMMA);
    } while (!lexer_match(ctx->lexer, LEX_T_RPAREN));
    add_prerequisite(ctx, "ip");

    hash = hash_string(ds_cstr(&ds), 0);

    /* Check whether we have non installed but allocated group_id. */
    HMAP_FOR_EACH_WITH_HASH (group_info, hmap_node, hash,
                             &ctx->ap->group_table->desired_groups) {
        if (!strcmp(ds_cstr(&group_info->group), ds_cstr(&ds))) {
            group_id = group_info->group_id;
            break;
        }
    }

    if (!group_id) {
        /* Check whether we already have an installed entry for this
         * combination. */
        HMAP_FOR_EACH_WITH_HASH (group_info, hmap_node, hash,
                                 &ctx->ap->group_table->existing_groups) {
            if (!strcmp(ds_cstr(&group_info->group), ds_cstr(&ds))) {
                group_id = group_info->group_id;
            }
        }

        if (!group_id) {
            /* Reserve a new group_id. */
            group_id = bitmap_scan(ctx->ap->group_table->group_ids, 0, 1,
                                   MAX_OVN_GROUPS + 1);
        }

        if (group_id == MAX_OVN_GROUPS + 1) {
            ds_destroy(&ds);
            action_error(ctx, "out of group ids.");
            return;
        }
        bitmap_set1(ctx->ap->group_table->group_ids, group_id);

        group_info = xmalloc(sizeof *group_info);
        group_info->group = ds;
        group_info->group_id = group_id;
        group_info->hmap_node.hash = hash;

        hmap_insert(&ctx->ap->group_table->desired_groups,
                    &group_info->hmap_node, group_info->hmap_node.hash);
    } else {
        ds_destroy(&ds);
    }

    /* Create an action to set the group. */
    og = ofpact_put_GROUP(ctx->ofpacts);
    og->group_id = group_id;
}

static void
parse_get_nd_action(struct action_context *ctx)
{
    struct mf_subfield port, ip6;

    if (!action_force_match(ctx, LEX_T_LPAREN)
        || !action_parse_field(ctx, 0, &port)
        || !action_force_match(ctx, LEX_T_COMMA)
        || !action_parse_field(ctx, 128, &ip6)
        || !action_force_match(ctx, LEX_T_RPAREN)) {
        return;
    }

    const struct arg args[] = {
        { &port, MFF_LOG_OUTPORT },
        { &ip6, MFF_XXREG0 },
    };
    setup_args(ctx, args, ARRAY_SIZE(args));

    put_load(0, MFF_ETH_DST, 0, 48, ctx->ofpacts);
    emit_resubmit(ctx, ctx->ap->mac_bind_ptable);

    restore_args(ctx, args, ARRAY_SIZE(args));
}

static void
parse_put_nd_action(struct action_context *ctx)
{
    struct mf_subfield port, ip6, mac;

    if (!action_force_match(ctx, LEX_T_LPAREN)
        || !action_parse_field(ctx, 0, &port)
        || !action_force_match(ctx, LEX_T_COMMA)
        || !action_parse_field(ctx, 128, &ip6)
        || !action_force_match(ctx, LEX_T_COMMA)
        || !action_parse_field(ctx, 48, &mac)
        || !action_force_match(ctx, LEX_T_RPAREN)) {
        return;
    }

    const struct arg args[] = {
        { &port, MFF_LOG_INPORT },
        { &ip6, MFF_XXREG0 },
        { &mac, MFF_ETH_SRC }
    };
    setup_args(ctx, args, ARRAY_SIZE(args));
    put_controller_op(ctx->ofpacts, ACTION_OPCODE_PUT_ND);
    restore_args(ctx, args, ARRAY_SIZE(args));
}

static void
emit_ct(struct action_context *ctx, bool recirc_next, bool commit,
        int *ct_mark, int *ct_mark_mask,
        ovs_be128 *ct_label, ovs_be128 *ct_label_mask)
{
    struct ofpact_conntrack *ct = ofpact_put_CT(ctx->ofpacts);
    ct->flags |= commit ? NX_CT_F_COMMIT : 0;

    /* If "recirc" is set, we automatically go to the next table. */
    if (recirc_next) {
        if (ctx->ap->cur_ltable < ctx->ap->n_tables) {
            ct->recirc_table = ctx->ap->first_ptable + ctx->ap->cur_ltable + 1;
        } else {
            action_error(ctx, "\"ct_next\" action not allowed in last table.");
            return;
        }
    } else {
        ct->recirc_table = NX_CT_RECIRC_NONE;
    }

    ct->zone_src.field = mf_from_id(MFF_LOG_CT_ZONE);
    ct->zone_src.ofs = 0;
    ct->zone_src.n_bits = 16;

    /* We do not support ALGs yet. */
    ct->alg = 0;

    /* CT only works with IP, so set up a prerequisite. */
    add_prerequisite(ctx, "ip");

    size_t set_field_offset = ctx->ofpacts->size;
    ofpbuf_pull(ctx->ofpacts, set_field_offset);

    if (ct_mark) {
        struct ofpact_set_field *sf = ofpact_put_SET_FIELD(ctx->ofpacts);
        sf->field = mf_from_id(MFF_CT_MARK);
        sf->value.be32 = htonl(*ct_mark);
        sf->mask.be32 = ct_mark_mask ? htonl(*ct_mark_mask) : OVS_BE32_MAX;
    }

    if (ct_label) {
        struct ofpact_set_field *sf = ofpact_put_SET_FIELD(ctx->ofpacts);
        sf->field = mf_from_id(MFF_CT_LABEL);
        sf->value.be128 = *ct_label;
        sf->mask.be128 = ct_label_mask ? *ct_label_mask : OVS_BE128_MAX;
    }

    ctx->ofpacts->header = ofpbuf_push_uninit(ctx->ofpacts, set_field_offset);
    ct = ctx->ofpacts->header;
    ofpact_finish(ctx->ofpacts, &ct->ofpact);
}

/* Parse an argument to the ct_commit(); action.  Supported arguments include:
 *
 *      ct_mark=<value>[/<mask>]
 *      ct_label=<value>[/<mask>]
 *
 * If a comma separates the current argument from the next argument, this
 * function will consume it.
 *
 * set_mark - This will be set to true if a value for ct_mark was successfully
 *            parsed. Otherwise, it will be unchanged.
 * mark_value - If set_mark was set to true, this will contain the value
 *              parsed for ct_mark.
 * mark_mask - If set_mark was set to true, this will contain the mask
 *             for ct_mark if one was found.  Otherwise, it will be
 *             unchanged, so the caller should initialize this to an
 *             appropriate value.
 * set_label - This will be set to true if a value for ct_label was successfully
 *             parsed. Otherwise, it will be unchanged.
 * label_value - If set_label was set to true, this will contain the value
 *               parsed for ct_label.
 * label_mask - If set_label was set to true, this will contain the mask
 *              for ct_label if one was found.  Otherwise, it will be
 *              unchanged, so the caller should initialize this to an
 *              appropriate value.
 *
 * Return true after successfully parsing an argument.  false on failure. */
static bool
parse_ct_commit_arg(struct action_context *ctx,
                    bool *set_mark, int *mark_value, int *mark_mask,
                    bool *set_label, ovs_be128 *label_value,
                    ovs_be128 *label_mask)
{
    if (lexer_match_id(ctx->lexer, "ct_mark")) {
        if (!lexer_match(ctx->lexer, LEX_T_EQUALS)) {
            action_error(ctx, "Expected '=' after argument to ct_commit");
            return false;
        }
        if (ctx->lexer->token.type == LEX_T_INTEGER) {
            *mark_value = ntohll(ctx->lexer->token.value.integer);
        } else if (ctx->lexer->token.type == LEX_T_MASKED_INTEGER) {
            *mark_value = ntohll(ctx->lexer->token.value.integer);
            *mark_mask = ntohll(ctx->lexer->token.mask.integer);
        } else {
            action_error(ctx, "Expected integer after 'ct_mark='");
            return false;
        }
        lexer_get(ctx->lexer);
        *set_mark = true;
    } else if (lexer_match_id(ctx->lexer, "ct_label")) {
        if (!lexer_match(ctx->lexer, LEX_T_EQUALS)) {
            action_error(ctx, "Expected '=' after argument to ct_commit");
            return false;
        }

        /* ct_label is a 128-bit field.  The lexer supports 128-bit
         * integers if its a hex string. The ct_label value should be specified
         * in hex string if > 64-bits are to be used */
        if (ctx->lexer->token.type == LEX_T_INTEGER) {
            label_value->be64.lo = ctx->lexer->token.value.be128_int.be64.lo;
            label_value->be64.hi = ctx->lexer->token.value.be128_int.be64.hi;
        } else if (ctx->lexer->token.type == LEX_T_MASKED_INTEGER) {
            label_value->be64.lo = ctx->lexer->token.value.be128_int.be64.lo;
            label_value->be64.hi = ctx->lexer->token.value.be128_int.be64.hi;
            label_mask->be64.lo = ctx->lexer->token.mask.be128_int.be64.lo;
            label_mask->be64.hi = ctx->lexer->token.mask.be128_int.be64.hi;
        } else {
            action_error(ctx, "Expected integer after 'ct_label='");
            return false;
        }
        lexer_get(ctx->lexer);
        *set_label = true;
    } else {
        action_error(ctx, "Expected argument to ct_commit()");
        return false;
    }

    if (lexer_match(ctx->lexer, LEX_T_COMMA)) {
        /* A comma is valid after an argument, but only if another
         * argument is present (not a closing paren) */
        if (lexer_lookahead(ctx->lexer) == LEX_T_RPAREN) {
            action_error(ctx, "Another argument to ct_commit() expected "
                              "after comma.");
            return false;
        }
    }

    return true;
}

static void
parse_ct_commit_action(struct action_context *ctx)
{
    if (!lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        /* ct_commit; */
        emit_ct(ctx, false, true, NULL, NULL, NULL, NULL);
        return;
    }

    /* ct_commit();
     * ct_commit(ct_mark=0);
     * ct_commit(ct_label=0);
     * ct_commit(ct_mark=0, ct_label=0); */

    bool set_mark = false;
    bool set_label = false;
    int mark_value = 0;
    int mark_mask = ~0;
    ovs_be128 label_value = { .be32 = { 0, }, };
    ovs_be128 label_mask = OVS_BE128_MAX;

    while (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
        if (!parse_ct_commit_arg(ctx, &set_mark, &mark_value, &mark_mask,
                                 &set_label, &label_value, &label_mask)) {
            return;
        }
    }

    emit_ct(ctx, false, true,
            set_mark ? &mark_value : NULL,
            set_mark ? &mark_mask : NULL,
            set_label ? &label_value : NULL,
            set_label ? &label_mask : NULL);
}

static void
parse_ct_nat(struct action_context *ctx, bool snat)
{
    const size_t ct_offset = ctx->ofpacts->size;
    ofpbuf_pull(ctx->ofpacts, ct_offset);

    struct ofpact_conntrack *ct = ofpact_put_CT(ctx->ofpacts);

    if (ctx->ap->cur_ltable < ctx->ap->n_tables) {
        ct->recirc_table = ctx->ap->first_ptable + ctx->ap->cur_ltable + 1;
    } else {
        action_error(ctx,
                     "\"ct_[sd]nat\" action not allowed in last table.");
        return;
    }

    if (snat) {
        ct->zone_src.field = mf_from_id(MFF_LOG_SNAT_ZONE);
    } else {
        ct->zone_src.field = mf_from_id(MFF_LOG_DNAT_ZONE);
    }
    ct->zone_src.ofs = 0;
    ct->zone_src.n_bits = 16;
    ct->flags = 0;
    ct->alg = 0;

    add_prerequisite(ctx, "ip");

    struct ofpact_nat *nat;
    size_t nat_offset;
    nat_offset = ctx->ofpacts->size;
    ofpbuf_pull(ctx->ofpacts, nat_offset);

    nat = ofpact_put_NAT(ctx->ofpacts);
    nat->flags = 0;
    nat->range_af = AF_UNSPEC;

    int commit = 0;
    if (lexer_match(ctx->lexer, LEX_T_LPAREN)) {
        ovs_be32 ip;
        if (ctx->lexer->token.type == LEX_T_INTEGER
            && ctx->lexer->token.format == LEX_F_IPV4) {
            ip = ctx->lexer->token.value.ipv4;
        } else {
            action_syntax_error(ctx, "invalid ip");
            return;
        }

        nat->range_af = AF_INET;
        nat->range.addr.ipv4.min = ip;
        if (snat) {
            nat->flags |= NX_NAT_F_SRC;
        } else {
            nat->flags |= NX_NAT_F_DST;
        }
        commit = NX_CT_F_COMMIT;
        lexer_get(ctx->lexer);
        if (!lexer_match(ctx->lexer, LEX_T_RPAREN)) {
            action_syntax_error(ctx, "expecting `)'");
            return;
        }
    }

    ctx->ofpacts->header = ofpbuf_push_uninit(ctx->ofpacts, nat_offset);
    ct = ctx->ofpacts->header;
    ct->flags |= commit;

    /* XXX: For performance reasons, we try to prevent additional
     * recirculations.  So far, ct_snat which is used in a gateway router
     * does not need a recirculation. ct_snat(IP) does need a recirculation.
     * Should we consider a method to let the actions specify whether a action
     * needs recirculation if there more use cases?. */
    if (!commit && snat) {
        ct->recirc_table = NX_CT_RECIRC_NONE;
    }
    ofpact_finish(ctx->ofpacts, &ct->ofpact);
    ofpbuf_push_uninit(ctx->ofpacts, ct_offset);
}

static bool
parse_action(struct action_context *ctx)
{
    if (ctx->lexer->token.type != LEX_T_ID) {
        action_syntax_error(ctx, NULL);
        return false;
    }

    enum lex_type lookahead = lexer_lookahead(ctx->lexer);
    if (lookahead == LEX_T_EQUALS || lookahead == LEX_T_EXCHANGE
        || lookahead == LEX_T_LSQUARE) {
        parse_set_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "next")) {
        parse_next_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "output")) {
        emit_resubmit(ctx, ctx->ap->output_ptable);
    } else if (lexer_match_id(ctx->lexer, "ip.ttl")) {
        if (lexer_match(ctx->lexer, LEX_T_DECREMENT)) {
            add_prerequisite(ctx, "ip");
            ofpact_put_DEC_TTL(ctx->ofpacts);
        } else {
            action_syntax_error(ctx, "expecting `--'");
        }
    } else if (lexer_match_id(ctx->lexer, "ct_next")) {
        emit_ct(ctx, true, false, NULL, NULL, NULL, NULL);
    } else if (lexer_match_id(ctx->lexer, "ct_commit")) {
        parse_ct_commit_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "ct_dnat")) {
        parse_ct_nat(ctx, false);
    } else if (lexer_match_id(ctx->lexer, "ct_snat")) {
        parse_ct_nat(ctx, true);
    } else if (lexer_match_id(ctx->lexer, "ct_lb")) {
        parse_ct_lb_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "arp")) {
        parse_nested_action(ctx, ACTION_OPCODE_ARP, "ip4");
    } else if (lexer_match_id(ctx->lexer, "get_arp")) {
        parse_get_arp_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "put_arp")) {
        parse_put_arp_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "nd_na")) {
        parse_nested_action(ctx, ACTION_OPCODE_ND_NA, "nd_ns");
    } else if (lexer_match_id(ctx->lexer, "get_nd")) {
        parse_get_nd_action(ctx);
    } else if (lexer_match_id(ctx->lexer, "put_nd")) {
        parse_put_nd_action(ctx);
    } else {
        action_syntax_error(ctx, "expecting action");
    }
    if (!lexer_match(ctx->lexer, LEX_T_SEMICOLON)) {
        action_syntax_error(ctx, "expecting ';'");
    }
    return !ctx->error;
}

static void
parse_actions(struct action_context *ctx)
{
    /* "drop;" by itself is a valid (empty) set of actions, but it can't be
     * combined with other actions because that doesn't make sense. */
    if (ctx->lexer->token.type == LEX_T_ID
        && !strcmp(ctx->lexer->token.s, "drop")
        && lexer_lookahead(ctx->lexer) == LEX_T_SEMICOLON) {
        lexer_get(ctx->lexer);  /* Skip "drop". */
        lexer_get(ctx->lexer);  /* Skip ";". */
        if (ctx->lexer->token.type != LEX_T_END) {
            action_syntax_error(ctx, "expecting end of input");
        }
        return;
    }

    while (ctx->lexer->token.type != LEX_T_END) {
        if (!parse_action(ctx)) {
            return;
        }
    }
}

/* Parses OVN actions, in the format described for the "actions" column in the
 * Logical_Flow table in ovn-sb(5), and appends the parsed versions of the
 * actions to 'ofpacts' as "struct ofpact"s.
 *
 * 'ap' provides most of the parameters for translation.
 *
 * Some actions add extra requirements (prerequisites) to the flow's match.  If
 * so, this function sets '*prereqsp' to the actions' prerequisites; otherwise,
 * it sets '*prereqsp' to NULL.  The caller owns '*prereqsp' and must
 * eventually free it.
 *
 * Returns NULL on success, otherwise a malloc()'d error message that the
 * caller must free.  On failure, 'ofpacts' has the same contents and
 * '*prereqsp' is set to NULL, but some tokens may have been consumed from
 * 'lexer'.
  */
char * OVS_WARN_UNUSED_RESULT
actions_parse(struct lexer *lexer, const struct action_params *ap,
              struct ofpbuf *ofpacts, struct expr **prereqsp)
{
    size_t ofpacts_start = ofpacts->size;

    struct action_context ctx = {
        .ap = ap,
        .lexer = lexer,
        .error = NULL,
        .ofpacts = ofpacts,
        .prereqs = NULL,
    };
    parse_actions(&ctx);

    if (!ctx.error) {
        *prereqsp = ctx.prereqs;
        return NULL;
    } else {
        ofpacts->size = ofpacts_start;
        expr_destroy(ctx.prereqs);
        *prereqsp = NULL;
        return ctx.error;
    }
}

/* Like actions_parse(), but the actions are taken from 's'. */
char * OVS_WARN_UNUSED_RESULT
actions_parse_string(const char *s, const struct action_params *ap,
                     struct ofpbuf *ofpacts, struct expr **prereqsp)
{
    struct lexer lexer;
    char *error;

    lexer_init(&lexer, s);
    lexer_get(&lexer);
    error = actions_parse(&lexer, ap, ofpacts, prereqsp);
    lexer_destroy(&lexer);

    return error;
}
