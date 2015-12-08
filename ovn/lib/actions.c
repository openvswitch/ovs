/*
 * Copyright (c) 2015 Nicira, Inc.
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
#include "actions.h"
#include <stdarg.h>
#include <stdbool.h>
#include "compiler.h"
#include "dynamic-string.h"
#include "expr.h"
#include "lex.h"
#include "logical-fields.h"
#include "ofp-actions.h"
#include "ofpbuf.h"
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

/* Parses an assignment or exchange action. */
static void
parse_set_action(struct action_context *ctx)
{
    struct expr *prereqs;
    char *error;

    error = expr_parse_assignment(ctx->lexer, ctx->ap->symtab, ctx->ap->ports,
                                  ctx->ofpacts, &prereqs);
    if (error) {
        action_error(ctx, "%s", error);
        free(error);
        return;
    }

    ctx->prereqs = expr_combine(EXPR_T_AND, ctx->prereqs, prereqs);
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

    expr = expr_parse_string(prerequisite, ctx->ap->symtab, &error);
    ovs_assert(!error);
    ctx->prereqs = expr_combine(EXPR_T_AND, ctx->prereqs, expr);
}

static void
emit_ct(struct action_context *ctx, bool recirc_next, bool commit)
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
        emit_ct(ctx, true, false);
    } else if (lexer_match_id(ctx->lexer, "ct_commit")) {
        emit_ct(ctx, false, true);
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
