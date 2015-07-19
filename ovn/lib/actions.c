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
#include "ofp-actions.h"
#include "ofpbuf.h"

/* Context maintained during actions_parse(). */
struct action_context {
    /* Input. */
    struct lexer *lexer;        /* Lexer for pulling more tokens. */
    const struct shash *symtab; /* Symbol table. */
    uint8_t next_table_id;      /* OpenFlow table for 'next' to resubmit. */
    uint8_t output_table_id;    /* OpenFlow table for 'output' to resubmit. */
    const struct simap *ports;  /* Map from port name to number. */

    /* State. */
    char *error;                /* Error, if any, otherwise NULL. */

    /* Output. */
    struct ofpbuf *ofpacts;     /* Actions. */
    struct expr *prereqs;       /* Prerequisites to apply to match. */
};

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

static void
parse_set_action(struct action_context *ctx)
{
    struct expr *prereqs;
    char *error;

    error = expr_parse_assignment(ctx->lexer, ctx->symtab, ctx->ports,
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
        if (ctx->lexer->token.type != LEX_T_ID) {
            action_syntax_error(ctx, NULL);
            break;
        }

        enum lex_type lookahead = lexer_lookahead(ctx->lexer);
        if (lookahead == LEX_T_EQUALS || lookahead == LEX_T_LSQUARE) {
            parse_set_action(ctx);
        } else if (lexer_match_id(ctx->lexer, "next")) {
            if (ctx->next_table_id) {
                emit_resubmit(ctx, ctx->next_table_id);
            } else {
                action_error(ctx, "\"next\" action not allowed here.");
            }
        } else if (lexer_match_id(ctx->lexer, "output")) {
            emit_resubmit(ctx, ctx->output_table_id);
        } else {
            action_syntax_error(ctx, "expecting action");
        }
        if (!lexer_match(ctx->lexer, LEX_T_SEMICOLON)) {
            action_syntax_error(ctx, "expecting ';'");
        }
        if (ctx->error) {
            return;
        }
    }
}

/* Parses OVN actions, in the format described for the "actions" column in the
 * Logical_Flow table in ovn-sb(5), and appends the parsed versions of the
 * actions to 'ofpacts' as "struct ofpact"s.
 *
 * 'symtab' provides a table of "struct expr_symbol"s to support (as one would
 * provide to expr_parse()).
 *
 * 'ports' must be a map from strings (presumably names of ports) to integers
 * (as one would provide to expr_to_matches()).  Strings used in the actions
 * that are not in 'ports' are translated to zero.
 *
 * 'next_table_id' should be the OpenFlow table to which the "next" action will
 * resubmit, or 0 to disable "next".
 *
 * 'output_table_id' should be the OpenFlow table to which the "output" action
 * will resubmit
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
actions_parse(struct lexer *lexer, const struct shash *symtab,
              const struct simap *ports, uint8_t next_table_id,
              uint8_t output_table_id, struct ofpbuf *ofpacts,
              struct expr **prereqsp)
{
    size_t ofpacts_start = ofpacts->size;

    struct action_context ctx;
    ctx.lexer = lexer;
    ctx.symtab = symtab;
    ctx.ports = ports;
    ctx.next_table_id = next_table_id;
    ctx.output_table_id = output_table_id;
    ctx.error = NULL;
    ctx.ofpacts = ofpacts;
    ctx.prereqs = NULL;

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
actions_parse_string(const char *s, const struct shash *symtab,
                     const struct simap *ports, uint8_t next_table_id,
                     uint8_t output_table_id, struct ofpbuf *ofpacts,
                     struct expr **prereqsp)
{
    struct lexer lexer;
    char *error;

    lexer_init(&lexer, s);
    lexer_get(&lexer);
    error = actions_parse(&lexer, symtab, ports, next_table_id,
                          output_table_id, ofpacts, prereqsp);
    lexer_destroy(&lexer);

    return error;
}
