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
#include "command-line.h"
#include <getopt.h>
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "match.h"
#include "ovn/lib/lex.h"
#include "ovstest.h"
#include "util.h"
#include "openvswitch/vlog.h"

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
    while (!ds_get_line(&input, stdin)) {
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
test_ovn_main(int argc, char *argv[])
{
    set_program_name(argv[0]);

    static const struct ovs_cmdl_command commands[] = {
        {"lex", NULL, 0, 0, test_lex},
        {NULL, NULL, 0, 0, NULL},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ovn", test_ovn_main);
