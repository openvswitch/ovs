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

#ifndef OVN_LEX_H
#define OVN_LEX_H 1

/* OVN lexical analyzer
 * ====================
 *
 * This is a simple lexical analyzer (or tokenizer) for OVN match expressions
 * and ACLs. */

#include "openvswitch/meta-flow.h"

struct ds;

/* Token type. */
enum lex_type {
    LEX_T_END,                  /* end of input */

    /* Tokens with auxiliary data. */
    LEX_T_ID,                   /* foo */
    LEX_T_STRING,               /* "foo" */
    LEX_T_INTEGER,              /* 12345 or 1.2.3.4 or ::1 or 01:02:03:04:05 */
    LEX_T_MASKED_INTEGER,       /* 12345/10 or 1.2.0.0/16 or ::2/127 or... */
    LEX_T_MACRO,                /* $NAME */
    LEX_T_ERROR,                /* invalid input */

    /* Bare tokens. */
    LEX_T_LPAREN,               /* ( */
    LEX_T_RPAREN,               /* ) */
    LEX_T_LCURLY,               /* { */
    LEX_T_RCURLY,               /* } */
    LEX_T_LSQUARE,              /* [ */
    LEX_T_RSQUARE,              /* ] */
    LEX_T_EQ,                   /* == */
    LEX_T_NE,                   /* != */
    LEX_T_LT,                   /* < */
    LEX_T_LE,                   /* <= */
    LEX_T_GT,                   /* > */
    LEX_T_GE,                   /* >= */
    LEX_T_LOG_NOT,              /* ! */
    LEX_T_LOG_AND,              /* && */
    LEX_T_LOG_OR,               /* || */
    LEX_T_ELLIPSIS,             /* .. */
    LEX_T_COMMA,                /* , */
    LEX_T_SEMICOLON,            /* ; */
    LEX_T_EQUALS,               /* = */
    LEX_T_EXCHANGE,             /* <-> */
    LEX_T_DECREMENT,            /* -- */
    LEX_T_COLON,                /* : */
};

/* Subtype for LEX_T_INTEGER and LEX_T_MASKED_INTEGER tokens.
 *
 * These do not change the semantics of a token; instead, they determine the
 * format used when a token is serialized back to a text form.  That's
 * important because 3232268289 is meaningless to a human whereas 192.168.128.1
 * has some actual significance. */
enum lex_format {
    LEX_F_DECIMAL,
    LEX_F_HEXADECIMAL,
    LEX_F_IPV4,
    LEX_F_IPV6,
    LEX_F_ETHERNET,
};
const char *lex_format_to_string(enum lex_format);

/* A token. */
struct lex_token {
    /* One of LEX_*. */
    enum lex_type type;

    /* Meaningful for LEX_T_ID, LEX_T_STRING, LEX_T_ERROR, LEX_T_MACRO only.
     * For these token types, 's' may point to 'buffer'; otherwise, it points
     * to malloc()ed memory owned by the token.
     *
     * Must be NULL for other token types.
     *
     * For LEX_T_MACRO, 's' does not include the leading $. */
    char *s;

    /* LEX_T_INTEGER, LEX_T_MASKED_INTEGER only. */
    enum lex_format format;

    union {
        /* LEX_T_INTEGER, LEX_T_MASKED_INTEGER only. */
        struct {
            union mf_subvalue value; /* LEX_T_INTEGER, LEX_T_MASKED_INTEGER. */
            union mf_subvalue mask;  /* LEX_T_MASKED_INTEGER only. */
        };

        /* LEX_T_ID, LEX_T_STRING, LEX_T_ERROR, LEX_T_MACRO only. */
        char buffer[256];
    };
};

void lex_token_init(struct lex_token *);
void lex_token_destroy(struct lex_token *);
void lex_token_swap(struct lex_token *, struct lex_token *);
void lex_token_strcpy(struct lex_token *, const char *s, size_t length);
void lex_token_strset(struct lex_token *, char *s);
void lex_token_vsprintf(struct lex_token *, const char *format, va_list args);

void lex_token_format(const struct lex_token *, struct ds *);
const char *lex_token_parse(struct lex_token *, const char *input,
                            const char **startp);

/* A lexical analyzer. */
struct lexer {
    const char *input;          /* Remaining input (not owned by lexer). */
    const char *start;          /* Start of current token in 'input'. */
    struct lex_token token;     /* Current token (owned by lexer). */
    char *error;                /* Error message, if any (owned by lexer). */
};

void lexer_init(struct lexer *, const char *input);
void lexer_destroy(struct lexer *);

enum lex_type lexer_get(struct lexer *);
enum lex_type lexer_lookahead(const struct lexer *);
bool lexer_match(struct lexer *, enum lex_type);
bool lexer_force_match(struct lexer *, enum lex_type);
bool lexer_match_id(struct lexer *, const char *id);
bool lexer_is_int(const struct lexer *);
bool lexer_get_int(struct lexer *, int *value);
bool lexer_force_int(struct lexer *, int *value);

bool lexer_force_end(struct lexer *);

void lexer_error(struct lexer *, const char *message, ...)
    OVS_PRINTF_FORMAT(2, 3);
void lexer_syntax_error(struct lexer *, const char *message, ...)
    OVS_PRINTF_FORMAT(2, 3);

char *lexer_steal_error(struct lexer *);

#endif /* ovn/lex.h */
