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
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "ovn/lex.h"
#include "packets.h"
#include "util.h"

/* Returns a string that represents 'format'. */
const char *
lex_format_to_string(enum lex_format format)
{
    switch (format) {
    case LEX_F_DECIMAL:
        return "decimal";
    case LEX_F_HEXADECIMAL:
        return "hexadecimal";
    case LEX_F_IPV4:
        return "IPv4";
    case LEX_F_IPV6:
        return "IPv6";
    case LEX_F_ETHERNET:
        return "Ethernet";
    default:
        abort();
    }
}

/* Initializes 'token'. */
void
lex_token_init(struct lex_token *token)
{
    token->type = LEX_T_END;
    token->s = NULL;
}

/* Frees memory owned by 'token'. */
void
lex_token_destroy(struct lex_token *token)
{
    if (token->s != token->buffer) {
        free(token->s);
    }
    token->s = NULL;
}

/* Exchanges 'a' and 'b'. */
void
lex_token_swap(struct lex_token *a, struct lex_token *b)
{
    struct lex_token tmp = *a;
    *a = *b;
    *b = tmp;

    /* Before swap, if 's' was pointed to 'buffer', its value shall be changed
     * to point to the 'buffer' with the copied value. */
    if (a->s == b->buffer) {
        a->s = a->buffer;
    }
    if (b->s == a->buffer) {
        b->s = b->buffer;
    }
}

/* The string 's' need not be null-terminated at 'length'. */
void
lex_token_strcpy(struct lex_token *token, const char *s, size_t length)
{
    lex_token_destroy(token);
    token->s = (length + 1 <= sizeof token->buffer
                ? token->buffer
                : xmalloc(length + 1));
    memcpy(token->s, s, length);
    token->s[length] = '\0';
}

void
lex_token_strset(struct lex_token *token, char *s)
{
    lex_token_destroy(token);
    token->s = s;
}

void
lex_token_vsprintf(struct lex_token *token, const char *format, va_list args)
{
    lex_token_destroy(token);

    va_list args2;
    va_copy(args2, args);
    token->s = (vsnprintf(token->buffer, sizeof token->buffer, format, args)
                < sizeof token->buffer
                ? token->buffer
                : xvasprintf(format, args2));
    va_end(args2);
}

/* lex_token_format(). */

static size_t
lex_token_n_zeros(enum lex_format format)
{
    switch (format) {
    case LEX_F_DECIMAL:     return offsetof(union mf_subvalue, integer);
    case LEX_F_HEXADECIMAL: return 0;
    case LEX_F_IPV4:        return offsetof(union mf_subvalue, ipv4);
    case LEX_F_IPV6:        return offsetof(union mf_subvalue, ipv6);
    case LEX_F_ETHERNET:    return offsetof(union mf_subvalue, mac);
    default: OVS_NOT_REACHED();
    }
}

/* Returns the effective format for 'token', that is, the format in which it
 * should actually be printed.  This is ordinarily the same as 'token->format',
 * but it's always possible that someone sets up a token with a format that
 * won't work for a value, e.g. 'token->value' is wider than 32 bits but the
 * format is LEX_F_IPV4.  (The lexer itself won't do that; this is an attempt
 * to avoid confusion in the future.) */
static enum lex_format
lex_token_get_format(const struct lex_token *token)
{
    size_t n_zeros = lex_token_n_zeros(token->format);
    return (is_all_zeros(&token->value, n_zeros)
            && (token->type != LEX_T_MASKED_INTEGER
                || is_all_zeros(&token->mask, n_zeros))
            ? token->format
            : LEX_F_HEXADECIMAL);
}

static void
lex_token_format_value(const union mf_subvalue *value,
                       enum lex_format format, struct ds *s)
{
    switch (format) {
    case LEX_F_DECIMAL:
        ds_put_format(s, "%"PRIu64, ntohll(value->integer));
        break;

    case LEX_F_HEXADECIMAL:
        mf_format_subvalue(value, s);
        break;

    case LEX_F_IPV4:
        ds_put_format(s, IP_FMT, IP_ARGS(value->ipv4));
        break;

    case LEX_F_IPV6:
        ipv6_format_addr(&value->ipv6, s);
        break;

    case LEX_F_ETHERNET:
        ds_put_format(s, ETH_ADDR_FMT, ETH_ADDR_ARGS(value->mac));
        break;

    default:
        OVS_NOT_REACHED();
    }

}

static void
lex_token_format_masked_integer(const struct lex_token *token, struct ds *s)
{
    enum lex_format format = lex_token_get_format(token);

    lex_token_format_value(&token->value, format, s);
    ds_put_char(s, '/');

    const union mf_subvalue *mask = &token->mask;
    if (format == LEX_F_IPV4 && ip_is_cidr(mask->ipv4)) {
        ds_put_format(s, "%d", ip_count_cidr_bits(mask->ipv4));
    } else if (token->format == LEX_F_IPV6 && ipv6_is_cidr(&mask->ipv6)) {
        ds_put_format(s, "%d", ipv6_count_cidr_bits(&mask->ipv6));
    } else {
        lex_token_format_value(&token->mask, format, s);
    }
}

/* Appends a string representation of 'token' to 's', in a format that can be
 * losslessly parsed back by the lexer.  (LEX_T_END and LEX_T_ERROR can't be
 * parsed back.) */
void
lex_token_format(const struct lex_token *token, struct ds *s)
{
    switch (token->type) {
    case LEX_T_END:
        ds_put_cstr(s, "$");
        break;

    case LEX_T_ID:
        ds_put_cstr(s, token->s);
        break;

    case LEX_T_ERROR:
        ds_put_cstr(s, "error(");
        json_string_escape(token->s, s);
        ds_put_char(s, ')');
        break;

    case LEX_T_STRING:
        json_string_escape(token->s, s);
        break;

    case LEX_T_INTEGER:
        lex_token_format_value(&token->value, lex_token_get_format(token), s);
        break;

    case LEX_T_MASKED_INTEGER:
        lex_token_format_masked_integer(token, s);
        break;

    case LEX_T_MACRO:
        ds_put_format(s, "$%s", token->s);
        break;

    case LEX_T_PORT_GROUP:
        ds_put_format(s, "@%s", token->s);
        break;

    case LEX_T_LPAREN:
        ds_put_cstr(s, "(");
        break;
    case LEX_T_RPAREN:
        ds_put_cstr(s, ")");
        break;
    case LEX_T_LCURLY:
        ds_put_cstr(s, "{");
        break;
    case LEX_T_RCURLY:
        ds_put_cstr(s, "}");
        break;
    case LEX_T_LSQUARE:
        ds_put_cstr(s, "[");
        break;
    case LEX_T_RSQUARE:
        ds_put_cstr(s, "]");
        break;
    case LEX_T_EQ:
        ds_put_cstr(s, "==");
        break;
    case LEX_T_NE:
        ds_put_cstr(s, "!=");
        break;
    case LEX_T_LT:
        ds_put_cstr(s, "<");
        break;
    case LEX_T_LE:
        ds_put_cstr(s, "<=");
        break;
    case LEX_T_GT:
        ds_put_cstr(s, ">");
        break;
    case LEX_T_GE:
        ds_put_cstr(s, ">=");
        break;
    case LEX_T_LOG_NOT:
        ds_put_cstr(s, "!");
        break;
    case LEX_T_LOG_AND:
        ds_put_cstr(s, "&&");
        break;
    case LEX_T_LOG_OR:
        ds_put_cstr(s, "||");
        break;
    case LEX_T_ELLIPSIS:
        ds_put_cstr(s, "..");
        break;
    case LEX_T_COMMA:
        ds_put_cstr(s, ",");
        break;
    case LEX_T_SEMICOLON:
        ds_put_cstr(s, ";");
        break;
    case LEX_T_EQUALS:
        ds_put_cstr(s, "=");
        break;
    case LEX_T_EXCHANGE:
        ds_put_cstr(s, "<->");
        break;
    case LEX_T_DECREMENT:
        ds_put_cstr(s, "--");
        break;
    case LEX_T_COLON:
        ds_put_char(s, ':');
        break;
    default:
        OVS_NOT_REACHED();
    }

}

/* lex_token_parse(). */

static void OVS_PRINTF_FORMAT(2, 3)
lex_error(struct lex_token *token, const char *message, ...)
{
    ovs_assert(!token->s);
    token->type = LEX_T_ERROR;

    va_list args;
    va_start(args, message);
    lex_token_vsprintf(token, message, args);
    va_end(args);
}

static void
lex_parse_hex_integer(const char *start, size_t len, struct lex_token *token)
{
    const char *in = start + (len - 1);
    uint8_t *out = token->value.u8 + (sizeof token->value.u8 - 1);

    for (int i = 0; i < len; i++) {
        int hexit = hexit_value(in[-i]);
        if (hexit < 0) {
            lex_error(token, "Invalid syntax in hexadecimal constant.");
            return;
        }
        if (hexit && i / 2 >= sizeof token->value.u8) {
            lex_error(token, "Hexadecimal constant requires more than "
                      "%"PRIuSIZE" bits.", 8 * sizeof token->value.u8);
            return;
        }
        out[-(i / 2)] |= i % 2 ? hexit << 4 : hexit;
    }
    token->format = LEX_F_HEXADECIMAL;
}

static const char *
lex_parse_integer__(const char *p, struct lex_token *token)
{
    lex_token_init(token);
    token->type = LEX_T_INTEGER;
    memset(&token->value, 0, sizeof token->value);

    /* Find the extent of an "integer" token, which can be in decimal or
     * hexadecimal, or an Ethernet address or IPv4 or IPv6 address, as 'start'
     * through 'end'.
     *
     * Special cases we handle here are:
     *
     *     - The ellipsis token "..", used as e.g. 123..456.  A doubled dot
     *       is never valid syntax as part of an "integer", so we stop if
     *       we encounter two dots in a row.
     *
     *     - Syntax like 1.2.3.4:1234 to indicate an IPv4 address followed by a
     *       port number should be considered three tokens: 1.2.3.4 : 1234.
     *       The obvious approach is to allow just dots or just colons within a
     *       given integer, but that would disallow IPv4-mapped IPv6 addresses,
     *       e.g. ::ffff:192.0.2.128.  However, even in those addresses, a
     *       colon never follows a dot, so we stop if we encounter a colon
     *       after a dot.
     *
     *       (There is no corresponding way to parse an IPv6 address followed
     *       by a port number: ::1:2:3:4:1234 is unavoidably ambiguous.)
     */
    const char *start = p;
    const char *end = start;
    bool saw_dot = false;
    while (isalnum((unsigned char) *end)
           || (*end == ':' && !saw_dot)
           || (*end == '.' && end[1] != '.')) {
        if (*end == '.') {
            saw_dot = true;
        }
        end++;
    }
    size_t len = end - start;

    int n;
    struct eth_addr mac;

    if (!len) {
        lex_error(token, "Integer constant expected.");
    } else if (len == 17
               && ovs_scan(start, ETH_ADDR_SCAN_FMT"%n",
                           ETH_ADDR_SCAN_ARGS(mac), &n)
               && n == len) {
        token->value.mac = mac;
        token->format = LEX_F_ETHERNET;
    } else if (start + strspn(start, "0123456789") == end) {
        if (p[0] == '0' && len > 1) {
            lex_error(token, "Decimal constants must not have leading zeros.");
        } else {
            unsigned long long int integer;
            char *tail;

            errno = 0;
            integer = strtoull(p, &tail, 10);
            if (tail != end || errno == ERANGE) {
                lex_error(token, "Decimal constants must be less than 2**64.");
            } else {
                token->value.integer = htonll(integer);
                token->format = LEX_F_DECIMAL;
            }
        }
    } else if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        if (len > 2) {
            lex_parse_hex_integer(start + 2, len - 2, token);
        } else {
            lex_error(token, "Hex digits expected following 0%c.", p[1]);
        }
    } else if (len < INET6_ADDRSTRLEN) {
        char copy[INET6_ADDRSTRLEN];
        memcpy(copy, p, len);
        copy[len] = '\0';

        if (ip_parse(copy, &token->value.ipv4)) {
            token->format = LEX_F_IPV4;
        } else if (ipv6_parse(copy, &token->value.ipv6)) {
            token->format = LEX_F_IPV6;
        } else {
            lex_error(token, "Invalid numeric constant.");
        }
    } else {
        lex_error(token, "Invalid numeric constant.");
    }

    ovs_assert(token->type == LEX_T_INTEGER || token->type == LEX_T_ERROR);
    return end;
}

static const char *
lex_parse_mask(const char *p, struct lex_token *token)
{
    struct lex_token mask;

    /* Parse just past the '/' as a second integer.  Handle errors. */
    p = lex_parse_integer__(p + 1, &mask);
    if (mask.type == LEX_T_ERROR) {
        lex_token_swap(&mask, token);
        lex_token_destroy(&mask);
        return p;
    }
    ovs_assert(mask.type == LEX_T_INTEGER);

    /* Now convert the value and mask into a masked integer token.
     * We have a few special cases. */
    token->type = LEX_T_MASKED_INTEGER;
    memset(&token->mask, 0, sizeof token->mask);
    uint32_t prefix_bits = ntohll(mask.value.integer);
    if (token->format == mask.format) {
        /* Same format value and mask is always OK. */
        token->mask = mask.value;
    } else if (token->format == LEX_F_IPV4
               && mask.format == LEX_F_DECIMAL
               && prefix_bits <= 32) {
        /* IPv4 address with decimal mask is a CIDR prefix. */
        token->mask.integer = htonll(ntohl(be32_prefix_mask(prefix_bits)));
    } else if (token->format == LEX_F_IPV6
               && mask.format == LEX_F_DECIMAL
               && prefix_bits <= 128) {
        /* IPv6 address with decimal mask is a CIDR prefix. */
        token->mask.ipv6 = ipv6_create_mask(prefix_bits);
    } else if (token->format == LEX_F_DECIMAL
               && mask.format == LEX_F_HEXADECIMAL
               && token->value.integer == 0) {
        /* Special case for e.g. 0/0x1234. */
        token->format = LEX_F_HEXADECIMAL;
        token->mask = mask.value;
    } else {
        lex_error(token, "Value and mask have incompatible formats.");
        return p;
    }

    /* Check invariant that a 1-bit in the value corresponds to a 1-bit in the
     * mask. */
    for (int i = 0; i < ARRAY_SIZE(token->mask.be32); i++) {
        ovs_be32 v = token->value.be32[i];
        ovs_be32 m = token->mask.be32[i];

        if (v & ~m) {
            lex_error(token, "Value contains unmasked 1-bits.");
            break;
        }
    }

    /* Done! */
    lex_token_destroy(&mask);
    return p;
}

static const char *
lex_parse_integer(const char *p, struct lex_token *token)
{
    p = lex_parse_integer__(p, token);
    if (token->type == LEX_T_INTEGER && *p == '/') {
        p = lex_parse_mask(p, token);
    }
    return p;
}

static const char *
lex_parse_string(const char *p, struct lex_token *token)
{
    const char *start = ++p;
    char * s = NULL;
    for (;;) {
        switch (*p) {
        case '\0':
            lex_error(token, "Input ends inside quoted string.");
            return p;

        case '"':
            token->type = (json_string_unescape(start, p - start, &s)
                           ? LEX_T_STRING : LEX_T_ERROR);
            lex_token_strset(token, s);
            return p + 1;

        case '\\':
            p++;
            if (*p) {
                p++;
            }
            break;

        default:
            p++;
            break;
        }
    }
}

static bool
lex_is_id1(unsigned char c)
{
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || c == '_' || c == '.');
}

static bool
lex_is_idn(unsigned char c)
{
    return lex_is_id1(c) || (c >= '0' && c <= '9');
}

static const char *
lex_parse_id(const char *p, enum lex_type type, struct lex_token *token)
{
    const char *start = p;

    do {
        p++;
    } while (lex_is_idn(*p));

    token->type = type;
    lex_token_strcpy(token, start, p - start);
    return p;
}

static const char *
lex_parse_addr_set(const char *p, struct lex_token *token)
{
    p++;
    if (!lex_is_id1(*p)) {
        lex_error(token, "`$' must be followed by a valid identifier.");
        return p;
    }

    return lex_parse_id(p, LEX_T_MACRO, token);
}

static const char *
lex_parse_port_group(const char *p, struct lex_token *token)
{
    p++;
    if (!lex_is_id1(*p)) {
        lex_error(token, "`@' must be followed by a valid identifier.");
        return p;
    }

    return lex_parse_id(p, LEX_T_PORT_GROUP, token);
}

/* Initializes 'token' and parses the first token from the beginning of
 * null-terminated string 'p' into 'token'.  Stores a pointer to the start of
 * the token (after skipping white space and comments, if any) into '*startp'.
 * Returns the character position at which to begin parsing the next token. */
const char *
lex_token_parse(struct lex_token *token, const char *p, const char **startp)
{
    lex_token_init(token);

next:
    *startp = p;
    switch (*p) {
    case '\0':
        token->type = LEX_T_END;
        return p;

    case ' ': case '\t': case '\n': case '\r': case '\v': case '\f':
        p++;
        goto next;

    case '/':
        p++;
        if (*p == '/') {
            do {
                p++;
            } while (*p != '\0' && *p != '\n');
            goto next;
        } else if (*p == '*') {
            p++;
            for (;;) {
                if (*p == '*' && p[1] == '/') {
                    p += 2;
                    goto next;
                } else if (*p == '\0' || *p == '\n') {
                    lex_error(token, "`/*' without matching `*/'.");
                    return p;
                } else {
                    p++;
                }
            }
            goto next;
        } else {
            lex_error(token,
                      "`/' is only valid as part of `//' or `/*'.");
        }
        break;

    case '(':
        token->type = LEX_T_LPAREN;
        p++;
        break;

    case ')':
        token->type = LEX_T_RPAREN;
        p++;
        break;

    case '{':
        token->type = LEX_T_LCURLY;
        p++;
        break;

    case '}':
        token->type = LEX_T_RCURLY;
        p++;
        break;

    case '[':
        token->type = LEX_T_LSQUARE;
        p++;
        break;

    case ']':
        token->type = LEX_T_RSQUARE;
        p++;
        break;

    case '=':
        p++;
        if (*p == '=') {
            token->type = LEX_T_EQ;
            p++;
        } else {
            token->type = LEX_T_EQUALS;
        }
        break;

    case '!':
        p++;
        if (*p == '=') {
            token->type = LEX_T_NE;
            p++;
        } else {
            token->type = LEX_T_LOG_NOT;
        }
        break;

    case '&':
        p++;
        if (*p == '&') {
            token->type = LEX_T_LOG_AND;
            p++;
        } else {
            lex_error(token, "`&' is only valid as part of `&&'.");
        }
        break;

    case '|':
        p++;
        if (*p == '|') {
            token->type = LEX_T_LOG_OR;
            p++;
        } else {
            lex_error(token, "`|' is only valid as part of `||'.");
        }
        break;

    case '<':
        p++;
        if (*p == '=') {
            token->type = LEX_T_LE;
            p++;
        } else if (*p == '-' && p[1] == '>') {
            token->type = LEX_T_EXCHANGE;
            p += 2;
        } else {
            token->type = LEX_T_LT;
        }
        break;

    case '>':
        p++;
        if (*p == '=') {
            token->type = LEX_T_GE;
            p++;
        } else {
            token->type = LEX_T_GT;
        }
        break;

    case '.':
        p++;
        if (*p == '.') {
            token->type = LEX_T_ELLIPSIS;
            p++;
        } else {
            lex_error(token, "`.' is only valid as part of `..' or a number.");
        }
        break;

    case ',':
        p++;
        token->type = LEX_T_COMMA;
        break;

    case ';':
        p++;
        token->type = LEX_T_SEMICOLON;
        break;

    case '-':
        p++;
        if (*p == '-') {
            token->type = LEX_T_DECREMENT;
            p++;
        } else {
            lex_error(token, "`-' is only valid as part of `--'.");
        }
        break;

    case '$':
        p = lex_parse_addr_set(p, token);
        break;

    case '@':
        p = lex_parse_port_group(p, token);
        break;

    case ':':
        if (p[1] != ':') {
            token->type = LEX_T_COLON;
            p++;
            break;
        }
        /* IPv6 address beginning with "::". */
        /* fall through */
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        p = lex_parse_integer(p, token);
        break;

    case '"':
        p = lex_parse_string(p, token);
        break;

    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
        /* We need to distinguish an Ethernet address or IPv6 address from an
         * identifier.  Fortunately, Ethernet addresses and IPv6 addresses that
         * are ambiguous based on the first character, always start with hex
         * digits followed by a colon, but identifiers never do. */
        p = (p[strspn(p, "0123456789abcdefABCDEF")] == ':'
             ? lex_parse_integer(p, token)
             : lex_parse_id(p, LEX_T_ID, token));
        break;

    default:
        if (lex_is_id1(*p)) {
            p = lex_parse_id(p, LEX_T_ID, token);
        } else {
            if (isprint((unsigned char) *p)) {
                lex_error(token, "Invalid character `%c' in input.", *p);
            } else {
                lex_error(token, "Invalid byte 0x%d in input.", *p);
            }
            p++;
        }
        break;
    }

    return p;
}

/* Initializes 'lexer' for parsing 'input'.
 *
 * While the lexer is in use, 'input' must remain available, but the caller
 * otherwise retains ownership of 'input'.
 *
 * The caller must call lexer_get() to obtain the first token. */
void
lexer_init(struct lexer *lexer, const char *input)
{
    lexer->input = input;
    lexer->start = NULL;
    lex_token_init(&lexer->token);
    lexer->error = NULL;
}

/* Frees storage associated with 'lexer'. */
void
lexer_destroy(struct lexer *lexer)
{
    lex_token_destroy(&lexer->token);
    free(lexer->error);
}

/* Obtains the next token from 'lexer' into 'lexer->token', and returns the
 * token's type.  The caller may examine 'lexer->token' directly to obtain full
 * information about the token. */
enum lex_type
lexer_get(struct lexer *lexer)
{
    lex_token_destroy(&lexer->token);
    lexer->input = lex_token_parse(&lexer->token, lexer->input, &lexer->start);
    return lexer->token.type;
}

/* Returns the type of the next token that will be fetched by lexer_get(),
 * without advancing 'lexer->token' to that token. */
enum lex_type
lexer_lookahead(const struct lexer *lexer)
{
    struct lex_token next;
    enum lex_type type;
    const char *start;

    lex_token_parse(&next, lexer->input, &start);
    type = next.type;
    lex_token_destroy(&next);
    return type;
}

/* If 'lexer''s current token has the given 'type', advances 'lexer' to the
 * next token and returns true.  Otherwise returns false. */
bool
lexer_match(struct lexer *lexer, enum lex_type type)
{
    if (lexer->token.type == type) {
        lexer_get(lexer);
        return true;
    } else {
        return false;
    }
}

bool
lexer_force_match(struct lexer *lexer, enum lex_type t)
{
    if (t == LEX_T_END) {
        return lexer_force_end(lexer);
    } else if (lexer_match(lexer, t)) {
        return true;
    } else {
        struct lex_token token = { .type = t };
        struct ds s = DS_EMPTY_INITIALIZER;
        lex_token_format(&token, &s);

        lexer_syntax_error(lexer, "expecting `%s'", ds_cstr(&s));

        ds_destroy(&s);

        return false;
    }
}

/* If 'lexer''s current token is the identifier given in 'id', advances 'lexer'
 * to the next token and returns true.  Otherwise returns false.  */
bool
lexer_match_id(struct lexer *lexer, const char *id)
{
    if (lexer->token.type == LEX_T_ID && !strcmp(lexer->token.s, id)) {
        lexer_get(lexer);
        return true;
    } else {
        return false;
    }
}

bool
lexer_is_int(const struct lexer *lexer)
{
    return (lexer->token.type == LEX_T_INTEGER
            && lexer->token.format == LEX_F_DECIMAL
            && ntohll(lexer->token.value.integer) <= INT_MAX);
}

bool
lexer_get_int(struct lexer *lexer, int *value)
{
    if (lexer_is_int(lexer)) {
        *value = ntohll(lexer->token.value.integer);
        lexer_get(lexer);
        return true;
    } else {
        *value = 0;
        return false;
    }
}

bool
lexer_force_int(struct lexer *lexer, int *value)
{
    bool ok = lexer_get_int(lexer, value);
    if (!ok) {
        lexer_syntax_error(lexer, "expecting small integer");
    }
    return ok;
}

bool
lexer_force_end(struct lexer *lexer)
{
    if (lexer->token.type == LEX_T_END) {
        return true;
    } else {
        lexer_syntax_error(lexer, "expecting end of input");
        return false;
    }
}

static bool
lexer_error_handle_common(struct lexer *lexer)
{
    if (lexer->error) {
        /* Already have an error, suppress this one since the cascade seems
         * unlikely to be useful. */
        return true;
    } else if (lexer->token.type == LEX_T_ERROR) {
        /* The lexer signaled an error.  Nothing at a higher level accepts an
         * error token, so we'll inevitably end up here with some meaningless
         * parse error.  Report the lexical error instead. */
        lexer->error = xstrdup(lexer->token.s);
        return true;
    } else {
        return false;
    }
}

void OVS_PRINTF_FORMAT(2, 3)
lexer_error(struct lexer *lexer, const char *message, ...)
{
    if (lexer_error_handle_common(lexer)) {
        return;
    }

    va_list args;
    va_start(args, message);
    lexer->error = xvasprintf(message, args);
    va_end(args);
}

void OVS_PRINTF_FORMAT(2, 3)
lexer_syntax_error(struct lexer *lexer, const char *message, ...)
{
    if (lexer_error_handle_common(lexer)) {
        return;
    }

    struct ds s;

    ds_init(&s);
    ds_put_cstr(&s, "Syntax error");
    if (lexer->token.type == LEX_T_END) {
        ds_put_cstr(&s, " at end of input");
    } else if (lexer->start) {
        ds_put_format(&s, " at `%.*s'",
                      (int) (lexer->input - lexer->start),
                      lexer->start);
    }

    if (message) {
        ds_put_char(&s, ' ');

        va_list args;
        va_start(args, message);
        ds_put_format_valist(&s, message, args);
        va_end(args);
    }
    ds_put_char(&s, '.');

    lexer->error = ds_steal_cstr(&s);
}

char *
lexer_steal_error(struct lexer *lexer)
{
    char *error = lexer->error;
    lexer->error = NULL;
    return error;
}
