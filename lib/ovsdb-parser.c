/* Copyright (c) 2009, 2011, 2013, 2015 Nicira, Inc.
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

#include "ovsdb-parser.h"

#include <ctype.h>
#include <stdarg.h>

#include "ovsdb-error.h"

void
ovsdb_parser_init(struct ovsdb_parser *parser, const struct json *json,
                  const char *name, ...)
{
    va_list args;

    va_start(args, name);
    parser->name = xvasprintf(name, args);
    va_end(args);

    sset_init(&parser->used);
    parser->error = NULL;

    parser->json = (json && json->type == JSON_OBJECT ? json : NULL);
    if (!parser->json) {
        ovsdb_parser_raise_error(parser, "Object expected.");
    }
}

bool
ovsdb_parser_is_id(const char *string)
{
    unsigned char c;

    c = *string;
    if (!isalpha(c) && c != '_') {
        return false;
    }

    for (;;) {
        c = *++string;
        if (c == '\0') {
            return true;
        } else if (!isalpha(c) && !isdigit(c) && c != '_') {
            return false;
        }
    }
}

const struct json *
ovsdb_parser_member(struct ovsdb_parser *parser, const char *name,
                    enum ovsdb_parser_types types)
{
    struct json *value;

    if (!parser->json) {
        return NULL;
    }

    value = shash_find_data(json_object(parser->json), name);
    if (!value) {
        if (!(types & OP_OPTIONAL)) {
            ovsdb_parser_raise_error(parser,
                                     "Required '%s' member is missing.", name);
        }
        return NULL;
    }

    if (((int) value->type >= 0 && value->type < JSON_N_TYPES
         && types & (1u << value->type))
        || (types & OP_ID && value->type == JSON_STRING
            && ovsdb_parser_is_id(value->u.string)))
    {
        sset_add(&parser->used, name);
        return value;
    } else {
        ovsdb_parser_raise_error(parser, "Type mismatch for member '%s'.",
                                 name);
        return NULL;
    }
}

void
ovsdb_parser_raise_error(struct ovsdb_parser *parser, const char *format, ...)
{
    if (!parser->error) {
        struct ovsdb_error *error;
        va_list args;
        char *message;

        va_start(args, format);
        message = xvasprintf(format, args);
        va_end(args);

        error = ovsdb_syntax_error(parser->json, NULL, "Parsing %s failed: %s",
                                   parser->name, message);
        free(message);

        parser->error = error;
    }
}

struct ovsdb_error *
ovsdb_parser_get_error(const struct ovsdb_parser *parser)
{
    return parser->error ? ovsdb_error_clone(parser->error) : NULL;
}

bool
ovsdb_parser_has_error(const struct ovsdb_parser *parser)
{
    return parser->error != NULL;
}

struct ovsdb_error *
ovsdb_parser_destroy(struct ovsdb_parser *parser)
{
    free(parser->name);
    sset_destroy(&parser->used);

    return parser->error;
}

struct ovsdb_error *
ovsdb_parser_finish(struct ovsdb_parser *parser)
{
    if (!parser->error) {
        const struct shash *object = json_object(parser->json);
        size_t n_unused;

        n_unused = shash_count(object) - sset_count(&parser->used);
        if (n_unused) {
            struct shash_node *node;

            SHASH_FOR_EACH (node, object) {
                if (!sset_contains(&parser->used, node->name)) {
                    if (n_unused > 1) {
                        ovsdb_parser_raise_error(
                            parser,
                            "Member '%s' and %"PRIuSIZE" other member%s "
                            "are present but not allowed here.",
                            node->name, n_unused - 1, n_unused > 2 ? "s" : "");
                    } else {
                        ovsdb_parser_raise_error(
                            parser,
                            "Member '%s' is present but not allowed here.",
                            node->name);
                    }
                    break;
                }
            }
        }
    }

    return ovsdb_parser_destroy(parser);
}
