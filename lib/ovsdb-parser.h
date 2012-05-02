/* Copyright (c) 2009, 2010, 2011 Nicira, Inc.
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

#ifndef OVSDB_PARSER_H
#define OVSDB_PARSER_H 1

#include <stdbool.h>
#include "compiler.h"
#include "json.h"
#include "sset.h"
#include "util.h"

struct ovsdb_parser {
    char *name;                 /* Used only in error messages. */
    struct sset used;           /* Already-parsed names from 'object'. */
    const struct json *json;    /* JSON object being parsed. */
    struct ovsdb_error *error;  /* Error signaled, if any. */
};

/* Check that the JSON types make the bitwise tricks below work OK. */
BUILD_ASSERT_DECL(JSON_NULL >= 0 && JSON_NULL < 10);
BUILD_ASSERT_DECL(JSON_FALSE >= 0 && JSON_FALSE < 10);
BUILD_ASSERT_DECL(JSON_TRUE >= 0 && JSON_TRUE < 10);
BUILD_ASSERT_DECL(JSON_OBJECT >= 0 && JSON_OBJECT < 10);
BUILD_ASSERT_DECL(JSON_ARRAY >= 0 && JSON_ARRAY < 10);
BUILD_ASSERT_DECL(JSON_INTEGER >= 0 && JSON_INTEGER < 10);
BUILD_ASSERT_DECL(JSON_REAL >= 0 && JSON_REAL < 10);
BUILD_ASSERT_DECL(JSON_STRING >= 0 && JSON_STRING < 10);
BUILD_ASSERT_DECL(JSON_N_TYPES == 8);

enum ovsdb_parser_types {
    OP_NULL = 1 << JSON_NULL,             /* null */
    OP_FALSE = 1 << JSON_FALSE,           /* false */
    OP_TRUE = 1 << JSON_TRUE,             /* true */
    OP_OBJECT = 1 << JSON_OBJECT,         /* {"a": b, "c": d, ...} */
    OP_ARRAY = 1 << JSON_ARRAY,           /* [1, 2, 3, ...] */
    OP_INTEGER = 1 << JSON_INTEGER,       /* 123. */
    OP_NONINTEGER = 1 << JSON_REAL,       /* 123.456. */
    OP_STRING = 1 << JSON_STRING,         /* "..." */
    OP_ANY = (OP_NULL | OP_FALSE | OP_TRUE | OP_OBJECT | OP_ARRAY
              | OP_INTEGER | OP_NONINTEGER | OP_STRING),

    OP_BOOLEAN = OP_FALSE | OP_TRUE,
    OP_NUMBER = OP_INTEGER | OP_NONINTEGER,

    OP_ID = 1 << JSON_N_TYPES,            /* "[_a-zA-Z][_a-zA-Z0-9]*" */
    OP_OPTIONAL = 1 << (JSON_N_TYPES + 1) /* no value at all */
};

void ovsdb_parser_init(struct ovsdb_parser *, const struct json *,
                       const char *name, ...)
    PRINTF_FORMAT(3, 4);
const struct json *ovsdb_parser_member(struct ovsdb_parser *, const char *name,
                                       enum ovsdb_parser_types);

void ovsdb_parser_raise_error(struct ovsdb_parser *parser,
                              const char *format, ...)
    PRINTF_FORMAT(2, 3);
bool ovsdb_parser_has_error(const struct ovsdb_parser *);
struct ovsdb_error *ovsdb_parser_get_error(const struct ovsdb_parser *);
struct ovsdb_error *ovsdb_parser_finish(struct ovsdb_parser *)
    WARN_UNUSED_RESULT;
void ovsdb_parser_destroy(struct ovsdb_parser *);

bool ovsdb_parser_is_id(const char *string);

#endif /* ovsdb-parser.h */
