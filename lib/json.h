/*
 * Copyright (c) 2009, 2010 Nicira, Inc.
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

#ifndef JSON_H
#define JSON_H 1

/* This is an implementation of JavaScript Object Notation (JSON) as specified
 * by RFC 4627.  It is intended to fully comply with RFC 4627, with the
 * following known exceptions and clarifications:
 *
 *      - Null bytes (\u0000) are not allowed in strings.
 *
 *      - Only UTF-8 encoding is supported (RFC 4627 allows for other Unicode
 *        encodings).
 *
 *      - Names within an object must be unique (RFC 4627 says that they
 *        "should" be unique).
 */

#include "shash.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ds;

/* Type of a JSON value. */
enum json_type {
    JSON_NULL,                  /* null */
    JSON_FALSE,                 /* false */
    JSON_TRUE,                  /* true */
    JSON_OBJECT,                /* {"a": b, "c": d, ...} */
    JSON_ARRAY,                 /* [1, 2, 3, ...] */
    JSON_INTEGER,               /* 123. */
    JSON_REAL,                  /* 123.456. */
    JSON_STRING,                /* "..." */
    JSON_N_TYPES
};

const char *json_type_to_string(enum json_type);

/* A JSON array. */
struct json_array {
    size_t n, n_allocated;
    struct json **elems;
};

/* A JSON value. */
struct json {
    enum json_type type;
    union {
        struct shash *object;   /* Contains "struct json *"s. */
        struct json_array array;
        long long int integer;
        double real;
        char *string;
    } u;
};

struct json *json_null_create(void);
struct json *json_boolean_create(bool);
struct json *json_string_create(const char *);
struct json *json_string_create_nocopy(char *);
struct json *json_integer_create(long long int);
struct json *json_real_create(double);

struct json *json_array_create_empty(void);
void json_array_add(struct json *, struct json *element);
void json_array_trim(struct json *);
struct json *json_array_create(struct json **, size_t n);
struct json *json_array_create_1(struct json *);
struct json *json_array_create_2(struct json *, struct json *);
struct json *json_array_create_3(struct json *, struct json *, struct json *);

struct json *json_object_create(void);
void json_object_put(struct json *, const char *name, struct json *value);
void json_object_put_string(struct json *,
                            const char *name, const char *value);

const char *json_string(const struct json *);
struct json_array *json_array(const struct json *);
struct shash *json_object(const struct json *);
bool json_boolean(const struct json *);
double json_real(const struct json *);
int64_t json_integer(const struct json *);

struct json *json_clone(const struct json *);
void json_destroy(struct json *);

size_t json_hash(const struct json *, size_t basis);
bool json_equal(const struct json *, const struct json *);

/* Parsing JSON. */
enum {
    JSPF_TRAILER = 1 << 0       /* Check for garbage following input.  */
};

struct json_parser *json_parser_create(int flags);
size_t json_parser_feed(struct json_parser *, const char *, size_t);
bool json_parser_is_done(const struct json_parser *);
struct json *json_parser_finish(struct json_parser *);
void json_parser_abort(struct json_parser *);

struct json *json_from_string(const char *string);
struct json *json_from_file(const char *file_name);
struct json *json_from_stream(FILE *stream);

/* Serializing JSON. */

enum {
    JSSF_PRETTY = 1 << 0,       /* Multiple lines with indentation, if true. */
    JSSF_SORT = 1 << 1          /* Object members in sorted order, if true. */
};
char *json_to_string(const struct json *, int flags);
void json_to_ds(const struct json *, int flags, struct ds *);

/* JSON string formatting operations. */

bool json_string_unescape(const char *in, size_t in_len, char **outp);

#ifdef  __cplusplus
}
#endif

#endif /* json.h */
