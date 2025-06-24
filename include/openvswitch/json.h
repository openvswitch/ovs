/*
 * Copyright (c) 2009, 2010, 2015, 2016 Nicira, Inc.
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

#ifndef OPENVSWITCH_JSON_H
#define OPENVSWITCH_JSON_H 1

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

#include <stdio.h>
#include "openvswitch/shash.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ds;
struct uuid;

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
    JSON_N_TYPES,
    JSON_SERIALIZED_OBJECT,     /* Internal type to hold serialized version of
                                 * data of other types. */
};

const char *json_type_to_string(enum json_type);

/* A JSON array. */
struct json_array {
    size_t size, allocated;
    struct json **elements;
};

/* Maximum string length that can be stored inline ('\0' is not included). */
#define JSON_STRING_INLINE_LEN (sizeof(struct json_array) - 1)

enum json_storage_type {
    JSON_STRING_DYNAMIC = 0, /* JSON_STRING is stored via 'str_ptr'. */
    JSON_STRING_INLINE,      /* JSON_STRING is stored in 'str' array. */
};

/* A JSON value. */
struct json {
    enum json_type type;
    enum json_storage_type storage_type;
    size_t count;
    union {
        struct shash *object;   /* Contains "struct json *"s. */
        struct json_array array;
        long long int integer;
        double real;
        union {
            char str[JSON_STRING_INLINE_LEN + 1];
            char *str_ptr;
        }; /* JSON_STRING or JSON_SERIALIZED_OBJECT. */
    };
};

struct json *json_null_create(void);
struct json *json_boolean_create(bool);
struct json *json_string_create(const char *);
struct json *json_string_create_nocopy(char *);
struct json *json_string_create_uuid(const struct uuid *);
struct json *json_serialized_object_create(const struct json *);
struct json *json_integer_create(long long int);
struct json *json_real_create(double);

struct json *json_array_create_empty(void);
void json_array_add(struct json *, struct json *element);
void json_array_set(struct json *, size_t index, struct json *element);
struct json *json_array_pop(struct json *);
void json_array_trim(struct json *);
struct json *json_array_create(struct json **, size_t n);
struct json *json_array_create_1(struct json *);
struct json *json_array_create_2(struct json *, struct json *);
struct json *json_array_create_3(struct json *, struct json *, struct json *);
bool json_array_contains_string(const struct json *, const char *);

struct json *json_object_create(void);
void json_object_put(struct json *, const char *name, struct json *value);
void json_object_put_nocopy(struct json *, char *name, struct json *value);
void json_object_put_string(struct json *,
                            const char *name, const char *value);
void json_object_put_format(struct json *,
                            const char *name, const char *format, ...)
    OVS_PRINTF_FORMAT(3, 4);
void json_object_put_uuid(struct json *, const char *name,
                          const struct uuid *);

const char *json_string(const struct json *);
const char *json_serialized_object(const struct json *);
size_t json_array_size(const struct json *);
const struct json *json_array_at(const struct json *, size_t index);
struct shash *json_object(const struct json *);
bool json_boolean(const struct json *);
double json_real(const struct json *);
int64_t json_integer(const struct json *);

struct json *json_deep_clone(const struct json *);
static inline struct json *json_clone(const struct json *);
struct json *json_nullable_clone(const struct json *);
static inline void json_destroy(struct json *);

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
struct json *json_from_serialized_object(const struct json *);
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
void json_string_escape(const char *in, struct ds *out);

/* Inline functions. */

/* Returns 'json', with the reference count incremented. */
static inline struct json *
json_clone(const struct json *json_)
{
    struct json *json = CONST_CAST(struct json *, json_);
    json->count++;
    return json;
}

void json_destroy__(struct json *json, bool);

/* Frees 'json' and everything it points to, recursively. */
static inline void
json_destroy(struct json *json)
{
    if (json && !--json->count) {
        json_destroy__(json, false);
    }
}

#ifdef  __cplusplus
}
#endif

#endif /* OPENVSWITCH_JSON_H */
