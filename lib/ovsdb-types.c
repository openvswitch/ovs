/* Copyright (c) 2009 Nicira Networks
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

#include "ovsdb-types.h"

#include <limits.h>

#include "dynamic-string.h"
#include "json.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"

const struct ovsdb_type ovsdb_type_integer =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_TYPE_INTEGER);
const struct ovsdb_type ovsdb_type_real =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_TYPE_REAL);
const struct ovsdb_type ovsdb_type_boolean =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_TYPE_BOOLEAN);
const struct ovsdb_type ovsdb_type_string =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_TYPE_STRING);
const struct ovsdb_type ovsdb_type_uuid =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_TYPE_UUID);

const char *
ovsdb_atomic_type_to_string(enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        return "void";

    case OVSDB_TYPE_INTEGER:
        return "integer";

    case OVSDB_TYPE_REAL:
        return "real";

    case OVSDB_TYPE_BOOLEAN:
        return "boolean";

    case OVSDB_TYPE_STRING:
        return "string";

    case OVSDB_TYPE_UUID:
        return "uuid";

    case OVSDB_N_TYPES:
    default:
        return "<invalid>";
    }
}

struct json *
ovsdb_atomic_type_to_json(enum ovsdb_atomic_type type)
{
    return json_string_create(ovsdb_atomic_type_to_string(type));
}

bool
ovsdb_type_is_valid(const struct ovsdb_type *type)
{
    return (type->key_type != OVSDB_TYPE_VOID
            && ovsdb_atomic_type_is_valid(type->key_type)
            && ovsdb_atomic_type_is_valid(type->value_type)
            && type->n_min <= type->n_max
            && (type->value_type == OVSDB_TYPE_VOID
                || ovsdb_atomic_type_is_valid_key(type->key_type)));
}

bool
ovsdb_atomic_type_from_string(const char *string, enum ovsdb_atomic_type *type)
{
    if (!strcmp(string, "integer")) {
        *type = OVSDB_TYPE_INTEGER;
    } else if (!strcmp(string, "real")) {
        *type = OVSDB_TYPE_REAL;
    } else if (!strcmp(string, "boolean")) {
        *type = OVSDB_TYPE_BOOLEAN;
    } else if (!strcmp(string, "string")) {
        *type = OVSDB_TYPE_STRING;
    } else if (!strcmp(string, "uuid")) {
        *type = OVSDB_TYPE_UUID;
    } else {
        return false;
    }
    return true;
}

struct ovsdb_error *
ovsdb_atomic_type_from_json(enum ovsdb_atomic_type *type,
                            const struct json *json)
{
    if (json->type == JSON_STRING) {
        if (ovsdb_atomic_type_from_string(json_string(json), type)) {
            return NULL;
        } else {
            *type = OVSDB_TYPE_VOID;
            return ovsdb_syntax_error(json, NULL,
                                      "\"%s\" is not an atomic-type",
                                      json_string(json));
        }
    } else {
        *type = OVSDB_TYPE_VOID;
        return ovsdb_syntax_error(json, NULL, "atomic-type expected");
    }
}

static struct ovsdb_error *
n_from_json(const struct json *json, unsigned int *n)
{
    if (!json) {
        return NULL;
    } else if (json->type == JSON_INTEGER
               && json->u.integer >= 0 && json->u.integer < UINT_MAX) {
        *n = json->u.integer;
        return NULL;
    } else {
        return ovsdb_syntax_error(json, NULL, "bad min or max value");
    }
}

char *
ovsdb_type_to_english(const struct ovsdb_type *type)
{
    const char *key = ovsdb_atomic_type_to_string(type->key_type);
    const char *value = ovsdb_atomic_type_to_string(type->value_type);
    if (ovsdb_type_is_scalar(type)) {
        return xstrdup(key);
    } else {
        struct ds s = DS_EMPTY_INITIALIZER;
        ds_put_cstr(&s, ovsdb_type_is_set(type) ? "set" : "map");
        if (type->n_max == UINT_MAX) {
            if (type->n_min) {
                ds_put_format(&s, " of %u or more", type->n_min);
            } else {
                ds_put_cstr(&s, " of");
            }
        } else if (type->n_min) {
            ds_put_format(&s, " of %u to %u", type->n_min, type->n_max);
        } else {
            ds_put_format(&s, " of up to %u", type->n_max);
        }
        if (ovsdb_type_is_set(type)) {
            ds_put_format(&s, " %ss", key);
        } else {
            ds_put_format(&s, " (%s, %s) pairs", key, value);
        }
        return ds_cstr(&s);
    }
}

struct ovsdb_error *
ovsdb_type_from_json(struct ovsdb_type *type, const struct json *json)
{
    type->value_type = OVSDB_TYPE_VOID;
    type->n_min = 1;
    type->n_max = 1;

    if (json->type == JSON_STRING) {
        return ovsdb_atomic_type_from_json(&type->key_type, json);
    } else if (json->type == JSON_OBJECT) {
        const struct json *key, *value, *min, *max;
        struct ovsdb_error *error;
        struct ovsdb_parser parser;

        ovsdb_parser_init(&parser, json, "ovsdb type");
        key = ovsdb_parser_member(&parser, "key", OP_STRING);
        value = ovsdb_parser_member(&parser, "value", OP_STRING | OP_OPTIONAL);
        min = ovsdb_parser_member(&parser, "min", OP_INTEGER | OP_OPTIONAL);
        max = ovsdb_parser_member(&parser, "max",
                                  OP_INTEGER | OP_STRING | OP_OPTIONAL);
        error = ovsdb_parser_finish(&parser);
        if (error) {
            return error;
        }

        error = ovsdb_atomic_type_from_json(&type->key_type, key);
        if (error) {
            return error;
        }

        if (value) {
            error = ovsdb_atomic_type_from_json(&type->value_type, value);
            if (error) {
                return error;
            }
        }

        error = n_from_json(min, &type->n_min);
        if (error) {
            return error;
        }

        if (max && max->type == JSON_STRING
            && !strcmp(max->u.string, "unlimited")) {
            type->n_max = UINT_MAX;
        } else {
            error = n_from_json(max, &type->n_max);
            if (error) {
                return error;
            }
        }

        if (!ovsdb_type_is_valid(type)) {
            return ovsdb_syntax_error(json, NULL,
                                      "ovsdb type fails constraint checks");
        }

        return NULL;
    } else {
        return ovsdb_syntax_error(json, NULL, "ovsdb type expected");
    }
}

struct json *
ovsdb_type_to_json(const struct ovsdb_type *type)
{
    if (ovsdb_type_is_scalar(type)) {
        return ovsdb_atomic_type_to_json(type->key_type);
    } else {
        struct json *json = json_object_create();
        json_object_put(json, "key",
                        ovsdb_atomic_type_to_json(type->key_type));
        if (type->value_type != OVSDB_TYPE_VOID) {
            json_object_put(json, "value",
                            ovsdb_atomic_type_to_json(type->value_type));
        }
        if (type->n_min != 1) {
            json_object_put(json, "min", json_integer_create(type->n_min));
        }
        if (type->n_max == UINT_MAX) {
            json_object_put_string(json, "max", "unlimited");
        } else if (type->n_max != 1) {
            json_object_put(json, "max", json_integer_create(type->n_max));
        }
        return json;
    }
}
