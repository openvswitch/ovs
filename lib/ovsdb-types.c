/* Copyright (c) 2009, 2010, 2011, 2013 Nicira, Inc.
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

#include <float.h>
#include <limits.h>

#include "dynamic-string.h"
#include "json.h"
#include "ovs-thread.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"

const struct ovsdb_type ovsdb_type_integer =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_BASE_INTEGER_INIT);
const struct ovsdb_type ovsdb_type_real =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_BASE_REAL_INIT);
const struct ovsdb_type ovsdb_type_boolean =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_BASE_BOOLEAN_INIT);
const struct ovsdb_type ovsdb_type_string =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_BASE_STRING_INIT);
const struct ovsdb_type ovsdb_type_uuid =
    OVSDB_TYPE_SCALAR_INITIALIZER(OVSDB_BASE_UUID_INIT);

/* ovsdb_atomic_type */
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

/* ovsdb_base_type */

void
ovsdb_base_type_init(struct ovsdb_base_type *base, enum ovsdb_atomic_type type)
{
    base->type = type;
    base->enum_ = NULL;

    switch (base->type) {
    case OVSDB_TYPE_VOID:
        break;

    case OVSDB_TYPE_INTEGER:
        base->u.integer.min = INT64_MIN;
        base->u.integer.max = INT64_MAX;
        break;

    case OVSDB_TYPE_REAL:
        base->u.real.min = -DBL_MAX;
        base->u.real.max = DBL_MAX;
        break;

    case OVSDB_TYPE_BOOLEAN:
        break;

    case OVSDB_TYPE_STRING:
        base->u.string.minLen = 0;
        base->u.string.maxLen = UINT_MAX;
        break;

    case OVSDB_TYPE_UUID:
        base->u.uuid.refTableName = NULL;
        base->u.uuid.refTable = NULL;
        break;

    case OVSDB_N_TYPES:
        OVS_NOT_REACHED();

    default:
        OVS_NOT_REACHED();
    }
}

/* Returns the type of the 'enum_' member for an ovsdb_base_type whose 'type'
 * is 'atomic_type'. */
const struct ovsdb_type *
ovsdb_base_type_get_enum_type(enum ovsdb_atomic_type atomic_type)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static struct ovsdb_type *types[OVSDB_N_TYPES];

    if (ovsthread_once_start(&once)) {
        enum ovsdb_atomic_type i;

        for (i = 0; i < OVSDB_N_TYPES; i++) {
            struct ovsdb_type *type;

            types[i] = type = xmalloc(sizeof *type);
            ovsdb_base_type_init(&type->key, i);
            ovsdb_base_type_init(&type->value, OVSDB_TYPE_VOID);
            type->n_min = 1;
            type->n_max = UINT_MAX;
        }

        ovsthread_once_done(&once);
    }
    return types[atomic_type];
}

void
ovsdb_base_type_clone(struct ovsdb_base_type *dst,
                      const struct ovsdb_base_type *src)
{
    *dst = *src;

    if (src->enum_) {
        dst->enum_ = xmalloc(sizeof *dst->enum_);
        ovsdb_datum_clone(dst->enum_, src->enum_,
                          ovsdb_base_type_get_enum_type(dst->type));
    }

    switch (dst->type) {
    case OVSDB_TYPE_VOID:
    case OVSDB_TYPE_INTEGER:
    case OVSDB_TYPE_REAL:
    case OVSDB_TYPE_BOOLEAN:
        break;

    case OVSDB_TYPE_STRING:
        break;

    case OVSDB_TYPE_UUID:
        if (dst->u.uuid.refTableName) {
            dst->u.uuid.refTableName = xstrdup(dst->u.uuid.refTableName);
        }
        break;

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

void
ovsdb_base_type_destroy(struct ovsdb_base_type *base)
{
    if (base) {
        if (base->enum_) {
            ovsdb_datum_destroy(base->enum_,
                                ovsdb_base_type_get_enum_type(base->type));
            free(base->enum_);
        }

        switch (base->type) {
        case OVSDB_TYPE_VOID:
        case OVSDB_TYPE_INTEGER:
        case OVSDB_TYPE_REAL:
        case OVSDB_TYPE_BOOLEAN:
            break;

        case OVSDB_TYPE_STRING:
            break;

        case OVSDB_TYPE_UUID:
            free(base->u.uuid.refTableName);
            break;

        case OVSDB_N_TYPES:
            OVS_NOT_REACHED();

        default:
            OVS_NOT_REACHED();
        }
    }
}

bool
ovsdb_base_type_is_valid(const struct ovsdb_base_type *base)
{
    switch (base->type) {
    case OVSDB_TYPE_VOID:
        return true;

    case OVSDB_TYPE_INTEGER:
        return base->u.integer.min <= base->u.integer.max;

    case OVSDB_TYPE_REAL:
        return base->u.real.min <= base->u.real.max;

    case OVSDB_TYPE_BOOLEAN:
        return true;

    case OVSDB_TYPE_STRING:
        return base->u.string.minLen <= base->u.string.maxLen;

    case OVSDB_TYPE_UUID:
        return true;

    case OVSDB_N_TYPES:
    default:
        return false;
    }
}

bool
ovsdb_base_type_has_constraints(const struct ovsdb_base_type *base)
{
    if (base->enum_) {
        return true;
    }

    switch (base->type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        return (base->u.integer.min != INT64_MIN
                || base->u.integer.max != INT64_MAX);

    case OVSDB_TYPE_REAL:
        return (base->u.real.min != -DBL_MAX
                || base->u.real.max != DBL_MAX);

    case OVSDB_TYPE_BOOLEAN:
        return false;

    case OVSDB_TYPE_STRING:
        return base->u.string.minLen != 0 || base->u.string.maxLen != UINT_MAX;

    case OVSDB_TYPE_UUID:
        return base->u.uuid.refTableName != NULL;

    case OVSDB_N_TYPES:
        OVS_NOT_REACHED();

    default:
        OVS_NOT_REACHED();
    }
}

void
ovsdb_base_type_clear_constraints(struct ovsdb_base_type *base)
{
    enum ovsdb_atomic_type type = base->type;
    ovsdb_base_type_destroy(base);
    ovsdb_base_type_init(base, type);
}

static struct ovsdb_error *
parse_optional_uint(struct ovsdb_parser *parser, const char *member,
                    unsigned int *uint)
{
    const struct json *json;

    json = ovsdb_parser_member(parser, member, OP_INTEGER | OP_OPTIONAL);
    if (json) {
        if (json->u.integer < 0 || json->u.integer > UINT_MAX) {
            return ovsdb_syntax_error(json, NULL,
                                      "%s out of valid range 0 to %u",
                                      member, UINT_MAX);
        }
        *uint = json->u.integer;
    }
    return NULL;
}

struct ovsdb_error *
ovsdb_base_type_from_json(struct ovsdb_base_type *base,
                          const struct json *json)
{
    struct ovsdb_parser parser;
    struct ovsdb_error *error;
    const struct json *type, *enum_;

    if (json->type == JSON_STRING) {
        error = ovsdb_atomic_type_from_json(&base->type, json);
        if (error) {
            return error;
        }
        ovsdb_base_type_init(base, base->type);
        return NULL;
    }

    ovsdb_parser_init(&parser, json, "ovsdb type");
    type = ovsdb_parser_member(&parser, "type", OP_STRING);
    if (ovsdb_parser_has_error(&parser)) {
        base->type = OVSDB_TYPE_VOID;
        return ovsdb_parser_finish(&parser);
    }

    error = ovsdb_atomic_type_from_json(&base->type, type);
    if (error) {
        return error;
    }

    ovsdb_base_type_init(base, base->type);

    enum_ = ovsdb_parser_member(&parser, "enum", OP_ANY | OP_OPTIONAL);
    if (enum_) {
        base->enum_ = xmalloc(sizeof *base->enum_);
        error = ovsdb_datum_from_json(
            base->enum_, ovsdb_base_type_get_enum_type(base->type),
            enum_, NULL);
        if (error) {
            free(base->enum_);
            base->enum_ = NULL;
        }
    } else if (base->type == OVSDB_TYPE_INTEGER) {
        const struct json *min, *max;

        min = ovsdb_parser_member(&parser, "minInteger",
                                  OP_INTEGER | OP_OPTIONAL);
        max = ovsdb_parser_member(&parser, "maxInteger",
                                  OP_INTEGER | OP_OPTIONAL);
        base->u.integer.min = min ? min->u.integer : INT64_MIN;
        base->u.integer.max = max ? max->u.integer : INT64_MAX;
        if (base->u.integer.min > base->u.integer.max) {
            error = ovsdb_syntax_error(json, NULL,
                                       "minInteger exceeds maxInteger");
        }
    } else if (base->type == OVSDB_TYPE_REAL) {
        const struct json *min, *max;

        min = ovsdb_parser_member(&parser, "minReal", OP_NUMBER | OP_OPTIONAL);
        max = ovsdb_parser_member(&parser, "maxReal", OP_NUMBER | OP_OPTIONAL);
        base->u.real.min = min ? json_real(min) : -DBL_MAX;
        base->u.real.max = max ? json_real(max) : DBL_MAX;
        if (base->u.real.min > base->u.real.max) {
            error = ovsdb_syntax_error(json, NULL, "minReal exceeds maxReal");
        }
    } else if (base->type == OVSDB_TYPE_STRING) {
        if (!error) {
            error = parse_optional_uint(&parser, "minLength",
                                        &base->u.string.minLen);
        }
        if (!error) {
            error = parse_optional_uint(&parser, "maxLength",
                                        &base->u.string.maxLen);
        }
        if (!error && base->u.string.minLen > base->u.string.maxLen) {
            error = ovsdb_syntax_error(json, NULL,
                                       "minLength exceeds maxLength");
        }
    } else if (base->type == OVSDB_TYPE_UUID) {
        const struct json *refTable;

        refTable = ovsdb_parser_member(&parser, "refTable",
                                       OP_ID | OP_OPTIONAL);
        if (refTable) {
            const struct json *refType;

            base->u.uuid.refTableName = xstrdup(refTable->u.string);

            /* We can't set base->u.uuid.refTable here because we don't have
             * enough context (we might not even be running in ovsdb-server).
             * ovsdb_create() will set refTable later. */

            refType = ovsdb_parser_member(&parser, "refType",
                                          OP_ID | OP_OPTIONAL);
            if (refType) {
                const char *refType_s = json_string(refType);
                if (!strcmp(refType_s, "strong")) {
                    base->u.uuid.refType = OVSDB_REF_STRONG;
                } else if (!strcmp(refType_s, "weak")) {
                    base->u.uuid.refType = OVSDB_REF_WEAK;
                } else {
                    error = ovsdb_syntax_error(json, NULL, "refType must be "
                                               "\"strong\" or \"weak\" (not "
                                               "\"%s\")", refType_s);
                }
            } else {
                base->u.uuid.refType = OVSDB_REF_STRONG;
            }
        }
    }

    if (error) {
        ovsdb_error_destroy(ovsdb_parser_finish(&parser));
    } else {
        error = ovsdb_parser_finish(&parser);
    }
    if (error) {
        ovsdb_base_type_destroy(base);
        base->type = OVSDB_TYPE_VOID;
    }
    return error;
}

struct json *
ovsdb_base_type_to_json(const struct ovsdb_base_type *base)
{
    struct json *json;

    if (!ovsdb_base_type_has_constraints(base)) {
        return json_string_create(ovsdb_atomic_type_to_string(base->type));
    }

    json = json_object_create();
    json_object_put_string(json, "type",
                           ovsdb_atomic_type_to_string(base->type));

    if (base->enum_) {
        const struct ovsdb_type *type;

        type = ovsdb_base_type_get_enum_type(base->type);
        json_object_put(json, "enum", ovsdb_datum_to_json(base->enum_, type));
    }

    switch (base->type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        if (base->u.integer.min != INT64_MIN) {
            json_object_put(json, "minInteger",
                            json_integer_create(base->u.integer.min));
        }
        if (base->u.integer.max != INT64_MAX) {
            json_object_put(json, "maxInteger",
                            json_integer_create(base->u.integer.max));
        }
        break;

    case OVSDB_TYPE_REAL:
        if (base->u.real.min != -DBL_MAX) {
            json_object_put(json, "minReal",
                            json_real_create(base->u.real.min));
        }
        if (base->u.real.max != DBL_MAX) {
            json_object_put(json, "maxReal",
                            json_real_create(base->u.real.max));
        }
        break;

    case OVSDB_TYPE_BOOLEAN:
        break;

    case OVSDB_TYPE_STRING:
        if (base->u.string.minLen != 0) {
            json_object_put(json, "minLength",
                            json_integer_create(base->u.string.minLen));
        }
        if (base->u.string.maxLen != UINT_MAX) {
            json_object_put(json, "maxLength",
                            json_integer_create(base->u.string.maxLen));
        }
        break;

    case OVSDB_TYPE_UUID:
        if (base->u.uuid.refTableName) {
            json_object_put_string(json, "refTable",
                                   base->u.uuid.refTableName);
            if (base->u.uuid.refType == OVSDB_REF_WEAK) {
                json_object_put_string(json, "refType", "weak");
            }
        }
        break;

    case OVSDB_N_TYPES:
        OVS_NOT_REACHED();

    default:
        OVS_NOT_REACHED();
    }

    return json;
}

/* ovsdb_type */

void
ovsdb_type_clone(struct ovsdb_type *dst, const struct ovsdb_type *src)
{
    ovsdb_base_type_clone(&dst->key, &src->key);
    ovsdb_base_type_clone(&dst->value, &src->value);
    dst->n_min = src->n_min;
    dst->n_max = src->n_max;
}

void
ovsdb_type_destroy(struct ovsdb_type *type)
{
    ovsdb_base_type_destroy(&type->key);
    ovsdb_base_type_destroy(&type->value);
}

bool
ovsdb_type_is_valid(const struct ovsdb_type *type)
{
    return (type->key.type != OVSDB_TYPE_VOID
            && ovsdb_base_type_is_valid(&type->key)
            && ovsdb_base_type_is_valid(&type->value)
            && type->n_min <= 1
            && type->n_max >= 1);
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
    const char *key = ovsdb_atomic_type_to_string(type->key.type);
    const char *value = ovsdb_atomic_type_to_string(type->value.type);
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
    ovsdb_base_type_init(&type->value, OVSDB_TYPE_VOID);
    type->n_min = 1;
    type->n_max = 1;

    if (json->type == JSON_STRING) {
        return ovsdb_base_type_from_json(&type->key, json);
    } else if (json->type == JSON_OBJECT) {
        const struct json *key, *value, *min, *max;
        struct ovsdb_error *error;
        struct ovsdb_parser parser;

        ovsdb_parser_init(&parser, json, "ovsdb type");
        key = ovsdb_parser_member(&parser, "key", OP_STRING | OP_OBJECT);
        value = ovsdb_parser_member(&parser, "value",
                                    OP_STRING | OP_OBJECT | OP_OPTIONAL);
        min = ovsdb_parser_member(&parser, "min", OP_INTEGER | OP_OPTIONAL);
        max = ovsdb_parser_member(&parser, "max",
                                  OP_INTEGER | OP_STRING | OP_OPTIONAL);
        error = ovsdb_parser_finish(&parser);
        if (error) {
            return error;
        }

        error = ovsdb_base_type_from_json(&type->key, key);
        if (error) {
            return error;
        }

        if (value) {
            error = ovsdb_base_type_from_json(&type->value, value);
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
    if (ovsdb_type_is_scalar(type)
        && !ovsdb_base_type_has_constraints(&type->key)) {
        return ovsdb_base_type_to_json(&type->key);
    } else {
        struct json *json = json_object_create();
        json_object_put(json, "key", ovsdb_base_type_to_json(&type->key));
        if (type->value.type != OVSDB_TYPE_VOID) {
            json_object_put(json, "value",
                            ovsdb_base_type_to_json(&type->value));
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
