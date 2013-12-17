/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#include "ovsdb-data.h"

#include <ctype.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>

#include "dynamic-string.h"
#include "hash.h"
#include "ovs-thread.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "json.h"
#include "shash.h"
#include "smap.h"
#include "sort.h"
#include "unicode.h"

static struct json *
wrap_json(const char *name, struct json *wrapped)
{
    return json_array_create_2(json_string_create(name), wrapped);
}

/* Initializes 'atom' with the default value of the given 'type'.
 *
 * The default value for an atom is as defined in ovsdb/SPECS:
 *
 *      - "integer" or "real": 0
 *
 *      - "boolean": false
 *
 *      - "string": "" (the empty string)
 *
 *      - "uuid": 00000000-0000-0000-0000-000000000000
 *
 * The caller must eventually arrange for 'atom' to be destroyed (with
 * ovsdb_atom_destroy()). */
void
ovsdb_atom_init_default(union ovsdb_atom *atom, enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        atom->integer = 0;
        break;

    case OVSDB_TYPE_REAL:
        atom->real = 0.0;
        break;

    case OVSDB_TYPE_BOOLEAN:
        atom->boolean = false;
        break;

    case OVSDB_TYPE_STRING:
        atom->string = xmemdup("", 1);
        break;

    case OVSDB_TYPE_UUID:
        uuid_zero(&atom->uuid);
        break;

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

/* Returns a read-only atom of the given 'type' that has the default value for
 * 'type'.  The caller must not modify or free the returned atom.
 *
 * See ovsdb_atom_init_default() for an explanation of the default value of an
 * atom. */
const union ovsdb_atom *
ovsdb_atom_default(enum ovsdb_atomic_type type)
{
    static union ovsdb_atom default_atoms[OVSDB_N_TYPES];
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        int i;

        for (i = 0; i < OVSDB_N_TYPES; i++) {
            if (i != OVSDB_TYPE_VOID) {
                ovsdb_atom_init_default(&default_atoms[i], i);
            }
        }
        ovsthread_once_done(&once);
    }

    ovs_assert(ovsdb_atomic_type_is_valid(type));
    return &default_atoms[type];
}

/* Returns true if 'atom', which must have the given 'type', has the default
 * value for that type.
 *
 * See ovsdb_atom_init_default() for an explanation of the default value of an
 * atom. */
bool
ovsdb_atom_is_default(const union ovsdb_atom *atom,
                      enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        return atom->integer == 0;

    case OVSDB_TYPE_REAL:
        return atom->real == 0.0;

    case OVSDB_TYPE_BOOLEAN:
        return atom->boolean == false;

    case OVSDB_TYPE_STRING:
        return atom->string[0] == '\0';

    case OVSDB_TYPE_UUID:
        return uuid_is_zero(&atom->uuid);

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

/* Initializes 'new' as a copy of 'old', with the given 'type'.
 *
 * The caller must eventually arrange for 'new' to be destroyed (with
 * ovsdb_atom_destroy()). */
void
ovsdb_atom_clone(union ovsdb_atom *new, const union ovsdb_atom *old,
                 enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        new->integer = old->integer;
        break;

    case OVSDB_TYPE_REAL:
        new->real = old->real;
        break;

    case OVSDB_TYPE_BOOLEAN:
        new->boolean = old->boolean;
        break;

    case OVSDB_TYPE_STRING:
        new->string = xstrdup(old->string);
        break;

    case OVSDB_TYPE_UUID:
        new->uuid = old->uuid;
        break;

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

/* Swaps the contents of 'a' and 'b', which need not have the same type. */
void
ovsdb_atom_swap(union ovsdb_atom *a, union ovsdb_atom *b)
{
    union ovsdb_atom tmp = *a;
    *a = *b;
    *b = tmp;
}

/* Returns a hash value for 'atom', which has the specified 'type', folding
 * 'basis' into the calculation. */
uint32_t
ovsdb_atom_hash(const union ovsdb_atom *atom, enum ovsdb_atomic_type type,
                uint32_t basis)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        return hash_int(atom->integer, basis);

    case OVSDB_TYPE_REAL:
        return hash_double(atom->real, basis);

    case OVSDB_TYPE_BOOLEAN:
        return hash_boolean(atom->boolean, basis);

    case OVSDB_TYPE_STRING:
        return hash_string(atom->string, basis);

    case OVSDB_TYPE_UUID:
        return hash_int(uuid_hash(&atom->uuid), basis);

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

/* Compares 'a' and 'b', which both have type 'type', and returns a
 * strcmp()-like result. */
int
ovsdb_atom_compare_3way(const union ovsdb_atom *a,
                        const union ovsdb_atom *b,
                        enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        return a->integer < b->integer ? -1 : a->integer > b->integer;

    case OVSDB_TYPE_REAL:
        return a->real < b->real ? -1 : a->real > b->real;

    case OVSDB_TYPE_BOOLEAN:
        return a->boolean - b->boolean;

    case OVSDB_TYPE_STRING:
        return strcmp(a->string, b->string);

    case OVSDB_TYPE_UUID:
        return uuid_compare_3way(&a->uuid, &b->uuid);

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

static struct ovsdb_error *
unwrap_json(const struct json *json, const char *name,
            enum json_type value_type, const struct json **value)
{
    if (json->type != JSON_ARRAY
        || json->u.array.n != 2
        || json->u.array.elems[0]->type != JSON_STRING
        || (name && strcmp(json->u.array.elems[0]->u.string, name))
        || json->u.array.elems[1]->type != value_type)
    {
        *value = NULL;
        return ovsdb_syntax_error(json, NULL, "expected [\"%s\", <%s>]", name,
                                  json_type_to_string(value_type));
    }
    *value = json->u.array.elems[1];
    return NULL;
}

static struct ovsdb_error *
parse_json_pair(const struct json *json,
                const struct json **elem0, const struct json **elem1)
{
    if (json->type != JSON_ARRAY || json->u.array.n != 2) {
        return ovsdb_syntax_error(json, NULL, "expected 2-element array");
    }
    *elem0 = json->u.array.elems[0];
    *elem1 = json->u.array.elems[1];
    return NULL;
}

static void
ovsdb_symbol_referenced(struct ovsdb_symbol *symbol,
                        const struct ovsdb_base_type *base)
{
    ovs_assert(base->type == OVSDB_TYPE_UUID);

    if (base->u.uuid.refTableName) {
        switch (base->u.uuid.refType) {
        case OVSDB_REF_STRONG:
            symbol->strong_ref = true;
            break;
        case OVSDB_REF_WEAK:
            symbol->weak_ref = true;
            break;
        }
    }
}

static struct ovsdb_error * WARN_UNUSED_RESULT
ovsdb_atom_parse_uuid(struct uuid *uuid, const struct json *json,
                      struct ovsdb_symbol_table *symtab,
                      const struct ovsdb_base_type *base)
{
    struct ovsdb_error *error0;
    const struct json *value;

    error0 = unwrap_json(json, "uuid", JSON_STRING, &value);
    if (!error0) {
        const char *uuid_string = json_string(value);
        if (!uuid_from_string(uuid, uuid_string)) {
            return ovsdb_syntax_error(json, NULL, "\"%s\" is not a valid UUID",
                                      uuid_string);
        }
    } else if (symtab) {
        struct ovsdb_error *error1;

        error1 = unwrap_json(json, "named-uuid", JSON_STRING, &value);
        if (!error1) {
            struct ovsdb_symbol *symbol;

            ovsdb_error_destroy(error0);
            if (!ovsdb_parser_is_id(json_string(value))) {
                return ovsdb_syntax_error(json, NULL, "named-uuid string is "
                                          "not a valid <id>");
            }

            symbol = ovsdb_symbol_table_insert(symtab, json_string(value));
            *uuid = symbol->uuid;
            ovsdb_symbol_referenced(symbol, base);
            return NULL;
        }
        ovsdb_error_destroy(error1);
    }

    return error0;
}

static struct ovsdb_error * WARN_UNUSED_RESULT
ovsdb_atom_from_json__(union ovsdb_atom *atom,
                       const struct ovsdb_base_type *base,
                       const struct json *json,
                       struct ovsdb_symbol_table *symtab)
{
    enum ovsdb_atomic_type type = base->type;

    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        if (json->type == JSON_INTEGER) {
            atom->integer = json->u.integer;
            return NULL;
        }
        break;

    case OVSDB_TYPE_REAL:
        if (json->type == JSON_INTEGER) {
            atom->real = json->u.integer;
            return NULL;
        } else if (json->type == JSON_REAL) {
            atom->real = json->u.real;
            return NULL;
        }
        break;

    case OVSDB_TYPE_BOOLEAN:
        if (json->type == JSON_TRUE) {
            atom->boolean = true;
            return NULL;
        } else if (json->type == JSON_FALSE) {
            atom->boolean = false;
            return NULL;
        }
        break;

    case OVSDB_TYPE_STRING:
        if (json->type == JSON_STRING) {
            atom->string = xstrdup(json->u.string);
            return NULL;
        }
        break;

    case OVSDB_TYPE_UUID:
        return ovsdb_atom_parse_uuid(&atom->uuid, json, symtab, base);

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }

    return ovsdb_syntax_error(json, NULL, "expected %s",
                              ovsdb_atomic_type_to_string(type));
}

/* Parses 'json' as an atom of the type described by 'base'.  If successful,
 * returns NULL and initializes 'atom' with the parsed atom.  On failure,
 * returns an error and the contents of 'atom' are indeterminate.  The caller
 * is responsible for freeing the error or the atom that is returned.
 *
 * Violations of constraints expressed by 'base' are treated as errors.
 *
 * If 'symtab' is nonnull, then named UUIDs in 'symtab' are accepted.  Refer to
 * ovsdb/SPECS for information about this, and for the syntax that this
 * function accepts.  If 'base' is a reference and a symbol is parsed, then the
 * symbol's 'strong_ref' or 'weak_ref' member is set to true, as
 * appropriate. */
struct ovsdb_error *
ovsdb_atom_from_json(union ovsdb_atom *atom,
                     const struct ovsdb_base_type *base,
                     const struct json *json,
                     struct ovsdb_symbol_table *symtab)
{
    struct ovsdb_error *error;

    error = ovsdb_atom_from_json__(atom, base, json, symtab);
    if (error) {
        return error;
    }

    error = ovsdb_atom_check_constraints(atom, base);
    if (error) {
        ovsdb_atom_destroy(atom, base->type);
    }
    return error;
}

/* Converts 'atom', of the specified 'type', to JSON format, and returns the
 * JSON.  The caller is responsible for freeing the returned JSON.
 *
 * Refer to ovsdb/SPECS for the format of the JSON that this function
 * produces. */
struct json *
ovsdb_atom_to_json(const union ovsdb_atom *atom, enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        return json_integer_create(atom->integer);

    case OVSDB_TYPE_REAL:
        return json_real_create(atom->real);

    case OVSDB_TYPE_BOOLEAN:
        return json_boolean_create(atom->boolean);

    case OVSDB_TYPE_STRING:
        return json_string_create(atom->string);

    case OVSDB_TYPE_UUID:
        return wrap_json("uuid", json_string_create_nocopy(
                             xasprintf(UUID_FMT, UUID_ARGS(&atom->uuid))));

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

/* Returns strlen(json_to_string(ovsdb_atom_to_json(atom, type), 0)). */
size_t
ovsdb_atom_json_length(const union ovsdb_atom *atom,
                       enum ovsdb_atomic_type type)
{
    struct json json;

    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        json.type = JSON_INTEGER;
        json.u.integer = atom->integer;
        break;

    case OVSDB_TYPE_REAL:
        json.type = JSON_REAL;
        json.u.real = atom->real;
        break;

    case OVSDB_TYPE_BOOLEAN:
        json.type = atom->boolean ? JSON_TRUE : JSON_FALSE;
        break;

    case OVSDB_TYPE_STRING:
        json.type = JSON_STRING;
        json.u.string = atom->string;
        break;

    case OVSDB_TYPE_UUID:
        return strlen("[\"uuid\",\"00000000-0000-0000-0000-000000000000\"]");

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }

    return json_serialized_length(&json);
}

static char *
ovsdb_atom_from_string__(union ovsdb_atom *atom,
                         const struct ovsdb_base_type *base, const char *s,
                         struct ovsdb_symbol_table *symtab)
{
    enum ovsdb_atomic_type type = base->type;

    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER: {
        long long int integer;
        if (!str_to_llong(s, 10, &integer)) {
            return xasprintf("\"%s\" is not a valid integer", s);
        }
        atom->integer = integer;
    }
        break;

    case OVSDB_TYPE_REAL:
        if (!str_to_double(s, &atom->real)) {
            return xasprintf("\"%s\" is not a valid real number", s);
        }
        /* Our JSON input routines map negative zero to zero, so do that here
         * too for consistency. */
        if (atom->real == 0.0) {
            atom->real = 0.0;
        }
        break;

    case OVSDB_TYPE_BOOLEAN:
        if (!strcmp(s, "true") || !strcmp(s, "yes") || !strcmp(s, "on")
            || !strcmp(s, "1")) {
            atom->boolean = true;
        } else if (!strcmp(s, "false") || !strcmp(s, "no") || !strcmp(s, "off")
                   || !strcmp(s, "0")) {
            atom->boolean = false;
        } else {
            return xasprintf("\"%s\" is not a valid boolean "
                             "(use \"true\" or \"false\")", s);
        }
        break;

    case OVSDB_TYPE_STRING:
        if (*s == '\0') {
            return xstrdup("An empty string is not valid as input; "
                           "use \"\" to represent the empty string");
        } else if (*s == '"') {
            size_t s_len = strlen(s);

            if (s_len < 2 || s[s_len - 1] != '"') {
                return xasprintf("%s: missing quote at end of "
                                 "quoted string", s);
            } else if (!json_string_unescape(s + 1, s_len - 2,
                                             &atom->string)) {
                char *error = xasprintf("%s: %s", s, atom->string);
                free(atom->string);
                return error;
            }
        } else {
            atom->string = xstrdup(s);
        }
        break;

    case OVSDB_TYPE_UUID:
        if (*s == '@') {
            struct ovsdb_symbol *symbol = ovsdb_symbol_table_insert(symtab, s);
            atom->uuid = symbol->uuid;
            ovsdb_symbol_referenced(symbol, base);
        } else if (!uuid_from_string(&atom->uuid, s)) {
            return xasprintf("\"%s\" is not a valid UUID", s);
        }
        break;

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }

    return NULL;
}

/* Initializes 'atom' to a value of type 'base' parsed from 's', which takes
 * one of the following forms:
 *
 *      - OVSDB_TYPE_INTEGER: A decimal integer optionally preceded by a sign.
 *
 *      - OVSDB_TYPE_REAL: A floating-point number in the format accepted by
 *        strtod().
 *
 *      - OVSDB_TYPE_BOOLEAN: "true", "yes", "on", "1" for true, or "false",
 *        "no", "off", or "0" for false.
 *
 *      - OVSDB_TYPE_STRING: A JSON string if it begins with a quote, otherwise
 *        an arbitrary string.
 *
 *      - OVSDB_TYPE_UUID: A UUID in RFC 4122 format.  If 'symtab' is nonnull,
 *        then an identifier beginning with '@' is also acceptable.  If the
 *        named identifier is already in 'symtab', then the associated UUID is
 *        used; otherwise, a new, random UUID is used and added to the symbol
 *        table.  If 'base' is a reference and a symbol is parsed, then the
 *        symbol's 'strong_ref' or 'weak_ref' member is set to true, as
 *        appropriate.
 *
 * Returns a null pointer if successful, otherwise an error message describing
 * the problem.  On failure, the contents of 'atom' are indeterminate.  The
 * caller is responsible for freeing the atom or the error.
 */
char *
ovsdb_atom_from_string(union ovsdb_atom *atom,
                       const struct ovsdb_base_type *base, const char *s,
                       struct ovsdb_symbol_table *symtab)
{
    struct ovsdb_error *error;
    char *msg;

    msg = ovsdb_atom_from_string__(atom, base, s, symtab);
    if (msg) {
        return msg;
    }

    error = ovsdb_atom_check_constraints(atom, base);
    if (error) {
        ovsdb_atom_destroy(atom, base->type);
        msg = ovsdb_error_to_string(error);
        ovsdb_error_destroy(error);
    }
    return msg;
}

static bool
string_needs_quotes(const char *s)
{
    const char *p = s;
    unsigned char c;

    c = *p++;
    if (!isalpha(c) && c != '_') {
        return true;
    }

    while ((c = *p++) != '\0') {
        if (!isalpha(c) && c != '_' && c != '-' && c != '.') {
            return true;
        }
    }

    if (!strcmp(s, "true") || !strcmp(s, "false")) {
        return true;
    }

    return false;
}

/* Appends 'atom' (which has the given 'type') to 'out', in a format acceptable
 * to ovsdb_atom_from_string().  */
void
ovsdb_atom_to_string(const union ovsdb_atom *atom, enum ovsdb_atomic_type type,
                     struct ds *out)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        ds_put_format(out, "%"PRId64, atom->integer);
        break;

    case OVSDB_TYPE_REAL:
        ds_put_format(out, "%.*g", DBL_DIG, atom->real);
        break;

    case OVSDB_TYPE_BOOLEAN:
        ds_put_cstr(out, atom->boolean ? "true" : "false");
        break;

    case OVSDB_TYPE_STRING:
        if (string_needs_quotes(atom->string)) {
            struct json json;

            json.type = JSON_STRING;
            json.u.string = atom->string;
            json_to_ds(&json, 0, out);
        } else {
            ds_put_cstr(out, atom->string);
        }
        break;

    case OVSDB_TYPE_UUID:
        ds_put_format(out, UUID_FMT, UUID_ARGS(&atom->uuid));
        break;

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

/* Appends 'atom' (which has the given 'type') to 'out', in a bare string
 * format that cannot be parsed uniformly back into a datum but is easier for
 * shell scripts, etc., to deal with. */
void
ovsdb_atom_to_bare(const union ovsdb_atom *atom, enum ovsdb_atomic_type type,
                   struct ds *out)
{
    if (type == OVSDB_TYPE_STRING) {
        ds_put_cstr(out, atom->string);
    } else {
        ovsdb_atom_to_string(atom, type, out);
    }
}

static struct ovsdb_error *
check_string_constraints(const char *s,
                         const struct ovsdb_string_constraints *c)
{
    size_t n_chars;
    char *msg;

    msg = utf8_validate(s, &n_chars);
    if (msg) {
        struct ovsdb_error *error;

        error = ovsdb_error("constraint violation",
                            "not a valid UTF-8 string: %s", msg);
        free(msg);
        return error;
    }

    if (n_chars < c->minLen) {
        return ovsdb_error(
            "constraint violation",
            "\"%s\" length %"PRIuSIZE" is less than minimum allowed "
            "length %u", s, n_chars, c->minLen);
    } else if (n_chars > c->maxLen) {
        return ovsdb_error(
            "constraint violation",
            "\"%s\" length %"PRIuSIZE" is greater than maximum allowed "
            "length %u", s, n_chars, c->maxLen);
    }

    return NULL;
}

/* Checks whether 'atom' meets the constraints (if any) defined in 'base'.
 * (base->type must specify 'atom''s type.)  Returns a null pointer if the
 * constraints are met, otherwise an error that explains the violation.
 *
 * Checking UUID constraints is deferred to transaction commit time, so this
 * function does nothing for UUID constraints. */
struct ovsdb_error *
ovsdb_atom_check_constraints(const union ovsdb_atom *atom,
                             const struct ovsdb_base_type *base)
{
    if (base->enum_
        && ovsdb_datum_find_key(base->enum_, atom, base->type) == UINT_MAX) {
        struct ovsdb_error *error;
        struct ds actual = DS_EMPTY_INITIALIZER;
        struct ds valid = DS_EMPTY_INITIALIZER;

        ovsdb_atom_to_string(atom, base->type, &actual);
        ovsdb_datum_to_string(base->enum_,
                              ovsdb_base_type_get_enum_type(base->type),
                              &valid);
        error = ovsdb_error("constraint violation",
                            "%s is not one of the allowed values (%s)",
                            ds_cstr(&actual), ds_cstr(&valid));
        ds_destroy(&actual);
        ds_destroy(&valid);

        return error;
    }

    switch (base->type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER:
        if (atom->integer >= base->u.integer.min
            && atom->integer <= base->u.integer.max) {
            return NULL;
        } else if (base->u.integer.min != INT64_MIN) {
            if (base->u.integer.max != INT64_MAX) {
                return ovsdb_error("constraint violation",
                                   "%"PRId64" is not in the valid range "
                                   "%"PRId64" to %"PRId64" (inclusive)",
                                   atom->integer,
                                   base->u.integer.min, base->u.integer.max);
            } else {
                return ovsdb_error("constraint violation",
                                   "%"PRId64" is less than minimum allowed "
                                   "value %"PRId64,
                                   atom->integer, base->u.integer.min);
            }
        } else {
            return ovsdb_error("constraint violation",
                               "%"PRId64" is greater than maximum allowed "
                               "value %"PRId64,
                               atom->integer, base->u.integer.max);
        }
        OVS_NOT_REACHED();

    case OVSDB_TYPE_REAL:
        if (atom->real >= base->u.real.min && atom->real <= base->u.real.max) {
            return NULL;
        } else if (base->u.real.min != -DBL_MAX) {
            if (base->u.real.max != DBL_MAX) {
                return ovsdb_error("constraint violation",
                                   "%.*g is not in the valid range "
                                   "%.*g to %.*g (inclusive)",
                                   DBL_DIG, atom->real,
                                   DBL_DIG, base->u.real.min,
                                   DBL_DIG, base->u.real.max);
            } else {
                return ovsdb_error("constraint violation",
                                   "%.*g is less than minimum allowed "
                                   "value %.*g",
                                   DBL_DIG, atom->real,
                                   DBL_DIG, base->u.real.min);
            }
        } else {
            return ovsdb_error("constraint violation",
                               "%.*g is greater than maximum allowed "
                               "value %.*g",
                               DBL_DIG, atom->real,
                               DBL_DIG, base->u.real.max);
        }
        OVS_NOT_REACHED();

    case OVSDB_TYPE_BOOLEAN:
        return NULL;

    case OVSDB_TYPE_STRING:
        return check_string_constraints(atom->string, &base->u.string);

    case OVSDB_TYPE_UUID:
        return NULL;

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

static union ovsdb_atom *
alloc_default_atoms(enum ovsdb_atomic_type type, size_t n)
{
    if (type != OVSDB_TYPE_VOID && n) {
        union ovsdb_atom *atoms;
        unsigned int i;

        atoms = xmalloc(n * sizeof *atoms);
        for (i = 0; i < n; i++) {
            ovsdb_atom_init_default(&atoms[i], type);
        }
        return atoms;
    } else {
        /* Avoid wasting memory in the n == 0 case, because xmalloc(0) is
         * treated as xmalloc(1). */
        return NULL;
    }
}

/* Initializes 'datum' as an empty datum.  (An empty datum can be treated as
 * any type.) */
void
ovsdb_datum_init_empty(struct ovsdb_datum *datum)
{
    datum->n = 0;
    datum->keys = NULL;
    datum->values = NULL;
}

/* Initializes 'datum' as a datum that has the default value for 'type'.
 *
 * The default value for a particular type is as defined in ovsdb/SPECS:
 *
 *    - If n_min is 0, then the default value is the empty set (or map).
 *
 *    - If n_min is 1, the default value is a single value or a single
 *      key-value pair, whose key and value are the defaults for their
 *      atomic types.  (See ovsdb_atom_init_default() for details.)
 *
 *    - n_min > 1 is invalid.  See ovsdb_type_is_valid().
 */
void
ovsdb_datum_init_default(struct ovsdb_datum *datum,
                         const struct ovsdb_type *type)
{
    datum->n = type->n_min;
    datum->keys = alloc_default_atoms(type->key.type, datum->n);
    datum->values = alloc_default_atoms(type->value.type, datum->n);
}

/* Returns a read-only datum of the given 'type' that has the default value for
 * 'type'.  The caller must not modify or free the returned datum.
 *
 * See ovsdb_datum_init_default() for an explanation of the default value of a
 * datum. */
const struct ovsdb_datum *
ovsdb_datum_default(const struct ovsdb_type *type)
{
    if (type->n_min == 0) {
        static const struct ovsdb_datum empty;
        return &empty;
    } else if (type->n_min == 1) {
        static struct ovsdb_datum default_data[OVSDB_N_TYPES][OVSDB_N_TYPES];
        struct ovsdb_datum *d;
        int kt = type->key.type;
        int vt = type->value.type;

        ovs_assert(ovsdb_type_is_valid(type));

        d = &default_data[kt][vt];
        if (!d->n) {
            d->n = 1;
            d->keys = CONST_CAST(union ovsdb_atom *, ovsdb_atom_default(kt));
            if (vt != OVSDB_TYPE_VOID) {
                d->values = CONST_CAST(union ovsdb_atom *,
                                       ovsdb_atom_default(vt));
            }
        }
        return d;
    } else {
        OVS_NOT_REACHED();
    }
}

/* Returns true if 'datum', which must have the given 'type', has the default
 * value for that type.
 *
 * See ovsdb_datum_init_default() for an explanation of the default value of a
 * datum. */
bool
ovsdb_datum_is_default(const struct ovsdb_datum *datum,
                       const struct ovsdb_type *type)
{
    size_t i;

    if (datum->n != type->n_min) {
        return false;
    }
    for (i = 0; i < datum->n; i++) {
        if (!ovsdb_atom_is_default(&datum->keys[i], type->key.type)) {
            return false;
        }
        if (type->value.type != OVSDB_TYPE_VOID
            && !ovsdb_atom_is_default(&datum->values[i], type->value.type)) {
            return false;
        }
    }

    return true;
}

static union ovsdb_atom *
clone_atoms(const union ovsdb_atom *old, enum ovsdb_atomic_type type, size_t n)
{
    if (type != OVSDB_TYPE_VOID && n) {
        union ovsdb_atom *new;
        unsigned int i;

        new = xmalloc(n * sizeof *new);
        for (i = 0; i < n; i++) {
            ovsdb_atom_clone(&new[i], &old[i], type);
        }
        return new;
    } else {
        /* Avoid wasting memory in the n == 0 case, because xmalloc(0) is
         * treated as xmalloc(1). */
        return NULL;
    }
}

/* Initializes 'new' as a copy of 'old', with the given 'type'.
 *
 * The caller must eventually arrange for 'new' to be destroyed (with
 * ovsdb_datum_destroy()). */
void
ovsdb_datum_clone(struct ovsdb_datum *new, const struct ovsdb_datum *old,
                  const struct ovsdb_type *type)
{
    unsigned int n = old->n;
    new->n = n;
    new->keys = clone_atoms(old->keys, type->key.type, n);
    new->values = clone_atoms(old->values, type->value.type, n);
}

static void
free_data(enum ovsdb_atomic_type type,
          union ovsdb_atom *atoms, size_t n_atoms)
{
    if (ovsdb_atom_needs_destruction(type)) {
        unsigned int i;
        for (i = 0; i < n_atoms; i++) {
            ovsdb_atom_destroy(&atoms[i], type);
        }
    }
    free(atoms);
}

/* Frees the data owned by 'datum', which must have the given 'type'.
 *
 * This does not actually call free(datum).  If necessary, the caller must be
 * responsible for that. */
void
ovsdb_datum_destroy(struct ovsdb_datum *datum, const struct ovsdb_type *type)
{
    free_data(type->key.type, datum->keys, datum->n);
    free_data(type->value.type, datum->values, datum->n);
}

/* Swaps the contents of 'a' and 'b', which need not have the same type. */
void
ovsdb_datum_swap(struct ovsdb_datum *a, struct ovsdb_datum *b)
{
    struct ovsdb_datum tmp = *a;
    *a = *b;
    *b = tmp;
}

struct ovsdb_datum_sort_cbdata {
    enum ovsdb_atomic_type key_type;
    enum ovsdb_atomic_type value_type;
    struct ovsdb_datum *datum;
};

static int
ovsdb_datum_sort_compare_cb(size_t a, size_t b, void *cbdata_)
{
    struct ovsdb_datum_sort_cbdata *cbdata = cbdata_;
    int retval;

    retval = ovsdb_atom_compare_3way(&cbdata->datum->keys[a],
                                     &cbdata->datum->keys[b],
                                     cbdata->key_type);
    if (retval || cbdata->value_type == OVSDB_TYPE_VOID) {
        return retval;
    }

    return ovsdb_atom_compare_3way(&cbdata->datum->values[a],
                                   &cbdata->datum->values[b],
                                   cbdata->value_type);
}

static void
ovsdb_datum_sort_swap_cb(size_t a, size_t b, void *cbdata_)
{
    struct ovsdb_datum_sort_cbdata *cbdata = cbdata_;

    ovsdb_atom_swap(&cbdata->datum->keys[a], &cbdata->datum->keys[b]);
    if (cbdata->datum->values) {
        ovsdb_atom_swap(&cbdata->datum->values[a], &cbdata->datum->values[b]);
    }
}

static void
ovsdb_datum_sort__(struct ovsdb_datum *datum, enum ovsdb_atomic_type key_type,
                   enum ovsdb_atomic_type value_type)
{
    struct ovsdb_datum_sort_cbdata cbdata;

    cbdata.key_type = key_type;
    cbdata.value_type = value_type;
    cbdata.datum = datum;
    sort(datum->n, ovsdb_datum_sort_compare_cb, ovsdb_datum_sort_swap_cb,
         &cbdata);
}

/* The keys in an ovsdb_datum must be unique and in sorted order.  Most
 * functions that modify an ovsdb_datum maintain these invariants.  For those
 * that don't, this function checks and restores these invariants for 'datum',
 * whose keys are of type 'key_type'.
 *
 * This function returns NULL if successful, otherwise an error message.  The
 * caller must free the returned error when it is no longer needed.  On error,
 * 'datum' is sorted but not unique. */
struct ovsdb_error *
ovsdb_datum_sort(struct ovsdb_datum *datum, enum ovsdb_atomic_type key_type)
{
    size_t i;

    if (datum->n < 2) {
        return NULL;
    }

    ovsdb_datum_sort__(datum, key_type, OVSDB_TYPE_VOID);

    for (i = 0; i < datum->n - 1; i++) {
        if (ovsdb_atom_equals(&datum->keys[i], &datum->keys[i + 1],
                              key_type)) {
            if (datum->values) {
                return ovsdb_error(NULL, "map contains duplicate key");
            } else {
                return ovsdb_error(NULL, "set contains duplicate");
            }
        }
    }
    return NULL;
}

/* This function is the same as ovsdb_datum_sort(), except that the caller
 * knows that 'datum' is unique.  The operation therefore "cannot fail", so
 * this function assert-fails if it actually does. */
void
ovsdb_datum_sort_assert(struct ovsdb_datum *datum,
                        enum ovsdb_atomic_type key_type)
{
    struct ovsdb_error *error = ovsdb_datum_sort(datum, key_type);
    if (error) {
        OVS_NOT_REACHED();
    }
}

/* This is similar to ovsdb_datum_sort(), except that it drops duplicate keys
 * instead of reporting an error.  In a map type, the smallest value among a
 * group of duplicate pairs is retained and the others are dropped.
 *
 * Returns the number of keys (or pairs) that were dropped. */
size_t
ovsdb_datum_sort_unique(struct ovsdb_datum *datum,
                        enum ovsdb_atomic_type key_type,
                        enum ovsdb_atomic_type value_type)
{
    size_t src, dst;

    if (datum->n < 2) {
        return 0;
    }

    ovsdb_datum_sort__(datum, key_type, value_type);

    dst = 1;
    for (src = 1; src < datum->n; src++) {
        if (ovsdb_atom_equals(&datum->keys[src], &datum->keys[dst - 1],
                              key_type)) {
            ovsdb_atom_destroy(&datum->keys[src], key_type);
            if (value_type != OVSDB_TYPE_VOID) {
                ovsdb_atom_destroy(&datum->values[src], value_type);
            }
        } else {
            if (src != dst) {
                datum->keys[dst] = datum->keys[src];
                if (value_type != OVSDB_TYPE_VOID) {
                    datum->values[dst] = datum->values[src];
                }
            }
            dst++;
        }
    }
    datum->n = dst;
    return datum->n - src;
}

/* Checks that each of the atoms in 'datum' conforms to the constraints
 * specified by its 'type'.  Returns an error if a constraint is violated,
 * otherwise a null pointer.
 *
 * This function is not commonly useful because the most ordinary way to obtain
 * a datum is ultimately via ovsdb_atom_from_string() or
 * ovsdb_atom_from_json(), which check constraints themselves. */
struct ovsdb_error *
ovsdb_datum_check_constraints(const struct ovsdb_datum *datum,
                              const struct ovsdb_type *type)
{
    struct ovsdb_error *error;
    unsigned int i;

    for (i = 0; i < datum->n; i++) {
        error = ovsdb_atom_check_constraints(&datum->keys[i], &type->key);
        if (error) {
            return error;
        }
    }

    if (type->value.type != OVSDB_TYPE_VOID) {
        for (i = 0; i < datum->n; i++) {
            error = ovsdb_atom_check_constraints(&datum->values[i],
                                                 &type->value);
            if (error) {
                return error;
            }
        }
    }

    return NULL;
}

static struct ovsdb_error *
ovsdb_datum_from_json__(struct ovsdb_datum *datum,
                        const struct ovsdb_type *type,
                        const struct json *json,
                        struct ovsdb_symbol_table *symtab)
{
    struct ovsdb_error *error;

    if (ovsdb_type_is_map(type)
        || (json->type == JSON_ARRAY
            && json->u.array.n > 0
            && json->u.array.elems[0]->type == JSON_STRING
            && !strcmp(json->u.array.elems[0]->u.string, "set"))) {
        bool is_map = ovsdb_type_is_map(type);
        const char *class = is_map ? "map" : "set";
        const struct json *inner;
        unsigned int i;
        size_t n;

        error = unwrap_json(json, class, JSON_ARRAY, &inner);
        if (error) {
            return error;
        }

        n = inner->u.array.n;
        if (n < type->n_min || n > type->n_max) {
            return ovsdb_syntax_error(json, NULL, "%s must have %u to "
                                      "%u members but %"PRIuSIZE" are present",
                                      class, type->n_min, type->n_max, n);
        }

        datum->n = 0;
        datum->keys = xmalloc(n * sizeof *datum->keys);
        datum->values = is_map ? xmalloc(n * sizeof *datum->values) : NULL;
        for (i = 0; i < n; i++) {
            const struct json *element = inner->u.array.elems[i];
            const struct json *key = NULL;
            const struct json *value = NULL;

            if (!is_map) {
                key = element;
            } else {
                error = parse_json_pair(element, &key, &value);
                if (error) {
                    goto error;
                }
            }

            error = ovsdb_atom_from_json(&datum->keys[i], &type->key,
                                         key, symtab);
            if (error) {
                goto error;
            }

            if (is_map) {
                error = ovsdb_atom_from_json(&datum->values[i],
                                             &type->value, value, symtab);
                if (error) {
                    ovsdb_atom_destroy(&datum->keys[i], type->key.type);
                    goto error;
                }
            }

            datum->n++;
        }
        return NULL;

    error:
        ovsdb_datum_destroy(datum, type);
        return error;
    } else {
        datum->n = 1;
        datum->keys = xmalloc(sizeof *datum->keys);
        datum->values = NULL;

        error = ovsdb_atom_from_json(&datum->keys[0], &type->key,
                                     json, symtab);
        if (error) {
            free(datum->keys);
        }
        return error;
    }
}

/* Parses 'json' as a datum of the type described by 'type'.  If successful,
 * returns NULL and initializes 'datum' with the parsed datum.  On failure,
 * returns an error and the contents of 'datum' are indeterminate.  The caller
 * is responsible for freeing the error or the datum that is returned.
 *
 * Violations of constraints expressed by 'type' are treated as errors.
 *
 * If 'symtab' is nonnull, then named UUIDs in 'symtab' are accepted.  Refer to
 * ovsdb/SPECS for information about this, and for the syntax that this
 * function accepts. */
struct ovsdb_error *
ovsdb_datum_from_json(struct ovsdb_datum *datum,
                      const struct ovsdb_type *type,
                      const struct json *json,
                      struct ovsdb_symbol_table *symtab)
{
    struct ovsdb_error *error;

    error = ovsdb_datum_from_json__(datum, type, json, symtab);
    if (error) {
        return error;
    }

    error = ovsdb_datum_sort(datum, type->key.type);
    if (error) {
        ovsdb_datum_destroy(datum, type);
    }
    return error;
}

/* Converts 'datum', of the specified 'type', to JSON format, and returns the
 * JSON.  The caller is responsible for freeing the returned JSON.
 *
 * 'type' constraints on datum->n are ignored.
 *
 * Refer to ovsdb/SPECS for the format of the JSON that this function
 * produces. */
struct json *
ovsdb_datum_to_json(const struct ovsdb_datum *datum,
                    const struct ovsdb_type *type)
{
    if (ovsdb_type_is_map(type)) {
        struct json **elems;
        size_t i;

        elems = xmalloc(datum->n * sizeof *elems);
        for (i = 0; i < datum->n; i++) {
            elems[i] = json_array_create_2(
                ovsdb_atom_to_json(&datum->keys[i], type->key.type),
                ovsdb_atom_to_json(&datum->values[i], type->value.type));
        }

        return wrap_json("map", json_array_create(elems, datum->n));
    } else if (datum->n == 1) {
        return ovsdb_atom_to_json(&datum->keys[0], type->key.type);
    } else {
        struct json **elems;
        size_t i;

        elems = xmalloc(datum->n * sizeof *elems);
        for (i = 0; i < datum->n; i++) {
            elems[i] = ovsdb_atom_to_json(&datum->keys[i], type->key.type);
        }

        return wrap_json("set", json_array_create(elems, datum->n));
    }
}

/* Returns strlen(json_to_string(ovsdb_datum_to_json(datum, type), 0)). */
size_t
ovsdb_datum_json_length(const struct ovsdb_datum *datum,
                        const struct ovsdb_type *type)
{
    if (ovsdb_type_is_map(type)) {
        size_t length;

        /* ["map",[...]]. */
        length = 10;
        if (datum->n > 0) {
            size_t i;

            /* Commas between pairs in the inner [...] */
            length += datum->n - 1;

            /* [,] in each pair. */
            length += datum->n * 3;

            /* Data. */
            for (i = 0; i < datum->n; i++) {
                length += ovsdb_atom_json_length(&datum->keys[i],
                                                 type->key.type);
                length += ovsdb_atom_json_length(&datum->values[i],
                                                 type->value.type);
            }
        }
        return length;
    } else if (datum->n == 1) {
        return ovsdb_atom_json_length(&datum->keys[0], type->key.type);
    } else {
        size_t length;
        size_t i;

        /* ["set",[...]]. */
        length = 10;
        if (datum->n > 0) {
            /* Commas between elements in the inner [...]. */
            length += datum->n - 1;

            /* Data. */
            for (i = 0; i < datum->n; i++) {
                length += ovsdb_atom_json_length(&datum->keys[i],
                                                 type->key.type);
            }
        }
        return length;
    }
}

static const char *
skip_spaces(const char *p)
{
    while (isspace((unsigned char) *p)) {
        p++;
    }
    return p;
}

static char *
parse_atom_token(const char **s, const struct ovsdb_base_type *base,
                 union ovsdb_atom *atom, struct ovsdb_symbol_table *symtab)
{
    char *token, *error;

    error = ovsdb_token_parse(s, &token);
    if (!error) {
        error = ovsdb_atom_from_string(atom, base, token, symtab);
        free(token);
    }
    return error;
}

static char *
parse_key_value(const char **s, const struct ovsdb_type *type,
                union ovsdb_atom *key, union ovsdb_atom *value,
                struct ovsdb_symbol_table *symtab)
{
    const char *start = *s;
    char *error;

    error = parse_atom_token(s, &type->key, key, symtab);
    if (!error && type->value.type != OVSDB_TYPE_VOID) {
        *s = skip_spaces(*s);
        if (**s == '=') {
            (*s)++;
            *s = skip_spaces(*s);
            error = parse_atom_token(s, &type->value, value, symtab);
        } else {
            error = xasprintf("%s: syntax error at \"%c\" expecting \"=\"",
                              start, **s);
        }
        if (error) {
            ovsdb_atom_destroy(key, type->key.type);
        }
    }
    return error;
}

static void
free_key_value(const struct ovsdb_type *type,
               union ovsdb_atom *key, union ovsdb_atom *value)
{
    ovsdb_atom_destroy(key, type->key.type);
    if (type->value.type != OVSDB_TYPE_VOID) {
        ovsdb_atom_destroy(value, type->value.type);
    }
}

/* Initializes 'datum' as a datum of the given 'type', parsing its contents
 * from 's'.  The format of 's' is a series of space or comma separated atoms
 * or, for a map, '='-delimited pairs of atoms.  Each atom must in a format
 * acceptable to ovsdb_atom_from_string().  Optionally, a set may be enclosed
 * in "[]" or a map in "{}"; for an empty set or map these punctuators are
 * required.
 *
 * Optionally, a symbol table may be supplied as 'symtab'.  It is passed to
 * ovsdb_atom_to_string(). */
char *
ovsdb_datum_from_string(struct ovsdb_datum *datum,
                        const struct ovsdb_type *type, const char *s,
                        struct ovsdb_symbol_table *symtab)
{
    bool is_map = ovsdb_type_is_map(type);
    struct ovsdb_error *dberror;
    const char *p;
    int end_delim;
    char *error;

    ovsdb_datum_init_empty(datum);

    /* Swallow a leading delimiter if there is one. */
    p = skip_spaces(s);
    if (*p == (is_map ? '{' : '[')) {
        end_delim = is_map ? '}' : ']';
        p = skip_spaces(p + 1);
    } else if (!*p) {
        if (is_map) {
            return xstrdup("use \"{}\" to specify the empty map");
        } else {
            return xstrdup("use \"[]\" to specify the empty set");
        }
    } else {
        end_delim = 0;
    }

    while (*p && *p != end_delim) {
        union ovsdb_atom key, value;

        if (ovsdb_token_is_delim(*p)) {
            char *type_str = ovsdb_type_to_english(type);
            error = xasprintf("%s: unexpected \"%c\" parsing %s",
                              s, *p, type_str);
            free(type_str);
            goto error;
        }

        /* Add to datum. */
        error = parse_key_value(&p, type, &key, &value, symtab);
        if (error) {
            goto error;
        }
        ovsdb_datum_add_unsafe(datum, &key, &value, type);
        free_key_value(type, &key, &value);

        /* Skip optional white space and comma. */
        p = skip_spaces(p);
        if (*p == ',') {
            p = skip_spaces(p + 1);
        }
    }

    if (*p != end_delim) {
        error = xasprintf("%s: missing \"%c\" at end of data", s, end_delim);
        goto error;
    }
    if (end_delim) {
        p = skip_spaces(p + 1);
        if (*p) {
            error = xasprintf("%s: trailing garbage after \"%c\"",
                              s, end_delim);
            goto error;
        }
    }

    if (datum->n < type->n_min) {
        error = xasprintf("%s: %u %s specified but the minimum number is %u",
                          s, datum->n, is_map ? "pair(s)" : "value(s)",
                          type->n_min);
        goto error;
    } else if (datum->n > type->n_max) {
        error = xasprintf("%s: %u %s specified but the maximum number is %u",
                          s, datum->n, is_map ? "pair(s)" : "value(s)",
            type->n_max);
        goto error;
    }

    dberror = ovsdb_datum_sort(datum, type->key.type);
    if (dberror) {
        ovsdb_error_destroy(dberror);
        if (ovsdb_type_is_map(type)) {
            error = xasprintf("%s: map contains duplicate key", s);
        } else {
            error = xasprintf("%s: set contains duplicate value", s);
        }
        goto error;
    }

    return NULL;

error:
    ovsdb_datum_destroy(datum, type);
    ovsdb_datum_init_empty(datum);
    return error;
}

/* Appends to 'out' the 'datum' (with the given 'type') in a format acceptable
 * to ovsdb_datum_from_string(). */
void
ovsdb_datum_to_string(const struct ovsdb_datum *datum,
                      const struct ovsdb_type *type, struct ds *out)
{
    bool is_map = ovsdb_type_is_map(type);
    size_t i;

    if (type->n_max > 1 || !datum->n) {
        ds_put_char(out, is_map ? '{' : '[');
    }
    for (i = 0; i < datum->n; i++) {
        if (i > 0) {
            ds_put_cstr(out, ", ");
        }

        ovsdb_atom_to_string(&datum->keys[i], type->key.type, out);
        if (is_map) {
            ds_put_char(out, '=');
            ovsdb_atom_to_string(&datum->values[i], type->value.type, out);
        }
    }
    if (type->n_max > 1 || !datum->n) {
        ds_put_char(out, is_map ? '}' : ']');
    }
}

/* Appends to 'out' the 'datum' (with the given 'type') in a bare string format
 * that cannot be parsed uniformly back into a datum but is easier for shell
 * scripts, etc., to deal with. */
void
ovsdb_datum_to_bare(const struct ovsdb_datum *datum,
                    const struct ovsdb_type *type, struct ds *out)
{
    bool is_map = ovsdb_type_is_map(type);
    size_t i;

    for (i = 0; i < datum->n; i++) {
        if (i > 0) {
            ds_put_cstr(out, " ");
        }

        ovsdb_atom_to_bare(&datum->keys[i], type->key.type, out);
        if (is_map) {
            ds_put_char(out, '=');
            ovsdb_atom_to_bare(&datum->values[i], type->value.type, out);
        }
    }
}

/* Initializes 'datum' as a string-to-string map whose contents are taken from
 * 'smap'.  Destroys 'smap'. */
void
ovsdb_datum_from_smap(struct ovsdb_datum *datum, struct smap *smap)
{
    struct smap_node *node, *next;
    size_t i;

    datum->n = smap_count(smap);
    datum->keys = xmalloc(datum->n * sizeof *datum->keys);
    datum->values = xmalloc(datum->n * sizeof *datum->values);

    i = 0;
    SMAP_FOR_EACH_SAFE (node, next, smap) {
        smap_steal(smap, node,
                   &datum->keys[i].string, &datum->values[i].string);
        i++;
    }
    ovs_assert(i == datum->n);

    smap_destroy(smap);
    ovsdb_datum_sort_unique(datum, OVSDB_TYPE_STRING, OVSDB_TYPE_STRING);
}

static uint32_t
hash_atoms(enum ovsdb_atomic_type type, const union ovsdb_atom *atoms,
           unsigned int n, uint32_t basis)
{
    if (type != OVSDB_TYPE_VOID) {
        unsigned int i;

        for (i = 0; i < n; i++) {
            basis = ovsdb_atom_hash(&atoms[i], type, basis);
        }
    }
    return basis;
}

uint32_t
ovsdb_datum_hash(const struct ovsdb_datum *datum,
                 const struct ovsdb_type *type, uint32_t basis)
{
    basis = hash_atoms(type->key.type, datum->keys, datum->n, basis);
    basis ^= (type->key.type << 24) | (type->value.type << 16) | datum->n;
    basis = hash_atoms(type->value.type, datum->values, datum->n, basis);
    return basis;
}

static int
atom_arrays_compare_3way(const union ovsdb_atom *a,
                         const union ovsdb_atom *b,
                         enum ovsdb_atomic_type type,
                         size_t n)
{
    unsigned int i;

    for (i = 0; i < n; i++) {
        int cmp = ovsdb_atom_compare_3way(&a[i], &b[i], type);
        if (cmp) {
            return cmp;
        }
    }

    return 0;
}

bool
ovsdb_datum_equals(const struct ovsdb_datum *a,
                   const struct ovsdb_datum *b,
                   const struct ovsdb_type *type)
{
    return !ovsdb_datum_compare_3way(a, b, type);
}

int
ovsdb_datum_compare_3way(const struct ovsdb_datum *a,
                         const struct ovsdb_datum *b,
                         const struct ovsdb_type *type)
{
    int cmp;

    if (a->n != b->n) {
        return a->n < b->n ? -1 : 1;
    }

    cmp = atom_arrays_compare_3way(a->keys, b->keys, type->key.type, a->n);
    if (cmp) {
        return cmp;
    }

    return (type->value.type == OVSDB_TYPE_VOID ? 0
            : atom_arrays_compare_3way(a->values, b->values, type->value.type,
                                       a->n));
}

/* If 'key' is one of the keys in 'datum', returns its index within 'datum',
 * otherwise UINT_MAX.  'key.type' must be the type of the atoms stored in the
 * 'keys' array in 'datum'.
 */
unsigned int
ovsdb_datum_find_key(const struct ovsdb_datum *datum,
                     const union ovsdb_atom *key,
                     enum ovsdb_atomic_type key_type)
{
    unsigned int low = 0;
    unsigned int high = datum->n;
    while (low < high) {
        unsigned int idx = (low + high) / 2;
        int cmp = ovsdb_atom_compare_3way(key, &datum->keys[idx], key_type);
        if (cmp < 0) {
            high = idx;
        } else if (cmp > 0) {
            low = idx + 1;
        } else {
            return idx;
        }
    }
    return UINT_MAX;
}

/* If 'key' and 'value' is one of the key-value pairs in 'datum', returns its
 * index within 'datum', otherwise UINT_MAX.  'key.type' must be the type of
 * the atoms stored in the 'keys' array in 'datum'.  'value_type' may be the
 * type of the 'values' atoms or OVSDB_TYPE_VOID to compare only keys.
 */
unsigned int
ovsdb_datum_find_key_value(const struct ovsdb_datum *datum,
                           const union ovsdb_atom *key,
                           enum ovsdb_atomic_type key_type,
                           const union ovsdb_atom *value,
                           enum ovsdb_atomic_type value_type)
{
    unsigned int idx = ovsdb_datum_find_key(datum, key, key_type);
    if (idx != UINT_MAX
        && value_type != OVSDB_TYPE_VOID
        && !ovsdb_atom_equals(&datum->values[idx], value, value_type)) {
        idx = UINT_MAX;
    }
    return idx;
}

/* If atom 'i' in 'a' is also in 'b', returns its index in 'b', otherwise
 * UINT_MAX.  'type' must be the type of 'a' and 'b', except that
 * type->value.type may be set to OVSDB_TYPE_VOID to compare keys but not
 * values. */
static unsigned int
ovsdb_datum_find(const struct ovsdb_datum *a, int i,
                 const struct ovsdb_datum *b,
                 const struct ovsdb_type *type)
{
    return ovsdb_datum_find_key_value(b,
                                      &a->keys[i], type->key.type,
                                      a->values ? &a->values[i] : NULL,
                                      type->value.type);
}

/* Returns true if every element in 'a' is also in 'b', false otherwise. */
bool
ovsdb_datum_includes_all(const struct ovsdb_datum *a,
                         const struct ovsdb_datum *b,
                         const struct ovsdb_type *type)
{
    size_t i;

    if (a->n > b->n) {
        return false;
    }
    for (i = 0; i < a->n; i++) {
        if (ovsdb_datum_find(a, i, b, type) == UINT_MAX) {
            return false;
        }
    }
    return true;
}

/* Returns true if no element in 'a' is also in 'b', false otherwise. */
bool
ovsdb_datum_excludes_all(const struct ovsdb_datum *a,
                         const struct ovsdb_datum *b,
                         const struct ovsdb_type *type)
{
    size_t i;

    for (i = 0; i < a->n; i++) {
        if (ovsdb_datum_find(a, i, b, type) != UINT_MAX) {
            return false;
        }
    }
    return true;
}

static void
ovsdb_datum_reallocate(struct ovsdb_datum *a, const struct ovsdb_type *type,
                       unsigned int capacity)
{
    a->keys = xrealloc(a->keys, capacity * sizeof *a->keys);
    if (type->value.type != OVSDB_TYPE_VOID) {
        a->values = xrealloc(a->values, capacity * sizeof *a->values);
    }
}

/* Removes the element with index 'idx' from 'datum', which has type 'type'.
 * If 'idx' is not the last element in 'datum', then the removed element is
 * replaced by the (former) last element.
 *
 * This function does not maintain ovsdb_datum invariants.  Use
 * ovsdb_datum_sort() to check and restore these invariants. */
void
ovsdb_datum_remove_unsafe(struct ovsdb_datum *datum, size_t idx,
                          const struct ovsdb_type *type)
{
    ovsdb_atom_destroy(&datum->keys[idx], type->key.type);
    datum->keys[idx] = datum->keys[datum->n - 1];
    if (type->value.type != OVSDB_TYPE_VOID) {
        ovsdb_atom_destroy(&datum->values[idx], type->value.type);
        datum->values[idx] = datum->values[datum->n - 1];
    }
    datum->n--;
}

/* Adds the element with the given 'key' and 'value' to 'datum', which must
 * have the specified 'type'.
 *
 * This function always allocates memory, so it is not an efficient way to add
 * a number of elements to a datum.
 *
 * This function does not maintain ovsdb_datum invariants.  Use
 * ovsdb_datum_sort() to check and restore these invariants.  (But a datum with
 * 0 or 1 elements cannot violate the invariants anyhow.) */
void
ovsdb_datum_add_unsafe(struct ovsdb_datum *datum,
                       const union ovsdb_atom *key,
                       const union ovsdb_atom *value,
                       const struct ovsdb_type *type)
{
    size_t idx = datum->n++;
    datum->keys = xrealloc(datum->keys, datum->n * sizeof *datum->keys);
    ovsdb_atom_clone(&datum->keys[idx], key, type->key.type);
    if (type->value.type != OVSDB_TYPE_VOID) {
        datum->values = xrealloc(datum->values,
                                 datum->n * sizeof *datum->values);
        ovsdb_atom_clone(&datum->values[idx], value, type->value.type);
    }
}

void
ovsdb_datum_union(struct ovsdb_datum *a, const struct ovsdb_datum *b,
                  const struct ovsdb_type *type, bool replace)
{
    unsigned int n;
    size_t bi;

    n = a->n;
    for (bi = 0; bi < b->n; bi++) {
        unsigned int ai;

        ai = ovsdb_datum_find_key(a, &b->keys[bi], type->key.type);
        if (ai == UINT_MAX) {
            if (n == a->n) {
                ovsdb_datum_reallocate(a, type, a->n + (b->n - bi));
            }
            ovsdb_atom_clone(&a->keys[n], &b->keys[bi], type->key.type);
            if (type->value.type != OVSDB_TYPE_VOID) {
                ovsdb_atom_clone(&a->values[n], &b->values[bi],
                                 type->value.type);
            }
            n++;
        } else if (replace && type->value.type != OVSDB_TYPE_VOID) {
            ovsdb_atom_destroy(&a->values[ai], type->value.type);
            ovsdb_atom_clone(&a->values[ai], &b->values[bi],
                             type->value.type);
        }
    }
    if (n != a->n) {
        struct ovsdb_error *error;
        a->n = n;
        error = ovsdb_datum_sort(a, type->key.type);
        ovs_assert(!error);
    }
}

void
ovsdb_datum_subtract(struct ovsdb_datum *a, const struct ovsdb_type *a_type,
                     const struct ovsdb_datum *b,
                     const struct ovsdb_type *b_type)
{
    bool changed = false;
    size_t i;

    ovs_assert(a_type->key.type == b_type->key.type);
    ovs_assert(a_type->value.type == b_type->value.type
               || b_type->value.type == OVSDB_TYPE_VOID);

    /* XXX The big-O of this could easily be improved. */
    for (i = 0; i < a->n; ) {
        unsigned int idx = ovsdb_datum_find(a, i, b, b_type);
        if (idx != UINT_MAX) {
            changed = true;
            ovsdb_datum_remove_unsafe(a, i, a_type);
        } else {
            i++;
        }
    }
    if (changed) {
        ovsdb_datum_sort_assert(a, a_type->key.type);
    }
}

struct ovsdb_symbol_table *
ovsdb_symbol_table_create(void)
{
    struct ovsdb_symbol_table *symtab = xmalloc(sizeof *symtab);
    shash_init(&symtab->sh);
    return symtab;
}

void
ovsdb_symbol_table_destroy(struct ovsdb_symbol_table *symtab)
{
    if (symtab) {
        shash_destroy_free_data(&symtab->sh);
        free(symtab);
    }
}

struct ovsdb_symbol *
ovsdb_symbol_table_get(const struct ovsdb_symbol_table *symtab,
                       const char *name)
{
    return shash_find_data(&symtab->sh, name);
}

struct ovsdb_symbol *
ovsdb_symbol_table_put(struct ovsdb_symbol_table *symtab, const char *name,
                       const struct uuid *uuid, bool created)
{
    struct ovsdb_symbol *symbol;

    ovs_assert(!ovsdb_symbol_table_get(symtab, name));
    symbol = xmalloc(sizeof *symbol);
    symbol->uuid = *uuid;
    symbol->created = created;
    symbol->strong_ref = false;
    symbol->weak_ref = false;
    shash_add(&symtab->sh, name, symbol);
    return symbol;
}

struct ovsdb_symbol *
ovsdb_symbol_table_insert(struct ovsdb_symbol_table *symtab,
                          const char *name)
{
    struct ovsdb_symbol *symbol;

    symbol = ovsdb_symbol_table_get(symtab, name);
    if (!symbol) {
        struct uuid uuid;

        uuid_generate(&uuid);
        symbol = ovsdb_symbol_table_put(symtab, name, &uuid, false);
    }
    return symbol;
}

/* Extracts a token from the beginning of 's' and returns a pointer just after
 * the token.  Stores the token itself into '*outp', which the caller is
 * responsible for freeing (with free()).
 *
 * If 's[0]' is a delimiter, the returned token is the empty string.
 *
 * A token extends from 's' to the first delimiter, as defined by
 * ovsdb_token_is_delim(), or until the end of the string.  A delimiter can be
 * escaped with a backslash, in which case the backslash does not appear in the
 * output.  Double quotes also cause delimiters to be ignored, but the double
 * quotes are retained in the output.  (Backslashes inside double quotes are
 * not removed, either.)
 */
char *
ovsdb_token_parse(const char **s, char **outp)
{
    const char *p;
    struct ds out;
    bool in_quotes;
    char *error;

    ds_init(&out);
    in_quotes = false;
    for (p = *s; *p != '\0'; ) {
        int c = *p++;
        if (c == '\\') {
            if (in_quotes) {
                ds_put_char(&out, '\\');
            }
            if (!*p) {
                error = xasprintf("%s: backslash at end of argument", *s);
                goto error;
            }
            ds_put_char(&out, *p++);
        } else if (!in_quotes && ovsdb_token_is_delim(c)) {
            p--;
            break;
        } else {
            ds_put_char(&out, c);
            if (c == '"') {
                in_quotes = !in_quotes;
            }
        }
    }
    if (in_quotes) {
        error = xasprintf("%s: quoted string extends past end of argument",
                          *s);
        goto error;
    }
    *outp = ds_cstr(&out);
    *s = p;
    return NULL;

error:
    ds_destroy(&out);
    *outp = NULL;
    return error;
}

/* Returns true if 'c' delimits tokens, or if 'c' is 0, and false otherwise. */
bool
ovsdb_token_is_delim(unsigned char c)
{
    return strchr(":=, []{}!<>", c) != NULL;
}
