/* Copyright (c) 2009, 2010, 2011, 2012, 2014, 2016, 2017 Nicira, Inc.
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

#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "ovs-thread.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "openvswitch/json.h"
#include "openvswitch/shash.h"
#include "smap.h"
#include "sort.h"
#include "unicode.h"
#include "util.h"

static struct json *
wrap_json(const char *name, struct json *wrapped)
{
    return json_array_create_2(json_string_create(name), wrapped);
}

/* Initializes 'atom' with the default value of the given 'type'.
 *
 * The default value for an atom is as defined in RFC 7047:
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
        atom->s = ovsdb_atom_string_create_nocopy(xmemdup("", 1));
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
        return json_string(atom->s)[0] == '\0';

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
        new->s = json_clone(old->s);
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
        return json_hash(atom->s, basis);

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
        return a->s == b->s ? 0 : strcmp(json_string(a->s), json_string(b->s));

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
        || json->array.n != 2
        || json->array.elems[0]->type != JSON_STRING
        || (name && strcmp(json_string(json->array.elems[0]), name))
        || json->array.elems[1]->type != value_type)
    {
        *value = NULL;
        return ovsdb_syntax_error(json, NULL, "expected [\"%s\", <%s>]", name,
                                  json_type_to_string(value_type));
    }
    *value = json->array.elems[1];
    return NULL;
}

static struct ovsdb_error *
parse_json_pair(const struct json *json,
                const struct json **elem0, const struct json **elem1)
{
    if (json->type != JSON_ARRAY || json->array.n != 2) {
        return ovsdb_syntax_error(json, NULL, "expected 2-element array");
    }
    *elem0 = json->array.elems[0];
    *elem1 = json->array.elems[1];
    return NULL;
}

static void
ovsdb_symbol_referenced(struct ovsdb_symbol *symbol,
                        const struct ovsdb_base_type *base)
{
    ovs_assert(base->type == OVSDB_TYPE_UUID);

    if (base->uuid.refTableName) {
        switch (base->uuid.refType) {
        case OVSDB_REF_STRONG:
            symbol->strong_ref = true;
            break;
        case OVSDB_REF_WEAK:
            symbol->weak_ref = true;
            break;
        }
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

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
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

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
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
            atom->integer = json->integer;
            return NULL;
        }
        break;

    case OVSDB_TYPE_REAL:
        if (json->type == JSON_INTEGER) {
            atom->real = json->integer;
            return NULL;
        } else if (json->type == JSON_REAL) {
            atom->real = json->real;
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
            atom->s = json_clone(json);
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
 * RFC 7047 for information about this, and for the syntax that this function
 * accepts.  If 'base' is a reference and a symbol is parsed, then the symbol's
 * 'strong_ref' or 'weak_ref' member is set to true, as appropriate. */
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
 * If 'allow_shallow_copies' is false, deep copy of the string JSON object
 * will be used.  Useful when the same string object is accessed by multiple
 * threads as deep copy will not change the reference counter of the original
 * JSON string.
 *
 * Refer to RFC 7047 for the format of the JSON that this function produces. */
static struct json *
ovsdb_atom_to_json__(const union ovsdb_atom *atom, enum ovsdb_atomic_type type,
                     bool allow_shallow_copies)
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
        return allow_shallow_copies ? json_clone(atom->s)
                                    : json_deep_clone(atom->s);

    case OVSDB_TYPE_UUID:
        return wrap_json("uuid", json_string_create_uuid(&atom->uuid));

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

struct json *
ovsdb_atom_to_json(const union ovsdb_atom *atom, enum ovsdb_atomic_type type)
{
    return ovsdb_atom_to_json__(atom, type, true);
}

static struct json *
ovsdb_atom_to_json_deep(const union ovsdb_atom *atom,
                        enum ovsdb_atomic_type type)
{
    return ovsdb_atom_to_json__(atom, type, false);
}

static char *
ovsdb_atom_from_string__(union ovsdb_atom *atom,
                         union ovsdb_atom **range_end_atom,
                         const struct ovsdb_base_type *base, const char *s,
                         struct ovsdb_symbol_table *symtab)
{
    enum ovsdb_atomic_type type = base->type;

    switch (type) {
    case OVSDB_TYPE_VOID:
        OVS_NOT_REACHED();

    case OVSDB_TYPE_INTEGER: {
        long long int integer, end;
        if (range_end_atom
            && str_to_llong_range(s, 10, &integer, &end)) {
            if (end < integer) {
                return xasprintf("\"%s\" is not a valid range. "
                    "Range end cannot be before start.", s);
            }
            *range_end_atom = alloc_default_atoms(type, 1);
            if (!(*range_end_atom)) {
                return xasprintf("\"%s\" is not a valid range", s);
            }
            (*range_end_atom)->integer = end;
        } else if (!str_to_llong(s, 10, &integer)) {
            return xasprintf("\"%s\" is not a valid integer or range", s);
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
            } else {
                char *res;
                if (json_string_unescape(s + 1, s_len - 2, &res)) {
                    atom->s = ovsdb_atom_string_create_nocopy(res);
                } else {
                    char *error = xasprintf("%s: %s", s, res);
                    free(res);
                    return error;
                }
            }
        } else {
            atom->s = ovsdb_atom_string_create(s);
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

/* Initializes 'atom' and optionally 'range_end_atom' to a value of type 'base'
 * parsed from 's', which takes one of the following forms:
 *
 *      - OVSDB_TYPE_INTEGER: A decimal integer optionally preceded by a sign
 *        or two decimal integers optionally preceded by a sign and separated
 *        by a hyphen, representing inclusive range of integers
 *        ['atom', 'range_end_atom'].
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
 *
 * Does not attempt to parse range if 'range_end_atom' is a null pointer.
 * Dynamically allocates ovdsb_atom and stores its address in '*range_end_atom'
 * if successfully parses range. Caller is responsible for deallocating
 * the memory by calling 'ovsdb_atom_destroy' and then 'free' on the address.
 * Does not allocate memory and sets '*range_end_atom' to a null pointer
 * if does not parse a range or fails for any reason.
 */
char *
ovsdb_atom_from_string(union ovsdb_atom *atom,
                       union ovsdb_atom **range_end_atom,
                       const struct ovsdb_base_type *base, const char *s,
                       struct ovsdb_symbol_table *symtab)
{
    struct ovsdb_error *error;
    char *msg;

    if (range_end_atom) {
        *range_end_atom = NULL;
    }

    msg = ovsdb_atom_from_string__(atom, range_end_atom, base, s, symtab);
    if (msg) {
        return msg;
    }

    error = ovsdb_atom_check_constraints(atom, base);

    if (!error && range_end_atom && *range_end_atom) {
        /* Check range constraints */
        int64_t start = atom->integer;
        int64_t end = (*range_end_atom)->integer;
        if (base->enum_) {
            for (int64_t i = start + 1; i <= end; i++) {
                union ovsdb_atom ai = { .integer = i };
                error = ovsdb_atom_check_constraints(&ai, base);
                if (error) {
                    break;
                }
            }
        } else {
            error = ovsdb_atom_check_constraints(*range_end_atom, base);
        }

        if (!error) {
            error = ovsdb_atom_range_check_size(start, end);
        }
    }

    if (error) {
        ovsdb_atom_destroy(atom, base->type);
        if (range_end_atom && *range_end_atom) {
            ovsdb_atom_destroy(*range_end_atom, base->type);
            free(*range_end_atom);
            *range_end_atom = NULL;
        }
        msg = ovsdb_error_to_string_free(error);
    }
    return msg;
}

static bool
string_needs_quotes(const char *s)
{
    const char *p = s;
    unsigned char c;
    struct uuid uuid;

    c = *p++;
    if (!isalpha(c) && c != '_') {
        return true;
    }

    while ((c = *p++) != '\0') {
        if (!isalpha(c) && !isdigit(c) && c != '_' && c != '-' && c != '.') {
            return true;
        }
    }

    if (!strcmp(s, "true") || !strcmp(s, "false")) {
        return true;
    }

    if (uuid_from_string(&uuid, s)) {
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
        if (string_needs_quotes(json_string(atom->s))) {
            json_to_ds(atom->s, 0, out);
        } else {
            ds_put_cstr(out, json_string(atom->s));
        }
        break;

    case OVSDB_TYPE_UUID:
        ds_put_uuid(out, &atom->uuid);
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
        ds_put_cstr(out, json_string(atom->s));
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
        && !ovsdb_datum_find_key(base->enum_, atom, base->type, NULL)) {
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
        if (atom->integer >= base->integer.min
            && atom->integer <= base->integer.max) {
            return NULL;
        } else if (base->integer.min != INT64_MIN) {
            if (base->integer.max != INT64_MAX) {
                return ovsdb_error("constraint violation",
                                   "%"PRId64" is not in the valid range "
                                   "%"PRId64" to %"PRId64" (inclusive)",
                                   atom->integer,
                                   base->integer.min, base->integer.max);
            } else {
                return ovsdb_error("constraint violation",
                                   "%"PRId64" is less than minimum allowed "
                                   "value %"PRId64,
                                   atom->integer, base->integer.min);
            }
        } else {
            return ovsdb_error("constraint violation",
                               "%"PRId64" is greater than maximum allowed "
                               "value %"PRId64,
                               atom->integer, base->integer.max);
        }
        OVS_NOT_REACHED();

    case OVSDB_TYPE_REAL:
        if (atom->real >= base->real.min && atom->real <= base->real.max) {
            return NULL;
        } else if (base->real.min != -DBL_MAX) {
            if (base->real.max != DBL_MAX) {
                return ovsdb_error("constraint violation",
                                   "%.*g is not in the valid range "
                                   "%.*g to %.*g (inclusive)",
                                   DBL_DIG, atom->real,
                                   DBL_DIG, base->real.min,
                                   DBL_DIG, base->real.max);
            } else {
                return ovsdb_error("constraint violation",
                                   "%.*g is less than minimum allowed "
                                   "value %.*g",
                                   DBL_DIG, atom->real,
                                   DBL_DIG, base->real.min);
            }
        } else {
            return ovsdb_error("constraint violation",
                               "%.*g is greater than maximum allowed "
                               "value %.*g",
                               DBL_DIG, atom->real,
                               DBL_DIG, base->real.max);
        }
        OVS_NOT_REACHED();

    case OVSDB_TYPE_BOOLEAN:
        return NULL;

    case OVSDB_TYPE_STRING:
        return check_string_constraints(json_string(atom->s), &base->string);

    case OVSDB_TYPE_UUID:
        return NULL;

    case OVSDB_N_TYPES:
    default:
        OVS_NOT_REACHED();
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
    datum->refcnt = NULL;
}

/* Initializes 'datum' as a datum that has the default value for 'type'.
 *
 * The default value for a particular type is as defined in RFC 7047:
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
    datum->refcnt = NULL;
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
        static unsigned int refcnt = 1;
        static const struct ovsdb_datum empty = { .refcnt = &refcnt };
        return &empty;
    } else if (type->n_min == 1) {
        static struct ovsdb_datum default_data[OVSDB_N_TYPES][OVSDB_N_TYPES];
        static unsigned int refcnt[OVSDB_N_TYPES][OVSDB_N_TYPES];
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
            d->refcnt = &refcnt[kt][vt];
            *d->refcnt = 1;
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

/* Initializes 'new' as a shallow copy of 'old_'.
 *
 * The caller must eventually arrange for 'new' to be destroyed (with
 * ovsdb_datum_destroy()).  The caller must call ovsdb_datum_unshare()
 * before attempting direct modifications of the 'new' or 'old_', i.e.
 * modifications outside of the ovsdb_datum_* API. */
void
ovsdb_datum_clone(struct ovsdb_datum *new, const struct ovsdb_datum *old_)
{
    struct ovsdb_datum *old = CONST_CAST(struct ovsdb_datum *, old_);

    if (!old->refcnt) {
        old->refcnt = xmalloc(sizeof *old->refcnt);
        *old->refcnt = 1;
    }
    memcpy(new, old, sizeof *new);
    (*new->refcnt)++;
}

static void
free_data(enum ovsdb_atomic_type type,
          union ovsdb_atom *atoms, size_t n_atoms)
{
    if (!atoms) {
        return;
    }

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
    if (!datum->refcnt || !--(*datum->refcnt)) {
        free_data(type->key.type, datum->keys, datum->n);
        free_data(type->value.type, datum->values, datum->n);
        free(datum->refcnt);
    }
}

/* This function should be called before attempting direct modifications
 * of the 'datum', i.e. modifications outside of the ovsdb_datum_* API. */
void
ovsdb_datum_unshare(struct ovsdb_datum *datum, const struct ovsdb_type *type)
{
    if (!datum->refcnt || *datum->refcnt == 1) {
        return;
    }
    datum->keys = clone_atoms(datum->keys, type->key.type, datum->n);
    datum->values = clone_atoms(datum->values, type->value.type, datum->n);
    (*datum->refcnt)--;
    datum->refcnt = NULL;
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
ovsdb_datum_sort(struct ovsdb_datum *datum, const struct ovsdb_type *type)
{
    size_t i;

    if (datum->n < 2) {
        return NULL;
    }

    ovsdb_datum_unshare(datum, type);

    ovsdb_datum_sort__(datum, type->key.type, OVSDB_TYPE_VOID);

    for (i = 0; i < datum->n - 1; i++) {
        if (ovsdb_atom_equals(&datum->keys[i], &datum->keys[i + 1],
                              type->key.type)) {
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
                        const struct ovsdb_type *type)
{
    struct ovsdb_error *error = ovsdb_datum_sort(datum, type);
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
                        const struct ovsdb_type *type)
{
    size_t src, dst;

    if (datum->n < 2) {
        return 0;
    }

    ovsdb_datum_unshare(datum, type);
    ovsdb_datum_sort__(datum, type->key.type, type->value.type);

    dst = 1;
    for (src = 1; src < datum->n; src++) {
        if (ovsdb_atom_equals(&datum->keys[src], &datum->keys[dst - 1],
                              type->key.type)) {
            ovsdb_atom_destroy(&datum->keys[src], type->key.type);
            if (type->value.type != OVSDB_TYPE_VOID) {
                ovsdb_atom_destroy(&datum->values[src], type->value.type);
            }
        } else {
            if (src != dst) {
                datum->keys[dst] = datum->keys[src];
                if (type->value.type != OVSDB_TYPE_VOID) {
                    datum->values[dst] = datum->values[src];
                }
            }
            dst++;
        }
    }
    datum->n = dst;
    return src - datum->n;
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
            && json->array.n > 0
            && json->array.elems[0]->type == JSON_STRING
            && !strcmp(json_string(json->array.elems[0]), "set"))) {
        bool is_map = ovsdb_type_is_map(type);
        const char *class = is_map ? "map" : "set";
        const struct json *inner;
        unsigned int i;
        size_t n;

        error = unwrap_json(json, class, JSON_ARRAY, &inner);
        if (error) {
            return error;
        }

        n = inner->array.n;
        if (n < type->n_min || n > type->n_max) {
            if (type->n_min == 1 && type->n_max == 1) {
                return ovsdb_syntax_error(json, NULL, "%s must have exactly "
                                          "one member but %"PRIuSIZE" "
                                          "are present", class, n);
            } else {
                return ovsdb_syntax_error(json, NULL, "%s must have %u to "
                                          "%u members but %"PRIuSIZE" are "
                                          "present",
                                          class, type->n_min, type->n_max, n);
            }
        }

        datum->n = 0;
        datum->keys = xmalloc(n * sizeof *datum->keys);
        datum->values = is_map ? xmalloc(n * sizeof *datum->values) : NULL;
        datum->refcnt = NULL;
        for (i = 0; i < n; i++) {
            const struct json *element = inner->array.elems[i];
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
        datum->refcnt = NULL;

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
 * RFC 7047 for information about this, and for the syntax that this function
 * accepts. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
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

    error = ovsdb_datum_sort(datum, type);
    if (error) {
        ovsdb_datum_destroy(datum, type);
    }
    return error;
}

/* Parses 'json' as a datum of the type described by 'type' for internal
 * use. This function is similar to 'ovsdb_datum_from_json', except the
 * member size of set or map is not checked.
 *
 * The datum generated should be used then discard. It is not suitable
 * for storing into IDL because of the possible member size violation.  */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_transient_datum_from_json(struct ovsdb_datum *datum,
                                const struct ovsdb_type *type,
                                const struct json *json)
{
    struct ovsdb_type relaxed_type = *type;

    relaxed_type.n_min = 0;
    relaxed_type.n_max = UINT_MAX;

    return ovsdb_datum_from_json(datum, &relaxed_type, json, NULL);
}

/* Parses 'json' as a datum of the type described by 'type', but ignoring all
 * constraints. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_unconstrained_datum_from_json(struct ovsdb_datum *datum,
                                    const struct ovsdb_type *type,
                                    const struct json *json)
{
    struct ovsdb_type relaxed_type;

    ovsdb_base_type_init(&relaxed_type.key, type->key.type);
    ovsdb_base_type_init(&relaxed_type.value, type->value.type);
    relaxed_type.n_min = 0;
    relaxed_type.n_max = UINT_MAX;

    return ovsdb_datum_from_json(datum, &relaxed_type, json, NULL);
}

static struct json *
ovsdb_base_to_json(const union ovsdb_atom *atom,
                   const struct ovsdb_base_type *base,
                   bool use_row_names,
                   bool allow_shallow_copies)
{
    if (!use_row_names
        || base->type != OVSDB_TYPE_UUID
        || !base->uuid.refTableName) {
        return allow_shallow_copies
               ? ovsdb_atom_to_json(atom, base->type)
               : ovsdb_atom_to_json_deep(atom, base->type);
    } else {
        return json_array_create_2(
            json_string_create("named-uuid"),
            json_string_create_nocopy(ovsdb_data_row_name(&atom->uuid)));
    }
}

static struct json *
ovsdb_datum_to_json__(const struct ovsdb_datum *datum,
                      const struct ovsdb_type *type,
                      bool use_row_names,
                      bool allow_shallow_copies)
{
    if (ovsdb_type_is_map(type)) {
        struct json **elems;
        size_t i;

        elems = xmalloc(datum->n * sizeof *elems);
        for (i = 0; i < datum->n; i++) {
            elems[i] = json_array_create_2(
                ovsdb_base_to_json(&datum->keys[i], &type->key,
                                   use_row_names, allow_shallow_copies),
                ovsdb_base_to_json(&datum->values[i], &type->value,
                                   use_row_names, allow_shallow_copies));
        }

        return wrap_json("map", json_array_create(elems, datum->n));
    } else if (datum->n == 1) {
        return ovsdb_base_to_json(&datum->keys[0], &type->key,
                                  use_row_names, allow_shallow_copies);
    } else {
        struct json **elems;
        size_t i;

        elems = xmalloc(datum->n * sizeof *elems);
        for (i = 0; i < datum->n; i++) {
            elems[i] = ovsdb_base_to_json(&datum->keys[i], &type->key,
                                          use_row_names, allow_shallow_copies);
        }

        return wrap_json("set", json_array_create(elems, datum->n));
    }
}

/* Converts 'datum', of the specified 'type', to JSON format, and returns the
 * JSON.  The caller is responsible for freeing the returned JSON.
 *
 * 'type' constraints on datum->n are ignored.
 *
 * Refer to RFC 7047 for the format of the JSON that this function produces. */
struct json *
ovsdb_datum_to_json(const struct ovsdb_datum *datum,
                    const struct ovsdb_type *type)
{
    return ovsdb_datum_to_json__(datum, type, false, true);
}

struct json *
ovsdb_datum_to_json_deep(const struct ovsdb_datum *datum,
                         const struct ovsdb_type *type)
{
    return ovsdb_datum_to_json__(datum, type, false, false);
}

struct json *
ovsdb_datum_to_json_with_row_names(const struct ovsdb_datum *datum,
                                   const struct ovsdb_type *type)
{
    return ovsdb_datum_to_json__(datum, type, true, true);
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
                 union ovsdb_atom *atom, union ovsdb_atom **range_end_atom,
                 struct ovsdb_symbol_table *symtab)
{
    char *token, *error;

    error = ovsdb_token_parse(s, &token);
    if (!error) {
        error = ovsdb_atom_from_string(atom, range_end_atom,
                                       base, token, symtab);
        free(token);
    }
    return error;
}

static char *
parse_key_value(const char **s, const struct ovsdb_type *type,
                union ovsdb_atom *key, union ovsdb_atom *value,
                struct ovsdb_symbol_table *symtab,
                union ovsdb_atom **range_end_key)
{
    const char *start = *s;
    char *error;

    error = parse_atom_token(s, &type->key, key, range_end_key, symtab);

    if (!error && type->value.type != OVSDB_TYPE_VOID) {
        *s = skip_spaces(*s);
        if (**s == '=') {
            (*s)++;
            *s = skip_spaces(*s);
            error = parse_atom_token(s, &type->value, value, NULL, symtab);
        } else {
            error = xasprintf("%s: syntax error at \"%c\" expecting \"=\"",
                              start, **s);
        }
        if (error) {
            ovsdb_atom_destroy(key, type->key.type);
            if (range_end_key && *range_end_key) {
                ovsdb_atom_destroy(*range_end_key, type->key.type);
                free(*range_end_key);
                *range_end_key = NULL;
            }
        }
    }
    return error;
}

static void
free_key_value_range(const struct ovsdb_type *type,
                     union ovsdb_atom *key, union ovsdb_atom *value,
                     union ovsdb_atom **range_end_atom)
{
    ovsdb_atom_destroy(key, type->key.type);
    if (type->value.type != OVSDB_TYPE_VOID) {
        ovsdb_atom_destroy(value, type->value.type);
    }
    if (range_end_atom && *range_end_atom) {
        ovsdb_atom_destroy(*range_end_atom, type->key.type);
        free(*range_end_atom);
        *range_end_atom = NULL;
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
        union ovsdb_atom *range_end_key = NULL;

        if (ovsdb_token_is_delim(*p)) {
            char *type_str = ovsdb_type_to_english(type);
            error = xasprintf("%s: unexpected \"%c\" parsing %s",
                              s, *p, type_str);
            free(type_str);
            goto error;
        }

        /* Add to datum. */
        error = parse_key_value(&p, type, &key, &value,
                                symtab, &range_end_key);
        if (error) {
            goto error;
        }
        ovsdb_datum_add_unsafe(datum, &key, &value, type, range_end_key);
        free_key_value_range(type, &key, &value, &range_end_key);

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

    dberror = ovsdb_datum_sort(datum, type);
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

/* Initializes 'datum' as a string-to-string map whose contents are copied from
 * 'smap', which is not modified. */
void
ovsdb_datum_from_smap(struct ovsdb_datum *datum, const struct smap *smap)
{
    datum->n = smap_count(smap);
    datum->keys = xmalloc(datum->n * sizeof *datum->keys);
    datum->values = xmalloc(datum->n * sizeof *datum->values);
    datum->refcnt = NULL;

    struct smap_node *node;
    size_t i = 0;
    SMAP_FOR_EACH (node, smap) {
        datum->keys[i].s = ovsdb_atom_string_create(node->key);
        datum->values[i].s = ovsdb_atom_string_create(node->value);
        i++;
    }
    ovs_assert(i == datum->n);

    struct ovsdb_type type = {
        OVSDB_BASE_STRING_INIT, OVSDB_BASE_STRING_INIT,
        0, UINT_MAX
    };
    ovsdb_datum_sort_unique(datum, &type);
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_datum_convert(struct ovsdb_datum *dst,
                    const struct ovsdb_type *dst_type,
                    const struct ovsdb_datum *src,
                    const struct ovsdb_type *src_type)
{
    struct json *json = ovsdb_datum_to_json(src, src_type);
    struct ovsdb_error *error = ovsdb_datum_from_json(dst, dst_type, json,
                                                      NULL);
    json_destroy(json);
    return error;
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

    if (a->refcnt && a->refcnt == b->refcnt) {
        return 0;
    }

    cmp = atom_arrays_compare_3way(a->keys, b->keys, type->key.type, a->n);
    if (cmp) {
        return cmp;
    }

    return (type->value.type == OVSDB_TYPE_VOID ? 0
            : atom_arrays_compare_3way(a->values, b->values, type->value.type,
                                       a->n));
}

/* If 'key' is one of the keys in 'datum', returns 'true' and sets '*pos' to
 * its index within 'datum', otherwise returns 'false' and sets '*pos' to the
 * index where 'key' should have been.  'key.type' must be the type of the
 * atoms stored in the 'keys' array in 'datum'.
 */
bool
ovsdb_datum_find_key(const struct ovsdb_datum *datum,
                     const union ovsdb_atom *key,
                     enum ovsdb_atomic_type key_type,
                     unsigned int *pos)
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
            if (pos) {
                *pos = idx;
            }
            return true;
        }
    }
    if (pos) {
        *pos = low;
    }
    return false;
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
    unsigned int idx;

    if (!ovsdb_datum_find_key(datum, key, key_type, &idx)
        || (value_type != OVSDB_TYPE_VOID
            && !ovsdb_atom_equals(&datum->values[idx], value, value_type))) {
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
    ovsdb_datum_unshare(a, type);

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
    ovsdb_datum_unshare(datum, type);

    ovsdb_atom_destroy(&datum->keys[idx], type->key.type);
    datum->keys[idx] = datum->keys[datum->n - 1];
    if (type->value.type != OVSDB_TYPE_VOID) {
        ovsdb_atom_destroy(&datum->values[idx], type->value.type);
        datum->values[idx] = datum->values[datum->n - 1];
    }
    datum->n--;
}

/* Adds the element with the given 'key' and 'value' to 'datum', which must
 * have the specified 'type'. Optionally if 'range_end_atom' is not
 * a null pointer, adds a set of integers to 'datum' from inclusive
 * range ['key', 'range_end_atom'].
 *
 * This function always allocates memory, so it is not an efficient way to add
 * a number of elements to a datum.
 *
 * When adding a range of integers, this function allocates the memory once
 * for the whole range.
 *
 * This function does not maintain ovsdb_datum invariants.  Use
 * ovsdb_datum_sort() to check and restore these invariants.  (But a datum with
 * 0 or 1 elements cannot violate the invariants anyhow.) */
void
ovsdb_datum_add_unsafe(struct ovsdb_datum *datum,
                       const union ovsdb_atom *key,
                       const union ovsdb_atom *value,
                       const struct ovsdb_type *type,
                       const union ovsdb_atom *range_end_atom)
{
    size_t idx = datum->n;

    ovsdb_datum_unshare(datum, type);

    datum->n += range_end_atom ?
                (range_end_atom->integer - key->integer + 1) : 1;
    datum->keys = xrealloc(datum->keys, datum->n * sizeof *datum->keys);
    if (range_end_atom && key->integer <= range_end_atom->integer) {
        for (int64_t i = key->integer; i <= range_end_atom->integer; i++) {
            datum->keys[idx++].integer = i;
        }
    } else {
        ovsdb_atom_clone(&datum->keys[idx], key, type->key.type);
        if (type->value.type != OVSDB_TYPE_VOID) {
            datum->values = xrealloc(datum->values,
                                     datum->n * sizeof *datum->values);
            ovsdb_atom_clone(&datum->values[idx], value, type->value.type);
        }
    }
}

void
ovsdb_datum_add_from_index_unsafe(struct ovsdb_datum *dst,
                                  const struct ovsdb_datum *src,
                                  size_t idx,
                                  const struct ovsdb_type *type)
{
    const union ovsdb_atom *key = &src->keys[idx];
    const union ovsdb_atom *value = type->value.type != OVSDB_TYPE_VOID
                                    ? &src->values[idx]
                                    : NULL;
    ovsdb_datum_add_unsafe(dst, key, value, type, NULL);
}

/* Adds 'n' atoms starting from index 'start_idx' from 'src' to the end of
 * 'dst'.  'dst' should have enough memory allocated to hold the additional
 * 'n' atoms.  Atoms are not cloned, i.e. 'dst' will reference the same data.
 * Caller also should take care of the result being sorted. */
static void
ovsdb_datum_push_unsafe(struct ovsdb_datum *dst,
                        const struct ovsdb_datum *src,
                        unsigned int start_idx, unsigned int n,
                        const struct ovsdb_type *type)
{
    if (n == 0) {
        return;
    }

    ovsdb_datum_unshare(dst, type);

    memcpy(&dst->keys[dst->n], &src->keys[start_idx], n * sizeof src->keys[0]);
    if (type->value.type != OVSDB_TYPE_VOID) {
        memcpy(&dst->values[dst->n], &src->values[start_idx],
               n * sizeof src->values[0]);
    }
    dst->n += n;
}

void
ovsdb_datum_union(struct ovsdb_datum *a, const struct ovsdb_datum *b,
                  const struct ovsdb_type *type)
{
    struct ovsdb_datum result;
    unsigned int copied, pos;

    ovsdb_datum_unshare(a, type);
    ovsdb_datum_init_empty(&result);

    copied = 0;
    for (size_t bi = 0; bi < b->n; bi++) {
        if (ovsdb_datum_find_key(a, &b->keys[bi], type->key.type, &pos)) {
            /* Atom with the same key already exists. */
            continue;
        }
        if (!result.keys) {
            ovsdb_datum_reallocate(&result, type, a->n + (b->n - bi));
        }
        if (pos > copied) {
            /* Need to copy some atoms from 'a' first. */
            ovsdb_datum_push_unsafe(&result, a, copied, pos - copied, type);
            copied = pos;
        }
        /* Inserting new atom from 'b'. */
        ovsdb_atom_clone(&result.keys[result.n], &b->keys[bi], type->key.type);
        if (type->value.type != OVSDB_TYPE_VOID) {
            ovsdb_atom_clone(&result.values[result.n], &b->values[bi],
                             type->value.type);
        }
        result.n++;
    }
    if (!result.keys) {
        /* 'a' doesn't need to be changed. */
        return;
    }
    if (a->n > copied) {
        /* Copying remaining atoms. */
        ovsdb_datum_push_unsafe(&result, a, copied, a->n - copied, type);
    }
    /* All atoms are copied now. */
    a->n = 0;

    ovsdb_datum_swap(&result, a);
    ovsdb_datum_destroy(&result, type);
}

void
ovsdb_datum_subtract(struct ovsdb_datum *a, const struct ovsdb_type *a_type,
                     const struct ovsdb_datum *b,
                     const struct ovsdb_type *b_type)
{
    unsigned int *idx, ai;
    size_t n_idx;

    ovs_assert(a_type->key.type == b_type->key.type);
    ovs_assert(a_type->value.type == b_type->value.type
               || b_type->value.type == OVSDB_TYPE_VOID);

    ovsdb_datum_unshare(a, a_type);

    idx = xmalloc(b->n * sizeof *idx);
    n_idx = 0;
    for (size_t bi = 0; bi < b->n; bi++) {
        ai = ovsdb_datum_find(b, bi, a, b_type);
        if (ai == UINT_MAX) {
            /* No such atom in 'a'. */
            continue;
        }
        /* Not destroying right away since ovsdb_datum_find() will use them. */
        idx[n_idx++] = ai;
    }
    if (!n_idx) {
        free(idx);
        return;
    }

    struct ovsdb_datum result;

    ovsdb_datum_init_empty(&result);
    ovsdb_datum_reallocate(&result, a_type, a->n - n_idx);

    unsigned int start_idx = 0;
    for (size_t i = 0; i < n_idx; i++) {
        ai = idx[i];

        /* Destroying atom. */
        ovsdb_atom_destroy(&a->keys[ai], a_type->key.type);
        if (a_type->value.type != OVSDB_TYPE_VOID) {
            ovsdb_atom_destroy(&a->values[ai], a_type->value.type);
        }

        /* Copy non-removed atoms from 'a' to result. */
        ovsdb_datum_push_unsafe(&result, a, start_idx, ai - start_idx, a_type);
        start_idx = idx[i] + 1;
    }
    /* Copying remaining atoms. */
    ovsdb_datum_push_unsafe(&result, a, start_idx, a->n - start_idx, a_type);
    a->n = 0;

    ovsdb_datum_swap(&result, a);
    ovsdb_datum_destroy(&result, a_type);
    free(idx);
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

/* APIs for Generating and apply diffs.  */

/* Find what needs to be added to and removed from 'old' to construct 'new'.
 * If the optional 'diff' is provided, it can be used to speed up processing,
 * in case it is smaller than the original 'old' and 'new'.
 *
 * The 'added' and 'removed' datums are always safe; the orders of keys are
 * maintained since they are added in order.   */
void
ovsdb_datum_added_removed(struct ovsdb_datum *added,
                          struct ovsdb_datum *removed,
                          const struct ovsdb_datum *old,
                          const struct ovsdb_datum *new,
                          const struct ovsdb_datum *diff,
                          const struct ovsdb_type *type)
{
    size_t oi, ni;

    ovsdb_datum_init_empty(added);
    ovsdb_datum_init_empty(removed);
    if (!ovsdb_type_is_composite(type)) {
        ovsdb_datum_clone(removed, old);
        ovsdb_datum_clone(added, new);
        return;
    }

    /* Use diff, if provided, unless it's comparable in size.  With a large
     * diff, the O(n log n) binary search of each element may be slower than
     * a simple O(n) comparison between old and new. */
    if (diff && diff->n * 2 < old->n + new->n) {
        unsigned int idx;

        for (size_t di = 0; di < diff->n; di++) {
            bool found = ovsdb_datum_find_key(old, &diff->keys[di],
                                              type->key.type, &idx);

            if (!found) {
                ovsdb_datum_add_from_index_unsafe(added, diff, di, type);
            } else {
                if (type->value.type != OVSDB_TYPE_VOID
                    && !ovsdb_atom_equals(&diff->values[di],
                                          &old->values[idx],
                                          type->value.type)) {
                    ovsdb_datum_add_from_index_unsafe(added, diff, di, type);
                }
                ovsdb_datum_add_from_index_unsafe(removed, old, idx, type);
            }
        }
        return;
    }

    /* Generate the diff in O(n) time. */
    for (oi = ni = 0; oi < old->n && ni < new->n;) {
        int c = ovsdb_atom_compare_3way(&old->keys[oi], &new->keys[ni],
                                        type->key.type);
        if (c < 0) {
            ovsdb_datum_add_from_index_unsafe(removed, old, oi, type);
            oi++;
        } else if (c > 0) {
            ovsdb_datum_add_from_index_unsafe(added, new, ni, type);
            ni++;
        } else {
            if (type->value.type != OVSDB_TYPE_VOID &&
                ovsdb_atom_compare_3way(&old->values[oi], &new->values[ni],
                                        type->value.type)) {
                ovsdb_datum_add_unsafe(removed, &old->keys[oi],
                                       &old->values[oi], type, NULL);
                ovsdb_datum_add_unsafe(added, &new->keys[ni], &new->values[ni],
                                       type, NULL);
            }
            oi++; ni++;
        }
    }

    for (; oi < old->n; oi++) {
        ovsdb_datum_add_from_index_unsafe(removed, old, oi, type);
    }

    for (; ni < new->n; ni++) {
        ovsdb_datum_add_from_index_unsafe(added, new, ni, type);
    }
}


/* Generate a difference ovsdb_dataum between 'old' and 'new'.
 * 'new' can be regenerated by applying the difference to the 'old'.
 *
 * The diff operation is reversible. Given 'old',
 * 'new' can be recreated by applying diff to 'old'.
 *
 * Thus
 *     Let  d = 'old' diff 'new'
 *     then 'new' = 'old' diff d
 *
 * The 'diff' datum is always safe; the orders of keys are maintained
 * since they are added in order.   */
void
ovsdb_datum_diff(struct ovsdb_datum *diff,
                 const struct ovsdb_datum *old,
                 const struct ovsdb_datum *new,
                 const struct ovsdb_type *type)
{
    size_t oi, ni;

    ovsdb_datum_init_empty(diff);
    if (!ovsdb_type_is_composite(type)) {
        ovsdb_datum_clone(diff, new);
        return;
    }

    /* Generate the diff in O(n) time. */
    for (oi = ni = 0; oi < old->n && ni < new->n; ) {
        int c = ovsdb_atom_compare_3way(&old->keys[oi], &new->keys[ni],
                                        type->key.type);
        if (c < 0) {
            ovsdb_datum_add_from_index_unsafe(diff, old, oi, type);
            oi++;
        } else if (c > 0) {
            ovsdb_datum_add_from_index_unsafe(diff, new, ni, type);
            ni++;
        } else {
            if (type->value.type != OVSDB_TYPE_VOID &&
                ovsdb_atom_compare_3way(&old->values[oi], &new->values[ni],
                                        type->value.type)) {
                ovsdb_datum_add_unsafe(diff, &new->keys[ni], &new->values[ni],
                                       type, NULL);
            }
            oi++; ni++;
        }
    }

    for (; oi < old->n; oi++) {
        ovsdb_datum_add_from_index_unsafe(diff, old, oi, type);
    }

    for (; ni < new->n; ni++) {
        ovsdb_datum_add_from_index_unsafe(diff, new, ni, type);
    }
}

/* Apply 'diff' to 'a'.
 *
 * Return NULL if the 'a' is successfully updated, otherwise, return
 * ovsdb_error. */
struct ovsdb_error *
ovsdb_datum_apply_diff_in_place(struct ovsdb_datum *a,
                                const struct ovsdb_datum *diff,
                                const struct ovsdb_type *type)
{
    struct ovsdb_error *error = NULL;
    struct ovsdb_datum result;
    size_t i, new_size;
    unsigned int *idx, pos;
    enum {
        DIFF_OP_ADD,
        DIFF_OP_REMOVE,
        DIFF_OP_UPDATE,
    } *operation;

    if (!ovsdb_type_is_composite(type)) {
        ovsdb_datum_destroy(a, type);
        ovsdb_datum_clone(a, diff);
        return NULL;
    }

    ovsdb_datum_unshare(a, type);

    operation = xmalloc(diff->n * sizeof *operation);
    idx = xmalloc(diff->n * sizeof *idx);
    new_size = a->n;
    for (i = 0; i < diff->n; i++) {
        if (!ovsdb_datum_find_key(a, &diff->keys[i], type->key.type, &pos)) {
            operation[i] = DIFF_OP_ADD;
            new_size++;
        } else if (type->value.type != OVSDB_TYPE_VOID
                   && !ovsdb_atom_equals(&diff->values[i], &a->values[pos],
                                         type->value.type)) {
            operation[i] = DIFF_OP_UPDATE;
        } else {
            operation[i] = DIFF_OP_REMOVE;
            new_size--;
        }
        idx[i] = pos;
    }

    /* Make sure member size of 'new' conforms to type. */
    if (new_size < type->n_min || new_size > type->n_max) {
        error = ovsdb_error(NULL, "Datum crated by diff has size error");
        goto exit;
    }

    ovsdb_datum_init_empty(&result);
    ovsdb_datum_reallocate(&result, type, new_size);

    unsigned int copied = 0;
    for (i = 0; i < diff->n; i++) {
        pos = idx[i];

        if (copied < pos) {
            /* Copying all atoms that should go before the current one. */
            ovsdb_datum_push_unsafe(&result, a, copied, pos - copied, type);
            copied = pos;
        }

        switch (operation[i]) {
        case DIFF_OP_UPDATE:
        case DIFF_OP_ADD:
            /* Inserting new atom from 'diff'. */
            ovsdb_atom_clone(&result.keys[result.n],
                             &diff->keys[i], type->key.type);
            if (type->value.type != OVSDB_TYPE_VOID) {
                ovsdb_atom_clone(&result.values[result.n],
                                 &diff->values[i], type->value.type);
            }
            result.n++;
            if (operation[i] != DIFF_OP_UPDATE) {
                break;
            }
            /* fall through */

        case DIFF_OP_REMOVE:
            /* Destroying atom. */
            ovsdb_atom_destroy(&a->keys[pos], type->key.type);
            if (type->value.type != OVSDB_TYPE_VOID) {
                ovsdb_atom_destroy(&a->values[pos], type->value.type);
            }
            copied++; /* Skipping removed atom. */
            break;
        }
    }
    /* Copying remaining atoms. */
    ovsdb_datum_push_unsafe(&result, a, copied, a->n - copied, type);
    a->n = 0;

    ovsdb_datum_swap(&result, a);
    ovsdb_datum_destroy(&result, type);
exit:
    free(operation);
    free(idx);
    return error;
}

/* Apply 'diff' to 'old' to regenerate 'new'.
 *
 * Return NULL if the 'new' is successfully generated, otherwise, return
 * ovsdb_error and the stat of 'new' is indeterministic. */
struct ovsdb_error *
ovsdb_datum_apply_diff(struct ovsdb_datum *new,
                       const struct ovsdb_datum *old,
                       const struct ovsdb_datum *diff,
                       const struct ovsdb_type *type)
{
    ovsdb_datum_diff(new, old, diff, type);

    /* Make sure member size of 'new' conforms to type. */
    if (new->n < type->n_min || new->n > type->n_max) {
        ovsdb_datum_destroy(new, type);
        return ovsdb_error(NULL, "Datum crated by diff has size error");
    }

    return NULL;
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

struct ovsdb_error *
ovsdb_atom_range_check_size(int64_t range_start, int64_t range_end)
{
    if ((uint64_t) range_end - (uint64_t) range_start
        >= MAX_OVSDB_ATOM_RANGE_SIZE) {
        return ovsdb_error("constraint violation",
                           "Range \"%"PRId64"-%"PRId64"\" is too big. "
                           "Maximum allowed size is %d.",
                           range_start, range_end, MAX_OVSDB_ATOM_RANGE_SIZE);
    }
    return NULL;
}

char *
ovsdb_data_row_name(const struct uuid *uuid)
{
    char *name;
    char *p;

    name = xasprintf("row"UUID_FMT, UUID_ARGS(uuid));
    for (p = name; *p != '\0'; p++) {
        if (*p == '-') {
            *p = '_';
        }
    }

    return name;
}
