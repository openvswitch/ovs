/* Copyright (c) 2009, 2010 Nicira Networks
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

#include <assert.h>
#include <ctype.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>

#include "dynamic-string.h"
#include "hash.h"
#include "ovsdb-error.h"
#include "json.h"
#include "shash.h"
#include "sort.h"

static struct json *
wrap_json(const char *name, struct json *wrapped)
{
    return json_array_create_2(json_string_create(name), wrapped);
}

void
ovsdb_atom_init_default(union ovsdb_atom *atom, enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        NOT_REACHED();

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
        NOT_REACHED();
    }
}

bool
ovsdb_atom_is_default(const union ovsdb_atom *atom,
                      enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        NOT_REACHED();

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
        NOT_REACHED();
    }
}

void
ovsdb_atom_clone(union ovsdb_atom *new, const union ovsdb_atom *old,
                 enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        NOT_REACHED();

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
        NOT_REACHED();
    }
}

void
ovsdb_atom_swap(union ovsdb_atom *a, union ovsdb_atom *b)
{
    union ovsdb_atom tmp = *a;
    *a = *b;
    *b = tmp;
}

uint32_t
ovsdb_atom_hash(const union ovsdb_atom *atom, enum ovsdb_atomic_type type,
                uint32_t basis)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        NOT_REACHED();

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
        NOT_REACHED();
    }
}

int
ovsdb_atom_compare_3way(const union ovsdb_atom *a,
                        const union ovsdb_atom *b,
                        enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        NOT_REACHED();

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
        NOT_REACHED();
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

static struct ovsdb_error *
ovsdb_atom_parse_uuid(struct uuid *uuid, const struct json *json,
                      const struct ovsdb_symbol_table *symtab)
    WARN_UNUSED_RESULT;

static struct ovsdb_error *
ovsdb_atom_parse_uuid(struct uuid *uuid, const struct json *json,
                      const struct ovsdb_symbol_table *symtab)
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
            const char *name = json_string(value);
            const struct ovsdb_symbol *symbol;

            ovsdb_error_destroy(error0);

            symbol = ovsdb_symbol_table_get(symtab, name);
            if (symbol) {
                *uuid = symbol->uuid;
                return NULL;
            } else {
                return ovsdb_syntax_error(json, NULL,
                                          "unknown named-uuid \"%s\"", name);
            }
        }
        ovsdb_error_destroy(error1);
    }

    return error0;
}

struct ovsdb_error *
ovsdb_atom_from_json(union ovsdb_atom *atom, enum ovsdb_atomic_type type,
                     const struct json *json,
                     const struct ovsdb_symbol_table *symtab)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        NOT_REACHED();

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
        return ovsdb_atom_parse_uuid(&atom->uuid, json, symtab);

    case OVSDB_N_TYPES:
    default:
        NOT_REACHED();
    }

    return ovsdb_syntax_error(json, NULL, "expected %s",
                              ovsdb_atomic_type_to_string(type));
}

struct json *
ovsdb_atom_to_json(const union ovsdb_atom *atom, enum ovsdb_atomic_type type)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        NOT_REACHED();

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
        NOT_REACHED();
    }
}

/* Initializes 'atom' to a value of the given 'type' parsed from 's', which
 * takes one of the following forms:
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
 *      - OVSDB_TYPE_UUID: A UUID in RFC 4122 format.
 *
 * Returns a null pointer if successful, otherwise an error message describing
 * the problem.  The caller is responsible for freeing the error.
 */
char *
ovsdb_atom_from_string(union ovsdb_atom *atom, enum ovsdb_atomic_type type,
                       const char *s)
{
    switch (type) {
    case OVSDB_TYPE_VOID:
        NOT_REACHED();

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
        if (!uuid_from_string(&atom->uuid, s)) {
            return xasprintf("\"%s\" is not a valid UUID", s);
        }
        break;

    case OVSDB_N_TYPES:
    default:
        NOT_REACHED();
    }

    return NULL;
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
        NOT_REACHED();

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
        NOT_REACHED();
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

void
ovsdb_datum_init_empty(struct ovsdb_datum *datum)
{
    datum->n = 0;
    datum->keys = NULL;
    datum->values = NULL;
}

void
ovsdb_datum_init_default(struct ovsdb_datum *datum,
                         const struct ovsdb_type *type)
{
    datum->n = type->n_min;
    datum->keys = alloc_default_atoms(type->key_type, datum->n);
    datum->values = alloc_default_atoms(type->value_type, datum->n);
}

bool
ovsdb_datum_is_default(const struct ovsdb_datum *datum,
                       const struct ovsdb_type *type)
{
    size_t i;

    if (datum->n != type->n_min) {
        return false;
    }
    for (i = 0; i < datum->n; i++) {
        if (!ovsdb_atom_is_default(&datum->keys[i], type->key_type)) {
            return false;
        }
        if (type->value_type != OVSDB_TYPE_VOID
            && !ovsdb_atom_is_default(&datum->values[i], type->value_type)) {
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

void
ovsdb_datum_clone(struct ovsdb_datum *new, const struct ovsdb_datum *old,
                  const struct ovsdb_type *type)
{
    unsigned int n = old->n;
    new->n = n;
    new->keys = clone_atoms(old->keys, type->key_type, n);
    new->values = clone_atoms(old->values, type->value_type, n);
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

void
ovsdb_datum_destroy(struct ovsdb_datum *datum, const struct ovsdb_type *type)
{
    free_data(type->key_type, datum->keys, datum->n);
    free_data(type->value_type, datum->values, datum->n);
}

void
ovsdb_datum_swap(struct ovsdb_datum *a, struct ovsdb_datum *b)
{
    struct ovsdb_datum tmp = *a;
    *a = *b;
    *b = tmp;
}

struct ovsdb_datum_sort_cbdata {
    const struct ovsdb_type *type;
    struct ovsdb_datum *datum;
};

static int
ovsdb_datum_sort_compare_cb(size_t a, size_t b, void *cbdata_)
{
    struct ovsdb_datum_sort_cbdata *cbdata = cbdata_;

    return ovsdb_atom_compare_3way(&cbdata->datum->keys[a],
                                   &cbdata->datum->keys[b],
                                   cbdata->type->key_type);
}

static void
ovsdb_datum_sort_swap_cb(size_t a, size_t b, void *cbdata_)
{
    struct ovsdb_datum_sort_cbdata *cbdata = cbdata_;

    ovsdb_atom_swap(&cbdata->datum->keys[a], &cbdata->datum->keys[b]);
    if (cbdata->type->value_type != OVSDB_TYPE_VOID) {
        ovsdb_atom_swap(&cbdata->datum->values[a], &cbdata->datum->values[b]);
    }
}

struct ovsdb_error *
ovsdb_datum_sort(struct ovsdb_datum *datum, const struct ovsdb_type *type)
{
    if (datum->n < 2) {
        return NULL;
    } else {
        struct ovsdb_datum_sort_cbdata cbdata;
        size_t i;

        cbdata.type = type;
        cbdata.datum = datum;
        sort(datum->n, ovsdb_datum_sort_compare_cb, ovsdb_datum_sort_swap_cb,
             &cbdata);

        for (i = 0; i < datum->n - 1; i++) {
            if (ovsdb_atom_equals(&datum->keys[i], &datum->keys[i + 1],
                                  type->key_type)) {
                if (ovsdb_type_is_map(type)) {
                    return ovsdb_error(NULL, "map contains duplicate key");
                } else {
                    return ovsdb_error(NULL, "set contains duplicate");
                }
            }
        }

        return NULL;
    }
}

struct ovsdb_error *
ovsdb_datum_from_json(struct ovsdb_datum *datum,
                      const struct ovsdb_type *type,
                      const struct json *json,
                      const struct ovsdb_symbol_table *symtab)
{
    struct ovsdb_error *error;

    if (ovsdb_type_is_scalar(type)) {
        datum->n = 1;
        datum->keys = xmalloc(sizeof *datum->keys);
        datum->values = NULL;

        error = ovsdb_atom_from_json(&datum->keys[0], type->key_type,
                                     json, symtab);
        if (error) {
            free(datum->keys);
        }
        return error;
    } else {
        bool is_map = ovsdb_type_is_map(type);
        const char *class = is_map ? "map" : "set";
        const struct json *inner;
        unsigned int i;
        size_t n;

        assert(is_map || ovsdb_type_is_set(type));

        error = unwrap_json(json, class, JSON_ARRAY, &inner);
        if (error) {
            return error;
        }

        n = inner->u.array.n;
        if (n < type->n_min || n > type->n_max) {
            return ovsdb_syntax_error(json, NULL, "%s must have %u to "
                                      "%u members but %zu are present",
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

            error = ovsdb_atom_from_json(&datum->keys[i], type->key_type,
                                         key, symtab);
            if (error) {
                goto error;
            }

            if (is_map) {
                error = ovsdb_atom_from_json(&datum->values[i],
                                             type->value_type, value, symtab);
                if (error) {
                    ovsdb_atom_destroy(&datum->keys[i], type->key_type);
                    goto error;
                }
            }

            datum->n++;
        }

        error = ovsdb_datum_sort(datum, type);
        if (error) {
            goto error;
        }

        return NULL;

    error:
        ovsdb_datum_destroy(datum, type);
        return error;
    }
}

struct json *
ovsdb_datum_to_json(const struct ovsdb_datum *datum,
                    const struct ovsdb_type *type)
{
    /* These tests somewhat tolerate a 'datum' that does not exactly match
     * 'type', in particular a datum with 'n' not in the allowed range. */
    if (datum->n == 1 && ovsdb_type_is_scalar(type)) {
        return ovsdb_atom_to_json(&datum->keys[0], type->key_type);
    } else if (type->value_type == OVSDB_TYPE_VOID) {
        struct json **elems;
        size_t i;

        elems = xmalloc(datum->n * sizeof *elems);
        for (i = 0; i < datum->n; i++) {
            elems[i] = ovsdb_atom_to_json(&datum->keys[i], type->key_type);
        }

        return wrap_json("set", json_array_create(elems, datum->n));
    } else {
        struct json **elems;
        size_t i;

        elems = xmalloc(datum->n * sizeof *elems);
        for (i = 0; i < datum->n; i++) {
            elems[i] = json_array_create_2(
                ovsdb_atom_to_json(&datum->keys[i], type->key_type),
                ovsdb_atom_to_json(&datum->values[i], type->value_type));
        }

        return wrap_json("map", json_array_create(elems, datum->n));
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
parse_atom_token(const char **s, enum ovsdb_atomic_type type,
                 union ovsdb_atom *atom)
{
    char *token, *error;

    error = ovsdb_token_parse(s, &token);
    if (!error) {
        error = ovsdb_atom_from_string(atom, type, token);
        free(token);
    }
    return error;
}


static char *
parse_key_value(const char **s, const struct ovsdb_type *type,
                union ovsdb_atom *key, union ovsdb_atom *value)
{
    const char *start = *s;
    char *error;

    error = parse_atom_token(s, type->key_type, key);
    if (!error && type->value_type != OVSDB_TYPE_VOID) {
        if (**s == '=') {
            (*s)++;
            error = parse_atom_token(s, type->value_type, value);
        } else {
            error = xasprintf("%s: syntax error at \"%c\" expecting \"=\"",
                              start, **s);
        }
        if (error) {
            ovsdb_atom_destroy(key, type->key_type);
        }
    }
    return error;
}

static void
free_key_value(const struct ovsdb_type *type,
               union ovsdb_atom *key, union ovsdb_atom *value)
{
    ovsdb_atom_destroy(key, type->key_type);
    if (type->value_type != OVSDB_TYPE_VOID) {
        ovsdb_atom_destroy(value, type->value_type);
    }
}

/* Initializes 'datum' as a datum of the given 'type', parsing its contents
 * from 's'.  The format of 's' is a series of space or comma separated atoms
 * or, for a map, '='-delimited pairs of atoms.  Each atom must in a format
 * acceptable to ovsdb_atom_from_string().  Optionally, a set may be enclosed
 * in "[]" or a map in "{}"; for an empty set or map these punctuators are
 * required. */
char *
ovsdb_datum_from_string(struct ovsdb_datum *datum,
                        const struct ovsdb_type *type, const char *s)
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
            error = xasprintf("%s: unexpected \"%c\" parsing %s",
                              s, *p, ovsdb_type_to_english(type));
            goto error;
        }

        /* Add to datum. */
        error = parse_key_value(&p, type, &key, &value);
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

        ovsdb_atom_to_string(&datum->keys[i], type->key_type, out);
        if (is_map) {
            ds_put_char(out, '=');
            ovsdb_atom_to_string(&datum->values[i], type->value_type, out);
        }
    }
    if (type->n_max > 1 || !datum->n) {
        ds_put_char(out, is_map ? '}' : ']');
    }
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
    basis = hash_atoms(type->key_type, datum->keys, datum->n, basis);
    basis ^= (type->key_type << 24) | (type->value_type << 16) | datum->n;
    basis = hash_atoms(type->value_type, datum->values, datum->n, basis);
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

    cmp = atom_arrays_compare_3way(a->keys, b->keys, type->key_type, a->n);
    if (cmp) {
        return cmp;
    }

    return (type->value_type == OVSDB_TYPE_VOID ? 0
            : atom_arrays_compare_3way(a->values, b->values, type->value_type,
                                       a->n));
}

/* If 'key' is one of the keys in 'datum', returns its index within 'datum',
 * otherwise UINT_MAX.  'key_type' must be the type of the atoms stored in the
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
 * index within 'datum', otherwise UINT_MAX.  'key_type' must be the type of
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
 * type->value_type may be set to OVSDB_TYPE_VOID to compare keys but not
 * values. */
static unsigned int
ovsdb_datum_find(const struct ovsdb_datum *a, int i,
                 const struct ovsdb_datum *b,
                 const struct ovsdb_type *type)
{
    return ovsdb_datum_find_key_value(b,
                                      &a->keys[i], type->key_type,
                                      a->values ? &a->values[i] : NULL,
                                      type->value_type);
}

/* Returns true if every element in 'a' is also in 'b', false otherwise. */
bool
ovsdb_datum_includes_all(const struct ovsdb_datum *a,
                         const struct ovsdb_datum *b,
                         const struct ovsdb_type *type)
{
    size_t i;

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
    if (type->value_type != OVSDB_TYPE_VOID) {
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
    ovsdb_atom_destroy(&datum->keys[idx], type->key_type);
    datum->keys[idx] = datum->keys[datum->n - 1];
    if (type->value_type != OVSDB_TYPE_VOID) {
        ovsdb_atom_destroy(&datum->values[idx], type->value_type);
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
    ovsdb_atom_clone(&datum->keys[idx], key, type->key_type);
    if (type->value_type != OVSDB_TYPE_VOID) {
        datum->values = xrealloc(datum->values,
                                 datum->n * sizeof *datum->values);
        ovsdb_atom_clone(&datum->values[idx], value, type->value_type);
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

        ai = ovsdb_datum_find_key(a, &b->keys[bi], type->key_type);
        if (ai == UINT_MAX) {
            if (n == a->n) {
                ovsdb_datum_reallocate(a, type, a->n + (b->n - bi));
            }
            ovsdb_atom_clone(&a->keys[n], &b->keys[bi], type->key_type);
            if (type->value_type != OVSDB_TYPE_VOID) {
                ovsdb_atom_clone(&a->values[n], &b->values[bi],
                                 type->value_type);
            }
            n++;
        } else if (replace && type->value_type != OVSDB_TYPE_VOID) {
            ovsdb_atom_destroy(&a->values[ai], type->value_type);
            ovsdb_atom_clone(&a->values[ai], &b->values[bi],
                             type->value_type);
        }
    }
    if (n != a->n) {
        struct ovsdb_error *error;
        a->n = n;
        error = ovsdb_datum_sort(a, type);
        assert(!error);
    }
}

void
ovsdb_datum_subtract(struct ovsdb_datum *a, const struct ovsdb_type *a_type,
                     const struct ovsdb_datum *b,
                     const struct ovsdb_type *b_type)
{
    bool changed = false;
    size_t i;

    assert(a_type->key_type == b_type->key_type);
    assert(a_type->value_type == b_type->value_type
           || b_type->value_type == OVSDB_TYPE_VOID);

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
        struct ovsdb_error *error = ovsdb_datum_sort(a, a_type);
        assert(!error);
    }
}

struct ovsdb_symbol_table {
    struct shash sh;
};

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
        struct shash_node *node, *next;

        SHASH_FOR_EACH_SAFE (node, next, &symtab->sh) {
            struct ovsdb_symbol *symbol = node->data;
            free(symbol);
            shash_delete(&symtab->sh, node);
        }
        shash_destroy(&symtab->sh);
        free(symtab);
    }
}

struct ovsdb_symbol *
ovsdb_symbol_table_get(const struct ovsdb_symbol_table *symtab,
                       const char *name)
{
    return shash_find_data(&symtab->sh, name);
}

void
ovsdb_symbol_table_put(struct ovsdb_symbol_table *symtab, const char *name,
                       const struct uuid *uuid, bool used)
{
    struct ovsdb_symbol *symbol;

    assert(!ovsdb_symbol_table_get(symtab, name));
    symbol = xmalloc(sizeof *symbol);
    symbol->uuid = *uuid;
    symbol->used = used;
    shash_add(&symtab->sh, name, symbol);
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
    return strchr(":=, []{}", c) != NULL;
}
