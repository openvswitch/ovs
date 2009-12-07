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

#include "ovsdb-data.h"

#include <assert.h>

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
ovsdb_datum_init_default(struct ovsdb_datum *datum,
                         const struct ovsdb_type *type)
{
    datum->n = type->n_min;
    datum->keys = alloc_default_atoms(type->key_type, datum->n);
    datum->values = alloc_default_atoms(type->value_type, datum->n);
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

static struct ovsdb_error *
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

static bool
ovsdb_datum_contains(const struct ovsdb_datum *a, int i,
                     const struct ovsdb_datum *b,
                     const struct ovsdb_type *type)
{
    int low = 0;
    int high = b->n;
    while (low < high) {
        int j = (low + high) / 2;
        int cmp = ovsdb_atom_compare_3way(&a->keys[i], &b->keys[j], type->key_type);
        if (cmp < 0) {
            high = j;
        } else if (cmp > 0) {
            low = j + 1;
        } else {
            return (type->value_type == OVSDB_TYPE_VOID
                    || ovsdb_atom_equals(&a->values[i], &b->values[j],
                                         type->value_type));
        }
    }
    return false;
}

/* Returns true if every element in 'a' is also in 'b', false otherwise. */
bool
ovsdb_datum_includes_all(const struct ovsdb_datum *a,
                         const struct ovsdb_datum *b,
                         const struct ovsdb_type *type)
{
    size_t i;

    for (i = 0; i < a->n; i++) {
        if (!ovsdb_datum_contains(a, i, b, type)) {
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
        if (ovsdb_datum_contains(a, i, b, type)) {
            return false;
        }
    }
    return true;
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
