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

#ifndef OVSDB_DATA_H
#define OVSDB_DATA_H 1

#include <stdlib.h>
#include "compiler.h"
#include "ovsdb-types.h"

struct ovsdb_symbol_table;

/* One value of an atomic type (given by enum ovs_atomic_type). */
union ovsdb_atom {
    int64_t integer;
    double real;
    bool boolean;
    char *string;
    struct uuid uuid;
};

void ovsdb_atom_init_default(union ovsdb_atom *, enum ovsdb_atomic_type);
void ovsdb_atom_clone(union ovsdb_atom *, const union ovsdb_atom *,
                      enum ovsdb_atomic_type);
void ovsdb_atom_swap(union ovsdb_atom *, union ovsdb_atom *);

static inline bool
ovsdb_atom_needs_destruction(enum ovsdb_atomic_type type)
{
    return type == OVSDB_TYPE_STRING;
}

static inline void
ovsdb_atom_destroy(union ovsdb_atom *atom, enum ovsdb_atomic_type type)
{
    if (type == OVSDB_TYPE_STRING) {
        free(atom->string);
    }
}

uint32_t ovsdb_atom_hash(const union ovsdb_atom *, enum ovsdb_atomic_type,
                         uint32_t basis);

int ovsdb_atom_compare_3way(const union ovsdb_atom *,
                            const union ovsdb_atom *,
                            enum ovsdb_atomic_type);

static inline bool ovsdb_atom_equals(const union ovsdb_atom *a,
                                     const union ovsdb_atom *b,
                                     enum ovsdb_atomic_type type)
{
    return !ovsdb_atom_compare_3way(a, b, type);
}

struct ovsdb_error *ovsdb_atom_from_json(union ovsdb_atom *,
                                         enum ovsdb_atomic_type,
                                         const struct json *,
                                         const struct ovsdb_symbol_table *)
    WARN_UNUSED_RESULT;
struct json *ovsdb_atom_to_json(const union ovsdb_atom *,
                                enum ovsdb_atomic_type);

/* One value of an OVSDB type (given by struct ovsdb_type). */
struct ovsdb_datum {
    unsigned int n;             /* Number of 'keys' and 'values'. */
    union ovsdb_atom *keys;     /* Each of the ovsdb_type's 'key_type'. */
    union ovsdb_atom *values;   /* Each of the ovsdb_type's 'value_type'. */
};

void ovsdb_datum_init_default(struct ovsdb_datum *, const struct ovsdb_type *);
void ovsdb_datum_clone(struct ovsdb_datum *, const struct ovsdb_datum *,
                       const struct ovsdb_type *);
void ovsdb_datum_destroy(struct ovsdb_datum *, const struct ovsdb_type *);
void ovsdb_datum_swap(struct ovsdb_datum *, struct ovsdb_datum *);

struct ovsdb_error *ovsdb_datum_from_json(struct ovsdb_datum *,
                                          const struct ovsdb_type *,
                                          const struct json *,
                                          const struct ovsdb_symbol_table *)
    WARN_UNUSED_RESULT;
struct json *ovsdb_datum_to_json(const struct ovsdb_datum *,
                                 const struct ovsdb_type *);

uint32_t ovsdb_datum_hash(const struct ovsdb_datum *,
                          const struct ovsdb_type *, uint32_t basis);
int ovsdb_datum_compare_3way(const struct ovsdb_datum *,
                             const struct ovsdb_datum *,
                             const struct ovsdb_type *);
bool ovsdb_datum_equals(const struct ovsdb_datum *,
                        const struct ovsdb_datum *,
                        const struct ovsdb_type *);
bool ovsdb_datum_includes_all(const struct ovsdb_datum *,
                              const struct ovsdb_datum *,
                              const struct ovsdb_type *);
bool ovsdb_datum_excludes_all(const struct ovsdb_datum *,
                              const struct ovsdb_datum *,
                              const struct ovsdb_type *);

static inline bool
ovsdb_datum_conforms_to_type(const struct ovsdb_datum *datum,
                             const struct ovsdb_type *type)
{
    return datum->n >= type->n_min && datum->n <= type->n_max;
}

/* A table mapping from names to data items.  Currently the data items are
 * always UUIDs; perhaps this will be expanded in the future. */

struct ovsdb_symbol {
    struct uuid uuid;           /* The UUID that the symbol represents. */
    bool used;                  /* Already used as row UUID? */
};

struct ovsdb_symbol_table *ovsdb_symbol_table_create(void);
void ovsdb_symbol_table_destroy(struct ovsdb_symbol_table *);
struct ovsdb_symbol *ovsdb_symbol_table_get(const struct ovsdb_symbol_table *,
                                            const char *name);
void ovsdb_symbol_table_put(struct ovsdb_symbol_table *, const char *name,
                            const struct uuid *, bool used);

#endif /* ovsdb-data.h */
