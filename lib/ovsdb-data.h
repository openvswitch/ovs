/* Copyright (c) 2009, 2010, 2011, 2012, 2015, 2016, 2017 Nicira, Inc.
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
#include "openvswitch/shash.h"

#define MAX_OVSDB_ATOM_RANGE_SIZE 4096

struct ds;
struct ovsdb_symbol_table;
struct smap;

/* One value of an atomic type (given by enum ovs_atomic_type). */
union ovsdb_atom {
    int64_t integer;
    double real;
    bool boolean;
    char *string;
    struct uuid uuid;
};

void ovsdb_atom_init_default(union ovsdb_atom *, enum ovsdb_atomic_type);
const union ovsdb_atom *ovsdb_atom_default(enum ovsdb_atomic_type);
bool ovsdb_atom_is_default(const union ovsdb_atom *, enum ovsdb_atomic_type);
void ovsdb_atom_clone(union ovsdb_atom *, const union ovsdb_atom *,
                      enum ovsdb_atomic_type);
void ovsdb_atom_swap(union ovsdb_atom *, union ovsdb_atom *);

/* Returns false if ovsdb_atom_destroy() is a no-op when it is applied to an
 * initialized atom of the given 'type', true if ovsdb_atom_destroy() actually
 * does something.
 *
 * This can be used to avoid calling ovsdb_atom_destroy() for each element in
 * an array of homogeneous atoms.  (It's not worthwhile for a single atom.) */
static inline bool
ovsdb_atom_needs_destruction(enum ovsdb_atomic_type type)
{
    return type == OVSDB_TYPE_STRING;
}

/* Frees the contents of 'atom', which must have the specified 'type'.
 *
 * This does not actually call free(atom).  If necessary, the caller must be
 * responsible for that. */
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

/* Returns true if 'a' and 'b', which are both of type 'type', has the same
 * contents, false if their contents differ.  */
static inline bool ovsdb_atom_equals(const union ovsdb_atom *a,
                                     const union ovsdb_atom *b,
                                     enum ovsdb_atomic_type type)
{
    return !ovsdb_atom_compare_3way(a, b, type);
}

struct ovsdb_error *ovsdb_atom_from_json(union ovsdb_atom *,
                                         const struct ovsdb_base_type *,
                                         const struct json *,
                                         struct ovsdb_symbol_table *)
    OVS_WARN_UNUSED_RESULT;
struct json *ovsdb_atom_to_json(const union ovsdb_atom *,
                                enum ovsdb_atomic_type);

char *ovsdb_atom_from_string(union ovsdb_atom *, union ovsdb_atom **,
                             const struct ovsdb_base_type *, const char *,
                             struct ovsdb_symbol_table *)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_atom_to_string(const union ovsdb_atom *, enum ovsdb_atomic_type,
                          struct ds *);
void ovsdb_atom_to_bare(const union ovsdb_atom *, enum ovsdb_atomic_type,
                        struct ds *);

struct ovsdb_error *ovsdb_atom_check_constraints(
    const union ovsdb_atom *, const struct ovsdb_base_type *)
    OVS_WARN_UNUSED_RESULT;

/* An instance of an OVSDB type (given by struct ovsdb_type).
 *
 * - The 'keys' must be unique and in sorted order.  Most functions that modify
 *   an ovsdb_datum maintain these invariants.  Functions that don't maintain
 *   the invariants have names that end in "_unsafe".  Use ovsdb_datum_sort()
 *   to check and restore these invariants.
 *
 * - 'n' is constrained by the ovsdb_type's 'n_min' and 'n_max'.
 *
 *   If 'n' is nonzero, then 'keys' points to an array of 'n' atoms of the type
 *   specified by the ovsdb_type's 'key_type'.  (Otherwise, 'keys' should be
 *   null.)
 *
 *   If 'n' is nonzero and the ovsdb_type's 'value_type' is not
 *   OVSDB_TYPE_VOID, then 'values' points to an array of 'n' atoms of the type
 *   specified by the 'value_type'.  (Otherwise, 'values' should be null.)
 *
 *   Thus, for 'n' > 0, 'keys' will always be nonnull and 'values' will be
 *   nonnull only for "map" types.
 */
struct ovsdb_datum {
    unsigned int n;             /* Number of 'keys' and 'values'. */
    union ovsdb_atom *keys;     /* Each of the ovsdb_type's 'key_type'. */
    union ovsdb_atom *values;   /* Each of the ovsdb_type's 'value_type'. */
};
#define OVSDB_DATUM_INITIALIZER { 0, NULL, NULL }

/* Basics. */
void ovsdb_datum_init_empty(struct ovsdb_datum *);
void ovsdb_datum_init_default(struct ovsdb_datum *, const struct ovsdb_type *);
bool ovsdb_datum_is_default(const struct ovsdb_datum *,
                            const struct ovsdb_type *);
const struct ovsdb_datum *ovsdb_datum_default(const struct ovsdb_type *);
void ovsdb_datum_clone(struct ovsdb_datum *, const struct ovsdb_datum *,
                       const struct ovsdb_type *);
void ovsdb_datum_destroy(struct ovsdb_datum *, const struct ovsdb_type *);
void ovsdb_datum_swap(struct ovsdb_datum *, struct ovsdb_datum *);

/* Checking and maintaining invariants. */
struct ovsdb_error *ovsdb_datum_sort(struct ovsdb_datum *,
                                     enum ovsdb_atomic_type key_type)
    OVS_WARN_UNUSED_RESULT;

void ovsdb_datum_sort_assert(struct ovsdb_datum *,
                             enum ovsdb_atomic_type key_type);

size_t ovsdb_datum_sort_unique(struct ovsdb_datum *,
                               enum ovsdb_atomic_type key_type,
                               enum ovsdb_atomic_type value_type);

struct ovsdb_error *ovsdb_datum_check_constraints(
    const struct ovsdb_datum *, const struct ovsdb_type *)
    OVS_WARN_UNUSED_RESULT;

/* Type conversion. */
struct ovsdb_error *ovsdb_datum_from_json(struct ovsdb_datum *,
                                          const struct ovsdb_type *,
                                          const struct json *,
                                          struct ovsdb_symbol_table *)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_transient_datum_from_json(
                                          struct ovsdb_datum *,
                                          const struct ovsdb_type *,
                                          const struct json *)
    OVS_WARN_UNUSED_RESULT;
struct json *ovsdb_datum_to_json(const struct ovsdb_datum *,
                                 const struct ovsdb_type *);

char *ovsdb_datum_from_string(struct ovsdb_datum *,
                              const struct ovsdb_type *, const char *,
                              struct ovsdb_symbol_table *)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_datum_to_string(const struct ovsdb_datum *,
                           const struct ovsdb_type *, struct ds *);
void ovsdb_datum_to_bare(const struct ovsdb_datum *,
                         const struct ovsdb_type *, struct ds *);

void ovsdb_datum_from_smap(struct ovsdb_datum *, const struct smap *);

/* Comparison. */
uint32_t ovsdb_datum_hash(const struct ovsdb_datum *,
                          const struct ovsdb_type *, uint32_t basis);
int ovsdb_datum_compare_3way(const struct ovsdb_datum *,
                             const struct ovsdb_datum *,
                             const struct ovsdb_type *);
bool ovsdb_datum_equals(const struct ovsdb_datum *,
                        const struct ovsdb_datum *,
                        const struct ovsdb_type *);

/* Search. */
unsigned int ovsdb_datum_find_key(const struct ovsdb_datum *,
                                  const union ovsdb_atom *key,
                                  enum ovsdb_atomic_type key_type);
unsigned int ovsdb_datum_find_key_value(const struct ovsdb_datum *,
                                        const union ovsdb_atom *key,
                                        enum ovsdb_atomic_type key_type,
                                        const union ovsdb_atom *value,
                                        enum ovsdb_atomic_type value_type);

/* Set operations. */
bool ovsdb_datum_includes_all(const struct ovsdb_datum *,
                              const struct ovsdb_datum *,
                              const struct ovsdb_type *);
bool ovsdb_datum_excludes_all(const struct ovsdb_datum *,
                              const struct ovsdb_datum *,
                              const struct ovsdb_type *);
void ovsdb_datum_union(struct ovsdb_datum *,
                       const struct ovsdb_datum *,
                       const struct ovsdb_type *,
                       bool replace);
void ovsdb_datum_subtract(struct ovsdb_datum *a,
                          const struct ovsdb_type *a_type,
                          const struct ovsdb_datum *b,
                          const struct ovsdb_type *b_type);

/* Generate and apply diffs */
void ovsdb_datum_diff(struct ovsdb_datum *diff,
                      const struct ovsdb_datum *old,
                      const struct ovsdb_datum *new,
                      const struct ovsdb_type *type);

struct ovsdb_error *ovsdb_datum_apply_diff(struct ovsdb_datum *new,
                                           const struct ovsdb_datum *old,
                                           const struct ovsdb_datum *diff,
                                           const struct ovsdb_type *type)
OVS_WARN_UNUSED_RESULT;

/* Raw operations that may not maintain the invariants. */
void ovsdb_datum_remove_unsafe(struct ovsdb_datum *, size_t idx,
                               const struct ovsdb_type *);
void ovsdb_datum_add_unsafe(struct ovsdb_datum *,
                            const union ovsdb_atom *key,
                            const union ovsdb_atom *value,
                            const struct ovsdb_type *,
                            const union ovsdb_atom *range_end_atom);

/* Type checking. */
static inline bool
ovsdb_datum_conforms_to_type(const struct ovsdb_datum *datum,
                             const struct ovsdb_type *type)
{
    return datum->n >= type->n_min && datum->n <= type->n_max;
}

/* A table mapping from names to data items.  Currently the data items are
 * always UUIDs; perhaps this will be expanded in the future. */

struct ovsdb_symbol_table {
    struct shash sh;            /* Maps from name to struct ovsdb_symbol *. */
};

struct ovsdb_symbol {
    struct uuid uuid;           /* The UUID that the symbol represents. */
    bool created;               /* Already used to create row? */
    bool strong_ref;            /* Parsed a strong reference to this row? */
    bool weak_ref;              /* Parsed a weak reference to this row? */
};

struct ovsdb_symbol_table *ovsdb_symbol_table_create(void);
void ovsdb_symbol_table_destroy(struct ovsdb_symbol_table *);
struct ovsdb_symbol *ovsdb_symbol_table_get(const struct ovsdb_symbol_table *,
                                            const char *name);
struct ovsdb_symbol *ovsdb_symbol_table_put(struct ovsdb_symbol_table *,
                                            const char *name,
                                            const struct uuid *, bool used);
struct ovsdb_symbol *ovsdb_symbol_table_insert(struct ovsdb_symbol_table *,
                                               const char *name);

/* Tokenization
 *
 * Used by ovsdb_atom_from_string() and ovsdb_datum_from_string(). */

char *ovsdb_token_parse(const char **, char **outp) OVS_WARN_UNUSED_RESULT;
bool ovsdb_token_is_delim(unsigned char);

struct ovsdb_error *ovsdb_atom_range_check_size(int64_t range_start,
                                                int64_t range_end);

#endif /* ovsdb-data.h */
