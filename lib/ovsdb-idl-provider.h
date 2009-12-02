/* Copyright (c) 2009 Nicira Networks.
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

#ifndef OVSDB_IDL_PROVIDER_H
#define OVSDB_IDL_PROVIDER_H 1

#include "hmap.h"
#include "list.h"
#include "ovsdb-idl.h"
#include "ovsdb-types.h"
#include "shash.h"
#include "uuid.h"

struct ovsdb_idl_row {
    struct hmap_node hmap_node; /* In struct ovsdb_idl_table's 'rows'. */
    struct uuid uuid;           /* Row "_uuid" field. */
    struct list src_arcs;       /* Forward arcs (ovsdb_idl_arc.src_node). */
    struct list dst_arcs;       /* Backward arcs (ovsdb_idl_arc.dst_node). */
    struct ovsdb_idl_table *table; /* Containing table. */
    struct ovsdb_datum *fields;    /* Row data, or null if orphaned. */
};

struct ovsdb_idl_column {
    char *name;
    struct ovsdb_type type;
};

struct ovsdb_idl_table_class {
    char *name;
    const struct ovsdb_idl_column *columns;
    size_t n_columns;
    size_t allocation_size;
    void (*parse)(struct ovsdb_idl_row *);
    void (*unparse)(struct ovsdb_idl_row *);
};

struct ovsdb_idl_table {
    const struct ovsdb_idl_table_class *class;
    struct shash columns;    /* Contains "const struct ovsdb_idl_column *"s. */
    struct hmap rows;        /* Contains "struct ovsdb_idl_row"s. */
    struct ovsdb_idl *idl;   /* Containing idl. */
};

struct ovsdb_idl_class {
    const struct ovsdb_idl_table_class *tables;
    size_t n_tables;
};

struct ovsdb_idl_row *ovsdb_idl_get_row_arc(
    struct ovsdb_idl_row *src,
    struct ovsdb_idl_table_class *dst_table,
    const struct uuid *dst_uuid);

struct ovsdb_idl_row *ovsdb_idl_first_row(
    const struct ovsdb_idl *, const struct ovsdb_idl_table_class *);

struct ovsdb_idl_row *ovsdb_idl_next_row(const struct ovsdb_idl_row *);

#endif /* ovsdb-idl-provider.h */
