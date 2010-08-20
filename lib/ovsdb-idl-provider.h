/* Copyright (c) 2009, 2010 Nicira Networks.
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
    struct ovsdb_datum *old;    /* Committed data (null if orphaned). */

    /* Transactional data. */
    struct ovsdb_datum *new;    /* Modified data (null to delete row). */
    unsigned long int *prereqs; /* Bitmap of columns to verify in "old". */
    unsigned long int *written; /* Bitmap of columns from "new" to write. */
    struct hmap_node txn_node;  /* Node in ovsdb_idl_txn's list. */
};

struct ovsdb_idl_column {
    char *name;
    struct ovsdb_type type;
    void (*parse)(struct ovsdb_idl_row *, const struct ovsdb_datum *);
    void (*unparse)(struct ovsdb_idl_row *);
};

struct ovsdb_idl_table_class {
    char *name;
    const struct ovsdb_idl_column *columns;
    size_t n_columns;
    size_t allocation_size;
};

enum ovsdb_idl_mode {
    /* Client reads and may write this column and wants to be alerted upon
     * updates to it.
     *
     * This is the default. */
    OVSDB_IDL_MODE_RW,

    /* Client may read and write this column, but doesn't care to be alerted
     * when it is updated.
     *
     * This is useful for columns that a client treats as "write-only", that
     * is, it updates them but doesn't want to get alerted about its own
     * updates.  It also won't be alerted about other clients' updates, so this
     * is suitable only for use by a client that "owns" a particular column. */
    OVSDB_IDL_MODE_WO,

    /* Client won't read or write this column at all.  The IDL code can't
     * prevent reading the column, but writing will cause assertion
     * failures. */
    OVSDB_IDL_MODE_NONE
};

struct ovsdb_idl_table {
    const struct ovsdb_idl_table_class *class;
    unsigned char *modes;    /* One of OVSDB_MODE_*, indexed by column. */
    struct shash columns;    /* Contains "const struct ovsdb_idl_column *"s. */
    struct hmap rows;        /* Contains "struct ovsdb_idl_row"s. */
    struct ovsdb_idl *idl;   /* Containing idl. */
};

struct ovsdb_idl_class {
    const char *database;       /* <db-name> for this database. */
    const struct ovsdb_idl_table_class *tables;
    size_t n_tables;
};

struct ovsdb_idl_row *ovsdb_idl_get_row_arc(
    struct ovsdb_idl_row *src,
    struct ovsdb_idl_table_class *dst_table,
    const struct uuid *dst_uuid);

void ovsdb_idl_txn_verify(const struct ovsdb_idl_row *,
                          const struct ovsdb_idl_column *);

struct ovsdb_idl_txn *ovsdb_idl_txn_get(const struct ovsdb_idl_row *);

#endif /* ovsdb-idl-provider.h */
