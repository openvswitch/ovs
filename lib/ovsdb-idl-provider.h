/* Copyright (c) 2009, 2010, 2011, 2012, 2016 Nicira, Inc.
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "ovsdb-idl.h"
#include "ovsdb-map-op.h"
#include "ovsdb-set-op.h"
#include "ovsdb-types.h"
#include "openvswitch/shash.h"
#include "uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A local copy of a row in an OVSDB table, replicated from an OVSDB server.
 * This structure is used as a header for a larger structure that translates
 * the "struct ovsdb_datum"s into easier-to-use forms, via the ->parse() and
 * ->unparse functions in struct ovsdb_idl_column.  (Those functions are
 * generated automatically via ovsdb-idlc.)
 *
 * When no transaction is in progress:
 *
 *     - 'old_datum' points to the data committed to the database and currently
 *       in the row.
 *
 *     - 'new_datum == old_datum'.
 *
 * When a transaction is in progress, the situation is a little different.  For
 * a row inserted in the transaction, 'old_datum' is NULL and 'new_datum'
 * points to the row's initial contents.  Otherwise:
 *
 *     - 'old_datum' points to the data committed to the database and currently
 *       in the row.  (This is the same as when no transaction is in progress.)
 *
 *     - If the transaction does not modify the row, 'new_datum == old_datum'.
 *
 *     - If the transaction modifies the row, 'new_datum' points to the
 *       modified data.
 *
 *     - If the transaction deletes the row, 'new_datum' is NULL.
 *
 * Thus:
 *
 *     - 'old_datum' always points to committed data, except that it is NULL if
 *       the row is inserted within the current transaction.
 *
 *     - 'new_datum' always points to the newest, possibly uncommitted version
 *       of the row's data, except that it is NULL if the row is deleted within
 *       the current transaction.
 */
struct ovsdb_idl_row {
    struct hmap_node hmap_node; /* In struct ovsdb_idl_table's 'rows'. */
    struct uuid uuid;           /* Row "_uuid" field. */
    struct ovs_list src_arcs;   /* Forward arcs (ovsdb_idl_arc.src_node). */
    struct ovs_list dst_arcs;   /* Backward arcs (ovsdb_idl_arc.dst_node). */
    struct ovsdb_idl_table *table; /* Containing table. */
    struct ovsdb_datum *old_datum; /* Committed data (null if orphaned). */

    /* Transactional data. */
    struct ovsdb_datum *new_datum; /* Modified data (null to delete row). */
    unsigned long int *prereqs; /* Bitmap of "old_datum" columns to verify. */
    unsigned long int *written; /* Bitmap of "new_datum" columns to write. */
    struct hmap_node txn_node;  /* Node in ovsdb_idl_txn's list. */
    unsigned long int *map_op_written; /* Bitmap of columns pending map ops. */
    struct map_op_list **map_op_lists; /* Per-column map operations. */
    unsigned long int *set_op_written; /* Bitmap of columns pending set ops. */
    struct set_op_list **set_op_lists; /* Per-column set operations. */

    /* Tracking data */
    unsigned int change_seqno[OVSDB_IDL_CHANGE_MAX];
    struct ovs_list track_node; /* Rows modified/added/deleted by IDL */
    unsigned long int *updated; /* Bitmap of columns updated by IDL */
};

struct ovsdb_idl_column {
    char *name;
    struct ovsdb_type type;
    bool is_mutable;
    bool is_synthetic;
    void (*parse)(struct ovsdb_idl_row *, const struct ovsdb_datum *);
    void (*unparse)(struct ovsdb_idl_row *);
};

struct ovsdb_idl_table_class {
    char *name;
    bool is_root;
    bool is_singleton;
    const struct ovsdb_idl_column *columns;
    size_t n_columns;
    size_t allocation_size;
    void (*row_init)(struct ovsdb_idl_row *);
};

struct ovsdb_idl_table {
    const struct ovsdb_idl_table_class *class_;
    unsigned char *modes;    /* OVSDB_IDL_* bitmasks, indexed by column. */
    bool need_table;         /* Monitor table even if no columns are selected
                              * for replication. */
    struct shash columns;    /* Contains "const struct ovsdb_idl_column *"s. */
    struct hmap rows;        /* Contains "struct ovsdb_idl_row"s. */
    struct ovsdb_idl *idl;   /* Containing idl. */
    unsigned int change_seqno[OVSDB_IDL_CHANGE_MAX];
    struct shash indexes;    /* Contains "struct ovsdb_idl_index"s */
    struct ovs_list track_list; /* Tracked rows (ovsdb_idl_row.track_node). */
    struct ovsdb_idl_condition condition;
    bool cond_changed;
};

struct ovsdb_idl_class {
    const char *database;       /* <db-name> for this database. */
    const struct ovsdb_idl_table_class *tables;
    size_t n_tables;
};

/*
 * Structure containing the per-column configuration of the index.
 */
struct ovsdb_idl_index_column {
    const struct ovsdb_idl_column *column; /* Column used for index key. */
    column_comparator *comparer; /* Column comparison function. */
    int sorting_order; /* Sorting order (ascending or descending). */
};

/*
 * Defines a IDL compound index
 */
struct ovsdb_idl_index {
    struct skiplist *skiplist;    /* Skiplist with pointers to rows. */
    struct ovsdb_idl_index_column *columns; /* Columns configuration */
    size_t n_columns;             /* Number of columns in index. */
    size_t alloc_columns;         /* Size allocated memory for columns,
                                     comparers and sorting order. */
    bool ins_del;                 /* True if a row in the index is being
                                     inserted or deleted; if true, the
                                     search key is augmented with the
                                     UUID and address in order to discriminate
                                     between entries with identical keys. */
    const struct ovsdb_idl_table *table; /* Table that owns this index */
    const char *index_name;       /* The name of this index. */
};

struct ovsdb_idl_row *ovsdb_idl_get_row_arc(
    struct ovsdb_idl_row *src,
    const struct ovsdb_idl_table_class *dst_table,
    const struct uuid *dst_uuid);

void ovsdb_idl_txn_verify(const struct ovsdb_idl_row *,
                          const struct ovsdb_idl_column *);

struct ovsdb_idl_txn *ovsdb_idl_txn_get(const struct ovsdb_idl_row *);

#ifdef __cplusplus
}
#endif

#endif /* ovsdb-idl-provider.h */
