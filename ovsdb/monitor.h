/*
 * Copyright (c) 2015 Nicira, Inc.
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

#ifndef OVSDB_MONITOR_H
#define OVSDB_MONITOR_H

struct ovsdb_monitor;

enum ovsdb_monitor_selection {
    OJMS_INITIAL = 1 << 0,      /* All rows when monitor is created. */
    OJMS_INSERT = 1 << 1,       /* New rows. */
    OJMS_DELETE = 1 << 2,       /* Deleted rows. */
    OJMS_MODIFY = 1 << 3        /* Modified rows. */
};


struct ovsdb_monitor *ovsdb_monitor_create(struct ovsdb *db,
                       struct ovsdb_jsonrpc_monitor *jsonrpc_monitor);

struct ovsdb_monitor *ovsdb_monitor_add(struct ovsdb_monitor *dbmon);

void ovsdb_monitor_add_jsonrpc_monitor(struct ovsdb_monitor *dbmon,
                       struct ovsdb_jsonrpc_monitor *jsonrpc_monitor);

void ovsdb_monitor_remove_jsonrpc_monitor(struct ovsdb_monitor *dbmon,
                       struct ovsdb_jsonrpc_monitor *jsonrpc_monitor);

void ovsdb_monitor_remove_jsonrpc_monitor(struct ovsdb_monitor *dbmon,
                               struct ovsdb_jsonrpc_monitor *jsonrpc_monitor);

void ovsdb_monitor_add_table(struct ovsdb_monitor *m,
                             const struct ovsdb_table *table);

void ovsdb_monitor_add_column(struct ovsdb_monitor *dbmon,
                              const struct ovsdb_table *table,
                              const struct ovsdb_column *column,
                              enum ovsdb_monitor_selection select,
                              size_t *allocated_columns);

const char * OVS_WARN_UNUSED_RESULT
ovsdb_monitor_table_check_duplicates(struct ovsdb_monitor *,
                          const struct ovsdb_table *);

struct json *ovsdb_monitor_get_update(struct ovsdb_monitor *dbmon,
                                bool initial, uint64_t *unflushed_transaction);

void ovsdb_monitor_table_add_select(struct ovsdb_monitor *dbmon,
                                    const struct ovsdb_table *table,
                                    enum ovsdb_monitor_selection select);

bool ovsdb_monitor_needs_flush(struct ovsdb_monitor *dbmon,
                               uint64_t next_transaction);

void ovsdb_monitor_get_initial(const struct ovsdb_monitor *dbmon);
#endif
