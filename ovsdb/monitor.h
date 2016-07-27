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
struct ovsdb_jsonrpc_monitor;
struct ovsdb_monitor_session_condition;
struct ovsdb_condition;

enum ovsdb_monitor_selection {
    OJMS_NONE = 0,              /* None for this iteration */
    OJMS_INITIAL = 1 << 0,      /* All rows when monitor is created. */
    OJMS_INSERT = 1 << 1,       /* New rows. */
    OJMS_DELETE = 1 << 2,       /* Deleted rows. */
    OJMS_MODIFY = 1 << 3        /* Modified rows. */
};


enum ovsdb_monitor_version {
      OVSDB_MONITOR_V1,         /* RFC 7047 "monitor" method. */
      OVSDB_MONITOR_V2,         /* Extension to RFC 7047, see ovsdb-server
                                   man page for details. */

      /* Last entry.  */
      OVSDB_MONITOR_VERSION_MAX
};

struct ovsdb_monitor *ovsdb_monitor_create(struct ovsdb *db,
                       struct ovsdb_jsonrpc_monitor *jsonrpc_monitor);

struct ovsdb_monitor *ovsdb_monitor_add(struct ovsdb_monitor *dbmon);

void ovsdb_monitor_add_jsonrpc_monitor(struct ovsdb_monitor *dbmon,
                       struct ovsdb_jsonrpc_monitor *jsonrpc_monitor);

void ovsdb_monitor_remove_jsonrpc_monitor(struct ovsdb_monitor *dbmon,
                               struct ovsdb_jsonrpc_monitor *jsonrpc_monitor,
                               uint64_t unflushed);

void ovsdb_monitor_add_table(struct ovsdb_monitor *m,
                             const struct ovsdb_table *table);

const char * ovsdb_monitor_add_column(struct ovsdb_monitor *dbmon,
                                      const struct ovsdb_table *table,
                                      const struct ovsdb_column *column,
                                      enum ovsdb_monitor_selection select,
                                      bool monitored);
bool
ovsdb_monitor_table_exists(struct ovsdb_monitor *m,
                           const struct ovsdb_table *table);

struct json *ovsdb_monitor_get_update(struct ovsdb_monitor *dbmon,
                                      bool initial,
                                      bool cond_updated,
                                      uint64_t *unflushed_transaction,
                                      struct ovsdb_monitor_session_condition *condition,
                                      enum ovsdb_monitor_version version);

void ovsdb_monitor_table_add_select(struct ovsdb_monitor *dbmon,
                                    const struct ovsdb_table *table,
                                    enum ovsdb_monitor_selection select);

bool ovsdb_monitor_needs_flush(struct ovsdb_monitor *dbmon,
                               uint64_t next_transaction);

void ovsdb_monitor_get_initial(const struct ovsdb_monitor *dbmon);

void ovsdb_monitor_get_memory_usage(struct simap *usage);

struct ovsdb_monitor_session_condition *
ovsdb_monitor_session_condition_create(void);

void
ovsdb_monitor_session_condition_destroy(
                          struct ovsdb_monitor_session_condition *condition);
struct ovsdb_error *
ovsdb_monitor_table_condition_create(
                          struct ovsdb_monitor_session_condition *condition,
                          const struct ovsdb_table *table,
                          const struct json *json_cnd);

void
ovsdb_monitor_condition_bind(struct ovsdb_monitor *dbmon,
                             struct ovsdb_monitor_session_condition *cond);

struct ovsdb_error *
ovsdb_monitor_table_condition_update(
                           struct ovsdb_monitor *dbmon,
                           struct ovsdb_monitor_session_condition *condition,
                           const struct ovsdb_table *table,
                           const struct json *cond_json);

#endif
