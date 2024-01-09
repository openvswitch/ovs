/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 * Copyright (c) 2009, 2010, 2012, 2013 Nicira, Inc.
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

#ifndef REPLICATION_H
#define REPLICATION_H 1

#include <stdbool.h>
struct ovsdb;
struct jsonrpc_session_options;

/* Replication module runs when OVSDB server runs in the backup mode.
 *
 * API Usage
 *===========
 *
 * - replication_set_db() needs to be called whenever database switches into
 *   the backup mode.
 *
 * - replication_remove_db() needs to be called whenever backup database
 *   switches into an active mode.
 *
 * - replication_destroy() should be called when OVSDB server shutdown to
 *   reclaim resources.
 *
 * - replication_run(), replication_wait(), replication_is_alive() and
 *   replication_get_last_error() should be call within the main loop
 *   whenever OVSDB has backup databases.
 *
 * - parse_excluded_tables(), get_excluded_tables() and replication_usage()
 *   are support functions used mainly by unixctl commands.
 */

#define REPLICATION_DEFAULT_PROBE_INTERVAL 60000

void replication_set_db(struct ovsdb *, const char *sync_from,
                        const char *exclude_tables, const struct uuid *server,
                        const struct jsonrpc_session_options *);
void replication_remove_db(const struct ovsdb *);

void replication_run(void);
void replication_wait(void);
void replication_destroy(void);
void replication_usage(void);
bool replication_is_alive(const struct ovsdb *);
int replication_get_last_error(const struct ovsdb *);
char *replication_status(const struct ovsdb *);
void replication_set_probe_interval(const struct ovsdb *, int probe_interval);

char *parse_excluded_tables(const char *excluded) OVS_WARN_UNUSED_RESULT;
char *get_excluded_tables(const struct ovsdb *) OVS_WARN_UNUSED_RESULT;

#endif /* ovsdb/replication.h */
