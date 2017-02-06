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

/* Replication module runs when OVSDB server runs in the backup mode.
 *
 * API Usage
 *===========
 *
 * - replication_init() needs to be called whenever OVSDB server switches into
 *   the backup mode.
 *
 * - replication_add_local_db() should be called immediately after to add all
 *   known database that OVSDB server owns, one at a time.
 *
 * - replication_destroy() should be called when OVSDB server shutdown to
 *   reclaim resources.
 *
 * - replication_run(), replication_wait(), replication_is_alive() and
 *   replication_get_last_error() should be call within the main loop
 *   whenever OVSDB server runs in the backup mode.
 *
 *  - set_blacklist_tables(), get_blacklist_tables(),
 *    disconnect_active_server() and replication_usage() are support functions
 *    used mainly by uinxctl commands.
 */

void replication_init(const char *sync_from, const char *exclude_tables,
                      const struct uuid *server);
void replication_run(void);
void replication_wait(void);
void replication_destroy(void);
void replication_usage(void);
void replication_add_local_db(const char *databse, struct ovsdb *db);
bool replication_is_alive(void);
int replication_get_last_error(void);
char *replication_status(void);

char *set_blacklist_tables(const char *blacklist, bool dryrun)
    OVS_WARN_UNUSED_RESULT;
char *get_blacklist_tables(void) OVS_WARN_UNUSED_RESULT;
void disconnect_active_server(void);

#endif /* ovsdb/replication.h */
