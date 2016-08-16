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
#include "openvswitch/shash.h"

struct db {
    /* Initialized in main(). */
    char *filename;
    struct ovsdb_file *file;
    struct ovsdb *db;

    /* Only used by update_remote_status(). */
    struct ovsdb_txn *txn;
};

/* Functions to be called from the main loop. */
void replication_init(void);
void replication_run(struct shash *dbs);
void replication_wait(void);
void replication_destroy(void);
void replication_usage(void);

/* Unixctl APIs */
void set_active_ovsdb_server(const char *remote_server);
const char *get_active_ovsdb_server(void);
char *set_blacklist_tables(const char *blacklist, bool dryrun)
    OVS_WARN_UNUSED_RESULT;
char *get_blacklist_tables(void) OVS_WARN_UNUSED_RESULT;
void disconnect_active_server(void);
const struct db *find_db(const struct shash *all_dbs, const char *db_name);

#endif /* ovsdb/replication.h */
