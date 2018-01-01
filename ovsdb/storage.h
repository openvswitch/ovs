/* Copyright (c) 2009, 2010, 2011, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this storage except in compliance with the License.
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

#ifndef OVSDB_STORAGE_H
#define OVSDB_STORAGE_H 1

#include <stdint.h>
#include <sys/types.h>
#include "compiler.h"

struct json;
struct ovsdb_schema;
struct ovsdb_storage;
struct uuid;

struct ovsdb_error *ovsdb_storage_open(const char *filename, bool rw,
                                       struct ovsdb_storage **)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_storage *ovsdb_storage_create_unbacked(void);
void ovsdb_storage_close(struct ovsdb_storage *);

const char *ovsdb_storage_get_model(const struct ovsdb_storage *);
bool ovsdb_storage_is_clustered(const struct ovsdb_storage *);
bool ovsdb_storage_is_connected(const struct ovsdb_storage *);
bool ovsdb_storage_is_dead(const struct ovsdb_storage *);
bool ovsdb_storage_is_leader(const struct ovsdb_storage *);
const struct uuid *ovsdb_storage_get_cid(const struct ovsdb_storage *);
const struct uuid *ovsdb_storage_get_sid(const struct ovsdb_storage *);
uint64_t ovsdb_storage_get_applied_index(const struct ovsdb_storage *);

void ovsdb_storage_run(struct ovsdb_storage *);
void ovsdb_storage_wait(struct ovsdb_storage *);

const char *ovsdb_storage_get_name(const struct ovsdb_storage *);

struct ovsdb_error *ovsdb_storage_read(struct ovsdb_storage *,
                                       struct ovsdb_schema **schemap,
                                       struct json **txnp,
                                       struct uuid *txnid)
    OVS_WARN_UNUSED_RESULT;
bool ovsdb_storage_read_wait(struct ovsdb_storage *);

void ovsdb_storage_unread(struct ovsdb_storage *);

struct ovsdb_write *ovsdb_storage_write(struct ovsdb_storage *,
                                        const struct json *,
                                        const struct uuid *prereq,
                                        struct uuid *result,
                                        bool durable)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_storage_write_block(struct ovsdb_storage *,
                                              const struct json *,
                                              const struct uuid *prereq,
                                              struct uuid *result,
                                              bool durable);

bool ovsdb_write_is_complete(const struct ovsdb_write *);
const struct ovsdb_error *ovsdb_write_get_error(const struct ovsdb_write *);
uint64_t ovsdb_write_get_commit_index(const struct ovsdb_write *);
void ovsdb_write_wait(const struct ovsdb_write *);
void ovsdb_write_destroy(struct ovsdb_write *);

bool ovsdb_storage_should_snapshot(const struct ovsdb_storage *);
struct ovsdb_error *ovsdb_storage_store_snapshot(struct ovsdb_storage *storage,
                                                 const struct json *schema,
                                                 const struct json *snapshot)
    OVS_WARN_UNUSED_RESULT;

struct ovsdb_write *ovsdb_storage_write_schema_change(
    struct ovsdb_storage *,
    const struct json *schema, const struct json *data,
    const struct uuid *prereq, struct uuid *result)
    OVS_WARN_UNUSED_RESULT;

/* Convenience functions for ovsdb-tool and other command-line utilities,
 * for use with standalone database files only, which terminate the process
 * on error. */
struct ovsdb_storage *ovsdb_storage_open_standalone(const char *filename,
                                                    bool rw);
struct ovsdb_schema *ovsdb_storage_read_schema(struct ovsdb_storage *);

#endif /* ovsdb/storage.h */
