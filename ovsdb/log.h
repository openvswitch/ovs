/* Copyright (c) 2009, 2010, 2011, 2017 Nicira, Inc.
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

#ifndef OVSDB_LOG_H
#define OVSDB_LOG_H 1

/* OVSDB log.
 *
 * A log consists of a series of records.  After opening or creating a log with
 * ovsdb_log_open(), the client may use ovsdb_log_read() to read any existing
 * records, one by one.  The client may also use ovsdb_log_write() to write new
 * records (if some records have not yet been read at this point, then the
 * first write truncates them).
 *
 * Log writes are atomic.  A client may use ovsdb_log_commit() to ensure that
 * they are durable.
 *
 * Logs provide a mechansim to allow the client to tell when they have grown
 * enough that compacting may be warranted.  After reading existing log
 * contents, the client uses ovsdb_log_mark_base() to mark the "base" to be
 * considered as the initial size of the log.  Thereafter, a client may call
 * ovsdb_log_grew_lots() to get an indication whether the log has grown enough
 * that compacting is advised.
 */

#include <stdint.h>
#include <sys/types.h>
#include "compiler.h"

struct ds;
struct json;
struct ovsdb_log;

/* Access mode for opening an OVSDB log. */
enum ovsdb_log_open_mode {
    OVSDB_LOG_READ_ONLY,        /* Open existing file, read-only. */
    OVSDB_LOG_READ_WRITE,       /* Open existing file, read/write. */
    OVSDB_LOG_CREATE_EXCL,      /* Create new file, read/write. */
    OVSDB_LOG_CREATE            /* Create or open file, read/write. */
};

/* 'magic' for use with ovsdb_log_open() for OVSDB databases (see ovsdb(5)). */
#define OVSDB_MAGIC "JSON"

struct ovsdb_error *ovsdb_log_open(const char *name, const char *magic,
                                   enum ovsdb_log_open_mode,
                                   int locking, struct ovsdb_log **)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_log_close(struct ovsdb_log *);

const char *ovsdb_log_get_magic(const struct ovsdb_log *);

struct ovsdb_error *ovsdb_log_read(struct ovsdb_log *, struct json **)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_log_unread(struct ovsdb_log *);

void ovsdb_log_compose_record(const struct json *, const char *magic,
                              struct ds *header, struct ds *data);

struct ovsdb_error *ovsdb_log_write(struct ovsdb_log *, const struct json *)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_log_write_and_free(struct ovsdb_log *, struct json *)
    OVS_WARN_UNUSED_RESULT;

uint64_t ovsdb_log_commit_start(struct ovsdb_log *);
uint64_t ovsdb_log_commit_progress(struct ovsdb_log *);
void ovsdb_log_commit_wait(struct ovsdb_log *, uint64_t);
struct ovsdb_error *ovsdb_log_commit_block(struct ovsdb_log *)
    OVS_WARN_UNUSED_RESULT;

void ovsdb_log_mark_base(struct ovsdb_log *);
bool ovsdb_log_grew_lots(const struct ovsdb_log *);

struct ovsdb_error *ovsdb_log_replace(struct ovsdb_log *,
                                      struct json **entries, size_t n)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_log_replace_start(struct ovsdb_log *old,
                                            struct ovsdb_log **newp)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_log_replace_commit(struct ovsdb_log *old,
                                             struct ovsdb_log *new)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_log_replace_abort(struct ovsdb_log *new);

/* For testing. */
void ovsdb_log_disable_renaming_open_files(void);

#endif /* ovsdb/log.h */
