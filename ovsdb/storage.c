
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

#include <config.h>

#include "storage.h"
#include <string.h>
#include "log.h"
#include "ovsdb-error.h"
#include "openvswitch/json.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovsdb.h"
#include "raft.h"
#include "random.h"
#include "simap.h"
#include "timeval.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(storage);

struct ovsdb_storage {
    /* There are three kinds of storage:
     *
     *    - Standalone, backed by a disk file.  'log' is nonnull, 'raft' is
     *      null.
     *
     *    - Clustered, backed by a Raft cluster.  'log' is null, 'raft' is
     *      nonnull.
     *
     *    - Memory only, unbacked.  'log' and 'raft' are null. */
    struct ovsdb_log *log;
    struct raft *raft;

    /* All kinds of storage. */
    struct ovsdb_error *error;  /* If nonnull, a permanent error. */
    long long next_snapshot_min; /* Earliest time to take next snapshot. */
    long long next_snapshot_max; /* Latest time to take next snapshot. */

    /* Standalone only. */
    unsigned int n_read;
    unsigned int n_written;
};

static void schedule_next_snapshot(struct ovsdb_storage *, bool quick);

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_open__(const char *filename, bool rw, bool allow_clustered,
                     struct ovsdb_storage **storagep)
{
    *storagep = NULL;

    struct ovsdb_log *log;
    struct ovsdb_error *error;
    error = ovsdb_log_open(filename, OVSDB_MAGIC"|"RAFT_MAGIC,
                           rw ? OVSDB_LOG_READ_WRITE : OVSDB_LOG_READ_ONLY,
                           -1, &log);
    if (error) {
        return error;
    }

    struct raft *raft = NULL;
    if (!strcmp(ovsdb_log_get_magic(log), RAFT_MAGIC)) {
        if (!allow_clustered) {
            ovsdb_log_close(log);
            return ovsdb_error(NULL, "%s: cannot apply this operation to "
                               "clustered database file", filename);
        }
        error = raft_open(log, &raft);
        log = NULL;
        if (error) {
            return error;
        }
    }

    struct ovsdb_storage *storage = xzalloc(sizeof *storage);
    storage->log = log;
    storage->raft = raft;
    schedule_next_snapshot(storage, false);
    *storagep = storage;
    return NULL;
}

/* Opens 'filename' for use as storage.  If 'rw', opens it for read/write
 * access, otherwise read-only.  If successful, stores the new storage in
 * '*storagep' and returns NULL; on failure, stores NULL in '*storagep' and
 * returns the error.
 *
 * The returned storage might be clustered or standalone, depending on what the
 * disk file contains. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_open(const char *filename, bool rw,
                   struct ovsdb_storage **storagep)
{
    return ovsdb_storage_open__(filename, rw, true, storagep);
}

struct ovsdb_storage *
ovsdb_storage_open_standalone(const char *filename, bool rw)
{
    struct ovsdb_storage *storage;
    struct ovsdb_error *error = ovsdb_storage_open__(filename, rw, false,
                                                     &storage);
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string_free(error));
    }
    return storage;
}

/* Creates and returns new storage without any backing.  Nothing will be read
 * from the storage, and writes are discarded. */
struct ovsdb_storage *
ovsdb_storage_create_unbacked(void)
{
    struct ovsdb_storage *storage = xzalloc(sizeof *storage);
    schedule_next_snapshot(storage, false);
    return storage;
}

void
ovsdb_storage_close(struct ovsdb_storage *storage)
{
    if (storage) {
        ovsdb_log_close(storage->log);
        raft_close(storage->raft);
        ovsdb_error_destroy(storage->error);
        free(storage);
    }
}

const char *
ovsdb_storage_get_model(const struct ovsdb_storage *storage)
{
    return storage->raft ? "clustered" : "standalone";
}

bool
ovsdb_storage_is_clustered(const struct ovsdb_storage *storage)
{
    return storage->raft != NULL;
}

bool
ovsdb_storage_is_connected(const struct ovsdb_storage *storage)
{
    return !storage->raft || raft_is_connected(storage->raft);
}

bool
ovsdb_storage_is_dead(const struct ovsdb_storage *storage)
{
    return storage->raft && raft_left(storage->raft);
}

bool
ovsdb_storage_is_leader(const struct ovsdb_storage *storage)
{
    return !storage->raft || raft_is_leader(storage->raft);
}

const struct uuid *
ovsdb_storage_get_cid(const struct ovsdb_storage *storage)
{
    return storage->raft ? raft_get_cid(storage->raft) : NULL;
}

const struct uuid *
ovsdb_storage_get_sid(const struct ovsdb_storage *storage)
{
    return storage->raft ? raft_get_sid(storage->raft) : NULL;
}

uint64_t
ovsdb_storage_get_applied_index(const struct ovsdb_storage *storage)
{
    return storage->raft ? raft_get_applied_index(storage->raft) : 0;
}

void
ovsdb_storage_get_memory_usage(const struct ovsdb_storage *storage,
                               struct simap *usage)
{
    if (storage->raft) {
        raft_get_memory_usage(storage->raft, usage);
    }
}

char *
ovsdb_storage_get_error(const struct ovsdb_storage *storage)
{
    if (storage->error) {
        return ovsdb_error_to_string(storage->error);
    }

    return NULL;
}

void
ovsdb_storage_run(struct ovsdb_storage *storage)
{
    if (storage->raft) {
        raft_run(storage->raft);
    }
}

void
ovsdb_storage_wait(struct ovsdb_storage *storage)
{
    if (storage->raft) {
        raft_wait(storage->raft);
    }
}

/* Returns 'storage''s embedded name, if it has one, otherwise null.
 *
 * Only clustered storage has a built-in name.  */
const char *
ovsdb_storage_get_name(const struct ovsdb_storage *storage)
{
    return storage->raft ? raft_get_name(storage->raft) : NULL;
}

/* Attempts to read a log record from 'storage'.
 *
 * If successful, returns NULL and stores the transaction information in
 * '*schemap', '*txnp', and '*txnid'.  At least one of these will be nonnull.
 * The caller owns the data and must eventually free it (with json_destroy()).
 *
 * If 'storage' is not clustered, 'txnid' may be null.
 *
 * If a read error occurs, returns the error and stores NULL in '*jsonp'.
 *
 * If the read reaches end of file, returns NULL and stores NULL in
 * '*jsonp'. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_read(struct ovsdb_storage *storage,
                   struct ovsdb_schema **schemap,
                   struct json **txnp,
                   struct uuid *txnid)
{
    *schemap = NULL;
    *txnp = NULL;
    if (txnid) {
        *txnid = UUID_ZERO;
    }

    struct json *json;
    struct json *schema_json = NULL;
    struct json *txn_json = NULL;
    if (storage->raft) {
        bool is_snapshot;
        json = json_nullable_clone(
            raft_next_entry(storage->raft, txnid, &is_snapshot));
        if (!json) {
            return NULL;
        } else if (json->type != JSON_ARRAY || json->array.n != 2) {
            json_destroy(json);
            return ovsdb_error(NULL, "invalid commit format");
        }

        struct json **e = json->array.elems;
        schema_json = e[0]->type != JSON_NULL ? e[0] : NULL;
        txn_json = e[1]->type != JSON_NULL ? e[1] : NULL;
    } else if (storage->log) {
        struct ovsdb_error *error = ovsdb_log_read(storage->log, &json);
        if (error || !json) {
            return error;
        }

        unsigned int n = storage->n_read++;
        struct json **jsonp = !n ? &schema_json : &txn_json;
        *jsonp = json;
        if (n == 1) {
            ovsdb_log_mark_base(storage->log);
        }
    } else {
        /* Unbacked.  Nothing to do. */
        return NULL;
    }

    /* If we got this far then we must have at least a schema or a
     * transaction. */
    ovs_assert(schema_json || txn_json);

    if (schema_json) {
        struct ovsdb_schema *schema;
        struct ovsdb_error *error = ovsdb_schema_from_json(schema_json,
                                                           &schema);
        if (error) {
            json_destroy(json);
            return error;
        }

        const char *storage_name = ovsdb_storage_get_name(storage);
        const char *schema_name = schema->name;
        if (storage_name && strcmp(storage_name, schema_name)) {
            error = ovsdb_error(NULL, "name %s in header does not match "
                                "name %s in schema",
                                storage_name, schema_name);
            json_destroy(json);
            ovsdb_schema_destroy(schema);
            return error;
        }

        *schemap = schema;
    }

    if (txn_json) {
        *txnp = json_clone(txn_json);
    }

    json_destroy(json);
    return NULL;
}

/* Reads and returns the schema from standalone storage 'storage'.  Terminates
 * with an error on failure. */
struct ovsdb_schema *
ovsdb_storage_read_schema(struct ovsdb_storage *storage)
{
    ovs_assert(storage->log);

    struct json *txn_json;
    struct ovsdb_schema *schema;
    struct ovsdb_error *error = ovsdb_storage_read(storage, &schema,
                                                   &txn_json, NULL);
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string_free(error));
    }
    if (!schema && !txn_json) {
        ovs_fatal(0, "unexpected end of file reading schema");
    }
    ovs_assert(schema && !txn_json);

    return schema;
}

bool
ovsdb_storage_read_wait(struct ovsdb_storage *storage)
{
    return (storage->raft
            ? raft_has_next_entry(storage->raft)
            : false);
}

void
ovsdb_storage_unread(struct ovsdb_storage *storage)
{
    if (storage->error) {
        return;
    }

    if (storage->raft) {
        if (!storage->error) {
            storage->error = ovsdb_error(NULL, "inconsistent data");
        }
    } else if (storage->log) {
        ovsdb_log_unread(storage->log);
    }
}

struct ovsdb_write {
    struct ovsdb_error *error;
    struct raft_command *command;
};

/* Not suitable for writing transactions that change the schema. */
struct ovsdb_write * OVS_WARN_UNUSED_RESULT
ovsdb_storage_write(struct ovsdb_storage *storage, const struct json *data,
                    const struct uuid *prereq, struct uuid *resultp,
                    bool durable)
{
    struct ovsdb_write *w = xzalloc(sizeof *w);
    struct uuid result = UUID_ZERO;
    if (storage->error) {
        w->error = ovsdb_error_clone(storage->error);
    } else if (storage->raft) {
        struct json *txn_json = json_array_create_2(json_null_create(),
                                                    json_clone(data));
        w->command = raft_command_execute(storage->raft, txn_json,
                                          prereq, &result);
        json_destroy(txn_json);
    } else if (storage->log) {
        w->error = ovsdb_log_write(storage->log, data);
        if (!w->error) {
            storage->n_written++;
            if (durable) {
                w->error = ovsdb_log_commit_block(storage->log);
            }
        }
    } else {
        /* When 'error' and 'command' are both null, it indicates that the
         * command is complete.  This is fine since this unbacked storage drops
         * writes. */
    }
    if (resultp) {
        *resultp = result;
    }
    return w;
}

/* Not suitable for writing transactions that change the schema. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_write_block(struct ovsdb_storage *storage,
                          const struct json *data, const struct uuid *prereq,
                          struct uuid *resultp, bool durable)
{
    struct ovsdb_write *w = ovsdb_storage_write(storage, data,
                                                prereq, resultp, durable);
    while (!ovsdb_write_is_complete(w)) {
        if (storage->raft) {
            raft_run(storage->raft);
        }

        ovsdb_write_wait(w);
        if (storage->raft) {
            raft_wait(storage->raft);
        }
        poll_block();
    }

    struct ovsdb_error *error = ovsdb_error_clone(ovsdb_write_get_error(w));
    ovsdb_write_destroy(w);
    return error;
}

bool
ovsdb_write_is_complete(const struct ovsdb_write *w)
{
    return (w->error
            || !w->command
            || raft_command_get_status(w->command) != RAFT_CMD_INCOMPLETE);
}

const struct ovsdb_error *
ovsdb_write_get_error(const struct ovsdb_write *w_)
{
    struct ovsdb_write *w = CONST_CAST(struct ovsdb_write *, w_);
    ovs_assert(ovsdb_write_is_complete(w));

    if (w->command && !w->error) {
        enum raft_command_status status = raft_command_get_status(w->command);
        if (status != RAFT_CMD_SUCCESS) {
            w->error = ovsdb_error("cluster error", "%s",
                                   raft_command_status_to_string(status));
        }
    }

    return w->error;
}

uint64_t
ovsdb_write_get_commit_index(const struct ovsdb_write *w)
{
    ovs_assert(ovsdb_write_is_complete(w));
    return (w->command && !w->error
            ? raft_command_get_commit_index(w->command)
            : 0);
}

void
ovsdb_write_wait(const struct ovsdb_write *w)
{
    if (ovsdb_write_is_complete(w)) {
        poll_immediate_wake();
    }
}

void
ovsdb_write_destroy(struct ovsdb_write *w)
{
    if (w) {
        raft_command_unref(w->command);
        ovsdb_error_destroy(w->error);
        free(w);
    }
}

static void
schedule_next_snapshot(struct ovsdb_storage *storage, bool quick)
{
    if (storage->log || storage->raft) {
        unsigned int base = 10 * 60 * 1000;  /* 10 minutes */
        unsigned int range = 10 * 60 * 1000; /* 10 minutes */
        if (quick) {
            base /= 10;
            range /= 10;
        }

        long long int now = time_msec();
        storage->next_snapshot_min = now + base + random_range(range);
        storage->next_snapshot_max = now + 60LL * 60 * 24 * 1000; /* 1 day */
    } else {
        storage->next_snapshot_min = LLONG_MAX;
        storage->next_snapshot_max = LLONG_MAX;
    }
}

bool
ovsdb_storage_should_snapshot(const struct ovsdb_storage *storage)
{
    if (storage->raft || storage->log) {
        /* If we haven't reached the minimum snapshot time, don't snapshot. */
        long long int now = time_msec();
        if (now < storage->next_snapshot_min) {
            return false;
        }

        uint64_t log_len = (storage->raft
                            ? raft_get_log_length(storage->raft)
                            : storage->n_read + storage->n_written);
        bool snapshot_recommended = false;

        if (now < storage->next_snapshot_max) {
            /* Maximum snapshot time not yet reached.  Take a snapshot if there
             * have been at least 100 log entries and the log file size has
             * grown a lot. */
            bool grew_lots = (storage->raft
                              ? raft_grew_lots(storage->raft)
                              : ovsdb_log_grew_lots(storage->log));
            snapshot_recommended = (log_len >= 100 && grew_lots);
        } else {
            /* We have reached the maximum snapshot time.  Take a snapshot if
             * there have been any log entries at all. */
            snapshot_recommended = (log_len > 0);
        }

        if (!snapshot_recommended) {
            return false;
        }

        /* If we can't snapshot right now, don't. */
        if (storage->raft && !raft_may_snapshot(storage->raft)) {
            /* Notifying the storage that it needs to make a snapshot soon. */
            raft_notify_snapshot_recommended(storage->raft);
            return false;
        }

        return true;
    }

    return false;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_store_snapshot__(struct ovsdb_storage *storage,
                               const struct json *schema,
                               const struct json *data)
{
    if (storage->raft) {
        struct json *entries = json_array_create_empty();
        if (schema) {
            json_array_add(entries, json_clone(schema));
        }
        if (data) {
            json_array_add(entries, json_clone(data));
        }
        struct ovsdb_error *error = raft_store_snapshot(storage->raft,
                                                        entries);
        json_destroy(entries);
        return error;
    } else if (storage->log) {
        struct json *entries[2];
        size_t n = 0;
        if (schema) {
            entries[n++] = CONST_CAST(struct json *, schema);
        }
        if (data) {
            entries[n++] = CONST_CAST(struct json *, data);
        }
        return ovsdb_log_replace(storage->log, entries, n);
    } else {
        return NULL;
    }
}

/* 'schema' and 'data' should faithfully represent the current schema and data,
 * otherwise the two storing backing formats will yield divergent results.  Use
 * ovsdb_storage_write_schema_change() to change the schema. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_store_snapshot(struct ovsdb_storage *storage,
                             const struct json *schema,
                             const struct json *data)
{
    struct ovsdb_error *error = ovsdb_storage_store_snapshot__(storage,
                                                               schema, data);
    bool retry_quickly = error != NULL;
    schedule_next_snapshot(storage, retry_quickly);
    return error;
}

struct ovsdb_write * OVS_WARN_UNUSED_RESULT
ovsdb_storage_write_schema_change(struct ovsdb_storage *storage,
                                  const struct json *schema,
                                  const struct json *data,
                                  const struct uuid *prereq,
                                  struct uuid *resultp)
{
    struct ovsdb_write *w = xzalloc(sizeof *w);
    struct uuid result = UUID_ZERO;
    if (storage->error) {
        w->error = ovsdb_error_clone(storage->error);
    } else if (storage->raft) {
        struct json *txn_json = json_array_create_2(json_clone(schema),
                                                    json_clone(data));
        w->command = raft_command_execute(storage->raft, txn_json,
                                          prereq, &result);
        json_destroy(txn_json);
    } else if (storage->log) {
        w->error = ovsdb_storage_store_snapshot__(storage, schema, data);
    } else {
        /* When 'error' and 'command' are both null, it indicates that the
         * command is complete.  This is fine since this unbacked storage drops
         * writes. */
    }
    if (resultp) {
        *resultp = result;
    }
    return w;
}

const struct uuid *
ovsdb_storage_peek_last_eid(struct ovsdb_storage *storage)
{
    if (!storage->raft) {
        return NULL;
    }
    return raft_current_eid(storage->raft);
}
