/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2017 Nicira, Inc.
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

#ifndef OVSDB_OVSDB_H
#define OVSDB_OVSDB_H 1

#include "compiler.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/shash.h"
#include "openvswitch/uuid.h"
#include "ovs-thread.h"

struct json;
struct ovsdb_log;
struct ovsdb_session;
struct ovsdb_txn;
struct simap;

/* Database schema. */
struct ovsdb_schema {
    char *name;
    char *version;
    char *cksum;
    struct shash tables;        /* Contains "struct ovsdb_table_schema *"s. */
};

struct ovsdb_schema *ovsdb_schema_create(const char *name,
                                         const char *version,
                                         const char *cksum);
struct ovsdb_schema *ovsdb_schema_clone(const struct ovsdb_schema *);
void ovsdb_schema_destroy(struct ovsdb_schema *);

struct ovsdb_error *ovsdb_schema_from_file(const char *file_name,
                                           struct ovsdb_schema **)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_schema_from_json(const struct json *,
                                           struct ovsdb_schema **)
    OVS_WARN_UNUSED_RESULT;
struct json *ovsdb_schema_to_json(const struct ovsdb_schema *);

bool ovsdb_schema_equal(const struct ovsdb_schema *,
                        const struct ovsdb_schema *);

struct ovsdb_error *ovsdb_schema_check_for_ephemeral_columns(
    const struct ovsdb_schema *) OVS_WARN_UNUSED_RESULT;
void ovsdb_schema_persist_ephemeral_columns(struct ovsdb_schema *,
                                            const char *filename);

struct ovsdb_version {
    unsigned int x;
    unsigned int y;
    unsigned int z;
};
bool ovsdb_parse_version(const char *, struct ovsdb_version *);
bool ovsdb_is_valid_version(const char *);

/* Database. */
struct ovsdb_txn_history_node {
    struct ovs_list node; /* Element in struct ovsdb's txn_history list */
    struct ovsdb_txn *txn;
};

struct ovsdb_compaction_state {
    pthread_t thread;          /* Thread handle. */

    struct ovsdb *db;          /* Copy of a database data to compact. */

    struct json *data;         /* 'db' as a serialized json. */
    struct json *schema;       /* 'db' schema json. */
    uint64_t applied_index;    /* Last applied index reported by the storage
                                * at the moment of a database copy. */

    /* Completion signaling. */
    struct seq *done;
    uint64_t seqno;

    uint64_t init_time;        /* Time spent by the main thread preparing. */
    uint64_t thread_time;      /* Time spent for compaction by the thread. */
};

struct ovsdb {
    char *name;
    struct ovsdb_schema *schema;
    struct ovsdb_storage *storage; /* If nonnull, log for transactions. */
    struct uuid prereq;
    struct ovs_list monitors;   /* Contains "struct ovsdb_monitor"s. */
    struct shash tables;        /* Contains "struct ovsdb_table *"s. */

    /* Triggers. */
    struct ovs_list triggers;   /* Contains "struct ovsdb_trigger"s. */
    bool run_triggers;
    bool run_triggers_now;

    struct ovsdb_table *rbac_role;

    /* History trasanctions for incremental monitor transfer. */
    bool need_txn_history;     /* Need to maintain history of transactions. */
    unsigned int n_txn_history; /* Current number of history transactions. */
    unsigned int n_txn_history_atoms; /* Total number of atoms in history. */
    struct ovs_list txn_history; /* Contains "struct ovsdb_txn_history_node. */

    size_t n_atoms;  /* Total number of ovsdb atoms in the database. */

    /* Relay mode. */
    bool is_relay;  /* True, if database is in relay mode. */
    /* List that holds transactions waiting to be forwarded to the server. */
    struct ovs_list txn_forward_new;
    /* Hash map for transactions that are already sent and waits for reply. */
    struct hmap txn_forward_sent;

    /* Database compaction. */
    struct ovsdb_compaction_state *snap_state;
};

/* Total number of 'weak reference' objects in all databases
 * and transactions. */
extern size_t n_weak_refs;

struct ovsdb *ovsdb_create(struct ovsdb_schema *, struct ovsdb_storage *);
void ovsdb_destroy(struct ovsdb *);

void ovsdb_no_data_conversion_disable(void);
bool ovsdb_conversion_with_no_data_supported(const struct ovsdb *);

void ovsdb_get_memory_usage(const struct ovsdb *, struct simap *usage);

struct ovsdb_table *ovsdb_get_table(const struct ovsdb *, const char *);

struct ovsdb_txn *ovsdb_execute_compose(
    struct ovsdb *, const struct ovsdb_session *, const struct json *params,
    bool read_only, const char *role, const char *id,
    long long int elapsed_msec, long long int *timeout_msec,
    bool *durable, bool *forwarding_needed, struct json **);

struct json *ovsdb_execute(struct ovsdb *, const struct ovsdb_session *,
                           const struct json *params, bool read_only,
                           const char *role, const char *id,
                           long long int elapsed_msec,
                           long long int *timeout_msec);

struct ovsdb_error *ovsdb_snapshot(struct ovsdb *, bool trim_memory)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_snapshot_wait(struct ovsdb *);
bool ovsdb_snapshot_in_progress(struct ovsdb *);
bool ovsdb_snapshot_ready(struct ovsdb *);

void ovsdb_replace(struct ovsdb *dst, struct ovsdb *src);

#endif /* ovsdb/ovsdb.h */
