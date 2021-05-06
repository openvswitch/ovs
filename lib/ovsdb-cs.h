/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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

#ifndef OVSDB_CS_H
#define OVSDB_CS_H 1

/* Open vSwitch Database client synchronization layer.
 *
 * This is a base layer for maintaining an in-memory replica of a database.  It
 * issues RPC requests to an OVSDB database server and passes the semantically
 * meaningful parts of the stream up to a higher layer.  The OVSDB IDL uses
 * this as a base layer, as well as OVN's DDlog-based northd implementation.
 */

#include <stdbool.h>
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/shash.h"
#include "openvswitch/uuid.h"

struct json;
struct ovsdb_cs;

struct ovsdb_cs_ops {
    /* Returns <monitor-requests> to use for the specified <schema>.  The
     * implementation might find ovsdb_cs_parse_table_updates() to be a useful
     * helper.
     *
     * The caller might actually use "monitor_cond" or "monitor_cond_since",
     * rather than plain "monitor".  If so, this function's implementation
     * doesn't need to worry about that, because the caller will add the
     * conditions itself. */
    struct json *(*compose_monitor_requests)(const struct json *schema,
                                             void *aux);
};

/* An event is a happening that is worth reporting to the CS client.
 *
 * Currently there are three kinds of events:
 *
 *    - "Reconnect": The connection to the database was lost and it is now
 *      being reconnected.  This means that any transactions submitted by the
 *      client will never receive a reply (although it's possible that some of
 *      them were actually committed).  This event has no associated data.
 *
 *    - "Locked": The server granted the lock we requested.
 *
 *    - "Update": The server sent an update to one or more monitored tables.
 *      The client can use the associated data to update its idea of the
 *      snapshot.
 *
 *    - "Transaction reply": The server sent a reply to a transaction sent by
 *      the client using ovsdb_cs_send_transaction().
 */
struct ovsdb_cs_event {
    struct ovs_list list_node;

    enum ovsdb_cs_event_type {
        OVSDB_CS_EVENT_TYPE_RECONNECT,   /* Connection lost. */
        OVSDB_CS_EVENT_TYPE_LOCKED,      /* Got the lock we wanted. */
        OVSDB_CS_EVENT_TYPE_UPDATE,      /* Received update notification. */
        OVSDB_CS_EVENT_TYPE_TXN_REPLY,   /* Received reply to transaction. */
    } type;

    union {
        /* Represents a <table-updates> or <table-updates2> that contains
         * either the initial data in a monitor reply or a delta received in an
         * update notification.  The client can use this to update its database
         * replica.
         *
         * If 'clear' is true, then the client should first clear its idea of
         * what's in the replica before applying the update; otherwise, it's an
         * incremental update.
         *
         * If 'monitor_reply' is true, then this comes from a monitor reply.
         * This doesn't have real semantic meaning, but it allows the caller
         * to imitate the exact behavior of previous versions of code that
         * behaved differently on updates from monitor replies vs. updates.
         *
         * 'table-updates' is a <table-updates> if 'version' if 1, otherwise a
         * <table-updates2>.  The client can use ovsdb_cs_parse_table_updates()
         * to parse the update.
         */
        struct ovsdb_cs_update_event {
            bool clear;
            bool monitor_reply;
            struct json *table_updates;
            int version;
        } update;

        /* The "result" member from a transaction reply.  The transaction is
         * one sent by the client using ovsdb_cs_send_transaction().  The
         * client can match 'txn_reply->id' against the ID in a transaction it
         * sent.  */
        struct jsonrpc_msg *txn_reply;
    };
};
void ovsdb_cs_event_destroy(struct ovsdb_cs_event *);

/* Lifecycle. */
struct ovsdb_cs *ovsdb_cs_create(const char *database, int max_version,
                                 const struct ovsdb_cs_ops *ops,
                                 void *ops_aux);
void ovsdb_cs_destroy(struct ovsdb_cs *);

void ovsdb_cs_run(struct ovsdb_cs *, struct ovs_list *events);
void ovsdb_cs_wait(struct ovsdb_cs *);

/* Network connection. */
void ovsdb_cs_set_remote(struct ovsdb_cs *, const char *remote, bool retry);

void ovsdb_cs_enable_reconnect(struct ovsdb_cs *);
void ovsdb_cs_force_reconnect(struct ovsdb_cs *);
void ovsdb_cs_flag_inconsistency(struct ovsdb_cs *);

bool ovsdb_cs_is_alive(const struct ovsdb_cs *);
bool ovsdb_cs_is_connected(const struct ovsdb_cs *);
int ovsdb_cs_get_last_error(const struct ovsdb_cs *);

void ovsdb_cs_set_probe_interval(const struct ovsdb_cs *, int probe_interval);

/* Conditional monitoring (specifying that only rows matching particular
 * criteria should be monitored).
 *
 * Some database servers don't support conditional monitoring; in that case,
 * the client will get all the rows. */
unsigned int ovsdb_cs_set_condition(struct ovsdb_cs *, const char *table,
                                    const struct json *condition);
unsigned int ovsdb_cs_get_condition_seqno(const struct ovsdb_cs *);

/* Clustered servers. */
void ovsdb_cs_set_leader_only(struct ovsdb_cs *, bool leader_only);
void ovsdb_cs_set_shuffle_remotes(struct ovsdb_cs *, bool shuffle);
void ovsdb_cs_reset_min_index(struct ovsdb_cs *);

/* Database locks. */
void ovsdb_cs_set_lock(struct ovsdb_cs *, const char *lock_name);
const char *ovsdb_cs_get_lock(const struct ovsdb_cs *);
bool ovsdb_cs_has_lock(const struct ovsdb_cs *);
bool ovsdb_cs_is_lock_contended(const struct ovsdb_cs *);

/* Transactions. */
bool ovsdb_cs_may_send_transaction(const struct ovsdb_cs *);
struct json *ovsdb_cs_send_transaction(struct ovsdb_cs *, struct json *ops)
    OVS_WARN_UNUSED_RESULT;
bool ovsdb_cs_forget_transaction(struct ovsdb_cs *, const struct json *);

/* Helper for partially parsing the <table-updates> or <table-updates2> that
 * appear in struct ovsdb_cs_update_event.  The helper leaves the data in JSON
 * format, so it doesn't need to know column types. */

/* The kind of change to a row. */
enum ovsdb_cs_row_update_type {
    OVSDB_CS_ROW_DELETE,        /* Row deletion. */
    OVSDB_CS_ROW_INSERT,        /* Row insertion. */
    OVSDB_CS_ROW_UPDATE,        /* Replacement of data within a row. */
    OVSDB_CS_ROW_XOR            /* <table-updates2> diff application. */
};

/* Partially parsed <row-update> or <row-update2>. */
struct ovsdb_cs_row_update {
    struct uuid row_uuid;       /* Row's _uuid. */
    enum ovsdb_cs_row_update_type type; /* Type of change. */
    const struct shash *columns; /* Map from column name to json data. */
};

/* Partially parsed <table-update> or <table-update2>. */
struct ovsdb_cs_table_update {
    const char *table_name;
    struct ovsdb_cs_row_update *row_updates;
    size_t n;
};

struct ovsdb_cs_db_update {
    struct ovsdb_cs_table_update *table_updates;
    size_t n;
};

struct ovsdb_error *ovsdb_cs_parse_db_update(
    const struct json *table_updates, int version,
    struct ovsdb_cs_db_update **db_updatep)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_cs_db_update_destroy(struct ovsdb_cs_db_update *);
const struct ovsdb_cs_table_update *ovsdb_cs_db_update_find_table(
    const struct ovsdb_cs_db_update *, const char *table_name);

/* Simple parsing of OVSDB schemas for use by ovsdb_cs clients.  */

struct shash *ovsdb_cs_parse_schema(const struct json *schema_json);
void ovsdb_cs_free_schema(struct shash *schema);

#endif /* ovsdb-cs.h */
