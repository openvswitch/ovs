/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
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

#include <config.h>

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include "column.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "file.h"
#include "hash.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "jsonrpc-server.h"
#include "openvswitch/list.h"
#include "memory.h"
#include "monitor.h"
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-types.h"
#include "ovsdb-error.h"
#include "openvswitch/poll-loop.h"
#include "process.h"
#include "replication.h"
#include "row.h"
#include "simap.h"
#include "openvswitch/shash.h"
#include "stream-ssl.h"
#include "stream.h"
#include "sset.h"
#include "storage.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "trigger.h"
#include "util.h"
#include "unixctl.h"
#include "perf-counter.h"
#include "ovsdb-util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_server);

struct db {
    char *filename;
    struct ovsdb *db;
    struct uuid row_uuid;
};

/* SSL configuration. */
static char *private_key_file;
static char *certificate_file;
static char *ca_cert_file;
static char *ssl_protocols;
static char *ssl_ciphers;
static bool bootstrap_ca_cert;

static unixctl_cb_func ovsdb_server_exit;
static unixctl_cb_func ovsdb_server_compact;
static unixctl_cb_func ovsdb_server_reconnect;
static unixctl_cb_func ovsdb_server_perf_counters_clear;
static unixctl_cb_func ovsdb_server_perf_counters_show;
static unixctl_cb_func ovsdb_server_disable_monitor_cond;
static unixctl_cb_func ovsdb_server_set_active_ovsdb_server;
static unixctl_cb_func ovsdb_server_get_active_ovsdb_server;
static unixctl_cb_func ovsdb_server_connect_active_ovsdb_server;
static unixctl_cb_func ovsdb_server_disconnect_active_ovsdb_server;
static unixctl_cb_func ovsdb_server_set_sync_exclude_tables;
static unixctl_cb_func ovsdb_server_get_sync_exclude_tables;
static unixctl_cb_func ovsdb_server_get_sync_status;

struct server_config {
    struct sset *remotes;
    struct shash *all_dbs;
    FILE *config_tmpfile;
    char **sync_from;
    char **sync_exclude;
    bool *is_backup;
    struct ovsdb_jsonrpc_server *jsonrpc;
};
static unixctl_cb_func ovsdb_server_add_remote;
static unixctl_cb_func ovsdb_server_remove_remote;
static unixctl_cb_func ovsdb_server_list_remotes;

static unixctl_cb_func ovsdb_server_add_database;
static unixctl_cb_func ovsdb_server_remove_database;
static unixctl_cb_func ovsdb_server_list_databases;

static void read_db(struct server_config *, struct db *);
static struct ovsdb_error *open_db(struct server_config *,
                                   const char *filename)
    OVS_WARN_UNUSED_RESULT;
static void add_server_db(struct server_config *);
static void remove_db(struct server_config *, struct shash_node *db, char *);
static void close_db(struct server_config *, struct db *, char *);

static void parse_options(int argc, char *argvp[],
                          struct sset *db_filenames, struct sset *remotes,
                          char **unixctl_pathp, char **run_command,
                          char **sync_from, char **sync_exclude,
                          bool *is_backup);
OVS_NO_RETURN static void usage(void);

static char *reconfigure_remotes(struct ovsdb_jsonrpc_server *,
                                 const struct shash *all_dbs,
                                 struct sset *remotes);
static char *reconfigure_ssl(const struct shash *all_dbs);
static void report_error_if_changed(char *error, char **last_errorp);

static void update_remote_status(const struct ovsdb_jsonrpc_server *jsonrpc,
                                 const struct sset *remotes,
                                 struct shash *all_dbs);
static void update_server_status(struct shash *all_dbs);

static void save_config__(FILE *config_file, const struct sset *remotes,
                          const struct sset *db_filenames,
                          const char *sync_from, const char *sync_exclude,
                          bool is_backup);
static void save_config(struct server_config *);
static void load_config(FILE *config_file, struct sset *remotes,
                        struct sset *db_filenames, char **sync_from,
                        char **sync_exclude, bool *is_backup);

static void
ovsdb_replication_init(const char *sync_from, const char *exclude,
                       struct shash *all_dbs, const struct uuid *server_uuid)
{
    replication_init(sync_from, exclude, server_uuid);
    struct shash_node *node;
    SHASH_FOR_EACH (node, all_dbs) {
        struct db *db = node->data;
        if (node->name[0] != '_' && db->db) {
            replication_add_local_db(node->name, db->db);
        }
    }
}

static void
log_and_free_error(struct ovsdb_error *error)
{
    if (error) {
        char *s = ovsdb_error_to_string_free(error);
        VLOG_INFO("%s", s);
        free(s);
    }
}

static void
main_loop(struct server_config *config,
          struct ovsdb_jsonrpc_server *jsonrpc, struct shash *all_dbs,
          struct unixctl_server *unixctl, struct sset *remotes,
          struct process *run_process, bool *exiting, bool *is_backup)
{
    char *remotes_error, *ssl_error;
    struct shash_node *node;
    long long int status_timer = LLONG_MIN;

    *exiting = false;
    ssl_error = NULL;
    remotes_error = NULL;
    while (!*exiting) {
        memory_run();
        if (memory_should_report()) {
            struct simap usage;

            simap_init(&usage);
            ovsdb_jsonrpc_server_get_memory_usage(jsonrpc, &usage);
            ovsdb_monitor_get_memory_usage(&usage);
            SHASH_FOR_EACH(node, all_dbs) {
                struct db *db = node->data;
                ovsdb_get_memory_usage(db->db, &usage);
            }
            memory_report(&usage);
            simap_destroy(&usage);
        }

        /* Run unixctl_server_run() before reconfigure_remotes() because
         * ovsdb-server/add-remote and ovsdb-server/remove-remote can change
         * the set of remotes that reconfigure_remotes() uses. */
        unixctl_server_run(unixctl);

        ovsdb_jsonrpc_server_set_read_only(jsonrpc, *is_backup);

        report_error_if_changed(
            reconfigure_remotes(jsonrpc, all_dbs, remotes),
            &remotes_error);
        report_error_if_changed(reconfigure_ssl(all_dbs), &ssl_error);
        ovsdb_jsonrpc_server_run(jsonrpc);

        if (*is_backup) {
            replication_run();
            if (!replication_is_alive()) {
                disconnect_active_server();
                *is_backup = false;
            }
        }

        struct shash_node *next;
        SHASH_FOR_EACH_SAFE (node, next, all_dbs) {
            struct db *db = node->data;
            if (ovsdb_trigger_run(db->db, time_msec())) {
                /* The message below is currently the only reason to disconnect
                 * all clients. */
                ovsdb_jsonrpc_server_reconnect(
                    jsonrpc, false,
                    xasprintf("committed %s database schema conversion",
                              db->db->name));
            }
            ovsdb_storage_run(db->db->storage);
            read_db(config, db);
            if (ovsdb_storage_is_dead(db->db->storage)) {
                VLOG_INFO("%s: removing database because storage disconnected "
                          "permanently", node->name);
                remove_db(config, node,
                          xasprintf("removing database %s because storage "
                                    "disconnected permanently", node->name));
            } else if (ovsdb_storage_should_snapshot(db->db->storage)) {
                log_and_free_error(ovsdb_snapshot(db->db));
            }
        }
        if (run_process) {
            process_run();
            if (process_exited(run_process)) {
                *exiting = true;
            }
        }

        /* update Manager status(es) every 2.5 seconds */
        if (time_msec() >= status_timer) {
            status_timer = time_msec() + 2500;
            update_remote_status(jsonrpc, remotes, all_dbs);
        }

        update_server_status(all_dbs);

        memory_wait();
        if (*is_backup) {
            replication_wait();
        }

        ovsdb_jsonrpc_server_wait(jsonrpc);
        unixctl_server_wait(unixctl);
        SHASH_FOR_EACH(node, all_dbs) {
            struct db *db = node->data;
            ovsdb_trigger_wait(db->db, time_msec());
            ovsdb_storage_wait(db->db->storage);
            ovsdb_storage_read_wait(db->db->storage);
        }
        if (run_process) {
            process_wait(run_process);
        }
        if (*exiting) {
            poll_immediate_wake();
        }
        poll_timer_wait_until(status_timer);
        poll_block();
        if (should_service_stop()) {
            *exiting = true;
        }
    }

    free(remotes_error);
}

int
main(int argc, char *argv[])
{
    char *unixctl_path = NULL;
    char *run_command = NULL;
    struct unixctl_server *unixctl;
    struct ovsdb_jsonrpc_server *jsonrpc;
    struct sset remotes, db_filenames;
    char *sync_from, *sync_exclude;
    bool is_backup;
    const char *db_filename;
    struct process *run_process;
    bool exiting;
    int retval;
    FILE *config_tmpfile;
    struct server_config server_config;
    struct shash all_dbs;
    struct shash_node *node, *next;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    fatal_ignore_sigpipe();
    process_init();

    bool active = false;
    parse_options(argc, argv, &db_filenames, &remotes, &unixctl_path,
                  &run_command, &sync_from, &sync_exclude, &active);
    is_backup = sync_from && !active;

    daemon_become_new_user(false);

    /* Create and initialize 'config_tmpfile' as a temporary file to hold
     * ovsdb-server's most basic configuration, and then save our initial
     * configuration to it.  When --monitor is used, this preserves the effects
     * of ovs-appctl commands such as ovsdb-server/add-remote (which saves the
     * new configuration) across crashes. */
    config_tmpfile = tmpfile();
    if (!config_tmpfile) {
        ovs_fatal(errno, "failed to create temporary file");
    }

    server_config.remotes = &remotes;
    server_config.config_tmpfile = config_tmpfile;

    save_config__(config_tmpfile, &remotes, &db_filenames, sync_from,
                  sync_exclude, is_backup);

    daemonize_start(false);

    /* Load the saved config. */
    load_config(config_tmpfile, &remotes, &db_filenames, &sync_from,
                &sync_exclude, &is_backup);

    /* Start ovsdb jsonrpc server. When running as a backup server,
     * jsonrpc connections are read only. Otherwise, both read
     * and write transactions are allowed.  */
    jsonrpc = ovsdb_jsonrpc_server_create(is_backup);

    shash_init(&all_dbs);
    server_config.all_dbs = &all_dbs;
    server_config.jsonrpc = jsonrpc;
    server_config.sync_from = &sync_from;
    server_config.sync_exclude = &sync_exclude;
    server_config.is_backup = &is_backup;

    perf_counters_init();

    SSET_FOR_EACH (db_filename, &db_filenames) {
        struct ovsdb_error *error = open_db(&server_config, db_filename);
        if (error) {
            char *s = ovsdb_error_to_string_free(error);
            ovs_fatal(0, "%s", s);
        }
    }
    add_server_db(&server_config);

    char *error = reconfigure_remotes(jsonrpc, &all_dbs, &remotes);
    if (!error) {
        error = reconfigure_ssl(&all_dbs);
    }
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    if (run_command) {
        char *run_argv[4];

        run_argv[0] = "/bin/sh";
        run_argv[1] = "-c";
        run_argv[2] = run_command;
        run_argv[3] = NULL;

        retval = process_start(run_argv, &run_process);
        if (retval) {
            ovs_fatal(retval, "%s: process failed to start", run_command);
        }
    } else {
        run_process = NULL;
    }

    daemonize_complete();

    if (!run_command) {
        /* ovsdb-server is usually a long-running process, in which case it
         * makes plenty of sense to log the version, but --run makes
         * ovsdb-server more like a command-line tool, so skip it.  */
        VLOG_INFO("%s (Open vSwitch) %s", program_name, VERSION);
    }

    unixctl_command_register("exit", "", 0, 0, ovsdb_server_exit, &exiting);
    unixctl_command_register("ovsdb-server/compact", "", 0, 1,
                             ovsdb_server_compact, &all_dbs);
    unixctl_command_register("ovsdb-server/reconnect", "", 0, 0,
                             ovsdb_server_reconnect, jsonrpc);

    unixctl_command_register("ovsdb-server/add-remote", "REMOTE", 1, 1,
                             ovsdb_server_add_remote, &server_config);
    unixctl_command_register("ovsdb-server/remove-remote", "REMOTE", 1, 1,
                             ovsdb_server_remove_remote, &server_config);
    unixctl_command_register("ovsdb-server/list-remotes", "", 0, 0,
                             ovsdb_server_list_remotes, &remotes);

    unixctl_command_register("ovsdb-server/add-db", "DB", 1, 1,
                             ovsdb_server_add_database, &server_config);
    unixctl_command_register("ovsdb-server/remove-db", "DB", 1, 1,
                             ovsdb_server_remove_database, &server_config);
    unixctl_command_register("ovsdb-server/list-dbs", "", 0, 0,
                             ovsdb_server_list_databases, &all_dbs);
    unixctl_command_register("ovsdb-server/perf-counters-show", "", 0, 0,
                             ovsdb_server_perf_counters_show, NULL);
    unixctl_command_register("ovsdb-server/perf-counters-clear", "", 0, 0,
                             ovsdb_server_perf_counters_clear, NULL);
    unixctl_command_register("ovsdb-server/set-active-ovsdb-server", "", 1, 1,
                             ovsdb_server_set_active_ovsdb_server,
                             &server_config);
    unixctl_command_register("ovsdb-server/get-active-ovsdb-server", "", 0, 0,
                             ovsdb_server_get_active_ovsdb_server,
                             &server_config);
    unixctl_command_register("ovsdb-server/connect-active-ovsdb-server", "",
                             0, 0, ovsdb_server_connect_active_ovsdb_server,
                             &server_config);
    unixctl_command_register("ovsdb-server/disconnect-active-ovsdb-server", "",
                             0, 0, ovsdb_server_disconnect_active_ovsdb_server,
                             &server_config);
    unixctl_command_register("ovsdb-server/set-sync-exclude-tables", "",
                             0, 1, ovsdb_server_set_sync_exclude_tables,
                             &server_config);
    unixctl_command_register("ovsdb-server/get-sync-exclude-tables", "",
                             0, 0, ovsdb_server_get_sync_exclude_tables,
                             NULL);
    unixctl_command_register("ovsdb-server/sync-status", "",
                             0, 0, ovsdb_server_get_sync_status,
                             &server_config);

    /* Simulate the behavior of OVS release prior to version 2.5 that
     * does not support the monitor_cond method.  */
    unixctl_command_register("ovsdb-server/disable-monitor-cond", "", 0, 0,
                             ovsdb_server_disable_monitor_cond, jsonrpc);

    if (is_backup) {
        const struct uuid *server_uuid;
        server_uuid = ovsdb_jsonrpc_server_get_uuid(jsonrpc);
        ovsdb_replication_init(sync_from, sync_exclude, &all_dbs, server_uuid);
    }

    main_loop(&server_config, jsonrpc, &all_dbs, unixctl, &remotes,
              run_process, &exiting, &is_backup);

    SHASH_FOR_EACH_SAFE(node, next, &all_dbs) {
        struct db *db = node->data;
        close_db(&server_config, db, NULL);
        shash_delete(&all_dbs, node);
    }
    ovsdb_jsonrpc_server_destroy(jsonrpc);
    shash_destroy(&all_dbs);
    sset_destroy(&remotes);
    sset_destroy(&db_filenames);
    free(sync_from);
    free(sync_exclude);
    unixctl_server_destroy(unixctl);
    replication_destroy();

    if (run_process && process_exited(run_process)) {
        int status = process_status(run_process);
        if (status) {
            ovs_fatal(0, "%s: child exited, %s",
                      run_command, process_status_msg(status));
        }
    }
    perf_counters_destroy();
    service_stop();
    return 0;
}

/* Returns true if 'filename' is known to be already open as a database,
 * false if not.
 *
 * "False negatives" are possible. */
static bool
is_already_open(struct server_config *config OVS_UNUSED,
                const char *filename OVS_UNUSED)
{
#ifndef _WIN32
    struct stat s;

    if (!stat(filename, &s)) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, config->all_dbs) {
            struct db *db = node->data;
            struct stat s2;

            if (!stat(db->filename, &s2)
                && s.st_dev == s2.st_dev
                && s.st_ino == s2.st_ino) {
                return true;
            }
        }
    }
#endif  /* !_WIN32 */

    return false;
}

static void
close_db(struct server_config *config, struct db *db, char *comment)
{
    if (db) {
        ovsdb_jsonrpc_server_remove_db(config->jsonrpc, db->db, comment);
        ovsdb_destroy(db->db);
        free(db->filename);
        free(db);
    } else {
        free(comment);
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
parse_txn(struct server_config *config, struct db *db,
          struct ovsdb_schema *schema, const struct json *txn_json,
          const struct uuid *txnid)
{
    if (schema) {
        /* We're replacing the schema (and the data).  Destroy the database
         * (first grabbing its storage), then replace it with the new schema.
         * The transaction must also include the replacement data.
         *
         * Only clustered database schema changes go through this path. */
        ovs_assert(txn_json);
        ovs_assert(ovsdb_storage_is_clustered(db->db->storage));

        struct ovsdb_error *error = ovsdb_schema_check_for_ephemeral_columns(
            schema);
        if (error) {
            return error;
        }

        ovsdb_jsonrpc_server_reconnect(
            config->jsonrpc, false,
            (db->db->schema
             ? xasprintf("database %s schema changed", db->db->name)
             : xasprintf("database %s connected to storage", db->db->name)));

        ovsdb_replace(db->db, ovsdb_create(schema, NULL));

        /* Force update to schema in _Server database. */
        db->row_uuid = UUID_ZERO;
    }

    if (txn_json) {
        if (!db->db->schema) {
            return ovsdb_error(NULL, "%s: data without schema", db->filename);
        }

        struct ovsdb_txn *txn;
        struct ovsdb_error *error;

        error = ovsdb_file_txn_from_json(db->db, txn_json, false, &txn);
        if (!error) {
            log_and_free_error(ovsdb_txn_replay_commit(txn));
        }
        if (!error && !uuid_is_zero(txnid)) {
            db->db->prereq = *txnid;
        }
        if (error) {
            ovsdb_storage_unread(db->db->storage);
            return error;
        }
    }

    return NULL;
}

static void
read_db(struct server_config *config, struct db *db)
{
    struct ovsdb_error *error;
    for (;;) {
        struct ovsdb_schema *schema;
        struct json *txn_json;
        struct uuid txnid;
        error = ovsdb_storage_read(db->db->storage, &schema, &txn_json,
                                   &txnid);
        if (error) {
            break;
        } else if (!schema && !txn_json) {
            /* End of file. */
            return;
        } else {
            error = parse_txn(config, db, schema, txn_json, &txnid);
            json_destroy(txn_json);
            if (error) {
                break;
            }
        }
    }

    /* Log error but otherwise ignore it.  Probably the database just
     * got truncated due to power failure etc. and we should use its
     * current contents. */
    char *msg = ovsdb_error_to_string_free(error);
    VLOG_ERR("%s", msg);
    free(msg);
}

static void
add_db(struct server_config *config, struct db *db)
{
    db->row_uuid = UUID_ZERO;
    shash_add_assert(config->all_dbs, db->db->name, db);
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
open_db(struct server_config *config, const char *filename)
{
    struct db *db;

    /* If we know that the file is already open, return a good error message.
     * Otherwise, if the file is open, we'll fail later on with a harder to
     * interpret file locking error. */
    if (is_already_open(config, filename)) {
        return ovsdb_error(NULL, "%s: already open", filename);
    }

    struct ovsdb_storage *storage;
    struct ovsdb_error *error;
    error = ovsdb_storage_open(filename, true, &storage);
    if (error) {
        return error;
    }

    db = xzalloc(sizeof *db);
    db->filename = xstrdup(filename);

    struct ovsdb_schema *schema;
    if (ovsdb_storage_is_clustered(storage)) {
        schema = NULL;
    } else {
        struct json *txn_json;
        error = ovsdb_storage_read(storage, &schema, &txn_json, NULL);
        if (error) {
            ovsdb_storage_close(storage);
            return error;
        }
        ovs_assert(schema && !txn_json);
    }
    db->db = ovsdb_create(schema, storage);
    ovsdb_jsonrpc_server_add_db(config->jsonrpc, db->db);

    read_db(config, db);

    error = (db->db->name[0] == '_'
             ? ovsdb_error(NULL, "%s: names beginning with \"_\" are reserved",
                           db->db->name)
             : shash_find(config->all_dbs, db->db->name)
             ? ovsdb_error(NULL, "%s: duplicate database name", db->db->name)
             : NULL);
    if (error) {
        char *error_s = ovsdb_error_to_string(error);
        close_db(config, db,
                 xasprintf("cannot complete opening %s database (%s)",
                           db->db->name, error_s));
        free(error_s);
        return error;
    }

    add_db(config, db);
    return NULL;
}

/* Add the internal _Server database to the server configuration. */
static void
add_server_db(struct server_config *config)
{
    struct json *schema_json = json_from_string(
#include "ovsdb/_server.ovsschema.inc"
        );
    ovs_assert(schema_json->type == JSON_OBJECT);

    struct ovsdb_schema *schema;
    struct ovsdb_error *error OVS_UNUSED = ovsdb_schema_from_json(schema_json,
                                                                  &schema);
    ovs_assert(!error);
    json_destroy(schema_json);

    struct db *db = xzalloc(sizeof *db);
    db->filename = xstrdup("<internal>");
    db->db = ovsdb_create(schema, ovsdb_storage_create_unbacked());
    bool ok OVS_UNUSED = ovsdb_jsonrpc_server_add_db(config->jsonrpc, db->db);
    ovs_assert(ok);
    add_db(config, db);
}

static char * OVS_WARN_UNUSED_RESULT
parse_db_column__(const struct shash *all_dbs,
                  const char *name_, char *name,
                  const struct db **dbp,
                  const struct ovsdb_table **tablep,
                  const struct ovsdb_column **columnp)
{
    const char *db_name, *table_name, *column_name;
    const char *tokens[3];
    char *save_ptr = NULL;

    *dbp = NULL;
    *tablep = NULL;
    *columnp = NULL;

    strtok_r(name, ":", &save_ptr); /* "db:" */
    tokens[0] = strtok_r(NULL, ",", &save_ptr);
    tokens[1] = strtok_r(NULL, ",", &save_ptr);
    tokens[2] = strtok_r(NULL, ",", &save_ptr);
    if (!tokens[0] || !tokens[1] || !tokens[2]) {
        return xasprintf("\"%s\": invalid syntax", name_);
    }

    db_name = tokens[0];
    table_name = tokens[1];
    column_name = tokens[2];

    *dbp = shash_find_data(all_dbs, tokens[0]);
    if (!*dbp) {
        return xasprintf("\"%s\": no database named %s", name_, db_name);
    }

    *tablep = ovsdb_get_table((*dbp)->db, table_name);
    if (!*tablep) {
        return xasprintf("\"%s\": no table named %s", name_, table_name);
    }

    *columnp = ovsdb_table_schema_get_column((*tablep)->schema, column_name);
    if (!*columnp) {
        return xasprintf("\"%s\": table \"%s\" has no column \"%s\"",
                         name_, table_name, column_name);
    }

    return NULL;
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error. */
static char * OVS_WARN_UNUSED_RESULT
parse_db_column(const struct shash *all_dbs,
                const char *name_,
                const struct db **dbp,
                const struct ovsdb_table **tablep,
                const struct ovsdb_column **columnp)
{
    char *name = xstrdup(name_);
    char *retval = parse_db_column__(all_dbs, name_, name,
                                     dbp, tablep, columnp);
    free(name);
    return retval;
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error. */
static char * OVS_WARN_UNUSED_RESULT
parse_db_string_column(const struct shash *all_dbs,
                       const char *name,
                       const struct db **dbp,
                       const struct ovsdb_table **tablep,
                       const struct ovsdb_column **columnp)
{
    char *retval;

    retval = parse_db_column(all_dbs, name, dbp, tablep, columnp);
    if (retval) {
        return retval;
    }

    if ((*columnp)->type.key.type != OVSDB_TYPE_STRING
        || (*columnp)->type.value.type != OVSDB_TYPE_VOID) {
        return xasprintf("\"%s\": table \"%s\" column \"%s\" is "
                         "not string or set of strings",
                         name, (*tablep)->schema->name, (*columnp)->name);
    }

    return NULL;
}

static const char *
query_db_string(const struct shash *all_dbs, const char *name,
                struct ds *errors)
{
    if (!name || strncmp(name, "db:", 3)) {
        return name;
    } else {
        const struct ovsdb_column *column;
        const struct ovsdb_table *table;
        const struct ovsdb_row *row;
        const struct db *db;
        char *retval;

        retval = parse_db_string_column(all_dbs, name,
                                        &db, &table, &column);
        if (retval) {
            if (db && !db->db->schema) {
                /* 'db' is a clustered database but it hasn't connected to the
                 * cluster yet, so we can't get anything out of it, not even a
                 * schema.  Not really an error. */
            } else {
                ds_put_format(errors, "%s\n", retval);
            }
            free(retval);
            return NULL;
        }

        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum;
            size_t i;

            datum = &row->fields[column->index];
            for (i = 0; i < datum->n; i++) {
                if (datum->keys[i].string[0]) {
                    return datum->keys[i].string;
                }
            }
        }
        return NULL;
    }
}

static struct ovsdb_jsonrpc_options *
add_remote(struct shash *remotes, const char *target)
{
    struct ovsdb_jsonrpc_options *options;

    options = shash_find_data(remotes, target);
    if (!options) {
        options = ovsdb_jsonrpc_default_options(target);
        shash_add(remotes, target, options);
    }

    return options;
}

static void
free_remotes(struct shash *remotes)
{
    if (remotes) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, remotes) {
            struct ovsdb_jsonrpc_options *options = node->data;
            free(options->role);
        }
        shash_destroy_free_data(remotes);
    }
}

/* Adds a remote and options to 'remotes', based on the Manager table row in
 * 'row'. */
static void
add_manager_options(struct shash *remotes, const struct ovsdb_row *row)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    struct ovsdb_jsonrpc_options *options;
    long long int max_backoff, probe_interval;
    bool read_only;
    const char *target, *dscp_string, *role;

    if (!ovsdb_util_read_string_column(row, "target", &target) || !target) {
        VLOG_INFO_RL(&rl, "Table `%s' has missing or invalid `target' column",
                     row->table->schema->name);
        return;
    }

    options = add_remote(remotes, target);
    if (ovsdb_util_read_integer_column(row, "max_backoff", &max_backoff)) {
        options->max_backoff = max_backoff;
    }
    if (ovsdb_util_read_integer_column(row, "inactivity_probe",
                                       &probe_interval)) {
        options->probe_interval = probe_interval;
    }
    if (ovsdb_util_read_bool_column(row, "read_only", &read_only)) {
        options->read_only = read_only;
    }

    free(options->role);
    options->role = NULL;
    if (ovsdb_util_read_string_column(row, "role", &role) && role) {
        options->role = xstrdup(role);
    }

    options->dscp = DSCP_DEFAULT;
    dscp_string = ovsdb_util_read_map_string_column(row, "other_config",
                                                    "dscp");
    if (dscp_string) {
        int dscp = atoi(dscp_string);
        if (dscp >= 0 && dscp <= 63) {
            options->dscp = dscp;
        }
    }
}

static void
query_db_remotes(const char *name, const struct shash *all_dbs,
                 struct shash *remotes, struct ds *errors)
{
    const struct ovsdb_column *column;
    const struct ovsdb_table *table;
    const struct ovsdb_row *row;
    const struct db *db;
    char *retval;

    retval = parse_db_column(all_dbs, name, &db, &table, &column);
    if (retval) {
        if (db && !db->db->schema) {
            /* 'db' is a clustered database but it hasn't connected to the
             * cluster yet, so we can't get anything out of it, not even a
             * schema.  Not really an error. */
        } else {
            ds_put_format(errors, "%s\n", retval);
        }
        free(retval);
        return;
    }

    if (column->type.key.type == OVSDB_TYPE_STRING
        && column->type.value.type == OVSDB_TYPE_VOID) {
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum;
            size_t i;

            datum = &row->fields[column->index];
            for (i = 0; i < datum->n; i++) {
                add_remote(remotes, datum->keys[i].string);
            }
        }
    } else if (column->type.key.type == OVSDB_TYPE_UUID
               && column->type.key.uuid.refTable
               && column->type.value.type == OVSDB_TYPE_VOID) {
        const struct ovsdb_table *ref_table = column->type.key.uuid.refTable;
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum;
            size_t i;

            datum = &row->fields[column->index];
            for (i = 0; i < datum->n; i++) {
                const struct ovsdb_row *ref_row;

                ref_row = ovsdb_table_get_row(ref_table, &datum->keys[i].uuid);
                if (ref_row) {
                    add_manager_options(remotes, ref_row);
                }
            }
        }
    }
}

static void
update_remote_row(const struct ovsdb_row *row, struct ovsdb_txn *txn,
                  const struct ovsdb_jsonrpc_server *jsonrpc)
{
    struct ovsdb_jsonrpc_remote_status status;
    struct ovsdb_row *rw_row;
    const char *target;
    char *keys[9], *values[9];
    size_t n = 0;

    /* Get the "target" (protocol/host/port) spec. */
    if (!ovsdb_util_read_string_column(row, "target", &target)) {
        /* Bad remote spec or incorrect schema. */
        return;
    }
    rw_row = ovsdb_txn_row_modify(txn, row);
    ovsdb_jsonrpc_server_get_remote_status(jsonrpc, target, &status);

    /* Update status information columns. */
    ovsdb_util_write_bool_column(rw_row, "is_connected", status.is_connected);

    if (status.state) {
        keys[n] = xstrdup("state");
        values[n++] = xstrdup(status.state);
    }
    if (status.sec_since_connect != UINT_MAX) {
        keys[n] = xstrdup("sec_since_connect");
        values[n++] = xasprintf("%u", status.sec_since_connect);
    }
    if (status.sec_since_disconnect != UINT_MAX) {
        keys[n] = xstrdup("sec_since_disconnect");
        values[n++] = xasprintf("%u", status.sec_since_disconnect);
    }
    if (status.last_error) {
        keys[n] = xstrdup("last_error");
        values[n++] =
            xstrdup(ovs_retval_to_string(status.last_error));
    }
    if (status.locks_held && status.locks_held[0]) {
        keys[n] = xstrdup("locks_held");
        values[n++] = xstrdup(status.locks_held);
    }
    if (status.locks_waiting && status.locks_waiting[0]) {
        keys[n] = xstrdup("locks_waiting");
        values[n++] = xstrdup(status.locks_waiting);
    }
    if (status.locks_lost && status.locks_lost[0]) {
        keys[n] = xstrdup("locks_lost");
        values[n++] = xstrdup(status.locks_lost);
    }
    if (status.n_connections > 1) {
        keys[n] = xstrdup("n_connections");
        values[n++] = xasprintf("%d", status.n_connections);
    }
    if (status.bound_port != htons(0)) {
        keys[n] = xstrdup("bound_port");
        values[n++] = xasprintf("%"PRIu16, ntohs(status.bound_port));
    }
    ovsdb_util_write_string_string_column(rw_row, "status", keys, values, n);

    ovsdb_jsonrpc_server_free_remote_status(&status);
}

static void
update_remote_rows(const struct shash *all_dbs, const struct db *db_,
                   const char *remote_name,
                   const struct ovsdb_jsonrpc_server *jsonrpc,
                   struct ovsdb_txn *txn)
{
    const struct ovsdb_table *table, *ref_table;
    const struct ovsdb_column *column;
    const struct ovsdb_row *row;
    const struct db *db;
    char *retval;

    if (strncmp("db:", remote_name, 3)) {
        return;
    }

    retval = parse_db_column(all_dbs, remote_name, &db, &table, &column);
    if (retval) {
        free(retval);
        return;
    }

    if (db != db_
        || column->type.key.type != OVSDB_TYPE_UUID
        || !column->type.key.uuid.refTable
        || column->type.value.type != OVSDB_TYPE_VOID) {
        return;
    }

    ref_table = column->type.key.uuid.refTable;

    HMAP_FOR_EACH (row, hmap_node, &table->rows) {
        const struct ovsdb_datum *datum;
        size_t i;

        datum = &row->fields[column->index];
        for (i = 0; i < datum->n; i++) {
            const struct ovsdb_row *ref_row;

            ref_row = ovsdb_table_get_row(ref_table, &datum->keys[i].uuid);
            if (ref_row) {
                update_remote_row(ref_row, txn, jsonrpc);
            }
        }
    }
}

static void
commit_txn(struct ovsdb_txn *txn, const char *name)
{
    struct ovsdb_error *error = ovsdb_txn_propose_commit_block(txn, false);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        char *msg = ovsdb_error_to_string_free(error);
        VLOG_ERR_RL(&rl, "Failed to update %s: %s", name, msg);
        free(msg);
    }
}

static void
update_remote_status(const struct ovsdb_jsonrpc_server *jsonrpc,
                     const struct sset *remotes,
                     struct shash *all_dbs)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, all_dbs) {
        struct db *db = node->data;
        if (!db->db || ovsdb_storage_is_clustered(db->db->storage)) {
            continue;
        }

        struct ovsdb_txn *txn = ovsdb_txn_create(db->db);
        const char *remote;
        SSET_FOR_EACH (remote, remotes) {
            update_remote_rows(all_dbs, db, remote, jsonrpc, txn);
        }
        commit_txn(txn, "remote status");
    }
}

/* Updates 'row', a row in the _Server database's Database table, to match
 * 'db'. */
static void
update_database_status(struct ovsdb_row *row, struct db *db)
{
    ovsdb_util_write_string_column(row, "name", db->db->name);
    ovsdb_util_write_string_column(row, "model",
                                   ovsdb_storage_get_model(db->db->storage));
    ovsdb_util_write_bool_column(row, "connected",
                                 ovsdb_storage_is_connected(db->db->storage));
    ovsdb_util_write_bool_column(row, "leader",
                                 ovsdb_storage_is_leader(db->db->storage));
    ovsdb_util_write_uuid_column(row, "cid",
                                 ovsdb_storage_get_cid(db->db->storage));
    ovsdb_util_write_uuid_column(row, "sid",
                                 ovsdb_storage_get_sid(db->db->storage));

    uint64_t index = ovsdb_storage_get_applied_index(db->db->storage);
    if (index) {
        ovsdb_util_write_integer_column(row, "index", index);
    } else {
        ovsdb_util_clear_column(row, "index");
    }

    const struct uuid *row_uuid = ovsdb_row_get_uuid(row);
    if (!uuid_equals(row_uuid, &db->row_uuid)) {
        db->row_uuid = *row_uuid;

        /* The schema can only change if the row UUID changes, so only update
         * it in that case.  Presumably, this is worth optimizing because
         * schemas are often kilobytes in size and nontrivial to serialize. */
        char *schema = NULL;
        if (db->db->schema) {
            struct json *json_schema = ovsdb_schema_to_json(db->db->schema);
            schema = json_to_string(json_schema, JSSF_SORT);
            json_destroy(json_schema);
        }
        ovsdb_util_write_string_column(row, "schema", schema);
        free(schema);
    }
}

/* Updates the Database table in the _Server database. */
static void
update_server_status(struct shash *all_dbs)
{
    struct db *server_db = shash_find_data(all_dbs, "_Server");
    struct ovsdb_table *database_table = shash_find_data(
        &server_db->db->tables, "Database");
    struct ovsdb_txn *txn = ovsdb_txn_create(server_db->db);

    /* Update rows for databases that still exist.
     * Delete rows for databases that no longer exist. */
    const struct ovsdb_row *row, *next_row;
    HMAP_FOR_EACH_SAFE (row, next_row, hmap_node, &database_table->rows) {
        const char *name;
        ovsdb_util_read_string_column(row, "name", &name);
        struct db *db = shash_find_data(all_dbs, name);
        if (!db || !db->db) {
            ovsdb_txn_row_delete(txn, row);
        } else {
            update_database_status(ovsdb_txn_row_modify(txn, row), db);
        }
    }

    /* Add rows for new databases.
     *
     * This is O(n**2) but usually there are only 2 or 3 databases. */
    struct shash_node *node;
    SHASH_FOR_EACH (node, all_dbs) {
        struct db *db = node->data;

        if (!db->db) {
            continue;
        }

        HMAP_FOR_EACH (row, hmap_node, &database_table->rows) {
            const char *name;
            ovsdb_util_read_string_column(row, "name", &name);
            if (!strcmp(name, node->name)) {
                goto next;
            }
        }

        /* Add row. */
        struct ovsdb_row *new_row = ovsdb_row_create(database_table);
        uuid_generate(ovsdb_row_get_uuid_rw(new_row));
        update_database_status(new_row, db);
        ovsdb_txn_row_insert(txn, new_row);

    next:;
    }

    commit_txn(txn, "_Server");
}

/* Reconfigures ovsdb-server's remotes based on information in the database. */
static char *
reconfigure_remotes(struct ovsdb_jsonrpc_server *jsonrpc,
                    const struct shash *all_dbs, struct sset *remotes)
{
    struct ds errors = DS_EMPTY_INITIALIZER;
    struct shash resolved_remotes;
    const char *name;

    /* Configure remotes. */
    shash_init(&resolved_remotes);
    SSET_FOR_EACH (name, remotes) {
        if (!strncmp(name, "db:", 3)) {
            query_db_remotes(name, all_dbs, &resolved_remotes, &errors);
        } else {
            add_remote(&resolved_remotes, name);
        }
    }
    ovsdb_jsonrpc_server_set_remotes(jsonrpc, &resolved_remotes);
    free_remotes(&resolved_remotes);

    return errors.string;
}

static char *
reconfigure_ssl(const struct shash *all_dbs)
{
    struct ds errors = DS_EMPTY_INITIALIZER;
    const char *resolved_private_key;
    const char *resolved_certificate;
    const char *resolved_ca_cert;
    const char *resolved_ssl_protocols;
    const char *resolved_ssl_ciphers;

    resolved_private_key = query_db_string(all_dbs, private_key_file, &errors);
    resolved_certificate = query_db_string(all_dbs, certificate_file, &errors);
    resolved_ca_cert = query_db_string(all_dbs, ca_cert_file, &errors);
    resolved_ssl_protocols = query_db_string(all_dbs, ssl_protocols, &errors);
    resolved_ssl_ciphers = query_db_string(all_dbs, ssl_ciphers, &errors);

    stream_ssl_set_key_and_cert(resolved_private_key, resolved_certificate);
    stream_ssl_set_ca_cert_file(resolved_ca_cert, bootstrap_ca_cert);
    stream_ssl_set_protocols(resolved_ssl_protocols);
    stream_ssl_set_ciphers(resolved_ssl_ciphers);

    return errors.string;
}

static void
report_error_if_changed(char *error, char **last_errorp)
{
    if (error) {
        if (!*last_errorp || strcmp(error, *last_errorp)) {
            VLOG_WARN("%s", error);
            free(*last_errorp);
            *last_errorp = error;
            return;
        }
        free(error);
    } else {
        free(*last_errorp);
        *last_errorp = NULL;
    }
}

static void
ovsdb_server_set_active_ovsdb_server(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED, const char *argv[],
                                     void *config_)
{
    struct server_config *config = config_;

    if (*config->sync_from) {
        free(*config->sync_from);
    }
    *config->sync_from = xstrdup(argv[1]);
    save_config(config);

    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_server_get_active_ovsdb_server(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED,
                                     const char *argv[] OVS_UNUSED,
                                     void *config_ )
{
    struct server_config *config = config_;

    unixctl_command_reply(conn, *config->sync_from);
}

static void
ovsdb_server_connect_active_ovsdb_server(struct unixctl_conn *conn,
                                         int argc OVS_UNUSED,
                                         const char *argv[] OVS_UNUSED,
                                         void *config_)
{
    struct server_config *config = config_;
    char *msg = NULL;

    if ( !*config->sync_from) {
        msg = "Unable to connect: active server is not specified.\n";
    } else {
        const struct uuid *server_uuid;
        server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);
        ovsdb_replication_init(*config->sync_from, *config->sync_exclude,
                               config->all_dbs, server_uuid);
        if (!*config->is_backup) {
            *config->is_backup = true;
            save_config(config);
        }
    }
    unixctl_command_reply(conn, msg);
}

static void
ovsdb_server_disconnect_active_ovsdb_server(struct unixctl_conn *conn,
                                            int argc OVS_UNUSED,
                                            const char *argv[] OVS_UNUSED,
                                            void *config_)
{
    struct server_config *config = config_;

    disconnect_active_server();
    *config->is_backup = false;
    save_config(config);
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_server_set_sync_exclude_tables(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED,
                                     const char *argv[],
                                     void *config_)
{
    struct server_config *config = config_;

    char *err = set_blacklist_tables(argv[1], true);
    if (!err) {
        free(*config->sync_exclude);
        *config->sync_exclude = xstrdup(argv[1]);
        save_config(config);
        if (*config->is_backup) {
            const struct uuid *server_uuid;
            server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);
            ovsdb_replication_init(*config->sync_from, *config->sync_exclude,
                                   config->all_dbs, server_uuid);
        }
        err = set_blacklist_tables(argv[1], false);
    }
    unixctl_command_reply(conn, err);
    free(err);
}

static void
ovsdb_server_get_sync_exclude_tables(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED,
                                     const char *argv[] OVS_UNUSED,
                                     void *arg_ OVS_UNUSED)
{
    char *reply = get_blacklist_tables();
    unixctl_command_reply(conn, reply);
    free(reply);
}

static void
ovsdb_server_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED,
                  void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_server_perf_counters_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                const char *argv[] OVS_UNUSED,
                                void *arg_ OVS_UNUSED)
{
    char *s = perf_counters_to_string();

    unixctl_command_reply(conn, s);
    free(s);
}

static void
ovsdb_server_perf_counters_clear(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                 const char *argv[] OVS_UNUSED,
                                 void *arg_ OVS_UNUSED)
{
    perf_counters_clear();
    unixctl_command_reply(conn, NULL);
}

/* "ovsdb-server/disable-monitor-cond": makes ovsdb-server drop all of its
 * JSON-RPC connections and reconnect. New sessions will not recognize
 * the 'monitor_cond' method.   */
static void
ovsdb_server_disable_monitor_cond(struct unixctl_conn *conn,
                                  int argc OVS_UNUSED,
                                  const char *argv[] OVS_UNUSED,
                                  void *jsonrpc_)
{
    struct ovsdb_jsonrpc_server *jsonrpc = jsonrpc_;

    ovsdb_jsonrpc_disable_monitor_cond();
    ovsdb_jsonrpc_server_reconnect(
        jsonrpc, true, xstrdup("user ran ovsdb-server/disable-monitor"));
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_server_compact(struct unixctl_conn *conn, int argc,
                     const char *argv[], void *dbs_)
{
    const char *db_name = argc < 2 ? NULL : argv[1];
    struct shash *all_dbs = dbs_;
    struct ds reply;
    struct shash_node *node;
    int n = 0;

    if (db_name && db_name[0] == '_') {
        unixctl_command_reply_error(conn, "cannot compact built-in databases");
        return;
    }

    ds_init(&reply);
    SHASH_FOR_EACH(node, all_dbs) {
        struct db *db = node->data;
        if (db_name
            ? !strcmp(node->name, db_name)
            : node->name[0] != '_') {
            if (db->db) {
                VLOG_INFO("compacting %s database by user request",
                          node->name);

                struct ovsdb_error *error = ovsdb_snapshot(db->db);
                if (error) {
                    char *s = ovsdb_error_to_string(error);
                    ds_put_format(&reply, "%s\n", s);
                    free(s);
                    ovsdb_error_destroy(error);
                }

                n++;
            }
        }
    }

    if (!n) {
        unixctl_command_reply_error(conn, "no database by that name");
    } else if (reply.length) {
        unixctl_command_reply_error(conn, ds_cstr(&reply));
    } else {
        unixctl_command_reply(conn, NULL);
    }
    ds_destroy(&reply);
}

/* "ovsdb-server/reconnect": makes ovsdb-server drop all of its JSON-RPC
 * connections and reconnect. */
static void
ovsdb_server_reconnect(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[] OVS_UNUSED, void *jsonrpc_)
{
    struct ovsdb_jsonrpc_server *jsonrpc = jsonrpc_;
    ovsdb_jsonrpc_server_reconnect(
        jsonrpc, true, xstrdup("user ran ovsdb-server/reconnect"));
    unixctl_command_reply(conn, NULL);
}

/* "ovsdb-server/add-remote REMOTE": adds REMOTE to the set of remotes that
 * ovsdb-server services. */
static void
ovsdb_server_add_remote(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[], void *config_)
{
    struct server_config *config = config_;
    const char *remote = argv[1];

    const struct ovsdb_column *column;
    const struct ovsdb_table *table;
    const struct db *db;
    char *retval;

    retval = (strncmp("db:", remote, 3)
              ? NULL
              : parse_db_column(config->all_dbs, remote,
                                &db, &table, &column));
    if (!retval) {
        if (sset_add(config->remotes, remote)) {
            save_config(config);
        }
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply_error(conn, retval);
        free(retval);
    }
}

/* "ovsdb-server/remove-remote REMOTE": removes REMOTE frmo the set of remotes
 * that ovsdb-server services. */
static void
ovsdb_server_remove_remote(struct unixctl_conn *conn, int argc OVS_UNUSED,
                           const char *argv[], void *config_)
{
    struct server_config *config = config_;
    struct sset_node *node;

    node = sset_find(config->remotes, argv[1]);
    if (node) {
        sset_delete(config->remotes, node);
        save_config(config);
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply_error(conn, "no such remote");
    }
}

/* "ovsdb-server/list-remotes": outputs a list of configured rmeotes. */
static void
ovsdb_server_list_remotes(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[] OVS_UNUSED, void *remotes_)
{
    struct sset *remotes = remotes_;
    const char **list, **p;
    struct ds s;

    ds_init(&s);

    list = sset_sort(remotes);
    for (p = list; *p; p++) {
        ds_put_format(&s, "%s\n", *p);
    }
    free(list);

    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}


/* "ovsdb-server/add-db DB": adds the DB to ovsdb-server. */
static void
ovsdb_server_add_database(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[], void *config_)
{
    struct server_config *config = config_;
    const char *filename = argv[1];

    char *error = ovsdb_error_to_string_free(open_db(config, filename));
    if (!error) {
        save_config(config);
        if (*config->is_backup) {
            const struct uuid *server_uuid;
            server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);
            ovsdb_replication_init(*config->sync_from, *config->sync_exclude,
                                   config->all_dbs, server_uuid);
        }
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply_error(conn, error);
        free(error);
    }
}

static void
remove_db(struct server_config *config, struct shash_node *node, char *comment)
{
    struct db *db = node->data;

    close_db(config, db, comment);
    shash_delete(config->all_dbs, node);

    save_config(config);
    if (*config->is_backup) {
        const struct uuid *server_uuid;
        server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);
        ovsdb_replication_init(*config->sync_from, *config->sync_exclude,
                               config->all_dbs, server_uuid);
    }
}

static void
ovsdb_server_remove_database(struct unixctl_conn *conn, int argc OVS_UNUSED,
                             const char *argv[], void *config_)
{
    struct server_config *config = config_;
    struct shash_node *node;

    node = shash_find(config->all_dbs, argv[1]);
    if (!node) {
        unixctl_command_reply_error(conn, "Failed to find the database.");
        return;
    }
    if (node->name[0] == '_') {
        unixctl_command_reply_error(conn, "Cannot remove reserved database.");
        return;
    }

    remove_db(config, node, xasprintf("removing %s database by user request",
                                      node->name));
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_server_list_databases(struct unixctl_conn *conn, int argc OVS_UNUSED,
                            const char *argv[] OVS_UNUSED, void *all_dbs_)
{
    struct shash *all_dbs = all_dbs_;
    const struct shash_node **nodes;
    struct ds s;
    size_t i;

    ds_init(&s);

    nodes = shash_sort(all_dbs);
    for (i = 0; i < shash_count(all_dbs); i++) {
        const struct shash_node *node = nodes[i];
        struct db *db = node->data;
        if (db->db) {
            ds_put_format(&s, "%s\n", node->name);
        }
    }
    free(nodes);

    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}

static void
ovsdb_server_get_sync_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                             const char *argv[] OVS_UNUSED, void *config_)
{
    struct server_config *config = config_;
    bool is_backup = *config->is_backup;
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "state: %s\n", is_backup ? "backup" : "active");

    if (is_backup) {
        ds_put_and_free_cstr(&ds, replication_status());
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
parse_options(int argc, char *argv[],
              struct sset *db_filenames, struct sset *remotes,
              char **unixctl_pathp, char **run_command,
              char **sync_from, char **sync_exclude, bool *active)
{
    enum {
        OPT_REMOTE = UCHAR_MAX + 1,
        OPT_UNIXCTL,
        OPT_RUN,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_PEER_CA_CERT,
        OPT_SYNC_FROM,
        OPT_SYNC_EXCLUDE,
        OPT_ACTIVE,
        OPT_NO_DBS,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };

    static const struct option long_options[] = {
        {"remote",      required_argument, NULL, OPT_REMOTE},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
#ifndef _WIN32
        {"run",         required_argument, NULL, OPT_RUN},
#endif
        {"help",        no_argument, NULL, 'h'},
        {"version",     no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        STREAM_SSL_LONG_OPTIONS,
        {"sync-from",   required_argument, NULL, OPT_SYNC_FROM},
        {"sync-exclude-tables", required_argument, NULL, OPT_SYNC_EXCLUDE},
        {"active", no_argument, NULL, OPT_ACTIVE},
        {"no-dbs", no_argument, NULL, OPT_NO_DBS},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);
    bool add_default_db = true;

    *sync_from = NULL;
    *sync_exclude = NULL;
    sset_init(db_filenames);
    sset_init(remotes);
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_REMOTE:
            sset_add(remotes, optarg);
            break;

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        case OPT_RUN:
            *run_command = optarg;
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case 'p':
            private_key_file = optarg;
            break;

        case 'c':
            certificate_file = optarg;
            break;

        case 'C':
            ca_cert_file = optarg;
            bootstrap_ca_cert = false;
            break;

        case OPT_SSL_PROTOCOLS:
            ssl_protocols = optarg;
            break;

        case OPT_SSL_CIPHERS:
            ssl_ciphers = optarg;
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            ca_cert_file = optarg;
            bootstrap_ca_cert = true;
            break;

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_SYNC_FROM:
            *sync_from = xstrdup(optarg);
            break;

        case OPT_SYNC_EXCLUDE: {
            char *err = set_blacklist_tables(optarg, false);
            if (err) {
                ovs_fatal(0, "%s", err);
            }
            *sync_exclude = xstrdup(optarg);
            break;
        }
        case OPT_ACTIVE:
            *active = true;
            break;

        case OPT_NO_DBS:
            add_default_db = false;
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;
    if (argc > 0) {
        for (int i = 0; i < argc; i++) {
            sset_add(db_filenames, argv[i]);
        }
    } else if (add_default_db) {
        sset_add_and_free(db_filenames, xasprintf("%s/conf.db", ovs_dbdir()));
    }
}

static void
usage(void)
{
    printf("%s: Open vSwitch database server\n"
           "usage: %s [OPTIONS] [DATABASE...]\n"
           "where each DATABASE is a database file in ovsdb format.\n"
           "The default DATABASE, if none is given, is\n%s/conf.db.\n",
           program_name, program_name, ovs_dbdir());
    printf("\nJSON-RPC options (may be specified any number of times):\n"
           "  --remote=REMOTE         connect or listen to REMOTE\n");
    stream_usage("JSON-RPC", true, true, true);
    daemon_usage();
    vlog_usage();
    replication_usage();
    printf("\nOther options:\n"
           "  --run COMMAND           run COMMAND as subprocess then exit\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

static struct json *
sset_to_json(const struct sset *sset)
{
    struct json *array;
    const char *s;

    array = json_array_create_empty();
    SSET_FOR_EACH (s, sset) {
        json_array_add(array, json_string_create(s));
    }
    return array;
}

/* Truncates and replaces the contents of 'config_file' by a representation of
 * 'remotes' and 'db_filenames'. */
static void
save_config__(FILE *config_file, const struct sset *remotes,
              const struct sset *db_filenames, const char *sync_from,
              const char *sync_exclude, bool is_backup)
{
    struct json *obj;
    char *s;

    if (ftruncate(fileno(config_file), 0) == -1) {
        VLOG_FATAL("failed to truncate temporary file (%s)",
                   ovs_strerror(errno));
    }

    obj = json_object_create();
    json_object_put(obj, "remotes", sset_to_json(remotes));
    json_object_put(obj, "db_filenames", sset_to_json(db_filenames));
    if (sync_from) {
        json_object_put(obj, "sync_from", json_string_create(sync_from));
    }
    if (sync_exclude) {
        json_object_put(obj, "sync_exclude",
                        json_string_create(sync_exclude));
    }
    json_object_put(obj, "is_backup", json_boolean_create(is_backup));

    s = json_to_string(obj, 0);
    json_destroy(obj);

    if (fseek(config_file, 0, SEEK_SET) != 0
        || fputs(s, config_file) == EOF
        || fflush(config_file) == EOF) {
        VLOG_FATAL("failed to write temporary file (%s)", ovs_strerror(errno));
    }
    free(s);
}

/* Truncates and replaces the contents of 'config_file' by a representation of
 * 'config'. */
static void
save_config(struct server_config *config)
{
    struct sset db_filenames;
    struct shash_node *node;

    sset_init(&db_filenames);
    SHASH_FOR_EACH (node, config->all_dbs) {
        struct db *db = node->data;
        if (node->name[0] != '_') {
            sset_add(&db_filenames, db->filename);
        }
    }

    save_config__(config->config_tmpfile, config->remotes, &db_filenames,
                  *config->sync_from, *config->sync_exclude,
                  *config->is_backup);

    sset_destroy(&db_filenames);
}

static void
sset_from_json(struct sset *sset, const struct json *array)
{
    size_t i;

    sset_clear(sset);

    ovs_assert(array->type == JSON_ARRAY);
    for (i = 0; i < array->array.n; i++) {
        const struct json *elem = array->array.elems[i];
        sset_add(sset, json_string(elem));
    }
}

/* Clears and replaces 'remotes' and 'dbnames' by a configuration read from
 * 'config_file', which must have been previously written by save_config(). */
static void
load_config(FILE *config_file, struct sset *remotes, struct sset *db_filenames,
            char **sync_from, char **sync_exclude, bool *is_backup)
{
    struct json *json;

    if (fseek(config_file, 0, SEEK_SET) != 0) {
        VLOG_FATAL("seek failed in temporary file (%s)", ovs_strerror(errno));
    }
    json = json_from_stream(config_file);
    if (json->type == JSON_STRING) {
        VLOG_FATAL("reading json failed (%s)", json_string(json));
    }
    ovs_assert(json->type == JSON_OBJECT);

    sset_from_json(remotes, shash_find_data(json_object(json), "remotes"));
    sset_from_json(db_filenames,
                   shash_find_data(json_object(json), "db_filenames"));

    struct json *string;
    string = shash_find_data(json_object(json), "sync_from");
    free(*sync_from);
    *sync_from = string ? xstrdup(json_string(string)) : NULL;

    string = shash_find_data(json_object(json), "sync_exclude");
    free(*sync_exclude);
    *sync_exclude = string ? xstrdup(json_string(string)) : NULL;

    *is_backup = json_boolean(shash_find_data(json_object(json), "is_backup"));

    json_destroy(json);
}
