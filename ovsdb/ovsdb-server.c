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
#include "cooperative-multitasking.h"
#include "daemon.h"
#include "dirs.h"
#include "dns-resolve.h"
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
#include "ovs-replay.h"
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-types.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "openvswitch/poll-loop.h"
#include "process.h"
#include "replication.h"
#include "relay.h"
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

/* SSL/TLS configuration. */
static char *private_key_file;
static char *certificate_file;
static char *ca_cert_file;
static char *ssl_protocols;
static char *ssl_ciphers;
static char *ssl_ciphersuites;
static char *ssl_server_name;
static bool bootstrap_ca_cert;

/* Try to reclaim heap memory back to system after DB compaction. */
static bool trim_memory = true;

static unixctl_cb_func ovsdb_server_exit;
static unixctl_cb_func ovsdb_server_compact;
static unixctl_cb_func ovsdb_server_memory_trim_on_compaction;
static unixctl_cb_func ovsdb_server_reconnect;
static unixctl_cb_func ovsdb_server_perf_counters_clear;
static unixctl_cb_func ovsdb_server_perf_counters_show;
static unixctl_cb_func ovsdb_server_disable_monitor_cond;
static unixctl_cb_func ovsdb_server_set_active_ovsdb_server;
static unixctl_cb_func ovsdb_server_get_active_ovsdb_server;
static unixctl_cb_func ovsdb_server_connect_active_ovsdb_server;
static unixctl_cb_func ovsdb_server_disconnect_active_ovsdb_server;
static unixctl_cb_func ovsdb_server_set_active_ovsdb_server_probe_interval;
static unixctl_cb_func ovsdb_server_set_relay_source_interval;
static unixctl_cb_func ovsdb_server_set_sync_exclude_tables;
static unixctl_cb_func ovsdb_server_get_sync_exclude_tables;
static unixctl_cb_func ovsdb_server_get_sync_status;
static unixctl_cb_func ovsdb_server_get_db_storage_status;

/* Holds the name of the configuration file passed via --config-file.
 * Mutually exclusive with command-line and unixctl configuration
 * that can otherwise be done via configuration file. */
static char *config_file_path;
/* UnixCtl command to reload configuration from a configuration file. */
static unixctl_cb_func ovsdb_server_reload;

#define SERVICE_MODELS \
    SERVICE_MODEL(UNDEFINED,      undefined)         \
    SERVICE_MODEL(STANDALONE,     standalone)        \
    SERVICE_MODEL(CLUSTERED,      clustered)         \
    SERVICE_MODEL(ACTIVE_BACKUP,  active-backup)     \
    SERVICE_MODEL(RELAY,          relay)

enum service_model {
#define SERVICE_MODEL(ENUM, NAME) SM_##ENUM,
    SERVICE_MODELS
#undef SERVICE_MODEL
};

static const char *
service_model_to_string(enum service_model model)
{
    switch (model) {
#define SERVICE_MODEL(ENUM, NAME) \
    case SM_##ENUM: return #NAME;
    SERVICE_MODELS
#undef SERVICE_MODEL
    default: OVS_NOT_REACHED();
    }
}

static enum service_model
service_model_from_string(const char *model)
{
#define SERVICE_MODEL(ENUM, NAME) \
    if (!strcmp(model, #NAME)) {  \
        return SM_##ENUM;         \
    }
    SERVICE_MODELS
#undef SERVICE_MODEL

    VLOG_WARN("Unrecognized database service model: '%s'", model);

    return SM_UNDEFINED;
}

struct db_config {
    enum service_model model;
    char *source;  /* sync-from for backup or relay source. */
    struct ovsdb_jsonrpc_options *options;  /* For 'source' connection. */

    /* Configuration specific to SM_ACTIVE_BACKUP. */
    struct {
        char *sync_exclude;  /* Tables to exclude. */
        bool backup;  /* If true, the database is read-only and receives
                       * updates from the 'source'. */
    } ab;
};

struct db {
    struct ovsdb *db;
    char *filename;
    struct db_config *config;
    struct uuid row_uuid;
};

struct server_config {
    struct shash *remotes;
    struct shash *all_dbs;     /* All the currently serviced databases.
                                * 'struct db' by a schema name. */
    struct ovsdb_jsonrpc_server *jsonrpc;

    /* Command line + appctl configuration. */
    char **sync_from;
    char **sync_exclude;
    bool *is_backup;
    int *replication_probe_interval;
    int *relay_source_probe_interval;
    FILE *config_tmpfile;
};
static unixctl_cb_func ovsdb_server_add_remote;
static unixctl_cb_func ovsdb_server_remove_remote;
static unixctl_cb_func ovsdb_server_list_remotes;

static unixctl_cb_func ovsdb_server_add_database;
static unixctl_cb_func ovsdb_server_remove_database;
static unixctl_cb_func ovsdb_server_list_databases;
static unixctl_cb_func ovsdb_server_tlog_set;
static unixctl_cb_func ovsdb_server_tlog_list;

static void read_db(struct server_config *, struct db *);
static struct ovsdb_error *open_db(struct server_config *,
                                   const char *filename,
                                   const struct db_config *)
    OVS_WARN_UNUSED_RESULT;
static void add_server_db(struct server_config *);
static void remove_db(struct server_config *, struct shash_node *db, char *);
static void close_db(struct server_config *, struct db *, char *);

static struct ovsdb_error *update_schema(struct ovsdb *,
                                         const struct ovsdb_schema *,
                                         const struct uuid *txnid,
                                         bool conversion_with_no_data,
                                         void *aux)
    OVS_WARN_UNUSED_RESULT;

static void parse_options(int argc, char *argvp[],
                          struct shash *db_conf, struct shash *remotes,
                          char **unixctl_pathp, char **run_command,
                          char **sync_from, char **sync_exclude,
                          bool *is_backup);
OVS_NO_RETURN static void usage(void);

static struct ovsdb_jsonrpc_options *add_remote(
                            struct shash *remotes, const char *target,
                            const struct ovsdb_jsonrpc_options *);
static void free_remotes(struct shash *remotes);

static char *reconfigure_remotes(struct ovsdb_jsonrpc_server *,
                                 const struct shash *all_dbs,
                                 struct shash *remotes);
static char *reconfigure_ssl(const struct shash *all_dbs);
static void report_error_if_changed(char *error, char **last_errorp);

static void update_remote_status(const struct ovsdb_jsonrpc_server *jsonrpc,
                                 const struct shash *remotes,
                                 struct shash *all_dbs);
static void update_server_status(struct shash *all_dbs);

static void save_config__(FILE *config_file, const struct shash *remotes,
                          const struct shash *db_conf,
                          const char *sync_from, const char *sync_exclude,
                          bool is_backup);
static void save_config(struct server_config *);
static bool load_config(FILE *config_file, struct shash *remotes,
                        struct shash *db_conf, char **sync_from,
                        char **sync_exclude, bool *is_backup);

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
ovsdb_server_replication_remove_db(struct db *db)
{
    replication_remove_db(db->db);
    db->config->ab.backup = false;
}

static void
ovsdb_server_replication_run(struct server_config *config)
{
    struct shash_node *node;
    bool all_alive = true;

    replication_run();

    SHASH_FOR_EACH (node, config->all_dbs) {
        struct db *db = node->data;

        if (db->config->model == SM_ACTIVE_BACKUP && db->config->ab.backup
            && !replication_is_alive(db->db)) {
            ovsdb_server_replication_remove_db(db);
            all_alive = false;
        }
    }

    /* If one connection is broken, switch all databases to active,
     * if they are configured via the command line / appctl and so have
     * shared configuration. */
    if (!config_file_path && !all_alive && *config->is_backup) {
        *config->is_backup = false;

        SHASH_FOR_EACH (node, config->all_dbs) {
            struct db *db = node->data;

            if (db->config->model == SM_ACTIVE_BACKUP
                && db->config->ab.backup) {
                ovsdb_server_replication_remove_db(db);
            }
        }
    }
}

static void
main_loop(struct server_config *config,
          struct ovsdb_jsonrpc_server *jsonrpc, struct shash *all_dbs,
          struct unixctl_server *unixctl, struct shash *remotes,
          struct process *run_process, bool *exiting)
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

        ovsdb_jsonrpc_server_set_read_only(jsonrpc, false);

        report_error_if_changed(
            reconfigure_remotes(jsonrpc, all_dbs, remotes),
            &remotes_error);
        report_error_if_changed(reconfigure_ssl(all_dbs), &ssl_error);
        ovsdb_jsonrpc_server_run(jsonrpc);

        ovsdb_server_replication_run(config);
        ovsdb_relay_run();

        SHASH_FOR_EACH_SAFE (node, all_dbs) {
            struct db *db = node->data;

            ovsdb_storage_run(db->db->storage);
            read_db(config, db);
            /* Run triggers after storage_run and read_db to make sure new raft
             * updates are utilized in current iteration. */
            if (ovsdb_trigger_run(db->db, time_msec())) {
                /* The message below is currently the only reason to disconnect
                 * all clients. */
                ovsdb_jsonrpc_server_reconnect(
                    jsonrpc, false,
                    xasprintf("committed %s database schema conversion",
                              db->db->name));
            }
            if (ovsdb_storage_is_dead(db->db->storage)) {
                VLOG_INFO("%s: removing database because storage disconnected "
                          "permanently", node->name);
                remove_db(config, node,
                          xasprintf("removing database %s because storage "
                                    "disconnected permanently", node->name));
            } else if (!ovsdb_snapshot_in_progress(db->db)
                       && (ovsdb_storage_should_snapshot(db->db->storage) ||
                           ovsdb_snapshot_ready(db->db))) {
                log_and_free_error(ovsdb_snapshot(db->db, trim_memory));
            }
        }
        if (run_process) {
            process_run();
            if (process_exited(run_process)) {
                *exiting = true;
            }
        }

        /* update Manager status(es) every 2.5 seconds.  Don't update if we're
         * recording or performing replay. */
        if (status_timer == LLONG_MIN ||
             (!ovs_replay_is_active() && time_msec() >= status_timer)) {
            status_timer = time_msec() + 2500;
            update_remote_status(jsonrpc, remotes, all_dbs);
        }

        update_server_status(all_dbs);

        memory_wait();

        replication_wait();
        ovsdb_relay_wait();

        ovsdb_jsonrpc_server_wait(jsonrpc);
        unixctl_server_wait(unixctl);
        SHASH_FOR_EACH(node, all_dbs) {
            struct db *db = node->data;
            ovsdb_trigger_wait(db->db, time_msec());
            ovsdb_storage_wait(db->db->storage);
            ovsdb_storage_read_wait(db->db->storage);
            ovsdb_snapshot_wait(db->db);
        }
        if (run_process) {
            process_wait(run_process);
        }
        if (*exiting) {
            poll_immediate_wake();
        }
        if (!ovs_replay_is_active()) {
            poll_timer_wait_until(status_timer);
        }
        poll_block();
        if (should_service_stop()) {
            *exiting = true;
        }
    }

    free(remotes_error);
}

/* Parsing the relay in format 'relay:DB_NAME:<list of remotes>'.
 * On success, returns 'true', 'name' is set to DB_NAME, 'remotes' to
 * '<list of remotes>'.  Caller is responsible of freeing 'name' and
 * 'remotes'.  On failure, returns 'false'.  */
static bool
parse_relay_args(const char *arg, char **name, char **remote)
{
    const char *relay_prefix = "relay:";
    const int relay_prefix_len = strlen(relay_prefix);
    bool is_relay;

    is_relay = !strncmp(arg, relay_prefix, relay_prefix_len);
    if (!is_relay) {
        return false;
    }

    *remote = strchr(arg + relay_prefix_len, ':');

    if (!*remote || (*remote)[0] == '\0') {
        *remote = NULL;
        return false;
    }
    arg += relay_prefix_len;
    *name = xmemdup0(arg, *remote - arg);
    *remote = xstrdup(*remote + 1);
    return true;
}

static void
db_config_destroy(struct db_config *conf)
{
    if (!conf) {
        return;
    }

    free(conf->source);
    ovsdb_jsonrpc_options_free(conf->options);
    free(conf->ab.sync_exclude);
    free(conf);
}

static struct db_config *
db_config_clone(const struct db_config *c)
{
    struct db_config *conf = xmemdup(c, sizeof *c);

    conf->source = nullable_xstrdup(c->source);
    if (c->options) {
        conf->options = ovsdb_jsonrpc_options_clone(c->options);
    }
    conf->ab.sync_exclude = nullable_xstrdup(c->ab.sync_exclude);

    return conf;
}

static struct ovsdb_jsonrpc_options *
get_jsonrpc_options(const char *target, enum service_model model)
{
    struct ovsdb_jsonrpc_options *options;

    options = ovsdb_jsonrpc_default_options(target);
    if (model == SM_ACTIVE_BACKUP) {
        options->rpc.probe_interval = REPLICATION_DEFAULT_PROBE_INTERVAL;
    } else if (model == SM_RELAY) {
        options->rpc.probe_interval = RELAY_SOURCE_DEFAULT_PROBE_INTERVAL;
    }

    return options;
}

static void
add_database_config(struct shash *db_conf, const char *opt,
                    const char *sync_from, const char *sync_exclude,
                    bool active)
{
    struct db_config *conf = xzalloc(sizeof *conf);
    char *filename = NULL;

    if (parse_relay_args(opt, &filename, &conf->source)) {
        conf->model = SM_RELAY;
        conf->options = get_jsonrpc_options(conf->source, conf->model);
    } else if (sync_from) {
        conf->model = SM_ACTIVE_BACKUP;
        conf->source = xstrdup(sync_from);
        conf->options = get_jsonrpc_options(conf->source, conf->model);
        conf->ab.sync_exclude = nullable_xstrdup(sync_exclude);
        conf->ab.backup = !active;
        filename = xstrdup(opt);
    } else {
        conf->model = SM_UNDEFINED; /* We'll update once the file is open. */
        filename = xstrdup(opt);
    }

    conf = shash_replace_nocopy(db_conf, filename, conf);
    if (conf) {
        VLOG_WARN("Duplicate database configuration: %s", opt);
        db_config_destroy(conf);
    }
}

static void
free_database_configs(struct shash *db_conf)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, db_conf) {
        db_config_destroy(node->data);
    }
    shash_clear(db_conf);
}

static bool
service_model_can_convert(enum service_model a, enum service_model b)
{
    ovs_assert(a != SM_UNDEFINED);

    if (a == b) {
        return true;
    }

    if (b == SM_UNDEFINED) {
        return a == SM_STANDALONE || a == SM_CLUSTERED;
    }

    /* Conversion can happen only between standalone and active-backup. */
    return (a == SM_STANDALONE && b == SM_ACTIVE_BACKUP)
            || (a == SM_ACTIVE_BACKUP && b == SM_STANDALONE);
}

static void
database_update_config(struct server_config *server_config,
                       struct db *db, const struct db_config *new_conf)
{
    struct db_config *conf = db->config;
    enum service_model model = conf->model;

    /* Stop replicating when transitioning to active or standalone. */
    if (conf->model == SM_ACTIVE_BACKUP && conf->ab.backup
        && (new_conf->model == SM_STANDALONE || !new_conf->ab.backup)) {
        ovsdb_server_replication_remove_db(db);
    }

    db_config_destroy(conf);
    conf = db->config = db_config_clone(new_conf);

    if (conf->model == SM_UNDEFINED) {
        /* We're operating on the same file, the model is the same. */
        conf->model = model;
    }

    if (conf->model == SM_RELAY) {
        ovsdb_relay_add_db(db->db, conf->source, update_schema, server_config,
                           &conf->options->rpc);
    }
    if (conf->model == SM_ACTIVE_BACKUP && conf->ab.backup) {
        const struct uuid *server_uuid;

        server_uuid = ovsdb_jsonrpc_server_get_uuid(server_config->jsonrpc);
        replication_set_db(db->db, conf->source, conf->ab.sync_exclude,
                           server_uuid, &conf->options->rpc);
    }
}

static bool
reconfigure_databases(struct server_config *server_config,
                      struct shash *db_conf)
{
    struct db_config *cur_conf, *new_conf;
    struct shash_node *node, *conf_node;
    bool res = true;
    struct db *db;

    /* Remove databases that are no longer in the configuration or have
     * incompatible configuration.  Update compatible ones. */
    SHASH_FOR_EACH_SAFE (node, server_config->all_dbs) {
        db = node->data;

        if (node->name[0] == '_') {
            /* Skip internal databases. */
            continue;
        }

        cur_conf = db->config;
        conf_node = shash_find(db_conf, db->filename);
        new_conf = conf_node ? conf_node->data : NULL;

        if (!new_conf) {
            remove_db(server_config, node,
                      xasprintf("database %s removed from configuration",
                                node->name));
            continue;
        }
        if (!service_model_can_convert(cur_conf->model, new_conf->model)) {
            remove_db(server_config, node,
                      xasprintf("service model changed for database %s",
                                node->name));
            continue;
        }
        database_update_config(server_config, db, new_conf);

        db_config_destroy(new_conf);
        shash_delete(db_conf, conf_node);
    }

    /* Create new databases. */
    SHASH_FOR_EACH (node, db_conf) {
        struct ovsdb_error *error = open_db(server_config,
                                            node->name, node->data);
        if (error) {
            char *s = ovsdb_error_to_string_free(error);

            VLOG_WARN("failed to open database '%s': %s", node->name, s);
            free(s);
            res = false;
        }
        db_config_destroy(node->data);
    }
    shash_clear(db_conf);

    return res;
}

static bool
reconfigure_ovsdb_server(struct server_config *server_config)
{
    char *sync_from = NULL, *sync_exclude = NULL;
    bool is_backup = false;
    struct shash remotes;
    struct shash db_conf;
    bool res = true;

    FILE *file = NULL;

    if (config_file_path) {
        file = fopen(config_file_path, "r+b");
        if (!file) {
            VLOG_ERR("failed to open configuration file '%s': %s",
                     config_file_path, ovs_strerror(errno));
            return false;
        } else {
            VLOG_INFO("loading configuration from '%s'", config_file_path);
        }
    } else {
        file = server_config->config_tmpfile;
    }
    ovs_assert(file);

    shash_init(&remotes);
    shash_init(&db_conf);

    if (!load_config(file, &remotes, &db_conf,
                     &sync_from, &sync_exclude, &is_backup)) {
        if (config_file_path) {
            VLOG_WARN("failed to load configuration from %s",
                      config_file_path);
        } else {
            VLOG_FATAL("failed to load configuration from a temporary file");
        }
        res = false;
        goto exit_close;
    }

    /* Parsing was successful.  Update the server configuration. */
    shash_swap(server_config->remotes, &remotes);
    free(*server_config->sync_from);
    *server_config->sync_from = sync_from;
    free(*server_config->sync_exclude);
    *server_config->sync_exclude = sync_exclude;
    *server_config->is_backup = is_backup;

    if (!reconfigure_databases(server_config, &db_conf)) {
        VLOG_WARN("failed to configure databases");
        res = false;
    }

    char *error = reconfigure_remotes(server_config->jsonrpc,
                                      server_config->all_dbs,
                                      server_config->remotes);
    if (error) {
        VLOG_WARN("failed to configure remotes: %s", error);
        res = false;
    } else {
        error = reconfigure_ssl(server_config->all_dbs);
        if (error) {
            VLOG_WARN("failed to configure SSL/TLS: %s", error);
            res = false;
        }
    }
    free(error);

exit_close:
    if (config_file_path) {
        fclose(file);
    }
    free_remotes(&remotes);
    free_database_configs(&db_conf);
    shash_destroy(&remotes);
    shash_destroy(&db_conf);
    return res;
}

int
main(int argc, char *argv[])
{
    char *unixctl_path = NULL;
    char *run_command = NULL;
    struct unixctl_server *unixctl;
    struct ovsdb_jsonrpc_server *jsonrpc;
    struct process *run_process;
    bool exiting;
    int retval;
    FILE *config_tmpfile = NULL;
    struct shash all_dbs;
    struct shash_node *node;
    int replication_probe_interval = REPLICATION_DEFAULT_PROBE_INTERVAL;
    int relay_source_probe_interval = RELAY_SOURCE_DEFAULT_PROBE_INTERVAL;
    struct sset db_filenames = SSET_INITIALIZER(&db_filenames);
    struct shash db_conf = SHASH_INITIALIZER(&db_conf);
    struct shash remotes = SHASH_INITIALIZER(&remotes);
    char *sync_from = NULL, *sync_exclude = NULL;
    bool is_backup;

    struct server_config server_config = {
        .remotes = &remotes,
        .all_dbs = &all_dbs,
        .sync_from = &sync_from,
        .sync_exclude = &sync_exclude,
        .is_backup = &is_backup,
        .replication_probe_interval = &replication_probe_interval,
        .relay_source_probe_interval = &relay_source_probe_interval,
    };

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    fatal_ignore_sigpipe();
    process_init();
    dns_resolve_init(true);

    bool active = false;
    parse_options(argc, argv, &db_conf, &remotes, &unixctl_path,
                  &run_command, &sync_from, &sync_exclude, &active);
    is_backup = sync_from && !active;

    daemon_become_new_user(false, false);

    if (!config_file_path) {
         /* Create and initialize 'config_tmpfile' as a temporary file to hold
         * ovsdb-server's most basic configuration, and then save our initial
         * configuration to it.  When --monitor is used, this preserves the
         * effects of ovs-appctl commands such as ovsdb-server/add-remote
         * (which saves the new configuration) across crashes. */
        config_tmpfile = tmpfile();
        if (!config_tmpfile) {
            ovs_fatal(errno, "failed to create temporary file");
        }
        server_config.config_tmpfile = config_tmpfile;
        save_config__(config_tmpfile, &remotes, &db_conf, sync_from,
                      sync_exclude, is_backup);
    }

    free_remotes(&remotes);
    free_database_configs(&db_conf);

    daemonize_start(false, false);

    perf_counters_init();

    /* Start ovsdb jsonrpc server.  Both read and write transactions are
     * allowed by default, individual remotes and databases will be configured
     * as read-only, if necessary. */
    jsonrpc = ovsdb_jsonrpc_server_create(false);
    server_config.jsonrpc = jsonrpc;

    shash_init(&all_dbs);
    add_server_db(&server_config);

    if (!reconfigure_ovsdb_server(&server_config)) {
        ovs_fatal(0, "server configuration failed");
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
        VLOG_INFO("%s", ovs_get_program_version());
    }

    unixctl_command_register("exit", "", 0, 0, ovsdb_server_exit, &exiting);
    unixctl_command_register("ovsdb-server/compact", "", 0, 1,
                             ovsdb_server_compact, &all_dbs);
    unixctl_command_register("ovsdb-server/memory-trim-on-compaction",
                             "on|off", 1, 1,
                             ovsdb_server_memory_trim_on_compaction, NULL);
    unixctl_command_register("ovsdb-server/reconnect", "", 0, 0,
                             ovsdb_server_reconnect, jsonrpc);
    unixctl_command_register("ovsdb-server/reload", "", 0, 0,
                             ovsdb_server_reload, &server_config);

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
    unixctl_command_register("ovsdb-server/tlog-set", "DB:TABLE on|off",
                             2, 2, ovsdb_server_tlog_set, &all_dbs);
    unixctl_command_register("ovsdb-server/tlog-list", "",
                             0, 0, ovsdb_server_tlog_list, &all_dbs);
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
    unixctl_command_register(
        "ovsdb-server/set-active-ovsdb-server-probe-interval", "", 1, 1,
        ovsdb_server_set_active_ovsdb_server_probe_interval, &server_config);
    unixctl_command_register(
        "ovsdb-server/set-relay-source-probe-interval", "", 1, 1,
        ovsdb_server_set_relay_source_interval, &server_config);
    unixctl_command_register("ovsdb-server/set-sync-exclude-tables", "",
                             0, 1, ovsdb_server_set_sync_exclude_tables,
                             &server_config);
    unixctl_command_register("ovsdb-server/get-sync-exclude-tables", "",
                             0, 0, ovsdb_server_get_sync_exclude_tables,
                             &server_config);
    unixctl_command_register("ovsdb-server/sync-status", "",
                             0, 0, ovsdb_server_get_sync_status,
                             &server_config);
    unixctl_command_register("ovsdb-server/get-db-storage-status", "DB", 1, 1,
                             ovsdb_server_get_db_storage_status,
                             &server_config);

    /* Simulate the behavior of OVS release prior to version 2.5 that
     * does not support the monitor_cond method.  */
    unixctl_command_register("ovsdb-server/disable-monitor-cond", "", 0, 0,
                             ovsdb_server_disable_monitor_cond, jsonrpc);

    main_loop(&server_config, jsonrpc, &all_dbs, unixctl, &remotes,
              run_process, &exiting);

    SHASH_FOR_EACH_SAFE (node, &all_dbs) {
        struct db *db = node->data;
        close_db(&server_config, db, NULL);
        shash_delete(&all_dbs, node);
    }
    ovsdb_jsonrpc_server_destroy(jsonrpc);
    shash_destroy(&all_dbs);
    free_remotes(&remotes);
    shash_destroy(&remotes);
    free_database_configs(&db_conf);
    shash_destroy(&db_conf);
    free(sync_from);
    free(sync_exclude);
    unixctl_server_destroy(unixctl);
    replication_destroy();
    free(config_file_path);

    if (run_process && process_exited(run_process)) {
        int status = process_status(run_process);
        if (status) {
            ovs_fatal(0, "%s: child exited, %s",
                      run_command, process_status_msg(status));
        }
    }
    dns_resolve_destroy();
    perf_counters_destroy();
    cooperative_multitasking_destroy();
    service_stop();
    return 0;
}

/* Returns true if 'filename' is known to be already open as a database,
 * false if not.
 *
 * "False negatives" are possible. */
static bool
is_already_open(struct server_config *server_config OVS_UNUSED,
                const char *filename OVS_UNUSED)
{
#ifndef _WIN32
    struct stat s;

    if (!stat(filename, &s)) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, server_config->all_dbs) {
            struct db *db = node->data;
            struct stat s2;

            if (db->config->model != SM_RELAY
                && !stat(db->filename, &s2)
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
close_db(struct server_config *server_config, struct db *db, char *comment)
{
    if (db) {
        ovsdb_jsonrpc_server_remove_db(server_config->jsonrpc,
                                       db->db, comment);
        if (db->config->model == SM_RELAY) {
            ovsdb_relay_del_db(db->db);
        }
        if (db->config->model == SM_ACTIVE_BACKUP
            && db->config->ab.backup) {
            ovsdb_server_replication_remove_db(db);
        }
        db_config_destroy(db->config);
        ovsdb_destroy(db->db);
        free(db->filename);
        free(db);
    } else {
        free(comment);
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
update_schema(struct ovsdb *db,
              const struct ovsdb_schema *schema,
              const struct uuid *txnid,
              bool conversion_with_no_data, void *aux)
{
    struct server_config *config = aux;

    if (!db->schema || strcmp(schema->version, db->schema->version)) {
        ovsdb_jsonrpc_server_reconnect(
            config->jsonrpc, false,
            (db->schema
            ? xasprintf("database %s schema changed", db->name)
            : xasprintf("database %s connected to storage", db->name)));
    }

    if (db->schema && conversion_with_no_data) {
        struct ovsdb *new_db = NULL;
        struct ovsdb_error *error;

        /* If conversion was triggered by the current process, we might
         * already have converted version of a database. */
        new_db = ovsdb_trigger_find_and_steal_converted_db(db, txnid);
        if (!new_db) {
            /* No luck.  Converting. */
            error = ovsdb_convert(db, schema, &new_db);
            if (error) {
                /* Should never happen, because conversion should have been
                 * checked before writing the schema to the storage. */
                return error;
            }
        }
        ovsdb_replace(db, new_db);
    } else {
        ovsdb_replace(db, ovsdb_create(ovsdb_schema_clone(schema), NULL));
    }

    /* Force update to schema in _Server database. */
    struct db *dbp = shash_find_data(config->all_dbs, db->name);
    if (dbp) {
        dbp->row_uuid = UUID_ZERO;
    }
    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
parse_txn(struct server_config *config, struct db *db,
          const struct ovsdb_schema *schema, const struct json *txn_json,
          const struct uuid *txnid)
{
    struct ovsdb_error *error = NULL;
    struct ovsdb_txn *txn = NULL;

    if (schema) {
        /* We're replacing the schema (and the data).  If transaction includes
         * replacement data, destroy the database (first grabbing its storage),
         * then replace it with the new schema.  If not, it's a conversion
         * without data specified.  In this case, convert the current database
         * to a new schema instead.
         *
         * Only clustered database schema changes and snapshot installs
         * go through this path.
         */
        ovs_assert(ovsdb_storage_is_clustered(db->db->storage));

        error = ovsdb_schema_check_for_ephemeral_columns(schema);
        if (error) {
            return error;
        }

        error = update_schema(db->db, schema, txnid, txn_json == NULL, config);
        if (error) {
            return error;
        }
    }

    if (txn_json) {
        if (!db->db->schema) {
            return ovsdb_error(NULL, "%s: data without schema", db->filename);
        }

        error = ovsdb_file_txn_from_json(db->db, txn_json, false, &txn);
        if (error) {
            ovsdb_storage_unread(db->db->storage);
            return error;
        }
    } else if (schema) {
        /* We just performed conversion without data.  Transaction history
         * was destroyed.  Commit a dummy transaction to set the txnid. */
        txn = ovsdb_txn_create(db->db);
    }

    if (txn) {
        ovsdb_txn_set_txnid(txnid, txn);
        error = ovsdb_txn_replay_commit(txn);
        if (!error && !uuid_is_zero(txnid)) {
            db->db->prereq = *txnid;
        }
        ovsdb_txn_history_run(db->db);
    }
    return error;
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
            ovsdb_schema_destroy(schema);
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
open_db(struct server_config *server_config,
        const char *filename, const struct db_config *conf)
{
    struct ovsdb_storage *storage;
    struct ovsdb_error *error;

    if (conf->model != SM_RELAY) {
        /* If we know that the file is already open, return a good error
         * message.  Otherwise, if the file is open, we'll fail later on with
         * a harder to interpret file locking error. */
        if (is_already_open(server_config, filename)) {
            return ovsdb_error(NULL, "%s: already open", filename);
        }

        error = ovsdb_storage_open(filename, true, &storage);
        if (error) {
            return error;
        }
    } else {
        storage = ovsdb_storage_create_unbacked(filename);
    }

    enum service_model model = conf->model;
    if (model == SM_UNDEFINED || model == SM_STANDALONE
        || model == SM_CLUSTERED) {
        /* Check the actual service model from the storage. */
        model = ovsdb_storage_is_clustered(storage)
                ? SM_CLUSTERED : SM_STANDALONE;
    }
    if (conf->model != SM_UNDEFINED && conf->model != model) {
        ovsdb_storage_close(storage);
        return ovsdb_error(NULL, "%s: database is %s and not %s",
                           filename, service_model_to_string(model),
                           service_model_to_string(conf->model));
    }

    struct ovsdb_schema *schema;
    if (model == SM_RELAY || model == SM_CLUSTERED) {
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

    struct db *db = xzalloc(sizeof *db);
    db->filename = xstrdup(filename);
    db->config = db_config_clone(conf);
    db->config->model = model;
    db->db = ovsdb_create(schema, storage);
    ovsdb_jsonrpc_server_add_db(server_config->jsonrpc, db->db);

    /* Enable txn history for clustered and relay modes.  It is not enabled for
     * other modes for now, since txn id is available for clustered and relay
     * modes only. */
    ovsdb_txn_history_init(db->db, model == SM_RELAY || model == SM_CLUSTERED);

    read_db(server_config, db);

    error = (db->db->name[0] == '_'
             ? ovsdb_error(NULL, "%s: names beginning with \"_\" are reserved",
                           db->db->name)
             : shash_find(server_config->all_dbs, db->db->name)
             ? ovsdb_error(NULL, "%s: duplicate database name", db->db->name)
             : NULL);
    if (error) {
        char *error_s = ovsdb_error_to_string(error);
        close_db(server_config, db,
                 xasprintf("cannot complete opening %s database (%s)",
                           db->db->name, error_s));
        free(error_s);
        return error;
    }

    add_db(server_config, db);

    if (model == SM_RELAY) {
        ovsdb_relay_add_db(db->db, conf->source, update_schema, server_config,
                           &conf->options->rpc);
    }
    if (model == SM_ACTIVE_BACKUP && conf->ab.backup) {
        const struct uuid *server_uuid;

        server_uuid = ovsdb_jsonrpc_server_get_uuid(server_config->jsonrpc);
        replication_set_db(db->db, conf->source, conf->ab.sync_exclude,
                           server_uuid, &conf->options->rpc);
    }
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
    /* We don't need txn_history for server_db. */

    db->filename = xstrdup("<internal>");
    db->config = xzalloc(sizeof *db->config);
    db->config->model = SM_UNDEFINED;
    db->db = ovsdb_create(schema, ovsdb_storage_create_unbacked(NULL));
    db->db->read_only = true;

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
                const char *key = json_string(datum->keys[i].s);
                if (key[0]) {
                    return key;
                }
            }
        }
        return NULL;
    }
}

static struct ovsdb_jsonrpc_options *
add_remote(struct shash *remotes, const char *target,
           const struct ovsdb_jsonrpc_options *options_)
{
    struct ovsdb_jsonrpc_options *options;

    options = shash_find_data(remotes, target);
    if (!options) {
        options = options_
                  ? ovsdb_jsonrpc_options_clone(options_)
                  : ovsdb_jsonrpc_default_options(target);
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

            ovsdb_jsonrpc_options_free(options);
        }
        shash_clear(remotes);
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

    options = add_remote(remotes, target, NULL);
    if (ovsdb_util_read_integer_column(row, "max_backoff", &max_backoff)) {
        options->rpc.max_backoff = max_backoff;
    }
    if (ovsdb_util_read_integer_column(row, "inactivity_probe",
                                       &probe_interval)) {
        options->rpc.probe_interval = probe_interval;
    }
    if (ovsdb_util_read_bool_column(row, "read_only", &read_only)) {
        options->read_only = read_only;
    }

    free(options->role);
    options->role = NULL;
    if (ovsdb_util_read_string_column(row, "role", &role) && role) {
        options->role = xstrdup(role);
    }

    options->rpc.dscp = DSCP_DEFAULT;
    dscp_string = ovsdb_util_read_map_string_column(row, "other_config",
                                                    "dscp");
    if (dscp_string) {
        int dscp = atoi(dscp_string);
        if (dscp >= 0 && dscp <= 63) {
            options->rpc.dscp = dscp;
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
                add_remote(remotes, json_string(datum->keys[i].s), NULL);
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
    ovsdb_txn_row_modify(txn, row, &rw_row, NULL);
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
                     const struct shash *remotes,
                     struct shash *all_dbs)
{
    struct shash_node *db_node;

    SHASH_FOR_EACH (db_node, all_dbs) {
        struct db *db = db_node->data;

        if (!db->db || ovsdb_storage_is_clustered(db->db->storage)) {
            continue;
        }

        struct ovsdb_txn *txn = ovsdb_txn_create(db->db);
        const struct shash_node *remote_node;

        SHASH_FOR_EACH (remote_node, remotes) {
            const char *remote = remote_node->name;

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
        db->db->is_relay ? "relay" : ovsdb_storage_get_model(db->db->storage));
    ovsdb_util_write_bool_column(row, "connected",
        db->db->is_relay ? ovsdb_relay_is_connected(db->db)
                         : ovsdb_storage_is_connected(db->db->storage));
    ovsdb_util_write_bool_column(row, "leader",
        db->db->is_relay ? false : ovsdb_storage_is_leader(db->db->storage));
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
    const struct ovsdb_row *row;
    HMAP_FOR_EACH_SAFE (row, hmap_node, &database_table->rows) {
        const char *name;
        ovsdb_util_read_string_column(row, "name", &name);
        struct db *db = shash_find_data(all_dbs, name);
        if (!db || !db->db) {
            ovsdb_txn_row_delete(txn, row);
        } else {
            struct ovsdb_row *rw_row;

            ovsdb_txn_row_modify(txn, row, &rw_row, NULL);
            update_database_status(rw_row, db);
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
                    const struct shash *all_dbs, struct shash *remotes)
{
    struct ds errors = DS_EMPTY_INITIALIZER;
    struct shash resolved_remotes;
    struct shash_node *node;

    /* Configure remotes. */
    shash_init(&resolved_remotes);
    SHASH_FOR_EACH (node, remotes) {
        const struct ovsdb_jsonrpc_options *options = node->data;
        const char *name = node->name;

        if (!strncmp(name, "db:", 3)) {
            query_db_remotes(name, all_dbs, &resolved_remotes, &errors);
        } else {
            add_remote(&resolved_remotes, name, options);
        }
    }
    ovsdb_jsonrpc_server_set_remotes(jsonrpc, &resolved_remotes);
    free_remotes(&resolved_remotes);
    shash_destroy(&resolved_remotes);

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
    const char *resolved_ssl_ciphersuites;
    const char *resolved_ssl_server_name;

    resolved_private_key = query_db_string(all_dbs, private_key_file, &errors);
    resolved_certificate = query_db_string(all_dbs, certificate_file, &errors);
    resolved_ca_cert = query_db_string(all_dbs, ca_cert_file, &errors);
    resolved_ssl_protocols = query_db_string(all_dbs, ssl_protocols, &errors);
    resolved_ssl_ciphers = query_db_string(all_dbs, ssl_ciphers, &errors);
    resolved_ssl_ciphersuites = query_db_string(all_dbs, ssl_ciphersuites,
                                                &errors);
    resolved_ssl_server_name = query_db_string(all_dbs, ssl_server_name,
                                               &errors);

    stream_ssl_set_key_and_cert(resolved_private_key, resolved_certificate);
    stream_ssl_set_ca_cert_file(resolved_ca_cert, bootstrap_ca_cert);
    stream_ssl_set_protocols(resolved_ssl_protocols);
    stream_ssl_set_ciphers(resolved_ssl_ciphers);
    stream_ssl_set_ciphersuites(resolved_ssl_ciphersuites);
    stream_ssl_set_server_name(resolved_ssl_server_name);

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

static bool
check_config_file_on_unixctl(struct unixctl_conn *conn)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    if (!config_file_path) {
        return false;
    }

    ds_put_format(&ds, "Update the %s and use ovsdb-server/reload instead",
                  config_file_path);
    unixctl_command_reply_error(conn, ds_cstr(&ds));
    ds_destroy(&ds);

    return true;
}

static void
ovsdb_server_set_active_ovsdb_server(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED, const char *argv[],
                                     void *config_)
{
    struct server_config *config = config_;
    struct shash_node *node;

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

    free(*config->sync_from);
    *config->sync_from = xstrdup(argv[1]);

    SHASH_FOR_EACH (node, config->all_dbs) {
        struct db *db = node->data;

        if (db->config->model == SM_ACTIVE_BACKUP) {
            free(db->config->source);
            db->config->source = xstrdup(argv[1]);
        }
    }

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
    struct shash_node *node;
    char *msg = NULL;

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

    if (!*config->sync_from) {
        msg = "Unable to connect: active server is not specified.\n";
    } else {
        const struct uuid *server_uuid;
        server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);

        SHASH_FOR_EACH (node, config->all_dbs) {
            struct db *db = node->data;
            struct db_config *conf = db->config;

            /* This command also converts standalone databases to AB. */
            if (conf->model == SM_STANDALONE) {
                conf->model = SM_ACTIVE_BACKUP;
                conf->source = xstrdup(*config->sync_from);
                conf->options = ovsdb_jsonrpc_default_options(conf->source);
                conf->options->rpc.probe_interval =
                    *config->replication_probe_interval;
                conf->ab.sync_exclude =
                    nullable_xstrdup(*config->sync_exclude);
                conf->ab.backup = false;
            }

            if (conf->model == SM_ACTIVE_BACKUP && !conf->ab.backup) {
                replication_set_db(db->db, conf->source, conf->ab.sync_exclude,
                                   server_uuid, &conf->options->rpc);
                conf->ab.backup = true;
            }
        }
        *config->is_backup = true;
        save_config(config);
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
    struct shash_node *node;

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

    SHASH_FOR_EACH (node, config->all_dbs) {
        struct db *db = node->data;
        struct db_config *conf = db->config;

        if (conf->model == SM_ACTIVE_BACKUP && conf->ab.backup) {
            ovsdb_server_replication_remove_db(db);
        }
    }
    *config->is_backup = false;
    save_config(config);
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_server_set_active_ovsdb_server_probe_interval(struct unixctl_conn *conn,
                                                   int argc OVS_UNUSED,
                                                   const char *argv[],
                                                   void *config_)
{
    struct server_config *config = config_;
    struct shash_node *node;
    int probe_interval;

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

    if (!str_to_int(argv[1], 10, &probe_interval)) {
        unixctl_command_reply_error(
            conn, "Invalid probe interval, integer value expected");
        return;
    }

    const struct uuid *server_uuid;
    server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);

    *config->replication_probe_interval = probe_interval;

    SHASH_FOR_EACH (node, config->all_dbs) {
        struct db *db = node->data;
        struct db_config *conf = db->config;

        if (conf->model == SM_ACTIVE_BACKUP) {
            conf->options->rpc.probe_interval = probe_interval;
            if (conf->ab.backup) {
                replication_set_db(db->db, conf->source, conf->ab.sync_exclude,
                                   server_uuid, &conf->options->rpc);
            }
        }
    }

    save_config(config);
    unixctl_command_reply(conn, NULL);
}

static void
ovsdb_server_set_relay_source_interval(struct unixctl_conn *conn,
                                       int argc OVS_UNUSED,
                                       const char *argv[],
                                       void *config_)
{
    struct server_config *config = config_;
    struct shash_node *node;
    int probe_interval;

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

    if (!str_to_int(argv[1], 10, &probe_interval)) {
        unixctl_command_reply_error(
            conn, "Invalid probe interval, integer value expected");
        return;
    }

    *config->relay_source_probe_interval = probe_interval;

    SHASH_FOR_EACH (node, config->all_dbs) {
        struct db *db = node->data;
        struct db_config *conf = db->config;

        if (conf->model == SM_RELAY) {
            conf->options->rpc.probe_interval = probe_interval;
        }
    }

    ovsdb_relay_set_probe_interval(probe_interval);
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
    struct shash_node *node;

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

    char *err = parse_excluded_tables(argv[1]);
    if (err) {
        goto exit;
    }

    const struct uuid *server_uuid;
    server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);

    free(*config->sync_exclude);
    *config->sync_exclude = xstrdup(argv[1]);

    SHASH_FOR_EACH (node, config->all_dbs) {
        struct db *db = node->data;
        struct db_config *conf = db->config;

        if (conf->model == SM_ACTIVE_BACKUP) {
            free(conf->ab.sync_exclude);
            conf->ab.sync_exclude = xstrdup(argv[1]);
            if (conf->ab.backup) {
                replication_set_db(db->db, conf->source, conf->ab.sync_exclude,
                                   server_uuid, &conf->options->rpc);
            }
        }
    }

    save_config(config);

exit:
    unixctl_command_reply(conn, err);
    free(err);
}

static void
ovsdb_server_get_sync_exclude_tables(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED,
                                     const char *argv[] OVS_UNUSED,
                                     void *config_)
{
    struct server_config *config = config_;

    unixctl_command_reply(conn, *config->sync_exclude);
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
        jsonrpc, true, xstrdup("user ran ovsdb-server/disable-monitor-cond"));
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
                struct ovsdb_error *error = NULL;

                VLOG_INFO("compacting %s database by user request",
                          node->name);

                error = ovsdb_snapshot(db->db, trim_memory);
                if (!error && ovsdb_snapshot_in_progress(db->db)) {
                    while (ovsdb_snapshot_in_progress(db->db)) {
                        ovsdb_snapshot_wait(db->db);
                        poll_block();
                    }
                    error = ovsdb_snapshot(db->db, trim_memory);
                }

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

/* "ovsdb-server/memory-trim-on-compaction": controls whether ovsdb-server
 * tries to reclaim heap memory back to system using malloc_trim() after
 * compaction.  */
static void
ovsdb_server_memory_trim_on_compaction(struct unixctl_conn *conn,
                                       int argc OVS_UNUSED,
                                       const char *argv[],
                                       void *arg OVS_UNUSED)
{
    bool old_trim_memory = trim_memory;
    static bool have_logged = false;
    const char *command = argv[1];

#if !HAVE_DECL_MALLOC_TRIM
    unixctl_command_reply_error(conn, "memory trimming is not supported");
    return;
#endif

    if (!strcmp(command, "on")) {
        trim_memory = true;
    } else if (!strcmp(command, "off")) {
        trim_memory = false;
    } else {
        unixctl_command_reply_error(conn, "invalid argument");
        return;
    }
    if (!have_logged || (trim_memory != old_trim_memory)) {
        have_logged = true;
        VLOG_INFO("memory trimming after compaction %s.",
                  trim_memory ? "enabled" : "disabled");
    }
    unixctl_command_reply(conn, NULL);
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

/* "ovsdb-server/reload": makes ovsdb-server open a configuration file on
 * 'config_file_path', read it and sync the runtime configuration with it. */
static void
ovsdb_server_reload(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *config_)
{
    struct server_config *config = config_;

    if (!config_file_path) {
        unixctl_command_reply_error(conn,
            "Configuration file was not specified on command line");
        return;
    }

    if (!reconfigure_ovsdb_server(config)) {
        unixctl_command_reply_error(conn,
            "Configuration failed.  See the log file for details.");
    } else {
        unixctl_command_reply(conn, NULL);
    }
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

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

    retval = (strncmp("db:", remote, 3)
              ? NULL
              : parse_db_column(config->all_dbs, remote,
                                &db, &table, &column));
    if (!retval) {
        if (add_remote(config->remotes, remote, NULL)) {
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
    struct ovsdb_jsonrpc_options *options;

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

    options = shash_find_and_delete(config->remotes, argv[1]);
    if (options) {
        ovsdb_jsonrpc_options_free(options);
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
    const struct shash *remotes = remotes_;
    const struct shash_node **list;
    struct ds s;

    ds_init(&s);

    list = shash_sort(remotes);
    for (size_t i = 0; i < shash_count(remotes); i++) {
        ds_put_format(&s, "%s\n", list[i]->name);
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
    const struct shash_node *node;
    struct shash db_conf;

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

    shash_init(&db_conf);
    add_database_config(&db_conf, filename, *config->sync_from,
                        *config->sync_exclude, !config->is_backup);
    ovs_assert(shash_count(&db_conf) == 1);
    node = shash_first(&db_conf);

    char *error = ovsdb_error_to_string_free(open_db(config,
                                                     node->name, node->data));
    if (!error) {
        save_config(config);
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply_error(conn, error);
        free(error);
    }
    db_config_destroy(node->data);
    shash_destroy(&db_conf);
}

static void
remove_db(struct server_config *config, struct shash_node *node, char *comment)
{
    struct db *db = node->data;

    close_db(config, db, comment);
    shash_delete(config->all_dbs, node);

    save_config(config);
}

static void
ovsdb_server_remove_database(struct unixctl_conn *conn, int argc OVS_UNUSED,
                             const char *argv[], void *config_)
{
    struct server_config *config = config_;
    struct shash_node *node;

    if (check_config_file_on_unixctl(conn)) {
        return;
    }

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
ovsdb_server_tlog_set(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[], void *all_dbs_)
{
    struct shash *all_dbs = all_dbs_;
    const char *name_ = argv[1];
    const char *command = argv[2];
    bool log;

    if (!strcasecmp(command, "on")) {
        log = true;
    } else if (!strcasecmp(command, "off")) {
        log = false;
    } else {
        unixctl_command_reply_error(conn, "invalid command argument");
        return;
    }

    char *name = xstrdup(name_);
    char *save_ptr = NULL;

    const char *db_name = strtok_r(name, ":", &save_ptr); /* "DB" */
    const char *tbl_name = strtok_r(NULL, ":", &save_ptr); /* "TABLE" */
    if (!db_name || !tbl_name || strtok_r(NULL, ":", &save_ptr)) {
        unixctl_command_reply_error(conn, "invalid DB:TABLE argument");
        goto out;
    }

    struct db *db = shash_find_data(all_dbs, db_name);
    if (!db) {
        unixctl_command_reply_error(conn, "no such database");
        goto out;
    }

    struct ovsdb_table *table = ovsdb_get_table(db->db, tbl_name);
    if (!table) {
        unixctl_command_reply_error(conn, "no such table");
        goto out;
    }

    ovsdb_table_logging_enable(table, log);
    unixctl_command_reply(conn, NULL);
out:
    free(name);
}

static void
ovsdb_server_tlog_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[] OVS_UNUSED, void *all_dbs_)
{
    const struct shash_node **db_nodes;
    struct ds s = DS_EMPTY_INITIALIZER;
    struct shash *all_dbs = all_dbs_;

    ds_put_cstr(&s, "database        table                       logging\n");
    ds_put_cstr(&s, "--------        -----                       -------\n");

    db_nodes = shash_sort(all_dbs);
    for (size_t i = 0; i < shash_count(all_dbs); i++) {
        const struct shash_node *db_node = db_nodes[i];
        struct db *db = db_node->data;
        if (db->db) {
            const struct shash_node **tbl_nodes = shash_sort(&db->db->tables);

            ds_put_format(&s, "%-16s \n", db_node->name);
            for (size_t j = 0; j < shash_count(&db->db->tables); j++) {
                const char *logging_enabled =
                    ovsdb_table_is_logging_enabled(tbl_nodes[j]->data)
                    ? "ON" : "OFF";
                ds_put_format(&s, "                %-27s %s\n",
                              tbl_nodes[j]->name, logging_enabled);
            }
            free(tbl_nodes);
        }
    }
    free(db_nodes);

    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}

static void
ovsdb_server_get_sync_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                             const char *argv[] OVS_UNUSED, void *config_)
{
    struct server_config *config = config_;
    struct ds ds = DS_EMPTY_INITIALIZER;
    bool any_backup = false;

    const struct shash_node **db_nodes = shash_sort(config->all_dbs);

    for (size_t i = 0; i < shash_count(config->all_dbs); i++) {
        const struct db *db = db_nodes[i]->data;

        if (db->config->model != SM_ACTIVE_BACKUP) {
            continue;
        }

        any_backup = true;

        ds_put_format(&ds, "database: %s\n", db->db->name);
        ds_put_format(&ds, "state: %s\n",
                      db->config->ab.backup ? "backup" : "active");
        if (db->config->ab.backup) {
            ds_put_and_free_cstr(&ds, replication_status(db->db));
        }
        if (i + 1 < shash_count(config->all_dbs)) {
            ds_put_char(&ds, '\n');
        }
    }
    free(db_nodes);

    if (!any_backup) {
        ds_put_cstr(&ds, "state: active\n");
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ovsdb_server_get_db_storage_status(struct unixctl_conn *conn,
                                   int argc OVS_UNUSED,
                                   const char *argv[],
                                   void *config_)
{
    struct server_config *config = config_;
    struct shash_node *node;

    node = shash_find(config->all_dbs, argv[1]);
    if (!node) {
        unixctl_command_reply_error(conn, "Failed to find the database.");
        return;
    }

    struct db *db = node->data;

    if (!db->db) {
        unixctl_command_reply_error(conn, "Failed to find the database.");
        return;
    }

    struct ds ds = DS_EMPTY_INITIALIZER;
    char *error = ovsdb_storage_get_error(db->db->storage);

    if (!error) {
        ds_put_cstr(&ds, "status: ok");
    } else {
        ds_put_format(&ds, "status: %s", error);
        free(error);
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
parse_options(int argc, char *argv[],
              struct shash *db_conf, struct shash *remotes,
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
        OPT_FILE_COLUMN_DIFF,
        OPT_FILE_NO_DATA_CONVERSION,
        OPT_CONFIG_FILE,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
        OVS_REPLAY_OPTION_ENUMS,
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
        OVS_REPLAY_LONG_OPTIONS,
        {"sync-from",   required_argument, NULL, OPT_SYNC_FROM},
        {"sync-exclude-tables", required_argument, NULL, OPT_SYNC_EXCLUDE},
        {"active", no_argument, NULL, OPT_ACTIVE},
        {"no-dbs", no_argument, NULL, OPT_NO_DBS},
        {"disable-file-column-diff", no_argument, NULL, OPT_FILE_COLUMN_DIFF},
        {"disable-file-no-data-conversion", no_argument, NULL,
         OPT_FILE_NO_DATA_CONVERSION},
        {"config-file", required_argument, NULL, OPT_CONFIG_FILE},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);
    bool add_default_db = true;

    *sync_from = NULL;
    *sync_exclude = NULL;
    shash_init(db_conf);
    shash_init(remotes);
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_REMOTE:
            add_remote(remotes, optarg, NULL);
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

        case OPT_SSL_CIPHERSUITES:
            ssl_ciphersuites = optarg;
            break;

        case OPT_SSL_SERVER_NAME:
            ssl_server_name = optarg;
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            ca_cert_file = optarg;
            bootstrap_ca_cert = true;
            break;

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        OVS_REPLAY_OPTION_HANDLERS

        case OPT_SYNC_FROM:
            *sync_from = xstrdup(optarg);
            break;

        case OPT_SYNC_EXCLUDE: {
            char *err = parse_excluded_tables(optarg);
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

        case OPT_FILE_COLUMN_DIFF:
            ovsdb_file_column_diff_disable();
            break;

        case OPT_FILE_NO_DATA_CONVERSION:
            ovsdb_no_data_conversion_disable();
            break;

        case OPT_CONFIG_FILE:
            free(config_file_path);
            config_file_path = abs_file_name(ovs_dbdir(), optarg);
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

    if (config_file_path) {
        if (*sync_from || *sync_exclude || *active) {
            ovs_fatal(0, "--config-file is mutually exclusive with "
                         "--sync-from, --sync-exclude and --active");
        }
        if (shash_count(remotes)) {
            ovs_fatal(0, "--config-file is mutually exclusive with --remote");
        }
        if (argc > 0) {
            ovs_fatal(0, "Databases should be specified in a config file");
        }
    } else if (argc > 0) {
        for (int i = 0; i < argc; i++) {
            add_database_config(db_conf, argv[i], *sync_from, *sync_exclude,
                                *active);
        }
    } else if (add_default_db) {
        char *filename = xasprintf("%s/conf.db", ovs_dbdir());

        add_database_config(db_conf, filename, *sync_from, *sync_exclude,
                            *active);
        free(filename);
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
    printf("\nConfiguration file:\n"
           "  --config-file PATH      Use configuration file as a source of\n"
           "                          database and JSON-RPC configuration.\n"
           "                          Mutually exclusive with the DATABASE,\n"
           "                          JSON-RPC and Syncing options.\n"
           "                          Assumes --no-dbs.\n");
    daemon_usage();
    vlog_usage();
    replication_usage();
    ovs_replay_usage();
    printf("\nOther options:\n"
           "  --run COMMAND           run COMMAND as subprocess then exit\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  --no-dbs                do not add default database\n"
           "  --disable-file-column-diff\n"
           "                          don't use column diff in database file\n"
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

static struct json *
remotes_to_json(const struct shash *remotes)
{
    const struct shash_node *node;
    struct json *json;

    json = json_object_create();
    SHASH_FOR_EACH (node, remotes) {
        json_object_put(json, node->name,
                        ovsdb_jsonrpc_options_to_json(node->data, false));
    }
    return json;
}

static struct json *
db_config_to_json(const struct db_config *conf)
{
    struct json *json;

    json = json_object_create();

    if (conf->model != SM_UNDEFINED) {
        json_object_put(json, "service-model",
                        json_string_create(
                            service_model_to_string(conf->model)));
    }

    if (conf->source) {
        struct json *source = json_object_create();

        json_object_put(source, conf->source,
                        ovsdb_jsonrpc_options_to_json(conf->options, true));
        json_object_put(json, "source", source);
    }

    if (conf->model == SM_ACTIVE_BACKUP) {
        if (conf->ab.sync_exclude) {
            struct sset set = SSET_INITIALIZER(&set);

            sset_from_delimited_string(&set, conf->ab.sync_exclude, " ,");
            json_object_put(json, "exclude-tables", sset_to_json(&set));
            sset_destroy(&set);
        }
        json_object_put(json, "backup", json_boolean_create(conf->ab.backup));
    }
    return json;
}

static struct json *
databases_to_json(const struct shash *db_conf)
{
    const struct shash_node *node;
    struct json *json;

    json = json_object_create();
    SHASH_FOR_EACH (node, db_conf) {
        json_object_put(json, node->name, db_config_to_json(node->data));
    }
    return json;
}

/* Truncates and replaces the contents of 'config_file' by a representation of
 * 'remotes', 'db_conf' and a few global replication paramaters. */
static void
save_config__(FILE *config_file, const struct shash *remotes,
              const struct shash *db_conf, const char *sync_from,
              const char *sync_exclude, bool is_backup)
{
    struct json *obj;
    char *s;

    if (ftruncate(fileno(config_file), 0) == -1) {
        VLOG_FATAL("failed to truncate temporary file (%s)",
                   ovs_strerror(errno));
    }

    obj = json_object_create();
    json_object_put(obj, "remotes", remotes_to_json(remotes));
    json_object_put(obj, "databases", databases_to_json(db_conf));

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
    struct shash_node *node;
    struct shash db_conf;

    if (config_file_path) {
        return;
    }

    shash_init(&db_conf);
    SHASH_FOR_EACH (node, config->all_dbs) {
        struct db *db = node->data;

        if (node->name[0] != '_') {
            shash_add(&db_conf, db->filename, db->config);
        }
    }

    save_config__(config->config_tmpfile, config->remotes, &db_conf,
                  *config->sync_from, *config->sync_exclude,
                  *config->is_backup);

    shash_destroy(&db_conf);
}

static bool
remotes_from_json(struct shash *remotes, const struct json *json)
{
    struct ovsdb_jsonrpc_options *options;
    const struct shash_node *node;
    const struct shash *object;

    free_remotes(remotes);

    ovs_assert(json);
    if (json->type == JSON_NULL) {
        return true;
    }
    if (json->type != JSON_OBJECT) {
        VLOG_WARN("config: 'remotes' is not a JSON object");
        return false;
    }

    object = json_object(json);
    SHASH_FOR_EACH (node, object) {
        options = ovsdb_jsonrpc_default_options(node->name);
        shash_add(remotes, node->name, options);

        json = node->data;
        if (json->type == JSON_OBJECT) {
            ovsdb_jsonrpc_options_update_from_json(options, node->data, false);
        } else if (json->type != JSON_NULL) {
            VLOG_WARN("%s: JSON-RPC options are not a JSON object or null",
                      node->name);
            free_remotes(remotes);
            return false;
        }
    }

    return true;
}

static struct db_config *
db_config_from_json(const char *name, const struct json *json)
{
    const struct json *model, *source, *sync_exclude, *backup;
    struct db_config *conf = xzalloc(sizeof *conf);
    struct ovsdb_parser parser;
    struct ovsdb_error *error;

    conf->model = SM_UNDEFINED;

    ovs_assert(json);
    if (json->type == JSON_NULL) {
        return conf;
    }

    ovsdb_parser_init(&parser, json, "database %s", name);

    model = ovsdb_parser_member(&parser, "service-model",
                                OP_STRING | OP_OPTIONAL);
    if (model) {
        conf->model = service_model_from_string(json_string(model));
        if (conf->model == SM_UNDEFINED) {
            ovsdb_parser_raise_error(&parser,
                "'%s' is not a valid service model", json_string(model));
        }
    }

    if (conf->model == SM_ACTIVE_BACKUP) {
        backup = ovsdb_parser_member(&parser, "backup", OP_BOOLEAN);
        conf->ab.backup = backup ? json_boolean(backup) : false;

        sync_exclude = ovsdb_parser_member(&parser, "exclude-tables",
                                           OP_ARRAY | OP_OPTIONAL);
        if (sync_exclude) {
            struct sset set = SSET_INITIALIZER(&set);
            size_t n = json_array_size(sync_exclude);

            for (size_t i = 0; i < n; i++) {
                const struct json *exclude = json_array_at(sync_exclude, i);

                if (exclude->type != JSON_STRING) {
                    ovsdb_parser_raise_error(&parser,
                        "'exclude-tables' must contain strings");
                    break;
                }
                sset_add(&set, json_string(exclude));
            }
            conf->ab.sync_exclude = sset_join(&set, ",", "");
            sset_destroy(&set);
        }
    }

    if (conf->model == SM_ACTIVE_BACKUP || conf->model == SM_RELAY) {
        enum ovsdb_parser_types type = OP_OBJECT;

        if (conf->model == SM_ACTIVE_BACKUP && !conf->ab.backup) {
            /* Active database doesn't have to have a source. */
            type |= OP_OPTIONAL;
        }
        source = ovsdb_parser_member(&parser, "source", type);

        if (source && shash_count(json_object(source)) != 1) {
            ovsdb_parser_raise_error(&parser,
                "'source' should be an object with exactly one element");
        } else if (source) {
            const struct shash_node *node = shash_first(json_object(source));
            const struct json *options;

            ovs_assert(node);
            conf->source = xstrdup(node->name);
            options = node->data;

            conf->options = get_jsonrpc_options(conf->source, conf->model);

            if (options->type == JSON_OBJECT) {
                ovsdb_jsonrpc_options_update_from_json(conf->options,
                                                       options, true);
            } else if (options->type != JSON_NULL) {
                ovsdb_parser_raise_error(&parser,
                    "JSON-RPC options is not a JSON object or null");
            }
        }
    }

    error = ovsdb_parser_finish(&parser);
    if (error) {
        char *s = ovsdb_error_to_string_free(error);

        VLOG_WARN("%s", s);
        free(s);
        db_config_destroy(conf);
        return NULL;
    }

    return conf;
}


static bool
databases_from_json(struct shash *db_conf, const struct json *json)
{
    const struct shash_node *node;
    const struct shash *object;

    free_database_configs(db_conf);

    ovs_assert(json);
    if (json->type == JSON_NULL) {
        return true;
    }
    if (json->type != JSON_OBJECT) {
        VLOG_WARN("config: 'databases' is not a JSON object or null");
    }

    object = json_object(json);
    SHASH_FOR_EACH (node, object) {
        struct db_config *conf = db_config_from_json(node->name, node->data);

        if (conf) {
            shash_add(db_conf, node->name, conf);
        } else {
            free_database_configs(db_conf);
            return false;
        }
    }
    return true;
}

/* Clears and replaces 'remotes' and 'db_conf' by a configuration read from
 * 'config_file', which must have been previously written by save_config()
 * or provided by the user with --config-file.
 * Returns 'true', if parsing was successful, 'false' otherwise. */
static bool
load_config(FILE *config_file, struct shash *remotes,
            struct shash *db_conf, char **sync_from,
            char **sync_exclude, bool *is_backup)
{
    struct json *json;

    if (fseek(config_file, 0, SEEK_SET) != 0) {
        VLOG_WARN("config: file seek failed (%s)", ovs_strerror(errno));
        return false;
    }
    json = json_from_stream(config_file);
    if (json->type == JSON_STRING) {
        VLOG_WARN("config: reading JSON failed (%s)", json_string(json));
        json_destroy(json);
        return false;
    }
    if (json->type != JSON_OBJECT) {
        VLOG_WARN("configuration in a file must be a JSON object");
        json_destroy(json);
        return false;
    }

    if (!remotes_from_json(remotes,
                           shash_find_data(json_object(json), "remotes"))) {
        VLOG_WARN("config: failed to parse 'remotes'");
        json_destroy(json);
        return false;
    }
    if (!databases_from_json(db_conf, shash_find_data(json_object(json),
                                                      "databases"))) {
        VLOG_WARN("config: failed to parse 'databases'");
        free_remotes(remotes);
        json_destroy(json);
        return false;
    }

    struct json *string;
    string = shash_find_data(json_object(json), "sync_from");
    free(*sync_from);
    *sync_from = string ? xstrdup(json_string(string)) : NULL;

    string = shash_find_data(json_object(json), "sync_exclude");
    free(*sync_exclude);
    *sync_exclude = string ? xstrdup(json_string(string)) : NULL;

    struct json *boolean = shash_find_data(json_object(json), "is_backup");
    *is_backup = boolean ? json_boolean(boolean) : false;

    json_destroy(json);
    return true;
}
