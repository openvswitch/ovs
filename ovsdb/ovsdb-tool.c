/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016, 2017 Nicira, Inc.
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
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "column.h"
#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "file.h"
#include "hash.h"
#include "lockfile.h"
#include "log.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "raft.h"
#include "raft-private.h"
#include "smap.h"
#include "socket-util.h"
#include "storage.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "util.h"
#include "openvswitch/vlog.h"

/* -m, --more: Verbosity level for "show-log" command output. */
static int show_log_verbosity;

/* --role: RBAC role to use for "transact" and "query" commands. */
static const char *rbac_role;

/* --cid: Cluster ID for "join-cluster" command. */
static struct uuid cid;

/* --election-timer: Election timer for "create-cluster" command. */
static uint64_t election_timer;

static const struct ovs_cmdl_command *get_all_commands(void);

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);

static const char *default_db(void);
static const char *default_schema(void);

int
main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = { .argc = 0, };
    set_program_name(argv[0]);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();
    fatal_signal_init();
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, get_all_commands());
    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_RBAC_ROLE = UCHAR_MAX + 1,
        OPT_CID,
        OPT_ELECTION_TIMER,
    };
    static const struct option long_options[] = {
        {"more", no_argument, NULL, 'm'},
        {"rbac-role", required_argument, NULL, OPT_RBAC_ROLE},
        {"cid", required_argument, NULL, OPT_CID},
        {"election-timer", required_argument, NULL, OPT_ELECTION_TIMER},
        {"verbose", optional_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {"option", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        struct ovsdb_error *error;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'm':
            show_log_verbosity++;
            break;

        case OPT_RBAC_ROLE:
            rbac_role = optarg;
            break;

        case OPT_CID:
            if (!uuid_from_string(&cid, optarg) || uuid_is_zero(&cid)) {
                ovs_fatal(0, "%s: not a valid UUID", optarg);
            }
            break;

        case OPT_ELECTION_TIMER:
            election_timer = atoll(optarg);
            error = raft_validate_election_timer(election_timer);
            if (error) {
                ovs_fatal(0, "%s", ovsdb_error_to_string_free(error));
            }
            break;

        case 'h':
            usage();

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: Open vSwitch database management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "  create [DB [SCHEMA]]    create DB with the given SCHEMA\n"
           "  [--election-timer=ms] create-cluster DB CONTENTS LOCAL\n"
           "    create clustered DB with given CONTENTS and LOCAL address\n"
           "  [--cid=UUID] join-cluster DB NAME LOCAL REMOTE...\n"
           "    join clustered DB with given NAME and LOCAL and REMOTE addrs\n"
           "  compact [DB [DST]]      compact DB in-place (or to DST)\n"
           "  convert [DB [SCHEMA [DST]]]   convert DB to SCHEMA (to DST)\n"
           "  db-name [DB]            report name of schema used by DB\n"
           "  db-version [DB]         report version of schema used by DB\n"
           "  db-cksum [DB]           report checksum of schema used by DB\n"
           "  db-cid DB               report cluster ID of clustered DB\n"
           "  db-sid DB               report server ID of clustered DB\n"
           "  db-local-address DB     report local address of clustered DB\n"
           "  db-is-clustered DB      test whether DB is clustered\n"
           "  db-is-standalone DB     test whether DB is standalone\n"
           "  schema-name [SCHEMA]    report SCHEMA's name\n"
           "  schema-version [SCHEMA] report SCHEMA's schema version\n"
           "  schema-cksum [SCHEMA]   report SCHEMA's checksum\n"
           "  compare-versions A OP B  compare OVSDB schema version numbers\n"
           "  query [DB] TRNS         execute read-only transaction on DB\n"
           "  transact [DB] TRNS      execute read/write transaction on DB\n"
           "  cluster-to-standalone DB DB    Convert clustered DB to\n"
           "      standalone DB when cluster is down and cannot be\n"
           "        revived\n"
           "  [-m]... show-log [DB]   print DB's log entries\n"
           "The default DB is %s.\n"
           "The default SCHEMA is %s.\n",
           program_name, program_name, default_db(), default_schema());
    vlog_usage();
    printf("\
\nOther options:\n\
  -m, --more                  increase show-log verbosity\n\
  --rbac-role=ROLE            RBAC role for transact and query commands\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static const char *
default_db(void)
{
    static char *db;
    if (!db) {
        db = xasprintf("%s/conf.db", ovs_dbdir());
    }
    return db;
}

static const char *
default_schema(void)
{
    static char *schema;
    if (!schema) {
        schema = xasprintf("%s/vswitch.ovsschema", ovs_pkgdatadir());
    }
    return schema;
}

static struct json *
parse_json(const char *s)
{
    struct json *json = json_from_string(s);
    if (json->type == JSON_STRING) {
        ovs_fatal(0, "\"%s\": %s", s, json->string);
    }
    return json;
}

static void
print_and_free_json(struct json *json)
{
    char *string = json_to_string(json, JSSF_SORT);
    json_destroy(json);
    puts(string);
    free(string);
}

static void
check_ovsdb_error(struct ovsdb_error *error)
{
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string(error));
    }
}

/* Opens the standalone database 'filename' and returns its schema. */
static struct ovsdb_schema *
read_standalone_schema(const char *filename)
{
    struct ovsdb_storage *storage = ovsdb_storage_open_standalone(filename,
                                                                  false);
    struct ovsdb_schema *schema = ovsdb_storage_read_schema(storage);
    ovsdb_storage_close(storage);
    return schema;
}

static void
do_create(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    const char *schema_file_name = ctx->argc >= 3 ? ctx->argv[2] : default_schema();
    struct ovsdb_schema *schema;
    struct ovsdb_log *log;
    struct json *json;

    /* Read schema from file and convert to JSON. */
    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    json = ovsdb_schema_to_json(schema);
    ovsdb_schema_destroy(schema);

    /* Create database file. */
    check_ovsdb_error(ovsdb_log_open(db_file_name, OVSDB_MAGIC,
                                     OVSDB_LOG_CREATE_EXCL, -1, &log));
    check_ovsdb_error(ovsdb_log_write_and_free(log, json));
    check_ovsdb_error(ovsdb_log_commit_block(log));
    ovsdb_log_close(log);
}

static void
do_create_cluster(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    const char *src_file_name = ctx->argv[2];
    const char *local = ctx->argv[3];

    struct ovsdb_schema *schema;
    struct json *data;

    struct ovsdb_error *error = ovsdb_schema_from_file(src_file_name, &schema);
    if (!error) {
        /* It's just a schema file. */
        data = json_object_create();
    } else {
        /* Not a schema file.  Try reading it as a standalone database. */
        ovsdb_error_destroy(error);

        struct ovsdb *ovsdb = ovsdb_file_read(src_file_name, false);
        char *comment = xasprintf("created from %s", src_file_name);
        data = ovsdb_to_txn_json(ovsdb, comment);
        free(comment);
        schema = ovsdb_schema_clone(ovsdb->schema);
        ovsdb_destroy(ovsdb);
    }

    ovsdb_schema_persist_ephemeral_columns(schema, src_file_name);

    struct json *schema_json = ovsdb_schema_to_json(schema);

    /* Create database file. */
    struct json *snapshot = json_array_create_2(schema_json, data);
    check_ovsdb_error(raft_create_cluster(db_file_name, schema->name,
                                          local, snapshot, election_timer));
    ovsdb_schema_destroy(schema);
    json_destroy(snapshot);
}

static void
do_join_cluster(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    const char *name = ctx->argv[2];
    const char *local = ctx->argv[3];

    /* Check for a plausible 'name'. */
    if (!ovsdb_parser_is_id(name)) {
        ovs_fatal(0, "%s: not a valid schema name (use \"schema-name\" "
                  "command to find the correct name)", name);
    }

    /* Create database file. */
    struct sset remote_addrs = SSET_INITIALIZER(&remote_addrs);
    for (size_t i = 4; i < ctx->argc; i++) {
        sset_add(&remote_addrs, ctx->argv[i]);
    }
    check_ovsdb_error(raft_join_cluster(db_file_name, name, local,
                                        &remote_addrs,
                                        uuid_is_zero(&cid) ? NULL : &cid));
    sset_destroy(&remote_addrs);
}

static struct ovsdb_error *
write_standalone_db(const char *file_name, const char *comment,
                    const struct ovsdb *db)
{
    struct ovsdb_log *log;
    struct ovsdb_error *error = ovsdb_log_open(file_name, OVSDB_MAGIC,
                                               OVSDB_LOG_CREATE, false, &log);
    if (error) {
        return error;
    }

    error = ovsdb_log_write_and_free(log, ovsdb_schema_to_json(db->schema));
    if (!error) {
        error = ovsdb_log_write_and_free(log, ovsdb_to_txn_json(db, comment));
    }
    ovsdb_log_close(log);

    if (error) {
        remove(file_name);
    }
    return error;
}

/* Reads 'src_name' and writes it back, compacted, to 'dst_name', adding the
 * specified 'comment'.  If 'new_schema' is nonull, converts the databse to
 * that schema.
 *
 * Standalone databases only. */
static void
compact_or_convert(const char *src_name_, const char *dst_name_,
                   struct ovsdb_schema *new_schema, const char *comment)
{
    bool in_place = dst_name_ == NULL;

    /* Dereference symlinks for source and destination names.  In the in-place
     * case this ensures that, if the source name is a symlink, we replace its
     * target instead of replacing the symlink by a regular file.  In the
     * non-in-place, this has the same effect for the destination name. */
    char *src_name = follow_symlinks(src_name_);
    char *dst_name = (in_place
                      ? xasprintf("%s.tmp", src_name)
                      : follow_symlinks(dst_name_));

    /* Lock the source, if we will be replacing it. */
    struct lockfile *src_lock = NULL;
    if (in_place) {
        int retval = lockfile_lock(src_name, &src_lock);
        if (retval) {
            ovs_fatal(retval, "%s: failed to lock lockfile", src_name);
        }
    }

    /* Get (temporary) destination and lock it. */
    struct lockfile *dst_lock = NULL;
    int retval = lockfile_lock(dst_name, &dst_lock);
    if (retval) {
        ovs_fatal(retval, "%s: failed to lock lockfile", dst_name);
    }

    /* Resulted DB will contain a single transaction without diff anyway. */
    ovsdb_file_column_diff_disable();

    /* Save a copy. */
    struct ovsdb *ovsdb = (new_schema
                           ? ovsdb_file_read_as_schema(src_name, new_schema)
                           : ovsdb_file_read(src_name, false));
    ovsdb_storage_close(ovsdb->storage);
    ovsdb->storage = NULL;
    check_ovsdb_error(write_standalone_db(dst_name, comment, ovsdb));
    ovsdb_destroy(ovsdb);

    /* Replace source. */
    if (in_place) {
#ifdef _WIN32
        unlink(src_name);
#endif
        if (rename(dst_name, src_name)) {
            ovs_fatal(errno, "failed to rename \"%s\" to \"%s\"",
                      dst_name, src_name);
        }
        fsync_parent_dir(dst_name);
        lockfile_unlock(src_lock);
    }

    lockfile_unlock(dst_lock);

    free(src_name);
    free(dst_name);
}

static void
do_compact(struct ovs_cmdl_context *ctx)
{
    const char *db = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    const char *target = ctx->argc >= 3 ? ctx->argv[2] : NULL;

    compact_or_convert(db, target, NULL, "compacted by ovsdb-tool "VERSION);
}

static void
do_convert(struct ovs_cmdl_context *ctx)
{
    const char *db = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    const char *schema = ctx->argc >= 3 ? ctx->argv[2] : default_schema();
    const char *target = ctx->argc >= 4 ? ctx->argv[3] : NULL;
    struct ovsdb_schema *new_schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema, &new_schema));
    compact_or_convert(db, target, new_schema,
                       "converted by ovsdb-tool "VERSION);
}

static void
do_needs_conversion(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    const char *schema_file_name = ctx->argc >= 3 ? ctx->argv[2] : default_schema();
    struct ovsdb_schema *schema1 = read_standalone_schema(db_file_name);
    struct ovsdb_schema *schema2;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema2));
    puts(ovsdb_schema_equal(schema1, schema2) ? "no" : "yes");
    ovsdb_schema_destroy(schema1);
    ovsdb_schema_destroy(schema2);
}

static void
do_db_name(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();

    struct ovsdb_log *log;
    check_ovsdb_error(ovsdb_log_open(db_file_name, OVSDB_MAGIC"|"RAFT_MAGIC,
                                     OVSDB_LOG_READ_ONLY, -1, &log));
    if (!strcmp(ovsdb_log_get_magic(log), OVSDB_MAGIC)) {
        struct json *schema_json;
        check_ovsdb_error(ovsdb_log_read(log, &schema_json));

        struct ovsdb_schema *schema;
        check_ovsdb_error(ovsdb_schema_from_json(schema_json, &schema));

        puts(schema->name);

        ovsdb_schema_destroy(schema);
        json_destroy(schema_json);
    } else if (!strcmp(ovsdb_log_get_magic(log), RAFT_MAGIC)) {
        struct raft_metadata md;
        check_ovsdb_error(raft_read_metadata(log, &md));
        puts(md.name);
        raft_metadata_destroy(&md);
    } else {
        OVS_NOT_REACHED();
    }

    ovsdb_log_close(log);
}

static void
do_db_version(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    struct ovsdb_schema *schema = read_standalone_schema(db_file_name);

    puts(schema->version);
    ovsdb_schema_destroy(schema);
}

static void
do_db_cksum(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    struct ovsdb_schema *schema = read_standalone_schema(db_file_name);
    puts(schema->cksum);
    ovsdb_schema_destroy(schema);
}

static struct raft_metadata
read_cluster_metadata(const char *filename)
{
    struct ovsdb_log *log;
    check_ovsdb_error(ovsdb_log_open(filename, OVSDB_MAGIC"|"RAFT_MAGIC,
                                     OVSDB_LOG_READ_ONLY, -1, &log));
    if (strcmp(ovsdb_log_get_magic(log), RAFT_MAGIC)) {
        ovs_fatal(0, "%s: not a clustered database", filename);
    }

    struct raft_metadata md;
    check_ovsdb_error(raft_read_metadata(log, &md));

    ovsdb_log_close(log);

    return md;
}

static void
do_db_cid(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    struct raft_metadata md = read_cluster_metadata(db_file_name);
    if (uuid_is_zero(&md.cid)) {
        fprintf(stderr, "%s: cluster ID not yet known\n", db_file_name);
        exit(2);
    }
    printf(UUID_FMT"\n", UUID_ARGS(&md.cid));
    raft_metadata_destroy(&md);
}

static void
do_db_sid(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    struct raft_metadata md = read_cluster_metadata(db_file_name);
    printf(UUID_FMT"\n", UUID_ARGS(&md.sid));
    raft_metadata_destroy(&md);
}

static void
do_db_local_address(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    struct raft_metadata md = read_cluster_metadata(db_file_name);
    puts(md.local);
    raft_metadata_destroy(&md);
}

static void
do_db_has_magic(struct ovs_cmdl_context *ctx, const char *magic)
{
    const char *filename = ctx->argv[1];
    struct ovsdb_log *log;

    check_ovsdb_error(ovsdb_log_open(filename, OVSDB_MAGIC"|"RAFT_MAGIC,
                                     OVSDB_LOG_READ_ONLY, -1, &log));
    int cmp = strcmp(ovsdb_log_get_magic(log), magic);
    ovsdb_log_close(log);
    if (cmp) {
        exit(2);
    }
}

static void
do_db_is_clustered(struct ovs_cmdl_context *ctx)
{
    do_db_has_magic(ctx, RAFT_MAGIC);
}

static void
do_db_is_standalone(struct ovs_cmdl_context *ctx)
{
    do_db_has_magic(ctx, OVSDB_MAGIC);
}

static void
do_schema_name(struct ovs_cmdl_context *ctx)
{
    const char *schema_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_schema();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    puts(schema->name);
    ovsdb_schema_destroy(schema);
}

static void
do_schema_version(struct ovs_cmdl_context *ctx)
{
    const char *schema_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_schema();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    puts(schema->version);
    ovsdb_schema_destroy(schema);
}

static void
do_schema_cksum(struct ovs_cmdl_context *ctx)
{
    const char *schema_file_name
        = ctx->argc >= 2 ? ctx->argv[1] : default_schema();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    puts(schema->cksum);
    ovsdb_schema_destroy(schema);
}

/* Standalone databases only. */
static void
transact(struct ovs_cmdl_context *ctx, bool rw)
{
    const char *db_file_name = ctx->argc >= 3 ? ctx->argv[1] : default_db();
    const char *transaction = ctx->argv[ctx->argc - 1];

    struct ovsdb *ovsdb = ovsdb_file_read(db_file_name, rw);
    struct json *request = parse_json(transaction);
    struct json *result = ovsdb_execute(ovsdb, NULL, request, false,
                                        rbac_role, NULL, 0, NULL);
    json_destroy(request);

    print_and_free_json(result);
    ovsdb_destroy(ovsdb);
}

static void
do_query(struct ovs_cmdl_context *ctx)
{
    transact(ctx, false);
}

static void
do_transact(struct ovs_cmdl_context *ctx)
{
    transact(ctx, true);
}

static void
print_db_changes(struct shash *tables, struct smap *names,
                 const struct ovsdb_schema *schema)
{
    struct json *is_diff = shash_find_data(tables, "_is_diff");
    bool diff = (is_diff && is_diff->type == JSON_TRUE);
    struct shash_node *n1;

    int i = 0;
    SHASH_FOR_EACH (n1, tables) {
        const char *table = n1->name;
        struct ovsdb_table_schema *table_schema;
        struct json *rows = n1->data;
        struct shash_node *n2;

        if (n1->name[0] == '_' || rows->type != JSON_OBJECT) {
            continue;
        }

        if (i++ == 0) {
            putchar('\n');
        }

        table_schema = schema ? shash_find_data(&schema->tables, table) : NULL;
        SHASH_FOR_EACH (n2, json_object(rows)) {
            const char *row_uuid = n2->name;
            struct json *columns = n2->data;
            struct shash_node *n3;

            const char *old_name = smap_get(names, row_uuid);
            char *new_name = NULL;
            if (columns->type == JSON_OBJECT) {
                struct json *new_name_json;

                new_name_json = shash_find_data(json_object(columns), "name");
                if (new_name_json) {
                    new_name = json_to_string(new_name_json, JSSF_SORT);
                }
            }

            printf("  table %s", table);

            if (!old_name) {
                if (new_name) {
                    printf(" insert row %s (%.8s):\n", new_name, row_uuid);
                } else {
                    printf(" insert row %.8s:\n", row_uuid);
                }
            } else {
                printf(" row %s (%.8s)%s:\n", old_name, row_uuid,
                                              diff ? " diff" : "");
            }

            if (columns->type == JSON_OBJECT) {
                if (show_log_verbosity > 1) {
                    SHASH_FOR_EACH (n3, json_object(columns)) {
                        const char *column = n3->name;
                        const struct ovsdb_column *column_schema;
                        struct json *value = n3->data;
                        char *value_string = NULL;

                        column_schema =
                            (table_schema
                             ? shash_find_data(&table_schema->columns, column)
                             : NULL);
                        if (column_schema) {
                            const struct ovsdb_type *type;
                            struct ovsdb_error *error;
                            struct ovsdb_datum datum;

                            type = &column_schema->type;
                            error = ovsdb_datum_from_json(&datum, type,
                                                          value, NULL);
                            if (!error) {
                                struct ds s;

                                ds_init(&s);
                                ovsdb_datum_to_string(&datum, type, &s);
                                value_string = ds_steal_cstr(&s);
                                ovsdb_datum_destroy(&datum, type);
                            } else {
                                ovsdb_error_destroy(error);
                            }
                        }
                        if (!value_string) {
                            value_string = json_to_string(value, JSSF_SORT);
                        }
                        printf("    %s=%s\n", column, value_string);
                        free(value_string);
                    }
                }

                if (new_name && (!old_name || strcmp(old_name, new_name))) {
                    smap_replace_nocopy(names, row_uuid, new_name);
                    new_name = NULL;
                } else if (!old_name) {
                    smap_add_nocopy(names, xstrdup(row_uuid),
                                    xmemdup0(row_uuid, 8));
                }
            } else if (columns->type == JSON_NULL) {
                printf("    delete row\n");
                smap_remove(names, row_uuid);
            }

            free(new_name);
        }
    }
}

static void
print_change_record(const struct json *json, const struct ovsdb_schema *schema,
                    struct smap *names)
{
    if (!json || json->type != JSON_OBJECT) {
        return;
    }

    struct json *date, *comment;

    date = shash_find_data(json_object(json), "_date");
    if (date && date->type == JSON_INTEGER) {
        long long int t = json_integer(date);
        char *s;

        if (t < INT32_MAX) {
            /* Older versions of ovsdb wrote timestamps in seconds. */
            t *= 1000;
        }

        s = xastrftime_msec(" %Y-%m-%d %H:%M:%S.###", t, true);
        fputs(s, stdout);
        free(s);
    }

    comment = shash_find_data(json_object(json), "_comment");
    if (comment && comment->type == JSON_STRING) {
        printf(" \"%s\"", json_string(comment));
    }

    if (show_log_verbosity > 0) {
        print_db_changes(json_object(json), names, schema);
    }
}

static void
do_show_log_standalone(struct ovsdb_log *log)
{
    struct smap names = SMAP_INITIALIZER(&names);
    struct ovsdb_schema *schema = NULL;

    for (unsigned int i = 0; ; i++) {
        struct json *json;

        check_ovsdb_error(ovsdb_log_read(log, &json));
        if (!json) {
            break;
        }

        printf("record %u:", i);
        if (i == 0) {
            check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
            printf(" \"%s\" schema, version=\"%s\", cksum=\"%s\"\n",
                   schema->name, schema->version, schema->cksum);
        } else {
            print_change_record(json, schema, &names);
        }
        json_destroy(json);
        putchar('\n');
    }

    ovsdb_schema_destroy(schema);
    smap_destroy(&names);
}

static void
print_servers(const char *name, const struct json *servers)
{
    if (!servers) {
        return;
    }

    printf(" %s: ", name);

    const struct shash_node **nodes = shash_sort(json_object(servers));
    size_t n = shash_count(json_object(servers));
    for (size_t i = 0; i < n; i++) {
        if (i > 0) {
            printf(", ");
        }

        const struct shash_node *node = nodes[i];
        printf("%.4s(", node->name);

        const struct json *address = node->data;
        char *s = json_to_string(address, JSSF_SORT);
        fputs(s, stdout);
        free(s);

        putchar(')');
    }
    free(nodes);
    putchar('\n');
}

static void
print_data(const char *prefix, const struct json *data,
           struct ovsdb_schema **schemap, struct smap *names)
{
    if (!data) {
        return;
    }

    if (json_array(data)->n != 2) {
        printf(" ***invalid data***\n");
        return;
    }

    const struct json *schema_json = json_array(data)->elems[0];
    if (schema_json->type != JSON_NULL) {
        struct ovsdb_schema *schema;

        check_ovsdb_error(ovsdb_schema_from_json(schema_json, &schema));
        printf(" %sschema: \"%s\", version=\"%s\", cksum=\"%s\"\n",
               prefix, schema->name, schema->version, schema->cksum);

        ovsdb_schema_destroy(*schemap);
        *schemap = schema;
    }

    print_change_record(json_array(data)->elems[1], *schemap, names);
}

static void
print_raft_header(const struct raft_header *h,
                  struct ovsdb_schema **schemap, struct smap *names)
{
    printf(" name: \"%s\'\n", h->name);
    printf(" local address: \"%s\"\n", h->local_address);
    printf(" server_id: "SID_FMT"\n", SID_ARGS(&h->sid));
    if (!uuid_is_zero(&h->cid)) {
        printf(" cluster_id: "CID_FMT"\n", CID_ARGS(&h->cid));
    }
    if (!sset_is_empty(&h->remote_addresses)) {
        printf(" remote_addresses:");

        const char *s;
        SSET_FOR_EACH (s, &h->remote_addresses) {
            printf(" %s", s);
        }
        putchar('\n');
    }
    if (h->snap_index) {
        printf(" prev_index: %"PRIu64"\n", h->snap_index);
        printf(" prev_term: %"PRIu64"\n", h->snap.term);
        print_servers("prev_servers", h->snap.servers);
        if (!uuid_is_zero(&h->snap.eid)) {
            printf(" prev_eid: %04x\n", uuid_prefix(&h->snap.eid, 4));
        }
        print_data("prev_", h->snap.data, schemap, names);
    }
}

static void
print_raft_record(const struct raft_record *r,
                  struct ovsdb_schema **schemap, struct smap *names)
{
    if (r->comment) {
        printf(" comment: \"%s\"\n", r->comment);
    }
    if (r->term) {
        printf(" term: %"PRIu64"\n", r->term);
    }

    switch (r->type) {
    case RAFT_REC_ENTRY:
        printf(" index: %"PRIu64"\n", r->entry.index);
        print_servers("servers", r->entry.servers);
        if (!uuid_is_zero(&r->entry.eid)) {
            printf(" eid: %04x\n", uuid_prefix(&r->entry.eid, 4));
        }
        print_data("", r->entry.data, schemap, names);
        break;

    case RAFT_REC_TERM:
        break;

    case RAFT_REC_VOTE:
        printf(" vote: "SID_FMT"\n", SID_ARGS(&r->sid));
        break;

    case RAFT_REC_NOTE:
        printf(" note: \"%s\"\n", r->note);
        break;

    case RAFT_REC_COMMIT_INDEX:
        printf(" commit_index: %"PRIu64"\n", r->commit_index);
        break;

    case RAFT_REC_LEADER:
        printf(" leader: "SID_FMT"\n", SID_ARGS(&r->sid));
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static void
raft_header_to_standalone_log(const struct raft_header *h,
                              struct ovsdb_log *db_log_data)
{
    if (h->snap_index) {
        if (!h->snap.data || json_array(h->snap.data)->n != 2) {
            ovs_fatal(0, "Incorrect raft header data array length");
        }

        struct json_array *pa = json_array(h->snap.data);
        struct json *schema_json = pa->elems[0];
        struct ovsdb_error *error = NULL;

        if (schema_json->type != JSON_NULL) {
            struct ovsdb_schema *schema;
            check_ovsdb_error(ovsdb_schema_from_json(schema_json, &schema));
            ovsdb_schema_destroy(schema);
            error = ovsdb_log_write(db_log_data, schema_json);
        }

        if (!error) {
            struct json *data_json = pa->elems[1];
            if (!data_json || data_json->type != JSON_OBJECT) {
                ovs_fatal(0, "Invalid raft header data");
            }
            if (data_json->type != JSON_NULL) {
                error = ovsdb_log_write(db_log_data, data_json);
            }
        }
        check_ovsdb_error(error);
    }
}

static void
raft_record_to_standalone_log(const struct raft_record *r,
                              struct ovsdb_log *db_log_data)
{
    if (r->type == RAFT_REC_ENTRY) {
        if (!r->entry.data) {
            return;
        }
        struct json_array *pa = json_array(r->entry.data);

        if (pa->n != 2) {
            ovs_fatal(0, "Incorrect raft record array length");
        }
        struct json *data_json = pa->elems[1];
        if (data_json->type != JSON_NULL) {
            check_ovsdb_error(ovsdb_log_write(db_log_data, data_json));
        }
    }
}

static void
do_show_log_cluster(struct ovsdb_log *log)
{
    struct smap names = SMAP_INITIALIZER(&names);
    struct ovsdb_schema *schema = NULL;
    for (unsigned int i = 0; ; i++) {
        struct json *json;
        check_ovsdb_error(ovsdb_log_read(log, &json));
        if (!json) {
            break;
        }

        printf("record %u:\n", i);
        struct ovsdb_error *error;
        if (i == 0) {
            struct raft_header h;
            error = raft_header_from_json(&h, json);
            if (!error) {
                print_raft_header(&h, &schema, &names);
                raft_header_uninit(&h);
            }
        } else {
            struct raft_record r;
            error = raft_record_from_json(&r, json);
            if (!error) {
                print_raft_record(&r, &schema, &names);
                raft_record_uninit(&r);
            }
        }
        if (error) {
            char *s = ovsdb_error_to_string_free(error);
            puts(s);
            free(s);
        }

        putchar('\n');
    }

    ovsdb_schema_destroy(schema);
    smap_destroy(&names);
}

static void
do_show_log(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    struct ovsdb_log *log;

    check_ovsdb_error(ovsdb_log_open(db_file_name, OVSDB_MAGIC"|"RAFT_MAGIC,
                                     OVSDB_LOG_READ_ONLY, -1, &log));
    if (!strcmp(ovsdb_log_get_magic(log), OVSDB_MAGIC)) {
        do_show_log_standalone(log);
    } else {
        do_show_log_cluster(log);
    }
    ovsdb_log_close(log);
}

struct server {
    struct ovsdb_log *log;
    const char *filename;
    const char *nickname;

    struct raft_header header;

    struct raft_record *records;
    size_t n_records;

    struct raft_entry *snap;
    struct raft_entry *entries;
    uint64_t log_start, log_end;
};

struct leader {
    /* In struct cluster's 'leaders', indexed by 'term'. */
    struct hmap_node hmap_node;

    /* This structure indicates that in 'term', 'server' reported that 'leader'
     * was elected leader.  When 'log_end' is nonzero, it additionally
     * indicates 'leader''s log_end at the time it was elected. */
    uint64_t term;
    struct server *server;
    struct uuid leader;
    uint64_t log_end;
};

struct commit {
    /* In struct cluster's 'commits', indexed by 'term'. */
    struct hmap_node hmap_node;

    /* This structure indicates that in 'term', 'server' reported the commit
     * index as 'index'. */
    uint64_t term;
    struct server *server;
    uint64_t index;             /* Commit index. */
};

struct cluster {
    struct server *servers;
    size_t n_servers;

    struct hmap leaders;        /* Contains 'struct leader's. */

    struct hmap commits;        /* Contains 'struct commit's. */
};

static const char *
get_server_name(const struct cluster *c, const struct uuid *sid,
                char buf[SID_LEN + 1], size_t bufsize)
{
    for (size_t i = 0; i < c->n_servers; i++) {
        struct server *s = &c->servers[i];
        if (uuid_equals(&s->header.sid, sid)) {
            return s->filename;
        }
    }

    snprintf(buf, bufsize, SID_FMT, SID_ARGS(sid));
    return buf;
}

static struct leader *
find_leader(struct cluster *c, uint64_t term)
{
    struct leader *leader;
    HMAP_FOR_EACH_WITH_HASH (leader, hmap_node, hash_uint64(term),
                             &c->leaders) {
        if (term == leader->term) {
            return leader;
        }
    }
    return NULL;
}

/* Records that 'server' reported that 'leader' was elected leader in 'term'.
 *
 * Checks the Election Safety Property: at most one leader may be elected in a
 * single term (see Figure 3.2). */
static void
record_leader(struct cluster *c, uint64_t term, struct server *server,
              const struct uuid *leader)
{
    bool server_is_leader = uuid_equals(&server->header.sid, leader);
    struct leader *p = find_leader(c, term);
    if (p) {
        if (!uuid_equals(&p->leader, leader)) {
            char buf1[SID_LEN + 1];
            char buf2[SID_LEN + 1];
            ovs_fatal(0, "term %"PRIu64" has two different leaders: "
                      "%s says that the leader is %s and "
                      "%s says that the leader is %s",
                      term,
                      p->server->filename,
                      get_server_name(c, &p->leader, buf1, sizeof buf1),
                      server->filename,
                      get_server_name(c, leader, buf2, sizeof buf2));
        }
        if (server_is_leader && server->log_end > p->log_end) {
            p->log_end = server->log_end;
        }
    } else {
        p = xmalloc(sizeof *p);
        hmap_insert(&c->leaders, &p->hmap_node, hash_uint64(term));
        p->term = term;
        p->server = server;
        p->leader = *leader;
        if (server_is_leader) {
            p->log_end = server->log_end;
        } else {
            p->log_end = 0;
        }
    }
}

static struct commit *
find_commit(struct cluster *c, uint64_t term)
{
    struct commit *commit;
    HMAP_FOR_EACH_WITH_HASH (commit, hmap_node, hash_uint64(term),
                             &c->commits) {
        if (term == commit->term) {
            return commit;
        }
    }
    return NULL;
}

static void
record_commit(struct cluster *c, uint64_t term, struct server *server,
              uint64_t commit_index)
{
    struct commit *commit = find_commit(c, term);
    if (commit) {
        if (commit_index > commit->index) {
            commit->server = server;
            commit->index = commit_index;
        }
    } else {
        commit = xmalloc(sizeof *commit);
        hmap_insert(&c->commits, &commit->hmap_node, hash_uint64(term));
        commit->term = term;
        commit->server = server;
        commit->index = commit_index;
    }
}

static void
do_check_cluster(struct ovs_cmdl_context *ctx)
{
    struct cluster c = {
        .servers = xzalloc((ctx->argc - 1) * sizeof *c.servers),
        .n_servers = 0,
        .leaders = HMAP_INITIALIZER(&c.leaders),
        .commits = HMAP_INITIALIZER(&c.commits),
    };

    uint64_t min_term = UINT64_MAX;
    uint64_t max_term = 0;

    for (int i = 1; i < ctx->argc; i++) {
        struct server *s = &c.servers[c.n_servers];
        s->filename = ctx->argv[i];

        check_ovsdb_error(ovsdb_log_open(s->filename, RAFT_MAGIC,
                                         OVSDB_LOG_READ_ONLY, -1, &s->log));

        struct json *json;
        check_ovsdb_error(ovsdb_log_read(s->log, &json));
        check_ovsdb_error(raft_header_from_json(&s->header, json));
        json_destroy(json);

        if (s->header.joining) {
            printf("%s has not joined the cluster, omitting\n", s->filename);
            ovsdb_log_close(s->log);
            continue;
        }
        for (size_t j = 0; j < c.n_servers; j++) {
            if (uuid_equals(&s->header.sid, &c.servers[j].header.sid)) {
                ovs_fatal(0, "Duplicate server ID "SID_FMT" in %s and %s.",
                          SID_ARGS(&s->header.sid),
                          s->filename, c.servers[j].filename);
            }
        }
        if (c.n_servers > 0) {
            struct server *s0 = &c.servers[0];
            if (!uuid_equals(&s0->header.cid, &s->header.cid)) {
                ovs_fatal(0, "%s has cluster ID "CID_FMT" but %s "
                          "has cluster ID "CID_FMT,
                          s0->filename, CID_ARGS(&s0->header.cid),
                          s->filename, CID_ARGS(&s->header.cid));
            }
            if (strcmp(s0->header.name, s->header.name)) {
                ovs_fatal(0, "%s is named \"%s\" but %s is named \"%s\"",
                          s0->filename, s0->header.name,
                          s->filename, s->header.name);
            }
        }
        c.n_servers++;
    }

    for (struct server *s = c.servers; s < &c.servers[c.n_servers]; s++) {
        s->snap = &s->header.snap;
        s->log_start = s->log_end = s->header.snap_index + 1;

        size_t allocated_records = 0;
        size_t allocated_entries = 0;

        uint64_t term = 0;              /* Current term. */
        struct uuid vote = UUID_ZERO;   /* Server 's''s vote in 'term'. */
        struct uuid leader = UUID_ZERO; /* Cluster leader in 'term'. */
        uint64_t leader_rec_idx = 0;    /* Index of last "leader" record. */

        uint64_t commit_index = s->header.snap_index;

        for (unsigned long long int rec_idx = 1; ; rec_idx++) {
            if (s->n_records >= allocated_records) {
                s->records = x2nrealloc(s->records, &allocated_records,
                                        sizeof *s->records);
            }

            struct json *json;
            check_ovsdb_error(ovsdb_log_read(s->log, &json));
            if (!json) {
                break;
            }
            struct raft_record *r = &s->records[s->n_records++];
            check_ovsdb_error(raft_record_from_json(r, json));
            json_destroy(json);

            if (r->term > term) {
                term = r->term;
                vote = UUID_ZERO;
                leader = UUID_ZERO;
                leader_rec_idx = 0;
            }
            if (term < min_term) {
                min_term = term;
            }
            if (term > max_term) {
                max_term = term;
            }

            switch (r->type) {
            case RAFT_REC_ENTRY:
                if (r->entry.index < commit_index) {
                    ovs_fatal(0, "%s: record %llu attempts to truncate log "
                              "from %"PRIu64" to %"PRIu64" entries, but "
                              "commit index is already %"PRIu64,
                              s->filename, rec_idx,
                              s->log_end, r->entry.index,
                              commit_index);
                } else if (r->entry.index > s->log_end) {
                    ovs_fatal(0, "%s: record %llu with index %"PRIu64" skips "
                              "past expected index %"PRIu64, s->filename,
                              rec_idx, r->entry.index, s->log_end);
                }

                if (r->entry.index < s->log_end) {
                    bool is_leader = uuid_equals(&s->header.sid, &leader);
                    if (is_leader) {
                        /* Leader Append-Only property (see Figure 3.2). */
                        ovs_fatal(0, "%s: record %llu truncates log from "
                                  "%"PRIu64" to %"PRIu64" entries while "
                                  "server is leader", s->filename, rec_idx,
                                  s->log_end, r->entry.index);
                    } else {
                        /* This can happen, but it is unusual. */
                        printf("%s: record %llu truncates log from %"PRIu64
                               " to %"PRIu64" entries\n", s->filename, rec_idx,
                               s->log_end, r->entry.index);
                    }
                    s->log_end = r->entry.index;
                }

                uint64_t prev_term = (s->log_end > s->log_start
                                      ? s->entries[s->log_end
                                                   - s->log_start - 1].term
                                      : s->snap->term);
                if (r->term < prev_term) {
                    ovs_fatal(0, "%s: record %llu with index %"PRIu64" term "
                              "%"PRIu64" precedes previous entry's term "
                              "%"PRIu64, s->filename, rec_idx,
                              r->entry.index, r->term, prev_term);
                }

                uint64_t log_idx = s->log_end++ - s->log_start;
                if (log_idx >= allocated_entries) {
                    s->entries = x2nrealloc(s->entries, &allocated_entries,
                                            sizeof *s->entries);
                }
                struct raft_entry *e = &s->entries[log_idx];
                e->term = r->term;
                e->data = r->entry.data;
                e->eid = r->entry.eid;
                e->servers = r->entry.servers;
                break;

            case RAFT_REC_TERM:
                break;

            case RAFT_REC_VOTE:
                if (r->term < term) {
                    ovs_fatal(0, "%s: record %llu votes for term %"PRIu64" "
                              "but current term is %"PRIu64, s->filename,
                              rec_idx, r->term, term);
                } else if (!uuid_is_zero(&vote)
                           && !uuid_equals(&vote, &r->sid)) {
                    char buf1[SID_LEN + 1];
                    char buf2[SID_LEN + 1];
                    ovs_fatal(0, "%s: record %llu votes for %s in term "
                              "%"PRIu64" but a previous record for the "
                              "same term voted for %s", s->filename,
                              rec_idx,
                              get_server_name(&c, &vote, buf1, sizeof buf1),
                              r->term,
                              get_server_name(&c, &r->sid, buf2, sizeof buf2));
                } else {
                    vote = r->sid;
                }
                break;

            case RAFT_REC_NOTE:
                if (!strcmp(r->note, "left")) {
                    printf("%s: record %llu shows that the server left the "
                           "cluster\n", s->filename, rec_idx);
                }
                break;

            case RAFT_REC_COMMIT_INDEX:
                if (r->commit_index < commit_index) {
                    ovs_fatal(0, "%s: record %llu regresses commit index "
                              "from %"PRIu64 " to %"PRIu64, s->filename,
                              rec_idx, commit_index, r->commit_index);
                } else if (r->commit_index >= s->log_end) {
                    ovs_fatal(0, "%s: record %llu advances commit index to "
                              "%"PRIu64 " but last log index is %"PRIu64,
                              s->filename, rec_idx, r->commit_index,
                              s->log_end - 1);
                } else {
                    commit_index = r->commit_index;
                }

                record_commit(&c, term, s, r->commit_index);
                break;

            case RAFT_REC_LEADER:
                if (!uuid_equals(&r->sid, &leader)) {
                    if (uuid_is_zero(&leader)) {
                        leader = r->sid;
                        leader_rec_idx = rec_idx;
                    } else {
                        char buf1[SID_LEN + 1];
                        char buf2[SID_LEN + 1];
                        ovs_fatal(0, "%s: record %llu reports leader %s "
                                  "for term %"PRIu64" but record %"PRIu64" "
                                  "previously reported the leader as %s "
                                  "in that term",
                                  s->filename, rec_idx,
                                  get_server_name(&c, &r->sid,
                                                  buf1, sizeof buf1),
                                  term, leader_rec_idx,
                                  get_server_name(&c, &leader,
                                                  buf2, sizeof buf2));
                    }
                }
                record_leader(&c, term, s, &r->sid);
                break;
            }
        }

        ovsdb_log_close(s->log);
        s->log = NULL;
    }

    /* Check the Leader Completeness property from Figure 3.2: If a log entry
     * is committed in a given term, then that entry will be present in the
     * logs of the leaders for all higher-numbered terms. */
    if (min_term == UINT64_MAX || max_term == 0) {
        ovs_fatal(0, "all logs are empty");
    }
    struct commit *commit = NULL;
    for (uint64_t term = min_term; term <= max_term; term++) {
        struct leader *leader = find_leader(&c, term);
        if (leader && leader->log_end
            && commit && commit->index >= leader->log_end) {
            ovs_fatal(0, "leader %s for term %"PRIu64" has log entries only "
                      "up to index %"PRIu64", but index %"PRIu64" was "
                      "committed in a previous term (e.g. by %s)",
                      leader->server->filename, term, leader->log_end - 1,
                      commit->index, commit->server->filename);
        }

        struct commit *next = find_commit(&c, term);
        if (next && (!commit || next->index > commit->index)) {
            commit = next;
        }
    }

    /* Section 3.5: Check the Log Matching Property in Figure 3.2:
     *
     *   - If two entries in different logs have the same index and term, then
     *     they store the same command.
     *
     *   - If two entries in different logs have the same index and term, then
     *     the logs are identical in all preceding entries.
     */
    for (size_t i = 0; i < c.n_servers; i++) {
        for (size_t j = 0; j < c.n_servers; j++) {
            struct server *a = &c.servers[i];
            struct server *b = &c.servers[j];

            if (a == b) {
                continue;
            }

            bool must_equal = false;
            for (uint64_t idx = MIN(a->log_end, b->log_end) - 1;
                 idx >= MAX(a->log_start, b->log_start);
                 idx--) {
                const struct raft_entry *ae = &a->entries[idx - a->log_start];
                const struct raft_entry *be = &b->entries[idx - b->log_start];
                if (ae->term == be->term) {
                    must_equal = true;
                }
                if (!must_equal || raft_entry_equals(ae, be)) {
                    continue;
                }
                char *as = json_to_string(raft_entry_to_json(ae), JSSF_SORT);
                char *bs = json_to_string(raft_entry_to_json(be), JSSF_SORT);
                ovs_fatal(0, "log entries with index %"PRIu64" differ:\n"
                          "%s has %s\n"
                          "%s has %s",
                          idx, a->filename, as, b->filename, bs);
            }
        }
    }

    /* Check for db consistency:
     * The serverid must be in the servers list.
     */

    for (struct server *s = c.servers; s < &c.servers[c.n_servers]; s++) {
        struct shash *servers_obj = json_object(s->snap->servers);
        char *server_id = xasprintf(SID_FMT, SID_ARGS(&s->header.sid));
        bool found = false;
        const struct shash_node *node;

        SHASH_FOR_EACH (node, servers_obj) {
            if (!strncmp(server_id, node->name, SID_LEN)) {
                found = true;
            }
        }

        if (!found) {
            for (struct raft_entry *e = s->entries;
                 e < &s->entries[s->log_end - s->log_start]; e++) {
                if (e->servers == NULL) {
                    continue;
                }
                struct shash *log_servers_obj = json_object(e->servers);
                SHASH_FOR_EACH (node, log_servers_obj) {
                    if (!strncmp(server_id, node->name, SID_LEN)) {
                        found = true;
                    }
                }
            }
        }

        if (!found) {
            ovs_fatal(0, "%s: server %s not found in server list",
                      s->filename, server_id);
        }
        free(server_id);
    }

    /* Clean up. */

    for (size_t i = 0; i < c.n_servers; i++) {
        struct server *s = &c.servers[i];

        raft_header_uninit(&s->header);
        for (size_t j = 0; j < s->n_records; j++) {
            struct raft_record *r = &s->records[j];

            raft_record_uninit(r);
        }
        free(s->records);
        free(s->entries);
    }
    free(c.servers);

    struct commit *next_commit;
    HMAP_FOR_EACH_SAFE (commit, next_commit, hmap_node, &c.commits) {
        hmap_remove(&c.commits, &commit->hmap_node);
        free(commit);
    }
    hmap_destroy(&c.commits);

    struct leader *leader, *next_leader;
    HMAP_FOR_EACH_SAFE (leader, next_leader, hmap_node, &c.leaders) {
        hmap_remove(&c.leaders, &leader->hmap_node);
        free(leader);
    }
    hmap_destroy(&c.leaders);
}

static struct ovsdb_version
parse_version(const char *s)
{
    struct ovsdb_version version;
    if (!ovsdb_parse_version(s, &version)) {
        ovs_fatal(0, "%s: not an OVSDB version number in format x.y.z", s);
    }
    return version;
}

static void
do_compare_versions(struct ovs_cmdl_context *ctx)
{
    struct ovsdb_version a = parse_version(ctx->argv[1]);
    struct ovsdb_version b = parse_version(ctx->argv[3]);
    int cmp = (a.x != b.x ? (a.x > b.x ? 1 : -1)
               : a.y != b.y ? (a.y > b.y ? 1 : -1)
               : a.z != b.z ? (a.z > b.z ? 1 : -1)
               : 0);

    const char *op = ctx->argv[2];
    bool result;
    if (!strcmp(op, "<")) {
        result = cmp < 0;
    } else if (!strcmp(op, "<=")) {
        result = cmp <= 0;
    } else if (!strcmp(op, "==")) {
        result = cmp == 0;
    } else if (!strcmp(op, ">=")) {
        result = cmp >= 0;
    } else if (!strcmp(op, ">")) {
        result = cmp > 0;
    } else if (!strcmp(op, "!=")) {
        result = cmp != 0;
    } else {
        ovs_fatal(0, "%s: not a relational operator", op);
    }

    exit(result ? 0 : 2);
}

static void
do_convert_to_standalone(struct ovsdb_log *log, struct ovsdb_log *db_log_data)
{
    for (unsigned int i = 0; ; i++) {
        struct json *json;
        check_ovsdb_error(ovsdb_log_read(log, &json));
        if (!json) {
            break;
        }

        if (i == 0) {
            struct raft_header h;
            check_ovsdb_error(raft_header_from_json(&h, json));
            raft_header_to_standalone_log(&h, db_log_data);
            raft_header_uninit(&h);
        } else {
            struct raft_record r;
            check_ovsdb_error(raft_record_from_json(&r, json));
            raft_record_to_standalone_log(&r, db_log_data);
            raft_record_uninit(&r);
        }
        json_destroy(json);
    }
}

static void
do_cluster_standalone(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    const char *cluster_db_file_name = ctx->argv[2];
    struct ovsdb_log *log;
    struct ovsdb_log *db_log_data;

    check_ovsdb_error(ovsdb_log_open(cluster_db_file_name,
                                     OVSDB_MAGIC"|"RAFT_MAGIC,
                                     OVSDB_LOG_READ_ONLY, -1, &log));
    check_ovsdb_error(ovsdb_log_open(db_file_name, OVSDB_MAGIC,
                                     OVSDB_LOG_CREATE_EXCL, -1, &db_log_data));
    if (strcmp(ovsdb_log_get_magic(log), RAFT_MAGIC) != 0) {
        ovs_fatal(0, "Database is not clustered db.\n");
    }
    do_convert_to_standalone(log, db_log_data);
    check_ovsdb_error(ovsdb_log_commit_block(db_log_data));
    ovsdb_log_close(db_log_data);
    ovsdb_log_close(log);
}

static void
do_help(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    usage();
}

static void
do_list_commands(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
     ovs_cmdl_print_commands(get_all_commands());
}

static const struct ovs_cmdl_command all_commands[] = {
    { "create", "[db [schema]]", 0, 2, do_create, OVS_RW },
    { "create-cluster", "db contents local", 3, 3, do_create_cluster, OVS_RW },
    { "join-cluster", "db name local remote...", 4, INT_MAX, do_join_cluster,
      OVS_RW },
    { "compact", "[db [dst]]", 0, 2, do_compact, OVS_RW },
    { "convert", "[db [schema [dst]]]", 0, 3, do_convert, OVS_RW },
    { "needs-conversion", NULL, 0, 2, do_needs_conversion, OVS_RO },
    { "db-name", "[db]",  0, 1, do_db_name, OVS_RO },
    { "db-version", "[db]",  0, 1, do_db_version, OVS_RO },
    { "db-cksum", "[db]", 0, 1, do_db_cksum, OVS_RO },
    { "db-cid", "db", 1, 1, do_db_cid, OVS_RO },
    { "db-sid", "db", 1, 1, do_db_sid, OVS_RO },
    { "db-local-address", "db", 1, 1, do_db_local_address, OVS_RO },
    { "db-is-clustered", "db", 1, 1, do_db_is_clustered, OVS_RO },
    { "db-is-standalone", "db", 1, 1, do_db_is_standalone, OVS_RO },
    { "schema-name", "[schema]", 0, 1, do_schema_name, OVS_RO },
    { "schema-version", "[schema]", 0, 1, do_schema_version, OVS_RO },
    { "schema-cksum", "[schema]", 0, 1, do_schema_cksum, OVS_RO },
    { "query", "[db] trns", 1, 2, do_query, OVS_RO },
    { "transact", "[db] trns", 1, 2, do_transact, OVS_RO },
    { "show-log", "[db]", 0, 1, do_show_log, OVS_RO },
    { "check-cluster", "db...", 1, INT_MAX, do_check_cluster, OVS_RO },
    { "compare-versions", "a op b", 3, 3, do_compare_versions, OVS_RO },
    { "help", NULL, 0, INT_MAX, do_help, OVS_RO },
    { "list-commands", NULL, 0, INT_MAX, do_list_commands, OVS_RO },
    { "cluster-to-standalone", "db clusterdb", 2, 2,
    do_cluster_standalone, OVS_RW },
    { NULL, NULL, 2, 2, NULL, OVS_RO },
};

static const struct ovs_cmdl_command *get_all_commands(void)
{
    return all_commands;
}
