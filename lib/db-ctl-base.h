/*
 * Copyright (c) 2015, 2017 Nicira, Inc.
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

#ifndef DB_CTL_BASE_H
#define DB_CTL_BASE_H 1

#include "compiler.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/shash.h"

struct ctl_context;
struct option;
struct ovsdb_idl;
struct ovsdb_idl_row;
struct ovsdb_idl_txn;
struct ovsdb_symbol_table;
struct table;

/* This library module contains the common parts for ovsdb manipulation
 * (structs, commands and functions).  To utilize this module, user must
 * define the following:
 *
 * - the command syntaxes for each command.  (See 'struct ctl_command_syntax'
 *   for more info)  and regiters them using ctl_register_commands().
 *
 * - the *ctl command context by inheriting the 'struct ctl_context' for
 *   additional commands implemented by user.  (See 'struct ctl_context' for
 *   more info)
*/

/* ctl_fatal() also logs the error, so it is preferred in this file. */
#define ovs_fatal please_use_ctl_fatal_instead_of_ovs_fatal

struct ctl_table_class;
struct ovsdb_idl_class;
struct ovsdb_idl_table_class;
struct cmd_show_table;

/* ctl_init() figures out the number of tables on its own and flags an error if
 * 'ctl_classes' was defined with the wrong number of elements. */
#define ctl_init(idl_class, table_classes, ctl_classes, cmd_show_table, \
                 ctl_exit_func)                                         \
    (BUILD_ASSERT(ARRAY_SIZE(table_classes) == ARRAY_SIZE(ctl_classes)),  \
     ctl_init__(idl_class, ctl_classes, cmd_show_table, ctl_exit_func))
void ctl_init__(const struct ovsdb_idl_class *, const struct ctl_table_class *,
                const struct cmd_show_table *cmd_show_tables,
                void (*ctl_exit_func)(int status));
char *ctl_default_db(void);
OVS_NO_RETURN void ctl_fatal(const char *, ...) OVS_PRINTF_FORMAT(1, 2);

/* *ctl command syntax structure, to be defined by each command implementation.
 *
 * Execution Path
 * ==============
 *
 * Three stylized functions accompany each of these data structures:
 *
 *               "pre-run"         "run"        "post-run"
 *            ---------------  ------------  -----------------
 * *ctl       ->prerequisites     ->run        ->postprocess
 *
 * Any *ctl command implementation should go through the following execution
 * path:
 *
 *   1. parses user command-line input and finds the corresponding syntax
 *      structures.
 *
 *   2. calls prerequisites() for getting the columns or tables used by each
 *      command.
 *
 *   3. calls run() to execute each command and to generate output.
 *
 *   4. calls postprocess() after output has been committed.  (Only needed
 *      by 'create' command sofar)
 *
 * Execution Context
 * =================
 *
 * Each of the stylized functions requires the 'struct ctl_context' as input
 * to provide context e.g. command-line arguments, table to be modified.  User
 * may define more specific context (by inheriting 'struct ctl_context') and
 * write stylized functions that use it.  In that case, CONTAINER_OF() can
 * be used to cast the generic context to the specific one.
 *
 * */
struct ctl_command_syntax {
    const char *name;           /* e.g. "add-br" */
    int min_args;               /* Min number of arguments following name. */
    int max_args;               /* Max number of arguments following name. */

    /* Names that roughly describe the arguments that the command
     * uses.  These should be similar to the names displayed in the
     * man page or in the help output. */
    const char *arguments;

    /* If nonnull, calls ovsdb_idl_add_column() or ovsdb_idl_add_table() for
     * each column or table in ctx->idl that it uses. */
    void (*prerequisites)(struct ctl_context *ctx);

    /* Does the actual work of the command and puts the command's output, if
     * any, in ctx->output or ctx->table.
     *
     * Alternatively, if some prerequisite of the command is not met and the
     * caller should wait for something to change and then retry, it may set
     * ctx->try_again to true.  (Only the "wait-until" command currently does
     * this.) */
    void (*run)(struct ctl_context *ctx);

    /* If nonnull, called after the transaction has been successfully
     * committed.  ctx->output is the output from the "run" function, which
     * this function may modify and otherwise postprocess as needed.  (Only the
     * "create" command currently does any postprocessing.) */
    void (*postprocess)(struct ctl_context *ctx);

    /* A comma-separated list of supported options, e.g. "--a,--b", or the
     * empty string if the command does not support any options.
     *
     * Arguments are determined by appending special characters to option
     * names:
     *
     *   - Append "=" (e.g. "--id=") for a required argument.
     *
     *   - Append "?" (e.g. "--ovs?") for an optional argument.
     *
     *   - Otherwise an option does not accept an argument. */
    const char *options;

    enum { RO, RW } mode;   /* Does this command modify the database? */
};

/* A command extracted from command-line input plus the structs for
 * output generation. */
struct ctl_command {
    /* Data that remains constant after initialization. */
    const struct ctl_command_syntax *syntax;
    int argc;
    char **argv;
    struct shash options;

    /* Data modified by commands. */
    struct ds output;
    struct table *table;
};

bool ctl_might_write_to_db(char **argv);
const char *ctl_get_db_cmd_usage(void);

const char *ctl_list_db_tables_usage(void);
void ctl_print_commands(void);
void ctl_print_options(const struct option *);
void ctl_add_cmd_options(struct option **, size_t *n_options_p,
                         size_t *allocated_options_p, int opt_val);
void ctl_register_commands(const struct ctl_command_syntax *);
struct ctl_command *ctl_parse_commands(int argc, char *argv[],
                                       struct shash *local_options,
                                       size_t *n_commandsp);

/* Sometimes, it is desirable to print the table with weak reference to
 * rows in a 'cmd_show_table' table.  In that case, the 'weak_ref_table'
 * should be used and user must define all variables. */
struct weak_ref_table {
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *name_column;
    /* This colum must be a weak reference to the owning
     * 'struct cmd_show_table''s table row. */
    const struct ovsdb_idl_column *wref_column;
};

/* This struct is for organizing the 'show' command output where:
 *
 * - 'table' is the table to show.
 *
 * - if 'name_column' is not null, it is used as the name for each row
 *   in 'table'.
 *
 * - 'columns[]' allows user to specify the print of additional columns
 *   in 'table'.
 *
 * - if 'wref_table' is populated, print 'wref_table.name_column' for
 *   each row in table 'wref_table.table' that has a reference to 'table'
 *   in 'wref_table.wref_column'.  Every field must be populated.
 *
 * */
struct cmd_show_table {
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *name_column;
    const struct ovsdb_idl_column *columns[3]; /* Seems like a good number. */
    const struct weak_ref_table wref_table;
};


/* The base context struct for conducting the common database
 * operations (commands listed in 'db_ctl_commands').  User should
 * define the per-schema context by inheriting this struct as base.
 *
 * Database Caches
 * ===============
 *
 * User may implement caches for contents of the database to facilitate
 * specific commands.  In that case, the common commands defined in
 * 'db_ctl_commands' that may invalidate the cache must call the
 * invalidate_cache().
 *
 **/
struct ctl_context {
    /* Read-only. */
    int argc;
    char **argv;
    struct shash options;

    /* Modifiable state. */
    struct ds output;
    struct table *table;
    struct ovsdb_idl *idl;
    struct ovsdb_idl_txn *txn;
    struct ovsdb_symbol_table *symtab;

    /* For implementation with a cache of the contents of the database,
     * this function will be called when the database is changed and the
     * change makes the cache no longer valid. */
    void (*invalidate_cache_cb)(struct ctl_context *);

    /* A command may set this member to true if some prerequisite is not met
     * and the caller should wait for something to change and then retry. */
    bool try_again;
};

void ctl_context_init_command(struct ctl_context *, struct ctl_command *);
void ctl_context_init(struct ctl_context *, struct ctl_command *,
                      struct ovsdb_idl *, struct ovsdb_idl_txn *,
                      struct ovsdb_symbol_table *,
                      void (*invalidate_cache)(struct ctl_context *));
void ctl_context_done_command(struct ctl_context *, struct ctl_command *);
void ctl_context_done(struct ctl_context *, struct ctl_command *);

/* A way to identify a particular row in the database based on a user-provided
 * string.  If all fields are NULL, the struct is ignored.  Otherwise,
 * 'name_column' designates a column whose table is searched for rows that
 * match with the user string.  If 'key' is NULL, then 'name_column' should be
 * a string or integer-valued column; otherwise it should be a map from a
 * string to one of those types and the value corresponding to 'key' is what is
 * matched.  If a matching row is found, then:
 *
 *    - If 'uuid_column' is NULL, the matching row is the final row.
 *
 *    - Otherwise 'uuid_column' must designate a UUID-typed column whose value
 *      refers to exactly one row, which is the final row.
 */
struct ctl_row_id {
    const struct ovsdb_idl_column *name_column;
    const char *key;
    const struct ovsdb_idl_column *uuid_column;
};

struct ctl_table_class {
    struct ctl_row_id row_ids[4];
};

const struct ovsdb_idl_row *ctl_get_row(struct ctl_context *,
                                        const struct ovsdb_idl_table_class *,
                                        const char *record_id,
                                        bool must_exist);

void ctl_set_column(const char *table_name,
                    const struct ovsdb_idl_row *, const char *arg,
                    struct ovsdb_symbol_table *);

#endif /* db-ctl-base.h */
