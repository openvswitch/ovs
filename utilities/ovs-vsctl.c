/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "json.h"
#include "ovsdb-data.h"
#include "ovsdb-idl.h"
#include "poll-loop.h"
#include "process.h"
#include "stream.h"
#include "stream-ssl.h"
#include "smap.h"
#include "sset.h"
#include "svec.h"
#include "lib/vswitch-idl.h"
#include "table.h"
#include "timeval.h"
#include "util.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(vsctl);

/* vsctl_fatal() also logs the error, so it is preferred in this file. */
#define ovs_fatal please_use_vsctl_fatal_instead_of_ovs_fatal

struct vsctl_context;

/* A command supported by ovs-vsctl. */
struct vsctl_command_syntax {
    const char *name;           /* e.g. "add-br" */
    int min_args;               /* Min number of arguments following name. */
    int max_args;               /* Max number of arguments following name. */

    /* If nonnull, calls ovsdb_idl_add_column() or ovsdb_idl_add_table() for
     * each column or table in ctx->idl that it uses. */
    void (*prerequisites)(struct vsctl_context *ctx);

    /* Does the actual work of the command and puts the command's output, if
     * any, in ctx->output or ctx->table.
     *
     * Alternatively, if some prerequisite of the command is not met and the
     * caller should wait for something to change and then retry, it may set
     * ctx->try_again to true.  (Only the "wait-until" command currently does
     * this.) */
    void (*run)(struct vsctl_context *ctx);

    /* If nonnull, called after the transaction has been successfully
     * committed.  ctx->output is the output from the "run" function, which
     * this function may modify and otherwise postprocess as needed.  (Only the
     * "create" command currently does any postprocessing.) */
    void (*postprocess)(struct vsctl_context *ctx);

    /* A comma-separated list of supported options, e.g. "--a,--b", or the
     * empty string if the command does not support any options. */
    const char *options;
    enum { RO, RW } mode;       /* Does this command modify the database? */
};

struct vsctl_command {
    /* Data that remains constant after initialization. */
    const struct vsctl_command_syntax *syntax;
    int argc;
    char **argv;
    struct shash options;

    /* Data modified by commands. */
    struct ds output;
    struct table *table;
};

/* --db: The database server to contact. */
static const char *db;

/* --oneline: Write each command's output as a single line? */
static bool oneline;

/* --dry-run: Do not commit any changes. */
static bool dry_run;

/* --no-wait: Wait for ovs-vswitchd to reload its configuration? */
static bool wait_for_reload = true;

/* --timeout: Time to wait for a connection to 'db'. */
static int timeout;

/* --retry: If true, ovs-vsctl will retry connecting to the database forever.
 * If false and --db says to use an active connection method (e.g. "unix:",
 * "tcp:", "ssl:"), then ovs-vsctl will try to connect once and exit with an
 * error if the database server cannot be contacted (e.g. ovsdb-server is not
 * running).
 *
 * Regardless of this setting, --timeout always limits how long ovs-vsctl will
 * wait. */
static bool retry;

/* Format for table output. */
static struct table_style table_style = TABLE_STYLE_DEFAULT;

/* All supported commands. */
static const struct vsctl_command_syntax *get_all_commands(void);

/* The IDL we're using and the current transaction, if any.
 * This is for use by vsctl_exit() only, to allow it to clean up.
 * Other code should use its context arguments. */
static struct ovsdb_idl *the_idl;
static struct ovsdb_idl_txn *the_idl_txn;

static void vsctl_exit(int status) NO_RETURN;
static void vsctl_fatal(const char *, ...) PRINTF_FORMAT(1, 2) NO_RETURN;
static char *default_db(void);
static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[], struct shash *local_options);
static bool might_write_to_db(char **argv);

static struct vsctl_command *parse_commands(int argc, char *argv[],
                                            struct shash *local_options,
                                            size_t *n_commandsp);
static void parse_command(int argc, char *argv[], struct shash *local_options,
                          struct vsctl_command *);
static const struct vsctl_command_syntax *find_command(const char *name);
static void run_prerequisites(struct vsctl_command[], size_t n_commands,
                              struct ovsdb_idl *);
static void do_vsctl(const char *args, struct vsctl_command *, size_t n,
                     struct ovsdb_idl *);

static const struct vsctl_table_class *get_table(const char *table_name);
static void set_column(const struct vsctl_table_class *,
                       const struct ovsdb_idl_row *, const char *arg,
                       struct ovsdb_symbol_table *);

static bool is_condition_satisfied(const struct vsctl_table_class *,
                                   const struct ovsdb_idl_row *,
                                   const char *arg,
                                   struct ovsdb_symbol_table *);

/* Post_db_reload_check frame work is to allow ovs-vsctl to do additional
 * checks after OVSDB transactions are successfully recorded and reload by
 * ovs-vswitchd.
 *
 * For example, When a new interface is added to OVSDB, ovs-vswitchd will
 * either store a positive values on successful implementing the new
 * interface, or -1 on failure.
 *
 * Unless -no-wait command line option is specified,
 * post_db_reload_do_checks() is called right after any configuration
 * changes is picked up (i.e. reload) by ovs-vswitchd. Any error detected
 * post OVSDB reload is reported as ovs-vsctl errors. OVS-vswitchd logs
 * more detailed messages about those errors.
 *
 * Current implementation only check for Post OVSDB reload failures on new
 * interface additions with 'add-br' and 'add-port' commands.
 *
 * post_db_reload_expect_iface()
 *
 * keep track of interfaces to be checked post OVSDB reload. */
static void post_db_reload_check_init(void);
static void post_db_reload_do_checks(const struct vsctl_context *);
static void post_db_reload_expect_iface(const struct ovsrec_interface *);

static struct uuid *neoteric_ifaces;
static size_t n_neoteric_ifaces;
static size_t allocated_neoteric_ifaces;

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_reconnect;
    struct ovsdb_idl *idl;
    struct vsctl_command *commands;
    struct shash local_options;
    unsigned int seqno;
    size_t n_commands;
    char *args;

    set_program_name(argv[0]);
    fatal_ignore_sigpipe();
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_FACILITY, VLL_WARN);
    ovsrec_init();

    /* Log our arguments.  This is often valuable for debugging systems. */
    args = process_escape_args(argv);
    VLOG(might_write_to_db(argv) ? VLL_INFO : VLL_DBG, "Called as %s", args);

    /* Parse command line. */
    shash_init(&local_options);
    parse_options(argc, argv, &local_options);
    commands = parse_commands(argc - optind, argv + optind, &local_options,
                              &n_commands);

    if (timeout) {
        time_alarm(timeout);
    }

    /* Initialize IDL. */
    idl = the_idl = ovsdb_idl_create(db, &ovsrec_idl_class, false, retry);
    run_prerequisites(commands, n_commands, idl);

    /* Execute the commands.
     *
     * 'seqno' is the database sequence number for which we last tried to
     * execute our transaction.  There's no point in trying to commit more than
     * once for any given sequence number, because if the transaction fails
     * it's because the database changed and we need to obtain an up-to-date
     * view of the database before we try the transaction again. */
    seqno = ovsdb_idl_get_seqno(idl);
    for (;;) {
        ovsdb_idl_run(idl);
        if (!ovsdb_idl_is_alive(idl)) {
            int retval = ovsdb_idl_get_last_error(idl);
            vsctl_fatal("%s: database connection failed (%s)",
                        db, ovs_retval_to_string(retval));
        }

        if (seqno != ovsdb_idl_get_seqno(idl)) {
            seqno = ovsdb_idl_get_seqno(idl);
            do_vsctl(args, commands, n_commands, idl);
        }

        if (seqno == ovsdb_idl_get_seqno(idl)) {
            ovsdb_idl_wait(idl);
            poll_block();
        }
    }
}

static struct option *
find_option(const char *name, struct option *options, size_t n_options)
{
    size_t i;

    for (i = 0; i < n_options; i++) {
        if (!strcmp(options[i].name, name)) {
            return &options[i];
        }
    }
    return NULL;
}

static struct option *
add_option(struct option **optionsp, size_t *n_optionsp,
           size_t *allocated_optionsp)
{
    if (*n_optionsp >= *allocated_optionsp) {
        *optionsp = x2nrealloc(*optionsp, allocated_optionsp,
                               sizeof **optionsp);
    }
    return &(*optionsp)[(*n_optionsp)++];
}

static void
parse_options(int argc, char *argv[], struct shash *local_options)
{
    enum {
        OPT_DB = UCHAR_MAX + 1,
        OPT_ONELINE,
        OPT_NO_SYSLOG,
        OPT_NO_WAIT,
        OPT_DRY_RUN,
        OPT_PEER_CA_CERT,
        OPT_LOCAL,
        OPT_RETRY,
        VLOG_OPTION_ENUMS,
        TABLE_OPTION_ENUMS
    };
    static const struct option global_long_options[] = {
        {"db", required_argument, NULL, OPT_DB},
        {"no-syslog", no_argument, NULL, OPT_NO_SYSLOG},
        {"no-wait", no_argument, NULL, OPT_NO_WAIT},
        {"dry-run", no_argument, NULL, OPT_DRY_RUN},
        {"oneline", no_argument, NULL, OPT_ONELINE},
        {"timeout", required_argument, NULL, 't'},
        {"retry", no_argument, NULL, OPT_RETRY},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        TABLE_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {NULL, 0, NULL, 0},
    };
    const int n_global_long_options = ARRAY_SIZE(global_long_options) - 1;
    char *tmp, *short_options;

    const struct vsctl_command_syntax *p;
    struct option *options, *o;
    size_t allocated_options;
    size_t n_options;
    size_t i;

    tmp = long_options_to_short_options(global_long_options);
    short_options = xasprintf("+%s", tmp);
    free(tmp);

    /* We want to parse both global and command-specific options here, but
     * getopt_long() isn't too convenient for the job.  We copy our global
     * options into a dynamic array, then append all of the command-specific
     * options. */
    options = xmemdup(global_long_options, sizeof global_long_options);
    allocated_options = ARRAY_SIZE(global_long_options);
    n_options = n_global_long_options;
    for (p = get_all_commands(); p->name; p++) {
        if (p->options[0]) {
            char *save_ptr = NULL;
            char *name;
            char *s;

            s = xstrdup(p->options);
            for (name = strtok_r(s, ",", &save_ptr); name != NULL;
                 name = strtok_r(NULL, ",", &save_ptr)) {
                char *equals;
                int has_arg;

                ovs_assert(name[0] == '-' && name[1] == '-' && name[2]);
                name += 2;

                equals = strchr(name, '=');
                if (equals) {
                    has_arg = required_argument;
                    *equals = '\0';
                } else {
                    has_arg = no_argument;
                }

                o = find_option(name, options, n_options);
                if (o) {
                    ovs_assert(o - options >= n_global_long_options);
                    ovs_assert(o->has_arg == has_arg);
                } else {
                    o = add_option(&options, &n_options, &allocated_options);
                    o->name = xstrdup(name);
                    o->has_arg = has_arg;
                    o->flag = NULL;
                    o->val = OPT_LOCAL;
                }
            }

            free(s);
        }
    }
    o = add_option(&options, &n_options, &allocated_options);
    memset(o, 0, sizeof *o);

    table_style.format = TF_LIST;

    for (;;) {
        int idx;
        int c;

        c = getopt_long(argc, argv, short_options, options, &idx);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_DB:
            db = optarg;
            break;

        case OPT_ONELINE:
            oneline = true;
            break;

        case OPT_NO_SYSLOG:
            vlog_set_levels(&VLM_vsctl, VLF_SYSLOG, VLL_WARN);
            break;

        case OPT_NO_WAIT:
            wait_for_reload = false;
            break;

        case OPT_DRY_RUN:
            dry_run = true;
            break;

        case OPT_LOCAL:
            if (shash_find(local_options, options[idx].name)) {
                vsctl_fatal("'%s' option specified multiple times",
                            options[idx].name);
            }
            shash_add_nocopy(local_options,
                             xasprintf("--%s", options[idx].name),
                             optarg ? xstrdup(optarg) : NULL);
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            printf("DB Schema %s\n", ovsrec_get_db_version());
            exit(EXIT_SUCCESS);

        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout < 0) {
                vsctl_fatal("value %s on -t or --timeout is invalid",
                            optarg);
            }
            break;

        case OPT_RETRY:
            retry = true;
            break;

        VLOG_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)

        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    if (!db) {
        db = default_db();
    }

    for (i = n_global_long_options; options[i].name; i++) {
        free(CONST_CAST(char *, options[i].name));
    }
    free(options);
}

static struct vsctl_command *
parse_commands(int argc, char *argv[], struct shash *local_options,
               size_t *n_commandsp)
{
    struct vsctl_command *commands;
    size_t n_commands, allocated_commands;
    int i, start;

    commands = NULL;
    n_commands = allocated_commands = 0;

    for (start = i = 0; i <= argc; i++) {
        if (i == argc || !strcmp(argv[i], "--")) {
            if (i > start) {
                if (n_commands >= allocated_commands) {
                    struct vsctl_command *c;

                    commands = x2nrealloc(commands, &allocated_commands,
                                          sizeof *commands);
                    for (c = commands; c < &commands[n_commands]; c++) {
                        shash_moved(&c->options);
                    }
                }
                parse_command(i - start, &argv[start], local_options,
                              &commands[n_commands++]);
            } else if (!shash_is_empty(local_options)) {
                vsctl_fatal("missing command name (use --help for help)");
            }
            start = i + 1;
        }
    }
    if (!n_commands) {
        vsctl_fatal("missing command name (use --help for help)");
    }
    *n_commandsp = n_commands;
    return commands;
}

static void
parse_command(int argc, char *argv[], struct shash *local_options,
              struct vsctl_command *command)
{
    const struct vsctl_command_syntax *p;
    struct shash_node *node;
    int n_arg;
    int i;

    shash_init(&command->options);
    shash_swap(local_options, &command->options);
    for (i = 0; i < argc; i++) {
        const char *option = argv[i];
        const char *equals;
        char *key, *value;

        if (option[0] != '-') {
            break;
        }

        equals = strchr(option, '=');
        if (equals) {
            key = xmemdup0(option, equals - option);
            value = xstrdup(equals + 1);
        } else {
            key = xstrdup(option);
            value = NULL;
        }

        if (shash_find(&command->options, key)) {
            vsctl_fatal("'%s' option specified multiple times", argv[i]);
        }
        shash_add_nocopy(&command->options, key, value);
    }
    if (i == argc) {
        vsctl_fatal("missing command name (use --help for help)");
    }

    p = find_command(argv[i]);
    if (!p) {
        vsctl_fatal("unknown command '%s'; use --help for help", argv[i]);
    }

    SHASH_FOR_EACH (node, &command->options) {
        const char *s = strstr(p->options, node->name);
        int end = s ? s[strlen(node->name)] : EOF;

        if (end != '=' && end != ',' && end != ' ' && end != '\0') {
            vsctl_fatal("'%s' command has no '%s' option",
                        argv[i], node->name);
        }
        if ((end == '=') != (node->data != NULL)) {
            if (end == '=') {
                vsctl_fatal("missing argument to '%s' option on '%s' "
                            "command", node->name, argv[i]);
            } else {
                vsctl_fatal("'%s' option on '%s' does not accept an "
                            "argument", node->name, argv[i]);
            }
        }
    }

    n_arg = argc - i - 1;
    if (n_arg < p->min_args) {
        vsctl_fatal("'%s' command requires at least %d arguments",
                    p->name, p->min_args);
    } else if (n_arg > p->max_args) {
        int j;

        for (j = i + 1; j < argc; j++) {
            if (argv[j][0] == '-') {
                vsctl_fatal("'%s' command takes at most %d arguments "
                            "(note that options must precede command "
                            "names and follow a \"--\" argument)",
                            p->name, p->max_args);
            }
        }

        vsctl_fatal("'%s' command takes at most %d arguments",
                    p->name, p->max_args);
    }

    command->syntax = p;
    command->argc = n_arg + 1;
    command->argv = &argv[i];
}

/* Returns the "struct vsctl_command_syntax" for a given command 'name', or a
 * null pointer if there is none. */
static const struct vsctl_command_syntax *
find_command(const char *name)
{
    static struct shash commands = SHASH_INITIALIZER(&commands);

    if (shash_is_empty(&commands)) {
        const struct vsctl_command_syntax *p;

        for (p = get_all_commands(); p->name; p++) {
            shash_add_assert(&commands, p->name, p);
        }
    }

    return shash_find_data(&commands, name);
}

static void
vsctl_fatal(const char *format, ...)
{
    char *message;
    va_list args;

    va_start(args, format);
    message = xvasprintf(format, args);
    va_end(args);

    vlog_set_levels(&VLM_vsctl, VLF_CONSOLE, VLL_OFF);
    VLOG_ERR("%s", message);
    ovs_error(0, "%s", message);
    vsctl_exit(EXIT_FAILURE);
}

/* Frees the current transaction and the underlying IDL and then calls
 * exit(status).
 *
 * Freeing the transaction and the IDL is not strictly necessary, but it makes
 * for a clean memory leak report from valgrind in the normal case.  That makes
 * it easier to notice real memory leaks. */
static void
vsctl_exit(int status)
{
    if (the_idl_txn) {
        ovsdb_idl_txn_abort(the_idl_txn);
        ovsdb_idl_txn_destroy(the_idl_txn);
    }
    ovsdb_idl_destroy(the_idl);
    exit(status);
}

static void
usage(void)
{
    printf("\
%s: ovs-vswitchd management utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
Open vSwitch commands:\n\
  init                        initialize database, if not yet initialized\n\
  show                        print overview of database contents\n\
  emer-reset                  reset configuration to clean state\n\
\n\
Bridge commands:\n\
  add-br BRIDGE               create a new bridge named BRIDGE\n\
  add-br BRIDGE PARENT VLAN   create new fake BRIDGE in PARENT on VLAN\n\
  del-br BRIDGE               delete BRIDGE and all of its ports\n\
  list-br                     print the names of all the bridges\n\
  br-exists BRIDGE            exit 2 if BRIDGE does not exist\n\
  br-to-vlan BRIDGE           print the VLAN which BRIDGE is on\n\
  br-to-parent BRIDGE         print the parent of BRIDGE\n\
  br-set-external-id BRIDGE KEY VALUE  set KEY on BRIDGE to VALUE\n\
  br-set-external-id BRIDGE KEY  unset KEY on BRIDGE\n\
  br-get-external-id BRIDGE KEY  print value of KEY on BRIDGE\n\
  br-get-external-id BRIDGE  list key-value pairs on BRIDGE\n\
\n\
Port commands (a bond is considered to be a single port):\n\
  list-ports BRIDGE           print the names of all the ports on BRIDGE\n\
  add-port BRIDGE PORT        add network device PORT to BRIDGE\n\
  add-bond BRIDGE PORT IFACE...  add bonded port PORT in BRIDGE from IFACES\n\
  del-port [BRIDGE] PORT      delete PORT (which may be bonded) from BRIDGE\n\
  port-to-br PORT             print name of bridge that contains PORT\n\
\n\
Interface commands (a bond consists of multiple interfaces):\n\
  list-ifaces BRIDGE          print the names of all interfaces on BRIDGE\n\
  iface-to-br IFACE           print name of bridge that contains IFACE\n\
\n\
Controller commands:\n\
  get-controller BRIDGE      print the controllers for BRIDGE\n\
  del-controller BRIDGE      delete the controllers for BRIDGE\n\
  set-controller BRIDGE TARGET...  set the controllers for BRIDGE\n\
  get-fail-mode BRIDGE       print the fail-mode for BRIDGE\n\
  del-fail-mode BRIDGE       delete the fail-mode for BRIDGE\n\
  set-fail-mode BRIDGE MODE  set the fail-mode for BRIDGE to MODE\n\
\n\
Manager commands:\n\
  get-manager                print the managers\n\
  del-manager                delete the managers\n\
  set-manager TARGET...      set the list of managers to TARGET...\n\
\n\
SSL commands:\n\
  get-ssl                     print the SSL configuration\n\
  del-ssl                     delete the SSL configuration\n\
  set-ssl PRIV-KEY CERT CA-CERT  set the SSL configuration\n\
\n\
Switch commands:\n\
  emer-reset                  reset switch to known good state\n\
\n\
Database commands:\n\
  list TBL [REC]              list RECord (or all records) in TBL\n\
  find TBL CONDITION...       list records satisfying CONDITION in TBL\n\
  get TBL REC COL[:KEY]       print values of COLumns in RECord in TBL\n\
  set TBL REC COL[:KEY]=VALUE set COLumn values in RECord in TBL\n\
  add TBL REC COL [KEY=]VALUE add (KEY=)VALUE to COLumn in RECord in TBL\n\
  remove TBL REC COL [KEY=]VALUE  remove (KEY=)VALUE from COLumn\n\
  clear TBL REC COL           clear values from COLumn in RECord in TBL\n\
  create TBL COL[:KEY]=VALUE  create and initialize new record\n\
  destroy TBL REC             delete RECord from TBL\n\
  wait-until TBL REC [COL[:KEY]=VALUE]  wait until condition is true\n\
Potentially unsafe database commands require --force option.\n\
\n\
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  --no-wait                   do not wait for ovs-vswitchd to reconfigure\n\
  --retry                     keep trying to connect to server forever\n\
  -t, --timeout=SECS          wait at most SECS seconds for ovs-vswitchd\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           program_name, program_name, default_db());
    vlog_usage();
    printf("\
  --no-syslog             equivalent to --verbose=vsctl:syslog:warn\n");
    stream_usage("database", true, true, false);
    printf("\n\
Other options:\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static char *
default_db(void)
{
    static char *def;
    if (!def) {
        def = xasprintf("unix:%s/db.sock", ovs_rundir());
    }
    return def;
}

/* Returns true if it looks like this set of arguments might modify the
 * database, otherwise false.  (Not very smart, so it's prone to false
 * positives.) */
static bool
might_write_to_db(char **argv)
{
    for (; *argv; argv++) {
        const struct vsctl_command_syntax *p = find_command(*argv);
        if (p && p->mode == RW) {
            return true;
        }
    }
    return false;
}

struct vsctl_context {
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
    const struct ovsrec_open_vswitch *ovs;
    bool verified_ports;

    /* A cache of the contents of the database.
     *
     * A command that needs to use any of this information must first call
     * vsctl_context_populate_cache().  A command that changes anything that
     * could invalidate the cache must either call
     * vsctl_context_invalidate_cache() or manually update the cache to
     * maintain its correctness. */
    bool cache_valid;
    struct shash bridges;   /* Maps from bridge name to struct vsctl_bridge. */
    struct shash ports;     /* Maps from port name to struct vsctl_port. */
    struct shash ifaces;    /* Maps from port name to struct vsctl_iface. */

    /* A command may set this member to true if some prerequisite is not met
     * and the caller should wait for something to change and then retry. */
    bool try_again;
};

struct vsctl_bridge {
    struct ovsrec_bridge *br_cfg;
    char *name;
    struct list ports;          /* Contains "struct vsctl_port"s. */

    /* VLAN ("fake") bridge support.
     *
     * Use 'parent != NULL' to detect a fake bridge, because 'vlan' can be 0
     * in either case. */
    struct hmap children;        /* VLAN bridges indexed by 'vlan'. */
    struct hmap_node children_node; /* Node in parent's 'children' hmap. */
    struct vsctl_bridge *parent; /* Real bridge, or NULL. */
    int vlan;                    /* VLAN VID (0...4095), or 0. */
};

struct vsctl_port {
    struct list ports_node;     /* In struct vsctl_bridge's 'ports' list. */
    struct list ifaces;         /* Contains "struct vsctl_iface"s. */
    struct ovsrec_port *port_cfg;
    struct vsctl_bridge *bridge;
};

struct vsctl_iface {
    struct list ifaces_node;     /* In struct vsctl_port's 'ifaces' list. */
    struct ovsrec_interface *iface_cfg;
    struct vsctl_port *port;
};

static char *
vsctl_context_to_string(const struct vsctl_context *ctx)
{
    const struct shash_node *node;
    struct svec words;
    char *s;
    int i;

    svec_init(&words);
    SHASH_FOR_EACH (node, &ctx->options) {
        svec_add(&words, node->name);
    }
    for (i = 0; i < ctx->argc; i++) {
        svec_add(&words, ctx->argv[i]);
    }
    svec_terminate(&words);

    s = process_escape_args(words.names);

    svec_destroy(&words);

    return s;
}

static void
verify_ports(struct vsctl_context *ctx)
{
    if (!ctx->verified_ports) {
        const struct ovsrec_bridge *bridge;
        const struct ovsrec_port *port;

        ovsrec_open_vswitch_verify_bridges(ctx->ovs);
        OVSREC_BRIDGE_FOR_EACH (bridge, ctx->idl) {
            ovsrec_bridge_verify_ports(bridge);
        }
        OVSREC_PORT_FOR_EACH (port, ctx->idl) {
            ovsrec_port_verify_interfaces(port);
        }

        ctx->verified_ports = true;
    }
}

static struct vsctl_bridge *
add_bridge_to_cache(struct vsctl_context *ctx,
                    struct ovsrec_bridge *br_cfg, const char *name,
                    struct vsctl_bridge *parent, int vlan)
{
    struct vsctl_bridge *br = xmalloc(sizeof *br);
    br->br_cfg = br_cfg;
    br->name = xstrdup(name);
    list_init(&br->ports);
    br->parent = parent;
    br->vlan = vlan;
    hmap_init(&br->children);
    if (parent) {
        hmap_insert(&parent->children, &br->children_node, hash_int(vlan, 0));
    }
    shash_add(&ctx->bridges, br->name, br);
    return br;
}

static void
ovs_delete_bridge(const struct ovsrec_open_vswitch *ovs,
                  struct ovsrec_bridge *bridge)
{
    struct ovsrec_bridge **bridges;
    size_t i, n;

    bridges = xmalloc(sizeof *ovs->bridges * ovs->n_bridges);
    for (i = n = 0; i < ovs->n_bridges; i++) {
        if (ovs->bridges[i] != bridge) {
            bridges[n++] = ovs->bridges[i];
        }
    }
    ovsrec_open_vswitch_set_bridges(ovs, bridges, n);
    free(bridges);
}

static void
del_cached_bridge(struct vsctl_context *ctx, struct vsctl_bridge *br)
{
    ovs_assert(list_is_empty(&br->ports));
    ovs_assert(hmap_is_empty(&br->children));
    if (br->parent) {
        hmap_remove(&br->parent->children, &br->children_node);
    }
    if (br->br_cfg) {
        ovsrec_bridge_delete(br->br_cfg);
        ovs_delete_bridge(ctx->ovs, br->br_cfg);
    }
    shash_find_and_delete(&ctx->bridges, br->name);
    hmap_destroy(&br->children);
    free(br->name);
    free(br);
}

static bool
port_is_fake_bridge(const struct ovsrec_port *port_cfg)
{
    return (port_cfg->fake_bridge
            && port_cfg->tag
            && *port_cfg->tag >= 0 && *port_cfg->tag <= 4095);
}

static struct vsctl_bridge *
find_vlan_bridge(struct vsctl_bridge *parent, int vlan)
{
    struct vsctl_bridge *child;

    HMAP_FOR_EACH_IN_BUCKET (child, children_node, hash_int(vlan, 0),
                             &parent->children) {
        if (child->vlan == vlan) {
            return child;
        }
    }

    return NULL;
}

static struct vsctl_port *
add_port_to_cache(struct vsctl_context *ctx, struct vsctl_bridge *parent,
                  struct ovsrec_port *port_cfg)
{
    struct vsctl_port *port;

    if (port_cfg->tag
        && *port_cfg->tag >= 0 && *port_cfg->tag <= 4095) {
        struct vsctl_bridge *vlan_bridge;

        vlan_bridge = find_vlan_bridge(parent, *port_cfg->tag);
        if (vlan_bridge) {
            parent = vlan_bridge;
        }
    }

    port = xmalloc(sizeof *port);
    list_push_back(&parent->ports, &port->ports_node);
    list_init(&port->ifaces);
    port->port_cfg = port_cfg;
    port->bridge = parent;
    shash_add(&ctx->ports, port_cfg->name, port);

    return port;
}

static void
del_cached_port(struct vsctl_context *ctx, struct vsctl_port *port)
{
    ovs_assert(list_is_empty(&port->ifaces));
    list_remove(&port->ports_node);
    shash_find_and_delete(&ctx->ports, port->port_cfg->name);
    ovsrec_port_delete(port->port_cfg);
    free(port);
}

static struct vsctl_iface *
add_iface_to_cache(struct vsctl_context *ctx, struct vsctl_port *parent,
                   struct ovsrec_interface *iface_cfg)
{
    struct vsctl_iface *iface;

    iface = xmalloc(sizeof *iface);
    list_push_back(&parent->ifaces, &iface->ifaces_node);
    iface->iface_cfg = iface_cfg;
    iface->port = parent;
    shash_add(&ctx->ifaces, iface_cfg->name, iface);

    return iface;
}

static void
del_cached_iface(struct vsctl_context *ctx, struct vsctl_iface *iface)
{
    list_remove(&iface->ifaces_node);
    shash_find_and_delete(&ctx->ifaces, iface->iface_cfg->name);
    ovsrec_interface_delete(iface->iface_cfg);
    free(iface);
}

static void
vsctl_context_invalidate_cache(struct vsctl_context *ctx)
{
    struct shash_node *node;

    if (!ctx->cache_valid) {
        return;
    }
    ctx->cache_valid = false;

    SHASH_FOR_EACH (node, &ctx->bridges) {
        struct vsctl_bridge *bridge = node->data;
        hmap_destroy(&bridge->children);
        free(bridge->name);
        free(bridge);
    }
    shash_destroy(&ctx->bridges);

    shash_destroy_free_data(&ctx->ports);
    shash_destroy_free_data(&ctx->ifaces);
}

static void
pre_get_info(struct vsctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &ovsrec_open_vswitch_col_bridges);

    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_controller);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_fail_mode);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_column(ctx->idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_port_col_fake_bridge);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_port_col_tag);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_port_col_interfaces);

    ovsdb_idl_add_column(ctx->idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_interface_col_ofport);
}

static void
vsctl_context_populate_cache(struct vsctl_context *ctx)
{
    const struct ovsrec_open_vswitch *ovs = ctx->ovs;
    struct sset bridges, ports;
    size_t i;

    if (ctx->cache_valid) {
        /* Cache is already populated. */
        return;
    }
    ctx->cache_valid = true;
    shash_init(&ctx->bridges);
    shash_init(&ctx->ports);
    shash_init(&ctx->ifaces);

    sset_init(&bridges);
    sset_init(&ports);
    for (i = 0; i < ovs->n_bridges; i++) {
        struct ovsrec_bridge *br_cfg = ovs->bridges[i];
        struct vsctl_bridge *br;
        size_t j;

        if (!sset_add(&bridges, br_cfg->name)) {
            VLOG_WARN("%s: database contains duplicate bridge name",
                      br_cfg->name);
            continue;
        }
        br = add_bridge_to_cache(ctx, br_cfg, br_cfg->name, NULL, 0);
        if (!br) {
            continue;
        }

        for (j = 0; j < br_cfg->n_ports; j++) {
            struct ovsrec_port *port_cfg = br_cfg->ports[j];

            if (!sset_add(&ports, port_cfg->name)) {
                /* Duplicate port name.  (We will warn about that later.) */
                continue;
            }

            if (port_is_fake_bridge(port_cfg)
                && sset_add(&bridges, port_cfg->name)) {
                add_bridge_to_cache(ctx, NULL, port_cfg->name, br,
                                    *port_cfg->tag);
            }
        }
    }
    sset_destroy(&bridges);
    sset_destroy(&ports);

    sset_init(&bridges);
    for (i = 0; i < ovs->n_bridges; i++) {
        struct ovsrec_bridge *br_cfg = ovs->bridges[i];
        struct vsctl_bridge *br;
        size_t j;

        if (!sset_add(&bridges, br_cfg->name)) {
            continue;
        }
        br = shash_find_data(&ctx->bridges, br_cfg->name);
        for (j = 0; j < br_cfg->n_ports; j++) {
            struct ovsrec_port *port_cfg = br_cfg->ports[j];
            struct vsctl_port *port;
            size_t k;

            port = shash_find_data(&ctx->ports, port_cfg->name);
            if (port) {
                if (port_cfg == port->port_cfg) {
                    VLOG_WARN("%s: port is in multiple bridges (%s and %s)",
                              port_cfg->name, br->name, port->bridge->name);
                } else {
                    /* Log as an error because this violates the database's
                     * uniqueness constraints, so the database server shouldn't
                     * have allowed it. */
                    VLOG_ERR("%s: database contains duplicate port name",
                             port_cfg->name);
                }
                continue;
            }

            if (port_is_fake_bridge(port_cfg)
                && !sset_add(&bridges, port_cfg->name)) {
                continue;
            }

            port = add_port_to_cache(ctx, br, port_cfg);
            for (k = 0; k < port_cfg->n_interfaces; k++) {
                struct ovsrec_interface *iface_cfg = port_cfg->interfaces[k];
                struct vsctl_iface *iface;

                iface = shash_find_data(&ctx->ifaces, iface_cfg->name);
                if (iface) {
                    if (iface_cfg == iface->iface_cfg) {
                        VLOG_WARN("%s: interface is in multiple ports "
                                  "(%s and %s)",
                                  iface_cfg->name,
                                  iface->port->port_cfg->name,
                                  port->port_cfg->name);
                    } else {
                        /* Log as an error because this violates the database's
                         * uniqueness constraints, so the database server
                         * shouldn't have allowed it. */
                        VLOG_ERR("%s: database contains duplicate interface "
                                 "name", iface_cfg->name);
                    }
                    continue;
                }

                add_iface_to_cache(ctx, port, iface_cfg);
            }
        }
    }
    sset_destroy(&bridges);
}

static void
check_conflicts(struct vsctl_context *ctx, const char *name,
                char *msg)
{
    struct vsctl_iface *iface;
    struct vsctl_port *port;

    verify_ports(ctx);

    if (shash_find(&ctx->bridges, name)) {
        vsctl_fatal("%s because a bridge named %s already exists",
                    msg, name);
    }

    port = shash_find_data(&ctx->ports, name);
    if (port) {
        vsctl_fatal("%s because a port named %s already exists on "
                    "bridge %s", msg, name, port->bridge->name);
    }

    iface = shash_find_data(&ctx->ifaces, name);
    if (iface) {
        vsctl_fatal("%s because an interface named %s already exists "
                    "on bridge %s", msg, name, iface->port->bridge->name);
    }

    free(msg);
}

static struct vsctl_bridge *
find_bridge(struct vsctl_context *ctx, const char *name, bool must_exist)
{
    struct vsctl_bridge *br;

    ovs_assert(ctx->cache_valid);

    br = shash_find_data(&ctx->bridges, name);
    if (must_exist && !br) {
        vsctl_fatal("no bridge named %s", name);
    }
    ovsrec_open_vswitch_verify_bridges(ctx->ovs);
    return br;
}

static struct vsctl_bridge *
find_real_bridge(struct vsctl_context *ctx, const char *name, bool must_exist)
{
    struct vsctl_bridge *br = find_bridge(ctx, name, must_exist);
    if (br && br->parent) {
        vsctl_fatal("%s is a fake bridge", name);
    }
    return br;
}

static struct vsctl_port *
find_port(struct vsctl_context *ctx, const char *name, bool must_exist)
{
    struct vsctl_port *port;

    ovs_assert(ctx->cache_valid);

    port = shash_find_data(&ctx->ports, name);
    if (port && !strcmp(name, port->bridge->name)) {
        port = NULL;
    }
    if (must_exist && !port) {
        vsctl_fatal("no port named %s", name);
    }
    verify_ports(ctx);
    return port;
}

static struct vsctl_iface *
find_iface(struct vsctl_context *ctx, const char *name, bool must_exist)
{
    struct vsctl_iface *iface;

    ovs_assert(ctx->cache_valid);

    iface = shash_find_data(&ctx->ifaces, name);
    if (iface && !strcmp(name, iface->port->bridge->name)) {
        iface = NULL;
    }
    if (must_exist && !iface) {
        vsctl_fatal("no interface named %s", name);
    }
    verify_ports(ctx);
    return iface;
}

static void
bridge_insert_port(struct ovsrec_bridge *br, struct ovsrec_port *port)
{
    struct ovsrec_port **ports;
    size_t i;

    ports = xmalloc(sizeof *br->ports * (br->n_ports + 1));
    for (i = 0; i < br->n_ports; i++) {
        ports[i] = br->ports[i];
    }
    ports[br->n_ports] = port;
    ovsrec_bridge_set_ports(br, ports, br->n_ports + 1);
    free(ports);
}

static void
bridge_delete_port(struct ovsrec_bridge *br, struct ovsrec_port *port)
{
    struct ovsrec_port **ports;
    size_t i, n;

    ports = xmalloc(sizeof *br->ports * br->n_ports);
    for (i = n = 0; i < br->n_ports; i++) {
        if (br->ports[i] != port) {
            ports[n++] = br->ports[i];
        }
    }
    ovsrec_bridge_set_ports(br, ports, n);
    free(ports);
}

static void
ovs_insert_bridge(const struct ovsrec_open_vswitch *ovs,
                  struct ovsrec_bridge *bridge)
{
    struct ovsrec_bridge **bridges;
    size_t i;

    bridges = xmalloc(sizeof *ovs->bridges * (ovs->n_bridges + 1));
    for (i = 0; i < ovs->n_bridges; i++) {
        bridges[i] = ovs->bridges[i];
    }
    bridges[ovs->n_bridges] = bridge;
    ovsrec_open_vswitch_set_bridges(ovs, bridges, ovs->n_bridges + 1);
    free(bridges);
}

static void
cmd_init(struct vsctl_context *ctx OVS_UNUSED)
{
}

struct cmd_show_table {
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *name_column;
    const struct ovsdb_idl_column *columns[3];
    bool recurse;
};

static struct cmd_show_table cmd_show_tables[] = {
    {&ovsrec_table_open_vswitch,
     NULL,
     {&ovsrec_open_vswitch_col_manager_options,
      &ovsrec_open_vswitch_col_bridges,
      &ovsrec_open_vswitch_col_ovs_version},
     false},

    {&ovsrec_table_bridge,
     &ovsrec_bridge_col_name,
     {&ovsrec_bridge_col_controller,
      &ovsrec_bridge_col_fail_mode,
      &ovsrec_bridge_col_ports},
     false},

    {&ovsrec_table_port,
     &ovsrec_port_col_name,
     {&ovsrec_port_col_tag,
      &ovsrec_port_col_trunks,
      &ovsrec_port_col_interfaces},
     false},

    {&ovsrec_table_interface,
     &ovsrec_interface_col_name,
     {&ovsrec_interface_col_type,
      &ovsrec_interface_col_options,
      NULL},
     false},

    {&ovsrec_table_controller,
     &ovsrec_controller_col_target,
     {&ovsrec_controller_col_is_connected,
      NULL,
      NULL},
     false},

    {&ovsrec_table_manager,
     &ovsrec_manager_col_target,
     {&ovsrec_manager_col_is_connected,
      NULL,
      NULL},
     false},
};

static void
pre_cmd_show(struct vsctl_context *ctx)
{
    struct cmd_show_table *show;

    for (show = cmd_show_tables;
         show < &cmd_show_tables[ARRAY_SIZE(cmd_show_tables)];
         show++) {
        size_t i;

        ovsdb_idl_add_table(ctx->idl, show->table);
        if (show->name_column) {
            ovsdb_idl_add_column(ctx->idl, show->name_column);
        }
        for (i = 0; i < ARRAY_SIZE(show->columns); i++) {
            const struct ovsdb_idl_column *column = show->columns[i];
            if (column) {
                ovsdb_idl_add_column(ctx->idl, column);
            }
        }
    }
}

static struct cmd_show_table *
cmd_show_find_table_by_row(const struct ovsdb_idl_row *row)
{
    struct cmd_show_table *show;

    for (show = cmd_show_tables;
         show < &cmd_show_tables[ARRAY_SIZE(cmd_show_tables)];
         show++) {
        if (show->table == row->table->class) {
            return show;
        }
    }
    return NULL;
}

static struct cmd_show_table *
cmd_show_find_table_by_name(const char *name)
{
    struct cmd_show_table *show;

    for (show = cmd_show_tables;
         show < &cmd_show_tables[ARRAY_SIZE(cmd_show_tables)];
         show++) {
        if (!strcmp(show->table->name, name)) {
            return show;
        }
    }
    return NULL;
}

static void
cmd_show_row(struct vsctl_context *ctx, const struct ovsdb_idl_row *row,
             int level)
{
    struct cmd_show_table *show = cmd_show_find_table_by_row(row);
    size_t i;

    ds_put_char_multiple(&ctx->output, ' ', level * 4);
    if (show && show->name_column) {
        const struct ovsdb_datum *datum;

        ds_put_format(&ctx->output, "%s ", show->table->name);
        datum = ovsdb_idl_read(row, show->name_column);
        ovsdb_datum_to_string(datum, &show->name_column->type, &ctx->output);
    } else {
        ds_put_format(&ctx->output, UUID_FMT, UUID_ARGS(&row->uuid));
    }
    ds_put_char(&ctx->output, '\n');

    if (!show || show->recurse) {
        return;
    }

    show->recurse = true;
    for (i = 0; i < ARRAY_SIZE(show->columns); i++) {
        const struct ovsdb_idl_column *column = show->columns[i];
        const struct ovsdb_datum *datum;

        if (!column) {
            break;
        }

        datum = ovsdb_idl_read(row, column);
        if (column->type.key.type == OVSDB_TYPE_UUID &&
            column->type.key.u.uuid.refTableName) {
            struct cmd_show_table *ref_show;
            size_t j;

            ref_show = cmd_show_find_table_by_name(
                column->type.key.u.uuid.refTableName);
            if (ref_show) {
                for (j = 0; j < datum->n; j++) {
                    const struct ovsdb_idl_row *ref_row;

                    ref_row = ovsdb_idl_get_row_for_uuid(ctx->idl,
                                                         ref_show->table,
                                                         &datum->keys[j].uuid);
                    if (ref_row) {
                        cmd_show_row(ctx, ref_row, level + 1);
                    }
                }
                continue;
            }
        }

        if (!ovsdb_datum_is_default(datum, &column->type)) {
            ds_put_char_multiple(&ctx->output, ' ', (level + 1) * 4);
            ds_put_format(&ctx->output, "%s: ", column->name);
            ovsdb_datum_to_string(datum, &column->type, &ctx->output);
            ds_put_char(&ctx->output, '\n');
        }
    }
    show->recurse = false;
}

static void
cmd_show(struct vsctl_context *ctx)
{
    const struct ovsdb_idl_row *row;

    for (row = ovsdb_idl_first_row(ctx->idl, cmd_show_tables[0].table);
         row; row = ovsdb_idl_next_row(row)) {
        cmd_show_row(ctx, row, 0);
    }
}

static void
pre_cmd_emer_reset(struct vsctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &ovsrec_open_vswitch_col_manager_options);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_open_vswitch_col_ssl);

    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_controller);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_fail_mode);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_mirrors);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_netflow);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_sflow);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_ipfix);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_flood_vlans);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_other_config);

    ovsdb_idl_add_column(ctx->idl, &ovsrec_port_col_other_config);

    ovsdb_idl_add_column(ctx->idl,
                          &ovsrec_interface_col_ingress_policing_rate);
    ovsdb_idl_add_column(ctx->idl,
                          &ovsrec_interface_col_ingress_policing_burst);
}

static void
cmd_emer_reset(struct vsctl_context *ctx)
{
    const struct ovsdb_idl *idl = ctx->idl;
    const struct ovsrec_bridge *br;
    const struct ovsrec_port *port;
    const struct ovsrec_interface *iface;
    const struct ovsrec_mirror *mirror, *next_mirror;
    const struct ovsrec_controller *ctrl, *next_ctrl;
    const struct ovsrec_manager *mgr, *next_mgr;
    const struct ovsrec_netflow *nf, *next_nf;
    const struct ovsrec_ssl *ssl, *next_ssl;
    const struct ovsrec_sflow *sflow, *next_sflow;
    const struct ovsrec_ipfix *ipfix, *next_ipfix;
    const struct ovsrec_flow_sample_collector_set *fscset, *next_fscset;

    /* Reset the Open_vSwitch table. */
    ovsrec_open_vswitch_set_manager_options(ctx->ovs, NULL, 0);
    ovsrec_open_vswitch_set_ssl(ctx->ovs, NULL);

    OVSREC_BRIDGE_FOR_EACH (br, idl) {
        const char *hwaddr;

        ovsrec_bridge_set_controller(br, NULL, 0);
        ovsrec_bridge_set_fail_mode(br, NULL);
        ovsrec_bridge_set_mirrors(br, NULL, 0);
        ovsrec_bridge_set_netflow(br, NULL);
        ovsrec_bridge_set_sflow(br, NULL);
        ovsrec_bridge_set_ipfix(br, NULL);
        ovsrec_bridge_set_flood_vlans(br, NULL, 0);

        /* We only want to save the "hwaddr" key from other_config. */
        hwaddr = smap_get(&br->other_config, "hwaddr");
        if (hwaddr) {
            struct smap smap = SMAP_INITIALIZER(&smap);
            smap_add(&smap, "hwaddr", hwaddr);
            ovsrec_bridge_set_other_config(br, &smap);
            smap_destroy(&smap);
        } else {
            ovsrec_bridge_set_other_config(br, NULL);
        }
    }

    OVSREC_PORT_FOR_EACH (port, idl) {
        ovsrec_port_set_other_config(port, NULL);
    }

    OVSREC_INTERFACE_FOR_EACH (iface, idl) {
        /* xxx What do we do about gre/patch devices created by mgr? */

        ovsrec_interface_set_ingress_policing_rate(iface, 0);
        ovsrec_interface_set_ingress_policing_burst(iface, 0);
    }

    OVSREC_MIRROR_FOR_EACH_SAFE (mirror, next_mirror, idl) {
        ovsrec_mirror_delete(mirror);
    }

    OVSREC_CONTROLLER_FOR_EACH_SAFE (ctrl, next_ctrl, idl) {
        ovsrec_controller_delete(ctrl);
    }

    OVSREC_MANAGER_FOR_EACH_SAFE (mgr, next_mgr, idl) {
        ovsrec_manager_delete(mgr);
    }

    OVSREC_NETFLOW_FOR_EACH_SAFE (nf, next_nf, idl) {
        ovsrec_netflow_delete(nf);
    }

    OVSREC_SSL_FOR_EACH_SAFE (ssl, next_ssl, idl) {
        ovsrec_ssl_delete(ssl);
    }

    OVSREC_SFLOW_FOR_EACH_SAFE (sflow, next_sflow, idl) {
        ovsrec_sflow_delete(sflow);
    }

    OVSREC_IPFIX_FOR_EACH_SAFE (ipfix, next_ipfix, idl) {
        ovsrec_ipfix_delete(ipfix);
    }

    OVSREC_FLOW_SAMPLE_COLLECTOR_SET_FOR_EACH_SAFE (fscset, next_fscset, idl) {
        ovsrec_flow_sample_collector_set_delete(fscset);
    }

    vsctl_context_invalidate_cache(ctx);
}

static void
cmd_add_br(struct vsctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    const char *br_name, *parent_name;
    struct ovsrec_interface *iface;
    int vlan;

    br_name = ctx->argv[1];
    if (ctx->argc == 2) {
        parent_name = NULL;
        vlan = 0;
    } else if (ctx->argc == 4) {
        parent_name = ctx->argv[2];
        vlan = atoi(ctx->argv[3]);
        if (vlan < 0 || vlan > 4095) {
            vsctl_fatal("%s: vlan must be between 0 and 4095", ctx->argv[0]);
        }
    } else {
        vsctl_fatal("'%s' command takes exactly 1 or 3 arguments",
                    ctx->argv[0]);
    }

    vsctl_context_populate_cache(ctx);
    if (may_exist) {
        struct vsctl_bridge *br;

        br = find_bridge(ctx, br_name, false);
        if (br) {
            if (!parent_name) {
                if (br->parent) {
                    vsctl_fatal("\"--may-exist add-br %s\" but %s is "
                                "a VLAN bridge for VLAN %d",
                                br_name, br_name, br->vlan);
                }
            } else {
                if (!br->parent) {
                    vsctl_fatal("\"--may-exist add-br %s %s %d\" but %s "
                                "is not a VLAN bridge",
                                br_name, parent_name, vlan, br_name);
                } else if (strcmp(br->parent->name, parent_name)) {
                    vsctl_fatal("\"--may-exist add-br %s %s %d\" but %s "
                                "has the wrong parent %s",
                                br_name, parent_name, vlan,
                                br_name, br->parent->name);
                } else if (br->vlan != vlan) {
                    vsctl_fatal("\"--may-exist add-br %s %s %d\" but %s "
                                "is a VLAN bridge for the wrong VLAN %d",
                                br_name, parent_name, vlan, br_name, br->vlan);
                }
            }
            return;
        }
    }
    check_conflicts(ctx, br_name,
                    xasprintf("cannot create a bridge named %s", br_name));

    if (!parent_name) {
        struct ovsrec_port *port;
        struct ovsrec_bridge *br;

        iface = ovsrec_interface_insert(ctx->txn);
        ovsrec_interface_set_name(iface, br_name);
        ovsrec_interface_set_type(iface, "internal");

        port = ovsrec_port_insert(ctx->txn);
        ovsrec_port_set_name(port, br_name);
        ovsrec_port_set_interfaces(port, &iface, 1);

        br = ovsrec_bridge_insert(ctx->txn);
        ovsrec_bridge_set_name(br, br_name);
        ovsrec_bridge_set_ports(br, &port, 1);

        ovs_insert_bridge(ctx->ovs, br);
    } else {
        struct vsctl_bridge *parent;
        struct ovsrec_port *port;
        struct ovsrec_bridge *br;
        int64_t tag = vlan;

        parent = find_bridge(ctx, parent_name, false);
        if (parent && parent->parent) {
            vsctl_fatal("cannot create bridge with fake bridge as parent");
        }
        if (!parent) {
            vsctl_fatal("parent bridge %s does not exist", parent_name);
        }
        br = parent->br_cfg;

        iface = ovsrec_interface_insert(ctx->txn);
        ovsrec_interface_set_name(iface, br_name);
        ovsrec_interface_set_type(iface, "internal");

        port = ovsrec_port_insert(ctx->txn);
        ovsrec_port_set_name(port, br_name);
        ovsrec_port_set_interfaces(port, &iface, 1);
        ovsrec_port_set_fake_bridge(port, true);
        ovsrec_port_set_tag(port, &tag, 1);

        bridge_insert_port(br, port);
    }

    post_db_reload_expect_iface(iface);
    vsctl_context_invalidate_cache(ctx);
}

static void
del_port(struct vsctl_context *ctx, struct vsctl_port *port)
{
    struct vsctl_iface *iface, *next_iface;

    bridge_delete_port((port->bridge->parent
                        ? port->bridge->parent->br_cfg
                        : port->bridge->br_cfg), port->port_cfg);

    LIST_FOR_EACH_SAFE (iface, next_iface, ifaces_node, &port->ifaces) {
        del_cached_iface(ctx, iface);
    }
    del_cached_port(ctx, port);
}

static void
del_bridge(struct vsctl_context *ctx, struct vsctl_bridge *br)
{
    struct vsctl_bridge *child, *next_child;
    struct vsctl_port *port, *next_port;
    const struct ovsrec_flow_sample_collector_set *fscset, *next_fscset;

    HMAP_FOR_EACH_SAFE (child, next_child, children_node, &br->children) {
        del_bridge(ctx, child);
    }

    LIST_FOR_EACH_SAFE (port, next_port, ports_node, &br->ports) {
        del_port(ctx, port);
    }

    OVSREC_FLOW_SAMPLE_COLLECTOR_SET_FOR_EACH_SAFE (fscset, next_fscset,
                                                    ctx->idl) {
        if (fscset->bridge == br->br_cfg) {
            ovsrec_flow_sample_collector_set_delete(fscset);
        }
    }

    del_cached_bridge(ctx, br);
}

static void
cmd_del_br(struct vsctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vsctl_bridge *bridge;

    vsctl_context_populate_cache(ctx);
    bridge = find_bridge(ctx, ctx->argv[1], must_exist);
    if (bridge) {
        del_bridge(ctx, bridge);
    }
}

static void
output_sorted(struct svec *svec, struct ds *output)
{
    const char *name;
    size_t i;

    svec_sort(svec);
    SVEC_FOR_EACH (i, name, svec) {
        ds_put_format(output, "%s\n", name);
    }
}

static void
cmd_list_br(struct vsctl_context *ctx)
{
    struct shash_node *node;
    struct svec bridges;
    bool real = shash_find(&ctx->options, "--real");
    bool fake = shash_find(&ctx->options, "--fake");

    /* If neither fake nor real were requested, return both. */
    if (!real && !fake) {
        real = fake = true;
    }

    vsctl_context_populate_cache(ctx);

    svec_init(&bridges);
    SHASH_FOR_EACH (node, &ctx->bridges) {
        struct vsctl_bridge *br = node->data;

        if (br->parent ? fake : real) {
            svec_add(&bridges, br->name);
        }
    }
    output_sorted(&bridges, &ctx->output);
    svec_destroy(&bridges);
}

static void
cmd_br_exists(struct vsctl_context *ctx)
{
    vsctl_context_populate_cache(ctx);
    if (!find_bridge(ctx, ctx->argv[1], false)) {
        vsctl_exit(2);
    }
}

static void
set_external_id(struct smap *old, struct smap *new,
                char *key, char *value)
{
    smap_clone(new, old);

    if (value) {
        smap_replace(new, key, value);
    } else {
        smap_remove(new, key);
    }
}

static void
pre_cmd_br_set_external_id(struct vsctl_context *ctx)
{
    pre_get_info(ctx);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_bridge_col_external_ids);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_port_col_external_ids);
}

static void
cmd_br_set_external_id(struct vsctl_context *ctx)
{
    struct vsctl_bridge *bridge;
    struct smap new;

    vsctl_context_populate_cache(ctx);
    bridge = find_bridge(ctx, ctx->argv[1], true);
    if (bridge->br_cfg) {

        set_external_id(&bridge->br_cfg->external_ids, &new, ctx->argv[2],
                        ctx->argc >= 4 ? ctx->argv[3] : NULL);
        ovsrec_bridge_verify_external_ids(bridge->br_cfg);
        ovsrec_bridge_set_external_ids(bridge->br_cfg, &new);
    } else {
        char *key = xasprintf("fake-bridge-%s", ctx->argv[2]);
        struct vsctl_port *port = shash_find_data(&ctx->ports, ctx->argv[1]);
        set_external_id(&port->port_cfg->external_ids, &new,
                        key, ctx->argc >= 4 ? ctx->argv[3] : NULL);
        ovsrec_port_verify_external_ids(port->port_cfg);
        ovsrec_port_set_external_ids(port->port_cfg, &new);
        free(key);
    }
    smap_destroy(&new);
}

static void
get_external_id(struct smap *smap, const char *prefix, const char *key,
                struct ds *output)
{
    if (key) {
        char *prefix_key = xasprintf("%s%s", prefix, key);
        const char *value = smap_get(smap, prefix_key);

        if (value) {
            ds_put_format(output, "%s\n", value);
        }
        free(prefix_key);
    } else {
        const struct smap_node **sorted = smap_sort(smap);
        size_t prefix_len = strlen(prefix);
        size_t i;

        for (i = 0; i < smap_count(smap); i++) {
            const struct smap_node *node = sorted[i];
            if (!strncmp(node->key, prefix, prefix_len)) {
                ds_put_format(output, "%s=%s\n", node->key + prefix_len,
                              node->value);
            }
        }
        free(sorted);
    }
}

static void
pre_cmd_br_get_external_id(struct vsctl_context *ctx)
{
    pre_cmd_br_set_external_id(ctx);
}

static void
cmd_br_get_external_id(struct vsctl_context *ctx)
{
    struct vsctl_bridge *bridge;

    vsctl_context_populate_cache(ctx);

    bridge = find_bridge(ctx, ctx->argv[1], true);
    if (bridge->br_cfg) {
        ovsrec_bridge_verify_external_ids(bridge->br_cfg);
        get_external_id(&bridge->br_cfg->external_ids, "",
                        ctx->argc >= 3 ? ctx->argv[2] : NULL, &ctx->output);
    } else {
        struct vsctl_port *port = shash_find_data(&ctx->ports, ctx->argv[1]);
        ovsrec_port_verify_external_ids(port->port_cfg);
        get_external_id(&port->port_cfg->external_ids, "fake-bridge-",
                        ctx->argc >= 3 ? ctx->argv[2] : NULL, &ctx->output);
    }
}

static void
cmd_list_ports(struct vsctl_context *ctx)
{
    struct vsctl_bridge *br;
    struct vsctl_port *port;
    struct svec ports;

    vsctl_context_populate_cache(ctx);
    br = find_bridge(ctx, ctx->argv[1], true);
    ovsrec_bridge_verify_ports(br->br_cfg ? br->br_cfg : br->parent->br_cfg);

    svec_init(&ports);
    LIST_FOR_EACH (port, ports_node, &br->ports) {
        if (strcmp(port->port_cfg->name, br->name)) {
            svec_add(&ports, port->port_cfg->name);
        }
    }
    output_sorted(&ports, &ctx->output);
    svec_destroy(&ports);
}

static void
add_port(struct vsctl_context *ctx,
         const char *br_name, const char *port_name,
         bool may_exist, bool fake_iface,
         char *iface_names[], int n_ifaces,
         char *settings[], int n_settings)
{
    struct vsctl_port *vsctl_port;
    struct vsctl_bridge *bridge;
    struct ovsrec_interface **ifaces;
    struct ovsrec_port *port;
    size_t i;

    vsctl_context_populate_cache(ctx);
    if (may_exist) {
        struct vsctl_port *vsctl_port;

        vsctl_port = find_port(ctx, port_name, false);
        if (vsctl_port) {
            struct svec want_names, have_names;

            svec_init(&want_names);
            for (i = 0; i < n_ifaces; i++) {
                svec_add(&want_names, iface_names[i]);
            }
            svec_sort(&want_names);

            svec_init(&have_names);
            for (i = 0; i < vsctl_port->port_cfg->n_interfaces; i++) {
                svec_add(&have_names,
                         vsctl_port->port_cfg->interfaces[i]->name);
            }
            svec_sort(&have_names);

            if (strcmp(vsctl_port->bridge->name, br_name)) {
                char *command = vsctl_context_to_string(ctx);
                vsctl_fatal("\"%s\" but %s is actually attached to bridge %s",
                            command, port_name, vsctl_port->bridge->name);
            }

            if (!svec_equal(&want_names, &have_names)) {
                char *have_names_string = svec_join(&have_names, ", ", "");
                char *command = vsctl_context_to_string(ctx);

                vsctl_fatal("\"%s\" but %s actually has interface(s) %s",
                            command, port_name, have_names_string);
            }

            svec_destroy(&want_names);
            svec_destroy(&have_names);

            return;
        }
    }
    check_conflicts(ctx, port_name,
                    xasprintf("cannot create a port named %s", port_name));
    for (i = 0; i < n_ifaces; i++) {
        check_conflicts(ctx, iface_names[i],
                        xasprintf("cannot create an interface named %s",
                                  iface_names[i]));
    }
    bridge = find_bridge(ctx, br_name, true);

    ifaces = xmalloc(n_ifaces * sizeof *ifaces);
    for (i = 0; i < n_ifaces; i++) {
        ifaces[i] = ovsrec_interface_insert(ctx->txn);
        ovsrec_interface_set_name(ifaces[i], iface_names[i]);
        post_db_reload_expect_iface(ifaces[i]);
    }

    port = ovsrec_port_insert(ctx->txn);
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, ifaces, n_ifaces);
    ovsrec_port_set_bond_fake_iface(port, fake_iface);

    if (bridge->parent) {
        int64_t tag = bridge->vlan;
        ovsrec_port_set_tag(port, &tag, 1);
    }

    for (i = 0; i < n_settings; i++) {
        set_column(get_table("Port"), &port->header_, settings[i],
                   ctx->symtab);
    }

    bridge_insert_port((bridge->parent ? bridge->parent->br_cfg
                        : bridge->br_cfg), port);

    vsctl_port = add_port_to_cache(ctx, bridge, port);
    for (i = 0; i < n_ifaces; i++) {
        add_iface_to_cache(ctx, vsctl_port, ifaces[i]);
    }
    free(ifaces);
}

static void
cmd_add_port(struct vsctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;

    add_port(ctx, ctx->argv[1], ctx->argv[2], may_exist, false,
             &ctx->argv[2], 1, &ctx->argv[3], ctx->argc - 3);
}

static void
cmd_add_bond(struct vsctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool fake_iface = shash_find(&ctx->options, "--fake-iface");
    int n_ifaces;
    int i;

    n_ifaces = ctx->argc - 3;
    for (i = 3; i < ctx->argc; i++) {
        if (strchr(ctx->argv[i], '=')) {
            n_ifaces = i - 3;
            break;
        }
    }
    if (n_ifaces < 2) {
        vsctl_fatal("add-bond requires at least 2 interfaces, but only "
                    "%d were specified", n_ifaces);
    }

    add_port(ctx, ctx->argv[1], ctx->argv[2], may_exist, fake_iface,
             &ctx->argv[3], n_ifaces,
             &ctx->argv[n_ifaces + 3], ctx->argc - 3 - n_ifaces);
}

static void
cmd_del_port(struct vsctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    bool with_iface = shash_find(&ctx->options, "--with-iface") != NULL;
    const char *target = ctx->argv[ctx->argc - 1];
    struct vsctl_port *port;

    vsctl_context_populate_cache(ctx);
    if (find_bridge(ctx, target, false)) {
        if (must_exist) {
            vsctl_fatal("cannot delete port %s because it is the local port "
                        "for bridge %s (deleting this port requires deleting "
                        "the entire bridge)", target, target);
        }
        port = NULL;
    } else if (!with_iface) {
        port = find_port(ctx, target, must_exist);
    } else {
        struct vsctl_iface *iface;

        port = find_port(ctx, target, false);
        if (!port) {
            iface = find_iface(ctx, target, false);
            if (iface) {
                port = iface->port;
            }
        }
        if (must_exist && !port) {
            vsctl_fatal("no port or interface named %s", target);
        }
    }

    if (port) {
        if (ctx->argc == 3) {
            struct vsctl_bridge *bridge;

            bridge = find_bridge(ctx, ctx->argv[1], true);
            if (port->bridge != bridge) {
                if (port->bridge->parent == bridge) {
                    vsctl_fatal("bridge %s does not have a port %s (although "
                                "its parent bridge %s does)",
                                ctx->argv[1], ctx->argv[2],
                                bridge->parent->name);
                } else {
                    vsctl_fatal("bridge %s does not have a port %s",
                                ctx->argv[1], ctx->argv[2]);
                }
            }
        }

        del_port(ctx, port);
    }
}

static void
cmd_port_to_br(struct vsctl_context *ctx)
{
    struct vsctl_port *port;

    vsctl_context_populate_cache(ctx);

    port = find_port(ctx, ctx->argv[1], true);
    ds_put_format(&ctx->output, "%s\n", port->bridge->name);
}

static void
cmd_br_to_vlan(struct vsctl_context *ctx)
{
    struct vsctl_bridge *bridge;

    vsctl_context_populate_cache(ctx);

    bridge = find_bridge(ctx, ctx->argv[1], true);
    ds_put_format(&ctx->output, "%d\n", bridge->vlan);
}

static void
cmd_br_to_parent(struct vsctl_context *ctx)
{
    struct vsctl_bridge *bridge;

    vsctl_context_populate_cache(ctx);

    bridge = find_bridge(ctx, ctx->argv[1], true);
    if (bridge->parent) {
        bridge = bridge->parent;
    }
    ds_put_format(&ctx->output, "%s\n", bridge->name);
}

static void
cmd_list_ifaces(struct vsctl_context *ctx)
{
    struct vsctl_bridge *br;
    struct vsctl_port *port;
    struct svec ifaces;

    vsctl_context_populate_cache(ctx);

    br = find_bridge(ctx, ctx->argv[1], true);
    verify_ports(ctx);

    svec_init(&ifaces);
    LIST_FOR_EACH (port, ports_node, &br->ports) {
        struct vsctl_iface *iface;

        LIST_FOR_EACH (iface, ifaces_node, &port->ifaces) {
            if (strcmp(iface->iface_cfg->name, br->name)) {
                svec_add(&ifaces, iface->iface_cfg->name);
            }
        }
    }
    output_sorted(&ifaces, &ctx->output);
    svec_destroy(&ifaces);
}

static void
cmd_iface_to_br(struct vsctl_context *ctx)
{
    struct vsctl_iface *iface;

    vsctl_context_populate_cache(ctx);

    iface = find_iface(ctx, ctx->argv[1], true);
    ds_put_format(&ctx->output, "%s\n", iface->port->bridge->name);
}

static void
verify_controllers(struct ovsrec_bridge *bridge)
{
    size_t i;

    ovsrec_bridge_verify_controller(bridge);
    for (i = 0; i < bridge->n_controller; i++) {
        ovsrec_controller_verify_target(bridge->controller[i]);
    }
}

static void
pre_controller(struct vsctl_context *ctx)
{
    pre_get_info(ctx);

    ovsdb_idl_add_column(ctx->idl, &ovsrec_controller_col_target);
}

static void
cmd_get_controller(struct vsctl_context *ctx)
{
    struct vsctl_bridge *br;
    struct svec targets;
    size_t i;

    vsctl_context_populate_cache(ctx);

    br = find_bridge(ctx, ctx->argv[1], true);
    if (br->parent) {
        br = br->parent;
    }
    verify_controllers(br->br_cfg);

    /* Print the targets in sorted order for reproducibility. */
    svec_init(&targets);
    for (i = 0; i < br->br_cfg->n_controller; i++) {
        svec_add(&targets, br->br_cfg->controller[i]->target);
    }

    svec_sort(&targets);
    for (i = 0; i < targets.n; i++) {
        ds_put_format(&ctx->output, "%s\n", targets.names[i]);
    }
    svec_destroy(&targets);
}

static void
delete_controllers(struct ovsrec_controller **controllers,
                   size_t n_controllers)
{
    size_t i;

    for (i = 0; i < n_controllers; i++) {
        ovsrec_controller_delete(controllers[i]);
    }
}

static void
cmd_del_controller(struct vsctl_context *ctx)
{
    struct ovsrec_bridge *br;

    vsctl_context_populate_cache(ctx);

    br = find_real_bridge(ctx, ctx->argv[1], true)->br_cfg;
    verify_controllers(br);

    if (br->controller) {
        delete_controllers(br->controller, br->n_controller);
        ovsrec_bridge_set_controller(br, NULL, 0);
    }
}

static struct ovsrec_controller **
insert_controllers(struct ovsdb_idl_txn *txn, char *targets[], size_t n)
{
    struct ovsrec_controller **controllers;
    size_t i;

    controllers = xmalloc(n * sizeof *controllers);
    for (i = 0; i < n; i++) {
        if (vconn_verify_name(targets[i]) && pvconn_verify_name(targets[i])) {
            VLOG_WARN("target type \"%s\" is possibly erroneous", targets[i]);
        }
        controllers[i] = ovsrec_controller_insert(txn);
        ovsrec_controller_set_target(controllers[i], targets[i]);
    }

    return controllers;
}

static void
cmd_set_controller(struct vsctl_context *ctx)
{
    struct ovsrec_controller **controllers;
    struct ovsrec_bridge *br;
    size_t n;

    vsctl_context_populate_cache(ctx);

    br = find_real_bridge(ctx, ctx->argv[1], true)->br_cfg;
    verify_controllers(br);

    delete_controllers(br->controller, br->n_controller);

    n = ctx->argc - 2;
    controllers = insert_controllers(ctx->txn, &ctx->argv[2], n);
    ovsrec_bridge_set_controller(br, controllers, n);
    free(controllers);
}

static void
cmd_get_fail_mode(struct vsctl_context *ctx)
{
    struct vsctl_bridge *br;
    const char *fail_mode;

    vsctl_context_populate_cache(ctx);
    br = find_bridge(ctx, ctx->argv[1], true);

    if (br->parent) {
        br = br->parent;
    }
    ovsrec_bridge_verify_fail_mode(br->br_cfg);

    fail_mode = br->br_cfg->fail_mode;
    if (fail_mode && strlen(fail_mode)) {
        ds_put_format(&ctx->output, "%s\n", fail_mode);
    }
}

static void
cmd_del_fail_mode(struct vsctl_context *ctx)
{
    struct vsctl_bridge *br;

    vsctl_context_populate_cache(ctx);

    br = find_real_bridge(ctx, ctx->argv[1], true);

    ovsrec_bridge_set_fail_mode(br->br_cfg, NULL);
}

static void
cmd_set_fail_mode(struct vsctl_context *ctx)
{
    struct vsctl_bridge *br;
    const char *fail_mode = ctx->argv[2];

    vsctl_context_populate_cache(ctx);

    br = find_real_bridge(ctx, ctx->argv[1], true);

    if (strcmp(fail_mode, "standalone") && strcmp(fail_mode, "secure")) {
        vsctl_fatal("fail-mode must be \"standalone\" or \"secure\"");
    }

    ovsrec_bridge_set_fail_mode(br->br_cfg, fail_mode);
}

static void
verify_managers(const struct ovsrec_open_vswitch *ovs)
{
    size_t i;

    ovsrec_open_vswitch_verify_manager_options(ovs);

    for (i = 0; i < ovs->n_manager_options; ++i) {
        const struct ovsrec_manager *mgr = ovs->manager_options[i];

        ovsrec_manager_verify_target(mgr);
    }
}

static void
pre_manager(struct vsctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &ovsrec_open_vswitch_col_manager_options);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_manager_col_target);
}

static void
cmd_get_manager(struct vsctl_context *ctx)
{
    const struct ovsrec_open_vswitch *ovs = ctx->ovs;
    struct svec targets;
    size_t i;

    verify_managers(ovs);

    /* Print the targets in sorted order for reproducibility. */
    svec_init(&targets);

    for (i = 0; i < ovs->n_manager_options; i++) {
        svec_add(&targets, ovs->manager_options[i]->target);
    }

    svec_sort_unique(&targets);
    for (i = 0; i < targets.n; i++) {
        ds_put_format(&ctx->output, "%s\n", targets.names[i]);
    }
    svec_destroy(&targets);
}

static void
delete_managers(const struct vsctl_context *ctx)
{
    const struct ovsrec_open_vswitch *ovs = ctx->ovs;
    size_t i;

    /* Delete Manager rows pointed to by 'manager_options' column. */
    for (i = 0; i < ovs->n_manager_options; i++) {
        ovsrec_manager_delete(ovs->manager_options[i]);
    }

    /* Delete 'Manager' row refs in 'manager_options' column. */
    ovsrec_open_vswitch_set_manager_options(ovs, NULL, 0);
}

static void
cmd_del_manager(struct vsctl_context *ctx)
{
    const struct ovsrec_open_vswitch *ovs = ctx->ovs;

    verify_managers(ovs);
    delete_managers(ctx);
}

static void
insert_managers(struct vsctl_context *ctx, char *targets[], size_t n)
{
    struct ovsrec_manager **managers;
    size_t i;

    /* Insert each manager in a new row in Manager table. */
    managers = xmalloc(n * sizeof *managers);
    for (i = 0; i < n; i++) {
        if (stream_verify_name(targets[i]) && pstream_verify_name(targets[i])) {
            VLOG_WARN("target type \"%s\" is possibly erroneous", targets[i]);
        }
        managers[i] = ovsrec_manager_insert(ctx->txn);
        ovsrec_manager_set_target(managers[i], targets[i]);
    }

    /* Store uuids of new Manager rows in 'manager_options' column. */
    ovsrec_open_vswitch_set_manager_options(ctx->ovs, managers, n);
    free(managers);
}

static void
cmd_set_manager(struct vsctl_context *ctx)
{
    const size_t n = ctx->argc - 1;

    verify_managers(ctx->ovs);
    delete_managers(ctx);
    insert_managers(ctx, &ctx->argv[1], n);
}

static void
pre_cmd_get_ssl(struct vsctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &ovsrec_open_vswitch_col_ssl);

    ovsdb_idl_add_column(ctx->idl, &ovsrec_ssl_col_private_key);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_ssl_col_certificate);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_ssl_col_ca_cert);
    ovsdb_idl_add_column(ctx->idl, &ovsrec_ssl_col_bootstrap_ca_cert);
}

static void
cmd_get_ssl(struct vsctl_context *ctx)
{
    struct ovsrec_ssl *ssl = ctx->ovs->ssl;

    ovsrec_open_vswitch_verify_ssl(ctx->ovs);
    if (ssl) {
        ovsrec_ssl_verify_private_key(ssl);
        ovsrec_ssl_verify_certificate(ssl);
        ovsrec_ssl_verify_ca_cert(ssl);
        ovsrec_ssl_verify_bootstrap_ca_cert(ssl);

        ds_put_format(&ctx->output, "Private key: %s\n", ssl->private_key);
        ds_put_format(&ctx->output, "Certificate: %s\n", ssl->certificate);
        ds_put_format(&ctx->output, "CA Certificate: %s\n", ssl->ca_cert);
        ds_put_format(&ctx->output, "Bootstrap: %s\n",
                ssl->bootstrap_ca_cert ? "true" : "false");
    }
}

static void
pre_cmd_del_ssl(struct vsctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &ovsrec_open_vswitch_col_ssl);
}

static void
cmd_del_ssl(struct vsctl_context *ctx)
{
    struct ovsrec_ssl *ssl = ctx->ovs->ssl;

    if (ssl) {
        ovsrec_open_vswitch_verify_ssl(ctx->ovs);
        ovsrec_ssl_delete(ssl);
        ovsrec_open_vswitch_set_ssl(ctx->ovs, NULL);
    }
}

static void
pre_cmd_set_ssl(struct vsctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &ovsrec_open_vswitch_col_ssl);
}

static void
cmd_set_ssl(struct vsctl_context *ctx)
{
    bool bootstrap = shash_find(&ctx->options, "--bootstrap");
    struct ovsrec_ssl *ssl = ctx->ovs->ssl;

    ovsrec_open_vswitch_verify_ssl(ctx->ovs);
    if (ssl) {
        ovsrec_ssl_delete(ssl);
    }
    ssl = ovsrec_ssl_insert(ctx->txn);

    ovsrec_ssl_set_private_key(ssl, ctx->argv[1]);
    ovsrec_ssl_set_certificate(ssl, ctx->argv[2]);
    ovsrec_ssl_set_ca_cert(ssl, ctx->argv[3]);

    ovsrec_ssl_set_bootstrap_ca_cert(ssl, bootstrap);

    ovsrec_open_vswitch_set_ssl(ctx->ovs, ssl);
}

/* Parameter commands. */

struct vsctl_row_id {
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *name_column;
    const struct ovsdb_idl_column *uuid_column;
};

struct vsctl_table_class {
    struct ovsdb_idl_table_class *class;
    struct vsctl_row_id row_ids[2];
};

static const struct vsctl_table_class tables[] = {
    {&ovsrec_table_bridge,
     {{&ovsrec_table_bridge, &ovsrec_bridge_col_name, NULL},
      {&ovsrec_table_flow_sample_collector_set, NULL,
       &ovsrec_flow_sample_collector_set_col_bridge}}},

    {&ovsrec_table_controller,
     {{&ovsrec_table_bridge,
       &ovsrec_bridge_col_name,
       &ovsrec_bridge_col_controller}}},

    {&ovsrec_table_interface,
     {{&ovsrec_table_interface, &ovsrec_interface_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_mirror,
     {{&ovsrec_table_mirror, &ovsrec_mirror_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_manager,
     {{&ovsrec_table_manager, &ovsrec_manager_col_target, NULL},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_netflow,
     {{&ovsrec_table_bridge,
       &ovsrec_bridge_col_name,
       &ovsrec_bridge_col_netflow},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_open_vswitch,
     {{&ovsrec_table_open_vswitch, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_port,
     {{&ovsrec_table_port, &ovsrec_port_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_qos,
     {{&ovsrec_table_port, &ovsrec_port_col_name, &ovsrec_port_col_qos},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_queue,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_ssl,
     {{&ovsrec_table_open_vswitch, NULL, &ovsrec_open_vswitch_col_ssl}}},

    {&ovsrec_table_sflow,
     {{&ovsrec_table_bridge,
       &ovsrec_bridge_col_name,
       &ovsrec_bridge_col_sflow},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_flow_table,
     {{&ovsrec_table_flow_table, &ovsrec_flow_table_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&ovsrec_table_ipfix,
     {{&ovsrec_table_bridge,
       &ovsrec_bridge_col_name,
       &ovsrec_bridge_col_ipfix},
      {&ovsrec_table_flow_sample_collector_set, NULL,
       &ovsrec_flow_sample_collector_set_col_ipfix}}},

    {&ovsrec_table_flow_sample_collector_set,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {NULL, {{NULL, NULL, NULL}, {NULL, NULL, NULL}}}
};

static void
die_if_error(char *error)
{
    if (error) {
        vsctl_fatal("%s", error);
    }
}

static int
to_lower_and_underscores(unsigned c)
{
    return c == '-' ? '_' : tolower(c);
}

static unsigned int
score_partial_match(const char *name, const char *s)
{
    int score;

    if (!strcmp(name, s)) {
        return UINT_MAX;
    }
    for (score = 0; ; score++, name++, s++) {
        if (to_lower_and_underscores(*name) != to_lower_and_underscores(*s)) {
            break;
        } else if (*name == '\0') {
            return UINT_MAX - 1;
        }
    }
    return *s == '\0' ? score : 0;
}

static const struct vsctl_table_class *
get_table(const char *table_name)
{
    const struct vsctl_table_class *table;
    const struct vsctl_table_class *best_match = NULL;
    unsigned int best_score = 0;

    for (table = tables; table->class; table++) {
        unsigned int score = score_partial_match(table->class->name,
                                                 table_name);
        if (score > best_score) {
            best_match = table;
            best_score = score;
        } else if (score == best_score) {
            best_match = NULL;
        }
    }
    if (best_match) {
        return best_match;
    } else if (best_score) {
        vsctl_fatal("multiple table names match \"%s\"", table_name);
    } else {
        vsctl_fatal("unknown table \"%s\"", table_name);
    }
}

static const struct vsctl_table_class *
pre_get_table(struct vsctl_context *ctx, const char *table_name)
{
    const struct vsctl_table_class *table_class;
    int i;

    table_class = get_table(table_name);
    ovsdb_idl_add_table(ctx->idl, table_class->class);

    for (i = 0; i < ARRAY_SIZE(table_class->row_ids); i++) {
        const struct vsctl_row_id *id = &table_class->row_ids[i];
        if (id->table) {
            ovsdb_idl_add_table(ctx->idl, id->table);
        }
        if (id->name_column) {
            ovsdb_idl_add_column(ctx->idl, id->name_column);
        }
        if (id->uuid_column) {
            ovsdb_idl_add_column(ctx->idl, id->uuid_column);
        }
    }

    return table_class;
}

static const struct ovsdb_idl_row *
get_row_by_id(struct vsctl_context *ctx, const struct vsctl_table_class *table,
              const struct vsctl_row_id *id, const char *record_id)
{
    const struct ovsdb_idl_row *referrer, *final;

    if (!id->table) {
        return NULL;
    }

    if (!id->name_column) {
        if (strcmp(record_id, ".")) {
            return NULL;
        }
        referrer = ovsdb_idl_first_row(ctx->idl, id->table);
        if (!referrer || ovsdb_idl_next_row(referrer)) {
            return NULL;
        }
    } else {
        const struct ovsdb_idl_row *row;

        referrer = NULL;
        for (row = ovsdb_idl_first_row(ctx->idl, id->table);
             row != NULL;
             row = ovsdb_idl_next_row(row))
        {
            const struct ovsdb_datum *name;

            name = ovsdb_idl_get(row, id->name_column,
                                 OVSDB_TYPE_STRING, OVSDB_TYPE_VOID);
            if (name->n == 1 && !strcmp(name->keys[0].string, record_id)) {
                if (referrer) {
                    vsctl_fatal("multiple rows in %s match \"%s\"",
                                table->class->name, record_id);
                }
                referrer = row;
            }
        }
    }
    if (!referrer) {
        return NULL;
    }

    final = NULL;
    if (id->uuid_column) {
        const struct ovsdb_datum *uuid;

        ovsdb_idl_txn_verify(referrer, id->uuid_column);
        uuid = ovsdb_idl_get(referrer, id->uuid_column,
                             OVSDB_TYPE_UUID, OVSDB_TYPE_VOID);
        if (uuid->n == 1) {
            final = ovsdb_idl_get_row_for_uuid(ctx->idl, table->class,
                                               &uuid->keys[0].uuid);
        }
    } else {
        final = referrer;
    }

    return final;
}

static const struct ovsdb_idl_row *
get_row (struct vsctl_context *ctx,
         const struct vsctl_table_class *table, const char *record_id,
         bool must_exist)
{
    const struct ovsdb_idl_row *row;
    struct uuid uuid;

    if (uuid_from_string(&uuid, record_id)) {
        row = ovsdb_idl_get_row_for_uuid(ctx->idl, table->class, &uuid);
    } else {
        int i;

        for (i = 0; i < ARRAY_SIZE(table->row_ids); i++) {
            row = get_row_by_id(ctx, table, &table->row_ids[i], record_id);
            if (row) {
                break;
            }
        }
    }
    if (must_exist && !row) {
        vsctl_fatal("no row \"%s\" in table %s",
                    record_id, table->class->name);
    }
    return row;
}

static char *
get_column(const struct vsctl_table_class *table, const char *column_name,
           const struct ovsdb_idl_column **columnp)
{
    const struct ovsdb_idl_column *best_match = NULL;
    unsigned int best_score = 0;
    size_t i;

    for (i = 0; i < table->class->n_columns; i++) {
        const struct ovsdb_idl_column *column = &table->class->columns[i];
        unsigned int score = score_partial_match(column->name, column_name);
        if (score > best_score) {
            best_match = column;
            best_score = score;
        } else if (score == best_score) {
            best_match = NULL;
        }
    }

    *columnp = best_match;
    if (best_match) {
        return NULL;
    } else if (best_score) {
        return xasprintf("%s contains more than one column whose name "
                         "matches \"%s\"", table->class->name, column_name);
    } else {
        return xasprintf("%s does not contain a column whose name matches "
                         "\"%s\"", table->class->name, column_name);
    }
}

static struct ovsdb_symbol *
create_symbol(struct ovsdb_symbol_table *symtab, const char *id, bool *newp)
{
    struct ovsdb_symbol *symbol;

    if (id[0] != '@') {
        vsctl_fatal("row id \"%s\" does not begin with \"@\"", id);
    }

    if (newp) {
        *newp = ovsdb_symbol_table_get(symtab, id) == NULL;
    }

    symbol = ovsdb_symbol_table_insert(symtab, id);
    if (symbol->created) {
        vsctl_fatal("row id \"%s\" may only be specified on one --id option",
                    id);
    }
    symbol->created = true;
    return symbol;
}

static void
pre_get_column(struct vsctl_context *ctx,
               const struct vsctl_table_class *table, const char *column_name,
               const struct ovsdb_idl_column **columnp)
{
    die_if_error(get_column(table, column_name, columnp));
    ovsdb_idl_add_column(ctx->idl, *columnp);
}

static char *
missing_operator_error(const char *arg, const char **allowed_operators,
                       size_t n_allowed)
{
    struct ds s;

    ds_init(&s);
    ds_put_format(&s, "%s: argument does not end in ", arg);
    ds_put_format(&s, "\"%s\"", allowed_operators[0]);
    if (n_allowed == 2) {
        ds_put_format(&s, " or \"%s\"", allowed_operators[1]);
    } else if (n_allowed > 2) {
        size_t i;

        for (i = 1; i < n_allowed - 1; i++) {
            ds_put_format(&s, ", \"%s\"", allowed_operators[i]);
        }
        ds_put_format(&s, ", or \"%s\"", allowed_operators[i]);
    }
    ds_put_format(&s, " followed by a value.");

    return ds_steal_cstr(&s);
}

/* Breaks 'arg' apart into a number of fields in the following order:
 *
 *      - The name of a column in 'table', stored into '*columnp'.  The column
 *        name may be abbreviated.
 *
 *      - Optionally ':' followed by a key string.  The key is stored as a
 *        malloc()'d string into '*keyp', or NULL if no key is present in
 *        'arg'.
 *
 *      - If 'valuep' is nonnull, an operator followed by a value string.  The
 *        allowed operators are the 'n_allowed' string in 'allowed_operators',
 *        or just "=" if 'n_allowed' is 0.  If 'operatorp' is nonnull, then the
 *        index of the operator within 'allowed_operators' is stored into
 *        '*operatorp'.  The value is stored as a malloc()'d string into
 *        '*valuep', or NULL if no value is present in 'arg'.
 *
 * On success, returns NULL.  On failure, returned a malloc()'d string error
 * message and stores NULL into all of the nonnull output arguments. */
static char * WARN_UNUSED_RESULT
parse_column_key_value(const char *arg,
                       const struct vsctl_table_class *table,
                       const struct ovsdb_idl_column **columnp, char **keyp,
                       int *operatorp,
                       const char **allowed_operators, size_t n_allowed,
                       char **valuep)
{
    const char *p = arg;
    char *column_name;
    char *error;

    ovs_assert(!(operatorp && !valuep));
    *keyp = NULL;
    if (valuep) {
        *valuep = NULL;
    }

    /* Parse column name. */
    error = ovsdb_token_parse(&p, &column_name);
    if (error) {
        goto error;
    }
    if (column_name[0] == '\0') {
        free(column_name);
        error = xasprintf("%s: missing column name", arg);
        goto error;
    }
    error = get_column(table, column_name, columnp);
    free(column_name);
    if (error) {
        goto error;
    }

    /* Parse key string. */
    if (*p == ':') {
        p++;
        error = ovsdb_token_parse(&p, keyp);
        if (error) {
            goto error;
        }
    }

    /* Parse value string. */
    if (valuep) {
        size_t best_len;
        size_t i;
        int best;

        if (!allowed_operators) {
            static const char *equals = "=";
            allowed_operators = &equals;
            n_allowed = 1;
        }

        best = -1;
        best_len = 0;
        for (i = 0; i < n_allowed; i++) {
            const char *op = allowed_operators[i];
            size_t op_len = strlen(op);

            if (op_len > best_len && !strncmp(op, p, op_len) && p[op_len]) {
                best_len = op_len;
                best = i;
            }
        }
        if (best < 0) {
            error = missing_operator_error(arg, allowed_operators, n_allowed);
            goto error;
        }

        if (operatorp) {
            *operatorp = best;
        }
        *valuep = xstrdup(p + best_len);
    } else {
        if (*p != '\0') {
            error = xasprintf("%s: trailing garbage \"%s\" in argument",
                              arg, p);
            goto error;
        }
    }
    return NULL;

error:
    *columnp = NULL;
    free(*keyp);
    *keyp = NULL;
    if (valuep) {
        free(*valuep);
        *valuep = NULL;
        if (operatorp) {
            *operatorp = -1;
        }
    }
    return error;
}

static const struct ovsdb_idl_column *
pre_parse_column_key_value(struct vsctl_context *ctx,
                           const char *arg,
                           const struct vsctl_table_class *table)
{
    const struct ovsdb_idl_column *column;
    const char *p;
    char *column_name;

    p = arg;
    die_if_error(ovsdb_token_parse(&p, &column_name));
    if (column_name[0] == '\0') {
        vsctl_fatal("%s: missing column name", arg);
    }

    pre_get_column(ctx, table, column_name, &column);
    free(column_name);

    return column;
}

static void
check_mutable(const struct vsctl_table_class *table,
              const struct ovsdb_idl_column *column)
{
    if (!column->mutable) {
        vsctl_fatal("cannot modify read-only column %s in table %s",
                    column->name, table->class->name);
    }
}

static void
pre_cmd_get(struct vsctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;
    int i;

    /* Using "get" without --id or a column name could possibly make sense.
     * Maybe, for example, a ovs-vsctl run wants to assert that a row exists.
     * But it is unlikely that an interactive user would want to do that, so
     * issue a warning if we're running on a terminal. */
    if (!id && ctx->argc <= 3 && isatty(STDOUT_FILENO)) {
        VLOG_WARN("\"get\" command without row arguments or \"--id\" is "
                  "possibly erroneous");
    }

    table = pre_get_table(ctx, table_name);
    for (i = 3; i < ctx->argc; i++) {
        if (!strcasecmp(ctx->argv[i], "_uuid")
            || !strcasecmp(ctx->argv[i], "-uuid")) {
            continue;
        }

        pre_parse_column_key_value(ctx, ctx->argv[i], table);
    }
}

static void
cmd_get(struct vsctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct vsctl_table_class *table;
    const struct ovsdb_idl_row *row;
    struct ds *out = &ctx->output;
    int i;

    if (id && !must_exist) {
        vsctl_fatal("--if-exists and --id may not be specified together");
    }

    table = get_table(table_name);
    row = get_row(ctx, table, record_id, must_exist);
    if (!row) {
        return;
    }

    if (id) {
        struct ovsdb_symbol *symbol;
        bool new;

        symbol = create_symbol(ctx->symtab, id, &new);
        if (!new) {
            vsctl_fatal("row id \"%s\" specified on \"get\" command was used "
                        "before it was defined", id);
        }
        symbol->uuid = row->uuid;

        /* This symbol refers to a row that already exists, so disable warnings
         * about it being unreferenced. */
        symbol->strong_ref = true;
    }
    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;
        const struct ovsdb_datum *datum;
        char *key_string;

        /* Special case for obtaining the UUID of a row.  We can't just do this
         * through parse_column_key_value() below since it returns a "struct
         * ovsdb_idl_column" and the UUID column doesn't have one. */
        if (!strcasecmp(ctx->argv[i], "_uuid")
            || !strcasecmp(ctx->argv[i], "-uuid")) {
            ds_put_format(out, UUID_FMT"\n", UUID_ARGS(&row->uuid));
            continue;
        }

        die_if_error(parse_column_key_value(ctx->argv[i], table,
                                            &column, &key_string,
                                            NULL, NULL, 0, NULL));

        ovsdb_idl_txn_verify(row, column);
        datum = ovsdb_idl_read(row, column);
        if (key_string) {
            union ovsdb_atom key;
            unsigned int idx;

            if (column->type.value.type == OVSDB_TYPE_VOID) {
                vsctl_fatal("cannot specify key to get for non-map column %s",
                            column->name);
            }

            die_if_error(ovsdb_atom_from_string(&key,
                                                &column->type.key,
                                                key_string, ctx->symtab));

            idx = ovsdb_datum_find_key(datum, &key,
                                       column->type.key.type);
            if (idx == UINT_MAX) {
                if (must_exist) {
                    vsctl_fatal("no key \"%s\" in %s record \"%s\" column %s",
                                key_string, table->class->name, record_id,
                                column->name);
                }
            } else {
                ovsdb_atom_to_string(&datum->values[idx],
                                     column->type.value.type, out);
            }
            ovsdb_atom_destroy(&key, column->type.key.type);
        } else {
            ovsdb_datum_to_string(datum, &column->type, out);
        }
        ds_put_char(out, '\n');

        free(key_string);
    }
}

static void
parse_column_names(const char *column_names,
                   const struct vsctl_table_class *table,
                   const struct ovsdb_idl_column ***columnsp,
                   size_t *n_columnsp)
{
    const struct ovsdb_idl_column **columns;
    size_t n_columns;

    if (!column_names) {
        size_t i;

        n_columns = table->class->n_columns + 1;
        columns = xmalloc(n_columns * sizeof *columns);
        columns[0] = NULL;
        for (i = 0; i < table->class->n_columns; i++) {
            columns[i + 1] = &table->class->columns[i];
        }
    } else {
        char *s = xstrdup(column_names);
        size_t allocated_columns;
        char *save_ptr = NULL;
        char *column_name;

        columns = NULL;
        allocated_columns = n_columns = 0;
        for (column_name = strtok_r(s, ", ", &save_ptr); column_name;
             column_name = strtok_r(NULL, ", ", &save_ptr)) {
            const struct ovsdb_idl_column *column;

            if (!strcasecmp(column_name, "_uuid")) {
                column = NULL;
            } else {
                die_if_error(get_column(table, column_name, &column));
            }
            if (n_columns >= allocated_columns) {
                columns = x2nrealloc(columns, &allocated_columns,
                                     sizeof *columns);
            }
            columns[n_columns++] = column;
        }
        free(s);

        if (!n_columns) {
            vsctl_fatal("must specify at least one column name");
        }
    }
    *columnsp = columns;
    *n_columnsp = n_columns;
}


static void
pre_list_columns(struct vsctl_context *ctx,
                 const struct vsctl_table_class *table,
                 const char *column_names)
{
    const struct ovsdb_idl_column **columns;
    size_t n_columns;
    size_t i;

    parse_column_names(column_names, table, &columns, &n_columns);
    for (i = 0; i < n_columns; i++) {
        if (columns[i]) {
            ovsdb_idl_add_column(ctx->idl, columns[i]);
        }
    }
    free(columns);
}

static void
pre_cmd_list(struct vsctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;

    table = pre_get_table(ctx, table_name);
    pre_list_columns(ctx, table, column_names);
}

static struct table *
list_make_table(const struct ovsdb_idl_column **columns, size_t n_columns)
{
    struct table *out;
    size_t i;

    out = xmalloc(sizeof *out);
    table_init(out);

    for (i = 0; i < n_columns; i++) {
        const struct ovsdb_idl_column *column = columns[i];
        const char *column_name = column ? column->name : "_uuid";

        table_add_column(out, "%s", column_name);
    }

    return out;
}

static void
list_record(const struct ovsdb_idl_row *row,
            const struct ovsdb_idl_column **columns, size_t n_columns,
            struct table *out)
{
    size_t i;

    if (!row) {
        return;
    }

    table_add_row(out);
    for (i = 0; i < n_columns; i++) {
        const struct ovsdb_idl_column *column = columns[i];
        struct cell *cell = table_add_cell(out);

        if (!column) {
            struct ovsdb_datum datum;
            union ovsdb_atom atom;

            atom.uuid = row->uuid;

            datum.keys = &atom;
            datum.values = NULL;
            datum.n = 1;

            cell->json = ovsdb_datum_to_json(&datum, &ovsdb_type_uuid);
            cell->type = &ovsdb_type_uuid;
        } else {
            const struct ovsdb_datum *datum = ovsdb_idl_read(row, column);

            cell->json = ovsdb_datum_to_json(datum, &column->type);
            cell->type = &column->type;
        }
    }
}

static void
cmd_list(struct vsctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct ovsdb_idl_column **columns;
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;
    struct table *out;
    size_t n_columns;
    int i;

    table = get_table(table_name);
    parse_column_names(column_names, table, &columns, &n_columns);
    out = ctx->table = list_make_table(columns, n_columns);
    if (ctx->argc > 2) {
        for (i = 2; i < ctx->argc; i++) {
            list_record(get_row(ctx, table, ctx->argv[i], must_exist),
                        columns, n_columns, out);
        }
    } else {
        const struct ovsdb_idl_row *row;

        for (row = ovsdb_idl_first_row(ctx->idl, table->class); row != NULL;
             row = ovsdb_idl_next_row(row)) {
            list_record(row, columns, n_columns, out);
        }
    }
    free(columns);
}

static void
pre_cmd_find(struct vsctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;
    int i;

    table = pre_get_table(ctx, table_name);
    pre_list_columns(ctx, table, column_names);
    for (i = 2; i < ctx->argc; i++) {
        pre_parse_column_key_value(ctx, ctx->argv[i], table);
    }
}

static void
cmd_find(struct vsctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const struct ovsdb_idl_column **columns;
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;
    const struct ovsdb_idl_row *row;
    struct table *out;
    size_t n_columns;

    table = get_table(table_name);
    parse_column_names(column_names, table, &columns, &n_columns);
    out = ctx->table = list_make_table(columns, n_columns);
    for (row = ovsdb_idl_first_row(ctx->idl, table->class); row;
         row = ovsdb_idl_next_row(row)) {
        int i;

        for (i = 2; i < ctx->argc; i++) {
            if (!is_condition_satisfied(table, row, ctx->argv[i],
                                        ctx->symtab)) {
                goto next_row;
            }
        }
        list_record(row, columns, n_columns, out);

    next_row: ;
    }
    free(columns);
}

static void
pre_cmd_set(struct vsctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;
    int i;

    table = pre_get_table(ctx, table_name);
    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;

        column = pre_parse_column_key_value(ctx, ctx->argv[i], table);
        check_mutable(table, column);
    }
}

static void
set_column(const struct vsctl_table_class *table,
           const struct ovsdb_idl_row *row, const char *arg,
           struct ovsdb_symbol_table *symtab)
{
    const struct ovsdb_idl_column *column;
    char *key_string, *value_string;
    char *error;

    error = parse_column_key_value(arg, table, &column, &key_string,
                                   NULL, NULL, 0, &value_string);
    die_if_error(error);
    if (!value_string) {
        vsctl_fatal("%s: missing value", arg);
    }

    if (key_string) {
        union ovsdb_atom key, value;
        struct ovsdb_datum datum;

        if (column->type.value.type == OVSDB_TYPE_VOID) {
            vsctl_fatal("cannot specify key to set for non-map column %s",
                        column->name);
        }

        die_if_error(ovsdb_atom_from_string(&key, &column->type.key,
                                            key_string, symtab));
        die_if_error(ovsdb_atom_from_string(&value, &column->type.value,
                                            value_string, symtab));

        ovsdb_datum_init_empty(&datum);
        ovsdb_datum_add_unsafe(&datum, &key, &value, &column->type);

        ovsdb_atom_destroy(&key, column->type.key.type);
        ovsdb_atom_destroy(&value, column->type.value.type);

        ovsdb_datum_union(&datum, ovsdb_idl_read(row, column),
                          &column->type, false);
        ovsdb_idl_txn_verify(row, column);
        ovsdb_idl_txn_write(row, column, &datum);
    } else {
        struct ovsdb_datum datum;

        die_if_error(ovsdb_datum_from_string(&datum, &column->type,
                                             value_string, symtab));
        ovsdb_idl_txn_write(row, column, &datum);
    }

    free(key_string);
    free(value_string);
}

static void
cmd_set(struct vsctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct vsctl_table_class *table;
    const struct ovsdb_idl_row *row;
    int i;

    table = get_table(table_name);
    row = get_row(ctx, table, record_id, must_exist);
    if (!row) {
        return;
    }

    for (i = 3; i < ctx->argc; i++) {
        set_column(table, row, ctx->argv[i], ctx->symtab);
    }

    vsctl_context_invalidate_cache(ctx);
}

static void
pre_cmd_add(struct vsctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *column_name = ctx->argv[3];
    const struct vsctl_table_class *table;
    const struct ovsdb_idl_column *column;

    table = pre_get_table(ctx, table_name);
    pre_get_column(ctx, table, column_name, &column);
    check_mutable(table, column);
}

static void
cmd_add(struct vsctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const char *column_name = ctx->argv[3];
    const struct vsctl_table_class *table;
    const struct ovsdb_idl_column *column;
    const struct ovsdb_idl_row *row;
    const struct ovsdb_type *type;
    struct ovsdb_datum old;
    int i;

    table = get_table(table_name);
    die_if_error(get_column(table, column_name, &column));
    row = get_row(ctx, table, record_id, must_exist);
    if (!row) {
        return;
    }

    type = &column->type;
    ovsdb_datum_clone(&old, ovsdb_idl_read(row, column), &column->type);
    for (i = 4; i < ctx->argc; i++) {
        struct ovsdb_type add_type;
        struct ovsdb_datum add;

        add_type = *type;
        add_type.n_min = 1;
        add_type.n_max = UINT_MAX;
        die_if_error(ovsdb_datum_from_string(&add, &add_type, ctx->argv[i],
                                             ctx->symtab));
        ovsdb_datum_union(&old, &add, type, false);
        ovsdb_datum_destroy(&add, type);
    }
    if (old.n > type->n_max) {
        vsctl_fatal("\"add\" operation would put %u %s in column %s of "
                    "table %s but the maximum number is %u",
                    old.n,
                    type->value.type == OVSDB_TYPE_VOID ? "values" : "pairs",
                    column->name, table->class->name, type->n_max);
    }
    ovsdb_idl_txn_verify(row, column);
    ovsdb_idl_txn_write(row, column, &old);

    vsctl_context_invalidate_cache(ctx);
}

static void
pre_cmd_remove(struct vsctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *column_name = ctx->argv[3];
    const struct vsctl_table_class *table;
    const struct ovsdb_idl_column *column;

    table = pre_get_table(ctx, table_name);
    pre_get_column(ctx, table, column_name, &column);
    check_mutable(table, column);
}

static void
cmd_remove(struct vsctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const char *column_name = ctx->argv[3];
    const struct vsctl_table_class *table;
    const struct ovsdb_idl_column *column;
    const struct ovsdb_idl_row *row;
    const struct ovsdb_type *type;
    struct ovsdb_datum old;
    int i;

    table = get_table(table_name);
    die_if_error(get_column(table, column_name, &column));
    row = get_row(ctx, table, record_id, must_exist);
    if (!row) {
        return;
    }

    type = &column->type;
    ovsdb_datum_clone(&old, ovsdb_idl_read(row, column), &column->type);
    for (i = 4; i < ctx->argc; i++) {
        struct ovsdb_type rm_type;
        struct ovsdb_datum rm;
        char *error;

        rm_type = *type;
        rm_type.n_min = 1;
        rm_type.n_max = UINT_MAX;
        error = ovsdb_datum_from_string(&rm, &rm_type,
                                        ctx->argv[i], ctx->symtab);
        if (error) {
            if (ovsdb_type_is_map(&rm_type)) {
                rm_type.value.type = OVSDB_TYPE_VOID;
                free(error);
                die_if_error(ovsdb_datum_from_string(
                                 &rm, &rm_type, ctx->argv[i], ctx->symtab));
            } else {
                vsctl_fatal("%s", error);
            }
        }
        ovsdb_datum_subtract(&old, type, &rm, &rm_type);
        ovsdb_datum_destroy(&rm, &rm_type);
    }
    if (old.n < type->n_min) {
        vsctl_fatal("\"remove\" operation would put %u %s in column %s of "
                    "table %s but the minimum number is %u",
                    old.n,
                    type->value.type == OVSDB_TYPE_VOID ? "values" : "pairs",
                    column->name, table->class->name, type->n_min);
    }
    ovsdb_idl_txn_verify(row, column);
    ovsdb_idl_txn_write(row, column, &old);

    vsctl_context_invalidate_cache(ctx);
}

static void
pre_cmd_clear(struct vsctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;
    int i;

    table = pre_get_table(ctx, table_name);
    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;

        pre_get_column(ctx, table, ctx->argv[i], &column);
        check_mutable(table, column);
    }
}

static void
cmd_clear(struct vsctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct vsctl_table_class *table;
    const struct ovsdb_idl_row *row;
    int i;

    table = get_table(table_name);
    row = get_row(ctx, table, record_id, must_exist);
    if (!row) {
        return;
    }

    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;
        const struct ovsdb_type *type;
        struct ovsdb_datum datum;

        die_if_error(get_column(table, ctx->argv[i], &column));

        type = &column->type;
        if (type->n_min > 0) {
            vsctl_fatal("\"clear\" operation cannot be applied to column %s "
                        "of table %s, which is not allowed to be empty",
                        column->name, table->class->name);
        }

        ovsdb_datum_init_empty(&datum);
        ovsdb_idl_txn_write(row, column, &datum);
    }

    vsctl_context_invalidate_cache(ctx);
}

static void
pre_create(struct vsctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;

    table = get_table(table_name);
    if (!id && !table->class->is_root) {
        VLOG_WARN("applying \"create\" command to table %s without --id "
                  "option will have no effect", table->class->name);
    }
}

static void
cmd_create(struct vsctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table = get_table(table_name);
    const struct ovsdb_idl_row *row;
    const struct uuid *uuid;
    int i;

    if (id) {
        struct ovsdb_symbol *symbol = create_symbol(ctx->symtab, id, NULL);
        if (table->class->is_root) {
            /* This table is in the root set, meaning that rows created in it
             * won't disappear even if they are unreferenced, so disable
             * warnings about that by pretending that there is a reference. */
            symbol->strong_ref = true;
        }
        uuid = &symbol->uuid;
    } else {
        uuid = NULL;
    }

    row = ovsdb_idl_txn_insert(ctx->txn, table->class, uuid);
    for (i = 2; i < ctx->argc; i++) {
        set_column(table, row, ctx->argv[i], ctx->symtab);
    }
    ds_put_format(&ctx->output, UUID_FMT, UUID_ARGS(&row->uuid));
}

/* This function may be used as the 'postprocess' function for commands that
 * insert new rows into the database.  It expects that the command's 'run'
 * function prints the UUID reported by ovsdb_idl_txn_insert() as the command's
 * sole output.  It replaces that output by the row's permanent UUID assigned
 * by the database server and appends a new-line.
 *
 * Currently we use this only for "create", because the higher-level commands
 * are supposed to be independent of the actual structure of the vswitch
 * configuration. */
static void
post_create(struct vsctl_context *ctx)
{
    const struct uuid *real;
    struct uuid dummy;

    if (!uuid_from_string(&dummy, ds_cstr(&ctx->output))) {
        OVS_NOT_REACHED();
    }
    real = ovsdb_idl_txn_get_insert_uuid(ctx->txn, &dummy);
    if (real) {
        ds_clear(&ctx->output);
        ds_put_format(&ctx->output, UUID_FMT, UUID_ARGS(real));
    }
    ds_put_char(&ctx->output, '\n');
}

static void
post_db_reload_check_init(void)
{
    n_neoteric_ifaces = 0;
}

static void
post_db_reload_expect_iface(const struct ovsrec_interface *iface)
{
    if (n_neoteric_ifaces >= allocated_neoteric_ifaces) {
        neoteric_ifaces = x2nrealloc(neoteric_ifaces,
                                     &allocated_neoteric_ifaces,
                                     sizeof *neoteric_ifaces);
    }
    neoteric_ifaces[n_neoteric_ifaces++] = iface->header_.uuid;
}

static void
post_db_reload_do_checks(const struct vsctl_context *ctx)
{
    struct ds dead_ifaces = DS_EMPTY_INITIALIZER;
    size_t i;

    for (i = 0; i < n_neoteric_ifaces; i++) {
        const struct uuid *uuid;

        uuid = ovsdb_idl_txn_get_insert_uuid(ctx->txn, &neoteric_ifaces[i]);
        if (uuid) {
            const struct ovsrec_interface *iface;

            iface = ovsrec_interface_get_for_uuid(ctx->idl, uuid);
            if (iface && (!iface->ofport || *iface->ofport == -1)) {
                ds_put_format(&dead_ifaces, "'%s', ", iface->name);
            }
        }
    }

    if (dead_ifaces.length) {
        dead_ifaces.length -= 2; /* Strip off trailing comma and space. */
        ovs_error(0, "Error detected while setting up %s.  See ovs-vswitchd "
                  "log for details.", ds_cstr(&dead_ifaces));
    }

    ds_destroy(&dead_ifaces);
}

static void
pre_cmd_destroy(struct vsctl_context *ctx)
{
    const char *table_name = ctx->argv[1];

    pre_get_table(ctx, table_name);
}

static void
cmd_destroy(struct vsctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    bool delete_all = shash_find(&ctx->options, "--all");
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;
    int i;

    table = get_table(table_name);

    if (delete_all && ctx->argc > 2) {
        vsctl_fatal("--all and records argument should not be specified together");
    }

    if (delete_all && !must_exist) {
        vsctl_fatal("--all and --if-exists should not be specified together");
    }

    if (delete_all) {
        const struct ovsdb_idl_row *row;
        const struct ovsdb_idl_row *next_row;

        for (row = ovsdb_idl_first_row(ctx->idl, table->class);
             row;) {
             next_row = ovsdb_idl_next_row(row);
             ovsdb_idl_txn_delete(row);
             row = next_row;
        }
    } else {
        for (i = 2; i < ctx->argc; i++) {
            const struct ovsdb_idl_row *row;

            row = get_row(ctx, table, ctx->argv[i], must_exist);
            if (row) {
                ovsdb_idl_txn_delete(row);
            }
        }
    }
    vsctl_context_invalidate_cache(ctx);
}

#define RELOPS                                  \
    RELOP(RELOP_EQ,     "=")                    \
    RELOP(RELOP_NE,     "!=")                   \
    RELOP(RELOP_LT,     "<")                    \
    RELOP(RELOP_GT,     ">")                    \
    RELOP(RELOP_LE,     "<=")                   \
    RELOP(RELOP_GE,     ">=")                   \
    RELOP(RELOP_SET_EQ, "{=}")                  \
    RELOP(RELOP_SET_NE, "{!=}")                 \
    RELOP(RELOP_SET_LT, "{<}")                  \
    RELOP(RELOP_SET_GT, "{>}")                  \
    RELOP(RELOP_SET_LE, "{<=}")                 \
    RELOP(RELOP_SET_GE, "{>=}")

enum relop {
#define RELOP(ENUM, STRING) ENUM,
    RELOPS
#undef RELOP
};

static bool
is_set_operator(enum relop op)
{
    return (op == RELOP_SET_EQ || op == RELOP_SET_NE ||
            op == RELOP_SET_LT || op == RELOP_SET_GT ||
            op == RELOP_SET_LE || op == RELOP_SET_GE);
}

static bool
evaluate_relop(const struct ovsdb_datum *a, const struct ovsdb_datum *b,
               const struct ovsdb_type *type, enum relop op)
{
    switch (op) {
    case RELOP_EQ:
    case RELOP_SET_EQ:
        return ovsdb_datum_compare_3way(a, b, type) == 0;
    case RELOP_NE:
    case RELOP_SET_NE:
        return ovsdb_datum_compare_3way(a, b, type) != 0;
    case RELOP_LT:
        return ovsdb_datum_compare_3way(a, b, type) < 0;
    case RELOP_GT:
        return ovsdb_datum_compare_3way(a, b, type) > 0;
    case RELOP_LE:
        return ovsdb_datum_compare_3way(a, b, type) <= 0;
    case RELOP_GE:
        return ovsdb_datum_compare_3way(a, b, type) >= 0;

    case RELOP_SET_LT:
        return b->n > a->n && ovsdb_datum_includes_all(a, b, type);
    case RELOP_SET_GT:
        return a->n > b->n && ovsdb_datum_includes_all(b, a, type);
    case RELOP_SET_LE:
        return ovsdb_datum_includes_all(a, b, type);
    case RELOP_SET_GE:
        return ovsdb_datum_includes_all(b, a, type);

    default:
        OVS_NOT_REACHED();
    }
}

static bool
is_condition_satisfied(const struct vsctl_table_class *table,
                       const struct ovsdb_idl_row *row, const char *arg,
                       struct ovsdb_symbol_table *symtab)
{
    static const char *operators[] = {
#define RELOP(ENUM, STRING) STRING,
        RELOPS
#undef RELOP
    };

    const struct ovsdb_idl_column *column;
    const struct ovsdb_datum *have_datum;
    char *key_string, *value_string;
    struct ovsdb_type type;
    int operator;
    bool retval;
    char *error;

    error = parse_column_key_value(arg, table, &column, &key_string,
                                   &operator, operators, ARRAY_SIZE(operators),
                                   &value_string);
    die_if_error(error);
    if (!value_string) {
        vsctl_fatal("%s: missing value", arg);
    }

    type = column->type;
    type.n_max = UINT_MAX;

    have_datum = ovsdb_idl_read(row, column);
    if (key_string) {
        union ovsdb_atom want_key;
        struct ovsdb_datum b;
        unsigned int idx;

        if (column->type.value.type == OVSDB_TYPE_VOID) {
            vsctl_fatal("cannot specify key to check for non-map column %s",
                        column->name);
        }

        die_if_error(ovsdb_atom_from_string(&want_key, &column->type.key,
                                            key_string, symtab));

        type.key = type.value;
        type.value.type = OVSDB_TYPE_VOID;
        die_if_error(ovsdb_datum_from_string(&b, &type, value_string, symtab));

        idx = ovsdb_datum_find_key(have_datum,
                                   &want_key, column->type.key.type);
        if (idx == UINT_MAX && !is_set_operator(operator)) {
            retval = false;
        } else {
            struct ovsdb_datum a;

            if (idx != UINT_MAX) {
                a.n = 1;
                a.keys = &have_datum->values[idx];
                a.values = NULL;
            } else {
                a.n = 0;
                a.keys = NULL;
                a.values = NULL;
            }

            retval = evaluate_relop(&a, &b, &type, operator);
        }

        ovsdb_atom_destroy(&want_key, column->type.key.type);
        ovsdb_datum_destroy(&b, &type);
    } else {
        struct ovsdb_datum want_datum;

        die_if_error(ovsdb_datum_from_string(&want_datum, &column->type,
                                             value_string, symtab));
        retval = evaluate_relop(have_datum, &want_datum, &type, operator);
        ovsdb_datum_destroy(&want_datum, &column->type);
    }

    free(key_string);
    free(value_string);

    return retval;
}

static void
pre_cmd_wait_until(struct vsctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const struct vsctl_table_class *table;
    int i;

    table = pre_get_table(ctx, table_name);

    for (i = 3; i < ctx->argc; i++) {
        pre_parse_column_key_value(ctx, ctx->argv[i], table);
    }
}

static void
cmd_wait_until(struct vsctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct vsctl_table_class *table;
    const struct ovsdb_idl_row *row;
    int i;

    table = get_table(table_name);

    row = get_row(ctx, table, record_id, false);
    if (!row) {
        ctx->try_again = true;
        return;
    }

    for (i = 3; i < ctx->argc; i++) {
        if (!is_condition_satisfied(table, row, ctx->argv[i], ctx->symtab)) {
            ctx->try_again = true;
            return;
        }
    }
}

/* Prepares 'ctx', which has already been initialized with
 * vsctl_context_init(), for processing 'command'. */
static void
vsctl_context_init_command(struct vsctl_context *ctx,
                           struct vsctl_command *command)
{
    ctx->argc = command->argc;
    ctx->argv = command->argv;
    ctx->options = command->options;

    ds_swap(&ctx->output, &command->output);
    ctx->table = command->table;

    ctx->verified_ports = false;

    ctx->try_again = false;
}

/* Prepares 'ctx' for processing commands, initializing its members with the
 * values passed in as arguments.
 *
 * If 'command' is nonnull, calls vsctl_context_init_command() to prepare for
 * that particular command. */
static void
vsctl_context_init(struct vsctl_context *ctx, struct vsctl_command *command,
                   struct ovsdb_idl *idl, struct ovsdb_idl_txn *txn,
                   const struct ovsrec_open_vswitch *ovs,
                   struct ovsdb_symbol_table *symtab)
{
    if (command) {
        vsctl_context_init_command(ctx, command);
    }
    ctx->idl = idl;
    ctx->txn = txn;
    ctx->ovs = ovs;
    ctx->symtab = symtab;
    ctx->cache_valid = false;
}

/* Completes processing of 'command' within 'ctx'. */
static void
vsctl_context_done_command(struct vsctl_context *ctx,
                           struct vsctl_command *command)
{
    ds_swap(&ctx->output, &command->output);
    command->table = ctx->table;
}

/* Finishes up with 'ctx'.
 *
 * If command is nonnull, first calls vsctl_context_done_command() to complete
 * processing that command within 'ctx'. */
static void
vsctl_context_done(struct vsctl_context *ctx, struct vsctl_command *command)
{
    if (command) {
        vsctl_context_done_command(ctx, command);
    }
    vsctl_context_invalidate_cache(ctx);
}

static void
run_prerequisites(struct vsctl_command *commands, size_t n_commands,
                  struct ovsdb_idl *idl)
{
    struct vsctl_command *c;

    ovsdb_idl_add_table(idl, &ovsrec_table_open_vswitch);
    if (wait_for_reload) {
        ovsdb_idl_add_column(idl, &ovsrec_open_vswitch_col_cur_cfg);
    }
    for (c = commands; c < &commands[n_commands]; c++) {
        if (c->syntax->prerequisites) {
            struct vsctl_context ctx;

            ds_init(&c->output);
            c->table = NULL;

            vsctl_context_init(&ctx, c, idl, NULL, NULL, NULL);
            (c->syntax->prerequisites)(&ctx);
            vsctl_context_done(&ctx, c);

            ovs_assert(!c->output.string);
            ovs_assert(!c->table);
        }
    }
}

static void
do_vsctl(const char *args, struct vsctl_command *commands, size_t n_commands,
         struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;
    const struct ovsrec_open_vswitch *ovs;
    enum ovsdb_idl_txn_status status;
    struct ovsdb_symbol_table *symtab;
    struct vsctl_context ctx;
    struct vsctl_command *c;
    struct shash_node *node;
    int64_t next_cfg = 0;
    char *error = NULL;

    txn = the_idl_txn = ovsdb_idl_txn_create(idl);
    if (dry_run) {
        ovsdb_idl_txn_set_dry_run(txn);
    }

    ovsdb_idl_txn_add_comment(txn, "ovs-vsctl: %s", args);

    ovs = ovsrec_open_vswitch_first(idl);
    if (!ovs) {
        /* XXX add verification that table is empty */
        ovs = ovsrec_open_vswitch_insert(txn);
    }

    if (wait_for_reload) {
        ovsdb_idl_txn_increment(txn, &ovs->header_,
                                &ovsrec_open_vswitch_col_next_cfg);
    }

    post_db_reload_check_init();
    symtab = ovsdb_symbol_table_create();
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_init(&c->output);
        c->table = NULL;
    }
    vsctl_context_init(&ctx, NULL, idl, txn, ovs, symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        vsctl_context_init_command(&ctx, c);
        if (c->syntax->run) {
            (c->syntax->run)(&ctx);
        }
        vsctl_context_done_command(&ctx, c);

        if (ctx.try_again) {
            vsctl_context_done(&ctx, NULL);
            goto try_again;
        }
    }
    vsctl_context_done(&ctx, NULL);

    SHASH_FOR_EACH (node, &symtab->sh) {
        struct ovsdb_symbol *symbol = node->data;
        if (!symbol->created) {
            vsctl_fatal("row id \"%s\" is referenced but never created (e.g. "
                        "with \"-- --id=%s create ...\")",
                        node->name, node->name);
        }
        if (!symbol->strong_ref) {
            if (!symbol->weak_ref) {
                VLOG_WARN("row id \"%s\" was created but no reference to it "
                          "was inserted, so it will not actually appear in "
                          "the database", node->name);
            } else {
                VLOG_WARN("row id \"%s\" was created but only a weak "
                          "reference to it was inserted, so it will not "
                          "actually appear in the database", node->name);
            }
        }
    }

    status = ovsdb_idl_txn_commit_block(txn);
    if (wait_for_reload && status == TXN_SUCCESS) {
        next_cfg = ovsdb_idl_txn_get_increment_new_value(txn);
    }
    if (status == TXN_UNCHANGED || status == TXN_SUCCESS) {
        for (c = commands; c < &commands[n_commands]; c++) {
            if (c->syntax->postprocess) {
                struct vsctl_context ctx;

                vsctl_context_init(&ctx, c, idl, txn, ovs, symtab);
                (c->syntax->postprocess)(&ctx);
                vsctl_context_done(&ctx, c);
            }
        }
    }
    error = xstrdup(ovsdb_idl_txn_get_error(txn));

    switch (status) {
    case TXN_UNCOMMITTED:
    case TXN_INCOMPLETE:
        OVS_NOT_REACHED();

    case TXN_ABORTED:
        /* Should not happen--we never call ovsdb_idl_txn_abort(). */
        vsctl_fatal("transaction aborted");

    case TXN_UNCHANGED:
    case TXN_SUCCESS:
        break;

    case TXN_TRY_AGAIN:
        goto try_again;

    case TXN_ERROR:
        vsctl_fatal("transaction error: %s", error);

    case TXN_NOT_LOCKED:
        /* Should not happen--we never call ovsdb_idl_set_lock(). */
        vsctl_fatal("database not locked");

    default:
        OVS_NOT_REACHED();
    }
    free(error);

    ovsdb_symbol_table_destroy(symtab);

    for (c = commands; c < &commands[n_commands]; c++) {
        struct ds *ds = &c->output;

        if (c->table) {
            table_print(c->table, &table_style);
        } else if (oneline) {
            size_t j;

            ds_chomp(ds, '\n');
            for (j = 0; j < ds->length; j++) {
                int ch = ds->string[j];
                switch (ch) {
                case '\n':
                    fputs("\\n", stdout);
                    break;

                case '\\':
                    fputs("\\\\", stdout);
                    break;

                default:
                    putchar(ch);
                }
            }
            putchar('\n');
        } else {
            fputs(ds_cstr(ds), stdout);
        }
        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);

        shash_destroy_free_data(&c->options);
    }
    free(commands);

    if (wait_for_reload && status != TXN_UNCHANGED) {
        /* Even, if --retry flag was not specified, ovs-vsctl still
         * has to retry to establish OVSDB connection, if wait_for_reload
         * was set.  Otherwise, ovs-vsctl would end up waiting forever
         * until cur_cfg would be updated. */
        ovsdb_idl_enable_reconnect(idl);
        for (;;) {
            ovsdb_idl_run(idl);
            OVSREC_OPEN_VSWITCH_FOR_EACH (ovs, idl) {
                if (ovs->cur_cfg >= next_cfg) {
                    post_db_reload_do_checks(&ctx);
                    goto done;
                }
            }
            ovsdb_idl_wait(idl);
            poll_block();
        }
    done: ;
    }
    ovsdb_idl_txn_destroy(txn);
    ovsdb_idl_destroy(idl);

    exit(EXIT_SUCCESS);

try_again:
    /* Our transaction needs to be rerun, or a prerequisite was not met.  Free
     * resources and return so that the caller can try again. */
    if (txn) {
        ovsdb_idl_txn_abort(txn);
        ovsdb_idl_txn_destroy(txn);
        the_idl_txn = NULL;
    }
    ovsdb_symbol_table_destroy(symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);
    }
    free(error);
}

static const struct vsctl_command_syntax all_commands[] = {
    /* Open vSwitch commands. */
    {"init", 0, 0, NULL, cmd_init, NULL, "", RW},
    {"show", 0, 0, pre_cmd_show, cmd_show, NULL, "", RO},

    /* Bridge commands. */
    {"add-br", 1, 3, pre_get_info, cmd_add_br, NULL, "--may-exist", RW},
    {"del-br", 1, 1, pre_get_info, cmd_del_br, NULL, "--if-exists", RW},
    {"list-br", 0, 0, pre_get_info, cmd_list_br, NULL, "--real,--fake", RO},
    {"br-exists", 1, 1, pre_get_info, cmd_br_exists, NULL, "", RO},
    {"br-to-vlan", 1, 1, pre_get_info, cmd_br_to_vlan, NULL, "", RO},
    {"br-to-parent", 1, 1, pre_get_info, cmd_br_to_parent, NULL, "", RO},
    {"br-set-external-id", 2, 3, pre_cmd_br_set_external_id,
     cmd_br_set_external_id, NULL, "", RW},
    {"br-get-external-id", 1, 2, pre_cmd_br_get_external_id,
     cmd_br_get_external_id, NULL, "", RO},

    /* Port commands. */
    {"list-ports", 1, 1, pre_get_info, cmd_list_ports, NULL, "", RO},
    {"add-port", 2, INT_MAX, pre_get_info, cmd_add_port, NULL, "--may-exist",
     RW},
    {"add-bond", 4, INT_MAX, pre_get_info, cmd_add_bond, NULL,
     "--may-exist,--fake-iface", RW},
    {"del-port", 1, 2, pre_get_info, cmd_del_port, NULL,
     "--if-exists,--with-iface", RW},
    {"port-to-br", 1, 1, pre_get_info, cmd_port_to_br, NULL, "", RO},

    /* Interface commands. */
    {"list-ifaces", 1, 1, pre_get_info, cmd_list_ifaces, NULL, "", RO},
    {"iface-to-br", 1, 1, pre_get_info, cmd_iface_to_br, NULL, "", RO},

    /* Controller commands. */
    {"get-controller", 1, 1, pre_controller, cmd_get_controller, NULL, "", RO},
    {"del-controller", 1, 1, pre_controller, cmd_del_controller, NULL, "", RW},
    {"set-controller", 1, INT_MAX, pre_controller, cmd_set_controller, NULL,
     "", RW},
    {"get-fail-mode", 1, 1, pre_get_info, cmd_get_fail_mode, NULL, "", RO},
    {"del-fail-mode", 1, 1, pre_get_info, cmd_del_fail_mode, NULL, "", RW},
    {"set-fail-mode", 2, 2, pre_get_info, cmd_set_fail_mode, NULL, "", RW},

    /* Manager commands. */
    {"get-manager", 0, 0, pre_manager, cmd_get_manager, NULL, "", RO},
    {"del-manager", 0, 0, pre_manager, cmd_del_manager, NULL, "", RW},
    {"set-manager", 1, INT_MAX, pre_manager, cmd_set_manager, NULL, "", RW},

    /* SSL commands. */
    {"get-ssl", 0, 0, pre_cmd_get_ssl, cmd_get_ssl, NULL, "", RO},
    {"del-ssl", 0, 0, pre_cmd_del_ssl, cmd_del_ssl, NULL, "", RW},
    {"set-ssl", 3, 3, pre_cmd_set_ssl, cmd_set_ssl, NULL, "--bootstrap", RW},

    /* Switch commands. */
    {"emer-reset", 0, 0, pre_cmd_emer_reset, cmd_emer_reset, NULL, "", RW},

    /* Database commands. */
    {"comment", 0, INT_MAX, NULL, NULL, NULL, "", RO},
    {"get", 2, INT_MAX, pre_cmd_get, cmd_get, NULL, "--if-exists,--id=", RO},
    {"list", 1, INT_MAX, pre_cmd_list, cmd_list, NULL,
     "--if-exists,--columns=", RO},
    {"find", 1, INT_MAX, pre_cmd_find, cmd_find, NULL, "--columns=", RO},
    {"set", 3, INT_MAX, pre_cmd_set, cmd_set, NULL, "--if-exists", RW},
    {"add", 4, INT_MAX, pre_cmd_add, cmd_add, NULL, "--if-exists", RW},
    {"remove", 4, INT_MAX, pre_cmd_remove, cmd_remove, NULL, "--if-exists",
     RW},
    {"clear", 3, INT_MAX, pre_cmd_clear, cmd_clear, NULL, "--if-exists", RW},
    {"create", 2, INT_MAX, pre_create, cmd_create, post_create, "--id=", RW},
    {"destroy", 1, INT_MAX, pre_cmd_destroy, cmd_destroy, NULL,
     "--if-exists,--all", RW},
    {"wait-until", 2, INT_MAX, pre_cmd_wait_until, cmd_wait_until, NULL, "",
     RO},

    {NULL, 0, 0, NULL, NULL, NULL, NULL, RO},
};

static const struct vsctl_command_syntax *get_all_commands(void)
{
    return all_commands;
}
