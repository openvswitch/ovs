/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "lib/vtep-idl.h"
#include "table.h"
#include "timeval.h"
#include "util.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(vtep_ctl);

/* vtep_ctl_fatal() also logs the error, so it is preferred in this file. */
#define ovs_fatal please_use_vtep_ctl_fatal_instead_of_ovs_fatal

struct vtep_ctl_context;

/* A command supported by vtep-ctl. */
struct vtep_ctl_command_syntax {
    const char *name;           /* e.g. "add-ps" */
    int min_args;               /* Min number of arguments following name. */
    int max_args;               /* Max number of arguments following name. */

    /* If nonnull, calls ovsdb_idl_add_column() or ovsdb_idl_add_table() for
     * each column or table in ctx->idl that it uses. */
    void (*prerequisites)(struct vtep_ctl_context *ctx);

    /* Does the actual work of the command and puts the command's output, if
     * any, in ctx->output or ctx->table.
     *
     * Alternatively, if some prerequisite of the command is not met and the
     * caller should wait for something to change and then retry, it may set
     * ctx->try_again to true.  (Only the "wait-until" command currently does
     * this.) */
    void (*run)(struct vtep_ctl_context *ctx);

    /* If nonnull, called after the transaction has been successfully
     * committed.  ctx->output is the output from the "run" function, which
     * this function may modify and otherwise postprocess as needed.  (Only the
     * "create" command currently does any postprocessing.) */
    void (*postprocess)(struct vtep_ctl_context *ctx);

    /* A comma-separated list of supported options, e.g. "--a,--b", or the
     * empty string if the command does not support any options. */
    const char *options;
    enum { RO, RW } mode;       /* Does this command modify the database? */
};

struct vtep_ctl_command {
    /* Data that remains constant after initialization. */
    const struct vtep_ctl_command_syntax *syntax;
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

/* --timeout: Time to wait for a connection to 'db'. */
static int timeout;

/* Format for table output. */
static struct table_style table_style = TABLE_STYLE_DEFAULT;

/* All supported commands. */
static const struct vtep_ctl_command_syntax all_commands[];

/* The IDL we're using and the current transaction, if any.
 * This is for use by vtep_ctl_exit() only, to allow it to clean up.
 * Other code should use its context arguments. */
static struct ovsdb_idl *the_idl;
static struct ovsdb_idl_txn *the_idl_txn;

static void vtep_ctl_exit(int status) NO_RETURN;
static void vtep_ctl_fatal(const char *, ...) PRINTF_FORMAT(1, 2) NO_RETURN;
static char *default_db(void);
static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[], struct shash *local_options);
static bool might_write_to_db(char **argv);

static struct vtep_ctl_command *parse_commands(int argc, char *argv[],
                                            struct shash *local_options,
                                            size_t *n_commandsp);
static void parse_command(int argc, char *argv[], struct shash *local_options,
                          struct vtep_ctl_command *);
static const struct vtep_ctl_command_syntax *find_command(const char *name);
static void run_prerequisites(struct vtep_ctl_command[], size_t n_commands,
                              struct ovsdb_idl *);
static void do_vtep_ctl(const char *args, struct vtep_ctl_command *, size_t n,
                     struct ovsdb_idl *);

static const struct vtep_ctl_table_class *get_table(const char *table_name);
static void set_column(const struct vtep_ctl_table_class *,
                       const struct ovsdb_idl_row *, const char *arg,
                       struct ovsdb_symbol_table *);

static bool is_condition_satisfied(const struct vtep_ctl_table_class *,
                                   const struct ovsdb_idl_row *,
                                   const char *arg,
                                   struct ovsdb_symbol_table *);

static struct vtep_ctl_lswitch *find_lswitch(struct vtep_ctl_context *,
                                             const char *name,
                                             bool must_exist);

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_reconnect;
    struct ovsdb_idl *idl;
    struct vtep_ctl_command *commands;
    struct shash local_options;
    unsigned int seqno;
    size_t n_commands;
    char *args;

    set_program_name(argv[0]);
    signal(SIGPIPE, SIG_IGN);
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_FACILITY, VLL_WARN);
    vteprec_init();

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
    idl = the_idl = ovsdb_idl_create(db, &vteprec_idl_class, false, false);
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

        if (seqno != ovsdb_idl_get_seqno(idl)) {
            seqno = ovsdb_idl_get_seqno(idl);
            do_vtep_ctl(args, commands, n_commands, idl);
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
        OPT_DRY_RUN,
        OPT_PEER_CA_CERT,
        OPT_LOCAL,
        VLOG_OPTION_ENUMS,
        TABLE_OPTION_ENUMS
    };
    static const struct option global_long_options[] = {
        {"db", required_argument, NULL, OPT_DB},
        {"no-syslog", no_argument, NULL, OPT_NO_SYSLOG},
        {"dry-run", no_argument, NULL, OPT_DRY_RUN},
        {"oneline", no_argument, NULL, OPT_ONELINE},
        {"timeout", required_argument, NULL, 't'},
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

    const struct vtep_ctl_command_syntax *p;
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
    for (p = all_commands; p->name; p++) {
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
            vlog_set_levels(&VLM_vtep_ctl, VLF_SYSLOG, VLL_WARN);
            break;

        case OPT_DRY_RUN:
            dry_run = true;
            break;

        case OPT_LOCAL:
            if (shash_find(local_options, options[idx].name)) {
                vtep_ctl_fatal("'%s' option specified multiple times",
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
            exit(EXIT_SUCCESS);

        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout < 0) {
                vtep_ctl_fatal("value %s on -t or --timeout is invalid",
                            optarg);
            }
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

static struct vtep_ctl_command *
parse_commands(int argc, char *argv[], struct shash *local_options,
               size_t *n_commandsp)
{
    struct vtep_ctl_command *commands;
    size_t n_commands, allocated_commands;
    int i, start;

    commands = NULL;
    n_commands = allocated_commands = 0;

    for (start = i = 0; i <= argc; i++) {
        if (i == argc || !strcmp(argv[i], "--")) {
            if (i > start) {
                if (n_commands >= allocated_commands) {
                    struct vtep_ctl_command *c;

                    commands = x2nrealloc(commands, &allocated_commands,
                                          sizeof *commands);
                    for (c = commands; c < &commands[n_commands]; c++) {
                        shash_moved(&c->options);
                    }
                }
                parse_command(i - start, &argv[start], local_options,
                              &commands[n_commands++]);
            } else if (!shash_is_empty(local_options)) {
                vtep_ctl_fatal("missing command name (use --help for help)");
            }
            start = i + 1;
        }
    }
    if (!n_commands) {
        vtep_ctl_fatal("missing command name (use --help for help)");
    }
    *n_commandsp = n_commands;
    return commands;
}

static void
parse_command(int argc, char *argv[], struct shash *local_options,
              struct vtep_ctl_command *command)
{
    const struct vtep_ctl_command_syntax *p;
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
            vtep_ctl_fatal("'%s' option specified multiple times", argv[i]);
        }
        shash_add_nocopy(&command->options, key, value);
    }
    if (i == argc) {
        vtep_ctl_fatal("missing command name (use --help for help)");
    }

    p = find_command(argv[i]);
    if (!p) {
        vtep_ctl_fatal("unknown command '%s'; use --help for help", argv[i]);
    }

    SHASH_FOR_EACH (node, &command->options) {
        const char *s = strstr(p->options, node->name);
        int end = s ? s[strlen(node->name)] : EOF;

        if (end != '=' && end != ',' && end != ' ' && end != '\0') {
            vtep_ctl_fatal("'%s' command has no '%s' option",
                        argv[i], node->name);
        }
        if ((end == '=') != (node->data != NULL)) {
            if (end == '=') {
                vtep_ctl_fatal("missing argument to '%s' option on '%s' "
                            "command", node->name, argv[i]);
            } else {
                vtep_ctl_fatal("'%s' option on '%s' does not accept an "
                            "argument", node->name, argv[i]);
            }
        }
    }

    n_arg = argc - i - 1;
    if (n_arg < p->min_args) {
        vtep_ctl_fatal("'%s' command requires at least %d arguments",
                    p->name, p->min_args);
    } else if (n_arg > p->max_args) {
        int j;

        for (j = i + 1; j < argc; j++) {
            if (argv[j][0] == '-') {
                vtep_ctl_fatal("'%s' command takes at most %d arguments "
                            "(note that options must precede command "
                            "names and follow a \"--\" argument)",
                            p->name, p->max_args);
            }
        }

        vtep_ctl_fatal("'%s' command takes at most %d arguments",
                    p->name, p->max_args);
    }

    command->syntax = p;
    command->argc = n_arg + 1;
    command->argv = &argv[i];
}

/* Returns the "struct vtep_ctl_command_syntax" for a given command 'name', or a
 * null pointer if there is none. */
static const struct vtep_ctl_command_syntax *
find_command(const char *name)
{
    static struct shash commands = SHASH_INITIALIZER(&commands);

    if (shash_is_empty(&commands)) {
        const struct vtep_ctl_command_syntax *p;

        for (p = all_commands; p->name; p++) {
            shash_add_assert(&commands, p->name, p);
        }
    }

    return shash_find_data(&commands, name);
}

static void
vtep_ctl_fatal(const char *format, ...)
{
    char *message;
    va_list args;

    va_start(args, format);
    message = xvasprintf(format, args);
    va_end(args);

    vlog_set_levels(&VLM_vtep_ctl, VLF_CONSOLE, VLL_OFF);
    VLOG_ERR("%s", message);
    ovs_error(0, "%s", message);
    vtep_ctl_exit(EXIT_FAILURE);
}

/* Frees the current transaction and the underlying IDL and then calls
 * exit(status).
 *
 * Freeing the transaction and the IDL is not strictly necessary, but it makes
 * for a clean memory leak report from valgrind in the normal case.  That makes
 * it easier to notice real memory leaks. */
static void
vtep_ctl_exit(int status)
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
%s: VTEP configuration utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
Manager commands:\n\
  get-manager                 print the managers\n\
  del-manager                 delete the managers\n\
  set-manager TARGET...       set the list of managers to TARGET...\n\
\n\
Physical Switch commands:\n\
  add-ps PS                   create a new physical switch named PS\n\
  del-ps PS                   delete PS and all of its ports\n\
  list-ps                     print the names of all the physical switches\n\
  ps-exists PS                exit 2 if PS does not exist\n\
\n\
Port commands:\n\
  list-ports PS               print the names of all the ports on PS\n\
  add-port PS PORT            add network device PORT to PS\n\
  del-port PS PORT            delete PORT from PS\n\
\n\
Logical Switch commands:\n\
  add-ls LS                   create a new logical switch named LS\n\
  del-ls LS                   delete LS and all of its ports\n\
  list-ls                     print the names of all the logical switches\n\
  ls-exists LS                exit 2 if LS does not exist\n\
  bind-ls PS PORT VLAN LS     bind LS to VLAN on PORT\n\
  unbind-ls PS PORT VLAN      unbind logical switch on VLAN from PORT\n\
  list-bindings PS PORT       list bindings for PORT on PS\n\
\n\
MAC binding commands:\n\
  add-ucast-local LS MAC [ENCAP] IP   add ucast local entry in LS\n\
  del-ucast-local LS MAC              del ucast local entry from LS\n\
  add-mcast-local LS MAC [ENCAP] IP   add mcast local entry in LS\n\
  del-mcast-local LS MAC [ENCAP] IP   del mcast local entry from LS\n\
  clear-local-macs LS                 clear local mac entries\n\
  list-local-macs LS                  list local mac entries\n\
  add-ucast-remote LS MAC [ENCAP] IP  add ucast remote entry in LS\n\
  del-ucast-remote LS MAC             del ucast remote entry from LS\n\
  add-mcast-remote LS MAC [ENCAP] IP  add mcast remote entry in LS\n\
  del-mcast-remote LS MAC [ENCAP] IP  del mcast remote entry from LS\n\
  clear-remote-macs LS                clear remote mac entries\n\
  list-remote-macs LS                 list remote mac entries\n\
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
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           program_name, program_name, default_db());
    vlog_usage();
    printf("\
  --no-syslog                 equivalent to --verbose=vtep_ctl:syslog:warn\n");
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
        const struct vtep_ctl_command_syntax *p = find_command(*argv);
        if (p && p->mode == RW) {
            return true;
        }
    }
    return false;
}

struct vtep_ctl_context {
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
    const struct vteprec_global *vtep_global;
    bool verified_ports;

    /* A cache of the contents of the database.
     *
     * A command that needs to use any of this information must first
     * call vtep_ctl_context_populate_cache().  A command that changes
     * anything that could invalidate the cache must either call
     * vtep_ctl_context_invalidate_cache() or manually update the cache
     * to maintain its correctness. */
    bool cache_valid;
    struct shash pswitches; /* Maps from physical switch name to
                             * struct vtep_ctl_pswitch. */
    struct shash ports;     /* Maps from port name to struct vtep_ctl_port. */

    struct shash lswitches; /* Maps from logical switch name to
                             * struct vtep_ctl_lswitch. */
    struct shash plocs;     /* Maps from "<encap>+<dst_ip>" to
                             * struct vteprec_physical_locator. */

    /* A command may set this member to true if some prerequisite is not met
     * and the caller should wait for something to change and then retry. */
    bool try_again;
};

struct vtep_ctl_pswitch {
    const struct vteprec_physical_switch *ps_cfg;
    char *name;
    struct list ports;          /* Contains "struct vteprec_physical_port"s. */
};

struct vtep_ctl_port {
    struct list ports_node;     /* In struct vtep_ctl_pswitch's 'ports' list. */
    const struct vteprec_physical_port *port_cfg;
    struct vtep_ctl_pswitch *ps;
    struct shash bindings;      /* Maps from vlan to vtep_ctl_lswitch. */
};

struct vtep_ctl_lswitch {
    const struct vteprec_logical_switch *ls_cfg;
    char *name;
    struct shash ucast_local;   /* Maps from mac to vteprec_ucast_macs_local. */
    struct shash ucast_remote;  /* Maps from mac to vteprec_ucast_macs_remote.*/
    struct shash mcast_local;   /* Maps from mac to vtep_ctl_mcast_mac. */
    struct shash mcast_remote;  /* Maps from mac to vtep_ctl_mcast_mac. */
};

struct vtep_ctl_mcast_mac {
    const struct vteprec_mcast_macs_local *local_cfg;
    const struct vteprec_mcast_macs_remote *remote_cfg;

    const struct vteprec_physical_locator_set *ploc_set_cfg;
    struct list locators;       /* Contains 'vtep_ctl_ploc's. */
};

struct vtep_ctl_ploc {
    struct list locators_node;  /* In struct vtep_ctl_ploc_set's 'locators'
                                   list. */
    const struct vteprec_physical_locator *ploc_cfg;
};

static void
verify_ports(struct vtep_ctl_context *ctx)
{
    if (!ctx->verified_ports) {
        const struct vteprec_physical_switch *ps;

        vteprec_global_verify_switches(ctx->vtep_global);
        VTEPREC_PHYSICAL_SWITCH_FOR_EACH (ps, ctx->idl) {
            vteprec_physical_switch_verify_ports(ps);
        }

        ctx->verified_ports = true;
    }
}

static struct vtep_ctl_port *
add_port_to_cache(struct vtep_ctl_context *ctx,
                  struct vtep_ctl_pswitch *ps,
                  struct vteprec_physical_port *port_cfg)
{
    char *cache_name = xasprintf("%s+%s", ps->name, port_cfg->name);
    struct vtep_ctl_port *port;

    port = xmalloc(sizeof *port);
    list_push_back(&ps->ports, &port->ports_node);
    port->port_cfg = port_cfg;
    port->ps = ps;
    shash_add(&ctx->ports, cache_name, port);
    free(cache_name);
    shash_init(&port->bindings);

    return port;
}

static void
del_cached_port(struct vtep_ctl_context *ctx, struct vtep_ctl_port *port)
{
    char *cache_name = xasprintf("%s+%s", port->ps->name, port->port_cfg->name);

    list_remove(&port->ports_node);
    shash_find_and_delete(&ctx->ports, port->port_cfg->name);
    vteprec_physical_port_delete(port->port_cfg);
    free(cache_name);
    free(port);
}

static struct vtep_ctl_pswitch *
add_pswitch_to_cache(struct vtep_ctl_context *ctx,
                     struct vteprec_physical_switch *ps_cfg)
{
    struct vtep_ctl_pswitch *ps = xmalloc(sizeof *ps);
    ps->ps_cfg = ps_cfg;
    ps->name = xstrdup(ps_cfg->name);
    list_init(&ps->ports);
    shash_add(&ctx->pswitches, ps->name, ps);
    return ps;
}

static void
vtep_delete_pswitch(const struct vteprec_global *vtep_global,
                    const struct vteprec_physical_switch *ps)
{
    struct vteprec_physical_switch **pswitches;
    size_t i, n;

    pswitches = xmalloc(sizeof *vtep_global->switches
                        * vtep_global->n_switches);
    for (i = n = 0; i < vtep_global->n_switches; i++) {
        if (vtep_global->switches[i] != ps) {
            pswitches[n++] = vtep_global->switches[i];
        }
    }
    vteprec_global_set_switches(vtep_global, pswitches, n);
    free(pswitches);
}

static void
del_cached_pswitch(struct vtep_ctl_context *ctx, struct vtep_ctl_pswitch *ps)
{
    ovs_assert(list_is_empty(&ps->ports));
    if (ps->ps_cfg) {
        vteprec_physical_switch_delete(ps->ps_cfg);
        vtep_delete_pswitch(ctx->vtep_global, ps->ps_cfg);
    }
    shash_find_and_delete(&ctx->pswitches, ps->name);
    free(ps->name);
    free(ps);
}

static struct vtep_ctl_lswitch *
add_lswitch_to_cache(struct vtep_ctl_context *ctx,
                     const struct vteprec_logical_switch *ls_cfg)
{
    struct vtep_ctl_lswitch *ls = xmalloc(sizeof *ls);
    ls->ls_cfg = ls_cfg;
    ls->name = xstrdup(ls_cfg->name);
    shash_add(&ctx->lswitches, ls->name, ls);
    shash_init(&ls->ucast_local);
    shash_init(&ls->ucast_remote);
    shash_init(&ls->mcast_local);
    shash_init(&ls->mcast_remote);
    return ls;
}

static void
del_cached_lswitch(struct vtep_ctl_context *ctx, struct vtep_ctl_lswitch *ls)
{
    if (ls->ls_cfg) {
        vteprec_logical_switch_delete(ls->ls_cfg);
    }
    shash_find_and_delete(&ctx->lswitches, ls->name);
    free(ls->name);
    free(ls);
}

static void
commit_ls_bindings(struct vtep_ctl_port *port)
{
    struct vteprec_logical_switch **binding_values;
    int64_t *binding_keys;
    size_t n_bindings;
    struct shash_node *node;
    int i;

    n_bindings = shash_count(&port->bindings);
    binding_keys = xmalloc(n_bindings * sizeof *binding_keys);
    binding_values = xmalloc(n_bindings * sizeof *binding_values);

    i = 0;
    SHASH_FOR_EACH(node, &port->bindings) {
        struct vtep_ctl_lswitch *ls_entry = node->data;

        binding_keys[i] = strtoll(node->name, NULL, 0);
        binding_values[i] = (struct vteprec_logical_switch *)ls_entry->ls_cfg;
        i++;
    }

    vteprec_physical_port_set_vlan_bindings(port->port_cfg,
                                            binding_keys, binding_values,
                                            n_bindings);
    free(binding_values);
    free(binding_keys);
}

static void
add_ls_binding_to_cache(struct vtep_ctl_port *port,
                        const char *vlan,
                        struct vtep_ctl_lswitch *ls)
{
    if (shash_find(&port->bindings, vlan)) {
        vtep_ctl_fatal("multiple bindings for vlan %s", vlan);
    }

    shash_add(&port->bindings, vlan, ls);
}

static void
del_cached_ls_binding(struct vtep_ctl_port *port, const char *vlan)
{
    if (!shash_find(&port->bindings, vlan)) {
        vtep_ctl_fatal("no binding for vlan %s", vlan);
    }

    shash_find_and_delete(&port->bindings, vlan);
}

static struct vteprec_physical_locator *
find_ploc(struct vtep_ctl_context *ctx, const char *encap,
          const char *dst_ip)
{
    struct vteprec_physical_locator *ploc;
    char *name = xasprintf("%s+%s", encap, dst_ip);

    ovs_assert(ctx->cache_valid);

    ploc = shash_find_data(&ctx->plocs, name);
    free(name);

    return ploc;
}

static void
add_ploc_to_cache(struct vtep_ctl_context *ctx,
                  struct vteprec_physical_locator *ploc)
{
    char *name = xasprintf("%s+%s", ploc->encapsulation_type, ploc->dst_ip);
    struct vteprec_physical_locator *orig_ploc;

    orig_ploc = find_ploc(ctx, ploc->encapsulation_type, ploc->dst_ip);
    if (!orig_ploc) {
        shash_add(&ctx->plocs, name, ploc);
    }

    free(name);
}

static void
add_ploc_to_mcast_mac(struct vtep_ctl_mcast_mac *mcast_mac,
                      struct vteprec_physical_locator *ploc_cfg)
{
    struct vtep_ctl_ploc *ploc;

    ploc = xmalloc(sizeof *ploc);
    ploc->ploc_cfg = ploc_cfg;
    list_push_back(&mcast_mac->locators, &ploc->locators_node);
}

static void
del_ploc_from_mcast_mac(struct vtep_ctl_mcast_mac *mcast_mac,
                        struct vteprec_physical_locator *ploc_cfg)
{
    struct vtep_ctl_ploc *ploc;

    LIST_FOR_EACH (ploc, locators_node, &mcast_mac->locators) {
        if (ploc->ploc_cfg == ploc_cfg) {
            list_remove(&ploc->locators_node);
            free(ploc);
            return;
        }
    }
}

static struct vtep_ctl_mcast_mac *
add_mcast_mac_to_cache(struct vtep_ctl_context *ctx,
                       struct vtep_ctl_lswitch *ls, const char *mac,
                       struct vteprec_physical_locator_set *ploc_set_cfg,
                       bool local)
{
    struct vtep_ctl_mcast_mac *mcast_mac;
    struct shash *mcast_shash;
    size_t i;

    mcast_mac = xmalloc(sizeof *mcast_mac);
    mcast_shash = local ? &ls->mcast_local : &ls->mcast_remote;

    mcast_mac->ploc_set_cfg = ploc_set_cfg;
    list_init(&mcast_mac->locators);
    shash_add(mcast_shash, mac, mcast_mac);
 
    for (i = 0; i < ploc_set_cfg->n_locators; i++) {
        struct vteprec_physical_locator *ploc_cfg;

        ploc_cfg = ploc_set_cfg->locators[i];
        add_ploc_to_mcast_mac(mcast_mac, ploc_cfg);
        add_ploc_to_cache(ctx, ploc_cfg);
    }

    return mcast_mac;
}

static void
vtep_ctl_context_invalidate_cache(struct vtep_ctl_context *ctx)
{
    struct shash_node *node;

    if (!ctx->cache_valid) {
        return;
    }
    ctx->cache_valid = false;

    SHASH_FOR_EACH (node, &ctx->pswitches) {
        struct vtep_ctl_pswitch *ps = node->data;
        free(ps->name);
        free(ps);
    }
    shash_destroy(&ctx->pswitches);

    SHASH_FOR_EACH (node, &ctx->ports) {
        struct vtep_ctl_port *port = node->data;
        shash_destroy(&port->bindings);
    }
    shash_destroy_free_data(&ctx->ports);

    SHASH_FOR_EACH (node, &ctx->lswitches) {
        struct vtep_ctl_lswitch *ls = node->data;
        struct shash_node *node2, *next_node2;

        shash_destroy(&ls->ucast_local);
        shash_destroy(&ls->ucast_remote);

        SHASH_FOR_EACH_SAFE (node2, next_node2, &ls->mcast_local) {
            struct vtep_ctl_mcast_mac *mcast_mac = node2->data;
            struct vtep_ctl_ploc *ploc, *next_ploc;

            LIST_FOR_EACH_SAFE (ploc, next_ploc, locators_node,
                                &mcast_mac->locators) {
                free(ploc);
            }
            free(mcast_mac);
        }
        shash_destroy(&ls->mcast_local);

        SHASH_FOR_EACH_SAFE (node2, next_node2, &ls->mcast_remote) {
            struct vtep_ctl_mcast_mac *mcast_mac = node2->data;
            struct vtep_ctl_ploc *ploc, *next_ploc;

            LIST_FOR_EACH_SAFE (ploc, next_ploc, locators_node,
                                &mcast_mac->locators) {
                free(ploc);
            }
            free(mcast_mac);
        }
        shash_destroy(&ls->mcast_remote);

        free(ls->name);
        free(ls);
    }
    shash_destroy(&ctx->lswitches);
    shash_destroy(&ctx->plocs);
}

static void
pre_get_info(struct vtep_ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &vteprec_global_col_switches);

    ovsdb_idl_add_column(ctx->idl, &vteprec_physical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &vteprec_physical_switch_col_ports);

    ovsdb_idl_add_column(ctx->idl, &vteprec_physical_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &vteprec_physical_port_col_vlan_bindings);

    ovsdb_idl_add_column(ctx->idl, &vteprec_logical_switch_col_name);

    ovsdb_idl_add_column(ctx->idl, &vteprec_ucast_macs_local_col_MAC);
    ovsdb_idl_add_column(ctx->idl, &vteprec_ucast_macs_local_col_locator);
    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_ucast_macs_local_col_logical_switch);

    ovsdb_idl_add_column(ctx->idl, &vteprec_ucast_macs_remote_col_MAC);
    ovsdb_idl_add_column(ctx->idl, &vteprec_ucast_macs_remote_col_locator);
    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_ucast_macs_remote_col_logical_switch);

    ovsdb_idl_add_column(ctx->idl, &vteprec_mcast_macs_local_col_MAC);
    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_mcast_macs_local_col_locator_set);
    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_mcast_macs_local_col_logical_switch);

    ovsdb_idl_add_column(ctx->idl, &vteprec_mcast_macs_remote_col_MAC);
    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_mcast_macs_remote_col_locator_set);
    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_mcast_macs_remote_col_logical_switch);

    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_physical_locator_set_col_locators);

    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_physical_locator_col_dst_ip);
    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_physical_locator_col_encapsulation_type);
}

static void
vtep_ctl_context_populate_cache(struct vtep_ctl_context *ctx)
{
    const struct vteprec_global *vtep_global = ctx->vtep_global;
    const struct vteprec_logical_switch *ls_cfg;
    const struct vteprec_ucast_macs_local *ucast_local_cfg;
    const struct vteprec_ucast_macs_remote *ucast_remote_cfg;
    const struct vteprec_mcast_macs_local *mcast_local_cfg;
    const struct vteprec_mcast_macs_remote *mcast_remote_cfg;
    struct sset pswitches, ports, lswitches;
    size_t i;

    if (ctx->cache_valid) {
        /* Cache is already populated. */
        return;
    }
    ctx->cache_valid = true;
    shash_init(&ctx->pswitches);
    shash_init(&ctx->ports);
    shash_init(&ctx->lswitches);
    shash_init(&ctx->plocs);

    sset_init(&pswitches);
    sset_init(&ports);
    for (i = 0; i < vtep_global->n_switches; i++) {
        struct vteprec_physical_switch *ps_cfg = vtep_global->switches[i];
        struct vtep_ctl_pswitch *ps;
        size_t j;

        if (!sset_add(&pswitches, ps_cfg->name)) {
            VLOG_WARN("%s: database contains duplicate physical switch name",
                      ps_cfg->name);
            continue;
        }
        ps = add_pswitch_to_cache(ctx, ps_cfg);
        if (!ps) {
            continue;
        }

        for (j = 0; j < ps_cfg->n_ports; j++) {
            struct vteprec_physical_port *port_cfg = ps_cfg->ports[j];

            if (!sset_add(&ports, port_cfg->name)) {
                /* Duplicate port name.  (We will warn about that later.) */
                continue;
            }
        }
    }
    sset_destroy(&pswitches);
    sset_destroy(&ports);

    sset_init(&lswitches);
    VTEPREC_LOGICAL_SWITCH_FOR_EACH (ls_cfg, ctx->idl) {
        if (!sset_add(&lswitches, ls_cfg->name)) {
            VLOG_WARN("%s: database contains duplicate logical switch name",
                      ls_cfg->name);
            continue;
        }
        add_lswitch_to_cache(ctx, ls_cfg);
    }
    sset_destroy(&lswitches);

    VTEPREC_UCAST_MACS_LOCAL_FOR_EACH (ucast_local_cfg, ctx->idl) {
        struct vtep_ctl_lswitch *ls;

        if (!ucast_local_cfg->logical_switch) {
            continue;
        }
        ls = find_lswitch(ctx, ucast_local_cfg->logical_switch->name, false);
        if (!ls) {
            continue;
        }

        if (ucast_local_cfg->locator) {
            add_ploc_to_cache(ctx, ucast_local_cfg->locator);
        }

        shash_add(&ls->ucast_local, ucast_local_cfg->MAC, ucast_local_cfg);
    }

    VTEPREC_UCAST_MACS_REMOTE_FOR_EACH (ucast_remote_cfg, ctx->idl) {
        struct vtep_ctl_lswitch *ls;

        if (!ucast_remote_cfg->logical_switch) {
            continue;
        }
        ls = find_lswitch(ctx, ucast_remote_cfg->logical_switch->name, false);
        if (!ls) {
            continue;
        }

        if (ucast_remote_cfg->locator) {
            add_ploc_to_cache(ctx, ucast_remote_cfg->locator);
        }

        shash_add(&ls->ucast_remote, ucast_remote_cfg->MAC, ucast_remote_cfg);
    }

    VTEPREC_MCAST_MACS_LOCAL_FOR_EACH (mcast_local_cfg, ctx->idl) {
        struct vtep_ctl_mcast_mac *mcast_mac;
        struct vtep_ctl_lswitch *ls;

        if (!mcast_local_cfg->logical_switch) {
            continue;
        }
        ls = find_lswitch(ctx, mcast_local_cfg->logical_switch->name, false);
        if (!ls) {
            continue;
        }

        mcast_mac = add_mcast_mac_to_cache(ctx, ls, mcast_local_cfg->MAC,
                                           mcast_local_cfg->locator_set,
                                           true);
        mcast_mac->local_cfg = mcast_local_cfg;
    }

    VTEPREC_MCAST_MACS_REMOTE_FOR_EACH (mcast_remote_cfg, ctx->idl) {
        struct vtep_ctl_mcast_mac *mcast_mac;
        struct vtep_ctl_lswitch *ls;

        if (!mcast_remote_cfg->logical_switch) {
            continue;
        }
        ls = find_lswitch(ctx, mcast_remote_cfg->logical_switch->name, false);
        if (!ls) {
            continue;
        }

        mcast_mac = add_mcast_mac_to_cache(ctx, ls, mcast_remote_cfg->MAC,
                                           mcast_remote_cfg->locator_set,
                                           false);
        mcast_mac->remote_cfg = mcast_remote_cfg;
    }

    sset_init(&pswitches);
    for (i = 0; i < vtep_global->n_switches; i++) {
        struct vteprec_physical_switch *ps_cfg = vtep_global->switches[i];
        struct vtep_ctl_pswitch *ps;
        size_t j;

        if (!sset_add(&pswitches, ps_cfg->name)) {
            continue;
        }
        ps = shash_find_data(&ctx->pswitches, ps_cfg->name);
        for (j = 0; j < ps_cfg->n_ports; j++) {
            struct vteprec_physical_port *port_cfg = ps_cfg->ports[j];
            struct vtep_ctl_port *port;
            size_t k;

            port = shash_find_data(&ctx->ports, port_cfg->name);
            if (port) {
                if (port_cfg == port->port_cfg) {
                    VLOG_WARN("%s: port is in multiple physical switches "
                              "(%s and %s)",
                              port_cfg->name, ps->name, port->ps->name);
                } else {
                    /* Log as an error because this violates the database's
                     * uniqueness constraints, so the database server shouldn't
                     * have allowed it. */
                    VLOG_ERR("%s: database contains duplicate port name",
                             port_cfg->name);
                }
                continue;
            }

            port = add_port_to_cache(ctx, ps, port_cfg);

            for (k = 0; k < port_cfg->n_vlan_bindings; k++) {
                struct vteprec_logical_switch *ls_cfg;
                struct vtep_ctl_lswitch *ls;
                char *vlan;

                vlan = xasprintf("%"PRId64, port_cfg->key_vlan_bindings[k]);
                if (shash_find(&port->bindings, vlan)) {
                    vtep_ctl_fatal("multiple bindings for vlan %s", vlan);
                }
 
                ls_cfg = port_cfg->value_vlan_bindings[k];
                ls = find_lswitch(ctx, ls_cfg->name, true);

                shash_add_nocopy(&port->bindings, vlan, ls);
            }
        }
    }
    sset_destroy(&pswitches);
}

static struct vtep_ctl_pswitch *
find_pswitch(struct vtep_ctl_context *ctx, const char *name, bool must_exist)
{
    struct vtep_ctl_pswitch *ps;

    ovs_assert(ctx->cache_valid);

    ps = shash_find_data(&ctx->pswitches, name);
    if (must_exist && !ps) {
        vtep_ctl_fatal("no physical switch named %s", name);
    }
    vteprec_global_verify_switches(ctx->vtep_global);
    return ps;
}

static struct vtep_ctl_port *
find_port(struct vtep_ctl_context *ctx, const char *ps_name,
          const char *port_name, bool must_exist)
{
    char *cache_name = xasprintf("%s+%s", ps_name, port_name);
    struct vtep_ctl_port *port;

    ovs_assert(ctx->cache_valid);

    port = shash_find_data(&ctx->ports, cache_name);
    if (port && !strcmp(port_name, port->ps->name)) {
        port = NULL;
    }
    free(cache_name);
    if (must_exist && !port) {
        vtep_ctl_fatal("no port named %s", port_name);
    }
    verify_ports(ctx);
    return port;
}

static void
pswitch_insert_port(const struct vteprec_physical_switch *ps,
                    struct vteprec_physical_port *port)
{
    struct vteprec_physical_port **ports;
    size_t i;

    ports = xmalloc(sizeof *ps->ports * (ps->n_ports + 1));
    for (i = 0; i < ps->n_ports; i++) {
        ports[i] = ps->ports[i];
    }
    ports[ps->n_ports] = port;
    vteprec_physical_switch_set_ports(ps, ports, ps->n_ports + 1);
    free(ports);
}

static void
pswitch_delete_port(const struct vteprec_physical_switch *ps,
                    const struct vteprec_physical_port *port)
{
    struct vteprec_physical_port **ports;
    size_t i, n;

    ports = xmalloc(sizeof *ps->ports * ps->n_ports);
    for (i = n = 0; i < ps->n_ports; i++) {
        if (ps->ports[i] != port) {
            ports[n++] = ps->ports[i];
        }
    }
    vteprec_physical_switch_set_ports(ps, ports, n);
    free(ports);
}

static void
vtep_insert_pswitch(const struct vteprec_global *vtep_global,
                    struct vteprec_physical_switch *ps)
{
    struct vteprec_physical_switch **pswitches;
    size_t i;

    pswitches = xmalloc(sizeof *vtep_global->switches
                        * (vtep_global->n_switches + 1));
    for (i = 0; i < vtep_global->n_switches; i++) {
        pswitches[i] = vtep_global->switches[i];
    }
    pswitches[vtep_global->n_switches] = ps;
    vteprec_global_set_switches(vtep_global, pswitches,
                                vtep_global->n_switches + 1);
    free(pswitches);
}

static void
cmd_add_ps(struct vtep_ctl_context *ctx)
{
    const char *ps_name = ctx->argv[1];
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    struct vteprec_physical_switch *ps;

    vtep_ctl_context_populate_cache(ctx);
    if (find_pswitch(ctx, ps_name, false)) {
        if (!may_exist) {
            vtep_ctl_fatal("cannot create physical switch %s because it "
                           "already exists", ps_name);
        }
        return;
    }

    ps = vteprec_physical_switch_insert(ctx->txn);
    vteprec_physical_switch_set_name(ps, ps_name);

    vtep_insert_pswitch(ctx->vtep_global, ps);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
del_port(struct vtep_ctl_context *ctx, struct vtep_ctl_port *port)
{
    pswitch_delete_port(port->ps->ps_cfg, port->port_cfg);
    del_cached_port(ctx, port);
}

static void
del_pswitch(struct vtep_ctl_context *ctx, struct vtep_ctl_pswitch *ps)
{
    struct vtep_ctl_port *port, *next_port;

    LIST_FOR_EACH_SAFE (port, next_port, ports_node, &ps->ports) {
        del_port(ctx, port);
    }

    del_cached_pswitch(ctx, ps);
}

static void
cmd_del_ps(struct vtep_ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vtep_ctl_pswitch *ps;

    vtep_ctl_context_populate_cache(ctx);
    ps = find_pswitch(ctx, ctx->argv[1], must_exist);
    if (ps) {
        del_pswitch(ctx, ps);
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
cmd_list_ps(struct vtep_ctl_context *ctx)
{
    struct shash_node *node;
    struct svec pswitches;

    vtep_ctl_context_populate_cache(ctx);

    svec_init(&pswitches);
    SHASH_FOR_EACH (node, &ctx->pswitches) {
        struct vtep_ctl_pswitch *ps = node->data;

        svec_add(&pswitches, ps->name);
    }
    output_sorted(&pswitches, &ctx->output);
    svec_destroy(&pswitches);
}

static void
cmd_ps_exists(struct vtep_ctl_context *ctx)
{
    vtep_ctl_context_populate_cache(ctx);
    if (!find_pswitch(ctx, ctx->argv[1], false)) {
        vtep_ctl_exit(2);
    }
}

static void
cmd_list_ports(struct vtep_ctl_context *ctx)
{
    struct vtep_ctl_pswitch *ps;
    struct vtep_ctl_port *port;
    struct svec ports;

    vtep_ctl_context_populate_cache(ctx);
    ps = find_pswitch(ctx, ctx->argv[1], true);
    vteprec_physical_switch_verify_ports(ps->ps_cfg);

    svec_init(&ports);
    LIST_FOR_EACH (port, ports_node, &ps->ports) {
        if (strcmp(port->port_cfg->name, ps->name)) {
            svec_add(&ports, port->port_cfg->name);
        }
    }
    output_sorted(&ports, &ctx->output);
    svec_destroy(&ports);
}

static void
add_port(struct vtep_ctl_context *ctx, const char *ps_name,
         const char *port_name, bool may_exist)
{
    struct vtep_ctl_port *vtep_ctl_port;
    struct vtep_ctl_pswitch *ps;
    struct vteprec_physical_port *port;

    vtep_ctl_context_populate_cache(ctx);

    vtep_ctl_port = find_port(ctx, ps_name, port_name, false);
    if (vtep_ctl_port) {
        if (!may_exist) {
            vtep_ctl_fatal("cannot create a port named %s on %s because a "
                           "port with that name already exists",
                           port_name, ps_name);
        }
        return;
    }

    ps = find_pswitch(ctx, ps_name, true);

    port = vteprec_physical_port_insert(ctx->txn);
    vteprec_physical_port_set_name(port, port_name);

    pswitch_insert_port(ps->ps_cfg, port);

    add_port_to_cache(ctx, ps, port);
}

static void
cmd_add_port(struct vtep_ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    add_port(ctx, ctx->argv[1], ctx->argv[2], may_exist);
}

static void
cmd_del_port(struct vtep_ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vtep_ctl_port *port;

    vtep_ctl_context_populate_cache(ctx);

    port = find_port(ctx, ctx->argv[1], ctx->argv[2], must_exist);
    if (port) {
        if (ctx->argc == 3) {
            struct vtep_ctl_pswitch *ps;

            ps = find_pswitch(ctx, ctx->argv[1], true);
            if (port->ps != ps) {
                vtep_ctl_fatal("physical switch %s does not have a port %s",
                               ctx->argv[1], ctx->argv[2]);
            }
        }

        del_port(ctx, port);
    }
}

static struct vtep_ctl_lswitch *
find_lswitch(struct vtep_ctl_context *ctx, const char *name, bool must_exist)
{
    struct vtep_ctl_lswitch *ls;

    ovs_assert(ctx->cache_valid);

    ls = shash_find_data(&ctx->lswitches, name);
    if (must_exist && !ls) {
        vtep_ctl_fatal("no logical switch named %s", name);
    }
    return ls;
}

static void
cmd_add_ls(struct vtep_ctl_context *ctx)
{
    const char *ls_name = ctx->argv[1];
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    struct vteprec_logical_switch *ls;

    vtep_ctl_context_populate_cache(ctx);
    if (find_lswitch(ctx, ls_name, false)) {
        if (!may_exist) {
            vtep_ctl_fatal("cannot create logical switch %s because it "
                           "already exists", ls_name);
        }
        return;
    }

    ls = vteprec_logical_switch_insert(ctx->txn);
    vteprec_logical_switch_set_name(ls, ls_name);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
del_lswitch(struct vtep_ctl_context *ctx, struct vtep_ctl_lswitch *ls)
{
    del_cached_lswitch(ctx, ls);
}

static void
cmd_del_ls(struct vtep_ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vtep_ctl_lswitch *ls;

    vtep_ctl_context_populate_cache(ctx);
    ls = find_lswitch(ctx, ctx->argv[1], must_exist);
    if (ls) {
        del_lswitch(ctx, ls);
    }
}

static void
cmd_list_ls(struct vtep_ctl_context *ctx)
{
    struct shash_node *node;
    struct svec lswitches;

    vtep_ctl_context_populate_cache(ctx);

    svec_init(&lswitches);
    SHASH_FOR_EACH (node, &ctx->lswitches) {
        struct vtep_ctl_lswitch *ls = node->data;

        svec_add(&lswitches, ls->name);
    }
    output_sorted(&lswitches, &ctx->output);
    svec_destroy(&lswitches);
}

static void
cmd_ls_exists(struct vtep_ctl_context *ctx)
{
    vtep_ctl_context_populate_cache(ctx);
    if (!find_lswitch(ctx, ctx->argv[1], false)) {
        vtep_ctl_exit(2);
    }
}

static void
cmd_list_bindings(struct vtep_ctl_context *ctx)
{
    const struct shash_node *node;
    struct vtep_ctl_port *port;
    struct svec bindings;

    vtep_ctl_context_populate_cache(ctx);
    port = find_port(ctx, ctx->argv[1], ctx->argv[2], true);

    svec_init(&bindings);
    SHASH_FOR_EACH (node, &port->bindings) {
        struct vtep_ctl_lswitch *lswitch = node->data;
        char *binding;
        
        binding = xasprintf("%04lld %s", strtoll(node->name, NULL, 0),
                            lswitch->name);
        svec_add_nocopy(&bindings, binding);
    }
    output_sorted(&bindings, &ctx->output);
    svec_destroy(&bindings);
}

static void
cmd_bind_ls(struct vtep_ctl_context *ctx)
{
    struct vtep_ctl_lswitch *ls;
    struct vtep_ctl_port *port;
    const char *vlan;

    vtep_ctl_context_populate_cache(ctx);

    port = find_port(ctx, ctx->argv[1], ctx->argv[2], true);
    vlan = ctx->argv[3];
    ls = find_lswitch(ctx, ctx->argv[4], true);

    add_ls_binding_to_cache(port, vlan, ls);
    commit_ls_bindings(port);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
cmd_unbind_ls(struct vtep_ctl_context *ctx)
{
    struct vtep_ctl_port *port;
    const char *vlan;

    vtep_ctl_context_populate_cache(ctx);

    port = find_port(ctx, ctx->argv[1], ctx->argv[2], true);
    vlan = ctx->argv[3];

    del_cached_ls_binding(port, vlan);
    commit_ls_bindings(port);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
add_ucast_entry(struct vtep_ctl_context *ctx, bool local)
{
    struct vtep_ctl_lswitch *ls;
    const char *mac;
    const char *encap;
    const char *dst_ip;
    struct vteprec_physical_locator *ploc_cfg;

    vtep_ctl_context_populate_cache(ctx);

    ls = find_lswitch(ctx, ctx->argv[1], true);
    mac = ctx->argv[2];

    if (ctx->argc == 4) {
        encap = "vxlan_over_ipv4";
        dst_ip = ctx->argv[3];
    } else {
        encap = ctx->argv[3];
        dst_ip = ctx->argv[4];
    }

    ploc_cfg = find_ploc(ctx, encap, dst_ip);
    if (!ploc_cfg) {
        ploc_cfg = vteprec_physical_locator_insert(ctx->txn);
        vteprec_physical_locator_set_dst_ip(ploc_cfg, dst_ip);
        vteprec_physical_locator_set_encapsulation_type(ploc_cfg, encap);

        add_ploc_to_cache(ctx, ploc_cfg);
    }

    if (local) {
        struct vteprec_ucast_macs_local *ucast_cfg;

        ucast_cfg = shash_find_data(&ls->ucast_local, mac);
        if (!ucast_cfg) {
            ucast_cfg = vteprec_ucast_macs_local_insert(ctx->txn);
            vteprec_ucast_macs_local_set_MAC(ucast_cfg, mac);
            vteprec_ucast_macs_local_set_logical_switch(ucast_cfg, ls->ls_cfg);
            shash_add(&ls->ucast_local, mac, ucast_cfg);
        }
        vteprec_ucast_macs_local_set_locator(ucast_cfg, ploc_cfg);
    } else {
        struct vteprec_ucast_macs_remote *ucast_cfg;

        ucast_cfg = shash_find_data(&ls->ucast_remote, mac);
        if (!ucast_cfg) {
            ucast_cfg = vteprec_ucast_macs_remote_insert(ctx->txn);
            vteprec_ucast_macs_remote_set_MAC(ucast_cfg, mac);
            vteprec_ucast_macs_remote_set_logical_switch(ucast_cfg, ls->ls_cfg);
            shash_add(&ls->ucast_remote, mac, ucast_cfg);
        }
        vteprec_ucast_macs_remote_set_locator(ucast_cfg, ploc_cfg);
    }

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
cmd_add_ucast_local(struct vtep_ctl_context *ctx)
{
    add_ucast_entry(ctx, true);
}

static void
cmd_add_ucast_remote(struct vtep_ctl_context *ctx)
{
    add_ucast_entry(ctx, false);
}

static void
del_ucast_entry(struct vtep_ctl_context *ctx, bool local)
{
    struct vtep_ctl_lswitch *ls;
    struct shash *ucast_shash;
    struct shash_node *node;

    vtep_ctl_context_populate_cache(ctx);

    ls = find_lswitch(ctx, ctx->argv[1], true);
    ucast_shash = local ? &ls->ucast_local : &ls->ucast_remote;

    node = shash_find(ucast_shash, ctx->argv[2]);
    if (!node) {
        return;
    }

    if (local) {
        struct vteprec_ucast_macs_local *ucast_cfg = node->data;
        vteprec_ucast_macs_local_delete(ucast_cfg);
    } else {
        struct vteprec_ucast_macs_remote *ucast_cfg = node->data;
        vteprec_ucast_macs_remote_delete(ucast_cfg);
    }
    shash_delete(ucast_shash, node);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
cmd_del_ucast_local(struct vtep_ctl_context *ctx)
{
    del_ucast_entry(ctx, true);
}

static void
cmd_del_ucast_remote(struct vtep_ctl_context *ctx)
{
    del_ucast_entry(ctx, false);
}

static void
commit_mcast_entries(struct vtep_ctl_mcast_mac *mcast_mac)
{
    struct vtep_ctl_ploc *ploc;
    struct vteprec_physical_locator **locators = NULL;
    size_t n_locators;
    int i;

    n_locators = list_size(&mcast_mac->locators);
    ovs_assert(n_locators);

    locators = xmalloc(n_locators * sizeof *locators);

    i = 0;
    LIST_FOR_EACH (ploc, locators_node, &mcast_mac->locators) {
        locators[i] = (struct vteprec_physical_locator *)ploc->ploc_cfg;
        i++;
    }

    vteprec_physical_locator_set_set_locators(mcast_mac->ploc_set_cfg,
                                              locators,
                                              n_locators);

    free(locators);
}

static void
add_mcast_entry(struct vtep_ctl_context *ctx,
                struct vtep_ctl_lswitch *ls, const char *mac,
                const char *encap, const char *dst_ip, bool local)
{
    struct shash *mcast_shash;
    struct vtep_ctl_mcast_mac *mcast_mac;
    struct vteprec_physical_locator *ploc_cfg;
    struct vteprec_physical_locator_set *ploc_set_cfg;

    mcast_shash = local ? &ls->mcast_local : &ls->mcast_remote;

    /* Physical locator sets are immutable, so allocate a new one. */
    ploc_set_cfg = vteprec_physical_locator_set_insert(ctx->txn);

    mcast_mac = shash_find_data(mcast_shash, mac);
    if (!mcast_mac) {
        mcast_mac = add_mcast_mac_to_cache(ctx, ls, mac, ploc_set_cfg, local);

        if (local) {
            mcast_mac->local_cfg = vteprec_mcast_macs_local_insert(ctx->txn);
            vteprec_mcast_macs_local_set_MAC(mcast_mac->local_cfg, mac);
            vteprec_mcast_macs_local_set_locator_set(mcast_mac->local_cfg,
                                                     ploc_set_cfg);
            vteprec_mcast_macs_local_set_logical_switch(mcast_mac->local_cfg,
                                                        ls->ls_cfg);
            mcast_mac->remote_cfg = NULL;
        } else {
            mcast_mac->remote_cfg = vteprec_mcast_macs_remote_insert(ctx->txn);
            vteprec_mcast_macs_remote_set_MAC(mcast_mac->remote_cfg, mac);
            vteprec_mcast_macs_remote_set_locator_set(mcast_mac->remote_cfg,
                                                      ploc_set_cfg);
            vteprec_mcast_macs_remote_set_logical_switch(mcast_mac->remote_cfg,
                                                         ls->ls_cfg);
            mcast_mac->local_cfg = NULL;
        }
    } else {
        mcast_mac->ploc_set_cfg = ploc_set_cfg;
        if (local) {
            vteprec_mcast_macs_local_set_locator_set(mcast_mac->local_cfg,
                                                     ploc_set_cfg);
        } else {
            vteprec_mcast_macs_remote_set_locator_set(mcast_mac->remote_cfg,
                                                      ploc_set_cfg);
        }
    }

    ploc_cfg = find_ploc(ctx, encap, dst_ip);
    if (!ploc_cfg) {
        ploc_cfg = vteprec_physical_locator_insert(ctx->txn);
        vteprec_physical_locator_set_dst_ip(ploc_cfg, dst_ip);
        vteprec_physical_locator_set_encapsulation_type(ploc_cfg, encap);

        add_ploc_to_cache(ctx, ploc_cfg);
    }

    add_ploc_to_mcast_mac(mcast_mac, ploc_cfg);
    commit_mcast_entries(mcast_mac);
}

static void
del_mcast_entry(struct vtep_ctl_context *ctx,
                struct vtep_ctl_lswitch *ls, const char *mac,
                const char *encap, const char *dst_ip, bool local)
{
    struct vtep_ctl_mcast_mac *mcast_mac;
    struct shash *mcast_shash;
    struct vteprec_physical_locator *ploc_cfg;
    struct vteprec_physical_locator_set *ploc_set_cfg;

    mcast_shash = local ? &ls->mcast_local : &ls->mcast_remote;

    mcast_mac = shash_find_data(mcast_shash, mac);
    if (!mcast_mac) {
        return;
    }

    ploc_cfg = find_ploc(ctx, encap, dst_ip);
    if (!ploc_cfg) {
        /* Couldn't find the physical locator, so just ignore. */
        return;
    }

    /* Physical locator sets are immutable, so allocate a new one. */
    ploc_set_cfg = vteprec_physical_locator_set_insert(ctx->txn);
    mcast_mac->ploc_set_cfg = ploc_set_cfg;

    del_ploc_from_mcast_mac(mcast_mac, ploc_cfg);
    if (list_is_empty(&mcast_mac->locators)) {
        struct shash_node *node = shash_find(mcast_shash, mac);

        vteprec_physical_locator_set_delete(ploc_set_cfg);

        if (local) {
            vteprec_mcast_macs_local_delete(mcast_mac->local_cfg);
        } else {
            vteprec_mcast_macs_remote_delete(mcast_mac->remote_cfg);
        }
        
        free(node->data);
        shash_delete(mcast_shash, node);
    } else {
        if (local) {
            vteprec_mcast_macs_local_set_locator_set(mcast_mac->local_cfg,
                                                     ploc_set_cfg);
        } else {
            vteprec_mcast_macs_remote_set_locator_set(mcast_mac->remote_cfg,
                                                      ploc_set_cfg);
        }
        commit_mcast_entries(mcast_mac);
    }
}

static void
add_del_mcast_entry(struct vtep_ctl_context *ctx, bool add, bool local)
{
    struct vtep_ctl_lswitch *ls;
    const char *mac;
    const char *encap;
    const char *dst_ip;

    vtep_ctl_context_populate_cache(ctx);

    ls = find_lswitch(ctx, ctx->argv[1], true);
    mac = ctx->argv[2];

    if (ctx->argc == 4) {
        encap = "vxlan_over_ipv4";
        dst_ip = ctx->argv[3];
    } else {
        encap = ctx->argv[3];
        dst_ip = ctx->argv[4];
    }

    if (add) {
        add_mcast_entry(ctx, ls, mac, encap, dst_ip, local);
    } else {
        del_mcast_entry(ctx, ls, mac, encap, dst_ip, local);
    }

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
cmd_add_mcast_local(struct vtep_ctl_context *ctx)
{
    add_del_mcast_entry(ctx, true, true);
}

static void
cmd_add_mcast_remote(struct vtep_ctl_context *ctx)
{
    add_del_mcast_entry(ctx, true, false);
}

static void
cmd_del_mcast_local(struct vtep_ctl_context *ctx)
{
    add_del_mcast_entry(ctx, false, true);
}

static void
cmd_del_mcast_remote(struct vtep_ctl_context *ctx)
{
    add_del_mcast_entry(ctx, false, false);
}

static void
clear_macs(struct vtep_ctl_context *ctx, bool local)
{
    struct vtep_ctl_lswitch *ls;
    const struct shash_node *node;
    struct shash *ucast_shash;
    struct shash *mcast_shash;

    vtep_ctl_context_populate_cache(ctx);
    ls = find_lswitch(ctx, ctx->argv[1], true);

    ucast_shash = local ? &ls->ucast_local : &ls->ucast_remote;
    mcast_shash = local ? &ls->mcast_local : &ls->mcast_remote;

    SHASH_FOR_EACH (node, ucast_shash) {
        if (local) {
            struct vteprec_ucast_macs_local *ucast_cfg = node->data;
            vteprec_ucast_macs_local_delete(ucast_cfg);
        } else {
            struct vteprec_ucast_macs_remote *ucast_cfg = node->data;
            vteprec_ucast_macs_remote_delete(ucast_cfg);
        }
    }

    SHASH_FOR_EACH (node, mcast_shash) {
        struct vtep_ctl_mcast_mac *mcast_mac = node->data;
        if (local) {
            vteprec_mcast_macs_local_delete(mcast_mac->local_cfg);
        } else {
            vteprec_mcast_macs_remote_delete(mcast_mac->remote_cfg);
        }
    }

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
cmd_clear_local_macs(struct vtep_ctl_context *ctx)
{
    clear_macs(ctx, true);
}

static void
cmd_clear_remote_macs(struct vtep_ctl_context *ctx)
{
    clear_macs(ctx, false);
}

static void
list_macs(struct vtep_ctl_context *ctx, bool local)
{
    struct vtep_ctl_lswitch *ls;
    const struct shash_node *node;
    struct shash *ucast_shash;
    struct svec ucast_macs;
    struct shash *mcast_shash;
    struct svec mcast_macs;

    vtep_ctl_context_populate_cache(ctx);
    ls = find_lswitch(ctx, ctx->argv[1], true);

    ucast_shash = local ? &ls->ucast_local : &ls->ucast_remote;
    mcast_shash = local ? &ls->mcast_local : &ls->mcast_remote;

    svec_init(&ucast_macs);
    SHASH_FOR_EACH (node, ucast_shash) {
        struct vteprec_ucast_macs_local *ucast_local = node->data;
        struct vteprec_ucast_macs_remote *ucast_remote = node->data;
        struct vteprec_physical_locator *ploc_cfg;
        char *entry;

        ploc_cfg = local ? ucast_local->locator : ucast_remote->locator;

        entry = xasprintf("  %s -> %s/%s", node->name,
                          ploc_cfg->encapsulation_type, ploc_cfg->dst_ip);
        svec_add_nocopy(&ucast_macs, entry);
    }
    ds_put_format(&ctx->output, "ucast-mac-%s\n", local ? "local" : "remote");
    output_sorted(&ucast_macs, &ctx->output);
    ds_put_char(&ctx->output, '\n');
    svec_destroy(&ucast_macs);

    svec_init(&mcast_macs);
    SHASH_FOR_EACH (node, mcast_shash) {
        struct vtep_ctl_mcast_mac *mcast_mac = node->data;
        struct vtep_ctl_ploc *ploc;
        char *entry;

        LIST_FOR_EACH (ploc, locators_node, &mcast_mac->locators) {
            entry = xasprintf("  %s -> %s/%s", node->name,
                              ploc->ploc_cfg->encapsulation_type,
                              ploc->ploc_cfg->dst_ip);
            svec_add_nocopy(&mcast_macs, entry);
        }
    }
    ds_put_format(&ctx->output, "mcast-mac-%s\n", local ? "local" : "remote");
    output_sorted(&mcast_macs, &ctx->output);
    ds_put_char(&ctx->output, '\n');
    svec_destroy(&mcast_macs);
}

static void
cmd_list_local_macs(struct vtep_ctl_context *ctx)
{
    list_macs(ctx, true);
}

static void
cmd_list_remote_macs(struct vtep_ctl_context *ctx)
{
    list_macs(ctx, false);
}

static void
verify_managers(const struct vteprec_global *vtep_global)
{
    size_t i;

    vteprec_global_verify_managers(vtep_global);

    for (i = 0; i < vtep_global->n_managers; ++i) {
        const struct vteprec_manager *mgr = vtep_global->managers[i];

        vteprec_manager_verify_target(mgr);
    }
}

static void
pre_manager(struct vtep_ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &vteprec_global_col_managers);
    ovsdb_idl_add_column(ctx->idl, &vteprec_manager_col_target);
}

static void
cmd_get_manager(struct vtep_ctl_context *ctx)
{
    const struct vteprec_global *vtep_global = ctx->vtep_global;
    struct svec targets;
    size_t i;

    verify_managers(vtep_global);

    /* Print the targets in sorted order for reproducibility. */
    svec_init(&targets);

    for (i = 0; i < vtep_global->n_managers; i++) {
        svec_add(&targets, vtep_global->managers[i]->target);
    }

    svec_sort_unique(&targets);
    for (i = 0; i < targets.n; i++) {
        ds_put_format(&ctx->output, "%s\n", targets.names[i]);
    }
    svec_destroy(&targets);
}

static void
delete_managers(const struct vtep_ctl_context *ctx)
{
    const struct vteprec_global *vtep_global = ctx->vtep_global;
    size_t i;

    /* Delete Manager rows pointed to by 'managers' column. */
    for (i = 0; i < vtep_global->n_managers; i++) {
        vteprec_manager_delete(vtep_global->managers[i]);
    }

    /* Delete 'Manager' row refs in 'managers' column. */
    vteprec_global_set_managers(vtep_global, NULL, 0);
}

static void
cmd_del_manager(struct vtep_ctl_context *ctx)
{
    const struct vteprec_global *vtep_global = ctx->vtep_global;

    verify_managers(vtep_global);
    delete_managers(ctx);
}

static void
insert_managers(struct vtep_ctl_context *ctx, char *targets[], size_t n)
{
    struct vteprec_manager **managers;
    size_t i;

    /* Insert each manager in a new row in Manager table. */
    managers = xmalloc(n * sizeof *managers);
    for (i = 0; i < n; i++) {
        if (stream_verify_name(targets[i]) && pstream_verify_name(targets[i])) {
            VLOG_WARN("target type \"%s\" is possibly erroneous", targets[i]);
        }
        managers[i] = vteprec_manager_insert(ctx->txn);
        vteprec_manager_set_target(managers[i], targets[i]);
    }

    /* Store uuids of new Manager rows in 'managers' column. */
    vteprec_global_set_managers(ctx->vtep_global, managers, n);
    free(managers);
}

static void
cmd_set_manager(struct vtep_ctl_context *ctx)
{
    const size_t n = ctx->argc - 1;

    verify_managers(ctx->vtep_global);
    delete_managers(ctx);
    insert_managers(ctx, &ctx->argv[1], n);
}

/* Parameter commands. */

struct vtep_ctl_row_id {
    const struct ovsdb_idl_table_class *table;
    const struct ovsdb_idl_column *name_column;
    const struct ovsdb_idl_column *uuid_column;
};

struct vtep_ctl_table_class {
    struct ovsdb_idl_table_class *class;
    struct vtep_ctl_row_id row_ids[2];
};

static const struct vtep_ctl_table_class tables[] = {
    {&vteprec_table_global,
     {{&vteprec_table_global, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_logical_binding_stats,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_logical_switch,
     {{&vteprec_table_logical_switch, &vteprec_logical_switch_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_ucast_macs_local,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_ucast_macs_remote,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_mcast_macs_local,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_mcast_macs_remote,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_manager,
     {{&vteprec_table_manager, &vteprec_manager_col_target, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_physical_locator,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_physical_locator_set,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_physical_port,
     {{&vteprec_table_physical_port, &vteprec_physical_port_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&vteprec_table_physical_switch,
     {{&vteprec_table_physical_switch, &vteprec_physical_switch_col_name, NULL},
      {NULL, NULL, NULL}}},

    {NULL, {{NULL, NULL, NULL}, {NULL, NULL, NULL}}}
};

static void
die_if_error(char *error)
{
    if (error) {
        vtep_ctl_fatal("%s", error);
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

static const struct vtep_ctl_table_class *
get_table(const char *table_name)
{
    const struct vtep_ctl_table_class *table;
    const struct vtep_ctl_table_class *best_match = NULL;
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
        vtep_ctl_fatal("multiple table names match \"%s\"", table_name);
    } else {
        vtep_ctl_fatal("unknown table \"%s\"", table_name);
    }
}

static const struct vtep_ctl_table_class *
pre_get_table(struct vtep_ctl_context *ctx, const char *table_name)
{
    const struct vtep_ctl_table_class *table_class;
    int i;

    table_class = get_table(table_name);
    ovsdb_idl_add_table(ctx->idl, table_class->class);

    for (i = 0; i < ARRAY_SIZE(table_class->row_ids); i++) {
        const struct vtep_ctl_row_id *id = &table_class->row_ids[i];
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
get_row_by_id(struct vtep_ctl_context *ctx, const struct vtep_ctl_table_class *table,
              const struct vtep_ctl_row_id *id, const char *record_id)
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
                    vtep_ctl_fatal("multiple rows in %s match \"%s\"",
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
get_row (struct vtep_ctl_context *ctx,
         const struct vtep_ctl_table_class *table, const char *record_id)
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
    return row;
}

static const struct ovsdb_idl_row *
must_get_row(struct vtep_ctl_context *ctx,
             const struct vtep_ctl_table_class *table, const char *record_id)
{
    const struct ovsdb_idl_row *row = get_row(ctx, table, record_id);
    if (!row) {
        vtep_ctl_fatal("no row \"%s\" in table %s",
                    record_id, table->class->name);
    }
    return row;
}

static char *
get_column(const struct vtep_ctl_table_class *table, const char *column_name,
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
        vtep_ctl_fatal("row id \"%s\" does not begin with \"@\"", id);
    }

    if (newp) {
        *newp = ovsdb_symbol_table_get(symtab, id) == NULL;
    }

    symbol = ovsdb_symbol_table_insert(symtab, id);
    if (symbol->created) {
        vtep_ctl_fatal("row id \"%s\" may only be specified on one --id option",
                    id);
    }
    symbol->created = true;
    return symbol;
}

static void
pre_get_column(struct vtep_ctl_context *ctx,
               const struct vtep_ctl_table_class *table, const char *column_name,
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
                       const struct vtep_ctl_table_class *table,
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
pre_parse_column_key_value(struct vtep_ctl_context *ctx,
                           const char *arg,
                           const struct vtep_ctl_table_class *table)
{
    const struct ovsdb_idl_column *column;
    const char *p;
    char *column_name;

    p = arg;
    die_if_error(ovsdb_token_parse(&p, &column_name));
    if (column_name[0] == '\0') {
        vtep_ctl_fatal("%s: missing column name", arg);
    }

    pre_get_column(ctx, table, column_name, &column);
    free(column_name);

    return column;
}

static void
check_mutable(const struct vtep_ctl_table_class *table,
              const struct ovsdb_idl_column *column)
{
    if (!column->mutable) {
        vtep_ctl_fatal("cannot modify read-only column %s in table %s",
                    column->name, table->class->name);
    }
}

static void
pre_cmd_get(struct vtep_ctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;
    int i;

    /* Using "get" without --id or a column name could possibly make sense.
     * Maybe, for example, a vtep-ctl run wants to assert that a row exists.
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
cmd_get(struct vtep_ctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    bool if_exists = shash_find(&ctx->options, "--if-exists");
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct vtep_ctl_table_class *table;
    const struct ovsdb_idl_row *row;
    struct ds *out = &ctx->output;
    int i;

    table = get_table(table_name);
    row = must_get_row(ctx, table, record_id);
    if (id) {
        struct ovsdb_symbol *symbol;
        bool new;

        symbol = create_symbol(ctx->symtab, id, &new);
        if (!new) {
            vtep_ctl_fatal("row id \"%s\" specified on \"get\" command was used "
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
                vtep_ctl_fatal("cannot specify key to get for non-map column %s",
                            column->name);
            }

            die_if_error(ovsdb_atom_from_string(&key,
                                                &column->type.key,
                                                key_string, ctx->symtab));

            idx = ovsdb_datum_find_key(datum, &key,
                                       column->type.key.type);
            if (idx == UINT_MAX) {
                if (!if_exists) {
                    vtep_ctl_fatal("no key \"%s\" in %s record \"%s\" column %s",
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
                   const struct vtep_ctl_table_class *table,
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
            vtep_ctl_fatal("must specify at least one column name");
        }
    }
    *columnsp = columns;
    *n_columnsp = n_columns;
}


static void
pre_list_columns(struct vtep_ctl_context *ctx,
                 const struct vtep_ctl_table_class *table,
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
pre_cmd_list(struct vtep_ctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;

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
cmd_list(struct vtep_ctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const struct ovsdb_idl_column **columns;
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;
    struct table *out;
    size_t n_columns;
    int i;

    table = get_table(table_name);
    parse_column_names(column_names, table, &columns, &n_columns);
    out = ctx->table = list_make_table(columns, n_columns);
    if (ctx->argc > 2) {
        for (i = 2; i < ctx->argc; i++) {
            list_record(must_get_row(ctx, table, ctx->argv[i]),
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
pre_cmd_find(struct vtep_ctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;
    int i;

    table = pre_get_table(ctx, table_name);
    pre_list_columns(ctx, table, column_names);
    for (i = 2; i < ctx->argc; i++) {
        pre_parse_column_key_value(ctx, ctx->argv[i], table);
    }
}

static void
cmd_find(struct vtep_ctl_context *ctx)
{
    const char *column_names = shash_find_data(&ctx->options, "--columns");
    const struct ovsdb_idl_column **columns;
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;
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
pre_cmd_set(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;
    int i;

    table = pre_get_table(ctx, table_name);
    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;

        column = pre_parse_column_key_value(ctx, ctx->argv[i], table);
        check_mutable(table, column);
    }
}

static void
set_column(const struct vtep_ctl_table_class *table,
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
        vtep_ctl_fatal("%s: missing value", arg);
    }

    if (key_string) {
        union ovsdb_atom key, value;
        struct ovsdb_datum datum;

        if (column->type.value.type == OVSDB_TYPE_VOID) {
            vtep_ctl_fatal("cannot specify key to set for non-map column %s",
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
cmd_set(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct vtep_ctl_table_class *table;
    const struct ovsdb_idl_row *row;
    int i;

    table = get_table(table_name);
    row = must_get_row(ctx, table, record_id);
    for (i = 3; i < ctx->argc; i++) {
        set_column(table, row, ctx->argv[i], ctx->symtab);
    }
}

static void
pre_cmd_add(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *column_name = ctx->argv[3];
    const struct vtep_ctl_table_class *table;
    const struct ovsdb_idl_column *column;

    table = pre_get_table(ctx, table_name);
    pre_get_column(ctx, table, column_name, &column);
    check_mutable(table, column);
}

static void
cmd_add(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const char *column_name = ctx->argv[3];
    const struct vtep_ctl_table_class *table;
    const struct ovsdb_idl_column *column;
    const struct ovsdb_idl_row *row;
    const struct ovsdb_type *type;
    struct ovsdb_datum old;
    int i;

    table = get_table(table_name);
    row = must_get_row(ctx, table, record_id);
    die_if_error(get_column(table, column_name, &column));

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
        vtep_ctl_fatal("\"add\" operation would put %u %s in column %s of "
                    "table %s but the maximum number is %u",
                    old.n,
                    type->value.type == OVSDB_TYPE_VOID ? "values" : "pairs",
                    column->name, table->class->name, type->n_max);
    }
    ovsdb_idl_txn_verify(row, column);
    ovsdb_idl_txn_write(row, column, &old);
}

static void
pre_cmd_remove(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *column_name = ctx->argv[3];
    const struct vtep_ctl_table_class *table;
    const struct ovsdb_idl_column *column;

    table = pre_get_table(ctx, table_name);
    pre_get_column(ctx, table, column_name, &column);
    check_mutable(table, column);
}

static void
cmd_remove(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const char *column_name = ctx->argv[3];
    const struct vtep_ctl_table_class *table;
    const struct ovsdb_idl_column *column;
    const struct ovsdb_idl_row *row;
    const struct ovsdb_type *type;
    struct ovsdb_datum old;
    int i;

    table = get_table(table_name);
    row = must_get_row(ctx, table, record_id);
    die_if_error(get_column(table, column_name, &column));

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
        if (error && ovsdb_type_is_map(&rm_type)) {
            free(error);
            rm_type.value.type = OVSDB_TYPE_VOID;
            die_if_error(ovsdb_datum_from_string(&rm, &rm_type,
                                                 ctx->argv[i], ctx->symtab));
        }
        ovsdb_datum_subtract(&old, type, &rm, &rm_type);
        ovsdb_datum_destroy(&rm, &rm_type);
    }
    if (old.n < type->n_min) {
        vtep_ctl_fatal("\"remove\" operation would put %u %s in column %s of "
                    "table %s but the minimum number is %u",
                    old.n,
                    type->value.type == OVSDB_TYPE_VOID ? "values" : "pairs",
                    column->name, table->class->name, type->n_min);
    }
    ovsdb_idl_txn_verify(row, column);
    ovsdb_idl_txn_write(row, column, &old);
}

static void
pre_cmd_clear(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;
    int i;

    table = pre_get_table(ctx, table_name);
    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;

        pre_get_column(ctx, table, ctx->argv[i], &column);
        check_mutable(table, column);
    }
}

static void
cmd_clear(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct vtep_ctl_table_class *table;
    const struct ovsdb_idl_row *row;
    int i;

    table = get_table(table_name);
    row = must_get_row(ctx, table, record_id);
    for (i = 3; i < ctx->argc; i++) {
        const struct ovsdb_idl_column *column;
        const struct ovsdb_type *type;
        struct ovsdb_datum datum;

        die_if_error(get_column(table, ctx->argv[i], &column));

        type = &column->type;
        if (type->n_min > 0) {
            vtep_ctl_fatal("\"clear\" operation cannot be applied to column %s "
                        "of table %s, which is not allowed to be empty",
                        column->name, table->class->name);
        }

        ovsdb_datum_init_empty(&datum);
        ovsdb_idl_txn_write(row, column, &datum);
    }
}

static void
pre_create(struct vtep_ctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;

    table = get_table(table_name);
    if (!id && !table->class->is_root) {
        VLOG_WARN("applying \"create\" command to table %s without --id "
                  "option will have no effect", table->class->name);
    }
}

static void
cmd_create(struct vtep_ctl_context *ctx)
{
    const char *id = shash_find_data(&ctx->options, "--id");
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table = get_table(table_name);
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
 * are supposed to be independent of the actual structure of the VTEP
 * configuration. */
static void
post_create(struct vtep_ctl_context *ctx)
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
pre_cmd_destroy(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];

    pre_get_table(ctx, table_name);
}

static void
cmd_destroy(struct vtep_ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    bool delete_all = shash_find(&ctx->options, "--all");
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;
    int i;

    table = get_table(table_name);

    if (delete_all && ctx->argc > 2) {
        vtep_ctl_fatal("--all and records argument should not be specified together");
    }

    if (delete_all && !must_exist) {
        vtep_ctl_fatal("--all and --if-exists should not be specified together");
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

            row = (must_exist ? must_get_row : get_row)(ctx, table, ctx->argv[i]);
            if (row) {
                ovsdb_idl_txn_delete(row);
            }
        }
    }
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
is_condition_satisfied(const struct vtep_ctl_table_class *table,
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
        vtep_ctl_fatal("%s: missing value", arg);
    }

    type = column->type;
    type.n_max = UINT_MAX;

    have_datum = ovsdb_idl_read(row, column);
    if (key_string) {
        union ovsdb_atom want_key;
        struct ovsdb_datum b;
        unsigned int idx;

        if (column->type.value.type == OVSDB_TYPE_VOID) {
            vtep_ctl_fatal("cannot specify key to check for non-map column %s",
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
pre_cmd_wait_until(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const struct vtep_ctl_table_class *table;
    int i;

    table = pre_get_table(ctx, table_name);

    for (i = 3; i < ctx->argc; i++) {
        pre_parse_column_key_value(ctx, ctx->argv[i], table);
    }
}

static void
cmd_wait_until(struct vtep_ctl_context *ctx)
{
    const char *table_name = ctx->argv[1];
    const char *record_id = ctx->argv[2];
    const struct vtep_ctl_table_class *table;
    const struct ovsdb_idl_row *row;
    int i;

    table = get_table(table_name);

    row = get_row(ctx, table, record_id);
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
 * vtep_ctl_context_init(), for processing 'command'. */
static void
vtep_ctl_context_init_command(struct vtep_ctl_context *ctx,
                           struct vtep_ctl_command *command)
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
 * If 'command' is nonnull, calls vtep_ctl_context_init_command() to prepare for
 * that particular command. */
static void
vtep_ctl_context_init(struct vtep_ctl_context *ctx,
                      struct vtep_ctl_command *command,
                      struct ovsdb_idl *idl, struct ovsdb_idl_txn *txn,
                      const struct vteprec_global *vtep_global,
                      struct ovsdb_symbol_table *symtab)
{
    if (command) {
        vtep_ctl_context_init_command(ctx, command);
    }
    ctx->idl = idl;
    ctx->txn = txn;
    ctx->vtep_global = vtep_global;
    ctx->symtab = symtab;
    ctx->cache_valid = false;
}

/* Completes processing of 'command' within 'ctx'. */
static void
vtep_ctl_context_done_command(struct vtep_ctl_context *ctx,
                           struct vtep_ctl_command *command)
{
    ds_swap(&ctx->output, &command->output);
    command->table = ctx->table;
}

/* Finishes up with 'ctx'.
 *
 * If command is nonnull, first calls vtep_ctl_context_done_command() to complete
 * processing that command within 'ctx'. */
static void
vtep_ctl_context_done(struct vtep_ctl_context *ctx, struct vtep_ctl_command *command)
{
    if (command) {
        vtep_ctl_context_done_command(ctx, command);
    }
}

static void
run_prerequisites(struct vtep_ctl_command *commands, size_t n_commands,
                  struct ovsdb_idl *idl)
{
    struct vtep_ctl_command *c;

    ovsdb_idl_add_table(idl, &vteprec_table_global);
    for (c = commands; c < &commands[n_commands]; c++) {
        if (c->syntax->prerequisites) {
            struct vtep_ctl_context ctx;

            ds_init(&c->output);
            c->table = NULL;

            vtep_ctl_context_init(&ctx, c, idl, NULL, NULL, NULL);
            (c->syntax->prerequisites)(&ctx);
            vtep_ctl_context_done(&ctx, c);

            ovs_assert(!c->output.string);
            ovs_assert(!c->table);
        }
    }
}

static void
do_vtep_ctl(const char *args, struct vtep_ctl_command *commands,
            size_t n_commands, struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;
    const struct vteprec_global *vtep_global;
    enum ovsdb_idl_txn_status status;
    struct ovsdb_symbol_table *symtab;
    struct vtep_ctl_context ctx;
    struct vtep_ctl_command *c;
    struct shash_node *node;
    char *error = NULL;

    txn = the_idl_txn = ovsdb_idl_txn_create(idl);
    if (dry_run) {
        ovsdb_idl_txn_set_dry_run(txn);
    }

    ovsdb_idl_txn_add_comment(txn, "vtep-ctl: %s", args);

    vtep_global = vteprec_global_first(idl);
    if (!vtep_global) {
        /* XXX add verification that table is empty */
        vtep_global = vteprec_global_insert(txn);
    }

    symtab = ovsdb_symbol_table_create();
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_init(&c->output);
        c->table = NULL;
    }
    vtep_ctl_context_init(&ctx, NULL, idl, txn, vtep_global, symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        vtep_ctl_context_init_command(&ctx, c);
        if (c->syntax->run) {
            (c->syntax->run)(&ctx);
        }
        vtep_ctl_context_done_command(&ctx, c);

        if (ctx.try_again) {
            vtep_ctl_context_done(&ctx, NULL);
            goto try_again;
        }
    }
    vtep_ctl_context_done(&ctx, NULL);

    SHASH_FOR_EACH (node, &symtab->sh) {
        struct ovsdb_symbol *symbol = node->data;
        if (!symbol->created) {
            vtep_ctl_fatal("row id \"%s\" is referenced but never created "
                           "(e.g. with \"-- --id=%s create ...\")",
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
    if (status == TXN_UNCHANGED || status == TXN_SUCCESS) {
        for (c = commands; c < &commands[n_commands]; c++) {
            if (c->syntax->postprocess) {
                struct vtep_ctl_context ctx;

                vtep_ctl_context_init(&ctx, c, idl, txn, vtep_global, symtab);
                (c->syntax->postprocess)(&ctx);
                vtep_ctl_context_done(&ctx, c);
            }
        }
    }
    error = xstrdup(ovsdb_idl_txn_get_error(txn));
    ovsdb_idl_txn_destroy(txn);
    txn = the_idl_txn = NULL;

    switch (status) {
    case TXN_UNCOMMITTED:
    case TXN_INCOMPLETE:
        OVS_NOT_REACHED();

    case TXN_ABORTED:
        /* Should not happen--we never call ovsdb_idl_txn_abort(). */
        vtep_ctl_fatal("transaction aborted");

    case TXN_UNCHANGED:
    case TXN_SUCCESS:
        break;

    case TXN_TRY_AGAIN:
        goto try_again;

    case TXN_ERROR:
        vtep_ctl_fatal("transaction error: %s", error);

    case TXN_NOT_LOCKED:
        /* Should not happen--we never call ovsdb_idl_set_lock(). */
        vtep_ctl_fatal("database not locked");

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

    ovsdb_idl_destroy(idl);

    exit(EXIT_SUCCESS);

try_again:
    /* Our transaction needs to be rerun, or a prerequisite was not met.  Free
     * resources and return so that the caller can try again. */
    if (txn) {
        ovsdb_idl_txn_abort(txn);
        ovsdb_idl_txn_destroy(txn);
    }
    ovsdb_symbol_table_destroy(symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);
    }
    free(error);
}

static const struct vtep_ctl_command_syntax all_commands[] = {
    /* Physical Switch commands. */
    {"add-ps", 1, 1, pre_get_info, cmd_add_ps, NULL, "--may-exist", RW},
    {"del-ps", 1, 1, pre_get_info, cmd_del_ps, NULL, "--if-exists", RW},
    {"list-ps", 0, 0, pre_get_info, cmd_list_ps, NULL, "", RO},
    {"ps-exists", 1, 1, pre_get_info, cmd_ps_exists, NULL, "", RO},

    /* Port commands. */
    {"list-ports", 1, 1, pre_get_info, cmd_list_ports, NULL, "", RO},
    {"add-port", 2, 2, pre_get_info, cmd_add_port, NULL, "--may-exist",
     RW},
    {"del-port", 2, 2, pre_get_info, cmd_del_port, NULL, "--if-exists", RW},

    /* Logical Switch commands. */
    {"add-ls", 1, 1, pre_get_info, cmd_add_ls, NULL, "--may-exist", RW},
    {"del-ls", 1, 1, pre_get_info, cmd_del_ls, NULL, "--if-exists", RW},
    {"list-ls", 0, 0, pre_get_info, cmd_list_ls, NULL, "", RO},
    {"ls-exists", 1, 1, pre_get_info, cmd_ls_exists, NULL, "", RO},
    {"list-bindings", 2, 2, pre_get_info, cmd_list_bindings, NULL, "", RO},
    {"bind-ls", 4, 4, pre_get_info, cmd_bind_ls, NULL, "", RO},
    {"unbind-ls", 3, 3, pre_get_info, cmd_unbind_ls, NULL, "", RO},

    /* MAC binding commands. */
    {"add-ucast-local", 3, 4, pre_get_info, cmd_add_ucast_local, NULL, "", RW},
    {"del-ucast-local", 2, 2, pre_get_info, cmd_del_ucast_local, NULL, "", RW},
    {"add-mcast-local", 3, 4, pre_get_info, cmd_add_mcast_local, NULL, "", RW},
    {"del-mcast-local", 3, 4, pre_get_info, cmd_del_mcast_local, NULL, "", RW},
    {"clear-local-macs", 1, 1, pre_get_info, cmd_clear_local_macs, NULL, "",
     RO},
    {"list-local-macs", 1, 1, pre_get_info, cmd_list_local_macs, NULL, "", RO},
    {"add-ucast-remote", 3, 4, pre_get_info, cmd_add_ucast_remote, NULL, "",
     RW},
    {"del-ucast-remote", 2, 2, pre_get_info, cmd_del_ucast_remote, NULL, "",
     RW},
    {"add-mcast-remote", 3, 4, pre_get_info, cmd_add_mcast_remote, NULL, "",
     RW},
    {"del-mcast-remote", 3, 4, pre_get_info, cmd_del_mcast_remote, NULL, "",
     RW},
    {"clear-remote-macs", 1, 1, pre_get_info, cmd_clear_remote_macs, NULL, "",
     RO},
    {"list-remote-macs", 1, 1, pre_get_info, cmd_list_remote_macs, NULL, "",
     RO},

    /* Manager commands. */
    {"get-manager", 0, 0, pre_manager, cmd_get_manager, NULL, "", RO},
    {"del-manager", 0, 0, pre_manager, cmd_del_manager, NULL, "", RW},
    {"set-manager", 1, INT_MAX, pre_manager, cmd_set_manager, NULL, "", RW},

    /* Database commands. */
    {"comment", 0, INT_MAX, NULL, NULL, NULL, "", RO},
    {"get", 2, INT_MAX, pre_cmd_get, cmd_get, NULL, "--if-exists,--id=", RO},
    {"list", 1, INT_MAX, pre_cmd_list, cmd_list, NULL, "--columns=", RO},
    {"find", 1, INT_MAX, pre_cmd_find, cmd_find, NULL, "--columns=", RO},
    {"set", 3, INT_MAX, pre_cmd_set, cmd_set, NULL, "", RW},
    {"add", 4, INT_MAX, pre_cmd_add, cmd_add, NULL, "", RW},
    {"remove", 4, INT_MAX, pre_cmd_remove, cmd_remove, NULL, "", RW},
    {"clear", 3, INT_MAX, pre_cmd_clear, cmd_clear, NULL, "", RW},
    {"create", 2, INT_MAX, pre_create, cmd_create, post_create, "--id=", RW},
    {"destroy", 1, INT_MAX, pre_cmd_destroy, cmd_destroy, NULL,
     "--if-exists,--all", RW},
    {"wait-until", 2, INT_MAX, pre_cmd_wait_until, cmd_wait_until, NULL, "",
     RO},

    {NULL, 0, 0, NULL, NULL, NULL, NULL, RO},
};

