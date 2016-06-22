/*
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

#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include "command-line.h"
#include "db-ctl-base.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "json.h"
#include "ovn/lib/ovn-nb-idl.h"
#include "packets.h"
#include "poll-loop.h"
#include "process.h"
#include "smap.h"
#include "stream.h"
#include "stream-ssl.h"
#include "svec.h"
#include "table.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(nbctl);

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

/* The IDL we're using and the current transaction, if any.
 * This is for use by nbctl_exit() only, to allow it to clean up.
 * Other code should use its context arguments. */
static struct ovsdb_idl *the_idl;
static struct ovsdb_idl_txn *the_idl_txn;
OVS_NO_RETURN static void nbctl_exit(int status);

static void nbctl_cmd_init(void);
OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[], struct shash *local_options);
static const char *nbctl_default_db(void);
static void run_prerequisites(struct ctl_command[], size_t n_commands,
                              struct ovsdb_idl *);
static bool do_nbctl(const char *args, struct ctl_command *, size_t n,
                     struct ovsdb_idl *);

int
main(int argc, char *argv[])
{
    struct ovsdb_idl *idl;
    struct ctl_command *commands;
    struct shash local_options;
    unsigned int seqno;
    size_t n_commands;
    char *args;

    set_program_name(argv[0]);
    fatal_ignore_sigpipe();
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels_from_string_assert("reconnect:warn");
    nbrec_init();

    nbctl_cmd_init();

    /* Log our arguments.  This is often valuable for debugging systems. */
    args = process_escape_args(argv);
    VLOG(ctl_might_write_to_db(argv) ? VLL_INFO : VLL_DBG,
         "Called as %s", args);

    /* Parse command line. */
    shash_init(&local_options);
    parse_options(argc, argv, &local_options);
    commands = ctl_parse_commands(argc - optind, argv + optind, &local_options,
                                  &n_commands);

    if (timeout) {
        time_alarm(timeout);
    }

    /* Initialize IDL. */
    idl = the_idl = ovsdb_idl_create(db, &nbrec_idl_class, true, false);
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
            ctl_fatal("%s: database connection failed (%s)",
                        db, ovs_retval_to_string(retval));
        }

        if (seqno != ovsdb_idl_get_seqno(idl)) {
            seqno = ovsdb_idl_get_seqno(idl);
            if (do_nbctl(args, commands, n_commands, idl)) {
                free(args);
                exit(EXIT_SUCCESS);
            }
        }

        if (seqno == ovsdb_idl_get_seqno(idl)) {
            ovsdb_idl_wait(idl);
            poll_block();
        }
    }
}

static const char *
nbctl_default_db(void)
{
    static char *def;
    if (!def) {
        def = getenv("OVN_NB_DB");
        if (!def) {
            def = xasprintf("unix:%s/ovnnb_db.sock", ovs_rundir());
        }
    }
    return def;
}

static void
parse_options(int argc, char *argv[], struct shash *local_options)
{
    enum {
        OPT_DB = UCHAR_MAX + 1,
        OPT_NO_SYSLOG,
        OPT_DRY_RUN,
        OPT_ONELINE,
        OPT_LOCAL,
        OPT_COMMANDS,
        OPT_OPTIONS,
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
        {"commands", no_argument, NULL, OPT_COMMANDS},
        {"options", no_argument, NULL, OPT_OPTIONS},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        TABLE_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    const int n_global_long_options = ARRAY_SIZE(global_long_options) - 1;
    char *tmp, *short_options;

    struct option *options;
    size_t allocated_options;
    size_t n_options;
    size_t i;

    tmp = ovs_cmdl_long_options_to_short_options(global_long_options);
    short_options = xasprintf("+%s", tmp);
    free(tmp);

    /* We want to parse both global and command-specific options here, but
     * getopt_long() isn't too convenient for the job.  We copy our global
     * options into a dynamic array, then append all of the command-specific
     * options. */
    options = xmemdup(global_long_options, sizeof global_long_options);
    allocated_options = ARRAY_SIZE(global_long_options);
    n_options = n_global_long_options;
    ctl_add_cmd_options(&options, &n_options, &allocated_options, OPT_LOCAL);
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
            vlog_set_levels(&this_module, VLF_SYSLOG, VLL_WARN);
            break;

        case OPT_DRY_RUN:
            dry_run = true;
            break;

        case OPT_LOCAL:
            if (shash_find(local_options, options[idx].name)) {
                ctl_fatal("'%s' option specified multiple times",
                            options[idx].name);
            }
            shash_add_nocopy(local_options,
                             xasprintf("--%s", options[idx].name),
                             optarg ? xstrdup(optarg) : NULL);
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case OPT_COMMANDS:
            ctl_print_commands();

        case OPT_OPTIONS:
            ctl_print_options(global_long_options);

        case 'V':
            ovs_print_version(0, 0);
            printf("DB Schema %s\n", nbrec_get_db_version());
            exit(EXIT_SUCCESS);

        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout < 0) {
                ctl_fatal("value %s on -t or --timeout is invalid", optarg);
            }
            break;

        VLOG_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)
        STREAM_SSL_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    if (!db) {
        db = nbctl_default_db();
    }

    for (i = n_global_long_options; options[i].name; i++) {
        free(CONST_CAST(char *, options[i].name));
    }
    free(options);
}

static void
usage(void)
{
    printf("\
%s: OVN northbound DB management utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
General commands:\n\
  show                      print overview of database contents\n\
  show SWITCH               print overview of database contents for SWITCH\n\
  show ROUTER               print overview of database contents for ROUTER\n\
\n\
Logical switch commands:\n\
  ls-add [LSWITCH]     create a logical switch named LSWITCH\n\
  ls-del LSWITCH       delete LSWITCH and all its ports\n\
  ls-list              print the names of all logical switches\n\
\n\
Logical port-chain commands:\n\
  lport-chain-add LSWITCH [LPORT-CHAIN]     create a logical port-chain named LPORT-CHAIN\n\
  lport-chain-del LPORT-CHAIN               delete LPORT-CHAIN but not FLOW-CLASSIFIER\n \
  lport-chain-list LSWITCH                  print the names of all logical port-chains on LSWITCH\n\
\n\
Logical port-pair-groups commands:\n\
  lport-pair-group-add LPORT-CHAIN LPORT-PAIR-GROUP-NAME\n\
                           create a logical port-pair-group \n\
  lport-pair-group-del LPORT-PAIR-GROUP-NAME    delete a port-pair-group, does not delete port-pairs\n\
                                      or flow-classifier\n\
  lport-pair-group-list LPORT-CHAIN   print the names of all logical port-pair-groups\n\
  lport-pair-group-add-port-pair LPORT-PAIR-GROUP LPORT-PAIR add a port pair to a port-group\n\
  lport-pair-group-del-port-pair LPORT-PAIR-GROUP LPORT-PAIR del a port pair from a port-group\n\
\n\
Logical port-pair commands:\n\
  lport-pair-add LSWITCH LIN-PORT LOUT-PORT [LPORT-PAIR-NAME]\n\
                                    create a logical port-pair \n\
  lport-pair-del LPORT-PAIR-NAME    delete a port-pair, does not delete ports\n\
  lport-pair-list                   print the names of all logical port-pairs\n\
\n\
Logical flow-classifier commands:\n\
  lflow-classifier-add LPORT-CHAIN LIN-PORT [LFLOW-CLASSIFIER-NAME]\n\
                                                  create a logical flow-classifer \n\
  lflow-classifier-del LFLOW-CLASSIFIER-NAME      delete a flow-classifier, does not delete ports\n\
  lflow-classifier-list LPORT-CHAIN               print the names of all logical flow-classifiers on a switch\n\
  lflow-classifier-set-logical-destination-port LFLOW_CLASSIFIER [LDEST_PORT]\n\
                                                  set the name of ldest port \n\
  lflow-classifier-get-logical-destination-port LFLOW_CLASSIFIER\n\
                                                  get the name of ldest port \n\
\n\
Logical router commands:\n\
  lrouter-add [LROUTER]     create a logical router named LROUTER\n\
  lrouter-del LROUTER       delete LROUTER and all its ports\n\
  lrouter-list              print the names of all logical routers\n\
\n\
ACL commands:\n\
  acl-add SWITCH DIRECTION PRIORITY MATCH ACTION [log]\n\
                            add an ACL to SWITCH\n\
  acl-del SWITCH [DIRECTION [PRIORITY MATCH]]\n\
                            remove ACLs from SWITCH\n\
  acl-list SWITCH           print ACLs for SWITCH\n\
\n\
Logical switch port commands:\n\
  lsp-add SWITCH PORT       add logical port PORT on SWITCH\n\
  lsp-add SWITCH PORT PARENT TAG\n\
                            add logical port PORT on SWITCH with PARENT\n\
                            on TAG\n\
  lsp-del PORT              delete PORT from its attached switch\n\
  lsp-list SWITCH           print the names of all logical ports on SWITCH\n\
  lsp-get-parent PORT       get the parent of PORT if set\n\
  lsp-get-tag PORT          get the PORT's tag if set\n\
  lsp-set-addresses PORT [ADDRESS]...\n\
                            set MAC or MAC+IP addresses for PORT.\n\
  lsp-get-addresses PORT    get a list of MAC addresses on PORT\n\
  lsp-set-port-security PORT [ADDRS]...\n\
                            set port security addresses for PORT.\n\
  lsp-get-port-security PORT    get PORT's port security addresses\n\
  lsp-get-up PORT           get state of PORT ('up' or 'down')\n\
  lsp-set-enabled PORT STATE\n\
                            set administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lsp-get-enabled PORT      get administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lsp-set-type PORT TYPE    set the type for PORT\n\
  lsp-get-type PORT         get the type for PORT\n\
  lsp-set-options PORT KEY=VALUE [KEY=VALUE]...\n\
                            set options related to the type of PORT\n\
  lsp-get-options PORT      get the type specific options for PORT\n\
\n\
Logical router commands:\n\
  lr-add [ROUTER]           create a logical router named ROUTER\n\
  lr-del ROUTER             delete ROUTER and all its ports\n\
  lr-list                   print the names of all logical routers\n\
\n\
Logical router port commands:\n\
  lrp-add ROUTER PORT MAC NETWORK [PEER]\n\
                            add logical port PORT on ROUTER\n\
  lrp-del PORT              delete PORT from its attached router\n\
  lrp-list ROUTER           print the names of all ports on ROUTER\n\
  lrp-set-enabled PORT STATE\n\
                            set administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lrp-get-enabled PORT      get administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
\n\
Route commands:\n\
  lr-route-add ROUTER PREFIX NEXTHOP [PORT]\n\
                            add a route to ROUTER\n\
  lr-route-del ROUTER [PREFIX]\n\
                            remove routes from ROUTER\n\
  lr-route-list ROUTER      print routes for ROUTER\n\
\n\
%s\
\n\
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           program_name, program_name, ctl_get_db_cmd_usage(), nbctl_default_db());
    vlog_usage();
    printf("\
  --no-syslog             equivalent to --verbose=nbctl:syslog:warn\n");
    printf("\n\
Other options:\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}


/* Find a logical router given its id. */
static const struct nbrec_logical_router *
lr_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                        bool must_exist)
{
    const struct nbrec_logical_router *lr = NULL;
    bool is_uuid = false;
    struct uuid lr_uuid;

    if (uuid_from_string(&lr_uuid, id)) {
        is_uuid = true;
        lr = nbrec_logical_router_get_for_uuid(ctx->idl, &lr_uuid);
    }

    if (!lr) {
        const struct nbrec_logical_router *iter;

        NBREC_LOGICAL_ROUTER_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (lr) {
                ctl_fatal("Multiple logical routers named '%s'.  "
                          "Use a UUID.", id);
            }
            lr = iter;
        }
    }

    if (!lr && must_exist) {
        ctl_fatal("%s: router %s not found", id, is_uuid ? "UUID" : "name");
    }

    return lr;
}

static const struct nbrec_logical_switch *
ls_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist)
{
    const struct nbrec_logical_switch *ls = NULL;

    struct uuid ls_uuid;
    bool is_uuid = uuid_from_string(&ls_uuid, id);
    if (is_uuid) {
        ls = nbrec_logical_switch_get_for_uuid(ctx->idl, &ls_uuid);
    }

    if (!ls) {
        const struct nbrec_logical_switch *iter;

        NBREC_LOGICAL_SWITCH_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (ls) {
                ctl_fatal("Multiple logical switches named '%s'.  "
                          "Use a UUID.", id);
            }
            ls = iter;
        }
    }

    if (!ls && must_exist) {
        ctl_fatal("%s: switch %s not found", id, is_uuid ? "UUID" : "name");
    }

    return ls;
}

static const struct nbrec_logical_port_chain *
lport_chain_by_name_or_uuid(struct ctl_context *ctx, const char *id)
{
    const struct nbrec_logical_port_chain *lport_chain = NULL;
    bool is_uuid = false;
    struct uuid lport_chain_uuid;

    if (uuid_from_string(&lport_chain_uuid, id)) {
        is_uuid = true;
        lport_chain = nbrec_logical_port_chain_get_for_uuid(ctx->idl,
                                                    &lport_chain_uuid);
	printf("found lport_chain %s\n",id);
    }

    if (!lport_chain) {
        NBREC_LOGICAL_PORT_CHAIN_FOR_EACH(lport_chain, ctx->idl) {
            if (!strcmp(lport_chain->name, id)) {
                break;
	    }
	}
    }
    if (!lport_chain) {
      ctl_fatal("lport_chain not found for %s: '%s'",
                is_uuid ? "UUID" : "name", id);
    }

    return lport_chain;
}
static const struct nbrec_logical_port_pair_group *
lport_pair_group_by_name_or_uuid(struct ctl_context *ctx, const char *id)
{
    const struct nbrec_logical_port_pair_group *lport_pair_group = NULL;
    bool is_uuid = false;
    struct uuid lport_pair_group_uuid;

    if (uuid_from_string(&lport_pair_group_uuid, id)) {
        is_uuid = true;
        lport_pair_group = nbrec_logical_port_pair_group_get_for_uuid(ctx->idl,
                                                    &lport_pair_group_uuid);
	printf("Found lport_pair_group %s\n",id);
    }

    if (!lport_pair_group) {
        NBREC_LOGICAL_PORT_PAIR_GROUP_FOR_EACH(lport_pair_group, ctx->idl) {
            if (!strcmp(lport_pair_group->name, id)) {
                break;
	    }
	}
    }
    if (!lport_pair_group) {
      ctl_fatal("lport_pair_group not found for %s: '%s'",
                is_uuid ? "UUID" : "name", id);
    }

    return lport_pair_group;
}
static const struct nbrec_logical_port_pair *
lport_pair_by_name_or_uuid(struct ctl_context *ctx, const char *id)
{
    const struct nbrec_logical_port_pair *lport_pair = NULL;
    bool is_uuid = false;
    struct uuid lport_pair_uuid;

    if (uuid_from_string(&lport_pair_uuid, id)) {
        is_uuid = true;
        lport_pair = nbrec_logical_port_pair_get_for_uuid(ctx->idl,
                                                    &lport_pair_uuid);
	printf("found lport_pair %s\n",id);
    }

    if (!lport_pair) {
        NBREC_LOGICAL_PORT_PAIR_FOR_EACH(lport_pair, ctx->idl) {
            if (!strcmp(lport_pair->name, id)) {
                break;
	    }
	}
    }
    if (!lport_pair) {
      ctl_fatal("lport_pair not found for %s: '%s'",
                is_uuid ? "UUID" : "name", id);
    }

    return lport_pair;
}
static const struct nbrec_logical_flow_classifier *
lflow_classifier_by_name_or_uuid(struct ctl_context *ctx, const char *id)
{
    const struct nbrec_logical_flow_classifier *lflow_classifier = NULL;
    bool is_uuid = false;
    struct uuid lflow_classifier_uuid;

    if (uuid_from_string(&lflow_classifier_uuid, id)) {
        is_uuid = true;
        lflow_classifier = nbrec_logical_flow_classifier_get_for_uuid(ctx->idl,
                                                    &lflow_classifier_uuid);
	printf("found lflow_classifier %s\n",id);
    }

    if (!lflow_classifier) {
      NBREC_LOGICAL_FLOW_CLASSIFIER_FOR_EACH(lflow_classifier, ctx->idl) {
            if (!strcmp(lflow_classifier->name, id)) {
                break;
	    }
	}
    }
    if (!lflow_classifier) {
      ctl_fatal("lflow_classifier not found for %s: '%s'",
                is_uuid ? "UUID" : "name", id);
    }

    return lflow_classifier;
}
static const struct nbrec_logical_port *
lport_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                      bool must_exist){

    const struct nbrec_logical_port *lport = NULL;

    struct uuid lport_uuid;
    bool is_uuid = uuid_from_string(&lport_uuid, id);
    if (is_uuid) {
        lport = nbrec_logical_port_get_for_uuid(ctx->idl, &lport_uuid);
    }

    if (!lport) {
        NBREC_LOGICAL_PORT_FOR_EACH(lport, ctx->idl) {
            if (!strcmp(lport->name, id)) {
                break;
            }
        }
    }

    if (!lport && must_exist) {
        ctl_fatal("%s: lport %s not found", id, is_uuid ? "UUID" : "name");
    }

    return lport;
}
/* Given pointer to logical router, this routine prints the router
 * information.  */
static void
print_lr(const struct nbrec_logical_router *lr, struct ds *s)
{
    ds_put_format(s, "    router "UUID_FMT" (%s)\n",
                  UUID_ARGS(&lr->header_.uuid), lr->name);

    for (size_t i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        ds_put_format(s, "        port %s\n", lrp->name);
        if (lrp->mac) {
            ds_put_cstr(s, "            mac: ");
            ds_put_format(s, "\"%s\"", lrp->mac);
        }
        ds_put_format(s, "\n");
    }
}

static void
print_ls(const struct nbrec_logical_switch *ls, struct ds *s)
{
    ds_put_format(s, "    switch "UUID_FMT" (%s)\n",
                  UUID_ARGS(&ls->header_.uuid), ls->name);

    for (size_t i = 0; i < ls->n_ports; i++) {
        const struct nbrec_logical_switch_port *lsp = ls->ports[i];

        ds_put_format(s, "        port %s\n", lsp->name);
        if (lsp->parent_name) {
            ds_put_format(s, "            parent: %s\n", lsp->parent_name);
        }
        if (lsp->n_tag) {
            ds_put_format(s, "            tag: %"PRIu64"\n", lsp->tag[0]);
        }
        if (lsp->n_addresses) {
            ds_put_cstr(s, "            addresses: [");
            for (size_t j = 0; j < lsp->n_addresses; j++) {
                ds_put_format(s, "%s\"%s\"",
                        j == 0 ? "" : ", ",
                        lsp->addresses[j]);
            }
            ds_put_cstr(s, "]\n");
        }
    }
}

static void
nbctl_show(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;

    if (ctx->argc == 2) {
        ls = ls_by_name_or_uuid(ctx, ctx->argv[1], false);
        if (ls) {
            print_ls(ls, &ctx->output);
        }
    } else {
        NBREC_LOGICAL_SWITCH_FOR_EACH(ls, ctx->idl) {
            print_ls(ls, &ctx->output);
        }
    }
    const struct nbrec_logical_router *lr;

    if (ctx->argc == 2) {
        lr = lr_by_name_or_uuid(ctx, ctx->argv[1], false);
        if (lr) {
            print_lr(lr, &ctx->output);
        }
    } else {
        NBREC_LOGICAL_ROUTER_FOR_EACH(lr, ctx->idl) {
            print_lr(lr, &ctx->output);
        }
    }
}

static void
nbctl_ls_add(struct ctl_context *ctx)
{
    const char *ls_name = ctx->argc == 2 ? ctx->argv[1] : NULL;

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;
    if (may_exist && add_duplicate) {
        ctl_fatal("--may-exist and --add-duplicate may not be used together");
    }

    if (ls_name) {
        if (!add_duplicate) {
            const struct nbrec_logical_switch *ls;
            NBREC_LOGICAL_SWITCH_FOR_EACH (ls, ctx->idl) {
                if (!strcmp(ls->name, ls_name)) {
                    if (may_exist) {
                        return;
                    }
                    ctl_fatal("%s: a switch with this name already exists",
                              ls_name);
                }
            }
        }
    } else if (may_exist) {
        ctl_fatal("--may-exist requires specifying a name");
    } else if (add_duplicate) {
        ctl_fatal("--add-duplicate requires specifying a name");
    }

    struct nbrec_logical_switch *ls;
    ls = nbrec_logical_switch_insert(ctx->txn);
    if (ls_name) {
        nbrec_logical_switch_set_name(ls, ls_name);
    }
}

static void
nbctl_ls_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *ls;

    ls = ls_by_name_or_uuid(ctx, id, must_exist);
    if (!ls) {
        return;
    }

    nbrec_logical_switch_delete(ls);
}

static void
nbctl_ls_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    struct smap lswitches;

    smap_init(&lswitches);
    NBREC_LOGICAL_SWITCH_FOR_EACH(ls, ctx->idl) {
        smap_add_format(&lswitches, ls->name, UUID_FMT " (%s)",
                        UUID_ARGS(&ls->header_.uuid), ls->name);
    }
    const struct smap_node **nodes = smap_sort(&lswitches);
    for (size_t i = 0; i < smap_count(&lswitches); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lswitches);
    free(nodes);
}

/* Find the lrport given its id. */
static const struct nbrec_logical_router_port *
lrport_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                       bool must_exist)
{
    const struct nbrec_logical_router_port *lrport = NULL;
    bool is_uuid = false;
    struct uuid lrport_uuid;

    if (uuid_from_string(&lrport_uuid, id)) {
        is_uuid = true;
        lrport = nbrec_logical_router_port_get_for_uuid(ctx->idl,
                                                        &lrport_uuid);
    }

    if (!lrport) {
        NBREC_LOGICAL_ROUTER_PORT_FOR_EACH(lrport, ctx->idl) {
            if (!strcmp(lrport->name, id)) {
                break;
            }
        }
    }

    if (!lrport && must_exist) {
        ctl_fatal("%s: lrport with this %s not found",
                  id, is_uuid ? "name" : "UUID");
    }

    return lrport;
}

/*
 * Port chain CLI Functions
 */
static void
nbctl_lport_chain_add(struct ctl_context *ctx)
{

  const struct nbrec_logical_switch *lswitch;

  if (ctx->argc < 2) {
      /* ensure all arguments are present */
      ctl_fatal("Invalid number of arguments: (%d), to lport-chain-add.",ctx->argc);
    }

  const char *lport_chain_name = ctx->argc == 3 ? ctx->argv[2] : NULL;
  lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1], true);

  if (lport_chain_name) {
            const struct nbrec_logical_port_chain *lport_chain;
            NBREC_LOGICAL_PORT_CHAIN_FOR_EACH(lport_chain, ctx->idl) {
                if (strcmp(lport_chain->name, lport_chain_name)) 
                    ctl_fatal("%s: an lport_chain with this name already exists",
                              lport_chain_name);
                }
        }
    struct nbrec_logical_port_chain *lport_chain;
    lport_chain = nbrec_logical_port_chain_insert(ctx->txn);
    if (lport_chain_name) {
        nbrec_logical_port_chain_set_name(lport_chain, lport_chain_name);
    }

    /* Insert the logical port-chain into the logical switch. */

    nbrec_logical_switch_verify_port_chains(lswitch);
    struct nbrec_logical_port_chain  **new_port_chain = xmalloc(sizeof *new_port_chain *
                                                    (lswitch->n_port_chains + 1));
    memcpy(new_port_chain, lswitch->port_chains, sizeof *new_port_chain * lswitch->n_port_chains);
    new_port_chain[lswitch->n_port_chains] = CONST_CAST(struct nbrec_logical_port_chain *, lport_chain);
    nbrec_logical_switch_set_port_chains(lswitch, new_port_chain, lswitch->n_port_chains + 1);
    free(new_port_chain);
}

/* Removes lswitch->pair_chain[idx]'. */
static void
remove_lport_chain(const struct nbrec_logical_switch *lswitch, size_t idx)
{
  const struct nbrec_logical_port_chain *lport_chain = lswitch->port_chains[idx];

    /* First remove 'lport-chain' from the array of port-chains.  This is what will
     * actually cause the logical port-chain to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_port_chain **new_port_chain
      = xmemdup(lswitch->port_chains, sizeof *new_port_chain * lswitch->n_port_chains);
    new_port_chain[idx] = new_port_chain[lswitch->n_port_chains - 1];
    nbrec_logical_switch_verify_port_chains(lswitch);
    nbrec_logical_switch_set_port_chains(lswitch, new_port_chain, lswitch->n_port_chains - 1);
    free(new_port_chain);

    /* Delete 'lport-chain' from the IDL.  This won't have a real effect on the
     * database server (the IDL will suppress it in fact) but it means that it
     * won't show up when we iterate with NBREC_LOGICAL_PORT_CHAIN_FOR_EACH later. */
    nbrec_logical_port_chain_delete(lport_chain);
}

static void
nbctl_lport_chain_del(struct ctl_context *ctx)
{
 const struct nbrec_logical_port_chain *lport_chain;

    lport_chain = lport_chain_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lport_chain) {
      ctl_fatal("Cannot find lport_chain: %s\n", ctx->argv[1]);
    }

    /* Find the lswitch that contains 'port-chain', then delete it. */
    const struct nbrec_logical_switch *lswitch;
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->idl) {
        for (size_t i = 0; i < lswitch->n_port_chains; i++) {
            if (lswitch->port_chains[i] == lport_chain) {
	      remove_lport_chain(lswitch,i);
	      printf("Deleted lport-chain: %s\n", ctx->argv[1]);
              return;

static const struct nbrec_logical_switch_port *
lsp_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                    bool must_exist)
{
    const struct nbrec_logical_switch_port *lsp = NULL;

    struct uuid lsp_uuid;
    bool is_uuid = uuid_from_string(&lsp_uuid, id);
    if (is_uuid) {
        lsp = nbrec_logical_switch_port_get_for_uuid(ctx->idl, &lsp_uuid);
    }

    if (!lsp) {
        NBREC_LOGICAL_SWITCH_PORT_FOR_EACH(lsp, ctx->idl) {
            if (!strcmp(lsp->name, id)) {
                break;
            }
        }
    }

    if (!lsp && must_exist) {
        ctl_fatal("%s: port %s not found", id, is_uuid ? "UUID" : "name");
    }

    return lsp;

}

static void
nbctl_lport_chain_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;
    struct smap lport_chains;
    size_t i;

    lswitch = lswitch_by_name_or_uuid(ctx, id, true);
    if (!lswitch) {
        return;
    }

    smap_init(&lport_chains);
    for (i = 0; i < lswitch->n_port_chains; i++) {
        const struct nbrec_logical_port_chain *lport_chain = lswitch->port_chains[i];
        smap_add_format(&lport_chains, lport_chain->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lport_chain->header_.uuid), lport_chain->name);
    }
    const struct smap_node **nodes = smap_sort(&lport_chains);
    for (i = 0; i < smap_count(&lport_chains); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lport_chains);
    free(nodes);
}

static void
print_lport_chain(const struct nbrec_logical_port_chain *lport_chain,
		  struct ctl_context *ctx)
{
  const char *port_not_set="Not Set";
    ds_put_format(&ctx->output, "    lport-chain "UUID_FMT" (%s)\n",
                  UUID_ARGS(&lport_chain->header_.uuid), lport_chain->name);
    printf("Number of port-pair-groups: %d\n", lport_chain->n_port_pair_groups);
    for (size_t i = 0; i < lport_chain->n_port_pair_groups; i++) {
        const struct nbrec_logical_port_pair_group *lport_pair_group 
	  = lport_chain->port_pair_groups[i];
        ds_put_format(&ctx->output, "        lport-pair-group %s\n", lport_pair_group->name);
	for (size_t j = 0; j < lport_pair_group->n_port_pairs; j++){
	  const struct nbrec_logical_port *linport;
	  const struct nbrec_logical_port *loutport;
	  const struct nbrec_logical_port_pair *lport_pair 
	    = lport_pair_group->port_pairs[j];
	  ds_put_format(&ctx->output, "             lport-pair %s\n", lport_pair->name);
	  printf("\n inport %s from port-pair %s \n", lport_pair->inport->name, lport_pair->name);
	  // linport = lport_by_name_or_uuid(ctx,lport_pair->inport->name,true);
	  linport = lport_pair->inport;
	  printf("Linport name: %s\n", linport->name);
	  ds_put_format(&ctx->output, "                 lport-pair inport "UUID_FMT" (%s)\n",
                  UUID_ARGS(&linport->header_.uuid), linport->name);

	  // loutport = lport_by_name_or_uuid(ctx,lport_pair->outport->name,true);
	  loutport = lport_pair->outport;
	  printf("Loutport name: %s\n", loutport->name);
	  ds_put_format(&ctx->output, "                 lport-pair outport "UUID_FMT" (%s)\n",
                  UUID_ARGS(&loutport->header_.uuid), loutport->name);
	}
    }
    printf("finished port pairs\n");

    const struct nbrec_logical_flow_classifier *lflow_classifier = lport_chain->flow_classifier;
    printf("Getting flow classifier: %s\n", lflow_classifier->name);
    ds_put_format(&ctx->output, "        lflow_classifier %s\n", lflow_classifier->name);
    if (lflow_classifier->logical_source_port == NULL){
      ds_put_format(&ctx->output, "          logical-source-port %s\n", port_not_set);
    } else {
      ds_put_format(&ctx->output, "          logical-source-port %s\n", lflow_classifier->logical_source_port->name);
    }
    if (lflow_classifier->logical_destination_port == NULL){
      ds_put_format(&ctx->output, "          logical-destination-port %s\n", port_not_set);
    } else {
      ds_put_format(&ctx->output, "          logical-destination-port %s\n", lflow_classifier->logical_destination_port->name);
    }
    ds_put_format(&ctx->output, "          ethertype: %s\n", lflow_classifier->ethertype);
    ds_put_format(&ctx->output, "          protocol: %s\n", lflow_classifier->protocol);
    ds_put_format(&ctx->output, "          source_port_range_min: %d\n", lflow_classifier->source_port_range_min);
    ds_put_format(&ctx->output, "          source_port_range_max: %d\n", lflow_classifier->source_port_range_max);
    ds_put_format(&ctx->output, "          destination_port_range_min: %d\n", lflow_classifier->destination_port_range_min);
    ds_put_format(&ctx->output, "          destination_port_range_max: %d\n", lflow_classifier->destination_port_range_max);
    ds_put_format(&ctx->output, "          source_ip_prefix: %d\n", lflow_classifier->source_ip_prefix);
    ds_put_format(&ctx->output, "          destination_ip_prefix: %d\n", lflow_classifier->destination_ip_prefix);
}

static void
nbctl_lport_chain_show(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *lswitch;
    const struct nbrec_logical_port_chain *lport_chain;
    printf("\nIn lport-chain-show\n");
    if (ctx->argc < 2) {
	/* ensure all arguments are present */
      ctl_fatal("Invalid number of arguments: (%d), to lport-chain-show.",ctx->argc);
    }
    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1], true);
    ds_put_format(&ctx->output, " lswitch "UUID_FMT" (%s)\n",
                  UUID_ARGS(&lswitch->header_.uuid), lswitch->name);
    if (ctx->argc == 3) {
      lport_chain = lport_chain_by_name_or_uuid(ctx, ctx->argv[2]);
        if (lport_chain) {
	  print_lport_chain(lport_chain, ctx);
        }
    } else {
        NBREC_LOGICAL_PORT_CHAIN_FOR_EACH(lport_chain, ctx->idl) {
	  print_lport_chain(lport_chain, ctx);
        }
    }
}


static void
nbctl_lport_chain_set_flow_classifier(struct ctl_context *ctx)
{
    
    const struct nbrec_logical_port_chain *lport_chain;
    const struct nbrec_logical_flow_classifier *lflow_classifier = NULL;

    if (ctx->argc < 3){
      /* ensure all arguments are present */
      ctl_fatal("Invalid number of arguments: (%d), to lport-chain-set-flow-classifier.",ctx->argc);
    }
   
    lport_chain = lport_chain_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lport_chain){
	ctl_fatal("Invalid port_chain %s ", ctx->argv[1]);
      }
    /* Check flow classifier exists*/
      lflow_classifier = lflow_classifier_by_name_or_uuid(ctx, ctx->argv[2]);
      if (!lflow_classifier){
	ctl_fatal("Invalid flow_classifier %s ", ctx->argv[2]);
      }

    /* Insert the logical flow-classifier into the logical port-chain. */
    nbrec_logical_port_chain_verify_flow_classifier(lport_chain);
    //struct nbrec_logical_flow_classifier  **new_flow_classifier= xmalloc(sizeof *new_flow_classifier);
    //memcpy(new_flow_classifier, lport_chain->flow_classifier, sizeof *new_flow_classifier);
    //new_flow_classifier = CONST_CAST(struct nbrec_logical_flow_classifier *, lflow_classifier);
    //nbrec_logical_port_chain_set_flow_classifier(lport_chain, new_flow_classifier);
    nbrec_logical_port_chain_set_flow_classifier(lport_chain, lflow_classifier);
    //free(new_flow_classifier);
}

static void nbctl_lport_chain_get_flow_classifier(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port_chain *lport_chain;

    lport_chain = lport_chain_by_name_or_uuid(ctx, id);
    ds_put_format(&ctx->output, "%s\n", lport_chain->flow_classifier->name);
}
/* End of port-chain operations */

/*
 * Port Pair Groups CLI Functions
 */
static void
nbctl_lport_pair_group_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_port_pair_group *lport_pair_group;
    const struct nbrec_logical_port_chain *lport_chain;

    /* check lport_chain exists */
    lport_chain = lport_chain_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lport_chain) {
        return;
    }

    if (ctx->argc < 2) {
      /* ensure all arguments are present */
      ctl_fatal("invalid number of arguments: %d to lport-pair-groups-add.", ctx->argc);
    }

    /* create the logical port-pair-group. */
    lport_pair_group = nbrec_logical_port_pair_group_insert(ctx->txn);
    if (ctx->argc == 3){
       nbrec_logical_port_pair_group_set_name(lport_pair_group, ctx->argv[2]);
    }

    /* Insert the logical port into the logical switch. */
    nbrec_logical_port_chain_verify_port_pair_groups(lport_chain);
    struct nbrec_logical_port_pair_group  **new_port_pair_group = xmalloc(sizeof *new_port_pair_group *
                                                    (lport_chain->n_port_pair_groups + 1));
    memcpy(new_port_pair_group, lport_chain->port_pair_groups, sizeof *new_port_pair_group * lport_chain->n_port_pair_groups);
    new_port_pair_group[lport_chain->n_port_pair_groups] = 
      CONST_CAST(struct nbrec_logical_port_pair_group *,lport_pair_group);
    nbrec_logical_port_chain_set_port_pair_groups(lport_chain, new_port_pair_group, lport_chain->n_port_pair_groups + 1);
    free(new_port_pair_group);
}
/* Removes lport-pair-group 'lport_chain->port_pair_group[idx]'. */
static void
remove_lport_pair_group(const struct nbrec_logical_port_chain *lport_chain, size_t idx)
{
  const struct nbrec_logical_port_pair_group *lport_pair_group = lport_chain->port_pair_groups[idx];

    /* First remove 'lport-pair-group' from the array of port-pair-groups.  This is what will
     * actually cause the logical port-pair-group to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_port_pair_group **new_port_pair_group
      = xmemdup(lport_chain->port_pair_groups, sizeof *new_port_pair_group * lport_chain->n_port_pair_groups);
    new_port_pair_group[idx] = new_port_pair_group[lport_chain->n_port_pair_groups - 1];
    nbrec_logical_port_chain_verify_port_pair_groups(lport_chain);
    nbrec_logical_port_chain_set_port_pair_groups(lport_chain, new_port_pair_group, lport_chain->n_port_pair_groups - 1);
    free(new_port_pair_group);

    /* Delete 'lport-pair-group' from the IDL.  This won't have a real effect on the
     * database server (the IDL will suppress it in fact) but it means that it
     * won't show up when we iterate with NBREC_LOGICAL_PORT_PAIR_GROUP_FOR_EACH later. */
    nbrec_logical_port_pair_group_delete(lport_pair_group);
}

static void
nbctl_lport_pair_group_del(struct ctl_context *ctx)
{
 const struct nbrec_logical_port_pair_group *lport_pair_group;

    lport_pair_group = lport_pair_group_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lport_pair_group) {
      ctl_fatal("Cannot find lport_pair_group: %s\n", ctx->argv[1]);
    }

    /* Find the port-chain that contains 'port-pair-group', then delete it. */
    const struct nbrec_logical_port_chain *lport_chain;
    NBREC_LOGICAL_PORT_CHAIN_FOR_EACH (lport_chain, ctx->idl) {
        for (size_t i = 0; i < lport_chain->n_port_pair_groups; i++) {
            if (lport_chain->port_pair_groups[i] == lport_pair_group) {
	      remove_lport_pair_group(lport_chain,i);
	      printf("Deleted lport-pair-group: %s\n", ctx->argv[1]);
              return;
            }
        }
    }
    ctl_fatal("logical port-pair-group %s is not part of any logical port-chain",
              ctx->argv[1]);
}

static void
nbctl_lport_pair_group_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port_chain *lport_chain;
    struct smap lport_pair_groups;
    size_t i;

    lport_chain = lport_chain_by_name_or_uuid(ctx, id);
    if (!lport_chain) {
        return;
    }

    smap_init(&lport_pair_groups);
    for (i = 0; i < lport_chain->n_port_pair_groups; i++) {
        const struct nbrec_logical_port_pair_group *lport_pair_group = lport_chain->port_pair_groups[i];
        smap_add_format(&lport_pair_groups, lport_pair_group->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lport_pair_group->header_.uuid), lport_pair_group->name);
    }
    const struct smap_node **nodes = smap_sort(&lport_pair_groups);
    for (i = 0; i < smap_count(&lport_pair_groups); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lport_pair_groups);
    free(nodes);
}

static void
nbctl_lport_pair_group_add_port_pair(struct ctl_context *ctx)
{
    const struct nbrec_logical_port_pair_group *lport_pair_group;
    const struct nbrec_logical_port_pair *lport_pair;
    const char *lport_pair_name;
    
    lport_pair_group = lport_pair_group_by_name_or_uuid(ctx, ctx->argv[1]);

    if (ctx->argc < 3) {
      /* ensure all arguments are present */
      ctl_fatal("Invalid number of arguments: (%d), to lport-pair-group-add-port-pair.",ctx->argc);
    }
    /* Check that port-pair exists  */
    lport_pair_name = ctx->argv[2];
    lport_pair = lport_pair_by_name_or_uuid(ctx, lport_pair_name);
    if (!lport_pair){
      ctl_fatal("%s: an lport-pair with this name does not exist",lport_pair_name);
    }

    /* Insert the logical port-pair into the logical port-pair-group. */
    nbrec_logical_port_pair_group_verify_port_pairs(lport_pair_group);
    struct nbrec_logical_port_pair  **new_port_pair = xmalloc(sizeof *new_port_pair *
                                                    (lport_pair_group->n_port_pairs + 1));
    memcpy(new_port_pair, lport_pair_group->port_pairs, sizeof *new_port_pair * lport_pair_group->n_port_pairs);
    new_port_pair[lport_pair_group->n_port_pairs] = CONST_CAST(struct nbrec_logical_port_pair *, lport_pair);
    nbrec_logical_port_pair_group_set_port_pairs(lport_pair_group, new_port_pair, lport_pair_group->n_port_pairs + 1);
    free(new_port_pair);
}

/* Removes port-pair from port-pair-groiup but does not delete it'. */
static void
remove_lport_pair_from_port_pair_group(const struct nbrec_logical_port_pair_group *lport_pair_group, size_t idx)
{
  //TODO Check const struct nbrec_logical_port_pair *lport_pair = lport_pair_group->port_pairs[idx];

    /* First remove 'lport-pair' from the array of port-pairs.  This is what will
     * actually cause the logical port-pair to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_port_pair **new_port_pair
      = xmemdup(lport_pair_group->port_pairs, sizeof *new_port_pair * lport_pair_group->n_port_pairs);
    new_port_pair[idx] = new_port_pair[lport_pair_group->n_port_pairs - 1];
    nbrec_logical_port_pair_group_verify_port_pairs(lport_pair_group);
    nbrec_logical_port_pair_group_set_port_pairs(lport_pair_group, new_port_pair, lport_pair_group->n_port_pairs - 1);
    free(new_port_pair);

    /* Do not delete actual port-pair as they are owned by a lswitch and can be reused. */
    //nbrec_logical_port_pair_delete(lport_pair);
}

static void
nbctl_lport_pair_group_del_port_pair(struct ctl_context *ctx)
{
 const struct nbrec_logical_port_pair *lport_pair;

    lport_pair = lport_pair_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lport_pair) {
      ctl_fatal("Cannot find lport_pair: %s\n", ctx->argv[1]);
    }

    /* Find the port-pair_group that contains 'port-pair', then delete it. */
    const struct nbrec_logical_port_pair_group *lport_pair_group;
    NBREC_LOGICAL_PORT_PAIR_GROUP_FOR_EACH (lport_pair_group, ctx->idl) {
        for (size_t i = 0; i < lport_pair_group->n_port_pairs; i++) {
            if (lport_pair_group->port_pairs[i] == lport_pair) {
	      remove_lport_pair_from_port_pair_group(lport_pair_group,i);
	      printf("Deleted lport-pair: %s from lport-group-pair \n", ctx->argv[1]);
              return;
            }
        }
    }
    ctl_fatal("logical port-pair %s is not part of any logical switch",
              ctx->argv[1]);
}
/* End of port-pair-group operations */

/*
 * port-pair operations
 */
static void
nbctl_lport_pair_add(struct ctl_context *ctx)
{
  const char *port_id_in = ctx->argv[2];
  const char *port_id_out = ctx->argv[3];

    const struct nbrec_logical_switch *lswitch;
    const struct nbrec_logical_port_pair *lport_pair;
    const struct nbrec_logical_port *lport_in,*lport_out;

    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1], true);

    if (ctx->argc < 4) {
      /* ensure all arguments are present */
      ctl_fatal("Invalid number of arguments: (%d), to lport-pair-add.",ctx->argc);
    }
    /* Check that ports exist in this switch */
    lport_in = lport_by_name_or_uuid(ctx, port_id_in, false);
    if (!lport_in){
      ctl_fatal("%s: an lport with this name does not exist",ctx->argv[2]);
    }
    lport_out = lport_by_name_or_uuid(ctx, port_id_out, false);
    if (!lport_out){
      ctl_fatal("%s: an lport with this name does not exist",ctx->argv[3]);
    }

    /* create the logical port-pair. */
    lport_pair = nbrec_logical_port_pair_insert(ctx->txn);
    nbrec_logical_port_pair_set_inport(lport_pair, lport_in);
    nbrec_logical_port_pair_set_outport(lport_pair, lport_out);
    if (ctx->argc == 5){
       nbrec_logical_port_pair_set_name(lport_pair, ctx->argv[4]);
    }

    /* Insert the logical port-pair into the logical port-pair-group. */
    nbrec_logical_switch_verify_port_pairs(lswitch);
    struct nbrec_logical_port_pair  **new_port_pair = xmalloc(sizeof *new_port_pair *
                                                    (lswitch->n_port_pairs + 1));
    memcpy(new_port_pair, lswitch->port_pairs, sizeof *new_port_pair * lswitch->n_port_pairs);
    new_port_pair[lswitch->n_port_pairs] = CONST_CAST(struct nbrec_logical_port_pair *, lport_pair);
    nbrec_logical_switch_set_port_pairs(lswitch, new_port_pair, lswitch->n_port_pairs + 1);
    free(new_port_pair);
}
/* Removes lswitch->pair_pair[idx]'. */
static void
remove_lport_pair(const struct nbrec_logical_switch *lswitch, size_t idx)
{
  const struct nbrec_logical_port_pair *lport_pair = lswitch->port_pairs[idx];

    /* First remove 'lport-pair' from the array of port-pairs.  This is what will
     * actually cause the logical port-pair to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_port_pair **new_port_pair
      = xmemdup(lswitch->port_pairs, sizeof *new_port_pair * lswitch->n_port_pairs);
    new_port_pair[idx] = new_port_pair[lswitch->n_port_pairs - 1];
    nbrec_logical_switch_verify_port_pairs(lswitch);
    nbrec_logical_switch_set_port_pairs(lswitch, new_port_pair, lswitch->n_port_pairs - 1);
    free(new_port_pair);

    /* Delete 'lport-pair' from the IDL.  This won't have a real effect on the
     * database server (the IDL will suppress it in fact) but it means that it
     * won't show up when we iterate with NBREC_LOGICAL_PORT_PAIR_FOR_EACH later. */
    nbrec_logical_port_pair_delete(lport_pair);
}

static void
nbctl_lport_pair_del(struct ctl_context *ctx)
{
 const struct nbrec_logical_port_pair *lport_pair;

    lport_pair = lport_pair_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lport_pair) {
      ctl_fatal("Cannot find lport_pair: %s\n", ctx->argv[1]);
    }

    /* Find the port-pair_group that contains 'port-pair', then delete it. */
    const struct nbrec_logical_switch *lswitch;
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->idl) {
        for (size_t i = 0; i < lswitch->n_port_pairs; i++) {
            if (lswitch->port_pairs[i] == lport_pair) {
	      remove_lport_pair(lswitch,i);
	      printf("Deleted lport-pair: %s\n", ctx->argv[1]);
              return;
            }
        }
    }
    ctl_fatal("logical port-pair %s is not part of any logical switch",
              ctx->argv[1]);
}

static void
nbctl_lport_pair_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;
    struct smap lport_pairs;
    size_t i;

    lswitch = lswitch_by_name_or_uuid(ctx, id, true);
    if (!lswitch) {
        return;
    }

    smap_init(&lport_pairs);
    for (i = 0; i < lswitch->n_port_pairs; i++) {
        const struct nbrec_logical_port_pair *lport_pair = lswitch->port_pairs[i];
        smap_add_format(&lport_pairs, lport_pair->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lport_pair->header_.uuid), lport_pair->name);
    }
    const struct smap_node **nodes = smap_sort(&lport_pairs);
    for (i = 0; i < smap_count(&lport_pairs); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lport_pairs);
    free(nodes);
}
/* End of port-pair operations */
/*
 * flow_classifier operations
 */
static void
nbctl_lflow_classifier_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_port_chain *lport_chain; 
    const struct nbrec_logical_port *lport;
    const char *lport_name;
    const struct nbrec_logical_flow_classifier *lflow_classifier;
   

    if (ctx->argc < 3) {
      /* ensure all arguments are present */
      ctl_fatal("Invalid number of arguments: (%d), to lflow_classifier-add",ctx->argc);
    }
    lport_chain = lport_chain_by_name_or_uuid(ctx, ctx->argv[1]);
    /* Check that logical source port exist in this switch */
    lport_name = ctx->argv[2];
    lport = lport_by_name_or_uuid(ctx, lport_name, false);
    if (!lport){
      ctl_fatal("%s: a lport with this name does not exist",lport_name);
    }

    /* create the logical flow_classifier. */
    lflow_classifier = nbrec_logical_flow_classifier_insert(ctx->txn);
    nbrec_logical_flow_classifier_set_logical_source_port(lflow_classifier, lport);
    if (ctx->argc == 4){
       nbrec_logical_flow_classifier_set_name(lflow_classifier, ctx->argv[3]);
    }
 
    /* Insert the logical flow_classifier into the logical switch. */
    nbrec_logical_port_chain_verify_flow_classifier(lport_chain);
    //struct nbrec_logical_flow_classifier  **new_flow_classifier = xmalloc(sizeof *new_flow_classifier);
    //memcpy(new_flow_classifier, lswitch->flow_classifiers, sizeof *new_flow_classifier * lswitch->n_flow_classifiers);
    //new_flow_classifier[lswitch->n_flow_classifiers] = CONST_CAST(struct nbrec_logical_flow_classifier *, lflow_classifier);
    nbrec_logical_port_chain_set_flow_classifier(lport_chain, lflow_classifier);
    //free(new_flow_classifier);
}
static void
nbctl_lflow_classifier_del(struct ctl_context *ctx)
{
 const struct nbrec_logical_flow_classifier *lflow_classifier;

    lflow_classifier = lflow_classifier_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lflow_classifier) {
      printf("Cannot find lflow_classifier: %s\n", ctx->argv[1]);
      return;
    }

    /* Find the switch that contains 'flow-classifier', then delete it. */
    const struct nbrec_logical_port_chain *lport_chain;
    NBREC_LOGICAL_PORT_CHAIN_FOR_EACH (lport_chain, ctx->idl) {
            if (lport_chain->flow_classifier == lflow_classifier) {
	      nbrec_logical_flow_classifier_delete(lflow_classifier);
	      printf("Deleted lflow-classifier: %s\n", ctx->argv[1]);
              return;
        }
    }
    ctl_fatal("logical flow-classifier %s is not part of any logical switch",
              ctx->argv[1]);
}

static void
nbctl_lflow_classifier_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port_chain *lport_chain;
   

    lport_chain = lport_chain_by_name_or_uuid(ctx, id);
    if (!lport_chain) {
        return;
    }
    const struct nbrec_logical_flow_classifier *lflow_classifier = lport_chain->flow_classifier;
    printf("Getting flow classifier: %s\n", lflow_classifier->name);
    ds_put_format(&ctx->output, "        lflow_classifier %s\n", lflow_classifier->name);
    ds_put_format(&ctx->output, "          logical-source-port %s\n", lflow_classifier->logical_source_port);
    ds_put_format(&ctx->output, "          ethertype: %s\n", lflow_classifier->ethertype);
    ds_put_format(&ctx->output, "          protocol: %s\n", lflow_classifier->protocol);
    
  
}

static void
nbctl_lflow_classifier_set_logical_destination_port(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];

    const struct nbrec_logical_port *lport = NULL;
    const struct nbrec_logical_flow_classifier *lflow_classifier;

    lflow_classifier = lflow_classifier_by_name_or_uuid(ctx, id);

    /* Check port exists if given*/
    if (!strcmp(ctx->argv[2],"") ){
      lport = lport_by_name_or_uuid(ctx, ctx->argv[2], true);
      if (!lport){
	ctl_fatal("Invalid port %s ", ctx->argv[2]);
      }
    }
    nbrec_logical_flow_classifier_set_logical_destination_port(lflow_classifier,lport);
}

static void
nbctl_lflow_classifier_get_logical_destination_port(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_flow_classifier *lflow_classifier;

    lflow_classifier = lflow_classifier_by_name_or_uuid(ctx, id);
    ds_put_format(&ctx->output, "%s\n", (lflow_classifier->logical_destination_port)->name);
}
/* End of flow-classifier operations */




/* Returns the logical switch that contains 'lsp'. */
static const struct nbrec_logical_switch *
lsp_to_ls(const struct ovsdb_idl *idl,
               const struct nbrec_logical_switch_port *lsp)
{
    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_FOR_EACH (ls, idl) {
        for (size_t i = 0; i < ls->n_ports; i++) {
            if (ls->ports[i] == lsp) {
                return ls;
            }
        }
    }

    /* Can't happen because of the database schema */
    ctl_fatal("logical port %s is not part of any logical switch",
              lsp->name);
}

static const char *
ls_get_name(const struct nbrec_logical_switch *ls,
                 char uuid_s[UUID_LEN + 1], size_t uuid_s_size)
{
    if (ls->name[0]) {
        return ls->name;
    }
    snprintf(uuid_s, uuid_s_size, UUID_FMT, UUID_ARGS(&ls->header_.uuid));
    return uuid_s;
}

static void
nbctl_lsp_add(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;

    const struct nbrec_logical_switch *ls;
    ls = ls_by_name_or_uuid(ctx, ctx->argv[1], true);

    const char *parent_name;
    int64_t tag;
    if (ctx->argc == 3) {
        parent_name = NULL;
        tag = -1;
    } else if (ctx->argc == 5) {
        /* Validate tag. */
        parent_name = ctx->argv[3];
        if (!ovs_scan(ctx->argv[4], "%"SCNd64, &tag)
            || tag < 0 || tag > 4095) {
            ctl_fatal("%s: invalid tag", ctx->argv[4]);
        }
    } else {
        ctl_fatal("lsp-add with parent must also specify a tag");
    }

    const char *lsp_name = ctx->argv[2];
    const struct nbrec_logical_switch_port *lsp;
    lsp = lsp_by_name_or_uuid(ctx, lsp_name, false);
    if (lsp) {
        if (!may_exist) {
            ctl_fatal("%s: a port with this name already exists",
                      lsp_name);
        }

        const struct nbrec_logical_switch *lsw;
        lsw = lsp_to_ls(ctx->idl, lsp);
        if (lsw != ls) {
            char uuid_s[UUID_LEN + 1];
            ctl_fatal("%s: port already exists but in switch %s", lsp_name,
                      ls_get_name(lsw, uuid_s, sizeof uuid_s));
        }

        if (parent_name) {
            if (!lsp->parent_name) {
                ctl_fatal("%s: port already exists but has no parent",
                          lsp_name);
            } else if (strcmp(parent_name, lsp->parent_name)) {
                ctl_fatal("%s: port already exists with different parent %s",
                          lsp_name, lsp->parent_name);
            }

            if (!lsp->n_tag) {
                ctl_fatal("%s: port already exists but has no tag",
                          lsp_name);
            } else if (lsp->tag[0] != tag) {
                ctl_fatal("%s: port already exists with different "
                          "tag %"PRId64, lsp_name, lsp->tag[0]);
            }
        } else {
            if (lsp->parent_name) {
                ctl_fatal("%s: port already exists but has parent %s",
                          lsp_name, lsp->parent_name);
            }
        }

        return;
    }

    /* Create the logical port. */
    lsp = nbrec_logical_switch_port_insert(ctx->txn);
    nbrec_logical_switch_port_set_name(lsp, lsp_name);
    if (tag >= 0) {
        nbrec_logical_switch_port_set_parent_name(lsp, parent_name);
        nbrec_logical_switch_port_set_tag(lsp, &tag, 1);
    }

    /* Insert the logical port into the logical switch. */
    nbrec_logical_switch_verify_ports(ls);
    struct nbrec_logical_switch_port **new_ports = xmalloc(sizeof *new_ports *
                                                    (ls->n_ports + 1));
    memcpy(new_ports, ls->ports, sizeof *new_ports * ls->n_ports);
    new_ports[ls->n_ports] = CONST_CAST(struct nbrec_logical_switch_port *,
                                             lsp);
    nbrec_logical_switch_set_ports(ls, new_ports, ls->n_ports + 1);
    free(new_ports);
}

/* Removes logical switch port 'ls->ports[idx]'. */
static void
remove_lsp(const struct nbrec_logical_switch *ls, size_t idx)
{
    const struct nbrec_logical_switch_port *lsp = ls->ports[idx];

    /* First remove 'lsp' from the array of ports.  This is what will
     * actually cause the logical port to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_switch_port **new_ports
        = xmemdup(ls->ports, sizeof *new_ports * ls->n_ports);
    new_ports[idx] = new_ports[ls->n_ports - 1];
    nbrec_logical_switch_verify_ports(ls);
    nbrec_logical_switch_set_ports(ls, new_ports, ls->n_ports - 1);
    free(new_ports);

    /* Delete 'lsp' from the IDL.  This won't have a real effect on the
     * database server (the IDL will suppress it in fact) but it means that it
     * won't show up when we iterate with NBREC_LOGICAL_SWITCH_PORT_FOR_EACH
     * later. */
    nbrec_logical_switch_port_delete(lsp);
}

static void
nbctl_lsp_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, ctx->argv[1], must_exist);
    if (!lsp) {
        return;
    }

    /* Find the switch that contains 'lsp', then delete it. */
    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_FOR_EACH (ls, ctx->idl) {
        for (size_t i = 0; i < ls->n_ports; i++) {
            if (ls->ports[i] == lsp) {
                remove_lsp(ls, i);
                return;
            }
        }
    }

    /* Can't happen because of the database schema. */
    ctl_fatal("logical port %s is not part of any logical switch",
              ctx->argv[1]);
}

static void
nbctl_lsp_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *ls;
    struct smap lsps;
    size_t i;

    ls = ls_by_name_or_uuid(ctx, id, true);

    smap_init(&lsps);
    for (i = 0; i < ls->n_ports; i++) {
        const struct nbrec_logical_switch_port *lsp = ls->ports[i];
        smap_add_format(&lsps, lsp->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lsp->header_.uuid), lsp->name);
    }
    const struct smap_node **nodes = smap_sort(&lsps);
    for (i = 0; i < smap_count(&lsps); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lsps);
    free(nodes);
}

static void
nbctl_lsp_get_parent(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, ctx->argv[1], true);
    if (lsp->parent_name) {
        ds_put_format(&ctx->output, "%s\n", lsp->parent_name);
    }
}

static void
nbctl_lsp_get_tag(struct ctl_context *ctx)
{
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, ctx->argv[1], true);
    if (lport->n_tag > 0) {
        ds_put_format(&ctx->output, "%"PRId64"\n", lport->tag[0]);
    }
}

/* Set the address of lrport. */
static void
nbctl_lrport_set_mac(struct ctl_context *ctx)
{
    struct eth_addr ea;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router_port *lrport;

    lrport = lrport_by_name_or_uuid(ctx, id, true);

    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, ctx->argv[1], true);
    if (lsp->n_tag > 0) {
        ds_put_format(&ctx->output, "%"PRId64"\n", lsp->tag[0]);
    }
}

static void
nbctl_lsp_set_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, id, true);

    int i;
    for (i = 2; i < ctx->argc; i++) {
        struct eth_addr ea;

        if (strcmp(ctx->argv[i], "unknown")
            && !ovs_scan(ctx->argv[i], ETH_ADDR_SCAN_FMT,
                         ETH_ADDR_SCAN_ARGS(ea))) {
            ctl_fatal("%s: Invalid address format. See ovn-nb(5). "
                      "Hint: An Ethernet address must be "
                      "listed before an IP address, together as a single "
                      "argument.", ctx->argv[i]);
        }
    }

    nbrec_logical_switch_port_set_addresses(lsp,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

static void
nbctl_lsp_get_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp;
    struct svec addresses;
    const char *mac;
    size_t i;

    lsp = lsp_by_name_or_uuid(ctx, id, true);

    svec_init(&addresses);
    for (i = 0; i < lsp->n_addresses; i++) {
        svec_add(&addresses, lsp->addresses[i]);
    }
    svec_sort(&addresses);
    SVEC_FOR_EACH(i, mac, &addresses) {
        ds_put_format(&ctx->output, "%s\n", mac);
    }
    svec_destroy(&addresses);
}

static void
nbctl_lsp_set_port_security(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, id, true);
    nbrec_logical_switch_port_set_port_security(lsp,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

static void
nbctl_lsp_get_port_security(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp;
    struct svec addrs;
    const char *addr;
    size_t i;

    lsp = lsp_by_name_or_uuid(ctx, id, true);
    svec_init(&addrs);
    for (i = 0; i < lsp->n_port_security; i++) {
        svec_add(&addrs, lsp->port_security[i]);
    }
    svec_sort(&addrs);
    SVEC_FOR_EACH(i, addr, &addrs) {
        ds_put_format(&ctx->output, "%s\n", addr);
    }
    svec_destroy(&addrs);
}

static void
nbctl_lsp_get_up(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, id, true);
    ds_put_format(&ctx->output,
                  "%s\n", (lsp->up && *lsp->up) ? "up" : "down");
}

static bool
parse_enabled(const char *state)
{
    if (!strcasecmp(state, "enabled")) {
        return true;
    } else if (!strcasecmp(state, "disabled")) {
        return false;
    } else {
        ctl_fatal("%s: state must be \"enabled\" or \"disabled\"", state);
    }
}

static void
nbctl_lsp_set_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *state = ctx->argv[2];
    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, id, true);
    bool enabled = parse_enabled(state);
    nbrec_logical_switch_port_set_enabled(lsp, &enabled, 1);
}

static void
nbctl_lsp_get_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, id, true);
    ds_put_format(&ctx->output, "%s\n",
                  !lsp->enabled || *lsp->enabled ? "enabled" : "disabled");
}

static void
nbctl_lsp_set_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *type = ctx->argv[2];
    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, id, true);
    nbrec_logical_switch_port_set_type(lsp, type);
}

static void
nbctl_lsp_get_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp;

    lsp = lsp_by_name_or_uuid(ctx, id, true);
    ds_put_format(&ctx->output, "%s\n", lsp->type);
}

static void
nbctl_lsp_set_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp;
    size_t i;
    struct smap options = SMAP_INITIALIZER(&options);

    lsp = lsp_by_name_or_uuid(ctx, id, true);
    for (i = 2; i < ctx->argc; i++) {
        char *key, *value;
        value = xstrdup(ctx->argv[i]);
        key = strsep(&value, "=");
        if (value) {
            smap_add(&options, key, value);
        }
        free(key);
    }

    nbrec_logical_switch_port_set_options(lsp, &options);

    smap_destroy(&options);
}

static void
nbctl_lsp_get_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp;
    struct smap_node *node;

    lsp = lsp_by_name_or_uuid(ctx, id, true);
    SMAP_FOR_EACH(node, &lsp->options) {
        ds_put_format(&ctx->output, "%s=%s\n", node->key, node->value);
    }
}

enum {
    DIR_FROM_LPORT,
    DIR_TO_LPORT
};

static int
dir_encode(const char *dir)
{
    if (!strcmp(dir, "from-lport")) {
        return DIR_FROM_LPORT;
    } else if (!strcmp(dir, "to-lport")) {
        return DIR_TO_LPORT;
    }

    OVS_NOT_REACHED();
}

static int
acl_cmp(const void *acl1_, const void *acl2_)
{
    const struct nbrec_acl *const *acl1p = acl1_;
    const struct nbrec_acl *const *acl2p = acl2_;
    const struct nbrec_acl *acl1 = *acl1p;
    const struct nbrec_acl *acl2 = *acl2p;

    int dir1 = dir_encode(acl1->direction);
    int dir2 = dir_encode(acl2->direction);

    if (dir1 != dir2) {
        return dir1 < dir2 ? -1 : 1;
    } else if (acl1->priority != acl2->priority) {
        return acl1->priority > acl2->priority ? -1 : 1;
    } else {
        return strcmp(acl1->match, acl2->match);
    }
}

static void
nbctl_acl_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    const struct nbrec_acl **acls;
    size_t i;

    ls = ls_by_name_or_uuid(ctx, ctx->argv[1], true);

    acls = xmalloc(sizeof *acls * ls->n_acls);
    for (i = 0; i < ls->n_acls; i++) {
        acls[i] = ls->acls[i];
    }

    qsort(acls, ls->n_acls, sizeof *acls, acl_cmp);

    for (i = 0; i < ls->n_acls; i++) {
        const struct nbrec_acl *acl = acls[i];
        ds_put_format(&ctx->output, "%10s %5"PRId64" (%s) %s%s\n",
                      acl->direction, acl->priority,
                      acl->match, acl->action, acl->log ? " log" : "");
    }

    free(acls);
}

static const char *
parse_direction(const char *arg)
{
    /* Validate direction.  Only require the first letter. */
    if (arg[0] == 't') {
        return "to-lport";
    } else if (arg[0] == 'f') {
        return "from-lport";
    } else {
        ctl_fatal("%s: direction must be \"to-lport\" or \"from-lport\"", arg);
    }
}

static int
parse_priority(const char *arg)
{
    /* Validate priority. */
    int64_t priority;
    if (!ovs_scan(arg, "%"SCNd64, &priority)
        || priority < 0 || priority > 32767) {
        ctl_fatal("%s: priority must in range 0...32767", arg);
    }
    return priority;
}

static void
nbctl_acl_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    const char *action = ctx->argv[5];

    ls = ls_by_name_or_uuid(ctx, ctx->argv[1], true);

    const char *direction = parse_direction(ctx->argv[2]);
    int64_t priority = parse_priority(ctx->argv[3]);

    /* Validate action. */
    if (strcmp(action, "allow") && strcmp(action, "allow-related")
        && strcmp(action, "drop") && strcmp(action, "reject")) {
        ctl_fatal("%s: action must be one of \"allow\", \"allow-related\", "
                  "\"drop\", and \"reject\"", action);
        return;
    }

    /* Create the acl. */
    struct nbrec_acl *acl = nbrec_acl_insert(ctx->txn);
    nbrec_acl_set_priority(acl, priority);
    nbrec_acl_set_direction(acl, direction);
    nbrec_acl_set_match(acl, ctx->argv[4]);
    nbrec_acl_set_action(acl, action);
    if (shash_find(&ctx->options, "--log") != NULL) {
        nbrec_acl_set_log(acl, true);
    }

    /* Insert the acl into the logical switch. */
    nbrec_logical_switch_verify_acls(ls);
    struct nbrec_acl **new_acls = xmalloc(sizeof *new_acls * (ls->n_acls + 1));
    memcpy(new_acls, ls->acls, sizeof *new_acls * ls->n_acls);
    new_acls[ls->n_acls] = acl;
    nbrec_logical_switch_set_acls(ls, new_acls, ls->n_acls + 1);
    free(new_acls);
}

static void
nbctl_acl_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    ls = ls_by_name_or_uuid(ctx, ctx->argv[1], true);

    if (ctx->argc != 2 && ctx->argc != 3 && ctx->argc != 5) {
        ctl_fatal("cannot specify priority without match");
    }

    if (ctx->argc == 2) {
        /* If direction, priority, and match are not specified, delete
         * all ACLs. */
        nbrec_logical_switch_verify_acls(ls);
        nbrec_logical_switch_set_acls(ls, NULL, 0);
        return;
    }

    const char *direction = parse_direction(ctx->argv[2]);

    /* If priority and match are not specified, delete all ACLs with the
     * specified direction. */
    if (ctx->argc == 3) {
        struct nbrec_acl **new_acls = xmalloc(sizeof *new_acls * ls->n_acls);

        int n_acls = 0;
        for (size_t i = 0; i < ls->n_acls; i++) {
            if (strcmp(direction, ls->acls[i]->direction)) {
                new_acls[n_acls++] = ls->acls[i];
            }
        }

        nbrec_logical_switch_verify_acls(ls);
        nbrec_logical_switch_set_acls(ls, new_acls, n_acls);
        free(new_acls);
        return;
    }

    int64_t priority = parse_priority(ctx->argv[3]);

    /* Remove the matching rule. */
    for (size_t i = 0; i < ls->n_acls; i++) {
        struct nbrec_acl *acl = ls->acls[i];

        if (priority == acl->priority && !strcmp(ctx->argv[4], acl->match) &&
             !strcmp(direction, acl->direction)) {
            struct nbrec_acl **new_acls
                = xmemdup(ls->acls, sizeof *new_acls * ls->n_acls);
            new_acls[i] = ls->acls[ls->n_acls - 1];
            nbrec_logical_switch_verify_acls(ls);
            nbrec_logical_switch_set_acls(ls, new_acls,
                                          ls->n_acls - 1);
            free(new_acls);
            return;
        }
    }
}

static void
nbctl_lr_add(struct ctl_context *ctx)
{
    const char *lr_name = ctx->argc == 2 ? ctx->argv[1] : NULL;

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;
    if (may_exist && add_duplicate) {
        ctl_fatal("--may-exist and --add-duplicate may not be used together");
    }

    if (lr_name) {
        if (!add_duplicate) {
            const struct nbrec_logical_router *lr;
            NBREC_LOGICAL_ROUTER_FOR_EACH (lr, ctx->idl) {
                if (!strcmp(lr->name, lr_name)) {
                    if (may_exist) {
                        return;
                    }
                    ctl_fatal("%s: a router with this name already exists",
                              lr_name);
                }
            }
        }
    } else if (may_exist) {
        ctl_fatal("--may-exist requires specifying a name");
    } else if (add_duplicate) {
        ctl_fatal("--add-duplicate requires specifying a name");
    }

    struct nbrec_logical_router *lr;
    lr = nbrec_logical_router_insert(ctx->txn);
    if (lr_name) {
        nbrec_logical_router_set_name(lr, lr_name);
    }
}

static void
nbctl_lr_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router *lr;

    lr = lr_by_name_or_uuid(ctx, id, must_exist);
    if (!lr) {
        return;
    }

    nbrec_logical_router_delete(lr);
}

static void
nbctl_lr_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    struct smap lrs;

    smap_init(&lrs);
    NBREC_LOGICAL_ROUTER_FOR_EACH(lr, ctx->idl) {
        smap_add_format(&lrs, lr->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lr->header_.uuid), lr->name);
    }
    const struct smap_node **nodes = smap_sort(&lrs);
    for (size_t i = 0; i < smap_count(&lrs); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lrs);
    free(nodes);
}

/* The caller must free the returned string. */
static char *
normalize_ipv4_prefix(ovs_be32 ipv4, unsigned int plen)
{
    ovs_be32 network = ipv4 & be32_prefix_mask(plen);
    if (plen == 32) {
        return xasprintf(IP_FMT, IP_ARGS(network));
    } else {
        return xasprintf(IP_FMT"/%d", IP_ARGS(network), plen);
    }
}

/* The caller must free the returned string. */
static char *
normalize_ipv6_prefix(struct in6_addr ipv6, unsigned int plen)
{
    char network_s[INET6_ADDRSTRLEN];

    struct in6_addr mask = ipv6_create_mask(plen);
    struct in6_addr network = ipv6_addr_bitand(&ipv6, &mask);

    inet_ntop(AF_INET6, &network, network_s, INET6_ADDRSTRLEN);
    if (plen == 128) {
        return xasprintf("%s", network_s);
    } else {
        return xasprintf("%s/%d", network_s, plen);
    }
}

/* The caller must free the returned string. */
static char *
normalize_prefix_str(const char *orig_prefix)
{
    unsigned int plen;
    ovs_be32 ipv4;
    char *error;

    error = ip_parse_cidr(orig_prefix, &ipv4, &plen);
    if (!error) {
        return normalize_ipv4_prefix(ipv4, plen);
    } else {
        struct in6_addr ipv6;
        free(error);

        error = ipv6_parse_cidr(orig_prefix, &ipv6, &plen);
        if (error) {
            free(error);
            return NULL;
        }
        return normalize_ipv6_prefix(ipv6, plen);
    }
}

static void
nbctl_lr_route_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    lr = lr_by_name_or_uuid(ctx, ctx->argv[1], true);
    char *prefix, *next_hop;

    prefix = normalize_prefix_str(ctx->argv[2]);
    if (!prefix) {
        ctl_fatal("bad prefix argument: %s", ctx->argv[2]);
    }

    next_hop = normalize_prefix_str(ctx->argv[3]);
    if (!next_hop) {
        ctl_fatal("bad next hop argument: %s", ctx->argv[3]);
    }

    if (strchr(prefix, '.')) {
        ovs_be32 hop_ipv4;
        if (!ip_parse(ctx->argv[3], &hop_ipv4)) {
            ctl_fatal("bad IPv4 nexthop argument: %s", ctx->argv[3]);
        }
    } else {
        struct in6_addr hop_ipv6;
        if (!ipv6_parse(ctx->argv[3], &hop_ipv6)) {
            ctl_fatal("bad IPv6 nexthop argument: %s", ctx->argv[3]);
        }
    }

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    for (int i = 0; i < lr->n_static_routes; i++) {
        const struct nbrec_logical_router_static_route *route
            = lr->static_routes[i];
        char *rt_prefix;

        rt_prefix = normalize_prefix_str(lr->static_routes[i]->ip_prefix);
        if (!rt_prefix) {
            /* Ignore existing prefix we couldn't parse. */
            continue;
        }

        if (strcmp(rt_prefix, prefix)) {
            free(rt_prefix);
            continue;
        }

        if (!may_exist) {
            ctl_fatal("duplicate prefix: %s", prefix);
        }

        /* Update the next hop for an existing route. */
        nbrec_logical_router_verify_static_routes(lr);
        nbrec_logical_router_static_route_verify_ip_prefix(route);
        nbrec_logical_router_static_route_verify_nexthop(route);
        nbrec_logical_router_static_route_set_ip_prefix(route, prefix);
        nbrec_logical_router_static_route_set_nexthop(route, next_hop);
        free(rt_prefix);
        free(next_hop);
        free(prefix);
        return;
    }

    struct nbrec_logical_router_static_route *route;
    route = nbrec_logical_router_static_route_insert(ctx->txn);
    nbrec_logical_router_static_route_set_ip_prefix(route, prefix);
    nbrec_logical_router_static_route_set_nexthop(route, next_hop);
    if (ctx->argc == 5) {
        nbrec_logical_router_static_route_set_output_port(route, ctx->argv[4]);
    }

    nbrec_logical_router_verify_static_routes(lr);
    struct nbrec_logical_router_static_route **new_routes
        = xmalloc(sizeof *new_routes * (lr->n_static_routes + 1));
    memcpy(new_routes, lr->static_routes,
           sizeof *new_routes * lr->n_static_routes);
    new_routes[lr->n_static_routes] = route;
    nbrec_logical_router_set_static_routes(lr, new_routes,
                                           lr->n_static_routes + 1);
    free(new_routes);
    free(next_hop);
    free(prefix);
}

static void
nbctl_lr_route_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    lr = lr_by_name_or_uuid(ctx, ctx->argv[1], true);

    if (ctx->argc == 2) {
        /* If a prefix is not specified, delete all routes. */
        nbrec_logical_router_set_static_routes(lr, NULL, 0);
        return;
    }

    char *prefix = normalize_prefix_str(ctx->argv[2]);
    if (!prefix) {
        ctl_fatal("bad prefix argument: %s", ctx->argv[2]);
    }

    for (int i = 0; i < lr->n_static_routes; i++) {
        char *rt_prefix = normalize_prefix_str(lr->static_routes[i]->ip_prefix);
        if (!rt_prefix) {
            /* Ignore existing prefix we couldn't parse. */
            continue;
        }

        if (!strcmp(prefix, rt_prefix)) {
            struct nbrec_logical_router_static_route **new_routes
                = xmemdup(lr->static_routes,
                          sizeof *new_routes * lr->n_static_routes);

            new_routes[i] = lr->static_routes[lr->n_static_routes - 1];
            nbrec_logical_router_verify_static_routes(lr);
            nbrec_logical_router_set_static_routes(lr, new_routes,
                                                 lr->n_static_routes - 1);
            free(new_routes);
            free(rt_prefix);
            free(prefix);
            return;
        }
        free(rt_prefix);
    }

    if (!shash_find(&ctx->options, "--if-exists")) {
        ctl_fatal("no matching prefix: %s", prefix);
    }
    free(prefix);
}

static const struct nbrec_logical_router_port *
lrp_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist)
{
    const struct nbrec_logical_router_port *lrp = NULL;

    struct uuid lrp_uuid;
    bool is_uuid = uuid_from_string(&lrp_uuid, id);
    if (is_uuid) {
        lrp = nbrec_logical_router_port_get_for_uuid(ctx->idl, &lrp_uuid);
    }

    if (!lrp) {
        NBREC_LOGICAL_ROUTER_PORT_FOR_EACH(lrp, ctx->idl) {
            if (!strcmp(lrp->name, id)) {
                break;
            }
        }
    }

    if (!lrp && must_exist) {
        ctl_fatal("%s: port %s not found", id, is_uuid ? "UUID" : "name");
    }

    return lrp;
}

/* Returns the logical router that contains 'lrp'. */
static const struct nbrec_logical_router *
lrp_to_lr(const struct ovsdb_idl *idl,
               const struct nbrec_logical_router_port *lrp)
{
    const struct nbrec_logical_router *lr;
    NBREC_LOGICAL_ROUTER_FOR_EACH (lr, idl) {
        for (size_t i = 0; i < lr->n_ports; i++) {
            if (lr->ports[i] == lrp) {
                return lr;
            }
        }
    }

    /* Can't happen because of the database schema */
    ctl_fatal("port %s is not part of any logical router",
              lrp->name);
}

static const char *
lr_get_name(const struct nbrec_logical_router *lr, char uuid_s[UUID_LEN + 1],
            size_t uuid_s_size)
{
    if (lr->name[0]) {
        return lr->name;
    }
    snprintf(uuid_s, uuid_s_size, UUID_FMT, UUID_ARGS(&lr->header_.uuid));
    return uuid_s;
}

static void
nbctl_lrp_add(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;

    const struct nbrec_logical_router *lr;
    lr = lr_by_name_or_uuid(ctx, ctx->argv[1], true);

    const char *lrp_name = ctx->argv[2];
    const char *mac = ctx->argv[3];
    const char *network = ctx->argv[4];
    const char *peer = (ctx->argc == 6) ? ctx->argv[5] : NULL;

    const struct nbrec_logical_router_port *lrp;
    lrp = lrp_by_name_or_uuid(ctx, lrp_name, false);
    if (lrp) {
        if (!may_exist) {
            ctl_fatal("%s: a port with this name already exists",
                      lrp_name);
        }

        const struct nbrec_logical_router *bound_lr;
        bound_lr = lrp_to_lr(ctx->idl, lrp);
        if (bound_lr != lr) {
            char uuid_s[UUID_LEN + 1];
            ctl_fatal("%s: port already exists but in router %s", lrp_name,
                      lr_get_name(bound_lr, uuid_s, sizeof uuid_s));
        }

        if (strcmp(mac, lrp->mac)) {
            ctl_fatal("%s: port already exists with mac %s", lrp_name,
                      lrp->mac);
        }

        if (strcmp(network, lrp->network)) {
            ctl_fatal("%s: port already exists with network %s", lrp_name,
                      lrp->network);
        }

        if ((!peer != !lrp->peer) ||
                (lrp->peer && strcmp(peer, lrp->peer))) {
            ctl_fatal("%s: port already exists with mismatching peer",
                      lrp_name);
        }

        return;
    }

    struct eth_addr ea;
    if (!ovs_scan(mac, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(ea))) {
        ctl_fatal("%s: invalid mac address.", mac);
    }

    ovs_be32 ipv4;
    unsigned int plen;
    char *error = ip_parse_cidr(network, &ipv4, &plen);
    if (error) {
        free(error);
        struct in6_addr ipv6;
        error = ipv6_parse_cidr(network, &ipv6, &plen);
        if (error) {
            free(error);
            ctl_fatal("%s: invalid network address.", network);
        }
    }

    /* Create the logical port. */
    lrp = nbrec_logical_router_port_insert(ctx->txn);
    nbrec_logical_router_port_set_name(lrp, lrp_name);
    nbrec_logical_router_port_set_mac(lrp, mac);
    nbrec_logical_router_port_set_network(lrp, network);
    if (peer) {
        nbrec_logical_router_port_set_peer(lrp, peer);
    }

    /* Insert the logical port into the logical router. */
    nbrec_logical_router_verify_ports(lr);
    struct nbrec_logical_router_port **new_ports = xmalloc(sizeof *new_ports *
                                                        (lr->n_ports + 1));
    memcpy(new_ports, lr->ports, sizeof *new_ports * lr->n_ports);
    new_ports[lr->n_ports] = CONST_CAST(struct nbrec_logical_router_port *,
                                             lrp);
    nbrec_logical_router_set_ports(lr, new_ports, lr->n_ports + 1);
    free(new_ports);
}

/* Removes logical router port 'lr->ports[idx]'. */
static void
remove_lrp(const struct nbrec_logical_router *lr, size_t idx)
{
    const struct nbrec_logical_router_port *lrp = lr->ports[idx];

    /* First remove 'lrp' from the array of ports.  This is what will
     * actually cause the logical port to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_router_port **new_ports
        = xmemdup(lr->ports, sizeof *new_ports * lr->n_ports);
    new_ports[idx] = new_ports[lr->n_ports - 1];
    nbrec_logical_router_verify_ports(lr);
    nbrec_logical_router_set_ports(lr, new_ports, lr->n_ports - 1);
    free(new_ports);

    /* Delete 'lrp' from the IDL.  This won't have a real effect on
     * the database server (the IDL will suppress it in fact) but it
     * means that it won't show up when we iterate with
     * NBREC_LOGICAL_ROUTER_PORT_FOR_EACH later. */
    nbrec_logical_router_port_delete(lrp);
}

static void
nbctl_lrp_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct nbrec_logical_router_port *lrp;

    lrp = lrp_by_name_or_uuid(ctx, ctx->argv[1], must_exist);
    if (!lrp) {
        return;
    }

    /* Find the router that contains 'lrp', then delete it. */
    const struct nbrec_logical_router *lr;
    NBREC_LOGICAL_ROUTER_FOR_EACH (lr, ctx->idl) {
        for (size_t i = 0; i < lr->n_ports; i++) {
            if (lr->ports[i] == lrp) {
                remove_lrp(lr, i);
                return;
            }
        }
    }

    /* Can't happen because of the database schema. */
    ctl_fatal("logical port %s is not part of any logical router",
              ctx->argv[1]);
}

/* Print a list of logical router ports. */
static void
nbctl_lrp_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router *lr;
    struct smap lrps;
    size_t i;

    lr = lr_by_name_or_uuid(ctx, id, true);

    smap_init(&lrps);
    for (i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        smap_add_format(&lrps, lrp->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lrp->header_.uuid), lrp->name);
    }
    const struct smap_node **nodes = smap_sort(&lrps);
    for (i = 0; i < smap_count(&lrps); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lrps);
    free(nodes);
}

/* Set the logical router port admin-enabled state. */
static void
nbctl_lrp_set_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *state = ctx->argv[2];
    const struct nbrec_logical_router_port *lrp;

    lrp = lrp_by_name_or_uuid(ctx, id, true);
    if (!lrp) {
        return;
    }

    bool enabled = parse_enabled(state);
    nbrec_logical_router_port_set_enabled(lrp, &enabled, 1);
}

/* Print admin-enabled state for logical router port. */
static void
nbctl_lrp_get_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router_port *lrp;

    lrp = lrp_by_name_or_uuid(ctx, id, true);
    if (!lrp) {
        return;
    }

    ds_put_format(&ctx->output, "%s\n",
                  !lrp->enabled ||
                  *lrp->enabled ? "enabled" : "disabled");
}

struct ipv4_route {
    int plen;
    ovs_be32 addr;
    const struct nbrec_logical_router_static_route *route;
};

static int
ipv4_route_cmp(const void *route1_, const void *route2_)
{
    const struct ipv4_route *route1p = route1_;
    const struct ipv4_route *route2p = route2_;

    if (route1p->plen != route2p->plen) {
        return route1p->plen > route2p->plen ? -1 : 1;
    } else if (route1p->addr != route2p->addr) {
        return ntohl(route1p->addr) < ntohl(route2p->addr) ? -1 : 1;
    } else {
        return 0;
    }
}

struct ipv6_route {
    int plen;
    struct in6_addr addr;
    const struct nbrec_logical_router_static_route *route;
};

static int
ipv6_route_cmp(const void *route1_, const void *route2_)
{
    const struct ipv6_route *route1p = route1_;
    const struct ipv6_route *route2p = route2_;

    if (route1p->plen != route2p->plen) {
        return route1p->plen > route2p->plen ? -1 : 1;
    }
    return memcmp(&route1p->addr, &route2p->addr, sizeof(route1p->addr));
}

static void
print_route(const struct nbrec_logical_router_static_route *route, struct ds *s)
{

    char *prefix = normalize_prefix_str(route->ip_prefix);
    char *next_hop = normalize_prefix_str(route->nexthop);
    ds_put_format(s, "%25s %25s", prefix, next_hop);
    free(prefix);
    free(next_hop);

    if (route->output_port) {
        ds_put_format(s, " %s", route->output_port);
    }
    ds_put_char(s, '\n');
}

static void
nbctl_lr_route_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    struct ipv4_route *ipv4_routes;
    struct ipv6_route *ipv6_routes;
    size_t n_ipv4_routes = 0;
    size_t n_ipv6_routes = 0;

    lr = lr_by_name_or_uuid(ctx, ctx->argv[1], true);

    ipv4_routes = xmalloc(sizeof *ipv4_routes * lr->n_static_routes);
    ipv6_routes = xmalloc(sizeof *ipv6_routes * lr->n_static_routes);

    for (int i = 0; i < lr->n_static_routes; i++) {
        const struct nbrec_logical_router_static_route *route
            = lr->static_routes[i];
        unsigned int plen;
        ovs_be32 ipv4;
        char *error;

        error = ip_parse_cidr(route->ip_prefix, &ipv4, &plen);
        if (!error) {
            ipv4_routes[n_ipv4_routes].plen = plen;
            ipv4_routes[n_ipv4_routes].addr = ipv4;
            ipv4_routes[n_ipv4_routes].route = route;
            n_ipv4_routes++;
        } else {
            free(error);

            struct in6_addr ipv6;
            if (!ipv6_parse_cidr(route->ip_prefix, &ipv6, &plen)) {
                ipv6_routes[n_ipv6_routes].plen = plen;
                ipv6_routes[n_ipv6_routes].addr = ipv6;
                ipv6_routes[n_ipv6_routes].route = route;
                n_ipv6_routes++;
            } else {
                /* Invalid prefix. */
                VLOG_WARN("router "UUID_FMT" (%s) has invalid prefix: %s",
                          UUID_ARGS(&lr->header_.uuid), lr->name,
                          route->ip_prefix);
                free(error);
                continue;
            }
        }
    }

    qsort(ipv4_routes, n_ipv4_routes, sizeof *ipv4_routes, ipv4_route_cmp);
    qsort(ipv6_routes, n_ipv6_routes, sizeof *ipv6_routes, ipv6_route_cmp);

    if (n_ipv4_routes) {
        ds_put_cstr(&ctx->output, "IPv4 Routes\n");
    }
    for (int i = 0; i < n_ipv4_routes; i++) {
        print_route(ipv4_routes[i].route, &ctx->output);
    }

    if (n_ipv6_routes) {
        ds_put_format(&ctx->output, "%sIPv6 Routes\n",
                      n_ipv4_routes ?  "\n" : "");
    }
    for (int i = 0; i < n_ipv6_routes; i++) {
        print_route(ipv6_routes[i].route, &ctx->output);
    }

    free(ipv4_routes);
    free(ipv6_routes);
}

static const struct ctl_table_class tables[] = {
    {&nbrec_table_logical_switch,
     {{&nbrec_table_logical_switch, &nbrec_logical_switch_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_logical_port_chain,
     {{&nbrec_table_logical_port_chain, &nbrec_logical_port_chain_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_logical_port_pair_group,
     {{&nbrec_table_logical_port_pair_group, &nbrec_logical_port_pair_group_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_logical_port_pair,
     {{&nbrec_table_logical_port_pair, &nbrec_logical_port_pair_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_logical_flow_classifier,
     {{&nbrec_table_logical_flow_classifier, &nbrec_logical_flow_classifier_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_logical_port,
     {{&nbrec_table_logical_port, &nbrec_logical_port_col_name, NULL},

    {&nbrec_table_logical_switch_port,
     {{&nbrec_table_logical_switch_port, &nbrec_logical_switch_port_col_name,
       NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_acl,
     {{NULL, NULL, NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_logical_router,
     {{&nbrec_table_logical_router, &nbrec_logical_router_col_name, NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_logical_router_port,
     {{&nbrec_table_logical_router_port, &nbrec_logical_router_port_col_name,
       NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_logical_router_static_route,
     {{&nbrec_table_logical_router_static_route, NULL,
       NULL},
      {NULL, NULL, NULL}}},

    {&nbrec_table_nat,
     {{&nbrec_table_nat, NULL,
       NULL},
      {NULL, NULL, NULL}}},

    {NULL, {{NULL, NULL, NULL}, {NULL, NULL, NULL}}}
};

static void
run_prerequisites(struct ctl_command *commands, size_t n_commands,
                  struct ovsdb_idl *idl)
{
    struct ctl_command *c;

    for (c = commands; c < &commands[n_commands]; c++) {
        if (c->syntax->prerequisites) {
            struct ctl_context ctx;

            ds_init(&c->output);
            c->table = NULL;

            ctl_context_init(&ctx, c, idl, NULL, NULL, NULL);
            (c->syntax->prerequisites)(&ctx);
            ctl_context_done(&ctx, c);

            ovs_assert(!c->output.string);
            ovs_assert(!c->table);
        }
    }
}

static bool
do_nbctl(const char *args, struct ctl_command *commands, size_t n_commands,
         struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;
    enum ovsdb_idl_txn_status status;
    struct ovsdb_symbol_table *symtab;
    struct ctl_context ctx;
    struct ctl_command *c;
    struct shash_node *node;
    char *error = NULL;

    txn = the_idl_txn = ovsdb_idl_txn_create(idl);
    if (dry_run) {
        ovsdb_idl_txn_set_dry_run(txn);
    }

    ovsdb_idl_txn_add_comment(txn, "ovs-nbctl: %s", args);

    symtab = ovsdb_symbol_table_create();
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_init(&c->output);
        c->table = NULL;
    }
    ctl_context_init(&ctx, NULL, idl, txn, symtab, NULL);
    for (c = commands; c < &commands[n_commands]; c++) {
        ctl_context_init_command(&ctx, c);
        if (c->syntax->run) {
            (c->syntax->run)(&ctx);
        }
        ctl_context_done_command(&ctx, c);

        if (ctx.try_again) {
            ctl_context_done(&ctx, NULL);
            goto try_again;
        }
    }
    ctl_context_done(&ctx, NULL);

    SHASH_FOR_EACH (node, &symtab->sh) {
        struct ovsdb_symbol *symbol = node->data;
        if (!symbol->created) {
            ctl_fatal("row id \"%s\" is referenced but never created (e.g. "
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
    if (status == TXN_UNCHANGED || status == TXN_SUCCESS) {
        for (c = commands; c < &commands[n_commands]; c++) {
            if (c->syntax->postprocess) {
                ctl_context_init(&ctx, c, idl, txn, symtab, NULL);
                (c->syntax->postprocess)(&ctx);
                ctl_context_done(&ctx, c);
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
        ctl_fatal("transaction aborted");

    case TXN_UNCHANGED:
    case TXN_SUCCESS:
        break;

    case TXN_TRY_AGAIN:
        goto try_again;

    case TXN_ERROR:
        ctl_fatal("transaction error: %s", error);

    case TXN_NOT_LOCKED:
        /* Should not happen--we never call ovsdb_idl_set_lock(). */
        ctl_fatal("database not locked");

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
    ovsdb_idl_txn_destroy(txn);
    ovsdb_idl_destroy(idl);

    return true;

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
    return false;
}

/* Frees the current transaction and the underlying IDL and then calls
 * exit(status).
 *
 * Freeing the transaction and the IDL is not strictly necessary, but it makes
 * for a clean memory leak report from valgrind in the normal case.  That makes
 * it easier to notice real memory leaks. */
static void
nbctl_exit(int status)
{
    if (the_idl_txn) {
        ovsdb_idl_txn_abort(the_idl_txn);
        ovsdb_idl_txn_destroy(the_idl_txn);
    }
    ovsdb_idl_destroy(the_idl);
    exit(status);
}

static const struct ctl_command_syntax nbctl_commands[] = {
    { "show", 0, 1, "[SWITCH]", NULL, nbctl_show, NULL, "", RO },

    /* lport-chain commands. */
    { "lport-chain-add", 1, 2, "LSWITCH,[LPORT-CHAIN]", NULL, nbctl_lport_chain_add,
      NULL, "", RW },
    { "lport-chain-del", 1, 1, "LPORT-CHAIN", NULL, nbctl_lport_chain_del,
      NULL, "--if-exists", RW },
    { "lport-chain-list", 1, 1, "LSWITCH", NULL, nbctl_lport_chain_list, NULL, "", RO },
    { "lport-chain-show", 1, 2, "LSWITCH [LPORT-CHAIN]", NULL, nbctl_lport_chain_show, NULL, "", RO },
    { "lport-chain-get-flow-classifier", 1, 1, "LPORT-CHAIN", NULL, 
      nbctl_lport_chain_get_flow_classifier, NULL, "", RO },
    { "lport-chain-set-flow-classifier", 2, 2, "LPORT-CHAIN LFLOW-CLASSIFIER", NULL, 
      nbctl_lport_chain_set_flow_classifier, NULL, "", RW },

    /* lport-pair-group commands. */
    { "lport-pair-group-add", 1, 2, "LPORT-CHAIN [LPORT-PAIR-GROUP]", 
      NULL, nbctl_lport_pair_group_add, NULL, "", RW },
    { "lport-pair-group-del", 2, 2, "LPORT-CHAIN, LPORT-PAIR-GROUP", NULL, nbctl_lport_pair_group_del,
      NULL, "", RW },
    { "lport-pair-group-list", 1, 1, "LPORT_CHAIN", NULL, nbctl_lport_pair_group_list, NULL, "", RO },
    { "lport-pair-group-add-port-pair", 2, 2, "LPORT-PAIR-GROUP LPORT-PAIR", 
      NULL, nbctl_lport_pair_group_add_port_pair, NULL, "", RW },
    { "lport-pair-group-del-port-pair", 2, 2, "LPORT-PAIR-GROUP LPORT-PAIR", 
      NULL, nbctl_lport_pair_group_del_port_pair, NULL, "", RW },

    /* lport-pair commands. */
    { "lport-pair-add", 3, 4, "LSWITCH, LPORT, LPORT [LPORT_PAIR_NAME]", NULL, nbctl_lport_pair_add,
      NULL, "", RW },
    { "lport-pair-del", 1, 1, "LPORT-PAIR", NULL, nbctl_lport_pair_del,
      NULL, "", RW },
    { "lport-pair-list", 1, 1, "LSWITCH", NULL, nbctl_lport_pair_list, NULL, "", RO },

   /* lflow-classifier commands. */
    { "lflow-classifier-add", 2, 3, "LPORT-CHAIN LSOURCE_PORT [LFLOW-CLASSIFIER-NAME]", NULL, 
      nbctl_lflow_classifier_add, NULL, "", RW },
    { "lflow-classifier-del", 1, 1, "LFLOW-CLASSIFIER", NULL, 
      nbctl_lflow_classifier_del, NULL, "", RW },
    { "lflow-classifier-list", 1, 1, "LPORT-CHAIN", NULL, nbctl_lflow_classifier_list,
      NULL, "", RO },
    { "lflow-classifier-get-logical-destination-port", 1, 1, "LFLOW-CLASSIFIER", NULL, 
      nbctl_lflow_classifier_get_logical_destination_port, NULL, "", RO },
    { "lflow-classifier-set-logical-destination-port", 1, 1, "LFLOW-CLASSIFIER [LDESTINATION_PORT", NULL, 
      nbctl_lflow_classifier_set_logical_destination_port, NULL, "", RO },
    /* TODO ADD OTHER FLOW-CLASSIFIER PARAMETERS */

    /* lrouter commands. */
    { "lrouter-add", 0, 1, "[LROUTER]", NULL, nbctl_lrouter_add,
      NULL, "--may-exist,--add-duplicate", RW },
    { "lrouter-del", 1, 1, "LROUTER", NULL, nbctl_lrouter_del,
      NULL, "--if-exists", RW },
    { "lrouter-list", 0, 0, "", NULL, nbctl_lrouter_list, NULL, "", RO },

    /* logical switch commands. */
    { "ls-add", 0, 1, "[SWITCH]", NULL, nbctl_ls_add, NULL,
      "--may-exist,--add-duplicate", RW },
    { "ls-del", 1, 1, "SWITCH", NULL, nbctl_ls_del, NULL, "--if-exists", RW },
    { "ls-list", 0, 0, "", NULL, nbctl_ls_list, NULL, "", RO },

    /* acl commands. */
    { "acl-add", 5, 5, "SWITCH DIRECTION PRIORITY MATCH ACTION", NULL,
      nbctl_acl_add, NULL, "--log", RW },
    { "acl-del", 1, 4, "SWITCH [DIRECTION [PRIORITY MATCH]]", NULL,
      nbctl_acl_del, NULL, "", RW },
    { "acl-list", 1, 1, "SWITCH", NULL, nbctl_acl_list, NULL, "", RO },

    /* logical switch port commands. */
    { "lsp-add", 2, 4, "SWITCH PORT [PARENT] [TAG]", NULL, nbctl_lsp_add,
      NULL, "--may-exist", RW },
    { "lsp-del", 1, 1, "PORT", NULL, nbctl_lsp_del, NULL, "--if-exists", RW },
    { "lsp-list", 1, 1, "SWITCH", NULL, nbctl_lsp_list, NULL, "", RO },
    { "lsp-get-parent", 1, 1, "PORT", NULL, nbctl_lsp_get_parent, NULL,
      "", RO },
    { "lsp-get-tag", 1, 1, "PORT", NULL, nbctl_lsp_get_tag, NULL, "", RO },
    { "lsp-set-addresses", 1, INT_MAX, "PORT [ADDRESS]...", NULL,
      nbctl_lsp_set_addresses, NULL, "", RW },
    { "lsp-get-addresses", 1, 1, "PORT", NULL, nbctl_lsp_get_addresses, NULL,
      "", RO },
    { "lsp-set-port-security", 0, INT_MAX, "PORT [ADDRS]...", NULL,
      nbctl_lsp_set_port_security, NULL, "", RW },
    { "lsp-get-port-security", 1, 1, "PORT", NULL,
      nbctl_lsp_get_port_security, NULL, "", RO },
    { "lsp-get-up", 1, 1, "PORT", NULL, nbctl_lsp_get_up, NULL, "", RO },
    { "lsp-set-enabled", 2, 2, "PORT STATE", NULL, nbctl_lsp_set_enabled,
      NULL, "", RW },
    { "lsp-get-enabled", 1, 1, "PORT", NULL, nbctl_lsp_get_enabled, NULL,
      "", RO },
    { "lsp-set-type", 2, 2, "PORT TYPE", NULL, nbctl_lsp_set_type, NULL,
      "", RW },
    { "lsp-get-type", 1, 1, "PORT", NULL, nbctl_lsp_get_type, NULL, "", RO },
    { "lsp-set-options", 1, INT_MAX, "PORT KEY=VALUE [KEY=VALUE]...", NULL,
      nbctl_lsp_set_options, NULL, "", RW },
    { "lsp-get-options", 1, 1, "PORT", NULL, nbctl_lsp_get_options, NULL,
      "", RO },

    /* logical router commands. */
    { "lr-add", 0, 1, "[ROUTER]", NULL, nbctl_lr_add, NULL,
      "--may-exist,--add-duplicate", RW },
    { "lr-del", 1, 1, "ROUTER", NULL, nbctl_lr_del, NULL, "--if-exists", RW },
    { "lr-list", 0, 0, "", NULL, nbctl_lr_list, NULL, "", RO },

    /* logical router port commands. */
    { "lrp-add", 4, 5, "ROUTER PORT MAC NETWORK [PEER]", NULL, nbctl_lrp_add,
      NULL, "--may-exist", RW },
    { "lrp-del", 1, 1, "LPORT", NULL, nbctl_lrp_del, NULL, "--if-exists", RW },
    { "lrp-list", 1, 1, "ROUTER", NULL, nbctl_lrp_list, NULL, "", RO },
    { "lrp-set-enabled", 2, 2, "PORT STATE", NULL, nbctl_lrp_set_enabled,
      NULL, "", RW },
    { "lrp-get-enabled", 1, 1, "PORT", NULL, nbctl_lrp_get_enabled,
      NULL, "", RO },

    /* logical router route commands. */
    { "lr-route-add", 3, 4, "ROUTER PREFIX NEXTHOP [PORT]", NULL,
      nbctl_lr_route_add, NULL, "--may-exist", RW },
    { "lr-route-del", 1, 2, "ROUTER [PREFIX]", NULL, nbctl_lr_route_del,
      NULL, "--if-exists", RW },
    { "lr-route-list", 1, 1, "ROUTER", NULL, nbctl_lr_route_list, NULL,
      "", RO },
    {NULL, 0, 0, NULL, NULL, NULL, NULL, "", RO},
};

/* Registers nbctl and common db commands. */
static void
nbctl_cmd_init(void)
{
    ctl_init(tables, NULL, nbctl_exit);
    ctl_register_commands(nbctl_commands);
}
