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
  show LSWITCH              print overview of database contents for LSWITCH\n\
  show LROUTER              print overview of database contents for LROUTER\n\
\n\
Logical switch commands:\n\
  lswitch-add [LSWITCH]     create a logical switch named LSWITCH\n\
  lswitch-del LSWITCH       delete LSWITCH and all its ports\n\
  lswitch-list              print the names of all logical switches\n\
\n\
Logical port-chain commands:\n\
  lport-chain-add [LPORT-CHAIN]     create a logical port-chain named LPORT-CHAIN\n\
  lport-chain-del LPORT-CHAIN       delete LPORT-CHAIN but not FLOW-CLASSIFIER\n\
  lport-chain-list              print the names of all logical port-chains\n\
  lport-chain-set-flow-classifier LPORT_CHAIN LFLOW_CLASSIFIER set the name of the flow classifier\n\
  lport-chain-get-flow-classifier LPORT_CHAIN get the name of the flow classifier \n\
\n\
Logical port-pair-groups commands:\n\
  lport-pair-group-add LPORT-CHAIN [LPORT-PAIR_GROUP-NAME]\n\
                           create a logical port-pair-group \n\
  lport-pair-group-del LPORT-PAIR-GROUP-NAME    delete a port-pair-group, does not delete port-pairs\n\
                                      or flow-classifier\n\
  lport-pair-group-list LPORT-CHAIN   print the names of all logical port-pair-groups\n\
  lport-pair-group-add-port-pair LPORT-PAIR-GROUP LPORT-PAIR add a port pair to a port-group\n\
  lport-pair-group-del-port-pair LPORT-PAIR-GROUP LPORT-PAIR del a port pair from a port-group\n\
\n\
logical port-pair commands:\n\
  lport-pair-add LSWITCH LIN-PORT LOUT-PORT [LPORT-PAIR-NAME]\n\
                           create a logical port-pair \n\
  lport-pair-del LPORT-PAIR-NAME    delete a port-pair, does not delete ports\n\
  lport-pair-list            print the names of all logical port-pairs\n\
\n\
logical flow-classifier commands:\n\
  lflow-classifier-add LSWITCH LIN-PORT [LFLOW-CLASSIFIER-NAME]\n\
                           create a logical flow-classifer \n\
  lflow-classifier-del LFLOW-CLASSIFIER-NAME    delete a flow-classifier, does not delete ports\n\
  lflow-classifier-list LSWITCH            print the names of all logical flow-classifiers on a switch\n\
  lflow-classifier-set-logical-destination-port LFLOW_CLASSIFIER [LDEST_PORT] set the name of ldest port |n\
  lflow-classifier-get-logical-destination-port LFLOW_CLASSIFIER  get the name of ldest port |n\
\n\
Logical router commands:\n\
  lrouter-add [LROUTER]     create a logical router named LROUTER\n\
  lrouter-del LROUTER       delete LROUTER and all its ports\n\
  lrouter-list              print the names of all logical routers\n\
\n\
ACL commands:\n\
  acl-add LSWITCH DIRECTION PRIORITY MATCH ACTION [log]\n\
                            add an ACL to LSWITCH\n\
  acl-del LSWITCH [DIRECTION [PRIORITY MATCH]]\n\
                            remove ACLs from LSWITCH\n\
  acl-list LSWITCH          print ACLs for LSWITCH\n\
\n\
Logical router port commands:\n\
  lrport-add LROUTER LRPORT   add logical router port LRPORT to LROUTER\n\
  lrport-del LRPORT           delete LRPORT from its attached router\n\
  lrport-list LROUTER        print the names of all logical ports on LROUTER\n\
  lrport-set-mac-address LRPORT [ADDRESS]\n\
                            set MAC address for LRPORT.\n\
  lrport-get-mac-address LRPORT      get MAC addresses on LRPORT\n\
  lrport-set-enabled LRPORT STATE\n\
                            set administrative state LRPORT\n\
                            ('enabled' or 'disabled')\n\
  lrport-get-enabled LRPORT   get administrative state LRPORT\n\
                            ('enabled' or 'disabled')\n\
\n\
Logical port commands:\n\
  lport-add LSWITCH LPORT   add logical port LPORT on LSWITCH\n\
  lport-add LSWITCH LPORT PARENT TAG\n\
                            add logical port LPORT on LSWITCH with PARENT\n\
                            on TAG\n\
  lport-del LPORT           delete LPORT from its attached switch\n\
  lport-list LSWITCH        print the names of all logical ports on LSWITCH\n\
  lport-get-parent LPORT    get the parent of LPORT if set\n\
  lport-get-tag LPORT       get the LPORT's tag if set\n\
  lport-set-addresses LPORT [ADDRESS]...\n\
                            set MAC or MAC+IP addresses for LPORT.\n\
  lport-get-addresses LPORT      get a list of MAC addresses on LPORT\n\
  lport-set-port-security LPORT [ADDRS]...\n\
                            set port security addresses for LPORT.\n\
  lport-get-port-security LPORT    get LPORT's port security addresses\n\
  lport-get-up LPORT        get state of LPORT ('up' or 'down')\n\
  lport-set-enabled LPORT STATE\n\
                            set administrative state LPORT\n\
                            ('enabled' or 'disabled')\n\
  lport-get-enabled LPORT   get administrative state LPORT\n\
                            ('enabled' or 'disabled')\n\
  lport-set-type LPORT TYPE Set the type for LPORT\n\
  lport-get-type LPORT      Get the type for LPORT\n\
  lport-set-options LPORT KEY=VALUE [KEY=VALUE]...\n\
                            Set options related to the type of LPORT\n\
  lport-get-options LPORT   Get the type specific options for LPORT\n\
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


/* Find an lrouter given its id. */
static const struct nbrec_logical_router *
lrouter_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                        bool must_exist)
{
    const struct nbrec_logical_router *lrouter = NULL;
    bool is_uuid = false;
    struct uuid lrouter_uuid;

    if (uuid_from_string(&lrouter_uuid, id)) {
        is_uuid = true;
        lrouter = nbrec_logical_router_get_for_uuid(ctx->idl,
                                                    &lrouter_uuid);
    }

    if (!lrouter) {
        const struct nbrec_logical_router *iter;

        NBREC_LOGICAL_ROUTER_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (lrouter) {
                ctl_fatal("Multiple logical routers named '%s'.  "
                          "Use a UUID.", id);
            }
            lrouter = iter;
        }
    }

    if (!lrouter && must_exist) {
        ctl_fatal("%s: lrouter %s not found", id, is_uuid ? "UUID" : "name");
    }

    return lrouter;
}

static const struct nbrec_logical_switch *
lswitch_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                        bool must_exist)
{
    const struct nbrec_logical_switch *lswitch = NULL;

    struct uuid lswitch_uuid;
    bool is_uuid = uuid_from_string(&lswitch_uuid, id);
    if (is_uuid) {
        lswitch = nbrec_logical_switch_get_for_uuid(ctx->idl, &lswitch_uuid);
    }

    if (!lswitch) {
        const struct nbrec_logical_switch *iter;

        NBREC_LOGICAL_SWITCH_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (lswitch) {
                ctl_fatal("Multiple logical switches named '%s'.  "
                          "Use a UUID.", id);
            }
            lswitch = iter;
        }
    }

    if (!lswitch && must_exist) {
        ctl_fatal("%s: lswitch %s not found", id, is_uuid ? "UUID" : "name");
    }

    return lswitch;
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
	printf("found lport_pair_group %s\n",id);
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
/* Given pointer to lrouter, this routine prints the lrouter information.  */
static void
print_lrouter(const struct nbrec_logical_router *lrouter, struct ds *s)
{
    ds_put_format(s, "    lrouter "UUID_FMT" (%s)\n",
                  UUID_ARGS(&lrouter->header_.uuid), lrouter->name);

    for (size_t i = 0; i < lrouter->n_ports; i++) {
        const struct nbrec_logical_router_port *lrport = lrouter->ports[i];
        ds_put_format(s, "        lrport %s\n", lrport->name);
        if (lrport->mac) {
            ds_put_cstr(s, "            mac: ");
            ds_put_format(s, "\"%s\"", lrport->mac);
        }
        ds_put_format(s, "\n");
    }
}

static void
print_lswitch(const struct nbrec_logical_switch *lswitch, struct ds *s)
{
    ds_put_format(s, "    lswitch "UUID_FMT" (%s)\n",
                  UUID_ARGS(&lswitch->header_.uuid), lswitch->name);

    for (size_t i = 0; i < lswitch->n_ports; i++) {
        const struct nbrec_logical_port *lport = lswitch->ports[i];

        ds_put_format(s, "        lport %s\n", lport->name);
        if (lport->parent_name) {
            ds_put_format(s, "            parent: %s\n", lport->parent_name);
        }
        if (lport->n_tag) {
            ds_put_format(s, "            tag: %"PRIu64"\n", lport->tag[0]);
        }
        if (lport->n_addresses) {
            ds_put_cstr(s, "            addresses: [");
            for (size_t j = 0; j < lport->n_addresses; j++) {
                ds_put_format(s, "%s\"%s\"",
                        j == 0 ? "" : ", ",
                        lport->addresses[j]);
            }
            ds_put_cstr(s, "]\n");
        }
    }
}

static void
nbctl_show(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *lswitch;

    if (ctx->argc == 2) {
        lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1], false);
        if (lswitch) {
            print_lswitch(lswitch, &ctx->output);
        }
    } else {
        NBREC_LOGICAL_SWITCH_FOR_EACH(lswitch, ctx->idl) {
            print_lswitch(lswitch, &ctx->output);
        }
    }
    const struct nbrec_logical_router *lrouter;

    if (ctx->argc == 2) {
        lrouter = lrouter_by_name_or_uuid(ctx, ctx->argv[1], false);
        if (lrouter) {
            print_lrouter(lrouter, &ctx->output);
        }
    } else {
        NBREC_LOGICAL_ROUTER_FOR_EACH(lrouter, ctx->idl) {
            print_lrouter(lrouter, &ctx->output);
        }
    }
}

/* Add an lrouter. */
static void
nbctl_lrouter_add(struct ctl_context *ctx)
{
    const char *lrouter_name = ctx->argc == 2 ? ctx->argv[1] : NULL;

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;
    if (may_exist && add_duplicate) {
        ctl_fatal("--may-exist and --add-duplicate may not be used together");
    }

    if (lrouter_name) {
        if (!add_duplicate) {
            const struct nbrec_logical_router *lrouter;
            NBREC_LOGICAL_ROUTER_FOR_EACH (lrouter, ctx->idl) {
                if (!strcmp(lrouter->name, lrouter_name)) {
                    if (may_exist) {
                        return;
                    }
                    ctl_fatal("%s: an lrouter with this name already exists",
                              lrouter_name);
                }
            }
        }
    } else if (may_exist) {
        ctl_fatal("--may-exist requires specifying a name");
    } else if (add_duplicate) {
        ctl_fatal("--add-duplicate requires specifying a name");
    }

    struct nbrec_logical_router *lrouter;
    lrouter = nbrec_logical_router_insert(ctx->txn);
    if (lrouter_name) {
        nbrec_logical_router_set_name(lrouter, lrouter_name);
    }
}

/* Delete an lrouter. */
static void
nbctl_lrouter_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router *lrouter;

    lrouter = lrouter_by_name_or_uuid(ctx, id, must_exist);
    if (!lrouter) {
        return;
    }

    nbrec_logical_router_delete(lrouter);
}

/* Print list of lrouters. */
static void
nbctl_lrouter_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lrouter;
    struct smap lrouters;

    smap_init(&lrouters);
    NBREC_LOGICAL_ROUTER_FOR_EACH (lrouter, ctx->idl) {
        smap_add_format(&lrouters, lrouter->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lrouter->header_.uuid), lrouter->name);
    }
    const struct smap_node **nodes = smap_sort(&lrouters);
    for (size_t i = 0; i < smap_count(&lrouters); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lrouters);
    free(nodes);
}

static void
nbctl_lswitch_add(struct ctl_context *ctx)
{
    const char *lswitch_name = ctx->argc == 2 ? ctx->argv[1] : NULL;

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;
    if (may_exist && add_duplicate) {
        ctl_fatal("--may-exist and --add-duplicate may not be used together");
    }

    if (lswitch_name) {
        if (!add_duplicate) {
            const struct nbrec_logical_switch *lswitch;
            NBREC_LOGICAL_SWITCH_FOR_EACH(lswitch, ctx->idl) {
                if (!strcmp(lswitch->name, lswitch_name)) {
                    if (may_exist) {
                        return;
                    }
                    ctl_fatal("%s: an lswitch with this name already exists",
                              lswitch_name);
                }
            }
        }
    } else if (may_exist) {
        ctl_fatal("--may-exist requires specifying a name");
    } else if (add_duplicate) {
        ctl_fatal("--add-duplicate requires specifying a name");
    }

    struct nbrec_logical_switch *lswitch;
    lswitch = nbrec_logical_switch_insert(ctx->txn);
    if (lswitch_name) {
        nbrec_logical_switch_set_name(lswitch, lswitch_name);
    }
}

static void
nbctl_lswitch_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;

    lswitch = lswitch_by_name_or_uuid(ctx, id, must_exist);
    if (!lswitch) {
        return;
    }

    nbrec_logical_switch_delete(lswitch);
}

static void
nbctl_lswitch_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *lswitch;
    struct smap lswitches;

    smap_init(&lswitches);
    NBREC_LOGICAL_SWITCH_FOR_EACH(lswitch, ctx->idl) {
        smap_add_format(&lswitches, lswitch->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lswitch->header_.uuid), lswitch->name);
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
  const char *lport_chain_name = ctx->argc == 2 ? ctx->argv[1] : NULL;

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
}

static void
nbctl_lport_chain_del(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port_chain *lport_chain;

    lport_chain = lport_chain_by_name_or_uuid(ctx, id);
    if (!lport_chain) {
        return;
    }

    nbrec_logical_port_chain_delete(lport_chain);
}

static void
nbctl_lport_chain_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_port_chain *lport_chain;
    struct smap lport_chains;
    
    smap_init(&lport_chains);
    /* check if lport_chain exists */
    NBREC_LOGICAL_PORT_CHAIN_FOR_EACH(lport_chain, ctx->idl){
      smap_add_format(&lport_chains, lport_chain->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lport_chain->header_.uuid), lport_chain->name);
    
    } 
 
    const struct smap_node **nodes = smap_sort(&lport_chains);
    for (size_t i = 0; i < smap_count(&lport_chains); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lport_chains);
    free(nodes);
}

static void
nbctl_lport_chain_set_flow_classifier(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    
    const struct nbrec_logical_port_chain *lport_chain;
    const struct nbrec_logical_flow_classifier *lflow_classifier = NULL;

    
    lport_chain = lport_chain_by_name_or_uuid(ctx, id);

    /* Check port exists if given*/
    if (!strcmp(ctx->argv[2],"")){
      lflow_classifier = lflow_classifier_by_name_or_uuid(ctx, ctx->argv[2]);
      if (!lflow_classifier){
	ctl_fatal("Invalid flow_classifier %s ", ctx->argv[2]);
      }
    }
    nbrec_logical_port_chain_set_flow_classifier(lport_chain, lflow_classifier);
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
    lport_pair_group = lport_pair_group_by_name_or_uuid(ctx,ctx->argv[2]);
    /* create the logical port-pair-group. */
    lport_pair_group = nbrec_logical_port_pair_group_insert(ctx->txn);
    if (ctx->argc == 3){
       nbrec_logical_port_pair_group_set_name(lport_pair_group, ctx->argv[3]);
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
    const struct nbrec_logical_switch *lswitch; 
    const struct nbrec_logical_port *lport;
    const char *lport_name;
    const struct nbrec_logical_flow_classifier *lflow_classifier;
    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1], true);

    if (ctx->argc < 3) {
      /* ensure all arguments are present */
      ctl_fatal("Invalid number of arguments: (%d), to lflow_classifier.",ctx->argc);
    }
    /* Check that logical source port exist in this switch */
    lport_name = ctx->argv[2];
    lport = lport_by_name_or_uuid(ctx, lport_name, false);
    if (!lport){
      ctl_fatal("%s: an lport with this name does not exist",lport_name);
    }

    /* create the logical port-pair. */
    lflow_classifier = nbrec_logical_flow_classifier_insert(ctx->txn);
    nbrec_logical_flow_classifier_set_logical_source_port(lflow_classifier, lport);
    if (ctx->argc == 4){
       nbrec_logical_flow_classifier_set_name(lflow_classifier, ctx->argv[3]);
    }

    /* Insert the logical flow_classifier into the logical switch. */
    nbrec_logical_switch_verify_flow_classifiers(lswitch);
    struct nbrec_logical_flow_classifier  **new_flow_classifier = xmalloc(sizeof *new_flow_classifier *
                                                    (lswitch->n_flow_classifiers + 1));
    memcpy(new_flow_classifier, lswitch->flow_classifiers, sizeof *new_flow_classifier * lswitch->n_flow_classifiers);
    new_flow_classifier[lswitch->n_flow_classifiers] = CONST_CAST(struct nbrec_logical_flow_classifier *, lflow_classifier);
    nbrec_logical_switch_set_flow_classifiers(lswitch, new_flow_classifier, lswitch->n_flow_classifiers + 1);
    free(new_flow_classifier);
}
/* Removes lswitch->flow_classifier[idx]'. */
static void
remove_lflow_classifier(const struct nbrec_logical_switch *lswitch, size_t idx)
{
  const struct nbrec_logical_flow_classifier *lflow_classifier = lswitch->flow_classifiers[idx];

    /* First remove 'lflow_classifier' from the array of flow_classifiers.  This is what will
     * actually cause the logical flow classifier to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_flow_classifier **new_flow_classifier
      = xmemdup(lswitch->flow_classifiers, sizeof *new_flow_classifier * lswitch->n_flow_classifiers);
    new_flow_classifier[idx] = new_flow_classifier[lswitch->n_flow_classifiers - 1];
    nbrec_logical_switch_verify_flow_classifiers(lswitch);
    nbrec_logical_switch_set_flow_classifiers(lswitch, new_flow_classifier, lswitch->n_port_pairs - 1);
    free(new_flow_classifier);

    /* Delete 'lflow_classifier' from the IDL.  This won't have a real effect on the
     * database server (the IDL will suppress it in fact) but it means that it
     * won't show up when we iterate with NBREC_LOGICAL_FLOW_CLASSIFIER_FOR_EACH later. */
    nbrec_logical_flow_classifier_delete(lflow_classifier);
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
    const struct nbrec_logical_switch *lswitch;
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->idl) {
        for (size_t i = 0; i < lswitch->n_flow_classifiers; i++) {
            if (lswitch->flow_classifiers[i] == lflow_classifier) {
	      remove_lflow_classifier(lswitch,i);
	      printf("Deleted lflow-classifier: %s\n", ctx->argv[1]);
              return;
            }
        }
    }
    ctl_fatal("logical flow-classifier %s is not part of any logical switch",
              ctx->argv[1]);
}

static void
nbctl_lflow_classifier_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;
    struct smap lflow_classifiers;
    size_t i;

    lswitch = lswitch_by_name_or_uuid(ctx, id, true);
    if (!lswitch) {
        return;
    }

    smap_init(&lflow_classifiers);
    for (i = 0; i < lswitch->n_flow_classifiers; i++) {
        const struct nbrec_logical_flow_classifier *lflow_classifier = lswitch->flow_classifiers[i];
        smap_add_format(&lflow_classifiers, lflow_classifier->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lflow_classifier->header_.uuid), lflow_classifier->name);
    }
    const struct smap_node **nodes = smap_sort(&lflow_classifiers);
    for (i = 0; i < smap_count(&lflow_classifiers); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lflow_classifiers);
    free(nodes);
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



/* Returns the lswitch that contains 'lport'. */
static const struct nbrec_logical_switch *
lport_to_lswitch(const struct ovsdb_idl *idl,
                 const struct nbrec_logical_port *lport)
{
    const struct nbrec_logical_switch *lswitch;
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, idl) {
        for (size_t i = 0; i < lswitch->n_ports; i++) {
            if (lswitch->ports[i] == lport) {
                return lswitch;
            }
        }
    }

    /* Can't happen because of the database schema */
    ctl_fatal("logical port %s is not part of any logical switch",
              lport->name);
}

/* Returns the lrouter that contains 'lport'. */
static const struct nbrec_logical_router *
lrport_to_lrouter(const struct ovsdb_idl *idl,
                  const struct nbrec_logical_router_port *lrport)
{
    const struct nbrec_logical_router *lrouter;
    NBREC_LOGICAL_ROUTER_FOR_EACH (lrouter, idl) {
        for (size_t i = 0; i < lrouter->n_ports; i++) {
            if (lrouter->ports[i] == lrport) {
                return lrouter;
            }
        }
    }

    /* Can't happen because of the database schema */
    ctl_fatal("logical port %s is not part of any logical router",
              lrport->name);
}

static const char *
lswitch_get_name(const struct nbrec_logical_switch *lswitch,
                 char uuid_s[UUID_LEN + 1], size_t uuid_s_size)
{
    if (lswitch->name[0]) {
        return lswitch->name;
    }
    snprintf(uuid_s, uuid_s_size, UUID_FMT, UUID_ARGS(&lswitch->header_.uuid));
    return uuid_s;
}

static const char *
lrouter_get_name(const struct nbrec_logical_router *lrouter,
                 char uuid_s[UUID_LEN + 1], size_t uuid_s_size)
{
    if (lrouter->name[0]) {
        return lrouter->name;
    }
    snprintf(uuid_s, uuid_s_size, UUID_FMT, UUID_ARGS(&lrouter->header_.uuid));
    return uuid_s;
}

static void
nbctl_lport_add(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;

    const struct nbrec_logical_switch *lswitch;
    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1], true);

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
        ctl_fatal("lport-add with parent must also specify a tag");
    }

    const char *lport_name = ctx->argv[2];
    const struct nbrec_logical_port *lport;
    lport = lport_by_name_or_uuid(ctx, lport_name, false);
    if (lport) {
        if (!may_exist) {
            ctl_fatal("%s: an lport with this name already exists",
                      lport_name);
        }

        const struct nbrec_logical_switch *lsw;
        lsw = lport_to_lswitch(ctx->idl, lport);
        if (lsw != lswitch) {
            char uuid_s[UUID_LEN + 1];
            ctl_fatal("%s: lport already exists but in lswitch %s", lport_name,
                      lswitch_get_name(lsw, uuid_s, sizeof uuid_s));
        }

        if (parent_name) {
            if (!lport->parent_name) {
                ctl_fatal("%s: lport already exists but has no parent",
                          lport_name);
            } else if (strcmp(parent_name, lport->parent_name)) {
                ctl_fatal("%s: lport already exists with different parent %s",
                          lport_name, lport->parent_name);
            }

            if (!lport->n_tag) {
                ctl_fatal("%s: lport already exists but has no tag",
                          lport_name);
            } else if (lport->tag[0] != tag) {
                ctl_fatal("%s: lport already exists with different "
                          "tag %"PRId64, lport_name, lport->tag[0]);
            }
        } else {
            if (lport->parent_name) {
                ctl_fatal("%s: lport already exists but has parent %s",
                          lport_name, lport->parent_name);
            }
        }

        return;
    }

    /* Create the logical port. */
    lport = nbrec_logical_port_insert(ctx->txn);
    nbrec_logical_port_set_name(lport, lport_name);
    if (tag >= 0) {
        nbrec_logical_port_set_parent_name(lport, parent_name);
        nbrec_logical_port_set_tag(lport, &tag, 1);
    }

    /* Insert the logical port into the logical switch. */
    nbrec_logical_switch_verify_ports(lswitch);
    struct nbrec_logical_port **new_ports = xmalloc(sizeof *new_ports *
                                                    (lswitch->n_ports + 1));
    memcpy(new_ports, lswitch->ports, sizeof *new_ports * lswitch->n_ports);
    new_ports[lswitch->n_ports] = CONST_CAST(struct nbrec_logical_port *,
                                             lport);
    nbrec_logical_switch_set_ports(lswitch, new_ports, lswitch->n_ports + 1);
    free(new_ports);
}

/* Removes lrport 'lrouter->ports[idx]' from lrouter. */
static void
remove_lrport(const struct nbrec_logical_router *lrouter, size_t idx)
{
    const struct nbrec_logical_router_port *lrport = lrouter->ports[idx];

    /* First remove 'lrport' from the array of ports.  This is what will
     * actually cause the logical port to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_router_port **new_ports
        = xmemdup(lrouter->ports, sizeof *new_ports * lrouter->n_ports);
    new_ports[idx] = new_ports[lrouter->n_ports - 1];
    nbrec_logical_router_verify_ports(lrouter);
    nbrec_logical_router_set_ports(lrouter, new_ports, lrouter->n_ports - 1);
    free(new_ports);

    /* Delete 'lrport' from the IDL. */
    nbrec_logical_router_port_delete(lrport);
}

/* Removes lport 'lswitch->ports[idx]'. */
static void
remove_lport(const struct nbrec_logical_switch *lswitch, size_t idx)
{
    const struct nbrec_logical_port *lport = lswitch->ports[idx];

    /* First remove 'lport' from the array of ports.  This is what will
     * actually cause the logical port to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_port **new_ports
        = xmemdup(lswitch->ports, sizeof *new_ports * lswitch->n_ports);
    new_ports[idx] = new_ports[lswitch->n_ports - 1];
    nbrec_logical_switch_verify_ports(lswitch);
    nbrec_logical_switch_set_ports(lswitch, new_ports, lswitch->n_ports - 1);
    free(new_ports);

    /* Delete 'lport' from the IDL.  This won't have a real effect on the
     * database server (the IDL will suppress it in fact) but it means that it
     * won't show up when we iterate with NBREC_LOGICAL_PORT_FOR_EACH later. */
    nbrec_logical_port_delete(lport);
}

static void
nbctl_lport_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, ctx->argv[1], must_exist);
    if (!lport) {
        return;
    }

    /* Find the switch that contains 'lport', then delete it. */
    const struct nbrec_logical_switch *lswitch;
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->idl) {
        for (size_t i = 0; i < lswitch->n_ports; i++) {
            if (lswitch->ports[i] == lport) {
                remove_lport(lswitch, i);
                return;
            }
        }
    }

    /* Can't happen because of the database schema. */
    ctl_fatal("logical port %s is not part of any logical switch",
              ctx->argv[1]);
}

static void
nbctl_lport_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;
    struct smap lports;
    size_t i;

    lswitch = lswitch_by_name_or_uuid(ctx, id, true);

    smap_init(&lports);
    for (i = 0; i < lswitch->n_ports; i++) {
        const struct nbrec_logical_port *lport = lswitch->ports[i];
        smap_add_format(&lports, lport->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lport->header_.uuid), lport->name);
    }
    const struct smap_node **nodes = smap_sort(&lports);
    for (i = 0; i < smap_count(&lports); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lports);
    free(nodes);
}

static void
nbctl_lport_get_parent(struct ctl_context *ctx)
{
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, ctx->argv[1], true);
    if (lport->parent_name) {
        ds_put_format(&ctx->output, "%s\n", lport->parent_name);
    }
}

static void
nbctl_lport_get_tag(struct ctl_context *ctx)
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

    const char *mac = ctx->argc > 2 ? ctx->argv[2] : "";
    if (mac[0] && !ovs_scan(ctx->argv[2], ETH_ADDR_SCAN_FMT,
                            ETH_ADDR_SCAN_ARGS(ea))) {
        ctl_fatal("%s: invalid MAC address format", mac);
        return;
    }

    nbrec_logical_router_port_set_mac(lrport, mac);
}

static void
nbctl_lport_set_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id, true);

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

    nbrec_logical_port_set_addresses(lport,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

/* Following function prints the mac address of the lrport. */
static void
nbctl_lrport_get_mac(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router_port *lrport;

    lrport = lrport_by_name_or_uuid(ctx, id, true);
    if (!lrport) {
        return;
    }
    ds_put_format(&ctx->output, "%s\n", lrport->mac);
}

static void
nbctl_lport_get_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;
    struct svec addresses;
    const char *mac;
    size_t i;

    lport = lport_by_name_or_uuid(ctx, id, true);

    svec_init(&addresses);
    for (i = 0; i < lport->n_addresses; i++) {
        svec_add(&addresses, lport->addresses[i]);
    }
    svec_sort(&addresses);
    SVEC_FOR_EACH(i, mac, &addresses) {
        ds_put_format(&ctx->output, "%s\n", mac);
    }
    svec_destroy(&addresses);
}

static void
nbctl_lport_set_port_security(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id, true);
    nbrec_logical_port_set_port_security(lport,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

static void
nbctl_lport_get_port_security(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;
    struct svec addrs;
    const char *addr;
    size_t i;

    lport = lport_by_name_or_uuid(ctx, id, true);
    svec_init(&addrs);
    for (i = 0; i < lport->n_port_security; i++) {
        svec_add(&addrs, lport->port_security[i]);
    }
    svec_sort(&addrs);
    SVEC_FOR_EACH(i, addr, &addrs) {
        ds_put_format(&ctx->output, "%s\n", addr);
    }
    svec_destroy(&addrs);
}

static void
nbctl_lport_get_up(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id, true);
    ds_put_format(&ctx->output,
                  "%s\n", (lport->up && *lport->up) ? "up" : "down");
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

/* Set the lrport admin-enabled state. */
static void
nbctl_lrport_set_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *state = ctx->argv[2];
    const struct nbrec_logical_router_port *lrport;

    lrport = lrport_by_name_or_uuid(ctx, id, true);
    if (!lrport) {
        return;
    }

    bool enabled = parse_enabled(state);
    nbrec_logical_router_port_set_enabled(lrport, &enabled, 1);
}

static void
nbctl_lport_set_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *state = ctx->argv[2];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id, true);
    bool enabled = parse_enabled(state);
    nbrec_logical_port_set_enabled(lport, &enabled, 1);
}

/* Print admin-enabled state for lrport. */
static void
nbctl_lrport_get_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router_port *lrport;

    lrport = lrport_by_name_or_uuid(ctx, id, true);
    if (!lrport) {
        return;
    }

    ds_put_format(&ctx->output, "%s\n",
                  !lrport->enabled ||
                  *lrport->enabled ? "enabled" : "disabled");
}

static void
nbctl_lport_get_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id, true);
    ds_put_format(&ctx->output, "%s\n",
                  !lport->enabled || *lport->enabled ? "enabled" : "disabled");
}

static void
nbctl_lport_set_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *type = ctx->argv[2];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id, true);
    nbrec_logical_port_set_type(lport, type);
}

static void
nbctl_lport_get_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id, true);
    ds_put_format(&ctx->output, "%s\n", lport->type);
}

static void
nbctl_lport_set_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;
    size_t i;
    struct smap options = SMAP_INITIALIZER(&options);

    lport = lport_by_name_or_uuid(ctx, id, true);
    for (i = 2; i < ctx->argc; i++) {
        char *key, *value;
        value = xstrdup(ctx->argv[i]);
        key = strsep(&value, "=");
        if (value) {
            smap_add(&options, key, value);
        }
        free(key);
    }

    nbrec_logical_port_set_options(lport, &options);

    smap_destroy(&options);
}

static void
nbctl_lport_get_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;
    struct smap_node *node;

    lport = lport_by_name_or_uuid(ctx, id, true);
    SMAP_FOR_EACH(node, &lport->options) {
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
    const struct nbrec_logical_switch *lswitch;
    const struct nbrec_acl **acls;
    size_t i;

    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1], true);

    acls = xmalloc(sizeof *acls * lswitch->n_acls);
    for (i = 0; i < lswitch->n_acls; i++) {
        acls[i] = lswitch->acls[i];
    }

    qsort(acls, lswitch->n_acls, sizeof *acls, acl_cmp);

    for (i = 0; i < lswitch->n_acls; i++) {
        const struct nbrec_acl *acl = acls[i];
        printf("%10s %5"PRId64" (%s) %s%s\n", acl->direction, acl->priority,
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
    const struct nbrec_logical_switch *lswitch;
    const char *action = ctx->argv[5];

    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1], true);

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
    nbrec_logical_switch_verify_acls(lswitch);
    struct nbrec_acl **new_acls = xmalloc(sizeof *new_acls *
                                          (lswitch->n_acls + 1));
    memcpy(new_acls, lswitch->acls, sizeof *new_acls * lswitch->n_acls);
    new_acls[lswitch->n_acls] = acl;
    nbrec_logical_switch_set_acls(lswitch, new_acls, lswitch->n_acls + 1);
    free(new_acls);
}

static void
nbctl_acl_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *lswitch;
    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1], true);

    if (ctx->argc != 2 && ctx->argc != 3 && ctx->argc != 5) {
        ctl_fatal("cannot specify priority without match");
    }

    if (ctx->argc == 2) {
        /* If direction, priority, and match are not specified, delete
         * all ACLs. */
        nbrec_logical_switch_verify_acls(lswitch);
        nbrec_logical_switch_set_acls(lswitch, NULL, 0);
        return;
    }

    const char *direction = parse_direction(ctx->argv[2]);

    /* If priority and match are not specified, delete all ACLs with the
     * specified direction. */
    if (ctx->argc == 3) {
        struct nbrec_acl **new_acls
            = xmalloc(sizeof *new_acls * lswitch->n_acls);

        int n_acls = 0;
        for (size_t i = 0; i < lswitch->n_acls; i++) {
            if (strcmp(direction, lswitch->acls[i]->direction)) {
                new_acls[n_acls++] = lswitch->acls[i];
            }
        }

        nbrec_logical_switch_verify_acls(lswitch);
        nbrec_logical_switch_set_acls(lswitch, new_acls, n_acls);
        free(new_acls);
        return;
    }

    int64_t priority = parse_priority(ctx->argv[3]);

    /* Remove the matching rule. */
    for (size_t i = 0; i < lswitch->n_acls; i++) {
        struct nbrec_acl *acl = lswitch->acls[i];

        if (priority == acl->priority && !strcmp(ctx->argv[4], acl->match) &&
             !strcmp(direction, acl->direction)) {
            struct nbrec_acl **new_acls
                = xmemdup(lswitch->acls, sizeof *new_acls * lswitch->n_acls);
            new_acls[i] = lswitch->acls[lswitch->n_acls - 1];
            nbrec_logical_switch_verify_acls(lswitch);
            nbrec_logical_switch_set_acls(lswitch, new_acls,
                                          lswitch->n_acls - 1);
            free(new_acls);
            return;
        }
    }
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

/* Print a list of lrports. */
static void
nbctl_lrport_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router *lrouter;
    struct smap lports;
    size_t i;

    lrouter = lrouter_by_name_or_uuid(ctx, id, true);

    smap_init(&lports);
    for (i = 0; i < lrouter->n_ports; i++) {
        const struct nbrec_logical_router_port *lport = lrouter->ports[i];
        smap_add_format(&lports, lport->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lport->header_.uuid), lport->name);
    }
    const struct smap_node **nodes = smap_sort(&lports);
    for (i = 0; i < smap_count(&lports); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lports);
    free(nodes);
}

/* Add an lrport to the lrouter. */
static void
nbctl_lrport_add(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;

    const struct nbrec_logical_router *lrouter;
    lrouter = lrouter_by_name_or_uuid(ctx, ctx->argv[1], true);

    const char *lrport_name = ctx->argv[2];
    const struct nbrec_logical_router_port *lrport;

    lrport = lrport_by_name_or_uuid(ctx, lrport_name, false);
    if (lrport) {
        if (!may_exist) {
            ctl_fatal("%s: an lrport with this name already exists",
                      lrport_name);
        }

        const struct nbrec_logical_router *lr;
        lr = lrport_to_lrouter(ctx->idl, lrport);
        if (lr != lrouter) {
            char uuid_s[UUID_LEN + 1];
            ctl_fatal("%s: lrport already exists but in lrouter %s",
                      lrport_name,
                      lrouter_get_name(lr, uuid_s, sizeof uuid_s));
        }

        return;
    }

    /* Create the logical router port. */
    lrport = nbrec_logical_router_port_insert(ctx->txn);
    nbrec_logical_router_port_set_name(lrport, ctx->argv[2]);

    /* Insert the logical port into the logical router. */
    nbrec_logical_router_verify_ports(lrouter);
    struct nbrec_logical_router_port **new_ports = xmalloc(sizeof *new_ports *
                                                    (lrouter->n_ports + 1));
    memcpy(new_ports, lrouter->ports, sizeof *new_ports * lrouter->n_ports);
    new_ports[lrouter->n_ports] = CONST_CAST(
        struct nbrec_logical_router_port *, lrport);
    nbrec_logical_router_set_ports(lrouter, new_ports, lrouter->n_ports + 1);
    free(new_ports);
}

/* Deletes an lrport from an lrouter. */
static void
nbctl_lrport_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct nbrec_logical_router_port *lrport;

    lrport = lrport_by_name_or_uuid(ctx, ctx->argv[1], must_exist);
    if (!lrport) {
        return;
    }

    /* Find the router that contains 'lrport', then delete it. */
    const struct nbrec_logical_router *lrouter;
    NBREC_LOGICAL_ROUTER_FOR_EACH (lrouter, ctx->idl) {
        for (size_t i = 0; i < lrouter->n_ports; i++) {
            if (lrouter->ports[i] == lrport) {
                remove_lrport(lrouter, i);
                return;
            }
        }
    }

    ctl_fatal("logical router port %s is not part of any logical router",
              ctx->argv[1]);
}

static const struct ctl_command_syntax nbctl_commands[] = {
    { "show", 0, 1, "[LSWITCH]", NULL, nbctl_show, NULL, "", RO },

    /* lswitch commands. */
    { "lswitch-add", 0, 1, "[LSWITCH]", NULL, nbctl_lswitch_add,
      NULL, "--may-exist,--add-duplicate", RW },
    { "lswitch-del", 1, 1, "LSWITCH", NULL, nbctl_lswitch_del,
      NULL, "--if-exists", RW },
    { "lswitch-list", 0, 0, "", NULL, nbctl_lswitch_list, NULL, "", RO },

    /* lport-chain commands. */
    { "lport-chain-add", 0, 1, "[LPORT-CHAIN]", NULL, nbctl_lport_chain_add,
      NULL, "", RW },
    { "lport-chain-del", 1, 1, "LPORT-CHAIN", NULL, nbctl_lport_chain_del,
      NULL, "--if-exists", RW },
    { "lport-chain-list", 0, 0, "", NULL, nbctl_lport_chain_list, NULL, "", RO },
    { "lport-chain-get-flow-classifier", 1, 1, "LPORT-CHAIN", NULL, 
      nbctl_lport_chain_get_flow_classifier, NULL, "", RO },
    { "lport_chain_set_flow-classifier", 1, 1, "LPORT-CHAIN [LFLOW-CLASSIFIER]", NULL, 
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
    { "lport-pair-list", 0, 0, "", NULL, nbctl_lport_pair_list, NULL, "", RO },

   /* lflow-classifier commands. */
    { "lflow-classifier-add", 2, 3, "LSWITCH LSOURCE_PORT [LFLOW-CLASSIFIER-NAME]", NULL, 
      nbctl_lflow_classifier_add, NULL, "", RW },
    { "lflow-classifier-del", 1, 1, "LFLOW-CLASSIFIER", NULL, 
      nbctl_lflow_classifier_del, NULL, "", RW },
    { "lflow-classifier-list", 1, 1, "LFLOW-CLASSIFIER", NULL, nbctl_lflow_classifier_list,
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

    /* acl commands. */
    { "acl-add", 5, 5, "LSWITCH DIRECTION PRIORITY MATCH ACTION", NULL,
      nbctl_acl_add, NULL, "--log", RW },
    { "acl-del", 1, 4, "LSWITCH [DIRECTION [PRIORITY MATCH]]", NULL,
      nbctl_acl_del, NULL, "", RW },
    { "acl-list", 1, 1, "LSWITCH", NULL, nbctl_acl_list, NULL, "", RO },

    /* lrport commands. */
    { "lrport-add", 2, 2, "LROUTER LRPORT", NULL, nbctl_lrport_add,
      NULL, "--may-exist", RW },
    { "lrport-del", 1, 1, "LRPORT", NULL, nbctl_lrport_del, NULL, "", RO },
    { "lrport-list", 1, 1, "LROUTER", NULL, nbctl_lrport_list, NULL, "", RO },
    { "lrport-set-mac-address", 1, 2, "LRPORT [ADDRESS]", NULL,
      nbctl_lrport_set_mac, NULL, "", RW },
    { "lrport-get-mac-address", 1, 1, "LRPORT", NULL,
      nbctl_lrport_get_mac, NULL,
      "", RO },
    { "lrport-set-enabled", 2, 2, "LRPORT STATE", NULL,
      nbctl_lrport_set_enabled, NULL, "", RW },
    { "lrport-get-enabled", 1, 1, "LRPORT", NULL,
      nbctl_lrport_get_enabled, NULL, "", RO },

    /* lport commands. */
    { "lport-add", 2, 4, "LSWITCH LPORT [PARENT] [TAG]", NULL, nbctl_lport_add,
      NULL, "--may-exist", RW },
    { "lport-del", 1, 1, "LPORT", NULL, nbctl_lport_del, NULL, "--if-exists",
      RW },
    { "lport-list", 1, 1, "LSWITCH", NULL, nbctl_lport_list, NULL, "", RO },
    { "lport-get-parent", 1, 1, "LPORT", NULL, nbctl_lport_get_parent, NULL,
      "", RO },
    { "lport-get-tag", 1, 1, "LPORT", NULL, nbctl_lport_get_tag, NULL, "",
      RO },
    { "lport-set-addresses", 1, INT_MAX, "LPORT [ADDRESS]...", NULL,
      nbctl_lport_set_addresses, NULL, "", RW },
    { "lport-get-addresses", 1, 1, "LPORT", NULL,
      nbctl_lport_get_addresses, NULL,
      "", RO },
    { "lport-set-port-security", 0, INT_MAX, "LPORT [ADDRS]...", NULL,
      nbctl_lport_set_port_security, NULL, "", RW },
    { "lport-get-port-security", 1, 1, "LPORT", NULL,
      nbctl_lport_get_port_security, NULL, "", RO },
    { "lport-get-up", 1, 1, "LPORT", NULL, nbctl_lport_get_up, NULL, "", RO },
    { "lport-set-enabled", 2, 2, "LPORT STATE", NULL, nbctl_lport_set_enabled,
      NULL, "", RW },
    { "lport-get-enabled", 1, 1, "LPORT", NULL, nbctl_lport_get_enabled, NULL,
      "", RO },
    { "lport-set-type", 2, 2, "LPORT TYPE", NULL, nbctl_lport_set_type, NULL,
      "", RW },
    { "lport-get-type", 1, 1, "LPORT", NULL, nbctl_lport_get_type, NULL, "",
      RO },
    { "lport-set-options", 1, INT_MAX, "LPORT KEY=VALUE [KEY=VALUE]...", NULL,
      nbctl_lport_set_options, NULL, "", RW },
    { "lport-get-options", 1, 1, "LPORT", NULL, nbctl_lport_get_options, NULL,
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
