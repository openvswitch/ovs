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
static void do_nbctl(const char *args, struct ctl_command *, size_t n,
                     struct ovsdb_idl *);

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_reconnect;
    struct ovsdb_idl *idl;
    struct ctl_command *commands;
    struct shash local_options;
    unsigned int seqno;
    size_t n_commands;
    char *args;

    set_program_name(argv[0]);
    fatal_ignore_sigpipe();
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_DESTINATION, VLL_WARN);
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
            do_nbctl(args, commands, n_commands, idl);
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
            def = ctl_default_db();
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
            vlog_set_levels(&VLM_nbctl, VLF_SYSLOG, VLL_WARN);
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
\n\
Logical switch commands:\n\
  lswitch-add [LSWITCH]     create a logical switch named LSWITCH\n\
  lswitch-del LSWITCH       delete LSWITCH and all its ports\n\
  lswitch-list              print the names of all logical switches\n\
\n\
ACL commands:\n\
  acl-add LSWITCH DIRECTION PRIORITY MATCH ACTION [log]\n\
                            add an ACL to LSWITCH\n\
  acl-del LSWITCH [DIRECTION [PRIORITY MATCH]]\n\
                            remove ACLs from LSWITCH\n\
  acl-list LSWITCH          print ACLs for LSWITCH\n\
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
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           program_name, program_name, nbctl_default_db());
    vlog_usage();
    printf("\
  --no-syslog             equivalent to --verbose=nbctl:syslog:warn\n");
    printf("\n\
Other options:\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static const struct nbrec_logical_switch *
lswitch_by_name_or_uuid(struct ctl_context *ctx, const char *id)
{
    const struct nbrec_logical_switch *lswitch = NULL;
    bool is_uuid = false;
    bool duplicate = false;
    struct uuid lswitch_uuid;

    if (uuid_from_string(&lswitch_uuid, id)) {
        is_uuid = true;
        lswitch = nbrec_logical_switch_get_for_uuid(ctx->idl,
                                                    &lswitch_uuid);
    }

    if (!lswitch) {
        const struct nbrec_logical_switch *iter;

        NBREC_LOGICAL_SWITCH_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (lswitch) {
                VLOG_WARN("There is more than one logical switch named '%s'. "
                        "Use a UUID.", id);
                lswitch = NULL;
                duplicate = true;
                break;
            }
            lswitch = iter;
        }
    }

    if (!lswitch && !duplicate) {
        VLOG_WARN("lswitch not found for %s: '%s'",
                is_uuid ? "UUID" : "name", id);
    }

    return lswitch;
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
            ds_put_cstr(s, "            addresses:");
            for (size_t j = 0; j < lport->n_addresses; j++) {
                ds_put_format(s, " %s", lport->addresses[j]);
            }
            ds_put_char(s, '\n');
        }
    }
}

static void
nbctl_show(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *lswitch;

    if (ctx->argc == 2) {
        lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1]);
        if (lswitch) {
            print_lswitch(lswitch, &ctx->output);
        }
    } else {
        NBREC_LOGICAL_SWITCH_FOR_EACH(lswitch, ctx->idl) {
            print_lswitch(lswitch, &ctx->output);
        }
    }
}

static void
nbctl_lswitch_add(struct ctl_context *ctx)
{
    struct nbrec_logical_switch *lswitch;

    lswitch = nbrec_logical_switch_insert(ctx->txn);
    if (ctx->argc == 2) {
        nbrec_logical_switch_set_name(lswitch, ctx->argv[1]);
    }
}

static void
nbctl_lswitch_del(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;

    lswitch = lswitch_by_name_or_uuid(ctx, id);
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

static const struct nbrec_logical_port *
lport_by_name_or_uuid(struct ctl_context *ctx, const char *id)
{
    const struct nbrec_logical_port *lport = NULL;
    bool is_uuid = false;
    struct uuid lport_uuid;

    if (uuid_from_string(&lport_uuid, id)) {
        is_uuid = true;
        lport = nbrec_logical_port_get_for_uuid(ctx->idl, &lport_uuid);
    }

    if (!lport) {
        NBREC_LOGICAL_PORT_FOR_EACH(lport, ctx->idl) {
            if (!strcmp(lport->name, id)) {
                break;
            }
        }
    }

    if (!lport) {
        VLOG_WARN("lport not found for %s: '%s'",
                is_uuid ? "UUID" : "name", id);
    }

    return lport;
}

static void
nbctl_lport_add(struct ctl_context *ctx)
{
    struct nbrec_logical_port *lport;
    const struct nbrec_logical_switch *lswitch;
    int64_t tag;

    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lswitch) {
        return;
    }

    if (ctx->argc != 3 && ctx->argc != 5) {
        /* If a parent_name is specified, a tag must be specified as well. */
        VLOG_WARN("Invalid arguments to lport-add.");
        return;
    }

    if (ctx->argc == 5) {
        /* Validate tag. */
        if (!ovs_scan(ctx->argv[4], "%"SCNd64, &tag) || tag < 0 || tag > 4095) {
            VLOG_WARN("Invalid tag '%s'", ctx->argv[4]);
            return;
        }
    }

    /* Create the logical port. */
    lport = nbrec_logical_port_insert(ctx->txn);
    nbrec_logical_port_set_name(lport, ctx->argv[2]);
    if (ctx->argc == 5) {
        nbrec_logical_port_set_parent_name(lport, ctx->argv[3]);
        nbrec_logical_port_set_tag(lport, &tag, 1);
    }

    /* Insert the logical port into the logical switch. */
    nbrec_logical_switch_verify_ports(lswitch);
    struct nbrec_logical_port **new_ports = xmalloc(sizeof *new_ports *
                                                    (lswitch->n_ports + 1));
    memcpy(new_ports, lswitch->ports, sizeof *new_ports * lswitch->n_ports);
    new_ports[lswitch->n_ports] = lport;
    nbrec_logical_switch_set_ports(lswitch, new_ports, lswitch->n_ports + 1);
    free(new_ports);
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
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, ctx->argv[1]);
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

    VLOG_WARN("logical port %s is not part of any logical switch",
              ctx->argv[1]);
}

static void
nbctl_lport_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;
    struct smap lports;
    size_t i;

    lswitch = lswitch_by_name_or_uuid(ctx, id);
    if (!lswitch) {
        return;
    }

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

    lport = lport_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lport) {
        return;
    }

    if (lport->parent_name) {
        ds_put_format(&ctx->output, "%s\n", lport->parent_name);
    }
}

static void
nbctl_lport_get_tag(struct ctl_context *ctx)
{
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lport) {
        return;
    }

    if (lport->n_tag > 0) {
        ds_put_format(&ctx->output, "%"PRId64"\n", lport->tag[0]);
    }
}

static void
nbctl_lport_set_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

    nbrec_logical_port_set_addresses(lport,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

static void
nbctl_lport_get_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;
    struct svec addresses;
    const char *mac;
    size_t i;

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

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

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

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

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

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

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

    ds_put_format(&ctx->output,
                  "%s\n", (lport->up && *lport->up) ? "up" : "down");
}

static void
nbctl_lport_set_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *state = ctx->argv[2];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

    if (!strcasecmp(state, "enabled")) {
        bool enabled = true;
        nbrec_logical_port_set_enabled(lport, &enabled, 1);
    } else if (!strcasecmp(state, "disabled")) {
        bool enabled = false;
        nbrec_logical_port_set_enabled(lport, &enabled, 1);
    } else {
        VLOG_ERR("Invalid state '%s' provided to lport-set-enabled", state);
    }
}

static void
nbctl_lport_get_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

    ds_put_format(&ctx->output, "%s\n",
                  !lport->enabled || *lport->enabled ? "enabled" : "disabled");
}

static void
nbctl_lport_set_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *type = ctx->argv[2];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

    nbrec_logical_port_set_type(lport, type);
}

static void
nbctl_lport_get_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

    ds_put_format(&ctx->output, "%s\n", lport->type);
}

static void
nbctl_lport_set_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;
    size_t i;
    struct smap options = SMAP_INITIALIZER(&options);

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

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

    lport = lport_by_name_or_uuid(ctx, id);
    if (!lport) {
        return;
    }

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

    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lswitch) {
        return;
    }

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

static void
nbctl_acl_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *lswitch;
    const char *action = ctx->argv[5];
    const char *direction;
    int64_t priority;

    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lswitch) {
        return;
    }

    /* Validate direction.  Only require the first letter. */
    if (ctx->argv[2][0] == 't') {
        direction = "to-lport";
    } else if (ctx->argv[2][0] == 'f') {
        direction = "from-lport";
    } else {
        VLOG_WARN("Invalid direction '%s'", ctx->argv[2]);
        return;
    }

    /* Validate priority. */
    if (!ovs_scan(ctx->argv[3], "%"SCNd64, &priority) || priority < 0
        || priority > 32767) {
        VLOG_WARN("Invalid priority '%s'", ctx->argv[3]);
        return;
    }

    /* Validate action. */
    if (strcmp(action, "allow") && strcmp(action, "allow-related")
        && strcmp(action, "drop") && strcmp(action, "reject")) {
        VLOG_WARN("Invalid action '%s'", action);
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
    const char *direction;
    int64_t priority = 0;

    lswitch = lswitch_by_name_or_uuid(ctx, ctx->argv[1]);
    if (!lswitch) {
        return;
    }

    if (ctx->argc != 2 && ctx->argc != 3 && ctx->argc != 5) {
        VLOG_WARN("Invalid number of arguments");
        return;
    }

    if (ctx->argc == 2) {
        /* If direction, priority, and match are not specified, delete
         * all ACLs. */
        nbrec_logical_switch_verify_acls(lswitch);
        nbrec_logical_switch_set_acls(lswitch, NULL, 0);
        return;
    }

    /* Validate direction.  Only require first letter. */
    if (ctx->argv[2][0] == 't') {
        direction = "to-lport";
    } else if (ctx->argv[2][0] == 'f') {
        direction = "from-lport";
    } else {
        VLOG_WARN("Invalid direction '%s'", ctx->argv[2]);
        return;
    }

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

    /* Validate priority. */
    if (!ovs_scan(ctx->argv[3], "%"SCNd64, &priority) || priority < 0
        || priority > 32767) {
        VLOG_WARN("Invalid priority '%s'", ctx->argv[3]);
        return;
    }

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

static void
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
    { "show", 0, 1, "[LSWITCH]", NULL, nbctl_show, NULL, "", RO },

    /* lswitch commands. */
    { "lswitch-add", 0, 1, "[LSWITCH]", NULL, nbctl_lswitch_add,
      NULL, "", RW },
    { "lswitch-del", 1, 1, "LSWITCH", NULL, nbctl_lswitch_del,
      NULL, "", RW },
    { "lswitch-list", 0, 0, "", NULL, nbctl_lswitch_list, NULL, "", RO },

    /* acl commands. */
    { "acl-add", 5, 5, "LSWITCH DIRECTION PRIORITY MATCH ACTION", NULL,
      nbctl_acl_add, NULL, "--log", RW },
    { "acl-del", 1, 4, "LSWITCH [DIRECTION [PRIORITY MATCH]]", NULL,
      nbctl_acl_del, NULL, "", RW },
    { "acl-list", 1, 1, "LSWITCH", NULL, nbctl_acl_list, NULL, "", RO },

    /* lport commands. */
    { "lport-add", 2, 4, "LSWITCH LPORT [PARENT] [TAG]", NULL, nbctl_lport_add,
      NULL, "", RW },
    { "lport-del", 1, 1, "LPORT", NULL, nbctl_lport_del, NULL, "", RO },
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
