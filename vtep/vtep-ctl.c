/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2014, 2015, 2016, 2017 Nicira, Inc.
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

#include "db-ctl-base.h"

#include "command-line.h"
#include "compiler.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/json.h"
#include "ovsdb-data.h"
#include "ovsdb-idl.h"
#include "openvswitch/poll-loop.h"
#include "process.h"
#include "stream.h"
#include "stream-ssl.h"
#include "smap.h"
#include "sset.h"
#include "svec.h"
#include "vtep/vtep-idl.h"
#include "table.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(vtep_ctl);

struct vtep_ctl_context;

/* --db: The database server to contact. */
static const char *db;

/* --oneline: Write each command's output as a single line? */
static bool oneline;

/* --dry-run: Do not commit any changes. */
static bool dry_run;

/* --timeout: Time to wait for a connection to 'db'. */
static unsigned int timeout;

/* Format for table output. */
static struct table_style table_style = TABLE_STYLE_DEFAULT;

/* The IDL we're using and the current transaction, if any.
 * This is for use by vtep_ctl_exit() only, to allow it to clean up.
 * Other code should use its context arguments. */
static struct ovsdb_idl *the_idl;
static struct ovsdb_idl_txn *the_idl_txn;

OVS_NO_RETURN static void vtep_ctl_exit(int status);
static void vtep_ctl_cmd_init(void);
OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[], struct shash *local_options);
static void run_prerequisites(struct ctl_command[], size_t n_commands,
                              struct ovsdb_idl *);
static bool do_vtep_ctl(const char *args, struct ctl_command *, size_t n,
                        struct ovsdb_idl *);
static struct vtep_ctl_lswitch *find_lswitch(struct vtep_ctl_context *,
                                             const char *name,
                                             bool must_exist);
static struct vtep_ctl_lrouter *find_lrouter(struct vtep_ctl_context *,
                                             const char *name,
                                             bool must_exist);

int
main(int argc, char *argv[])
{
    struct ovsdb_idl *idl;
    struct ctl_command *commands;
    struct shash local_options;
    unsigned int seqno;
    size_t n_commands;

    set_program_name(argv[0]);
    fatal_ignore_sigpipe();
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels_from_string_assert("reconnect:warn");

    vtep_ctl_cmd_init();

    /* Parse command line. */
    char *args = process_escape_args(argv);
    shash_init(&local_options);
    parse_options(argc, argv, &local_options);
    char *error = ctl_parse_commands(argc - optind, argv + optind,
                                     &local_options, &commands, &n_commands);
    if (error) {
        ctl_fatal("%s", error);
    }
    VLOG(ctl_might_write_to_db(commands, n_commands) ? VLL_INFO : VLL_DBG,
         "Called as %s", args);

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
        if (!ovsdb_idl_is_alive(idl)) {
            int retval = ovsdb_idl_get_last_error(idl);
            ctl_fatal("%s: database connection failed (%s)",
                        db, ovs_retval_to_string(retval));
        }

        if (seqno != ovsdb_idl_get_seqno(idl)) {
            seqno = ovsdb_idl_get_seqno(idl);
            if (do_vtep_ctl(args, commands, n_commands, idl)) {
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
        TABLE_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
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
                             nullable_xstrdup(optarg));
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            printf("DB Schema %s\n", vteprec_get_db_version());
            exit(EXIT_SUCCESS);

        case 't':
            if (!str_to_uint(optarg, 10, &timeout) || !timeout) {
                ctl_fatal("value %s on -t or --timeout is invalid", optarg);
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
        db = ctl_default_db();
    }

    for (i = n_global_long_options; options[i].name; i++) {
        free(CONST_CAST(char *, options[i].name));
    }
    free(options);
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
VTEP commands:\n\
  show                        print overview of database contents\n\
\n\
Manager commands:\n\
  get-manager                 print the managers\n\
  del-manager                 delete the managers\n\
  [--inactivity-probe=MSECS]\n\
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
  set-replication-mode LS MODE  set replication mode on LS\n\
  get-replication-mode LS       get replication mode on LS\n\
\n\
Logical Router commands:\n\
  add-lr LR                   create a new logical router named LR\n\
  del-lr LR                   delete LR\n\
  list-lr                     print the names of all the logical routers\n\
  lr-exists LR                exit 2 if LR does not exist\n\
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
%s\
%s\
\n\
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           program_name, program_name, ctl_get_db_cmd_usage(),
           ctl_list_db_tables_usage(), ctl_default_db());
    table_usage();
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


static struct cmd_show_table cmd_show_tables[] = {
    {&vteprec_table_global,
     NULL,
     {&vteprec_global_col_managers,
      &vteprec_global_col_switches,
      NULL},
     {NULL, NULL, NULL}
    },

    {&vteprec_table_manager,
     &vteprec_manager_col_target,
     {&vteprec_manager_col_is_connected,
      NULL,
      NULL},
     {NULL, NULL, NULL}
    },

    {&vteprec_table_physical_switch,
     &vteprec_physical_switch_col_name,
     {&vteprec_physical_switch_col_management_ips,
      &vteprec_physical_switch_col_tunnel_ips,
      &vteprec_physical_switch_col_ports},
     {NULL, NULL, NULL}
    },

    {&vteprec_table_physical_port,
     &vteprec_physical_port_col_name,
     {&vteprec_physical_port_col_vlan_bindings,
      NULL,
      NULL},
     {NULL, NULL, NULL}
    },

    {&vteprec_table_logical_switch,
     &vteprec_logical_switch_col_name,
     {NULL,
      NULL,
      NULL},
     {NULL, NULL, NULL}
    },

    {NULL, NULL, {NULL, NULL, NULL}, {NULL, NULL, NULL}}
};

/* vtep-ctl specific context.  Inherits the 'struct ctl_context' as base. */
struct vtep_ctl_context {
    struct ctl_context base;

    /* Modifiable state. */
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
    struct shash lrouters;  /* Maps from logical router name to
                             * struct vtep_ctl_lrouter. */
};

/* Casts 'base' into 'struct vtep_ctl_context'. */
static struct vtep_ctl_context *
vtep_ctl_context_cast(struct ctl_context *base)
{
    return CONTAINER_OF(base, struct vtep_ctl_context, base);
}

struct vtep_ctl_pswitch {
    const struct vteprec_physical_switch *ps_cfg;
    char *name;
    struct ovs_list ports;      /* Contains "struct vteprec_physical_port"s. */
};

struct vtep_ctl_port {
    struct ovs_list ports_node; /* In struct vtep_ctl_pswitch's 'ports' list. */
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

struct vtep_ctl_lrouter {
    const struct vteprec_logical_router *lr_cfg;
    char *name;
};

struct vtep_ctl_mcast_mac {
    const struct vteprec_mcast_macs_local *local_cfg;
    const struct vteprec_mcast_macs_remote *remote_cfg;

    const struct vteprec_physical_locator_set *ploc_set_cfg;
    struct ovs_list locators;   /* Contains 'vtep_ctl_ploc's. */
};

struct vtep_ctl_ploc {
    struct ovs_list locators_node;  /* In struct vtep_ctl_ploc_set's 'locators'
                                       list. */
    const struct vteprec_physical_locator *ploc_cfg;
};

static void
verify_ports(struct vtep_ctl_context *vtepctl_ctx)
{
    if (!vtepctl_ctx->verified_ports) {
        const struct vteprec_physical_switch *ps;

        vteprec_global_verify_switches(vtepctl_ctx->vtep_global);
        VTEPREC_PHYSICAL_SWITCH_FOR_EACH (ps, vtepctl_ctx->base.idl) {
            vteprec_physical_switch_verify_ports(ps);
        }

        vtepctl_ctx->verified_ports = true;
    }
}

static struct vtep_ctl_port *
add_port_to_cache(struct vtep_ctl_context *vtepctl_ctx,
                  struct vtep_ctl_pswitch *ps,
                  struct vteprec_physical_port *port_cfg)
{
    char *cache_name = xasprintf("%s+%s", ps->name, port_cfg->name);
    struct vtep_ctl_port *port;

    port = xmalloc(sizeof *port);
    ovs_list_push_back(&ps->ports, &port->ports_node);
    port->port_cfg = port_cfg;
    port->ps = ps;
    shash_add(&vtepctl_ctx->ports, cache_name, port);
    free(cache_name);
    shash_init(&port->bindings);

    return port;
}

static void
del_cached_port(struct vtep_ctl_context *vtepctl_ctx,
                struct vtep_ctl_port *port)
{
    char *cache_name = xasprintf("%s+%s", port->ps->name, port->port_cfg->name);

    ovs_list_remove(&port->ports_node);
    shash_find_and_delete(&vtepctl_ctx->ports, cache_name);
    vteprec_physical_port_delete(port->port_cfg);
    shash_destroy(&port->bindings);
    free(cache_name);
    free(port);
}

static void
add_pswitch_to_cache(struct vtep_ctl_context *vtepctl_ctx,
                     struct vteprec_physical_switch *ps_cfg)
{
    struct vtep_ctl_pswitch *ps = xmalloc(sizeof *ps);
    ps->ps_cfg = ps_cfg;
    ps->name = xstrdup(ps_cfg->name);
    ovs_list_init(&ps->ports);
    shash_add(&vtepctl_ctx->pswitches, ps->name, ps);
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
    ovs_assert(ovs_list_is_empty(&ps->ports));
    if (ps->ps_cfg) {
        vteprec_physical_switch_delete(ps->ps_cfg);
        vtep_delete_pswitch(ctx->vtep_global, ps->ps_cfg);
    }
    shash_find_and_delete(&ctx->pswitches, ps->name);
    free(ps->name);
    free(ps);
}

static struct vtep_ctl_lswitch *
add_lswitch_to_cache(struct vtep_ctl_context *vtepctl_ctx,
                     const struct vteprec_logical_switch *ls_cfg)
{
    struct vtep_ctl_lswitch *ls = xmalloc(sizeof *ls);
    ls->ls_cfg = ls_cfg;
    ls->name = xstrdup(ls_cfg->name);
    shash_add(&vtepctl_ctx->lswitches, ls->name, ls);
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
        ctl_fatal("multiple bindings for vlan %s", vlan);
    }

    shash_add(&port->bindings, vlan, ls);
}

static void
del_cached_ls_binding(struct vtep_ctl_port *port, const char *vlan)
{
    if (!shash_find(&port->bindings, vlan)) {
        ctl_fatal("no binding for vlan %s", vlan);
    }

    shash_find_and_delete(&port->bindings, vlan);
}

static struct vtep_ctl_lrouter *
add_lrouter_to_cache(struct vtep_ctl_context *vtepctl_ctx,
                     const struct vteprec_logical_router *lr_cfg)
{
    struct vtep_ctl_lrouter *lr = xmalloc(sizeof *lr);
    lr->lr_cfg = lr_cfg;
    lr->name = xstrdup(lr_cfg->name);
    shash_add(&vtepctl_ctx->lrouters, lr->name, lr);
    return lr;
}

static void
del_cached_lrouter(struct vtep_ctl_context *ctx, struct vtep_ctl_lrouter *lr)
{
    if (lr->lr_cfg) {
        vteprec_logical_router_delete(lr->lr_cfg);
    }
    shash_find_and_delete(&ctx->lrouters, lr->name);
    free(lr->name);
    free(lr);
}

static struct vteprec_physical_locator *
find_ploc(struct vtep_ctl_context *vtepctl_ctx, const char *encap,
          const char *dst_ip)
{
    struct vteprec_physical_locator *ploc;
    char *name = xasprintf("%s+%s", encap, dst_ip);

    ovs_assert(vtepctl_ctx->cache_valid);

    ploc = shash_find_data(&vtepctl_ctx->plocs, name);
    free(name);

    return ploc;
}

static void
add_ploc_to_cache(struct vtep_ctl_context *vtepctl_ctx,
                  struct vteprec_physical_locator *ploc)
{
    char *name = xasprintf("%s+%s", ploc->encapsulation_type, ploc->dst_ip);
    struct vteprec_physical_locator *orig_ploc;

    orig_ploc = find_ploc(vtepctl_ctx, ploc->encapsulation_type, ploc->dst_ip);
    if (!orig_ploc) {
        shash_add(&vtepctl_ctx->plocs, name, ploc);
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
    ovs_list_push_back(&mcast_mac->locators, &ploc->locators_node);
}

static void
del_ploc_from_mcast_mac(struct vtep_ctl_mcast_mac *mcast_mac,
                        struct vteprec_physical_locator *ploc_cfg)
{
    struct vtep_ctl_ploc *ploc;

    LIST_FOR_EACH (ploc, locators_node, &mcast_mac->locators) {
        if (ploc->ploc_cfg == ploc_cfg) {
            ovs_list_remove(&ploc->locators_node);
            free(ploc);
            return;
        }
    }
}

static struct vtep_ctl_mcast_mac *
add_mcast_mac_to_cache(struct vtep_ctl_context *vtepctl_ctx,
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
    ovs_list_init(&mcast_mac->locators);
    shash_add(mcast_shash, mac, mcast_mac);

    for (i = 0; i < ploc_set_cfg->n_locators; i++) {
        struct vteprec_physical_locator *ploc_cfg;

        ploc_cfg = ploc_set_cfg->locators[i];
        add_ploc_to_mcast_mac(mcast_mac, ploc_cfg);
        add_ploc_to_cache(vtepctl_ctx, ploc_cfg);
    }

    return mcast_mac;
}

static void
vtep_ctl_context_invalidate_cache(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct shash_node *node;

    if (!vtepctl_ctx->cache_valid) {
        return;
    }
    vtepctl_ctx->cache_valid = false;

    SHASH_FOR_EACH (node, &vtepctl_ctx->pswitches) {
        struct vtep_ctl_pswitch *ps = node->data;
        free(ps->name);
        free(ps);
    }
    shash_destroy(&vtepctl_ctx->pswitches);

    SHASH_FOR_EACH (node, &vtepctl_ctx->ports) {
        struct vtep_ctl_port *port = node->data;
        shash_destroy(&port->bindings);
    }
    shash_destroy_free_data(&vtepctl_ctx->ports);

    SHASH_FOR_EACH (node, &vtepctl_ctx->lswitches) {
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
    shash_destroy(&vtepctl_ctx->lswitches);
    shash_destroy(&vtepctl_ctx->plocs);

    SHASH_FOR_EACH (node, &vtepctl_ctx->lrouters) {
        struct vtep_ctl_lrouter *lr = node->data;
        free(lr->name);
        free(lr);
    }
    shash_destroy(&vtepctl_ctx->lrouters);
}

static void
pre_get_info(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &vteprec_global_col_switches);

    ovsdb_idl_add_column(ctx->idl, &vteprec_physical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &vteprec_physical_switch_col_ports);
    ovsdb_idl_add_column(ctx->idl, &vteprec_physical_switch_col_tunnels);

    ovsdb_idl_add_column(ctx->idl, &vteprec_physical_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &vteprec_physical_port_col_vlan_bindings);

    ovsdb_idl_add_column(ctx->idl, &vteprec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl,
                         &vteprec_logical_switch_col_replication_mode);

    ovsdb_idl_add_column(ctx->idl, &vteprec_logical_router_col_name);

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

    ovsdb_idl_add_column(ctx->idl, &vteprec_tunnel_col_local);
    ovsdb_idl_add_column(ctx->idl, &vteprec_tunnel_col_remote);
}

static void
vtep_ctl_context_populate_cache(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    const struct vteprec_global *vtep_global = vtepctl_ctx->vtep_global;
    const struct vteprec_logical_switch *ls_cfg;
    const struct vteprec_logical_router *lr_cfg;
    const struct vteprec_ucast_macs_local *ucast_local_cfg;
    const struct vteprec_ucast_macs_remote *ucast_remote_cfg;
    const struct vteprec_mcast_macs_local *mcast_local_cfg;
    const struct vteprec_mcast_macs_remote *mcast_remote_cfg;
    const struct vteprec_tunnel *tunnel_cfg;
    struct sset pswitches, ports, lswitches;
    struct sset lrouters;
    size_t i;

    if (vtepctl_ctx->cache_valid) {
        /* Cache is already populated. */
        return;
    }
    vtepctl_ctx->cache_valid = true;
    shash_init(&vtepctl_ctx->pswitches);
    shash_init(&vtepctl_ctx->ports);
    shash_init(&vtepctl_ctx->lswitches);
    shash_init(&vtepctl_ctx->plocs);
    shash_init(&vtepctl_ctx->lrouters);

    sset_init(&pswitches);
    sset_init(&ports);
    for (i = 0; i < vtep_global->n_switches; i++) {
        struct vteprec_physical_switch *ps_cfg = vtep_global->switches[i];
        size_t j;

        if (!sset_add(&pswitches, ps_cfg->name)) {
            VLOG_WARN("%s: database contains duplicate physical switch name",
                      ps_cfg->name);
            continue;
        }
        add_pswitch_to_cache(vtepctl_ctx, ps_cfg);

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
        add_lswitch_to_cache(vtepctl_ctx, ls_cfg);
    }
    sset_destroy(&lswitches);

    sset_init(&lrouters);
    VTEPREC_LOGICAL_ROUTER_FOR_EACH (lr_cfg, ctx->idl) {
        if (!sset_add(&lrouters, lr_cfg->name)) {
            VLOG_WARN("%s: database contains duplicate logical router name",
                      lr_cfg->name);
            continue;
        }
        add_lrouter_to_cache(vtepctl_ctx, lr_cfg);
    }
    sset_destroy(&lrouters);

    VTEPREC_UCAST_MACS_LOCAL_FOR_EACH (ucast_local_cfg, ctx->idl) {
        struct vtep_ctl_lswitch *ls;

        if (!ucast_local_cfg->logical_switch) {
            continue;
        }
        ls = find_lswitch(vtepctl_ctx, ucast_local_cfg->logical_switch->name,
                          false);
        if (!ls) {
            continue;
        }

        if (ucast_local_cfg->locator) {
            add_ploc_to_cache(vtepctl_ctx, ucast_local_cfg->locator);
        }

        shash_add(&ls->ucast_local, ucast_local_cfg->MAC, ucast_local_cfg);
    }

    VTEPREC_UCAST_MACS_REMOTE_FOR_EACH (ucast_remote_cfg, ctx->idl) {
        struct vtep_ctl_lswitch *ls;

        if (!ucast_remote_cfg->logical_switch) {
            continue;
        }
        ls = find_lswitch(vtepctl_ctx, ucast_remote_cfg->logical_switch->name,
                          false);
        if (!ls) {
            continue;
        }

        if (ucast_remote_cfg->locator) {
            add_ploc_to_cache(vtepctl_ctx, ucast_remote_cfg->locator);
        }

        shash_add(&ls->ucast_remote, ucast_remote_cfg->MAC, ucast_remote_cfg);
    }

    VTEPREC_MCAST_MACS_LOCAL_FOR_EACH (mcast_local_cfg, ctx->idl) {
        struct vtep_ctl_mcast_mac *mcast_mac;
        struct vtep_ctl_lswitch *ls;

        if (!mcast_local_cfg->logical_switch) {
            continue;
        }
        ls = find_lswitch(vtepctl_ctx, mcast_local_cfg->logical_switch->name,
                          false);
        if (!ls) {
            continue;
        }

        mcast_mac = add_mcast_mac_to_cache(vtepctl_ctx, ls, mcast_local_cfg->MAC,
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
        ls = find_lswitch(vtepctl_ctx, mcast_remote_cfg->logical_switch->name,
                          false);
        if (!ls) {
            continue;
        }

        mcast_mac = add_mcast_mac_to_cache(vtepctl_ctx, ls, mcast_remote_cfg->MAC,
                                           mcast_remote_cfg->locator_set,
                                           false);
        mcast_mac->remote_cfg = mcast_remote_cfg;
    }

    VTEPREC_TUNNEL_FOR_EACH (tunnel_cfg, ctx->idl) {
        if (tunnel_cfg->local) {
            add_ploc_to_cache(vtepctl_ctx, tunnel_cfg->local);
        }
        if (tunnel_cfg->remote) {
            add_ploc_to_cache(vtepctl_ctx, tunnel_cfg->remote);
        }
    }

    sset_init(&pswitches);
    for (i = 0; i < vtep_global->n_switches; i++) {
        struct vteprec_physical_switch *ps_cfg = vtep_global->switches[i];
        struct vtep_ctl_pswitch *ps;
        size_t j;

        if (!sset_add(&pswitches, ps_cfg->name)) {
            continue;
        }
        ps = shash_find_data(&vtepctl_ctx->pswitches, ps_cfg->name);
        for (j = 0; j < ps_cfg->n_ports; j++) {
            struct vteprec_physical_port *port_cfg = ps_cfg->ports[j];
            struct vtep_ctl_port *port;
            size_t k;

            port = shash_find_data(&vtepctl_ctx->ports, port_cfg->name);
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

            port = add_port_to_cache(vtepctl_ctx, ps, port_cfg);

            for (k = 0; k < port_cfg->n_vlan_bindings; k++) {
                struct vtep_ctl_lswitch *ls;
                char *vlan;

                vlan = xasprintf("%"PRId64, port_cfg->key_vlan_bindings[k]);
                if (shash_find(&port->bindings, vlan)) {
                    ctl_fatal("multiple bindings for vlan %s", vlan);
                }

                ls_cfg = port_cfg->value_vlan_bindings[k];
                ls = find_lswitch(vtepctl_ctx, ls_cfg->name, true);

                shash_add_nocopy(&port->bindings, vlan, ls);
            }
        }
    }
    sset_destroy(&pswitches);
}

static struct vtep_ctl_pswitch *
find_pswitch(struct vtep_ctl_context *vtepctl_ctx, const char *name, bool must_exist)
{
    struct vtep_ctl_pswitch *ps;

    ovs_assert(vtepctl_ctx->cache_valid);

    ps = shash_find_data(&vtepctl_ctx->pswitches, name);
    if (must_exist && !ps) {
        ctl_fatal("no physical switch named %s", name);
    }
    vteprec_global_verify_switches(vtepctl_ctx->vtep_global);
    return ps;
}

static struct vtep_ctl_port *
find_port(struct vtep_ctl_context *vtepctl_ctx, const char *ps_name,
          const char *port_name, bool must_exist)
{
    char *cache_name = xasprintf("%s+%s", ps_name, port_name);
    struct vtep_ctl_port *port;

    ovs_assert(vtepctl_ctx->cache_valid);

    port = shash_find_data(&vtepctl_ctx->ports, cache_name);
    if (port && !strcmp(port_name, port->ps->name)) {
        port = NULL;
    }
    free(cache_name);
    if (must_exist && !port) {
        ctl_fatal("no port named %s", port_name);
    }
    verify_ports(vtepctl_ctx);
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
cmd_add_ps(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    const char *ps_name = ctx->argv[1];
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    struct vteprec_physical_switch *ps;

    vtep_ctl_context_populate_cache(ctx);
    if (find_pswitch(vtepctl_ctx, ps_name, false)) {
        if (!may_exist) {
            ctl_fatal("cannot create physical switch %s because it "
                      "already exists", ps_name);
        }
        return;
    }

    ps = vteprec_physical_switch_insert(ctx->txn);
    vteprec_physical_switch_set_name(ps, ps_name);

    vtep_insert_pswitch(vtepctl_ctx->vtep_global, ps);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
del_port(struct vtep_ctl_context *vtepctl_ctx, struct vtep_ctl_port *port)
{
    pswitch_delete_port(port->ps->ps_cfg, port->port_cfg);
    del_cached_port(vtepctl_ctx, port);
}

static void
del_pswitch(struct vtep_ctl_context *vtepctl_ctx, struct vtep_ctl_pswitch *ps)
{
    struct vtep_ctl_port *port, *next_port;

    LIST_FOR_EACH_SAFE (port, next_port, ports_node, &ps->ports) {
        del_port(vtepctl_ctx, port);
    }

    del_cached_pswitch(vtepctl_ctx, ps);
}

static void
cmd_del_ps(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vtep_ctl_pswitch *ps;

    vtep_ctl_context_populate_cache(ctx);
    ps = find_pswitch(vtepctl_ctx, ctx->argv[1], must_exist);
    if (ps) {
        del_pswitch(vtepctl_ctx, ps);
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
cmd_list_ps(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct shash_node *node;
    struct svec pswitches;

    vtep_ctl_context_populate_cache(ctx);

    svec_init(&pswitches);
    SHASH_FOR_EACH (node, &vtepctl_ctx->pswitches) {
        struct vtep_ctl_pswitch *ps = node->data;

        svec_add(&pswitches, ps->name);
    }
    output_sorted(&pswitches, &ctx->output);
    svec_destroy(&pswitches);
}

static void
cmd_ps_exists(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);

    vtep_ctl_context_populate_cache(ctx);
    if (!find_pswitch(vtepctl_ctx, ctx->argv[1], false)) {
        vtep_ctl_exit(2);
    }
}

static void
cmd_list_ports(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_pswitch *ps;
    struct vtep_ctl_port *port;
    struct svec ports;

    vtep_ctl_context_populate_cache(ctx);
    ps = find_pswitch(vtepctl_ctx, ctx->argv[1], true);
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
add_port(struct ctl_context *ctx, const char *ps_name,
         const char *port_name, bool may_exist)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_port *vtep_ctl_port;
    struct vtep_ctl_pswitch *ps;
    struct vteprec_physical_port *port;

    vtep_ctl_context_populate_cache(ctx);

    vtep_ctl_port = find_port(vtepctl_ctx, ps_name, port_name, false);
    if (vtep_ctl_port) {
        if (!may_exist) {
            ctl_fatal("cannot create a port named %s on %s because a "
                      "port with that name already exists",
                      port_name, ps_name);
        }
        return;
    }

    ps = find_pswitch(vtepctl_ctx, ps_name, true);

    port = vteprec_physical_port_insert(ctx->txn);
    vteprec_physical_port_set_name(port, port_name);

    pswitch_insert_port(ps->ps_cfg, port);

    add_port_to_cache(vtepctl_ctx, ps, port);
}

static void
cmd_add_port(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;

    add_port(ctx, ctx->argv[1], ctx->argv[2], may_exist);
}

static void
cmd_del_port(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vtep_ctl_port *port;

    vtep_ctl_context_populate_cache(ctx);

    port = find_port(vtepctl_ctx, ctx->argv[1], ctx->argv[2], must_exist);
    if (port) {
        if (ctx->argc == 3) {
            struct vtep_ctl_pswitch *ps;

            ps = find_pswitch(vtepctl_ctx, ctx->argv[1], true);
            if (port->ps != ps) {
                ctl_fatal("physical switch %s does not have a port %s",
                          ctx->argv[1], ctx->argv[2]);
            }
        }

        del_port(vtepctl_ctx, port);
    }
}

static struct vtep_ctl_lswitch *
find_lswitch(struct vtep_ctl_context *vtepctl_ctx,
             const char *name, bool must_exist)
{
    struct vtep_ctl_lswitch *ls;

    ovs_assert(vtepctl_ctx->cache_valid);

    ls = shash_find_data(&vtepctl_ctx->lswitches, name);
    if (must_exist && !ls) {
        ctl_fatal("no logical switch named %s", name);
    }
    return ls;
}

static void
cmd_add_ls(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    const char *ls_name = ctx->argv[1];
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    struct vteprec_logical_switch *ls;

    vtep_ctl_context_populate_cache(ctx);
    if (find_lswitch(vtepctl_ctx, ls_name, false)) {
        if (!may_exist) {
            ctl_fatal("cannot create logical switch %s because it "
                      "already exists", ls_name);
        }
        return;
    }

    ls = vteprec_logical_switch_insert(ctx->txn);
    vteprec_logical_switch_set_name(ls, ls_name);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
del_lswitch(struct vtep_ctl_context *vtepctl_ctx, struct vtep_ctl_lswitch *ls)
{
    del_cached_lswitch(vtepctl_ctx, ls);
}

static void
cmd_del_ls(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vtep_ctl_lswitch *ls;

    vtep_ctl_context_populate_cache(ctx);
    ls = find_lswitch(vtepctl_ctx, ctx->argv[1], must_exist);
    if (ls) {
        del_lswitch(vtepctl_ctx, ls);
    }
}

static void
cmd_list_ls(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct shash_node *node;
    struct svec lswitches;

    vtep_ctl_context_populate_cache(ctx);

    svec_init(&lswitches);
    SHASH_FOR_EACH (node, &vtepctl_ctx->lswitches) {
        struct vtep_ctl_lswitch *ls = node->data;

        svec_add(&lswitches, ls->name);
    }
    output_sorted(&lswitches, &ctx->output);
    svec_destroy(&lswitches);
}

static void
cmd_ls_exists(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);

    vtep_ctl_context_populate_cache(ctx);
    if (!find_lswitch(vtepctl_ctx, ctx->argv[1], false)) {
        vtep_ctl_exit(2);
    }
}

static void
cmd_list_bindings(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    const struct shash_node *node;
    struct vtep_ctl_port *port;
    struct svec bindings;

    vtep_ctl_context_populate_cache(ctx);
    port = find_port(vtepctl_ctx, ctx->argv[1], ctx->argv[2], true);

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
cmd_bind_ls(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_lswitch *ls;
    struct vtep_ctl_port *port;
    const char *vlan;

    vtep_ctl_context_populate_cache(ctx);

    port = find_port(vtepctl_ctx, ctx->argv[1], ctx->argv[2], true);
    vlan = ctx->argv[3];
    ls = find_lswitch(vtepctl_ctx, ctx->argv[4], true);

    add_ls_binding_to_cache(port, vlan, ls);
    commit_ls_bindings(port);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
cmd_unbind_ls(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_port *port;
    const char *vlan;

    vtep_ctl_context_populate_cache(ctx);

    port = find_port(vtepctl_ctx, ctx->argv[1], ctx->argv[2], true);
    vlan = ctx->argv[3];

    del_cached_ls_binding(port, vlan);
    commit_ls_bindings(port);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
cmd_set_replication_mode(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_lswitch *ls;
    const char *ls_name = ctx->argv[1];

    vtep_ctl_context_populate_cache(ctx);

    if (strcmp(ctx->argv[2], "service_node") &&
        strcmp(ctx->argv[2], "source_node")) {
        ctl_fatal("Replication mode must be 'service_node' or 'source_node'");
    }

    ls = find_lswitch(vtepctl_ctx, ls_name, true);
    vteprec_logical_switch_set_replication_mode(ls->ls_cfg, ctx->argv[2]);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
cmd_get_replication_mode(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_lswitch *ls;
    const char *ls_name = ctx->argv[1];

    vtep_ctl_context_populate_cache(ctx);

    ls = find_lswitch(vtepctl_ctx, ls_name, true);
    ds_put_format(&ctx->output, "%s\n", ls->ls_cfg->replication_mode);
}

static struct vtep_ctl_lrouter *
find_lrouter(struct vtep_ctl_context *vtepctl_ctx,
             const char *name, bool must_exist)
{
    struct vtep_ctl_lrouter *lr;

    ovs_assert(vtepctl_ctx->cache_valid);

    lr = shash_find_data(&vtepctl_ctx->lrouters, name);
    if (must_exist && !lr) {
        ctl_fatal("no logical router named %s", name);
    }
    return lr;
}

static void
cmd_add_lr(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    const char *lr_name = ctx->argv[1];
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    struct vteprec_logical_router *lr;

    vtep_ctl_context_populate_cache(ctx);
    if (find_lrouter(vtepctl_ctx, lr_name, false)) {
        if (!may_exist) {
            ctl_fatal("cannot create logical router %s because it "
                      "already exists", lr_name);
        }
        return;
    }

    lr = vteprec_logical_router_insert(ctx->txn);
    vteprec_logical_router_set_name(lr, lr_name);

    vtep_ctl_context_invalidate_cache(ctx);
}

static void
del_lrouter(struct vtep_ctl_context *vtepctl_ctx, struct vtep_ctl_lrouter *lr)
{
    del_cached_lrouter(vtepctl_ctx, lr);
}

static void
cmd_del_lr(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vtep_ctl_lrouter *lr;

    vtep_ctl_context_populate_cache(ctx);
    lr = find_lrouter(vtepctl_ctx, ctx->argv[1], must_exist);
    if (lr) {
        del_lrouter(vtepctl_ctx, lr);
    }
}

static void
cmd_list_lr(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct shash_node *node;
    struct svec lrouters;

    vtep_ctl_context_populate_cache(ctx);

    svec_init(&lrouters);
    SHASH_FOR_EACH (node, &vtepctl_ctx->lrouters) {
        struct vtep_ctl_lrouter *lr = node->data;

        svec_add(&lrouters, lr->name);
    }
    output_sorted(&lrouters, &ctx->output);
    svec_destroy(&lrouters);
}

static void
cmd_lr_exists(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);

    vtep_ctl_context_populate_cache(ctx);
    if (!find_lrouter(vtepctl_ctx, ctx->argv[1], false)) {
        vtep_ctl_exit(2);
    }
}

static void
add_ucast_entry(struct ctl_context *ctx, bool local)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_lswitch *ls;
    const char *mac;
    const char *encap;
    const char *dst_ip;
    struct vteprec_physical_locator *ploc_cfg;

    vtep_ctl_context_populate_cache(ctx);

    ls = find_lswitch(vtepctl_ctx, ctx->argv[1], true);
    mac = ctx->argv[2];

    if (ctx->argc == 4) {
        encap = "vxlan_over_ipv4";
        dst_ip = ctx->argv[3];
    } else {
        encap = ctx->argv[3];
        dst_ip = ctx->argv[4];
    }

    ploc_cfg = find_ploc(vtepctl_ctx, encap, dst_ip);
    if (!ploc_cfg) {
        ploc_cfg = vteprec_physical_locator_insert(ctx->txn);
        vteprec_physical_locator_set_dst_ip(ploc_cfg, dst_ip);
        vteprec_physical_locator_set_encapsulation_type(ploc_cfg, encap);

        add_ploc_to_cache(vtepctl_ctx, ploc_cfg);
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
cmd_add_ucast_local(struct ctl_context *ctx)
{
    add_ucast_entry(ctx, true);
}

static void
cmd_add_ucast_remote(struct ctl_context *ctx)
{
    add_ucast_entry(ctx, false);
}

static void
del_ucast_entry(struct ctl_context *ctx, bool local)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_lswitch *ls;
    struct shash *ucast_shash;
    struct shash_node *node;

    vtep_ctl_context_populate_cache(ctx);

    ls = find_lswitch(vtepctl_ctx, ctx->argv[1], true);
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
cmd_del_ucast_local(struct ctl_context *ctx)
{
    del_ucast_entry(ctx, true);
}

static void
cmd_del_ucast_remote(struct ctl_context *ctx)
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

    n_locators = ovs_list_size(&mcast_mac->locators);
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
add_mcast_entry(struct ctl_context *ctx,
                struct vtep_ctl_lswitch *ls, const char *mac,
                const char *encap, const char *dst_ip, bool local)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct shash *mcast_shash;
    struct vtep_ctl_mcast_mac *mcast_mac;
    struct vteprec_physical_locator *ploc_cfg;
    struct vteprec_physical_locator_set *ploc_set_cfg;

    mcast_shash = local ? &ls->mcast_local : &ls->mcast_remote;

    /* Physical locator sets are immutable, so allocate a new one. */
    ploc_set_cfg = vteprec_physical_locator_set_insert(ctx->txn);

    mcast_mac = shash_find_data(mcast_shash, mac);
    if (!mcast_mac) {
        mcast_mac = add_mcast_mac_to_cache(vtepctl_ctx, ls, mac, ploc_set_cfg,
                                           local);

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

    ploc_cfg = find_ploc(vtepctl_ctx, encap, dst_ip);
    if (!ploc_cfg) {
        ploc_cfg = vteprec_physical_locator_insert(ctx->txn);
        vteprec_physical_locator_set_dst_ip(ploc_cfg, dst_ip);
        vteprec_physical_locator_set_encapsulation_type(ploc_cfg, encap);

        add_ploc_to_cache(vtepctl_ctx, ploc_cfg);
    }

    add_ploc_to_mcast_mac(mcast_mac, ploc_cfg);
    commit_mcast_entries(mcast_mac);
}

static void
del_mcast_entry(struct ctl_context *ctx,
                struct vtep_ctl_lswitch *ls, const char *mac,
                const char *encap, const char *dst_ip, bool local)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_mcast_mac *mcast_mac;
    struct shash *mcast_shash;
    struct vteprec_physical_locator *ploc_cfg;
    struct vteprec_physical_locator_set *ploc_set_cfg;

    mcast_shash = local ? &ls->mcast_local : &ls->mcast_remote;

    mcast_mac = shash_find_data(mcast_shash, mac);
    if (!mcast_mac) {
        return;
    }

    ploc_cfg = find_ploc(vtepctl_ctx, encap, dst_ip);
    if (!ploc_cfg) {
        /* Couldn't find the physical locator, so just ignore. */
        return;
    }

    /* Physical locator sets are immutable, so allocate a new one. */
    ploc_set_cfg = vteprec_physical_locator_set_insert(ctx->txn);
    mcast_mac->ploc_set_cfg = ploc_set_cfg;

    del_ploc_from_mcast_mac(mcast_mac, ploc_cfg);
    if (ovs_list_is_empty(&mcast_mac->locators)) {
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
add_del_mcast_entry(struct ctl_context *ctx, bool add, bool local)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_lswitch *ls;
    const char *mac;
    const char *encap;
    const char *dst_ip;

    vtep_ctl_context_populate_cache(ctx);

    ls = find_lswitch(vtepctl_ctx, ctx->argv[1], true);
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
cmd_add_mcast_local(struct ctl_context *ctx)
{
    add_del_mcast_entry(ctx, true, true);
}

static void
cmd_add_mcast_remote(struct ctl_context *ctx)
{
    add_del_mcast_entry(ctx, true, false);
}

static void
cmd_del_mcast_local(struct ctl_context *ctx)
{
    add_del_mcast_entry(ctx, false, true);
}

static void
cmd_del_mcast_remote(struct ctl_context *ctx)
{
    add_del_mcast_entry(ctx, false, false);
}

static void
clear_macs(struct ctl_context *ctx, bool local)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_lswitch *ls;
    const struct shash_node *node;
    struct shash *ucast_shash;
    struct shash *mcast_shash;

    vtep_ctl_context_populate_cache(ctx);
    ls = find_lswitch(vtepctl_ctx, ctx->argv[1], true);

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
cmd_clear_local_macs(struct ctl_context *ctx)
{
    clear_macs(ctx, true);
}

static void
cmd_clear_remote_macs(struct ctl_context *ctx)
{
    clear_macs(ctx, false);
}

static void
list_macs(struct ctl_context *ctx, bool local)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    struct vtep_ctl_lswitch *ls;
    const struct shash_node *node;
    struct shash *ucast_shash;
    struct svec ucast_macs;
    struct shash *mcast_shash;
    struct svec mcast_macs;

    vtep_ctl_context_populate_cache(ctx);
    ls = find_lswitch(vtepctl_ctx, ctx->argv[1], true);

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
cmd_list_local_macs(struct ctl_context *ctx)
{
    list_macs(ctx, true);
}

static void
cmd_list_remote_macs(struct ctl_context *ctx)
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
pre_manager(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &vteprec_global_col_managers);
    ovsdb_idl_add_column(ctx->idl, &vteprec_manager_col_target);
    ovsdb_idl_add_column(ctx->idl, &vteprec_manager_col_inactivity_probe);
}

static void
cmd_get_manager(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    const struct vteprec_global *vtep_global = vtepctl_ctx->vtep_global;
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
delete_managers(const struct vtep_ctl_context *vtepctl_ctx)
{
    const struct vteprec_global *vtep_global = vtepctl_ctx->vtep_global;
    size_t i;

    /* Delete Manager rows pointed to by 'managers' column. */
    for (i = 0; i < vtep_global->n_managers; i++) {
        vteprec_manager_delete(vtep_global->managers[i]);
    }

    /* Delete 'Manager' row refs in 'managers' column. */
    vteprec_global_set_managers(vtep_global, NULL, 0);
}

static void
cmd_del_manager(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    const struct vteprec_global *vtep_global = vtepctl_ctx->vtep_global;

    verify_managers(vtep_global);
    delete_managers(vtepctl_ctx);
}

static void
insert_managers(struct vtep_ctl_context *vtepctl_ctx, char *targets[],
                size_t n, struct shash *options)
{
    struct vteprec_manager **managers;
    size_t i;
    const char *inactivity_probe = shash_find_data(options,
                                                   "--inactivity-probe");

    /* Insert each manager in a new row in Manager table. */
    managers = xmalloc(n * sizeof *managers);
    for (i = 0; i < n; i++) {
        if (stream_verify_name(targets[i]) && pstream_verify_name(targets[i])) {
            VLOG_WARN("target type \"%s\" is possibly erroneous", targets[i]);
        }
        managers[i] = vteprec_manager_insert(vtepctl_ctx->base.txn);
        vteprec_manager_set_target(managers[i], targets[i]);
        if (inactivity_probe) {
            int64_t msecs = atoll(inactivity_probe);
            vteprec_manager_set_inactivity_probe(managers[i], &msecs, 1);
        }
    }

    /* Store uuids of new Manager rows in 'managers' column. */
    vteprec_global_set_managers(vtepctl_ctx->vtep_global, managers, n);
    free(managers);
}

static void
cmd_set_manager(struct ctl_context *ctx)
{
    struct vtep_ctl_context *vtepctl_ctx = vtep_ctl_context_cast(ctx);
    const size_t n = ctx->argc - 1;

    verify_managers(vtepctl_ctx->vtep_global);
    delete_managers(vtepctl_ctx);
    insert_managers(vtepctl_ctx, &ctx->argv[1], n, &ctx->options);
}

/* Parameter commands. */
static const struct ctl_table_class tables[VTEPREC_N_TABLES] = {
    [VTEPREC_TABLE_LOGICAL_SWITCH].row_ids[0]
    = {&vteprec_logical_switch_col_name, NULL, NULL},

    [VTEPREC_TABLE_MANAGER].row_ids[0]
    = {&vteprec_manager_col_target, NULL, NULL},

    [VTEPREC_TABLE_PHYSICAL_PORT].row_ids[0]
    = {&vteprec_physical_port_col_name, NULL, NULL},

    [VTEPREC_TABLE_PHYSICAL_SWITCH].row_ids[0]
    = {&vteprec_physical_switch_col_name, NULL, NULL},

    [VTEPREC_TABLE_LOGICAL_ROUTER].row_ids[0]
    = {&vteprec_logical_router_col_name, NULL, NULL},
};


static void
vtep_ctl_context_init_command(struct vtep_ctl_context *vtepctl_ctx,
                              struct ctl_command *command)
{
    ctl_context_init_command(&vtepctl_ctx->base, command);
    vtepctl_ctx->verified_ports = false;

}

static void
vtep_ctl_context_init(struct vtep_ctl_context *vtepctl_ctx,
                      struct ctl_command *command,
                      struct ovsdb_idl *idl, struct ovsdb_idl_txn *txn,
                      const struct vteprec_global *vtep_global,
                      struct ovsdb_symbol_table *symtab)
{
    ctl_context_init(&vtepctl_ctx->base, command, idl, txn, symtab,
                     vtep_ctl_context_invalidate_cache);
    if (command) {
        vtepctl_ctx->verified_ports = false;
    }
    vtepctl_ctx->vtep_global = vtep_global;
    vtepctl_ctx->cache_valid = false;
}

static void
vtep_ctl_context_done_command(struct vtep_ctl_context *vtepctl_ctx,
                              struct ctl_command *command)
{
    ctl_context_done_command(&vtepctl_ctx->base, command);
}

static void
vtep_ctl_context_done(struct vtep_ctl_context *vtepctl_ctx,
                      struct ctl_command *command)
{
    ctl_context_done(&vtepctl_ctx->base, command);
}

static void
run_prerequisites(struct ctl_command *commands, size_t n_commands,
                  struct ovsdb_idl *idl)
{
    struct ctl_command *c;

    ovsdb_idl_add_table(idl, &vteprec_table_global);
    for (c = commands; c < &commands[n_commands]; c++) {
        if (c->syntax->prerequisites) {
            struct vtep_ctl_context vtepctl_ctx;

            ds_init(&c->output);
            c->table = NULL;

            vtep_ctl_context_init(&vtepctl_ctx, c, idl, NULL, NULL, NULL);
            (c->syntax->prerequisites)(&vtepctl_ctx.base);
            if (vtepctl_ctx.base.error) {
                ctl_fatal("%s", vtepctl_ctx.base.error);
            }
            vtep_ctl_context_done(&vtepctl_ctx, c);

            ovs_assert(!c->output.string);
            ovs_assert(!c->table);
        }
    }
}

static bool
do_vtep_ctl(const char *args, struct ctl_command *commands,
            size_t n_commands, struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;
    const struct vteprec_global *vtep_global;
    enum ovsdb_idl_txn_status status;
    struct ovsdb_symbol_table *symtab;
    struct vtep_ctl_context vtepctl_ctx;
    struct ctl_command *c;
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
    vtep_ctl_context_init(&vtepctl_ctx, NULL, idl, txn, vtep_global, symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        vtep_ctl_context_init_command(&vtepctl_ctx, c);
        if (c->syntax->run) {
            (c->syntax->run)(&vtepctl_ctx.base);
        }
        if (vtepctl_ctx.base.error) {
            ctl_fatal("%s", vtepctl_ctx.base.error);
        }
        vtep_ctl_context_done_command(&vtepctl_ctx, c);

        if (vtepctl_ctx.base.try_again) {
            vtep_ctl_context_done(&vtepctl_ctx, NULL);
            goto try_again;
        }
    }
    vtep_ctl_context_done(&vtepctl_ctx, NULL);

    SHASH_FOR_EACH (node, &symtab->sh) {
        struct ovsdb_symbol *symbol = node->data;
        if (!symbol->created) {
            ctl_fatal("row id \"%s\" is referenced but never created "
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
                vtep_ctl_context_init(&vtepctl_ctx, c, idl, txn, vtep_global, symtab);
                (c->syntax->postprocess)(&vtepctl_ctx.base);
                if (vtepctl_ctx.base.error) {
                    ctl_fatal("%s", vtepctl_ctx.base.error);
                }
                vtep_ctl_context_done(&vtepctl_ctx, c);
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

    ovsdb_idl_destroy(idl);

    return true;

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
    return false;
}

static const struct ctl_command_syntax vtep_commands[] = {
    /* Physical Switch commands. */
    {"add-ps", 1, 1, NULL, pre_get_info, cmd_add_ps, NULL, "--may-exist", RW},
    {"del-ps", 1, 1, NULL, pre_get_info, cmd_del_ps, NULL, "--if-exists", RW},
    {"list-ps", 0, 0, NULL, pre_get_info, cmd_list_ps, NULL, "", RO},
    {"ps-exists", 1, 1, NULL, pre_get_info, cmd_ps_exists, NULL, "", RO},

    /* Port commands. */
    {"list-ports", 1, 1, NULL, pre_get_info, cmd_list_ports, NULL, "", RO},
    {"add-port", 2, 2, NULL, pre_get_info, cmd_add_port, NULL, "--may-exist",
     RW},
    {"del-port", 2, 2, NULL, pre_get_info, cmd_del_port, NULL, "--if-exists",
     RW},

    /* Logical Switch commands. */
    {"add-ls", 1, 1, NULL, pre_get_info, cmd_add_ls, NULL, "--may-exist", RW},
    {"del-ls", 1, 1, NULL, pre_get_info, cmd_del_ls, NULL, "--if-exists", RW},
    {"list-ls", 0, 0, NULL, pre_get_info, cmd_list_ls, NULL, "", RO},
    {"ls-exists", 1, 1, NULL, pre_get_info, cmd_ls_exists, NULL, "", RO},
    {"list-bindings", 2, 2, NULL, pre_get_info, cmd_list_bindings, NULL, "", RO},
    {"bind-ls", 4, 4, NULL, pre_get_info, cmd_bind_ls, NULL, "", RO},
    {"unbind-ls", 3, 3, NULL, pre_get_info, cmd_unbind_ls, NULL, "", RO},
    {"set-replication-mode", 2, 2, "LS MODE", pre_get_info,
        cmd_set_replication_mode, NULL, "", RW},
    {"get-replication-mode", 1, 1, "LS", pre_get_info,
        cmd_get_replication_mode, NULL, "", RO},

    /* Logical Router commands. */
    {"add-lr", 1, 1, NULL, pre_get_info, cmd_add_lr, NULL, "--may-exist", RW},
    {"del-lr", 1, 1, NULL, pre_get_info, cmd_del_lr, NULL, "--if-exists", RW},
    {"list-lr", 0, 0, NULL, pre_get_info, cmd_list_lr, NULL, "", RO},
    {"lr-exists", 1, 1, NULL, pre_get_info, cmd_lr_exists, NULL, "", RO},

    /* MAC binding commands. */
    {"add-ucast-local", 3, 4, NULL, pre_get_info, cmd_add_ucast_local, NULL,
     "", RW},
    {"del-ucast-local", 2, 2, NULL, pre_get_info, cmd_del_ucast_local, NULL,
     "", RW},
    {"add-mcast-local", 3, 4, NULL, pre_get_info, cmd_add_mcast_local, NULL,
     "", RW},
    {"del-mcast-local", 3, 4, NULL, pre_get_info, cmd_del_mcast_local, NULL,
     "", RW},
    {"clear-local-macs", 1, 1, NULL, pre_get_info, cmd_clear_local_macs, NULL,
     "", RO},
    {"list-local-macs", 1, 1, NULL, pre_get_info, cmd_list_local_macs, NULL,
     "", RO},
    {"add-ucast-remote", 3, 4, NULL, pre_get_info, cmd_add_ucast_remote, NULL,
     "", RW},
    {"del-ucast-remote", 2, 2, NULL, pre_get_info, cmd_del_ucast_remote, NULL,
     "", RW},
    {"add-mcast-remote", 3, 4, NULL, pre_get_info, cmd_add_mcast_remote, NULL,
     "", RW},
    {"del-mcast-remote", 3, 4, NULL, pre_get_info, cmd_del_mcast_remote, NULL,
     "", RW},
    {"clear-remote-macs", 1, 1, NULL, pre_get_info, cmd_clear_remote_macs, NULL,
     "", RO},
    {"list-remote-macs", 1, 1, NULL, pre_get_info, cmd_list_remote_macs, NULL,
     "", RO},

    /* Manager commands. */
    {"get-manager", 0, 0, NULL, pre_manager, cmd_get_manager, NULL, "", RO},
    {"del-manager", 0, 0, NULL, pre_manager, cmd_del_manager, NULL, "", RW},
    {"set-manager", 1, INT_MAX, NULL, pre_manager, cmd_set_manager, NULL,
     "--inactivity-probe=", RW},

    {NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, RO},
};

/* Registers vsctl and common db commands. */
static void
vtep_ctl_cmd_init(void)
{
    ctl_init(&vteprec_idl_class, vteprec_table_classes, tables,
             cmd_show_tables, vtep_ctl_exit);
    ctl_register_commands(vtep_commands);
}
