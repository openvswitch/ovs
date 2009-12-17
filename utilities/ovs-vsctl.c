/*
 * Copyright (c) 2009 Nicira Networks.
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

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "json.h"
#include "ovsdb-idl.h"
#include "poll-loop.h"
#include "svec.h"
#include "vswitchd/vswitch-idl.h"
#include "timeval.h"
#include "util.h"

#include "vlog.h"
#define THIS_MODULE VLM_vsctl

/* --db: The database server to contact. */
static const char *db;

/* --oneline: Write each command's output as a single line? */
static bool oneline;

/* --dry-run: Do not commit any changes. */
static bool dry_run;

/* --no-wait: Wait for ovs-vswitchd to reload its configuration? */
static bool wait_for_reload = true;

/* --timeout: Time to wait for a connection to 'db'. */
static int timeout = 5;

static void vsctl_fatal(const char *, ...) PRINTF_FORMAT(1, 2) NO_RETURN;
static char *default_db(void);
static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

static void check_vsctl_command(int argc, char *argv[]);
static void do_vsctl(int argc, char *argv[], struct ovsdb_idl *idl);

int
main(int argc, char *argv[])
{
    struct ovsdb_idl *idl;
    unsigned int seqno;
    struct ds args;
    int start, n_commands;
    int trials;
    int i;

    set_program_name(argv[0]);
    signal(SIGPIPE, SIG_IGN);
    time_init();
    vlog_init();
    vlog_set_levels(VLM_ANY_MODULE, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(VLM_reconnect, VLF_ANY_FACILITY, VLL_WARN);
    parse_options(argc, argv);

    if (timeout) {
        time_alarm(timeout);
    }

    /* Log our arguments.  This is often valuable for debugging systems. */
    ds_init(&args);
    for (i = 1; i < argc; i++) {
        ds_put_format(&args, " %s", argv[i]);
    }
    VLOG_INFO("Called as%s", ds_cstr(&args));
    ds_destroy(&args);

    /* Do basic command syntax checking. */
    n_commands = 0;
    for (start = i = optind; i <= argc; i++) {
        if (i == argc || !strcmp(argv[i], "--")) {
            if (i > start) {
                check_vsctl_command(i - start, &argv[start]);
                n_commands++;
            }
            start = i + 1;
        }
    }
    if (!n_commands) {
        vsctl_fatal("missing command name (use --help for help)");
    }

    /* Now execute the commands. */
    idl = ovsdb_idl_create(db, &ovsrec_idl_class);
    seqno = ovsdb_idl_get_seqno(idl);
    trials = 0;
    for (;;) {
        unsigned int new_seqno;

        ovsdb_idl_run(idl);
        new_seqno = ovsdb_idl_get_seqno(idl);
        if (new_seqno != seqno) {
            if (++trials > 5) {
                vsctl_fatal("too many database inconsistency failures");
            }
            do_vsctl(argc - optind, argv + optind, idl);
            seqno = new_seqno;
        }

        ovsdb_idl_wait(idl);
        poll_block();
    }
}

static void
vsctl_fatal(const char *format, ...)
{
    char *message;
    va_list args;

    va_start(args, format);
    message = xvasprintf(format, args);
    va_end(args);

    vlog_set_levels(VLM_vsctl, VLF_CONSOLE, VLL_EMER);
    VLOG_ERR("%s", message);
    ovs_fatal(0, "%s", message);
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_DB = UCHAR_MAX + 1,
        OPT_ONELINE,
        OPT_NO_SYSLOG,
        OPT_NO_WAIT,
        OPT_DRY_RUN
    };
    static struct option long_options[] = {
        {"db", required_argument, 0, OPT_DB},
        {"no-syslog", no_argument, 0, OPT_NO_SYSLOG},
        {"no-wait", no_argument, 0, OPT_NO_WAIT},
        {"dry-run", no_argument, 0, OPT_DRY_RUN},
        {"oneline", no_argument, 0, OPT_ONELINE},
        {"timeout", required_argument, 0, 't'},
        {"verbose", optional_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
    };


    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, "+v::hVt:", long_options, NULL);
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
            vlog_set_levels(VLM_vsctl, VLF_SYSLOG, VLL_WARN);
            break;

        case OPT_NO_WAIT:
            wait_for_reload = false;
            break;

        case OPT_DRY_RUN:
            dry_run = true;
            break;

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(0, 0);
            exit(EXIT_SUCCESS);

        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout < 0) {
                ovs_fatal(0, "value %s on -t or --timeout is invalid",
                          optarg);
            }
            break;

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }

    if (!db) {
        db = default_db();
    }
}

static void
usage(void)
{
    printf("%s: ovs-vswitchd management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n",
           program_name, program_name);
    printf("\nBridge commands:\n"
           "  add-br BRIDGE               "
           "create a new bridge named BRIDGE\n"
           "  add-br BRIDGE PARENT VLAN   "
           "create new fake bridge BRIDGE in PARENT on VLAN\n"
           "  del-br BRIDGE               "
           "delete BRIDGE and all of its ports\n"
           "  list-br                     "
           "print the names of all the bridges\n"
           "  br-exists BRIDGE            "
           "test whether BRIDGE exists\n"
           "  br-to-vlan BRIDGE           "
           "print the VLAN which BRIDGE is on\n"
           "  br-to-parent BRIDGE         "
           "print the parent of BRIDGE\n"
           "  br-set-external-id BRIDGE KEY VALUE"
           "  set KEY on BRIDGE to VALUE\n"
           "  br-set-external-id BRIDGE KEY"
           "  unset KEY on BRIDGE\n"
           "  br-get-external-id BRIDGE KEY"
           "  print value of KEY on BRIDGE\n"
           "  br-get-external-id BRIDGE"
           "  list key-value pairs on BRIDGE\n"
        );
    printf("\nPort commands:\n"
           "  list-ports BRIDGE           "
           "print the names of all the ports on BRIDGE\n"
           "  add-port BRIDGE PORT        "
           "add network device PORT to BRIDGE\n"
           "  add-bond BRIDGE PORT IFACE...  "
           "add new bonded port PORT in BRIDGE from IFACES\n"
           "  del-port [BRIDGE] PORT      "
           "delete PORT (which may be bonded) from BRIDGE\n"
           "  port-to-br PORT             "
           "print name of bridge that contains PORT\n"
           "  port-set-external-id PORT KEY VALUE"
           "  set KEY on PORT to VALUE\n"
           "  port-set-external-id PORT KEY"
           "  unset KEY on PORT\n"
           "  port-get-external-id PORT KEY"
           "  print value of KEY on PORT\n"
           "  port-get-external-id PORT"
           "  list key-value pairs on PORT\n"
           "A bond is considered to be a single port.\n"
        );
    printf("\nInterface commands (a bond consists of multiple interfaces):\n"
           "  list-ifaces BRIDGE          "
           "print the names of all the interfaces on BRIDGE\n"
           "  iface-to-br IFACE           "
           "print name of bridge that contains IFACE\n"
           "  iface-set-external-id IFACE KEY VALUE"
           "  set KEY on IFACE to VALUE\n"
           "  iface-set-external-id IFACE KEY"
           "  unset KEY on IFACE\n"
           "  iface-get-external-id IFACE KEY"
           "  print value of KEY on IFACE\n"
           "  iface-get-external-id IFACE"
           "  list key-value pairs on IFACE\n"
        );
    printf("\nOptions:\n"
           "  --db=DATABASE               "
           "connect to DATABASE\n"
           "                              "
           "(default: %s)\n"
           "  --oneline                   "
           "print exactly one line of output per command\n",
           default_db());
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help                  "
           "display this help message\n"
           "  -V, --version               "
           "display version information\n");
    exit(EXIT_SUCCESS);
}

static char *
default_db(void)
{
    static char *def;
    if (!def) {
        def = xasprintf("unix:%s/ovsdb-server", ovs_rundir);
    }
    return def;
}

struct vsctl_context {
    int argc;
    char **argv;
    const struct ovsrec_open_vswitch *ovs;
    struct ds output;
    struct shash options;
};

struct vsctl_bridge {
    struct ovsrec_bridge *br_cfg;
    char *name;
    struct vsctl_bridge *parent;
    int vlan;
};

struct vsctl_port {
    struct ovsrec_port *port_cfg;
    struct vsctl_bridge *bridge;
};

struct vsctl_iface {
    struct ovsrec_interface *iface_cfg;
    struct vsctl_port *port;
};

struct vsctl_info {
    struct shash bridges;
    struct shash ports;
    struct shash ifaces;
};

static struct ovsdb_idl_txn *
txn_from_openvswitch(const struct ovsrec_open_vswitch *ovs)
{
    return ovsdb_idl_txn_get(&ovs->header_);
}

static struct vsctl_bridge *
add_bridge(struct vsctl_info *b,
           struct ovsrec_bridge *br_cfg, const char *name,
           struct vsctl_bridge *parent, int vlan)
{
    struct vsctl_bridge *br = xmalloc(sizeof *br);
    br->br_cfg = br_cfg;
    br->name = xstrdup(name);
    br->parent = parent;
    br->vlan = vlan;
    shash_add(&b->bridges, br->name, br);
    return br;
}

static bool
port_is_fake_bridge(const struct ovsrec_port *port_cfg)
{
    return (port_cfg->fake_bridge
            && port_cfg->tag
            && *port_cfg->tag >= 1 && *port_cfg->tag <= 4095);
}

static struct vsctl_bridge *
find_vlan_bridge(struct vsctl_info *info,
                 struct vsctl_bridge *parent, int vlan)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &info->bridges) {
        struct vsctl_bridge *br = node->data;
        if (br->parent == parent && br->vlan == vlan) {
            return br;
        }
    }

    return NULL;
}

static void
free_info(struct vsctl_info *info)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &info->bridges) {
        struct vsctl_bridge *bridge = node->data;
        free(bridge->name);
        free(bridge);
    }
    shash_destroy(&info->bridges);

    SHASH_FOR_EACH (node, &info->ports) {
        struct vsctl_port *port = node->data;
        free(port);
    }
    shash_destroy(&info->ports);

    SHASH_FOR_EACH (node, &info->ifaces) {
        struct vsctl_iface *iface = node->data;
        free(iface);
    }
    shash_destroy(&info->ifaces);
}

static void
get_info(const struct ovsrec_open_vswitch *ovs, struct vsctl_info *info)
{
    struct shash bridges, ports;
    size_t i;

    shash_init(&info->bridges);
    shash_init(&info->ports);
    shash_init(&info->ifaces);

    shash_init(&bridges);
    shash_init(&ports);
    for (i = 0; i < ovs->n_bridges; i++) {
        struct ovsrec_bridge *br_cfg = ovs->bridges[i];
        struct vsctl_bridge *br;
        size_t j;

        if (!shash_add_once(&bridges, br_cfg->name, NULL)) {
            VLOG_WARN("%s: database contains duplicate bridge name",
                      br_cfg->name);
            continue;
        }
        br = add_bridge(info, br_cfg, br_cfg->name, NULL, 0);
        if (!br) {
            continue;
        }

        for (j = 0; j < br_cfg->n_ports; j++) {
            struct ovsrec_port *port_cfg = br_cfg->ports[j];

            if (!shash_add_once(&ports, port_cfg->name, NULL)) {
                VLOG_WARN("%s: database contains duplicate port name",
                          port_cfg->name);
                continue;
            }

            if (port_is_fake_bridge(port_cfg)
                && shash_add_once(&bridges, port_cfg->name, NULL)) {
                add_bridge(info, NULL, port_cfg->name, br, *port_cfg->tag);
            }
        }
    }
    shash_destroy(&bridges);
    shash_destroy(&ports);

    shash_init(&bridges);
    shash_init(&ports);
    for (i = 0; i < ovs->n_bridges; i++) {
        struct ovsrec_bridge *br_cfg = ovs->bridges[i];
        struct vsctl_bridge *br;
        size_t j;

        if (!shash_add_once(&bridges, br_cfg->name, NULL)) {
            continue;
        }
        br = shash_find_data(&info->bridges, br_cfg->name);
        for (j = 0; j < br_cfg->n_ports; j++) {
            struct ovsrec_port *port_cfg = br_cfg->ports[j];
            struct vsctl_port *port;
            size_t k;

            if (!shash_add_once(&ports, port_cfg->name, NULL)) {
                continue;
            }

            if (port_is_fake_bridge(port_cfg)
                && !shash_add_once(&bridges, port_cfg->name, NULL)) {
                continue;
            }

            port = xmalloc(sizeof *port);
            port->port_cfg = port_cfg;
            if (port_cfg->tag
                && *port_cfg->tag >= 1 && *port_cfg->tag <= 4095) {
                port->bridge = find_vlan_bridge(info, br, *port_cfg->tag);
                if (!port->bridge) {
                    port->bridge = br;
                }
            } else {
                port->bridge = br;
            }
            shash_add(&info->ports, port_cfg->name, port);

            for (k = 0; k < port_cfg->n_interfaces; k++) {
                struct ovsrec_interface *iface_cfg = port_cfg->interfaces[k];
                struct vsctl_iface *iface;

                if (shash_find(&info->ifaces, iface_cfg->name)) {
                    VLOG_WARN("%s: database contains duplicate interface name",
                              iface_cfg->name);
                    continue;
                }

                iface = xmalloc(sizeof *iface);
                iface->iface_cfg = iface_cfg;
                iface->port = port;
                shash_add(&info->ifaces, iface_cfg->name, iface);
            }
        }
    }
    shash_destroy(&bridges);
    shash_destroy(&ports);
}

static void
check_conflicts(struct vsctl_info *info, const char *name,
                char *msg)
{
    struct vsctl_iface *iface;
    struct vsctl_port *port;

    if (shash_find(&info->bridges, name)) {
        vsctl_fatal("%s because a bridge named %s already exists",
                    msg, name);
    }

    port = shash_find_data(&info->ports, name);
    if (port) {
        vsctl_fatal("%s because a port named %s already exists on "
                    "bridge %s", msg, name, port->bridge->name);
    }

    iface = shash_find_data(&info->ifaces, name);
    if (iface) {
        vsctl_fatal("%s because an interface named %s already exists "
                    "on bridge %s", msg, name, iface->port->bridge->name);
    }

    free(msg);
}

static struct vsctl_bridge *
find_bridge(struct vsctl_info *info, const char *name, bool must_exist)
{
    struct vsctl_bridge *br = shash_find_data(&info->bridges, name);
    if (must_exist && !br) {
        vsctl_fatal("no bridge named %s", name);
    }
    return br;
}

static struct vsctl_port *
find_port(struct vsctl_info *info, const char *name, bool must_exist)
{
    struct vsctl_port *port = shash_find_data(&info->ports, name);
    if (port && !strcmp(name, port->bridge->name)) {
        port = NULL;
    }
    if (must_exist && !port) {
        vsctl_fatal("no port named %s", name);
    }
    return port;
}

static struct vsctl_iface *
find_iface(struct vsctl_info *info, const char *name, bool must_exist)
{
    struct vsctl_iface *iface = shash_find_data(&info->ifaces, name);
    if (iface && !strcmp(name, iface->port->bridge->name)) {
        iface = NULL;
    }
    if (must_exist && !iface) {
        vsctl_fatal("no interface named %s", name);
    }
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
cmd_init(struct vsctl_context *ctx UNUSED)
{
}

static void
cmd_add_br(struct vsctl_context *ctx)
{
    const char *br_name = ctx->argv[1];
    struct vsctl_info info;

    get_info(ctx->ovs, &info);
    check_conflicts(&info, br_name,
                    xasprintf("cannot create a bridge named %s", br_name));

    if (ctx->argc == 2) {
        struct ovsrec_bridge *br;
        struct ovsrec_port *port;
        struct ovsrec_interface *iface;

        iface = ovsrec_interface_insert(txn_from_openvswitch(ctx->ovs));
        ovsrec_interface_set_name(iface, br_name);

        port = ovsrec_port_insert(txn_from_openvswitch(ctx->ovs));
        ovsrec_port_set_name(port, br_name);
        ovsrec_port_set_interfaces(port, &iface, 1);

        br = ovsrec_bridge_insert(txn_from_openvswitch(ctx->ovs));
        ovsrec_bridge_set_name(br, br_name);
        ovsrec_bridge_set_ports(br, &port, 1);

        ovs_insert_bridge(ctx->ovs, br);
    } else if (ctx->argc == 3) {
        vsctl_fatal("'%s' command takes exactly 1 or 3 arguments",
                    ctx->argv[0]);
    } else if (ctx->argc == 4) {
        const char *parent_name = ctx->argv[2];
        int vlan = atoi(ctx->argv[3]);
        struct ovsrec_bridge *br;
        struct vsctl_bridge *parent;
        struct ovsrec_port *port;
        struct ovsrec_interface *iface;
        int64_t tag = vlan;

        if (vlan < 1 || vlan > 4095) {
            vsctl_fatal("%s: vlan must be between 1 and 4095", ctx->argv[0]);
        }

        parent = find_bridge(&info, parent_name, false);
        if (parent && parent->vlan) {
            vsctl_fatal("cannot create brdige with fake bridge as parent");
        }
        if (!parent) {
            vsctl_fatal("parent bridge %s does not exist", parent_name);
        }
        br = parent->br_cfg;

        iface = ovsrec_interface_insert(txn_from_openvswitch(ctx->ovs));
        ovsrec_interface_set_name(iface, br_name);
        ovsrec_interface_set_type(iface, "internal");

        port = ovsrec_port_insert(txn_from_openvswitch(ctx->ovs));
        ovsrec_port_set_name(port, br_name);
        ovsrec_port_set_interfaces(port, &iface, 1);
        ovsrec_port_set_fake_bridge(port, true);
        ovsrec_port_set_tag(port, &tag, 1);

        bridge_insert_port(br, port);
    } else {
        NOT_REACHED();
    }

    free_info(&info);
}

static void
del_port(struct vsctl_info *info, struct vsctl_port *port)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &info->ifaces) {
        struct vsctl_iface *iface = node->data;
        if (iface->port == port) {
            ovsrec_interface_delete(iface->iface_cfg);
        }
    }
    ovsrec_port_delete(port->port_cfg);

    bridge_delete_port((port->bridge->parent
                        ? port->bridge->parent->br_cfg
                        : port->bridge->br_cfg), port->port_cfg);
}

static void
cmd_del_br(struct vsctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vsctl_bridge *bridge;
    struct vsctl_info info;

    get_info(ctx->ovs, &info);
    bridge = find_bridge(&info, ctx->argv[1], must_exist);
    if (bridge) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, &info.ports) {
            struct vsctl_port *port = node->data;
            if (port->bridge == bridge
                || !strcmp(port->port_cfg->name, bridge->name)) {
                del_port(&info, port);
            }
        }
        if (bridge->br_cfg) {
            ovsrec_bridge_delete(bridge->br_cfg);
            ovs_delete_bridge(ctx->ovs, bridge->br_cfg);
        }
    }
    free_info(&info);
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
    struct vsctl_info info;
    struct svec bridges;

    get_info(ctx->ovs, &info);

    svec_init(&bridges);
    SHASH_FOR_EACH (node, &info.bridges) {
        struct vsctl_bridge *br = node->data;
        svec_add(&bridges, br->name);
    }
    output_sorted(&bridges, &ctx->output);
    svec_destroy(&bridges);

    free_info(&info);
}

static void
cmd_br_exists(struct vsctl_context *ctx)
{
    struct vsctl_info info;

    get_info(ctx->ovs, &info);
    if (!find_bridge(&info, ctx->argv[1], false)) {
        exit(2);
    }
    free_info(&info);
}

/* Returns true if 'b_prefix' (of length 'b_prefix_len') concatenated with 'b'
 * equals 'a', false otherwise. */
static bool
key_matches(const char *a,
            const char *b_prefix, size_t b_prefix_len, const char *b)
{
    return !strncmp(a, b_prefix, b_prefix_len) && !strcmp(a + b_prefix_len, b);
}

static void
set_external_id(char **old_keys, char **old_values, size_t old_n,
                char *key, char *value,
                char ***new_keysp, char ***new_valuesp, size_t *new_np)
{
    char **new_keys;
    char **new_values;
    size_t new_n;
    size_t i;

    new_keys = xmalloc(sizeof *new_keys * (old_n + 1));
    new_values = xmalloc(sizeof *new_values * (old_n + 1));
    new_n = 0;
    for (i = 0; i < old_n; i++) {
        if (strcmp(key, old_keys[i])) {
            new_keys[new_n] = old_keys[i];
            new_values[new_n] = old_values[i];
            new_n++;
        }
    }
    if (value) {
        new_keys[new_n] = key;
        new_values[new_n] = value;
        new_n++;
    }
    *new_keysp = new_keys;
    *new_valuesp = new_values;
    *new_np = new_n;
}

static void
cmd_br_set_external_id(struct vsctl_context *ctx)
{
    struct vsctl_info info;
    struct vsctl_bridge *bridge;
    char **keys, **values;
    size_t n;

    get_info(ctx->ovs, &info);
    bridge = find_bridge(&info, ctx->argv[1], true);
    if (bridge->br_cfg) {
        set_external_id(bridge->br_cfg->key_external_ids,
                        bridge->br_cfg->value_external_ids,
                        bridge->br_cfg->n_external_ids,
                        ctx->argv[2], ctx->argc >= 4 ? ctx->argv[3] : NULL,
                        &keys, &values, &n);
        ovsrec_bridge_set_external_ids(bridge->br_cfg, keys, values, n);
    } else {
        char *key = xasprintf("fake-bridge-%s", ctx->argv[2]);
        struct vsctl_port *port = shash_find_data(&info.ports, ctx->argv[1]);
        set_external_id(port->port_cfg->key_external_ids,
                        port->port_cfg->value_external_ids,
                        port->port_cfg->n_external_ids,
                        key, ctx->argc >= 4 ? ctx->argv[3] : NULL,
                        &keys, &values, &n);
        ovsrec_port_set_external_ids(port->port_cfg, keys, values, n);
        free(key);
    }
    free(keys);
    free(values);

    free_info(&info);
}

static void
get_external_id(char **keys, char **values, size_t n,
                const char *prefix, const char *key,
                struct ds *output)
{
    size_t prefix_len = strlen(prefix);
    struct svec svec;
    size_t i;

    svec_init(&svec);
    for (i = 0; i < n; i++) {
        if (!key && !strncmp(keys[i], prefix, prefix_len)) {
            svec_add_nocopy(&svec, xasprintf("%s=%s",
                                             keys[i] + prefix_len, values[i]));
        } else if (key_matches(keys[i], prefix, prefix_len, key)) {
            svec_add(&svec, values[i]);
            break;
        }
    }
    output_sorted(&svec, output);
    svec_destroy(&svec);
}

static void
cmd_br_get_external_id(struct vsctl_context *ctx)
{
    struct vsctl_info info;
    struct vsctl_bridge *bridge;

    get_info(ctx->ovs, &info);
    bridge = find_bridge(&info, ctx->argv[1], true);
    if (bridge->br_cfg) {
        get_external_id(bridge->br_cfg->key_external_ids,
                        bridge->br_cfg->value_external_ids,
                        bridge->br_cfg->n_external_ids,
                        "", ctx->argc >= 3 ? ctx->argv[2] : NULL,
                        &ctx->output);
    } else {
        struct vsctl_port *port = shash_find_data(&info.ports, ctx->argv[1]);
        get_external_id(port->port_cfg->key_external_ids,
                        port->port_cfg->value_external_ids,
                        port->port_cfg->n_external_ids,
                        "fake-bridge-", ctx->argc >= 3 ? ctx->argv[2] : NULL, &ctx->output);
    }
    free_info(&info);
}


static void
cmd_list_ports(struct vsctl_context *ctx)
{
    struct vsctl_bridge *br;
    struct shash_node *node;
    struct vsctl_info info;
    struct svec ports;

    get_info(ctx->ovs, &info);
    br = find_bridge(&info, ctx->argv[1], true);

    svec_init(&ports);
    SHASH_FOR_EACH (node, &info.ports) {
        struct vsctl_port *port = node->data;

        if (strcmp(port->port_cfg->name, br->name) && br == port->bridge) {
            svec_add(&ports, port->port_cfg->name);
        }
    }
    output_sorted(&ports, &ctx->output);
    svec_destroy(&ports);

    free_info(&info);
}

static void
add_port(const struct ovsrec_open_vswitch *ovs,
         const char *br_name, const char *port_name,
         char *iface_names[], int n_ifaces)
{
    struct vsctl_info info;
    struct vsctl_bridge *bridge;
    struct ovsrec_interface **ifaces;
    struct ovsrec_port *port;
    size_t i;

    get_info(ovs, &info);
    check_conflicts(&info, port_name,
                    xasprintf("cannot create a port named %s", port_name));
    /* XXX need to check for conflicts on interfaces too */
    bridge = find_bridge(&info, br_name, true);

    ifaces = xmalloc(n_ifaces * sizeof *ifaces);
    for (i = 0; i < n_ifaces; i++) {
        ifaces[i] = ovsrec_interface_insert(txn_from_openvswitch(ovs));
        ovsrec_interface_set_name(ifaces[i], iface_names[i]);
    }

    port = ovsrec_port_insert(txn_from_openvswitch(ovs));
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, ifaces, n_ifaces);
    free(ifaces);

    if (bridge->vlan) {
        int64_t tag = bridge->vlan;
        ovsrec_port_set_tag(port, &tag, 1);
    }

    bridge_insert_port((bridge->parent ? bridge->parent->br_cfg
                        : bridge->br_cfg), port);

    free_info(&info);
}

static void
cmd_add_port(struct vsctl_context *ctx)
{
    add_port(ctx->ovs, ctx->argv[1], ctx->argv[2], &ctx->argv[2], 1);
}

static void
cmd_add_bond(struct vsctl_context *ctx)
{
    add_port(ctx->ovs, ctx->argv[1], ctx->argv[2], &ctx->argv[3], ctx->argc - 3);
}

static void
cmd_del_port(struct vsctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct vsctl_info info;

    get_info(ctx->ovs, &info);
    if (ctx->argc == 2) {
        struct vsctl_port *port = find_port(&info, ctx->argv[1], must_exist);
        if (port) {
            del_port(&info, port);
        }
    } else if (ctx->argc == 3) {
        struct vsctl_bridge *bridge = find_bridge(&info, ctx->argv[1], true);
        struct vsctl_port *port = find_port(&info, ctx->argv[2], must_exist);

        if (port) {
            if (port->bridge == bridge) {
                del_port(&info, port);
            } else if (port->bridge->parent == bridge) {
                vsctl_fatal("bridge %s does not have a port %s (although its "
                            "parent bridge %s does)",
                            ctx->argv[1], ctx->argv[2], bridge->parent->name);
            } else {
                vsctl_fatal("bridge %s does not have a port %s",
                            ctx->argv[1], ctx->argv[2]);
            }
        }
    }
    free_info(&info);
}

static void
cmd_port_to_br(struct vsctl_context *ctx)
{
    struct vsctl_port *port;
    struct vsctl_info info;

    get_info(ctx->ovs, &info);
    port = find_port(&info, ctx->argv[1], true);
    ds_put_format(&ctx->output, "%s\n", port->bridge->name);
    free_info(&info);
}

static void
cmd_port_set_external_id(struct vsctl_context *ctx)
{
    struct vsctl_info info;
    struct vsctl_port *port;
    char **keys, **values;
    size_t n;

    get_info(ctx->ovs, &info);
    port = find_port(&info, ctx->argv[1], true);
    set_external_id(port->port_cfg->key_external_ids,
                    port->port_cfg->value_external_ids,
                    port->port_cfg->n_external_ids,
                    ctx->argv[2], ctx->argc >= 4 ? ctx->argv[3] : NULL,
                    &keys, &values, &n);
    ovsrec_port_set_external_ids(port->port_cfg, keys, values, n);
    free(keys);
    free(values);

    free_info(&info);
}

static void
cmd_port_get_external_id(struct vsctl_context *ctx)
{
    struct vsctl_info info;
    struct vsctl_port *port;

    get_info(ctx->ovs, &info);
    port = find_port(&info, ctx->argv[1], true);
    get_external_id(port->port_cfg->key_external_ids,
                    port->port_cfg->value_external_ids,
                    port->port_cfg->n_external_ids,
                    "",  ctx->argc >= 3 ? ctx->argv[2] : NULL, &ctx->output);
    free_info(&info);
}

static void
cmd_br_to_vlan(struct vsctl_context *ctx)
{
    struct vsctl_bridge *bridge;
    struct vsctl_info info;

    get_info(ctx->ovs, &info);
    bridge = find_bridge(&info, ctx->argv[1], true);
    ds_put_format(&ctx->output, "%d\n", bridge->vlan);
    free_info(&info);
}

static void
cmd_br_to_parent(struct vsctl_context *ctx)
{
    struct vsctl_bridge *bridge;
    struct vsctl_info info;

    get_info(ctx->ovs, &info);
    bridge = find_bridge(&info, ctx->argv[1], true);
    if (bridge->parent) {
        bridge = bridge->parent;
    }
    ds_put_format(&ctx->output, "%s\n", bridge->name);
    free_info(&info);
}

static void
cmd_list_ifaces(struct vsctl_context *ctx)
{
    struct vsctl_bridge *br;
    struct shash_node *node;
    struct vsctl_info info;
    struct svec ifaces;

    get_info(ctx->ovs, &info);
    br = find_bridge(&info, ctx->argv[1], true);

    svec_init(&ifaces);
    SHASH_FOR_EACH (node, &info.ifaces) {
        struct vsctl_iface *iface = node->data;

        if (strcmp(iface->iface_cfg->name, br->name)
            && br == iface->port->bridge) {
            svec_add(&ifaces, iface->iface_cfg->name);
        }
    }
    output_sorted(&ifaces, &ctx->output);
    svec_destroy(&ifaces);

    free_info(&info);
}

static void
cmd_iface_to_br(struct vsctl_context *ctx)
{
    struct vsctl_iface *iface;
    struct vsctl_info info;

    get_info(ctx->ovs, &info);
    iface = find_iface(&info, ctx->argv[1], true);
    ds_put_format(&ctx->output, "%s\n", iface->port->bridge->name);
    free_info(&info);
}

static void
cmd_iface_set_external_id(struct vsctl_context *ctx)
{
    struct vsctl_info info;
    struct vsctl_iface *iface;
    char **keys, **values;
    size_t n;

    get_info(ctx->ovs, &info);
    iface = find_iface(&info, ctx->argv[1], true);
    set_external_id(iface->iface_cfg->key_external_ids,
                    iface->iface_cfg->value_external_ids,
                    iface->iface_cfg->n_external_ids,
                    ctx->argv[2], ctx->argc >= 4 ? ctx->argv[3] : NULL,
                    &keys, &values, &n);
    ovsrec_interface_set_external_ids(iface->iface_cfg, keys, values, n);
    free(keys);
    free(values);

    free_info(&info);
}

static void
cmd_iface_get_external_id(struct vsctl_context *ctx)
{
    struct vsctl_info info;
    struct vsctl_iface *iface;

    get_info(ctx->ovs, &info);
    iface = find_iface(&info, ctx->argv[1], true);
    get_external_id(iface->iface_cfg->key_external_ids,
                    iface->iface_cfg->value_external_ids,
                    iface->iface_cfg->n_external_ids,
                    "",  ctx->argc >= 3 ? ctx->argv[2] : NULL, &ctx->output);
    free_info(&info);
}

typedef void vsctl_handler_func(struct vsctl_context *);

struct vsctl_command {
    const char *name;
    int min_args;
    int max_args;
    vsctl_handler_func *handler;
    const char *options;
};

static void run_vsctl_command(int argc, char *argv[],
                              const struct ovsrec_open_vswitch *ovs,
                              struct ds *output);

static struct json *
where_uuid_equals(const struct uuid *uuid)
{
    return
        json_array_create_1(
            json_array_create_3(
                json_string_create("_uuid"),
                json_string_create("=="),
                json_array_create_2(
                    json_string_create("uuid"),
                    json_string_create_nocopy(
                        xasprintf(UUID_FMT, UUID_ARGS(uuid))))));
}

static void
do_vsctl(int argc, char *argv[], struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;
    const struct ovsrec_open_vswitch *ovs;
    enum ovsdb_idl_txn_status status;
    struct ds comment, *output;
    int64_t next_cfg;
    int n_output;
    int i, start;

    txn = ovsdb_idl_txn_create(idl);
    if (dry_run) {
        ovsdb_idl_txn_set_dry_run(txn);
    }

    ds_init(&comment);
    ds_put_cstr(&comment, "ovs-vsctl:");
    for (i = 0; i < argc; i++) {
        ds_put_format(&comment, " %s", argv[i]);
    }
    ovsdb_idl_txn_add_comment(txn, ds_cstr(&comment));
    ds_destroy(&comment);

    ovs = ovsrec_open_vswitch_first(idl);
    if (!ovs) {
        /* XXX add verification that table is empty */
        ovs = ovsrec_open_vswitch_insert(txn);
    }

    if (wait_for_reload) {
        struct json *where = where_uuid_equals(&ovs->header_.uuid);
        ovsdb_idl_txn_increment(txn, "Open_vSwitch", "next_cfg",
                                where);
        json_destroy(where);
    }

    output = xmalloc(argc * sizeof *output);
    n_output = 0;
    for (start = i = 0; i <= argc; i++) {
        if (i == argc || !strcmp(argv[i], "--")) {
            if (i > start) {
                ds_init(&output[n_output]);
                run_vsctl_command(i - start, &argv[start], ovs,
                                  &output[n_output++]);
            }
            start = i + 1;
        }
    }

    while ((status = ovsdb_idl_txn_commit(txn)) == TXN_INCOMPLETE) {
        ovsdb_idl_run(idl);
        ovsdb_idl_wait(idl);
        ovsdb_idl_txn_wait(txn);
        poll_block();
    }
    if (wait_for_reload && status == TXN_SUCCESS) {
        next_cfg = ovsdb_idl_txn_get_increment_new_value(txn);
    }
    ovsdb_idl_txn_destroy(txn);

    switch (status) {
    case TXN_INCOMPLETE:
        NOT_REACHED();

    case TXN_ABORTED:
        /* Should not happen--we never call ovsdb_idl_txn_abort(). */
        vsctl_fatal("transaction aborted");

    case TXN_UNCHANGED:
    case TXN_SUCCESS:
        break;

    case TXN_TRY_AGAIN:
        for (i = 0; i < n_output; i++) {
            ds_destroy(&output[i]);
        }
        return;

    case TXN_ERROR:
        vsctl_fatal("transaction error");

    default:
        NOT_REACHED();
    }

    for (i = 0; i < n_output; i++) {
        struct ds *ds = &output[i];
        if (oneline) {
            size_t j;

            ds_chomp(ds, '\n');
            for (j = 0; j < ds->length; j++) {
                int c = ds->string[j];
                switch (c) {
                case '\n':
                    fputs("\\n", stdout);
                    break;

                case '\\':
                    fputs("\\\\", stdout);
                    break;

                default:
                    putchar(c);
                }
            }
            putchar('\n');
        } else {
            fputs(ds_cstr(ds), stdout);
        }
    }

    if (wait_for_reload && status != TXN_UNCHANGED) {
        for (;;) {
            const struct ovsrec_open_vswitch *ovs;

            ovsdb_idl_run(idl);
            OVSREC_OPEN_VSWITCH_FOR_EACH (ovs, idl) {
                if (ovs->cur_cfg >= next_cfg) {
                    goto done;
                }
            }
            ovsdb_idl_wait(idl);
            poll_block();
        }
    done: ;
    }

    exit(EXIT_SUCCESS);
}

static vsctl_handler_func *
get_vsctl_handler(int argc, char *argv[], struct vsctl_context *ctx)
{
    static const struct vsctl_command all_commands[] = {
        /* Open vSwitch commands. */
        {"init", 0, 0, cmd_init, ""},

        /* Bridge commands. */
        {"add-br", 1, 3, cmd_add_br, ""},
        {"del-br", 1, 1, cmd_del_br, "--if-exists"},
        {"list-br", 0, 0, cmd_list_br, ""},
        {"br-exists", 1, 1, cmd_br_exists, ""},
        {"br-to-vlan", 1, 1, cmd_br_to_vlan, ""},
        {"br-to-parent", 1, 1, cmd_br_to_parent, ""},
        {"br-set-external-id", 2, 3, cmd_br_set_external_id, ""},
        {"br-get-external-id", 1, 2, cmd_br_get_external_id, ""},

        /* Port commands. */
        {"list-ports", 1, 1, cmd_list_ports, ""},
        {"add-port", 2, 2, cmd_add_port, ""},
        {"add-bond", 4, INT_MAX, cmd_add_bond, ""},
        {"del-port", 1, 2, cmd_del_port, "--if-exists"},
        {"port-to-br", 1, 1, cmd_port_to_br, ""},
        {"port-set-external-id", 2, 3, cmd_port_set_external_id, ""},
        {"port-get-external-id", 1, 2, cmd_port_get_external_id, ""},

        /* Interface commands. */
        {"list-ifaces", 1, 1, cmd_list_ifaces, ""},
        {"iface-to-br", 1, 1, cmd_iface_to_br, ""},
        {"iface-set-external-id", 2, 3, cmd_iface_set_external_id, ""},
        {"iface-get-external-id", 1, 2, cmd_iface_get_external_id, ""},
    };

    const struct vsctl_command *p;
    int i;

    shash_init(&ctx->options);
    for (i = 0; i < argc; i++) {
        if (argv[i][0] != '-') {
            break;
        }
        if (!shash_add_once(&ctx->options, argv[i], NULL)) {
            vsctl_fatal("'%s' option specified multiple times", argv[i]);
        }
    }
    if (i == argc) {
        vsctl_fatal("missing command name");
    }

    for (p = all_commands; p < &all_commands[ARRAY_SIZE(all_commands)]; p++) {
        if (!strcmp(p->name, argv[i])) {
            struct shash_node *node;
            int n_arg;

            SHASH_FOR_EACH (node, &ctx->options) {
                const char *s = strstr(p->options, node->name);
                int end = s ? s[strlen(node->name)] : EOF;
                if (end != ',' && end != ' ' && end != '\0') {
                    vsctl_fatal("'%s' command has no '%s' option",
                                argv[i], node->name);
                }
            }

            n_arg = argc - i - 1;
            if (n_arg < p->min_args) {
                vsctl_fatal("'%s' command requires at least %d arguments",
                            p->name, p->min_args);
            } else if (n_arg > p->max_args) {
                vsctl_fatal("'%s' command takes at most %d arguments",
                            p->name, p->max_args);
            } else {
                ctx->argc = n_arg + 1;
                ctx->argv = &argv[i];
                return p->handler;
            }
        }
    }

    vsctl_fatal("unknown command '%s'; use --help for help", argv[i]);
}

static void
check_vsctl_command(int argc, char *argv[])
{
    struct vsctl_context ctx;

    get_vsctl_handler(argc, argv, &ctx);
    shash_destroy(&ctx.options);
}

static void
run_vsctl_command(int argc, char *argv[],
                  const struct ovsrec_open_vswitch *ovs, struct ds *output)
{
    vsctl_handler_func *function;
    struct vsctl_context ctx;

    function = get_vsctl_handler(argc, argv, &ctx);
    ctx.ovs = ovs;
    ds_init(&ctx.output);
    function(&ctx);
    *output = ctx.output;
    shash_destroy(&ctx.options);
}
