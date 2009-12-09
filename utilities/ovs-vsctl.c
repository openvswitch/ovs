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
        ovs_fatal(0, "missing command name (use --help for help)");
    }

    /* Now execut the commands. */
    idl = ovsdb_idl_create(db, &ovsrec_idl_class);
    seqno = ovsdb_idl_get_seqno(idl);
    trials = 0;
    for (;;) {
        unsigned int new_seqno;

        ovsdb_idl_run(idl);
        new_seqno = ovsdb_idl_get_seqno(idl);
        if (new_seqno != seqno) {
            if (++trials > 5) {
                ovs_fatal(0, "too many database inconsistency failures");
            }
            do_vsctl(argc - optind, argv + optind, idl);
            seqno = new_seqno;
        }

        ovsdb_idl_wait(idl);
        poll_block();
    }
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_DB = UCHAR_MAX + 1,
        OPT_ONELINE,
        OPT_NO_SYSLOG
    };
    static struct option long_options[] = {
        {"db", required_argument, 0, OPT_DB},
        {"no-syslog", no_argument, 0, OPT_NO_SYSLOG},
        {"oneline", no_argument, 0, OPT_ONELINE},
        {"verbose", optional_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
    };

    for (;;) {
        int c;

        c = getopt_long(argc, argv, "+v::hV", long_options, NULL);
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

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(0, 0);
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
           "print the parent of BRIDGE\n");
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
           "A bond is considered to be a single port.\n");
    printf("\nInterface commands (a bond consists of multiple interfaces):\n"
           "  list-ifaces BRIDGE          "
           "print the names of all the interfaces on BRIDGE\n"
           "  iface-to-br IFACE           "
           "print name of bridge that contains IFACE\n");
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
        ovs_fatal(0, "%s because a bridge named %s already exists", msg, name);
    }

    port = shash_find_data(&info->ports, name);
    if (port) {
        ovs_fatal(0, "%s because a port named %s already exists on bridge %s",
                  msg, name, port->bridge->name);
    }

    iface = shash_find_data(&info->ifaces, name);
    if (iface) {
        ovs_fatal(0, "%s because an interface named %s already exists "
                  "on bridge %s", msg, name, iface->port->bridge->name);
    }

    free(msg);
}

static struct vsctl_bridge *
find_bridge(struct vsctl_info *info, const char *name)
{
    struct vsctl_bridge *br = shash_find_data(&info->bridges, name);
    if (!br) {
        ovs_fatal(0, "no bridge named %s", name);
    }
    return br;
}

static struct vsctl_port *
find_port(struct vsctl_info *info, const char *name)
{
    struct vsctl_port *port = shash_find_data(&info->ports, name);
    if (!port || !strcmp(name, port->bridge->name)) {
        ovs_fatal(0, "no port named %s", name);
    }
    return port;
}

static struct vsctl_iface *
find_iface(struct vsctl_info *info, const char *name)
{
    struct vsctl_iface *iface = shash_find_data(&info->ifaces, name);
    if (!iface || !strcmp(name, iface->port->bridge->name)) {
        ovs_fatal(0, "no interface named %s", name);
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
cmd_add_br(int argc, char *argv[], const struct ovsrec_open_vswitch *ovs,
           struct ds *output UNUSED)
{
    const char *br_name = argv[1];
    struct vsctl_info info;

    get_info(ovs, &info);
    check_conflicts(&info, br_name,
                    xasprintf("cannot create a bridge named %s", br_name));

    if (argc == 2) {
        struct ovsrec_bridge *br;
        struct ovsrec_port *port;
        struct ovsrec_interface *iface;

        iface = ovsrec_interface_insert(txn_from_openvswitch(ovs));
        ovsrec_interface_set_name(iface, br_name);

        port = ovsrec_port_insert(txn_from_openvswitch(ovs));
        ovsrec_port_set_name(port, br_name);
        ovsrec_port_set_interfaces(port, &iface, 1);

        br = ovsrec_bridge_insert(txn_from_openvswitch(ovs));
        ovsrec_bridge_set_name(br, br_name);
        ovsrec_bridge_set_ports(br, &port, 1);

        ovs_insert_bridge(ovs, br);
    } else if (argc == 3) {
        ovs_fatal(0, "'%s' comamnd takes exactly 1 or 3 arguments", argv[0]);
    } else if (argc == 4) {
        const char *parent_name = argv[2];
        int vlan = atoi(argv[3]);
        struct ovsrec_bridge *br;
        struct vsctl_bridge *parent;
        struct ovsrec_port *port;
        struct ovsrec_interface *iface;
        int64_t tag = vlan;

        if (vlan < 1 || vlan > 4095) {
            ovs_fatal(0, "%s: vlan must be between 1 and 4095", argv[0]);
        }

        parent = shash_find_data(&info.bridges, parent_name);
        if (parent && parent->vlan) {
            ovs_fatal(0, "cannot create brdige with fake bridge as parent");
        }
        if (!parent) {
            ovs_fatal(0, "parent bridge %s does not exist", parent_name);
        }
        br = parent->br_cfg;

        iface = ovsrec_interface_insert(txn_from_openvswitch(ovs));
        ovsrec_interface_set_name(iface, br_name);
        ovsrec_interface_set_type(iface, "internal");

        port = ovsrec_port_insert(txn_from_openvswitch(ovs));
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
cmd_del_br(int argc UNUSED, char *argv[],
           const struct ovsrec_open_vswitch *ovs, struct ds *output UNUSED)
{
    struct shash_node *node;
    struct vsctl_info info;
    struct vsctl_bridge *bridge;

    get_info(ovs, &info);
    bridge = find_bridge(&info, argv[1]);
    SHASH_FOR_EACH (node, &info.ports) {
        struct vsctl_port *port = node->data;
        if (port->bridge == bridge
            || !strcmp(port->port_cfg->name, bridge->name)) {
            del_port(&info, port);
        }
    }
    if (bridge->br_cfg) {
        ovsrec_bridge_delete(bridge->br_cfg);
        ovs_delete_bridge(ovs, bridge->br_cfg);
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
cmd_list_br(int argc UNUSED, char *argv[] UNUSED,
            const struct ovsrec_open_vswitch *ovs, struct ds *output)
{
    struct shash_node *node;
    struct vsctl_info info;
    struct svec bridges;

    get_info(ovs, &info);

    svec_init(&bridges);
    SHASH_FOR_EACH (node, &info.bridges) {
        struct vsctl_bridge *br = node->data;
        svec_add(&bridges, br->name);
    }
    output_sorted(&bridges, output);
    svec_destroy(&bridges);

    free_info(&info);
}

static void
cmd_br_exists(int argc UNUSED, char *argv[],
              const struct ovsrec_open_vswitch *ovs, struct ds *output UNUSED)
{
    struct vsctl_info info;

    get_info(ovs, &info);
    if (!shash_find_data(&info.bridges, argv[1])) {
        exit(2);
    }
    free_info(&info);
}

static void
cmd_list_ports(int argc UNUSED, char *argv[],
               const struct ovsrec_open_vswitch *ovs, struct ds *output)
{
    struct vsctl_bridge *br;
    struct shash_node *node;
    struct vsctl_info info;
    struct svec ports;

    get_info(ovs, &info);
    br = find_bridge(&info, argv[1]);

    svec_init(&ports);
    SHASH_FOR_EACH (node, &info.ports) {
        struct vsctl_port *port = node->data;

        if (strcmp(port->port_cfg->name, br->name) && br == port->bridge) {
            svec_add(&ports, port->port_cfg->name);
        }
    }
    output_sorted(&ports, output);
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
    bridge = find_bridge(&info, br_name);

    ifaces = xmalloc(n_ifaces * sizeof *ifaces);
    for (i = 0; i < n_ifaces; i++) {
        ifaces[i] = ovsrec_interface_insert(txn_from_openvswitch(ovs));
        ovsrec_interface_set_name(ifaces[i], iface_names[i]);
    }

    port = ovsrec_port_insert(txn_from_openvswitch(ovs));
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, ifaces, n_ifaces);
    if (bridge->vlan) {
        int64_t tag = bridge->vlan;
        ovsrec_port_set_tag(port, &tag, 1);
    }

    bridge_insert_port((bridge->parent ? bridge->parent->br_cfg
                        : bridge->br_cfg), port);

    free_info(&info);
}

static void
cmd_add_port(int argc UNUSED, char *argv[],
             const struct ovsrec_open_vswitch *ovs, struct ds *output UNUSED)
{
    add_port(ovs, argv[1], argv[2], &argv[2], 1);
}

static void
cmd_add_bond(int argc, char *argv[],
             const struct ovsrec_open_vswitch *ovs, struct ds *output UNUSED)
{
    add_port(ovs, argv[1], argv[2], &argv[3], argc - 3);
}

static void
cmd_del_port(int argc, char *argv[],
             const struct ovsrec_open_vswitch *ovs, struct ds *output UNUSED)
{
    struct vsctl_info info;

    get_info(ovs, &info);
    if (argc == 2) {
        struct vsctl_port *port = find_port(&info, argv[1]);
        del_port(&info, port);
    } else if (argc == 3) {
        struct vsctl_bridge *bridge = find_bridge(&info, argv[1]);
        struct vsctl_port *port = find_port(&info, argv[2]);

        if (port->bridge == bridge) {
            del_port(&info, port);
        } else if (port->bridge->parent == bridge) {
            ovs_fatal(0, "bridge %s does not have a port %s (although its "
                      "parent bridge %s does)",
                      argv[1], argv[2], bridge->parent->name);
        } else {
            ovs_fatal(0, "bridge %s does not have a port %s",
                      argv[1], argv[2]);
        }
    }
    free_info(&info);
}

static void
cmd_port_to_br(int argc UNUSED, char *argv[],
               const struct ovsrec_open_vswitch *ovs, struct ds *output)
{
    struct vsctl_port *port;
    struct vsctl_info info;

    get_info(ovs, &info);
    port = find_port(&info, argv[1]);
    ds_put_format(output, "%s\n", port->bridge->name);
    free_info(&info);
}

static void
cmd_br_to_vlan(int argc UNUSED, char *argv[],
               const struct ovsrec_open_vswitch *ovs, struct ds *output)
{
    struct vsctl_bridge *bridge;
    struct vsctl_info info;

    get_info(ovs, &info);
    bridge = find_bridge(&info, argv[1]);
    ds_put_format(output, "%d\n", bridge->vlan);
    free_info(&info);
}

static void
cmd_br_to_parent(int argc UNUSED, char *argv[],
                 const struct ovsrec_open_vswitch *ovs, struct ds *output)
{
    struct vsctl_bridge *bridge;
    struct vsctl_info info;

    get_info(ovs, &info);
    bridge = find_bridge(&info, argv[1]);
    if (bridge->parent) {
        bridge = bridge->parent;
    }
    ds_put_format(output, "%s\n", bridge->name);
    free_info(&info);
}

static void
cmd_list_ifaces(int argc UNUSED, char *argv[],
                const struct ovsrec_open_vswitch *ovs, struct ds *output)
{
    struct vsctl_bridge *br;
    struct shash_node *node;
    struct vsctl_info info;
    struct svec ifaces;

    get_info(ovs, &info);
    br = find_bridge(&info, argv[1]);

    svec_init(&ifaces);
    SHASH_FOR_EACH (node, &info.ifaces) {
        struct vsctl_iface *iface = node->data;

        if (strcmp(iface->iface_cfg->name, br->name)
            && br == iface->port->bridge) {
            svec_add(&ifaces, iface->iface_cfg->name);
        }
    }
    output_sorted(&ifaces, output);
    svec_destroy(&ifaces);

    free_info(&info);
}

static void
cmd_iface_to_br(int argc UNUSED, char *argv[],
                const struct ovsrec_open_vswitch *ovs, struct ds *output)
{
    struct vsctl_iface *iface;
    struct vsctl_info info;

    get_info(ovs, &info);
    iface = find_iface(&info, argv[1]);
    ds_put_format(output, "%s\n", iface->port->bridge->name);
    free_info(&info);
}

typedef void vsctl_handler_func(int argc, char *argv[],
                                const struct ovsrec_open_vswitch *,
                                struct ds *output);

struct vsctl_command {
    const char *name;
    int min_args;
    int max_args;
    vsctl_handler_func *handler;
};

static void run_vsctl_command(int argc, char *argv[],
                              const struct ovsrec_open_vswitch *ovs,
                              struct ds *output);

static void
do_vsctl(int argc, char *argv[], struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;
    const struct ovsrec_open_vswitch *ovs;
    enum ovsdb_idl_txn_status status;
    struct ds *output;
    int n_output;
    int i, start;

    ovs = ovsrec_open_vswitch_first(idl);
    if (!ovs) {
        /* XXX it would be more user-friendly to create a record ourselves
         * (while verifying that the table is empty before doing so). */
        ovs_fatal(0, "%s: database does not contain any Open vSwitch "
                  "configuration", db);
    }

    txn = ovsdb_idl_txn_create(idl);
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
    ovsdb_idl_txn_destroy(txn);

    switch (status) {
    case TXN_INCOMPLETE:
        NOT_REACHED();

    case TXN_ABORTED:
        /* Should not happen--we never call ovsdb_idl_txn_abort(). */
        ovs_fatal(0, "transaction aborted");

    case TXN_SUCCESS:
        break;

    case TXN_TRY_AGAIN:
        for (i = 0; i < n_output; i++) {
            ds_destroy(&output[i]);
        }
        return;

    case TXN_ERROR:
        ovs_fatal(0, "transaction error");

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
    exit(EXIT_SUCCESS);
}

static vsctl_handler_func *
get_vsctl_handler(int argc, char *argv[])
{
    static const struct vsctl_command all_commands[] = {
        {"add-br", 1, 3, cmd_add_br},
        {"del-br", 1, 1, cmd_del_br},
        {"list-br", 0, 0, cmd_list_br},
        {"br-exists", 1, 1, cmd_br_exists},
        {"list-ports", 1, 1, cmd_list_ports},
        {"add-port", 2, 2, cmd_add_port},
        {"add-bond", 4, INT_MAX, cmd_add_bond},
        {"del-port", 1, 2, cmd_del_port},
        {"port-to-br", 1, 1, cmd_port_to_br},
        {"br-to-vlan", 1, 1, cmd_br_to_vlan},
        {"br-to-parent", 1, 1, cmd_br_to_parent},
        {"list-ifaces", 1, 1, cmd_list_ifaces},
        {"iface-to-br", 1, 1, cmd_iface_to_br},
    };

    const struct vsctl_command *p;

    assert(argc > 0);
    for (p = all_commands; p < &all_commands[ARRAY_SIZE(all_commands)]; p++) {
        if (!strcmp(p->name, argv[0])) {
            int n_arg = argc - 1;
            if (n_arg < p->min_args) {
                ovs_fatal(0, "'%s' command requires at least %d arguments",
                          p->name, p->min_args);
            } else if (n_arg > p->max_args) {
                ovs_fatal(0, "'%s' command takes at most %d arguments",
                          p->name, p->max_args);
            } else {
                return p->handler;
            }
        }
    }

    ovs_fatal(0, "unknown command '%s'; use --help for help", argv[0]);
}

static void
check_vsctl_command(int argc, char *argv[])
{
    get_vsctl_handler(argc, argv);
}

static void
run_vsctl_command(int argc, char *argv[],
                  const struct ovsrec_open_vswitch *ovs, struct ds *output)
{
    get_vsctl_handler(argc, argv)(argc, argv, ovs, output);
}
