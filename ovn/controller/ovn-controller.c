/* Copyright (c) 2015 Nicira, Inc.
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

#include "ovn-controller.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "poll-loop.h"
#include "fatal-signal.h"
#include "lib/vswitch-idl.h"
#include "smap.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"

#include "ofctrl.h"
#include "binding.h"
#include "chassis.h"
#include "encaps.h"
#include "physical.h"
#include "lflow.h"

VLOG_DEFINE_THIS_MODULE(main);

static unixctl_cb_func ovn_controller_exit;

#define DEFAULT_BRIDGE_NAME "br-int"

static void parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

static char *ovs_remote;

static const struct ovsrec_bridge *
get_bridge(struct ovsdb_idl *ovs_idl, const char *br_name)
{
    const struct ovsrec_bridge *br;
    OVSREC_BRIDGE_FOR_EACH (br, ovs_idl) {
        if (!strcmp(br->name, br_name)) {
            return br;
        }
    }
    return NULL;
}

static const struct ovsrec_bridge *
create_br_int(struct controller_ctx *ctx,
              const struct ovsrec_open_vswitch *cfg,
              const char *bridge_name)
{
    if (!ctx->ovs_idl_txn) {
        return NULL;
    }

    ovsdb_idl_txn_add_comment(ctx->ovs_idl_txn,
            "ovn-controller: creating integration bridge '%s'", bridge_name);

    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ctx->ovs_idl_txn);
    ovsrec_interface_set_name(iface, bridge_name);
    ovsrec_interface_set_type(iface, "internal");

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ctx->ovs_idl_txn);
    ovsrec_port_set_name(port, bridge_name);
    ovsrec_port_set_interfaces(port, &iface, 1);

    struct ovsrec_bridge *bridge;
    bridge = ovsrec_bridge_insert(ctx->ovs_idl_txn);
    ovsrec_bridge_set_name(bridge, bridge_name);
    ovsrec_bridge_set_fail_mode(bridge, "secure");
    const struct smap oc = SMAP_CONST1(&oc, "disable-in-band", "true");
    ovsrec_bridge_set_other_config(bridge, &oc);
    ovsrec_bridge_set_ports(bridge, &port, 1);

    struct ovsrec_bridge **bridges;
    size_t bytes = sizeof *bridges * cfg->n_bridges;
    bridges = xmalloc(bytes + sizeof *bridges);
    memcpy(bridges, cfg->bridges, bytes);
    bridges[cfg->n_bridges] = bridge;
    ovsrec_open_vswitch_verify_bridges(cfg);
    ovsrec_open_vswitch_set_bridges(cfg, bridges, cfg->n_bridges + 1);

    return bridge;
}

static const struct ovsrec_bridge *
get_br_int(struct controller_ctx *ctx)
{
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (!cfg) {
        return NULL;
    }

    const char *br_int_name = smap_get(&cfg->external_ids, "ovn-bridge");
    if (!br_int_name) {
        br_int_name = DEFAULT_BRIDGE_NAME;
    }

    const struct ovsrec_bridge *br;
    br = get_bridge(ctx->ovs_idl, br_int_name);
    if (!br) {
        return create_br_int(ctx, cfg, br_int_name);
    }
    return br;
}

static const char *
get_chassis_id(const struct ovsdb_idl *ovs_idl)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(ovs_idl);
    return cfg ? smap_get(&cfg->external_ids, "system-id") : NULL;
}

static char *
patch_port_name(const struct ovsrec_bridge *b1, const struct ovsrec_bridge *b2)
{
    return xasprintf("patch-%s-to-%s", b1->name, b2->name);
}

/*
 * Return true if the port is a patch port from b1 to b2
 */
static bool
match_patch_port(const struct ovsrec_port *port,
                 const struct ovsrec_bridge *b1,
                 const struct ovsrec_bridge *b2)
{
    struct ovsrec_interface *iface;
    size_t i;
    char *peer_port_name;
    bool res = false;

    peer_port_name = patch_port_name(b2, b1);

    for (i = 0; i < port->n_interfaces; i++) {
        iface = port->interfaces[i];
        if (strcmp(iface->type, "patch")) {
            continue;
        }
        const char *peer;
        peer = smap_get(&iface->options, "peer");
        if (peer && !strcmp(peer, peer_port_name)) {
            res = true;
            break;
        }
    }

    free(peer_port_name);

    return res;
}

static void
create_patch_port(struct controller_ctx *ctx,
                  const char *network,
                  const struct ovsrec_bridge *b1,
                  const struct ovsrec_bridge *b2)
{
    if (!ctx->ovs_idl_txn) {
        return;
    }

    char *port_name = patch_port_name(b1, b2);
    char *peer_port_name = patch_port_name(b2, b1);

    ovsdb_idl_txn_add_comment(ctx->ovs_idl_txn,
            "ovn-controller: creating patch port '%s' from '%s' to '%s'",
            port_name, b1->name, b2->name);

    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ctx->ovs_idl_txn);
    ovsrec_interface_set_name(iface, port_name);
    ovsrec_interface_set_type(iface, "patch");
    const struct smap options = SMAP_CONST1(&options, "peer", peer_port_name);
    ovsrec_interface_set_options(iface, &options);

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ctx->ovs_idl_txn);
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, &iface, 1);
    const struct smap ids = SMAP_CONST1(&ids, "ovn-patch-port", network);
    ovsrec_port_set_external_ids(port, &ids);

    struct ovsrec_port **ports;
    ports = xmalloc(sizeof *ports * (b1->n_ports + 1));
    memcpy(ports, b1->ports, sizeof *ports * b1->n_ports);
    ports[b1->n_ports] = port;
    ovsrec_bridge_verify_ports(b1);
    ovsrec_bridge_set_ports(b1, ports, b1->n_ports + 1);

    free(ports);
    free(port_name);
    free(peer_port_name);
}

static void
create_patch_ports(struct controller_ctx *ctx,
                   const char *network,
                   struct shash *existing_ports,
                   const struct ovsrec_bridge *b1,
                   const struct ovsrec_bridge *b2)
{
    size_t i;

    for (i = 0; i < b1->n_ports; i++) {
        if (match_patch_port(b1->ports[i], b1, b2)) {
            /* Patch port already exists on b1 */
            shash_find_and_delete(existing_ports, b1->ports[i]->name);
            break;
        }
    }
    if (i == b1->n_ports) {
        create_patch_port(ctx, network, b1, b2);
    }
}

static void
init_existing_ports(struct controller_ctx *ctx,
                    struct shash *existing_ports)
{
    const struct ovsrec_port *port;

    OVSREC_PORT_FOR_EACH (port, ctx->ovs_idl) {
        if (smap_get(&port->external_ids, "ovn-patch-port")) {
            shash_add(existing_ports, port->name, port);
        }
    }
}

static void
remove_port(struct controller_ctx *ctx,
            const struct ovsrec_port *port)
{
    const struct ovsrec_bridge *bridge;

    /* We know the port we want to delete, but we have to find the bridge its on
     * to do so.  Note this only runs on a config change that should be pretty
     * rare. */
    OVSREC_BRIDGE_FOR_EACH (bridge, ctx->ovs_idl) {
        size_t i;
        for (i = 0; i < bridge->n_ports; i++) {
            if (bridge->ports[i] != port) {
                continue;
            }
            struct ovsrec_port **new_ports;
            new_ports = xmemdup(bridge->ports,
                    sizeof *new_ports * (bridge->n_ports - 1));
            if (i != bridge->n_ports - 1) {
                /* Removed port was not last */
                new_ports[i] = bridge->ports[bridge->n_ports - 1];
            }
            ovsrec_bridge_verify_ports(bridge);
            ovsrec_bridge_set_ports(bridge, new_ports, bridge->n_ports - 1);
            free(new_ports);
            ovsrec_port_delete(port);
            return;
        }
    }
}

static void
parse_bridge_mappings(struct controller_ctx *ctx,
                      const struct ovsrec_bridge *br_int,
                      const char *mappings_cfg)
{
    struct shash existing_ports = SHASH_INITIALIZER(&existing_ports);
    init_existing_ports(ctx, &existing_ports);

    char *cur, *next, *start;
    next = start = xstrdup(mappings_cfg);
    while ((cur = strsep(&next, ",")) && *cur) {
        char *network, *bridge = cur;
        const struct ovsrec_bridge *ovs_bridge;

        network = strsep(&bridge, ":");
        if (!bridge || !*network || !*bridge) {
            VLOG_ERR("Invalid ovn-bridge-mappings configuration: '%s'",
                    mappings_cfg);
            break;
        }

        ovs_bridge = get_bridge(ctx->ovs_idl, bridge);
        if (!ovs_bridge) {
            VLOG_WARN("Bridge '%s' not found for network '%s'",
                    bridge, network);
            continue;
        }

        create_patch_ports(ctx, network, &existing_ports, br_int, ovs_bridge);
        create_patch_ports(ctx, network, &existing_ports, ovs_bridge, br_int);
    }
    free(start);

    /* Any ports left in existing_ports are related to configuration that has
     * been removed, so we should delete the ports now. */
    struct shash_node *port_node, *port_next_node;
    SHASH_FOR_EACH_SAFE (port_node, port_next_node, &existing_ports) {
        struct ovsrec_port *port = port_node->data;
        shash_delete(&existing_ports, port_node);
        remove_port(ctx, port);
    }
    shash_destroy(&existing_ports);
}

static void
init_bridge_mappings(struct controller_ctx *ctx,
                     const struct ovsrec_bridge *br_int)
{
    const char *mappings_cfg = "";
    const struct ovsrec_open_vswitch *cfg;

    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (cfg) {
        mappings_cfg = smap_get(&cfg->external_ids, "ovn-bridge-mappings");
        if (!mappings_cfg) {
            mappings_cfg = "";
        }
    }
    parse_bridge_mappings(ctx, br_int, mappings_cfg);
}

/* Retrieves the OVN Southbound remote location from the
 * "external-ids:ovn-remote" key in 'ovs_idl' and returns a copy of it.
 *
 * XXX ovn-controller does not support this changing mid-run, but that should
 * be addressed later. */
static char *
get_ovnsb_remote(struct ovsdb_idl *ovs_idl)
{
    while (1) {
        ovsdb_idl_run(ovs_idl);

        const struct ovsrec_open_vswitch *cfg
            = ovsrec_open_vswitch_first(ovs_idl);
        if (cfg) {
            const char *remote = smap_get(&cfg->external_ids, "ovn-remote");
            if (remote) {
                return xstrdup(remote);
            }
        }

        VLOG_INFO("OVN OVSDB remote not specified.  Waiting...");
        ovsdb_idl_wait(ovs_idl);
        poll_block();
    }
}

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    bool exiting;
    int retval;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemonize_start(false);

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_controller_exit, &exiting);

    daemonize_complete();

    ovsrec_init();
    sbrec_init();

    ofctrl_init();
    lflow_init();

    /* Connect to OVS OVSDB instance.  We do not monitor all tables by
     * default, so modules must register their interest explicitly.  */
    struct ovsdb_idl_loop ovs_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovs_remote, &ovsrec_idl_class, false, true));
    ovsdb_idl_add_table(ovs_idl_loop.idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl_loop.idl,
                         &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_open_vswitch_col_bridges);
    ovsdb_idl_add_table(ovs_idl_loop.idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_interface_col_type);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_interface_col_options);
    ovsdb_idl_add_table(ovs_idl_loop.idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_add_table(ovs_idl_loop.idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_bridge_col_fail_mode);
    ovsdb_idl_add_column(ovs_idl_loop.idl, &ovsrec_bridge_col_other_config);
    chassis_register_ovs_idl(ovs_idl_loop.idl);
    encaps_register_ovs_idl(ovs_idl_loop.idl);
    binding_register_ovs_idl(ovs_idl_loop.idl);
    physical_register_ovs_idl(ovs_idl_loop.idl);
    ovsdb_idl_get_initial_snapshot(ovs_idl_loop.idl);

    /* Connect to OVN SB database. */
    char *ovnsb_remote = get_ovnsb_remote(ovs_idl_loop.idl);
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_remote, &sbrec_idl_class, true, true));
    ovsdb_idl_get_initial_snapshot(ovnsb_idl_loop.idl);

    /* Main loop. */
    exiting = false;
    while (!exiting) {
        struct controller_ctx ctx = {
            .ovs_idl = ovs_idl_loop.idl,
            .ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_idl_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        const struct ovsrec_bridge *br_int = get_br_int(&ctx);
        const char *chassis_id = get_chassis_id(ctx.ovs_idl);

        /* Map bridges to local nets from ovn-bridge-mappings */
        if (br_int) {
            init_bridge_mappings(&ctx, br_int);
        }

        if (chassis_id) {
            chassis_run(&ctx, chassis_id);
            encaps_run(&ctx, br_int, chassis_id);
            binding_run(&ctx, br_int, chassis_id);
        }

        if (br_int) {
            enum mf_field_id mff_ovn_geneve = ofctrl_run(br_int);

            struct hmap flow_table = HMAP_INITIALIZER(&flow_table);
            lflow_run(&ctx, &flow_table);
            if (chassis_id) {
                physical_run(&ctx, mff_ovn_geneve,
                             br_int, chassis_id, &flow_table);
            }
            ofctrl_put(&flow_table);
            hmap_destroy(&flow_table);
        }

        unixctl_server_run(unixctl);

        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }

        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
        ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop);

        if (br_int) {
            ofctrl_wait();
        }
        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }

    /* It's time to exit.  Clean up the databases. */
    bool done = false;
    while (!done) {
        struct controller_ctx ctx = {
            .ovs_idl = ovs_idl_loop.idl,
            .ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_idl_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        const struct ovsrec_bridge *br_int = get_br_int(&ctx);
        const char *chassis_id = get_chassis_id(ctx.ovs_idl);

        /* Run all of the cleanup functions, even if one of them returns false.
         * We're done if all of them return true. */
        done = binding_cleanup(&ctx, chassis_id);
        done = chassis_cleanup(&ctx, chassis_id) && done;
        done = encaps_cleanup(&ctx, br_int) && done;
        if (done) {
            poll_immediate_wake();
        }

        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
        ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop);
        poll_block();
    }

    unixctl_server_destroy(unixctl);
    lflow_destroy();
    ofctrl_destroy();

    ovsdb_idl_loop_destroy(&ovs_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);

    free(ovnsb_remote);
    free(ovs_remote);
    service_stop();

    exit(retval);
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_BOOTSTRAP_CA_CERT,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS
    };

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        DAEMON_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {NULL, 0, NULL, 0}
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(OFP13_VERSION, OFP13_VERSION);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    if (argc == 0) {
        ovs_remote = xasprintf("unix:%s/db.sock", ovs_rundir());
    } else if (argc == 1) {
        ovs_remote = xstrdup(argv[0]);
    } else {
        VLOG_FATAL("exactly zero or one non-option argument required; "
                   "use --help for usage");
    }
}

static void
usage(void)
{
    printf("%s: OVN controller\n"
           "usage %s [OPTIONS] [OVS-DATABASE]\n"
           "where OVS-DATABASE is a socket on which the OVS OVSDB server is listening.\n",
               program_name, program_name);
    stream_usage("OVS-DATABASE", true, false, false);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

static void
ovn_controller_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}
