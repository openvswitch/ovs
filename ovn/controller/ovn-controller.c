/* Copyright (c) 2015, 2016 Nicira, Inc.
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

#include "binding.h"
#include "chassis.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "encaps.h"
#include "fatal-signal.h"
#include "hmap.h"
#include "lflow.h"
#include "lib/vswitch-idl.h"
#include "lport.h"
#include "ofctrl.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "patch.h"
#include "physical.h"
#include "pinctrl.h"
#include "poll-loop.h"
#include "smap.h"
#include "stream-ssl.h"
#include "stream.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(main);

static unixctl_cb_func ovn_controller_exit;
static unixctl_cb_func ct_zone_list;

#define DEFAULT_BRIDGE_NAME "br-int"

static void parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

static char *ovs_remote;

const struct sbrec_chassis *
get_chassis(struct ovsdb_idl *ovnsb_idl, const char *chassis_id)
{
    const struct sbrec_chassis *chassis_rec;

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ovnsb_idl) {
        if (!strcmp(chassis_rec->name, chassis_id)) {
            break;
        }
    }

    return chassis_rec;
}

uint32_t
get_tunnel_type(const char *name)
{
    if (!strcmp(name, "geneve")) {
        return GENEVE;
    } else if (!strcmp(name, "stt")) {
        return STT;
    } else if (!strcmp(name, "vxlan")) {
        return VXLAN;
    }

    return 0;
}

const struct ovsrec_bridge *
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

/* Retrieves the OVN Southbound remote's json session probe interval from the
 * "external-ids:ovn-remote-probe-interval" key in 'ovs_idl' and returns it.
 *
 * This function must be called after get_ovnsb_remote(). */
static bool
get_ovnsb_remote_probe_interval(struct ovsdb_idl *ovs_idl, int *value)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(ovs_idl);
    if (!cfg) {
        return false;
    }

    const char *probe_interval =
        smap_get(&cfg->external_ids, "ovn-remote-probe-interval");
    if (probe_interval) {
        if (str_to_int(probe_interval, 10, value)) {
            return true;
        }

        VLOG_WARN("Invalid value for OVN remote probe interval: %s",
                  probe_interval);
    }

    return false;
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
    pinctrl_init();
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

    int probe_interval = 0;
    if (get_ovnsb_remote_probe_interval(ovs_idl_loop.idl, &probe_interval)) {
        ovsdb_idl_set_probe_interval(ovnsb_idl_loop.idl, probe_interval);
    }

    /* Initialize connection tracking zones. */
    struct simap ct_zones = SIMAP_INITIALIZER(&ct_zones);
    unsigned long ct_zone_bitmap[BITMAP_N_LONGS(MAX_CT_ZONES)];
    bitmap_set1(ct_zone_bitmap, 0); /* Zone 0 is reserved. */
    unixctl_command_register("ct-zone-list", "", 0, 0,
                             ct_zone_list, &ct_zones);

    /* Main loop. */
    exiting = false;
    while (!exiting) {
        struct controller_ctx ctx = {
            .ovs_idl = ovs_idl_loop.idl,
            .ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_idl_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        /* Contains "struct local_datpath" nodes whose hash values are the
         * tunnel_key of datapaths with at least one local port binding. */
        struct hmap local_datapaths = HMAP_INITIALIZER(&local_datapaths);

        struct hmap patched_datapaths = HMAP_INITIALIZER(&patched_datapaths);

        const struct ovsrec_bridge *br_int = get_br_int(&ctx);
        const char *chassis_id = get_chassis_id(ctx.ovs_idl);

        if (chassis_id) {
            chassis_run(&ctx, chassis_id);
            encaps_run(&ctx, br_int, chassis_id);
            binding_run(&ctx, br_int, chassis_id, &ct_zones, ct_zone_bitmap,
                    &local_datapaths);
        }

        if (br_int) {
            patch_run(&ctx, br_int, &local_datapaths, &patched_datapaths);

            struct lport_index lports;
            struct mcgroup_index mcgroups;
            lport_index_init(&lports, ctx.ovnsb_idl);
            mcgroup_index_init(&mcgroups, ctx.ovnsb_idl);

            enum mf_field_id mff_ovn_geneve = ofctrl_run(br_int);

            pinctrl_run(&ctx, &lports, br_int);

            struct hmap flow_table = HMAP_INITIALIZER(&flow_table);
            lflow_run(&ctx, &lports, &mcgroups, &local_datapaths,
                      &patched_datapaths, &ct_zones, &flow_table);
            if (chassis_id) {
                physical_run(&ctx, mff_ovn_geneve,
                             br_int, chassis_id, &ct_zones, &flow_table,
                             &local_datapaths, &patched_datapaths);
            }
            ofctrl_put(&flow_table);
            hmap_destroy(&flow_table);
            mcgroup_index_destroy(&mcgroups);
            lport_index_destroy(&lports);
        }

        struct local_datapath *cur_node, *next_node;
        HMAP_FOR_EACH_SAFE (cur_node, next_node, hmap_node, &local_datapaths) {
            hmap_remove(&local_datapaths, &cur_node->hmap_node);
            free(cur_node);
        }
        hmap_destroy(&local_datapaths);

        struct patched_datapath *pd_cur_node, *pd_next_node;
        HMAP_FOR_EACH_SAFE (pd_cur_node, pd_next_node, hmap_node,
                &patched_datapaths) {
            hmap_remove(&patched_datapaths, &pd_cur_node->hmap_node);
            free(pd_cur_node);
        }
        hmap_destroy(&patched_datapaths);

        unixctl_server_run(unixctl);

        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }

        if (br_int) {
            ofctrl_wait();
            pinctrl_wait(&ctx);
        }
        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
        ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop);
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
    pinctrl_destroy();

    simap_destroy(&ct_zones);

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

static void
ct_zone_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *ct_zones_)
{
    struct simap *ct_zones = ct_zones_;
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct simap_node *zone;

    SIMAP_FOR_EACH(zone, ct_zones) {
        ds_put_format(&ds, "%s %d\n", zone->name, zone->data);
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}
