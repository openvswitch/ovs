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
#include "physical.h"
#include "pipeline.h"

VLOG_DEFINE_THIS_MODULE(main);

static unixctl_cb_func ovn_controller_exit;

#define DEFAULT_BRIDGE_NAME "br-int"

static void parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

static char *ovs_remote;
static char *ovnsb_remote;


static void
get_initial_snapshot(struct ovsdb_idl *idl)
{
    while (1) {
        ovsdb_idl_run(idl);
        if (ovsdb_idl_has_ever_connected(idl)) {
            return;
        }
        ovsdb_idl_wait(idl);
        poll_block();
    }
}

static const struct ovsrec_bridge *
get_bridge(struct controller_ctx *ctx, const char *name)
{
    const struct ovsrec_bridge *br;

    OVSREC_BRIDGE_FOR_EACH(br, ctx->ovs_idl) {
        if (!strcmp(br->name, name)) {
            return br;
        }
    }

    return NULL;
}

/* Retrieve the OVN integration bridge from the "external-ids:ovn-bridge"
 * key, the remote location from the "external-ids:ovn-remote" key, and
 * the chassis name from the "external-ids:system-id" key in the
 * Open_vSwitch table of the OVS database instance.
 *
 * xxx ovn-controller does not support changing any of these mid-run,
 * xxx but that should be addressed later. */
static void
get_core_config(struct controller_ctx *ctx)
{
    const struct ovsrec_open_vswitch *cfg;

    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (!cfg) {
        VLOG_ERR("No Open_vSwitch row defined.");
        ovsdb_idl_destroy(ctx->ovs_idl);
        exit(EXIT_FAILURE);
    }

    while (1) {
        const struct ovsrec_bridge *br_int;
        const char *remote, *system_id, *br_int_name;

        ovsdb_idl_run(ctx->ovs_idl);

        br_int_name = smap_get(&cfg->external_ids, "ovn-bridge");
        if (!br_int_name) {
            br_int_name = DEFAULT_BRIDGE_NAME;
        }
        ctx->br_int_name = xstrdup(br_int_name);

        br_int = get_bridge(ctx, ctx->br_int_name);
        if (!br_int) {
            VLOG_INFO("Integration bridge '%s' does not exist.  Waiting...",
                      ctx->br_int_name);
            goto try_again;
        }

        remote = smap_get(&cfg->external_ids, "ovn-remote");
        if (!remote) {
            VLOG_INFO("OVN OVSDB remote not specified.  Waiting...");
            goto try_again;
        }

        system_id = smap_get(&cfg->external_ids, "system-id");
        if (!system_id) {
            VLOG_INFO("system-id not specified.  Waiting...");
            goto try_again;
        }

        ovnsb_remote = xstrdup(remote);
        ctx->chassis_id = xstrdup(system_id);
        return;

try_again:
        ovsdb_idl_wait(ctx->ovs_idl);
        poll_block();
    }

}

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct controller_ctx ctx = { .chassis_id = NULL };
    bool exiting;
    int retval;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemonize_start();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_controller_exit, &exiting);

    daemonize_complete();

    ovsrec_init();
    sbrec_init();

    ofctrl_init();

    /* Connect to OVS OVSDB instance.  We do not monitor all tables by
     * default, so modules must register their interest explicitly.  */
    ctx.ovs_idl = ovsdb_idl_create(ovs_remote, &ovsrec_idl_class, false, true);

    /* Register interest in "external_ids" column in "Open_vSwitch" table,
     * since we'll need to get the OVN OVSDB remote. */
    ovsdb_idl_add_table(ctx.ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ctx.ovs_idl, &ovsrec_open_vswitch_col_external_ids);

    chassis_init(&ctx);
    binding_init(&ctx);
    physical_init(&ctx);
    pipeline_init();

    get_initial_snapshot(ctx.ovs_idl);

    get_core_config(&ctx);

    ctx.ovnsb_idl = ovsdb_idl_create(ovnsb_remote, &sbrec_idl_class,
                                     true, true);
    get_initial_snapshot(ctx.ovnsb_idl);

    exiting = false;
    while (!exiting) {
        ovsdb_idl_run(ctx.ovs_idl);
        ovsdb_idl_run(ctx.ovnsb_idl);

        /* xxx If run into any surprising changes, we exit.  We should
         * xxx handle this more gracefully. */
        ctx.br_int = get_bridge(&ctx, ctx.br_int_name);
        if (!ctx.br_int) {
            VLOG_ERR("Integration bridge '%s' disappeared",
                     ctx.br_int_name);
            retval = EXIT_FAILURE;
            break;
        }

        if (!ovsdb_idl_is_alive(ctx.ovnsb_idl)) {
            int retval = ovsdb_idl_get_last_error(ctx.ovnsb_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                     ovnsb_remote, ovs_retval_to_string(retval));
            retval = EXIT_FAILURE;
            break;
        }

        if (!ovsdb_idl_is_alive(ctx.ovs_idl)) {
            int retval = ovsdb_idl_get_last_error(ctx.ovs_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                     ovs_remote, ovs_retval_to_string(retval));
            retval = EXIT_FAILURE;
            break;
        }

        ofctrl_clear_flows();

        chassis_run(&ctx);
        binding_run(&ctx);
        pipeline_run(&ctx);
        physical_run(&ctx);
        ofctrl_run(&ctx);
        unixctl_server_run(unixctl);

        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }

        ovsdb_idl_wait(ctx.ovs_idl);
        ovsdb_idl_wait(ctx.ovnsb_idl);
        ofctrl_wait();
        poll_block();
    }

    unixctl_server_destroy(unixctl);
    pipeline_destroy(&ctx);
    ofctrl_destroy();
    binding_destroy(&ctx);
    chassis_destroy(&ctx);

    ovsdb_idl_destroy(ctx.ovs_idl);
    ovsdb_idl_destroy(ctx.ovnsb_idl);

    free(ctx.br_int_name);
    free(ctx.chassis_id);
    free(ovnsb_remote);
    free(ovs_remote);

    exit(retval);
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
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
