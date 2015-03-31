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
#include <stdlib.h>
#include <stdio.h>

#include "command-line.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "ovn/ovn-idl.h"
#include "ovn/ovn-nb-idl.h"
#include "poll-loop.h"
#include "stream.h"
#include "stream-ssl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_nbd);

static const char *ovnnb_db;
static const char *ovn_db;

static const char *default_db(void);

static void
usage(void)
{
    printf("\
%s: OVN northbound management daemon\n\
usage: %s [OPTIONS]\n\
\n\
Options:\n\
  --ovnnb-db=DATABASE       connect to ovn-nb database at DATABASE\n\
                            (default: %s)\n\
  --ovn-db=DATABASE         connect to ovn database at DATABASE\n\
                            (default: %s)\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_db(), default_db());
    vlog_usage();
    stream_usage("database", true, true, false);
}

static void
ovnnb_db_changed(struct ovsdb_idl *idl OVS_UNUSED)
{
    /* XXX */
    printf("ovn-nbd: ovn-nb db contents have changed.\n");
}

static void
ovn_db_changed(struct ovsdb_idl *idl OVS_UNUSED)
{
    /* XXX */
    printf("ovn-nbd: ovn db contents have changed.\n");
}

static const char *
default_db(void)
{
    static char *def;
    if (!def) {
        def = xasprintf("unix:%s/db.sock", ovs_rundir());
    }
    return def;
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        VLOG_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"ovn-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        VLOG_OPTION_HANDLERS;
        STREAM_SSL_OPTION_HANDLERS;

        case 'd':
            ovn_db = optarg;
            break;

        case 'D':
            ovnnb_db = optarg;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        default:
            break;
        }
    }

    if (!ovn_db) {
        ovn_db = default_db();
    }

    if (!ovnnb_db) {
        ovnnb_db = default_db();
    }

    free(short_options);
}

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_reconnect;
    struct ovsdb_idl *ovnnb_idl, *ovn_idl;
    unsigned int ovnnb_seqno, ovn_seqno;
    int res = EXIT_SUCCESS;

    fatal_ignore_sigpipe();
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_DESTINATION, VLL_WARN);
    parse_options(argc, argv);
    nbrec_init();
    ovnrec_init();

    /* We want to detect all changes to the ovn-nb db. */
    ovnnb_idl = ovsdb_idl_create(ovnnb_db, &nbrec_idl_class, true, true);

    /* There is only a small subset of changes to the ovn db that ovn-nbd has to
     * care about, so we'll enable monitoring those directly. */
    ovn_idl = ovsdb_idl_create(ovn_db, &ovnrec_idl_class, false, true);
    ovsdb_idl_add_column(ovn_idl, &ovnrec_bindings_col_chassis);

    /*
     * The loop here just runs the IDL in a loop waiting for the seqno to
     * change, which indicates that the contents of the db have changed.
     *
     * If the contents of the ovn-nb db change, the mappings to the ovn db must
     * be recalculated.
     *
     * If the contents of the ovn db change, it means the 'up' state of a port
     * may have changed, as that's the only type of change ovn-nbd is watching
     * for.
     */

    ovnnb_seqno = ovsdb_idl_get_seqno(ovnnb_idl);
    ovn_seqno = ovsdb_idl_get_seqno(ovn_idl);
    for (;;) {
        ovsdb_idl_run(ovnnb_idl);
        ovsdb_idl_run(ovn_idl);

        if (!ovsdb_idl_is_alive(ovnnb_idl)) {
            int retval = ovsdb_idl_get_last_error(ovnnb_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                    ovnnb_db, ovs_retval_to_string(retval));
            res = EXIT_FAILURE;
            break;
        }

        if (!ovsdb_idl_is_alive(ovn_idl)) {
            int retval = ovsdb_idl_get_last_error(ovn_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                    ovn_db, ovs_retval_to_string(retval));
            res = EXIT_FAILURE;
            break;
        }

        if (ovnnb_seqno != ovsdb_idl_get_seqno(ovnnb_idl)) {
            ovnnb_seqno = ovsdb_idl_get_seqno(ovnnb_idl);
            ovnnb_db_changed(ovnnb_idl);
        }

        if (ovn_seqno != ovsdb_idl_get_seqno(ovn_idl)) {
            ovn_seqno = ovsdb_idl_get_seqno(ovn_idl);
            ovn_db_changed(ovn_idl);
        }

        if (ovnnb_seqno == ovsdb_idl_get_seqno(ovnnb_idl) &&
                ovn_seqno == ovsdb_idl_get_seqno(ovn_idl)) {
            ovsdb_idl_wait(ovnnb_idl);
            ovsdb_idl_wait(ovn_idl);
            poll_block();
        }
    }

    ovsdb_idl_destroy(ovnnb_idl);

    exit(res);
}
