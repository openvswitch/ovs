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
#include "daemon.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "hash.h"
#include "hmap.h"
#include "ovn/ovn-nb-idl.h"
#include "ovn/ovn-sb-idl.h"
#include "poll-loop.h"
#include "stream.h"
#include "stream-ssl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_nbd);

struct nbd_context {
    struct ovsdb_idl *ovnnb_idl;
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnnb_txn;
    struct ovsdb_idl_txn *ovn_txn;
};

static const char *ovnnb_db;
static const char *ovnsb_db;

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
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_db(), default_db());
    daemon_usage();
    vlog_usage();
    stream_usage("database", true, true, false);
}

static int
compare_strings(const void *a_, const void *b_)
{
    char *const *a = a_;
    char *const *b = b_;
    return strcmp(*a, *b);
}

/*
 * Determine whether 2 arrays of MAC addresses are the same.  It's possible that
 * the lists could be *very* long and this check is being done a lot (every
 * time the OVN_Northbound database changes).
 */
static bool
macs_equal(char **binding_macs_, size_t b_n_macs,
           char **lport_macs_, size_t l_n_macs)
{
    char **binding_macs, **lport_macs;
    size_t bytes, i;

    if (b_n_macs != l_n_macs) {
        return false;
    }

    bytes = b_n_macs * sizeof binding_macs_[0];
    binding_macs = xmalloc(bytes);
    lport_macs = xmalloc(bytes);

    memcpy(binding_macs, binding_macs_, bytes);
    memcpy(lport_macs, lport_macs_, bytes);

    qsort(binding_macs, b_n_macs, sizeof binding_macs[0], compare_strings);
    qsort(lport_macs, l_n_macs, sizeof lport_macs[0], compare_strings);

    for (i = 0; i < b_n_macs; i++) {
        if (strcmp(binding_macs[i], lport_macs[i])) {
            break;
        }
    }

    free(binding_macs);
    free(lport_macs);

    return (i == b_n_macs) ? true : false;
}

/*
 * When a change has occurred in the OVN_Northbound database, we go through and
 * make sure that the contents of the Bindings table in the OVN_Southbound
 * database are up to date with the logical ports defined in the
 * OVN_Northbound database.
 */
static void
set_bindings(struct nbd_context *ctx)
{
    struct hmap bindings_hmap;
    const struct sbrec_bindings *binding;
    const struct nbrec_logical_port *lport;

    struct binding_hash_node {
        struct hmap_node node;
        const struct sbrec_bindings *binding;
    } *hash_node, *hash_node_next;

    /*
     * We will need to look up a binding for every logical port.  We don't want
     * to have to do an O(n) search for every binding, so start out by hashing
     * them on the logical port.
     *
     * As we go through every logical port, we will update the binding if it
     * exists or create one otherwise.  When the update is done, we'll remove it
     * from the hashmap.  At the end, any bindings left in the hashmap are for
     * logical ports that have been deleted.
     */
    hmap_init(&bindings_hmap);

    SBREC_BINDINGS_FOR_EACH(binding, ctx->ovnsb_idl) {
        struct binding_hash_node *hash_node = xzalloc(sizeof *hash_node);

        hash_node->binding = binding;
        hmap_insert(&bindings_hmap, &hash_node->node,
                hash_string(binding->logical_port, 0));
    }

    NBREC_LOGICAL_PORT_FOR_EACH(lport, ctx->ovnnb_idl) {
        HMAP_FOR_EACH_WITH_HASH(hash_node, node,
                hash_string(lport->name, 0), &bindings_hmap) {
            if (!strcmp(lport->name, hash_node->binding->logical_port)) {
                break;
            }
        }

        if (hash_node) {
            /* We found an existing binding for this logical port.  Update its
             * contents.  Right now the only thing we expect that could change
             * is the list of MAC addresses. */

            binding = hash_node->binding;
            hmap_remove(&bindings_hmap, &hash_node->node);
            free(hash_node);
            hash_node = NULL;

            if (!macs_equal(binding->mac, binding->n_mac,
                        lport->macs, lport->n_macs)) {
                sbrec_bindings_set_mac(binding,
                        (const char **) lport->macs, lport->n_macs);
            }
        } else {
            /* There is no binding for this logical port, so create one. */

            binding = sbrec_bindings_insert(ctx->ovn_txn);
            sbrec_bindings_set_logical_port(binding, lport->name);
            sbrec_bindings_set_mac(binding,
                    (const char **) lport->macs, lport->n_macs);
        }
    }

    HMAP_FOR_EACH_SAFE(hash_node, hash_node_next, node, &bindings_hmap) {
        hmap_remove(&bindings_hmap, &hash_node->node);
        sbrec_bindings_delete(hash_node->binding);
        free(hash_node);
    }
    hmap_destroy(&bindings_hmap);
}

static void
ovnnb_db_changed(struct nbd_context *ctx)
{
    VLOG_DBG("ovn-nbd: ovn-nb db contents have changed.\n");

    set_bindings(ctx);
}

/*
 * The only change we get notified about is if the 'chassis' column of the
 * 'Bindings' table changes.  When this column is not empty, it means we need to
 * set the corresponding logical port as 'up' in the northbound DB.
 */
static void
ovnsb_db_changed(struct nbd_context *ctx)
{
    const struct sbrec_bindings *bindings;

    VLOG_DBG("Recalculating port up states for ovn-nb db.");

    SBREC_BINDINGS_FOR_EACH(bindings, ctx->ovnsb_idl) {
        const struct nbrec_logical_port *lport;
        struct uuid lport_uuid;

        if (!uuid_from_string(&lport_uuid, bindings->logical_port)) {
            VLOG_WARN("Invalid logical port UUID '%s' in Bindings table.",
                    bindings->logical_port);
            continue;
        }

        lport = nbrec_logical_port_get_for_uuid(ctx->ovnnb_idl, &lport_uuid);
        if (!lport) {
            VLOG_WARN("No logical port '%s' found in OVN-nb db.",
                    bindings->logical_port);
            continue;
        }

        if (*bindings->chassis && (!lport->up || !*lport->up)) {
            bool up = true;
            nbrec_logical_port_set_up(lport, &up, 1);
        } else if (!*bindings->chassis && (!lport->up || *lport->up)) {
            bool up = false;
            nbrec_logical_port_set_up(lport, &up, 1);
        }
    }
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
        DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
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
        DAEMON_OPTION_HANDLERS;
        VLOG_OPTION_HANDLERS;
        STREAM_SSL_OPTION_HANDLERS;

        case 'd':
            ovnsb_db = optarg;
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

    if (!ovnsb_db) {
        ovnsb_db = default_db();
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
    struct ovsdb_idl *ovnnb_idl, *ovnsb_idl;
    unsigned int ovnnb_seqno, ovn_seqno;
    int res = EXIT_SUCCESS;
    struct nbd_context ctx = {
        .ovn_txn = NULL,
    };
    bool ovnnb_changes_pending = false;
    bool ovn_changes_pending = false;

    fatal_ignore_sigpipe();
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_DESTINATION, VLL_WARN);
    parse_options(argc, argv);

    daemonize();

    nbrec_init();
    sbrec_init();

    /* We want to detect all changes to the ovn-nb db. */
    ctx.ovnnb_idl = ovnnb_idl = ovsdb_idl_create(ovnnb_db,
            &nbrec_idl_class, true, true);

    /* There is only a small subset of changes to the ovn db that ovn-nbd has to
     * care about, so we'll enable monitoring those directly. */
    ctx.ovnsb_idl = ovnsb_idl = ovsdb_idl_create(ovnsb_db,
            &sbrec_idl_class, false, true);
    ovsdb_idl_add_table(ovnsb_idl, &sbrec_table_bindings);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_bindings_col_logical_port);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_bindings_col_chassis);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_bindings_col_mac);

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
    ovn_seqno = ovsdb_idl_get_seqno(ovnsb_idl);
    for (;;) {
        ovsdb_idl_run(ovnnb_idl);
        ovsdb_idl_run(ovnsb_idl);

        if (!ovsdb_idl_is_alive(ovnnb_idl)) {
            int retval = ovsdb_idl_get_last_error(ovnnb_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                    ovnnb_db, ovs_retval_to_string(retval));
            res = EXIT_FAILURE;
            break;
        }

        if (!ovsdb_idl_is_alive(ovnsb_idl)) {
            int retval = ovsdb_idl_get_last_error(ovnsb_idl);
            VLOG_ERR("%s: database connection failed (%s)",
                    ovnsb_db, ovs_retval_to_string(retval));
            res = EXIT_FAILURE;
            break;
        }

        if (ovnnb_seqno != ovsdb_idl_get_seqno(ovnnb_idl)) {
            ovnnb_seqno = ovsdb_idl_get_seqno(ovnnb_idl);
            ovnnb_changes_pending = true;
        }

        if (ovn_seqno != ovsdb_idl_get_seqno(ovnsb_idl)) {
            ovn_seqno = ovsdb_idl_get_seqno(ovnsb_idl);
            ovn_changes_pending = true;
        }

        /*
         * If there are any pending changes, we delay recalculating the
         * necessary updates until after an existing transaction finishes.
         * This avoids the possibility of rapid updates causing ovn-nbd to never
         * be able to successfully make the corresponding updates to the other
         * db.  Instead, pending changes are batched up until the next time we
         * get a chance to calculate the new state and apply it.
         */

        if (ovnnb_changes_pending && !ctx.ovn_txn) {
            /*
             * The OVN-nb db contents have changed, so create a transaction for
             * updating the OVN DB.
             */
            ctx.ovn_txn = ovsdb_idl_txn_create(ctx.ovnsb_idl);
            ovnnb_db_changed(&ctx);
            ovnnb_changes_pending = false;
        }

        if (ovn_changes_pending && !ctx.ovnnb_txn) {
            /*
             * The OVN db contents have changed, so create a transaction for
             * updating the northbound DB.
             */
            ctx.ovnnb_txn = ovsdb_idl_txn_create(ctx.ovnnb_idl);
            ovnsb_db_changed(&ctx);
            ovn_changes_pending = false;
        }

        if (ctx.ovnnb_txn) {
            enum ovsdb_idl_txn_status txn_status;
            txn_status = ovsdb_idl_txn_commit(ctx.ovnnb_txn);
            switch (txn_status) {
            case TXN_UNCOMMITTED:
            case TXN_INCOMPLETE:
                /* Come back around and try to commit this transaction again */
                break;
            case TXN_ABORTED:
            case TXN_TRY_AGAIN:
            case TXN_NOT_LOCKED:
            case TXN_ERROR:
                /* Something went wrong, so try creating a new transaction. */
                ovn_changes_pending = true;
            case TXN_UNCHANGED:
            case TXN_SUCCESS:
                ovsdb_idl_txn_destroy(ctx.ovnnb_txn);
                ctx.ovnnb_txn = NULL;
            }
        }

        if (ctx.ovn_txn) {
            enum ovsdb_idl_txn_status txn_status;
            txn_status = ovsdb_idl_txn_commit(ctx.ovn_txn);
            switch (txn_status) {
            case TXN_UNCOMMITTED:
            case TXN_INCOMPLETE:
                /* Come back around and try to commit this transaction again */
                break;
            case TXN_ABORTED:
            case TXN_TRY_AGAIN:
            case TXN_NOT_LOCKED:
            case TXN_ERROR:
                /* Something went wrong, so try creating a new transaction. */
                ovnnb_changes_pending = true;
            case TXN_UNCHANGED:
            case TXN_SUCCESS:
                ovsdb_idl_txn_destroy(ctx.ovn_txn);
                ctx.ovn_txn = NULL;
            }
        }

        if (ovnnb_seqno == ovsdb_idl_get_seqno(ovnnb_idl) &&
                ovn_seqno == ovsdb_idl_get_seqno(ovnsb_idl)) {
            ovsdb_idl_wait(ovnnb_idl);
            ovsdb_idl_wait(ovnsb_idl);
            if (ctx.ovnnb_txn) {
                ovsdb_idl_txn_wait(ctx.ovnnb_txn);
            }
            if (ctx.ovn_txn) {
                ovsdb_idl_txn_wait(ctx.ovn_txn);
            }
            poll_block();
        }
    }

    ovsdb_idl_destroy(ovnsb_idl);
    ovsdb_idl_destroy(ovnnb_idl);

    exit(res);
}
