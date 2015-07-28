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
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "hmap.h"
#include "json.h"
#include "ovn/lib/lex.h"
#include "ovn/lib/ovn-nb-idl.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "poll-loop.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_northd);

static unixctl_cb_func ovn_northd_exit;

struct northd_context {
    struct ovsdb_idl *ovnnb_idl;
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnnb_txn;
    struct ovsdb_idl_txn *ovnsb_txn;
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

/* Pipeline generation.
 *
 * This code generates the Pipeline table in the southbound database, as a
 * function of most of the northbound database.
 */

/* Enough context to add a Pipeline row, using pipeline_add(). */
struct pipeline_ctx {
    /* From northd_context. */
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnsb_txn;

    /* Contains "struct pipeline_hash_node"s.  Used to figure out what existing
     * Pipeline rows should be deleted: we index all of the Pipeline rows into
     * this data structure, then as existing rows are generated we remove them.
     * After generating all the rows, any remaining in 'pipeline_hmap' must be
     * deleted from the database. */
    struct hmap pipeline_hmap;
};

/* A row in the Pipeline table, indexed by its full contents, */
struct pipeline_hash_node {
    struct hmap_node node;
    const struct sbrec_pipeline *pipeline;
};

static size_t
pipeline_hash(const struct uuid *logical_datapath, uint8_t table_id,
              uint16_t priority, const char *match, const char *actions)
{
    size_t hash = uuid_hash(logical_datapath);
    hash = hash_2words((table_id << 16) | priority, hash);
    hash = hash_string(match, hash);
    return hash_string(actions, hash);
}

static size_t
pipeline_hash_rec(const struct sbrec_pipeline *pipeline)
{
    return pipeline_hash(&pipeline->logical_datapath, pipeline->table_id,
                         pipeline->priority, pipeline->match,
                         pipeline->actions);
}

/* Adds a row with the specified contents to the Pipeline table. */
static void
pipeline_add(struct pipeline_ctx *ctx,
             const struct nbrec_logical_switch *logical_datapath,
             uint8_t table_id,
             uint16_t priority,
             const char *match,
             const char *actions)
{
    struct pipeline_hash_node *hash_node;

    /* Check whether such a row already exists in the Pipeline table.  If so,
     * remove it from 'ctx->pipeline_hmap' and we're done. */
    HMAP_FOR_EACH_WITH_HASH (hash_node, node,
                             pipeline_hash(&logical_datapath->header_.uuid,
                                           table_id, priority, match, actions),
                             &ctx->pipeline_hmap) {
        const struct sbrec_pipeline *pipeline = hash_node->pipeline;
        if (uuid_equals(&pipeline->logical_datapath,
                        &logical_datapath->header_.uuid)
            && pipeline->table_id == table_id
            && pipeline->priority == priority
            && !strcmp(pipeline->match, match)
            && !strcmp(pipeline->actions, actions)) {
            hmap_remove(&ctx->pipeline_hmap, &hash_node->node);
            free(hash_node);
            return;
        }
    }

    /* No such Pipeline row.  Add one. */
    const struct sbrec_pipeline *pipeline;
    pipeline = sbrec_pipeline_insert(ctx->ovnsb_txn);
    sbrec_pipeline_set_logical_datapath(pipeline,
                                        logical_datapath->header_.uuid);
    sbrec_pipeline_set_table_id(pipeline, table_id);
    sbrec_pipeline_set_priority(pipeline, priority);
    sbrec_pipeline_set_match(pipeline, match);
    sbrec_pipeline_set_actions(pipeline, actions);
}

/* Appends port security constraints on L2 address field 'eth_addr_field'
 * (e.g. "eth.src" or "eth.dst") to 'match'.  'port_security', with
 * 'n_port_security' elements, is the collection of port_security constraints
 * from an OVN_NB Logical_Port row. */
static void
build_port_security(const char *eth_addr_field,
                    char **port_security, size_t n_port_security,
                    struct ds *match)
{
    size_t base_len = match->length;
    ds_put_format(match, " && %s == {", eth_addr_field);

    size_t n = 0;
    for (size_t i = 0; i < n_port_security; i++) {
        uint8_t ea[ETH_ADDR_LEN];

        if (eth_addr_from_string(port_security[i], ea)) {
            ds_put_format(match, ETH_ADDR_FMT, ETH_ADDR_ARGS(ea));
            ds_put_char(match, ' ');
            n++;
        }
    }
    ds_chomp(match, ' ');
    ds_put_cstr(match, "}");

    if (!n) {
        match->length = base_len;
    }
}

static bool
lport_is_enabled(const struct nbrec_logical_port *lport)
{
    return !lport->enabled || *lport->enabled;
}

/* Updates the Pipeline table in the OVN_SB database, constructing its contents
 * based on the OVN_NB database. */
static void
build_pipeline(struct northd_context *ctx)
{
    struct pipeline_ctx pc = {
        .ovnsb_idl = ctx->ovnsb_idl,
        .ovnsb_txn = ctx->ovnsb_txn,
        .pipeline_hmap = HMAP_INITIALIZER(&pc.pipeline_hmap)
    };

    /* Add all the Pipeline entries currently in the southbound database to
     * 'pc.pipeline_hmap'.  We remove entries that we generate from the hmap,
     * thus by the time we're done only entries that need to be removed
     * remain. */
    const struct sbrec_pipeline *pipeline;
    SBREC_PIPELINE_FOR_EACH (pipeline, ctx->ovnsb_idl) {
        struct pipeline_hash_node *hash_node = xzalloc(sizeof *hash_node);
        hash_node->pipeline = pipeline;
        hmap_insert(&pc.pipeline_hmap, &hash_node->node,
                    pipeline_hash_rec(pipeline));
    }

    /* Table 0: Admission control framework. */
    const struct nbrec_logical_switch *lswitch;
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->ovnnb_idl) {
        /* Logical VLANs not supported. */
        pipeline_add(&pc, lswitch, 0, 100, "vlan.present", "drop;");

        /* Broadcast/multicast source address is invalid. */
        pipeline_add(&pc, lswitch, 0, 100, "eth.src[40]", "drop;");

        /* Port security flows have priority 50 (see below) and will continue
         * to the next table if packet source is acceptable. */

        /* Otherwise drop the packet. */
        pipeline_add(&pc, lswitch, 0, 0, "1", "drop;");
    }

    /* Table 0: Ingress port security. */
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->ovnnb_idl) {
        for (size_t i = 0; i < lswitch->n_ports; i++) {
            const struct nbrec_logical_port *lport = lswitch->ports[i];
            struct ds match = DS_EMPTY_INITIALIZER;
            ds_put_cstr(&match, "inport == ");
            json_string_escape(lport->name, &match);
            build_port_security("eth.src",
                                lport->port_security, lport->n_port_security,
                                &match);
            pipeline_add(&pc, lswitch, 0, 50, ds_cstr(&match),
                         lport_is_enabled(lport) ? "next;" : "drop;");
            ds_destroy(&match);
        }
    }

    /* Table 1: Destination lookup:
     *
     *   - Broadcast and multicast handling (priority 100).
     *   - Unicast handling (priority 50).
     *   - Unknown unicast address handling (priority 0).
     *   */
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->ovnnb_idl) {
        struct ds bcast;        /* Actions for broadcast on 'lswitch'. */
        struct ds unknown;      /* Actions for unknown MACs on 'lswitch'. */

        ds_init(&bcast);
        ds_init(&unknown);
        for (size_t i = 0; i < lswitch->n_ports; i++) {
            const struct nbrec_logical_port *lport = lswitch->ports[i];

            ds_put_cstr(&bcast, "outport = ");
            json_string_escape(lport->name, &bcast);
            ds_put_cstr(&bcast, "; next; ");

            for (size_t j = 0; j < lport->n_macs; j++) {
                const char *s = lport->macs[j];
                uint8_t mac[ETH_ADDR_LEN];

                if (eth_addr_from_string(s, mac)) {
                    struct ds match, unicast;

                    ds_init(&match);
                    ds_put_format(&match, "eth.dst == %s", s);

                    ds_init(&unicast);
                    ds_put_cstr(&unicast, "outport = ");
                    json_string_escape(lport->name, &unicast);
                    ds_put_cstr(&unicast, "; next;");
                    pipeline_add(&pc, lswitch, 1, 50,
                                 ds_cstr(&match), ds_cstr(&unicast));
                    ds_destroy(&unicast);
                    ds_destroy(&match);
                } else if (!strcmp(s, "unknown")) {
                    ds_put_cstr(&unknown, "outport = ");
                    json_string_escape(lport->name, &unknown);
                    ds_put_cstr(&unknown, "; next; ");
                } else {
                    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

                    VLOG_INFO_RL(&rl, "%s: invalid syntax '%s' in macs column",
                                 lport->name, s);
                }
            }
        }

        ds_chomp(&bcast, ' ');
        pipeline_add(&pc, lswitch, 1, 100, "eth.dst[40]", ds_cstr(&bcast));
        ds_destroy(&bcast);

        if (unknown.length) {
            ds_chomp(&unknown, ' ');
            pipeline_add(&pc, lswitch, 1, 0, "1", ds_cstr(&unknown));
        }
        ds_destroy(&unknown);
    }

    /* Table 2: ACLs. */
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->ovnnb_idl) {
        for (size_t i = 0; i < lswitch->n_acls; i++) {
            const struct nbrec_acl *acl = lswitch->acls[i];

            NBREC_ACL_FOR_EACH (acl, ctx->ovnnb_idl) {
                pipeline_add(&pc, lswitch, 2, acl->priority, acl->match,
                             (!strcmp(acl->action, "allow") ||
                              !strcmp(acl->action, "allow-related")
                              ? "next;" : "drop;"));
            }
        }

        pipeline_add(&pc, lswitch, 2, 0, "1", "next;");
    }

    /* Table 3: Egress port security. */
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->ovnnb_idl) {
        pipeline_add(&pc, lswitch, 3, 100, "eth.dst[40]", "output;");

        for (size_t i = 0; i < lswitch->n_ports; i++) {
            const struct nbrec_logical_port *lport = lswitch->ports[i];
            struct ds match;

            ds_init(&match);
            ds_put_cstr(&match, "outport == ");
            json_string_escape(lport->name, &match);
            build_port_security("eth.dst",
                                lport->port_security, lport->n_port_security,
                                &match);

            pipeline_add(&pc, lswitch, 3, 50, ds_cstr(&match),
                         lport_is_enabled(lport) ? "output;" : "drop;");

            ds_destroy(&match);
        }
    }

    /* Delete any existing Pipeline rows that were not re-generated.  */
    struct pipeline_hash_node *hash_node, *next_hash_node;
    HMAP_FOR_EACH_SAFE (hash_node, next_hash_node, node, &pc.pipeline_hmap) {
        hmap_remove(&pc.pipeline_hmap, &hash_node->node);
        sbrec_pipeline_delete(hash_node->pipeline);
        free(hash_node);
    }
    hmap_destroy(&pc.pipeline_hmap);
}

static bool
parents_equal(const struct sbrec_binding *binding,
              const struct nbrec_logical_port *lport)
{
    if (!!binding->parent_port != !!lport->parent_name) {
        /* One is set and the other is not. */
        return false;
    }

    if (binding->parent_port) {
        /* Both are set. */
        return strcmp(binding->parent_port, lport->parent_name) ? false : true;
    }

    /* Both are NULL. */
    return true;
}

static bool
tags_equal(const struct sbrec_binding *binding,
           const struct nbrec_logical_port *lport)
{
    if (binding->n_tag != lport->n_tag) {
        return false;
    }

    return binding->n_tag ? (binding->tag[0] == lport->tag[0]) : true;
}

struct binding_hash_node {
    struct hmap_node lp_node; /* In 'lp_map', by binding->logical_port. */
    struct hmap_node tk_node; /* In 'tk_map', by binding->tunnel_key. */
    const struct sbrec_binding *binding;
};

static bool
tunnel_key_in_use(const struct hmap *tk_hmap, uint16_t tunnel_key)
{
    const struct binding_hash_node *hash_node;

    HMAP_FOR_EACH_IN_BUCKET (hash_node, tk_node, hash_int(tunnel_key, 0),
                             tk_hmap) {
        if (hash_node->binding->tunnel_key == tunnel_key) {
            return true;
        }
    }
    return false;
}

/* Chooses and returns a positive tunnel key that is not already in use in
 * 'tk_hmap'.  Returns 0 if all tunnel keys are in use. */
static uint16_t
choose_tunnel_key(const struct hmap *tk_hmap)
{
    static uint16_t prev;

    for (uint16_t key = prev + 1; key != prev; key++) {
        if (!tunnel_key_in_use(tk_hmap, key)) {
            prev = key;
            return key;
        }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    VLOG_WARN_RL(&rl, "all tunnel keys exhausted");
    return 0;
}

/*
 * When a change has occurred in the OVN_Northbound database, we go through and
 * make sure that the contents of the Binding table in the OVN_Southbound
 * database are up to date with the logical ports defined in the
 * OVN_Northbound database.
 */
static void
set_bindings(struct northd_context *ctx)
{
    const struct sbrec_binding *binding;

    /*
     * We will need to look up a binding for every logical port.  We don't want
     * to have to do an O(n) search for every binding, so start out by hashing
     * them on the logical port.
     *
     * As we go through every logical port, we will update the binding if it
     * exists or create one otherwise.  When the update is done, we'll remove
     * it from the hashmap.  At the end, any bindings left in the hashmap are
     * for logical ports that have been deleted.
     *
     * We index the logical_port column because that's the shared key between
     * the OVN_NB and OVN_SB databases.  We index the tunnel_key column to
     * allow us to choose a unique tunnel key for any Binding rows we have to
     * add.
     */
    struct hmap lp_hmap = HMAP_INITIALIZER(&lp_hmap);
    struct hmap tk_hmap = HMAP_INITIALIZER(&tk_hmap);

    SBREC_BINDING_FOR_EACH(binding, ctx->ovnsb_idl) {
        struct binding_hash_node *hash_node = xzalloc(sizeof *hash_node);
        hash_node->binding = binding;
        hmap_insert(&lp_hmap, &hash_node->lp_node,
                    hash_string(binding->logical_port, 0));
        hmap_insert(&tk_hmap, &hash_node->tk_node,
                    hash_int(binding->tunnel_key, 0));
    }

    const struct nbrec_logical_switch *lswitch;
    NBREC_LOGICAL_SWITCH_FOR_EACH (lswitch, ctx->ovnnb_idl) {
        const struct uuid *logical_datapath = &lswitch->header_.uuid;

        for (size_t i = 0; i < lswitch->n_ports; i++) {
            const struct nbrec_logical_port *lport = lswitch->ports[i];
            struct binding_hash_node *hash_node;
            binding = NULL;
            HMAP_FOR_EACH_WITH_HASH(hash_node, lp_node,
                                    hash_string(lport->name, 0), &lp_hmap) {
                if (!strcmp(lport->name, hash_node->binding->logical_port)) {
                    binding = hash_node->binding;
                    break;
                }
            }

            if (binding) {
                /* We found an existing binding for this logical port.  Update
                 * its contents. */

                hmap_remove(&lp_hmap, &hash_node->lp_node);

                if (!macs_equal(binding->mac, binding->n_mac,
                                lport->macs, lport->n_macs)) {
                    sbrec_binding_set_mac(binding, (const char **) lport->macs,
                                          lport->n_macs);
                }
                if (!parents_equal(binding, lport)) {
                    sbrec_binding_set_parent_port(binding, lport->parent_name);
                }
                if (!tags_equal(binding, lport)) {
                    sbrec_binding_set_tag(binding, lport->tag, lport->n_tag);
                }
                if (!uuid_equals(&binding->logical_datapath,
                                 logical_datapath)) {
                    sbrec_binding_set_logical_datapath(binding,
                                                       *logical_datapath);
                }
            } else {
                /* There is no binding for this logical port, so create one. */

                uint16_t tunnel_key = choose_tunnel_key(&tk_hmap);
                if (!tunnel_key) {
                    continue;
                }

                binding = sbrec_binding_insert(ctx->ovnsb_txn);
                sbrec_binding_set_logical_port(binding, lport->name);
                sbrec_binding_set_mac(binding, (const char **) lport->macs,
                                      lport->n_macs);
                if (lport->parent_name && lport->n_tag > 0) {
                    sbrec_binding_set_parent_port(binding, lport->parent_name);
                    sbrec_binding_set_tag(binding, lport->tag, lport->n_tag);
                }

                sbrec_binding_set_tunnel_key(binding, tunnel_key);
                sbrec_binding_set_logical_datapath(binding, *logical_datapath);

                /* Add the tunnel key to the tk_hmap so that we don't try to
                 * use it for another port.  (We don't want it in the lp_hmap
                 * because that would just get the Binding record deleted
                 * later.) */
                struct binding_hash_node *hash_node
                    = xzalloc(sizeof *hash_node);
                hash_node->binding = binding;
                hmap_insert(&tk_hmap, &hash_node->tk_node,
                            hash_int(binding->tunnel_key, 0));
            }
        }
    }

    struct binding_hash_node *hash_node;
    HMAP_FOR_EACH (hash_node, lp_node, &lp_hmap) {
        hmap_remove(&lp_hmap, &hash_node->lp_node);
        sbrec_binding_delete(hash_node->binding);
    }
    hmap_destroy(&lp_hmap);

    struct binding_hash_node *hash_node_next;
    HMAP_FOR_EACH_SAFE (hash_node, hash_node_next, tk_node, &tk_hmap) {
        hmap_remove(&tk_hmap, &hash_node->tk_node);
        free(hash_node);
    }
    hmap_destroy(&tk_hmap);
}

static void
ovnnb_db_changed(struct northd_context *ctx)
{
    VLOG_DBG("ovn-nb db contents have changed.");

    set_bindings(ctx);
    build_pipeline(ctx);
}

/*
 * The only change we get notified about is if the 'chassis' column of the
 * 'Binding' table changes.  When this column is not empty, it means we need to
 * set the corresponding logical port as 'up' in the northbound DB.
 */
static void
ovnsb_db_changed(struct northd_context *ctx)
{
    struct hmap lports_hmap;
    const struct sbrec_binding *binding;
    const struct nbrec_logical_port *lport;

    struct lport_hash_node {
        struct hmap_node node;
        const struct nbrec_logical_port *lport;
    } *hash_node, *hash_node_next;

    VLOG_DBG("Recalculating port up states for ovn-nb db.");

    hmap_init(&lports_hmap);

    NBREC_LOGICAL_PORT_FOR_EACH(lport, ctx->ovnnb_idl) {
        hash_node = xzalloc(sizeof *hash_node);
        hash_node->lport = lport;
        hmap_insert(&lports_hmap, &hash_node->node,
                hash_string(lport->name, 0));
    }

    SBREC_BINDING_FOR_EACH(binding, ctx->ovnsb_idl) {
        lport = NULL;
        HMAP_FOR_EACH_WITH_HASH(hash_node, node,
                hash_string(binding->logical_port, 0), &lports_hmap) {
            if (!strcmp(binding->logical_port, hash_node->lport->name)) {
                lport = hash_node->lport;
                break;
            }
        }

        if (!lport) {
            /* The logical port doesn't exist for this binding.  This can
             * happen under normal circumstances when ovn-northd hasn't gotten
             * around to pruning the Binding yet. */
            continue;
        }

        if (binding->chassis && (!lport->up || !*lport->up)) {
            bool up = true;
            nbrec_logical_port_set_up(lport, &up, 1);
        } else if (!binding->chassis && (!lport->up || *lport->up)) {
            bool up = false;
            nbrec_logical_port_set_up(lport, &up, 1);
        }
    }

    HMAP_FOR_EACH_SAFE(hash_node, hash_node_next, node, &lports_hmap) {
        hmap_remove(&lports_hmap, &hash_node->node);
        free(hash_node);
    }
    hmap_destroy(&lports_hmap);
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
    struct northd_context ctx = {
        .ovnsb_txn = NULL,
    };
    bool ovnnb_changes_pending = false;
    bool ovn_changes_pending = false;
    struct unixctl_server *unixctl;
    int retval;
    bool exiting;

    fatal_ignore_sigpipe();
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_DESTINATION, VLL_WARN);
    parse_options(argc, argv);

    daemonize_start();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_northd_exit, &exiting);

    daemonize_complete();

    nbrec_init();
    sbrec_init();

    /* We want to detect all changes to the ovn-nb db. */
    ctx.ovnnb_idl = ovnnb_idl = ovsdb_idl_create(ovnnb_db,
            &nbrec_idl_class, true, true);

    /* There is only a small subset of changes to the ovn-sb db that ovn-northd
     * has to care about, so we'll enable monitoring those directly. */
    ctx.ovnsb_idl = ovnsb_idl = ovsdb_idl_create(ovnsb_db,
            &sbrec_idl_class, false, true);
    ovsdb_idl_add_table(ovnsb_idl, &sbrec_table_binding);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_binding_col_logical_port);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_binding_col_chassis);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_binding_col_mac);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_binding_col_tag);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_binding_col_parent_port);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_binding_col_logical_datapath);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_binding_col_tunnel_key);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_logical_datapath);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_logical_datapath);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_table_id);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_table_id);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_priority);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_priority);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_match);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_match);
    ovsdb_idl_add_column(ovnsb_idl, &sbrec_pipeline_col_actions);
    ovsdb_idl_omit_alert(ovnsb_idl, &sbrec_pipeline_col_actions);

    /*
     * The loop here just runs the IDL in a loop waiting for the seqno to
     * change, which indicates that the contents of the db have changed.
     *
     * If the contents of the ovn-nb db change, the mappings to the ovn-sb
     * db must be recalculated.
     *
     * If the contents of the ovn-sb db change, it means the 'up' state of
     * a port may have changed, as that's the only type of change ovn-northd is
     * watching for.
     */

    ovnnb_seqno = ovsdb_idl_get_seqno(ovnnb_idl);
    ovn_seqno = ovsdb_idl_get_seqno(ovnsb_idl);
    exiting = false;
    while (!exiting) {
        ovsdb_idl_run(ovnnb_idl);
        ovsdb_idl_run(ovnsb_idl);
        unixctl_server_run(unixctl);

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
         * This avoids the possibility of rapid updates causing ovn-northd to
         * never be able to successfully make the corresponding updates to the
         * other db.  Instead, pending changes are batched up until the next
         * time we get a chance to calculate the new state and apply it.
         */

        if (ovnnb_changes_pending && !ctx.ovnsb_txn) {
            /*
             * The OVN-nb db contents have changed, so create a transaction for
             * updating the OVN-sb DB.
             */
            ctx.ovnsb_txn = ovsdb_idl_txn_create(ctx.ovnsb_idl);
            ovsdb_idl_txn_add_comment(ctx.ovnsb_txn,
                                      "ovn-northd: northbound db changed");
            ovnnb_db_changed(&ctx);
            ovnnb_changes_pending = false;
        }

        if (ovn_changes_pending && !ctx.ovnnb_txn) {
            /*
             * The OVN-sb db contents have changed, so create a transaction for
             * updating the northbound DB.
             */
            ctx.ovnnb_txn = ovsdb_idl_txn_create(ctx.ovnnb_idl);
            ovsdb_idl_txn_add_comment(ctx.ovnnb_txn,
                                      "ovn-northd: southbound db changed");
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

        if (ctx.ovnsb_txn) {
            enum ovsdb_idl_txn_status txn_status;
            txn_status = ovsdb_idl_txn_commit(ctx.ovnsb_txn);
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
                ovsdb_idl_txn_destroy(ctx.ovnsb_txn);
                ctx.ovnsb_txn = NULL;
            }
        }

        if (ovnnb_seqno == ovsdb_idl_get_seqno(ovnnb_idl) &&
                ovn_seqno == ovsdb_idl_get_seqno(ovnsb_idl)) {
            ovsdb_idl_wait(ovnnb_idl);
            ovsdb_idl_wait(ovnsb_idl);
            if (ctx.ovnnb_txn) {
                ovsdb_idl_txn_wait(ctx.ovnnb_txn);
            }
            if (ctx.ovnsb_txn) {
                ovsdb_idl_txn_wait(ctx.ovnsb_txn);
            }
            unixctl_server_wait(unixctl);
            if (exiting) {
                poll_immediate_wake();
            }
            poll_block();
        }
    }

    unixctl_server_destroy(unixctl);
    ovsdb_idl_destroy(ovnsb_idl);
    ovsdb_idl_destroy(ovnnb_idl);

    exit(res);
}

static void
ovn_northd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}
