/*
 * Copyright (c) 2016, 2017 Nicira, Inc.
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

#include <getopt.h>

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "flow.h"
#include "nx-match.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn/actions.h"
#include "ovn/expr.h"
#include "ovn/lex.h"
#include "ovn/lib/acl-log.h"
#include "ovn/lib/logical-fields.h"
#include "ovn/lib/ovn-l7.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn/lib/ovn-util.h"
#include "ovsdb-idl.h"
#include "openvswitch/poll-loop.h"
#include "stream-ssl.h"
#include "stream.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ovntrace);

/* --db: The database server to contact. */
static const char *db;

/* --unixctl-path: Path to use for unixctl server, for "monitor" and "snoop"
     commands. */
static char *unixctl_path;

/* The southbound database. */
static struct ovsdb_idl *ovnsb_idl;

/* --detailed: Show a detailed, table-by-table trace. */
static bool detailed;

/* --summary: Show a trace that omits table information. */
static bool summary;

/* --minimal: Show a trace with only minimal information. */
static bool minimal;

/* --ovs: OVS instance to contact to get OpenFlow flows. */
static const char *ovs;
static struct vconn *vconn;

/* --ct: Connection tracking state to use for ct_next() actions. */
static uint32_t *ct_states;
static size_t n_ct_states;
static size_t ct_state_idx;

/* --friendly-names, --no-friendly-names: Whether to substitute human-friendly
 * port and datapath names for the awkward UUIDs typically used in the actual
 * logical flows. */
static bool use_friendly_names = true;

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);
static char *trace(const char *datapath, const char *flow);
static void read_db(void);
static unixctl_cb_func ovntrace_exit;
static unixctl_cb_func ovntrace_trace;

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    fatal_ignore_sigpipe();
    vlog_set_levels_from_string_assert("reconnect:warn");

    /* Parse command line. */
    parse_options(argc, argv);
    argc -= optind;
    argv += optind;

    if (get_detach()) {
        if (argc != 0) {
            ovs_fatal(0, "non-option arguments not supported with --detach "
                      "(use --help for help)");
        }
    } else {
        if (argc != 2) {
            ovs_fatal(0, "exactly two non-option arguments are required "
                      "(use --help for help)");
        }
    }

    struct unixctl_server *server = NULL;
    bool exiting = false;
    if (get_detach()) {
        daemonize_start(false);
        int error = unixctl_server_create(unixctl_path, &server);
        if (error) {
            ovs_fatal(error, "failed to create unixctl server");
        }
        unixctl_command_register("exit", "", 0, 0, ovntrace_exit, &exiting);
        unixctl_command_register("trace", "[OPTIONS] DATAPATH MICROFLOW",
                                 2, INT_MAX, ovntrace_trace, NULL);
    }
    ovnsb_idl = ovsdb_idl_create(db, &sbrec_idl_class, true, false);

    bool already_read = false;
    for (;;) {
        ovsdb_idl_run(ovnsb_idl);
        unixctl_server_run(server);
        if (!ovsdb_idl_is_alive(ovnsb_idl)) {
            int retval = ovsdb_idl_get_last_error(ovnsb_idl);
            ovs_fatal(0, "%s: database connection failed (%s)",
                      db, ovs_retval_to_string(retval));
        }

        if (ovsdb_idl_has_ever_connected(ovnsb_idl)) {
            if (!already_read) {
                already_read = true;
                read_db();
            }

            daemonize_complete();
            if (!get_detach()) {
                char *output = trace(argv[0], argv[1]);
                fputs(output, stdout);
                free(output);
                return 0;
            }
        }

        if (exiting) {
            break;
        }
        ovsdb_idl_wait(ovnsb_idl);
        unixctl_server_wait(server);
        poll_block();
    }
}

static char *
default_ovs(void)
{
    return xasprintf("unix:%s/br-int.mgmt", ovs_rundir());
}

static void
parse_ct_option(const char *state_s_)
{
    uint32_t state;
    struct ds ds = DS_EMPTY_INITIALIZER;

    if (!parse_ct_state(state_s_, CS_TRACKED, &state, &ds)) {
        ovs_fatal(0, "%s", ds_cstr(&ds));
    }
    if (!validate_ct_state(state, &ds)) {
        VLOG_WARN("%s", ds_cstr(&ds));
    }
    ds_destroy(&ds);

    ct_states = xrealloc(ct_states, (n_ct_states + 1) * sizeof *ct_states);
    ct_states[n_ct_states++] = state;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_DB = UCHAR_MAX + 1,
        OPT_UNIXCTL,
        OPT_DETAILED,
        OPT_SUMMARY,
        OPT_MINIMAL,
        OPT_ALL,
        OPT_OVS,
        OPT_CT,
        OPT_FRIENDLY_NAMES,
        OPT_NO_FRIENDLY_NAMES,
        DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"db", required_argument, NULL, OPT_DB},
        {"unixctl", required_argument, NULL, OPT_UNIXCTL},
        {"detailed", no_argument, NULL, OPT_DETAILED},
        {"summary", no_argument, NULL, OPT_SUMMARY},
        {"minimal", no_argument, NULL, OPT_MINIMAL},
        {"all", no_argument, NULL, OPT_ALL},
        {"ovs", optional_argument, NULL, OPT_OVS},
        {"ct", required_argument, NULL, OPT_CT},
        {"friendly-names", no_argument, NULL, OPT_FRIENDLY_NAMES},
        {"no-friendly-names", no_argument, NULL, OPT_NO_FRIENDLY_NAMES},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int idx;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, &idx);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_DB:
            db = optarg;
            break;

        case OPT_UNIXCTL:
            unixctl_path = optarg;
            break;

        case OPT_DETAILED:
            detailed = true;
            break;

        case OPT_SUMMARY:
            summary = true;
            break;

        case OPT_MINIMAL:
            minimal = true;
            break;

        case OPT_ALL:
            detailed = summary = minimal = true;
            break;

        case OPT_OVS:
            ovs = optarg ? optarg : default_ovs();
            break;

        case OPT_CT:
            parse_ct_option(optarg);
            break;

        case OPT_FRIENDLY_NAMES:
            use_friendly_names = true;
            break;

        case OPT_NO_FRIENDLY_NAMES:
            use_friendly_names = false;
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            printf("DB Schema %s\n", sbrec_get_db_version());
            exit(EXIT_SUCCESS);

        DAEMON_OPTION_HANDLERS
        VLOG_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    if (!db) {
        db = default_sb_db();
    }

    if (!detailed && !summary && !minimal) {
        detailed = true;
    }
}

static void
usage(void)
{
    printf("\
%s: OVN trace utility\n\
usage: %s [OPTIONS] DATAPATH MICROFLOW\n\
       %s [OPTIONS] --detach\n\
\n\
Output format options:\n\
  --detailed              table-by-table \"backtrace\" (default)\n\
  --summary               less detailed, more parseable\n\
  --minimal               minimum to explain externally visible behavior\n\
  --all                   provide all forms of output\n\
Output style options:\n\
  --no-friendly-names     do not substitute human friendly names for UUIDs\n",
           program_name, program_name, program_name);
    daemon_usage();
    vlog_usage();
    printf("\n\
Other options:\n\
  --db=DATABASE           connect to DATABASE\n\
                          (default: %s)\n\
  --ovs[=REMOTE]          obtain corresponding OpenFlow flows from REMOTE\n\
                          (default: %s)\n\
  --unixctl=SOCKET        set control socket name\n\
  -h, --help              display this help message\n\
  -V, --version           display version information\n",
           default_sb_db(), default_ovs());
    stream_usage("database", true, true, false);
    vconn_usage(true, false, false);
    exit(EXIT_SUCCESS);
}

struct ovntrace_datapath {
    struct hmap_node sb_uuid_node;
    struct uuid sb_uuid;
    struct uuid nb_uuid;
    char *name;
    char *name2;
    char *friendly_name;
    uint32_t tunnel_key;

    struct ovs_list mcgroups;   /* Contains "struct ovntrace_mcgroup"s. */

    struct ovntrace_flow **flows;
    size_t n_flows, allocated_flows;

    struct hmap mac_bindings;   /* Contains "struct ovntrace_mac_binding"s. */

    bool has_local_l3gateway;
};

struct ovntrace_port {
    struct ovntrace_datapath *dp;
    struct uuid uuid;
    char *name;
    char *name2;
    const char *friendly_name;
    char *type;
    uint16_t tunnel_key;
    struct ovntrace_port *peer; /* Patch ports only. */
    struct ovntrace_port *distributed_port; /* chassisredirect ports only. */
};

struct ovntrace_mcgroup {
    struct ovs_list list_node;  /* In struct ovntrace_datapath's 'mcgroups'. */

    struct ovntrace_datapath *dp;
    char *name;

    uint16_t tunnel_key;

    struct ovntrace_port **ports;
    size_t n_ports;
};

struct ovntrace_flow {
    struct uuid uuid;
    enum ovnact_pipeline pipeline;
    int table_id;
    char *stage_name;
    char *source;
    int priority;
    char *match_s;
    struct expr *match;
    struct ovnact *ovnacts;
    size_t ovnacts_len;
};

struct ovntrace_mac_binding {
    struct hmap_node node;
    uint16_t port_key;
    struct in6_addr ip;
    struct eth_addr mac;
};

static inline uint32_t
hash_mac_binding(uint16_t port_key, const struct in6_addr *ip)
{
    return hash_bytes(ip, sizeof *ip, port_key);
}

/* Every ovntrace_datapath, by southbound Datapath_Binding record UUID. */
static struct hmap datapaths;

/* Every ovntrace_port, by name. */
static struct shash ports;

/* Symbol table for expressions and actions. */
static struct shash symtab;

/* Address sets. */
static struct shash address_sets;

/* Port groups. */
static struct shash port_groups;

/* DHCP options. */
static struct hmap dhcp_opts;   /* Contains "struct gen_opts_map"s. */
static struct hmap dhcpv6_opts; /* Contains "struct gen_opts_map"s. */
static struct hmap nd_ra_opts; /* Contains "struct gen_opts_map"s. */

static struct ovntrace_datapath *
ovntrace_datapath_find_by_sb_uuid(const struct uuid *sb_uuid)
{
    struct ovntrace_datapath *dp;
    HMAP_FOR_EACH_WITH_HASH (dp, sb_uuid_node, uuid_hash(sb_uuid),
                             &datapaths) {
        if (uuid_equals(&dp->sb_uuid, sb_uuid)) {
            return dp;
        }
    }
    return NULL;
}

static const struct ovntrace_datapath *
ovntrace_datapath_find_by_name(const char *name)
{
    struct ovntrace_datapath *dp;
    HMAP_FOR_EACH (dp, sb_uuid_node, &datapaths) {
        if (!strcmp(name, dp->name)
            || (dp->name2 && !strcmp(name, dp->name2))) {
            return dp;
        }
    }

    struct ovntrace_datapath *match = NULL;
    HMAP_FOR_EACH (dp, sb_uuid_node, &datapaths) {
        if (uuid_is_partial_match(&dp->sb_uuid, name) >= 4 ||
            uuid_is_partial_match(&dp->nb_uuid, name) >= 4) {
            if (match) {
                VLOG_WARN("name \"%s\" matches multiple datapaths", name);
                return NULL;
            }
            match = dp;
        }
    }
    return match;
}

static const struct ovntrace_port *
ovntrace_port_find_by_key(const struct ovntrace_datapath *dp,
                          uint16_t tunnel_key)
{
    const struct shash_node *node;
    SHASH_FOR_EACH (node, &ports) {
        const struct ovntrace_port *port = node->data;
        if (port->dp == dp && port->tunnel_key == tunnel_key) {
            return port;
        }
    }
    return NULL;
}

static const char *
ovntrace_port_key_to_name(const struct ovntrace_datapath *dp,
                          uint16_t key)
{
    const struct ovntrace_port *port = ovntrace_port_find_by_key(dp, key);
    return (port ? port->friendly_name
            : !key ? ""
            : "(unnamed)");
}

static const struct ovntrace_mcgroup *
ovntrace_mcgroup_find_by_key(const struct ovntrace_datapath *dp,
                             uint16_t tunnel_key)
{
    const struct ovntrace_mcgroup *mcgroup;
    LIST_FOR_EACH (mcgroup, list_node, &dp->mcgroups) {
        if (mcgroup->tunnel_key == tunnel_key) {
            return mcgroup;
        }
    }
    return NULL;
}

static const struct ovntrace_mcgroup *
ovntrace_mcgroup_find_by_name(const struct ovntrace_datapath *dp,
                              const char *name)
{
    const struct ovntrace_mcgroup *mcgroup;
    LIST_FOR_EACH (mcgroup, list_node, &dp->mcgroups) {
        if (!strcmp(mcgroup->name, name)) {
            return mcgroup;
        }
    }
    return NULL;
}

static const struct ovntrace_mac_binding *
ovntrace_mac_binding_find(const struct ovntrace_datapath *dp,
                          uint16_t port_key, const struct in6_addr *ip)
{
    const struct ovntrace_mac_binding *bind;
    HMAP_FOR_EACH_WITH_HASH (bind, node, hash_mac_binding(port_key, ip),
                             &dp->mac_bindings) {
        if (bind->port_key == port_key && ipv6_addr_equals(ip, &bind->ip)) {
            return bind;
        }
    }
    return NULL;
}

/* If 's' ends with a UUID, returns a copy of it with the UUID truncated to
 * just the first 6 characters; otherwise, returns a copy of 's'. */
static char *
shorten_uuid(const char *s)
{
    size_t len = strlen(s);
    return (len >= UUID_LEN && uuid_is_partial_string(s + (len - UUID_LEN))
            ? xmemdup0(s, len - (UUID_LEN - 6))
            : xstrdup(s));
}

static void
read_datapaths(void)
{
    hmap_init(&datapaths);
    const struct sbrec_datapath_binding *sbdb;
    SBREC_DATAPATH_BINDING_FOR_EACH (sbdb, ovnsb_idl) {
        struct ovntrace_datapath *dp = xzalloc(sizeof *dp);
        const struct smap *ids = &sbdb->external_ids;

        dp->sb_uuid = sbdb->header_.uuid;
        if (!smap_get_uuid(ids, "logical-switch", &dp->nb_uuid) &&
            !smap_get_uuid(ids, "logical-router", &dp->nb_uuid)) {
            dp->nb_uuid = dp->sb_uuid;
        }

        const char *name = smap_get(ids, "name");
        dp->name = (name
                    ? xstrdup(name)
                    : xasprintf(UUID_FMT, UUID_ARGS(&dp->nb_uuid)));

        dp->name2 = nullable_xstrdup(smap_get(ids, "name2"));
        dp->friendly_name = (!use_friendly_names
                             ? xasprintf(UUID_FMT, UUID_ARGS(&dp->nb_uuid))
                             : shorten_uuid(dp->name2 ? dp->name2 : dp->name));

        dp->tunnel_key = sbdb->tunnel_key;

        ovs_list_init(&dp->mcgroups);
        hmap_init(&dp->mac_bindings);

        hmap_insert(&datapaths, &dp->sb_uuid_node, uuid_hash(&dp->sb_uuid));
    }
}

static void
read_ports(void)
{
    shash_init(&ports);
    const struct sbrec_port_binding *sbpb;
    SBREC_PORT_BINDING_FOR_EACH (sbpb, ovnsb_idl) {
        const char *port_name = sbpb->logical_port;
        struct ovntrace_datapath *dp
            = ovntrace_datapath_find_by_sb_uuid(&sbpb->datapath->header_.uuid);
        if (!dp) {
            VLOG_WARN("logical port %s missing datapath", port_name);
            continue;
        }

        struct ovntrace_port *port = xzalloc(sizeof *port);
        if (!shash_add_once(&ports, port_name, port)) {
            VLOG_WARN("duplicate logical port name %s", port_name);
            free(port);
            continue;
        }
        port->dp = dp;
        port->uuid = sbpb->header_.uuid;
        port->name = xstrdup(port_name);
        port->type = xstrdup(sbpb->type);
        port->tunnel_key = sbpb->tunnel_key;

        port->name2 = nullable_xstrdup(smap_get(&sbpb->external_ids, "name"));
        port->friendly_name = (!use_friendly_names ? xstrdup(port->name)
                               : shorten_uuid(port->name2
                                              ? port->name2 : port->name));

        if (!strcmp(sbpb->type, "patch")) {
            const char *peer_name = smap_get(&sbpb->options, "peer");
            if (peer_name) {
                struct ovntrace_port *peer
                    = shash_find_data(&ports, peer_name);
                if (peer) {
                    port->peer = peer;
                    port->peer->peer = port;
                }
            }
        } else if (!strcmp(sbpb->type, "l3gateway")) {
            /* Treat all gateways as local for our purposes. */
            dp->has_local_l3gateway = true;
        }
    }

    SBREC_PORT_BINDING_FOR_EACH (sbpb, ovnsb_idl) {
        if (!strcmp(sbpb->type, "chassisredirect")) {
            struct ovntrace_port *port
                = shash_find_data(&ports, sbpb->logical_port);
            if (port) {
                const char *distributed_name = smap_get(&sbpb->options,
                                                       "distributed-port");
                if (distributed_name) {
                    struct ovntrace_port *distributed_port
                        = shash_find_data(&ports, distributed_name);
                    if (distributed_port && distributed_port->dp == port->dp) {
                        port->distributed_port = distributed_port;
                    }
                }
            }
        }
    }
}

static int
compare_port(const void *a_, const void *b_)
{
    struct ovntrace_port *const *ap = a_;
    struct ovntrace_port *const *bp = b_;
    const struct ovntrace_port *a = *ap;
    const struct ovntrace_port *b = *bp;

    return strcmp(a->name, b->name);
}

static void
read_mcgroups(void)
{
    const struct sbrec_multicast_group *sbmg;
    SBREC_MULTICAST_GROUP_FOR_EACH (sbmg, ovnsb_idl) {
        struct ovntrace_datapath *dp
            = ovntrace_datapath_find_by_sb_uuid(&sbmg->datapath->header_.uuid);
        if (!dp) {
            VLOG_WARN("logical multicast group %s missing datapath",
                      sbmg->name);
            continue;
        }

        struct ovntrace_mcgroup *mcgroup = xzalloc(sizeof *mcgroup);
        ovs_list_push_back(&dp->mcgroups, &mcgroup->list_node);
        mcgroup->dp = dp;
        mcgroup->tunnel_key = sbmg->tunnel_key;
        mcgroup->name = xstrdup(sbmg->name);
        mcgroup->ports = xmalloc(sbmg->n_ports * sizeof *mcgroup->ports);
        for (size_t i = 0; i < sbmg->n_ports; i++) {
            const char *port_name = sbmg->ports[i]->logical_port;
            struct ovntrace_port *p = shash_find_data(&ports, port_name);
            if (!p) {
                VLOG_WARN("missing port %s", port_name);
                continue;
            }
            if (!uuid_equals(&sbmg->ports[i]->datapath->header_.uuid,
                             &p->dp->sb_uuid)) {
                VLOG_WARN("multicast group %s in datapath %s contains "
                          "port %s outside that datapath",
                          mcgroup->name, mcgroup->dp->name, port_name);
                continue;
            }
            mcgroup->ports[mcgroup->n_ports++] = p;
        }

        /* Sort the ports in alphabetical order to make output more
         * predictable. */
        qsort(mcgroup->ports, mcgroup->n_ports, sizeof *mcgroup->ports,
              compare_port);
    }
}

static void
read_address_sets(void)
{
    shash_init(&address_sets);

    const struct sbrec_address_set *sbas;
    SBREC_ADDRESS_SET_FOR_EACH (sbas, ovnsb_idl) {
        expr_const_sets_add(&address_sets, sbas->name,
                           (const char *const *) sbas->addresses,
                           sbas->n_addresses, true);
    }
}

static void
read_port_groups(void)
{
    shash_init(&port_groups);

    const struct sbrec_port_group *sbpg;
    SBREC_PORT_GROUP_FOR_EACH (sbpg, ovnsb_idl) {
        expr_const_sets_add(&port_groups, sbpg->name,
                           (const char *const *) sbpg->ports,
                           sbpg->n_ports, false);
    }
}

static bool
ovntrace_is_chassis_resident(const void *aux OVS_UNUSED,
                             const char *port_name)
{
    if (port_name[0] == '\0') {
        return true;
    }

    const struct ovntrace_port *port = shash_find_data(&ports, port_name);
    if (port) {
        /* Since ovntrace is not chassis specific, assume any port
         * that exists is resident. */
        return true;
    }

    VLOG_WARN("%s: unknown logical port\n", port_name);
    return false;
}

static int
compare_flow(const void *a_, const void *b_)
{
    struct ovntrace_flow *const *ap = a_;
    struct ovntrace_flow *const *bp = b_;
    const struct ovntrace_flow *a = *ap;
    const struct ovntrace_flow *b = *bp;

    if (a->pipeline != b->pipeline) {
        /* Sort OVNACT_P_INGRESS before OVNACT_P_EGRESS. */
        return a->pipeline == OVNACT_P_EGRESS ? 1 : -1;
    } else if (a->table_id != b->table_id) {
        /* Sort in increasing order of table_id. */
        return a->table_id > b->table_id ? 1 : -1;
    } else if (a->priority != b->priority) {
        /* Sort in decreasing order of priority. */
        return a->priority > b->priority ? -1 : 1;
    } else {
        /* Otherwise who cares. */
        return 0;
    }
}

static char *
ovntrace_make_names_friendly(const char *in)
{
    if (!use_friendly_names) {
        return xstrdup(in);
    }

    struct ds out = DS_EMPTY_INITIALIZER;
    while (*in) {
        struct lex_token token;
        const char *start;
        const char *next;

        next = lex_token_parse(&token, in, &start);
        if (token.type == LEX_T_STRING) {
            const struct ovntrace_port *port = shash_find_data(&ports,
                                                               token.s);
            if (port) {
                ds_put_buffer(&out, in, start - in);
                json_string_escape(port->friendly_name, &out);
            } else {
                ds_put_buffer(&out, in, next - in);
            }
        } else if (token.type != LEX_T_END) {
            ds_put_buffer(&out, in, next - in);
        } else {
            break;
        }
        lex_token_destroy(&token);
        in = next;
    }
    return ds_steal_cstr(&out);
}

static void
read_flows(void)
{
    ovn_init_symtab(&symtab);

    const struct sbrec_logical_flow *sblf;
    SBREC_LOGICAL_FLOW_FOR_EACH (sblf, ovnsb_idl) {
        const struct sbrec_datapath_binding *sbdb = sblf->logical_datapath;
        struct ovntrace_datapath *dp
            = ovntrace_datapath_find_by_sb_uuid(&sbdb->header_.uuid);
        if (!dp) {
            VLOG_WARN("logical flow missing datapath");
            continue;
        }

        char *error;
        struct expr *match;
        match = expr_parse_string(sblf->match, &symtab, &address_sets,
                                  &port_groups, &error);
        if (error) {
            VLOG_WARN("%s: parsing expression failed (%s)",
                      sblf->match, error);
            free(error);
            continue;
        }

        struct ovnact_parse_params pp = {
            .symtab = &symtab,
            .dhcp_opts = &dhcp_opts,
            .dhcpv6_opts = &dhcpv6_opts,
            .nd_ra_opts = &nd_ra_opts,
            .pipeline = (!strcmp(sblf->pipeline, "ingress")
                         ? OVNACT_P_INGRESS
                         : OVNACT_P_EGRESS),
            .n_tables = 24,
            .cur_ltable = sblf->table_id,
        };
        uint64_t stub[1024 / 8];
        struct ofpbuf ovnacts = OFPBUF_STUB_INITIALIZER(stub);
        struct expr *prereqs;
        error = ovnacts_parse_string(sblf->actions, &pp, &ovnacts, &prereqs);
        if (error) {
            VLOG_WARN("%s: parsing actions failed (%s)", sblf->actions, error);
            free(error);
            expr_destroy(match);
            continue;
        }

        match = expr_combine(EXPR_T_AND, match, prereqs);
        match = expr_annotate(match, &symtab, &error);
        if (error) {
            VLOG_WARN("match annotation failed (%s)", error);
            free(error);
            expr_destroy(match);
            ovnacts_free(ovnacts.data, ovnacts.size);
            ofpbuf_uninit(&ovnacts);
            continue;
        }
        if (match) {
            match = expr_simplify(match, ovntrace_is_chassis_resident, NULL);
        }

        struct ovntrace_flow *flow = xzalloc(sizeof *flow);
        flow->uuid = sblf->header_.uuid;
        flow->pipeline = (!strcmp(sblf->pipeline, "ingress")
                          ? OVNACT_P_INGRESS
                          : OVNACT_P_EGRESS);
        flow->table_id = sblf->table_id;
        flow->stage_name = nullable_xstrdup(smap_get(&sblf->external_ids,
                                                     "stage-name"));
        flow->source = nullable_xstrdup(smap_get(&sblf->external_ids,
                                                 "source"));
        flow->priority = sblf->priority;
        flow->match_s = ovntrace_make_names_friendly(sblf->match);
        flow->match = match;
        flow->ovnacts_len = ovnacts.size;
        flow->ovnacts = ofpbuf_steal_data(&ovnacts);

        if (dp->n_flows >= dp->allocated_flows) {
            dp->flows = x2nrealloc(dp->flows, &dp->allocated_flows,
                                   sizeof *dp->flows);
        }
        dp->flows[dp->n_flows++] = flow;
    }

    const struct ovntrace_datapath *dp;
    HMAP_FOR_EACH (dp, sb_uuid_node, &datapaths) {
        qsort(dp->flows, dp->n_flows, sizeof *dp->flows, compare_flow);
    }
}

static void
read_gen_opts(void)
{
    hmap_init(&dhcp_opts);
    const struct sbrec_dhcp_options *sdo;
    SBREC_DHCP_OPTIONS_FOR_EACH (sdo, ovnsb_idl) {
        dhcp_opt_add(&dhcp_opts, sdo->name, sdo->code, sdo->type);
    }


    hmap_init(&dhcpv6_opts);
    const struct sbrec_dhcpv6_options *sdo6;
    SBREC_DHCPV6_OPTIONS_FOR_EACH(sdo6, ovnsb_idl) {
       dhcp_opt_add(&dhcpv6_opts, sdo6->name, sdo6->code, sdo6->type);
    }

    hmap_init(&nd_ra_opts);
    nd_ra_opts_init(&nd_ra_opts);
}

static void
read_mac_bindings(void)
{
    const struct sbrec_mac_binding *sbmb;
    SBREC_MAC_BINDING_FOR_EACH (sbmb, ovnsb_idl) {
        const struct ovntrace_port *port = shash_find_data(
            &ports, sbmb->logical_port);
        if (!port) {
            VLOG_WARN("missing port %s", sbmb->logical_port);
            continue;
        }

        if (!uuid_equals(&port->dp->sb_uuid, &sbmb->datapath->header_.uuid)) {
            VLOG_WARN("port %s is in wrong datapath", sbmb->logical_port);
            continue;
        }

        struct in6_addr ip6;
        ovs_be32 ip4;
        if (ip_parse(sbmb->ip, &ip4)) {
            ip6 = in6_addr_mapped_ipv4(ip4);
        } else if (!ipv6_parse(sbmb->ip, &ip6)) {
            VLOG_WARN("%s: bad IP address", sbmb->ip);
            continue;
        }

        struct eth_addr mac;
        if (!eth_addr_from_string(sbmb->mac, &mac)) {
            VLOG_WARN("%s: bad Ethernet address", sbmb->mac);
            continue;
        }

        struct ovntrace_mac_binding *binding = xmalloc(sizeof *binding);
        binding->port_key = port->tunnel_key;
        binding->ip = ip6;
        binding->mac = mac;
        hmap_insert(&port->dp->mac_bindings, &binding->node,
                    hash_mac_binding(binding->port_key, &ip6));
    }
}

static void
read_db(void)
{
    read_datapaths();
    read_ports();
    read_mcgroups();
    read_address_sets();
    read_port_groups();
    read_gen_opts();
    read_flows();
    read_mac_bindings();
}

static const struct ovntrace_port *
ovntrace_port_lookup_by_name(const char *name)
{
    const struct ovntrace_port *port = shash_find_data(&ports, name);
    if (port) {
        return port;
    }

    const struct ovntrace_port *match = NULL;

    struct shash_node *node;
    SHASH_FOR_EACH (node, &ports) {
        port = node->data;

        if (port->name2 && !strcmp(port->name2, name)) {
            if (match) {
                VLOG_WARN("name \"%s\" matches multiple ports", name);
                return NULL;
            }
            match = port;
        }
    }

    if (uuid_is_partial_string(name) >= 4) {
        SHASH_FOR_EACH (node, &ports) {
            port = node->data;

            struct uuid name_uuid;
            if (uuid_is_partial_match(&port->uuid, name)
                || (uuid_from_string(&name_uuid, port->name)
                    && uuid_is_partial_match(&name_uuid, name))) {
                if (match && match != port) {
                    VLOG_WARN("name \"%s\" matches multiple ports", name);
                    return NULL;
                }
                match = port;
            }
        }
    }

    return match;
}

static bool
ovntrace_lookup_port(const void *dp_, const char *port_name,
                     unsigned int *portp)
{
    const struct ovntrace_datapath *dp = dp_;

    if (port_name[0] == '\0') {
        *portp = 0;
        return true;
    }

    const struct ovntrace_port *port = ovntrace_port_lookup_by_name(port_name);
    if (port) {
        if (port->dp == dp) {
            *portp = port->tunnel_key;
            return true;
        }
        /* The port is found but not in this datapath. It happens when port
         * group is used in match conditions. */
        return false;
    }

    const struct ovntrace_mcgroup *mcgroup = ovntrace_mcgroup_find_by_name(dp, port_name);
    if (mcgroup) {
        *portp = mcgroup->tunnel_key;
        return true;
    }

    VLOG_WARN("%s: unknown logical port", port_name);
    return false;
}

static const struct ovntrace_flow *
ovntrace_flow_lookup(const struct ovntrace_datapath *dp,
                     const struct flow *uflow,
                     uint8_t table_id, enum ovnact_pipeline pipeline)
{
    for (size_t i = 0; i < dp->n_flows; i++) {
        const struct ovntrace_flow *flow = dp->flows[i];
        if (flow->pipeline == pipeline &&
            flow->table_id == table_id &&
            expr_evaluate(flow->match, uflow, ovntrace_lookup_port, dp)) {
            return flow;
        }
    }
    return NULL;
}

static char *
ovntrace_stage_name(const struct ovntrace_datapath *dp,
                    uint8_t table_id, enum ovnact_pipeline pipeline)
{
    for (size_t i = 0; i < dp->n_flows; i++) {
        const struct ovntrace_flow *flow = dp->flows[i];
        if (flow->pipeline == pipeline && flow->table_id == table_id) {
            return xstrdup(flow->stage_name);;
        }
    }
    return NULL;
}

/* Type of a node within a trace. */
enum ovntrace_node_type {
    /* Nodes that may have children (nonterminal nodes). */
    OVNTRACE_NODE_OUTPUT,
    OVNTRACE_NODE_MODIFY,
    OVNTRACE_NODE_ACTION,
    OVNTRACE_NODE_ERROR,

    /* Nodes that never have children (terminal nodes). */
    OVNTRACE_NODE_PIPELINE,
    OVNTRACE_NODE_TABLE,
    OVNTRACE_NODE_TRANSFORMATION
};

static bool
ovntrace_node_type_is_terminal(enum ovntrace_node_type type)
{
    switch (type) {
    case OVNTRACE_NODE_OUTPUT:
    case OVNTRACE_NODE_MODIFY:
    case OVNTRACE_NODE_ACTION:
    case OVNTRACE_NODE_ERROR:
        return true;

    case OVNTRACE_NODE_PIPELINE:
    case OVNTRACE_NODE_TABLE:
    case OVNTRACE_NODE_TRANSFORMATION:
        return false;
    }

    OVS_NOT_REACHED();
}

struct ovntrace_node {
    struct ovs_list node;       /* In parent. */

    enum ovntrace_node_type type;
    char *name;
    bool always_indent;
    struct ovs_list subs;       /* List of children. */
};

static void ovntrace_node_destroy(struct ovntrace_node *);

static struct ovntrace_node * OVS_PRINTF_FORMAT(3, 4)
ovntrace_node_append(struct ovs_list *super, enum ovntrace_node_type type,
                     const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *s = xvasprintf(format, args);
    va_end(args);

    struct ovntrace_node *node = xmalloc(sizeof *node);
    ovs_list_push_back(super, &node->node);
    node->type = type;
    node->name = s;
    node->always_indent = false;
    ovs_list_init(&node->subs);

    return node;
}

static void
ovntrace_node_clone(const struct ovs_list *old, struct ovs_list *new)
{
    const struct ovntrace_node *osub;
    LIST_FOR_EACH (osub, node, old) {
        struct ovntrace_node *nsub = ovntrace_node_append(new, osub->type,
                                                          "%s", osub->name);
        nsub->always_indent = osub->always_indent;
        ovntrace_node_clone(&osub->subs, &nsub->subs);
    }
}

static void
ovntrace_node_list_destroy(struct ovs_list *list)
{
    if (list) {
        struct ovntrace_node *node, *next;

        LIST_FOR_EACH_SAFE (node, next, node, list) {
            ovs_list_remove(&node->node);
            ovntrace_node_destroy(node);
        }
    }
}

static void
ovntrace_node_destroy(struct ovntrace_node *node)
{
    if (node) {
        ovntrace_node_list_destroy(&node->subs);
        free(node->name);
        free(node);
    }
}

static void
ovntrace_node_print_details(struct ds *output,
                            const struct ovs_list *nodes, int level)
{
    const struct ovntrace_node *sub;
    LIST_FOR_EACH (sub, node, nodes) {
        if (sub->type == OVNTRACE_NODE_MODIFY) {
            continue;
        }

        bool more = (sub->node.next != nodes
                     || sub->always_indent
                     || ovntrace_node_type_is_terminal(sub->type));
        bool title = (sub->type == OVNTRACE_NODE_PIPELINE ||
                      sub->type == OVNTRACE_NODE_TRANSFORMATION);
        if (title) {
            ds_put_char(output, '\n');
        }
        ds_put_char_multiple(output, ' ', (level + more) * 4);
        ds_put_format(output, "%s\n", sub->name);
        if (title) {
            ds_put_char_multiple(output, ' ', (level + more) * 4);
            ds_put_char_multiple(output, '-', strlen(sub->name));
            ds_put_char(output, '\n');
        }

        ovntrace_node_print_details(output, &sub->subs, level + more + more);
    }
}

static void
ovntrace_node_prune_summary(struct ovs_list *nodes)
{
    struct ovntrace_node *sub, *next;
    LIST_FOR_EACH_SAFE (sub, next, node, nodes) {
        ovntrace_node_prune_summary(&sub->subs);
        if (sub->type == OVNTRACE_NODE_MODIFY ||
            sub->type == OVNTRACE_NODE_TABLE) {
            /* Replace 'sub' by its children, if any, */
            ovs_list_remove(&sub->node);
            ovs_list_splice(&next->node, sub->subs.next, &sub->subs);
            ovntrace_node_destroy(sub);
        }
    }
}

static void
ovntrace_node_print_summary(struct ds *output, const struct ovs_list *nodes,
                            int level)
{
    const struct ovntrace_node *sub;
    LIST_FOR_EACH (sub, node, nodes) {
        if (sub->type == OVNTRACE_NODE_ACTION
            && !strncmp(sub->name, "next(", 5)) {
            continue;
        }

        ds_put_char_multiple(output, ' ', level * 4);
        ds_put_cstr(output, sub->name);
        if (!ovs_list_is_empty(&sub->subs)) {
            ds_put_cstr(output, " {\n");
            ovntrace_node_print_summary(output, &sub->subs, level + 1);
            ds_put_char_multiple(output, ' ', level * 4);
            ds_put_char(output, '}');
        }
        if (sub->type != OVNTRACE_NODE_ACTION) {
            ds_put_char(output, ';');
        }
        ds_put_char(output, '\n');
    }
}

static void
ovntrace_node_prune_hard(struct ovs_list *nodes)
{
    struct ovntrace_node *sub, *next;
    LIST_FOR_EACH_SAFE (sub, next, node, nodes) {
        ovntrace_node_prune_hard(&sub->subs);
        if (sub->type == OVNTRACE_NODE_ACTION ||
            sub->type == OVNTRACE_NODE_PIPELINE ||
            sub->type == OVNTRACE_NODE_TABLE ||
            sub->type == OVNTRACE_NODE_OUTPUT) {
            /* Replace 'sub' by its children, if any, */
            ovs_list_remove(&sub->node);
            ovs_list_splice(&next->node, sub->subs.next, &sub->subs);
            ovntrace_node_destroy(sub);
        }
    }
}

static void
execute_load(const struct ovnact_load *load,
             const struct ovntrace_datapath *dp, struct flow *uflow,
             struct ovs_list *super OVS_UNUSED)
{
    const struct ovnact_encode_params ep = {
        .lookup_port = ovntrace_lookup_port,
        .aux = dp,
    };
    uint64_t stub[512 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);

    ovnacts_encode(&load->ovnact, sizeof *load, &ep, &ofpacts);

    struct ofpact *a;
    OFPACT_FOR_EACH (a, ofpacts.data, ofpacts.size) {
        struct ofpact_set_field *sf = ofpact_get_SET_FIELD(a);

        if (!mf_is_register(sf->field->id)) {
            struct ds s = DS_EMPTY_INITIALIZER;
            ovnacts_format(&load->ovnact, OVNACT_LOAD_SIZE, &s);
            ds_chomp(&s, ';');

            char *friendly = ovntrace_make_names_friendly(ds_cstr(&s));
            ovntrace_node_append(super, OVNTRACE_NODE_MODIFY, "%s", friendly);
            free(friendly);

            ds_destroy(&s);
        }

        if (mf_are_prereqs_ok(sf->field, uflow, NULL)) {
            mf_set_flow_value_masked(sf->field, sf->value,
                                     ofpact_set_field_mask(sf), uflow);
        }
    }
    ofpbuf_uninit(&ofpacts);
}

static void
summarize_move(const struct mf_subfield *rsrc,
               const struct expr_field *dst, const struct mf_subfield *rdst,
               const struct flow *uflow, struct ovs_list *super OVS_UNUSED)
{
    if (!mf_is_register(rdst->field->id)) {
        struct ds s = DS_EMPTY_INITIALIZER;
        expr_field_format(dst, &s);
        ds_put_cstr(&s, " = ");

        if (rsrc->ofs == 0 && rsrc->n_bits >= rsrc->field->n_bits) {
            union mf_value value;
            mf_get_value(rsrc->field, uflow, &value);
            mf_format(rsrc->field, &value, NULL, NULL, &s);
        } else {
            union mf_subvalue cst;
            mf_read_subfield(rsrc, uflow, &cst);
            ds_put_hex(&s, &cst, sizeof cst);
        }

        ovntrace_node_append(super, OVNTRACE_NODE_MODIFY, "%s", ds_cstr(&s));

        ds_destroy(&s);
    }
}

static void
execute_move(const struct ovnact_move *move, struct flow *uflow,
             struct ovs_list *super)
{
    struct mf_subfield dst = expr_resolve_field(&move->lhs);
    struct mf_subfield src = expr_resolve_field(&move->rhs);
    summarize_move(&src, &move->lhs, &dst, uflow, super);
    mf_subfield_copy(&src, &dst, uflow, NULL);
}

static void
execute_exchange(const struct ovnact_move *move, struct flow *uflow,
             struct ovs_list *super)
{
    struct mf_subfield a = expr_resolve_field(&move->lhs);
    struct mf_subfield b = expr_resolve_field(&move->rhs);
    summarize_move(&b, &move->lhs, &a, uflow, super);
    summarize_move(&a, &move->rhs, &b, uflow, super);
    mf_subfield_swap(&a, &b, uflow, NULL);
}

static void
trace__(const struct ovntrace_datapath *dp, struct flow *uflow,
        uint8_t table_id, enum ovnact_pipeline pipeline,
        struct ovs_list *super);

static void
trace_actions(const struct ovnact *ovnacts, size_t ovnacts_len,
              const struct ovntrace_datapath *dp, struct flow *uflow,
              uint8_t table_id, enum ovnact_pipeline pipeline,
              struct ovs_list *super);
static void
execute_output(const struct ovntrace_datapath *dp, struct flow *uflow,
               enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    uint16_t key = uflow->regs[MFF_LOG_OUTPORT - MFF_REG0];
    if (!key) {
        ovntrace_node_append(super, OVNTRACE_NODE_ERROR,
                             "*** output to null logical port");
        return;
    }

    const struct ovntrace_port *port = ovntrace_port_find_by_key(dp, key);
    const struct ovntrace_mcgroup *mcgroup = ovntrace_mcgroup_find_by_key(dp,
                                                                          key);
    const char *out_name = (port ? port->friendly_name
                            : mcgroup ? mcgroup->name
                            : "(unnamed)");
    if (!port && !mcgroup) {
        ovntrace_node_append(super, OVNTRACE_NODE_ERROR,
                             "*** unknown port or multicast group %"PRIu16,
                             key);
    }

    if (pipeline == OVNACT_P_EGRESS) {
        ovntrace_node_append(super, OVNTRACE_NODE_OUTPUT,
                             "/* output to \"%s\", type \"%s\" */",
                             out_name, port ? port->type : "");
        if (port && port->peer) {
            const struct ovntrace_port *peer = port->peer;

            struct ovntrace_node *node = ovntrace_node_append(
                super, OVNTRACE_NODE_PIPELINE,
                "ingress(dp=\"%s\", inport=\"%s\")",
                peer->dp->friendly_name, peer->friendly_name);

            struct flow new_uflow = *uflow;
            new_uflow.regs[MFF_LOG_INPORT - MFF_REG0] = peer->tunnel_key;
            new_uflow.regs[MFF_LOG_OUTPORT - MFF_REG0] = 0;
            trace__(peer->dp, &new_uflow, 0, OVNACT_P_INGRESS, &node->subs);
        } else {
            ovntrace_node_append(super, OVNTRACE_NODE_MODIFY,
                                 "output(\"%s\")", out_name);

        }
        return;
    }

    struct flow egress_uflow = *uflow;
    for (int i = 0; i < FLOW_N_REGS; i++) {
        if (i != MFF_LOG_INPORT - MFF_REG0 &&
            i != MFF_LOG_OUTPORT - MFF_REG0) {
            egress_uflow.regs[i] = 0;
        }
    }

    uint16_t in_key = uflow->regs[MFF_LOG_INPORT - MFF_REG0];
    const char *inport_name = ovntrace_port_key_to_name(dp, in_key);
    uint32_t flags = uflow->regs[MFF_LOG_FLAGS - MFF_REG0];
    bool allow_loopback = (flags & MLF_ALLOW_LOOPBACK) != 0;

    if (mcgroup) {
        struct ovntrace_node *mcnode = ovntrace_node_append(
            super, OVNTRACE_NODE_PIPELINE,
            "multicast(dp=\"%s\", mcgroup=\"%s\")",
            dp->friendly_name, mcgroup->name);
        for (size_t i = 0; i < mcgroup->n_ports; i++) {
            const struct ovntrace_port *p = mcgroup->ports[i];

            struct ovntrace_node *node = ovntrace_node_append(
                &mcnode->subs, OVNTRACE_NODE_PIPELINE,
                "egress(dp=\"%s\", inport=\"%s\", outport=\"%s\")",
                dp->friendly_name, inport_name, p->friendly_name);

            if (p->tunnel_key != in_key || allow_loopback) {
                node->always_indent = true;

                egress_uflow.regs[MFF_LOG_OUTPORT - MFF_REG0] = p->tunnel_key;
                trace__(dp, &egress_uflow, 0, OVNACT_P_EGRESS, &node->subs);
            } else {
                ovntrace_node_append(&node->subs, OVNTRACE_NODE_OUTPUT,
                                     "/* omitting output because inport == outport && !flags.loopback */");
            }
        }
        return;
    }

    if (port && !strcmp(port->type, "chassisredirect")) {
        if (port->distributed_port) {
            ovntrace_node_append(super, OVNTRACE_NODE_OUTPUT,
                                 "/* Replacing type \"%s\" outport \"%s\""
                                 " with distributed port \"%s\". */",
                                 port->type, port->friendly_name,
                                 port->distributed_port->friendly_name);
            port = port->distributed_port;
            out_name = port->friendly_name;
            egress_uflow.regs[MFF_LOG_OUTPORT - MFF_REG0] = port->tunnel_key;
        } else {
            ovntrace_node_append(super, OVNTRACE_NODE_ERROR,
                                 "*** output to type \"%s\" port \"%s\""
                                 " with no or invalid distributed port",
                                 port->type, out_name);
            return;
        }
    }

    if ((port && port->tunnel_key != in_key) || allow_loopback) {
        struct ovntrace_node *node = ovntrace_node_append(
            super, OVNTRACE_NODE_PIPELINE,
            "egress(dp=\"%s\", inport=\"%s\", outport=\"%s\")",
            dp->friendly_name, inport_name, out_name);

        trace__(dp, &egress_uflow, 0, OVNACT_P_EGRESS, &node->subs);
    } else {
        ovntrace_node_append(super, OVNTRACE_NODE_OUTPUT,
                             "/* omitting output because inport == outport && !flags.loopback */");
    }
}

static void
execute_clone(const struct ovnact_nest *on, const struct ovntrace_datapath *dp,
              const struct flow *uflow, uint8_t table_id,
              enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    struct flow cloned_flow = *uflow;

    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TRANSFORMATION, "clone");

    trace_actions(on->nested, on->nested_len, dp, &cloned_flow,
                  table_id, pipeline, &node->subs);
}

static void
execute_arp(const struct ovnact_nest *on, const struct ovntrace_datapath *dp,
            const struct flow *uflow, uint8_t table_id,
            enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    struct flow arp_flow = *uflow;

    /* Zero fields that are no longer relevant. */
    arp_flow.nw_frag = 0;
    arp_flow.nw_tos = 0;
    arp_flow.nw_ttl = 0;
    arp_flow.tcp_flags = 0;

    /* Update fields for ARP. */
    arp_flow.dl_type = htons(ETH_TYPE_ARP);
    arp_flow.nw_proto = ARP_OP_REQUEST;
    arp_flow.arp_sha = arp_flow.dl_src;
    arp_flow.arp_tha = eth_addr_zero;
    /* ARP SPA is already in arp_flow.nw_src. */
    /* ARP TPA is already in arp_flow.nw_dst. */

    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TRANSFORMATION, "arp");

    trace_actions(on->nested, on->nested_len, dp, &arp_flow,
                  table_id, pipeline, &node->subs);
}

static void
execute_nd_na(const struct ovnact_nest *on, const struct ovntrace_datapath *dp,
              const struct flow *uflow, uint8_t table_id,
              enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    struct flow na_flow = *uflow;

    /* Update fields for NA. */
    na_flow.dl_src = uflow->dl_dst;
    na_flow.dl_dst = uflow->dl_src;
    na_flow.ipv6_dst = uflow->ipv6_src;
    na_flow.ipv6_src = uflow->nd_target;
    na_flow.tp_src = htons(136);
    na_flow.arp_sha = eth_addr_zero;
    na_flow.arp_tha = uflow->dl_dst;

    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TRANSFORMATION, "nd_na");

    trace_actions(on->nested, on->nested_len, dp, &na_flow,
                  table_id, pipeline, &node->subs);
}

static void
execute_nd_ns(const struct ovnact_nest *on, const struct ovntrace_datapath *dp,
              const struct flow *uflow, uint8_t table_id,
              enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    struct flow na_flow = *uflow;

    /* Update fields for NA. */
    na_flow.dl_src = uflow->dl_src;
    na_flow.ipv6_src = uflow->ipv6_src;
    na_flow.ipv6_dst = uflow->ipv6_dst;
    struct in6_addr sn_addr;
    in6_addr_solicited_node(&sn_addr, &uflow->ipv6_dst);
    ipv6_multicast_to_ethernet(&na_flow.dl_dst, &sn_addr);
    na_flow.tp_src = htons(135);
    na_flow.arp_sha = eth_addr_zero;
    na_flow.arp_tha = uflow->dl_dst;

    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TRANSFORMATION, "nd_ns");

    trace_actions(on->nested, on->nested_len, dp, &na_flow,
                  table_id, pipeline, &node->subs);
}

static void
execute_icmp4(const struct ovnact_nest *on,
              const struct ovntrace_datapath *dp,
              const struct flow *uflow, uint8_t table_id,
              enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    struct flow icmp4_flow = *uflow;

    /* Update fields for ICMP. */
    icmp4_flow.dl_dst = uflow->dl_dst;
    icmp4_flow.dl_src = uflow->dl_src;
    icmp4_flow.nw_dst = uflow->nw_dst;
    icmp4_flow.nw_src = uflow->nw_src;
    icmp4_flow.nw_proto = IPPROTO_ICMP;
    icmp4_flow.nw_ttl = 255;
    icmp4_flow.tp_src = htons(ICMP4_DST_UNREACH); /* icmp type */
    icmp4_flow.tp_dst = htons(1); /* icmp code */

    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TRANSFORMATION, "icmp4");

    trace_actions(on->nested, on->nested_len, dp, &icmp4_flow,
                  table_id, pipeline, &node->subs);
}

static void
execute_icmp6(const struct ovnact_nest *on,
              const struct ovntrace_datapath *dp,
              const struct flow *uflow, uint8_t table_id,
              enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    struct flow icmp6_flow = *uflow;

    /* Update fields for ICMPv6. */
    icmp6_flow.dl_dst = uflow->dl_dst;
    icmp6_flow.dl_src = uflow->dl_src;
    icmp6_flow.ipv6_dst = uflow->ipv6_dst;
    icmp6_flow.ipv6_src = uflow->ipv6_src;
    icmp6_flow.nw_proto = IPPROTO_ICMPV6;
    icmp6_flow.nw_ttl = 255;
    icmp6_flow.tp_src = htons(ICMP6_DST_UNREACH); /* icmp type */
    icmp6_flow.tp_dst = htons(1); /* icmp code */

    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TRANSFORMATION, "icmp6");

    trace_actions(on->nested, on->nested_len, dp, &icmp6_flow,
                  table_id, pipeline, &node->subs);
}

static void
execute_tcp_reset(const struct ovnact_nest *on,
                  const struct ovntrace_datapath *dp,
                  const struct flow *uflow, uint8_t table_id,
                  enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    struct flow tcp_flow = *uflow;

    /* Update fields for TCP segment. */
    tcp_flow.dl_dst = uflow->dl_dst;
    tcp_flow.dl_src = uflow->dl_src;
    tcp_flow.nw_dst = uflow->nw_dst;
    tcp_flow.nw_src = uflow->nw_src;
    tcp_flow.nw_proto = IPPROTO_TCP;
    tcp_flow.nw_ttl = 255;
    tcp_flow.tp_src = uflow->tp_src;
    tcp_flow.tp_dst = uflow->tp_dst;
    tcp_flow.tcp_flags = htons(TCP_RST);

    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TRANSFORMATION, "tcp_reset");

    trace_actions(on->nested, on->nested_len, dp, &tcp_flow,
                  table_id, pipeline, &node->subs);
}

static void
execute_get_mac_bind(const struct ovnact_get_mac_bind *bind,
                     const struct ovntrace_datapath *dp,
                     struct flow *uflow, struct ovs_list *super)
{
    /* Get logical port number.*/
    struct mf_subfield port_sf = expr_resolve_field(&bind->port);
    ovs_assert(port_sf.n_bits == 32);
    uint32_t port_key = mf_get_subfield(&port_sf, uflow);

    /* Get IP address. */
    struct mf_subfield ip_sf = expr_resolve_field(&bind->ip);
    ovs_assert(ip_sf.n_bits == 32 || ip_sf.n_bits == 128);
    union mf_subvalue ip_sv;
    mf_read_subfield(&ip_sf, uflow, &ip_sv);
    struct in6_addr ip = (ip_sf.n_bits == 32
                          ? in6_addr_mapped_ipv4(ip_sv.ipv4)
                          : ip_sv.ipv6);

    const struct ovntrace_mac_binding *binding
        = ovntrace_mac_binding_find(dp, port_key, &ip);

    uflow->dl_dst = binding ? binding->mac : eth_addr_zero;
    if (binding) {
        ovntrace_node_append(super, OVNTRACE_NODE_ACTION,
                             "/* MAC binding to "ETH_ADDR_FMT". */",
                             ETH_ADDR_ARGS(uflow->dl_dst));
    } else {
        ovntrace_node_append(super, OVNTRACE_NODE_ACTION,
                             "/* No MAC binding. */");
    }
    ovntrace_node_append(super, OVNTRACE_NODE_MODIFY,
                         "eth.dst = "ETH_ADDR_FMT,
                         ETH_ADDR_ARGS(uflow->dl_dst));
}

static void
execute_put_opts(const struct ovnact_put_opts *po,
                 const char *name, struct flow *uflow,
                 struct ovs_list *super)
{
    /* Format the put_dhcp_opts action. */
    struct ds s = DS_EMPTY_INITIALIZER;
    for (const struct ovnact_gen_option *o = po->options;
         o < &po->options[po->n_options]; o++) {
        if (o != po->options) {
            ds_put_cstr(&s, ", ");
        }
        ds_put_format(&s, "%s = ", o->option->name);
        expr_constant_set_format(&o->value, &s);
    }
    ovntrace_node_append(super, OVNTRACE_NODE_MODIFY, "%s(%s)",
                         name, ds_cstr(&s));

    struct mf_subfield dst = expr_resolve_field(&po->dst);
    if (!mf_is_register(dst.field->id)) {
        /* Format assignment. */
        ds_clear(&s);
        expr_field_format(&po->dst, &s);
        ovntrace_node_append(super, OVNTRACE_NODE_MODIFY,
                             "%s = 1", ds_cstr(&s));
    }
    ds_destroy(&s);

    struct mf_subfield sf = expr_resolve_field(&po->dst);
    union mf_subvalue sv = { .u8_val = 1 };
    mf_write_subfield_flow(&sf, &sv, uflow);
}

static void
execute_put_dhcp_opts(const struct ovnact_put_opts *pdo,
                      const char *name, struct flow *uflow,
                      struct ovs_list *super)
{
    ovntrace_node_append(
        super, OVNTRACE_NODE_ERROR,
        "/* We assume that this packet is DHCPDISCOVER or DHCPREQUEST. */");
    execute_put_opts(pdo, name, uflow, super);
}

static void
execute_put_nd_ra_opts(const struct ovnact_put_opts *pdo,
                       const char *name, struct flow *uflow,
                       struct ovs_list *super)
{
    execute_put_opts(pdo, name, uflow, super);
}

static void
execute_next(const struct ovnact_next *next,
             const struct ovntrace_datapath *dp, struct flow *uflow,
             enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    if (pipeline != next->pipeline) {
        ovs_assert(next->pipeline == OVNACT_P_INGRESS);

        uint16_t in_key = uflow->regs[MFF_LOG_INPORT - MFF_REG0];
        struct ovntrace_node *node = ovntrace_node_append(
            super, OVNTRACE_NODE_PIPELINE, "ingress(dp=\"%s\", inport=\"%s\")",
            dp->friendly_name, ovntrace_port_key_to_name(dp, in_key));
        super = &node->subs;
    }
    trace__(dp, uflow, next->ltable, next->pipeline, super);
}


static void
execute_dns_lookup(const struct ovnact_dns_lookup *dl, struct flow *uflow,
                   struct ovs_list *super)
{
    struct mf_subfield sf = expr_resolve_field(&dl->dst);
    union mf_subvalue sv = { .u8_val = 0 };
    mf_write_subfield_flow(&sf, &sv, uflow);
    ovntrace_node_append(super, OVNTRACE_NODE_ERROR,
                         "*** dns_lookup action not implemented");
}

static void
execute_ct_next(const struct ovnact_ct_next *ct_next,
                const struct ovntrace_datapath *dp, struct flow *uflow,
                enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    /* Figure out ct_state. */
    uint32_t state;
    const char *comment;
    if (ct_state_idx < n_ct_states) {
        state = ct_states[ct_state_idx++];
        comment = "";
    } else {
        state = CS_ESTABLISHED | CS_TRACKED;
        comment = " /* default (use --ct to customize) */";
    }

    /* Make a sub-node for attaching the next table. */
    struct ds s = DS_EMPTY_INITIALIZER;
    format_flags(&s, ct_state_to_string, state, '|');
    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TRANSFORMATION, "ct_next(ct_state=%s%s)",
        ds_cstr(&s), comment);
    ds_destroy(&s);

    /* Trace the actions in the next table. */
    struct flow ct_flow = *uflow;
    ct_flow.ct_state = state;
    trace__(dp, &ct_flow, ct_next->ltable, pipeline, &node->subs);

    /* Upon return, we will trace the actions following the ct action in the
     * original table.  The pipeline forked, so we're using the original
     * flow, not ct_flow. */
}

static void
execute_ct_nat(const struct ovnact_ct_nat *ct_nat,
               const struct ovntrace_datapath *dp, struct flow *uflow,
               enum ovnact_pipeline pipeline, struct ovs_list *super)
{
    bool is_dst = ct_nat->ovnact.type == OVNACT_CT_DNAT;
    if (!is_dst && dp->has_local_l3gateway && !ct_nat->ip) {
        /* "ct_snat;" has no visible effect in a gateway router. */
        return;
    }
    const char *direction = is_dst ? "dst" : "src";

    /* Make a sub-node for attaching the next table,
     * and figure out the changes if any. */
    struct flow ct_flow = *uflow;
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "ct_%cnat", direction[0]);
    if (ct_nat->ip) {
        ds_put_format(&s, "(ip4.%s="IP_FMT")", direction, IP_ARGS(ct_nat->ip));
        ovs_be32 *ip = is_dst ? &ct_flow.nw_dst : &ct_flow.nw_src;
        *ip = ct_nat->ip;

        uint8_t state = is_dst ? CS_DST_NAT : CS_SRC_NAT;
        ct_flow.ct_state |= state;
    } else {
        ds_put_format(&s, " /* assuming no un-%cnat entry, so no change */",
                      direction[0]);
    }
    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TRANSFORMATION, "%s", ds_cstr(&s));
    ds_destroy(&s);

    /* Trace the actions in the next table. */
    trace__(dp, &ct_flow, ct_nat->ltable, pipeline, &node->subs);

    /* Upon return, we will trace the actions following the ct action in the
     * original table.  The pipeline forked, so we're using the original
     * flow, not ct_flow. */
}

static void
execute_log(const struct ovnact_log *log, struct flow *uflow,
            struct ovs_list *super)
{
    char *packet_str = flow_to_string(uflow, NULL);
    ovntrace_node_append(super, OVNTRACE_NODE_TRANSFORMATION,
                    "LOG: ACL name=%s, verdict=%s, severity=%s, packet=\"%s\"",
                    log->name ? log->name : "<unnamed>",
                    log_verdict_to_string(log->verdict),
                    log_severity_to_string(log->severity),
                    packet_str);
    free(packet_str);
}

static void
trace_actions(const struct ovnact *ovnacts, size_t ovnacts_len,
              const struct ovntrace_datapath *dp, struct flow *uflow,
              uint8_t table_id, enum ovnact_pipeline pipeline,
              struct ovs_list *super)
{
    if (!ovnacts_len) {
        ovntrace_node_append(super, OVNTRACE_NODE_ACTION, "drop;");
        return;
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    const struct ovnact *a;
    OVNACT_FOR_EACH (a, ovnacts, ovnacts_len) {
        ds_clear(&s);
        ovnacts_format(a, sizeof *a * (ovnact_next(a) - a), &s);
        char *friendly = ovntrace_make_names_friendly(ds_cstr(&s));
        ovntrace_node_append(super, OVNTRACE_NODE_ACTION, "%s", friendly);
        free(friendly);

        switch (a->type) {
        case OVNACT_OUTPUT:
            execute_output(dp, uflow, pipeline, super);
            break;

        case OVNACT_NEXT:
            execute_next(ovnact_get_NEXT(a), dp, uflow, pipeline, super);
            break;

        case OVNACT_LOAD:
            execute_load(ovnact_get_LOAD(a), dp, uflow, super);
            break;

        case OVNACT_MOVE:
            execute_move(ovnact_get_MOVE(a), uflow, super);
            break;

        case OVNACT_EXCHANGE:
            execute_exchange(ovnact_get_EXCHANGE(a), uflow, super);
            break;

        case OVNACT_DEC_TTL:
            if (is_ip_any(uflow)) {
                if (uflow->nw_ttl) {
                    uflow->nw_ttl--;
                    ovntrace_node_append(super, OVNTRACE_NODE_MODIFY,
                                         "ip.ttl--");
                } else {
                    ovntrace_node_append(super, OVNTRACE_NODE_ERROR,
                                         "*** TTL underflow");
                }
            } else {
                ovntrace_node_append(super, OVNTRACE_NODE_ERROR,
                                     "*** TTL decrement of non-IP packet");
            }
            break;

        case OVNACT_CT_NEXT:
            execute_ct_next(ovnact_get_CT_NEXT(a), dp, uflow, pipeline, super);
            break;

        case OVNACT_CT_COMMIT:
            /* Nothing to do. */
            break;

        case OVNACT_CT_DNAT:
            execute_ct_nat(ovnact_get_CT_DNAT(a), dp, uflow, pipeline, super);
            break;

        case OVNACT_CT_SNAT:
            execute_ct_nat(ovnact_get_CT_SNAT(a), dp, uflow, pipeline, super);
            break;

        case OVNACT_CT_LB:
            ovntrace_node_append(super, OVNTRACE_NODE_ERROR,
                                 "*** ct_lb action not implemented");
            break;

        case OVNACT_CT_CLEAR:
            flow_clear_conntrack(uflow);
            break;

        case OVNACT_CLONE:
            execute_clone(ovnact_get_CLONE(a), dp, uflow, table_id, pipeline,
                          super);
            break;

        case OVNACT_ARP:
            execute_arp(ovnact_get_ARP(a), dp, uflow, table_id, pipeline,
                        super);
            break;

        case OVNACT_ND_NA:
        case OVNACT_ND_NA_ROUTER:
            execute_nd_na(ovnact_get_ND_NA(a), dp, uflow, table_id, pipeline,
                          super);
            break;

        case OVNACT_ND_NS:
            execute_nd_ns(ovnact_get_ND_NS(a), dp, uflow, table_id, pipeline,
                          super);
            break;

        case OVNACT_GET_ARP:
            execute_get_mac_bind(ovnact_get_GET_ARP(a), dp, uflow, super);
            break;

        case OVNACT_GET_ND:
            execute_get_mac_bind(ovnact_get_GET_ND(a), dp, uflow, super);
            break;

        case OVNACT_PUT_ARP:
        case OVNACT_PUT_ND:
            /* Nothing to do for tracing. */
            break;

        case OVNACT_PUT_DHCPV4_OPTS:
            execute_put_dhcp_opts(ovnact_get_PUT_DHCPV4_OPTS(a),
                                  "put_dhcp_opts", uflow, super);
            break;

        case OVNACT_PUT_DHCPV6_OPTS:
            execute_put_dhcp_opts(ovnact_get_PUT_DHCPV6_OPTS(a),
                                  "put_dhcpv6_opts", uflow, super);
            break;

        case OVNACT_PUT_ND_RA_OPTS:
            execute_put_nd_ra_opts(ovnact_get_PUT_DHCPV6_OPTS(a),
                                   "put_nd_ra_opts", uflow, super);
            break;

        case OVNACT_SET_QUEUE:
            /* The set_queue action is slippery from a logical perspective.  It
             * has no visible effect as long as the packet remains on the same
             * chassis: it can bounce from one logical datapath to another
             * retaining the queue and even end up at a VM on the same chassis.
             * Without taking the physical arrangement into account, we can't
             * do anything with this action other than just to note that it
             * happened.  If we ever add some physical knowledge to ovn-trace,
             * though, it would be easy enough to track the queue information
             * by adjusting uflow->skb_priority. */
            break;

        case OVNACT_DNS_LOOKUP:
            execute_dns_lookup(ovnact_get_DNS_LOOKUP(a), uflow, super);
            break;

        case OVNACT_LOG:
            execute_log(ovnact_get_LOG(a), uflow, super);
            break;

        case OVNACT_SET_METER:
            /* Nothing to do. */
            break;

        case OVNACT_ICMP4:
            execute_icmp4(ovnact_get_ICMP4(a), dp, uflow, table_id, pipeline,
                          super);
            break;

        case OVNACT_ICMP6:
            execute_icmp6(ovnact_get_ICMP6(a), dp, uflow, table_id, pipeline,
                          super);
            break;

        case OVNACT_TCP_RESET:
            execute_tcp_reset(ovnact_get_TCP_RESET(a), dp, uflow, table_id,
                              pipeline, super);
            break;
        }

    }
    ds_destroy(&s);
}

static bool
may_omit_stage(const struct ovntrace_flow *f, uint8_t table_id)
{
    return (f
            && f->match->type == EXPR_T_BOOLEAN && f->match->boolean
            && f->ovnacts_len == OVNACT_NEXT_SIZE
            && f->ovnacts->type == OVNACT_NEXT
            && ovnact_get_NEXT(f->ovnacts)->ltable == table_id + 1);
}

static void
trace_openflow(const struct ovntrace_flow *f, struct ovs_list *super)
{
    struct ofputil_flow_stats_request fsr = {
        .cookie = htonll(f->uuid.parts[0]),
        .cookie_mask = OVS_BE64_MAX,
        .out_port = OFPP_ANY,
        .out_group = OFPG_ANY,
        .table_id = OFPTT_ALL,
    };

    struct ofputil_flow_stats *fses;
    size_t n_fses;
    int error = vconn_dump_flows(vconn, &fsr, OFPUTIL_P_OF13_OXM,
                                 &fses, &n_fses);
    if (error) {
        ovntrace_node_append(super, OVNTRACE_NODE_ERROR,
                             "*** error obtaining flow stats (%s)",
                             ovs_strerror(error));
        VLOG_WARN("%s: error obtaining flow stats (%s)",
                  ovs, ovs_strerror(error));
        return;
    }

    if (n_fses) {
        struct ds s = DS_EMPTY_INITIALIZER;
        for (size_t i = 0; i < n_fses; i++) {
            ds_clear(&s);
            ofputil_flow_stats_format(&s, &fses[i], NULL, NULL, true);
            ovntrace_node_append(super, OVNTRACE_NODE_ACTION,
                                 "%s", ds_cstr(&s));
        }
        ds_destroy(&s);
    } else {
        ovntrace_node_append(super, OVNTRACE_NODE_ERROR,
                             "*** no OpenFlow flows");
    }

    for (size_t i = 0; i < n_fses; i++) {
        free(CONST_CAST(struct ofpact *, fses[i].ofpacts));
    }
    free(fses);
}

static void
trace__(const struct ovntrace_datapath *dp, struct flow *uflow,
        uint8_t table_id, enum ovnact_pipeline pipeline,
        struct ovs_list *super)
{
    const struct ovntrace_flow *f;
    for (;;) {
        f = ovntrace_flow_lookup(dp, uflow, table_id, pipeline);
        if (!may_omit_stage(f, table_id)) {
            break;
        }
        table_id++;
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "%2d. ", table_id);
    if (f) {
        if (f->stage_name && f->source) {
            ds_put_format(&s, "%s (%s): ", f->stage_name, f->source);
        } else if (f->stage_name) {
            ds_put_format(&s, "%s: ", f->stage_name);
        } else if (f->source) {
            ds_put_format(&s, "(%s): ", f->source);
        }
        ds_put_format(&s, "%s, priority %d, uuid %08x",
                      f->match_s, f->priority, f->uuid.parts[0]);
    } else {
        char *stage_name = ovntrace_stage_name(dp, table_id, pipeline);
        ds_put_format(&s, "%s%sno match (implicit drop)",
                      stage_name ? stage_name : "",
                      stage_name ? ": " : "");
        free(stage_name);
    }
    struct ovntrace_node *node = ovntrace_node_append(
        super, OVNTRACE_NODE_TABLE, "%s", ds_cstr(&s));
    ds_destroy(&s);

    if (f) {
        if (vconn) {
            trace_openflow(f, &node->subs);
        }
        trace_actions(f->ovnacts, f->ovnacts_len, dp, uflow, table_id,
                      pipeline, &node->subs);
    }
}

static char *
trace(const char *dp_s, const char *flow_s)
{
    const struct ovntrace_datapath *dp = ovntrace_datapath_find_by_name(dp_s);
    if (!dp) {
        return xasprintf("unknown datapath \"%s\"\n", dp_s);
    }

    struct flow uflow;
    char *error = expr_parse_microflow(flow_s, &symtab, &address_sets,
                                       &port_groups, ovntrace_lookup_port,
                                       dp, &uflow);
    if (error) {
        char *s = xasprintf("error parsing flow: %s\n", error);
        free(error);
        return s;
    }

    uint32_t in_key = uflow.regs[MFF_LOG_INPORT - MFF_REG0];
    if (!in_key) {
        VLOG_WARN("microflow does not specify ingress port");
    }
    const struct ovntrace_port *inport = ovntrace_port_find_by_key(dp, in_key);
    const char *inport_name = inport ? inport->friendly_name : "(unnamed)";

    struct ds output = DS_EMPTY_INITIALIZER;

    ds_put_cstr(&output, "# ");
    flow_format(&output, &uflow, NULL);
    ds_put_char(&output, '\n');

    if (ovs) {
        int retval = vconn_open_block(ovs, 1 << OFP13_VERSION, 0, &vconn);
        if (retval) {
            VLOG_WARN("%s: connection failed (%s)", ovs, ovs_strerror(retval));
        }
    }

    struct ovs_list root = OVS_LIST_INITIALIZER(&root);
    struct ovntrace_node *node = ovntrace_node_append(
        &root, OVNTRACE_NODE_PIPELINE, "ingress(dp=\"%s\", inport=\"%s\")",
        dp->friendly_name, inport_name);
    trace__(dp, &uflow, 0, OVNACT_P_INGRESS, &node->subs);

    bool multiple = (detailed + summary + minimal) > 1;
    if (detailed) {
        if (multiple) {
            ds_put_cstr(&output, "# Detailed trace.\n");
        }
        ovntrace_node_print_details(&output, &root, 0);
    }

    if (summary) {
        if (multiple) {
            ds_put_cstr(&output, "# Summary trace.\n");
        }
        struct ovs_list clone = OVS_LIST_INITIALIZER(&clone);
        ovntrace_node_clone(&root, &clone);
        ovntrace_node_prune_summary(&clone);
        ovntrace_node_print_summary(&output, &clone, 0);
        ovntrace_node_list_destroy(&clone);
    }

    if (minimal) {
        if (multiple) {
            ds_put_cstr(&output, "# Minimal trace.\n");
        }
        ovntrace_node_prune_hard(&root);
        ovntrace_node_print_summary(&output, &root, 0);
    }

    ovntrace_node_list_destroy(&root);

    vconn_close(vconn);

    return ds_steal_cstr(&output);
}

static void
ovntrace_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

static void
ovntrace_trace(struct unixctl_conn *conn, int argc,
               const char *argv[], void *aux OVS_UNUSED)
{
    detailed = summary = minimal = false;
    while (argc > 1 && argv[1][0] == '-') {
        if (!strcmp(argv[1], "--detailed")) {
            detailed = true;
        } else if (!strcmp(argv[1], "--summary")) {
            summary = true;
        } else if (!strcmp(argv[1], "--minimal")) {
            minimal = true;
        } else if (!strcmp(argv[1], "--all")) {
            detailed = summary = minimal = true;
        } else {
            unixctl_command_reply_error(conn, "unknown option");
            return;
        }
        argc--;
        argv++;
    }
    if (!detailed && !summary && !minimal) {
        detailed = true;
    }

    if (argc != 3) {
        unixctl_command_reply_error(
            conn, "exactly 2 non-option arguments are required");
        return;
    }

    char *output = trace(argv[1], argv[2]);
    unixctl_command_reply(conn, output);
    free(output);
}
