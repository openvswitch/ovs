/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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

#include "ofproto-dpif-trace.h"

#include "conntrack.h"
#include "dpif.h"
#include "ofproto-dpif-xlate.h"
#include "openvswitch/ofp-parse.h"
#include "unixctl.h"

static void ofproto_trace(struct ofproto_dpif *, const struct flow *,
                          const struct dp_packet *packet,
                          const struct ofpact[], size_t ofpacts_len,
                          struct ovs_list *next_ct_states,
                          struct ds *);
static void oftrace_node_destroy(struct oftrace_node *);

/* Creates a new oftrace_node, populates it with the given 'type' and a copy of
 * 'text', and appends it to list 'super'.  The caller retains ownership of
 * 'text'. */
struct oftrace_node *
oftrace_report(struct ovs_list *super, enum oftrace_node_type type,
               const char *text)
{
    struct oftrace_node *node = xmalloc(sizeof *node);
    ovs_list_push_back(super, &node->node);
    node->type = type;
    node->text = xstrdup(text);
    ovs_list_init(&node->subs);

    return node;
}

static bool
oftrace_node_type_is_terminal(enum oftrace_node_type type)
{
    switch (type) {
    case OFT_ACTION:
    case OFT_DETAIL:
    case OFT_WARN:
    case OFT_ERROR:
        return true;

    case OFT_BRIDGE:
    case OFT_TABLE:
    case OFT_THAW:
        return false;
    }

    OVS_NOT_REACHED();
}

static void
oftrace_node_list_destroy(struct ovs_list *nodes)
{
    if (nodes) {
        struct oftrace_node *node, *next;
        LIST_FOR_EACH_SAFE (node, next, node, nodes) {
            ovs_list_remove(&node->node);
            oftrace_node_destroy(node);
        }
    }
}

static void
oftrace_node_destroy(struct oftrace_node *node)
{
    if (node) {
        oftrace_node_list_destroy(&node->subs);
        free(node->text);
        free(node);
    }
}

bool
oftrace_add_recirc_node(struct ovs_list *recirc_queue,
                        enum oftrace_recirc_type type, const struct flow *flow,
                        const struct dp_packet *packet, uint32_t recirc_id,
                        const uint16_t zone)
{
    if (!recirc_id_node_find_and_ref(recirc_id)) {
        return false;
    }

    struct oftrace_recirc_node *node = xmalloc(sizeof *node);
    ovs_list_push_back(recirc_queue, &node->node);

    node->type = type;
    node->recirc_id = recirc_id;
    node->flow = *flow;
    node->flow.recirc_id = recirc_id;
    node->flow.ct_zone = zone;
    node->packet = packet ? dp_packet_clone(packet) : NULL;

    return true;
}

static void
oftrace_recirc_node_destroy(struct oftrace_recirc_node *node)
{
    if (node) {
        recirc_free_id(node->recirc_id);
        dp_packet_delete(node->packet);
        free(node);
    }
}

static void
oftrace_push_ct_state(struct ovs_list *next_ct_states, uint32_t ct_state)
{
    struct oftrace_next_ct_state *next_ct_state =
        xmalloc(sizeof *next_ct_state);
    next_ct_state->state = ct_state;
    ovs_list_push_back(next_ct_states, &next_ct_state->node);
}

static uint32_t
oftrace_pop_ct_state(struct ovs_list *next_ct_states)
{
    struct oftrace_next_ct_state *s;
    LIST_FOR_EACH_POP (s, node, next_ct_states) {
        uint32_t state = s->state;
        free(s);
        return state;
    }
    OVS_NOT_REACHED();
}

static void
oftrace_node_print_details(struct ds *output,
                           const struct ovs_list *nodes, int level)
{
    const struct oftrace_node *sub;
    LIST_FOR_EACH (sub, node, nodes) {
        if (sub->type == OFT_BRIDGE) {
            ds_put_char(output, '\n');
        }

        bool more = (sub->node.next != nodes
                     || oftrace_node_type_is_terminal(sub->type));

        ds_put_char_multiple(output, ' ', (level + more) * 4);
        switch (sub->type) {
        case OFT_DETAIL:
            ds_put_format(output, " -> %s\n", sub->text);
            break;
        case OFT_WARN:
            ds_put_format(output, " >> %s\n", sub->text);
            break;
        case OFT_ERROR:
            ds_put_format(output, " >>>> %s <<<<\n", sub->text);
            break;
        case OFT_BRIDGE:
            ds_put_format(output, "%s\n", sub->text);
            ds_put_char_multiple(output, ' ', (level + more) * 4);
            ds_put_char_multiple(output, '-', strlen(sub->text));
            ds_put_char(output, '\n');
            break;
        case OFT_TABLE:
        case OFT_THAW:
        case OFT_ACTION:
            ds_put_format(output, "%s\n", sub->text);
            break;
        }

        oftrace_node_print_details(output, &sub->subs, level + more + more);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_oftrace_options(int argc, const char *argv[],
                      struct ovs_list *next_ct_states)
{
    int k;
    struct ds ds = DS_EMPTY_INITIALIZER;

    for (k = 0; k < argc; k++) {
        if (!strncmp(argv[k], "--ct-next", 9)) {
            if (k + 1 > argc) {
                return xasprintf("Missing argument for option %s", argv[k]);
            }

            uint32_t ct_state;
            if (!parse_ct_state(argv[++k], 0, &ct_state, &ds)) {
                return ds_steal_cstr(&ds);
            }
            if (!validate_ct_state(ct_state, &ds)) {
                return ds_steal_cstr(&ds);
            }
            oftrace_push_ct_state(next_ct_states, ct_state);
        } else {
            return xasprintf("Invalid option %s", argv[k]);
        }
    }

    ds_destroy(&ds);
    return NULL;
}

/* Parses the 'argc' elements of 'argv', ignoring argv[0].  The following
 * forms are supported:
 *
 *     - [dpname] odp_flow [OPTIONS] [-generate | packet]
 *     - bridge br_flow [OPTIONS] [-generate | packet]
 *
 * On success, initializes '*ofprotop' and 'flow' and returns NULL.  On failure
 * returns a nonnull malloced error message. */
static char * OVS_WARN_UNUSED_RESULT
parse_flow_and_packet(int argc, const char *argv[],
                      struct ofproto_dpif **ofprotop, struct flow *flow,
                      struct dp_packet **packetp,
                      struct ovs_list *next_ct_states)
{
    const struct dpif_backer *backer = NULL;
    const char *error = NULL;
    char *m_err = NULL;
    struct simap port_names = SIMAP_INITIALIZER(&port_names);
    struct dp_packet *packet;
    struct ofpbuf odp_key;
    struct ofpbuf odp_mask;
    int first_option;

    ofpbuf_init(&odp_key, 0);
    ofpbuf_init(&odp_mask, 0);

    /* Handle "-generate" or a hex string as the last argument. */
    if (!strcmp(argv[argc - 1], "-generate")) {
        packet = dp_packet_new(0);
        argc--;
    } else {
        error = eth_from_hex(argv[argc - 1], &packet);
        if (!error) {
            argc--;
        } else if (argc == 4) {
            /* The 3-argument form must end in "-generate' or a hex string. */
            goto exit;
        }
        error = NULL;
    }

    /* Parse options. */
    if (argc >= 4) {
        if (!strncmp(argv[2], "--", 2)) {
            first_option = 2;
        } else if (!strncmp(argv[3], "--", 2)) {
            first_option = 3;
        } else {
            error = "Syntax error: invalid option";
            goto exit;
        }

        m_err = parse_oftrace_options(argc - first_option, argv + first_option,
                                      next_ct_states);
        if (m_err) {
            goto exit;
        }
        argc = first_option;
    }

    /* odp_flow can have its in_port specified as a name instead of port no.
     * We do not yet know whether a given flow is a odp_flow or a br_flow.
     * But, to know whether a flow is odp_flow through odp_flow_from_string(),
     * we need to create a simap of name to port no. */
    if (argc == 3) {
        const char *dp_type;
        if (!strncmp(argv[1], "ovs-", 4)) {
            dp_type = argv[1] + 4;
        } else {
            dp_type = argv[1];
        }
        backer = shash_find_data(&all_dpif_backers, dp_type);
    } else if (argc == 2) {
        struct shash_node *node;
        if (shash_count(&all_dpif_backers) == 1) {
            node = shash_first(&all_dpif_backers);
            backer = node->data;
        }
    } else {
        error = "Syntax error";
        goto exit;
    }
    if (backer && backer->dpif) {
        struct dpif_port dpif_port;
        struct dpif_port_dump port_dump;
        DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, backer->dpif) {
            simap_put(&port_names, dpif_port.name,
                      odp_to_u32(dpif_port.port_no));
        }
    }

    /* Parse the flow and determine whether a datapath or
     * bridge is specified. If function odp_flow_key_from_string()
     * returns 0, the flow is a odp_flow. If function
     * parse_ofp_exact_flow() returns NULL, the flow is a br_flow. */
    if (!odp_flow_from_string(argv[argc - 1], &port_names,
                              &odp_key, &odp_mask)) {
        if (!backer) {
            error = "Cannot find the datapath";
            goto exit;
        }

        if (odp_flow_key_to_flow(odp_key.data, odp_key.size, flow) == ODP_FIT_ERROR) {
            error = "Failed to parse datapath flow key";
            goto exit;
        }

        *ofprotop = xlate_lookup_ofproto(backer, flow,
                                         &flow->in_port.ofp_port);
        if (*ofprotop == NULL) {
            error = "Invalid datapath flow";
            goto exit;
        }

        flow->tunnel.metadata.tab = ofproto_get_tun_tab(&(*ofprotop)->up);

        /* Convert Geneve options to OpenFlow format now. This isn't actually
         * required in order to get the right results since the ofproto xlate
         * actions will handle this for us. However, converting now ensures
         * that our formatting code will always be able to consistently print
         * in OpenFlow format, which is what we use here. */
        if (flow->tunnel.flags & FLOW_TNL_F_UDPIF) {
            struct flow_tnl tnl;
            int err;

            memcpy(&tnl, &flow->tunnel, sizeof tnl);
            err = tun_metadata_from_geneve_udpif(flow->tunnel.metadata.tab,
                                                 &tnl, &tnl, &flow->tunnel);
            if (err) {
                error = "Failed to parse Geneve options";
                goto exit;
            }
        }
    } else {
        char *err;

        if (argc != 3) {
            error = "Must specify bridge name";
            goto exit;
        }

        *ofprotop = ofproto_dpif_lookup_by_name(argv[1]);
        if (!*ofprotop) {
            error = "Unknown bridge name";
            goto exit;
        }

        struct ofputil_port_map map = OFPUTIL_PORT_MAP_INITIALIZER(&map);
        const struct ofport *ofport;
        HMAP_FOR_EACH (ofport, hmap_node, &(*ofprotop)->up.ports) {
            ofputil_port_map_put(&map, ofport->ofp_port,
                                 netdev_get_name(ofport->netdev));
        }
        err = parse_ofp_exact_flow(flow, NULL,
                                   ofproto_get_tun_tab(&(*ofprotop)->up),
                                   argv[argc - 1], &map);
        ofputil_port_map_destroy(&map);
        if (err) {
            m_err = xasprintf("Bad openflow flow syntax: %s", err);
            free(err);
            goto exit;
        }
    }

    /* Generate a packet, if requested. */
    if (packet) {
        if (!dp_packet_size(packet)) {
            flow_compose(packet, flow, 0);
        } else {
            /* Use the metadata from the flow and the packet argument
             * to reconstruct the flow. */
            pkt_metadata_from_flow(&packet->md, flow);
            flow_extract(packet, flow);
        }
    }

exit:
    if (error && !m_err) {
        m_err = xstrdup(error);
    }
    if (m_err) {
        dp_packet_delete(packet);
        packet = NULL;
    }
    *packetp = packet;
    ofpbuf_uninit(&odp_key);
    ofpbuf_uninit(&odp_mask);
    simap_destroy(&port_names);
    return m_err;
}

static void
free_ct_states(struct ovs_list *ct_states)
{
    while (!ovs_list_is_empty(ct_states)) {
        oftrace_pop_ct_state(ct_states);
    }
}

static void
ofproto_unixctl_trace(struct unixctl_conn *conn, int argc, const char *argv[],
                      void *aux OVS_UNUSED)
{
    struct ofproto_dpif *ofproto;
    struct dp_packet *packet;
    char *error;
    struct flow flow;
    struct ovs_list next_ct_states = OVS_LIST_INITIALIZER(&next_ct_states);

    error = parse_flow_and_packet(argc, argv, &ofproto, &flow, &packet,
                                  &next_ct_states);
    if (!error) {
        struct ds result;

        ds_init(&result);
        ofproto_trace(ofproto, &flow, packet, NULL, 0, &next_ct_states,
                      &result);
        unixctl_command_reply(conn, ds_cstr(&result));
        ds_destroy(&result);
        dp_packet_delete(packet);
    } else {
        unixctl_command_reply_error(conn, error);
        free(error);
    }
    free_ct_states(&next_ct_states);
}

static void
ofproto_unixctl_trace_actions(struct unixctl_conn *conn, int argc,
                              const char *argv[], void *aux OVS_UNUSED)
{
    enum ofputil_protocol usable_protocols;
    struct ofproto_dpif *ofproto;
    bool enforce_consistency;
    struct ofpbuf ofpacts;
    struct dp_packet *packet;
    struct ds result;
    struct match match;
    uint16_t in_port;
    struct ovs_list next_ct_states = OVS_LIST_INITIALIZER(&next_ct_states);

    /* Three kinds of error return values! */
    enum ofperr retval;
    char *error;

    packet = NULL;
    ds_init(&result);
    ofpbuf_init(&ofpacts, 0);

    /* Parse actions. */
    error = ofpacts_parse_actions(argv[--argc], NULL,
                                  &ofpacts, &usable_protocols);
    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
        goto exit;
    }

    /* OpenFlow 1.1 and later suggest that the switch enforces certain forms of
     * consistency between the flow and the actions.  With -consistent, we
     * enforce consistency even for a flow supported in OpenFlow 1.0. */
    if (!strcmp(argv[1], "-consistent")) {
        enforce_consistency = true;
        argv++;
        argc--;
    } else {
        enforce_consistency = false;
    }

    error = parse_flow_and_packet(argc, argv, &ofproto, &match.flow, &packet,
                                  &next_ct_states);
    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
        goto exit;
    }
    match_wc_init(&match, &match.flow);

    /* Do the same checks as handle_packet_out() in ofproto.c.
     *
     * We pass a 'table_id' of 0 to ofpacts_check(), which isn't
     * strictly correct because these actions aren't in any table, but it's OK
     * because it 'table_id' is used only to check goto_table instructions, but
     * packet-outs take a list of actions and therefore it can't include
     * instructions.
     *
     * We skip the "meter" check here because meter is an instruction, not an
     * action, and thus cannot appear in ofpacts. */
    in_port = ofp_to_u16(match.flow.in_port.ofp_port);
    if (in_port >= ofproto->up.max_ports && in_port < ofp_to_u16(OFPP_MAX)) {
        unixctl_command_reply_error(conn, "invalid in_port");
        goto exit;
    }
    if (enforce_consistency) {
        retval = ofpacts_check_consistency(ofpacts.data, ofpacts.size, &match,
                                           u16_to_ofp(ofproto->up.max_ports),
                                           0, ofproto->up.n_tables,
                                           usable_protocols);
    } else {
        retval = ofpacts_check(ofpacts.data, ofpacts.size, &match,
                               u16_to_ofp(ofproto->up.max_ports), 0,
                               ofproto->up.n_tables, &usable_protocols);
    }
    if (!retval) {
        ovs_mutex_lock(&ofproto_mutex);
        retval = ofproto_check_ofpacts(&ofproto->up, ofpacts.data,
                                       ofpacts.size);
        ovs_mutex_unlock(&ofproto_mutex);
    }

    if (retval) {
        ds_clear(&result);
        ds_put_format(&result, "Bad actions: %s", ofperr_to_string(retval));
        unixctl_command_reply_error(conn, ds_cstr(&result));
        goto exit;
    }

    ofproto_trace(ofproto, &match.flow, packet,
                  ofpacts.data, ofpacts.size, &next_ct_states, &result);
    unixctl_command_reply(conn, ds_cstr(&result));

exit:
    ds_destroy(&result);
    dp_packet_delete(packet);
    ofpbuf_uninit(&ofpacts);
    free_ct_states(&next_ct_states);
}

static void
ofproto_trace__(struct ofproto_dpif *ofproto, const struct flow *flow,
                const struct dp_packet *packet, struct ovs_list *recirc_queue,
                const struct ofpact ofpacts[], size_t ofpacts_len,
                struct ds *output)
{
    struct ofpbuf odp_actions;
    ofpbuf_init(&odp_actions, 0);

    struct xlate_in xin;
    struct flow_wildcards wc;
    struct ovs_list trace = OVS_LIST_INITIALIZER(&trace);
    xlate_in_init(&xin, ofproto,
                  ofproto_dpif_get_tables_version(ofproto), flow,
                  flow->in_port.ofp_port, NULL, ntohs(flow->tcp_flags),
                  packet, &wc, &odp_actions);
    xin.ofpacts = ofpacts;
    xin.ofpacts_len = ofpacts_len;
    xin.trace = &trace;
    xin.recirc_queue = recirc_queue;

    /* Copy initial flow out of xin.flow.  It differs from '*flow' because
     * xlate_in_init() initializes actset_output to OFPP_UNSET. */
    struct flow initial_flow = xin.flow;
    ds_put_cstr(output, "Flow: ");
    flow_format(output, &initial_flow, NULL);
    ds_put_char(output, '\n');

    struct xlate_out xout;
    enum xlate_error error = xlate_actions(&xin, &xout);

    oftrace_node_print_details(output, &trace, 0);

    ds_put_cstr(output, "\nFinal flow: ");
    if (flow_equal(&initial_flow, &xin.flow)) {
        ds_put_cstr(output, "unchanged");
    } else {
        flow_format(output, &xin.flow, NULL);
    }
    ds_put_char(output, '\n');

    ds_put_cstr(output, "Megaflow: ");
    struct match match;
    match_init(&match, flow, &wc);
    match_format(&match, NULL, output, OFP_DEFAULT_PRIORITY);
    ds_put_char(output, '\n');

    ds_put_cstr(output, "Datapath actions: ");
    format_odp_actions(output, odp_actions.data, odp_actions.size, NULL);

    if (error != XLATE_OK) {
        ds_put_format(output,
                      "\nTranslation failed (%s), packet is dropped.\n",
                      xlate_strerror(error));
    } else if (xout.slow) {
        enum slow_path_reason slow;

        ds_put_cstr(output, "\nThis flow is handled by the userspace "
                    "slow path because it:");

        slow = xout.slow;
        while (slow) {
            enum slow_path_reason bit = rightmost_1bit(slow);

            ds_put_format(output, "\n\t- %s.",
                          slow_path_reason_to_explanation(bit));

            slow &= ~bit;
        }
    }

    xlate_out_uninit(&xout);
    ofpbuf_uninit(&odp_actions);
    oftrace_node_list_destroy(&trace);
}

/* Implements a "trace" through 'ofproto''s flow table, appending a textual
 * description of the results to 'output'.
 *
 * The trace follows a packet with the specified 'flow' through the flow
 * table.  'packet' may be nonnull to trace an actual packet, with consequent
 * side effects (if it is nonnull then its flow must be 'flow').
 *
 * If 'ofpacts' is nonnull then its 'ofpacts_len' bytes specify the actions to
 * trace, otherwise the actions are determined by a flow table lookup. */
static void
ofproto_trace(struct ofproto_dpif *ofproto, const struct flow *flow,
              const struct dp_packet *packet,
              const struct ofpact ofpacts[], size_t ofpacts_len,
              struct ovs_list *next_ct_states, struct ds *output)
{
    struct ovs_list recirc_queue = OVS_LIST_INITIALIZER(&recirc_queue);
    ofproto_trace__(ofproto, flow, packet, &recirc_queue,
                    ofpacts, ofpacts_len, output);

    struct oftrace_recirc_node *recirc_node;
    LIST_FOR_EACH_POP (recirc_node, node, &recirc_queue) {
        ds_put_cstr(output, "\n\n");
        ds_put_char_multiple(output, '=', 79);
        ds_put_format(output, "\nrecirc(%#"PRIx32")",
                      recirc_node->recirc_id);

        if (recirc_node->type == OFT_RECIRC_CONNTRACK) {
            uint32_t ct_state;
            if (ovs_list_is_empty(next_ct_states)) {
                ct_state = CS_TRACKED | CS_NEW;
                ds_put_cstr(output, " - resume conntrack with default "
                            "ct_state=trk|new (use --ct-next to customize)");
            } else {
                ct_state = oftrace_pop_ct_state(next_ct_states);
                struct ds s = DS_EMPTY_INITIALIZER;
                format_flags(&s, ct_state_to_string, ct_state, '|');
                ds_put_format(output, " - resume conntrack with ct_state=%s",
                              ds_cstr(&s));
                ds_destroy(&s);
            }
            recirc_node->flow.ct_state = ct_state;
        }
        ds_put_char(output, '\n');
        ds_put_char_multiple(output, '=', 79);
        ds_put_cstr(output, "\n\n");

        ofproto_trace__(ofproto, &recirc_node->flow, recirc_node->packet,
                        &recirc_queue, ofpacts, ofpacts_len, output);
        oftrace_recirc_node_destroy(recirc_node);
    }
}

void
ofproto_dpif_trace_init(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    unixctl_command_register(
        "ofproto/trace",
        "{[dp_name] odp_flow | bridge br_flow} [OPTIONS...] "
        "[-generate|packet]", 1, INT_MAX, ofproto_unixctl_trace, NULL);
    unixctl_command_register(
        "ofproto/trace-packet-out",
        "[-consistent] {[dp_name] odp_flow | bridge br_flow} [OPTIONS...] "
        "[-generate|packet] actions",
        2, INT_MAX, ofproto_unixctl_trace_actions, NULL);
}
