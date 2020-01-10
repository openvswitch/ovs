/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2019 Nicira, Inc.
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
#include "unixctl.h"

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
    case OFT_BUCKET:
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
                        const struct ofpact_nat *ofn,
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
    node->nat_act = ofn;
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
        case OFT_BUCKET:
        case OFT_THAW:
        case OFT_ACTION:
            ds_put_format(output, "%s\n", sub->text);
            break;
        }

        oftrace_node_print_details(output, &sub->subs, level + more + more);
    }
}

static void
oftrace_print_ip_flow(const struct flow *flow, int af, struct ds *output)
{
    if (af == AF_INET) {
        ds_put_format(output, "nw_src="IP_FMT",tp_src=%"PRIu16","
                      "nw_dst="IP_FMT",tp_dst=%"PRIu16,
                      IP_ARGS(flow->nw_src), ntohs(flow->tp_src),
                      IP_ARGS(flow->nw_dst), ntohs(flow->tp_dst));
    } else if (af == AF_INET6) {
        ds_put_cstr(output, "ipv6_src=");
        ipv6_format_addr_bracket(&flow->ipv6_src, output, true);
        ds_put_format(output, ",tp_src=%"PRIu16, ntohs(flow->tp_src));
        ds_put_cstr(output, ",ipv6_dst=");
        ipv6_format_addr_bracket(&flow->ipv6_dst, output, true);
        ds_put_format(output, ",tp_dst=%"PRIu16, ntohs(flow->tp_dst));
    }
    ds_put_char(output, '\n');
}

/* Parses the 'argc' elements of 'argv', ignoring argv[0].  The following
 * forms are supported:
 *
 *     - [options] [dpname] odp_flow [packet]
 *     - [options] bridge br_flow [packet]
 *
 * On success, initializes '*ofprotop' and 'flow' and returns NULL.  On failure
 * returns a nonnull malloced error message. */
static char * OVS_WARN_UNUSED_RESULT
parse_flow_and_packet(int argc, const char *argv[],
                      struct ofproto_dpif **ofprotop, struct flow *flow,
                      struct dp_packet **packetp,
                      struct ovs_list *next_ct_states,
                      bool *consistent)
{
    const struct dpif_backer *backer = NULL;
    char *error = NULL;
    struct simap port_names = SIMAP_INITIALIZER(&port_names);
    struct dp_packet *packet = NULL;
    uint8_t *l7 = NULL;
    size_t l7_len = 64;
    struct ofpbuf odp_key;
    struct ofpbuf odp_mask;

    ofpbuf_init(&odp_key, 0);
    ofpbuf_init(&odp_mask, 0);

    const char *args[3];
    int n_args = 0;
    bool generate_packet = false;
    if (consistent) {
        *consistent = false;
    }
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (!strcmp(arg, "-generate") || !strcmp(arg, "--generate")) {
            generate_packet = true;
        } else if (!strcmp(arg, "--l7")) {
            if (i + 1 >= argc) {
                error = xasprintf("Missing argument for option %s", arg);
                goto exit;
            }

            struct dp_packet payload;
            memset(&payload, 0, sizeof payload);
            dp_packet_init(&payload, 0);
            if (dp_packet_put_hex(&payload, argv[++i], NULL)[0] != '\0') {
                dp_packet_uninit(&payload);
                error = xstrdup("Trailing garbage in packet data");
                goto exit;
            }
            free(l7);
            l7_len = dp_packet_size(&payload);
            l7 = dp_packet_steal_data(&payload);
        } else if (!strcmp(arg, "--l7-len")) {
            if (i + 1 >= argc) {
                error = xasprintf("Missing argument for option %s", arg);
                goto exit;
            }
            free(l7);
            l7 = NULL;
            l7_len = atoi(argv[++i]);
            if (l7_len > 64000) {
                error = xasprintf("%s: too much L7 data", argv[i]);
                goto exit;
            }
        } else if (consistent
                   && (!strcmp(arg, "-consistent") ||
                       !strcmp(arg, "--consistent"))) {
            *consistent = true;
        } else if (!strcmp(arg, "--ct-next")) {
            if (i + 1 >= argc) {
                error = xasprintf("Missing argument for option %s", arg);
                goto exit;
            }

            uint32_t ct_state;
            struct ds ds = DS_EMPTY_INITIALIZER;
            if (!parse_ct_state(argv[++i], 0, &ct_state, &ds)
                || !validate_ct_state(ct_state, &ds)) {
                error = ds_steal_cstr(&ds);
                goto exit;
            }
            oftrace_push_ct_state(next_ct_states, ct_state);
        } else if (arg[0] == '-') {
            error = xasprintf("%s: unknown option", arg);
            goto exit;
        } else if (n_args >= ARRAY_SIZE(args)) {
            error = xstrdup("too many arguments");
            goto exit;
        } else {
            args[n_args++] = arg;
        }
    }

    /* 'args' must now have one of the following forms:
     *
     *     odp_flow
     *     dpname odp_flow
     *     bridge br_flow
     *     odp_flow packet
     *     dpname odp_flow packet
     *     bridge br_flow packet
     *
     * Parse the packet if it's there.  Note that:
     *
     *     - If there is one argument, there cannot be a packet.
     *
     *     - If there are three arguments, there must be a packet.
     *
     * If there is a packet, we strip it off.
     */
    if (!generate_packet && n_args > 1) {
        const char *const_error = eth_from_hex(args[n_args - 1], &packet);
        if (!const_error) {
            n_args--;
        } else if (n_args > 2) {
            /* The 3-argument form must end in a hex string. */
            error = xstrdup(const_error);
            goto exit;
        }
    }

    /* We stripped off the packet if there was one, so 'args' now has one of
     * the following forms:
     *
     *     odp_flow
     *     dpname odp_flow
     *     bridge br_flow
     *
     * Before we parse the flow, try to identify the backer, then use that
     * backer to assemble a collection of port names.  The port names are
     * useful so that the user can specify ports by name instead of number in
     * the flow. */
    if (n_args == 2) {
        /* args[0] might be dpname. */
        const char *dp_type;
        if (!strncmp(args[0], "ovs-", 4)) {
            dp_type = args[0] + 4;
        } else {
            dp_type = args[0];
        }
        backer = shash_find_data(&all_dpif_backers, dp_type);
    } else if (n_args == 1) {
        /* Pick default backer. */
        struct shash_node *node;
        if (shash_count(&all_dpif_backers) == 1) {
            node = shash_first(&all_dpif_backers);
            backer = node->data;
        }
    } else {
        error = xstrdup("Syntax error");
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
    if (!odp_flow_from_string(args[n_args - 1], &port_names,
                              &odp_key, &odp_mask, &error)) {
        if (!backer) {
            error = xstrdup("Cannot find the datapath");
            goto exit;
        }

        if (odp_flow_key_to_flow(odp_key.data, odp_key.size, flow, &error)
            == ODP_FIT_ERROR) {
            goto exit;
        }

        *ofprotop = xlate_lookup_ofproto(backer, flow,
                                         &flow->in_port.ofp_port, &error);
        if (*ofprotop == NULL) {
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
            memcpy(&tnl, &flow->tunnel, sizeof tnl);
            int err = tun_metadata_from_geneve_udpif(
                flow->tunnel.metadata.tab, &tnl, &tnl, &flow->tunnel);
            if (err) {
                error = xstrdup("Failed to parse Geneve options");
                goto exit;
            }
        }
    } else if (n_args != 2) {
        char *s = error;
        error = xasprintf("%s (or the bridge name was omitted)", s);
        free(s);
        goto exit;
    } else {
        free(error);
        error = NULL;

        *ofprotop = ofproto_dpif_lookup_by_name(args[0]);
        if (!*ofprotop) {
            error = xasprintf("%s: unknown bridge", args[0]);
            goto exit;
        }

        struct ofputil_port_map map = OFPUTIL_PORT_MAP_INITIALIZER(&map);
        const struct ofport *ofport;
        HMAP_FOR_EACH (ofport, hmap_node, &(*ofprotop)->up.ports) {
            ofputil_port_map_put(&map, ofport->ofp_port,
                                 netdev_get_name(ofport->netdev));
        }
        char *err = parse_ofp_exact_flow(flow, NULL,
                                         ofproto_get_tun_tab(&(*ofprotop)->up),
                                         args[n_args - 1], &map);
        ofputil_port_map_destroy(&map);
        if (err) {
            error = xasprintf("Bad openflow flow syntax: %s", err);
            free(err);
            goto exit;
        }
    }

    if (generate_packet) {
        /* Generate a packet, as requested. */
        packet = dp_packet_new(0);
        flow_compose(packet, flow, l7, l7_len);
    } else if (packet) {
        /* Use the metadata from the flow and the packet argument to
         * reconstruct the flow. */
        pkt_metadata_from_flow(&packet->md, flow);
        flow_extract(packet, flow);
    }

exit:
    if (error) {
        dp_packet_delete(packet);
        packet = NULL;
    }
    *packetp = packet;
    ofpbuf_uninit(&odp_key);
    ofpbuf_uninit(&odp_mask);
    simap_destroy(&port_names);
    free(l7);
    return error;
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
                                  &next_ct_states, NULL);
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
    struct ofpact_parse_params pp = {
        .port_map = NULL,
        .ofpacts = &ofpacts,
        .usable_protocols = &usable_protocols,
    };
    error = ofpacts_parse_actions(argv[--argc], &pp);
    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
        goto exit;
    }

    error = parse_flow_and_packet(argc, argv, &ofproto, &match.flow, &packet,
                                  &next_ct_states, &enforce_consistency);
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

    struct ofpact_check_params cp = {
        .match = &match,
        .max_ports = u16_to_ofp(ofproto->up.max_ports),
        .table_id = 0,
        .n_tables = ofproto->up.n_tables,
    };
    retval = ofpacts_check_consistency(
        ofpacts.data, ofpacts.size,
        enforce_consistency ? usable_protocols : 0, &cp);
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
explain_slow_path(enum slow_path_reason slow, struct ds *output)
{
    ds_put_cstr(output, "\nThis flow is handled by the userspace "
                "slow path because it:");
    for (; slow; slow = zero_rightmost_1bit(slow)) {
        enum slow_path_reason bit = rightmost_1bit(slow);
        ds_put_format(output, "\n  - %s.",
                      slow_path_reason_to_explanation(bit));
    }
}

/* Copies ODP actions from 'in' to 'out', dropping OVS_ACTION_ATTR_OUTPUT and
 * OVS_ACTION_ATTR_RECIRC along the way. */
static void
prune_output_actions(const struct ofpbuf *in, struct ofpbuf *out)
{
    const struct nlattr *a;
    unsigned int left;
    NL_ATTR_FOR_EACH (a, left, in->data, in->size) {
        if (a->nla_type == OVS_ACTION_ATTR_CLONE) {
            struct ofpbuf in_nested;
            nl_attr_get_nested(a, &in_nested);

            size_t ofs = nl_msg_start_nested(out, OVS_ACTION_ATTR_CLONE);
            prune_output_actions(&in_nested, out);
            nl_msg_end_nested(out, ofs);
        } else if (a->nla_type != OVS_ACTION_ATTR_OUTPUT &&
                   a->nla_type != OVS_ACTION_ATTR_RECIRC) {
            ofpbuf_put(out, a, NLA_ALIGN(a->nla_len));
        }
    }
}

/* Executes all of the datapath actions, except for any OVS_ACTION_ATTR_OUTPUT
 * and OVS_ACTION_ATTR_RECIRC actions, in 'actions' on 'packet', which has the
 * given 'flow', on 'dpif'.  The actions have slow path reason 'slow' (if any).
 * Appends any error message to 'output'.
 *
 * With output and recirculation actions dropped, the only remaining side
 * effects are from OVS_ACTION_ATTR_USERSPACE actions for executing actions to
 * send a packet to an OpenFlow controller, IPFIX, NetFlow, and sFlow, etc. */
static void
execute_actions_except_outputs(struct dpif *dpif,
                               const struct dp_packet *packet,
                               const struct flow *flow,
                               const struct ofpbuf *actions,
                               enum slow_path_reason slow,
                               struct ds *output)
{
    struct ofpbuf pruned_actions;
    ofpbuf_init(&pruned_actions, 0);
    prune_output_actions(actions, &pruned_actions);

    struct dpif_execute execute = {
        .actions = pruned_actions.data,
        .actions_len = pruned_actions.size,
        .needs_help = (slow & SLOW_ACTION) != 0,
        .flow = flow,
        .packet = dp_packet_clone_with_headroom(packet, 2),
    };
    int error = dpif_execute(dpif, &execute);
    if (error) {
        ds_put_format(output, "\nAction execution failed (%s)\n.",
                      ovs_strerror(error));
    }
    dp_packet_delete(execute.packet);
    ofpbuf_uninit(&pruned_actions);
}

static void
ofproto_trace_recirc_node(struct oftrace_recirc_node *node,
                          struct ovs_list *next_ct_states,
                          struct ds *output)
{
    ds_put_cstr(output, "\n\n");
    ds_put_char_multiple(output, '=', 79);
    ds_put_format(output, "\nrecirc(%#"PRIx32")", node->recirc_id);

    if (next_ct_states && node->type == OFT_RECIRC_CONNTRACK) {
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
        node->flow.ct_state = ct_state;
    }
    ds_put_char(output, '\n');

    /* If there's any snat/dnat information assume we always translate to
     * the first IP/port to make sure we don't match on incorrect flows later
     * on.
     */
    if (node->nat_act) {
        const struct ofpact_nat *ofn = node->nat_act;

        ds_put_cstr(output, "Replacing src/dst IP/ports to simulate NAT:\n");
        ds_put_cstr(output, " Initial flow: ");
        oftrace_print_ip_flow(&node->flow, ofn->range_af, output);

        if (ofn->flags & NX_NAT_F_SRC) {
            if (ofn->range_af == AF_INET) {
                node->flow.nw_src = ofn->range.addr.ipv4.min;
            } else if (ofn->range_af == AF_INET6) {
                node->flow.ipv6_src = ofn->range.addr.ipv6.min;
            }

            if (ofn->range_af != AF_UNSPEC && ofn->range.proto.min) {
                node->flow.tp_src = htons(ofn->range.proto.min);
            }
        }
        if (ofn->flags & NX_NAT_F_DST) {
            if (ofn->range_af == AF_INET) {
                node->flow.nw_dst = ofn->range.addr.ipv4.min;
            } else if (ofn->range_af == AF_INET6) {
                node->flow.ipv6_dst = ofn->range.addr.ipv6.min;
            }

            if (ofn->range_af != AF_UNSPEC && ofn->range.proto.min) {
                node->flow.tp_dst = htons(ofn->range.proto.min);
            }
        }
        ds_put_cstr(output, " Modified flow: ");
        oftrace_print_ip_flow(&node->flow, ofn->range_af, output);
    }
    ds_put_char_multiple(output, '=', 79);
    ds_put_cstr(output, "\n\n");
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
    } else {
        if (xout.slow) {
            explain_slow_path(xout.slow, output);
        }
        if (packet) {
            execute_actions_except_outputs(ofproto->backer->dpif, packet,
                                           &initial_flow, &odp_actions,
                                           xout.slow, output);
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
void
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
        ofproto_trace_recirc_node(recirc_node, next_ct_states, output);
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
