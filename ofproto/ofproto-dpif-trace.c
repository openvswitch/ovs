/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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

#include "dpif.h"
#include "ofproto-dpif-xlate.h"
#include "openvswitch/ofp-parse.h"
#include "unixctl.h"

struct trace_ctx {
    struct xlate_out xout;
    struct xlate_in xin;
    const struct flow *key;
    struct flow flow;
    struct ds *result;
    struct flow_wildcards wc;
    struct ofpbuf odp_actions;
};

static void ofproto_trace(struct ofproto_dpif *, struct flow *,
                          const struct dp_packet *packet,
                          const struct ofpact[], size_t ofpacts_len,
                          struct ds *);

static void
trace_format_rule(struct ofproto *ofproto, struct ds *result, int level,
                  const struct rule_dpif *rule)
{
    const struct rule_actions *actions;
    ovs_be64 cookie;

    ds_put_char_multiple(result, '\t', level);
    if (!rule) {
        ds_put_cstr(result, "No match\n");
        return;
    }

    ovs_mutex_lock(&rule->up.mutex);
    cookie = rule->up.flow_cookie;
    ovs_mutex_unlock(&rule->up.mutex);

    ds_put_format(result, "Rule: table=%"PRIu8" cookie=%#"PRIx64" ",
                  rule ? rule->up.table_id : 0, ntohll(cookie));
    cls_rule_format(&rule->up.cr, ofproto_get_tun_tab(ofproto), result);
    ds_put_char(result, '\n');

    actions = rule_get_actions(&rule->up);

    ds_put_char_multiple(result, '\t', level);
    ds_put_cstr(result, "OpenFlow actions=");
    ofpacts_format(actions->ofpacts, actions->ofpacts_len, result);
    ds_put_char(result, '\n');
}

static void
trace_format_flow(struct ds *result, int level, const char *title,
                  struct trace_ctx *trace)
{
    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s: ", title);
    /* Do not report unchanged flows for resubmits. */
    if ((level > 0 && flow_equal(&trace->xin.flow, &trace->flow))
        || (level == 0 && flow_equal(&trace->xin.flow, trace->key))) {
        ds_put_cstr(result, "unchanged");
    } else {
        flow_format(result, &trace->xin.flow);
        trace->flow = trace->xin.flow;
    }
    ds_put_char(result, '\n');
}

static void
trace_format_regs(struct ds *result, int level, const char *title,
                  struct trace_ctx *trace)
{
    size_t i;

    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s:", title);
    for (i = 0; i < FLOW_N_REGS; i++) {
        ds_put_format(result, " reg%"PRIuSIZE"=0x%"PRIx32, i, trace->flow.regs[i]);
    }
    ds_put_char(result, '\n');
}

static void
trace_format_odp(struct ds *result, int level, const char *title,
                 struct trace_ctx *trace)
{
    struct ofpbuf *odp_actions = &trace->odp_actions;

    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s: ", title);
    format_odp_actions(result, odp_actions->data, odp_actions->size);
    ds_put_char(result, '\n');
}

static void
trace_format_megaflow(struct ds *result, int level, const char *title,
                      struct trace_ctx *trace)
{
    struct match match;

    ds_put_char_multiple(result, '\t', level);
    ds_put_format(result, "%s: ", title);
    match_init(&match, trace->key, &trace->wc);
    match_format(&match, result, OFP_DEFAULT_PRIORITY);
    ds_put_char(result, '\n');
}

static void trace_report(struct xlate_in *, int indentation,
                         const char *format, ...)
    OVS_PRINTF_FORMAT(3, 4);
static void trace_report_valist(struct xlate_in *, int indentation,
                                const char *format, va_list args)
    OVS_PRINTF_FORMAT(3, 0);

static void
trace_resubmit(struct xlate_in *xin, struct rule_dpif *rule, int indentation)
{
    struct trace_ctx *trace = CONTAINER_OF(xin, struct trace_ctx, xin);
    struct ds *result = trace->result;

    if (!indentation) {
        if (rule == xin->ofproto->miss_rule) {
            trace_report(xin, indentation,
                         "No match, flow generates \"packet in\"s.");
        } else if (rule == xin->ofproto->no_packet_in_rule) {
            trace_report(xin, indentation, "No match, packets dropped because "
                         "OFPPC_NO_PACKET_IN is set on in_port.");
        } else if (rule == xin->ofproto->drop_frags_rule) {
            trace_report(xin, indentation,
                         "Packets dropped because they are IP fragments and "
                         "the fragment handling mode is \"drop\".");
        }
    }

    ds_put_char(result, '\n');
    if (indentation) {
        trace_format_flow(result, indentation, "Resubmitted flow", trace);
        trace_format_regs(result, indentation, "Resubmitted regs", trace);
        trace_format_odp(result,  indentation, "Resubmitted  odp", trace);
        trace_format_megaflow(result, indentation, "Resubmitted megaflow",
                              trace);
    }
    trace_format_rule(&xin->ofproto->up, result, indentation, rule);
}

static void
trace_report_valist(struct xlate_in *xin, int indentation,
                    const char *format, va_list args)
{
    struct trace_ctx *trace = CONTAINER_OF(xin, struct trace_ctx, xin);
    struct ds *result = trace->result;

    ds_put_char_multiple(result, '\t', indentation);
    ds_put_format_valist(result, format, args);
    ds_put_char(result, '\n');
}

static void
trace_report(struct xlate_in *xin, int indentation, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    trace_report_valist(xin, indentation, format, args);
    va_end(args);
}

/* Parses the 'argc' elements of 'argv', ignoring argv[0].  The following
 * forms are supported:
 *
 *     - [dpname] odp_flow [-generate | packet]
 *     - bridge br_flow [-generate | packet]
 *
 * On success, initializes '*ofprotop' and 'flow' and returns NULL.  On failure
 * returns a nonnull malloced error message. */
static char * OVS_WARN_UNUSED_RESULT
parse_flow_and_packet(int argc, const char *argv[],
                      struct ofproto_dpif **ofprotop, struct flow *flow,
                      struct dp_packet **packetp)
{
    const struct dpif_backer *backer = NULL;
    const char *error = NULL;
    char *m_err = NULL;
    struct simap port_names = SIMAP_INITIALIZER(&port_names);
    struct dp_packet *packet;
    struct ofpbuf odp_key;
    struct ofpbuf odp_mask;

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

        *ofprotop = ofproto_dpif_lookup(argv[1]);
        if (!*ofprotop) {
            error = "Unknown bridge name";
            goto exit;
        }

        err = parse_ofp_exact_flow(flow, NULL,
                                   ofproto_get_tun_tab(&(*ofprotop)->up),
                                   argv[argc - 1], NULL);
        if (err) {
            m_err = xasprintf("Bad openflow flow syntax: %s", err);
            free(err);
            goto exit;
        }
    }

    /* Generate a packet, if requested. */
    if (packet) {
        if (!dp_packet_size(packet)) {
            flow_compose(packet, flow);
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
ofproto_unixctl_trace(struct unixctl_conn *conn, int argc, const char *argv[],
                      void *aux OVS_UNUSED)
{
    struct ofproto_dpif *ofproto;
    struct dp_packet *packet;
    char *error;
    struct flow flow;

    error = parse_flow_and_packet(argc, argv, &ofproto, &flow, &packet);
    if (!error) {
        struct ds result;

        ds_init(&result);
        ofproto_trace(ofproto, &flow, packet, NULL, 0, &result);
        unixctl_command_reply(conn, ds_cstr(&result));
        ds_destroy(&result);
        dp_packet_delete(packet);
    } else {
        unixctl_command_reply_error(conn, error);
        free(error);
    }
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
    struct flow flow;
    uint16_t in_port;

    /* Three kinds of error return values! */
    enum ofperr retval;
    char *error;

    packet = NULL;
    ds_init(&result);
    ofpbuf_init(&ofpacts, 0);

    /* Parse actions. */
    error = ofpacts_parse_actions(argv[--argc], &ofpacts, &usable_protocols);
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

    error = parse_flow_and_packet(argc, argv, &ofproto, &flow, &packet);
    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
        goto exit;
    }

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
    in_port = ofp_to_u16(flow.in_port.ofp_port);
    if (in_port >= ofproto->up.max_ports && in_port < ofp_to_u16(OFPP_MAX)) {
        unixctl_command_reply_error(conn, "invalid in_port");
        goto exit;
    }
    if (enforce_consistency) {
        retval = ofpacts_check_consistency(ofpacts.data, ofpacts.size, &flow,
                                           u16_to_ofp(ofproto->up.max_ports),
                                           0, ofproto->up.n_tables,
                                           usable_protocols);
    } else {
        retval = ofpacts_check(ofpacts.data, ofpacts.size, &flow,
                               u16_to_ofp(ofproto->up.max_ports), 0,
                               ofproto->up.n_tables, &usable_protocols);
    }
    if (!retval) {
        retval = ofproto_check_ofpacts(&ofproto->up, ofpacts.data,
                                       ofpacts.size);
    }

    if (retval) {
        ds_clear(&result);
        ds_put_format(&result, "Bad actions: %s", ofperr_to_string(retval));
        unixctl_command_reply_error(conn, ds_cstr(&result));
        goto exit;
    }

    ofproto_trace(ofproto, &flow, packet,
                  ofpacts.data, ofpacts.size, &result);
    unixctl_command_reply(conn, ds_cstr(&result));

exit:
    ds_destroy(&result);
    dp_packet_delete(packet);
    ofpbuf_uninit(&ofpacts);
}

/* Implements a "trace" through 'ofproto''s flow table, appending a textual
 * description of the results to 'ds'.
 *
 * The trace follows a packet with the specified 'flow' through the flow
 * table.  'packet' may be nonnull to trace an actual packet, with consequent
 * side effects (if it is nonnull then its flow must be 'flow').
 *
 * If 'ofpacts' is nonnull then its 'ofpacts_len' bytes specify the actions to
 * trace, otherwise the actions are determined by a flow table lookup. */
static void
ofproto_trace(struct ofproto_dpif *ofproto, struct flow *flow,
              const struct dp_packet *packet,
              const struct ofpact ofpacts[], size_t ofpacts_len,
              struct ds *ds)
{
    struct trace_ctx trace;
    enum xlate_error error;

    ds_put_format(ds, "Bridge: %s\n", ofproto->up.name);
    ds_put_cstr(ds, "Flow: ");
    flow_format(ds, flow);
    ds_put_char(ds, '\n');

    ofpbuf_init(&trace.odp_actions, 0);

    trace.result = ds;
    trace.key = flow; /* Original flow key, used for megaflow. */
    trace.flow = *flow; /* May be modified by actions. */
    xlate_in_init(&trace.xin, ofproto,
                  ofproto_dpif_get_tables_version(ofproto), flow,
                  flow->in_port.ofp_port, NULL, ntohs(flow->tcp_flags),
                  packet, &trace.wc, &trace.odp_actions);
    trace.xin.ofpacts = ofpacts;
    trace.xin.ofpacts_len = ofpacts_len;
    trace.xin.resubmit_hook = trace_resubmit;
    trace.xin.report_hook = trace_report_valist;

    error = xlate_actions(&trace.xin, &trace.xout);
    ds_put_char(ds, '\n');
    trace.xin.flow.actset_output = 0;
    trace_format_flow(ds, 0, "Final flow", &trace);
    trace_format_megaflow(ds, 0, "Megaflow", &trace);

    ds_put_cstr(ds, "Datapath actions: ");
    format_odp_actions(ds, trace.odp_actions.data, trace.odp_actions.size);

    if (error != XLATE_OK) {
        ds_put_format(ds, "\nTranslation failed (%s), packet is dropped.\n",
                      xlate_strerror(error));
    } else if (trace.xout.slow) {
        enum slow_path_reason slow;

        ds_put_cstr(ds, "\nThis flow is handled by the userspace "
                    "slow path because it:");

        slow = trace.xout.slow;
        while (slow) {
            enum slow_path_reason bit = rightmost_1bit(slow);

            ds_put_format(ds, "\n\t- %s.",
                          slow_path_reason_to_explanation(bit));

            slow &= ~bit;
        }
    }

    xlate_out_uninit(&trace.xout);
    ofpbuf_uninit(&trace.odp_actions);
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
        "{[dp_name] odp_flow | bridge br_flow} [-generate|packet]",
        1, 3, ofproto_unixctl_trace, NULL);
    unixctl_command_register(
        "ofproto/trace-packet-out",
        "[-consistent] {[dp_name] odp_flow | bridge br_flow} [-generate|packet] actions",
        2, 6, ofproto_unixctl_trace_actions, NULL);
}
