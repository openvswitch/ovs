/*
 * Copyright (c) 2010, 2011, 2012 Nicira, Inc.
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

#include "ofp-parse.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

#include "autopath.h"
#include "bundle.h"
#include "byte-order.h"
#include "dynamic-string.h"
#include "learn.h"
#include "meta-flow.h"
#include "netdev.h"
#include "multipath.h"
#include "nx-match.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "socket-util.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_parse);

static void ofp_fatal(const char *flow, bool verbose, const char *format, ...)
    NO_RETURN;

static uint8_t
str_to_table_id(const char *str)
{
    int table_id;

    if (!str_to_int(str, 10, &table_id) || table_id < 0 || table_id > 255) {
        ovs_fatal(0, "invalid table \"%s\"", str);
    }
    return table_id;
}

static uint16_t
str_to_u16(const char *str, const char *name)
{
    int value;

    if (!str_to_int(str, 0, &value) || value < 0 || value > 65535) {
        ovs_fatal(0, "invalid %s \"%s\"", name, str);
    }
    return value;
}

static uint32_t
str_to_u32(const char *str)
{
    char *tail;
    uint32_t value;

    if (!str[0]) {
        ovs_fatal(0, "missing required numeric argument");
    }

    errno = 0;
    value = strtoul(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        ovs_fatal(0, "invalid numeric format %s", str);
    }
    return value;
}

static uint64_t
str_to_u64(const char *str)
{
    char *tail;
    uint64_t value;

    if (!str[0]) {
        ovs_fatal(0, "missing required numeric argument");
    }

    errno = 0;
    value = strtoull(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        ovs_fatal(0, "invalid numeric format %s", str);
    }
    return value;
}

static void
str_to_mac(const char *str, uint8_t mac[6])
{
    if (sscanf(str, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))
        != ETH_ADDR_SCAN_COUNT) {
        ovs_fatal(0, "invalid mac address %s", str);
    }
}

static void
str_to_ip(const char *str, ovs_be32 *ip)
{
    struct in_addr in_addr;

    if (lookup_ip(str, &in_addr)) {
        ovs_fatal(0, "%s: could not convert to IP address", str);
    }
    *ip = in_addr.s_addr;
}

static struct ofp_action_output *
put_output_action(struct ofpbuf *b, uint16_t port)
{
    struct ofp_action_output *oao;

    oao = ofputil_put_OFPAT10_OUTPUT(b);
    oao->port = htons(port);
    return oao;
}

static void
parse_enqueue(struct ofpbuf *b, char *arg)
{
    char *sp = NULL;
    char *port = strtok_r(arg, ":q", &sp);
    char *queue = strtok_r(NULL, "", &sp);
    struct ofp_action_enqueue *oae;

    if (port == NULL || queue == NULL) {
        ovs_fatal(0, "\"enqueue\" syntax is \"enqueue:PORT:QUEUE\"");
    }

    oae = ofputil_put_OFPAT10_ENQUEUE(b);
    oae->port = htons(str_to_u32(port));
    oae->queue_id = htonl(str_to_u32(queue));
}

static void
parse_output(struct ofpbuf *b, char *arg)
{
    if (strchr(arg, '[')) {
        struct nx_action_output_reg *naor;
        struct mf_subfield src;

        mf_parse_subfield(&src, arg);

        naor = ofputil_put_NXAST_OUTPUT_REG(b);
        naor->ofs_nbits = nxm_encode_ofs_nbits(src.ofs, src.n_bits);
        naor->src = htonl(src.field->nxm_header);
        naor->max_len = htons(UINT16_MAX);
    } else {
        put_output_action(b, str_to_u32(arg));
    }
}

static void
parse_resubmit(struct ofpbuf *b, char *arg)
{
    struct nx_action_resubmit *nar;
    char *in_port_s, *table_s;
    uint16_t in_port;
    uint8_t table;

    in_port_s = strsep(&arg, ",");
    if (in_port_s && in_port_s[0]) {
        if (!ofputil_port_from_string(in_port_s, &in_port)) {
            in_port = str_to_u32(in_port_s);
        }
    } else {
        in_port = OFPP_IN_PORT;
    }

    table_s = strsep(&arg, ",");
    table = table_s && table_s[0] ? str_to_u32(table_s) : 255;

    if (in_port == OFPP_IN_PORT && table == 255) {
        ovs_fatal(0, "at least one \"in_port\" or \"table\" must be specified "
                  " on resubmit");
    }

    if (in_port != OFPP_IN_PORT && table == 255) {
        nar = ofputil_put_NXAST_RESUBMIT(b);
    } else {
        nar = ofputil_put_NXAST_RESUBMIT_TABLE(b);
        nar->table = table;
    }
    nar->in_port = htons(in_port);
}

static void
parse_set_tunnel(struct ofpbuf *b, const char *arg)
{
    uint64_t tun_id = str_to_u64(arg);
    if (tun_id > UINT32_MAX) {
        ofputil_put_NXAST_SET_TUNNEL64(b)->tun_id = htonll(tun_id);
    } else {
        ofputil_put_NXAST_SET_TUNNEL(b)->tun_id = htonl(tun_id);
    }
}

static void
parse_note(struct ofpbuf *b, const char *arg)
{
    size_t start_ofs = b->size;
    struct nx_action_note *nan;
    int remainder;
    size_t len;

    nan = ofputil_put_NXAST_NOTE(b);

    b->size -= sizeof nan->note;
    while (*arg != '\0') {
        uint8_t byte;
        bool ok;

        if (*arg == '.') {
            arg++;
        }
        if (*arg == '\0') {
            break;
        }

        byte = hexits_value(arg, 2, &ok);
        if (!ok) {
            ovs_fatal(0, "bad hex digit in `note' argument");
        }
        ofpbuf_put(b, &byte, 1);

        arg += 2;
    }

    len = b->size - start_ofs;
    remainder = len % OFP_ACTION_ALIGN;
    if (remainder) {
        ofpbuf_put_zeros(b, OFP_ACTION_ALIGN - remainder);
    }
    nan = (struct nx_action_note *)((char *)b->data + start_ofs);
    nan->len = htons(b->size - start_ofs);
}

static void
parse_fin_timeout(struct ofpbuf *b, char *arg)
{
    struct nx_action_fin_timeout *naft;
    char *key, *value;

    naft = ofputil_put_NXAST_FIN_TIMEOUT(b);
    while (ofputil_parse_key_value(&arg, &key, &value)) {
        if (!strcmp(key, "idle_timeout")) {
            naft->fin_idle_timeout = htons(str_to_u16(value, key));
        } else if (!strcmp(key, "hard_timeout")) {
            naft->fin_hard_timeout = htons(str_to_u16(value, key));
        } else {
            ovs_fatal(0, "invalid key '%s' in 'fin_timeout' argument", key);
        }
    }
}

static void
parse_controller(struct ofpbuf *b, char *arg)
{
    enum ofp_packet_in_reason reason = OFPR_ACTION;
    uint16_t controller_id = 0;
    uint16_t max_len = UINT16_MAX;

    if (!arg[0]) {
        /* Use defaults. */
    } else if (strspn(arg, "0123456789") == strlen(arg)) {
        max_len = str_to_u16(arg, "max_len");
    } else {
        char *name, *value;

        while (ofputil_parse_key_value(&arg, &name, &value)) {
            if (!strcmp(name, "reason")) {
                if (!ofputil_packet_in_reason_from_string(value, &reason)) {
                    ovs_fatal(0, "unknown reason \"%s\"", value);
                }
            } else if (!strcmp(name, "max_len")) {
                max_len = str_to_u16(value, "max_len");
            } else if (!strcmp(name, "id")) {
                controller_id = str_to_u16(value, "id");
            } else {
                ovs_fatal(0, "unknown key \"%s\" parsing controller action",
                          name);
            }
        }
    }

    if (reason == OFPR_ACTION && controller_id == 0) {
        put_output_action(b, OFPP_CONTROLLER)->max_len = htons(max_len);
    } else {
        struct nx_action_controller *nac;

        nac = ofputil_put_NXAST_CONTROLLER(b);
        nac->max_len = htons(max_len);
        nac->reason = reason;
        nac->controller_id = htons(controller_id);
    }
}

static void
parse_named_action(enum ofputil_action_code code, const struct flow *flow,
                   struct ofpbuf *b, char *arg)
{
    struct ofp_action_dl_addr *oada;
    struct ofp_action_vlan_pcp *oavp;
    struct ofp_action_vlan_vid *oavv;
    struct ofp_action_nw_addr *oana;
    struct ofp_action_tp_port *oata;

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
        NOT_REACHED();

    case OFPUTIL_OFPAT10_OUTPUT:
        parse_output(b, arg);
        break;

    case OFPUTIL_OFPAT10_SET_VLAN_VID:
        oavv = ofputil_put_OFPAT10_SET_VLAN_VID(b);
        oavv->vlan_vid = htons(str_to_u32(arg));
        break;

    case OFPUTIL_OFPAT10_SET_VLAN_PCP:
        oavp = ofputil_put_OFPAT10_SET_VLAN_PCP(b);
        oavp->vlan_pcp = str_to_u32(arg);
        break;

    case OFPUTIL_OFPAT10_STRIP_VLAN:
        ofputil_put_OFPAT10_STRIP_VLAN(b);
        break;

    case OFPUTIL_OFPAT10_SET_DL_SRC:
    case OFPUTIL_OFPAT10_SET_DL_DST:
        oada = ofputil_put_action(code, b);
        str_to_mac(arg, oada->dl_addr);
        break;

    case OFPUTIL_OFPAT10_SET_NW_SRC:
    case OFPUTIL_OFPAT10_SET_NW_DST:
        oana = ofputil_put_action(code, b);
        str_to_ip(arg, &oana->nw_addr);
        break;

    case OFPUTIL_OFPAT10_SET_NW_TOS:
        ofputil_put_OFPAT10_SET_NW_TOS(b)->nw_tos = str_to_u32(arg);
        break;

    case OFPUTIL_OFPAT10_SET_TP_SRC:
    case OFPUTIL_OFPAT10_SET_TP_DST:
        oata = ofputil_put_action(code, b);
        oata->tp_port = htons(str_to_u32(arg));
        break;

    case OFPUTIL_OFPAT10_ENQUEUE:
        parse_enqueue(b, arg);
        break;

    case OFPUTIL_NXAST_RESUBMIT:
        parse_resubmit(b, arg);
        break;

    case OFPUTIL_NXAST_SET_TUNNEL:
        parse_set_tunnel(b, arg);
        break;

    case OFPUTIL_NXAST_SET_QUEUE:
        ofputil_put_NXAST_SET_QUEUE(b)->queue_id = htonl(str_to_u32(arg));
        break;

    case OFPUTIL_NXAST_POP_QUEUE:
        ofputil_put_NXAST_POP_QUEUE(b);
        break;

    case OFPUTIL_NXAST_REG_MOVE:
        nxm_parse_reg_move(ofputil_put_NXAST_REG_MOVE(b), arg);
        break;

    case OFPUTIL_NXAST_REG_LOAD:
        nxm_parse_reg_load(ofputil_put_NXAST_REG_LOAD(b), arg);
        break;

    case OFPUTIL_NXAST_NOTE:
        parse_note(b, arg);
        break;

    case OFPUTIL_NXAST_SET_TUNNEL64:
        ofputil_put_NXAST_SET_TUNNEL64(b)->tun_id = htonll(str_to_u64(arg));
        break;

    case OFPUTIL_NXAST_MULTIPATH:
        multipath_parse(ofputil_put_NXAST_MULTIPATH(b), arg);
        break;

    case OFPUTIL_NXAST_AUTOPATH:
        autopath_parse(ofputil_put_NXAST_AUTOPATH(b), arg);
        break;

    case OFPUTIL_NXAST_BUNDLE:
        bundle_parse(b, arg);
        break;

    case OFPUTIL_NXAST_BUNDLE_LOAD:
        bundle_parse_load(b, arg);
        break;

    case OFPUTIL_NXAST_RESUBMIT_TABLE:
    case OFPUTIL_NXAST_OUTPUT_REG:
        NOT_REACHED();

    case OFPUTIL_NXAST_LEARN:
        learn_parse(b, arg, flow);
        break;

    case OFPUTIL_NXAST_EXIT:
        ofputil_put_NXAST_EXIT(b);
        break;

    case OFPUTIL_NXAST_DEC_TTL:
        ofputil_put_NXAST_DEC_TTL(b);
        break;

    case OFPUTIL_NXAST_FIN_TIMEOUT:
        parse_fin_timeout(b, arg);
        break;

    case OFPUTIL_NXAST_CONTROLLER:
        parse_controller(b, arg);
        break;
    }
}

static void
str_to_action(const struct flow *flow, char *str, struct ofpbuf *b)
{
    char *pos, *act, *arg;
    int n_actions;

    pos = str;
    n_actions = 0;
    while (ofputil_parse_key_value(&pos, &act, &arg)) {
        uint16_t port;
        int code;

        code = ofputil_action_code_from_name(act);
        if (code >= 0) {
            parse_named_action(code, flow, b, arg);
        } else if (!strcasecmp(act, "drop")) {
            /* A drop action in OpenFlow occurs by just not setting
             * an action. */
            if (n_actions) {
                ovs_fatal(0, "Drop actions must not be preceded by other "
                          "actions");
            } else if (ofputil_parse_key_value(&pos, &act, &arg)) {
                ovs_fatal(0, "Drop actions must not be followed by other "
                          "actions");
            }
            break;
        } else if (ofputil_port_from_string(act, &port)) {
            put_output_action(b, port);
        } else {
            ovs_fatal(0, "Unknown action: %s", act);
        }
        n_actions++;
    }
}

struct protocol {
    const char *name;
    uint16_t dl_type;
    uint8_t nw_proto;
};

static bool
parse_protocol(const char *name, const struct protocol **p_out)
{
    static const struct protocol protocols[] = {
        { "ip", ETH_TYPE_IP, 0 },
        { "arp", ETH_TYPE_ARP, 0 },
        { "icmp", ETH_TYPE_IP, IPPROTO_ICMP },
        { "tcp", ETH_TYPE_IP, IPPROTO_TCP },
        { "udp", ETH_TYPE_IP, IPPROTO_UDP },
        { "ipv6", ETH_TYPE_IPV6, 0 },
        { "ip6", ETH_TYPE_IPV6, 0 },
        { "icmp6", ETH_TYPE_IPV6, IPPROTO_ICMPV6 },
        { "tcp6", ETH_TYPE_IPV6, IPPROTO_TCP },
        { "udp6", ETH_TYPE_IPV6, IPPROTO_UDP },
    };
    const struct protocol *p;

    for (p = protocols; p < &protocols[ARRAY_SIZE(protocols)]; p++) {
        if (!strcmp(p->name, name)) {
            *p_out = p;
            return true;
        }
    }
    *p_out = NULL;
    return false;
}

static void
ofp_fatal(const char *flow, bool verbose, const char *format, ...)
{
    va_list args;

    if (verbose) {
        fprintf(stderr, "%s:\n", flow);
    }

    va_start(args, format);
    ovs_fatal_valist(0, format, args);
}

static void
parse_field(const struct mf_field *mf, const char *s, struct cls_rule *rule)
{
    union mf_value value, mask;
    char *error;

    error = mf_parse(mf, s, &value, &mask);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    mf_set(mf, &value, &mask, rule);
}

/* Convert 'str_' (as described in the Flow Syntax section of the ovs-ofctl man
 * page) into 'fm' for sending the specified flow_mod 'command' to a switch.
 * If 'actions' is specified, an action must be in 'string' and may be expanded
 * or reallocated.
 *
 * To parse syntax for an OFPT_FLOW_MOD (or NXT_FLOW_MOD), use an OFPFC_*
 * constant for 'command'.  To parse syntax for an OFPST_FLOW or
 * OFPST_AGGREGATE (or NXST_FLOW or NXST_AGGREGATE), use -1 for 'command'. */
void
parse_ofp_str(struct ofputil_flow_mod *fm, int command, const char *str_,
              bool verbose)
{
    enum {
        F_OUT_PORT = 1 << 0,
        F_ACTIONS = 1 << 1,
        F_TIMEOUT = 1 << 3,
        F_PRIORITY = 1 << 4,
        F_FLAGS = 1 << 5,
    } fields;
    char *string = xstrdup(str_);
    char *save_ptr = NULL;
    char *act_str = NULL;
    char *name;

    switch (command) {
    case -1:
        fields = F_OUT_PORT;
        break;

    case OFPFC_ADD:
        fields = F_ACTIONS | F_TIMEOUT | F_PRIORITY | F_FLAGS;
        break;

    case OFPFC_DELETE:
        fields = F_OUT_PORT;
        break;

    case OFPFC_DELETE_STRICT:
        fields = F_OUT_PORT | F_PRIORITY;
        break;

    case OFPFC_MODIFY:
        fields = F_ACTIONS | F_TIMEOUT | F_PRIORITY | F_FLAGS;
        break;

    case OFPFC_MODIFY_STRICT:
        fields = F_ACTIONS | F_TIMEOUT | F_PRIORITY | F_FLAGS;
        break;

    default:
        NOT_REACHED();
    }

    cls_rule_init_catchall(&fm->cr, OFP_DEFAULT_PRIORITY);
    fm->cookie = htonll(0);
    fm->cookie_mask = htonll(0);
    if (command == OFPFC_MODIFY || command == OFPFC_MODIFY_STRICT) {
        /* For modify, by default, don't update the cookie. */
        fm->new_cookie = htonll(UINT64_MAX);
    } else{
        fm->new_cookie = htonll(0);
    }
    fm->table_id = 0xff;
    fm->command = command;
    fm->idle_timeout = OFP_FLOW_PERMANENT;
    fm->hard_timeout = OFP_FLOW_PERMANENT;
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_NONE;
    fm->flags = 0;
    if (fields & F_ACTIONS) {
        act_str = strstr(string, "action");
        if (!act_str) {
            ofp_fatal(str_, verbose, "must specify an action");
        }
        *act_str = '\0';

        act_str = strchr(act_str + 1, '=');
        if (!act_str) {
            ofp_fatal(str_, verbose, "must specify an action");
        }

        act_str++;
    }
    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {
        const struct protocol *p;

        if (parse_protocol(name, &p)) {
            cls_rule_set_dl_type(&fm->cr, htons(p->dl_type));
            if (p->nw_proto) {
                cls_rule_set_nw_proto(&fm->cr, p->nw_proto);
            }
        } else if (fields & F_FLAGS && !strcmp(name, "send_flow_rem")) {
            fm->flags |= OFPFF_SEND_FLOW_REM;
        } else if (fields & F_FLAGS && !strcmp(name, "check_overlap")) {
            fm->flags |= OFPFF_CHECK_OVERLAP;
        } else {
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                ofp_fatal(str_, verbose, "field %s missing value", name);
            }

            if (!strcmp(name, "table")) {
                fm->table_id = str_to_table_id(value);
            } else if (!strcmp(name, "out_port")) {
                fm->out_port = atoi(value);
            } else if (fields & F_PRIORITY && !strcmp(name, "priority")) {
                fm->cr.priority = str_to_u16(value, name);
            } else if (fields & F_TIMEOUT && !strcmp(name, "idle_timeout")) {
                fm->idle_timeout = str_to_u16(value, name);
            } else if (fields & F_TIMEOUT && !strcmp(name, "hard_timeout")) {
                fm->hard_timeout = str_to_u16(value, name);
            } else if (!strcmp(name, "cookie")) {
                char *mask = strchr(value, '/');

                if (mask) {
                    /* A mask means we're searching for a cookie. */
                    if (command == OFPFC_ADD) {
                        ofp_fatal(str_, verbose, "flow additions cannot use "
                                  "a cookie mask");
                    }
                    *mask = '\0';
                    fm->cookie = htonll(str_to_u64(value));
                    fm->cookie_mask = htonll(str_to_u64(mask+1));
                } else {
                    /* No mask means that the cookie is being set. */
                    if (command != OFPFC_ADD && command != OFPFC_MODIFY
                            && command != OFPFC_MODIFY_STRICT) {
                        ofp_fatal(str_, verbose, "cannot set cookie");
                    }
                    fm->new_cookie = htonll(str_to_u64(value));
                }
            } else if (mf_from_name(name)) {
                parse_field(mf_from_name(name), value, &fm->cr);
            } else if (!strcmp(name, "duration")
                       || !strcmp(name, "n_packets")
                       || !strcmp(name, "n_bytes")) {
                /* Ignore these, so that users can feed the output of
                 * "ovs-ofctl dump-flows" back into commands that parse
                 * flows. */
            } else {
                ofp_fatal(str_, verbose, "unknown keyword %s", name);
            }
        }
    }
    if (!fm->cookie_mask && fm->new_cookie == htonll(UINT64_MAX)
            && (command == OFPFC_MODIFY || command == OFPFC_MODIFY_STRICT)) {
        /* On modifies without a mask, we are supposed to add a flow if
         * one does not exist.  If a cookie wasn't been specified, use a
         * default of zero. */
        fm->new_cookie = htonll(0);
    }
    if (fields & F_ACTIONS) {
        struct ofpbuf actions;

        ofpbuf_init(&actions, sizeof(union ofp_action));
        str_to_action(&fm->cr.flow, act_str, &actions);
        fm->actions = ofpbuf_steal_data(&actions);
        fm->n_actions = actions.size / sizeof(union ofp_action);
    } else {
        fm->actions = NULL;
        fm->n_actions = 0;
    }

    free(string);
}

/* Parses 's' as a set of OpenFlow actions and appends the actions to
 * 'actions'.
 *
 * Prints an error on stderr and aborts the program if 's' syntax is
 * invalid. */
void
parse_ofp_actions(const char *s_, struct ofpbuf *actions)
{
    char *s = xstrdup(s_);
    str_to_action(NULL, s, actions);
    free(s);
}

/* Parses 'string' as an OFPT_FLOW_MOD or NXT_FLOW_MOD with command 'command'
 * (one of OFPFC_*) into 'fm'. */
void
parse_ofp_flow_mod_str(struct ofputil_flow_mod *fm, const char *string,
                       uint16_t command, bool verbose)
{
    struct cls_rule rule_copy;

    parse_ofp_str(fm, command, string, verbose);

    /* Normalize a copy of the rule.  This ensures that non-normalized flows
     * get logged but doesn't affect what gets sent to the switch, so that the
     * switch can do whatever it likes with the flow. */
    rule_copy = fm->cr;
    ofputil_normalize_rule(&rule_copy);
}

void
parse_ofp_flow_mod_file(const char *file_name, uint16_t command,
                        struct ofputil_flow_mod **fms, size_t *n_fms)
{
    size_t allocated_fms;
    FILE *stream;
    struct ds s;

    stream = !strcmp(file_name, "-") ? stdin : fopen(file_name, "r");
    if (stream == NULL) {
        ovs_fatal(errno, "%s: open", file_name);
    }

    allocated_fms = *n_fms;
    ds_init(&s);
    while (!ds_get_preprocessed_line(&s, stream)) {
        if (*n_fms >= allocated_fms) {
            *fms = x2nrealloc(*fms, &allocated_fms, sizeof **fms);
        }
        parse_ofp_flow_mod_str(&(*fms)[*n_fms], ds_cstr(&s), command, false);
        *n_fms += 1;
    }
    ds_destroy(&s);

    if (stream != stdin) {
        fclose(stream);
    }
}

void
parse_ofp_flow_stats_request_str(struct ofputil_flow_stats_request *fsr,
                                 bool aggregate, const char *string)
{
    struct ofputil_flow_mod fm;

    parse_ofp_str(&fm, -1, string, false);
    fsr->aggregate = aggregate;
    fsr->cookie = fm.cookie;
    fsr->cookie_mask = fm.cookie_mask;
    fsr->match = fm.cr;
    fsr->out_port = fm.out_port;
    fsr->table_id = fm.table_id;
}

/* Parses a specification of a flow from 's' into 'flow'.  's' must take the
 * form FIELD=VALUE[,FIELD=VALUE]... where each FIELD is the name of a
 * mf_field.  Fields must be specified in a natural order for satisfying
 * prerequisites.
 *
 * Returns NULL on success, otherwise a malloc()'d string that explains the
 * problem. */
char *
parse_ofp_exact_flow(struct flow *flow, const char *s)
{
    char *pos, *key, *value_s;
    char *error = NULL;
    char *copy;

    memset(flow, 0, sizeof *flow);

    pos = copy = xstrdup(s);
    while (ofputil_parse_key_value(&pos, &key, &value_s)) {
        const struct protocol *p;
        if (parse_protocol(key, &p)) {
            if (flow->dl_type) {
                error = xasprintf("%s: Ethernet type set multiple times", s);
                goto exit;
            }
            flow->dl_type = htons(p->dl_type);

            if (p->nw_proto) {
                if (flow->nw_proto) {
                    error = xasprintf("%s: network protocol set "
                                      "multiple times", s);
                    goto exit;
                }
                flow->nw_proto = p->nw_proto;
            }
        } else {
            const struct mf_field *mf;
            union mf_value value;
            char *field_error;

            mf = mf_from_name(key);
            if (!mf) {
                error = xasprintf("%s: unknown field %s", s, key);
                goto exit;
            }

            if (!mf_are_prereqs_ok(mf, flow)) {
                error = xasprintf("%s: prerequisites not met for setting %s",
                                  s, key);
                goto exit;
            }

            if (!mf_is_zero(mf, flow)) {
                error = xasprintf("%s: field %s set multiple times", s, key);
                goto exit;
            }

            field_error = mf_parse_value(mf, value_s, &value);
            if (field_error) {
                error = xasprintf("%s: bad value for %s (%s)",
                                  s, key, field_error);
                free(field_error);
                goto exit;
            }

            mf_set_flow_value(mf, &value, flow);
        }
    }

exit:
    free(copy);

    if (error) {
        memset(flow, 0, sizeof *flow);
    }
    return error;
}
