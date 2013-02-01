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
#include "multipath.h"
#include "netdev.h"
#include "nx-match.h"
#include "ofp-actions.h"
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

static void
parse_enqueue(char *arg, struct ofpbuf *ofpacts)
{
    char *sp = NULL;
    char *port = strtok_r(arg, ":q", &sp);
    char *queue = strtok_r(NULL, "", &sp);
    struct ofpact_enqueue *enqueue;

    if (port == NULL || queue == NULL) {
        ovs_fatal(0, "\"enqueue\" syntax is \"enqueue:PORT:QUEUE\"");
    }

    enqueue = ofpact_put_ENQUEUE(ofpacts);
    enqueue->port = str_to_u32(port);
    enqueue->queue = str_to_u32(queue);
}

static void
parse_output(char *arg, struct ofpbuf *ofpacts)
{
    if (strchr(arg, '[')) {
        struct ofpact_output_reg *output_reg;

        output_reg = ofpact_put_OUTPUT_REG(ofpacts);
        mf_parse_subfield(&output_reg->src, arg);
        output_reg->max_len = UINT16_MAX;
    } else {
        struct ofpact_output *output;

        output = ofpact_put_OUTPUT(ofpacts);
        output->port = str_to_u32(arg);
        output->max_len = output->port == OFPP_CONTROLLER ? UINT16_MAX : 0;
    }
}

static void
parse_resubmit(char *arg, struct ofpbuf *ofpacts)
{
    struct ofpact_resubmit *resubmit;
    char *in_port_s, *table_s;

    resubmit = ofpact_put_RESUBMIT(ofpacts);

    in_port_s = strsep(&arg, ",");
    if (in_port_s && in_port_s[0]) {
        if (!ofputil_port_from_string(in_port_s, &resubmit->in_port)) {
            ovs_fatal(0, "%s: resubmit to unknown port", in_port_s);
        }
    } else {
        resubmit->in_port = OFPP_IN_PORT;
    }

    table_s = strsep(&arg, ",");
    resubmit->table_id = table_s && table_s[0] ? str_to_u32(table_s) : 255;

    if (resubmit->in_port == OFPP_IN_PORT && resubmit->table_id == 255) {
        ovs_fatal(0, "at least one \"in_port\" or \"table\" must be specified "
                  " on resubmit");
    }
}

static void
parse_note(const char *arg, struct ofpbuf *ofpacts)
{
    struct ofpact_note *note;

    note = ofpact_put_NOTE(ofpacts);
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
        ofpbuf_put(ofpacts, &byte, 1);

        note = ofpacts->l2;
        note->length++;

        arg += 2;
    }
    ofpact_update_len(ofpacts, &note->ofpact);
}

static void
parse_fin_timeout(struct ofpbuf *b, char *arg)
{
    struct ofpact_fin_timeout *oft = ofpact_put_FIN_TIMEOUT(b);
    char *key, *value;

    while (ofputil_parse_key_value(&arg, &key, &value)) {
        if (!strcmp(key, "idle_timeout")) {
            oft->fin_idle_timeout = str_to_u16(value, key);
        } else if (!strcmp(key, "hard_timeout")) {
            oft->fin_hard_timeout = str_to_u16(value, key);
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
        struct ofpact_output *output;

        output = ofpact_put_OUTPUT(b);
        output->port = OFPP_CONTROLLER;
        output->max_len = max_len;
    } else {
        struct ofpact_controller *controller;

        controller = ofpact_put_CONTROLLER(b);
        controller->max_len = max_len;
        controller->reason = reason;
        controller->controller_id = controller_id;
    }
}

static void
parse_noargs_dec_ttl(struct ofpbuf *b)
{
    struct ofpact_cnt_ids *ids;
    uint16_t id = 0;

    ids = ofpact_put_DEC_TTL(b);
    ofpbuf_put(b, &id, sizeof id);
    ids = b->l2;
    ids->n_controllers++;
    ofpact_update_len(b, &ids->ofpact);
}

static void
parse_dec_ttl(struct ofpbuf *b, char *arg)
{
    if (*arg == '\0') {
        parse_noargs_dec_ttl(b);
    } else {
        struct ofpact_cnt_ids *ids;
        char *cntr;

        ids = ofpact_put_DEC_TTL(b);
        ids->ofpact.compat = OFPUTIL_NXAST_DEC_TTL_CNT_IDS;
        for (cntr = strtok_r(arg, ", ", &arg); cntr != NULL;
             cntr = strtok_r(NULL, ", ", &arg)) {
            uint16_t id = atoi(cntr);

            ofpbuf_put(b, &id, sizeof id);
            ids = b->l2;
            ids->n_controllers++;
        }
        if (!ids->n_controllers) {
            ovs_fatal(0, "dec_ttl_cnt_ids: expected at least one controller "
                      "id.");
        }
        ofpact_update_len(b, &ids->ofpact);
    }
}

static void
set_field_parse(const char *arg, struct ofpbuf *ofpacts)
{
    char *orig = xstrdup(arg);
    struct ofpact_reg_load *load = ofpact_put_REG_LOAD(ofpacts);
    char *value;
    char *delim;
    char *key;
    const struct mf_field *mf;
    const char *error;
    union mf_value mf_value;

    value = orig;
    delim = strstr(orig, "->");
    if (!delim) {
        ovs_fatal(0, "%s: missing `->'", orig);
    }
    if (strlen(delim) <= strlen("->")) {
        ovs_fatal(0, "%s: missing field name following `->'", orig);
    }

    key = delim + strlen("->");
    mf = mf_from_name(key);
    if (!mf) {
        ovs_fatal(0, "%s is not valid oxm field name", key);
    }
    if (!mf->writable) {
        ovs_fatal(0, "%s is not allowed to set", key);
    }

    delim[0] = '\0';
    error = mf_parse_value(mf, value, &mf_value);
    if (error) {
        ovs_fatal(0, "%s", error);
    }
    if (!mf_is_value_valid(mf, &mf_value)) {
        ovs_fatal(0, "%s is not valid valid for field %s", value, key);
    }
    ofpact_set_field_init(load, mf, &mf_value);
    free(orig);
}

static void
parse_metadata(struct ofpbuf *b, char *arg)
{
    struct ofpact_metadata *om;
    char *mask = strchr(arg, '/');

    om = ofpact_put_WRITE_METADATA(b);

    if (mask) {
        *mask = '\0';
        om->mask = htonll(str_to_u64(mask + 1));
    } else {
        om->mask = htonll(UINT64_MAX);
    }

    om->metadata = htonll(str_to_u64(arg));
}

static void
parse_named_action(enum ofputil_action_code code, const struct flow *flow,
                   char *arg, struct ofpbuf *ofpacts)
{
    struct ofpact_tunnel *tunnel;
    uint16_t vid;
    ovs_be32 ip;
    uint8_t pcp;
    uint8_t tos;

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
        NOT_REACHED();

    case OFPUTIL_OFPAT10_OUTPUT:
    case OFPUTIL_OFPAT11_OUTPUT:
        parse_output(arg, ofpacts);
        break;

    case OFPUTIL_OFPAT10_SET_VLAN_VID:
    case OFPUTIL_OFPAT11_SET_VLAN_VID:
        vid = str_to_u32(arg);
        if (vid & ~VLAN_VID_MASK) {
            ovs_fatal(0, "%s: not a valid VLAN VID", arg);
        }
        ofpact_put_SET_VLAN_VID(ofpacts)->vlan_vid = vid;
        break;

    case OFPUTIL_OFPAT10_SET_VLAN_PCP:
    case OFPUTIL_OFPAT11_SET_VLAN_PCP:
        pcp = str_to_u32(arg);
        if (pcp & ~7) {
            ovs_fatal(0, "%s: not a valid VLAN PCP", arg);
        }
        ofpact_put_SET_VLAN_PCP(ofpacts)->vlan_pcp = pcp;
        break;

    case OFPUTIL_OFPAT12_SET_FIELD:
        set_field_parse(arg, ofpacts);
        break;

    case OFPUTIL_OFPAT10_STRIP_VLAN:
    case OFPUTIL_OFPAT11_POP_VLAN:
        ofpact_put_STRIP_VLAN(ofpacts);
        break;

    case OFPUTIL_OFPAT10_SET_DL_SRC:
    case OFPUTIL_OFPAT11_SET_DL_SRC:
        str_to_mac(arg, ofpact_put_SET_ETH_SRC(ofpacts)->mac);
        break;

    case OFPUTIL_OFPAT10_SET_DL_DST:
    case OFPUTIL_OFPAT11_SET_DL_DST:
        str_to_mac(arg, ofpact_put_SET_ETH_DST(ofpacts)->mac);
        break;

    case OFPUTIL_OFPAT10_SET_NW_SRC:
    case OFPUTIL_OFPAT11_SET_NW_SRC:
        str_to_ip(arg, &ip);
        ofpact_put_SET_IPV4_SRC(ofpacts)->ipv4 = ip;
        break;

    case OFPUTIL_OFPAT10_SET_NW_DST:
    case OFPUTIL_OFPAT11_SET_NW_DST:
        str_to_ip(arg, &ip);
        ofpact_put_SET_IPV4_DST(ofpacts)->ipv4 = ip;
        break;

    case OFPUTIL_OFPAT10_SET_NW_TOS:
    case OFPUTIL_OFPAT11_SET_NW_TOS:
        tos = str_to_u32(arg);
        if (tos & ~IP_DSCP_MASK) {
            ovs_fatal(0, "%s: not a valid TOS", arg);
        }
        ofpact_put_SET_IPV4_DSCP(ofpacts)->dscp = tos;
        break;

    case OFPUTIL_OFPAT11_DEC_NW_TTL:
        NOT_REACHED();

    case OFPUTIL_OFPAT10_SET_TP_SRC:
    case OFPUTIL_OFPAT11_SET_TP_SRC:
        ofpact_put_SET_L4_SRC_PORT(ofpacts)->port = str_to_u32(arg);
        break;

    case OFPUTIL_OFPAT10_SET_TP_DST:
    case OFPUTIL_OFPAT11_SET_TP_DST:
        ofpact_put_SET_L4_DST_PORT(ofpacts)->port = str_to_u32(arg);
        break;

    case OFPUTIL_OFPAT10_ENQUEUE:
        parse_enqueue(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_RESUBMIT:
        parse_resubmit(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_SET_TUNNEL:
    case OFPUTIL_NXAST_SET_TUNNEL64:
        tunnel = ofpact_put_SET_TUNNEL(ofpacts);
        tunnel->ofpact.compat = code;
        tunnel->tun_id = str_to_u64(arg);
        break;

    case OFPUTIL_NXAST_WRITE_METADATA:
        parse_metadata(ofpacts, arg);
        break;

    case OFPUTIL_NXAST_SET_QUEUE:
        ofpact_put_SET_QUEUE(ofpacts)->queue_id = str_to_u32(arg);
        break;

    case OFPUTIL_NXAST_POP_QUEUE:
        ofpact_put_POP_QUEUE(ofpacts);
        break;

    case OFPUTIL_NXAST_REG_MOVE:
        nxm_parse_reg_move(ofpact_put_REG_MOVE(ofpacts), arg);
        break;

    case OFPUTIL_NXAST_REG_LOAD:
        nxm_parse_reg_load(ofpact_put_REG_LOAD(ofpacts), arg);
        break;

    case OFPUTIL_NXAST_NOTE:
        parse_note(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_MULTIPATH:
        multipath_parse(ofpact_put_MULTIPATH(ofpacts), arg);
        break;

    case OFPUTIL_NXAST_AUTOPATH__DEPRECATED:
        autopath_parse(ofpact_put_AUTOPATH(ofpacts), arg);
        break;

    case OFPUTIL_NXAST_BUNDLE:
        bundle_parse(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_BUNDLE_LOAD:
        bundle_parse_load(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_RESUBMIT_TABLE:
    case OFPUTIL_NXAST_OUTPUT_REG:
    case OFPUTIL_NXAST_DEC_TTL_CNT_IDS:
        NOT_REACHED();

    case OFPUTIL_NXAST_LEARN:
        learn_parse(arg, flow, ofpacts);
        break;

    case OFPUTIL_NXAST_EXIT:
        ofpact_put_EXIT(ofpacts);
        break;

    case OFPUTIL_NXAST_DEC_TTL:
        parse_dec_ttl(ofpacts, arg);
        break;

    case OFPUTIL_NXAST_FIN_TIMEOUT:
        parse_fin_timeout(ofpacts, arg);
        break;

    case OFPUTIL_NXAST_CONTROLLER:
        parse_controller(ofpacts, arg);
        break;
    }
}

static bool
str_to_ofpact__(const struct flow *flow, char *pos, char *act, char *arg,
                struct ofpbuf *ofpacts, int n_actions)
{
    int code = ofputil_action_code_from_name(act);
    if (code >= 0) {
        parse_named_action(code, flow, arg, ofpacts);
    } else if (!strcasecmp(act, "drop")) {
        if (n_actions) {
            ovs_fatal(0, "Drop actions must not be preceded by other "
                      "actions");
        } else if (ofputil_parse_key_value(&pos, &act, &arg)) {
            ovs_fatal(0, "Drop actions must not be followed by other "
                      "actions");
        }
        return false;
    } else {
        uint16_t port;
        if (ofputil_port_from_string(act, &port)) {
            ofpact_put_OUTPUT(ofpacts)->port = port;
        } else {
            ovs_fatal(0, "Unknown action: %s", act);
        }
    }

    return true;
}

static void
str_to_ofpacts(const struct flow *flow, char *str, struct ofpbuf *ofpacts)
{
    char *pos, *act, *arg;
    enum ofperr error;
    int n_actions;

    pos = str;
    n_actions = 0;
    while (ofputil_parse_key_value(&pos, &act, &arg)) {
        if (!str_to_ofpact__(flow, pos, act, arg, ofpacts, n_actions)) {
            break;
        }
        n_actions++;
    }

    error = ofpacts_verify(ofpacts->data, ofpacts->size);
    if (error) {
        ovs_fatal(0, "Incorrect action ordering");
    }

    ofpact_pad(ofpacts);
}

static void
parse_named_instruction(enum ovs_instruction_type type,
                        char *arg, struct ofpbuf *ofpacts)
{
    enum ofperr error;

    switch (type) {
    case OVSINST_OFPIT11_APPLY_ACTIONS:
        NOT_REACHED();  /* This case is handled by str_to_inst_ofpacts() */
        break;

    case OVSINST_OFPIT11_WRITE_ACTIONS:
        /* TODO:XXX */
        ovs_fatal(0, "instruction write-actions is not supported yet");
        break;

    case OVSINST_OFPIT11_CLEAR_ACTIONS:
        ofpact_put_CLEAR_ACTIONS(ofpacts);
        break;

    case OVSINST_OFPIT11_WRITE_METADATA:
        parse_metadata(ofpacts, arg);
        break;

    case OVSINST_OFPIT11_GOTO_TABLE: {
        struct ofpact_goto_table *ogt = ofpact_put_GOTO_TABLE(ofpacts);
        char *table_s = strsep(&arg, ",");
        if (!table_s || !table_s[0]) {
            ovs_fatal(0, "instruction goto-table needs table id");
        }
        ogt->table_id = str_to_table_id(table_s);
        break;
    }
    }

    /* If write_metadata is specified as an action AND an instruction, ofpacts
       could be invalid. */
    error = ofpacts_verify(ofpacts->data, ofpacts->size);
    if (error) {
        ovs_fatal(0, "Incorrect instruction ordering");
    }
}

static void
str_to_inst_ofpacts(const struct flow *flow, char *str, struct ofpbuf *ofpacts)
{
    char *pos, *inst, *arg;
    int type;
    const char *prev_inst = NULL;
    int prev_type = -1;
    int n_actions = 0;

    pos = str;
    while (ofputil_parse_key_value(&pos, &inst, &arg)) {
        type = ofpact_instruction_type_from_name(inst);
        if (type < 0) {
            if (!str_to_ofpact__(flow, pos, inst, arg, ofpacts, n_actions)) {
                break;
            }

            type = OVSINST_OFPIT11_APPLY_ACTIONS;
            if (prev_type == type) {
                n_actions++;
                continue;
            }
        } else if (type == OVSINST_OFPIT11_APPLY_ACTIONS) {
            ovs_fatal(0, "%s isn't supported. Just write actions then "
                      "it is interpreted as apply_actions", inst);
        } else {
            parse_named_instruction(type, arg, ofpacts);
        }

        if (type == prev_type) {
            ovs_fatal(0, "instruction can be specified at most once: %s",
                      inst);
        }
        if (type <= prev_type) {
            ovs_fatal(0, "Instruction %s must be specified before %s",
                      inst, prev_inst);
        }

        prev_inst = inst;
        prev_type = type;
        n_actions++;
    }
    ofpact_pad(ofpacts);
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
        { "rarp", ETH_TYPE_RARP, 0},
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
parse_field(const struct mf_field *mf, const char *s, struct match *match)
{
    union mf_value value, mask;
    char *error;

    error = mf_parse(mf, s, &value, &mask);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    mf_set(mf, &value, &mask, match);
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

    match_init_catchall(&fm->match);
    fm->priority = OFP_DEFAULT_PRIORITY;
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
            match_set_dl_type(&fm->match, htons(p->dl_type));
            if (p->nw_proto) {
                match_set_nw_proto(&fm->match, p->nw_proto);
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
                if (!ofputil_port_from_string(name, &fm->out_port)) {
                    ofp_fatal(str_, verbose, "%s is not a valid OpenFlow port",
                              name);
                }
            } else if (fields & F_PRIORITY && !strcmp(name, "priority")) {
                fm->priority = str_to_u16(value, name);
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
                parse_field(mf_from_name(name), value, &fm->match);
            } else if (!strcmp(name, "duration")
                       || !strcmp(name, "n_packets")
                       || !strcmp(name, "n_bytes")
                       || !strcmp(name, "idle_age")
                       || !strcmp(name, "hard_age")) {
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
        struct ofpbuf ofpacts;

        ofpbuf_init(&ofpacts, 32);
        str_to_inst_ofpacts(&fm->match.flow, act_str, &ofpacts);
        fm->ofpacts_len = ofpacts.size;
        fm->ofpacts = ofpbuf_steal_data(&ofpacts);
    } else {
        fm->ofpacts_len = 0;
        fm->ofpacts = NULL;
    }

    free(string);
}

/* Convert 'str_' (as described in the documentation for the "monitor" command
 * in the ovs-ofctl man page) into 'fmr'. */
void
parse_flow_monitor_request(struct ofputil_flow_monitor_request *fmr,
                           const char *str_)
{
    static uint32_t id;

    char *string = xstrdup(str_);
    char *save_ptr = NULL;
    char *name;

    fmr->id = id++;
    fmr->flags = (NXFMF_INITIAL | NXFMF_ADD | NXFMF_DELETE | NXFMF_MODIFY
                  | NXFMF_OWN | NXFMF_ACTIONS);
    fmr->out_port = OFPP_NONE;
    fmr->table_id = 0xff;
    match_init_catchall(&fmr->match);

    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {
        const struct protocol *p;

        if (!strcmp(name, "!initial")) {
            fmr->flags &= ~NXFMF_INITIAL;
        } else if (!strcmp(name, "!add")) {
            fmr->flags &= ~NXFMF_ADD;
        } else if (!strcmp(name, "!delete")) {
            fmr->flags &= ~NXFMF_DELETE;
        } else if (!strcmp(name, "!modify")) {
            fmr->flags &= ~NXFMF_MODIFY;
        } else if (!strcmp(name, "!actions")) {
            fmr->flags &= ~NXFMF_ACTIONS;
        } else if (!strcmp(name, "!own")) {
            fmr->flags &= ~NXFMF_OWN;
        } else if (parse_protocol(name, &p)) {
            match_set_dl_type(&fmr->match, htons(p->dl_type));
            if (p->nw_proto) {
                match_set_nw_proto(&fmr->match, p->nw_proto);
            }
        } else {
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                ovs_fatal(0, "%s: field %s missing value", str_, name);
            }

            if (!strcmp(name, "table")) {
                fmr->table_id = str_to_table_id(value);
            } else if (!strcmp(name, "out_port")) {
                fmr->out_port = atoi(value);
            } else if (mf_from_name(name)) {
                parse_field(mf_from_name(name), value, &fmr->match);
            } else {
                ovs_fatal(0, "%s: unknown keyword %s", str_, name);
            }
        }
    }
    free(string);
}

/* Parses 's' as a set of OpenFlow actions and appends the actions to
 * 'actions'.
 *
 * Prints an error on stderr and aborts the program if 's' syntax is
 * invalid. */
void
parse_ofpacts(const char *s_, struct ofpbuf *ofpacts)
{
    char *s = xstrdup(s_);
    str_to_ofpacts(NULL, s, ofpacts);
    free(s);
}

/* Parses 'string' as an OFPT_FLOW_MOD or NXT_FLOW_MOD with command 'command'
 * (one of OFPFC_*) into 'fm'. */
void
parse_ofp_flow_mod_str(struct ofputil_flow_mod *fm, const char *string,
                       uint16_t command, bool verbose)
{
    struct match match_copy;

    parse_ofp_str(fm, command, string, verbose);

    /* Normalize a copy of the match.  This ensures that non-normalized flows
     * get logged but doesn't affect what gets sent to the switch, so that the
     * switch can do whatever it likes with the flow. */
    match_copy = fm->match;
    ofputil_normalize_match(&match_copy);
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
    fsr->match = fm.match;
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
