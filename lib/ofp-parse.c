/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "ovs-thread.h"
#include "packets.h"
#include "simap.h"
#include "socket-util.h"
#include "vconn.h"

/* Parses 'str' as an 8-bit unsigned integer into '*valuep'.
 *
 * 'name' describes the value parsed in an error message, if any.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_u8(const char *str, const char *name, uint8_t *valuep)
{
    int value;

    if (!str_to_int(str, 0, &value) || value < 0 || value > 255) {
        return xasprintf("invalid %s \"%s\"", name, str);
    }
    *valuep = value;
    return NULL;
}

/* Parses 'str' as a 16-bit unsigned integer into '*valuep'.
 *
 * 'name' describes the value parsed in an error message, if any.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_u16(const char *str, const char *name, uint16_t *valuep)
{
    int value;

    if (!str_to_int(str, 0, &value) || value < 0 || value > 65535) {
        return xasprintf("invalid %s \"%s\"", name, str);
    }
    *valuep = value;
    return NULL;
}

/* Parses 'str' as a 32-bit unsigned integer into '*valuep'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_u32(const char *str, uint32_t *valuep)
{
    char *tail;
    uint32_t value;

    if (!str[0]) {
        return xstrdup("missing required numeric argument");
    }

    errno = 0;
    value = strtoul(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        return xasprintf("invalid numeric format %s", str);
    }
    *valuep = value;
    return NULL;
}

/* Parses 'str' as an 64-bit unsigned integer into '*valuep'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_u64(const char *str, uint64_t *valuep)
{
    char *tail;
    uint64_t value;

    if (!str[0]) {
        return xstrdup("missing required numeric argument");
    }

    errno = 0;
    value = strtoull(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        return xasprintf("invalid numeric format %s", str);
    }
    *valuep = value;
    return NULL;
}

/* Parses 'str' as an 64-bit unsigned integer in network byte order into
 * '*valuep'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_be64(const char *str, ovs_be64 *valuep)
{
    uint64_t value = 0;
    char *error;

    error = str_to_u64(str, &value);
    if (!error) {
        *valuep = htonll(value);
    }
    return error;
}

/* Parses 'str' as an Ethernet address into 'mac'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_mac(const char *str, uint8_t mac[6])
{
    if (!ovs_scan(str, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))) {
        return xasprintf("invalid mac address %s", str);
    }
    return NULL;
}

/* Parses 'str' as an IP address into '*ip'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_ip(const char *str, ovs_be32 *ip)
{
    struct in_addr in_addr;

    if (lookup_ip(str, &in_addr)) {
        return xasprintf("%s: could not convert to IP address", str);
    }
    *ip = in_addr.s_addr;
    return NULL;
}

/* Parses 'arg' as the argument to an "enqueue" action, and appends such an
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_enqueue(char *arg, struct ofpbuf *ofpacts)
{
    char *sp = NULL;
    char *port = strtok_r(arg, ":q,", &sp);
    char *queue = strtok_r(NULL, "", &sp);
    struct ofpact_enqueue *enqueue;

    if (port == NULL || queue == NULL) {
        return xstrdup("\"enqueue\" syntax is \"enqueue:PORT:QUEUE\" or "
                       "\"enqueue(PORT,QUEUE)\"");
    }

    enqueue = ofpact_put_ENQUEUE(ofpacts);
    if (!ofputil_port_from_string(port, &enqueue->port)) {
        return xasprintf("%s: enqueue to unknown port", port);
    }
    return str_to_u32(queue, &enqueue->queue);
}

/* Parses 'arg' as the argument to an "output" action, and appends such an
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_output(const char *arg, struct ofpbuf *ofpacts)
{
    if (strchr(arg, '[')) {
        struct ofpact_output_reg *output_reg;

        output_reg = ofpact_put_OUTPUT_REG(ofpacts);
        output_reg->max_len = UINT16_MAX;
        return mf_parse_subfield(&output_reg->src, arg);
    } else {
        struct ofpact_output *output;

        output = ofpact_put_OUTPUT(ofpacts);
        if (!ofputil_port_from_string(arg, &output->port)) {
            return xasprintf("%s: output to unknown port", arg);
        }
        output->max_len = output->port == OFPP_CONTROLLER ? UINT16_MAX : 0;
        return NULL;
    }
}

/* Parses 'arg' as the argument to an "resubmit" action, and appends such an
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_resubmit(char *arg, struct ofpbuf *ofpacts)
{
    struct ofpact_resubmit *resubmit;
    char *in_port_s, *table_s;

    resubmit = ofpact_put_RESUBMIT(ofpacts);

    in_port_s = strsep(&arg, ",");
    if (in_port_s && in_port_s[0]) {
        if (!ofputil_port_from_string(in_port_s, &resubmit->in_port)) {
            return xasprintf("%s: resubmit to unknown port", in_port_s);
        }
    } else {
        resubmit->in_port = OFPP_IN_PORT;
    }

    table_s = strsep(&arg, ",");
    if (table_s && table_s[0]) {
        uint32_t table_id = 0;
        char *error;

        error = str_to_u32(table_s, &table_id);
        if (error) {
            return error;
        }
        resubmit->table_id = table_id;
    } else {
        resubmit->table_id = 255;
    }

    if (resubmit->in_port == OFPP_IN_PORT && resubmit->table_id == 255) {
        return xstrdup("at least one \"in_port\" or \"table\" must be "
                       "specified  on resubmit");
    }
    return NULL;
}

/* Parses 'arg' as the argument to a "note" action, and appends such an action
 * to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
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
            return xstrdup("bad hex digit in `note' argument");
        }
        ofpbuf_put(ofpacts, &byte, 1);

        note = ofpacts->l2;
        note->length++;

        arg += 2;
    }
    ofpact_update_len(ofpacts, &note->ofpact);
    return NULL;
}

/* Parses 'arg' as the argument to a "fin_timeout" action, and appends such an
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_fin_timeout(struct ofpbuf *b, char *arg)
{
    struct ofpact_fin_timeout *oft = ofpact_put_FIN_TIMEOUT(b);
    char *key, *value;

    while (ofputil_parse_key_value(&arg, &key, &value)) {
        char *error;

        if (!strcmp(key, "idle_timeout")) {
            error =  str_to_u16(value, key, &oft->fin_idle_timeout);
        } else if (!strcmp(key, "hard_timeout")) {
            error = str_to_u16(value, key, &oft->fin_hard_timeout);
        } else {
            error = xasprintf("invalid key '%s' in 'fin_timeout' argument",
                              key);
        }

        if (error) {
            return error;
        }
    }
    return NULL;
}

/* Parses 'arg' as the argument to a "controller" action, and appends such an
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_controller(struct ofpbuf *b, char *arg)
{
    enum ofp_packet_in_reason reason = OFPR_ACTION;
    uint16_t controller_id = 0;
    uint16_t max_len = UINT16_MAX;

    if (!arg[0]) {
        /* Use defaults. */
    } else if (strspn(arg, "0123456789") == strlen(arg)) {
        char *error = str_to_u16(arg, "max_len", &max_len);
        if (error) {
            return error;
        }
    } else {
        char *name, *value;

        while (ofputil_parse_key_value(&arg, &name, &value)) {
            if (!strcmp(name, "reason")) {
                if (!ofputil_packet_in_reason_from_string(value, &reason)) {
                    return xasprintf("unknown reason \"%s\"", value);
                }
            } else if (!strcmp(name, "max_len")) {
                char *error = str_to_u16(value, "max_len", &max_len);
                if (error) {
                    return error;
                }
            } else if (!strcmp(name, "id")) {
                char *error = str_to_u16(value, "id", &controller_id);
                if (error) {
                    return error;
                }
            } else {
                return xasprintf("unknown key \"%s\" parsing controller "
                                 "action", name);
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

    return NULL;
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

/* Parses 'arg' as the argument to a "dec_ttl" action, and appends such an
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
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
            return xstrdup("dec_ttl_cnt_ids: expected at least one controller "
                           "id.");
        }
        ofpact_update_len(b, &ids->ofpact);
    }
    return NULL;
}

/* Parses 'arg' as the argument to a "set_mpls_label" action, and appends such
 * an action to 'b'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_set_mpls_label(struct ofpbuf *b, const char *arg)
{
    struct ofpact_mpls_label *mpls_label = ofpact_put_SET_MPLS_LABEL(b);

    if (*arg == '\0') {
        return xstrdup("parse_set_mpls_label: expected label.");
    }

    mpls_label->label = htonl(atoi(arg));
    return NULL;
}

/* Parses 'arg' as the argument to a "set_mpls_tc" action, and appends such an
 * action to 'b'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_set_mpls_tc(struct ofpbuf *b, const char *arg)
{
    struct ofpact_mpls_tc *mpls_tc = ofpact_put_SET_MPLS_TC(b);

    if (*arg == '\0') {
        return xstrdup("parse_set_mpls_tc: expected tc.");
    }

    mpls_tc->tc = atoi(arg);
    return NULL;
}

/* Parses 'arg' as the argument to a "set_mpls_ttl" action, and appends such an
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_set_mpls_ttl(struct ofpbuf *b, const char *arg)
{
    struct ofpact_mpls_ttl *mpls_ttl = ofpact_put_SET_MPLS_TTL(b);

    if (*arg == '\0') {
        return xstrdup("parse_set_mpls_ttl: expected ttl.");
    }

    mpls_ttl->ttl = atoi(arg);
    return NULL;
}

/* Parses a "set_field" action with argument 'arg', appending the parsed
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
set_field_parse__(char *arg, struct ofpbuf *ofpacts,
                  enum ofputil_protocol *usable_protocols)
{
    struct ofpact_set_field *sf = ofpact_put_SET_FIELD(ofpacts);
    char *value;
    char *delim;
    char *key;
    const struct mf_field *mf;
    char *error;

    value = arg;
    delim = strstr(arg, "->");
    if (!delim) {
        return xasprintf("%s: missing `->'", arg);
    }
    if (strlen(delim) <= strlen("->")) {
        return xasprintf("%s: missing field name following `->'", arg);
    }

    key = delim + strlen("->");
    mf = mf_from_name(key);
    if (!mf) {
        return xasprintf("%s is not a valid OXM field name", key);
    }
    if (!mf->writable) {
        return xasprintf("%s is read-only", key);
    }
    sf->field = mf;
    delim[0] = '\0';
    error = mf_parse_value(mf, value, &sf->value);
    if (error) {
        return error;
    }

    if (!mf_is_value_valid(mf, &sf->value)) {
        return xasprintf("%s is not a valid value for field %s", value, key);
    }

    *usable_protocols &= mf->usable_protocols;
    return NULL;
}

/* Parses 'arg' as the argument to a "set_field" action, and appends such an
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
set_field_parse(const char *arg, struct ofpbuf *ofpacts,
                enum ofputil_protocol *usable_protocols)
{
    char *copy = xstrdup(arg);
    char *error = set_field_parse__(copy, ofpacts, usable_protocols);
    free(copy);
    return error;
}

/* Parses 'arg' as the argument to a "write_metadata" instruction, and appends
 * such an action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_metadata(struct ofpbuf *b, char *arg)
{
    struct ofpact_metadata *om;
    char *mask = strchr(arg, '/');

    om = ofpact_put_WRITE_METADATA(b);

    if (mask) {
        char *error;

        *mask = '\0';
        error = str_to_be64(mask + 1, &om->mask);
        if (error) {
            return error;
        }
    } else {
        om->mask = OVS_BE64_MAX;
    }

    return str_to_be64(arg, &om->metadata);
}

/* Parses 'arg' as the argument to a "sample" action, and appends such an
 * action to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_sample(struct ofpbuf *b, char *arg)
{
    struct ofpact_sample *os = ofpact_put_SAMPLE(b);
    char *key, *value;

    while (ofputil_parse_key_value(&arg, &key, &value)) {
        char *error = NULL;

        if (!strcmp(key, "probability")) {
            error = str_to_u16(value, "probability", &os->probability);
            if (!error && os->probability == 0) {
                error = xasprintf("invalid probability value \"%s\"", value);
            }
        } else if (!strcmp(key, "collector_set_id")) {
            error = str_to_u32(value, &os->collector_set_id);
        } else if (!strcmp(key, "obs_domain_id")) {
            error = str_to_u32(value, &os->obs_domain_id);
        } else if (!strcmp(key, "obs_point_id")) {
            error = str_to_u32(value, &os->obs_point_id);
        } else {
            error = xasprintf("invalid key \"%s\" in \"sample\" argument",
                              key);
        }
        if (error) {
            return error;
        }
    }
    if (os->probability == 0) {
        return xstrdup("non-zero \"probability\" must be specified on sample");
    }
    return NULL;
}

/* Parses 'arg' as the argument to action 'code', and appends such an action to
 * 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_named_action(enum ofputil_action_code code,
                   char *arg, struct ofpbuf *ofpacts,
                   enum ofputil_protocol *usable_protocols)
{
    size_t orig_size = ofpacts->size;
    struct ofpact_tunnel *tunnel;
    struct ofpact_vlan_vid *vlan_vid;
    struct ofpact_vlan_pcp *vlan_pcp;
    char *error = NULL;
    uint16_t ethertype = 0;
    uint16_t vid = 0;
    uint8_t tos = 0, ecn, ttl;
    uint8_t pcp = 0;

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
        OVS_NOT_REACHED();

    case OFPUTIL_OFPAT10_OUTPUT:
    case OFPUTIL_OFPAT11_OUTPUT:
        error = parse_output(arg, ofpacts);
        break;

    case OFPUTIL_OFPAT10_SET_VLAN_VID:
    case OFPUTIL_OFPAT11_SET_VLAN_VID:
        error = str_to_u16(arg, "VLAN VID", &vid);
        if (error) {
            return error;
        }

        if (vid & ~VLAN_VID_MASK) {
            return xasprintf("%s: not a valid VLAN VID", arg);
        }
        vlan_vid = ofpact_put_SET_VLAN_VID(ofpacts);
        vlan_vid->vlan_vid = vid;
        vlan_vid->ofpact.compat = code;
        vlan_vid->push_vlan_if_needed = code == OFPUTIL_OFPAT10_SET_VLAN_VID;
        break;

    case OFPUTIL_OFPAT10_SET_VLAN_PCP:
    case OFPUTIL_OFPAT11_SET_VLAN_PCP:
        error = str_to_u8(arg, "VLAN PCP", &pcp);
        if (error) {
            return error;
        }

        if (pcp & ~7) {
            return xasprintf("%s: not a valid VLAN PCP", arg);
        }
        vlan_pcp = ofpact_put_SET_VLAN_PCP(ofpacts);
        vlan_pcp->vlan_pcp = pcp;
        vlan_pcp->ofpact.compat = code;
        vlan_pcp->push_vlan_if_needed = code == OFPUTIL_OFPAT10_SET_VLAN_PCP;
        break;

    case OFPUTIL_OFPAT12_SET_FIELD:
        return set_field_parse(arg, ofpacts, usable_protocols);

    case OFPUTIL_OFPAT10_STRIP_VLAN:
    case OFPUTIL_OFPAT11_POP_VLAN:
        ofpact_put_STRIP_VLAN(ofpacts)->ofpact.compat = code;
        break;

    case OFPUTIL_OFPAT11_PUSH_VLAN:
        *usable_protocols &= OFPUTIL_P_OF11_UP;
        error = str_to_u16(arg, "ethertype", &ethertype);
        if (error) {
            return error;
        }

        if (ethertype != ETH_TYPE_VLAN_8021Q) {
            /* XXX ETH_TYPE_VLAN_8021AD case isn't supported */
            return xasprintf("%s: not a valid VLAN ethertype", arg);
        }

        ofpact_put_PUSH_VLAN(ofpacts);
        break;

    case OFPUTIL_OFPAT11_SET_QUEUE:
        error = str_to_u32(arg, &ofpact_put_SET_QUEUE(ofpacts)->queue_id);
        break;

    case OFPUTIL_OFPAT10_SET_DL_SRC:
    case OFPUTIL_OFPAT11_SET_DL_SRC:
        error = str_to_mac(arg, ofpact_put_SET_ETH_SRC(ofpacts)->mac);
        break;

    case OFPUTIL_OFPAT10_SET_DL_DST:
    case OFPUTIL_OFPAT11_SET_DL_DST:
        error = str_to_mac(arg, ofpact_put_SET_ETH_DST(ofpacts)->mac);
        break;

    case OFPUTIL_OFPAT10_SET_NW_SRC:
    case OFPUTIL_OFPAT11_SET_NW_SRC:
        error = str_to_ip(arg, &ofpact_put_SET_IPV4_SRC(ofpacts)->ipv4);
        break;

    case OFPUTIL_OFPAT10_SET_NW_DST:
    case OFPUTIL_OFPAT11_SET_NW_DST:
        error = str_to_ip(arg, &ofpact_put_SET_IPV4_DST(ofpacts)->ipv4);
        break;

    case OFPUTIL_OFPAT10_SET_NW_TOS:
    case OFPUTIL_OFPAT11_SET_NW_TOS:
        error = str_to_u8(arg, "TOS", &tos);
        if (error) {
            return error;
        }

        if (tos & ~IP_DSCP_MASK) {
            return xasprintf("%s: not a valid TOS", arg);
        }
        ofpact_put_SET_IP_DSCP(ofpacts)->dscp = tos;
        break;

    case OFPUTIL_OFPAT11_SET_NW_ECN:
        error = str_to_u8(arg, "ECN", &ecn);
        if (error) {
            return error;
        }

        if (ecn & ~IP_ECN_MASK) {
            return xasprintf("%s: not a valid ECN", arg);
        }
        ofpact_put_SET_IP_ECN(ofpacts)->ecn = ecn;
        break;

    case OFPUTIL_OFPAT11_SET_NW_TTL:
        error = str_to_u8(arg, "TTL", &ttl);
        if (error) {
            return error;
        }

        ofpact_put_SET_IP_TTL(ofpacts)->ttl = ttl;
        break;

    case OFPUTIL_OFPAT11_DEC_NW_TTL:
        OVS_NOT_REACHED();

    case OFPUTIL_OFPAT10_SET_TP_SRC:
    case OFPUTIL_OFPAT11_SET_TP_SRC:
        error = str_to_u16(arg, "source port",
                           &ofpact_put_SET_L4_SRC_PORT(ofpacts)->port);
        break;

    case OFPUTIL_OFPAT10_SET_TP_DST:
    case OFPUTIL_OFPAT11_SET_TP_DST:
        error = str_to_u16(arg, "destination port",
                           &ofpact_put_SET_L4_DST_PORT(ofpacts)->port);
        break;

    case OFPUTIL_OFPAT10_ENQUEUE:
        error = parse_enqueue(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_RESUBMIT:
        error = parse_resubmit(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_SET_TUNNEL:
    case OFPUTIL_NXAST_SET_TUNNEL64:
        tunnel = ofpact_put_SET_TUNNEL(ofpacts);
        tunnel->ofpact.compat = code;
        error = str_to_u64(arg, &tunnel->tun_id);
        break;

    case OFPUTIL_NXAST_WRITE_METADATA:
        error = parse_metadata(ofpacts, arg);
        break;

    case OFPUTIL_NXAST_SET_QUEUE:
        error = str_to_u32(arg, &ofpact_put_SET_QUEUE(ofpacts)->queue_id);
        break;

    case OFPUTIL_NXAST_POP_QUEUE:
        ofpact_put_POP_QUEUE(ofpacts);
        break;

    case OFPUTIL_NXAST_REG_MOVE:
        error = nxm_parse_reg_move(ofpact_put_REG_MOVE(ofpacts), arg);
        break;

    case OFPUTIL_NXAST_REG_LOAD:
        error = nxm_parse_reg_load(ofpact_put_REG_LOAD(ofpacts), arg);
        break;

    case OFPUTIL_NXAST_NOTE:
        error = parse_note(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_MULTIPATH:
        error = multipath_parse(ofpact_put_MULTIPATH(ofpacts), arg);
        break;

    case OFPUTIL_NXAST_BUNDLE:
        error = bundle_parse(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_BUNDLE_LOAD:
        error = bundle_parse_load(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_RESUBMIT_TABLE:
    case OFPUTIL_NXAST_OUTPUT_REG:
    case OFPUTIL_NXAST_DEC_TTL_CNT_IDS:
        OVS_NOT_REACHED();

    case OFPUTIL_NXAST_LEARN:
        error = learn_parse(arg, ofpacts);
        break;

    case OFPUTIL_NXAST_EXIT:
        ofpact_put_EXIT(ofpacts);
        break;

    case OFPUTIL_NXAST_DEC_TTL:
        error = parse_dec_ttl(ofpacts, arg);
        break;

    case OFPUTIL_NXAST_SET_MPLS_LABEL:
    case OFPUTIL_OFPAT11_SET_MPLS_LABEL:
        error = parse_set_mpls_label(ofpacts, arg);
        break;

    case OFPUTIL_NXAST_SET_MPLS_TC:
    case OFPUTIL_OFPAT11_SET_MPLS_TC:
        error = parse_set_mpls_tc(ofpacts, arg);
        break;

    case OFPUTIL_NXAST_SET_MPLS_TTL:
    case OFPUTIL_OFPAT11_SET_MPLS_TTL:
        error = parse_set_mpls_ttl(ofpacts, arg);
        break;

    case OFPUTIL_OFPAT11_DEC_MPLS_TTL:
    case OFPUTIL_NXAST_DEC_MPLS_TTL:
        ofpact_put_DEC_MPLS_TTL(ofpacts);
        break;

    case OFPUTIL_NXAST_FIN_TIMEOUT:
        error = parse_fin_timeout(ofpacts, arg);
        break;

    case OFPUTIL_NXAST_CONTROLLER:
        error = parse_controller(ofpacts, arg);
        break;

    case OFPUTIL_OFPAT11_PUSH_MPLS:
    case OFPUTIL_NXAST_PUSH_MPLS:
        error = str_to_u16(arg, "push_mpls", &ethertype);
        if (!error) {
            ofpact_put_PUSH_MPLS(ofpacts)->ethertype = htons(ethertype);
        }
        break;

    case OFPUTIL_OFPAT11_POP_MPLS:
    case OFPUTIL_NXAST_POP_MPLS:
        error = str_to_u16(arg, "pop_mpls", &ethertype);
        if (!error) {
            ofpact_put_POP_MPLS(ofpacts)->ethertype = htons(ethertype);
        }
        break;

    case OFPUTIL_OFPAT11_GROUP:
        error = str_to_u32(arg, &ofpact_put_GROUP(ofpacts)->group_id);
        break;

    case OFPUTIL_NXAST_STACK_PUSH:
        error = nxm_parse_stack_action(ofpact_put_STACK_PUSH(ofpacts), arg);
        break;
    case OFPUTIL_NXAST_STACK_POP:
        error = nxm_parse_stack_action(ofpact_put_STACK_POP(ofpacts), arg);
        break;

    case OFPUTIL_NXAST_SAMPLE:
        error = parse_sample(ofpacts, arg);
        break;
    }

    if (error) {
        ofpacts->size = orig_size;
    }
    return error;
}

/* Parses action 'act', with argument 'arg', and appends a parsed version to
 * 'ofpacts'.
 *
 * 'n_actions' specifies the number of actions already parsed (for proper
 * handling of "drop" actions).
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_ofpact__(char *pos, char *act, char *arg,
                struct ofpbuf *ofpacts, int n_actions,
                enum ofputil_protocol *usable_protocols)
{
    int code = ofputil_action_code_from_name(act);
    if (code >= 0) {
        return parse_named_action(code, arg, ofpacts, usable_protocols);
    } else if (!strcasecmp(act, "drop")) {
        if (n_actions) {
            return xstrdup("Drop actions must not be preceded by other "
                           "actions");
        } else if (ofputil_parse_key_value(&pos, &act, &arg)) {
            return xstrdup("Drop actions must not be followed by other "
                           "actions");
        }
    } else {
        ofp_port_t port;
        if (ofputil_port_from_string(act, &port)) {
            ofpact_put_OUTPUT(ofpacts)->port = port;
        } else {
            return xasprintf("Unknown action: %s", act);
        }
    }

    return NULL;
}

/* Parses 'str' as a series of actions, and appends them to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_ofpacts__(char *str, struct ofpbuf *ofpacts,
                 enum ofputil_protocol *usable_protocols)
{
    size_t orig_size = ofpacts->size;
    char *pos, *act, *arg;
    int n_actions;

    pos = str;
    n_actions = 0;
    while (ofputil_parse_key_value(&pos, &act, &arg)) {
        char *error = str_to_ofpact__(pos, act, arg, ofpacts, n_actions,
                                      usable_protocols);
        if (error) {
            ofpacts->size = orig_size;
            return error;
        }
        n_actions++;
    }

    ofpact_pad(ofpacts);
    return NULL;
}


/* Parses 'str' as a series of actions, and appends them to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_ofpacts(char *str, struct ofpbuf *ofpacts,
               enum ofputil_protocol *usable_protocols)
{
    size_t orig_size = ofpacts->size;
    char *error_s;
    enum ofperr error;

    error_s = str_to_ofpacts__(str, ofpacts, usable_protocols);
    if (error_s) {
        return error_s;
    }

    error = ofpacts_verify(ofpacts->data, ofpacts->size);
    if (error) {
        ofpacts->size = orig_size;
        return xstrdup("Incorrect action ordering");
    }

    return NULL;
}

/* Parses 'arg' as the argument to instruction 'type', and appends such an
 * instruction to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_named_instruction(enum ovs_instruction_type type,
                        char *arg, struct ofpbuf *ofpacts,
                        enum ofputil_protocol *usable_protocols)
{
    char *error_s = NULL;
    enum ofperr error;

    *usable_protocols &= OFPUTIL_P_OF11_UP;

    switch (type) {
    case OVSINST_OFPIT11_APPLY_ACTIONS:
        OVS_NOT_REACHED();  /* This case is handled by str_to_inst_ofpacts() */
        break;

    case OVSINST_OFPIT11_WRITE_ACTIONS: {
        struct ofpact_nest *on;
        size_t ofs;

        ofpact_pad(ofpacts);
        ofs = ofpacts->size;
        on = ofpact_put(ofpacts, OFPACT_WRITE_ACTIONS,
                        offsetof(struct ofpact_nest, actions));
        error_s = str_to_ofpacts__(arg, ofpacts, usable_protocols);

        on = ofpbuf_at_assert(ofpacts, ofs, sizeof *on);
        on->ofpact.len = ofpacts->size - ofs;

        if (error_s) {
            ofpacts->size = ofs;
        }
        break;
    }

    case OVSINST_OFPIT11_CLEAR_ACTIONS:
        ofpact_put_CLEAR_ACTIONS(ofpacts);
        break;

    case OVSINST_OFPIT13_METER:
        *usable_protocols &= OFPUTIL_P_OF13_UP;
        error_s = str_to_u32(arg, &ofpact_put_METER(ofpacts)->meter_id);
        break;

    case OVSINST_OFPIT11_WRITE_METADATA:
        *usable_protocols &= OFPUTIL_P_NXM_OF11_UP;
        error_s = parse_metadata(ofpacts, arg);
        break;

    case OVSINST_OFPIT11_GOTO_TABLE: {
        struct ofpact_goto_table *ogt = ofpact_put_GOTO_TABLE(ofpacts);
        char *table_s = strsep(&arg, ",");
        if (!table_s || !table_s[0]) {
            return xstrdup("instruction goto-table needs table id");
        }
        error_s = str_to_u8(table_s, "table", &ogt->table_id);
        break;
    }
    }

    if (error_s) {
        return error_s;
    }

    /* If write_metadata is specified as an action AND an instruction, ofpacts
       could be invalid. */
    error = ofpacts_verify(ofpacts->data, ofpacts->size);
    if (error) {
        return xstrdup("Incorrect instruction ordering");
    }
    return NULL;
}

/* Parses 'str' as a series of instructions, and appends them to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
str_to_inst_ofpacts(char *str, struct ofpbuf *ofpacts,
                    enum ofputil_protocol *usable_protocols)
{
    size_t orig_size = ofpacts->size;
    char *pos, *inst, *arg;
    int type;
    const char *prev_inst = NULL;
    int prev_type = -1;
    int n_actions = 0;

    pos = str;
    while (ofputil_parse_key_value(&pos, &inst, &arg)) {
        type = ovs_instruction_type_from_name(inst);
        if (type < 0) {
            char *error = str_to_ofpact__(pos, inst, arg, ofpacts, n_actions,
                                          usable_protocols);
            if (error) {
                ofpacts->size = orig_size;
                return error;
            }

            type = OVSINST_OFPIT11_APPLY_ACTIONS;
            if (prev_type == type) {
                n_actions++;
                continue;
            }
        } else if (type == OVSINST_OFPIT11_APPLY_ACTIONS) {
            ofpacts->size = orig_size;
            return xasprintf("%s isn't supported. Just write actions then "
                             "it is interpreted as apply_actions", inst);
        } else {
            char *error = parse_named_instruction(type, arg, ofpacts,
                                                  usable_protocols);
            if (error) {
                ofpacts->size = orig_size;
                return error;
            }
        }

        if (type <= prev_type) {
            ofpacts->size = orig_size;
            if (type == prev_type) {
                return xasprintf("instruction %s may be specified only once",
                                 inst);
            } else {
                return xasprintf("instruction %s must be specified before %s",
                                 inst, prev_inst);
            }
        }

        prev_inst = inst;
        prev_type = type;
        n_actions++;
    }
    ofpact_pad(ofpacts);

    return NULL;
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
        { "sctp", ETH_TYPE_IP, IPPROTO_SCTP },
        { "ipv6", ETH_TYPE_IPV6, 0 },
        { "ip6", ETH_TYPE_IPV6, 0 },
        { "icmp6", ETH_TYPE_IPV6, IPPROTO_ICMPV6 },
        { "tcp6", ETH_TYPE_IPV6, IPPROTO_TCP },
        { "udp6", ETH_TYPE_IPV6, IPPROTO_UDP },
        { "sctp6", ETH_TYPE_IPV6, IPPROTO_SCTP },
        { "rarp", ETH_TYPE_RARP, 0},
        { "mpls", ETH_TYPE_MPLS, 0 },
        { "mplsm", ETH_TYPE_MPLS_MCAST, 0 },
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

/* Parses 's' as the (possibly masked) value of field 'mf', and updates
 * 'match' appropriately.  Restricts the set of usable protocols to ones
 * supporting the parsed field.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * WARN_UNUSED_RESULT
parse_field(const struct mf_field *mf, const char *s, struct match *match,
            enum ofputil_protocol *usable_protocols)
{
    union mf_value value, mask;
    char *error;

    error = mf_parse(mf, s, &value, &mask);
    if (!error) {
        *usable_protocols &= mf_set(mf, &value, &mask, match);
    }
    return error;
}

static char * WARN_UNUSED_RESULT
parse_ofp_str__(struct ofputil_flow_mod *fm, int command, char *string,
                enum ofputil_protocol *usable_protocols)
{
    enum {
        F_OUT_PORT = 1 << 0,
        F_ACTIONS = 1 << 1,
        F_TIMEOUT = 1 << 3,
        F_PRIORITY = 1 << 4,
        F_FLAGS = 1 << 5,
    } fields;
    char *save_ptr = NULL;
    char *act_str = NULL;
    char *name;

    *usable_protocols = OFPUTIL_P_ANY;

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
        OVS_NOT_REACHED();
    }

    match_init_catchall(&fm->match);
    fm->priority = OFP_DEFAULT_PRIORITY;
    fm->cookie = htonll(0);
    fm->cookie_mask = htonll(0);
    if (command == OFPFC_MODIFY || command == OFPFC_MODIFY_STRICT) {
        /* For modify, by default, don't update the cookie. */
        fm->new_cookie = OVS_BE64_MAX;
    } else{
        fm->new_cookie = htonll(0);
    }
    fm->modify_cookie = false;
    fm->table_id = 0xff;
    fm->command = command;
    fm->idle_timeout = OFP_FLOW_PERMANENT;
    fm->hard_timeout = OFP_FLOW_PERMANENT;
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_ANY;
    fm->flags = 0;
    fm->out_group = OFPG11_ANY;
    if (fields & F_ACTIONS) {
        act_str = strstr(string, "action");
        if (!act_str) {
            return xstrdup("must specify an action");
        }
        *act_str = '\0';

        act_str = strchr(act_str + 1, '=');
        if (!act_str) {
            return xstrdup("must specify an action");
        }

        act_str++;
    }
    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {
        const struct protocol *p;
        char *error = NULL;

        if (parse_protocol(name, &p)) {
            match_set_dl_type(&fm->match, htons(p->dl_type));
            if (p->nw_proto) {
                match_set_nw_proto(&fm->match, p->nw_proto);
            }
        } else if (fields & F_FLAGS && !strcmp(name, "send_flow_rem")) {
            fm->flags |= OFPUTIL_FF_SEND_FLOW_REM;
        } else if (fields & F_FLAGS && !strcmp(name, "check_overlap")) {
            fm->flags |= OFPUTIL_FF_CHECK_OVERLAP;
        } else if (fields & F_FLAGS && !strcmp(name, "reset_counts")) {
            fm->flags |= OFPUTIL_FF_RESET_COUNTS;
            *usable_protocols &= OFPUTIL_P_OF12_UP;
        } else if (fields & F_FLAGS && !strcmp(name, "no_packet_counts")) {
            fm->flags |= OFPUTIL_FF_NO_PKT_COUNTS;
            *usable_protocols &= OFPUTIL_P_OF13_UP;
        } else if (fields & F_FLAGS && !strcmp(name, "no_byte_counts")) {
            fm->flags |= OFPUTIL_FF_NO_BYT_COUNTS;
            *usable_protocols &= OFPUTIL_P_OF13_UP;
        } else {
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                return xasprintf("field %s missing value", name);
            }

            if (!strcmp(name, "table")) {
                error = str_to_u8(value, "table", &fm->table_id);
                if (fm->table_id != 0xff) {
                    *usable_protocols &= OFPUTIL_P_TID;
                }
            } else if (!strcmp(name, "out_port")) {
                if (!ofputil_port_from_string(value, &fm->out_port)) {
                    error = xasprintf("%s is not a valid OpenFlow port",
                                      value);
                }
            } else if (fields & F_PRIORITY && !strcmp(name, "priority")) {
                uint16_t priority = 0;

                error = str_to_u16(value, name, &priority);
                fm->priority = priority;
            } else if (fields & F_TIMEOUT && !strcmp(name, "idle_timeout")) {
                error = str_to_u16(value, name, &fm->idle_timeout);
            } else if (fields & F_TIMEOUT && !strcmp(name, "hard_timeout")) {
                error = str_to_u16(value, name, &fm->hard_timeout);
            } else if (!strcmp(name, "cookie")) {
                char *mask = strchr(value, '/');

                if (mask) {
                    /* A mask means we're searching for a cookie. */
                    if (command == OFPFC_ADD) {
                        return xstrdup("flow additions cannot use "
                                       "a cookie mask");
                    }
                    *mask = '\0';
                    error = str_to_be64(value, &fm->cookie);
                    if (error) {
                        return error;
                    }
                    error = str_to_be64(mask + 1, &fm->cookie_mask);

                    /* Matching of the cookie is only supported through NXM or
                     * OF1.1+. */
                    if (fm->cookie_mask != htonll(0)) {
                        *usable_protocols &= OFPUTIL_P_NXM_OF11_UP;
                    }
                } else {
                    /* No mask means that the cookie is being set. */
                    if (command != OFPFC_ADD && command != OFPFC_MODIFY
                        && command != OFPFC_MODIFY_STRICT) {
                        return xstrdup("cannot set cookie");
                    }
                    error = str_to_be64(value, &fm->new_cookie);
                    fm->modify_cookie = true;
                }
            } else if (mf_from_name(name)) {
                error = parse_field(mf_from_name(name), value, &fm->match,
                                    usable_protocols);
            } else if (!strcmp(name, "duration")
                       || !strcmp(name, "n_packets")
                       || !strcmp(name, "n_bytes")
                       || !strcmp(name, "idle_age")
                       || !strcmp(name, "hard_age")) {
                /* Ignore these, so that users can feed the output of
                 * "ovs-ofctl dump-flows" back into commands that parse
                 * flows. */
            } else {
                error = xasprintf("unknown keyword %s", name);
            }

            if (error) {
                return error;
            }
        }
    }
    /* Check for usable protocol interdependencies between match fields. */
    if (fm->match.flow.dl_type == htons(ETH_TYPE_IPV6)) {
        const struct flow_wildcards *wc = &fm->match.wc;
        /* Only NXM and OXM support matching L3 and L4 fields within IPv6.
         *
         * (IPv6 specific fields as well as arp_sha, arp_tha, nw_frag, and
         *  nw_ttl are covered elsewhere so they don't need to be included in
         *  this test too.)
         */
        if (wc->masks.nw_proto || wc->masks.nw_tos
            || wc->masks.tp_src || wc->masks.tp_dst) {
            *usable_protocols &= OFPUTIL_P_NXM_OXM_ANY;
        }
    }
    if (!fm->cookie_mask && fm->new_cookie == OVS_BE64_MAX
        && (command == OFPFC_MODIFY || command == OFPFC_MODIFY_STRICT)) {
        /* On modifies without a mask, we are supposed to add a flow if
         * one does not exist.  If a cookie wasn't been specified, use a
         * default of zero. */
        fm->new_cookie = htonll(0);
    }
    if (fields & F_ACTIONS) {
        struct ofpbuf ofpacts;
        char *error;

        ofpbuf_init(&ofpacts, 32);
        error = str_to_inst_ofpacts(act_str, &ofpacts, usable_protocols);
        if (!error) {
            enum ofperr err;

            err = ofpacts_check(ofpacts.data, ofpacts.size, &fm->match.flow,
                                OFPP_MAX, fm->table_id, 255, usable_protocols);
            if (!err && !usable_protocols) {
                err = OFPERR_OFPBAC_MATCH_INCONSISTENT;
            }
            if (err) {
                error = xasprintf("actions are invalid with specified match "
                                  "(%s)", ofperr_to_string(err));
            }

        }
        if (error) {
            ofpbuf_uninit(&ofpacts);
            return error;
        }

        fm->ofpacts_len = ofpacts.size;
        fm->ofpacts = ofpbuf_steal_data(&ofpacts);
    } else {
        fm->ofpacts_len = 0;
        fm->ofpacts = NULL;
    }

    return NULL;
}

/* Convert 'str_' (as described in the Flow Syntax section of the ovs-ofctl man
 * page) into 'fm' for sending the specified flow_mod 'command' to a switch.
 * Returns the set of usable protocols in '*usable_protocols'.
 *
 * To parse syntax for an OFPT_FLOW_MOD (or NXT_FLOW_MOD), use an OFPFC_*
 * constant for 'command'.  To parse syntax for an OFPST_FLOW or
 * OFPST_AGGREGATE (or NXST_FLOW or NXST_AGGREGATE), use -1 for 'command'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
parse_ofp_str(struct ofputil_flow_mod *fm, int command, const char *str_,
              enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error;

    error = parse_ofp_str__(fm, command, string, usable_protocols);
    if (error) {
        fm->ofpacts = NULL;
        fm->ofpacts_len = 0;
    }

    free(string);
    return error;
}

static char * WARN_UNUSED_RESULT
parse_ofp_meter_mod_str__(struct ofputil_meter_mod *mm, char *string,
                          struct ofpbuf *bands, int command,
                          enum ofputil_protocol *usable_protocols)
{
    enum {
        F_METER = 1 << 0,
        F_FLAGS = 1 << 1,
        F_BANDS = 1 << 2,
    } fields;
    char *save_ptr = NULL;
    char *band_str = NULL;
    char *name;

    /* Meters require at least OF 1.3. */
    *usable_protocols = OFPUTIL_P_OF13_UP;

    switch (command) {
    case -1:
        fields = F_METER;
        break;

    case OFPMC13_ADD:
        fields = F_METER | F_FLAGS | F_BANDS;
        break;

    case OFPMC13_DELETE:
        fields = F_METER;
        break;

    case OFPMC13_MODIFY:
        fields = F_METER | F_FLAGS | F_BANDS;
        break;

    default:
        OVS_NOT_REACHED();
    }

    mm->command = command;
    mm->meter.meter_id = 0;
    mm->meter.flags = 0;
    if (fields & F_BANDS) {
        band_str = strstr(string, "band");
        if (!band_str) {
            return xstrdup("must specify bands");
        }
        *band_str = '\0';

        band_str = strchr(band_str + 1, '=');
        if (!band_str) {
            return xstrdup("must specify bands");
        }

        band_str++;
    }
    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {

        if (fields & F_FLAGS && !strcmp(name, "kbps")) {
            mm->meter.flags |= OFPMF13_KBPS;
        } else if (fields & F_FLAGS && !strcmp(name, "pktps")) {
            mm->meter.flags |= OFPMF13_PKTPS;
        } else if (fields & F_FLAGS && !strcmp(name, "burst")) {
            mm->meter.flags |= OFPMF13_BURST;
        } else if (fields & F_FLAGS && !strcmp(name, "stats")) {
            mm->meter.flags |= OFPMF13_STATS;
        } else {
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                return xasprintf("field %s missing value", name);
            }

            if (!strcmp(name, "meter")) {
                if (!strcmp(value, "all")) {
                    mm->meter.meter_id = OFPM13_ALL;
                } else if (!strcmp(value, "controller")) {
                    mm->meter.meter_id = OFPM13_CONTROLLER;
                } else if (!strcmp(value, "slowpath")) {
                    mm->meter.meter_id = OFPM13_SLOWPATH;
                } else {
                    char *error = str_to_u32(value, &mm->meter.meter_id);
                    if (error) {
                        return error;
                    }
                    if (mm->meter.meter_id > OFPM13_MAX) {
                        return xasprintf("invalid value for %s", name);
                    }
                }
            } else {
                return xasprintf("unknown keyword %s", name);
            }
        }
    }
    if (fields & F_METER && !mm->meter.meter_id) {
        return xstrdup("must specify 'meter'");
    }
    if (fields & F_FLAGS && !mm->meter.flags) {
        return xstrdup("meter must specify either 'kbps' or 'pktps'");
    }

    if (fields & F_BANDS) {
        uint16_t n_bands = 0;
        struct ofputil_meter_band *band = NULL;
        int i;

        for (name = strtok_r(band_str, "=, \t\r\n", &save_ptr); name;
             name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {

            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                return xasprintf("field %s missing value", name);
            }

            if (!strcmp(name, "type")) {
                /* Start a new band */
                band = ofpbuf_put_zeros(bands, sizeof *band);
                n_bands++;

                if (!strcmp(value, "drop")) {
                    band->type = OFPMBT13_DROP;
                } else if (!strcmp(value, "dscp_remark")) {
                    band->type = OFPMBT13_DSCP_REMARK;
                } else {
                    return xasprintf("field %s unknown value %s", name, value);
                }
            } else if (!band || !band->type) {
                return xstrdup("band must start with the 'type' keyword");
            } else if (!strcmp(name, "rate")) {
                char *error = str_to_u32(value, &band->rate);
                if (error) {
                    return error;
                }
            } else if (!strcmp(name, "burst_size")) {
                char *error = str_to_u32(value, &band->burst_size);
                if (error) {
                    return error;
                }
            } else if (!strcmp(name, "prec_level")) {
                char *error = str_to_u8(value, name, &band->prec_level);
                if (error) {
                    return error;
                }
            } else {
                return xasprintf("unknown keyword %s", name);
            }
        }
        /* validate bands */
        if (!n_bands) {
            return xstrdup("meter must have bands");
        }

        mm->meter.n_bands = n_bands;
        mm->meter.bands = ofpbuf_steal_data(bands);

        for (i = 0; i < n_bands; ++i) {
            band = &mm->meter.bands[i];

            if (!band->type) {
                return xstrdup("band must have 'type'");
            }
            if (band->type == OFPMBT13_DSCP_REMARK) {
                if (!band->prec_level) {
                    return xstrdup("'dscp_remark' band must have"
                                   " 'prec_level'");
                }
            } else {
                if (band->prec_level) {
                    return xstrdup("Only 'dscp_remark' band may have"
                                   " 'prec_level'");
                }
            }
            if (!band->rate) {
                return xstrdup("band must have 'rate'");
            }
            if (mm->meter.flags & OFPMF13_BURST) {
                if (!band->burst_size) {
                    return xstrdup("band must have 'burst_size' "
                                   "when 'burst' flag is set");
                }
            } else {
                if (band->burst_size) {
                    return xstrdup("band may have 'burst_size' only "
                                   "when 'burst' flag is set");
                }
            }
        }
    } else {
        mm->meter.n_bands = 0;
        mm->meter.bands = NULL;
    }

    return NULL;
}

/* Convert 'str_' (as described in the Flow Syntax section of the ovs-ofctl man
 * page) into 'mm' for sending the specified meter_mod 'command' to a switch.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
parse_ofp_meter_mod_str(struct ofputil_meter_mod *mm, const char *str_,
                        int command, enum ofputil_protocol *usable_protocols)
{
    struct ofpbuf bands;
    char *string;
    char *error;

    ofpbuf_init(&bands, 64);
    string = xstrdup(str_);

    error = parse_ofp_meter_mod_str__(mm, string, &bands, command,
                                      usable_protocols);

    free(string);
    ofpbuf_uninit(&bands);

    return error;
}

static char * WARN_UNUSED_RESULT
parse_flow_monitor_request__(struct ofputil_flow_monitor_request *fmr,
                             const char *str_, char *string,
                             enum ofputil_protocol *usable_protocols)
{
    static atomic_uint32_t id = ATOMIC_VAR_INIT(0);
    char *save_ptr = NULL;
    char *name;

    atomic_add(&id, 1, &fmr->id);

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
                return xasprintf("%s: field %s missing value", str_, name);
            }

            if (!strcmp(name, "table")) {
                char *error = str_to_u8(value, "table", &fmr->table_id);
                if (error) {
                    return error;
                }
            } else if (!strcmp(name, "out_port")) {
                fmr->out_port = u16_to_ofp(atoi(value));
            } else if (mf_from_name(name)) {
                char *error;

                error = parse_field(mf_from_name(name), value, &fmr->match,
                                    usable_protocols);
                if (error) {
                    return error;
                }
            } else {
                return xasprintf("%s: unknown keyword %s", str_, name);
            }
        }
    }
    return NULL;
}

/* Convert 'str_' (as described in the documentation for the "monitor" command
 * in the ovs-ofctl man page) into 'fmr'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
parse_flow_monitor_request(struct ofputil_flow_monitor_request *fmr,
                           const char *str_,
                           enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error = parse_flow_monitor_request__(fmr, str_, string,
                                               usable_protocols);
    free(string);
    return error;
}

/* Parses 's' as a set of OpenFlow actions and appends the actions to
 * 'actions'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
parse_ofpacts(const char *s_, struct ofpbuf *ofpacts,
              enum ofputil_protocol *usable_protocols)
{
    char *s = xstrdup(s_);
    char *error;

    *usable_protocols = OFPUTIL_P_ANY;

    error = str_to_ofpacts(s, ofpacts, usable_protocols);
    free(s);

    return error;
}

/* Parses 'string' as an OFPT_FLOW_MOD or NXT_FLOW_MOD with command 'command'
 * (one of OFPFC_*) into 'fm'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
parse_ofp_flow_mod_str(struct ofputil_flow_mod *fm, const char *string,
                       uint16_t command,
                       enum ofputil_protocol *usable_protocols)
{
    char *error = parse_ofp_str(fm, command, string, usable_protocols);
    if (!error) {
        /* Normalize a copy of the match.  This ensures that non-normalized
         * flows get logged but doesn't affect what gets sent to the switch, so
         * that the switch can do whatever it likes with the flow. */
        struct match match_copy = fm->match;
        ofputil_normalize_match(&match_copy);
    }

    return error;
}

/* Convert 'table_id' and 'flow_miss_handling' (as described for the
 * "mod-table" command in the ovs-ofctl man page) into 'tm' for sending the
 * specified table_mod 'command' to a switch.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
parse_ofp_table_mod(struct ofputil_table_mod *tm, const char *table_id,
                    const char *flow_miss_handling,
                    enum ofputil_protocol *usable_protocols)
{
    /* Table mod requires at least OF 1.1. */
    *usable_protocols = OFPUTIL_P_OF11_UP;

    if (!strcasecmp(table_id, "all")) {
        tm->table_id = OFPTT_ALL;
    } else {
        char *error = str_to_u8(table_id, "table_id", &tm->table_id);
        if (error) {
            return error;
        }
    }

    if (strcmp(flow_miss_handling, "controller") == 0) {
        tm->config = OFPTC11_TABLE_MISS_CONTROLLER;
    } else if (strcmp(flow_miss_handling, "continue") == 0) {
        tm->config = OFPTC11_TABLE_MISS_CONTINUE;
    } else if (strcmp(flow_miss_handling, "drop") == 0) {
        tm->config = OFPTC11_TABLE_MISS_DROP;
    } else {
        return xasprintf("invalid flow_miss_handling %s", flow_miss_handling);
    }

    if (tm->table_id == 0xfe && tm->config == OFPTC11_TABLE_MISS_CONTINUE) {
        return xstrdup("last table's flow miss handling can not be continue");
    }

    return NULL;
}


/* Opens file 'file_name' and reads each line as a flow_mod of the specified
 * type (one of OFPFC_*).  Stores each flow_mod in '*fm', an array allocated
 * on the caller's behalf, and the number of flow_mods in '*n_fms'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
parse_ofp_flow_mod_file(const char *file_name, uint16_t command,
                        struct ofputil_flow_mod **fms, size_t *n_fms,
                        enum ofputil_protocol *usable_protocols)
{
    size_t allocated_fms;
    int line_number;
    FILE *stream;
    struct ds s;

    *usable_protocols = OFPUTIL_P_ANY;

    *fms = NULL;
    *n_fms = 0;

    stream = !strcmp(file_name, "-") ? stdin : fopen(file_name, "r");
    if (stream == NULL) {
        return xasprintf("%s: open failed (%s)",
                         file_name, ovs_strerror(errno));
    }

    allocated_fms = *n_fms;
    ds_init(&s);
    line_number = 0;
    while (!ds_get_preprocessed_line(&s, stream, &line_number)) {
        char *error;
        enum ofputil_protocol usable;

        if (*n_fms >= allocated_fms) {
            *fms = x2nrealloc(*fms, &allocated_fms, sizeof **fms);
        }
        error = parse_ofp_flow_mod_str(&(*fms)[*n_fms], ds_cstr(&s), command,
                                       &usable);
        if (error) {
            size_t i;

            for (i = 0; i < *n_fms; i++) {
                free((*fms)[i].ofpacts);
            }
            free(*fms);
            *fms = NULL;
            *n_fms = 0;

            ds_destroy(&s);
            if (stream != stdin) {
                fclose(stream);
            }

            return xasprintf("%s:%d: %s", file_name, line_number, error);
        }
        *usable_protocols &= usable; /* Each line can narrow the set. */
        *n_fms += 1;
    }

    ds_destroy(&s);
    if (stream != stdin) {
        fclose(stream);
    }
    return NULL;
}

char * WARN_UNUSED_RESULT
parse_ofp_flow_stats_request_str(struct ofputil_flow_stats_request *fsr,
                                 bool aggregate, const char *string,
                                 enum ofputil_protocol *usable_protocols)
{
    struct ofputil_flow_mod fm;
    char *error;

    error = parse_ofp_str(&fm, -1, string, usable_protocols);
    if (error) {
        return error;
    }

    /* Special table ID support not required for stats requests. */
    if (*usable_protocols & OFPUTIL_P_OF10_STD_TID) {
        *usable_protocols |= OFPUTIL_P_OF10_STD;
    }
    if (*usable_protocols & OFPUTIL_P_OF10_NXM_TID) {
        *usable_protocols |= OFPUTIL_P_OF10_NXM;
    }

    fsr->aggregate = aggregate;
    fsr->cookie = fm.cookie;
    fsr->cookie_mask = fm.cookie_mask;
    fsr->match = fm.match;
    fsr->out_port = fm.out_port;
    fsr->out_group = fm.out_group;
    fsr->table_id = fm.table_id;
    return NULL;
}

/* Parses a specification of a flow from 's' into 'flow'.  's' must take the
 * form FIELD=VALUE[,FIELD=VALUE]... where each FIELD is the name of a
 * mf_field.  Fields must be specified in a natural order for satisfying
 * prerequisites. If 'mask' is specified, fills the mask field for each of the
 * field specified in flow. If the map, 'names_portno' is specfied, converts
 * the in_port name into port no while setting the 'flow'.
 *
 * Returns NULL on success, otherwise a malloc()'d string that explains the
 * problem. */
char *
parse_ofp_exact_flow(struct flow *flow, struct flow *mask, const char *s,
                     const struct simap *portno_names)
{
    char *pos, *key, *value_s;
    char *error = NULL;
    char *copy;

    memset(flow, 0, sizeof *flow);
    if (mask) {
        memset(mask, 0, sizeof *mask);
    }

    pos = copy = xstrdup(s);
    while (ofputil_parse_key_value(&pos, &key, &value_s)) {
        const struct protocol *p;
        if (parse_protocol(key, &p)) {
            if (flow->dl_type) {
                error = xasprintf("%s: Ethernet type set multiple times", s);
                goto exit;
            }
            flow->dl_type = htons(p->dl_type);
            if (mask) {
                mask->dl_type = OVS_BE16_MAX;
            }

            if (p->nw_proto) {
                if (flow->nw_proto) {
                    error = xasprintf("%s: network protocol set "
                                      "multiple times", s);
                    goto exit;
                }
                flow->nw_proto = p->nw_proto;
                if (mask) {
                    mask->nw_proto = UINT8_MAX;
                }
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

            if (!strcmp(key, "in_port")
                && portno_names
                && simap_contains(portno_names, value_s)) {
                flow->in_port.ofp_port = u16_to_ofp(
                    simap_get(portno_names, value_s));
                if (mask) {
                    mask->in_port.ofp_port = u16_to_ofp(ntohs(OVS_BE16_MAX));
                }
            } else {
                field_error = mf_parse_value(mf, value_s, &value);
                if (field_error) {
                    error = xasprintf("%s: bad value for %s (%s)",
                                      s, key, field_error);
                    free(field_error);
                    goto exit;
                }

                mf_set_flow_value(mf, &value, flow);
                if (mask) {
                    mf_mask_field(mf, mask);
                }
            }
        }
    }

    if (!flow->in_port.ofp_port) {
        flow->in_port.ofp_port = OFPP_NONE;
    }

exit:
    free(copy);

    if (error) {
        memset(flow, 0, sizeof *flow);
        if (mask) {
            memset(mask, 0, sizeof *mask);
        }
    }
    return error;
}

static char * WARN_UNUSED_RESULT
parse_bucket_str(struct ofputil_bucket *bucket, char *str_,
                  enum ofputil_protocol *usable_protocols)
{
    struct ofpbuf ofpacts;
    char *pos, *act, *arg;
    int n_actions;

    bucket->weight = 1;
    bucket->watch_port = OFPP_ANY;
    bucket->watch_group = OFPG11_ANY;

    pos = str_;
    n_actions = 0;
    ofpbuf_init(&ofpacts, 64);
    while (ofputil_parse_key_value(&pos, &act, &arg)) {
        char *error = NULL;

        if (!strcasecmp(act, "weight")) {
            error = str_to_u16(arg, "weight", &bucket->weight);
        } else if (!strcasecmp(act, "watch_port")) {
            if (!ofputil_port_from_string(arg, &bucket->watch_port)
                || (ofp_to_u16(bucket->watch_port) >= ofp_to_u16(OFPP_MAX)
                    && bucket->watch_port != OFPP_ANY)) {
                error = xasprintf("%s: invalid watch_port", arg);
            }
        } else if (!strcasecmp(act, "watch_group")) {
            error = str_to_u32(arg, &bucket->watch_group);
            if (!error && bucket->watch_group > OFPG_MAX) {
                error = xasprintf("invalid watch_group id %"PRIu32,
                                  bucket->watch_group);
            }
        } else {
            error = str_to_ofpact__(pos, act, arg, &ofpacts, n_actions,
                                    usable_protocols);
            n_actions++;
        }

        if (error) {
            ofpbuf_uninit(&ofpacts);
            return error;
        }
    }

    ofpact_pad(&ofpacts);
    bucket->ofpacts = ofpacts.data;
    bucket->ofpacts_len = ofpacts.size;

    return NULL;
}

static char * WARN_UNUSED_RESULT
parse_ofp_group_mod_str__(struct ofputil_group_mod *gm, uint16_t command,
                          char *string,
                          enum ofputil_protocol *usable_protocols)
{
    enum {
        F_GROUP_TYPE  = 1 << 0,
        F_BUCKETS     = 1 << 1,
    } fields;
    char *save_ptr = NULL;
    bool had_type = false;
    char *name;
    struct ofputil_bucket *bucket;
    char *error = NULL;

    *usable_protocols = OFPUTIL_P_OF11_UP;

    switch (command) {
    case OFPGC11_ADD:
        fields = F_GROUP_TYPE | F_BUCKETS;
        break;

    case OFPGC11_DELETE:
        fields = 0;
        break;

    case OFPGC11_MODIFY:
        fields = F_GROUP_TYPE | F_BUCKETS;
        break;

    default:
        OVS_NOT_REACHED();
    }

    memset(gm, 0, sizeof *gm);
    gm->command = command;
    gm->group_id = OFPG_ANY;
    list_init(&gm->buckets);
    if (command == OFPGC11_DELETE && string[0] == '\0') {
        gm->group_id = OFPG_ALL;
        return NULL;
    }

    *usable_protocols = OFPUTIL_P_OF11_UP;

    if (fields & F_BUCKETS) {
        char *bkt_str = strstr(string, "bucket");

        if (bkt_str) {
            *bkt_str = '\0';
        }

        while (bkt_str) {
            char *next_bkt_str;

            bkt_str = strchr(bkt_str + 1, '=');
            if (!bkt_str) {
                error = xstrdup("must specify bucket content");
                goto out;
            }
            bkt_str++;

            next_bkt_str = strstr(bkt_str, "bucket");
            if (next_bkt_str) {
                *next_bkt_str = '\0';
            }

            bucket = xzalloc(sizeof(struct ofputil_bucket));
            error = parse_bucket_str(bucket, bkt_str, usable_protocols);
            if (error) {
                free(bucket);
                goto out;
            }
            list_push_back(&gm->buckets, &bucket->list_node);

            bkt_str = next_bkt_str;
        }
    }

    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {
        char *value;

        value = strtok_r(NULL, ", \t\r\n", &save_ptr);
        if (!value) {
            error = xasprintf("field %s missing value", name);
            goto out;
        }

        if (!strcmp(name, "group_id")) {
            if(!strcmp(value, "all")) {
                gm->group_id = OFPG_ALL;
            } else {
                char *error = str_to_u32(value, &gm->group_id);
                if (error) {
                    goto out;
                }
                if (gm->group_id != OFPG_ALL && gm->group_id > OFPG_MAX) {
                    error = xasprintf("invalid group id %"PRIu32,
                                      gm->group_id);
                    goto out;
                }
            }
        } else if (!strcmp(name, "type")){
            if (!(fields & F_GROUP_TYPE)) {
                error = xstrdup("type is not needed");
                goto out;
            }
            if (!strcmp(value, "all")) {
                gm->type = OFPGT11_ALL;
            } else if (!strcmp(value, "select")) {
                gm->type = OFPGT11_SELECT;
            } else if (!strcmp(value, "indirect")) {
                gm->type = OFPGT11_INDIRECT;
            } else if (!strcmp(value, "ff") ||
                       !strcmp(value, "fast_failover")) {
                gm->type = OFPGT11_FF;
            } else {
                error = xasprintf("invalid group type %s", value);
                goto out;
            }
            had_type = true;
        } else if (!strcmp(name, "bucket")) {
            error = xstrdup("bucket is not needed");
            goto out;
        } else {
            error = xasprintf("unknown keyword %s", name);
            goto out;
        }
    }
    if (gm->group_id == OFPG_ANY) {
        error = xstrdup("must specify a group_id");
        goto out;
    }
    if (fields & F_GROUP_TYPE && !had_type) {
        error = xstrdup("must specify a type");
        goto out;
    }

    /* Validate buckets. */
    LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
        if (bucket->weight != 1 && gm->type != OFPGT11_SELECT) {
            error = xstrdup("Only select groups can have bucket weights.");
            goto out;
        }
    }
    if (gm->type == OFPGT11_INDIRECT && !list_is_short(&gm->buckets)) {
        error = xstrdup("Indirect groups can have at most one bucket.");
        goto out;
    }

    return NULL;
 out:
    ofputil_bucket_list_destroy(&gm->buckets);
    return error;
}

char * WARN_UNUSED_RESULT
parse_ofp_group_mod_str(struct ofputil_group_mod *gm, uint16_t command,
                        const char *str_,
                        enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error = parse_ofp_group_mod_str__(gm, command, string,
                                            usable_protocols);
    free(string);

    if (error) {
        ofputil_bucket_list_destroy(&gm->buckets);
    }
    return error;
}

char * WARN_UNUSED_RESULT
parse_ofp_group_mod_file(const char *file_name, uint16_t command,
                         struct ofputil_group_mod **gms, size_t *n_gms,
                         enum ofputil_protocol *usable_protocols)
{
    size_t allocated_gms;
    int line_number;
    FILE *stream;
    struct ds s;

    *gms = NULL;
    *n_gms = 0;

    stream = !strcmp(file_name, "-") ? stdin : fopen(file_name, "r");
    if (stream == NULL) {
        return xasprintf("%s: open failed (%s)",
                         file_name, ovs_strerror(errno));
    }

    allocated_gms = *n_gms;
    ds_init(&s);
    line_number = 0;
    *usable_protocols = OFPUTIL_P_OF11_UP;
    while (!ds_get_preprocessed_line(&s, stream, &line_number)) {
        enum ofputil_protocol usable;
        char *error;

        if (*n_gms >= allocated_gms) {
            size_t i;

            *gms = x2nrealloc(*gms, &allocated_gms, sizeof **gms);
            for (i = 0; i < *n_gms; i++) {
                list_moved(&(*gms)[i].buckets);
            }
        }
        error = parse_ofp_group_mod_str(&(*gms)[*n_gms], command, ds_cstr(&s),
                                        &usable);
        if (error) {
            size_t i;

            for (i = 0; i < *n_gms; i++) {
                ofputil_bucket_list_destroy(&(*gms)[i].buckets);
            }
            free(*gms);
            *gms = NULL;
            *n_gms = 0;

            ds_destroy(&s);
            if (stream != stdin) {
                fclose(stream);
            }

            return xasprintf("%s:%d: %s", file_name, line_number, error);
        }
        *usable_protocols &= usable;
        *n_gms += 1;
    }

    ds_destroy(&s);
    if (stream != stdin) {
        fclose(stream);
    }
    return NULL;
}
