/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "byte-order.h"
#include "dp-packet.h"
#include "learn.h"
#include "multipath.h"
#include "netdev.h"
#include "nx-match.h"
#include "openflow/openflow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vconn.h"
#include "ovs-thread.h"
#include "packets.h"
#include "simap.h"
#include "socket-util.h"
#include "util.h"

/* Parses 'str' as an 8-bit unsigned integer into '*valuep'.
 *
 * 'name' describes the value parsed in an error message, if any.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
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
char * OVS_WARN_UNUSED_RESULT
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
char * OVS_WARN_UNUSED_RESULT
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
char * OVS_WARN_UNUSED_RESULT
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
char * OVS_WARN_UNUSED_RESULT
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
char * OVS_WARN_UNUSED_RESULT
str_to_mac(const char *str, struct eth_addr *mac)
{
    if (!ovs_scan(str, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(*mac))) {
        return xasprintf("invalid mac address %s", str);
    }
    return NULL;
}

/* Parses 'str' as an IP address into '*ip'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
str_to_ip(const char *str, ovs_be32 *ip)
{
    struct in_addr in_addr;

    if (lookup_ip(str, &in_addr)) {
        return xasprintf("%s: could not convert to IP address", str);
    }
    *ip = in_addr.s_addr;
    return NULL;
}

/* Parses 'str' as a conntrack helper into 'alg'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
str_to_connhelper(const char *str, uint16_t *alg)
{
    if (!strcmp(str, "ftp")) {
        *alg = IPPORT_FTP;
        return NULL;
    }
    if (!strcmp(str, "tftp")) {
        *alg = IPPORT_TFTP;
        return NULL;
    }
    return xasprintf("invalid conntrack helper \"%s\"", str);
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
        { "ipv4", ETH_TYPE_IP, 0 },
        { "ip4", ETH_TYPE_IP, 0 },
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
static char * OVS_WARN_UNUSED_RESULT
parse_field(const struct mf_field *mf, const char *s,
            const struct ofputil_port_map *port_map, struct match *match,
            enum ofputil_protocol *usable_protocols)
{
    union mf_value value, mask;
    char *error;

    if (!*s) {
        /* If there's no string, we're just trying to match on the
         * existence of the field, so use a no-op value. */
        s = "0/0";
    }

    error = mf_parse(mf, s, port_map, &value, &mask);
    if (!error) {
        *usable_protocols &= mf_set(mf, &value, &mask, match, &error);
        match_add_ethernet_prereq(match, mf);
    }
    return error;
}

/* Parses 'str_value' as the value of subfield 'name', and updates
 * 'match' appropriately.  Restricts the set of usable protocols to ones
 * supporting the parsed field.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
parse_subfield(const char *name, const char *str_value, struct match *match,
               enum ofputil_protocol *usable_protocols)
{
    struct mf_subfield sf;
    char *error;

    error = mf_parse_subfield(&sf, name);
    if (!error) {
        union mf_value val;
        char *tail;
        if (parse_int_string(str_value, (uint8_t *)&val, sf.field->n_bytes,
                             &tail) || *tail != 0) {
            return xasprintf("%s: cannot parse integer value: %s", name,
                             str_value);
        }
        if (!bitwise_is_all_zeros(&val, sf.field->n_bytes, sf.n_bits,
                                  sf.field->n_bytes * 8 - sf.n_bits)) {
            struct ds ds;

            ds_init(&ds);
            mf_format(sf.field, &val, NULL, NULL, &ds);
            error = xasprintf("%s: value %s does not fit into %d bits",
                              name, ds_cstr(&ds), sf.n_bits);
            ds_destroy(&ds);
            return error;
        }

        const struct mf_field *field = sf.field;
        union mf_value value, mask;
        unsigned int size = field->n_bytes;

        mf_get(field, match, &value, &mask);
        bitwise_copy(&val, size, 0, &value, size, sf.ofs, sf.n_bits);
        bitwise_one (               &mask,  size, sf.ofs, sf.n_bits);
        *usable_protocols &= mf_set(field, &value, &mask, match, &error);

        match_add_ethernet_prereq(match, sf.field);
    }
    return error;
}

static char *
extract_actions(char *s)
{
    s = strstr(s, "action");
    if (s) {
        *s = '\0';
        s = strchr(s + 1, '=');
        return s ? s + 1 : NULL;
    } else {
        return NULL;
    }
}


static char * OVS_WARN_UNUSED_RESULT
parse_ofp_str__(struct ofputil_flow_mod *fm, int command, char *string,
                const struct ofputil_port_map *port_map,
                const struct ofputil_table_map *table_map,
                enum ofputil_protocol *usable_protocols)
{
    enum {
        F_OUT_PORT = 1 << 0,
        F_ACTIONS = 1 << 1,
        F_IMPORTANCE = 1 << 2,
        F_TIMEOUT = 1 << 3,
        F_PRIORITY = 1 << 4,
        F_FLAGS = 1 << 5,
    } fields;
    char *act_str = NULL;
    char *name, *value;

    *usable_protocols = OFPUTIL_P_ANY;

    if (command == -2) {
        size_t len;

        string += strspn(string, " \t\r\n");   /* Skip white space. */
        len = strcspn(string, ", \t\r\n"); /* Get length of the first token. */

        if (!strncmp(string, "add", len)) {
            command = OFPFC_ADD;
        } else if (!strncmp(string, "delete", len)) {
            command = OFPFC_DELETE;
        } else if (!strncmp(string, "delete_strict", len)) {
            command = OFPFC_DELETE_STRICT;
        } else if (!strncmp(string, "modify", len)) {
            command = OFPFC_MODIFY;
        } else if (!strncmp(string, "modify_strict", len)) {
            command = OFPFC_MODIFY_STRICT;
        } else {
            len = 0;
            command = OFPFC_ADD;
        }
        string += len;
    }

    switch (command) {
    case -1:
        fields = F_OUT_PORT;
        break;

    case OFPFC_ADD:
        fields = F_ACTIONS | F_TIMEOUT | F_PRIORITY | F_FLAGS | F_IMPORTANCE;
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

    *fm = (struct ofputil_flow_mod) {
        .match = MATCH_CATCHALL_INITIALIZER,
        .priority = OFP_DEFAULT_PRIORITY,
        .table_id = 0xff,
        .command = command,
        .buffer_id = UINT32_MAX,
        .out_port = OFPP_ANY,
        .out_group = OFPG_ANY,
    };
    /* For modify, by default, don't update the cookie. */
    if (command == OFPFC_MODIFY || command == OFPFC_MODIFY_STRICT) {
        fm->new_cookie = OVS_BE64_MAX;
    }

    if (fields & F_ACTIONS) {
        act_str = extract_actions(string);
        if (!act_str) {
            return xstrdup("must specify an action");
        }
    }

    while (ofputil_parse_key_value(&string, &name, &value)) {
        const struct protocol *p;
        const struct mf_field *mf;
        char *error = NULL;

        if (parse_protocol(name, &p)) {
            match_set_dl_type(&fm->match, htons(p->dl_type));
            if (p->nw_proto) {
                match_set_nw_proto(&fm->match, p->nw_proto);
            }
            match_set_default_packet_type(&fm->match);
        } else if (!strcmp(name, "eth")) {
            match_set_packet_type(&fm->match, htonl(PT_ETH));
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
        } else if (!strcmp(name, "no_readonly_table")
                   || !strcmp(name, "allow_hidden_fields")) {
             /* ignore these fields. */
        } else if ((mf = mf_from_name(name)) != NULL) {
            error = parse_field(mf, value, port_map,
                                &fm->match, usable_protocols);
        } else if (strchr(name, '[')) {
            error = parse_subfield(name, value, &fm->match, usable_protocols);
        } else {
            if (!*value) {
                return xasprintf("field %s missing value", name);
            }

            if (!strcmp(name, "table")) {
                if (!ofputil_table_from_string(value, table_map,
                                               &fm->table_id)) {
                    return xasprintf("unknown table \"%s\"", value);
                }
                if (fm->table_id != 0xff) {
                    *usable_protocols &= OFPUTIL_P_TID;
                }
            } else if (fields & F_OUT_PORT && !strcmp(name, "out_port")) {
                if (!ofputil_port_from_string(value, port_map,
                                              &fm->out_port)) {
                    error = xasprintf("%s is not a valid OpenFlow port",
                                      value);
                }
            } else if (fields & F_OUT_PORT && !strcmp(name, "out_group")) {
                *usable_protocols &= OFPUTIL_P_OF11_UP;
                if (!ofputil_group_from_string(value, &fm->out_group)) {
                    error = xasprintf("%s is not a valid OpenFlow group",
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
            } else if (fields & F_IMPORTANCE && !strcmp(name, "importance")) {
                error = str_to_u16(value, name, &fm->importance);
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
        }

        if (error) {
            return error;
        }
    }
    /* Copy ethertype to flow->dl_type for matches on packet_type
     * (OFPHTN_ETHERTYPE, ethertype). */
    if (fm->match.wc.masks.packet_type == OVS_BE32_MAX &&
            pt_ns(fm->match.flow.packet_type) == OFPHTN_ETHERTYPE) {
        fm->match.flow.dl_type = pt_ns_type_be(fm->match.flow.packet_type);
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
        enum ofputil_protocol action_usable_protocols;
        struct ofpbuf ofpacts;
        char *error;

        ofpbuf_init(&ofpacts, 32);
        struct ofpact_parse_params pp = {
            .port_map = port_map,
            .table_map = table_map,
            .ofpacts = &ofpacts,
            .usable_protocols = &action_usable_protocols
        };
        error = ofpacts_parse_instructions(act_str, &pp);
        *usable_protocols &= action_usable_protocols;
        if (!error) {
            enum ofperr err;

            err = ofpacts_check(ofpacts.data, ofpacts.size, &fm->match,
                                OFPP_MAX, fm->table_id, 255, usable_protocols);
            if (!err && !*usable_protocols) {
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
 * If 'command' is given as -2, 'str_' may begin with a command name ("add",
 * "modify", "delete", "modify_strict", or "delete_strict").  A missing command
 * name is treated as "add".
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_str(struct ofputil_flow_mod *fm, int command, const char *str_,
              const struct ofputil_port_map *port_map,
              const struct ofputil_table_map *table_map,
              enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error;

    error = parse_ofp_str__(fm, command, string, port_map, table_map,
                            usable_protocols);
    if (error) {
        fm->ofpacts = NULL;
        fm->ofpacts_len = 0;
    }

    free(string);
    return error;
}

/* Parse a string representation of a OFPT_PACKET_OUT to '*po'.  If successful,
 * both 'po->ofpacts' and 'po->packet' must be free()d by the caller. */
static char * OVS_WARN_UNUSED_RESULT
parse_ofp_packet_out_str__(struct ofputil_packet_out *po, char *string,
                           const struct ofputil_port_map *port_map,
                           const struct ofputil_table_map *table_map,
                           enum ofputil_protocol *usable_protocols)
{
    enum ofputil_protocol action_usable_protocols;
    uint64_t stub[256 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    struct dp_packet *packet = NULL;
    char *act_str = NULL;
    char *name, *value;
    char *error = NULL;

    *usable_protocols = OFPUTIL_P_ANY;

    *po = (struct ofputil_packet_out) {
        .buffer_id = UINT32_MAX,
    };
    match_init_catchall(&po->flow_metadata);
    match_set_in_port(&po->flow_metadata, OFPP_CONTROLLER);

    act_str = extract_actions(string);

    while (ofputil_parse_key_value(&string, &name, &value)) {
        if (!*value) {
            error = xasprintf("field %s missing value", name);
            goto out;
        }

        if (!strcmp(name, "in_port")) {
            ofp_port_t in_port;
            if (!ofputil_port_from_string(value, port_map, &in_port)) {
                error = xasprintf("%s is not a valid OpenFlow port", value);
                goto out;
            }
            if (ofp_to_u16(in_port) > ofp_to_u16(OFPP_MAX)
                && in_port != OFPP_LOCAL
                && in_port != OFPP_NONE
                && in_port != OFPP_CONTROLLER) {
                error = xasprintf(
                              "%s is not a valid OpenFlow port for PACKET_OUT",
                              value);
                goto out;
            }
            match_set_in_port(&po->flow_metadata, in_port);
        } else if (!strcmp(name, "packet_type")) {
            char *ns = value;
            char *ns_type = strstr(value, ",");
            if (ns_type) {
                ovs_be32 packet_type;
                *ns_type = '\0';
                packet_type = PACKET_TYPE_BE(strtoul(ns, NULL, 0),
                                             strtoul(++ns_type, NULL, 0));
                match_set_packet_type(&po->flow_metadata, packet_type);
            } else {
                error = xasprintf("%s(%s) can't be interpreted", name, value);
                goto out;
            }
        } else if (!strcmp(name, "packet")) {
            const char *error_msg = eth_from_hex(value, &packet);
            if (error_msg) {
                error = xasprintf("%s: %s", name, error_msg);
                goto out;
            }
        } else {
            const struct mf_field *mf = mf_from_name(name);
            if (!mf) {
                error = xasprintf("unknown keyword %s", name);
                goto out;
            }

            error = parse_field(mf, value, port_map, &po->flow_metadata,
                                usable_protocols);
            if (error) {
                goto out;
            }
            if (!mf_is_pipeline_field(mf)) {
                error = xasprintf("%s is not a valid pipeline field "
                                  "for PACKET_OUT", name);
                goto out;
            }
        }
    }

    if (!packet || !dp_packet_size(packet)) {
        error = xstrdup("must specify packet");
        goto out;
    }

    if (act_str) {
        struct ofpact_parse_params pp = {
            .port_map = port_map,
            .table_map = table_map,
            .ofpacts = &ofpacts,
            .usable_protocols = &action_usable_protocols,
        };
        error = ofpacts_parse_actions(act_str, &pp);
        *usable_protocols &= action_usable_protocols;
        if (error) {
            goto out;
        }
    }
    po->ofpacts_len = ofpacts.size;
    po->ofpacts = ofpbuf_steal_data(&ofpacts);

    po->packet_len = dp_packet_size(packet);
    po->packet = dp_packet_steal_data(packet);
out:
    ofpbuf_uninit(&ofpacts);
    dp_packet_delete(packet);
    return error;
}

/* Convert 'str_' (as described in the Packet-Out Syntax section of the
 * ovs-ofctl man page) into 'po' for sending a OFPT_PACKET_OUT message to a
 * switch.  Returns the set of usable protocols in '*usable_protocols'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string.
 * If successful, both 'po->ofpacts' and 'po->packet' must be free()d by
 * the caller. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_packet_out_str(struct ofputil_packet_out *po, const char *str_,
                         const struct ofputil_port_map *port_map,
                         const struct ofputil_table_map *table_map,
                         enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error;

    error = parse_ofp_packet_out_str__(po, string, port_map, table_map,
                                       usable_protocols);
    if (error) {
        po->ofpacts = NULL;
        po->ofpacts_len = 0;
    }

    free(string);
    return error;
}

/* Parse a string representation of a meter modification message to '*mm'.
 * If successful, 'mm->meter.bands' must be free()d by the caller. */
static char * OVS_WARN_UNUSED_RESULT
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
    mm->meter.n_bands = 0;
    mm->meter.bands = NULL;

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
                    if (mm->meter.meter_id > OFPM13_MAX
                        || !mm->meter.meter_id) {
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
    }

    return NULL;
}

/* Convert 'str_' (as described in the Flow Syntax section of the ovs-ofctl man
 * page) into 'mm' for sending the specified meter_mod 'command' to a switch.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string.
 * If successful, 'mm->meter.bands' must be free()d by the caller. */
char * OVS_WARN_UNUSED_RESULT
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

static char * OVS_WARN_UNUSED_RESULT
parse_flow_monitor_request__(struct ofputil_flow_monitor_request *fmr,
                             const char *str_,
                             const struct ofputil_port_map *port_map,
                             const struct ofputil_table_map *table_map,
                             char *string,
                             enum ofputil_protocol *usable_protocols)
{
    static atomic_count id = ATOMIC_COUNT_INIT(0);
    char *name, *value;

    fmr->id = atomic_count_inc(&id);

    fmr->flags = (NXFMF_INITIAL | NXFMF_ADD | NXFMF_DELETE | NXFMF_MODIFY
                  | NXFMF_OWN | NXFMF_ACTIONS);
    fmr->out_port = OFPP_NONE;
    fmr->table_id = 0xff;
    match_init_catchall(&fmr->match);

    while (ofputil_parse_key_value(&string, &name, &value)) {
        const struct protocol *p;
        char *error = NULL;

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
        } else if (mf_from_name(name)) {
            error = parse_field(mf_from_name(name), value, port_map,
                                &fmr->match, usable_protocols);
        } else {
            if (!*value) {
                return xasprintf("%s: field %s missing value", str_, name);
            }

            if (!strcmp(name, "table")) {
                if (!ofputil_table_from_string(value, table_map,
                                               &fmr->table_id)) {
                    error = xasprintf("unknown table \"%s\"", value);
                }
            } else if (!strcmp(name, "out_port")) {
                fmr->out_port = u16_to_ofp(atoi(value));
            } else {
                return xasprintf("%s: unknown keyword %s", str_, name);
            }
        }

        if (error) {
            return error;
        }
    }
    return NULL;
}

/* Convert 'str_' (as described in the documentation for the "monitor" command
 * in the ovs-ofctl man page) into 'fmr'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_flow_monitor_request(struct ofputil_flow_monitor_request *fmr,
                           const char *str_,
                           const struct ofputil_port_map *port_map,
                           const struct ofputil_table_map *table_map,
                           enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error = parse_flow_monitor_request__(fmr, str_, port_map, table_map,
                                               string, usable_protocols);
    free(string);
    return error;
}

/* Parses 'string' as an OFPT_FLOW_MOD or NXT_FLOW_MOD with command 'command'
 * (one of OFPFC_*) into 'fm'.
 *
 * If 'command' is given as -2, 'string' may begin with a command name ("add",
 * "modify", "delete", "modify_strict", or "delete_strict").  A missing command
 * name is treated as "add".
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_flow_mod_str(struct ofputil_flow_mod *fm, const char *string,
                       const struct ofputil_port_map *port_map,
                       const struct ofputil_table_map *table_map,
                       int command,
                       enum ofputil_protocol *usable_protocols)
{
    char *error = parse_ofp_str(fm, command, string, port_map, table_map,
                                usable_protocols);

    if (!error) {
        /* Normalize a copy of the match.  This ensures that non-normalized
         * flows get logged but doesn't affect what gets sent to the switch, so
         * that the switch can do whatever it likes with the flow. */
        struct match match_copy = fm->match;
        ofputil_normalize_match(&match_copy);
    }

    return error;
}

/* Convert 'setting' (as described for the "mod-table" command
 * in ovs-ofctl man page) into 'tm->table_vacancy->vacancy_up' and
 * 'tm->table_vacancy->vacancy_down' threshold values.
 * For the two threshold values, value of vacancy_up is always greater
 * than value of vacancy_down.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_table_vacancy(struct ofputil_table_mod *tm, const char *setting)
{
    char *save_ptr = NULL;
    char *vac_up, *vac_down;
    char *value = xstrdup(setting);
    char *ret_msg;
    int vacancy_up, vacancy_down;

    strtok_r(value, ":", &save_ptr);
    vac_down = strtok_r(NULL, ",", &save_ptr);
    if (!vac_down) {
        ret_msg = xasprintf("Vacancy down value missing");
        goto exit;
    }
    if (!str_to_int(vac_down, 0, &vacancy_down) ||
        vacancy_down < 0 || vacancy_down > 100) {
        ret_msg = xasprintf("Invalid vacancy down value \"%s\"", vac_down);
        goto exit;
    }
    vac_up = strtok_r(NULL, ",", &save_ptr);
    if (!vac_up) {
        ret_msg = xasprintf("Vacancy up value missing");
        goto exit;
    }
    if (!str_to_int(vac_up, 0, &vacancy_up) ||
        vacancy_up < 0 || vacancy_up > 100) {
        ret_msg = xasprintf("Invalid vacancy up value \"%s\"", vac_up);
        goto exit;
    }
    if (vacancy_down > vacancy_up) {
        ret_msg = xasprintf("Invalid vacancy range, vacancy up should be "
                            "greater than vacancy down (%s)",
                            ofperr_to_string(OFPERR_OFPBPC_BAD_VALUE));
        goto exit;
    }

    free(value);
    tm->table_vacancy.vacancy_down = vacancy_down;
    tm->table_vacancy.vacancy_up = vacancy_up;
    return NULL;

exit:
    free(value);
    return ret_msg;
}

/* Convert 'table_id' and 'setting' (as described for the "mod-table" command
 * in the ovs-ofctl man page) into 'tm' for sending a table_mod command to a
 * switch.
 *
 * Stores a bitmap of the OpenFlow versions that are usable for 'tm' into
 * '*usable_versions'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_table_mod(struct ofputil_table_mod *tm, const char *table_id,
                    const char *setting,
                    const struct ofputil_table_map *table_map,
                    uint32_t *usable_versions)
{
    *usable_versions = 0;
    if (!strcasecmp(table_id, "all")) {
        tm->table_id = OFPTT_ALL;
    } else if (!ofputil_table_from_string(table_id, table_map,
                                          &tm->table_id)) {
        return xasprintf("unknown table \"%s\"", table_id);
    }

    tm->miss = OFPUTIL_TABLE_MISS_DEFAULT;
    tm->eviction = OFPUTIL_TABLE_EVICTION_DEFAULT;
    tm->eviction_flags = UINT32_MAX;
    tm->vacancy = OFPUTIL_TABLE_VACANCY_DEFAULT;
    tm->table_vacancy.vacancy_down = 0;
    tm->table_vacancy.vacancy_up = 0;
    tm->table_vacancy.vacancy = 0;
    /* Only OpenFlow 1.1 and 1.2 can configure table-miss via table_mod.
     * Only OpenFlow 1.4+ can configure eviction and vacancy events
     * via table_mod.
     */
    if (!strcmp(setting, "controller")) {
        tm->miss = OFPUTIL_TABLE_MISS_CONTROLLER;
        *usable_versions = (1u << OFP11_VERSION) | (1u << OFP12_VERSION);
    } else if (!strcmp(setting, "continue")) {
        tm->miss = OFPUTIL_TABLE_MISS_CONTINUE;
        *usable_versions = (1u << OFP11_VERSION) | (1u << OFP12_VERSION);
    } else if (!strcmp(setting, "drop")) {
        tm->miss = OFPUTIL_TABLE_MISS_DROP;
        *usable_versions = (1u << OFP11_VERSION) | (1u << OFP12_VERSION);
    } else if (!strcmp(setting, "evict")) {
        tm->eviction = OFPUTIL_TABLE_EVICTION_ON;
        *usable_versions = (1 << OFP14_VERSION) | (1u << OFP15_VERSION);
    } else if (!strcmp(setting, "noevict")) {
        tm->eviction = OFPUTIL_TABLE_EVICTION_OFF;
        *usable_versions = (1 << OFP14_VERSION) | (1u << OFP15_VERSION);
    } else if (!strncmp(setting, "vacancy", strcspn(setting, ":"))) {
        tm->vacancy = OFPUTIL_TABLE_VACANCY_ON;
        *usable_versions = (1 << OFP14_VERSION) | (1u << OFP15_VERSION);
        char *error = parse_ofp_table_vacancy(tm, setting);
        if (error) {
            return error;
        }
    } else if (!strcmp(setting, "novacancy")) {
        tm->vacancy = OFPUTIL_TABLE_VACANCY_OFF;
        *usable_versions = (1 << OFP14_VERSION) | (1u << OFP15_VERSION);
    } else {
        return xasprintf("invalid table_mod setting %s", setting);
    }

    if (tm->table_id == 0xfe
        && tm->miss == OFPUTIL_TABLE_MISS_CONTINUE) {
        return xstrdup("last table's flow miss handling can not be continue");
    }

    return NULL;
}


/* Opens file 'file_name' and reads each line as a flow_mod of the specified
 * type (one of OFPFC_*).  Stores each flow_mod in '*fm', an array allocated
 * on the caller's behalf, and the number of flow_mods in '*n_fms'.
 *
 * If 'command' is given as -2, each line may start with a command name
 * ("add", "modify", "delete", "modify_strict", or "delete_strict").  A missing
 * command name is treated as "add".
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_flow_mod_file(const char *file_name,
                        const struct ofputil_port_map *port_map,
                        const struct ofputil_table_map *table_map,
                        int command,
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
        error = parse_ofp_flow_mod_str(&(*fms)[*n_fms], ds_cstr(&s), port_map,
                                       table_map, command, &usable);
        if (error) {
            char *err_msg;
            size_t i;

            for (i = 0; i < *n_fms; i++) {
                free(CONST_CAST(struct ofpact *, (*fms)[i].ofpacts));
            }
            free(*fms);
            *fms = NULL;
            *n_fms = 0;

            ds_destroy(&s);
            if (stream != stdin) {
                fclose(stream);
            }

            err_msg = xasprintf("%s:%d: %s", file_name, line_number, error);
            free(error);
            return err_msg;
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

char * OVS_WARN_UNUSED_RESULT
parse_ofp_flow_stats_request_str(struct ofputil_flow_stats_request *fsr,
                                 bool aggregate, const char *string,
                                 const struct ofputil_port_map *port_map,
                                 const struct ofputil_table_map *table_map,
                                 enum ofputil_protocol *usable_protocols)
{
    struct ofputil_flow_mod fm;
    char *error;

    error = parse_ofp_str(&fm, -1, string, port_map, table_map,
                          usable_protocols);
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
 * prerequisites. If 'wc' is specified, masks the field in 'wc' for each of the
 * field specified in flow. If the map, 'names_portno' is specfied, converts
 * the in_port name into port no while setting the 'flow'.
 *
 * Returns NULL on success, otherwise a malloc()'d string that explains the
 * problem. */
char *
parse_ofp_exact_flow(struct flow *flow, struct flow_wildcards *wc,
                     const struct tun_table *tun_table, const char *s,
                     const struct ofputil_port_map *port_map)
{
    char *pos, *key, *value_s;
    char *error = NULL;
    char *copy;

    memset(flow, 0, sizeof *flow);
    if (wc) {
        memset(wc, 0, sizeof *wc);
    }
    flow->tunnel.metadata.tab = tun_table;

    pos = copy = xstrdup(s);
    while (ofputil_parse_key_value(&pos, &key, &value_s)) {
        const struct protocol *p;
        if (parse_protocol(key, &p)) {
            if (flow->dl_type) {
                error = xasprintf("%s: Ethernet type set multiple times", s);
                goto exit;
            }
            flow->dl_type = htons(p->dl_type);
            if (wc) {
                wc->masks.dl_type = OVS_BE16_MAX;
            }

            if (p->nw_proto) {
                if (flow->nw_proto) {
                    error = xasprintf("%s: network protocol set "
                                      "multiple times", s);
                    goto exit;
                }
                flow->nw_proto = p->nw_proto;
                if (wc) {
                    wc->masks.nw_proto = UINT8_MAX;
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

            if (!mf_are_prereqs_ok(mf, flow, NULL)) {
                error = xasprintf("%s: prerequisites not met for setting %s",
                                  s, key);
                goto exit;
            }

            if (mf_is_set(mf, flow)) {
                error = xasprintf("%s: field %s set multiple times", s, key);
                goto exit;
            }

            field_error = mf_parse_value(mf, value_s, port_map, &value);
            if (field_error) {
                error = xasprintf("%s: bad value for %s (%s)",
                                  s, key, field_error);
                free(field_error);
                goto exit;
            }

            mf_set_flow_value(mf, &value, flow);
            if (wc) {
                mf_mask_field(mf, wc);
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
        if (wc) {
            memset(wc, 0, sizeof *wc);
        }
    }
    return error;
}

static char * OVS_WARN_UNUSED_RESULT
parse_bucket_str(struct ofputil_bucket *bucket, char *str_,
                 const struct ofputil_port_map *port_map,
                 const struct ofputil_table_map *table_map,
                 uint8_t group_type, enum ofputil_protocol *usable_protocols)
{
    char *pos, *key, *value;
    struct ofpbuf ofpacts;
    struct ds actions;
    char *error;

    bucket->weight = group_type == OFPGT11_SELECT ? 1 : 0;
    bucket->bucket_id = OFPG15_BUCKET_ALL;
    bucket->watch_port = OFPP_ANY;
    bucket->watch_group = OFPG_ANY;

    ds_init(&actions);

    pos = str_;
    error = NULL;
    while (ofputil_parse_key_value(&pos, &key, &value)) {
        if (!strcasecmp(key, "weight")) {
            error = str_to_u16(value, "weight", &bucket->weight);
        } else if (!strcasecmp(key, "watch_port")) {
            if (!ofputil_port_from_string(value, port_map, &bucket->watch_port)
                || (ofp_to_u16(bucket->watch_port) >= ofp_to_u16(OFPP_MAX)
                    && bucket->watch_port != OFPP_ANY)) {
                error = xasprintf("%s: invalid watch_port", value);
            }
        } else if (!strcasecmp(key, "watch_group")) {
            error = str_to_u32(value, &bucket->watch_group);
            if (!error && bucket->watch_group > OFPG_MAX) {
                error = xasprintf("invalid watch_group id %"PRIu32,
                                  bucket->watch_group);
            }
        } else if (!strcasecmp(key, "bucket_id")) {
            error = str_to_u32(value, &bucket->bucket_id);
            if (!error && bucket->bucket_id > OFPG15_BUCKET_MAX) {
                error = xasprintf("invalid bucket_id id %"PRIu32,
                                  bucket->bucket_id);
            }
            *usable_protocols &= OFPUTIL_P_OF15_UP;
        } else if (!strcasecmp(key, "action") || !strcasecmp(key, "actions")) {
            ds_put_format(&actions, "%s,", value);
        } else {
            ds_put_format(&actions, "%s(%s),", key, value);
        }

        if (error) {
            ds_destroy(&actions);
            return error;
        }
    }

    if (!actions.length) {
        return xstrdup("bucket must specify actions");
    }
    ds_chomp(&actions, ',');

    ofpbuf_init(&ofpacts, 0);
    struct ofpact_parse_params pp = {
        .port_map = port_map,
        .table_map = table_map,
        .ofpacts = &ofpacts,
        .usable_protocols = usable_protocols,
    };
    error = ofpacts_parse_actions(ds_cstr(&actions), &pp);
    ds_destroy(&actions);
    if (error) {
        ofpbuf_uninit(&ofpacts);
        return error;
    }
    bucket->ofpacts = ofpacts.data;
    bucket->ofpacts_len = ofpacts.size;

    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_select_group_field(char *s, const struct ofputil_port_map *port_map,
                         struct field_array *fa,
                         enum ofputil_protocol *usable_protocols)
{
    char *name, *value_str;

    while (ofputil_parse_key_value(&s, &name, &value_str)) {
        const struct mf_field *mf = mf_from_name(name);

        if (mf) {
            char *error;
            union mf_value value;

            if (bitmap_is_set(fa->used.bm, mf->id)) {
                return xasprintf("%s: duplicate field", name);
            }

            if (*value_str) {
                error = mf_parse_value(mf, value_str, port_map, &value);
                if (error) {
                    return error;
                }

                /* The mask cannot be all-zeros */
                if (!mf_is_tun_metadata(mf) &&
                    is_all_zeros(&value, mf->n_bytes)) {
                    return xasprintf("%s: values are wildcards here "
                                     "and must not be all-zeros", s);
                }

                /* The values parsed are masks for fields used
                 * by the selection method */
                if (!mf_is_mask_valid(mf, &value)) {
                    return xasprintf("%s: invalid mask for field %s",
                                     value_str, mf->name);
                }
            } else {
                memset(&value, 0xff, mf->n_bytes);
            }

            field_array_set(mf->id, &value, fa);

            if (is_all_ones(&value, mf->n_bytes)) {
                *usable_protocols &= mf->usable_protocols_exact;
            } else if (mf->usable_protocols_bitwise == mf->usable_protocols_cidr
                       || ip_is_cidr(value.be32)) {
                *usable_protocols &= mf->usable_protocols_cidr;
            } else {
                *usable_protocols &= mf->usable_protocols_bitwise;
            }
        } else {
            return xasprintf("%s: unknown field %s", s, name);
        }
    }

    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_ofp_group_mod_str__(struct ofputil_group_mod *gm, int command,
                          char *string,
                          const struct ofputil_port_map *port_map,
                          const struct ofputil_table_map *table_map,
                          enum ofputil_protocol *usable_protocols)
{
    enum {
        F_GROUP_TYPE            = 1 << 0,
        F_BUCKETS               = 1 << 1,
        F_COMMAND_BUCKET_ID     = 1 << 2,
        F_COMMAND_BUCKET_ID_ALL = 1 << 3,
    } fields;
    bool had_type = false;
    bool had_command_bucket_id = false;
    struct ofputil_bucket *bucket;
    char *error = NULL;

    *usable_protocols = OFPUTIL_P_OF11_UP;

    if (command == -2) {
        size_t len;

        string += strspn(string, " \t\r\n");   /* Skip white space. */
        len = strcspn(string, ", \t\r\n"); /* Get length of the first token. */

        if (!strncmp(string, "add", len)) {
            command = OFPGC11_ADD;
        } else if (!strncmp(string, "delete", len)) {
            command = OFPGC11_DELETE;
        } else if (!strncmp(string, "modify", len)) {
            command = OFPGC11_MODIFY;
        } else if (!strncmp(string, "add_or_mod", len)) {
            command = OFPGC11_ADD_OR_MOD;
        } else if (!strncmp(string, "insert_bucket", len)) {
            command = OFPGC15_INSERT_BUCKET;
        } else if (!strncmp(string, "remove_bucket", len)) {
            command = OFPGC15_REMOVE_BUCKET;
        } else {
            len = 0;
            command = OFPGC11_ADD;
        }
        string += len;
    }

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

    case OFPGC11_ADD_OR_MOD:
        fields = F_GROUP_TYPE | F_BUCKETS;
        break;

    case OFPGC15_INSERT_BUCKET:
        fields = F_BUCKETS | F_COMMAND_BUCKET_ID;
        *usable_protocols &= OFPUTIL_P_OF15_UP;
        break;

    case OFPGC15_REMOVE_BUCKET:
        fields = F_COMMAND_BUCKET_ID | F_COMMAND_BUCKET_ID_ALL;
        *usable_protocols &= OFPUTIL_P_OF15_UP;
        break;

    default:
        OVS_NOT_REACHED();
    }

    memset(gm, 0, sizeof *gm);
    gm->command = command;
    gm->group_id = OFPG_ANY;
    gm->command_bucket_id = OFPG15_BUCKET_ALL;
    ovs_list_init(&gm->buckets);
    if (command == OFPGC11_DELETE && string[0] == '\0') {
        gm->group_id = OFPG_ALL;
        return NULL;
    }

    *usable_protocols = OFPUTIL_P_OF11_UP;

    /* Strip the buckets off the end of 'string', if there are any, saving a
     * pointer for later.  We want to parse the buckets last because the bucket
     * type influences bucket defaults. */
    char *bkt_str = strstr(string, "bucket=");
    if (bkt_str) {
        if (!(fields & F_BUCKETS)) {
            error = xstrdup("bucket is not needed");
            goto out;
        }
        *bkt_str = '\0';
    }

    /* Parse everything before the buckets. */
    char *pos = string;
    char *name, *value;
    while (ofputil_parse_key_value(&pos, &name, &value)) {
        if (!strcmp(name, "command_bucket_id")) {
            if (!(fields & F_COMMAND_BUCKET_ID)) {
                error = xstrdup("command bucket id is not needed");
                goto out;
            }
            if (!strcmp(value, "all")) {
                gm->command_bucket_id = OFPG15_BUCKET_ALL;
            } else if (!strcmp(value, "first")) {
                gm->command_bucket_id = OFPG15_BUCKET_FIRST;
            } else if (!strcmp(value, "last")) {
                gm->command_bucket_id = OFPG15_BUCKET_LAST;
            } else {
                error = str_to_u32(value, &gm->command_bucket_id);
                if (error) {
                    goto out;
                }
                if (gm->command_bucket_id > OFPG15_BUCKET_MAX
                    && (gm->command_bucket_id != OFPG15_BUCKET_FIRST
                        && gm->command_bucket_id != OFPG15_BUCKET_LAST
                        && gm->command_bucket_id != OFPG15_BUCKET_ALL)) {
                    error = xasprintf("invalid command bucket id %"PRIu32,
                                      gm->command_bucket_id);
                    goto out;
                }
            }
            if (gm->command_bucket_id == OFPG15_BUCKET_ALL
                && !(fields & F_COMMAND_BUCKET_ID_ALL)) {
                error = xstrdup("command_bucket_id=all is not permitted");
                goto out;
            }
            had_command_bucket_id = true;
        } else if (!strcmp(name, "group_id")) {
            if(!strcmp(value, "all")) {
                gm->group_id = OFPG_ALL;
            } else {
                error = str_to_u32(value, &gm->group_id);
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
        } else if (!strcmp(name, "selection_method")) {
            if (!(fields & F_GROUP_TYPE)) {
                error = xstrdup("selection method is not needed");
                goto out;
            }
            if (strlen(value) >= NTR_MAX_SELECTION_METHOD_LEN) {
                error = xasprintf("selection method is longer than %u"
                                  " bytes long",
                                  NTR_MAX_SELECTION_METHOD_LEN - 1);
                goto out;
            }
            memset(gm->props.selection_method, '\0',
                   NTR_MAX_SELECTION_METHOD_LEN);
            strcpy(gm->props.selection_method, value);
            *usable_protocols &= OFPUTIL_P_OF15_UP;
        } else if (!strcmp(name, "selection_method_param")) {
            if (!(fields & F_GROUP_TYPE)) {
                error = xstrdup("selection method param is not needed");
                goto out;
            }
            error = str_to_u64(value, &gm->props.selection_method_param);
            if (error) {
                goto out;
            }
            *usable_protocols &= OFPUTIL_P_OF15_UP;
        } else if (!strcmp(name, "fields")) {
            if (!(fields & F_GROUP_TYPE)) {
                error = xstrdup("fields are not needed");
                goto out;
            }
            error = parse_select_group_field(value, port_map,
                                             &gm->props.fields,
                                             usable_protocols);
            if (error) {
                goto out;
            }
            *usable_protocols &= OFPUTIL_P_OF15_UP;
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

    /* Exclude fields for non "hash" selection method. */
    if (strcmp(gm->props.selection_method, "hash") &&
        gm->props.fields.values_size) {
        error = xstrdup("fields may only be specified with \"selection_method=hash\"");
        goto out;
    }
    /* Exclude selection_method_param if no selection_method is given. */
    if (gm->props.selection_method[0] == 0
        && gm->props.selection_method_param != 0) {
        error = xstrdup("selection_method_param is only allowed with \"selection_method\"");
        goto out;
    }
    if (fields & F_COMMAND_BUCKET_ID) {
        if (!(fields & F_COMMAND_BUCKET_ID_ALL || had_command_bucket_id)) {
            error = xstrdup("must specify a command bucket id");
            goto out;
        }
    } else if (had_command_bucket_id) {
        error = xstrdup("command bucket id is not needed");
        goto out;
    }

    /* Now parse the buckets, if any. */
    while (bkt_str) {
        char *next_bkt_str;

        bkt_str = strchr(bkt_str + 1, '=');
        if (!bkt_str) {
            error = xstrdup("must specify bucket content");
            goto out;
        }
        bkt_str++;

        next_bkt_str = strstr(bkt_str, "bucket=");
        if (next_bkt_str) {
            *next_bkt_str = '\0';
        }

        bucket = xzalloc(sizeof(struct ofputil_bucket));
        error = parse_bucket_str(bucket, bkt_str, port_map, table_map,
                                 gm->type, usable_protocols);
        if (error) {
            free(bucket);
            goto out;
        }
        ovs_list_push_back(&gm->buckets, &bucket->list_node);

        if (gm->type != OFPGT11_SELECT && bucket->weight) {
            error = xstrdup("Only select groups can have bucket weights.");
            goto out;
        }

        bkt_str = next_bkt_str;
    }
    if (gm->type == OFPGT11_INDIRECT && !ovs_list_is_short(&gm->buckets)) {
        error = xstrdup("Indirect groups can have at most one bucket.");
        goto out;
    }

    return NULL;
 out:
    ofputil_uninit_group_mod(gm);
    return error;
}

/* If 'command' is given as -2, each line may start with a command name ("add",
 * "modify", "add_or_mod", "delete", "insert_bucket", or "remove_bucket").  A
 * missing command name is treated as "add".
 */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_group_mod_str(struct ofputil_group_mod *gm, int command,
                        const char *str_,
                        const struct ofputil_port_map *port_map,
                        const struct ofputil_table_map *table_map,
                        enum ofputil_protocol *usable_protocols)
{
    char *string = xstrdup(str_);
    char *error = parse_ofp_group_mod_str__(gm, command, string, port_map,
                                            table_map, usable_protocols);
    free(string);
    return error;
}

/* If 'command' is given as -2, each line may start with a command name ("add",
 * "modify", "add_or_mod", "delete", "insert_bucket", or "remove_bucket").  A
 * missing command name is treated as "add".
 */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_group_mod_file(const char *file_name,
                         const struct ofputil_port_map *port_map,
                         const struct ofputil_table_map *table_map,
                         int command,
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
            struct ofputil_group_mod *new_gms;
            size_t i;

            new_gms = x2nrealloc(*gms, &allocated_gms, sizeof **gms);
            for (i = 0; i < *n_gms; i++) {
                ovs_list_moved(&new_gms[i].buckets, &(*gms)[i].buckets);
            }
            *gms = new_gms;
        }
        error = parse_ofp_group_mod_str(&(*gms)[*n_gms], command, ds_cstr(&s),
                                        port_map, table_map, &usable);
        if (error) {
            size_t i;

            for (i = 0; i < *n_gms; i++) {
                ofputil_uninit_group_mod(&(*gms)[i]);
            }
            free(*gms);
            *gms = NULL;
            *n_gms = 0;

            ds_destroy(&s);
            if (stream != stdin) {
                fclose(stream);
            }

            char *ret = xasprintf("%s:%d: %s", file_name, line_number, error);
            free(error);
            return ret;
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

/* Opens file 'file_name' and reads each line as a flow_mod or a group_mod,
 * depending on the first keyword on each line.  Stores each flow and group
 * mods in '*bms', an array allocated on the caller's behalf, and the number of
 * messages in '*n_bms'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
parse_ofp_bundle_file(const char *file_name,
                      const struct ofputil_port_map *port_map,
                      const struct ofputil_table_map *table_map,
                      struct ofputil_bundle_msg **bms, size_t *n_bms,
                      enum ofputil_protocol *usable_protocols)
{
    size_t allocated_bms;
    char *error = NULL;
    int line_number;
    FILE *stream;
    struct ds ds;

    *usable_protocols = OFPUTIL_P_ANY;

    *bms = NULL;
    *n_bms = 0;

    stream = !strcmp(file_name, "-") ? stdin : fopen(file_name, "r");
    if (stream == NULL) {
        return xasprintf("%s: open failed (%s)",
                         file_name, ovs_strerror(errno));
    }

    allocated_bms = *n_bms;
    ds_init(&ds);
    line_number = 0;
    while (!ds_get_preprocessed_line(&ds, stream, &line_number)) {
        enum ofputil_protocol usable;
        char *s = ds_cstr(&ds);
        size_t len;

        if (*n_bms >= allocated_bms) {
            struct ofputil_bundle_msg *new_bms;

            new_bms = x2nrealloc(*bms, &allocated_bms, sizeof **bms);
            for (size_t i = 0; i < *n_bms; i++) {
                if (new_bms[i].type == OFPTYPE_GROUP_MOD) {
                    ovs_list_moved(&new_bms[i].gm.buckets,
                                   &(*bms)[i].gm.buckets);
                }
            }
            *bms = new_bms;
        }

        s += strspn(s, " \t\r\n");   /* Skip white space. */
        len = strcspn(s, ", \t\r\n"); /* Get length of the first token. */

        if (!strncmp(s, "flow", len)) {
            s += len;
            error = parse_ofp_flow_mod_str(&(*bms)[*n_bms].fm, s, port_map,
                                           table_map, -2, &usable);
            if (error) {
                break;
            }
            (*bms)[*n_bms].type = OFPTYPE_FLOW_MOD;
        } else if (!strncmp(s, "group", len)) {
            s += len;
            error = parse_ofp_group_mod_str(&(*bms)[*n_bms].gm, -2, s,
                                            port_map, table_map, &usable);
            if (error) {
                break;
            }
            (*bms)[*n_bms].type = OFPTYPE_GROUP_MOD;
        } else if (!strncmp(s, "packet-out", len)) {
            s += len;
            error = parse_ofp_packet_out_str(&(*bms)[*n_bms].po, s, port_map,
                                             table_map, &usable);
            if (error) {
                break;
            }
            (*bms)[*n_bms].type = OFPTYPE_PACKET_OUT;
        } else {
            error = xasprintf("Unsupported bundle message type: %.*s",
                              (int)len, s);
            break;
        }

        *usable_protocols &= usable; /* Each line can narrow the set. */
        *n_bms += 1;
    }

    ds_destroy(&ds);
    if (stream != stdin) {
        fclose(stream);
    }

    if (error) {
        char *err_msg = xasprintf("%s:%d: %s", file_name, line_number, error);
        free(error);

        ofputil_free_bundle_msgs(*bms, *n_bms);
        *bms = NULL;
        *n_bms = 0;
        return err_msg;
    }
    return NULL;
}

char * OVS_WARN_UNUSED_RESULT
parse_ofp_tlv_table_mod_str(struct ofputil_tlv_table_mod *ttm,
                               uint16_t command, const char *s,
                               enum ofputil_protocol *usable_protocols)
{
    *usable_protocols = OFPUTIL_P_NXM_OXM_ANY;

    ttm->command = command;
    ovs_list_init(&ttm->mappings);

    while (*s) {
        struct ofputil_tlv_map *map = xmalloc(sizeof *map);
        int n;

        if (*s == ',') {
            s++;
        }

        ovs_list_push_back(&ttm->mappings, &map->list_node);

        if (!ovs_scan(s, "{class=%"SCNi16",type=%"SCNi8",len=%"SCNi8"}->tun_metadata%"SCNi16"%n",
                      &map->option_class, &map->option_type, &map->option_len,
                      &map->index, &n)) {
            ofputil_uninit_tlv_table(&ttm->mappings);
            return xstrdup("invalid tlv mapping");
        }

        s += n;
    }

    return NULL;
}
