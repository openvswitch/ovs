/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "openvswitch/vconn.h"

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
str_to_mac(const char *str, uint8_t mac[ETH_ADDR_LEN])
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
static char * OVS_WARN_UNUSED_RESULT
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
    char *save_ptr = NULL;
    char *act_str = NULL;
    char *name;

    *usable_protocols = OFPUTIL_P_ANY;

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
    fm->importance = 0;
    fm->out_group = OFPG11_ANY;
    fm->delete_reason = OFPRR_DELETE;
    if (fields & F_ACTIONS) {
        act_str = extract_actions(string);
        if (!act_str) {
            return xstrdup("must specify an action");
        }
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
        } else if (!strcmp(name, "no_readonly_table")
                   || !strcmp(name, "allow_hidden_fields")) {
             /* ignore these fields. */
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
        enum ofputil_protocol action_usable_protocols;
        struct ofpbuf ofpacts;
        char *error;

        ofpbuf_init(&ofpacts, 32);
        error = ofpacts_parse_instructions(act_str, &ofpacts,
                                           &action_usable_protocols);
        *usable_protocols &= action_usable_protocols;
        if (!error) {
            enum ofperr err;

            err = ofpacts_check(ofpbuf_data(&ofpacts), ofpbuf_size(&ofpacts), &fm->match.flow,
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

        fm->ofpacts_len = ofpbuf_size(&ofpacts);
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
char * OVS_WARN_UNUSED_RESULT
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
                             const char *str_, char *string,
                             enum ofputil_protocol *usable_protocols)
{
    static atomic_count id = ATOMIC_COUNT_INIT(0);
    char *save_ptr = NULL;
    char *name;

    fmr->id = atomic_count_inc(&id);

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
char * OVS_WARN_UNUSED_RESULT
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

/* Parses 'string' as an OFPT_FLOW_MOD or NXT_FLOW_MOD with command 'command'
 * (one of OFPFC_*) into 'fm'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
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
char * OVS_WARN_UNUSED_RESULT
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
        tm->miss_config = OFPUTIL_TABLE_MISS_CONTROLLER;
    } else if (strcmp(flow_miss_handling, "continue") == 0) {
        tm->miss_config = OFPUTIL_TABLE_MISS_CONTINUE;
    } else if (strcmp(flow_miss_handling, "drop") == 0) {
        tm->miss_config = OFPUTIL_TABLE_MISS_DROP;
    } else {
        return xasprintf("invalid flow_miss_handling %s", flow_miss_handling);
    }

    if (tm->table_id == 0xfe
        && tm->miss_config == OFPUTIL_TABLE_MISS_CONTINUE) {
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
char * OVS_WARN_UNUSED_RESULT
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
                free(CONST_CAST(struct ofpact *, (*fms)[i].ofpacts));
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

char * OVS_WARN_UNUSED_RESULT
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

static char * OVS_WARN_UNUSED_RESULT
parse_bucket_str(struct ofputil_bucket *bucket, char *str_,
                  enum ofputil_protocol *usable_protocols)
{
    char *pos, *key, *value;
    struct ofpbuf ofpacts;
    struct ds actions;
    char *error;

    bucket->weight = 1;
    bucket->bucket_id = OFPG15_BUCKET_ALL;
    bucket->watch_port = OFPP_ANY;
    bucket->watch_group = OFPG11_ANY;

    ds_init(&actions);

    pos = str_;
    error = NULL;
    while (ofputil_parse_key_value(&pos, &key, &value)) {
        if (!strcasecmp(key, "weight")) {
            error = str_to_u16(value, "weight", &bucket->weight);
        } else if (!strcasecmp(key, "watch_port")) {
            if (!ofputil_port_from_string(value, &bucket->watch_port)
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
    error = ofpacts_parse_actions(ds_cstr(&actions), &ofpacts,
                                  usable_protocols);
    ds_destroy(&actions);
    if (error) {
        ofpbuf_uninit(&ofpacts);
        return error;
    }
    bucket->ofpacts = ofpbuf_data(&ofpacts);
    bucket->ofpacts_len = ofpbuf_size(&ofpacts);

    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_ofp_group_mod_str__(struct ofputil_group_mod *gm, uint16_t command,
                          char *string,
                          enum ofputil_protocol *usable_protocols)
{
    enum {
        F_GROUP_TYPE            = 1 << 0,
        F_BUCKETS               = 1 << 1,
        F_COMMAND_BUCKET_ID     = 1 << 2,
        F_COMMAND_BUCKET_ID_ALL = 1 << 3,
    } fields;
    char *save_ptr = NULL;
    bool had_type = false;
    bool had_command_bucket_id = false;
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
    list_init(&gm->buckets);
    if (command == OFPGC11_DELETE && string[0] == '\0') {
        gm->group_id = OFPG_ALL;
        return NULL;
    }

    *usable_protocols = OFPUTIL_P_OF11_UP;

    if (fields & F_BUCKETS) {
        char *bkt_str = strstr(string, "bucket=");

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

            next_bkt_str = strstr(bkt_str, "bucket=");
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
                char *error = str_to_u32(value, &gm->command_bucket_id);
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

    if (fields & F_COMMAND_BUCKET_ID) {
        if (!(fields & F_COMMAND_BUCKET_ID_ALL || had_command_bucket_id)) {
            error = xstrdup("must specify a command bucket id");
            goto out;
        }
    } else if (had_command_bucket_id) {
        error = xstrdup("command bucket id is not needed");
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

char * OVS_WARN_UNUSED_RESULT
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

char * OVS_WARN_UNUSED_RESULT
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
