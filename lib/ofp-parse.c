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
#include "openvswitch/ofp-parse.h"
#include <errno.h>
#include "byte-order.h"
#include "openvswitch/match.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-table.h"
#include "packets.h"
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

bool
ofp_parse_protocol(const char *name, const struct ofp_protocol **p_out)
{
    static const struct ofp_protocol protocols[] = {
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
    const struct ofp_protocol *p;

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
char * OVS_WARN_UNUSED_RESULT
ofp_parse_field(const struct mf_field *mf, const char *s,
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

char *
ofp_extract_actions(char *s)
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

static size_t
parse_value(const char *s, const char *delimiters)
{
    size_t n = 0;

    /* Iterate until we reach a delimiter.
     *
     * strchr(s, '\0') returns s+strlen(s), so this test handles the null
     * terminator at the end of 's'.  */
    while (!strchr(delimiters, s[n])) {
        if (s[n] == '(') {
            int level = 0;
            do {
                switch (s[n]) {
                case '\0':
                    return n;
                case '(':
                    level++;
                    break;
                case ')':
                    level--;
                    break;
                }
                n++;
            } while (level > 0);
        } else {
            n++;
        }
    }
    return n;
}

/* Parses a key or a key-value pair from '*stringp'.
 *
 * On success: Stores the key into '*keyp'.  Stores the value, if present, into
 * '*valuep', otherwise an empty string.  Advances '*stringp' past the end of
 * the key-value pair, preparing it for another call.  '*keyp' and '*valuep'
 * are substrings of '*stringp' created by replacing some of its bytes by null
 * terminators.  Returns true.
 *
 * If '*stringp' is just white space or commas, sets '*keyp' and '*valuep' to
 * NULL and returns false. */
bool
ofputil_parse_key_value(char **stringp, char **keyp, char **valuep)
{
    /* Skip white space and delimiters.  If that brings us to the end of the
     * input string, we are done and there are no more key-value pairs. */
    *stringp += strspn(*stringp, ", \t\r\n");
    if (**stringp == '\0') {
        *keyp = *valuep = NULL;
        return false;
    }

    /* Extract the key and the delimiter that ends the key-value pair or begins
     * the value.  Advance the input position past the key and delimiter. */
    char *key = *stringp;
    size_t key_len = strcspn(key, ":=(, \t\r\n");
    char key_delim = key[key_len];
    key[key_len] = '\0';
    *stringp += key_len + (key_delim != '\0');

    /* Figure out what delimiter ends the value:
     *
     *     - If key_delim is ":" or "=", the value extends until white space
     *       or a comma.
     *
     *     - If key_delim is "(", the value extends until ")".
     *
     * If there is no value, we are done. */
    const char *value_delims;
    if (key_delim == ':' || key_delim == '=') {
        value_delims = ", \t\r\n";
    } else if (key_delim == '(') {
        value_delims = ")";
    } else {
        *keyp = key;
        *valuep = key + key_len; /* Empty string. */
        return true;
    }

    /* Extract the value.  Advance the input position past the value and
     * delimiter. */
    char *value = *stringp;
    size_t value_len = parse_value(value, value_delims);
    char value_delim = value[value_len];
    value[value_len] = '\0';
    *stringp += value_len + (value_delim != '\0');

    *keyp = key;
    *valuep = value;
    return true;
}
