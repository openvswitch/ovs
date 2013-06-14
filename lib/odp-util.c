/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <arpa/inet.h>
#include "odp-util.h"
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include <string.h>
#include "byte-order.h"
#include "coverage.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "packets.h"
#include "simap.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(odp_util);

/* The interface between userspace and kernel uses an "OVS_*" prefix.
 * Since this is fairly non-specific for the OVS userspace components,
 * "ODP_*" (Open vSwitch Datapath) is used as the prefix for
 * interactions with the datapath.
 */

/* The set of characters that may separate one action or one key attribute
 * from another. */
static const char *delimiters = ", \t\r\n";

static int parse_odp_key_attr(const char *, const struct simap *port_names,
                              struct ofpbuf *);
static void format_odp_key_attr(const struct nlattr *a, struct ds *ds);

/* Returns one the following for the action with the given OVS_ACTION_ATTR_*
 * 'type':
 *
 *   - For an action whose argument has a fixed length, returned that
 *     nonnegative length in bytes.
 *
 *   - For an action with a variable-length argument, returns -2.
 *
 *   - For an invalid 'type', returns -1. */
static int
odp_action_len(uint16_t type)
{
    if (type > OVS_ACTION_ATTR_MAX) {
        return -1;
    }

    switch ((enum ovs_action_attr) type) {
    case OVS_ACTION_ATTR_OUTPUT: return sizeof(uint32_t);
    case OVS_ACTION_ATTR_USERSPACE: return -2;
    case OVS_ACTION_ATTR_PUSH_VLAN: return sizeof(struct ovs_action_push_vlan);
    case OVS_ACTION_ATTR_POP_VLAN: return 0;
    case OVS_ACTION_ATTR_SET: return -2;
    case OVS_ACTION_ATTR_SAMPLE: return -2;

    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        return -1;
    }

    return -1;
}

static const char *
ovs_key_attr_to_string(enum ovs_key_attr attr)
{
    static char unknown_attr[3 + INT_STRLEN(unsigned int) + 1];

    switch (attr) {
    case OVS_KEY_ATTR_UNSPEC: return "unspec";
    case OVS_KEY_ATTR_ENCAP: return "encap";
    case OVS_KEY_ATTR_PRIORITY: return "skb_priority";
    case OVS_KEY_ATTR_SKB_MARK: return "skb_mark";
    case OVS_KEY_ATTR_TUN_ID: return "tun_id";
    case OVS_KEY_ATTR_TUNNEL: return "tunnel";
    case OVS_KEY_ATTR_IN_PORT: return "in_port";
    case OVS_KEY_ATTR_ETHERNET: return "eth";
    case OVS_KEY_ATTR_VLAN: return "vlan";
    case OVS_KEY_ATTR_ETHERTYPE: return "eth_type";
    case OVS_KEY_ATTR_IPV4: return "ipv4";
    case OVS_KEY_ATTR_IPV6: return "ipv6";
    case OVS_KEY_ATTR_TCP: return "tcp";
    case OVS_KEY_ATTR_UDP: return "udp";
    case OVS_KEY_ATTR_ICMP: return "icmp";
    case OVS_KEY_ATTR_ICMPV6: return "icmpv6";
    case OVS_KEY_ATTR_ARP: return "arp";
    case OVS_KEY_ATTR_ND: return "nd";

    case __OVS_KEY_ATTR_MAX:
    default:
        snprintf(unknown_attr, sizeof unknown_attr, "key%u",
                 (unsigned int) attr);
        return unknown_attr;
    }
}

static void
format_generic_odp_action(struct ds *ds, const struct nlattr *a)
{
    size_t len = nl_attr_get_size(a);

    ds_put_format(ds, "action%"PRId16, nl_attr_type(a));
    if (len) {
        const uint8_t *unspec;
        unsigned int i;

        unspec = nl_attr_get(a);
        for (i = 0; i < len; i++) {
            ds_put_char(ds, i ? ' ': '(');
            ds_put_format(ds, "%02x", unspec[i]);
        }
        ds_put_char(ds, ')');
    }
}

static void
format_odp_sample_action(struct ds *ds, const struct nlattr *attr)
{
    static const struct nl_policy ovs_sample_policy[] = {
        [OVS_SAMPLE_ATTR_PROBABILITY] = { .type = NL_A_U32 },
        [OVS_SAMPLE_ATTR_ACTIONS] = { .type = NL_A_NESTED }
    };
    struct nlattr *a[ARRAY_SIZE(ovs_sample_policy)];
    double percentage;
    const struct nlattr *nla_acts;
    int len;

    ds_put_cstr(ds, "sample");

    if (!nl_parse_nested(attr, ovs_sample_policy, a, ARRAY_SIZE(a))) {
        ds_put_cstr(ds, "(error)");
        return;
    }

    percentage = (100.0 * nl_attr_get_u32(a[OVS_SAMPLE_ATTR_PROBABILITY])) /
                        UINT32_MAX;

    ds_put_format(ds, "(sample=%.1f%%,", percentage);

    ds_put_cstr(ds, "actions(");
    nla_acts = nl_attr_get(a[OVS_SAMPLE_ATTR_ACTIONS]);
    len = nl_attr_get_size(a[OVS_SAMPLE_ATTR_ACTIONS]);
    format_odp_actions(ds, nla_acts, len);
    ds_put_format(ds, "))");
}

static const char *
slow_path_reason_to_string(uint32_t data)
{
    enum slow_path_reason bit = (enum slow_path_reason) data;

    switch (bit) {
    case SLOW_CFM:
        return "cfm";
    case SLOW_LACP:
        return "lacp";
    case SLOW_STP:
        return "stp";
    case SLOW_IN_BAND:
        return "in_band";
    case SLOW_CONTROLLER:
        return "controller";
    case SLOW_MATCH:
        return "match";
    default:
        return NULL;
    }
}

static int
parse_flags(const char *s, const char *(*bit_to_string)(uint32_t),
            uint32_t *res)
{
    uint32_t result = 0;
    int n = 0;

    if (s[n] != '(') {
        return -EINVAL;
    }
    n++;

    while (s[n] != ')') {
        unsigned long long int flags;
        uint32_t bit;
        int n0;

        if (sscanf(&s[n], "%lli%n", &flags, &n0) > 0 && n0 > 0) {
            n += n0 + (s[n + n0] == ',');
            result |= flags;
            continue;
        }

        for (bit = 1; bit; bit <<= 1) {
            const char *name = bit_to_string(bit);
            size_t len;

            if (!name) {
                continue;
            }

            len = strlen(name);
            if (!strncmp(s + n, name, len) &&
                (s[n + len] == ',' || s[n + len] == ')')) {
                result |= bit;
                n += len + (s[n + len] == ',');
                break;
            }
        }

        if (!bit) {
            return -EINVAL;
        }
    }
    n++;

    *res = result;
    return n;
}

static void
format_odp_userspace_action(struct ds *ds, const struct nlattr *attr)
{
    static const struct nl_policy ovs_userspace_policy[] = {
        [OVS_USERSPACE_ATTR_PID] = { .type = NL_A_U32 },
        [OVS_USERSPACE_ATTR_USERDATA] = { .type = NL_A_U64, .optional = true },
    };
    struct nlattr *a[ARRAY_SIZE(ovs_userspace_policy)];

    if (!nl_parse_nested(attr, ovs_userspace_policy, a, ARRAY_SIZE(a))) {
        ds_put_cstr(ds, "userspace(error)");
        return;
    }

    ds_put_format(ds, "userspace(pid=%"PRIu32,
                  nl_attr_get_u32(a[OVS_USERSPACE_ATTR_PID]));

    if (a[OVS_USERSPACE_ATTR_USERDATA]) {
        uint64_t userdata = nl_attr_get_u64(a[OVS_USERSPACE_ATTR_USERDATA]);
        union user_action_cookie cookie;

        memcpy(&cookie, &userdata, sizeof cookie);

        switch (cookie.type) {
        case USER_ACTION_COOKIE_SFLOW:
            ds_put_format(ds, ",sFlow("
                          "vid=%"PRIu16",pcp=%"PRIu8",output=%"PRIu32")",
                          vlan_tci_to_vid(cookie.sflow.vlan_tci),
                          vlan_tci_to_pcp(cookie.sflow.vlan_tci),
                          cookie.sflow.output);
            break;

        case USER_ACTION_COOKIE_SLOW_PATH:
            ds_put_cstr(ds, ",slow_path(");
            format_flags(ds, slow_path_reason_to_string,
                         cookie.slow_path.reason, ',');
            ds_put_format(ds, ")");
            break;

        case USER_ACTION_COOKIE_UNSPEC:
        default:
            ds_put_format(ds, ",userdata=0x%"PRIx64, userdata);
            break;
        }
    }

    ds_put_char(ds, ')');
}

static void
format_vlan_tci(struct ds *ds, ovs_be16 vlan_tci)
{
    ds_put_format(ds, "vid=%"PRIu16",pcp=%d",
                  vlan_tci_to_vid(vlan_tci),
                  vlan_tci_to_pcp(vlan_tci));
    if (!(vlan_tci & htons(VLAN_CFI))) {
        ds_put_cstr(ds, ",cfi=0");
    }
}

static void
format_odp_action(struct ds *ds, const struct nlattr *a)
{
    int expected_len;
    enum ovs_action_attr type = nl_attr_type(a);
    const struct ovs_action_push_vlan *vlan;

    expected_len = odp_action_len(nl_attr_type(a));
    if (expected_len != -2 && nl_attr_get_size(a) != expected_len) {
        ds_put_format(ds, "bad length %zu, expected %d for: ",
                      nl_attr_get_size(a), expected_len);
        format_generic_odp_action(ds, a);
        return;
    }

    switch (type) {
    case OVS_ACTION_ATTR_OUTPUT:
        ds_put_format(ds, "%"PRIu32, nl_attr_get_u32(a));
        break;
    case OVS_ACTION_ATTR_USERSPACE:
        format_odp_userspace_action(ds, a);
        break;
    case OVS_ACTION_ATTR_SET:
        ds_put_cstr(ds, "set(");
        format_odp_key_attr(nl_attr_get(a), ds);
        ds_put_cstr(ds, ")");
        break;
    case OVS_ACTION_ATTR_PUSH_VLAN:
        vlan = nl_attr_get(a);
        ds_put_cstr(ds, "push_vlan(");
        if (vlan->vlan_tpid != htons(ETH_TYPE_VLAN)) {
            ds_put_format(ds, "tpid=0x%04"PRIx16",", ntohs(vlan->vlan_tpid));
        }
        format_vlan_tci(ds, vlan->vlan_tci);
        ds_put_char(ds, ')');
        break;
    case OVS_ACTION_ATTR_POP_VLAN:
        ds_put_cstr(ds, "pop_vlan");
        break;
    case OVS_ACTION_ATTR_SAMPLE:
        format_odp_sample_action(ds, a);
        break;
    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
    default:
        format_generic_odp_action(ds, a);
        break;
    }
}

void
format_odp_actions(struct ds *ds, const struct nlattr *actions,
                   size_t actions_len)
{
    if (actions_len) {
        const struct nlattr *a;
        unsigned int left;

        NL_ATTR_FOR_EACH (a, left, actions, actions_len) {
            if (a != actions) {
                ds_put_char(ds, ',');
            }
            format_odp_action(ds, a);
        }
        if (left) {
            int i;

            if (left == actions_len) {
                ds_put_cstr(ds, "<empty>");
            }
            ds_put_format(ds, ",***%u leftover bytes*** (", left);
            for (i = 0; i < left; i++) {
                ds_put_format(ds, "%02x", ((const uint8_t *) a)[i]);
            }
            ds_put_char(ds, ')');
        }
    } else {
        ds_put_cstr(ds, "drop");
    }
}

static int
parse_odp_action(const char *s, const struct simap *port_names,
                 struct ofpbuf *actions)
{
    /* Many of the sscanf calls in this function use oversized destination
     * fields because some sscanf() implementations truncate the range of %i
     * directives, so that e.g. "%"SCNi16 interprets input of "0xfedc" as a
     * value of 0x7fff.  The other alternatives are to allow only a single
     * radix (e.g. decimal or hexadecimal) or to write more sophisticated
     * parsers.
     *
     * The tun_id parser has to use an alternative approach because there is no
     * type larger than 64 bits. */

    {
        unsigned long long int port;
        int n = -1;

        if (sscanf(s, "%lli%n", &port, &n) > 0 && n > 0) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_OUTPUT, port);
            return n;
        }
    }

    if (port_names) {
        int len = strcspn(s, delimiters);
        struct simap_node *node;

        node = simap_find_len(port_names, s, len);
        if (node) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_OUTPUT, node->data);
            return len;
        }
    }

    {
        unsigned long long int pid;
        unsigned long long int output;
        char userdata_s[32];
        int vid, pcp;
        int n = -1;

        if (sscanf(s, "userspace(pid=%lli)%n", &pid, &n) > 0 && n > 0) {
            odp_put_userspace_action(pid, NULL, actions);
            return n;
        } else if (sscanf(s, "userspace(pid=%lli,sFlow(vid=%i,"
                          "pcp=%i,output=%lli))%n",
                          &pid, &vid, &pcp, &output, &n) > 0 && n > 0) {
            union user_action_cookie cookie;
            uint16_t tci;

            tci = vid | (pcp << VLAN_PCP_SHIFT);
            if (tci) {
                tci |= VLAN_CFI;
            }

            cookie.type = USER_ACTION_COOKIE_SFLOW;
            cookie.sflow.vlan_tci = htons(tci);
            cookie.sflow.output = output;
            odp_put_userspace_action(pid, &cookie, actions);
            return n;
        } else if (sscanf(s, "userspace(pid=%lli,slow_path%n", &pid, &n) > 0
                   && n > 0) {
            union user_action_cookie cookie;
            int res;

            cookie.type = USER_ACTION_COOKIE_SLOW_PATH;
            cookie.slow_path.unused = 0;
            cookie.slow_path.reason = 0;

            res = parse_flags(&s[n], slow_path_reason_to_string,
                              &cookie.slow_path.reason);
            if (res < 0) {
                return res;
            }
            n += res;
            if (s[n] != ')') {
                return -EINVAL;
            }
            n++;

            odp_put_userspace_action(pid, &cookie, actions);
            return n;
        } else if (sscanf(s, "userspace(pid=%lli,userdata="
                          "%31[x0123456789abcdefABCDEF])%n", &pid, userdata_s,
                          &n) > 0 && n > 0) {
            union user_action_cookie cookie;
            uint64_t userdata;

            userdata = strtoull(userdata_s, NULL, 0);
            memcpy(&cookie, &userdata, sizeof cookie);
            odp_put_userspace_action(pid, &cookie, actions);
            return n;
        }
    }

    if (!strncmp(s, "set(", 4)) {
        size_t start_ofs;
        int retval;

        start_ofs = nl_msg_start_nested(actions, OVS_ACTION_ATTR_SET);
        retval = parse_odp_key_attr(s + 4, port_names, actions);
        if (retval < 0) {
            return retval;
        }
        if (s[retval + 4] != ')') {
            return -EINVAL;
        }
        nl_msg_end_nested(actions, start_ofs);
        return retval + 5;
    }

    {
        struct ovs_action_push_vlan push;
        int tpid = ETH_TYPE_VLAN;
        int vid, pcp;
        int cfi = 1;
        int n = -1;

        if ((sscanf(s, "push_vlan(vid=%i,pcp=%i)%n", &vid, &pcp, &n) > 0
             && n > 0)
            || (sscanf(s, "push_vlan(vid=%i,pcp=%i,cfi=%i)%n",
                       &vid, &pcp, &cfi, &n) > 0 && n > 0)
            || (sscanf(s, "push_vlan(tpid=%i,vid=%i,pcp=%i)%n",
                       &tpid, &vid, &pcp, &n) > 0 && n > 0)
            || (sscanf(s, "push_vlan(tpid=%i,vid=%i,pcp=%i,cfi=%i)%n",
                       &tpid, &vid, &pcp, &cfi, &n) > 0 && n > 0)) {
            push.vlan_tpid = htons(tpid);
            push.vlan_tci = htons((vid << VLAN_VID_SHIFT)
                                  | (pcp << VLAN_PCP_SHIFT)
                                  | (cfi ? VLAN_CFI : 0));
            nl_msg_put_unspec(actions, OVS_ACTION_ATTR_PUSH_VLAN,
                              &push, sizeof push);

            return n;
        }
    }

    if (!strncmp(s, "pop_vlan", 8)) {
        nl_msg_put_flag(actions, OVS_ACTION_ATTR_POP_VLAN);
        return 8;
    }

    {
        double percentage;
        int n = -1;

        if (sscanf(s, "sample(sample=%lf%%,actions(%n", &percentage, &n) > 0
            && percentage >= 0. && percentage <= 100.0
            && n > 0) {
            size_t sample_ofs, actions_ofs;
            double probability;

            probability = floor(UINT32_MAX * (percentage / 100.0) + .5);
            sample_ofs = nl_msg_start_nested(actions, OVS_ACTION_ATTR_SAMPLE);
            nl_msg_put_u32(actions, OVS_SAMPLE_ATTR_PROBABILITY,
                           (probability <= 0 ? 0
                            : probability >= UINT32_MAX ? UINT32_MAX
                            : probability));

            actions_ofs = nl_msg_start_nested(actions,
                                              OVS_SAMPLE_ATTR_ACTIONS);
            for (;;) {
                int retval;

                n += strspn(s + n, delimiters);
                if (s[n] == ')') {
                    break;
                }

                retval = parse_odp_action(s + n, port_names, actions);
                if (retval < 0) {
                    return retval;
                }
                n += retval;
            }
            nl_msg_end_nested(actions, actions_ofs);
            nl_msg_end_nested(actions, sample_ofs);

            return s[n + 1] == ')' ? n + 2 : -EINVAL;
        }
    }

    return -EINVAL;
}

/* Parses the string representation of datapath actions, in the format output
 * by format_odp_action().  Returns 0 if successful, otherwise a positive errno
 * value.  On success, the ODP actions are appended to 'actions' as a series of
 * Netlink attributes.  On failure, no data is appended to 'actions'.  Either
 * way, 'actions''s data might be reallocated. */
int
odp_actions_from_string(const char *s, const struct simap *port_names,
                        struct ofpbuf *actions)
{
    size_t old_size;

    if (!strcasecmp(s, "drop")) {
        return 0;
    }

    old_size = actions->size;
    for (;;) {
        int retval;

        s += strspn(s, delimiters);
        if (!*s) {
            return 0;
        }

        retval = parse_odp_action(s, port_names, actions);
        if (retval < 0 || !strchr(delimiters, s[retval])) {
            actions->size = old_size;
            return -retval;
        }
        s += retval;
    }

    return 0;
}

/* Returns the correct length of the payload for a flow key attribute of the
 * specified 'type', -1 if 'type' is unknown, or -2 if the attribute's payload
 * is variable length. */
static int
odp_flow_key_attr_len(uint16_t type)
{
    if (type > OVS_KEY_ATTR_MAX) {
        return -1;
    }

    switch ((enum ovs_key_attr) type) {
    case OVS_KEY_ATTR_ENCAP: return -2;
    case OVS_KEY_ATTR_PRIORITY: return 4;
    case OVS_KEY_ATTR_SKB_MARK: return 4;
    case OVS_KEY_ATTR_TUN_ID: return 8;
    case OVS_KEY_ATTR_TUNNEL: return -2;
    case OVS_KEY_ATTR_IN_PORT: return 4;
    case OVS_KEY_ATTR_ETHERNET: return sizeof(struct ovs_key_ethernet);
    case OVS_KEY_ATTR_VLAN: return sizeof(ovs_be16);
    case OVS_KEY_ATTR_ETHERTYPE: return 2;
    case OVS_KEY_ATTR_IPV4: return sizeof(struct ovs_key_ipv4);
    case OVS_KEY_ATTR_IPV6: return sizeof(struct ovs_key_ipv6);
    case OVS_KEY_ATTR_TCP: return sizeof(struct ovs_key_tcp);
    case OVS_KEY_ATTR_UDP: return sizeof(struct ovs_key_udp);
    case OVS_KEY_ATTR_ICMP: return sizeof(struct ovs_key_icmp);
    case OVS_KEY_ATTR_ICMPV6: return sizeof(struct ovs_key_icmpv6);
    case OVS_KEY_ATTR_ARP: return sizeof(struct ovs_key_arp);
    case OVS_KEY_ATTR_ND: return sizeof(struct ovs_key_nd);

    case OVS_KEY_ATTR_UNSPEC:
    case __OVS_KEY_ATTR_MAX:
        return -1;
    }

    return -1;
}

static void
format_generic_odp_key(const struct nlattr *a, struct ds *ds)
{
    size_t len = nl_attr_get_size(a);
    if (len) {
        const uint8_t *unspec;
        unsigned int i;

        unspec = nl_attr_get(a);
        for (i = 0; i < len; i++) {
            ds_put_char(ds, i ? ' ': '(');
            ds_put_format(ds, "%02x", unspec[i]);
        }
        ds_put_char(ds, ')');
    }
}

static const char *
ovs_frag_type_to_string(enum ovs_frag_type type)
{
    switch (type) {
    case OVS_FRAG_TYPE_NONE:
        return "no";
    case OVS_FRAG_TYPE_FIRST:
        return "first";
    case OVS_FRAG_TYPE_LATER:
        return "later";
    case __OVS_FRAG_TYPE_MAX:
    default:
        return "<error>";
    }
}

static int
tunnel_key_attr_len(int type)
{
    switch (type) {
    case OVS_TUNNEL_KEY_ATTR_ID: return 8;
    case OVS_TUNNEL_KEY_ATTR_IPV4_SRC: return 4;
    case OVS_TUNNEL_KEY_ATTR_IPV4_DST: return 4;
    case OVS_TUNNEL_KEY_ATTR_TOS: return 1;
    case OVS_TUNNEL_KEY_ATTR_TTL: return 1;
    case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT: return 0;
    case OVS_TUNNEL_KEY_ATTR_CSUM: return 0;
    case __OVS_TUNNEL_KEY_ATTR_MAX:
        return -1;
    }
    return -1;
}

static enum odp_key_fitness
tun_key_from_attr(const struct nlattr *attr, struct flow_tnl *tun)
{
    unsigned int left;
    const struct nlattr *a;
    bool ttl = false;
    bool unknown = false;

    NL_NESTED_FOR_EACH(a, left, attr) {
        uint16_t type = nl_attr_type(a);
        size_t len = nl_attr_get_size(a);
        int expected_len = tunnel_key_attr_len(type);

        if (len != expected_len && expected_len >= 0) {
            return ODP_FIT_ERROR;
        }

        switch (type) {
        case OVS_TUNNEL_KEY_ATTR_ID:
            tun->tun_id = nl_attr_get_be64(a);
            tun->flags |= FLOW_TNL_F_KEY;
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
            tun->ip_src = nl_attr_get_be32(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_DST:
            tun->ip_dst = nl_attr_get_be32(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_TOS:
            tun->ip_tos = nl_attr_get_u8(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_TTL:
            tun->ip_ttl = nl_attr_get_u8(a);
            ttl = true;
            break;
        case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
            tun->flags |= FLOW_TNL_F_DONT_FRAGMENT;
            break;
        case OVS_TUNNEL_KEY_ATTR_CSUM:
            tun->flags |= FLOW_TNL_F_CSUM;
            break;
        default:
            /* Allow this to show up as unexpected, if there are unknown
             * tunnel attribute, eventually resulting in ODP_FIT_TOO_MUCH. */
            unknown = true;
            break;
        }
    }

    if (!ttl) {
        return ODP_FIT_ERROR;
    }
    if (unknown) {
            return ODP_FIT_TOO_MUCH;
    }
    return ODP_FIT_PERFECT;
}

static void
tun_key_to_attr(struct ofpbuf *a, const struct flow_tnl *tun_key)
{
    size_t tun_key_ofs;

    tun_key_ofs = nl_msg_start_nested(a, OVS_KEY_ATTR_TUNNEL);

    if (tun_key->flags & FLOW_TNL_F_KEY) {
        nl_msg_put_be64(a, OVS_TUNNEL_KEY_ATTR_ID, tun_key->tun_id);
    }
    if (tun_key->ip_src) {
        nl_msg_put_be32(a, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, tun_key->ip_src);
    }
    if (tun_key->ip_dst) {
        nl_msg_put_be32(a, OVS_TUNNEL_KEY_ATTR_IPV4_DST, tun_key->ip_dst);
    }
    if (tun_key->ip_tos) {
        nl_msg_put_u8(a, OVS_TUNNEL_KEY_ATTR_TOS, tun_key->ip_tos);
    }
    nl_msg_put_u8(a, OVS_TUNNEL_KEY_ATTR_TTL, tun_key->ip_ttl);
    if (tun_key->flags & FLOW_TNL_F_DONT_FRAGMENT) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT);
    }
    if (tun_key->flags & FLOW_TNL_F_CSUM) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_CSUM);
    }

    nl_msg_end_nested(a, tun_key_ofs);
}

static void
format_odp_key_attr(const struct nlattr *a, struct ds *ds)
{
    const struct ovs_key_ethernet *eth_key;
    const struct ovs_key_ipv4 *ipv4_key;
    const struct ovs_key_ipv6 *ipv6_key;
    const struct ovs_key_tcp *tcp_key;
    const struct ovs_key_udp *udp_key;
    const struct ovs_key_icmp *icmp_key;
    const struct ovs_key_icmpv6 *icmpv6_key;
    const struct ovs_key_arp *arp_key;
    const struct ovs_key_nd *nd_key;
    struct flow_tnl tun_key;
    enum ovs_key_attr attr = nl_attr_type(a);
    int expected_len;

    ds_put_cstr(ds, ovs_key_attr_to_string(attr));
    expected_len = odp_flow_key_attr_len(nl_attr_type(a));
    if (expected_len != -2 && nl_attr_get_size(a) != expected_len) {
        ds_put_format(ds, "(bad length %zu, expected %d)",
                      nl_attr_get_size(a),
                      odp_flow_key_attr_len(nl_attr_type(a)));
        format_generic_odp_key(a, ds);
        return;
    }

    switch (attr) {
    case OVS_KEY_ATTR_ENCAP:
        ds_put_cstr(ds, "(");
        if (nl_attr_get_size(a)) {
            odp_flow_key_format(nl_attr_get(a), nl_attr_get_size(a), ds);
        }
        ds_put_char(ds, ')');
        break;

    case OVS_KEY_ATTR_PRIORITY:
        ds_put_format(ds, "(%#"PRIx32")", nl_attr_get_u32(a));
        break;

    case OVS_KEY_ATTR_SKB_MARK:
        ds_put_format(ds, "(%#"PRIx32")", nl_attr_get_u32(a));
        break;

    case OVS_KEY_ATTR_TUN_ID:
        ds_put_format(ds, "(%#"PRIx64")", ntohll(nl_attr_get_be64(a)));
        break;

    case OVS_KEY_ATTR_TUNNEL:
        memset(&tun_key, 0, sizeof tun_key);
        if (tun_key_from_attr(a, &tun_key) == ODP_FIT_ERROR) {
            ds_put_format(ds, "(error)");
        } else {
            ds_put_format(ds, "(tun_id=0x%"PRIx64",src="IP_FMT",dst="IP_FMT","
                          "tos=0x%"PRIx8",ttl=%"PRIu8",flags(",
                          ntohll(tun_key.tun_id),
                          IP_ARGS(&tun_key.ip_src),
                          IP_ARGS(&tun_key.ip_dst),
                          tun_key.ip_tos, tun_key.ip_ttl);

            format_flags(ds, flow_tun_flag_to_string,
                         (uint32_t) tun_key.flags, ',');
            ds_put_format(ds, "))");
        }

        break;

    case OVS_KEY_ATTR_IN_PORT:
        ds_put_format(ds, "(%"PRIu32")", nl_attr_get_u32(a));
        break;

    case OVS_KEY_ATTR_ETHERNET:
        eth_key = nl_attr_get(a);
        ds_put_format(ds, "(src="ETH_ADDR_FMT",dst="ETH_ADDR_FMT")",
                      ETH_ADDR_ARGS(eth_key->eth_src),
                      ETH_ADDR_ARGS(eth_key->eth_dst));
        break;

    case OVS_KEY_ATTR_VLAN:
        ds_put_char(ds, '(');
        format_vlan_tci(ds, nl_attr_get_be16(a));
        ds_put_char(ds, ')');
        break;

    case OVS_KEY_ATTR_ETHERTYPE:
        ds_put_format(ds, "(0x%04"PRIx16")",
                      ntohs(nl_attr_get_be16(a)));
        break;

    case OVS_KEY_ATTR_IPV4:
        ipv4_key = nl_attr_get(a);
        ds_put_format(ds, "(src="IP_FMT",dst="IP_FMT",proto=%"PRIu8
                      ",tos=%#"PRIx8",ttl=%"PRIu8",frag=%s)",
                      IP_ARGS(&ipv4_key->ipv4_src),
                      IP_ARGS(&ipv4_key->ipv4_dst),
                      ipv4_key->ipv4_proto, ipv4_key->ipv4_tos,
                      ipv4_key->ipv4_ttl,
                      ovs_frag_type_to_string(ipv4_key->ipv4_frag));
        break;

    case OVS_KEY_ATTR_IPV6: {
        char src_str[INET6_ADDRSTRLEN];
        char dst_str[INET6_ADDRSTRLEN];

        ipv6_key = nl_attr_get(a);
        inet_ntop(AF_INET6, ipv6_key->ipv6_src, src_str, sizeof src_str);
        inet_ntop(AF_INET6, ipv6_key->ipv6_dst, dst_str, sizeof dst_str);

        ds_put_format(ds, "(src=%s,dst=%s,label=%#"PRIx32",proto=%"PRIu8
                      ",tclass=%#"PRIx8",hlimit=%"PRIu8",frag=%s)",
                      src_str, dst_str, ntohl(ipv6_key->ipv6_label),
                      ipv6_key->ipv6_proto, ipv6_key->ipv6_tclass,
                      ipv6_key->ipv6_hlimit,
                      ovs_frag_type_to_string(ipv6_key->ipv6_frag));
        break;
    }

    case OVS_KEY_ATTR_TCP:
        tcp_key = nl_attr_get(a);
        ds_put_format(ds, "(src=%"PRIu16",dst=%"PRIu16")",
                      ntohs(tcp_key->tcp_src), ntohs(tcp_key->tcp_dst));
        break;

    case OVS_KEY_ATTR_UDP:
        udp_key = nl_attr_get(a);
        ds_put_format(ds, "(src=%"PRIu16",dst=%"PRIu16")",
                      ntohs(udp_key->udp_src), ntohs(udp_key->udp_dst));
        break;

    case OVS_KEY_ATTR_ICMP:
        icmp_key = nl_attr_get(a);
        ds_put_format(ds, "(type=%"PRIu8",code=%"PRIu8")",
                      icmp_key->icmp_type, icmp_key->icmp_code);
        break;

    case OVS_KEY_ATTR_ICMPV6:
        icmpv6_key = nl_attr_get(a);
        ds_put_format(ds, "(type=%"PRIu8",code=%"PRIu8")",
                      icmpv6_key->icmpv6_type, icmpv6_key->icmpv6_code);
        break;

    case OVS_KEY_ATTR_ARP:
        arp_key = nl_attr_get(a);
        ds_put_format(ds, "(sip="IP_FMT",tip="IP_FMT",op=%"PRIu16","
                      "sha="ETH_ADDR_FMT",tha="ETH_ADDR_FMT")",
                      IP_ARGS(&arp_key->arp_sip), IP_ARGS(&arp_key->arp_tip),
                      ntohs(arp_key->arp_op), ETH_ADDR_ARGS(arp_key->arp_sha),
                      ETH_ADDR_ARGS(arp_key->arp_tha));
        break;

    case OVS_KEY_ATTR_ND: {
        char target[INET6_ADDRSTRLEN];

        nd_key = nl_attr_get(a);
        inet_ntop(AF_INET6, nd_key->nd_target, target, sizeof target);

        ds_put_format(ds, "(target=%s", target);
        if (!eth_addr_is_zero(nd_key->nd_sll)) {
            ds_put_format(ds, ",sll="ETH_ADDR_FMT,
                          ETH_ADDR_ARGS(nd_key->nd_sll));
        }
        if (!eth_addr_is_zero(nd_key->nd_tll)) {
            ds_put_format(ds, ",tll="ETH_ADDR_FMT,
                          ETH_ADDR_ARGS(nd_key->nd_tll));
        }
        ds_put_char(ds, ')');
        break;
    }

    case OVS_KEY_ATTR_UNSPEC:
    case __OVS_KEY_ATTR_MAX:
    default:
        format_generic_odp_key(a, ds);
        break;
    }
}

/* Appends to 'ds' a string representation of the 'key_len' bytes of
 * OVS_KEY_ATTR_* attributes in 'key'. */
void
odp_flow_key_format(const struct nlattr *key, size_t key_len, struct ds *ds)
{
    if (key_len) {
        const struct nlattr *a;
        unsigned int left;

        NL_ATTR_FOR_EACH (a, left, key, key_len) {
            if (a != key) {
                ds_put_char(ds, ',');
            }
            format_odp_key_attr(a, ds);
        }
        if (left) {
            int i;
            
            if (left == key_len) {
                ds_put_cstr(ds, "<empty>");
            }
            ds_put_format(ds, ",***%u leftover bytes*** (", left);
            for (i = 0; i < left; i++) {
                ds_put_format(ds, "%02x", ((const uint8_t *) a)[i]);
            }
            ds_put_char(ds, ')');
        }
    } else {
        ds_put_cstr(ds, "<empty>");
    }
}

static int
put_nd_key(int n, const char *nd_target_s,
           const uint8_t *nd_sll, const uint8_t *nd_tll, struct ofpbuf *key)
{
    struct ovs_key_nd nd_key;

    memset(&nd_key, 0, sizeof nd_key);
    if (inet_pton(AF_INET6, nd_target_s, nd_key.nd_target) != 1) {
        return -EINVAL;
    }
    if (nd_sll) {
        memcpy(nd_key.nd_sll, nd_sll, ETH_ADDR_LEN);
    }
    if (nd_tll) {
        memcpy(nd_key.nd_tll, nd_tll, ETH_ADDR_LEN);
    }
    nl_msg_put_unspec(key, OVS_KEY_ATTR_ND, &nd_key, sizeof nd_key);
    return n;
}

static bool
ovs_frag_type_from_string(const char *s, enum ovs_frag_type *type)
{
    if (!strcasecmp(s, "no")) {
        *type = OVS_FRAG_TYPE_NONE;
    } else if (!strcasecmp(s, "first")) {
        *type = OVS_FRAG_TYPE_FIRST;
    } else if (!strcasecmp(s, "later")) {
        *type = OVS_FRAG_TYPE_LATER;
    } else {
        return false;
    }
    return true;
}

static int
parse_odp_key_attr(const char *s, const struct simap *port_names,
                   struct ofpbuf *key)
{
    /* Many of the sscanf calls in this function use oversized destination
     * fields because some sscanf() implementations truncate the range of %i
     * directives, so that e.g. "%"SCNi16 interprets input of "0xfedc" as a
     * value of 0x7fff.  The other alternatives are to allow only a single
     * radix (e.g. decimal or hexadecimal) or to write more sophisticated
     * parsers.
     *
     * The tun_id parser has to use an alternative approach because there is no
     * type larger than 64 bits. */

    {
        unsigned long long int priority;
        int n = -1;

        if (sscanf(s, "skb_priority(%llx)%n", &priority, &n) > 0 && n > 0) {
            nl_msg_put_u32(key, OVS_KEY_ATTR_PRIORITY, priority);
            return n;
        }
    }

    {
        unsigned long long int mark;
        int n = -1;

        if (sscanf(s, "skb_mark(%llx)%n", &mark, &n) > 0 && n > 0) {
            nl_msg_put_u32(key, OVS_KEY_ATTR_SKB_MARK, mark);
            return n;
        }
    }

    {
        char tun_id_s[32];
        int n = -1;

        if (sscanf(s, "tun_id(%31[x0123456789abcdefABCDEF])%n",
                   tun_id_s, &n) > 0 && n > 0) {
            uint64_t tun_id = strtoull(tun_id_s, NULL, 0);
            nl_msg_put_be64(key, OVS_KEY_ATTR_TUN_ID, htonll(tun_id));
            return n;
        }
    }

    {
        char tun_id_s[32];
        int tos, ttl;
        struct flow_tnl tun_key;
        int n = -1;

        if (sscanf(s, "tunnel(tun_id=%31[x0123456789abcdefABCDEF],"
                   "src="IP_SCAN_FMT",dst="IP_SCAN_FMT
                   ",tos=%i,ttl=%i,flags%n", tun_id_s,
                    IP_SCAN_ARGS(&tun_key.ip_src),
                    IP_SCAN_ARGS(&tun_key.ip_dst), &tos, &ttl,
                    &n) > 0 && n > 0) {
            int res;
            uint32_t flags;

            tun_key.tun_id = htonll(strtoull(tun_id_s, NULL, 0));
            tun_key.ip_tos = tos;
            tun_key.ip_ttl = ttl;
            res = parse_flags(&s[n], flow_tun_flag_to_string, &flags);
            tun_key.flags = (uint16_t) flags;

            if (res < 0) {
                return res;
            }
            n += res;
            if (s[n] != ')') {
                return -EINVAL;
            }
            n++;
            tun_key_to_attr(key, &tun_key);
            return n;
        }
    }

    {
        unsigned long long int in_port;
        int n = -1;

        if (sscanf(s, "in_port(%lli)%n", &in_port, &n) > 0 && n > 0) {
            nl_msg_put_u32(key, OVS_KEY_ATTR_IN_PORT, in_port);
            return n;
        }
    }

    if (port_names && !strncmp(s, "in_port(", 8)) {
        const char *name;
        const struct simap_node *node;
        int name_len;

        name = s + 8;
        name_len = strcspn(s, ")");
        node = simap_find_len(port_names, name, name_len);
        if (node) {
            nl_msg_put_u32(key, OVS_KEY_ATTR_IN_PORT, node->data);
            return 8 + name_len + 1;
        }
    }

    {
        struct ovs_key_ethernet eth_key;
        int n = -1;

        if (sscanf(s,
                   "eth(src="ETH_ADDR_SCAN_FMT",dst="ETH_ADDR_SCAN_FMT")%n",
                   ETH_ADDR_SCAN_ARGS(eth_key.eth_src),
                   ETH_ADDR_SCAN_ARGS(eth_key.eth_dst), &n) > 0 && n > 0) {
            nl_msg_put_unspec(key, OVS_KEY_ATTR_ETHERNET,
                              &eth_key, sizeof eth_key);
            return n;
        }
    }

    {
        uint16_t vid;
        int pcp;
        int cfi;
        int n = -1;

        if ((sscanf(s, "vlan(vid=%"SCNi16",pcp=%i)%n", &vid, &pcp, &n) > 0
             && n > 0)) {
            nl_msg_put_be16(key, OVS_KEY_ATTR_VLAN,
                            htons((vid << VLAN_VID_SHIFT) |
                                  (pcp << VLAN_PCP_SHIFT) |
                                  VLAN_CFI));
            return n;
        } else if ((sscanf(s, "vlan(vid=%"SCNi16",pcp=%i,cfi=%i)%n",
                           &vid, &pcp, &cfi, &n) > 0
             && n > 0)) {
            nl_msg_put_be16(key, OVS_KEY_ATTR_VLAN,
                            htons((vid << VLAN_VID_SHIFT) |
                                  (pcp << VLAN_PCP_SHIFT) |
                                  (cfi ? VLAN_CFI : 0)));
            return n;
        }
    }

    {
        int eth_type;
        int n = -1;

        if (sscanf(s, "eth_type(%i)%n", &eth_type, &n) > 0 && n > 0) {
            nl_msg_put_be16(key, OVS_KEY_ATTR_ETHERTYPE, htons(eth_type));
            return n;
        }
    }

    {
        ovs_be32 ipv4_src;
        ovs_be32 ipv4_dst;
        int ipv4_proto;
        int ipv4_tos;
        int ipv4_ttl;
        char frag[8];
        enum ovs_frag_type ipv4_frag;
        int n = -1;

        if (sscanf(s, "ipv4(src="IP_SCAN_FMT",dst="IP_SCAN_FMT","
                   "proto=%i,tos=%i,ttl=%i,frag=%7[a-z])%n",
                   IP_SCAN_ARGS(&ipv4_src), IP_SCAN_ARGS(&ipv4_dst),
                   &ipv4_proto, &ipv4_tos, &ipv4_ttl, frag, &n) > 0
            && n > 0
            && ovs_frag_type_from_string(frag, &ipv4_frag)) {
            struct ovs_key_ipv4 ipv4_key;

            ipv4_key.ipv4_src = ipv4_src;
            ipv4_key.ipv4_dst = ipv4_dst;
            ipv4_key.ipv4_proto = ipv4_proto;
            ipv4_key.ipv4_tos = ipv4_tos;
            ipv4_key.ipv4_ttl = ipv4_ttl;
            ipv4_key.ipv4_frag = ipv4_frag;
            nl_msg_put_unspec(key, OVS_KEY_ATTR_IPV4,
                              &ipv4_key, sizeof ipv4_key);
            return n;
        }
    }

    {
        char ipv6_src_s[IPV6_SCAN_LEN + 1];
        char ipv6_dst_s[IPV6_SCAN_LEN + 1];
        int ipv6_label;
        int ipv6_proto;
        int ipv6_tclass;
        int ipv6_hlimit;
        char frag[8];
        enum ovs_frag_type ipv6_frag;
        int n = -1;

        if (sscanf(s, "ipv6(src="IPV6_SCAN_FMT",dst="IPV6_SCAN_FMT","
                   "label=%i,proto=%i,tclass=%i,hlimit=%i,frag=%7[a-z])%n",
                   ipv6_src_s, ipv6_dst_s, &ipv6_label,
                   &ipv6_proto, &ipv6_tclass, &ipv6_hlimit, frag, &n) > 0
            && n > 0
            && ovs_frag_type_from_string(frag, &ipv6_frag)) {
            struct ovs_key_ipv6 ipv6_key;

            if (inet_pton(AF_INET6, ipv6_src_s, &ipv6_key.ipv6_src) != 1 ||
                inet_pton(AF_INET6, ipv6_dst_s, &ipv6_key.ipv6_dst) != 1) {
                return -EINVAL;
            }
            ipv6_key.ipv6_label = htonl(ipv6_label);
            ipv6_key.ipv6_proto = ipv6_proto;
            ipv6_key.ipv6_tclass = ipv6_tclass;
            ipv6_key.ipv6_hlimit = ipv6_hlimit;
            ipv6_key.ipv6_frag = ipv6_frag;
            nl_msg_put_unspec(key, OVS_KEY_ATTR_IPV6,
                              &ipv6_key, sizeof ipv6_key);
            return n;
        }
    }

    {
        int tcp_src;
        int tcp_dst;
        int n = -1;

        if (sscanf(s, "tcp(src=%i,dst=%i)%n",&tcp_src, &tcp_dst, &n) > 0
            && n > 0) {
            struct ovs_key_tcp tcp_key;

            tcp_key.tcp_src = htons(tcp_src);
            tcp_key.tcp_dst = htons(tcp_dst);
            nl_msg_put_unspec(key, OVS_KEY_ATTR_TCP, &tcp_key, sizeof tcp_key);
            return n;
        }
    }

    {
        int udp_src;
        int udp_dst;
        int n = -1;

        if (sscanf(s, "udp(src=%i,dst=%i)%n", &udp_src, &udp_dst, &n) > 0
            && n > 0) {
            struct ovs_key_udp udp_key;

            udp_key.udp_src = htons(udp_src);
            udp_key.udp_dst = htons(udp_dst);
            nl_msg_put_unspec(key, OVS_KEY_ATTR_UDP, &udp_key, sizeof udp_key);
            return n;
        }
    }

    {
        int icmp_type;
        int icmp_code;
        int n = -1;

        if (sscanf(s, "icmp(type=%i,code=%i)%n",
                   &icmp_type, &icmp_code, &n) > 0
            && n > 0) {
            struct ovs_key_icmp icmp_key;

            icmp_key.icmp_type = icmp_type;
            icmp_key.icmp_code = icmp_code;
            nl_msg_put_unspec(key, OVS_KEY_ATTR_ICMP,
                              &icmp_key, sizeof icmp_key);
            return n;
        }
    }

    {
        struct ovs_key_icmpv6 icmpv6_key;
        int n = -1;

        if (sscanf(s, "icmpv6(type=%"SCNi8",code=%"SCNi8")%n",
                   &icmpv6_key.icmpv6_type, &icmpv6_key.icmpv6_code,&n) > 0
            && n > 0) {
            nl_msg_put_unspec(key, OVS_KEY_ATTR_ICMPV6,
                              &icmpv6_key, sizeof icmpv6_key);
            return n;
        }
    }

    {
        ovs_be32 arp_sip;
        ovs_be32 arp_tip;
        int arp_op;
        uint8_t arp_sha[ETH_ADDR_LEN];
        uint8_t arp_tha[ETH_ADDR_LEN];
        int n = -1;

        if (sscanf(s, "arp(sip="IP_SCAN_FMT",tip="IP_SCAN_FMT","
                   "op=%i,sha="ETH_ADDR_SCAN_FMT",tha="ETH_ADDR_SCAN_FMT")%n",
                   IP_SCAN_ARGS(&arp_sip),
                   IP_SCAN_ARGS(&arp_tip),
                   &arp_op,
                   ETH_ADDR_SCAN_ARGS(arp_sha),
                   ETH_ADDR_SCAN_ARGS(arp_tha), &n) > 0 && n > 0) {
            struct ovs_key_arp arp_key;

            memset(&arp_key, 0, sizeof arp_key);
            arp_key.arp_sip = arp_sip;
            arp_key.arp_tip = arp_tip;
            arp_key.arp_op = htons(arp_op);
            memcpy(arp_key.arp_sha, arp_sha, ETH_ADDR_LEN);
            memcpy(arp_key.arp_tha, arp_tha, ETH_ADDR_LEN);
            nl_msg_put_unspec(key, OVS_KEY_ATTR_ARP, &arp_key, sizeof arp_key);
            return n;
        }
    }

    {
        char nd_target_s[IPV6_SCAN_LEN + 1];
        uint8_t nd_sll[ETH_ADDR_LEN];
        uint8_t nd_tll[ETH_ADDR_LEN];
        int n = -1;

        if (sscanf(s, "nd(target="IPV6_SCAN_FMT")%n",
                   nd_target_s, &n) > 0 && n > 0) {
            return put_nd_key(n, nd_target_s, NULL, NULL, key);
        }
        if (sscanf(s, "nd(target="IPV6_SCAN_FMT",sll="ETH_ADDR_SCAN_FMT")%n",
                   nd_target_s, ETH_ADDR_SCAN_ARGS(nd_sll), &n) > 0
            && n > 0) {
            return put_nd_key(n, nd_target_s, nd_sll, NULL, key);
        }
        if (sscanf(s, "nd(target="IPV6_SCAN_FMT",tll="ETH_ADDR_SCAN_FMT")%n",
                   nd_target_s, ETH_ADDR_SCAN_ARGS(nd_tll), &n) > 0
            && n > 0) {
            return put_nd_key(n, nd_target_s, NULL, nd_tll, key);
        }
        if (sscanf(s, "nd(target="IPV6_SCAN_FMT",sll="ETH_ADDR_SCAN_FMT","
                   "tll="ETH_ADDR_SCAN_FMT")%n",
                   nd_target_s, ETH_ADDR_SCAN_ARGS(nd_sll),
                   ETH_ADDR_SCAN_ARGS(nd_tll), &n) > 0
            && n > 0) {
            return put_nd_key(n, nd_target_s, nd_sll, nd_tll, key);
        }
    }

    if (!strncmp(s, "encap(", 6)) {
        const char *start = s;
        size_t encap;

        encap = nl_msg_start_nested(key, OVS_KEY_ATTR_ENCAP);

        s += 6;
        for (;;) {
            int retval;

            s += strspn(s, ", \t\r\n");
            if (!*s) {
                return -EINVAL;
            } else if (*s == ')') {
                break;
            }

            retval = parse_odp_key_attr(s, port_names, key);
            if (retval < 0) {
                return retval;
            }
            s += retval;
        }
        s++;

        nl_msg_end_nested(key, encap);

        return s - start;
    }

    return -EINVAL;
}

/* Parses the string representation of a datapath flow key, in the
 * format output by odp_flow_key_format().  Returns 0 if successful,
 * otherwise a positive errno value.  On success, the flow key is
 * appended to 'key' as a series of Netlink attributes.  On failure, no
 * data is appended to 'key'.  Either way, 'key''s data might be
 * reallocated.
 *
 * If 'port_names' is nonnull, it points to an simap that maps from a port name
 * to a port number.  (Port names may be used instead of port numbers in
 * in_port.)
 *
 * On success, the attributes appended to 'key' are individually syntactically
 * valid, but they may not be valid as a sequence.  'key' might, for example,
 * have duplicated keys.  odp_flow_key_to_flow() will detect those errors. */
int
odp_flow_key_from_string(const char *s, const struct simap *port_names,
                         struct ofpbuf *key)
{
    const size_t old_size = key->size;
    for (;;) {
        int retval;

        s += strspn(s, delimiters);
        if (!*s) {
            return 0;
        }

        retval = parse_odp_key_attr(s, port_names, key);
        if (retval < 0) {
            key->size = old_size;
            return -retval;
        }
        s += retval;
    }

    return 0;
}

static uint8_t
ovs_to_odp_frag(uint8_t nw_frag)
{
    return (nw_frag == 0 ? OVS_FRAG_TYPE_NONE
          : nw_frag == FLOW_NW_FRAG_ANY ? OVS_FRAG_TYPE_FIRST
          : OVS_FRAG_TYPE_LATER);
}

/* Appends a representation of 'flow' as OVS_KEY_ATTR_* attributes to 'buf'.
 *
 * 'buf' must have at least ODPUTIL_FLOW_KEY_BYTES bytes of space, or be
 * capable of being expanded to allow for that much space. */
void
odp_flow_key_from_flow(struct ofpbuf *buf, const struct flow *flow)
{
    struct ovs_key_ethernet *eth_key;
    size_t encap;

    if (flow->skb_priority) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_PRIORITY, flow->skb_priority);
    }

    if (flow->tunnel.tun_id != htonll(0)) {
        nl_msg_put_be64(buf, OVS_KEY_ATTR_TUN_ID, flow->tunnel.tun_id);
    }

    if (flow->skb_mark) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_SKB_MARK, flow->skb_mark);
    }

    if (flow->in_port != OFPP_NONE && flow->in_port != OFPP_CONTROLLER) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_IN_PORT,
                       ofp_port_to_odp_port(flow->in_port));
    }

    eth_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ETHERNET,
                                       sizeof *eth_key);
    memcpy(eth_key->eth_src, flow->dl_src, ETH_ADDR_LEN);
    memcpy(eth_key->eth_dst, flow->dl_dst, ETH_ADDR_LEN);

    if (flow->vlan_tci != htons(0) || flow->dl_type == htons(ETH_TYPE_VLAN)) {
        nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, htons(ETH_TYPE_VLAN));
        nl_msg_put_be16(buf, OVS_KEY_ATTR_VLAN, flow->vlan_tci);
        encap = nl_msg_start_nested(buf, OVS_KEY_ATTR_ENCAP);
        if (flow->vlan_tci == htons(0)) {
            goto unencap;
        }
    } else {
        encap = 0;
    }

    if (ntohs(flow->dl_type) < ETH_TYPE_MIN) {
        goto unencap;
    }

    nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, flow->dl_type);

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        struct ovs_key_ipv4 *ipv4_key;

        ipv4_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_IPV4,
                                            sizeof *ipv4_key);
        ipv4_key->ipv4_src = flow->nw_src;
        ipv4_key->ipv4_dst = flow->nw_dst;
        ipv4_key->ipv4_proto = flow->nw_proto;
        ipv4_key->ipv4_tos = flow->nw_tos;
        ipv4_key->ipv4_ttl = flow->nw_ttl;
        ipv4_key->ipv4_frag = ovs_to_odp_frag(flow->nw_frag);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        struct ovs_key_ipv6 *ipv6_key;

        ipv6_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_IPV6,
                                            sizeof *ipv6_key);
        memcpy(ipv6_key->ipv6_src, &flow->ipv6_src, sizeof ipv6_key->ipv6_src);
        memcpy(ipv6_key->ipv6_dst, &flow->ipv6_dst, sizeof ipv6_key->ipv6_dst);
        ipv6_key->ipv6_label = flow->ipv6_label;
        ipv6_key->ipv6_proto = flow->nw_proto;
        ipv6_key->ipv6_tclass = flow->nw_tos;
        ipv6_key->ipv6_hlimit = flow->nw_ttl;
        ipv6_key->ipv6_frag = ovs_to_odp_frag(flow->nw_frag);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        struct ovs_key_arp *arp_key;

        arp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ARP,
                                           sizeof *arp_key);
        memset(arp_key, 0, sizeof *arp_key);
        arp_key->arp_sip = flow->nw_src;
        arp_key->arp_tip = flow->nw_dst;
        arp_key->arp_op = htons(flow->nw_proto);
        memcpy(arp_key->arp_sha, flow->arp_sha, ETH_ADDR_LEN);
        memcpy(arp_key->arp_tha, flow->arp_tha, ETH_ADDR_LEN);
    }

    if ((flow->dl_type == htons(ETH_TYPE_IP)
         || flow->dl_type == htons(ETH_TYPE_IPV6))
        && !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {

        if (flow->nw_proto == IPPROTO_TCP) {
            struct ovs_key_tcp *tcp_key;

            tcp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_TCP,
                                               sizeof *tcp_key);
            tcp_key->tcp_src = flow->tp_src;
            tcp_key->tcp_dst = flow->tp_dst;
        } else if (flow->nw_proto == IPPROTO_UDP) {
            struct ovs_key_udp *udp_key;

            udp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_UDP,
                                               sizeof *udp_key);
            udp_key->udp_src = flow->tp_src;
            udp_key->udp_dst = flow->tp_dst;
        } else if (flow->dl_type == htons(ETH_TYPE_IP)
                && flow->nw_proto == IPPROTO_ICMP) {
            struct ovs_key_icmp *icmp_key;

            icmp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ICMP,
                                                sizeof *icmp_key);
            icmp_key->icmp_type = ntohs(flow->tp_src);
            icmp_key->icmp_code = ntohs(flow->tp_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)
                && flow->nw_proto == IPPROTO_ICMPV6) {
            struct ovs_key_icmpv6 *icmpv6_key;

            icmpv6_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ICMPV6,
                                                  sizeof *icmpv6_key);
            icmpv6_key->icmpv6_type = ntohs(flow->tp_src);
            icmpv6_key->icmpv6_code = ntohs(flow->tp_dst);

            if (icmpv6_key->icmpv6_type == ND_NEIGHBOR_SOLICIT
                    || icmpv6_key->icmpv6_type == ND_NEIGHBOR_ADVERT) {
                struct ovs_key_nd *nd_key;

                nd_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ND,
                                                    sizeof *nd_key);
                memcpy(nd_key->nd_target, &flow->nd_target,
                        sizeof nd_key->nd_target);
                memcpy(nd_key->nd_sll, flow->arp_sha, ETH_ADDR_LEN);
                memcpy(nd_key->nd_tll, flow->arp_tha, ETH_ADDR_LEN);
            }
        }
    }

unencap:
    if (encap) {
        nl_msg_end_nested(buf, encap);
    }
}

uint32_t
odp_flow_key_hash(const struct nlattr *key, size_t key_len)
{
    BUILD_ASSERT_DECL(!(NLA_ALIGNTO % sizeof(uint32_t)));
    return hash_words((const uint32_t *) key, key_len / sizeof(uint32_t), 0);
}

static void
log_odp_key_attributes(struct vlog_rate_limit *rl, const char *title,
                       uint64_t attrs, int out_of_range_attr,
                       const struct nlattr *key, size_t key_len)
{
    struct ds s;
    int i;

    if (VLOG_DROP_DBG(rl)) {
        return;
    }

    ds_init(&s);
    for (i = 0; i < 64; i++) {
        if (attrs & (UINT64_C(1) << i)) {
            ds_put_format(&s, " %s", ovs_key_attr_to_string(i));
        }
    }
    if (out_of_range_attr) {
        ds_put_format(&s, " %d (and possibly others)", out_of_range_attr);
    }

    ds_put_cstr(&s, ": ");
    odp_flow_key_format(key, key_len, &s);

    VLOG_DBG("%s:%s", title, ds_cstr(&s));
    ds_destroy(&s);
}

static bool
odp_to_ovs_frag(uint8_t odp_frag, struct flow *flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (odp_frag > OVS_FRAG_TYPE_LATER) {
        VLOG_ERR_RL(&rl, "invalid frag %"PRIu8" in flow key", odp_frag);
        return false;
    }

    if (odp_frag != OVS_FRAG_TYPE_NONE) {
        flow->nw_frag |= FLOW_NW_FRAG_ANY;
        if (odp_frag == OVS_FRAG_TYPE_LATER) {
            flow->nw_frag |= FLOW_NW_FRAG_LATER;
        }
    }
    return true;
}

static bool
parse_flow_nlattrs(const struct nlattr *key, size_t key_len,
                   const struct nlattr *attrs[], uint64_t *present_attrsp,
                   int *out_of_range_attrp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    const struct nlattr *nla;
    uint64_t present_attrs;
    size_t left;

    present_attrs = 0;
    *out_of_range_attrp = 0;
    NL_ATTR_FOR_EACH (nla, left, key, key_len) {
        uint16_t type = nl_attr_type(nla);
        size_t len = nl_attr_get_size(nla);
        int expected_len = odp_flow_key_attr_len(type);

        if (len != expected_len && expected_len >= 0) {
            VLOG_ERR_RL(&rl, "attribute %s has length %zu but should have "
                        "length %d", ovs_key_attr_to_string(type),
                        len, expected_len);
            return false;
        }

        if (type >= CHAR_BIT * sizeof present_attrs) {
            *out_of_range_attrp = type;
        } else {
            if (present_attrs & (UINT64_C(1) << type)) {
                VLOG_ERR_RL(&rl, "duplicate %s attribute in flow key",
                            ovs_key_attr_to_string(type));
                return false;
            }

            present_attrs |= UINT64_C(1) << type;
            attrs[type] = nla;
        }
    }
    if (left) {
        VLOG_ERR_RL(&rl, "trailing garbage in flow key");
        return false;
    }

    *present_attrsp = present_attrs;
    return true;
}

static enum odp_key_fitness
check_expectations(uint64_t present_attrs, int out_of_range_attr,
                   uint64_t expected_attrs,
                   const struct nlattr *key, size_t key_len)
{
    uint64_t missing_attrs;
    uint64_t extra_attrs;

    missing_attrs = expected_attrs & ~present_attrs;
    if (missing_attrs) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
        log_odp_key_attributes(&rl, "expected but not present",
                               missing_attrs, 0, key, key_len);
        return ODP_FIT_TOO_LITTLE;
    }

    extra_attrs = present_attrs & ~expected_attrs;
    if (extra_attrs || out_of_range_attr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
        log_odp_key_attributes(&rl, "present but not expected",
                               extra_attrs, out_of_range_attr, key, key_len);
        return ODP_FIT_TOO_MUCH;
    }

    return ODP_FIT_PERFECT;
}

static bool
parse_ethertype(const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1],
                uint64_t present_attrs, uint64_t *expected_attrs,
                struct flow *flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE)) {
        flow->dl_type = nl_attr_get_be16(attrs[OVS_KEY_ATTR_ETHERTYPE]);
        if (ntohs(flow->dl_type) < 1536) {
            VLOG_ERR_RL(&rl, "invalid Ethertype %"PRIu16" in flow key",
                        ntohs(flow->dl_type));
            return false;
        }
        *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE;
    } else {
        flow->dl_type = htons(FLOW_DL_TYPE_NONE);
    }
    return true;
}

static enum odp_key_fitness
parse_l3_onward(const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1],
                uint64_t present_attrs, int out_of_range_attr,
                uint64_t expected_attrs, struct flow *flow,
                const struct nlattr *key, size_t key_len)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IPV4;
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IPV4)) {
            const struct ovs_key_ipv4 *ipv4_key;

            ipv4_key = nl_attr_get(attrs[OVS_KEY_ATTR_IPV4]);
            flow->nw_src = ipv4_key->ipv4_src;
            flow->nw_dst = ipv4_key->ipv4_dst;
            flow->nw_proto = ipv4_key->ipv4_proto;
            flow->nw_tos = ipv4_key->ipv4_tos;
            flow->nw_ttl = ipv4_key->ipv4_ttl;
            if (!odp_to_ovs_frag(ipv4_key->ipv4_frag, flow)) {
                return ODP_FIT_ERROR;
            }
        }
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IPV6;
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IPV6)) {
            const struct ovs_key_ipv6 *ipv6_key;

            ipv6_key = nl_attr_get(attrs[OVS_KEY_ATTR_IPV6]);
            memcpy(&flow->ipv6_src, ipv6_key->ipv6_src, sizeof flow->ipv6_src);
            memcpy(&flow->ipv6_dst, ipv6_key->ipv6_dst, sizeof flow->ipv6_dst);
            flow->ipv6_label = ipv6_key->ipv6_label;
            flow->nw_proto = ipv6_key->ipv6_proto;
            flow->nw_tos = ipv6_key->ipv6_tclass;
            flow->nw_ttl = ipv6_key->ipv6_hlimit;
            if (!odp_to_ovs_frag(ipv6_key->ipv6_frag, flow)) {
                return ODP_FIT_ERROR;
            }
        }
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ARP;
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ARP)) {
            const struct ovs_key_arp *arp_key;

            arp_key = nl_attr_get(attrs[OVS_KEY_ATTR_ARP]);
            flow->nw_src = arp_key->arp_sip;
            flow->nw_dst = arp_key->arp_tip;
            if (arp_key->arp_op & htons(0xff00)) {
                VLOG_ERR_RL(&rl, "unsupported ARP opcode %"PRIu16" in flow "
                            "key", ntohs(arp_key->arp_op));
                return ODP_FIT_ERROR;
            }
            flow->nw_proto = ntohs(arp_key->arp_op);
            memcpy(flow->arp_sha, arp_key->arp_sha, ETH_ADDR_LEN);
            memcpy(flow->arp_tha, arp_key->arp_tha, ETH_ADDR_LEN);
        }
    }

    if (flow->nw_proto == IPPROTO_TCP
        && (flow->dl_type == htons(ETH_TYPE_IP) ||
            flow->dl_type == htons(ETH_TYPE_IPV6))
        && !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_TCP;
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_TCP)) {
            const struct ovs_key_tcp *tcp_key;

            tcp_key = nl_attr_get(attrs[OVS_KEY_ATTR_TCP]);
            flow->tp_src = tcp_key->tcp_src;
            flow->tp_dst = tcp_key->tcp_dst;
        }
    } else if (flow->nw_proto == IPPROTO_UDP
               && (flow->dl_type == htons(ETH_TYPE_IP) ||
                   flow->dl_type == htons(ETH_TYPE_IPV6))
               && !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_UDP;
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_UDP)) {
            const struct ovs_key_udp *udp_key;

            udp_key = nl_attr_get(attrs[OVS_KEY_ATTR_UDP]);
            flow->tp_src = udp_key->udp_src;
            flow->tp_dst = udp_key->udp_dst;
        }
    } else if (flow->nw_proto == IPPROTO_ICMP
               && flow->dl_type == htons(ETH_TYPE_IP)
               && !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ICMP;
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ICMP)) {
            const struct ovs_key_icmp *icmp_key;

            icmp_key = nl_attr_get(attrs[OVS_KEY_ATTR_ICMP]);
            flow->tp_src = htons(icmp_key->icmp_type);
            flow->tp_dst = htons(icmp_key->icmp_code);
        }
    } else if (flow->nw_proto == IPPROTO_ICMPV6
               && flow->dl_type == htons(ETH_TYPE_IPV6)
               && !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ICMPV6;
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ICMPV6)) {
            const struct ovs_key_icmpv6 *icmpv6_key;

            icmpv6_key = nl_attr_get(attrs[OVS_KEY_ATTR_ICMPV6]);
            flow->tp_src = htons(icmpv6_key->icmpv6_type);
            flow->tp_dst = htons(icmpv6_key->icmpv6_code);

            if (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT) ||
                flow->tp_src == htons(ND_NEIGHBOR_ADVERT)) {
                expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ND;
                if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ND)) {
                    const struct ovs_key_nd *nd_key;

                    nd_key = nl_attr_get(attrs[OVS_KEY_ATTR_ND]);
                    memcpy(&flow->nd_target, nd_key->nd_target,
                           sizeof flow->nd_target);
                    memcpy(flow->arp_sha, nd_key->nd_sll, ETH_ADDR_LEN);
                    memcpy(flow->arp_tha, nd_key->nd_tll, ETH_ADDR_LEN);
                }
            }
        }
    }

    return check_expectations(present_attrs, out_of_range_attr, expected_attrs,
                              key, key_len);
}

/* Parse 802.1Q header then encapsulated L3 attributes. */
static enum odp_key_fitness
parse_8021q_onward(const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1],
                   uint64_t present_attrs, int out_of_range_attr,
                   uint64_t expected_attrs, struct flow *flow,
                   const struct nlattr *key, size_t key_len)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    const struct nlattr *encap
        = (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ENCAP)
           ? attrs[OVS_KEY_ATTR_ENCAP] : NULL);
    enum odp_key_fitness encap_fitness;
    enum odp_key_fitness fitness;
    ovs_be16 tci;

    /* Calulate fitness of outer attributes. */
    expected_attrs |= ((UINT64_C(1) << OVS_KEY_ATTR_VLAN) |
                       (UINT64_C(1) << OVS_KEY_ATTR_ENCAP));
    fitness = check_expectations(present_attrs, out_of_range_attr,
                                 expected_attrs, key, key_len);

    /* Get the VLAN TCI value. */
    if (!(present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VLAN))) {
        return ODP_FIT_TOO_LITTLE;
    }
    tci = nl_attr_get_be16(attrs[OVS_KEY_ATTR_VLAN]);
    if (tci == htons(0)) {
        /* Corner case for a truncated 802.1Q header. */
        if (fitness == ODP_FIT_PERFECT && nl_attr_get_size(encap)) {
            return ODP_FIT_TOO_MUCH;
        }
        return fitness;
    } else if (!(tci & htons(VLAN_CFI))) {
        VLOG_ERR_RL(&rl, "OVS_KEY_ATTR_VLAN 0x%04"PRIx16" is nonzero "
                    "but CFI bit is not set", ntohs(tci));
        return ODP_FIT_ERROR;
    }

    /* Set vlan_tci.
     * Remove the TPID from dl_type since it's not the real Ethertype.  */
    flow->vlan_tci = tci;
    flow->dl_type = htons(0);

    /* Now parse the encapsulated attributes. */
    if (!parse_flow_nlattrs(nl_attr_get(encap), nl_attr_get_size(encap),
                            attrs, &present_attrs, &out_of_range_attr)) {
        return ODP_FIT_ERROR;
    }
    expected_attrs = 0;

    if (!parse_ethertype(attrs, present_attrs, &expected_attrs, flow)) {
        return ODP_FIT_ERROR;
    }
    encap_fitness = parse_l3_onward(attrs, present_attrs, out_of_range_attr,
                                    expected_attrs, flow, key, key_len);

    /* The overall fitness is the worse of the outer and inner attributes. */
    return MAX(fitness, encap_fitness);
}

/* Converts the 'key_len' bytes of OVS_KEY_ATTR_* attributes in 'key' to a flow
 * structure in 'flow'.  Returns an ODP_FIT_* value that indicates how well
 * 'key' fits our expectations for what a flow key should contain.
 *
 * This function doesn't take the packet itself as an argument because none of
 * the currently understood OVS_KEY_ATTR_* attributes require it.  Currently,
 * it is always possible to infer which additional attribute(s) should appear
 * by looking at the attributes for lower-level protocols, e.g. if the network
 * protocol in OVS_KEY_ATTR_IPV4 or OVS_KEY_ATTR_IPV6 is IPPROTO_TCP then we
 * know that a OVS_KEY_ATTR_TCP attribute must appear and that otherwise it
 * must be absent. */
enum odp_key_fitness
odp_flow_key_to_flow(const struct nlattr *key, size_t key_len,
                     struct flow *flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1];
    uint64_t expected_attrs;
    uint64_t present_attrs;
    int out_of_range_attr;

    memset(flow, 0, sizeof *flow);

    /* Parse attributes. */
    if (!parse_flow_nlattrs(key, key_len, attrs, &present_attrs,
                            &out_of_range_attr)) {
        return ODP_FIT_ERROR;
    }
    expected_attrs = 0;

    /* Metadata. */
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_PRIORITY)) {
        flow->skb_priority = nl_attr_get_u32(attrs[OVS_KEY_ATTR_PRIORITY]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_PRIORITY;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_SKB_MARK)) {
        flow->skb_mark = nl_attr_get_u32(attrs[OVS_KEY_ATTR_SKB_MARK]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_SKB_MARK;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_TUN_ID)) {
        flow->tunnel.tun_id = nl_attr_get_be64(attrs[OVS_KEY_ATTR_TUN_ID]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_TUN_ID;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IN_PORT)) {
        uint32_t in_port = nl_attr_get_u32(attrs[OVS_KEY_ATTR_IN_PORT]);
        if (in_port >= UINT16_MAX || in_port >= OFPP_MAX) {
            VLOG_ERR_RL(&rl, "in_port %"PRIu32" out of supported range",
                        in_port);
            return ODP_FIT_ERROR;
        }
        flow->in_port = odp_port_to_ofp_port(in_port);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IN_PORT;
    } else {
        flow->in_port = OFPP_NONE;
    }

    /* Ethernet header. */
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERNET)) {
        const struct ovs_key_ethernet *eth_key;

        eth_key = nl_attr_get(attrs[OVS_KEY_ATTR_ETHERNET]);
        memcpy(flow->dl_src, eth_key->eth_src, ETH_ADDR_LEN);
        memcpy(flow->dl_dst, eth_key->eth_dst, ETH_ADDR_LEN);
    }
    expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERNET;

    /* Get Ethertype or 802.1Q TPID or FLOW_DL_TYPE_NONE. */
    if (!parse_ethertype(attrs, present_attrs, &expected_attrs, flow)) {
        return ODP_FIT_ERROR;
    }

    if (flow->dl_type == htons(ETH_TYPE_VLAN)) {
        return parse_8021q_onward(attrs, present_attrs, out_of_range_attr,
                                  expected_attrs, flow, key, key_len);
    }
    return parse_l3_onward(attrs, present_attrs, out_of_range_attr,
                           expected_attrs, flow, key, key_len);
}

/* Returns 'fitness' as a string, for use in debug messages. */
const char *
odp_key_fitness_to_string(enum odp_key_fitness fitness)
{
    switch (fitness) {
    case ODP_FIT_PERFECT:
        return "OK";
    case ODP_FIT_TOO_MUCH:
        return "too_much";
    case ODP_FIT_TOO_LITTLE:
        return "too_little";
    case ODP_FIT_ERROR:
        return "error";
    default:
        return "<unknown>";
    }
}

/* Appends an OVS_ACTION_ATTR_USERSPACE action to 'odp_actions' that specifies
 * Netlink PID 'pid'.  If 'cookie' is nonnull, adds a userdata attribute whose
 * contents contains 'cookie' and returns the offset within 'odp_actions' of
 * the start of the cookie.  (If 'cookie' is null, then the return value is not
 * meaningful.) */
size_t
odp_put_userspace_action(uint32_t pid, const union user_action_cookie *cookie,
                         struct ofpbuf *odp_actions)
{
    size_t offset;

    offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_USERSPACE);
    nl_msg_put_u32(odp_actions, OVS_USERSPACE_ATTR_PID, pid);
    if (cookie) {
        nl_msg_put_unspec(odp_actions, OVS_USERSPACE_ATTR_USERDATA,
                          cookie, sizeof *cookie);
    }
    nl_msg_end_nested(odp_actions, offset);

    return cookie ? odp_actions->size - NLA_ALIGN(sizeof *cookie) : 0;
}

/* The commit_odp_actions() function and its helpers. */

static void
commit_set_action(struct ofpbuf *odp_actions, enum ovs_key_attr key_type,
                  const void *key, size_t key_size)
{
    size_t offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_SET);
    nl_msg_put_unspec(odp_actions, key_type, key, key_size);
    nl_msg_end_nested(odp_actions, offset);
}

static void
commit_set_tun_id_action(const struct flow *flow, struct flow *base,
                         struct ofpbuf *odp_actions)
{
    if (base->tunnel.tun_id == flow->tunnel.tun_id) {
        return;
    }
    base->tunnel.tun_id = flow->tunnel.tun_id;

    commit_set_action(odp_actions, OVS_KEY_ATTR_TUN_ID,
                      &base->tunnel.tun_id, sizeof(base->tunnel.tun_id));
}

static void
commit_set_ether_addr_action(const struct flow *flow, struct flow *base,
                             struct ofpbuf *odp_actions)
{
    struct ovs_key_ethernet eth_key;

    if (eth_addr_equals(base->dl_src, flow->dl_src) &&
        eth_addr_equals(base->dl_dst, flow->dl_dst)) {
        return;
    }

    memcpy(base->dl_src, flow->dl_src, ETH_ADDR_LEN);
    memcpy(base->dl_dst, flow->dl_dst, ETH_ADDR_LEN);

    memcpy(eth_key.eth_src, base->dl_src, ETH_ADDR_LEN);
    memcpy(eth_key.eth_dst, base->dl_dst, ETH_ADDR_LEN);

    commit_set_action(odp_actions, OVS_KEY_ATTR_ETHERNET,
                      &eth_key, sizeof(eth_key));
}

static void
commit_vlan_action(const struct flow *flow, struct flow *base,
                   struct ofpbuf *odp_actions)
{
    if (base->vlan_tci == flow->vlan_tci) {
        return;
    }

    if (base->vlan_tci & htons(VLAN_CFI)) {
        nl_msg_put_flag(odp_actions, OVS_ACTION_ATTR_POP_VLAN);
    }

    if (flow->vlan_tci & htons(VLAN_CFI)) {
        struct ovs_action_push_vlan vlan;

        vlan.vlan_tpid = htons(ETH_TYPE_VLAN);
        vlan.vlan_tci = flow->vlan_tci;
        nl_msg_put_unspec(odp_actions, OVS_ACTION_ATTR_PUSH_VLAN,
                          &vlan, sizeof vlan);
    }
    base->vlan_tci = flow->vlan_tci;
}

static void
commit_set_ipv4_action(const struct flow *flow, struct flow *base,
                     struct ofpbuf *odp_actions)
{
    struct ovs_key_ipv4 ipv4_key;

    if (base->nw_src == flow->nw_src &&
        base->nw_dst == flow->nw_dst &&
        base->nw_tos == flow->nw_tos &&
        base->nw_ttl == flow->nw_ttl &&
        base->nw_frag == flow->nw_frag) {
        return;
    }

    ipv4_key.ipv4_src = base->nw_src = flow->nw_src;
    ipv4_key.ipv4_dst = base->nw_dst = flow->nw_dst;
    ipv4_key.ipv4_tos = base->nw_tos = flow->nw_tos;
    ipv4_key.ipv4_ttl = base->nw_ttl = flow->nw_ttl;
    ipv4_key.ipv4_proto = base->nw_proto;
    ipv4_key.ipv4_frag = ovs_to_odp_frag(base->nw_frag);

    commit_set_action(odp_actions, OVS_KEY_ATTR_IPV4,
                      &ipv4_key, sizeof(ipv4_key));
}

static void
commit_set_ipv6_action(const struct flow *flow, struct flow *base,
                       struct ofpbuf *odp_actions)
{
    struct ovs_key_ipv6 ipv6_key;

    if (ipv6_addr_equals(&base->ipv6_src, &flow->ipv6_src) &&
        ipv6_addr_equals(&base->ipv6_dst, &flow->ipv6_dst) &&
        base->ipv6_label == flow->ipv6_label &&
        base->nw_tos == flow->nw_tos &&
        base->nw_ttl == flow->nw_ttl &&
        base->nw_frag == flow->nw_frag) {
        return;
    }

    base->ipv6_src = flow->ipv6_src;
    memcpy(&ipv6_key.ipv6_src, &base->ipv6_src, sizeof(ipv6_key.ipv6_src));
    base->ipv6_dst = flow->ipv6_dst;
    memcpy(&ipv6_key.ipv6_dst, &base->ipv6_dst, sizeof(ipv6_key.ipv6_dst));

    ipv6_key.ipv6_label = base->ipv6_label = flow->ipv6_label;
    ipv6_key.ipv6_tclass = base->nw_tos = flow->nw_tos;
    ipv6_key.ipv6_hlimit = base->nw_ttl = flow->nw_ttl;
    ipv6_key.ipv6_proto = base->nw_proto;
    ipv6_key.ipv6_frag = ovs_to_odp_frag(base->nw_frag);

    commit_set_action(odp_actions, OVS_KEY_ATTR_IPV6,
                      &ipv6_key, sizeof(ipv6_key));
}

static void
commit_set_nw_action(const struct flow *flow, struct flow *base,
                     struct ofpbuf *odp_actions)
{
    /* Check if flow really have an IP header. */
    if (!flow->nw_proto) {
        return;
    }

    if (base->dl_type == htons(ETH_TYPE_IP)) {
        commit_set_ipv4_action(flow, base, odp_actions);
    } else if (base->dl_type == htons(ETH_TYPE_IPV6)) {
        commit_set_ipv6_action(flow, base, odp_actions);
    }
}

static void
commit_set_port_action(const struct flow *flow, struct flow *base,
                       struct ofpbuf *odp_actions)
{
    if (!base->tp_src && !base->tp_dst) {
        return;
    }

    if (base->tp_src == flow->tp_src &&
        base->tp_dst == flow->tp_dst) {
        return;
    }

    if (flow->nw_proto == IPPROTO_TCP) {
        struct ovs_key_tcp port_key;

        port_key.tcp_src = base->tp_src = flow->tp_src;
        port_key.tcp_dst = base->tp_dst = flow->tp_dst;

        commit_set_action(odp_actions, OVS_KEY_ATTR_TCP,
                          &port_key, sizeof(port_key));

    } else if (flow->nw_proto == IPPROTO_UDP) {
        struct ovs_key_udp port_key;

        port_key.udp_src = base->tp_src = flow->tp_src;
        port_key.udp_dst = base->tp_dst = flow->tp_dst;

        commit_set_action(odp_actions, OVS_KEY_ATTR_UDP,
                          &port_key, sizeof(port_key));
    }
}

static void
commit_set_priority_action(const struct flow *flow, struct flow *base,
                           struct ofpbuf *odp_actions)
{
    if (base->skb_priority == flow->skb_priority) {
        return;
    }
    base->skb_priority = flow->skb_priority;

    commit_set_action(odp_actions, OVS_KEY_ATTR_PRIORITY,
                      &base->skb_priority, sizeof(base->skb_priority));
}

static void
commit_set_skb_mark_action(const struct flow *flow, struct flow *base,
                           struct ofpbuf *odp_actions)
{
    if (base->skb_mark == flow->skb_mark) {
        return;
    }
    base->skb_mark = flow->skb_mark;

    commit_set_action(odp_actions, OVS_KEY_ATTR_SKB_MARK,
                      &base->skb_mark, sizeof(base->skb_mark));
}
/* If any of the flow key data that ODP actions can modify are different in
 * 'base' and 'flow', appends ODP actions to 'odp_actions' that change the flow
 * key from 'base' into 'flow', and then changes 'base' the same way. */
void
commit_odp_actions(const struct flow *flow, struct flow *base,
                   struct ofpbuf *odp_actions)
{
    commit_set_tun_id_action(flow, base, odp_actions);
    commit_set_ether_addr_action(flow, base, odp_actions);
    commit_vlan_action(flow, base, odp_actions);
    commit_set_nw_action(flow, base, odp_actions);
    commit_set_port_action(flow, base, odp_actions);
    commit_set_priority_action(flow, base, odp_actions);
    commit_set_skb_mark_action(flow, base, odp_actions);
}
