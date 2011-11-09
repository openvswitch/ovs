/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

#include <arpa/inet.h>
#include <config.h>
#include "odp-util.h"
#include <errno.h>
#include <inttypes.h>
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
#include "openvswitch/tunnel.h"
#include "packets.h"
#include "timeval.h"
#include "util.h"

static void
format_odp_key_attr(const struct nlattr *a, struct ds *ds);

/* The interface between userspace and kernel uses an "OVS_*" prefix.
 * Since this is fairly non-specific for the OVS userspace components,
 * "ODP_*" (Open vSwitch Datapath) is used as the prefix for
 * interactions with the datapath.
 */

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
    case OVS_ACTION_ATTR_OUTPUT: return 4;
    case OVS_ACTION_ATTR_USERSPACE: return -2;
    case OVS_ACTION_ATTR_PUSH: return -2;
    case OVS_ACTION_ATTR_POP: return 2;
    case OVS_ACTION_ATTR_SET: return -2;
    case OVS_ACTION_ATTR_SAMPLE: return -2;

    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        return -1;
    }

    return -1;
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
        struct user_action_cookie cookie;

        memcpy(&cookie, &userdata, sizeof cookie);

        if (cookie.type == USER_ACTION_COOKIE_CONTROLLER) {
            ds_put_format(ds, ",controller,length=%"PRIu32,
                          cookie.data);
        } else if (cookie.type == USER_ACTION_COOKIE_SFLOW) {
            ds_put_format(ds, ",sFlow,n_output=%"PRIu8","
                          "vid=%"PRIu16",pcp=%"PRIu8",ifindex=%"PRIu32,
                          cookie.n_output, vlan_tci_to_vid(cookie.vlan_tci),
                          vlan_tci_to_pcp(cookie.vlan_tci), cookie.data);
        } else {
            ds_put_format(ds, ",userdata=0x%"PRIx64, userdata);
        }
    }

    ds_put_char(ds, ')');
}


static void
format_odp_action(struct ds *ds, const struct nlattr *a)
{
    int expected_len;
    enum ovs_action_attr type = nl_attr_type(a);

    expected_len = odp_action_len(nl_attr_type(a));
    if (expected_len != -2 && nl_attr_get_size(a) != expected_len) {
        ds_put_format(ds, "bad length %zu, expected %d for: ",
                      nl_attr_get_size(a), expected_len);
        format_generic_odp_action(ds, a);
        return;
    }

    switch (type) {

    case OVS_ACTION_ATTR_OUTPUT:
        ds_put_format(ds, "%"PRIu16, nl_attr_get_u32(a));
        break;
    case OVS_ACTION_ATTR_USERSPACE:
        format_odp_userspace_action(ds, a);
        break;
    case OVS_ACTION_ATTR_SET:
        ds_put_cstr(ds, "set(");
        format_odp_key_attr(nl_attr_get(a), ds);
        ds_put_cstr(ds, ")");
        break;
    case OVS_ACTION_ATTR_PUSH:
        ds_put_cstr(ds, "push(");
        format_odp_key_attr(nl_attr_get(a), ds);
        ds_put_cstr(ds, ")");
        break;
    case OVS_ACTION_ATTR_POP:
        if (nl_attr_get_u16(a) == OVS_KEY_ATTR_8021Q) {
            ds_put_cstr(ds, "pop(vlan)");
        } else {
            ds_put_format(ds, "pop(key%"PRIu16")", nl_attr_get_u16(a));
        }
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
            if (left == actions_len) {
                ds_put_cstr(ds, "<empty>");
            }
            ds_put_format(ds, ",***%u leftover bytes***", left);
        }
    } else {
        ds_put_cstr(ds, "drop");
    }
}

/* Returns the correct length of the payload for a flow key attribute of the
 * specified 'type', or -1 if 'type' is unknown. */
static int
odp_flow_key_attr_len(uint16_t type)
{
    if (type > OVS_KEY_ATTR_MAX) {
        return -1;
    }

    switch ((enum ovs_key_attr) type) {
    case OVS_KEY_ATTR_PRIORITY: return 4;
    case OVS_KEY_ATTR_TUN_ID: return 8;
    case OVS_KEY_ATTR_IN_PORT: return 4;
    case OVS_KEY_ATTR_ETHERNET: return sizeof(struct ovs_key_ethernet);
    case OVS_KEY_ATTR_8021Q: return sizeof(struct ovs_key_8021q);
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

    ds_put_format(ds, "key%"PRId16, nl_attr_type(a));
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

static void
format_odp_key_attr(const struct nlattr *a, struct ds *ds)
{
    const struct ovs_key_ethernet *eth_key;
    const struct ovs_key_8021q *q_key;
    const struct ovs_key_ipv4 *ipv4_key;
    const struct ovs_key_ipv6 *ipv6_key;
    const struct ovs_key_tcp *tcp_key;
    const struct ovs_key_udp *udp_key;
    const struct ovs_key_icmp *icmp_key;
    const struct ovs_key_icmpv6 *icmpv6_key;
    const struct ovs_key_arp *arp_key;
    const struct ovs_key_nd *nd_key;

    if (nl_attr_get_size(a) != odp_flow_key_attr_len(nl_attr_type(a))) {
        ds_put_format(ds, "bad length %zu, expected %d for: ",
                      nl_attr_get_size(a),
                      odp_flow_key_attr_len(nl_attr_type(a)));
        format_generic_odp_key(a, ds);
        return;
    }

    switch (nl_attr_type(a)) {
    case OVS_KEY_ATTR_PRIORITY:
        ds_put_format(ds, "priority(%"PRIu32")", nl_attr_get_u32(a));
        break;

    case OVS_KEY_ATTR_TUN_ID:
        ds_put_format(ds, "tun_id(%#"PRIx64")", ntohll(nl_attr_get_be64(a)));
        break;

    case OVS_KEY_ATTR_IN_PORT:
        ds_put_format(ds, "in_port(%"PRIu32")", nl_attr_get_u32(a));
        break;

    case OVS_KEY_ATTR_ETHERNET:
        eth_key = nl_attr_get(a);
        ds_put_format(ds, "eth(src="ETH_ADDR_FMT",dst="ETH_ADDR_FMT")",
                      ETH_ADDR_ARGS(eth_key->eth_src),
                      ETH_ADDR_ARGS(eth_key->eth_dst));
        break;

    case OVS_KEY_ATTR_8021Q:
        q_key = nl_attr_get(a);
        ds_put_cstr(ds, "vlan(");
        if (q_key->q_tpid != htons(ETH_TYPE_VLAN)) {
            ds_put_format(ds, "tpid=0x%04"PRIx16",", ntohs(q_key->q_tpid));
        }
        ds_put_format(ds, "vid=%"PRIu16",pcp=%d)",
                      vlan_tci_to_vid(q_key->q_tci),
                      vlan_tci_to_pcp(q_key->q_tci));
        break;

    case OVS_KEY_ATTR_ETHERTYPE:
        ds_put_format(ds, "eth_type(0x%04"PRIx16")",
                      ntohs(nl_attr_get_be16(a)));
        break;

    case OVS_KEY_ATTR_IPV4:
        ipv4_key = nl_attr_get(a);
        ds_put_format(ds, "ipv4(src="IP_FMT",dst="IP_FMT",proto=%"PRIu8
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

        ds_put_format(ds, "ipv6(src=%s,dst=%s,label=%#"PRIx32",proto=%"PRIu8
                      ",tclass=%#"PRIx8",hlimit=%"PRIu8",frag=%s)",
                      src_str, dst_str, ntohl(ipv6_key->ipv6_label),
                      ipv6_key->ipv6_proto, ipv6_key->ipv6_tclass,
                      ipv6_key->ipv6_hlimit,
                      ovs_frag_type_to_string(ipv6_key->ipv6_frag));
        break;
    }

    case OVS_KEY_ATTR_TCP:
        tcp_key = nl_attr_get(a);
        ds_put_format(ds, "tcp(src=%"PRIu16",dst=%"PRIu16")",
                      ntohs(tcp_key->tcp_src), ntohs(tcp_key->tcp_dst));
        break;

    case OVS_KEY_ATTR_UDP:
        udp_key = nl_attr_get(a);
        ds_put_format(ds, "udp(src=%"PRIu16",dst=%"PRIu16")",
                      ntohs(udp_key->udp_src), ntohs(udp_key->udp_dst));
        break;

    case OVS_KEY_ATTR_ICMP:
        icmp_key = nl_attr_get(a);
        ds_put_format(ds, "icmp(type=%"PRIu8",code=%"PRIu8")",
                      icmp_key->icmp_type, icmp_key->icmp_code);
        break;

    case OVS_KEY_ATTR_ICMPV6:
        icmpv6_key = nl_attr_get(a);
        ds_put_format(ds, "icmpv6(type=%"PRIu8",code=%"PRIu8")",
                      icmpv6_key->icmpv6_type, icmpv6_key->icmpv6_code);
        break;

    case OVS_KEY_ATTR_ARP:
        arp_key = nl_attr_get(a);
        ds_put_format(ds, "arp(sip="IP_FMT",tip="IP_FMT",op=%"PRIu16","
                      "sha="ETH_ADDR_FMT",tha="ETH_ADDR_FMT")",
                      IP_ARGS(&arp_key->arp_sip), IP_ARGS(&arp_key->arp_tip),
                      ntohs(arp_key->arp_op), ETH_ADDR_ARGS(arp_key->arp_sha),
                      ETH_ADDR_ARGS(arp_key->arp_tha));
        break;

    case OVS_KEY_ATTR_ND: {
        char target[INET6_ADDRSTRLEN];

        nd_key = nl_attr_get(a);
        inet_ntop(AF_INET6, nd_key->nd_target, target, sizeof target);

        ds_put_format(ds, "nd(target=%s", target);
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
            if (left == key_len) {
                ds_put_cstr(ds, "<empty>");
            }
            ds_put_format(ds, ",***%u leftover bytes***", left);
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
parse_odp_key_attr(const char *s, struct ofpbuf *key)
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

        if (sscanf(s, "priority(%lli)%n", &priority, &n) > 0 && n > 0) {
            nl_msg_put_u32(key, OVS_KEY_ATTR_PRIORITY, priority);
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
        unsigned long long int in_port;
        int n = -1;

        if (sscanf(s, "in_port(%lli)%n", &in_port, &n) > 0 && n > 0) {
            nl_msg_put_u32(key, OVS_KEY_ATTR_IN_PORT, in_port);
            return n;
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
        uint16_t tpid = ETH_TYPE_VLAN;
        uint16_t vid;
        int pcp;
        int n = -1;

        if ((sscanf(s, "vlan(vid=%"SCNi16",pcp=%i)%n",
                    &vid, &pcp, &n) > 0 && n > 0) ||
            (sscanf(s, "vlan(tpid=%"SCNi16",vid=%"SCNi16",pcp=%i)%n",
                    &tpid, &vid, &pcp, &n) > 0 && n > 0)) {
            struct ovs_key_8021q q_key;

            q_key.q_tpid = htons(tpid);
            q_key.q_tci = htons((vid << VLAN_VID_SHIFT) |
                                (pcp << VLAN_PCP_SHIFT));
            nl_msg_put_unspec(key, OVS_KEY_ATTR_8021Q, &q_key, sizeof q_key);
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

    return -EINVAL;
}

/* Parses the string representation of a datapath flow key, in the
 * format output by odp_flow_key_format().  Returns 0 if successful,
 * otherwise a positive errno value.  On success, the flow key is
 * appended to 'key' as a series of Netlink attributes.  On failure, no
 * data is appended to 'key'.  Either way, 'key''s data might be
 * reallocated.
 *
 * On success, the attributes appended to 'key' are individually syntactically
 * valid, but they may not be valid as a sequence.  'key' might, for example,
 * be missing an "in_port" key, have duplicated keys, or have keys in the wrong
 * order.  odp_flow_key_to_flow() will detect those errors. */
int
odp_flow_key_from_string(const char *s, struct ofpbuf *key)
{
    const size_t old_size = key->size;
    for (;;) {
        int retval;

        s += strspn(s, ", \t\r\n");
        if (!*s) {
            return 0;
        }

        retval = parse_odp_key_attr(s, key);
        if (retval < 0) {
            key->size = old_size;
            return -retval;
        }
        s += retval;
    }

    return 0;
}

static uint8_t
ovs_to_odp_frag(uint8_t ovs_frag)
{
    return (ovs_frag & FLOW_FRAG_LATER ? OVS_FRAG_TYPE_LATER
            : ovs_frag & FLOW_FRAG_ANY ? OVS_FRAG_TYPE_FIRST
            : OVS_FRAG_TYPE_NONE);
}

/* Appends a representation of 'flow' as OVS_KEY_ATTR_* attributes to 'buf'. */
void
odp_flow_key_from_flow(struct ofpbuf *buf, const struct flow *flow)
{
    struct ovs_key_ethernet *eth_key;

    if (flow->priority) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_PRIORITY, flow->priority);
    }

    if (flow->tun_id != htonll(0)) {
        nl_msg_put_be64(buf, OVS_KEY_ATTR_TUN_ID, flow->tun_id);
    }

    if (flow->in_port != OFPP_NONE) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_IN_PORT,
                       ofp_port_to_odp_port(flow->in_port));
    }

    eth_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ETHERNET,
                                       sizeof *eth_key);
    memcpy(eth_key->eth_src, flow->dl_src, ETH_ADDR_LEN);
    memcpy(eth_key->eth_dst, flow->dl_dst, ETH_ADDR_LEN);

    if (flow->vlan_tci != htons(0)) {
        struct ovs_key_8021q *q_key;

        q_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_8021Q,
                                         sizeof *q_key);
        q_key->q_tpid = htons(ETH_TYPE_VLAN);
        q_key->q_tci = flow->vlan_tci & ~htons(VLAN_CFI);
    }

    if (ntohs(flow->dl_type) < ETH_TYPE_MIN) {
        return;
    }

    nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, flow->dl_type);

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        struct ovs_key_ipv4 *ipv4_key;

        ipv4_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_IPV4,
                                            sizeof *ipv4_key);
        ipv4_key->ipv4_src = flow->nw_src;
        ipv4_key->ipv4_dst = flow->nw_dst;
        ipv4_key->ipv4_proto = flow->nw_proto;
        ipv4_key->ipv4_tos = flow->tos;
        ipv4_key->ipv4_ttl = flow->nw_ttl;
        ipv4_key->ipv4_frag = ovs_to_odp_frag(flow->frag);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        struct ovs_key_ipv6 *ipv6_key;

        ipv6_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_IPV6,
                                            sizeof *ipv6_key);
        memcpy(ipv6_key->ipv6_src, &flow->ipv6_src, sizeof ipv6_key->ipv6_src);
        memcpy(ipv6_key->ipv6_dst, &flow->ipv6_dst, sizeof ipv6_key->ipv6_dst);
        ipv6_key->ipv6_label = flow->ipv6_label;
        ipv6_key->ipv6_proto = flow->nw_proto;
        ipv6_key->ipv6_tclass = flow->tos;
        ipv6_key->ipv6_hlimit = flow->nw_ttl;
        ipv6_key->ipv6_frag = ovs_to_odp_frag(flow->frag);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
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
        && !(flow->frag & FLOW_FRAG_LATER)) {

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
}

static bool
odp_to_ovs_frag(uint8_t odp_frag, struct flow *flow)
{
    if (odp_frag > OVS_FRAG_TYPE_LATER) {
        return false;
    }

    if (odp_frag != OVS_FRAG_TYPE_NONE) {
        flow->frag |= FLOW_FRAG_ANY;
        if (odp_frag == OVS_FRAG_TYPE_LATER) {
            flow->frag |= FLOW_FRAG_LATER;
        }
    }
    return true;
}

/* Converts the 'key_len' bytes of OVS_KEY_ATTR_* attributes in 'key' to a flow
 * structure in 'flow'.  Returns 0 if successful, otherwise EINVAL. */
int
odp_flow_key_to_flow(const struct nlattr *key, size_t key_len,
                     struct flow *flow)
{
    const struct nlattr *nla;
    enum ovs_key_attr prev_type;
    size_t left;

    memset(flow, 0, sizeof *flow);
    flow->dl_type = htons(FLOW_DL_TYPE_NONE);
    flow->in_port = OFPP_NONE;

    prev_type = OVS_KEY_ATTR_UNSPEC;
    NL_ATTR_FOR_EACH (nla, left, key, key_len) {
        const struct ovs_key_ethernet *eth_key;
        const struct ovs_key_8021q *q_key;
        const struct ovs_key_ipv4 *ipv4_key;
        const struct ovs_key_ipv6 *ipv6_key;
        const struct ovs_key_tcp *tcp_key;
        const struct ovs_key_udp *udp_key;
        const struct ovs_key_icmp *icmp_key;
        const struct ovs_key_icmpv6 *icmpv6_key;
        const struct ovs_key_arp *arp_key;
        const struct ovs_key_nd *nd_key;

        uint16_t type = nl_attr_type(nla);
        int len = odp_flow_key_attr_len(type);

        if (nl_attr_get_size(nla) != len && len != -1) {
            return EINVAL;
        }

#define TRANSITION(PREV_TYPE, TYPE) (((PREV_TYPE) << 16) | (TYPE))
        switch (TRANSITION(prev_type, type)) {
        case TRANSITION(OVS_KEY_ATTR_UNSPEC, OVS_KEY_ATTR_PRIORITY):
            flow->priority = nl_attr_get_u32(nla);
            break;

        case TRANSITION(OVS_KEY_ATTR_UNSPEC, OVS_KEY_ATTR_TUN_ID):
        case TRANSITION(OVS_KEY_ATTR_PRIORITY, OVS_KEY_ATTR_TUN_ID):
            flow->tun_id = nl_attr_get_be64(nla);
            break;

        case TRANSITION(OVS_KEY_ATTR_UNSPEC, OVS_KEY_ATTR_IN_PORT):
        case TRANSITION(OVS_KEY_ATTR_PRIORITY, OVS_KEY_ATTR_IN_PORT):
        case TRANSITION(OVS_KEY_ATTR_TUN_ID, OVS_KEY_ATTR_IN_PORT):
            if (nl_attr_get_u32(nla) >= UINT16_MAX) {
                return EINVAL;
            }
            flow->in_port = odp_port_to_ofp_port(nl_attr_get_u32(nla));
            break;

        case TRANSITION(OVS_KEY_ATTR_UNSPEC, OVS_KEY_ATTR_ETHERNET):
        case TRANSITION(OVS_KEY_ATTR_PRIORITY, OVS_KEY_ATTR_ETHERNET):
        case TRANSITION(OVS_KEY_ATTR_TUN_ID, OVS_KEY_ATTR_ETHERNET):
        case TRANSITION(OVS_KEY_ATTR_IN_PORT, OVS_KEY_ATTR_ETHERNET):
            eth_key = nl_attr_get(nla);
            memcpy(flow->dl_src, eth_key->eth_src, ETH_ADDR_LEN);
            memcpy(flow->dl_dst, eth_key->eth_dst, ETH_ADDR_LEN);
            break;

        case TRANSITION(OVS_KEY_ATTR_ETHERNET, OVS_KEY_ATTR_8021Q):
            q_key = nl_attr_get(nla);
            if (q_key->q_tpid != htons(ETH_TYPE_VLAN)) {
                /* Only standard 0x8100 VLANs currently supported. */
                return EINVAL;
            }
            if (q_key->q_tci & htons(VLAN_CFI)) {
                return EINVAL;
            }
            flow->vlan_tci = q_key->q_tci | htons(VLAN_CFI);
            break;

        case TRANSITION(OVS_KEY_ATTR_8021Q, OVS_KEY_ATTR_ETHERTYPE):
        case TRANSITION(OVS_KEY_ATTR_ETHERNET, OVS_KEY_ATTR_ETHERTYPE):
            flow->dl_type = nl_attr_get_be16(nla);
            if (ntohs(flow->dl_type) < 1536) {
                return EINVAL;
            }
            break;

        case TRANSITION(OVS_KEY_ATTR_ETHERTYPE, OVS_KEY_ATTR_IPV4):
            if (flow->dl_type != htons(ETH_TYPE_IP)) {
                return EINVAL;
            }
            ipv4_key = nl_attr_get(nla);
            flow->nw_src = ipv4_key->ipv4_src;
            flow->nw_dst = ipv4_key->ipv4_dst;
            flow->nw_proto = ipv4_key->ipv4_proto;
            flow->tos = ipv4_key->ipv4_tos;
            flow->nw_ttl = ipv4_key->ipv4_ttl;
            if (!odp_to_ovs_frag(ipv4_key->ipv4_frag, flow)) {
                return EINVAL;
            }
            break;

        case TRANSITION(OVS_KEY_ATTR_ETHERTYPE, OVS_KEY_ATTR_IPV6):
            if (flow->dl_type != htons(ETH_TYPE_IPV6)) {
                return EINVAL;
            }
            ipv6_key = nl_attr_get(nla);
            memcpy(&flow->ipv6_src, ipv6_key->ipv6_src, sizeof flow->ipv6_src);
            memcpy(&flow->ipv6_dst, ipv6_key->ipv6_dst, sizeof flow->ipv6_dst);
            flow->ipv6_label = ipv6_key->ipv6_label;
            flow->nw_proto = ipv6_key->ipv6_proto;
            flow->tos = ipv6_key->ipv6_tclass;
            flow->nw_ttl = ipv6_key->ipv6_hlimit;
            if (!odp_to_ovs_frag(ipv6_key->ipv6_frag, flow)) {
                return EINVAL;
            }
            break;

        case TRANSITION(OVS_KEY_ATTR_IPV4, OVS_KEY_ATTR_TCP):
        case TRANSITION(OVS_KEY_ATTR_IPV6, OVS_KEY_ATTR_TCP):
            if (flow->nw_proto != IPPROTO_TCP) {
                return EINVAL;
            }
            tcp_key = nl_attr_get(nla);
            flow->tp_src = tcp_key->tcp_src;
            flow->tp_dst = tcp_key->tcp_dst;
            break;

        case TRANSITION(OVS_KEY_ATTR_IPV4, OVS_KEY_ATTR_UDP):
        case TRANSITION(OVS_KEY_ATTR_IPV6, OVS_KEY_ATTR_UDP):
            if (flow->nw_proto != IPPROTO_UDP) {
                return EINVAL;
            }
            udp_key = nl_attr_get(nla);
            flow->tp_src = udp_key->udp_src;
            flow->tp_dst = udp_key->udp_dst;
            break;

        case TRANSITION(OVS_KEY_ATTR_IPV4, OVS_KEY_ATTR_ICMP):
            if (flow->nw_proto != IPPROTO_ICMP) {
                return EINVAL;
            }
            icmp_key = nl_attr_get(nla);
            flow->tp_src = htons(icmp_key->icmp_type);
            flow->tp_dst = htons(icmp_key->icmp_code);
            break;

        case TRANSITION(OVS_KEY_ATTR_IPV6, OVS_KEY_ATTR_ICMPV6):
            if (flow->nw_proto != IPPROTO_ICMPV6) {
                return EINVAL;
            }
            icmpv6_key = nl_attr_get(nla);
            flow->tp_src = htons(icmpv6_key->icmpv6_type);
            flow->tp_dst = htons(icmpv6_key->icmpv6_code);
            break;

        case TRANSITION(OVS_KEY_ATTR_ETHERTYPE, OVS_KEY_ATTR_ARP):
            if (flow->dl_type != htons(ETH_TYPE_ARP)) {
                return EINVAL;
            }
            arp_key = nl_attr_get(nla);
            flow->nw_src = arp_key->arp_sip;
            flow->nw_dst = arp_key->arp_tip;
            if (arp_key->arp_op & htons(0xff00)) {
                return EINVAL;
            }
            flow->nw_proto = ntohs(arp_key->arp_op);
            memcpy(flow->arp_sha, arp_key->arp_sha, ETH_ADDR_LEN);
            memcpy(flow->arp_tha, arp_key->arp_tha, ETH_ADDR_LEN);
            break;

        case TRANSITION(OVS_KEY_ATTR_ICMPV6, OVS_KEY_ATTR_ND):
            if (flow->tp_src != htons(ND_NEIGHBOR_SOLICIT)
                    && flow->tp_src != htons(ND_NEIGHBOR_ADVERT)) {
                return EINVAL;
            }
            nd_key = nl_attr_get(nla);
            memcpy(&flow->nd_target, nd_key->nd_target, sizeof flow->nd_target);
            memcpy(flow->arp_sha, nd_key->nd_sll, ETH_ADDR_LEN);
            memcpy(flow->arp_tha, nd_key->nd_tll, ETH_ADDR_LEN);
            break;

        default:
            return EINVAL;
        }

        prev_type = type;
    }
    if (left) {
        return EINVAL;
    }

    switch (prev_type) {
    case OVS_KEY_ATTR_UNSPEC:
        return EINVAL;

    case OVS_KEY_ATTR_PRIORITY:
    case OVS_KEY_ATTR_TUN_ID:
    case OVS_KEY_ATTR_IN_PORT:
        return EINVAL;

    case OVS_KEY_ATTR_ETHERNET:
    case OVS_KEY_ATTR_8021Q:
        return 0;

    case OVS_KEY_ATTR_ETHERTYPE:
        if (flow->dl_type == htons(ETH_TYPE_IP)
            || flow->dl_type == htons(ETH_TYPE_IPV6)
            || flow->dl_type == htons(ETH_TYPE_ARP)) {
            return EINVAL;
        }
        return 0;

    case OVS_KEY_ATTR_IPV4:
        if (flow->frag & FLOW_FRAG_LATER) {
            return 0;
        }
        if (flow->nw_proto == IPPROTO_TCP
            || flow->nw_proto == IPPROTO_UDP
            || flow->nw_proto == IPPROTO_ICMP) {
            return EINVAL;
        }
        return 0;

    case OVS_KEY_ATTR_IPV6:
        if (flow->frag & FLOW_FRAG_LATER) {
            return 0;
        }
        if (flow->nw_proto == IPPROTO_TCP
            || flow->nw_proto == IPPROTO_UDP
            || flow->nw_proto == IPPROTO_ICMPV6) {
            return EINVAL;
        }
        return 0;

    case OVS_KEY_ATTR_ICMPV6:
        if (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT)
            || flow->tp_src == htons(ND_NEIGHBOR_ADVERT)
            || flow->frag & FLOW_FRAG_LATER) {
            return EINVAL;
        }
        return 0;

    case OVS_KEY_ATTR_TCP:
    case OVS_KEY_ATTR_UDP:
    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ND:
        if (flow->frag & FLOW_FRAG_LATER) {
            return EINVAL;
        }
        return 0;

    case OVS_KEY_ATTR_ARP:
        return 0;

    case __OVS_KEY_ATTR_MAX:
    default:
        NOT_REACHED();
    }
}
