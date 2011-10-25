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
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(odp_util);

/* The interface between userspace and kernel uses an "OVS_*" prefix.
 * Since this is fairly non-specific for the OVS userspace components,
 * "ODP_*" (Open vSwitch Datapath) is used as the prefix for
 * interactions with the datapath.
 */

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
    case OVS_KEY_ATTR_PRIORITY: return "priority";
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
    case OVS_KEY_ATTR_TUN_ID: return "tun_id";

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
            ds_put_format(ds, ",controller,length=%"PRIu32, cookie.data);
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
    case OVS_KEY_ATTR_TUN_ID: return 8;
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
        ds_put_format(ds, "(%"PRIu32")", nl_attr_get_u32(a));
        break;

    case OVS_KEY_ATTR_TUN_ID:
        ds_put_format(ds, "(%#"PRIx64")", ntohll(nl_attr_get_be64(a)));
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

            retval = parse_odp_key_attr(s, key);
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
 * On success, the attributes appended to 'key' are individually syntactically
 * valid, but they may not be valid as a sequence.  'key' might, for example,
 * have duplicated keys.  odp_flow_key_to_flow() will detect those errors. */
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
    return (ovs_frag & FLOW_NW_FRAG_LATER ? OVS_FRAG_TYPE_LATER
            : ovs_frag & FLOW_NW_FRAG_ANY ? OVS_FRAG_TYPE_FIRST
            : OVS_FRAG_TYPE_NONE);
}

/* Appends a representation of 'flow' as OVS_KEY_ATTR_* attributes to 'buf'. */
void
odp_flow_key_from_flow(struct ofpbuf *buf, const struct flow *flow)
{
    struct ovs_key_ethernet *eth_key;
    size_t encap;

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

static void
log_odp_key_attributes(struct vlog_rate_limit *rl, const char *title,
                       uint32_t attrs,
                       const struct nlattr *key, size_t key_len)
{
    struct ds s;
    int i;

    if (VLOG_DROP_WARN(rl)) {
        return;
    }

    ds_init(&s);
    ds_put_format(&s, "%s:", title);
    for (i = 0; i < 32; i++) {
        if (attrs & (1u << i)) {
            ds_put_format(&s, " %s", ovs_key_attr_to_string(i));
        }
    }

    ds_put_cstr(&s, ": ");
    odp_flow_key_format(key, key_len, &s);

    VLOG_WARN("%s", ds_cstr(&s));
    ds_destroy(&s);
}

static bool
odp_to_ovs_frag(uint8_t odp_frag, struct flow *flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (odp_frag > OVS_FRAG_TYPE_LATER) {
        VLOG_ERR_RL(&rl, "invalid frag %"PRIu8" in flow key",
                    odp_frag);
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

static int
parse_flow_nlattrs(const struct nlattr *key, size_t key_len,
                   const struct nlattr *attrs[], uint64_t *present_attrsp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const struct nlattr *nla;
    uint64_t present_attrs;
    size_t left;

    present_attrs = 0;
    NL_ATTR_FOR_EACH (nla, left, key, key_len) {
        uint16_t type = nl_attr_type(nla);
        size_t len = nl_attr_get_size(nla);
        int expected_len = odp_flow_key_attr_len(type);

        if (len != expected_len && expected_len != -2) {
            if (expected_len == -1) {
                VLOG_ERR_RL(&rl, "unknown attribute %"PRIu16" in flow key",
                            type);
            } else {
                VLOG_ERR_RL(&rl, "attribute %s has length %zu but should have "
                            "length %d", ovs_key_attr_to_string(type),
                            len, expected_len);
            }
            return EINVAL;
        } else if (present_attrs & (UINT64_C(1) << type)) {
            VLOG_ERR_RL(&rl, "duplicate %s attribute in flow key",
                        ovs_key_attr_to_string(type));
            return EINVAL;
        }

        present_attrs |= UINT64_C(1) << type;
        attrs[type] = nla;
    }
    if (left) {
        VLOG_ERR_RL(&rl, "trailing garbage in flow key");
        return EINVAL;
    }

    *present_attrsp = present_attrs;
    return 0;
}

static int
check_expectations(uint64_t present_attrs, uint64_t expected_attrs,
                   const struct nlattr *key, size_t key_len)
{
    uint64_t missing_attrs;
    uint64_t extra_attrs;

    missing_attrs = expected_attrs & ~present_attrs;
    if (missing_attrs) {
        static struct vlog_rate_limit miss_rl = VLOG_RATE_LIMIT_INIT(10, 10);
        log_odp_key_attributes(&miss_rl, "expected but not present",
                               missing_attrs, key, key_len);
        return EINVAL;
    }

    extra_attrs = present_attrs & ~expected_attrs;
    if (extra_attrs) {
        static struct vlog_rate_limit extra_rl = VLOG_RATE_LIMIT_INIT(10, 10);
        log_odp_key_attributes(&extra_rl, "present but not expected",
                               extra_attrs, key, key_len);
        return EINVAL;
    }

    return 0;
}

/* Converts the 'key_len' bytes of OVS_KEY_ATTR_* attributes in 'key' to a flow
 * structure in 'flow'.  Returns 0 if successful, otherwise EINVAL. */
int
odp_flow_key_to_flow(const struct nlattr *key, size_t key_len,
                     struct flow *flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1];
    uint64_t expected_attrs;
    uint64_t present_attrs;
    int error;

    memset(flow, 0, sizeof *flow);

    error = parse_flow_nlattrs(key, key_len, attrs, &present_attrs);
    if (error) {
        return error;
    }

    expected_attrs = 0;

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_PRIORITY)) {
        flow->priority = nl_attr_get_u32(attrs[OVS_KEY_ATTR_PRIORITY]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_PRIORITY;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_TUN_ID)) {
        flow->tun_id = nl_attr_get_be64(attrs[OVS_KEY_ATTR_TUN_ID]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_TUN_ID;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IN_PORT)) {
        uint32_t in_port = nl_attr_get_u32(attrs[OVS_KEY_ATTR_IN_PORT]);
        if (in_port >= UINT16_MAX || in_port >= OFPP_MAX) {
            VLOG_ERR_RL(&rl, "in_port %"PRIu32" out of supported range",
                        in_port);
            return EINVAL;
        }
        flow->in_port = odp_port_to_ofp_port(in_port);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IN_PORT;
    } else {
        flow->in_port = OFPP_NONE;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERNET)) {
        const struct ovs_key_ethernet *eth_key;

        eth_key = nl_attr_get(attrs[OVS_KEY_ATTR_ETHERNET]);
        memcpy(flow->dl_src, eth_key->eth_src, ETH_ADDR_LEN);
        memcpy(flow->dl_dst, eth_key->eth_dst, ETH_ADDR_LEN);
    } else {
        VLOG_ERR_RL(&rl, "missing Ethernet attribute in flow key");
        return EINVAL;
    }
    expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERNET;

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE)
        && (nl_attr_get_be16(attrs[OVS_KEY_ATTR_ETHERTYPE])
            == htons(ETH_TYPE_VLAN))) {
        /* The Ethernet type is 0x8100 so there must be a VLAN tag
         * and encapsulated protocol information. */
        const struct nlattr *encap;
        __be16 tci;
        int error;

        expected_attrs |= ((UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE) |
                           (UINT64_C(1) << OVS_KEY_ATTR_VLAN) |
                           (UINT64_C(1) << OVS_KEY_ATTR_ENCAP));
        error = check_expectations(present_attrs, expected_attrs,
                                   key, key_len);
        if (error) {
            return error;
        }

        encap = attrs[OVS_KEY_ATTR_ENCAP];
        tci = nl_attr_get_be16(attrs[OVS_KEY_ATTR_VLAN]);
        if (tci & htons(VLAN_CFI)) {
            flow->vlan_tci = tci;

            error = parse_flow_nlattrs(nl_attr_get(encap),
                                       nl_attr_get_size(encap),
                                       attrs, &present_attrs);
            if (error) {
                return error;
            }
            expected_attrs = 0;
        } else if (tci == htons(0)) {
            /* Corner case for a truncated 802.1Q header. */
            if (nl_attr_get_size(encap)) {
                return EINVAL;
            }

            flow->dl_type = htons(ETH_TYPE_VLAN);
            return 0;
        } else {
            return EINVAL;
        }
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE)) {
        flow->dl_type = nl_attr_get_be16(attrs[OVS_KEY_ATTR_ETHERTYPE]);
        if (ntohs(flow->dl_type) < 1536) {
            VLOG_ERR_RL(&rl, "invalid Ethertype %"PRIu16" in flow key",
                        ntohs(flow->dl_type));
            return EINVAL;
        }
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE;
    } else {
        flow->dl_type = htons(FLOW_DL_TYPE_NONE);
    }

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
                return EINVAL;
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
                return EINVAL;
            }
        }
    } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ARP;
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ARP)) {
            const struct ovs_key_arp *arp_key;

            arp_key = nl_attr_get(attrs[OVS_KEY_ATTR_ARP]);
            flow->nw_src = arp_key->arp_sip;
            flow->nw_dst = arp_key->arp_tip;
            if (arp_key->arp_op & htons(0xff00)) {
                VLOG_ERR_RL(&rl, "unsupported ARP opcode %"PRIu16" in flow "
                            "key", ntohs(arp_key->arp_op));
                return EINVAL;
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

    return check_expectations(present_attrs, expected_attrs, key, key_len);
}

/* Appends an OVS_ACTION_ATTR_USERSPACE action to 'odp_actions' that specifies
 * Netlink PID 'pid'.  If 'cookie' is nonnull, adds a userdata attribute whose
 * contents contains 'cookie' and returns the offset within 'odp_actions' of
 * the start of the cookie.  (If 'cookie' is null, then the return value is not
 * meaningful.) */
size_t
odp_put_userspace_action(uint32_t pid, const struct user_action_cookie *cookie,
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
