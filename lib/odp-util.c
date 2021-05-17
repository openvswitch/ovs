/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2019 Nicira, Inc.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "odp-util.h"
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>

#include "byte-order.h"
#include "coverage.h"
#include "dpif.h"
#include "openvswitch/dynamic-string.h"
#include "flow.h"
#include "netlink.h"
#include "openvswitch/ofpbuf.h"
#include "packets.h"
#include "simap.h"
#include "timeval.h"
#include "tun-metadata.h"
#include "unaligned.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"
#include "openvswitch/match.h"
#include "odp-netlink-macros.h"
#include "csum.h"

VLOG_DEFINE_THIS_MODULE(odp_util);

/* The interface between userspace and kernel uses an "OVS_*" prefix.
 * Since this is fairly non-specific for the OVS userspace components,
 * "ODP_*" (Open vSwitch Datapath) is used as the prefix for
 * interactions with the datapath.
 */

/* The set of characters that may separate one action or one key attribute
 * from another. */
static const char *delimiters = ", \t\r\n";
static const char *delimiters_end = ", \t\r\n)";

#define MAX_ODP_NESTED 32

struct parse_odp_context {
    const struct simap *port_names;
    int depth; /* Current nested depth of odp string. */
};

static int parse_odp_key_mask_attr(struct parse_odp_context *, const char *,
                                   struct ofpbuf *, struct ofpbuf *);

static int parse_odp_key_mask_attr__(struct parse_odp_context *, const char *,
                                   struct ofpbuf *, struct ofpbuf *);

static void format_odp_key_attr(const struct nlattr *a,
                                const struct nlattr *ma,
                                const struct hmap *portno_names, struct ds *ds,
                                bool verbose);

struct geneve_scan {
    struct geneve_opt d[63];
    int len;
};

static int scan_geneve(const char *s, struct geneve_scan *key,
                       struct geneve_scan *mask);
static void format_geneve_opts(const struct geneve_opt *opt,
                               const struct geneve_opt *mask, int opts_len,
                               struct ds *, bool verbose);

static struct nlattr *generate_all_wildcard_mask(const struct attr_len_tbl tbl[],
                                                 int max, struct ofpbuf *,
                                                 const struct nlattr *key);
static void format_u128(struct ds *d, const ovs_32aligned_u128 *key,
                        const ovs_32aligned_u128 *mask, bool verbose);
static int scan_u128(const char *s, ovs_u128 *value, ovs_u128 *mask);

static int parse_odp_action(struct parse_odp_context *context, const char *s,
                            struct ofpbuf *actions);

static int parse_odp_action__(struct parse_odp_context *context, const char *s,
                            struct ofpbuf *actions);

/* Returns one the following for the action with the given OVS_ACTION_ATTR_*
 * 'type':
 *
 *   - For an action whose argument has a fixed length, returned that
 *     nonnegative length in bytes.
 *
 *   - For an action with a variable-length argument, returns ATTR_LEN_VARIABLE.
 *
 *   - For an invalid 'type', returns ATTR_LEN_INVALID. */
static int
odp_action_len(uint16_t type)
{
    if (type > OVS_ACTION_ATTR_MAX) {
        return -1;
    }

    switch ((enum ovs_action_attr) type) {
    case OVS_ACTION_ATTR_OUTPUT: return sizeof(uint32_t);
    case OVS_ACTION_ATTR_LB_OUTPUT: return sizeof(uint32_t);
    case OVS_ACTION_ATTR_TRUNC: return sizeof(struct ovs_action_trunc);
    case OVS_ACTION_ATTR_TUNNEL_PUSH: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_TUNNEL_POP: return sizeof(uint32_t);
    case OVS_ACTION_ATTR_METER: return sizeof(uint32_t);
    case OVS_ACTION_ATTR_USERSPACE: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_PUSH_VLAN: return sizeof(struct ovs_action_push_vlan);
    case OVS_ACTION_ATTR_POP_VLAN: return 0;
    case OVS_ACTION_ATTR_PUSH_MPLS: return sizeof(struct ovs_action_push_mpls);
    case OVS_ACTION_ATTR_POP_MPLS: return sizeof(ovs_be16);
    case OVS_ACTION_ATTR_RECIRC: return sizeof(uint32_t);
    case OVS_ACTION_ATTR_HASH: return sizeof(struct ovs_action_hash);
    case OVS_ACTION_ATTR_SET: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_SET_MASKED: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_SAMPLE: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_CT: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_CT_CLEAR: return 0;
    case OVS_ACTION_ATTR_PUSH_ETH: return sizeof(struct ovs_action_push_eth);
    case OVS_ACTION_ATTR_POP_ETH: return 0;
    case OVS_ACTION_ATTR_CLONE: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_PUSH_NSH: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_POP_NSH: return 0;
    case OVS_ACTION_ATTR_CHECK_PKT_LEN: return ATTR_LEN_VARIABLE;
    case OVS_ACTION_ATTR_DROP: return sizeof(uint32_t);

    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        return ATTR_LEN_INVALID;
    }

    return ATTR_LEN_INVALID;
}

/* Returns a string form of 'attr'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'namebuf'.  'bufsize'
 * should be at least OVS_KEY_ATTR_BUFSIZE. */
enum { OVS_KEY_ATTR_BUFSIZE = 3 + INT_STRLEN(unsigned int) + 1 };
static const char *
ovs_key_attr_to_string(enum ovs_key_attr attr, char *namebuf, size_t bufsize)
{
    switch (attr) {
    case OVS_KEY_ATTR_UNSPEC: return "unspec";
    case OVS_KEY_ATTR_ENCAP: return "encap";
    case OVS_KEY_ATTR_PRIORITY: return "skb_priority";
    case OVS_KEY_ATTR_SKB_MARK: return "skb_mark";
    case OVS_KEY_ATTR_CT_STATE: return "ct_state";
    case OVS_KEY_ATTR_CT_ZONE: return "ct_zone";
    case OVS_KEY_ATTR_CT_MARK: return "ct_mark";
    case OVS_KEY_ATTR_CT_LABELS: return "ct_label";
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4: return "ct_tuple4";
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6: return "ct_tuple6";
    case OVS_KEY_ATTR_TUNNEL: return "tunnel";
    case OVS_KEY_ATTR_IN_PORT: return "in_port";
    case OVS_KEY_ATTR_ETHERNET: return "eth";
    case OVS_KEY_ATTR_VLAN: return "vlan";
    case OVS_KEY_ATTR_ETHERTYPE: return "eth_type";
    case OVS_KEY_ATTR_IPV4: return "ipv4";
    case OVS_KEY_ATTR_IPV6: return "ipv6";
    case OVS_KEY_ATTR_TCP: return "tcp";
    case OVS_KEY_ATTR_TCP_FLAGS: return "tcp_flags";
    case OVS_KEY_ATTR_UDP: return "udp";
    case OVS_KEY_ATTR_SCTP: return "sctp";
    case OVS_KEY_ATTR_ICMP: return "icmp";
    case OVS_KEY_ATTR_ICMPV6: return "icmpv6";
    case OVS_KEY_ATTR_ARP: return "arp";
    case OVS_KEY_ATTR_ND: return "nd";
    case OVS_KEY_ATTR_ND_EXTENSIONS: return "nd_ext";
    case OVS_KEY_ATTR_MPLS: return "mpls";
    case OVS_KEY_ATTR_DP_HASH: return "dp_hash";
    case OVS_KEY_ATTR_RECIRC_ID: return "recirc_id";
    case OVS_KEY_ATTR_PACKET_TYPE: return "packet_type";
    case OVS_KEY_ATTR_NSH: return "nsh";

    case __OVS_KEY_ATTR_MAX:
    default:
        snprintf(namebuf, bufsize, "key%u", (unsigned int) attr);
        return namebuf;
    }
}

static void
format_generic_odp_action(struct ds *ds, const struct nlattr *a)
{
    size_t len = nl_attr_get_size(a);

    ds_put_format(ds, "action%d", nl_attr_type(a));
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
format_odp_sample_action(struct ds *ds, const struct nlattr *attr,
                         const struct hmap *portno_names)
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
    format_odp_actions(ds, nla_acts, len, portno_names);
    ds_put_format(ds, "))");
}

static void
format_odp_clone_action(struct ds *ds, const struct nlattr *attr,
                        const struct hmap *portno_names)
{
    const struct nlattr *nla_acts = nl_attr_get(attr);
    int len = nl_attr_get_size(attr);

    ds_put_cstr(ds, "clone");
    ds_put_format(ds, "(");
    format_odp_actions(ds, nla_acts, len, portno_names);
    ds_put_format(ds, ")");
}

static void
format_nsh_key(struct ds *ds, const struct ovs_key_nsh *key)
{
    ds_put_format(ds, "flags=%d", key->flags);
    ds_put_format(ds, ",ttl=%d", key->ttl);
    ds_put_format(ds, ",mdtype=%d", key->mdtype);
    ds_put_format(ds, ",np=%d", key->np);
    ds_put_format(ds, ",spi=0x%x",
                  nsh_path_hdr_to_spi_uint32(key->path_hdr));
    ds_put_format(ds, ",si=%d",
                  nsh_path_hdr_to_si(key->path_hdr));

    switch (key->mdtype) {
        case NSH_M_TYPE1:
            for (int i = 0; i < 4; i++) {
                ds_put_format(ds, ",c%d=0x%x", i + 1, ntohl(key->context[i]));
            }
            break;
        case NSH_M_TYPE2:
        default:
            /* No support for matching other metadata formats yet. */
            break;
    }
}

static void
format_uint8_masked(struct ds *s, bool *first, const char *name,
                    uint8_t value, uint8_t mask)
{
    if (mask != 0) {
        if (!*first) {
            ds_put_char(s, ',');
        }
        ds_put_format(s, "%s=", name);
        if (mask == UINT8_MAX) {
            ds_put_format(s, "%"PRIu8, value);
        } else {
            ds_put_format(s, "0x%02"PRIx8"/0x%02"PRIx8, value, mask);
        }
        *first = false;
    }
}

static void
format_be32_masked(struct ds *s, bool *first, const char *name,
                   ovs_be32 value, ovs_be32 mask)
{
    if (mask != htonl(0)) {
        if (!*first) {
            ds_put_char(s, ',');
        }
        ds_put_format(s, "%s=", name);
        if (mask == OVS_BE32_MAX) {
            ds_put_format(s, "0x%"PRIx32, ntohl(value));
        } else {
            ds_put_format(s, "0x%"PRIx32"/0x%08"PRIx32,
                          ntohl(value), ntohl(mask));
        }
        *first = false;
    }
}

static void
format_nsh_key_mask(struct ds *ds, const struct ovs_key_nsh *key,
                    const struct ovs_key_nsh *mask)
{
    if (!mask) {
        format_nsh_key(ds, key);
    } else {
        bool first = true;
        uint32_t spi = nsh_path_hdr_to_spi_uint32(key->path_hdr);
        uint32_t spi_mask = nsh_path_hdr_to_spi_uint32(mask->path_hdr);
        if (spi_mask == (NSH_SPI_MASK >> NSH_SPI_SHIFT)) {
            spi_mask = UINT32_MAX;
        }
        uint8_t si = nsh_path_hdr_to_si(key->path_hdr);
        uint8_t si_mask = nsh_path_hdr_to_si(mask->path_hdr);

        format_uint8_masked(ds, &first, "flags", key->flags, mask->flags);
        format_uint8_masked(ds, &first, "ttl", key->ttl, mask->ttl);
        format_uint8_masked(ds, &first, "mdtype", key->mdtype, mask->mdtype);
        format_uint8_masked(ds, &first, "np", key->np, mask->np);
        format_be32_masked(ds, &first, "spi", htonl(spi), htonl(spi_mask));
        format_uint8_masked(ds, &first, "si", si, si_mask);
        format_be32_masked(ds, &first, "c1", key->context[0],
                           mask->context[0]);
        format_be32_masked(ds, &first, "c2", key->context[1],
                           mask->context[1]);
        format_be32_masked(ds, &first, "c3", key->context[2],
                           mask->context[2]);
        format_be32_masked(ds, &first, "c4", key->context[3],
                           mask->context[3]);
    }
}

static void
format_odp_push_nsh_action(struct ds *ds,
                           const struct nsh_hdr *nsh_hdr)
 {
    size_t mdlen = nsh_hdr_len(nsh_hdr) - NSH_BASE_HDR_LEN;
    uint32_t spi = ntohl(nsh_get_spi(nsh_hdr));
    uint8_t si = nsh_get_si(nsh_hdr);
    uint8_t flags = nsh_get_flags(nsh_hdr);
    uint8_t ttl = nsh_get_ttl(nsh_hdr);

    ds_put_cstr(ds, "push_nsh(");
    ds_put_format(ds, "flags=%d", flags);
    ds_put_format(ds, ",ttl=%d", ttl);
    ds_put_format(ds, ",mdtype=%d", nsh_hdr->md_type);
    ds_put_format(ds, ",np=%d", nsh_hdr->next_proto);
    ds_put_format(ds, ",spi=0x%x", spi);
    ds_put_format(ds, ",si=%d", si);
    switch (nsh_hdr->md_type) {
    case NSH_M_TYPE1: {
        const struct nsh_md1_ctx *md1_ctx = &nsh_hdr->md1;
        for (int i = 0; i < 4; i++) {
            ds_put_format(ds, ",c%d=0x%x", i + 1,
                          ntohl(get_16aligned_be32(&md1_ctx->context[i])));
        }
        break;
    }
    case NSH_M_TYPE2: {
        const struct nsh_md2_tlv *md2_ctx = &nsh_hdr->md2;
        ds_put_cstr(ds, ",md2=");
        ds_put_hex(ds, md2_ctx, mdlen);
        break;
    }
    default:
        ds_put_cstr(ds, ",<error: unknown mdtype>");
        break;
    }
    ds_put_format(ds, ")");
}

static const char *
slow_path_reason_to_string(uint32_t reason)
{
    switch ((enum slow_path_reason) reason) {
#define SPR(ENUM, STRING, EXPLANATION) case ENUM: return STRING;
        SLOW_PATH_REASONS
#undef SPR
    }

    return NULL;
}

const char *
slow_path_reason_to_explanation(enum slow_path_reason reason)
{
    switch (reason) {
#define SPR(ENUM, STRING, EXPLANATION) case ENUM: return EXPLANATION;
        SLOW_PATH_REASONS
#undef SPR
    }

    return "<unknown>";
}

static int
parse_odp_flags(const char *s, const char *(*bit_to_string)(uint32_t),
                uint32_t *res_flags, uint32_t allowed, uint32_t *res_mask)
{
    return parse_flags(s, bit_to_string, ')', NULL, NULL,
                       res_flags, allowed, res_mask);
}

static void
format_odp_userspace_action(struct ds *ds, const struct nlattr *attr,
                            const struct hmap *portno_names)
{
    static const struct nl_policy ovs_userspace_policy[] = {
        [OVS_USERSPACE_ATTR_PID] = { .type = NL_A_U32 },
        [OVS_USERSPACE_ATTR_USERDATA] = { .type = NL_A_UNSPEC,
                                          .optional = true },
        [OVS_USERSPACE_ATTR_EGRESS_TUN_PORT] = { .type = NL_A_U32,
                                                 .optional = true },
        [OVS_USERSPACE_ATTR_ACTIONS] = { .type = NL_A_UNSPEC,
                                                 .optional = true },
    };
    struct nlattr *a[ARRAY_SIZE(ovs_userspace_policy)];
    const struct nlattr *userdata_attr;
    const struct nlattr *tunnel_out_port_attr;

    if (!nl_parse_nested(attr, ovs_userspace_policy, a, ARRAY_SIZE(a))) {
        ds_put_cstr(ds, "userspace(error)");
        return;
    }

    ds_put_format(ds, "userspace(pid=%"PRIu32,
                  nl_attr_get_u32(a[OVS_USERSPACE_ATTR_PID]));

    userdata_attr = a[OVS_USERSPACE_ATTR_USERDATA];

    if (userdata_attr) {
        const uint8_t *userdata = nl_attr_get(userdata_attr);
        size_t userdata_len = nl_attr_get_size(userdata_attr);
        bool userdata_unspec = true;
        struct user_action_cookie cookie;

        if (userdata_len == sizeof cookie) {
            memcpy(&cookie, userdata, sizeof cookie);

            userdata_unspec = false;

            if (cookie.type == USER_ACTION_COOKIE_SFLOW) {
                ds_put_format(ds, ",sFlow("
                              "vid=%"PRIu16",pcp=%d,output=%"PRIu32")",
                              vlan_tci_to_vid(cookie.sflow.vlan_tci),
                              vlan_tci_to_pcp(cookie.sflow.vlan_tci),
                              cookie.sflow.output);
            } else if (cookie.type == USER_ACTION_COOKIE_SLOW_PATH) {
                ds_put_cstr(ds, ",slow_path(");
                format_flags(ds, slow_path_reason_to_string,
                             cookie.slow_path.reason, ',');
                ds_put_format(ds, ")");
            } else if (cookie.type == USER_ACTION_COOKIE_FLOW_SAMPLE) {
                ds_put_format(ds, ",flow_sample(probability=%"PRIu16
                              ",collector_set_id=%"PRIu32
                              ",obs_domain_id=%"PRIu32
                              ",obs_point_id=%"PRIu32
                              ",output_port=",
                              cookie.flow_sample.probability,
                              cookie.flow_sample.collector_set_id,
                              cookie.flow_sample.obs_domain_id,
                              cookie.flow_sample.obs_point_id);
                odp_portno_name_format(portno_names,
                                       cookie.flow_sample.output_odp_port, ds);
                if (cookie.flow_sample.direction == NX_ACTION_SAMPLE_INGRESS) {
                    ds_put_cstr(ds, ",ingress");
                } else if (cookie.flow_sample.direction == NX_ACTION_SAMPLE_EGRESS) {
                    ds_put_cstr(ds, ",egress");
                }
                ds_put_char(ds, ')');
            } else if (cookie.type == USER_ACTION_COOKIE_IPFIX) {
                ds_put_format(ds, ",ipfix(output_port=");
                odp_portno_name_format(portno_names,
                                       cookie.ipfix.output_odp_port, ds);
                ds_put_char(ds, ')');
            } else if (cookie.type == USER_ACTION_COOKIE_CONTROLLER) {
                ds_put_format(ds, ",controller(reason=%"PRIu16
                              ",dont_send=%d"
                              ",continuation=%d"
                              ",recirc_id=%"PRIu32
                              ",rule_cookie=%#"PRIx64
                              ",controller_id=%"PRIu16
                              ",max_len=%"PRIu16,
                              cookie.controller.reason,
                              !!cookie.controller.dont_send,
                              !!cookie.controller.continuation,
                              cookie.controller.recirc_id,
                              ntohll(get_32aligned_be64(
                                         &cookie.controller.rule_cookie)),
                              cookie.controller.controller_id,
                              cookie.controller.max_len);
                ds_put_char(ds, ')');
            } else {
                userdata_unspec = true;
            }
        }

        if (userdata_unspec) {
            size_t i;
            ds_put_format(ds, ",userdata(");
            for (i = 0; i < userdata_len; i++) {
                ds_put_format(ds, "%02x", userdata[i]);
            }
            ds_put_char(ds, ')');
        }
    }

    if (a[OVS_USERSPACE_ATTR_ACTIONS]) {
        ds_put_cstr(ds, ",actions");
    }

    tunnel_out_port_attr = a[OVS_USERSPACE_ATTR_EGRESS_TUN_PORT];
    if (tunnel_out_port_attr) {
        ds_put_format(ds, ",tunnel_out_port=");
        odp_portno_name_format(portno_names,
                               nl_attr_get_odp_port(tunnel_out_port_attr), ds);
    }

    ds_put_char(ds, ')');
}

static void
format_vlan_tci(struct ds *ds, ovs_be16 tci, ovs_be16 mask, bool verbose)
{
    if (verbose || vlan_tci_to_vid(tci) || vlan_tci_to_vid(mask)) {
        ds_put_format(ds, "vid=%"PRIu16, vlan_tci_to_vid(tci));
        if (vlan_tci_to_vid(mask) != VLAN_VID_MASK) { /* Partially masked. */
            ds_put_format(ds, "/0x%"PRIx16, vlan_tci_to_vid(mask));
        };
        ds_put_char(ds, ',');
    }
    if (verbose || vlan_tci_to_pcp(tci) || vlan_tci_to_pcp(mask)) {
        ds_put_format(ds, "pcp=%d", vlan_tci_to_pcp(tci));
        if (vlan_tci_to_pcp(mask) != (VLAN_PCP_MASK >> VLAN_PCP_SHIFT)) {
            ds_put_format(ds, "/0x%x", vlan_tci_to_pcp(mask));
        }
        ds_put_char(ds, ',');
    }
    if (!(tci & htons(VLAN_CFI))) {
        ds_put_cstr(ds, "cfi=0");
        ds_put_char(ds, ',');
    }
    ds_chomp(ds, ',');
}

static void
format_mpls_lse(struct ds *ds, ovs_be32 mpls_lse)
{
    ds_put_format(ds, "label=%"PRIu32",tc=%d,ttl=%d,bos=%d",
                  mpls_lse_to_label(mpls_lse),
                  mpls_lse_to_tc(mpls_lse),
                  mpls_lse_to_ttl(mpls_lse),
                  mpls_lse_to_bos(mpls_lse));
}

static void
format_mpls(struct ds *ds, const struct ovs_key_mpls *mpls_key,
            const struct ovs_key_mpls *mpls_mask, int n)
{
    for (int i = 0; i < n; i++) {
        ovs_be32 key = mpls_key[i].mpls_lse;

        if (mpls_mask == NULL) {
            format_mpls_lse(ds, key);
        } else {
            ovs_be32 mask = mpls_mask[i].mpls_lse;

            ds_put_format(ds, "label=%"PRIu32"/0x%x,tc=%d/%x,ttl=%d/0x%x,bos=%d/%x",
                          mpls_lse_to_label(key), mpls_lse_to_label(mask),
                          mpls_lse_to_tc(key), mpls_lse_to_tc(mask),
                          mpls_lse_to_ttl(key), mpls_lse_to_ttl(mask),
                          mpls_lse_to_bos(key), mpls_lse_to_bos(mask));
        }
        ds_put_char(ds, ',');
    }
    ds_chomp(ds, ',');
}

static void
format_odp_recirc_action(struct ds *ds, uint32_t recirc_id)
{
    ds_put_format(ds, "recirc(%#"PRIx32")", recirc_id);
}

static void
format_odp_hash_action(struct ds *ds, const struct ovs_action_hash *hash_act)
{
    ds_put_format(ds, "hash(");

    if (hash_act->hash_alg == OVS_HASH_ALG_L4) {
        ds_put_format(ds, "l4(%"PRIu32")", hash_act->hash_basis);
    } else if (hash_act->hash_alg == OVS_HASH_ALG_SYM_L4) {
        ds_put_format(ds, "sym_l4(%"PRIu32")", hash_act->hash_basis);
    } else {
        ds_put_format(ds, "Unknown hash algorithm(%"PRIu32")",
                      hash_act->hash_alg);
    }
    ds_put_format(ds, ")");
}

static const void *
format_udp_tnl_push_header(struct ds *ds, const struct udp_header *udp)
{
    ds_put_format(ds, "udp(src=%"PRIu16",dst=%"PRIu16",csum=0x%"PRIx16"),",
                  ntohs(udp->udp_src), ntohs(udp->udp_dst),
                  ntohs(udp->udp_csum));

    return udp + 1;
}

static void
format_odp_tnl_push_header(struct ds *ds, struct ovs_action_push_tnl *data)
{
    const struct eth_header *eth;
    const void *l3;
    const void *l4;
    const struct udp_header *udp;

    eth = (const struct eth_header *)data->header;

    l3 = eth + 1;

    /* Ethernet */
    ds_put_format(ds, "header(size=%"PRIu32",type=%"PRIu32",eth(dst=",
                  data->header_len, data->tnl_type);
    ds_put_format(ds, ETH_ADDR_FMT, ETH_ADDR_ARGS(eth->eth_dst));
    ds_put_format(ds, ",src=");
    ds_put_format(ds, ETH_ADDR_FMT, ETH_ADDR_ARGS(eth->eth_src));
    ds_put_format(ds, ",dl_type=0x%04"PRIx16"),", ntohs(eth->eth_type));

    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        /* IPv4 */
        const struct ip_header *ip = l3;
        ds_put_format(ds, "ipv4(src="IP_FMT",dst="IP_FMT",proto=%"PRIu8
                      ",tos=%#"PRIx8",ttl=%"PRIu8",frag=0x%"PRIx16"),",
                      IP_ARGS(get_16aligned_be32(&ip->ip_src)),
                      IP_ARGS(get_16aligned_be32(&ip->ip_dst)),
                      ip->ip_proto, ip->ip_tos,
                      ip->ip_ttl,
                      ntohs(ip->ip_frag_off));
        l4 = (ip + 1);
    } else {
        const struct ovs_16aligned_ip6_hdr *ip6 = l3;
        struct in6_addr src, dst;
        memcpy(&src, &ip6->ip6_src, sizeof src);
        memcpy(&dst, &ip6->ip6_dst, sizeof dst);
        uint32_t ipv6_flow = ntohl(get_16aligned_be32(&ip6->ip6_flow));

        ds_put_format(ds, "ipv6(src=");
        ipv6_format_addr(&src, ds);
        ds_put_format(ds, ",dst=");
        ipv6_format_addr(&dst, ds);
        ds_put_format(ds, ",label=%i,proto=%"PRIu8",tclass=0x%"PRIx32
                          ",hlimit=%"PRIu8"),",
                      ipv6_flow & IPV6_LABEL_MASK, ip6->ip6_nxt,
                      (ipv6_flow >> 20) & 0xff, ip6->ip6_hlim);
        l4 = (ip6 + 1);
    }

    udp = (const struct udp_header *) l4;

    if (data->tnl_type == OVS_VPORT_TYPE_VXLAN) {
        const struct vxlanhdr *vxh;

        vxh = format_udp_tnl_push_header(ds, udp);

        ds_put_format(ds, "vxlan(flags=0x%"PRIx32",vni=0x%"PRIx32")",
                      ntohl(get_16aligned_be32(&vxh->vx_flags)),
                      ntohl(get_16aligned_be32(&vxh->vx_vni)) >> 8);
    } else if (data->tnl_type == OVS_VPORT_TYPE_GENEVE) {
        const struct genevehdr *gnh;

        gnh = format_udp_tnl_push_header(ds, udp);

        ds_put_format(ds, "geneve(%s%svni=0x%"PRIx32,
                      gnh->oam ? "oam," : "",
                      gnh->critical ? "crit," : "",
                      ntohl(get_16aligned_be32(&gnh->vni)) >> 8);

        if (gnh->opt_len) {
            ds_put_cstr(ds, ",options(");
            format_geneve_opts(gnh->options, NULL, gnh->opt_len * 4,
                               ds, false);
            ds_put_char(ds, ')');
        }

        ds_put_char(ds, ')');
    } else if (data->tnl_type == OVS_VPORT_TYPE_GRE ||
               data->tnl_type == OVS_VPORT_TYPE_IP6GRE) {
        const struct gre_base_hdr *greh;
        ovs_16aligned_be32 *options;

        greh = (const struct gre_base_hdr *) l4;

        ds_put_format(ds, "gre((flags=0x%"PRIx16",proto=0x%"PRIx16")",
                           ntohs(greh->flags), ntohs(greh->protocol));
        options = (ovs_16aligned_be32 *)(greh + 1);
        if (greh->flags & htons(GRE_CSUM)) {
            ds_put_format(ds, ",csum=0x%"PRIx16, ntohs(*((ovs_be16 *)options)));
            options++;
        }
        if (greh->flags & htons(GRE_KEY)) {
            ds_put_format(ds, ",key=0x%"PRIx32, ntohl(get_16aligned_be32(options)));
            options++;
        }
        if (greh->flags & htons(GRE_SEQ)) {
            ds_put_format(ds, ",seq=0x%"PRIx32, ntohl(get_16aligned_be32(options)));
            options++;
        }
        ds_put_format(ds, ")");
    } else if (data->tnl_type == OVS_VPORT_TYPE_ERSPAN ||
               data->tnl_type == OVS_VPORT_TYPE_IP6ERSPAN) {
        const struct gre_base_hdr *greh;
        const struct erspan_base_hdr *ersh;

        greh = (const struct gre_base_hdr *) l4;
        ersh = ERSPAN_HDR(greh);

        if (ersh->ver == 1) {
            ovs_16aligned_be32 *index = ALIGNED_CAST(ovs_16aligned_be32 *,
                                                     ersh + 1);
            ds_put_format(ds, "erspan(ver=1,sid=0x%"PRIx16",idx=0x%"PRIx32")",
                          get_sid(ersh), ntohl(get_16aligned_be32(index)));
        } else if (ersh->ver == 2) {
            struct erspan_md2 *md2 = ALIGNED_CAST(struct erspan_md2 *,
                                                  ersh + 1);
            ds_put_format(ds, "erspan(ver=2,sid=0x%"PRIx16
                          ",dir=%"PRIu8",hwid=0x%"PRIx8")",
                          get_sid(ersh), md2->dir, get_hwid(md2));
        } else {
            VLOG_WARN("%s Invalid ERSPAN version %d\n", __func__, ersh->ver);
        }
    } else if (data->tnl_type == OVS_VPORT_TYPE_GTPU) {
        const struct gtpuhdr *gtph;

        gtph = format_udp_tnl_push_header(ds, udp);

        ds_put_format(ds, "gtpu(flags=0x%"PRIx8
                          ",msgtype=%"PRIu8",teid=0x%"PRIx32")",
                      gtph->md.flags, gtph->md.msgtype,
                      ntohl(get_16aligned_be32(&gtph->teid)));
    }

    ds_put_format(ds, ")");
}

static void
format_odp_tnl_push_action(struct ds *ds, const struct nlattr *attr,
                           const struct hmap *portno_names)
{
    struct ovs_action_push_tnl *data;

    data = (struct ovs_action_push_tnl *) nl_attr_get(attr);

    ds_put_cstr(ds, "tnl_push(tnl_port(");
    odp_portno_name_format(portno_names, data->tnl_port, ds);
    ds_put_cstr(ds, "),");
    format_odp_tnl_push_header(ds, data);
    ds_put_format(ds, ",out_port(");
    odp_portno_name_format(portno_names, data->out_port, ds);
    ds_put_cstr(ds, "))");
}

static const struct nl_policy ovs_nat_policy[] = {
    [OVS_NAT_ATTR_SRC] = { .type = NL_A_FLAG, .optional = true, },
    [OVS_NAT_ATTR_DST] = { .type = NL_A_FLAG, .optional = true, },
    [OVS_NAT_ATTR_IP_MIN] = { .type = NL_A_UNSPEC, .optional = true,
                              .min_len = sizeof(struct in_addr),
                              .max_len = sizeof(struct in6_addr)},
    [OVS_NAT_ATTR_IP_MAX] = { .type = NL_A_UNSPEC, .optional = true,
                              .min_len = sizeof(struct in_addr),
                              .max_len = sizeof(struct in6_addr)},
    [OVS_NAT_ATTR_PROTO_MIN] = { .type = NL_A_U16, .optional = true, },
    [OVS_NAT_ATTR_PROTO_MAX] = { .type = NL_A_U16, .optional = true, },
    [OVS_NAT_ATTR_PERSISTENT] = { .type = NL_A_FLAG, .optional = true, },
    [OVS_NAT_ATTR_PROTO_HASH] = { .type = NL_A_FLAG, .optional = true, },
    [OVS_NAT_ATTR_PROTO_RANDOM] = { .type = NL_A_FLAG, .optional = true, },
};

static void
format_odp_ct_nat(struct ds *ds, const struct nlattr *attr)
{
    struct nlattr *a[ARRAY_SIZE(ovs_nat_policy)];
    size_t addr_len;
    ovs_be32 ip_min, ip_max;
    struct in6_addr ip6_min, ip6_max;
    uint16_t proto_min, proto_max;

    if (!nl_parse_nested(attr, ovs_nat_policy, a, ARRAY_SIZE(a))) {
        ds_put_cstr(ds, "nat(error: nl_parse_nested() failed.)");
        return;
    }
    /* If no type, then nothing else either. */
    if (!(a[OVS_NAT_ATTR_SRC] || a[OVS_NAT_ATTR_DST])
        && (a[OVS_NAT_ATTR_IP_MIN] || a[OVS_NAT_ATTR_IP_MAX]
            || a[OVS_NAT_ATTR_PROTO_MIN] || a[OVS_NAT_ATTR_PROTO_MAX]
            || a[OVS_NAT_ATTR_PERSISTENT] || a[OVS_NAT_ATTR_PROTO_HASH]
            || a[OVS_NAT_ATTR_PROTO_RANDOM])) {
        ds_put_cstr(ds, "nat(error: options allowed only with \"src\" or \"dst\")");
        return;
    }
    /* Both SNAT & DNAT may not be specified. */
    if (a[OVS_NAT_ATTR_SRC] && a[OVS_NAT_ATTR_DST]) {
        ds_put_cstr(ds, "nat(error: Only one of \"src\" or \"dst\" may be present.)");
        return;
    }
    /* proto may not appear without ip. */
    if (!a[OVS_NAT_ATTR_IP_MIN] && a[OVS_NAT_ATTR_PROTO_MIN]) {
        ds_put_cstr(ds, "nat(error: proto but no IP.)");
        return;
    }
    /* MAX may not appear without MIN. */
    if ((!a[OVS_NAT_ATTR_IP_MIN] && a[OVS_NAT_ATTR_IP_MAX])
        || (!a[OVS_NAT_ATTR_PROTO_MIN] && a[OVS_NAT_ATTR_PROTO_MAX])) {
        ds_put_cstr(ds, "nat(error: range max without min.)");
        return;
    }
    /* Address sizes must match. */
    if ((a[OVS_NAT_ATTR_IP_MIN]
         && (nl_attr_get_size(a[OVS_NAT_ATTR_IP_MIN]) != sizeof(ovs_be32) &&
             nl_attr_get_size(a[OVS_NAT_ATTR_IP_MIN]) != sizeof(struct in6_addr)))
        || (a[OVS_NAT_ATTR_IP_MIN] && a[OVS_NAT_ATTR_IP_MAX]
            && (nl_attr_get_size(a[OVS_NAT_ATTR_IP_MIN])
                != nl_attr_get_size(a[OVS_NAT_ATTR_IP_MAX])))) {
        ds_put_cstr(ds, "nat(error: IP address sizes do not match)");
        return;
    }

    addr_len = a[OVS_NAT_ATTR_IP_MIN]
        ? nl_attr_get_size(a[OVS_NAT_ATTR_IP_MIN]) : 0;
    ip_min = addr_len == sizeof(ovs_be32) && a[OVS_NAT_ATTR_IP_MIN]
        ? nl_attr_get_be32(a[OVS_NAT_ATTR_IP_MIN]) : 0;
    ip_max = addr_len == sizeof(ovs_be32) && a[OVS_NAT_ATTR_IP_MAX]
        ? nl_attr_get_be32(a[OVS_NAT_ATTR_IP_MAX]) : 0;
    if (addr_len == sizeof ip6_min) {
        ip6_min = a[OVS_NAT_ATTR_IP_MIN]
            ? *(struct in6_addr *)nl_attr_get(a[OVS_NAT_ATTR_IP_MIN])
            : in6addr_any;
        ip6_max = a[OVS_NAT_ATTR_IP_MAX]
            ? *(struct in6_addr *)nl_attr_get(a[OVS_NAT_ATTR_IP_MAX])
            : in6addr_any;
    }
    proto_min = a[OVS_NAT_ATTR_PROTO_MIN]
        ? nl_attr_get_u16(a[OVS_NAT_ATTR_PROTO_MIN]) : 0;
    proto_max = a[OVS_NAT_ATTR_PROTO_MAX]
        ? nl_attr_get_u16(a[OVS_NAT_ATTR_PROTO_MAX]) : 0;

    if ((addr_len == sizeof(ovs_be32)
         && ip_max && ntohl(ip_min) > ntohl(ip_max))
        || (addr_len == sizeof(struct in6_addr)
            && !ipv6_mask_is_any(&ip6_max)
            && memcmp(&ip6_min, &ip6_max, sizeof ip6_min) > 0)
        || (proto_max && proto_min > proto_max)) {
        ds_put_cstr(ds, "nat(range error)");
        return;
    }

    ds_put_cstr(ds, "nat");
    if (a[OVS_NAT_ATTR_SRC] || a[OVS_NAT_ATTR_DST]) {
        ds_put_char(ds, '(');
        if (a[OVS_NAT_ATTR_SRC]) {
            ds_put_cstr(ds, "src");
        } else if (a[OVS_NAT_ATTR_DST]) {
            ds_put_cstr(ds, "dst");
        }

        if (addr_len > 0) {
            ds_put_cstr(ds, "=");

            if (addr_len == sizeof ip_min) {
                ds_put_format(ds, IP_FMT, IP_ARGS(ip_min));

                if (ip_max && ip_max != ip_min) {
                    ds_put_format(ds, "-"IP_FMT, IP_ARGS(ip_max));
                }
            } else if (addr_len == sizeof ip6_min) {
                ipv6_format_addr_bracket(&ip6_min, ds, proto_min);

                if (!ipv6_mask_is_any(&ip6_max) &&
                    memcmp(&ip6_max, &ip6_min, sizeof ip6_max) != 0) {
                    ds_put_char(ds, '-');
                    ipv6_format_addr_bracket(&ip6_max, ds, proto_min);
                }
            }
            if (proto_min) {
                ds_put_format(ds, ":%"PRIu16, proto_min);

                if (proto_max && proto_max != proto_min) {
                    ds_put_format(ds, "-%"PRIu16, proto_max);
                }
            }
        }
        ds_put_char(ds, ',');
        if (a[OVS_NAT_ATTR_PERSISTENT]) {
            ds_put_cstr(ds, "persistent,");
        }
        if (a[OVS_NAT_ATTR_PROTO_HASH]) {
            ds_put_cstr(ds, "hash,");
        }
        if (a[OVS_NAT_ATTR_PROTO_RANDOM]) {
            ds_put_cstr(ds, "random,");
        }
        ds_chomp(ds, ',');
        ds_put_char(ds, ')');
    }
}

static const struct nl_policy ovs_conntrack_policy[] = {
    [OVS_CT_ATTR_COMMIT] = { .type = NL_A_FLAG, .optional = true, },
    [OVS_CT_ATTR_FORCE_COMMIT] = { .type = NL_A_FLAG, .optional = true, },
    [OVS_CT_ATTR_ZONE] = { .type = NL_A_U16, .optional = true, },
    [OVS_CT_ATTR_MARK] = { .type = NL_A_UNSPEC, .optional = true,
                           .min_len = sizeof(uint32_t) * 2 },
    [OVS_CT_ATTR_LABELS] = { .type = NL_A_UNSPEC, .optional = true,
                             .min_len = sizeof(struct ovs_key_ct_labels) * 2 },
    [OVS_CT_ATTR_HELPER] = { .type = NL_A_STRING, .optional = true,
                             .min_len = 1, .max_len = 16 },
    [OVS_CT_ATTR_NAT] = { .type = NL_A_UNSPEC, .optional = true },
    [OVS_CT_ATTR_TIMEOUT] = { .type = NL_A_STRING, .optional = true,
                              .min_len = 1, .max_len = 32 },
};

static void
format_odp_conntrack_action(struct ds *ds, const struct nlattr *attr)
{
    struct nlattr *a[ARRAY_SIZE(ovs_conntrack_policy)];
    const struct {
        ovs_32aligned_u128 value;
        ovs_32aligned_u128 mask;
    } *label;
    const uint32_t *mark;
    const char *helper, *timeout;
    uint16_t zone;
    bool commit, force;
    const struct nlattr *nat;

    if (!nl_parse_nested(attr, ovs_conntrack_policy, a, ARRAY_SIZE(a))) {
        ds_put_cstr(ds, "ct(error)");
        return;
    }

    commit = a[OVS_CT_ATTR_COMMIT] ? true : false;
    force = a[OVS_CT_ATTR_FORCE_COMMIT] ? true : false;
    zone = a[OVS_CT_ATTR_ZONE] ? nl_attr_get_u16(a[OVS_CT_ATTR_ZONE]) : 0;
    mark = a[OVS_CT_ATTR_MARK] ? nl_attr_get(a[OVS_CT_ATTR_MARK]) : NULL;
    label = a[OVS_CT_ATTR_LABELS] ? nl_attr_get(a[OVS_CT_ATTR_LABELS]): NULL;
    helper = a[OVS_CT_ATTR_HELPER] ? nl_attr_get(a[OVS_CT_ATTR_HELPER]) : NULL;
    timeout = a[OVS_CT_ATTR_TIMEOUT] ?
                nl_attr_get(a[OVS_CT_ATTR_TIMEOUT]) : NULL;
    nat = a[OVS_CT_ATTR_NAT];

    ds_put_format(ds, "ct");
    if (commit || force || zone || mark || label || helper || timeout || nat) {
        ds_put_cstr(ds, "(");
        if (commit) {
            ds_put_format(ds, "commit,");
        }
        if (force) {
            ds_put_format(ds, "force_commit,");
        }
        if (zone) {
            ds_put_format(ds, "zone=%"PRIu16",", zone);
        }
        if (mark) {
            ds_put_format(ds, "mark=%#"PRIx32"/%#"PRIx32",", *mark,
                          *(mark + 1));
        }
        if (label) {
            ds_put_format(ds, "label=");
            format_u128(ds, &label->value, &label->mask, true);
            ds_put_char(ds, ',');
        }
        if (helper) {
            ds_put_format(ds, "helper=%s,", helper);
        }
        if (timeout) {
            ds_put_format(ds, "timeout=%s", timeout);
        }
        if (nat) {
            format_odp_ct_nat(ds, nat);
        }
        ds_chomp(ds, ',');
        ds_put_cstr(ds, ")");
    }
}

static const struct attr_len_tbl
ovs_nsh_key_attr_lens[OVS_NSH_KEY_ATTR_MAX + 1] = {
    [OVS_NSH_KEY_ATTR_BASE]     = { .len = 8 },
    [OVS_NSH_KEY_ATTR_MD1]      = { .len = 16 },
    [OVS_NSH_KEY_ATTR_MD2]      = { .len = ATTR_LEN_VARIABLE },
};

static void
format_odp_set_nsh(struct ds *ds, const struct nlattr *attr)
{
    unsigned int left;
    const struct nlattr *a;
    struct ovs_key_nsh nsh;
    struct ovs_key_nsh nsh_mask;

    memset(&nsh, 0, sizeof nsh);
    memset(&nsh_mask, 0xff, sizeof nsh_mask);

    NL_NESTED_FOR_EACH (a, left, attr) {
        enum ovs_nsh_key_attr type = nl_attr_type(a);
        size_t len = nl_attr_get_size(a);

        if (type >= OVS_NSH_KEY_ATTR_MAX) {
            return;
        }

        int expected_len = ovs_nsh_key_attr_lens[type].len;
        if ((expected_len != ATTR_LEN_VARIABLE) && (len != 2 * expected_len)) {
            return;
        }

        switch (type) {
        case OVS_NSH_KEY_ATTR_UNSPEC:
            break;
        case OVS_NSH_KEY_ATTR_BASE: {
            const struct ovs_nsh_key_base *base = nl_attr_get(a);
            const struct ovs_nsh_key_base *base_mask = base + 1;
            memcpy(&nsh, base, sizeof(*base));
            memcpy(&nsh_mask, base_mask, sizeof(*base_mask));
            break;
        }
        case OVS_NSH_KEY_ATTR_MD1: {
            const struct ovs_nsh_key_md1 *md1 = nl_attr_get(a);
            const struct ovs_nsh_key_md1 *md1_mask = md1 + 1;
            memcpy(&nsh.context, &md1->context, sizeof(*md1));
            memcpy(&nsh_mask.context, &md1_mask->context, sizeof(*md1_mask));
            break;
        }
        case OVS_NSH_KEY_ATTR_MD2:
        case __OVS_NSH_KEY_ATTR_MAX:
        default:
            /* No support for matching other metadata formats yet. */
            break;
        }
    }

    ds_put_cstr(ds, "set(nsh(");
    format_nsh_key_mask(ds, &nsh, &nsh_mask);
    ds_put_cstr(ds, "))");
}

static void
format_odp_check_pkt_len_action(struct ds *ds, const struct nlattr *attr,
                                const struct hmap *portno_names OVS_UNUSED)
{
    static const struct nl_policy ovs_cpl_policy[] = {
        [OVS_CHECK_PKT_LEN_ATTR_PKT_LEN] = { .type = NL_A_U16 },
        [OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER] = { .type = NL_A_NESTED },
        [OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL]
            = { .type = NL_A_NESTED },
    };
    struct nlattr *a[ARRAY_SIZE(ovs_cpl_policy)];
    ds_put_cstr(ds, "check_pkt_len");
    if (!nl_parse_nested(attr, ovs_cpl_policy, a, ARRAY_SIZE(a))) {
        ds_put_cstr(ds, "(error)");
        return;
    }

    if (!a[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER] ||
        !a[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL]) {
        ds_put_cstr(ds, "(error)");
        return;
    }

    uint16_t pkt_len = nl_attr_get_u16(a[OVS_CHECK_PKT_LEN_ATTR_PKT_LEN]);
    ds_put_format(ds, "(size=%u,gt(", pkt_len);
    const struct nlattr *acts;
    acts = a[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER];
    format_odp_actions(ds, nl_attr_get(acts), nl_attr_get_size(acts),
                       portno_names);

    ds_put_cstr(ds, "),le(");
    acts = a[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL];
    format_odp_actions(ds, nl_attr_get(acts), nl_attr_get_size(acts),
                           portno_names);
    ds_put_cstr(ds, "))");
}

static void
format_odp_action(struct ds *ds, const struct nlattr *a,
                  const struct hmap *portno_names)
{
    int expected_len;
    enum ovs_action_attr type = nl_attr_type(a);
    size_t size;

    expected_len = odp_action_len(nl_attr_type(a));
    if (expected_len != ATTR_LEN_VARIABLE &&
        nl_attr_get_size(a) != expected_len) {
        ds_put_format(ds, "bad length %"PRIuSIZE", expected %d for: ",
                      nl_attr_get_size(a), expected_len);
        format_generic_odp_action(ds, a);
        return;
    }

    switch (type) {
    case OVS_ACTION_ATTR_METER:
        ds_put_format(ds, "meter(%"PRIu32")", nl_attr_get_u32(a));
        break;
    case OVS_ACTION_ATTR_OUTPUT:
        odp_portno_name_format(portno_names, nl_attr_get_odp_port(a), ds);
        break;
    case OVS_ACTION_ATTR_LB_OUTPUT:
        ds_put_format(ds, "lb_output(%"PRIu32")", nl_attr_get_u32(a));
        break;
    case OVS_ACTION_ATTR_TRUNC: {
        const struct ovs_action_trunc *trunc =
                       nl_attr_get_unspec(a, sizeof *trunc);

        ds_put_format(ds, "trunc(%"PRIu32")", trunc->max_len);
        break;
    }
    case OVS_ACTION_ATTR_TUNNEL_POP:
        ds_put_cstr(ds, "tnl_pop(");
        odp_portno_name_format(portno_names, nl_attr_get_odp_port(a), ds);
        ds_put_char(ds, ')');
        break;
    case OVS_ACTION_ATTR_TUNNEL_PUSH:
        format_odp_tnl_push_action(ds, a, portno_names);
        break;
    case OVS_ACTION_ATTR_USERSPACE:
        format_odp_userspace_action(ds, a, portno_names);
        break;
    case OVS_ACTION_ATTR_RECIRC:
        format_odp_recirc_action(ds, nl_attr_get_u32(a));
        break;
    case OVS_ACTION_ATTR_HASH:
        format_odp_hash_action(ds, nl_attr_get(a));
        break;
    case OVS_ACTION_ATTR_SET_MASKED:
        a = nl_attr_get(a);
        /* OVS_KEY_ATTR_NSH is nested attribute, so it needs special process */
        if (nl_attr_type(a) == OVS_KEY_ATTR_NSH) {
            format_odp_set_nsh(ds, a);
            break;
        }
        size = nl_attr_get_size(a) / 2;
        ds_put_cstr(ds, "set(");

        /* Masked set action not supported for tunnel key, which is bigger. */
        if (size <= sizeof(struct ovs_key_ipv6)) {
            struct nlattr attr[1 + DIV_ROUND_UP(sizeof(struct ovs_key_ipv6),
                                                sizeof(struct nlattr))];
            struct nlattr mask[1 + DIV_ROUND_UP(sizeof(struct ovs_key_ipv6),
                                                sizeof(struct nlattr))];

            mask->nla_type = attr->nla_type = nl_attr_type(a);
            mask->nla_len = attr->nla_len = NLA_HDRLEN + size;
            memcpy(attr + 1, (char *)(a + 1), size);
            memcpy(mask + 1, (char *)(a + 1) + size, size);
            format_odp_key_attr(attr, mask, NULL, ds, false);
        } else {
            format_odp_key_attr(a, NULL, NULL, ds, false);
        }
        ds_put_cstr(ds, ")");
        break;
    case OVS_ACTION_ATTR_SET:
        ds_put_cstr(ds, "set(");
        format_odp_key_attr(nl_attr_get(a), NULL, NULL, ds, true);
        ds_put_cstr(ds, ")");
        break;
    case OVS_ACTION_ATTR_PUSH_ETH: {
        const struct ovs_action_push_eth *eth = nl_attr_get(a);
        ds_put_format(ds, "push_eth(src="ETH_ADDR_FMT",dst="ETH_ADDR_FMT")",
                      ETH_ADDR_ARGS(eth->addresses.eth_src),
                      ETH_ADDR_ARGS(eth->addresses.eth_dst));
        break;
    }
    case OVS_ACTION_ATTR_POP_ETH:
        ds_put_cstr(ds, "pop_eth");
        break;
    case OVS_ACTION_ATTR_PUSH_VLAN: {
        const struct ovs_action_push_vlan *vlan = nl_attr_get(a);
        ds_put_cstr(ds, "push_vlan(");
        if (vlan->vlan_tpid != htons(ETH_TYPE_VLAN)) {
            ds_put_format(ds, "tpid=0x%04"PRIx16",", ntohs(vlan->vlan_tpid));
        }
        format_vlan_tci(ds, vlan->vlan_tci, OVS_BE16_MAX, false);
        ds_put_char(ds, ')');
        break;
    }
    case OVS_ACTION_ATTR_POP_VLAN:
        ds_put_cstr(ds, "pop_vlan");
        break;
    case OVS_ACTION_ATTR_PUSH_MPLS: {
        const struct ovs_action_push_mpls *mpls = nl_attr_get(a);
        ds_put_cstr(ds, "push_mpls(");
        format_mpls_lse(ds, mpls->mpls_lse);
        ds_put_format(ds, ",eth_type=0x%"PRIx16")", ntohs(mpls->mpls_ethertype));
        break;
    }
    case OVS_ACTION_ATTR_POP_MPLS: {
        ovs_be16 ethertype = nl_attr_get_be16(a);
        ds_put_format(ds, "pop_mpls(eth_type=0x%"PRIx16")", ntohs(ethertype));
        break;
    }
    case OVS_ACTION_ATTR_SAMPLE:
        format_odp_sample_action(ds, a, portno_names);
        break;
    case OVS_ACTION_ATTR_CT:
        format_odp_conntrack_action(ds, a);
        break;
    case OVS_ACTION_ATTR_CT_CLEAR:
        ds_put_cstr(ds, "ct_clear");
        break;
    case OVS_ACTION_ATTR_CLONE:
        format_odp_clone_action(ds, a, portno_names);
        break;
    case OVS_ACTION_ATTR_PUSH_NSH: {
        uint32_t buffer[NSH_HDR_MAX_LEN / 4];
        struct nsh_hdr *nsh_hdr = ALIGNED_CAST(struct nsh_hdr *, buffer);
        nsh_reset_ver_flags_ttl_len(nsh_hdr);
        odp_nsh_hdr_from_attr(nl_attr_get(a), nsh_hdr, NSH_HDR_MAX_LEN);
        format_odp_push_nsh_action(ds, nsh_hdr);
        break;
    }
    case OVS_ACTION_ATTR_POP_NSH:
        ds_put_cstr(ds, "pop_nsh()");
        break;
    case OVS_ACTION_ATTR_CHECK_PKT_LEN:
        format_odp_check_pkt_len_action(ds, a, portno_names);
        break;
    case OVS_ACTION_ATTR_DROP:
        ds_put_cstr(ds, "drop");
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
                   size_t actions_len, const struct hmap *portno_names)
{
    if (actions_len) {
        const struct nlattr *a;
        unsigned int left;

        NL_ATTR_FOR_EACH (a, left, actions, actions_len) {
            if (a != actions) {
                ds_put_char(ds, ',');
            }
            format_odp_action(ds, a, portno_names);
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

/* Separate out parse_odp_userspace_action() function. */
static int
parse_odp_userspace_action(const char *s, struct ofpbuf *actions)
{
    uint32_t pid;
    struct user_action_cookie cookie;
    struct ofpbuf buf;
    odp_port_t tunnel_out_port;
    int n = -1;
    void *user_data = NULL;
    size_t user_data_size = 0;
    bool include_actions = false;
    int res;

    if (!ovs_scan(s, "userspace(pid=%"SCNi32"%n", &pid, &n)) {
        return -EINVAL;
    }

    ofpbuf_init(&buf, 16);
    memset(&cookie, 0, sizeof cookie);

    user_data = &cookie;
    user_data_size = sizeof cookie;
    {
        uint32_t output;
        uint32_t probability;
        uint32_t collector_set_id;
        uint32_t obs_domain_id;
        uint32_t obs_point_id;

        /* USER_ACTION_COOKIE_CONTROLLER. */
        uint8_t dont_send;
        uint8_t continuation;
        uint16_t reason;
        uint32_t recirc_id;
        uint64_t rule_cookie;
        uint16_t controller_id;
        uint16_t max_len;

        int vid, pcp;
        int n1 = -1;
        if (ovs_scan(&s[n], ",sFlow(vid=%i,"
                     "pcp=%i,output=%"SCNi32")%n",
                     &vid, &pcp, &output, &n1)) {
            uint16_t tci;

            n += n1;
            tci = vid | (pcp << VLAN_PCP_SHIFT);
            if (tci) {
                tci |= VLAN_CFI;
            }

            cookie.type = USER_ACTION_COOKIE_SFLOW;
            cookie.ofp_in_port = OFPP_NONE;
            cookie.ofproto_uuid = UUID_ZERO;
            cookie.sflow.vlan_tci = htons(tci);
            cookie.sflow.output = output;
        } else if (ovs_scan(&s[n], ",slow_path(%n",
                            &n1)) {
            n += n1;
            cookie.type = USER_ACTION_COOKIE_SLOW_PATH;
            cookie.ofp_in_port = OFPP_NONE;
            cookie.ofproto_uuid = UUID_ZERO;
            cookie.slow_path.reason = 0;

            res = parse_odp_flags(&s[n], slow_path_reason_to_string,
                                  &cookie.slow_path.reason,
                                  SLOW_PATH_REASON_MASK, NULL);
            if (res < 0 || s[n + res] != ')') {
                goto out;
            }
            n += res + 1;
        } else if (ovs_scan(&s[n], ",flow_sample(probability=%"SCNi32","
                            "collector_set_id=%"SCNi32","
                            "obs_domain_id=%"SCNi32","
                            "obs_point_id=%"SCNi32","
                            "output_port=%"SCNi32"%n",
                            &probability, &collector_set_id,
                            &obs_domain_id, &obs_point_id,
                            &output, &n1)) {
            n += n1;

            cookie.type = USER_ACTION_COOKIE_FLOW_SAMPLE;
            cookie.ofp_in_port = OFPP_NONE;
            cookie.ofproto_uuid = UUID_ZERO;
            cookie.flow_sample.probability = probability;
            cookie.flow_sample.collector_set_id = collector_set_id;
            cookie.flow_sample.obs_domain_id = obs_domain_id;
            cookie.flow_sample.obs_point_id = obs_point_id;
            cookie.flow_sample.output_odp_port = u32_to_odp(output);

            if (ovs_scan(&s[n], ",ingress%n", &n1)) {
                cookie.flow_sample.direction = NX_ACTION_SAMPLE_INGRESS;
                n += n1;
            } else if (ovs_scan(&s[n], ",egress%n", &n1)) {
                cookie.flow_sample.direction = NX_ACTION_SAMPLE_EGRESS;
                n += n1;
            } else {
                cookie.flow_sample.direction = NX_ACTION_SAMPLE_DEFAULT;
            }
            if (s[n] != ')') {
                res = -EINVAL;
                goto out;
            }
            n++;
        } else if (ovs_scan(&s[n], ",ipfix(output_port=%"SCNi32")%n",
                            &output, &n1) ) {
            n += n1;
            cookie.type = USER_ACTION_COOKIE_IPFIX;
            cookie.ofp_in_port = OFPP_NONE;
            cookie.ofproto_uuid = UUID_ZERO;
            cookie.ipfix.output_odp_port = u32_to_odp(output);
        } else if (ovs_scan(&s[n], ",controller(reason=%"SCNu16
                              ",dont_send=%"SCNu8
                              ",continuation=%"SCNu8
                              ",recirc_id=%"SCNu32
                              ",rule_cookie=%"SCNx64
                              ",controller_id=%"SCNu16
                              ",max_len=%"SCNu16")%n",
                              &reason, &dont_send, &continuation, &recirc_id,
                              &rule_cookie, &controller_id, &max_len, &n1)) {
            n += n1;
            cookie.type = USER_ACTION_COOKIE_CONTROLLER;
            cookie.ofp_in_port = OFPP_NONE;
            cookie.ofproto_uuid = UUID_ZERO;
            cookie.controller.dont_send = dont_send ? true : false;
            cookie.controller.continuation = continuation ? true : false;
            cookie.controller.reason = reason;
            cookie.controller.recirc_id = recirc_id;
            put_32aligned_be64(&cookie.controller.rule_cookie,
                               htonll(rule_cookie));
            cookie.controller.controller_id = controller_id;
            cookie.controller.max_len = max_len;
       } else if (ovs_scan(&s[n], ",userdata(%n", &n1)) {
            char *end;

            n += n1;
            end = ofpbuf_put_hex(&buf, &s[n], NULL);
            if (end[0] != ')') {
                res = -EINVAL;
                goto out;
            }
            user_data = buf.data;
            user_data_size = buf.size;
            n = (end + 1) - s;
        }
    }

    {
        int n1 = -1;
        if (ovs_scan(&s[n], ",actions%n", &n1)) {
            n += n1;
            include_actions = true;
        }
    }

    {
        int n1 = -1;
        if (ovs_scan(&s[n], ",tunnel_out_port=%"SCNi32")%n",
                     &tunnel_out_port, &n1)) {
            res = odp_put_userspace_action(pid, user_data, user_data_size,
                                           tunnel_out_port, include_actions,
                                           actions, NULL);
            if (!res) {
                res = n + n1;
            }
            goto out;
        } else if (s[n] == ')') {
            res = odp_put_userspace_action(pid, user_data, user_data_size,
                                           ODPP_NONE, include_actions,
                                           actions, NULL);
            if (!res) {
                res = n + 1;
            }
            goto out;
        }
    }

    {
        struct ovs_action_push_eth push;
        int eth_type = 0;
        int n1 = -1;

        if (ovs_scan(&s[n], "push_eth(src="ETH_ADDR_SCAN_FMT","
                     "dst="ETH_ADDR_SCAN_FMT",type=%i)%n",
                     ETH_ADDR_SCAN_ARGS(push.addresses.eth_src),
                     ETH_ADDR_SCAN_ARGS(push.addresses.eth_dst),
                     &eth_type, &n1)) {

            nl_msg_put_unspec(actions, OVS_ACTION_ATTR_PUSH_ETH,
                              &push, sizeof push);

            res = n + n1;
            goto out;
        }
    }

    if (!strncmp(&s[n], "pop_eth", 7)) {
        nl_msg_put_flag(actions, OVS_ACTION_ATTR_POP_ETH);
        res = 7;
        goto out;
    }

    res = -EINVAL;
out:
    ofpbuf_uninit(&buf);
    return res;
}

static int
ovs_parse_tnl_push(const char *s, struct ovs_action_push_tnl *data)
{
    struct eth_header *eth;
    struct ip_header *ip;
    struct ovs_16aligned_ip6_hdr *ip6;
    struct udp_header *udp;
    struct gre_base_hdr *greh;
    struct erspan_base_hdr *ersh;
    struct erspan_md2 *md2;
    uint16_t gre_proto, gre_flags, dl_type, udp_src, udp_dst, udp_csum, sid;
    ovs_be32 sip, dip;
    uint32_t tnl_type = 0, header_len = 0, ip_len = 0, erspan_idx = 0;
    void *l3, *l4;
    int n = 0;
    uint8_t hwid, dir;
    uint32_t teid;
    uint8_t gtpu_flags, gtpu_msgtype;

    if (!ovs_scan_len(s, &n, "tnl_push(tnl_port(%"SCNi32"),", &data->tnl_port)) {
        return -EINVAL;
    }
    eth = (struct eth_header *) data->header;
    l3 = (struct ip_header *) (eth + 1);
    ip = (struct ip_header *) l3;
    ip6 = (struct ovs_16aligned_ip6_hdr *) l3;
    if (!ovs_scan_len(s, &n, "header(size=%"SCNi32",type=%"SCNi32","
                      "eth(dst="ETH_ADDR_SCAN_FMT",",
                      &data->header_len,
                      &data->tnl_type,
                      ETH_ADDR_SCAN_ARGS(eth->eth_dst))) {
        return -EINVAL;
    }

    if (!ovs_scan_len(s, &n, "src="ETH_ADDR_SCAN_FMT",",
                      ETH_ADDR_SCAN_ARGS(eth->eth_src))) {
        return -EINVAL;
    }
    if (!ovs_scan_len(s, &n, "dl_type=0x%"SCNx16"),", &dl_type)) {
        return -EINVAL;
    }
    eth->eth_type = htons(dl_type);

    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        /* IPv4 */
        uint16_t ip_frag_off;
        memset(ip, 0, sizeof(*ip));
        if (!ovs_scan_len(s, &n, "ipv4(src="IP_SCAN_FMT",dst="IP_SCAN_FMT",proto=%"SCNi8
                          ",tos=%"SCNi8",ttl=%"SCNi8",frag=0x%"SCNx16"),",
                          IP_SCAN_ARGS(&sip),
                          IP_SCAN_ARGS(&dip),
                          &ip->ip_proto, &ip->ip_tos,
                          &ip->ip_ttl, &ip_frag_off)) {
            return -EINVAL;
        }
        put_16aligned_be32(&ip->ip_src, sip);
        put_16aligned_be32(&ip->ip_dst, dip);
        ip->ip_frag_off = htons(ip_frag_off);
        ip->ip_ihl_ver = IP_IHL_VER(5, 4);
        ip_len = sizeof *ip;
        ip->ip_csum = csum(ip, ip_len);
    } else {
        char sip6_s[IPV6_SCAN_LEN + 1];
        char dip6_s[IPV6_SCAN_LEN + 1];
        struct in6_addr sip6, dip6;
        uint8_t tclass;
        uint32_t label;
        if (!ovs_scan_len(s, &n, "ipv6(src="IPV6_SCAN_FMT",dst="IPV6_SCAN_FMT
                             ",label=%i,proto=%"SCNi8",tclass=0x%"SCNx8
                             ",hlimit=%"SCNi8"),",
                             sip6_s, dip6_s, &label, &ip6->ip6_nxt,
                             &tclass, &ip6->ip6_hlim)
            || (label & ~IPV6_LABEL_MASK) != 0
            || inet_pton(AF_INET6, sip6_s, &sip6) != 1
            || inet_pton(AF_INET6, dip6_s, &dip6) != 1) {
            return -EINVAL;
        }
        put_16aligned_be32(&ip6->ip6_flow, htonl(6 << 28) |
                           htonl(tclass << 20) | htonl(label));
        memcpy(&ip6->ip6_src, &sip6, sizeof(ip6->ip6_src));
        memcpy(&ip6->ip6_dst, &dip6, sizeof(ip6->ip6_dst));
        ip_len = sizeof *ip6;
    }

    /* Tunnel header */
    l4 = ((uint8_t *) l3 + ip_len);
    udp = (struct udp_header *) l4;
    greh = (struct gre_base_hdr *) l4;
    if (ovs_scan_len(s, &n, "udp(src=%"SCNi16",dst=%"SCNi16",csum=0x%"SCNx16"),",
                     &udp_src, &udp_dst, &udp_csum)) {
        uint32_t vx_flags, vni;

        udp->udp_src = htons(udp_src);
        udp->udp_dst = htons(udp_dst);
        udp->udp_len = 0;
        udp->udp_csum = htons(udp_csum);

        if (ovs_scan_len(s, &n, "vxlan(flags=0x%"SCNx32",vni=0x%"SCNx32"))",
                         &vx_flags, &vni)) {
            struct vxlanhdr *vxh = (struct vxlanhdr *) (udp + 1);

            put_16aligned_be32(&vxh->vx_flags, htonl(vx_flags));
            put_16aligned_be32(&vxh->vx_vni, htonl(vni << 8));
            tnl_type = OVS_VPORT_TYPE_VXLAN;
            header_len = sizeof *eth + ip_len +
                         sizeof *udp + sizeof *vxh;
        } else if (ovs_scan_len(s, &n, "geneve(")) {
            struct genevehdr *gnh = (struct genevehdr *) (udp + 1);

            memset(gnh, 0, sizeof *gnh);
            header_len = sizeof *eth + ip_len +
                         sizeof *udp + sizeof *gnh;

            if (ovs_scan_len(s, &n, "oam,")) {
                gnh->oam = 1;
            }
            if (ovs_scan_len(s, &n, "crit,")) {
                gnh->critical = 1;
            }
            if (!ovs_scan_len(s, &n, "vni=%"SCNi32, &vni)) {
                return -EINVAL;
            }
            if (ovs_scan_len(s, &n, ",options(")) {
                struct geneve_scan options;
                int len;

                memset(&options, 0, sizeof options);
                len = scan_geneve(s + n, &options, NULL);
                if (!len) {
                    return -EINVAL;
                }

                memcpy(gnh->options, options.d, options.len);
                gnh->opt_len = options.len / 4;
                header_len += options.len;

                n += len;
            }
            if (!ovs_scan_len(s, &n, "))")) {
                return -EINVAL;
            }

            gnh->proto_type = htons(ETH_TYPE_TEB);
            put_16aligned_be32(&gnh->vni, htonl(vni << 8));
            tnl_type = OVS_VPORT_TYPE_GENEVE;
        } else {
            return -EINVAL;
        }
    } else if (ovs_scan_len(s, &n, "gre((flags=0x%"SCNx16",proto=0x%"SCNx16")",
                            &gre_flags, &gre_proto)){

        if (eth->eth_type == htons(ETH_TYPE_IP)) {
            tnl_type = OVS_VPORT_TYPE_GRE;
        } else {
            tnl_type = OVS_VPORT_TYPE_IP6GRE;
        }
        greh->flags = htons(gre_flags);
        greh->protocol = htons(gre_proto);
        ovs_16aligned_be32 *options = (ovs_16aligned_be32 *) (greh + 1);

        if (greh->flags & htons(GRE_CSUM)) {
            uint16_t csum;
            if (!ovs_scan_len(s, &n, ",csum=0x%"SCNx16, &csum)) {
                return -EINVAL;
            }

            memset(options, 0, sizeof *options);
            *((ovs_be16 *)options) = htons(csum);
            options++;
        }
        if (greh->flags & htons(GRE_KEY)) {
            uint32_t key;

            if (!ovs_scan_len(s, &n, ",key=0x%"SCNx32, &key)) {
                return -EINVAL;
            }

            put_16aligned_be32(options, htonl(key));
            options++;
        }
        if (greh->flags & htons(GRE_SEQ)) {
            uint32_t seq;

            if (!ovs_scan_len(s, &n, ",seq=0x%"SCNx32, &seq)) {
                return -EINVAL;
            }
            put_16aligned_be32(options, htonl(seq));
            options++;
        }

        if (!ovs_scan_len(s, &n, "))")) {
            return -EINVAL;
        }

        header_len = sizeof *eth + ip_len +
                     ((uint8_t *) options - (uint8_t *) greh);
    } else if (ovs_scan_len(s, &n, "erspan(ver=1,sid="SCNx16",idx=0x"SCNx32")",
                            &sid, &erspan_idx)) {
        ersh = ERSPAN_HDR(greh);
        ovs_16aligned_be32 *index = ALIGNED_CAST(ovs_16aligned_be32 *,
                                                 ersh + 1);

        if (eth->eth_type == htons(ETH_TYPE_IP)) {
            tnl_type = OVS_VPORT_TYPE_ERSPAN;
        } else {
            tnl_type = OVS_VPORT_TYPE_IP6ERSPAN;
        }

        greh->flags = htons(GRE_SEQ);
        greh->protocol = htons(ETH_TYPE_ERSPAN1);

        ersh->ver = 1;
        set_sid(ersh, sid);
        put_16aligned_be32(index, htonl(erspan_idx));

        if (!ovs_scan_len(s, &n, ")")) {
            return -EINVAL;
        }
        header_len = sizeof *eth + ip_len + ERSPAN_GREHDR_LEN +
                     sizeof *ersh + ERSPAN_V1_MDSIZE;

    } else if (ovs_scan_len(s, &n, "erspan(ver=2,sid="SCNx16"dir="SCNu8
                            ",hwid=0x"SCNx8")", &sid, &dir, &hwid)) {

        ersh = ERSPAN_HDR(greh);
        md2 = ALIGNED_CAST(struct erspan_md2 *, ersh + 1);

        if (eth->eth_type == htons(ETH_TYPE_IP)) {
            tnl_type = OVS_VPORT_TYPE_ERSPAN;
        } else {
            tnl_type = OVS_VPORT_TYPE_IP6ERSPAN;
        }

        greh->flags = htons(GRE_SEQ);
        greh->protocol = htons(ETH_TYPE_ERSPAN2);

        ersh->ver = 2;
        set_sid(ersh, sid);
        set_hwid(md2, hwid);
        md2->dir = dir;

        if (!ovs_scan_len(s, &n, ")")) {
            return -EINVAL;
        }

        header_len = sizeof *eth + ip_len + ERSPAN_GREHDR_LEN +
                     sizeof *ersh + ERSPAN_V2_MDSIZE;

    } else if (ovs_scan_len(s, &n, "gtpu(flags=%"SCNi8",msgtype=%"
                SCNu8",teid=0x%"SCNx32"))",
                &gtpu_flags, &gtpu_msgtype, &teid)) {
        struct gtpuhdr *gtph = (struct gtpuhdr *) (udp + 1);

        gtph->md.flags = gtpu_flags;
        gtph->md.msgtype = gtpu_msgtype;
        put_16aligned_be32(&gtph->teid, htonl(teid));
        tnl_type = OVS_VPORT_TYPE_GTPU;
        header_len = sizeof *eth + ip_len +
                     sizeof *udp + sizeof *gtph;
    } else {
        return -EINVAL;
    }

    /* check tunnel meta data. */
    if (data->tnl_type != tnl_type) {
        return -EINVAL;
    }
    if (data->header_len != header_len) {
        return -EINVAL;
    }

    /* Out port */
    if (!ovs_scan_len(s, &n, ",out_port(%"SCNi32"))", &data->out_port)) {
        return -EINVAL;
    }

    return n;
}

struct ct_nat_params {
    bool snat;
    bool dnat;
    size_t addr_len;
    union {
        ovs_be32 ip;
        struct in6_addr ip6;
    } addr_min;
    union {
        ovs_be32 ip;
        struct in6_addr ip6;
    } addr_max;
    uint16_t proto_min;
    uint16_t proto_max;
    bool persistent;
    bool proto_hash;
    bool proto_random;
};

static int
scan_ct_nat_range(const char *s, int *n, struct ct_nat_params *p)
{
    if (ovs_scan_len(s, n, "=")) {
        char ipv6_s[IPV6_SCAN_LEN + 1];
        struct in6_addr ipv6;

        if (ovs_scan_len(s, n, IP_SCAN_FMT, IP_SCAN_ARGS(&p->addr_min.ip))) {
            p->addr_len = sizeof p->addr_min.ip;
            if (ovs_scan_len(s, n, "-")) {
                if (!ovs_scan_len(s, n, IP_SCAN_FMT,
                                  IP_SCAN_ARGS(&p->addr_max.ip))) {
                    return -EINVAL;
                }
            }
        } else if ((ovs_scan_len(s, n, IPV6_SCAN_FMT, ipv6_s)
                    || ovs_scan_len(s, n, "["IPV6_SCAN_FMT"]", ipv6_s))
                   && inet_pton(AF_INET6, ipv6_s, &ipv6) == 1) {
            p->addr_len = sizeof p->addr_min.ip6;
            p->addr_min.ip6 = ipv6;
            if (ovs_scan_len(s, n, "-")) {
                if ((ovs_scan_len(s, n, IPV6_SCAN_FMT, ipv6_s)
                     || ovs_scan_len(s, n, "["IPV6_SCAN_FMT"]", ipv6_s))
                    && inet_pton(AF_INET6, ipv6_s, &ipv6) == 1) {
                    p->addr_max.ip6 = ipv6;
                } else {
                    return -EINVAL;
                }
            }
        } else {
            return -EINVAL;
        }
        if (ovs_scan_len(s, n, ":%"SCNu16, &p->proto_min)) {
            if (ovs_scan_len(s, n, "-")) {
                if (!ovs_scan_len(s, n, "%"SCNu16, &p->proto_max)) {
                    return -EINVAL;
                }
            }
        }
    }
    return 0;
}

static int
scan_ct_nat(const char *s, struct ct_nat_params *p)
{
    int n = 0;

    if (ovs_scan_len(s, &n, "nat")) {
        memset(p, 0, sizeof *p);

        if (ovs_scan_len(s, &n, "(")) {
            char *end;
            int end_n;

            end = strchr(s + n, ')');
            if (!end) {
                return -EINVAL;
            }
            end_n = end - s;

            while (n < end_n) {
                n += strspn(s + n, delimiters);
                if (ovs_scan_len(s, &n, "src")) {
                    int err = scan_ct_nat_range(s, &n, p);
                    if (err) {
                        return err;
                    }
                    p->snat = true;
                    continue;
                }
                if (ovs_scan_len(s, &n, "dst")) {
                    int err = scan_ct_nat_range(s, &n, p);
                    if (err) {
                        return err;
                    }
                    p->dnat = true;
                    continue;
                }
                if (ovs_scan_len(s, &n, "persistent")) {
                    p->persistent = true;
                    continue;
                }
                if (ovs_scan_len(s, &n, "hash")) {
                    p->proto_hash = true;
                    continue;
                }
                if (ovs_scan_len(s, &n, "random")) {
                    p->proto_random = true;
                    continue;
                }
                return -EINVAL;
            }

            if (p->snat && p->dnat) {
                return -EINVAL;
            }
            if ((p->addr_len != 0 &&
                 memcmp(&p->addr_max, &in6addr_any, p->addr_len) &&
                 memcmp(&p->addr_max, &p->addr_min, p->addr_len) < 0) ||
                (p->proto_max && p->proto_max < p->proto_min)) {
                return -EINVAL;
            }
            if (p->proto_hash && p->proto_random) {
                return -EINVAL;
            }
            n++;
        }
    }
    return n;
}

static void
nl_msg_put_ct_nat(struct ct_nat_params *p, struct ofpbuf *actions)
{
    size_t start = nl_msg_start_nested(actions, OVS_CT_ATTR_NAT);

    if (p->snat) {
        nl_msg_put_flag(actions, OVS_NAT_ATTR_SRC);
    } else if (p->dnat) {
        nl_msg_put_flag(actions, OVS_NAT_ATTR_DST);
    } else {
        goto out;
    }
    if (p->addr_len != 0) {
        nl_msg_put_unspec(actions, OVS_NAT_ATTR_IP_MIN, &p->addr_min,
                          p->addr_len);
        if (memcmp(&p->addr_max, &p->addr_min, p->addr_len) > 0) {
            nl_msg_put_unspec(actions, OVS_NAT_ATTR_IP_MAX, &p->addr_max,
                              p->addr_len);
        }
        if (p->proto_min) {
            nl_msg_put_u16(actions, OVS_NAT_ATTR_PROTO_MIN, p->proto_min);
            if (p->proto_max && p->proto_max > p->proto_min) {
                nl_msg_put_u16(actions, OVS_NAT_ATTR_PROTO_MAX, p->proto_max);
            }
        }
        if (p->persistent) {
            nl_msg_put_flag(actions, OVS_NAT_ATTR_PERSISTENT);
        }
        if (p->proto_hash) {
            nl_msg_put_flag(actions, OVS_NAT_ATTR_PROTO_HASH);
        }
        if (p->proto_random) {
            nl_msg_put_flag(actions, OVS_NAT_ATTR_PROTO_RANDOM);
        }
    }
out:
    nl_msg_end_nested(actions, start);
}

static int
parse_conntrack_action(const char *s_, struct ofpbuf *actions)
{
    const char *s = s_;

    if (ovs_scan(s, "ct")) {
        const char *helper = NULL, *timeout = NULL;
        size_t helper_len = 0, timeout_len = 0;
        bool commit = false;
        bool force_commit = false;
        uint16_t zone = 0;
        struct {
            uint32_t value;
            uint32_t mask;
        } ct_mark = { 0, 0 };
        struct {
            ovs_u128 value;
            ovs_u128 mask;
        } ct_label;
        struct ct_nat_params nat_params;
        bool have_nat = false;
        size_t start;
        char *end;

        memset(&ct_label, 0, sizeof(ct_label));

        s += 2;
        if (ovs_scan(s, "(")) {
            s++;
find_end:
            end = strchr(s, ')');
            if (!end) {
                return -EINVAL;
            }

            while (s != end) {
                int n;

                s += strspn(s, delimiters);
                if (ovs_scan(s, "commit%n", &n)) {
                    commit = true;
                    s += n;
                    continue;
                }
                if (ovs_scan(s, "force_commit%n", &n)) {
                    force_commit = true;
                    s += n;
                    continue;
                }
                if (ovs_scan(s, "zone=%"SCNu16"%n", &zone, &n)) {
                    s += n;
                    continue;
                }
                if (ovs_scan(s, "mark=%"SCNx32"%n", &ct_mark.value, &n)) {
                    s += n;
                    n = -1;
                    if (ovs_scan(s, "/%"SCNx32"%n", &ct_mark.mask, &n)) {
                        s += n;
                    } else {
                        ct_mark.mask = UINT32_MAX;
                    }
                    continue;
                }
                if (ovs_scan(s, "label=%n", &n)) {
                    int retval;

                    s += n;
                    retval = scan_u128(s, &ct_label.value, &ct_label.mask);
                    if (retval == 0) {
                        return -EINVAL;
                    }
                    s += retval;
                    continue;
                }
                if (ovs_scan(s, "helper=%n", &n)) {
                    s += n;
                    helper_len = strcspn(s, delimiters_end);
                    if (!helper_len || helper_len > 15) {
                        return -EINVAL;
                    }
                    helper = s;
                    s += helper_len;
                    continue;
                }
                if (ovs_scan(s, "timeout=%n", &n)) {
                    s += n;
                    timeout_len = strcspn(s, delimiters_end);
                    if (!timeout_len || timeout_len > 31) {
                        return -EINVAL;
                    }
                    timeout = s;
                    s += timeout_len;
                    continue;
                }

                n = scan_ct_nat(s, &nat_params);
                if (n > 0) {
                    s += n;
                    have_nat = true;

                    /* end points to the end of the nested, nat action.
                     * find the real end. */
                    goto find_end;
                }
                /* Nothing matched. */
                return -EINVAL;
            }
            s++;
        }
        if (commit && force_commit) {
            return -EINVAL;
        }

        start = nl_msg_start_nested(actions, OVS_ACTION_ATTR_CT);
        if (commit) {
            nl_msg_put_flag(actions, OVS_CT_ATTR_COMMIT);
        } else if (force_commit) {
            nl_msg_put_flag(actions, OVS_CT_ATTR_FORCE_COMMIT);
        }
        if (zone) {
            nl_msg_put_u16(actions, OVS_CT_ATTR_ZONE, zone);
        }
        if (ct_mark.mask) {
            nl_msg_put_unspec(actions, OVS_CT_ATTR_MARK, &ct_mark,
                              sizeof(ct_mark));
        }
        if (!ovs_u128_is_zero(ct_label.mask)) {
            nl_msg_put_unspec(actions, OVS_CT_ATTR_LABELS, &ct_label,
                              sizeof ct_label);
        }
        if (helper) {
            nl_msg_put_string__(actions, OVS_CT_ATTR_HELPER, helper,
                                helper_len);
        }
        if (timeout) {
            nl_msg_put_string__(actions, OVS_CT_ATTR_TIMEOUT, timeout,
                                timeout_len);
        }
        if (have_nat) {
            nl_msg_put_ct_nat(&nat_params, actions);
        }
        nl_msg_end_nested(actions, start);
    }

    return s - s_;
}

static void
nsh_key_to_attr(struct ofpbuf *buf, const struct ovs_key_nsh *nsh,
                uint8_t * metadata, size_t md_size,
                bool is_mask)
{
    size_t nsh_key_ofs;
    struct ovs_nsh_key_base base;

    base.flags = nsh->flags;
    base.ttl = nsh->ttl;
    base.mdtype = nsh->mdtype;
    base.np = nsh->np;
    base.path_hdr = nsh->path_hdr;

    nsh_key_ofs = nl_msg_start_nested(buf, OVS_KEY_ATTR_NSH);
    nl_msg_put_unspec(buf, OVS_NSH_KEY_ATTR_BASE, &base, sizeof base);

    if (is_mask) {
        nl_msg_put_unspec(buf, OVS_NSH_KEY_ATTR_MD1, nsh->context,
                          sizeof nsh->context);
    } else {
        switch (nsh->mdtype) {
        case NSH_M_TYPE1:
            nl_msg_put_unspec(buf, OVS_NSH_KEY_ATTR_MD1, nsh->context,
                              sizeof nsh->context);
            break;
        case NSH_M_TYPE2:
            if (metadata && md_size > 0) {
                nl_msg_put_unspec(buf, OVS_NSH_KEY_ATTR_MD2, metadata,
                                  md_size);
            }
            break;
        default:
            /* No match support for other MD formats yet. */
            break;
        }
    }
    nl_msg_end_nested(buf, nsh_key_ofs);
}


static int
parse_odp_push_nsh_action(const char *s, struct ofpbuf *actions)
{
    int n = 0;
    int ret = 0;
    uint32_t spi = 0;
    uint8_t si = 255;
    uint32_t cd;
    struct ovs_key_nsh nsh;
    uint8_t metadata[NSH_CTX_HDRS_MAX_LEN];
    uint8_t md_size = 0;

    if (!ovs_scan_len(s, &n, "push_nsh(")) {
        ret = -EINVAL;
        goto out;
    }

    /* The default is NSH_M_TYPE1 */
    nsh.flags = 0;
    nsh.ttl = 63;
    nsh.mdtype = NSH_M_TYPE1;
    nsh.np = NSH_P_ETHERNET;
    nsh.path_hdr = nsh_spi_si_to_path_hdr(0, 255);
    memset(nsh.context, 0, NSH_M_TYPE1_MDLEN);

    for (;;) {
        n += strspn(s + n, delimiters);
        if (s[n] == ')') {
            break;
        }

        if (ovs_scan_len(s, &n, "flags=%"SCNi8, &nsh.flags)) {
            continue;
        }
        if (ovs_scan_len(s, &n, "ttl=%"SCNi8, &nsh.ttl)) {
            continue;
        }
        if (ovs_scan_len(s, &n, "mdtype=%"SCNi8, &nsh.mdtype)) {
            switch (nsh.mdtype) {
            case NSH_M_TYPE1:
                /* This is the default format. */;
                break;
            case NSH_M_TYPE2:
                /* Length will be updated later. */
                md_size = 0;
                break;
            default:
                ret = -EINVAL;
                goto out;
            }
            continue;
        }
        if (ovs_scan_len(s, &n, "np=%"SCNi8, &nsh.np)) {
            continue;
        }
        if (ovs_scan_len(s, &n, "spi=0x%"SCNx32, &spi)) {
            continue;
        }
        if (ovs_scan_len(s, &n, "si=%"SCNi8, &si)) {
            continue;
        }
        if (nsh.mdtype == NSH_M_TYPE1) {
            if (ovs_scan_len(s, &n, "c1=0x%"SCNx32, &cd)) {
                nsh.context[0] = htonl(cd);
                continue;
            }
            if (ovs_scan_len(s, &n, "c2=0x%"SCNx32, &cd)) {
                nsh.context[1] = htonl(cd);
                continue;
            }
            if (ovs_scan_len(s, &n, "c3=0x%"SCNx32, &cd)) {
                nsh.context[2] = htonl(cd);
                continue;
            }
            if (ovs_scan_len(s, &n, "c4=0x%"SCNx32, &cd)) {
                nsh.context[3] = htonl(cd);
                continue;
            }
        }
        else if (nsh.mdtype == NSH_M_TYPE2) {
            struct ofpbuf b;
            char buf[512];
            size_t mdlen, padding;
            if (ovs_scan_len(s, &n, "md2=0x%511[0-9a-fA-F]", buf)
                && n/2 <= sizeof metadata) {
                ofpbuf_use_stub(&b, metadata, sizeof metadata);
                ofpbuf_put_hex(&b, buf, &mdlen);
                /* Pad metadata to 4 bytes. */
                padding = PAD_SIZE(mdlen, 4);
                if (padding > 0) {
                    ofpbuf_put_zeros(&b, padding);
                }
                md_size = mdlen + padding;
                ofpbuf_uninit(&b);
                continue;
            }
        }

        ret = -EINVAL;
        goto out;
    }
out:
    if (ret >= 0) {
        nsh.path_hdr = nsh_spi_si_to_path_hdr(spi, si);
        size_t offset = nl_msg_start_nested(actions, OVS_ACTION_ATTR_PUSH_NSH);
        nsh_key_to_attr(actions, &nsh, metadata, md_size, false);
        nl_msg_end_nested(actions, offset);
        ret = n;
    }
    return ret;
}

static int
parse_action_list(struct parse_odp_context *context, const char *s,
                  struct ofpbuf *actions)
{
    int n = 0;

    for (;;) {
        int retval;

        n += strspn(s + n, delimiters);
        if (s[n] == ')') {
            break;
        }
        retval = parse_odp_action(context, s + n, actions);
        if (retval < 0) {
            return retval;
        }
        n += retval;
    }

    if (actions->size > UINT16_MAX) {
        return -EFBIG;
    }

    return n;
}


static int
parse_odp_action(struct parse_odp_context *context, const char *s,
                 struct ofpbuf *actions)
{
    int retval;

    context->depth++;

    if (context->depth == MAX_ODP_NESTED) {
        retval = -EINVAL;
    } else {
        retval = parse_odp_action__(context, s, actions);
    }

    context->depth--;

    return retval;
}


static int
parse_odp_action__(struct parse_odp_context *context, const char *s,
                   struct ofpbuf *actions)
{
    {
        uint32_t port;
        int n;

        if (ovs_scan(s, "%"SCNi32"%n", &port, &n)) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_OUTPUT, port);
            return n;
        }
    }

    {
        uint32_t bond_id;
        int n;

        if (ovs_scan(s, "lb_output(%"PRIu32")%n", &bond_id, &n)) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_LB_OUTPUT, bond_id);
            return n;
        }
    }

    {
        uint32_t max_len;
        int n;

        if (ovs_scan(s, "trunc(%"SCNi32")%n", &max_len, &n)) {
            struct ovs_action_trunc *trunc;

            trunc = nl_msg_put_unspec_uninit(actions,
                     OVS_ACTION_ATTR_TRUNC, sizeof *trunc);
            trunc->max_len = max_len;
            return n;
        }
    }

    if (context->port_names) {
        int len = strcspn(s, delimiters);
        struct simap_node *node;

        node = simap_find_len(context->port_names, s, len);
        if (node) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_OUTPUT, node->data);
            return len;
        }
    }

    {
        uint32_t recirc_id;
        int n = -1;

        if (ovs_scan(s, "recirc(%"PRIu32")%n", &recirc_id, &n)) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_RECIRC, recirc_id);
            return n;
        }
    }

    if (!strncmp(s, "userspace(", 10)) {
        return parse_odp_userspace_action(s, actions);
    }

    if (!strncmp(s, "set(", 4)) {
        size_t start_ofs;
        int retval;
        struct nlattr mask[1024 / sizeof(struct nlattr)];
        struct ofpbuf maskbuf = OFPBUF_STUB_INITIALIZER(mask);
        struct nlattr *nested, *key;
        size_t size;

        start_ofs = nl_msg_start_nested(actions, OVS_ACTION_ATTR_SET);
        retval = parse_odp_key_mask_attr(context, s + 4, actions, &maskbuf);
        if (retval < 0) {
            ofpbuf_uninit(&maskbuf);
            return retval;
        }
        if (s[retval + 4] != ')') {
            ofpbuf_uninit(&maskbuf);
            return -EINVAL;
        }

        nested = ofpbuf_at_assert(actions, start_ofs, sizeof *nested);
        key = nested + 1;

        size = nl_attr_get_size(mask);
        if (size == nl_attr_get_size(key)) {
            /* Change to masked set action if not fully masked. */
            if (!is_all_ones(mask + 1, size)) {
                /* Remove padding of eariler key payload  */
                actions->size -= NLA_ALIGN(key->nla_len) - key->nla_len;

                /* Put mask payload right after key payload */
                key->nla_len += size;
                ofpbuf_put(actions, mask + 1, size);

                /* 'actions' may have been reallocated by ofpbuf_put(). */
                nested = ofpbuf_at_assert(actions, start_ofs, sizeof *nested);
                nested->nla_type = OVS_ACTION_ATTR_SET_MASKED;

                key = nested + 1;
                /* Add new padding as needed */
                ofpbuf_put_zeros(actions, NLA_ALIGN(key->nla_len) -
                                          key->nla_len);
            }
        }
        ofpbuf_uninit(&maskbuf);

        nl_msg_end_nested(actions, start_ofs);
        return retval + 5;
    }

    {
        struct ovs_action_push_vlan push;
        int tpid = ETH_TYPE_VLAN;
        int vid, pcp;
        int cfi = 1;
        int n = -1;

        if (ovs_scan(s, "push_vlan(vid=%i,pcp=%i)%n", &vid, &pcp, &n)
            || ovs_scan(s, "push_vlan(vid=%i,pcp=%i,cfi=%i)%n",
                        &vid, &pcp, &cfi, &n)
            || ovs_scan(s, "push_vlan(tpid=%i,vid=%i,pcp=%i)%n",
                        &tpid, &vid, &pcp, &n)
            || ovs_scan(s, "push_vlan(tpid=%i,vid=%i,pcp=%i,cfi=%i)%n",
                        &tpid, &vid, &pcp, &cfi, &n)) {
            if ((vid & ~(VLAN_VID_MASK >> VLAN_VID_SHIFT)) != 0
                || (pcp & ~(VLAN_PCP_MASK >> VLAN_PCP_SHIFT)) != 0) {
                return -EINVAL;
            }
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
        unsigned long long int meter_id;
        int n = -1;

        if (sscanf(s, "meter(%lli)%n", &meter_id, &n) > 0 && n > 0) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_METER, meter_id);
            return n;
        }
    }

    {
        double percentage;
        int n = -1;

        if (ovs_scan(s, "sample(sample=%lf%%,actions(%n", &percentage, &n)
            && percentage >= 0. && percentage <= 100.0) {
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
            int retval = parse_action_list(context, s + n, actions);
            if (retval < 0) {
                return retval;
            }


            n += retval;
            nl_msg_end_nested(actions, actions_ofs);
            nl_msg_end_nested(actions, sample_ofs);

            return s[n + 1] == ')' ? n + 2 : -EINVAL;
        }
    }

    {
        if (!strncmp(s, "clone(", 6)) {
            size_t actions_ofs;
            int n = 6;

            actions_ofs = nl_msg_start_nested(actions, OVS_ACTION_ATTR_CLONE);
            int retval = parse_action_list(context, s + n, actions);
            if (retval < 0) {
                return retval;
            }
            n += retval;
            nl_msg_end_nested(actions, actions_ofs);
            return n + 1;
        }
    }

    {
        if (!strncmp(s, "push_nsh(", 9)) {
            int retval = parse_odp_push_nsh_action(s, actions);
            if (retval < 0) {
                return retval;
            }
            return retval + 1;
        }
    }

    {
        int n;
        if (ovs_scan(s, "pop_nsh()%n", &n)) {
            nl_msg_put_flag(actions, OVS_ACTION_ATTR_POP_NSH);
            return n;
        }
    }

    {
        uint32_t port;
        int n;

        if (ovs_scan(s, "tnl_pop(%"SCNi32")%n", &port, &n)) {
            nl_msg_put_u32(actions, OVS_ACTION_ATTR_TUNNEL_POP, port);
            return n;
        }
    }

    {
        if (!strncmp(s, "ct_clear", 8)) {
            nl_msg_put_flag(actions, OVS_ACTION_ATTR_CT_CLEAR);
            return 8;
        }
    }

    {
        uint16_t pkt_len;
        int n = -1;
        if (ovs_scan(s, "check_pkt_len(size=%"SCNi16",gt(%n", &pkt_len, &n)) {
            size_t cpl_ofs, actions_ofs;
            cpl_ofs = nl_msg_start_nested(actions,
                                          OVS_ACTION_ATTR_CHECK_PKT_LEN);
            nl_msg_put_u16(actions, OVS_CHECK_PKT_LEN_ATTR_PKT_LEN, pkt_len);
            actions_ofs = nl_msg_start_nested(
                actions, OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER);

            int retval;
            if (!strncasecmp(s + n, "drop", 4)) {
                n += 4;
            } else {
                retval = parse_action_list(context, s + n, actions);
                if (retval < 0) {
                    return retval;
                }

                n += retval;
            }
            nl_msg_end_nested(actions, actions_ofs);
            retval = -1;
            if (!ovs_scan(s + n, "),le(%n", &retval)) {
                return -EINVAL;
            }
            n += retval;

            actions_ofs = nl_msg_start_nested(
                actions, OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL);
            if (!strncasecmp(s + n, "drop", 4)) {
                n += 4;
            } else {
                retval = parse_action_list(context, s + n, actions);
                if (retval < 0) {
                    return retval;
                }
                n += retval;
            }
            nl_msg_end_nested(actions, actions_ofs);
            nl_msg_end_nested(actions, cpl_ofs);
            return s[n + 1] == ')' ? n + 2 : -EINVAL;
        }
    }

    {
        int retval;

        retval = parse_conntrack_action(s, actions);
        if (retval) {
            return retval;
        }
    }

    {
        struct ovs_action_push_tnl data;
        int n;

        n = ovs_parse_tnl_push(s, &data);
        if (n > 0) {
            odp_put_tnl_push_action(actions, &data);
            return n;
        } else if (n < 0) {
            return n;
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
        nl_msg_put_u32(actions, OVS_ACTION_ATTR_DROP, XLATE_OK);
        return 0;
    }

    struct parse_odp_context context = (struct parse_odp_context) {
        .port_names = port_names,
    };

    old_size = actions->size;
    for (;;) {
        int retval;

        s += strspn(s, delimiters);
        if (!*s) {
            return 0;
        }

        retval = parse_odp_action(&context, s, actions);

        if (retval >= 0 && nl_attr_oversized(actions->size - NLA_HDRLEN)) {
            retval = -E2BIG;
        }

        if (retval < 0 || !strchr(delimiters, s[retval])) {
            actions->size = old_size;
            return -retval;
        }
        s += retval;
    }

    return 0;
}

static const struct attr_len_tbl ovs_vxlan_ext_attr_lens[OVS_VXLAN_EXT_MAX + 1] = {
    [OVS_VXLAN_EXT_GBP]                 = { .len = 4 },
};

static const struct attr_len_tbl ovs_tun_key_attr_lens[OVS_TUNNEL_KEY_ATTR_MAX + 1] = {
    [OVS_TUNNEL_KEY_ATTR_ID]            = { .len = 8 },
    [OVS_TUNNEL_KEY_ATTR_IPV4_SRC]      = { .len = 4 },
    [OVS_TUNNEL_KEY_ATTR_IPV4_DST]      = { .len = 4 },
    [OVS_TUNNEL_KEY_ATTR_TOS]           = { .len = 1 },
    [OVS_TUNNEL_KEY_ATTR_TTL]           = { .len = 1 },
    [OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = { .len = 0 },
    [OVS_TUNNEL_KEY_ATTR_CSUM]          = { .len = 0 },
    [OVS_TUNNEL_KEY_ATTR_TP_SRC]        = { .len = 2 },
    [OVS_TUNNEL_KEY_ATTR_TP_DST]        = { .len = 2 },
    [OVS_TUNNEL_KEY_ATTR_OAM]           = { .len = 0 },
    [OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS]   = { .len = ATTR_LEN_VARIABLE },
    [OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS]    = { .len = ATTR_LEN_NESTED,
                                            .next = ovs_vxlan_ext_attr_lens ,
                                            .next_max = OVS_VXLAN_EXT_MAX},
    [OVS_TUNNEL_KEY_ATTR_IPV6_SRC]      = { .len = 16 },
    [OVS_TUNNEL_KEY_ATTR_IPV6_DST]      = { .len = 16 },
    [OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS]   = { .len = ATTR_LEN_VARIABLE },
    [OVS_TUNNEL_KEY_ATTR_GTPU_OPTS]   = { .len = ATTR_LEN_VARIABLE },
};

const struct attr_len_tbl ovs_flow_key_attr_lens[OVS_KEY_ATTR_MAX + 1] = {
    [OVS_KEY_ATTR_ENCAP]     = { .len = ATTR_LEN_NESTED },
    [OVS_KEY_ATTR_PRIORITY]  = { .len = 4 },
    [OVS_KEY_ATTR_SKB_MARK]  = { .len = 4 },
    [OVS_KEY_ATTR_DP_HASH]   = { .len = 4 },
    [OVS_KEY_ATTR_RECIRC_ID] = { .len = 4 },
    [OVS_KEY_ATTR_TUNNEL]    = { .len = ATTR_LEN_NESTED,
                                 .next = ovs_tun_key_attr_lens,
                                 .next_max = OVS_TUNNEL_KEY_ATTR_MAX },
    [OVS_KEY_ATTR_IN_PORT]   = { .len = 4  },
    [OVS_KEY_ATTR_ETHERNET]  = { .len = sizeof(struct ovs_key_ethernet) },
    [OVS_KEY_ATTR_VLAN]      = { .len = 2 },
    [OVS_KEY_ATTR_ETHERTYPE] = { .len = 2 },
    [OVS_KEY_ATTR_MPLS]      = { .len = ATTR_LEN_VARIABLE },
    [OVS_KEY_ATTR_IPV4]      = { .len = sizeof(struct ovs_key_ipv4) },
    [OVS_KEY_ATTR_IPV6]      = { .len = sizeof(struct ovs_key_ipv6) },
    [OVS_KEY_ATTR_TCP]       = { .len = sizeof(struct ovs_key_tcp) },
    [OVS_KEY_ATTR_TCP_FLAGS] = { .len = 2 },
    [OVS_KEY_ATTR_UDP]       = { .len = sizeof(struct ovs_key_udp) },
    [OVS_KEY_ATTR_SCTP]      = { .len = sizeof(struct ovs_key_sctp) },
    [OVS_KEY_ATTR_ICMP]      = { .len = sizeof(struct ovs_key_icmp) },
    [OVS_KEY_ATTR_ICMPV6]    = { .len = sizeof(struct ovs_key_icmpv6) },
    [OVS_KEY_ATTR_ARP]       = { .len = sizeof(struct ovs_key_arp) },
    [OVS_KEY_ATTR_ND]        = { .len = sizeof(struct ovs_key_nd) },
    [OVS_KEY_ATTR_ND_EXTENSIONS] = { .len = sizeof(struct ovs_key_nd_extensions) },
    [OVS_KEY_ATTR_CT_STATE]  = { .len = 4 },
    [OVS_KEY_ATTR_CT_ZONE]   = { .len = 2 },
    [OVS_KEY_ATTR_CT_MARK]   = { .len = 4 },
    [OVS_KEY_ATTR_CT_LABELS] = { .len = sizeof(struct ovs_key_ct_labels) },
    [OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4] = { .len = sizeof(struct ovs_key_ct_tuple_ipv4) },
    [OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6] = { .len = sizeof(struct ovs_key_ct_tuple_ipv6) },
    [OVS_KEY_ATTR_PACKET_TYPE] = { .len = 4  },
    [OVS_KEY_ATTR_NSH]       = { .len = ATTR_LEN_NESTED,
                                 .next = ovs_nsh_key_attr_lens,
                                 .next_max = OVS_NSH_KEY_ATTR_MAX },
};

/* Returns the correct length of the payload for a flow key attribute of the
 * specified 'type', ATTR_LEN_INVALID if 'type' is unknown, ATTR_LEN_VARIABLE
 * if the attribute's payload is variable length, or ATTR_LEN_NESTED if the
 * payload is a nested type. */
static int
odp_key_attr_len(const struct attr_len_tbl tbl[], int max_type, uint16_t type)
{
    if (type > max_type) {
        return ATTR_LEN_INVALID;
    }

    return tbl[type].len;
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
            if (i) {
                ds_put_char(ds, ' ');
            }
            ds_put_format(ds, "%02x", unspec[i]);
        }
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

enum odp_key_fitness
odp_nsh_hdr_from_attr(const struct nlattr *attr,
                      struct nsh_hdr *nsh_hdr, size_t size)
{
    unsigned int left;
    const struct nlattr *a;
    bool unknown = false;
    uint8_t flags = 0;
    uint8_t ttl = 63;
    size_t mdlen = 0;
    bool has_md1 = false;
    bool has_md2 = false;

    memset(nsh_hdr, 0, size);

    NL_NESTED_FOR_EACH (a, left, attr) {
        uint16_t type = nl_attr_type(a);
        size_t len = nl_attr_get_size(a);
        int expected_len = odp_key_attr_len(ovs_nsh_key_attr_lens,
                                            OVS_NSH_KEY_ATTR_MAX, type);

        if (len != expected_len && expected_len >= 0) {
            return ODP_FIT_ERROR;
        }

        switch (type) {
        case OVS_NSH_KEY_ATTR_BASE: {
            const struct ovs_nsh_key_base *base = nl_attr_get(a);
            nsh_hdr->next_proto = base->np;
            nsh_hdr->md_type = base->mdtype;
            put_16aligned_be32(&nsh_hdr->path_hdr, base->path_hdr);
            flags = base->flags;
            ttl = base->ttl;
            break;
        }
        case OVS_NSH_KEY_ATTR_MD1: {
            const struct ovs_nsh_key_md1 *md1 = nl_attr_get(a);
            struct nsh_md1_ctx *md1_dst = &nsh_hdr->md1;
            has_md1 = true;
            mdlen = nl_attr_get_size(a);
            if ((mdlen + NSH_BASE_HDR_LEN != NSH_M_TYPE1_LEN) ||
                (mdlen + NSH_BASE_HDR_LEN > size)) {
                return ODP_FIT_ERROR;
            }
            memcpy(md1_dst, md1, mdlen);
            break;
        }
        case OVS_NSH_KEY_ATTR_MD2: {
            struct nsh_md2_tlv *md2_dst = &nsh_hdr->md2;
            const uint8_t *md2 = nl_attr_get(a);
            has_md2 = true;
            mdlen = nl_attr_get_size(a);
            if (mdlen + NSH_BASE_HDR_LEN > size) {
                return ODP_FIT_ERROR;
            }
            memcpy(md2_dst, md2, mdlen);
            break;
        }
        default:
            /* Allow this to show up as unexpected, if there are unknown
             * tunnel attribute, eventually resulting in ODP_FIT_TOO_MUCH. */
            unknown = true;
            break;
        }
    }

    if (unknown) {
        return ODP_FIT_TOO_MUCH;
    }

    if ((has_md1 && nsh_hdr->md_type != NSH_M_TYPE1)
        || (has_md2 && nsh_hdr->md_type != NSH_M_TYPE2)) {
        return ODP_FIT_ERROR;
    }

    /* nsh header length  = NSH_BASE_HDR_LEN + mdlen */
    nsh_set_flags_ttl_len(nsh_hdr, flags, ttl, NSH_BASE_HDR_LEN + mdlen);

    return ODP_FIT_PERFECT;
}

/* Reports the error 'msg', which is formatted as with printf().
 *
 * If 'errorp' is nonnull, then some the wants the error report to come
 * directly back to it, so the function stores the error message into '*errorp'
 * (after first freeing it in case there's something there already).
 *
 * Otherwise, logs the message at WARN level, rate-limited. */
static void OVS_PRINTF_FORMAT(3, 4)
odp_parse_error(struct vlog_rate_limit *rl, char **errorp,
                const char *msg, ...)
{
    if (OVS_UNLIKELY(errorp)) {
        free(*errorp);

        va_list args;
        va_start(args, msg);
        *errorp = xvasprintf(msg, args);
        va_end(args);
    } else if (!VLOG_DROP_WARN(rl)) {
        va_list args;
        va_start(args, msg);
        char *error = xvasprintf(msg, args);
        va_end(args);

        VLOG_WARN("%s", error);

        free(error);
    }
}

/* Parses OVS_KEY_ATTR_NSH attribute 'attr' into 'nsh' and 'nsh_mask' and
 * returns fitness.  If the attribute is a key, 'is_mask' should be false;
 * if it is a mask, 'is_mask' should be true.  If 'errorp' is nonnull and the
 * function returns ODP_FIT_ERROR, stores a malloc()'d error message in
 * '*errorp'. */
static enum odp_key_fitness
odp_nsh_key_from_attr__(const struct nlattr *attr, bool is_mask,
                        struct ovs_key_nsh *nsh, struct ovs_key_nsh *nsh_mask,
                        char **errorp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    if (errorp) {
        *errorp = NULL;
    }

    unsigned int left;
    const struct nlattr *a;
    bool unknown = false;
    bool has_md1 = false;

    NL_NESTED_FOR_EACH (a, left, attr) {
        uint16_t type = nl_attr_type(a);
        size_t len = nl_attr_get_size(a);
        int expected_len = odp_key_attr_len(ovs_nsh_key_attr_lens,
                                            OVS_NSH_KEY_ATTR_MAX, type);
        if (expected_len) {
            if (nsh_mask) {
                expected_len *= 2;
            }
            if (len != expected_len) {
                odp_parse_error(&rl, errorp, "NSH %s attribute %"PRIu16" "
                                "should have length %d but actually has "
                                "%"PRIuSIZE,
                                nsh_mask ? "mask" : "key",
                                type, expected_len, len);
                return ODP_FIT_ERROR;
            }
        }

        switch (type) {
        case OVS_NSH_KEY_ATTR_UNSPEC:
            break;
        case OVS_NSH_KEY_ATTR_BASE: {
            const struct ovs_nsh_key_base *base = nl_attr_get(a);
            nsh->flags = base->flags;
            nsh->ttl = base->ttl;
            nsh->mdtype = base->mdtype;
            nsh->np = base->np;
            nsh->path_hdr = base->path_hdr;
            if (nsh_mask && (len == 2 * sizeof(*base))) {
                const struct ovs_nsh_key_base *base_mask = base + 1;
                nsh_mask->flags = base_mask->flags;
                nsh_mask->ttl = base_mask->ttl;
                nsh_mask->mdtype = base_mask->mdtype;
                nsh_mask->np = base_mask->np;
                nsh_mask->path_hdr = base_mask->path_hdr;
            }
            break;
        }
        case OVS_NSH_KEY_ATTR_MD1: {
            const struct ovs_nsh_key_md1 *md1 = nl_attr_get(a);
            has_md1 = true;
            memcpy(nsh->context, md1->context, sizeof md1->context);
            if (len == 2 * sizeof(*md1)) {
                const struct ovs_nsh_key_md1 *md1_mask = md1 + 1;
                memcpy(nsh_mask->context, md1_mask->context,
                       sizeof(*md1_mask));
            }
            break;
        }
        case OVS_NSH_KEY_ATTR_MD2:
        default:
            /* Allow this to show up as unexpected, if there are unknown
             * tunnel attribute, eventually resulting in ODP_FIT_TOO_MUCH. */
            unknown = true;
            break;
        }
    }

    if (unknown) {
        return ODP_FIT_TOO_MUCH;
    }

    if (!is_mask && has_md1 && nsh->mdtype != NSH_M_TYPE1 && !nsh_mask) {
        odp_parse_error(&rl, errorp, "OVS_NSH_KEY_ATTR_MD1 present but "
                        "declared mdtype %"PRIu8" is not %d (NSH_M_TYPE1)",
                        nsh->mdtype, NSH_M_TYPE1);
        return ODP_FIT_ERROR;
    }

    return ODP_FIT_PERFECT;
}

/* Parses OVS_KEY_ATTR_NSH attribute 'attr' into 'nsh' and 'nsh_mask' and
 * returns fitness.  The attribute should be a key (not a mask).  If 'errorp'
 * is nonnull and the function returns ODP_FIT_ERROR, stores a malloc()'d error
 * message in '*errorp'. */
enum odp_key_fitness
odp_nsh_key_from_attr(const struct nlattr *attr, struct ovs_key_nsh *nsh,
                      struct ovs_key_nsh *nsh_mask, char **errorp)
{
    return odp_nsh_key_from_attr__(attr, false, nsh, nsh_mask, errorp);
}

/* Parses OVS_KEY_ATTR_TUNNEL attribute 'attr' into 'tun' and returns fitness.
 * If the attribute is a key, 'is_mask' should be false; if it is a mask,
 * 'is_mask' should be true.  If 'errorp' is nonnull and the function returns
 * ODP_FIT_ERROR, stores a malloc()'d error message in '*errorp'. */
static enum odp_key_fitness
odp_tun_key_from_attr__(const struct nlattr *attr, bool is_mask,
                        struct flow_tnl *tun, char **errorp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    unsigned int left;
    const struct nlattr *a;
    bool ttl = false;
    bool unknown = false;

    NL_NESTED_FOR_EACH(a, left, attr) {
        uint16_t type = nl_attr_type(a);
        size_t len = nl_attr_get_size(a);
        int expected_len = odp_key_attr_len(ovs_tun_key_attr_lens,
                                            OVS_TUNNEL_ATTR_MAX, type);

        if (len != expected_len && expected_len >= 0) {
            odp_parse_error(&rl, errorp, "tunnel key attribute %"PRIu16" "
                            "should have length %d but actually has %"PRIuSIZE,
                            type, expected_len, len);
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
        case OVS_TUNNEL_KEY_ATTR_IPV6_SRC:
            tun->ipv6_src = nl_attr_get_in6_addr(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV6_DST:
            tun->ipv6_dst = nl_attr_get_in6_addr(a);
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
        case OVS_TUNNEL_KEY_ATTR_TP_SRC:
            tun->tp_src = nl_attr_get_be16(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_TP_DST:
            tun->tp_dst = nl_attr_get_be16(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_OAM:
            tun->flags |= FLOW_TNL_F_OAM;
            break;
        case OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS: {
            static const struct nl_policy vxlan_opts_policy[] = {
                [OVS_VXLAN_EXT_GBP] = { .type = NL_A_U32 },
            };
            struct nlattr *ext[ARRAY_SIZE(vxlan_opts_policy)];

            if (!nl_parse_nested(a, vxlan_opts_policy, ext, ARRAY_SIZE(ext))) {
                odp_parse_error(&rl, errorp, "error parsing VXLAN options");
                return ODP_FIT_ERROR;
            }

            if (ext[OVS_VXLAN_EXT_GBP]) {
                uint32_t gbp = nl_attr_get_u32(ext[OVS_VXLAN_EXT_GBP]);

                tun->gbp_id = htons(gbp & 0xFFFF);
                tun->gbp_flags = (gbp >> 16) & 0xFF;
            }

            break;
        }
        case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
            tun_metadata_from_geneve_nlattr(a, is_mask, tun);
            break;
        case OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS: {
            const struct erspan_metadata *opts = nl_attr_get(a);

            tun->erspan_ver = opts->version;
            if (tun->erspan_ver == 1) {
                tun->erspan_idx = ntohl(opts->u.index);
            } else if (tun->erspan_ver == 2) {
                tun->erspan_dir = opts->u.md2.dir;
                tun->erspan_hwid = get_hwid(&opts->u.md2);
            } else {
                VLOG_WARN("%s invalid erspan version\n", __func__);
            }
            break;
        }
        case OVS_TUNNEL_KEY_ATTR_GTPU_OPTS: {
            const struct gtpu_metadata *opts = nl_attr_get(a);

            tun->gtpu_flags = opts->flags;
            tun->gtpu_msgtype = opts->msgtype;
            break;
        }

        default:
            /* Allow this to show up as unexpected, if there are unknown
             * tunnel attribute, eventually resulting in ODP_FIT_TOO_MUCH. */
            unknown = true;
            break;
        }
    }

    if (!ttl) {
        odp_parse_error(&rl, errorp, "tunnel options missing TTL");
        return ODP_FIT_ERROR;
    }
    if (unknown) {
        return ODP_FIT_TOO_MUCH;
    }
    return ODP_FIT_PERFECT;
}

/* Parses OVS_KEY_ATTR_TUNNEL key attribute 'attr' into 'tun' and returns
 * fitness.  The attribute should be a key (not a mask).  If 'errorp' is
 * nonnull, stores NULL into '*errorp' on success, otherwise a malloc()'d error
 * message. */
enum odp_key_fitness
odp_tun_key_from_attr(const struct nlattr *attr, struct flow_tnl *tun,
                      char **errorp)
{
    if (errorp) {
        *errorp = NULL;
    }
    memset(tun, 0, sizeof *tun);
    return odp_tun_key_from_attr__(attr, false, tun, errorp);
}

static void
tun_key_to_attr(struct ofpbuf *a, const struct flow_tnl *tun_key,
                const struct flow_tnl *tun_flow_key,
                const struct ofpbuf *key_buf, const char *tnl_type)
{
    size_t tun_key_ofs;

    tun_key_ofs = nl_msg_start_nested(a, OVS_KEY_ATTR_TUNNEL);

    /* tun_id != 0 without FLOW_TNL_F_KEY is valid if tun_key is a mask. */
    if (tun_key->tun_id || tun_key->flags & FLOW_TNL_F_KEY) {
        nl_msg_put_be64(a, OVS_TUNNEL_KEY_ATTR_ID, tun_key->tun_id);
    }
    if (tun_key->ip_src) {
        nl_msg_put_be32(a, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, tun_key->ip_src);
    }
    if (tun_key->ip_dst) {
        nl_msg_put_be32(a, OVS_TUNNEL_KEY_ATTR_IPV4_DST, tun_key->ip_dst);
    }
    if (ipv6_addr_is_set(&tun_key->ipv6_src)) {
        nl_msg_put_in6_addr(a, OVS_TUNNEL_KEY_ATTR_IPV6_SRC, &tun_key->ipv6_src);
    }
    if (ipv6_addr_is_set(&tun_key->ipv6_dst)) {
        nl_msg_put_in6_addr(a, OVS_TUNNEL_KEY_ATTR_IPV6_DST, &tun_key->ipv6_dst);
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
    if (tun_key->tp_src) {
        nl_msg_put_be16(a, OVS_TUNNEL_KEY_ATTR_TP_SRC, tun_key->tp_src);
    }
    if (tun_key->tp_dst) {
        nl_msg_put_be16(a, OVS_TUNNEL_KEY_ATTR_TP_DST, tun_key->tp_dst);
    }
    if (tun_key->flags & FLOW_TNL_F_OAM) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_OAM);
    }

    /* If tnl_type is set to a particular type of output tunnel,
     * only put its relevant tunnel metadata to the nlattr.
     * If tnl_type is NULL, put tunnel metadata according to the
     * 'tun_key'.
     */
    if ((!tnl_type || !strcmp(tnl_type, "vxlan")) &&
        (tun_key->gbp_flags || tun_key->gbp_id)) {
        size_t vxlan_opts_ofs;

        vxlan_opts_ofs = nl_msg_start_nested(a, OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS);
        nl_msg_put_u32(a, OVS_VXLAN_EXT_GBP,
                       (tun_key->gbp_flags << 16) | ntohs(tun_key->gbp_id));
        nl_msg_end_nested(a, vxlan_opts_ofs);
    }

    if (!tnl_type || !strcmp(tnl_type, "geneve")) {
        tun_metadata_to_geneve_nlattr(tun_key, tun_flow_key, key_buf, a);
    }

    if ((!tnl_type || !strcmp(tnl_type, "erspan") ||
        !strcmp(tnl_type, "ip6erspan")) &&
        (tun_key->erspan_ver == 1 || tun_key->erspan_ver == 2)) {
        struct erspan_metadata *opts;

        opts = nl_msg_put_unspec_zero(a, OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS,
                                      sizeof *opts);
        opts->version = tun_key->erspan_ver;
        if (opts->version == 1) {
            opts->u.index = htonl(tun_key->erspan_idx);
        } else {
            opts->u.md2.dir = tun_key->erspan_dir;
            set_hwid(&opts->u.md2, tun_key->erspan_hwid);
        }
    }

    if ((!tnl_type || !strcmp(tnl_type, "gtpu")) &&
        (tun_key->gtpu_flags && tun_key->gtpu_msgtype)) {
        struct gtpu_metadata opts;

        opts.flags = tun_key->gtpu_flags;
        opts.msgtype = tun_key->gtpu_msgtype;
        nl_msg_put_unspec(a, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,
                          &opts, sizeof(opts));
    }
    nl_msg_end_nested(a, tun_key_ofs);
}

static bool
odp_mask_is_constant__(enum ovs_key_attr attr, const void *mask, size_t size,
                       int constant)
{
    /* Convert 'constant' to all the widths we need.  C conversion rules ensure
     * that -1 becomes all-1-bits and 0 does not change. */
    ovs_be16 be16 = (OVS_FORCE ovs_be16) constant;
    uint32_t u32 = constant;
    uint8_t u8 = constant;
    const struct in6_addr *in6 = constant ? &in6addr_exact : &in6addr_any;

    switch (attr) {
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case __OVS_KEY_ATTR_MAX:
    default:
        return false;

    case OVS_KEY_ATTR_PRIORITY:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_ETHERNET:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IPV4:
    case OVS_KEY_ATTR_TCP:
    case OVS_KEY_ATTR_UDP:
    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
    case OVS_KEY_ATTR_ND:
    case OVS_KEY_ATTR_ND_EXTENSIONS:
    case OVS_KEY_ATTR_SKB_MARK:
    case OVS_KEY_ATTR_TUNNEL:
    case OVS_KEY_ATTR_SCTP:
    case OVS_KEY_ATTR_DP_HASH:
    case OVS_KEY_ATTR_RECIRC_ID:
    case OVS_KEY_ATTR_MPLS:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case OVS_KEY_ATTR_PACKET_TYPE:
    case OVS_KEY_ATTR_NSH:
        return is_all_byte(mask, size, u8);

    case OVS_KEY_ATTR_TCP_FLAGS:
        return TCP_FLAGS(*(ovs_be16 *) mask) == TCP_FLAGS(be16);

    case OVS_KEY_ATTR_IPV6: {
        const struct ovs_key_ipv6 *ipv6_mask = mask;
        return ((ipv6_mask->ipv6_label & htonl(IPV6_LABEL_MASK))
                == htonl(IPV6_LABEL_MASK & u32)
                && ipv6_mask->ipv6_proto == u8
                && ipv6_mask->ipv6_tclass == u8
                && ipv6_mask->ipv6_hlimit == u8
                && ipv6_mask->ipv6_frag == u8
                && ipv6_addr_equals(&ipv6_mask->ipv6_src, in6)
                && ipv6_addr_equals(&ipv6_mask->ipv6_dst, in6));
    }

    case OVS_KEY_ATTR_ARP:
        return is_all_byte(mask, OFFSETOFEND(struct ovs_key_arp, arp_tha), u8);

    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
        return is_all_byte(mask, OFFSETOFEND(struct ovs_key_ct_tuple_ipv4,
                                             ipv4_proto), u8);

    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
        return is_all_byte(mask, OFFSETOFEND(struct ovs_key_ct_tuple_ipv6,
                                             ipv6_proto), u8);
    }
}

/* The caller must already have verified that 'ma' has a correct length.
 *
 * The main purpose of this function is formatting, to allow code to figure out
 * whether the mask can be omitted.  It doesn't try hard for attributes that
 * contain sub-attributes, etc., because normally those would be broken down
 * further for formatting. */
static bool
odp_mask_attr_is_wildcard(const struct nlattr *ma)
{
    return odp_mask_is_constant__(nl_attr_type(ma),
                                  nl_attr_get(ma), nl_attr_get_size(ma), 0);
}

/* The caller must already have verified that 'size' is a correct length for
 * 'attr'.
 *
 * The main purpose of this function is formatting, to allow code to figure out
 * whether the mask can be omitted.  It doesn't try hard for attributes that
 * contain sub-attributes, etc., because normally those would be broken down
 * further for formatting. */
static bool
odp_mask_is_exact(enum ovs_key_attr attr, const void *mask, size_t size)
{
    return odp_mask_is_constant__(attr, mask, size, -1);
}

/* The caller must already have verified that 'ma' has a correct length. */
static bool
odp_mask_attr_is_exact(const struct nlattr *ma)
{
    enum ovs_key_attr attr = nl_attr_type(ma);
    return odp_mask_is_exact(attr, nl_attr_get(ma), nl_attr_get_size(ma));
}

void
odp_portno_names_set(struct hmap *portno_names, odp_port_t port_no,
                     char *port_name)
{
    struct odp_portno_names *odp_portno_names;

    odp_portno_names = xmalloc(sizeof *odp_portno_names);
    odp_portno_names->port_no = port_no;
    odp_portno_names->name = xstrdup(port_name);
    hmap_insert(portno_names, &odp_portno_names->hmap_node,
                hash_odp_port(port_no));
}

static char *
odp_portno_names_get(const struct hmap *portno_names, odp_port_t port_no)
{
    if (portno_names) {
        struct odp_portno_names *odp_portno_names;

        HMAP_FOR_EACH_IN_BUCKET (odp_portno_names, hmap_node,
                                 hash_odp_port(port_no), portno_names) {
            if (odp_portno_names->port_no == port_no) {
                return odp_portno_names->name;
            }
        }
    }
    return NULL;
}

void
odp_portno_names_destroy(struct hmap *portno_names)
{
    struct odp_portno_names *odp_portno_names;

    HMAP_FOR_EACH_POP (odp_portno_names, hmap_node, portno_names) {
        free(odp_portno_names->name);
        free(odp_portno_names);
    }
}

void
odp_portno_name_format(const struct hmap *portno_names, odp_port_t port_no,
                       struct ds *s)
{
    const char *name = odp_portno_names_get(portno_names, port_no);
    if (name) {
        ds_put_cstr(s, name);
    } else {
        ds_put_format(s, "%"PRIu32, port_no);
    }
}

/* Format helpers. */

static void
format_eth(struct ds *ds, const char *name, const struct eth_addr key,
           const struct eth_addr *mask, bool verbose)
{
    bool mask_empty = mask && eth_addr_is_zero(*mask);

    if (verbose || !mask_empty) {
        bool mask_full = !mask || eth_mask_is_exact(*mask);

        if (mask_full) {
            ds_put_format(ds, "%s="ETH_ADDR_FMT",", name, ETH_ADDR_ARGS(key));
        } else {
            ds_put_format(ds, "%s=", name);
            eth_format_masked(key, mask, ds);
            ds_put_char(ds, ',');
        }
    }
}


static void
format_be64(struct ds *ds, const char *name, ovs_be64 key,
            const ovs_be64 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == OVS_BE64_MAX;

        ds_put_format(ds, "%s=0x%"PRIx64, name, ntohll(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx64, ntohll(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_ipv4(struct ds *ds, const char *name, ovs_be32 key,
            const ovs_be32 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == OVS_BE32_MAX;

        ds_put_format(ds, "%s="IP_FMT, name, IP_ARGS(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/"IP_FMT, IP_ARGS(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_in6_addr(struct ds *ds, const char *name,
                const struct in6_addr *key,
                const struct in6_addr *mask,
                bool verbose)
{
    char buf[INET6_ADDRSTRLEN];
    bool mask_empty = mask && ipv6_mask_is_any(mask);

    if (verbose || !mask_empty) {
        bool mask_full = !mask || ipv6_mask_is_exact(mask);

        inet_ntop(AF_INET6, key, buf, sizeof buf);
        ds_put_format(ds, "%s=%s", name, buf);
        if (!mask_full) { /* Partially masked. */
            inet_ntop(AF_INET6, mask, buf, sizeof buf);
            ds_put_format(ds, "/%s", buf);
        }
        ds_put_char(ds, ',');
    }
}

static void
format_ipv6_label(struct ds *ds, const char *name, ovs_be32 key,
                  const ovs_be32 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask
            || (*mask & htonl(IPV6_LABEL_MASK)) == htonl(IPV6_LABEL_MASK);

        ds_put_format(ds, "%s=%#"PRIx32, name, ntohl(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx32, ntohl(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_u8x(struct ds *ds, const char *name, uint8_t key,
           const uint8_t *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == UINT8_MAX;

        ds_put_format(ds, "%s=%#"PRIx8, name, key);
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx8, *mask);
        }
        ds_put_char(ds, ',');
    }
}

static void
format_u8u(struct ds *ds, const char *name, uint8_t key,
           const uint8_t *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == UINT8_MAX;

        ds_put_format(ds, "%s=%"PRIu8, name, key);
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx8, *mask);
        }
        ds_put_char(ds, ',');
    }
}

static void
format_be16(struct ds *ds, const char *name, ovs_be16 key,
            const ovs_be16 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == OVS_BE16_MAX;

        ds_put_format(ds, "%s=%"PRIu16, name, ntohs(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx16, ntohs(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_be16x(struct ds *ds, const char *name, ovs_be16 key,
             const ovs_be16 *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        bool mask_full = !mask || *mask == OVS_BE16_MAX;

        ds_put_format(ds, "%s=%#"PRIx16, name, ntohs(key));
        if (!mask_full) { /* Partially masked. */
            ds_put_format(ds, "/%#"PRIx16, ntohs(*mask));
        }
        ds_put_char(ds, ',');
    }
}

static void
format_tun_flags(struct ds *ds, const char *name, uint16_t key,
                 const uint16_t *mask, bool verbose)
{
    bool mask_empty = mask && !*mask;

    if (verbose || !mask_empty) {
        ds_put_cstr(ds, name);
        ds_put_char(ds, '(');
        if (mask) {
            format_flags_masked(ds, NULL, flow_tun_flag_to_string, key,
                                *mask & FLOW_TNL_F_MASK, FLOW_TNL_F_MASK);
        } else { /* Fully masked. */
            format_flags(ds, flow_tun_flag_to_string, key, '|');
        }
        ds_put_cstr(ds, "),");
    }
}

static bool
check_attr_len(struct ds *ds, const struct nlattr *a, const struct nlattr *ma,
               const struct attr_len_tbl tbl[], int max_type, bool need_key)
{
    int expected_len;

    expected_len = odp_key_attr_len(tbl, max_type, nl_attr_type(a));
    if (expected_len != ATTR_LEN_VARIABLE &&
        expected_len != ATTR_LEN_NESTED) {

        bool bad_key_len = nl_attr_get_size(a) != expected_len;
        bool bad_mask_len = ma && nl_attr_get_size(ma) != expected_len;

        if (bad_key_len || bad_mask_len) {
            if (need_key) {
                ds_put_format(ds, "key%u", nl_attr_type(a));
            }
            if (bad_key_len) {
                ds_put_format(ds, "(bad key length %"PRIuSIZE", expected %d)(",
                              nl_attr_get_size(a), expected_len);
            }
            format_generic_odp_key(a, ds);
            if (ma) {
                ds_put_char(ds, '/');
                if (bad_mask_len) {
                    ds_put_format(ds, "(bad mask length %"PRIuSIZE", expected %d)(",
                                  nl_attr_get_size(ma), expected_len);
                }
                format_generic_odp_key(ma, ds);
            }
            ds_put_char(ds, ')');
            return false;
        }
    }

    return true;
}

static void
format_unknown_key(struct ds *ds, const struct nlattr *a,
                   const struct nlattr *ma)
{
    ds_put_format(ds, "key%u(", nl_attr_type(a));
    format_generic_odp_key(a, ds);
    if (ma && !odp_mask_attr_is_exact(ma)) {
        ds_put_char(ds, '/');
        format_generic_odp_key(ma, ds);
    }
    ds_put_cstr(ds, "),");
}

static void
format_odp_tun_vxlan_opt(const struct nlattr *attr,
                         const struct nlattr *mask_attr, struct ds *ds,
                         bool verbose)
{
    unsigned int left;
    const struct nlattr *a;
    struct ofpbuf ofp;

    ofpbuf_init(&ofp, 100);
    NL_NESTED_FOR_EACH(a, left, attr) {
        uint16_t type = nl_attr_type(a);
        const struct nlattr *ma = NULL;

        if (mask_attr) {
            ma = nl_attr_find__(nl_attr_get(mask_attr),
                                nl_attr_get_size(mask_attr), type);
            if (!ma) {
                ma = generate_all_wildcard_mask(ovs_vxlan_ext_attr_lens,
                                                OVS_VXLAN_EXT_MAX,
                                                &ofp, a);
            }
        }

        if (!check_attr_len(ds, a, ma, ovs_vxlan_ext_attr_lens,
                            OVS_VXLAN_EXT_MAX, true)) {
            continue;
        }

        switch (type) {
        case OVS_VXLAN_EXT_GBP: {
            uint32_t key = nl_attr_get_u32(a);
            ovs_be16 id, id_mask;
            uint8_t flags, flags_mask = 0;

            id = htons(key & 0xFFFF);
            flags = (key >> 16) & 0xFF;
            if (ma) {
                uint32_t mask = nl_attr_get_u32(ma);
                id_mask = htons(mask & 0xFFFF);
                flags_mask = (mask >> 16) & 0xFF;
            }

            ds_put_cstr(ds, "gbp(");
            format_be16(ds, "id", id, ma ? &id_mask : NULL, verbose);
            format_u8x(ds, "flags", flags, ma ? &flags_mask : NULL, verbose);
            ds_chomp(ds, ',');
            ds_put_cstr(ds, "),");
            break;
        }

        default:
            format_unknown_key(ds, a, ma);
        }
        ofpbuf_clear(&ofp);
    }

    ds_chomp(ds, ',');
    ofpbuf_uninit(&ofp);
}

static void
format_odp_tun_erspan_opt(const struct nlattr *attr,
                          const struct nlattr *mask_attr, struct ds *ds,
                          bool verbose)
{
    const struct erspan_metadata *opts, *mask;
    uint8_t ver, ver_ma, dir, dir_ma, hwid, hwid_ma;

    opts = nl_attr_get(attr);
    mask = mask_attr ? nl_attr_get(mask_attr) : NULL;

    ver = (uint8_t)opts->version;
    if (mask) {
        ver_ma = (uint8_t)mask->version;
    }

    format_u8u(ds, "ver", ver, mask ? &ver_ma : NULL, verbose);

    if (opts->version == 1) {
        if (mask) {
            ds_put_format(ds, "idx=%#"PRIx32"/%#"PRIx32",",
                          ntohl(opts->u.index),
                          ntohl(mask->u.index));
        } else {
            ds_put_format(ds, "idx=%#"PRIx32",", ntohl(opts->u.index));
        }
    } else if (opts->version == 2) {
        dir = opts->u.md2.dir;
        hwid = opts->u.md2.hwid;
        if (mask) {
            dir_ma = mask->u.md2.dir;
            hwid_ma = mask->u.md2.hwid;
        }

        format_u8u(ds, "dir", dir, mask ? &dir_ma : NULL, verbose);
        format_u8x(ds, "hwid", hwid, mask ? &hwid_ma : NULL, verbose);
    }
    ds_chomp(ds, ',');
}

static void
format_odp_tun_gtpu_opt(const struct nlattr *attr,
                        const struct nlattr *mask_attr, struct ds *ds,
                        bool verbose)
{
    const struct gtpu_metadata *opts, *mask;

    opts = nl_attr_get(attr);
    mask = mask_attr ? nl_attr_get(mask_attr) : NULL;

    format_u8x(ds, "flags", opts->flags, mask ? &mask->flags : NULL, verbose);
    format_u8u(ds, "msgtype", opts->msgtype, mask ? &mask->msgtype : NULL,
               verbose);
    ds_chomp(ds, ',');
}

#define MASK(PTR, FIELD) PTR ? &PTR->FIELD : NULL

static void
format_geneve_opts(const struct geneve_opt *opt,
                   const struct geneve_opt *mask, int opts_len,
                   struct ds *ds, bool verbose)
{
    while (opts_len > 0) {
        unsigned int len;
        uint8_t data_len, data_len_mask;

        if (opts_len < sizeof *opt) {
            ds_put_format(ds, "opt len %u less than minimum %"PRIuSIZE,
                          opts_len, sizeof *opt);
            return;
        }

        data_len = opt->length * 4;
        if (mask) {
            if (mask->length == 0x1f) {
                data_len_mask = UINT8_MAX;
            } else {
                data_len_mask = mask->length;
            }
        }
        len = sizeof *opt + data_len;
        if (len > opts_len) {
            ds_put_format(ds, "opt len %u greater than remaining %u",
                          len, opts_len);
            return;
        }

        ds_put_char(ds, '{');
        format_be16x(ds, "class", opt->opt_class, MASK(mask, opt_class),
                    verbose);
        format_u8x(ds, "type", opt->type, MASK(mask, type), verbose);
        format_u8u(ds, "len", data_len, mask ? &data_len_mask : NULL, verbose);
        if (data_len &&
            (verbose || !mask || !is_all_zeros(mask + 1, data_len))) {
            ds_put_hex(ds, opt + 1, data_len);
            if (mask && !is_all_ones(mask + 1, data_len)) {
                ds_put_char(ds, '/');
                ds_put_hex(ds, mask + 1, data_len);
            }
        } else {
            ds_chomp(ds, ',');
        }
        ds_put_char(ds, '}');

        opt += len / sizeof(*opt);
        if (mask) {
            mask += len / sizeof(*opt);
        }
        opts_len -= len;
    };
}

static void
format_odp_tun_geneve(const struct nlattr *attr,
                      const struct nlattr *mask_attr, struct ds *ds,
                      bool verbose)
{
    int opts_len = nl_attr_get_size(attr);
    const struct geneve_opt *opt = nl_attr_get(attr);
    const struct geneve_opt *mask = mask_attr ?
                                    nl_attr_get(mask_attr) : NULL;

    if (mask && nl_attr_get_size(attr) != nl_attr_get_size(mask_attr)) {
        ds_put_format(ds, "value len %"PRIuSIZE" different from mask len %"PRIuSIZE,
                      nl_attr_get_size(attr), nl_attr_get_size(mask_attr));
        return;
    }

    format_geneve_opts(opt, mask, opts_len, ds, verbose);
}

static void
format_odp_nsh_attr(const struct nlattr *attr, const struct nlattr *mask_attr,
                    struct ds *ds)
{
    unsigned int left;
    const struct nlattr *a;
    struct ovs_key_nsh nsh;
    struct ovs_key_nsh nsh_mask;

    memset(&nsh, 0, sizeof nsh);
    memset(&nsh_mask, 0xff, sizeof nsh_mask);

    NL_NESTED_FOR_EACH (a, left, attr) {
        enum ovs_nsh_key_attr type = nl_attr_type(a);
        const struct nlattr *ma = NULL;

        if (mask_attr) {
            ma = nl_attr_find__(nl_attr_get(mask_attr),
                                nl_attr_get_size(mask_attr), type);
        }

        if (!check_attr_len(ds, a, ma, ovs_nsh_key_attr_lens,
                            OVS_NSH_KEY_ATTR_MAX, true)) {
            continue;
        }

        switch (type) {
        case OVS_NSH_KEY_ATTR_UNSPEC:
            break;
        case OVS_NSH_KEY_ATTR_BASE: {
            const struct ovs_nsh_key_base *base = nl_attr_get(a);
            const struct ovs_nsh_key_base *base_mask
                = ma ? nl_attr_get(ma) : NULL;
            nsh.flags = base->flags;
            nsh.ttl = base->ttl;
            nsh.mdtype = base->mdtype;
            nsh.np = base->np;
            nsh.path_hdr = base->path_hdr;
            if (base_mask) {
                nsh_mask.flags = base_mask->flags;
                nsh_mask.ttl = base_mask->ttl;
                nsh_mask.mdtype = base_mask->mdtype;
                nsh_mask.np = base_mask->np;
                nsh_mask.path_hdr = base_mask->path_hdr;
            }
            break;
        }
        case OVS_NSH_KEY_ATTR_MD1: {
            const struct ovs_nsh_key_md1 *md1 = nl_attr_get(a);
            const struct ovs_nsh_key_md1 *md1_mask
                = ma ? nl_attr_get(ma) : NULL;
            memcpy(nsh.context, md1->context, sizeof md1->context);
            if (md1_mask) {
                memcpy(nsh_mask.context, md1_mask->context,
                       sizeof md1_mask->context);
            }
            break;
        }
        case OVS_NSH_KEY_ATTR_MD2:
        case __OVS_NSH_KEY_ATTR_MAX:
        default:
            /* No support for matching other metadata formats yet. */
            break;
        }
    }

    if (mask_attr) {
        format_nsh_key_mask(ds, &nsh, &nsh_mask);
    } else {
        format_nsh_key(ds, &nsh);
    }
}

static void
format_odp_tun_attr(const struct nlattr *attr, const struct nlattr *mask_attr,
                    struct ds *ds, bool verbose)
{
    unsigned int left;
    const struct nlattr *a;
    uint16_t flags = 0;
    uint16_t mask_flags = 0;
    struct ofpbuf ofp;

    ofpbuf_init(&ofp, 100);
    NL_NESTED_FOR_EACH(a, left, attr) {
        enum ovs_tunnel_key_attr type = nl_attr_type(a);
        const struct nlattr *ma = NULL;

        if (mask_attr) {
            ma = nl_attr_find__(nl_attr_get(mask_attr),
                                nl_attr_get_size(mask_attr), type);
            if (!ma) {
                ma = generate_all_wildcard_mask(ovs_tun_key_attr_lens,
                                                OVS_TUNNEL_KEY_ATTR_MAX,
                                                &ofp, a);
            }
        }

        if (!check_attr_len(ds, a, ma, ovs_tun_key_attr_lens,
                            OVS_TUNNEL_KEY_ATTR_MAX, true)) {
            continue;
        }

        switch (type) {
        case OVS_TUNNEL_KEY_ATTR_ID:
            format_be64(ds, "tun_id", nl_attr_get_be64(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
            flags |= FLOW_TNL_F_KEY;
            if (ma) {
                mask_flags |= FLOW_TNL_F_KEY;
            }
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
            format_ipv4(ds, "src", nl_attr_get_be32(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_DST:
            format_ipv4(ds, "dst", nl_attr_get_be32(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV6_SRC: {
            struct in6_addr ipv6_src;
            ipv6_src = nl_attr_get_in6_addr(a);
            format_in6_addr(ds, "ipv6_src", &ipv6_src,
                            ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        }
        case OVS_TUNNEL_KEY_ATTR_IPV6_DST: {
            struct in6_addr ipv6_dst;
            ipv6_dst = nl_attr_get_in6_addr(a);
            format_in6_addr(ds, "ipv6_dst", &ipv6_dst,
                            ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        }
        case OVS_TUNNEL_KEY_ATTR_TOS:
            format_u8x(ds, "tos", nl_attr_get_u8(a),
                       ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_TTL:
            format_u8u(ds, "ttl", nl_attr_get_u8(a),
                       ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
            flags |= FLOW_TNL_F_DONT_FRAGMENT;
            break;
        case OVS_TUNNEL_KEY_ATTR_CSUM:
            flags |= FLOW_TNL_F_CSUM;
            break;
        case OVS_TUNNEL_KEY_ATTR_TP_SRC:
            format_be16(ds, "tp_src", nl_attr_get_be16(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_TP_DST:
            format_be16(ds, "tp_dst", nl_attr_get_be16(a),
                        ma ? nl_attr_get(ma) : NULL, verbose);
            break;
        case OVS_TUNNEL_KEY_ATTR_OAM:
            flags |= FLOW_TNL_F_OAM;
            break;
        case OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS:
            ds_put_cstr(ds, "vxlan(");
            format_odp_tun_vxlan_opt(a, ma, ds, verbose);
            ds_put_cstr(ds, "),");
            break;
        case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
            ds_put_cstr(ds, "geneve(");
            format_odp_tun_geneve(a, ma, ds, verbose);
            ds_put_cstr(ds, "),");
            break;
        case OVS_TUNNEL_KEY_ATTR_PAD:
            break;
        case OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS:
            ds_put_cstr(ds, "erspan(");
            format_odp_tun_erspan_opt(a, ma, ds, verbose);
            ds_put_cstr(ds, "),");
            break;
        case OVS_TUNNEL_KEY_ATTR_GTPU_OPTS:
            ds_put_cstr(ds, "gtpu(");
            format_odp_tun_gtpu_opt(a, ma, ds, verbose);
            ds_put_cstr(ds, "),");
            break;
        case __OVS_TUNNEL_KEY_ATTR_MAX:
        default:
            format_unknown_key(ds, a, ma);
        }
        ofpbuf_clear(&ofp);
    }

    /* Flags can have a valid mask even if the attribute is not set, so
     * we need to collect these separately. */
    if (mask_attr) {
        NL_NESTED_FOR_EACH(a, left, mask_attr) {
            switch (nl_attr_type(a)) {
            case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
                mask_flags |= FLOW_TNL_F_DONT_FRAGMENT;
                break;
            case OVS_TUNNEL_KEY_ATTR_CSUM:
                mask_flags |= FLOW_TNL_F_CSUM;
                break;
            case OVS_TUNNEL_KEY_ATTR_OAM:
                mask_flags |= FLOW_TNL_F_OAM;
                break;
            }
        }
    }

    format_tun_flags(ds, "flags", flags, mask_attr ? &mask_flags : NULL,
                     verbose);
    ds_chomp(ds, ',');
    ofpbuf_uninit(&ofp);
}

static const char *
odp_ct_state_to_string(uint32_t flag)
{
    switch (flag) {
    case OVS_CS_F_REPLY_DIR:
        return "rpl";
    case OVS_CS_F_TRACKED:
        return "trk";
    case OVS_CS_F_NEW:
        return "new";
    case OVS_CS_F_ESTABLISHED:
        return "est";
    case OVS_CS_F_RELATED:
        return "rel";
    case OVS_CS_F_INVALID:
        return "inv";
    case OVS_CS_F_SRC_NAT:
        return "snat";
    case OVS_CS_F_DST_NAT:
        return "dnat";
    default:
        return NULL;
    }
}

static void
format_frag(struct ds *ds, const char *name, uint8_t key,
            const uint8_t *mask, bool verbose OVS_UNUSED)
{
    bool mask_empty = mask && !*mask;
    bool mask_full = !mask || *mask == UINT8_MAX;

    /* ODP frag is an enumeration field; partial masks are not meaningful. */
    if (!mask_empty && !mask_full) {
        ds_put_format(ds, "error: partial mask not supported for frag (%#"
                      PRIx8"),", *mask);
    } else if (!mask_empty) {
        ds_put_format(ds, "%s=%s,", name, ovs_frag_type_to_string(key));
    }
}

static bool
mask_empty(const struct nlattr *ma)
{
    const void *mask;
    size_t n;

    if (!ma) {
        return true;
    }
    mask = nl_attr_get(ma);
    n = nl_attr_get_size(ma);

    return is_all_zeros(mask, n);
}

/* The caller must have already verified that 'a' and 'ma' have correct
 * lengths. */
static void
format_odp_key_attr__(const struct nlattr *a, const struct nlattr *ma,
                      const struct hmap *portno_names, struct ds *ds,
                      bool verbose)
{
    enum ovs_key_attr attr = nl_attr_type(a);
    char namebuf[OVS_KEY_ATTR_BUFSIZE];
    bool is_exact;

    is_exact = ma ? odp_mask_attr_is_exact(ma) : true;

    ds_put_cstr(ds, ovs_key_attr_to_string(attr, namebuf, sizeof namebuf));

    ds_put_char(ds, '(');
    switch (attr) {
    case OVS_KEY_ATTR_ENCAP:
        if (ma && nl_attr_get_size(ma) && nl_attr_get_size(a)) {
            odp_flow_format(nl_attr_get(a), nl_attr_get_size(a),
                            nl_attr_get(ma), nl_attr_get_size(ma), NULL, ds,
                            verbose);
        } else if (nl_attr_get_size(a)) {
            odp_flow_format(nl_attr_get(a), nl_attr_get_size(a), NULL, 0, NULL,
                            ds, verbose);
        }
        break;

    case OVS_KEY_ATTR_PRIORITY:
    case OVS_KEY_ATTR_SKB_MARK:
    case OVS_KEY_ATTR_DP_HASH:
    case OVS_KEY_ATTR_RECIRC_ID:
        ds_put_format(ds, "%#"PRIx32, nl_attr_get_u32(a));
        if (!is_exact) {
            ds_put_format(ds, "/%#"PRIx32, nl_attr_get_u32(ma));
        }
        break;

    case OVS_KEY_ATTR_CT_MARK:
        if (verbose || !mask_empty(ma)) {
            ds_put_format(ds, "%#"PRIx32, nl_attr_get_u32(a));
            if (!is_exact) {
                ds_put_format(ds, "/%#"PRIx32, nl_attr_get_u32(ma));
            }
        }
        break;

    case OVS_KEY_ATTR_CT_STATE:
        if (verbose) {
                ds_put_format(ds, "%#"PRIx32, nl_attr_get_u32(a));
                if (!is_exact) {
                    ds_put_format(ds, "/%#"PRIx32,
                                  mask_empty(ma) ? 0 : nl_attr_get_u32(ma));
                }
        } else if (!is_exact) {
            format_flags_masked(ds, NULL, odp_ct_state_to_string,
                                nl_attr_get_u32(a),
                                mask_empty(ma) ? 0 : nl_attr_get_u32(ma),
                                UINT32_MAX);
        } else {
            format_flags(ds, odp_ct_state_to_string, nl_attr_get_u32(a), '|');
        }
        break;

    case OVS_KEY_ATTR_CT_ZONE:
        if (verbose || !mask_empty(ma)) {
            ds_put_format(ds, "%#"PRIx16, nl_attr_get_u16(a));
            if (!is_exact) {
                ds_put_format(ds, "/%#"PRIx16, nl_attr_get_u16(ma));
            }
        }
        break;

    case OVS_KEY_ATTR_CT_LABELS: {
        const ovs_32aligned_u128 *value = nl_attr_get(a);
        const ovs_32aligned_u128 *mask = ma ? nl_attr_get(ma) : NULL;

        format_u128(ds, value, mask, verbose);
        break;
    }

    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4: {
        const struct ovs_key_ct_tuple_ipv4 *key = nl_attr_get(a);
        const struct ovs_key_ct_tuple_ipv4 *mask = ma ? nl_attr_get(ma) : NULL;

        format_ipv4(ds, "src", key->ipv4_src, MASK(mask, ipv4_src), verbose);
        format_ipv4(ds, "dst", key->ipv4_dst, MASK(mask, ipv4_dst), verbose);
        format_u8u(ds, "proto", key->ipv4_proto, MASK(mask, ipv4_proto),
                   verbose);
        format_be16(ds, "tp_src", key->src_port, MASK(mask, src_port),
                    verbose);
        format_be16(ds, "tp_dst", key->dst_port, MASK(mask, dst_port),
                    verbose);
        ds_chomp(ds, ',');
        break;
    }

    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6: {
        const struct ovs_key_ct_tuple_ipv6 *key = nl_attr_get(a);
        const struct ovs_key_ct_tuple_ipv6 *mask = ma ? nl_attr_get(ma) : NULL;

        format_in6_addr(ds, "src", &key->ipv6_src, MASK(mask, ipv6_src),
                        verbose);
        format_in6_addr(ds, "dst", &key->ipv6_dst, MASK(mask, ipv6_dst),
                        verbose);
        format_u8u(ds, "proto", key->ipv6_proto, MASK(mask, ipv6_proto),
                   verbose);
        format_be16(ds, "src_port", key->src_port, MASK(mask, src_port),
                    verbose);
        format_be16(ds, "dst_port", key->dst_port, MASK(mask, dst_port),
                    verbose);
        ds_chomp(ds, ',');
        break;
    }

    case OVS_KEY_ATTR_TUNNEL:
        format_odp_tun_attr(a, ma, ds, verbose);
        break;

    case OVS_KEY_ATTR_IN_PORT:
        if (is_exact) {
            odp_portno_name_format(portno_names, nl_attr_get_odp_port(a), ds);
        } else {
            ds_put_format(ds, "%"PRIu32, nl_attr_get_u32(a));
            if (!is_exact) {
                ds_put_format(ds, "/%#"PRIx32, nl_attr_get_u32(ma));
            }
        }
        break;

    case OVS_KEY_ATTR_PACKET_TYPE: {
        ovs_be32 value = nl_attr_get_be32(a);
        ovs_be32 mask = ma ? nl_attr_get_be32(ma) : OVS_BE32_MAX;

        ovs_be16 ns = htons(pt_ns(value));
        ovs_be16 ns_mask = htons(pt_ns(mask));
        format_be16(ds, "ns", ns, &ns_mask, verbose);

        ovs_be16 ns_type = pt_ns_type_be(value);
        ovs_be16 ns_type_mask = pt_ns_type_be(mask);
        format_be16x(ds, "id", ns_type, &ns_type_mask, verbose);

        ds_chomp(ds, ',');
        break;
    }

    case OVS_KEY_ATTR_ETHERNET: {
        const struct ovs_key_ethernet *mask = ma ? nl_attr_get(ma) : NULL;
        const struct ovs_key_ethernet *key = nl_attr_get(a);

        format_eth(ds, "src", key->eth_src, MASK(mask, eth_src), verbose);
        format_eth(ds, "dst", key->eth_dst, MASK(mask, eth_dst), verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_VLAN:
        format_vlan_tci(ds, nl_attr_get_be16(a),
                        ma ? nl_attr_get_be16(ma) : OVS_BE16_MAX, verbose);
        break;

    case OVS_KEY_ATTR_MPLS: {
        const struct ovs_key_mpls *mpls_key = nl_attr_get(a);
        const struct ovs_key_mpls *mpls_mask = NULL;
        size_t size = nl_attr_get_size(a);

        if (!size || size % sizeof *mpls_key) {
            ds_put_format(ds, "(bad key length %"PRIuSIZE")", size);
            return;
        }
        if (!is_exact) {
            mpls_mask = nl_attr_get(ma);
            if (size != nl_attr_get_size(ma)) {
                ds_put_format(ds, "(key length %"PRIuSIZE" != "
                              "mask length %"PRIuSIZE")",
                              size, nl_attr_get_size(ma));
                return;
            }
        }
        format_mpls(ds, mpls_key, mpls_mask, size / sizeof *mpls_key);
        break;
    }
    case OVS_KEY_ATTR_ETHERTYPE:
        ds_put_format(ds, "0x%04"PRIx16, ntohs(nl_attr_get_be16(a)));
        if (!is_exact) {
            ds_put_format(ds, "/0x%04"PRIx16, ntohs(nl_attr_get_be16(ma)));
        }
        break;

    case OVS_KEY_ATTR_IPV4: {
        const struct ovs_key_ipv4 *key = nl_attr_get(a);
        const struct ovs_key_ipv4 *mask = ma ? nl_attr_get(ma) : NULL;

        format_ipv4(ds, "src", key->ipv4_src, MASK(mask, ipv4_src), verbose);
        format_ipv4(ds, "dst", key->ipv4_dst, MASK(mask, ipv4_dst), verbose);
        format_u8u(ds, "proto", key->ipv4_proto, MASK(mask, ipv4_proto),
                      verbose);
        format_u8x(ds, "tos", key->ipv4_tos, MASK(mask, ipv4_tos), verbose);
        format_u8u(ds, "ttl", key->ipv4_ttl, MASK(mask, ipv4_ttl), verbose);
        format_frag(ds, "frag", key->ipv4_frag, MASK(mask, ipv4_frag),
                    verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_IPV6: {
        const struct ovs_key_ipv6 *key = nl_attr_get(a);
        const struct ovs_key_ipv6 *mask = ma ? nl_attr_get(ma) : NULL;

        format_in6_addr(ds, "src", &key->ipv6_src, MASK(mask, ipv6_src),
                        verbose);
        format_in6_addr(ds, "dst", &key->ipv6_dst, MASK(mask, ipv6_dst),
                        verbose);
        format_ipv6_label(ds, "label", key->ipv6_label, MASK(mask, ipv6_label),
                          verbose);
        format_u8u(ds, "proto", key->ipv6_proto, MASK(mask, ipv6_proto),
                   verbose);
        format_u8x(ds, "tclass", key->ipv6_tclass, MASK(mask, ipv6_tclass),
                   verbose);
        format_u8u(ds, "hlimit", key->ipv6_hlimit, MASK(mask, ipv6_hlimit),
                   verbose);
        format_frag(ds, "frag", key->ipv6_frag, MASK(mask, ipv6_frag),
                    verbose);
        ds_chomp(ds, ',');
        break;
    }
        /* These have the same structure and format. */
    case OVS_KEY_ATTR_TCP:
    case OVS_KEY_ATTR_UDP:
    case OVS_KEY_ATTR_SCTP: {
        const struct ovs_key_tcp *key = nl_attr_get(a);
        const struct ovs_key_tcp *mask = ma ? nl_attr_get(ma) : NULL;

        format_be16(ds, "src", key->tcp_src, MASK(mask, tcp_src), verbose);
        format_be16(ds, "dst", key->tcp_dst, MASK(mask, tcp_dst), verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_TCP_FLAGS:
        if (!is_exact) {
            format_flags_masked(ds, NULL, packet_tcp_flag_to_string,
                                ntohs(nl_attr_get_be16(a)),
                                TCP_FLAGS(nl_attr_get_be16(ma)),
                                TCP_FLAGS(OVS_BE16_MAX));
        } else {
            format_flags(ds, packet_tcp_flag_to_string,
                         ntohs(nl_attr_get_be16(a)), '|');
        }
        break;

    case OVS_KEY_ATTR_ICMP: {
        const struct ovs_key_icmp *key = nl_attr_get(a);
        const struct ovs_key_icmp *mask = ma ? nl_attr_get(ma) : NULL;

        format_u8u(ds, "type", key->icmp_type, MASK(mask, icmp_type), verbose);
        format_u8u(ds, "code", key->icmp_code, MASK(mask, icmp_code), verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_ICMPV6: {
        const struct ovs_key_icmpv6 *key = nl_attr_get(a);
        const struct ovs_key_icmpv6 *mask = ma ? nl_attr_get(ma) : NULL;

        format_u8u(ds, "type", key->icmpv6_type, MASK(mask, icmpv6_type),
                   verbose);
        format_u8u(ds, "code", key->icmpv6_code, MASK(mask, icmpv6_code),
                   verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_ARP: {
        const struct ovs_key_arp *mask = ma ? nl_attr_get(ma) : NULL;
        const struct ovs_key_arp *key = nl_attr_get(a);

        format_ipv4(ds, "sip", key->arp_sip, MASK(mask, arp_sip), verbose);
        format_ipv4(ds, "tip", key->arp_tip, MASK(mask, arp_tip), verbose);
        format_be16(ds, "op", key->arp_op, MASK(mask, arp_op), verbose);
        format_eth(ds, "sha", key->arp_sha, MASK(mask, arp_sha), verbose);
        format_eth(ds, "tha", key->arp_tha, MASK(mask, arp_tha), verbose);
        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_ND: {
        const struct ovs_key_nd *mask = ma ? nl_attr_get(ma) : NULL;
        const struct ovs_key_nd *key = nl_attr_get(a);

        format_in6_addr(ds, "target", &key->nd_target, MASK(mask, nd_target),
                        verbose);
        format_eth(ds, "sll", key->nd_sll, MASK(mask, nd_sll), verbose);
        format_eth(ds, "tll", key->nd_tll, MASK(mask, nd_tll), verbose);

        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_ND_EXTENSIONS: {
        const struct ovs_key_nd_extensions *mask = ma ? nl_attr_get(ma) : NULL;
        const struct ovs_key_nd_extensions *key = nl_attr_get(a);

        bool first = true;
        format_be32_masked(ds, &first, "nd_reserved", key->nd_reserved,
                           OVS_BE32_MAX);
        ds_put_char(ds, ',');

        format_u8u(ds, "nd_options_type", key->nd_options_type,
                   MASK(mask, nd_options_type), verbose);

        ds_chomp(ds, ',');
        break;
    }
    case OVS_KEY_ATTR_NSH: {
        format_odp_nsh_attr(a, ma, ds);
        break;
    }
    case OVS_KEY_ATTR_UNSPEC:
    case __OVS_KEY_ATTR_MAX:
    default:
        format_generic_odp_key(a, ds);
        if (!is_exact) {
            ds_put_char(ds, '/');
            format_generic_odp_key(ma, ds);
        }
        break;
    }
    ds_put_char(ds, ')');
}

static void
format_odp_key_attr(const struct nlattr *a, const struct nlattr *ma,
                    const struct hmap *portno_names, struct ds *ds,
                    bool verbose)
{
    if (check_attr_len(ds, a, ma, ovs_flow_key_attr_lens,
                        OVS_KEY_ATTR_MAX, false)) {
        format_odp_key_attr__(a, ma, portno_names, ds, verbose);
    }
}

static struct nlattr *
generate_all_wildcard_mask(const struct attr_len_tbl tbl[], int max,
                           struct ofpbuf *ofp, const struct nlattr *key)
{
    const struct nlattr *a;
    unsigned int left;
    int type = nl_attr_type(key);
    int size = nl_attr_get_size(key);

    if (odp_key_attr_len(tbl, max, type) != ATTR_LEN_NESTED) {
        nl_msg_put_unspec_zero(ofp, type, size);
    } else {
        size_t nested_mask;

        if (tbl[type].next) {
            const struct attr_len_tbl *entry = &tbl[type];
            tbl = entry->next;
            max = entry->next_max;
        }

        nested_mask = nl_msg_start_nested(ofp, type);
        NL_ATTR_FOR_EACH(a, left, key, nl_attr_get_size(key)) {
            generate_all_wildcard_mask(tbl, max, ofp, nl_attr_get(a));
        }
        nl_msg_end_nested(ofp, nested_mask);
    }

    return ofp->base;
}

static void
format_u128(struct ds *ds, const ovs_32aligned_u128 *key,
            const ovs_32aligned_u128 *mask, bool verbose)
{
    if (verbose || (mask && !ovs_u128_is_zero(get_32aligned_u128(mask)))) {
        ovs_be128 value = hton128(get_32aligned_u128(key));
        ds_put_hex(ds, &value, sizeof value);
        if (mask && !(ovs_u128_is_ones(get_32aligned_u128(mask)))) {
            value = hton128(get_32aligned_u128(mask));
            ds_put_char(ds, '/');
            ds_put_hex(ds, &value, sizeof value);
        }
    }
}

/* Read the string from 's_' as a 128-bit value.  If the string contains
 * a "/", the rest of the string will be treated as a 128-bit mask.
 *
 * If either the value or mask is larger than 64 bits, the string must
 * be in hexadecimal.
 */
static int
scan_u128(const char *s_, ovs_u128 *value, ovs_u128 *mask)
{
    char *s = CONST_CAST(char *, s_);
    ovs_be128 be_value;
    ovs_be128 be_mask;

    if (!parse_int_string(s, (uint8_t *)&be_value, sizeof be_value, &s)) {
        *value = ntoh128(be_value);

        if (mask) {
            int n;

            if (ovs_scan(s, "/%n", &n)) {
                int error;

                s += n;
                error = parse_int_string(s, (uint8_t *)&be_mask,
                                         sizeof be_mask, &s);
                if (error) {
                    return 0;
                }
                *mask = ntoh128(be_mask);
            } else {
                *mask = OVS_U128_MAX;
            }
        }
        return s - s_;
    }

    return 0;
}

int
odp_ufid_from_string(const char *s_, ovs_u128 *ufid)
{
    const char *s = s_;

    if (ovs_scan(s, "ufid:")) {
        s += 5;

        if (!uuid_from_string_prefix((struct uuid *)ufid, s)) {
            return -EINVAL;
        }
        s += UUID_LEN;

        return s - s_;
    }

    return 0;
}

void
odp_format_ufid(const ovs_u128 *ufid, struct ds *ds)
{
    ds_put_format(ds, "ufid:"UUID_FMT, UUID_ARGS((struct uuid *)ufid));
}

/* Appends to 'ds' a string representation of the 'key_len' bytes of
 * OVS_KEY_ATTR_* attributes in 'key'. If non-null, additionally formats the
 * 'mask_len' bytes of 'mask' which apply to 'key'. If 'portno_names' is
 * non-null, translates odp port number to its name. */
void
odp_flow_format(const struct nlattr *key, size_t key_len,
                const struct nlattr *mask, size_t mask_len,
                const struct hmap *portno_names, struct ds *ds, bool verbose)
{
    if (key_len) {
        const struct nlattr *a;
        unsigned int left;
        bool has_ethtype_key = false;
        bool has_packet_type_key = false;
        struct ofpbuf ofp;
        bool first_field = true;

        ofpbuf_init(&ofp, 100);
        NL_ATTR_FOR_EACH (a, left, key, key_len) {
            int attr_type = nl_attr_type(a);
            const struct nlattr *ma = (mask && mask_len
                                       ? nl_attr_find__(mask, mask_len,
                                                        attr_type)
                                       : NULL);
            if (!check_attr_len(ds, a, ma, ovs_flow_key_attr_lens,
                                OVS_KEY_ATTR_MAX, false)) {
                continue;
            }

            bool is_nested_attr;
            bool is_wildcard = false;

            if (attr_type == OVS_KEY_ATTR_ETHERTYPE) {
                has_ethtype_key = true;
            } else if (attr_type == OVS_KEY_ATTR_PACKET_TYPE) {
                has_packet_type_key = true;
            }

            is_nested_attr = odp_key_attr_len(ovs_flow_key_attr_lens,
                                              OVS_KEY_ATTR_MAX, attr_type) ==
                             ATTR_LEN_NESTED;

            if (mask && mask_len) {
                ma = nl_attr_find__(mask, mask_len, nl_attr_type(a));
                is_wildcard = ma ? odp_mask_attr_is_wildcard(ma) : true;
            }

            if (verbose || !is_wildcard  || is_nested_attr) {
                if (is_wildcard && !ma) {
                    ma = generate_all_wildcard_mask(ovs_flow_key_attr_lens,
                                                    OVS_KEY_ATTR_MAX,
                                                    &ofp, a);
                }
                if (!first_field) {
                    ds_put_char(ds, ',');
                }
                format_odp_key_attr__(a, ma, portno_names, ds, verbose);
                first_field = false;
            } else if (attr_type == OVS_KEY_ATTR_ETHERNET
                       && !has_packet_type_key) {
                /* This special case reflects differences between the kernel
                 * and userspace datapaths regarding the root type of the
                 * packet being matched (typically Ethernet but some tunnels
                 * can encapsulate IPv4 etc.).  The kernel datapath does not
                 * have an explicit way to indicate packet type; instead:
                 *
                 *   - If OVS_KEY_ATTR_ETHERNET is present, the packet is an
                 *     Ethernet packet and OVS_KEY_ATTR_ETHERTYPE is the
                 *     Ethertype encoded in the Ethernet header.
                 *
                 *   - If OVS_KEY_ATTR_ETHERNET is absent, then the packet's
                 *     root type is that encoded in OVS_KEY_ATTR_ETHERTYPE
                 *     (i.e. if OVS_KEY_ATTR_ETHERTYPE is 0x0800 then the
                 *     packet is an IPv4 packet).
                 *
                 * Thus, if OVS_KEY_ATTR_ETHERNET is present, even if it is
                 * all-wildcarded, it is important to print it.
                 *
                 * On the other hand, the userspace datapath supports
                 * OVS_KEY_ATTR_PACKET_TYPE and uses it to indicate the packet
                 * type.  Thus, if OVS_KEY_ATTR_PACKET_TYPE is present, we need
                 * not print an all-wildcarded OVS_KEY_ATTR_ETHERNET. */
                if (!first_field) {
                    ds_put_char(ds, ',');
                }
                ds_put_cstr(ds, "eth()");
            }
            ofpbuf_clear(&ofp);
        }
        ofpbuf_uninit(&ofp);

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
        if (!has_ethtype_key) {
            const struct nlattr *ma = nl_attr_find__(mask, mask_len,
                                                     OVS_KEY_ATTR_ETHERTYPE);
            if (ma) {
                ds_put_format(ds, ",eth_type(0/0x%04"PRIx16")",
                              ntohs(nl_attr_get_be16(ma)));
            }
        }
    } else {
        ds_put_cstr(ds, "<empty>");
    }
}

/* Appends to 'ds' a string representation of the 'key_len' bytes of
 * OVS_KEY_ATTR_* attributes in 'key'. */
void
odp_flow_key_format(const struct nlattr *key,
                    size_t key_len, struct ds *ds)
{
    odp_flow_format(key, key_len, NULL, 0, NULL, ds, true);
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

/* Parsing. */

static int
scan_eth(const char *s, struct eth_addr *key, struct eth_addr *mask)
{
    int n;

    if (ovs_scan(s, ETH_ADDR_SCAN_FMT"%n",
                 ETH_ADDR_SCAN_ARGS(*key), &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/"ETH_ADDR_SCAN_FMT"%n",
                         ETH_ADDR_SCAN_ARGS(*mask), &n)) {
                len += n;
            } else {
                memset(mask, 0xff, sizeof *mask);
            }
        }
        return len;
    }
    return 0;
}

static int
scan_ipv4(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    int n;

    if (ovs_scan(s, IP_SCAN_FMT"%n", IP_SCAN_ARGS(key), &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/"IP_SCAN_FMT"%n",
                         IP_SCAN_ARGS(mask), &n)) {
                len += n;
            } else {
                *mask = OVS_BE32_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_in6_addr(const char *s, struct in6_addr *key, struct in6_addr *mask)
{
    int n;
    char ipv6_s[IPV6_SCAN_LEN + 1];

    if (ovs_scan(s, IPV6_SCAN_FMT"%n", ipv6_s, &n)
        && inet_pton(AF_INET6, ipv6_s, key) == 1) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/"IPV6_SCAN_FMT"%n", ipv6_s, &n)
                && inet_pton(AF_INET6, ipv6_s, mask) == 1) {
                len += n;
            } else {
                memset(mask, 0xff, sizeof *mask);
            }
        }
        return len;
    }
    return 0;
}

static int
scan_ipv6_label(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    int key_, mask_;
    int n;

    if (ovs_scan(s, "%i%n", &key_, &n)
        && (key_ & ~IPV6_LABEL_MASK) == 0) {
        int len = n;

        *key = htonl(key_);
        if (mask) {
            if (ovs_scan(s + len, "/%i%n", &mask_, &n)
                && (mask_ & ~IPV6_LABEL_MASK) == 0) {
                len += n;
                *mask = htonl(mask_);
            } else {
                *mask = htonl(IPV6_LABEL_MASK);
            }
        }
        return len;
    }
    return 0;
}

static int
scan_u8(const char *s, uint8_t *key, uint8_t *mask)
{
    int n;

    if (ovs_scan(s, "%"SCNi8"%n", key, &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi8"%n", mask, &n)) {
                len += n;
            } else {
                *mask = UINT8_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_u16(const char *s, uint16_t *key, uint16_t *mask)
{
    int n;

    if (ovs_scan(s, "%"SCNi16"%n", key, &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi16"%n", mask, &n)) {
                len += n;
            } else {
                *mask = UINT16_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_u32(const char *s, uint32_t *key, uint32_t *mask)
{
    int n;

    if (ovs_scan(s, "%"SCNi32"%n", key, &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi32"%n", mask, &n)) {
                len += n;
            } else {
                *mask = UINT32_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_be16(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    uint16_t key_, mask_;
    int n;

    if (ovs_scan(s, "%"SCNi16"%n", &key_, &n)) {
        int len = n;

        *key = htons(key_);
        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi16"%n", &mask_, &n)) {
                len += n;
                *mask = htons(mask_);
            } else {
                *mask = OVS_BE16_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_be32(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    uint32_t key_, mask_;
    int n;

    if (ovs_scan(s, "%"SCNi32"%n", &key_, &n)) {
        int len = n;

        *key = htonl(key_);
        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi32"%n", &mask_, &n)) {
                len += n;
                *mask = htonl(mask_);
            } else {
                *mask = OVS_BE32_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_be64(const char *s, ovs_be64 *key, ovs_be64 *mask)
{
    uint64_t key_, mask_;
    int n;

    if (ovs_scan(s, "%"SCNi64"%n", &key_, &n)) {
        int len = n;

        *key = htonll(key_);
        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi64"%n", &mask_, &n)) {
                len += n;
                *mask = htonll(mask_);
            } else {
                *mask = OVS_BE64_MAX;
            }
        }
        return len;
    }
    return 0;
}

static int
scan_tun_flags(const char *s, uint16_t *key, uint16_t *mask)
{
    uint32_t flags, fmask;
    int n;

    n = parse_odp_flags(s, flow_tun_flag_to_string, &flags,
                        FLOW_TNL_F_MASK, mask ? &fmask : NULL);
    if (n >= 0 && s[n] == ')') {
        *key = flags;
        if (mask) {
            *mask = fmask;
        }
        return n + 1;
    }
    return 0;
}

static int
scan_tcp_flags(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    uint32_t flags, fmask;
    int n;

    n = parse_odp_flags(s, packet_tcp_flag_to_string, &flags,
                        TCP_FLAGS(OVS_BE16_MAX), mask ? &fmask : NULL);
    if (n >= 0) {
        *key = htons(flags);
        if (mask) {
            *mask = htons(fmask);
        }
        return n;
    }
    return 0;
}

static uint32_t
ovs_to_odp_ct_state(uint8_t state)
{
    uint32_t odp = 0;

#define CS_STATE(ENUM, INDEX, NAME)             \
    if (state & CS_##ENUM) {                    \
        odp |= OVS_CS_F_##ENUM;                 \
    }
    CS_STATES
#undef CS_STATE

    return odp;
}

static uint8_t
odp_to_ovs_ct_state(uint32_t flags)
{
    uint32_t state = 0;

#define CS_STATE(ENUM, INDEX, NAME) \
    if (flags & OVS_CS_F_##ENUM) {  \
        state |= CS_##ENUM;         \
    }
    CS_STATES
#undef CS_STATE

    return state;
}

static int
scan_ct_state(const char *s, uint32_t *key, uint32_t *mask)
{
    uint32_t flags, fmask;
    int n;

    n = parse_flags(s, odp_ct_state_to_string, ')', NULL, NULL, &flags,
                    ovs_to_odp_ct_state(CS_SUPPORTED_MASK),
                    mask ? &fmask : NULL);

    if (n >= 0) {
        *key = flags;
        if (mask) {
            *mask = fmask;
        }
        return n;
    }
    return 0;
}

static int
scan_frag(const char *s, uint8_t *key, uint8_t *mask)
{
    int n;
    char frag[8];
    enum ovs_frag_type frag_type;

    if (ovs_scan(s, "%7[a-z]%n", frag, &n)
        && ovs_frag_type_from_string(frag, &frag_type)) {
        int len = n;

        *key = frag_type;
        if (mask) {
            *mask = UINT8_MAX;
        }
        return len;
    }
    return 0;
}

static int
scan_port(const char *s, uint32_t *key, uint32_t *mask,
          const struct simap *port_names)
{
    int n;

    if (ovs_scan(s, "%"SCNi32"%n", key, &n)) {
        int len = n;

        if (mask) {
            if (ovs_scan(s + len, "/%"SCNi32"%n", mask, &n)) {
                len += n;
            } else {
                *mask = UINT32_MAX;
            }
        }
        return len;
    } else if (port_names) {
        const struct simap_node *node;
        int len;

        len = strcspn(s, ")");
        node = simap_find_len(port_names, s, len);
        if (node) {
            *key = node->data;

            if (mask) {
                *mask = UINT32_MAX;
            }
            return len;
        }
    }
    return 0;
}

/* Helper for vlan parsing. */
struct ovs_key_vlan__ {
    ovs_be16 tci;
};

static bool
set_be16_bf(ovs_be16 *bf, uint8_t bits, uint8_t offset, uint16_t value)
{
    const uint16_t mask = ((1U << bits) - 1) << offset;

    if (value >> bits) {
        return false;
    }

    *bf = htons((ntohs(*bf) & ~mask) | (value << offset));
    return true;
}

static int
scan_be16_bf(const char *s, ovs_be16 *key, ovs_be16 *mask, uint8_t bits,
             uint8_t offset)
{
    uint16_t key_, mask_;
    int n;

    if (ovs_scan(s, "%"SCNi16"%n", &key_, &n)) {
        int len = n;

        if (set_be16_bf(key, bits, offset, key_)) {
            if (mask) {
                if (ovs_scan(s + len, "/%"SCNi16"%n", &mask_, &n)) {
                    len += n;

                    if (!set_be16_bf(mask, bits, offset, mask_)) {
                        return 0;
                    }
                } else {
                    *mask |= htons(((1U << bits) - 1) << offset);
                }
            }
            return len;
        }
    }
    return 0;
}

static int
scan_vid(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    return scan_be16_bf(s, key, mask, 12, VLAN_VID_SHIFT);
}

static int
scan_pcp(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    return scan_be16_bf(s, key, mask, 3, VLAN_PCP_SHIFT);
}

static int
scan_cfi(const char *s, ovs_be16 *key, ovs_be16 *mask)
{
    return scan_be16_bf(s, key, mask, 1, VLAN_CFI_SHIFT);
}

/* For MPLS. */
static bool
set_be32_bf(ovs_be32 *bf, uint8_t bits, uint8_t offset, uint32_t value)
{
    const uint32_t mask = ((1U << bits) - 1) << offset;

    if (value >> bits) {
        return false;
    }

    *bf = htonl((ntohl(*bf) & ~mask) | (value << offset));
    return true;
}

static int
scan_be32_bf(const char *s, ovs_be32 *key, ovs_be32 *mask, uint8_t bits,
             uint8_t offset)
{
    uint32_t key_, mask_;
    int n;

    if (ovs_scan(s, "%"SCNi32"%n", &key_, &n)) {
        int len = n;

        if (set_be32_bf(key, bits, offset, key_)) {
            if (mask) {
                if (ovs_scan(s + len, "/%"SCNi32"%n", &mask_, &n)) {
                    len += n;

                    if (!set_be32_bf(mask, bits, offset, mask_)) {
                        return 0;
                    }
                } else {
                    *mask |= htonl(((1U << bits) - 1) << offset);
                }
            }
            return len;
        }
    }
    return 0;
}

static int
scan_mpls_label(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    return scan_be32_bf(s, key, mask, 20, MPLS_LABEL_SHIFT);
}

static int
scan_mpls_tc(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    return scan_be32_bf(s, key, mask, 3, MPLS_TC_SHIFT);
}

static int
scan_mpls_ttl(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    return scan_be32_bf(s, key, mask, 8, MPLS_TTL_SHIFT);
}

static int
scan_mpls_bos(const char *s, ovs_be32 *key, ovs_be32 *mask)
{
    return scan_be32_bf(s, key, mask, 1, MPLS_BOS_SHIFT);
}

static int
scan_vxlan_gbp(const char *s, uint32_t *key, uint32_t *mask)
{
    const char *s_base = s;
    ovs_be16 id = 0, id_mask = 0;
    uint8_t flags = 0, flags_mask = 0;
    int len;

    if (!strncmp(s, "id=", 3)) {
        s += 3;
        len = scan_be16(s, &id, mask ? &id_mask : NULL);
        if (len == 0) {
            return 0;
        }
        s += len;
    }

    if (s[0] == ',') {
        s++;
    }
    if (!strncmp(s, "flags=", 6)) {
        s += 6;
        len = scan_u8(s, &flags, mask ? &flags_mask : NULL);
        if (len == 0) {
            return 0;
        }
        s += len;
    }

    if (!strncmp(s, "))", 2)) {
        s += 2;

        *key = (flags << 16) | ntohs(id);
        if (mask) {
            *mask = (flags_mask << 16) | ntohs(id_mask);
        }

        return s - s_base;
    }

    return 0;
}

static int
scan_gtpu_metadata(const char *s,
                   struct gtpu_metadata *key,
                   struct gtpu_metadata *mask)
{
    const char *s_base = s;
    uint8_t flags = 0, flags_ma = 0;
    uint8_t msgtype = 0, msgtype_ma = 0;
    int len;

    if (!strncmp(s, "flags=", 6)) {
        s += 6;
        len = scan_u8(s, &flags, mask ? &flags_ma : NULL);
        if (len == 0) {
            return 0;
        }
        s += len;
    }

    if (s[0] == ',') {
        s++;
    }

    if (!strncmp(s, "msgtype=", 8)) {
        s += 8;
        len = scan_u8(s, &msgtype, mask ? &msgtype_ma : NULL);
        if (len == 0) {
            return 0;
        }
        s += len;
    }

    if (!strncmp(s, ")", 1)) {
        s += 1;
        key->flags = flags;
        key->msgtype = msgtype;
        if (mask) {
            mask->flags = flags_ma;
            mask->msgtype = msgtype_ma;
        }
    }
    return s - s_base;
}

static int
scan_erspan_metadata(const char *s,
                     struct erspan_metadata *key,
                     struct erspan_metadata *mask)
{
    const char *s_base = s;
    uint32_t idx = 0, idx_mask = 0;
    uint8_t ver = 0, dir = 0, hwid = 0;
    uint8_t ver_mask = 0, dir_mask = 0, hwid_mask = 0;
    int len;

    if (!strncmp(s, "ver=", 4)) {
        s += 4;
        len = scan_u8(s, &ver, mask ? &ver_mask : NULL);
        if (len == 0) {
            return 0;
        }
        s += len;
    }

    if (s[0] == ',') {
        s++;
    }

    if (ver == 1) {
        if (!strncmp(s, "idx=", 4)) {
            s += 4;
            len = scan_u32(s, &idx, mask ? &idx_mask : NULL);
            if (len == 0) {
                return 0;
            }
            s += len;
        }

        if (!strncmp(s, ")", 1)) {
            s += 1;
            key->version = ver;
            key->u.index = htonl(idx);
            if (mask) {
                mask->u.index = htonl(idx_mask);
            }
        }
        return s - s_base;

    } else if (ver == 2) {
        if (!strncmp(s, "dir=", 4)) {
            s += 4;
            len = scan_u8(s, &dir, mask ? &dir_mask : NULL);
            if (len == 0) {
                return 0;
            }
            s += len;
        }
        if (s[0] == ',') {
            s++;
        }
        if (!strncmp(s, "hwid=", 5)) {
            s += 5;
            len = scan_u8(s, &hwid, mask ? &hwid_mask : NULL);
            if (len == 0) {
                return 0;
            }
            s += len;
        }

        if (!strncmp(s, ")", 1)) {
            s += 1;
            key->version = ver;
            key->u.md2.hwid = hwid;
            key->u.md2.dir = dir;
            if (mask) {
                mask->u.md2.hwid = hwid_mask;
                mask->u.md2.dir = dir_mask;
            }
        }
        return s - s_base;
    }

    return 0;
}

static int
scan_geneve(const char *s, struct geneve_scan *key, struct geneve_scan *mask)
{
    const char *s_base = s;
    struct geneve_opt *opt = key->d;
    struct geneve_opt *opt_mask = mask ? mask->d : NULL;
    int len_remain = sizeof key->d;
    int len;

    while (s[0] == '{' && len_remain >= sizeof *opt) {
        int data_len = 0;

        s++;
        len_remain -= sizeof *opt;

        if (!strncmp(s, "class=", 6)) {
            s += 6;
            len = scan_be16(s, &opt->opt_class,
                            mask ? &opt_mask->opt_class : NULL);
            if (len == 0) {
                return 0;
            }
            s += len;
        } else if (mask) {
            memset(&opt_mask->opt_class, 0, sizeof opt_mask->opt_class);
        }

        if (s[0] == ',') {
            s++;
        }
        if (!strncmp(s, "type=", 5)) {
            s += 5;
            len = scan_u8(s, &opt->type, mask ? &opt_mask->type : NULL);
            if (len == 0) {
                return 0;
            }
            s += len;
        } else if (mask) {
            memset(&opt_mask->type, 0, sizeof opt_mask->type);
        }

        if (s[0] == ',') {
            s++;
        }
        if (!strncmp(s, "len=", 4)) {
            uint8_t opt_len, opt_len_mask;
            s += 4;
            len = scan_u8(s, &opt_len, mask ? &opt_len_mask : NULL);
            if (len == 0) {
                return 0;
            }
            s += len;

            if (opt_len > 124 || opt_len % 4 || opt_len > len_remain) {
                return 0;
            }
            opt->length = opt_len / 4;
            if (mask) {
                opt_mask->length = opt_len_mask;
            }
            data_len = opt_len;
        } else if (mask) {
            memset(&opt_mask->type, 0, sizeof opt_mask->type);
        }

        if (s[0] == ',') {
            s++;
            if (parse_int_string(s, (uint8_t *)(opt + 1),
                                 data_len, (char **)&s)) {
                return 0;
            }
        }
        if (mask) {
            if (s[0] == '/') {
                s++;
                if (parse_int_string(s, (uint8_t *)(opt_mask + 1),
                                     data_len, (char **)&s)) {
                    return 0;
                }
            }
            opt_mask->r1 = 0;
            opt_mask->r2 = 0;
            opt_mask->r3 = 0;
        }

        if (s[0] == '}') {
            s++;
            opt += 1 + data_len / 4;
            if (mask) {
                opt_mask += 1 + data_len / 4;
            }
            len_remain -= data_len;
        } else {
            return 0;
        }
    }

    if (s[0] == ')') {
        len = sizeof key->d - len_remain;

        s++;
        key->len = len;
        if (mask) {
            mask->len = len;
        }
        return s - s_base;
    }

    return 0;
}

static void
tun_flags_to_attr(struct ofpbuf *a, const void *data_)
{
    const uint16_t *flags = data_;

    if (*flags & FLOW_TNL_F_DONT_FRAGMENT) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT);
    }
    if (*flags & FLOW_TNL_F_CSUM) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_CSUM);
    }
    if (*flags & FLOW_TNL_F_OAM) {
        nl_msg_put_flag(a, OVS_TUNNEL_KEY_ATTR_OAM);
    }
}

static void
vxlan_gbp_to_attr(struct ofpbuf *a, const void *data_)
{
    const uint32_t *gbp = data_;

    if (*gbp) {
        size_t vxlan_opts_ofs;

        vxlan_opts_ofs = nl_msg_start_nested(a, OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS);
        nl_msg_put_u32(a, OVS_VXLAN_EXT_GBP, *gbp);
        nl_msg_end_nested(a, vxlan_opts_ofs);
    }
}

static void
geneve_to_attr(struct ofpbuf *a, const void *data_)
{
    const struct geneve_scan *geneve = data_;

    nl_msg_put_unspec(a, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS, geneve->d,
                      geneve->len);
}

static void
erspan_to_attr(struct ofpbuf *a, const void *data_)
{
    const struct erspan_metadata *md = data_;

    nl_msg_put_unspec(a, OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS, md,
                      sizeof *md);
}

static void
gtpu_to_attr(struct ofpbuf *a, const void *data_)
{
    const struct gtpu_metadata *md = data_;

    nl_msg_put_unspec(a, OVS_TUNNEL_KEY_ATTR_GTPU_OPTS, md,
                      sizeof *md);
}

#define SCAN_PUT_ATTR(BUF, ATTR, DATA, FUNC)                      \
    {                                                             \
        unsigned long call_fn = (unsigned long)FUNC;              \
        if (call_fn) {                                            \
            typedef void (*fn)(struct ofpbuf *, const void *);    \
            fn func = FUNC;                                       \
            func(BUF, &(DATA));                                   \
        } else {                                                  \
            nl_msg_put_unspec(BUF, ATTR, &(DATA), sizeof (DATA)); \
        }                                                         \
    }

#define SCAN_IF(NAME)                           \
    if (strncmp(s, NAME, strlen(NAME)) == 0) {  \
        const char *start = s;                  \
        int len;                                \
                                                \
        s += strlen(NAME)

/* Usually no special initialization is needed. */
#define SCAN_BEGIN(NAME, TYPE)                  \
    SCAN_IF(NAME);                              \
        TYPE skey, smask;                       \
        memset(&skey, 0, sizeof skey);          \
        memset(&smask, 0, sizeof smask);        \
        do {                                    \
            len = 0;

/* Init as fully-masked as mask will not be scanned. */
#define SCAN_BEGIN_FULLY_MASKED(NAME, TYPE)     \
    SCAN_IF(NAME);                              \
        TYPE skey, smask;                       \
        memset(&skey, 0, sizeof skey);          \
        memset(&smask, 0xff, sizeof smask);     \
        do {                                    \
            len = 0;

/* VLAN needs special initialization. */
#define SCAN_BEGIN_INIT(NAME, TYPE, KEY_INIT, MASK_INIT)  \
    SCAN_IF(NAME);                                        \
        TYPE skey = KEY_INIT;                       \
        TYPE smask = MASK_INIT;                     \
        do {                                        \
            len = 0;

/* Scan unnamed entry as 'TYPE' */
#define SCAN_TYPE(TYPE, KEY, MASK)              \
    len = scan_##TYPE(s, KEY, MASK);            \
    if (len == 0) {                             \
        return -EINVAL;                         \
    }                                           \
    s += len

/* Scan named ('NAME') entry 'FIELD' as 'TYPE'. */
#define SCAN_FIELD(NAME, TYPE, FIELD)                                   \
    if (strncmp(s, NAME, strlen(NAME)) == 0) {                          \
        s += strlen(NAME);                                              \
        SCAN_TYPE(TYPE, &skey.FIELD, mask ? &smask.FIELD : NULL);       \
        continue;                                                       \
    }

#define SCAN_FINISH()                           \
        } while (*s++ == ',' && len != 0);      \
        if (s[-1] != ')') {                     \
            return -EINVAL;                     \
        }

#define SCAN_FINISH_SINGLE()                    \
        } while (false);                        \
        if (*s++ != ')') {                      \
            return -EINVAL;                     \
        }

/* Beginning of nested attribute. */
#define SCAN_BEGIN_NESTED(NAME, ATTR)                      \
    SCAN_IF(NAME);                                         \
        size_t key_offset, mask_offset = 0;                \
        key_offset = nl_msg_start_nested(key, ATTR);       \
        if (mask) {                                        \
            mask_offset = nl_msg_start_nested(mask, ATTR); \
        }                                                  \
        do {                                               \
            len = 0;

#define SCAN_END_NESTED()                                                     \
        SCAN_FINISH();                                                        \
        if (nl_attr_oversized(key->size - key_offset - NLA_HDRLEN)) {         \
            return -E2BIG;                                                    \
        }                                                                     \
        nl_msg_end_nested(key, key_offset);                                   \
        if (mask) {                                                           \
            nl_msg_end_nested(mask, mask_offset);                             \
        }                                                                     \
        return s - start;                                                     \
    }

#define SCAN_FIELD_NESTED__(NAME, TYPE, SCAN_AS, ATTR, FUNC)  \
    if (strncmp(s, NAME, strlen(NAME)) == 0) {                \
        TYPE skey, smask;                                     \
        memset(&skey, 0, sizeof skey);                        \
        memset(&smask, 0xff, sizeof smask);                   \
        s += strlen(NAME);                                    \
        SCAN_TYPE(SCAN_AS, &skey, &smask);                    \
        SCAN_PUT(ATTR, FUNC);                                 \
        continue;                                             \
    }

#define SCAN_FIELD_NESTED(NAME, TYPE, SCAN_AS, ATTR)  \
        SCAN_FIELD_NESTED__(NAME, TYPE, SCAN_AS, ATTR, NULL)

#define SCAN_FIELD_NESTED_FUNC(NAME, TYPE, SCAN_AS, FUNC)  \
        SCAN_FIELD_NESTED__(NAME, TYPE, SCAN_AS, 0, FUNC)

#define SCAN_PUT(ATTR, FUNC)                            \
        SCAN_PUT_ATTR(key, ATTR, skey, FUNC);           \
        if (mask)                                       \
            SCAN_PUT_ATTR(mask, ATTR, smask, FUNC);     \

#define SCAN_END(ATTR)                                  \
        SCAN_FINISH();                                  \
        SCAN_PUT(ATTR, NULL);                           \
        return s - start;                               \
    }

#define SCAN_BEGIN_ARRAY(NAME, TYPE, CNT)       \
    SCAN_IF(NAME);                              \
        TYPE skey[CNT], smask[CNT];             \
        memset(&skey, 0, sizeof skey);          \
        memset(&smask, 0, sizeof smask);        \
        int idx = 0, cnt = CNT;                 \
        uint64_t fields = 0;                    \
        do {                                    \
            int field = 0;                      \
            len = 0;

/* Scan named ('NAME') entry 'FIELD' as 'TYPE'. */
#define SCAN_FIELD_ARRAY(NAME, TYPE, FIELD)                             \
    if (strncmp(s, NAME, strlen(NAME)) == 0) {                          \
        if (fields & (1UL << field)) {                                  \
            fields = 0;                                                 \
            if (++idx == cnt) {                                         \
                break;                                                  \
            }                                                           \
        }                                                               \
        s += strlen(NAME);                                              \
        SCAN_TYPE(TYPE, &skey[idx].FIELD, mask ? &smask[idx].FIELD : NULL); \
        fields |= 1UL << field;                                         \
        continue;                                                       \
    }                                                                   \
    field++;

#define SCAN_PUT_ATTR_ARRAY(BUF, ATTR, DATA, CNT)                    \
    nl_msg_put_unspec(BUF, ATTR, &(DATA), sizeof (DATA)[0] * (CNT)); \

#define SCAN_PUT_ARRAY(ATTR, CNT)                        \
    SCAN_PUT_ATTR_ARRAY(key, ATTR, skey, CNT);       \
    if (mask) {                                      \
        SCAN_PUT_ATTR_ARRAY(mask, ATTR, smask, CNT); \
    }

#define SCAN_END_ARRAY(ATTR)             \
        SCAN_FINISH();                   \
        if (idx == cnt) {                \
            return -EINVAL;              \
        }                                \
        SCAN_PUT_ARRAY(ATTR, idx + 1);   \
        return s - start;                \
    }

#define SCAN_END_SINGLE(ATTR)                           \
        SCAN_FINISH_SINGLE();                           \
        SCAN_PUT(ATTR, NULL);                           \
        return s - start;                               \
    }

#define SCAN_SINGLE(NAME, TYPE, SCAN_AS, ATTR)       \
    SCAN_BEGIN(NAME, TYPE) {                         \
        SCAN_TYPE(SCAN_AS, &skey, &smask);           \
    } SCAN_END_SINGLE(ATTR)

#define SCAN_SINGLE_FULLY_MASKED(NAME, TYPE, SCAN_AS, ATTR) \
    SCAN_BEGIN_FULLY_MASKED(NAME, TYPE) {                   \
        SCAN_TYPE(SCAN_AS, &skey, NULL);                    \
    } SCAN_END_SINGLE(ATTR)

/* scan_port needs one extra argument. */
#define SCAN_SINGLE_PORT(NAME, TYPE, ATTR)  \
    SCAN_BEGIN(NAME, TYPE) {                            \
        len = scan_port(s, &skey, &smask,               \
                        context->port_names);           \
        if (len == 0) {                                 \
            return -EINVAL;                             \
        }                                               \
        s += len;                                       \
    } SCAN_END_SINGLE(ATTR)

static int
parse_odp_nsh_key_mask_attr(const char *s, struct ofpbuf *key,
                            struct ofpbuf *mask)
{
    if (strncmp(s, "nsh(", 4) == 0) {
        const char *start = s;
        int len;
        struct ovs_key_nsh skey, smask;
        uint32_t spi = 0, spi_mask = 0;
        uint8_t si = 0, si_mask = 0;

        s += 4;

        memset(&skey, 0, sizeof skey);
        memset(&smask, 0, sizeof smask);
        do {
            len = 0;

            if (strncmp(s, "flags=", 6) == 0) {
                s += 6;
                len = scan_u8(s, &skey.flags, mask ? &smask.flags : NULL);
                if (len == 0) {
                    return -EINVAL;
                }
                s += len;
                continue;
            }

            if (strncmp(s, "mdtype=", 7) == 0) {
                s += 7;
                len = scan_u8(s, &skey.mdtype, mask ? &smask.mdtype : NULL);
                if (len == 0) {
                    return -EINVAL;
                }
                s += len;
                continue;
            }

            if (strncmp(s, "np=", 3) == 0) {
                s += 3;
                len = scan_u8(s, &skey.np, mask ? &smask.np : NULL);
                if (len == 0) {
                    return -EINVAL;
                }
                s += len;
                continue;
            }

            if (strncmp(s, "spi=", 4) == 0) {
                s += 4;
                len = scan_u32(s, &spi, mask ? &spi_mask : NULL);
                if (len == 0) {
                    return -EINVAL;
                }
                s += len;
                continue;
            }

            if (strncmp(s, "si=", 3) == 0) {
                s += 3;
                len = scan_u8(s, &si, mask ? &si_mask : NULL);
                if (len == 0) {
                    return -EINVAL;
                }
                s += len;
                continue;
            }

            if (strncmp(s, "c1=", 3) == 0) {
                s += 3;
                len = scan_be32(s, &skey.context[0],
                                mask ? &smask.context[0] : NULL);
                if (len == 0) {
                    return -EINVAL;
                }
                s += len;
                continue;
            }

            if (strncmp(s, "c2=", 3) == 0) {
                s += 3;
                len = scan_be32(s, &skey.context[1],
                                mask ? &smask.context[1] : NULL);
                if (len == 0) {
                    return -EINVAL;
                }
                s += len;
                continue;
            }

            if (strncmp(s, "c3=", 3) == 0) {
                s += 3;
                len = scan_be32(s, &skey.context[2],
                                mask ? &smask.context[2] : NULL);
                if (len == 0) {
                    return -EINVAL;
                }
                s += len;
                continue;
            }

            if (strncmp(s, "c4=", 3) == 0) {
                s += 3;
                len = scan_be32(s, &skey.context[3],
                                mask ? &smask.context[3] : NULL);
                if (len == 0) {
                    return -EINVAL;
                }
                s += len;
                continue;
            }
        } while (*s++ == ',' && len != 0);
        if (s[-1] != ')') {
            return -EINVAL;
        }

        skey.path_hdr = nsh_spi_si_to_path_hdr(spi, si);
        smask.path_hdr = nsh_spi_si_to_path_hdr(spi_mask, si_mask);

        nsh_key_to_attr(key, &skey, NULL, 0, false);
        if (mask) {
            nsh_key_to_attr(mask, &smask, NULL, 0, true);
        }
        return s - start;
    }
    return 0;
}

static int
parse_odp_key_mask_attr(struct parse_odp_context *context, const char *s,
                        struct ofpbuf *key, struct ofpbuf *mask)
{
    int retval;

    context->depth++;

    if (context->depth == MAX_ODP_NESTED) {
        retval = -EINVAL;
    } else {
        retval = parse_odp_key_mask_attr__(context, s, key, mask);
    }

    context->depth--;

    return retval;
}

static int
parse_odp_key_mask_attr__(struct parse_odp_context *context, const char *s,
                          struct ofpbuf *key, struct ofpbuf *mask)
{
    SCAN_SINGLE("skb_priority(", uint32_t, u32, OVS_KEY_ATTR_PRIORITY);
    SCAN_SINGLE("skb_mark(", uint32_t, u32, OVS_KEY_ATTR_SKB_MARK);
    SCAN_SINGLE_FULLY_MASKED("recirc_id(", uint32_t, u32,
                             OVS_KEY_ATTR_RECIRC_ID);
    SCAN_SINGLE("dp_hash(", uint32_t, u32, OVS_KEY_ATTR_DP_HASH);

    SCAN_SINGLE("ct_state(", uint32_t, ct_state, OVS_KEY_ATTR_CT_STATE);
    SCAN_SINGLE("ct_zone(", uint16_t, u16, OVS_KEY_ATTR_CT_ZONE);
    SCAN_SINGLE("ct_mark(", uint32_t, u32, OVS_KEY_ATTR_CT_MARK);
    SCAN_SINGLE("ct_label(", ovs_u128, u128, OVS_KEY_ATTR_CT_LABELS);

    SCAN_BEGIN("ct_tuple4(", struct ovs_key_ct_tuple_ipv4) {
        SCAN_FIELD("src=", ipv4, ipv4_src);
        SCAN_FIELD("dst=", ipv4, ipv4_dst);
        SCAN_FIELD("proto=", u8, ipv4_proto);
        SCAN_FIELD("tp_src=", be16, src_port);
        SCAN_FIELD("tp_dst=", be16, dst_port);
    } SCAN_END(OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4);

    SCAN_BEGIN("ct_tuple6(", struct ovs_key_ct_tuple_ipv6) {
        SCAN_FIELD("src=", in6_addr, ipv6_src);
        SCAN_FIELD("dst=", in6_addr, ipv6_dst);
        SCAN_FIELD("proto=", u8, ipv6_proto);
        SCAN_FIELD("tp_src=", be16, src_port);
        SCAN_FIELD("tp_dst=", be16, dst_port);
    } SCAN_END(OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6);

    SCAN_BEGIN_NESTED("tunnel(", OVS_KEY_ATTR_TUNNEL) {
        SCAN_FIELD_NESTED("tun_id=", ovs_be64, be64, OVS_TUNNEL_KEY_ATTR_ID);
        SCAN_FIELD_NESTED("src=", ovs_be32, ipv4, OVS_TUNNEL_KEY_ATTR_IPV4_SRC);
        SCAN_FIELD_NESTED("dst=", ovs_be32, ipv4, OVS_TUNNEL_KEY_ATTR_IPV4_DST);
        SCAN_FIELD_NESTED("ipv6_src=", struct in6_addr, in6_addr, OVS_TUNNEL_KEY_ATTR_IPV6_SRC);
        SCAN_FIELD_NESTED("ipv6_dst=", struct in6_addr, in6_addr, OVS_TUNNEL_KEY_ATTR_IPV6_DST);
        SCAN_FIELD_NESTED("tos=", uint8_t, u8, OVS_TUNNEL_KEY_ATTR_TOS);
        SCAN_FIELD_NESTED("ttl=", uint8_t, u8, OVS_TUNNEL_KEY_ATTR_TTL);
        SCAN_FIELD_NESTED("tp_src=", ovs_be16, be16, OVS_TUNNEL_KEY_ATTR_TP_SRC);
        SCAN_FIELD_NESTED("tp_dst=", ovs_be16, be16, OVS_TUNNEL_KEY_ATTR_TP_DST);
        SCAN_FIELD_NESTED_FUNC("erspan(", struct erspan_metadata, erspan_metadata,
                               erspan_to_attr);
        SCAN_FIELD_NESTED_FUNC("vxlan(gbp(", uint32_t, vxlan_gbp, vxlan_gbp_to_attr);
        SCAN_FIELD_NESTED_FUNC("geneve(", struct geneve_scan, geneve,
                               geneve_to_attr);
        SCAN_FIELD_NESTED_FUNC("gtpu(", struct gtpu_metadata, gtpu_metadata,
                               gtpu_to_attr);
        SCAN_FIELD_NESTED_FUNC("flags(", uint16_t, tun_flags, tun_flags_to_attr);
    } SCAN_END_NESTED();

    SCAN_SINGLE_PORT("in_port(", uint32_t, OVS_KEY_ATTR_IN_PORT);

    SCAN_BEGIN("eth(", struct ovs_key_ethernet) {
        SCAN_FIELD("src=", eth, eth_src);
        SCAN_FIELD("dst=", eth, eth_dst);
    } SCAN_END(OVS_KEY_ATTR_ETHERNET);

    SCAN_BEGIN_INIT("vlan(", struct ovs_key_vlan__,
                    { htons(VLAN_CFI) }, { htons(VLAN_CFI) }) {
        SCAN_FIELD("vid=", vid, tci);
        SCAN_FIELD("pcp=", pcp, tci);
        SCAN_FIELD("cfi=", cfi, tci);
    } SCAN_END(OVS_KEY_ATTR_VLAN);

    SCAN_SINGLE("eth_type(", ovs_be16, be16, OVS_KEY_ATTR_ETHERTYPE);

    SCAN_BEGIN_ARRAY("mpls(", struct ovs_key_mpls, FLOW_MAX_MPLS_LABELS) {
        SCAN_FIELD_ARRAY("label=", mpls_label, mpls_lse);
        SCAN_FIELD_ARRAY("tc=", mpls_tc, mpls_lse);
        SCAN_FIELD_ARRAY("ttl=", mpls_ttl, mpls_lse);
        SCAN_FIELD_ARRAY("bos=", mpls_bos, mpls_lse);
    } SCAN_END_ARRAY(OVS_KEY_ATTR_MPLS);

    SCAN_BEGIN("ipv4(", struct ovs_key_ipv4) {
        SCAN_FIELD("src=", ipv4, ipv4_src);
        SCAN_FIELD("dst=", ipv4, ipv4_dst);
        SCAN_FIELD("proto=", u8, ipv4_proto);
        SCAN_FIELD("tos=", u8, ipv4_tos);
        SCAN_FIELD("ttl=", u8, ipv4_ttl);
        SCAN_FIELD("frag=", frag, ipv4_frag);
    } SCAN_END(OVS_KEY_ATTR_IPV4);

    SCAN_BEGIN("ipv6(", struct ovs_key_ipv6) {
        SCAN_FIELD("src=", in6_addr, ipv6_src);
        SCAN_FIELD("dst=", in6_addr, ipv6_dst);
        SCAN_FIELD("label=", ipv6_label, ipv6_label);
        SCAN_FIELD("proto=", u8, ipv6_proto);
        SCAN_FIELD("tclass=", u8, ipv6_tclass);
        SCAN_FIELD("hlimit=", u8, ipv6_hlimit);
        SCAN_FIELD("frag=", frag, ipv6_frag);
    } SCAN_END(OVS_KEY_ATTR_IPV6);

    SCAN_BEGIN("tcp(", struct ovs_key_tcp) {
        SCAN_FIELD("src=", be16, tcp_src);
        SCAN_FIELD("dst=", be16, tcp_dst);
    } SCAN_END(OVS_KEY_ATTR_TCP);

    SCAN_SINGLE("tcp_flags(", ovs_be16, tcp_flags, OVS_KEY_ATTR_TCP_FLAGS);

    SCAN_BEGIN("udp(", struct ovs_key_udp) {
        SCAN_FIELD("src=", be16, udp_src);
        SCAN_FIELD("dst=", be16, udp_dst);
    } SCAN_END(OVS_KEY_ATTR_UDP);

    SCAN_BEGIN("sctp(", struct ovs_key_sctp) {
        SCAN_FIELD("src=", be16, sctp_src);
        SCAN_FIELD("dst=", be16, sctp_dst);
    } SCAN_END(OVS_KEY_ATTR_SCTP);

    SCAN_BEGIN("icmp(", struct ovs_key_icmp) {
        SCAN_FIELD("type=", u8, icmp_type);
        SCAN_FIELD("code=", u8, icmp_code);
    } SCAN_END(OVS_KEY_ATTR_ICMP);

    SCAN_BEGIN("icmpv6(", struct ovs_key_icmpv6) {
        SCAN_FIELD("type=", u8, icmpv6_type);
        SCAN_FIELD("code=", u8, icmpv6_code);
    } SCAN_END(OVS_KEY_ATTR_ICMPV6);

    SCAN_BEGIN("arp(", struct ovs_key_arp) {
        SCAN_FIELD("sip=", ipv4, arp_sip);
        SCAN_FIELD("tip=", ipv4, arp_tip);
        SCAN_FIELD("op=", be16, arp_op);
        SCAN_FIELD("sha=", eth, arp_sha);
        SCAN_FIELD("tha=", eth, arp_tha);
    } SCAN_END(OVS_KEY_ATTR_ARP);

    SCAN_BEGIN("nd(", struct ovs_key_nd) {
        SCAN_FIELD("target=", in6_addr, nd_target);
        SCAN_FIELD("sll=", eth, nd_sll);
        SCAN_FIELD("tll=", eth, nd_tll);
    } SCAN_END(OVS_KEY_ATTR_ND);

    SCAN_BEGIN("nd_ext(", struct ovs_key_nd_extensions) {
        SCAN_FIELD("nd_reserved=", be32, nd_reserved);
        SCAN_FIELD("nd_options_type=", u8, nd_options_type);
    } SCAN_END(OVS_KEY_ATTR_ND_EXTENSIONS);

    struct packet_type {
        ovs_be16 ns;
        ovs_be16 id;
    };
    SCAN_BEGIN("packet_type(", struct packet_type) {
        SCAN_FIELD("ns=", be16, ns);
        SCAN_FIELD("id=", be16, id);
    } SCAN_END(OVS_KEY_ATTR_PACKET_TYPE);

    /* nsh is nested, it needs special process */
    int ret = parse_odp_nsh_key_mask_attr(s, key, mask);
    if (ret < 0) {
        return ret;
    } else {
        s += ret;
    }

    /* Encap open-coded. */
    if (!strncmp(s, "encap(", 6)) {
        const char *start = s;
        size_t encap, encap_mask = 0;

        encap = nl_msg_start_nested(key, OVS_KEY_ATTR_ENCAP);
        if (mask) {
            encap_mask = nl_msg_start_nested(mask, OVS_KEY_ATTR_ENCAP);
        }

        s += 6;
        for (;;) {
            int retval;

            s += strspn(s, delimiters);
            if (!*s) {
                return -EINVAL;
            } else if (*s == ')') {
                break;
            }

            retval = parse_odp_key_mask_attr(context, s, key, mask);
            if (retval < 0) {
                return retval;
            }

            if (nl_attr_oversized(key->size - encap - NLA_HDRLEN)) {
                return -E2BIG;
            }
            s += retval;
        }
        s++;

        nl_msg_end_nested(key, encap);
        if (mask) {
            nl_msg_end_nested(mask, encap_mask);
        }

        return s - start;
    }

    return -EINVAL;
}

/* Parses the string representation of a datapath flow key, in the format
 * output by odp_flow_key_format().  Returns 0 if successful, otherwise a
 * positive errno value.  On success, stores NULL into '*errorp' and the flow
 * key is appended to 'key' as a series of Netlink attributes.  On failure,
 * stores a malloc()'d error message in '*errorp' without changing the data in
 * 'key'.  Either way, 'key''s data might be reallocated.
 *
 * If 'port_names' is nonnull, it points to an simap that maps from a port name
 * to a port number.  (Port names may be used instead of port numbers in
 * in_port.)
 *
 * On success, the attributes appended to 'key' are individually syntactically
 * valid, but they may not be valid as a sequence.  'key' might, for example,
 * have duplicated keys.  odp_flow_key_to_flow() will detect those errors. */
int
odp_flow_from_string(const char *s, const struct simap *port_names,
                     struct ofpbuf *key, struct ofpbuf *mask,
                     char **errorp)
{
    if (errorp) {
        *errorp = NULL;
    }

    const size_t old_size = key->size;
    struct parse_odp_context context = (struct parse_odp_context) {
        .port_names = port_names,
    };
    for (;;) {
        int retval;

        s += strspn(s, delimiters);
        if (!*s) {
            return 0;
        }

        /* Skip UFID. */
        ovs_u128 ufid;
        retval = odp_ufid_from_string(s, &ufid);
        if (retval < 0) {
            if (errorp) {
                *errorp = xasprintf("syntax error at %s", s);
            }
            key->size = old_size;
            return -retval;
        } else if (retval > 0) {
            s += retval;
            s += s[0] == ' ' ? 1 : 0;
        }

        retval = parse_odp_key_mask_attr(&context, s, key, mask);
        if (retval < 0) {
            if (errorp) {
                *errorp = xasprintf("syntax error at %s", s);
            }
            key->size = old_size;
            return -retval;
        }
        s += retval;
    }

    return 0;
}

static uint8_t
ovs_to_odp_frag(uint8_t nw_frag, bool is_mask)
{
    if (is_mask) {
        /* Netlink interface 'enum ovs_frag_type' is an 8-bit enumeration type,
         * not a set of flags or bitfields. Hence, if the struct flow nw_frag
         * mask, which is a set of bits, has the FLOW_NW_FRAG_ANY as zero, we
         * must use a zero mask for the netlink frag field, and all ones mask
         * otherwise. */
        return (nw_frag & FLOW_NW_FRAG_ANY) ? UINT8_MAX : 0;
    }
    return !(nw_frag & FLOW_NW_FRAG_ANY) ? OVS_FRAG_TYPE_NONE
        : nw_frag & FLOW_NW_FRAG_LATER ? OVS_FRAG_TYPE_LATER
        : OVS_FRAG_TYPE_FIRST;
}

static void get_ethernet_key(const struct flow *, struct ovs_key_ethernet *);
static void put_ethernet_key(const struct ovs_key_ethernet *, struct flow *);
static void get_ipv4_key(const struct flow *, struct ovs_key_ipv4 *,
                         bool is_mask);
static void put_ipv4_key(const struct ovs_key_ipv4 *, struct flow *,
                         bool is_mask);
static void get_ipv6_key(const struct flow *, struct ovs_key_ipv6 *,
                         bool is_mask);
static void put_ipv6_key(const struct ovs_key_ipv6 *, struct flow *,
                         bool is_mask);
static void get_arp_key(const struct flow *, struct ovs_key_arp *);
static void put_arp_key(const struct ovs_key_arp *, struct flow *);
static void get_nd_key(const struct flow *, struct ovs_key_nd *);
static void put_nd_key(const struct ovs_key_nd *, struct flow *);
static void get_nsh_key(const struct flow *flow, struct ovs_key_nsh *nsh,
                        bool is_mask);
static void put_nsh_key(const struct ovs_key_nsh *nsh, struct flow *flow,
                        bool is_mask);

/* These share the same layout. */
union ovs_key_tp {
    struct ovs_key_tcp tcp;
    struct ovs_key_udp udp;
    struct ovs_key_sctp sctp;
};

static void get_tp_key(const struct flow *, union ovs_key_tp *);
static void put_tp_key(const union ovs_key_tp *, struct flow *);

static void
odp_flow_key_from_flow__(const struct odp_flow_key_parms *parms,
                         bool export_mask, struct ofpbuf *buf)
{
    /* New "struct flow" fields that are visible to the datapath (including all
     * data fields) should be translated into equivalent datapath flow fields
     * here (you will have to add a OVS_KEY_ATTR_* for them). */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    struct ovs_key_ethernet *eth_key;
    size_t encap[FLOW_MAX_VLAN_HEADERS] = {0};
    size_t max_vlans;
    const struct flow *flow = parms->flow;
    const struct flow *mask = parms->mask;
    const struct flow *data = export_mask ? mask : flow;

    nl_msg_put_u32(buf, OVS_KEY_ATTR_PRIORITY, data->skb_priority);

    if (flow_tnl_dst_is_set(&flow->tunnel) ||
        flow_tnl_src_is_set(&flow->tunnel) || export_mask) {
        tun_key_to_attr(buf, &data->tunnel, &parms->flow->tunnel,
                        parms->key_buf, NULL);
    }

    nl_msg_put_u32(buf, OVS_KEY_ATTR_SKB_MARK, data->pkt_mark);

    if (parms->support.ct_state) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_CT_STATE,
                       ovs_to_odp_ct_state(data->ct_state));
    }
    if (parms->support.ct_zone) {
        nl_msg_put_u16(buf, OVS_KEY_ATTR_CT_ZONE, data->ct_zone);
    }
    if (parms->support.ct_mark) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_CT_MARK, data->ct_mark);
    }
    if (parms->support.ct_label) {
        nl_msg_put_unspec(buf, OVS_KEY_ATTR_CT_LABELS, &data->ct_label,
                          sizeof(data->ct_label));
    }
    if (flow->ct_nw_proto) {
        if (parms->support.ct_orig_tuple
            && flow->dl_type == htons(ETH_TYPE_IP)) {
            struct ovs_key_ct_tuple_ipv4 *ct;

            /* 'struct ovs_key_ct_tuple_ipv4' has padding, clear it. */
            ct = nl_msg_put_unspec_zero(buf, OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4,
                                        sizeof *ct);
            ct->ipv4_src = data->ct_nw_src;
            ct->ipv4_dst = data->ct_nw_dst;
            ct->src_port = data->ct_tp_src;
            ct->dst_port = data->ct_tp_dst;
            ct->ipv4_proto = data->ct_nw_proto;
        } else if (parms->support.ct_orig_tuple6
                   && flow->dl_type == htons(ETH_TYPE_IPV6)) {
            struct ovs_key_ct_tuple_ipv6 *ct;

            /* 'struct ovs_key_ct_tuple_ipv6' has padding, clear it. */
            ct = nl_msg_put_unspec_zero(buf, OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6,
                                        sizeof *ct);
            ct->ipv6_src = data->ct_ipv6_src;
            ct->ipv6_dst = data->ct_ipv6_dst;
            ct->src_port = data->ct_tp_src;
            ct->dst_port = data->ct_tp_dst;
            ct->ipv6_proto = data->ct_nw_proto;
        }
    }
    if (parms->support.recirc) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_RECIRC_ID, data->recirc_id);
        nl_msg_put_u32(buf, OVS_KEY_ATTR_DP_HASH, data->dp_hash);
    }

    /* Add an ingress port attribute if this is a mask or 'in_port.odp_port'
     * is not the magical value "ODPP_NONE". */
    if (export_mask || flow->in_port.odp_port != ODPP_NONE) {
        nl_msg_put_odp_port(buf, OVS_KEY_ATTR_IN_PORT, data->in_port.odp_port);
    }

    nl_msg_put_be32(buf, OVS_KEY_ATTR_PACKET_TYPE, data->packet_type);

    if (OVS_UNLIKELY(parms->probe)) {
        max_vlans = FLOW_MAX_VLAN_HEADERS;
    } else {
        max_vlans = MIN(parms->support.max_vlan_headers, flow_vlan_limit);
    }

    /* Conditionally add L2 attributes for Ethernet packets */
    if (flow->packet_type == htonl(PT_ETH)) {
        eth_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ETHERNET,
                                           sizeof *eth_key);
        get_ethernet_key(data, eth_key);

        for (int encaps = 0; encaps < max_vlans; encaps++) {
            ovs_be16 tpid = flow->vlans[encaps].tpid;

            if (flow->vlans[encaps].tci == htons(0)) {
                if (eth_type_vlan(flow->dl_type)) {
                    /* If VLAN was truncated the tpid is in dl_type */
                    tpid = flow->dl_type;
                } else {
                    break;
                }
            }

            if (export_mask) {
                nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, OVS_BE16_MAX);
            } else {
                nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, tpid);
            }
            nl_msg_put_be16(buf, OVS_KEY_ATTR_VLAN, data->vlans[encaps].tci);
            encap[encaps] = nl_msg_start_nested(buf, OVS_KEY_ATTR_ENCAP);
            if (flow->vlans[encaps].tci == htons(0)) {
                goto unencap;
            }
        }
    }

    if (ntohs(flow->dl_type) < ETH_TYPE_MIN) {
        /* For backwards compatibility with kernels that don't support
         * wildcarding, the following convention is used to encode the
         * OVS_KEY_ATTR_ETHERTYPE for key and mask:
         *
         *   key      mask    matches
         * -------- --------  -------
         *  >0x5ff   0xffff   Specified Ethernet II Ethertype.
         *  >0x5ff      0     Any Ethernet II or non-Ethernet II frame.
         *  <none>   0xffff   Any non-Ethernet II frame (except valid
         *                    802.3 SNAP packet with valid eth_type).
         */
        if (export_mask) {
            nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, OVS_BE16_MAX);
        }
        goto unencap;
    }

    nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, data->dl_type);

    if (eth_type_vlan(flow->dl_type)) {
        goto unencap;
    }

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        struct ovs_key_ipv4 *ipv4_key;

        ipv4_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_IPV4,
                                            sizeof *ipv4_key);
        get_ipv4_key(data, ipv4_key, export_mask);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        struct ovs_key_ipv6 *ipv6_key;

        ipv6_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_IPV6,
                                            sizeof *ipv6_key);
        get_ipv6_key(data, ipv6_key, export_mask);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        struct ovs_key_arp *arp_key;

        arp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ARP,
                                           sizeof *arp_key);
        get_arp_key(data, arp_key);
    } else if (eth_type_mpls(flow->dl_type)) {
        struct ovs_key_mpls *mpls_key;
        int i, n;

        n = flow_count_mpls_labels(flow, NULL);
        if (export_mask) {
            n = MIN(n, parms->support.max_mpls_depth);
        }
        mpls_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_MPLS,
                                            n * sizeof *mpls_key);
        for (i = 0; i < n; i++) {
            mpls_key[i].mpls_lse = data->mpls_lse[i];
        }
    } else if (flow->dl_type == htons(ETH_TYPE_NSH)) {
        nsh_key_to_attr(buf, &data->nsh, NULL, 0, export_mask);
    }

    if (is_ip_any(flow) && !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (flow->nw_proto == IPPROTO_TCP) {
            union ovs_key_tp *tcp_key;

            tcp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_TCP,
                                               sizeof *tcp_key);
            get_tp_key(data, tcp_key);
            if (data->tcp_flags || (mask && mask->tcp_flags)) {
                nl_msg_put_be16(buf, OVS_KEY_ATTR_TCP_FLAGS, data->tcp_flags);
            }
        } else if (flow->nw_proto == IPPROTO_UDP) {
            union ovs_key_tp *udp_key;

            udp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_UDP,
                                               sizeof *udp_key);
            get_tp_key(data, udp_key);
        } else if (flow->nw_proto == IPPROTO_SCTP) {
            union ovs_key_tp *sctp_key;

            sctp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_SCTP,
                                               sizeof *sctp_key);
            get_tp_key(data, sctp_key);
        } else if (flow->dl_type == htons(ETH_TYPE_IP)
                && flow->nw_proto == IPPROTO_ICMP) {
            struct ovs_key_icmp *icmp_key;

            icmp_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ICMP,
                                                sizeof *icmp_key);
            icmp_key->icmp_type = ntohs(data->tp_src);
            icmp_key->icmp_code = ntohs(data->tp_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)
                && flow->nw_proto == IPPROTO_ICMPV6) {
            struct ovs_key_icmpv6 *icmpv6_key;

            icmpv6_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ICMPV6,
                                                  sizeof *icmpv6_key);
            icmpv6_key->icmpv6_type = ntohs(data->tp_src);
            icmpv6_key->icmpv6_code = ntohs(data->tp_dst);

            if (is_nd(flow, NULL)
                /* Even though 'tp_src' and 'tp_dst' are 16 bits wide, ICMP
                 * type and code are 8 bits wide.  Therefore, an exact match
                 * looks like htons(0xff), not htons(0xffff).  See
                 * xlate_wc_finish() for details. */
                && (!export_mask || (data->tp_src == htons(0xff)
                                     && data->tp_dst == htons(0xff)))) {
                struct ovs_key_nd *nd_key;
                nd_key = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_ND,
                                                    sizeof *nd_key);
                nd_key->nd_target = data->nd_target;
                nd_key->nd_sll = data->arp_sha;
                nd_key->nd_tll = data->arp_tha;

                /* Add ND Extensions Attr only if supported and reserved field
                 * or options type is set. */
                if (parms->support.nd_ext) {
                    struct ovs_key_nd_extensions *nd_ext_key;

                    if (data->igmp_group_ip4 != 0 || data->tcp_flags != 0) {
                        /* 'struct ovs_key_nd_extensions' has padding,
                         * clear it. */
                        nd_ext_key = nl_msg_put_unspec_zero(buf,
                                            OVS_KEY_ATTR_ND_EXTENSIONS,
                                            sizeof *nd_ext_key);
                        nd_ext_key->nd_reserved = data->igmp_group_ip4;
                        nd_ext_key->nd_options_type = ntohs(data->tcp_flags);
                    }
                }
            }
        }
    }

unencap:
    for (int encaps = max_vlans - 1; encaps >= 0; encaps--) {
        if (encap[encaps]) {
            nl_msg_end_nested(buf, encap[encaps]);
        }
    }
}

/* Appends a representation of 'flow' as OVS_KEY_ATTR_* attributes to 'buf'.
 *
 * 'buf' must have at least ODPUTIL_FLOW_KEY_BYTES bytes of space, or be
 * capable of being expanded to allow for that much space. */
void
odp_flow_key_from_flow(const struct odp_flow_key_parms *parms,
                       struct ofpbuf *buf)
{
    odp_flow_key_from_flow__(parms, false, buf);
}

/* Appends a representation of 'mask' as OVS_KEY_ATTR_* attributes to
 * 'buf'.
 *
 * 'buf' must have at least ODPUTIL_FLOW_KEY_BYTES bytes of space, or be
 * capable of being expanded to allow for that much space. */
void
odp_flow_key_from_mask(const struct odp_flow_key_parms *parms,
                       struct ofpbuf *buf)
{
    odp_flow_key_from_flow__(parms, true, buf);
}

/* Generate ODP flow key from the given packet metadata */
void
odp_key_from_dp_packet(struct ofpbuf *buf, const struct dp_packet *packet)
{
    const struct pkt_metadata *md = &packet->md;

    nl_msg_put_u32(buf, OVS_KEY_ATTR_PRIORITY, md->skb_priority);

    if (md->dp_hash) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_DP_HASH, md->dp_hash);
    }

    if (flow_tnl_dst_is_set(&md->tunnel)) {
        tun_key_to_attr(buf, &md->tunnel, &md->tunnel, NULL, NULL);
    }

    nl_msg_put_u32(buf, OVS_KEY_ATTR_SKB_MARK, md->pkt_mark);

    if (md->ct_state) {
        nl_msg_put_u32(buf, OVS_KEY_ATTR_CT_STATE,
                       ovs_to_odp_ct_state(md->ct_state));
        if (md->ct_zone) {
            nl_msg_put_u16(buf, OVS_KEY_ATTR_CT_ZONE, md->ct_zone);
        }
        if (md->ct_mark) {
            nl_msg_put_u32(buf, OVS_KEY_ATTR_CT_MARK, md->ct_mark);
        }
        if (!ovs_u128_is_zero(md->ct_label)) {
            nl_msg_put_unspec(buf, OVS_KEY_ATTR_CT_LABELS, &md->ct_label,
                              sizeof(md->ct_label));
        }
        if (md->ct_orig_tuple_ipv6) {
            if (md->ct_orig_tuple.ipv6.ipv6_proto) {
                nl_msg_put_unspec(buf, OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6,
                                  &md->ct_orig_tuple.ipv6,
                                  sizeof md->ct_orig_tuple.ipv6);
            }
        } else {
            if (md->ct_orig_tuple.ipv4.ipv4_proto) {
                nl_msg_put_unspec(buf, OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4,
                                  &md->ct_orig_tuple.ipv4,
                                  sizeof md->ct_orig_tuple.ipv4);
            }
        }
    }

    /* Add an ingress port attribute if 'odp_in_port' is not the magical
     * value "ODPP_NONE". */
    if (md->in_port.odp_port != ODPP_NONE) {
        nl_msg_put_odp_port(buf, OVS_KEY_ATTR_IN_PORT, md->in_port.odp_port);
    }

    /* Add OVS_KEY_ATTR_ETHERNET for non-Ethernet packets */
    if (pt_ns(packet->packet_type) == OFPHTN_ETHERTYPE) {
        nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE,
                        pt_ns_type_be(packet->packet_type));
    }
}

/* Generate packet metadata from the given ODP flow key. */
void
odp_key_to_dp_packet(const struct nlattr *key, size_t key_len,
                     struct dp_packet *packet)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const struct nlattr *nla;
    struct pkt_metadata *md = &packet->md;
    ovs_be32 packet_type = htonl(PT_UNKNOWN);
    ovs_be16 ethertype = 0;
    size_t left;

    pkt_metadata_init(md, ODPP_NONE);

    NL_ATTR_FOR_EACH (nla, left, key, key_len) {
        enum ovs_key_attr type = nl_attr_type(nla);
        size_t len = nl_attr_get_size(nla);
        int expected_len = odp_key_attr_len(ovs_flow_key_attr_lens,
                                            OVS_KEY_ATTR_MAX, type);

        if (len != expected_len && expected_len >= 0) {
            continue;
        }

        switch (type) {
        case OVS_KEY_ATTR_RECIRC_ID:
            md->recirc_id = nl_attr_get_u32(nla);
            break;
        case OVS_KEY_ATTR_DP_HASH:
            md->dp_hash = nl_attr_get_u32(nla);
            break;
        case OVS_KEY_ATTR_PRIORITY:
            md->skb_priority = nl_attr_get_u32(nla);
            break;
        case OVS_KEY_ATTR_SKB_MARK:
            md->pkt_mark = nl_attr_get_u32(nla);
            break;
        case OVS_KEY_ATTR_CT_STATE:
            md->ct_state = odp_to_ovs_ct_state(nl_attr_get_u32(nla));
            break;
        case OVS_KEY_ATTR_CT_ZONE:
            md->ct_zone = nl_attr_get_u16(nla);
            break;
        case OVS_KEY_ATTR_CT_MARK:
            md->ct_mark = nl_attr_get_u32(nla);
            break;
        case OVS_KEY_ATTR_CT_LABELS: {
            md->ct_label = nl_attr_get_u128(nla);
            break;
        }
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4: {
            const struct ovs_key_ct_tuple_ipv4 *ct = nl_attr_get(nla);
            md->ct_orig_tuple.ipv4 = *ct;
            md->ct_orig_tuple_ipv6 = false;
            break;
        }
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6: {
            const struct ovs_key_ct_tuple_ipv6 *ct = nl_attr_get(nla);

            md->ct_orig_tuple.ipv6 = *ct;
            md->ct_orig_tuple_ipv6 = true;
            break;
        }
        case OVS_KEY_ATTR_TUNNEL: {
            enum odp_key_fitness res;

            res = odp_tun_key_from_attr(nla, &md->tunnel, NULL);
            if (res == ODP_FIT_ERROR) {
                memset(&md->tunnel, 0, sizeof md->tunnel);
            }
            break;
        }
        case OVS_KEY_ATTR_IN_PORT:
            md->in_port.odp_port = nl_attr_get_odp_port(nla);
            break;
        case OVS_KEY_ATTR_ETHERNET:
            /* Presence of OVS_KEY_ATTR_ETHERNET indicates Ethernet packet. */
            packet_type = htonl(PT_ETH);
            break;
        case OVS_KEY_ATTR_ETHERTYPE:
            ethertype = nl_attr_get_be16(nla);
            break;
        case OVS_KEY_ATTR_UNSPEC:
        case OVS_KEY_ATTR_ENCAP:
        case OVS_KEY_ATTR_VLAN:
        case OVS_KEY_ATTR_IPV4:
        case OVS_KEY_ATTR_IPV6:
        case OVS_KEY_ATTR_TCP:
        case OVS_KEY_ATTR_UDP:
        case OVS_KEY_ATTR_ICMP:
        case OVS_KEY_ATTR_ICMPV6:
        case OVS_KEY_ATTR_ARP:
        case OVS_KEY_ATTR_ND:
        case OVS_KEY_ATTR_ND_EXTENSIONS:
        case OVS_KEY_ATTR_SCTP:
        case OVS_KEY_ATTR_TCP_FLAGS:
        case OVS_KEY_ATTR_MPLS:
        case OVS_KEY_ATTR_PACKET_TYPE:
        case OVS_KEY_ATTR_NSH:
        case __OVS_KEY_ATTR_MAX:
        default:
            break;
        }
    }

    if (packet_type == htonl(PT_ETH)) {
        packet->packet_type = htonl(PT_ETH);
    } else if (packet_type == htonl(PT_UNKNOWN) && ethertype != 0) {
        packet->packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE,
                                             ntohs(ethertype));
    } else {
        VLOG_ERR_RL(&rl, "Packet without ETHERTYPE. Unknown packet_type.");
    }
}

/* Places the hash of the 'key_len' bytes starting at 'key' into '*hash'.
 * Generated value has format of random UUID. */
void
odp_flow_key_hash(const void *key, size_t key_len, ovs_u128 *hash)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static uint32_t secret;

    if (ovsthread_once_start(&once)) {
        secret = random_uint32();
        ovsthread_once_done(&once);
    }
    hash_bytes128(key, key_len, secret, hash);
    uuid_set_bits_v4((struct uuid *)hash);
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
            char namebuf[OVS_KEY_ATTR_BUFSIZE];

            ds_put_format(&s, " %s",
                          ovs_key_attr_to_string(i, namebuf, sizeof namebuf));
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

static uint8_t
odp_to_ovs_frag(uint8_t odp_frag, bool is_mask)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (is_mask) {
        return odp_frag ? FLOW_NW_FRAG_MASK : 0;
    }

    if (odp_frag > OVS_FRAG_TYPE_LATER) {
        VLOG_ERR_RL(&rl, "invalid frag %"PRIu8" in flow key", odp_frag);
        return 0xff; /* Error. */
    }

    return (odp_frag == OVS_FRAG_TYPE_NONE) ? 0
        : (odp_frag == OVS_FRAG_TYPE_FIRST) ? FLOW_NW_FRAG_ANY
        :  FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER;
}

/* Parses the attributes in the 'key_len' bytes of 'key' into 'attrs', which
 * must have OVS_KEY_ATTR_MAX + 1 elements.  Stores each attribute in 'key'
 * into the corresponding element of 'attrs'.
 *
 * Stores a bitmask of the attributes' indexes found in 'key' into
 * '*present_attrsp'.
 *
 * If an attribute beyond OVS_KEY_ATTR_MAX is found, stores its attribute type
 * (or one of them, if more than one) into '*out_of_range_attrp', otherwise 0.
 *
 * If 'errorp' is nonnull and the function returns false, stores a malloc()'d
 * error message in '*errorp'. */
static bool
parse_flow_nlattrs(const struct nlattr *key, size_t key_len,
                   const struct nlattr *attrs[], uint64_t *present_attrsp,
                   int *out_of_range_attrp, char **errorp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    const struct nlattr *nla;
    uint64_t present_attrs;
    size_t left;

    BUILD_ASSERT(OVS_KEY_ATTR_MAX < CHAR_BIT * sizeof present_attrs);
    present_attrs = 0;
    *out_of_range_attrp = 0;
    NL_ATTR_FOR_EACH (nla, left, key, key_len) {
        uint16_t type = nl_attr_type(nla);
        size_t len = nl_attr_get_size(nla);
        int expected_len = odp_key_attr_len(ovs_flow_key_attr_lens,
                                            OVS_KEY_ATTR_MAX, type);

        if (len != expected_len && expected_len >= 0) {
            char namebuf[OVS_KEY_ATTR_BUFSIZE];

            odp_parse_error(&rl, errorp, "attribute %s has length %"PRIuSIZE" "
                            "but should have length %d",
                            ovs_key_attr_to_string(type, namebuf,
                                                   sizeof namebuf),
                            len, expected_len);
            return false;
        }

        if (type > OVS_KEY_ATTR_MAX) {
            *out_of_range_attrp = type;
        } else {
            if (present_attrs & (UINT64_C(1) << type)) {
                char namebuf[OVS_KEY_ATTR_BUFSIZE];

                odp_parse_error(&rl, errorp,
                                "duplicate %s attribute in flow key",
                                ovs_key_attr_to_string(type, namebuf,
                                                       sizeof namebuf));
                return false;
            }

            present_attrs |= UINT64_C(1) << type;
            attrs[type] = nla;
        }
    }
    if (left) {
        odp_parse_error(&rl, errorp, "trailing garbage in flow key");
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

/* Initializes 'flow->dl_type' based on the attributes in 'attrs', in which the
 * attributes in the bit-mask 'present_attrs' are present.  Returns true if
 * successful, false on failure.
 *
 * Sets 1-bits in '*expected_attrs' for the attributes in 'attrs' that were
 * consulted.  'flow' is assumed to be a flow key unless 'src_flow' is nonnull,
 * in which case 'flow' is a flow mask and 'src_flow' is its corresponding
 * previously parsed flow key.
 *
 * If 'errorp' is nonnull and the function returns false, stores a malloc()'d
 * error message in '*errorp'. */
static bool
parse_ethertype(const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1],
                uint64_t present_attrs, uint64_t *expected_attrs,
                struct flow *flow, const struct flow *src_flow,
                char **errorp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    bool is_mask = flow != src_flow;

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE)) {
        flow->dl_type = nl_attr_get_be16(attrs[OVS_KEY_ATTR_ETHERTYPE]);
        if (!is_mask && ntohs(flow->dl_type) < ETH_TYPE_MIN) {
            odp_parse_error(&rl, errorp,
                            "invalid Ethertype %"PRIu16" in flow key",
                            ntohs(flow->dl_type));
            return false;
        }
        if (is_mask && ntohs(src_flow->dl_type) < ETH_TYPE_MIN &&
            flow->dl_type != htons(0xffff)) {
            odp_parse_error(&rl, errorp, "can't bitwise match non-Ethernet II "
                            "\"Ethertype\" %#"PRIx16" (with mask %#"PRIx16")",
                            ntohs(src_flow->dl_type), ntohs(flow->dl_type));
            return false;
        }
        *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE;
    } else {
        if (!is_mask) {
            /* Default ethertype for well-known L3 packets. */
            if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IPV4)) {
                flow->dl_type = htons(ETH_TYPE_IP);
            } else if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IPV6)) {
                flow->dl_type = htons(ETH_TYPE_IPV6);
            } else if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_MPLS)) {
                flow->dl_type = htons(ETH_TYPE_MPLS);
            } else {
                flow->dl_type = htons(FLOW_DL_TYPE_NONE);
            }
        } else if (src_flow->packet_type != htonl(PT_ETH)) {
            /* dl_type is mandatory for non-Ethernet packets */
            flow->dl_type = htons(0xffff);
        } else if (ntohs(src_flow->dl_type) < ETH_TYPE_MIN) {
            /* See comments in odp_flow_key_from_flow__(). */
            odp_parse_error(&rl, errorp,
                            "mask expected for non-Ethernet II frame");
            return false;
        }
    }
    return true;
}

/* Initializes MPLS, L3, and L4 fields in 'flow' based on the attributes in
 * 'attrs', in which the attributes in the bit-mask 'present_attrs' are
 * present.  The caller also indicates an out-of-range attribute
 * 'out_of_range_attr' if one was present when parsing (if so, the fitness
 * cannot be perfect).
 *
 * Sets 1-bits in '*expected_attrs' for the attributes in 'attrs' that were
 * consulted.  'flow' is assumed to be a flow key unless 'src_flow' is nonnull,
 * in which case 'flow' is a flow mask and 'src_flow' is its corresponding
 * previously parsed flow key.
 *
 * Returns fitness based on any discrepancies between present and expected
 * attributes, except that a 'need_check' of false overrides this.
 *
 * If 'errorp' is nonnull and the function returns false, stores a malloc()'d
 * error message in '*errorp'.  'key' and 'key_len' are just used for error
 * reporting in this case. */
static enum odp_key_fitness
parse_l2_5_onward(const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1],
                  uint64_t present_attrs, int out_of_range_attr,
                  uint64_t *expected_attrs, struct flow *flow,
                  const struct nlattr *key, size_t key_len,
                  const struct flow *src_flow, bool need_check, char **errorp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    bool is_mask = src_flow != flow;
    const void *check_start = NULL;
    size_t check_len = 0;
    enum ovs_key_attr expected_bit = 0xff;

    if (eth_type_mpls(src_flow->dl_type)) {
        if (!is_mask || present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_MPLS)) {
            *expected_attrs |= (UINT64_C(1) << OVS_KEY_ATTR_MPLS);
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_MPLS)) {
            size_t size = nl_attr_get_size(attrs[OVS_KEY_ATTR_MPLS]);
            const ovs_be32 *mpls_lse = nl_attr_get(attrs[OVS_KEY_ATTR_MPLS]);
            int n = size / sizeof(ovs_be32);
            int i;

            if (!size || size % sizeof(ovs_be32)) {
                odp_parse_error(&rl, errorp,
                                "MPLS LSEs have invalid length %"PRIuSIZE,
                                size);
                return ODP_FIT_ERROR;
            }
            if (flow->mpls_lse[0] && flow->dl_type != htons(0xffff)) {
                odp_parse_error(&rl, errorp,
                                "unexpected MPLS Ethertype mask %x"PRIx16,
                                ntohs(flow->dl_type));
                return ODP_FIT_ERROR;
            }

            for (i = 0; i < n && i < FLOW_MAX_MPLS_LABELS; i++) {
                flow->mpls_lse[i] = mpls_lse[i];
            }
            if (n > FLOW_MAX_MPLS_LABELS) {
                return ODP_FIT_TOO_MUCH;
            }

            if (!is_mask) {
                /* BOS may be set only in the innermost label. */
                for (i = 0; i < n - 1; i++) {
                    if (flow->mpls_lse[i] & htonl(MPLS_BOS_MASK)) {
                        odp_parse_error(&rl, errorp,
                                        "MPLS BOS set in non-innermost label");
                        return ODP_FIT_ERROR;
                    }
                }

                /* BOS must be set in the innermost label. */
                if (n < FLOW_MAX_MPLS_LABELS
                    && !(flow->mpls_lse[n - 1] & htonl(MPLS_BOS_MASK))) {
                    return ODP_FIT_TOO_LITTLE;
                }
            }
        }

        goto done;
    } else if (src_flow->dl_type == htons(ETH_TYPE_IP)) {
        if (!is_mask) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IPV4;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IPV4)) {
            const struct ovs_key_ipv4 *ipv4_key;

            ipv4_key = nl_attr_get(attrs[OVS_KEY_ATTR_IPV4]);
            put_ipv4_key(ipv4_key, flow, is_mask);
            if (flow->nw_frag > FLOW_NW_FRAG_MASK) {
                odp_parse_error(&rl, errorp, "OVS_KEY_ATTR_IPV4 has invalid "
                                "nw_frag %#"PRIx8, flow->nw_frag);
                return ODP_FIT_ERROR;
            }

            if (is_mask) {
                check_start = ipv4_key;
                check_len = sizeof *ipv4_key;
                expected_bit = OVS_KEY_ATTR_IPV4;
            }
        }
    } else if (src_flow->dl_type == htons(ETH_TYPE_IPV6)) {
        if (!is_mask) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IPV6;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IPV6)) {
            const struct ovs_key_ipv6 *ipv6_key;

            ipv6_key = nl_attr_get(attrs[OVS_KEY_ATTR_IPV6]);
            put_ipv6_key(ipv6_key, flow, is_mask);
            if (flow->nw_frag > FLOW_NW_FRAG_MASK) {
                odp_parse_error(&rl, errorp, "OVS_KEY_ATTR_IPV6 has invalid "
                                "nw_frag %#"PRIx8, flow->nw_frag);
                return ODP_FIT_ERROR;
            }
            if (is_mask) {
                check_start = ipv6_key;
                check_len = sizeof *ipv6_key;
                expected_bit = OVS_KEY_ATTR_IPV6;
            }
        }
    } else if (src_flow->dl_type == htons(ETH_TYPE_ARP) ||
               src_flow->dl_type == htons(ETH_TYPE_RARP)) {
        if (!is_mask) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ARP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ARP)) {
            const struct ovs_key_arp *arp_key;

            arp_key = nl_attr_get(attrs[OVS_KEY_ATTR_ARP]);
            if (!is_mask && (arp_key->arp_op & htons(0xff00))) {
                odp_parse_error(&rl, errorp,
                                "unsupported ARP opcode %"PRIu16" in flow "
                                "key", ntohs(arp_key->arp_op));
                return ODP_FIT_ERROR;
            }
            put_arp_key(arp_key, flow);
            if (is_mask) {
                check_start = arp_key;
                check_len = sizeof *arp_key;
                expected_bit = OVS_KEY_ATTR_ARP;
            }
        }
    } else if (src_flow->dl_type == htons(ETH_TYPE_NSH)) {
        if (!is_mask) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_NSH;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_NSH)) {
            if (odp_nsh_key_from_attr__(attrs[OVS_KEY_ATTR_NSH],
                                        is_mask, &flow->nsh,
                                        NULL, errorp) == ODP_FIT_ERROR) {
                return ODP_FIT_ERROR;
            }
            if (is_mask) {
                check_start = nl_attr_get(attrs[OVS_KEY_ATTR_NSH]);
                check_len = nl_attr_get_size(attrs[OVS_KEY_ATTR_NSH]);
                expected_bit = OVS_KEY_ATTR_NSH;
            }
        }
    } else {
        goto done;
    }
    if (check_len > 0) { /* Happens only when 'is_mask'. */
        if (!is_all_zeros(check_start, check_len) &&
            flow->dl_type != htons(0xffff)) {
            odp_parse_error(&rl, errorp, "unexpected L3 matching with "
                            "masked Ethertype %#"PRIx16"/%#"PRIx16,
                            ntohs(src_flow->dl_type),
                            ntohs(flow->dl_type));
            return ODP_FIT_ERROR;
        } else {
            *expected_attrs |= UINT64_C(1) << expected_bit;
        }
    }

    expected_bit = OVS_KEY_ATTR_UNSPEC;
    if (src_flow->nw_proto == IPPROTO_TCP
        && (src_flow->dl_type == htons(ETH_TYPE_IP) ||
            src_flow->dl_type == htons(ETH_TYPE_IPV6))
        && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_TCP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_TCP)) {
            const union ovs_key_tp *tcp_key;

            tcp_key = nl_attr_get(attrs[OVS_KEY_ATTR_TCP]);
            put_tp_key(tcp_key, flow);
            expected_bit = OVS_KEY_ATTR_TCP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_TCP_FLAGS)) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_TCP_FLAGS;
            flow->tcp_flags = nl_attr_get_be16(attrs[OVS_KEY_ATTR_TCP_FLAGS]);
        }
    } else if (src_flow->nw_proto == IPPROTO_UDP
               && (src_flow->dl_type == htons(ETH_TYPE_IP) ||
                   src_flow->dl_type == htons(ETH_TYPE_IPV6))
               && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_UDP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_UDP)) {
            const union ovs_key_tp *udp_key;

            udp_key = nl_attr_get(attrs[OVS_KEY_ATTR_UDP]);
            put_tp_key(udp_key, flow);
            expected_bit = OVS_KEY_ATTR_UDP;
        }
    } else if (src_flow->nw_proto == IPPROTO_SCTP
               && (src_flow->dl_type == htons(ETH_TYPE_IP) ||
                   src_flow->dl_type == htons(ETH_TYPE_IPV6))
               && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_SCTP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_SCTP)) {
            const union ovs_key_tp *sctp_key;

            sctp_key = nl_attr_get(attrs[OVS_KEY_ATTR_SCTP]);
            put_tp_key(sctp_key, flow);
            expected_bit = OVS_KEY_ATTR_SCTP;
        }
    } else if (src_flow->nw_proto == IPPROTO_ICMP
               && src_flow->dl_type == htons(ETH_TYPE_IP)
               && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ICMP;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ICMP)) {
            const struct ovs_key_icmp *icmp_key;

            icmp_key = nl_attr_get(attrs[OVS_KEY_ATTR_ICMP]);
            flow->tp_src = htons(icmp_key->icmp_type);
            flow->tp_dst = htons(icmp_key->icmp_code);
            expected_bit = OVS_KEY_ATTR_ICMP;
        }
    } else if (src_flow->nw_proto == IPPROTO_ICMPV6
               && src_flow->dl_type == htons(ETH_TYPE_IPV6)
               && !(src_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (!is_mask) {
            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ICMPV6;
        }
        if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ICMPV6)) {
            const struct ovs_key_icmpv6 *icmpv6_key;

            icmpv6_key = nl_attr_get(attrs[OVS_KEY_ATTR_ICMPV6]);
            flow->tp_src = htons(icmpv6_key->icmpv6_type);
            flow->tp_dst = htons(icmpv6_key->icmpv6_code);
            expected_bit = OVS_KEY_ATTR_ICMPV6;
            if (is_nd(src_flow, NULL)) {
                if (!is_mask) {
                    *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ND;
                }
                if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ND)) {
                    const struct ovs_key_nd *nd_key;

                    nd_key = nl_attr_get(attrs[OVS_KEY_ATTR_ND]);
                    flow->nd_target = nd_key->nd_target;
                    flow->arp_sha = nd_key->nd_sll;
                    flow->arp_tha = nd_key->nd_tll;
                    if (is_mask) {
                        /* Even though 'tp_src' and 'tp_dst' are 16 bits wide,
                         * ICMP type and code are 8 bits wide.  Therefore, an
                         * exact match looks like htons(0xff), not
                         * htons(0xffff).  See xlate_wc_finish() for details.
                         * */
                        if (!is_all_zeros(nd_key, sizeof *nd_key) &&
                            (flow->tp_src != htons(0xff) ||
                             flow->tp_dst != htons(0xff))) {
                            odp_parse_error(&rl, errorp,
                                            "ICMP (src,dst) masks should be "
                                            "(0xff,0xff) but are actually "
                                            "(%#"PRIx16",%#"PRIx16")",
                                            ntohs(flow->tp_src),
                                            ntohs(flow->tp_dst));
                            return ODP_FIT_ERROR;
                        } else {
                            *expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ND;
                        }
                    }
                }
                if (present_attrs &
                    (UINT64_C(1) << OVS_KEY_ATTR_ND_EXTENSIONS)) {
                    const struct ovs_key_nd_extensions *nd_ext_key;
                    if (!is_mask) {
                        *expected_attrs |=
                                UINT64_C(1) << OVS_KEY_ATTR_ND_EXTENSIONS;
                    }

                    nd_ext_key =
                        nl_attr_get(attrs[OVS_KEY_ATTR_ND_EXTENSIONS]);
                    flow->igmp_group_ip4 = nd_ext_key->nd_reserved;
                    flow->tcp_flags = htons(nd_ext_key->nd_options_type);

                    if (is_mask) {
                        /* Even though 'tp_src' and 'tp_dst' are 16 bits wide,
                         * ICMP type and code are 8 bits wide.  Therefore, an
                         * exact match looks like htons(0xff), not
                         * htons(0xffff).  See xlate_wc_finish() for details.
                         * */
                        if (!is_all_zeros(nd_ext_key, sizeof *nd_ext_key) &&
                            (flow->tp_src != htons(0xff) ||
                             flow->tp_dst != htons(0xff))) {
                            return ODP_FIT_ERROR;
                        } else {
                            *expected_attrs |=
                                UINT64_C(1) << OVS_KEY_ATTR_ND_EXTENSIONS;
                        }
                    }
                }
            }
        }
    } else if (src_flow->nw_proto == IPPROTO_IGMP
               && src_flow->dl_type == htons(ETH_TYPE_IP)) {
        /* OVS userspace parses the IGMP type, code, and group, but its
         * datapaths do not, so there is always missing information. */
        return ODP_FIT_TOO_LITTLE;
    }
    if (is_mask && expected_bit != OVS_KEY_ATTR_UNSPEC) {
        if ((flow->tp_src || flow->tp_dst) && flow->nw_proto != 0xff) {
            odp_parse_error(&rl, errorp, "flow matches on L4 ports but does "
                            "not define an L4 protocol");
            return ODP_FIT_ERROR;
        } else {
            *expected_attrs |= UINT64_C(1) << expected_bit;
        }
    }

done:
    return need_check ? check_expectations(present_attrs, out_of_range_attr,
                            *expected_attrs, key, key_len) : ODP_FIT_PERFECT;
}

/* Parse 802.1Q header then encapsulated L3 attributes. */
static enum odp_key_fitness
parse_8021q_onward(const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1],
                   uint64_t present_attrs, int out_of_range_attr,
                   uint64_t expected_attrs, struct flow *flow,
                   const struct nlattr *key, size_t key_len,
                   const struct flow *src_flow, char **errorp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    bool is_mask = src_flow != flow;

    const struct nlattr *encap;
    enum odp_key_fitness encap_fitness;
    enum odp_key_fitness fitness = ODP_FIT_ERROR;
    int encaps = 0;

    while (encaps < flow_vlan_limit &&
           (is_mask
            ? (src_flow->vlans[encaps].tci & htons(VLAN_CFI)) != 0
            : eth_type_vlan(flow->dl_type))) {

        encap = (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ENCAP)
                 ? attrs[OVS_KEY_ATTR_ENCAP] : NULL);

        /* Calculate fitness of outer attributes. */
        if (!is_mask) {
            expected_attrs |= ((UINT64_C(1) << OVS_KEY_ATTR_VLAN) |
                              (UINT64_C(1) << OVS_KEY_ATTR_ENCAP));
        } else {
            if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VLAN)) {
                expected_attrs |= (UINT64_C(1) << OVS_KEY_ATTR_VLAN);
            }
            if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ENCAP)) {
                expected_attrs |= (UINT64_C(1) << OVS_KEY_ATTR_ENCAP);
            }
        }
        fitness = check_expectations(present_attrs, out_of_range_attr,
                                     expected_attrs, key, key_len);

        /* Set vlan_tci.
         * Remove the TPID from dl_type since it's not the real Ethertype.  */
        flow->vlans[encaps].tpid = flow->dl_type;
        flow->dl_type = htons(0);
        flow->vlans[encaps].tci =
                        (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VLAN)
                        ? nl_attr_get_be16(attrs[OVS_KEY_ATTR_VLAN])
                        : htons(0));
        if (!is_mask) {
            if (!(present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VLAN)) ||
                !(present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ENCAP))) {
                return ODP_FIT_TOO_LITTLE;
            } else if (flow->vlans[encaps].tci == htons(0)) {
                /* Corner case for a truncated 802.1Q header. */
                if (fitness == ODP_FIT_PERFECT && nl_attr_get_size(encap)) {
                    return ODP_FIT_TOO_MUCH;
                }
                return fitness;
            } else if (!(flow->vlans[encaps].tci & htons(VLAN_CFI))) {
                odp_parse_error(
                    &rl, errorp, "OVS_KEY_ATTR_VLAN 0x%04"PRIx16" is nonzero "
                    "but CFI bit is not set", ntohs(flow->vlans[encaps].tci));
                return ODP_FIT_ERROR;
            }
        } else {
            if (!(present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ENCAP))) {
                return fitness;
            }
        }

        /* Now parse the encapsulated attributes. */
        if (!parse_flow_nlattrs(nl_attr_get(encap), nl_attr_get_size(encap),
                                attrs, &present_attrs, &out_of_range_attr,
                                errorp)) {
            return ODP_FIT_ERROR;
        }
        expected_attrs = 0;

        if (!parse_ethertype(attrs, present_attrs, &expected_attrs,
                             flow, src_flow, errorp)) {
            return ODP_FIT_ERROR;
        }
        encap_fitness = parse_l2_5_onward(attrs, present_attrs,
                                          out_of_range_attr,
                                          &expected_attrs,
                                          flow, key, key_len,
                                          src_flow, false, errorp);
        if (encap_fitness != ODP_FIT_PERFECT) {
            return encap_fitness;
        }
        encaps++;
    }

    return check_expectations(present_attrs, out_of_range_attr,
                              expected_attrs, key, key_len);
}

static enum odp_key_fitness
odp_flow_key_to_flow__(const struct nlattr *key, size_t key_len,
                       struct flow *flow, const struct flow *src_flow,
                       char **errorp)
{
    /* New "struct flow" fields that are visible to the datapath (including all
     * data fields) should be translated from equivalent datapath flow fields
     * here (you will have to add a OVS_KEY_ATTR_* for them).  */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    enum odp_key_fitness fitness = ODP_FIT_ERROR;
    if (errorp) {
        *errorp = NULL;
    }

    const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1];
    uint64_t expected_attrs;
    uint64_t present_attrs;
    int out_of_range_attr;
    bool is_mask = src_flow != flow;

    memset(flow, 0, sizeof *flow);

    /* Parse attributes. */
    if (!parse_flow_nlattrs(key, key_len, attrs, &present_attrs,
                            &out_of_range_attr, errorp)) {
        goto exit;
    }
    expected_attrs = 0;

    /* Metadata. */
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_RECIRC_ID)) {
        flow->recirc_id = nl_attr_get_u32(attrs[OVS_KEY_ATTR_RECIRC_ID]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_RECIRC_ID;
    } else if (is_mask) {
        /* Always exact match recirc_id if it is not specified. */
        flow->recirc_id = UINT32_MAX;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_DP_HASH)) {
        flow->dp_hash = nl_attr_get_u32(attrs[OVS_KEY_ATTR_DP_HASH]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_DP_HASH;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_PRIORITY)) {
        flow->skb_priority = nl_attr_get_u32(attrs[OVS_KEY_ATTR_PRIORITY]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_PRIORITY;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_SKB_MARK)) {
        flow->pkt_mark = nl_attr_get_u32(attrs[OVS_KEY_ATTR_SKB_MARK]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_SKB_MARK;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_STATE)) {
        uint32_t odp_state = nl_attr_get_u32(attrs[OVS_KEY_ATTR_CT_STATE]);

        flow->ct_state = odp_to_ovs_ct_state(odp_state);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_STATE;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_ZONE)) {
        flow->ct_zone = nl_attr_get_u16(attrs[OVS_KEY_ATTR_CT_ZONE]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_ZONE;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_MARK)) {
        flow->ct_mark = nl_attr_get_u32(attrs[OVS_KEY_ATTR_CT_MARK]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_MARK;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_LABELS)) {
        flow->ct_label = nl_attr_get_u128(attrs[OVS_KEY_ATTR_CT_LABELS]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_LABELS;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4)) {
        const struct ovs_key_ct_tuple_ipv4 *ct = nl_attr_get(attrs[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4]);
        flow->ct_nw_src = ct->ipv4_src;
        flow->ct_nw_dst = ct->ipv4_dst;
        flow->ct_nw_proto = ct->ipv4_proto;
        flow->ct_tp_src = ct->src_port;
        flow->ct_tp_dst = ct->dst_port;
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4;
    }
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6)) {
        const struct ovs_key_ct_tuple_ipv6 *ct = nl_attr_get(attrs[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6]);

        flow->ct_ipv6_src = ct->ipv6_src;
        flow->ct_ipv6_dst = ct->ipv6_dst;
        flow->ct_nw_proto = ct->ipv6_proto;
        flow->ct_tp_src = ct->src_port;
        flow->ct_tp_dst = ct->dst_port;
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_TUNNEL)) {
        enum odp_key_fitness res;

        res = odp_tun_key_from_attr__(attrs[OVS_KEY_ATTR_TUNNEL], is_mask,
                                      &flow->tunnel, errorp);
        if (res == ODP_FIT_ERROR) {
            goto exit;
        } else if (res == ODP_FIT_PERFECT) {
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_TUNNEL;
        }
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_IN_PORT)) {
        flow->in_port.odp_port
            = nl_attr_get_odp_port(attrs[OVS_KEY_ATTR_IN_PORT]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_IN_PORT;
    } else if (!is_mask) {
        flow->in_port.odp_port = ODPP_NONE;
    }

    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_PACKET_TYPE)) {
        flow->packet_type
            = nl_attr_get_be32(attrs[OVS_KEY_ATTR_PACKET_TYPE]);
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_PACKET_TYPE;
        if (pt_ns(src_flow->packet_type) == OFPHTN_ETHERTYPE) {
            flow->dl_type = pt_ns_type_be(flow->packet_type);
        }
    } else if (!is_mask) {
        flow->packet_type = htonl(PT_ETH);
    }

    /* Check for Ethernet header. */
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERNET)) {
        const struct ovs_key_ethernet *eth_key;

        eth_key = nl_attr_get(attrs[OVS_KEY_ATTR_ETHERNET]);
        put_ethernet_key(eth_key, flow);
        if (!is_mask) {
            flow->packet_type = htonl(PT_ETH);
        }
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERNET;
    }
    else if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE)) {
        ovs_be16 ethertype = nl_attr_get_be16(attrs[OVS_KEY_ATTR_ETHERTYPE]);
        if (!is_mask) {
            flow->packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE,
                                               ntohs(ethertype));
        }
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_ETHERTYPE;
    }

    /* Get Ethertype or 802.1Q TPID or FLOW_DL_TYPE_NONE. */
    if (!parse_ethertype(attrs, present_attrs, &expected_attrs, flow,
                         src_flow, errorp)) {
        goto exit;
    }

    if (is_mask
        ? (src_flow->vlans[0].tci & htons(VLAN_CFI)) != 0
        : eth_type_vlan(src_flow->dl_type)) {
        fitness = parse_8021q_onward(attrs, present_attrs, out_of_range_attr,
                                     expected_attrs, flow, key, key_len,
                                     src_flow, errorp);
    } else {
        if (is_mask) {
            /* A missing VLAN mask means exact match on vlan_tci 0 (== no
             * VLAN). */
            flow->vlans[0].tpid = htons(0xffff);
            flow->vlans[0].tci = htons(0xffff);
            if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VLAN)) {
                flow->vlans[0].tci = nl_attr_get_be16(
                    attrs[OVS_KEY_ATTR_VLAN]);
                expected_attrs |= (UINT64_C(1) << OVS_KEY_ATTR_VLAN);
            }
        }
        fitness = parse_l2_5_onward(attrs, present_attrs, out_of_range_attr,
                                    &expected_attrs, flow, key, key_len,
                                    src_flow, true, errorp);
    }

exit:;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    if (fitness == ODP_FIT_ERROR && (errorp || !VLOG_DROP_WARN(&rl))) {
        struct ds s = DS_EMPTY_INITIALIZER;
        if (is_mask) {
            ds_put_cstr(&s, "the flow mask in error is: ");
            odp_flow_key_format(key, key_len, &s);
            ds_put_cstr(&s, ", for the following flow key: ");
            flow_format(&s, src_flow, NULL);
        } else {
            ds_put_cstr(&s, "the flow key in error is: ");
            odp_flow_key_format(key, key_len, &s);
        }
        if (errorp) {
            char *old_error = *errorp;
            *errorp = xasprintf("%s; %s", old_error, ds_cstr(&s));
            free(old_error);
        } else {
            VLOG_WARN("%s", ds_cstr(&s));
        }
        ds_destroy(&s);
    }
    return fitness;
}

/* Converts the 'key_len' bytes of OVS_KEY_ATTR_* attributes in 'key' to a flow
 * structure in 'flow'.  Returns an ODP_FIT_* value that indicates how well
 * 'key' fits our expectations for what a flow key should contain.
 *
 * The 'in_port' will be the datapath's understanding of the port.  The
 * caller will need to translate with odp_port_to_ofp_port() if the
 * OpenFlow port is needed.
 *
 * This function doesn't take the packet itself as an argument because none of
 * the currently understood OVS_KEY_ATTR_* attributes require it.  Currently,
 * it is always possible to infer which additional attribute(s) should appear
 * by looking at the attributes for lower-level protocols, e.g. if the network
 * protocol in OVS_KEY_ATTR_IPV4 or OVS_KEY_ATTR_IPV6 is IPPROTO_TCP then we
 * know that a OVS_KEY_ATTR_TCP attribute must appear and that otherwise it
 * must be absent.
 *
 * If 'errorp' is nonnull, this function uses it for detailed error reports: if
 * the return value is ODP_FIT_ERROR, it stores a malloc()'d error string in
 * '*errorp', otherwise NULL. */
enum odp_key_fitness
odp_flow_key_to_flow(const struct nlattr *key, size_t key_len,
                     struct flow *flow, char **errorp)
{
    return odp_flow_key_to_flow__(key, key_len, flow, flow, errorp);
}

/* Converts the 'mask_key_len' bytes of OVS_KEY_ATTR_* attributes in 'mask_key'
 * to a mask structure in 'mask'.  'flow' must be a previously translated flow
 * corresponding to 'mask' and similarly flow_key/flow_key_len must be the
 * attributes from that flow.  Returns an ODP_FIT_* value that indicates how
 * well 'key' fits our expectations for what a flow key should contain.
 *
 * If 'errorp' is nonnull, this function uses it for detailed error reports: if
 * the return value is ODP_FIT_ERROR, it stores a malloc()'d error string in
 * '*errorp', otherwise NULL. */
enum odp_key_fitness
odp_flow_key_to_mask(const struct nlattr *mask_key, size_t mask_key_len,
                     struct flow_wildcards *mask, const struct flow *src_flow,
                     char **errorp)
{
    if (mask_key_len) {
        return odp_flow_key_to_flow__(mask_key, mask_key_len,
                                      &mask->masks, src_flow, errorp);
    } else {
        if (errorp) {
            *errorp = NULL;
        }

        /* A missing mask means that the flow should be exact matched.
         * Generate an appropriate exact wildcard for the flow. */
        flow_wildcards_init_for_packet(mask, src_flow);

        return ODP_FIT_PERFECT;
    }
}

/* Converts the netlink formated key/mask to match.
 * Fails if odp_flow_key_from_key/mask and odp_flow_key_key/mask
 * disagree on the acceptable form of flow */
int
parse_key_and_mask_to_match(const struct nlattr *key, size_t key_len,
                            const struct nlattr *mask, size_t mask_len,
                            struct match *match)
{
    enum odp_key_fitness fitness;

    fitness = odp_flow_key_to_flow(key, key_len, &match->flow, NULL);
    if (fitness) {
        /* This should not happen: it indicates that
         * odp_flow_key_from_flow() and odp_flow_key_to_flow() disagree on
         * the acceptable form of a flow.  Log the problem as an error,
         * with enough details to enable debugging. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        if (!VLOG_DROP_ERR(&rl)) {
            struct ds s;

            ds_init(&s);
            odp_flow_format(key, key_len, NULL, 0, NULL, &s, true);
            VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));
            ds_destroy(&s);
        }

        return EINVAL;
    }

    fitness = odp_flow_key_to_mask(mask, mask_len, &match->wc, &match->flow,
                                   NULL);
    if (fitness) {
        /* This should not happen: it indicates that
         * odp_flow_key_from_mask() and odp_flow_key_to_mask()
         * disagree on the acceptable form of a mask.  Log the problem
         * as an error, with enough details to enable debugging. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        if (!VLOG_DROP_ERR(&rl)) {
            struct ds s;

            ds_init(&s);
            odp_flow_format(key, key_len, mask, mask_len, NULL, &s,
                            true);
            VLOG_ERR("internal error parsing flow mask %s (%s)",
                     ds_cstr(&s), odp_key_fitness_to_string(fitness));
            ds_destroy(&s);
        }

        return EINVAL;
    }

    return 0;
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
 * Netlink PID 'pid'.  If 'userdata' is nonnull, adds a userdata attribute
 * whose contents are the 'userdata_size' bytes at 'userdata' and sets
 * 'odp_actions_ofs' if nonnull with the offset within 'odp_actions' of the
 * start of the cookie.  (If 'userdata' is null, then the 'odp_actions_ofs'
 * value is not meaningful.)
 *
 * Returns negative error code on failure. */
int
odp_put_userspace_action(uint32_t pid,
                         const void *userdata, size_t userdata_size,
                         odp_port_t tunnel_out_port,
                         bool include_actions,
                         struct ofpbuf *odp_actions, size_t *odp_actions_ofs)
{
    size_t userdata_ofs;
    size_t offset;

    offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_USERSPACE);
    nl_msg_put_u32(odp_actions, OVS_USERSPACE_ATTR_PID, pid);
    if (userdata) {
        if (nl_attr_oversized(userdata_size)) {
            return -E2BIG;
        }
        userdata_ofs = odp_actions->size + NLA_HDRLEN;

        /* The OVS kernel module before OVS 1.11 and the upstream Linux kernel
         * module before Linux 3.10 required the userdata to be exactly 8 bytes
         * long:
         *
         *   - The kernel rejected shorter userdata with -ERANGE.
         *
         *   - The kernel silently dropped userdata beyond the first 8 bytes.
         *
         * Thus, for maximum compatibility, always put at least 8 bytes.  (We
         * separately disable features that required more than 8 bytes.) */
        memcpy(nl_msg_put_unspec_zero(odp_actions, OVS_USERSPACE_ATTR_USERDATA,
                                      MAX(8, userdata_size)),
               userdata, userdata_size);
    } else {
        userdata_ofs = 0;
    }
    if (tunnel_out_port != ODPP_NONE) {
        nl_msg_put_odp_port(odp_actions, OVS_USERSPACE_ATTR_EGRESS_TUN_PORT,
                            tunnel_out_port);
    }
    if (include_actions) {
        nl_msg_put_flag(odp_actions, OVS_USERSPACE_ATTR_ACTIONS);
    }
    if (nl_attr_oversized(odp_actions->size - offset - NLA_HDRLEN)) {
        return -E2BIG;
    }
    nl_msg_end_nested(odp_actions, offset);

    if (odp_actions_ofs) {
        *odp_actions_ofs = userdata_ofs;
    }

    return 0;
}

void
odp_put_pop_eth_action(struct ofpbuf *odp_actions)
{
    nl_msg_put_flag(odp_actions, OVS_ACTION_ATTR_POP_ETH);
}

void
odp_put_push_eth_action(struct ofpbuf *odp_actions,
                        const struct eth_addr *eth_src,
                        const struct eth_addr *eth_dst)
{
    struct ovs_action_push_eth eth;

    memset(&eth, 0, sizeof eth);
    if (eth_src) {
        eth.addresses.eth_src = *eth_src;
    }
    if (eth_dst) {
        eth.addresses.eth_dst = *eth_dst;
    }

    nl_msg_put_unspec(odp_actions, OVS_ACTION_ATTR_PUSH_ETH,
                      &eth, sizeof eth);
}

void
odp_put_tunnel_action(const struct flow_tnl *tunnel,
                      struct ofpbuf *odp_actions, const char *tnl_type)
{
    size_t offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_SET);
    tun_key_to_attr(odp_actions, tunnel, tunnel, NULL, tnl_type);
    nl_msg_end_nested(odp_actions, offset);
}

void
odp_put_tnl_push_action(struct ofpbuf *odp_actions,
                        struct ovs_action_push_tnl *data)
{
    int size = offsetof(struct ovs_action_push_tnl, header);

    size += data->header_len;
    nl_msg_put_unspec(odp_actions, OVS_ACTION_ATTR_TUNNEL_PUSH, data, size);
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

/* Masked set actions have a mask following the data within the netlink
 * attribute.  The unmasked bits in the data will be cleared as the data
 * is copied to the action. */
void
commit_masked_set_action(struct ofpbuf *odp_actions,
                         enum ovs_key_attr key_type,
                         const void *key_, const void *mask_, size_t key_size)
{
    size_t offset = nl_msg_start_nested(odp_actions,
                                        OVS_ACTION_ATTR_SET_MASKED);
    char *data = nl_msg_put_unspec_uninit(odp_actions, key_type, key_size * 2);
    const char *key = key_, *mask = mask_;

    memcpy(data + key_size, mask, key_size);
    /* Clear unmasked bits while copying. */
    while (key_size--) {
        *data++ = *key++ & *mask++;
    }
    nl_msg_end_nested(odp_actions, offset);
}

/* If any of the flow key data that ODP actions can modify are different in
 * 'base->tunnel' and 'flow->tunnel', appends a set_tunnel ODP action to
 * 'odp_actions' that change the flow tunneling information in key from
 * 'base->tunnel' into 'flow->tunnel', and then changes 'base->tunnel' in the
 * same way.  In other words, operates the same as commit_odp_actions(), but
 * only on tunneling information. */
void
commit_odp_tunnel_action(const struct flow *flow, struct flow *base,
                         struct ofpbuf *odp_actions, const char *tnl_type)
{
    /* A valid IPV4_TUNNEL must have non-zero ip_dst; a valid IPv6 tunnel
     * must have non-zero ipv6_dst. */
    if (flow_tnl_dst_is_set(&flow->tunnel)) {
        if (!memcmp(&base->tunnel, &flow->tunnel, sizeof base->tunnel)) {
            return;
        }
        memcpy(&base->tunnel, &flow->tunnel, sizeof base->tunnel);
        odp_put_tunnel_action(&base->tunnel, odp_actions, tnl_type);
    }
}

struct offsetof_sizeof {
    int offset;
    int size;
};


/* Performs bitwise OR over the fields in 'dst_' and 'src_' specified in
 * 'offsetof_sizeof_arr' array.  Result is stored in 'dst_'. */
static void
or_masks(void *dst_, const void *src_,
         struct offsetof_sizeof *offsetof_sizeof_arr)
{
    int field, size, offset;
    const uint8_t *src = src_;
    uint8_t *dst = dst_;

    for (field = 0; ; field++) {
        size   = offsetof_sizeof_arr[field].size;
        offset = offsetof_sizeof_arr[field].offset;

        if (!size) {
            return;
        }
        or_bytes(dst + offset, src + offset, size);
    }
}

/* Compares each of the fields in 'key0' and 'key1'.  The fields are specified
 * in 'offsetof_sizeof_arr', which is an array terminated by a 0-size field.
 * Returns true if all of the fields are equal, false if at least one differs.
 * As a side effect, for each field that is the same in 'key0' and 'key1',
 * zeros the corresponding bytes in 'mask'. */
static bool
keycmp_mask(const void *key0, const void *key1,
            struct offsetof_sizeof *offsetof_sizeof_arr, void *mask)
{
    bool differ = false;

    for (int field = 0 ; ; field++) {
        int size = offsetof_sizeof_arr[field].size;
        int offset = offsetof_sizeof_arr[field].offset;
        if (size == 0) {
            break;
        }

        char *pkey0 = ((char *)key0) + offset;
        char *pkey1 = ((char *)key1) + offset;
        char *pmask = ((char *)mask) + offset;
        if (memcmp(pkey0, pkey1, size) == 0) {
            memset(pmask, 0, size);
        } else {
            differ = true;
        }
    }

    return differ;
}

static bool
commit(enum ovs_key_attr attr, bool use_masked_set,
       const void *key, void *base, void *mask, size_t size,
       struct offsetof_sizeof *offsetof_sizeof_arr,
       struct ofpbuf *odp_actions)
{
    if (keycmp_mask(key, base, offsetof_sizeof_arr, mask)) {
        bool fully_masked = odp_mask_is_exact(attr, mask, size);

        if (use_masked_set && !fully_masked) {
            commit_masked_set_action(odp_actions, attr, key, mask, size);
        } else {
            if (!fully_masked) {
                memset(mask, 0xff, size);
            }
            commit_set_action(odp_actions, attr, key, size);
        }
        memcpy(base, key, size);
        return true;
    } else {
        /* Mask bits are set when we have either read or set the corresponding
         * values.  Masked bits will be exact-matched, no need to set them
         * if the value did not actually change. */
        return false;
    }
}

static void
get_ethernet_key(const struct flow *flow, struct ovs_key_ethernet *eth)
{
    eth->eth_src = flow->dl_src;
    eth->eth_dst = flow->dl_dst;
}

static void
put_ethernet_key(const struct ovs_key_ethernet *eth, struct flow *flow)
{
    flow->dl_src = eth->eth_src;
    flow->dl_dst = eth->eth_dst;
}

static void
commit_set_ether_action(const struct flow *flow, struct flow *base_flow,
                        struct ofpbuf *odp_actions,
                        struct flow_wildcards *wc,
                        bool use_masked)
{
    struct ovs_key_ethernet key, base, mask, orig_mask;
    struct offsetof_sizeof ovs_key_ethernet_offsetof_sizeof_arr[] =
        OVS_KEY_ETHERNET_OFFSETOF_SIZEOF_ARR;

    if (flow->packet_type != htonl(PT_ETH) ||
        base_flow->packet_type != htonl(PT_ETH)) {
        return;
    }

    get_ethernet_key(flow, &key);
    get_ethernet_key(base_flow, &base);
    get_ethernet_key(&wc->masks, &mask);
    memcpy(&orig_mask, &mask, sizeof mask);

    if (commit(OVS_KEY_ATTR_ETHERNET, use_masked,
               &key, &base, &mask, sizeof key,
               ovs_key_ethernet_offsetof_sizeof_arr, odp_actions)) {
        put_ethernet_key(&base, base_flow);
        or_masks(&mask, &orig_mask, ovs_key_ethernet_offsetof_sizeof_arr);
        put_ethernet_key(&mask, &wc->masks);
    }
}

static void
commit_vlan_action(const struct flow* flow, struct flow *base,
                   struct ofpbuf *odp_actions, struct flow_wildcards *wc)
{
    int base_n = flow_count_vlan_headers(base);
    int flow_n = flow_count_vlan_headers(flow);
    flow_skip_common_vlan_headers(base, &base_n, flow, &flow_n);

    /* Pop all mismatching vlan of base, push those of flow */
    for (; base_n >= 0; base_n--) {
        nl_msg_put_flag(odp_actions, OVS_ACTION_ATTR_POP_VLAN);
        wc->masks.vlans[base_n].qtag = OVS_BE32_MAX;
    }

    for (; flow_n >= 0; flow_n--) {
        struct ovs_action_push_vlan vlan;

        vlan.vlan_tpid = flow->vlans[flow_n].tpid;
        vlan.vlan_tci = flow->vlans[flow_n].tci;
        nl_msg_put_unspec(odp_actions, OVS_ACTION_ATTR_PUSH_VLAN,
                          &vlan, sizeof vlan);
    }
    memcpy(base->vlans, flow->vlans, sizeof(base->vlans));
}

/* Wildcarding already done at action translation time. */
static void
commit_mpls_action(const struct flow *flow, struct flow *base,
                   struct ofpbuf *odp_actions)
{
    int base_n = flow_count_mpls_labels(base, NULL);
    int flow_n = flow_count_mpls_labels(flow, NULL);
    int common_n = flow_count_common_mpls_labels(flow, flow_n, base, base_n,
                                                 NULL);

    while (base_n > common_n) {
        if (base_n - 1 == common_n && flow_n > common_n) {
            /* If there is only one more LSE in base than there are common
             * between base and flow; and flow has at least one more LSE than
             * is common then the topmost LSE of base may be updated using
             * set */
            struct ovs_key_mpls mpls_key;

            mpls_key.mpls_lse = flow->mpls_lse[flow_n - base_n];
            commit_set_action(odp_actions, OVS_KEY_ATTR_MPLS,
                              &mpls_key, sizeof mpls_key);
            flow_set_mpls_lse(base, 0, mpls_key.mpls_lse);
            common_n++;
        } else {
            /* Otherwise, if there more LSEs in base than are common between
             * base and flow then pop the topmost one. */
            ovs_be16 dl_type;
            /* If all the LSEs are to be popped and this is not the outermost
             * LSE then use ETH_TYPE_MPLS as the ethertype parameter of the
             * POP_MPLS action instead of flow->dl_type.
             *
             * This is because the POP_MPLS action requires its ethertype
             * argument to be an MPLS ethernet type but in this case
             * flow->dl_type will be a non-MPLS ethernet type.
             *
             * When the final POP_MPLS action occurs it use flow->dl_type and
             * the and the resulting packet will have the desired dl_type. */
            if ((!eth_type_mpls(flow->dl_type)) && base_n > 1) {
                dl_type = htons(ETH_TYPE_MPLS);
            } else {
                dl_type = flow->dl_type;
            }
            nl_msg_put_be16(odp_actions, OVS_ACTION_ATTR_POP_MPLS, dl_type);
            ovs_assert(flow_pop_mpls(base, base_n, flow->dl_type, NULL));
            base_n--;
        }
    }

    /* If, after the above popping and setting, there are more LSEs in flow
     * than base then some LSEs need to be pushed. */
    while (base_n < flow_n) {
        struct ovs_action_push_mpls *mpls;

        mpls = nl_msg_put_unspec_zero(odp_actions,
                                      OVS_ACTION_ATTR_PUSH_MPLS,
                                      sizeof *mpls);
        mpls->mpls_ethertype = flow->dl_type;
        mpls->mpls_lse = flow->mpls_lse[flow_n - base_n - 1];
        /* Update base flow's MPLS stack, but do not clear L3.  We need the L3
         * headers if the flow is restored later due to returning from a patch
         * port or group bucket. */
        flow_push_mpls(base, base_n, mpls->mpls_ethertype, NULL, false);
        flow_set_mpls_lse(base, 0, mpls->mpls_lse);
        base_n++;
    }
}

static void
get_ipv4_key(const struct flow *flow, struct ovs_key_ipv4 *ipv4, bool is_mask)
{
    ipv4->ipv4_src = flow->nw_src;
    ipv4->ipv4_dst = flow->nw_dst;
    ipv4->ipv4_proto = flow->nw_proto;
    ipv4->ipv4_tos = flow->nw_tos;
    ipv4->ipv4_ttl = flow->nw_ttl;
    ipv4->ipv4_frag = ovs_to_odp_frag(flow->nw_frag, is_mask);
}

static void
put_ipv4_key(const struct ovs_key_ipv4 *ipv4, struct flow *flow, bool is_mask)
{
    flow->nw_src = ipv4->ipv4_src;
    flow->nw_dst = ipv4->ipv4_dst;
    flow->nw_proto = ipv4->ipv4_proto;
    flow->nw_tos = ipv4->ipv4_tos;
    flow->nw_ttl = ipv4->ipv4_ttl;
    flow->nw_frag = odp_to_ovs_frag(ipv4->ipv4_frag, is_mask);
}

static void
commit_set_ipv4_action(const struct flow *flow, struct flow *base_flow,
                       struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                       bool use_masked)
{
    struct ovs_key_ipv4 key, mask, orig_mask, base;
    struct offsetof_sizeof ovs_key_ipv4_offsetof_sizeof_arr[] =
        OVS_KEY_IPV4_OFFSETOF_SIZEOF_ARR;

    /* Check that nw_proto and nw_frag remain unchanged. */
    ovs_assert(flow->nw_proto == base_flow->nw_proto &&
               flow->nw_frag == base_flow->nw_frag);

    get_ipv4_key(flow, &key, false);
    get_ipv4_key(base_flow, &base, false);
    get_ipv4_key(&wc->masks, &mask, true);
    memcpy(&orig_mask, &mask, sizeof mask);
    mask.ipv4_proto = 0;        /* Not writeable. */
    mask.ipv4_frag = 0;         /* Not writable. */

    if (flow_tnl_dst_is_set(&base_flow->tunnel) &&
        ((base_flow->nw_tos ^ flow->nw_tos) & IP_ECN_MASK) == 0) {
        mask.ipv4_tos &= ~IP_ECN_MASK;
    }

    if (commit(OVS_KEY_ATTR_IPV4, use_masked, &key, &base, &mask, sizeof key,
               ovs_key_ipv4_offsetof_sizeof_arr, odp_actions)) {
        put_ipv4_key(&base, base_flow, false);
        or_masks(&mask, &orig_mask, ovs_key_ipv4_offsetof_sizeof_arr);
        put_ipv4_key(&mask, &wc->masks, true);
   }
}

static void
get_ipv6_key(const struct flow *flow, struct ovs_key_ipv6 *ipv6, bool is_mask)
{
    ipv6->ipv6_src = flow->ipv6_src;
    ipv6->ipv6_dst = flow->ipv6_dst;
    ipv6->ipv6_label = flow->ipv6_label;
    ipv6->ipv6_proto = flow->nw_proto;
    ipv6->ipv6_tclass = flow->nw_tos;
    ipv6->ipv6_hlimit = flow->nw_ttl;
    ipv6->ipv6_frag = ovs_to_odp_frag(flow->nw_frag, is_mask);
}

static void
put_ipv6_key(const struct ovs_key_ipv6 *ipv6, struct flow *flow, bool is_mask)
{
    flow->ipv6_src = ipv6->ipv6_src;
    flow->ipv6_dst = ipv6->ipv6_dst;
    flow->ipv6_label = ipv6->ipv6_label;
    flow->nw_proto = ipv6->ipv6_proto;
    flow->nw_tos = ipv6->ipv6_tclass;
    flow->nw_ttl = ipv6->ipv6_hlimit;
    flow->nw_frag = odp_to_ovs_frag(ipv6->ipv6_frag, is_mask);
}

static void
commit_set_ipv6_action(const struct flow *flow, struct flow *base_flow,
                       struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                       bool use_masked)
{
    struct ovs_key_ipv6 key, mask, orig_mask, base;
    struct offsetof_sizeof ovs_key_ipv6_offsetof_sizeof_arr[] =
        OVS_KEY_IPV6_OFFSETOF_SIZEOF_ARR;

    /* Check that nw_proto and nw_frag remain unchanged. */
    ovs_assert(flow->nw_proto == base_flow->nw_proto &&
               flow->nw_frag == base_flow->nw_frag);

    get_ipv6_key(flow, &key, false);
    get_ipv6_key(base_flow, &base, false);
    get_ipv6_key(&wc->masks, &mask, true);
    memcpy(&orig_mask, &mask, sizeof mask);
    mask.ipv6_proto = 0;        /* Not writeable. */
    mask.ipv6_frag = 0;         /* Not writable. */
    mask.ipv6_label &= htonl(IPV6_LABEL_MASK); /* Not writable. */

    if (flow_tnl_dst_is_set(&base_flow->tunnel) &&
        ((base_flow->nw_tos ^ flow->nw_tos) & IP_ECN_MASK) == 0) {
        mask.ipv6_tclass &= ~IP_ECN_MASK;
    }

    if (commit(OVS_KEY_ATTR_IPV6, use_masked, &key, &base, &mask, sizeof key,
               ovs_key_ipv6_offsetof_sizeof_arr, odp_actions)) {
        put_ipv6_key(&base, base_flow, false);
        or_masks(&mask, &orig_mask, ovs_key_ipv6_offsetof_sizeof_arr);
        put_ipv6_key(&mask, &wc->masks, true);
    }
}

static void
get_arp_key(const struct flow *flow, struct ovs_key_arp *arp)
{
    /* ARP key has padding, clear it. */
    memset(arp, 0, sizeof *arp);

    arp->arp_sip = flow->nw_src;
    arp->arp_tip = flow->nw_dst;
    arp->arp_op = flow->nw_proto == UINT8_MAX ?
                  OVS_BE16_MAX : htons(flow->nw_proto);
    arp->arp_sha = flow->arp_sha;
    arp->arp_tha = flow->arp_tha;
}

static void
put_arp_key(const struct ovs_key_arp *arp, struct flow *flow)
{
    flow->nw_src = arp->arp_sip;
    flow->nw_dst = arp->arp_tip;
    flow->nw_proto = ntohs(arp->arp_op);
    flow->arp_sha = arp->arp_sha;
    flow->arp_tha = arp->arp_tha;
}

static enum slow_path_reason
commit_set_arp_action(const struct flow *flow, struct flow *base_flow,
                      struct ofpbuf *odp_actions, struct flow_wildcards *wc)
{
    struct ovs_key_arp key, mask, orig_mask, base;
    struct offsetof_sizeof ovs_key_arp_offsetof_sizeof_arr[] =
        OVS_KEY_ARP_OFFSETOF_SIZEOF_ARR;

    get_arp_key(flow, &key);
    get_arp_key(base_flow, &base);
    get_arp_key(&wc->masks, &mask);
    memcpy(&orig_mask, &mask, sizeof mask);

    if (commit(OVS_KEY_ATTR_ARP, true, &key, &base, &mask, sizeof key,
               ovs_key_arp_offsetof_sizeof_arr, odp_actions)) {
        put_arp_key(&base, base_flow);
        or_masks(&mask, &orig_mask, ovs_key_arp_offsetof_sizeof_arr);
        put_arp_key(&mask, &wc->masks);
        return SLOW_ACTION;
    }
    return 0;
}

static void
get_icmp_key(const struct flow *flow, struct ovs_key_icmp *icmp)
{
    /* icmp_type and icmp_code are stored in tp_src and tp_dst, respectively */
    icmp->icmp_type = ntohs(flow->tp_src);
    icmp->icmp_code = ntohs(flow->tp_dst);
}

static void
put_icmp_key(const struct ovs_key_icmp *icmp, struct flow *flow)
{
    /* icmp_type and icmp_code are stored in tp_src and tp_dst, respectively */
    flow->tp_src = htons(icmp->icmp_type);
    flow->tp_dst = htons(icmp->icmp_code);
}

static enum slow_path_reason
commit_set_icmp_action(const struct flow *flow, struct flow *base_flow,
                       struct ofpbuf *odp_actions, struct flow_wildcards *wc)
{
    struct ovs_key_icmp key, mask, orig_mask, base;
    struct offsetof_sizeof ovs_key_icmp_offsetof_sizeof_arr[] =
        OVS_KEY_ICMP_OFFSETOF_SIZEOF_ARR;
    enum ovs_key_attr attr;

    if (is_icmpv4(flow, NULL)) {
        attr = OVS_KEY_ATTR_ICMP;
    } else if (is_icmpv6(flow, NULL)) {
        attr = OVS_KEY_ATTR_ICMPV6;
    } else {
        return 0;
    }

    get_icmp_key(flow, &key);
    get_icmp_key(base_flow, &base);
    get_icmp_key(&wc->masks, &mask);
    memcpy(&orig_mask, &mask, sizeof mask);

    if (commit(attr, false, &key, &base, &mask, sizeof key,
               ovs_key_icmp_offsetof_sizeof_arr, odp_actions)) {
        put_icmp_key(&base, base_flow);
        or_masks(&mask, &orig_mask, ovs_key_icmp_offsetof_sizeof_arr);
        put_icmp_key(&mask, &wc->masks);
        return SLOW_ACTION;
    }
    return 0;
}

static void
get_nd_key(const struct flow *flow, struct ovs_key_nd *nd)
{
    nd->nd_target = flow->nd_target;
    /* nd_sll and nd_tll are stored in arp_sha and arp_tha, respectively */
    nd->nd_sll = flow->arp_sha;
    nd->nd_tll = flow->arp_tha;
}

static void
put_nd_key(const struct ovs_key_nd *nd, struct flow *flow)
{
    flow->nd_target = nd->nd_target;
    /* nd_sll and nd_tll are stored in arp_sha and arp_tha, respectively */
    flow->arp_sha = nd->nd_sll;
    flow->arp_tha = nd->nd_tll;
}

static void
get_nd_extensions_key(const struct flow *flow,
                      struct ovs_key_nd_extensions *nd_ext)
{
    /* ND Extensions key has padding, clear it. */
    memset(nd_ext, 0, sizeof *nd_ext);
    nd_ext->nd_reserved = flow->igmp_group_ip4;
    nd_ext->nd_options_type = ntohs(flow->tcp_flags);
}

static void
put_nd_extensions_key(const struct ovs_key_nd_extensions *nd_ext,
                      struct flow *flow)
{
    flow->igmp_group_ip4 = nd_ext->nd_reserved;
    flow->tcp_flags = htons(nd_ext->nd_options_type);
}

static enum slow_path_reason
commit_set_nd_action(const struct flow *flow, struct flow *base_flow,
                     struct ofpbuf *odp_actions,
                     struct flow_wildcards *wc, bool use_masked)
{
    struct ovs_key_nd key, mask, orig_mask, base;
    struct offsetof_sizeof ovs_key_nd_offsetof_sizeof_arr[] =
        OVS_KEY_ND_OFFSETOF_SIZEOF_ARR;

    get_nd_key(flow, &key);
    get_nd_key(base_flow, &base);
    get_nd_key(&wc->masks, &mask);
    memcpy(&orig_mask, &mask, sizeof mask);

    if (commit(OVS_KEY_ATTR_ND, use_masked, &key, &base, &mask, sizeof key,
               ovs_key_nd_offsetof_sizeof_arr, odp_actions)) {
        put_nd_key(&base, base_flow);
        or_masks(&mask, &orig_mask, ovs_key_nd_offsetof_sizeof_arr);
        put_nd_key(&mask, &wc->masks);
        return SLOW_ACTION;
    }

    return 0;
}

static enum slow_path_reason
commit_set_nd_extensions_action(const struct flow *flow,
                                struct flow *base_flow,
                                struct ofpbuf *odp_actions,
                                struct flow_wildcards *wc, bool use_masked)
{
    struct ovs_key_nd_extensions key, mask, orig_mask, base;
    struct offsetof_sizeof ovs_key_nd_extensions_offsetof_sizeof_arr[] =
        OVS_KEY_ND_EXTENSIONS_OFFSETOF_SIZEOF_ARR;

    get_nd_extensions_key(flow, &key);
    get_nd_extensions_key(base_flow, &base);
    get_nd_extensions_key(&wc->masks, &mask);
    memcpy(&orig_mask, &mask, sizeof mask);

    if (commit(OVS_KEY_ATTR_ND_EXTENSIONS, use_masked, &key, &base, &mask,
               sizeof key, ovs_key_nd_extensions_offsetof_sizeof_arr,
               odp_actions)) {
        put_nd_extensions_key(&base, base_flow);
        or_masks(&mask, &orig_mask, ovs_key_nd_extensions_offsetof_sizeof_arr);
        put_nd_extensions_key(&mask, &wc->masks);
        return SLOW_ACTION;
    }
    return 0;
}

static enum slow_path_reason
commit_set_nw_action(const struct flow *flow, struct flow *base,
                     struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                     bool use_masked)
{
    uint32_t reason;

    /* Check if 'flow' really has an L3 header. */
    if (!flow->nw_proto) {
        return 0;
    }

    switch (ntohs(base->dl_type)) {
    case ETH_TYPE_IP:
        commit_set_ipv4_action(flow, base, odp_actions, wc, use_masked);
        break;

    case ETH_TYPE_IPV6:
        commit_set_ipv6_action(flow, base, odp_actions, wc, use_masked);
        if (base->nw_proto == IPPROTO_ICMPV6) {
            /* Commit extended attrs first to make sure
               correct options are added.*/
            reason = commit_set_nd_extensions_action(flow, base,
                                         odp_actions, wc, use_masked);
            reason |= commit_set_nd_action(flow, base, odp_actions,
                                         wc, use_masked);
            return reason;
        }
        break;

    case ETH_TYPE_ARP:
        return commit_set_arp_action(flow, base, odp_actions, wc);
    }

    return 0;
}

static inline void
get_nsh_key(const struct flow *flow, struct ovs_key_nsh *nsh, bool is_mask)
{
    *nsh = flow->nsh;
    if (!is_mask) {
        if (nsh->mdtype != NSH_M_TYPE1) {
            memset(nsh->context, 0, sizeof(nsh->context));
        }
    }
}

static inline void
put_nsh_key(const struct ovs_key_nsh *nsh, struct flow *flow,
            bool is_mask OVS_UNUSED)
{
    flow->nsh = *nsh;
    if (flow->nsh.mdtype != NSH_M_TYPE1) {
        memset(flow->nsh.context, 0, sizeof(flow->nsh.context));
    }
}

static bool
commit_nsh(const struct ovs_key_nsh * flow_nsh, bool use_masked_set,
           const struct ovs_key_nsh *key, struct ovs_key_nsh *base,
           struct ovs_key_nsh *mask, size_t size,
           struct ofpbuf *odp_actions)
{
    enum ovs_key_attr attr = OVS_KEY_ATTR_NSH;

    if (memcmp(key, base, size)  == 0) {
        /* Mask bits are set when we have either read or set the corresponding
         * values.  Masked bits will be exact-matched, no need to set them
         * if the value did not actually change. */
        return false;
    }

    bool fully_masked = odp_mask_is_exact(attr, mask, size);

    if (use_masked_set && !fully_masked) {
        size_t nsh_key_ofs;
        struct ovs_nsh_key_base nsh_base;
        struct ovs_nsh_key_base nsh_base_mask;
        struct ovs_nsh_key_md1 md1;
        struct ovs_nsh_key_md1 md1_mask;
        size_t offset = nl_msg_start_nested(odp_actions,
                                            OVS_ACTION_ATTR_SET_MASKED);

        nsh_base.flags = key->flags;
        nsh_base.ttl = key->ttl;
        nsh_base.mdtype = key->mdtype;
        nsh_base.np = key->np;
        nsh_base.path_hdr = key->path_hdr;

        nsh_base_mask.flags = mask->flags;
        nsh_base_mask.ttl = mask->ttl;
        nsh_base_mask.mdtype = mask->mdtype;
        nsh_base_mask.np = mask->np;
        nsh_base_mask.path_hdr = mask->path_hdr;

        /* OVS_KEY_ATTR_NSH keys */
        nsh_key_ofs = nl_msg_start_nested(odp_actions, OVS_KEY_ATTR_NSH);

        /* put value and mask for OVS_NSH_KEY_ATTR_BASE */
        char *data = nl_msg_put_unspec_uninit(odp_actions,
                                              OVS_NSH_KEY_ATTR_BASE,
                                              2 * sizeof(nsh_base));
        const char *lkey = (char *)&nsh_base, *lmask = (char *)&nsh_base_mask;
        size_t lkey_size = sizeof(nsh_base);

        while (lkey_size--) {
            *data++ = *lkey++ & *lmask++;
        }
        lmask = (char *)&nsh_base_mask;
        memcpy(data, lmask, sizeof(nsh_base_mask));

        switch (key->mdtype) {
        case NSH_M_TYPE1:
            memcpy(md1.context, key->context, sizeof key->context);
            memcpy(md1_mask.context, mask->context, sizeof mask->context);

            /* put value and mask for OVS_NSH_KEY_ATTR_MD1 */
            data = nl_msg_put_unspec_uninit(odp_actions,
                                            OVS_NSH_KEY_ATTR_MD1,
                                            2 * sizeof(md1));
            lkey = (char *)&md1;
            lmask = (char *)&md1_mask;
            lkey_size = sizeof(md1);

            while (lkey_size--) {
                *data++ = *lkey++ & *lmask++;
            }
            lmask = (char *)&md1_mask;
            memcpy(data, lmask, sizeof(md1_mask));
            break;
        case NSH_M_TYPE2:
        default:
            /* No match support for other MD formats yet. */
            break;
        }

        nl_msg_end_nested(odp_actions, nsh_key_ofs);

        nl_msg_end_nested(odp_actions, offset);
    } else {
        if (!fully_masked) {
            memset(mask, 0xff, size);
        }
        size_t offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_SET);
        nsh_key_to_attr(odp_actions, flow_nsh, NULL, 0, false);
        nl_msg_end_nested(odp_actions, offset);
    }
    memcpy(base, key, size);
    return true;
}

static void
commit_set_nsh_action(const struct flow *flow, struct flow *base_flow,
                      struct ofpbuf *odp_actions,
                      struct flow_wildcards *wc,
                      bool use_masked)
{
    struct ovs_key_nsh key, mask, base;

    if (flow->dl_type != htons(ETH_TYPE_NSH) ||
        !memcmp(&base_flow->nsh, &flow->nsh, sizeof base_flow->nsh)) {
        return;
    }

    /* Check that mdtype and np remain unchanged. */
    ovs_assert(flow->nsh.mdtype == base_flow->nsh.mdtype &&
               flow->nsh.np == base_flow->nsh.np);

    get_nsh_key(flow, &key, false);
    get_nsh_key(base_flow, &base, false);
    get_nsh_key(&wc->masks, &mask, true);
    mask.mdtype = 0;     /* Not writable. */
    mask.np = 0;         /* Not writable. */

    if (commit_nsh(&base_flow->nsh, use_masked, &key, &base, &mask,
            sizeof key, odp_actions)) {
        put_nsh_key(&base, base_flow, false);
        if (mask.mdtype != 0) { /* Mask was changed by commit(). */
            put_nsh_key(&mask, &wc->masks, true);
        }
    }
}

/* TCP, UDP, and SCTP keys have the same layout. */
BUILD_ASSERT_DECL(sizeof(struct ovs_key_tcp) == sizeof(struct ovs_key_udp) &&
                  sizeof(struct ovs_key_tcp) == sizeof(struct ovs_key_sctp));

static void
get_tp_key(const struct flow *flow, union ovs_key_tp *tp)
{
    tp->tcp.tcp_src = flow->tp_src;
    tp->tcp.tcp_dst = flow->tp_dst;
}

static void
put_tp_key(const union ovs_key_tp *tp, struct flow *flow)
{
    flow->tp_src = tp->tcp.tcp_src;
    flow->tp_dst = tp->tcp.tcp_dst;
}

static void
commit_set_port_action(const struct flow *flow, struct flow *base_flow,
                       struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                       bool use_masked)
{
    enum ovs_key_attr key_type;
    union ovs_key_tp key, mask, orig_mask, base;
    struct offsetof_sizeof ovs_key_tp_offsetof_sizeof_arr[] =
        OVS_KEY_TCP_OFFSETOF_SIZEOF_ARR;

    /* Check if 'flow' really has an L3 header. */
    if (!flow->nw_proto) {
        return;
    }

    if (!is_ip_any(base_flow)) {
        return;
    }

    if (flow->nw_proto == IPPROTO_TCP) {
        key_type = OVS_KEY_ATTR_TCP;
    } else if (flow->nw_proto == IPPROTO_UDP) {
        key_type = OVS_KEY_ATTR_UDP;
    } else if (flow->nw_proto == IPPROTO_SCTP) {
        key_type = OVS_KEY_ATTR_SCTP;
    } else {
        return;
    }

    get_tp_key(flow, &key);
    get_tp_key(base_flow, &base);
    get_tp_key(&wc->masks, &mask);
    memcpy(&orig_mask, &mask, sizeof mask);

    if (commit(key_type, use_masked, &key, &base, &mask, sizeof key,
               ovs_key_tp_offsetof_sizeof_arr, odp_actions)) {
        put_tp_key(&base, base_flow);
        or_masks(&mask, &orig_mask, ovs_key_tp_offsetof_sizeof_arr);
        put_tp_key(&mask, &wc->masks);
    }
}

static void
commit_set_priority_action(const struct flow *flow, struct flow *base_flow,
                           struct ofpbuf *odp_actions,
                           struct flow_wildcards *wc,
                           bool use_masked)
{
    uint32_t key, mask, base;
    struct offsetof_sizeof ovs_key_prio_offsetof_sizeof_arr[] = {
        {0, sizeof(uint32_t)},
        {0, 0}
    };

    key = flow->skb_priority;
    base = base_flow->skb_priority;
    mask = wc->masks.skb_priority;

    if (commit(OVS_KEY_ATTR_PRIORITY, use_masked, &key, &base, &mask,
               sizeof key, ovs_key_prio_offsetof_sizeof_arr, odp_actions)) {
        base_flow->skb_priority = base;
        wc->masks.skb_priority |= mask;
    }
}

static void
commit_set_pkt_mark_action(const struct flow *flow, struct flow *base_flow,
                           struct ofpbuf *odp_actions,
                           struct flow_wildcards *wc,
                           bool use_masked)
{
    uint32_t key, mask, base;
    struct offsetof_sizeof ovs_key_pkt_mark_offsetof_sizeof_arr[] = {
        {0, sizeof(uint32_t)},
        {0, 0}
    };

    key = flow->pkt_mark;
    base = base_flow->pkt_mark;
    mask = wc->masks.pkt_mark;

    if (commit(OVS_KEY_ATTR_SKB_MARK, use_masked, &key, &base, &mask,
               sizeof key, ovs_key_pkt_mark_offsetof_sizeof_arr,
               odp_actions)) {
        base_flow->pkt_mark = base;
        wc->masks.pkt_mark |= mask;
    }
}

static void
odp_put_pop_nsh_action(struct ofpbuf *odp_actions)
{
    nl_msg_put_flag(odp_actions, OVS_ACTION_ATTR_POP_NSH);
}

static void
odp_put_push_nsh_action(struct ofpbuf *odp_actions,
                         const struct flow *flow,
                         struct ofpbuf *encap_data)
{
    uint8_t * metadata = NULL;
    uint8_t md_size = 0;

    switch (flow->nsh.mdtype) {
    case NSH_M_TYPE2:
        if (encap_data) {
            ovs_assert(encap_data->size < NSH_CTX_HDRS_MAX_LEN);
            metadata = encap_data->data;
            md_size = encap_data->size;
        } else {
            md_size = 0;
        }
        break;
    default:
        md_size = 0;
        break;
    }
    size_t offset = nl_msg_start_nested(odp_actions, OVS_ACTION_ATTR_PUSH_NSH);
    nsh_key_to_attr(odp_actions, &flow->nsh, metadata, md_size, false);
    nl_msg_end_nested(odp_actions, offset);
}

static void
commit_encap_decap_action(const struct flow *flow,
                          struct flow *base_flow,
                          struct ofpbuf *odp_actions,
                          struct flow_wildcards *wc,
                          bool pending_encap, bool pending_decap,
                          struct ofpbuf *encap_data)
{
    if (pending_encap) {
        switch (ntohl(flow->packet_type)) {
        case PT_ETH: {
            /* push_eth */
            odp_put_push_eth_action(odp_actions, &flow->dl_src,
                                    &flow->dl_dst);
            base_flow->packet_type = flow->packet_type;
            base_flow->dl_src = flow->dl_src;
            base_flow->dl_dst = flow->dl_dst;
            break;
        }
        case PT_NSH:
            /* push_nsh */
            odp_put_push_nsh_action(odp_actions, flow, encap_data);
            base_flow->packet_type = flow->packet_type;
            /* Update all packet headers in base_flow. */
            memcpy(&base_flow->dl_dst, &flow->dl_dst,
                   sizeof(*flow) - offsetof(struct flow, dl_dst));
            break;
        default:
            /* Only the above protocols are supported for encap.
             * The check is done at action translation. */
            OVS_NOT_REACHED();
        }
    } else if (pending_decap || flow->packet_type != base_flow->packet_type) {
        /* This is an explicit or implicit decap case. */
        if (pt_ns(flow->packet_type) == OFPHTN_ETHERTYPE &&
            base_flow->packet_type == htonl(PT_ETH)) {
            /* Generate pop_eth and continue without recirculation. */
            odp_put_pop_eth_action(odp_actions);
            base_flow->packet_type = flow->packet_type;
            base_flow->dl_src = eth_addr_zero;
            base_flow->dl_dst = eth_addr_zero;
        } else {
            /* All other decap cases require recirculation.
             * No need to update the base flow here. */
            switch (ntohl(base_flow->packet_type)) {
            case PT_NSH:
                /* pop_nsh. */
                odp_put_pop_nsh_action(odp_actions);
                break;
            default:
                /* Checks are done during translation. */
                OVS_NOT_REACHED();
            }
        }
    }

    wc->masks.packet_type = OVS_BE32_MAX;
}

/* If any of the flow key data that ODP actions can modify are different in
 * 'base' and 'flow', appends ODP actions to 'odp_actions' that change the flow
 * key from 'base' into 'flow', and then changes 'base' the same way.  Does not
 * commit set_tunnel actions.  Users should call commit_odp_tunnel_action()
 * in addition to this function if needed.  Sets fields in 'wc' that are
 * used as part of the action.
 *
 * In the common case, this function returns 0.  If the flow key modification
 * requires the flow's packets to be forced into the userspace slow path, this
 * function returns SLOW_ACTION.  This only happens when there is no ODP action
 * to modify some field that was actually modified.  For example, there is no
 * ODP action to modify any ARP field, so such a modification triggers
 * SLOW_ACTION.  (When this happens, packets that need such modification get
 * flushed to userspace and handled there, which works OK but much more slowly
 * than if the datapath handled it directly.) */
enum slow_path_reason
commit_odp_actions(const struct flow *flow, struct flow *base,
                   struct ofpbuf *odp_actions, struct flow_wildcards *wc,
                   bool use_masked, bool pending_encap, bool pending_decap,
                   struct ofpbuf *encap_data)
{
    /* If you add a field that OpenFlow actions can change, and that is visible
     * to the datapath (including all data fields), then you should also add
     * code here to commit changes to the field. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    enum slow_path_reason slow1, slow2;
    bool mpls_done = false;

    commit_encap_decap_action(flow, base, odp_actions, wc,
                              pending_encap, pending_decap, encap_data);
    commit_set_ether_action(flow, base, odp_actions, wc, use_masked);
    /* Make packet a non-MPLS packet before committing L3/4 actions,
     * which would otherwise do nothing. */
    if (eth_type_mpls(base->dl_type) && !eth_type_mpls(flow->dl_type)) {
        commit_mpls_action(flow, base, odp_actions);
        mpls_done = true;
    }
    commit_set_nsh_action(flow, base, odp_actions, wc, use_masked);
    slow1 = commit_set_nw_action(flow, base, odp_actions, wc, use_masked);
    commit_set_port_action(flow, base, odp_actions, wc, use_masked);
    slow2 = commit_set_icmp_action(flow, base, odp_actions, wc);
    if (!mpls_done) {
        commit_mpls_action(flow, base, odp_actions);
    }
    commit_vlan_action(flow, base, odp_actions, wc);
    commit_set_priority_action(flow, base, odp_actions, wc, use_masked);
    commit_set_pkt_mark_action(flow, base, odp_actions, wc, use_masked);

    return slow1 ? slow1 : slow2;
}
