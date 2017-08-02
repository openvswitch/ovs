/*
 * Copyright (c) 2015 Nicira, Inc.
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

#include "netlink-conntrack.h"

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nf_conntrack_ftp.h>
#include <linux/netfilter/nf_conntrack_sctp.h>

#include "byte-order.h"
#include "compiler.h"
#include "openvswitch/dynamic-string.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "poll-loop.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(netlink_conntrack);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* This module works only if conntrack modules and features are enabled in the
 * Linux kernel.  This can be done from a root shell like this:
 *
 * $ modprobe ip_conntrack
 * $ sysctl -w net.netfilter.nf_conntrack_acct=1
 * $ sysctl -w net.netfilter.nf_conntrack_timestamp=1
 *
 * Also, if testing conntrack label feature without conntrack-aware OVS kernel
 * module, there must be a connlabel rule in iptables for space to be reserved
 * for the labels (see kernel source connlabel_mt_check()).  Such a rule can be
 * inserted from a root shell like this:
 *
 * $ iptables -A INPUT -m conntrack -m connlabel \
 *   --ctstate NEW,ESTABLISHED,RELATED --label 127 -j ACCEPT
 */

/* Some attributes were introduced in later kernels: with these definitions
 * we should be able to compile userspace against Linux 2.6.32+. */

#define CTA_ZONE          (CTA_SECMARK + 1)
#define CTA_SECCTX        (CTA_SECMARK + 2)
#define CTA_TIMESTAMP     (CTA_SECMARK + 3)
#define CTA_MARK_MASK     (CTA_SECMARK + 4)
#define CTA_LABELS        (CTA_SECMARK + 5)
#define CTA_LABELS_MASK   (CTA_SECMARK + 6)

#define CTA_TIMESTAMP_START 1
#define CTA_TIMESTAMP_STOP  2

#define IPS_TEMPLATE_BIT 11
#define IPS_TEMPLATE (1 << IPS_TEMPLATE_BIT)

#define IPS_UNTRACKED_BIT 12
#define IPS_UNTRACKED (1 << IPS_UNTRACKED_BIT)

static const struct nl_policy nfnlgrp_conntrack_policy[] = {
    [CTA_TUPLE_ORIG] = { .type = NL_A_NESTED, .optional = false },
    [CTA_TUPLE_REPLY] = { .type = NL_A_NESTED, .optional = false },
    [CTA_ZONE] = { .type = NL_A_BE16, .optional = true },
    [CTA_STATUS] = { .type = NL_A_BE32, .optional = false },
    [CTA_TIMESTAMP] = { .type = NL_A_NESTED, .optional = true },
    [CTA_TIMEOUT] = { .type = NL_A_BE32, .optional = true },
    [CTA_COUNTERS_ORIG] = { .type = NL_A_NESTED, .optional = true },
    [CTA_COUNTERS_REPLY] = { .type = NL_A_NESTED, .optional = true },
    [CTA_PROTOINFO] = { .type = NL_A_NESTED, .optional = true },
    [CTA_HELP] = { .type = NL_A_NESTED, .optional = true },
    [CTA_MARK] = { .type = NL_A_BE32, .optional = true },
    [CTA_SECCTX] = { .type = NL_A_NESTED, .optional = true },
    [CTA_ID] = { .type = NL_A_BE32, .optional = false },
    [CTA_USE] = { .type = NL_A_BE32, .optional = true },
    [CTA_TUPLE_MASTER] = { .type = NL_A_NESTED, .optional = true },
    [CTA_NAT_SEQ_ADJ_ORIG] = { .type = NL_A_NESTED, .optional = true },
    [CTA_NAT_SEQ_ADJ_REPLY] = { .type = NL_A_NESTED, .optional = true },
    [CTA_LABELS] = { .type = NL_A_UNSPEC, .optional = true },
    /* CTA_NAT_SRC, CTA_NAT_DST, CTA_TIMESTAMP, CTA_MARK_MASK, and
     * CTA_LABELS_MASK are not received from kernel. */
};

/* Declarations for conntrack netlink dumping. */
static void nl_msg_put_nfgenmsg(struct ofpbuf *msg, size_t expected_payload,
                                int family, uint8_t subsystem, uint8_t cmd,
                                uint32_t flags);

static bool nl_ct_parse_header_policy(struct ofpbuf *buf,
        enum nl_ct_event_type *event_type,
        uint8_t *nfgen_family,
        struct nlattr *attrs[ARRAY_SIZE(nfnlgrp_conntrack_policy)]);

static bool nl_ct_attrs_to_ct_dpif_entry(struct ct_dpif_entry *entry,
        struct nlattr *attrs[ARRAY_SIZE(nfnlgrp_conntrack_policy)],
        uint8_t nfgen_family);

struct nl_ct_dump_state {
    struct nl_dump dump;
    struct ofpbuf buf;
    bool filter_zone;
    uint16_t zone;
};

/* Conntrack netlink dumping. */

/* Initialize a conntrack netlink dump. */
int
nl_ct_dump_start(struct nl_ct_dump_state **statep, const uint16_t *zone,
        int *ptot_bkts)
{
    struct nl_ct_dump_state *state;

    *statep = state = xzalloc(sizeof *state);
    ofpbuf_init(&state->buf, NL_DUMP_BUFSIZE);

    if (zone) {
        state->filter_zone = true;
        state->zone = *zone;
    }

    nl_msg_put_nfgenmsg(&state->buf, 0, AF_UNSPEC, NFNL_SUBSYS_CTNETLINK,
                        IPCTNL_MSG_CT_GET, NLM_F_REQUEST);
    nl_dump_start(&state->dump, NETLINK_NETFILTER, &state->buf);
    ofpbuf_clear(&state->buf);

    /* Buckets to store connections are not used. */
    *ptot_bkts = -1;

    return 0;
}

/* Receive the next 'entry' from the conntrack netlink dump with 'state'.
 * Returns 'EOF' when no more entries are available, 0 otherwise.  'entry' may
 * be uninitilized memory on entry, and must be uninitialized with
 * ct_dpif_entry_uninit() afterwards by the caller.  In case the same 'entry' is
 * passed to this function again, the entry must also be uninitialized before
 * the next call. */
int
nl_ct_dump_next(struct nl_ct_dump_state *state, struct ct_dpif_entry *entry)
{
    struct ofpbuf buf;

    memset(entry, 0, sizeof *entry);
    for (;;) {
        struct nlattr *attrs[ARRAY_SIZE(nfnlgrp_conntrack_policy)];
        enum nl_ct_event_type type;
        uint8_t nfgen_family;

        if (!nl_dump_next(&state->dump, &buf, &state->buf)) {
            return EOF;
        }

        if (!nl_ct_parse_header_policy(&buf, &type, &nfgen_family, attrs)) {
            continue;
        };

        if (state->filter_zone) {
            uint16_t entry_zone = attrs[CTA_ZONE]
                                  ? ntohs(nl_attr_get_be16(attrs[CTA_ZONE]))
                                  : 0;
            if (entry_zone != state->zone) {
                continue;
            }
        }

        if (nl_ct_attrs_to_ct_dpif_entry(entry, attrs, nfgen_family)) {
            break;
        }

        ct_dpif_entry_uninit(entry);
        memset(entry, 0, sizeof *entry);
        /* Ignore the failed entry and get the next one. */
    }

    ofpbuf_uninit(&buf);
    return 0;
}

/* End a conntrack netlink dump. */
int
nl_ct_dump_done(struct nl_ct_dump_state *state)
{
    int error = nl_dump_done(&state->dump);

    ofpbuf_uninit(&state->buf);
    free(state);
    return error;
}

/* Format conntrack event 'entry' of 'type' to 'ds'. */
void
nl_ct_format_event_entry(const struct ct_dpif_entry *entry,
                         enum nl_ct_event_type type, struct ds *ds,
                         bool verbose, bool print_stats)
{
    ds_put_format(ds, "%s ",
                  type == NL_CT_EVENT_NEW ? "NEW"
                  : type == NL_CT_EVENT_UPDATE ? "UPDATE"
                  : type == NL_CT_EVENT_DELETE ? "DELETE"
                  : "UNKNOWN");
    ct_dpif_format_entry(entry, ds, verbose, print_stats);
}

int
nl_ct_flush(void)
{
    struct ofpbuf buf;
    int err;

    ofpbuf_init(&buf, NL_DUMP_BUFSIZE);

    nl_msg_put_nfgenmsg(&buf, 0, AF_UNSPEC, NFNL_SUBSYS_CTNETLINK,
                        IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST);

    err = nl_transact(NETLINK_NETFILTER, &buf, NULL);
    ofpbuf_uninit(&buf);

    /* Expectations are flushed automatically, because they do not
     * have a master connection anymore */

    return err;
}

#ifdef _WIN32
int
nl_ct_flush_zone(uint16_t flush_zone)
{
    /* Windows can flush a specific zone */
    struct ofpbuf buf;
    int err;

    ofpbuf_init(&buf, NL_DUMP_BUFSIZE);

    nl_msg_put_nfgenmsg(&buf, 0, AF_UNSPEC, NFNL_SUBSYS_CTNETLINK,
                        IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST);
    nl_msg_put_be16(&buf, CTA_ZONE, flush_zone);

    err = nl_transact(NETLINK_NETFILTER, &buf, NULL);
    ofpbuf_uninit(&buf);

    return err;
}
#else
int
nl_ct_flush_zone(uint16_t flush_zone)
{
    /* Apparently, there's no netlink interface to flush a specific zone.
     * This code dumps every connection, checks the zone and eventually
     * delete the entry.
     *
     * This is race-prone, but it is better than using shell scripts. */

    struct nl_dump dump;
    struct ofpbuf buf, reply, delete;

    ofpbuf_init(&buf, NL_DUMP_BUFSIZE);
    ofpbuf_init(&delete, NL_DUMP_BUFSIZE);

    nl_msg_put_nfgenmsg(&buf, 0, AF_UNSPEC, NFNL_SUBSYS_CTNETLINK,
                        IPCTNL_MSG_CT_GET, NLM_F_REQUEST);
    nl_dump_start(&dump, NETLINK_NETFILTER, &buf);
    ofpbuf_clear(&buf);

    for (;;) {
        struct nlattr *attrs[ARRAY_SIZE(nfnlgrp_conntrack_policy)];
        enum nl_ct_event_type event_type;
        uint8_t nfgen_family;
        uint16_t zone = 0;

        if (!nl_dump_next(&dump, &reply, &buf)) {
            break;
        }

        if (!nl_ct_parse_header_policy(&reply, &event_type, &nfgen_family,
                                       attrs)) {
            continue;
        };

        if (attrs[CTA_ZONE]) {
            zone = ntohs(nl_attr_get_be16(attrs[CTA_ZONE]));
        }

        if (zone != flush_zone) {
            /* The entry is not in the zone we're flushing. */
            continue;
        }
        nl_msg_put_nfgenmsg(&delete, 0, nfgen_family, NFNL_SUBSYS_CTNETLINK,
                            IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST);

        nl_msg_put_be16(&delete, CTA_ZONE, htons(zone));
        nl_msg_put_unspec(&delete, CTA_TUPLE_ORIG, attrs[CTA_TUPLE_ORIG] + 1,
                          attrs[CTA_TUPLE_ORIG]->nla_len - NLA_HDRLEN);
        nl_msg_put_unspec(&delete, CTA_ID, attrs[CTA_ID] + 1,
                          attrs[CTA_ID]->nla_len - NLA_HDRLEN);
        nl_transact(NETLINK_NETFILTER, &delete, NULL);
        ofpbuf_clear(&delete);
    }

    nl_dump_done(&dump);

    ofpbuf_uninit(&delete);
    ofpbuf_uninit(&buf);

    /* Expectations are flushed automatically, because they do not
     * have a master connection anymore */
    return 0;
}
#endif

/* Conntrack netlink parsing. */

static bool
nl_ct_parse_counters(struct nlattr *nla, struct ct_dpif_counters *counters)
{
    static const struct nl_policy policy[] = {
        [CTA_COUNTERS_PACKETS] = { .type = NL_A_BE64, .optional = false },
        [CTA_COUNTERS_BYTES] = { .type = NL_A_BE64, .optional = false },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];
    bool parsed;

    parsed = nl_parse_nested(nla, policy, attrs, ARRAY_SIZE(policy));

    if (parsed) {
        counters->packets
            = ntohll(nl_attr_get_be64(attrs[CTA_COUNTERS_PACKETS]));
        counters->bytes = ntohll(nl_attr_get_be64(attrs[CTA_COUNTERS_BYTES]));
    } else {
        VLOG_ERR_RL(&rl, "Could not parse nested counters. "
                    "Possibly incompatible Linux kernel version.");
    }

    return parsed;
}

static bool
nl_ct_parse_timestamp(struct nlattr *nla, struct ct_dpif_timestamp *timestamp)
{
    static const struct nl_policy policy[] = {
        [CTA_TIMESTAMP_START] = { .type = NL_A_BE64, .optional = false },
        [CTA_TIMESTAMP_STOP] = { .type = NL_A_BE64, .optional = true },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];
    bool parsed;

    parsed = nl_parse_nested(nla, policy, attrs, ARRAY_SIZE(policy));

    if (parsed) {
        timestamp->start
            = ntohll(nl_attr_get_be64(attrs[CTA_TIMESTAMP_START]));
        if (attrs[CTA_TIMESTAMP_STOP]) {
            timestamp->stop
                = ntohll(nl_attr_get_be64(attrs[CTA_TIMESTAMP_STOP]));
        }
    } else {
        VLOG_ERR_RL(&rl, "Could not parse nested timestamp. "
                    "Possibly incompatible Linux kernel version.");
    }

    return parsed;
}

static bool
nl_ct_parse_tuple_ip(struct nlattr *nla, struct ct_dpif_tuple *tuple)
{
    static const struct nl_policy policy[] = {
        [CTA_IP_V4_SRC] = { .type = NL_A_BE32, .optional = true },
        [CTA_IP_V4_DST] = { .type = NL_A_BE32, .optional = true },
        [CTA_IP_V6_SRC] = { NL_POLICY_FOR(struct in6_addr), .optional = true },
        [CTA_IP_V6_DST] = { NL_POLICY_FOR(struct in6_addr), .optional = true },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];
    bool parsed;

    parsed = nl_parse_nested(nla, policy, attrs, ARRAY_SIZE(policy));

    if (parsed) {
        if (tuple->l3_type == AF_INET) {
            if (attrs[CTA_IP_V4_SRC]) {
                tuple->src.ip = nl_attr_get_be32(attrs[CTA_IP_V4_SRC]);
            }
            if (attrs[CTA_IP_V4_DST]) {
                tuple->dst.ip = nl_attr_get_be32(attrs[CTA_IP_V4_DST]);
            }
        } else if (tuple->l3_type == AF_INET6) {
            if (attrs[CTA_IP_V6_SRC]) {
                memcpy(&tuple->src.in6, nl_attr_get(attrs[CTA_IP_V6_SRC]),
                       sizeof tuple->src.in6);
            }
            if (attrs[CTA_IP_V6_DST]) {
                memcpy(&tuple->dst.in6, nl_attr_get(attrs[CTA_IP_V6_DST]),
                       sizeof tuple->dst.in6);
            }
        } else {
            VLOG_WARN_RL(&rl, "Unsupported IP protocol: %u.", tuple->l3_type);
            return false;
        }
    } else {
        VLOG_ERR_RL(&rl, "Could not parse nested tuple IP options. "
                    "Possibly incompatible Linux kernel version.");
    }

    return parsed;
}

static bool
nl_ct_parse_tuple_proto(struct nlattr *nla, struct ct_dpif_tuple *tuple)
{
    static const struct nl_policy policy[] = {
        [CTA_PROTO_NUM] = { .type = NL_A_U8, .optional = false },
        [CTA_PROTO_SRC_PORT] = { .type = NL_A_BE16, .optional = true },
        [CTA_PROTO_DST_PORT] = { .type = NL_A_BE16, .optional = true },
        [CTA_PROTO_ICMP_ID] = { .type = NL_A_BE16, .optional = true },
        [CTA_PROTO_ICMP_TYPE] = { .type = NL_A_U8, .optional = true },
        [CTA_PROTO_ICMP_CODE] = { .type = NL_A_U8, .optional = true },
        [CTA_PROTO_ICMPV6_ID] = { .type = NL_A_BE16, .optional = true },
        [CTA_PROTO_ICMPV6_TYPE] = { .type = NL_A_U8, .optional = true },
        [CTA_PROTO_ICMPV6_CODE] = { .type = NL_A_U8, .optional = true },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];
    bool parsed;

    parsed = nl_parse_nested(nla, policy, attrs, ARRAY_SIZE(policy));

    if (parsed) {
        tuple->ip_proto = nl_attr_get_u8(attrs[CTA_PROTO_NUM]);

        if (tuple->l3_type == AF_INET && tuple->ip_proto == IPPROTO_ICMP) {
            if (!attrs[CTA_PROTO_ICMP_ID] || !attrs[CTA_PROTO_ICMP_TYPE]
                || !attrs[CTA_PROTO_ICMP_CODE]) {
                VLOG_ERR_RL(&rl, "Tuple ICMP data missing.");
                return false;
            }
            tuple->icmp_id = nl_attr_get_be16(attrs[CTA_PROTO_ICMP_ID]);
            tuple->icmp_type = nl_attr_get_u8(attrs[CTA_PROTO_ICMP_TYPE]);
            tuple->icmp_code = nl_attr_get_u8(attrs[CTA_PROTO_ICMP_CODE]);
        } else if (tuple->l3_type == AF_INET6 &&
                   tuple->ip_proto == IPPROTO_ICMPV6) {
            if (!attrs[CTA_PROTO_ICMPV6_ID] || !attrs[CTA_PROTO_ICMPV6_TYPE]
                || !attrs[CTA_PROTO_ICMPV6_CODE]) {
                VLOG_ERR_RL(&rl, "Tuple ICMPv6 data missing.");
                return false;
            }
            tuple->icmp_id = nl_attr_get_be16(attrs[CTA_PROTO_ICMPV6_ID]);
            tuple->icmp_type = nl_attr_get_u8(attrs[CTA_PROTO_ICMPV6_TYPE]);
            tuple->icmp_code = nl_attr_get_u8(attrs[CTA_PROTO_ICMPV6_CODE]);
        } else if (attrs[CTA_PROTO_SRC_PORT] && attrs[CTA_PROTO_DST_PORT]) {
            tuple->src_port = nl_attr_get_be16(attrs[CTA_PROTO_SRC_PORT]);
            tuple->dst_port = nl_attr_get_be16(attrs[CTA_PROTO_DST_PORT]);
        } else {
            /* Unsupported IPPROTO and no ports, leave them zeroed.
             * We have parsed the ip_proto, so this is not a failure. */
            VLOG_DBG_RL(&rl, "Unsupported L4 protocol: %u.", tuple->ip_proto);
        }
    } else {
        VLOG_ERR_RL(&rl, "Could not parse nested tuple protocol options. "
                    "Possibly incompatible Linux kernel version.");
    }

    return parsed;
}

static bool
nl_ct_parse_tuple(struct nlattr *nla, struct ct_dpif_tuple *tuple,
                  uint16_t l3_type)
{
    static const struct nl_policy policy[] = {
        [CTA_TUPLE_IP] = { .type = NL_A_NESTED, .optional = false },
        [CTA_TUPLE_PROTO] = { .type = NL_A_NESTED, .optional = false },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];
    bool parsed;

    parsed = nl_parse_nested(nla, policy, attrs, ARRAY_SIZE(policy));

    memset(tuple, 0, sizeof *tuple);

    if (parsed) {
        tuple->l3_type = l3_type;

        if (!nl_ct_parse_tuple_ip(attrs[CTA_TUPLE_IP], tuple)
            || !nl_ct_parse_tuple_proto(attrs[CTA_TUPLE_PROTO], tuple)) {
            struct ds ds;

            ds_init(&ds);
            ct_dpif_format_tuple(&ds, tuple);

            VLOG_ERR_RL(&rl, "Failed to parse tuple: %s", ds_cstr(&ds));
            ds_destroy(&ds);

            memset(tuple, 0, sizeof *tuple);
            return false;
        }
    } else {
        VLOG_ERR_RL(&rl, "Could not parse nested tuple options. "
                    "Possibly incompatible Linux kernel version.");
    }

    return parsed;
}

/* Translate netlink TCP state to CT_DPIF_TCP state. */
static uint8_t
nl_ct_tcp_state_to_dpif(uint8_t state)
{
#ifdef _WIN32
    /* Windows currently sends up CT_DPIF_TCP state */
    return state;
#else
    switch (state) {
    case TCP_CONNTRACK_NONE:
        return CT_DPIF_TCPS_CLOSED;
    case TCP_CONNTRACK_SYN_SENT:
        return CT_DPIF_TCPS_SYN_SENT;
    case TCP_CONNTRACK_SYN_SENT2:
        return CT_DPIF_TCPS_SYN_SENT;
    case TCP_CONNTRACK_SYN_RECV:
        return CT_DPIF_TCPS_SYN_RECV;
    case TCP_CONNTRACK_ESTABLISHED:
        return CT_DPIF_TCPS_ESTABLISHED;
    case TCP_CONNTRACK_FIN_WAIT:
        return CT_DPIF_TCPS_FIN_WAIT_1;
    case TCP_CONNTRACK_CLOSE_WAIT:
        return CT_DPIF_TCPS_CLOSE_WAIT;
    case TCP_CONNTRACK_LAST_ACK:
        return CT_DPIF_TCPS_LAST_ACK;
    case TCP_CONNTRACK_TIME_WAIT:
        return CT_DPIF_TCPS_TIME_WAIT;
    case TCP_CONNTRACK_CLOSE:
        return CT_DPIF_TCPS_CLOSING;
    default:
        return CT_DPIF_TCPS_CLOSED;
    }
#endif
}

static uint8_t
ip_ct_tcp_flags_to_dpif(uint8_t flags)
{
#ifdef _WIN32
    /* Windows currently sends up CT_DPIF_TCP flags */
    return flags;
#else
    uint8_t ret = 0;
#define CT_DPIF_TCP_FLAG(FLAG) \
        ret |= (flags & IP_CT_TCP_FLAG_##FLAG) ? CT_DPIF_TCPF_##FLAG : 0;
    CT_DPIF_TCP_FLAGS
#undef CT_DPIF_STATUS_FLAG
    return ret;
#endif
}

static bool
nl_ct_parse_protoinfo_tcp(struct nlattr *nla,
                          struct ct_dpif_protoinfo *protoinfo)
{
    static const struct nl_policy policy[] = {
        [CTA_PROTOINFO_TCP_STATE] = { .type = NL_A_U8, .optional = false },
        [CTA_PROTOINFO_TCP_WSCALE_ORIGINAL] = { .type = NL_A_U8,
                                                .optional = false },
        [CTA_PROTOINFO_TCP_WSCALE_REPLY] = { .type = NL_A_U8,
                                             .optional = false },
        [CTA_PROTOINFO_TCP_FLAGS_ORIGINAL] = { .type = NL_A_U16,
                                               .optional = false },
        [CTA_PROTOINFO_TCP_FLAGS_REPLY] = { .type = NL_A_U16,
                                            .optional = false },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];
    bool parsed;

    parsed = nl_parse_nested(nla, policy, attrs, ARRAY_SIZE(policy));

    if (parsed) {
        const struct nf_ct_tcp_flags *flags_orig, *flags_reply;
        uint8_t state;
        protoinfo->proto = IPPROTO_TCP;
        state = nl_ct_tcp_state_to_dpif(
            nl_attr_get_u8(attrs[CTA_PROTOINFO_TCP_STATE]));
        /* The connection tracker keeps only one tcp state for the
         * connection, but our structures store a separate state for
         * each endpoint.  Here we duplicate the state. */
        protoinfo->tcp.state_orig = protoinfo->tcp.state_reply = state;
        protoinfo->tcp.wscale_orig = nl_attr_get_u8(
            attrs[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL]);
        protoinfo->tcp.wscale_reply = nl_attr_get_u8(
            attrs[CTA_PROTOINFO_TCP_WSCALE_REPLY]);
        flags_orig =
            nl_attr_get_unspec(attrs[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL],
                               sizeof *flags_orig);
        protoinfo->tcp.flags_orig =
            ip_ct_tcp_flags_to_dpif(flags_orig->flags);
        flags_reply =
            nl_attr_get_unspec(attrs[CTA_PROTOINFO_TCP_FLAGS_REPLY],
                               sizeof *flags_reply);
        protoinfo->tcp.flags_reply =
            ip_ct_tcp_flags_to_dpif(flags_reply->flags);
    } else {
        VLOG_ERR_RL(&rl, "Could not parse nested TCP protoinfo options. "
                    "Possibly incompatible Linux kernel version.");
    }

    return parsed;
}

static bool
nl_ct_parse_protoinfo(struct nlattr *nla, struct ct_dpif_protoinfo *protoinfo)
{
    /* These are mutually exclusive. */
    static const struct nl_policy policy[] = {
        [CTA_PROTOINFO_TCP] = { .type = NL_A_NESTED, .optional = true },
        [CTA_PROTOINFO_SCTP] = { .type = NL_A_NESTED, .optional = true },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];
    bool parsed;

    parsed = nl_parse_nested(nla, policy, attrs, ARRAY_SIZE(policy));

    memset(protoinfo, 0, sizeof *protoinfo);

    if (parsed) {
        if (attrs[CTA_PROTOINFO_TCP]) {
            parsed = nl_ct_parse_protoinfo_tcp(attrs[CTA_PROTOINFO_TCP],
                                               protoinfo);
        } else if (attrs[CTA_PROTOINFO_SCTP]) {
            VLOG_WARN_RL(&rl, "SCTP protoinfo not yet supported!");
        } else {
            VLOG_WARN_RL(&rl, "Empty protoinfo!");
        }
    } else {
        VLOG_ERR_RL(&rl, "Could not parse nested protoinfo options. "
                    "Possibly incompatible Linux kernel version.");
    }

    return parsed;
}

static bool
nl_ct_parse_helper(struct nlattr *nla, struct ct_dpif_helper *helper)
{
    static const struct nl_policy policy[] = {
        [CTA_HELP_NAME] = { .type = NL_A_STRING, .optional = false },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];
    bool parsed;

    parsed = nl_parse_nested(nla, policy, attrs, ARRAY_SIZE(policy));

    memset(helper, 0, sizeof *helper);

    if (parsed) {
        helper->name = xstrdup(nl_attr_get_string(attrs[CTA_HELP_NAME]));
    } else {
        VLOG_ERR_RL(&rl, "Could not parse nested helper options. "
                    "Possibly incompatible Linux kernel version.");
    }

    return parsed;
}

/* Translate netlink entry status flags to CT_DPIF_TCP status flags. */
static uint32_t
ips_status_to_dpif_flags(uint32_t status)
{
    uint32_t ret = 0;
#define CT_DPIF_STATUS_FLAG(FLAG) \
        ret |= (status & IPS_##FLAG) ? CT_DPIF_STATUS_##FLAG : 0;
    CT_DPIF_STATUS_FLAGS
#undef CT_DPIF_STATUS_FLAG
    return ret;
}

static bool
nl_ct_parse_header_policy(struct ofpbuf *buf,
        enum nl_ct_event_type *event_type,
        uint8_t *nfgen_family,
        struct nlattr *attrs[ARRAY_SIZE(nfnlgrp_conntrack_policy)])
{
    struct nlmsghdr *nlh;
    struct nfgenmsg *nfm;
    uint8_t type;

    nlh = ofpbuf_at(buf, 0, NLMSG_HDRLEN);
    nfm = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *nfm);
    if (!nfm) {
        VLOG_ERR_RL(&rl, "Received bad nfnl message (no nfgenmsg).");
        return false;
    }
    if (NFNL_SUBSYS_ID(nlh->nlmsg_type) != NFNL_SUBSYS_CTNETLINK) {
        VLOG_ERR_RL(&rl, "Received non-conntrack message (subsystem: %u).",
                 NFNL_SUBSYS_ID(nlh->nlmsg_type));
        return false;
    }
    if (nfm->version != NFNETLINK_V0) {
        VLOG_ERR_RL(&rl, "Received unsupported nfnetlink version (%u).",
                 NFNL_MSG_TYPE(nfm->version));
        return false;
    }

    if (!nl_policy_parse(buf, NLMSG_HDRLEN + sizeof *nfm,
                         nfnlgrp_conntrack_policy, attrs,
                         ARRAY_SIZE(nfnlgrp_conntrack_policy))) {
        VLOG_ERR_RL(&rl, "Received bad nfnl message (policy).");
        return false;
    }

    type = NFNL_MSG_TYPE(nlh->nlmsg_type);
    *nfgen_family = nfm->nfgen_family;

    switch (type) {
    case IPCTNL_MSG_CT_NEW:
        *event_type = nlh->nlmsg_flags & NLM_F_CREATE
            ? NL_CT_EVENT_NEW : NL_CT_EVENT_UPDATE;
        break;
    case IPCTNL_MSG_CT_DELETE:
        *event_type = NL_CT_EVENT_DELETE;
        break;
    default:
        VLOG_ERR_RL(&rl, "Can't parse conntrack event type.");
        return false;
    }

    return true;
}

static bool
nl_ct_attrs_to_ct_dpif_entry(struct ct_dpif_entry *entry,
        struct nlattr *attrs[ARRAY_SIZE(nfnlgrp_conntrack_policy)],
        uint8_t nfgen_family)
{
    if (!nl_ct_parse_tuple(attrs[CTA_TUPLE_ORIG], &entry->tuple_orig,
                           nfgen_family)) {
        return false;
    }
    if (!nl_ct_parse_tuple(attrs[CTA_TUPLE_REPLY], &entry->tuple_reply,
                           nfgen_family)) {
        return false;
    }
    if (attrs[CTA_COUNTERS_ORIG] &&
        !nl_ct_parse_counters(attrs[CTA_COUNTERS_ORIG],
                              &entry->counters_orig)) {
        return false;
    }
    if (attrs[CTA_COUNTERS_REPLY] &&
        !nl_ct_parse_counters(attrs[CTA_COUNTERS_REPLY],
                              &entry->counters_reply)) {
        return false;
    }
    if (attrs[CTA_TIMESTAMP] &&
        !nl_ct_parse_timestamp(attrs[CTA_TIMESTAMP], &entry->timestamp)) {
        return false;
    }
    if (attrs[CTA_ID]) {
        entry->id = ntohl(nl_attr_get_be32(attrs[CTA_ID]));
    }
    if (attrs[CTA_ZONE]) {
        entry->zone = ntohs(nl_attr_get_be16(attrs[CTA_ZONE]));
    }
    if (attrs[CTA_STATUS]) {
        entry->status = ips_status_to_dpif_flags(
            ntohl(nl_attr_get_be32(attrs[CTA_STATUS])));
    }
    if (attrs[CTA_TIMEOUT]) {
        entry->timeout = ntohl(nl_attr_get_be32(attrs[CTA_TIMEOUT]));
    }
    if (attrs[CTA_MARK]) {
        entry->mark = ntohl(nl_attr_get_be32(attrs[CTA_MARK]));
    }
    if (attrs[CTA_LABELS]) {
        entry->have_labels = true;
        memcpy(&entry->labels, nl_attr_get(attrs[CTA_LABELS]),
               MIN(sizeof entry->labels, nl_attr_get_size(attrs[CTA_LABELS])));
    }
    if (attrs[CTA_PROTOINFO] &&
        !nl_ct_parse_protoinfo(attrs[CTA_PROTOINFO], &entry->protoinfo)) {
        return false;
    }
    if (attrs[CTA_HELP] &&
        !nl_ct_parse_helper(attrs[CTA_HELP], &entry->helper)) {
        return false;
    }
    if (attrs[CTA_TUPLE_MASTER] &&
        !nl_ct_parse_tuple(attrs[CTA_TUPLE_MASTER], &entry->tuple_master,
                           nfgen_family)) {
        return false;
    }
    return true;
}

bool
nl_ct_parse_entry(struct ofpbuf *buf, struct ct_dpif_entry *entry,
                  enum nl_ct_event_type *event_type)
{
    struct nlattr *attrs[ARRAY_SIZE(nfnlgrp_conntrack_policy)];
    uint8_t nfgen_family;

    memset(entry, 0, sizeof *entry);
    if (!nl_ct_parse_header_policy(buf, event_type, &nfgen_family, attrs)) {
        return false;
    };

    if (!nl_ct_attrs_to_ct_dpif_entry(entry, attrs, nfgen_family)) {
        ct_dpif_entry_uninit(entry);
        memset(entry, 0, sizeof *entry);
        return false;
    }

    return true;
}

/* NetFilter utility functions. */

/* Puts a nlmsghdr and nfgenmsg at the beginning of 'msg', which must be
 * initially empty.  'expected_payload' should be an estimate of the number of
 * payload bytes to be supplied; if the size of the payload is unknown a value
 * of 0 is acceptable.
 *
 * Non-zero 'family' is the address family of items to get (e.g. AF_INET).
 *
 * 'flags' is a bit-mask that indicates what kind of request is being made.  It
 * is often NLM_F_REQUEST indicating that a request is being made, commonly
 * or'd with NLM_F_ACK to request an acknowledgement.  NLM_F_DUMP flag reguests
 * a dump of the table.
 *
 * 'subsystem' is a netfilter subsystem id, e.g., NFNL_SUBSYS_CTNETLINK.
 *
 * 'cmd' is an enumerated value specific to the 'subsystem'.
 *
 * Sets the new nlmsghdr's nlmsg_pid field to 0 for now.  nl_sock_send() will
 * fill it in just before sending the message.
 *
 * nl_msg_put_nlmsghdr() should be used to compose Netlink messages that are
 * not NetFilter Netlink messages. */
static void
nl_msg_put_nfgenmsg(struct ofpbuf *msg, size_t expected_payload,
                    int family, uint8_t subsystem, uint8_t cmd,
                    uint32_t flags)
{
    struct nfgenmsg *nfm;

    nl_msg_put_nlmsghdr(msg, sizeof *nfm + expected_payload,
                        subsystem << 8 | cmd, flags);
    ovs_assert(msg->size == NLMSG_HDRLEN);
    nfm = nl_msg_put_uninit(msg, sizeof *nfm);
    nfm->nfgen_family = family;
    nfm->version = NFNETLINK_V0;
    nfm->res_id = 0;
#ifdef _WIN32
    /* nfgenmsg contains ovsHdr padding in windows */
    nfm->ovsHdr.dp_ifindex = 0;
#endif
}
