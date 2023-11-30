/*
 * Copyright (c) 2023, Red Hat, Inc.
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
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "ct-dpif.h"
#include "openvswitch/ofp-ct.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/packets.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_ct);

static void
ofp_ct_tuple_format(struct ds *ds, const struct ofp_ct_tuple *tuple,
                    uint8_t ip_proto, uint16_t l3_type)
{
    ds_put_cstr(ds, l3_type == AF_INET ? "ct_nw_src=": "ct_ipv6_src=");
    ipv6_format_mapped(&tuple->src, ds);
    ds_put_cstr(ds, l3_type == AF_INET ? ",ct_nw_dst=": ",ct_ipv6_dst=");
    ipv6_format_mapped(&tuple->dst, ds);
    if (ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6) {
        ds_put_format(ds, ",icmp_id=%u,icmp_type=%u,icmp_code=%u",
                      ntohs(tuple->icmp_id), tuple->icmp_type,
                      tuple->icmp_code);
    } else {
        ds_put_format(ds, ",ct_tp_src=%u,ct_tp_dst=%u", ntohs(tuple->src_port),
                      ntohs(tuple->dst_port));
    }
}

bool
ofp_ct_tuple_is_zero(const struct ofp_ct_tuple *tuple, uint8_t ip_proto)
{
    bool is_zero = ipv6_is_zero(&tuple->src) && ipv6_is_zero(&tuple->dst);

    if (!(ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6)) {
        is_zero = is_zero && !tuple->src_port && !tuple->dst_port;
    }

    return is_zero;
}

bool
ofp_ct_tuple_is_five_tuple(const struct ofp_ct_tuple *tuple, uint8_t ip_proto)
{
    /* First check if we have address. */
    bool five_tuple = !ipv6_is_zero(&tuple->src) && !ipv6_is_zero(&tuple->dst);

    if (!(ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6)) {
        five_tuple = five_tuple && tuple->src_port && tuple->dst_port;
    }

    return five_tuple;
}

bool
ofp_ct_match_is_zero(const struct ofp_ct_match *match)
{
    return !match->ip_proto && !match->l3_type &&
           ofp_ct_tuple_is_zero(&match->tuple_orig, match->ip_proto) &&
           ofp_ct_tuple_is_zero(&match->tuple_reply, match->ip_proto);
}

void
ofp_ct_match_format(struct ds *ds, const struct ofp_ct_match *match)
{
    ds_put_cstr(ds, "'");
    ofp_ct_tuple_format(ds, &match->tuple_orig, match->ip_proto,
                        match->l3_type);
    ds_put_format(ds, ",ct_nw_proto=%u' '", match->ip_proto);
    ofp_ct_tuple_format(ds, &match->tuple_reply, match->ip_proto,
                        match->l3_type);
    ds_put_cstr(ds, "'");
}

/* Parses a specification of a conntrack 5-tuple from 's' into 'tuple'.
 * Returns true on success.  Otherwise, returns false and puts the error
 * message in 'ds'. */
bool
ofp_ct_tuple_parse(struct ofp_ct_tuple *tuple, const char *s,
                   struct ds *ds, uint8_t *ip_proto, uint16_t *l3_type)
{
    char *pos, *key, *value, *copy;

    pos = copy = xstrdup(s);
    while (ofputil_parse_key_value(&pos, &key, &value)) {
        if (!*value) {
            ds_put_format(ds, "field %s missing value", key);
            goto error;
        }

        if (!strcmp(key, "ct_nw_src") || !strcmp(key, "ct_nw_dst")) {
            struct in6_addr *addr = key[6] == 's' ? &tuple->src : &tuple->dst;

            if (*l3_type && *l3_type != AF_INET) {
                ds_put_format(ds ,"the L3 protocol does not match %s", value);
                goto error;
            }

            if (!ipv6_is_zero(addr)) {
                ds_put_format(ds, "%s is set multiple times", key);
                goto error;
            }

            ovs_be32 ip = 0;
            if (!ip_parse(value, &ip)) {
                goto error_with_msg;
            }

            *l3_type = AF_INET;
            *addr = in6_addr_mapped_ipv4(ip);
        } else if (!strcmp(key, "ct_ipv6_src") ||
                   !strcmp(key, "ct_ipv6_dst")) {
            struct in6_addr *addr = key[8] == 's' ? &tuple->src : &tuple->dst;

            if (*l3_type && *l3_type != AF_INET6) {
                ds_put_format(ds, "the L3 protocol does not match %s", value);
                goto error;
            }

            if (!ipv6_is_zero(addr)) {
                ds_put_format(ds, "%s is set multiple times", key);
                goto error;
            }


            if (!ipv6_parse(value, addr)) {
                goto error_with_msg;
            }

            *l3_type = AF_INET6;
        } else if (!strcmp(key, "ct_nw_proto")) {
            if (*ip_proto) {
                ds_put_format(ds, "%s is set multiple times", key);
            }
            char *err = str_to_u8(value, key, ip_proto);

            if (err) {
                free(err);
                goto error_with_msg;
            }
        } else if (!strcmp(key, "ct_tp_src") || !strcmp(key, "ct_tp_dst")) {
            uint16_t port;
            char *err = str_to_u16(value, key, &port);

            if (err) {
                free(err);
                goto error_with_msg;
            }
            if (key[6] == 's') {
                tuple->src_port = htons(port);
            } else {
                tuple->dst_port = htons(port);
            }
        } else if (!strcmp(key, "icmp_type") || !strcmp(key, "icmp_code") ||
                   !strcmp(key, "icmp_id")) {
            if (*ip_proto != IPPROTO_ICMP && *ip_proto != IPPROTO_ICMPV6) {
                ds_put_cstr(ds, "invalid L4 fields");
                goto error;
            }
            uint16_t icmp_id;
            char *err;

            if (key[5] == 't') {
                err = str_to_u8(value, key, &tuple->icmp_type);
            } else if (key[5] == 'c') {
                err = str_to_u8(value, key, &tuple->icmp_code);
            } else {
                err = str_to_u16(value, key, &icmp_id);
                tuple->icmp_id = htons(icmp_id);
            }
            if (err) {
                free(err);
                goto error_with_msg;
            }
        } else {
            ds_put_format(ds, "invalid conntrack tuple field: %s", key);
            goto error;
        }
    }

    if (!*ip_proto && (tuple->src_port || tuple->dst_port)) {
        ds_put_cstr(ds, "port is set without protocol");
        goto error;
    }

    free(copy);
    return true;

error_with_msg:
    ds_put_format(ds, "failed to parse field %s", key);
error:
    free(copy);
    return false;
}

static enum ofperr
ofpprop_pull_ipv6(struct ofpbuf *property, struct in6_addr *addr,
                  uint16_t *l3_type)
{
    if (ofpbuf_msgsize(property) < sizeof *addr) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    memcpy(addr, property->msg, sizeof *addr);

    uint16_t l3 = 0;
    if (!ipv6_is_zero(addr)) {
        l3 = IN6_IS_ADDR_V4MAPPED(addr) ? AF_INET : AF_INET6;
    }

    if (*l3_type && l3 && *l3_type != l3) {
        return OFPERR_OFPBPC_BAD_VALUE;
    }

    *l3_type = l3;

    return 0;
}

static enum ofperr
ofp_ct_tuple_decode_nested(struct ofpbuf *property, struct ofp_ct_tuple *tuple,
                           uint16_t *l3_type)
{
    struct ofpbuf nested;
    enum ofperr error = ofpprop_parse_nested(property, &nested);
    if (error) {
        return error;
    }

    while (nested.size) {
        struct ofpbuf inner;
        uint64_t type;

        error = ofpprop_pull(&nested, &inner, &type);
        if (error) {
            return error;
        }
        switch (type) {
        case NXT_CT_TUPLE_SRC:
            error = ofpprop_pull_ipv6(&inner, &tuple->src, l3_type);
            break;

        case NXT_CT_TUPLE_DST:
            error = ofpprop_pull_ipv6(&inner, &tuple->dst, l3_type);
            break;

        case NXT_CT_TUPLE_SRC_PORT:
            error = ofpprop_parse_be16(&inner, &tuple->src_port);
            break;

        case NXT_CT_TUPLE_DST_PORT:
            error = ofpprop_parse_be16(&inner, &tuple->dst_port);
            break;

        case NXT_CT_TUPLE_ICMP_ID:
            error = ofpprop_parse_be16(&inner, &tuple->icmp_id);
            break;

        case NXT_CT_TUPLE_ICMP_TYPE:
            error = ofpprop_parse_u8(&inner, &tuple->icmp_type);
            break;

        case NXT_CT_TUPLE_ICMP_CODE:
            error = ofpprop_parse_u8(&inner, &tuple->icmp_code);
            break;

        default:
            error = OFPPROP_UNKNOWN(false, "NXT_CT_TUPLE", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

static void
ofp_ct_tuple_encode(const struct ofp_ct_tuple *tuple, struct ofpbuf *buf,
                    enum nx_ct_flush_tlv_type type, uint8_t ip_proto)
{
    /* 128 B is enough to hold the whole tuple. */
    uint8_t stub[128];
    struct ofpbuf nested = OFPBUF_STUB_INITIALIZER(stub);

    if (!ipv6_is_zero(&tuple->src)) {
        ofpprop_put(&nested, NXT_CT_TUPLE_SRC, &tuple->src, sizeof tuple->src);
    }

    if (!ipv6_is_zero(&tuple->dst)) {
        ofpprop_put(&nested, NXT_CT_TUPLE_DST, &tuple->dst, sizeof tuple->dst);
    }

    if (ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6) {
        ofpprop_put_be16(&nested, NXT_CT_TUPLE_ICMP_ID, tuple->icmp_id);
        ofpprop_put_u8(&nested, NXT_CT_TUPLE_ICMP_TYPE, tuple->icmp_type);
        ofpprop_put_u8(&nested, NXT_CT_TUPLE_ICMP_CODE, tuple->icmp_code);
    } else {
        if (tuple->src_port) {
            ofpprop_put_be16(&nested, NXT_CT_TUPLE_SRC_PORT, tuple->src_port);
        }

        if (tuple->dst_port) {
            ofpprop_put_be16(&nested, NXT_CT_TUPLE_DST_PORT, tuple->dst_port);
        }
    }

    if (nested.size) {
        ofpprop_put_nested(buf, type, &nested);
    }

    ofpbuf_uninit(&nested);
}

enum ofperr
ofp_ct_match_decode(struct ofp_ct_match *match, bool *with_zone,
                    uint16_t *zone_id, const struct ofp_header *oh)
{
    struct ofpbuf msg = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&msg);

    const struct nx_ct_flush *nx_flush = ofpbuf_pull(&msg, sizeof *nx_flush);

    if (!is_all_zeros(nx_flush->pad, sizeof nx_flush->pad)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    match->ip_proto = nx_flush->ip_proto;

    struct ofp_ct_tuple *orig = &match->tuple_orig;
    struct ofp_ct_tuple *reply = &match->tuple_reply;

    while (msg.size) {
        struct ofpbuf property;
        uint64_t type;

        enum ofperr error = ofpprop_pull(&msg, &property, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case NXT_CT_ORIG_TUPLE:
            error = ofp_ct_tuple_decode_nested(&property, orig,
                                               &match->l3_type);
            break;

        case NXT_CT_REPLY_TUPLE:
            error = ofp_ct_tuple_decode_nested(&property, reply,
                                               &match->l3_type);
            break;

        case NXT_CT_ZONE_ID:
            if (with_zone) {
                *with_zone = true;
            }
            error = ofpprop_parse_u16(&property, zone_id);
            break;

        default:
            error = OFPPROP_UNKNOWN(false, "NXT_CT_FLUSH", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

struct ofpbuf *
ofp_ct_match_encode(const struct ofp_ct_match *match, uint16_t *zone_id,
                    enum ofp_version version)
{
    struct ofpbuf *msg = ofpraw_alloc(OFPRAW_NXT_CT_FLUSH, version, 0);
    struct nx_ct_flush *nx_flush = ofpbuf_put_zeros(msg, sizeof *nx_flush);
    const struct ofp_ct_tuple *orig = &match->tuple_orig;
    const struct ofp_ct_tuple *reply = &match->tuple_reply;

    nx_flush->ip_proto = match->ip_proto;

    ofp_ct_tuple_encode(orig, msg, NXT_CT_ORIG_TUPLE,match->ip_proto);
    ofp_ct_tuple_encode(reply, msg, NXT_CT_REPLY_TUPLE, match->ip_proto);

    if (zone_id) {
        ofpprop_put_u16(msg, NXT_CT_ZONE_ID, *zone_id);
    }

    return msg;
}
