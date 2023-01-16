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
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/packets.h"

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
