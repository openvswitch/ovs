/*
 * Copyright (c) 2014, 2015 Nicira, Inc.
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

#include "ovs-router.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "classifier.h"
#include "command-line.h"
#include "compiler.h"
#include "dpif.h"
#include "openvswitch/dynamic-string.h"
#include "netdev.h"
#include "packets.h"
#include "seq.h"
#include "ovs-thread.h"
#include "route-table.h"
#include "tnl-ports.h"
#include "unixctl.h"
#include "util.h"

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct classifier cls;

struct ovs_router_entry {
    struct cls_rule cr;
    char output_bridge[IFNAMSIZ];
    struct in6_addr gw;
    struct in6_addr nw_addr;
    uint8_t plen;
    uint8_t priority;
};

static struct ovs_router_entry *
ovs_router_entry_cast(const struct cls_rule *cr)
{
    if (offsetof(struct ovs_router_entry, cr) == 0) {
        return CONTAINER_OF(cr, struct ovs_router_entry, cr);
    } else {
        return cr ? CONTAINER_OF(cr, struct ovs_router_entry, cr) : NULL;
    }
}

bool
ovs_router_lookup(const struct in6_addr *ip6_dst, char output_bridge[],
                  struct in6_addr *gw)
{
    const struct cls_rule *cr;
    struct flow flow = {.ipv6_dst = *ip6_dst};

    cr = classifier_lookup(&cls, CLS_MAX_VERSION, &flow, NULL);
    if (cr) {
        struct ovs_router_entry *p = ovs_router_entry_cast(cr);

        ovs_strlcpy(output_bridge, p->output_bridge, IFNAMSIZ);
        *gw = p->gw;
        return true;
    }
    return false;
}

bool
ovs_router_lookup4(ovs_be32 ip_dst, char output_bridge[], ovs_be32 *gw)
{
    struct in6_addr ip6_dst = in6_addr_mapped_ipv4(ip_dst);
    struct in6_addr gw6;

    if (ovs_router_lookup(&ip6_dst, output_bridge, &gw6)) {
        *gw = in6_addr_get_mapped_ipv4(&gw6);
        return true;
    }
    return route_table_fallback_lookup(ip_dst, output_bridge, gw);
}

static void
rt_entry_free(struct ovs_router_entry *p)
{
    cls_rule_destroy(&p->cr);
    free(p);
}

static void rt_init_match(struct match *match, const struct in6_addr *ip6_dst,
                          uint8_t plen)
{
    struct in6_addr dst;
    struct in6_addr mask;

    mask = ipv6_create_mask(plen);

    dst = ipv6_addr_bitand(ip6_dst, &mask);
    memset(match, 0, sizeof *match);
    match->flow.ipv6_dst = dst;
    match->wc.masks.ipv6_dst = mask;
}

static void
ovs_router_insert__(uint8_t priority, const struct in6_addr *ip6_dst,
                    uint8_t plen, const char output_bridge[],
                    const struct in6_addr *gw)
{
    const struct cls_rule *cr;
    struct ovs_router_entry *p;
    struct match match;

    rt_init_match(&match, ip6_dst, plen);

    p = xzalloc(sizeof *p);
    ovs_strlcpy(p->output_bridge, output_bridge, sizeof p->output_bridge);
    if (ipv6_addr_is_set(gw)) {
        p->gw = *gw;
    }
    p->nw_addr = match.flow.ipv6_dst;
    p->plen = plen;
    p->priority = priority;
    /* Longest prefix matches first. */
    cls_rule_init(&p->cr, &match, priority);

    ovs_mutex_lock(&mutex);
    cr = classifier_replace(&cls, &p->cr, CLS_MIN_VERSION, NULL, 0);
    ovs_mutex_unlock(&mutex);

    if (cr) {
        /* An old rule with the same match was displaced. */
        ovsrcu_postpone(rt_entry_free, ovs_router_entry_cast(cr));
    }
    tnl_port_map_insert_ipdev(output_bridge);
    seq_change(tnl_conf_seq);
}

void
ovs_router_insert(const struct in6_addr *ip_dst, uint8_t plen,
                  const char output_bridge[], const struct in6_addr *gw)
{
    ovs_router_insert__(plen, ip_dst, plen, output_bridge, gw);
}


static bool
__rt_entry_delete(const struct cls_rule *cr)
{
    struct ovs_router_entry *p = ovs_router_entry_cast(cr);

    tnl_port_map_delete_ipdev(p->output_bridge);
    /* Remove it. */
    cr = classifier_remove(&cls, cr);
    if (cr) {
        ovsrcu_postpone(rt_entry_free, ovs_router_entry_cast(cr));
        return true;
    }
    return false;
}

static bool
rt_entry_delete(uint8_t priority, const struct in6_addr *ip6_dst, uint8_t plen)
{
    const struct cls_rule *cr;
    struct cls_rule rule;
    struct match match;
    bool res = false;

    rt_init_match(&match, ip6_dst, plen);

    cls_rule_init(&rule, &match, priority);

    /* Find the exact rule. */
    cr = classifier_find_rule_exactly(&cls, &rule, CLS_MAX_VERSION);
    if (cr) {
        ovs_mutex_lock(&mutex);
        res = __rt_entry_delete(cr);
        ovs_mutex_unlock(&mutex);
    }
    return res;
}

static bool
scan_ipv6_route(const char *s, struct in6_addr *addr, unsigned int *plen)
{
    char *error = ipv6_parse_cidr(s, addr, plen);
    if (error) {
        free(error);
        return false;
    }
    return true;
}

static bool
scan_ipv4_route(const char *s, ovs_be32 *addr, unsigned int *plen)
{
    char *error = ip_parse_cidr(s, addr, plen);
    if (error) {
        free(error);
        return false;
    }
    return true;
}

static void
ovs_router_add(struct unixctl_conn *conn, int argc,
              const char *argv[], void *aux OVS_UNUSED)
{
    ovs_be32 ip;
    unsigned int plen;
    struct in6_addr ip6;
    struct in6_addr gw6;

    if (scan_ipv4_route(argv[1], &ip, &plen)) {
        ovs_be32 gw = 0;
        if (argc > 3 && !ip_parse(argv[3], &gw)) {
            unixctl_command_reply_error(conn, "Invalid gateway");
            return;
        }
        in6_addr_set_mapped_ipv4(&ip6, ip);
        in6_addr_set_mapped_ipv4(&gw6, gw);
        plen += 96;
    } else if (scan_ipv6_route(argv[1], &ip6, &plen)) {
        gw6 = in6addr_any;
        if (argc > 3 && !ipv6_parse(argv[3], &gw6)) {
            unixctl_command_reply_error(conn, "Invalid IPv6 gateway");
            return;
        }
    } else {
        unixctl_command_reply_error(conn, "Invalid parameters");
        return;
    }
    ovs_router_insert__(plen + 32, &ip6, plen, argv[2], &gw6);
    unixctl_command_reply(conn, "OK");
}

static void
ovs_router_del(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[], void *aux OVS_UNUSED)
{
    ovs_be32 ip;
    unsigned int plen;
    struct in6_addr ip6;

    if (scan_ipv4_route(argv[1], &ip, &plen)) {
        in6_addr_set_mapped_ipv4(&ip6, ip);
        plen += 96;
    } else if (!scan_ipv6_route(argv[1], &ip6, &plen)) {
        unixctl_command_reply_error(conn, "Invalid parameters");
        return;
    }
    if (rt_entry_delete(plen + 32, &ip6, plen)) {
        unixctl_command_reply(conn, "OK");
        seq_change(tnl_conf_seq);
    } else {
        unixctl_command_reply_error(conn, "Not found");
    }
}

static void
ovs_router_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
               const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ovs_router_entry *rt;
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "Route Table:\n");
    CLS_FOR_EACH(rt, cr, &cls) {
        uint8_t plen;
        if (rt->priority == rt->plen) {
            ds_put_format(&ds, "Cached: ");
        } else {
            ds_put_format(&ds, "User: ");
        }
        ipv6_format_mapped(&rt->nw_addr, &ds);
        plen = rt->plen;
        if (IN6_IS_ADDR_V4MAPPED(&rt->nw_addr)) {
            plen -= 96;
        }
        ds_put_format(&ds, "/%"PRIu16" dev %s", plen, rt->output_bridge);
        if (ipv6_addr_is_set(&rt->gw)) {
            ds_put_format(&ds, " GW ");
            ipv6_format_mapped(&rt->gw, &ds);
        }
        ds_put_format(&ds, "\n");
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ovs_router_lookup_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[], void *aux OVS_UNUSED)
{
    ovs_be32 ip;
    struct in6_addr ip6;
    unsigned int plen;
    char iface[IFNAMSIZ];
    struct in6_addr gw;

    if (scan_ipv4_route(argv[1], &ip, &plen) && plen == 32) {
        in6_addr_set_mapped_ipv4(&ip6, ip);
    } else if (!(scan_ipv6_route(argv[1], &ip6, &plen) && plen == 128)) {
        unixctl_command_reply_error(conn, "Invalid parameters");
        return;
    }

    if (ovs_router_lookup(&ip6, iface, &gw)) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        ds_put_format(&ds, "gateway ");
        ipv6_format_mapped(&ip6, &ds);
        ds_put_format(&ds, "\ndev %s\n", iface);
        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
    } else {
        unixctl_command_reply_error(conn, "Not found");
    }
}

void
ovs_router_flush(void)
{
    struct ovs_router_entry *rt;

    ovs_mutex_lock(&mutex);
    classifier_defer(&cls);
    CLS_FOR_EACH(rt, cr, &cls) {
        if (rt->priority == rt->plen) {
            __rt_entry_delete(&rt->cr);
        }
    }
    classifier_publish(&cls);
    ovs_mutex_unlock(&mutex);
    seq_change(tnl_conf_seq);
}

/* May not be called more than once. */
void
ovs_router_init(void)
{
    classifier_init(&cls, NULL);
    unixctl_command_register("ovs/route/add", "ip_addr/prefix_len out_br_name gw", 2, 3,
                             ovs_router_add, NULL);
    unixctl_command_register("ovs/route/show", "", 0, 0, ovs_router_show, NULL);
    unixctl_command_register("ovs/route/del", "ip_addr/prefix_len", 1, 1, ovs_router_del,
                             NULL);
    unixctl_command_register("ovs/route/lookup", "ip_addr", 1, 1,
                             ovs_router_lookup_cmd, NULL);
}
