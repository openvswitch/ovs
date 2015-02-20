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
#include "dynamic-string.h"
#include "netdev.h"
#include "packets.h"
#include "seq.h"
#include "ovs-router.h"
#include "ovs-thread.h"
#include "route-table.h"
#include "unixctl.h"
#include "util.h"

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct classifier cls;

struct ovs_router_entry {
    struct cls_rule cr;
    char output_bridge[IFNAMSIZ];
    ovs_be32 gw;
    ovs_be32 nw_addr;
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
ovs_router_lookup(ovs_be32 ip_dst, char output_bridge[], ovs_be32 *gw)
{
    const struct cls_rule *cr;
    struct flow flow = {.nw_dst = ip_dst};

    cr = classifier_lookup(&cls, &flow, NULL);
    if (cr) {
        struct ovs_router_entry *p = ovs_router_entry_cast(cr);

        ovs_strlcpy(output_bridge, p->output_bridge, IFNAMSIZ);
        *gw = p->gw;
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

static void rt_init_match(struct match *match, ovs_be32 ip_dst, uint8_t plen)
{
    ovs_be32 mask;

    mask = be32_prefix_mask(plen);

    ip_dst &= mask; /* Clear out insignificant bits. */
    memset(match, 0, sizeof *match);
    match->flow.nw_dst = ip_dst;
    match->wc.masks.nw_dst = mask;
}

static void
ovs_router_insert__(uint8_t priority, ovs_be32 ip_dst, uint8_t plen,
                    const char output_bridge[],
                    ovs_be32 gw)
{
    const struct cls_rule *cr;
    struct ovs_router_entry *p;
    struct match match;

    rt_init_match(&match, ip_dst, plen);

    p = xzalloc(sizeof *p);
    ovs_strlcpy(p->output_bridge, output_bridge, sizeof p->output_bridge);
    p->gw = gw;
    p->nw_addr = match.flow.nw_dst;
    p->plen = plen;
    p->priority = priority;
    cls_rule_init(&p->cr, &match, priority); /* Longest prefix matches first. */

    ovs_mutex_lock(&mutex);
    cr = classifier_replace(&cls, &p->cr, NULL, 0);
    ovs_mutex_unlock(&mutex);

    if (cr) {
        /* An old rule with the same match was displaced. */
        ovsrcu_postpone(rt_entry_free, ovs_router_entry_cast(cr));
    }
    seq_change(tnl_conf_seq);
}

void
ovs_router_insert(ovs_be32 ip_dst, uint8_t plen, const char output_bridge[],
                  ovs_be32 gw)
{
    ovs_router_insert__(plen, ip_dst, plen, output_bridge, gw);
}

static bool
rt_entry_delete(uint8_t priority, ovs_be32 ip_dst, uint8_t plen)
{
    const struct cls_rule *cr;
    struct cls_rule rule;
    struct match match;

    rt_init_match(&match, ip_dst, plen);

    cls_rule_init(&rule, &match, priority);

    /* Find the exact rule. */
    cr = classifier_find_rule_exactly(&cls, &rule);
    if (cr) {
        /* Remove it. */
        ovs_mutex_lock(&mutex);
        cr = classifier_remove(&cls, cr);
        ovs_mutex_unlock(&mutex);

        if (cr) {
            ovsrcu_postpone(rt_entry_free, ovs_router_entry_cast(cr));
            return true;
        }
    }
    return false;
}

static bool
scan_ipv4_route(const char *s, ovs_be32 *addr, unsigned int *plen)
{
    int len, max_plen, n;
    int slen = strlen(s);
    uint8_t *ip = (uint8_t *)addr;

    *addr = htonl(0);
    if (!ovs_scan(s, "%"SCNu8"%n", &ip[0], &n)) {
        return false;
    }
    len = n;
    max_plen = 8;
    for (int i = 1; i < 4; i++) {
        if (ovs_scan(s + len, ".%"SCNu8"%n", &ip[i], &n)) {
            len += n;
            max_plen += 8;
        } else {
            break;
        }
    }
    if (len == slen && max_plen == 32) {
        *plen = 32;
        return true;
    }
    if (ovs_scan(s + len, "/%u%n", plen, &n)
        && len + n == slen && *plen <= max_plen) {
        return true;
    }
    return false;
}

static void
ovs_router_add(struct unixctl_conn *conn, int argc,
              const char *argv[], void *aux OVS_UNUSED)
{
    ovs_be32 ip, gw;
    unsigned int plen;

    if (scan_ipv4_route(argv[1], &ip, &plen)) {
        if (argc > 3) {
            inet_pton(AF_INET, argv[3], (struct in_addr *)&gw);
        } else {
            gw = 0;
        }
        ovs_router_insert__(plen + 32, ip, plen, argv[2], gw);
        unixctl_command_reply(conn, "OK");
    } else {
        unixctl_command_reply(conn, "Invalid parameters");
    }
}

static void
ovs_router_del(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[], void *aux OVS_UNUSED)
{
    ovs_be32 ip;
    unsigned int plen;

    if (scan_ipv4_route(argv[1], &ip, &plen)) {

        if (rt_entry_delete(plen + 32, ip, plen)) {
            unixctl_command_reply(conn, "OK");
            seq_change(tnl_conf_seq);
        } else {
            unixctl_command_reply(conn, "Not found");
        }
    } else {
        unixctl_command_reply(conn, "Invalid parameters");
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
        if (rt->priority == rt->plen) {
            ds_put_format(&ds, "Cached: ");
        } else {
            ds_put_format(&ds, "User: ");
        }
        ds_put_format(&ds, IP_FMT"/%"PRIu16" dev %s",
                      IP_ARGS(rt->nw_addr), rt->plen,
                      rt->output_bridge);
        if (rt->gw) {
            ds_put_format(&ds, " GW "IP_FMT, IP_ARGS(rt->gw));
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
    unsigned int plen;

    if (scan_ipv4_route(argv[1], &ip, &plen) && plen == 32) {
        char iface[IFNAMSIZ];
        ovs_be32 gw;

        if (ovs_router_lookup(ip, iface, &gw)) {
            struct ds ds = DS_EMPTY_INITIALIZER;

            ds_put_format(&ds, "gateway " IP_FMT "\n", IP_ARGS(gw));
            ds_put_format(&ds, "dev %s\n", iface);
            unixctl_command_reply(conn, ds_cstr(&ds));
        } else {
            unixctl_command_reply(conn, "Not found");
        }
    } else {
        unixctl_command_reply(conn, "Invalid parameters");
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
            if (classifier_remove(&cls, &rt->cr)) {
                ovsrcu_postpone(rt_entry_free, rt);
            }
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
    unixctl_command_register("ovs/route/add", "ipv4_addr/prefix_len out_br_name gw", 2, 3,
                             ovs_router_add, NULL);
    unixctl_command_register("ovs/route/show", "", 0, 0, ovs_router_show, NULL);
    unixctl_command_register("ovs/route/del", "ipv4_addr/prefix_len", 1, 1, ovs_router_del,
                             NULL);
    unixctl_command_register("ovs/route/lookup", "ipv4_addr", 1, 1,
                             ovs_router_lookup_cmd, NULL);
}
