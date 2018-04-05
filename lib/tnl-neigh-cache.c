/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#include "tnl-neigh-cache.h"

#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdlib.h>

#include "bitmap.h"
#include "cmap.h"
#include "coverage.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "errno.h"
#include "flow.h"
#include "netdev.h"
#include "ovs-thread.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "socket-util.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"


/* In seconds */
#define NEIGH_ENTRY_DEFAULT_IDLE_TIME  (15 * 60)

struct tnl_neigh_entry {
    struct cmap_node cmap_node;
    struct in6_addr ip;
    struct eth_addr mac;
    time_t expires;             /* Expiration time. */
    char br_name[IFNAMSIZ];
};

static struct cmap table = CMAP_INITIALIZER;
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

static uint32_t
tnl_neigh_hash(const struct in6_addr *ip)
{
    return hash_bytes(ip->s6_addr, 16, 0);
}

static struct tnl_neigh_entry *
tnl_neigh_lookup__(const char br_name[IFNAMSIZ], const struct in6_addr *dst)
{
    struct tnl_neigh_entry *neigh;
    uint32_t hash;

    hash = tnl_neigh_hash(dst);
    CMAP_FOR_EACH_WITH_HASH (neigh, cmap_node, hash, &table) {
        if (ipv6_addr_equals(&neigh->ip, dst) && !strcmp(neigh->br_name, br_name)) {
            if (neigh->expires <= time_now()) {
                return NULL;
            }

            neigh->expires = time_now() + NEIGH_ENTRY_DEFAULT_IDLE_TIME;
            return neigh;
        }
    }
    return NULL;
}

int
tnl_neigh_lookup(const char br_name[IFNAMSIZ], const struct in6_addr *dst,
                 struct eth_addr *mac)
{
    struct tnl_neigh_entry *neigh;
    int res = ENOENT;

    neigh = tnl_neigh_lookup__(br_name, dst);
    if (neigh) {
        *mac = neigh->mac;
        res = 0;
    }
    return res;
}

static void
neigh_entry_free(struct tnl_neigh_entry *neigh)
{
    free(neigh);
}

static void
tnl_neigh_delete(struct tnl_neigh_entry *neigh)
{
    uint32_t hash = tnl_neigh_hash(&neigh->ip);
    cmap_remove(&table, &neigh->cmap_node, hash);
    ovsrcu_postpone(neigh_entry_free, neigh);
}

static void
tnl_neigh_set__(const char name[IFNAMSIZ], const struct in6_addr *dst,
                const struct eth_addr mac)
{
    ovs_mutex_lock(&mutex);
    struct tnl_neigh_entry *neigh = tnl_neigh_lookup__(name, dst);
    if (neigh) {
        if (eth_addr_equals(neigh->mac, mac)) {
            neigh->expires = time_now() + NEIGH_ENTRY_DEFAULT_IDLE_TIME;
            ovs_mutex_unlock(&mutex);
            return;
        }
        tnl_neigh_delete(neigh);
    }
    seq_change(tnl_conf_seq);

    neigh = xmalloc(sizeof *neigh);

    neigh->ip = *dst;
    neigh->mac = mac;
    neigh->expires = time_now() + NEIGH_ENTRY_DEFAULT_IDLE_TIME;
    ovs_strlcpy(neigh->br_name, name, sizeof neigh->br_name);
    cmap_insert(&table, &neigh->cmap_node, tnl_neigh_hash(&neigh->ip));
    ovs_mutex_unlock(&mutex);
}

static void
tnl_arp_set(const char name[IFNAMSIZ], ovs_be32 dst,
            const struct eth_addr mac)
{
    struct in6_addr dst6 = in6_addr_mapped_ipv4(dst);
    tnl_neigh_set__(name, &dst6, mac);
}

static int
tnl_arp_snoop(const struct flow *flow, struct flow_wildcards *wc,
              const char name[IFNAMSIZ])
{
    /* Snoop normal ARP replies and gratuitous ARP requests/replies only */
    if (!is_arp(flow)
        || (!is_garp(flow, wc) &&
            FLOW_WC_GET_AND_MASK_WC(flow, wc, nw_proto) != ARP_OP_REPLY)
        || eth_addr_is_zero(FLOW_WC_GET_AND_MASK_WC(flow, wc, arp_sha))) {
        return EINVAL;
    }

    tnl_arp_set(name, FLOW_WC_GET_AND_MASK_WC(flow, wc, nw_src), flow->arp_sha);
    return 0;
}

static int
tnl_nd_snoop(const struct flow *flow, struct flow_wildcards *wc,
             const char name[IFNAMSIZ])
{
    if (!is_nd(flow, wc) || flow->tp_src != htons(ND_NEIGHBOR_ADVERT)) {
        return EINVAL;
    }
    /* - RFC4861 says Neighbor Advertisements sent in response to unicast Neighbor
     *   Solicitations SHOULD include the Target link-layer address. However, Linux
     *   doesn't. So, the response to Solicitations sent by OVS will include the
     *   TLL address and other Advertisements not including it can be ignored.
     * - OVS flow extract can set this field to zero in case of packet parsing errors.
     *   For details refer miniflow_extract()*/
    if (eth_addr_is_zero(FLOW_WC_GET_AND_MASK_WC(flow, wc, arp_tha))) {
        return EINVAL;
    }

    memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
    memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
    memset(&wc->masks.nd_target, 0xff, sizeof wc->masks.nd_target);

    tnl_neigh_set__(name, &flow->nd_target, flow->arp_tha);
    return 0;
}

int
tnl_neigh_snoop(const struct flow *flow, struct flow_wildcards *wc,
                const char name[IFNAMSIZ])
{
    int res;
    res = tnl_arp_snoop(flow, wc, name);
    if (res != EINVAL) {
        return res;
    }
    return tnl_nd_snoop(flow, wc, name);
}

void
tnl_neigh_cache_run(void)
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        if (neigh->expires <= time_now()) {
            tnl_neigh_delete(neigh);
            changed = true;
        }
    }
    ovs_mutex_unlock(&mutex);

    if (changed) {
        seq_change(tnl_conf_seq);
    }
}

static void
tnl_neigh_cache_flush(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        tnl_neigh_delete(neigh);
        changed = true;
    }
    ovs_mutex_unlock(&mutex);
    if (changed) {
        seq_change(tnl_conf_seq);
    }
    unixctl_command_reply(conn, "OK");
}

static int
lookup_any(const char *host_name, struct in6_addr *address)
{
    if (addr_is_ipv6(host_name)) {
        return lookup_ipv6(host_name, address);
    } else {
        int r;
        struct in_addr ip;
        r = lookup_ip(host_name, &ip);
        if (r == 0) {
            in6_addr_set_mapped_ipv4(address, ip.s_addr);
        }
        return r;
    }
    return ENOENT;
}

static void
tnl_neigh_cache_add(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[], void *aux OVS_UNUSED)
{
    const char *br_name = argv[1];
    struct eth_addr mac;
    struct in6_addr ip6;

    if (lookup_any(argv[2], &ip6) != 0) {
        unixctl_command_reply_error(conn, "bad IP address");
        return;
    }

    if (!eth_addr_from_string(argv[3], &mac)) {
        unixctl_command_reply_error(conn, "bad MAC address");
        return;
    }

    tnl_neigh_set__(br_name, &ip6, mac);
    unixctl_command_reply(conn, "OK");
}

static void
tnl_neigh_cache_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct tnl_neigh_entry *neigh;

    ds_put_cstr(&ds, "IP                                            MAC                 Bridge\n");
    ds_put_cstr(&ds, "==========================================================================\n");
    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        int start_len, need_ws;

        start_len = ds.length;
        ipv6_format_mapped(&neigh->ip, &ds);

        need_ws = INET6_ADDRSTRLEN - (ds.length - start_len);
        ds_put_char_multiple(&ds, ' ', need_ws);

        ds_put_format(&ds, ETH_ADDR_FMT"   %s",
                      ETH_ADDR_ARGS(neigh->mac), neigh->br_name);
        if (neigh->expires <= time_now()) {
            ds_put_format(&ds, " STALE");
        }
        ds_put_char(&ds, '\n');

    }
    ovs_mutex_unlock(&mutex);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

void
tnl_neigh_cache_init(void)
{
    unixctl_command_register("tnl/arp/show", "", 0, 0, tnl_neigh_cache_show, NULL);
    unixctl_command_register("tnl/arp/set", "BRIDGE IP MAC", 3, 3, tnl_neigh_cache_add, NULL);
    unixctl_command_register("tnl/arp/flush", "", 0, 0, tnl_neigh_cache_flush, NULL);
    unixctl_command_register("tnl/neigh/show", "", 0, 0, tnl_neigh_cache_show, NULL);
    unixctl_command_register("tnl/neigh/set", "BRIDGE IP MAC", 3, 3, tnl_neigh_cache_add, NULL);
    unixctl_command_register("tnl/neigh/flush", "", 0, 0, tnl_neigh_cache_flush, NULL);
}
