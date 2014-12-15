/*
 * Copyright (c) 2014 Nicira, Inc.
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
#include <inttypes.h>
#include <stdlib.h>

#include "bitmap.h"
#include "cmap.h"
#include "coverage.h"
#include "dpif-netdev.h"
#include "dynamic-string.h"
#include "errno.h"
#include "flow.h"
#include "netdev.h"
#include "ovs-thread.h"
#include "packets.h"
#include "packet-dpif.h"
#include "poll-loop.h"
#include "seq.h"
#include "timeval.h"
#include "tnl-arp-cache.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"


/* In seconds */
#define ARP_ENTRY_DEFAULT_IDLE_TIME  (15 * 60)

struct tnl_arp_entry {
    struct cmap_node cmap_node;
    ovs_be32 ip;
    uint8_t mac[ETH_ADDR_LEN];
    time_t expires;             /* Expiration time. */
    char br_name[IFNAMSIZ];
};

static struct cmap table;
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

static struct tnl_arp_entry *
tnl_arp_lookup__(const char br_name[IFNAMSIZ], ovs_be32 dst)
{
    struct tnl_arp_entry *arp;

    CMAP_FOR_EACH_WITH_HASH (arp, cmap_node, (OVS_FORCE uint32_t) dst, &table) {
        if (arp->ip == dst && !strcmp(arp->br_name, br_name)) {
            arp->expires = time_now() + ARP_ENTRY_DEFAULT_IDLE_TIME;
            return arp;
        }
    }
    return NULL;
}

int
tnl_arp_lookup(const char br_name[IFNAMSIZ], ovs_be32 dst,
               uint8_t mac[ETH_ADDR_LEN])
{
    struct tnl_arp_entry *arp;
    int res = ENOENT;

    arp = tnl_arp_lookup__(br_name, dst);
    if (arp) {
            memcpy(mac, arp->mac, ETH_ADDR_LEN);
            res = 0;
    }

    return res;
}

static void
arp_entry_free(struct tnl_arp_entry *arp)
{
    free(arp);
}

static void
tnl_arp_delete(struct tnl_arp_entry *arp)
{
    cmap_remove(&table, &arp->cmap_node, (OVS_FORCE uint32_t) arp->ip);
    ovsrcu_postpone(arp_entry_free, arp);
}

int
tnl_arp_snoop(const struct flow *flow, struct flow_wildcards *wc,
              const char name[IFNAMSIZ])
{
    struct tnl_arp_entry *arp;

    if (flow->dl_type != htons(ETH_TYPE_ARP)) {
        return EINVAL;
    }

    /* Exact Match on all ARP flows. */
    memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
    memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
    memset(&wc->masks.arp_sha, 0xff, sizeof wc->masks.arp_sha);

    ovs_mutex_lock(&mutex);
    arp = tnl_arp_lookup__(name, flow->nw_src);
    if (arp) {
        if (!memcmp(arp->mac, flow->arp_sha, ETH_ADDR_LEN)) {
            arp->expires = time_now() + ARP_ENTRY_DEFAULT_IDLE_TIME;
            ovs_mutex_unlock(&mutex);
            return 0;
        }
        tnl_arp_delete(arp);
        seq_change(tnl_conf_seq);
    }

    arp = xmalloc(sizeof *arp);

    arp->ip = flow->nw_src;
    memcpy(arp->mac, flow->arp_sha, ETH_ADDR_LEN);
    arp->expires = time_now() + ARP_ENTRY_DEFAULT_IDLE_TIME;
    strncpy(arp->br_name, name, IFNAMSIZ);
    cmap_insert(&table, &arp->cmap_node, (OVS_FORCE uint32_t) arp->ip);
    ovs_mutex_unlock(&mutex);
    return 0;
}

void
tnl_arp_cache_run(void)
{
    struct tnl_arp_entry *arp;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(arp, cmap_node, &table) {
        if (arp->expires <= time_now()) {
             tnl_arp_delete(arp);
             changed = true;
        }
    }
    ovs_mutex_unlock(&mutex);

    if (changed) {
        seq_change(tnl_conf_seq);
    }
}

static void
tnl_arp_cache_flush(struct unixctl_conn *conn OVS_UNUSED, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct tnl_arp_entry *arp;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(arp, cmap_node, &table) {
          tnl_arp_delete(arp);
          changed = true;
    }
    ovs_mutex_unlock(&mutex);
    if (changed) {
        seq_change(tnl_conf_seq);
    }
    unixctl_command_reply(conn, "OK");
}

#define MAX_IP_ADDR_LEN 17

static void
tnl_arp_cache_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct tnl_arp_entry *arp;

    ds_put_cstr(&ds, "IP               MAC                 Bridge\n");
    ds_put_cstr(&ds, "=============================================\n");
    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(arp, cmap_node, &table) {
        int start_len, need_ws;

        start_len = ds.length;
        ds_put_format(&ds, IP_FMT, IP_ARGS(arp->ip));

        need_ws = MAX_IP_ADDR_LEN - (ds.length - start_len);
        ds_put_char_multiple(&ds, ' ', need_ws);

        ds_put_format(&ds, ETH_ADDR_FMT"   %s\n",
                      ETH_ADDR_ARGS(arp->mac), arp->br_name);

    }
    ovs_mutex_unlock(&mutex);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

void
tnl_arp_cache_init(void)
{
    cmap_init(&table);

    unixctl_command_register("tnl/arp/show", "", 0, 0, tnl_arp_cache_show, NULL);
    unixctl_command_register("tnl/arp/flush", "", 0, 0, tnl_arp_cache_flush, NULL);
}
