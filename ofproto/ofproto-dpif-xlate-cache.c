/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
 * limitations under the License. */

#include <config.h>

#include "ofproto/ofproto-dpif-xlate-cache.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <sys/socket.h>

#include "bfd.h"
#include "bitmap.h"
#include "bond.h"
#include "bundle.h"
#include "byte-order.h"
#include "connmgr.h"
#include "coverage.h"
#include "dp-packet.h"
#include "dpif.h"
#include "learn.h"
#include "mac-learning.h"
#include "netdev-vport.h"
#include "ofproto/ofproto-dpif-mirror.h"
#include "ofproto/ofproto-dpif-xlate.h"
#include "ofproto/ofproto-dpif.h"
#include "ofproto/ofproto-provider.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovs-router.h"
#include "packets.h"
#include "tnl-neigh-cache.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofproto_xlate_cache);

void
xlate_cache_init(struct xlate_cache *xcache)
{
    ofpbuf_init(&xcache->entries, 120);
}

struct xlate_cache *
xlate_cache_new(void)
{
    struct xlate_cache *xcache = xmalloc(sizeof *xcache);
    xlate_cache_init(xcache);
    return xcache;
}

struct xc_entry *
xlate_cache_add_entry(struct xlate_cache *xcache, enum xc_type type)
{
    struct xc_entry *entry;

    entry = ofpbuf_put_zeros(&xcache->entries, sizeof *entry);
    entry->type = type;

    return entry;
}

static void
xlate_cache_netdev(struct xc_entry *entry, const struct dpif_flow_stats *stats)
{
    if (entry->dev.tx) {
        netdev_vport_inc_tx(entry->dev.tx, stats);
    }
    if (entry->dev.rx) {
        netdev_vport_inc_rx(entry->dev.rx, stats);
    }
    if (entry->dev.bfd) {
        bfd_account_rx(entry->dev.bfd, stats);
    }
}

/* Push stats and perform side effects of flow translation. */
void
xlate_push_stats_entry(struct xc_entry *entry,
                       struct dpif_flow_stats *stats, bool offloaded)
{
    struct eth_addr dmac;

    switch (entry->type) {
    case XC_TABLE:
        ofproto_dpif_credit_table_stats(entry->table.ofproto,
                                        entry->table.id,
                                        entry->table.match
                                        ? stats->n_packets : 0,
                                        entry->table.match
                                        ? 0 : stats->n_packets);
        break;
    case XC_RULE:
        rule_dpif_credit_stats(entry->rule, stats, offloaded);
        break;
    case XC_BOND:
        bond_account(entry->bond.bond, entry->bond.flow,
                     entry->bond.vid, stats->n_bytes);
        break;
    case XC_NETDEV:
        xlate_cache_netdev(entry, stats);
        break;
    case XC_NETFLOW:
        netflow_flow_update(entry->nf.netflow, entry->nf.flow,
                            entry->nf.iface, stats);
        break;
    case XC_MIRROR:
        mirror_update_stats(entry->mirror.mbridge,
                            entry->mirror.mirrors,
                            stats->n_packets, stats->n_bytes);
        break;
    case XC_LEARN: {
        enum ofperr error;
        error = ofproto_flow_mod_learn(entry->learn.ofm, true,
                                       entry->learn.limit, NULL);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "xcache LEARN action execution failed.");
        }
        break;
    }
    case XC_NORMAL:
        xlate_mac_learning_update(entry->normal.ofproto,
                                  entry->normal.in_port,
                                  entry->normal.dl_src,
                                  entry->normal.vlan,
                                  entry->normal.is_gratuitous_arp);
        break;
    case XC_FIN_TIMEOUT:
        if (stats->tcp_flags & (TCP_FIN | TCP_RST)) {
            ofproto_rule_reduce_timeouts(&entry->fin.rule->up, entry->fin.idle,
                                         entry->fin.hard);
        }
        break;
    case XC_GROUP:
        group_dpif_credit_stats(entry->group.group, entry->group.bucket,
                                stats);
        break;
    case XC_TNL_NEIGH:
        /* Lookup neighbor to avoid timeout. */
        tnl_neigh_lookup(entry->tnl_neigh_cache.br_name,
                         &entry->tnl_neigh_cache.d_ipv6, &dmac);
        break;
    case XC_TUNNEL_HEADER:
        if (entry->tunnel_hdr.operation == ADD) {
            stats->n_bytes += stats->n_packets * entry->tunnel_hdr.hdr_size;
        } else {
            stats->n_bytes -= stats->n_packets * entry->tunnel_hdr.hdr_size;
        }

        break;
    default:
        OVS_NOT_REACHED();
    }
}

void
xlate_push_stats(struct xlate_cache *xcache,
                 struct dpif_flow_stats *stats, bool offloaded)
{
    if (!stats->n_packets) {
        return;
    }

    struct xc_entry *entry;
    struct ofpbuf entries = xcache->entries;
    XC_ENTRY_FOR_EACH (entry, &entries) {
        xlate_push_stats_entry(entry, stats, offloaded);
    }
}

static void
xlate_dev_unref(struct xc_entry *entry)
{
    if (entry->dev.tx) {
        netdev_close(entry->dev.tx);
    }
    if (entry->dev.rx) {
        netdev_close(entry->dev.rx);
    }
    if (entry->dev.bfd) {
        bfd_unref(entry->dev.bfd);
    }
}

static void
xlate_cache_clear_netflow(struct netflow *netflow, struct flow *flow)
{
    netflow_flow_clear(netflow, flow);
    netflow_unref(netflow);
    free(flow);
}

void
xlate_cache_clear_entry(struct xc_entry *entry)
{
    switch (entry->type) {
    case XC_TABLE:
        break;
    case XC_RULE:
        ofproto_rule_unref(&entry->rule->up);
        break;
    case XC_BOND:
        free(entry->bond.flow);
        bond_unref(entry->bond.bond);
        break;
    case XC_NETDEV:
        xlate_dev_unref(entry);
        break;
    case XC_NETFLOW:
        xlate_cache_clear_netflow(entry->nf.netflow, entry->nf.flow);
        break;
    case XC_MIRROR:
        mbridge_unref(entry->mirror.mbridge);
        break;
    case XC_LEARN:
        ofproto_flow_mod_uninit(entry->learn.ofm);
        free(entry->learn.ofm);
        break;
    case XC_NORMAL:
        break;
    case XC_FIN_TIMEOUT:
        /* 'u.fin.rule' is always already held as a XC_RULE, which
         * has already released it's reference above. */
        break;
    case XC_GROUP:
        ofproto_group_unref(&entry->group.group->up);
        break;
    case XC_TNL_NEIGH:
        break;
    case XC_TUNNEL_HEADER:
        break;
    default:
        OVS_NOT_REACHED();
    }
}

void
xlate_cache_clear(struct xlate_cache *xcache)
{
    if (!xcache) {
        return;
    }

    struct xc_entry *entry;
    struct ofpbuf entries = xcache->entries;
    XC_ENTRY_FOR_EACH (entry, &entries) {
        xlate_cache_clear_entry(entry);
    }

    ofpbuf_clear(&xcache->entries);
}

void
xlate_cache_uninit(struct xlate_cache *xcache)
{
    if (!xcache) {
        return;
    }
    xlate_cache_clear(xcache);
    ofpbuf_uninit(&xcache->entries);
}

void
xlate_cache_delete(struct xlate_cache *xcache)
{
    xlate_cache_uninit(xcache);
    free(xcache);
}

/* Append all the entries in src into dst and remove them from src.
 * The caller must own both xc-caches to use this function.
 * The 'src' entries are not freed in this function as its owned by caller.
 */
void
xlate_cache_steal_entries(struct xlate_cache *dst, struct xlate_cache *src)
{
    if (!dst || !src) {
        return;
    }
    struct ofpbuf *src_entries = &src->entries;
    struct ofpbuf *dst_entries = &dst->entries;
    void *p;

    p = ofpbuf_put_uninit(dst_entries, src_entries->size);
    memcpy(p, src_entries->data, src_entries->size);
    ofpbuf_clear(src_entries);
}
