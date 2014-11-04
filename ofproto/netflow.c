/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2014 Nicira, Inc.
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
#include "netflow.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "byte-order.h"
#include "collectors.h"
#include "dpif.h"
#include "flow.h"
#include "lib/netflow.h"
#include "ofpbuf.h"
#include "ofproto.h"
#include "ofproto/netflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netflow);

struct netflow {
    uint8_t engine_type;          /* Value of engine_type to use. */
    uint8_t engine_id;            /* Value of engine_id to use. */
    long long int boot_time;      /* Time when netflow_create() was called. */
    struct collectors *collectors; /* NetFlow collectors. */
    bool add_id_to_iface;         /* Put the 7 least significiant bits of
                                   * 'engine_id' into the most significant
                                   * bits of the interface fields. */
    uint32_t netflow_cnt;         /* Flow sequence number for NetFlow. */
    struct ofpbuf packet;         /* NetFlow packet being accumulated. */
    long long int active_timeout; /* Timeout for flows that are still active. */
    long long int next_timeout;   /* Next scheduled active timeout. */
    long long int reconfig_time;  /* When we reconfigured the timeouts. */

    struct hmap flows;            /* Contains 'netflow_flows'. */

    struct ovs_refcount ref_cnt;
};

struct netflow_flow {
    struct hmap_node hmap_node;

    long long int last_expired;   /* Time this flow last timed out. */
    long long int created;        /* Time flow was created since time out. */

    ofp_port_t output_iface;      /* Output interface index. */
    uint16_t tcp_flags;           /* Bitwise-OR of all TCP flags seen. */

    ofp_port_t in_port;           /* Input port. */
    ovs_be32 nw_src;              /* IPv4 source address. */
    ovs_be32 nw_dst;              /* IPv4 destination address. */
    uint8_t nw_tos;               /* IP ToS (including DSCP and ECN). */
    uint8_t nw_proto;             /* IP protocol. */
    ovs_be16 tp_src;              /* TCP/UDP/SCTP source port. */
    ovs_be16 tp_dst;              /* TCP/UDP/SCTP destination port. */

    uint64_t packet_count;        /* Packets from subrules. */
    uint64_t byte_count;          /* Bytes from subrules. */
    long long int used;           /* Last-used time (0 if never used). */
};

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static atomic_uint netflow_count = ATOMIC_VAR_INIT(0);

static struct netflow_flow *netflow_flow_lookup(const struct netflow *,
                                                const struct flow *)
    OVS_REQUIRES(mutex);
static uint32_t netflow_flow_hash(const struct flow *);
static void netflow_expire__(struct netflow *, struct netflow_flow *)
    OVS_REQUIRES(mutex);
static void netflow_run__(struct netflow *) OVS_REQUIRES(mutex);

void
netflow_mask_wc(struct flow *flow, struct flow_wildcards *wc)
{
    if (flow->dl_type != htons(ETH_TYPE_IP)) {
        return;
    }
    memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
    memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
    memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
    flow_unwildcard_tp_ports(flow, wc);
    wc->masks.nw_tos |= IP_DSCP_MASK;
}

static void
gen_netflow_rec(struct netflow *nf, struct netflow_flow *nf_flow,
                uint32_t packet_count, uint32_t byte_count)
    OVS_REQUIRES(mutex)
{
    struct netflow_v5_header *nf_hdr;
    struct netflow_v5_record *nf_rec;

    if (!ofpbuf_size(&nf->packet)) {
        struct timespec now;

        time_wall_timespec(&now);

        nf_hdr = ofpbuf_put_zeros(&nf->packet, sizeof *nf_hdr);
        nf_hdr->version = htons(NETFLOW_V5_VERSION);
        nf_hdr->count = htons(0);
        nf_hdr->sysuptime = htonl(time_msec() - nf->boot_time);
        nf_hdr->unix_secs = htonl(now.tv_sec);
        nf_hdr->unix_nsecs = htonl(now.tv_nsec);
        nf_hdr->engine_type = nf->engine_type;
        nf_hdr->engine_id = nf->engine_id;
        nf_hdr->sampling_interval = htons(0);
    }

    nf_hdr = ofpbuf_data(&nf->packet);
    nf_hdr->count = htons(ntohs(nf_hdr->count) + 1);
    nf_hdr->flow_seq = htonl(nf->netflow_cnt++);

    nf_rec = ofpbuf_put_zeros(&nf->packet, sizeof *nf_rec);
    nf_rec->src_addr = nf_flow->nw_src;
    nf_rec->dst_addr = nf_flow->nw_dst;
    nf_rec->nexthop = htonl(0);
    if (nf->add_id_to_iface) {
        uint16_t iface = (nf->engine_id & 0x7f) << 9;
        nf_rec->input = htons(iface | (ofp_to_u16(nf_flow->in_port) & 0x1ff));
        nf_rec->output = htons(iface
            | (ofp_to_u16(nf_flow->output_iface) & 0x1ff));
    } else {
        nf_rec->input = htons(ofp_to_u16(nf_flow->in_port));
        nf_rec->output = htons(ofp_to_u16(nf_flow->output_iface));
    }
    nf_rec->packet_count = htonl(packet_count);
    nf_rec->byte_count = htonl(byte_count);
    nf_rec->init_time = htonl(nf_flow->created - nf->boot_time);
    nf_rec->used_time = htonl(MAX(nf_flow->created, nf_flow->used)
                             - nf->boot_time);
    if (nf_flow->nw_proto == IPPROTO_ICMP) {
        /* In NetFlow, the ICMP type and code are concatenated and
         * placed in the 'dst_port' field. */
        uint8_t type = ntohs(nf_flow->tp_src);
        uint8_t code = ntohs(nf_flow->tp_dst);
        nf_rec->src_port = htons(0);
        nf_rec->dst_port = htons((type << 8) | code);
    } else {
        nf_rec->src_port = nf_flow->tp_src;
        nf_rec->dst_port = nf_flow->tp_dst;
    }
    nf_rec->tcp_flags = (uint8_t) nf_flow->tcp_flags;
    nf_rec->ip_proto = nf_flow->nw_proto;
    nf_rec->ip_tos = nf_flow->nw_tos & IP_DSCP_MASK;

    /* NetFlow messages are limited to 30 records. */
    if (ntohs(nf_hdr->count) >= 30) {
        netflow_run__(nf);
    }
}

void
netflow_flow_update(struct netflow *nf, const struct flow *flow,
                    ofp_port_t output_iface,
                    const struct dpif_flow_stats *stats)
    OVS_EXCLUDED(mutex)
{
    struct netflow_flow *nf_flow;
    long long int used;

    /* NetFlow only reports on IP packets. */
    if (flow->dl_type != htons(ETH_TYPE_IP)) {
        return;
    }

    ovs_mutex_lock(&mutex);
    nf_flow = netflow_flow_lookup(nf, flow);
    if (!nf_flow) {
        nf_flow = xzalloc(sizeof *nf_flow);
        nf_flow->in_port = flow->in_port.ofp_port;
        nf_flow->nw_src = flow->nw_src;
        nf_flow->nw_dst = flow->nw_dst;
        nf_flow->nw_tos = flow->nw_tos;
        nf_flow->nw_proto = flow->nw_proto;
        nf_flow->tp_src = flow->tp_src;
        nf_flow->tp_dst = flow->tp_dst;
        nf_flow->created = stats->used;
        nf_flow->output_iface = output_iface;
        hmap_insert(&nf->flows, &nf_flow->hmap_node, netflow_flow_hash(flow));
    }

    if (nf_flow->output_iface != output_iface) {
        netflow_expire__(nf, nf_flow);
        nf_flow->created = stats->used;
        nf_flow->output_iface = output_iface;
    }

    nf_flow->packet_count += stats->n_packets;
    nf_flow->byte_count += stats->n_bytes;
    nf_flow->tcp_flags |= stats->tcp_flags;

    used = MAX(nf_flow->used, stats->used);
    if (nf_flow->used != used) {
        nf_flow->used = used;
        if (!nf->active_timeout || !nf_flow->last_expired
            || nf->reconfig_time > nf_flow->last_expired) {
            /* Keep the time updated to prevent a flood of expiration in
             * the future. */
            nf_flow->last_expired = time_msec();
        }
    }

    ovs_mutex_unlock(&mutex);
}

static void
netflow_expire__(struct netflow *nf, struct netflow_flow *nf_flow)
    OVS_REQUIRES(mutex)
{
    uint64_t pkts, bytes;

    pkts = nf_flow->packet_count;
    bytes = nf_flow->byte_count;

    nf_flow->last_expired += nf->active_timeout;

    if (pkts == 0) {
        return;
    }

    if ((bytes >> 32) <= 175) {
        /* NetFlow v5 records are limited to 32-bit counters.  If we've wrapped
         * a counter, send as multiple records so we don't lose track of any
         * traffic.  We try to evenly distribute the packet and byte counters,
         * so that the bytes-per-packet lengths don't look wonky across the
         * records. */
        while (bytes) {
            int n_recs = (bytes + UINT32_MAX - 1) / UINT32_MAX;
            uint32_t pkt_count = pkts / n_recs;
            uint32_t byte_count = bytes / n_recs;

            gen_netflow_rec(nf, nf_flow, pkt_count, byte_count);

            pkts -= pkt_count;
            bytes -= byte_count;
        }
    } else {
        /* In 600 seconds, a 10GbE link can theoretically transmit 75 * 10**10
         * == 175 * 2**32 bytes.  The byte counter is bigger than that, so it's
         * probably a bug--for example, the netdev code uses UINT64_MAX to
         * report "unknown value", and perhaps that has leaked through to here.
         *
         * We wouldn't want to hit the loop above in this case, because it
         * would try to send up to UINT32_MAX netflow records, which would take
         * a long time.
         */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_WARN_RL(&rl, "impossible byte counter %"PRIu64, bytes);
    }

    /* Update flow tracking data. */
    nf_flow->packet_count = 0;
    nf_flow->byte_count = 0;
    nf_flow->tcp_flags = 0;
}

void
netflow_flow_clear(struct netflow *nf, struct flow *flow) OVS_EXCLUDED(mutex)
{
    struct netflow_flow *nf_flow;

    ovs_mutex_lock(&mutex);
    nf_flow = netflow_flow_lookup(nf, flow);
    if (nf_flow) {
        netflow_expire__(nf, nf_flow);
        hmap_remove(&nf->flows, &nf_flow->hmap_node);
        free(nf_flow);
    }
    ovs_mutex_unlock(&mutex);
}

/* Returns true if it's time to send out a round of NetFlow active timeouts,
 * false otherwise. */
static void
netflow_run__(struct netflow *nf) OVS_REQUIRES(mutex)
{
    long long int now = time_msec();
    struct netflow_flow *nf_flow, *next;

    if (ofpbuf_size(&nf->packet)) {
        collectors_send(nf->collectors, ofpbuf_data(&nf->packet), ofpbuf_size(&nf->packet));
        ofpbuf_set_size(&nf->packet, 0);
    }

    if (!nf->active_timeout || now < nf->next_timeout) {
        return;
    }

    nf->next_timeout = now + 1000;

    HMAP_FOR_EACH_SAFE (nf_flow, next, hmap_node, &nf->flows) {
        if (now > nf_flow->last_expired + nf->active_timeout) {
            bool idle = nf_flow->used < nf_flow->last_expired;
            netflow_expire__(nf, nf_flow);

            if (idle) {
                /* If the netflow_flow hasn't been used in a while, it's
                 * possible the upper layer lost track of it. */
                hmap_remove(&nf->flows, &nf_flow->hmap_node);
                free(nf_flow);
            }
        }
    }
}

void
netflow_run(struct netflow *nf)
{
    ovs_mutex_lock(&mutex);
    netflow_run__(nf);
    ovs_mutex_unlock(&mutex);
}

void
netflow_wait(struct netflow *nf) OVS_EXCLUDED(mutex)
{
    ovs_mutex_lock(&mutex);
    if (nf->active_timeout) {
        poll_timer_wait_until(nf->next_timeout);
    }
    if (ofpbuf_size(&nf->packet)) {
        poll_immediate_wake();
    }
    ovs_mutex_unlock(&mutex);
}

int
netflow_set_options(struct netflow *nf,
                    const struct netflow_options *nf_options)
    OVS_EXCLUDED(mutex)
{
    int error = 0;
    long long int old_timeout;

    ovs_mutex_lock(&mutex);
    nf->engine_type = nf_options->engine_type;
    nf->engine_id = nf_options->engine_id;
    nf->add_id_to_iface = nf_options->add_id_to_iface;

    collectors_destroy(nf->collectors);
    collectors_create(&nf_options->collectors, 0, &nf->collectors);

    old_timeout = nf->active_timeout;
    if (nf_options->active_timeout >= 0) {
        nf->active_timeout = nf_options->active_timeout;
    } else {
        nf->active_timeout = NF_ACTIVE_TIMEOUT_DEFAULT;
    }
    nf->active_timeout *= 1000;
    if (old_timeout != nf->active_timeout) {
        nf->reconfig_time = time_msec();
        nf->next_timeout = time_msec();
    }
    ovs_mutex_unlock(&mutex);

    return error;
}

struct netflow *
netflow_create(void)
{
    struct netflow *nf = xzalloc(sizeof *nf);
    int junk;

    nf->engine_type = 0;
    nf->engine_id = 0;
    nf->boot_time = time_msec();
    nf->collectors = NULL;
    nf->add_id_to_iface = false;
    nf->netflow_cnt = 0;
    hmap_init(&nf->flows);
    ovs_refcount_init(&nf->ref_cnt);
    ofpbuf_init(&nf->packet, 1500);
    atomic_add(&netflow_count, 1, &junk);
    return nf;
}

struct netflow *
netflow_ref(const struct netflow *nf_)
{
    struct netflow *nf = CONST_CAST(struct netflow *, nf_);
    if (nf) {
        ovs_refcount_ref(&nf->ref_cnt);
    }
    return nf;
}

void
netflow_unref(struct netflow *nf)
{
    if (nf && ovs_refcount_unref(&nf->ref_cnt) == 1) {
        int orig;

        atomic_sub(&netflow_count, 1, &orig);
        collectors_destroy(nf->collectors);
        ofpbuf_uninit(&nf->packet);
        free(nf);
    }
}

/* Returns true if there exist any netflow objects, false otherwise. */
bool
netflow_exists(void)
{
    int n;

    atomic_read(&netflow_count, &n);
    return n > 0;
}

/* Helpers. */

static struct netflow_flow *
netflow_flow_lookup(const struct netflow *nf, const struct flow *flow)
    OVS_REQUIRES(mutex)
{
    struct netflow_flow *nf_flow;

    HMAP_FOR_EACH_WITH_HASH (nf_flow, hmap_node, netflow_flow_hash(flow),
                             &nf->flows) {
        if (flow->in_port.ofp_port == nf_flow->in_port
            && flow->nw_src == nf_flow->nw_src
            && flow->nw_dst == nf_flow->nw_dst
            && flow->nw_tos == nf_flow->nw_tos
            && flow->nw_proto == nf_flow->nw_proto
            && flow->tp_src == nf_flow->tp_src
            && flow->tp_dst == nf_flow->tp_dst) {
            return nf_flow;
        }
    }

    return NULL;
}

static uint32_t
netflow_flow_hash(const struct flow *flow)
{
    uint32_t hash = 0;

    hash = mhash_add(hash, (OVS_FORCE uint32_t) flow->in_port.ofp_port);
    hash = mhash_add(hash, ntohl(flow->nw_src));
    hash = mhash_add(hash, ntohl(flow->nw_dst));
    hash = mhash_add(hash, flow->nw_tos);
    hash = mhash_add(hash, flow->nw_proto);
    hash = mhash_add(hash, ntohs(flow->tp_src));
    hash = mhash_add(hash, ntohs(flow->tp_dst));

    return mhash_finish(hash, 28);
}
