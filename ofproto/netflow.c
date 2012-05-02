/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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
    bool add_id_to_iface;         /* Put the 7 least signficiant bits of
                                   * 'engine_id' into the most signficant
                                   * bits of the interface fields. */
    uint32_t netflow_cnt;         /* Flow sequence number for NetFlow. */
    struct ofpbuf packet;         /* NetFlow packet being accumulated. */
    long long int active_timeout; /* Timeout for flows that are still active. */
    long long int next_timeout;   /* Next scheduled active timeout. */
    long long int reconfig_time;  /* When we reconfigured the timeouts. */
};

static void
gen_netflow_rec(struct netflow *nf, struct netflow_flow *nf_flow,
                struct ofexpired *expired,
                uint32_t packet_count, uint32_t byte_count)
{
    struct netflow_v5_header *nf_hdr;
    struct netflow_v5_record *nf_rec;

    if (!nf->packet.size) {
        struct timespec now;

        time_wall_timespec(&now);

        nf_hdr = ofpbuf_put_zeros(&nf->packet, sizeof *nf_hdr);
        nf_hdr->version = htons(NETFLOW_V5_VERSION);
        nf_hdr->count = htons(0);
        nf_hdr->sysuptime = htonl(time_msec() - nf->boot_time);
        nf_hdr->unix_secs = htonl(now.tv_sec);
        nf_hdr->unix_nsecs = htonl(now.tv_nsec);
        nf_hdr->flow_seq = htonl(nf->netflow_cnt++);
        nf_hdr->engine_type = nf->engine_type;
        nf_hdr->engine_id = nf->engine_id;
        nf_hdr->sampling_interval = htons(0);
    }

    nf_hdr = nf->packet.data;
    nf_hdr->count = htons(ntohs(nf_hdr->count) + 1);

    nf_rec = ofpbuf_put_zeros(&nf->packet, sizeof *nf_rec);
    nf_rec->src_addr = expired->flow.nw_src;
    nf_rec->dst_addr = expired->flow.nw_dst;
    nf_rec->nexthop = htonl(0);
    if (nf->add_id_to_iface) {
        uint16_t iface = (nf->engine_id & 0x7f) << 9;
        nf_rec->input = htons(iface | (expired->flow.in_port & 0x1ff));
        nf_rec->output = htons(iface | (nf_flow->output_iface & 0x1ff));
    } else {
        nf_rec->input = htons(expired->flow.in_port);
        nf_rec->output = htons(nf_flow->output_iface);
    }
    nf_rec->packet_count = htonl(packet_count);
    nf_rec->byte_count = htonl(byte_count);
    nf_rec->init_time = htonl(nf_flow->created - nf->boot_time);
    nf_rec->used_time = htonl(MAX(nf_flow->created, expired->used)
                             - nf->boot_time);
    if (expired->flow.nw_proto == IPPROTO_ICMP) {
        /* In NetFlow, the ICMP type and code are concatenated and
         * placed in the 'dst_port' field. */
        uint8_t type = ntohs(expired->flow.tp_src);
        uint8_t code = ntohs(expired->flow.tp_dst);
        nf_rec->src_port = htons(0);
        nf_rec->dst_port = htons((type << 8) | code);
    } else {
        nf_rec->src_port = expired->flow.tp_src;
        nf_rec->dst_port = expired->flow.tp_dst;
    }
    nf_rec->tcp_flags = nf_flow->tcp_flags;
    nf_rec->ip_proto = expired->flow.nw_proto;
    nf_rec->ip_tos = expired->flow.nw_tos & IP_DSCP_MASK;

    /* NetFlow messages are limited to 30 records. */
    if (ntohs(nf_hdr->count) >= 30) {
        netflow_run(nf);
    }
}

void
netflow_expire(struct netflow *nf, struct netflow_flow *nf_flow,
               struct ofexpired *expired)
{
    uint64_t pkt_delta = expired->packet_count - nf_flow->packet_count_off;
    uint64_t byte_delta = expired->byte_count - nf_flow->byte_count_off;

    nf_flow->last_expired += nf->active_timeout;

    /* NetFlow only reports on IP packets and we should only report flows
     * that actually have traffic. */
    if (expired->flow.dl_type != htons(ETH_TYPE_IP) || pkt_delta == 0) {
        return;
    }

    if ((byte_delta >> 32) <= 175) {
        /* NetFlow v5 records are limited to 32-bit counters.  If we've wrapped
         * a counter, send as multiple records so we don't lose track of any
         * traffic.  We try to evenly distribute the packet and byte counters,
         * so that the bytes-per-packet lengths don't look wonky across the
         * records. */
        while (byte_delta) {
            int n_recs = (byte_delta + UINT32_MAX - 1) / UINT32_MAX;
            uint32_t pkt_count = pkt_delta / n_recs;
            uint32_t byte_count = byte_delta / n_recs;

            gen_netflow_rec(nf, nf_flow, expired, pkt_count, byte_count);

            pkt_delta -= pkt_count;
            byte_delta -= byte_count;
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

        VLOG_WARN_RL(&rl, "impossible byte counter %"PRIu64, byte_delta);
    }

    /* Update flow tracking data. */
    nf_flow->created = 0;
    nf_flow->packet_count_off = expired->packet_count;
    nf_flow->byte_count_off = expired->byte_count;
    nf_flow->tcp_flags = 0;
}

/* Returns true if it's time to send out a round of NetFlow active timeouts,
 * false otherwise. */
bool
netflow_run(struct netflow *nf)
{
    if (nf->packet.size) {
        collectors_send(nf->collectors, nf->packet.data, nf->packet.size);
        nf->packet.size = 0;
    }

    if (nf->active_timeout && time_msec() >= nf->next_timeout) {
        nf->next_timeout = time_msec() + 1000;
        return true;
    } else {
        return false;
    }
}

void
netflow_wait(struct netflow *nf)
{
    if (nf->active_timeout) {
        poll_timer_wait_until(nf->next_timeout);
    }
    if (nf->packet.size) {
        poll_immediate_wake();
    }
}

int
netflow_set_options(struct netflow *nf,
                    const struct netflow_options *nf_options)
{
    int error = 0;
    long long int old_timeout;

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

    return error;
}

struct netflow *
netflow_create(void)
{
    struct netflow *nf = xzalloc(sizeof *nf);
    nf->engine_type = 0;
    nf->engine_id = 0;
    nf->boot_time = time_msec();
    nf->collectors = NULL;
    nf->add_id_to_iface = false;
    nf->netflow_cnt = 0;
    ofpbuf_init(&nf->packet, 1500);
    return nf;
}

void
netflow_destroy(struct netflow *nf)
{
    if (nf) {
        ofpbuf_uninit(&nf->packet);
        collectors_destroy(nf->collectors);
        free(nf);
    }
}

/* Initializes a new 'nf_flow' given that the caller has already cleared it to
 * all-zero-bits. */
void
netflow_flow_init(struct netflow_flow *nf_flow OVS_UNUSED)
{
    /* Nothing to do. */
}

void
netflow_flow_clear(struct netflow_flow *nf_flow)
{
    uint16_t output_iface = nf_flow->output_iface;

    memset(nf_flow, 0, sizeof *nf_flow);
    nf_flow->output_iface = output_iface;
}

void
netflow_flow_update_time(struct netflow *nf, struct netflow_flow *nf_flow,
                         long long int used)
{
    if (!nf_flow->created) {
        nf_flow->created = used;
    }

    if (!nf || !nf->active_timeout || !nf_flow->last_expired ||
        nf->reconfig_time > nf_flow->last_expired) {
        /* Keep the time updated to prevent a flood of expiration in
         * the future. */
        nf_flow->last_expired = time_msec();
    }
}

void
netflow_flow_update_flags(struct netflow_flow *nf_flow, uint8_t tcp_flags)
{
    nf_flow->tcp_flags |= tcp_flags;
}

bool
netflow_active_timeout_expired(struct netflow *nf, struct netflow_flow *nf_flow)
{
    if (nf->active_timeout) {
        return time_msec() > nf_flow->last_expired + nf->active_timeout;
    }

    return false;
}
