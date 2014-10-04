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

#ifndef PACKET_DPIF_H
#define PACKET_DPIF_H 1

#include "ofpbuf.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* A packet received from a netdev and passed to a dpif. */

struct dpif_packet {
    struct ofpbuf ofpbuf;       /* Packet data. */
#ifndef DPDK_NETDEV
    uint32_t dp_hash;           /* Packet hash. */
#endif
    struct pkt_metadata md;
};

struct dpif_packet *dpif_packet_new_with_headroom(size_t size,
                                                  size_t headroom);

struct dpif_packet *dpif_packet_clone_from_ofpbuf(const struct ofpbuf *b);

struct dpif_packet *dpif_packet_clone(struct dpif_packet *p);

static inline void dpif_packet_delete(struct dpif_packet *p)
{
    struct ofpbuf *buf = &p->ofpbuf;

    ofpbuf_delete(buf);
}

static inline uint32_t dpif_packet_get_dp_hash(struct dpif_packet *p)
{
#ifdef DPDK_NETDEV
    return p->ofpbuf.mbuf.pkt.hash.rss;
#else
    return p->dp_hash;
#endif
}

static inline void dpif_packet_set_dp_hash(struct dpif_packet *p,
                                           uint32_t hash)
{
#ifdef DPDK_NETDEV
    p->ofpbuf.mbuf.pkt.hash.rss = hash;
#else
    p->dp_hash = hash;
#endif
}

#ifdef  __cplusplus
}
#endif

#endif /* packet-dpif.h */
