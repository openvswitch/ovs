/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef DPBUF_H
#define DPBUF_H 1

#include <stddef.h>
#include <stdint.h>
#include "openvswitch/list.h"
#include "packets.h"
#include "util.h"
#include "netdev-dpdk.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum OVS_PACKED_ENUM dp_packet_source {
    DPBUF_MALLOC,              /* Obtained via malloc(). */
    DPBUF_STACK,               /* Un-movable stack space or static buffer. */
    DPBUF_STUB,                /* Starts on stack, may expand into heap. */
    DPBUF_DPDK,                /* buffer data is from DPDK allocated memory.
                                * ref to build_dp_packet() in netdev-dpdk. */
};

#define DP_PACKET_CONTEXT_SIZE 64

/* Buffer for holding packet data.  A dp_packet is automatically reallocated
 * as necessary if it grows too large for the available memory.
 */
struct dp_packet {
#ifdef DPDK_NETDEV
    struct rte_mbuf mbuf;       /* DPDK mbuf */
#else
    void *base_;                /* First byte of allocated space. */
    uint16_t allocated_;        /* Number of bytes allocated. */
    uint16_t data_ofs;          /* First byte actually in use. */
    uint32_t size_;             /* Number of bytes in use. */
    uint32_t rss_hash;          /* Packet hash. */
    bool rss_hash_valid;        /* Is the 'rss_hash' valid? */
#endif
    enum dp_packet_source source;  /* Source of memory allocated as 'base'. */
    uint8_t l2_pad_size;           /* Detected l2 padding size.
                                    * Padding is non-pullable. */
    uint16_t l2_5_ofs;             /* MPLS label stack offset, or UINT16_MAX */
    uint16_t l3_ofs;               /* Network-level header offset,
                                    * or UINT16_MAX. */
    uint16_t l4_ofs;               /* Transport-level header offset,
                                      or UINT16_MAX. */
    uint32_t cutlen;               /* length in bytes to cut from the end. */
    union {
        struct pkt_metadata md;
        uint64_t data[DP_PACKET_CONTEXT_SIZE / 8];
    };
};

static inline void *dp_packet_data(const struct dp_packet *);
static inline void dp_packet_set_data(struct dp_packet *, void *);
static inline void *dp_packet_base(const struct dp_packet *);
static inline void dp_packet_set_base(struct dp_packet *, void *);

static inline uint32_t dp_packet_size(const struct dp_packet *);
static inline void dp_packet_set_size(struct dp_packet *, uint32_t);

static inline uint16_t dp_packet_get_allocated(const struct dp_packet *);
static inline void dp_packet_set_allocated(struct dp_packet *, uint16_t);

void *dp_packet_resize_l2(struct dp_packet *, int increment);
void *dp_packet_resize_l2_5(struct dp_packet *, int increment);
static inline void *dp_packet_l2(const struct dp_packet *);
static inline void dp_packet_reset_offsets(struct dp_packet *);
static inline uint8_t dp_packet_l2_pad_size(const struct dp_packet *);
static inline void dp_packet_set_l2_pad_size(struct dp_packet *, uint8_t);
static inline void *dp_packet_l2_5(const struct dp_packet *);
static inline void dp_packet_set_l2_5(struct dp_packet *, void *);
static inline void *dp_packet_l3(const struct dp_packet *);
static inline void dp_packet_set_l3(struct dp_packet *, void *);
static inline void *dp_packet_l4(const struct dp_packet *);
static inline void dp_packet_set_l4(struct dp_packet *, void *);
static inline size_t dp_packet_l4_size(const struct dp_packet *);
static inline const void *dp_packet_get_tcp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_udp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_sctp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_icmp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_nd_payload(const struct dp_packet *);

void dp_packet_use(struct dp_packet *, void *, size_t);
void dp_packet_use_stub(struct dp_packet *, void *, size_t);
void dp_packet_use_const(struct dp_packet *, const void *, size_t);

void dp_packet_init_dpdk(struct dp_packet *, size_t allocated);

void dp_packet_init(struct dp_packet *, size_t);
void dp_packet_uninit(struct dp_packet *);

struct dp_packet *dp_packet_new(size_t);
struct dp_packet *dp_packet_new_with_headroom(size_t, size_t headroom);
struct dp_packet *dp_packet_clone(const struct dp_packet *);
struct dp_packet *dp_packet_clone_with_headroom(const struct dp_packet *,
                                                size_t headroom);
struct dp_packet *dp_packet_clone_data(const void *, size_t);
struct dp_packet *dp_packet_clone_data_with_headroom(const void *, size_t,
                                                     size_t headroom);
static inline void dp_packet_delete(struct dp_packet *);

static inline void *dp_packet_at(const struct dp_packet *, size_t offset,
                                 size_t size);
static inline void *dp_packet_at_assert(const struct dp_packet *,
                                        size_t offset, size_t size);
static inline void *dp_packet_tail(const struct dp_packet *);
static inline void *dp_packet_end(const struct dp_packet *);

void *dp_packet_put_uninit(struct dp_packet *, size_t);
void *dp_packet_put_zeros(struct dp_packet *, size_t);
void *dp_packet_put(struct dp_packet *, const void *, size_t);
char *dp_packet_put_hex(struct dp_packet *, const char *s, size_t *n);
void dp_packet_reserve(struct dp_packet *, size_t);
void dp_packet_reserve_with_tailroom(struct dp_packet *, size_t headroom,
                                     size_t tailroom);
void *dp_packet_push_uninit(struct dp_packet *, size_t);
void *dp_packet_push_zeros(struct dp_packet *, size_t);
void *dp_packet_push(struct dp_packet *, const void *, size_t);

static inline size_t dp_packet_headroom(const struct dp_packet *);
static inline size_t dp_packet_tailroom(const struct dp_packet *);
void dp_packet_prealloc_headroom(struct dp_packet *, size_t);
void dp_packet_prealloc_tailroom(struct dp_packet *, size_t);
void dp_packet_shift(struct dp_packet *, int);

static inline void dp_packet_clear(struct dp_packet *);
static inline void *dp_packet_pull(struct dp_packet *, size_t);
static inline void *dp_packet_try_pull(struct dp_packet *, size_t);

void *dp_packet_steal_data(struct dp_packet *);

static inline bool dp_packet_equal(const struct dp_packet *,
                                   const struct dp_packet *);


/* Frees memory that 'b' points to, as well as 'b' itself. */
static inline void
dp_packet_delete(struct dp_packet *b)
{
    if (b) {
        if (b->source == DPBUF_DPDK) {
            /* If this dp_packet was allocated by DPDK it must have been
             * created as a dp_packet */
            free_dpdk_buf((struct dp_packet*) b);
            return;
        }

        dp_packet_uninit(b);
        free(b);
    }
}

/* If 'b' contains at least 'offset + size' bytes of data, returns a pointer to
 * byte 'offset'.  Otherwise, returns a null pointer. */
static inline void *
dp_packet_at(const struct dp_packet *b, size_t offset, size_t size)
{
    return offset + size <= dp_packet_size(b)
           ? (char *) dp_packet_data(b) + offset
           : NULL;
}

/* Returns a pointer to byte 'offset' in 'b', which must contain at least
 * 'offset + size' bytes of data. */
static inline void *
dp_packet_at_assert(const struct dp_packet *b, size_t offset, size_t size)
{
    ovs_assert(offset + size <= dp_packet_size(b));
    return ((char *) dp_packet_data(b)) + offset;
}

/* Returns a pointer to byte following the last byte of data in use in 'b'. */
static inline void *
dp_packet_tail(const struct dp_packet *b)
{
    return (char *) dp_packet_data(b) + dp_packet_size(b);
}

/* Returns a pointer to byte following the last byte allocated for use (but
 * not necessarily in use) in 'b'. */
static inline void *
dp_packet_end(const struct dp_packet *b)
{
    return (char *) dp_packet_base(b) + dp_packet_get_allocated(b);
}

/* Returns the number of bytes of headroom in 'b', that is, the number of bytes
 * of unused space in dp_packet 'b' before the data that is in use.  (Most
 * commonly, the data in a dp_packet is at its beginning, and thus the
 * dp_packet's headroom is 0.) */
static inline size_t
dp_packet_headroom(const struct dp_packet *b)
{
    return (char *) dp_packet_data(b) - (char *) dp_packet_base(b);
}

/* Returns the number of bytes that may be appended to the tail end of
 * dp_packet 'b' before the dp_packet must be reallocated. */
static inline size_t
dp_packet_tailroom(const struct dp_packet *b)
{
    return (char *) dp_packet_end(b) - (char *) dp_packet_tail(b);
}

/* Clears any data from 'b'. */
static inline void
dp_packet_clear(struct dp_packet *b)
{
    dp_packet_set_data(b, dp_packet_base(b));
    dp_packet_set_size(b, 0);
}

/* Removes 'size' bytes from the head end of 'b', which must contain at least
 * 'size' bytes of data.  Returns the first byte of data removed. */
static inline void *
dp_packet_pull(struct dp_packet *b, size_t size)
{
    void *data = dp_packet_data(b);
    ovs_assert(dp_packet_size(b) - dp_packet_l2_pad_size(b) >= size);
    dp_packet_set_data(b, (char *) dp_packet_data(b) + size);
    dp_packet_set_size(b, dp_packet_size(b) - size);
    return data;
}

/* If 'b' has at least 'size' bytes of data, removes that many bytes from the
 * head end of 'b' and returns the first byte removed.  Otherwise, returns a
 * null pointer without modifying 'b'. */
static inline void *
dp_packet_try_pull(struct dp_packet *b, size_t size)
{
    return dp_packet_size(b) - dp_packet_l2_pad_size(b) >= size
        ? dp_packet_pull(b, size) : NULL;
}

static inline bool
dp_packet_equal(const struct dp_packet *a, const struct dp_packet *b)
{
    return dp_packet_size(a) == dp_packet_size(b) &&
           !memcmp(dp_packet_data(a), dp_packet_data(b), dp_packet_size(a));
}

/* Get the start of the Ethernet frame.  'l3_ofs' marks the end of the l2
 * headers, so return NULL if it is not set. */
static inline void *
dp_packet_l2(const struct dp_packet *b)
{
    return (b->l3_ofs != UINT16_MAX) ? dp_packet_data(b) : NULL;
}

/* Resets all layer offsets.  'l3' offset must be set before 'l2' can be
 * retrieved. */
static inline void
dp_packet_reset_offsets(struct dp_packet *b)
{
    b->l2_pad_size = 0;
    b->l2_5_ofs = UINT16_MAX;
    b->l3_ofs = UINT16_MAX;
    b->l4_ofs = UINT16_MAX;
}

static inline uint8_t
dp_packet_l2_pad_size(const struct dp_packet *b)
{
    return b->l2_pad_size;
}

static inline void
dp_packet_set_l2_pad_size(struct dp_packet *b, uint8_t pad_size)
{
    ovs_assert(pad_size <= dp_packet_size(b));
    b->l2_pad_size = pad_size;
}

static inline void *
dp_packet_l2_5(const struct dp_packet *b)
{
    return b->l2_5_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->l2_5_ofs
           : NULL;
}

static inline void
dp_packet_set_l2_5(struct dp_packet *b, void *l2_5)
{
    b->l2_5_ofs = l2_5
                  ? (char *) l2_5 - (char *) dp_packet_data(b)
                  : UINT16_MAX;
}

static inline void *
dp_packet_l3(const struct dp_packet *b)
{
    return b->l3_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->l3_ofs
           : NULL;
}

static inline void
dp_packet_set_l3(struct dp_packet *b, void *l3)
{
    b->l3_ofs = l3 ? (char *) l3 - (char *) dp_packet_data(b) : UINT16_MAX;
}

static inline void *
dp_packet_l4(const struct dp_packet *b)
{
    return b->l4_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->l4_ofs
           : NULL;
}

static inline void
dp_packet_set_l4(struct dp_packet *b, void *l4)
{
    b->l4_ofs = l4 ? (char *) l4 - (char *) dp_packet_data(b) : UINT16_MAX;
}

static inline size_t
dp_packet_l4_size(const struct dp_packet *b)
{
    return b->l4_ofs != UINT16_MAX
        ? (const char *)dp_packet_tail(b) - (const char *)dp_packet_l4(b)
        - dp_packet_l2_pad_size(b)
        : 0;
}

static inline const void *
dp_packet_get_tcp_payload(const struct dp_packet *b)
{
    size_t l4_size = dp_packet_l4_size(b);

    if (OVS_LIKELY(l4_size >= TCP_HEADER_LEN)) {
        struct tcp_header *tcp = dp_packet_l4(b);
        int tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;

        if (OVS_LIKELY(tcp_len >= TCP_HEADER_LEN && tcp_len <= l4_size)) {
            return (const char *)tcp + tcp_len;
        }
    }
    return NULL;
}

static inline const void *
dp_packet_get_udp_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= UDP_HEADER_LEN)
        ? (const char *)dp_packet_l4(b) + UDP_HEADER_LEN : NULL;
}

static inline const void *
dp_packet_get_sctp_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= SCTP_HEADER_LEN)
        ? (const char *)dp_packet_l4(b) + SCTP_HEADER_LEN : NULL;
}

static inline const void *
dp_packet_get_icmp_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= ICMP_HEADER_LEN)
        ? (const char *)dp_packet_l4(b) + ICMP_HEADER_LEN : NULL;
}

static inline const void *
dp_packet_get_nd_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= ND_MSG_LEN)
        ? (const char *)dp_packet_l4(b) + ND_MSG_LEN : NULL;
}

#ifdef DPDK_NETDEV
BUILD_ASSERT_DECL(offsetof(struct dp_packet, mbuf) == 0);

static inline void *
dp_packet_base(const struct dp_packet *b)
{
    return b->mbuf.buf_addr;
}

static inline void
dp_packet_set_base(struct dp_packet *b, void *d)
{
    b->mbuf.buf_addr = d;
}

static inline uint32_t
dp_packet_size(const struct dp_packet *b)
{
    return b->mbuf.pkt_len;
}

static inline void
dp_packet_set_size(struct dp_packet *b, uint32_t v)
{
    /* netdev-dpdk does not currently support segmentation; consequently, for
     * all intents and purposes, 'data_len' (16 bit) and 'pkt_len' (32 bit) may
     * be used interchangably.
     *
     * On the datapath, it is expected that the size of packets
     * (and thus 'v') will always be <= UINT16_MAX; this means that there is no
     * loss of accuracy in assigning 'v' to 'data_len'.
     */
    b->mbuf.data_len = (uint16_t)v;  /* Current seg length. */
    b->mbuf.pkt_len = v;             /* Total length of all segments linked to
                                      * this segment. */
}

static inline uint16_t
__packet_data(const struct dp_packet *b)
{
    return b->mbuf.data_off;
}

static inline void
__packet_set_data(struct dp_packet *b, uint16_t v)
{
    b->mbuf.data_off = v;
}

static inline uint16_t
dp_packet_get_allocated(const struct dp_packet *b)
{
    return b->mbuf.buf_len;
}

static inline void
dp_packet_set_allocated(struct dp_packet *b, uint16_t s)
{
    b->mbuf.buf_len = s;
}
#else
static inline void *
dp_packet_base(const struct dp_packet *b)
{
    return b->base_;
}

static inline void
dp_packet_set_base(struct dp_packet *b, void *d)
{
    b->base_ = d;
}

static inline uint32_t
dp_packet_size(const struct dp_packet *b)
{
    return b->size_;
}

static inline void
dp_packet_set_size(struct dp_packet *b, uint32_t v)
{
    b->size_ = v;
}

static inline uint16_t
__packet_data(const struct dp_packet *b)
{
    return b->data_ofs;
}

static inline void
__packet_set_data(struct dp_packet *b, uint16_t v)
{
    b->data_ofs = v;
}

static inline uint16_t
dp_packet_get_allocated(const struct dp_packet *b)
{
    return b->allocated_;
}

static inline void
dp_packet_set_allocated(struct dp_packet *b, uint16_t s)
{
    b->allocated_ = s;
}
#endif

static inline void
dp_packet_reset_cutlen(struct dp_packet *b)
{
    b->cutlen = 0;
}

static inline uint32_t
dp_packet_set_cutlen(struct dp_packet *b, uint32_t max_len)
{
    if (max_len < ETH_HEADER_LEN) {
        max_len = ETH_HEADER_LEN;
    }

    if (max_len >= dp_packet_size(b)) {
        b->cutlen = 0;
    } else {
        b->cutlen = dp_packet_size(b) - max_len;
    }
    return b->cutlen;
}

static inline uint32_t
dp_packet_get_cutlen(struct dp_packet *b)
{
    /* Always in valid range if user uses dp_packet_set_cutlen. */
    return b->cutlen;
}

static inline void *
dp_packet_data(const struct dp_packet *b)
{
    return __packet_data(b) != UINT16_MAX
           ? (char *) dp_packet_base(b) + __packet_data(b) : NULL;
}

static inline void
dp_packet_set_data(struct dp_packet *b, void *data)
{
    if (data) {
        __packet_set_data(b, (char *) data - (char *) dp_packet_base(b));
    } else {
        __packet_set_data(b, UINT16_MAX);
    }
}

static inline void
dp_packet_reset_packet(struct dp_packet *b, int off)
{
    dp_packet_set_size(b, dp_packet_size(b) - off);
    dp_packet_set_data(b, ((unsigned char *) dp_packet_data(b) + off));
    dp_packet_reset_offsets(b);
}

/* Returns the RSS hash of the packet 'p'.  Note that the returned value is
 * correct only if 'dp_packet_rss_valid(p)' returns true */
static inline uint32_t
dp_packet_get_rss_hash(struct dp_packet *p)
{
#ifdef DPDK_NETDEV
    return p->mbuf.hash.rss;
#else
    return p->rss_hash;
#endif
}

static inline void
dp_packet_set_rss_hash(struct dp_packet *p, uint32_t hash)
{
#ifdef DPDK_NETDEV
    p->mbuf.hash.rss = hash;
    p->mbuf.ol_flags |= PKT_RX_RSS_HASH;
#else
    p->rss_hash = hash;
    p->rss_hash_valid = true;
#endif
}

static inline bool
dp_packet_rss_valid(struct dp_packet *p)
{
#ifdef DPDK_NETDEV
    return p->mbuf.ol_flags & PKT_RX_RSS_HASH;
#else
    return p->rss_hash_valid;
#endif
}

static inline void
dp_packet_rss_invalidate(struct dp_packet *p)
{
#ifdef DPDK_NETDEV
    p->mbuf.ol_flags &= ~PKT_RX_RSS_HASH;
#else
    p->rss_hash_valid = false;
#endif
}

enum { NETDEV_MAX_BURST = 32 }; /* Maximum number packets in a batch. */

struct dp_packet_batch {
    int count;
    bool trunc; /* true if the batch needs truncate. */
    struct dp_packet *packets[NETDEV_MAX_BURST];
};

static inline void dp_packet_batch_init(struct dp_packet_batch *b)
{
    b->count = 0;
    b->trunc = false;
}

static inline void
dp_packet_batch_clone(struct dp_packet_batch *dst,
                      struct dp_packet_batch *src)
{
    int i;

    for (i = 0; i < src->count; i++) {
        dst->packets[i] = dp_packet_clone(src->packets[i]);
    }
    dst->count = src->count;
    dst->trunc = src->trunc;
}

static inline void
packet_batch_init_packet(struct dp_packet_batch *b, struct dp_packet *p)
{
    b->count = 1;
    b->trunc = false;
    b->packets[0] = p;
}

static inline void
dp_packet_delete_batch(struct dp_packet_batch *batch, bool may_steal)
{
    if (may_steal) {
        int i;

        for (i = 0; i < batch->count; i++) {
            dp_packet_delete(batch->packets[i]);
        }
    }
}

static inline void
dp_packet_batch_apply_cutlen(struct dp_packet_batch *pktb)
{
    int i;

    if (!pktb->trunc)
        return;

    for (i = 0; i < pktb->count; i++) {
        uint32_t cutlen = dp_packet_get_cutlen(pktb->packets[i]);

        dp_packet_set_size(pktb->packets[i],
                    dp_packet_size(pktb->packets[i]) - cutlen);
        dp_packet_reset_cutlen(pktb->packets[i]);
    }
    pktb->trunc = false;
}

static inline void
dp_packet_batch_reset_cutlen(struct dp_packet_batch *pktb)
{
    int i;

    if (!pktb->trunc)
        return;

    pktb->trunc = false;
    for (i = 0; i < pktb->count; i++) {
        dp_packet_reset_cutlen(pktb->packets[i]);
    }
}

#ifdef  __cplusplus
}
#endif

#endif /* dp-packet.h */
