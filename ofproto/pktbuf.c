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

#include <config.h>
#include "pktbuf.h"
#include <inttypes.h>
#include <stdlib.h>
#include "coverage.h"
#include "ofp-util.h"
#include "dp-packet.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(pktbuf);

COVERAGE_DEFINE(pktbuf_buffer_unknown);
COVERAGE_DEFINE(pktbuf_null_cookie);
COVERAGE_DEFINE(pktbuf_retrieved);
COVERAGE_DEFINE(pktbuf_reuse_error);

/* Buffers are identified by a 32-bit opaque ID.  We divide the ID
 * into a buffer number (low bits) and a cookie (high bits).  The buffer number
 * is an index into an array of buffers.  The cookie distinguishes between
 * different packets that have occupied a single buffer.  Thus, the more
 * buffers we have, the lower-quality the cookie... */
#define PKTBUF_BITS     8
#define PKTBUF_MASK     (PKTBUF_CNT - 1)
#define PKTBUF_CNT      (1u << PKTBUF_BITS)

#define COOKIE_BITS     (32 - PKTBUF_BITS)
#define COOKIE_MAX      ((1u << COOKIE_BITS) - 1)

#define OVERWRITE_MSECS 5000

struct packet {
    struct dp_packet *buffer;
    uint32_t cookie;
    long long int timeout;
    ofp_port_t in_port;
};

struct pktbuf {
    struct packet packets[PKTBUF_CNT];
    unsigned int buffer_idx;
    unsigned int null_idx;
};

int
pktbuf_capacity(void)
{
    return PKTBUF_CNT;
}

struct pktbuf *
pktbuf_create(void)
{
    return xzalloc(sizeof *pktbuf_create());
}

void
pktbuf_destroy(struct pktbuf *pb)
{
    if (pb) {
        size_t i;

        for (i = 0; i < PKTBUF_CNT; i++) {
            dp_packet_delete(pb->packets[i].buffer);
        }
        free(pb);
    }
}

static unsigned int
make_id(unsigned int buffer_idx, unsigned int cookie)
{
    return buffer_idx | (cookie << PKTBUF_BITS);
}

/* Attempts to allocate an OpenFlow packet buffer id within 'pb'.  The packet
 * buffer will store a copy of 'buffer_size' bytes in 'buffer' and the port
 * number 'in_port', which should be the OpenFlow port number on which 'buffer'
 * was received.
 *
 * If successful, returns the packet buffer id (a number other than
 * UINT32_MAX).  pktbuf_retrieve() can later be used to retrieve the buffer and
 * its input port number (buffers do expire after a time, so this is not
 * guaranteed to be true forever).  On failure, returns UINT32_MAX.
 *
 * The caller retains ownership of 'buffer'. */
uint32_t
pktbuf_save(struct pktbuf *pb, const void *buffer, size_t buffer_size,
            ofp_port_t in_port)
{
    struct packet *p = &pb->packets[pb->buffer_idx];
    pb->buffer_idx = (pb->buffer_idx + 1) & PKTBUF_MASK;
    if (p->buffer) {
        if (time_msec() < p->timeout) {
            return UINT32_MAX;
        }
        dp_packet_delete(p->buffer);
    }

    /* Don't use maximum cookie value since all-1-bits ID is special. */
    if (++p->cookie >= COOKIE_MAX) {
        p->cookie = 0;
    }

    /* Use 2 bytes of headroom to 32-bit align the L3 header. */
    p->buffer = dp_packet_clone_data_with_headroom(buffer, buffer_size, 2);

    p->timeout = time_msec() + OVERWRITE_MSECS;
    p->in_port = in_port;
    return make_id(p - pb->packets, p->cookie);
}

/*
 * Allocates and returns a "null" packet buffer id.  The returned packet buffer
 * id is considered valid by pktbuf_retrieve(), but it is not associated with
 * actual buffered data.
 *
 * This function is always successful.
 *
 * This is useful in one special case: with the current OpenFlow design, the
 * "fail-open" code cannot always know whether a connection to a controller is
 * actually valid until it receives a OFPT_PACKET_OUT or OFPT_FLOW_MOD request,
 * but at that point the packet in question has already been forwarded (since
 * we are still in "fail-open" mode).  If the packet was buffered in the usual
 * way, then the OFPT_PACKET_OUT or OFPT_FLOW_MOD would cause a duplicate
 * packet in the network.  Null packet buffer ids identify such a packet that
 * has already been forwarded, so that Open vSwitch can quietly ignore the
 * request to re-send it.  (After that happens, the switch exits fail-open
 * mode.)
 *
 * See the top-level comment in fail-open.c for an overview.
 */
uint32_t
pktbuf_get_null(void)
{
    return make_id(0, COOKIE_MAX);
}

/* Attempts to retrieve a saved packet with the given 'id' from 'pb'.  Returns
 * 0 if successful, otherwise an OpenFlow error code.
 *
 * On success, ordinarily stores the buffered packet in '*bufferp' and the
 * OpenFlow port number on which the packet was received in '*in_port'.  The
 * caller becomes responsible for freeing the buffer.  However, if 'id'
 * identifies a "null" packet buffer (created with pktbuf_get_null()), stores
 * NULL in '*bufferp' and OFPP_NONE in '*in_port'.
 *
 * 'in_port' may be NULL if the input port is not of interest.
 *
 * The L3 header of a returned packet will be 32-bit aligned.
 *
 * On failure, stores NULL in in '*bufferp' and UINT16_MAX in '*in_port'. */
enum ofperr
pktbuf_retrieve(struct pktbuf *pb, uint32_t id, struct dp_packet **bufferp,
                ofp_port_t *in_port)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 20);
    struct packet *p;
    enum ofperr error;

    if (id == UINT32_MAX) {
        error = 0;
        goto error;
    }

    if (!pb) {
        VLOG_WARN_RL(&rl, "attempt to send buffered packet via connection "
                     "without buffers");
        error = OFPERR_OFPBRC_BUFFER_UNKNOWN;
        goto error;
    }

    p = &pb->packets[id & PKTBUF_MASK];
    if (p->cookie == id >> PKTBUF_BITS) {
        struct dp_packet *buffer = p->buffer;
        if (buffer) {
            *bufferp = buffer;
            if (in_port) {
                *in_port = p->in_port;
            }
            p->buffer = NULL;
            COVERAGE_INC(pktbuf_retrieved);
            return 0;
        } else {
            COVERAGE_INC(pktbuf_reuse_error);
            VLOG_WARN_RL(&rl, "attempt to reuse buffer %08"PRIx32, id);
            error = OFPERR_OFPBRC_BUFFER_EMPTY;
        }
    } else if (id >> PKTBUF_BITS != COOKIE_MAX) {
        COVERAGE_INC(pktbuf_buffer_unknown);
        VLOG_WARN_RL(&rl, "cookie mismatch: %08"PRIx32" != %08"PRIx32,
                     id, (id & PKTBUF_MASK) | (p->cookie << PKTBUF_BITS));
        error = OFPERR_OFPBRC_BUFFER_UNKNOWN;
    } else {
        COVERAGE_INC(pktbuf_null_cookie);
        VLOG_INFO_RL(&rl, "Received null cookie %08"PRIx32" (this is normal "
                     "if the switch was recently in fail-open mode)", id);
        error = 0;
    }
error:
    *bufferp = NULL;
    if (in_port) {
        *in_port = OFPP_NONE;
    }
    return error;
}

void
pktbuf_discard(struct pktbuf *pb, uint32_t id)
{
    struct packet *p = &pb->packets[id & PKTBUF_MASK];
    if (p->cookie == id >> PKTBUF_BITS) {
        dp_packet_delete(p->buffer);
        p->buffer = NULL;
    }
}

/* Returns the number of packets buffered in 'pb'.  Returns 0 if 'pb' is
 * null. */
unsigned int
pktbuf_count_packets(const struct pktbuf *pb)
{
    int n = 0;

    if (pb) {
        int i;

        for (i = 0; i < PKTBUF_CNT; i++) {
            if (pb->packets[i].buffer) {
                n++;
            }
        }
    }

    return n;
}
