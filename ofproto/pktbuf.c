/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "ofpbuf.h"
#include "timeval.h"
#include "util.h"
#include "vconn.h"

#define THIS_MODULE VLM_pktbuf
#include "vlog.h"

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
    struct ofpbuf *buffer;
    uint32_t cookie;
    long long int timeout;
    uint16_t in_port;
};

struct pktbuf {
    struct packet packets[PKTBUF_CNT];
    unsigned int buffer_idx;
};

int
pktbuf_capacity(void)
{
    return PKTBUF_CNT;
}

struct pktbuf *
pktbuf_create(void)
{
    return xcalloc(1, sizeof *pktbuf_create());
}

void
pktbuf_destroy(struct pktbuf *pb)
{
    if (pb) {
        size_t i;

        for (i = 0; i < PKTBUF_CNT; i++) {
            ofpbuf_delete(pb->packets[i].buffer);
        }
        free(pb);
    }
}

uint32_t
pktbuf_save(struct pktbuf *pb, struct ofpbuf *buffer, uint16_t in_port)
{
    struct packet *p = &pb->packets[pb->buffer_idx];
    pb->buffer_idx = (pb->buffer_idx + 1) & PKTBUF_MASK;
    if (p->buffer) {
        if (time_msec() < p->timeout) {
            return UINT32_MAX;
        }
        ofpbuf_delete(p->buffer);
    }

    /* Don't use maximum cookie value since all-1-bits ID is special. */
    if (++p->cookie >= COOKIE_MAX) {
        p->cookie = 0;
    }
    p->buffer = ofpbuf_clone(buffer);
    p->timeout = time_msec() + OVERWRITE_MSECS;
    p->in_port = in_port;
    return (p - pb->packets) | (p->cookie << PKTBUF_BITS);
}

int
pktbuf_retrieve(struct pktbuf *pb, uint32_t id, struct ofpbuf **bufferp,
                uint16_t *in_port)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 20);
    struct packet *p;
    int error;

    if (!pb) {
        VLOG_WARN_RL(&rl, "attempt to send buffered packet via connection "
                     "without buffers");
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_COOKIE);
    }

    p = &pb->packets[id & PKTBUF_MASK];
    if (p->cookie == id >> PKTBUF_BITS) {
        struct ofpbuf *buffer = p->buffer;
        if (buffer) {
            *bufferp = buffer;
            *in_port = p->in_port;
            p->buffer = NULL;
            COVERAGE_INC(pktbuf_retrieved);
            return 0;
        } else {
            COVERAGE_INC(pktbuf_reuse_error);
            VLOG_WARN_RL(&rl, "attempt to reuse buffer %08"PRIx32, id);
            error = ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BUFFER_EMPTY);
        }
    } else {
        COVERAGE_INC(pktbuf_bad_cookie);
        VLOG_WARN_RL(&rl, "cookie mismatch: %08"PRIx32" != %08"PRIx32,
                     id, (id & PKTBUF_MASK) | (p->cookie << PKTBUF_BITS));
        error = ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_COOKIE);
    }
    *bufferp = NULL;
    *in_port = -1;
    return error;
}

void
pktbuf_discard(struct pktbuf *pb, uint32_t id)
{
    struct packet *p = &pb->packets[id & PKTBUF_MASK];
    if (p->cookie == id >> PKTBUF_BITS) {
        ofpbuf_delete(p->buffer);
        p->buffer = NULL;
    }
}
