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
#include "dp-packet.h"

#include "ofpbuf.h"

struct dp_packet *
dp_packet_new_with_headroom(size_t size, size_t headroom)
{
    struct dp_packet *p = xmalloc(sizeof *p);
    struct ofpbuf *b = &p->ofpbuf;

    ofpbuf_init(b, size + headroom);
    ofpbuf_reserve(b, headroom);
    p->md = PKT_METADATA_INITIALIZER(0);

    return p;
}

struct dp_packet *
dp_packet_clone_from_ofpbuf(const struct ofpbuf *b)
{
    struct dp_packet *p = xmalloc(sizeof *p);
    size_t headroom = ofpbuf_headroom(b);

    ofpbuf_init(&p->ofpbuf, ofpbuf_size(b) + headroom);
    p->md = PKT_METADATA_INITIALIZER(0);
    ofpbuf_reserve(&p->ofpbuf, headroom);

    ofpbuf_put(&p->ofpbuf, ofpbuf_data(b), ofpbuf_size(b));

    if (b->frame) {
        uintptr_t data_delta
            = (char *)ofpbuf_data(&p->ofpbuf) - (char *)ofpbuf_data(b);

        p->ofpbuf.frame = (char *) b->frame + data_delta;
    }
    p->ofpbuf.l2_5_ofs = b->l2_5_ofs;
    p->ofpbuf.l3_ofs = b->l3_ofs;
    p->ofpbuf.l4_ofs = b->l4_ofs;

    return p;
}

struct dp_packet *
dp_packet_clone(struct dp_packet *p)
{
    struct dp_packet *newp;

    newp = dp_packet_clone_from_ofpbuf(&p->ofpbuf);
    memcpy(&newp->md, &p->md, sizeof p->md);

    dp_packet_set_dp_hash(newp, dp_packet_get_dp_hash(p));

    return newp;
}
