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

#include "ofp-prop.h"

#include "byte-order.h"
#include "ofpbuf.h"
#include "ofp-errors.h"
#include "util.h"

/* Pulls a property, beginning with struct ofp_prop_header, from the beginning
 * of 'msg'.  Stores the type of the property in '*typep' and, if 'property' is
 * nonnull, the entire property, including the header, in '*property'.  Returns
 * 0 if successful, otherwise an OpenFlow error code.
 *
 * This function pulls the property's stated size padded out to a multiple of
 * 'alignment' bytes.  The common case in OpenFlow is an 'alignment' of 8, so
 * you can use ofpprop_pull() for that case. */
enum ofperr
ofpprop_pull__(struct ofpbuf *msg, struct ofpbuf *property,
               unsigned int alignment, uint16_t *typep)
{
    struct ofp_prop_header *oph;
    unsigned int padded_len;
    unsigned int len;

    if (msg->size < sizeof *oph) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    oph = msg->data;
    len = ntohs(oph->len);
    padded_len = ROUND_UP(len, alignment);
    if (len < sizeof *oph || padded_len > msg->size) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    *typep = ntohs(oph->type);
    if (property) {
        ofpbuf_use_const(property, msg->data, len);
    }
    ofpbuf_pull(msg, padded_len);
    return 0;
}

/* Pulls a property, beginning with struct ofp_prop_header, from the beginning
 * of 'msg'.  Stores the type of the property in '*typep' and, if 'property' is
 * nonnull, the entire property, including the header, in '*property'.  Returns
 * 0 if successful, otherwise an error code.
 *
 * This function pulls the property's stated size padded out to a multiple of
 * 8 bytes, which is the common case for OpenFlow properties. */
enum ofperr
ofpprop_pull(struct ofpbuf *msg, struct ofpbuf *property, uint16_t *typep)
{
    return ofpprop_pull__(msg, property, 8, typep);
}

/* Adds a property with the given 'type' and 'len'-byte contents 'value' to
 * 'msg', padding the property out to a multiple of 8 bytes. */
void
ofpprop_put(struct ofpbuf *msg, uint16_t type, const void *value, size_t len)
{
    size_t start_ofs = ofpprop_start(msg, type);
    ofpbuf_put(msg, value, len);
    ofpprop_end(msg, start_ofs);
}

/* Appends a property to 'msg' whose type is 'type' and whose contents is a
 * series of property headers, one for each 1-bit in 'bitmap'. */
void
ofpprop_put_bitmap(struct ofpbuf *msg, uint16_t type, uint64_t bitmap)
{
    size_t start_ofs = ofpprop_start(msg, type);

    for (; bitmap; bitmap = zero_rightmost_1bit(bitmap)) {
        ofpprop_start(msg, rightmost_1bit_idx(bitmap));
    }
    ofpprop_end(msg, start_ofs);
}

/* Appends a header for a property of type 'type' to 'msg'.  The caller should
 * add the contents of the property to 'msg', then finish it by calling
 * ofpprop_end().  Returns the offset of the beginning of the property (to pass
 * to ofpprop_end() later). */
size_t
ofpprop_start(struct ofpbuf *msg, uint16_t type)
{
    size_t start_ofs = msg->size;
    struct ofp_prop_header *oph;

    oph = ofpbuf_put_uninit(msg, sizeof *oph);
    oph->type = htons(type);
    oph->len = htons(4);        /* May be updated later by ofpprop_end(). */
    return start_ofs;
}

/* Finishes serializing a property that was begun with ofpprop_start(), by
 * padding 'msg' to a multiple of 8 bytes and updating the property's length.
 * 'start_ofs' should be the offset of the beginning of the property, as
 * returned by ofpprop_start(). */
void
ofpprop_end(struct ofpbuf *msg, size_t start_ofs)
{
    struct ofp_prop_header *oph;

    oph = ofpbuf_at_assert(msg, start_ofs, sizeof *oph);
    oph->len = htons(msg->size - start_ofs);
    ofpbuf_padto(msg, ROUND_UP(msg->size, 8));
}

