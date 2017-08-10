/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
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
#include <stdlib.h>
#include <string.h>

#include "dp-packet.h"
#include "netdev-dpdk.h"
#include "openvswitch/dynamic-string.h"
#include "util.h"

static void
dp_packet_init__(struct dp_packet *b, size_t allocated, enum dp_packet_source source)
{
    dp_packet_set_allocated(b, allocated);
    b->source = source;
    dp_packet_reset_offsets(b);
    pkt_metadata_init(&b->md, 0);
    dp_packet_rss_invalidate(b);
    dp_packet_mbuf_init(b);
    dp_packet_reset_cutlen(b);
    /* By default assume the packet type to be Ethernet. */
    b->packet_type = htonl(PT_ETH);
}

static void
dp_packet_use__(struct dp_packet *b, void *base, size_t allocated,
             enum dp_packet_source source)
{
    dp_packet_set_base(b, base);
    dp_packet_set_data(b, base);
    dp_packet_set_size(b, 0);

    dp_packet_init__(b, allocated, source);
}

/* Initializes 'b' as an empty dp_packet that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should be the first byte of a region
 * obtained from malloc().  It will be freed (with free()) if 'b' is resized or
 * freed. */
void
dp_packet_use(struct dp_packet *b, void *base, size_t allocated)
{
    dp_packet_use__(b, base, allocated, DPBUF_MALLOC);
}

/* Initializes 'b' as an empty dp_packet that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should point to a buffer on the stack.
 * (Nothing actually relies on 'base' being allocated on the stack.  It could
 * be static or malloc()'d memory.  But stack space is the most common use
 * case.)
 *
 * 'base' should be appropriately aligned.  Using an array of uint32_t or
 * uint64_t for the buffer is a reasonable way to ensure appropriate alignment
 * for 32- or 64-bit data.
 *
 * An dp_packet operation that requires reallocating data will copy the provided
 * buffer into a malloc()'d buffer.  Thus, it is wise to call dp_packet_uninit()
 * on an dp_packet initialized by this function, so that if it expanded into the
 * heap, that memory is freed. */
void
dp_packet_use_stub(struct dp_packet *b, void *base, size_t allocated)
{
    dp_packet_use__(b, base, allocated, DPBUF_STUB);
}

/* Initializes 'b' as an dp_packet whose data starts at 'data' and continues for
 * 'size' bytes.  This is appropriate for an dp_packet that will be used to
 * inspect existing data, without moving it around or reallocating it, and
 * generally without modifying it at all.
 *
 * An dp_packet operation that requires reallocating data will assert-fail if this
 * function was used to initialize it. */
void
dp_packet_use_const(struct dp_packet *b, const void *data, size_t size)
{
    dp_packet_use__(b, CONST_CAST(void *, data), size, DPBUF_STACK);
    dp_packet_set_size(b, size);
}

/* Initializes 'b' as an empty dp_packet that contains the 'allocated' bytes of
 * memory starting at 'base'.  DPDK allocated dp_packet and *data is allocated
 * from one continous memory region, so in memory data start right after
 * dp_packet.  Therefore there is special method to free this type of
 * buffer.  dp_packet base, data and size are initialized by dpdk rcv() so no
 * need to initialize those fields. */
void
dp_packet_init_dpdk(struct dp_packet *b, size_t allocated)
{
    dp_packet_init__(b, allocated, DPBUF_DPDK);
}

/* Initializes 'b' as an empty dp_packet with an initial capacity of 'size'
 * bytes. */
void
dp_packet_init(struct dp_packet *b, size_t size)
{
    dp_packet_use(b, size ? xmalloc(size) : NULL, size);
}

/* Frees memory that 'b' points to. */
void
dp_packet_uninit(struct dp_packet *b)
{
    if (b) {
        if (b->source == DPBUF_MALLOC) {
            free(dp_packet_base(b));
        } else if (b->source == DPBUF_DPDK) {
#ifdef DPDK_NETDEV
            /* If this dp_packet was allocated by DPDK it must have been
             * created as a dp_packet */
            free_dpdk_buf((struct dp_packet*) b);
#endif
        }
    }
}

/* Creates and returns a new dp_packet with an initial capacity of 'size'
 * bytes. */
struct dp_packet *
dp_packet_new(size_t size)
{
    struct dp_packet *b = xmalloc(sizeof *b);
    dp_packet_init(b, size);
    return b;
}

/* Creates and returns a new dp_packet with an initial capacity of 'size +
 * headroom' bytes, reserving the first 'headroom' bytes as headroom. */
struct dp_packet *
dp_packet_new_with_headroom(size_t size, size_t headroom)
{
    struct dp_packet *b = dp_packet_new(size + headroom);
    dp_packet_reserve(b, headroom);
    return b;
}

/* Creates and returns a new dp_packet that initially contains a copy of the
 * 'dp_packet_size(buffer)' bytes of data starting at 'buffer->data' with no headroom or
 * tailroom. */
struct dp_packet *
dp_packet_clone(const struct dp_packet *buffer)
{
    return dp_packet_clone_with_headroom(buffer, 0);
}

/* Creates and returns a new dp_packet whose data are copied from 'buffer'.   The
 * returned dp_packet will additionally have 'headroom' bytes of headroom. */
struct dp_packet *
dp_packet_clone_with_headroom(const struct dp_packet *buffer, size_t headroom)
{
    struct dp_packet *new_buffer;

    new_buffer = dp_packet_clone_data_with_headroom(dp_packet_data(buffer),
                                                 dp_packet_size(buffer),
                                                 headroom);
    new_buffer->l2_pad_size = buffer->l2_pad_size;
    new_buffer->l2_5_ofs = buffer->l2_5_ofs;
    new_buffer->l3_ofs = buffer->l3_ofs;
    new_buffer->l4_ofs = buffer->l4_ofs;
    new_buffer->md = buffer->md;
    new_buffer->cutlen = buffer->cutlen;
    new_buffer->packet_type = buffer->packet_type;
#ifdef DPDK_NETDEV
    new_buffer->mbuf.ol_flags = buffer->mbuf.ol_flags;
#else
    new_buffer->rss_hash_valid = buffer->rss_hash_valid;
#endif

    if (dp_packet_rss_valid(new_buffer)) {
#ifdef DPDK_NETDEV
        new_buffer->mbuf.hash.rss = buffer->mbuf.hash.rss;
#else
        new_buffer->rss_hash = buffer->rss_hash;
#endif
    }

    return new_buffer;
}

/* Creates and returns a new dp_packet that initially contains a copy of the
 * 'size' bytes of data starting at 'data' with no headroom or tailroom. */
struct dp_packet *
dp_packet_clone_data(const void *data, size_t size)
{
    return dp_packet_clone_data_with_headroom(data, size, 0);
}

/* Creates and returns a new dp_packet that initially contains 'headroom' bytes of
 * headroom followed by a copy of the 'size' bytes of data starting at
 * 'data'. */
struct dp_packet *
dp_packet_clone_data_with_headroom(const void *data, size_t size, size_t headroom)
{
    struct dp_packet *b = dp_packet_new_with_headroom(size, headroom);
    dp_packet_put(b, data, size);
    return b;
}

static void
dp_packet_copy__(struct dp_packet *b, uint8_t *new_base,
              size_t new_headroom, size_t new_tailroom)
{
    const uint8_t *old_base = dp_packet_base(b);
    size_t old_headroom = dp_packet_headroom(b);
    size_t old_tailroom = dp_packet_tailroom(b);
    size_t copy_headroom = MIN(old_headroom, new_headroom);
    size_t copy_tailroom = MIN(old_tailroom, new_tailroom);

    memcpy(&new_base[new_headroom - copy_headroom],
           &old_base[old_headroom - copy_headroom],
           copy_headroom + dp_packet_size(b) + copy_tailroom);
}

/* Reallocates 'b' so that it has exactly 'new_headroom' and 'new_tailroom'
 * bytes of headroom and tailroom, respectively. */
static void
dp_packet_resize__(struct dp_packet *b, size_t new_headroom, size_t new_tailroom)
{
    void *new_base, *new_data;
    size_t new_allocated;

    new_allocated = new_headroom + dp_packet_size(b) + new_tailroom;

    switch (b->source) {
    case DPBUF_DPDK:
        OVS_NOT_REACHED();

    case DPBUF_MALLOC:
        if (new_headroom == dp_packet_headroom(b)) {
            new_base = xrealloc(dp_packet_base(b), new_allocated);
        } else {
            new_base = xmalloc(new_allocated);
            dp_packet_copy__(b, new_base, new_headroom, new_tailroom);
            free(dp_packet_base(b));
        }
        break;

    case DPBUF_STACK:
        OVS_NOT_REACHED();

    case DPBUF_STUB:
        b->source = DPBUF_MALLOC;
        new_base = xmalloc(new_allocated);
        dp_packet_copy__(b, new_base, new_headroom, new_tailroom);
        break;

    default:
        OVS_NOT_REACHED();
    }

    dp_packet_set_allocated(b, new_allocated);
    dp_packet_set_base(b, new_base);

    new_data = (char *) new_base + new_headroom;
    if (dp_packet_data(b) != new_data) {
        dp_packet_set_data(b, new_data);
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its tail end,
 * reallocating and copying its data if necessary.  Its headroom, if any, is
 * preserved. */
void
dp_packet_prealloc_tailroom(struct dp_packet *b, size_t size)
{
    if (size > dp_packet_tailroom(b)) {
        dp_packet_resize__(b, dp_packet_headroom(b), MAX(size, 64));
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its head,
 * reallocating and copying its data if necessary.  Its tailroom, if any, is
 * preserved. */
void
dp_packet_prealloc_headroom(struct dp_packet *b, size_t size)
{
    if (size > dp_packet_headroom(b)) {
        dp_packet_resize__(b, MAX(size, 64), dp_packet_tailroom(b));
    }
}

/* Shifts all of the data within the allocated space in 'b' by 'delta' bytes.
 * For example, a 'delta' of 1 would cause each byte of data to move one byte
 * forward (from address 'p' to 'p+1'), and a 'delta' of -1 would cause each
 * byte to move one byte backward (from 'p' to 'p-1'). */
void
dp_packet_shift(struct dp_packet *b, int delta)
{
    ovs_assert(delta > 0 ? delta <= dp_packet_tailroom(b)
               : delta < 0 ? -delta <= dp_packet_headroom(b)
               : true);

    if (delta != 0) {
        char *dst = (char *) dp_packet_data(b) + delta;
        memmove(dst, dp_packet_data(b), dp_packet_size(b));
        dp_packet_set_data(b, dst);
    }
}

/* Appends 'size' bytes of data to the tail end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * new data, which is left uninitialized. */
void *
dp_packet_put_uninit(struct dp_packet *b, size_t size)
{
    void *p;
    dp_packet_prealloc_tailroom(b, size);
    p = dp_packet_tail(b);
    dp_packet_set_size(b, dp_packet_size(b) + size);
    return p;
}

/* Appends 'size' zeroed bytes to the tail end of 'b'.  Data in 'b' is
 * reallocated and copied if necessary.  Returns a pointer to the first byte of
 * the data's location in the dp_packet. */
void *
dp_packet_put_zeros(struct dp_packet *b, size_t size)
{
    void *dst = dp_packet_put_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Appends the 'size' bytes of data in 'p' to the tail end of 'b'.  Data in 'b'
 * is reallocated and copied if necessary.  Returns a pointer to the first
 * byte of the data's location in the dp_packet. */
void *
dp_packet_put(struct dp_packet *b, const void *p, size_t size)
{
    void *dst = dp_packet_put_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Parses as many pairs of hex digits as possible (possibly separated by
 * spaces) from the beginning of 's', appending bytes for their values to 'b'.
 * Returns the first character of 's' that is not the first of a pair of hex
 * digits.  If 'n' is nonnull, stores the number of bytes added to 'b' in
 * '*n'. */
char *
dp_packet_put_hex(struct dp_packet *b, const char *s, size_t *n)
{
    size_t initial_size = dp_packet_size(b);
    for (;;) {
        uint8_t byte;
        bool ok;

        s += strspn(s, " \t\r\n");
        byte = hexits_value(s, 2, &ok);
        if (!ok) {
            if (n) {
                *n = dp_packet_size(b) - initial_size;
            }
            return CONST_CAST(char *, s);
        }

        dp_packet_put(b, &byte, 1);
        s += 2;
    }
}

/* Reserves 'size' bytes of headroom so that they can be later allocated with
 * dp_packet_push_uninit() without reallocating the dp_packet. */
void
dp_packet_reserve(struct dp_packet *b, size_t size)
{
    ovs_assert(!dp_packet_size(b));
    dp_packet_prealloc_tailroom(b, size);
    dp_packet_set_data(b, (char*)dp_packet_data(b) + size);
}

/* Reserves 'headroom' bytes at the head and 'tailroom' at the end so that
 * they can be later allocated with dp_packet_push_uninit() or
 * dp_packet_put_uninit() without reallocating the dp_packet. */
void
dp_packet_reserve_with_tailroom(struct dp_packet *b, size_t headroom,
                             size_t tailroom)
{
    ovs_assert(!dp_packet_size(b));
    dp_packet_prealloc_tailroom(b, headroom + tailroom);
    dp_packet_set_data(b, (char*)dp_packet_data(b) + headroom);
}

/* Prefixes 'size' bytes to the head end of 'b', reallocating and copying its
 * data if necessary.  Returns a pointer to the first byte of the data's
 * location in the dp_packet.  The new data is left uninitialized. */
void *
dp_packet_push_uninit(struct dp_packet *b, size_t size)
{
    dp_packet_prealloc_headroom(b, size);
    dp_packet_set_data(b, (char*)dp_packet_data(b) - size);
    dp_packet_set_size(b, dp_packet_size(b) + size);
    return dp_packet_data(b);
}

/* Prefixes 'size' zeroed bytes to the head end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * data's location in the dp_packet. */
void *
dp_packet_push_zeros(struct dp_packet *b, size_t size)
{
    void *dst = dp_packet_push_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Copies the 'size' bytes starting at 'p' to the head end of 'b', reallocating
 * and copying its data if necessary.  Returns a pointer to the first byte of
 * the data's location in the dp_packet. */
void *
dp_packet_push(struct dp_packet *b, const void *p, size_t size)
{
    void *dst = dp_packet_push_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Returns the data in 'b' as a block of malloc()'d memory and frees the buffer
 * within 'b'.  (If 'b' itself was dynamically allocated, e.g. with
 * dp_packet_new(), then it should still be freed with, e.g., dp_packet_delete().) */
void *
dp_packet_steal_data(struct dp_packet *b)
{
    void *p;
    ovs_assert(b->source != DPBUF_DPDK);

    if (b->source == DPBUF_MALLOC && dp_packet_data(b) == dp_packet_base(b)) {
        p = dp_packet_data(b);
    } else {
        p = xmemdup(dp_packet_data(b), dp_packet_size(b));
        if (b->source == DPBUF_MALLOC) {
            free(dp_packet_base(b));
        }
    }
    dp_packet_set_base(b, NULL);
    dp_packet_set_data(b, NULL);
    return p;
}

static inline void
dp_packet_adjust_layer_offset(uint16_t *offset, int increment)
{
    if (*offset != UINT16_MAX) {
        *offset += increment;
    }
}

/* Adjust the size of the l2_5 portion of the dp_packet, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
void *
dp_packet_resize_l2_5(struct dp_packet *b, int increment)
{
    if (increment >= 0) {
        dp_packet_push_uninit(b, increment);
    } else {
        dp_packet_pull(b, -increment);
    }

    /* Adjust layer offsets after l2_5. */
    dp_packet_adjust_layer_offset(&b->l3_ofs, increment);
    dp_packet_adjust_layer_offset(&b->l4_ofs, increment);

    return dp_packet_data(b);
}

/* Adjust the size of the l2 portion of the dp_packet, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
void *
dp_packet_resize_l2(struct dp_packet *b, int increment)
{
    dp_packet_resize_l2_5(b, increment);
    dp_packet_adjust_layer_offset(&b->l2_5_ofs, increment);
    return dp_packet_data(b);
}
