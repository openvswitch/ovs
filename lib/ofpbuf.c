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
#include "ofpbuf.h"
#include <stdlib.h>
#include <string.h>
#include "dynamic-string.h"
#include "netdev-dpdk.h"
#include "util.h"

static void
ofpbuf_init__(struct ofpbuf *b, size_t allocated, enum ofpbuf_source source)
{
    b->allocated = allocated;
    b->source = source;
    b->frame = NULL;
    b->l2_5_ofs = b->l3_ofs = b->l4_ofs = UINT16_MAX;
    list_poison(&b->list_node);
}

static void
ofpbuf_use__(struct ofpbuf *b, void *base, size_t allocated,
             enum ofpbuf_source source)
{
    ofpbuf_set_base(b, base);
    ofpbuf_set_data(b, base);
    ofpbuf_set_size(b, 0);

    ofpbuf_init__(b, allocated, source);
}

/* Initializes 'b' as an empty ofpbuf that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should be the first byte of a region
 * obtained from malloc().  It will be freed (with free()) if 'b' is resized or
 * freed. */
void
ofpbuf_use(struct ofpbuf *b, void *base, size_t allocated)
{
    ofpbuf_use__(b, base, allocated, OFPBUF_MALLOC);
}

/* Initializes 'b' as an empty ofpbuf that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should point to a buffer on the stack.
 * (Nothing actually relies on 'base' being allocated on the stack.  It could
 * be static or malloc()'d memory.  But stack space is the most common use
 * case.)
 *
 * 'base' should be appropriately aligned.  Using an array of uint32_t or
 * uint64_t for the buffer is a reasonable way to ensure appropriate alignment
 * for 32- or 64-bit data.
 *
 * An ofpbuf operation that requires reallocating data will assert-fail if this
 * function was used to initialize it.  Thus, one need not call ofpbuf_uninit()
 * on an ofpbuf initialized by this function (though doing so is harmless),
 * because it is guaranteed that 'b' does not own any heap-allocated memory. */
void
ofpbuf_use_stack(struct ofpbuf *b, void *base, size_t allocated)
{
    ofpbuf_use__(b, base, allocated, OFPBUF_STACK);
}

/* Initializes 'b' as an empty ofpbuf that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should point to a buffer on the stack.
 * (Nothing actually relies on 'base' being allocated on the stack.  It could
 * be static or malloc()'d memory.  But stack space is the most common use
 * case.)
 *
 * 'base' should be appropriately aligned.  Using an array of uint32_t or
 * uint64_t for the buffer is a reasonable way to ensure appropriate alignment
 * for 32- or 64-bit data.
 *
 * An ofpbuf operation that requires reallocating data will copy the provided
 * buffer into a malloc()'d buffer.  Thus, it is wise to call ofpbuf_uninit()
 * on an ofpbuf initialized by this function, so that if it expanded into the
 * heap, that memory is freed. */
void
ofpbuf_use_stub(struct ofpbuf *b, void *base, size_t allocated)
{
    ofpbuf_use__(b, base, allocated, OFPBUF_STUB);
}

/* Initializes 'b' as an ofpbuf whose data starts at 'data' and continues for
 * 'size' bytes.  This is appropriate for an ofpbuf that will be used to
 * inspect existing data, without moving it around or reallocating it, and
 * generally without modifying it at all.
 *
 * An ofpbuf operation that requires reallocating data will assert-fail if this
 * function was used to initialize it. */
void
ofpbuf_use_const(struct ofpbuf *b, const void *data, size_t size)
{
    ofpbuf_use__(b, CONST_CAST(void *, data), size, OFPBUF_STACK);
    ofpbuf_set_size(b, size);
}

/* Initializes 'b' as an empty ofpbuf that contains the 'allocated' bytes of
 * memory starting at 'base'.  DPDK allocated ofpbuf and *data is allocated
 * from one continous memory region, so in memory data start right after
 * ofpbuf.  Therefore there is special method to free this type of
 * buffer.  ofpbuf base, data and size are initialized by dpdk rcv() so no
 * need to initialize those fields. */
void
ofpbuf_init_dpdk(struct ofpbuf *b, size_t allocated)
{
    ofpbuf_init__(b, allocated, OFPBUF_DPDK);
}

/* Initializes 'b' as an empty ofpbuf with an initial capacity of 'size'
 * bytes. */
void
ofpbuf_init(struct ofpbuf *b, size_t size)
{
    ofpbuf_use(b, size ? xmalloc(size) : NULL, size);
}

/* Frees memory that 'b' points to. */
void
ofpbuf_uninit(struct ofpbuf *b)
{
    if (b) {
        if (b->source == OFPBUF_MALLOC) {
            free(ofpbuf_base(b));
        }
        ovs_assert(b->source != OFPBUF_DPDK);
    }
}

/* Frees memory that 'b' points to and allocates a new ofpbuf */
void
ofpbuf_reinit(struct ofpbuf *b, size_t size)
{
    ofpbuf_uninit(b);
    ofpbuf_init(b, size);
}

/* Creates and returns a new ofpbuf with an initial capacity of 'size'
 * bytes. */
struct ofpbuf *
ofpbuf_new(size_t size)
{
    struct ofpbuf *b = xmalloc(sizeof *b);
    ofpbuf_init(b, size);
    return b;
}

/* Creates and returns a new ofpbuf with an initial capacity of 'size +
 * headroom' bytes, reserving the first 'headroom' bytes as headroom. */
struct ofpbuf *
ofpbuf_new_with_headroom(size_t size, size_t headroom)
{
    struct ofpbuf *b = ofpbuf_new(size + headroom);
    ofpbuf_reserve(b, headroom);
    return b;
}

/* Creates and returns a new ofpbuf that initially contains a copy of the
 * 'ofpbuf_size(buffer)' bytes of data starting at 'buffer->data' with no headroom or
 * tailroom. */
struct ofpbuf *
ofpbuf_clone(const struct ofpbuf *buffer)
{
    return ofpbuf_clone_with_headroom(buffer, 0);
}

/* Creates and returns a new ofpbuf whose data are copied from 'buffer'.   The
 * returned ofpbuf will additionally have 'headroom' bytes of headroom. */
struct ofpbuf *
ofpbuf_clone_with_headroom(const struct ofpbuf *buffer, size_t headroom)
{
    struct ofpbuf *new_buffer;

    new_buffer = ofpbuf_clone_data_with_headroom(ofpbuf_data(buffer),
                                                 ofpbuf_size(buffer),
                                                 headroom);
    if (buffer->frame) {
        uintptr_t data_delta
            = (char *)ofpbuf_data(new_buffer) - (char *)ofpbuf_data(buffer);

        new_buffer->frame = (char *) buffer->frame + data_delta;
    }
    new_buffer->l2_5_ofs = buffer->l2_5_ofs;
    new_buffer->l3_ofs = buffer->l3_ofs;
    new_buffer->l4_ofs = buffer->l4_ofs;

    return new_buffer;
}

/* Creates and returns a new ofpbuf that initially contains a copy of the
 * 'size' bytes of data starting at 'data' with no headroom or tailroom. */
struct ofpbuf *
ofpbuf_clone_data(const void *data, size_t size)
{
    return ofpbuf_clone_data_with_headroom(data, size, 0);
}

/* Creates and returns a new ofpbuf that initially contains 'headroom' bytes of
 * headroom followed by a copy of the 'size' bytes of data starting at
 * 'data'. */
struct ofpbuf *
ofpbuf_clone_data_with_headroom(const void *data, size_t size, size_t headroom)
{
    struct ofpbuf *b = ofpbuf_new_with_headroom(size, headroom);
    ofpbuf_put(b, data, size);
    return b;
}

static void
ofpbuf_copy__(struct ofpbuf *b, uint8_t *new_base,
              size_t new_headroom, size_t new_tailroom)
{
    const uint8_t *old_base = ofpbuf_base(b);
    size_t old_headroom = ofpbuf_headroom(b);
    size_t old_tailroom = ofpbuf_tailroom(b);
    size_t copy_headroom = MIN(old_headroom, new_headroom);
    size_t copy_tailroom = MIN(old_tailroom, new_tailroom);

    memcpy(&new_base[new_headroom - copy_headroom],
           &old_base[old_headroom - copy_headroom],
           copy_headroom + ofpbuf_size(b) + copy_tailroom);
}

/* Reallocates 'b' so that it has exactly 'new_headroom' and 'new_tailroom'
 * bytes of headroom and tailroom, respectively. */
static void
ofpbuf_resize__(struct ofpbuf *b, size_t new_headroom, size_t new_tailroom)
{
    void *new_base, *new_data;
    size_t new_allocated;

    new_allocated = new_headroom + ofpbuf_size(b) + new_tailroom;

    switch (b->source) {
    case OFPBUF_DPDK:
        OVS_NOT_REACHED();

    case OFPBUF_MALLOC:
        if (new_headroom == ofpbuf_headroom(b)) {
            new_base = xrealloc(ofpbuf_base(b), new_allocated);
        } else {
            new_base = xmalloc(new_allocated);
            ofpbuf_copy__(b, new_base, new_headroom, new_tailroom);
            free(ofpbuf_base(b));
        }
        break;

    case OFPBUF_STACK:
        OVS_NOT_REACHED();

    case OFPBUF_STUB:
        b->source = OFPBUF_MALLOC;
        new_base = xmalloc(new_allocated);
        ofpbuf_copy__(b, new_base, new_headroom, new_tailroom);
        break;

    default:
        OVS_NOT_REACHED();
    }

    b->allocated = new_allocated;
    ofpbuf_set_base(b, new_base);

    new_data = (char *) new_base + new_headroom;
    if (ofpbuf_data(b) != new_data) {
        if (b->frame) {
            uintptr_t data_delta = (char *) new_data - (char *) ofpbuf_data(b);

            b->frame = (char *) b->frame + data_delta;
        }
        ofpbuf_set_data(b, new_data);
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its tail end,
 * reallocating and copying its data if necessary.  Its headroom, if any, is
 * preserved. */
void
ofpbuf_prealloc_tailroom(struct ofpbuf *b, size_t size)
{
    if (size > ofpbuf_tailroom(b)) {
        ofpbuf_resize__(b, ofpbuf_headroom(b), MAX(size, 64));
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its head,
 * reallocating and copying its data if necessary.  Its tailroom, if any, is
 * preserved. */
void
ofpbuf_prealloc_headroom(struct ofpbuf *b, size_t size)
{
    if (size > ofpbuf_headroom(b)) {
        ofpbuf_resize__(b, MAX(size, 64), ofpbuf_tailroom(b));
    }
}

/* Trims the size of 'b' to fit its actual content, reducing its tailroom to
 * 0.  Its headroom, if any, is preserved.
 *
 * Buffers not obtained from malloc() are not resized, since that wouldn't save
 * any memory. */
void
ofpbuf_trim(struct ofpbuf *b)
{
    ovs_assert(b->source != OFPBUF_DPDK);

    if (b->source == OFPBUF_MALLOC
        && (ofpbuf_headroom(b) || ofpbuf_tailroom(b))) {
        ofpbuf_resize__(b, 0, 0);
    }
}

/* If 'b' is shorter than 'length' bytes, pads its tail out with zeros to that
 * length. */
void
ofpbuf_padto(struct ofpbuf *b, size_t length)
{
    if (ofpbuf_size(b) < length) {
        ofpbuf_put_zeros(b, length - ofpbuf_size(b));
    }
}

/* Shifts all of the data within the allocated space in 'b' by 'delta' bytes.
 * For example, a 'delta' of 1 would cause each byte of data to move one byte
 * forward (from address 'p' to 'p+1'), and a 'delta' of -1 would cause each
 * byte to move one byte backward (from 'p' to 'p-1'). */
void
ofpbuf_shift(struct ofpbuf *b, int delta)
{
    ovs_assert(delta > 0 ? delta <= ofpbuf_tailroom(b)
               : delta < 0 ? -delta <= ofpbuf_headroom(b)
               : true);

    if (delta != 0) {
        char *dst = (char *) ofpbuf_data(b) + delta;
        memmove(dst, ofpbuf_data(b), ofpbuf_size(b));
        ofpbuf_set_data(b, dst);
    }
}

/* Appends 'size' bytes of data to the tail end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * new data, which is left uninitialized. */
void *
ofpbuf_put_uninit(struct ofpbuf *b, size_t size)
{
    void *p;
    ofpbuf_prealloc_tailroom(b, size);
    p = ofpbuf_tail(b);
    ofpbuf_set_size(b, ofpbuf_size(b) + size);
    return p;
}

/* Appends 'size' zeroed bytes to the tail end of 'b'.  Data in 'b' is
 * reallocated and copied if necessary.  Returns a pointer to the first byte of
 * the data's location in the ofpbuf. */
void *
ofpbuf_put_zeros(struct ofpbuf *b, size_t size)
{
    void *dst = ofpbuf_put_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Appends the 'size' bytes of data in 'p' to the tail end of 'b'.  Data in 'b'
 * is reallocated and copied if necessary.  Returns a pointer to the first
 * byte of the data's location in the ofpbuf. */
void *
ofpbuf_put(struct ofpbuf *b, const void *p, size_t size)
{
    void *dst = ofpbuf_put_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Parses as many pairs of hex digits as possible (possibly separated by
 * spaces) from the beginning of 's', appending bytes for their values to 'b'.
 * Returns the first character of 's' that is not the first of a pair of hex
 * digits.  If 'n' is nonnull, stores the number of bytes added to 'b' in
 * '*n'. */
char *
ofpbuf_put_hex(struct ofpbuf *b, const char *s, size_t *n)
{
    size_t initial_size = ofpbuf_size(b);
    for (;;) {
        uint8_t byte;
        bool ok;

        s += strspn(s, " \t\r\n");
        byte = hexits_value(s, 2, &ok);
        if (!ok) {
            if (n) {
                *n = ofpbuf_size(b) - initial_size;
            }
            return CONST_CAST(char *, s);
        }

        ofpbuf_put(b, &byte, 1);
        s += 2;
    }
}

/* Reserves 'size' bytes of headroom so that they can be later allocated with
 * ofpbuf_push_uninit() without reallocating the ofpbuf. */
void
ofpbuf_reserve(struct ofpbuf *b, size_t size)
{
    ovs_assert(!ofpbuf_size(b));
    ofpbuf_prealloc_tailroom(b, size);
    ofpbuf_set_data(b, (char*)ofpbuf_data(b) + size);
}

/* Reserves 'size' bytes of headroom so that they can be later allocated with
 * ofpbuf_push_uninit() without reallocating the ofpbuf. */
void
ofpbuf_reserve_with_tailroom(struct ofpbuf *b, size_t headroom,
                             size_t tailroom)
{
    ovs_assert(!ofpbuf_size(b));
    ofpbuf_prealloc_tailroom(b, headroom + tailroom);
    ofpbuf_set_data(b, (char*)ofpbuf_data(b) + headroom);
}

/* Prefixes 'size' bytes to the head end of 'b', reallocating and copying its
 * data if necessary.  Returns a pointer to the first byte of the data's
 * location in the ofpbuf.  The new data is left uninitialized. */
void *
ofpbuf_push_uninit(struct ofpbuf *b, size_t size)
{
    ofpbuf_prealloc_headroom(b, size);
    ofpbuf_set_data(b, (char*)ofpbuf_data(b) - size);
    ofpbuf_set_size(b, ofpbuf_size(b) + size);
    return ofpbuf_data(b);
}

/* Prefixes 'size' zeroed bytes to the head end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * data's location in the ofpbuf. */
void *
ofpbuf_push_zeros(struct ofpbuf *b, size_t size)
{
    void *dst = ofpbuf_push_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Copies the 'size' bytes starting at 'p' to the head end of 'b', reallocating
 * and copying its data if necessary.  Returns a pointer to the first byte of
 * the data's location in the ofpbuf. */
void *
ofpbuf_push(struct ofpbuf *b, const void *p, size_t size)
{
    void *dst = ofpbuf_push_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Returns the data in 'b' as a block of malloc()'d memory and frees the buffer
 * within 'b'.  (If 'b' itself was dynamically allocated, e.g. with
 * ofpbuf_new(), then it should still be freed with, e.g., ofpbuf_delete().) */
void *
ofpbuf_steal_data(struct ofpbuf *b)
{
    void *p;
    ovs_assert(b->source != OFPBUF_DPDK);

    if (b->source == OFPBUF_MALLOC && ofpbuf_data(b) == ofpbuf_base(b)) {
        p = ofpbuf_data(b);
    } else {
        p = xmemdup(ofpbuf_data(b), ofpbuf_size(b));
        if (b->source == OFPBUF_MALLOC) {
            free(ofpbuf_base(b));
        }
    }
    ofpbuf_set_base(b, NULL);
    ofpbuf_set_data(b, NULL);
    return p;
}

/* Returns a string that describes some of 'b''s metadata plus a hex dump of up
 * to 'maxbytes' from the start of the buffer. */
char *
ofpbuf_to_string(const struct ofpbuf *b, size_t maxbytes)
{
    struct ds s;

    ds_init(&s);
    ds_put_format(&s, "size=%"PRIu32", allocated=%"PRIu32", head=%"PRIuSIZE", tail=%"PRIuSIZE"\n",
                  ofpbuf_size(b), b->allocated,
                  ofpbuf_headroom(b), ofpbuf_tailroom(b));
    ds_put_hex_dump(&s, ofpbuf_data(b), MIN(ofpbuf_size(b), maxbytes), 0, false);
    return ds_cstr(&s);
}

/* Removes each of the "struct ofpbuf"s on 'list' from the list and frees
 * them.  */
void
ofpbuf_list_delete(struct list *list)
{
    struct ofpbuf *b, *next;

    LIST_FOR_EACH_SAFE (b, next, list_node, list) {
        list_remove(&b->list_node);
        ofpbuf_delete(b);
    }
}

static inline void
ofpbuf_adjust_layer_offset(uint16_t *offset, int increment)
{
    if (*offset != UINT16_MAX) {
        *offset += increment;
    }
}

/* Adjust the size of the l2_5 portion of the ofpbuf, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
void *
ofpbuf_resize_l2_5(struct ofpbuf *b, int increment)
{
    if (increment >= 0) {
        ofpbuf_push_uninit(b, increment);
    } else {
        ofpbuf_pull(b, -increment);
    }

    b->frame = ofpbuf_data(b);
    /* Adjust layer offsets after l2_5. */
    ofpbuf_adjust_layer_offset(&b->l3_ofs, increment);
    ofpbuf_adjust_layer_offset(&b->l4_ofs, increment);

    return b->frame;
}

/* Adjust the size of the l2 portion of the ofpbuf, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
void *
ofpbuf_resize_l2(struct ofpbuf *b, int increment)
{
    ofpbuf_resize_l2_5(b, increment);
    ofpbuf_adjust_layer_offset(&b->l2_5_ofs, increment);
    return b->frame;
}
