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
#include "openvswitch/ofpbuf.h"
#include <stdlib.h>
#include <string.h>
#include "openvswitch/dynamic-string.h"
#include "util.h"

static void
ofpbuf_init__(struct ofpbuf *b, size_t allocated, enum ofpbuf_source source)
{
    b->allocated = allocated;
    b->source = source;
    b->header = NULL;
    b->msg = NULL;
    ovs_list_poison(&b->list_node);
}

static void
ofpbuf_use__(struct ofpbuf *b, void *base, size_t allocated, size_t size,
             enum ofpbuf_source source)
{
    b->base = base;
    b->data = base;
    b->size = size;

    ofpbuf_init__(b, allocated, source);
}

/* Initializes 'b' as an empty ofpbuf that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should be the first byte of a region
 * obtained from malloc().  It will be freed (with free()) if 'b' is resized or
 * freed. */
static void
ofpbuf_use(struct ofpbuf *b, void *base, size_t allocated)
{
    ofpbuf_use__(b, base, allocated, 0, OFPBUF_MALLOC);
}

/* Converts ds into ofpbuf 'b'. 'b' contains the 'ds->allocated' bytes of
 * memory starting at 'ds->string'.  'ds' should not be modified any more.
 * The memory allocated for 'ds' will be freed (with free()) if 'b' is
 * resized or freed. */
void
ofpbuf_use_ds(struct ofpbuf *b, const struct ds *ds)
{
    ofpbuf_use__(b, ds->string, ds->allocated + 1, ds->length, OFPBUF_MALLOC);
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
    ofpbuf_use__(b, base, allocated, 0, OFPBUF_STACK);
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
    ofpbuf_use__(b, base, allocated, 0, OFPBUF_STUB);
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
    ofpbuf_use__(b, CONST_CAST(void *, data), size, size, OFPBUF_STACK);
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
            free(b->base);
        }
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
 * 'buffer->size' bytes of data starting at 'buffer->data' with no headroom or
 * tailroom. */
struct ofpbuf *
ofpbuf_clone(const struct ofpbuf *buffer)
{
    return ofpbuf_clone_with_headroom(buffer, 0);
}

/* Creates and returns a new ofpbuf whose data are copied from 'buffer'.   The
 * returned ofpbuf will additionally have 'headroom' bytes of headroom. */
struct ofpbuf *
ofpbuf_clone_with_headroom(const struct ofpbuf *b, size_t headroom)
{
    struct ofpbuf *new_buffer;

    new_buffer = ofpbuf_clone_data_with_headroom(b->data, b->size, headroom);
    if (b->header) {
        ptrdiff_t header_offset = (char *) b->header - (char *) b->data;

        new_buffer->header = (char *) new_buffer->data + header_offset;
    }
    if (b->msg) {
        ptrdiff_t msg_offset = (char *) b->msg - (char *) b->data;

        new_buffer->msg = (char *) new_buffer->data + msg_offset;
    }

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
    const uint8_t *old_base = b->base;
    size_t old_headroom = ofpbuf_headroom(b);
    size_t old_tailroom = ofpbuf_tailroom(b);
    size_t copy_headroom = MIN(old_headroom, new_headroom);
    size_t copy_tailroom = MIN(old_tailroom, new_tailroom);

    memcpy(&new_base[new_headroom - copy_headroom],
           &old_base[old_headroom - copy_headroom],
           copy_headroom + b->size + copy_tailroom);
}

/* Reallocates 'b' so that it has exactly 'new_headroom' and 'new_tailroom'
 * bytes of headroom and tailroom, respectively. */
static void
ofpbuf_resize__(struct ofpbuf *b, size_t new_headroom, size_t new_tailroom)
{
    void *new_base, *new_data;
    size_t new_allocated;

    new_allocated = new_headroom + b->size + new_tailroom;

    switch (b->source) {
    case OFPBUF_MALLOC:
        if (new_headroom == ofpbuf_headroom(b)) {
            new_base = xrealloc(b->base, new_allocated);
        } else {
            new_base = xmalloc(new_allocated);
            ofpbuf_copy__(b, new_base, new_headroom, new_tailroom);
            free(b->base);
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
    b->base = new_base;

    new_data = (char *) new_base + new_headroom;
    if (b->data != new_data) {
        if (b->header) {
            ptrdiff_t header_offset = (char *) b->header - (char *) b->data;

            b->header = (char *) new_data + header_offset;
        }
        if (b->msg) {
            ptrdiff_t msg_offset = (char *) b->msg - (char *) b->data;

            b->msg = (char *) new_data + msg_offset;
        }
        b->data = new_data;
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

/* Trims the size of 'b' to fit its actual content, reducing its headroom and
 * tailroom to 0, if any.
 *
 * Buffers not obtained from malloc() are not resized, since that wouldn't save
 * any memory.
 *
 * Caller needs to updates 'b->header' and 'b->msg' so that they point to the
 * same locations in the data.  (If they pointed into the tailroom or headroom
 * then they become invalid.)
 *
 */
void
ofpbuf_trim(struct ofpbuf *b)
{
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
    if (b->size < length) {
        ofpbuf_put_zeros(b, length - b->size);
    }
}

/* Shifts all of the data within the allocated space in 'b' by 'delta' bytes.
 * For example, a 'delta' of 1 would cause each byte of data to move one byte
 * forward (from address 'p' to 'p+1'), and a 'delta' of -1 would cause each
 * byte to move one byte backward (from 'p' to 'p-1').
 *
 * If used, user must make sure the 'header' and 'msg' pointers are updated
 * after shifting.
 */
void
ofpbuf_shift(struct ofpbuf *b, int delta)
{
    ovs_assert(delta > 0 ? delta <= ofpbuf_tailroom(b)
               : delta < 0 ? -delta <= ofpbuf_headroom(b)
               : true);

    if (delta != 0) {
        char *dst = (char *) b->data + delta;
        memmove(dst, b->data, b->size);
        b->data = dst;
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
    b->size += size;
    return p;
}

/* Appends 'size' zeroed bytes to the tail end of 'b'.  Data in 'b' is
 * reallocated and copied if necessary.  Returns a pointer to the first byte of
 * the data's location in the ofpbuf. */
void *
ofpbuf_put_zeros(struct ofpbuf *b, size_t size)
{
    void *dst = ofpbuf_put_uninit(b, size);
    nullable_memset(dst, 0, size);
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

/* Parses as many pairs of hex digits as possible (possibly separated by spaces
 * or periods) from the beginning of 's', appending bytes for their values to
 * 'b'.  Returns the first character of 's' that is not the first of a pair of
 * hex digits.  If 'n' is nonnull, stores the number of bytes added to 'b' in
 * '*n'. */
char *
ofpbuf_put_hex(struct ofpbuf *b, const char *s, size_t *n)
{
    size_t initial_size = b->size;
    for (;;) {
        uint8_t byte;
        bool ok;

        s += strspn(s, " .\t\r\n");
        byte = hexits_value(s, 2, &ok);
        if (!ok) {
            if (n) {
                *n = b->size - initial_size;
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
    ovs_assert(!b->size);
    ofpbuf_prealloc_tailroom(b, size);
    b->data = (char*)b->data + size;
}

/* Prefixes 'size' bytes to the head end of 'b', reallocating and copying its
 * data if necessary.  Returns a pointer to the first byte of the data's
 * location in the ofpbuf.  The new data is left uninitialized. */
void *
ofpbuf_push_uninit(struct ofpbuf *b, size_t size)
{
    ofpbuf_prealloc_headroom(b, size);
    b->data = (char*)b->data - size;
    b->size += size;
    return b->data;
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

/* Inserts the 'n' bytes of 'data' into 'b' starting at the given 'offset',
 * moving data forward as necessary to make room.
 *
 * 'data' must not point inside 'b'. */
void
ofpbuf_insert(struct ofpbuf *b, size_t offset, const void *data, size_t n)
{
    if (offset < b->size) {
        ofpbuf_put_uninit(b, n); /* b->size gets increased. */
        memmove((char *) b->data + offset + n, (char *) b->data + offset,
                b->size - offset - n);
        memcpy((char *) b->data + offset, data, n);
    } else {
        ovs_assert(offset == b->size);
        ofpbuf_put(b, data, n);
    }
}

/* Returns the data in 'b' as a block of malloc()'d memory and frees the buffer
 * within 'b'.  (If 'b' itself was dynamically allocated, e.g. with
 * ofpbuf_new(), then it should still be freed with, e.g., ofpbuf_delete().) */
void *
ofpbuf_steal_data(struct ofpbuf *b)
{
    void *p;

    if (b->source == OFPBUF_MALLOC && b->data == b->base) {
        p = b->data;
    } else {
        p = xmemdup(b->data, b->size);
        if (b->source == OFPBUF_MALLOC) {
            free(b->base);
        }
    }
    b->base = NULL;
    b->data = NULL;
    b->header = NULL;
    b->msg = NULL;
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
                  b->size, b->allocated,
                  ofpbuf_headroom(b), ofpbuf_tailroom(b));
    ds_put_hex_dump(&s, b->data, MIN(b->size, maxbytes), 0, false);
    return ds_cstr(&s);
}

/* Removes each of the "struct ofpbuf"s on 'list' from the list and frees
 * them.  */
void
ofpbuf_list_delete(struct ovs_list *list)
{
    struct ofpbuf *b;

    LIST_FOR_EACH_POP (b, list_node, list) {
        ofpbuf_delete(b);
    }
}
