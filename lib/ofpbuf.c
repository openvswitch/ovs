/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "dynamic-string.h"
#include "util.h"

static void
ofpbuf_use__(struct ofpbuf *b, void *base, size_t allocated,
             enum ofpbuf_source source)
{
    b->base = b->data = base;
    b->allocated = allocated;
    b->source = source;
    b->size = 0;
    b->l2 = b->l3 = b->l4 = b->l7 = NULL;
    list_poison(&b->list_node);
    b->private_p = NULL;
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
 * for 32- or 64-bit data.  OFPBUF_STACK_BUFFER is a convenient way to do so.
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
 * be static or malloc()'d memory.  But stack space is the most common usen
 * case.)
 *
 * 'base' should be appropriately aligned.  Using an array of uint32_t or
 * uint64_t for the buffer is a reasonable way to ensure appropriate alignment
 * for 32- or 64-bit data.  OFPBUF_STACK_BUFFER is a convenient way to do so.
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
    b->size = size;
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
    if (b && b->source == OFPBUF_MALLOC) {
        free(b->base);
    }
}

/* Returns a pointer that may be passed to free() to accomplish the same thing
 * as ofpbuf_uninit(b).  The return value is a null pointer if ofpbuf_uninit()
 * would not free any memory. */
void *
ofpbuf_get_uninit_pointer(struct ofpbuf *b)
{
    return b && b->source == OFPBUF_MALLOC ? b->base : NULL;
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
ofpbuf_clone_with_headroom(const struct ofpbuf *buffer, size_t headroom)
{
    struct ofpbuf *new_buffer;
    uintptr_t data_delta;

    new_buffer = ofpbuf_clone_data_with_headroom(buffer->data, buffer->size,
                                                 headroom);
    data_delta = (char *) new_buffer->data - (char *) buffer->data;

    if (buffer->l2) {
        new_buffer->l2 = (char *) buffer->l2 + data_delta;
    }
    if (buffer->l3) {
        new_buffer->l3 = (char *) buffer->l3 + data_delta;
    }
    if (buffer->l4) {
        new_buffer->l4 = (char *) buffer->l4 + data_delta;
    }
    if (buffer->l7) {
        new_buffer->l7 = (char *) buffer->l7 + data_delta;
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

/* Frees memory that 'b' points to, as well as 'b' itself. */
void
ofpbuf_delete(struct ofpbuf *b)
{
    if (b) {
        ofpbuf_uninit(b);
        free(b);
    }
}

/* Returns the number of bytes of headroom in 'b', that is, the number of bytes
 * of unused space in ofpbuf 'b' before the data that is in use.  (Most
 * commonly, the data in a ofpbuf is at its beginning, and thus the ofpbuf's
 * headroom is 0.) */
size_t
ofpbuf_headroom(const struct ofpbuf *b)
{
    return (char*)b->data - (char*)b->base;
}

/* Returns the number of bytes that may be appended to the tail end of ofpbuf
 * 'b' before the ofpbuf must be reallocated. */
size_t
ofpbuf_tailroom(const struct ofpbuf *b)
{
    return (char*)ofpbuf_end(b) - (char*)ofpbuf_tail(b);
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
        NOT_REACHED();

    case OFPBUF_STUB:
        b->source = OFPBUF_MALLOC;
        new_base = xmalloc(new_allocated);
        ofpbuf_copy__(b, new_base, new_headroom, new_tailroom);
        break;

    default:
        NOT_REACHED();
    }

    b->allocated = new_allocated;
    b->base = new_base;

    new_data = (char *) new_base + new_headroom;
    if (b->data != new_data) {
        uintptr_t data_delta = (char *) new_data - (char *) b->data;
        b->data = new_data;
        if (b->l2) {
            b->l2 = (char *) b->l2 + data_delta;
        }
        if (b->l3) {
            b->l3 = (char *) b->l3 + data_delta;
        }
        if (b->l4) {
            b->l4 = (char *) b->l4 + data_delta;
        }
        if (b->l7) {
            b->l7 = (char *) b->l7 + data_delta;
        }
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
    size_t initial_size = b->size;
    for (;;) {
        uint8_t byte;
        bool ok;

        s += strspn(s, " ");
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
    assert(!b->size);
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

/* If 'b' contains at least 'offset + size' bytes of data, returns a pointer to
 * byte 'offset'.  Otherwise, returns a null pointer. */
void *
ofpbuf_at(const struct ofpbuf *b, size_t offset, size_t size)
{
    return offset + size <= b->size ? (char *) b->data + offset : NULL;
}

/* Returns a pointer to byte 'offset' in 'b', which must contain at least
 * 'offset + size' bytes of data. */
void *
ofpbuf_at_assert(const struct ofpbuf *b, size_t offset, size_t size)
{
    assert(offset + size <= b->size);
    return ((char *) b->data) + offset;
}

/* Returns the byte following the last byte of data in use in 'b'. */
void *
ofpbuf_tail(const struct ofpbuf *b)
{
    return (char *) b->data + b->size;
}

/* Returns the byte following the last byte allocated for use (but not
 * necessarily in use) by 'b'. */
void *
ofpbuf_end(const struct ofpbuf *b)
{
    return (char *) b->base + b->allocated;
}

/* Clears any data from 'b'. */
void
ofpbuf_clear(struct ofpbuf *b)
{
    b->data = b->base;
    b->size = 0;
}

/* Removes 'size' bytes from the head end of 'b', which must contain at least
 * 'size' bytes of data.  Returns the first byte of data removed. */
void *
ofpbuf_pull(struct ofpbuf *b, size_t size)
{
    void *data = b->data;
    assert(b->size >= size);
    b->data = (char*)b->data + size;
    b->size -= size;
    return data;
}

/* If 'b' has at least 'size' bytes of data, removes that many bytes from the
 * head end of 'b' and returns the first byte removed.  Otherwise, returns a
 * null pointer without modifying 'b'. */
void *
ofpbuf_try_pull(struct ofpbuf *b, size_t size)
{
    return b->size >= size ? ofpbuf_pull(b, size) : NULL;
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
    b->base = b->data = NULL;
    return p;
}

/* Returns a string that describes some of 'b''s metadata plus a hex dump of up
 * to 'maxbytes' from the start of the buffer. */
char *
ofpbuf_to_string(const struct ofpbuf *b, size_t maxbytes)
{
    struct ds s;

    ds_init(&s);
    ds_put_format(&s, "size=%zu, allocated=%zu, head=%zu, tail=%zu\n",
                  b->size, b->allocated,
                  ofpbuf_headroom(b), ofpbuf_tailroom(b));
    ds_put_hex_dump(&s, b->data, MIN(b->size, maxbytes), 0, false);
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
