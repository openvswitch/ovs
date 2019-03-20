/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015, 2016 Nicira, Inc.
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

#ifndef OPENVSWITCH_OFPBUF_H
#define OPENVSWITCH_OFPBUF_H 1

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/util.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum OVS_PACKED_ENUM ofpbuf_source {
    OFPBUF_MALLOC,              /* Obtained via malloc(). */
    OFPBUF_STACK,               /* Un-movable stack space or static buffer. */
    OFPBUF_STUB,                /* Starts on stack, may expand into heap. */
};

/* Buffer for holding arbitrary data.  An ofpbuf is automatically reallocated
 * as necessary if it grows too large for the available memory.
 *
 * 'header' and 'msg' conventions:
 *
 * OpenFlow messages: 'header' points to the start of the OpenFlow
 *    header, while 'msg' is the OpenFlow msg body.
 *    When parsing, the 'data' will move past these, as data is being
 *    pulled from the OpenFlow message.
 *
 *    Caution: buffer manipulation of 'struct ofpbuf' must always update
 *             the 'header' and 'msg' pointers.
 *
 *
 * Actions: When encoding OVS action lists, the 'header' is used
 *    as a pointer to the beginning of the current action (see ofpact_put()).
 *
 * rconn: Reuses 'header' as a private pointer while queuing.
 */
struct ofpbuf {
    void *base;                 /* First byte of allocated space. */
    void *data;                 /* First byte actually in use. */
    uint32_t size;              /* Number of bytes in use. */
    uint32_t allocated;         /* Number of bytes allocated. */

    void *header;               /* OpenFlow header. */
    void *msg;                  /* message's body */
    struct ovs_list list_node;  /* Private list element for use by owner. */
    enum ofpbuf_source source;  /* Source of memory allocated as 'base'. */
};

/* An initializer for a struct ofpbuf that will be initially empty and uses the
 * space in STUB (which should be an array) as a stub.  This is the initializer
 * form of ofpbuf_use_stub().
 *
 * Usage example:
 *
 *     uint64_t stub[1024 / 8];         <-- 1 kB stub aligned for 64-bit data.
 *     struct ofpbuf ofpbuf = OFPBUF_STUB_INITIALIZER(stub);
 */
#define OFPBUF_STUB_INITIALIZER(STUB) {         \
        .base = (STUB),                         \
        .data = (STUB),                         \
        .size = 0,                              \
        .allocated = sizeof (STUB),             \
        .header = NULL,                         \
        .msg = NULL,                            \
        .list_node = OVS_LIST_POISON,           \
        .source = OFPBUF_STUB,                  \
    }

/* An initializer for a struct ofpbuf whose data starts at DATA and continues
 * for SIZE bytes.  This is appropriate for an ofpbuf that will be used to
 * inspect existing data, without moving it around or reallocating it, and
 * generally without modifying it at all.  This is the initializer form of
 * ofpbuf_use_const().
 */
static inline struct ofpbuf
ofpbuf_const_initializer(const void *data, uint32_t size)
{
    return (struct ofpbuf) {
        .base = CONST_CAST(void *, data),
        .data = CONST_CAST(void *, data),
        .size = size,
        .allocated = size,
        .header = NULL,
        .msg = NULL,
        .list_node = OVS_LIST_POISON,
        .source = OFPBUF_STACK,
    };
}

void ofpbuf_use_ds(struct ofpbuf *, const struct ds *);
void ofpbuf_use_stack(struct ofpbuf *, void *, size_t);
void ofpbuf_use_stub(struct ofpbuf *, void *, size_t);
void ofpbuf_use_const(struct ofpbuf *, const void *, size_t);

void ofpbuf_init(struct ofpbuf *, size_t);
void ofpbuf_uninit(struct ofpbuf *);
void ofpbuf_reinit(struct ofpbuf *, size_t);

struct ofpbuf *ofpbuf_new(size_t);
struct ofpbuf *ofpbuf_new_with_headroom(size_t, size_t headroom);
struct ofpbuf *ofpbuf_clone(const struct ofpbuf *);
struct ofpbuf *ofpbuf_clone_with_headroom(const struct ofpbuf *,
                                          size_t headroom);
struct ofpbuf *ofpbuf_clone_data(const void *, size_t);
struct ofpbuf *ofpbuf_clone_data_with_headroom(const void *, size_t,
                                               size_t headroom);
static inline void ofpbuf_delete(struct ofpbuf *);

static inline void *ofpbuf_at(const struct ofpbuf *, size_t offset,
                              size_t size);
static inline void *ofpbuf_at_assert(const struct ofpbuf *, size_t offset,
                                     size_t size);
static inline void *ofpbuf_tail(const struct ofpbuf *);
static inline void *ofpbuf_end(const struct ofpbuf *);

void *ofpbuf_put_uninit(struct ofpbuf *, size_t);
void *ofpbuf_put_zeros(struct ofpbuf *, size_t);
void *ofpbuf_put(struct ofpbuf *, const void *, size_t);
char *ofpbuf_put_hex(struct ofpbuf *, const char *s, size_t *n);
void ofpbuf_reserve(struct ofpbuf *, size_t);
void *ofpbuf_push_uninit(struct ofpbuf *b, size_t);
void *ofpbuf_push_zeros(struct ofpbuf *, size_t);
void *ofpbuf_push(struct ofpbuf *b, const void *, size_t);
void ofpbuf_insert(struct ofpbuf *b, size_t offset, const void *data, size_t);

static inline size_t ofpbuf_headroom(const struct ofpbuf *);
static inline size_t ofpbuf_tailroom(const struct ofpbuf *);
static inline size_t ofpbuf_msgsize(const struct ofpbuf *);
void ofpbuf_prealloc_headroom(struct ofpbuf *, size_t);
void ofpbuf_prealloc_tailroom(struct ofpbuf *, size_t);
void ofpbuf_trim(struct ofpbuf *);
void ofpbuf_padto(struct ofpbuf *, size_t);
void ofpbuf_shift(struct ofpbuf *, int);

static inline void ofpbuf_clear(struct ofpbuf *);
static inline void *ofpbuf_pull(struct ofpbuf *, size_t);
static inline void *ofpbuf_try_pull(struct ofpbuf *, size_t);

void *ofpbuf_steal_data(struct ofpbuf *);

char *ofpbuf_to_string(const struct ofpbuf *, size_t maxbytes);
static inline struct ofpbuf *ofpbuf_from_list(const struct ovs_list *);
void ofpbuf_list_delete(struct ovs_list *);
static inline bool ofpbuf_equal(const struct ofpbuf *, const struct ofpbuf *);
static inline bool ofpbuf_oversized(const struct ofpbuf *ofpacts);


/* Frees memory that 'b' points to, as well as 'b' itself. */
static inline void ofpbuf_delete(struct ofpbuf *b)
{
    if (b) {
        ofpbuf_uninit(b);
        free(b);
    }
}

/* If 'b' contains at least 'offset + size' bytes of data, returns a pointer to
 * byte 'offset'.  Otherwise, returns a null pointer. */
static inline void *ofpbuf_at(const struct ofpbuf *b, size_t offset,
                              size_t size)
{
    return offset + size <= b->size ? (char *) b->data + offset : NULL;
}

/* Returns a pointer to byte 'offset' in 'b', which must contain at least
 * 'offset + size' bytes of data. */
static inline void *ofpbuf_at_assert(const struct ofpbuf *b, size_t offset,
                                     size_t size)
{
    ovs_assert(offset + size <= b->size);
    return ((char *) b->data) + offset;
}

/* Returns a pointer to byte following the last byte of data in use in 'b'. */
static inline void *ofpbuf_tail(const struct ofpbuf *b)
{
    return (char *) b->data + b->size;
}

/* Returns a pointer to byte following the last byte allocated for use (but
 * not necessarily in use) in 'b'. */
static inline void *ofpbuf_end(const struct ofpbuf *b)
{
    return (char *) b->base + b->allocated;
}

/* Returns the number of bytes of headroom in 'b', that is, the number of bytes
 * of unused space in ofpbuf 'b' before the data that is in use.  (Most
 * commonly, the data in a ofpbuf is at its beginning, and thus the ofpbuf's
 * headroom is 0.) */
static inline size_t ofpbuf_headroom(const struct ofpbuf *b)
{
    return (char*)b->data - (char*)b->base;
}

/* Returns the number of bytes that may be appended to the tail end of ofpbuf
 * 'b' before the ofpbuf must be reallocated. */
static inline size_t ofpbuf_tailroom(const struct ofpbuf *b)
{
    return (char*)ofpbuf_end(b) - (char*)ofpbuf_tail(b);
}

/* Returns the number of bytes from 'b->header' to 'b->msg', that is, the
 * length of 'b''s header. */
static inline size_t
ofpbuf_headersize(const struct ofpbuf *b)
{
    return (char *)b->msg - (char *)b->header;
}

/* Returns the number of bytes from 'b->msg' to 'b->data + b->size', that is,
 * the length of the used space in 'b' starting from 'msg'. */
static inline size_t
ofpbuf_msgsize(const struct ofpbuf *b)
{
    return (char *)ofpbuf_tail(b) - (char *)b->msg;
}

/* Clears any data from 'b'. */
static inline void ofpbuf_clear(struct ofpbuf *b)
{
    b->data = b->base;
    b->size = 0;
}

/* Removes 'size' bytes from the head end of 'b', which must contain at least
 * 'size' bytes of data.  Returns the first byte of data removed. */
static inline void *ofpbuf_pull(struct ofpbuf *b, size_t size)
{
    ovs_assert(b->size >= size);
    void *data = b->data;
    b->data = (char*)b->data + size;
    b->size = b->size - size;
    return data;
}

/* If 'b' has at least 'size' bytes of data, removes that many bytes from the
 * head end of 'b' and returns the first byte removed.  Otherwise, returns a
 * null pointer without modifying 'b'. */
static inline void *ofpbuf_try_pull(struct ofpbuf *b, size_t size)
{
    return b->size >= size ? ofpbuf_pull(b, size) : NULL;
}

static inline struct ofpbuf *ofpbuf_from_list(const struct ovs_list *list)
{
    return CONTAINER_OF(list, struct ofpbuf, list_node);
}

static inline bool ofpbuf_equal(const struct ofpbuf *a, const struct ofpbuf *b)
{
    return a->size == b->size &&
           memcmp(a->data, b->data, a->size) == 0;
}

static inline bool ofpbuf_oversized(const struct ofpbuf *ofpacts)
{
    return (char *)ofpbuf_tail(ofpacts) - (char *)ofpacts->header > UINT16_MAX;
}

#ifdef  __cplusplus
}
#endif

#endif /* ofpbuf.h */
