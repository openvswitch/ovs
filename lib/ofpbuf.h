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

#ifndef OFPBUF_H
#define OFPBUF_H 1

#include <stddef.h>
#include <stdint.h>
#include "list.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum ofpbuf_source {
    OFPBUF_MALLOC,              /* Obtained via malloc(). */
    OFPBUF_STACK,               /* Un-movable stack space or static buffer. */
    OFPBUF_STUB                 /* Starts on stack, may expand into heap. */
};

/* Buffer for holding arbitrary data.  An ofpbuf is automatically reallocated
 * as necessary if it grows too large for the available memory. */
struct ofpbuf {
    void *base;                 /* First byte of allocated space. */
    size_t allocated;           /* Number of bytes allocated. */
    enum ofpbuf_source source;  /* Source of memory allocated as 'base'. */

    void *data;                 /* First byte actually in use. */
    size_t size;                /* Number of bytes in use. */

    void *l2;                   /* Link-level header. */
    void *l2_5;                 /* MPLS label stack */
    void *l3;                   /* Network-level header. */
    void *l4;                   /* Transport-level header. */
    void *l7;                   /* Application data. */

    struct list list_node;      /* Private list element for use by owner. */
    void *private_p;            /* Private pointer for use by owner. */
};

void ofpbuf_use(struct ofpbuf *, void *, size_t);
void ofpbuf_use_stack(struct ofpbuf *, void *, size_t);
void ofpbuf_use_stub(struct ofpbuf *, void *, size_t);
void ofpbuf_use_const(struct ofpbuf *, const void *, size_t);

void ofpbuf_init(struct ofpbuf *, size_t);
void ofpbuf_uninit(struct ofpbuf *);
void *ofpbuf_get_uninit_pointer(struct ofpbuf *);
void ofpbuf_reinit(struct ofpbuf *, size_t);

struct ofpbuf *ofpbuf_new(size_t);
struct ofpbuf *ofpbuf_new_with_headroom(size_t, size_t headroom);
struct ofpbuf *ofpbuf_clone(const struct ofpbuf *);
struct ofpbuf *ofpbuf_clone_with_headroom(const struct ofpbuf *,
                                          size_t headroom);
struct ofpbuf *ofpbuf_clone_data(const void *, size_t);
struct ofpbuf *ofpbuf_clone_data_with_headroom(const void *, size_t,
                                               size_t headroom);
void ofpbuf_delete(struct ofpbuf *);

void *ofpbuf_at(const struct ofpbuf *, size_t offset, size_t size);
void *ofpbuf_at_assert(const struct ofpbuf *, size_t offset, size_t size);
void *ofpbuf_tail(const struct ofpbuf *);
void *ofpbuf_end(const struct ofpbuf *);

void *ofpbuf_put_uninit(struct ofpbuf *, size_t);
void *ofpbuf_put_zeros(struct ofpbuf *, size_t);
void *ofpbuf_put(struct ofpbuf *, const void *, size_t);
char *ofpbuf_put_hex(struct ofpbuf *, const char *s, size_t *n);
void ofpbuf_reserve(struct ofpbuf *, size_t);
void ofpbuf_reserve_with_tailroom(struct ofpbuf *b, size_t headroom,
                                  size_t tailroom);
void *ofpbuf_push_uninit(struct ofpbuf *b, size_t);
void *ofpbuf_push_zeros(struct ofpbuf *, size_t);
void *ofpbuf_push(struct ofpbuf *b, const void *, size_t);

size_t ofpbuf_headroom(const struct ofpbuf *);
size_t ofpbuf_tailroom(const struct ofpbuf *);
void ofpbuf_prealloc_headroom(struct ofpbuf *, size_t);
void ofpbuf_prealloc_tailroom(struct ofpbuf *, size_t);
void ofpbuf_trim(struct ofpbuf *);
void ofpbuf_padto(struct ofpbuf *, size_t);
void ofpbuf_shift(struct ofpbuf *, int);

void ofpbuf_clear(struct ofpbuf *);
void *ofpbuf_pull(struct ofpbuf *, size_t);
void *ofpbuf_try_pull(struct ofpbuf *, size_t);

void *ofpbuf_steal_data(struct ofpbuf *);

char *ofpbuf_to_string(const struct ofpbuf *, size_t maxbytes);

static inline struct ofpbuf *ofpbuf_from_list(const struct list *list)
{
    return CONTAINER_OF(list, struct ofpbuf, list_node);
}
void ofpbuf_list_delete(struct list *);

static inline bool
ofpbuf_equal(const struct ofpbuf *a, const struct ofpbuf *b)
{
    return a->size == b->size && memcmp(a->data, b->data, a->size) == 0;
}

#ifdef  __cplusplus
}
#endif

#endif /* ofpbuf.h */
