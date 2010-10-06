/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

#ifdef  __cplusplus
extern "C" {
#endif

/* Buffer for holding arbitrary data.  An ofpbuf is automatically reallocated
 * as necessary if it grows too large for the available memory. */
struct ofpbuf {
    void *base;                 /* First byte of area malloc()'d area. */
    size_t allocated;           /* Number of bytes allocated. */

    void *data;                 /* First byte actually in use. */
    size_t size;                /* Number of bytes in use. */

    void *l2;                   /* Link-level header. */
    void *l3;                   /* Network-level header. */
    void *l4;                   /* Transport-level header. */
    void *l7;                   /* Application data. */

    struct ofpbuf *next;        /* Next in a list of ofpbufs. */
    void *private_p;            /* Private pointer for use by owner. */
};

void ofpbuf_use(struct ofpbuf *, void *, size_t);

void ofpbuf_init(struct ofpbuf *, size_t);
void ofpbuf_uninit(struct ofpbuf *);
void ofpbuf_reinit(struct ofpbuf *, size_t);

struct ofpbuf *ofpbuf_new(size_t);
struct ofpbuf *ofpbuf_new_with_headroom(size_t, size_t headroom);
struct ofpbuf *ofpbuf_clone(const struct ofpbuf *);
struct ofpbuf *ofpbuf_clone_with_headroom(const struct ofpbuf *,
                                          size_t headroom);
struct ofpbuf *ofpbuf_clone_data(const void *, size_t);
void ofpbuf_delete(struct ofpbuf *);

void *ofpbuf_at(const struct ofpbuf *, size_t offset, size_t size);
void *ofpbuf_at_assert(const struct ofpbuf *, size_t offset, size_t size);
void *ofpbuf_tail(const struct ofpbuf *);
void *ofpbuf_end(const struct ofpbuf *);

void *ofpbuf_put_uninit(struct ofpbuf *, size_t);
void *ofpbuf_put_zeros(struct ofpbuf *, size_t);
void *ofpbuf_put(struct ofpbuf *, const void *, size_t);
void ofpbuf_reserve(struct ofpbuf *, size_t);
void *ofpbuf_push_uninit(struct ofpbuf *b, size_t);
void *ofpbuf_push_zeros(struct ofpbuf *, size_t);
void *ofpbuf_push(struct ofpbuf *b, const void *, size_t);

size_t ofpbuf_headroom(const struct ofpbuf *);
size_t ofpbuf_tailroom(const struct ofpbuf *);
void ofpbuf_prealloc_headroom(struct ofpbuf *, size_t);
void ofpbuf_prealloc_tailroom(struct ofpbuf *, size_t);
void ofpbuf_trim(struct ofpbuf *);

void ofpbuf_clear(struct ofpbuf *);
void *ofpbuf_pull(struct ofpbuf *, size_t);
void *ofpbuf_try_pull(struct ofpbuf *, size_t);

char *ofpbuf_to_string(const struct ofpbuf *, size_t maxbytes);

#ifdef  __cplusplus
}
#endif

#endif /* ofpbuf.h */
