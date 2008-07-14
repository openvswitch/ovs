/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#ifndef BUFFER_H
#define BUFFER_H 1

#include <stddef.h>

/* Buffer for holding arbitrary data.  A buffer is automatically reallocated as
 * necessary if it grows too large for the available memory. */
struct buffer {
    void *base;                 /* First byte of area malloc()'d area. */
    size_t allocated;           /* Number of bytes allocated. */

    void *data;                 /* First byte actually in use. */
    size_t size;                /* Number of bytes in use. */

    void *l2;                   /* Link-level header. */
    void *l3;                   /* Network-level header. */
    void *l4;                   /* Transport-level header. */
    void *l7;                   /* Application data. */

    struct buffer *next;        /* Next in a list of buffers. */
};

void buffer_use(struct buffer *, void *, size_t);

void buffer_init(struct buffer *, size_t);
void buffer_uninit(struct buffer *);
void buffer_reinit(struct buffer *, size_t);

struct buffer *buffer_new(size_t);
struct buffer *buffer_clone(const struct buffer *);
void buffer_delete(struct buffer *);

void *buffer_at(const struct buffer *, size_t offset, size_t size);
void *buffer_at_assert(const struct buffer *, size_t offset, size_t size);
void *buffer_tail(const struct buffer *);
void *buffer_end(const struct buffer *);

void *buffer_put_uninit(struct buffer *, size_t);
void *buffer_put(struct buffer *, const void *, size_t);
void buffer_reserve(struct buffer *, size_t);
void *buffer_push_uninit(struct buffer *b, size_t);
void *buffer_push(struct buffer *b, const void *, size_t);

size_t buffer_headroom(struct buffer *);
size_t buffer_tailroom(struct buffer *);
void buffer_prealloc_headroom(struct buffer *, size_t);
void buffer_prealloc_tailroom(struct buffer *, size_t);

void buffer_clear(struct buffer *);
void *buffer_pull(struct buffer *, size_t);
void *buffer_try_pull(struct buffer *, size_t);

#endif /* buffer.h */
