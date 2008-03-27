/* Copyright (C) 2008 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "queue.h"
#include <assert.h>
#include "buffer.h"

static void check_queue(struct queue *q);

void
queue_init(struct queue *q)
{
    q->n = 0;
    q->head = NULL;
    q->tail = NULL;
}

void
queue_destroy(struct queue *q)
{
    struct buffer *cur, *next;
    for (cur = q->head; cur != NULL; cur = next) {
        next = cur->next;
        buffer_delete(cur);
    }
}

void
queue_clear(struct queue *q)
{
    queue_destroy(q);
    queue_init(q);
}

void
queue_advance_head(struct queue *q, struct buffer *next)
{
    assert(q->n);
    assert(q->head);
    q->head = next;
    if (q->head == NULL) {
        q->tail = NULL;
    }
    q->n--;
}

void
queue_push_tail(struct queue *q, struct buffer *b)
{
    check_queue(q);

    b->next = NULL;
    if (q->n++) {
        q->tail->next = b;
    } else {
        q->head = b;
    }
    q->tail = b;

    check_queue(q);
}

static void
check_queue(struct queue *q)
{
#if 0
    struct buffer *iter;
    size_t n;

    assert(q->n == 0
           ? q->head == NULL && q->tail == NULL
           : q->head != NULL && q->tail != NULL);

    n = 0;
    for (iter = q->head; iter != NULL; iter = iter->next) {
        n++;
        assert((iter->next != NULL) == (iter != q->tail));
    }
    assert(n == q->n);
#endif
}
