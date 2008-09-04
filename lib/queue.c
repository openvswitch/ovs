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

#include <config.h>
#include "queue.h"
#include <assert.h>
#include "ofpbuf.h"

static void check_queue(struct ofp_queue *q);

/* Initializes 'q' as an empty packet queue. */
void
queue_init(struct ofp_queue *q)
{
    q->n = 0;
    q->head = NULL;
    q->tail = NULL;
}

/* Destroys 'q' and all of the packets that it contains. */
void
queue_destroy(struct ofp_queue *q)
{
    struct ofpbuf *cur, *next;
    for (cur = q->head; cur != NULL; cur = next) {
        next = cur->next;
        ofpbuf_delete(cur);
    }
}

/* Removes and destroys all of the packets in 'q', rendering it empty. */
void
queue_clear(struct ofp_queue *q)
{
    queue_destroy(q);
    queue_init(q);
}

/* Advances the first packet in 'q' from 'q->head' to 'next', which should be
 * the second packet in the queue.
 *
 * The odd, unsafe interface here allows the first packet in the queue to be
 * passed to a function for possible consumption (and destruction) and only
 * dropped from the queue if that function actually accepts it. */
void
queue_advance_head(struct ofp_queue *q, struct ofpbuf *next)
{
    assert(q->n);
    assert(q->head);
    q->head = next;
    if (q->head == NULL) {
        q->tail = NULL;
    }
    q->n--;
}

/* Appends 'b' to the tail of 'q'. */
void
queue_push_tail(struct ofp_queue *q, struct ofpbuf *b)
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

/* Removes the first buffer from 'q', which must not be empty, and returns
 * it.  The caller must free the buffer (with ofpbuf_delete()) when it is no
 * longer needed. */
struct ofpbuf *
queue_pop_head(struct ofp_queue *q)
{
    struct ofpbuf *head = q->head;
    queue_advance_head(q, head->next);
    return head;
}

/* Checks the internal integrity of 'q'.  For use in debugging. */
static void
check_queue(struct ofp_queue *q)
{
#if 0
    struct ofpbuf *iter;
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
