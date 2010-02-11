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

#include <config.h>
#include "queue.h"
#include <assert.h>
#include "compiler.h"
#include "leak-checker.h"
#include "ofpbuf.h"

static void check_queue(struct ovs_queue *q);

/* Initializes 'q' as an empty packet queue. */
void
queue_init(struct ovs_queue *q)
{
    q->n = 0;
    q->head = NULL;
    q->tail = NULL;
}

/* Destroys 'q' and all of the packets that it contains. */
void
queue_destroy(struct ovs_queue *q)
{
    struct ofpbuf *cur, *next;
    for (cur = q->head; cur != NULL; cur = next) {
        next = cur->next;
        ofpbuf_delete(cur);
    }
}

/* Removes and destroys all of the packets in 'q', rendering it empty. */
void
queue_clear(struct ovs_queue *q)
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
queue_advance_head(struct ovs_queue *q, struct ofpbuf *next)
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
queue_push_tail(struct ovs_queue *q, struct ofpbuf *b)
{
    check_queue(q);
    leak_checker_claim(b);

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
queue_pop_head(struct ovs_queue *q)
{
    struct ofpbuf *head = q->head;
    queue_advance_head(q, head->next);
    return head;
}

/* Checks the internal integrity of 'q'.  For use in debugging. */
static void
check_queue(struct ovs_queue *q OVS_UNUSED)
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
