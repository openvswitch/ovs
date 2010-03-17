/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#ifndef QUEUE_H
#define QUEUE_H 1

#include <stdbool.h>

/* Packet queue. */
struct ovs_queue {
    int n;                      /* Number of queued packets. */
    struct ofpbuf *head;        /* First queued packet, null if n == 0. */
    struct ofpbuf *tail;        /* Last queued packet, null if n == 0. */
};

void queue_init(struct ovs_queue *);
void queue_destroy(struct ovs_queue *);
void queue_clear(struct ovs_queue *);
void queue_advance_head(struct ovs_queue *, struct ofpbuf *next);
void queue_push_tail(struct ovs_queue *, struct ofpbuf *);
struct ofpbuf *queue_pop_head(struct ovs_queue *);

static inline bool queue_is_empty(const struct ovs_queue *q)
{
    return q->n == 0;
}

#endif /* queue.h */
