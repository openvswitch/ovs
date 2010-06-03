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
#include "pinsched.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "port-array.h"
#include "queue.h"
#include "random.h"
#include "rconn.h"
#include "status.h"
#include "timeval.h"
#include "vconn.h"

struct pinsched {
    /* Client-supplied parameters. */
    int rate_limit;           /* Packets added to bucket per second. */
    int burst_limit;          /* Maximum token bucket size, in packets. */

    /* One queue per physical port. */
    struct port_array queues;   /* Array of "struct ovs_queue *". */
    int n_queued;               /* Sum over queues[*].n. */
    unsigned int last_tx_port;  /* Last port checked in round-robin. */

    /* Token bucket.
     *
     * It costs 1000 tokens to send a single packet_in message.  A single token
     * per message would be more straightforward, but this choice lets us avoid
     * round-off error in refill_bucket()'s calculation of how many tokens to
     * add to the bucket, since no division step is needed. */
    long long int last_fill;    /* Time at which we last added tokens. */
    int tokens;                 /* Current number of tokens. */

    /* Transmission queue. */
    int n_txq;                  /* No. of packets waiting in rconn for tx. */

    /* Statistics reporting. */
    unsigned long long n_normal;        /* # txed w/o rate limit queuing. */
    unsigned long long n_limited;       /* # queued for rate limiting. */
    unsigned long long n_queue_dropped; /* # dropped due to queue overflow. */

    /* Switch status. */
    struct status_category *ss_cat;
};

static struct ofpbuf *
dequeue_packet(struct pinsched *ps, struct ovs_queue *q,
               unsigned int port_no)
{
    struct ofpbuf *packet = queue_pop_head(q);
    if (!q->n) {
        free(q);
        port_array_delete(&ps->queues, port_no);
    }
    ps->n_queued--;
    return packet;
}

/* Drop a packet from the longest queue in 'ps'. */
static void
drop_packet(struct pinsched *ps)
{
    struct ovs_queue *longest;  /* Queue currently selected as longest. */
    int n_longest;              /* # of queues of same length as 'longest'. */
    unsigned int longest_port_no;
    unsigned int port_no;
    struct ovs_queue *q;

    ps->n_queue_dropped++;

    longest = port_array_first(&ps->queues, &port_no);
    longest_port_no = port_no;
    n_longest = 1;
    while ((q = port_array_next(&ps->queues, &port_no)) != NULL) {
        if (longest->n < q->n) {
            longest = q;
            n_longest = 1;
        } else if (longest->n == q->n) {
            n_longest++;

            /* Randomly select one of the longest queues, with a uniform
             * distribution (Knuth algorithm 3.4.2R). */
            if (!random_range(n_longest)) {
                longest = q;
                longest_port_no = port_no;
            }
        }
    }

    /* FIXME: do we want to pop the tail instead? */
    ofpbuf_delete(dequeue_packet(ps, longest, longest_port_no));
}

/* Remove and return the next packet to transmit (in round-robin order). */
static struct ofpbuf *
get_tx_packet(struct pinsched *ps)
{
    struct ovs_queue *q = port_array_next(&ps->queues, &ps->last_tx_port);
    if (!q) {
        q = port_array_first(&ps->queues, &ps->last_tx_port);
    }
    return dequeue_packet(ps, q, ps->last_tx_port);
}

/* Add tokens to the bucket based on elapsed time. */
static void
refill_bucket(struct pinsched *ps)
{
    long long int now = time_msec();
    long long int tokens = (now - ps->last_fill) * ps->rate_limit + ps->tokens;
    if (tokens >= 1000) {
        ps->last_fill = now;
        ps->tokens = MIN(tokens, ps->burst_limit * 1000);
    }
}

/* Attempts to remove enough tokens from 'ps' to transmit a packet.  Returns
 * true if successful, false otherwise.  (In the latter case no tokens are
 * removed.) */
static bool
get_token(struct pinsched *ps)
{
    if (ps->tokens >= 1000) {
        ps->tokens -= 1000;
        return true;
    } else {
        return false;
    }
}

void
pinsched_send(struct pinsched *ps, uint16_t port_no,
              struct ofpbuf *packet, pinsched_tx_cb *cb, void *aux)
{
    if (!ps) {
        cb(packet, aux);
    } else if (!ps->n_queued && get_token(ps)) {
        /* In the common case where we are not constrained by the rate limit,
         * let the packet take the normal path. */
        ps->n_normal++;
        cb(packet, aux);
    } else {
        /* Otherwise queue it up for the periodic callback to drain out. */
        struct ovs_queue *q;

        /* We are called with a buffer obtained from dpif_recv() that has much
         * more allocated space than actual content most of the time.  Since
         * we're going to store the packet for some time, free up that
         * otherwise wasted space. */
        ofpbuf_trim(packet);

        if (ps->n_queued >= ps->burst_limit) {
            drop_packet(ps);
        }
        q = port_array_get(&ps->queues, port_no);
        if (!q) {
            q = xmalloc(sizeof *q);
            queue_init(q);
            port_array_set(&ps->queues, port_no, q);
        }
        queue_push_tail(q, packet);
        ps->n_queued++;
        ps->n_limited++;
    }
}

static void
pinsched_status_cb(struct status_reply *sr, void *ps_)
{
    struct pinsched *ps = ps_;

    status_reply_put(sr, "normal=%llu", ps->n_normal);
    status_reply_put(sr, "limited=%llu", ps->n_limited);
    status_reply_put(sr, "queue-dropped=%llu", ps->n_queue_dropped);
}

void
pinsched_run(struct pinsched *ps, pinsched_tx_cb *cb, void *aux)
{
    if (ps) {
        int i;

        /* Drain some packets out of the bucket if possible, but limit the
         * number of iterations to allow other code to get work done too. */
        refill_bucket(ps);
        for (i = 0; ps->n_queued && get_token(ps) && i < 50; i++) {
            cb(get_tx_packet(ps), aux);
        }
    }
}

void
pinsched_wait(struct pinsched *ps)
{
    if (ps && ps->n_queued) {
        if (ps->tokens >= 1000) {
            /* We can transmit more packets as soon as we're called again. */
            poll_immediate_wake();
        } else {
            /* We have to wait for the bucket to re-fill.  We could calculate
             * the exact amount of time here for increased smoothness. */
            poll_timer_wait(TIME_UPDATE_INTERVAL / 2);
        }
    }
}

/* Creates and returns a scheduler for sending packet-in messages. */
struct pinsched *
pinsched_create(int rate_limit, int burst_limit, struct switch_status *ss)
{
    struct pinsched *ps;

    ps = xzalloc(sizeof *ps);
    port_array_init(&ps->queues);
    ps->n_queued = 0;
    ps->last_tx_port = PORT_ARRAY_SIZE;
    ps->last_fill = time_msec();
    ps->tokens = rate_limit * 100;
    ps->n_txq = 0;
    ps->n_normal = 0;
    ps->n_limited = 0;
    ps->n_queue_dropped = 0;
    pinsched_set_limits(ps, rate_limit, burst_limit);

    if (ss) {
        ps->ss_cat = switch_status_register(ss, "rate-limit",
                                            pinsched_status_cb, ps);
    }

    return ps;
}

void
pinsched_destroy(struct pinsched *ps)
{
    if (ps) {
        struct ovs_queue *queue;
        unsigned int port_no;

        PORT_ARRAY_FOR_EACH (queue, &ps->queues, port_no) {
            queue_destroy(queue);
            free(queue);
        }
        port_array_destroy(&ps->queues);
        switch_status_unregister(ps->ss_cat);
        free(ps);
    }
}

void
pinsched_get_limits(const struct pinsched *ps,
                    int *rate_limit, int *burst_limit)
{
    *rate_limit = ps->rate_limit;
    *burst_limit = ps->burst_limit;
}

void
pinsched_set_limits(struct pinsched *ps, int rate_limit, int burst_limit)
{
    if (rate_limit <= 0) {
        rate_limit = 1000;
    }
    if (burst_limit <= 0) {
        burst_limit = rate_limit / 4;
    }
    burst_limit = MAX(burst_limit, 1);
    burst_limit = MIN(burst_limit, INT_MAX / 1000);

    ps->rate_limit = rate_limit;
    ps->burst_limit = burst_limit;
    while (ps->n_queued > burst_limit) {
        drop_packet(ps);
    }
}
