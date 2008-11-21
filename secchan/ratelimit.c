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
#include "ratelimit.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "queue.h"
#include "rconn.h"
#include "secchan.h"
#include "status.h"
#include "timeval.h"
#include "vconn.h"

struct rate_limiter {
    const struct settings *s;
    struct rconn *remote_rconn;

    /* One queue per physical port. */
    struct ofp_queue queues[OFPP_MAX];
    int n_queued;               /* Sum over queues[*].n. */
    int next_tx_port;           /* Next port to check in round-robin. */

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
    unsigned long long n_tx_dropped;    /* # dropped due to tx overflow. */
};

/* Drop a packet from the longest queue in 'rl'. */
static void
drop_packet(struct rate_limiter *rl)
{
    struct ofp_queue *longest;  /* Queue currently selected as longest. */
    int n_longest;              /* # of queues of same length as 'longest'. */
    struct ofp_queue *q;

    longest = &rl->queues[0];
    n_longest = 1;
    for (q = &rl->queues[0]; q < &rl->queues[OFPP_MAX]; q++) {
        if (longest->n < q->n) {
            longest = q;
            n_longest = 1;
        } else if (longest->n == q->n) {
            n_longest++;

            /* Randomly select one of the longest queues, with a uniform
             * distribution (Knuth algorithm 3.4.2R). */
            if (!random_range(n_longest)) {
                longest = q;
            }
        }
    }

    /* FIXME: do we want to pop the tail instead? */
    ofpbuf_delete(queue_pop_head(longest));
    rl->n_queued--;
}

/* Remove and return the next packet to transmit (in round-robin order). */
static struct ofpbuf *
dequeue_packet(struct rate_limiter *rl)
{
    unsigned int i;

    for (i = 0; i < OFPP_MAX; i++) {
        unsigned int port = (rl->next_tx_port + i) % OFPP_MAX;
        struct ofp_queue *q = &rl->queues[port];
        if (q->n) {
            rl->next_tx_port = (port + 1) % OFPP_MAX;
            rl->n_queued--;
            return queue_pop_head(q);
        }
    }
    NOT_REACHED();
}

/* Add tokens to the bucket based on elapsed time. */
static void
refill_bucket(struct rate_limiter *rl)
{
    const struct settings *s = rl->s;
    long long int now = time_msec();
    long long int tokens = (now - rl->last_fill) * s->rate_limit + rl->tokens;
    if (tokens >= 1000) {
        rl->last_fill = now;
        rl->tokens = MIN(tokens, s->burst_limit * 1000);
    }
}

/* Attempts to remove enough tokens from 'rl' to transmit a packet.  Returns
 * true if successful, false otherwise.  (In the latter case no tokens are
 * removed.) */
static bool
get_token(struct rate_limiter *rl)
{
    if (rl->tokens >= 1000) {
        rl->tokens -= 1000;
        return true;
    } else {
        return false;
    }
}

static bool
rate_limit_local_packet_cb(struct relay *r, void *rl_)
{
    struct rate_limiter *rl = rl_;
    const struct settings *s = rl->s;
    struct ofp_packet_in *opi;

    opi = get_ofp_packet_in(r);
    if (!opi) {
        return false;
    }

    if (opi->reason == OFPR_ACTION) {
        /* Don't rate-limit 'ofp-packet_in's generated by flows that the
         * controller set up.  XXX we should really just rate-limit them
         * *separately* so that no one can flood the controller this way. */
        return false;
    }

    if (!rl->n_queued && get_token(rl)) {
        /* In the common case where we are not constrained by the rate limit,
         * let the packet take the normal path. */
        rl->n_normal++;
        return false;
    } else {
        /* Otherwise queue it up for the periodic callback to drain out. */
        struct ofpbuf *msg = r->halves[HALF_LOCAL].rxbuf;
        int port = ntohs(opi->in_port) % OFPP_MAX;
        if (rl->n_queued >= s->burst_limit) {
            drop_packet(rl);
        }
        queue_push_tail(&rl->queues[port], ofpbuf_clone(msg));
        rl->n_queued++;
        rl->n_limited++;
        return true;
    }
}

static void
rate_limit_status_cb(struct status_reply *sr, void *rl_)
{
    struct rate_limiter *rl = rl_;

    status_reply_put(sr, "normal=%llu", rl->n_normal);
    status_reply_put(sr, "limited=%llu", rl->n_limited);
    status_reply_put(sr, "queue-dropped=%llu", rl->n_queue_dropped);
    status_reply_put(sr, "tx-dropped=%llu", rl->n_tx_dropped);
}

static void
rate_limit_periodic_cb(void *rl_)
{
    struct rate_limiter *rl = rl_;
    int i;

    /* Drain some packets out of the bucket if possible, but limit the number
     * of iterations to allow other code to get work done too. */
    refill_bucket(rl);
    for (i = 0; rl->n_queued && get_token(rl) && i < 50; i++) {
        /* Use a small, arbitrary limit for the amount of queuing to do here,
         * because the TCP connection is responsible for buffering and there is
         * no point in trying to transmit faster than the TCP connection can
         * handle. */
        struct ofpbuf *b = dequeue_packet(rl);
        if (rconn_send_with_limit(rl->remote_rconn, b, &rl->n_txq, 10)) {
            rl->n_tx_dropped++;
        }
    }
}

static void
rate_limit_wait_cb(void *rl_)
{
    struct rate_limiter *rl = rl_;
    if (rl->n_queued) {
        if (rl->tokens >= 1000) {
            /* We can transmit more packets as soon as we're called again. */
            poll_immediate_wake();
        } else {
            /* We have to wait for the bucket to re-fill.  We could calculate
             * the exact amount of time here for increased smoothness. */
            poll_timer_wait(TIME_UPDATE_INTERVAL / 2);
        }
    }
}

static struct hook_class rate_limit_hook_class = {
    rate_limit_local_packet_cb, /* local_packet_cb */
    NULL,                       /* remote_packet_cb */
    rate_limit_periodic_cb,     /* periodic_cb */
    rate_limit_wait_cb,         /* wait_cb */
    NULL,                       /* closing_cb */
};

void
rate_limit_start(struct secchan *secchan, const struct settings *s,
                 struct switch_status *ss, struct rconn *remote)
{
    struct rate_limiter *rl;
    size_t i;

    rl = xcalloc(1, sizeof *rl);
    rl->s = s;
    rl->remote_rconn = remote;
    for (i = 0; i < ARRAY_SIZE(rl->queues); i++) {
        queue_init(&rl->queues[i]);
    }
    rl->last_fill = time_msec();
    rl->tokens = s->rate_limit * 100;
    switch_status_register_category(ss, "rate-limit",
                                    rate_limit_status_cb, rl);
    add_hook(secchan, &rate_limit_hook_class, rl);
}
