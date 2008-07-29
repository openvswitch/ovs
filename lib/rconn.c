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
#include "rconn.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "poll-loop.h"
#include "ofp-print.h"
#include "timeval.h"
#include "util.h"
#include "vconn.h"

#define THIS_MODULE VLM_rconn
#include "vlog.h"

#define STATES                                  \
    STATE(VOID, 1 << 0)                         \
    STATE(BACKOFF, 1 << 1)                      \
    STATE(CONNECTING, 1 << 2)                   \
    STATE(ACTIVE, 1 << 3)                       \
    STATE(IDLE, 1 << 4)
enum state {
#define STATE(NAME, VALUE) S_##NAME = VALUE,
    STATES
#undef STATE
};

static const char *
state_name(enum state state)
{
    switch (state) {
#define STATE(NAME, VALUE) case S_##NAME: return #NAME;
        STATES
#undef STATE
    }
    return "***ERROR***";
}

/* A reliable connection to an OpenFlow switch or controller.
 *
 * See the large comment in rconn.h for more information. */
struct rconn {
    enum state state;
    time_t state_entered;

    struct vconn *vconn;
    char *name;
    bool reliable;

    struct queue txq;
    int txq_limit;

    int backoff;
    int max_backoff;
    time_t backoff_deadline;
    time_t last_received;
    time_t last_connected;

    unsigned int packets_sent;

    /* If we can't connect to the peer, it could be for any number of reasons.
     * Usually, one would assume it is because the peer is not running or
     * because the network is partitioned.  But it could also be because the
     * network topology has changed, in which case the upper layer will need to
     * reassess it (in particular, obtain a new IP address via DHCP and find
     * the new location of the controller).  We set this flag when we suspect
     * that this could be the case. */
    bool questionable_connectivity;
    time_t last_questioned;

    /* Throughout this file, "probe" is shorthand for "inactivity probe".
     * When nothing has been received from the peer for a while, we send out
     * an echo request as an inactivity probe packet.  We should receive back
     * a response. */
    int probe_interval;         /* Secs of inactivity before sending probe. */
};

static unsigned int sat_add(unsigned int x, unsigned int y);
static unsigned int sat_mul(unsigned int x, unsigned int y);
static unsigned int elapsed_in_this_state(const struct rconn *);
static unsigned int timeout(const struct rconn *);
static bool timed_out(const struct rconn *);
static void state_transition(struct rconn *, enum state);
static int try_send(struct rconn *);
static int reconnect(struct rconn *);
static void disconnect(struct rconn *, int error);
static void question_connectivity(struct rconn *);

/* Creates a new rconn, connects it (reliably) to 'name', and returns it. */
struct rconn *
rconn_new(const char *name, int txq_limit, int inactivity_probe_interval,
          int max_backoff) 
{
    struct rconn *rc = rconn_create(txq_limit, inactivity_probe_interval,
                                    max_backoff);
    rconn_connect(rc, name);
    return rc;
}

/* Creates a new rconn, connects it (unreliably) to 'vconn', and returns it. */
struct rconn *
rconn_new_from_vconn(const char *name, int txq_limit, struct vconn *vconn) 
{
    struct rconn *rc = rconn_create(txq_limit, 60, 0);
    rconn_connect_unreliably(rc, name, vconn);
    return rc;
}

/* Creates and returns a new rconn.
 *
 * 'txq_limit' is the maximum length of the send queue, in packets.
 *
 * 'probe_interval' is a number of seconds.  If the interval passes once
 * without an OpenFlow message being received from the peer, the rconn sends
 * out an "echo request" message.  If the interval passes again without a
 * message being received, the rconn disconnects and re-connects to the peer.
 * Setting 'probe_interval' to 0 disables this behavior.
 *
 * 'max_backoff' is the maximum number of seconds between attempts to connect
 * to the peer.  The actual interval starts at 1 second and doubles on each
 * failure until it reaches 'max_backoff'.  If 0 is specified, the default of
 * 60 seconds is used. */
struct rconn *
rconn_create(int txq_limit, int probe_interval, int max_backoff)
{
    struct rconn *rc = xcalloc(1, sizeof *rc);

    rc->state = S_VOID;
    rc->state_entered = time(0);

    rc->vconn = NULL;
    rc->name = xstrdup("void");
    rc->reliable = false;

    queue_init(&rc->txq);
    assert(txq_limit > 0);
    rc->txq_limit = txq_limit;

    rc->backoff = 0;
    rc->max_backoff = max_backoff ? max_backoff : 60;
    rc->backoff_deadline = TIME_MIN;
    rc->last_received = time(0);
    rc->last_connected = time(0);

    rc->packets_sent = 0;

    rc->questionable_connectivity = false;
    rc->last_questioned = time(0);

    rc->probe_interval = probe_interval ? MAX(5, probe_interval) : 0;

    return rc;
}

int
rconn_connect(struct rconn *rc, const char *name)
{
    rconn_disconnect(rc);
    free(rc->name);
    rc->name = xstrdup(name);
    rc->reliable = true;
    return reconnect(rc);
}

void
rconn_connect_unreliably(struct rconn *rc,
                         const char *name, struct vconn *vconn)
{
    assert(vconn != NULL);
    rconn_disconnect(rc);
    free(rc->name);
    rc->name = xstrdup(name);
    rc->reliable = false;
    rc->vconn = vconn;
    rc->last_connected = time(0);
    state_transition(rc, S_ACTIVE);
}

void
rconn_disconnect(struct rconn *rc)
{
    if (rc->vconn) {
        vconn_close(rc->vconn);
        rc->vconn = NULL;
    }
    free(rc->name);
    rc->name = xstrdup("void");
    rc->reliable = false;

    rc->backoff = 0;
    rc->backoff_deadline = TIME_MIN;

    state_transition(rc, S_VOID);
}

/* Disconnects 'rc' and frees the underlying storage. */
void
rconn_destroy(struct rconn *rc)
{
    if (rc) {
        free(rc->name);
        vconn_close(rc->vconn);
        queue_destroy(&rc->txq);
        free(rc);
    }
}

static unsigned int
timeout_VOID(const struct rconn *rc)
{
    return UINT_MAX;
}

static void
run_VOID(struct rconn *rc)
{
    /* Nothing to do. */
}

static int
reconnect(struct rconn *rc)
{
    int retval;

    VLOG_WARN("%s: connecting...", rc->name);
    retval = vconn_open(rc->name, &rc->vconn);
    if (!retval) {
        rc->backoff_deadline = time(0) + rc->backoff;
        state_transition(rc, S_CONNECTING);
    } else {
        VLOG_WARN("%s: connection failed (%s)", rc->name, strerror(retval));
        disconnect(rc, 0);
    }
    return retval;
}

static unsigned int
timeout_BACKOFF(const struct rconn *rc)
{
    return rc->backoff;
}

static void
run_BACKOFF(struct rconn *rc)
{
    if (timed_out(rc)) {
        reconnect(rc);
    }
}

static unsigned int
timeout_CONNECTING(const struct rconn *rc)
{
    return MAX(1, rc->backoff);
}

static void
run_CONNECTING(struct rconn *rc)
{
    int retval = vconn_connect(rc->vconn);
    if (!retval) {
        VLOG_WARN("%s: connected", rc->name);
        if (vconn_is_passive(rc->vconn)) {
            error(0, "%s: passive vconn not supported", rc->name);
            state_transition(rc, S_VOID);
        } else {
            state_transition(rc, S_ACTIVE);
            rc->last_connected = rc->state_entered;
        }
    } else if (retval != EAGAIN) {
        VLOG_WARN("%s: connection failed (%s)", rc->name, strerror(retval));
        disconnect(rc, retval);
    } else if (timed_out(rc)) {
        VLOG_WARN("%s: connection timed out", rc->name);
        rc->backoff_deadline = TIME_MAX; /* Prevent resetting backoff. */
        disconnect(rc, 0);
    }
}

static void
do_tx_work(struct rconn *rc)
{
    while (rc->txq.n > 0) {
        int error = try_send(rc);
        if (error) {
            break;
        }
    }
}

static unsigned int
timeout_ACTIVE(const struct rconn *rc)
{
    if (rc->probe_interval) {
        unsigned int base = MAX(rc->last_received, rc->state_entered);
        unsigned int arg = base + rc->probe_interval - rc->state_entered;
        return arg;
    }
    return UINT_MAX;
}

static void
run_ACTIVE(struct rconn *rc)
{
    if (timed_out(rc)) {
        unsigned int base = MAX(rc->last_received, rc->state_entered);
        queue_push_tail(&rc->txq, make_echo_request());
        VLOG_DBG("%s: idle %u seconds, sending inactivity probe",
                 rc->name, (unsigned int) (time(0) - base));
        state_transition(rc, S_IDLE);
        return;
    }

    do_tx_work(rc);
}

static unsigned int
timeout_IDLE(const struct rconn *rc)
{
    return rc->probe_interval;
}

static void
run_IDLE(struct rconn *rc)
{
    if (timed_out(rc)) {
        question_connectivity(rc);
        VLOG_ERR("%s: no response to inactivity probe after %u "
                 "seconds, disconnecting",
                 rc->name, elapsed_in_this_state(rc));
        disconnect(rc, 0);
    } else {
        do_tx_work(rc);
    }
}

/* Performs whatever activities are necessary to maintain 'rc': if 'rc' is
 * disconnected, attempts to (re)connect, backing off as necessary; if 'rc' is
 * connected, attempts to send packets in the send queue, if any. */
void
rconn_run(struct rconn *rc)
{
    int old_state;
    do {
        old_state = rc->state;
        switch (rc->state) {
#define STATE(NAME, VALUE) case S_##NAME: run_##NAME(rc); break;
            STATES
#undef STATE
        default:
            NOT_REACHED();
        }
    } while (rc->state != old_state);
}

/* Causes the next call to poll_block() to wake up when rconn_run() should be
 * called on 'rc'. */
void
rconn_run_wait(struct rconn *rc)
{
    unsigned int timeo = timeout(rc);
    if (timeo != UINT_MAX) {
        poll_timer_wait(sat_mul(timeo, 1000));
    }

    if ((rc->state & (S_ACTIVE | S_IDLE)) && rc->txq.n) {
        vconn_wait(rc->vconn, WAIT_SEND);
    }
}

/* Attempts to receive a packet from 'rc'.  If successful, returns the packet;
 * otherwise, returns a null pointer.  The caller is responsible for freeing
 * the packet (with buffer_delete()). */
struct buffer *
rconn_recv(struct rconn *rc)
{
    if (rc->state & (S_ACTIVE | S_IDLE)) {
        struct buffer *buffer;
        int error = vconn_recv(rc->vconn, &buffer);
        if (!error) {
            rc->last_received = time(0);
            if (rc->state == S_IDLE) {
                state_transition(rc, S_ACTIVE);
            }
            return buffer;
        } else if (error != EAGAIN) {
            disconnect(rc, error);
        }
    }
    return NULL;
}

/* Causes the next call to poll_block() to wake up when a packet may be ready
 * to be received by vconn_recv() on 'rc'.  */
void
rconn_recv_wait(struct rconn *rc)
{
    if (rc->vconn) {
        vconn_wait(rc->vconn, WAIT_RECV);
    }
}

/* Sends 'b' on 'rc'.  Returns 0 if successful, EAGAIN if at least 'txq_limit'
 * packets are already queued, otherwise a positive errno value. */
int
do_send(struct rconn *rc, struct buffer *b, int txq_limit)
{
    if (rc->vconn) {
        if (rc->txq.n < txq_limit) {
            queue_push_tail(&rc->txq, b);
            if (rc->txq.n == 1) {
                try_send(rc);
            }
            return 0;
        } else {
            return EAGAIN;
        }
    } else {
        return ENOTCONN;
    }
}

/* Sends 'b' on 'rc'.  Returns 0 if successful, EAGAIN if the send queue is
 * full, or ENOTCONN if 'rc' is not currently connected.
 *
 * There is no rconn_send_wait() function: an rconn has a send queue that it
 * takes care of sending if you call rconn_run(), which will have the side
 * effect of waking up poll_block(). */
int
rconn_send(struct rconn *rc, struct buffer *b)
{
    return do_send(rc, b, rc->txq_limit);
}

/* Sends 'b' on 'rc'.  Returns 0 if successful, EAGAIN if the send queue is
 * full, otherwise a positive errno value.
 *
 * Compared to rconn_send(), this function relaxes the queue limit, allowing
 * more packets than usual to be queued. */
int
rconn_force_send(struct rconn *rc, struct buffer *b)
{
    return do_send(rc, b, 2 * rc->txq_limit);
}

/* Returns true if 'rc''s send buffer is full,
 * false if it has room for at least one more packet. */
bool
rconn_is_full(const struct rconn *rc)
{
    return rc->txq.n >= rc->txq_limit;
}

/* Returns the total number of packets successfully sent on the underlying
 * vconn.  A packet is not counted as sent while it is still queued in the
 * rconn, only when it has been successfuly passed to the vconn.  */
unsigned int
rconn_packets_sent(const struct rconn *rc)
{
    return rc->packets_sent;
}

/* Returns 'rc''s name (the 'name' argument passed to rconn_new()). */
const char *
rconn_get_name(const struct rconn *rc)
{
    return rc->name;
}

/* Returns true if 'rconn' is connected or in the process of reconnecting,
 * false if 'rconn' is disconnected and will not reconnect on its own. */
bool
rconn_is_alive(const struct rconn *rconn)
{
    return rconn->state != S_VOID;
}

/* Returns true if 'rconn' is connected, false otherwise. */
bool
rconn_is_connected(const struct rconn *rconn)
{
    return rconn->state & (S_ACTIVE | S_IDLE);
}

/* Returns 0 if 'rconn' is connected, otherwise the number of seconds that it
 * has been disconnected. */
int
rconn_disconnected_duration(const struct rconn *rconn)
{
    return rconn_is_connected(rconn) ? 0 : time(0) - rconn->last_received;
}

/* Returns the IP address of the peer, or 0 if the peer is not connected over
 * an IP-based protocol or if its IP address is not known. */
uint32_t
rconn_get_ip(const struct rconn *rconn) 
{
    return rconn->vconn ? vconn_get_ip(rconn->vconn) : 0;
}

/* If 'rconn' can't connect to the peer, it could be for any number of reasons.
 * Usually, one would assume it is because the peer is not running or because
 * the network is partitioned.  But it could also be because the network
 * topology has changed, in which case the upper layer will need to reassess it
 * (in particular, obtain a new IP address via DHCP and find the new location
 * of the controller).  When this appears that this might be the case, this
 * function returns true.  It also clears the questionability flag and prevents
 * it from being set again for some time. */
bool
rconn_is_connectivity_questionable(struct rconn *rconn)
{
    bool questionable = rconn->questionable_connectivity;
    rconn->questionable_connectivity = false;
    return questionable;
}

/* Tries to send a packet from 'rc''s send buffer.  Returns 0 if successful,
 * otherwise a positive errno value. */
static int
try_send(struct rconn *rc)
{
    int retval = 0;
    struct buffer *next = rc->txq.head->next;
    retval = vconn_send(rc->vconn, rc->txq.head);
    if (retval) {
        if (retval != EAGAIN) {
            disconnect(rc, retval);
        }
        return retval;
    }
    rc->packets_sent++;
    queue_advance_head(&rc->txq, next);
    return 0;
}

/* Disconnects 'rc'.  'error' is used only for logging purposes.  If it is
 * nonzero, then it should be EOF to indicate the connection was closed by the
 * peer in a normal fashion or a positive errno value. */
static void
disconnect(struct rconn *rc, int error)
{
    if (rc->reliable) {
        time_t now = time(0);

        if (rc->state & (S_CONNECTING | S_ACTIVE | S_IDLE)) {
            if (error > 0) {
                VLOG_WARN("%s: connection dropped (%s)",
                          rc->name, strerror(error));
            } else if (error == EOF) {
                if (rc->reliable) {
                    VLOG_WARN("%s: connection closed", rc->name);
                }
            } else {
                VLOG_WARN("%s: connection dropped", rc->name);
            }
            vconn_close(rc->vconn);
            rc->vconn = NULL;
            queue_clear(&rc->txq);
        }

        if (now >= rc->backoff_deadline) {
            rc->backoff = 1;
        } else {
            rc->backoff = MIN(rc->max_backoff, MAX(1, 2 * rc->backoff));
            VLOG_WARN("%s: waiting %d seconds before reconnect\n",
                      rc->name, rc->backoff);
        }
        rc->backoff_deadline = now + rc->backoff;
        state_transition(rc, S_BACKOFF);
        if (now - rc->last_connected > 60) {
            question_connectivity(rc);
        }
    } else {
        rconn_disconnect(rc);
    }
}

static unsigned int
elapsed_in_this_state(const struct rconn *rc)
{
    return time(0) - rc->state_entered;
}

static unsigned int
timeout(const struct rconn *rc)
{
    switch (rc->state) {
#define STATE(NAME, VALUE) case S_##NAME: return timeout_##NAME(rc);
        STATES
#undef STATE
    default:
        NOT_REACHED();
    }
}

static bool
timed_out(const struct rconn *rc)
{
    return time(0) >= sat_add(rc->state_entered, timeout(rc));
}

static void
state_transition(struct rconn *rc, enum state state)
{
    VLOG_DBG("%s: entering %s", rc->name, state_name(state));
    rc->state = state;
    rc->state_entered = time(0);
}

static unsigned int
sat_add(unsigned int x, unsigned int y)
{
    return x + y >= x ? x + y : UINT_MAX;
}

static unsigned int
sat_mul(unsigned int x, unsigned int y)
{
    assert(y);
    return x <= UINT_MAX / y ? x * y : UINT_MAX;
}

static void
question_connectivity(struct rconn *rc) 
{
    time_t now = time(0);
    if (now - rc->last_questioned > 60) {
        rc->questionable_connectivity = true;
        rc->last_questioned = now;
    }
}
