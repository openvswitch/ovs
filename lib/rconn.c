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

#include "rconn.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "poll-loop.h"
#include "ofp-print.h"
#include "util.h"
#include "vconn.h"

#define THIS_MODULE VLM_rconn
#include "vlog.h"

/* A reliable connection to an OpenFlow switch or controller.
 *
 * See the large comment in rconn.h for more information. */
struct rconn {
    bool reliable;
    char *name;
    struct vconn *vconn;
    bool connected;
    struct queue txq;
    int txq_limit;
    time_t backoff_deadline;
    int backoff;
    time_t last_connected;
    unsigned int packets_sent;

    /* Throughout this file, "probe" is shorthand for "inactivity probe".
     * When nothing has been received from the peer for a while, we send out
     * an echo request as an inactivity probe packet.  We should receive back
     * a response. */
    int probe_interval;         /* Secs of inactivity before sending probe. */
    time_t probe_sent;          /* Time at which last probe sent, or 0 if none
                                 * has been sent since 'last_connected'. */
};

static struct rconn *create_rconn(const char *name, int txq_limit,
                                  int probe_interval, struct vconn *);
static int try_send(struct rconn *);
static void disconnect(struct rconn *, int error);
static time_t probe_deadline(const struct rconn *);

/* Creates and returns a new rconn that connects (and re-connects as necessary)
 * to the vconn named 'name'.
 *
 * 'txq_limit' is the maximum length of the send queue, in packets.
 *
 * 'probe_interval' is a number of seconds.  If the interval passes once
 * without an OpenFlow message being received from the peer, the rconn sends
 * out an "echo request" message.  If the interval passes again without a
 * message being received, the rconn disconnects and re-connects to the peer.
 * Setting 'probe_interval' to 0 disables this behavior.  */
struct rconn *
rconn_new(const char *name, int txq_limit, int probe_interval)
{
    return create_rconn(name, txq_limit, probe_interval, NULL);
}

/* Creates and returns a new rconn that is initially connected to 'vconn' and
 * has the given 'name'.  The rconn will not re-connect after the connection
 * drops.
 *
 * 'txq_limit' is the maximum length of the send queue, in packets. */
struct rconn *
rconn_new_from_vconn(const char *name, int txq_limit, struct vconn *vconn)
{
    assert(vconn != NULL);
    return create_rconn(name, txq_limit, 0, vconn);
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

/* Performs whatever activities are necessary to maintain 'rc': if 'rc' is
 * disconnected, attempts to (re)connect, backing off as necessary; if 'rc' is
 * connected, attempts to send packets in the send queue, if any. */
void
rconn_run(struct rconn *rc)
{
    if (!rc->vconn) {
        if (rc->reliable && time(0) >= rc->backoff_deadline) {
            int retval;

            retval = vconn_open(rc->name, &rc->vconn);
            if (!retval) {
                rc->backoff_deadline = time(0) + rc->backoff;
                rc->connected = false;
            } else {
                VLOG_WARN("%s: connection failed (%s)",
                          rc->name, strerror(retval)); 
                disconnect(rc, 0);
            }
        }
    } else if (!rc->connected) {
        int error = vconn_connect(rc->vconn);
        if (!error) {
            VLOG_WARN("%s: connected", rc->name);
            if (vconn_is_passive(rc->vconn)) {
                fatal(0, "%s: passive vconn not supported in switch",
                      rc->name);
            }
            rc->connected = true;
        } else if (error != EAGAIN) {
            VLOG_WARN("%s: connection failed (%s)", rc->name, strerror(error));
            disconnect(rc, 0);
        }
    } else {
        if (rc->probe_interval) {
            time_t now = time(0);
            if (now >= probe_deadline(rc)) {
                if (!rc->probe_sent) {
                    queue_push_tail(&rc->txq, make_echo_request());
                    rc->probe_sent = now;
                    VLOG_DBG("%s: idle %d seconds, sending inactivity probe",
                             rc->name, (int) (now - rc->last_connected)); 
                } else {
                    VLOG_ERR("%s: no response to inactivity probe after %d "
                             "seconds, disconnecting",
                             rc->name, (int) (now - rc->probe_sent));
                    disconnect(rc, 0);
                }
            }
        }
        while (rc->txq.n > 0) {
            int error = try_send(rc);
            if (error == EAGAIN) {
                break;
            } else if (error) {
                disconnect(rc, error);
                return;
            }
        }
    }
}

/* Causes the next call to poll_block() to wake up when rconn_run() should be
 * called on 'rc'. */
void
rconn_run_wait(struct rconn *rc)
{
    if (rc->vconn) {
        if (rc->txq.n) {
            vconn_wait(rc->vconn, WAIT_SEND);
        }
        if (rc->probe_interval) {
            poll_timer_wait((probe_deadline(rc) - time(0)) * 1000);
        }
    } else {
        poll_timer_wait((rc->backoff_deadline - time(0)) * 1000);
    }
}

/* Returns the time at which, should nothing be received, we should send out an
 * inactivity probe (if none has yet been sent) or conclude that the connection
 * is dead (if a probe has already been sent). */
static time_t
probe_deadline(const struct rconn *rc) 
{
    assert(rc->probe_interval);
    return (rc->probe_interval
            + (rc->probe_sent ? rc->probe_sent : rc->last_connected));
}

/* Attempts to receive a packet from 'rc'.  If successful, returns the packet;
 * otherwise, returns a null pointer.  The caller is responsible for freeing
 * the packet (with buffer_delete()). */
struct buffer *
rconn_recv(struct rconn *rc)
{
    if (rc->vconn && rc->connected) {
        struct buffer *buffer;
        int error = vconn_recv(rc->vconn, &buffer);
        if (!error) {
            rc->last_connected = time(0);
            rc->probe_sent = 0;
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
 * false if 'rconn' is disconnected and will not be reconnected. */
bool
rconn_is_alive(const struct rconn *rconn) 
{
    return rconn->reliable || rconn->vconn;
}

/* Returns true if 'rconn' is connected, false otherwise. */
bool
rconn_is_connected(const struct rconn *rconn)
{
    return rconn->vconn && !vconn_connect(rconn->vconn);
}

/* Returns 0 if 'rconn' is connected, otherwise the number of seconds that it
 * has been disconnected. */
int
rconn_disconnected_duration(const struct rconn *rconn) 
{
    return rconn_is_connected(rconn) ? 0 : time(0) - rconn->last_connected;
}

static struct rconn *
create_rconn(const char *name, int txq_limit, int probe_interval,
             struct vconn *vconn)
{
    struct rconn *rc = xmalloc(sizeof *rc);
    assert(txq_limit > 0);
    rc->reliable = vconn == NULL;
    rc->connected = vconn != NULL;
    rc->name = xstrdup(name);
    rc->vconn = vconn;
    queue_init(&rc->txq);
    rc->txq_limit = txq_limit;
    rc->backoff_deadline = 0;
    rc->backoff = 0;
    rc->last_connected = time(0);
    rc->probe_interval = (probe_interval
                              ? MAX(5, probe_interval) : 0);
    rc->probe_sent = 0;
    rc->packets_sent = 0;
    return rc;
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
    time_t now = time(0);
    
    if (rc->vconn) {
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
        rc->backoff = MIN(60, MAX(1, 2 * rc->backoff));
        VLOG_WARN("%s: waiting %d seconds before reconnect\n",
                  rc->name, rc->backoff);
    }
    rc->backoff_deadline = now + rc->backoff;
    rc->probe_sent = 0;
}
