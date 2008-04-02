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
};

static struct rconn *create_rconn(const char *name, int txq_limit,
                                  struct vconn *);
static int try_send(struct rconn *);
static void disconnect(struct rconn *, int error);

/* Creates and returns a new rconn that connects (and re-connects as necessary)
 * to the vconn named 'name'.
 *
 * 'txq_limit' is the maximum length of the send queue, in packets. */
struct rconn *
rconn_new(const char *name, int txq_limit) 
{
    return create_rconn(name, txq_limit, NULL);
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
    return create_rconn(name, txq_limit, vconn);
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
    } else {
        poll_timer_wait((rc->backoff_deadline - time(0)) * 1000);
    }
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

/* There is no rconn_send_wait() function: an rconn has a send queue that it
 * takes care of sending if you call rconn_wait(), which will have the side
 * effect of waking up poll_block(). */
int
rconn_send(struct rconn *rc, struct buffer *b) 
{
    if (rc->vconn) {
        if (rc->txq.n < rc->txq_limit) {
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

static struct rconn *
create_rconn(const char *name, int txq_limit, struct vconn *vconn)
{
    struct rconn *rc = xmalloc(sizeof *rc);
    assert(txq_limit > 0);
    rc->reliable = vconn == NULL;
    rc->name = xstrdup(name);
    rc->vconn = vconn;
    queue_init(&rc->txq);
    rc->txq_limit = txq_limit;
    rc->backoff_deadline = 0;
    rc->backoff = 0;
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
}
