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

#include "controller.h"
#include <errno.h>
#include <string.h>
#include "buffer.h"
#include "forward.h"
#include "poll-loop.h"
#include "ofp-print.h"
#include "util.h"
#include "vconn.h"

#define THIS_MODULE VLM_controller_connection
#include "vlog.h"

void
controller_init(struct controller_connection *cc,
                const char *name, bool reliable)
{
    cc->reliable = reliable;
    cc->name = name;
    cc->vconn = NULL;
    queue_init(&cc->txq);
    cc->backoff_deadline = 0;
    cc->backoff = 0;
}

static int
try_send(struct controller_connection *cc)
{
    int retval = 0;
    struct buffer *next = cc->txq.head->next;
    retval = vconn_send(cc->vconn, cc->txq.head);
    if (retval) {
        return retval;
    }
    queue_advance_head(&cc->txq, next);
    return 0;
}

void
controller_run(struct controller_connection *cc, struct datapath *dp)
{
    if (!cc->vconn) {
        if (time(0) >= cc->backoff_deadline) {
            int retval;

            retval = vconn_open(cc->name, &cc->vconn);
            if (!retval) {
                cc->backoff_deadline = time(0) + cc->backoff;
                cc->connected = false;
            } else {
                VLOG_WARN("%s: connection failed (%s)",
                          cc->name, strerror(retval)); 
                controller_disconnect(cc, 0);
            }
        }
    } else if (!cc->connected) {
        int error = vconn_connect(cc->vconn);
        if (!error) {
            VLOG_WARN("%s: connected", cc->name);
            if (vconn_is_passive(cc->vconn)) {
                fatal(0, "%s: passive vconn not supported in switch",
                      cc->name);
            }
            cc->connected = true;
        } else if (error != EAGAIN) {
            VLOG_WARN("%s: connection failed (%s)",
                      cc->name, strerror(error));
            controller_disconnect(cc, 0);
        }
    } else {
        int iterations;

        for (iterations = 0; iterations < 50; iterations++) {
            struct buffer *buffer;
            int error = vconn_recv(cc->vconn, &buffer);
            if (!error) {
                fwd_control_input(dp, buffer->data, buffer->size);
                buffer_delete(buffer);
            } else if (error == EAGAIN) {
                break;
            } else {
                controller_disconnect(cc, error);
                return;
            }
        }

        while (cc->txq.n > 0) {
            int error = try_send(cc);
            if (error == EAGAIN) {
                break;
            } else if (error) {
                controller_disconnect(cc, error);
                return;
            }
        } 
    }
}

void
controller_disconnect(struct controller_connection *cc, int error) 
{
    time_t now = time(0);
    
    if (cc->vconn) {
        if (!cc->reliable) {
            fatal(0, "%s: connection dropped", cc->name);
        }

        if (error > 0) {
            VLOG_WARN("%s: connection dropped (%s)",
                      cc->name, strerror(error)); 
        } else if (error == EOF) { 
            VLOG_WARN("%s: connection closed", cc->name); 
        } else {
            VLOG_WARN("%s: connection dropped", cc->name); 
        }
        vconn_close(cc->vconn);
        cc->vconn = NULL;
        queue_clear(&cc->txq);
    }

    if (now >= cc->backoff_deadline) {
        cc->backoff = 1;
    } else {
        cc->backoff = MIN(60, MAX(1, 2 * cc->backoff));
        VLOG_WARN("%s: waiting %d seconds before reconnect\n",
                  cc->name, cc->backoff);
    }
    cc->backoff_deadline = now + cc->backoff;
}

void
controller_wait(struct controller_connection *cc) 
{
    if (cc->vconn) {
        vconn_wait(cc->vconn, WAIT_RECV);
        if (cc->txq.n) {
            vconn_wait(cc->vconn, WAIT_SEND);
        }
    } else {
        poll_timer_wait((cc->backoff_deadline - time(0)) * 1000);
    }
}

void
controller_send(struct controller_connection *cc, struct buffer *b) 
{
    if (cc->vconn) {
        if (cc->txq.n < 128) {
            queue_push_tail(&cc->txq, b);
            if (cc->txq.n == 1) {
                try_send(cc);
            }
        } else {
            VLOG_WARN("%s: controller queue overflow", cc->name);
            buffer_delete(b);
        } 
    }
}
