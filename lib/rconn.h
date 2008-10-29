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

#ifndef RCONN_H
#define RCONN_H 1

#include "queue.h"
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* A wrapper around vconn that provides queuing and optionally reliability.
 *
 * An rconn maintains a message transmission queue of bounded length specified
 * by the caller.  The rconn does not guarantee reliable delivery of
 * queued messages: all queued messages are dropped when reconnection becomes
 * necessary.
 *
 * An rconn optionally provides reliable communication, in this sense: the
 * rconn will re-connect, with exponential backoff, when the underlying vconn
 * disconnects.
 */

struct vconn;

struct rconn *rconn_new(const char *name, 
                        int inactivity_probe_interval, int max_backoff);
struct rconn *rconn_new_from_vconn(const char *name, struct vconn *);
struct rconn *rconn_create(int inactivity_probe_interval, int max_backoff);
int rconn_connect(struct rconn *, const char *name);
void rconn_connect_unreliably(struct rconn *,
                              const char *name, struct vconn *vconn);
void rconn_disconnect(struct rconn *);
void rconn_destroy(struct rconn *);

void rconn_run(struct rconn *);
void rconn_run_wait(struct rconn *);
struct ofpbuf *rconn_recv(struct rconn *);
void rconn_recv_wait(struct rconn *);
int rconn_send(struct rconn *, struct ofpbuf *, int *n_queued);
int rconn_send_with_limit(struct rconn *, struct ofpbuf *,
                          int *n_queued, int queue_limit);
unsigned int rconn_packets_sent(const struct rconn *);
unsigned int rconn_packets_received(const struct rconn *);

void rconn_add_monitor(struct rconn *, struct vconn *);

const char *rconn_get_name(const struct rconn *);
bool rconn_is_alive(const struct rconn *);
bool rconn_is_connected(const struct rconn *);
int rconn_failure_duration(const struct rconn *);
bool rconn_is_connectivity_questionable(struct rconn *);

uint32_t rconn_get_ip(const struct rconn *);

const char *rconn_get_state(const struct rconn *);
unsigned int rconn_get_attempted_connections(const struct rconn *);
unsigned int rconn_get_successful_connections(const struct rconn *);
time_t rconn_get_last_connection(const struct rconn *);
time_t rconn_get_creation_time(const struct rconn *);
unsigned long int rconn_get_total_time_connected(const struct rconn *);
int rconn_get_backoff(const struct rconn *);
unsigned int rconn_get_state_elapsed(const struct rconn *);

#endif /* rconn.h */
